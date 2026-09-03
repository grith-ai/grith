// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Event handling logic for the supervisor loop.
//!
//! Contains the per-syscall event handler, proxy decision enforcement,
//! digest queueing, freeze/thaw orchestration, audit record and WebSocket
//! event construction, and the digest review wait loop.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::FutureExt;
use uuid::Uuid;

use grith_analytics::contract::{Category, CompletenessTier, RecordClass};
use grith_audit::types::AuditRecord;
use grith_audit::CorrelationTracker;
use grith_digest::types::{
    DigestItem, DigestStatus, FilterBreakdown, ReviewOutcome, ScoreSeverity,
};
use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::session_containment::ContainmentTracker;
use grith_proxy::session_state::SessionStateRegistry;
use grith_proxy::types::{
    format_dns_candidate_array, parse_dns_candidate_array, ProxyAction, SessionScopeKey,
    ToolCallContext, ToolCallType,
};
use grith_proxy::{audit_bridge, exfil};
use tokio::sync::broadcast;

use crate::config::SupervisorConfig;
use crate::dns_cache::DnsCache;
use crate::error::Result;
use crate::forensics_trace::ForensicsTraceSink;
use crate::freezer::Freezer;
use crate::interceptor::{
    CrossProcessOp, OpenFlags, SyscallEvent, SyscallInterceptor, SyscallKind,
};
use crate::reviewer::{DigestStore, QueueReviewer};
use crate::session_sync::SessionSync;
use crate::syscall_map;

use super::authority_delegation;
use super::mass_destruction;
use grith_proxy::types::CallOutcome;

use super::remote_eval::{self, RemoteEvalError};
use super::spawn_families;
use super::{session_state::SupervisorSession, DaemonRestartConfig};

fn session_scope_name(session: &SupervisorSession) -> &str {
    session.scope_name().unwrap_or("unknown")
}

fn analytics_completeness(value: crate::config::AuditCompletenessLevel) -> CompletenessTier {
    match value {
        crate::config::AuditCompletenessLevel::Decisions => CompletenessTier::Decisions,
        crate::config::AuditCompletenessLevel::Spawns => CompletenessTier::Spawns,
        crate::config::AuditCompletenessLevel::Io => CompletenessTier::Io,
        crate::config::AuditCompletenessLevel::All => CompletenessTier::All,
    }
}

/// The `queue_policy` analytics dimension for an [`InteractiveQueueAction`].
/// Kept in sync with the enum's `#[serde(rename_all = "lowercase")]` names —
/// serializing through serde_json would wrap the value in JSON quotes.
fn queue_policy_name(action: crate::config::InteractiveQueueAction) -> &'static str {
    match action {
        crate::config::InteractiveQueueAction::Freeze => "freeze",
        crate::config::InteractiveQueueAction::Log => "log",
        crate::config::InteractiveQueueAction::Deny => "deny",
    }
}

/// Analytics `profile_id`: the session's profile name when set, else the
/// policy scope name. Matches the DNS producer in `dns_decision.rs`.
fn analytics_profile_id(session: &SupervisorSession) -> &str {
    session
        .profile_name
        .as_deref()
        .unwrap_or_else(|| session_scope_name(session))
}

pub(super) fn prospective_analytics_metadata(
    loop_ctx: &SupervisorLoopContext<'_>,
    session: &SupervisorSession,
    record_class: RecordClass,
    tool_call_type: &str,
) -> grith_audit::AuditAnalyticsMetadata {
    prospective_analytics_metadata_with_category(
        loop_ctx,
        session,
        record_class,
        grith_analytics::normalize::category_for_tool_kind(tool_call_type),
    )
}

pub(super) fn prospective_analytics_metadata_with_category(
    loop_ctx: &SupervisorLoopContext<'_>,
    session: &SupervisorSession,
    record_class: RecordClass,
    category: Category,
) -> grith_audit::AuditAnalyticsMetadata {
    // The config envelope serializes + hashes the session config; both are
    // immutable for the session's lifetime, so the envelope is computed once
    // and cloned per record (the hot path runs per intercepted syscall).
    let config = loop_ctx.analytics_config.get_or_init(|| {
        let (allow, deny) = loop_ctx.proxy.scoring_config().thresholds();
        let fingerprint = serde_json::to_vec(loop_ctx.config).unwrap_or_default();
        crate::audit_analytics::config_envelope(
            analytics_profile_id(session),
            &fingerprint,
            allow,
            deny,
            queue_policy_name(loop_ctx.config.interactive_queue_action),
        )
    });
    crate::audit_analytics::metadata(
        config,
        analytics_completeness(loop_ctx.config.audit_completeness),
        record_class,
        category,
    )
}

/// Temporary kill switch for the PR 1 Phase D containment ordering. When set
/// to a truthy value (`"1"`, `"true"`, `"yes"` — case-insensitive, trimmed),
/// the noise-reduction and session-allowlist short-circuits ignore the
/// containment flag and behave as they did before PR 1.
///
/// **Removal:** this env var is scheduled for removal in PR 4 of the
/// codex-startup-prompt-flood remediation plan (see
/// `work/64-pr4-provenance-routine-spawn-tasks.md` Phase H4). Do not depend
/// on it in production tests.
///
/// The env var is read **once per process** via `OnceLock` — the supervisor's
/// P95 per-syscall budget is 50µs, and a `std::env::var` call costs a syscall
/// plus a heap allocation that we don't want on every event.
/// PR 3 Phase C: check whether a loopback address has a listener on
/// the given port. Used by the failed-connect suppression to avoid
/// prompting on connects that the kernel will refuse with
/// `ECONNREFUSED`.
///
/// Parses `/proc/net/tcp` + `/proc/net/tcp6` for sockets in LISTEN
/// state (st = `0A`). The check returns `true` when at least one
/// listening socket is bound to the loopback interface (`127.0.0.0/8`
/// or `::1`) on `port`, OR to the wildcard address (`0.0.0.0:port` /
/// `[::]:port` — those also accept loopback connects).
///
/// On non-Linux platforms `/proc/net/tcp` is absent and this function
/// returns `false` (we can't prove a listener exists, so we never
/// suppress). Linux-specific by design.
///
/// **TOCTOU caveat:** a listener could appear between this check and
/// the kernel's `connect()`. For typical Codex-like sessions the
/// listener set is stable enough that this is acceptable; the
/// suppression event is audit-logged so any TOCTOU-exploited miss is
/// forensically visible.
#[cfg(target_os = "linux")]
fn loopback_port_has_listener(port: u16) -> bool {
    fn scan(path: &str, port: u16, ipv6: bool) -> bool {
        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return false,
        };
        for line in content.lines().skip(1) {
            // /proc/net/tcp columns: sl local_address rem_address st ...
            let mut fields = line.split_whitespace();
            let _sl = fields.next();
            let local = match fields.next() {
                Some(l) => l,
                None => continue,
            };
            let _rem = fields.next();
            let st = match fields.next() {
                Some(s) => s,
                None => continue,
            };
            if st != "0A" {
                // not LISTEN
                continue;
            }
            let (addr_hex, port_hex) = match local.rsplit_once(':') {
                Some(p) => p,
                None => continue,
            };
            let parsed_port = match u16::from_str_radix(port_hex, 16) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if parsed_port != port {
                continue;
            }
            // Loopback hex: ipv4 `0100007F` (127.0.0.1 little-endian);
            // wildcard ipv4 `00000000`. ipv6 loopback is `...00000001`;
            // wildcard ipv6 is all zeros. Be conservative — accept
            // both loopback and wildcard.
            if ipv6 {
                if addr_hex == "00000000000000000000000000000000"
                    || addr_hex == "00000000000000000000000001000000"
                {
                    return true;
                }
            } else if addr_hex == "0100007F" || addr_hex == "00000000" {
                return true;
            }
        }
        false
    }
    scan("/proc/net/tcp", port, false) || scan("/proc/net/tcp6", port, true)
}

#[cfg(not(target_os = "linux"))]
fn loopback_port_has_listener(_port: u16) -> bool {
    false
}

/// PR 3 Phase C: whether `addr` parses as a loopback address. Used to
/// gate the failed-connect suppression — only loopback connects are
/// eligible (a missing listener on a non-loopback host could be a
/// transient route failure that the user still wants to know about).
fn is_loopback_connect_address(addr: &str) -> bool {
    if addr.is_empty() {
        return false;
    }
    if addr == "localhost" {
        return true;
    }
    if let Ok(ipv4) = addr.parse::<std::net::Ipv4Addr>() {
        return ipv4.is_loopback();
    }
    if let Ok(ipv6) = addr.parse::<std::net::Ipv6Addr>() {
        return ipv6.is_loopback();
    }
    false
}

/// Resolve network attribution without holding the shared DNS cache lock while
/// libc performs a potentially blocking PTR lookup.
async fn resolve_network_attribution(
    dns_cache: &Arc<Mutex<DnsCache>>,
    address: &str,
) -> crate::dns_cache::Resolution {
    let lookup = match dns_cache.lock() {
        Ok(mut cache) => cache.lookup_attribution(address),
        Err(_) => {
            return address
                .parse()
                .map(crate::dns_cache::Resolution::Unknown)
                .unwrap_or_else(|_| crate::dns_cache::Resolution::NotAnIp(address.to_string()));
        }
    };

    match lookup {
        crate::dns_cache::AttributionLookup::Ready(resolution) => resolution,
        crate::dns_cache::AttributionLookup::NeedsReverse(addr) => {
            let lookup_address = addr.to_string();
            let hostname = tokio::task::spawn_blocking(move || {
                crate::dns_cache::reverse_dns_lookup(&lookup_address)
            })
            .await
            .unwrap_or(None);
            dns_cache
                .lock()
                .map(|mut cache| cache.commit_reverse_lookup(addr, hostname))
                .unwrap_or(crate::dns_cache::Resolution::Unknown(addr))
        }
    }
}

/// Bounded wall-clock budget for a miss-triggered forward re-resolve,
/// mirroring the startup seed barrier. On expiry the lookup continues in the
/// background so the next miss still benefits from the refreshed cache.
const DNS_FORWARD_CONFIRM_BUDGET: Duration = Duration::from_millis(400);

/// Last-chance recovery for a `NetConnect` attribution miss: re-resolve the
/// session's trusted destinations right now and re-check the cache.
///
/// The periodic priority refresh only accumulates the answers the supervisor's
/// own queries happened to receive; rotating-CDN pools (github.com/Azure) can
/// hand the supervised tool an address the refresh has never seen, and such
/// IPs often have no PTR record either. A fresh resolution at prompt time
/// frequently covers exactly the address the tool just connected to —
/// converting a raw-IP QUEUE prompt into the silent allow the operator's
/// profile already intends.
///
/// Returns the (possibly upgraded) resolution plus whether the upgrade came
/// from this confirm pass. Rate-limited via [`DnsForwardConfirm::try_begin`];
/// a skipped or failed confirm returns the original miss unchanged.
async fn confirm_forward_attribution(
    dns_cache: &Arc<Mutex<DnsCache>>,
    confirm: Option<&crate::dns_cache::DnsForwardConfirm>,
    address: &str,
    miss: crate::dns_cache::Resolution,
) -> (crate::dns_cache::Resolution, bool) {
    use crate::dns_cache::Resolution;

    let Some(confirm) = confirm else {
        return (miss, false);
    };
    if !confirm.try_begin() {
        return (miss, false);
    }
    let domains = confirm.domains().to_vec();
    let mut handle = tokio::task::spawn_blocking(move || {
        crate::dns_cache::resolve_domains(domains.iter().map(String::as_str))
    });
    match tokio::time::timeout(DNS_FORWARD_CONFIRM_BUDGET, &mut handle).await {
        Ok(Ok(resolved)) => {
            let refreshed = match dns_cache.lock() {
                Ok(mut cache) => {
                    cache.record_resolved_domains(resolved);
                    match cache.lookup_attribution(address) {
                        crate::dns_cache::AttributionLookup::Ready(resolution) => Some(resolution),
                        // The reverse path already ran (and negative-cached)
                        // on the way to this miss; do not re-run it here.
                        crate::dns_cache::AttributionLookup::NeedsReverse(_) => None,
                    }
                }
                Err(_) => None,
            };
            match refreshed {
                Some(resolution @ (Resolution::Exact(_) | Resolution::Ambiguous(_))) => {
                    tracing::info!(
                        event = "dns_forward_confirm",
                        outcome = "hit",
                        raw_ip = %address,
                        "attribution miss recovered by re-resolving trusted destinations"
                    );
                    (resolution, true)
                }
                _ => {
                    tracing::debug!(
                        event = "dns_forward_confirm",
                        outcome = "miss",
                        raw_ip = %address,
                        "re-resolved trusted destinations do not cover this address"
                    );
                    (miss, false)
                }
            }
        }
        Ok(Err(join_error)) => {
            tracing::warn!(
                event = "dns_forward_confirm",
                outcome = "error",
                raw_ip = %address,
                error = %join_error,
                "forward re-resolve task failed"
            );
            (miss, false)
        }
        Err(_elapsed) => {
            // Budget spent. Let the lookup finish detached and merge its
            // results so the next miss finds a warm cache.
            let cache = Arc::clone(dns_cache);
            tokio::spawn(async move {
                if let Ok(resolved) = handle.await {
                    if let Ok(mut cache) = cache.lock() {
                        cache.record_resolved_domains(resolved);
                    }
                }
            });
            tracing::debug!(
                event = "dns_forward_confirm",
                outcome = "timeout",
                raw_ip = %address,
                budget_ms = DNS_FORWARD_CONFIRM_BUDGET.as_millis() as u64,
                "forward re-resolve exceeded its budget; continuing in background"
            );
            (miss, false)
        }
    }
}

/// PR 3 Phase B: cheap pre-execve check for "this binary doesn't exist
/// at the supervisor's filesystem view." Returns `true` only when we
/// can prove the path is missing.
///
/// For absolute paths: stat the path. If it doesn't exist or isn't a
/// regular file with execute permission for the supervised UID, return
/// true.
///
/// For relative paths (no `/`): walk `PATH`. If no directory contains
/// an executable with this name, return true. (This catches the
/// dominant Codex prompt-flood case: shells probing for `git` across
/// many `$PATH` entries that don't all have it.)
///
/// Caveats:
/// - **TOCTOU.** A symlink swap between this stat and the kernel's
///   `execve` could let an attacker arrange a "stat says missing →
///   kernel says found" window. Documented in the call-site comment;
///   suppression events are tagged in the audit trail so any
///   exploited miss is forensically visible.
/// - **Mount-namespace mismatch.** If the supervised tool runs in a
///   different mount namespace, the supervisor's stat may not match
///   the tracee's view. We use `/proc/<pid>/root` resolution where
///   possible, but bwrap-style sandboxes can still produce gaps.
///   PR 6's namespace coverage addresses that separately.
fn exec_path_clearly_missing(command: &str) -> bool {
    if command.is_empty() {
        return false;
    }
    if command.contains('/') {
        // Absolute or relative-with-/ path. Just stat it.
        return !std::path::Path::new(command).is_file();
    }
    // Bare command — walk PATH.
    let path_var = match std::env::var_os("PATH") {
        Some(v) => v,
        None => return false, // Can't be confident without PATH.
    };
    for dir in std::env::split_paths(&path_var) {
        if dir.join(command).is_file() {
            return false;
        }
    }
    true
}

// PR 4 Phase H: the `GRITH_DEBUG_ALLOW_SESSION_ALLOWLIST_BYPASS`
// kill switch (added in PR 1 Phase G as an emergency rollback hatch
// for the session-allowlist containment-gating short-circuit) is
// removed. After ~3 months of containment-gated behaviour with no
// observed regressions, the env-var escape hatch is no longer needed
// — operators with concerns should disable containment via profile
// config, not by hot-patching the env. Removing the cache and the
// `from_env` helper closes a small but real attack surface
// (an attacker who can manipulate the supervisor's env can no longer
// silently disable containment).

// ---------------------------------------------------------------------------
// Read batch tracker for noise reduction
// ---------------------------------------------------------------------------

/// Tracks recent per-fd read evaluations to coalesce rapid consecutive reads
/// within a configurable time window. When `batch_rapid_reads` is enabled,
/// reads to the same `(pid, fd)` pair within `window` of the last proxy
/// evaluation are auto-allowed without re-evaluation.
pub(super) struct ReadBatchTracker {
    last_eval: HashMap<(u32, i32), Instant>,
    window: Duration,
}

impl ReadBatchTracker {
    pub(super) fn new(window_ms: u64) -> Self {
        Self {
            last_eval: HashMap::new(),
            window: Duration::from_millis(window_ms),
        }
    }

    /// Returns `true` if this read should be coalesced (auto-allowed without
    /// proxy evaluation). Records the current timestamp for new evaluations.
    pub(super) fn should_coalesce(&mut self, pid: u32, fd: i32) -> bool {
        let key = (pid, fd);
        let now = Instant::now();
        if let Some(last) = self.last_eval.get(&key) {
            if now.duration_since(*last) < self.window {
                return true;
            }
        }
        self.last_eval.insert(key, now);
        false
    }
}

// ---------------------------------------------------------------------------
// Loop context (shared references for the event loop)
// ---------------------------------------------------------------------------

pub(super) struct SupervisorLoopContext<'a> {
    pub(super) proxy: &'a SecurityProxy,
    pub(super) audit_sink: Arc<dyn crate::audit_sink::AuditSink>,
    pub(super) digest_store: Arc<dyn DigestStore>,
    pub(super) dlp_redactor: &'a grith_proxy::filters::dlp_gate::DlpRedactor,
    pub(super) correlation_tracker: &'a CorrelationTracker,
    pub(super) containment_tracker: &'a Arc<ContainmentTracker>,
    pub(super) config: &'a SupervisorConfig,
    pub(super) event_tx: Option<&'a broadcast::Sender<String>>,
    /// Freezer instance with idempotency guards for freeze/thaw operations.
    /// Tracks which PIDs are currently frozen and enforces the configured
    /// freeze timeout. Wired into the supervisor loop so it persists across
    /// all events within a session (CR-7).
    ///
    /// Currently exposed for future use in idempotent freeze/thaw guards.
    /// The freeze timeout value is used by the queue reviewer.
    #[allow(dead_code)]
    pub(super) freezer: Freezer,
    /// Tracks recent per-fd reads for batch noise reduction.
    pub(super) read_batch_tracker: Mutex<ReadBatchTracker>,
    /// Reviewer implementation for digest items awaiting human review.
    pub(super) reviewer: Arc<dyn QueueReviewer>,
    /// Consecutive reviews that expired with no human answer.
    ///
    /// Reset to zero by any resolution a person is behind — a local answer, a
    /// notification channel, or a scope grant. Read by [`queue_and_wait`] to
    /// decide whether the operator is still at the keyboard; see
    /// `SupervisorConfig::unattended_review_streak`.
    pub(super) unanswered_reviews: Arc<AtomicU32>,
    /// Optional session-state sync target used to keep a shared registry up to date.
    pub(super) session_sync: Option<Arc<dyn SessionSync>>,
    /// Paths approved via "learn" during this session. Auto-allowed on
    /// subsequent accesses without going through the proxy.
    pub(super) session_allowed: Arc<Mutex<HashSet<String>>>,
    /// work/85: directory refusals the reviewer installed from the permission
    /// dialog's block action, as `deny-ro-prefix:` / `deny-write-prefix:` /
    /// `deny-delete-prefix:` entries.
    ///
    /// A separate set from `session_allowed` on purpose. A `deny-…` string
    /// living in the allowlist would be one missing namespace exclusion away
    /// from being read as a bare allow prefix by the catch-all matcher at the
    /// end of `is_session_allowlist_match` — an inverted security decision
    /// from a refactor that looked harmless. Two sets make that
    /// unrepresentable.
    pub(super) session_denied: Arc<Mutex<HashSet<String>>>,
    /// work/85: the workspace-only boundary, when
    /// `[supervisor.trust] restrict_to_workspace` (or `--workspace-only`) is
    /// on. `None` in every other session, which is the default.
    pub(super) workspace_boundary: Option<crate::workspace_only::WorkspaceBoundary>,
    /// Reverse DNS cache: resolves raw IPs from `connect()` syscalls
    /// to hostnames so the egress filter can match trusted domains.
    pub(super) dns_cache: Arc<Mutex<DnsCache>>,
    /// Whether in-line DNS inspection is active (query blocking + response
    /// observation). Gates the DoT deny and the in-line query evaluation.
    pub(super) dns_inspection_enabled: bool,
    /// Transport-neutral DNS policy service shared by the in-line and
    /// connected-proxy inspection owners.
    pub(super) dns_decision_service:
        Option<Arc<dyn crate::connected_dns_proxy::DnsDecisionService>>,
    /// Miss-triggered forward re-resolution of the session's trusted
    /// destinations, consulted before a `NetConnect` attribution miss turns
    /// into a raw-IP prompt. `None` in unit tests and for sessions without
    /// seed domains.
    pub(super) dns_forward_confirm: Option<crate::dns_cache::DnsForwardConfirm>,
    /// Optional file writer for logging every syscall request and decision.
    pub(super) syscall_log: Option<Mutex<std::io::BufWriter<std::fs::File>>>,
    /// Optional JSONL sink for pre-filter forensic tracing.
    pub(super) forensics_trace: Option<ForensicsTraceSink>,
    /// Feature-tuple reputation table for learned trust.
    /// Shared across sessions via Arc when daemon-owned.
    pub(super) reputation_table: Arc<Mutex<grith_proxy::reputation::ReputationTable>>,
    /// Reputation system configuration.
    pub(super) reputation_config: grith_proxy::reputation::ReputationConfig,
    /// Optional daemon URL for remote proxy evaluation.
    /// When set, proxy evaluation is delegated to the running daemon via HTTP.
    pub(super) daemon_proxy_url: Option<String>,
    /// Bearer token for daemon IPC authentication.
    pub(super) daemon_proxy_token: Option<Arc<Mutex<String>>>,
    /// Optional daemon restart state for fail-closed recovery.
    pub(super) daemon_restart: Option<Arc<DaemonRestartState>>,
    /// Final outcomes waiting to ride along with the next daemon evaluate.
    /// Only used in daemon mode, where the filters live in the daemon.
    pub(super) observation_outbox: Arc<remote_eval::ObservationOutbox>,
    /// Whether this session should persist its local reputation table to disk.
    pub(super) persist_local_reputation: bool,
    /// PR 4 Phase D: profile-declared routine_exec_roots, fully expanded
    /// at session start (globs walked, paths canonicalised, trailing
    /// slashes normalised). Consumed by `compute_spawn_provenance` to
    /// populate `SpawnProvenance.matched_routine_root` on every
    /// `ProcessSpawn`. Empty when the profile declares no roots or none
    /// resolve on this host.
    pub(super) routine_exec_roots: Vec<String>,
    /// Profile-declared `scratch_roots`, fully expanded at session start
    /// (trailing-slashed absolute prefixes). Consumed by the mass-destruction
    /// signal (`mass_destruction::is_valuable_out_of_tree`) to exclude routine
    /// scratch churn from the out-of-tree deletion count. (Previously also fed
    /// the `rate_limit` scratch burst exemption, retired in favour of
    /// risk-gating.)
    pub(super) scratch_roots: Vec<String>,
    /// work/83 F4: additional project roots this session trusts beyond the
    /// launch cwd — the launch repository's linked git worktrees plus any
    /// operator-declared `additional_project_roots`. Resolved ONCE at session
    /// start (never re-read: a mid-session re-read would let the supervised
    /// tool widen its own trust with `git worktree add`), canonicalised, with
    /// work/80's dangerous-root refusal applied and capped at
    /// `profiles::MAX_WORKSPACE_ROOTS`.
    ///
    /// Two consumers: the session allowlist (extended at session start with a
    /// `projdir:`-marked prefix per root, so the credential-store guard still
    /// applies) and the mass-destruction backstop, which counts deletions here
    /// as in-tree rather than as a spree.
    pub(super) workspace_roots: Vec<String>,
    /// PR 5 Phase C: session profile's declared local-IPC listener
    /// policy. Empty when the profile doesn't declare any entries —
    /// in which case every wildcard bind goes through the standard
    /// queue/deny path.
    pub(super) local_listener_policy: Vec<crate::profiles::LocalListenerEntry>,
    /// PR 6 Phase C: profile's declared `namespace_users` list — the
    /// canonical paths of binaries permitted to invoke `unshare(2)` /
    /// `setns(2)` silently when spawned from a `routine_exec_root`.
    /// Bwrap / bubblewrap / firejail / nsenter live here by default.
    pub(super) namespace_users: Vec<String>,
    /// Profile-declared basenames of authority-delegating binaries this
    /// session may spawn without the enforcement QUEUE (consulted only when
    /// `config.enforce_authority_delegating_spawn` is on). Empty permits none.
    pub(super) permit_authority_delegating: Vec<String>,
    /// Profile-declared control-injection socket path substrings this session
    /// may connect to without the enforcement QUEUE (consulted only when
    /// `config.enforce_control_socket_connect` is on). Empty permits none.
    pub(super) permit_control_sockets: Vec<String>,
    /// Whether D-Bus control-socket access is actually being decided per method
    /// call for this session — the interceptor confirmed it can see the writes,
    /// not merely that the config asked for it.
    ///
    /// Load-bearing distinction: an attach-mode session has no stepped-write
    /// path, so its bus writes are invisible. Suppressing the connect-time
    /// escalation on the strength of the config alone would turn "decide per
    /// message" into "decide never" there. Set at session start from
    /// `SyscallInterceptor::set_dbus_inspection`, which reports what the
    /// backend can really do.
    pub(super) dbus_inspection_armed: bool,
    /// Session identity pins for the curated authority-delegating binaries on
    /// `$PATH`. A ProcessSpawn whose canonical bytes hash into the pinned set
    /// is a copy/hardlink of a delegating binary regardless of its name. Sizes
    /// resolve at session start; hashes are built lazily on first real need,
    /// so an ordinary session never reads a docker-class binary. Empty unless
    /// `enforce_authority_delegating_spawn` was on at session start.
    pub(super) authority_delegating_pins: authority_delegation::AuthorityDelegatingPins,
    /// Session working root — the supervisor's cwd at session start, which the
    /// supervised tool inherits, i.e. the project the tool was pointed at. The
    /// mass-destruction signal uses it to classify deletes as in-tree (the
    /// agent's job, never flagged) vs out-of-tree (potentially a spree).
    /// `None` if the cwd could not be resolved.
    pub(super) working_root: Option<std::path::PathBuf>,
    /// Per-session sliding-window tracker for the target-aware
    /// mass-destruction signal (rate-limit-burst redesign step 2). Always
    /// present; recording is gated on [`mass_destruction::signal_enabled`].
    pub(super) mass_destruction: Mutex<mass_destruction::MassDestructionTracker>,
    /// YAMA `ptrace_scope` probed once at session start (`None` = Yama
    /// absent or the file unreadable, i.e. classic ptrace semantics). Used
    /// by the cross-process gate: at scope >= 2 the kernel refuses
    /// ptrace/process_vm for a caller without CAP_SYS_PTRACE, so a
    /// provably-doomed out-of-tree cross-process syscall is
    /// allowed-and-recorded rather than queued — a prompt cannot change an
    /// outcome the kernel has already decided. Probe failures fail toward
    /// enforcement.
    pub(super) yama_ptrace_scope: Option<u8>,
    /// Session-lifetime cache of the analytics config envelope. The envelope
    /// serializes and SHA-256-hashes the (immutable-per-session) supervisor
    /// config, which must not run per audit record on the syscall hot path.
    pub(super) analytics_config: std::sync::OnceLock<grith_audit::AuditConfigVersion>,
}

/// Minimum spacing between daemon restart attempts. Per-outage rather than
/// once-per-session: a session that loses the recovery race during one daemon
/// restart must still be able to recover from the next outage, but a flapping
/// daemon must not be restarted in a tight loop.
const DAEMON_RESTART_RETRY_COOLDOWN: Duration = Duration::from_secs(60);

pub(super) struct DaemonRestartState {
    config: DaemonRestartConfig,
    last_attempt: Mutex<Option<Instant>>,
}

impl DaemonRestartState {
    pub(super) fn new(config: DaemonRestartConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            last_attempt: Mutex::new(None),
        })
    }

    fn take_attempt(&self) -> bool {
        match self.last_attempt.lock() {
            Ok(mut last) => {
                let now = Instant::now();
                if last.is_some_and(|at| now.duration_since(at) < DAEMON_RESTART_RETRY_COOLDOWN) {
                    false
                } else {
                    *last = Some(now);
                    true
                }
            }
            Err(_) => false,
        }
    }

    /// Re-arm the restart budget after a healthy remote evaluation so the
    /// next outage gets an immediate recovery attempt.
    fn note_success(&self) {
        if let Ok(mut last) = self.last_attempt.lock() {
            *last = None;
        }
    }
}

// ---------------------------------------------------------------------------
// Syscall log file writer
// ---------------------------------------------------------------------------

/// Write a line to the syscall log file (if configured).
///
/// Format: `TIMESTAMP  DECISION  SCORE  PID  CALL_TYPE  REASON`
fn write_syscall_log(
    loop_ctx: &SupervisorLoopContext<'_>,
    pid: u32,
    call_type: &ToolCallType,
    score: f64,
    decision: &str,
    reason: &str,
) {
    if let Some(ref log) = loop_ctx.syscall_log {
        if let Ok(mut writer) = log.lock() {
            let ts = Utc::now().format("%H:%M:%S%.3f");
            let _ = writeln!(
                writer,
                "{ts}  {decision:<16}  {score:>5.1}  pid={pid:<8}  {call_type}  {reason}",
            );
            let _ = writer.flush();
        }
    }
}

fn write_forensics_stage(
    loop_ctx: &SupervisorLoopContext<'_>,
    event_id: Uuid,
    session: &SupervisorSession,
    pid: u32,
    call_type: Option<&ToolCallType>,
    stage: &'static str,
    decision: Option<&str>,
    score: Option<f64>,
    reason: Option<&str>,
) {
    if let Some(trace) = &loop_ctx.forensics_trace {
        trace.record_stage(
            event_id,
            session.id,
            session.root_pid,
            &session.process_tree,
            pid,
            call_type,
            stage,
            decision,
            score,
            reason,
        );
    }
}

/// Watchdog reporter: emit a `tracing::warn!` for each tracee that the
/// platform interceptor flagged as wedged in a ptrace stop.
///
/// `tracing` only, no audit-sink write: the wedge symptom is most
/// commonly triggered by audit-sink backpressure (the supervisor's hot
/// path blocked on synchronous SQLite writes), so writing more audit
/// rows during a wedge would compound the exact bottleneck we're
/// reporting on. Operators tailing the daemon log will see the warn
/// with full forensic context.
///
/// Per-tid dedup against `session.wedge_reported_tids` so a long-running
/// wedge produces one log line per (session, tid), not one per 10s
/// scan tick.
///
/// Observation-only: does not release the tracee. The whole point is to
/// keep live `/proc` state around for debugging until the operator
/// kills the session.
pub(super) async fn report_wedged_tracees(
    session: &mut SupervisorSession,
    _loop_ctx: &SupervisorLoopContext<'_>,
    wedged: &[crate::interceptor::WedgedTracee],
) {
    for w in wedged {
        if !session.wedge_reported_tids.insert(w.tid) {
            continue;
        }
        tracing::warn!(
            event = "tracee_wedge_detected",
            tid = w.tid,
            comm = %w.comm,
            state = %w.state,
            since_last_event_secs = w.since_last_event.as_secs(),
            last_event_kind = ?w.last_event_kind,
            syscall_info = %w.syscall_info,
            stack_summary = %w.stack_summary,
            signal_summary = %w.signal_summary,
            jobctl_stop_pending = w.jobctl_stop_pending,
            resume_primitive = %w.resume_primitive,
            is_thread = w.is_thread,
            in_syscall_stop = w.in_syscall_stop,
            "tracee wedged in ptrace stop — supervisor never released it; \
             session continues but this thread is stuck"
        );
    }
}

/// Variant name of a `SyscallKind` (e.g. `RawSocketCreate`, `IoUringSetup`),
/// for use as an audit `tool_call_type`. Derived from the Debug repr's leading
/// identifier so it stays in sync with the enum without a hand-maintained
/// match. Matches the dashboard's `baseType` convention (strips at `(`/`{`).
fn syscall_kind_label(kind: &SyscallKind) -> String {
    let dbg = format!("{kind:?}");
    let end = dbg.find([' ', '{', '(']).unwrap_or(dbg.len());
    dbg[..end].trim().to_string()
}

/// Record a supervisor-origin audit event for a syscall handled outside the
/// normal proxy pipeline (hard-deny / carveout / category-disabled paths).
///
/// `tool_call_type` is the real call-type dimension (e.g. `RawSocketCreate`) so
/// these records group correctly in the dashboard's Call Types breakdown. The
/// forensic `event_name` (e.g. `raw_socket_denied`) is recorded inside the
/// `arguments` object under `"event"` — it must NOT be used as the call type,
/// or it pollutes that dimension with decision tags.
async fn log_supervisor_audit_event(
    loop_ctx: &SupervisorLoopContext<'_>,
    session: &SupervisorSession,
    pid: u32,
    tool_call_type: &str,
    event_name: &str,
    action: grith_audit::types::ProxyActionSummary,
    mut arguments: serde_json::Value,
    reason: &str,
) {
    if let serde_json::Value::Object(map) = &mut arguments {
        map.insert(
            "event".into(),
            serde_json::Value::String(event_name.to_string()),
        );
    }
    // These hard-deny / carveout paths bypass the scoring pipeline, so there is
    // no computed composite score. A denial is maximally severe — surface it at
    // the top of the score scale so the dashboard's Evaluation Scores scatter
    // plots it in the DENY zone, not at score 0 (the bottom, with low-risk
    // allows). Allows/carveouts stay at 0.0.
    let composite_score = if matches!(&action, grith_audit::types::ProxyActionSummary::Deny) {
        10.0
    } else {
        0.0
    };
    // These records never pass through the proxy decision pipeline, so they
    // are `system`, not `decision` (the frozen contract reserves `decision`
    // for pipeline-evaluated calls). A hard-deny still surfaces on the
    // security-events plane via the security envelope below.
    let mut analytics =
        prospective_analytics_metadata(loop_ctx, session, RecordClass::System, tool_call_type);
    if matches!(&action, grith_audit::types::ProxyActionSummary::Deny) {
        analytics.security = Some(grith_audit::AuditSecurityMetadata {
            event_type: grith_analytics::contract::SecurityEventType::Deny,
            event_revision: 1,
            resolution_status: None,
            resolved_at: None,
            resolution_code: None,
            enforcement_outcome_code: Some(event_name.to_string()),
            gap_count: None,
        });
    }
    let mut record = AuditRecord::new(
        session.id,
        "supervisor".into(),
        tool_call_type.into(),
        &arguments,
        composite_score,
        action,
        Vec::new(),
        0.0,
        Some(reason.into()),
    )
    .with_supervisor_source(session.tool_name.clone(), pid)
    .with_project_name(session.project_name.clone())
    .with_analytics_metadata(analytics);
    record.execution_result = Some(reason.into());
    if let Err(e) = loop_ctx.audit_sink.log(record).await {
        tracing::error!(
            error = %e,
            event = event_name,
            "failed to log supervisor audit event"
        );
    }
}

/// Read a process's parent PID from `/proc/<tgid>/status`. `None` if the
/// process has already exited or the field can't be parsed.
fn read_ppid(tgid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{tgid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:")?.trim().parse().ok())
}

/// Backfill a spawn/provenance audit record for a process whose creation was
/// never tagged as a `ProcessSpawn`.
///
/// Two situations produce an untagged actor doing security-relevant work:
/// - **In-process engines that never `execve`.** An agent's code-execution
///   runtime can walk the filesystem with direct `openat`/`getdents` from its
///   own threads — there is no child process to record.
/// - **`posix_spawn`'d direct children whose exec event slipped past tagging.**
///   Exec tagging relies on a single `PTRACE_EVENT_EXEC` path; a
///   fork-then-immediately-exec child can race it.
///
/// Either way, enforcement still happened (every syscall was scored at the
/// boundary) — only the durable *provenance* link was missing. This records
/// that link, audit-only (`Allow`, score 0), reusing the supervisor-origin
/// audit path so it groups under `ProcessSpawn` in the dashboard. Best-effort:
/// a process that has already exited yields a `<pid:N>` placeholder rather than
/// failing. Runs at most once per process (deduped by the caller).
async fn synthesize_spawn_provenance(
    loop_ctx: &SupervisorLoopContext<'_>,
    session: &SupervisorSession,
    tgid: u32,
) {
    let command = std::fs::read_link(format!("/proc/{tgid}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| format!("<pid:{tgid}>"));
    let args: Vec<String> = std::fs::read(format!("/proc/{tgid}/cmdline"))
        .map(|data| {
            data.split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default();
    let ppid = read_ppid(tgid);

    // Match the `ToolCallType::ProcessSpawn` Display so these group with real
    // spawn rows in the dashboard's Call Types breakdown.
    let tool_call_type = format!("ProcessSpawn({} {})", command, args.join(" "));
    let arguments = serde_json::json!({
        "command": command,
        "args": args,
        "pid": tgid,
        "ppid": ppid,
        "synthesized": true,
    });

    log_supervisor_audit_event(
        loop_ctx,
        session,
        tgid,
        &tool_call_type,
        "synthesized_spawn_provenance",
        grith_audit::types::ProxyActionSummary::Allow,
        arguments,
        "provenance backfill: first security-relevant syscall from a process with no prior spawn record",
    )
    .await;
}

// ---------------------------------------------------------------------------
// YAMA ptrace-scope probe (cross-process gate refinement)
// ---------------------------------------------------------------------------

/// CAP_SYS_PTRACE bit index in the `/proc/<pid>/status` `CapEff` bitmask.
const CAP_SYS_PTRACE_BIT: u32 = 19;

/// Read the kernel's YAMA ptrace policy. Probed once per session and cached
/// on [`SupervisorLoopContext`] — the setting is a live sysctl, so it must
/// not be assumed stable across sessions. `None` = Yama absent or the file
/// unreadable (classic ptrace semantics apply); callers treat that like
/// scope 0/1, i.e. enforce.
pub(super) fn probe_yama_ptrace_scope() -> Option<u8> {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()?
        .trim()
        .parse::<u8>()
        .ok()
}

/// Parse the `CapEff` hex bitmask out of `/proc/<pid>/status` content.
fn parse_cap_eff(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix("CapEff:")?;
        u64::from_str_radix(rest.trim(), 16).ok()
    })
}

/// Whether task `id` (a pid or a tid — procfs resolves `/proc/<tid>/status`
/// to the individual thread, whose effective caps may differ from the
/// leader's) currently holds CAP_SYS_PTRACE in its effective set. `None`
/// when the status file is unreadable — callers must treat unknown as "may
/// hold it" (enforce).
pub(super) fn pid_has_cap_sys_ptrace(id: u32) -> Option<bool> {
    let status = std::fs::read_to_string(format!("/proc/{id}/status")).ok()?;
    Some(parse_cap_eff(&status)? & (1u64 << CAP_SYS_PTRACE_BIT) != 0)
}

/// The user-namespace identity of `pid` (the `user:[<inode>]` symlink
/// target). Readable only for same-uid (or capability-held) targets — an
/// unreadable link yields `None`, which callers treat as unverifiable.
fn pid_user_ns(pid: u32) -> Option<std::ffi::OsString> {
    std::fs::read_link(format!("/proc/{pid}/ns/user"))
        .ok()
        .map(std::path::PathBuf::into_os_string)
}

/// True when the kernel is *guaranteed* to EPERM a cross-process
/// ptrace/process_vm from `caller_tid` to `target_pid`, so queueing it
/// would prompt the user about an operation whose outcome is already
/// decided. Requires ALL of:
///
/// 1. YAMA scope >= 2 (admin-only / disabled) — below that, same-uid
///    access is kernel-legal and the proxy must evaluate it.
/// 2. The *calling thread* provably lacks CAP_SYS_PTRACE (effective set).
///    We key on the tid, not the thread-group leader: capabilities are
///    per-task, YAMA checks `current` (the issuing thread), and a worker
///    thread can hold a different effective set than the leader. Reading
///    the effective set is race-free because the calling thread is frozen
///    at the syscall-entry stop — it resumes directly into the intercepted
///    syscall and cannot `capset` permitted→effective in between, so a
///    permitted-but-not-effective cap genuinely stays blocked.
/// 3. Caller and target share a user namespace. A capability-less process
///    can still hold CAP_SYS_PTRACE *over a descendant user namespace it
///    owns* (e.g. a rootless container it created), so a cross-namespace
///    read cannot be assumed blocked. (A different-uid target's
///    `/proc/<pid>/ns/user` is unreadable → `None` → not suppressed, which
///    is the wanted outcome: an other-uid memory read is worth surfacing.)
///    User namespace is thread-group-wide, so probing it via the tid is
///    equivalent to the leader.
///
/// Every probe failure returns false — fail toward enforcement.
pub(super) fn kernel_blocks_cross_process(
    yama_scope: Option<u8>,
    caller_tid: u32,
    target_pid: u32,
) -> bool {
    let Some(scope) = yama_scope else {
        return false;
    };
    if scope < 2 {
        return false;
    }
    if pid_has_cap_sys_ptrace(caller_tid) != Some(false) {
        return false;
    }
    match (pid_user_ns(caller_tid), pid_user_ns(target_pid)) {
        (Some(caller_ns), Some(target_ns)) => caller_ns == target_ns,
        _ => false,
    }
}

/// The PID-namespace identity of task `id` (the `pid:[<inode>]` symlink
/// target). `None` when unreadable — callers treat unknown as unverifiable.
fn pid_pid_ns(id: u32) -> Option<std::ffi::OsString> {
    std::fs::read_link(format!("/proc/{id}/ns/pid"))
        .ok()
        .map(std::path::PathBuf::into_os_string)
}

/// True when a cross-process syscall's target provably does not exist, so
/// the kernel is guaranteed to answer ESRCH and the syscall can grant no
/// authority — prompting would only train the operator to mash approve
/// (test harnesses probe dead PIDs on purpose; grith's own dead-tracee
/// tests are the canonical flood).
///
/// Preconditions, all failing toward enforcement:
///
/// 1. The *caller* shares the supervisor's PID namespace. A tracee inside a
///    child pidns numbers processes differently, so our `/proc` view says
///    nothing about what ITS `target_pid` names — an absent
///    `/proc/<target>` here could be a live process there.
/// 2. `/proc/<target_pid>` does not exist (procfs resolves bare TIDs too,
///    so a live worker thread of any process counts as existing).
///    `target_pid == 0` also qualifies: no task is addressable as 0 from a
///    caller's view, the kernel ESRCHs it unconditionally.
///
/// TOCTOU: the pid could be allocated to a *new* process between this probe
/// and syscall resumption. The window is the microseconds the caller spends
/// frozen at its syscall-entry stop, the caller cannot influence which
/// process receives a recycled pid, and the suppression is audit-recorded —
/// same accepted trade as PR 3's failed-exec pre-stat.
fn cross_process_target_provably_absent(caller_tid: u32, target_pid: u32) -> bool {
    match (pid_pid_ns(caller_tid), pid_pid_ns(std::process::id())) {
        (Some(caller_ns), Some(own_ns)) if caller_ns == own_ns => {}
        _ => return false,
    }
    if target_pid == 0 {
        return true;
    }
    !std::path::Path::new(&format!("/proc/{target_pid}")).exists()
}

// ---------------------------------------------------------------------------
// Core event handler
// ---------------------------------------------------------------------------

pub(super) async fn handle_syscall_event(
    interceptor: &mut Box<dyn SyscallInterceptor>,
    session: &mut SupervisorSession,
    loop_ctx: &SupervisorLoopContext<'_>,
    event: SyscallEvent,
) -> Result<()> {
    session.stats.tick();
    let trace_event_id = Uuid::new_v4();

    if let Some(trace) = &loop_ctx.forensics_trace {
        trace.capture_syscall(
            trace_event_id,
            session.id,
            session.root_pid,
            &session.process_tree,
            &event,
        );
    }

    // Provenance backfill. The first time we see security-relevant activity
    // from a process (keyed by TGID), guarantee it has a spawn record. When a
    // real `ProcessExec` is the first thing we see, the normal path below
    // audits it — we only mark the TGID so we don't double-log. When the first
    // thing we see is anything else (its exec was never tagged, or it never
    // exec'd — an in-process code engine), synthesize the provenance record.
    // `HashSet::insert` returns true only on first insertion, so this fires at
    // most once per process. `pid == 0` is a pre-assignment fork placeholder.
    // Short-circuit `&&` still runs `insert` (marking the TGID seen) for a
    // real exec, so we don't re-synthesize once its normal record lands.
    if event.pid != 0
        && session.spawn_recorded.insert(event.pid)
        && !matches!(event.kind, SyscallKind::ProcessExec { .. })
    {
        synthesize_spawn_provenance(loop_ctx, session, event.pid).await;
    }

    // Update the process tree with fork events.
    if let SyscallKind::ProcessFork { child_pid } = &event.kind {
        if *child_pid == 0 {
            tracing::trace!(
                session_id = %session.id,
                parent_pid = event.pid,
                "fork/clone syscall observed before child PID assignment"
            );
        } else if let Err(e) = session.process_tree.add_child(
            event.pid,
            *child_pid,
            format!("fork-from-{}", event.pid),
        ) {
            tracing::warn!(
                session_id = %session.id,
                parent_pid = event.pid,
                child_pid = *child_pid,
                error = %e,
                "failed to add child to process tree (parent may not be tracked yet)"
            );
        }
    }

    // Use the TID (thread ID) for all ptrace operations — on Linux,
    // waitpid returns the TID of the stopped thread, not the TGID.
    // Using the TGID would fail to resume the correct thread in
    // multi-threaded programs (e.g. Node.js / Claude Code).
    let tid = event.tid;

    // ---- In-line DNS owner ----
    // These events come only from unconnected or explicit-destination DNS
    // sends. Connected-proxy sockets bypass this query/response state in the
    // interceptor and are evaluated in their route worker. Here we (a) block
    // DNS-over-TLS so encrypted DNS cannot dodge inspection, and (b) evaluate
    // the stashed in-line query and block a disallowed send.
    if loop_ctx.dns_inspection_enabled {
        let port = match &event.kind {
            SyscallKind::NetConnect { port, .. } | SyscallKind::NetSendTo { port, .. } => {
                Some(*port)
            }
            _ => None,
        };

        // Force plaintext DNS: block DNS-over-TLS (853) so it stays inspectable.
        if port == Some(853) {
            tracing::debug!(tid, "blocking DoT (port 853) — DNS inspection on");
            if let Err(e) = interceptor.deny(tid).await {
                tracing::warn!(error = %e, tid, "deny (DoT block) failed");
            }
            return Ok(());
        }

        // Block TCP-DNS: this :53 connect is on a stream (TCP) socket, whose
        // query/response ride write/read and can't be content-inspected.
        // Denying forces resolution onto the inspected UDP path so query
        // blocking isn't bypassable (gated by block_tcp_dns).
        if port == Some(53) && interceptor.take_tcp_dns_deny(tid) {
            tracing::debug!(tid, "blocking TCP-DNS connect — forcing inspected UDP path");
            if let Err(e) = interceptor.deny(tid).await {
                tracing::warn!(error = %e, tid, "deny (TCP-DNS block) failed");
            }
            return Ok(());
        }

        // In-line DNS query inspection. The interceptor stashed the parsed
        // (domain, qtype) for a send on a tracked DNS socket; evaluate it and
        // block the send (EPERM) for a denied domain — the query never leaves.
        if matches!(event.kind, SyscallKind::NetSendTo { .. }) {
            if let Some(inspection) = interceptor.take_dns_query(tid) {
                if let Some(reason) = inspection.parse_error {
                    interceptor.finish_dns_query(tid, false);
                    tracing::warn!(
                        pid = event.pid,
                        tid,
                        reason,
                        "denying uninspectable outbound DNS traffic"
                    );
                    write_forensics_stage(
                        loop_ctx,
                        trace_event_id,
                        session,
                        event.pid,
                        None,
                        "denied",
                        Some("auto-deny"),
                        None,
                        Some(&reason),
                    );
                    if let Err(e) = interceptor.deny(tid).await {
                        tracing::warn!(error = %e, tid, "deny (DNS parse failure) failed");
                    }
                    return Ok(());
                }

                let mut allow = true;
                for (domain, query_type) in &inspection.queries {
                    if !evaluate_dns_query_inline(
                        session, loop_ctx, event.pid, tid, domain, query_type,
                    )
                    .await
                    {
                        allow = false;
                        break;
                    }
                }
                if allow && !inspection.queries.is_empty() {
                    interceptor.finish_dns_query(tid, true);
                    if let Err(e) = interceptor.allow(tid).await {
                        tracing::warn!(error = %e, tid, "allow (DNS query) failed");
                    }
                } else {
                    interceptor.finish_dns_query(tid, false);
                    if let Err(e) = interceptor.deny(tid).await {
                        tracing::warn!(error = %e, tid, "deny (DNS query block) failed");
                    }
                }
                return Ok(());
            }
        }
    }

    // Hard-deny io_uring before proxy evaluation.
    //
    // io_uring submissions bypass the per-syscall ptrace stop model: I/O
    // queued in the ring buffer executes without individual entry stops,
    // making file reads, writes, and network operations invisible to grith.
    // Denying io_uring_setup prevents ring creation entirely. io_uring_enter
    // and io_uring_register are denied as defence-in-depth.
    //
    // Node.js/libuv falls back to epoll + standard syscalls on EPERM, so
    // this has no practical compatibility cost for supervised AI tools.
    if matches!(&event.kind, SyscallKind::IoUringSetup) {
        write_forensics_stage(
            loop_ctx,
            trace_event_id,
            session,
            event.pid,
            None,
            "denied",
            Some("auto-deny"),
            None,
            Some("io_uring denied"),
        );
        tracing::warn!(
            pid = event.pid,
            tid,
            syscall_nr = event.raw_syscall_nr,
            "io_uring denied — ring-buffer I/O bypasses syscall interception"
        );
        log_supervisor_audit_event(
            loop_ctx,
            session,
            event.pid,
            &syscall_kind_label(&event.kind),
            "io_uring_denied",
            grith_audit::types::ProxyActionSummary::Deny,
            serde_json::json!({
                "pid": event.pid,
                "tid": tid,
                "syscall_nr": event.raw_syscall_nr,
            }),
            "io_uring denied before proxy evaluation",
        )
        .await;
        if let Err(e) = interceptor.deny(tid).await {
            tracing::warn!(error = %e, tid, "deny (io_uring) failed");
        }
        return Ok(());
    }

    // Hard-deny raw socket creation before proxy evaluation.
    //
    // AF_PACKET and AF_NETLINK sockets bypass the normal IP stack: a process
    // holding one can capture or inject arbitrary link-layer frames or manipulate
    // kernel subsystems directly. No legitimate supervised AI tool requires this
    // capability. Denying at socket() creation time is earlier and more reliable
    // than waiting for connect()/sendto() — the socket fd never exists.
    if let SyscallKind::RawSocketCreate { domain, .. } = &event.kind {
        write_forensics_stage(
            loop_ctx,
            trace_event_id,
            session,
            event.pid,
            None,
            "denied",
            Some("auto-deny"),
            None,
            Some("raw socket denied"),
        );
        tracing::warn!(
            pid = event.pid,
            tid,
            domain = *domain,
            syscall_nr = event.raw_syscall_nr,
            "raw socket denied — AF_PACKET/AF_NETLINK bypasses IP stack"
        );
        log_supervisor_audit_event(
            loop_ctx,
            session,
            event.pid,
            &syscall_kind_label(&event.kind),
            "raw_socket_denied",
            grith_audit::types::ProxyActionSummary::Deny,
            serde_json::json!({
                "pid": event.pid,
                "tid": tid,
                "domain": *domain,
                "syscall_nr": event.raw_syscall_nr,
            }),
            "raw socket denied before proxy evaluation",
        )
        .await;
        if let Err(e) = interceptor.deny(tid).await {
            tracing::warn!(error = %e, tid, "deny (raw socket) failed");
        }
        return Ok(());
    }

    // PR 6 Phase F: per-category coverage flags. When a category is
    // disabled, its syscalls fall through as "not security-relevant"
    // (matching pre-PR-6 behaviour) — allow + return BEFORE the
    // hard-deny / carveout / routing logic below sees the syscall.
    //
    // Defaults: categories 1 & 4 ON; categories 2 & 3 OFF (calibration
    // window for chown/mount/ptrace + namespace primitives).
    {
        let coverage = &loop_ctx.config.coverage;
        let pr6_category_off = match &event.kind {
            SyscallKind::KernelModuleOp { .. } | SyscallKind::KexecLoad { .. } => {
                !coverage.category1_hard_deny
            }
            SyscallKind::OwnershipChange { .. } | SyscallKind::FilesystemMutation { .. } => {
                !coverage.category2_proxy
            }
            // Cross-process access (ptrace / process_vm) is split onto its own
            // flag: enforced by default because supervised coding tools never
            // read/debug another process's memory, so it is ~0 false positives
            // and closes the scope-0 secret-theft path. process_vm-of-self is
            // already carved out upstream in classify.
            SyscallKind::CrossProcessAccess { .. } => !coverage.category2_crossprocess,
            SyscallKind::NamespaceOp { .. } => !coverage.category3_namespace,
            SyscallKind::ArchPrivilegedOp { .. } => !coverage.category4_arch_priv,
            _ => false,
        };
        if pr6_category_off {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                None,
                "noise_filtered",
                Some("auto-allow"),
                None,
                Some("PR 6 category disabled"),
            );
            session.stats.total_filtered_noise += 1;
            log_supervisor_audit_event(
                loop_ctx,
                session,
                event.pid,
                &syscall_kind_label(&event.kind),
                "pr6_category_disabled_allowed",
                grith_audit::types::ProxyActionSummary::Allow,
                serde_json::json!({
                    "pid": event.pid,
                    "tid": tid,
                    "syscall_nr": event.raw_syscall_nr,
                    "kind": format!("{:?}", &event.kind),
                }),
                "PR 6 coverage category disabled; allowed without proxy evaluation",
            )
            .await;
            if let Err(e) = interceptor.allow(tid).await {
                tracing::warn!(error = %e, tid, "allow (PR 6 category disabled) failed");
            }
            return Ok(());
        }
    }

    // PR 6 cross-process refinement (category2_crossprocess). ptrace /
    // process_vm against a target INSIDE grith's supervised tree is not a
    // cross-boundary secret-theft primitive: the target already lives in the
    // session sandbox the user launched, and a descendant-to-descendant
    // ptrace-attach is EPERM'd anyway because grith holds the tracer slot.
    // Sanitizers (LeakSanitizer's StopTheWorld `process_vm_readv` at every
    // ASan/LSan test-binary exit), crash handlers and fork/trace test
    // harnesses all read a descendant/sibling, so QUEUEing them would flood
    // the user with prompts for zero security gain. Allow-and-record those.
    //
    // Only a read of a target OUTSIDE the tree falls through to the proxy and
    // QUEUEs — another same-uid app holding decrypted secrets (the scope-0
    // exfil path the kernel does NOT block; `process_vm_readv` needs no tracer
    // slot), or the supervisor's own memory (grith is the tracer/parent, never
    // in its own `supervised` set → correctly non-descendant). `supervised_pids()`
    // is the full PID+TID set, so a sibling worker-thread tid is recognised as
    // in-tree.
    //
    // Fail-safe: a brand-new sibling whose clone event grith has not yet
    // processed is treated as out-of-tree → a transient QUEUE, never a missed
    // read. `target_pid` is a register scalar, not a pointer, so there is no
    // check-vs-use TOCTOU. PTRACE_TRACEME is already carved in classify.
    if let SyscallKind::CrossProcessAccess { op, target_pid } = &event.kind {
        let in_tree = *target_pid != 0 && interceptor.supervised_pids().contains(target_pid);
        // pidfd_getfd carries no pid argument; classify resolved the target
        // from the pidfd's fdinfo and used 0 when it could not (fdinfo
        // unreadable, not a real pidfd, or a target invisible in grith's pid
        // namespace). Unlike a genuine 0 pid argument to ptrace/process_vm —
        // which the kernel unconditionally ESRCHs — an *unresolved* pidfd
        // target must fail closed: skip the "provably dead" auto-allow below so
        // it reaches the proxy and QUEUEs. (`kernel_blocks_cross_process`
        // already returns false for pid 0, so only the dead-target check needs
        // this guard; the in-tree branch already excludes 0.)
        let pidfd_unknown_target = matches!(op, CrossProcessOp::PidfdGetfd) && *target_pid == 0;
        if in_tree {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                None,
                "noise_filtered",
                Some("auto-allow"),
                None,
                Some("cross-process in-tree"),
            );
            session.stats.total_filtered_noise += 1;
            log_supervisor_audit_event(
                loop_ctx,
                session,
                event.pid,
                &syscall_kind_label(&event.kind),
                "cross_process_intree_allowed",
                grith_audit::types::ProxyActionSummary::Allow,
                serde_json::json!({
                    "pid": event.pid,
                    "tid": tid,
                    "op": format!("{op:?}"),
                    "target_pid": target_pid,
                }),
                "cross-process access to an in-tree target; allowed without proxy evaluation",
            )
            .await;
            if let Err(e) = interceptor.allow(tid).await {
                tracing::warn!(error = %e, tid, "allow (cross-process in-tree) failed");
            }
            return Ok(());
        }

        // Dead-target refinement: a cross-process syscall aimed at a PID
        // that does not exist can only get ESRCH from the kernel — no
        // authority is at stake, so a prompt cannot change the outcome.
        // Applies at any YAMA scope (unlike the kernel-blocked check
        // below). Guarded on the caller sharing our PID namespace; see
        // `cross_process_target_provably_absent` for the TOCTOU trade.
        if !pidfd_unknown_target && cross_process_target_provably_absent(tid, *target_pid) {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                None,
                "noise_filtered",
                Some("auto-allow"),
                None,
                Some("cross-process dead target"),
            );
            session.stats.total_filtered_noise += 1;
            log_supervisor_audit_event(
                loop_ctx,
                session,
                event.pid,
                &syscall_kind_label(&event.kind),
                "cross_process_dead_target_allowed",
                grith_audit::types::ProxyActionSummary::Allow,
                serde_json::json!({
                    "pid": event.pid,
                    "tid": tid,
                    "op": format!("{op:?}"),
                    "target_pid": target_pid,
                }),
                "cross-process access to a nonexistent process; the kernel will answer ESRCH — allowed without prompting",
            )
            .await;
            if let Err(e) = interceptor.allow(tid).await {
                tracing::warn!(error = %e, tid, "allow (cross-process dead-target) failed");
            }
            return Ok(());
        }

        // Scope-probe refinement: an out-of-tree cross-process syscall the
        // kernel is guaranteed to EPERM (YAMA scope >= 2, the calling thread
        // provably uncapped, same user namespace) is allowed-and-recorded
        // instead of queued — the prompt cannot change an outcome the kernel
        // already decided, and in non-interactive exec it would hang forever.
        // Any probe failure falls through to the proxy (fail toward
        // enforcement). We pass `tid` (the syscall-issuing thread), not
        // `event.pid`: capabilities are per-task and YAMA checks the calling
        // thread, so the leader's caps are the wrong ones to consult.
        //
        // The scope is probed once at session start and cached; a mid-session
        // sysctl lowering (2 -> 0) could stale this toward suppression, but
        // writing `ptrace_scope` needs root outside the supervised tool's
        // reach (the tool's own write would be EPERM'd and proxy-scored), so
        // it is out of the tool's threat model — the same session-start
        // granularity grith uses for the listener-clamp capability probe.
        if kernel_blocks_cross_process(loop_ctx.yama_ptrace_scope, tid, *target_pid) {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                None,
                "noise_filtered",
                Some("auto-allow"),
                None,
                Some("cross-process kernel-blocked"),
            );
            session.stats.total_filtered_noise += 1;
            log_supervisor_audit_event(
                loop_ctx,
                session,
                event.pid,
                &syscall_kind_label(&event.kind),
                "cross_process_kernel_blocked_allowed",
                grith_audit::types::ProxyActionSummary::Allow,
                serde_json::json!({
                    "pid": event.pid,
                    "tid": tid,
                    "op": format!("{op:?}"),
                    "target_pid": target_pid,
                    "yama_ptrace_scope": loop_ctx.yama_ptrace_scope,
                }),
                "cross-process access the kernel will refuse (YAMA scope >= 2, caller without CAP_SYS_PTRACE); allowed without proxy evaluation",
            )
            .await;
            if let Err(e) = interceptor.allow(tid).await {
                tracing::warn!(error = %e, tid, "allow (cross-process kernel-blocked) failed");
            }
            return Ok(());
        }
    }

    // Self-filter defence (go-live review round 2). A tracee that installs
    // its own seccomp filter can out-rank grith's SECCOMP_RET_TRACE:
    // SECCOMP_RET_USER_NOTIF (0x7fc00000) wins over TRACE (0x7ff00000) on
    // action precedence, and by answering its own notifications with
    // USER_NOTIF_FLAG_CONTINUE the tracee runs syscalls grith never sees.
    //
    // The NEW_LISTENER install is the escape and is denied (fail-closed:
    // seccomp() returns EPERM, no listener fd exists). A plain filter cannot
    // grant authority — it can only make the tracee's own syscalls fail
    // invisibly — so it is observed only when the operator asks, and
    // otherwise allowed. Both branches are register-only decisions, immune to
    // the argument-rewrite TOCTOU that pointer-carried syscalls have.
    if let SyscallKind::SeccompInstall { via, new_listener } = &event.kind {
        let deny = *new_listener && loop_ctx.config.coverage.deny_self_seccomp_notify;
        if deny {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                None,
                "denied",
                Some("auto-deny"),
                None,
                Some("self seccomp NEW_LISTENER denied"),
            );
            tracing::warn!(
                event = "self_seccomp_notify_denied",
                pid = event.pid,
                tid,
                via = ?via,
                "denied a tracee's own seccomp NEW_LISTENER filter — it would out-rank grith's interception",
            );
            log_supervisor_audit_event(
                loop_ctx,
                session,
                event.pid,
                &syscall_kind_label(&event.kind),
                "self_seccomp_notify_denied",
                grith_audit::types::ProxyActionSummary::Deny,
                serde_json::json!({
                    "pid": event.pid,
                    "tid": tid,
                    "via": format!("{via:?}"),
                    "new_listener": new_listener,
                }),
                "tracee seccomp NEW_LISTENER filter denied before it could hide syscalls",
            )
            .await;
            if let Err(e) = interceptor.deny(tid).await {
                tracing::warn!(error = %e, tid, "deny (self seccomp notify) failed");
            }
            return Ok(());
        }

        // Not the escape form. Record it if the operator is observing filter
        // installs; either way, allow — a plain filter cannot escape the
        // sandbox, and denying every self-filter would break bwrap, Electron
        // and Node/Bun sandboxes.
        if loop_ctx.config.coverage.observe_self_seccomp_filter {
            log_supervisor_audit_event(
                loop_ctx,
                session,
                event.pid,
                &syscall_kind_label(&event.kind),
                "self_seccomp_filter_observed",
                grith_audit::types::ProxyActionSummary::Allow,
                serde_json::json!({
                    "pid": event.pid,
                    "tid": tid,
                    "via": format!("{via:?}"),
                    "new_listener": new_listener,
                }),
                "tracee installed its own seccomp filter (audit-only; can blind but not escape)",
            )
            .await;
        }
        if let Err(e) = interceptor.allow(tid).await {
            tracing::warn!(error = %e, tid, "allow (self seccomp filter) failed");
        }
        return Ok(());
    }

    // Go-live review B1: hard-deny foreign-ABI syscalls before any
    // classification or proxy evaluation. The seccomp filter fails
    // closed on a non-x86_64 audit arch or x32 numbering; the raw
    // number belongs to a foreign syscall table, so nothing downstream
    // may interpret it. Unconditional — no coverage flag gates this.
    if let SyscallKind::ForeignAbiSyscall { abi, raw_nr } = &event.kind {
        // Throttle the durable record: a tracee can loop a foreign-ABI
        // syscall ~30k/s, and each grants no authority (all denied), so an
        // un-throttled record floods the bounded audit channel and evicts
        // genuine evidence — audit blinding on demand. The counter records
        // the true total; records are written for the first few and then
        // exponentially sparser.
        let should_audit = session.stats.record_foreign_abi_denial();
        if should_audit {
            let total = session.stats.foreign_abi_denied;
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                None,
                "denied",
                Some("auto-deny"),
                None,
                Some("foreign-ABI syscall denied"),
            );
            tracing::warn!(
                event = "foreign_abi_syscall_denied",
                pid = event.pid,
                tid,
                abi = ?abi,
                raw_nr,
                session_total = total,
                "foreign-ABI syscall denied — the supervisor cannot interpret non-x86_64 syscall numbers and never allows what it cannot interpret",
            );
            log_supervisor_audit_event(
                loop_ctx,
                session,
                event.pid,
                &syscall_kind_label(&event.kind),
                "foreign_abi_syscall_denied",
                grith_audit::types::ProxyActionSummary::Deny,
                serde_json::json!({
                    "pid": event.pid,
                    "tid": tid,
                    "abi": format!("{abi:?}"),
                    "raw_syscall_nr": raw_nr,
                    "session_total": total,
                }),
                "foreign-ABI syscall denied before classification; seccomp arch check failed closed",
            )
            .await;
        }
        if let Err(e) = interceptor.deny(tid).await {
            tracing::warn!(error = %e, tid, "deny (foreign ABI) failed");
        }
        return Ok(());
    }

    // PR 6 Phase A: hard-deny kernel-module load/unload before proxy
    // evaluation. Mirrors the io_uring and raw-socket pattern.
    // Supervised AI tools never need to load or unload kernel modules
    // — these syscalls require CAP_SYS_MODULE and would only matter
    // on a tool with elevated privilege, where they could replace
    // kernel code wholesale.
    if let SyscallKind::KernelModuleOp { op } = &event.kind {
        write_forensics_stage(
            loop_ctx,
            trace_event_id,
            session,
            event.pid,
            None,
            "denied",
            Some("auto-deny"),
            None,
            Some("kernel-module op denied"),
        );
        tracing::warn!(
            event = "kernel_module_op_denied",
            pid = event.pid,
            tid,
            op = ?op,
            syscall_nr = event.raw_syscall_nr,
            "kernel-module {op:?} denied — supervised tools must not modify the running kernel",
        );
        log_supervisor_audit_event(
            loop_ctx,
            session,
            event.pid,
            &syscall_kind_label(&event.kind),
            "kernel_module_op_denied",
            grith_audit::types::ProxyActionSummary::Deny,
            serde_json::json!({
                "pid": event.pid,
                "tid": tid,
                "op": format!("{op:?}"),
                "syscall_nr": event.raw_syscall_nr,
            }),
            "kernel-module syscall denied before proxy evaluation",
        )
        .await;
        if let Err(e) = interceptor.deny(tid).await {
            tracing::warn!(error = %e, tid, "deny (kernel module) failed");
        }
        return Ok(());
    }

    // PR 6 Phase C: namespace primitive carveout for sandbox tools.
    //
    // The supervised tool's bootstrap may run `bwrap` (or
    // bubblewrap/firejail/nsenter) to set up its own user/mount
    // namespace. Those binaries legitimately call
    // `unshare(CLONE_NEWUSER | CLONE_NEWNS | …)`. Without this
    // carveout, every Codex/Claude startup would queue dozens of
    // such calls.
    //
    // The carveout requires BOTH:
    //   1. The calling binary's canonical path is on the profile's
    //      `namespace_users` list.
    //   2. That same canonical path is under a `routine_exec_root`.
    //
    // We resolve the canonical path of the calling process via
    // /proc/<pid>/exe. If we can't read it (e.g. process exited),
    // we fall through to the proxy → standard QUEUE path. The
    // standard path is fail-safe: an attacker that can't be
    // identified gets queued, not auto-allowed.
    if let SyscallKind::NamespaceOp { syscall, flags } = &event.kind {
        let allowed = if loop_ctx.namespace_users.is_empty() {
            false
        } else {
            match std::fs::canonicalize(format!("/proc/{}/exe", event.pid)) {
                Ok(canonical) => {
                    let canon_str = canonical.to_string_lossy().into_owned();
                    let in_namespace_users = loop_ctx
                        .namespace_users
                        .iter()
                        .any(|allowed| allowed == &canon_str);
                    let in_routine_root = loop_ctx.routine_exec_roots.iter().any(|root| {
                        let trimmed = root.trim_end_matches('/');
                        canon_str
                            .strip_prefix(trimmed)
                            .is_some_and(|rest| rest.starts_with('/'))
                            || canon_str == trimmed
                    });
                    in_namespace_users && in_routine_root
                }
                Err(_) => false,
            }
        };
        if allowed {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                None,
                "noise_filtered",
                Some("auto-allow"),
                None,
                Some("namespace_users carveout"),
            );
            tracing::info!(
                event = "namespace_op_carveout_allowed",
                pid = event.pid,
                tid,
                syscall = ?syscall,
                flags = format_args!("{flags:#x}"),
                "namespace primitive allowed by namespace_users carveout",
            );
            session.stats.total_filtered_noise += 1;
            log_supervisor_audit_event(
                loop_ctx,
                session,
                event.pid,
                &syscall_kind_label(&event.kind),
                "namespace_op_carveout_allowed",
                grith_audit::types::ProxyActionSummary::Allow,
                serde_json::json!({
                    "pid": event.pid,
                    "tid": tid,
                    "syscall": format!("{syscall:?}"),
                    "flags": format!("{flags:#x}"),
                    "syscall_nr": event.raw_syscall_nr,
                }),
                "namespace primitive allowed by namespace_users carveout",
            )
            .await;
            if let Err(e) = interceptor.allow(tid).await {
                tracing::warn!(error = %e, tid, "allow (namespace carveout) failed");
            }
            return Ok(());
        }
        // else: fall through to standard proxy evaluation. The proxy's
        // operation-risk filter scores NamespaceOp at +5.0 → QUEUE.
    }

    // PR 6 Phase D: hard-deny architecture-specific privileged ops.
    // Each represents a host-wide authority change that no supervised
    // AI tool has any reason to attempt: sethostname/setdomainname
    // (global identity), iopl/ioperm (raw I/O ports), swapon/swapoff
    // (kernel resource management), reboot (obvious). If a tool is
    // calling these, it's either a bug or an exploit.
    if let SyscallKind::ArchPrivilegedOp { op } = &event.kind {
        write_forensics_stage(
            loop_ctx,
            trace_event_id,
            session,
            event.pid,
            None,
            "denied",
            Some("auto-deny"),
            None,
            Some("arch-privileged op denied"),
        );
        tracing::warn!(
            event = "arch_privileged_op_denied",
            pid = event.pid,
            tid,
            op = ?op,
            syscall_nr = event.raw_syscall_nr,
            "arch-privileged {op:?} denied — host-wide authority change",
        );
        log_supervisor_audit_event(
            loop_ctx,
            session,
            event.pid,
            &syscall_kind_label(&event.kind),
            "arch_privileged_op_denied",
            grith_audit::types::ProxyActionSummary::Deny,
            serde_json::json!({
                "pid": event.pid,
                "tid": tid,
                "op": format!("{op:?}"),
                "syscall_nr": event.raw_syscall_nr,
            }),
            "arch-privileged syscall denied before proxy evaluation",
        )
        .await;
        if let Err(e) = interceptor.deny(tid).await {
            tracing::warn!(error = %e, tid, "deny (arch privileged) failed");
        }
        return Ok(());
    }

    // PR 6 Phase A: hard-deny kexec — staging a replacement kernel for
    // next boot is the most extreme form of authority change a process
    // can attempt. No supervised dev tool has any reason to do this.
    if let SyscallKind::KexecLoad { from_fd } = &event.kind {
        write_forensics_stage(
            loop_ctx,
            trace_event_id,
            session,
            event.pid,
            None,
            "denied",
            Some("auto-deny"),
            None,
            Some("kexec denied"),
        );
        tracing::warn!(
            event = "kexec_load_denied",
            pid = event.pid,
            tid,
            from_fd = *from_fd,
            syscall_nr = event.raw_syscall_nr,
            "kexec denied — supervised tools must not stage replacement kernels",
        );
        log_supervisor_audit_event(
            loop_ctx,
            session,
            event.pid,
            &syscall_kind_label(&event.kind),
            "kexec_load_denied",
            grith_audit::types::ProxyActionSummary::Deny,
            serde_json::json!({
                "pid": event.pid,
                "tid": tid,
                "from_fd": *from_fd,
                "syscall_nr": event.raw_syscall_nr,
            }),
            "kexec syscall denied before proxy evaluation",
        )
        .await;
        if let Err(e) = interceptor.deny(tid).await {
            tracing::warn!(error = %e, tid, "deny (kexec) failed");
        }
        return Ok(());
    }

    // ---- Map syscall to ToolCallType ----
    let call_type = match syscall_map::to_tool_call_type(&event.kind) {
        Some(ct) => ct,
        None => {
            // Not security-relevant -- let the syscall through silently.
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                None,
                "noise_filtered",
                Some("auto-allow"),
                None,
                Some("not security-relevant"),
            );
            session.stats.total_filtered_noise += 1;
            if let Err(e) = interceptor.allow(tid).await {
                tracing::warn!(error = %e, tid, "allow (noise) failed");
            }
            return Ok(());
        }
    };

    // Update process tree command name on exec — when a fork-child calls
    // execve(), replace the placeholder "fork-from-{pid}" with the actual binary.
    if let grith_proxy::types::ToolCallType::ProcessSpawn { command, args } = &call_type {
        let name = std::path::Path::new(command.as_str())
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(command.as_str());
        session
            .process_tree
            .update_command(event.pid, name, args.clone());

        // Authority-delegating binary spawn (docker/kubectl/tmux/systemctl/
        // systemd-run/dbus-send/…): its effect runs in a privileged or
        // unsupervised peer, outside the supervised tree — the
        // `systemd-run --user … -- <cmd>` supervision-escape class. When
        // enforcement is off this is audit-only (detected, logged, allowed).
        // When on and the profile has not permitted the binary, the actual
        // Allow→QUEUE escalation happens after proxy evaluation below; here we
        // only tag the forensic trace so the two states are distinguishable.
        if authority_delegation::is_authority_delegating_binary(command) {
            let will_enforce = authority_delegation::spawn_enforcement_enabled(
                loop_ctx.config.enforce_authority_delegating_spawn,
            ) && authority_delegation::spawn_should_escalate(
                command,
                args,
                &loop_ctx.permit_authority_delegating,
            );
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                Some(&call_type),
                "authority_delegating_spawn",
                Some(if will_enforce {
                    "enforce-queue"
                } else {
                    "audit-only-allow"
                }),
                None,
                Some("spawn of an authority-delegating binary (effect runs in a privileged peer)"),
            );
            tracing::debug!(
                command = %command,
                tid,
                will_enforce,
                "authority-delegating binary spawn"
            );
        }
    }

    // Hard-deny writes to grith's own configuration files.
    //
    // A supervised tool must never modify grith's configuration, learned rules,
    // reputation data, or credentials. This is a self-protection invariant:
    // the security boundary's own state must not be writable by the tool it
    // supervises. A prompt injection that can write to these files could silently
    // weaken enforcement for all future sessions.
    {
        let is_grith_config_write = match &call_type {
            grith_proxy::types::ToolCallType::FileWrite { path, .. }
            | grith_proxy::types::ToolCallType::FileAppend { path }
            | grith_proxy::types::ToolCallType::FileDelete { path }
            | grith_proxy::types::ToolCallType::FileChmod { path, .. }
            | grith_proxy::types::ToolCallType::DirCreate { path }
            | grith_proxy::types::ToolCallType::OwnershipChange { target: path, .. }
            | grith_proxy::types::ToolCallType::FilesystemMutation { target: path, .. } => {
                let p = path.to_lowercase();
                p.contains("/.config/grith/") || p.contains("/config/grith/")
            }
            grith_proxy::types::ToolCallType::FileRename { old_path, new_path } => {
                let o = old_path.to_lowercase();
                let n = new_path.to_lowercase();
                o.contains("/.config/grith/")
                    || o.contains("/config/grith/")
                    || n.contains("/.config/grith/")
                    || n.contains("/config/grith/")
            }
            _ => false,
        };
        if is_grith_config_write {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                Some(&call_type),
                "denied",
                Some("auto-deny"),
                None,
                Some("write to grith config denied — self-protection"),
            );
            tracing::warn!(
                pid = event.pid,
                tid,
                call_type = %call_type,
                "write to grith config denied — supervised tool must not modify grith's own configuration"
            );
            if let Err(e) = interceptor.deny(tid).await {
                tracing::warn!(error = %e, tid, "deny (grith config write) failed");
            }
            session.stats.total_denied += 1;
            return Ok(());
        }
    }

    // Filter out local-only network operations that never leave the machine:
    // - Unix domain sockets (paths like /var/run/nscd/socket)
    // - Loopback addresses for connect/listen
    //
    // Wildcard binds such as 0.0.0.0/:: are intentionally NOT treated as
    // local for NetListen. They expose the service on every interface and must
    // go through the normal review path.
    {
        // Whether this NetConnect is a control-injection IPC socket we will
        // enforce on: the flag is on, it is a control socket, and the profile
        // has not permitted it. Reused to (a) keep the connect OUT of the
        // local-IPC auto-allow below so it reaches proxy evaluation and the
        // Allow→QUEUE escalation, and (b) tag the forensic trace.
        let control_socket_enforce = match &call_type {
            grith_proxy::types::ToolCallType::NetConnect { address, .. } => {
                authority_delegation::control_socket_enforcement_enabled(
                    loop_ctx.config.enforce_control_socket_connect,
                ) && authority_delegation::control_socket_should_escalate(
                    address,
                    &loop_ctx.permit_control_sockets,
                )
                    // work/84: a curated clipboard tool at a system path,
                    // writing the selection, is the routine desktop use the
                    // X11/Wayland de-scoring was written to accommodate — see
                    // `is_routine_desktop_connect`. Every other connect to the
                    // display socket, including a clipboard READ and any
                    // unknown binary, still escalates.
                    && !authority_delegation::is_routine_desktop_connect(address, event.pid)
            }
            _ => false,
        };
        // Whether the *connect* is still the enforcement point. For a D-Bus
        // endpoint under message inspection it is not: the connection carries
        // no authority on its own, and each method call written to it is
        // judged separately (see `crate::dbus`). The connect is still kept
        // out of the local-IPC auto-allow above, so it is scored and audited
        // exactly as before — it just no longer prompts.
        let control_socket_escalates = control_socket_enforce
            && !matches!(
                &call_type,
                grith_proxy::types::ToolCallType::NetConnect { address, .. }
                    if dbus_inspection_covers(loop_ctx, address)
            );
        let is_local = match &call_type {
            grith_proxy::types::ToolCallType::NetConnect { address, .. } => {
                // A control-injection socket we are enforcing must NOT be
                // treated as local IPC — it has to reach the proxy so it
                // QUEUEs rather than being auto-allowed as noise.
                !control_socket_enforce
                    && (is_local_connect_address(address)
                    // Routine SSH/GPG agent use (git push over ssh-agent,
                    // GPG-signed commits) is local IPC — the exfil channel is
                    // the separately-scored remote connection (FP research §5.1).
                    // Two-part gated (client binary under a routine exec root)
                    // AND suppressed under containment so a high-taint session
                    // never silently uses the agent as a signing oracle.
                    || (!SessionStateRegistry::global().is_containment_active(
                        SessionScopeKey::from_session_id(session.id),
                    ) && connect_is_routine_agent_use(
                        address,
                        event.pid,
                        &loop_ctx.routine_exec_roots,
                    )))
            }
            grith_proxy::types::ToolCallType::NetListen { address, .. } => {
                is_local_listen_address(address)
            }
            _ => false,
        };
        // Control-injection IPC socket (tmux/screen/X11/session-D-Bus): local
        // IPC that can drive a more-privileged peer to run commands on the
        // tool's behalf. When enforcement is off it is audit-only (logged,
        // auto-allowed as local IPC below); when on and unpermitted it has
        // been kept non-local above and is escalated to QUEUE after proxy
        // evaluation.
        if let grith_proxy::types::ToolCallType::NetConnect { address, .. } = &call_type {
            if authority_delegation::is_control_injection_socket(address) {
                // Distinguish an enforcement candidate that a durable
                // exe-bound grant will allow from one that will actually
                // queue — "enforce-queue" on a call the grant then allows
                // would be a lying forensics record. Same predicate the
                // escalation guard uses downstream.
                let grant_covers = control_socket_escalates
                    && !SessionStateRegistry::global()
                        .is_containment_active(SessionScopeKey::from_session_id(session.id))
                    && ipc_socket_grant_key_parts(address, u64::from(event.pid)).is_some_and(
                        |key| {
                            loop_ctx
                                .session_allowed
                                .lock()
                                .is_ok_and(|s| s.contains(&key))
                        },
                    );
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event.pid,
                    Some(&call_type),
                    "control_socket_connect",
                    Some(if grant_covers {
                        "grant-allow"
                    } else if control_socket_escalates {
                        "enforce-queue"
                    } else if control_socket_enforce {
                        // D-Bus under message inspection: the connect is
                        // scored and recorded, and the decision it used to
                        // carry now belongs to the method calls written to it.
                        "dbus-inspection-armed"
                    } else {
                        "audit-only-allow"
                    }),
                    None,
                    Some("connect to a control-injection IPC socket (tmux/screen/X11/D-Bus)"),
                );
                tracing::debug!(
                    address = %address,
                    tid,
                    control_socket_enforce,
                    control_socket_escalates,
                    "control-injection IPC socket connect"
                );
            }
        }
        if is_local {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                Some(&call_type),
                "noise_filtered",
                Some("auto-allow"),
                None,
                Some("local-only network"),
            );
            session.stats.total_filtered_noise += 1;
            if let Err(e) = interceptor.allow(tid).await {
                tracing::warn!(error = %e, tid, "allow (local network) failed");
            }
            return Ok(());
        }
    }

    // Enrich NetConnect addresses with reverse DNS hostnames so the
    // egress filter can match against trusted domain names instead of
    // opaque raw IPs from the connect() syscall.
    let call_type = match call_type {
        grith_proxy::types::ToolCallType::NetConnect { address, port } => {
            let resolution = resolve_network_attribution(&loop_ctx.dns_cache, &address).await;
            let (resolution, via_forward_confirm) =
                if matches!(resolution, crate::dns_cache::Resolution::Unknown(_)) {
                    confirm_forward_attribution(
                        &loop_ctx.dns_cache,
                        loop_ctx.dns_forward_confirm.as_ref(),
                        &address,
                        resolution,
                    )
                    .await
                } else {
                    (resolution, false)
                };
            let confirm_suffix = if via_forward_confirm {
                " (recovered by re-resolving trusted destinations)"
            } else {
                ""
            };
            let (resolved, attribution_reason) = match resolution {
                crate::dns_cache::Resolution::Exact(name) => {
                    let reason = format!("exact DNS attribution{confirm_suffix}: {name}");
                    (name, reason)
                }
                crate::dns_cache::Resolution::Ambiguous(candidates) => {
                    let candidate_array = format_dns_candidate_array(&candidates);
                    tracing::warn!(
                        raw_ip = %address,
                        ?candidates,
                        "displaying ambiguous shared-IP DNS attribution as hostname candidates"
                    );
                    (
                        candidate_array.clone(),
                        format!(
                            "ambiguous DNS attribution{confirm_suffix} for {address}: \
                             {candidate_array}"
                        ),
                    )
                }
                crate::dns_cache::Resolution::Unknown(_)
                | crate::dns_cache::Resolution::NotAnIp(_) => {
                    (address.clone(), "DNS attribution miss".into())
                }
            };
            let resolved_call = grith_proxy::types::ToolCallType::NetConnect {
                address: resolved,
                port,
            };
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                Some(&resolved_call),
                "dns_attribution",
                None,
                None,
                Some(&attribution_reason),
            );
            resolved_call
        }
        other => other,
    };

    // PR 1 Phase D: derive the session scope once and consult the session-
    // lifetime containment flag. When containment is active (set by a
    // High-taint access earlier in this session — see Phase C), the
    // ignore_read_only and session_allowed short-circuits below are bypassed
    // so the full proxy pipeline evaluates each call. The is_noise_path
    // short-circuit immediately below this block is NOT gated — those paths
    // (/proc, /sys, /dev/pts, /dev/tty, CA cert dirs, …) are always noise
    // regardless of containment.
    //
    // PR 4 Phase H removed the GRITH_DEBUG_ALLOW_SESSION_ALLOWLIST_BYPASS
    // env-var kill switch. Containment is now always honoured when set;
    // operators who want to disable containment must do so via profile
    // config.
    let scope = SessionScopeKey::from_session_id(session.id);
    let containment_active = SessionStateRegistry::global().is_containment_active(scope);

    // ---- work/85: subtractive controls, ahead of every auto-allow ----
    //
    // Both of these are things the operator asked for explicitly — a blocked
    // directory, or a workspace boundary — and both are checked here, before
    // the noise fast path, `ignore_read_only`, the batch-read window, the
    // session allowlist and the reputation auto-allow. Anywhere later and a
    // block would be silently undone by a short-circuit that ran first, which
    // is the "allow only works once" failure in reverse: a refusal that only
    // works when nothing else claims the call.
    //
    // Neither path prompts. Suppressing the prompt is the entire point: the
    // operator answered this question once, for the whole directory.
    if let Some(rule) = loop_ctx
        .session_denied
        .lock()
        .ok()
        .and_then(|denied| session_deny_match(&call_type, &denied))
    {
        deny_subtractive_control(
            loop_ctx,
            session,
            interceptor,
            trace_event_id,
            event.pid,
            tid,
            &call_type,
            "scoped_deny_blocked",
            &format!("blocked by session rule {rule}"),
        )
        .await;
        return Ok(());
    }
    if let Some(outside) = loop_ctx.workspace_boundary.as_ref().and_then(|boundary| {
        workspace_only_block_reason(boundary, &call_type, &loop_ctx.session_allowed)
    }) {
        deny_subtractive_control(
            loop_ctx,
            session,
            interceptor,
            trace_event_id,
            event.pid,
            tid,
            &call_type,
            "workspace_only_blocked",
            &format!("outside the workspace: {outside}"),
        )
        .await;
        return Ok(());
    }

    // Optional noise path check (e.g., reads of /proc/, /sys/, etc.).
    //
    // A call is noise only when EVERY path it touches is noise. Link creation
    // carries two, and keying on the primary one alone let a link whose
    // *target* was noise carry an arbitrary link path past the proxy without
    // any filter running (go-live review B2).
    let noise_probe = ToolCallContext::new("", call_type.clone(), session.id);
    let probe_paths = noise_probe.paths();
    if let Some(path) = probe_paths.first().copied() {
        if probe_paths.iter().all(|p| syscall_map::is_noise_path(p)) {
            // H2 Option 1 (IPC-delegated authority): `/dev/pts/*` is a noise
            // path, but a WRITE to a pts that is not the tool's own controlling
            // terminal is a possible command injection into a sibling pane
            // (`echo cmd > /dev/pts/<other>`, the tmux-pane escape class). The
            // tool's own terminal writes (its fd 0/1/2) are unaffected. Always
            // forensically log a foreign-pts write; with `pty_ownership_enforce`
            // off (default) it is allowed (audit-only, to measure the FP
            // budget); with it on, it is denied.
            let own_pts = session.controlling_pts().map(str::to_string);
            if is_foreign_pts_write(&call_type, path, own_pts.as_deref()) {
                let enforce = loop_ctx.config.pty_ownership_enforce;
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event.pid,
                    Some(&call_type),
                    "foreign_pts_write",
                    Some(if enforce { "deny" } else { "audit-only-allow" }),
                    None,
                    Some("write to a /dev/pts that is not the tool's controlling terminal"),
                );
                tracing::warn!(
                    path,
                    tid,
                    root_pid = session.root_pid,
                    own_pts = own_pts.as_deref().unwrap_or("<unknown>"),
                    enforce,
                    "foreign /dev/pts write (possible IPC injection into a sibling pane)"
                );
                if enforce {
                    session.stats.total_denied += 1;
                    if let Err(e) = interceptor.deny(tid).await {
                        tracing::warn!(error = %e, tid, "deny (foreign pts write) failed");
                    }
                    return Ok(());
                }
                // audit-only: fall through to the normal noise auto-allow.
            }
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                Some(&call_type),
                "noise_filtered",
                Some("auto-allow"),
                None,
                Some("noise path"),
            );
            session.stats.total_filtered_noise += 1;
            maybe_log_compact(
                loop_ctx,
                session,
                event.pid,
                &call_type,
                CompactTier::NoisePath,
                "noise_path",
            )
            .await;
            if let Err(e) = interceptor.allow(tid).await {
                tracing::warn!(error = %e, tid, "allow (noise path) failed");
            }
            return Ok(());
        }
    }

    // Noise reduction: skip proxy for read-only file opens, fd-based reads,
    // and directory listings on non-sensitive paths.
    //
    // Note: sensitive paths (containing "token", "secret", etc. in filename)
    // are excluded from noise reduction UNLESS they match the session allowlist.
    // This prevents profile-trusted paths like ~/.claude/remote/.oauth_token
    // from being unnecessarily sent to the proxy just because of filename heuristics.
    //
    // PR 1 Phase D: gated by containment. When containment is active, every
    // read flows through the full proxy pipeline so it cannot bypass post-
    // contamination egress checks via the read-only fast path.
    if loop_ctx.config.noise_reduction.ignore_read_only && !containment_active {
        let read_path: Option<&str> = match &event.kind {
            // A directory open belongs here for the same reason `DirList`
            // below does: it is read-only, and leaving it out would push every
            // directory a traversal walks through the full proxy pipeline.
            SyscallKind::FileOpen {
                flags: OpenFlags::ReadOnly | OpenFlags::ReadOnlyDirectory,
                ref path,
            } => Some(path.as_str()),
            SyscallKind::FileRead {
                path: Some(ref path),
                ..
            } => Some(path.as_str()),
            SyscallKind::DirList { ref path } => Some(path.as_str()),
            _ => None,
        };
        if let Some(path) = read_path {
            // Check if the path is explicitly trusted by the session allowlist
            // (from profile routine_paths). If so, allow even if is_sensitive_path
            // would flag it — the profile explicitly trusts this path.
            let session_trusted = loop_ctx.session_allowed.lock().is_ok_and(|s| {
                s.iter().any(|prefix| {
                    !prefix.starts_with("exec-prefix:")
                        && !prefix.starts_with("ro:")
                        && !prefix.starts_with("ro-glob:")
                        && !prefix.starts_with("rw:")
                        && !prefix.starts_with("net:")
                        && !prefix.starts_with("exec:")
                        && !prefix.starts_with("dns:")
                        && !prefix.starts_with("projdir:")
                        && path.starts_with(prefix.as_str())
                        // work/80: trust derived from the launch cwd (marked
                        // by a `projdir:` twin) must never noise-allow a
                        // credential store — `cd ~/proj && grith exec` must
                        // not silently serve `~/proj/.aws/credentials` (this
                        // is the read-only `ignore_read_only` fast path;
                        // reads only, so the read key is the whole story).
                        // Explicit literal profile entries keep overriding.
                        //
                        // Same predicate as `projdir_grant_blocked`, and it
                        // has to be: this fast path returns before the
                        // allowlist matcher runs, so a set that only the
                        // matcher guarded would still be served here.
                        && !(s.contains(&format!("projdir:{prefix}"))
                            && syscall_map::is_project_trust_guarded_path(path))
                })
            });

            // Auto-allow reads of files that don't exist — the kernel will
            // return ENOENT anyway, so there's nothing to protect. This avoids
            // prompting for hardcoded probe paths (e.g. Claude Code's baked-in
            // /home/claude/.claude/remote/.oauth_token).
            let file_exists = std::path::Path::new(path).exists();

            if !syscall_map::is_sensitive_path(path) || session_trusted || !file_exists {
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event.pid,
                    Some(&call_type),
                    "noise_filtered",
                    Some("auto-allow"),
                    None,
                    Some(if !file_exists {
                        "nonexistent path"
                    } else {
                        "read-only noise"
                    }),
                );
                session.stats.total_filtered_noise += 1;
                maybe_log_compact(
                    loop_ctx,
                    session,
                    event.pid,
                    &call_type,
                    CompactTier::RoutineIo,
                    if !file_exists {
                        "nonexistent_path"
                    } else {
                        "read_only_noise"
                    },
                )
                .await;
                if let Err(e) = interceptor.allow(tid).await {
                    tracing::warn!(error = %e, tid, "allow (read-only noise) failed");
                }
                return Ok(());
            }
        }
    }

    // Noise reduction: coalesce rapid consecutive reads to the same fd.
    if loop_ctx.config.noise_reduction.batch_rapid_reads {
        if let SyscallKind::FileRead { fd, .. } = &event.kind {
            if loop_ctx
                .read_batch_tracker
                .lock()
                .is_ok_and(|mut t| t.should_coalesce(event.pid, *fd))
            {
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event.pid,
                    Some(&call_type),
                    "noise_filtered",
                    Some("auto-allow"),
                    None,
                    Some("batched read"),
                );
                session.stats.total_filtered_noise += 1;
                // Batched-read coalescing is a performance optimisation —
                // it merges N rapid reads from the same fd into 1
                // accounting event. Recording each underlying read at
                // compact level would defeat the coalescing benefit, so
                // emit one compact row tagged "batched_read" representing
                // the merge.
                maybe_log_compact(
                    loop_ctx,
                    session,
                    event.pid,
                    &call_type,
                    CompactTier::RoutineIo,
                    "batched_read",
                )
                .await;
                if let Err(e) = interceptor.allow(tid).await {
                    tracing::warn!(error = %e, tid, "allow (batched read) failed");
                }
                return Ok(());
            }
        }
    }

    // Session-level allowlist: paths/addresses approved during this session
    // bypass the proxy entirely. Supports exact matches, prefix matches
    // (for directory entries), and suffix matches for network domains
    // (so "net:datadoghq.com" matches "net:foo.bar.datadoghq.com").
    //
    // PR 1 Phase D: gated by containment. When containment is active, the
    // allowlist is not consulted — even profile-trusted destinations like
    // `api.openai.com` must run through the full proxy pipeline so the
    // post-contamination egress gate can decide whether to queue or deny.
    //
    // Explicit read-only scopes for sensitive directories are handled
    // separately: they still run through the proxy so taint/audit state is
    // recorded, then a queue decision is converted to an allow below.
    let sensitive_scoped_read_allowed = loop_ctx
        .session_allowed
        .lock()
        .is_ok_and(|allowed| is_sensitive_scoped_read_match(&call_type, &allowed));
    // Exact-command session approval: when the operator has already approved an
    // authority-delegating spawn / control-socket connect this session, the
    // IDENTICAL command must not be re-escalated — otherwise a probe that runs
    // once per session (or a tool the operator uses repeatedly) re-prompts every
    // time, since the enforcement path deliberately bypasses the broad session
    // allowlist. Keyed on the full call identity (command + args), so approving
    // `flatpak run foo` never covers `flatpak run bar`. Recorded on approval in
    // `queue_and_wait`; consumed here and at the escalation site below.
    //
    // Disabled under containment: post-contamination the session's taint can
    // change between identical runs, so a previously-approved delegating command
    // must be re-scrutinised (mirrors approve-replay being disabled under
    // containment).
    let already_user_approved_delegation = !containment_active
        && loop_ctx
            .session_allowed
            .lock()
            .is_ok_and(|s| s.contains(&delegating_approval_key(&call_type)));

    // An authority-delegating spawn / control-injection connect that WILL be
    // enforced must not be silently allowed by the session allowlist. A profile
    // that lists e.g. `docker` as a routine command would otherwise short-circuit
    // here and bypass enforcement entirely. The explicit
    // `permit_authority_delegating` / `permit_control_sockets` lists remain the
    // intended opt-out; an exact-command runtime approval is honoured via
    // `already_user_approved_delegation`; everything else routes to the proxy and
    // the Allow→QUEUE escalation below.
    let delegation_would_enforce = !already_user_approved_delegation
        && match &call_type {
            grith_proxy::types::ToolCallType::ProcessSpawn { command, args } => {
                authority_delegation::spawn_enforcement_enabled(
                    loop_ctx.config.enforce_authority_delegating_spawn,
                ) && (spawn_delegation_would_enforce(loop_ctx, command, args)
                    || authority_delegation::ssh_loopback_should_escalate(
                        command,
                        args,
                        &loop_ctx.permit_authority_delegating,
                    )
                    || authority_delegation::input_injection_should_escalate(
                        command,
                        args,
                        &loop_ctx.permit_authority_delegating,
                    ))
            }
            grith_proxy::types::ToolCallType::NetConnect { address, .. } => {
                authority_delegation::control_socket_enforcement_enabled(
                    loop_ctx.config.enforce_control_socket_connect,
                ) && !dbus_inspection_covers(loop_ctx, address)
                    && authority_delegation::control_socket_should_escalate(
                        address,
                        &loop_ctx.permit_control_sockets,
                    )
                    // Kept in step with `control_socket_enforce` above: if the
                    // connect is not going to be enforced, it must not skip the
                    // session-allowlist short-circuit either.
                    && !authority_delegation::is_routine_desktop_connect(address, event.pid)
            }
            _ => false,
        };
    // A latched session-containment flag disables the broad session-allowlist
    // short-circuit (PR 4 Phase H: post-contamination traffic must reach the
    // proxy, not an earlier grant). The one exception: a NetConnect the operator
    // explicitly approved at a prompt for a trusted `ssh` destination, marked by
    // an `ssh-egress:` grant that only that approval path ever writes. Honouring
    // it stops re-prompting on every reconnect to an already-approved ssh host,
    // without re-opening the short-circuit for profile-routine `net:` seeds.
    let containment_permits_operator_ssh = containment_active
        && netconnect_operator_ssh_egress_grant(&call_type, &loop_ctx.session_allowed);
    if !containment_active || containment_permits_operator_ssh {
        if let Some(key) = session_allowlist_key(&call_type) {
            if loop_ctx
                .session_allowed
                .lock()
                .is_ok_and(|s| is_session_allowlist_match(&key, &s, &call_type))
                && !sensitive_scoped_read_allowed
                && !delegation_would_enforce
            {
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event.pid,
                    Some(&call_type),
                    "session_allowed",
                    Some("auto-allow"),
                    None,
                    Some("session allowlist"),
                );
                session.stats.total_filtered_noise += 1;
                // Pick the compact tier for this allow. ProcessSpawn maps
                // to RoutineSpawn (cheapest "I saw the session run this
                // binary" record); File* / DirCreate / DnsQuery etc. map
                // to RoutineIo (recorded at completeness >= io).
                let tier = match &call_type {
                    grith_proxy::types::ToolCallType::ProcessSpawn { .. } => {
                        CompactTier::RoutineSpawn
                    }
                    _ => CompactTier::RoutineIo,
                };
                maybe_log_compact(
                    loop_ctx,
                    session,
                    event.pid,
                    &call_type,
                    tier,
                    "session_allowed",
                )
                .await;
                if let Err(e) = interceptor.allow(tid).await {
                    tracing::warn!(error = %e, tid, "allow (session-allowed) failed");
                }
                return Ok(());
            }
        }
    }

    // ---- Build proxy context ----
    let plugin_id = format!("supervisor:{}", session.tool_name);
    let mut ctx = ToolCallContext::new(plugin_id, call_type, session.id);
    ctx.profile_name = session.profile_name.clone();
    ctx.task_context = session.project_name.clone();
    ctx.arguments = supervisor_event_arguments(session, event.pid, &ctx.call_type);

    // A client may batch several messages into one write. The decision is on
    // the *write*, so approving the call named in the prompt also sends
    // anything else that rode along — record every escalated message so the
    // audit shows what an approval actually covered, and flag the batch so the
    // reason line can say so rather than naming one call and sending two.
    if matches!(
        ctx.call_type,
        grith_proxy::types::ToolCallType::DbusMethodCall { .. }
    ) {
        let batched = interceptor.take_dbus_method_calls(tid);
        if batched.len() > 1 {
            if let Some(obj) = ctx.arguments.as_object_mut() {
                obj.insert(
                    "dbus_batched_calls".into(),
                    serde_json::json!(batched
                        .iter()
                        .map(|c| c.description.clone())
                        .collect::<Vec<_>>()),
                );
            }
        }
    }

    // (The `scratch_root_match` proxy-argument flag that used to be set here was
    // retired with the rate_limit scratch/`.git`/`~/.cache` burst exemptions —
    // risk-gating now subsumes that carve-out. `scratch_roots` is still used by
    // the mass-destruction signal below.)

    // PR 4 Phase D: compute SpawnProvenance for ProcessSpawn so
    // operation-risk's routine signal can consult it. Skipped on
    // non-spawn calls (cheap branch). Empty `routine_exec_roots` is
    // valid — the resulting `matched_routine_root: None` causes the
    // signal to fail closed downstream.
    if let grith_proxy::types::ToolCallType::ProcessSpawn { command, args } = &ctx.call_type {
        let argv: Vec<String> = std::iter::once(command.clone())
            .chain(args.iter().cloned())
            .collect();
        let raw_path = command.clone();
        ctx.spawn_provenance = crate::provenance::compute_spawn_provenance(
            &raw_path,
            &loop_ctx.routine_exec_roots,
            |canonical| {
                matches!(
                    grith_proxy::filters::outbound_binaries::classify_binary(canonical, &argv),
                    grith_proxy::filters::outbound_binaries::Classification::Outbound { .. }
                )
            },
        );
    }

    // PR 5 Phase C: match NetListen against the session profile's
    // local_listener_policy so egress-policy knows whether to queue,
    // pass through (loopback), or clamp (wildcard + allow_clamp).
    //
    // PR 5 Phase D: also propagate the tracee-side sockaddr pointer
    // + addrlen from the originating SyscallKind into ctx.arguments
    // so the allow path can rewrite the bind in place if the
    // listener policy authorises a clamp.
    if let grith_proxy::types::ToolCallType::NetListen { address, port } = &ctx.call_type {
        ctx.listener_policy_match =
            match_listener_policy(&loop_ctx.local_listener_policy, address, *port);
        // The transport protocol the classifier already resolved for this
        // bind (fd inode → /proc/<pid>/net/udp{,6}) was being dropped on the
        // floor between `SyscallKind::NetBind` and `ToolCallType::NetListen`.
        // egress-policy needs it to tell a connected UDP *client* socket from
        // a UDP service listener. Unix binds keep `None` — `UnixSocketClass`
        // is their classifier.
        if let crate::interceptor::SyscallKind::NetBind { protocol, .. } = &event.kind {
            ctx.bind_protocol = match protocol {
                crate::interceptor::NetProtocol::Tcp => Some(grith_proxy::types::BindProtocol::Tcp),
                crate::interceptor::NetProtocol::Udp => Some(grith_proxy::types::BindProtocol::Udp),
                crate::interceptor::NetProtocol::Unix => None,
            };
        }
        if let crate::interceptor::SyscallKind::NetBind {
            sockaddr_ptr: Some(ptr),
            addrlen: Some(len),
            ..
        } = &event.kind
        {
            if let Some(map) = ctx.arguments.as_object_mut() {
                map.insert(
                    "bind_sockaddr_ptr".into(),
                    serde_json::Value::Number((*ptr).into()),
                );
                map.insert(
                    "bind_addrlen".into(),
                    serde_json::Value::Number((*len).into()),
                );
            }
        }
    }

    // ---- Reputation-based pre-evaluation auto-allow ----
    // Check if the reputation system has enough trust to auto-allow this
    // operation before running the full proxy pipeline. This is the main
    // enforcement path for the BRS (plan 48).
    //
    // Note: we evaluate the proxy first anyway to get filter_results for the
    // safety ceiling check. The auto-allow only fires if no ceiling applies.
    // The pipeline evaluates `ctx` exactly once here, so it must be observed
    // exactly once below. EVERY path that returned before this line never
    // entered the pipeline and has no state to commit - that is why the many
    // early-return sites above (noise auto-allows, hard denies,
    // ignore_read_only, batched reads, local IPC, the session-allowlist
    // short-circuit, subtractive control) need no wiring.
    let attempt_at = std::time::Instant::now();
    let mut decision = evaluate_proxy(loop_ctx, &ctx).await;

    // A scoped read of a sensitive directory must not bypass evaluation:
    // doing so would skip taint registration and its egress containment
    // signal. Once evaluated, honour the operator's explicit session scope
    // for queue-level reads. Auto-deny decisions remain fail-closed.
    if sensitive_scoped_read_allowed && matches!(decision.action, ProxyAction::Queue { .. }) {
        decision.action = ProxyAction::Allow;
        decision.decision_reason =
            "read allowed by explicit sensitive-directory session scope after proxy evaluation"
                .to_string();
    }

    // ---- Target-aware mass-destruction signal (rate-limit-burst redesign,
    // step 2) ----
    //
    // Volume is the one signal a per-op score and the risk-gated burst both
    // miss for a destructive spree: each delete is individually allowed and
    // untainted. Count distinct *valuable out-of-tree* deletions/renames in a
    // short window; when the spree crosses the threshold, escalate this op
    // Allow→QUEUE so the operator is prompted before it continues. In-tree,
    // routine, scratch and ephemeral targets never count, so build/VCS/cache
    // churn is invisible to it. Gated off by default (see module docs).
    let mut mass_destruction_escalated = false;
    if mass_destruction::signal_enabled() {
        if let Some(count) = mass_destruction::maybe_escalate(
            &mut decision,
            &ctx.call_type,
            loop_ctx.working_root.as_deref(),
            &loop_ctx.workspace_roots,
            &loop_ctx.routine_exec_roots,
            &loop_ctx.scratch_roots,
            &loop_ctx.mass_destruction,
            Instant::now(),
        ) {
            mass_destruction_escalated = true;
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                Some(&ctx.call_type),
                "mass_destruction_escalation",
                Some("queue"),
                Some(decision.composite_score),
                Some("distinct out-of-tree deletion spread crossed threshold"),
            );
            tracing::warn!(
                distinct = count,
                window_s = mass_destruction::WINDOW.as_secs(),
                "mass-destruction signal: escalating Allow→QUEUE"
            );
        }
    }

    // ---- Authority-delegating spawn + control-injection socket enforcement
    // (systemd-run supervision-escape class) ----
    //
    // These calls reach the proxy, but its filters do not recognise that a
    // `systemd-run` / `at` / `docker` spawn (or a session-D-Bus connect) hands
    // the real work to a peer OUTSIDE the supervised tree — nothing the peer
    // then does is intercepted or scored. When the operator has enabled
    // enforcement and the profile has not permitted the target, escalate the
    // Allow to QUEUE so it is reviewed rather than silently escaping
    // supervision. Like mass-destruction, an escalation here must not be
    // auto-allowed away by reputation, so it sets its own guard.
    let mut authority_delegation_escalated = false;
    // When a denied decision must actually STOP the spawn rather than be a
    // silent no-op. A `ProcessSpawn` is intercepted at `PTRACE_EVENT_EXEC` —
    // the execve has already returned into the new program image, so
    // `deny_syscall` (which EPERMs an *in-flight* syscall at a syscall-entry
    // stop) has nothing to reject and the delegating binary would run anyway.
    // For an enforced authority-delegating spawn we therefore SIGKILL the
    // tracee on deny: the new image is loaded but has not executed its first
    // instruction, so the kill stops `systemd-run`/`docker`/`ssh localhost`/…
    // before it hands work to the untraced peer. Keyed on the enforcement
    // predicate (not merely on whether escalation fired) so it also covers a
    // delegating spawn that independently scored Queue/Deny — escalation only
    // rewrites a base `Allow`.
    let mut kill_on_deny = false;
    if let grith_proxy::types::ToolCallType::ProcessSpawn { command, args } = &ctx.call_type {
        // Canonical path + content hash come free from the SpawnProvenance PR 4
        // already computed for this call (None if canonicalisation failed —
        // then the raw-basename check still applies).
        let (prov_canonical, prov_sha256) =
            ctx.spawn_provenance.as_ref().map_or((None, None), |p| {
                (Some(p.canonical_path.as_str()), Some(p.sha256.as_str()))
            });
        if authority_delegation::spawn_enforcement_enabled(
            loop_ctx.config.enforce_authority_delegating_spawn,
        ) {
            // Permit-INDEPENDENT: a permitted delegating binary is exempt from
            // the escalation (below), but NOT from having an independent DENY
            // (secret in argv, taint data-flow, reviewer/non-interactive deny)
            // actually enforced. The permit list opts out of the delegation
            // signal, not out of every other filter's verdict — so a deny of a
            // permitted delegating spawn must still SIGKILL, or it escapes via
            // the no-op deny at PTRACE_EVENT_EXEC.
            // Resolved once and shared: two independent lookups could stat the
            // target either side of a rename and disagree, escalating to QUEUE
            // while kill_on_deny stayed false - exactly the no-op deny the
            // comment above guards against.
            let pinned_hashes =
                loop_ctx
                    .authority_delegating_pins
                    .hashes_for(command, prov_canonical, prov_sha256);
            kill_on_deny =
                authority_delegation::spawn_targets_delegating_binary(
                    command,
                    args,
                    prov_canonical,
                    prov_sha256,
                    pinned_hashes,
                ) || authority_delegation::ssh_family_loopback_destination(command, args);
            if !already_user_approved_delegation
                && authority_delegation::maybe_escalate_spawn_full(
                    &mut decision,
                    command,
                    args,
                    prov_canonical,
                    prov_sha256,
                    &loop_ctx.permit_authority_delegating,
                    pinned_hashes,
                )
            {
                authority_delegation_escalated = true;
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event.pid,
                    Some(&ctx.call_type),
                    "authority_delegating_escalation",
                    Some("queue"),
                    Some(decision.composite_score),
                    Some("authority-delegating spawn escalated Allow→QUEUE"),
                );
                tracing::warn!(
                    command = %command,
                    tid,
                    "authority-delegating spawn: escalating Allow→QUEUE"
                );
            } else if !already_user_approved_delegation
                && authority_delegation::maybe_escalate_ssh_loopback_spawn(
                    &mut decision,
                    command,
                    args,
                    &loop_ctx.permit_authority_delegating,
                )
            {
                // ssh/scp/sftp are NOT in is_authority_delegating_binary, so the
                // spawn escalator above returned false and control falls here —
                // no double-escalation. The same guard skips the reputation
                // auto-allow bypass for free.
                authority_delegation_escalated = true;
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event.pid,
                    Some(&ctx.call_type),
                    "ssh_loopback_escalation",
                    Some("queue"),
                    Some(decision.composite_score),
                    Some("ssh-family loopback spawn escalated Allow→QUEUE"),
                );
                tracing::warn!(
                    command = %command,
                    tid,
                    "ssh-family loopback spawn: escalating Allow→QUEUE"
                );
            } else if !already_user_approved_delegation
                && authority_delegation::maybe_escalate_input_injection_spawn(
                    &mut decision,
                    command,
                    args,
                    &loop_ctx.permit_authority_delegating,
                )
            {
                // Compensating control for scoring X11 / Wayland sockets as
                // local IPC: desktop access is cheap now, so the spawns that
                // turn it into control of the operator's session are what
                // carries the review pressure. Neither of the arms above
                // matches these binaries, so control only reaches here — no
                // double-escalation.
                authority_delegation_escalated = true;
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event.pid,
                    Some(&ctx.call_type),
                    "input_injection_escalation",
                    Some("queue"),
                    Some(decision.composite_score),
                    Some("desktop input-injection spawn escalated Allow→QUEUE"),
                );
                tracing::warn!(
                    command = %command,
                    tid,
                    "desktop input-injection spawn: escalating Allow→QUEUE"
                );
            }
        }
    } else if let grith_proxy::types::ToolCallType::NetConnect { address, .. } = &ctx.call_type {
        // Durable exe-bound IPC grant: a prior [a]/[l] approval of this
        // control socket minted `ipc-socket:<address>|<client exe>` (the [l]
        // form persists across sessions via learned rules). A match guards
        // the escalation only — the call has still been fully proxy-scored
        // and audit-recorded, and a Queue produced by the SCORE (containment,
        // taint) is deliberately not downgraded: the grant answers the
        // delegation question, not whatever else flagged the call. Checked
        // post-proxy rather than at the session-allowlist short-circuit so
        // the exe identity is enforced (the broad `net:unix:` entry the same
        // approval inserts is exe-blind, and the enforcement path skips it).
        // Suspended under containment like every other approval memory.
        let ipc_grant_matches = !containment_active
            && ipc_socket_grant_key_for_ctx(&ctx).is_some_and(|key| {
                loop_ctx
                    .session_allowed
                    .lock()
                    .is_ok_and(|s| s.contains(&key))
            });
        if ipc_grant_matches {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                Some(&ctx.call_type),
                "control_socket_grant",
                Some("grant-allow"),
                Some(decision.composite_score),
                Some("durable exe-bound ipc-socket grant covers this connect"),
            );
            tracing::info!(
                address = %address,
                tid,
                "control-socket connect covered by durable ipc-socket grant"
            );
        }
        if !already_user_approved_delegation
            && !ipc_grant_matches
            && !dbus_inspection_covers(loop_ctx, address)
            && authority_delegation::control_socket_enforcement_enabled(
                loop_ctx.config.enforce_control_socket_connect,
            )
        {
            match authority_delegation::maybe_escalate_control_socket(
                &mut decision,
                address,
                &loop_ctx.permit_control_sockets,
            ) {
                authority_delegation::ControlSocketEscalation::Escalated => {
                    authority_delegation_escalated = true;
                    write_forensics_stage(
                        loop_ctx,
                        trace_event_id,
                        session,
                        event.pid,
                        Some(&ctx.call_type),
                        "control_socket_escalation",
                        Some("queue"),
                        Some(decision.composite_score),
                        Some("control-injection socket connect escalated Allow→QUEUE"),
                    );
                    tracing::warn!(
                        address = %address,
                        tid,
                        "control-injection socket connect: escalating Allow→QUEUE"
                    );
                }
                // Score-driven Queue on a control socket: the action stands
                // and only the reason was rewritten for the prompt.
                // `authority_delegation_escalated` stays false — its contract
                // (relied on by the reputation bypass below) is "a base Allow
                // was rewritten"; the base-Queue case is held out of the
                // reputation auto-allow by `delegation_would_enforce` instead.
                authority_delegation::ControlSocketEscalation::Annotated => {
                    write_forensics_stage(
                        loop_ctx,
                        trace_event_id,
                        session,
                        event.pid,
                        Some(&ctx.call_type),
                        "control_socket_escalation",
                        Some("queue-annotated"),
                        Some(decision.composite_score),
                        Some("control-injection socket connect already queued on score; reason annotated"),
                    );
                    tracing::info!(
                        address = %address,
                        tid,
                        "control-injection socket connect: already queued on score, reason annotated"
                    );
                }
                authority_delegation::ControlSocketEscalation::None => {}
            }
        }
    }

    // Check if reputation would auto-allow this operation. A mass-destruction
    // or authority-delegating escalation must not be auto-allowed away, so it
    // bypasses this block. `authority_delegation_escalated` only fires when a
    // base `Allow` was rewritten to `Queue`; a delegating spawn whose base
    // decision was *already* `Queue` (e.g. routine baseline + a taint /
    // behavioural contribution scoring 3.0–8.0) would not set it, and could
    // then be reputation-auto-allowed straight past the queue — escaping
    // supervision without ever reaching `enforce_decision`'s kill path. Gate on
    // `delegation_would_enforce` too (the permit-aware predicate computed at the
    // session-allowlist short-circuit): an unpermitted enforced delegating call
    // never gets reputation-auto-allowed, regardless of its base action.
    if loop_ctx.daemon_proxy_url.is_none()
        && !mass_destruction_escalated
        && !authority_delegation_escalated
        && !delegation_would_enforce
        && matches!(
            decision.action,
            grith_proxy::types::ProxyAction::Queue { .. }
        )
    {
        let profile = session_scope_name(session);
        let action_name = grith_proxy::reputation::action_name(&ctx.call_type);
        let process = ctx
            .arguments
            .get("process")
            .and_then(|v| v.as_str())
            .unwrap_or("*");
        let destination = ctx
            .arguments
            .get("process_args")
            .and_then(|v| v.as_array())
            .and_then(|args| {
                args.iter()
                    .filter_map(|a| a.as_str())
                    .find(|a| !a.starts_with('-') && (a.contains('@') || a.contains('.')))
            })
            .unwrap_or("*");
        let path = match &ctx.call_type {
            ToolCallType::FileRead { path }
            | ToolCallType::FileWrite { path, .. }
            | ToolCallType::FileAppend { path }
            | ToolCallType::FileDelete { path }
            | ToolCallType::FileChmod { path, .. }
            | ToolCallType::DirList { path }
            | ToolCallType::DirCreate { path } => path.as_str(),
            ToolCallType::FileRename { old_path, .. } => old_path.as_str(),
            ToolCallType::OwnershipChange { target, .. }
            | ToolCallType::FilesystemMutation { target, .. } => target.as_str(),
            ToolCallType::ProcessSpawn { command, .. } => command.as_str(),
            ToolCallType::NetConnect { address, .. } | ToolCallType::NetListen { address, .. } => {
                address.as_str()
            }
            ToolCallType::DnsQuery { domain, .. } => domain.as_str(),
            _ => "",
        };

        if !path.is_empty() {
            let keys = grith_proxy::reputation::build_reputation_keys(
                profile,
                action_name,
                process,
                destination,
                path,
            );
            let ceiling = grith_proxy::reputation::has_safety_ceiling(
                &decision.filter_results,
                &ctx.call_type,
                &loop_ctx.reputation_config,
            );

            // Compute reputation decision in a sync block to avoid holding
            // the MutexGuard across an await point.
            let reputation_auto_allow_ctx = if !ceiling {
                loop_ctx.reputation_table.lock().ok().and_then(|table| {
                    let adjusted = table.adjust_score(
                        decision.composite_score,
                        &keys,
                        false,
                        &loop_ctx.reputation_config,
                    );
                    if adjusted != 0.0 {
                        return None;
                    }
                    let trust = table
                        .lookup(&keys, &loop_ctx.reputation_config)
                        .map(|(trust, _level)| trust)
                        .unwrap_or(0.0);
                    Some(ReputationContext {
                        trust_score: trust,
                        auto_allowed: true,
                        score_reduction: decision.composite_score - adjusted,
                        reputation_key: keys.first().map(|(_, k)| k.clone()).unwrap_or_default(),
                    })
                })
            } else {
                None
            };

            if let Some(rep_ctx) = reputation_auto_allow_ctx {
                // Reputation auto-allow: bypass the normal enforcement path.
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event.pid,
                    Some(&ctx.call_type),
                    "reputation_auto_allow",
                    Some("auto-allow"),
                    Some(decision.composite_score),
                    Some("reputation trust sufficient"),
                );
                write_syscall_log(
                    loop_ctx,
                    event.pid,
                    &ctx.call_type,
                    decision.composite_score,
                    "reputation-auto-allow",
                    &format!(
                        "trust sufficient (raw score {:.1})",
                        decision.composite_score
                    ),
                );
                tracing::info!(
                    call_type = %ctx.call_type,
                    raw_score = decision.composite_score,
                    "reputation auto-allow: trust sufficient"
                );
                if let Err(e) = interceptor.allow(tid).await {
                    tracing::warn!(error = %e, tid, "allow (reputation) failed");
                }
                let correlation_id =
                    if let Some(source_event) = exfil::correlation_source_event(&ctx.call_type) {
                        Some(
                            loop_ctx
                                .correlation_tracker
                                .open_chain(session.id, source_event),
                        )
                    } else if exfil::is_outbound_sink(&ctx.call_type) {
                        loop_ctx.correlation_tracker.link_sink(session.id)
                    } else {
                        None
                    };
                let mut effective_decision = decision.clone();
                effective_decision.action = ProxyAction::Allow;
                effective_decision.decision_reason =
                    "reputation trust sufficient; auto-allowed".into();
                let audit_record = build_audit_record(
                    &ctx,
                    &effective_decision,
                    session,
                    event.pid,
                    loop_ctx.dlp_redactor,
                    correlation_id,
                    Some(&rep_ctx),
                )
                .with_analytics_metadata(prospective_analytics_metadata(
                    loop_ctx,
                    session,
                    RecordClass::Decision,
                    &ctx.call_type.to_string(),
                ));
                if let Err(e) = loop_ctx.audit_sink.log(audit_record).await {
                    tracing::error!(
                        error = %e,
                        "failed to log reputation auto-allow audit record"
                    );
                }
                session.stats.total_allowed += 1;
                // This arm bypasses enforce_decision, so it must close out its
                // own evaluation. Without this, every reputation-auto-allowed
                // egress - the calls a trusted session makes most - would stop
                // being committed.
                observe_proxy_outcome(loop_ctx, &ctx, CallOutcome::Executed, attempt_at);
                return Ok(());
            }
        }
    }

    let enforced = enforce_decision(
        interceptor,
        session,
        loop_ctx,
        &ctx,
        &decision,
        tid,
        event.pid,
        trace_event_id,
        kill_on_deny,
        delegation_would_enforce,
    )
    .await;

    let observed = match &enforced {
        Ok(outcome) => *outcome,
        // enforce_decision and queue_and_wait are infallible today. If a
        // future fallible call is added the evaluation must still be closed
        // out, and an unknown fate commits as Denied: that can only
        // under-count. Never fabricate an Executed.
        Err(_) => CallOutcome::Denied,
    };
    // Skip when nothing evaluated the call: an unreachable daemon staged no
    // state, so committing would invent a refusal it never scored.
    if was_evaluated(&decision) {
        observe_proxy_outcome(loop_ctx, &ctx, observed, attempt_at);
    }
    // Propagated only after observing, so an error cannot skip the commit -
    // nor the audit record and exfil annotations below.
    enforced?;

    log_exfil_annotations(session, event.pid, &decision.filter_results);

    // ---- Audit logging ----
    let correlation_id = if let Some(source_event) = exfil::correlation_source_event(&ctx.call_type)
    {
        Some(
            loop_ctx
                .correlation_tracker
                .open_chain(session.id, source_event),
        )
    } else if exfil::is_outbound_sink(&ctx.call_type) {
        loop_ctx.correlation_tracker.link_sink(session.id)
    } else {
        None
    };

    // Look up reputation context for audit record enrichment.
    let reputation_ctx = {
        let profile = session_scope_name(session);
        let action = grith_proxy::reputation::action_name(&ctx.call_type);
        let path = match &ctx.call_type {
            ToolCallType::FileRead { path }
            | ToolCallType::FileWrite { path, .. }
            | ToolCallType::FileAppend { path }
            | ToolCallType::FileDelete { path }
            | ToolCallType::FileChmod { path, .. }
            | ToolCallType::DirList { path }
            | ToolCallType::DirCreate { path } => path.as_str(),
            ToolCallType::FileRename { old_path, .. } => old_path.as_str(),
            ToolCallType::OwnershipChange { target, .. }
            | ToolCallType::FilesystemMutation { target, .. } => target.as_str(),
            ToolCallType::ProcessSpawn { command, .. } => command.as_str(),
            ToolCallType::NetConnect { address, .. } | ToolCallType::NetListen { address, .. } => {
                address.as_str()
            }
            ToolCallType::DnsQuery { domain, .. } => domain.as_str(),
            _ => "",
        };
        if !path.is_empty() {
            let keys =
                grith_proxy::reputation::build_reputation_keys(profile, action, "*", "*", path);
            loop_ctx.reputation_table.lock().ok().and_then(|table| {
                table
                    .lookup(&keys, &loop_ctx.reputation_config)
                    .map(|(trust, _level)| {
                        let ceiling = grith_proxy::reputation::has_safety_ceiling(
                            &decision.filter_results,
                            &ctx.call_type,
                            &loop_ctx.reputation_config,
                        );
                        let adjusted = table.adjust_score(
                            decision.composite_score,
                            &keys,
                            ceiling,
                            &loop_ctx.reputation_config,
                        );
                        let reduction = decision.composite_score - adjusted;
                        let auto_allowed = adjusted == 0.0;
                        ReputationContext {
                            trust_score: trust,
                            auto_allowed,
                            score_reduction: reduction,
                            reputation_key: keys
                                .first()
                                .map(|(_, k)| k.clone())
                                .unwrap_or_default(),
                        }
                    })
            })
        } else {
            None
        }
    };

    let audit_record = build_audit_record(
        &ctx,
        &decision,
        session,
        event.pid,
        loop_ctx.dlp_redactor,
        correlation_id,
        reputation_ctx.as_ref(),
    )
    .with_analytics_metadata(prospective_analytics_metadata(
        loop_ctx,
        session,
        RecordClass::Decision,
        &ctx.call_type.to_string(),
    ));
    if let Err(e) = loop_ctx.audit_sink.log(audit_record).await {
        tracing::error!(error = %e, "failed to log audit record");
    }

    // ---- Optional WS broadcast ----
    if let Some(tx) = loop_ctx.event_tx {
        // In Log mode, queue-range decisions are effectively allows — reflect
        // this in the broadcast so the TUI counters are accurate.
        let effective_action = if matches!(decision.action, ProxyAction::Queue { .. })
            && loop_ctx.config.interactive_queue_action
                == crate::config::InteractiveQueueAction::Log
        {
            "allow (logged)"
        } else {
            ""
        };
        let event_json = build_ws_event(&ctx, &decision, session, effective_action);
        let _ = tx.send(event_json);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Decision enforcement
// ---------------------------------------------------------------------------

/// Enforce a proxy decision.
///
/// `tid` is the thread ID returned by waitpid — the thread that is actually
/// stopped and must be resumed via ptrace.  Process-tree operations (freeze /
/// thaw of children) use the TGID from `ctx.session_id` indirectly through
/// the session's process tree, which is keyed by TGID.
/// Stop a denied syscall. Normally this is `deny_syscall` — set `orig_rax = -1`
/// / `rax = -EPERM` on the in-flight syscall at its entry stop. But a
/// `ProcessSpawn` is surfaced at `PTRACE_EVENT_EXEC`, *after* execve returned
/// into the new program image; there is no in-flight syscall to reject, so
/// `deny_syscall` is a silent no-op and the (already-exec'd) binary runs. When
/// `kill_on_deny` is set (an enforced authority-delegating spawn) we SIGKILL the
/// tracee instead: the new image is loaded but has not run its first
/// instruction, so the kill stops it before it delegates to the untraced peer.
async fn deny_or_kill(
    interceptor: &mut Box<dyn SyscallInterceptor>,
    tid: u32,
    kill_on_deny: bool,
) -> Result<()> {
    if kill_on_deny {
        interceptor.kill(tid).await
    } else {
        interceptor.deny(tid).await
    }
}

async fn enforce_decision(
    interceptor: &mut Box<dyn SyscallInterceptor>,
    session: &mut SupervisorSession,
    loop_ctx: &SupervisorLoopContext<'_>,
    ctx: &ToolCallContext,
    decision: &grith_proxy::types::ProxyDecision,
    tid: u32,
    event_pid: u32,
    trace_event_id: Uuid,
    // When true, a deny must SIGKILL the tracee rather than call `deny_syscall`
    // (a no-op for a `ProcessSpawn` intercepted at `PTRACE_EVENT_EXEC`). Set for
    // an enforced authority-delegating spawn. See the call site for the why.
    kill_on_deny: bool,
    // When true, this is an enforced authority-delegating call: an Approve
    // outcome records the exact command so an identical recurrence auto-allows
    // (propagated to `queue_and_wait`).
    record_delegating_approval: bool,
) -> Result<CallOutcome> {
    match &decision.action {
        ProxyAction::Allow => {
            // PR 5 Phase D: opportunistic wildcard-to-loopback clamp.
            // When NetListen got an Allow despite being a wildcard
            // bind, that means a `local_listener_policy` entry with
            // `allow_clamp = true` matched (egress-policy silently
            // passed it through). The supervisor now rewrites the
            // tracee's sockaddr to loopback before resuming the
            // syscall — kernel processes the bind on `127.0.0.1` /
            // `::1` instead of `0.0.0.0` / `::`.
            //
            // Clamp failure is fail-closed: we deny the call rather
            // than allow the wildcard bind to proceed unmodified.
            // PR 5 Phase D: `tid` (not `event_pid`) is the thread
            // actually ptrace-stopped at the bind() entry. On a
            // multi-threaded tracee that binds from a worker, the
            // TGID-leader is running and `ptrace::write` against it
            // fails ESRCH. Pass the stopped tid through to the clamp.
            if let Err(e) = maybe_clamp_listen_address(ctx, decision, tid, event_pid).await {
                tracing::warn!(
                    error = %e,
                    tid,
                    "clamp_sockaddr_to_loopback failed; denying syscall fail-closed",
                );
                if let Err(de) = interceptor.deny(tid).await {
                    tracing::warn!(error = %de, tid, "deny after failed clamp also failed");
                }
                session.stats.total_denied += 1;
                return Ok(CallOutcome::Denied);
            }
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event_pid,
                Some(&ctx.call_type),
                "proxy_scored",
                Some("auto-allow"),
                Some(decision.composite_score),
                Some(&decision.decision_reason),
            );
            write_syscall_log(
                loop_ctx,
                event_pid,
                &ctx.call_type,
                decision.composite_score,
                "auto-allow",
                &decision.decision_reason,
            );
            if let Err(e) = interceptor.allow(tid).await {
                tracing::warn!(error = %e, tid, "allow failed");
            }
            session.stats.total_allowed += 1;

            // /tmp self-created subtree auto-allow: also register on
            // proxy-direct Allow (not just user-approved Queue). When
            // the proxy scored a top-level `/tmp/<name>` dir create
            // under threshold, treat the success as "session created
            // it" so subsequent subtree accesses bypass the pipeline.
            // Matches the same registration done in the Approve arm.
            if let Some(tmp_prefix) = tmp_self_created_prefix(&ctx.call_type) {
                if let Ok(mut allowed) = loop_ctx.session_allowed.lock() {
                    if allowed.insert(tmp_prefix.clone()) {
                        tracing::info!(
                            entry = tmp_prefix,
                            "session allowlist: /tmp self-created subtree registered (auto-allow)"
                        );
                    }
                }
            }

            Ok(CallOutcome::Executed)
        }
        ProxyAction::Queue { .. } => {
            // PR 3 Phase B: failed-exec suppression (pre-stat shipping
            // config (b) from the work doc). If the syscall is a
            // ProcessSpawn whose target binary is clearly missing,
            // allow it to proceed — the kernel will return ENOENT,
            // no authority was granted, no point prompting the user.
            //
            // Documented TOCTOU caveat: a symlink swap between the
            // supervisor's stat and the kernel's execve could let an
            // attacker arrange a "stat says missing → kernel says
            // found" window. Every suppression is recorded in tracing,
            // the optional forensic trace, and the syscall log with
            // `suppressed_failed_exec` so any TOCTOU-exploited miss is
            // forensically visible. The underlying proxy evaluation is
            // still persisted as the normal audit record.
            // Full post-syscall observation (shipping config (a)) is
            // tracked as a follow-up — see Phase A's audit notes.
            if let ToolCallType::ProcessSpawn { command, .. } = &ctx.call_type {
                if exec_path_clearly_missing(command) {
                    write_forensics_stage(
                        loop_ctx,
                        trace_event_id,
                        session,
                        event_pid,
                        Some(&ctx.call_type),
                        "suppressed_failed_exec",
                        Some("auto-allow"),
                        Some(decision.composite_score),
                        Some("kernel will return ENOENT; not prompting"),
                    );
                    write_syscall_log(
                        loop_ctx,
                        event_pid,
                        &ctx.call_type,
                        decision.composite_score,
                        "suppressed_failed_exec",
                        "binary not found on PATH or at absolute path",
                    );
                    tracing::info!(
                        event = "suppressed_failed_exec",
                        session_id = %session.id,
                        tid,
                        score = decision.composite_score,
                        command = command,
                        "PR3-B: spawn target absent; kernel will reject — suppressing prompt"
                    );
                    if let Err(e) = interceptor.allow(tid).await {
                        tracing::warn!(
                            error = %e,
                            tid,
                            "allow (failed-exec suppression) failed"
                        );
                    }
                    session.stats.total_allowed += 1;
                    return Ok(CallOutcome::KernelRefused);
                }
            }

            // PR 3 Phase C: failed-connect suppression for loopback.
            // A connect to 127.0.0.1:N or ::1:N with no listener on N
            // will return ECONNREFUSED — no payload reaches anything
            // off-host, no authority granted. Prompting on these
            // probes is friction without security value.
            //
            // Strictly loopback-only: a missing listener on a remote
            // host could be a transient routing or firewall issue
            // that the user still wants to know about, so we never
            // suppress non-loopback. The /proc/net/tcp parse is
            // Linux-only; non-Linux platforms always return false
            // (no suppression).
            if let ToolCallType::NetConnect { address, port } = &ctx.call_type {
                if is_loopback_connect_address(address) && !loopback_port_has_listener(*port) {
                    write_forensics_stage(
                        loop_ctx,
                        trace_event_id,
                        session,
                        event_pid,
                        Some(&ctx.call_type),
                        "suppressed_failed_connect",
                        Some("auto-allow"),
                        Some(decision.composite_score),
                        Some("loopback port has no listener; kernel will refuse"),
                    );
                    write_syscall_log(
                        loop_ctx,
                        event_pid,
                        &ctx.call_type,
                        decision.composite_score,
                        "suppressed_failed_connect",
                        "ECONNREFUSED expected — loopback port unbound",
                    );
                    tracing::info!(
                        event = "suppressed_failed_connect",
                        session_id = %session.id,
                        tid,
                        score = decision.composite_score,
                        address = address.as_str(),
                        port = port,
                        "PR3-C: loopback connect with no listener — suppressing prompt"
                    );
                    if let Err(e) = interceptor.allow(tid).await {
                        tracing::warn!(
                            error = %e,
                            tid,
                            "allow (failed-connect suppression) failed"
                        );
                    }
                    session.stats.total_allowed += 1;
                    return Ok(CallOutcome::KernelRefused);
                }
            }

            // In "log" mode, allow the syscall and log it as informational
            // instead of freezing the process tree for a blocking dialog.
            // This keeps interactive TUI tools running uninterrupted.
            //
            // Not when containment or taint put the call in the queue band.
            // `--allow-queued` is a throughput concession for a headless
            // session whose queued calls are ordinary friction; it was never
            // meant to wave through the two signals that specifically mean
            // "this session has already touched something sensitive". Those
            // fall through to the deny branch below — the same fail-closed
            // outcome the flag's absence would produce.
            if loop_ctx.config.interactive_queue_action
                == crate::config::InteractiveQueueAction::Log
                && !contamination_signalled(decision)
            {
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event_pid,
                    Some(&ctx.call_type),
                    "proxy_scored",
                    Some("auto-allow-log"),
                    Some(decision.composite_score),
                    Some(&decision.decision_reason),
                );
                write_syscall_log(
                    loop_ctx,
                    event_pid,
                    &ctx.call_type,
                    decision.composite_score,
                    "auto-allow-log",
                    &decision.decision_reason,
                );
                tracing::info!(
                    session_id = %session.id,
                    tid,
                    score = decision.composite_score,
                    call_type = %ctx.call_type,
                    "QUEUE decision logged (non-blocking mode)"
                );
                // Log as informational digest item for post-session review.
                let mut digest_item = build_digest_item(ctx, decision, loop_ctx.dlp_redactor);
                digest_item.informational_only = true;
                if let Err(e) = loop_ctx.digest_store.enqueue(&digest_item).await {
                    tracing::error!(error = %e, "failed to enqueue informational digest item");
                }
                // Allow the syscall to proceed.
                if let Err(e) = interceptor.allow(tid).await {
                    tracing::warn!(error = %e, tid, "allow (non-blocking queue) failed");
                }
                session.stats.total_queued += 1;
                return Ok(CallOutcome::ObservedOnly);
            }

            // In "deny" mode (a non-interactive session with no reviewer to
            // answer a dialog — CI, piped, backgrounded), deny the queued
            // syscall immediately rather than freezing the process tree for
            // `freeze_timeout_seconds` on a prompt no one can see. Fail-closed:
            // same outcome as the freeze-then-timeout auto-deny, but immediate
            // and legible.
            if loop_ctx.config.interactive_queue_action
                == crate::config::InteractiveQueueAction::Deny
            {
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event_pid,
                    Some(&ctx.call_type),
                    "proxy_scored",
                    Some("auto-deny-headless"),
                    Some(decision.composite_score),
                    Some(&decision.decision_reason),
                );
                write_syscall_log(
                    loop_ctx,
                    event_pid,
                    &ctx.call_type,
                    decision.composite_score,
                    "auto-deny-headless",
                    &decision.decision_reason,
                );
                tracing::warn!(
                    session_id = %session.id,
                    tid,
                    score = decision.composite_score,
                    call_type = %ctx.call_type,
                    "QUEUE auto-denied (non-interactive session, no reviewer) — allowlist it in the profile, run with a terminal, or pass --allow-queued"
                );
                let mut digest_item = build_digest_item(ctx, decision, loop_ctx.dlp_redactor);
                digest_item.informational_only = true;
                if let Err(e) = loop_ctx.digest_store.enqueue(&digest_item).await {
                    tracing::error!(error = %e, "failed to enqueue informational digest item");
                }
                if let Err(e) = deny_or_kill(interceptor, tid, kill_on_deny).await {
                    tracing::warn!(error = %e, tid, "deny/kill (non-interactive queue) failed");
                }
                session.stats.total_denied += 1;
                return Ok(CallOutcome::Denied);
            }
            // Blocking review — logged inside queue_and_wait with the review outcome.
            queue_and_wait(
                interceptor,
                session,
                loop_ctx,
                ctx,
                decision,
                tid,
                event_pid,
                trace_event_id,
                kill_on_deny,
                record_delegating_approval,
            )
            .await
        }
        ProxyAction::Deny { reason } => {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event_pid,
                Some(&ctx.call_type),
                "proxy_scored",
                Some("auto-deny"),
                Some(decision.composite_score),
                Some(reason),
            );
            write_syscall_log(
                loop_ctx,
                event_pid,
                &ctx.call_type,
                decision.composite_score,
                "auto-deny",
                reason,
            );
            tracing::warn!(
                session_id = %session.id,
                tid,
                reason = %reason,
                score = decision.composite_score,
                "syscall denied"
            );
            if let Err(e) = deny_or_kill(interceptor, tid, kill_on_deny).await {
                tracing::warn!(error = %e, tid, "deny/kill failed");
            }
            // Record implicit deny signal for reputation (lower weight than manual).
            record_reputation_observation(
                loop_ctx,
                session,
                &ctx.call_type,
                grith_proxy::reputation::ReputationOutcome::Denied(implicit_deny_weight(
                    &loop_ctx.reputation_config,
                )),
            );
            session.stats.total_denied += 1;
            Ok(CallOutcome::Denied)
        }
    }
}

// ---------------------------------------------------------------------------
// Queue + freeze/thaw orchestration
// ---------------------------------------------------------------------------

/// How often a queued item re-checks the session allowlist while waiting for
/// its review - the cadence at which a scoped grant made on one prompt
/// drains the rest of the backlog. Matches the polling reviewer's interval.
const SCOPE_DRAIN_POLL: Duration = Duration::from_millis(250);

/// The shortened review window to use when the operator looks absent, or
/// `None` to use the configured `freeze_timeout_seconds`.
///
/// `unattended_review_streak == 0` disables the fallback.
fn unattended_review_timeout(loop_ctx: &SupervisorLoopContext<'_>) -> Option<Duration> {
    unattended_window(
        loop_ctx.config.unattended_review_streak,
        loop_ctx.unanswered_reviews.load(Ordering::Relaxed),
        loop_ctx.config.unattended_review_timeout_seconds,
    )
}

/// Pure form of [`unattended_review_timeout`], split out so the policy can be
/// exercised without building a whole loop context.
fn unattended_window(streak_limit: u32, unanswered: u32, fallback_secs: u64) -> Option<Duration> {
    if streak_limit == 0 || unanswered < streak_limit {
        return None;
    }
    Some(Duration::from_secs(fallback_secs))
}

/// Record how a review ended, so the next one knows whether anybody is there.
///
/// Only a timeout counts against the operator. Every other outcome means a
/// decision was made — locally, remotely, or by a scope grant — and clears the
/// streak, so someone who steps away and returns gets the full window back on
/// their very next prompt.
fn note_review_attendance(loop_ctx: &SupervisorLoopContext<'_>, outcome: ReviewOutcome) {
    let streak_limit = loop_ctx.config.unattended_review_streak;
    match note_attendance(streak_limit, &loop_ctx.unanswered_reviews, outcome) {
        AttendanceChange::WentUnattended(unanswered) => tracing::warn!(
            event = "review_operator_unattended",
            unanswered,
            fallback_seconds = loop_ctx.config.unattended_review_timeout_seconds,
            "reviews are expiring unanswered; shortening the window so a \
             queued call stops holding the session for one that is not coming"
        ),
        AttendanceChange::Returned(unanswered) => tracing::info!(
            event = "review_operator_returned",
            unanswered,
            "a review was answered; restoring the full review window"
        ),
        AttendanceChange::Unchanged => {}
    }
}

/// What [`note_attendance`] concluded, so the caller can log the transition
/// once rather than on every review.
#[derive(Debug, PartialEq, Eq)]
enum AttendanceChange {
    /// This timeout was the one that crossed the streak limit.
    WentUnattended(u32),
    /// A review was answered after the limit had been crossed.
    Returned(u32),
    Unchanged,
}

/// Pure form of [`note_review_attendance`]: fold one review outcome into the
/// unanswered counter and report whether that crossed a boundary.
fn note_attendance(
    streak_limit: u32,
    unanswered: &AtomicU32,
    outcome: ReviewOutcome,
) -> AttendanceChange {
    if streak_limit == 0 {
        return AttendanceChange::Unchanged;
    }
    if matches!(outcome, ReviewOutcome::TimedOut) {
        let now = unanswered.fetch_add(1, Ordering::Relaxed) + 1;
        return if now == streak_limit {
            AttendanceChange::WentUnattended(now)
        } else {
            AttendanceChange::Unchanged
        };
    }
    let previous = unanswered.swap(0, Ordering::Relaxed);
    if previous >= streak_limit {
        AttendanceChange::Returned(previous)
    } else {
        AttendanceChange::Unchanged
    }
}

/// True when `call_type` would be auto-allowed by the session-allowlist
/// short-circuit in [`handle_syscall_event`] if it were re-issued right now.
/// The same predicate, evaluated live: not under containment, not an
/// enforced authority-delegation call, not a sensitive scoped read (those
/// route through the proxy by design), and matching a session allowlist
/// entry (exact or scoped prefix).
///
/// Used to resolve queued items after the operator grants a scoped
/// permission on another prompt (`work/findings/mass-destruction-cargo-
/// churn-prompt-flood-2026-08-17.md`): once the grant lands, holding the
/// prompt buys no security - the tool could simply retry the syscall and be
/// silently allowed - so the backlog drains instead of stacking hundreds of
/// already-decided dialogs.
fn session_scope_now_covers(
    loop_ctx: &SupervisorLoopContext<'_>,
    session_id: Uuid,
    call_type: &grith_proxy::types::ToolCallType,
) -> bool {
    if SessionStateRegistry::global()
        .is_containment_active(SessionScopeKey::from_session_id(session_id))
    {
        return false;
    }
    // Mirror of `delegation_would_enforce` at the short-circuit: an enforced
    // authority-delegating spawn / control-socket connect must never be
    // drained away by a directory grant — unless the operator already approved
    // this exact command this session (then it is auto-allowed like any other).
    let already_user_approved_delegation = loop_ctx
        .session_allowed
        .lock()
        .is_ok_and(|s| s.contains(&delegating_approval_key(call_type)));
    let delegation_would_enforce = !already_user_approved_delegation
        && match call_type {
            grith_proxy::types::ToolCallType::ProcessSpawn { command, args } => {
                authority_delegation::spawn_enforcement_enabled(
                    loop_ctx.config.enforce_authority_delegating_spawn,
                ) && (spawn_delegation_would_enforce(loop_ctx, command, args)
                    || authority_delegation::ssh_loopback_should_escalate(
                        command,
                        args,
                        &loop_ctx.permit_authority_delegating,
                    )
                    || authority_delegation::input_injection_should_escalate(
                        command,
                        args,
                        &loop_ctx.permit_authority_delegating,
                    ))
            }
            grith_proxy::types::ToolCallType::NetConnect { address, .. } => {
                authority_delegation::control_socket_enforcement_enabled(
                    loop_ctx.config.enforce_control_socket_connect,
                ) && !dbus_inspection_covers(loop_ctx, address)
                    && authority_delegation::control_socket_should_escalate(
                        address,
                        &loop_ctx.permit_control_sockets,
                    )
                // NOT gated by work/84's clipboard carveout, deliberately:
                // this path is only reached for a call that ALREADY escalated
                // and is sitting in the queue, so a carved connect never
                // arrives here. Adding the check would need the connecting pid
                // threaded in for no behaviour change.
            }
            _ => false,
        };
    if delegation_would_enforce {
        return false;
    }
    let Some(key) = session_allowlist_key(call_type) else {
        return false;
    };
    loop_ctx.session_allowed.lock().is_ok_and(|allowed| {
        !is_sensitive_scoped_read_match(call_type, &allowed)
            && is_session_allowlist_match(&key, &allowed, call_type)
    })
}

async fn queue_and_wait(
    interceptor: &mut Box<dyn SyscallInterceptor>,
    session: &mut SupervisorSession,
    loop_ctx: &SupervisorLoopContext<'_>,
    ctx: &ToolCallContext,
    decision: &grith_proxy::types::ProxyDecision,
    tid: u32,
    event_pid: u32,
    trace_event_id: Uuid,
    // Propagated to `thaw_and_resume`: on a deny outcome, SIGKILL rather than
    // no-op `deny_syscall` for an enforced authority-delegating spawn.
    kill_on_deny: bool,
    // When true (an enforced authority-delegating call), an Approve outcome
    // records the exact command in the session allowlist so an identical
    // recurrence auto-allows instead of re-escalating.
    record_delegating_approval: bool,
) -> Result<CallOutcome> {
    let dlp_redactor = loop_ctx.dlp_redactor;
    let containment_tracker = &loop_ctx.containment_tracker;
    let config = loop_ctx.config;
    // The intercepted thread is already held at its ptrace/seccomp stop —
    // no SIGSTOP needed. We intentionally do NOT freeze the rest of the
    // process tree so that the supervised tool (e.g. Ink/Node.js) keeps
    // rendering while the single syscall thread awaits a permission decision.

    // Deny-replay: a request identical to one the operator denied (or let
    // time out) inside the replay window is denied again without a fresh
    // prompt — a retrying tool would otherwise re-open the same dialog once
    // per attempt. Keyed by the full call identity (the same rendering the
    // prompt shows), so any change in target or arguments prompts anew. The
    // window runs from the reviewed decision and is NOT refreshed by
    // replays: after it lapses the operator is asked again. The durable
    // audit record for this evaluation is still written by the caller.
    let replay_key = ctx.call_type.to_string();
    let replay_window = Duration::from_secs(config.deny_replay_seconds);
    if !replay_window.is_zero()
        && session
            .recent_denials
            .get(&replay_key)
            .is_some_and(|denied_at| denied_at.elapsed() < replay_window)
    {
        write_forensics_stage(
            loop_ctx,
            trace_event_id,
            session,
            event_pid,
            Some(&ctx.call_type),
            "deny_replayed",
            Some("auto-deny"),
            Some(decision.composite_score),
            Some("identical request denied moments ago"),
        );
        write_syscall_log(
            loop_ctx,
            session.root_pid,
            &ctx.call_type,
            decision.composite_score,
            "deny-replay",
            "identical request denied moments ago",
        );
        tracing::info!(
            event = "deny_replayed",
            session_id = %session.id,
            tid,
            call = %replay_key,
            window_seconds = config.deny_replay_seconds,
            "identical request denied within the replay window — denying without a prompt"
        );
        record_reputation_observation(
            loop_ctx,
            session,
            &ctx.call_type,
            grith_proxy::reputation::ReputationOutcome::Denied(implicit_deny_weight(
                &loop_ctx.reputation_config,
            )),
        );
        thaw_and_resume(interceptor, session, tid, false, kill_on_deny).await;
        session.stats.total_denied += 1;
        return Ok(CallOutcome::Denied);
    }

    // Control-socket answer replay: a session-lifetime memory for
    // Control-class connects only (session D-Bus, X11, tmux/screen).
    // The windowed approve-replay below is deliberately disabled under
    // containment, and every other approval memory is containment-gated
    // too — which meant a contained session opened a fresh freeze dialog
    // for EVERY control-socket connect (observed: four X11 prompts in one
    // run, two of them 2ms apart). Replaying here is sound even under
    // containment because the call has already re-scored through the full
    // pipeline this time (an auto-deny never reaches queue_and_wait); the
    // only thing suppressed is re-asking a question a human answered this
    // session. Checked after deny-replay so a recent explicit deny still
    // wins its window.
    if is_control_class_connect(ctx) {
        if let Some(approved) = session.control_socket_answers.get(&replay_key).copied() {
            let (stage, decision_str, note) = if approved {
                (
                    "control_socket_answer_replayed",
                    "auto-allow",
                    "control-socket prompt answered approve earlier this session",
                )
            } else {
                (
                    "control_socket_answer_replayed",
                    "auto-deny",
                    "control-socket prompt answered deny earlier this session",
                )
            };
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event_pid,
                Some(&ctx.call_type),
                stage,
                Some(decision_str),
                Some(decision.composite_score),
                Some(note),
            );
            write_syscall_log(
                loop_ctx,
                session.root_pid,
                &ctx.call_type,
                decision.composite_score,
                "control-socket-answer",
                note,
            );
            tracing::info!(
                event = "control_socket_answer_replayed",
                session_id = %session.id,
                tid,
                call = %replay_key,
                approved,
                "control-socket prompt already answered this session — replaying without a prompt"
            );
            // One binding for both arms so the returned fate cannot drift
            // from the branch that produced it.
            let replayed_outcome = if approved {
                CallOutcome::Executed
            } else {
                CallOutcome::Denied
            };
            if approved {
                thaw_and_resume(interceptor, session, tid, true, kill_on_deny).await;
                session.stats.total_allowed += 1;
            } else {
                record_reputation_observation(
                    loop_ctx,
                    session,
                    &ctx.call_type,
                    grith_proxy::reputation::ReputationOutcome::Denied(implicit_deny_weight(
                        &loop_ctx.reputation_config,
                    )),
                );
                thaw_and_resume(interceptor, session, tid, false, kill_on_deny).await;
                session.stats.total_denied += 1;
            }
            return Ok(replayed_outcome);
        }
    }

    // Approve-replay: a request identical to one the operator approved
    // inside the replay window is allowed without a fresh prompt. Most
    // approvals also add a session allowlist grant, but grant keys can fail
    // to match (exec provenance rejections, unresolvable paths) and some
    // call types carry no grant — a retrying tool would re-open the same
    // dialog once per attempt. Keyed by the full call identity like
    // deny-replay. Checked after deny-replay so when the same key has been
    // both approved and later denied, the more recent human decision wins
    // (a live deny window always postdates any live approve window: replays
    // never re-prompt, so a later approval can only exist once the deny
    // window has lapsed).
    //
    // Never consulted while containment is active: post-contamination,
    // session taint can change between retries, so every call must re-score
    // through the full pipeline and re-queue for review — mirroring the
    // session-allowlist bypass under containment.
    let approve_replay_window = Duration::from_secs(config.approve_replay_seconds);
    if !approve_replay_window.is_zero()
        && session
            .recent_approvals
            .get(&replay_key)
            .is_some_and(|approved_at| approved_at.elapsed() < approve_replay_window)
        && !SessionStateRegistry::global()
            .is_containment_active(SessionScopeKey::from_session_id(session.id))
    {
        write_forensics_stage(
            loop_ctx,
            trace_event_id,
            session,
            event_pid,
            Some(&ctx.call_type),
            "approve_replayed",
            Some("auto-allow"),
            Some(decision.composite_score),
            Some("identical request approved moments ago"),
        );
        write_syscall_log(
            loop_ctx,
            session.root_pid,
            &ctx.call_type,
            decision.composite_score,
            "approve-replay",
            "identical request approved moments ago",
        );
        tracing::info!(
            event = "approve_replayed",
            session_id = %session.id,
            tid,
            call = %replay_key,
            window_seconds = config.approve_replay_seconds,
            "identical request approved within the replay window — allowing without a prompt"
        );
        // Deliberately NO reputation observation, unlike deny-replay: a
        // replayed deny accruing distrust is fail-safe, but a replayed
        // approval accruing trust would let a tool whitewash its reputation
        // by looping one approved call. Only the original human approval
        // counts.
        thaw_and_resume(interceptor, session, tid, true, kill_on_deny).await;
        session.stats.total_allowed += 1;
        return Ok(CallOutcome::Executed);
    }

    // Enqueue a digest item for human review.
    let digest_item = build_digest_item(ctx, decision, dlp_redactor);
    let digest_id = digest_item.id;
    if let Err(e) = loop_ctx.digest_store.enqueue(&digest_item).await {
        tracing::error!(error = %e, "failed to enqueue digest item");
    }

    session.stats.total_queued += 1;

    // Wait for approval/denial (or timeout) before resuming the syscall.
    // A malformed/unsafe scoped proposal is returned to Pending instead of
    // denying the exact request, so the operator can edit the proposal or
    // fall back to a single-request approval.
    let session_id = session.id;
    let (outcome, review_action, validated_scope, drained) = loop {
        // Race the human review against the session allowlist: a scoped
        // grant made while this item waits (on any other prompt) resolves
        // it without an answer - re-issued now, the same op would
        // short-circuit before ever reaching the proxy, so holding the
        // prompt buys no security and stacks the queue. The digest status
        // is written BEFORE the reviewer is cancelled so a disconnected or
        // late reviewer cannot stomp it with an auto-deny.
        // A queued syscall holds this thread, and the supervisor's event loop
        // awaits the review inline, so it holds the whole session behind it.
        // Paying the full window is right while somebody is answering; once a
        // run of reviews has expired untouched it is only stall, and the
        // outcome (deny) is already decided. Shorten the wait until a human
        // resolves something.
        let review_timeout = unattended_review_timeout(loop_ctx)
            .unwrap_or_else(|| Duration::from_secs(config.freeze_timeout_seconds));
        let review = loop_ctx.reviewer.review(&digest_item, review_timeout);
        tokio::pin!(review);
        let (outcome, drained) = loop {
            tokio::select! {
                outcome = &mut review => break (outcome, false),
                () = tokio::time::sleep(SCOPE_DRAIN_POLL) => {
                    if session_scope_now_covers(loop_ctx, session_id, &ctx.call_type) {
                        if let Err(e) = loop_ctx
                            .digest_store
                            .update_status(
                                digest_id,
                                grith_digest::types::DigestStatus::Approved,
                                Some("scope_drain"),
                                Some("auto-approved: a session scope granted during review covers this target"),
                            )
                            .await
                        {
                            tracing::error!(
                                error = %e,
                                item_id = %digest_id,
                                "failed to record scope drain; leaving item for manual review"
                            );
                            continue;
                        }
                        loop_ctx.reviewer.cancel_review(digest_id).await;
                        break (ReviewOutcome::Approved, true);
                    }
                    // Remote resolution: a notification channel (Telegram,
                    // Slack, the dashboard, ...) approved or denied this item
                    // out-of-band while the local TUI dialog is still on
                    // screen. The reviewer future only wakes on a LOCAL
                    // answer, so without this poll a remote approval would
                    // leave the syscall frozen until the freeze timeout.
                    // Honour the persisted status and drop the now-stale
                    // local dialog (cancel_review). drained = false: a remote
                    // human answer earns the same side effects as a local one
                    // (reputation, approve-replay, session allowlist), and the
                    // downstream re-fetch of review_action preserves a scoped
                    // approval if the channel supplied one.
                    match loop_ctx.digest_store.get(digest_id).await {
                        Ok(Some(item)) => match item.status {
                            grith_digest::types::DigestStatus::Approved => {
                                tracing::info!(
                                    event = "remote_review_resolved",
                                    item_id = %digest_id,
                                    action = "approve",
                                    "review resolved out-of-band by a notification channel"
                                );
                                loop_ctx.reviewer.cancel_review(digest_id).await;
                                break (ReviewOutcome::Approved, false);
                            }
                            grith_digest::types::DigestStatus::Denied
                            | grith_digest::types::DigestStatus::Expired => {
                                tracing::info!(
                                    event = "remote_review_resolved",
                                    item_id = %digest_id,
                                    action = "deny",
                                    "review resolved out-of-band by a notification channel"
                                );
                                loop_ctx.reviewer.cancel_review(digest_id).await;
                                break (ReviewOutcome::Denied, false);
                            }
                            // Pending/Escalated: still awaiting a decision.
                            _ => {}
                        },
                        Ok(None) => {}
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                item_id = %digest_id,
                                "failed to poll digest status for remote resolution"
                            );
                        }
                    }
                }
            }
        };
        // Every path out of the race lands here, so this is the one place
        // that sees whether a person resolved the review or it simply ran
        // out. Recorded before the early return below, which a scope drain
        // takes.
        note_review_attendance(loop_ctx, outcome);
        if drained {
            break (outcome, Some("scope_drain".to_string()), None, true);
        }

        let review_action = match loop_ctx.digest_store.get(digest_id).await {
            Ok(item) => item.and_then(|item| item.review_action.clone()),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    item_id = %digest_id,
                    "failed to fetch digest review action"
                );
                None
            }
        };

        let parsed = review_action
            .as_deref()
            .and_then(grith_digest::PermissionReviewAction::from_storage_value);
        if matches!(outcome, ReviewOutcome::Approved) {
            if let Some(grith_digest::PermissionReviewAction::ScopedAllow(request)) = &parsed {
                match crate::scoped_permissions::validate_scoped_allow(
                    request,
                    &ctx.call_type.to_string(),
                ) {
                    Ok(scope) => break (outcome, review_action, Some(scope), false),
                    Err(error) => {
                        tracing::warn!(
                            item_id = %digest_id,
                            error = %error,
                            "invalid scoped approval; returning review to pending"
                        );
                        if let Err(update_error) = loop_ctx
                            .digest_store
                            .update_status(
                                digest_id,
                                grith_digest::types::DigestStatus::Pending,
                                None,
                                Some(&format!("Scoped approval rejected: {error}")),
                            )
                            .await
                        {
                            tracing::error!(
                                error = %update_error,
                                item_id = %digest_id,
                                "failed to return invalid scoped approval to pending"
                            );
                            break (ReviewOutcome::Denied, review_action, None, false);
                        }
                        continue;
                    }
                }
            }
            // JSON is reserved for structured actions. Do not accidentally
            // treat malformed or unknown JSON as a legacy exact approval.
            if review_action
                .as_deref()
                .is_some_and(|action| action.trim_start().starts_with('{'))
                && parsed.is_none()
            {
                if let Err(error) = loop_ctx
                    .digest_store
                    .update_status(
                        digest_id,
                        grith_digest::types::DigestStatus::Pending,
                        None,
                        Some("Invalid structured review action"),
                    )
                    .await
                {
                    tracing::error!(
                        error = %error,
                        item_id = %digest_id,
                        "failed to return malformed review action to pending"
                    );
                    break (ReviewOutcome::Denied, review_action, None, false);
                }
                continue;
            }
        }
        break (outcome, review_action, None, false);
    };

    match outcome {
        // Scope drain: resolved by a scoped session grant, not by a human
        // answering THIS prompt. Deliberately none of the manual-approval
        // side effects - no reputation observation (hundreds of drained
        // items must not convert one human decision into mass trust), no
        // exact allowlist entry (the scoped prefix already covers it), no
        // approve-replay entry, no learned rule.
        ReviewOutcome::Approved if drained => {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event_pid,
                Some(&ctx.call_type),
                "scope_drain_resolved",
                Some("auto-allow"),
                Some(decision.composite_score),
                Some("session scope granted during review covers this target"),
            );
            write_syscall_log(
                loop_ctx,
                session.root_pid,
                &ctx.call_type,
                decision.composite_score,
                "auto-allow",
                "scope drain: session scope granted during review covers this target",
            );
            tracing::info!(
                event = "scope_drain_resolved",
                session_id = %session.id,
                item_id = %digest_id,
                call = %replay_key,
                "queued item resolved by a session scope granted during review - prompt withdrawn"
            );
            thaw_and_resume(interceptor, session, tid, true, kill_on_deny).await;
        }
        ReviewOutcome::Approved => {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event_pid,
                Some(&ctx.call_type),
                "approved",
                Some("manual-allow"),
                Some(decision.composite_score),
                Some(review_action.as_deref().unwrap_or("approve")),
            );
            write_syscall_log(
                loop_ctx,
                session.root_pid,
                &ctx.call_type,
                decision.composite_score,
                "manual-allow",
                review_action.as_deref().unwrap_or("approve"),
            );
            dispatch_supervisor_review_side_effects(
                review_action.as_deref(),
                containment_tracker,
                ctx,
                decision,
                session.scope_name(),
            );
            // Exact-command approval for an enforced authority-delegating call:
            // record the full identity so an identical recurrence auto-allows
            // this session instead of re-escalating (the broad `exec:`/`net:`
            // allowlist entry added below is deliberately bypassed by the
            // enforcement path, so this dedicated key is what makes an approval
            // stick). Applies to any Approve/Always-allow of a delegating call.
            if record_delegating_approval {
                if let Ok(mut allowed) = loop_ctx.session_allowed.lock() {
                    let key = delegating_approval_key(&ctx.call_type);
                    if allowed.insert(key) {
                        tracing::info!(
                            call_type = %ctx.call_type,
                            "session allowlist: authority-delegating command approved for session"
                        );
                    }
                }
            }
            // Scoped approvals deliberately do not add an exact `rw:` entry:
            // that namespace would broaden write/create intent to
            // delete/chmod on the current target.
            if let Some(scope) = &validated_scope {
                if let Ok(mut allowed) = loop_ctx.session_allowed.lock() {
                    for rule in &scope.rules {
                        allowed.insert(rule.clone());
                    }
                }
                let summary = scope.rules.join(", ");
                tracing::info!(
                    directory = scope.directory,
                    rules = summary,
                    "session scoped permission applied"
                );
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event_pid,
                    Some(&ctx.call_type),
                    "scoped_allow_applied",
                    Some("manual-allow"),
                    Some(decision.composite_score),
                    Some(&summary),
                );
                if let Some(tx) = loop_ctx.event_tx {
                    let event = serde_json::json!({
                        "session_id": session.id.to_string(),
                        "tool_name": session.tool_name,
                        "call_type": format!("Scoped: {summary}"),
                        "plugin_id": format!("supervisor:{}", session.tool_name),
                        "score": 0.0,
                        "action": "scoped-allow",
                        "reason": format!("Session directory scope added for {}", scope.directory),
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                    });
                    let _ = tx.send(event.to_string());
                }
            } else {
                // An ambiguous-attribution NetConnect expands to one `net:`
                // entry per candidate hostname; every other call type yields
                // its single entry.
                let entries = approved_session_allowlist_entries(&ctx.call_type);
                if !entries.is_empty() {
                    // When the operator approves a connect whose connecting
                    // process is a trusted system `ssh`, mint a port-scoped
                    // `ssh-egress:<addr>:<port>` grant. That key is the only one
                    // honoured by the session-allowlist short-circuit while
                    // containment is latched, so the approval sticks across
                    // reconnects instead of re-prompting — but ONLY for the exact
                    // host:port the operator saw. Gated on the binary being real
                    // `ssh` so the containment-surviving namespace can never
                    // cover a profile-routine or arbitrary destination. Resolved
                    // before taking the lock (it reads /proc/<pid>/exe).
                    let ssh_egress_grant = match &ctx.call_type {
                        grith_proxy::types::ToolCallType::NetConnect { address, port }
                            if grith_proxy::ssh_connect::is_trusted_ssh_exe(u64::from(
                                event_pid,
                            )) =>
                        {
                            Some(ssh_egress_key(address, *port))
                        }
                        _ => None,
                    };
                    if let Ok(mut allowed) = loop_ctx.session_allowed.lock() {
                        let is_learn = review_action.as_deref() == Some("approve_and_learn");
                        for key in &entries {
                            if is_learn {
                                tracing::info!(key, "session allowlist: learned (persisted)");
                            } else {
                                tracing::info!(key, "session allowlist: approved");
                            }
                            allowed.insert(key.clone());
                        }
                        if let Some(grant) = &ssh_egress_grant {
                            tracing::info!(
                                key = grant,
                                "session allowlist: ssh-egress grant (survives containment)"
                            );
                            allowed.insert(grant.clone());
                        }

                        // Approving a Control-class IPC socket additionally
                        // mints the exe-bound `ipc-socket:` grant consumed by
                        // the control-socket escalation guard (the broad
                        // `net:` entry above is deliberately ignored by that
                        // path — it is exe-blind). Not minted under
                        // containment: post-contamination approvals must not
                        // create durable artifacts.
                        if !SessionStateRegistry::global()
                            .is_containment_active(SessionScopeKey::from_session_id(ctx.session_id))
                        {
                            if let Some(grant) = ipc_socket_grant_key_for_ctx(ctx) {
                                tracing::info!(
                                    key = grant,
                                    "session allowlist: exe-bound ipc-socket grant minted"
                                );
                                allowed.insert(grant);
                            }
                        }

                        // /tmp self-created subtree auto-allow: when the
                        // approved op is a top-level `/tmp/<name>` dir create
                        // (or file write/rename), also register a bare-path
                        // prefix so subsequent accesses anywhere in that
                        // subtree (or to that file) bypass the proxy without
                        // further prompts. See `tmp_self_created_prefix` for
                        // the carveouts and scope rules.
                        if let Some(tmp_prefix) = tmp_self_created_prefix(&ctx.call_type) {
                            tracing::info!(
                                entry = tmp_prefix,
                                "session allowlist: /tmp self-created subtree registered"
                            );
                            allowed.insert(tmp_prefix);
                        }

                        // Broadcast learned-rule feedback to the TUI log.
                        if is_learn {
                            if let Some(tx) = loop_ctx.event_tx {
                                let profile = session_scope_name(session);
                                let summary = entries.join(", ");
                                let event = serde_json::json!({
                                    "session_id": session.id.to_string(),
                                    "tool_name": session.tool_name,
                                    "call_type": format!("Learned: {summary}"),
                                    "plugin_id": format!("supervisor:{}", session.tool_name),
                                    "score": 0.0,
                                    "action": "learned",
                                    "reason": format!("Rule persisted for profile {profile}"),
                                    "timestamp": chrono::Utc::now().to_rfc3339(),
                                });
                                let _ = tx.send(event.to_string());
                            }
                        }
                    }
                }
            }
            // Record reputation observation for approved operations.
            {
                let weight = if review_action.as_deref() == Some("approve_and_learn") {
                    1.5
                } else {
                    1.0
                };
                record_reputation_observation_with_ctx(
                    loop_ctx,
                    session,
                    &ctx.call_type,
                    grith_proxy::reputation::ReputationOutcome::Approved(weight),
                    Some(&ctx.arguments),
                );
            }
            // Remember the reviewed approval so identical retries inside the
            // replay window are allowed without a fresh prompt (see the
            // approve-replay check above). Lapsed entries are purged here,
            // so the map stays bounded by recent human decisions.
            if config.approve_replay_seconds > 0 {
                let now = Instant::now();
                let window = Duration::from_secs(config.approve_replay_seconds);
                session
                    .recent_approvals
                    .retain(|_, at| now.duration_since(*at) < window);
                session.recent_approvals.insert(replay_key.clone(), now);
            }
            // Session-lifetime answer for Control-class connects — replayed
            // by queue_and_wait even under containment (see the field doc).
            if is_control_class_connect(ctx) {
                session.control_socket_answers.insert(replay_key, true);
            }
            thaw_and_resume(interceptor, session, tid, true, kill_on_deny).await;
        }
        ReviewOutcome::Denied | ReviewOutcome::TimedOut => {
            // work/85: a "block this directory" answer installs session
            // refusals before anything else runs, so the rules are live for
            // the very next call — the flood this action exists to stop is
            // usually already queued behind this prompt.
            //
            // Re-validated here rather than trusted from the reviewer: the
            // dialog and the supervisor are different processes on the digest
            // queue's two ends, and the rule that gets installed has to be one
            // this side agrees with.
            let scoped_deny = if matches!(outcome, ReviewOutcome::Denied) {
                review_action
                    .as_deref()
                    .and_then(grith_digest::PermissionReviewAction::from_storage_value)
                    .and_then(|action| match action {
                        grith_digest::PermissionReviewAction::ScopedDeny(request) => Some(request),
                        _ => None,
                    })
            } else {
                None
            };
            if let Some(request) = &scoped_deny {
                match crate::scoped_permissions::validate_scoped_deny(
                    request,
                    &ctx.call_type.to_string(),
                ) {
                    Ok(scope) => {
                        if let Ok(mut denied) = loop_ctx.session_denied.lock() {
                            for rule in &scope.rules {
                                denied.insert(rule.clone());
                            }
                        }
                        let summary = scope.rules.join(", ");
                        tracing::info!(
                            event = "scoped_deny_applied",
                            directory = scope.directory,
                            rules = summary,
                            "session directory block applied"
                        );
                        write_forensics_stage(
                            loop_ctx,
                            trace_event_id,
                            session,
                            event_pid,
                            Some(&ctx.call_type),
                            "scoped_deny_applied",
                            Some("manual-deny"),
                            Some(decision.composite_score),
                            Some(&summary),
                        );
                        if let Some(tx) = loop_ctx.event_tx {
                            let event = serde_json::json!({
                                "session_id": session.id.to_string(),
                                "tool_name": session.tool_name,
                                "call_type": format!("Blocked: {summary}"),
                                "plugin_id": format!("supervisor:{}", session.tool_name),
                                "score": 0.0,
                                "action": "scoped-deny",
                                "reason": format!(
                                    "Session directory block added for {}",
                                    scope.directory
                                ),
                                "timestamp": chrono::Utc::now().to_rfc3339(),
                            });
                            let _ = tx.send(event.to_string());
                        }
                    }
                    Err(error) => {
                        // The call is denied either way — this is the deny
                        // branch — so an unusable directory costs the operator
                        // the standing rule, not the protection they asked
                        // for, and is worth a warning rather than a re-prompt.
                        tracing::warn!(
                            event = "scoped_deny_rejected",
                            error = %error,
                            directory = request.directory,
                            "directory block rejected; this call is still denied"
                        );
                    }
                }
            }
            let reason = if matches!(outcome, ReviewOutcome::TimedOut) {
                "timeout"
            } else if scoped_deny.is_some() {
                // The raw action is a JSON blob; the log line wants a verb.
                "scoped_deny"
            } else {
                review_action.as_deref().unwrap_or("deny")
            };
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event_pid,
                Some(&ctx.call_type),
                "denied",
                Some("manual-deny"),
                Some(decision.composite_score),
                Some(reason),
            );
            write_syscall_log(
                loop_ctx,
                session.root_pid,
                &ctx.call_type,
                decision.composite_score,
                "manual-deny",
                reason,
            );
            if review_action.as_deref() == Some("deny_and_terminate") {
                kill_supervised_process_tree(session);
            }
            // Record reputation observation for denied operations.
            {
                let weight = if review_action.as_deref() == Some("deny_and_terminate") {
                    terminate_deny_weight(&loop_ctx.reputation_config)
                } else {
                    manual_deny_weight(&loop_ctx.reputation_config)
                };
                record_reputation_observation_with_ctx(
                    loop_ctx,
                    session,
                    &ctx.call_type,
                    grith_proxy::reputation::ReputationOutcome::Denied(weight),
                    Some(&ctx.arguments),
                );
            }
            // Remember the reviewed denial so identical retries inside the
            // replay window are denied without a fresh prompt. Lapsed
            // entries are purged here, so the map stays bounded by recent
            // human decisions.
            if config.deny_replay_seconds > 0 {
                let now = Instant::now();
                let window = Duration::from_secs(config.deny_replay_seconds);
                session
                    .recent_denials
                    .retain(|_, at| now.duration_since(*at) < window);
                session.recent_denials.insert(replay_key.clone(), now);
            }
            // Session-lifetime answer for Control-class connects. Only an
            // EXPLICIT deny records — a timeout is not a human answer and
            // must re-prompt next time.
            if matches!(outcome, ReviewOutcome::Denied) && is_control_class_connect(ctx) {
                session.control_socket_answers.insert(replay_key, false);
            }
            thaw_and_resume(interceptor, session, tid, false, kill_on_deny).await;
            session.stats.total_denied += 1;
        }
    }

    // The match above dispatches on `outcome`; the call's fate follows it
    // exactly. A scope-drained Approve still resumed the syscall.
    Ok(match outcome {
        ReviewOutcome::Approved => CallOutcome::Executed,
        ReviewOutcome::Denied | ReviewOutcome::TimedOut => CallOutcome::Denied,
    })
}

/// Dispatch side-effects for supervisor review actions beyond simple approve/deny.
fn dispatch_supervisor_review_side_effects(
    review_action: Option<&str>,
    containment_tracker: &Arc<ContainmentTracker>,
    ctx: &ToolCallContext,
    _decision: &grith_proxy::types::ProxyDecision,
    profile_scope: Option<&str>,
) {
    let Some(action) = review_action else {
        return;
    };
    match action {
        "approve_and_learn" => {
            // Persist the learned rule(s) to disk. An ambiguous-attribution
            // NetConnect expands to one `net:` rule per candidate hostname.
            if let Some(profile) = profile_scope {
                // Build a human-readable reason from the context arguments.
                let reason = ctx
                    .arguments
                    .get("process")
                    .and_then(|v| v.as_str())
                    .map(|proc| {
                        let target = ctx
                            .arguments
                            .get("process_args")
                            .and_then(|v| v.as_array())
                            .and_then(|args| {
                                args.iter().filter_map(|a| a.as_str()).find(|a| {
                                    !a.starts_with('-') && (a.contains('@') || a.contains('.'))
                                })
                            });
                        match target {
                            Some(t) => format!("{proc} → {t}"),
                            None => proc.to_string(),
                        }
                    })
                    .unwrap_or_default();

                // A Control-class IPC socket approval also persists the
                // exe-bound `ipc-socket:` grant, so the [l] answer holds
                // across sessions (the session-scoped `delegating-approved:`
                // key cannot be persisted, and the `net:` entry is skipped by
                // the enforcement path). Not minted under containment.
                let ipc_grant = if SessionStateRegistry::global()
                    .is_containment_active(SessionScopeKey::from_session_id(ctx.session_id))
                {
                    None
                } else {
                    ipc_socket_grant_key_for_ctx(ctx)
                };
                for entry in approved_session_allowlist_entries(&ctx.call_type)
                    .into_iter()
                    .chain(ipc_grant)
                {
                    if crate::learned_rules::validate_persisted_rule(&entry).is_err() {
                        continue;
                    }
                    let rule = crate::learned_rules::LearnedRule {
                        pattern: entry.clone(),
                        profile: profile.to_string(),
                        scope: "user".to_string(),
                        reason: reason.clone(),
                        created_at: chrono::Utc::now().to_rfc3339(),
                        created_by: String::new(),
                    };
                    let path = crate::learned_rules::default_learned_rules_path();
                    match crate::learned_rules::append_learned_rule(&path, rule) {
                        Ok(()) => {
                            tracing::info!(
                                pattern = entry,
                                profile,
                                path = %path.display(),
                                "learned rule persisted"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                pattern = entry,
                                "failed to persist learned rule"
                            );
                        }
                    }
                }
            }

            tracing::info!(
                session_id = %ctx.session_id,
                "approve_and_learn: recorded feedback for the reputation system"
            );
        }
        "unlock_egress" => {
            let removed = containment_tracker.unregister(ctx.session_id);
            tracing::info!(
                session_id = %ctx.session_id,
                was_contained = removed,
                "unlock_egress: lifted egress containment for session"
            );
        }
        "allow_always" => match grith_proxy::allowlist_persistence::persist_allow_always(ctx) {
            Ok(Some(path)) => {
                tracing::info!(
                    session_id = %ctx.session_id,
                    call_type = %ctx.call_type,
                    path = %path.display(),
                    "allow_always: persisted allowlist entry"
                );
            }
            Ok(None) => {
                tracing::info!(
                    session_id = %ctx.session_id,
                    call_type = %ctx.call_type,
                    "allow_always: call type has no persistable allowlist target"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    session_id = %ctx.session_id,
                    call_type = %ctx.call_type,
                    "allow_always: failed to persist allowlist entry"
                );
            }
        },
        _ => {}
    }
}

#[cfg(unix)]
fn kill_supervised_process_tree(session: &SupervisorSession) {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let kill_targets = process_tree_kill_targets(session);
    let root_pid = session.root_pid;
    let descendant_count = kill_targets.len().saturating_sub(1);

    tracing::info!(
        session_id = %session.id,
        root_pid,
        descendants = descendant_count,
        "deny_and_terminate: killing supervised process tree"
    );

    for pid in kill_targets {
        if let Err(e) = kill(Pid::from_raw(pid as i32), Signal::SIGKILL) {
            tracing::warn!(error = %e, pid, "SIGKILL failed");
        }
    }
}

#[cfg(not(unix))]
fn kill_supervised_process_tree(session: &SupervisorSession) {
    tracing::warn!(
        session_id = %session.id,
        root_pid = session.root_pid,
        "deny_and_terminate requested but process signaling is not supported on this platform"
    );
}

fn process_tree_kill_targets(session: &SupervisorSession) -> Vec<u32> {
    let root_pid = session.root_pid;
    let mut descendants = session
        .process_tree
        .all_pids()
        .into_iter()
        .filter(|p| *p != root_pid)
        .collect::<Vec<_>>();
    descendants.sort_unstable();
    descendants.dedup();
    descendants.push(root_pid);
    descendants
}

async fn thaw_and_resume(
    interceptor: &mut Box<dyn SyscallInterceptor>,
    _session: &mut SupervisorSession,
    tid: u32,
    allow: bool,
    // On a deny outcome, SIGKILL rather than the no-op `deny_syscall` for an
    // enforced authority-delegating spawn (intercepted at `PTRACE_EVENT_EXEC`).
    kill_on_deny: bool,
) {
    // No SIGCONT needed — child processes were never frozen.
    // Resume the stopped thread using its TID.
    let result = if allow {
        interceptor.allow(tid).await
    } else {
        deny_or_kill(interceptor, tid, kill_on_deny).await
    };
    if let Err(e) = result {
        let msg = if allow {
            "allow after approval failed"
        } else if kill_on_deny {
            "kill after review failed"
        } else {
            "deny after review failed"
        };
        tracing::warn!(error = %e, tid, "{msg}");
    }
}

fn log_exfil_annotations(
    session: &SupervisorSession,
    pid: u32,
    filter_results: &[grith_proxy::types::FilterResult],
) {
    if !grith_proxy::annotations::has_exfil_detections(filter_results) {
        return;
    }
    for annotation in grith_proxy::annotations::exfil_annotations(filter_results) {
        tracing::warn!(session_id = %session.id, pid, "{annotation}");
    }
}

// ---------------------------------------------------------------------------
// DNS query evaluation
// ---------------------------------------------------------------------------

/// Evaluate an in-line DNS query parsed from a supervised `sendto` on a DNS
/// socket. Returns `true` to allow the send (the query reaches the real
/// resolver untouched and the reply is observed at the `recvfrom` exit) or
/// `false` to block it (the interceptor denies the syscall with EPERM).
///
/// This uses the same transport-neutral decision service as connected proxy
/// routes. The two owners differ only in enforcement: an in-line refusal
/// denies the syscall, while a proxied refusal returns a DNS error response.
pub(super) async fn evaluate_dns_query_inline(
    session: &mut SupervisorSession,
    loop_ctx: &SupervisorLoopContext<'_>,
    tgid: u32,
    tid: u32,
    domain: &str,
    query_type: &str,
) -> bool {
    let trace_event_id = Uuid::new_v4();
    let call_type = grith_proxy::types::ToolCallType::DnsQuery {
        domain: domain.to_string(),
        query_type: query_type.to_string(),
    };

    if let Some(trace) = &loop_ctx.forensics_trace {
        trace.capture_dns_query(
            trace_event_id,
            session.id,
            tgid,
            &session.process_tree,
            tgid,
            &call_type,
        );
    }

    let Some(service) = loop_ctx.dns_decision_service.as_ref() else {
        tracing::error!(
            query_type,
            "DNS decision service unavailable; denying query"
        );
        session.stats.total_denied += 1;
        return false;
    };
    let request = crate::connected_dns_proxy::DnsDecisionRequest {
        // Route zero is reserved for the in-line inspection owner. The
        // production adapter omits route-only metadata for this sentinel.
        route_id: crate::connected_dns_proxy::ConnectedDnsRouteId(0),
        provenance: crate::connected_dns_proxy::DnsRouteProvenance {
            tgid,
            creator_tid: tid,
            socket_id: 0,
        },
        original_resolver: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
        transaction_id: 0,
        domain: domain.to_string(),
        query_type: query_type.to_string(),
        queue_action: loop_ctx.config.dns_inspection.proxy_queue_action,
    };
    let evaluation = AssertUnwindSafe(service.evaluate(request)).catch_unwind();
    let decision = match tokio::time::timeout(
        Duration::from_millis(loop_ctx.config.dns_inspection.proxy_policy_timeout_ms),
        evaluation,
    )
    .await
    {
        Ok(Ok(decision)) => decision,
        Ok(Err(_)) => crate::connected_dns_proxy::DnsDecision::InfrastructureFailure {
            reason: "DNS policy evaluation panicked".into(),
        },
        Err(_) => crate::connected_dns_proxy::DnsDecision::InfrastructureFailure {
            reason: "DNS policy evaluation timed out".into(),
        },
    };

    match decision {
        crate::connected_dns_proxy::DnsDecision::Allow => {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                tgid,
                Some(&call_type),
                "proxy_scored",
                Some("auto-allow"),
                None,
                Some("shared DNS decision service allowed query"),
            );
            tracing::debug!(query_type, "in-line DNS query allowed");
            true
        }
        crate::connected_dns_proxy::DnsDecision::Deny { reason } => {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                tgid,
                Some(&call_type),
                "proxy_scored",
                Some("auto-deny"),
                None,
                Some(&reason),
            );
            tracing::warn!(query_type, %reason, "in-line DNS query denied");
            session.stats.total_denied += 1;
            false
        }
        crate::connected_dns_proxy::DnsDecision::Queue { reason } => {
            let forward = loop_ctx.config.dns_inspection.proxy_queue_action
                == crate::config::DnsProxyQueueAction::Forward;
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                tgid,
                Some(&call_type),
                "proxy_scored",
                Some("queue"),
                None,
                Some(&reason),
            );
            tracing::info!(
                query_type,
                %reason,
                forward,
                "in-line DNS query queued"
            );
            session.stats.total_queued += 1;
            if !forward {
                session.stats.total_denied += 1;
            }
            forward
        }
        crate::connected_dns_proxy::DnsDecision::InfrastructureFailure { reason } => {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                tgid,
                Some(&call_type),
                "infrastructure_failure",
                Some("auto-deny"),
                None,
                Some(&reason),
            );
            tracing::error!(
                query_type,
                %reason,
                "DNS policy infrastructure failure; denying in-line query"
            );
            // Surface the outage in the TUI/dashboard ticker (rate-limited).
            // An infrastructure failure denies every DNS query the tool
            // makes, which otherwise looks like the tool silently hanging
            // while the counters barely move.
            if let Some(tx) = loop_ctx.event_tx {
                if dns_infrastructure_event_permitted() {
                    let event = serde_json::json!({
                        "type": "proxy_evaluation",
                        "session_id": session.id.to_string(),
                        "tool_name": session.tool_name,
                        "project_name": session.project_name,
                        "call_type": call_type.to_string(),
                        "call_id": format!("{}:dns-infrastructure", session.id),
                        "plugin_id": "supervisor",
                        "composite_score": 0.0,
                        "score": 0.0,
                        "action": "deny",
                        "evaluation_time_ms": 0.0,
                        "filter_results": [],
                        "reason": format!(
                            "DNS lookups are being blocked: {reason}. They stay \
                             blocked until the grith service recovers."
                        ),
                        "timestamp": Utc::now().to_rfc3339(),
                    })
                    .to_string();
                    let _ = tx.send(event);
                }
            }
            session.stats.total_denied += 1;
            false
        }
    }
}

/// At most one DNS-infrastructure-failure event per interval reaches the
/// TUI/dashboard ticker — an outage denies every query and would otherwise
/// flood the ticker with identical lines.
fn dns_infrastructure_event_permitted() -> bool {
    static LAST_EMITTED: Mutex<Option<Instant>> = Mutex::new(None);
    const INTERVAL: Duration = Duration::from_secs(30);
    let Ok(mut last) = LAST_EMITTED.lock() else {
        return false;
    };
    let now = Instant::now();
    if last.is_some_and(|at| now.duration_since(at) < INTERVAL) {
        return false;
    }
    *last = Some(now);
    true
}

// ---------------------------------------------------------------------------
// Session allowlist key extraction
// ---------------------------------------------------------------------------

/// Extract a key suitable for the session allowlist from a `ToolCallType`.
///
/// For file operations, this returns the path. For network operations, it
/// Unix domain socket paths that grant full control-plane access to container
/// runtimes.  A process with write access to these sockets can launch arbitrary
/// containers (effectively root), exfiltrate data, or escape the sandbox.
///
/// Connections to these paths must NOT be silently allowed as local-only noise —
/// they are routed through the full proxy pipeline with `address = "unix:<path>"`.
///
/// For user-session Podman sockets (`/run/user/*/podman/podman.sock`) a
/// wildcard prefix match via [`is_sensitive_unix_socket`] covers all UIDs.
const SENSITIVE_UNIX_SOCKETS: &[&str] = &[
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/containerd/containerd.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
    "/run/crio/crio.sock",
    "/var/run/podman/podman.sock",
];

/// Evaluate a tool call through the proxy, preferring the remote daemon
/// when available. If the daemon becomes unreachable mid-session, fail closed
/// instead of silently reverting to an isolated local proxy state.
async fn evaluate_proxy(
    loop_ctx: &SupervisorLoopContext<'_>,
    ctx: &grith_proxy::types::ToolCallContext,
) -> grith_proxy::types::ProxyDecision {
    // Try remote daemon evaluation if configured.
    if let (Some(url), Some(token)) = (&loop_ctx.daemon_proxy_url, &loop_ctx.daemon_proxy_token) {
        let current_token = token
            .lock()
            .ok()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        match remote_proxy_evaluate(url, &current_token, ctx, Some(&loop_ctx.observation_outbox))
            .await
        {
            Ok(decision) => {
                if let Some(restart_state) = &loop_ctx.daemon_restart {
                    restart_state.note_success();
                }
                return decision;
            }
            Err(e) => {
                // Stale-token fast path: a 401/403 from a live daemon usually
                // means the daemon restarted and rotated its IPC token — the
                // current token is already on disk. Reload it and retry before
                // considering a restart.
                if e.is_auth_rejection() {
                    if let Some(restart_state) = &loop_ctx.daemon_restart {
                        if let Some(fresh) =
                            reload_rotated_token(&restart_state.config, token, &current_token)
                        {
                            match remote_proxy_evaluate(
                                url,
                                &fresh,
                                ctx,
                                Some(&loop_ctx.observation_outbox),
                            )
                            .await
                            {
                                Ok(decision) => {
                                    restart_state.note_success();
                                    return decision;
                                }
                                Err(retry_error) => {
                                    tracing::warn!(
                                        error = %retry_error,
                                        "remote proxy evaluation still failed after token reload"
                                    );
                                }
                            }
                        }
                    }
                }
                if let Some(restart_state) = &loop_ctx.daemon_restart {
                    if restart_state.take_attempt() {
                        tracing::warn!(
                            error = %e,
                            "remote proxy evaluation failed, attempting daemon restart once"
                        );
                        match attempt_daemon_restart(&restart_state.config).await {
                            Ok(new_token) => {
                                if let Ok(mut guard) = token.lock() {
                                    *guard = new_token.clone();
                                }
                                match remote_proxy_evaluate(
                                    url,
                                    &new_token,
                                    ctx,
                                    Some(&loop_ctx.observation_outbox),
                                )
                                .await
                                {
                                    Ok(decision) => return decision,
                                    Err(retry_error) => {
                                        tracing::warn!(
                                            error = %retry_error,
                                            "remote proxy evaluation still failed after restart attempt"
                                        );
                                        return daemon_unreachable_decision(retry_error);
                                    }
                                }
                            }
                            Err(restart_error) => {
                                tracing::warn!(error = %restart_error, "daemon restart attempt failed");
                            }
                        }
                    }
                }
                tracing::warn!(
                    error = %e,
                    "remote proxy evaluation failed, denying operation for safety"
                );
                return daemon_unreachable_decision(e);
            }
        }
    }
    // Fallback: local in-process proxy.
    loop_ctx.proxy.evaluate(ctx).await
}

fn daemon_unreachable_decision(error: impl std::fmt::Display) -> grith_proxy::types::ProxyDecision {
    grith_proxy::types::ProxyDecision {
        action: grith_proxy::types::ProxyAction::Deny {
            reason: DAEMON_UNREACHABLE_REASON.to_string(),
        },
        composite_score: f64::INFINITY,
        filter_results: Vec::new(),
        evaluation_time: std::time::Duration::from_secs(0),
        decision_reason: format!("Daemon unreachable; operation denied for safety: {error}"),
    }
}

/// Reload the IPC token from disk after an auth rejection, updating the
/// session's shared token so every holder (including the DNS decision
/// service) heals together.
fn reload_rotated_token(
    config: &DaemonRestartConfig,
    shared: &Arc<Mutex<String>>,
    just_used: &str,
) -> Option<String> {
    remote_eval::reload_rotated_token(&config.token_path, shared, just_used)
}

async fn attempt_daemon_restart(
    config: &DaemonRestartConfig,
) -> std::result::Result<String, String> {
    let mut args = Vec::new();
    if let Some(path) = &config.config_path {
        args.push("--config".to_string());
        args.push(path.display().to_string());
    }
    args.push("dashboard".to_string());
    args.push("start".to_string());

    std::process::Command::new(&config.executable)
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;

    tokio::time::sleep(Duration::from_millis(750)).await;
    std::fs::read_to_string(&config.token_path)
        .map(|token| token.trim().to_string())
        .map_err(|e| e.to_string())
}

/// Deny reason stamped when no proxy scored the call at all.
///
/// `observe_outcome` pairs with `evaluate`. When the daemon is unreachable
/// nothing evaluated the call, so there is no staged state to commit and
/// observing it would push a refusal into a filter that never saw the attempt
/// - manufacturing exfil pressure out of an outage.
pub(super) const DAEMON_UNREACHABLE_REASON: &str = "daemon_unreachable";

/// Whether this decision came from an actual evaluation.
fn was_evaluated(decision: &grith_proxy::types::ProxyDecision) -> bool {
    !matches!(
        &decision.action,
        grith_proxy::types::ProxyAction::Deny { reason } if reason == DAEMON_UNREACHABLE_REASON
    )
}

/// Send any outcomes still waiting in the outbox to the daemon.
pub(super) async fn flush_observation_outbox(
    loop_ctx: &SupervisorLoopContext<'_>,
    base_url: &str,
    token: &str,
) {
    let client = reqwest::Client::new();
    remote_eval::flush_observations(&client, base_url, token, &loop_ctx.observation_outbox).await;
}

/// Report a call's final outcome to whichever proxy actually scored it.
///
/// Mirrors `evaluate_proxy`'s exclusive remote/local branch. In daemon mode the
/// LOCAL proxy is deliberately never touched: the call was scored by the
/// daemon's `SecurityProxy`, so committing locally would advance filters that
/// never saw it while leaving the daemon's own state permanently inert.
fn observe_proxy_outcome(
    loop_ctx: &SupervisorLoopContext<'_>,
    ctx: &grith_proxy::types::ToolCallContext,
    outcome: CallOutcome,
    attempt_start: std::time::Instant,
) {
    let attempt_age = attempt_start.elapsed();
    // Both must be set, matching `evaluate_proxy`'s own condition: a URL
    // without a token never evaluated remotely, so its outcome belongs to the
    // local proxy.
    if loop_ctx.daemon_proxy_url.is_some() && loop_ctx.daemon_proxy_token.is_some() {
        loop_ctx
            .observation_outbox
            .push(remote_eval::PendingObservation {
                attempted_at: attempt_start,
                observation: remote_eval::WireObservation {
                    call_id: ctx.id,
                    scope: ctx
                        .session_scope
                        .map(|s| s.as_uuid())
                        .unwrap_or(ctx.session_id),
                    session_id: ctx.session_id,
                    call_type: ctx.call_type.clone(),
                    // Both are read by filters at commit time; omitting them makes
                    // the daemon's view of the call differ from the one it scored.
                    profile_name: ctx.profile_name.clone(),
                    arguments: ctx.arguments.clone(),
                    outcome,
                    // Overwritten at send time; an observation can wait in the
                    // outbox across many calls.
                    age_ms: 0,
                },
            });
        return;
    }
    loop_ctx.proxy.observe_outcome(ctx, outcome, attempt_age);
}

/// Call the daemon's proxy evaluate endpoint via HTTP.
async fn remote_proxy_evaluate(
    base_url: &str,
    token: &str,
    ctx: &grith_proxy::types::ToolCallContext,
    outbox: Option<&remote_eval::ObservationOutbox>,
) -> std::result::Result<grith_proxy::types::ProxyDecision, RemoteEvalError> {
    let client = reqwest::Client::new();
    let batch = outbox.map(|o| o.take()).unwrap_or_default();
    let sent = batch.len();
    let wire = remote_eval::ObservationOutbox::to_wire(&batch);
    match remote_eval::post_evaluate_with_observations(&client, base_url, token, ctx, wire).await {
        Ok(body) => {
            if sent > 0 {
                tracing::trace!(sent, "flushed pending outcome observations to the daemon");
            }
            parse_daemon_decision(&body).map_err(RemoteEvalError::Parse)
        }
        Err(error) => {
            // The daemon never applied them, so they must not be lost.
            if let Some(outbox) = outbox {
                outbox.restore(batch);
            }
            Err(error)
        }
    }
}

/// Read the daemon's evaluate response into a decision.
fn parse_daemon_decision(
    body: &serde_json::Value,
) -> std::result::Result<grith_proxy::types::ProxyDecision, String> {
    let composite_score = body["composite_score"]
        .as_f64()
        .ok_or("missing composite_score")?;
    let action_str = body["action"].as_str().ok_or("missing action")?;

    let action = if action_str == "allow" {
        grith_proxy::types::ProxyAction::Allow
    } else if let Some(reason) = action_str.strip_prefix("deny:") {
        grith_proxy::types::ProxyAction::Deny {
            reason: reason.to_string(),
        }
    } else if action_str.starts_with("queue:") {
        let priority = if action_str.contains("Critical") {
            grith_proxy::types::QueuePriority::Critical
        } else if action_str.contains("High") {
            grith_proxy::types::QueuePriority::High
        } else if action_str.contains("Medium") {
            grith_proxy::types::QueuePriority::Medium
        } else {
            grith_proxy::types::QueuePriority::Low
        };
        grith_proxy::types::ProxyAction::Queue { priority }
    } else {
        return Err(format!("unknown action: {action_str}"));
    };

    let decision_reason = body["decision_reason"].as_str().unwrap_or("").to_string();

    let filter_results: Vec<grith_proxy::types::FilterResult> = body["filter_results"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|fr| {
                    let severity = match fr["severity"].as_str().unwrap_or("Notice") {
                        "Critical" | "critical" => grith_proxy::types::Severity::Critical,
                        "Error" | "error" => grith_proxy::types::Severity::Error,
                        "Warning" | "warning" => grith_proxy::types::Severity::Warning,
                        _ => grith_proxy::types::Severity::Notice,
                    };
                    Some(grith_proxy::types::FilterResult {
                        filter_name: fr["filter_name"].as_str()?.to_string(),
                        matched: fr["matched"].as_bool()?,
                        score: fr["score"].as_f64()?,
                        rule_id: fr["rule_id"].as_str().unwrap_or("").to_string(),
                        severity,
                        message: fr["message"].as_str().unwrap_or("").to_string(),
                        metadata: std::collections::HashMap::new(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(grith_proxy::types::ProxyDecision {
        action,
        composite_score,
        filter_results,
        evaluation_time: std::time::Duration::from_secs_f64(
            body["evaluation_time_ms"].as_f64().unwrap_or(0.0) / 1000.0,
        ),
        decision_reason,
    })
}

/// H2 Option 1: `true` when `call_type` is a WRITE to a `/dev/pts/N` that is
/// not the supervised tool's own controlling terminal (`own_pts`). Writes to
/// the tool's own terminal, reads, and any non-pts path return `false`. When
/// `own_pts` is `None` (could not resolve) we conservatively do NOT flag, to
/// avoid false positives on a grith-side resolution failure.
fn is_foreign_pts_write(call_type: &ToolCallType, path: &str, own_pts: Option<&str>) -> bool {
    if !matches!(
        call_type,
        ToolCallType::FileWrite { .. } | ToolCallType::FileAppend { .. }
    ) {
        return false;
    }
    if !path.starts_with("/dev/pts/") {
        return false;
    }
    matches!(own_pts, Some(own) if path != own)
}

// `is_control_injection_socket` and `is_authority_delegating_binary` moved to
// the `authority_delegation` module, which owns their curated lists and the
// enforcement escalation built on them.

/// Classify a `NetConnect`/`NetListen` address for the proxy's
/// [`UnixSocketClass`](grith_proxy::types::UnixSocketClass) label.
///
/// `Privileged` wins over `Control` (checked first): a daemon control
/// socket must keep full network-grade scoring even if a marker ever
/// overlaps. A leading `@` (abstract-namespace render) is stripped before
/// the sensitive check so an abstract name mimicking a sensitive path
/// classifies as `Privileged` — over-scoring an impostor is the fail-safe
/// direction. Non-`unix:` addresses and the empty render
/// (unnamed/autobind) carry no label.
fn classify_unix_socket(address: &str) -> Option<grith_proxy::types::UnixSocketClass> {
    let path = address.strip_prefix("unix:")?;
    let bare = path.strip_prefix('@').unwrap_or(path);
    if bare.is_empty() {
        return None;
    }
    if is_sensitive_unix_socket(bare) {
        return Some(grith_proxy::types::UnixSocketClass::Privileged);
    }
    if authority_delegation::is_control_injection_socket(address) {
        return Some(grith_proxy::types::UnixSocketClass::Control);
    }
    None
}

/// Durable, client-bound grant key for a Control-class IPC socket connect:
/// `ipc-socket:<rendered address>|<canonical client exe>`.
///
/// Binding to the connecting binary's `/proc/<pid>/exe` is what makes the
/// grant strictly narrower than the session-scoped `delegating-approved:`
/// key it complements: approving `gh`'s session-bus keyring read must not
/// cover an in-process D-Bus payload inside `node` — same socket, different
/// client. Returns `None` (→ no grant, always prompt) for anything that is
/// not an unpermitted control socket, for Privileged daemon sockets
/// (deliberately un-grantable), and whenever the client exe cannot be
/// resolved — including a deleted/replaced binary, whose readlink renders
/// with a ` (deleted)` suffix.
fn ipc_socket_grant_key_parts(address: &str, pid: u64) -> Option<String> {
    let path = address.strip_prefix("unix:")?;
    let bare = path.strip_prefix('@').unwrap_or(path);
    if bare.is_empty() || is_sensitive_unix_socket(bare) {
        return None;
    }
    if !authority_delegation::is_control_injection_socket(address) {
        return None;
    }
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let exe = exe.to_str()?;
    if exe.ends_with(" (deleted)") {
        return None;
    }
    Some(format!("ipc-socket:{address}|{exe}"))
}

/// True when a connect to `address` is covered by D-Bus message inspection,
/// so the *connection* is no longer the enforcement point.
///
/// The connect is still scored and audited; what changes is that it is not
/// escalated to a prompt, because the authority it might carry is decided per
/// method call instead (see [`crate::dbus`]). Only D-Bus endpoints qualify —
/// X11, tmux and screen carry no per-message destination and keep
/// connect-time enforcement.
///
/// Deliberately does not consult the profile permit list: an address the
/// operator already permitted is not escalated anyway, and adding the check
/// here would only duplicate it.
fn dbus_inspection_covers(loop_ctx: &SupervisorLoopContext, address: &str) -> bool {
    // `dbus_inspection_armed`, not the config flag: the interceptor confirmed
    // at session start that it can see this session's bus writes. Trusting the
    // config alone would suppress the connect-time prompt in a session where
    // nothing downstream is watching.
    loop_ctx.dbus_inspection_armed && crate::dbus::is_dbus_socket(address)
}

/// True when `ctx` is a `NetConnect` the supervisor labelled Control-class
/// (session D-Bus, X11, tmux/screen) — the calls covered by the
/// session-lifetime `control_socket_answers` replay.
fn is_control_class_connect(ctx: &ToolCallContext) -> bool {
    matches!(
        ctx.call_type,
        grith_proxy::types::ToolCallType::NetConnect { .. }
    ) && matches!(
        ctx.unix_socket_class(),
        Some(grith_proxy::types::UnixSocketClass::Control)
    )
}

/// True when the taint or session-containment filter contributed to this
/// decision.
///
/// Consumed by the `--allow-queued` (`InteractiveQueueAction::Log`) branch,
/// which auto-allows queued calls in a headless session. Those two filters do
/// not report ordinary policy friction — they report that this session has
/// already read something sensitive or been contained — so a blanket
/// throughput flag must not clear them.
fn contamination_signalled(decision: &grith_proxy::types::ProxyDecision) -> bool {
    decision
        .filter_results
        .iter()
        .any(|r| r.matched && matches!(r.filter_name.as_str(), "taint" | "session-containment"))
}

/// [`ipc_socket_grant_key_parts`] for a built proxy context (the connect's
/// `pid` is stamped into `ctx.arguments` by `supervisor_event_arguments`).
fn ipc_socket_grant_key_for_ctx(ctx: &ToolCallContext) -> Option<String> {
    let grith_proxy::types::ToolCallType::NetConnect { address, .. } = &ctx.call_type else {
        return None;
    };
    let pid = ctx.arguments.get("pid")?.as_u64()?;
    ipc_socket_grant_key_parts(address, pid)
}

/// Returns `true` if `path` is a sensitive Unix socket that grants container
/// runtime control and must not be silently allowed.
pub(crate) fn is_sensitive_unix_socket(path: &str) -> bool {
    if SENSITIVE_UNIX_SOCKETS.contains(&path) {
        return true;
    }
    // Covers /run/user/<uid>/podman/podman.sock for any user ID.
    if path.contains("podman.sock") {
        return true;
    }

    // --- Root/host-daemon control sockets (curated LOW-FP denylist). ---
    // Each grants RCE-equivalent control of a privileged daemon whose work
    // runs OUTSIDE the ptrace tree (VM / container / service / print
    // managers) = a supervision escape. Returning `true` here makes
    // is_local_connect_address()/is_local_listen_address() report them
    // non-local; the connect then reaches evaluate_proxy and QUEUEs as an
    // unknown destination. QUEUE not DENY: an operator approves a legitimate
    // use once and the session allowlist (net:unix:<path>) remembers it.
    // Matched by SHAPE (family: multi-UID /run/user, /run vs /var/run,
    // per-container), not fixed strings. The high-frequency benign sockets
    // (journald, session/system D-Bus [handled by is_control_injection_socket],
    // systemd-resolved NSS varlink under .../resolve/, X11, PulseAudio,
    // PipeWire, nscd) are deliberately NOT matched by any branch below.

    // libvirt RW control sockets: system (/run/libvirt/, /var/run/libvirt/)
    // and session mode (/run/user/<uid>/libvirt/…). RW *-sock names
    // (libvirt-sock, virtqemud-sock, virtnetworkd-sock, virtstoraged-sock,
    // …); the read-only *-sock-ro variants deliberately stay local (info-only,
    // cannot define a domain).
    if path.contains("/libvirt/") && path.ends_with("-sock") {
        return true;
    }
    // systemd manager private control socket — start/stop units = arbitrary
    // code. Covers the system manager (/run/systemd/private) and a --user
    // manager (/run/user/<uid>/systemd/private).
    if path.ends_with("/systemd/private") {
        return true;
    }
    // systemd manager Varlink API (io.systemd.Manager, …). ANCHORED to the
    // manager dir on purpose: this must NOT match the high-frequency
    // nss-resolve socket /run/systemd/resolve/io.systemd.Resolve (lives under
    // …/resolve/, used by glibc name resolution).
    if path.starts_with("/run/systemd/io.systemd.")
        || path.starts_with("/var/run/systemd/io.systemd.")
    {
        return true;
    }
    // Podman Varlink API socket (no ".sock" suffix, so the podman.sock check
    // above misses it): /run/podman/io.podman and rootless
    // /run/user/<uid>/podman/io.podman.
    if path.ends_with("/io.podman") {
        return true;
    }
    // containerd control socket, incl. rootless (/run/user/<uid>/containerd/…)
    // which the SENSITIVE_UNIX_SOCKETS exact list misses; and buildkit.
    if path.ends_with("/containerd.sock") || path.ends_with("/buildkitd.sock") {
        return true;
    }
    // CUPS control socket — printer/filter/driver config has a long RCE
    // history. Anchored to the socket itself (not the whole /run/cups/ dir) to
    // minimise the benign-print-enumeration prompt surface.
    if path.ends_with("/cups.sock")
        && (path.starts_with("/run/cups/") || path.starts_with("/var/run/cups/"))
    {
        return true;
    }
    // LXC per-container command socket (/var/lib/lxc/<name>/command) and the
    // runtime dir (/run/lxc/) — driving a container escapes supervision.
    if (path.starts_with("/var/lib/lxc/") && path.ends_with("/command"))
        || path.starts_with("/run/lxc/")
    {
        return true;
    }

    // SSH / GPG agent sockets (research doc §5.1 #13): a prompt injection could
    // poke the agent to sign/decrypt. They stay "sensitive" so an *unexpected*
    // process touching them is surfaced; the routine git/ssh/gpg case is carved
    // out by `connect_is_routine_agent_use` at connect time (FP research §5.1).
    is_agent_socket_path(path)
}

/// SSH / GPG agent socket by shape. Paths are dynamic ($SSH_AUTH_SOCK,
/// /tmp/ssh-XXXX/agent.NNN, gnome-keyring, systemd user socket,
/// ~/.gnupg/S.gpg-agent).
fn is_agent_socket_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("/s.gpg-agent")
        || p.contains("/gpg-agent")
        || p.contains("/keyring/ssh")
        || p.contains("/ssh-agent")
        || looks_like_openssh_agent_socket(&p)
}

/// OpenSSH agent socket shape: `/tmp/ssh-XXXXXX/agent.<pid>`. Requires the
/// `agent.` to be followed by a digit so it doesn't match benign mux/control
/// sockets like `~/ssh-mux/agent.ctl`.
fn looks_like_openssh_agent_socket(p: &str) -> bool {
    if !p.contains("/ssh-") {
        return false;
    }
    match p.find("/agent.") {
        Some(idx) => p[idx + "/agent.".len()..]
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// Binaries that legitimately use the SSH/GPG agent. The agent socket itself is
/// local IPC for signing/auth; the actual exfil channel is the subsequent
/// *network* connection, which `egress-policy` scores independently. So when a
/// recognised agent client connects to an agent socket, it is routine local IPC
/// (FP research §5.1 — fixes the credentialed-git-over-SSH / GPG-signed-commit
/// false positive). A NON-client process touching the agent socket is NOT
/// carved out — it stays sensitive (the paired guard).
const AGENT_CLIENT_BINARIES: &[&str] = &[
    "ssh",
    "git",
    "gpg",
    "gpg2",
    "ssh-add",
    "scp",
    "sftp",
    "gpgconf",
    "gpg-connect-agent",
    "ssh-agent",
    "git-remote-https",
    "git-remote-http",
];

/// True when `address` is an agent socket AND the connecting process (`pid`)
/// is a recognised agent client resolved from a routine exec root — i.e.
/// routine local agent IPC that must not be held.
///
/// Mirrors the PR 6 `namespace_users` two-part carveout (see the NamespaceOp
/// block in `handle_syscall_event`): the carveout requires BOTH
///   1. the process's canonical exe basename is a known agent client, AND
///   2. that canonical path is under a `routine_exec_root`.
///
/// Identity is read from `/proc/<pid>/exe` (authoritative while the tracee is
/// syscall-stopped), NOT a spoofable argv[0]/process-tree name. A binary that
/// cannot be resolved (e.g. deleted after exec) → fail safe (stays sensitive).
///
/// This closes the basename-only hole: a client-NAMED binary dropped outside a
/// routine root (`cp /bin/sh /tmp/git && /tmp/git …`) is NOT carved out. A
/// non-client process is likewise not carved out (the paired guards). The
/// caller additionally gates this on `!containment_active`, so a high-taint
/// (contained) session never silently uses the agent.
fn connect_is_routine_agent_use(address: &str, pid: u32, routine_exec_roots: &[String]) -> bool {
    let Some(unix_path) = address.strip_prefix("unix:") else {
        return false;
    };
    if !is_agent_socket_path(unix_path) {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(format!("/proc/{pid}/exe")) else {
        return false; // unresolvable binary → fail safe (stays sensitive)
    };
    exe_is_agent_client_in_routine_root(&canonical.to_string_lossy(), routine_exec_roots)
}

/// Pure policy half of [`connect_is_routine_agent_use`]: given a connecting
/// process's already-resolved canonical exe path, is it a known agent client
/// living under one of the routine exec roots? Both conditions are required.
/// Extracted so the two-part gate is unit-testable without a live `/proc`.
fn exe_is_agent_client_in_routine_root(canonical_exe: &str, routine_exec_roots: &[String]) -> bool {
    let base = canonical_exe.rsplit('/').next().unwrap_or(canonical_exe);
    if !AGENT_CLIENT_BINARIES.contains(&base) {
        return false;
    }
    routine_exec_roots.iter().any(|root| {
        let trimmed = root.trim_end_matches('/');
        canonical_exe
            .strip_prefix(trimmed)
            .is_some_and(|rest| rest.starts_with('/'))
            || canonical_exe == trimmed
    })
}

/// Check if a connect target is local-only (never leaves the machine).
/// Covers Unix domain sockets, loopback, and unspecified addresses.
///
/// Unix domain socket addresses are expected in the `"unix:<path>"` format
/// produced by [`classify::read_sockaddr`].  Sensitive socket paths (container
/// runtime control sockets) return `false` so they flow through the proxy.
fn is_local_connect_address(address: &str) -> bool {
    // Unix domain sockets (prefixed with "unix:" by read_sockaddr).
    if let Some(unix_path) = address.strip_prefix("unix:") {
        // Sensitive sockets (e.g. Docker daemon) are NOT local-only.
        return !is_sensitive_unix_socket(unix_path);
    }
    // Legacy: raw paths starting with "/" or empty (pre-unix: era).
    if address.starts_with('/') || address.is_empty() {
        return true;
    }
    if address.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // Parse as IP and check loopback/unspecified
    if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        return ip.is_loopback() || ip.is_unspecified();
    }
    false
}

/// Check if a listen address is local-only for silent allow.
///
/// Unlike connect targets, wildcard binds (0.0.0.0 / ::) are not local: they
/// expose the listener on every interface and must be reviewed.
/// PR 5 Phase D: rewrite a wildcard `NetListen` to loopback at the
/// syscall-argument level when the proxy allowed it. The proxy reaches
/// the Allow branch in two shapes for `NetListen`:
///   1. Loopback bind — nothing to do; return Ok(()).
///   2. Wildcard bind with `listener_policy_match.allow_clamp = true` —
///      egress-policy silently passed it through; we now rewrite the
///      tracee's sockaddr to loopback before the kernel processes
///      `bind(2)`.
///
/// Returns `Err` if the clamp fails (caller must fail-closed: deny
/// the syscall rather than allow the wildcard bind to proceed).
async fn maybe_clamp_listen_address(
    ctx: &ToolCallContext,
    _decision: &grith_proxy::types::ProxyDecision,
    stopped_tid: u32,
    event_pid: u32,
) -> Result<()> {
    // Only NetListen calls are eligible.
    let (address, port) = match &ctx.call_type {
        ToolCallType::NetListen { address, port } => (address.as_str(), *port),
        _ => return Ok(()),
    };
    // Loopback already? Nothing to clamp.
    let parsed: std::net::IpAddr = match address.parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(()), // not an IP — non-clampable shape
    };
    if parsed.is_loopback() {
        return Ok(());
    }
    let is_wildcard = parsed.is_unspecified()
        || matches!(
            parsed,
            std::net::IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_unspecified())
        );
    if !is_wildcard {
        return Ok(());
    }
    // Policy must authorise clamp.
    let allow_clamp = ctx
        .listener_policy_match
        .as_ref()
        .is_some_and(|m| m.allow_clamp);
    if !allow_clamp {
        return Ok(());
    }
    // Pull the tracee-side sockaddr metadata from ctx.arguments
    // (populated in the NetListen branch of the build-context block).
    let sockaddr_ptr = ctx
        .arguments
        .get("bind_sockaddr_ptr")
        .and_then(serde_json::Value::as_u64);
    let addrlen = ctx
        .arguments
        .get("bind_addrlen")
        .and_then(serde_json::Value::as_u64)
        .map(|v| v as u32);
    let (Some(sockaddr_ptr), Some(addrlen)) = (sockaddr_ptr, addrlen) else {
        // Missing metadata is a programming error — the supervisor
        // populated `listener_policy_match` for this call so it must
        // have been a real bind. Fail closed.
        return Err(crate::error::Error::InterceptionError(
            "PR 5 Phase D: bind_sockaddr_ptr / bind_addrlen missing on NetListen ctx \
             with allow_clamp=true — refusing to allow wildcard bind without clamp"
                .into(),
        ));
    };
    // Determine which family to write back. We chose the family by
    // looking at the original address shape — v4 binds need a
    // sockaddr_in (16 bytes), v6 binds need sockaddr_in6 (28 bytes).
    let family = match parsed {
        std::net::IpAddr::V4(_) => crate::platform::linux::clamp::ClampFamily::V4,
        std::net::IpAddr::V6(_) => crate::platform::linux::clamp::ClampFamily::V6,
    };
    // ptrace::write targets the ptrace-stopped thread — that's the
    // tid we received the syscall event on, not the process leader.
    let stopped = nix::unistd::Pid::from_raw(stopped_tid as i32);
    crate::platform::linux::clamp::clamp_sockaddr_to_loopback(
        stopped,
        sockaddr_ptr,
        addrlen,
        family,
        port,
    )?;
    tracing::info!(
        event = "listener_clamp_applied",
        pid = event_pid,
        tid = stopped_tid,
        original_address = %address,
        original_port = port,
        rewritten_address = match family {
            crate::platform::linux::clamp::ClampFamily::V4 => "127.0.0.1",
            crate::platform::linux::clamp::ClampFamily::V6 => "::1",
        },
        clamp_desc = %ctx
            .listener_policy_match
            .as_ref()
            .map(|m| m.desc.as_str())
            .unwrap_or(""),
        "PR 5 Phase D: rewrote wildcard bind to loopback per local_listener_policy",
    );
    Ok(())
}

/// PR 5 Phase C: look up `(address, port)` against the session
/// profile's `local_listener_policy` and return a structured match
/// for the proxy to consume via `ToolCallContext.listener_policy_match`.
///
/// Returns `None` when no entry matches (treated as "undeclared" by
/// the egress filter, which queues wildcard binds). Returns `Some`
/// with the matching entry's `allow_clamp` + `desc` when a `(port,
/// family)` entry exists. Port `0` in the policy matches any port;
/// otherwise port equality is required.
fn match_listener_policy(
    policy: &[crate::profiles::LocalListenerEntry],
    address: &str,
    port: u16,
) -> Option<grith_proxy::types::ListenerPolicyMatch> {
    if policy.is_empty() {
        return None;
    }
    let family = listener_family_for_address(address)?;
    let entry = policy.iter().find(|e| {
        // Exact port equality. `port = 0` in a policy entry matches only
        // binds that pass literal port 0 (kernel-assigned ephemeral), as the
        // entry template documents — it is NOT an any-port wildcard. The old
        // `e.port == 0 ||` clause made the shipped codex entry (described as
        // "kernel-assigned localhost port") silently clamp arbitrary
        // fixed-port binds (10051, 11326, …) to loopback.
        let port_ok = e.port == port;
        let family_ok = matches!(
            (e.family, family),
            (crate::profiles::ListenerFamily::Any, _)
                | (
                    crate::profiles::ListenerFamily::V4,
                    ListenerAddressFamily::V4
                )
                | (
                    crate::profiles::ListenerFamily::V6,
                    ListenerAddressFamily::V6
                )
        );
        port_ok && family_ok
    })?;
    Some(grith_proxy::types::ListenerPolicyMatch {
        allow_clamp: entry.allow_clamp,
        desc: entry.desc.clone(),
    })
}

/// Internal helper for `match_listener_policy`: classify the bind
/// address by family. Unix-domain / unrecognised addresses return
/// `None` (no policy match makes sense for them).
#[derive(Debug, Clone, Copy)]
enum ListenerAddressFamily {
    V4,
    V6,
}

fn listener_family_for_address(address: &str) -> Option<ListenerAddressFamily> {
    // Localhost is loopback-only, no wildcard semantics — but for
    // family-matching purposes treat it as V4 (the kernel resolves
    // localhost to 127.0.0.1 by default; v6 hosts can use ::1
    // explicitly).
    if address.eq_ignore_ascii_case("localhost") {
        return Some(ListenerAddressFamily::V4);
    }
    match address.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(_) => Some(ListenerAddressFamily::V4),
        std::net::IpAddr::V6(_) => Some(ListenerAddressFamily::V6),
    }
}

fn is_local_listen_address(address: &str) -> bool {
    // Unix domain sockets (prefixed with "unix:" by read_sockaddr).
    if let Some(unix_path) = address.strip_prefix("unix:") {
        return !is_sensitive_unix_socket(unix_path);
    }
    if address.starts_with('/') || address.is_empty() {
        return true;
    }
    if address.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    false
}

/// Whether an authority-delegating ProcessSpawn of `command` should be
/// escalated (used at the two pre-proxy short-circuit gates, where
/// `ctx.spawn_provenance` is not yet available). Caller has already confirmed
/// `spawn_enforcement_enabled`.
///
/// Cheap-first: the raw-basename match needs no filesystem I/O. Only when the
/// raw name is not delegating do we canonicalise argv[0] (catches `run0` and
/// symlink-copies) and — only if the canonical size collides with a pinned
/// delegating binary — hash it (catches byte-copies/hardlinks). Canonicalise
/// failure / an unresolved relative argv[0] falls back to the raw result (same
/// resolution limitation as PR 4's `compute_spawn_provenance`).
fn spawn_delegation_would_enforce(
    loop_ctx: &SupervisorLoopContext<'_>,
    command: &str,
    args: &[String],
) -> bool {
    let permit = &loop_ctx.permit_authority_delegating;
    let pins = &loop_ctx.authority_delegating_pins;
    // (1) raw basename — no I/O. A name match short-circuits before the hash
    // fallback is consulted, so the empty set is verdict-identical here.
    if authority_delegation::is_authority_delegating_binary(command) {
        return authority_delegation::spawn_should_escalate_full(
            command,
            args,
            None,
            None,
            permit,
            authority_delegation::empty_pinned_hashes(),
        );
    }
    // (2) canonical basename — one path resolution, catches run0/symlink-copy.
    let Ok(canonical) = std::fs::canonicalize(command) else {
        return false;
    };
    let canonical_str = canonical.to_string_lossy();
    if authority_delegation::is_authority_delegating_binary(&canonical_str) {
        return authority_delegation::spawn_should_escalate_full(
            command,
            args,
            Some(&canonical_str),
            None,
            permit,
            authority_delegation::empty_pinned_hashes(),
        );
    }
    // (3) byte-copy — size prefilter, then hash only on a size collision.
    if pins.is_empty() {
        return false; // enforcement was off at session start: no pin to match
    }
    let Ok(meta) = std::fs::metadata(&canonical) else {
        return false;
    };
    if !pins.sizes().contains(&meta.len()) {
        return false;
    }
    let Ok(sha) = crate::provenance::sha256_file(&canonical) else {
        return false;
    };
    // Size collision: only now is the pinned hash set worth building.
    authority_delegation::spawn_should_escalate_full(
        command,
        args,
        Some(&canonical_str),
        Some(&sha),
        permit,
        pins.hashes(),
    )
}

/// Session-allowlist key recording that the operator explicitly approved this
/// EXACT authority-delegating call (command + args) this session. Namespaced so
/// it never collides with a normal `exec:`/`net:` allowlist entry and is checked
/// only by the delegation-enforcement path. Keyed on the full call identity (the
/// same `Display` the prompt and deny/approve-replay use), so `flatpak run foo`
/// never covers `flatpak run bar`.
fn delegating_approval_key(call_type: &grith_proxy::types::ToolCallType) -> String {
    // Family identity first: for the curated argv shapes in `spawn_families`
    // (docker compose exec/logs/up/…), the key drops the volatile parts of
    // the argv — the payload of an in-container exec, `--tail=N` — so one
    // approval covers the family for the session instead of re-prompting on
    // every one-character variant. Everything the curation does not
    // recognise keeps today's exact-argv key. All three users of this key
    // (the two consult gates and the record site) call this same function on
    // the same call type, so record and lookup can never disagree about
    // which identity an approval carries.
    if let grith_proxy::types::ToolCallType::ProcessSpawn { command, args } = call_type {
        if let Some(family) = spawn_families::spawn_family(command, args) {
            return format!("delegating-approved:family:{}", family.key);
        }
    }
    format!("delegating-approved:{call_type}")
}

/// returns the address (without port) so that approving one connection to a
/// host implicitly allows subsequent connections to the same host on any port.
/// The `ssh-egress:` session-allowlist key for a NetConnect: `ssh-egress:<addr>:<port>`.
///
/// Deliberately **port-scoped**, unlike the portless `net:<address>` grant. The
/// containment exception this key unlocks must be as narrow as the operator's
/// actual decision: approving `ssh` to `host:22` must not also let a
/// *contaminated* session reach `host:8080`. (The general `net:` connect grant
/// stays portless and host-level, as designed — this narrower key only gates
/// the containment-survival path.)
fn ssh_egress_key(address: &str, port: u16) -> String {
    format!("ssh-egress:{address}:{port}")
}

/// `true` iff `call_type` is a NetConnect whose exact destination+port carries an
/// operator-minted `ssh-egress:` session grant.
///
/// That namespace is written ONLY by an operator approving a trusted-`ssh`
/// connect at a prompt — [`SupervisorProfile::build_session_allowlist`] seeds
/// `net:` / `listen:` / `exec:` / `dns:` / `projdir:` / `ro:` / `rw:` but never
/// `ssh-egress:` — so its presence is proof of an explicit per-destination human
/// decision. It lets an approved ssh destination survive the sticky
/// session-containment flag WITHOUT re-opening the short-circuit for
/// profile-declared routine destinations (which was the point of PR 4 Phase H).
fn netconnect_operator_ssh_egress_grant(
    call_type: &grith_proxy::types::ToolCallType,
    session_allowed: &Arc<Mutex<HashSet<String>>>,
) -> bool {
    use grith_proxy::types::ToolCallType;
    let ToolCallType::NetConnect { address, port } = call_type else {
        return false;
    };
    let key = ssh_egress_key(address, *port);
    session_allowed.lock().is_ok_and(|s| s.contains(&key))
}

fn session_allowlist_key(call_type: &grith_proxy::types::ToolCallType) -> Option<String> {
    use grith_proxy::types::ToolCallType;
    match call_type {
        ToolCallType::FileRead { path }
        | ToolCallType::FileWrite { path, .. }
        | ToolCallType::FileAppend { path }
        | ToolCallType::FileDelete { path }
        | ToolCallType::DirList { path }
        | ToolCallType::FileChmod { path, .. }
        | ToolCallType::DirCreate { path } => Some(path.clone()),
        ToolCallType::FileRename { old_path, .. } => Some(old_path.clone()),
        // work/83 F5: link creation had NO key at all, so a hardlink could
        // never be covered by project trust even inside the launch cwd —
        // every rustc incremental hardlink was proxy-scored (511 queued
        // FileLink calls in one morning, 73% of them random compiler hashes
        // that happened to contain "auth"/"secret"). Keyed on `link_path`,
        // the name being created, because that is the path a directory-scoped
        // grant is about.
        //
        // The target is NOT ignored. `is_session_allowlist_match` refuses the
        // grant unless the TARGET is independently write-trusted by the same
        // allowlist and neither end is a credential store, so
        // `ln -s ~/.ssh/id_rsa ./benign` and
        // `ln -s ./mine ~/.ssh/authorized_keys` both still reach the proxy —
        // where `ToolCallContext::paths()` scores both ends (go-live B2/B3).
        ToolCallType::FileLink { link_path, .. } => Some(link_path.clone()),
        ToolCallType::OwnershipChange { target, .. }
        | ToolCallType::FilesystemMutation { target, .. } => Some(target.clone()),
        ToolCallType::NetConnect { address, .. } => Some(format!("net:{address}")),
        // Listens get their own namespace, keyed by (address, port). The old
        // shared `net:{address}` key dropped the port — an operator pressing
        // [l] on a fixed-port listener prompt persisted `net:0.0.0.0`, a
        // permanent all-ports wildcard-listener grant that additionally
        // auto-allowed CONNECTS to the same address string. `listen:` entries
        // never cross-match `net:` ones and vice versa.
        ToolCallType::NetListen { address, port } => Some(format!("listen:{address}:{port}")),
        ToolCallType::ProcessSpawn { command, .. } => Some(format!("exec:{command}")),
        ToolCallType::DnsQuery { domain, .. } => Some(format!("dns:{domain}")),
        // Cross-process operations get an exact, per-target session key so an
        // operator approval sticks for the rest of the session instead of
        // re-prompting on every identical syscall. The key is bound to the
        // target's start time, NOT just its pid: Linux recycles pids, and a
        // bare-pid grant would silently transfer to whatever same-uid
        // process later lands on that number — re-opening the exact
        // scope-0 `process_vm_readv` memory-theft path this coverage exists
        // to gate. Start time (procfs stat field 22, monotonic in boot
        // ticks) changes on every fork, so a recycled pid gets a different
        // key and must be re-approved. Unreadable identity (target already
        // gone) → `None` → no grant, always re-prompt (fail safe).
        //
        // Residual: a pid could still be recycled in the microseconds the
        // caller is frozen between this read and the kernel executing the
        // syscall, but that requires a grant to already exist for the exact
        // prior tenant and collapses the window from session-long to a
        // syscall stop — the same class of accepted pre-check TOCTOU as the
        // failed-exec/failed-connect suppressions.
        ToolCallType::CrossProcessAccess { op, target_pid } => process_start_time(*target_pid)
            .map(|start| format!("process:{op}:{target_pid}:{start}")),
        // Namespace grants key on (syscall, flag word); flags are not a
        // reusable handle the way a pid is, so no identity binding is needed.
        ToolCallType::NamespaceOp { syscall, flags } => {
            Some(format!("namespace:{syscall}:{flags:#x}"))
        }
        _ => None,
    }
}

/// A process's start time from `/proc/<pid>/stat` field 22 (monotonic boot
/// ticks), used to bind a cross-process session grant to a specific process
/// so a recycled pid does not inherit it. `None` when the process is gone or
/// the field is unparseable.
///
/// The `comm` field (field 2) is parenthesised and may itself contain spaces
/// and parentheses, so everything up to and including the LAST `)` is
/// skipped; after it, `state` is field 3 and `starttime` is field 22 — the
/// 20th whitespace token (index 19).
fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Record a reputation observation from the event handler context.
/// Record a reputation observation, extracting process/destination context
/// from the ToolCallContext arguments JSON (populated by supervisor_event_arguments).
fn record_reputation_observation(
    loop_ctx: &SupervisorLoopContext<'_>,
    session: &SupervisorSession,
    call_type: &ToolCallType,
    outcome: grith_proxy::reputation::ReputationOutcome,
) {
    record_reputation_observation_with_ctx(loop_ctx, session, call_type, outcome, None);
}

fn implicit_deny_weight(config: &grith_proxy::reputation::ReputationConfig) -> f64 {
    (config.deny_weight / 3.0).max(1.0)
}

fn manual_deny_weight(config: &grith_proxy::reputation::ReputationConfig) -> f64 {
    config.deny_weight.max(1.0)
}

fn terminate_deny_weight(config: &grith_proxy::reputation::ReputationConfig) -> f64 {
    manual_deny_weight(config) + (manual_deny_weight(config) - implicit_deny_weight(config))
}

fn record_reputation_observation_with_ctx(
    loop_ctx: &SupervisorLoopContext<'_>,
    session: &SupervisorSession,
    call_type: &ToolCallType,
    outcome: grith_proxy::reputation::ReputationOutcome,
    ctx_args: Option<&serde_json::Value>,
) {
    if !loop_ctx.reputation_config.enabled {
        return;
    }

    let profile = session_scope_name(session);
    let action = grith_proxy::reputation::action_name(call_type);

    // Extract process name and destination from context arguments.
    let process = ctx_args
        .and_then(|a| a.get("process"))
        .and_then(|v| v.as_str())
        .filter(|c| !c.is_empty() && !c.starts_with("fork-from-"))
        .unwrap_or("*");

    let destination = ctx_args
        .and_then(|a| a.get("process_args"))
        .and_then(|v| v.as_array())
        .and_then(|args| {
            args.iter()
                .filter_map(|a| a.as_str())
                .find(|a| !a.starts_with('-') && (a.contains('@') || a.contains('.')))
        })
        .unwrap_or("*");

    // Extract the path/address from the call type.
    let path = match call_type {
        ToolCallType::FileRead { path }
        | ToolCallType::FileWrite { path, .. }
        | ToolCallType::FileAppend { path }
        | ToolCallType::FileDelete { path }
        | ToolCallType::FileChmod { path, .. }
        | ToolCallType::DirList { path }
        | ToolCallType::DirCreate { path } => path.as_str(),
        ToolCallType::FileRename { old_path, .. } => old_path.as_str(),
        ToolCallType::OwnershipChange { target, .. }
        | ToolCallType::FilesystemMutation { target, .. } => target.as_str(),
        ToolCallType::ProcessSpawn { command, .. } => command.as_str(),
        ToolCallType::NetConnect { address, .. } | ToolCallType::NetListen { address, .. } => {
            address.as_str()
        }
        ToolCallType::DnsQuery { domain, .. } => domain.as_str(),
        _ => return,
    };

    let keys =
        grith_proxy::reputation::build_reputation_keys(profile, action, process, destination, path);

    if let (Some(url), Some(token)) = (&loop_ctx.daemon_proxy_url, &loop_ctx.daemon_proxy_token) {
        let outcome_str = match &outcome {
            grith_proxy::reputation::ReputationOutcome::Approved(weight) => {
                format!("approved:{weight}")
            }
            grith_proxy::reputation::ReputationOutcome::Denied(weight) => {
                format!("denied:{weight}")
            }
        };
        let token = token
            .lock()
            .ok()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        tokio::spawn({
            let url = url.clone();
            async move {
                if let Err(e) = remote_observe_reputation(&url, &token, &keys, &outcome_str).await {
                    tracing::warn!(error = %e, "failed to record reputation observation via daemon");
                }
            }
        });
        return;
    }

    if let Ok(mut table) = loop_ctx.reputation_table.lock() {
        table.observe(&keys, outcome, &loop_ctx.reputation_config);
    }
}

async fn remote_observe_reputation(
    base_url: &str,
    token: &str,
    keys: &[(u8, String)],
    outcome: &str,
) -> std::result::Result<(), String> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base_url}/api/reputation/observe"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "keys": keys,
            "outcome": outcome,
        }))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("daemon returned {status}: {body}"));
    }

    Ok(())
}

fn readonly_allowlist_entry(path: &str) -> Option<String> {
    canonicalize_allowlist_entry("ro:", path)
}

/// Canonicalize a path and prefix it with a namespace for allowlist matching.
fn canonicalize_allowlist_entry(namespace: &str, path: &str) -> Option<String> {
    std::fs::canonicalize(path)
        .ok()
        .and_then(|p| p.to_str().map(|s| format!("{namespace}{s}")))
}

fn approved_session_allowlist_entry(
    call_type: &grith_proxy::types::ToolCallType,
) -> Option<String> {
    match call_type {
        ToolCallType::FileRead { path } => canonicalize_allowlist_entry("ro:", path),
        ToolCallType::FileWrite { path, .. }
        | ToolCallType::FileAppend { path }
        | ToolCallType::FileDelete { path }
        | ToolCallType::FileChmod { path, .. }
        | ToolCallType::DirCreate { path } => canonicalize_allowlist_entry("rw:", path),
        ToolCallType::FileRename { old_path, .. } => canonicalize_allowlist_entry("rw:", old_path),
        ToolCallType::OwnershipChange { target, .. }
        | ToolCallType::FilesystemMutation { target, .. } => {
            canonicalize_allowlist_entry("rw:", target)
        }
        // work/83 F5 gave `FileLink` a session-allowlist KEY, which is a
        // lookup path, not a grant. An approved link deliberately stores
        // nothing (this arm keeps the pre-F5 behaviour explicit rather than
        // inheriting the fallthrough below):
        //
        //  - the key is a bare, un-namespaced path, so storing it would
        //    register a PREFIX granting every operation under the link path,
        //    and `approved_session_allowlist_entries` would persist it as a
        //    learned rule that outlives the session;
        //  - a grant on the link path alone says nothing about the target,
        //    and the target is the end that carries the authority — approving
        //    `ln x /proj/a` must not silently authorise
        //    `ln ~/.ssh/id_rsa /proj/a` later.
        //
        // A durable grant would have to be bound to BOTH ends; until it is,
        // repeated links are covered by project trust (F5) or re-reviewed.
        ToolCallType::FileLink { .. } => None,
        _ => session_allowlist_key(call_type),
    }
}

/// The session-allowlist entries to store for an approved call.
///
/// Wraps [`approved_session_allowlist_entry`], expanding a `net:` key that
/// carries an ambiguous DNS attribution array (`net:["a.example","b.example"]`)
/// into one `net:<candidate>` entry per hostname. Storing the array string
/// verbatim would be a dead grant: `is_session_allowlist_match` checks each
/// candidate of an incoming key against `net:` entries via domain matching,
/// which the literal array text can never satisfy, so every retry would
/// re-prompt. The operator saw the full candidate list in the prompt, so
/// granting each name is exactly the approval they gave.
fn approved_session_allowlist_entries(call_type: &grith_proxy::types::ToolCallType) -> Vec<String> {
    let Some(key) = approved_session_allowlist_entry(call_type) else {
        return Vec::new();
    };
    if let Some(domain) = key.strip_prefix("net:") {
        if let Some(candidates) = parse_dns_candidate_array(domain) {
            return candidates
                .into_iter()
                .map(|candidate| format!("net:{candidate}"))
                .collect();
        }
    }
    vec![key]
}

/// If `call_type` is a top-level `/tmp/<name>` create/write (DirCreate or
/// FileWrite/FileAppend/FileRename-target with a single path component
/// under `/tmp/`), return the bare-path prefix to register in
/// `session_allowed` so the *subtree* auto-allows on subsequent access.
///
/// Scope:
/// - Only TOP-LEVEL `/tmp/X` (no subdirectories). Per-user choice:
///   we don't claim authority over `/tmp/a/b/c` just because the
///   session happened to create something at `b/c` — only direct
///   children of `/tmp/`.
/// - Dirs registered with trailing `/` so prefix-matching naturally
///   requires a `/` boundary — `/tmp/foo/` matches `/tmp/foo/bar`
///   but NOT `/tmp/foobar`.
/// - Files registered without trailing slash (exact-only, no prefix).
///   The existing `rw:` exact-match already handles re-writes of the
///   same file; this entry is informational for future widening.
/// - Carveout for shared-mount sockets (`/tmp/.X11-unix` etc.): never
///   register, even if the session creates a name like that.
///
/// Returns `None` for paths outside `/tmp/`, sub-paths, or carveouts.
fn tmp_self_created_prefix(call_type: &grith_proxy::types::ToolCallType) -> Option<String> {
    let (path, is_dir_create) = match call_type {
        ToolCallType::DirCreate { path } => (path.as_str(), true),
        ToolCallType::FileWrite { path, .. } | ToolCallType::FileAppend { path } => {
            (path.as_str(), false)
        }
        ToolCallType::FileRename { new_path, .. } => (new_path.as_str(), false),
        _ => return None,
    };

    let suffix = path.strip_prefix("/tmp/")?;
    if suffix.is_empty() || suffix.contains('/') {
        // Either /tmp itself, or a sub-path (e.g. /tmp/foo/bar). We
        // only register top-level entries — subtrees inherit via prefix
        // matching from the eventual top-level create.
        return None;
    }
    if matches!(
        suffix,
        ".X11-unix" | ".ICE-unix" | ".font-unix" | ".Test-unix" | ".XIM-unix"
    ) {
        return None;
    }
    // Dir → trailing-slash prefix so subtree access matches.
    // File → exact-only (the existing rw: entry already covers this).
    if is_dir_create {
        Some(format!("/tmp/{suffix}/"))
    } else {
        Some(format!("/tmp/{suffix}"))
    }
}

/// Every path a call touches that a project-derived (`projdir:`-marked)
/// grant must not cover if it is a credential store or an in-project
/// high-value secret.
///
/// This is the lookup key, plus the OTHER end of every two-ended call. For a
/// rename the key is the source `old_path`, so a rename of a benign project
/// file into `~/.ssh/authorized_keys` would otherwise slip the guard (work/80
/// review defect 1); for a link (work/83 F5) the key is the `link_path`, so
/// the exposed `target` is the end that would otherwise slip it.
fn projdir_guarded_paths<'a>(
    key: &'a str,
    call_type: &'a grith_proxy::types::ToolCallType,
) -> impl Iterator<Item = &'a str> {
    use grith_proxy::types::ToolCallType;
    let other_end = match call_type {
        ToolCallType::FileRename { new_path, .. } => Some(new_path.as_str()),
        ToolCallType::FileLink { target, .. } => Some(target.as_str()),
        _ => None,
    };
    std::iter::once(key).chain(other_end)
}

/// True if a project-derived grant must be denied for this call because one
/// of the paths it touches is a credential store or an in-project high-value
/// secret.
///
/// The guarded set is [`crate::syscall_map::is_project_trust_guarded_path`],
/// not the full `is_sensitive_path`: work/80 narrowed it to credential stores
/// to keep `.pem`/`.key`/keyword-named files inside genuine project trees out
/// of the prompt flood, and that reasoning still holds — measured, every
/// `*.pem`/`*.key` in this workspace is a false positive and `config/
/// secrets.toml` scores 5.80 on the keyword rule alone. What the narrowing
/// went too far on is the handful of files whose CONTENT is the secret and
/// which live in a project tree by design (`.env`, Rails `master.key`,
/// terraform state, `.p12`/`.pfx`); `.env` in particular is the taint
/// filter's first sensitive source, so short-circuiting its read means no
/// taint is registered and a later exfiltration cannot be scored.
fn projdir_grant_blocked(key: &str, call_type: &grith_proxy::types::ToolCallType) -> bool {
    projdir_guarded_paths(key, call_type).any(crate::syscall_map::is_project_trust_guarded_path)
}

/// Return whether a session allowlist entry matches a syscall key.
///
/// Matching rules:
/// - `net:` / `dns:` keys use DNS suffix matching with label boundaries only
/// - `exec:` keys check exact match first, then `exec-prefix:` entries with
///   provenance verification (canonical path + ownership/permission checks)
/// - filesystem paths use exact or prefix matching
/// - `exec-prefix:` entries ONLY match `exec:` keys (namespace isolation)
/// - `ro:` entries use exact match only and only match `FileRead` operations
/// - scoped prefix entries use boundary-safe, operation-specific matching
fn is_session_allowlist_match(
    key: &str,
    allowed: &HashSet<String>,
    call_type: &grith_proxy::types::ToolCallType,
) -> bool {
    // work/83 F5: link creation is the one filesystem op whose authority
    // spans two trees — it publishes `target` under a second name. Giving it
    // a session key (so in-project build hardlinks stop being individually
    // scored) must not turn a link into the cheap way to move authority
    // ACROSS the trust boundary, which is exactly the `ln -s ./mine
    // ~/.ssh/authorized_keys` hole go-live review B2/B3 closed at the proxy.
    // The short-circuit skips the proxy entirely, so both conditions are
    // re-checked here:
    //
    //  1. Neither end may be a credential store or an in-project high-value
    //     secret — unconditionally, not only under a `projdir:` marker. An
    //     explicit literal profile entry gets to override `is_sensitive_path`
    //     (documented semantics) but must not get to hardlink
    //     `~/.aws/credentials` into the trusted tree. Zero FP cost: nothing
    //     links a credential store during a build. The set is the same one
    //     `projdir_grant_blocked` uses, and it has to be: the invariant below
    //     ("a link is strictly weaker than the copy trust already allows")
    //     only holds while `FileRead <target>` short-circuits too, so any
    //     path whose READ now reaches the proxy must take its link with it.
    //  2. The TARGET must be independently write-trusted by this same
    //     allowlist. Write-shaped, not read-shaped, because a hard link
    //     confers the underlying inode's write access under the new name —
    //     a `ro:` (read-only) grant must not become write-through.
    //
    // Everything else about the link is then decided by matching `link_path`
    // (the key) with the ordinary path rules below. An unresolved-or-outside
    // target simply fails the check and reaches the proxy — fail-safe.
    //
    // The invariant that makes this a safe narrowing: with both ends inside
    // the same trusted tree, a link is strictly weaker than the copy that
    // trust ALREADY allows unprompted — `FileRead <target>` plus
    // `FileWrite <link_path>` both short-circuit here today, so `cp` publishes
    // the same bytes under the same new name with no proxy evaluation. Paths
    // that are credential-shaped but not credential STORES (a `.pem` in the
    // repo, `/proj/.env`) are therefore no less covered after F5 than before
    // it. What must not change is the boundary itself, which is what the two
    // conditions above pin.
    if let grith_proxy::types::ToolCallType::FileLink { target, .. } = call_type {
        if crate::syscall_map::is_project_trust_guarded_path(target)
            || crate::syscall_map::is_project_trust_guarded_path(key)
        {
            return false;
        }
        let target_probe = grith_proxy::types::ToolCallType::FileWrite {
            path: target.clone(),
            content_hash: String::new(),
        };
        if !is_session_allowlist_match(target, allowed, &target_probe) {
            return false;
        }
    }

    // Listener grants: exact `(address, port)` match, plus profile-seeded
    // portless `listen:<addr>` entries (from `routine_listen_addresses`)
    // covering every port on that address. Deliberately isolated from `net:`
    // — approving a listener must not auto-allow connects to the same
    // address string, and subdomain matching makes no sense for a bind.
    if key.starts_with("listen:") {
        if allowed.contains(key) {
            return true;
        }
        // `rsplit_once` splits on the LAST colon, so IPv6 addresses
        // (`listen::::0` for `[::]:0`) resolve their port correctly.
        return key
            .strip_prefix("listen:")
            .and_then(|rest| rest.rsplit_once(':'))
            .is_some_and(|(addr, _port)| allowed.contains(&format!("listen:{addr}")));
    }

    // Subdomain matching for network destinations: both `net:` and `dns:`
    // keys match against `net:` allowlist entries, so `dns:api.anthropic.com`
    // matches `net:anthropic.com`.
    let net_domain = key
        .strip_prefix("net:")
        .or_else(|| key.strip_prefix("dns:"));
    if let Some(domain) = net_domain {
        // Ambiguous DNS attribution is rendered as a JSON hostname array
        // (for example `["ab.chatgpt.com","chatgpt.com"]`). Check every
        // candidate independently against the network allowlist. Requiring
        // all candidates to match preserves the shared-IP safety boundary:
        // one trusted name must not grant trust to an untrusted name that
        // currently resolves to the same address.
        if let Some(candidates) = parse_dns_candidate_array(domain) {
            return !candidates.is_empty()
                && candidates.iter().all(|candidate| {
                    allowed.iter().any(|entry| {
                        entry
                            .strip_prefix("net:")
                            .is_some_and(|suffix| domain_matches(candidate, suffix))
                    })
                });
        }

        return allowed.iter().any(|entry| {
            if let Some(suffix) = entry.strip_prefix("net:") {
                domain_matches(domain, suffix)
            } else {
                false
            }
        });
    }

    if let Some(exec_path) = key.strip_prefix("exec:") {
        let trusted_execs: Vec<String> = allowed
            .iter()
            .filter_map(|entry| entry.strip_prefix("exec:").map(String::from))
            .collect();
        let trusted_roots: Vec<String> = allowed
            .iter()
            .filter_map(|entry| entry.strip_prefix("exec-prefix:").map(String::from))
            .collect();

        let exact_decision = if trusted_execs.is_empty() {
            None
        } else {
            Some(crate::provenance::verify_exact_exec_provenance(
                exec_path,
                &trusted_execs,
            ))
        };

        if let Some(decision) = &exact_decision {
            if decision.trusted {
                tracing::debug!(
                    path = exec_path,
                    canonical = ?decision.canonical_path,
                    reason = %decision.reason,
                    "exec provenance: trusted exact executable"
                );
                return true;
            }
        }

        if trusted_roots.is_empty() {
            return false;
        }

        let decision = crate::provenance::verify_exec_provenance(exec_path, &trusted_roots);

        if decision.trusted {
            tracing::debug!(
                path = exec_path,
                canonical = ?decision.canonical_path,
                reason = %decision.reason,
                "exec provenance: trusted"
            );
        } else {
            tracing::trace!(
                path = exec_path,
                canonical = ?decision.canonical_path,
                reason = %decision.reason,
                "exec provenance: not trusted"
            );
        }

        return decision.trusted;
    }

    // Operation-specific directory scopes. Resolve the target through the
    // same existing-ancestor strategy used when the rule is created so
    // canonical stored directories also match not-yet-created child paths.
    if let Some(target) = crate::scoped_permissions::scoped_call_target(call_type) {
        let resolved = crate::scoped_permissions::resolve_target(target)
            .unwrap_or_else(|_| std::path::PathBuf::from(&target));
        let resolved = resolved.to_string_lossy().replace('\\', "/");
        if let Some(namespace) = scoped_prefix_namespace(call_type) {
            if allowed.iter().any(|entry| {
                entry
                    .strip_prefix(namespace)
                    .is_some_and(|directory| directory_scope_matches(directory, &resolved))
            }) {
                return true;
            }
        }
    }

    // Read-only path matching: `ro:` entries use exact match only and are
    // scoped to FileRead operations. They do not match writes, appends,
    // deletes, renames, chmod, ownership changes, filesystem
    // mutations, or directory creates.
    if matches!(call_type, grith_proxy::types::ToolCallType::FileRead { .. }) {
        if let Some(ro_entry) = readonly_allowlist_entry(key) {
            if allowed.contains(&ro_entry) {
                return true;
            }
        }
    }

    // Read-only glob pattern matching: `ro-glob:` entries use simple glob matching
    // (single `*` wildcard for one path segment) and are scoped to FileRead only.
    if matches!(call_type, grith_proxy::types::ToolCallType::FileRead { .. }) {
        for entry in allowed.iter() {
            if let Some(pattern) = entry.strip_prefix("ro-glob:") {
                if glob_match(key, pattern) {
                    return true;
                }
            }
        }
    }

    // Read-write path matching: `rw:` entries use exact match only and are
    // scoped to write-like filesystem operations (FileWrite, FileAppend,
    // FileDelete, FileRename, FileChmod, DirCreate, OwnershipChange,
    // FilesystemMutation). They do NOT match reads (reads should use
    // `ro:` instead) or non-filesystem operations.
    {
        use grith_proxy::types::ToolCallType;
        let is_write_op = matches!(
            call_type,
            ToolCallType::FileWrite { .. }
                | ToolCallType::FileAppend { .. }
                | ToolCallType::FileDelete { .. }
                | ToolCallType::FileRename { .. }
                | ToolCallType::FileChmod { .. }
                | ToolCallType::DirCreate { .. }
                | ToolCallType::OwnershipChange { .. }
                | ToolCallType::FilesystemMutation { .. }
        );
        if is_write_op {
            if let Some(rw_entry) = canonicalize_allowlist_entry("rw:", key) {
                if allowed.contains(&rw_entry) {
                    return true;
                }
            }
        }
    }

    // Cross-process / namespace grants: exact-match only, and gated on the
    // matching call type so a filesystem path that happens to spell a
    // `process:`/`namespace:` key can never borrow the grant (relative
    // paths from tracee registers are attacker-controlled strings).
    if key.starts_with("process:") {
        return matches!(call_type, ToolCallType::CrossProcessAccess { .. })
            && allowed.contains(key);
    }
    if key.starts_with("namespace:") {
        return matches!(call_type, ToolCallType::NamespaceOp { .. }) && allowed.contains(key);
    }

    let key_is_pathish = !key.starts_with("ro-prefix:")
        && !key.starts_with("write-prefix:")
        && !key.starts_with("delete-prefix:");
    if key_is_pathish && allowed.contains(key) {
        // work/80: an exact key that is itself a launch-derived prefix
        // (`cd ~/proj/.aws && grith exec` → key == projdir entry) must not
        // exact-match into trust when it (or a rename destination) is a
        // credential store.
        let launch_derived_store =
            allowed.contains(&format!("projdir:{key}")) && projdir_grant_blocked(key, call_type);
        if !launch_derived_store {
            return true;
        }
    }

    // Prefix matching for bare-path entries. Exclude namespaced entries
    // to prevent namespace leakage — `process:ptrace:1` must never serve
    // as a string prefix for `process:ptrace:123`.
    allowed.iter().any(|prefix| {
        !prefix.starts_with("exec-prefix:")
            && !prefix.starts_with("ro-prefix:")
            && !prefix.starts_with("write-prefix:")
            && !prefix.starts_with("delete-prefix:")
            && !prefix.starts_with("ro:")
            && !prefix.starts_with("ro-glob:")
            && !prefix.starts_with("rw:")
            && !prefix.starts_with("process:")
            && !prefix.starts_with("namespace:")
            && !prefix.starts_with("projdir:")
            && key.starts_with(prefix.as_str())
            // work/80: a prefix whose trust derives from the launch cwd
            // (marked by a `projdir:` twin) must not auto-allow operations
            // on credential stores — reads, writes, OR a rename whose
            // destination is a store. Explicit literal profile entries (no
            // twin) keep today's semantics.
            && !(allowed.contains(&format!("projdir:{prefix}"))
                && projdir_grant_blocked(key, call_type))
    })
}

/// work/85: deny a file operation refused by a subtractive control, with the
/// forensics stage, syscall log line, audit record and counter every other
/// pre-proxy deny writes.
///
/// One helper for both controls so a refusal is always visible in the same
/// four places. A silent EPERM is the failure mode that makes a supervised
/// tool look broken rather than restricted; the tag in the audit record is
/// what turns "npm failed" into "npm was blocked outside the workspace".
#[allow(clippy::too_many_arguments)]
async fn deny_subtractive_control(
    loop_ctx: &SupervisorLoopContext<'_>,
    session: &mut SupervisorSession,
    interceptor: &mut Box<dyn SyscallInterceptor>,
    trace_event_id: uuid::Uuid,
    event_pid: u32,
    tid: u32,
    call_type: &grith_proxy::types::ToolCallType,
    audit_event: &str,
    reason: &str,
) {
    write_forensics_stage(
        loop_ctx,
        trace_event_id,
        session,
        event_pid,
        Some(call_type),
        "denied",
        Some("auto-deny"),
        None,
        Some(reason),
    );
    write_syscall_log(loop_ctx, session.root_pid, call_type, 0.0, "deny", reason);
    tracing::info!(
        event = audit_event,
        pid = event_pid,
        tid,
        call = %call_type,
        reason,
        "denied before proxy evaluation by an operator-installed rule"
    );
    log_supervisor_audit_event(
        loop_ctx,
        session,
        event_pid,
        &call_type.to_string(),
        audit_event,
        grith_audit::types::ProxyActionSummary::Deny,
        serde_json::json!({
            "pid": event_pid,
            "tid": tid,
            "reason": reason,
        }),
        reason,
    )
    .await;
    session.stats.total_denied += 1;
    if let Err(e) = interceptor.deny(tid).await {
        tracing::warn!(error = %e, tid, "deny (subtractive control) failed");
    }
}

/// Session-rule namespace that governs `call_type`.
///
/// One map, two readers: the allow side (`ro-prefix:` …) and work/85's
/// refusal side, which is the same string behind
/// [`scoped_permissions::DENY_RULE_PREFIX`]. They must agree — a refusal that
/// classified a `FileAppend` differently from the grant would silently fail
/// to block the very call it was installed for.
fn scoped_prefix_namespace(call_type: &grith_proxy::types::ToolCallType) -> Option<&'static str> {
    use grith_proxy::types::ToolCallType;
    match call_type {
        ToolCallType::FileRead { .. } | ToolCallType::DirList { .. } => Some("ro-prefix:"),
        ToolCallType::FileWrite { .. }
        | ToolCallType::FileAppend { .. }
        | ToolCallType::DirCreate { .. } => Some("write-prefix:"),
        ToolCallType::FileDelete { .. } | ToolCallType::FileRename { .. } => Some("delete-prefix:"),
        _ => None,
    }
}

/// work/85: the operator-installed refusal that blocks this call, if any.
///
/// Mirrors the operation-specific directory matching in
/// `is_session_allowlist_match` — same namespaces, same existing-ancestor
/// target resolution, same `/`-boundary prefix test — so a reviewer who
/// blocks `/repo/build/` gets exactly the subtree they would have granted by
/// allowing it, and `/repo/build-secrets/` is not swept in by a string match.
fn session_deny_match(
    call_type: &grith_proxy::types::ToolCallType,
    denied: &HashSet<String>,
) -> Option<String> {
    if denied.is_empty() {
        return None;
    }
    let namespace = scoped_prefix_namespace(call_type)?;
    let namespace = format!("{}{namespace}", crate::scoped_permissions::DENY_RULE_PREFIX);
    // Every path the call touches is tested, not just the primary one: a
    // rename out of a blocked directory and a rename *into* one are both
    // things the operator asked to stop.
    let targets = crate::workspace_only::governed_paths(call_type)?;
    for target in targets {
        let resolved = crate::scoped_permissions::resolve_target(target)
            .unwrap_or_else(|_| std::path::PathBuf::from(target));
        let resolved = resolved.to_string_lossy().replace('\\', "/");
        if let Some(rule) = denied.iter().find(|entry| {
            entry
                .strip_prefix(namespace.as_str())
                .is_some_and(|directory| directory_scope_matches(directory, &resolved))
        }) {
            return Some(rule.clone());
        }
    }
    None
}

/// work/85: why the workspace-only boundary refuses this call, or `None` when
/// it does not govern it.
///
/// The exemptions are ordered cheapest-first, and every one of them means
/// "the boundary does not decide" — the call carries on into the normal
/// pipeline and can still be scored, queued or denied there.
fn workspace_only_block_reason(
    boundary: &crate::workspace_only::WorkspaceBoundary,
    call_type: &grith_proxy::types::ToolCallType,
    session_allowed: &Arc<Mutex<HashSet<String>>>,
) -> Option<String> {
    if boundary.is_empty() {
        return None;
    }
    let targets = crate::workspace_only::governed_paths(call_type)?;
    let read_like = crate::workspace_only::is_read_like(call_type);

    for target in targets {
        let resolved = crate::scoped_permissions::resolve_target(target)
            .unwrap_or_else(|_| std::path::PathBuf::from(target));
        let resolved = resolved.to_string_lossy().replace('\\', "/");

        // 1. Inside the workspace — the whole point of the mode.
        if boundary.contains(&resolved) {
            continue;
        }
        // 2. Noise: /proc, /sys, the tool's own PTY, CA certificates. These
        //    are never the user data the mode protects, and /dev/pts is the
        //    tool's own stdout — blocking it would wedge the session.
        if syscall_map::is_noise_path(&resolved) || syscall_map::is_noise_path(target) {
            continue;
        }
        // 3. Reads of runtime data. Without this the tool cannot load libc.
        if read_like && crate::workspace_only::is_system_read_root(&resolved) {
            continue;
        }
        // 4. Declared trust: the profile's routine paths (`~/.claude`,
        //    `~/.nvm/versions/**`, `/tmp/claude-*`, …) and anything approved
        //    earlier this session. The operator asked to supervise this tool,
        //    not to break it, and these are the paths its own profile says it
        //    needs. Checked last because it takes the lock.
        //
        //    Tested per path against a probe of the same operation class,
        //    NOT by asking the allowlist about the call as a whole:
        //    `session_allowlist_key` keys a rename on its SOURCE, so
        //    `mv ~/.claude/notes /home/dev/exfil/notes` would otherwise carry
        //    the source's declared trust to a destination the boundary exists
        //    to refuse.
        let probe = match scoped_prefix_namespace(call_type) {
            Some("ro-prefix:") => ToolCallType::FileRead {
                path: resolved.clone(),
            },
            Some("delete-prefix:") => ToolCallType::FileDelete {
                path: resolved.clone(),
            },
            _ => ToolCallType::FileWrite {
                path: resolved.clone(),
                content_hash: String::new(),
            },
        };
        let allowed_match = session_allowlist_key(&probe).is_some_and(|key| {
            session_allowed
                .lock()
                .is_ok_and(|allowed| is_session_allowlist_match(&key, &allowed, &probe))
        });
        if allowed_match {
            continue;
        }
        return Some(resolved);
    }
    None
}

/// Boundary-safe match for a normalized directory rule.
fn directory_scope_matches(directory: &str, target: &str) -> bool {
    let directory = directory.trim_end_matches('/');
    target == directory
        || target
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Match an explicit read scope for a sensitive path without using the normal
/// pre-proxy allowlist fast path.
fn is_sensitive_scoped_read_match(
    call_type: &grith_proxy::types::ToolCallType,
    allowed: &HashSet<String>,
) -> bool {
    use grith_proxy::types::ToolCallType;

    let path = match call_type {
        ToolCallType::FileRead { path } | ToolCallType::DirList { path } => path,
        _ => return false,
    };
    let directory_form = format!("{}/", path.trim_end_matches('/'));
    if !crate::syscall_map::is_sensitive_path(path)
        && !crate::syscall_map::is_sensitive_path(&directory_form)
    {
        return false;
    }

    let resolved = crate::scoped_permissions::resolve_target(path)
        .unwrap_or_else(|_| std::path::PathBuf::from(path));
    let resolved = resolved.to_string_lossy().replace('\\', "/");
    allowed.iter().any(|entry| {
        entry
            .strip_prefix("ro-prefix:")
            .is_some_and(|directory| directory_scope_matches(directory, &resolved))
    })
}

/// Simple glob matching: `*` matches any sequence of non-`/` characters.
/// Only supports `*` at the end of a filename segment (e.g., `dir/*.pub`).
fn glob_match(path: &str, pattern: &str) -> bool {
    if let Some(star_pos) = pattern.find('*') {
        let prefix = &pattern[..star_pos];
        let suffix = &pattern[star_pos + 1..];
        path.starts_with(prefix)
            && path.ends_with(suffix)
            && !path[prefix.len()..path.len() - suffix.len()].contains('/')
    } else {
        path == pattern
    }
}

fn domain_matches(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || (domain.len() > suffix.len()
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
}

fn supervisor_event_arguments(
    session: &SupervisorSession,
    event_pid: u32,
    call_type: &ToolCallType,
) -> serde_json::Value {
    let process_info = session.process_tree.get(event_pid);

    // Walk the ancestry chain to find the nearest parent with a real command
    // name (not a "fork-from-*" placeholder). This gives meaningful attribution
    // like "ssh → git" instead of "ssh → fork-from-12345".
    let (parent_pid, parent_info) = {
        let mut current = process_info.and_then(|info| {
            if info.parent_pid != 0 {
                session.process_tree.get(info.parent_pid)
            } else {
                None
            }
        });
        let mut found_pid = process_info.map(|i| i.parent_pid).unwrap_or(0);
        // Walk up to 8 levels to avoid infinite loops on malformed trees.
        let mut depth = 0;
        while let Some(info) = current {
            if !info.command.starts_with("fork-from-") || depth >= 8 {
                break;
            }
            found_pid = info.parent_pid;
            current = if info.parent_pid != 0 {
                session.process_tree.get(info.parent_pid)
            } else {
                None
            };
            depth += 1;
        }
        (found_pid, current)
    };

    let mut obj = serde_json::Map::new();
    obj.insert("pid".into(), serde_json::json!(event_pid));
    if let Some(info) = process_info {
        obj.insert("process".into(), serde_json::json!(info.command));
        if !info.args.is_empty() {
            obj.insert("process_args".into(), serde_json::json!(info.args));
        }
        if parent_pid != 0 {
            obj.insert("parent_pid".into(), serde_json::json!(parent_pid));
        }
    }
    if let Some(parent) = parent_info {
        obj.insert("parent_process".into(), serde_json::json!(parent.command));
        if !parent.args.is_empty() {
            obj.insert("parent_process_args".into(), serde_json::json!(parent.args));
        }
    }

    match call_type {
        ToolCallType::NetListen { address, port } | ToolCallType::NetConnect { address, port } => {
            obj.insert("address".into(), serde_json::json!(address));
            obj.insert("port".into(), serde_json::json!(port));
            if let Some(class) = classify_unix_socket(address) {
                obj.insert(
                    grith_proxy::types::UnixSocketClass::KEY.into(),
                    serde_json::json!(class.as_str()),
                );
            }
        }
        ToolCallType::ProcessSpawn { command, args } => {
            obj.insert("command".into(), serde_json::json!(command));
            obj.insert("spawn_args".into(), serde_json::json!(args));
        }
        ToolCallType::FileRead { path }
        | ToolCallType::FileAppend { path }
        | ToolCallType::FileDelete { path }
        | ToolCallType::DirList { path }
        | ToolCallType::DirCreate { path }
        | ToolCallType::FileChmod { path, .. } => {
            obj.insert("path".into(), serde_json::json!(path));
        }
        ToolCallType::FileWrite { path, .. } => {
            obj.insert("path".into(), serde_json::json!(path));
        }
        ToolCallType::FileRename { old_path, new_path } => {
            obj.insert("old_path".into(), serde_json::json!(old_path));
            obj.insert("new_path".into(), serde_json::json!(new_path));
        }
        ToolCallType::FileLink {
            target,
            link_path,
            symbolic,
        } => {
            // A link has two paths and the filters now score BOTH; the
            // deciding one is frequently the link path (where it was
            // planted), not the target. `path` is the link path so an
            // operator asking "what was created at ~/.ssh/authorized_keys"
            // finds it; `link_target` records what the link exposes. Both
            // are queryable.
            obj.insert("path".into(), serde_json::json!(link_path));
            obj.insert("link_target".into(), serde_json::json!(target));
            obj.insert("link_symbolic".into(), serde_json::json!(symbolic));
        }
        ToolCallType::HttpRequest { method, url } => {
            obj.insert("method".into(), serde_json::json!(method));
            obj.insert("url".into(), serde_json::json!(url));
        }
        ToolCallType::ShellExec { command, args } => {
            obj.insert("command".into(), serde_json::json!(command));
            obj.insert("exec_args".into(), serde_json::json!(args));
        }
        ToolCallType::DnsQuery { domain, query_type } => {
            obj.insert("domain".into(), serde_json::json!(domain));
            obj.insert("query_type".into(), serde_json::json!(query_type));
        }
        // PR 6 Phase B: category-2 syscalls.
        ToolCallType::OwnershipChange {
            target,
            new_uid,
            new_gid,
        } => {
            obj.insert("path".into(), serde_json::json!(target));
            obj.insert("new_uid".into(), serde_json::json!(new_uid));
            obj.insert("new_gid".into(), serde_json::json!(new_gid));
        }
        ToolCallType::FilesystemMutation {
            op,
            source,
            target,
            fstype,
        } => {
            obj.insert("fs_op".into(), serde_json::json!(op));
            obj.insert("path".into(), serde_json::json!(target));
            if let Some(s) = source {
                obj.insert("source".into(), serde_json::json!(s));
            }
            if let Some(t) = fstype {
                obj.insert("fstype".into(), serde_json::json!(t));
            }
        }
        ToolCallType::CrossProcessAccess { op, target_pid } => {
            obj.insert("cp_op".into(), serde_json::json!(op));
            obj.insert("target_pid".into(), serde_json::json!(target_pid));
        }
        ToolCallType::NamespaceOp { syscall, flags } => {
            obj.insert("ns_syscall".into(), serde_json::json!(syscall));
            obj.insert("ns_flags".into(), serde_json::json!(format!("{flags:#x}")));
        }
        ToolCallType::DbusMethodCall {
            socket,
            destination,
            interface,
            member,
        } => {
            obj.insert("address".into(), serde_json::json!(socket));
            if let Some(d) = destination {
                obj.insert("dbus_destination".into(), serde_json::json!(d));
            }
            if let Some(i) = interface {
                obj.insert("dbus_interface".into(), serde_json::json!(i));
            }
            if let Some(m) = member {
                obj.insert("dbus_member".into(), serde_json::json!(m));
            }
        }
    }

    serde_json::Value::Object(obj)
}

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

/// Convert proxy filter results into the digest `FilterBreakdown` list.
pub(super) fn to_filter_breakdowns(
    results: &[grith_proxy::types::FilterResult],
) -> Vec<FilterBreakdown> {
    results
        .iter()
        .filter(|r| r.matched)
        .map(|r| FilterBreakdown {
            filter_name: r.filter_name.clone(),
            score: r.score,
            rule_id: r.rule_id.clone(),
            message: r.message.clone(),
        })
        .collect()
}

/// Build a full `AuditRecord` from the proxy evaluation context.
/// Optional reputation context to inject into audit records.
#[allow(dead_code)]
pub(super) struct ReputationContext {
    pub trust_score: f64,
    pub auto_allowed: bool,
    pub score_reduction: f64,
    pub reputation_key: String,
}

/// Classification of a short-circuit path, used to pick which
/// `audit_completeness` tier records it.
#[derive(Debug, Clone, Copy)]
pub(super) enum CompactTier {
    /// `ProcessSpawn` matched the session allowlist (routine binary).
    RoutineSpawn,
    /// File-I/O call matched the session allowlist, the read-only noise
    /// reducer, or the batched-read coalescer.
    RoutineIo,
    /// `is_noise_path` filter discarded the call (`/proc/`, `/dev/null`,
    /// `/var/cache/`, CA cert dirs, …).
    NoisePath,
}

/// Emit a compact audit row for a short-circuit decision when the
/// configured `audit_completeness` level wants it.
///
/// Cheap fast-path when the level says no — avoids constructing the
/// `AuditRecord` and `arguments` JSON. Otherwise builds a minimal
/// record (no filter_results, no composite_score, no evaluation time)
/// and ships it through the same `audit_sink` the full pipeline uses,
/// so dashboard/sync semantics are identical.
///
/// `short_circuit_reason` is a stable label suffix (e.g. `"noise_path"`,
/// `"session_allowed"`, `"read_only_noise"`, `"batched_read"`) appended
/// to `tool_call_type` so dashboard rows can show which short-circuit
/// fired. The original call_type prefix is preserved.
pub(super) async fn maybe_log_compact(
    loop_ctx: &super::SupervisorLoopContext<'_>,
    session: &SupervisorSession,
    event_pid: u32,
    call_type: &ToolCallType,
    tier: CompactTier,
    short_circuit_reason: &'static str,
) {
    let level = loop_ctx.config.audit_completeness;
    let wants = match tier {
        CompactTier::RoutineSpawn => level.records_routine_spawns(),
        CompactTier::RoutineIo => level.records_routine_io(),
        CompactTier::NoisePath => level.records_noise_paths(),
    };
    if !wants {
        return;
    }

    let plugin_id = format!("supervisor:{}", session.tool_name);
    let arguments = supervisor_event_arguments(session, event_pid, call_type);
    let tool_call_type = format!("{} [{}]", call_type, short_circuit_reason);

    let mut record = grith_audit::AuditRecord::new_compact(
        session.id,
        plugin_id,
        tool_call_type,
        &arguments,
        grith_audit::ProxyActionSummary::Allow,
    )
    // `supervised_tool` is the actual tool under supervision (claude /
    // codex / aider / …). `project_name` is persisted on the record too
    // (in addition to the live supervisor registry, which is keyed off
    // `session_id` but evicted at session end) so audit history can be
    // grouped/labelled by project long after the session is gone.
    .with_supervisor_source(session.tool_name.clone(), event_pid)
    .with_project_name(session.project_name.clone())
    .with_analytics_metadata(prospective_analytics_metadata(
        loop_ctx,
        session,
        match tier {
            CompactTier::RoutineSpawn => RecordClass::RoutineSpawn,
            CompactTier::RoutineIo => RecordClass::RoutineIo,
            CompactTier::NoisePath => RecordClass::Noise,
        },
        &call_type.to_string(),
    ));

    // Extended summary for ProcessSpawn — the meaningful payload (the
    // bash wrapper around eval $(… | base64 -d), or the full argv of a
    // long-arg compile command) lives past the 256-byte default cap.
    if matches!(call_type, ToolCallType::ProcessSpawn { .. }) {
        record.arguments_summary = grith_audit::types::summarize_arguments_with_limit(
            &arguments,
            grith_audit::types::SPAWN_SUMMARY_LIMIT,
        );
    }

    if let Err(e) = loop_ctx.audit_sink.log(record).await {
        // Logging — not failing — because compact records are
        // best-effort telemetry, not a security gate. A loss here
        // doesn't allow anything the operator hasn't already permitted.
        tracing::warn!(
            error = %e,
            tier = ?tier,
            reason = short_circuit_reason,
            "compact audit record send failed"
        );
    }
}

pub(super) fn build_audit_record(
    ctx: &ToolCallContext,
    decision: &grith_proxy::types::ProxyDecision,
    session: &SupervisorSession,
    event_pid: u32,
    dlp_redactor: &grith_proxy::filters::dlp_gate::DlpRedactor,
    correlation_id: Option<Uuid>,
    reputation_ctx: Option<&ReputationContext>,
) -> AuditRecord {
    let mut record = AuditRecord::new(
        session.id,
        ctx.plugin_id.clone(),
        ctx.call_type.to_string(),
        &ctx.arguments,
        decision.composite_score,
        audit_bridge::to_action_summary(&decision.action),
        audit_bridge::to_filter_summaries(&decision.filter_results),
        decision.evaluation_time.as_secs_f64() * 1000.0,
        ctx.task_context.clone(),
    )
    // `supervised_tool` is the actual tool under supervision (claude /
    // codex / aider / …). `project_name` is persisted on the record too
    // (in addition to the live supervisor registry, which is keyed off
    // `session_id` but evicted at session end) so audit history can be
    // grouped/labelled by project long after the session is gone.
    .with_supervisor_source(session.tool_name.clone(), event_pid)
    .with_project_name(session.project_name.clone());

    // Extended summary for ProcessSpawn — the meaningful payload (full
    // argv of a compile command, the bash wrapper containing the eval
    // base64 blob, etc.) lives past the 256-byte default. Applied
    // BEFORE the DLP redactor so any secrets that newly appear in the
    // extended range still get redacted.
    if matches!(ctx.call_type, ToolCallType::ProcessSpawn { .. }) {
        record.arguments_summary = grith_audit::types::summarize_arguments_with_limit(
            &ctx.arguments,
            grith_audit::types::SPAWN_SUMMARY_LIMIT,
        );
    }

    if grith_proxy::filters::dlp_gate::has_dlp_detection(&decision.filter_results) {
        record.arguments_summary = dlp_redactor.redact(&record.arguments_summary);
    }
    if let Some(id) = correlation_id {
        record = record.with_correlation(id);
    }

    // PR 4 Phase F: attach routine-spawn forensic fields. Populated on
    // every ProcessSpawn decision where SpawnProvenance was computed
    // (Phase D plumbs it on the context). `shadow_phase3_filters` is a
    // JSON list of phase-3 filters that matched at non-zero — populated
    // only when the routine signal applied (rule_id "process-spawn-
    // routine") so operators can see what *would have* tripped at the
    // higher +1.0 baseline.
    if let Some(prov) = ctx.spawn_provenance.as_ref() {
        let routine_signal_applied = decision.filter_results.iter().any(|fr| {
            fr.filter_name == "operation-risk"
                && fr.rule_id == grith_proxy::filters::operation_risk::ROUTINE_SPAWN_RULE_ID
        });
        let shadow_phase3 = if routine_signal_applied {
            // Serialise the phase-3-shaped filter contributions so the
            // UI can render them. Use the filter_results list as the
            // source of truth; downstream phase-3 filters (taint,
            // behavioural, rate_limit, reputation, etc.) all emit
            // entries on the same Vec, so collecting non-zero matches
            // by filter_name is sufficient.
            let entries: Vec<serde_json::Value> = decision
                .filter_results
                .iter()
                .filter(|fr| fr.matched && fr.score > 0.0 && fr.filter_name != "operation-risk")
                .map(|fr| {
                    serde_json::json!({
                        "filter": fr.filter_name,
                        "rule_id": fr.rule_id,
                        "score": fr.score,
                    })
                })
                .collect();
            // Always Some(...) when the routine signal applied, even
            // if the list is empty — empty list is itself a signal
            // ("routine spawn evaluated clean").
            serde_json::to_string(&entries).ok()
        } else {
            None
        };
        record = record.with_spawn_provenance(
            Some(prov.sha256.clone()),
            prov.matched_routine_root.clone(),
            shadow_phase3,
        );
    }

    // PR 5 Phase E: attach listener-rewrite forensic fields. A
    // wildcard `NetListen` that the proxy allowed AND that has a
    // `listener_policy_match.allow_clamp = true` must have been
    // clamped by `maybe_clamp_listen_address` — any clamp failure
    // would have changed `decision.action` to Deny. So if we see
    // Allow on this shape, the clamp succeeded; record the original
    // + rewritten addresses and the policy entry that authorised it.
    if let ToolCallType::NetListen { address, port } = &ctx.call_type {
        let is_wildcard = address
            .parse::<std::net::IpAddr>()
            .map(|ip| {
                ip.is_unspecified()
                    || matches!(
                        ip,
                        std::net::IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_unspecified())
                    )
            })
            .unwrap_or(false);
        let allow_clamp = ctx
            .listener_policy_match
            .as_ref()
            .is_some_and(|m| m.allow_clamp);
        let is_allow = matches!(decision.action, grith_proxy::types::ProxyAction::Allow);
        if is_wildcard && allow_clamp && is_allow {
            let original = format!("{address}:{port}");
            let rewritten = match address.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(_)) => format!("127.0.0.1:{port}"),
                Ok(std::net::IpAddr::V6(_)) => format!("[::1]:{port}"),
                _ => format!("127.0.0.1:{port}"), // unreachable per parse above
            };
            let desc = ctx
                .listener_policy_match
                .as_ref()
                .map(|m| m.desc.clone())
                .unwrap_or_default();
            record = record.with_listener_rewrite(original, rewritten, desc);
        }
    }

    // Inject reputation context into the filter_scores map and execution_result.
    if let Some(rep) = reputation_ctx {
        let scores = record.filter_scores.get_or_insert_with(HashMap::new);
        scores.insert("reputation_trust".to_string(), rep.trust_score);
        scores.insert("reputation_reduction".to_string(), rep.score_reduction);
        if rep.auto_allowed {
            scores.insert("reputation_auto_allowed".to_string(), 1.0);
        }
        // Store the reputation key in execution_result so the audit UI can
        // link to the specific reputation entry.
        if !rep.reputation_key.is_empty() {
            record.execution_result = Some(format!("reputation_key:{}", rep.reputation_key));
        }
    }

    // H-16: populate decision_reason + enforcement_outcome on EVERY supervisor
    // record. Previously only the DNS path (dns_decision.rs) set these, so the
    // evidence columns — which exist and are hash-covered — were NULL on every
    // non-DNS record. Map the proxy decision to what grith enforced at the
    // syscall boundary; the reason is DLP-redacted like the DNS path.
    let decision_reason = (!decision.decision_reason.is_empty())
        .then(|| dlp_redactor.redact(&decision.decision_reason));
    let enforcement_outcome = match &decision.action {
        grith_proxy::types::ProxyAction::Allow => "allowed",
        grith_proxy::types::ProxyAction::Queue { .. } => "queued",
        grith_proxy::types::ProxyAction::Deny { .. } => "denied",
    };
    record = record.with_decision_enforcement(decision_reason, enforcement_outcome);

    record
}

/// Build a `DigestItem` for a queued decision.
pub(super) fn build_digest_item(
    ctx: &ToolCallContext,
    decision: &grith_proxy::types::ProxyDecision,
    dlp_redactor: &grith_proxy::filters::dlp_gate::DlpRedactor,
) -> DigestItem {
    let mut summary = grith_audit::types::summarize_arguments(&ctx.arguments);
    if grith_proxy::filters::dlp_gate::has_dlp_detection(&decision.filter_results) {
        summary = dlp_redactor.redact(&summary);
    }
    DigestItem {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        session_id: Some(ctx.session_id),
        tool_call_type: ctx.call_type.to_string(),
        arguments_summary: summary,
        decision_reason: (!decision.decision_reason.is_empty())
            .then(|| decision.decision_reason.clone()),
        composite_score: decision.composite_score,
        severity: ScoreSeverity::from_score(decision.composite_score),
        filter_breakdown: to_filter_breakdowns(&decision.filter_results),
        task_context: ctx.task_context.clone(),
        plugin_id: ctx.plugin_id.clone(),
        status: DigestStatus::Pending,
        reviewed_at: None,
        review_action: None,
        reviewer_notes: None,
        informational_only: false,
        escalated_at: None,
        escalated_by: None,
    }
}

/// Build a compact JSON string for WS broadcast.
///
/// `action_override` — if non-empty, replaces the action field (e.g. for
/// queue decisions that were effectively allowed in Log mode).
pub(super) fn build_ws_event(
    ctx: &ToolCallContext,
    decision: &grith_proxy::types::ProxyDecision,
    session: &SupervisorSession,
    action_override: &str,
) -> String {
    let action = if action_override.is_empty() {
        audit_bridge::to_action_summary(&decision.action).to_string()
    } else {
        action_override.to_string()
    };
    serde_json::json!({
        "type": "proxy_evaluation",
        "session_id": session.id.to_string(),
        "tool_name": session.tool_name,
        // Carry the project name on the live event so the dashboard's audit
        // ticker can label a brand-new session's rows immediately, instead of
        // waiting for the ~5s REST audit poll to populate the session→project map.
        "project_name": session.project_name,
        "call_type": ctx.call_type.to_string(),
        "call_id": format!("{}:{}", session.id, ctx.plugin_id),
        "plugin_id": ctx.plugin_id,
        "composite_score": decision.composite_score,
        "score": decision.composite_score,
        "action": action,
        "evaluation_time_ms": decision.evaluation_time.as_secs_f64() * 1000.0,
        "filter_results": decision.filter_results.iter().map(|fr| {
            serde_json::json!({
                "filter_name": fr.filter_name,
                "score": fr.score,
            })
        }).collect::<Vec<_>>(),
        "reason": decision.decision_reason,
        "timestamp": Utc::now().to_rfc3339(),
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod unattended_review_tests {
    use super::*;

    /// While reviews are being answered, the full window is used.
    #[test]
    fn an_attended_session_keeps_the_full_window() {
        assert_eq!(unattended_window(2, 0, 5), None);
        assert_eq!(unattended_window(2, 1, 5), None);
    }

    /// Once the streak is reached, the short window takes over. A queued
    /// syscall holds the whole session behind it, so five minutes per call
    /// for an answer nobody is giving is pure stall.
    #[test]
    fn an_unattended_session_falls_back_to_the_short_window() {
        assert_eq!(unattended_window(2, 2, 5), Some(Duration::from_secs(5)));
        assert_eq!(unattended_window(2, 41, 5), Some(Duration::from_secs(5)));
    }

    /// `0` is the documented off switch.
    #[test]
    fn a_zero_streak_disables_the_fallback() {
        assert_eq!(unattended_window(0, 99, 5), None);
    }

    /// The streak counts only timeouts, and ANY resolution clears it — a
    /// local answer, a notification channel, or a scope grant. An operator
    /// who steps away and comes back gets the full window on their next
    /// prompt, not a shortened one.
    #[test]
    fn any_answer_restores_the_full_window() {
        let unanswered = AtomicU32::new(0);
        let limit = 2u32;
        let window = |unanswered: &AtomicU32| {
            unattended_window(limit, unanswered.load(Ordering::Relaxed), 5)
        };

        note_attendance(limit, &unanswered, ReviewOutcome::TimedOut);
        assert_eq!(window(&unanswered), None);

        note_attendance(limit, &unanswered, ReviewOutcome::TimedOut);
        assert_eq!(
            window(&unanswered),
            Some(Duration::from_secs(5)),
            "two unanswered reviews mean nobody is there"
        );

        note_attendance(limit, &unanswered, ReviewOutcome::Approved);
        assert_eq!(
            window(&unanswered),
            None,
            "an approval proves somebody is at the keyboard"
        );

        note_attendance(limit, &unanswered, ReviewOutcome::TimedOut);
        note_attendance(limit, &unanswered, ReviewOutcome::Denied);
        assert_eq!(
            window(&unanswered),
            None,
            "an explicit deny is an answer too"
        );
    }

    /// The transition is reported once, not on every review, so the log says
    /// "the operator went away" rather than repeating it 41 times.
    #[test]
    fn the_transition_is_reported_once() {
        let unanswered = AtomicU32::new(0);
        assert_eq!(
            note_attendance(2, &unanswered, ReviewOutcome::TimedOut),
            AttendanceChange::Unchanged
        );
        assert_eq!(
            note_attendance(2, &unanswered, ReviewOutcome::TimedOut),
            AttendanceChange::WentUnattended(2)
        );
        assert_eq!(
            note_attendance(2, &unanswered, ReviewOutcome::TimedOut),
            AttendanceChange::Unchanged
        );
        assert_eq!(
            note_attendance(2, &unanswered, ReviewOutcome::Approved),
            AttendanceChange::Returned(3)
        );
        assert_eq!(
            note_attendance(2, &unanswered, ReviewOutcome::Approved),
            AttendanceChange::Unchanged
        );
    }

    /// With the fallback off, the counter is never touched at all.
    #[test]
    fn a_zero_streak_records_nothing() {
        let unanswered = AtomicU32::new(0);
        assert_eq!(
            note_attendance(0, &unanswered, ReviewOutcome::TimedOut),
            AttendanceChange::Unchanged
        );
        assert_eq!(unanswered.load(Ordering::Relaxed), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::Utc;
    use grith_proxy::engine::SecurityProxy;
    use grith_proxy::filters::FilterRegistry;
    use grith_proxy::meta_rules::MetaRuleEngine;
    use grith_proxy::scoring::ScoringConfig;
    use grith_proxy::types::ToolCallType;
    use std::collections::{HashSet, VecDeque};
    use std::sync::{Arc, Mutex};

    /// The containment gate exception opens ONLY for a NetConnect whose exact
    /// destination AND port carry an operator-minted `ssh-egress:` grant — never
    /// for a profile-seeded `net:` entry, a different host, or a different port.
    #[test]
    fn ssh_egress_grant_gates_only_operator_approved_destination() {
        let connect = |addr: &str, port: u16| ToolCallType::NetConnect {
            address: addr.to_string(),
            port,
        };
        // Profile routine seed: net: only — the exception must stay shut.
        let profile_seeded: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(
            ["net:api.anthropic.com".to_string()].into_iter().collect(),
        ));
        assert!(!netconnect_operator_ssh_egress_grant(
            &connect("api.anthropic.com", 443),
            &profile_seeded
        ));

        // Operator-approved ssh destination: the port-scoped grant is present.
        let approved: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(
            [
                "net:terminus.pelygo.com".to_string(),
                "ssh-egress:terminus.pelygo.com:22".to_string(),
            ]
            .into_iter()
            .collect(),
        ));
        assert!(netconnect_operator_ssh_egress_grant(
            &connect("terminus.pelygo.com", 22),
            &approved
        ));
        // Same host, DIFFERENT port — the port-scoped grant must not cover it,
        // even though the portless net: entry would.
        assert!(!netconnect_operator_ssh_egress_grant(
            &connect("terminus.pelygo.com", 8080),
            &approved
        ));
        // A different host is not covered by that grant.
        assert!(!netconnect_operator_ssh_egress_grant(
            &connect("evil.example", 22),
            &approved
        ));
        // Non-NetConnect never matches.
        assert!(!netconnect_operator_ssh_egress_grant(
            &ToolCallType::ProcessSpawn {
                command: "/usr/bin/ssh".into(),
                args: vec!["ssh".into(), "terminus.pelygo.com".into()],
            },
            &approved
        ));
    }

    /// `ToolCallType::supports_session_grant` is what the approval dialog
    /// renders "[l] Always allow" from; `session_allowlist_key` is what
    /// actually records the grant. If they disagree, the operator is offered
    /// a durable answer that this function then throws away — which is how
    /// the D-Bus prompts in supervised session 433ba7c7 (2026-08-25) came to
    /// re-ask after every approval.
    ///
    /// `session_allowlist_key` ends in a `_ => None` arm and so cannot be
    /// made exhaustive by the compiler. This test is the guard instead.
    #[test]
    fn session_grant_predicate_matches_the_allowlist_key() {
        // Self, so the `/proc/<pid>/stat` read behind the CrossProcessAccess
        // key always resolves — a dead pid legitimately yields `None` there,
        // which would make this test flaky rather than meaningful.
        let live_pid = std::process::id();
        let cases = vec![
            ToolCallType::FileRead { path: "/p".into() },
            ToolCallType::FileWrite {
                path: "/p".into(),
                content_hash: String::new(),
            },
            ToolCallType::FileAppend { path: "/p".into() },
            ToolCallType::FileDelete { path: "/p".into() },
            ToolCallType::DirList { path: "/p".into() },
            ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec![],
            },
            ToolCallType::HttpRequest {
                method: "GET".into(),
                url: "https://example.test/".into(),
            },
            ToolCallType::FileRename {
                old_path: "/a".into(),
                new_path: "/b".into(),
            },
            ToolCallType::FileLink {
                link_path: "/a".into(),
                target: "/b".into(),
                symbolic: true,
            },
            ToolCallType::FileChmod {
                path: "/p".into(),
                mode: 0o644,
            },
            ToolCallType::DirCreate { path: "/p".into() },
            ToolCallType::NetConnect {
                address: "example.test".into(),
                port: 443,
            },
            ToolCallType::NetListen {
                address: "0.0.0.0".into(),
                port: 8080,
            },
            ToolCallType::ProcessSpawn {
                command: "/bin/ls".into(),
                args: vec![],
            },
            ToolCallType::DnsQuery {
                domain: "example.test".into(),
                query_type: "A".into(),
            },
            ToolCallType::OwnershipChange {
                target: "/p".into(),
                new_uid: 0,
                new_gid: 0,
            },
            ToolCallType::FilesystemMutation {
                op: "mount".into(),
                source: None,
                target: "/mnt".into(),
                fstype: None,
            },
            ToolCallType::CrossProcessAccess {
                op: "ptrace".into(),
                target_pid: live_pid,
            },
            ToolCallType::NamespaceOp {
                syscall: "unshare".into(),
                flags: 0,
            },
            ToolCallType::DbusMethodCall {
                socket: "unix:/run/user/1000/bus".into(),
                destination: Some("org.freedesktop.systemd1".into()),
                interface: Some("org.freedesktop.systemd1.Manager".into()),
                member: Some("StartTransientUnit".into()),
            },
        ];
        assert_eq!(cases.len(), 20, "a ToolCallType variant is not covered");

        for call in cases {
            assert_eq!(
                session_allowlist_key(&call).is_some(),
                call.supports_session_grant(),
                "{call} is offered a session grant the allowlist key does not \
                 record (or vice versa)"
            );
        }
    }
    use std::time::Duration;

    /// Listener policy entries match their port exactly: `port = 0` covers
    /// only kernel-assigned-ephemeral binds (literal port 0), never a
    /// fixed-port bind. The old any-port clause made the shipped codex entry
    /// clamp arbitrary fixed ports to loopback under a description that
    /// promised "kernel-assigned localhost port".
    #[test]
    fn listener_policy_port_zero_is_exact_not_any_port() {
        let policy = vec![crate::profiles::LocalListenerEntry {
            port: 0,
            family: crate::profiles::ListenerFamily::Any,
            desc: "ephemeral MCP transport".into(),
            allow_clamp: true,
        }];
        assert!(
            match_listener_policy(&policy, "0.0.0.0", 0).is_some(),
            "literal port-0 bind must match a port-0 entry"
        );
        assert!(
            match_listener_policy(&policy, "0.0.0.0", 10051).is_none(),
            "a fixed-port bind must NOT match a port-0 entry"
        );
        // And the converse: a fixed-port entry matches only that port.
        let fixed = vec![crate::profiles::LocalListenerEntry {
            port: 41234,
            family: crate::profiles::ListenerFamily::Any,
            desc: "MCP server".into(),
            allow_clamp: false,
        }];
        assert!(match_listener_policy(&fixed, "0.0.0.0", 41234).is_some());
        assert!(match_listener_policy(&fixed, "0.0.0.0", 0).is_none());
    }

    /// NetListen session keys carry the port and live in their own
    /// `listen:` namespace: an approval on one (address, port) must not
    /// grant every port on that address, and must not cross over into
    /// `net:` connect grants (or vice versa).
    #[test]
    fn listen_session_keys_are_port_scoped_and_isolated_from_net() {
        let listen_3124 = ToolCallType::NetListen {
            address: "0.0.0.0".into(),
            port: 3124,
        };
        let key = session_allowlist_key(&listen_3124).unwrap();
        assert_eq!(key, "listen:0.0.0.0:3124");

        // Exact grant matches; a different port does not.
        let allowed: HashSet<String> = HashSet::from([key.clone()]);
        assert!(is_session_allowlist_match(&key, &allowed, &listen_3124));
        let listen_3125 = ToolCallType::NetListen {
            address: "0.0.0.0".into(),
            port: 3125,
        };
        let other_key = session_allowlist_key(&listen_3125).unwrap();
        assert!(!is_session_allowlist_match(
            &other_key,
            &allowed,
            &listen_3125
        ));

        // A listen grant must not authorise a CONNECT to the same address
        // string, and a net: connect grant must not authorise a listen.
        let connect = ToolCallType::NetConnect {
            address: "0.0.0.0".into(),
            port: 3124,
        };
        let connect_key = session_allowlist_key(&connect).unwrap();
        assert_eq!(connect_key, "net:0.0.0.0");
        assert!(!is_session_allowlist_match(
            &connect_key,
            &allowed,
            &connect
        ));
        let net_only: HashSet<String> = HashSet::from(["net:0.0.0.0".to_string()]);
        assert!(!is_session_allowlist_match(&key, &net_only, &listen_3124));

        // Profile-seeded portless `listen:<addr>` (routine_listen_addresses)
        // covers every port on that address — including IPv6, where the
        // port is split on the LAST colon.
        let portless: HashSet<String> = HashSet::from(["listen:127.0.0.1".to_string()]);
        let loopback_listen = ToolCallType::NetListen {
            address: "127.0.0.1".into(),
            port: 8080,
        };
        let loopback_key = session_allowlist_key(&loopback_listen).unwrap();
        assert!(is_session_allowlist_match(
            &loopback_key,
            &portless,
            &loopback_listen
        ));
        let v6_portless: HashSet<String> = HashSet::from(["listen:::1".to_string()]);
        let v6_listen = ToolCallType::NetListen {
            address: "::1".into(),
            port: 8080,
        };
        let v6_key = session_allowlist_key(&v6_listen).unwrap();
        assert!(is_session_allowlist_match(
            &v6_key,
            &v6_portless,
            &v6_listen
        ));
    }

    #[test]
    fn syscall_kind_label_strips_fields_to_variant_name() {
        // Unit variant → bare name.
        assert_eq!(
            syscall_kind_label(&SyscallKind::IoUringSetup),
            "IoUringSetup"
        );
        assert_eq!(syscall_kind_label(&SyscallKind::PipeCreate), "PipeCreate");
        // Struct variant → name only, no `{ .. }` payload. This is the value
        // that lands in the audit `tool_call_type` and the dashboard Call Types
        // breakdown — it must never carry the forensic event tag.
        let label = syscall_kind_label(&SyscallKind::FileDelete {
            path: "/tmp/x".into(),
        });
        assert_eq!(label, "FileDelete");
        // No call type should contain a space, brace, or paren.
        assert!(!label.contains(['{', '(', ' ']));
    }

    #[derive(Default, Debug)]
    struct MockInterceptorState {
        allow_pids: Vec<u32>,
        deny_pids: Vec<u32>,
    }

    struct MockInterceptor {
        events: VecDeque<SyscallEvent>,
        state: Arc<Mutex<MockInterceptorState>>,
    }

    impl MockInterceptor {
        fn new(events: Vec<SyscallEvent>) -> (Self, Arc<Mutex<MockInterceptorState>>) {
            let state = Arc::new(Mutex::new(MockInterceptorState::default()));
            (
                Self {
                    events: VecDeque::from(events),
                    state: state.clone(),
                },
                state,
            )
        }
    }

    #[async_trait]
    impl SyscallInterceptor for MockInterceptor {
        async fn attach(&mut self, pid: u32) -> crate::error::Result<()> {
            Err(crate::error::Error::AttachFailed {
                pid,
                reason: "mock interceptor does not support attach".into(),
            })
        }

        async fn spawn_supervised(
            &mut self,
            _command: &str,
            _args: &[String],
            _env: &[(String, String)],
        ) -> crate::error::Result<u32> {
            Err(crate::error::Error::SpawnFailed(
                "mock interceptor does not support spawn".into(),
            ))
        }

        async fn next_event(&mut self) -> crate::error::Result<Option<SyscallEvent>> {
            Ok(self.events.pop_front())
        }

        async fn allow(&mut self, pid: u32) -> crate::error::Result<()> {
            self.state.lock().unwrap().allow_pids.push(pid);
            Ok(())
        }

        async fn deny(&mut self, pid: u32) -> crate::error::Result<()> {
            self.state.lock().unwrap().deny_pids.push(pid);
            Ok(())
        }

        async fn kill(&mut self, pid: u32) -> crate::error::Result<()> {
            // This mock does not distinguish kill from deny; both record the pid
            // as a stopped call (enforcement kill assertions live in
            // protection_tests::RecordingInterceptor, which tracks them apart).
            self.state.lock().unwrap().deny_pids.push(pid);
            Ok(())
        }

        async fn freeze(&mut self, _pid: u32) -> crate::error::Result<()> {
            Ok(())
        }

        async fn thaw(&mut self, _pid: u32) -> crate::error::Result<()> {
            Ok(())
        }

        async fn detach(&mut self, _pid: u32) -> crate::error::Result<()> {
            Ok(())
        }

        async fn detach_all(&mut self) -> crate::error::Result<()> {
            Ok(())
        }

        fn supervised_pids(&self) -> Vec<u32> {
            Vec::new()
        }

        fn is_available() -> bool
        where
            Self: Sized,
        {
            true
        }

        fn mechanism_name(&self) -> &str {
            "mock"
        }
    }

    struct PanicReviewer;

    #[async_trait]
    impl QueueReviewer for PanicReviewer {
        async fn review(&self, _item: &DigestItem, _timeout: Duration) -> ReviewOutcome {
            panic!("io_uring should be denied before review")
        }
    }

    fn allow_only_proxy() -> Arc<SecurityProxy> {
        Arc::new(SecurityProxy::new(
            FilterRegistry::new(),
            ScoringConfig::default(),
            MetaRuleEngine::new(vec![]),
        ))
    }

    fn sample_io_uring_event(pid: u32, raw_syscall_nr: i64) -> SyscallEvent {
        SyscallEvent {
            pid,
            tid: pid,
            timestamp: Utc::now(),
            kind: SyscallKind::IoUringSetup,
            raw_syscall_nr,
        }
    }

    // Protection suite (§6.4) — fail-closed lock: when the daemon (remote proxy)
    // is unreachable, the supervisor must DENY, never fall open to allow.
    #[test]
    fn daemon_unreachable_is_fail_closed_deny() {
        let d = daemon_unreachable_decision("connection refused".to_string());
        assert!(
            matches!(d.action, ProxyAction::Deny { .. }),
            "daemon-unreachable must fail closed (Deny), got {:?}",
            d.action
        );
    }

    #[test]
    fn to_action_summary_maps_correctly() {
        assert_eq!(
            audit_bridge::to_action_summary(&ProxyAction::Allow),
            grith_audit::types::ProxyActionSummary::Allow
        );
        assert_eq!(
            audit_bridge::to_action_summary(&ProxyAction::Queue {
                priority: grith_proxy::types::QueuePriority::High,
            }),
            grith_audit::types::ProxyActionSummary::Queue
        );
        assert_eq!(
            audit_bridge::to_action_summary(&ProxyAction::Deny {
                reason: "test".into(),
            }),
            grith_audit::types::ProxyActionSummary::Deny
        );
    }

    #[test]
    fn to_filter_summaries_preserves_data() {
        use grith_proxy::types::{FilterResult, Severity};

        let results = vec![
            FilterResult::matched(
                "path-match",
                "ssh-key",
                5.0,
                Severity::Critical,
                "SSH key access",
            ),
            FilterResult::no_match("allowlist"),
        ];

        let summaries = audit_bridge::to_filter_summaries(&results);
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].filter_name, "path-match");
        assert!(summaries[0].matched);
        assert_eq!(summaries[0].score, 5.0);
        assert_eq!(summaries[0].severity, "critical");
        assert!(!summaries[1].matched);
    }

    #[test]
    fn to_filter_breakdowns_only_includes_matches() {
        use grith_proxy::types::{FilterResult, Severity};

        let results = vec![
            FilterResult::matched("cmd", "dangerous-cmd", 4.0, Severity::Warning, "risky"),
            FilterResult::no_match("path-match"),
            FilterResult::matched("secret", "aws-key", 7.0, Severity::Critical, "secret found"),
        ];

        let breakdowns = to_filter_breakdowns(&results);
        assert_eq!(breakdowns.len(), 2);
        assert_eq!(breakdowns[0].filter_name, "cmd");
        assert_eq!(breakdowns[1].filter_name, "secret");
    }

    #[test]
    fn build_digest_item_has_correct_fields() {
        let ctx = ToolCallContext::new(
            "supervisor:claude-code",
            ToolCallType::FileRead {
                path: "/etc/shadow".into(),
            },
            Uuid::new_v4(),
        );
        let decision =
            grith_proxy::types::ProxyDecision::queue(5.5, vec![], Duration::from_millis(2));

        let redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let item = build_digest_item(&ctx, &decision, &redactor);
        assert_eq!(item.status, DigestStatus::Pending);
        assert_eq!(item.composite_score, 5.5);
        assert_eq!(item.plugin_id, "supervisor:claude-code");
        assert!(!item.informational_only);
    }

    /// H-16: every supervisor record (not just DNS) now carries the dedicated
    /// decision_reason / enforcement_outcome columns instead of leaving them
    /// NULL. Outcome is derived from the proxy decision's action; the reason is
    /// the (redacted) policy explanation.
    #[test]
    fn build_audit_record_populates_decision_reason_and_outcome() {
        let session = SupervisorSession::new("claude-code", 42);
        let ctx = ToolCallContext::new(
            "supervisor:claude-code",
            ToolCallType::ShellExec {
                command: "rm".into(),
                args: vec!["-rf".into(), "/".into()],
            },
            session.id,
        );
        let redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();

        let deny = grith_proxy::types::ProxyDecision::deny(
            9.0,
            vec![],
            "dangerous command".into(),
            Duration::from_millis(1),
        );
        let rec = build_audit_record(&ctx, &deny, &session, 42, &redactor, None, None);
        assert_eq!(rec.enforcement_outcome.as_deref(), Some("denied"));
        assert_eq!(rec.decision_reason.as_deref(), Some("dangerous command"));

        let allow = grith_proxy::types::ProxyDecision::allow(0.5, vec![], Duration::from_millis(1));
        let rec = build_audit_record(&ctx, &allow, &session, 42, &redactor, None, None);
        assert_eq!(rec.enforcement_outcome.as_deref(), Some("allowed"));

        let queue = grith_proxy::types::ProxyDecision::queue(5.5, vec![], Duration::from_millis(1));
        let rec = build_audit_record(&ctx, &queue, &session, 42, &redactor, None, None);
        assert_eq!(rec.enforcement_outcome.as_deref(), Some("queued"));
    }

    #[test]
    fn build_ws_event_is_valid_json() {
        let session = SupervisorSession::new("claude-code", 42);
        let ctx = ToolCallContext::new(
            "supervisor:claude-code",
            ToolCallType::ShellExec {
                command: "rm".into(),
                args: vec!["-rf".into(), "/".into()],
            },
            session.id,
        );
        let decision = grith_proxy::types::ProxyDecision::deny(
            9.0,
            vec![],
            "dangerous command".into(),
            Duration::from_millis(1),
        );

        let json_str = build_ws_event(&ctx, &decision, &session, "");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["tool_name"], "claude-code");
        assert_eq!(parsed["action"], "deny");
        assert_eq!(parsed["score"], 9.0);
    }

    #[test]
    fn process_tree_kill_targets_include_descendants_then_root() {
        let mut session = SupervisorSession::new("claude-code", 100);
        session.process_tree.add_child(100, 200, "node").unwrap();
        session.process_tree.add_child(200, 300, "python").unwrap();

        let targets = process_tree_kill_targets(&session);
        assert_eq!(targets.last().copied(), Some(100));
        assert!(targets.contains(&200));
        assert!(targets.contains(&300));
        assert_eq!(targets.len(), 3);
    }

    /// work/80: launch-cwd-derived trust (a plain prefix with a `projdir:`
    /// twin) must never auto-allow operations on credential stores — reads
    /// or writes — while (a) non-store paths under the project keep matching
    /// (the FP posture) and (b) explicit literal prefixes without a twin
    /// keep today's override semantics.
    #[test]
    fn projdir_trust_never_covers_credential_stores() {
        use grith_proxy::types::ToolCallType;
        let read = |p: &str| ToolCallType::FileRead {
            path: p.to_string(),
        };
        let write = |p: &str| ToolCallType::FileWrite {
            path: p.to_string(),
            content_hash: String::new(),
        };

        // Project-derived trust of /home/u/proj (twin present).
        let mut allowed = HashSet::new();
        allowed.insert("/home/u/proj".to_string());
        allowed.insert("projdir:/home/u/proj".to_string());

        // Ordinary project files: still routine, reads and writes.
        assert!(is_session_allowlist_match(
            "/home/u/proj/src/main.rs",
            &allowed,
            &read("/home/u/proj/src/main.rs"),
        ));
        // work/80 deliberately let project trust cover the weak name-based
        // signals so `.pem` / `.key` / keyword-named files inside genuine
        // project trees would not re-open the prompt flood. That still holds
        // — these stay covered, and the measurement behind each is recorded
        // on `syscall_map::is_high_value_project_secret`.
        for path in [
            "/home/u/proj/tls/server.pem",
            "/home/u/proj/deploy.key",
            "/home/u/proj/config/secrets.toml",
            "/home/u/proj/.env.example",
        ] {
            assert!(
                is_session_allowlist_match(path, &allowed, &read(path)),
                "project trust must still cover the weak name signals: {path}"
            );
        }

        // Credential stores under the project prefix: never. Nor the
        // in-project high-value secrets — files whose CONTENT is the secret,
        // which live in a project tree by design, and which the proxy scores
        // 4.00-8.00 on a read. `.env` also has to reach the proxy for the
        // taint filter to register it as a sensitive source at all.
        for path in [
            "/home/u/proj/.aws/credentials",
            "/home/u/proj/.ssh/id_deploy",
            "/home/u/proj/.env",
            "/home/u/proj/.env.local",
            "/home/u/proj/config/master.key",
            "/home/u/proj/terraform.tfstate",
            "/home/u/proj/certs/client.p12",
        ] {
            assert!(
                !is_session_allowlist_match(path, &allowed, &read(path)),
                "projdir trust must not cover reads of {path}"
            );
            assert!(
                !is_session_allowlist_match(path, &allowed, &write(path)),
                "projdir trust must not cover writes of {path}"
            );
        }

        // The same prefix WITHOUT a twin (explicit literal profile entry):
        // today's explicit-trust override is preserved.
        let mut explicit = HashSet::new();
        explicit.insert("/home/u/proj".to_string());
        for path in ["/home/u/proj/.aws/credentials", "/home/u/proj/.env"] {
            assert!(
                is_session_allowlist_match(path, &explicit, &read(path)),
                "an explicit literal profile entry keeps its documented override: {path}"
            );
        }

        // The marker itself must be inert: it is not a usable path prefix
        // and must never match anything on its own.
        let mut only_marker = HashSet::new();
        only_marker.insert("projdir:/home/u/proj".to_string());
        assert!(!is_session_allowlist_match(
            "/home/u/proj/src/main.rs",
            &only_marker,
            &read("/home/u/proj/src/main.rs"),
        ));

        // Review defect 1: a rename whose SOURCE is an ordinary project file
        // but whose DESTINATION is a credential store must not be covered —
        // the key is old_path, so the destination has to be guarded too.
        let rename = |old: &str, new: &str| ToolCallType::FileRename {
            old_path: old.to_string(),
            new_path: new.to_string(),
        };
        assert!(
            !is_session_allowlist_match(
                "/home/u/proj/payload",
                &allowed,
                &rename("/home/u/proj/payload", "/home/u/proj/.ssh/authorized_keys"),
            ),
            "rename INTO a project credential store must not be launch-trusted"
        );
        // A rename between two ordinary project files stays routine.
        assert!(is_session_allowlist_match(
            "/home/u/proj/a",
            &allowed,
            &rename("/home/u/proj/a", "/home/u/proj/b"),
        ));

        // Review defect 2: the credential DIRECTORY itself (no trailing
        // file) is a store — a chmod of ~/proj/.aws must not be covered.
        let chmod = |p: &str| ToolCallType::FileChmod {
            path: p.to_string(),
            mode: 0o777,
        };
        assert!(
            !is_session_allowlist_match("/home/u/proj/.aws", &allowed, &chmod("/home/u/proj/.aws")),
            "the credential directory itself must not be launch-trusted"
        );

        // Review defect 2 (exact arm): launch cwd IS the store dir
        // (`cd ~/proj/.aws`), so the key equals the projdir prefix exactly.
        let mut in_store = HashSet::new();
        in_store.insert("/home/u/proj/.aws".to_string());
        in_store.insert("projdir:/home/u/proj/.aws".to_string());
        assert!(
            !is_session_allowlist_match(
                "/home/u/proj/.aws/credentials",
                &in_store,
                &read("/home/u/proj/.aws/credentials"),
            ),
            "launching inside a credential dir must not exact/prefix-trust its contents"
        );
    }

    /// work/83 F4: a workspace root (a linked worktree of the launch
    /// repository) is trusted the same way the launch tree is — as a
    /// `projdir:`-marked prefix — so work/80's credential-store guard keeps
    /// applying to it. Widening *where* project trust reaches must not widen
    /// *what* it may cover.
    #[test]
    fn workspace_root_trust_never_covers_credential_stores() {
        use grith_proxy::types::ToolCallType;
        let read = |p: &str| ToolCallType::FileRead {
            path: p.to_string(),
        };
        let write = |p: &str| ToolCallType::FileWrite {
            path: p.to_string(),
            content_hash: String::new(),
        };

        let mut allowed = HashSet::new();
        crate::profiles::extend_allowlist_with_workspace_roots(
            &mut allowed,
            &["/home/u/worktrees/wt".to_string()],
        );

        // Ordinary files in the worktree: routine, reads and writes — this is
        // the 24.9%-QUEUE-rate false positive F4 exists to remove.
        for path in [
            "/home/u/worktrees/wt/src/main.rs",
            "/home/u/worktrees/wt/target/debug/incremental/abc123auth.o",
        ] {
            assert!(
                is_session_allowlist_match(path, &allowed, &write(path)),
                "workspace trust must cover ordinary worktree files: {path}"
            );
        }

        // Credential stores inside the trusted worktree: never.
        for path in [
            "/home/u/worktrees/wt/.aws/credentials",
            "/home/u/worktrees/wt/.ssh/id_deploy",
        ] {
            assert!(
                !is_session_allowlist_match(path, &allowed, &read(path)),
                "workspace trust must not cover reads of {path}"
            );
            assert!(
                !is_session_allowlist_match(path, &allowed, &write(path)),
                "workspace trust must not cover writes of {path}"
            );
        }

        // Boundary safety: the trailing-slash prefix stops a sibling
        // directory that merely shares the name from inheriting trust.
        assert!(!is_session_allowlist_match(
            "/home/u/worktrees/wt-backup/src/main.rs",
            &allowed,
            &read("/home/u/worktrees/wt-backup/src/main.rs"),
        ));
    }

    /// Project-derived trust — launch-derived or workspace-derived, they share
    /// the `projdir:` marker — must not short-circuit the files whose CONTENT
    /// is the secret and that live in a project tree by design. Measured at
    /// the proxy on a read: `config/master.key` 8.00, `.env`/`.env.local`
    /// 6.00, `terraform.tfstate` 4.00, `certs/client.p12` 4.00 — all Queue.
    /// `.env` is also the taint filter's first sensitive source, so a
    /// short-circuited read registers no taint and the later exfiltration
    /// cannot be scored.
    ///
    /// The guard stops there. Every path in the second list stays covered,
    /// because widening to the full `is_sensitive_path` would reinstate the
    /// flood work/83 exists to remove — measured, all three `*.pem`/`*.key`
    /// files in this workspace are false positives (a public AWS CA bundle
    /// and two vendored TLS test fixtures, 8.00 each) and grith's own
    /// `config/secrets.toml` scores 5.80 on the keyword rule.
    #[test]
    fn project_trust_never_covers_in_project_secrets() {
        use grith_proxy::types::ToolCallType;
        let read = |p: &str| ToolCallType::FileRead {
            path: p.to_string(),
        };
        let write = |p: &str| ToolCallType::FileWrite {
            path: p.to_string(),
            content_hash: String::new(),
        };

        let mut allowed = HashSet::new();
        crate::profiles::extend_allowlist_with_workspace_roots(
            &mut allowed,
            &["/home/u/worktrees/wt".to_string()],
        );

        for relative in [
            ".env",
            ".env.local",
            ".env.production",
            "config/master.key",
            "terraform.tfstate",
            "terraform.tfstate.backup",
            "certs/client.p12",
            "certs/bundle.pfx",
        ] {
            let path = format!("/home/u/worktrees/wt/{relative}");
            assert!(
                !is_session_allowlist_match(&path, &allowed, &read(&path)),
                "project trust must not short-circuit reads of {path}"
            );
            assert!(
                !is_session_allowlist_match(&path, &allowed, &write(&path)),
                "project trust must not short-circuit writes of {path}"
            );
        }

        for relative in [
            "tls/server.pem",
            "deploy.key",
            "config/secrets.toml",
            "src/auth/token_store.rs",
            ".env.example",
            ".env.sample",
            "src/main.rs",
        ] {
            let path = format!("/home/u/worktrees/wt/{relative}");
            assert!(
                is_session_allowlist_match(&path, &allowed, &read(&path)),
                "the weak name signals stay covered inside a project tree: {path}"
            );
        }

        // Two-ended calls are guarded at BOTH ends, exactly as the credential
        // stores are: a rename INTO `.env`, and a hardlink whose target is
        // `.env`, would otherwise publish or overwrite the secret behind an
        // ordinary-looking key. (The link arm additionally has to move with
        // the read guard: its safety argument is that a link is no stronger
        // than the copy trust already allows, which stops being true the
        // moment `FileRead <target>` reaches the proxy.)
        let rename = ToolCallType::FileRename {
            old_path: "/home/u/worktrees/wt/build/staged".to_string(),
            new_path: "/home/u/worktrees/wt/.env".to_string(),
        };
        assert!(!is_session_allowlist_match(
            "/home/u/worktrees/wt/build/staged",
            &allowed,
            &rename,
        ));
        let link = ToolCallType::FileLink {
            target: "/home/u/worktrees/wt/.env".to_string(),
            link_path: "/home/u/worktrees/wt/build/artifact".to_string(),
            symbolic: false,
        };
        assert!(!is_session_allowlist_match(
            "/home/u/worktrees/wt/build/artifact",
            &allowed,
            &link,
        ));
    }

    /// work/83 F5: `FileLink` had no session-allowlist key, so in-project
    /// build hardlinks were proxy-scored forever. It has one now — but only
    /// when BOTH ends stay inside the trusted tree and neither is a
    /// credential store, so link creation cannot become the cheap way to
    /// move authority across the trust boundary.
    #[test]
    fn projdir_trust_covers_in_project_links_only() {
        use grith_proxy::types::ToolCallType;
        let link = |target: &str, link_path: &str| ToolCallType::FileLink {
            target: target.to_string(),
            link_path: link_path.to_string(),
            symbolic: false,
        };
        let symlink = |target: &str, link_path: &str| ToolCallType::FileLink {
            target: target.to_string(),
            link_path: link_path.to_string(),
            symbolic: true,
        };

        let mut allowed = HashSet::new();
        allowed.insert("/home/u/proj".to_string());
        allowed.insert("projdir:/home/u/proj".to_string());

        // The key is the link path (where the new name appears).
        let rustc_link = link(
            "/home/u/proj/target/debug/deps/net-9a598f.rcgu.o",
            "/home/u/proj/target/debug/incremental/773v9mxq3ohs6twiwt1rzauth.o",
        );
        assert_eq!(
            session_allowlist_key(&rustc_link).as_deref(),
            Some("/home/u/proj/target/debug/incremental/773v9mxq3ohs6twiwt1rzauth.o"),
        );

        // In-project hardlink: both ends under the trusted tree → short-circuits.
        assert!(
            is_session_allowlist_match(
                &session_allowlist_key(&rustc_link).unwrap(),
                &allowed,
                &rustc_link,
            ),
            "an in-project build hardlink must be covered by project trust"
        );

        // Target is a credential store: never, even though the link path is
        // an ordinary project file inside the trusted tree.
        let steal = link("/home/u/proj/.ssh/id_deploy", "/home/u/proj/build/artifact");
        assert!(
            !is_session_allowlist_match(&session_allowlist_key(&steal).unwrap(), &allowed, &steal,),
            "a link whose target is a credential store must reach the proxy"
        );

        // Link path is a credential store: never (the `ln -s ./mine
        // ~/.ssh/authorized_keys` shape, with the project as the source).
        let plant = symlink("/home/u/proj/mine", "/home/u/proj/.ssh/authorized_keys");
        assert!(
            !is_session_allowlist_match(&session_allowlist_key(&plant).unwrap(), &allowed, &plant,),
            "a link planted into a credential store must reach the proxy"
        );

        // Target outside the trusted tree: never — publishing an untrusted
        // file under a trusted name is the laundering shape.
        let launder = symlink("/home/u/other/private.key", "/home/u/proj/x");
        assert!(
            !is_session_allowlist_match(
                &session_allowlist_key(&launder).unwrap(),
                &allowed,
                &launder,
            ),
            "a link whose target is outside the trusted tree must reach the proxy"
        );

        // A read-only (`ro:`) grant on the target must not become
        // write-through via a hard link.
        let mut ro_allowed = allowed.clone();
        ro_allowed.insert("ro:/home/u/secrets.txt".to_string());
        let ro_link = link("/home/u/secrets.txt", "/home/u/proj/copy");
        assert!(
            !is_session_allowlist_match(
                &session_allowlist_key(&ro_link).unwrap(),
                &ro_allowed,
                &ro_link,
            ),
            "a read-only grant on the target must not authorise hardlinking it"
        );
    }

    #[test]
    fn net_allowlist_matches_exact_and_subdomain() {
        let d = dummy_file_read();
        let allowed = HashSet::from(["net:openai.com".to_string()]);
        assert!(is_session_allowlist_match("net:openai.com", &allowed, &d));
        assert!(is_session_allowlist_match(
            "net:api.openai.com",
            &allowed,
            &d
        ));
    }

    #[test]
    fn net_allowlist_rejects_prefix_spoof() {
        let d = dummy_file_read();
        let allowed = HashSet::from(["net:openai.com".to_string()]);
        assert!(!is_session_allowlist_match(
            "net:openai.com.attacker.tld",
            &allowed,
            &d
        ));
    }

    #[test]
    fn net_allowlist_matches_when_every_dns_candidate_is_trusted() {
        let call = ToolCallType::NetConnect {
            address: r#"["ab.chatgpt.com","chatgpt.com"]"#.into(),
            port: 443,
        };
        let allowed = HashSet::from(["net:chatgpt.com".to_string()]);

        assert!(is_session_allowlist_match(
            r#"net:["ab.chatgpt.com","chatgpt.com"]"#,
            &allowed,
            &call
        ));
    }

    #[test]
    fn net_allowlist_rejects_mixed_trust_dns_candidates() {
        let call = ToolCallType::NetConnect {
            address: r#"["chatgpt.com","untrusted.example"]"#.into(),
            port: 443,
        };
        let allowed = HashSet::from(["net:chatgpt.com".to_string()]);

        assert!(!is_session_allowlist_match(
            r#"net:["chatgpt.com","untrusted.example"]"#,
            &allowed,
            &call
        ));
    }

    #[test]
    fn net_allowlist_rejects_empty_or_malformed_dns_candidate_arrays() {
        let d = dummy_file_read();
        let allowed = HashSet::from(["net:chatgpt.com".to_string()]);

        assert!(!is_session_allowlist_match("net:[]", &allowed, &d));
        assert!(!is_session_allowlist_match(
            r#"net:["chatgpt.com""#,
            &allowed,
            &d
        ));
    }

    /// work/83 F5: giving `FileLink` a session-allowlist KEY must not turn an
    /// approved link into a stored GRANT. The key is a bare, un-namespaced
    /// path, so storing it would register a prefix covering every operation
    /// under the link path AND be persisted as a learned rule outliving the
    /// session — and it would say nothing about the target, which is the end
    /// that carries the authority.
    #[test]
    fn approved_link_stores_no_allowlist_grant() {
        let call = ToolCallType::FileLink {
            target: "/proj/target/debug/deps/x.o".into(),
            link_path: "/proj/target/debug/incremental/y.o".into(),
            symbolic: false,
        };
        assert!(
            approved_session_allowlist_entries(&call).is_empty(),
            "an approved link must not mint a prefix grant or a learned rule"
        );
        // The lookup key still exists — that is what project trust matches on.
        assert!(session_allowlist_key(&call).is_some());
    }

    #[test]
    fn approved_ambiguous_net_connect_expands_to_per_candidate_entries() {
        let call = ToolCallType::NetConnect {
            address: r#"["a.example.com","b.example.com"]"#.into(),
            port: 443,
        };
        assert_eq!(
            approved_session_allowlist_entries(&call),
            vec![
                "net:a.example.com".to_string(),
                "net:b.example.com".to_string()
            ]
        );
    }

    #[test]
    fn approved_single_host_net_connect_keeps_single_entry() {
        let call = ToolCallType::NetConnect {
            address: "api.example.com".into(),
            port: 443,
        };
        assert_eq!(
            approved_session_allowlist_entries(&call),
            vec!["net:api.example.com".to_string()]
        );
    }

    /// Regression: storing the array literal verbatim was a dead grant — the
    /// per-candidate matcher can never satisfy it, so every retried connect
    /// re-prompted even after an approval. Expanded entries must unlock the
    /// same ambiguous key the approval was granted for.
    #[test]
    fn approved_ambiguous_entries_unlock_subsequent_ambiguous_connects() {
        let call = ToolCallType::NetConnect {
            address: r#"["a.example.com","b.example.com"]"#.into(),
            port: 443,
        };
        let allowed: HashSet<String> = approved_session_allowlist_entries(&call)
            .into_iter()
            .collect();
        let key = session_allowlist_key(&call).expect("net key");
        assert!(is_session_allowlist_match(&key, &allowed, &call));
    }

    #[test]
    fn dns_allowlist_matches_via_net_entries() {
        let d = dummy_file_read();
        let allowed = HashSet::from([
            "net:anthropic.com".to_string(),
            "net:googleapis.com".to_string(),
        ]);
        assert!(is_session_allowlist_match(
            "dns:anthropic.com",
            &allowed,
            &d
        ));
        assert!(is_session_allowlist_match(
            "dns:api.anthropic.com",
            &allowed,
            &d
        ));
        assert!(is_session_allowlist_match(
            "dns:mcp-proxy.anthropic.com",
            &allowed,
            &d
        ));
        assert!(is_session_allowlist_match(
            "dns:storage.googleapis.com",
            &allowed,
            &d
        ));
        assert!(!is_session_allowlist_match("dns:evil.com", &allowed, &d));
        assert!(!is_session_allowlist_match(
            "dns:anthropic.com.evil.com",
            &allowed,
            &d
        ));
    }

    #[test]
    fn path_allowlist_still_uses_prefix_matching() {
        let d = dummy_file_read();
        let allowed = HashSet::from(["/home/user/project".to_string()]);
        assert!(is_session_allowlist_match(
            "/home/user/project/src/main.rs",
            &allowed,
            &d
        ));
    }

    #[test]
    fn exec_allowlist_requires_exact_match() {
        let d = dummy_file_read();
        let allowed = HashSet::from(["exec:/usr/bin/docker".to_string()]);
        assert!(is_session_allowlist_match(
            "exec:/usr/bin/docker",
            &allowed,
            &d
        ));
        assert!(!is_session_allowlist_match(
            "exec:/tmp/docker",
            &allowed,
            &d
        ));
        assert!(!is_session_allowlist_match(
            "exec:/usr/bin/docker-malicious",
            &allowed,
            &d
        ));
    }

    #[test]
    fn exec_allowlist_does_not_match_by_basename() {
        let d = dummy_file_read();
        let allowed = HashSet::from(["exec:docker".to_string()]);
        assert!(!is_session_allowlist_match("exec:docker", &allowed, &d));
        assert!(!is_session_allowlist_match(
            "exec:/tmp/docker",
            &allowed,
            &d
        ));
    }

    // -- Sensitive Unix socket detection ------------------------------------------

    #[test]
    fn sensitive_unix_sockets_are_not_local() {
        // Each of these paths must NOT be silently allowed.
        let sensitive = [
            "unix:/var/run/docker.sock",
            "unix:/run/docker.sock",
            "unix:/var/run/containerd/containerd.sock",
            "unix:/run/containerd/containerd.sock",
            "unix:/var/run/crio/crio.sock",
            "unix:/run/crio/crio.sock",
            "unix:/var/run/podman/podman.sock",
            // Wildcard: user-session Podman socket for an arbitrary UID.
            "unix:/run/user/1000/podman/podman.sock",
        ];
        for addr in &sensitive {
            assert!(
                !is_local_connect_address(addr),
                "{addr} should NOT be treated as local-only"
            );
        }
    }

    #[test]
    fn non_sensitive_unix_sockets_are_local() {
        // These are benign IPC sockets that should still be silently allowed.
        let benign = [
            "unix:/tmp/dbus-abc123",
            "unix:/run/user/1000/bus",
            "unix:/var/run/nscd/socket",
            "unix:/run/systemd/journal/stdout",
            // Abstract-namespace socket (empty path component).
            "unix:",
        ];
        for addr in &benign {
            assert!(
                is_local_connect_address(addr),
                "{addr} should be treated as local-only"
            );
        }
    }

    #[test]
    fn classify_unix_socket_two_class_whitelist() {
        use grith_proxy::types::UnixSocketClass::{Control, Privileged};
        // Privileged: daemon control sockets, pathname and abstract render.
        // An abstract name mimicking a sensitive path classifies Privileged
        // (over-scoring an impostor is the fail-safe direction).
        assert_eq!(
            classify_unix_socket("unix:/var/run/docker.sock"),
            Some(Privileged)
        );
        assert_eq!(
            classify_unix_socket("unix:@/var/run/docker.sock"),
            Some(Privileged)
        );
        assert_eq!(
            classify_unix_socket("unix:/run/user/1000/systemd/private"),
            Some(Privileged)
        );
        // Control: desktop control-injection IPC.
        assert_eq!(
            classify_unix_socket("unix:/run/user/1000/bus"),
            Some(Control)
        );
        assert_eq!(
            classify_unix_socket("unix:@/tmp/.X11-unix/X1"),
            Some(Control)
        );
        assert_eq!(
            classify_unix_socket("unix:/tmp/tmux-1000/default"),
            Some(Control)
        );
        // Whitelist: anything else — plain unix sockets, the empty
        // unnamed/autobind render, non-unix addresses — carries no label
        // and keeps pre-classification scoring.
        assert_eq!(classify_unix_socket("unix:/run/user/1000/app.sock"), None);
        assert_eq!(classify_unix_socket("unix:"), None);
        assert_eq!(classify_unix_socket("unix:@"), None);
        assert_eq!(classify_unix_socket("192.0.2.1"), None);
        assert_eq!(classify_unix_socket("example.com"), None);
    }

    /// The grant key binds (socket address, client exe). Own pid resolves
    /// the test binary's exe; control sockets mint, privileged and
    /// unclassified sockets and dead pids never do.
    #[test]
    fn ipc_socket_grant_key_binds_socket_and_exe() {
        let pid = u64::from(std::process::id());
        let own_exe = std::fs::read_link("/proc/self/exe").unwrap();
        let own_exe = own_exe.to_str().unwrap();

        let key = ipc_socket_grant_key_parts("unix:/run/user/1000/bus", pid)
            .expect("control socket + live pid must mint");
        assert_eq!(key, format!("ipc-socket:unix:/run/user/1000/bus|{own_exe}"));

        let abstract_key = ipc_socket_grant_key_parts("unix:@/tmp/.X11-unix/X1", pid)
            .expect("abstract control socket must mint");
        assert!(abstract_key.starts_with("ipc-socket:unix:@/tmp/.X11-unix/X1|"));

        // Privileged, unclassified, and non-unix addresses never mint.
        assert_eq!(
            ipc_socket_grant_key_parts("unix:/var/run/docker.sock", pid),
            None
        );
        assert_eq!(
            ipc_socket_grant_key_parts("unix:/run/user/1000/systemd/private", pid),
            None
        );
        assert_eq!(ipc_socket_grant_key_parts("unix:/tmp/app.sock", pid), None);
        assert_eq!(ipc_socket_grant_key_parts("192.0.2.1", pid), None);

        // A pid whose /proc entry cannot be read fails toward no grant.
        assert_eq!(
            ipc_socket_grant_key_parts("unix:/run/user/1000/bus", u64::MAX),
            None
        );
    }

    #[test]
    fn sensitive_unix_socket_helper_matches_all_known_paths() {
        // Direct unit test of the helper independent of the address format.
        assert!(is_sensitive_unix_socket("/var/run/docker.sock"));
        assert!(is_sensitive_unix_socket("/run/docker.sock"));
        assert!(is_sensitive_unix_socket(
            "/var/run/containerd/containerd.sock"
        ));
        assert!(is_sensitive_unix_socket("/run/containerd/containerd.sock"));
        assert!(is_sensitive_unix_socket("/var/run/crio/crio.sock"));
        assert!(is_sensitive_unix_socket("/run/crio/crio.sock"));
        assert!(is_sensitive_unix_socket("/var/run/podman/podman.sock"));
        // Wildcard match via contains("podman.sock").
        assert!(is_sensitive_unix_socket(
            "/run/user/1000/podman/podman.sock"
        ));
        assert!(is_sensitive_unix_socket("/run/user/42/podman/podman.sock"));
    }

    /// Curated root/host-daemon control sockets must reach the proxy (QUEUE),
    /// and — critically — the high-frequency benign sockets must STAY local.
    #[test]
    fn root_daemon_control_sockets_are_sensitive_but_benign_stay_local() {
        // RCE-capable daemon control sockets → sensitive (route to proxy).
        for p in [
            "/run/libvirt/libvirt-sock",
            "/var/run/libvirt/virtqemud-sock",
            "/run/user/1000/libvirt/virtqemud-sock",
            "/run/libvirt/virtnetworkd-sock",
            "/run/libvirt/virtstoraged-sock",
            "/run/systemd/private",
            "/run/user/1000/systemd/private",
            "/run/systemd/io.systemd.Manager",
            "/run/podman/io.podman",
            "/run/user/1000/podman/io.podman",
            "/run/containerd/containerd.sock",
            "/run/user/1000/containerd/containerd.sock",
            "/run/buildkit/buildkitd.sock",
            "/run/cups/cups.sock",
            "/var/run/cups/cups.sock",
            "/var/lib/lxc/mybox/command",
            "/run/lxc/lock",
        ] {
            assert!(is_sensitive_unix_socket(p), "{p:?} should be sensitive");
        }
        // Benign high-frequency local IPC MUST stay local (no QUEUE storm).
        for p in [
            "/run/systemd/journal/socket",
            "/run/systemd/journal/stdout",
            // nss-resolve name resolution — MUST stay local (the key FP guard).
            "/run/systemd/resolve/io.systemd.Resolve",
            "/run/user/1000/bus",
            "/run/dbus/system_bus_socket",
            "/tmp/.X11-unix/X0",
            "/run/user/1000/pulse/native",
            "/run/user/1000/pipewire-0",
            "/run/nscd/socket",
            "/var/run/nscd/socket",
            // Read-only libvirt is info-only, cannot define a domain.
            "/run/libvirt/libvirt-sock-ro",
            // CUPS is anchored to the socket file; other /run/cups/ paths stay local.
            "/run/cups/notify.log",
            "", // abstract-namespace socket renders empty
        ] {
            assert!(!is_sensitive_unix_socket(p), "{p:?} must stay local");
        }
    }

    // Protection suite (research doc §5.1 #13): SSH/GPG agent sockets are
    // credential-use primitives and must NOT be silently allowed as local IPC.
    // Their paths are dynamic, so they match by shape.
    #[test]
    fn ssh_and_gpg_agent_sockets_are_sensitive_and_not_local() {
        let agent_sockets = [
            "/tmp/ssh-XlK2aB/agent.12345",          // OpenSSH ssh-agent
            "/run/user/1000/keyring/ssh",           // gnome-keyring ssh agent
            "/run/user/1000/gnupg/S.gpg-agent",     // gpg-agent
            "/run/user/1000/gnupg/S.gpg-agent.ssh", // gpg-agent ssh emulation
            "/home/u/.gnupg/S.gpg-agent",
            "/run/user/1000/ssh-agent.socket", // systemd user ssh-agent
        ];
        for s in &agent_sockets {
            assert!(
                is_sensitive_unix_socket(s),
                "{s} must be treated as a sensitive socket"
            );
            assert!(
                !is_local_connect_address(&format!("unix:{s}")),
                "{s} must NOT be silently allowed as local-only"
            );
        }
    }

    // FP research §5.1 — routine git/ssh/gpg use of the agent socket is local IPC
    // and must be carved out (else every credentialed git-over-SSH push / GPG-
    // signed commit QUEUEs), while a NON-client process touching the agent socket
    // stays sensitive (the paired guard — the exfil channel is the separately-
    // scored remote connection).
    #[test]
    fn agent_client_carveout_requires_client_name_and_routine_root() {
        // Pure two-part policy (FP §5.1, hardened after adversarial review):
        // the carveout requires BOTH a known agent-client basename AND a
        // canonical path under a routine exec root — mirroring namespace_users.
        let roots = vec!["/usr/bin".to_string(), "/usr/lib/ssh".to_string()];

        // (1) client name + under a routine root → carved out (routine IPC).
        assert!(exe_is_agent_client_in_routine_root("/usr/bin/ssh", &roots));
        assert!(exe_is_agent_client_in_routine_root("/usr/bin/git", &roots));
        assert!(exe_is_agent_client_in_routine_root(
            "/usr/lib/ssh/ssh",
            &roots
        ));

        // (2) THE HOLE the review caught: a client-NAMED binary dropped OUTSIDE
        // any routine root (`cp /bin/sh /tmp/git && /tmp/git …`) must NOT be
        // carved out. This is the whole point of the two-part gate.
        assert!(
            !exe_is_agent_client_in_routine_root("/tmp/git", &roots),
            "client-named binary outside a routine root must NOT be carved out"
        );
        assert!(!exe_is_agent_client_in_routine_root(
            "/home/u/.local/bin/ssh",
            &roots
        ));

        // (3) non-client binary, even under a routine root → not carved.
        assert!(!exe_is_agent_client_in_routine_root(
            "/usr/bin/python3",
            &roots
        ));
        assert!(!exe_is_agent_client_in_routine_root(
            "/usr/bin/curl",
            &roots
        ));

        // (4) empty roots → nothing carved (default-deny).
        assert!(!exe_is_agent_client_in_routine_root("/usr/bin/ssh", &[]));

        // (5) prefix boundary: /usr/bin must not match /usr/binary-evil/ssh.
        assert!(!exe_is_agent_client_in_routine_root(
            "/usr/binary-evil/ssh",
            &roots
        ));
    }

    #[test]
    fn daemon_restart_state_is_per_outage_not_per_session() {
        let state = DaemonRestartState::new(DaemonRestartConfig {
            executable: std::path::PathBuf::from("/usr/bin/true"),
            config_path: None,
            token_path: std::path::PathBuf::from("/nonexistent/token"),
        });

        // First failure in an outage wins the attempt; an immediate second
        // failure is inside the cooldown and must not stack restarts.
        assert!(state.take_attempt());
        assert!(!state.take_attempt());

        // A healthy evaluation re-arms the budget, so the NEXT outage gets an
        // immediate attempt instead of being locked out for the session.
        state.note_success();
        assert!(state.take_attempt());
    }

    #[test]
    fn auth_rejection_is_distinguished_from_unreachable() {
        assert!(RemoteEvalError::AuthRejected {
            status: 403,
            body: "Invalid IPC token".into(),
        }
        .is_auth_rejection());
        assert!(RemoteEvalError::AuthRejected {
            status: 401,
            body: String::new(),
        }
        .is_auth_rejection());
        assert!(!RemoteEvalError::Transport("connection refused".into()).is_auth_rejection());
        assert!(!RemoteEvalError::HttpStatus {
            status: 500,
            body: "Internal Server Error".into(),
        }
        .is_auth_rejection());
    }

    #[test]
    fn reload_rotated_token_adopts_only_a_changed_token() {
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("daemon.token");
        let config = DaemonRestartConfig {
            executable: std::path::PathBuf::from("/usr/bin/true"),
            config_path: None,
            token_path: token_path.clone(),
        };
        let shared = Arc::new(Mutex::new("stale".to_string()));

        // Missing file: nothing to reload.
        assert_eq!(reload_rotated_token(&config, &shared, "stale"), None);

        // Disk still holds the token the daemon just rejected: a retry with
        // it cannot succeed, so nothing is adopted.
        std::fs::write(&token_path, "stale\n").unwrap();
        assert_eq!(reload_rotated_token(&config, &shared, "stale"), None);
        assert_eq!(*shared.lock().unwrap(), "stale");

        // Rotated token on disk: adopted into the shared slot (healing the
        // DNS decision service and any other holder) and returned for retry.
        std::fs::write(&token_path, "fresh\n").unwrap();
        assert_eq!(
            reload_rotated_token(&config, &shared, "stale"),
            Some("fresh".to_string())
        );
        assert_eq!(*shared.lock().unwrap(), "fresh");
    }

    #[test]
    fn dns_infrastructure_events_are_rate_limited() {
        assert!(dns_infrastructure_event_permitted());
        assert!(!dns_infrastructure_event_permitted());
    }

    #[tokio::test]
    async fn forward_confirm_recovers_attribution_miss_and_rate_limits() {
        use crate::dns_cache::{DnsCache, DnsForwardConfirm, Resolution};

        // localhost resolves via /etc/hosts — the same offline-safe precedent
        // as dns_cache::tests::forward_cache_seed_and_lookup.
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let confirm = DnsForwardConfirm::new(vec!["localhost".to_string()]).unwrap();

        // No confirm state configured → the miss passes through untouched.
        let miss = Resolution::Unknown("127.0.0.1".parse().unwrap());
        let (resolution, via) =
            confirm_forward_attribution(&cache, None, "127.0.0.1", miss.clone()).await;
        assert!(!via);
        assert_eq!(resolution, miss);

        // A live confirm re-resolves and recovers the attribution.
        let (resolution, via) =
            confirm_forward_attribution(&cache, Some(&confirm), "127.0.0.1", miss).await;
        assert!(via);
        assert_eq!(resolution, Resolution::Exact("localhost".into()));

        // A second miss inside the cooldown window is not allowed to spend
        // another resolve; it keeps its miss.
        let second = Resolution::Unknown("192.0.2.9".parse().unwrap());
        let (resolution, via) =
            confirm_forward_attribution(&cache, Some(&confirm), "192.0.2.9", second.clone()).await;
        assert!(!via);
        assert_eq!(resolution, second);
    }

    #[test]
    fn connect_carveout_rejects_non_agent_addresses_and_non_clients() {
        // A permissive root to isolate the address/identity checks from the
        // routine-root check.
        let roots = vec!["/".to_string()];
        let self_pid = std::process::id();

        // Non-unix address → never an agent carveout (no /proc resolution).
        assert!(!connect_is_routine_agent_use(
            "93.184.216.34",
            self_pid,
            &roots
        ));
        // Non-agent unix socket → not a carveout even with a permissive root.
        assert!(!connect_is_routine_agent_use(
            "unix:/tmp/x.sock",
            self_pid,
            &roots
        ));
        // Real agent socket + this test's REAL pid: /proc/self/exe resolves to
        // the test binary, whose basename is not an agent client → NOT carved.
        // Exercises the live /proc resolution path and confirms it rejects a
        // non-client real binary.
        assert!(
            !connect_is_routine_agent_use(
                "unix:/run/user/1000/gnupg/S.gpg-agent",
                self_pid,
                &roots
            ),
            "the test binary is not an agent client; a real-pid resolve must reject"
        );
    }

    #[test]
    fn sensitive_unix_socket_helper_does_not_match_benign_paths() {
        assert!(!is_sensitive_unix_socket("/tmp/dbus-abc123"));
        assert!(!is_sensitive_unix_socket("/run/user/1000/bus"));
        assert!(!is_sensitive_unix_socket("/var/run/nscd/socket"));
        assert!(!is_sensitive_unix_socket(""));
    }

    // -- Local address checks (existing behaviour) --------------------------------

    #[test]
    fn local_connect_allows_loopback_and_unspecified() {
        assert!(is_local_connect_address("127.0.0.1"));
        assert!(is_local_connect_address("::1"));
        assert!(is_local_connect_address("0.0.0.0"));
        assert!(is_local_connect_address("::"));
        assert!(is_local_connect_address("localhost"));
    }

    #[test]
    fn local_listen_only_allows_loopback() {
        assert!(is_local_listen_address("127.0.0.1"));
        assert!(is_local_listen_address("::1"));
        assert!(is_local_listen_address("localhost"));
        assert!(!is_local_listen_address("0.0.0.0"));
        assert!(!is_local_listen_address("::"));
        assert!(!is_local_listen_address("192.168.1.10"));
    }

    /// PR 3 Phase B: a nonexistent absolute path is reported missing.
    #[test]
    fn exec_path_clearly_missing_for_nonexistent_absolute() {
        assert!(exec_path_clearly_missing(
            "/this/path/almost/certainly/does/not/exist/xyz123"
        ));
    }

    /// PR 3 Phase B: an existing absolute path is NOT reported missing.
    #[test]
    fn exec_path_clearly_missing_for_existing_absolute() {
        // /bin/sh is on essentially every Unix.
        assert!(!exec_path_clearly_missing("/bin/sh"));
    }

    /// PR 3 Phase B: a bare command name walks `$PATH`. A name that
    /// won't be on PATH on any sane CI machine is reported missing.
    #[test]
    fn exec_path_clearly_missing_for_unknown_bare_name() {
        assert!(exec_path_clearly_missing(
            "grith-bare-name-that-cannot-exist-xyz123"
        ));
    }

    /// PR 3 Phase B: an empty command is NOT reported missing (defensive
    /// — the supervisor should never produce an empty command, but if it
    /// somehow did, we want the normal Queue flow to handle it).
    #[test]
    fn exec_path_clearly_missing_empty_command() {
        assert!(!exec_path_clearly_missing(""));
    }

    // PR 3 Phase C: loopback-address parsing and listener detection.

    #[test]
    fn loopback_address_detection() {
        assert!(is_loopback_connect_address("127.0.0.1"));
        assert!(is_loopback_connect_address("127.0.0.5"));
        assert!(is_loopback_connect_address("::1"));
        assert!(is_loopback_connect_address("localhost"));
        assert!(!is_loopback_connect_address("0.0.0.0"));
        assert!(!is_loopback_connect_address("192.168.1.10"));
        assert!(!is_loopback_connect_address("::"));
        assert!(!is_loopback_connect_address("example.com"));
        assert!(!is_loopback_connect_address(""));
    }

    #[test]
    fn ambiguous_dns_candidates_render_as_name_array() {
        let address = format_dns_candidate_array(&["ab.chatgpt.com".into(), "chatgpt.com".into()]);
        assert_eq!(address, r#"["ab.chatgpt.com","chatgpt.com"]"#);

        let call = ToolCallType::NetConnect { address, port: 443 };
        assert_eq!(
            call.to_string(),
            r#"NetConnect(["ab.chatgpt.com","chatgpt.com"]:443)"#
        );
    }

    /// PR 3 Phase C: a port that almost certainly has no listener
    /// returns false. We pick a high random port (65500) that's
    /// unlikely to be in use on any test machine.
    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_unused_port_has_no_listener() {
        assert!(!loopback_port_has_listener(65500));
    }

    /// PR 3 Phase C: the function must return a value without
    /// panicking even when /proc/net/tcp is unreadable (non-Linux
    /// stub returns false unconditionally).
    #[test]
    fn loopback_listener_check_does_not_panic() {
        let _ = loopback_port_has_listener(80);
        let _ = loopback_port_has_listener(0);
        let _ = loopback_port_has_listener(65535);
    }

    #[tokio::test]
    async fn io_uring_is_denied_before_proxy_evaluation() {
        let pid = 4242;
        let (mock, state) = MockInterceptor::new(vec![sample_io_uring_event(pid, 425)]);
        let mut interceptor: Box<dyn SyscallInterceptor> = Box::new(mock);
        let mut session = SupervisorSession::new("mock-tool", pid);
        let proxy = allow_only_proxy();
        let audit_storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let audit_sink: Arc<dyn crate::audit_sink::AuditSink> =
            Arc::new(crate::audit_sink::StorageAuditSink::new(audit_storage));
        let digest_queue = Arc::new(grith_digest::queue::DigestQueue::open_in_memory().unwrap());
        let digest_store: Arc<dyn crate::reviewer::DigestStore> =
            Arc::new(crate::reviewer::LocalDigestStore::new(digest_queue));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let containment_tracker = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::new(
                Duration::from_secs(60),
            ),
        );
        let config = SupervisorConfig::default();
        let loop_ctx = SupervisorLoopContext {
            proxy: &proxy,
            audit_sink,
            digest_store,
            dlp_redactor: &dlp_redactor,
            correlation_tracker: &correlation_tracker,
            containment_tracker: &containment_tracker,
            config: &config,
            event_tx: None,
            freezer: Freezer::new(Duration::from_secs(config.freeze_timeout_seconds)),
            read_batch_tracker: Mutex::new(ReadBatchTracker::new(10)),
            reviewer: Arc::new(PanicReviewer),
            unanswered_reviews: Arc::new(AtomicU32::new(0)),
            session_sync: None,
            session_allowed: Arc::new(Mutex::new(HashSet::new())),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_inspection_enabled: false,
            dns_decision_service: None,
            dns_forward_confirm: None,
            syscall_log: None,
            forensics_trace: None,
            reputation_table: Arc::new(Mutex::new(grith_proxy::reputation::ReputationTable::new())),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            daemon_restart: None,
            observation_outbox: Arc::new(Default::default()),
            persist_local_reputation: true,
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            workspace_roots: Vec::new(),
            session_denied: Arc::new(Mutex::new(HashSet::new())),
            workspace_boundary: None,
            local_listener_policy: Vec::new(),
            namespace_users: Vec::new(),
            permit_authority_delegating: Vec::new(),
            permit_control_sockets: Vec::new(),
            dbus_inspection_armed: false,
            authority_delegating_pins: authority_delegation::AuthorityDelegatingPins::empty(),
            working_root: None,
            mass_destruction: Mutex::new(mass_destruction::MassDestructionTracker::with_defaults()),
            yama_ptrace_scope: None,
            analytics_config: std::sync::OnceLock::new(),
        };

        let event = sample_io_uring_event(pid, crate::platform::linux::syscall_nr::IO_URING_SETUP);
        handle_syscall_event(&mut interceptor, &mut session, &loop_ctx, event)
            .await
            .unwrap();

        let state = state.lock().unwrap();
        assert_eq!(state.deny_pids, vec![pid]);
        assert!(state.allow_pids.is_empty());
        assert_eq!(session.stats.total_queued, 0);
        assert_eq!(session.stats.total_denied, 0);
    }

    /// Provenance backfill: the first non-exec syscall from a process with no
    /// prior spawn record gets exactly one synthesized `ProcessSpawn` audit
    /// record; repeats from the same TGID do not; and a process whose first
    /// event IS a real exec is not double-tagged as synthesized.
    #[tokio::test]
    async fn untagged_process_gets_one_synthesized_spawn_provenance() {
        let read_pid = 4242; // in-process / missed-exec actor: first event is a read
        let exec_pid = 4243; // normal actor: first event is a real exec

        let (mock, _state) = MockInterceptor::new(vec![]);
        let mut interceptor: Box<dyn SyscallInterceptor> = Box::new(mock);
        let mut session = SupervisorSession::new("mock-tool", read_pid);
        let proxy = allow_only_proxy();
        let audit_storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let audit_sink: Arc<dyn crate::audit_sink::AuditSink> = Arc::new(
            crate::audit_sink::StorageAuditSink::new(audit_storage.clone()),
        );
        let digest_queue = Arc::new(grith_digest::queue::DigestQueue::open_in_memory().unwrap());
        let digest_store: Arc<dyn crate::reviewer::DigestStore> =
            Arc::new(crate::reviewer::LocalDigestStore::new(digest_queue));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let containment_tracker = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::new(
                Duration::from_secs(60),
            ),
        );
        let config = SupervisorConfig::default();
        let loop_ctx = SupervisorLoopContext {
            proxy: &proxy,
            audit_sink,
            digest_store,
            dlp_redactor: &dlp_redactor,
            correlation_tracker: &correlation_tracker,
            containment_tracker: &containment_tracker,
            config: &config,
            event_tx: None,
            freezer: Freezer::new(Duration::from_secs(config.freeze_timeout_seconds)),
            read_batch_tracker: Mutex::new(ReadBatchTracker::new(10)),
            reviewer: Arc::new(PanicReviewer),
            unanswered_reviews: Arc::new(AtomicU32::new(0)),
            session_sync: None,
            session_allowed: Arc::new(Mutex::new(HashSet::new())),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_inspection_enabled: false,
            dns_decision_service: None,
            dns_forward_confirm: None,
            syscall_log: None,
            forensics_trace: None,
            reputation_table: Arc::new(Mutex::new(grith_proxy::reputation::ReputationTable::new())),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            daemon_restart: None,
            observation_outbox: Arc::new(Default::default()),
            persist_local_reputation: true,
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            workspace_roots: Vec::new(),
            session_denied: Arc::new(Mutex::new(HashSet::new())),
            workspace_boundary: None,
            local_listener_policy: Vec::new(),
            namespace_users: Vec::new(),
            permit_authority_delegating: Vec::new(),
            permit_control_sockets: Vec::new(),
            dbus_inspection_armed: false,
            authority_delegating_pins: authority_delegation::AuthorityDelegatingPins::empty(),
            working_root: None,
            mass_destruction: Mutex::new(mass_destruction::MassDestructionTracker::with_defaults()),
            yama_ptrace_scope: None,
            analytics_config: std::sync::OnceLock::new(),
        };

        let read_event = |pid: u32| SyscallEvent {
            pid,
            tid: pid,
            timestamp: Utc::now(),
            kind: SyscallKind::FileRead {
                fd: 7,
                path: Some("/etc/hostname".into()),
            },
            raw_syscall_nr: 0,
        };
        let exec_event = |pid: u32| SyscallEvent {
            pid,
            tid: pid,
            timestamp: Utc::now(),
            kind: SyscallKind::ProcessExec {
                path: "/bin/true".into(),
                args: vec!["/bin/true".into()],
            },
            raw_syscall_nr: crate::platform::linux::syscall_nr::EXECVE,
        };

        // The sink writes on a background thread, so read back the synthesized
        // rows for a session with a short poll for the flush.
        let synthesized_rows = |session_id: Uuid| {
            let storage = audit_storage.clone();
            async move {
                for _ in 0..200 {
                    let rows: Vec<_> = storage
                        .lock()
                        .unwrap()
                        .get_by_session(&session_id)
                        .unwrap()
                        .into_iter()
                        .filter(|r| {
                            r.tool_call_type.starts_with("ProcessSpawn(")
                                && r.arguments_summary.contains("synthesized_spawn_provenance")
                        })
                        .collect();
                    if !rows.is_empty() {
                        return rows;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Vec::new()
            }
        };

        // First read from an untagged actor → one synthesized provenance row.
        handle_syscall_event(
            &mut interceptor,
            &mut session,
            &loop_ctx,
            read_event(read_pid),
        )
        .await
        .unwrap();
        assert!(session.spawn_recorded.contains(&read_pid));
        let rows = synthesized_rows(session.id).await;
        assert_eq!(rows.len(), 1, "exactly one synthesized provenance row");
        assert_eq!(rows[0].supervised_pid, Some(read_pid));

        // Second read from the same TGID → no new provenance row (deduped).
        handle_syscall_event(
            &mut interceptor,
            &mut session,
            &loop_ctx,
            read_event(read_pid),
        )
        .await
        .unwrap();
        // A process whose FIRST event is a real exec must NOT be synthesized —
        // the normal exec path already tags it.
        handle_syscall_event(
            &mut interceptor,
            &mut session,
            &loop_ctx,
            exec_event(exec_pid),
        )
        .await
        .unwrap();
        assert!(session.spawn_recorded.contains(&exec_pid));
        // Let any erroneous extra writes flush, then confirm still exactly one.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let rows = synthesized_rows(session.id).await;
        assert_eq!(
            rows.len(),
            1,
            "provenance emitted at most once per process, and never for the real-exec actor"
        );
        assert_eq!(rows[0].supervised_pid, Some(read_pid));
    }

    // ---- PR 6 Phase A: category-1 hard-deny tests ----
    //
    // Each test asserts that an attempt to call the syscall is denied
    // BEFORE proxy evaluation reaches it. Mirrors the io_uring test
    // above.

    fn sample_phase_a_event(pid: u32, raw_syscall_nr: i64, kind: SyscallKind) -> SyscallEvent {
        SyscallEvent {
            pid,
            tid: pid,
            timestamp: Utc::now(),
            kind,
            raw_syscall_nr,
        }
    }

    async fn assert_event_denied(event: SyscallEvent) {
        let pid = event.pid;
        let (mock, state) = MockInterceptor::new(vec![event.clone()]);
        let mut interceptor: Box<dyn SyscallInterceptor> = Box::new(mock);
        let mut session = SupervisorSession::new("mock-tool", pid);
        let proxy = allow_only_proxy();
        let audit_storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let audit_sink: Arc<dyn crate::audit_sink::AuditSink> =
            Arc::new(crate::audit_sink::StorageAuditSink::new(audit_storage));
        let digest_queue = Arc::new(grith_digest::queue::DigestQueue::open_in_memory().unwrap());
        let digest_store: Arc<dyn crate::reviewer::DigestStore> =
            Arc::new(crate::reviewer::LocalDigestStore::new(digest_queue));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let containment_tracker = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::new(
                Duration::from_secs(60),
            ),
        );
        let config = SupervisorConfig::default();
        let loop_ctx = SupervisorLoopContext {
            proxy: &proxy,
            audit_sink,
            digest_store,
            dlp_redactor: &dlp_redactor,
            correlation_tracker: &correlation_tracker,
            containment_tracker: &containment_tracker,
            config: &config,
            event_tx: None,
            freezer: Freezer::new(Duration::from_secs(config.freeze_timeout_seconds)),
            read_batch_tracker: Mutex::new(ReadBatchTracker::new(10)),
            reviewer: Arc::new(PanicReviewer),
            unanswered_reviews: Arc::new(AtomicU32::new(0)),
            session_sync: None,
            session_allowed: Arc::new(Mutex::new(HashSet::new())),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_inspection_enabled: false,
            dns_decision_service: None,
            dns_forward_confirm: None,
            syscall_log: None,
            forensics_trace: None,
            reputation_table: Arc::new(Mutex::new(grith_proxy::reputation::ReputationTable::new())),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            daemon_restart: None,
            observation_outbox: Arc::new(Default::default()),
            persist_local_reputation: true,
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            workspace_roots: Vec::new(),
            session_denied: Arc::new(Mutex::new(HashSet::new())),
            workspace_boundary: None,
            local_listener_policy: Vec::new(),
            namespace_users: Vec::new(),
            permit_authority_delegating: Vec::new(),
            permit_control_sockets: Vec::new(),
            dbus_inspection_armed: false,
            authority_delegating_pins: authority_delegation::AuthorityDelegatingPins::empty(),
            working_root: None,
            mass_destruction: Mutex::new(mass_destruction::MassDestructionTracker::with_defaults()),
            yama_ptrace_scope: None,
            analytics_config: std::sync::OnceLock::new(),
        };

        handle_syscall_event(&mut interceptor, &mut session, &loop_ctx, event)
            .await
            .unwrap();

        let state = state.lock().unwrap();
        assert_eq!(state.deny_pids, vec![pid], "expected deny");
        assert!(state.allow_pids.is_empty(), "must not allow");
    }

    #[tokio::test]
    async fn phase_a_init_module_is_denied_before_proxy_evaluation() {
        assert_event_denied(sample_phase_a_event(
            5001,
            crate::platform::linux::syscall_nr::INIT_MODULE,
            SyscallKind::KernelModuleOp {
                op: crate::interceptor::KernelModuleOpKind::Init,
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn phase_a_finit_module_is_denied() {
        assert_event_denied(sample_phase_a_event(
            5002,
            crate::platform::linux::syscall_nr::FINIT_MODULE,
            SyscallKind::KernelModuleOp {
                op: crate::interceptor::KernelModuleOpKind::Finit,
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn phase_a_delete_module_is_denied() {
        assert_event_denied(sample_phase_a_event(
            5003,
            crate::platform::linux::syscall_nr::DELETE_MODULE,
            SyscallKind::KernelModuleOp {
                op: crate::interceptor::KernelModuleOpKind::Delete,
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn phase_a_kexec_load_is_denied() {
        assert_event_denied(sample_phase_a_event(
            5004,
            crate::platform::linux::syscall_nr::KEXEC_LOAD,
            SyscallKind::KexecLoad { from_fd: false },
        ))
        .await;
    }

    #[tokio::test]
    async fn phase_a_kexec_file_load_is_denied() {
        assert_event_denied(sample_phase_a_event(
            5005,
            crate::platform::linux::syscall_nr::KEXEC_FILE_LOAD,
            SyscallKind::KexecLoad { from_fd: true },
        ))
        .await;
    }

    // ---- B1: foreign-ABI hard-deny tests ----

    #[tokio::test]
    async fn foreign_compat_arch_syscall_is_denied() {
        // i386 open(5) via int 0x80 — the raw number must never be
        // interpreted through the x86_64 table (5 = fstat there).
        assert_event_denied(sample_phase_a_event(
            5006,
            5,
            SyscallKind::ForeignAbiSyscall {
                abi: crate::interceptor::ForeignAbiKind::CompatArch,
                raw_nr: 5,
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn foreign_x32_syscall_is_denied() {
        let raw_nr = crate::platform::linux::syscall_nr::OPENAT | 0x4000_0000;
        assert_event_denied(sample_phase_a_event(
            5007,
            raw_nr,
            SyscallKind::ForeignAbiSyscall {
                abi: crate::interceptor::ForeignAbiKind::X32,
                raw_nr,
            },
        ))
        .await;
    }

    // ---- PR 6 Phase D: arch-privileged hard-deny tests ----

    #[tokio::test]
    async fn phase_d_sethostname_is_denied() {
        assert_event_denied(sample_phase_a_event(
            6001,
            crate::platform::linux::syscall_nr::SETHOSTNAME,
            SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::SetHostname,
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn phase_d_setdomainname_is_denied() {
        assert_event_denied(sample_phase_a_event(
            6002,
            crate::platform::linux::syscall_nr::SETDOMAINNAME,
            SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::SetDomainName,
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn phase_d_iopl_is_denied() {
        assert_event_denied(sample_phase_a_event(
            6003,
            crate::platform::linux::arch::x86_64::syscall_nr::IOPL,
            SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::Iopl,
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn phase_d_ioperm_is_denied() {
        assert_event_denied(sample_phase_a_event(
            6004,
            crate::platform::linux::arch::x86_64::syscall_nr::IOPERM,
            SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::Ioperm,
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn phase_d_swapon_is_denied() {
        assert_event_denied(sample_phase_a_event(
            6005,
            crate::platform::linux::syscall_nr::SWAPON,
            SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::Swapon,
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn phase_d_swapoff_is_denied() {
        assert_event_denied(sample_phase_a_event(
            6006,
            crate::platform::linux::syscall_nr::SWAPOFF,
            SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::Swapoff,
            },
        ))
        .await;
    }

    #[tokio::test]
    async fn phase_d_reboot_is_denied() {
        assert_event_denied(sample_phase_a_event(
            6007,
            crate::platform::linux::syscall_nr::REBOOT,
            SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::Reboot,
            },
        ))
        .await;
    }

    // ---- PR 6 Phase F: feature-flag gating tests ----
    //
    // When a category flag is OFF, the corresponding syscalls must
    // fall through as "not security-relevant" — silent allow,
    // matching pre-PR-6 behaviour. This exercises the gate at the
    // top of handle_syscall_event.

    async fn assert_event_allowed_with_coverage(
        event: SyscallEvent,
        coverage: crate::config::CoverageConfig,
    ) {
        let pid = event.pid;
        let (mock, state) = MockInterceptor::new(vec![event.clone()]);
        let mut interceptor: Box<dyn SyscallInterceptor> = Box::new(mock);
        let mut session = SupervisorSession::new("mock-tool", pid);
        let proxy = allow_only_proxy();
        let audit_storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let audit_sink: Arc<dyn crate::audit_sink::AuditSink> =
            Arc::new(crate::audit_sink::StorageAuditSink::new(audit_storage));
        let digest_queue = Arc::new(grith_digest::queue::DigestQueue::open_in_memory().unwrap());
        let digest_store: Arc<dyn crate::reviewer::DigestStore> =
            Arc::new(crate::reviewer::LocalDigestStore::new(digest_queue));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let containment_tracker = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::new(
                Duration::from_secs(60),
            ),
        );
        let mut config = SupervisorConfig::default();
        config.coverage = coverage;
        let loop_ctx = SupervisorLoopContext {
            proxy: &proxy,
            audit_sink,
            digest_store,
            dlp_redactor: &dlp_redactor,
            correlation_tracker: &correlation_tracker,
            containment_tracker: &containment_tracker,
            config: &config,
            event_tx: None,
            freezer: Freezer::new(Duration::from_secs(config.freeze_timeout_seconds)),
            read_batch_tracker: Mutex::new(ReadBatchTracker::new(10)),
            reviewer: Arc::new(PanicReviewer),
            unanswered_reviews: Arc::new(AtomicU32::new(0)),
            session_sync: None,
            session_allowed: Arc::new(Mutex::new(HashSet::new())),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_inspection_enabled: false,
            dns_decision_service: None,
            dns_forward_confirm: None,
            syscall_log: None,
            forensics_trace: None,
            reputation_table: Arc::new(Mutex::new(grith_proxy::reputation::ReputationTable::new())),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            daemon_restart: None,
            observation_outbox: Arc::new(Default::default()),
            persist_local_reputation: true,
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            workspace_roots: Vec::new(),
            session_denied: Arc::new(Mutex::new(HashSet::new())),
            workspace_boundary: None,
            local_listener_policy: Vec::new(),
            namespace_users: Vec::new(),
            permit_authority_delegating: Vec::new(),
            permit_control_sockets: Vec::new(),
            dbus_inspection_armed: false,
            authority_delegating_pins: authority_delegation::AuthorityDelegatingPins::empty(),
            working_root: None,
            mass_destruction: Mutex::new(mass_destruction::MassDestructionTracker::with_defaults()),
            yama_ptrace_scope: None,
            analytics_config: std::sync::OnceLock::new(),
        };

        handle_syscall_event(&mut interceptor, &mut session, &loop_ctx, event)
            .await
            .unwrap();

        let state = state.lock().unwrap();
        assert_eq!(
            state.allow_pids,
            vec![pid],
            "expected allow with category off"
        );
        assert!(state.deny_pids.is_empty(), "must not deny");
    }

    #[tokio::test]
    async fn phase_f_category1_off_allows_kernel_module() {
        let mut coverage = crate::config::CoverageConfig::default();
        coverage.category1_hard_deny = false;
        assert_event_allowed_with_coverage(
            sample_phase_a_event(
                7001,
                crate::platform::linux::syscall_nr::INIT_MODULE,
                SyscallKind::KernelModuleOp {
                    op: crate::interceptor::KernelModuleOpKind::Init,
                },
            ),
            coverage,
        )
        .await;
    }

    #[tokio::test]
    async fn phase_f_category4_off_allows_reboot() {
        let mut coverage = crate::config::CoverageConfig::default();
        coverage.category4_arch_priv = false;
        assert_event_allowed_with_coverage(
            sample_phase_a_event(
                7002,
                crate::platform::linux::syscall_nr::REBOOT,
                SyscallKind::ArchPrivilegedOp {
                    op: crate::interceptor::ArchPrivOp::Reboot,
                },
            ),
            coverage,
        )
        .await;
    }

    #[tokio::test]
    async fn phase_f_category2_off_by_default_allows_chown() {
        // The default coverage config has category2_proxy = false.
        // A chown event must therefore allow silently rather than
        // routing through the proxy.
        assert_event_allowed_with_coverage(
            sample_phase_a_event(
                7003,
                crate::platform::linux::arch::x86_64::syscall_nr::CHOWN,
                SyscallKind::OwnershipChange {
                    op: crate::interceptor::OwnershipOp::Chown,
                    path: "/etc/passwd".into(),
                    new_uid: 1000,
                    new_gid: 1000,
                },
            ),
            crate::config::CoverageConfig::default(),
        )
        .await;
    }

    #[tokio::test]
    async fn phase_f_category3_off_by_default_allows_unshare() {
        // The default coverage config has category3_namespace = false.
        // An unshare event must therefore allow silently — even before
        // the namespace_users carveout kicks in.
        assert_event_allowed_with_coverage(
            sample_phase_a_event(
                7004,
                crate::platform::linux::syscall_nr::UNSHARE,
                SyscallKind::NamespaceOp {
                    syscall: crate::interceptor::NamespaceSyscall::Unshare,
                    flags: 0x1002_0000,
                },
            ),
            crate::config::CoverageConfig::default(),
        )
        .await;
    }

    // -- YAMA scope-probe helper tests --------------------------------------

    #[test]
    fn parse_cap_eff_reads_hex_mask() {
        let status = "Name:\tcat\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000080000\nCapBnd:\t000001ffffffffff\n";
        // 0x80000 = 1 << 19 = CAP_SYS_PTRACE alone.
        assert_eq!(parse_cap_eff(status), Some(0x8_0000));
        assert_eq!(
            parse_cap_eff("CapEff:\t000001ffffffffff"),
            Some(0x1ff_ffff_ffff)
        );
        assert_eq!(parse_cap_eff("Name:\tcat\n"), None);
    }

    #[test]
    fn kernel_blocks_requires_scope_two_or_higher() {
        // None = Yama absent (classic semantics) → never provably blocked.
        assert!(!kernel_blocks_cross_process(None, 1, 2));
        // Scope 0/1: same-uid access is kernel-legal → the proxy must see it.
        assert!(!kernel_blocks_cross_process(Some(0), 1, 2));
        assert!(!kernel_blocks_cross_process(Some(1), 1, 2));
    }

    #[test]
    fn dead_target_detected_from_live_same_ns_caller() {
        let me = std::process::id();
        // Unallocatable pid: provably absent → suppressible.
        assert!(cross_process_target_provably_absent(me, 0x3fff_fff1));
        // pid 0 is unaddressable — the kernel ESRCHs it unconditionally.
        assert!(cross_process_target_provably_absent(me, 0));
        // init always exists → never suppressible.
        assert!(!cross_process_target_provably_absent(me, 1));
        // Self as target trivially exists.
        assert!(!cross_process_target_provably_absent(me, me));
    }

    #[test]
    fn dead_target_fails_safe_on_unverifiable_caller() {
        // A caller with no /proc entry → PID namespace unknown → our /proc
        // view proves nothing about its target numbering → enforce.
        assert!(!cross_process_target_provably_absent(
            u32::MAX - 3,
            0x3fff_fff2
        ));
    }

    #[test]
    fn kernel_blocks_fails_safe_on_unreadable_caller() {
        // A pid with no /proc entry → capability unverifiable → enforce.
        assert!(!kernel_blocks_cross_process(Some(2), u32::MAX - 1, 1));
    }

    #[test]
    fn kernel_blocks_self_consistent_at_scope_two() {
        // Target ourselves: same user namespace by construction, so the
        // outcome depends only on whether this test process holds
        // CAP_SYS_PTRACE (it normally doesn't; under root/CI-with-caps the
        // expectation flips with it).
        let me = std::process::id();
        let expected = pid_has_cap_sys_ptrace(me) == Some(false);
        assert_eq!(kernel_blocks_cross_process(Some(2), me, me), expected);
    }

    // -- session allowlist matching tests ----------------------------------

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    // Helper: create a dummy ToolCallType for tests that don't care about
    // the operation type (exec, net tests).
    /// work/85 follow-up: one approval covers the docker command family for
    /// the session. The key function is shared by the record site and both
    /// consult gates, so equality here IS the auto-allow: the recorded key
    /// for the first payload matches the derived key for every later one.
    #[test]
    fn delegating_approval_key_unifies_docker_families_and_nothing_else() {
        let spawn = |args: &[&str]| ToolCallType::ProcessSpawn {
            command: "/usr/bin/docker".to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
        };
        let a = delegating_approval_key(&spawn(&[
            "docker", "compose", "exec", "-T", "web", "php", "-r", "echo 1;",
        ]));
        let b = delegating_approval_key(&spawn(&[
            "docker", "compose", "exec", "web", "mysql", "-e", "SELECT 1",
        ]));
        assert_eq!(a, b, "payload variants must share the approval");
        assert!(a.starts_with("delegating-approved:family:"));

        // `docker run` mints authority through its flags: exact key, so the
        // volume-mount variant can never ride the plain variant's approval.
        let run_a = delegating_approval_key(&spawn(&["docker", "run", "alpine", "sh"]));
        let run_b =
            delegating_approval_key(&spawn(&["docker", "run", "-v", "/:/host", "alpine", "sh"]));
        assert_ne!(run_a, run_b);
        assert!(!run_a.contains(":family:"));

        // Non-docker delegating binaries keep exact identity.
        let sysd = delegating_approval_key(&ToolCallType::ProcessSpawn {
            command: "/usr/bin/systemd-run".to_string(),
            args: vec!["systemd-run".to_string(), "id".to_string()],
        });
        assert!(!sysd.contains(":family:"));
    }

    fn dummy_file_read() -> ToolCallType {
        ToolCallType::FileRead {
            path: "/dummy".into(),
        }
    }

    fn dummy_file_write() -> ToolCallType {
        ToolCallType::FileWrite {
            path: "/dummy".into(),
            content_hash: String::new(),
        }
    }

    #[test]
    fn session_allowlist_exact_exec_match() {
        let mut allowed = HashSet::new();
        allowed.insert("exec:/usr/bin/git".into());
        assert!(is_session_allowlist_match(
            "exec:/usr/bin/git",
            &allowed,
            &dummy_file_read()
        ));
    }

    #[test]
    fn session_allowlist_exact_exec_requires_provenance() {
        let mut allowed = HashSet::new();
        allowed.insert("exec:/nonexistent/binary".into());
        assert!(!is_session_allowlist_match(
            "exec:/nonexistent/binary",
            &allowed,
            &dummy_file_read()
        ));
    }

    #[test]
    fn session_allowlist_exec_no_prefix_fallback() {
        let mut allowed = HashSet::new();
        allowed.insert("/usr/bin/".into());
        assert!(!is_session_allowlist_match(
            "exec:/usr/bin/git",
            &allowed,
            &dummy_file_read()
        ));
    }

    #[test]
    fn session_allowlist_exec_prefix_does_not_match_file_read() {
        let mut allowed = HashSet::new();
        allowed.insert("exec-prefix:/usr/lib/git-core/".into());
        assert!(!is_session_allowlist_match(
            "/usr/lib/git-core/git-remote-http",
            &allowed,
            &dummy_file_read()
        ));
    }

    #[test]
    fn session_allowlist_exec_prefix_does_not_match_file_write() {
        let mut allowed = HashSet::new();
        allowed.insert("exec-prefix:/usr/lib/git-core/".into());
        assert!(!is_session_allowlist_match(
            "/usr/lib/git-core/malicious-write-target",
            &allowed,
            &dummy_file_write()
        ));
    }

    #[test]
    fn session_allowlist_net_subdomain_match() {
        let mut allowed = HashSet::new();
        allowed.insert("net:anthropic.com".into());
        assert!(is_session_allowlist_match(
            "net:api.anthropic.com",
            &allowed,
            &dummy_file_read()
        ));
    }

    #[test]
    fn session_allowlist_dns_matches_net_entry() {
        let mut allowed = HashSet::new();
        allowed.insert("net:anthropic.com".into());
        assert!(is_session_allowlist_match(
            "dns:api.anthropic.com",
            &allowed,
            &dummy_file_read()
        ));
    }

    #[test]
    fn session_allowlist_filesystem_prefix_match() {
        let mut allowed = HashSet::new();
        allowed.insert("/home/user/project".into());
        assert!(is_session_allowlist_match(
            "/home/user/project/src/main.rs",
            &allowed,
            &dummy_file_read()
        ));
    }

    #[test]
    fn session_allowlist_filesystem_prefix_does_not_match_exec_prefix() {
        let mut allowed = HashSet::new();
        allowed.insert("exec-prefix:/home/user/tools/".into());
        assert!(!is_session_allowlist_match(
            "exec-prefix:/home/user/tools/foo",
            &allowed,
            &dummy_file_read()
        ));
    }

    #[test]
    fn scoped_read_prefix_matches_reads_and_directory_lists_only() {
        let mut allowed = HashSet::new();
        allowed.insert("ro-prefix:/repo/src/".into());

        for call in [
            ToolCallType::FileRead {
                path: "/repo/src/lib.rs".into(),
            },
            ToolCallType::DirList {
                path: "/repo/src/components".into(),
            },
        ] {
            assert!(is_session_allowlist_match("/ignored", &allowed, &call));
        }
        assert!(!is_session_allowlist_match(
            "/ignored",
            &allowed,
            &ToolCallType::FileWrite {
                path: "/repo/src/lib.rs".into(),
                content_hash: String::new(),
            }
        ));
        assert!(!is_session_allowlist_match(
            "/ignored",
            &allowed,
            &ToolCallType::FileRead {
                path: "/repo/src-old/lib.rs".into(),
            }
        ));
    }

    // ---- work/85: session refusals and the workspace boundary ---------

    fn denied_set(rules: &[&str]) -> HashSet<String> {
        rules.iter().map(|rule| (*rule).to_string()).collect()
    }

    #[test]
    fn session_deny_blocks_the_matching_operation_only() {
        let denied = denied_set(&["deny-ro-prefix:/repo/secrets/"]);

        assert_eq!(
            session_deny_match(
                &ToolCallType::FileRead {
                    path: "/repo/secrets/token".into(),
                },
                &denied
            )
            .as_deref(),
            Some("deny-ro-prefix:/repo/secrets/")
        );
        assert!(session_deny_match(
            &ToolCallType::DirList {
                path: "/repo/secrets".into(),
            },
            &denied
        )
        .is_some());
        // A read refusal is not a write refusal: the operator ticked one box.
        assert!(session_deny_match(
            &ToolCallType::FileWrite {
                path: "/repo/secrets/token".into(),
                content_hash: String::new(),
            },
            &denied
        )
        .is_none());
    }

    #[test]
    fn session_deny_is_boundary_safe() {
        let denied = denied_set(&["deny-ro-prefix:/repo/build/"]);
        assert!(session_deny_match(
            &ToolCallType::FileRead {
                path: "/repo/build/out.o".into(),
            },
            &denied
        )
        .is_some());
        // The sibling that merely shares the prefix keeps its access.
        assert!(session_deny_match(
            &ToolCallType::FileRead {
                path: "/repo/build-secrets/out.o".into(),
            },
            &denied
        )
        .is_none());
    }

    #[test]
    fn session_deny_covers_both_ends_of_a_rename() {
        let denied = denied_set(&["deny-delete-prefix:/repo/quarantine/"]);
        // Moving *into* a blocked directory is blocked too: the operator said
        // that subtree is off limits, not that it may only be written to.
        assert!(session_deny_match(
            &ToolCallType::FileRename {
                old_path: "/repo/src/payload".into(),
                new_path: "/repo/quarantine/payload".into(),
            },
            &denied
        )
        .is_some());
        assert!(session_deny_match(
            &ToolCallType::FileRename {
                old_path: "/repo/quarantine/payload".into(),
                new_path: "/repo/src/payload".into(),
            },
            &denied
        )
        .is_some());
    }

    #[test]
    fn session_deny_ignores_calls_it_does_not_govern() {
        let denied = denied_set(&["deny-ro-prefix:/repo/secrets/"]);
        assert!(session_deny_match(
            &ToolCallType::ProcessSpawn {
                command: "/repo/secrets/run.sh".into(),
                args: Vec::new(),
            },
            &denied
        )
        .is_none());
        assert!(session_deny_match(
            &ToolCallType::FileRead {
                path: "/repo/secrets/token".into(),
            },
            &HashSet::new()
        )
        .is_none());
    }

    fn empty_allowlist() -> Arc<Mutex<HashSet<String>>> {
        Arc::new(Mutex::new(HashSet::new()))
    }

    fn test_boundary() -> crate::workspace_only::WorkspaceBoundary {
        crate::workspace_only::WorkspaceBoundary::new(vec![
            "/repo".to_string(),
            "/repo-worktrees/feature".to_string(),
        ])
    }

    #[test]
    fn workspace_only_allows_the_workspace_and_its_linked_worktrees() {
        let boundary = test_boundary();
        let allowed = empty_allowlist();
        for call in [
            ToolCallType::FileRead {
                path: "/repo/src/lib.rs".into(),
            },
            ToolCallType::FileWrite {
                path: "/repo-worktrees/feature/src/lib.rs".into(),
                content_hash: String::new(),
            },
        ] {
            assert!(
                workspace_only_block_reason(&boundary, &call, &allowed).is_none(),
                "{call} is inside the workspace"
            );
        }
    }

    #[test]
    fn workspace_only_blocks_user_data_outside_the_workspace() {
        let boundary = test_boundary();
        let allowed = empty_allowlist();
        for call in [
            ToolCallType::FileRead {
                path: "/home/dev/.ssh/id_ed25519".into(),
            },
            ToolCallType::FileRead {
                path: "/repo-secrets/.env".into(),
            },
            ToolCallType::FileWrite {
                path: "/home/dev/other-project/main.rs".into(),
                content_hash: String::new(),
            },
            ToolCallType::FileDelete {
                path: "/mnt/backup/keys".into(),
            },
        ] {
            assert!(
                workspace_only_block_reason(&boundary, &call, &allowed).is_some(),
                "{call} is outside the workspace and must be refused"
            );
        }
    }

    #[test]
    fn workspace_only_keeps_the_runtime_readable_but_not_writable() {
        let boundary = test_boundary();
        let allowed = empty_allowlist();
        // Without this the tool cannot load libc, and the mode would be an
        // elaborate way to refuse to run.
        assert!(workspace_only_block_reason(
            &boundary,
            &ToolCallType::FileRead {
                path: "/usr/lib/os-release".into(),
            },
            &allowed
        )
        .is_none());
        // A write into the runtime is exactly what the mode exists to stop.
        assert!(workspace_only_block_reason(
            &boundary,
            &ToolCallType::FileWrite {
                path: "/usr/lib/evil.so".into(),
                content_hash: String::new(),
            },
            &allowed
        )
        .is_some());
    }

    #[test]
    fn workspace_only_respects_profile_declared_trust() {
        let boundary = test_boundary();
        let allowed = Arc::new(Mutex::new(HashSet::from([
            "/home/dev/.cache/tool/".to_string()
        ])));
        // The profile says the tool needs this directory; the boundary is not
        // a licence to break the tool the operator asked to supervise.
        assert!(workspace_only_block_reason(
            &boundary,
            &ToolCallType::FileWrite {
                path: "/home/dev/.cache/tool/state.json".into(),
                content_hash: String::new(),
            },
            &allowed
        )
        .is_none());
        // A sibling of the declared path is still outside.
        assert!(workspace_only_block_reason(
            &boundary,
            &ToolCallType::FileWrite {
                path: "/home/dev/.cache/other/state.json".into(),
                content_hash: String::new(),
            },
            &allowed
        )
        .is_some());
    }

    #[test]
    fn workspace_only_governs_file_calls_only_and_is_inert_without_roots() {
        let allowed = empty_allowlist();
        assert!(workspace_only_block_reason(
            &test_boundary(),
            &ToolCallType::NetConnect {
                address: "example.com".into(),
                port: 443,
            },
            &allowed
        )
        .is_none());
        // An unresolvable launch directory must not deny every file operation.
        assert!(workspace_only_block_reason(
            &crate::workspace_only::WorkspaceBoundary::default(),
            &ToolCallType::FileRead {
                path: "/home/dev/.ssh/id_ed25519".into(),
            },
            &allowed
        )
        .is_none());
    }

    #[test]
    fn workspace_only_tests_declared_trust_per_path_not_per_call() {
        // The rename's SOURCE is declared trust and its destination is not.
        // `session_allowlist_key` keys a rename on the source, so a per-call
        // exemption would carry that trust to the destination — the exact
        // move the boundary exists to refuse.
        let allowed = Arc::new(Mutex::new(HashSet::from([
            "/home/dev/.cache/tool/".to_string()
        ])));
        assert!(workspace_only_block_reason(
            &test_boundary(),
            &ToolCallType::FileRename {
                old_path: "/home/dev/.cache/tool/notes".into(),
                new_path: "/home/dev/exfil/notes".into(),
            },
            &allowed
        )
        .is_some());
    }

    #[test]
    fn workspace_only_blocks_a_rename_that_leaves_the_workspace() {
        assert!(workspace_only_block_reason(
            &test_boundary(),
            &ToolCallType::FileRename {
                old_path: "/repo/src/secret".into(),
                new_path: "/home/dev/exfil/secret".into(),
            },
            &empty_allowlist()
        )
        .is_some());
    }

    #[test]
    fn scoped_write_prefix_matches_write_create_but_not_delete() {
        let mut allowed = HashSet::new();
        allowed.insert("write-prefix:/repo/build/".into());

        for call in [
            ToolCallType::FileWrite {
                path: "/repo/build/out.o".into(),
                content_hash: String::new(),
            },
            ToolCallType::FileAppend {
                path: "/repo/build/log".into(),
            },
            ToolCallType::DirCreate {
                path: "/repo/build/new".into(),
            },
        ] {
            assert!(is_session_allowlist_match("/ignored", &allowed, &call));
        }
        assert!(!is_session_allowlist_match(
            "/ignored",
            &allowed,
            &ToolCallType::FileDelete {
                path: "/repo/build/out.o".into(),
            }
        ));
    }

    #[test]
    fn scoped_delete_prefix_matches_delete_and_rename_old_path_only() {
        let mut allowed = HashSet::new();
        allowed.insert("delete-prefix:/repo/build/".into());

        assert!(is_session_allowlist_match(
            "/ignored",
            &allowed,
            &ToolCallType::FileDelete {
                path: "/repo/build/out.o".into(),
            }
        ));
        assert!(is_session_allowlist_match(
            "/ignored",
            &allowed,
            &ToolCallType::FileRename {
                old_path: "/repo/build/out.o".into(),
                new_path: "/repo/archive/out.o".into(),
            }
        ));
        assert!(!is_session_allowlist_match(
            "/ignored",
            &allowed,
            &ToolCallType::FileRename {
                old_path: "/repo/src/out.o".into(),
                new_path: "/repo/build/out.o".into(),
            }
        ));
        assert!(!is_session_allowlist_match(
            "/ignored",
            &allowed,
            &ToolCallType::FileWrite {
                path: "/repo/build/out.o".into(),
                content_hash: String::new(),
            }
        ));
    }

    #[test]
    fn scoped_prefix_namespaces_never_fall_through_to_bare_matching() {
        let allowed = HashSet::from(["write-prefix:/repo/build/".to_string()]);
        assert!(!is_session_allowlist_match(
            "write-prefix:/repo/build/out.o",
            &allowed,
            &ToolCallType::FileRead {
                path: "/elsewhere/out.o".into(),
            }
        ));
    }

    #[test]
    fn sensitive_scoped_reads_are_identified_for_post_proxy_allow() {
        let allowed = HashSet::from(["ro-prefix:/home/dev/.config/grith/".to_string()]);

        assert!(is_sensitive_scoped_read_match(
            &ToolCallType::FileRead {
                path: "/home/dev/.config/grith/daemon.token".into(),
            },
            &allowed
        ));
        assert!(is_sensitive_scoped_read_match(
            &ToolCallType::DirList {
                path: "/home/dev/.config/grith".into(),
            },
            &allowed
        ));
        assert!(!is_sensitive_scoped_read_match(
            &ToolCallType::FileRead {
                path: "/home/dev/project/src/lib.rs".into(),
            },
            &allowed
        ));
        assert!(!is_sensitive_scoped_read_match(
            &ToolCallType::FileWrite {
                path: "/home/dev/.config/grith/config.toml".into(),
                content_hash: String::new(),
            },
            &allowed
        ));
    }

    // ── ro: (read-only path) matching ─────────────────────────────

    #[test]
    fn ro_matches_file_read_exact() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("config");
        std::fs::write(&file, "ok").unwrap();
        let canonical = std::fs::canonicalize(&file).unwrap();
        let canonical = canonical.to_string_lossy().into_owned();

        let mut allowed = HashSet::new();
        allowed.insert(format!("ro:{canonical}"));
        let call = ToolCallType::FileRead {
            path: file.to_string_lossy().into_owned(),
        };
        assert!(is_session_allowlist_match(
            &file.to_string_lossy(),
            &allowed,
            &call
        ));
    }

    #[test]
    fn ro_does_not_match_file_write() {
        let mut allowed = HashSet::new();
        allowed.insert("ro:/home/user/.ssh/config".into());
        let call = ToolCallType::FileWrite {
            path: "/home/user/.ssh/config".into(),
            content_hash: String::new(),
        };
        assert!(!is_session_allowlist_match(
            "/home/user/.ssh/config",
            &allowed,
            &call
        ));
    }

    #[test]
    fn ro_does_not_match_file_append() {
        let mut allowed = HashSet::new();
        allowed.insert("ro:/home/user/.ssh/config".into());
        let call = ToolCallType::FileAppend {
            path: "/home/user/.ssh/config".into(),
        };
        assert!(!is_session_allowlist_match(
            "/home/user/.ssh/config",
            &allowed,
            &call
        ));
    }

    #[test]
    fn ro_does_not_match_file_delete() {
        let mut allowed = HashSet::new();
        allowed.insert("ro:/home/user/.ssh/config".into());
        let call = ToolCallType::FileDelete {
            path: "/home/user/.ssh/config".into(),
        };
        assert!(!is_session_allowlist_match(
            "/home/user/.ssh/config",
            &allowed,
            &call
        ));
    }

    #[test]
    fn ro_does_not_match_file_chmod() {
        let mut allowed = HashSet::new();
        allowed.insert("ro:/home/user/.ssh/config".into());
        let call = ToolCallType::FileChmod {
            path: "/home/user/.ssh/config".into(),
            mode: 0o644,
        };
        assert!(!is_session_allowlist_match(
            "/home/user/.ssh/config",
            &allowed,
            &call
        ));
    }

    #[test]
    fn ro_does_not_match_dir_list() {
        let mut allowed = HashSet::new();
        allowed.insert("ro:/home/user/.ssh".into());
        let call = ToolCallType::DirList {
            path: "/home/user/.ssh".into(),
        };
        assert!(!is_session_allowlist_match(
            "/home/user/.ssh",
            &allowed,
            &call
        ));
    }

    #[test]
    fn ro_exact_match_only_no_prefix() {
        let mut allowed = HashSet::new();
        allowed.insert("ro:/home/user/.ssh/config".into());
        let call = ToolCallType::FileRead {
            path: "/home/user/.ssh/config.d/foo".into(),
        };
        // Must not prefix-match — exact only.
        assert!(!is_session_allowlist_match(
            "/home/user/.ssh/config.d/foo",
            &allowed,
            &call
        ));
    }

    #[test]
    fn ro_does_not_match_different_file() {
        let mut allowed = HashSet::new();
        allowed.insert("ro:/home/user/.ssh/config".into());
        let call = ToolCallType::FileRead {
            path: "/home/user/.ssh/id_rsa".into(),
        };
        assert!(!is_session_allowlist_match(
            "/home/user/.ssh/id_rsa",
            &allowed,
            &call
        ));
    }

    #[test]
    fn ro_not_reachable_via_bare_path_prefix() {
        // A bare-path prefix should not match an ro: entry.
        let mut allowed = HashSet::new();
        allowed.insert("ro:/home/user/.ssh/config".into());
        let call = ToolCallType::FileWrite {
            path: "/home/user/.ssh/config".into(),
            content_hash: String::new(),
        };
        // Even though the path matches the ro: entry, the write operation
        // should not be allowed — and the ro: entry should not leak into
        // prefix matching either.
        assert!(!is_session_allowlist_match(
            "/home/user/.ssh/config",
            &allowed,
            &call
        ));
    }

    #[test]
    fn ro_namespace_isolated_from_exec() {
        let mut allowed = HashSet::new();
        allowed.insert("ro:/usr/bin/git".into());
        let call = ToolCallType::ProcessSpawn {
            command: "/usr/bin/git".into(),
            args: vec![],
        };
        assert!(!is_session_allowlist_match(
            "exec:/usr/bin/git",
            &allowed,
            &call
        ));
    }

    #[test]
    fn ro_namespace_isolated_from_net() {
        let mut allowed = HashSet::new();
        allowed.insert("ro:net:example.com".into());
        let call = ToolCallType::NetConnect {
            address: "example.com".into(),
            port: 443,
        };
        assert!(!is_session_allowlist_match(
            "net:example.com",
            &allowed,
            &call
        ));
    }

    #[test]
    fn bare_path_not_reachable_via_ro_match() {
        // A file that's in routine_paths (bare path) should not also be
        // matchable by ro: namespace lookups.
        let mut allowed = HashSet::new();
        allowed.insert("/home/user/project".into());
        let call = ToolCallType::FileRead {
            path: "/home/user/project/src/main.rs".into(),
        };
        // This should match via bare-path prefix, NOT via ro:.
        // Verify there's no ro: entry that could match.
        assert!(!allowed.contains("ro:/home/user/project/src/main.rs"));
        // But the regular prefix match should still work.
        assert!(is_session_allowlist_match(
            "/home/user/project/src/main.rs",
            &allowed,
            &call
        ));
    }

    #[cfg(unix)]
    #[test]
    fn ro_match_uses_canonical_target_not_raw_symlink_path() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target.txt");
        let link = tmp.path().join("link.txt");
        std::fs::write(&target, "ok").unwrap();
        symlink(&target, &link).unwrap();

        let canonical = std::fs::canonicalize(&target).unwrap();
        let canonical = canonical.to_string_lossy().into_owned();

        let mut allowed = HashSet::new();
        allowed.insert(format!("ro:{canonical}"));

        let call = ToolCallType::FileRead {
            path: link.to_string_lossy().into_owned(),
        };
        assert!(is_session_allowlist_match(
            &link.to_string_lossy(),
            &allowed,
            &call
        ));
    }

    #[cfg(unix)]
    #[test]
    fn approved_file_read_creates_readonly_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("config.txt");
        std::fs::write(&file, "ok").unwrap();

        let call = ToolCallType::FileRead {
            path: file.to_string_lossy().into_owned(),
        };
        let entry = approved_session_allowlist_entry(&call).unwrap();
        let canonical = std::fs::canonicalize(&file).unwrap();
        let canonical = canonical.to_string_lossy().into_owned();
        assert_eq!(entry, format!("ro:{canonical}"));
    }

    #[cfg(unix)]
    #[test]
    fn approved_file_read_does_not_allow_later_write() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("config.txt");
        std::fs::write(&file, "ok").unwrap();

        let read_call = ToolCallType::FileRead {
            path: file.to_string_lossy().into_owned(),
        };
        let write_call = ToolCallType::FileWrite {
            path: file.to_string_lossy().into_owned(),
            content_hash: String::new(),
        };

        let mut allowed = HashSet::new();
        allowed.insert(approved_session_allowlist_entry(&read_call).unwrap());

        assert!(!is_session_allowlist_match(
            &file.to_string_lossy(),
            &allowed,
            &write_call
        ));
    }

    // ── rw: (read-write path) matching ────────────────────────────

    #[cfg(unix)]
    #[test]
    fn rw_matches_file_write_exact() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("target.txt");
        std::fs::write(&file, "ok").unwrap();
        let canonical = std::fs::canonicalize(&file).unwrap();
        let canonical = canonical.to_string_lossy().into_owned();

        let mut allowed = HashSet::new();
        allowed.insert(format!("rw:{canonical}"));
        let call = ToolCallType::FileWrite {
            path: file.to_string_lossy().into_owned(),
            content_hash: String::new(),
        };
        assert!(is_session_allowlist_match(
            &file.to_string_lossy(),
            &allowed,
            &call
        ));
    }

    #[test]
    fn rw_does_not_match_file_read() {
        let mut allowed = HashSet::new();
        allowed.insert("rw:/home/user/project/file.rs".into());
        let call = ToolCallType::FileRead {
            path: "/home/user/project/file.rs".into(),
        };
        assert!(!is_session_allowlist_match(
            "/home/user/project/file.rs",
            &allowed,
            &call
        ));
    }

    #[test]
    fn rw_does_not_prefix_match() {
        let mut allowed = HashSet::new();
        allowed.insert("rw:/home/user/project".into());
        let call = ToolCallType::FileWrite {
            path: "/home/user/project/sub/file.rs".into(),
            content_hash: String::new(),
        };
        // rw: is exact match only — must not prefix-match.
        assert!(!is_session_allowlist_match(
            "/home/user/project/sub/file.rs",
            &allowed,
            &call
        ));
    }

    #[cfg(unix)]
    #[test]
    fn approved_file_write_creates_rw_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("output.txt");
        std::fs::write(&file, "ok").unwrap();

        let call = ToolCallType::FileWrite {
            path: file.to_string_lossy().into_owned(),
            content_hash: String::new(),
        };
        let entry = approved_session_allowlist_entry(&call).unwrap();
        let canonical = std::fs::canonicalize(&file).unwrap();
        let canonical = canonical.to_string_lossy().into_owned();
        assert_eq!(entry, format!("rw:{canonical}"));
    }

    #[cfg(unix)]
    #[test]
    fn approved_file_delete_creates_rw_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("deleteme.txt");
        std::fs::write(&file, "ok").unwrap();

        let call = ToolCallType::FileDelete {
            path: file.to_string_lossy().into_owned(),
        };
        let entry = approved_session_allowlist_entry(&call).unwrap();
        assert!(entry.starts_with("rw:"), "delete should produce rw: entry");
    }

    #[test]
    fn rw_namespace_isolated_from_ro() {
        let mut allowed = HashSet::new();
        allowed.insert("rw:/home/user/file.txt".into());
        let call = ToolCallType::FileRead {
            path: "/home/user/file.txt".into(),
        };
        // rw: must not match FileRead — that's ro:'s job.
        assert!(!is_session_allowlist_match(
            "/home/user/file.txt",
            &allowed,
            &call
        ));
    }

    #[test]
    fn rw_not_reachable_via_prefix_matching() {
        let mut allowed = HashSet::new();
        allowed.insert("rw:/home/user/project/file.rs".into());
        let call = ToolCallType::FileWrite {
            path: "/home/user/project/file.rs.bak".into(),
            content_hash: String::new(),
        };
        // Prefix matching must skip rw: entries.
        assert!(!is_session_allowlist_match(
            "/home/user/project/file.rs.bak",
            &allowed,
            &call
        ));
    }

    // -- process:/namespace: session grants (cross-process approval flood) --

    fn cross_process_call(op: &str, target_pid: u32) -> ToolCallType {
        ToolCallType::CrossProcessAccess {
            op: op.into(),
            target_pid,
        }
    }

    #[test]
    fn approved_cross_process_key_binds_pid_and_start_time() {
        // A live target (self) yields a 4-component key ending in the
        // process's start time, so a recycled pid cannot inherit the grant.
        let me = std::process::id();
        let call = cross_process_call("ptrace", me);
        let entry = approved_session_allowlist_entry(&call).expect("live target has an entry");
        let parts: Vec<&str> = entry.split(':').collect();
        assert_eq!(
            parts.len(),
            4,
            "expected process:op:pid:starttime, got {entry}"
        );
        assert_eq!(parts[0], "process");
        assert_eq!(parts[1], "ptrace");
        assert_eq!(parts[2], me.to_string());
        assert!(
            parts[3].parse::<u64>().is_ok(),
            "start time must be numeric"
        );

        // A dead target has no readable identity → no grant (always
        // re-prompts). 0x3fff_fff5 is above pid_max, never allocatable.
        assert_eq!(
            approved_session_allowlist_entry(&cross_process_call("ptrace", 0x3fff_fff5)),
            None,
        );

        let ns_call = ToolCallType::NamespaceOp {
            syscall: "unshare".into(),
            flags: 0x2000_0000,
        };
        assert_eq!(
            approved_session_allowlist_entry(&ns_call).as_deref(),
            Some("namespace:unshare:0x20000000"),
        );
    }

    #[test]
    fn process_grant_survives_and_matches_only_the_same_live_process() {
        // The key derived for a live self-target round-trips: storing it and
        // re-deriving it matches. A recycled pid would derive a different
        // start-time component and miss.
        let me = std::process::id();
        let call = cross_process_call("ptrace", me);
        let key = session_allowlist_key(&call).expect("live target keyed");
        let mut allowed = HashSet::new();
        allowed.insert(key.clone());
        assert!(is_session_allowlist_match(&key, &allowed, &call));

        // A stored grant for the SAME pid but a DIFFERENT start time (the
        // recycled-pid case) must not match the live process's derived key.
        let stale = format!("process:ptrace:{me}:1");
        let mut stale_allowed = HashSet::new();
        stale_allowed.insert(stale);
        assert!(
            !is_session_allowlist_match(&key, &stale_allowed, &call),
            "a grant with a different start time is a different process"
        );
    }

    #[test]
    fn process_entry_matches_exact_key_and_type_only() {
        // is_session_allowlist_match works on the precomputed key, so these
        // use hand-crafted 4-part keys and don't depend on /proc.
        let mut allowed = HashSet::new();
        allowed.insert("process:ptrace:123:9999".to_string());
        assert!(is_session_allowlist_match(
            "process:ptrace:123:9999",
            &allowed,
            &cross_process_call("ptrace", 123),
        ));
        // Different op, same pid+start: no match.
        assert!(!is_session_allowlist_match(
            "process:process_vm_readv:123:9999",
            &allowed,
            &cross_process_call("process_vm_readv", 123),
        ));
    }

    #[test]
    fn process_entry_never_serves_as_string_prefix() {
        // A grant for pid 1 must not leak to pid 12, 123, ... via the
        // bare-path prefix fallback.
        let mut allowed = HashSet::new();
        allowed.insert("process:ptrace:1:100".to_string());
        assert!(!is_session_allowlist_match(
            "process:ptrace:12:100",
            &allowed,
            &cross_process_call("ptrace", 12),
        ));
    }

    #[test]
    fn process_entry_requires_cross_process_call_type() {
        // A relative path from a tracee register can spell anything —
        // including a process: key. It must not borrow the grant.
        let mut allowed = HashSet::new();
        allowed.insert("process:ptrace:123:9999".to_string());
        let read = ToolCallType::FileRead {
            path: "process:ptrace:123:9999".into(),
        };
        assert!(!is_session_allowlist_match(
            "process:ptrace:123:9999",
            &allowed,
            &read
        ));
    }

    #[test]
    fn namespace_entry_exact_and_type_gated() {
        let mut allowed = HashSet::new();
        allowed.insert("namespace:unshare:0x20000000".to_string());
        let ns = ToolCallType::NamespaceOp {
            syscall: "unshare".into(),
            flags: 0x2000_0000,
        };
        assert!(is_session_allowlist_match(
            "namespace:unshare:0x20000000",
            &allowed,
            &ns
        ));
        // Different flag word: a fresh prompt.
        let ns_wider = ToolCallType::NamespaceOp {
            syscall: "unshare".into(),
            flags: 0x2002_0000,
        };
        assert!(!is_session_allowlist_match(
            "namespace:unshare:0x20020000",
            &allowed,
            &ns_wider
        ));
        // Type gate: a file path spelling the key must not match.
        let read = ToolCallType::FileRead {
            path: "namespace:unshare:0x20000000".into(),
        };
        assert!(!is_session_allowlist_match(
            "namespace:unshare:0x20000000",
            &allowed,
            &read
        ));
    }

    #[test]
    fn process_start_time_reads_self_and_rejects_dead() {
        assert!(process_start_time(std::process::id()).is_some());
        assert_eq!(process_start_time(0x3fff_fff6), None);
    }

    #[cfg(unix)]
    #[test]
    fn rw_matches_file_append() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("log.txt");
        std::fs::write(&file, "ok").unwrap();
        let canonical = std::fs::canonicalize(&file).unwrap();
        let canonical = canonical.to_string_lossy().into_owned();

        let mut allowed = HashSet::new();
        allowed.insert(format!("rw:{canonical}"));
        let call = ToolCallType::FileAppend {
            path: file.to_string_lossy().into_owned(),
        };
        assert!(is_session_allowlist_match(
            &file.to_string_lossy(),
            &allowed,
            &call
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rw_matches_file_chmod() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("script.sh");
        std::fs::write(&file, "ok").unwrap();
        let canonical = std::fs::canonicalize(&file).unwrap();
        let canonical = canonical.to_string_lossy().into_owned();

        let mut allowed = HashSet::new();
        allowed.insert(format!("rw:{canonical}"));
        let call = ToolCallType::FileChmod {
            path: file.to_string_lossy().into_owned(),
            mode: 0o755,
        };
        assert!(is_session_allowlist_match(
            &file.to_string_lossy(),
            &allowed,
            &call
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rw_matches_pr6_path_bearing_filesystem_ops() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("mount-target");
        std::fs::create_dir(&path).unwrap();
        let canonical = std::fs::canonicalize(&path).unwrap();
        let canonical = canonical.to_string_lossy().into_owned();

        let mut allowed = HashSet::new();
        allowed.insert(format!("rw:{canonical}"));

        let ownership = ToolCallType::OwnershipChange {
            target: path.to_string_lossy().into_owned(),
            new_uid: 1000,
            new_gid: 1000,
        };
        assert!(is_session_allowlist_match(
            &path.to_string_lossy(),
            &allowed,
            &ownership
        ));

        let mutation = ToolCallType::FilesystemMutation {
            op: "mount".into(),
            source: None,
            target: path.to_string_lossy().into_owned(),
            fstype: None,
        };
        assert!(is_session_allowlist_match(
            &path.to_string_lossy(),
            &allowed,
            &mutation
        ));
    }

    // ─── /tmp self-created subtree auto-allow tests ──────────────────────

    #[test]
    fn tmp_self_created_prefix_top_level_dir_returns_slashed() {
        let call = ToolCallType::DirCreate {
            path: "/tmp/v100-0.16.2".into(),
        };
        assert_eq!(
            tmp_self_created_prefix(&call),
            Some("/tmp/v100-0.16.2/".into())
        );
    }

    #[test]
    fn tmp_self_created_prefix_top_level_file_returns_bare() {
        let call = ToolCallType::FileWrite {
            path: "/tmp/v100-0.16.2.crate".into(),
            content_hash: String::new(),
        };
        assert_eq!(
            tmp_self_created_prefix(&call),
            Some("/tmp/v100-0.16.2.crate".into())
        );
    }

    #[test]
    fn tmp_self_created_prefix_subpath_rejected() {
        // Sub-paths under /tmp/X don't register — only top-level.
        // Once /tmp/X/ is in the allowlist, /tmp/X/sub/ accesses match
        // via prefix; we don't need a second registration.
        let call = ToolCallType::DirCreate {
            path: "/tmp/v100-0.16.2/src".into(),
        };
        assert_eq!(tmp_self_created_prefix(&call), None);
    }

    #[test]
    fn tmp_self_created_prefix_outside_tmp_rejected() {
        let call = ToolCallType::DirCreate {
            path: "/home/user/project/build".into(),
        };
        assert_eq!(tmp_self_created_prefix(&call), None);
    }

    #[test]
    fn tmp_self_created_prefix_bare_tmp_rejected() {
        // /tmp itself (no name after slash) doesn't register —
        // would be a no-op anyway.
        let call = ToolCallType::DirCreate {
            path: "/tmp/".into(),
        };
        assert_eq!(tmp_self_created_prefix(&call), None);
    }

    #[test]
    fn tmp_self_created_prefix_shared_mounts_rejected() {
        for socket_dir in [
            ".X11-unix",
            ".ICE-unix",
            ".font-unix",
            ".Test-unix",
            ".XIM-unix",
        ] {
            let call = ToolCallType::DirCreate {
                path: format!("/tmp/{socket_dir}"),
            };
            assert_eq!(
                tmp_self_created_prefix(&call),
                None,
                "shared mount {socket_dir} must not register"
            );
        }
    }

    #[test]
    fn tmp_self_created_prefix_file_rename_uses_new_path() {
        // Rename target is the path that ends up created; old_path is
        // the source. We register the destination.
        let call = ToolCallType::FileRename {
            old_path: "/home/user/data.bin".into(),
            new_path: "/tmp/uploaded".into(),
        };
        assert_eq!(tmp_self_created_prefix(&call), Some("/tmp/uploaded".into()));
    }

    #[test]
    fn tmp_self_created_prefix_non_create_ops_rejected() {
        // ShellExec, NetConnect etc. — not creates, never register.
        let call = ToolCallType::ShellExec {
            command: "/usr/bin/ls".into(),
            args: vec!["/tmp".into()],
        };
        assert_eq!(tmp_self_created_prefix(&call), None);

        let call = ToolCallType::FileRead {
            path: "/tmp/foo".into(),
        };
        assert_eq!(tmp_self_created_prefix(&call), None);
    }

    #[test]
    fn tmp_self_created_prefix_grants_subtree_via_existing_match() {
        // End-to-end: registering /tmp/foo/ in session_allowed should
        // cause subsequent writes to /tmp/foo/bar/baz.txt to match via
        // the existing prefix-match logic — no further work needed.
        let mut allowed = HashSet::new();
        allowed.insert("/tmp/foo/".into());

        let subwrite = ToolCallType::FileWrite {
            path: "/tmp/foo/bar/baz.txt".into(),
            content_hash: String::new(),
        };
        assert!(is_session_allowlist_match(
            "/tmp/foo/bar/baz.txt",
            &allowed,
            &subwrite
        ));

        // Boundary check: /tmp/foobar (no slash separator) must NOT
        // match /tmp/foo/ even via naive starts_with — the trailing
        // slash in the prefix forces a boundary.
        let sibling = ToolCallType::FileWrite {
            path: "/tmp/foobar".into(),
            content_hash: String::new(),
        };
        assert!(!is_session_allowlist_match(
            "/tmp/foobar",
            &allowed,
            &sibling
        ));
    }

    // -----------------------------------------------------------------------
    // H2 Option 1: foreign-pts-write detection (IPC injection into a sibling
    // pane). The pure classifier; the audit-log/deny wiring is in
    // handle_syscall_event.
    // -----------------------------------------------------------------------

    fn pts_write(path: &str) -> ToolCallType {
        ToolCallType::FileWrite {
            path: path.into(),
            content_hash: String::new(),
        }
    }

    #[test]
    fn foreign_pts_write_flags_sibling_pane() {
        let own = Some("/dev/pts/3");
        // Write to a different pane's pts → flagged (the injection vector).
        assert!(is_foreign_pts_write(
            &pts_write("/dev/pts/7"),
            "/dev/pts/7",
            own
        ));
        // Write to the tool's OWN controlling terminal → not flagged.
        assert!(!is_foreign_pts_write(
            &pts_write("/dev/pts/3"),
            "/dev/pts/3",
            own
        ));
    }

    #[test]
    fn foreign_pts_write_only_for_writes_on_pts() {
        let own = Some("/dev/pts/3");
        // A read of another pts is not the injection vector.
        let read = ToolCallType::FileRead {
            path: "/dev/pts/7".into(),
        };
        assert!(!is_foreign_pts_write(&read, "/dev/pts/7", own));
        // A write to a non-pts noise path is unrelated.
        assert!(!is_foreign_pts_write(
            &pts_write("/dev/null"),
            "/dev/null",
            own
        ));
    }

    #[test]
    fn foreign_pts_write_fail_open_when_own_unknown() {
        // If the controlling pts could not be resolved, do not flag (avoid
        // false positives from a grith-side resolution failure).
        assert!(!is_foreign_pts_write(
            &pts_write("/dev/pts/7"),
            "/dev/pts/7",
            None
        ));
    }

    // control-injection-socket + authority-delegating-binary classifier tests
    // moved with their functions into the `authority_delegation` module.

    // -----------------------------------------------------------------------
    // Authority-delegating spawn + control-injection socket ENFORCEMENT
    // (handle_syscall_event level — the load-bearing "did it actually route
    // and escalate?" tests, not just the classifier unit tests).
    // -----------------------------------------------------------------------

    /// Outcome of driving one event through `handle_syscall_event`.
    struct DelegationOutcome {
        allow_pids: Vec<u32>,
        deny_pids: Vec<u32>,
        total_queued: u64,
        total_filtered_noise: u64,
    }

    /// Drive a single event through `handle_syscall_event` in Log queue-mode
    fn decision_with_filters(filters: &[(&str, bool)]) -> grith_proxy::types::ProxyDecision {
        let mut d = grith_proxy::types::ProxyDecision {
            action: grith_proxy::types::ProxyAction::Queue {
                priority: grith_proxy::types::QueuePriority::Medium,
            },
            composite_score: 4.0,
            filter_results: Vec::new(),
            decision_reason: "test".to_string(),
            evaluation_time: Duration::from_millis(0),
        };
        for (name, matched) in filters {
            d.filter_results.push(grith_proxy::types::FilterResult {
                filter_name: (*name).to_string(),
                matched: *matched,
                score: if *matched { 3.0 } else { 0.0 },
                rule_id: "test-rule".to_string(),
                severity: grith_proxy::types::Severity::Warning,
                message: String::new(),
                metadata: std::collections::HashMap::new(),
            });
        }
        d
    }

    /// `--allow-queued` trades safety for throughput on ordinary queued calls.
    /// Taint and containment are not ordinary: they mean the session has
    /// already touched something sensitive, so they must not be waved through.
    #[test]
    fn contamination_signalled_detects_taint_and_containment() {
        assert!(contamination_signalled(&decision_with_filters(&[(
            "taint", true
        )])));
        assert!(contamination_signalled(&decision_with_filters(&[(
            "session-containment",
            true
        )])));
        // Mixed: one ordinary filter alongside a contamination signal.
        assert!(contamination_signalled(&decision_with_filters(&[
            ("egress-policy", true),
            ("taint", true),
        ])));
    }

    /// Ordinary policy friction is exactly what the flag is for.
    #[test]
    fn contamination_signalled_ignores_ordinary_filters() {
        assert!(!contamination_signalled(&decision_with_filters(&[
            ("egress-policy", true),
            ("operation-risk", true),
        ])));
        assert!(!contamination_signalled(&decision_with_filters(&[])));
    }

    /// A filter that ran but did not match contributed nothing and must not
    /// suppress the flag — every filter appears in `filter_results`.
    #[test]
    fn contamination_signalled_requires_an_actual_match() {
        assert!(!contamination_signalled(&decision_with_filters(&[
            ("taint", false),
            ("session-containment", false),
        ])));
    }

    /// (so a QUEUE escalation is allowed-and-counted rather than freezing on
    /// the `PanicReviewer`) with an all-allow proxy, so the ONLY thing that can
    /// produce a QUEUE is the supervisor-side authority-delegation escalation.
    /// Run one event through the delegation path with D-Bus message inspection
    /// **off**, so the case under test is connect-time enforcement itself.
    /// D-Bus cases that need the shipped default use
    /// [`run_delegation_event_with_dbus_inspection`].
    async fn run_delegation_event(
        event: SyscallEvent,
        enforce_spawn: bool,
        enforce_control_socket: bool,
        permit_authority_delegating: Vec<String>,
        permit_control_sockets: Vec<String>,
        session_allowed_seed: Vec<String>,
    ) -> DelegationOutcome {
        run_delegation_event_with_dbus_inspection(
            event,
            enforce_spawn,
            enforce_control_socket,
            permit_authority_delegating,
            permit_control_sockets,
            session_allowed_seed,
            false,
        )
        .await
    }

    /// Run one event with a caller-supplied proxy, so a case can assert a
    /// score-driven decision rather than an escalation. Everything else in the
    /// harness is unchanged.
    async fn run_delegation_event_with_proxy(
        event: SyscallEvent,
        proxy: Arc<SecurityProxy>,
    ) -> DelegationOutcome {
        run_delegation_event_inner(event, false, true, vec![], vec![], vec![], true, proxy).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_delegation_event_with_dbus_inspection(
        event: SyscallEvent,
        enforce_spawn: bool,
        enforce_control_socket: bool,
        permit_authority_delegating: Vec<String>,
        permit_control_sockets: Vec<String>,
        session_allowed_seed: Vec<String>,
        dbus_message_inspection: bool,
    ) -> DelegationOutcome {
        run_delegation_event_inner(
            event,
            enforce_spawn,
            enforce_control_socket,
            permit_authority_delegating,
            permit_control_sockets,
            session_allowed_seed,
            dbus_message_inspection,
            allow_only_proxy(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_delegation_event_inner(
        event: SyscallEvent,
        enforce_spawn: bool,
        enforce_control_socket: bool,
        permit_authority_delegating: Vec<String>,
        permit_control_sockets: Vec<String>,
        session_allowed_seed: Vec<String>,
        dbus_message_inspection: bool,
        proxy: Arc<SecurityProxy>,
    ) -> DelegationOutcome {
        let pid = event.pid;
        let (mock, state) = MockInterceptor::new(vec![event.clone()]);
        let mut interceptor: Box<dyn SyscallInterceptor> = Box::new(mock);
        let mut session = SupervisorSession::new("mock-tool", pid);
        let audit_storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let audit_sink: Arc<dyn crate::audit_sink::AuditSink> =
            Arc::new(crate::audit_sink::StorageAuditSink::new(audit_storage));
        let digest_queue = Arc::new(grith_digest::queue::DigestQueue::open_in_memory().unwrap());
        let digest_store: Arc<dyn crate::reviewer::DigestStore> =
            Arc::new(crate::reviewer::LocalDigestStore::new(digest_queue));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let containment_tracker = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::new(
                Duration::from_secs(60),
            ),
        );
        let mut config = SupervisorConfig::default();
        config.interactive_queue_action = crate::config::InteractiveQueueAction::Log;
        config.enforce_authority_delegating_spawn = enforce_spawn;
        config.enforce_control_socket_connect = enforce_control_socket;
        config.dbus_message_inspection = dbus_message_inspection;
        let loop_ctx = SupervisorLoopContext {
            proxy: &proxy,
            audit_sink,
            digest_store,
            dlp_redactor: &dlp_redactor,
            correlation_tracker: &correlation_tracker,
            containment_tracker: &containment_tracker,
            config: &config,
            event_tx: None,
            freezer: Freezer::new(Duration::from_secs(config.freeze_timeout_seconds)),
            read_batch_tracker: Mutex::new(ReadBatchTracker::new(10)),
            reviewer: Arc::new(PanicReviewer),
            unanswered_reviews: Arc::new(AtomicU32::new(0)),
            session_sync: None,
            session_allowed: Arc::new(Mutex::new(session_allowed_seed.into_iter().collect())),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_inspection_enabled: false,
            dns_decision_service: None,
            dns_forward_confirm: None,
            syscall_log: None,
            forensics_trace: None,
            reputation_table: Arc::new(Mutex::new(grith_proxy::reputation::ReputationTable::new())),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            daemon_restart: None,
            observation_outbox: Arc::new(Default::default()),
            persist_local_reputation: true,
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            workspace_roots: Vec::new(),
            session_denied: Arc::new(Mutex::new(HashSet::new())),
            workspace_boundary: None,
            local_listener_policy: Vec::new(),
            namespace_users: Vec::new(),
            permit_authority_delegating,
            permit_control_sockets,
            dbus_inspection_armed: dbus_message_inspection,
            authority_delegating_pins: authority_delegation::AuthorityDelegatingPins::empty(),
            working_root: None,
            mass_destruction: Mutex::new(mass_destruction::MassDestructionTracker::with_defaults()),
            yama_ptrace_scope: None,
            analytics_config: std::sync::OnceLock::new(),
        };

        handle_syscall_event(&mut interceptor, &mut session, &loop_ctx, event)
            .await
            .unwrap();

        let st = state.lock().unwrap();
        DelegationOutcome {
            allow_pids: st.allow_pids.clone(),
            deny_pids: st.deny_pids.clone(),
            total_queued: session.stats.total_queued,
            total_filtered_noise: session.stats.total_filtered_noise,
        }
    }

    /// A ProcessExec event whose target is a real (existing) file with the
    /// given basename — real so PR-3-B failed-exec suppression does not
    /// short-circuit our QUEUE. Returns the event and the temp path (kept
    /// alive by the caller's binding is unnecessary; the file lives in tmp).
    fn existing_binary_exec_event(pid: u32, basename: &str) -> SyscallEvent {
        let dir = std::env::temp_dir().join(format!("grith_ad_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join(basename);
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        sample_phase_a_event(
            pid,
            crate::platform::linux::syscall_nr::EXECVE,
            SyscallKind::ProcessExec {
                path: bin.to_string_lossy().into_owned(),
                args: vec![
                    bin.to_string_lossy().into_owned(),
                    "--user".into(),
                    "--".into(),
                    "curl".into(),
                    "https://evil.example".into(),
                ],
            },
        )
    }

    fn dbus_method_call_event(pid: u32, member: &str) -> SyscallEvent {
        sample_phase_a_event(
            pid,
            crate::platform::linux::syscall_nr::WRITE,
            SyscallKind::DbusMethodCall {
                socket: "unix:/run/user/1000/bus".into(),
                destination: Some("org.freedesktop.systemd1".into()),
                interface: Some("org.freedesktop.systemd1.Manager".into()),
                member: Some(member.into()),
                path: Some("/org/freedesktop/systemd1".into()),
            },
        )
    }

    /// The end-to-end assertion for the moved enforcement point: an escalated
    /// D-Bus method call must reach the proxy, be scored by `operation-risk`,
    /// and land in the QUEUE band. Every other piece of this feature is worth
    /// nothing if the call the supervisor refuses gets auto-allowed here — and
    /// `to_tool_call_type`'s catch-all makes that the default failure mode.
    ///
    /// Uses a registry with the real `operation-risk` filter rather than the
    /// empty `allow_only_proxy`, because the QUEUE has to come from the score,
    /// not from an escalation.
    #[tokio::test]
    async fn escalated_dbus_method_call_queues_through_the_proxy() {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(
            grith_proxy::filters::operation_risk::OperationRiskFilter::new(),
        ));
        let proxy = Arc::new(SecurityProxy::new(
            registry,
            ScoringConfig::default(),
            MetaRuleEngine::new(vec![]),
        ));
        let out = run_delegation_event_with_proxy(
            dbus_method_call_event(9120, "StartTransientUnit"),
            proxy,
        )
        .await;
        assert_eq!(
            out.total_filtered_noise, 0,
            "a decoded method call is never noise"
        );
        assert_eq!(
            out.total_queued, 1,
            "an undeclared D-Bus method call must QUEUE for review"
        );

        // Negative control, so the assertion above cannot pass vacuously: with
        // no filters registered the same event is allowed. The QUEUE therefore
        // came from `operation-risk` scoring the mapped `ToolCallType`, which
        // is exactly the link that would break if the variant ever fell into
        // `to_tool_call_type`'s auto-allow catch-all.
        let unscored = run_delegation_event_with_proxy(
            dbus_method_call_event(9121, "StartTransientUnit"),
            allow_only_proxy(),
        )
        .await;
        assert_eq!(unscored.total_queued, 0);
    }

    fn connect_event(pid: u32, address: &str) -> SyscallEvent {
        sample_phase_a_event(
            pid,
            crate::platform::linux::syscall_nr::CONNECT,
            SyscallKind::NetConnect {
                address: address.to_string(),
                port: 0,
                protocol: crate::interceptor::NetProtocol::Unix,
            },
        )
    }

    #[tokio::test]
    async fn authority_delegating_spawn_queues_when_enforced() {
        let out = run_delegation_event(
            existing_binary_exec_event(9101, "systemd-run"),
            true,
            false,
            vec![],
            vec![],
            vec![],
        )
        .await;
        assert_eq!(
            out.total_queued, 1,
            "systemd-run spawn must QUEUE when enforced"
        );
        assert_eq!(out.allow_pids, vec![9101], "Log mode allows after queueing");
        assert!(out.deny_pids.is_empty());
    }

    #[tokio::test]
    async fn authority_delegating_spawn_allowed_when_flag_off() {
        let out = run_delegation_event(
            existing_binary_exec_event(9102, "systemd-run"),
            false,
            false,
            vec![],
            vec![],
            vec![],
        )
        .await;
        assert_eq!(out.total_queued, 0, "audit-only when flag off");
        assert_eq!(out.allow_pids, vec![9102]);
    }

    #[tokio::test]
    async fn authority_delegating_spawn_allowed_when_profile_permits() {
        let out = run_delegation_event(
            existing_binary_exec_event(9103, "systemd-run"),
            true,
            false,
            vec!["systemd-run".to_string()],
            vec![],
            vec![],
        )
        .await;
        assert_eq!(out.total_queued, 0, "permit list suppresses the QUEUE");
        assert_eq!(out.allow_pids, vec![9103]);
    }

    #[tokio::test]
    async fn ordinary_spawn_not_queued_when_enforced() {
        let out = run_delegation_event(
            existing_binary_exec_event(9104, "git"),
            true,
            false,
            vec![],
            vec![],
            vec![],
        )
        .await;
        assert_eq!(out.total_queued, 0, "git is not authority-delegating");
        assert_eq!(out.allow_pids, vec![9104]);
    }

    #[tokio::test]
    async fn control_socket_connect_queues_when_enforced() {
        // The load-bearing assertion: the connect must NOT be swallowed by the
        // local-IPC noise auto-allow (total_filtered_noise stays 0) and must
        // instead reach the proxy and QUEUE.
        //
        // X11 rather than the session bus: X11 carries no per-message
        // destination, so the connect stays the enforcement point for it under
        // every configuration. The D-Bus behaviour is covered separately below.
        let out = run_delegation_event(
            connect_event(9105, "unix:/tmp/.X11-unix/X0"),
            false,
            true,
            vec![],
            vec![],
            vec![],
        )
        .await;
        assert_eq!(
            out.total_filtered_noise, 0,
            "enforced control socket must bypass the local auto-allow"
        );
        assert_eq!(out.total_queued, 1, "control socket connect must QUEUE");
        assert_eq!(out.allow_pids, vec![9105]);
    }

    #[tokio::test]
    async fn dbus_connect_still_queues_with_inspection_disabled() {
        // Turning message inspection off must restore the pre-inspection
        // behaviour exactly — this is the emergency-rollback contract.
        let out = run_delegation_event(
            connect_event(9115, "unix:/run/user/1000/bus"),
            false,
            true,
            vec![],
            vec![],
            vec![],
        )
        .await;
        assert_eq!(out.total_filtered_noise, 0);
        assert_eq!(out.total_queued, 1, "session bus connect must QUEUE");
        assert_eq!(out.allow_pids, vec![9115]);
    }

    #[tokio::test]
    async fn dbus_connect_is_scored_but_not_queued_when_inspection_armed() {
        // The fix for the `gh auth token` prompt. Under the shipped default the
        // connect is still kept out of the local-IPC auto-allow — so it is
        // scored and audited exactly as before — but it no longer escalates,
        // because the authority it might carry is judged per method call.
        let out = run_delegation_event_with_dbus_inspection(
            connect_event(9116, "unix:/run/user/1000/bus"),
            false,
            true,
            vec![],
            vec![],
            vec![],
            true,
        )
        .await;
        assert_eq!(
            out.total_filtered_noise, 0,
            "the connect must still reach the proxy so it is scored and audited"
        );
        assert_eq!(
            out.total_queued, 0,
            "an inspected D-Bus connect must not prompt"
        );
        assert_eq!(out.allow_pids, vec![9116]);
    }

    #[tokio::test]
    async fn x11_still_queues_while_dbus_inspection_is_armed() {
        // Inspection must narrow only what it can actually decode. An X11
        // connect has no per-message destination, so it keeps connect-time
        // enforcement even with the D-Bus flag on.
        let out = run_delegation_event_with_dbus_inspection(
            connect_event(9117, "unix:/tmp/.X11-unix/X0"),
            false,
            true,
            vec![],
            vec![],
            vec![],
            true,
        )
        .await;
        assert_eq!(out.total_queued, 1, "X11 connect must still QUEUE");
    }

    #[tokio::test]
    async fn tmux_still_queues_while_dbus_inspection_is_armed() {
        let out = run_delegation_event_with_dbus_inspection(
            connect_event(9118, "unix:/tmp/tmux-1000/default"),
            false,
            true,
            vec![],
            vec![],
            vec![],
            true,
        )
        .await;
        assert_eq!(out.total_queued, 1, "tmux connect must still QUEUE");
    }

    #[tokio::test]
    async fn control_socket_connect_audit_only_when_flag_off() {
        let out = run_delegation_event(
            connect_event(9106, "unix:/run/user/1000/bus"),
            false,
            false,
            vec![],
            vec![],
            vec![],
        )
        .await;
        assert_eq!(
            out.total_filtered_noise, 1,
            "flag off keeps the local-IPC auto-allow"
        );
        assert_eq!(out.total_queued, 0);
        assert_eq!(out.allow_pids, vec![9106]);
    }

    #[tokio::test]
    async fn control_socket_connect_allowed_when_profile_permits() {
        let out = run_delegation_event(
            connect_event(9107, "unix:/run/user/1000/bus"),
            false,
            true,
            vec![],
            vec!["/run/user/1000/bus".to_string()],
            vec![],
        )
        .await;
        assert_eq!(
            out.total_filtered_noise, 1,
            "permitted control socket stays local-allowed"
        );
        assert_eq!(out.total_queued, 0);
    }

    #[tokio::test]
    async fn session_allowlisted_authority_binary_still_queues() {
        // Regression for the review's HIGH finding: the shipped profiles list
        // `tmux`/`docker`/`systemctl` in routine_commands, which seed the
        // session allowlist. That short-circuit runs BEFORE the escalation, so
        // without the `delegation_would_enforce` guard an authority-delegating
        // spawn already on the session allowlist would be auto-allowed and the
        // enforcement would be a silent no-op. Uses a real root-owned system
        // binary so the exec-provenance check in is_session_allowlist_match
        // actually trusts it (a /tmp temp file would be rejected as
        // world-writable and never exercise the interaction). A genuinely
        // *delegating* subcommand is used (`restart`/`new-session`/`run`) so the
        // read-only-query exemption does not apply — a bare invocation would be
        // a read-only query and correctly not escalate.
        let candidates: &[(&str, &str)] = &[
            ("/usr/bin/systemctl", "restart"),
            ("/bin/systemctl", "restart"),
            ("/usr/bin/tmux", "new-session"),
            ("/usr/bin/docker", "run"),
        ];
        let Some((bin, subcommand)) = candidates
            .iter()
            .find(|(p, _)| std::path::Path::new(p).exists())
        else {
            eprintln!("skipping: no root-owned authority-delegating binary present");
            return;
        };
        let event = sample_phase_a_event(
            9108,
            crate::platform::linux::syscall_nr::EXECVE,
            SyscallKind::ProcessExec {
                path: (*bin).to_string(),
                args: vec![(*bin).to_string(), (*subcommand).to_string()],
            },
        );
        let out = run_delegation_event(
            event,
            true, // enforce spawns
            false,
            vec![], // NOT in the permit list
            vec![],
            vec![format!("exec:{bin}")], // but IS on the session allowlist
        )
        .await;
        assert_eq!(
            out.total_queued, 1,
            "session-allowlisted authority-delegating binary must still QUEUE when enforced"
        );
        assert_eq!(
            out.total_filtered_noise, 0,
            "must not take the session-allowed auto-allow"
        );
    }

    // ---- Scope drain: queued items resolve when a scoped grant lands ----

    /// A reviewer that never answers: the prompt stays open until the review
    /// future is dropped. Records which items it was asked about and which
    /// were cancelled out-of-band.
    struct NeverAnsweringReviewer {
        seen: Arc<Mutex<Vec<Uuid>>>,
        cancelled: Arc<Mutex<Vec<Uuid>>>,
    }

    #[async_trait]
    impl QueueReviewer for NeverAnsweringReviewer {
        async fn review(&self, item: &DigestItem, _timeout: Duration) -> ReviewOutcome {
            self.seen.lock().unwrap().push(item.id);
            std::future::pending::<()>().await;
            unreachable!("pending() never resolves")
        }

        async fn cancel_review(&self, item_id: Uuid) {
            self.cancelled.lock().unwrap().push(item_id);
        }
    }

    /// The 2026-08-17 flood repair: an item queued and waiting on a prompt
    /// must resolve WITHOUT an operator answer once a scoped session grant
    /// (made on some other prompt) covers its target - status Approved with
    /// review_action `scope_drain`, syscall allowed, TUI prompt cancelled.
    #[tokio::test(start_paused = true)]
    async fn scope_drain_resolves_pending_item_when_scoped_grant_lands() {
        let tid = 4242;
        let (mock, state) = MockInterceptor::new(vec![]);
        let mut interceptor: Box<dyn SyscallInterceptor> = Box::new(mock);
        let mut session = SupervisorSession::new("mock-tool", tid);
        let proxy = allow_only_proxy();
        let audit_storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let audit_sink: Arc<dyn crate::audit_sink::AuditSink> =
            Arc::new(crate::audit_sink::StorageAuditSink::new(audit_storage));
        let digest_queue = Arc::new(grith_digest::queue::DigestQueue::open_in_memory().unwrap());
        let digest_store: Arc<dyn crate::reviewer::DigestStore> =
            Arc::new(crate::reviewer::LocalDigestStore::new(digest_queue.clone()));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let containment_tracker = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::new(
                Duration::from_secs(60),
            ),
        );
        let config = SupervisorConfig::default();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let cancelled = Arc::new(Mutex::new(Vec::new()));
        let session_allowed = Arc::new(Mutex::new(HashSet::new()));
        let loop_ctx = SupervisorLoopContext {
            proxy: &proxy,
            audit_sink,
            digest_store,
            dlp_redactor: &dlp_redactor,
            correlation_tracker: &correlation_tracker,
            containment_tracker: &containment_tracker,
            config: &config,
            event_tx: None,
            freezer: Freezer::new(Duration::from_secs(config.freeze_timeout_seconds)),
            read_batch_tracker: Mutex::new(ReadBatchTracker::new(10)),
            reviewer: Arc::new(NeverAnsweringReviewer {
                seen: seen.clone(),
                cancelled: cancelled.clone(),
            }),
            unanswered_reviews: Arc::new(AtomicU32::new(0)),
            session_sync: None,
            session_allowed: session_allowed.clone(),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_inspection_enabled: false,
            dns_decision_service: None,
            dns_forward_confirm: None,
            syscall_log: None,
            forensics_trace: None,
            reputation_table: Arc::new(Mutex::new(grith_proxy::reputation::ReputationTable::new())),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            daemon_restart: None,
            observation_outbox: Arc::new(Default::default()),
            persist_local_reputation: true,
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            workspace_roots: Vec::new(),
            session_denied: Arc::new(Mutex::new(HashSet::new())),
            workspace_boundary: None,
            local_listener_policy: Vec::new(),
            namespace_users: Vec::new(),
            permit_authority_delegating: Vec::new(),
            permit_control_sockets: Vec::new(),
            dbus_inspection_armed: false,
            authority_delegating_pins: authority_delegation::AuthorityDelegatingPins::empty(),
            working_root: None,
            mass_destruction: Mutex::new(mass_destruction::MassDestructionTracker::with_defaults()),
            yama_ptrace_scope: None,
            analytics_config: std::sync::OnceLock::new(),
        };

        let ctx = ToolCallContext::new(
            "supervisor:mock-tool",
            ToolCallType::FileDelete {
                path: "/repo/target/debug/deps/foo.o".into(),
            },
            session.id,
        );
        let decision =
            grith_proxy::types::ProxyDecision::queue(1.0, vec![], Duration::from_millis(1));

        // Run the wait alongside a grant that lands mid-review: the scoped
        // rule appears 600ms in, so the drain tick at 750ms resolves the
        // item while the reviewer is still holding its prompt open.
        let (wait_result, ()) = tokio::join!(
            queue_and_wait(
                &mut interceptor,
                &mut session,
                &loop_ctx,
                &ctx,
                &decision,
                tid,
                tid,
                Uuid::new_v4(),
                false,
                false,
            ),
            async {
                tokio::time::sleep(Duration::from_millis(600)).await;
                session_allowed
                    .lock()
                    .unwrap()
                    .insert("delete-prefix:/repo/target/debug/".to_string());
            }
        );
        wait_result.unwrap();

        let item_id = seen.lock().unwrap()[0];
        let item = digest_queue.get_by_id(&item_id).unwrap();
        assert_eq!(item.status, grith_digest::DigestStatus::Approved);
        assert_eq!(item.review_action.as_deref(), Some("scope_drain"));
        assert_eq!(
            *cancelled.lock().unwrap(),
            vec![item_id],
            "the reviewer's stale prompt must be withdrawn"
        );
        let state = state.lock().unwrap();
        assert_eq!(state.allow_pids, vec![tid], "the held syscall must resume");
        assert!(state.deny_pids.is_empty());
        assert_eq!(session.stats.total_queued, 1);
        assert_eq!(session.stats.total_denied, 0);
    }

    /// Predicate-level checks for `session_scope_now_covers` run against a
    /// minimal loop context; only `session_allowed`, `config`, and the
    /// delegation permit lists influence the result.
    fn covers_with(
        call_type: &ToolCallType,
        allowed: HashSet<String>,
        config: SupervisorConfig,
        session_id: Uuid,
    ) -> bool {
        let proxy = allow_only_proxy();
        let audit_storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let audit_sink: Arc<dyn crate::audit_sink::AuditSink> =
            Arc::new(crate::audit_sink::StorageAuditSink::new(audit_storage));
        let digest_queue = Arc::new(grith_digest::queue::DigestQueue::open_in_memory().unwrap());
        let digest_store: Arc<dyn crate::reviewer::DigestStore> =
            Arc::new(crate::reviewer::LocalDigestStore::new(digest_queue));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let containment_tracker = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::new(
                Duration::from_secs(60),
            ),
        );
        let loop_ctx = SupervisorLoopContext {
            proxy: &proxy,
            audit_sink,
            digest_store,
            dlp_redactor: &dlp_redactor,
            correlation_tracker: &correlation_tracker,
            containment_tracker: &containment_tracker,
            config: &config,
            event_tx: None,
            freezer: Freezer::new(Duration::from_secs(config.freeze_timeout_seconds)),
            read_batch_tracker: Mutex::new(ReadBatchTracker::new(10)),
            reviewer: Arc::new(PanicReviewer),
            unanswered_reviews: Arc::new(AtomicU32::new(0)),
            session_sync: None,
            session_allowed: Arc::new(Mutex::new(allowed)),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_inspection_enabled: false,
            dns_decision_service: None,
            dns_forward_confirm: None,
            syscall_log: None,
            forensics_trace: None,
            reputation_table: Arc::new(Mutex::new(grith_proxy::reputation::ReputationTable::new())),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            daemon_restart: None,
            observation_outbox: Arc::new(Default::default()),
            persist_local_reputation: true,
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            workspace_roots: Vec::new(),
            session_denied: Arc::new(Mutex::new(HashSet::new())),
            workspace_boundary: None,
            local_listener_policy: Vec::new(),
            namespace_users: Vec::new(),
            permit_authority_delegating: Vec::new(),
            permit_control_sockets: Vec::new(),
            dbus_inspection_armed: false,
            authority_delegating_pins: authority_delegation::AuthorityDelegatingPins::empty(),
            working_root: None,
            mass_destruction: Mutex::new(mass_destruction::MassDestructionTracker::with_defaults()),
            yama_ptrace_scope: None,
            analytics_config: std::sync::OnceLock::new(),
        };
        session_scope_now_covers(&loop_ctx, session_id, call_type)
    }

    /// Containment gates the drain exactly as it gates the live
    /// short-circuit: once active, a matching scoped rule must not resolve
    /// queued items - every call re-scores through the full pipeline.
    #[test]
    fn session_scope_now_covers_respects_containment() {
        let call = ToolCallType::FileDelete {
            path: "/repo/target/debug/deps/foo.o".into(),
        };
        let allowed: HashSet<String> =
            HashSet::from(["delete-prefix:/repo/target/debug/".to_string()]);

        let clean_session = Uuid::new_v4();
        assert!(covers_with(
            &call,
            allowed.clone(),
            SupervisorConfig::default(),
            clean_session
        ));

        let contained_session = Uuid::new_v4();
        SessionStateRegistry::global().activate_containment(
            SessionScopeKey::from_session_id(contained_session),
            grith_proxy::session_state::ContainmentReason::SensitiveAccessOutsideScope {
                path: "/home/u/.ssh/id_rsa".into(),
                taint_level: "critical".into(),
            },
        );
        assert!(!covers_with(
            &call,
            allowed,
            SupervisorConfig::default(),
            contained_session
        ));
    }

    /// An enforced authority-delegation call must never be drained by a
    /// session grant - mirroring `delegation_would_enforce` at the live
    /// short-circuit, which the enforcement escalation deliberately skips.
    #[test]
    fn session_scope_now_covers_never_drains_enforced_delegation() {
        // Enforced authority-delegating spawn: blocked by the guard before
        // allowlist matching is even consulted.
        let spawn = ToolCallType::ProcessSpawn {
            command: "systemd-run".into(),
            args: vec!["--user".into()],
        };
        let mut enforced = SupervisorConfig::default();
        enforced.enforce_authority_delegating_spawn = true;
        assert!(!covers_with(
            &spawn,
            HashSet::from(["exec:systemd-run".to_string()]),
            enforced,
            Uuid::new_v4()
        ));

        // Control-injection socket connect: same guard, string-matched
        // allowlist entries (exec entries need on-disk provenance, which a
        // test environment cannot satisfy, so the positive control uses the
        // socket form).
        let connect = ToolCallType::NetConnect {
            address: "unix:/tmp/tmux-1000/default".into(),
            port: 0,
        };
        let allowed: HashSet<String> =
            HashSet::from(["net:unix:/tmp/tmux-1000/default".to_string()]);

        let mut enforced = SupervisorConfig::default();
        enforced.enforce_control_socket_connect = true;
        assert!(!covers_with(
            &connect,
            allowed.clone(),
            enforced,
            Uuid::new_v4()
        ));

        let mut unenforced = SupervisorConfig::default();
        unenforced.enforce_control_socket_connect = false;
        assert!(covers_with(&connect, allowed, unenforced, Uuid::new_v4()));
    }
}
