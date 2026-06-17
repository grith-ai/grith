// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Event handling logic for the supervisor loop.
//!
//! Contains the per-syscall event handler, proxy decision enforcement,
//! digest queueing, freeze/thaw orchestration, audit record and WebSocket
//! event construction, and the digest review wait loop.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use uuid::Uuid;

use grith_audit::types::AuditRecord;
use grith_audit::CorrelationTracker;
use grith_digest::types::{
    DigestItem, DigestStatus, FilterBreakdown, ReviewOutcome, ScoreSeverity,
};
use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::session_containment::ContainmentTracker;
use grith_proxy::session_state::SessionStateRegistry;
use grith_proxy::types::{ProxyAction, SessionScopeKey, ToolCallContext, ToolCallType};
use grith_proxy::{audit_bridge, exfil};
use tokio::sync::broadcast;

use crate::config::SupervisorConfig;
use crate::dns_cache::DnsCache;
use crate::error::Result;
use crate::forensics_trace::ForensicsTraceSink;
use crate::freezer::Freezer;
use crate::interceptor::{OpenFlags, SyscallEvent, SyscallInterceptor, SyscallKind};
use crate::reviewer::{DigestStore, QueueReviewer};
use crate::session_sync::SessionSync;
use crate::syscall_map;

use super::mass_destruction;
use super::{session_state::SupervisorSession, DaemonRestartConfig};

fn session_scope_name(session: &SupervisorSession) -> &str {
    session.scope_name().unwrap_or("unknown")
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
    /// Optional session-state sync target used to keep a shared registry up to date.
    pub(super) session_sync: Option<Arc<dyn SessionSync>>,
    /// Paths approved via "learn" during this session. Auto-allowed on
    /// subsequent accesses without going through the proxy.
    pub(super) session_allowed: Mutex<HashSet<String>>,
    /// Reverse DNS cache: resolves raw IPs from `connect()` syscalls
    /// to hostnames so the egress filter can match trusted domains.
    pub(super) dns_cache: Arc<Mutex<DnsCache>>,
    /// Local port of the DNS inspection proxy, if running.
    pub(super) dns_proxy_port: Option<u16>,
    /// Receiver for DNS query events from the DNS proxy.
    pub(super) dns_query_rx:
        Option<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<crate::dns_proxy::DnsQueryEvent>>>,
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
}

pub(super) struct DaemonRestartState {
    config: DaemonRestartConfig,
    attempted: Mutex<bool>,
}

impl DaemonRestartState {
    pub(super) fn new(config: DaemonRestartConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            attempted: Mutex::new(false),
        })
    }

    fn take_attempt(&self) -> bool {
        match self.attempted.lock() {
            Ok(mut attempted) => {
                if *attempted {
                    false
                } else {
                    *attempted = true;
                    true
                }
            }
            Err(_) => false,
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
    .with_project_name(session.project_name.clone());
    record.execution_result = Some(reason.into());
    if let Err(e) = loop_ctx.audit_sink.log(record).await {
        tracing::error!(
            error = %e,
            event = event_name,
            "failed to log supervisor audit event"
        );
    }
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

    // ---- DNS proxy redirection: rewrite port 53 to DNS proxy ----
    // This MUST run before to_tool_call_type mapping because NetSendTo
    // (used by UDP DNS) maps to None and would be auto-allowed as noise,
    // bypassing the DNS proxy entirely.
    {
        let port = match &event.kind {
            SyscallKind::NetConnect { port, .. } | SyscallKind::NetSendTo { port, .. } => {
                Some(*port)
            }
            _ => None,
        };

        // Block DNS-over-TLS (port 853) to force DNS through our proxy
        if port == Some(853) {
            if let Some(dns_port) = loop_ctx.dns_proxy_port {
                tracing::debug!(tid, dns_proxy_port = dns_port, "blocking DoT (port 853)");
                if let Err(e) = interceptor.deny(tid).await {
                    tracing::warn!(error = %e, tid, "deny (DoT block) failed");
                }
                return Ok(());
            }
        }

        // Redirect port-53 traffic to the DNS proxy. Fail closed if we cannot
        // safely rewrite the destination sockaddr.
        if port == Some(53) {
            if let Some(dns_port) = loop_ctx.dns_proxy_port {
                let Some(sockaddr) = event.sockaddr_addr else {
                    tracing::warn!(tid, "missing sockaddr pointer for port-53 syscall; denying");
                    if let Err(e) = interceptor.deny(tid).await {
                        tracing::warn!(error = %e, tid, "deny (missing DNS sockaddr) failed");
                    }
                    return Ok(());
                };

                if let Err(e) = interceptor
                    .rewrite_sockaddr_port(tid, sockaddr, dns_port)
                    .await
                {
                    tracing::warn!(error = %e, tid, "DNS proxy sockaddr rewrite failed; denying");
                    if let Err(deny_err) = interceptor.deny(tid).await {
                        tracing::warn!(error = %deny_err, tid, "deny (DNS rewrite failure) failed");
                    }
                    return Ok(());
                }

                tracing::debug!(
                    tid,
                    dns_proxy_port = dns_port,
                    "redirected port-53 to DNS proxy"
                );
                if let Err(e) = interceptor.allow(tid).await {
                    tracing::warn!(error = %e, tid, "allow (DNS redirect) failed");
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
            SyscallKind::OwnershipChange { .. }
            | SyscallKind::FilesystemMutation { .. }
            | SyscallKind::CrossProcessAccess { .. } => !coverage.category2_proxy,
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
        // operation_risk filter scores NamespaceOp at +5.0 → QUEUE.
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

        // H2 Option 4 (audit-only): spawning an authority-delegating binary
        // (docker/kubectl/tmux/systemctl/dbus-send/…) — its effect runs in a
        // privileged or unsupervised peer, outside the supervised tree. Log it
        // for the FP-budget measurement; enforce-mode scoring is the follow-up.
        if is_authority_delegating_binary(command) {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                event.pid,
                Some(&call_type),
                "authority_delegating_spawn",
                Some("audit-only-allow"),
                None,
                Some("spawn of an authority-delegating binary (effect runs in a privileged peer)"),
            );
            tracing::debug!(
                command = %command,
                tid,
                "authority-delegating binary spawn (audit-only)"
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
        let is_local = match &call_type {
            grith_proxy::types::ToolCallType::NetConnect { address, .. } => {
                is_local_connect_address(address)
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
                    ))
            }
            grith_proxy::types::ToolCallType::NetListen { address, .. } => {
                is_local_listen_address(address)
            }
            _ => false,
        };
        // H2 Option 2 (audit-only): a connect to a control-injection IPC
        // socket (tmux/screen/X11/session-D-Bus) is local IPC but can drive a
        // more-privileged peer. Log it for the FP-budget measurement; the
        // connect is still allowed (the enforce-mode route-to-proxy is the
        // follow-up, after the FP budget is measured).
        if let grith_proxy::types::ToolCallType::NetConnect { address, .. } = &call_type {
            if is_control_injection_socket(address) {
                write_forensics_stage(
                    loop_ctx,
                    trace_event_id,
                    session,
                    event.pid,
                    Some(&call_type),
                    "control_socket_connect",
                    Some("audit-only-allow"),
                    None,
                    Some("connect to a control-injection IPC socket (tmux/screen/X11/D-Bus)"),
                );
                tracing::debug!(
                    address = %address,
                    tid,
                    "control-injection IPC socket connect (audit-only)"
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
            let resolved = loop_ctx
                .dns_cache
                .lock()
                .map(|mut cache| cache.resolve(&address))
                .unwrap_or_else(|_| address.clone());
            grith_proxy::types::ToolCallType::NetConnect {
                address: resolved,
                port,
            }
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

    // Optional noise path check (e.g., reads of /proc/, /sys/, etc.).
    if let Some(path) = ToolCallContext::new("", call_type.clone(), session.id).path() {
        if syscall_map::is_noise_path(path) {
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
            SyscallKind::FileOpen {
                flags: OpenFlags::ReadOnly,
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
                        && path.starts_with(prefix.as_str())
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
    if !containment_active {
        if let Some(key) = session_allowlist_key(&call_type) {
            if loop_ctx
                .session_allowed
                .lock()
                .is_ok_and(|s| is_session_allowlist_match(&key, &s, &call_type))
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

    // (The `scratch_root_match` proxy-argument flag that used to be set here was
    // retired with the rate_limit scratch/`.git`/`~/.cache` burst exemptions —
    // risk-gating now subsumes that carve-out. `scratch_roots` is still used by
    // the mass-destruction signal below.)

    // PR 4 Phase D: compute SpawnProvenance for ProcessSpawn so
    // operation_risk's routine signal can consult it. Skipped on
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
    // local_listener_policy so egress_policy knows whether to queue,
    // pass through (loopback), or clamp (wildcard + allow_clamp).
    //
    // PR 5 Phase D: also propagate the tracee-side sockaddr pointer
    // + addrlen from the originating SyscallKind into ctx.arguments
    // so the allow path can rewrite the bind in place if the
    // listener policy authorises a clamp.
    if let grith_proxy::types::ToolCallType::NetListen { address, port } = &ctx.call_type {
        ctx.listener_policy_match =
            match_listener_policy(&loop_ctx.local_listener_policy, address, *port);
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
    let mut decision = evaluate_proxy(loop_ctx, &ctx).await;

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

    // Check if reputation would auto-allow this operation. A mass-destruction
    // escalation must not be auto-allowed away, so it bypasses this block.
    if loop_ctx.daemon_proxy_url.is_none()
        && !mass_destruction_escalated
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
                );
                if let Err(e) = loop_ctx.audit_sink.log(audit_record).await {
                    tracing::error!(
                        error = %e,
                        "failed to log reputation auto-allow audit record"
                    );
                }
                session.stats.total_allowed += 1;
                return Ok(());
            }
        }
    }

    enforce_decision(
        interceptor,
        session,
        loop_ctx,
        &ctx,
        &decision,
        tid,
        event.pid,
        trace_event_id,
    )
    .await?;

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
    );
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
async fn enforce_decision(
    interceptor: &mut Box<dyn SyscallInterceptor>,
    session: &mut SupervisorSession,
    loop_ctx: &SupervisorLoopContext<'_>,
    ctx: &ToolCallContext,
    decision: &grith_proxy::types::ProxyDecision,
    tid: u32,
    event_pid: u32,
    trace_event_id: Uuid,
) -> Result<()> {
    match &decision.action {
        ProxyAction::Allow => {
            // PR 5 Phase D: opportunistic wildcard-to-loopback clamp.
            // When NetListen got an Allow despite being a wildcard
            // bind, that means a `local_listener_policy` entry with
            // `allow_clamp = true` matched (egress_policy silently
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
                return Ok(());
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

            Ok(())
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
                    return Ok(());
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
                    return Ok(());
                }
            }

            // In "log" mode, allow the syscall and log it as informational
            // instead of freezing the process tree for a blocking dialog.
            // This keeps interactive TUI tools running uninterrupted.
            if loop_ctx.config.interactive_queue_action
                == crate::config::InteractiveQueueAction::Log
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
                return Ok(());
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
            if let Err(e) = interceptor.deny(tid).await {
                tracing::warn!(error = %e, tid, "deny failed");
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
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Queue + freeze/thaw orchestration
// ---------------------------------------------------------------------------

async fn queue_and_wait(
    interceptor: &mut Box<dyn SyscallInterceptor>,
    session: &mut SupervisorSession,
    loop_ctx: &SupervisorLoopContext<'_>,
    ctx: &ToolCallContext,
    decision: &grith_proxy::types::ProxyDecision,
    tid: u32,
    event_pid: u32,
    trace_event_id: Uuid,
) -> Result<()> {
    let dlp_redactor = loop_ctx.dlp_redactor;
    let containment_tracker = &loop_ctx.containment_tracker;
    let config = loop_ctx.config;
    // The intercepted thread is already held at its ptrace/seccomp stop —
    // no SIGSTOP needed. We intentionally do NOT freeze the rest of the
    // process tree so that the supervised tool (e.g. Ink/Node.js) keeps
    // rendering while the single syscall thread awaits a permission decision.

    // Enqueue a digest item for human review.
    let digest_item = build_digest_item(ctx, decision, dlp_redactor);
    let digest_id = digest_item.id;
    if let Err(e) = loop_ctx.digest_store.enqueue(&digest_item).await {
        tracing::error!(error = %e, "failed to enqueue digest item");
    }

    session.stats.total_queued += 1;

    // Wait for approval/denial (or timeout) before resuming the syscall.
    let outcome = loop_ctx
        .reviewer
        .review(
            &digest_item,
            Duration::from_secs(config.freeze_timeout_seconds),
        )
        .await;

    // Retrieve the stored review action to dispatch side-effects.
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

    match outcome {
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
            // Add the approved path/address to the session allowlist so
            // subsequent accesses bypass the proxy. Both "approve" and
            // "approve_and_learn" benefit from this — the difference is that
            // "learn" also records a reputation observation for long-term trust.
            if let Some(key) = approved_session_allowlist_entry(&ctx.call_type) {
                if let Ok(mut allowed) = loop_ctx.session_allowed.lock() {
                    let is_learn = review_action.as_deref() == Some("approve_and_learn");
                    if is_learn {
                        tracing::info!(key, "session allowlist: learned (persisted)");
                    } else {
                        tracing::info!(key, "session allowlist: approved");
                    }
                    allowed.insert(key.clone());

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
                            let event = serde_json::json!({
                                "session_id": session.id.to_string(),
                                "tool_name": session.tool_name,
                                "call_type": format!("Learned: {key}"),
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
            thaw_and_resume(interceptor, session, tid, true).await;
        }
        ReviewOutcome::Denied | ReviewOutcome::TimedOut => {
            let reason = if matches!(outcome, ReviewOutcome::TimedOut) {
                "timeout"
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
            thaw_and_resume(interceptor, session, tid, false).await;
            session.stats.total_denied += 1;
        }
    }

    Ok(())
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
            // Persist the learned rule to disk.
            if let Some(profile) = profile_scope {
                if let Some(entry) = approved_session_allowlist_entry(&ctx.call_type) {
                    if crate::learned_rules::validate_persisted_rule(&entry).is_ok() {
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
                                            !a.starts_with('-')
                                                && (a.contains('@') || a.contains('.'))
                                        })
                                    });
                                match target {
                                    Some(t) => format!("{proc} → {t}"),
                                    None => proc.to_string(),
                                }
                            })
                            .unwrap_or_default();

                        let rule = crate::learned_rules::LearnedRule {
                            pattern: entry.clone(),
                            profile: profile.to_string(),
                            scope: "user".to_string(),
                            reason,
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
) {
    // No SIGCONT needed — child processes were never frozen.
    // Resume the stopped thread using its TID.
    let result = if allow {
        interceptor.allow(tid).await
    } else {
        interceptor.deny(tid).await
    };
    if let Err(e) = result {
        let msg = if allow {
            "allow after approval failed"
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

/// Handle a DNS query event from the DNS inspection proxy.
///
/// Builds a `ToolCallType::DnsQuery`, evaluates it through the security proxy,
/// and sends the decision back to the DNS proxy.
pub(super) async fn handle_dns_query_event(
    session: &mut SupervisorSession,
    loop_ctx: &SupervisorLoopContext<'_>,
    query_event: crate::dns_proxy::DnsQueryEvent,
) {
    let trace_event_id = Uuid::new_v4();
    let call_type = grith_proxy::types::ToolCallType::DnsQuery {
        domain: query_event.domain.clone(),
        query_type: query_event.query_type.clone(),
    };

    if let Some(trace) = &loop_ctx.forensics_trace {
        trace.capture_dns_query(
            trace_event_id,
            session.id,
            session.root_pid,
            &session.process_tree,
            session.root_pid,
            &call_type,
        );
    }

    // Session allowlist check: DNS queries for domains in the profile's
    // routine_destinations should be auto-allowed without hitting the proxy.
    if let Some(key) = session_allowlist_key(&call_type) {
        if loop_ctx
            .session_allowed
            .lock()
            .is_ok_and(|s| is_session_allowlist_match(&key, &s, &call_type))
        {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                session.root_pid,
                Some(&call_type),
                "session_allowed",
                Some("auto-allow"),
                None,
                Some("session allowlist"),
            );
            session.stats.total_filtered_noise += 1;
            tracing::debug!(
                domain = query_event.domain,
                query_type = query_event.query_type,
                "DNS query auto-allowed (session allowlist)"
            );
            let _ = query_event
                .response_tx
                .send(crate::dns_proxy::DnsDecision::Forward);
            return;
        }
    }

    let plugin_id = format!("supervisor:{}", session.tool_name);
    let mut ctx = ToolCallContext::new(plugin_id, call_type, session.id);
    ctx.profile_name = session.profile_name.clone();
    ctx.task_context = session.project_name.clone();
    ctx.arguments = supervisor_event_arguments(session, session.root_pid, &ctx.call_type);

    let decision = evaluate_proxy(loop_ctx, &ctx).await;

    let dns_decision = match &decision.action {
        ProxyAction::Deny { reason } => {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                session.root_pid,
                Some(&ctx.call_type),
                "proxy_scored",
                Some("auto-deny"),
                Some(decision.composite_score),
                Some(reason),
            );
            tracing::warn!(
                domain = query_event.domain,
                query_type = query_event.query_type,
                score = decision.composite_score,
                reason = %reason,
                "DNS query DENIED"
            );
            session.stats.total_denied += 1;
            crate::dns_proxy::DnsDecision::Refuse
        }
        ProxyAction::Queue { .. } => {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                session.root_pid,
                Some(&ctx.call_type),
                "proxy_scored",
                Some("queue"),
                Some(decision.composite_score),
                Some(&decision.decision_reason),
            );
            tracing::info!(
                domain = query_event.domain,
                query_type = query_event.query_type,
                score = decision.composite_score,
                "DNS query QUEUED for review (forwarding query)"
            );
            let digest_item = build_digest_item(&ctx, &decision, loop_ctx.dlp_redactor);
            if let Err(e) = loop_ctx.digest_store.enqueue(&digest_item).await {
                tracing::error!(error = %e, "failed to enqueue DNS digest item");
            } else {
                session.stats.total_queued += 1;
            }
            crate::dns_proxy::DnsDecision::Forward
        }
        ProxyAction::Allow => {
            write_forensics_stage(
                loop_ctx,
                trace_event_id,
                session,
                session.root_pid,
                Some(&ctx.call_type),
                "proxy_scored",
                Some("auto-allow"),
                Some(decision.composite_score),
                Some(&decision.decision_reason),
            );
            tracing::debug!(
                domain = query_event.domain,
                query_type = query_event.query_type,
                score = decision.composite_score,
                "DNS query allowed"
            );
            crate::dns_proxy::DnsDecision::Forward
        }
    };

    // Audit log the DNS query (no reputation context for DNS)
    let audit_record = build_audit_record(
        &ctx,
        &decision,
        session,
        0, // No specific PID for DNS queries
        loop_ctx.dlp_redactor,
        None,
        None,
    );
    if let Err(e) = loop_ctx.audit_sink.log(audit_record).await {
        tracing::error!(error = %e, "failed to log DNS audit record");
    }

    // Send decision back to the DNS proxy
    let _ = query_event.response_tx.send(dns_decision);
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
        match remote_proxy_evaluate(url, &current_token, ctx).await {
            Ok(decision) => return decision,
            Err(e) => {
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
                                match remote_proxy_evaluate(url, &new_token, ctx).await {
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

fn daemon_unreachable_decision(error: String) -> grith_proxy::types::ProxyDecision {
    grith_proxy::types::ProxyDecision {
        action: grith_proxy::types::ProxyAction::Deny {
            reason: "daemon_unreachable".to_string(),
        },
        composite_score: f64::INFINITY,
        filter_results: Vec::new(),
        evaluation_time: std::time::Duration::from_secs(0),
        decision_reason: format!("Daemon unreachable; operation denied for safety: {error}"),
    }
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

/// Call the daemon's proxy evaluate endpoint via HTTP.
async fn remote_proxy_evaluate(
    base_url: &str,
    token: &str,
    ctx: &grith_proxy::types::ToolCallContext,
) -> std::result::Result<grith_proxy::types::ProxyDecision, String> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base_url}/api/proxy/evaluate"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "context": ctx }))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("daemon returned {status}: {body}"));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("response parse failed: {e}"))?;

    // Parse the response into a ProxyDecision.
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
                    Some(grith_proxy::types::FilterResult {
                        filter_name: fr["filter_name"].as_str()?.to_string(),
                        matched: fr["matched"].as_bool()?,
                        score: fr["score"].as_f64()?,
                        rule_id: String::new(),
                        severity: grith_proxy::types::Severity::Notice,
                        message: String::new(),
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

/// H2 Option 2 (audit-only): control-injection IPC sockets — a connect here
/// drives a more-privileged peer that can run commands on the tool's behalf
/// (tmux/screen pane injection, X11 input synthesis, session D-Bus method
/// calls). These are currently auto-allowed as local IPC; we log connects to
/// them for FP-budget measurement. (ssh-agent / gpg-agent are already covered
/// by `is_sensitive_unix_socket` and route to the proxy.)
fn is_control_injection_socket(address: &str) -> bool {
    let path = address
        .strip_prefix("unix:")
        .unwrap_or(address)
        .to_ascii_lowercase();
    const MARKERS: &[&str] = &["/tmux-", "/.x11-unix/", "/screen", "/dbus"];
    MARKERS.iter().any(|m| path.contains(m))
        || (path.starts_with("/run/user/") && path.ends_with("/bus")) // session D-Bus
}

/// H2 Option 4 (audit-only): authority-delegating binaries — their effect is
/// executed by a privileged or unsupervised peer (a daemon, the init system,
/// the session bus, an `at`/`cron` queue) rather than in the supervised tree.
/// Spawns are logged for FP-budget measurement; enforce-mode scoring is the
/// follow-up. Curation is security-relevant — additions should be reviewed.
fn is_authority_delegating_binary(command: &str) -> bool {
    let b = std::path::Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command);
    matches!(
        b,
        "docker"
            | "podman"
            | "nerdctl"
            | "kubectl"
            | "tmux"
            | "screen"
            | "systemctl"
            | "systemd-run"
            | "dbus-send"
            | "gdbus"
            | "busctl"
            | "at"
            | "batch"
            | "crontab"
            | "flatpak"
            | "nsenter"
            | "machinectl"
            | "loginctl"
    )
}

/// Returns `true` if `path` is a sensitive Unix socket that grants container
/// runtime control and must not be silently allowed.
fn is_sensitive_unix_socket(path: &str) -> bool {
    if SENSITIVE_UNIX_SOCKETS.contains(&path) {
        return true;
    }
    // Covers /run/user/<uid>/podman/podman.sock for any user ID.
    if path.contains("podman.sock") {
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
/// *network* connection, which `egress_policy` scores independently. So when a
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
///      egress_policy silently passed it through; we now rewrite the
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
        let port_ok = e.port == 0 || e.port == port;
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

/// returns the address (without port) so that approving one connection to a
/// host implicitly allows subsequent connections to the same host on any port.
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
        ToolCallType::OwnershipChange { target, .. }
        | ToolCallType::FilesystemMutation { target, .. } => Some(target.clone()),
        ToolCallType::NetConnect { address, .. } | ToolCallType::NetListen { address, .. } => {
            Some(format!("net:{address}"))
        }
        ToolCallType::ProcessSpawn { command, .. } => Some(format!("exec:{command}")),
        ToolCallType::DnsQuery { domain, .. } => Some(format!("dns:{domain}")),
        _ => None,
    }
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
        _ => session_allowlist_key(call_type),
    }
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

/// Return whether a session allowlist entry matches a syscall key.
///
/// Matching rules:
/// - `net:` / `dns:` keys use DNS suffix matching with label boundaries only
/// - `exec:` keys check exact match first, then `exec-prefix:` entries with
///   provenance verification (canonical path + ownership/permission checks)
/// - filesystem paths use exact or prefix matching
/// - `exec-prefix:` entries ONLY match `exec:` keys (namespace isolation)
/// - `ro:` entries use exact match only and only match `FileRead` operations
fn is_session_allowlist_match(
    key: &str,
    allowed: &HashSet<String>,
    call_type: &grith_proxy::types::ToolCallType,
) -> bool {
    // Subdomain matching for network destinations: both `net:` and `dns:`
    // keys match against `net:` allowlist entries, so `dns:api.anthropic.com`
    // matches `net:anthropic.com`.
    let net_domain = key
        .strip_prefix("net:")
        .or_else(|| key.strip_prefix("dns:"));
    if let Some(domain) = net_domain {
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

    if allowed.contains(key) {
        return true;
    }

    // Prefix matching for bare-path entries. Exclude namespaced entries
    // to prevent namespace leakage.
    allowed.iter().any(|prefix| {
        !prefix.starts_with("exec-prefix:")
            && !prefix.starts_with("ro:")
            && !prefix.starts_with("ro-glob:")
            && !prefix.starts_with("rw:")
            && key.starts_with(prefix.as_str())
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
    .with_project_name(session.project_name.clone());

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
            fr.filter_name == "operation_risk"
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
                .filter(|fr| fr.matched && fr.score > 0.0 && fr.filter_name != "operation_risk")
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
    use std::time::Duration;

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
            sockaddr_addr: None,
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
                "path_match",
                "ssh-key",
                5.0,
                Severity::Critical,
                "SSH key access",
            ),
            FilterResult::no_match("allowlist"),
        ];

        let summaries = audit_bridge::to_filter_summaries(&results);
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].filter_name, "path_match");
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
            FilterResult::no_match("path_match"),
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
            session_sync: None,
            session_allowed: Mutex::new(HashSet::new()),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_proxy_port: None,
            dns_query_rx: None,
            syscall_log: None,
            forensics_trace: None,
            reputation_table: Arc::new(Mutex::new(grith_proxy::reputation::ReputationTable::new())),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            daemon_restart: None,
            persist_local_reputation: true,
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            local_listener_policy: Vec::new(),
            namespace_users: Vec::new(),
            working_root: None,
            mass_destruction: Mutex::new(mass_destruction::MassDestructionTracker::with_defaults()),
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
            sockaddr_addr: None,
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
            session_sync: None,
            session_allowed: Mutex::new(HashSet::new()),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_proxy_port: None,
            dns_query_rx: None,
            syscall_log: None,
            forensics_trace: None,
            reputation_table: Arc::new(Mutex::new(grith_proxy::reputation::ReputationTable::new())),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            daemon_restart: None,
            persist_local_reputation: true,
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            local_listener_policy: Vec::new(),
            namespace_users: Vec::new(),
            working_root: None,
            mass_destruction: Mutex::new(mass_destruction::MassDestructionTracker::with_defaults()),
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
            crate::platform::linux::syscall_nr::IOPL,
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
            crate::platform::linux::syscall_nr::IOPERM,
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
            session_sync: None,
            session_allowed: Mutex::new(HashSet::new()),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_proxy_port: None,
            dns_query_rx: None,
            syscall_log: None,
            forensics_trace: None,
            reputation_table: Arc::new(Mutex::new(grith_proxy::reputation::ReputationTable::new())),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            daemon_restart: None,
            persist_local_reputation: true,
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            local_listener_policy: Vec::new(),
            namespace_users: Vec::new(),
            working_root: None,
            mass_destruction: Mutex::new(mass_destruction::MassDestructionTracker::with_defaults()),
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
                crate::platform::linux::syscall_nr::CHOWN,
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

    // -- session allowlist matching tests ----------------------------------

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    // Helper: create a dummy ToolCallType for tests that don't care about
    // the operation type (exec, net tests).
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

    // -----------------------------------------------------------------------
    // H2 Options 2 & 4: control-injection sockets + authority-delegating bins.
    // -----------------------------------------------------------------------

    #[test]
    fn control_injection_socket_recognised() {
        for addr in [
            "unix:/tmp/tmux-1000/default",
            "unix:/tmp/.X11-unix/X0",
            "unix:/run/screen/S-user/12345.pts-0",
            "unix:/run/user/1000/bus",
            "unix:/run/user/1000/dbus/session_bus_socket",
        ] {
            assert!(is_control_injection_socket(addr), "{addr:?} should match");
        }
        for addr in [
            "unix:/var/run/nscd/socket",
            "unix:/run/user/1000/gnupg/S.gpg-agent", // agent socket: handled elsewhere
            "127.0.0.1",
        ] {
            assert!(
                !is_control_injection_socket(addr),
                "{addr:?} should NOT match"
            );
        }
    }

    #[test]
    fn authority_delegating_binary_recognised() {
        for cmd in [
            "/usr/bin/docker",
            "kubectl",
            "/usr/bin/tmux",
            "systemctl",
            "dbus-send",
            "crontab",
        ] {
            assert!(is_authority_delegating_binary(cmd), "{cmd:?} should match");
        }
        for cmd in ["/bin/ls", "cat", "/usr/bin/git", "node"] {
            assert!(
                !is_authority_delegating_binary(cmd),
                "{cmd:?} should NOT match"
            );
        }
    }
}
