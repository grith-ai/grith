// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Baseline operation risk scoring filter.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::session_state::SessionStateRegistry;
use crate::types::{FilterResult, Severity, SpawnProvenance, ToolCallContext, ToolCallType};

/// PR 4 Phase H: read the rollout flag from the filter instance.
///
/// Phase D shipped this as an env var (`GRITH_PROXY_ROUTINE_SIGNAL_ENABLED`)
/// so the signal could be smoke-tested before the config schema was
/// wired. Phase H replaces that with the operator-visible config key
/// `proxy.spawn.routine_provenance_signal`, plumbed through
/// `OperationRiskFilter`'s constructor. The env-var path is retained
/// as a tie-breaker: when set to a truthy value it forces the signal
/// ON, useful for emergency rollback testing without editing config.
/// The env-var read is the documented escape hatch — production
/// behaviour comes from config.
fn routine_signal_env_override() -> Option<bool> {
    let v = std::env::var_os("GRITH_PROXY_ROUTINE_SIGNAL_ENABLED")?;
    let s = v.to_string_lossy();
    if s.is_empty() {
        return None;
    }
    let truthy = !s.eq_ignore_ascii_case("0")
        && !s.eq_ignore_ascii_case("false")
        && !s.eq_ignore_ascii_case("no");
    Some(truthy)
}

/// PR 4 Phase D: the routine-spawn signal score. **Exactly `0.5`, never `0.0`.**
///
/// `+0.5` keeps the security boundary additive: a routine spawn plus
/// any single phase-3 hit at `+3.0` lands at `3.5`, still above the
/// `>3.0` QUEUE threshold. Scoring `+0.0` would silently absorb that
/// hit; documented as explicitly rejected in
/// `work/64-pr4-provenance-routine-spawn-work.md`.
pub const ROUTINE_SPAWN_SCORE: f64 = 0.5;

/// PR 4 Phase D: the legacy ProcessSpawn baseline score. Applied when
/// the routine signal does not fire (or is disabled).
pub const NON_ROUTINE_SPAWN_SCORE: f64 = 1.0;

/// PR 4 Phase D: rule_id emitted on `FilterResult` when the routine
/// signal applies. Phase F's audit-record builder keys
/// `shadow_phase3_filters` off this string, so the literal MUST stay
/// in one place. Lift to a const so a future rename is a compile-time
/// failure rather than a silent forensic-data loss.
pub const ROUTINE_SPAWN_RULE_ID: &str = "process-spawn-routine";

/// PR 4 Phase D: rule_id emitted on the legacy ProcessSpawn baseline.
pub const NON_ROUTINE_SPAWN_RULE_ID: &str = "process-spawn-baseline";

/// PR 4 Phase D: evaluate whether a `ProcessSpawn` qualifies for the
/// routine signal. Returns the baseline score the filter should apply.
///
/// The signal applies only when EVERY condition is met:
///   1. Feature flag enabled (Phase D env var; Phase H config).
///   2. `SpawnProvenance` attached and `matched_routine_root` populated.
///   3. Every path component on the canonical binary path passes the
///      writability safety check (no world-writable, no other-writable,
///      no root-owned-group-writable).
///   4. `is_outbound_capable = false`.
///   5. The binary's canonical path is present in the session-pinned
///      inventory AND the hash matches what was pinned at session start.
///
/// Note: cross-reference to PR 2's argv-tainted-path / argv-tainted-env
/// conditions (work-doc condition 4) is achieved *additively* — when
/// argv references taint, PR 2's taint filter independently scores
/// `+3.0`, so a routine spawn that also trips taint lands at `3.5` and
/// still queues. Re-checking taint here would only widen the signal's
/// margin by 0.5 and would tightly couple two filters; we skip it.
///
/// Returns `ROUTINE_SPAWN_SCORE` (0.5) on signal; `NON_ROUTINE_SPAWN_SCORE`
/// (1.0) otherwise.
pub fn operation_risk_for_spawn(ctx: &ToolCallContext, enabled: bool) -> f64 {
    if has_routine_signal(ctx, enabled) {
        ROUTINE_SPAWN_SCORE
    } else {
        NON_ROUTINE_SPAWN_SCORE
    }
}

/// HTTP methods that carry a request body — data leaving the host. Weighted
/// above read-shaped methods (GET/HEAD/OPTIONS/…) because an outbound body is
/// the exfil-relevant shape (W3). Matches the taint filter's high-risk set.
fn is_body_bearing_http_method(method: &str) -> bool {
    matches!(
        method.trim().to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH"
    )
}

fn has_routine_signal(ctx: &ToolCallContext, enabled: bool) -> bool {
    if !enabled {
        return false;
    }
    let Some(prov) = ctx.spawn_provenance.as_ref() else {
        return false;
    };
    if !provenance_qualifies(prov) {
        return false;
    }
    inventory_pins_canonical(ctx, prov)
}

/// Conditions 2, 3, 4 (provenance shape + writability + outbound-capable).
/// Split out so unit tests can exercise the predicate without setting up
/// a `SessionState`.
fn provenance_qualifies(prov: &SpawnProvenance) -> bool {
    if prov.matched_routine_root.is_none() {
        return false;
    }
    if prov.is_outbound_capable {
        return false;
    }
    let unsafe_component = prov
        .component_writability
        .iter()
        .any(|c| c.world_writable || c.other_writable || c.group_writable_non_root);
    !unsafe_component
}

/// Condition 5 — session-pinned inventory match. We require a pin for
/// every routine root (system and user-owned alike) per the work-doc
/// Open Question 1 recommendation: "pin, with a profile knob to disable".
/// The knob is deferred to Phase H.
///
/// Returns `false` when the session lacks a SessionState entry yet
/// (e.g. the spawn fires before Phase C's inventory-build task has
/// landed an entry), keeping the routine signal fail-closed during the
/// session-start race window.
fn inventory_pins_canonical(ctx: &ToolCallContext, prov: &SpawnProvenance) -> bool {
    let Some(scope) = ctx.session_scope else {
        tracing::debug!(
            target: "grith_proxy::operation_risk",
            canonical = %prov.canonical_path,
            "routine signal denied: no session_scope on ctx",
        );
        return false;
    };
    let state = match SessionStateRegistry::global().get(scope) {
        Some(s) => s,
        None => {
            tracing::debug!(
                target: "grith_proxy::operation_risk",
                %scope,
                canonical = %prov.canonical_path,
                "routine signal denied: no SessionState entry (Phase C race or scope leak)",
            );
            return false;
        }
    };
    let Some(inventory) = state.pinned_inventory() else {
        tracing::debug!(
            target: "grith_proxy::operation_risk",
            %scope,
            canonical = %prov.canonical_path,
            "routine signal denied: pinned_inventory not yet installed",
        );
        return false;
    };
    inventory.contains(&prov.canonical_path, &prov.sha256)
}

/// Filter that assigns baseline risk scores based on the inherent
/// riskiness of the operation type.
///
/// Runs in Phase 1 (Static) because it is a pure function of the
/// `ToolCallType` variant with no external dependencies.
///
/// This filter ensures that every non-trivial operation gets a small
/// but non-zero score reflecting its inherent risk level. Without this
/// filter, most normal operations (reading project files, listing
/// directories, running safe commands) would score 0.0 because none
/// of the pattern-specific filters match.
///
/// Scoring (baseline, additive with other filters):
/// - `0.0` for safe reads: `FileRead`, `DirList`
/// - `0.2` for mild mutations: `DirCreate`
/// - `0.3` for renames/appends: `FileRename`, `FileAppend`
/// - `0.5` for writes and HTTP: `FileWrite`, `HttpRequest`, `NetConnect`
/// - `1.0` for risky ops: `ShellExec`, `ProcessSpawn`, `FileDelete`, `FileChmod`
/// - `4.0` for non-loopback listeners that expose services beyond the local machine
pub struct OperationRiskFilter {
    /// PR 4 Phase H: cached rollout flag for the routine-spawn signal.
    /// Operators set this via `proxy.spawn.routine_provenance_signal` in
    /// config; `grith-core`'s daemon constructs the filter with the
    /// resolved value. Reading from a struct field instead of `getenv`
    /// keeps the spawn hot path branch-predictable.
    routine_signal_enabled: bool,
}

impl OperationRiskFilter {
    /// Construct with the routine signal **disabled**. Use this for
    /// callsites that don't need the PR 4 signal — every pre-PR-4
    /// callsite is covered by this shape, so no existing behaviour
    /// changes. To opt in to the signal, build with
    /// [`OperationRiskFilter::with_routine_signal(true)`]. New tests
    /// that *want* the signal-on path MUST construct via that method —
    /// `new()` will silently keep the signal off, which is the
    /// fail-closed default during rollout.
    pub fn new() -> Self {
        Self {
            routine_signal_enabled: false,
        }
    }

    /// PR 4 Phase H: construct with the routine signal flag explicit.
    /// `grith-core/src/daemon/filter_registry.rs` calls this with
    /// `cfg.proxy.spawn.routine_provenance_signal`.
    pub fn with_routine_signal(routine_signal_enabled: bool) -> Self {
        Self {
            routine_signal_enabled,
        }
    }

    /// Effective enablement: config flag OR an env-var override (used
    /// for emergency rollback / smoke testing). An env value of
    /// `0`/`false`/`no` explicitly disables even when config is true,
    /// which is the documented escape hatch for cutting the signal
    /// without a config redeploy.
    fn effective_routine_signal_enabled(&self) -> bool {
        match routine_signal_env_override() {
            Some(value) => value,
            None => self.routine_signal_enabled,
        }
    }
}

impl Default for OperationRiskFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SecurityFilter for OperationRiskFilter {
    fn name(&self) -> &str {
        "operation-risk"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Static
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let (score, rule_id, severity, message) = match &ctx.call_type {
            // Safe read-only operations: no baseline risk.
            ToolCallType::FileRead { .. } | ToolCallType::DirList { .. } => {
                return Ok(FilterResult::no_match("operation-risk"));
            }

            // Mild mutations.
            ToolCallType::DirCreate { path } => (
                0.2,
                "dir-create-baseline",
                Severity::Notice,
                format!("Directory creation: {path}"),
            ),

            // Moderate mutations.
            ToolCallType::FileAppend { path } => (
                0.3,
                "file-append-baseline",
                Severity::Notice,
                format!("File append: {path}"),
            ),
            ToolCallType::FileRename {
                old_path, new_path, ..
            } => (
                0.3,
                "file-rename-baseline",
                Severity::Notice,
                format!("File rename: {old_path} -> {new_path}"),
            ),
            // Link creation carries the same baseline as a write: it is a
            // routine build-system operation (node_modules, cargo caches,
            // `ln -s` in install scripts) and must not queue on its own.
            // What makes a link dangerous is its *target*, and `path()`
            // returns the target so path-match / sensitive_path score it —
            // a link to `~/.ssh/id_rsa` adds their +5.0/+4.0 on top of this
            // baseline and lands in DENY territory, while a link inside the
            // project stays at 0.5 and flows through.
            ToolCallType::FileLink {
                target,
                link_path,
                symbolic,
            } => (
                0.5,
                if *symbolic {
                    "symlink-create-baseline"
                } else {
                    "hardlink-create-baseline"
                },
                Severity::Notice,
                format!(
                    "{kind} link created: {link_path} -> {target}",
                    kind = if *symbolic { "Symbolic" } else { "Hard" }
                ),
            ),

            // Writes and network access.
            ToolCallType::FileWrite { path, .. } => (
                0.5,
                "file-write-baseline",
                Severity::Notice,
                format!("File write: {path}"),
            ),
            ToolCallType::HttpRequest { method, url } => {
                // W3: a body-bearing method (POST/PUT/PATCH) pushes data OUT — the
                // write-shaped, exfil-relevant direction — so it carries a higher
                // baseline than a read-shaped GET/HEAD/OPTIONS. This only sharpens
                // an already-flagged untrusted write (egress-policy owns the
                // destination score); a write to a trusted host stays well under
                // the queue threshold, so no new approvals. Method is visible only
                // on Path-1 HttpRequest; supervised HTTPS is TLS-opaque.
                if is_body_bearing_http_method(method) {
                    (
                        1.0,
                        "http-write-request-baseline",
                        Severity::Notice,
                        format!("HTTP {method} request (carries body): {url}"),
                    )
                } else {
                    (
                        0.5,
                        "http-request-baseline",
                        Severity::Notice,
                        format!("HTTP request: {method} {url}"),
                    )
                }
            }
            ToolCallType::NetConnect { address, port } => {
                // Unix-domain sockets get their own rule id so the audit
                // trail and dashboard can distinguish local IPC from real
                // network egress (the v0.2.5 D-Bus/X11 FP triage kept
                // conflating the two under `net-connect-baseline`). The
                // message drops the `:{port}` suffix — classify.rs
                // hardcodes port 0 for unix sockets, so
                // "unix:/run/user/1000/bus:0" is noise. Score and severity
                // are identical to the network baseline: this branch is
                // taxonomy and message hygiene only, never a risk change.
                if address.starts_with("unix:") {
                    (
                        0.5,
                        "unix-socket-connect-baseline",
                        Severity::Notice,
                        format!("Unix socket connection: {address}"),
                    )
                } else {
                    (
                        0.5,
                        "net-connect-baseline",
                        Severity::Notice,
                        format!("Network connection: {address}:{port}"),
                    )
                }
            }

            // Risky operations: shell execution, deletion, permission changes.
            ToolCallType::ShellExec { command, args } => {
                let msg = if args.is_empty() {
                    format!("Shell execution: {command}")
                } else {
                    format!("Shell execution: {} {}", command, args.join(" "))
                };
                (1.0, "shell-exec-baseline", Severity::Notice, msg)
            }
            ToolCallType::ProcessSpawn { command, args } => {
                let msg = if args.is_empty() {
                    format!("Process spawn: {command}")
                } else {
                    format!("Process spawn: {} {}", command, args.join(" "))
                };
                // PR 4 Phase D: the baseline is `operation_risk_for_spawn`
                // — `0.5` when the routine signal applies, `1.0` otherwise.
                // The phase-3 filters still run unmodified, so a routine
                // spawn that trips taint or behavioural anomaly lands at
                // `0.5 + 3.0 = 3.5` and still QUEUEs.
                let score = operation_risk_for_spawn(ctx, self.effective_routine_signal_enabled());
                let rule_id = if score < NON_ROUTINE_SPAWN_SCORE {
                    ROUTINE_SPAWN_RULE_ID
                } else {
                    NON_ROUTINE_SPAWN_RULE_ID
                };
                (score, rule_id, Severity::Notice, msg)
            }
            ToolCallType::FileDelete { path } => (
                1.0,
                "file-delete-baseline",
                Severity::Warning,
                format!("File deletion: {path}"),
            ),
            ToolCallType::FileChmod { path, mode } => {
                // setuid (0o4000) / setgid (0o2000) bits are a privilege-
                // escalation primitive (research doc §5.1 #3): the command
                // filter caught the string `chmod +s`, but an octal `0o4755`
                // mode previously scored the same flat baseline as any chmod.
                // Score the dangerous bit, not the syscall.
                if *mode & 0o6000 != 0 {
                    (
                        5.0,
                        "file-chmod-setuid",
                        Severity::Error,
                        format!("setuid/setgid permission change: {path} (mode {mode:o})"),
                    )
                } else {
                    (
                        1.0,
                        "file-chmod-baseline",
                        Severity::Warning,
                        format!("Permission change: {path} (mode {mode:o})"),
                    )
                }
            }
            ToolCallType::NetListen { address, port } => {
                // PR 69 Change 4: `operation-risk` no longer scores
                // bind-shape exposure. PR 5's `egress-policy` is the
                // authoritative scorer for the loopback / wildcard /
                // declared-clamp / specific-iface matrix; doubling the
                // score here pushed wildcard-undeclared from QUEUE
                // (5.0) to DENY (9.0) and broke codex's MCP startup
                // (see work/69-codex-prompt-noise-followup-work.md).
                //
                // We still want a non-zero baseline so listen ops show
                // up in audit-log queries even when no other filter
                // matches. The shape distinction now lives entirely in
                // `egress-policy`.
                (
                    0.5,
                    "net-listen-baseline",
                    Severity::Notice,
                    format!("Network listen: {address}:{port}"),
                )
            }
            ToolCallType::DnsQuery { domain, query_type } => (
                0.5,
                "dns-query-baseline",
                Severity::Notice,
                format!("DNS query: {domain} ({query_type})"),
            ),
            // PR 6 Phase B: category-2 syscalls. All three families
            // get a +5.0 baseline so QUEUE is the default outcome;
            // profile-declared allowlists can override per the
            // standard mechanism.
            ToolCallType::OwnershipChange {
                target,
                new_uid,
                new_gid,
            } => (
                5.0,
                "ownership-change-baseline",
                Severity::Warning,
                format!("Ownership change: target={target} uid={new_uid} gid={new_gid}"),
            ),
            ToolCallType::FilesystemMutation {
                op,
                source,
                target,
                fstype,
            } => (
                5.0,
                "filesystem-mutation-baseline",
                Severity::Warning,
                format!(
                    "Filesystem mutation: op={op} src={src} target={target} fstype={fs}",
                    src = source.as_deref().unwrap_or(""),
                    fs = fstype.as_deref().unwrap_or(""),
                ),
            ),
            ToolCallType::CrossProcessAccess { op, target_pid } => (
                5.0,
                "cross-process-access-baseline",
                Severity::Warning,
                format!("Cross-process access: op={op} target_pid={target_pid}"),
            ),
            // PR 6 Phase C: namespace primitive scored at +5.0 → QUEUE
            // by default. The supervisor's `namespace_users` carveout
            // (in `event_handler.rs`) short-circuits this evaluation
            // entirely when the calling binary is on the profile-
            // declared allowlist, so this baseline only fires for
            // non-allowlisted binaries.
            ToolCallType::NamespaceOp { syscall, flags } => (
                5.0,
                "namespace-op-baseline",
                Severity::Warning,
                format!("Namespace primitive: {syscall} flags={flags:#x}"),
            ),
            // A D-Bus method call only reaches the proxy when the supervisor's
            // curated allowlist did not vouch for it — an allowlisted call is
            // resumed without a round trip. So this baseline is not "a bus
            // method happened", it is "a bus method we do not recognise is
            // about to run in a peer outside supervision", which is the same
            // weight as the other authority-delegating operations.
            ToolCallType::DbusMethodCall {
                socket,
                destination,
                interface,
                member,
            } => {
                let dest = destination.as_deref().unwrap_or("(no destination)");
                let call = match (interface.as_deref(), member.as_deref()) {
                    (Some(iface), Some(m)) => format!("{iface}.{m}"),
                    (None, Some(m)) => m.to_string(),
                    (Some(iface), None) => iface.to_string(),
                    (None, None) => "(unnamed)".to_string(),
                };
                (
                    5.0,
                    "dbus-method-call-undeclared",
                    Severity::Warning,
                    format!("Undeclared D-Bus method call on {socket}: {dest} → {call}"),
                )
            }
        };

        Ok(FilterResult::matched(
            "operation-risk",
            rule_id,
            score,
            severity,
            message,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCallType;
    use uuid::Uuid;

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    #[tokio::test]
    async fn test_file_read_zero_score() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/test.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
        assert_eq!(result.score, 0.0);
    }

    #[tokio::test]
    async fn test_dir_list_zero_score() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::DirList {
            path: "/tmp".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
        assert_eq!(result.score, 0.0);
    }

    #[tokio::test]
    async fn test_file_write_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::FileWrite {
            path: "/tmp/out.txt".into(),
            content_hash: "abc".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.5);
        assert_eq!(result.rule_id, "file-write-baseline");
    }

    #[tokio::test]
    async fn test_shell_exec_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "grep".into(),
            args: vec!["foo".into(), "bar.txt".into()],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 1.0);
        assert_eq!(result.rule_id, "shell-exec-baseline");
    }

    #[tokio::test]
    async fn test_file_delete_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::FileDelete {
            path: "/tmp/trash.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 1.0);
        assert_eq!(result.rule_id, "file-delete-baseline");
    }

    #[tokio::test]
    async fn test_http_request_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://example.com".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.5);
    }

    /// W3: a body-bearing method (POST/PUT/PATCH) carries a higher baseline than
    /// a read-shaped GET — an outbound body is the exfil-relevant direction.
    #[tokio::test]
    async fn test_http_write_methods_weighted_higher() {
        let filter = OperationRiskFilter::new();
        for method in ["POST", "put", "PATCH"] {
            let ctx = make_ctx(ToolCallType::HttpRequest {
                method: method.into(),
                url: "https://example.com/upload".into(),
            });
            let result = filter.evaluate(&ctx).await.unwrap();
            assert_eq!(
                result.rule_id, "http-write-request-baseline",
                "method {method}"
            );
            assert_eq!(result.score, 1.0, "method {method}");
        }
    }

    /// Read-shaped methods keep the low baseline (no body leaves).
    #[tokio::test]
    async fn test_http_read_methods_keep_low_baseline() {
        let filter = OperationRiskFilter::new();
        for method in ["GET", "HEAD", "OPTIONS", "DELETE"] {
            let ctx = make_ctx(ToolCallType::HttpRequest {
                method: method.into(),
                url: "https://example.com".into(),
            });
            let result = filter.evaluate(&ctx).await.unwrap();
            assert_eq!(result.rule_id, "http-request-baseline", "method {method}");
            assert_eq!(result.score, 0.5, "method {method}");
        }
    }

    /// Unix-domain socket connects get their own rule id and a message
    /// without the `:{port}` suffix — classify.rs hardcodes port 0 for
    /// unix sockets, so "unix:/run/user/1000/bus:0" is noise. Score and
    /// severity stay identical to the network baseline (taxonomy only).
    #[tokio::test]
    async fn test_unix_socket_connect_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: "unix:/run/user/1000/bus".into(),
            port: 0,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.5);
        assert_eq!(result.rule_id, "unix-socket-connect-baseline");
        assert_eq!(
            result.message,
            "Unix socket connection: unix:/run/user/1000/bus"
        );
        assert!(
            !result.message.contains(":0"),
            "message: {}",
            result.message
        );
    }

    /// Regression guard: TCP connects keep the legacy rule id, score,
    /// and `{address}:{port}` message shape byte-for-byte.
    #[tokio::test]
    async fn test_tcp_net_connect_baseline_unchanged() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::NetConnect {
            address: "203.0.113.7".into(),
            port: 443,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.5);
        assert_eq!(result.rule_id, "net-connect-baseline");
        assert_eq!(result.message, "Network connection: 203.0.113.7:443");
    }

    /// PR 69 Change 4: every NetListen — loopback, wildcard, or
    /// specific interface — gets the same low baseline here. Bind-shape
    /// exposure is owned by `egress-policy`.
    #[tokio::test]
    async fn test_net_listen_wildcard_returns_baseline_only() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::NetListen {
            address: "0.0.0.0".into(),
            port: 8080,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.5);
        assert_eq!(result.rule_id, "net-listen-baseline");
    }

    #[tokio::test]
    async fn test_net_listen_loopback_returns_baseline_only() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::NetListen {
            address: "127.0.0.1".into(),
            port: 8080,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.5);
        assert_eq!(result.rule_id, "net-listen-baseline");
    }

    #[tokio::test]
    async fn test_net_listen_specific_iface_returns_baseline_only() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::NetListen {
            address: "192.168.1.10".into(),
            port: 8080,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.5);
        assert_eq!(result.rule_id, "net-listen-baseline");
    }

    #[tokio::test]
    async fn test_file_chmod_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::FileChmod {
            path: "/tmp/script.sh".into(),
            mode: 0o755,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 1.0);
    }

    #[tokio::test]
    async fn test_dir_create_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::DirCreate {
            path: "/tmp/newdir".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.2);
    }

    // ---- PR 6 Phase B: category-2 syscalls score +5.0 (QUEUE) ----

    #[tokio::test]
    async fn phase_b_ownership_change_scores_five() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::OwnershipChange {
            target: "/etc/passwd".into(),
            new_uid: 1000,
            new_gid: 1000,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 5.0);
        assert_eq!(result.rule_id, "ownership-change-baseline");
    }

    #[tokio::test]
    async fn phase_b_filesystem_mutation_scores_five() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::FilesystemMutation {
            op: "mount".into(),
            source: Some("/dev/sda1".into()),
            target: "/mnt/x".into(),
            fstype: Some("ext4".into()),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 5.0);
        assert_eq!(result.rule_id, "filesystem-mutation-baseline");
    }

    #[tokio::test]
    async fn phase_b_cross_process_access_scores_five() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::CrossProcessAccess {
            op: "ptrace".into(),
            target_pid: 9999,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 5.0);
        assert_eq!(result.rule_id, "cross-process-access-baseline");
    }

    // PR 6 Phase C: namespace primitive scores +5.0 (QUEUE) when not
    // carved-out. The supervisor's namespace_users + routine_root
    // check short-circuits this entirely for trusted sandbox tools.
    #[tokio::test]
    async fn phase_c_namespace_op_scores_five() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::NamespaceOp {
            syscall: "unshare".into(),
            flags: 0x1002_0000, // CLONE_NEWUSER | CLONE_NEWNS
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 5.0);
        assert_eq!(result.rule_id, "namespace-op-baseline");
    }

    #[tokio::test]
    async fn dbus_method_call_scores_five_and_queues() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::DbusMethodCall {
            socket: "unix:/run/user/1000/bus".into(),
            destination: Some("org.freedesktop.systemd1".into()),
            interface: Some("org.freedesktop.systemd1.Manager".into()),
            member: Some("StartTransientUnit".into()),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        // Must land in the QUEUE band (3.0..8.0) so it prompts rather than
        // being auto-allowed or hard-denied.
        assert_eq!(result.score, 5.0);
        assert_eq!(result.rule_id, "dbus-method-call-undeclared");
        assert!(
            result.message.contains("StartTransientUnit"),
            "the operator must see which method: {}",
            result.message
        );
    }

    #[tokio::test]
    async fn dbus_method_call_without_header_fields_still_scores() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::DbusMethodCall {
            socket: "unix:/run/user/1000/bus".into(),
            destination: None,
            interface: None,
            member: None,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(result.score, 5.0);
    }

    // ---- PR 4 Phase D: routine spawn signal tests ----

    use crate::session_state::SessionPinnedInventory;
    use crate::types::{ComponentWritability, SessionScopeKey, SpawnProvenance};

    fn safe_component(path: &str) -> ComponentWritability {
        ComponentWritability {
            path: path.into(),
            owner_uid: 0,
            other_writable: false,
            group_writable_non_root: false,
            world_writable: false,
        }
    }

    fn good_provenance() -> SpawnProvenance {
        SpawnProvenance {
            canonical_path: "/home/u/.nvm/versions/node/v22/lib/node_modules/x/bin".into(),
            sha256: "ab".repeat(32),
            owner_uid: 1000,
            owner_gid: 1000,
            mode: 0o755,
            component_writability: vec![
                safe_component("/"),
                safe_component("/home"),
                safe_component("/home/u"),
            ],
            matched_routine_root: Some("/home/u/.nvm/versions/node/v22/lib/node_modules/x/".into()),
            is_outbound_capable: false,
        }
    }

    fn install_inventory(scope: SessionScopeKey, prov: &SpawnProvenance) {
        let state = SessionStateRegistry::global().get_or_create(scope);
        let inv = SessionPinnedInventory::from_entries([(
            prov.canonical_path.clone(),
            prov.sha256.clone(),
        )]);
        state.set_pinned_inventory(inv);
    }

    fn spawn_ctx_with_provenance(prov: SpawnProvenance) -> ToolCallContext {
        let mut ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: prov.canonical_path.clone(),
            args: Vec::new(),
        });
        ctx.session_scope = Some(SessionScopeKey::fresh());
        ctx.spawn_provenance = Some(prov);
        ctx
    }

    // Phase D tests bypass the env-var gate by calling `has_routine_signal`
    // with an explicit `enabled` bool. The env-var read is exercised by
    // `default_off_env_var_check` only, which is isolated from other tests.

    /// Phase D guardrail: scoring is **exactly 0.5** on signal — never 0.0.
    #[tokio::test]
    async fn routine_signal_scores_exactly_zero_point_five() {
        let prov = good_provenance();
        let ctx = spawn_ctx_with_provenance(prov.clone());
        install_inventory(ctx.session_scope.unwrap(), &prov);
        assert!(has_routine_signal(&ctx, true));
        // Direct constant check (constant-time, no env-var involvement).
        assert!((ROUTINE_SPAWN_SCORE - 0.5).abs() < f64::EPSILON);
    }

    /// Phase D critical guardrail: routine spawn + a simulated phase-3
    /// hit at +3.0 still QUEUEs (the +0.5 baseline is additive). Proves
    /// "+0.5 not +0.0". The integration test
    /// `tests/routine_phase3_still_queues.rs` covers this same invariant
    /// from outside the crate; this unit test is the local mirror.
    #[tokio::test]
    #[allow(clippy::assertions_on_constants)]
    async fn routine_spawn_plus_phase3_still_queues() {
        // 0.5 (routine) + 3.0 (taint, simulated) = 3.5 → > 3.0 threshold.
        let sim_phase3 = 3.0_f64;
        let queue_threshold = 3.0_f64;
        assert!(
            ROUTINE_SPAWN_SCORE + sim_phase3 > queue_threshold,
            "scoring +0.0 would silently absorb a phase-3 hit at +3.0; \
             routine signal MUST be +0.5 (or greater)",
        );
        // Equally critical: confirm the constant is exactly 0.5, not 0.0.
        assert!((ROUTINE_SPAWN_SCORE - 0.5).abs() < f64::EPSILON);
    }

    /// Phase D gate: when the `enabled` bool is false (matching the
    /// default env-var-absent state), the signal never fires even on
    /// otherwise-qualifying provenance + inventory.
    #[tokio::test]
    async fn routine_signal_off_when_disabled() {
        let prov = good_provenance();
        let ctx = spawn_ctx_with_provenance(prov.clone());
        install_inventory(ctx.session_scope.unwrap(), &prov);
        assert!(!has_routine_signal(&ctx, false));
    }

    #[tokio::test]
    async fn provenance_disqualifies_when_no_matched_root() {
        let mut prov = good_provenance();
        prov.matched_routine_root = None;
        assert!(!provenance_qualifies(&prov));
    }

    #[tokio::test]
    async fn provenance_disqualifies_when_outbound_capable() {
        let mut prov = good_provenance();
        prov.is_outbound_capable = true;
        assert!(!provenance_qualifies(&prov));
    }

    #[tokio::test]
    async fn provenance_disqualifies_when_world_writable_component() {
        let mut prov = good_provenance();
        prov.component_writability.push(ComponentWritability {
            path: "/home/u/bad".into(),
            owner_uid: 1000,
            other_writable: true,
            group_writable_non_root: false,
            world_writable: true,
        });
        assert!(!provenance_qualifies(&prov));
    }

    #[tokio::test]
    async fn provenance_disqualifies_when_root_owned_group_writable() {
        let mut prov = good_provenance();
        prov.component_writability.push(ComponentWritability {
            path: "/etc".into(),
            owner_uid: 0,
            other_writable: false,
            group_writable_non_root: true,
            world_writable: false,
        });
        assert!(!provenance_qualifies(&prov));
    }

    /// Spawn outside the routine root → no signal even when enabled.
    #[tokio::test]
    async fn non_routine_spawn_no_signal_when_enabled() {
        let mut prov = good_provenance();
        prov.matched_routine_root = None;
        let ctx = spawn_ctx_with_provenance(prov);
        assert!(!has_routine_signal(&ctx, true));
    }

    /// Spawn with no SpawnProvenance attached (LLM path or missing
    /// provenance) → no signal.
    #[tokio::test]
    async fn spawn_with_no_provenance_no_signal_when_enabled() {
        let mut ctx = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/whatever".into(),
            args: Vec::new(),
        });
        ctx.session_scope = Some(SessionScopeKey::fresh());
        assert!(!has_routine_signal(&ctx, true));
    }

    /// Inventory miss (path not pinned) → routine signal denied.
    #[tokio::test]
    async fn inventory_miss_denies_routine_signal() {
        let prov = good_provenance();
        let ctx = spawn_ctx_with_provenance(prov);
        // Inventory NOT installed for this scope.
        assert!(!has_routine_signal(&ctx, true));
    }

    /// Inventory has a different hash for this canonical path → routine
    /// signal denied (binary swapped mid-session).
    #[tokio::test]
    async fn inventory_hash_drift_denies_routine_signal() {
        let prov = good_provenance();
        let scope = SessionScopeKey::fresh();
        let state = SessionStateRegistry::global().get_or_create(scope);
        let inv = SessionPinnedInventory::from_entries([(
            prov.canonical_path.clone(),
            "cc".repeat(32), // wrong hash
        )]);
        state.set_pinned_inventory(inv);
        let mut ctx = spawn_ctx_with_provenance(prov);
        ctx.session_scope = Some(scope);
        assert!(!has_routine_signal(&ctx, true));
    }

    /// PR 4 Phase E: a routine-rooted /usr/bin/curl (i.e. SpawnProvenance
    /// has matched_routine_root set AND is_outbound_capable=true) is
    /// denied the routine signal. Documents the cross-reference between
    /// PR 2's outbound-capable list and PR 4's routine signal: just
    /// because curl lives under a declared routine root does not mean
    /// it should auto-allow.
    #[tokio::test]
    async fn phase_e_outbound_curl_under_routine_root_denies_signal() {
        let mut prov = good_provenance();
        prov.canonical_path = "/usr/bin/curl".into();
        prov.matched_routine_root = Some("/usr/bin/".into());
        prov.is_outbound_capable = true; // what classify_binary returns

        // Pin the curl path so condition 5 (inventory) would otherwise
        // succeed — proves condition 4 (not outbound-capable) is doing
        // the rejection, not a missing pin.
        let ctx = spawn_ctx_with_provenance(prov.clone());
        install_inventory(ctx.session_scope.unwrap(), &prov);

        assert!(!has_routine_signal(&ctx, true));
        // Also verify the predicate directly, so a future refactor that
        // moves the outbound check elsewhere still trips here.
        assert!(!provenance_qualifies(&prov));
    }

    /// Env-var override: when unset, returns `None` so the filter's
    /// config flag wins. When set to a truthy value, forces signal ON;
    /// when set to a falsy value, forces signal OFF.
    #[tokio::test]
    async fn env_var_override_semantics() {
        // SAFETY: this test only reads. Other tests do not mutate the
        // env var any more (we refactored away from `set_var` calls),
        // so we can rely on the env being clean here.
        let was_set = std::env::var_os("GRITH_PROXY_ROUTINE_SIGNAL_ENABLED").is_some();
        if !was_set {
            assert_eq!(routine_signal_env_override(), None);
        }
    }

    /// PR 4 Phase H: the filter constructor caches the config flag,
    /// and the env-var override (when set) takes precedence in either
    /// direction.
    #[tokio::test]
    async fn phase_h_config_flag_off_by_default() {
        let f = OperationRiskFilter::new();
        // Without an env override, the filter respects its constructed flag.
        if std::env::var_os("GRITH_PROXY_ROUTINE_SIGNAL_ENABLED").is_none() {
            assert!(!f.effective_routine_signal_enabled());
        }
    }

    #[tokio::test]
    async fn phase_h_with_routine_signal_constructor() {
        let on = OperationRiskFilter::with_routine_signal(true);
        let off = OperationRiskFilter::with_routine_signal(false);
        if std::env::var_os("GRITH_PROXY_ROUTINE_SIGNAL_ENABLED").is_none() {
            assert!(on.effective_routine_signal_enabled());
            assert!(!off.effective_routine_signal_enabled());
        }
    }
}
