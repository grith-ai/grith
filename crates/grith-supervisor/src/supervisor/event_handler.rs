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
use grith_proxy::types::{ProxyAction, ToolCallContext, ToolCallType};
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

use super::{session_state::SupervisorSession, DaemonRestartConfig};

fn session_scope_name(session: &SupervisorSession) -> &str {
    session.scope_name().unwrap_or("unknown")
}

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
    if matches!(event.kind, SyscallKind::IoUringSetup) {
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
    if let SyscallKind::RawSocketCreate { domain, .. } = event.kind {
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
            domain,
            syscall_nr = event.raw_syscall_nr,
            "raw socket denied — AF_PACKET/AF_NETLINK bypasses IP stack"
        );
        if let Err(e) = interceptor.deny(tid).await {
            tracing::warn!(error = %e, tid, "deny (raw socket) failed");
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
            | grith_proxy::types::ToolCallType::DirCreate { path } => {
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
            }
            grith_proxy::types::ToolCallType::NetListen { address, .. } => {
                is_local_listen_address(address)
            }
            _ => false,
        };
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

    // Optional noise path check (e.g., reads of /proc/, /sys/, etc.).
    if let Some(path) = ToolCallContext::new("", call_type.clone(), session.id).path() {
        if syscall_map::is_noise_path(path) {
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
    if loop_ctx.config.noise_reduction.ignore_read_only {
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
            if let Err(e) = interceptor.allow(tid).await {
                tracing::warn!(error = %e, tid, "allow (session-allowed) failed");
            }
            return Ok(());
        }
    }

    // ---- Build proxy context ----
    let plugin_id = format!("supervisor:{}", session.tool_name);
    let mut ctx = ToolCallContext::new(plugin_id, call_type, session.id);
    ctx.profile_name = session.profile_name.clone();
    ctx.task_context = session.project_name.clone();
    ctx.arguments = supervisor_event_arguments(session, event.pid, &ctx.call_type);

    // ---- Reputation-based pre-evaluation auto-allow ----
    // Check if the reputation system has enough trust to auto-allow this
    // operation before running the full proxy pipeline. This is the main
    // enforcement path for the BRS (plan 48).
    //
    // Note: we evaluate the proxy first anyway to get filter_results for the
    // safety ceiling check. The auto-allow only fires if no ceiling applies.
    let decision = evaluate_proxy(loop_ctx, &ctx).await;

    // Check if reputation would auto-allow this operation.
    if loop_ctx.daemon_proxy_url.is_none()
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
            let reputation_auto_allow = if !ceiling {
                loop_ctx
                    .reputation_table
                    .lock()
                    .ok()
                    .map(|table| {
                        table.adjust_score(
                            decision.composite_score,
                            &keys,
                            false,
                            &loop_ctx.reputation_config,
                        ) == 0.0
                    })
                    .unwrap_or(false)
            } else {
                false
            };

            if reputation_auto_allow {
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
            Ok(())
        }
        ProxyAction::Queue { .. } => {
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

/// Returns `true` if `path` is a sensitive Unix socket that grants container
/// runtime control and must not be silently allowed.
fn is_sensitive_unix_socket(path: &str) -> bool {
    if SENSITIVE_UNIX_SOCKETS.contains(&path) {
        return true;
    }
    // Covers /run/user/<uid>/podman/podman.sock for any user ID.
    path.contains("podman.sock")
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
        _ => session_allowlist_key(call_type),
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
    // deletes, renames, chmod, or directory creates.
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
    // FileDelete, FileRename, FileChmod, DirCreate). They do NOT match reads
    // (reads should use `ro:` instead) or non-filesystem operations.
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
    .with_supervisor_source(
        session
            .project_name
            .clone()
            .unwrap_or_else(|| session.tool_name.clone()),
        event_pid,
    );

    if grith_proxy::filters::dlp_gate::has_dlp_detection(&decision.filter_results) {
        record.arguments_summary = dlp_redactor.redact(&record.arguments_summary);
    }
    if let Some(id) = correlation_id {
        record = record.with_correlation(id);
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
}
