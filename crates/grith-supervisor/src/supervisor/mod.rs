// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Supervisor orchestrator -- the main event loop that intercepts OS-level
//! syscalls from a supervised CLI tool and routes them through the grith
//! security proxy pipeline.
//!
//! This module contains the session management types (`SupervisorSession`,
//! `SupervisorRegistry`, `SessionStats`, `SessionSummary`) and the core
//! `run_supervisor_loop` function that ties together the interceptor,
//! process tree, proxy, audit sink, digest backend, and optional WebSocket
//! / session-state broadcasting.

mod event_handler;
mod mass_destruction;
#[cfg(test)]
mod protection_tests;
pub mod session_state;

// Re-export all public types so that `crate::supervisor::Foo` continues to work.
pub use session_state::{SessionStats, SessionSummary, SupervisorRegistry, SupervisorSession};

use std::sync::{Arc, Mutex};
use std::time::Duration;

use grith_audit::{
    types::{AuditRecord, ProxyActionSummary},
    CorrelationTracker,
};
use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::session_containment::ContainmentTracker;
use tokio::sync::broadcast;

use crate::audit_sink::AuditSink;
use crate::config::SupervisorConfig;
use crate::error::Result;
use crate::forensics_trace::ForensicsTraceSink;
use crate::freezer::Freezer;
use crate::interceptor::{SyscallEvent, SyscallInterceptor};
use crate::reviewer::{DigestStore, PollingQueueReviewer, QueueReviewer};
use crate::session_sync::SessionSync;

use event_handler::{handle_syscall_event, SupervisorLoopContext};

/// Restart command for a daemon-backed thin client session.
#[derive(Debug, Clone)]
pub struct DaemonRestartConfig {
    pub executable: std::path::PathBuf,
    pub config_path: Option<std::path::PathBuf>,
    pub token_path: std::path::PathBuf,
}

fn effective_policy_for_session(
    session: &SupervisorSession,
) -> Option<crate::profiles::EffectivePolicy> {
    let profile_name = session.profile_name.as_deref()?;
    let config = crate::profiles::SupervisorProfile::load_config().ok()?;
    config
        .build_effective_policy(
            profile_name,
            session.launcher_overlay_name.as_deref(),
            session.provider_overlay_name.as_deref(),
        )
        .ok()
}

// ---------------------------------------------------------------------------
// Core event loop
// ---------------------------------------------------------------------------

/// Run the supervisor interception loop for a single session.
///
/// This is the central orchestrator: it reads syscall events from the
/// platform-specific interceptor, converts them to `ToolCallType`, evaluates
/// them through the proxy, and enforces the resulting action (allow / freeze /
/// deny). Every evaluation is audit-logged, and optionally broadcast over
/// WebSocket for the dashboard.
///
/// The loop terminates when:
/// - the `shutdown_rx` channel receives a signal, or
/// - the interceptor returns an error indicating the supervised process has
///   exited.
///
/// On shutdown, all traced processes are detached (fail-open) so that the
/// supervised tool can continue unsupervised.
#[allow(clippy::too_many_arguments)]
pub async fn run_supervisor_loop(
    interceptor: &mut Box<dyn SyscallInterceptor>,
    session: &mut SupervisorSession,
    proxy: Arc<SecurityProxy>,
    audit_sink: Arc<dyn AuditSink>,
    digest_store: Arc<dyn DigestStore>,
    dlp_redactor: &grith_proxy::filters::dlp_gate::DlpRedactor,
    correlation_tracker: Arc<CorrelationTracker>,
    containment_tracker: Arc<ContainmentTracker>,
    config: &SupervisorConfig,
    mut shutdown_rx: broadcast::Receiver<()>,
    event_tx: Option<broadcast::Sender<String>>,
    queue_reviewer: Option<Arc<dyn QueueReviewer>>,
    session_sync: Option<Arc<dyn SessionSync>>,
    dns_seed_domains: &[String],
    session_allowed: std::collections::HashSet<String>,
    shared_reputation: Option<Arc<Mutex<grith_proxy::reputation::ReputationTable>>>,
    daemon_proxy_url: Option<String>,
    daemon_proxy_token: Option<String>,
    daemon_restart: Option<DaemonRestartConfig>,
    inventory_sink: Option<Arc<dyn crate::inventory_sink::InventorySink>>,
) -> Result<()> {
    let freezer = Freezer::new(Duration::from_secs(config.freeze_timeout_seconds));
    let read_batch_tracker = Mutex::new(event_handler::ReadBatchTracker::new(
        config.noise_reduction.batch_window_ms,
    ));
    let reviewer: Arc<dyn QueueReviewer> =
        queue_reviewer.unwrap_or_else(|| Arc::new(PollingQueueReviewer::new(digest_store.clone())));
    let event_tx = event_tx.as_ref();

    // Build DNS cache and seed it in the background so that the blocking
    // DNS lookups for routine destinations don't hold up PTY/supervisor start.
    // The cache is only needed on the first DNS query from the supervised tool,
    // which arrives well after grith itself is fully initialised.
    let dns_cache = std::sync::Arc::new(Mutex::new(crate::dns_cache::DnsCache::new()));
    {
        let cache = std::sync::Arc::clone(&dns_cache);
        let domains: Vec<String> = dns_seed_domains.to_vec();
        tokio::task::spawn_blocking(move || {
            let resolved = crate::dns_cache::resolve_domains(domains.iter().map(|s| s.as_str()));
            if let Ok(mut c) = cache.lock() {
                c.record_resolved_domains(resolved);
            }
        });
    }

    // Start DNS inspection proxy if enabled (Linux only).
    let (dns_proxy_port, dns_query_rx) = if cfg!(target_os = "linux")
        && config.dns_inspection.enabled
    {
        let upstream = config
            .dns_inspection
            .upstream_resolver
            .as_ref()
            .and_then(|s| {
                s.parse::<std::net::SocketAddr>().ok().or_else(|| {
                    s.parse::<std::net::IpAddr>()
                        .ok()
                        .map(|ip| std::net::SocketAddr::new(ip, 53))
                })
            })
            .unwrap_or_else(crate::dns_proxy::discover_upstream_resolver);

        match crate::dns_proxy::start_dns_proxy(upstream, std::sync::Arc::clone(&dns_cache)).await {
            Ok((proxy_handle, rx)) => {
                tracing::info!(
                    port = proxy_handle.local_port,
                    %upstream,
                    "DNS inspection proxy active"
                );
                (
                    Some(proxy_handle.local_port),
                    Some(tokio::sync::Mutex::new(rx)),
                )
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to start DNS inspection proxy, continuing without");
                (None, None)
            }
        }
    } else {
        (None, None)
    };
    let persist_local_reputation = shared_reputation.is_some() || daemon_proxy_url.is_none();
    let daemon_restart = daemon_restart.map(event_handler::DaemonRestartState::new);

    // PR 4 Phase D: resolve the profile once and reuse it for the
    // session-pinned inventory build (Phase C) and the per-spawn
    // provenance context (Phase D). `effective_policy_for_session`
    // reads the config from disk each call, so we cache it here.
    let session_policy = effective_policy_for_session(session);
    let expanded_routine_exec_roots: Vec<String> = session_policy
        .as_ref()
        .map(|p| p.merged_profile.expand_routine_exec_roots())
        .unwrap_or_default();
    // Fix #2: profile-declared scratch_roots, expanded at session start. Writes
    // under these are exempt from the rate-limit burst counter (only) so the
    // tool's XDG-cache churn doesn't queue routine work.
    let expanded_scratch_roots: Vec<String> = session_policy
        .as_ref()
        .map(|p| p.merged_profile.expand_scratch_roots())
        .unwrap_or_default();
    // PR 5 Phase C: lift the resolved profile's local_listener_policy
    // out of the same effective-policy lookup so the loop context can
    // serve `match_listener_policy` on every NetListen evaluation.
    let session_local_listener_policy: Vec<crate::profiles::LocalListenerEntry> = session_policy
        .as_ref()
        .map(|p| p.merged_profile.local_listener_policy.clone())
        .unwrap_or_default();
    // PR 6 Phase C: namespace_users — canonical paths of binaries
    // permitted to invoke unshare(2) / setns(2) silently when
    // spawned from a routine_exec_root. Defaults to empty when no
    // profile is resolved.
    let session_namespace_users: Vec<String> = session_policy
        .as_ref()
        .map(|p| p.merged_profile.namespace_users.clone())
        .unwrap_or_default();

    let loop_ctx = SupervisorLoopContext {
        proxy: &proxy,
        audit_sink,
        digest_store,
        dlp_redactor,
        correlation_tracker: &correlation_tracker,
        containment_tracker: &containment_tracker,
        config,
        event_tx,
        freezer,
        read_batch_tracker,
        reviewer,
        session_allowed: Mutex::new(session_allowed),
        dns_cache,
        dns_proxy_port,
        dns_query_rx,
        syscall_log: config.syscall_log_file.as_ref().and_then(|path| {
            std::fs::File::create(path)
                .map(|f| Mutex::new(std::io::BufWriter::new(f)))
                .map_err(|e| {
                    tracing::warn!(error = %e, path = %path.display(), "failed to open syscall log file");
                    e
                })
                .ok()
        }),
        forensics_trace: config
            .trace_syscalls_jsonl_file
            .as_ref()
            .map(|path| ForensicsTraceSink::new(path))
            .transpose()?,
        reputation_table: {
            // Use daemon-shared reputation table if provided, otherwise
            // load a session-local copy from disk (for tests and standalone use).
            let table = if let Some(shared) = shared_reputation {
                // Seed profile priors into the shared table (idempotent).
                if let Some(policy) = effective_policy_for_session(session) {
                    let scope = session.scope_name().unwrap_or(policy.scope_key.as_str());
                    if let Ok(mut t) = shared.lock() {
                        t.seed_from_profile(
                            scope,
                            &policy.merged_profile.routine_paths,
                            &policy.merged_profile.routine_commands,
                            &policy.merged_profile.routine_destinations,
                            &policy.merged_profile.readonly_paths,
                        );
                    }
                }
                shared
            } else {
                let rep_path = grith_proxy::reputation::default_reputation_path();
                let mut t = grith_proxy::reputation::ReputationTable::load(&rep_path);
                if let Some(policy) = effective_policy_for_session(session) {
                    let scope = session.scope_name().unwrap_or(policy.scope_key.as_str());
                    t.seed_from_profile(
                        scope,
                        &policy.merged_profile.routine_paths,
                        &policy.merged_profile.routine_commands,
                        &policy.merged_profile.routine_destinations,
                        &policy.merged_profile.readonly_paths,
                    );
                }
                Arc::new(Mutex::new(t))
            };
            tracing::info!(
                entries = table.lock().map(|t| t.len()).unwrap_or(0),
                "reputation table ready"
            );
            table
        },
        reputation_config: config.reputation_config.clone(),
        daemon_proxy_url,
        daemon_proxy_token: daemon_proxy_token.map(|token| Arc::new(Mutex::new(token))),
        daemon_restart,
        persist_local_reputation,
        session_sync,
        routine_exec_roots: expanded_routine_exec_roots.clone(),
        scratch_roots: expanded_scratch_roots,
        local_listener_policy: session_local_listener_policy,
        namespace_users: session_namespace_users,
        // The supervised tool is spawned as a child of this process and
        // inherits its cwd, so the supervisor's cwd at session start is the
        // project root the tool was pointed at — the mass-destruction signal's
        // in-tree boundary.
        working_root: std::env::current_dir().ok(),
        mass_destruction: std::sync::Mutex::new(
            mass_destruction::MassDestructionTracker::with_defaults(),
        ),
    };

    // PR 1 Phase F: sweep stale per-session state from any crashed previous
    // session. Anything in `SessionStateRegistry` whose `last_seen` is older
    // than the threshold below is evicted from the registry AND from every
    // scoping filter (taint, rate_limit, behavioural). This is the
    // crash-recovery counterpart to the session-end hook further down.
    //
    // The 60-second threshold matches the digest-item sweep window noted in
    // MEMORY.md; keep them in sync if either is tuned.
    {
        use grith_proxy::session_state::SessionStateRegistry;
        const STALE_THRESHOLD: Duration = Duration::from_secs(60);
        let cutoff = std::time::Instant::now() - STALE_THRESHOLD;
        let stale = SessionStateRegistry::global().snapshot_stale(cutoff);
        if !stale.is_empty() {
            let mut total_removed = 0usize;
            for (stale_scope, _last_seen) in &stale {
                total_removed += proxy.evict_session_state(*stale_scope);
            }
            tracing::info!(
                stale_scopes = stale.len(),
                filter_entries_removed = total_removed,
                "session-start sweep evicted stale per-session state",
            );
        }
    }

    // PR 1 Phase G: structured session-lifecycle event. Emitted at the
    // top of the supervisor loop alongside the human-readable "supervisor
    // loop started" log so audit pipelines that filter on `event` get a
    // typed marker, and the legacy text log still surfaces in tail-style
    // log readers.
    //
    // `session_start` measures the *supervision* lifetime — from the point
    // the event loop is ready to handle syscalls — not wall-clock from
    // `grith exec` invocation. The pre-loop setup (Phase F stale sweep,
    // DNS seeding, etc.) is deliberately excluded so `duration_secs` in
    // `event = "session_end"` reflects how long the supervised tool ran
    // under supervision, not startup overhead.
    let scope = grith_proxy::types::SessionScopeKey::from_session_id(session.id);
    let session_start = std::time::Instant::now();
    // PR 5 Phase D: probe whether the kernel ptrace policy will let
    // us rewrite a tracee's sockaddr at bind() entry-stop. Logged on
    // every session start so operators can audit whether the clamp
    // feature is usable in this environment. When false, every
    // `allow_clamp = true` entry effectively downgrades to
    // `allow_clamp = false` (egress_policy still queues wildcard
    // binds even when declared).
    let clamp_available = crate::platform::linux::clamp::clamp_capability_available();
    tracing::info!(
        event = "session_start",
        session_id = %session.id,
        scope = %scope,
        tool = %session.tool_name,
        profile = session.profile_name.as_deref().unwrap_or(""),
        root_pid = session.root_pid,
        listener_clamp_available = clamp_available,
        "supervisor session started",
    );
    log_session_lifecycle_audit(
        &loop_ctx,
        session,
        "session_start",
        serde_json::json!({
            "scope": scope.to_string(),
            "tool": &session.tool_name,
            "profile": session.profile_name.as_deref().unwrap_or(""),
            "root_pid": session.root_pid,
            "listener_clamp_available": clamp_available,
        }),
        "supervisor session started",
    )
    .await;

    // PR 4 Phase C: build the session-pinned binary inventory.
    //
    // Walks every binary under the profile's expanded `routine_exec_roots`,
    // computes SHA-256 and ownership/permission safety, and installs the
    // immutable snapshot on the proxy's `SessionState`. Phase D's routine
    // signal will reject any spawn target whose canonical path either isn't
    // in this inventory or whose hash drifts mid-session.
    //
    // Run via `spawn_blocking` so the FS walk + hashing doesn't stall the
    // Tokio runtime. We intentionally do NOT await this future — the
    // inventory is `OnceLock`-installed so a slow walk on rotational disk
    // can finish in the background and start protecting later spawns
    // without blocking session start. Phase D treats "inventory not yet
    // installed" as "no routine signal" (fail-closed), so the only
    // observable effect of a late install is a small window of routine
    // spawns scoring `+1.0` instead of `+0.5`.
    {
        let expanded_roots = expanded_routine_exec_roots.clone();
        if !expanded_roots.is_empty() {
            // Wrap the blocking walk in `tokio::spawn` + `.await` so a
            // panic inside the closure is surfaced via the join error
            // rather than being silently lost. Phase D fails closed when
            // the inventory is missing, so a panic just means "no routine
            // signal this session" — visible in logs as an `error!`.
            let inventory_sink_for_push = inventory_sink.clone();
            tokio::spawn(async move {
                let join = tokio::task::spawn_blocking(move || {
                    use grith_proxy::session_state::SessionStateRegistry;
                    let inventory =
                        crate::provenance::build_session_pinned_inventory(&expanded_roots);
                    let state = SessionStateRegistry::global().get_or_create(scope);
                    tracing::info!(
                        event = "session_pinned_inventory_built",
                        scope = %scope,
                        binaries_pinned = inventory.len(),
                        total_scanned = inventory.total_scanned,
                        truncated = inventory.truncated,
                        "session-pinned binary inventory installed",
                    );
                    state.set_pinned_inventory(inventory.clone());
                    inventory
                })
                .await;
                match join {
                    Ok(inventory) => {
                        // Push to the daemon (if configured) so the
                        // dashboard's /api/inventory endpoint, which
                        // reads from the daemon's per-process registry,
                        // can render this session. Failures are
                        // non-fatal: the local registry is already
                        // populated and the proxy reads from there.
                        if let Some(sink) = inventory_sink_for_push {
                            if let Err(e) = sink.install(scope, inventory).await {
                                tracing::warn!(
                                    scope = %scope,
                                    error = %e,
                                    "inventory IPC push to daemon failed; dashboard view will be unavailable",
                                );
                            }
                        }
                    }
                    Err(err) => {
                        tracing::error!(
                            scope = %scope,
                            error = %err,
                            "session-pinned inventory build panicked or was cancelled",
                        );
                    }
                }
            });
        }
    }

    let save_interval =
        Duration::from_secs(config.reputation_config.save_interval_seconds().max(30));
    let mut reputation_save_timer = tokio::time::interval(save_interval);
    reputation_save_timer.tick().await; // consume the first immediate tick

    // Wedge-detection watchdog: every WATCHDOG_INTERVAL seconds, scan
    // supervised tracees for ones that have been in ptrace_stop for
    // longer than WATCHDOG_THRESHOLD without producing any event.
    //
    // Observation-only: surfaces wedges via a tracing::warn! + a
    // forensic audit row, but does NOT release the tracee. Masking the
    // wedge would also mask whichever code path failed to release it,
    // which is the bug we want to find.
    const WATCHDOG_INTERVAL: Duration = Duration::from_secs(10);
    const WATCHDOG_THRESHOLD: Duration = Duration::from_secs(30);
    let mut watchdog_timer = tokio::time::interval(WATCHDOG_INTERVAL);
    watchdog_timer.tick().await; // consume the first immediate tick

    loop {
        // Force a cooperative yield each iteration so the runtime can
        // tick its time wheel and poll other tasks. Without this, when
        // `next_event` is always immediately ready (steady-state heavy
        // build load), the main loop never suspends, the runtime never
        // advances time, and timer-based work — including the wedge
        // watchdog, reputation_save_timer, and tokio::time::Instant —
        // never fires. The pre-eda4981 audit_sink.log path used to
        // yield naturally via `spawn_blocking + .await`; the async
        // writer replaced that with `try_send`, removing the implicit
        // yield. This re-adds it explicitly.
        tokio::task::yield_now().await;

        // ---- Select: shutdown signal vs. syscall event vs. DNS query vs. periodic save ----
        enum LoopEvent {
            Shutdown,
            Syscall(SyscallEvent),
            /// Supervised tool exited cleanly (interceptor returned `Ok(None)`).
            ChildExit,
            /// Interceptor returned an error mid-loop; the session ends but
            /// distinctly from a clean child exit.
            InterceptorError,
            DnsQuery(crate::dns_proxy::DnsQueryEvent),
            ReputationSave,
            /// Watchdog tick — scan for wedged tracees.
            WedgeScan,
        }

        let loop_event = tokio::select! {
            _ = shutdown_rx.recv() => LoopEvent::Shutdown,
            result = interceptor.next_event() => {
                match result {
                    Ok(Some(ev)) => LoopEvent::Syscall(ev),
                    Ok(None) => LoopEvent::ChildExit,
                    Err(e) => {
                        tracing::info!(
                            session_id = %session.id,
                            error = %e,
                            "interceptor ended, exiting supervisor loop"
                        );
                        LoopEvent::InterceptorError
                    }
                }
            }
            query = async {
                if let Some(rx) = &loop_ctx.dns_query_rx {
                    rx.lock().await.recv().await
                } else {
                    // No DNS proxy — pend forever so this branch is never selected
                    std::future::pending().await
                }
            } => {
                match query {
                    Some(q) => LoopEvent::DnsQuery(q),
                    None => continue, // DNS proxy channel closed
                }
            }
            _ = reputation_save_timer.tick() => LoopEvent::ReputationSave,
            _ = watchdog_timer.tick() => LoopEvent::WedgeScan,
        };

        match loop_event {
            LoopEvent::Shutdown => {
                tracing::info!(session_id = %session.id, "shutdown signal received, detaching");
                save_reputation(&loop_ctx);
                log_final_stats(session);
                if let Err(e) = interceptor.detach_all().await {
                    tracing::warn!(error = %e, "error during detach_all on shutdown");
                }
                evict_session_state_on_end(&loop_ctx, session, session_start, "shutdown").await;
                return Ok(());
            }
            LoopEvent::ChildExit => {
                save_reputation(&loop_ctx);
                log_final_stats(session);
                tracing::info!(
                    session_id = %session.id,
                    "all supervised processes exited, ending supervisor loop"
                );
                evict_session_state_on_end(&loop_ctx, session, session_start, "child_exit").await;
                return Ok(());
            }
            LoopEvent::InterceptorError => {
                save_reputation(&loop_ctx);
                log_final_stats(session);
                evict_session_state_on_end(&loop_ctx, session, session_start, "interceptor_error")
                    .await;
                return Ok(());
            }
            LoopEvent::ReputationSave => {
                save_reputation(&loop_ctx);
            }
            LoopEvent::Syscall(event) => {
                handle_syscall_event(interceptor, session, &loop_ctx, event).await?;
                sync_session_state(session, &loop_ctx).await;
            }
            LoopEvent::DnsQuery(query_event) => {
                event_handler::handle_dns_query_event(session, &loop_ctx, query_event).await;
                sync_session_state(session, &loop_ctx).await;
            }
            LoopEvent::WedgeScan => {
                let wedged = interceptor.wedge_scan(WATCHDOG_THRESHOLD);
                if !wedged.is_empty() {
                    event_handler::report_wedged_tracees(session, &loop_ctx, &wedged).await;
                }
            }
        }
    }
}

/// PR 1 Phase F: drop this session's per-scope filter state and
/// `SessionStateRegistry` entry. Called from both Shutdown and Done exit
/// branches of `run_supervisor_loop` so the next session starts cold even
/// when the current one ended cleanly. The crash case is handled by the
/// session-start stale-sweep at the top of `run_supervisor_loop`.
///
/// PR 1 Phase G: also emits a structured `event = "session_end"` line
/// carrying duration, `containment_triggered`, and the eviction count.
/// The eviction count is filters-only; the `SessionStateRegistry` entry
/// is read for `containment_triggered` *before* eviction so we can
/// report whether the session ever activated containment.
async fn evict_session_state_on_end(
    loop_ctx: &event_handler::SupervisorLoopContext<'_>,
    session: &SupervisorSession,
    session_start: std::time::Instant,
    reason: &'static str,
) {
    let session_id = session.id;
    let scope = grith_proxy::types::SessionScopeKey::from_session_id(session_id);
    let containment_triggered =
        grith_proxy::session_state::SessionStateRegistry::global().is_containment_active(scope);
    let removed = loop_ctx.proxy.evict_session_state(scope);
    let duration_secs = session_start.elapsed().as_secs_f64();
    tracing::info!(
        event = "session_end",
        session_id = %session_id,
        scope = %scope,
        reason,
        duration_secs,
        containment_triggered,
        filter_entries_removed = removed,
        "supervisor session ended",
    );
    log_session_lifecycle_audit(
        loop_ctx,
        session,
        "session_end",
        serde_json::json!({
            "scope": scope.to_string(),
            "reason": reason,
            "duration_secs": duration_secs,
            "containment_triggered": containment_triggered,
            "filter_entries_removed": removed,
        }),
        "supervisor session ended",
    )
    .await;
}

async fn log_session_lifecycle_audit(
    loop_ctx: &event_handler::SupervisorLoopContext<'_>,
    session: &SupervisorSession,
    event_name: &str,
    arguments: serde_json::Value,
    reason: &str,
) {
    let mut record = AuditRecord::new(
        session.id,
        "supervisor".into(),
        event_name.into(),
        &arguments,
        0.0,
        ProxyActionSummary::Allow,
        Vec::new(),
        0.0,
        Some(reason.into()),
    )
    .with_supervisor_source(session.tool_name.clone(), session.root_pid);
    record.execution_result = Some(reason.into());
    if let Err(e) = loop_ctx.audit_sink.log(record).await {
        tracing::error!(
            error = %e,
            event = event_name,
            "failed to log supervisor lifecycle audit event"
        );
    }
}

fn save_reputation(loop_ctx: &event_handler::SupervisorLoopContext<'_>) {
    if !loop_ctx.persist_local_reputation {
        return;
    }
    if let Ok(table) = loop_ctx.reputation_table.lock() {
        let path = grith_proxy::reputation::default_reputation_path();
        match table.save(&path) {
            Ok(()) => {
                tracing::info!(
                    entries = table.len(),
                    path = %path.display(),
                    "saved reputation table"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to save reputation table");
            }
        }
    }
}

async fn sync_session_state(
    session: &SupervisorSession,
    loop_ctx: &event_handler::SupervisorLoopContext<'_>,
) {
    let Some(sync) = &loop_ctx.session_sync else {
        return;
    };
    if let Err(e) = sync.sync(session).await {
        tracing::warn!(session_id = %session.id, error = %e, "failed to sync session state");
    }
}

fn log_final_stats(session: &SupervisorSession) {
    let s = &session.stats;
    let proxy_evals = s.total_allowed + s.total_queued + s.total_denied;
    let msg = format!(
        "FINAL tool={} duration_secs={} intercepted={} noise={} proxy_evals={} allowed={} queued={} denied={} noise_pct={:.1}%",
        session.tool_name,
        session.started_at.elapsed().as_secs(),
        s.total_intercepted,
        s.total_filtered_noise,
        proxy_evals,
        s.total_allowed,
        s.total_queued,
        s.total_denied,
        s.total_filtered_noise as f64 / s.total_intercepted.max(1) as f64 * 100.0,
    );
    tracing::info!("{}", msg);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interceptor::{OpenFlags, SyscallEvent, SyscallInterceptor, SyscallKind};
    use async_trait::async_trait;
    use chrono::Utc;
    use grith_proxy::engine::SecurityProxy;
    use grith_proxy::filters::{FilterPhase, FilterRegistry, SecurityFilter};
    use grith_proxy::meta_rules::MetaRuleEngine;
    use grith_proxy::scoring::ScoringConfig;
    use grith_proxy::types::{FilterResult, Severity, ToolCallContext};
    use std::collections::VecDeque;
    use std::time::Duration;

    #[derive(Default, Debug)]
    struct MockInterceptorState {
        allow_pids: Vec<u32>,
        deny_pids: Vec<u32>,
        freeze_pids: Vec<u32>,
        thaw_pids: Vec<u32>,
        detach_calls: Vec<u32>,
        detach_all_calls: u32,
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

        async fn freeze(&mut self, pid: u32) -> crate::error::Result<()> {
            self.state.lock().unwrap().freeze_pids.push(pid);
            Ok(())
        }

        async fn thaw(&mut self, pid: u32) -> crate::error::Result<()> {
            self.state.lock().unwrap().thaw_pids.push(pid);
            Ok(())
        }

        async fn detach(&mut self, pid: u32) -> crate::error::Result<()> {
            self.state.lock().unwrap().detach_calls.push(pid);
            Ok(())
        }

        async fn detach_all(&mut self) -> crate::error::Result<()> {
            self.state.lock().unwrap().detach_all_calls += 1;
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

    struct FixedQueueFilter {
        score: f64,
    }

    #[async_trait]
    impl SecurityFilter for FixedQueueFilter {
        fn name(&self) -> &str {
            "fixed_queue_filter"
        }

        fn phase(&self) -> FilterPhase {
            FilterPhase::Static
        }

        async fn evaluate(
            &self,
            _ctx: &ToolCallContext,
        ) -> grith_proxy::error::Result<FilterResult> {
            Ok(FilterResult::matched(
                self.name(),
                "forced-queue",
                self.score,
                Severity::Warning,
                "force queue for supervisor lifecycle test",
            ))
        }
    }

    fn queue_only_proxy(queue_score: f64) -> Arc<SecurityProxy> {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(FixedQueueFilter { score: queue_score }));
        let scoring = ScoringConfig {
            auto_allow_threshold: 3.0,
            auto_deny_threshold: 8.0,
        };
        Arc::new(SecurityProxy::new(
            registry,
            scoring,
            MetaRuleEngine::new(vec![]),
        ))
    }

    fn allow_only_proxy() -> Arc<SecurityProxy> {
        queue_only_proxy(0.0)
    }

    fn sample_file_read_event(pid: u32) -> SyscallEvent {
        SyscallEvent {
            pid,
            tid: pid,
            timestamp: Utc::now(),
            kind: SyscallKind::FileOpen {
                path: "/tmp/supervisor-e2e.txt".into(),
                flags: OpenFlags::ReadOnly,
            },
            raw_syscall_nr: 257,
            sockaddr_addr: None,
        }
    }

    fn sample_fd_read_event(pid: u32, fd: i32, path: &str) -> SyscallEvent {
        SyscallEvent {
            pid,
            tid: pid,
            timestamp: Utc::now(),
            kind: SyscallKind::FileRead {
                fd,
                path: Some(path.into()),
            },
            raw_syscall_nr: 0,
            sockaddr_addr: None,
        }
    }

    #[test]
    fn effective_policy_for_session_uses_launcher_and_provider_overlays() {
        let mut session = SupervisorSession::new("grith-repl", 4242);
        session.profile_name = Some("grith-repl".into());
        session.launcher_overlay_name = Some("vscode-terminal".into());
        session.provider_overlay_name = Some("openai".into());

        let policy = effective_policy_for_session(&session).expect("effective policy should load");

        assert_eq!(
            policy.scope_key,
            "grith-repl+provider:openai+launcher:vscode-terminal"
        );
        assert!(
            policy
                .merged_profile
                .routine_commands
                .contains(&"code".to_string()),
            "launcher overlay command should be merged"
        );
        assert!(
            policy
                .merged_profile
                .routine_destinations
                .contains(&"api.openai.com".to_string()),
            "provider overlay destinations should be merged"
        );
    }

    #[tokio::test]
    async fn queued_syscall_approved_allows_original_call() {
        let pid = 4242;
        let (mock, state) = MockInterceptor::new(vec![sample_file_read_event(pid)]);
        let mut interceptor: Box<dyn SyscallInterceptor> = Box::new(mock);
        let mut session = SupervisorSession::new("mock-tool", pid);
        let proxy = queue_only_proxy(4.0);
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
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let _shutdown_tx = shutdown_tx;
        let mut config = SupervisorConfig::default();
        config.noise_reduction.ignore_read_only = false;

        let reviewer_queue = digest_queue.clone();
        let reviewer = tokio::spawn(async move {
            let start = std::time::Instant::now();
            loop {
                let pending_id = reviewer_queue
                    .get_pending(1, 0)
                    .ok()
                    .and_then(|items| items.into_iter().next().map(|i| i.id));
                if let Some(id) = pending_id {
                    reviewer_queue
                        .update_status(
                            &id,
                            grith_digest::types::DigestStatus::Approved,
                            Some("approve"),
                            Some("test"),
                        )
                        .unwrap();
                    break;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(2),
                    "timed out waiting for queued digest item"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        let run = tokio::time::timeout(
            Duration::from_secs(3),
            run_supervisor_loop(
                &mut interceptor,
                &mut session,
                proxy,
                audit_sink,
                digest_store,
                &dlp_redactor,
                correlation_tracker,
                Arc::new(ContainmentTracker::with_defaults()),
                &config,
                shutdown_rx,
                None,
                None,
                None,
                &[],
                std::collections::HashSet::new(),
                None,
                None,
                None,
                None,
                None,
            ),
        )
        .await;

        assert!(run.is_ok(), "supervisor loop timed out");
        run.unwrap().unwrap();
        reviewer.await.unwrap();

        let s = state.lock().unwrap();
        assert_eq!(
            s.allow_pids,
            vec![pid],
            "queued+approved should allow syscall"
        );
        assert!(
            s.deny_pids.is_empty(),
            "queued+approved must not deny syscall"
        );
        assert_eq!(session.stats.total_queued, 1);
        assert_eq!(session.stats.total_denied, 0);
        assert_eq!(digest_queue.count_pending().unwrap(), 0);
    }

    #[tokio::test]
    async fn queued_syscall_denied_blocks_original_call() {
        let pid = 4343;
        let (mock, state) = MockInterceptor::new(vec![sample_file_read_event(pid)]);
        let mut interceptor: Box<dyn SyscallInterceptor> = Box::new(mock);
        let mut session = SupervisorSession::new("mock-tool", pid);
        let proxy = queue_only_proxy(4.0);
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
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let _shutdown_tx = shutdown_tx;
        let mut config = SupervisorConfig::default();
        config.noise_reduction.ignore_read_only = false;
        config.interactive_queue_action = crate::config::InteractiveQueueAction::Freeze;

        let reviewer_queue = digest_queue.clone();
        let reviewer = tokio::spawn(async move {
            let start = std::time::Instant::now();
            loop {
                let pending_id = reviewer_queue
                    .get_pending(1, 0)
                    .ok()
                    .and_then(|items| items.into_iter().next().map(|i| i.id));
                if let Some(id) = pending_id {
                    reviewer_queue
                        .update_status(
                            &id,
                            grith_digest::types::DigestStatus::Denied,
                            Some("deny"),
                            Some("test"),
                        )
                        .unwrap();
                    break;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(2),
                    "timed out waiting for queued digest item"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        let run = tokio::time::timeout(
            Duration::from_secs(3),
            run_supervisor_loop(
                &mut interceptor,
                &mut session,
                proxy,
                audit_sink,
                digest_store,
                &dlp_redactor,
                correlation_tracker,
                Arc::new(ContainmentTracker::with_defaults()),
                &config,
                shutdown_rx,
                None,
                None,
                None,
                &[],
                std::collections::HashSet::new(),
                None,
                None,
                None,
                None,
                None,
            ),
        )
        .await;

        assert!(run.is_ok(), "supervisor loop timed out");
        run.unwrap().unwrap();
        reviewer.await.unwrap();

        let s = state.lock().unwrap();
        assert_eq!(s.deny_pids, vec![pid], "queued+denied should deny syscall");
        assert!(
            s.allow_pids.is_empty(),
            "queued+denied must not allow syscall"
        );
        assert_eq!(session.stats.total_queued, 1);
        assert_eq!(session.stats.total_denied, 1);
        assert_eq!(digest_queue.count_pending().unwrap(), 0);
    }

    #[tokio::test]
    async fn queued_syscall_timeout_auto_denies_original_call() {
        let pid = 4444;
        let (mock, state) = MockInterceptor::new(vec![sample_file_read_event(pid)]);
        let mut interceptor: Box<dyn SyscallInterceptor> = Box::new(mock);
        let mut session = SupervisorSession::new("mock-tool", pid);
        let proxy = queue_only_proxy(4.0);
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
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let _shutdown_tx = shutdown_tx;

        let mut config = SupervisorConfig {
            freeze_timeout_seconds: 0,
            ..Default::default()
        };
        config.noise_reduction.ignore_read_only = false;
        config.interactive_queue_action = crate::config::InteractiveQueueAction::Freeze;

        let run = tokio::time::timeout(
            Duration::from_secs(3),
            run_supervisor_loop(
                &mut interceptor,
                &mut session,
                proxy,
                audit_sink,
                digest_store,
                &dlp_redactor,
                correlation_tracker,
                Arc::new(ContainmentTracker::with_defaults()),
                &config,
                shutdown_rx,
                None,
                None,
                None,
                &[],
                std::collections::HashSet::new(),
                None,
                None,
                None,
                None,
                None,
            ),
        )
        .await;

        assert!(run.is_ok(), "supervisor loop timed out");
        run.unwrap().unwrap();

        let s = state.lock().unwrap();
        assert_eq!(
            s.deny_pids,
            vec![pid],
            "queued+timeout should auto-deny syscall"
        );
        assert!(
            s.allow_pids.is_empty(),
            "queued+timeout must not allow syscall"
        );
        assert_eq!(session.stats.total_queued, 1);
        assert_eq!(session.stats.total_denied, 1);
        assert_eq!(digest_queue.count_pending().unwrap(), 0);
    }

    #[tokio::test]
    async fn ignore_read_only_noise_reduction_bypasses_proxy() {
        let pid = 4545;
        let read_only_open = SyscallEvent {
            pid,
            tid: pid,
            timestamp: Utc::now(),
            kind: SyscallKind::FileOpen {
                path: "/tmp/supervisor-noise-readonly.txt".into(),
                flags: OpenFlags::ReadOnly,
            },
            raw_syscall_nr: 257,
            sockaddr_addr: None,
        };
        let (mock, state) = MockInterceptor::new(vec![read_only_open]);
        let mut interceptor: Box<dyn SyscallInterceptor> = Box::new(mock);
        let mut session = SupervisorSession::new("mock-tool", pid);
        // Use a queueing proxy so the test would fail if read-only noise
        // reduction does not bypass proxy evaluation.
        let proxy = queue_only_proxy(4.0);
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
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let _shutdown_tx = shutdown_tx;

        let mut config = SupervisorConfig::default();
        config.noise_reduction.ignore_read_only = true;
        config.noise_reduction.batch_rapid_reads = false;

        let run = tokio::time::timeout(
            Duration::from_secs(3),
            run_supervisor_loop(
                &mut interceptor,
                &mut session,
                proxy,
                audit_sink,
                digest_store,
                &dlp_redactor,
                correlation_tracker,
                Arc::new(ContainmentTracker::with_defaults()),
                &config,
                shutdown_rx,
                None,
                None,
                None,
                &[],
                std::collections::HashSet::new(),
                None,
                None,
                None,
                None,
                None,
            ),
        )
        .await;

        assert!(run.is_ok(), "supervisor loop timed out");
        run.unwrap().unwrap();

        let s = state.lock().unwrap();
        assert_eq!(
            s.allow_pids,
            vec![pid],
            "read-only noise-reduced event should be allowed immediately"
        );
        assert_eq!(session.stats.total_filtered_noise, 1);
        assert_eq!(session.stats.total_queued, 0);
    }

    #[tokio::test]
    async fn batch_rapid_reads_coalesces_repeated_fd_reads() {
        let pid = 4646;
        let events = vec![
            sample_fd_read_event(pid, 7, "/tmp/supervisor-batch.txt"),
            sample_fd_read_event(pid, 7, "/tmp/supervisor-batch.txt"),
        ];
        let (mock, state) = MockInterceptor::new(events);
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
            Arc::new(crate::reviewer::LocalDigestStore::new(digest_queue.clone()));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let _shutdown_tx = shutdown_tx;

        let mut config = SupervisorConfig::default();
        config.noise_reduction.batch_rapid_reads = true;
        config.noise_reduction.batch_window_ms = 1_000;
        config.noise_reduction.ignore_read_only = false;

        let run = tokio::time::timeout(
            Duration::from_secs(3),
            run_supervisor_loop(
                &mut interceptor,
                &mut session,
                proxy,
                audit_sink,
                digest_store,
                &dlp_redactor,
                correlation_tracker,
                Arc::new(ContainmentTracker::with_defaults()),
                &config,
                shutdown_rx,
                None,
                None,
                None,
                &[],
                std::collections::HashSet::new(),
                None,
                None,
                None,
                None,
                None,
            ),
        )
        .await;

        assert!(run.is_ok(), "supervisor loop timed out");
        run.unwrap().unwrap();

        let s = state.lock().unwrap();
        assert_eq!(s.allow_pids, vec![pid, pid]);
        assert_eq!(
            session.stats.total_filtered_noise, 1,
            "second rapid read should be coalesced as noise"
        );
        assert_eq!(session.stats.total_allowed, 1);
    }
}
