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
pub mod session_state;

// Re-export all public types so that `crate::supervisor::Foo` continues to work.
pub use session_state::{SessionStats, SessionSummary, SupervisorRegistry, SupervisorSession};

use std::sync::{Arc, Mutex};
use std::time::Duration;

use grith_audit::CorrelationTracker;
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
    };

    tracing::info!(
        session_id = %session.id,
        tool = %session.tool_name,
        root_pid = session.root_pid,
        "supervisor loop started"
    );

    let save_interval =
        Duration::from_secs(config.reputation_config.save_interval_seconds().max(30));
    let mut reputation_save_timer = tokio::time::interval(save_interval);
    reputation_save_timer.tick().await; // consume the first immediate tick

    loop {
        // ---- Select: shutdown signal vs. syscall event vs. DNS query vs. periodic save ----
        enum LoopEvent {
            Shutdown,
            Syscall(SyscallEvent),
            Done,
            DnsQuery(crate::dns_proxy::DnsQueryEvent),
            ReputationSave,
        }

        let loop_event = tokio::select! {
            _ = shutdown_rx.recv() => LoopEvent::Shutdown,
            result = interceptor.next_event() => {
                match result {
                    Ok(Some(ev)) => LoopEvent::Syscall(ev),
                    Ok(None) => LoopEvent::Done,
                    Err(e) => {
                        tracing::info!(
                            session_id = %session.id,
                            error = %e,
                            "interceptor ended, exiting supervisor loop"
                        );
                        LoopEvent::Done
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
        };

        match loop_event {
            LoopEvent::Shutdown => {
                tracing::info!(session_id = %session.id, "shutdown signal received, detaching");
                save_reputation(&loop_ctx);
                log_final_stats(session);
                if let Err(e) = interceptor.detach_all().await {
                    tracing::warn!(error = %e, "error during detach_all on shutdown");
                }
                return Ok(());
            }
            LoopEvent::Done => {
                save_reputation(&loop_ctx);
                log_final_stats(session);
                tracing::info!(
                    session_id = %session.id,
                    "all supervised processes exited, ending supervisor loop"
                );
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
        }
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
            cold_start_calls: 0,
            cold_start_escalation_low: 2.0,
            cold_start_escalation_high: 10.0,
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
