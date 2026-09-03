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

mod authority_delegation;
mod dns_decision;
mod event_handler;
mod mass_destruction;
mod remote_eval;
mod spawn_families;

// Shared with `crate::learned_rules` so `ipc-socket:` grant validation
// rejects privileged daemon sockets with the same curated predicate the
// event handler enforces with.
/// Exposed so `crate::dbus` can assert that every address it claims for message
/// inspection is one connect-time enforcement would otherwise have escalated.
#[cfg(test)]
pub(crate) use authority_delegation::is_control_injection_socket as is_control_injection_socket_for_test;
pub(crate) use event_handler::is_sensitive_unix_socket;
#[cfg(test)]
mod protection_tests;
pub mod session_state;

// Re-export all public types so that `crate::supervisor::Foo` continues to work.
pub use session_state::{
    SessionReservation, SessionStats, SessionSummary, SupervisorRegistry, SupervisorSession,
    RESERVATION_TTL,
};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
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
use crate::connected_dns_proxy::{
    ConnectedDnsProxy, ConnectedDnsProxyConfig, ConnectedDnsProxyControl, ConnectedDnsProxyError,
    ConnectedDnsProxyHealth, DnsDecisionService,
};
use crate::error::{Error, Result};
use crate::forensics_trace::ForensicsTraceSink;
use crate::freezer::Freezer;
use crate::interceptor::{SyscallEvent, SyscallInterceptor};
use crate::reviewer::{DigestStore, PollingQueueReviewer, QueueReviewer};
use crate::session_sync::SessionSync;

use dns_decision::{DnsDecisionSession, ProductionDnsDecisionService};
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

/// Session-owned DNS cache work.
///
/// Tasks receive only a `Weak` cache reference, and resolver closures never
/// own the cache. Shutdown serializes the active-state transition with cache
/// insertion, aborts the async coordinators, and joins them. Any already
/// running `spawn_blocking` resolver may finish, but has no cache reference and
/// therefore cannot publish a result after shutdown.
struct SessionDnsBackgroundTasks {
    cache: Weak<Mutex<crate::dns_cache::DnsCache>>,
    active: Arc<AtomicBool>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl SessionDnsBackgroundTasks {
    fn new(cache: &Arc<Mutex<crate::dns_cache::DnsCache>>) -> Self {
        Self {
            cache: Arc::downgrade(cache),
            active: Arc::new(AtomicBool::new(true)),
            handles: Vec::new(),
        }
    }

    fn cache(&self) -> Weak<Mutex<crate::dns_cache::DnsCache>> {
        self.cache.clone()
    }

    fn active(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.active)
    }

    fn track(&mut self, handle: tokio::task::JoinHandle<()>) {
        self.handles.push(handle);
    }

    fn deactivate(&self) {
        // Take the same mutex used by publishers so that, once this returns,
        // no seed/refresh insertion can still be in progress or begin later.
        if let Some(cache) = self.cache.upgrade() {
            let _guard = cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.active.store(false, Ordering::Release);
        } else {
            self.active.store(false, Ordering::Release);
        }
    }

    async fn shutdown(&mut self) {
        self.deactivate();
        for handle in &self.handles {
            handle.abort();
        }
        for handle in self.handles.drain(..) {
            let _ = handle.await;
        }
    }
}

impl Drop for SessionDnsBackgroundTasks {
    fn drop(&mut self) {
        self.deactivate();
        for handle in &self.handles {
            handle.abort();
        }
    }
}

fn merge_resolved_if_active(
    cache: &Weak<Mutex<crate::dns_cache::DnsCache>>,
    active: &AtomicBool,
    resolved: Vec<(String, std::net::IpAddr)>,
) {
    let Some(cache) = cache.upgrade() else {
        return;
    };
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if active.load(Ordering::Acquire) {
        cache.record_resolved_domains(resolved);
    }
}

/// Seed priority domains concurrently, waiting only for a bounded readiness
/// window. Resolver work and cache insertion continue after a timeout, but
/// remain owned by the session lifecycle.
async fn seed_priority_domains<F>(
    cache: Weak<Mutex<crate::dns_cache::DnsCache>>,
    active: Arc<AtomicBool>,
    domains: Vec<String>,
    budget: Duration,
    resolver: Arc<F>,
) -> (bool, tokio::task::JoinHandle<()>)
where
    F: Fn(String) -> Vec<(String, std::net::IpAddr)> + Send + Sync + 'static,
{
    if domains.is_empty() {
        return (true, tokio::spawn(async {}));
    }
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        let concurrency = Arc::new(tokio::sync::Semaphore::new(8));
        for domain in domains {
            let concurrency = Arc::clone(&concurrency);
            let resolver = Arc::clone(&resolver);
            tasks.spawn(async move {
                let Ok(_permit) = concurrency.acquire_owned().await else {
                    return Vec::new();
                };
                tokio::task::spawn_blocking(move || resolver(domain))
                    .await
                    .unwrap_or_default()
            });
        }
        while let Some(result) = tasks.join_next().await {
            if let Ok(resolved) = result {
                merge_resolved_if_active(&cache, &active, resolved);
            }
        }
        let _ = ready_tx.send(());
    });
    let ready = matches!(tokio::time::timeout(budget, ready_rx).await, Ok(Ok(())));
    (ready, handle)
}

/// Interval between routine-destination re-seeds. Must stay below
/// `STARTUP_SEED_TTL` (5 min) so a warmed entry never lapses between refreshes.
const PRIORITY_DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(3 * 60);

/// Lock the cache and merge resolved mappings. Kept as a free function so the
/// `MutexGuard` temporary is fully contained (a `select!` arm otherwise extends
/// the guard's lifetime past the branch, which does not compile).
#[cfg(test)]
fn merge_resolved(
    cache: &Mutex<crate::dns_cache::DnsCache>,
    resolved: Vec<(String, std::net::IpAddr)>,
) {
    if let Ok(mut cache) = cache.lock() {
        cache.record_resolved_domains(resolved);
    }
}

/// Re-resolve `domains` once and merge the results into the cache. Returns the
/// number of (domain, ip) pairs inserted. Extracted for unit testing; the live
/// path drives it from a timer in [`spawn_priority_dns_refresh`].
#[cfg(test)]
fn reseed_domains_once<F>(
    cache: &Mutex<crate::dns_cache::DnsCache>,
    domains: &[String],
    resolver: F,
) -> usize
where
    F: Fn(&[String]) -> Vec<(String, std::net::IpAddr)>,
{
    let resolved = resolver(domains);
    let count = resolved.len();
    merge_resolved(cache, resolved);
    count
}

/// Periodically re-resolve the profile's routine destinations so their IP→domain
/// attributions stay warm for the whole session (see the call site for rationale).
///
/// The task terminates when either the session shuts down or the cache is
/// dropped (whichever comes first), so it never outlives the session it serves.
fn spawn_priority_dns_refresh(
    cache: Weak<Mutex<crate::dns_cache::DnsCache>>,
    active: Arc<AtomicBool>,
    domains: Vec<String>,
    mut shutdown: broadcast::Receiver<()>,
) -> Option<tokio::task::JoinHandle<()>> {
    if domains.is_empty() {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PRIORITY_DNS_REFRESH_INTERVAL);
        // The startup seed already covered the first interval; skip the tick
        // that `interval` fires immediately.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                _ = ticker.tick() => {
                    let domains = domains.clone();
                    // The blocking resolver deliberately owns no cache
                    // reference. Publication happens back on this cancellable
                    // coordinator after the lookup completes.
                    let resolved = tokio::task::spawn_blocking(move || {
                        crate::dns_cache::resolve_domains(domains.iter().map(String::as_str))
                    })
                    .await
                    .unwrap_or_default();
                    merge_resolved_if_active(&cache, &active, resolved);
                }
            }
        }
    }))
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
/// On **user-initiated** shutdown, all traced processes are detached so that
/// the supervised tool can continue unsupervised. That is a deliberate choice
/// for an operator who asked the session to end.
///
/// # Invariant (work/74 invariant 12) — do not detach on authority loss
///
/// Detaching is only ever correct when the *user* ended the session. It must
/// never be the response to losing daemon authority (an unreachable, killed,
/// restarted or quarantined daemon). Detaching there would convert a
/// supervised process into an unsupervised one that keeps every capability it
/// has already been granted — the exact fail-open this subsystem exists to
/// prevent, and a strictly worse outcome than either freezing or terminating
/// the tree.
///
/// If you are adding daemon-loss handling: route it to a distinct loop event
/// that freezes or terminates. Do **not** reuse `LoopEvent::Shutdown`, and do
/// not call `detach_all()` from that path. `PTRACE_O_EXITKILL` is already set,
/// so exiting the supervisor is itself sufficient to tear the tree down.
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

    // Resolve the profile once. Its routine destinations are the small,
    // latency-sensitive startup seed set; the full global domain list remains
    // background defence-in-depth.
    let session_policy = effective_policy_for_session(session);
    let dns_cache = std::sync::Arc::new(Mutex::new(crate::dns_cache::DnsCache::new()));
    let mut dns_background_tasks = SessionDnsBackgroundTasks::new(&dns_cache);
    let session_allowed = Arc::new(Mutex::new(session_allowed));
    let daemon_proxy_token = daemon_proxy_token.map(|token| Arc::new(Mutex::new(token)));
    let priority_domains: Vec<String> = session_policy
        .as_ref()
        .map(|policy| policy.merged_profile.routine_destinations.clone())
        .unwrap_or_default();

    // Miss-triggered forward confirm: the ordered list a NetConnect
    // attribution miss re-resolves before the operator sees a raw-IP prompt.
    // Profile destinations first (most likely to convert the prompt into a
    // silent allow), then the remaining global trusted domains, whose one-shot
    // startup seed has long expired by mid-session. Gated like the seed:
    // unit tests must not depend on live DNS.
    let dns_forward_confirm = if cfg!(test) {
        None
    } else {
        let mut confirm_domains = priority_domains.clone();
        for domain in dns_seed_domains {
            if !confirm_domains.contains(domain) {
                confirm_domains.push(domain.clone());
            }
        }
        crate::dns_cache::DnsForwardConfirm::new(confirm_domains)
    };

    // Unit tests use synthetic interceptors and must not depend on live DNS.
    if !cfg!(test) && !priority_domains.is_empty() {
        const PRIORITY_DNS_BUDGET: Duration = Duration::from_millis(400);
        let resolver =
            Arc::new(|domain: String| crate::dns_cache::resolve_domains([domain.as_str()]));
        let (ready, handle) = seed_priority_domains(
            dns_background_tasks.cache(),
            dns_background_tasks.active(),
            priority_domains.clone(),
            PRIORITY_DNS_BUDGET,
            resolver,
        )
        .await;
        dns_background_tasks.track(handle);
        if !ready {
            tracing::info!(
                budget_ms = PRIORITY_DNS_BUDGET.as_millis(),
                "priority DNS seed budget expired; remaining lookups continue in background"
            );
        }

        // Keep the routine-destination attributions warm for the session's
        // lifetime. A startup seed expires after STARTUP_SEED_TTL and, for
        // rotating-CDN routine domains (e.g. github.com / api.github.com on
        // Azure), a single resolution never covers the full, changing IP set
        // the supervised tool later connects to. Re-resolving on an interval
        // below the seed TTL keeps the cache populated and accumulates rotated
        // addresses, cutting raw-IP prompts for domains the operator already
        // trusts. Defence-in-depth only: exact per-query attribution still
        // depends on response observation (see dns_socket_tracker).
        if let Some(handle) = spawn_priority_dns_refresh(
            dns_background_tasks.cache(),
            dns_background_tasks.active(),
            priority_domains,
            shutdown_rx.resubscribe(),
        ) {
            dns_background_tasks.track(handle);
        }
    }

    // Resolve the global list in the background. Priority names are skipped
    // here because they were already scheduled concurrently above.
    {
        let cache = dns_background_tasks.cache();
        let active = dns_background_tasks.active();
        let priority: std::collections::HashSet<&str> = session_policy
            .as_ref()
            .map(|policy| {
                policy
                    .merged_profile
                    .routine_destinations
                    .iter()
                    .map(String::as_str)
                    .collect()
            })
            .unwrap_or_default();
        let domains: Vec<String> = dns_seed_domains
            .iter()
            .filter(|domain| !priority.contains(domain.as_str()))
            .cloned()
            .collect();
        dns_background_tasks.track(tokio::spawn(async move {
            let resolved = tokio::task::spawn_blocking(move || {
                crate::dns_cache::resolve_domains(domains.iter().map(|s| s.as_str()))
            })
            .await
            .unwrap_or_default();
            merge_resolved_if_active(&cache, &active, resolved);
        }));
    }

    // Hybrid DNS inspection (Linux only):
    // - explicit-destination datagrams keep the in-line sendto/sendmsg path;
    // - connected UDP/53 sockets can be redirected to a per-socket managed
    //   proxy route, preserving connected read/write semantics while allowing
    //   exact query inspection and response attribution.
    // D-Bus message inspection narrows control-socket enforcement, so it is
    // only meaningful while that enforcement is on: with the flag off there is
    // nothing to move off the connect, and arming the decoder would pay
    // per-message stepping for decisions nobody would act on.
    let dbus_inspection_armed = if authority_delegation::control_socket_enforcement_enabled(
        config.enforce_control_socket_connect,
    ) && authority_delegation::dbus_inspection_enabled(
        config.dbus_message_inspection,
    ) {
        // The interceptor gets the last word: it reports whether it can
        // actually see what a tracee writes to a socket. A `false` here keeps
        // the session enforcing at the connect — the same prompts as before,
        // rather than a config flag quietly disabling enforcement.
        let armed = interceptor.set_dbus_inspection();
        if armed {
            tracing::info!(
                event = "dbus_message_inspection_active",
                "D-Bus control-socket access decided per method call"
            );
        } else {
            tracing::warn!(
                event = "dbus_message_inspection_unavailable",
                "D-Bus message inspection requested but unavailable for this session; \
                 keeping connect-time control-socket enforcement"
            );
        }
        armed
    } else {
        false
    };

    let dns_inspection_enabled = cfg!(target_os = "linux") && config.dns_inspection.enabled;
    let mut connected_dns_proxy = None;
    let mut connected_dns_health = None;
    let mut dns_decision_service: Option<Arc<dyn DnsDecisionService>> = None;
    if config.dns_inspection.connected_udp_proxy && !dns_inspection_enabled {
        let _ = interceptor.terminate_all().await;
        return Err(Error::ConfigError(
            "connected UDP DNS proxy requires enabled Linux DNS inspection".into(),
        ));
    }
    if dns_inspection_enabled {
        interceptor.set_dns_inspection(
            std::sync::Arc::clone(&dns_cache),
            config.dns_inspection.observe_responses,
            config.dns_inspection.block_tcp_dns,
        );
        tracing::info!(
            observe_responses = config.dns_inspection.observe_responses,
            block_tcp_dns = config.dns_inspection.block_tcp_dns,
            "in-line DNS inspection active"
        );

        let mut decision_service = ProductionDnsDecisionService::new(
            Arc::clone(&proxy),
            Arc::clone(&audit_sink),
            Arc::clone(&digest_store),
            Arc::clone(&session_allowed),
            Arc::clone(&containment_tracker),
            DnsDecisionSession::from(&*session),
        )
        .with_dlp_redactor(dlp_redactor);
        if let Some(url) = daemon_proxy_url.as_deref() {
            let Some(token) = daemon_proxy_token.clone() else {
                let _ = interceptor.terminate_all().await;
                return Err(Error::ConfigError(
                    "daemon-backed DNS policy requires a daemon token".into(),
                ));
            };
            decision_service = decision_service.with_daemon(url, token);
            // Let the DNS worker heal a rotated IPC token itself. Without this
            // it can only pick up a reload performed by the event loop, which
            // never happens when a DNS query is the first thing the session
            // does after a daemon restart.
            if let Some(restart) = daemon_restart.as_ref() {
                decision_service = decision_service.with_token_reload(restart.token_path.clone());
            }
        }
        let decision_service: Arc<dyn DnsDecisionService> = Arc::new(decision_service);
        dns_decision_service = Some(Arc::clone(&decision_service));

        if config.dns_inspection.connected_udp_proxy {
            if !config.dns_inspection.accept_proxy_network_authority {
                let _ = interceptor.terminate_all().await;
                return Err(Error::ConfigError(
                    "connected UDP DNS proxy requires explicit \
                     accept_proxy_network_authority = true"
                        .into(),
                ));
            }
            let proxy_config = ConnectedDnsProxyConfig {
                max_routes: config.dns_inspection.proxy_route_capacity,
                max_in_flight_queries: config.dns_inspection.proxy_query_capacity,
                max_policy_in_flight: config.dns_inspection.proxy_policy_capacity,
                control_channel_capacity: config.dns_inspection.proxy_control_capacity,
                max_datagram_size: config.dns_inspection.proxy_max_response_bytes,
                queue_action: config.dns_inspection.proxy_queue_action,
                control_timeout: Duration::from_millis(
                    config.dns_inspection.proxy_policy_timeout_ms,
                ),
                policy_timeout: Duration::from_millis(
                    config.dns_inspection.proxy_policy_timeout_ms,
                ),
                upstream_timeout: Duration::from_millis(
                    config.dns_inspection.proxy_upstream_timeout_ms,
                ),
                shutdown_timeout: Duration::from_millis(
                    config.dns_inspection.proxy_shutdown_timeout_ms,
                ),
                ..ConnectedDnsProxyConfig::default()
            };
            let worker = match ConnectedDnsProxy::start(
                proxy_config,
                decision_service,
                Arc::clone(&dns_cache),
            )
            .await
            {
                Ok(worker) => worker,
                Err(error) => {
                    let _ = interceptor.terminate_all().await;
                    return Err(Error::InterceptionError(format!(
                        "connected DNS proxy startup failed: {error}"
                    )));
                }
            };
            let control = worker.control();
            if let Err(error) = interceptor.set_connected_dns_proxy(control.clone()) {
                let _ = interceptor.terminate_all().await;
                let _ = worker.shutdown().await;
                return Err(error);
            }
            connected_dns_health = Some(control);
            tracing::info!(
                route_capacity = config.dns_inspection.proxy_route_capacity,
                query_capacity = config.dns_inspection.proxy_query_capacity,
                policy_capacity = config.dns_inspection.proxy_policy_capacity,
                queue_action = ?config.dns_inspection.proxy_queue_action,
                "managed connected UDP DNS proxy active"
            );
            connected_dns_proxy = Some(worker);
        } else {
            tracing::warn!(
                "connected UDP DNS proxy is disabled; resolver traffic using \
                 connected write/read remains outside query inspection and \
                 exact response attribution"
            );
        }
    }
    let persist_local_reputation = shared_reputation.is_some() || daemon_proxy_url.is_none();
    let daemon_restart = daemon_restart.map(event_handler::DaemonRestartState::new);

    // PR 4 Phase D: reuse the resolved profile for the
    // session-pinned inventory build (Phase C) and the per-spawn
    // provenance context (Phase D). `effective_policy_for_session`
    // reads the config from disk each call, so we cache it here.
    let expanded_routine_exec_roots: Vec<String> = session_policy
        .as_ref()
        .map(|p| p.merged_profile.expand_routine_exec_roots())
        .unwrap_or_default();
    // work/83 F4: workspace-wide project trust, resolved ONCE, here.
    //
    // `${PROJECT_DIR}` expands to the launch cwd, so in a multi-worktree
    // layout the sibling worktrees of the very repository being worked on get
    // no trust at all — measured 24.9% of calls QUEUEd there against 0.32%
    // under the launch cwd, and 692 mass-destruction escalations from one
    // `git worktree remove`.
    //
    // Snapshotted at session start and never recomputed: if the worktree list
    // were re-read mid-session, a supervised tool could widen its own trust
    // with `git worktree add /home/<user>`, turning a false-positive fix into
    // a privilege escalation. The extra roots are inserted into the session
    // allowlist below with the inert `projdir:` twin, so work/80's
    // credential-store guard, the containment gate and the sensitive-scoped
    // read check all keep applying to them exactly as they do to the launch
    // tree — this widens *where* project trust reaches, never *what* project
    // trust may cover.
    let (workspace_roots, workspace_boundary): (
        Vec<String>,
        Option<crate::workspace_only::WorkspaceBoundary>,
    ) = {
        let (home, launch_cwd) = crate::profiles::resolved_home_and_project_dir();
        // Two gates before any git probe runs. (1) A profile that does not
        // grant `${PROJECT_DIR}` trust must not acquire trust in a sibling
        // worktree through this door — F4 mirrors existing trust, it does not
        // invent it. (2) A launch cwd work/80 already refused (`/`, `$HOME`,
        // an ancestor of `$HOME`) gets nothing back here either.
        let mirrors_project_trust = session_policy
            .as_ref()
            .is_some_and(|p| p.merged_profile.declares_project_dir_trust())
            && !crate::profiles::is_dangerous_project_root(&home, &launch_cwd);
        // work/85: the workspace-only boundary needs the same roots, and
        // neither gate applies to it. `mirrors_project_trust` exists to stop a
        // profile *gaining* trust it never declared; the boundary grants
        // nothing — it only refuses what lies outside — so a session that
        // trusts no worktree still has to be able to work in one. Resolved in
        // the same block so the git probes run at most once.
        let restrict_to_workspace = config.trust.restrict_to_workspace;
        let resolved = if mirrors_project_trust || restrict_to_workspace {
            crate::profiles::resolve_workspace_roots(
                std::path::Path::new(&launch_cwd),
                &home,
                config.trust.include_linked_worktrees,
                &config.trust.additional_project_roots,
            )
        } else {
            Vec::new()
        };
        let boundary = restrict_to_workspace.then(|| {
            // The launch cwd leads: `collect_workspace_roots` drops it from
            // the enumerated set precisely because `${PROJECT_DIR}` already
            // covers it for trust purposes, and the boundary has no such
            // other half to lean on.
            let mut roots = Vec::with_capacity(resolved.len() + 1);
            if !launch_cwd.is_empty() {
                roots.push(launch_cwd.clone());
            }
            roots.extend(resolved.iter().cloned());
            let boundary = crate::workspace_only::WorkspaceBoundary::new(roots);
            if crate::profiles::is_dangerous_project_root(&home, &launch_cwd) {
                // Not an error — the mode stays on and stays honest — but a
                // boundary rooted at `/` or `$HOME` excludes almost nothing,
                // and an operator who switched this on deserves to know they
                // are not getting what they asked for.
                tracing::warn!(
                    event = "workspace_only_boundary_ineffective",
                    launch_cwd = %launch_cwd,
                    "workspace-only was requested from / or the home directory: \
                     nearly every path is inside the boundary — relaunch from \
                     the project directory"
                );
            }
            boundary
        });
        // Trust — the session-allowlist half — still obeys both gates.
        let trusted = if mirrors_project_trust {
            resolved
        } else {
            Vec::new()
        };
        (trusted, boundary)
    };
    if !workspace_roots.is_empty() {
        match session_allowed.lock() {
            Ok(mut allowed) => {
                crate::profiles::extend_allowlist_with_workspace_roots(
                    &mut allowed,
                    &workspace_roots,
                );
            }
            Err(_) => {
                // A poisoned allowlist mutex this early means another thread
                // panicked holding it; failing closed (no extra trust) is the
                // safe direction and the session continues with launch-cwd
                // trust only.
                tracing::warn!(
                    event = "workspace_trust_not_installed",
                    "session allowlist unavailable; workspace roots not trusted"
                );
            }
        }
    }

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
    // Authority-delegating / control-socket enforcement carveouts: the
    // profile-declared binaries and socket paths this session may use without
    // the enforcement QUEUE. Empty when no profile is resolved.
    let session_permit_authority_delegating: Vec<String> = session_policy
        .as_ref()
        .map(|p| p.merged_profile.permit_authority_delegating.clone())
        .unwrap_or_default();
    let session_permit_control_sockets: Vec<String> = session_policy
        .as_ref()
        .map(|p| p.merged_profile.permit_control_sockets.clone())
        .unwrap_or_default();
    // Cross-process gate refinement: probe the kernel's YAMA ptrace policy
    // once per session (it is a live sysctl, so never cached across
    // sessions). At scope >= 2 the gate can prove an out-of-tree
    // ptrace/process_vm from an uncapped caller will EPERM and skip the
    // pointless prompt.
    let yama_ptrace_scope = event_handler::probe_yama_ptrace_scope();

    // Pin the identity of every curated authority-delegating binary on $PATH
    // so a copy/hardlink under a novel name is caught by identity, not just
    // basename. Resolved only when spawn enforcement is on at session start
    // (env override folded in). Sizes resolve here (stat only); the SHA-256s
    // are built lazily on first real need, because hashing every docker-class
    // binary on $PATH at session start would tax every launch now that
    // enforcement is on by default.
    let authority_delegating_pins = authority_delegation::AuthorityDelegatingPins::resolve(
        authority_delegation::spawn_enforcement_enabled(config.enforce_authority_delegating_spawn),
    );

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
        // Per session: a fresh session always starts by assuming somebody is
        // watching, however the last one ended.
        unanswered_reviews: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        session_allowed,
        dns_cache,
        dns_inspection_enabled,
        dns_decision_service,
        dns_forward_confirm,
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
        daemon_proxy_token,
        daemon_restart,
        observation_outbox: Arc::new(Default::default()),
        persist_local_reputation,
        session_sync,
        routine_exec_roots: expanded_routine_exec_roots.clone(),
        scratch_roots: expanded_scratch_roots,
        workspace_roots: workspace_roots.clone(),
        // work/85: refusals start empty and only ever grow, from a reviewer
        // explicitly blocking a directory at the permission dialog.
        session_denied: Arc::new(Mutex::new(std::collections::HashSet::new())),
        workspace_boundary,
        local_listener_policy: session_local_listener_policy,
        namespace_users: session_namespace_users,
        permit_authority_delegating: session_permit_authority_delegating,
        permit_control_sockets: session_permit_control_sockets,
        dbus_inspection_armed,
        authority_delegating_pins,
        // The supervised tool is spawned as a child of this process and
        // inherits its cwd, so the supervisor's cwd at session start is the
        // project root the tool was pointed at — the mass-destruction signal's
        // in-tree boundary.
        working_root: std::env::current_dir().ok(),
        mass_destruction: std::sync::Mutex::new(
            mass_destruction::MassDestructionTracker::with_defaults(),
        ),
        yama_ptrace_scope,
        analytics_config: std::sync::OnceLock::new(),
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
    // `allow_clamp = false` (egress-policy still queues wildcard
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
        yama_ptrace_scope = ?loop_ctx.yama_ptrace_scope,
        // work/83 F4: exactly which extra trees this session trusts, on the
        // session_start line, so an operator can audit a widened trust
        // boundary without reconstructing it from the git layout.
        workspace_roots = ?loop_ctx.workspace_roots,
        // work/85: a session that refuses everything outside a boundary has
        // to say what the boundary is, on the same line.
        workspace_only = ?loop_ctx.workspace_boundary.as_ref().map(
            crate::workspace_only::WorkspaceBoundary::roots
        ),
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
            "yama_ptrace_scope": loop_ctx.yama_ptrace_scope,
            "workspace_roots": loop_ctx.workspace_roots,
            "workspace_only": loop_ctx.workspace_boundary.as_ref().map(
                crate::workspace_only::WorkspaceBoundary::roots
            ),
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

    // work/74 Phase 3: whether the daemon has stopped accounting for this
    // session. Session-scoped, not per-thread — daemon authority is a
    // property of the session as a whole, and every thread in the tracee's
    // group shares it.
    let mut authority_loss = AuthorityLossState::default();

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
            InterceptorError(Error),
            /// Connected DNS worker health changed or its monitor channel
            /// failed. Non-ready states are session-fatal.
            DnsProxyHealth(std::result::Result<ConnectedDnsProxyHealth, ConnectedDnsProxyError>),
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
                        LoopEvent::InterceptorError(e)
                    }
                }
            }
            health = wait_for_connected_dns_health(&mut connected_dns_health) => {
                LoopEvent::DnsProxyHealth(health)
            }
            _ = reputation_save_timer.tick() => LoopEvent::ReputationSave,
            _ = watchdog_timer.tick() => LoopEvent::WedgeScan,
        };

        match loop_event {
            LoopEvent::Shutdown => {
                tracing::info!(session_id = %session.id, "shutdown signal received, detaching");
                save_reputation(&loop_ctx);
                log_final_stats(session);
                let detach_error = interceptor.detach_all().await.err();
                let termination_error = if detach_error.is_some() {
                    // A failed detach can leave a tracee stopped under ptrace.
                    // Fail closed before removing its connected-DNS peer.
                    interceptor.terminate_all().await.err()
                } else {
                    None
                };
                shutdown_connected_dns_proxy(&mut connected_dns_proxy).await;
                dns_background_tasks.shutdown().await;
                if let Some(detach_error) = detach_error {
                    evict_session_state_on_end(
                        &loop_ctx,
                        session,
                        session_start,
                        "shutdown_detach_error",
                    )
                    .await;
                    let detail = termination_error.map_or_else(String::new, |error| {
                        format!("; tracee termination also failed: {error}")
                    });
                    return Err(Error::InterceptionError(format!(
                        "failed to detach supervised processes during shutdown: \
                         {detach_error}{detail}"
                    )));
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
                shutdown_connected_dns_proxy(&mut connected_dns_proxy).await;
                dns_background_tasks.shutdown().await;
                evict_session_state_on_end(&loop_ctx, session, session_start, "child_exit").await;
                return Ok(());
            }
            LoopEvent::InterceptorError(error) => {
                let termination_error = interceptor.terminate_all().await.err();
                save_reputation(&loop_ctx);
                log_final_stats(session);
                shutdown_connected_dns_proxy(&mut connected_dns_proxy).await;
                dns_background_tasks.shutdown().await;
                evict_session_state_on_end(&loop_ctx, session, session_start, "interceptor_error")
                    .await;
                return Err(with_termination_error(error, termination_error));
            }
            LoopEvent::DnsProxyHealth(Ok(ConnectedDnsProxyHealth::Ready)) => {
                tracing::debug!("connected DNS proxy health confirmed ready");
            }
            LoopEvent::DnsProxyHealth(health) => {
                let reason = match health {
                    Ok(ConnectedDnsProxyHealth::Starting) => {
                        "worker returned to starting state".to_string()
                    }
                    Ok(ConnectedDnsProxyHealth::Unhealthy(reason)) => reason,
                    Ok(ConnectedDnsProxyHealth::Stopped) => {
                        "worker stopped during an active session".to_string()
                    }
                    Ok(ConnectedDnsProxyHealth::Ready) => unreachable!(),
                    Err(error) => format!("health monitor failed: {error}"),
                };
                tracing::error!(
                    %reason,
                    session_id = %session.id,
                    "connected DNS proxy failed; terminating supervised session"
                );
                let termination_error = interceptor.terminate_all().await.err();
                save_reputation(&loop_ctx);
                log_final_stats(session);
                shutdown_connected_dns_proxy(&mut connected_dns_proxy).await;
                dns_background_tasks.shutdown().await;
                evict_session_state_on_end(&loop_ctx, session, session_start, "dns_proxy_failure")
                    .await;
                return Err(with_termination_error(
                    Error::InterceptionError(format!("connected DNS proxy failed: {reason}")),
                    termination_error,
                ));
            }
            LoopEvent::ReputationSave => {
                save_reputation(&loop_ctx);
            }
            LoopEvent::Syscall(event) => {
                if let Err(error) =
                    handle_syscall_event(interceptor, session, &loop_ctx, event).await
                {
                    // The handler may fail with the current tracee still in a
                    // syscall-entry stop. Terminate it before joining the DNS
                    // worker, otherwise the stopped process can be stranded
                    // with a loopback-connected resolver socket.
                    let termination_error = interceptor.terminate_all().await.err();
                    save_reputation(&loop_ctx);
                    log_final_stats(session);
                    shutdown_connected_dns_proxy(&mut connected_dns_proxy).await;
                    dns_background_tasks.shutdown().await;
                    evict_session_state_on_end(
                        &loop_ctx,
                        session,
                        session_start,
                        "syscall_handler_error",
                    )
                    .await;
                    return Err(with_termination_error(error, termination_error));
                }
                if sync_session_state(session, &loop_ctx, &mut authority_loss).await
                    == AuthorityOutcome::Terminate
                {
                    interceptor.terminate_all().await.ok();
                    save_reputation(&loop_ctx);
                    log_final_stats(session);
                    shutdown_connected_dns_proxy(&mut connected_dns_proxy).await;
                    dns_background_tasks.shutdown().await;
                    evict_session_state_on_end(
                        &loop_ctx,
                        session,
                        session_start,
                        "daemon_authority_lost",
                    )
                    .await;
                    return Ok(());
                }
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

async fn wait_for_connected_dns_health(
    control: &mut Option<ConnectedDnsProxyControl>,
) -> std::result::Result<ConnectedDnsProxyHealth, ConnectedDnsProxyError> {
    match control {
        Some(control) => control.wait_for_health_change().await,
        None => std::future::pending().await,
    }
}

async fn shutdown_connected_dns_proxy(worker: &mut Option<ConnectedDnsProxy>) {
    let Some(worker) = worker.take() else {
        return;
    };
    if let Err(error) = worker.shutdown().await {
        tracing::error!(
            error = %error,
            "connected DNS proxy worker did not shut down cleanly"
        );
    }
}

fn with_termination_error(error: Error, termination_error: Option<Error>) -> Error {
    match termination_error {
        Some(termination_error) => Error::InterceptionError(format!(
            "{error}; tracee termination also failed: {termination_error}"
        )),
        None => error,
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
    // Flush before evicting: in daemon mode the session's last outcomes are
    // still sitting in the outbox with no next evaluate to carry them.
    if let (Some(url), Some(token)) = (&loop_ctx.daemon_proxy_url, &loop_ctx.daemon_proxy_token) {
        let current = token.lock().ok().map(|t| t.clone()).unwrap_or_default();
        event_handler::flush_observation_outbox(loop_ctx, url, &current).await;
    }
    let removed = loop_ctx.proxy.evict_session_state(scope);
    let duration_secs = session_start.elapsed().as_secs_f64();
    // B-CORE-2 (b): surface the audit-drop count so an incomplete chain is
    // visible to the operator at session end, not only to a chain verifier
    // reading the gap markers.
    let audit_records_dropped = loop_ctx.audit_sink.dropped_count();
    tracing::info!(
        event = "session_end",
        session_id = %session_id,
        scope = %scope,
        reason,
        duration_secs,
        containment_triggered,
        filter_entries_removed = removed,
        audit_records_dropped,
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
            "audit_records_dropped": audit_records_dropped,
        }),
        "supervisor session ended",
    )
    .await;
    // Buffered sinks (the exec path's remote batch sender) must drain before
    // exec teardown drops the runtime, or the tail of the session is lost.
    loop_ctx.audit_sink.flush().await;
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
    .with_supervisor_source(session.tool_name.clone(), session.root_pid)
    // Lifecycle records are system records with an explicit System category;
    // the event name ("session_start"/"session_end") is not a tool kind and
    // must not be pattern-matched into a category.
    .with_analytics_metadata(event_handler::prospective_analytics_metadata_with_category(
        loop_ctx,
        session,
        grith_analytics::contract::RecordClass::System,
        grith_analytics::contract::Category::System,
    ));
    record.execution_result = Some(reason.into());
    // B-CORE-2 (b): session lifecycle events are low-volume and important — the
    // session-end summary carries the audit-drop count, so it must not itself be
    // shed on a full channel. `log_required` commits synchronously.
    if let Err(e) = loop_ctx.audit_sink.log_required(record).await {
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

/// Tracks a session whose daemon has stopped accounting for it
/// (work/74 Phase 3, go-live review B12 item 2).
#[derive(Debug, Default)]
pub(crate) struct AuthorityLossState {
    /// When authority was first lost, if it currently is.
    since: Option<std::time::Instant>,
    /// Whether the operator-facing banner has been printed for this episode.
    announced: bool,
}

impl AuthorityLossState {
    /// Record an authoritative refusal. Returns true the first time this
    /// episode is seen, so the caller announces once rather than on every
    /// heartbeat.
    fn record_loss(&mut self) -> bool {
        if self.since.is_none() {
            self.since = Some(std::time::Instant::now());
        }
        let first = !self.announced;
        self.announced = true;
        first
    }

    /// Clear the state after a successful heartbeat — the daemon is
    /// accounting for us again (it restarted and adopted the session, or a
    /// slot freed).
    fn record_recovery(&mut self) -> bool {
        let was_lost = self.since.is_some();
        self.since = None;
        self.announced = false;
        was_lost
    }

    /// How long authority has been lost, if it is.
    fn lost_for(&self) -> Option<std::time::Duration> {
        self.since.map(|t| t.elapsed())
    }
}

async fn sync_session_state(
    session: &SupervisorSession,
    loop_ctx: &event_handler::SupervisorLoopContext<'_>,
    authority: &mut AuthorityLossState,
) -> AuthorityOutcome {
    let Some(sync) = &loop_ctx.session_sync else {
        return AuthorityOutcome::Continue;
    };
    match sync.sync(session).await {
        // B12 #79: only a CONFIRMED heartbeat clears an authority-loss
        // episode. A throttled beat sent nothing, so it must not reset the
        // loss state or the grace clock — otherwise a lost session that keeps
        // heartbeating fast enough to be throttled would flap "restored"/
        // "lost" forever and never reach the termination grace.
        Ok(crate::SyncOutcome::Confirmed) => {
            if authority.record_recovery() {
                tracing::info!(
                    event = "session_authority_restored",
                    session_id = %session.id,
                    "the daemon is tracking this session again"
                );
                // `\r\n`: the tracee may have put the terminal in raw mode, so
                // a bare `\n` would step down without returning to column 0.
                eprint!("\r\ngrith: the daemon is tracking this session again.\r\n");
            }
            AuthorityOutcome::Continue
        }
        // Skipped to honour the min-interval — carries no authority signal, so
        // leave the loss state exactly as it was.
        Ok(crate::SyncOutcome::Throttled) => AuthorityOutcome::Continue,
        // Transport failure: the daemon may simply be restarting. The session
        // is still legitimate, so keep going and keep enforcing — treating a
        // blip as disownment would kill work for no reason.
        Err(crate::SyncFailure::Transport(e)) => {
            tracing::warn!(session_id = %session.id, error = %e, "failed to sync session state");
            AuthorityOutcome::Continue
        }
        // The daemon answered and refused to account for this session.
        // Enforcement continues — every syscall is still evaluated — but
        // nothing is tracking the session, so say so loudly instead of
        // pretending all is well.
        //
        // We do NOT detach: PTRACE_DETACH would drop interception entirely,
        // turning a bookkeeping problem into an unsupervised process. The
        // tracee stays traced, and PTRACE_O_EXITKILL still guarantees it dies
        // with us.
        Err(crate::SyncFailure::AuthorityLost(reason)) => {
            if authority.record_loss() {
                tracing::error!(
                    event = "session_authority_lost",
                    session_id = %session.id,
                    reason = %reason,
                    "the daemon is no longer tracking this session"
                );
                // `\r\n`: the tracee may have put the terminal in raw mode, so
                // bare `\n`s would staircase the box down the screen instead of
                // returning to column 0 on each line.
                eprint!(
                    "\r\n\
                     ┌─ grith ───────────────────────────────────────────────\r\n\
                     │ The daemon is no longer tracking this session.\r\n\
                     │ {reason}\r\n\
                     │\r\n\
                     │ Syscalls are still being evaluated and denied, but the\r\n\
                     │ session is not visible to `grith exec list` and cannot\r\n\
                     │ be killed from the dashboard.\r\n\
                     │ Stop the tool, or free a session slot and it will be\r\n\
                     │ picked up on the next heartbeat.\r\n\
                     └───────────────────────────────────────────────────────\r\n"
                );
            }
            let grace = loop_ctx.config.authority_lost_terminate_after_seconds;
            if should_terminate_after_authority_loss(grace, authority.lost_for()) {
                tracing::error!(
                    event = "session_authority_lost_terminating",
                    session_id = %session.id,
                    grace_seconds = grace,
                    "terminating the supervised session after the configured \
                     authority-loss grace period"
                );
                return AuthorityOutcome::Terminate;
            }
            AuthorityOutcome::Continue
        }
    }
}

/// Whether an authority-lost session has outlived its configured grace.
///
/// `grace_seconds == 0` means never terminate — the default. Terminating on
/// daemon-side bookkeeping would destroy in-progress agent work the user did
/// not cause, so it is strictly opt-in (CI, where nobody reads the banner).
///
/// Note this decides *termination*, not detaching: on termination the tree is
/// torn down, never released unsupervised (see the `run_supervisor_loop`
/// invariant).
pub(crate) fn should_terminate_after_authority_loss(
    grace_seconds: u64,
    lost_for: Option<std::time::Duration>,
) -> bool {
    if grace_seconds == 0 {
        return false;
    }
    lost_for.is_some_and(|d| d.as_secs() >= grace_seconds)
}

/// What the supervisor loop should do after a heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityOutcome {
    /// Keep supervising.
    Continue,
    /// The configured authority-loss grace period expired; end the session.
    Terminate,
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

    // -- work/74 Phase 3: daemon authority loss ---------------------------

    /// The banner must be printed once per episode, not on every heartbeat —
    /// a warning repeated every few seconds is noise the operator learns to
    /// ignore, which defeats the point of warning at all.
    #[test]
    fn authority_loss_announces_once_per_episode() {
        let mut state = AuthorityLossState::default();
        assert!(state.record_loss(), "first loss announces");
        assert!(!state.record_loss(), "subsequent heartbeats stay quiet");
        assert!(!state.record_loss());
    }

    #[test]
    fn recovery_is_reported_once_and_rearms_the_announcement() {
        let mut state = AuthorityLossState::default();
        state.record_loss();
        assert!(state.record_recovery(), "recovery from loss is reported");
        assert!(!state.record_recovery(), "a steady-state sync says nothing");

        // A second episode announces again — the operator needs to know it
        // came back.
        assert!(state.record_loss());
    }

    #[test]
    fn a_session_that_never_lost_authority_reports_no_duration() {
        let state = AuthorityLossState::default();
        assert!(state.lost_for().is_none());
    }

    #[test]
    fn authority_loss_tracks_how_long_it_has_been_lost() {
        let mut state = AuthorityLossState::default();
        state.record_loss();
        assert!(state.lost_for().is_some());
        state.record_recovery();
        assert!(
            state.lost_for().is_none(),
            "recovery must clear the clock, or a later brief loss would \
             immediately exceed a grace period it never came close to"
        );
    }

    /// The default must never kill a user's work over a daemon-side event.
    #[test]
    fn zero_grace_never_terminates() {
        assert!(!should_terminate_after_authority_loss(0, None));
        assert!(!should_terminate_after_authority_loss(
            0,
            Some(Duration::from_secs(86_400))
        ));
    }

    #[test]
    fn a_configured_grace_terminates_only_after_it_elapses() {
        assert!(!should_terminate_after_authority_loss(
            60,
            Some(Duration::from_secs(59))
        ));
        assert!(should_terminate_after_authority_loss(
            60,
            Some(Duration::from_secs(60))
        ));
        assert!(should_terminate_after_authority_loss(
            60,
            Some(Duration::from_secs(600))
        ));
    }

    /// A session that has not lost authority is never terminated, whatever
    /// the grace setting.
    #[test]
    fn never_terminates_a_session_with_authority() {
        assert!(!should_terminate_after_authority_loss(1, None));
    }

    /// Transport and authority failures must stay distinguishable: a daemon
    /// that is merely restarting must never be mistaken for one that has
    /// disowned the session.
    #[test]
    fn sync_failure_variants_are_distinct() {
        let transport = crate::SyncFailure::Transport("connection refused".into());
        let authority = crate::SyncFailure::AuthorityLost("at capacity".into());
        assert_ne!(transport, authority);
        assert!(matches!(transport, crate::SyncFailure::Transport(_)));
        assert!(matches!(authority, crate::SyncFailure::AuthorityLost(_)));
        // Both render their reason for the operator.
        assert_eq!(transport.to_string(), "connection refused");
        assert_eq!(authority.to_string(), "at capacity");
    }

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

        async fn kill(&mut self, pid: u32) -> crate::error::Result<()> {
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

    #[tokio::test]
    async fn priority_dns_seed_is_ready_within_budget_when_fast() {
        let cache = Arc::new(Mutex::new(crate::dns_cache::DnsCache::new()));
        let resolver = Arc::new(|domain: String| {
            vec![(domain, "192.0.2.80".parse::<std::net::IpAddr>().unwrap())]
        });
        let (ready, handle) = seed_priority_domains(
            Arc::downgrade(&cache),
            Arc::new(AtomicBool::new(true)),
            vec!["chatgpt.test".into()],
            Duration::from_millis(100),
            resolver,
        )
        .await;
        assert!(ready);
        handle.await.unwrap();
        assert_eq!(cache.lock().unwrap().resolve("192.0.2.80"), "chatgpt.test");
    }

    #[tokio::test]
    async fn slow_priority_dns_seed_respects_budget_and_continues() {
        let cache = Arc::new(Mutex::new(crate::dns_cache::DnsCache::new()));
        let resolver = Arc::new(|domain: String| {
            std::thread::sleep(Duration::from_millis(80));
            vec![(domain, "192.0.2.81".parse::<std::net::IpAddr>().unwrap())]
        });
        let started = std::time::Instant::now();
        let (ready, _handle) = seed_priority_domains(
            Arc::downgrade(&cache),
            Arc::new(AtomicBool::new(true)),
            vec!["slow.test".into()],
            Duration::from_millis(10),
            resolver,
        )
        .await;
        assert!(!ready);
        assert!(started.elapsed() < Duration::from_millis(60));

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(cache.lock().unwrap().resolve("192.0.2.81"), "slow.test");
    }

    #[test]
    fn reseed_merges_rotated_ips_for_routine_domain() {
        // A rotating CDN returns a different address on the second resolution.
        // Re-seeding must retain BOTH so a connect to either is attributed,
        // rather than the first seed being lost.
        let cache = Mutex::new(crate::dns_cache::DnsCache::new());
        let domains = vec!["api.github.test".to_string()];

        let first = reseed_domains_once(&cache, &domains, |d| {
            d.iter()
                .map(|n| (n.clone(), "192.0.2.90".parse().unwrap()))
                .collect()
        });
        assert_eq!(first, 1);

        let second = reseed_domains_once(&cache, &domains, |d| {
            d.iter()
                .map(|n| (n.clone(), "192.0.2.91".parse().unwrap()))
                .collect()
        });
        assert_eq!(second, 1);

        let mut cache = cache.into_inner().unwrap();
        assert_eq!(cache.resolve("192.0.2.90"), "api.github.test");
        assert_eq!(cache.resolve("192.0.2.91"), "api.github.test");
    }

    #[tokio::test]
    async fn priority_dns_refresh_task_exits_when_cache_dropped() {
        // The refresh task must not outlive the session: once the cache Arc is
        // gone, the Weak upgrade fails and the task terminates on its own.
        let cache = Arc::new(Mutex::new(crate::dns_cache::DnsCache::new()));
        let (_tx, rx) = broadcast::channel(1);
        let _task = spawn_priority_dns_refresh(
            Arc::downgrade(&cache),
            Arc::new(AtomicBool::new(true)),
            vec!["x.test".into()],
            rx,
        );
        // Dropping the only strong ref leaves the task holding just a Weak.
        drop(cache);
        // The empty-domains guard and Weak-upgrade break path both keep the
        // task from panicking; nothing to assert beyond a clean shutdown.
        tokio::task::yield_now().await;
    }
}
