// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Managed connected-UDP DNS inspection data plane.
//!
//! This module deliberately has no dependency on the ptrace event loop. A
//! session owns one [`ConnectedDnsProxy`], which runs on a dedicated OS thread
//! with its own multi-thread Tokio runtime. Each connected tracee socket gets a
//! distinct UDP route endpoint. Routes start pending and cannot evaluate,
//! forward, or populate the DNS cache until the exact client tuple is
//! registered.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::FutureExt;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tokio::task::JoinSet;

use crate::config::DnsProxyQueueAction;
use crate::dns_cache::DnsCache;
use crate::dns_proxy::{
    build_formerr_response, build_refused_response, build_servfail_response,
    parse_matching_response, parse_query, ParsedQuery,
};

const ROUTE_COMMAND_CAPACITY: usize = 4;
const CACHE_COMMIT_TIMEOUT: Duration = Duration::from_millis(100);
const CACHE_COMMIT_RETRY_DELAY: Duration = Duration::from_millis(1);

/// Stable identifier assigned to one proxy route.
///
/// The Linux socket tracker owns a separate route-ID newtype. `get()` provides
/// an explicit conversion boundary rather than coupling this transport module
/// to platform-specific tracker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectedDnsRouteId(pub(crate) u64);

impl ConnectedDnsRouteId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Provenance retained for every route and policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsRouteProvenance {
    pub tgid: u32,
    pub creator_tid: u32,
    pub socket_id: u64,
}

impl DnsRouteProvenance {
    pub const fn for_tgid(tgid: u32) -> Self {
        Self {
            tgid,
            creator_tid: tgid,
            socket_id: 0,
        }
    }
}

/// Policy input produced after strict DNS query parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDecisionRequest {
    pub route_id: ConnectedDnsRouteId,
    pub provenance: DnsRouteProvenance,
    pub original_resolver: SocketAddr,
    pub transaction_id: u16,
    pub domain: String,
    pub query_type: String,
    /// Enforcement selected for a policy `Queue` result. This travels with the
    /// decision request so the required audit record can persist the exact
    /// queue outcome before either transport permits an upstream send.
    pub queue_action: DnsProxyQueueAction,
}

/// Transport-neutral semantic result returned by [`DnsDecisionService`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsDecision {
    Allow,
    Deny { reason: String },
    Queue { reason: String },
    InfrastructureFailure { reason: String },
}

/// Thread-safe policy boundary used by both future ptrace and proxy adapters.
///
/// A production implementation is responsible for completing any required
/// audit or digest enqueue before returning `Allow`. The proxy treats timeout,
/// task loss, and `InfrastructureFailure` as fail-closed `SERVFAIL`.
#[async_trait]
pub trait DnsDecisionService: Send + Sync + 'static {
    async fn evaluate(&self, request: DnsDecisionRequest) -> DnsDecision;
}

/// Tunable internal bounds for one session proxy.
#[derive(Debug, Clone)]
pub struct ConnectedDnsProxyConfig {
    pub max_routes: usize,
    pub max_in_flight_queries: usize,
    pub max_policy_in_flight: usize,
    pub control_channel_capacity: usize,
    pub pending_datagrams_per_route: usize,
    pub max_datagram_size: usize,
    pub queue_action: DnsProxyQueueAction,
    pub worker_threads: usize,
    pub control_timeout: Duration,
    pub policy_timeout: Duration,
    pub upstream_timeout: Duration,
    pub shutdown_timeout: Duration,
}

impl Default for ConnectedDnsProxyConfig {
    fn default() -> Self {
        Self {
            max_routes: 256,
            max_in_flight_queries: 1_024,
            max_policy_in_flight: 128,
            control_channel_capacity: 256,
            pending_datagrams_per_route: 8,
            max_datagram_size: 4096,
            queue_action: DnsProxyQueueAction::Refuse,
            worker_threads: 2,
            control_timeout: Duration::from_secs(2),
            policy_timeout: Duration::from_secs(1),
            upstream_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(2),
        }
    }
}

impl ConnectedDnsProxyConfig {
    fn validate(&self) -> Result<(), ConnectedDnsProxyError> {
        if self.max_routes == 0
            || self.max_in_flight_queries == 0
            || self.max_policy_in_flight == 0
            || self.control_channel_capacity == 0
            || self.pending_datagrams_per_route == 0
            || self.max_datagram_size < 12
            || self.worker_threads == 0
        {
            return Err(ConnectedDnsProxyError::InvalidConfiguration(
                "all capacities/worker counts must be non-zero and max_datagram_size >= 12".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectedDnsProxyHealth {
    Starting,
    Ready,
    Unhealthy(String),
    Stopped,
}

#[derive(Debug, Error)]
pub enum ConnectedDnsProxyError {
    #[error("invalid connected DNS proxy configuration: {0}")]
    InvalidConfiguration(String),
    #[error("connected DNS proxy startup failed: {0}")]
    Startup(String),
    #[error("connected DNS proxy worker is unavailable: {0}")]
    WorkerUnavailable(String),
    #[error("connected DNS proxy control channel is at capacity")]
    ControlCapacity,
    #[error("connected DNS proxy route capacity ({0}) exhausted")]
    RouteCapacity(usize),
    #[error("connected DNS proxy route {0:?} was not found")]
    RouteNotFound(ConnectedDnsRouteId),
    #[error("invalid connected DNS proxy client tuple: {0}")]
    InvalidClient(String),
    #[error("connected DNS proxy control operation timed out")]
    ControlTimeout,
    #[error("connected DNS proxy route operation failed: {0}")]
    Route(String),
    #[error("connected DNS proxy worker thread panicked")]
    WorkerPanicked,
}

/// Endpoint allocated for a route which is still unable to forward traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingDnsRoute {
    pub route_id: ConnectedDnsRouteId,
    pub endpoint: SocketAddr,
}

enum WorkerCommand {
    CreateRoute {
        original_resolver: SocketAddr,
        provenance: DnsRouteProvenance,
        response: std_mpsc::Sender<Result<PendingDnsRoute, ConnectedDnsProxyError>>,
    },
    RegisterClient {
        route_id: ConnectedDnsRouteId,
        client: SocketAddr,
        response: std_mpsc::SyncSender<Result<(), ConnectedDnsProxyError>>,
    },
    ActivateRoute {
        route_id: ConnectedDnsRouteId,
        response: std_mpsc::SyncSender<Result<(), ConnectedDnsProxyError>>,
    },
    ReleaseRoute {
        route_id: ConnectedDnsRouteId,
        response: std_mpsc::Sender<Result<(), ConnectedDnsProxyError>>,
    },
}

enum RouteCommand {
    Register {
        client: SocketAddr,
        response: std_mpsc::SyncSender<Result<(), ConnectedDnsProxyError>>,
    },
    Activate {
        response: std_mpsc::SyncSender<Result<(), ConnectedDnsProxyError>>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
pub struct ConnectedDnsProxyControl {
    command_tx: mpsc::Sender<WorkerCommand>,
    health_rx: watch::Receiver<ConnectedDnsProxyHealth>,
    control_timeout: Duration,
}

impl ConnectedDnsProxyControl {
    pub fn health(&self) -> ConnectedDnsProxyHealth {
        self.health_rx.borrow().clone()
    }

    pub async fn wait_for_health_change(
        &mut self,
    ) -> Result<ConnectedDnsProxyHealth, ConnectedDnsProxyError> {
        self.health_rx.changed().await.map_err(|_| {
            ConnectedDnsProxyError::WorkerUnavailable("health channel closed".into())
        })?;
        let health = self.health_rx.borrow().clone();
        Ok(health)
    }

    pub fn create_route(
        &self,
        original_resolver: SocketAddr,
        provenance: DnsRouteProvenance,
    ) -> Result<PendingDnsRoute, ConnectedDnsProxyError> {
        self.require_ready()?;
        let (response, receiver) = std_mpsc::channel();
        self.try_send(WorkerCommand::CreateRoute {
            original_resolver,
            provenance,
            response,
        })?;
        self.receive(receiver)?
    }

    /// Prepare a client tuple without allowing the route to process packets.
    ///
    /// Callers must install their authoritative socket-owner state and then
    /// call [`Self::activate_route`] before resuming the tracee.
    pub fn register_client(
        &self,
        route_id: ConnectedDnsRouteId,
        client: SocketAddr,
    ) -> Result<(), ConnectedDnsProxyError> {
        self.require_ready()?;
        // A zero-capacity rendezvous makes receipt by this exact caller the
        // route task's commit boundary. If this wait times out, the receiver is
        // dropped and the route task rolls back before it can poll traffic.
        let (response, receiver) = std_mpsc::sync_channel(0);
        self.try_send(WorkerCommand::RegisterClient {
            route_id,
            client,
            response,
        })?;
        self.receive(receiver)?
    }

    pub fn activate_route(
        &self,
        route_id: ConnectedDnsRouteId,
    ) -> Result<(), ConnectedDnsProxyError> {
        self.require_ready()?;
        let (response, receiver) = std_mpsc::sync_channel(0);
        self.try_send(WorkerCommand::ActivateRoute { route_id, response })?;
        self.receive(receiver)?
    }

    /// Release is idempotent so alias-close and session cleanup can safely
    /// converge on the same route.
    pub fn release_route(
        &self,
        route_id: ConnectedDnsRouteId,
    ) -> Result<(), ConnectedDnsProxyError> {
        if matches!(self.health(), ConnectedDnsProxyHealth::Stopped) {
            return Ok(());
        }
        let (response, receiver) = std_mpsc::channel();
        self.try_send(WorkerCommand::ReleaseRoute { route_id, response })?;
        self.receive(receiver)?
    }

    fn require_ready(&self) -> Result<(), ConnectedDnsProxyError> {
        match self.health() {
            ConnectedDnsProxyHealth::Ready => Ok(()),
            other => Err(ConnectedDnsProxyError::WorkerUnavailable(format!(
                "health is {other:?}"
            ))),
        }
    }

    fn try_send(&self, command: WorkerCommand) -> Result<(), ConnectedDnsProxyError> {
        self.command_tx
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ConnectedDnsProxyError::ControlCapacity,
                mpsc::error::TrySendError::Closed(_) => {
                    ConnectedDnsProxyError::WorkerUnavailable("control channel closed".into())
                }
            })
    }

    fn receive<T>(&self, receiver: std_mpsc::Receiver<T>) -> Result<T, ConnectedDnsProxyError> {
        receiver
            .recv_timeout(self.control_timeout)
            .map_err(|error| match error {
                std_mpsc::RecvTimeoutError::Timeout => ConnectedDnsProxyError::ControlTimeout,
                std_mpsc::RecvTimeoutError::Disconnected => {
                    ConnectedDnsProxyError::WorkerUnavailable(
                        "worker dropped a control response".into(),
                    )
                }
            })
    }
}

/// Session-owned proxy worker and joined lifecycle handle.
pub struct ConnectedDnsProxy {
    control: ConnectedDnsProxyControl,
    shutdown_tx: watch::Sender<bool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl ConnectedDnsProxy {
    pub async fn start(
        config: ConnectedDnsProxyConfig,
        decision_service: Arc<dyn DnsDecisionService>,
        dns_cache: Arc<Mutex<DnsCache>>,
    ) -> Result<Self, ConnectedDnsProxyError> {
        config.validate()?;

        let (command_tx, command_rx) = mpsc::channel(config.control_channel_capacity);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (health_tx, health_rx) = watch::channel(ConnectedDnsProxyHealth::Starting);
        let (ready_tx, ready_rx) = oneshot::channel();
        let thread_config = config.clone();
        let thread_health = health_tx.clone();

        let join = std::thread::Builder::new()
            .name("grith-connected-dns".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(thread_config.worker_threads)
                    .thread_name("grith-dns-worker")
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let message = error.to_string();
                        let _ =
                            thread_health.send(ConnectedDnsProxyHealth::Unhealthy(message.clone()));
                        let _ = ready_tx.send(Err(message));
                        return;
                    }
                };

                let _ = thread_health.send(ConnectedDnsProxyHealth::Ready);
                let _ = ready_tx.send(Ok(()));
                let result = runtime.block_on(
                    AssertUnwindSafe(run_worker(
                        thread_config,
                        command_rx,
                        shutdown_rx,
                        decision_service,
                        dns_cache,
                    ))
                    .catch_unwind(),
                );
                match result {
                    Ok(Ok(())) => {
                        let _ = thread_health.send(ConnectedDnsProxyHealth::Stopped);
                    }
                    Ok(Err(reason)) => {
                        let _ = thread_health.send(ConnectedDnsProxyHealth::Unhealthy(reason));
                    }
                    Err(_) => {
                        let _ = thread_health.send(ConnectedDnsProxyHealth::Unhealthy(
                            "connected DNS proxy worker panicked".into(),
                        ));
                    }
                }
            })
            .map_err(|error| ConnectedDnsProxyError::Startup(error.to_string()))?;

        let readiness = tokio::time::timeout(config.control_timeout, ready_rx).await;
        match readiness {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(reason))) => {
                let _ = shutdown_tx.send(true);
                let _ = tokio::task::spawn_blocking(move || join.join()).await;
                return Err(ConnectedDnsProxyError::Startup(reason));
            }
            Ok(Err(_)) => {
                let _ = shutdown_tx.send(true);
                let _ = tokio::task::spawn_blocking(move || join.join()).await;
                return Err(ConnectedDnsProxyError::Startup(
                    "worker exited before readiness".into(),
                ));
            }
            Err(_) => {
                let _ = shutdown_tx.send(true);
                let _ = tokio::task::spawn_blocking(move || join.join()).await;
                return Err(ConnectedDnsProxyError::Startup(
                    "worker readiness timed out".into(),
                ));
            }
        }

        Ok(Self {
            control: ConnectedDnsProxyControl {
                command_tx,
                health_rx,
                control_timeout: config.control_timeout,
            },
            shutdown_tx,
            join: Some(join),
        })
    }

    pub fn control(&self) -> ConnectedDnsProxyControl {
        self.control.clone()
    }

    pub async fn shutdown(mut self) -> Result<(), ConnectedDnsProxyError> {
        let _ = self.shutdown_tx.send(true);
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || join.join())
            .await
            .map_err(|_| ConnectedDnsProxyError::WorkerPanicked)?
            .map_err(|_| ConnectedDnsProxyError::WorkerPanicked)
    }
}

impl Drop for ConnectedDnsProxy {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(join) = self.join.take() {
            // Dropping the session worker is uncommon (normal callers use
            // `shutdown`). Joining here preserves the no-detached-worker
            // invariant even on early-return/error paths.
            let _ = join.join();
        }
    }
}

struct RouteControl {
    command_tx: mpsc::Sender<RouteCommand>,
}

async fn run_worker(
    config: ConnectedDnsProxyConfig,
    mut command_rx: mpsc::Receiver<WorkerCommand>,
    mut shutdown_rx: watch::Receiver<bool>,
    decision_service: Arc<dyn DnsDecisionService>,
    dns_cache: Arc<Mutex<DnsCache>>,
) -> Result<(), String> {
    let in_flight_queries = Arc::new(Semaphore::new(config.max_in_flight_queries));
    let in_flight_policy = Arc::new(Semaphore::new(config.max_policy_in_flight));
    let mut routes: HashMap<ConnectedDnsRouteId, RouteControl> = HashMap::new();
    let mut route_tasks: JoinSet<(ConnectedDnsRouteId, Result<(), String>)> = JoinSet::new();
    let mut next_route_id = 1u64;

    let result = loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break Ok(());
                }
            }
            command = command_rx.recv() => {
                let Some(command) = command else {
                    break Err("control channel closed without shutdown".into());
                };
                match command {
                    WorkerCommand::CreateRoute {
                        original_resolver,
                        provenance,
                        response,
                    } => {
                        let result = create_route(
                            &config,
                            &mut routes,
                            &mut route_tasks,
                            &mut next_route_id,
                            original_resolver,
                            provenance,
                            Arc::clone(&decision_service),
                            Arc::clone(&dns_cache),
                            Arc::clone(&in_flight_queries),
                            Arc::clone(&in_flight_policy),
                            shutdown_rx.clone(),
                        ).await;
                        match result {
                            Ok(route) => {
                                if response.send(Ok(route)).is_err() {
                                    let _ = release_route(
                                        &config,
                                        &mut routes,
                                        route.route_id,
                                    ).await;
                                }
                            }
                            Err(error) => {
                                let _ = response.send(Err(error));
                            }
                        }
                    }
                    WorkerCommand::RegisterClient { route_id, client, response } => {
                        register_route_client(&routes, route_id, client, response);
                    }
                    WorkerCommand::ActivateRoute { route_id, response } => {
                        activate_route(&routes, route_id, response);
                    }
                    WorkerCommand::ReleaseRoute { route_id, response } => {
                        let result = release_route(&config, &mut routes, route_id).await;
                        let _ = response.send(result);
                    }
                }
            }
            completed = route_tasks.join_next(), if !route_tasks.is_empty() => {
                match completed {
                    Some(Ok((route_id, Ok(())))) => {
                        if routes.remove(&route_id).is_some() {
                            break Err(format!("route {route_id:?} stopped unexpectedly"));
                        }
                    }
                    Some(Ok((route_id, Err(reason)))) => {
                        routes.remove(&route_id);
                        break Err(format!("route {route_id:?} failed: {reason}"));
                    }
                    Some(Err(error)) => {
                        break Err(format!("route task panicked or was cancelled: {error}"));
                    }
                    None => {}
                }
            }
        }
    };

    routes.clear();
    let drain = async { while route_tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(config.shutdown_timeout, drain)
        .await
        .is_err()
    {
        route_tasks.abort_all();
        while route_tasks.join_next().await.is_some() {}
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn create_route(
    config: &ConnectedDnsProxyConfig,
    routes: &mut HashMap<ConnectedDnsRouteId, RouteControl>,
    route_tasks: &mut JoinSet<(ConnectedDnsRouteId, Result<(), String>)>,
    next_route_id: &mut u64,
    original_resolver: SocketAddr,
    provenance: DnsRouteProvenance,
    decision_service: Arc<dyn DnsDecisionService>,
    dns_cache: Arc<Mutex<DnsCache>>,
    in_flight_queries: Arc<Semaphore>,
    in_flight_policy: Arc<Semaphore>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<PendingDnsRoute, ConnectedDnsProxyError> {
    if routes.len() >= config.max_routes {
        return Err(ConnectedDnsProxyError::RouteCapacity(config.max_routes));
    }

    let bind_address = proxy_bind_address(original_resolver);
    let socket = UdpSocket::bind(bind_address)
        .await
        .map_err(|error| ConnectedDnsProxyError::Route(error.to_string()))?;
    let endpoint = socket
        .local_addr()
        .map_err(|error| ConnectedDnsProxyError::Route(error.to_string()))?;
    let route_id = ConnectedDnsRouteId(*next_route_id);
    *next_route_id = next_route_id
        .checked_add(1)
        .ok_or_else(|| ConnectedDnsProxyError::Route("route ID space exhausted".into()))?;

    let (command_tx, command_rx) = mpsc::channel(ROUTE_COMMAND_CAPACITY);
    let route_config = config.clone();
    route_tasks.spawn(async move {
        let result = route_loop(
            route_config,
            route_id,
            original_resolver,
            provenance,
            socket,
            command_rx,
            shutdown_rx,
            decision_service,
            dns_cache,
            in_flight_queries,
            in_flight_policy,
        )
        .await;
        (route_id, result)
    });
    routes.insert(route_id, RouteControl { command_tx });

    tracing::debug!(
        route_id = route_id.get(),
        %endpoint,
        %original_resolver,
        tgid = provenance.tgid,
        "connected DNS proxy route created pending"
    );
    Ok(PendingDnsRoute { route_id, endpoint })
}

fn proxy_bind_address(original_resolver: SocketAddr) -> SocketAddr {
    match original_resolver {
        SocketAddr::V4(address) if address.ip().is_loopback() => {
            SocketAddr::new(IpAddr::V4(*address.ip()), 0)
        }
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        SocketAddr::V6(address) if address.ip().is_loopback() => {
            SocketAddr::new(IpAddr::V6(*address.ip()), 0)
        }
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    }
}

fn register_route_client(
    routes: &HashMap<ConnectedDnsRouteId, RouteControl>,
    route_id: ConnectedDnsRouteId,
    client: SocketAddr,
    response: std_mpsc::SyncSender<Result<(), ConnectedDnsProxyError>>,
) {
    if client.port() == 0 || !client.ip().is_loopback() {
        let _ = response.send(Err(ConnectedDnsProxyError::InvalidClient(format!(
            "client must be a bound loopback tuple, got {client}"
        ))));
        return;
    }
    let Some(route) = routes.get(&route_id) else {
        let _ = response.send(Err(ConnectedDnsProxyError::RouteNotFound(route_id)));
        return;
    };
    match route
        .command_tx
        .try_send(RouteCommand::Register { client, response })
    {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(RouteCommand::Register { response, .. })) => {
            let _ = response.send(Err(ConnectedDnsProxyError::ControlCapacity));
        }
        Err(mpsc::error::TrySendError::Closed(RouteCommand::Register { response, .. })) => {
            let _ = response.send(Err(ConnectedDnsProxyError::WorkerUnavailable(
                "route task closed".into(),
            )));
        }
        Err(_) => unreachable!("register delivery returned a different route command"),
    }
}

fn activate_route(
    routes: &HashMap<ConnectedDnsRouteId, RouteControl>,
    route_id: ConnectedDnsRouteId,
    response: std_mpsc::SyncSender<Result<(), ConnectedDnsProxyError>>,
) {
    let Some(route) = routes.get(&route_id) else {
        let _ = response.send(Err(ConnectedDnsProxyError::RouteNotFound(route_id)));
        return;
    };
    match route
        .command_tx
        .try_send(RouteCommand::Activate { response })
    {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(RouteCommand::Activate { response })) => {
            let _ = response.send(Err(ConnectedDnsProxyError::ControlCapacity));
        }
        Err(mpsc::error::TrySendError::Closed(RouteCommand::Activate { response })) => {
            let _ = response.send(Err(ConnectedDnsProxyError::WorkerUnavailable(
                "route task closed".into(),
            )));
        }
        Err(_) => unreachable!("activation delivery returned a different route command"),
    }
}

async fn release_route(
    config: &ConnectedDnsProxyConfig,
    routes: &mut HashMap<ConnectedDnsRouteId, RouteControl>,
    route_id: ConnectedDnsRouteId,
) -> Result<(), ConnectedDnsProxyError> {
    let Some(route) = routes.remove(&route_id) else {
        return Ok(());
    };
    let (response, receiver) = oneshot::channel();
    if tokio::time::timeout(
        config.control_timeout,
        route.command_tx.send(RouteCommand::Shutdown { response }),
    )
    .await
    .map_err(|_| ConnectedDnsProxyError::ControlTimeout)?
    .is_err()
    {
        return Ok(());
    }
    tokio::time::timeout(config.control_timeout, receiver)
        .await
        .map_err(|_| ConnectedDnsProxyError::ControlTimeout)?
        .map_err(|_| ConnectedDnsProxyError::WorkerUnavailable("route task exited".into()))
}

struct PendingDatagram {
    source: SocketAddr,
    bytes: Vec<u8>,
    oversized: bool,
}

#[allow(clippy::too_many_arguments)]
async fn route_loop(
    config: ConnectedDnsProxyConfig,
    route_id: ConnectedDnsRouteId,
    original_resolver: SocketAddr,
    provenance: DnsRouteProvenance,
    socket: UdpSocket,
    mut command_rx: mpsc::Receiver<RouteCommand>,
    mut shutdown_rx: watch::Receiver<bool>,
    decision_service: Arc<dyn DnsDecisionService>,
    dns_cache: Arc<Mutex<DnsCache>>,
    in_flight_queries: Arc<Semaphore>,
    in_flight_policy: Arc<Semaphore>,
) -> Result<(), String> {
    let socket = Arc::new(socket);
    let mut registered_client = None;
    let mut authorized_client = None;
    let mut pending: VecDeque<PendingDatagram> =
        VecDeque::with_capacity(config.pending_datagrams_per_route);
    let mut query_tasks = JoinSet::new();
    let mut receive_buffer = vec![0u8; config.max_datagram_size + 1];

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            command = command_rx.recv() => {
                match command {
                    Some(RouteCommand::Register { client, response }) => {
                        let existing = authorized_client.or(registered_client);
                        match existing {
                            Some(existing) if existing == client => {
                                let _ = response.send(Ok(()));
                            }
                            Some(existing) => {
                                let _ = response.send(Err(ConnectedDnsProxyError::Route(
                                    format!(
                                        "route already registered to {existing}, refusing {client}"
                                    ),
                                )));
                            }
                            None if client.is_ipv4()
                                != socket.local_addr().map_err(|e| e.to_string())?.is_ipv4() =>
                            {
                                let _ = response.send(Err(ConnectedDnsProxyError::Route(
                                    format!(
                                        "client family differs from route endpoint: {client}"
                                    ),
                                )));
                            }
                            None => {
                                // Stage the state before the rendezvous so a
                                // received acknowledgement means the route is
                                // already committed. The route task cannot
                                // process UDP while blocked in `send`; if the
                                // caller timed out, rollback before polling it.
                                registered_client = Some(client);
                                if response.send(Ok(())).is_err() {
                                    registered_client = None;
                                }
                            }
                        }
                    }
                    Some(RouteCommand::Activate { response }) => {
                        if authorized_client.is_some() {
                            let _ = response.send(Ok(()));
                        } else if let Some(client) = registered_client {
                            // As with registration, stage Ready before the
                            // rendezvous and rollback on caller cancellation.
                            // No datagram can be processed while this route
                            // task is blocked delivering the acknowledgement.
                            authorized_client = Some(client);
                            if response.send(Ok(())).is_err() {
                                authorized_client = None;
                                continue;
                            }
                            let queued: Vec<_> = pending.drain(..)
                                .filter(|datagram| datagram.source == client)
                                .collect();
                            for datagram in queued {
                                dispatch_datagram(
                                    &config,
                                    route_id,
                                    original_resolver,
                                    provenance,
                                    Arc::clone(&socket),
                                    client,
                                    datagram,
                                    Arc::clone(&decision_service),
                                    Arc::clone(&dns_cache),
                                    Arc::clone(&in_flight_queries),
                                    Arc::clone(&in_flight_policy),
                                    &mut query_tasks,
                                ).await;
                            }
                            tracing::debug!(
                                route_id = route_id.get(),
                                %client,
                                "connected DNS proxy route registered ready"
                            );
                        } else {
                            let _ = response.send(Err(ConnectedDnsProxyError::Route(
                                "route cannot activate before client registration".into(),
                            )));
                        }
                    }
                    Some(RouteCommand::Shutdown { response }) => {
                        query_tasks.abort_all();
                        while query_tasks.join_next().await.is_some() {}
                        let _ = response.send(());
                        return Ok(());
                    }
                    None => break,
                }
            }
            received = socket.recv_from(&mut receive_buffer) => {
                let (length, source) = received.map_err(|error| error.to_string())?;
                let oversized = length > config.max_datagram_size;
                let datagram = PendingDatagram {
                    source,
                    bytes: receive_buffer[..length].to_vec(),
                    oversized,
                };
                if let Some(client) = authorized_client {
                    if source == client {
                        dispatch_datagram(
                            &config,
                            route_id,
                            original_resolver,
                            provenance,
                            Arc::clone(&socket),
                            client,
                            datagram,
                            Arc::clone(&decision_service),
                            Arc::clone(&dns_cache),
                            Arc::clone(&in_flight_queries),
                            Arc::clone(&in_flight_policy),
                            &mut query_tasks,
                        ).await;
                    } else {
                        tracing::warn!(
                            route_id = route_id.get(),
                            %source,
                            "connected DNS proxy discarded packet from unauthorized source"
                        );
                    }
                } else if pending.len() < config.pending_datagrams_per_route {
                    pending.push_back(datagram);
                } else {
                    tracing::warn!(
                        route_id = route_id.get(),
                        "connected DNS proxy pending route queue full; packet discarded"
                    );
                }
            }
            completed = query_tasks.join_next(), if !query_tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    return Err(format!("query task panicked or was cancelled: {error}"));
                }
            }
        }
    }

    query_tasks.abort_all();
    while query_tasks.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_datagram(
    config: &ConnectedDnsProxyConfig,
    route_id: ConnectedDnsRouteId,
    original_resolver: SocketAddr,
    provenance: DnsRouteProvenance,
    route_socket: Arc<UdpSocket>,
    client: SocketAddr,
    datagram: PendingDatagram,
    decision_service: Arc<dyn DnsDecisionService>,
    dns_cache: Arc<Mutex<DnsCache>>,
    in_flight_queries: Arc<Semaphore>,
    in_flight_policy: Arc<Semaphore>,
    query_tasks: &mut JoinSet<()>,
) {
    if datagram.oversized {
        send_error(
            &route_socket,
            &datagram.bytes,
            client,
            build_formerr_response,
        )
        .await;
        return;
    }

    let Some(parsed_query) = parse_query(&datagram.bytes) else {
        send_error(
            &route_socket,
            &datagram.bytes,
            client,
            build_formerr_response,
        )
        .await;
        return;
    };

    let Ok(permit) = Arc::clone(&in_flight_queries).try_acquire_owned() else {
        send_error(
            &route_socket,
            &datagram.bytes,
            client,
            build_servfail_response,
        )
        .await;
        return;
    };

    let config = config.clone();
    query_tasks.spawn(async move {
        let _permit = permit;
        process_query(
            &config,
            route_id,
            original_resolver,
            provenance,
            route_socket,
            client,
            datagram.bytes,
            parsed_query,
            decision_service,
            dns_cache,
            in_flight_policy,
        )
        .await;
    });
}

#[allow(clippy::too_many_arguments)]
async fn process_query(
    config: &ConnectedDnsProxyConfig,
    route_id: ConnectedDnsRouteId,
    original_resolver: SocketAddr,
    provenance: DnsRouteProvenance,
    route_socket: Arc<UdpSocket>,
    client: SocketAddr,
    raw_query: Vec<u8>,
    parsed_query: ParsedQuery,
    decision_service: Arc<dyn DnsDecisionService>,
    dns_cache: Arc<Mutex<DnsCache>>,
    in_flight_policy: Arc<Semaphore>,
) {
    let request = DnsDecisionRequest {
        route_id,
        provenance,
        original_resolver,
        transaction_id: parsed_query.id,
        domain: parsed_query.domain.clone(),
        query_type: parsed_query.query_type.clone(),
        queue_action: config.queue_action,
    };
    let decision = match Arc::clone(&in_flight_policy).try_acquire_owned() {
        Ok(policy_permit) => {
            let evaluation = AssertUnwindSafe(decision_service.evaluate(request)).catch_unwind();
            let result = tokio::time::timeout(config.policy_timeout, evaluation).await;
            drop(policy_permit);
            match result {
                Ok(Ok(decision)) => decision,
                Ok(Err(_)) => DnsDecision::InfrastructureFailure {
                    reason: "DNS policy evaluation panicked".into(),
                },
                Err(_) => DnsDecision::InfrastructureFailure {
                    reason: "DNS policy evaluation timed out".into(),
                },
            }
        }
        Err(_) => DnsDecision::InfrastructureFailure {
            reason: "DNS policy capacity exhausted".into(),
        },
    };

    match decision {
        DnsDecision::Deny { reason } => {
            tracing::debug!(
                route_id = route_id.get(),
                %reason,
                "connected DNS proxy refused query"
            );
            send_error(&route_socket, &raw_query, client, build_refused_response).await;
            return;
        }
        DnsDecision::Queue { reason } => match config.queue_action {
            DnsProxyQueueAction::Refuse => {
                tracing::debug!(
                    route_id = route_id.get(),
                    %reason,
                    "connected DNS proxy refused queued query"
                );
                send_error(&route_socket, &raw_query, client, build_refused_response).await;
                return;
            }
            DnsProxyQueueAction::Forward => {
                tracing::warn!(
                    route_id = route_id.get(),
                    %reason,
                    "connected DNS proxy forwarding queued query in compatibility mode"
                );
            }
        },
        DnsDecision::InfrastructureFailure { reason } => {
            tracing::warn!(
                route_id = route_id.get(),
                %reason,
                "connected DNS proxy policy infrastructure failure"
            );
            send_error(&route_socket, &raw_query, client, build_servfail_response).await;
            return;
        }
        DnsDecision::Allow => {}
    }

    let response =
        match forward_exact_query(config, original_resolver, &raw_query, &parsed_query).await {
            Ok(response) => response,
            Err(reason) => {
                tracing::warn!(
                    route_id = route_id.get(),
                    %reason,
                    "connected DNS proxy upstream response rejected"
                );
                send_error(&route_socket, &raw_query, client, build_servfail_response).await;
                return;
            }
        };

    // The lock, validation and complete batch mutation finish before the
    // successful upstream response can become readable by the tracee.
    let committed = commit_cache_batch(
        &dns_cache,
        &parsed_query.domain,
        &response.parsed.answers,
        provenance.tgid,
    )
    .await;
    if let Err(error) = committed {
        tracing::warn!(
            route_id = route_id.get(),
            error = %error,
            "connected DNS proxy cache batch commit failed"
        );
        send_error(&route_socket, &raw_query, client, build_servfail_response).await;
        return;
    }

    if let Err(error) = route_socket.send_to(&response.bytes, client).await {
        tracing::debug!(
            route_id = route_id.get(),
            %client,
            error = %error,
            "connected DNS proxy response relay failed"
        );
    }
}

async fn commit_cache_batch(
    dns_cache: &Arc<Mutex<DnsCache>>,
    domain: &str,
    answers: &[crate::dns_proxy::DnsAnswer],
    tgid: u32,
) -> Result<usize, String> {
    let deadline = tokio::time::Instant::now() + CACHE_COMMIT_TIMEOUT;
    loop {
        match dns_cache.try_lock() {
            Ok(mut cache) => {
                return cache
                    .commit_observed_batch(
                        domain,
                        answers.iter().map(|answer| (answer.ip, answer.ttl)),
                        tgid,
                    )
                    .map_err(|error| error.to_string());
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err("DNS cache mutex poisoned".into());
            }
            Err(std::sync::TryLockError::WouldBlock) => {}
        }

        if tokio::time::Instant::now() >= deadline {
            return Err("DNS cache mutex remained unavailable".into());
        }
        tokio::time::sleep(CACHE_COMMIT_RETRY_DELAY).await;
    }
}

struct ValidatedResponse {
    bytes: Vec<u8>,
    parsed: crate::dns_proxy::ParsedResponse,
}

async fn forward_exact_query(
    config: &ConnectedDnsProxyConfig,
    original_resolver: SocketAddr,
    raw_query: &[u8],
    parsed_query: &ParsedQuery,
) -> Result<ValidatedResponse, String> {
    let bind_address = match original_resolver {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let upstream = UdpSocket::bind(bind_address)
        .await
        .map_err(|error| error.to_string())?;
    upstream
        .connect(original_resolver)
        .await
        .map_err(|error| error.to_string())?;
    let sent = upstream
        .send(raw_query)
        .await
        .map_err(|error| error.to_string())?;
    if sent != raw_query.len() {
        return Err(format!(
            "short upstream datagram send: {sent}/{}",
            raw_query.len()
        ));
    }

    let mut buffer = vec![0u8; config.max_datagram_size + 1];
    let length = tokio::time::timeout(config.upstream_timeout, upstream.recv(&mut buffer))
        .await
        .map_err(|_| "upstream DNS response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    if length > config.max_datagram_size {
        return Err(format!(
            "upstream DNS response exceeds {} bytes",
            config.max_datagram_size
        ));
    }
    buffer.truncate(length);
    let parsed = parse_matching_response(&buffer, parsed_query)
        .ok_or_else(|| "upstream response did not match transaction/question".to_string())?;
    Ok(ValidatedResponse {
        bytes: buffer,
        parsed,
    })
}

async fn send_error(
    socket: &UdpSocket,
    query: &[u8],
    client: SocketAddr,
    builder: fn(&[u8]) -> Vec<u8>,
) {
    let response = builder(query);
    if response.is_empty() {
        return;
    }
    if let Err(error) = socket.send_to(&response, client).await {
        tracing::debug!(
            %client,
            error = %error,
            "connected DNS proxy error response relay failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_cache::Resolution;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type ResponseFuture = Pin<Box<dyn Future<Output = Vec<u8>> + Send>>;
    type ResponseHandler = Arc<dyn Fn(Vec<u8>) -> ResponseFuture + Send + Sync>;

    struct TestResolver {
        address: SocketAddr,
        query_count: Arc<AtomicUsize>,
        shutdown_tx: watch::Sender<bool>,
        task: tokio::task::JoinHandle<()>,
    }

    impl TestResolver {
        async fn start(handler: ResponseHandler) -> Self {
            Self::try_start(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), handler)
                .await
                .unwrap()
        }

        async fn try_start(
            bind_address: SocketAddr,
            handler: ResponseHandler,
        ) -> std::io::Result<Self> {
            let socket = UdpSocket::bind(bind_address).await?;
            let address = socket.local_addr()?;
            let query_count = Arc::new(AtomicUsize::new(0));
            let task_count = Arc::clone(&query_count);
            let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
            let socket = Arc::new(socket);
            let task = tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                let mut responses = JoinSet::new();
                loop {
                    tokio::select! {
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                responses.abort_all();
                                while responses.join_next().await.is_some() {}
                                break;
                            }
                        }
                        received = socket.recv_from(&mut buffer) => {
                            let Ok((length, source)) = received else {
                                break;
                            };
                            task_count.fetch_add(1, Ordering::SeqCst);
                            let packet = buffer[..length].to_vec();
                            let handler = Arc::clone(&handler);
                            let socket = Arc::clone(&socket);
                            responses.spawn(async move {
                                let response = handler(packet).await;
                                if !response.is_empty() {
                                    let _ = socket.send_to(&response, source).await;
                                }
                            });
                        }
                        _ = responses.join_next(), if !responses.is_empty() => {
                        }
                    }
                }
            });
            Ok(Self {
                address,
                query_count,
                shutdown_tx,
                task,
            })
        }

        fn count(&self) -> usize {
            self.query_count.load(Ordering::SeqCst)
        }

        async fn shutdown(self) {
            let _ = self.shutdown_tx.send(true);
            let _ = self.task.await;
        }
    }

    struct StaticDecisionService {
        decision: DnsDecision,
        calls: AtomicUsize,
        requests: Mutex<Vec<DnsDecisionRequest>>,
    }

    impl StaticDecisionService {
        fn new(decision: DnsDecision) -> Self {
            Self {
                decision,
                calls: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    struct BlockingDecisionService {
        calls: AtomicUsize,
        release: Semaphore,
    }

    impl BlockingDecisionService {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                release: Semaphore::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn release_one(&self) {
            self.release.add_permits(1);
        }
    }

    #[async_trait]
    impl DnsDecisionService for BlockingDecisionService {
        async fn evaluate(&self, _request: DnsDecisionRequest) -> DnsDecision {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.release.acquire().await.unwrap().forget();
            DnsDecision::Allow
        }
    }

    struct PanickingDecisionService;

    #[async_trait]
    impl DnsDecisionService for PanickingDecisionService {
        async fn evaluate(&self, _request: DnsDecisionRequest) -> DnsDecision {
            panic!("injected policy panic");
        }
    }

    #[async_trait]
    impl DnsDecisionService for StaticDecisionService {
        async fn evaluate(&self, request: DnsDecisionRequest) -> DnsDecision {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.requests.lock().unwrap().push(request);
            self.decision.clone()
        }
    }

    fn query(domain: &str, id: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0; 6]);
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    fn answer(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response[8..12].fill(0);
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&ip.octets());
        response
    }

    fn answer_handler(ip: Ipv4Addr) -> ResponseHandler {
        Arc::new(move |packet| {
            let response = answer(&packet, ip);
            Box::pin(async move { response })
        })
    }

    fn test_config() -> ConnectedDnsProxyConfig {
        ConnectedDnsProxyConfig {
            worker_threads: 1,
            control_timeout: Duration::from_secs(3),
            policy_timeout: Duration::from_millis(500),
            upstream_timeout: Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(3),
            ..ConnectedDnsProxyConfig::default()
        }
    }

    async fn ready_client(
        control: &ConnectedDnsProxyControl,
        resolver: SocketAddr,
        tgid: u32,
    ) -> (UdpSocket, PendingDnsRoute) {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let route = control
            .create_route(resolver, DnsRouteProvenance::for_tgid(tgid))
            .unwrap();
        control
            .register_client(route.route_id, client.local_addr().unwrap())
            .unwrap();
        control.activate_route(route.route_id).unwrap();
        client.connect(route.endpoint).await.unwrap();
        (client, route)
    }

    async fn exchange(client: &UdpSocket, query: &[u8]) -> Vec<u8> {
        client.send(query).await.unwrap();
        let mut buffer = vec![0u8; 8192];
        let length = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buffer))
            .await
            .expect("proxy response timed out")
            .unwrap();
        buffer.truncate(length);
        buffer
    }

    fn rcode(response: &[u8]) -> u8 {
        response[3] & 0x0f
    }

    async fn wait_for_calls(policy: &BlockingDecisionService, count: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while policy.calls() < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("policy evaluation did not start");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn allowed_query_uses_exact_resolver_and_commits_cache_before_reply() {
        let answer_ip = Ipv4Addr::new(192, 0, 2, 41);
        let resolver = TestResolver::start(answer_handler(answer_ip)).await;
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let proxy = ConnectedDnsProxy::start(test_config(), policy.clone(), Arc::clone(&cache))
            .await
            .unwrap();
        let control = proxy.control();
        let (client, route) = ready_client(&control, resolver.address, 4100).await;

        let raw_query = query("cache-before-reply.test", 0x1001);
        let response = exchange(&client, &raw_query).await;
        let parsed_query = parse_query(&raw_query).unwrap();
        let parsed = parse_matching_response(&response, &parsed_query).unwrap();
        assert_eq!(parsed.answers[0].ip, IpAddr::V4(answer_ip));

        // If relay happened before commit, this assertion can race. The proxy
        // guarantees the commit completed before `recv` above became ready.
        assert_eq!(
            cache
                .lock()
                .unwrap()
                .resolve_attribution(&answer_ip.to_string()),
            Resolution::Exact("cache-before-reply.test".into())
        );
        assert_eq!(resolver.count(), 1);
        assert_eq!(policy.calls(), 1);
        {
            let requests = policy.requests.lock().unwrap();
            assert_eq!(requests[0].original_resolver, resolver.address);
        }

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn denied_and_queued_queries_are_refused_without_upstream_packet() {
        for decision in [
            DnsDecision::Deny {
                reason: "blocked".into(),
            },
            DnsDecision::Queue {
                reason: "review".into(),
            },
        ] {
            let resolver = TestResolver::start(answer_handler(Ipv4Addr::new(192, 0, 2, 42))).await;
            let policy = Arc::new(StaticDecisionService::new(decision));
            let cache = Arc::new(Mutex::new(DnsCache::new()));
            let proxy = ConnectedDnsProxy::start(test_config(), policy.clone(), Arc::clone(&cache))
                .await
                .unwrap();
            let control = proxy.control();
            let (client, route) = ready_client(&control, resolver.address, 4200).await;

            let response = exchange(&client, &query("denied.test", 0x1002)).await;
            assert_eq!(rcode(&response), 5);
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(resolver.count(), 0);
            assert_eq!(policy.calls(), 1);

            control.release_route(route.route_id).unwrap();
            proxy.shutdown().await.unwrap();
            resolver.shutdown().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_query_forwards_only_in_explicit_compatibility_mode() {
        let answer_ip = Ipv4Addr::new(192, 0, 2, 45);
        let resolver = TestResolver::start(answer_handler(answer_ip)).await;
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Queue {
            reason: "review enqueued".into(),
        }));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let config = ConnectedDnsProxyConfig {
            queue_action: DnsProxyQueueAction::Forward,
            ..test_config()
        };
        let proxy = ConnectedDnsProxy::start(config, policy.clone(), cache)
            .await
            .unwrap();
        let control = proxy.control();
        let (client, route) = ready_client(&control, resolver.address, 4250).await;

        let raw_query = query("queued-forward.test", 0x1005);
        let response = exchange(&client, &raw_query).await;
        assert_eq!(rcode(&response), 0);
        assert_eq!(
            parse_matching_response(&response, &parse_query(&raw_query).unwrap())
                .unwrap()
                .answers[0]
                .ip,
            IpAddr::V4(answer_ip)
        );
        assert_eq!(policy.calls(), 1);
        assert_eq!(resolver.count(), 1);

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_query_gets_formerr_without_policy_or_upstream() {
        let resolver = TestResolver::start(answer_handler(Ipv4Addr::new(192, 0, 2, 43))).await;
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let proxy = ConnectedDnsProxy::start(test_config(), policy.clone(), Arc::clone(&cache))
            .await
            .unwrap();
        let control = proxy.control();
        let (client, route) = ready_client(&control, resolver.address, 4300).await;

        let mut malformed = vec![0u8; 12];
        malformed[..2].copy_from_slice(&0x1003u16.to_be_bytes());
        let response = exchange(&client, &malformed).await;
        assert_eq!(&response[..2], &malformed[..2]);
        assert_eq!(rcode(&response), 1);
        assert_eq!(policy.calls(), 0);
        assert_eq!(resolver.count(), 0);

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn separate_routes_preserve_split_dns_resolvers() {
        let first_ip = Ipv4Addr::new(192, 0, 2, 51);
        let second_ip = Ipv4Addr::new(192, 0, 2, 52);
        let first = TestResolver::start(answer_handler(first_ip)).await;
        let second = TestResolver::start(answer_handler(second_ip)).await;
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let proxy = ConnectedDnsProxy::start(test_config(), policy.clone(), Arc::clone(&cache))
            .await
            .unwrap();
        let control = proxy.control();
        let (first_client, first_route) = ready_client(&control, first.address, 4401).await;
        let (second_client, second_route) = ready_client(&control, second.address, 4402).await;

        let first_query = query("first.split.test", 0x1101);
        let second_query = query("second.split.test", 0x1102);
        let first_response = exchange(&first_client, &first_query).await;
        let second_response = exchange(&second_client, &second_query).await;
        assert_eq!(
            parse_matching_response(&first_response, &parse_query(&first_query).unwrap())
                .unwrap()
                .answers[0]
                .ip,
            IpAddr::V4(first_ip)
        );
        assert_eq!(
            parse_matching_response(&second_response, &parse_query(&second_query).unwrap())
                .unwrap()
                .answers[0]
                .ip,
            IpAddr::V4(second_ip)
        );
        assert_eq!(first.count(), 1);
        assert_eq!(second.count(), 1);

        control.release_route(first_route.route_id).unwrap();
        control.release_route(second_route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        first.shutdown().await;
        second.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_queries_use_independent_upstreams_and_may_complete_out_of_order() {
        let first_ip = Ipv4Addr::new(192, 0, 2, 54);
        let second_ip = Ipv4Addr::new(192, 0, 2, 55);
        let second_seen = Arc::new(Semaphore::new(0));
        let handler: ResponseHandler = Arc::new(move |packet| {
            let id = u16::from_be_bytes(packet[..2].try_into().unwrap());
            let second_seen = Arc::clone(&second_seen);
            Box::pin(async move {
                if id == 0x1160 {
                    second_seen.acquire().await.unwrap().forget();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    answer(&packet, first_ip)
                } else {
                    second_seen.add_permits(1);
                    answer(&packet, second_ip)
                }
            })
        });
        let resolver = TestResolver::start(handler).await;
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let proxy = ConnectedDnsProxy::start(test_config(), policy.clone(), Arc::clone(&cache))
            .await
            .unwrap();
        let control = proxy.control();
        let (client, route) = ready_client(&control, resolver.address, 4460).await;

        let first = query("first-concurrent.test", 0x1160);
        let second = query("second-concurrent.test", 0x1161);
        client.send(&first).await.unwrap();
        client.send(&second).await.unwrap();

        let mut buffer = vec![0u8; 4096];
        let first_length = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..2], &second[..2]);
        assert_eq!(rcode(&buffer[..first_length]), 0);
        let second_length = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..2], &first[..2]);
        assert_eq!(rcode(&buffer[..second_length]), 0);
        assert_eq!(policy.calls(), 2);
        assert_eq!(resolver.count(), 2);
        assert_eq!(
            cache
                .lock()
                .unwrap()
                .resolve_attribution(&first_ip.to_string()),
            Resolution::Exact("first-concurrent.test".into())
        );
        assert_eq!(
            cache
                .lock()
                .unwrap()
                .resolve_attribution(&second_ip.to_string()),
            Resolution::Exact("second-concurrent.test".into())
        );

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ipv6_route_uses_same_family_endpoint_and_exact_resolver() {
        let answer_ip = Ipv4Addr::new(192, 0, 2, 53);
        let Ok(resolver) = TestResolver::try_start(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            answer_handler(answer_ip),
        )
        .await
        else {
            // Some minimal CI kernels disable IPv6 entirely.
            return;
        };
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let proxy = ConnectedDnsProxy::start(test_config(), policy, cache)
            .await
            .unwrap();
        let control = proxy.control();
        let client = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let route = control
            .create_route(resolver.address, DnsRouteProvenance::for_tgid(4450))
            .unwrap();
        assert!(route.endpoint.is_ipv6());
        control
            .register_client(route.route_id, client.local_addr().unwrap())
            .unwrap();
        control.activate_route(route.route_id).unwrap();
        client.connect(route.endpoint).await.unwrap();

        let raw_query = query("ipv6-route.test", 0x1150);
        let response = exchange(&client, &raw_query).await;
        assert_eq!(
            parse_matching_response(&response, &parse_query(&raw_query).unwrap())
                .unwrap()
                .answers[0]
                .ip,
            IpAddr::V4(answer_ip)
        );
        assert_eq!(resolver.count(), 1);

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_route_filters_queued_and_ready_packets_by_exact_source() {
        let resolver = TestResolver::start(answer_handler(Ipv4Addr::new(192, 0, 2, 61))).await;
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let proxy = ConnectedDnsProxy::start(test_config(), policy.clone(), Arc::clone(&cache))
            .await
            .unwrap();
        let control = proxy.control();
        let route = control
            .create_route(resolver.address, DnsRouteProvenance::for_tgid(4500))
            .unwrap();
        let authorized = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let unauthorized = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        authorized.connect(route.endpoint).await.unwrap();
        unauthorized.connect(route.endpoint).await.unwrap();

        // Both packets arrive while Pending. Registration must select only the
        // exact authorized tuple; the other source must never reach policy,
        // upstream, or the cache.
        unauthorized
            .send(&query("unauthorized.test", 0x1201))
            .await
            .unwrap();
        authorized
            .send(&query("authorized.test", 0x1202))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        control
            .register_client(route.route_id, authorized.local_addr().unwrap())
            .unwrap();
        control.activate_route(route.route_id).unwrap();

        let mut buffer = vec![0u8; 4096];
        let length = tokio::time::timeout(Duration::from_secs(1), authorized.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rcode(&buffer[..length]), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), unauthorized.recv(&mut buffer))
                .await
                .is_err()
        );
        assert_eq!(policy.calls(), 1);
        assert_eq!(resolver.count(), 1);

        // An unauthorized packet after Ready is filtered by the same tuple.
        unauthorized
            .send(&query("still-unauthorized.test", 0x1203))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(policy.calls(), 1);
        assert_eq!(resolver.count(), 1);

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_control_callers_cannot_register_or_activate_a_route() {
        let resolver = TestResolver::start(answer_handler(Ipv4Addr::new(192, 0, 2, 62))).await;
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let config = ConnectedDnsProxyConfig {
            control_timeout: Duration::from_millis(100),
            ..test_config()
        };
        let proxy = ConnectedDnsProxy::start(config, policy.clone(), cache)
            .await
            .unwrap();
        let control = proxy.control();
        let route = control
            .create_route(resolver.address, DnsRouteProvenance::for_tgid(4510))
            .unwrap();
        let abandoned = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client_address = client.local_addr().unwrap();

        // Hold the route task in a response rendezvous so the next public
        // registration times out after its command has entered both queues.
        let (block_response, block_receiver) = std_mpsc::sync_channel(0);
        control
            .try_send(WorkerCommand::RegisterClient {
                route_id: route.route_id,
                client: abandoned.local_addr().unwrap(),
                response: block_response,
            })
            .unwrap();
        assert!(matches!(
            control.register_client(route.route_id, client_address),
            Err(ConnectedDnsProxyError::ControlTimeout)
        ));
        drop(block_receiver);

        // This successful call is also an ordering barrier: both abandoned
        // registrations have been rolled back before it is acknowledged.
        control
            .register_client(route.route_id, client_address)
            .unwrap();

        // Repeat the same timeout at the activation boundary while retaining
        // the valid registration above.
        let (block_response, block_receiver) = std_mpsc::sync_channel(0);
        control
            .try_send(WorkerCommand::RegisterClient {
                route_id: route.route_id,
                client: client_address,
                response: block_response,
            })
            .unwrap();
        assert!(matches!(
            control.activate_route(route.route_id),
            Err(ConnectedDnsProxyError::ControlTimeout)
        ));
        drop(block_receiver);
        control
            .register_client(route.route_id, client_address)
            .unwrap();

        client.connect(route.endpoint).await.unwrap();
        let raw_query = query("still-pending-after-timeout.test", 0x1204);
        client.send(&raw_query).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(policy.calls(), 0);
        assert_eq!(resolver.count(), 0);

        // An acknowledgement delivered to the live caller commits activation
        // and releases the datagram buffered while the route was pending.
        control.activate_route(route.route_id).unwrap();
        let mut buffer = vec![0u8; 4096];
        let length = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rcode(&buffer[..length]), 0);
        assert_eq!(policy.calls(), 1);
        assert_eq!(resolver.count(), 1);

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mismatched_upstream_response_becomes_servfail_and_is_not_relayed() {
        let handler: ResponseHandler = Arc::new(|packet| {
            let mut response = answer(&packet, Ipv4Addr::new(192, 0, 2, 71));
            response[1] ^= 1;
            Box::pin(async move { response })
        });
        let resolver = TestResolver::start(handler).await;
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let proxy = ConnectedDnsProxy::start(test_config(), policy.clone(), Arc::clone(&cache))
            .await
            .unwrap();
        let control = proxy.control();
        let (client, route) = ready_client(&control, resolver.address, 4600).await;

        let raw_query = query("mismatch.test", 0x1301);
        let response = exchange(&client, &raw_query).await;
        assert_eq!(&response[..2], &raw_query[..2]);
        assert_eq!(rcode(&response), 2);
        assert_eq!(resolver.count(), 1);
        assert_eq!(policy.calls(), 1);

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn route_capacity_fails_closed_and_release_is_idempotent() {
        let resolver = TestResolver::start(answer_handler(Ipv4Addr::new(192, 0, 2, 81))).await;
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let config = ConnectedDnsProxyConfig {
            max_routes: 1,
            ..test_config()
        };
        let proxy = ConnectedDnsProxy::start(config, policy, cache)
            .await
            .unwrap();
        let control = proxy.control();
        let route = control
            .create_route(resolver.address, DnsRouteProvenance::for_tgid(4700))
            .unwrap();
        assert!(matches!(
            control.create_route(resolver.address, DnsRouteProvenance::for_tgid(4701)),
            Err(ConnectedDnsProxyError::RouteCapacity(1))
        ));
        control.release_route(route.route_id).unwrap();
        control.release_route(route.route_id).unwrap();

        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn policy_capacity_exhaustion_servfails_without_upstream_packet() {
        let resolver = TestResolver::start(answer_handler(Ipv4Addr::new(192, 0, 2, 91))).await;
        let policy = Arc::new(BlockingDecisionService::new());
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let config = ConnectedDnsProxyConfig {
            max_in_flight_queries: 2,
            max_policy_in_flight: 1,
            ..test_config()
        };
        let proxy = ConnectedDnsProxy::start(config, policy.clone(), cache)
            .await
            .unwrap();
        let control = proxy.control();
        let (client, route) = ready_client(&control, resolver.address, 4900).await;

        let first = query("first-policy-slot.test", 0x1401);
        client.send(&first).await.unwrap();
        wait_for_calls(&policy, 1).await;

        let second = query("no-policy-slot.test", 0x1402);
        let second_response = exchange(&client, &second).await;
        assert_eq!(&second_response[..2], &second[..2]);
        assert_eq!(rcode(&second_response), 2);
        assert_eq!(policy.calls(), 1);
        assert_eq!(resolver.count(), 0);

        policy.release_one();
        let mut buffer = vec![0u8; 4096];
        let length = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..2], &first[..2]);
        assert_eq!(rcode(&buffer[..length]), 0);
        assert_eq!(resolver.count(), 1);

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn policy_timeout_servfails_without_upstream_packet() {
        let resolver = TestResolver::start(answer_handler(Ipv4Addr::new(192, 0, 2, 92))).await;
        let policy = Arc::new(BlockingDecisionService::new());
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let config = ConnectedDnsProxyConfig {
            policy_timeout: Duration::from_millis(20),
            ..test_config()
        };
        let proxy = ConnectedDnsProxy::start(config, policy.clone(), cache)
            .await
            .unwrap();
        let control = proxy.control();
        let (client, route) = ready_client(&control, resolver.address, 4901).await;

        let raw_query = query("policy-timeout.test", 0x1403);
        let response = exchange(&client, &raw_query).await;
        assert_eq!(&response[..2], &raw_query[..2]);
        assert_eq!(rcode(&response), 2);
        assert_eq!(policy.calls(), 1);
        assert_eq!(resolver.count(), 0);

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn policy_panic_is_caught_and_servfails_without_stopping_worker() {
        let resolver = TestResolver::start(answer_handler(Ipv4Addr::new(192, 0, 2, 93))).await;
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let proxy =
            ConnectedDnsProxy::start(test_config(), Arc::new(PanickingDecisionService), cache)
                .await
                .unwrap();
        let control = proxy.control();
        let (client, route) = ready_client(&control, resolver.address, 4902).await;

        let raw_query = query("policy-panic.test", 0x1404);
        let response = exchange(&client, &raw_query).await;
        assert_eq!(&response[..2], &raw_query[..2]);
        assert_eq!(rcode(&response), 2);
        assert_eq!(resolver.count(), 0);
        assert_eq!(control.health(), ConnectedDnsProxyHealth::Ready);

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn contended_cache_fails_closed_without_blocking_relay_or_shutdown() {
        let resolver = TestResolver::start(answer_handler(Ipv4Addr::new(192, 0, 2, 94))).await;
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let proxy = ConnectedDnsProxy::start(test_config(), policy, Arc::clone(&cache))
            .await
            .unwrap();
        let control = proxy.control();
        let (client, route) = ready_client(&control, resolver.address, 4903).await;

        let holder_cache = Arc::clone(&cache);
        let (locked_tx, locked_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let holder = std::thread::spawn(move || {
            let _guard = holder_cache.lock().unwrap();
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        locked_rx.recv().unwrap();

        let raw_query = query("cache-contention.test", 0x1405);
        let response = exchange(&client, &raw_query).await;
        assert_eq!(&response[..2], &raw_query[..2]);
        assert_eq!(rcode(&response), 2);
        assert_eq!(resolver.count(), 1);

        release_tx.send(()).unwrap();
        holder.join().unwrap();
        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_upstream_datagram_is_rejected_with_servfail() {
        let handler: ResponseHandler = Arc::new(|packet| {
            let mut response = answer(&packet, Ipv4Addr::new(192, 0, 2, 95));
            response.resize(513, 0);
            Box::pin(async move { response })
        });
        let resolver = TestResolver::start(handler).await;
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let cache = Arc::new(Mutex::new(DnsCache::new()));
        let config = ConnectedDnsProxyConfig {
            max_datagram_size: 512,
            ..test_config()
        };
        let proxy = ConnectedDnsProxy::start(config, policy, cache)
            .await
            .unwrap();
        let control = proxy.control();
        let (client, route) = ready_client(&control, resolver.address, 4904).await;

        let raw_query = query("oversized-response.test", 0x1406);
        let response = exchange(&client, &raw_query).await;
        assert_eq!(&response[..2], &raw_query[..2]);
        assert_eq!(rcode(&response), 2);
        assert_eq!(resolver.count(), 1);

        control.release_route(route.route_id).unwrap();
        proxy.shutdown().await.unwrap();
        resolver.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_joins_worker_and_closes_control_plane() {
        let policy = Arc::new(StaticDecisionService::new(DnsDecision::Allow));
        let proxy =
            ConnectedDnsProxy::start(test_config(), policy, Arc::new(Mutex::new(DnsCache::new())))
                .await
                .unwrap();
        let control = proxy.control();
        assert_eq!(control.health(), ConnectedDnsProxyHealth::Ready);
        proxy.shutdown().await.unwrap();
        assert_eq!(control.health(), ConnectedDnsProxyHealth::Stopped);
        assert!(matches!(
            control.create_route(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
                DnsRouteProvenance::for_tgid(4800)
            ),
            Err(ConnectedDnsProxyError::WorkerUnavailable(_))
        ));
    }
}
