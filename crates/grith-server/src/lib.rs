// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! HTTP and WebSocket server for the grith dashboard and API.
//!
//! Serves the embedded React dashboard and provides REST endpoints
//! for audit, digest, proxy, supervisor, and notification management.

pub mod auth;
pub mod error;
pub mod ipc_auth;
pub mod rate_limit;
pub mod routes;
pub mod static_files;
pub mod supervisor;
pub mod websocket;

pub use error::Error;

use crate::error::Result;
use axum::http::{header, HeaderValue, Method};
use axum::Router;
use grith_audit::AuditStorage;
use grith_audit::CorrelationTracker;
use grith_digest::DigestQueue;
use grith_notify::NotificationDispatcher;
use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::canary::CanaryRegistry;
use grith_proxy::filters::session_containment::ContainmentTracker;
use grith_supervisor::supervisor::SupervisorRegistry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

/// Per-bucket API rate limiting configuration (mirrored from grith-core).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub general_rps: u32,
    pub write_rps: u32,
    pub proxy_test_rps: u32,
    pub ipc_rps: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            general_rps: 100,
            write_rps: 10,
            proxy_test_rps: 20,
            ipc_rps: 10_000,
        }
    }
}

/// TLS configuration for native HTTPS support (mirrored from grith-core).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// Configuration for the HTTP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub enabled: bool,
    #[serde(default)]
    pub dashboard_dir: Option<String>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 3141,
            enabled: false,
            dashboard_dir: None,
            tls: None,
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// Shared application state passed to all route handlers.
///
/// # Lock poisoning strategy
///
/// All `std::sync::Mutex` and `RwLock` fields below use the **graceful error**
/// pattern in production code: every `.lock()` / `.read()` / `.write()` call
/// uses `match` or `.map_err()` to convert a poisoned-lock error into an
/// HTTP 500 response (in route handlers) or a logged error (in background
/// tasks). This avoids panicking the server when a thread panics while
/// holding a lock. Test code may use `.lock().unwrap()` since panics are
/// acceptable in tests.
#[derive(Clone)]
pub struct AppState {
    pub audit_storage: Arc<Mutex<AuditStorage>>,
    pub digest_queue: Arc<DigestQueue>,
    pub proxy: Arc<SecurityProxy>,
    pub supervisor_registry: Arc<Mutex<SupervisorRegistry>>,
    pub supervisor_tasks: Arc<tokio::sync::Mutex<HashMap<Uuid, broadcast::Sender<()>>>>,
    pub containment_tracker: Arc<ContainmentTracker>,
    pub correlation_tracker: Arc<CorrelationTracker>,
    pub canary_registry: Arc<CanaryRegistry>,
    pub notification_dispatcher: Arc<NotificationDispatcher>,
    pub start_time: std::time::Instant,
    pub version: String,
    pub ws_tx: broadcast::Sender<String>,
    /// Optional shutdown sender — when present, allows API-driven shutdown.
    pub shutdown_tx: Option<broadcast::Sender<()>>,
    /// Plan tier: "community", "pro", or "enterprise".
    pub plan_tier: String,
    /// Directory containing local grith config files.
    pub config_dir: PathBuf,
    /// Path to the audit database file for persistent supervisor audit logging.
    pub audit_db_path: PathBuf,
    /// Current signed-in account identifier used for per-account config scoping.
    pub account_id: String,
    /// Authentication configuration.
    pub auth_config: auth::AuthConfig,
    /// Feature gate for tier-based feature access.
    pub feature_gate: Arc<RwLock<grith_digest::notification::FeatureGate>>,
    /// License renewal date (YYYY-MM-DD) when a Pro/Enterprise license is active.
    pub license_valid_until: Option<String>,
    /// Billing portal URL from license metadata, if provided.
    pub billing_portal_url: Option<String>,
    /// Live licence-refresh state shared with the daemon background task.
    pub refresh_state: Arc<RwLock<grith_digest::notification::RefreshState>>,
    /// Trusted domains for DNS cache seeding in supervisor sessions.
    pub dns_seed_domains: Vec<String>,
    /// Shared reputation table for learned trust (daemon-owned).
    pub reputation_table: Arc<std::sync::Mutex<grith_proxy::reputation::ReputationTable>>,
    /// Shared reputation configuration for daemon-owned BRS evaluation and observations.
    pub reputation_config: grith_proxy::reputation::ReputationConfig,
    /// Optional API key used to refresh team learned-rules cache at session start.
    pub sync_api_key: Option<String>,
    /// Base URL for sync endpoints when `sync_api_key` is present.
    pub sync_api_base_url: Option<String>,
    /// Bearer token for IPC endpoint authentication (empty = no auth).
    pub ipc_token: String,
}

/// Dependencies required to construct `AppState` for the server.
///
/// Grouped to keep `GrithServer::new` simple and avoid high-arity constructors.
#[derive(Clone)]
pub struct ServerDeps {
    pub audit_storage: Arc<Mutex<AuditStorage>>,
    pub digest_queue: Arc<DigestQueue>,
    pub proxy: Arc<SecurityProxy>,
    pub supervisor_registry: Arc<Mutex<SupervisorRegistry>>,
    pub containment_tracker: Arc<ContainmentTracker>,
    pub correlation_tracker: Arc<CorrelationTracker>,
    pub canary_registry: Arc<CanaryRegistry>,
    pub notification_dispatcher: Arc<NotificationDispatcher>,
    /// Path to the audit database file. Supervisor sessions use this to create
    /// file-backed audit loggers so records persist beyond session lifetime.
    pub audit_db_path: PathBuf,
    /// Trusted domains for DNS cache seeding in supervisor sessions.
    pub dns_seed_domains: Vec<String>,
    /// Shared reputation table for learned trust (daemon-owned).
    pub reputation_table: Arc<std::sync::Mutex<grith_proxy::reputation::ReputationTable>>,
    /// Shared reputation configuration for daemon-owned BRS evaluation and observations.
    pub reputation_config: grith_proxy::reputation::ReputationConfig,
    /// Optional API key used to refresh team learned-rules cache at session start.
    pub sync_api_key: Option<String>,
    /// Base URL for sync endpoints when `sync_api_key` is present.
    pub sync_api_base_url: Option<String>,
}

impl AppState {
    pub fn from_deps(deps: ServerDeps, version: impl Into<String>) -> Self {
        let (ws_tx, _) = broadcast::channel(256);
        let supervisor_tasks = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        Self {
            audit_storage: deps.audit_storage,
            digest_queue: deps.digest_queue,
            proxy: deps.proxy,
            supervisor_registry: deps.supervisor_registry,
            supervisor_tasks,
            containment_tracker: deps.containment_tracker,
            correlation_tracker: deps.correlation_tracker,
            canary_registry: deps.canary_registry,
            notification_dispatcher: deps.notification_dispatcher,
            start_time: std::time::Instant::now(),
            version: version.into(),
            ws_tx,
            shutdown_tx: None,
            plan_tier: "community".into(),
            config_dir: default_config_dir(),
            audit_db_path: deps.audit_db_path,
            account_id: "local:community".into(),
            auth_config: auth::AuthConfig::default(),
            feature_gate: Arc::new(RwLock::new(grith_digest::notification::FeatureGate {
                tier: grith_digest::notification::PlanTier::Community,
                seats: 1,
            })),
            license_valid_until: None,
            billing_portal_url: None,
            refresh_state: Arc::new(RwLock::new(
                grith_digest::notification::RefreshState::default(),
            )),
            dns_seed_domains: deps.dns_seed_domains,
            reputation_table: deps.reputation_table,
            reputation_config: deps.reputation_config,
            sync_api_key: deps.sync_api_key,
            sync_api_base_url: deps.sync_api_base_url,
            ipc_token: String::new(),
        }
    }
}

impl AppState {
    /// Set the IPC bearer token for endpoint authentication.
    pub fn set_ipc_token(&mut self, token: String) {
        self.ipc_token = token;
    }
}

fn default_config_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("GRITH_CONFIG_DIR") {
        return PathBuf::from(path);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".config").join("grith");
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(profile).join(".config").join("grith");
    }
    PathBuf::from(".grith")
}

/// The grith HTTP/WebSocket server.
pub struct GrithServer {
    config: ServerConfig,
    state: AppState,
    shutdown_rx: broadcast::Receiver<()>,
}

impl GrithServer {
    /// Create a new server with the given config and shared subsystem state.
    pub fn new(
        config: ServerConfig,
        deps: ServerDeps,
        version: impl Into<String>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        let state = AppState::from_deps(deps, version);

        Self {
            config,
            state,
            shutdown_rx,
        }
    }

    /// Build the Axum router with all routes and middleware.
    pub fn build_router(&self) -> Router {
        let origin = format!("http://{}:{}", self.config.host, self.config.port);
        let cors = CorsLayer::new()
            .allow_origin(
                origin
                    .parse::<HeaderValue>()
                    .unwrap_or_else(|_| HeaderValue::from_static("http://127.0.0.1:3141")),
            )
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                axum::http::HeaderName::from_static("x-grith-api-key"),
            ]);

        // Build rate limiter from config
        let rl = &self.config.rate_limit;
        let limiter = if rl.enabled {
            Arc::new(rate_limit::ApiRateLimiter::new(
                rl.general_rps,
                rl.write_rps,
                rl.proxy_test_rps,
                rl.ipc_rps,
            ))
        } else {
            Arc::new(rate_limit::ApiRateLimiter::disabled())
        };

        // Wrap each sub-router with its bucket-specific rate limit layer.
        // Rate limiting runs inside auth layers (innermost), so
        // unauthenticated requests are rejected before consuming quota.
        let general = routes::general_routes().layer(axum::middleware::from_fn({
            let limiter = Arc::clone(&limiter);
            move |req, next| {
                let limiter = Arc::clone(&limiter);
                async move {
                    rate_limit::check(limiter, rate_limit::RateLimitBucket::General, req, next)
                        .await
                }
            }
        }));

        let write = routes::write_routes().layer(axum::middleware::from_fn({
            let limiter = Arc::clone(&limiter);
            move |req, next| {
                let limiter = Arc::clone(&limiter);
                async move {
                    rate_limit::check(limiter, rate_limit::RateLimitBucket::Write, req, next).await
                }
            }
        }));

        let proxy_test = routes::proxy_test_routes().layer(axum::middleware::from_fn({
            let limiter = Arc::clone(&limiter);
            move |req, next| {
                let limiter = Arc::clone(&limiter);
                async move {
                    rate_limit::check(limiter, rate_limit::RateLimitBucket::ProxyTest, req, next)
                        .await
                }
            }
        }));

        let ipc = routes::ipc_routes().layer(axum::middleware::from_fn({
            let limiter = Arc::clone(&limiter);
            move |req, next| {
                let limiter = Arc::clone(&limiter);
                async move {
                    rate_limit::check(limiter, rate_limit::RateLimitBucket::Ipc, req, next).await
                }
            }
        }));

        let api_router = general.merge(write).merge(proxy_test).merge(ipc);

        // Supervisor API routes are mounted outside `routes::api_router()`,
        // so apply the same limiter here to keep coverage consistent.
        let supervisor_api = supervisor::supervisor_router().layer(axum::middleware::from_fn({
            let limiter = Arc::clone(&limiter);
            move |req: axum::extract::Request, next| {
                let limiter = Arc::clone(&limiter);
                async move {
                    let bucket = match *req.method() {
                        Method::GET | Method::HEAD | Method::OPTIONS => {
                            rate_limit::RateLimitBucket::General
                        }
                        _ => rate_limit::RateLimitBucket::Write,
                    };
                    rate_limit::check(limiter, bucket, req, next).await
                }
            }
        }));
        let supervisor_ws = supervisor::supervisor_ws_router();

        let ws_router = Router::new().route("/ws/live", axum::routing::get(websocket::ws_handler));

        let state = self.state.clone();

        let mut router = Router::new()
            .nest("/api", api_router)
            .nest("/api/supervisor", supervisor_api)
            .merge(ws_router)
            .merge(supervisor_ws)
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth::api_key_guard,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth::localhost_guard,
            ))
            .layer(cors);

        // Add static file serving if dashboard directory is configured
        if let Some(ref dir) = self.config.dashboard_dir {
            router = static_files::add_static_serving(router, dir);
        }

        router.with_state(state)
    }

    /// Start the server and block until shutdown.
    pub async fn start(mut self) -> Result<()> {
        // Validate auth configuration before binding to prevent insecure exposure
        self.state.auth_config.validate().map_err(Error::Server)?;

        // Check if the host is a non-loopback address and emit appropriate warnings
        let is_non_loopback = self
            .config
            .host
            .parse::<IpAddr>()
            .map(|ip| !ip.is_loopback())
            .unwrap_or(self.config.host != "localhost");

        if is_non_loopback {
            if self.config.tls.is_some() {
                let addr = format!("{}:{}", self.config.host, self.config.port);
                tracing::info!("TLS enabled — serving HTTPS on {addr}");
            } else {
                let addr = format!("{}:{}", self.config.host, self.config.port);
                tracing::warn!(
                    "SECURITY WARNING: binding to non-loopback address {addr} without TLS. \
                     API keys and all traffic are transmitted in plain text. \
                     Configure [server.tls] or use a TLS-terminating reverse proxy (nginx, Caddy)."
                );
            }
        }

        if !self.state.auth_config.localhost_only {
            tracing::warn!(
                "Non-localhost access is enabled — the API will accept connections from \
                 any network address. Ensure API key authentication is properly configured \
                 and the key is kept secret."
            );
        }

        let addr = format!("{}:{}", self.config.host, self.config.port);
        let router = self.build_router();

        if let Some(ref tls) = self.config.tls {
            let rustls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
                    .await
                    .map_err(|e| Error::Server(format!("failed to load TLS config: {e}")))?;

            tracing::info!(address = %addr, "grith-server listening (TLS)");

            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                let _ = self.shutdown_rx.recv().await;
                tracing::info!("grith-server shutting down");
                shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
            });

            axum_server::bind_rustls(
                addr.parse()
                    .map_err(|e| Error::Server(format!("invalid address {addr}: {e}")))?,
                rustls_config,
            )
            .handle(handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| Error::Server(format!("TLS server error: {e}")))?;
        } else {
            let listener = TcpListener::bind(&addr)
                .await
                .map_err(|e| Error::Server(format!("failed to bind to {addr}: {e}")))?;

            tracing::info!(address = %addr, "grith-server listening");

            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = self.shutdown_rx.recv().await;
                tracing::info!("grith-server shutting down");
            })
            .await
            .map_err(Error::Io)?;
        }

        Ok(())
    }

    /// Get the configured address string.
    pub fn address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }

    /// Get a WebSocket broadcast sender for publishing events.
    pub fn ws_sender(&self) -> broadcast::Sender<String> {
        self.state.ws_tx.clone()
    }

    /// Set the shutdown sender so the server can be stopped via API.
    pub fn with_shutdown_sender(mut self, tx: broadcast::Sender<()>) -> Self {
        self.state.shutdown_tx = Some(tx);
        self
    }

    /// Set the IPC bearer token used to protect daemon-client endpoints.
    pub fn with_ipc_token(mut self, token: impl Into<String>) -> Self {
        self.state.set_ipc_token(token.into());
        self
    }

    /// Set the plan tier for feature gating.
    pub fn with_plan_tier(mut self, tier: impl Into<String>) -> Self {
        self.state.plan_tier = tier.into();
        self
    }

    /// Set the account identifier used for account-scoped configuration.
    pub fn with_account_id(mut self, account_id: impl Into<String>) -> Self {
        self.state.account_id = account_id.into();
        self
    }

    /// Set the feature gate for tier-based feature access.
    pub fn with_feature_gate(
        mut self,
        gate: Arc<RwLock<grith_digest::notification::FeatureGate>>,
    ) -> Self {
        self.state.feature_gate = gate;
        self
    }

    /// Set the authentication configuration.
    pub fn with_auth_config(mut self, auth_config: auth::AuthConfig) -> Self {
        self.state.auth_config = auth_config;
        self
    }

    /// Set the license renewal date for API responses.
    pub fn with_license_valid_until(mut self, date: Option<String>) -> Self {
        self.state.license_valid_until = date;
        self
    }

    /// Set the billing portal URL for API responses.
    pub fn with_billing_portal_url(mut self, url: Option<String>) -> Self {
        self.state.billing_portal_url = url;
        self
    }

    /// Share the daemon's licence-refresh state so /api/license/status can
    /// surface scheduler health to dashboards and the CLI.
    pub fn with_refresh_state(
        mut self,
        state: Arc<RwLock<grith_digest::notification::RefreshState>>,
    ) -> Self {
        self.state.refresh_state = state;
        self
    }

    /// Set optional sync credentials for team learned-rules refresh.
    pub fn with_sync_api(mut self, api_key: Option<String>, base_url: Option<String>) -> Self {
        self.state.sync_api_key = api_key;
        self.state.sync_api_base_url = base_url;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use grith_proxy::filters::FilterRegistry;
    use grith_proxy::meta_rules::MetaRuleEngine;
    use grith_proxy::scoring::ScoringConfig;
    use grith_supervisor::config::SupervisorConfig;
    use tower::util::ServiceExt;

    fn make_deps() -> ServerDeps {
        let audit = Arc::new(Mutex::new(AuditStorage::open_in_memory().unwrap()));
        let digest = Arc::new(DigestQueue::open_in_memory().unwrap());
        let proxy = Arc::new(SecurityProxy::new(
            FilterRegistry::new(),
            ScoringConfig::default(),
            MetaRuleEngine::new(vec![]),
        ));
        let registry = Arc::new(Mutex::new(SupervisorRegistry::new(
            SupervisorConfig::default(),
        )));
        let containment = Arc::new(ContainmentTracker::with_defaults());
        let correlation = Arc::new(CorrelationTracker::with_defaults());
        let canary_registry = Arc::new(CanaryRegistry::empty());
        let notification_dispatcher = Arc::new(grith_notify::NotificationDispatcher::new(
            grith_notify::ChannelRegistry::new(),
            grith_notify::RoutingEngine::default(),
            Arc::new(grith_digest::notification::CallbackNonceStore::new(
                std::time::Duration::from_secs(300),
            )),
            grith_digest::notification::PlanTier::Community,
            digest.clone(),
            grith_notify::rate_limiter::RateLimiter::default(),
            grith_notify::batcher::Batcher::default(),
            std::time::Duration::from_secs(300),
            grith_digest::types::ScoreSeverity::High,
        ));
        let audit_db_path = std::env::temp_dir()
            .join(format!("grith-test-{}", uuid::Uuid::new_v4()))
            .join("audit.db");
        ServerDeps {
            audit_storage: audit,
            digest_queue: digest,
            proxy,
            supervisor_registry: registry,
            containment_tracker: containment,
            correlation_tracker: correlation,
            canary_registry,
            notification_dispatcher,
            audit_db_path,
            dns_seed_domains: vec![],
            reputation_table: Arc::new(std::sync::Mutex::new(
                grith_proxy::reputation::ReputationTable::new(),
            )),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            sync_api_key: None,
            sync_api_base_url: None,
        }
    }

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 3141);
        assert!(!config.enabled);
    }

    #[test]
    fn test_default_config_no_tls() {
        let config = ServerConfig::default();
        assert!(config.tls.is_none());
    }

    #[test]
    fn test_tls_config_round_trips() {
        let tls = TlsConfig {
            cert_path: "/tmp/cert.pem".to_string(),
            key_path: "/tmp/key.pem".to_string(),
        };
        let json = serde_json::to_string(&tls).unwrap();
        let deserialized: TlsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.cert_path, "/tmp/cert.pem");
        assert_eq!(deserialized.key_path, "/tmp/key.pem");
    }

    #[test]
    fn test_server_address() {
        let config = ServerConfig::default();
        let deps = make_deps();
        let (_, rx) = broadcast::channel(1);
        let server = GrithServer::new(config, deps, "0.1.0", rx);
        assert_eq!(server.address(), "127.0.0.1:3141");
    }

    #[test]
    fn test_build_router() {
        let config = ServerConfig::default();
        let deps = make_deps();
        let (_, rx) = broadcast::channel(1);
        let server = GrithServer::new(config, deps, "0.1.0", rx);
        // Should not panic
        let _router = server.build_router();
    }

    #[tokio::test]
    async fn test_ipc_routes_require_bearer_token() {
        let config = ServerConfig::default();
        let deps = make_deps();
        let (_, rx) = broadcast::channel(1);
        let server = GrithServer::new(config, deps, "0.1.0", rx).with_ipc_token("test-token");
        let app = server.build_router();

        let unauth_proxy = app
            .clone()
            .oneshot(
                Request::get("/api/proxy/status/full")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth_proxy.status(), StatusCode::UNAUTHORIZED);

        let authed_proxy = app
            .clone()
            .oneshot(
                Request::get("/api/proxy/status/full")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authed_proxy.status(), StatusCode::OK);

        let unauth_shutdown = app
            .clone()
            .oneshot(
                Request::post("/api/server/shutdown")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth_shutdown.status(), StatusCode::UNAUTHORIZED);

        let authed_shutdown = app
            .oneshot(
                Request::post("/api/server/shutdown")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authed_shutdown.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_supervisor_get_routes_are_rate_limited() {
        let config = ServerConfig {
            rate_limit: RateLimitConfig {
                enabled: true,
                general_rps: 1,
                write_rps: 10,
                proxy_test_rps: 10,
                ipc_rps: 10,
            },
            ..ServerConfig::default()
        };
        let deps = make_deps();
        let (_, rx) = broadcast::channel(1);
        let server = GrithServer::new(config, deps, "0.1.0", rx);
        let app = server.build_router();

        let first = app
            .clone()
            .oneshot(
                Request::get("/api/supervisor/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);

        let second = app
            .oneshot(
                Request::get("/api/supervisor/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_supervisor_write_routes_are_rate_limited() {
        let config = ServerConfig {
            rate_limit: RateLimitConfig {
                enabled: true,
                general_rps: 10,
                write_rps: 1,
                proxy_test_rps: 10,
                ipc_rps: 10,
            },
            ..ServerConfig::default()
        };
        let deps = make_deps();
        let (_, rx) = broadcast::channel(1);
        let server = GrithServer::new(config, deps, "0.1.0", rx);
        let app = server.build_router();

        let session_id = uuid::Uuid::new_v4();
        let path = format!("/api/supervisor/sessions/{session_id}/kill");
        let first = app
            .clone()
            .oneshot(Request::post(path.clone()).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);

        let second = app
            .oneshot(Request::post(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
