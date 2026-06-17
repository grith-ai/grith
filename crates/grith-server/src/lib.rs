// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! HTTP and WebSocket server for the grith dashboard and API.
//!
//! Serves the embedded React dashboard and provides REST endpoints
//! for audit, digest, proxy, supervisor, and notification management.

pub mod auth;
pub mod csrf;
pub mod error;
pub mod ipc_auth;
pub mod rate_limit;
pub mod routes;
pub mod static_files;
pub mod supervisor;
pub mod websocket;
pub mod ws_auth;

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
    /// Per-server dashboard token gating browser-facing mutations (and, from
    /// item 4, sensitive reads). Sent by the SPA in the `x-grith-csrf` header.
    /// Empty = no token configured: the CSRF guard then accepts the public
    /// sentinel (zero-config / test mode). See [`crate::csrf`].
    pub dashboard_token: String,
    /// Single-use browser pairing code (see [`crate::routes::dashboard_pair`]).
    ///
    /// Minted on demand; exchanged once for the real `dashboard_token` at the
    /// open `/api/dashboard/pair` endpoint, then cleared. Lets the CLI hand a
    /// browser the token without ever printing the long-lived secret — only the
    /// disposable code appears in a URL, and only until first use. `None` when
    /// no code is currently outstanding.
    pub dashboard_pair_code: Arc<Mutex<Option<String>>>,
    /// Rolling record of session-limit (429) rejection timestamps, pruned to a
    /// 7-day window on access. Powers the dashboard "you hit your session limit
    /// N times this week" upgrade nudge and `/api/tier` rejection telemetry.
    pub session_limit_rejections: Arc<Mutex<Vec<chrono::DateTime<chrono::Utc>>>>,
}

/// Number of days of session-limit rejections retained for the upgrade nudge.
pub const SESSION_LIMIT_REJECTION_WINDOW_DAYS: i64 = 7;

/// Record a session-limit rejection and return the rolling-window count.
///
/// Prunes entries older than [`SESSION_LIMIT_REJECTION_WINDOW_DAYS`] so the
/// returned count reflects only recent rejections. Lock poisoning is treated as
/// "no history" rather than panicking the request path.
pub fn record_session_limit_rejection(
    log: &Arc<Mutex<Vec<chrono::DateTime<chrono::Utc>>>>,
) -> usize {
    let now = chrono::Utc::now();
    let cutoff = now - chrono::Duration::days(SESSION_LIMIT_REJECTION_WINDOW_DAYS);
    match log.lock() {
        Ok(mut entries) => {
            entries.retain(|ts| *ts >= cutoff);
            entries.push(now);
            entries.len()
        }
        Err(_) => 0,
    }
}

/// Count session-limit rejections within the rolling window without recording a
/// new one. Used by read-only endpoints (e.g. `/api/tier`).
pub fn count_recent_session_limit_rejections(
    log: &Arc<Mutex<Vec<chrono::DateTime<chrono::Utc>>>>,
) -> usize {
    let cutoff = chrono::Utc::now() - chrono::Duration::days(SESSION_LIMIT_REJECTION_WINDOW_DAYS);
    match log.lock() {
        Ok(entries) => entries.iter().filter(|ts| **ts >= cutoff).count(),
        Err(_) => 0,
    }
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
            dashboard_token: String::new(),
            dashboard_pair_code: Arc::new(Mutex::new(None)),
            session_limit_rejections: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl AppState {
    /// Set the IPC bearer token for endpoint authentication.
    pub fn set_ipc_token(&mut self, token: String) {
        self.ipc_token = token;
    }

    pub fn set_dashboard_token(&mut self, token: String) {
        self.dashboard_token = token;
    }

    /// Mint a fresh single-use browser pairing code, replacing any outstanding
    /// one, and return it. The caller surfaces it to exactly one browser (via
    /// the `#pair=` URL fragment), which exchanges it at `/api/dashboard/pair`.
    pub fn mint_pair_code(&self) -> String {
        let code = uuid::Uuid::new_v4().simple().to_string();
        if let Ok(mut slot) = self.dashboard_pair_code.lock() {
            *slot = Some(code.clone());
        }
        code
    }

    /// Exchange a pairing code for the dashboard token. Returns the token when
    /// `candidate` matches the outstanding code (constant-time), clearing it so
    /// it cannot be reused; returns `None` otherwise (no code outstanding, or
    /// mismatch). An empty candidate never matches.
    pub fn redeem_pair_code(&self, candidate: &str) -> Option<String> {
        if candidate.is_empty() {
            return None;
        }
        let mut slot = self.dashboard_pair_code.lock().ok()?;
        let current = slot.as_deref()?;
        if crate::ipc_auth::constant_time_eq(candidate.as_bytes(), current.as_bytes()) {
            *slot = None; // single-use
            Some(self.dashboard_token.clone())
        } else {
            None
        }
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
                axum::http::HeaderName::from_static(csrf::DASHBOARD_CSRF_HEADER),
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

        // Low-sensitivity status reads: open, General rate-limit bucket.
        let open_read = routes::open_read_routes().layer(axum::middleware::from_fn({
            let limiter = Arc::clone(&limiter);
            move |req, next| {
                let limiter = Arc::clone(&limiter);
                async move {
                    rate_limit::check(limiter, rate_limit::RateLimitBucket::General, req, next)
                        .await
                }
            }
        }));

        // Sensitive reads (item 4): dashboard-token guard (outermost) over the
        // General rate-limit bucket. Gated only when a token is configured.
        let sensitive_read = routes::sensitive_read_routes()
            .layer(axum::middleware::from_fn({
                let limiter = Arc::clone(&limiter);
                move |req, next| {
                    let limiter = Arc::clone(&limiter);
                    async move {
                        rate_limit::check(limiter, rate_limit::RateLimitBucket::General, req, next)
                            .await
                    }
                }
            }))
            .layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                csrf::require_dashboard_token,
            ));

        // Browser-facing dashboard mutations: CSRF guard (outermost, so
        // unauthenticated requests are rejected before consuming write quota)
        // over the write-bucket rate limiter.
        let dashboard_write = routes::dashboard_write_routes()
            .layer(axum::middleware::from_fn({
                let limiter = Arc::clone(&limiter);
                move |req, next| {
                    let limiter = Arc::clone(&limiter);
                    async move {
                        rate_limit::check(limiter, rate_limit::RateLimitBucket::Write, req, next)
                            .await
                    }
                }
            }))
            .layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                csrf::require_dashboard_csrf,
            ));

        // Mutating routes with their own non-CSRF auth (webhook nonce / IPC
        // bearer). Same rate-limit bucket, but no CSRF layer.
        let protected_write = routes::protected_write_routes().layer(axum::middleware::from_fn({
            let limiter = Arc::clone(&limiter);
            move |req, next| {
                let limiter = Arc::clone(&limiter);
                async move {
                    rate_limit::check(limiter, rate_limit::RateLimitBucket::Write, req, next).await
                }
            }
        }));

        // Proxy dry-run is a dashboard-driven route (FilterConfig.tsx) — CSRF
        // guard over its own rate-limit bucket.
        let proxy_test = routes::proxy_test_routes()
            .layer(axum::middleware::from_fn({
                let limiter = Arc::clone(&limiter);
                move |req, next| {
                    let limiter = Arc::clone(&limiter);
                    async move {
                        rate_limit::check(
                            limiter,
                            rate_limit::RateLimitBucket::ProxyTest,
                            req,
                            next,
                        )
                        .await
                    }
                }
            }))
            .layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                csrf::require_dashboard_csrf,
            ));

        let ipc = routes::ipc_routes().layer(axum::middleware::from_fn({
            let limiter = Arc::clone(&limiter);
            move |req, next| {
                let limiter = Arc::clone(&limiter);
                async move {
                    rate_limit::check(limiter, rate_limit::RateLimitBucket::Ipc, req, next).await
                }
            }
        }));

        let api_router = open_read
            .merge(sensitive_read)
            .merge(dashboard_write)
            .merge(protected_write)
            .merge(proxy_test)
            .merge(ipc);

        // Supervisor API routes are mounted outside `routes::api_router()`,
        // so apply the same limiter here to keep coverage consistent. Two auth
        // layers compose here:
        //   * `require_dashboard_csrf` gates the mutations (create / kill /
        //     delete) on every profile, including zero-config, so a browser
        //     drive-by can't kill sessions.
        //   * `require_dashboard_token` gates the reads (`/sessions`,
        //     `/sessions/:id` — session/process metadata, root PIDs) once a
        //     token is configured (item 4 two-tier).
        let supervisor_api = supervisor::supervisor_router()
            .layer(axum::middleware::from_fn({
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
            }))
            .layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                csrf::require_dashboard_csrf,
            ))
            .layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                csrf::require_dashboard_token,
            ));
        // WebSocket streams are not covered by CORS, so gate the upgrade with
        // the Origin-vs-Host + dashboard-token middleware before any handler.
        let supervisor_ws = supervisor::supervisor_ws_router().layer(
            axum::middleware::from_fn_with_state(self.state.clone(), ws_auth::require_ws_auth),
        );

        let ws_router = Router::new()
            .route("/ws/live", axum::routing::get(websocket::ws_handler))
            .layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                ws_auth::require_ws_auth,
            ));

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

    /// Set the per-server dashboard token gating browser-facing mutations.
    ///
    /// When set, the [`crate::csrf`] guard requires the SPA to present this
    /// exact value in `x-grith-csrf` (verified in constant time) rather than
    /// the public sentinel. The SPA learns it from the `#token=` launch
    /// fragment.
    pub fn with_dashboard_token(mut self, token: impl Into<String>) -> Self {
        self.state.set_dashboard_token(token.into());
        self
    }

    /// Mint a fresh single-use browser pairing code on this server's state.
    ///
    /// Used by in-process launch paths (`grith run` / a direct `dashboard
    /// start`) to obtain a code *before* `start()` consumes `self`, so the CLI
    /// can build the `#pair=<code>` URL without printing the long-lived token.
    /// Separate-process callers fetch one over IPC instead.
    pub fn mint_pair_code(&self) -> String {
        self.state.mint_pair_code()
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
    fn session_limit_rejection_counter_records_and_counts() {
        let log = Arc::new(Mutex::new(Vec::new()));
        assert_eq!(count_recent_session_limit_rejections(&log), 0);
        assert_eq!(record_session_limit_rejection(&log), 1);
        assert_eq!(record_session_limit_rejection(&log), 2);
        // Read-only count reflects the recorded entries without adding more.
        assert_eq!(count_recent_session_limit_rejections(&log), 2);
        assert_eq!(count_recent_session_limit_rejections(&log), 2);
    }

    #[test]
    fn session_limit_rejection_counter_prunes_old_entries() {
        let log = Arc::new(Mutex::new(Vec::new()));
        // Seed an entry older than the retention window.
        {
            let mut entries = log.lock().unwrap();
            entries.push(
                chrono::Utc::now()
                    - chrono::Duration::days(SESSION_LIMIT_REJECTION_WINDOW_DAYS + 1),
            );
        }
        // Recording prunes the stale entry, leaving only the fresh one.
        assert_eq!(record_session_limit_rejection(&log), 1);
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
        // Send the dashboard CSRF header so these requests reach the
        // rate-limit layer rather than being rejected by the CSRF guard.
        let first = app
            .clone()
            .oneshot(
                Request::post(path.clone())
                    .header(
                        crate::csrf::DASHBOARD_CSRF_HEADER,
                        crate::csrf::DASHBOARD_CSRF_SENTINEL,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);

        let second = app
            .oneshot(
                Request::post(path)
                    .header(
                        crate::csrf::DASHBOARD_CSRF_HEADER,
                        crate::csrf::DASHBOARD_CSRF_SENTINEL,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // --- Dashboard CSRF guard (item 1) ---

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn csrf_test_server() -> GrithServer {
        let config = ServerConfig::default();
        let deps = make_deps();
        let (_, rx) = broadcast::channel(1);
        GrithServer::new(config, deps, "0.1.0", rx)
    }

    fn csrf_test_server_with_token(token: &str) -> GrithServer {
        let config = ServerConfig::default();
        let deps = make_deps();
        let (_, rx) = broadcast::channel(1);
        GrithServer::new(config, deps, "0.1.0", rx).with_dashboard_token(token)
    }

    async fn sync_apply_status(app: axum::Router, header: Option<(&str, &str)>) -> StatusCode {
        let mut req = Request::post("/api/sync/apply");
        if let Some((name, value)) = header {
            req = req.header(name, value);
        }
        app.oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    // --- Browser pairing (single-use code → token) ---

    #[tokio::test]
    async fn pair_code_mint_requires_ipc_bearer_then_redeems_once() {
        let dash_token = "the-real-dashboard-token";
        let config = ServerConfig::default();
        let deps = make_deps();
        let (_, rx) = broadcast::channel(1);
        let server = GrithServer::new(config, deps, "0.1.0", rx)
            .with_ipc_token("daemon-bearer")
            .with_dashboard_token(dash_token);
        let app = server.build_router();

        // Mint without the IPC bearer → 401.
        let unauth = app
            .clone()
            .oneshot(
                Request::post("/api/ipc/dashboard/pair-code")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        // Mint with the bearer → 200 + a code.
        let minted = app
            .clone()
            .oneshot(
                Request::post("/api/ipc/dashboard/pair-code")
                    .header("authorization", "Bearer daemon-bearer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(minted.status(), StatusCode::OK);
        let code = body_json(minted).await["code"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!code.is_empty());

        let redeem = |c: &str| {
            let app = app.clone();
            let body = format!("{{\"code\":\"{c}\"}}");
            async move {
                app.oneshot(
                    Request::post("/api/dashboard/pair")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };

        // Redeem the valid code → 200 + the real dashboard token.
        let ok = redeem(&code).await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(body_json(ok).await["token"].as_str().unwrap(), dash_token);

        // Single-use: the same code is now dead → 401.
        assert_eq!(redeem(&code).await.status(), StatusCode::UNAUTHORIZED);

        // A bogus code never matches.
        assert_eq!(
            redeem("not-a-code").await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn pair_redeem_with_no_outstanding_code_is_unauthorized() {
        // Fresh server, no code minted yet → any redeem attempt fails.
        let app = csrf_test_server_with_token("tok").build_router();
        let resp = app
            .oneshot(
                Request::post("/api/dashboard/pair")
                    .header("content-type", "application/json")
                    .body(Body::from("{\"code\":\"anything\"}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dashboard_write_with_configured_token_requires_exact_token() {
        let token = "s3cr3t-dashboard-token";

        // Correct token → passes the guard (handler returns its own non-CSRF
        // response, here a Pro feature gate).
        let app = csrf_test_server_with_token(token).build_router();
        let resp = app
            .oneshot(
                Request::post("/api/sync/apply")
                    .header(crate::csrf::DASHBOARD_CSRF_HEADER, token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!body_string(resp).await.contains("CSRF_REQUIRED"));

        // The public sentinel is NOT accepted once a real token is configured.
        let status = sync_apply_status(
            csrf_test_server_with_token(token).build_router(),
            Some((
                crate::csrf::DASHBOARD_CSRF_HEADER,
                crate::csrf::DASHBOARD_CSRF_SENTINEL,
            )),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Wrong token → rejected.
        let status = sync_apply_status(
            csrf_test_server_with_token(token).build_router(),
            Some((crate::csrf::DASHBOARD_CSRF_HEADER, "wrong-token")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Missing header → rejected.
        let status =
            sync_apply_status(csrf_test_server_with_token(token).build_router(), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn dashboard_read_is_open_even_with_token_configured() {
        // Item 2 gates writes only; reads stay open until item 4.
        let app = csrf_test_server_with_token("a-token").build_router();
        let resp = app
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- Two-tier read gating (item 4) ---

    async fn get_status(app: axum::Router, path: &str, token: Option<&str>) -> StatusCode {
        let mut req = Request::get(path);
        if let Some(t) = token {
            req = req.header(crate::csrf::DASHBOARD_CSRF_HEADER, t);
        }
        app.oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn sensitive_reads_require_token_when_configured() {
        let token = "read-gate-token";
        // No token header → 401 for sensitive reads.
        for path in ["/api/audit", "/api/digest", "/api/canaries", "/api/config"] {
            let status = get_status(
                csrf_test_server_with_token(token).build_router(),
                path,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} should be gated");
        }

        // Correct token → not the auth rejection (handler runs).
        let status = get_status(
            csrf_test_server_with_token(token).build_router(),
            "/api/audit",
            Some(token),
        )
        .await;
        assert_ne!(status, StatusCode::UNAUTHORIZED);

        // Wrong token / sentinel → still 401 once a real token is set.
        for bad in [crate::csrf::DASHBOARD_CSRF_SENTINEL, "nope"] {
            let status = get_status(
                csrf_test_server_with_token(token).build_router(),
                "/api/audit",
                Some(bad),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn open_reads_stay_open_with_token_configured() {
        let token = "read-gate-token";
        for path in ["/api/health", "/api/tier", "/api/proxy/status"] {
            let status = get_status(
                csrf_test_server_with_token(token).build_router(),
                path,
                None,
            )
            .await;
            assert_ne!(
                status,
                StatusCode::UNAUTHORIZED,
                "{path} must stay open even with a token configured"
            );
        }
    }

    #[tokio::test]
    async fn sensitive_reads_open_in_zero_config() {
        // No dashboard token configured → sensitive reads are not gated.
        for path in ["/api/audit", "/api/digest", "/api/config"] {
            let status = get_status(csrf_test_server().build_router(), path, None).await;
            assert_ne!(
                status,
                StatusCode::UNAUTHORIZED,
                "{path} open in zero-config"
            );
        }
    }

    #[tokio::test]
    async fn supervisor_reads_require_token_when_configured() {
        let token = "read-gate-token";
        let status = get_status(
            csrf_test_server_with_token(token).build_router(),
            "/api/supervisor/sessions",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dashboard_write_without_csrf_header_is_forbidden() {
        let app = csrf_test_server().build_router();
        let resp = app
            .oneshot(
                Request::post("/api/sync/apply")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_string(resp).await.contains("CSRF_REQUIRED"));
    }

    #[tokio::test]
    async fn dashboard_write_with_csrf_header_passes_the_guard() {
        let app = csrf_test_server().build_router();
        let resp = app
            .oneshot(
                Request::post("/api/sync/apply")
                    .header(
                        crate::csrf::DASHBOARD_CSRF_HEADER,
                        crate::csrf::DASHBOARD_CSRF_SENTINEL,
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // The handler runs (here it returns a Pro feature-gate response); the
        // important invariant is that the CSRF guard did not reject the request.
        assert!(!body_string(resp).await.contains("CSRF_REQUIRED"));
    }

    #[tokio::test]
    async fn dashboard_write_with_wrong_csrf_value_is_forbidden() {
        let app = csrf_test_server().build_router();
        let resp = app
            .oneshot(
                Request::post("/api/sync/apply")
                    .header(crate::csrf::DASHBOARD_CSRF_HEADER, "not-the-sentinel")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_string(resp).await.contains("CSRF_REQUIRED"));
    }

    #[tokio::test]
    async fn dashboard_read_does_not_require_csrf() {
        let app = csrf_test_server().build_router();
        let resp = app
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn supervisor_mutation_without_csrf_is_forbidden() {
        let app = csrf_test_server().build_router();
        let id = uuid::Uuid::new_v4();
        let resp = app
            .oneshot(
                Request::post(format!("/api/supervisor/sessions/{id}/kill"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_string(resp).await.contains("CSRF_REQUIRED"));
    }

    #[tokio::test]
    async fn supervisor_read_does_not_require_csrf() {
        let app = csrf_test_server().build_router();
        let resp = app
            .oneshot(
                Request::get("/api/supervisor/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn webhook_review_is_not_csrf_gated() {
        // The webhook callback authenticates via a single-use nonce, not the
        // dashboard CSRF header. A POST without the header must reach the
        // handler (and fail on the bad nonce / lookup), never the CSRF guard.
        let app = csrf_test_server().build_router();
        let id = uuid::Uuid::new_v4();
        let body = serde_json::json!({
            "action": "approve",
            "reviewer": "tester",
            "notes": serde_json::Value::Null,
            "nonce": "definitely-not-valid"
        })
        .to_string();
        let resp = app
            .oneshot(
                Request::post(format!("/api/digest/{id}/webhook-review"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Positively confirm the request reached the webhook handler and failed
        // on the bad nonce (REVIEW_ERROR), rather than being stopped by the
        // CSRF guard — proving the route is not CSRF-gated.
        let body = body_string(resp).await;
        assert!(body.contains("REVIEW_ERROR"), "body was: {body}");
        assert!(!body.contains("CSRF_REQUIRED"));
    }

    // --- WebSocket upgrade authorization (item 3) ---

    fn ws_request(path: &str, origin: Option<&str>, host: &str) -> axum::http::Request<Body> {
        let mut builder = Request::get(path)
            .header("host", host)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
        if let Some(o) = origin {
            builder = builder.header("origin", o);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn ws_live_rejects_cross_origin_handshake() {
        let app = csrf_test_server().build_router();
        let resp = app
            .oneshot(ws_request(
                "/ws/live",
                Some("http://evil.example"),
                "127.0.0.1:3141",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_string(resp).await.contains("WS_ORIGIN_FORBIDDEN"));
    }

    #[tokio::test]
    async fn ws_live_requires_token_when_configured() {
        let token = "ws-secret-token";
        // Same-origin but no token → 401.
        let resp = csrf_test_server_with_token(token)
            .build_router()
            .oneshot(ws_request(
                "/ws/live",
                Some("http://127.0.0.1:3141"),
                "127.0.0.1:3141",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(body_string(resp).await.contains("WS_TOKEN_REQUIRED"));

        // Same-origin with the correct token → the auth middleware passes the
        // request through. (A real upgrade can't complete under `oneshot`, so
        // assert only that auth did not reject it.)
        let resp = csrf_test_server_with_token(token)
            .build_router()
            .oneshot(ws_request(
                &format!("/ws/live?token={token}"),
                Some("http://127.0.0.1:3141"),
                "127.0.0.1:3141",
            ))
            .await
            .unwrap();
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(status, StatusCode::FORBIDDEN);
        assert!(!body_string(resp).await.contains("WS_TOKEN_REQUIRED"));

        // Same-origin with a wrong token → 401.
        let resp = csrf_test_server_with_token(token)
            .build_router()
            .oneshot(ws_request(
                "/ws/live?token=wrong",
                Some("http://127.0.0.1:3141"),
                "127.0.0.1:3141",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ws_supervisor_stream_is_origin_and_token_gated() {
        let token = "ws-secret-token";
        let id = uuid::Uuid::new_v4();

        // Cross-origin → 403 before the session-existence probe.
        let resp = csrf_test_server_with_token(token)
            .build_router()
            .oneshot(ws_request(
                &format!("/ws/supervisor/{id}"),
                Some("http://evil.example"),
                "127.0.0.1:3141",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_string(resp).await.contains("WS_ORIGIN_FORBIDDEN"));

        // Same-origin, no token → 401 (still no session-existence leak: a bare
        // handler would 404 on this random UUID, so 401 proves auth ran first).
        let resp = csrf_test_server_with_token(token)
            .build_router()
            .oneshot(ws_request(
                &format!("/ws/supervisor/{id}"),
                Some("http://127.0.0.1:3141"),
                "127.0.0.1:3141",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(body_string(resp).await.contains("WS_TOKEN_REQUIRED"));
    }

    #[tokio::test]
    async fn ws_live_open_without_token_when_unconfigured() {
        // Zero-config (no dashboard token): same-origin handshake is not
        // rejected by the auth middleware.
        let resp = csrf_test_server()
            .build_router()
            .oneshot(ws_request(
                "/ws/live",
                Some("http://127.0.0.1:3141"),
                "127.0.0.1:3141",
            ))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn ipc_events_require_bearer_and_reject_browser_injection() {
        // The event-ingestion route is IPC-only and bearer-authed. A browser
        // (or any caller) without the daemon token cannot inject events.
        let config = ServerConfig::default();
        let deps = make_deps();
        let (_, rx) = broadcast::channel(1);
        let app = GrithServer::new(config, deps, "0.1.0", rx)
            .with_ipc_token("test-token")
            .build_router();

        let event = serde_json::json!({ "type": "test" }).to_string();

        // No bearer token → rejected by IpcAuth before any broadcast.
        let unauth = app
            .clone()
            .oneshot(
                Request::post("/api/ipc/events")
                    .header("content-type", "application/json")
                    .body(Body::from(event.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        // The browser-facing `/api/events` route no longer exists at all.
        let removed = app
            .clone()
            .oneshot(
                Request::post("/api/events")
                    .header("content-type", "application/json")
                    .body(Body::from(event.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(removed.status(), StatusCode::NOT_FOUND);

        // With the daemon bearer token → accepted.
        let authed = app
            .oneshot(
                Request::post("/api/ipc/events")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(event))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authed.status(), StatusCode::ACCEPTED);
    }
}
