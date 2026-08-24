// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! REST API route definitions and shared request/response helpers.

mod analytics;
mod audit;
mod audit_ipc;
mod canary;
mod config;
mod dashboard_pair;
mod digest;
mod digest_ipc;
mod events;
mod health;
mod inventory;
mod inventory_ipc;
mod listener_rewrites;
mod notifications;
mod onboarding;
mod policies;
mod proxy;
mod proxy_ipc;
mod reputation_ipc;
mod server;
mod session_ipc;
mod sync;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;

// --- Named Constants (audit task 26) ---

/// Default pagination page size for list endpoints.
pub(crate) const DEFAULT_PAGE_LIMIT: usize = 20;
/// Maximum allowed pagination limit to prevent excessive queries.
pub(crate) const MAX_PAGE_LIMIT: usize = 100;
/// Default row limit for audit export.
pub(crate) const DEFAULT_EXPORT_LIMIT: usize = 1000;
/// Number of recent audit records examined for exfiltration stats.
pub(crate) const EXFIL_STATS_RECENT_COUNT: usize = 500;
/// Maximum number of top destinations returned in exfil stats.
pub(crate) const TOP_DESTINATIONS_LIMIT: usize = 10;

// --- Shared helpers ---

#[derive(Serialize)]
pub(crate) struct ApiError {
    error: String,
    code: String,
}

pub(crate) fn api_error(
    status: StatusCode,
    message: impl Into<String>,
    code: impl Into<String>,
) -> impl IntoResponse {
    (
        status,
        Json(ApiError {
            error: message.into(),
            code: code.into(),
        }),
    )
}

/// Parse a UUID from a path segment, returning a 400 response on failure.
#[allow(clippy::result_large_err)] // Response is axum's standard type; boxing adds no benefit here.
pub(crate) fn parse_uuid_or_400(id: &str) -> Result<Uuid, axum::response::Response> {
    Uuid::parse_str(id).map_err(|_| {
        api_error(StatusCode::BAD_REQUEST, "invalid UUID", "INVALID_ID").into_response()
    })
}

// --- Shared pagination types ---

#[derive(Deserialize)]
pub(crate) struct PaginationParams {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

impl PaginationParams {
    /// Return the effective limit, capped at `MAX_PAGE_LIMIT`.
    pub fn effective_limit(&self) -> usize {
        self.limit.min(MAX_PAGE_LIMIT)
    }
}

pub(crate) fn default_limit() -> usize {
    DEFAULT_PAGE_LIMIT
}

// --- Feature gate helper ---

/// Check a feature gate and return a rich 403 response with upgrade metadata
/// if the feature is not allowed for the current plan tier.
///
/// Returns `None` if the feature is allowed, or `Some(Response)` with a JSON
/// body containing `error`, `code`, `current_tier`, `required_tier`, and
/// `upgrade_url` if gated.
pub(crate) fn require_feature(
    state: &crate::AppState,
    feature: &str,
    required_tier: &str,
) -> Option<axum::response::Response> {
    let (allowed, current_tier) = state
        .feature_gate
        .read()
        .map(|gate| (gate.allows(feature), gate.tier.to_string()))
        .unwrap_or_else(|_| (false, "community".to_string()));

    if allowed {
        return None;
    }

    let upgrade_url = state
        .billing_portal_url
        .as_deref()
        .unwrap_or("https://grith.ai/pricing");

    Some(
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": format!("{feature} requires a {required_tier} subscription"),
                "code": "FEATURE_GATED",
                "feature": feature,
                "current_tier": current_tier,
                "required_tier": required_tier,
                "upgrade_url": upgrade_url,
            })),
        )
            .into_response(),
    )
}

// --- Sub-routers for per-bucket rate limiting ---

/// Low-sensitivity status / liveness GET endpoints that stay open even when a
/// dashboard token is configured (item 4 two-tier read gating). These reveal
/// no user activity, tool-call content, secrets, or session/process data —
/// only operational status — so zero-config scripting (health checks, tier
/// probes) keeps working without a token.
pub fn open_read_routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::health))
        .route("/tier", get(health::get_tier))
        .route("/license/status", get(health::get_license_status))
        .route("/proxy/status", get(proxy::proxy_status))
        .route("/onboarding/status", get(onboarding::get_onboarding_status))
        .route(
            "/notifications/channels",
            get(notifications::list_notification_channels),
        )
        .route(
            "/notifications/status",
            get(notifications::notification_status),
        )
        .route("/sync/status", get(sync::sync_status))
}

/// Sensitive GET endpoints gated behind the dashboard token when one is
/// configured (item 4). These expose tool-call arguments (paths/commands/
/// possible secrets), queued decisions, canary token values, session/process
/// metadata, security configuration, and activity analytics — none of which
/// should be readable by another local user (who cannot read the 0600 token
/// file) or a tokenless browser tab.
pub fn sensitive_read_routes() -> Router<AppState> {
    Router::new()
        .route("/digest", get(digest::list_digest))
        .route("/canaries", get(canary::list_canaries))
        .route("/audit", get(audit::list_audit))
        .route("/audit/export", get(audit::export_audit))
        .route("/audit/exfil-stats", get(audit::exfil_stats))
        .route("/audit/summary", get(audit::audit_summary))
        .route("/audit/:id", get(audit::get_audit))
        .route("/config", get(config::get_config))
        .route("/analytics/v2/free", get(analytics::analytics_v2_free))
        .route("/analytics/v2/pro", get(analytics::analytics_v2_pro))
        .route("/policies", get(policies::list_policies))
        .route("/policies/:name", get(policies::get_policy))
        .route("/sync/configs", get(sync::list_synced_configs))
        // PR 4 Phase G: session-pinned binary inventory ("binaries
        // trusted this session" dashboard view).
        .route("/inventory/:session_id", get(inventory::get_inventory))
        // PR 5 Phase E: per-session listener rewrites — every
        // wildcard → loopback clamp the supervisor performed.
        .route(
            "/sessions/:session_id/listener-rewrites",
            get(listener_rewrites::get_listener_rewrites),
        )
}

/// IPC endpoints used by trusted local daemon clients.
pub fn ipc_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/reputation/table",
            get(reputation_ipc::get_reputation_table),
        )
        .route(
            "/reputation/observe",
            post(reputation_ipc::observe_reputation),
        )
        .route("/reputation/reset", post(reputation_ipc::reset_reputation))
        .route("/reputation/save", post(reputation_ipc::save_reputation))
        .route("/proxy/evaluate", post(proxy_ipc::evaluate_proxy))
        .route("/proxy/status/full", get(proxy_ipc::proxy_status_full))
        .route("/ipc/audit/ingest", post(audit_ipc::ingest_audit))
        .route(
            "/ipc/audit/ingest-batch",
            post(audit_ipc::ingest_audit_batch),
        )
        .route(
            "/ipc/inventory/install",
            post(inventory_ipc::install_inventory),
        )
        .route("/ipc/digest/items", post(digest_ipc::enqueue_digest))
        .route("/ipc/digest/items/:id", get(digest_ipc::get_digest))
        .route(
            "/ipc/digest/items/:id/status",
            post(digest_ipc::update_digest),
        )
        .route("/ipc/digest/expire", post(digest_ipc::expire_digest))
        .route("/ipc/sessions", get(session_ipc::list_sessions))
        .route("/ipc/sessions", post(session_ipc::register_session))
        // work/74 Phase 1: reserve capacity BEFORE the target is spawned, so
        // a limit rejection can never arrive after the tool has run code.
        .route(
            "/ipc/session-reservations",
            post(session_ipc::reserve_session),
        )
        .route(
            "/ipc/session-reservations/:id/activate",
            post(session_ipc::activate_session),
        )
        .route(
            "/ipc/session-reservations/:id",
            delete(session_ipc::cancel_session_reservation),
        )
        .route("/ipc/sessions-prune", post(session_ipc::prune_sessions))
        .route("/ipc/sessions/:id", get(session_ipc::get_session))
        .route("/ipc/sessions/:id", put(session_ipc::update_session))
        .route("/ipc/sessions/:id", delete(session_ipc::unregister_session))
        .route("/ipc/sessions/:id/kill", post(session_ipc::kill_session))
        .route("/ipc/events", post(events::ingest_event))
        .route(
            "/ipc/dashboard/pair-code",
            post(dashboard_pair::mint_pair_code),
        )
}

/// Browser-facing dashboard mutations (POST/PUT/DELETE).
///
/// Every route here is driven by the dashboard SPA and must carry the
/// dashboard CSRF header (see [`crate::csrf`]). Routes with their own auth
/// proof — the webhook callback (nonce) and server shutdown (IPC bearer) —
/// live in [`protected_write_routes`] so the CSRF layer is never applied to
/// them.
///
/// Live-event *injection* is deliberately absent: the dashboard SPA only
/// *receives* events (over the WebSocket), it never posts them. Both machine
/// callers (the agent loop and the supervisor) ingest via the bearer-authed
/// `/ipc/events` route in [`ipc_routes`], so there is no open browser-facing
/// event-injection endpoint at all.
pub fn dashboard_write_routes() -> Router<AppState> {
    Router::new()
        .route("/digest/clear-all", post(digest::clear_all_digest))
        .route("/digest/:id/approve", post(digest::approve_digest))
        .route("/digest/:id/deny", post(digest::deny_digest))
        .route("/digest/:id/learn", post(digest::learn_digest))
        .route("/digest/:id/escalate", post(digest::escalate_digest))
        .route(
            "/digest/:id/unlock-egress",
            post(digest::unlock_egress_digest),
        )
        .route(
            "/digest/:id/deny-terminate",
            post(digest::deny_terminate_digest),
        )
        .route(
            "/digest/:id/allow-always",
            post(digest::allow_always_digest),
        )
        .route("/canaries", post(canary::add_canary))
        .route("/canaries/:id", delete(canary::remove_canary))
        .route("/canaries/:id/rotate", post(canary::rotate_canary))
        .route("/config", put(config::update_config))
        .route("/onboarding/dismiss", post(onboarding::dismiss_onboarding))
        .route("/onboarding/intro-seen", post(onboarding::mark_intro_seen))
        .route(
            "/notifications/test/:channel",
            post(notifications::test_notification),
        )
        .route("/policies", post(policies::create_policy))
        .route("/policies/:name", put(policies::update_policy))
        .route("/policies/:name", delete(policies::delete_policy))
        .route("/sync/apply", post(sync::apply_synced_configs))
}

/// Mutating routes that carry their own non-CSRF authentication and therefore
/// must **not** receive the dashboard CSRF layer:
///
/// - `/digest/:id/webhook-review` — external review callback, authenticated by
///   a single-use nonce embedded in the webhook URL.
/// - `/server/shutdown` — IPC bearer token via the `IpcAuth` extractor.
/// - `/dashboard/pair` — single-use pairing code in the body (the browser
///   bootstrap; must NOT require the dashboard token, which it hands out).
///
/// These share the write rate-limit bucket but are wired separately in
/// [`crate::GrithServer::build_router`].
pub fn protected_write_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/digest/:id/webhook-review",
            post(digest::webhook_review_digest),
        )
        .route("/server/shutdown", post(server::shutdown_server))
        .route("/dashboard/pair", post(dashboard_pair::redeem_pair_code))
}

/// Proxy dry-run endpoint (separate bucket).
pub fn proxy_test_routes() -> Router<AppState> {
    Router::new().route("/proxy/test", post(proxy::proxy_test))
}

// --- Router ---

/// Build the API router with all REST endpoints.
///
/// Composes the three sub-routers into a single router. Kept for backward
/// compatibility with existing tests that mount `api_router()` directly.
pub fn api_router() -> Router<AppState> {
    open_read_routes()
        .merge(sensitive_read_routes())
        .merge(dashboard_write_routes())
        .merge(protected_write_routes())
        .merge(proxy_test_routes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use grith_proxy::engine::SecurityProxy;
    use grith_proxy::filters::FilterRegistry;
    use grith_proxy::meta_rules::MetaRuleEngine;
    use grith_proxy::scoring::ScoringConfig;
    use grith_supervisor::config::SupervisorConfig;
    use grith_supervisor::supervisor::SupervisorRegistry;
    use std::sync::{Arc, Mutex};
    use tower::util::ServiceExt;

    pub(crate) fn make_state() -> AppState {
        let audit = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let digest = Arc::new(grith_digest::DigestQueue::open_in_memory().unwrap());
        let proxy = Arc::new(SecurityProxy::new(
            FilterRegistry::new(),
            ScoringConfig::default(),
            MetaRuleEngine::new(vec![]),
        ));
        let registry = Arc::new(Mutex::new(SupervisorRegistry::new(
            SupervisorConfig::default(),
        )));
        let containment = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::with_defaults(),
        );
        let correlation = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let canary_registry = Arc::new(grith_proxy::filters::canary::CanaryRegistry::empty());
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
        let (ws_tx, _) = tokio::sync::broadcast::channel(16);
        let supervisor_tasks = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        AppState {
            audit_storage: audit,
            digest_queue: digest,
            proxy,
            supervisor_registry: registry,
            supervisor_tasks,
            containment_tracker: containment,
            correlation_tracker: correlation,
            canary_registry,
            notification_dispatcher,
            start_time: std::time::Instant::now(),
            instance_id: None,
            protocol_version: None,
            version: "0.1.0-test".into(),
            ws_tx,
            shutdown_tx: None,
            plan_tier: "community".into(),
            config_dir: std::env::temp_dir().join(format!("grith-test-{}", uuid::Uuid::new_v4())),
            audit_db_path: std::env::temp_dir()
                .join(format!("grith-test-{}", uuid::Uuid::new_v4()))
                .join("audit.db"),
            account_id: "local:test".into(),
            auth_config: crate::auth::AuthConfig::default(),
            feature_gate: std::sync::Arc::new(std::sync::RwLock::new(
                grith_digest::notification::FeatureGate {
                    tier: grith_digest::notification::PlanTier::Community,
                    seats: 1,
                },
            )),
            license_valid_until: None,
            billing_portal_url: None,
            refresh_state: std::sync::Arc::new(std::sync::RwLock::new(
                grith_digest::notification::RefreshState::default(),
            )),
            dns_seed_domains: vec![],
            reputation_table: std::sync::Arc::new(std::sync::Mutex::new(
                grith_proxy::reputation::ReputationTable::new(),
            )),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            sync_api_key: None,
            sync_api_base_url: None,
            ipc_token: String::new(),
            dashboard_token: String::new(),
            dashboard_pair_code: std::sync::Arc::new(std::sync::Mutex::new(None)),
            session_limit_rejections: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn make_router() -> Router {
        let state = make_state();
        api_router().with_state(state)
    }

    #[tokio::test]
    async fn test_onboarding_status_and_dismiss() {
        // Share one state (and its temp config_dir) across both calls.
        let state = make_state();
        let router = api_router().with_state(state);

        // Fresh: no config file → onboarded false, community tier, not dismissed.
        let resp = router
            .clone()
            .oneshot(
                Request::get("/onboarding/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["onboarded"], false);
        assert_eq!(json["tier"], "community");
        assert_eq!(json["trial_active"], false);
        assert_eq!(json["dismissed"], false);
        assert_eq!(json["default_provider"], "ollama");

        // Dismiss the checklist card.
        let resp = router
            .clone()
            .oneshot(
                Request::post("/onboarding/dismiss")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Status now reports dismissed.
        let resp = router
            .oneshot(
                Request::get("/onboarding/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["dismissed"], true);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let router = make_router();
        let response = router
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "healthy");
        assert!(json["uptime_seconds"].is_number());
        // Subsystems should be objects with "status" field
        let subsystems = json["subsystems"].as_object().unwrap();
        assert_eq!(subsystems["audit"]["status"], "ok");
        assert_eq!(subsystems["proxy"]["status"], "ok");
    }

    #[tokio::test]
    async fn test_list_digest_empty() {
        let router = make_router();
        let response = router
            .oneshot(Request::get("/digest").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total"], 0);
        assert!(json["items"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_audit_empty() {
        let router = make_router();
        let response = router
            .oneshot(Request::get("/audit").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total"], 0);
    }

    /// `/audit/summary` must resolve as a static route, not be swallowed by
    /// `/audit/:id` and rejected as a malformed UUID.
    #[tokio::test]
    async fn audit_summary_defaults_to_the_seven_day_window() {
        let router = make_router();
        let response = router
            .oneshot(Request::get("/audit/summary").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["window"], "7d");
        assert!(
            json["since"].is_string(),
            "a bounded window must carry a cutoff"
        );
        assert_eq!(json["total"], 0);
        assert_eq!(json["allow"], 0);
        assert_eq!(json["queue"], 0);
        assert_eq!(json["deny"], 0);
    }

    /// Every offered window resolves, and only `all` drops the cutoff. An
    /// unknown value falls back to the default instead of 400ing a stale tab.
    #[tokio::test]
    async fn audit_summary_resolves_every_window() {
        for (query, expected, bounded) in [
            ("today", "today", true),
            ("7d", "7d", true),
            ("30d", "30d", true),
            ("all", "all", false),
            ("nonsense", "7d", true),
        ] {
            let response = make_router()
                .oneshot(
                    Request::get(format!("/audit/summary?window={query}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "window={query}");
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["window"], expected, "window={query}");
            assert_eq!(json["since"].is_string(), bounded, "window={query}");
        }
    }

    #[tokio::test]
    async fn test_proxy_status() {
        let router = make_router();
        let response = router
            .oneshot(Request::get("/proxy/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total_evaluations"], 0);
        assert_eq!(json["auto_allow_threshold"], 3.0);
        assert_eq!(json["auto_deny_threshold"], 8.0);
        assert!(json["filters"].is_array());
    }

    #[tokio::test]
    async fn test_get_audit_invalid_id() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::get("/audit/not-a-uuid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_export_audit_csv() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::get("/audit/export?format=csv")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.contains("csv"));
    }

    #[tokio::test]
    async fn test_approve_digest_invalid_id() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::post("/digest/not-a-uuid/approve")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_escalate_digest_invalid_id() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::post("/digest/not-a-uuid/escalate")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_tier_community() {
        let router = make_router();
        let response = router
            .oneshot(Request::get("/tier").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["tier"], "community");
        assert_eq!(json["seats"], 1);
        assert_eq!(json["max_sessions"], 2);
        assert_eq!(json["renewal_date"], serde_json::Value::Null);
        assert_eq!(json["billing_portal_url"], serde_json::Value::Null);
        // Community tier: core features enabled, pro features disabled
        assert_eq!(json["features"]["proxy"], true);
        assert_eq!(json["features"]["dashboard"], true);
        assert_eq!(json["features"]["notification_channels"], false);
        assert_eq!(json["features"]["policy_editor"], false);
    }

    #[tokio::test]
    async fn test_proxy_test_allow() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::post("/proxy/test")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "tool_call": {
                                "type": "FileRead",
                                "path": "/tmp/test.txt"
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["composite_score"].is_number());
        assert!(json["action"].is_string());
        assert!(json["filter_results"].is_array());
    }

    #[tokio::test]
    async fn test_proxy_test_invalid_tool_call() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::post("/proxy/test")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "tool_call": { "type": "NonExistentType" }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_proxy_test_legacy_tool_call_type_format() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::post("/proxy/test")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "tool_call": {
                                "tool_call_type": "fs.read",
                                "arguments": {
                                    "path": "/tmp/test.txt"
                                }
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["composite_score"].is_number());
        assert!(json["action"].is_string());
    }

    #[tokio::test]
    async fn test_get_config() {
        let router = make_router();
        let response = router
            .oneshot(Request::get("/config").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["config_scope"]["local"].is_string());
        assert!(json["config_scope"]["team"].is_string());
        assert!(json["proxy"]["auto_allow_threshold"].is_number());
        assert!(json["filters"].is_array());
    }

    #[tokio::test]
    async fn test_put_config_empty() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::put("/config")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "saved");
        assert_eq!(json["scope"], "local");
        assert_eq!(json["filters_updated"], 0);
        assert_eq!(json["proxy_updated"], false);
    }

    #[tokio::test]
    async fn test_put_config_persists_and_get_reflects_updates() {
        let state = make_state();
        let router = api_router().with_state(state);

        let put_response = router
            .clone()
            .oneshot(
                Request::put("/config")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "scope": "local",
                            "proxy": {
                                "auto_allow_threshold": 2.5,
                                "auto_deny_threshold": 7.5
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_response.status(), StatusCode::OK);

        let get_response = router
            .oneshot(Request::get("/config").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["proxy"]["auto_allow_threshold"], 2.5);
        assert_eq!(json["proxy"]["auto_deny_threshold"], 7.5);
    }

    // --- T8: Typed error status mapping tests ---

    fn enqueue_test_item(state: &AppState) -> Uuid {
        use grith_digest::types::{DigestItem, DigestStatus, ScoreSeverity};
        let item = DigestItem {
            id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            session_id: None,
            tool_call_type: "FileRead".into(),
            arguments_summary: "/etc/shadow".into(),
            decision_reason: None,
            composite_score: 5.0,
            severity: ScoreSeverity::Medium,
            filter_breakdown: vec![],
            task_context: None,
            plugin_id: "test".into(),
            status: DigestStatus::Pending,
            reviewed_at: None,
            review_action: None,
            reviewer_notes: None,
            informational_only: false,
            escalated_at: None,
            escalated_by: None,
        };
        let id = item.id;
        state.digest_queue.enqueue(&item).unwrap();
        id
    }

    #[tokio::test]
    async fn test_escalate_not_found_returns_404() {
        let state = make_state();
        let router = api_router().with_state(state);
        let fake_id = Uuid::new_v4();
        let response = router
            .oneshot(
                Request::post(format!("/digest/{fake_id}/escalate"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_escalate_invalid_action_returns_409() {
        let state = make_state();
        let router = api_router().with_state(state.clone());
        let id = enqueue_test_item(&state);
        // First approve the item
        state
            .digest_queue
            .update_status(
                &id,
                grith_digest::DigestStatus::Approved,
                Some("approve"),
                None,
            )
            .unwrap();

        // Now try to escalate it — should get 409 (InvalidAction)
        let response = router
            .oneshot(
                Request::post(format!("/digest/{id}/escalate"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_webhook_review_unknown_channel_returns_409() {
        // The test channel registry has no "webhook" channel registered, so
        // handle_callback returns ChannelNotFound which maps to 409 CONFLICT.
        let state = make_state();
        let router = api_router().with_state(state.clone());
        let id = enqueue_test_item(&state);
        let response = router
            .oneshot(
                Request::post(format!("/digest/{id}/webhook-review"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "action": "approve",
                            "nonce": "some-nonce"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    // --- Adaptive scoring endpoint tests ---

    /// Build an AppState with Pro tier.
    #[allow(dead_code)]
    fn make_pro_state_with_tier() -> AppState {
        let mut state = make_state();
        state.plan_tier = "pro".into();
        state.feature_gate = std::sync::Arc::new(std::sync::RwLock::new(
            grith_digest::notification::FeatureGate {
                tier: grith_digest::notification::PlanTier::Pro,
                seats: 1,
            },
        ));
        state
    }

    // --- Analytics endpoint tests ---

    fn make_pro_state() -> AppState {
        let mut state = make_state();
        state.plan_tier = "pro".into();
        state.feature_gate = std::sync::Arc::new(std::sync::RwLock::new(
            grith_digest::notification::FeatureGate {
                tier: grith_digest::notification::PlanTier::Pro,
                seats: 1,
            },
        ));
        state
    }

    fn make_enterprise_state() -> AppState {
        let mut state = make_state();
        state.plan_tier = "enterprise".into();
        state.feature_gate = std::sync::Arc::new(std::sync::RwLock::new(
            grith_digest::notification::FeatureGate {
                tier: grith_digest::notification::PlanTier::Enterprise,
                seats: 5,
            },
        ));
        state
    }

    // --- Session-limit (429) upsell + prune tests ---

    fn register_body(id: uuid::Uuid, tool: &str, pid: u32) -> Body {
        Body::from(
            serde_json::json!({
                "id": id.to_string(),
                "tool_name": tool,
                "root_pid": pid,
            })
            .to_string(),
        )
    }

    #[tokio::test]
    async fn test_update_unknown_session_adopts_on_heartbeat() {
        // Simulate a daemon that just restarted: the registry is empty, but a
        // supervised process is still running and sends its next heartbeat PUT.
        // The daemon should ADOPT (re-register) the session, not 404 it.
        let state = make_state();
        let router = ipc_routes().with_state(state.clone());
        let id = uuid::Uuid::new_v4();
        let live_pid = std::process::id();

        let resp = router
            .oneshot(
                Request::put(format!("/ipc/sessions/{id}"))
                    .header("content-type", "application/json")
                    .body(register_body(id, "claude", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let reg = state.supervisor_registry.lock().unwrap();
        assert_eq!(
            reg.count(),
            1,
            "unknown-id heartbeat should adopt the session"
        );
        assert!(reg.get(&id).is_some());
    }

    /// work/74 Phase 3: at capacity the daemon must say so. Answering 200
    /// told the client everything was fine while the daemon accounted for
    /// nothing — the session kept running untracked, outside the licensed
    /// cap and invisible to `grith exec list`.
    #[tokio::test]
    async fn test_unadoptable_heartbeat_returns_409_not_200() {
        let state = make_state();
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_max_sessions(1);
        }
        let router = ipc_routes().with_state(state.clone());
        let live_pid = std::process::id();

        // Fill the single slot with a live session that cannot be reaped.
        let resp = router
            .clone()
            .oneshot(
                Request::post("/ipc/sessions")
                    .header("content-type", "application/json")
                    .body(register_body(uuid::Uuid::new_v4(), "claude", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // An orphan heartbeats; there is no room to adopt it.
        let orphan = uuid::Uuid::new_v4();
        let resp = router
            .oneshot(
                Request::put(format!("/ipc/sessions/{orphan}"))
                    .header("content-type", "application/json")
                    .body(register_body(orphan, "codex", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "session_not_tracked");
        assert_eq!(json["reason"], "capacity");
        assert!(json["message"]
            .as_str()
            .unwrap()
            .contains(&orphan.to_string()));

        // And the registry did not quietly grow past its cap.
        assert_eq!(state.supervisor_registry.lock().unwrap().count(), 1);
    }

    /// With room, adoption still succeeds — the 409 is specifically the
    /// at-capacity case, not a general refusal to adopt orphans.
    #[tokio::test]
    async fn test_adoptable_heartbeat_still_returns_200() {
        let state = make_state();
        let router = ipc_routes().with_state(state.clone());
        let orphan = uuid::Uuid::new_v4();

        let resp = router
            .oneshot(
                Request::put(format!("/ipc/sessions/{orphan}"))
                    .header("content-type", "application/json")
                    .body(register_body(orphan, "claude", std::process::id()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(state
            .supervisor_registry
            .lock()
            .unwrap()
            .get(&orphan)
            .is_some());
    }

    #[tokio::test]
    async fn test_session_register_limit_returns_structured_429() {
        let state = make_state();
        // Force a one-session cap and use our own (live) PID so the reaper
        // can't reclaim the slot.
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_max_sessions(1);
        }
        let router = ipc_routes().with_state(state.clone());
        let live_pid = std::process::id();

        let resp1 = router
            .clone()
            .oneshot(
                Request::post("/ipc/sessions")
                    .header("content-type", "application/json")
                    .body(register_body(uuid::Uuid::new_v4(), "claude", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::CREATED);

        let resp2 = router
            .oneshot(
                Request::post("/ipc/sessions")
                    .header("content-type", "application/json")
                    .body(register_body(uuid::Uuid::new_v4(), "codex", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

        let bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "session_limit_reached");
        assert_eq!(json["tier"], "community");
        assert_eq!(json["current_limit"], 1);
        assert_eq!(json["active_sessions"], 1);
        assert!(json["upgrade_url"].is_string());
        assert!(json["message"].as_str().unwrap().contains("Community"));
        assert!(json["remediation"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "upgrade"));
    }

    #[tokio::test]
    async fn test_session_register_limit_text_plain_fallback() {
        let state = make_state();
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_max_sessions(1);
        }
        let router = ipc_routes().with_state(state.clone());
        let live_pid = std::process::id();

        let _ = router
            .clone()
            .oneshot(
                Request::post("/ipc/sessions")
                    .header("content-type", "application/json")
                    .body(register_body(uuid::Uuid::new_v4(), "claude", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = router
            .oneshot(
                Request::post("/ipc/sessions")
                    .header("content-type", "application/json")
                    .header("accept", "text/plain")
                    .body(register_body(uuid::Uuid::new_v4(), "codex", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        // Plain-text body is the human message, not JSON.
        assert!(!text.trim_start().starts_with('{'));
        assert!(text.contains("session"));
    }

    #[tokio::test]
    async fn test_enterprise_429_has_no_upgrade_url() {
        let state = make_enterprise_state();
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_max_sessions(1);
        }
        let router = ipc_routes().with_state(state.clone());
        let live_pid = std::process::id();
        let _ = router
            .clone()
            .oneshot(
                Request::post("/ipc/sessions")
                    .header("content-type", "application/json")
                    .body(register_body(uuid::Uuid::new_v4(), "claude", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();
        let resp = router
            .oneshot(
                Request::post("/ipc/sessions")
                    .header("content-type", "application/json")
                    .body(register_body(uuid::Uuid::new_v4(), "codex", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["tier"], "enterprise");
        assert!(json["upgrade_url"].is_null());
        assert!(!json["remediation"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "upgrade"));
    }

    // Pro is a paid tier, so — like Enterprise — hitting its (generous) session
    // cap offers no upgrade nudge: no upgrade would raise it, and the only
    // remedy is to close a session.
    #[tokio::test]
    async fn test_pro_429_has_no_upgrade_url() {
        let state = make_pro_state();
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_max_sessions(1);
        }
        let router = ipc_routes().with_state(state.clone());
        let live_pid = std::process::id();
        let _ = router
            .clone()
            .oneshot(
                Request::post("/ipc/sessions")
                    .header("content-type", "application/json")
                    .body(register_body(uuid::Uuid::new_v4(), "claude", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();
        let resp = router
            .oneshot(
                Request::post("/ipc/sessions")
                    .header("content-type", "application/json")
                    .body(register_body(uuid::Uuid::new_v4(), "codex", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["tier"], "pro");
        assert!(json["upgrade_url"].is_null());
        assert!(!json["remediation"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "upgrade"));
    }

    #[tokio::test]
    async fn test_prune_sessions_endpoint() {
        let state = make_state();
        let router = ipc_routes().with_state(state.clone());
        let live_pid = std::process::id();
        let _ = router
            .clone()
            .oneshot(
                Request::post("/ipc/sessions")
                    .header("content-type", "application/json")
                    .body(register_body(uuid::Uuid::new_v4(), "claude", live_pid))
                    .unwrap(),
            )
            .await
            .unwrap();
        let resp = router
            .oneshot(
                Request::post("/ipc/sessions-prune")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // Live PID can't be reaped, so nothing is pruned and the session remains.
        assert_eq!(json["reaped"], 0);
        assert_eq!(json["remaining"], 1);
    }

    // -- work/74 Phase 1: pre-spawn capacity reservations ------------------

    fn reserve_body(tool: &str) -> Body {
        Body::from(
            serde_json::json!({ "tool_name": tool, "profile_name": "claude-code" }).to_string(),
        )
    }

    async fn reserve(router: &axum::Router, tool: &str) -> axum::response::Response {
        router
            .clone()
            .oneshot(
                Request::post("/ipc/session-reservations")
                    .header("content-type", "application/json")
                    .body(reserve_body(tool))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// The whole point of B12 item 1: at capacity the refusal arrives from the
    /// reservation call, i.e. before the CLI has spawned anything.
    #[tokio::test]
    async fn test_reservation_refuses_at_capacity_before_any_session_exists() {
        let state = make_state();
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_max_sessions(1);
        }
        let router = ipc_routes().with_state(state.clone());

        let first = reserve(&router, "claude").await;
        assert_eq!(first.status(), StatusCode::CREATED);
        {
            let reg = state.supervisor_registry.lock().unwrap();
            assert_eq!(reg.count(), 0, "no session registered yet");
            assert_eq!(reg.reservation_count(), 1, "but the seat is held");
        }

        let second = reserve(&router, "codex").await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        let bytes = axum::body::to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "session_limit_reached");
        assert_eq!(json["current_limit"], 1);
    }

    #[tokio::test]
    async fn test_reservation_activate_registers_the_session() {
        let state = make_state();
        let router = ipc_routes().with_state(state.clone());
        let live_pid = std::process::id();

        let resp = reserve(&router, "claude").await;
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let reservation_id = json["reservation_id"].as_str().unwrap().to_string();
        assert!(json["expires_in_seconds"].as_u64().unwrap() > 0);

        let session_id = uuid::Uuid::new_v4();
        let activate = router
            .clone()
            .oneshot(
                Request::post(format!(
                    "/ipc/session-reservations/{reservation_id}/activate"
                ))
                .header("content-type", "application/json")
                .body(register_body(session_id, "claude", live_pid))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(activate.status(), StatusCode::CREATED);

        let reg = state.supervisor_registry.lock().unwrap();
        assert_eq!(reg.count(), 1);
        assert_eq!(reg.reservation_count(), 0, "lease consumed by activation");
        assert!(reg.get(&session_id).is_some());
    }

    /// A retried activation (lost response) must not consume a second seat.
    #[tokio::test]
    async fn test_reservation_activate_is_idempotent() {
        let state = make_state();
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_max_sessions(1);
        }
        let router = ipc_routes().with_state(state.clone());
        let live_pid = std::process::id();

        let resp = reserve(&router, "claude").await;
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let reservation_id = json["reservation_id"].as_str().unwrap().to_string();
        let session_id = uuid::Uuid::new_v4();

        for _ in 0..2 {
            let activate = router
                .clone()
                .oneshot(
                    Request::post(format!(
                        "/ipc/session-reservations/{reservation_id}/activate"
                    ))
                    .header("content-type", "application/json")
                    .body(register_body(session_id, "claude", live_pid))
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(activate.status(), StatusCode::CREATED);
        }

        let reg = state.supervisor_registry.lock().unwrap();
        assert_eq!(reg.count(), 1, "retry must not create a second session");
    }

    #[tokio::test]
    async fn test_reservation_cancel_releases_the_seat() {
        let state = make_state();
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_max_sessions(1);
        }
        let router = ipc_routes().with_state(state.clone());

        let resp = reserve(&router, "claude").await;
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let reservation_id = json["reservation_id"].as_str().unwrap().to_string();

        let cancel = router
            .clone()
            .oneshot(
                Request::delete(format!("/ipc/session-reservations/{reservation_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cancel.status(), StatusCode::NO_CONTENT);

        // The seat is immediately reusable.
        assert_eq!(
            reserve(&router, "codex").await.status(),
            StatusCode::CREATED
        );
    }

    /// Cancelling an unknown lease is a no-op success, not a 404 — the
    /// caller's intent (stop holding this seat) is satisfied either way.
    #[tokio::test]
    async fn test_cancel_unknown_reservation_is_a_noop_success() {
        let state = make_state();
        let router = ipc_routes().with_state(state);
        let resp = router
            .oneshot(
                Request::delete(format!(
                    "/ipc/session-reservations/{}",
                    uuid::Uuid::new_v4()
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    /// A quarantined audit chain must refuse the reservation with the
    /// quarantine envelope, not a bogus "upgrade for more sessions" prompt.
    #[tokio::test]
    async fn test_reservation_refused_while_audit_quarantined() {
        let state = make_state();
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_audit_quarantine(Some("chain broken at seq 42".into()));
        }
        let router = ipc_routes().with_state(state);

        let resp = reserve(&router, "claude").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "audit_chain_quarantined");
        assert_eq!(json["remediation"], "grith audit diagnose");
    }

    /// A daemon whose audit database is read-only (another process owns the
    /// writer lock) must refuse the reservation with the read-only envelope —
    /// not a bogus capacity 429, and not a mislabelled quarantine.
    #[tokio::test]
    async fn test_reservation_refused_while_audit_read_only() {
        let state = make_state();
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_audit_read_only(Some("another process owns the audit database".into()));
        }
        let router = ipc_routes().with_state(state);

        let resp = reserve(&router, "claude").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "audit_read_only");
        assert_eq!(json["remediation"], "grith daemon restart");
    }

    /// The legacy register path must refuse with the same envelope.
    #[tokio::test]
    async fn test_register_refused_while_audit_read_only() {
        let state = make_state();
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_audit_read_only(Some("another process owns the audit database".into()));
        }
        let router = ipc_routes().with_state(state);

        let resp = router
            .oneshot(
                Request::post("/ipc/sessions")
                    .header("content-type", "application/json")
                    .body(register_body(uuid::Uuid::new_v4(), "claude", 4242))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "audit_read_only");
        assert_eq!(json["remediation"], "grith daemon restart");
    }

    /// An ingest against a read-only audit handle must return the structured
    /// read-only 503, not a raw SQLITE_READONLY 500 the client cannot
    /// distinguish from a transient failure.
    #[tokio::test]
    async fn test_ingest_refused_while_audit_read_only() {
        let state = make_state();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        // An owner creates the database; the server then holds it read-only,
        // exactly as a daemon that lost the writer-lock race would.
        drop(grith_audit::AuditStorage::open(&db).unwrap());
        *state.audit_storage.lock().unwrap() =
            grith_audit::AuditStorage::open_read_only(&db).unwrap();
        let router = ipc_routes().with_state(state);

        let record = grith_audit::AuditRecord::new(
            uuid::Uuid::new_v4(),
            "test".into(),
            "FileRead(/tmp/x)".into(),
            &serde_json::json!({}),
            0.0,
            grith_audit::ProxyActionSummary::Allow,
            Vec::new(),
            0.0,
            None,
        );
        let resp = router
            .oneshot(
                Request::post("/ipc/audit/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "record": record }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "audit_read_only");
    }

    /// Ten racing reservations against a cap of two yield exactly two seats.
    #[tokio::test]
    async fn test_concurrent_reservations_respect_the_cap() {
        let state = make_state();
        {
            let mut reg = state.supervisor_registry.lock().unwrap();
            reg.set_max_sessions(2);
        }
        let router = ipc_routes().with_state(state.clone());

        let mut granted = 0;
        let mut refused = 0;
        for _ in 0..10 {
            match reserve(&router, "claude").await.status() {
                StatusCode::CREATED => granted += 1,
                StatusCode::TOO_MANY_REQUESTS => refused += 1,
                other => panic!("unexpected status {other}"),
            }
        }
        assert_eq!(granted, 2, "cap must hold across repeated reservations");
        assert_eq!(refused, 8);
    }

    // --- C-01: Feature gate enforcement tests ---

    #[tokio::test]
    async fn test_feature_gate_response_includes_upgrade_metadata() {
        let router = make_router(); // Community tier
        let response = router
            .oneshot(
                Request::get("/analytics/v2/pro")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "FEATURE_GATED");
        assert_eq!(json["current_tier"], "community");
        assert_eq!(json["required_tier"], "Pro");
        assert_eq!(json["feature"], "usage_analytics");
        assert!(json["upgrade_url"].is_string());
    }

    #[tokio::test]
    async fn test_notifications_channels_community_forbidden() {
        let router = make_router(); // Community tier
        let response = router
            .oneshot(
                Request::get("/notifications/channels")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "FEATURE_GATED");
        assert_eq!(json["feature"], "notification_channels");
    }

    #[tokio::test]
    async fn test_notifications_status_community_forbidden() {
        let router = make_router(); // Community tier
        let response = router
            .oneshot(
                Request::get("/notifications/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_notifications_test_community_forbidden() {
        let router = make_router(); // Community tier
        let response = router
            .oneshot(
                Request::post("/notifications/test/slack")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_notifications_channels_pro_ok() {
        let state = make_pro_state();
        let router = api_router().with_state(state);
        let response = router
            .oneshot(
                Request::get("/notifications/channels")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["total"].is_number());
        assert!(json["channels"].is_array());
    }

    #[tokio::test]
    async fn test_notifications_status_pro_ok() {
        let state = make_pro_state();
        let router = api_router().with_state(state);
        let response = router
            .oneshot(
                Request::get("/notifications/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // --- C-02: Sync endpoint tests ---

    #[tokio::test]
    async fn test_sync_status_community_forbidden() {
        let router = make_router(); // Community tier
        let response = router
            .oneshot(Request::get("/sync/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "FEATURE_GATED");
        assert_eq!(json["feature"], "cloud_sync");
    }

    #[tokio::test]
    async fn test_sync_status_pro_ok() {
        let state = make_pro_state();
        let router = api_router().with_state(state);
        let response = router
            .oneshot(Request::get("/sync/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["policies_count"].is_number());
        assert!(json["configs_count"].is_number());
        assert!(json["provider_keys_count"].is_number());
    }

    #[tokio::test]
    async fn test_sync_configs_community_forbidden() {
        let router = make_router();
        let response = router
            .oneshot(Request::get("/sync/configs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_sync_configs_pro_ok() {
        let state = make_pro_state();
        let router = api_router().with_state(state);
        let response = router
            .oneshot(Request::get("/sync/configs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total"], 0); // no synced configs in test tmpdir
        assert!(json["configs"].is_array());
    }

    #[tokio::test]
    async fn test_sync_apply_community_forbidden() {
        let router = make_router();
        let response = router
            .oneshot(Request::post("/sync/apply").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_sync_apply_pro_empty() {
        let state = make_pro_state();
        let router = api_router().with_state(state);
        let response = router
            .oneshot(Request::post("/sync/apply").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["configs_applied"], 0);
    }

    #[tokio::test]
    async fn test_sync_apply_merges_json_to_team_config() {
        let state = make_pro_state();
        // Write a synced config JSON file into the test config_dir/configs/
        let configs_dir = state.config_dir.join("configs");
        std::fs::create_dir_all(&configs_dir).unwrap();
        std::fs::write(
            configs_dir.join("team-thresholds.json"),
            serde_json::json!({
                "proxy": {
                    "auto_allow_threshold": 2.5,
                    "auto_deny_threshold": 7.0
                }
            })
            .to_string(),
        )
        .unwrap();

        let router = api_router().with_state(state.clone());
        let response = router
            .oneshot(Request::post("/sync/apply").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "applied");
        assert_eq!(json["configs_applied"], 1);

        // Verify team-config.toml was written with the merged content
        let team_config =
            std::fs::read_to_string(state.config_dir.join("team-config.toml")).unwrap();
        let parsed: toml::Value = toml::from_str(&team_config).unwrap();
        let allow = parsed["proxy"]["auto_allow_threshold"].as_float().unwrap();
        let deny = parsed["proxy"]["auto_deny_threshold"].as_float().unwrap();
        assert!((allow - 2.5).abs() < f64::EPSILON);
        assert!((deny - 7.0).abs() < f64::EPSILON);
    }
}
