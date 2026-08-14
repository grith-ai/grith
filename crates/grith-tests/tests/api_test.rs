// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! API integration tests for grith-server routes.
//!
//! These tests build an Axum Router using `routes::api_router()` and exercise
//! every REST endpoint with realistic, pre-populated data using
//! `tower::util::ServiceExt::oneshot`.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use grith_audit::{AuditRecord, AuditStorage, FilterResultSummary, ProxyActionSummary};
use grith_digest::types::{FilterBreakdown, ScoreSeverity};
use grith_digest::{DigestItem, DigestQueue, DigestStatus};
use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::canary::CanaryToken;
use grith_proxy::meta_rules::MetaRuleEngine;
use grith_proxy::scoring::ScoringConfig;
use grith_server::routes::api_router;
use grith_server::AppState;
use tokio::sync::broadcast;
use tower::util::ServiceExt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create an AppState with empty in-memory databases.
fn make_state() -> AppState {
    let audit = Arc::new(Mutex::new(
        AuditStorage::open_in_memory().expect("audit storage"),
    ));
    let digest = Arc::new(DigestQueue::open_in_memory().expect("digest queue"));
    let proxy = Arc::new(SecurityProxy::new(
        grith_tests::TestFixtures::default_filter_registry(),
        ScoringConfig::default(),
        MetaRuleEngine::new(vec![]),
    ));
    let supervisor_registry = Arc::new(Mutex::new(
        grith_supervisor::supervisor::SupervisorRegistry::new(
            grith_supervisor::config::SupervisorConfig::default(),
        ),
    ));
    let containment =
        Arc::new(grith_proxy::filters::session_containment::ContainmentTracker::with_defaults());
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
    let supervisor_tasks = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let (ws_tx, _) = broadcast::channel(16);
    AppState {
        audit_storage: audit,
        digest_queue: digest,
        proxy,
        supervisor_registry,
        supervisor_tasks,
        containment_tracker: containment,
        correlation_tracker: correlation,
        canary_registry,
        notification_dispatcher,
        start_time: std::time::Instant::now(),
        version: "0.1.0-test".into(),
        ws_tx,
        shutdown_tx: None,
        plan_tier: "community".into(),
        config_dir: std::env::temp_dir().join(format!("grith-test-{}", Uuid::new_v4())),
        audit_db_path: std::env::temp_dir()
            .join(format!("grith-test-{}", Uuid::new_v4()))
            .join("audit.db"),
        account_id: "local:test".into(),
        auth_config: grith_server::auth::AuthConfig::default(),
        feature_gate: Arc::new(std::sync::RwLock::new(
            grith_digest::notification::FeatureGate {
                tier: grith_digest::notification::PlanTier::Community,
                seats: 1,
            },
        )),
        license_valid_until: None,
        billing_portal_url: None,
        refresh_state: Arc::new(std::sync::RwLock::new(
            grith_digest::notification::RefreshState::default(),
        )),
        dns_seed_domains: vec![],
        reputation_table: Arc::new(std::sync::Mutex::new(
            grith_proxy::reputation::ReputationTable::new(),
        )),
        sync_api_key: None,
        sync_api_base_url: None,
        ipc_token: String::new(),
        dashboard_token: String::new(),
        dashboard_pair_code: std::sync::Arc::new(std::sync::Mutex::new(None)),
        session_limit_rejections: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        reputation_config: grith_proxy::reputation::ReputationConfig::default(),
        instance_id: None,
        protocol_version: None,
    }
}

/// Build a test router from the api_router with the given state.
fn make_router_with_state(state: AppState) -> Router {
    api_router().with_state(state)
}

/// Build a test router with empty state.
fn make_router() -> Router {
    make_router_with_state(make_state())
}

/// Create a test DigestItem with the given score.
fn make_digest_item(score: f64) -> DigestItem {
    DigestItem {
        id: Uuid::new_v4(),
        created_at: chrono::Utc::now(),
        session_id: None,
        tool_call_type: "ShellExec".into(),
        arguments_summary: "ls -la /home/user".into(),
        decision_reason: None,
        composite_score: score,
        severity: ScoreSeverity::from_score(score),
        filter_breakdown: vec![FilterBreakdown {
            filter_name: "command".into(),
            score,
            rule_id: "test-rule".into(),
            message: "test match".into(),
        }],
        task_context: Some("integration test".into()),
        plugin_id: "shell".into(),
        status: DigestStatus::Pending,
        reviewed_at: None,
        review_action: None,
        reviewer_notes: None,
        informational_only: false,
        escalated_at: None,
        escalated_by: None,
    }
}

/// Create a test AuditRecord with the given session_id and score.
fn make_audit_record(session_id: Uuid, score: f64) -> AuditRecord {
    AuditRecord::new(
        session_id,
        "file-ops".into(),
        "FileRead".into(),
        &serde_json::json!({"path": "/tmp/test.txt"}),
        score,
        ProxyActionSummary::Allow,
        vec![FilterResultSummary {
            filter_name: "path-match".into(),
            matched: false,
            score: 0.0,
            rule_id: String::new(),
            severity: "notice".into(),
            message: String::new(),
        }],
        1.2,
        Some("integration test".into()),
    )
}

/// Helper to read the response body as bytes and parse as JSON.
async fn body_json(response: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("parse JSON")
}

/// Helper to read the response body as a string.
async fn body_string(response: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8(bytes.to_vec()).expect("valid UTF-8")
}

// ===========================================================================
// Health endpoint
// ===========================================================================

#[tokio::test]
async fn health_returns_200_with_expected_fields() {
    let router = make_router();
    let response = router
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["status"], "healthy");
    assert_eq!(json["version"], "0.1.0-test");
    assert!(json["uptime_seconds"].is_number());
    assert_eq!(json["subsystems"]["proxy"]["status"], "ok");
    assert_eq!(json["subsystems"]["audit"]["status"], "ok");
    assert_eq!(json["subsystems"]["digest"]["status"], "ok");
}

// ===========================================================================
// Digest endpoints
// ===========================================================================

#[tokio::test]
async fn digest_list_returns_populated_items() {
    let state = make_state();

    // Pre-populate the digest queue with 3 items.
    state.digest_queue.enqueue(&make_digest_item(5.0)).unwrap();
    state.digest_queue.enqueue(&make_digest_item(7.5)).unwrap();
    state.digest_queue.enqueue(&make_digest_item(3.0)).unwrap();

    let router = make_router_with_state(state);
    let response = router
        .oneshot(Request::get("/digest").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["total"], 3);
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    // Items should be ordered by score descending (highest first).
    let first_score = items[0]["composite_score"].as_f64().unwrap();
    let last_score = items[2]["composite_score"].as_f64().unwrap();
    assert!(first_score >= last_score);
}

#[tokio::test]
async fn digest_list_respects_limit_parameter() {
    let state = make_state();

    state.digest_queue.enqueue(&make_digest_item(5.0)).unwrap();
    state.digest_queue.enqueue(&make_digest_item(7.5)).unwrap();
    state.digest_queue.enqueue(&make_digest_item(3.0)).unwrap();

    let router = make_router_with_state(state);
    let response = router
        .oneshot(Request::get("/digest?limit=1").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(json["limit"], 1);
}

#[tokio::test]
async fn digest_approve_updates_item_status() {
    let state = make_state();
    let item = make_digest_item(5.0);
    let item_id = item.id;

    state.digest_queue.enqueue(&item).unwrap();

    let router = make_router_with_state(state.clone());
    let response = router
        .oneshot(
            Request::post(format!("/digest/{item_id}/approve"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"notes": "looks safe"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["status"], "approved");
    assert_eq!(json["id"], item_id.to_string());

    // Verify the item was actually updated in the queue.
    let updated = state.digest_queue.get_by_id(&item_id).unwrap();
    assert_eq!(updated.status, DigestStatus::Approved);
}

#[tokio::test]
async fn digest_deny_updates_item_status() {
    let state = make_state();
    let item = make_digest_item(6.0);
    let item_id = item.id;

    state.digest_queue.enqueue(&item).unwrap();

    let router = make_router_with_state(state.clone());
    let response = router
        .oneshot(
            Request::post(format!("/digest/{item_id}/deny"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"notes": "too risky"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["status"], "denied");
    assert_eq!(json["id"], item_id.to_string());

    // Verify in database.
    let updated = state.digest_queue.get_by_id(&item_id).unwrap();
    assert_eq!(updated.status, DigestStatus::Denied);
}

#[tokio::test]
async fn digest_approve_with_invalid_uuid_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::post("/digest/not-a-valid-uuid/approve")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn digest_approve_with_nonexistent_uuid_returns_404() {
    let router = make_router();
    let fake_id = Uuid::new_v4();
    let response = router
        .oneshot(
            Request::post(format!("/digest/{fake_id}/approve"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let json = body_json(response).await;
    assert_eq!(json["code"], "NOT_FOUND");
}

// ===========================================================================
// Audit endpoints
// ===========================================================================

#[tokio::test]
async fn audit_list_returns_records_with_total_count() {
    let state = make_state();
    let session = Uuid::new_v4();

    {
        let storage = state.audit_storage.lock().unwrap();
        storage
            .insert_record(&make_audit_record(session, 1.5))
            .unwrap();
        storage
            .insert_record(&make_audit_record(session, 2.0))
            .unwrap();
        storage
            .insert_record(&make_audit_record(Uuid::new_v4(), 0.5))
            .unwrap();
    }

    let router = make_router_with_state(state);
    let response = router
        .oneshot(Request::get("/audit").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["total"], 3);
    let records = json["records"].as_array().unwrap();
    assert_eq!(records.len(), 3);
}

#[tokio::test]
async fn audit_list_filters_by_session_id() {
    let state = make_state();
    let session = Uuid::new_v4();
    let other_session = Uuid::new_v4();

    {
        let storage = state.audit_storage.lock().unwrap();
        storage
            .insert_record(&make_audit_record(session, 1.5))
            .unwrap();
        storage
            .insert_record(&make_audit_record(session, 2.0))
            .unwrap();
        storage
            .insert_record(&make_audit_record(other_session, 0.5))
            .unwrap();
    }

    let router = make_router_with_state(state);
    let response = router
        .oneshot(
            Request::get(format!("/audit?session_id={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["total"], 2);
    let records = json["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    // All returned records should belong to the requested session.
    for record in records {
        assert_eq!(record["session_id"], session.to_string());
    }
}

#[tokio::test]
async fn audit_get_by_id_returns_single_record() {
    let state = make_state();
    let session = Uuid::new_v4();
    let record = make_audit_record(session, 1.5);
    let record_id = record.id;

    {
        let storage = state.audit_storage.lock().unwrap();
        storage.insert_record(&record).unwrap();
    }

    let router = make_router_with_state(state);
    let response = router
        .oneshot(
            Request::get(format!("/audit/{record_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["id"], record_id.to_string());
    assert_eq!(json["plugin_id"], "file-ops");
    assert_eq!(json["composite_score"], 1.5);
}

#[tokio::test]
async fn audit_get_by_id_with_invalid_uuid_returns_400() {
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

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn audit_export_returns_json_by_default() {
    let state = make_state();
    let session = Uuid::new_v4();

    {
        let storage = state.audit_storage.lock().unwrap();
        storage
            .insert_record(&make_audit_record(session, 1.5))
            .unwrap();
        storage
            .insert_record(&make_audit_record(session, 2.0))
            .unwrap();
    }

    let router = make_router_with_state(state);
    let response = router
        .oneshot(Request::get("/audit/export").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["count"], 2);
    let records = json["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
}

#[tokio::test]
async fn audit_export_csv_returns_correct_content_type() {
    let state = make_state();
    let session = Uuid::new_v4();

    {
        let storage = state.audit_storage.lock().unwrap();
        storage
            .insert_record(&make_audit_record(session, 1.5))
            .unwrap();
        storage
            .insert_record(&make_audit_record(session, 3.0))
            .unwrap();
    }

    let router = make_router_with_state(state);
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
    assert!(content_type.contains("text/csv"));

    let csv = body_string(response).await;
    // Verify the CSV header row.
    assert!(csv.starts_with(
        "id,timestamp,session_id,plugin_id,tool_call_type,composite_score,proxy_action,filter_scores,"
    ));
    assert!(csv.contains("filter_scores"));
    // We inserted 2 records so there should be 3 lines (header + 2 data rows).
    let line_count = csv.lines().count();
    assert_eq!(
        line_count, 3,
        "Expected header + 2 data rows, got {line_count}"
    );
    // Verify data rows contain expected content.
    assert!(csv.contains("file-ops"));
    assert!(csv.contains("FileRead"));
    assert!(csv.contains("allow"));
    assert!(csv.contains("path-match"));
}

// ===========================================================================
// Digest error paths
// ===========================================================================

#[tokio::test]
async fn digest_deny_with_invalid_uuid_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::post("/digest/not-a-valid-uuid/deny")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn digest_deny_with_nonexistent_uuid_returns_404() {
    let router = make_router();
    let fake_id = Uuid::new_v4();
    let response = router
        .oneshot(
            Request::post(format!("/digest/{fake_id}/deny"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let json = body_json(response).await;
    assert_eq!(json["code"], "NOT_FOUND");
}

#[tokio::test]
async fn digest_learn_with_invalid_uuid_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::post("/digest/xyz-abc/learn")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn digest_learn_with_nonexistent_uuid_returns_404() {
    let router = make_router();
    let fake_id = Uuid::new_v4();
    let response = router
        .oneshot(
            Request::post(format!("/digest/{fake_id}/learn"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn digest_escalate_with_invalid_uuid_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::post("/digest/12345/escalate")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn digest_escalate_with_nonexistent_uuid_returns_error() {
    let router = make_router();
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

    // Escalate returns NOT_FOUND for nonexistent items.
    assert!(
        response.status() == StatusCode::NOT_FOUND || response.status() == StatusCode::CONFLICT,
        "Expected 404 or 409, got {}",
        response.status()
    );
}

#[tokio::test]
async fn digest_unlock_egress_with_invalid_uuid_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::post("/digest/garbage/unlock-egress")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn digest_deny_terminate_with_invalid_uuid_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::post("/digest/!!invalid!!/deny-terminate")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn digest_allow_always_with_invalid_uuid_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::post("/digest/not-uuid/allow-always")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn digest_approve_with_various_malformed_uuids_returns_400() {
    let malformed_ids = vec![
        "",                                      // empty
        "not-a-uuid",                            // plaintext
        "12345",                                 // short numeric
        "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",  // right format, invalid hex
        "00000000-0000-0000-0000-00000000000",   // too short by 1 char
        "00000000-0000-0000-0000-0000000000000", // too long by 1 char
    ];

    for bad_id in malformed_ids {
        let router = make_router();
        let response = router
            .oneshot(
                Request::post(format!("/digest/{bad_id}/approve"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Expected 400 for malformed UUID: '{bad_id}'"
        );
    }
}

// ===========================================================================
// Audit error paths
// ===========================================================================

#[tokio::test]
async fn audit_list_with_invalid_session_id_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::get("/audit?session_id=not-a-uuid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn audit_get_by_id_with_nonexistent_uuid_returns_404() {
    let router = make_router();
    let fake_id = Uuid::new_v4();
    let response = router
        .oneshot(
            Request::get(format!("/audit/{fake_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let json = body_json(response).await;
    assert_eq!(json["code"], "NOT_FOUND");
}

#[tokio::test]
async fn audit_get_by_id_with_various_malformed_uuids_returns_400() {
    let malformed_ids = vec![
        "not-a-uuid",
        "12345",
        "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
    ];

    for bad_id in malformed_ids {
        let router = make_router();
        let response = router
            .oneshot(
                Request::get(format!("/audit/{bad_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Expected 400 for malformed UUID: '{bad_id}'"
        );
    }
}

#[tokio::test]
async fn audit_export_with_unknown_format_falls_back_to_json() {
    let state = make_state();
    let session = Uuid::new_v4();

    {
        let storage = state.audit_storage.lock().unwrap();
        storage
            .insert_record(&make_audit_record(session, 1.5))
            .unwrap();
    }

    let router = make_router_with_state(state);
    let response = router
        .oneshot(
            Request::get("/audit/export?format=xml")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Unknown format falls back to JSON (the default branch in the match).
    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert!(json["count"].is_number());
    assert!(json["records"].is_array());
}

// ===========================================================================
// Canary endpoints
// ===========================================================================

#[tokio::test]
async fn canary_list_redacts_token_values() {
    let state = make_state();
    let canary_id = Uuid::new_v4();
    state.canary_registry.add(CanaryToken {
        id: canary_id,
        label: "trap-db-password".into(),
        value: "ABCD-SECRET-VALUE".into(),
    });

    let router = make_router_with_state(state);
    let response = router
        .oneshot(Request::get("/canaries").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    let item = &json["items"][0];
    assert_eq!(item["id"], canary_id.to_string());
    assert_eq!(item["label"], "trap-db-password");
    assert_eq!(item["value_prefix"], "ABCD...");
    assert!(item.get("value").is_none());
}

#[tokio::test]
async fn canary_add_returns_only_value_prefix() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::post("/canaries")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"label": "trap-api-key", "value": "WXYZ-SECRET-VALUE"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let json = body_json(response).await;
    assert_eq!(json["label"], "trap-api-key");
    assert_eq!(json["value_prefix"], "WXYZ...");
    assert!(json["value"].is_null());
}

#[tokio::test]
async fn canary_rotate_returns_only_value_prefix() {
    let state = make_state();
    let canary_id = Uuid::new_v4();
    state.canary_registry.add(CanaryToken {
        id: canary_id,
        label: "trap-rotate".into(),
        value: "ABCD-OLD-VALUE".into(),
    });

    let router = make_router_with_state(state);
    let response = router
        .oneshot(
            Request::post(format!("/canaries/{canary_id}/rotate"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value": "ZZZZ-NEW-VALUE"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["label"], "trap-rotate");
    assert_eq!(json["value_prefix"], "ZZZZ...");
    assert!(json["value"].is_null());
}

#[tokio::test]
async fn canary_remove_with_invalid_uuid_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::delete("/canaries/bad-uuid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn canary_remove_with_nonexistent_uuid_returns_404() {
    let router = make_router();
    let fake_id = Uuid::new_v4();
    let response = router
        .oneshot(
            Request::delete(format!("/canaries/{fake_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let json = body_json(response).await;
    assert_eq!(json["code"], "NOT_FOUND");
}

#[tokio::test]
async fn canary_rotate_with_invalid_uuid_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::post("/canaries/bad-uuid/rotate")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"generate": true}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn canary_rotate_with_nonexistent_uuid_returns_404() {
    let router = make_router();
    let fake_id = Uuid::new_v4();
    let response = router
        .oneshot(
            Request::post(format!("/canaries/{fake_id}/rotate"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"generate": true}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let json = body_json(response).await;
    assert_eq!(json["code"], "NOT_FOUND");
}

#[tokio::test]
async fn canary_add_with_empty_label_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::post("/canaries")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"label": "", "generate": true}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_LABEL");
}

// ===========================================================================
// Webhook review error paths
// ===========================================================================

#[tokio::test]
async fn webhook_review_with_invalid_uuid_returns_400() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::post("/digest/bad-uuid/webhook-review")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"action": "approve", "nonce": "test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ID");
}

#[tokio::test]
async fn webhook_review_with_invalid_action_returns_400() {
    let router = make_router();
    let valid_id = Uuid::new_v4();
    let response = router
        .oneshot(
            Request::post(format!("/digest/{valid_id}/webhook-review"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"action": "unknown_action", "nonce": "test"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let json = body_json(response).await;
    assert_eq!(json["code"], "INVALID_ACTION");
}

// ===========================================================================
// Proxy endpoint
// ===========================================================================

#[tokio::test]
async fn proxy_status_returns_active_with_filter_count() {
    let router = make_router();
    let response = router
        .oneshot(Request::get("/proxy/status").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["total_evaluations"], 0);
    assert_eq!(json["auto_allow_threshold"], 3.0);
    assert_eq!(json["auto_deny_threshold"], 8.0);
    // The default filter registry from TestFixtures has 6 filters.
    assert_eq!(json["filters"].as_array().unwrap().len(), 6);
}

// ===========================================================================
// Config endpoint — path stripping
// ===========================================================================

#[tokio::test]
async fn config_get_does_not_expose_filesystem_paths() {
    let router = make_router();
    let response = router
        .oneshot(Request::get("/config").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_string(response).await;
    // The response must not contain any absolute filesystem paths.
    assert!(
        !body.contains("/home/"),
        "response leaks /home/ path: {body}"
    );
    assert!(!body.contains("/tmp/"), "response leaks /tmp/ path: {body}");
    assert!(
        !body.contains(".config/grith"),
        "response leaks config dir path: {body}"
    );
    assert!(
        !body.contains("config.toml"),
        "response leaks config filename: {body}"
    );

    // Verify the response uses scope labels instead of paths.
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["config_scope"]["local"], "local");
    assert_eq!(json["config_scope"]["team"], "team");
}

#[tokio::test]
async fn config_parse_error_does_not_expose_filesystem_paths() {
    let state = make_state();
    let config_dir = &state.config_dir;

    // Create a malformed config file that will trigger a parse error.
    std::fs::create_dir_all(config_dir).unwrap();
    std::fs::write(config_dir.join("config.toml"), "{{{{invalid toml!").unwrap();

    let router = make_router_with_state(state);
    let response = router
        .oneshot(Request::get("/config").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = body_string(response).await;
    // Error response must not contain any absolute filesystem paths.
    assert!(
        !body.contains("/home/"),
        "error response leaks /home/ path: {body}"
    );
    assert!(
        !body.contains("/tmp/"),
        "error response leaks /tmp/ path: {body}"
    );
    assert!(
        !body.contains("config.toml"),
        "error response leaks config filename: {body}"
    );

    // Verify it uses a generic error message.
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["code"], "CONFIG_LOAD_ERROR");
    assert!(
        json["error"].as_str().unwrap().contains("Failed to parse"),
        "expected generic error message, got: {}",
        json["error"]
    );
}

#[tokio::test]
async fn config_update_response_does_not_expose_filesystem_paths() {
    let state = make_state();

    // Ensure the config dir exists so the write succeeds.
    std::fs::create_dir_all(&state.config_dir).unwrap();

    let router = make_router_with_state(state);
    let response = router
        .oneshot(
            Request::put("/config")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"scope": "local", "filters": [], "proxy": {"auto_allow_threshold": 2.5, "auto_deny_threshold": 8.5}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_string(response).await;
    assert!(
        !body.contains("/home/"),
        "update response leaks /home/ path: {body}"
    );
    assert!(
        !body.contains("/tmp/"),
        "update response leaks /tmp/ path: {body}"
    );
    assert!(
        !body.contains("config.toml"),
        "update response leaks config filename: {body}"
    );
}
