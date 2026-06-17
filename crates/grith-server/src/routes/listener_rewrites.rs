// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! PR 5 Phase E: listener-rewrite audit query API.
//!
//! Exposes the audit records produced by the supervisor's wildcard
//! → loopback clamp (Phase D). The dashboard's "Listener rewrites"
//! tab consumes this to render the original/rewritten address pairs
//! and the profile entry that authorised each rewrite.
//!
//! Source of truth is the `audit_log` table — every clamp emits a
//! row with non-null `original_addr`, `rewritten_addr`, and
//! `clamp_profile_entry`. We filter on `original_addr IS NOT NULL`
//! since the supervisor only sets all three together.

use crate::routes::parse_uuid_or_400;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct ListenerRewriteDto {
    /// Audit record UUID — primary key for cross-referencing the
    /// full record.
    id: String,
    /// RFC3339 timestamp of the bind decision.
    timestamp: String,
    /// PID of the tracee that issued the bind.
    pid: Option<u32>,
    /// Tool name (e.g. "codex") from the supervisor session.
    tool: Option<String>,
    /// Original address:port the tracee passed to `bind(2)`.
    original_addr: String,
    /// Address:port the kernel actually saw after the clamp.
    rewritten_addr: String,
    /// `LocalListenerEntry.desc` of the profile entry that
    /// authorised the rewrite.
    clamp_profile_entry: String,
}

#[derive(Serialize)]
pub(crate) struct ListenerRewritesResponse {
    /// Session UUID (echoed back for the UI).
    session_id: String,
    /// Number of rewrites returned in `rewrites`.
    total: usize,
    /// Rewrites for this session, most recent first.
    rewrites: Vec<ListenerRewriteDto>,
}

/// `GET /sessions/:session_id/listener-rewrites` — list every
/// wildcard → loopback clamp the supervisor performed during this
/// session. Returns 400 INVALID_ID for non-UUID input; 200 with an
/// empty list when the session has no clamp events (the common
/// case).
pub(crate) async fn get_listener_rewrites(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let session_uuid = match parse_uuid_or_400(&session_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // Pull all records for this session and filter the ones with a
    // recorded rewrite. The supervisor only writes original_addr
    // when all three fields are populated (see
    // `build_audit_record`'s Phase E branch).
    let storage = match state.audit_storage.lock() {
        Ok(g) => g,
        Err(_) => {
            return crate::routes::api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "audit storage lock poisoned",
                "STORAGE_ERROR",
            )
            .into_response();
        }
    };
    let records = match storage.get_by_session(&session_uuid) {
        Ok(records) => records,
        Err(e) => {
            return crate::routes::api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("query failed: {e}"),
                "STORAGE_ERROR",
            )
            .into_response();
        }
    };

    let mut rewrites: Vec<ListenerRewriteDto> = records
        .iter()
        .filter(|r| r.original_addr.is_some())
        .map(|r| ListenerRewriteDto {
            id: r.id.to_string(),
            timestamp: r.timestamp.to_rfc3339(),
            pid: r.supervised_pid,
            tool: r.supervised_tool.clone(),
            original_addr: r.original_addr.clone().unwrap_or_default(),
            rewritten_addr: r.rewritten_addr.clone().unwrap_or_default(),
            clamp_profile_entry: r.clamp_profile_entry.clone().unwrap_or_default(),
        })
        .collect();
    // Most recent first.
    rewrites.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    let total = rewrites.len();
    let body = ListenerRewritesResponse {
        session_id: session_uuid.to_string(),
        total,
        rewrites,
    };
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::api_router;
    use axum::body::Body;
    use axum::http::Request;
    use grith_audit::types::{AuditRecord, ProxyActionSummary};
    use tower::util::ServiceExt;
    use uuid::Uuid;

    fn make_record_with_rewrite(session_id: Uuid) -> AuditRecord {
        let mut r = AuditRecord::new(
            session_id,
            "supervisor:codex".into(),
            "NetListen".into(),
            &serde_json::json!({"port": 41234}),
            0.5,
            ProxyActionSummary::Allow,
            vec![],
            0.42,
            None,
        );
        r = r.with_listener_rewrite("0.0.0.0:41234", "127.0.0.1:41234", "MCP local server");
        r
    }

    #[tokio::test]
    async fn get_rewrites_invalid_uuid_returns_400() {
        let state = crate::routes::tests::make_state();
        let router = api_router().with_state(state);
        let response = router
            .oneshot(
                Request::get("/sessions/not-a-uuid/listener-rewrites")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_rewrites_unknown_session_returns_empty_list() {
        let state = crate::routes::tests::make_state();
        let router = api_router().with_state(state);
        let session_id = Uuid::new_v4();
        let response = router
            .oneshot(
                Request::get(format!("/sessions/{session_id}/listener-rewrites"))
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
        assert_eq!(json["total"], 0);
        assert!(json["rewrites"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_rewrites_returns_rows_for_session() {
        let state = crate::routes::tests::make_state();
        let session_id = Uuid::new_v4();
        let record = make_record_with_rewrite(session_id);
        {
            let storage = state.audit_storage.lock().unwrap();
            storage.insert_record(&record).unwrap();
        }
        let router = api_router().with_state(state);
        let response = router
            .oneshot(
                Request::get(format!("/sessions/{session_id}/listener-rewrites"))
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
        assert_eq!(json["total"], 1);
        let rewrite = &json["rewrites"][0];
        assert_eq!(rewrite["original_addr"], "0.0.0.0:41234");
        assert_eq!(rewrite["rewritten_addr"], "127.0.0.1:41234");
        assert_eq!(rewrite["clamp_profile_entry"], "MCP local server");
    }

    #[tokio::test]
    async fn get_rewrites_excludes_non_clamp_records() {
        let state = crate::routes::tests::make_state();
        let session_id = Uuid::new_v4();
        // Plain audit record without a rewrite.
        let plain = AuditRecord::new(
            session_id,
            "supervisor:codex".into(),
            "FileRead".into(),
            &serde_json::json!({"path": "/etc/hostname"}),
            0.0,
            ProxyActionSummary::Allow,
            vec![],
            0.1,
            None,
        );
        let clamp = make_record_with_rewrite(session_id);
        {
            let storage = state.audit_storage.lock().unwrap();
            storage.insert_record(&plain).unwrap();
            storage.insert_record(&clamp).unwrap();
        }
        let router = api_router().with_state(state);
        let response = router
            .oneshot(
                Request::get(format!("/sessions/{session_id}/listener-rewrites"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Only the clamp record should appear — the FileRead doesn't
        // have original_addr set.
        assert_eq!(json["total"], 1);
    }
}
