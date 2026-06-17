// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! PR 4 Phase G: session-pinned binary inventory API.
//!
//! Exposes the immutable snapshot of trusted binaries that was built
//! at session start (Phase C) so the dashboard's "Binaries trusted
//! this session" view can render the list, flag truncation, and
//! diff against future sessions.
//!
//! Source of truth is the in-memory `SessionStateRegistry`. Cross-
//! session diff persistence (work-doc Open Question 2) is deferred —
//! when an audit-DB-backed history lands it can replace the previous-
//! session field here.

use crate::routes::parse_uuid_or_400;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use grith_proxy::session_state::SessionStateRegistry;
use grith_proxy::types::SessionScopeKey;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct InventoryEntryDto {
    /// Canonical absolute path of the pinned binary.
    path: String,
    /// Hex-encoded SHA-256 of the binary contents at session start.
    sha256: String,
}

#[derive(Serialize)]
pub(crate) struct InventoryResponse {
    /// Session UUID that owns this inventory.
    session_id: String,
    /// Number of binaries currently in the inventory.
    binaries_pinned: usize,
    /// Total files walked while building the inventory (includes
    /// non-executable entries that were skipped). May exceed
    /// `binaries_pinned` because non-executable + unsafe-ancestor +
    /// hash-failure entries don't get pinned but still count against
    /// the file cap.
    total_scanned: usize,
    /// `true` when the walk hit `INVENTORY_MAX_FILES` (5000) and
    /// stopped short. The frontend should surface this so operators
    /// know to tighten their `routine_exec_roots`.
    truncated: bool,
    /// Inventory entries sorted by `path` for deterministic UI order.
    entries: Vec<InventoryEntryDto>,
    /// Previous-session inventory diff. Currently always `None`
    /// because cross-session persistence is deferred (work-doc Open
    /// Question 2). A later PR can populate this with `added` /
    /// `removed` / `hash_changed` lists once last-N inventories
    /// land in the audit DB.
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_session_diff: Option<serde_json::Value>,
}

/// `GET /inventory/:session_id` — return the session-pinned binary
/// inventory. Returns 404 if the session has no `SessionState` entry
/// (either it never started or it has already been evicted).
pub(crate) async fn get_inventory(
    State(_state): State<AppState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let session_id = match parse_uuid_or_400(&session_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let scope = SessionScopeKey::from_session_id(session_id);
    let Some(state) = SessionStateRegistry::global().get(scope) else {
        return crate::routes::api_error(
            StatusCode::NOT_FOUND,
            "session not found",
            "SESSION_NOT_FOUND",
        )
        .into_response();
    };
    let Some(inventory) = state.pinned_inventory() else {
        // Session exists but inventory hasn't been installed yet.
        // Return 200 with an empty inventory so the UI shows
        // "no binaries trusted yet" instead of erroring.
        let response = InventoryResponse {
            session_id: session_id.to_string(),
            binaries_pinned: 0,
            total_scanned: 0,
            truncated: false,
            entries: Vec::new(),
            previous_session_diff: None,
        };
        return (StatusCode::OK, Json(response)).into_response();
    };

    let mut entries: Vec<InventoryEntryDto> = inventory
        .iter()
        .map(|(path, sha)| InventoryEntryDto {
            path: path.to_string(),
            sha256: sha.to_string(),
        })
        .collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let response = InventoryResponse {
        session_id: session_id.to_string(),
        binaries_pinned: inventory.len(),
        total_scanned: inventory.total_scanned,
        truncated: inventory.truncated,
        entries,
        previous_session_diff: None,
    };
    (StatusCode::OK, Json(response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::api_router;
    use axum::body::Body;
    use axum::http::Request;
    use grith_proxy::session_state::SessionPinnedInventory;
    use tower::util::ServiceExt;
    use uuid::Uuid;

    fn install_inventory(session_id: Uuid, entries: Vec<(String, String)>) {
        let scope = SessionScopeKey::from_session_id(session_id);
        let state = SessionStateRegistry::global().get_or_create(scope);
        let mut inv = SessionPinnedInventory::from_entries(entries);
        inv.total_scanned = inv.len();
        state.set_pinned_inventory(inv);
    }

    #[tokio::test]
    async fn get_inventory_invalid_uuid_returns_400() {
        let state = crate::routes::tests::make_state();
        let router = api_router().with_state(state);
        let response = router
            .oneshot(
                Request::get("/inventory/not-a-uuid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_inventory_unknown_session_returns_404() {
        let state = crate::routes::tests::make_state();
        let router = api_router().with_state(state);
        // A UUID that has no SessionState entry.
        let unknown = Uuid::new_v4();
        let response = router
            .oneshot(
                Request::get(format!("/inventory/{unknown}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_inventory_returns_pinned_entries_sorted() {
        let state = crate::routes::tests::make_state();
        let router = api_router().with_state(state);
        let session_id = Uuid::new_v4();
        install_inventory(
            session_id,
            vec![
                ("/usr/bin/zsh".to_string(), "11".repeat(32)),
                ("/usr/bin/aaa".to_string(), "22".repeat(32)),
            ],
        );
        let response = router
            .oneshot(
                Request::get(format!("/inventory/{session_id}"))
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
        assert_eq!(json["binaries_pinned"], 2);
        assert_eq!(json["truncated"], false);
        let entries = json["entries"].as_array().unwrap();
        // Entries must be sorted by path for deterministic UI order.
        assert_eq!(entries[0]["path"], "/usr/bin/aaa");
        assert_eq!(entries[1]["path"], "/usr/bin/zsh");
    }

    #[tokio::test]
    async fn get_inventory_empty_session_state_returns_empty_list() {
        let state = crate::routes::tests::make_state();
        let router = api_router().with_state(state);
        // Create a SessionState without installing an inventory.
        let session_id = Uuid::new_v4();
        let scope = SessionScopeKey::from_session_id(session_id);
        let _ = SessionStateRegistry::global().get_or_create(scope);

        let response = router
            .oneshot(
                Request::get(format!("/inventory/{session_id}"))
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
        assert_eq!(json["binaries_pinned"], 0);
        assert!(json["entries"].as_array().unwrap().is_empty());
    }
}
