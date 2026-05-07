// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Reputation IPC endpoints for daemon-client communication.
//!
//! These endpoints allow `grith exec` clients to interact with the
//! daemon-owned reputation table via HTTP, ensuring all sessions share
//! a single reputation table without file contention.

use crate::ipc_auth::IpcAuth;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

// --- GET /api/reputation/table ---

#[derive(Serialize)]
struct ReputationTableResponse {
    entries: usize,
    table_json: String,
}

/// Return the full reputation table as serialized TOML.
/// Used by `grith reputation show` when connecting to a running daemon.
pub(crate) async fn get_reputation_table(
    _auth: IpcAuth,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let table = state.reputation_table.lock();
    match table {
        Ok(t) => {
            let json = serde_json::to_string(&*t).unwrap_or_default();
            Json(ReputationTableResponse {
                entries: t.len(),
                table_json: json,
            })
            .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "reputation table lock poisoned",
        )
            .into_response(),
    }
}

// --- POST /api/reputation/observe ---

#[derive(Deserialize)]
pub(crate) struct ObserveRequest {
    pub keys: Vec<(u8, String)>,
    pub outcome: String, // "approved:1.0", "denied:3.0", etc.
}

/// Record a reputation observation from a client session.
pub(crate) async fn observe_reputation(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(body): Json<ObserveRequest>,
) -> impl IntoResponse {
    let outcome = parse_outcome(&body.outcome);
    let Some(outcome) = outcome else {
        return (StatusCode::BAD_REQUEST, "invalid outcome format").into_response();
    };

    match state.reputation_table.lock() {
        Ok(mut table) => {
            table.observe(&body.keys, outcome, &state.reputation_config);
            (StatusCode::OK, "observed").into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "reputation table lock poisoned",
        )
            .into_response(),
    }
}

// --- POST /api/reputation/reset ---

#[derive(Deserialize)]
pub(crate) struct ResetRequest {
    pub profile: Option<String>,
}

/// Reset reputation data, optionally filtered by profile.
pub(crate) async fn reset_reputation(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(body): Json<ResetRequest>,
) -> impl IntoResponse {
    match state.reputation_table.lock() {
        Ok(mut table) => {
            if let Some(ref profile) = body.profile {
                let before = table.len();
                table
                    .entries
                    .retain(|key, _| !key.starts_with(&format!("{profile}|")));
                let removed = before - table.len();
                Json(serde_json::json!({ "reset": removed })).into_response()
            } else {
                table.reset();
                Json(serde_json::json!({ "reset": "all" })).into_response()
            }
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "reputation table lock poisoned",
        )
            .into_response(),
    }
}

// --- POST /api/reputation/save ---

/// Force-save the reputation table to disk.
pub(crate) async fn save_reputation(
    _auth: IpcAuth,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let path = grith_proxy::reputation::default_reputation_path();
    match state.reputation_table.lock() {
        Ok(table) => match table.save(&path) {
            Ok(()) => Json(serde_json::json!({
                "saved": true,
                "entries": table.len(),
                "path": path.to_string_lossy(),
            }))
            .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("save failed: {e}"),
            )
                .into_response(),
        },
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "reputation table lock poisoned",
        )
            .into_response(),
    }
}

fn parse_outcome(s: &str) -> Option<grith_proxy::reputation::ReputationOutcome> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    let weight: f64 = parts[1].parse().ok()?;
    match parts[0] {
        "approved" => Some(grith_proxy::reputation::ReputationOutcome::Approved(weight)),
        "denied" => Some(grith_proxy::reputation::ReputationOutcome::Denied(weight)),
        _ => None,
    }
}
