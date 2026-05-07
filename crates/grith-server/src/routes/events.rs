// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Event ingestion endpoint for the CLI agent loop.

use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

/// Maximum body size for event ingestion (64 KiB).
const MAX_EVENT_SIZE: usize = 64 * 1024;

/// Receive forwarded proxy evaluation events from CLI agent processes.
/// This enables the dashboard to show live data even though the server
/// runs as a separate process from the CLI.
pub(crate) async fn ingest_event(
    State(state): State<AppState>,
    Json(event): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Validate: event must be a JSON object with a "type" field.
    let obj = match event.as_object() {
        Some(o) => o,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "event must be a JSON object", "code": "INVALID_EVENT"})),
            )
                .into_response();
        }
    };
    if !obj.contains_key("type") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "event must contain a 'type' field", "code": "MISSING_TYPE"})),
        )
            .into_response();
    }

    // Reject overly large payloads.
    let serialized = event.to_string();
    if serialized.len() > MAX_EVENT_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "event payload too large", "code": "PAYLOAD_TOO_LARGE"})),
        )
            .into_response();
    }

    // Forward the event to connected WebSocket clients.
    let _ = state.ws_tx.send(serialized);
    StatusCode::ACCEPTED.into_response()
}
