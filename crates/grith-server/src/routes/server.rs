// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Server lifecycle endpoints (shutdown).

use crate::ipc_auth::IpcAuth;
use crate::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

/// Gracefully shut down the dashboard server.
pub(crate) async fn shutdown_server(
    _auth: IpcAuth,
    State(state): State<AppState>,
) -> impl IntoResponse {
    tracing::info!("shutdown requested via API");
    // Broadcast the shutdown event to connected dashboard clients.
    let _ = state.ws_tx.send(
        serde_json::json!({
            "type": "server_shutdown",
            "message": "Dashboard server is shutting down"
        })
        .to_string(),
    );

    // Use the shutdown sender if available.
    if let Some(ref tx) = state.shutdown_tx {
        let _ = tx.send(());
    }

    Json(serde_json::json!({
        "status": "shutting_down",
        "message": "Dashboard server is shutting down"
    }))
}
