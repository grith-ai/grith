// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! IPC endpoint for the supervisor (in the `grith exec` process) to push
//! its session-pinned binary inventory into the daemon's own
//! `SessionStateRegistry::global()`. Without this push the dashboard's
//! `/api/inventory` returns 404 for every session, because both
//! processes have their own per-process registries.

use crate::ipc_auth::IpcAuth;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use grith_proxy::session_state::{SessionPinnedInventory, SessionStateRegistry};
use grith_proxy::types::SessionScopeKey;
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct InventoryEntryPayload {
    pub path: String,
    pub sha256: String,
}

#[derive(Deserialize)]
pub(crate) struct InstallInventoryRequest {
    /// Serialised `SessionScopeKey` (UUID string).
    pub scope: SessionScopeKey,
    pub entries: Vec<InventoryEntryPayload>,
    pub total_scanned: usize,
    pub truncated: bool,
}

/// POST /api/ipc/inventory/install
pub(crate) async fn install_inventory(
    _auth: IpcAuth,
    State(_state): State<AppState>,
    Json(body): Json<InstallInventoryRequest>,
) -> impl IntoResponse {
    let scope = body.scope;
    let mut inventory =
        SessionPinnedInventory::from_entries(body.entries.into_iter().map(|e| (e.path, e.sha256)));
    inventory.total_scanned = body.total_scanned;
    inventory.truncated = body.truncated;

    let pinned = inventory.len();
    let total_scanned = inventory.total_scanned;
    let truncated = inventory.truncated;

    let state = SessionStateRegistry::global().get_or_create(scope);
    state.set_pinned_inventory(inventory);

    tracing::info!(
        event = "ipc_inventory_installed",
        scope = %scope,
        binaries_pinned = pinned,
        total_scanned,
        truncated,
        "inventory installed via IPC push from exec process"
    );

    StatusCode::CREATED.into_response()
}
