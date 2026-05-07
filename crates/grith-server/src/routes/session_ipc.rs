// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! IPC session registry routes for thin supervisor clients.

use crate::ipc_auth::IpcAuth;
use crate::routes::parse_uuid_or_400;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use grith_supervisor::process_tree::ProcessTree;
use grith_supervisor::supervisor::{SessionStats, SessionSummary, SupervisorSession};
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct SessionSnapshotRequest {
    pub id: String,
    pub tool_name: String,
    pub profile_name: Option<String>,
    pub policy_scope: Option<String>,
    pub launcher_overlay_name: Option<String>,
    pub provider_overlay_name: Option<String>,
    pub root_pid: u32,
    pub project_name: Option<String>,
    #[serde(default)]
    pub process_tree_pids: Vec<u32>,
    #[serde(default)]
    pub stats: SessionStats,
}

fn restore_process_tree(tool_name: &str, root_pid: u32, pids: &[u32]) -> ProcessTree {
    let mut tree = ProcessTree::new(root_pid, tool_name);
    for pid in pids.iter().copied().filter(|pid| *pid != root_pid) {
        let _ = tree.add_child(root_pid, pid, format!("pid-{pid}"));
    }
    tree
}

fn apply_snapshot(
    session: &mut SupervisorSession,
    body: &SessionSnapshotRequest,
    preserve_started_at: bool,
) {
    let started_at = session.started_at;
    let mut updated = SupervisorSession::new(body.tool_name.clone(), body.root_pid);
    updated.id = session.id;
    updated.profile_name = body.profile_name.clone();
    updated.policy_scope = body.policy_scope.clone();
    updated.launcher_overlay_name = body.launcher_overlay_name.clone();
    updated.provider_overlay_name = body.provider_overlay_name.clone();
    updated.project_name = body.project_name.clone();
    updated.stats = body.stats.clone();
    updated.process_tree =
        restore_process_tree(&body.tool_name, body.root_pid, &body.process_tree_pids);
    if preserve_started_at {
        updated.started_at = started_at;
    }
    // Refresh heartbeat — proves the thin client is still alive.
    updated.last_synced_at = std::time::Instant::now();
    *session = updated;
}

pub(crate) async fn register_session(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(body): Json<SessionSnapshotRequest>,
) -> impl IntoResponse {
    let id = match parse_uuid_or_400(&body.id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let mut session = SupervisorSession::new(body.tool_name.clone(), body.root_pid);
    session.id = id;
    session.profile_name = body.profile_name.clone();
    session.policy_scope = body.policy_scope.clone();
    session.launcher_overlay_name = body.launcher_overlay_name.clone();
    session.provider_overlay_name = body.provider_overlay_name.clone();
    session.project_name = body.project_name.clone();
    session.stats = body.stats.clone();
    session.process_tree =
        restore_process_tree(&body.tool_name, body.root_pid, &body.process_tree_pids);

    match state.supervisor_registry.lock() {
        Ok(mut registry) => match registry.register(session) {
            Ok(()) => {
                tracing::info!(session_id = %id, tool = %body.tool_name, pid = body.root_pid, "IPC session registered");
                StatusCode::CREATED.into_response()
            }
            Err(e) => {
                tracing::warn!(session_id = %id, error = %e, "IPC session register failed");
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("session register failed: {e}"),
                )
                    .into_response()
            }
        },
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "supervisor registry lock poisoned",
        )
            .into_response(),
    }
}

pub(crate) async fn update_session(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<SessionSnapshotRequest>,
) -> impl IntoResponse {
    let id = match parse_uuid_or_400(&id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if body.id != id.to_string() {
        return (StatusCode::BAD_REQUEST, "path ID does not match body ID").into_response();
    }
    match state.supervisor_registry.lock() {
        Ok(mut registry) => match registry.get_mut(&id) {
            Some(session) => {
                apply_snapshot(session, &body, true);
                StatusCode::OK.into_response()
            }
            None => (StatusCode::NOT_FOUND, "session not found").into_response(),
        },
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "supervisor registry lock poisoned",
        )
            .into_response(),
    }
}

pub(crate) async fn unregister_session(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let id = match parse_uuid_or_400(&id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match state.supervisor_registry.lock() {
        Ok(mut registry) => match registry.remove(&id) {
            Some(_) => StatusCode::NO_CONTENT.into_response(),
            None => (StatusCode::NOT_FOUND, "session not found").into_response(),
        },
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "supervisor registry lock poisoned",
        )
            .into_response(),
    }
}

pub(crate) async fn list_sessions(
    _auth: IpcAuth,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.supervisor_registry.lock() {
        Ok(registry) => {
            let mut sessions: Vec<SessionSummary> = registry.list();
            for summary in &mut sessions {
                summary.containment_remaining_seconds =
                    state.containment_tracker.remaining_seconds(summary.id);
            }
            Json(serde_json::json!({
                "sessions": sessions,
                "total": registry.count(),
            }))
            .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "supervisor registry lock poisoned",
        )
            .into_response(),
    }
}

pub(crate) async fn get_session(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let id = match parse_uuid_or_400(&id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match state.supervisor_registry.lock() {
        Ok(registry) => match registry.get(&id) {
            Some(session) => Json(serde_json::json!({
                "id": session.id,
                "tool_name": session.tool_name,
                "root_pid": session.root_pid,
                "uptime_seconds": session.uptime().as_secs(),
                "process_tree_pids": session.process_tree.all_pids(),
                "stats": session.stats,
                "containment_remaining_seconds": state.containment_tracker.remaining_seconds(session.id),
            }))
            .into_response(),
            None => (StatusCode::NOT_FOUND, "session not found").into_response(),
        },
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "supervisor registry lock poisoned",
        )
            .into_response(),
    }
}

pub(crate) async fn kill_session(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    crate::supervisor::terminate_session_by_id(state, &id).await
}
