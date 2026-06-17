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
    pub cwd: Option<String>,
    #[serde(default)]
    pub tty: Option<String>,
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
    updated.cwd = body.cwd.clone();
    updated.tty = body.tty.clone();
    updated.stats = body.stats.clone();
    updated.process_tree =
        restore_process_tree(&body.tool_name, body.root_pid, &body.process_tree_pids);
    if preserve_started_at {
        updated.started_at = started_at;
    }
    // Carry idle age forward across the rebuild: bump it only when the proxy
    // evaluated a real (non-noise) call since the last snapshot, otherwise
    // preserve the prior timestamp. Noise-only pushes must not reset idle.
    updated.last_activity_at = if body.stats.proxy_evals() > session.stats.proxy_evals() {
        std::time::Instant::now()
    } else {
        session.last_activity_at
    };
    // Refresh heartbeat — proves the thin client is still alive.
    updated.last_synced_at = std::time::Instant::now();
    *session = updated;
}

/// Build the structured `429 Too Many Requests` response for a session-limit
/// rejection. Carries the tier, current limit, active count, remediation
/// options, and an upgrade URL so the CLI/dashboard can render an upgrade
/// prompt instead of a bare error. Never echoes license keys or seat IDs.
///
/// Honours an explicit `Accept: text/plain` request (curl/scripts) with the
/// human message only.
fn session_limit_rejection_response(
    headers: &axum::http::HeaderMap,
    tier: grith_digest::notification::PlanTier,
    limit: usize,
    active: usize,
    billing_portal_url: Option<&str>,
) -> axum::response::Response {
    use grith_digest::notification::PlanTier;

    let is_top_tier = tier == PlanTier::Enterprise;
    let upgrade_url = if is_top_tier {
        None
    } else {
        Some(
            billing_portal_url
                .map(str::to_string)
                .unwrap_or_else(|| "https://grith.ai/billing?ref=429".to_string()),
        )
    };
    let remediation: Vec<&str> = if is_top_tier {
        vec!["close_session"]
    } else {
        vec!["close_session", "upgrade"]
    };
    let message = match tier {
        PlanTier::Community => format!(
            "You're using {active} of {limit} concurrent sessions on the Community plan. \
             Upgrade to Pro for more, or close a session with `grith exec kill <id>`."
        ),
        PlanTier::Pro => format!(
            "You're using {active} of {limit} concurrent sessions on Pro. \
             Add seats or close a session with `grith exec kill <id>`."
        ),
        PlanTier::Enterprise => format!(
            "You're using {active} of {limit} concurrent sessions on Enterprise. \
             Add seats or close a session with `grith exec kill <id>`."
        ),
    };

    // Honour an explicit text/plain preference; default to the JSON envelope.
    let wants_plain = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/plain") && !a.contains("application/json") && !a.contains("*/*"))
        .unwrap_or(false);
    if wants_plain {
        return (StatusCode::TOO_MANY_REQUESTS, message).into_response();
    }

    let body = serde_json::json!({
        "error": "session_limit_reached",
        "tier": tier.to_string(),
        "current_limit": limit,
        "active_sessions": active,
        "remediation": remediation,
        "upgrade_url": upgrade_url,
        "message": message,
    });
    (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response()
}

pub(crate) async fn register_session(
    _auth: IpcAuth,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
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
    session.cwd = body.cwd.clone();
    session.tty = body.tty.clone();
    session.stats = body.stats.clone();
    session.process_tree =
        restore_process_tree(&body.tool_name, body.root_pid, &body.process_tree_pids);

    let mut registry = match state.supervisor_registry.lock() {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "supervisor registry lock poisoned",
            )
                .into_response()
        }
    };

    // If we're at capacity, try to reclaim slots held by genuinely-dead
    // sessions before refusing. Defeats the "two crashed ghosts block a real
    // session" class and keeps the 429 honest. Cheap: only runs at the cap.
    if registry.count() >= registry.max_sessions() {
        let reaped = registry.reap_dead();
        if reaped > 0 {
            tracing::info!(
                event = "session_register_reclaimed_slot",
                reaped,
                session_id = %id,
                "reaped dead sessions before register"
            );
        }
    }

    let limit = registry.max_sessions();
    match registry.register(session) {
        Ok(()) => {
            drop(registry);
            tracing::info!(session_id = %id, tool = %body.tool_name, pid = body.root_pid, "IPC session registered");
            StatusCode::CREATED.into_response()
        }
        Err(e) => {
            let active = registry.count();
            drop(registry);
            let tier = state
                .feature_gate
                .read()
                .map(|g| g.tier)
                .unwrap_or(grith_digest::notification::PlanTier::Community);
            let recent = crate::record_session_limit_rejection(&state.session_limit_rejections);
            tracing::warn!(
                event = "session_limit_rejected",
                session_id = %id,
                error = %e,
                tier = %tier,
                active,
                limit,
                recent_rejections = recent,
                "session register refused: limit reached"
            );
            session_limit_rejection_response(
                &headers,
                tier,
                limit,
                active,
                state.billing_portal_url.as_deref(),
            )
        }
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
                "project_name": session.project_name,
                "cwd": session.cwd,
                "tty": session.tty,
                "root_pid": session.root_pid,
                "uptime_seconds": session.uptime().as_secs(),
                "last_activity_seconds": session.last_activity_at.elapsed().as_secs(),
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

/// Operator-initiated reap of dead sessions. Only removes sessions whose root
/// PID is dead and whose heartbeat is stale — never touches a live session.
/// Returns the number reaped and the count remaining.
pub(crate) async fn prune_sessions(
    _auth: IpcAuth,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.supervisor_registry.lock() {
        Ok(mut registry) => {
            let reaped = registry.reap_dead();
            let remaining = registry.count();
            if reaped > 0 {
                tracing::info!(reaped, remaining, "operator prune: removed dead sessions");
            }
            Json(serde_json::json!({
                "reaped": reaped,
                "remaining": remaining,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn snapshot(id: String, allowed: u64, noise: u64) -> SessionSnapshotRequest {
        SessionSnapshotRequest {
            id,
            tool_name: "claude-code".into(),
            profile_name: None,
            policy_scope: None,
            launcher_overlay_name: None,
            provider_overlay_name: None,
            root_pid: 1234,
            project_name: None,
            cwd: None,
            tty: None,
            process_tree_pids: vec![],
            stats: SessionStats {
                total_intercepted: allowed + noise,
                total_allowed: allowed,
                total_queued: 0,
                total_denied: 0,
                total_filtered_noise: noise,
            },
        }
    }

    /// An aged Instant that is safe even on a freshly-booted monotonic clock.
    fn aged(secs: u64) -> Instant {
        Instant::now()
            .checked_sub(Duration::from_secs(secs))
            .expect("monotonic clock should be older than the test offset")
    }

    #[test]
    fn noise_only_snapshot_does_not_reset_idle() {
        let mut session = SupervisorSession::new("claude-code", 1234);
        session.stats.total_allowed = 5;
        session.last_activity_at = aged(120);

        // Only noise increased (proxy_evals unchanged) — idle must be preserved.
        let body = snapshot(session.id.to_string(), 5, 999);
        apply_snapshot(&mut session, &body, true);

        assert!(
            session.last_activity_at.elapsed() >= Duration::from_secs(100),
            "noise-only push must not reset idle age"
        );
    }

    #[test]
    fn proxy_eval_snapshot_resets_idle() {
        let mut session = SupervisorSession::new("claude-code", 1234);
        session.stats.total_allowed = 5;
        session.last_activity_at = aged(120);

        // A newly evaluated call (proxy_evals increased) resets idle to ~0.
        let body = snapshot(session.id.to_string(), 6, 0);
        apply_snapshot(&mut session, &body, true);

        assert!(
            session.last_activity_at.elapsed() < Duration::from_secs(5),
            "a new proxy-evaluated call must reset idle age"
        );
    }
}
