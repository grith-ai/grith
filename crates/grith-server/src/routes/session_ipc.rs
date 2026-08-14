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

/// Body for `POST /api/ipc/session-reservations` (work/74 Phase 1).
///
/// Deliberately minimal: at reserve time the CLI knows only what it is about
/// to launch, not the session id or root PID — those exist only after a
/// successful spawn and arrive with the activation.
#[derive(Deserialize)]
pub(crate) struct SessionReservationRequest {
    pub tool_name: String,
    #[serde(default)]
    pub profile_name: Option<String>,
}

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
    /// Instance id of the daemon that originally *admitted* this session, as
    /// captured by the CLI at connect time (B12 #77). Carried on every
    /// heartbeat so the adopt-on-heartbeat path can tell a normal update from
    /// an authority transfer to a daemon that never admitted the session
    /// (i.e. the original daemon restarted or was replaced). `None` from an
    /// older CLI, or one that could not read the daemon's identity — treated
    /// as "cannot compare", never as a match.
    #[serde(default)]
    pub admitting_instance_id: Option<String>,
}

/// B12 #77: does adopting this heartbeat transfer the session's authority
/// across a daemon-instance boundary? True only when both the admitting id
/// (from the CLI) and this daemon's id are known *and differ*. A missing id
/// on either side is "cannot compare" — never a mismatch — so an older CLI
/// or a daemon without a published identity degrades to the prior behaviour
/// rather than blocking a live session.
fn adoption_crosses_instance(admitting: Option<&str>, current: Option<&str>) -> bool {
    matches!((admitting, current), (Some(a), Some(c)) if a != c)
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

/// Reconstruct a `SupervisorSession` from a wire snapshot. Shared by the
/// register path and the heartbeat-adopt path in `update_session` so both
/// build the session identically.
fn session_from_snapshot(id: uuid::Uuid, body: &SessionSnapshotRequest) -> SupervisorSession {
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
    session
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
    let session = session_from_snapshot(id, &body);

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
        // work/74 Phase 5: a quarantined audit chain is NOT a plan-limit
        // rejection. Reporting it as one would show the user a bogus "upgrade
        // for more sessions" prompt for a problem no upgrade fixes, and would
        // pollute the 7-day rejection counter that drives the upsell nudge.
        Err(grith_supervisor::Error::AuditQuarantined(reason)) => {
            drop(registry);
            tracing::error!(
                event = "session_refused_audit_quarantined",
                session_id = %id,
                reason = %reason,
                "refusing session registration: audit chain quarantined"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({
                    "error": "audit_chain_quarantined",
                    "message": format!(
                        "The audit chain failed verification, so grith will not start a \
                         supervised session it cannot verifiably record: {reason}"
                    ),
                    "remediation": "grith audit diagnose",
                    "records_preserved": true,
                })),
            )
                .into_response()
        }
        // Like quarantine, a read-only audit handle is not a plan-limit
        // rejection: no upgrade fixes it, and it must not pollute the
        // rejection counter that drives the upsell nudge.
        Err(grith_supervisor::Error::AuditReadOnly(reason)) => {
            drop(registry);
            tracing::error!(
                event = "session_refused_audit_read_only",
                session_id = %id,
                reason = %reason,
                "refusing session registration: audit database is read-only"
            );
            audit_read_only_response(&reason)
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

/// The 503 envelope for a daemon whose audit database is read-only: same
/// principle as the quarantine envelope (a session grith cannot record must
/// not start), different cause and remedy.
fn audit_read_only_response(reason: &str) -> axum::response::Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({
            "error": "audit_read_only",
            "message": format!(
                "This daemon cannot write audit records ({reason}), so grith \
                 will not start a supervised session it cannot record."
            ),
            "remediation": "grith daemon restart",
        })),
    )
        .into_response()
}

/// Shared rendering for an admission refusal, so the reservation routes
/// return exactly the envelopes the register route already returns.
fn admission_error_response(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    err: &grith_supervisor::Error,
    limit: usize,
    active: usize,
) -> axum::response::Response {
    match err {
        grith_supervisor::Error::AuditQuarantined(reason) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "error": "audit_chain_quarantined",
                "message": format!(
                    "The audit chain failed verification, so grith will not start a \
                     supervised session it cannot verifiably record: {reason}"
                ),
                "remediation": "grith audit diagnose",
                "records_preserved": true,
            })),
        )
            .into_response(),
        grith_supervisor::Error::AuditReadOnly(reason) => audit_read_only_response(reason),
        _ => {
            let tier = state
                .feature_gate
                .read()
                .map(|g| g.tier)
                .unwrap_or(grith_digest::notification::PlanTier::Community);
            crate::record_session_limit_rejection(&state.session_limit_rejections);
            session_limit_rejection_response(
                headers,
                tier,
                limit,
                active,
                state.billing_portal_url.as_deref(),
            )
        }
    }
}

/// `POST /api/ipc/session-reservations` — claim a capacity slot *before* the
/// target process is created (work/74 Phase 1, go-live review B12 item 1).
///
/// Admission used to happen after the spawn, so a capacity rejection could
/// land once the supervised tool had already executed code. Reserving first
/// means the refusal happens while there is still nothing running.
pub(crate) async fn reserve_session(
    _auth: IpcAuth,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SessionReservationRequest>,
) -> impl IntoResponse {
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

    let limit = registry.max_sessions();
    match registry.reserve(&body.tool_name, body.profile_name.as_deref()) {
        Ok(reservation_id) => {
            let active = registry.occupancy();
            drop(registry);
            tracing::info!(
                event = "session_reserved",
                reservation_id = %reservation_id,
                tool = %body.tool_name,
                active,
                limit,
                "capacity reserved before spawn"
            );
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "reservation_id": reservation_id.to_string(),
                    "expires_in_seconds":
                        grith_supervisor::supervisor::RESERVATION_TTL.as_secs(),
                })),
            )
                .into_response()
        }
        Err(e) => {
            let active = registry.occupancy();
            drop(registry);
            tracing::warn!(
                event = "session_reservation_refused",
                tool = %body.tool_name,
                error = %e,
                active,
                limit,
                "refused capacity reservation before spawn"
            );
            admission_error_response(&state, &headers, &e, limit, active)
        }
    }
}

/// `POST /api/ipc/session-reservations/:id/activate` — turn a held
/// reservation into a registered session once the spawn has succeeded.
///
/// Idempotent: a retried activation for an already-registered session is a
/// success, not a second seat.
pub(crate) async fn activate_session(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Path(reservation_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SessionSnapshotRequest>,
) -> impl IntoResponse {
    let reservation_id = match parse_uuid_or_400(&reservation_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let session_id = match parse_uuid_or_400(&body.id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let session = session_from_snapshot(session_id, &body);

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

    let limit = registry.max_sessions();
    match registry.activate(reservation_id, session) {
        Ok(()) => {
            drop(registry);
            tracing::info!(
                event = "session_activated",
                reservation_id = %reservation_id,
                session_id = %session_id,
                tool = %body.tool_name,
                pid = body.root_pid,
                "reservation activated into a live session"
            );
            StatusCode::CREATED.into_response()
        }
        Err(e) => {
            let active = registry.occupancy();
            drop(registry);
            tracing::warn!(
                event = "session_activation_refused",
                reservation_id = %reservation_id,
                session_id = %session_id,
                error = %e,
                "refused to activate reservation"
            );
            admission_error_response(&state, &headers, &e, limit, active)
        }
    }
}

/// `DELETE /api/ipc/session-reservations/:id` — release a reservation whose
/// spawn failed. The TTL reaper is the backstop; this is the fast path.
pub(crate) async fn cancel_session_reservation(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Path(reservation_id): Path<String>,
) -> impl IntoResponse {
    let reservation_id = match parse_uuid_or_400(&reservation_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match state.supervisor_registry.lock() {
        Ok(mut registry) => {
            let held = registry.cancel(reservation_id);
            drop(registry);
            if held {
                tracing::info!(
                    event = "session_reservation_cancelled",
                    reservation_id = %reservation_id,
                    "released capacity reservation"
                );
            }
            // Cancelling an unknown or already-expired lease is not an error:
            // the caller's intent (don't hold this seat) is satisfied either
            // way, and a 404 would only invite pointless retry logic.
            StatusCode::NO_CONTENT.into_response()
        }
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
        Ok(mut registry) => {
            if let Some(session) = registry.get_mut(&id) {
                apply_snapshot(session, &body, true);
                return StatusCode::OK.into_response();
            }
            // Adopt-on-heartbeat: the daemon doesn't know this session — almost
            // always because it restarted while the supervised process kept
            // running (its register-at-start call was against the old daemon).
            // The heartbeat PUT carries the full snapshot, so re-register the
            // session here instead of 404ing it into invisibility forever. Only
            // a live process heartbeats, so this can't resurrect a dead session;
            // reap dead slots first so adoption still honours the licensed cap.
            //
            // B12 #77: this is precisely the "silently transfer its authority
            // to a daemon that never admitted it" case the daemon-identity
            // work exists to surface. If the CLI captured the admitting
            // daemon's instance id and it differs from ours, the session is
            // crossing a daemon-instance boundary — make it loud rather than
            // silent. Fail-safe is to adopt anyway (refusing would drop a live
            // session), but never without a record.
            //
            // Residual: even flagged, we cannot prove the records written to
            // the *previous* daemon's audit chain and those we will now write
            // form one continuous, verifiable chain — the two daemons may own
            // different audit databases (`DaemonIdentity::audit_path`). That
            // audit-path continuity check is deferred; the flag here is the
            // detection, not the repair.
            if adoption_crosses_instance(
                body.admitting_instance_id.as_deref(),
                state.instance_id.as_deref(),
            ) {
                tracing::warn!(
                    event = "session_adopted_across_daemon_instance",
                    session_id = %id,
                    pid = body.root_pid,
                    admitting_instance_id = body.admitting_instance_id.as_deref().unwrap_or("unknown"),
                    current_instance_id = state.instance_id.as_deref().unwrap_or("unknown"),
                    "adopting a session admitted by a different daemon instance; audit-chain \
                     continuity across the restart is not verified (B12 #77 residual)"
                );
            }
            if registry.count() >= registry.max_sessions() {
                registry.reap_dead();
            }
            let session = session_from_snapshot(id, &body);
            match registry.register(session) {
                Ok(()) => {
                    tracing::info!(
                        event = "session_adopted_on_heartbeat",
                        session_id = %id,
                        pid = body.root_pid,
                        "adopted an orphaned session via heartbeat (daemon likely restarted)"
                    );
                    StatusCode::OK.into_response()
                }
                Err(e) => {
                    // work/74 Phase 3 (go-live review B12 item 2): answering
                    // 200 here told the client everything was fine while the
                    // daemon accounted for nothing — the session kept running
                    // untracked, outside the licensed cap and outside the
                    // registry that makes it visible or killable.
                    //
                    // 409 is the honest answer: the request is understood and
                    // refused because of the daemon's current state. The
                    // client decides what to do about it (see the
                    // authority-lost handling in the supervisor loop); the
                    // daemon does not kill anyone's work from here. The
                    // status stays 409 for every cause — the heartbeat
                    // client's authority-lost handling keys off 4xx, and a
                    // permanent 503 would retry forever — but the structured
                    // reason and remediation must name the actual cause.
                    let (reason, remediation) = match &e {
                        grith_supervisor::Error::AuditQuarantined(_) => {
                            ("audit_quarantined", vec!["grith audit diagnose"])
                        }
                        grith_supervisor::Error::AuditReadOnly(_) => {
                            ("audit_read_only", vec!["grith daemon restart"])
                        }
                        _ => ("capacity", vec!["close_session", "upgrade"]),
                    };
                    tracing::warn!(
                        event = "session_adoption_refused",
                        session_id = %id,
                        reason,
                        error = %e,
                        "refusing to adopt an orphaned session"
                    );
                    (
                        StatusCode::CONFLICT,
                        axum::Json(serde_json::json!({
                            "error": "session_not_tracked",
                            "reason": reason,
                            "message": format!(
                                "This daemon is not tracking session {id} and cannot adopt \
                                 it: {e}. Its decisions are still being evaluated, but the \
                                 daemon is not accounting for the session."
                            ),
                            "remediation": remediation,
                        })),
                    )
                        .into_response()
                }
            }
        }
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
                ..Default::default()
            },
            admitting_instance_id: None,
        }
    }

    #[test]
    fn adoption_crosses_instance_only_on_a_known_mismatch() {
        // Both known and different — the authority-transfer case.
        assert!(adoption_crosses_instance(Some("a"), Some("b")));
        // Same instance — an ordinary in-place update, not a crossing.
        assert!(!adoption_crosses_instance(Some("a"), Some("a")));
        // Either side unknown — cannot compare, so never a crossing. This is
        // what keeps an older CLI or an identity-less daemon from blocking a
        // live session.
        assert!(!adoption_crosses_instance(None, Some("b")));
        assert!(!adoption_crosses_instance(Some("a"), None));
        assert!(!adoption_crosses_instance(None, None));
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
