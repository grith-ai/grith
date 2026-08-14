// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Digest queue REST endpoints and webhook review callback.

use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use grith_digest::DigestStatus;
use serde::Deserialize;

use super::{api_error, parse_uuid_or_400, PaginationParams};

/// Map a digest action error to an appropriate HTTP response using typed variants.
fn digest_action_error_response(
    e: grith_digest::Error,
    error_code: &str,
) -> axum::response::Response {
    let status = match &e {
        grith_digest::Error::NotFound(_) => StatusCode::NOT_FOUND,
        grith_digest::Error::InvalidAction(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    api_error(status, e.to_string(), error_code).into_response()
}

/// Map a notification callback error to an appropriate HTTP response using typed variants.
fn notify_callback_error_response(
    e: grith_notify::Error,
    error_code: &str,
) -> axum::response::Response {
    let status = match &e {
        grith_notify::Error::Notification(grith_digest::notification::Error::InvalidNonce) => {
            StatusCode::FORBIDDEN
        }
        _ => StatusCode::CONFLICT,
    };
    api_error(status, e.to_string(), error_code).into_response()
}

#[derive(Deserialize)]
pub(crate) struct ReviewBody {
    #[serde(default)]
    notes: Option<String>,
}

pub(crate) async fn list_digest(
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let effective_limit = params.effective_limit();
    match state
        .digest_queue
        .get_actionable(effective_limit, params.offset)
    {
        Ok(items) => {
            let actionable_count = state.digest_queue.count_actionable().unwrap_or(0);
            let pending_count = state.digest_queue.count_pending().unwrap_or(0);
            let escalated_count = state.digest_queue.count_escalated().unwrap_or(0);
            Json(serde_json::json!({
                "items": items,
                "total": actionable_count,
                "pending_count": pending_count,
                "escalated_count": escalated_count,
                "limit": effective_limit,
                "offset": params.offset,
            }))
            .into_response()
        }
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            e.to_string(),
            "DIGEST_ERROR",
        )
        .into_response(),
    }
}

pub(crate) async fn approve_digest(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ReviewBody>,
) -> impl IntoResponse {
    let uuid = match parse_uuid_or_400(&id) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let result = state.digest_queue.update_status(
        &uuid,
        DigestStatus::Approved,
        Some("approve"),
        body.notes.as_deref(),
    );
    match result {
        Ok(()) => {
            let item = state.digest_queue.get_by_id(&uuid).ok();
            if let Some(item) = item {
                let _ = state.notification_dispatcher.notify_resolution(&item).await;
            }
            Json(serde_json::json!({"status": "approved", "id": id})).into_response()
        }
        Err(e) => api_error(StatusCode::NOT_FOUND, e.to_string(), "NOT_FOUND").into_response(),
    }
}

pub(crate) async fn deny_digest(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ReviewBody>,
) -> impl IntoResponse {
    let uuid = match parse_uuid_or_400(&id) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let result = state.digest_queue.update_status(
        &uuid,
        DigestStatus::Denied,
        Some("deny"),
        body.notes.as_deref(),
    );
    match result {
        Ok(()) => {
            let item = state.digest_queue.get_by_id(&uuid).ok();
            if let Some(item) = item {
                let _ = state.notification_dispatcher.notify_resolution(&item).await;
            }
            Json(serde_json::json!({"status": "denied", "id": id})).into_response()
        }
        Err(e) => api_error(StatusCode::NOT_FOUND, e.to_string(), "NOT_FOUND").into_response(),
    }
}

/// Clear all actionable digest items (pending + escalated) in one atomic
/// operation — a "dismiss all" for stale/older items. Does NOT approve
/// (execute) or deny them; it removes them from the queue (see
/// `bulk_clear_pending`). No per-item resolution notifications are dispatched
/// (bulk clear must not flood the operator's notification channels).
pub(crate) async fn clear_all_digest(State(state): State<AppState>) -> impl IntoResponse {
    match state.digest_queue.bulk_clear_pending() {
        Ok(cleared) => {
            Json(serde_json::json!({"status": "cleared", "cleared": cleared})).into_response()
        }
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            e.to_string(),
            "DIGEST_CLEAR_FAILED",
        )
        .into_response(),
    }
}

pub(crate) async fn learn_digest(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ReviewBody>,
) -> impl IntoResponse {
    let uuid = match parse_uuid_or_400(&id) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    match state.digest_queue.update_status(
        &uuid,
        DigestStatus::Approved,
        Some("learn"),
        body.notes.as_deref(),
    ) {
        Ok(()) => Json(serde_json::json!({"status": "learned", "id": id})).into_response(),
        Err(e) => api_error(StatusCode::NOT_FOUND, e.to_string(), "NOT_FOUND").into_response(),
    }
}

pub(crate) async fn escalate_digest(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ReviewBody>,
) -> impl IntoResponse {
    let uuid = match parse_uuid_or_400(&id) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let actions = grith_digest::actions::DigestActions::new(&state.digest_queue);
    let result = actions.escalate(&uuid, body.notes.as_deref());
    match result {
        Ok(()) => {
            let item = state.digest_queue.get_by_id(&uuid).ok();
            if let Some(item) = item {
                let _ = state.notification_dispatcher.notify_escalation(&item).await;
            }
            Json(serde_json::json!({"status": "escalated", "id": id})).into_response()
        }
        Err(e) => digest_action_error_response(e, "ESCALATE_ERROR"),
    }
}

pub(crate) async fn unlock_egress_digest(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(_body): Json<ReviewBody>,
) -> impl IntoResponse {
    let uuid = match parse_uuid_or_400(&id) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let actions = grith_digest::actions::DigestActions::new(&state.digest_queue);
    match actions.unlock_egress(&uuid) {
        Ok(()) => {
            let released = state
                .digest_queue
                .get_by_id(&uuid)
                .ok()
                .and_then(|item| item.session_id)
                .map(|sid| state.containment_tracker.unregister(sid))
                .unwrap_or(false);
            Json(serde_json::json!({
                "status": "approved",
                "action": "unlock_egress",
                "id": id,
                "containment_released": released
            }))
            .into_response()
        }
        Err(e) => digest_action_error_response(e, "UNLOCK_EGRESS_ERROR"),
    }
}

pub(crate) async fn deny_terminate_digest(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(_body): Json<ReviewBody>,
) -> impl IntoResponse {
    let uuid = match parse_uuid_or_400(&id) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let actions = grith_digest::actions::DigestActions::new(&state.digest_queue);
    match actions.deny_and_terminate(&uuid) {
        Ok(()) => {
            Json(serde_json::json!({"status": "denied", "action": "deny_and_terminate", "id": id}))
                .into_response()
        }
        Err(e) => digest_action_error_response(e, "DENY_TERMINATE_ERROR"),
    }
}

pub(crate) async fn allow_always_digest(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(_body): Json<ReviewBody>,
) -> impl IntoResponse {
    let uuid = match parse_uuid_or_400(&id) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let actions = grith_digest::actions::DigestActions::new(&state.digest_queue);
    match actions.allow_always(&uuid) {
        Ok(()) => {
            Json(serde_json::json!({"status": "approved", "action": "allow_always", "id": id}))
                .into_response()
        }
        Err(e) => digest_action_error_response(e, "ALLOW_ALWAYS_ERROR"),
    }
}

#[derive(Deserialize)]
pub(crate) struct WebhookReviewBody {
    action: String,
    #[serde(default)]
    reviewer: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    /// Required one-time nonce proving callback authenticity.
    nonce: String,
}

pub(crate) async fn webhook_review_digest(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<WebhookReviewBody>,
) -> impl IntoResponse {
    let uuid = match parse_uuid_or_400(&id) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let action = match body.action.as_str() {
        "approve" => grith_digest::ReviewAction::Approve,
        "deny" => grith_digest::ReviewAction::Deny,
        "escalate" => grith_digest::ReviewAction::Escalate,
        other => {
            return api_error(
                StatusCode::BAD_REQUEST,
                format!("unknown action: {other}"),
                "INVALID_ACTION",
            )
            .into_response()
        }
    };

    let payload = grith_digest::notification::CallbackPayload {
        item_id: uuid,
        action,
        reviewer: body.reviewer.unwrap_or_else(|| "webhook".into()),
        notes: body.notes,
        nonce: body.nonce,
        channel_id: "webhook".into(),
        user_id: None,
    };

    match state
        .notification_dispatcher
        .handle_callback(&payload)
        .await
    {
        Ok(Some(action)) => Json(serde_json::json!({
            "status": "reviewed",
            "action": action.to_string(),
            "id": id,
        }))
        .into_response(),
        Ok(None) => Json(serde_json::json!({
            "status": "no_action",
            "id": id,
        }))
        .into_response(),
        Err(e) => notify_callback_error_response(e, "REVIEW_ERROR"),
    }
}
