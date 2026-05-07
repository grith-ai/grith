// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! IPC digest queue routes for daemon-owned review state.

use crate::ipc_auth::IpcAuth;
use crate::routes::parse_uuid_or_400;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use grith_digest::types::{DigestItem, DigestStatus};
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct EnqueueDigestRequest {
    pub item: DigestItem,
}

#[derive(Deserialize)]
pub(crate) struct UpdateDigestRequest {
    pub status: DigestStatus,
    #[serde(default)]
    pub review_action: Option<String>,
    #[serde(default)]
    pub reviewer_notes: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ExpireDigestRequest {
    pub before_rfc3339: String,
}

pub(crate) async fn enqueue_digest(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(body): Json<EnqueueDigestRequest>,
) -> impl IntoResponse {
    match state.digest_queue.enqueue(&body.item) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("digest enqueue failed: {e}"),
        )
            .into_response(),
    }
}

pub(crate) async fn get_digest(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let id = match parse_uuid_or_400(&id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match state.digest_queue.get_by_id(&id) {
        Ok(item) => Json(item).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, format!("digest item not found: {e}")).into_response(),
    }
}

pub(crate) async fn update_digest(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateDigestRequest>,
) -> impl IntoResponse {
    let id = match parse_uuid_or_400(&id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match state.digest_queue.update_status(
        &id,
        body.status,
        body.review_action.as_deref(),
        body.reviewer_notes.as_deref(),
    ) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("digest update failed: {e}"),
        )
            .into_response(),
    }
}

pub(crate) async fn expire_digest(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(body): Json<ExpireDigestRequest>,
) -> impl IntoResponse {
    let before = match chrono::DateTime::parse_from_rfc3339(&body.before_rfc3339) {
        Ok(ts) => ts.with_timezone(&chrono::Utc),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid RFC3339 timestamp: {e}"),
            )
                .into_response()
        }
    };
    match state.digest_queue.expire_before(before) {
        Ok(expired) => Json(serde_json::json!({ "expired": expired })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("digest expire failed: {e}"),
        )
            .into_response(),
    }
}
