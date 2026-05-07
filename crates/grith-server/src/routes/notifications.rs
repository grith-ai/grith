// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Notification channel status and test endpoints (Pro feature).

use crate::AppState;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;

use super::api_error;

pub(crate) async fn list_notification_channels(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(resp) = super::require_feature(&state, "notification_channels", "Pro") {
        return resp;
    }
    let channels = state.notification_dispatcher.list_channels().await;
    Json(serde_json::json!({
        "channels": channels,
        "total": channels.len(),
    }))
    .into_response()
}

pub(crate) async fn notification_status(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(resp) = super::require_feature(&state, "notification_channels", "Pro") {
        return resp;
    }
    let tracker = state.notification_dispatcher.tracker();
    let recent = tracker.recent_events(50);
    Json(serde_json::json!({
        "recent_events": recent,
    }))
    .into_response()
}

pub(crate) async fn test_notification(
    State(state): State<AppState>,
    Path(channel): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = super::require_feature(&state, "notification_channels", "Pro") {
        return resp;
    }
    match state.notification_dispatcher.test_channel(&channel).await {
        Ok(()) => Json(serde_json::json!({
            "status": "sent",
            "channel": channel,
        }))
        .into_response(),
        Err(e) => api_error(
            axum::http::StatusCode::BAD_REQUEST,
            e.to_string(),
            "NOTIFICATION_ERROR",
        )
        .into_response(),
    }
}
