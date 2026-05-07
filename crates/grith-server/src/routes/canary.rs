// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Canary token management REST endpoints.
//!
//! Canary tokens are honey credentials planted in sensitive locations.
//! The actual `value` is NEVER returned in API responses — exposing it
//! would defeat the purpose of the trap.

use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use grith_proxy::filters::canary::CanaryToken;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{api_error, parse_uuid_or_400};

/// API response for a canary token — value is never exposed.
#[derive(Serialize)]
struct CanaryResponse {
    id: Uuid,
    label: String,
    /// Prefix of the value (first 4 chars) for identification without full exposure.
    value_prefix: String,
}

impl From<&CanaryToken> for CanaryResponse {
    fn from(token: &CanaryToken) -> Self {
        let prefix_len = token.value.len().min(4);
        Self {
            id: token.id,
            label: token.label.clone(),
            value_prefix: format!("{}...", &token.value[..prefix_len]),
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct CanaryCreateBody {
    label: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    generate: bool,
}

#[derive(Deserialize)]
pub(crate) struct CanaryRotateBody {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    generate: bool,
}

pub(crate) async fn list_canaries(State(state): State<AppState>) -> impl IntoResponse {
    let tokens = state.canary_registry.list();
    let items: Vec<CanaryResponse> = tokens.iter().map(CanaryResponse::from).collect();
    let total = items.len();
    Json(serde_json::json!({
        "items": items,
        "total": total,
    }))
}

pub(crate) async fn add_canary(
    State(state): State<AppState>,
    Json(body): Json<CanaryCreateBody>,
) -> impl IntoResponse {
    let label = body.label.trim();
    if label.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "label cannot be empty",
            "INVALID_LABEL",
        )
        .into_response();
    }
    let value = match grith_proxy::filters::canary::resolve_canary_value(body.value, body.generate)
    {
        Ok(v) => v,
        Err(msg) => {
            return api_error(StatusCode::BAD_REQUEST, msg, "INVALID_VALUE").into_response()
        }
    };
    let token = CanaryToken {
        id: Uuid::new_v4(),
        label: label.to_string(),
        value,
    };
    let response = CanaryResponse::from(&token);
    state.canary_registry.add(token);
    (StatusCode::CREATED, Json(response)).into_response()
}

pub(crate) async fn remove_canary(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let id = match parse_uuid_or_400(&id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if state.canary_registry.remove(&id) {
        Json(serde_json::json!({"status":"removed","id":id})).into_response()
    } else {
        api_error(StatusCode::NOT_FOUND, "canary not found", "NOT_FOUND").into_response()
    }
}

pub(crate) async fn rotate_canary(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<CanaryRotateBody>,
) -> impl IntoResponse {
    let id = match parse_uuid_or_400(&id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let value = match grith_proxy::filters::canary::resolve_canary_value(body.value, body.generate)
    {
        Ok(v) => v,
        Err(msg) => {
            return api_error(StatusCode::BAD_REQUEST, msg, "INVALID_VALUE").into_response()
        }
    };
    match state.canary_registry.rotate(&id, value) {
        Some(token) => Json(CanaryResponse::from(&token)).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "canary not found", "NOT_FOUND").into_response(),
    }
}
