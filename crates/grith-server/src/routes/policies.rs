// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Policy CRUD endpoints (Pro feature).

use super::api_error;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Data Model ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Policy {
    pub name: String,
    pub description: String,
    pub version: u32,
    pub created_at: String,
    pub updated_at: String,
    pub rules: PolicyRules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PolicyRules {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyOverrides>,
    #[serde(default)]
    pub filters: HashMap<String, bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlists: Option<AllowlistConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProxyOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_allow_threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_deny_threshold: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AllowlistConfig {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

// --- Request/Response types ---

#[derive(Deserialize)]
pub(crate) struct CreatePolicyRequest {
    name: String,
    #[serde(default)]
    description: String,
    rules: PolicyRules,
}

#[derive(Deserialize)]
pub(crate) struct UpdatePolicyRequest {
    #[serde(default)]
    description: Option<String>,
    rules: Option<PolicyRules>,
}

#[derive(Serialize)]
struct PolicyListResponse {
    policies: Vec<Policy>,
    total: usize,
}

// --- Helpers ---

/// Validate that a policy name contains only alphanumeric chars and hyphens.
fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("policy name must not be empty".into());
    }
    if name.len() > 64 {
        return Err("policy name must be 64 characters or fewer".into());
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("policy name must contain only alphanumeric characters and hyphens".into());
    }
    Ok(())
}

/// Validate proxy threshold overrides if present.
fn validate_thresholds(proxy: Option<&ProxyOverrides>) -> Result<(), String> {
    if let Some(p) = proxy {
        if let Some(allow) = p.auto_allow_threshold {
            if !(0.0..=10.0).contains(&allow) {
                return Err("auto_allow_threshold must be between 0 and 10".into());
            }
        }
        if let Some(deny) = p.auto_deny_threshold {
            if !(0.0..=10.0).contains(&deny) {
                return Err("auto_deny_threshold must be between 0 and 10".into());
            }
        }
        if let (Some(allow), Some(deny)) = (p.auto_allow_threshold, p.auto_deny_threshold) {
            if allow >= deny {
                return Err("auto_allow_threshold must be less than auto_deny_threshold".into());
            }
        }
    }
    Ok(())
}

/// Validate filter IDs against the proxy's known filters.
fn validate_filter_ids(filters: &HashMap<String, bool>, state: &AppState) -> Result<(), String> {
    if filters.is_empty() {
        return Ok(());
    }
    let known: Vec<String> = state
        .proxy
        .filter_info()
        .iter()
        .map(|f| f.name.clone())
        .collect();
    for id in filters.keys() {
        if !known.iter().any(|k| k == id) {
            return Err(format!("unknown filter ID: {id}"));
        }
    }
    Ok(())
}

fn policies_dir(state: &AppState) -> std::path::PathBuf {
    state.config_dir.join("policies")
}

fn read_policy(path: &std::path::Path) -> Result<Policy, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read policy file: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("failed to parse policy: {e}"))
}

fn write_policy(path: &std::path::Path, policy: &Policy) -> Result<(), String> {
    let content =
        serde_json::to_string_pretty(policy).map_err(|e| format!("failed to serialize: {e}"))?;
    std::fs::write(path, content).map_err(|e| format!("failed to write policy: {e}"))
}

/// Check Pro feature gate for policy editor. Returns an error response if not allowed.
fn check_policy_gate(state: &AppState) -> Option<axum::response::Response> {
    super::require_feature(state, "policy_editor", "Pro")
}

// --- Handlers ---

/// GET /api/policies — list all policies.
pub(crate) async fn list_policies(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(resp) = check_policy_gate(&state) {
        return resp;
    }

    let dir = policies_dir(&state);
    if !dir.exists() {
        return Json(PolicyListResponse {
            policies: vec![],
            total: 0,
        })
        .into_response();
    }

    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read policies directory: {e}"),
                "INTERNAL_ERROR",
            )
            .into_response();
        }
    };

    let mut policies = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(policy) = read_policy(&path) {
                policies.push(policy);
            }
        }
    }
    policies.sort_by(|a, b| a.name.cmp(&b.name));
    let total = policies.len();

    Json(PolicyListResponse { policies, total }).into_response()
}

/// GET /api/policies/:name — get one policy.
pub(crate) async fn get_policy(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = check_policy_gate(&state) {
        return resp;
    }

    let path = policies_dir(&state).join(format!("{name}.json"));
    if !path.exists() {
        return api_error(StatusCode::NOT_FOUND, "policy not found", "NOT_FOUND").into_response();
    }

    match read_policy(&path) {
        Ok(policy) => Json(policy).into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, e, "INTERNAL_ERROR").into_response(),
    }
}

/// POST /api/policies — create a new policy.
pub(crate) async fn create_policy(
    State(state): State<AppState>,
    Json(body): Json<CreatePolicyRequest>,
) -> impl IntoResponse {
    if let Some(resp) = check_policy_gate(&state) {
        return resp;
    }

    if let Err(e) = validate_name(&body.name) {
        return api_error(StatusCode::BAD_REQUEST, e, "VALIDATION_ERROR").into_response();
    }
    if let Err(e) = validate_thresholds(body.rules.proxy.as_ref()) {
        return api_error(StatusCode::BAD_REQUEST, e, "VALIDATION_ERROR").into_response();
    }
    if let Err(e) = validate_filter_ids(&body.rules.filters, &state) {
        return api_error(StatusCode::BAD_REQUEST, e, "VALIDATION_ERROR").into_response();
    }

    let dir = policies_dir(&state);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to create policies directory: {e}"),
            "INTERNAL_ERROR",
        )
        .into_response();
    }

    let path = dir.join(format!("{}.json", body.name));
    if path.exists() {
        return api_error(
            StatusCode::CONFLICT,
            "a policy with this name already exists",
            "ALREADY_EXISTS",
        )
        .into_response();
    }

    let now = chrono::Utc::now().to_rfc3339();
    let policy = Policy {
        name: body.name,
        description: body.description,
        version: 1,
        created_at: now.clone(),
        updated_at: now,
        rules: body.rules,
    };

    if let Err(e) = write_policy(&path, &policy) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, e, "INTERNAL_ERROR").into_response();
    }

    (StatusCode::CREATED, Json(policy)).into_response()
}

/// PUT /api/policies/:name — update a policy.
pub(crate) async fn update_policy(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<UpdatePolicyRequest>,
) -> impl IntoResponse {
    if let Some(resp) = check_policy_gate(&state) {
        return resp;
    }

    let path = policies_dir(&state).join(format!("{name}.json"));
    if !path.exists() {
        return api_error(StatusCode::NOT_FOUND, "policy not found", "NOT_FOUND").into_response();
    }

    let mut policy = match read_policy(&path) {
        Ok(p) => p,
        Err(e) => {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, e, "INTERNAL_ERROR")
                .into_response();
        }
    };

    if let Some(ref desc) = body.description {
        policy.description = desc.clone();
    }
    if let Some(ref rules) = body.rules {
        if let Err(e) = validate_thresholds(rules.proxy.as_ref()) {
            return api_error(StatusCode::BAD_REQUEST, e, "VALIDATION_ERROR").into_response();
        }
        if let Err(e) = validate_filter_ids(&rules.filters, &state) {
            return api_error(StatusCode::BAD_REQUEST, e, "VALIDATION_ERROR").into_response();
        }
        policy.rules = rules.clone();
    }

    policy.version += 1;
    policy.updated_at = chrono::Utc::now().to_rfc3339();

    if let Err(e) = write_policy(&path, &policy) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, e, "INTERNAL_ERROR").into_response();
    }

    Json(policy).into_response()
}

/// DELETE /api/policies/:name — delete a policy.
pub(crate) async fn delete_policy(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = check_policy_gate(&state) {
        return resp;
    }

    let path = policies_dir(&state).join(format!("{name}.json"));
    if !path.exists() {
        return api_error(StatusCode::NOT_FOUND, "policy not found", "NOT_FOUND").into_response();
    }

    if let Err(e) = std::fs::remove_file(&path) {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to delete policy: {e}"),
            "INTERNAL_ERROR",
        )
        .into_response();
    }

    (StatusCode::NO_CONTENT, ()).into_response()
}
