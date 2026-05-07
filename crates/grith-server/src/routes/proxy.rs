// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Proxy status, filter information, and test evaluation endpoints.

use super::api_error;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use grith_proxy::types::{ToolCallContext, ToolCallType};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

fn required_string(
    raw: &serde_json::Value,
    args: Option<&serde_json::Map<String, serde_json::Value>>,
    key: &str,
) -> Option<String> {
    args.and_then(|m| m.get(key))
        .or_else(|| raw.get(key))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

fn optional_string_vec(
    raw: &serde_json::Value,
    args: Option<&serde_json::Map<String, serde_json::Value>>,
    key: &str,
) -> Vec<String> {
    args.and_then(|m| m.get(key))
        .or_else(|| raw.get(key))
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn parse_tool_call_type(raw: &serde_json::Value) -> Result<ToolCallType, String> {
    // Canonical request format: tagged enum with "type".
    let tagged_err = match serde_json::from_value::<ToolCallType>(raw.clone()) {
        Ok(call_type) => return Ok(call_type),
        Err(e) => e.to_string(),
    };

    // Backward compatibility for dashboard examples that still use:
    // {"tool_call_type":"fs.read","arguments":{"path":"..."}}
    let Some(obj) = raw.as_object() else {
        return Err(format!("invalid tool call format: {tagged_err}"));
    };

    let legacy_type = obj
        .get("tool_call_type")
        .or_else(|| obj.get("type"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("invalid tool call format: {tagged_err}"))?;
    let args = obj.get("arguments").and_then(serde_json::Value::as_object);

    match legacy_type {
        "fs.read" | "FileRead" => {
            let path = required_string(raw, args, "path")
                .ok_or_else(|| "missing required field `path` for FileRead".to_string())?;
            Ok(ToolCallType::FileRead { path })
        }
        "fs.write" | "FileWrite" => {
            let path = required_string(raw, args, "path")
                .ok_or_else(|| "missing required field `path` for FileWrite".to_string())?;
            let content_hash =
                required_string(raw, args, "content_hash").unwrap_or_else(|| "unknown".to_string());
            Ok(ToolCallType::FileWrite { path, content_hash })
        }
        "fs.append" | "FileAppend" => {
            let path = required_string(raw, args, "path")
                .ok_or_else(|| "missing required field `path` for FileAppend".to_string())?;
            Ok(ToolCallType::FileAppend { path })
        }
        "fs.delete" | "FileDelete" => {
            let path = required_string(raw, args, "path")
                .ok_or_else(|| "missing required field `path` for FileDelete".to_string())?;
            Ok(ToolCallType::FileDelete { path })
        }
        "dir.list" | "DirList" => {
            let path = required_string(raw, args, "path")
                .ok_or_else(|| "missing required field `path` for DirList".to_string())?;
            Ok(ToolCallType::DirList { path })
        }
        "shell.exec" | "ShellExec" => {
            let command = required_string(raw, args, "command")
                .ok_or_else(|| "missing required field `command` for ShellExec".to_string())?;
            let args = optional_string_vec(raw, args, "args");
            Ok(ToolCallType::ShellExec { command, args })
        }
        "net.request" | "HttpRequest" => {
            let method = required_string(raw, args, "method").unwrap_or_else(|| "GET".to_string());
            let url = required_string(raw, args, "url")
                .ok_or_else(|| "missing required field `url` for HttpRequest".to_string())?;
            Ok(ToolCallType::HttpRequest { method, url })
        }
        other => Err(format!(
            "invalid tool call format: unknown tool_call_type `{other}`; tagged parse error: {tagged_err}"
        )),
    }
}

#[derive(Serialize)]
struct ProxyStatusResponse {
    auto_allow_threshold: f64,
    auto_deny_threshold: f64,
    total_evaluations: u64,
    allow_count: u64,
    queue_count: u64,
    deny_count: u64,
    cold_start_remaining: u64,
    filters: Vec<FilterStatusResponse>,
}

#[derive(Serialize)]
struct FilterStatusResponse {
    name: String,
    phase: String,
    enabled: bool,
    is_ready: bool,
    evaluation_count: u64,
    avg_latency_ms: f64,
}

pub(crate) async fn proxy_status(State(state): State<AppState>) -> impl IntoResponse {
    let scoring = state.proxy.scoring_config();
    let filters: Vec<FilterStatusResponse> = state
        .proxy
        .filter_info()
        .into_iter()
        .map(|f| {
            let phase = match f.phase {
                grith_proxy::filters::FilterPhase::Static => "static",
                grith_proxy::filters::FilterPhase::Pattern => "pattern",
                grith_proxy::filters::FilterPhase::Context => "context",
            };
            FilterStatusResponse {
                name: f.name,
                phase: phase.into(),
                enabled: f.is_ready,
                is_ready: f.is_ready,
                evaluation_count: f.evaluation_count,
                avg_latency_ms: f.avg_latency_ms,
            }
        })
        .collect();

    Json(ProxyStatusResponse {
        auto_allow_threshold: scoring.auto_allow_threshold,
        auto_deny_threshold: scoring.auto_deny_threshold,
        total_evaluations: state.proxy.call_count(),
        allow_count: state.proxy.allow_count(),
        queue_count: state.proxy.queue_count(),
        deny_count: state.proxy.deny_count(),
        cold_start_remaining: state.proxy.cold_start_remaining(),
        filters,
    })
}

// --- POST /api/proxy/test ---

#[derive(Deserialize)]
pub(crate) struct ProxyTestRequest {
    /// The tool call to evaluate, as a JSON object with `"type"` field.
    tool_call: serde_json::Value,
}

#[derive(Serialize)]
struct ProxyTestResponse {
    composite_score: f64,
    action: String,
    decision_reason: String,
    evaluation_time_ms: f64,
    filters_evaluated: usize,
    cold_start: bool,
    filter_results: Vec<ProxyTestFilterDetail>,
}

#[derive(Serialize)]
struct ProxyTestFilterDetail {
    filter_name: String,
    matched: bool,
    score: f64,
    severity: String,
    message: String,
}

pub(crate) async fn proxy_test(
    State(state): State<AppState>,
    Json(body): Json<ProxyTestRequest>,
) -> impl IntoResponse {
    let call_type: ToolCallType = match parse_tool_call_type(&body.tool_call) {
        Ok(ct) => ct,
        Err(e) => {
            return api_error(StatusCode::BAD_REQUEST, e, "INVALID_TOOL_CALL").into_response();
        }
    };

    let mut ctx = ToolCallContext::new("dashboard-test", call_type, Uuid::new_v4());
    ctx.arguments = body.tool_call;

    let cold_start = state.proxy.cold_start_remaining() > 0;
    let decision = state.proxy.evaluate(&ctx).await;

    let action = match &decision.action {
        grith_proxy::types::ProxyAction::Allow => "allow".to_string(),
        grith_proxy::types::ProxyAction::Queue { priority } => {
            format!("queue({priority:?})")
        }
        grith_proxy::types::ProxyAction::Deny { reason } => {
            format!("deny({reason})")
        }
    };

    let filter_results: Vec<ProxyTestFilterDetail> = decision
        .filter_results
        .iter()
        .map(|fr| ProxyTestFilterDetail {
            filter_name: fr.filter_name.clone(),
            matched: fr.matched,
            score: fr.score,
            severity: fr.severity.to_string(),
            message: fr.message.clone(),
        })
        .collect();

    Json(ProxyTestResponse {
        composite_score: decision.composite_score,
        action,
        decision_reason: decision.decision_reason,
        evaluation_time_ms: decision.evaluation_time.as_secs_f64() * 1000.0,
        filters_evaluated: decision.filter_results.len(),
        cold_start,
        filter_results,
    })
    .into_response()
}
