// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Proxy evaluation IPC endpoint for daemon-client communication.
//!
//! Allows `grith exec` clients to evaluate tool calls through the daemon's
//! pre-initialized proxy pipeline via HTTP, eliminating the need to load
//! all filters in every CLI process.

use crate::ipc_auth::IpcAuth;
use crate::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use grith_proxy::types::{ProxyDecision, ToolCallContext};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(crate) struct EvaluateRequest {
    pub context: ToolCallContext,
}

#[derive(Serialize)]
struct EvaluateResponse {
    composite_score: f64,
    action: String,
    decision_reason: String,
    filter_results: Vec<FilterResultSummary>,
    evaluation_time_ms: f64,
}

#[derive(Serialize)]
struct FilterResultSummary {
    filter_name: String,
    matched: bool,
    score: f64,
    rule_id: String,
    severity: grith_proxy::types::Severity,
    message: String,
}

/// POST /api/proxy/evaluate
///
/// Evaluate a tool call through the daemon's proxy pipeline and return the
/// decision. Used by `grith exec` to delegate proxy evaluation to the daemon
/// instead of running the full filter pipeline in-process.
pub(crate) async fn evaluate_proxy(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(body): Json<EvaluateRequest>,
) -> impl IntoResponse {
    let mut decision: ProxyDecision = state.proxy.evaluate(&body.context).await;
    if matches!(
        decision.action,
        grith_proxy::types::ProxyAction::Queue { .. }
    ) {
        maybe_apply_reputation_auto_allow(&state, &body.context, &mut decision);
    }

    let action = match &decision.action {
        grith_proxy::types::ProxyAction::Allow => "allow".to_string(),
        grith_proxy::types::ProxyAction::Queue { priority, .. } => {
            format!("queue:{:?}", priority)
        }
        grith_proxy::types::ProxyAction::Deny { reason } => {
            format!("deny:{reason}")
        }
    };

    let filter_results: Vec<FilterResultSummary> = decision
        .filter_results
        .iter()
        .map(|r| FilterResultSummary {
            filter_name: r.filter_name.clone(),
            matched: r.matched,
            score: r.score,
            rule_id: r.rule_id.clone(),
            severity: r.severity,
            message: r.message.clone(),
        })
        .collect();

    Json(EvaluateResponse {
        composite_score: decision.composite_score,
        action,
        decision_reason: decision.decision_reason.clone(),
        filter_results,
        evaluation_time_ms: decision.evaluation_time.as_secs_f64() * 1000.0,
    })
    .into_response()
}

fn maybe_apply_reputation_auto_allow(
    state: &AppState,
    ctx: &ToolCallContext,
    decision: &mut ProxyDecision,
) {
    let profile = ctx.profile_name.as_deref().unwrap_or("unknown");
    let action_name = grith_proxy::reputation::action_name(&ctx.call_type);
    let process = ctx
        .arguments
        .get("process")
        .and_then(|v| v.as_str())
        .unwrap_or("*");
    let destination = ctx
        .arguments
        .get("process_args")
        .and_then(|v| v.as_array())
        .and_then(|args| {
            args.iter()
                .filter_map(|a| a.as_str())
                .find(|a| !a.starts_with('-') && (a.contains('@') || a.contains('.')))
        })
        .unwrap_or("*");
    let path = match &ctx.call_type {
        grith_proxy::types::ToolCallType::FileRead { path }
        | grith_proxy::types::ToolCallType::FileWrite { path, .. }
        | grith_proxy::types::ToolCallType::FileAppend { path }
        | grith_proxy::types::ToolCallType::FileDelete { path }
        | grith_proxy::types::ToolCallType::FileChmod { path, .. }
        | grith_proxy::types::ToolCallType::DirList { path }
        | grith_proxy::types::ToolCallType::DirCreate { path } => path.as_str(),
        grith_proxy::types::ToolCallType::FileRename { old_path, .. } => old_path.as_str(),
        grith_proxy::types::ToolCallType::ProcessSpawn { command, .. } => command.as_str(),
        grith_proxy::types::ToolCallType::NetConnect { address, .. }
        | grith_proxy::types::ToolCallType::NetListen { address, .. } => address.as_str(),
        grith_proxy::types::ToolCallType::DnsQuery { domain, .. } => domain.as_str(),
        _ => "",
    };
    if path.is_empty() {
        return;
    }

    let ceiling = grith_proxy::reputation::has_safety_ceiling(
        &decision.filter_results,
        &ctx.call_type,
        &state.reputation_config,
    );
    if ceiling {
        return;
    }

    let keys = grith_proxy::reputation::build_reputation_keys(
        profile,
        action_name,
        process,
        destination,
        path,
    );
    let Ok(table) = state.reputation_table.lock() else {
        return;
    };
    let adjusted = table.adjust_score(
        decision.composite_score,
        &keys,
        false,
        &state.reputation_config,
    );
    if adjusted == 0.0 {
        decision.action = grith_proxy::types::ProxyAction::Allow;
        decision.decision_reason = "daemon reputation auto-allow: trust sufficient".to_string();
    }
}

/// GET /api/proxy/status/full
///
/// Return extended proxy status including filter count and scoring config.
pub(crate) async fn proxy_status_full(
    _auth: IpcAuth,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let config = state.proxy.scoring_config();
    Json(serde_json::json!({
        "filter_count": state.proxy.filter_count(),
        "auto_allow_threshold": config.auto_allow_threshold,
        "auto_deny_threshold": config.auto_deny_threshold,
        "call_count": state.proxy.call_count(),
        "filters": state.proxy.filter_info().iter().map(|f| {
            serde_json::json!({
                "name": f.name,
                "phase": format!("{:?}", f.phase),
            })
        }).collect::<Vec<_>>(),
    }))
    .into_response()
}
