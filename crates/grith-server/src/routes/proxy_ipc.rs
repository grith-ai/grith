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
    /// Outcomes of earlier calls, piggybacked so they can be committed before
    /// this one is scored. Defaulted so an older supervisor still works.
    #[serde(default)]
    pub observations: Vec<WireObservation>,
}

/// One call's final outcome, as the supervisor reports it.
///
/// The supervisor sends the fields a stateful filter actually reads rather
/// than a whole `ToolCallContext`, so the daemon reconstitutes a minimal one.
#[derive(Deserialize)]
pub(crate) struct WireObservation {
    pub call_id: uuid::Uuid,
    pub scope: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub call_type: grith_proxy::types::ToolCallType,
    /// Profile name and arguments both feed filter decisions at commit time
    /// (profile-trusted destinations, and the unix-socket class that decides
    /// whether a connect counts as egress at all). Defaulted so an older
    /// supervisor still interoperates, at the cost of those two signals.
    #[serde(default)]
    pub profile_name: Option<String>,
    #[serde(default)]
    pub arguments: serde_json::Value,
    pub outcome: grith_proxy::types::CallOutcome,
    /// How long ago the paired evaluate ran. Sent as an age rather than a
    /// timestamp because the two processes share no `Instant` epoch, and a
    /// wall clock would import clock-adjustment bugs into monotonic windows.
    pub age_ms: u64,
}

/// Call ids committed recently, so a re-sent batch cannot be applied twice.
///
/// The supervisor puts a batch back in its outbox whenever the POST does not
/// return success - but a timeout or a dropped response is indistinguishable
/// from a request that never arrived, so a batch the daemon DID apply can come
/// back. Observations are not naturally idempotent (each pushes a timestamp),
/// so without this a flaky link inflates exactly the counters this work exists
/// to make honest.
///
/// Bounded ring: far larger than the supervisor's 256-entry outbox, so a
/// re-send is always still covered, while the memory stays fixed.
const APPLIED_RING_CAPACITY: usize = 4096;

static RECENTLY_APPLIED: std::sync::LazyLock<
    std::sync::Mutex<(
        std::collections::HashSet<uuid::Uuid>,
        std::collections::VecDeque<uuid::Uuid>,
    )>,
> = std::sync::LazyLock::new(|| {
    std::sync::Mutex::new((
        std::collections::HashSet::new(),
        std::collections::VecDeque::new(),
    ))
});

/// Record `call_id` as applied. Returns false when it was already applied, in
/// which case the caller must skip it.
fn claim_call_id(call_id: uuid::Uuid) -> bool {
    let Ok(mut guard) = RECENTLY_APPLIED.lock() else {
        // A poisoned lock must not silently start double-committing.
        return false;
    };
    let (seen, order) = &mut *guard;
    if !seen.insert(call_id) {
        return false;
    }
    order.push_back(call_id);
    if order.len() > APPLIED_RING_CAPACITY {
        if let Some(evicted) = order.pop_front() {
            seen.remove(&evicted);
        }
    }
    true
}

/// Commit piggybacked outcomes into the daemon's filter state.
///
/// Runs BEFORE the evaluate it rode in on, so call N's commit is always
/// applied ahead of call N+1's evaluation.
fn apply_observations(state: &AppState, observations: Vec<WireObservation>) {
    for observation in observations {
        if !claim_call_id(observation.call_id) {
            tracing::trace!(
                call_id = %observation.call_id,
                "skipping already-applied observation (re-sent batch)"
            );
            continue;
        }
        let mut ctx = ToolCallContext::new(
            "grith-supervisor",
            observation.call_type,
            observation.session_id,
        );
        ctx.id = observation.call_id;
        ctx.session_scope = Some(grith_proxy::types::SessionScopeKey::from_session_id(
            observation.scope,
        ));
        ctx.profile_name = observation.profile_name;
        ctx.arguments = observation.arguments;
        state.proxy.observe_outcome(
            &ctx,
            observation.outcome,
            std::time::Duration::from_millis(observation.age_ms),
        );
    }
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

/// POST /api/proxy/observe
///
/// Commit call outcomes without evaluating anything. The supervisor
/// piggybacks observations on `/api/proxy/evaluate` in the steady state; this
/// exists for the flush at session end, where there is no next evaluate to
/// ride along with and the session's last calls would otherwise never land.
pub(crate) async fn observe_outcomes(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(observations): Json<Vec<WireObservation>>,
) -> impl IntoResponse {
    let applied = observations.len();
    apply_observations(&state, observations);
    Json(serde_json::json!({ "applied": applied }))
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
    apply_observations(&state, body.observations);
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
        // Evaluations that reported a final outcome, so stateful filters could
        // commit. `call_count - observed_count` is the running total that
        // never did. A few are by design (the proxy-test endpoint, one-shot
        // CLI evaluations), so this is a baseline to watch for drift rather
        // than a figure that should read zero. A climbing delta means outcome
        // wiring has regressed and some filter has quietly stopped
        // accumulating - which would otherwise present as "no alerts".
        "observed_count": state.proxy.observed_count(),
        "observed_executed": state.proxy.observed_executed(),
        "observed_suppressed": state.proxy.observed_suppressed(),
        "filters": state.proxy.filter_info().iter().map(|f| {
            serde_json::json!({
                "name": f.name,
                "phase": format!("{:?}", f.phase),
            })
        }).collect::<Vec<_>>(),
    }))
    .into_response()
}
