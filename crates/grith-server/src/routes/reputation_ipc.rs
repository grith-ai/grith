// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Reputation IPC endpoints for daemon-client communication.
//!
//! These endpoints allow `grith exec` clients to interact with the
//! daemon-owned reputation table via HTTP, ensuring all sessions share
//! a single reputation table without file contention.

use crate::ipc_auth::IpcAuth;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

// --- GET /api/reputation/table ---

#[derive(Serialize)]
struct ReputationTableResponse {
    entries: usize,
    table_json: String,
}

/// Return the full reputation table as serialized TOML.
/// Used by `grith reputation show` when connecting to a running daemon.
pub(crate) async fn get_reputation_table(
    _auth: IpcAuth,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let table = state.reputation_table.lock();
    match table {
        Ok(t) => {
            let json = serde_json::to_string(&*t).unwrap_or_default();
            Json(ReputationTableResponse {
                entries: t.len(),
                table_json: json,
            })
            .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "reputation table lock poisoned",
        )
            .into_response(),
    }
}

// --- POST /api/reputation/observe ---

/// Largest legitimate weight for an `approved` observation. Real observations
/// are 1.0 (user-approved) or 1.5 (learned); a client must not be able to
/// assert a larger magnitude. Without this clamp, `"approved:1000000.0"` drives
/// an entry's trust to ~1.0 in a single request, letting a caller
/// self-whitelist its own future spawns/connects and bypass the QUEUE gate.
const MAX_APPROVED_WEIGHT: f64 = 1.5;
/// Largest legitimate weight for a `denied` observation (terminate-denied=5.0).
/// Bounds the reverse attack (poisoning a routine key toward DENY).
const MAX_DENIED_WEIGHT: f64 = 5.0;
/// A single evaluated call maps to only a handful of reputation keys; cap the
/// count + per-key length so a malicious client can't flood/bloat the table.
const MAX_OBSERVE_KEYS: usize = 32;
const MAX_OBSERVE_KEY_LEN: usize = 512;

#[derive(Deserialize)]
pub(crate) struct ObserveRequest {
    pub keys: Vec<(u8, String)>,
    pub outcome: String, // "approved:1.0", "denied:3.0", etc.
}

/// Record a reputation observation from a client session.
pub(crate) async fn observe_reputation(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(body): Json<ObserveRequest>,
) -> impl IntoResponse {
    if body.keys.len() > MAX_OBSERVE_KEYS
        || body.keys.iter().any(|(_, k)| k.len() > MAX_OBSERVE_KEY_LEN)
    {
        return (StatusCode::BAD_REQUEST, "observation exceeds bounds").into_response();
    }
    let outcome = parse_outcome(&body.outcome);
    let Some(outcome) = outcome else {
        return (StatusCode::BAD_REQUEST, "invalid outcome format").into_response();
    };

    match state.reputation_table.lock() {
        Ok(mut table) => {
            table.observe(&body.keys, outcome, &state.reputation_config);
            (StatusCode::OK, "observed").into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "reputation table lock poisoned",
        )
            .into_response(),
    }
}

// --- POST /api/reputation/reset ---

#[derive(Deserialize)]
pub(crate) struct ResetRequest {
    pub profile: Option<String>,
}

/// Reset reputation data, optionally filtered by profile.
pub(crate) async fn reset_reputation(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(body): Json<ResetRequest>,
) -> impl IntoResponse {
    match state.reputation_table.lock() {
        Ok(mut table) => {
            if let Some(ref profile) = body.profile {
                let before = table.len();
                table
                    .entries
                    .retain(|key, _| !key.starts_with(&format!("{profile}|")));
                let removed = before - table.len();
                Json(serde_json::json!({ "reset": removed })).into_response()
            } else {
                table.reset();
                Json(serde_json::json!({ "reset": "all" })).into_response()
            }
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "reputation table lock poisoned",
        )
            .into_response(),
    }
}

// --- POST /api/reputation/save ---

/// Force-save the reputation table to disk.
pub(crate) async fn save_reputation(
    _auth: IpcAuth,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let path = grith_proxy::reputation::default_reputation_path();
    match state.reputation_table.lock() {
        Ok(table) => match table.save(&path) {
            Ok(()) => Json(serde_json::json!({
                "saved": true,
                "entries": table.len(),
                "path": path.to_string_lossy(),
            }))
            .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("save failed: {e}"),
            )
                .into_response(),
        },
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "reputation table lock poisoned",
        )
            .into_response(),
    }
}

fn parse_outcome(s: &str) -> Option<grith_proxy::reputation::ReputationOutcome> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    let weight: f64 = parts[1].parse().ok()?;
    // A client must not control the observation magnitude. Reject non-finite,
    // and clamp to the largest *legitimate* weight for the outcome kind — real
    // observations (approved 1.0/1.5, denied 1.0/3.0/5.0) are unchanged, while
    // a poisoning attempt (`approved:1e6`, negative weights) is neutralised.
    if !weight.is_finite() {
        return None;
    }
    match parts[0] {
        "approved" => Some(grith_proxy::reputation::ReputationOutcome::Approved(
            weight.clamp(0.0, MAX_APPROVED_WEIGHT),
        )),
        "denied" => Some(grith_proxy::reputation::ReputationOutcome::Denied(
            weight.clamp(0.0, MAX_DENIED_WEIGHT),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grith_proxy::reputation::ReputationOutcome;

    #[test]
    fn parse_outcome_clamps_hostile_weights_and_rejects_non_finite() {
        // The confirmed exploit: "approved:1e6" would drive trust to ~1.0 in
        // one request. Now clamped to the legit approved ceiling.
        assert!(matches!(
            parse_outcome("approved:1000000.0"),
            Some(ReputationOutcome::Approved(w)) if w == MAX_APPROVED_WEIGHT
        ));
        // Legit weights pass through unchanged.
        assert!(matches!(
            parse_outcome("approved:1.0"),
            Some(ReputationOutcome::Approved(w)) if w == 1.0
        ));
        assert!(matches!(
            parse_outcome("denied:3.0"),
            Some(ReputationOutcome::Denied(w)) if w == 3.0
        ));
        // Over-limit denied clamps to its (higher) ceiling.
        assert!(matches!(
            parse_outcome("denied:1000.0"),
            Some(ReputationOutcome::Denied(w)) if w == MAX_DENIED_WEIGHT
        ));
        // Negative weight clamps to 0 (no-op) — never subtracts from trust.
        assert!(matches!(
            parse_outcome("approved:-50"),
            Some(ReputationOutcome::Approved(w)) if w == 0.0
        ));
        // Non-finite is rejected outright.
        assert!(parse_outcome("approved:inf").is_none());
        assert!(parse_outcome("denied:NaN").is_none());
    }
}
