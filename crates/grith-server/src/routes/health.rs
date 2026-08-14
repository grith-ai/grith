// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Health check and plan tier endpoints.

use crate::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
    subsystems: std::collections::HashMap<String, SubsystemStatus>,
    /// Reason the audit chain is quarantined, when it is (work/74 Phase 5).
    ///
    /// Surfaced on the unauthenticated health payload deliberately: the CLI's
    /// readiness handshake reads it before starting a supervised session, so a
    /// daemon that cannot durably record decisions is caught before a target
    /// is spawned rather than at registration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_quarantined: Option<String>,
    /// Reason this daemon's audit database is read-only, when it is (another
    /// process owns the exclusive writer lock). Surfaced unauthenticated for
    /// the same reason as `audit_quarantined`: the readiness handshake reads
    /// it before starting a supervised session the daemon could not record.
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_read_only: Option<String>,
    /// Instance UUID of this daemon process (go-live review H-20).
    ///
    /// Regenerated on every start, so a CLI can tell "the daemon I was
    /// admitted by" from "a daemon that replaced it" — something the PID file
    /// cannot express, since PIDs are reused.
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,
    /// IPC contract version, so a peer can refuse to speak a protocol it does
    /// not understand instead of misinterpreting the payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol_version: Option<u32>,
}

#[derive(Serialize)]
struct SubsystemStatus {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_ms: Option<f64>,
}

pub(crate) async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();

    let audit_sub = match state
        .audit_storage
        .lock()
        .map_err(|e| e.to_string())
        .and_then(|s| s.count().map_err(|e| e.to_string()))
    {
        Ok(_) => SubsystemStatus {
            status: "ok".into(),
            message: None,
            latency_ms: None,
        },
        Err(e) => SubsystemStatus {
            status: "error".into(),
            message: Some(e),
            latency_ms: None,
        },
    };

    let digest_sub = match state
        .digest_queue
        .count_pending()
        .map_err(|e| e.to_string())
    {
        Ok(n) => SubsystemStatus {
            status: "ok".into(),
            message: Some(format!("{n} pending")),
            latency_ms: None,
        },
        Err(e) => SubsystemStatus {
            status: "error".into(),
            message: Some(e),
            latency_ms: None,
        },
    };

    let proxy_sub = SubsystemStatus {
        status: "ok".into(),
        message: None,
        latency_ms: None,
    };

    let (supervisor_sub, audit_quarantined, audit_read_only) =
        match state.supervisor_registry.lock() {
            Ok(reg) => {
                let n = reg.count();
                // work/74 Phase 5: while the audit chain is quarantined (or
                // this daemon's audit handle is read-only) the registry
                // refuses admission, so the supervisor is not "ok" even
                // though it is running.
                match (reg.audit_quarantine(), reg.audit_read_only()) {
                    (Some(reason), _) => (
                        SubsystemStatus {
                            status: "degraded".into(),
                            message: Some(format!(
                            "{n} active sessions; refusing new sessions (audit chain quarantined)"
                        )),
                            latency_ms: None,
                        },
                        Some(reason.to_string()),
                        None,
                    ),
                    (None, Some(reason)) => (
                        SubsystemStatus {
                            status: "degraded".into(),
                            message: Some(format!(
                            "{n} active sessions; refusing new sessions (audit database read-only)"
                        )),
                            latency_ms: None,
                        },
                        None,
                        Some(reason.to_string()),
                    ),
                    (None, None) => (
                        SubsystemStatus {
                            status: "ok".into(),
                            message: Some(format!("{n} active sessions")),
                            latency_ms: None,
                        },
                        None,
                        None,
                    ),
                }
            }
            Err(e) => (
                SubsystemStatus {
                    status: "error".into(),
                    message: Some(e.to_string()),
                    latency_ms: None,
                },
                None,
                None,
            ),
        };

    let mut subsystems = std::collections::HashMap::new();
    subsystems.insert("audit".into(), audit_sub);
    subsystems.insert("digest".into(), digest_sub);
    subsystems.insert("proxy".into(), proxy_sub);
    subsystems.insert("supervisor".into(), supervisor_sub);

    let overall = if subsystems.values().all(|s| s.status == "ok") {
        "healthy"
    } else if subsystems.values().any(|s| s.status == "error") {
        "unhealthy"
    } else {
        "degraded"
    };

    Json(HealthResponse {
        status: overall.into(),
        version: state.version.clone(),
        uptime_seconds: uptime,
        subsystems,
        audit_quarantined,
        audit_read_only,
        instance_id: state.instance_id.clone(),
        protocol_version: state.protocol_version,
    })
}

pub(crate) async fn get_tier(State(state): State<AppState>) -> impl IntoResponse {
    let (tier, seats, max_sessions, features) = match state.feature_gate.read() {
        Ok(gate) => (
            gate.tier.to_string(),
            gate.seats,
            gate.max_sessions(),
            gate.feature_list()
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>(),
        ),
        Err(_) => (
            "community".to_string(),
            1,
            2,
            grith_digest::notification::FeatureGate {
                tier: grith_digest::notification::PlanTier::Community,
                seats: 1,
            }
            .feature_list()
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>(),
        ),
    };
    let refresh_snapshot = match state.refresh_state.read() {
        Ok(s) => Some((*s).clone()),
        Err(_) => None,
    };
    // Rolling 7-day count of session-limit (429) rejections — powers the
    // dashboard upgrade nudge. Read-only; does not record a new rejection.
    let session_limit_rejections =
        crate::count_recent_session_limit_rejections(&state.session_limit_rejections);
    Json(serde_json::json!({
        "tier": tier,
        "seats": seats,
        "max_sessions": max_sessions,
        "renewal_date": state.license_valid_until,
        "billing_portal_url": state.billing_portal_url,
        "features": features,
        "refresh": refresh_snapshot,
        "session_limit_rejections": session_limit_rejections,
        "session_limit_rejection_window_days": crate::SESSION_LIMIT_REJECTION_WINDOW_DAYS,
    }))
}

/// Detailed licence-refresh state for dashboards and `grith pro status`.
/// Separate from `/tier` so callers that only need refresh health don't pull
/// the full feature list.
pub(crate) async fn get_license_status(State(state): State<AppState>) -> impl IntoResponse {
    let (tier, seats, air_gapped) = match state.feature_gate.read() {
        Ok(gate) => (
            gate.tier.to_string(),
            gate.seats,
            state
                .refresh_state
                .read()
                .map(|s| s.air_gapped)
                .unwrap_or(false),
        ),
        Err(_) => ("community".to_string(), 1, false),
    };
    let refresh_snapshot = match state.refresh_state.read() {
        Ok(s) => (*s).clone(),
        Err(_) => grith_digest::notification::RefreshState::default(),
    };
    let hours_since_refresh = refresh_snapshot
        .last_success
        .as_deref()
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|dt| (chrono::Utc::now() - dt.with_timezone(&chrono::Utc)).num_hours());
    Json(serde_json::json!({
        "tier": tier,
        "seats": seats,
        "renewal_date": state.license_valid_until,
        "billing_portal_url": state.billing_portal_url,
        "air_gapped": air_gapped,
        "hours_since_refresh": hours_since_refresh,
        "refresh": refresh_snapshot,
    }))
}
