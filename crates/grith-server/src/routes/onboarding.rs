// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Onboarding status for the dashboard "Get started" checklist.
//!
//! Read-only, non-secret status (`GET /api/onboarding/status`) plus a
//! dashboard-specific dismissal (`POST /api/onboarding/dismiss`). The dismissal
//! is tracked by a marker file in the config dir — deliberately separate from
//! the CLI's `general.onboarded` flag, because completing CLI setup and
//! dismissing the dashboard empty-state are different user actions.

use super::api_error;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use std::path::PathBuf;

/// Non-secret onboarding/status snapshot for the dashboard checklist.
// Independent status flags for a serialization DTO, not a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
struct OnboardingStatus {
    /// CLI first-run setup completed (`general.onboarded`).
    onboarded: bool,
    /// Whether audit records sync to the cloud (`general.audit_sync`).
    audit_sync: bool,
    /// Configured built-in provider (`llm.default_provider`).
    default_provider: String,
    /// License tier (community/pro/enterprise).
    tier: String,
    /// Whether a paid (Pro/Enterprise/trial) tier is active.
    trial_active: bool,
    /// Whether any notification channel is enabled.
    notifications_configured: bool,
    /// Currently-registered supervised sessions.
    active_sessions: usize,
    /// Whether the dashboard checklist card was dismissed.
    dismissed: bool,
    /// Whether the first-run dashboard intro overlay has been shown/acknowledged.
    /// Gates the "this is your local dashboard, your CLI session is still
    /// running in the terminal" explainer so it appears only once.
    intro_seen: bool,
}

pub(crate) async fn get_onboarding_status(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = std::fs::read_to_string(state.config_dir.join("config.toml"))
        .ok()
        .and_then(|s| s.parse::<toml::Value>().ok());

    let onboarded = cfg_bool(cfg.as_ref(), &["general", "onboarded"], false);
    let audit_sync = cfg_bool(cfg.as_ref(), &["general", "audit_sync"], true);
    let default_provider =
        cfg_str(cfg.as_ref(), &["llm", "default_provider"]).unwrap_or_else(|| "ollama".to_string());
    let notifications_configured = notifications_configured(cfg.as_ref());

    let tier = state
        .feature_gate
        .read()
        .map(|g| g.tier.to_string())
        .unwrap_or_else(|_| "community".to_string());
    let trial_active = tier != "community";

    let active_sessions = state
        .supervisor_registry
        .lock()
        .map(|r| r.count())
        .unwrap_or(0);

    let dismissed = dismissed_marker(&state).exists();
    let intro_seen = intro_seen_marker(&state).exists();

    Json(OnboardingStatus {
        onboarded,
        audit_sync,
        default_provider,
        tier,
        trial_active,
        notifications_configured,
        active_sessions,
        dismissed,
        intro_seen,
    })
}

pub(crate) async fn dismiss_onboarding(State(state): State<AppState>) -> impl IntoResponse {
    let marker = dismissed_marker(&state);
    if let Some(parent) = marker.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not create config dir: {e}"),
                "DISMISS_FAILED",
            )
            .into_response();
        }
    }
    match std::fs::write(&marker, b"1") {
        Ok(()) => Json(serde_json::json!({ "dismissed": true })).into_response(),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not persist dismissal: {e}"),
            "DISMISS_FAILED",
        )
        .into_response(),
    }
}

/// Record that the first-run dashboard intro overlay has been acknowledged, so
/// it is not shown again. Mirrors `dismiss_onboarding`: a marker file in the
/// config dir, deliberately separate from `general.onboarded` and the checklist
/// dismissal (they are different user actions).
pub(crate) async fn mark_intro_seen(State(state): State<AppState>) -> impl IntoResponse {
    let marker = intro_seen_marker(&state);
    if let Some(parent) = marker.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not create config dir: {e}"),
                "INTRO_SEEN_FAILED",
            )
            .into_response();
        }
    }
    match std::fs::write(&marker, b"1") {
        Ok(()) => Json(serde_json::json!({ "intro_seen": true })).into_response(),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not persist intro-seen marker: {e}"),
            "INTRO_SEEN_FAILED",
        )
        .into_response(),
    }
}

fn dismissed_marker(state: &AppState) -> PathBuf {
    state.config_dir.join("dashboard-onboarding-dismissed")
}

fn intro_seen_marker(state: &AppState) -> PathBuf {
    state.config_dir.join("dashboard-intro-seen")
}

fn cfg_get<'a>(cfg: Option<&'a toml::Value>, path: &[&str]) -> Option<&'a toml::Value> {
    let mut cur = cfg?;
    for key in path {
        cur = cur.get(key)?;
    }
    Some(cur)
}

fn cfg_bool(cfg: Option<&toml::Value>, path: &[&str], default: bool) -> bool {
    cfg_get(cfg, path)
        .and_then(toml::Value::as_bool)
        .unwrap_or(default)
}

fn cfg_str(cfg: Option<&toml::Value>, path: &[&str]) -> Option<String> {
    cfg_get(cfg, path)
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

fn notifications_configured(cfg: Option<&toml::Value>) -> bool {
    if !cfg_bool(cfg, &["notifications", "enabled"], false) {
        return false;
    }
    [
        ["notifications", "desktop", "enabled"],
        ["notifications", "email", "enabled"],
        ["notifications", "slack", "enabled"],
        ["notifications", "telegram", "enabled"],
        ["notifications", "discord", "enabled"],
        ["notifications", "whatsapp", "enabled"],
        ["notifications", "teams", "enabled"],
        ["notifications", "pagerduty", "enabled"],
        ["notifications", "opsgenie", "enabled"],
        ["notifications", "webhook", "enabled"],
    ]
    .iter()
    .any(|path| cfg_bool(cfg, path, false))
}

#[cfg(test)]
mod tests {
    use super::notifications_configured;

    fn parse_cfg(toml_src: &str) -> toml::Value {
        toml_src.parse::<toml::Value>().expect("valid test toml")
    }

    #[test]
    fn notifications_not_configured_when_no_channels_enabled() {
        let cfg = parse_cfg(
            r#"
            [notifications]
            enabled = true
            "#,
        );
        assert!(!notifications_configured(Some(&cfg)));
    }

    #[test]
    fn notifications_configured_when_global_and_channel_enabled() {
        let cfg = parse_cfg(
            r#"
            [notifications]
            enabled = true
            [notifications.desktop]
            enabled = true
            "#,
        );
        assert!(notifications_configured(Some(&cfg)));
    }

    #[test]
    fn notifications_not_configured_when_globally_disabled() {
        let cfg = parse_cfg(
            r#"
            [notifications]
            enabled = false
            [notifications.desktop]
            enabled = true
            "#,
        );
        assert!(!notifications_configured(Some(&cfg)));
    }
}
