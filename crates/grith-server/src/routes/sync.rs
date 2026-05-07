// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Sync status and team config apply endpoints (Pro feature).
//!
//! `grith pro sync` (CLI) pulls team policies, shared configs, provider keys,
//! and learned rules from the cloud API (hosted in grith-website) and writes
//! them to disk under `~/.config/grith/`. These endpoints expose that synced
//! state to the dashboard and provide a mechanism to apply synced shared
//! configs as the effective team configuration (`team-config.toml`).

use super::api_error;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use std::path::Path;

// --- Path helpers (derived from AppState.config_dir) ---

fn policies_dir(state: &AppState) -> std::path::PathBuf {
    state.config_dir.join("policies")
}

fn configs_dir(state: &AppState) -> std::path::PathBuf {
    state.config_dir.join("configs")
}

fn provider_keys_dir(state: &AppState) -> std::path::PathBuf {
    state.config_dir.join("provider-keys")
}

fn credentials_path(state: &AppState) -> std::path::PathBuf {
    state.config_dir.join("credentials.json")
}

/// Learned rules cache lives at `~/.cache/grith/learned-rules.json`.
/// Derive from config_dir by swapping `.config` → `.cache` in the path.
fn learned_rules_cache_path(state: &AppState) -> std::path::PathBuf {
    // config_dir is typically ~/.config/grith — go up two levels to ~, then .cache/grith
    state
        .config_dir
        .parent() // ~/.config
        .and_then(|p| p.parent()) // ~
        .map(|home| home.join(".cache/grith/learned-rules.json"))
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/grith/learned-rules.json"))
}

/// Count JSON files in a directory (returns 0 if directory doesn't exist).
fn count_json_files(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .count()
}

/// Read `last_synced` from the credentials file without pulling in grith-core.
fn read_last_synced(creds_path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(creds_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&raw).ok()?;
    json.get("last_synced")?.as_str().map(String::from)
}

// --- GET /api/sync/status ---

#[derive(Serialize)]
struct SyncStatusResponse {
    last_synced: Option<String>,
    policies_count: usize,
    configs_count: usize,
    provider_keys_count: usize,
    has_learned_rules: bool,
}

pub(crate) async fn sync_status(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(resp) = super::require_feature(&state, "cloud_sync", "Pro") {
        return resp;
    }

    let last_synced = read_last_synced(&credentials_path(&state));

    Json(SyncStatusResponse {
        last_synced,
        policies_count: count_json_files(&policies_dir(&state)),
        configs_count: count_json_files(&configs_dir(&state)),
        provider_keys_count: count_json_files(&provider_keys_dir(&state)),
        has_learned_rules: learned_rules_cache_path(&state).exists(),
    })
    .into_response()
}

// --- GET /api/sync/configs ---

#[derive(Serialize)]
struct SyncedConfigEntry {
    name: String,
    size_bytes: u64,
}

#[derive(Serialize)]
struct SyncedConfigsResponse {
    configs: Vec<SyncedConfigEntry>,
    total: usize,
}

pub(crate) async fn list_synced_configs(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(resp) = super::require_feature(&state, "cloud_sync", "Pro") {
        return resp;
    }

    let dir = configs_dir(&state);
    let mut configs = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                let name = path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let size_bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
                configs.push(SyncedConfigEntry { name, size_bytes });
            }
        }
    }
    configs.sort_by(|a, b| a.name.cmp(&b.name));

    let total = configs.len();
    Json(SyncedConfigsResponse { configs, total }).into_response()
}

// --- POST /api/sync/apply ---

#[derive(Serialize)]
struct SyncApplyResponse {
    status: String,
    configs_applied: usize,
    team_config_path: String,
}

/// Read all synced JSON config files from the configs directory, merge them
/// into a single TOML table, and write the result as `team-config.toml` so
/// that the existing config precedence system (`GET /api/config`) picks it up.
pub(crate) async fn apply_synced_configs(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(resp) = super::require_feature(&state, "cloud_sync", "Pro") {
        return resp;
    }

    let synced_dir = configs_dir(&state);
    let team_config_path = state.config_dir.join("team-config.toml");

    // Read all synced config JSON files.
    let entries = match std::fs::read_dir(&synced_dir) {
        Ok(e) => e,
        Err(_) => {
            // No configs directory — nothing to apply.
            return Json(SyncApplyResponse {
                status: "ok".into(),
                configs_applied: 0,
                team_config_path: team_config_path.display().to_string(),
            })
            .into_response();
        }
    };

    let mut merged = toml::value::Table::new();
    let mut applied = 0usize;

    // Collect and sort for deterministic merge order.
    let mut paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
        .collect();
    paths.sort();

    for path in &paths {
        let raw = match std::fs::read_to_string(path) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unreadable synced config");
                continue;
            }
        };
        let json: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unparseable synced config");
                continue;
            }
        };

        // Convert JSON object to TOML table entries and merge.
        if let serde_json::Value::Object(map) = json {
            for (key, value) in map {
                if let Ok(toml_val) = json_value_to_toml(&value) {
                    merged.insert(key, toml_val);
                }
            }
            applied += 1;
        }
    }

    // Write merged result as team-config.toml.
    let toml_value = toml::Value::Table(merged);
    let serialized = match toml::to_string_pretty(&toml_value) {
        Ok(s) => s,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to serialize team config: {e}"),
                "SYNC_APPLY_ERROR",
            )
            .into_response();
        }
    };

    if let Some(parent) = team_config_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to create config directory: {e}"),
                "SYNC_APPLY_ERROR",
            )
            .into_response();
        }
    }

    if let Err(e) = std::fs::write(&team_config_path, &serialized) {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to write team config: {e}"),
            "SYNC_APPLY_ERROR",
        )
        .into_response();
    }

    tracing::info!(
        configs_applied = applied,
        path = %team_config_path.display(),
        "applied synced configs to team-config.toml"
    );

    Json(SyncApplyResponse {
        status: "applied".into(),
        configs_applied: applied,
        team_config_path: team_config_path.display().to_string(),
    })
    .into_response()
}

/// Convert a serde_json::Value to a toml::Value.
fn json_value_to_toml(value: &serde_json::Value) -> Result<toml::Value, ()> {
    match value {
        serde_json::Value::Null => Err(()),
        serde_json::Value::Bool(b) => Ok(toml::Value::Boolean(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(toml::Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(toml::Value::Float(f))
            } else {
                Err(())
            }
        }
        serde_json::Value::String(s) => Ok(toml::Value::String(s.clone())),
        serde_json::Value::Array(arr) => {
            let items: Result<Vec<toml::Value>, ()> = arr.iter().map(json_value_to_toml).collect();
            Ok(toml::Value::Array(items?))
        }
        serde_json::Value::Object(map) => {
            let mut table = toml::value::Table::new();
            for (k, v) in map {
                if let Ok(tv) = json_value_to_toml(v) {
                    table.insert(k.clone(), tv);
                }
            }
            Ok(toml::Value::Table(table))
        }
    }
}
