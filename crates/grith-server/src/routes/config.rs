// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Configuration read/write endpoints for the dashboard.

use super::api_error;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// --- GET /api/config ---

#[derive(Serialize)]
struct ConfigResponse {
    config_scope: ConfigScopeInfo,
    proxy: ProxyConfigResponse,
    filters: Vec<FilterConfigEntry>,
}

#[derive(Serialize)]
struct ConfigScopeInfo {
    local: String,
    team: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProxyConfigResponse {
    auto_allow_threshold: f64,
    auto_deny_threshold: f64,
}

#[derive(Serialize)]
struct FilterConfigEntry {
    id: String,
    name: String,
    phase: String,
    enabled: bool,
}

#[derive(Debug, Clone)]
struct EffectiveConfig {
    proxy: ProxyConfigResponse,
    filters: HashMap<String, bool>,
}

fn local_config_path(state: &AppState) -> PathBuf {
    state.config_dir.join("config.toml")
}

fn team_config_path(state: &AppState) -> PathBuf {
    state.config_dir.join("team-config.toml")
}

fn empty_table() -> toml::Value {
    toml::Value::Table(toml::map::Map::new())
}

fn toml_num_as_f64(value: &toml::Value) -> Option<f64> {
    value
        .as_float()
        .or_else(|| value.as_integer().map(|n| n as f64))
}

fn read_toml_or_empty(path: &Path, scope: &str) -> Result<toml::Value, String> {
    if !path.exists() {
        return Ok(empty_table());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| {
        tracing::error!(path = %path.display(), scope, error = %e, "failed reading config file");
        format!("Failed to read {scope} configuration")
    })?;
    let parsed: toml::Value = toml::from_str(&raw).map_err(|e| {
        tracing::error!(path = %path.display(), scope, error = %e, "failed parsing config file");
        format!("Failed to parse {scope} configuration")
    })?;
    if parsed.is_table() {
        Ok(parsed)
    } else {
        tracing::error!(path = %path.display(), scope, "config file root is not a TOML table");
        Err(format!(
            "Invalid {scope} configuration: expected TOML table at root"
        ))
    }
}

fn write_toml(path: &Path, value: &toml::Value, scope: &str) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        tracing::error!(path = %path.display(), scope, "config path has no parent directory");
        format!("Failed to save {scope} configuration")
    })?;
    std::fs::create_dir_all(parent).map_err(|e| {
        tracing::error!(path = %parent.display(), scope, error = %e, "failed creating config directory");
        format!("Failed to save {scope} configuration")
    })?;
    let serialized = toml::to_string_pretty(value).map_err(|e| {
        tracing::error!(scope, error = %e, "failed serializing config");
        format!("Failed to save {scope} configuration")
    })?;
    std::fs::write(path, serialized).map_err(|e| {
        tracing::error!(path = %path.display(), scope, error = %e, "failed writing config file");
        format!("Failed to save {scope} configuration")
    })
}

fn extract_proxy_thresholds(value: &toml::Value) -> (Option<f64>, Option<f64>) {
    let Some(proxy) = value.get("proxy").and_then(toml::Value::as_table) else {
        return (None, None);
    };
    let allow = proxy.get("auto_allow_threshold").and_then(toml_num_as_f64);
    let deny = proxy.get("auto_deny_threshold").and_then(toml_num_as_f64);
    (allow, deny)
}

fn extract_filter_overrides(value: &toml::Value) -> HashMap<String, bool> {
    let mut out = HashMap::new();
    let Some(filters) = value
        .get("dashboard")
        .and_then(toml::Value::as_table)
        .and_then(|dashboard| dashboard.get("filters"))
        .and_then(toml::Value::as_table)
    else {
        return out;
    };
    for (key, value) in filters {
        if let Some(enabled) = value.as_bool() {
            out.insert(key.clone(), enabled);
        }
    }
    out
}

fn table_mut(value: &mut toml::Value) -> &mut toml::value::Table {
    if !value.is_table() {
        *value = empty_table();
    }
    value
        .as_table_mut()
        .expect("table_mut ensures root is table")
}

fn child_table_mut<'a>(
    parent: &'a mut toml::value::Table,
    key: &str,
) -> &'a mut toml::value::Table {
    let entry = parent
        .entry(key.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    if !entry.is_table() {
        *entry = toml::Value::Table(toml::map::Map::new());
    }
    entry
        .as_table_mut()
        .expect("child_table_mut ensures child is table")
}

#[allow(clippy::result_large_err)]
fn load_effective_config(state: &AppState) -> Result<EffectiveConfig, axum::response::Response> {
    let scoring = state.proxy.scoring_config();
    let mut filters = HashMap::new();
    for f in state.proxy.filter_info() {
        filters.insert(f.name, true);
    }

    let team_path = team_config_path(state);
    let local_path = local_config_path(state);
    let team_cfg = read_toml_or_empty(&team_path, "team").map_err(|e| {
        api_error(StatusCode::INTERNAL_SERVER_ERROR, e, "CONFIG_LOAD_ERROR").into_response()
    })?;
    let local_cfg = read_toml_or_empty(&local_path, "local").map_err(|e| {
        api_error(StatusCode::INTERNAL_SERVER_ERROR, e, "CONFIG_LOAD_ERROR").into_response()
    })?;

    let mut allow = scoring.auto_allow_threshold;
    let mut deny = scoring.auto_deny_threshold;

    let (team_allow, team_deny) = extract_proxy_thresholds(&team_cfg);
    if let Some(v) = team_allow {
        allow = v;
    }
    if let Some(v) = team_deny {
        deny = v;
    }
    let (local_allow, local_deny) = extract_proxy_thresholds(&local_cfg);
    if let Some(v) = local_allow {
        allow = v;
    }
    if let Some(v) = local_deny {
        deny = v;
    }

    for (k, v) in extract_filter_overrides(&team_cfg) {
        filters.insert(k, v);
    }
    for (k, v) in extract_filter_overrides(&local_cfg) {
        filters.insert(k, v);
    }

    Ok(EffectiveConfig {
        proxy: ProxyConfigResponse {
            auto_allow_threshold: allow,
            auto_deny_threshold: deny,
        },
        filters,
    })
}

pub(crate) async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    let effective = match load_effective_config(&state) {
        Ok(cfg) => cfg,
        Err(resp) => return resp,
    };

    let filters: Vec<FilterConfigEntry> = state
        .proxy
        .filter_info()
        .into_iter()
        .map(|f| {
            let name = f.name;
            let phase = match f.phase {
                grith_proxy::filters::FilterPhase::Static => "static",
                grith_proxy::filters::FilterPhase::Pattern => "pattern",
                grith_proxy::filters::FilterPhase::Context => "context",
            };
            FilterConfigEntry {
                id: name.clone(),
                name: name.clone(),
                phase: phase.into(),
                enabled: effective.filters.get(&name).copied().unwrap_or(true),
            }
        })
        .collect();

    Json(ConfigResponse {
        config_scope: ConfigScopeInfo {
            local: "local".into(),
            team: "team".into(),
        },
        proxy: effective.proxy,
        filters,
    })
    .into_response()
}

// --- PUT /api/config ---

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
enum ConfigScope {
    #[default]
    Local,
    Team,
}

#[derive(Deserialize)]
pub(crate) struct ConfigUpdateRequest {
    /// Save target: `local` (default) or `team`.
    #[serde(default)]
    scope: ConfigScope,
    /// Filter enable/disable configuration from the dashboard.
    #[serde(default)]
    filters: Vec<FilterUpdate>,
    /// Optional threshold updates.
    #[serde(default)]
    proxy: Option<ProxyUpdate>,
}

#[derive(Deserialize)]
struct FilterUpdate {
    id: String,
    enabled: bool,
}

#[derive(Deserialize, Default)]
struct ProxyUpdate {
    auto_allow_threshold: Option<f64>,
    auto_deny_threshold: Option<f64>,
}

#[derive(Serialize)]
struct ConfigUpdateResponse {
    status: String,
    scope: ConfigScope,
    filters_updated: usize,
    proxy_updated: bool,
    message: String,
}

pub(crate) async fn update_config(
    State(state): State<AppState>,
    Json(body): Json<ConfigUpdateRequest>,
) -> impl IntoResponse {
    let known: HashSet<String> = state
        .proxy
        .filter_info()
        .into_iter()
        .map(|f| f.name)
        .collect();

    let mut unknown = Vec::new();
    for fu in &body.filters {
        if !known.contains(&fu.id) {
            unknown.push(fu.id.clone());
        }
    }
    if !unknown.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            format!("unknown filter IDs: {}", unknown.join(", ")),
            "UNKNOWN_FILTERS",
        )
        .into_response();
    }

    let effective = match load_effective_config(&state) {
        Ok(cfg) => cfg,
        Err(resp) => return resp,
    };

    let scope_label = match body.scope {
        ConfigScope::Local => "local",
        ConfigScope::Team => "team",
    };
    let path = match body.scope {
        ConfigScope::Local => local_config_path(&state),
        ConfigScope::Team => team_config_path(&state),
    };
    let mut target_cfg = match read_toml_or_empty(&path, scope_label) {
        Ok(cfg) => cfg,
        Err(e) => {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, e, "CONFIG_LOAD_ERROR")
                .into_response();
        }
    };

    for update in &body.filters {
        let root = table_mut(&mut target_cfg);
        let dashboard = child_table_mut(root, "dashboard");
        let filters = child_table_mut(dashboard, "filters");
        filters.insert(update.id.clone(), toml::Value::Boolean(update.enabled));
    }

    let mut proxy_updated = false;
    if let Some(proxy) = body.proxy {
        let (scope_allow, scope_deny) = extract_proxy_thresholds(&target_cfg);
        let allow = proxy
            .auto_allow_threshold
            .or(scope_allow)
            .unwrap_or(effective.proxy.auto_allow_threshold);
        let deny = proxy
            .auto_deny_threshold
            .or(scope_deny)
            .unwrap_or(effective.proxy.auto_deny_threshold);
        if !(0.0..=10.0).contains(&allow) || !(0.0..=10.0).contains(&deny) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "proxy thresholds must be in range [0.0, 10.0]",
                "INVALID_PROXY_THRESHOLD",
            )
            .into_response();
        }
        if allow >= deny {
            return api_error(
                StatusCode::BAD_REQUEST,
                "proxy.auto_allow_threshold must be less than proxy.auto_deny_threshold",
                "INVALID_PROXY_THRESHOLD",
            )
            .into_response();
        }
        proxy_updated = proxy.auto_allow_threshold.is_some() || proxy.auto_deny_threshold.is_some();
        if proxy_updated {
            let root = table_mut(&mut target_cfg);
            let proxy_table = child_table_mut(root, "proxy");
            proxy_table.insert(
                "auto_allow_threshold".to_string(),
                toml::Value::Float(allow),
            );
            proxy_table.insert("auto_deny_threshold".to_string(), toml::Value::Float(deny));
        }
    }

    if let Err(e) = write_toml(&path, &target_cfg, scope_label) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, e, "CONFIG_SAVE_ERROR")
            .into_response();
    }

    let updated = body.filters.len();
    tracing::info!(
        scope = ?body.scope,
        config_path = %path.display(),
        filters_updated = updated,
        proxy_updated,
        "saved dashboard config to file"
    );

    Json(ConfigUpdateResponse {
        status: "saved".into(),
        scope: body.scope,
        filters_updated: updated,
        proxy_updated,
        message:
            "Configuration saved. Team config is shared baseline; local config overrides it. Proxy threshold changes apply after daemon restart.".into(),
    })
    .into_response()
}
