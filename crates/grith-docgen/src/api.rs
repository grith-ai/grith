// API surface generator. v1: curated TOML inventory at
// `crates/grith-docgen/data/api.toml`. Future revisions will introspect the
// axum router in `grith-server::routes` directly.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Serialize)]
struct ApiOutput {
    schema_version: u32,
    source: String,
    groups: Vec<Group>,
}

#[derive(Serialize, Deserialize)]
struct Group {
    name: String,
    description: Option<String>,
    routes: Vec<Route>,
}

#[derive(Serialize, Deserialize)]
struct Route {
    method: String,
    path: String,
    summary: String,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    ipc_only: bool,
    #[serde(default)]
    auth: Option<String>,
    #[serde(default)]
    since: Option<String>,
}

#[derive(Deserialize)]
struct ApiFile {
    groups: Vec<Group>,
}

pub fn emit(grith_root: &Path) -> Result<Value> {
    let path = grith_root.join("crates/grith-docgen/data/api.toml");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    let api: ApiFile = toml::from_str(&raw).context("parse api.toml")?;

    let out = ApiOutput {
        schema_version: 1,
        source: "crates/grith-docgen/data/api.toml (curated)".to_string(),
        groups: api.groups,
    };
    Ok(serde_json::to_value(out)?)
}
