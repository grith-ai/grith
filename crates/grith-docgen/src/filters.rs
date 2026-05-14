// Build the filter inventory. We scan `crates/grith-proxy/src/filters/`
// for module files, then enrich each entry with metadata from
// `crates/grith-docgen/data/filters.toml`. If a filter module exists but is
// not in the metadata file, we emit it with the `unmapped: true` flag so
// readers know it's a source-vs-doc drift to fix.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Serialize)]
struct FiltersOutput {
    schema_version: u32,
    source: String,
    filters: Vec<FilterEntry>,
}

#[derive(Serialize)]
struct FilterEntry {
    /// Stable ordinal — the canonical filter number (1..=17) used in docs.
    ordinal: u32,
    /// Module file name (e.g. "operation_risk").
    module: String,
    /// Display name (e.g. "Operation risk scoring").
    name: String,
    /// Phase: "static" | "pattern" | "context".
    phase: String,
    /// Inclusive score range as a tuple [min, max].
    score_range: [f64; 2],
    /// Path to TOML config file (relative to grith root), if any.
    config_file: Option<String>,
    /// One-line summary.
    summary: String,
    /// True if the filter module exists in source but has no metadata entry.
    #[serde(skip_serializing_if = "is_false")]
    unmapped: bool,
    /// True if metadata is present but the module file is missing.
    #[serde(skip_serializing_if = "is_false")]
    missing_source: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Deserialize)]
struct MetaFile {
    filters: Vec<MetaEntry>,
}

#[derive(Deserialize)]
struct MetaEntry {
    ordinal: u32,
    module: String,
    name: String,
    phase: String,
    score_range: [f64; 2],
    config_file: Option<String>,
    summary: String,
}

pub fn emit(grith_root: &Path) -> Result<Value> {
    let filters_dir = grith_root.join("crates/grith-proxy/src/filters");
    let meta_path = grith_root.join("crates/grith-docgen/data/filters.toml");

    let meta_raw = std::fs::read_to_string(&meta_path)
        .with_context(|| format!("read {}", meta_path.display()))?;
    let meta: MetaFile = toml::from_str(&meta_raw).context("parse filters.toml")?;
    let mut meta_by_module: BTreeMap<String, MetaEntry> = BTreeMap::new();
    for entry in meta.filters {
        meta_by_module.insert(entry.module.clone(), entry);
    }

    // Scan source modules.
    let mut module_files: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&filters_dir)
        .with_context(|| format!("read {}", filters_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "mod.rs" {
            continue;
        }
        if let Some(stem) = name.strip_suffix(".rs") {
            module_files.push(stem.to_string());
        }
    }
    module_files.sort();

    let mut filters: Vec<FilterEntry> = Vec::new();
    let mut seen_modules: BTreeMap<String, bool> = BTreeMap::new();

    // Pass 1: emit one entry per source module, using metadata when present.
    for module in &module_files {
        seen_modules.insert(module.clone(), true);
        if let Some(meta) = meta_by_module.get(module) {
            filters.push(FilterEntry {
                ordinal: meta.ordinal,
                module: module.clone(),
                name: meta.name.clone(),
                phase: meta.phase.clone(),
                score_range: meta.score_range,
                config_file: meta.config_file.clone(),
                summary: meta.summary.clone(),
                unmapped: false,
                missing_source: false,
            });
        } else {
            filters.push(FilterEntry {
                ordinal: 0,
                module: module.clone(),
                name: titlecase(module),
                phase: "unknown".to_string(),
                score_range: [0.0, 0.0],
                config_file: None,
                summary: format!("(no metadata entry for module `{module}`)"),
                unmapped: true,
                missing_source: false,
            });
        }
    }

    // Pass 2: metadata without matching source — drift signal.
    for (module, meta) in &meta_by_module {
        if !seen_modules.contains_key(module) {
            filters.push(FilterEntry {
                ordinal: meta.ordinal,
                module: module.clone(),
                name: meta.name.clone(),
                phase: meta.phase.clone(),
                score_range: meta.score_range,
                config_file: meta.config_file.clone(),
                summary: meta.summary.clone(),
                unmapped: false,
                missing_source: true,
            });
        }
    }

    filters.sort_by_key(|f| (f.ordinal == 0, f.ordinal, f.module.clone()));

    let out = FiltersOutput {
        schema_version: 1,
        source: "crates/grith-proxy/src/filters/ + crates/grith-docgen/data/filters.toml"
            .to_string(),
        filters,
    };
    Ok(serde_json::to_value(out)?)
}

fn titlecase(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
