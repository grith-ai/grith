// Parse `config/default.toml` into a structured JSON shape that the docs site
// can render. We preserve the section nesting, infer types from the parsed
// values, and pull descriptions from preceding `#` comments via a second pass
// over the raw text (since `toml` itself does not preserve comments).

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Serialize)]
struct ConfigOutput {
    schema_version: u32,
    source: String,
    sections: Vec<Section>,
}

#[derive(Serialize)]
struct Section {
    /// Dotted path (e.g. `proxy`, `proxy.filters.reputation`).
    path: String,
    /// Free-text description harvested from comments above the [section] header.
    description: Option<String>,
    keys: Vec<Key>,
}

#[derive(Serialize)]
struct Key {
    name: String,
    /// Inferred TOML type: "string" | "integer" | "float" | "boolean" | "array" | "table".
    r#type: String,
    /// JSON-encoded default value as found in the TOML.
    default: Value,
    /// Inline `#` comment on the same line (or comment block immediately above).
    description: Option<String>,
}

pub fn emit(grith_root: &Path) -> Result<Value> {
    let path = grith_root.join("config/default.toml");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;

    let parsed: toml::Value = toml::from_str(&raw).context("parse default.toml")?;
    let comments = harvest_comments(&raw);

    let mut sections = Vec::new();
    let toml::Value::Table(root) = parsed else {
        anyhow::bail!("default.toml root is not a table");
    };

    // Emit the root scalars as a synthetic "(root)" section if present (unlikely).
    let mut root_keys = Vec::new();
    let mut nested = BTreeMap::new();
    for (k, v) in root.iter() {
        match v {
            toml::Value::Table(_) => {
                nested.insert(k.clone(), v.clone());
            }
            other => {
                root_keys.push(make_key(k, other, &comments, ""));
            }
        }
    }
    if !root_keys.is_empty() {
        sections.push(Section {
            path: "(root)".to_string(),
            description: None,
            keys: root_keys,
        });
    }

    for (k, v) in nested {
        walk_section(&k, &v, &comments, &mut sections);
    }

    let out = ConfigOutput {
        schema_version: 1,
        source: "config/default.toml".to_string(),
        sections,
    };
    Ok(serde_json::to_value(out)?)
}

fn walk_section(
    section_path: &str,
    value: &toml::Value,
    comments: &CommentIndex,
    out: &mut Vec<Section>,
) {
    let toml::Value::Table(t) = value else {
        return;
    };
    let mut keys = Vec::new();
    let mut sub_tables: Vec<(String, toml::Value)> = Vec::new();
    for (k, v) in t {
        match v {
            toml::Value::Table(_) => sub_tables.push((k.clone(), v.clone())),
            other => keys.push(make_key(k, other, comments, section_path)),
        }
    }
    out.push(Section {
        path: section_path.to_string(),
        description: comments.for_section(section_path),
        keys,
    });
    for (sub_name, sub_val) in sub_tables {
        let sub_path = format!("{section_path}.{sub_name}");
        walk_section(&sub_path, &sub_val, comments, out);
    }
}

fn make_key(name: &str, value: &toml::Value, comments: &CommentIndex, section: &str) -> Key {
    let ty = type_name(value);
    let default = toml_to_json(value);
    let description = comments.for_key(section, name);
    Key {
        name: name.to_string(),
        r#type: ty.to_string(),
        default,
        description,
    }
}

fn type_name(v: &toml::Value) -> &'static str {
    match v {
        toml::Value::String(_) => "string",
        toml::Value::Integer(_) => "integer",
        toml::Value::Float(_) => "float",
        toml::Value::Boolean(_) => "boolean",
        toml::Value::Datetime(_) => "datetime",
        toml::Value::Array(_) => "array",
        toml::Value::Table(_) => "table",
    }
}

fn toml_to_json(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::Number((*i).into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Datetime(dt) => Value::String(dt.to_string()),
        toml::Value::Array(arr) => Value::Array(arr.iter().map(toml_to_json).collect()),
        toml::Value::Table(t) => {
            let mut m = serde_json::Map::new();
            for (k, v) in t {
                m.insert(k.clone(), toml_to_json(v));
            }
            Value::Object(m)
        }
    }
}

// --- Comment harvesting -----------------------------------------------------

struct CommentIndex {
    /// Section path → description (joined comment lines immediately above `[section]`).
    sections: BTreeMap<String, String>,
    /// (section, key) → description.
    keys: BTreeMap<(String, String), String>,
}

impl CommentIndex {
    fn for_section(&self, path: &str) -> Option<String> {
        self.sections.get(path).cloned()
    }
    fn for_key(&self, section: &str, key: &str) -> Option<String> {
        self.keys.get(&(section.to_string(), key.to_string())).cloned()
    }
}

fn harvest_comments(raw: &str) -> CommentIndex {
    let mut sections: BTreeMap<String, String> = BTreeMap::new();
    let mut keys: BTreeMap<(String, String), String> = BTreeMap::new();

    let mut current_section = String::new();
    let mut pending: Vec<String> = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            // Blank line: clear pending comment block (it doesn't attach to anything below).
            pending.clear();
            continue;
        }
        if let Some(stripped) = trimmed.strip_prefix('#') {
            pending.push(stripped.trim().to_string());
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let name = trimmed.trim_start_matches('[').trim_end_matches(']').to_string();
            if !pending.is_empty() {
                sections.insert(name.clone(), pending.join(" "));
            }
            current_section = name;
            pending.clear();
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            let key_name = trimmed[..eq_pos].trim().to_string();
            // Inline comment on the same line takes priority over block comment above.
            let inline = trimmed[eq_pos + 1..]
                .splitn(2, '#')
                .nth(1)
                .map(|s| s.trim().to_string());
            let desc = inline.or_else(|| {
                if pending.is_empty() {
                    None
                } else {
                    Some(pending.join(" "))
                }
            });
            if let Some(d) = desc {
                keys.insert((current_section.clone(), key_name), d);
            }
            pending.clear();
        }
    }

    CommentIndex { sections, keys }
}
