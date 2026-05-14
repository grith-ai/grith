// CLI surface generator. v1: regex extraction of clap-derive enum variants
// from `crates/grith-core/src/main.rs`. Best-effort. Captures top-level
// commands and their one-line doc comments. Detailed flag extraction is
// planned for a later pass (requires a syn-based parser).

use anyhow::{Context, Result};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

#[derive(Serialize)]
struct CliOutput {
    schema_version: u32,
    source: String,
    commands: Vec<CommandEntry>,
    /// True when this pass only extracted command names + descriptions.
    /// Flags and subcommands are not yet parsed.
    partial: bool,
}

#[derive(Serialize)]
struct CommandEntry {
    /// Variant identifier in PascalCase (e.g. "Exec").
    variant: String,
    /// Kebab-cased command name (e.g. "exec").
    name: String,
    /// One-line description from the variant's doc comment.
    description: String,
}

pub fn emit(grith_root: &Path) -> Result<Value> {
    let main_rs = grith_root.join("crates/grith-core/src/main.rs");
    let raw =
        std::fs::read_to_string(&main_rs).with_context(|| format!("read {}", main_rs.display()))?;

    let commands = extract_command_variants(&raw);

    let out = CliOutput {
        schema_version: 1,
        source: "crates/grith-core/src/main.rs".to_string(),
        commands,
        partial: true,
    };
    Ok(serde_json::to_value(out)?)
}

/// Walk the `enum Command { ... }` block and pull out each variant with its
/// doc comment. Tolerates `#[command(...)]` attributes and field bodies.
fn extract_command_variants(src: &str) -> Vec<CommandEntry> {
    // Find the `enum Command {` block.
    let Some(start_idx) = find_enum_block(src, "Command") else {
        return Vec::new();
    };
    let block_end = match_close_brace(src, start_idx).unwrap_or(src.len());
    let body = &src[start_idx..block_end];

    // Strip nested braces (variant struct bodies) so we don't accidentally
    // match doc comments inside them.
    let collapsed = collapse_braces(body);

    // Re-split into lines and walk: accumulate doc comments, then on a variant
    // identifier emit an entry.
    let mut pending_doc: Vec<String> = Vec::new();
    let mut commands = Vec::new();
    let variant_re = Regex::new(r"^\s*([A-Z][A-Za-z0-9_]*)\s*[{(,]").unwrap();

    for line in collapsed.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("///") {
            pending_doc.push(rest.trim().to_string());
            continue;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with("#[") {
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if let Some(caps) = variant_re.captures(trimmed) {
            let variant = caps[1].to_string();
            if variant == "Command" {
                continue;
            }
            let description = pending_doc.join(" ");
            pending_doc.clear();
            commands.push(CommandEntry {
                name: pascal_to_kebab(&variant),
                variant,
                description,
            });
        } else if !trimmed.starts_with('/') {
            pending_doc.clear();
        }
    }

    commands
}

fn find_enum_block(src: &str, name: &str) -> Option<usize> {
    let needle = format!("enum {name}");
    let pos = src.find(&needle)?;
    let brace_pos = src[pos..].find('{')? + pos;
    Some(brace_pos + 1)
}

fn match_close_brace(src: &str, start: usize) -> Option<usize> {
    let mut depth: i32 = 1;
    let bytes = src.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Strip the body of every `{...}` block so variant struct bodies don't leak
/// doc comments into the next variant. Outer braces are preserved so the
/// variant-recogniser regex still matches `Variant {`.
fn collapse_braces(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut depth: i32 = 0;
    for ch in src.chars() {
        match ch {
            '{' => {
                depth += 1;
                if depth == 1 {
                    out.push('{');
                }
            }
            '}' => {
                if depth == 1 {
                    out.push('}');
                }
                depth -= 1;
            }
            _ => {
                if depth == 0 {
                    out.push(ch);
                }
            }
        }
    }
    out
}

fn pascal_to_kebab(s: &str) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            out.push('-');
        }
        out.extend(ch.to_lowercase());
    }
    out
}
