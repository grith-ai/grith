// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Shared utility functions for terminal output, path formatting, and session naming.

use crossterm::style::{Color, Stylize};
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

pub fn color_enabled(no_color_flag: bool) -> bool {
    if no_color_flag || std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}

pub fn derive_session_name_from_cwd() -> String {
    let raw = std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "session".to_string());
    sanitize_session_name(raw)
}

pub fn sanitize_session_name(raw: String) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_was_dash = false;
    for ch in raw.chars() {
        let keep = ch.is_ascii_alphanumeric() || ch == '-' || ch == '_';
        let mapped = if keep { ch } else { '-' };
        if mapped == '-' {
            if !last_was_dash {
                out.push(mapped);
            }
            last_was_dash = true;
        } else {
            out.push(mapped);
            last_was_dash = false;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "session".to_string()
    } else {
        trimmed
    }
}

pub fn expand_user_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

pub fn format_provider_name(provider: &str) -> &str {
    match provider {
        "openai" => "OpenAI",
        "openrouter" => "OpenRouter",
        "anthropic" => "Anthropic",
        "ollama" => "Ollama",
        other => other,
    }
}

pub fn format_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    let minutes = total / 60;
    let seconds = total % 60;
    if minutes == 0 {
        format!("{seconds}s")
    } else {
        format!("{minutes}m {seconds}s")
    }
}

pub fn display_tool_label(tool: &str) -> String {
    match tool {
        "http_request" => "net_request".to_string(),
        other => other.to_string(),
    }
}

pub fn ordered_tool_breakdown(
    breakdown: &[(String, usize)],
    max_items: usize,
) -> Vec<(String, usize)> {
    let mut merged: BTreeMap<String, usize> = BTreeMap::new();
    for (name, count) in breakdown {
        *merged.entry(display_tool_label(name)).or_insert(0) += *count;
    }

    let preferred = [
        "file_read",
        "file_write",
        "shell_exec",
        "net_request",
        "dir_list",
    ];
    let mut out = Vec::new();
    for key in preferred {
        if let Some(count) = merged.remove(key) {
            out.push((key.to_string(), count));
        }
    }

    let mut rest = merged.into_iter().collect::<Vec<_>>();
    rest.sort_by(|(a_name, a_count), (b_name, b_count)| {
        b_count.cmp(a_count).then_with(|| a_name.cmp(b_name))
    });
    out.extend(rest);
    out.truncate(max_items);
    out
}

pub fn printable_tool_rows(breakdown: &[(String, usize)]) -> Vec<(String, usize)> {
    let preferred = ["file_read", "file_write", "shell_exec", "net_request"];
    let mut by_name: BTreeMap<String, usize> = BTreeMap::new();
    for (name, count) in breakdown {
        *by_name.entry(name.clone()).or_insert(0) += *count;
    }

    let mut rows = Vec::new();
    for name in preferred {
        let count = by_name.get(name).copied().unwrap_or(0);
        rows.push((name.to_string(), count));
    }
    rows
}

pub fn print_summary_row(
    left: &str,
    right: &str,
    color: Option<Color>,
    bold: bool,
    enable_color: bool,
) {
    const LEFT_WIDTH: usize = 30;
    let line = format!("{left:<LEFT_WIDTH$}{right}");
    if enable_color {
        let styled = match color {
            Some(c) => line.with(c),
            None => line.reset(),
        };
        if bold {
            println!("{}", styled.bold());
        } else {
            println!("{styled}");
        }
        return;
    }
    println!("{line}");
}

/// Print a single-column summary line (no right column, no fixed-width padding).
pub fn print_summary_line(text: &str, color: Option<Color>, bold: bool, enable_color: bool) {
    if enable_color {
        let styled = match color {
            Some(c) => text.with(c),
            None => text.reset(),
        };
        if bold {
            println!("{}", styled.bold());
        } else {
            println!("{styled}");
        }
        return;
    }
    println!("{text}");
}

pub fn normalize_tool_call_type_label(tool_call_type: &str) -> String {
    let base = tool_call_type
        .split_once('(')
        .map(|(prefix, _)| prefix)
        .unwrap_or(tool_call_type)
        .trim();
    camel_to_snake(base)
}

pub fn camel_to_snake(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    let mut prev_is_lower_or_digit = false;
    for ch in input.chars() {
        if ch.is_ascii_uppercase() {
            if prev_is_lower_or_digit && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_is_lower_or_digit = false;
        } else if ch == ' ' || ch == '-' {
            if !out.ends_with('_') && !out.is_empty() {
                out.push('_');
            }
            prev_is_lower_or_digit = false;
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_is_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        }
    }
    out
}
