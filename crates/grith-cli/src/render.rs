// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Terminal rendering helpers for tool calls, messages, and markdown.

use crossterm::style::{Color, Stylize};
use std::io::Write;

/// Decision type for tool call display.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Decision {
    Allowed,
    Queued,
    Denied,
}

/// Render a tool call status line to the terminal.
pub fn render_tool_call(
    w: &mut impl Write,
    action: &str,
    decision: Decision,
    score: f64,
) -> std::io::Result<()> {
    let icon = match decision {
        Decision::Allowed => "v",
        Decision::Queued => "?",
        Decision::Denied => "x",
    };

    let color = decision_color(decision);
    let status = match decision {
        Decision::Allowed => format!("{icon} score: {score:.1}"),
        Decision::Queued => format!("{icon} queued (score: {score:.1})"),
        Decision::Denied => format!("{icon} denied (score: {score:.1})"),
    };

    writeln!(w, "[agent] {action:<45} {}", colorize(&status, color))
}

/// Render streaming text output.
pub fn render_stream_token(w: &mut impl Write, token: &str) -> std::io::Result<()> {
    write!(w, "{token}")?;
    w.flush()
}

/// Render a complete assistant message.
#[allow(
    dead_code,
    reason = "public API reserved for streaming mode and plugin rendering"
)]
pub fn render_assistant_message(w: &mut impl Write, message: &str) -> std::io::Result<()> {
    let formatted = format_markdown(message);
    writeln!(w, "{formatted}")
}

/// Render an error message.
#[allow(
    dead_code,
    reason = "public API reserved for REPL error display and plugin rendering"
)]
pub fn render_error(w: &mut impl Write, message: &str) -> std::io::Result<()> {
    writeln!(w, "{}", colorize(&format!("Error: {message}"), Color::Red))
}

/// Render an info message.
pub fn render_info(w: &mut impl Write, message: &str) -> std::io::Result<()> {
    writeln!(w, "{}", colorize(message, Color::DarkGrey))
}

/// Get the color for a decision type.
fn decision_color(decision: Decision) -> Color {
    match decision {
        Decision::Allowed => Color::Green,
        Decision::Queued => Color::Yellow,
        Decision::Denied => Color::Red,
    }
}

/// Simple colorization helper.
fn colorize(text: &str, color: Color) -> String {
    text.with(color).to_string()
}

/// Basic markdown-to-terminal formatting.
/// Handles: headers, bold, code blocks, and bullet lists.
pub fn format_markdown(text: &str) -> String {
    let mut output = String::new();
    let mut in_code_block = false;

    for line in text.lines() {
        if line.starts_with("```") {
            in_code_block = !in_code_block;
            output.push_str("  ---\n");
            continue;
        }

        if in_code_block {
            output.push_str("  ");
            output.push_str(line);
            output.push('\n');
            continue;
        }

        // Headers
        if let Some(rest) = line.strip_prefix("### ") {
            output.push_str(&format!("  {rest}\n"));
        } else if let Some(rest) = line.strip_prefix("## ") {
            output.push_str(&format!(" {rest}\n"));
        } else if let Some(rest) = line.strip_prefix("# ") {
            output.push_str(&format!("{rest}\n"));
        } else {
            // Inline bold: **text** -> text (terminal can't always do bold)
            let processed = line.replace("**", "");
            output.push_str(&processed);
            output.push('\n');
        }
    }

    output
}

/// Get terminal width, defaulting to 80 columns.
pub fn terminal_width() -> u16 {
    crossterm::terminal::size().map(|(w, _)| w).unwrap_or(80)
}

/// Render a horizontal separator line.
pub fn render_separator(w: &mut impl Write) -> std::io::Result<()> {
    let width = terminal_width() as usize;
    writeln!(w, "{}", "-".repeat(width.min(80)))
}

/// Render a spinner frame (for progress indication).
pub fn spinner_frame(frame: usize) -> char {
    const FRAMES: &[char] = &['|', '/', '-', '\\'];
    FRAMES[frame % FRAMES.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_tool_call_allowed() {
        let mut buf = Vec::new();
        render_tool_call(&mut buf, "Reading src/main.rs...", Decision::Allowed, 0.2).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("[agent]"));
        assert!(output.contains("Reading src/main.rs"));
        assert!(output.contains("0.2"));
    }

    #[test]
    fn test_render_tool_call_denied() {
        let mut buf = Vec::new();
        render_tool_call(&mut buf, "rm -rf /", Decision::Denied, 9.1).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("denied"));
        assert!(output.contains("9.1"));
    }

    #[test]
    fn test_render_tool_call_queued() {
        let mut buf = Vec::new();
        render_tool_call(&mut buf, "Writing config...", Decision::Queued, 5.2).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("queued"));
    }

    #[test]
    fn test_render_stream_token() {
        let mut buf = Vec::new();
        render_stream_token(&mut buf, "hello").unwrap();
        render_stream_token(&mut buf, " world").unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "hello world");
    }

    #[test]
    fn test_format_markdown_headers() {
        let md = "# Title\n## Subtitle\n### Section\nNormal text";
        let output = format_markdown(md);
        assert!(output.contains("Title"));
        assert!(output.contains("Subtitle"));
        assert!(output.contains("Section"));
        assert!(output.contains("Normal text"));
    }

    #[test]
    fn test_format_markdown_code_block() {
        let md = "text\n```rust\nfn main() {}\n```\nmore text";
        let output = format_markdown(md);
        assert!(output.contains("fn main()"));
        assert!(output.contains("more text"));
    }

    #[test]
    fn test_format_markdown_bold() {
        let md = "This is **bold** text";
        let output = format_markdown(md);
        assert!(output.contains("This is bold text"));
    }

    #[test]
    fn test_spinner_frames() {
        assert_eq!(spinner_frame(0), '|');
        assert_eq!(spinner_frame(1), '/');
        assert_eq!(spinner_frame(4), '|'); // wraps around
    }

    #[test]
    fn test_terminal_width() {
        let width = terminal_width();
        assert!(width > 0);
    }

    #[test]
    fn test_decision_color() {
        assert_eq!(decision_color(Decision::Allowed), Color::Green);
        assert_eq!(decision_color(Decision::Queued), Color::Yellow);
        assert_eq!(decision_color(Decision::Denied), Color::Red);
    }
}
