// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Session summary screen — 2x2 grid shown on `[s]` key or session complete.

use crate::tui::state::SessionStats;
use crate::tui::theme::*;
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

pub fn render_session_summary(frame: &mut Frame, area: Rect, stats: &SessionStats) {
    frame.render_widget(Clear, area);

    let grid = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // Banner
    let banner = Paragraph::new(Line::from(vec![
        Span::styled(
            "Session complete  ",
            Style::new().fg(WHITE).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "{} actions \u{00b7} ${:.2} \u{00b7} {}% auto-allowed",
                stats.call_count,
                stats.cost_usd,
                stats.allow_pct()
            ),
            Style::new().fg(TEXT_MID),
        ),
    ]))
    .style(Style::new().bg(BG_PANEL));
    frame.render_widget(banner, grid[0]);

    // 2x2 grid
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(grid[1]);

    let left_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(cols[0]);

    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(cols[1]);

    render_card(frame, left_rows[0], "TOOL CALLS", &tool_call_rows(stats));
    render_card(
        frame,
        right_rows[0],
        "SECURITY DECISIONS",
        &security_rows(stats),
    );
    render_card(frame, left_rows[1], "MODEL & COST", &cost_rows(stats));
    render_card(frame, right_rows[1], "BUILD QUALITY", &build_rows());
}

fn render_card(frame: &mut Frame, area: Rect, title: &str, rows: &[(String, String)]) {
    let block = Block::default()
        .title(format!(" {} ", title))
        .title_style(Style::new().fg(TEXT_MID))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(BORDER))
        .style(Style::new().bg(BG_PANEL));

    frame.render_widget(block, area);

    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    let lines: Vec<Line> = rows
        .iter()
        .take(inner.height as usize)
        .map(|(label, value)| {
            Line::from(vec![
                Span::styled(format!("{:<20}", label), Style::new().fg(TEXT_DIM)),
                Span::styled(value.as_str(), Style::new().fg(WHITE)),
            ])
        })
        .collect();

    frame.render_widget(
        Paragraph::new(lines).style(Style::new().bg(BG_PANEL)),
        inner,
    );
}

fn tool_call_rows(stats: &SessionStats) -> Vec<(String, String)> {
    vec![
        ("total".to_string(), format!("{}", stats.call_count)),
        ("\u{251c}\u{2500} fs.read".to_string(), "-".to_string()),
        ("\u{251c}\u{2500} fs.write".to_string(), "-".to_string()),
        ("\u{251c}\u{2500} shell_exec".to_string(), "-".to_string()),
        ("\u{2514}\u{2500} net.request".to_string(), "-".to_string()),
    ]
}

fn security_rows(stats: &SessionStats) -> Vec<(String, String)> {
    let total = stats.call_count.max(1);
    vec![
        (
            "auto-allowed".to_string(),
            format!(
                "{} ({}%)",
                stats.allow_count,
                stats.allow_count * 100 / total
            ),
        ),
        (
            "queued / reviewed".to_string(),
            format!(
                "{} ({}%)",
                stats.queue_count,
                stats.queue_count * 100 / total
            ),
        ),
        (
            "auto-denied".to_string(),
            format!("{} ({}%)", stats.deny_count, stats.deny_count * 100 / total),
        ),
        (
            "attacks blocked".to_string(),
            format!("{}", stats.attacks_blocked),
        ),
        ("avg filter latency".to_string(), "Yes".to_string()),
    ]
}

fn cost_rows(stats: &SessionStats) -> Vec<(String, String)> {
    let provider = if stats.provider.is_empty() {
        "Anthropic".to_string()
    } else {
        stats.provider.clone()
    };
    let model = if stats.model.is_empty() {
        "-".to_string()
    } else {
        stats.model.clone()
    };
    vec![
        ("provider".to_string(), provider),
        ("model".to_string(), model),
        ("duration".to_string(), stats.duration_display()),
        (
            "input tokens".to_string(),
            format!("{}", stats.prompt_tokens),
        ),
        (
            "output tokens".to_string(),
            format!("{}", stats.completion_tokens),
        ),
        (
            "session cost".to_string(),
            format!("${:.2}", stats.cost_usd),
        ),
    ]
}

fn build_rows() -> Vec<(String, String)> {
    // Build quality is populated by post-session analysis
    vec![
        ("cargo build".to_string(), "-".to_string()),
        ("cargo test".to_string(), "-".to_string()),
        ("clippy warnings".to_string(), "-".to_string()),
        ("new files".to_string(), "-".to_string()),
        ("lines changed".to_string(), "-".to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn test_session_summary_renders() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut stats = SessionStats::new();
        stats.call_count = 47;
        stats.allow_count = 45;
        stats.queue_count = 2;
        stats.deny_count = 1;
        stats.cost_usd = 1.40;
        stats.model = "claude-sonnet-4-5".to_string();

        terminal
            .draw(|frame| render_session_summary(frame, frame.area(), &stats))
            .unwrap();
    }

    #[test]
    fn test_tool_call_rows() {
        let stats = SessionStats::new();
        let rows = tool_call_rows(&stats);
        assert!(!rows.is_empty());
        assert_eq!(rows[0].0, "total");
    }

    #[test]
    fn test_security_rows_pct() {
        let mut stats = SessionStats::new();
        stats.call_count = 100;
        stats.allow_count = 96;
        stats.queue_count = 3;
        stats.deny_count = 1;
        let rows = security_rows(&stats);
        assert!(rows[0].1.contains("96%"));
    }
}
