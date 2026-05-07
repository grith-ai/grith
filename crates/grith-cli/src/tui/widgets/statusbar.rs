// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Status bar widget: key hints (left), branding (right).

use crate::tui::state::{AppMode, AppState};
use crate::tui::theme::*;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

pub fn render_statusbar(frame: &mut Frame, area: Rect, state: &AppState) {
    let keys: &[(&str, &str)] = if state.passthrough {
        &[("ctrl+g", "grith menu")]
    } else {
        match &state.mode {
            AppMode::Repl { .. } => &[
                ("d", "digest"),
                ("s", "session"),
                ("a", "audit log"),
                ("ctrl+c", "cancel"),
                ("q", "quit"),
            ],
            AppMode::Supervisor { .. } => &[
                ("ctrl+g", "passthrough"),
                ("d", "digest"),
                ("s", "session"),
                ("q", "quit"),
            ],
        }
    };

    let mut spans: Vec<Span> = vec![];
    for (i, (key, desc)) in keys.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", Style::new().fg(TEXT_DIM)));
        }
        spans.push(Span::styled(
            format!("[{}]", key),
            Style::new().fg(TEXT_MID),
        ));
        spans.push(Span::styled(
            format!(" {}", desc),
            Style::new().fg(TEXT_DIM),
        ));
    }

    let branding = Span::styled("grith.ai", Style::new().fg(TEXT_DIM));

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::new().bg(BG_PANEL)),
        area,
    );
    let w = 8u16;
    if w + 2 < area.width {
        let brand_area = Rect {
            x: area.right().saturating_sub(w + 2),
            width: w,
            ..area
        };
        frame.render_widget(
            Paragraph::new(Line::from(branding)).style(Style::new().bg(BG_PANEL)),
            brand_area,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::{AppMode, AppState};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn test_statusbar_repl() {
        let backend = TestBackend::new(100, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            6,
        );
        terminal
            .draw(|frame| render_statusbar(frame, frame.area(), &state))
            .unwrap();
    }

    #[test]
    fn test_statusbar_supervisor() {
        let backend = TestBackend::new(100, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new(
            AppMode::Supervisor {
                tool: "claude-code".to_string(),
                pid: 1234,
            },
            6,
        );
        terminal
            .draw(|frame| render_statusbar(frame, frame.area(), &state))
            .unwrap();
    }
}
