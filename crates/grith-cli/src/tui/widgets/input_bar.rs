// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Input bar widget: prompt prefix, editable text, cursor blink, right-aligned hints.

use crate::tui::state::{AppMode, AppState};
use crate::tui::theme::*;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

pub fn render_input_bar(frame: &mut Frame, area: Rect, state: &AppState) {
    let prefix = match &state.mode {
        AppMode::Repl { .. } => vec![Span::styled("\u{276f} ", Style::new().fg(TEXT_DIM))],
        AppMode::Supervisor { .. } => vec![
            Span::styled(
                format!("{} ", state.method_label()),
                Style::new().fg(TEXT_DIM),
            ),
            Span::styled("\u{276f} ", Style::new().fg(TEXT_DIM)),
        ],
    };

    let cursor_visible = state.frame_count % 22 < 11;
    let cursor = if cursor_visible {
        Span::styled("\u{2588}", Style::new().fg(TEXT))
    } else {
        Span::raw(" ")
    };

    let mut spans = prefix;
    spans.push(Span::styled(
        state.input_buffer.as_str(),
        Style::new().fg(WHITE),
    ));
    spans.push(cursor);

    let hint = "\u{2191}\u{2193} history  \u{00b7}  tab complete  \u{00b7}  ctrl+c cancel";
    let hint_span = Span::styled(hint, Style::new().fg(TEXT_DIM));

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::new().bg(BG_PANEL)),
        area,
    );

    let hint_width = hint.chars().count() as u16;
    if hint_width + 4 < area.width {
        let hint_area = Rect {
            x: area.right().saturating_sub(hint_width + 2),
            width: hint_width,
            ..area
        };
        frame.render_widget(
            Paragraph::new(Line::from(hint_span)).style(Style::new().bg(BG_PANEL)),
            hint_area,
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
    fn test_input_bar_repl() {
        let backend = TestBackend::new(120, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            6,
        );
        state.input_buffer = "hello world".to_string();
        terminal
            .draw(|frame| render_input_bar(frame, frame.area(), &state))
            .unwrap();
    }

    #[test]
    fn test_input_bar_supervisor_prefix() {
        let backend = TestBackend::new(120, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new(
            AppMode::Supervisor {
                tool: "claude-code".to_string(),
                pid: 1234,
            },
            6,
        );
        terminal
            .draw(|frame| render_input_bar(frame, frame.area(), &state))
            .unwrap();
    }

    #[test]
    fn test_cursor_blink() {
        let backend = TestBackend::new(80, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            6,
        );

        // Cursor visible at frame 0
        state.frame_count = 0;
        terminal
            .draw(|frame| render_input_bar(frame, frame.area(), &state))
            .unwrap();

        // Cursor hidden at frame 15
        state.frame_count = 15;
        terminal
            .draw(|frame| render_input_bar(frame, frame.area(), &state))
            .unwrap();
    }

    #[test]
    fn test_narrow_terminal_hides_hints() {
        let backend = TestBackend::new(30, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            6,
        );
        // Should not panic even on narrow terminal
        terminal
            .draw(|frame| render_input_bar(frame, frame.area(), &state))
            .unwrap();
    }
}
