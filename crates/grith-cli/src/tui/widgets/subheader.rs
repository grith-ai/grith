// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Subheader widget: method, model/PID, filter count.

use crate::tui::state::{AppMode, AppState};
use crate::tui::theme::*;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render_subheader(frame: &mut Frame, area: Rect, state: &AppState) {
    let right_label = match &state.mode {
        AppMode::Repl { model } => {
            format!("{} \u{00b7} {} filters active", model, state.filter_count)
        }
        AppMode::Supervisor { pid, .. } => {
            format!("PID {} \u{00b7} {} filters active", pid, state.filter_count)
        }
    };

    let line = Line::from(vec![
        Span::styled("  \u{2394}  ", Style::new().fg(TEXT_DIM)),
        Span::styled(state.method_label(), Style::new().fg(TEXT_MID)),
        Span::styled(format!("    {}", right_label), Style::new().fg(TEXT_DIM)),
    ]);

    frame.render_widget(
        Paragraph::new(line)
            .style(Style::new().bg(BG).fg(TEXT_DIM))
            .block(
                Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(Style::new().fg(BORDER)),
            ),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn test_subheader_repl_mode() {
        let backend = TestBackend::new(80, 2);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new(
            AppMode::Repl {
                model: "claude-sonnet-4-5".to_string(),
            },
            17,
        );
        terminal
            .draw(|frame| render_subheader(frame, frame.area(), &state))
            .unwrap();
    }

    #[test]
    fn test_subheader_supervisor_mode() {
        let backend = TestBackend::new(80, 2);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new(
            AppMode::Supervisor {
                tool: "claude-code".to_string(),
                pid: 48291,
            },
            17,
        );
        terminal
            .draw(|frame| render_subheader(frame, frame.area(), &state))
            .unwrap();
    }
}
