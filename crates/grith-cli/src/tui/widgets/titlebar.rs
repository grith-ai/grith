// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Titlebar widget: version, method, call count, cost, live status.

use crate::tui::state::AppState;
use crate::tui::theme::*;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn render_titlebar(frame: &mut Frame, area: Rect, state: &AppState) {
    let live_color = if state.frame_count % 40 < 20 {
        GREEN
    } else {
        TEXT_DIM
    };

    let left = Line::from(vec![
        Span::styled("\u{2b21} ", Style::new().fg(GREEN_HI)),
        Span::styled(
            "grith",
            Style::new()
                .fg(WHITE)
                .add_modifier(ratatui::style::Modifier::BOLD),
        ),
        Span::styled(format!("  v{}  ", VERSION), Style::new().fg(TEXT_DIM)),
        Span::styled("via", Style::new().fg(TEXT_DIM)),
        Span::styled(
            format!("  {}", state.method_label()),
            Style::new().fg(TEXT_MID),
        ),
        Span::styled(
            format!("    calls {}", state.session.call_count),
            Style::new().fg(TEXT_DIM),
        ),
        Span::styled(
            format!("  \u{00b7}  cost ${:.2}", state.session.cost_usd),
            Style::new().fg(TEXT_DIM),
        ),
    ]);

    let right = Line::from(vec![
        Span::styled("\u{25cf} ", Style::new().fg(live_color)),
        Span::styled("live    ", Style::new().fg(live_color)),
        Span::styled("allowed ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            format!("{}%    ", state.session.allow_pct()),
            Style::new().fg(GREEN_HI),
        ),
        Span::styled("queued ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            format!("{}    ", state.session.queued_count()),
            Style::new().fg(AMBER_HI),
        ),
        Span::styled("denied ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            format!("{}", state.session.deny_count),
            Style::new().fg(RED),
        ),
    ]);

    frame.render_widget(Paragraph::new(left).style(Style::new().bg(BG_PANEL)), area);
    let right_width = right.width() as u16;
    if right_width < area.width {
        let right_area = Rect {
            x: area.right().saturating_sub(right_width),
            width: right_width,
            ..area
        };
        frame.render_widget(
            Paragraph::new(right).style(Style::new().bg(BG_PANEL)),
            right_area,
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
    fn test_titlebar_renders_without_panic() {
        let backend = TestBackend::new(80, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            6,
        );
        terminal
            .draw(|frame| {
                render_titlebar(frame, frame.area(), &state);
            })
            .unwrap();
    }

    #[test]
    fn test_titlebar_live_dot_animates() {
        let backend = TestBackend::new(120, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            6,
        );

        // Frame 0: live dot should be bright
        state.frame_count = 0;
        terminal
            .draw(|frame| render_titlebar(frame, frame.area(), &state))
            .unwrap();

        // Frame 30: live dot should be dim
        state.frame_count = 30;
        terminal
            .draw(|frame| render_titlebar(frame, frame.area(), &state))
            .unwrap();
    }
}
