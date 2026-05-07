// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Digest queue overlay — shows pending items for review.

use crate::tui::state::AppState;
use crate::tui::theme::*;
use ratatui::layout::{Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

pub fn render_digest_overlay(frame: &mut Frame, area: Rect, state: &AppState) {
    let popup = centered_rect(70, 70, area);
    frame.render_widget(Clear, popup);

    let count = state.digest_queue.len();
    let block = Block::default()
        .title(format!(" Digest Queue ({count} items) "))
        .title_style(Style::new().fg(AMBER_HI).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(BORDER))
        .style(Style::new().bg(BG_PANEL));

    frame.render_widget(block, popup);

    let inner = popup.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    if state.digest_queue.is_empty() {
        frame.render_widget(
            Paragraph::new("No pending items in digest queue.")
                .style(Style::new().fg(TEXT_DIM).bg(BG_PANEL)),
            inner,
        );
        return;
    }

    let lines: Vec<Line> = state
        .digest_queue
        .iter()
        .take(inner.height as usize)
        .enumerate()
        .map(|(i, req)| {
            let score_color = if req.score > 8.0 {
                RED
            } else if req.score > 5.0 {
                AMBER
            } else {
                GREEN
            };
            Line::from(vec![
                Span::styled(format!("  {:>2}. ", i + 1), Style::new().fg(TEXT_DIM)),
                Span::styled(format!("{:<20}", req.tool), Style::new().fg(TEXT_MID)),
                Span::styled(format!("{:.1}", req.score), Style::new().fg(score_color)),
                Span::styled(
                    format!("  {}", truncate(&req.args, 30)),
                    Style::new().fg(TEXT_DIM),
                ),
            ])
        })
        .collect();

    frame.render_widget(
        Paragraph::new(lines).style(Style::new().bg(BG_PANEL)),
        inner,
    );
}

fn centered_rect(width: u16, height_pct: u16, r: Rect) -> Rect {
    let popup_height = (r.height * height_pct / 100).max(8);
    let popup_width = width.min(r.width.saturating_sub(4));
    Rect {
        x: r.x + (r.width.saturating_sub(popup_width)) / 2,
        y: r.y + (r.height.saturating_sub(popup_height)) / 2,
        width: popup_width,
        height: popup_height,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else if max > 3 {
        format!("{}...", &s[..max - 3])
    } else {
        s[..max].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::{AppMode, AppState, FilterHit, PermissionRequest};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use uuid::Uuid;

    #[test]
    fn test_digest_overlay_empty() {
        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            6,
        );
        terminal
            .draw(|frame| render_digest_overlay(frame, frame.area(), &state))
            .unwrap();
    }

    #[test]
    fn test_digest_overlay_with_items() {
        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            6,
        );
        state.digest_queue.push_back(PermissionRequest {
            id: Uuid::new_v4(),
            tool: "shell_exec".to_string(),
            args: "npm install".to_string(),
            score: 4.2,
            filters: vec![FilterHit {
                name: "cmd".to_string(),
                delta: 2.0,
            }],
            reasons: vec!["Package install requires review".to_string()],
            context: "test".to_string(),
            severity: "medium".to_string(),
            call_type: "shell".to_string(),
            item_number: 1,
            total_items: 1,
        });
        terminal
            .draw(|frame| render_digest_overlay(frame, frame.area(), &state))
            .unwrap();
    }
}
