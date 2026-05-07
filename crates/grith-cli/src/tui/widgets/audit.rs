// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Audit log browser overlay.

use crate::tui::theme::*;
use ratatui::layout::{Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

pub fn render_audit_overlay(frame: &mut Frame, area: Rect) {
    let popup_height = (area.height * 70 / 100).max(8);
    let popup_width = 76u16.min(area.width.saturating_sub(4));
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(popup_width)) / 2,
        y: area.y + (area.height.saturating_sub(popup_height)) / 2,
        width: popup_width,
        height: popup_height,
    };

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(" Audit Log ")
        .title_style(Style::new().fg(BLUE).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(BORDER))
        .style(Style::new().bg(BG_PANEL));

    frame.render_widget(block, popup);

    let inner = popup.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    let lines = vec![Line::from(vec![Span::styled(
        "Audit log browser — connected to grith-audit.",
        Style::new().fg(TEXT_DIM),
    )])];

    frame.render_widget(
        Paragraph::new(lines).style(Style::new().bg(BG_PANEL)),
        inner,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn test_audit_overlay_renders() {
        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_audit_overlay(frame, frame.area()))
            .unwrap();
    }
}
