// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Top-level render dispatcher: lays out the five main regions and renders
//! any active modal overlay on top.

use crate::tui::state::{AppState, ModalState};
use crate::tui::theme::*;
use crate::tui::widgets::{
    audit, digest, input_bar, intercept_log, output, permission, session, statusbar, subheader,
    titlebar,
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::Style;
use ratatui::Frame;

pub fn render(frame: &mut Frame, state: &AppState) {
    // Fill background
    frame.render_widget(
        ratatui::widgets::Block::default().style(Style::new().bg(BG)),
        frame.area(),
    );

    // Show the intercept log panel only if there are entries
    let has_intercepts = !state.intercept_log.entries.is_empty();
    let intercept_height = if has_intercepts { 3u16 } else { 0 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),                // titlebar
            Constraint::Length(2),                // subheader (1 line + bottom border)
            Constraint::Min(0),                   // output panel
            Constraint::Length(intercept_height), // intercept log (0 when empty)
            Constraint::Length(1),                // input bar
            Constraint::Length(1),                // status bar
        ])
        .split(frame.area());

    titlebar::render_titlebar(frame, chunks[0], state);
    subheader::render_subheader(frame, chunks[1], state);
    output::render_output_panel(frame, chunks[2], &state.output);
    if has_intercepts {
        intercept_log::render_intercept_log(frame, chunks[3], &state.intercept_log);
    }
    input_bar::render_input_bar(frame, chunks[4], state);
    statusbar::render_statusbar(frame, chunks[5], state);

    // Modal overlays
    match &state.modal {
        ModalState::None => {}
        ModalState::PermissionDialog(req) => {
            let is_deny = matches!(
                &req.score,
                s if *s > 8.0
            );
            permission::render_permission_dialog(frame, req, is_deny, false);
        }
        ModalState::SessionSummary => {
            session::render_session_summary(frame, frame.area(), &state.session);
        }
        ModalState::DigestQueue => {
            digest::render_digest_overlay(frame, frame.area(), state);
        }
        ModalState::AuditLog => {
            audit::render_audit_overlay(frame, frame.area());
        }
        ModalState::Help => {
            render_help_overlay(frame);
        }
    }
}

fn render_help_overlay(frame: &mut Frame) {
    use ratatui::layout::Margin;
    use ratatui::style::Modifier;
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

    let area = frame.area();
    let popup_width = 50u16.min(area.width.saturating_sub(4));
    let popup_height = 18u16.min(area.height.saturating_sub(4));
    let popup = ratatui::layout::Rect {
        x: area.x + (area.width.saturating_sub(popup_width)) / 2,
        y: area.y + (area.height.saturating_sub(popup_height)) / 2,
        width: popup_width,
        height: popup_height,
    };

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(" Help ")
        .title_style(Style::new().fg(GREEN_HI).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(BORDER))
        .style(Style::new().bg(BG_PANEL));
    frame.render_widget(block, popup);

    let inner = popup.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    let lines = vec![
        Line::from(vec![
            Span::styled("[d]     ", Style::new().fg(TEXT_MID)),
            Span::styled("Open digest queue", Style::new().fg(TEXT_DIM)),
        ]),
        Line::from(vec![
            Span::styled("[s]     ", Style::new().fg(TEXT_MID)),
            Span::styled("Toggle session summary", Style::new().fg(TEXT_DIM)),
        ]),
        Line::from(vec![
            Span::styled("[a]     ", Style::new().fg(TEXT_MID)),
            Span::styled("Open audit log", Style::new().fg(TEXT_DIM)),
        ]),
        Line::from(vec![
            Span::styled("[?]     ", Style::new().fg(TEXT_MID)),
            Span::styled("Toggle help", Style::new().fg(TEXT_DIM)),
        ]),
        Line::from(vec![
            Span::styled("[q]     ", Style::new().fg(TEXT_MID)),
            Span::styled("Quit", Style::new().fg(TEXT_DIM)),
        ]),
        Line::from(vec![
            Span::styled("[esc]   ", Style::new().fg(TEXT_MID)),
            Span::styled("Dismiss overlay", Style::new().fg(TEXT_DIM)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Scroll: ", Style::new().fg(TEXT_MID)),
            Span::styled(
                "\u{2191}/k \u{2193}/j  PgUp PgDn  G=bottom  g=top",
                Style::new().fg(TEXT_DIM),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Input:  ", Style::new().fg(TEXT_MID)),
            Span::styled(
                "Enter=submit  Ctrl+C=cancel  Ctrl+U=clear",
                Style::new().fg(TEXT_DIM),
            ),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::new().bg(BG_PANEL))
            .wrap(Wrap { trim: true }),
        inner,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::{AppMode, AppState, Decision};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn test_full_render_no_modal() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new(
            AppMode::Repl {
                model: "claude-sonnet-4-5".to_string(),
            },
            17,
        );
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn test_full_render_session_summary() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            6,
        );
        state.modal = ModalState::SessionSummary;
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn test_full_render_help() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            6,
        );
        state.modal = ModalState::Help;
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn test_full_render_with_output_lines() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            17,
        );
        use crate::tui::state::OutputLine;
        state.output.push(OutputLine::Prompt {
            text: "review this repo".to_string(),
        });
        state.output.push(OutputLine::AgentText {
            text: "Reading project structure...".to_string(),
            dim: false,
        });
        state.output.push(OutputLine::TreeLine {
            text: "src/auth/mod.rs".to_string(),
        });
        state.output.push(OutputLine::Intercept {
            decision: Decision::Allow,
            detail: "3 reads allowed".to_string(),
        });
        state.output.push(OutputLine::Blank);

        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn test_render_narrow_terminal() {
        let backend = TestBackend::new(40, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            6,
        );
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }
}
