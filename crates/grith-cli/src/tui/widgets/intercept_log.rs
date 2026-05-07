// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Small intercept log panel: shows the last few grith proxy decisions
//! in a compact strip above the input bar.

use crate::tui::state::{Decision, InterceptLog};
use crate::tui::theme::*;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::List;
use ratatui::Frame;

pub fn render_intercept_log(frame: &mut Frame, area: Rect, log: &InterceptLog) {
    let height = area.height as usize;
    let items: Vec<_> = log
        .entries
        .iter()
        .rev()
        .take(height)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|entry| {
            let (sigil, sigil_color) = match &entry.decision {
                Decision::Allow => ("\u{2713}", GREEN),
                Decision::Queue { .. } => ("\u{23f8}", AMBER),
                Decision::Deny { .. } => ("\u{2715}", RED),
            };
            let ts = entry.timestamp.format("%H:%M:%S");
            Line::from(vec![
                Span::styled(format!("  {ts} "), Style::new().fg(TEXT_DIM)),
                Span::styled(sigil, Style::new().fg(sigil_color)),
                Span::styled(format!(" {}", entry.name), Style::new().fg(TEXT_MID)),
                Span::styled(format!("  {}", entry.detail), Style::new().fg(TEXT_DIM)),
            ])
        })
        .collect();

    frame.render_widget(List::new(items).style(Style::new().bg(BG)), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::InterceptEntry;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn test_render_empty_log() {
        let backend = TestBackend::new(80, 3);
        let mut terminal = Terminal::new(backend).unwrap();
        let log = InterceptLog::new(3);
        terminal
            .draw(|frame| render_intercept_log(frame, frame.area(), &log))
            .unwrap();
    }

    #[test]
    fn test_render_with_entries() {
        let backend = TestBackend::new(80, 3);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut log = InterceptLog::new(3);
        log.push(InterceptEntry {
            decision: Decision::Allow,
            name: "FileRead".to_string(),
            detail: "allowed".to_string(),
            timestamp: chrono::Local::now(),
        });
        log.push(InterceptEntry {
            decision: Decision::Deny {
                score: 9.0,
                filters: vec![],
            },
            name: "ShellExec".to_string(),
            detail: "score 9.0".to_string(),
            timestamp: chrono::Local::now(),
        });
        terminal
            .draw(|frame| render_intercept_log(frame, frame.area(), &log))
            .unwrap();
    }
}
