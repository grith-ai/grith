// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Output panel: scrollable list of `OutputLine` entries.

use crate::tui::state::{Decision, OutputLine, OutputPanel};
use crate::tui::theme::*;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem};
use ratatui::Frame;

pub fn output_line_to_spans(line: &OutputLine) -> Line<'_> {
    match line {
        OutputLine::Prompt { text } => Line::from(vec![
            Span::styled("> ", Style::new().fg(TEXT_DIM)),
            Span::styled(text.as_str(), Style::new().fg(WHITE)),
        ]),

        OutputLine::AgentText { text, dim } => Line::from(vec![Span::styled(
            text.as_str(),
            Style::new().fg(if *dim { TEXT_MID } else { WHITE }),
        )]),

        OutputLine::TreeLine { text } => Line::from(vec![
            Span::styled("  \u{2514} ", Style::new().fg(TEXT_DIM)),
            Span::styled(text.as_str(), Style::new().fg(TEXT_MID)),
        ]),

        OutputLine::Intercept { decision, detail } => {
            let (sigil, sigil_color, label, label_color) = match decision {
                Decision::Allow => ("\u{2713}", GREEN, "", TEXT_DIM),
                Decision::Queue { .. } => ("\u{23f8}", AMBER, " queued", AMBER),
                Decision::Deny { .. } => ("\u{2715}", RED, " denied", RED),
            };
            Line::from(vec![
                Span::styled("  grith ", Style::new().fg(TEXT_DIM)),
                Span::styled(sigil, Style::new().fg(sigil_color)),
                Span::styled(label, Style::new().fg(label_color)),
                Span::styled(format!("  {}", detail), Style::new().fg(TEXT_DIM)),
            ])
        }

        OutputLine::Blank => Line::from(""),
    }
}

pub fn render_output_panel(frame: &mut Frame, area: Rect, panel: &OutputPanel) {
    let visible_height = area.height as usize;
    let total = panel.lines.len();

    let offset = if panel.follow {
        total.saturating_sub(visible_height)
    } else {
        panel.offset.min(total.saturating_sub(visible_height))
    };

    let items: Vec<ListItem> = panel
        .lines
        .iter()
        .skip(offset)
        .take(visible_height)
        .map(|l| ListItem::new(output_line_to_spans(l)))
        .collect();

    frame.render_widget(List::new(items).style(Style::new().bg(BG).fg(TEXT)), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::FilterHit;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn test_output_line_prompt() {
        let line = OutputLine::Prompt {
            text: "hello world".to_string(),
        };
        let spans = output_line_to_spans(&line);
        let text: String = spans.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("> "));
        assert!(text.contains("hello world"));
    }

    #[test]
    fn test_output_line_agent_text() {
        let line = OutputLine::AgentText {
            text: "Reading files...".to_string(),
            dim: false,
        };
        let spans = output_line_to_spans(&line);
        let text: String = spans.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("Reading files..."));
    }

    #[test]
    fn test_output_line_tree() {
        let line = OutputLine::TreeLine {
            text: "src/main.rs".to_string(),
        };
        let spans = output_line_to_spans(&line);
        let text: String = spans.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("\u{2514}"));
        assert!(text.contains("src/main.rs"));
    }

    #[test]
    fn test_output_line_intercept_allow() {
        let line = OutputLine::Intercept {
            decision: Decision::Allow,
            detail: "allowed".to_string(),
        };
        let spans = output_line_to_spans(&line);
        let text: String = spans.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("grith"));
        assert!(text.contains("\u{2713}"));
    }

    #[test]
    fn test_output_line_intercept_deny() {
        let line = OutputLine::Intercept {
            decision: Decision::Deny {
                score: 9.2,
                filters: vec![FilterHit {
                    name: "path_match".to_string(),
                    delta: 5.0,
                }],
            },
            detail: "path_match +5.0 \u{00b7} score 9.2".to_string(),
        };
        let spans = output_line_to_spans(&line);
        let text: String = spans.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("denied"));
    }

    #[test]
    fn test_render_output_panel_empty() {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        let panel = OutputPanel::new();
        terminal
            .draw(|frame| render_output_panel(frame, frame.area(), &panel))
            .unwrap();
    }

    #[test]
    fn test_render_output_panel_with_lines() {
        let backend = TestBackend::new(80, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut panel = OutputPanel::new();
        for i in 0..20 {
            panel.push(OutputLine::AgentText {
                text: format!("Line {i}"),
                dim: false,
            });
        }
        terminal
            .draw(|frame| render_output_panel(frame, frame.area(), &panel))
            .unwrap();
    }

    #[test]
    fn test_follow_mode_shows_latest() {
        let mut panel = OutputPanel::new();
        for i in 0..50 {
            panel.push(OutputLine::AgentText {
                text: format!("line {i}"),
                dim: false,
            });
        }
        // With follow=true and visible_height=10, offset should be 40
        let visible_height = 10;
        let total = panel.lines.len();
        let offset = if panel.follow {
            total.saturating_sub(visible_height)
        } else {
            panel.offset
        };
        assert_eq!(offset, 40);
    }
}
