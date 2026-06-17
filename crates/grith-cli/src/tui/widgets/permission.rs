// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Permission dialog overlay — rendered for quarantine (QUEUE) and auto-deny dialogs.

use crate::tui::state::PermissionRequest;
use crate::tui::theme::*;
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use serde_json::Value;

pub fn render_permission_dialog(
    frame: &mut Frame,
    req: &PermissionRequest,
    is_deny: bool,
    show_inspect: bool,
) {
    let area = centered_rect(76, 60, frame.area());
    frame.render_widget(Clear, area);

    let border_color = if is_deny { RED } else { AMBER };
    let title = if is_deny {
        " \u{2715}  AUTO-DENIED \u{2014} ATTACK BLOCKED "
    } else {
        " \u{26a0}  QUARANTINE \u{2014} REVIEW REQUIRED "
    };

    let block = Block::default()
        .title(title)
        .title_style(Style::new().fg(border_color).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border_color))
        .style(Style::new().bg(BG_PANEL));

    frame.render_widget(block, area);

    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });

    render_dialog_body(frame, inner, req, is_deny, show_inspect);
}

fn render_dialog_body(
    frame: &mut Frame,
    area: Rect,
    req: &PermissionRequest,
    is_deny: bool,
    show_inspect: bool,
) {
    let detail_height = if show_inspect { 12 } else { 9 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),             // tool call title
            Constraint::Length(1),             // score line
            Constraint::Length(2),             // type line (may wrap)
            Constraint::Length(1),             // spacer
            Constraint::Min(3),                // filter breakdown
            Constraint::Length(1),             // spacer
            Constraint::Length(1),             // composite score line
            Constraint::Length(1),             // spacer
            Constraint::Length(detail_height), // context / inspect details
            Constraint::Length(1),             // spacer
            Constraint::Length(2),             // actions
        ])
        .split(area);

    // Tool call title with process attribution
    let max_title_len = (area.width as usize).saturating_sub(2);
    let tool_line = title_with_provenance(&req.tool, &req.args, max_title_len);
    frame.render_widget(
        Paragraph::new(tool_line).style(Style::new().bg(BG_PANEL)),
        chunks[0],
    );

    // Score line
    let severity_color = if req.score > 8.0 {
        RED
    } else if req.score > 5.0 {
        AMBER
    } else {
        GREEN
    };
    let score_line = Line::from(vec![
        Span::styled("score ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            format!("{:.1}", req.score),
            Style::new().fg(severity_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  severity ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            req.severity.as_str(),
            Style::new().fg(severity_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            if req.total_items > 1 {
                format!("  item {} of {}", req.item_number, req.total_items)
            } else {
                String::new()
            },
            Style::new().fg(TEXT_DIM),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(score_line).style(Style::new().bg(BG_PANEL)),
        chunks[1],
    );

    // Type line — category + detail from inside the parentheses of tool string.
    // Extract content between first '(' and last ')'.
    let detail = req
        .tool
        .find('(')
        .and_then(|open| {
            req.tool.rfind(')').map(|close| {
                if close > open + 1 {
                    req.tool[open + 1..close].trim()
                } else {
                    ""
                }
            })
        })
        .unwrap_or("");
    let type_desc = if detail.is_empty() {
        req.call_type.clone()
    } else {
        format!("{} — {}", req.call_type, detail)
    };
    let type_line = Line::from(vec![
        Span::styled("type  ", Style::new().fg(TEXT_DIM)),
        Span::styled(type_desc, Style::new().fg(TEXT_MID)),
    ]);
    frame.render_widget(
        Paragraph::new(type_line)
            .style(Style::new().bg(BG_PANEL))
            .wrap(Wrap { trim: true }),
        chunks[2],
    );

    // Filter breakdown with bars
    render_filter_bars(frame, chunks[4], &req.filters);

    // Composite score line
    let decision_label = if is_deny { "AUTO-DENY" } else { "QUEUED" };
    let decision_color = if is_deny { RED } else { AMBER };
    let composite = Line::from(vec![
        Span::styled("composite score", Style::new().fg(TEXT_DIM)),
        Span::styled(
            format!(
                "                {:.1} \u{2192} {}",
                req.score, decision_label
            ),
            Style::new().fg(decision_color).add_modifier(Modifier::BOLD),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(composite).style(Style::new().bg(BG_PANEL)),
        chunks[6],
    );

    let mut detail_text = summary_lines(req);
    if !req.context.is_empty() {
        detail_text.push(Line::from(vec![
            Span::styled("context: ", Style::new().fg(TEXT_DIM)),
            Span::styled(req.context.as_str(), Style::new().fg(TEXT_MID)),
        ]));
    }
    if !req.reasons.is_empty() {
        detail_text.push(Line::from(vec![
            Span::styled("why queued: ", Style::new().fg(TEXT_DIM)),
            Span::styled(req.reasons[0].as_str(), Style::new().fg(TEXT_MID)),
        ]));
        if req.reasons.len() > 1 {
            detail_text.push(Line::from(vec![
                Span::styled("why queued: ", Style::new().fg(TEXT_DIM)),
                Span::styled(req.reasons[1].as_str(), Style::new().fg(TEXT_MID)),
            ]));
        }
    }
    if show_inspect {
        detail_text.push(Line::from(vec![
            Span::styled("args: ", Style::new().fg(TEXT_DIM)),
            Span::styled(req.args.as_str(), Style::new().fg(TEXT_MID)),
        ]));
        detail_text.push(Line::from(vec![
            Span::styled("id: ", Style::new().fg(TEXT_DIM)),
            Span::styled(req.id.to_string(), Style::new().fg(TEXT_DIM)),
        ]));
    } else {
        detail_text.push(Line::from(vec![Span::styled(
            "[i] Inspect shows raw args and request id",
            Style::new().fg(TEXT_DIM),
        )]));
    }
    frame.render_widget(
        Paragraph::new(detail_text)
            .style(Style::new().bg(BG_PANEL))
            .wrap(Wrap { trim: true }),
        chunks[8],
    );

    // Action row — only for QUEUE, not AUTO-DENY
    if !is_deny {
        let actions = Line::from(vec![
            Span::styled(" [a] ", Style::new().fg(GREEN_HI)),
            Span::styled("Approve   ", Style::new().fg(TEXT_MID)),
            Span::styled(" [d] ", Style::new().fg(RED)),
            Span::styled("Deny   ", Style::new().fg(TEXT_MID)),
            Span::styled(" [l] ", Style::new().fg(BLUE)),
            Span::styled("Always allow  ", Style::new().fg(TEXT_MID)),
            Span::styled(" [i] ", Style::new().fg(TEXT_MID)),
            Span::styled(
                if show_inspect {
                    "Hide details"
                } else {
                    "Inspect details"
                },
                Style::new().fg(TEXT_DIM),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(actions)
                .style(Style::new().bg(BG_PANEL))
                .wrap(Wrap { trim: true }),
            chunks[10],
        );
    } else {
        let actions = Line::from(vec![
            Span::styled(" [c] ", Style::new().fg(TEXT_MID)),
            Span::styled("Continue  ", Style::new().fg(TEXT_DIM)),
            Span::styled(" [esc] ", Style::new().fg(TEXT_MID)),
            Span::styled("Continue  ", Style::new().fg(TEXT_DIM)),
            Span::styled(" [i] ", Style::new().fg(TEXT_MID)),
            Span::styled(
                if show_inspect {
                    "Hide details"
                } else {
                    "Inspect full record"
                },
                Style::new().fg(TEXT_DIM),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(actions)
                .style(Style::new().bg(BG_PANEL))
                .wrap(Wrap { trim: true }),
            chunks[10],
        );
    }
}

fn summary_lines(req: &PermissionRequest) -> Vec<Line<'static>> {
    let provenance = parse_provenance(&req.args);
    if req.call_type == "ProcessSpawn" {
        let mut lines = process_spawn_summary(req);
        if let Some((label, value)) = provenance.process_line {
            lines.push(Line::from(vec![
                Span::styled(format!("{label}: "), Style::new().fg(TEXT_DIM)),
                Span::styled(value, Style::new().fg(TEXT_MID)),
            ]));
        }
        if let Some((label, value)) = provenance.parent_line {
            lines.push(Line::from(vec![
                Span::styled(format!("{label}: "), Style::new().fg(TEXT_DIM)),
                Span::styled(value, Style::new().fg(TEXT_MID)),
            ]));
        }
        return lines;
    }
    if req.call_type != "NetListen" {
        let mut lines = vec![Line::from(vec![Span::styled(
            "Review this request before allowing it.",
            Style::new().fg(TEXT_DIM),
        )])];
        if let Some((label, value)) = provenance.process_line {
            lines.push(Line::from(vec![
                Span::styled(format!("{label}: "), Style::new().fg(TEXT_DIM)),
                Span::styled(value, Style::new().fg(TEXT_MID)),
            ]));
        }
        if let Some((label, value)) = provenance.parent_line {
            lines.push(Line::from(vec![
                Span::styled(format!("{label}: "), Style::new().fg(TEXT_DIM)),
                Span::styled(value, Style::new().fg(TEXT_MID)),
            ]));
        }
        return lines;
    }

    let detail = req
        .tool
        .find('(')
        .and_then(|open| {
            req.tool.rfind(')').map(|close| {
                if close > open + 1 {
                    req.tool[open + 1..close].trim().to_string()
                } else {
                    String::new()
                }
            })
        })
        .unwrap_or_default();

    let (address, port) = detail
        .rsplit_once(':')
        .map(|(address, port)| (address.trim(), port.trim()))
        .unwrap_or((detail.as_str(), ""));

    // PR 5 Phase A: parse the address rather than string-equality-match so
    // IPv6 loopback/wildcard in any canonical form (`::1`, `0:0:0:0:0:0:0:1`,
    // `::ffff:127.0.0.1`) labels the same as the dotted-quad form.
    let parsed_ip = address.parse::<std::net::IpAddr>().ok();
    let is_wildcard_bind = parsed_ip.is_some_and(|ip| ip.is_unspecified());
    let is_loopback_bind =
        parsed_ip.is_some_and(|ip| ip.is_loopback()) || address.eq_ignore_ascii_case("localhost");

    let bind_meaning = if is_wildcard_bind {
        "all interfaces"
    } else if is_loopback_bind {
        "loopback only"
    } else {
        "specific interface"
    };

    let port_meaning = if port == "0" {
        "ephemeral port requested"
    } else if port.is_empty() {
        "port not shown"
    } else {
        "fixed port requested"
    };

    let risk = if is_wildcard_bind {
        "remotely reachable unless firewall or network policy blocks it"
    } else if is_loopback_bind {
        "local-only listener"
    } else {
        "reachable from networks that can access that interface"
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("bind request: ", Style::new().fg(TEXT_DIM)),
            Span::styled(detail, Style::new().fg(TEXT_MID)),
        ]),
        Line::from(vec![
            Span::styled("meaning: ", Style::new().fg(TEXT_DIM)),
            Span::styled(
                format!("{bind_meaning}, {port_meaning}"),
                Style::new().fg(TEXT_MID),
            ),
        ]),
        Line::from(vec![
            Span::styled("risk: ", Style::new().fg(TEXT_DIM)),
            Span::styled(risk.to_string(), Style::new().fg(TEXT_MID)),
        ]),
    ];
    if let Some((label, value)) = provenance.process_line {
        lines.push(Line::from(vec![
            Span::styled(format!("{label}: "), Style::new().fg(TEXT_DIM)),
            Span::styled(value, Style::new().fg(TEXT_MID)),
        ]));
    }
    if let Some((label, value)) = provenance.parent_line {
        lines.push(Line::from(vec![
            Span::styled(format!("{label}: "), Style::new().fg(TEXT_DIM)),
            Span::styled(value, Style::new().fg(TEXT_MID)),
        ]));
    }
    lines
}

struct ProvenanceLines {
    process_line: Option<(&'static str, String)>,
    parent_line: Option<(&'static str, String)>,
    /// Short summary of what the process is doing, extracted from its args.
    /// E.g., "ssh git@github.com" or "curl https://api.example.com".
    process_target: Option<String>,
}

fn parse_provenance(raw_args: &str) -> ProvenanceLines {
    let Ok(value) = serde_json::from_str::<Value>(raw_args) else {
        return ProvenanceLines {
            process_line: None,
            parent_line: None,
            process_target: None,
        };
    };
    let process_name = value.get("process").and_then(Value::as_str);
    let process = process_name.map(|process| match value.get("pid").and_then(Value::as_u64) {
        Some(pid) => ("process", format!("{process} (pid {pid})")),
        None => ("process", process.to_string()),
    });
    let parent = value
        .get("parent_process")
        .and_then(Value::as_str)
        .map(
            |parent| match value.get("parent_pid").and_then(Value::as_u64) {
                Some(pid) => ("parent", format!("{parent} (pid {pid})")),
                None => ("parent", parent.to_string()),
            },
        );

    // Extract a meaningful target from process args — e.g., the SSH
    // destination or the URL being fetched. Shows what the process is
    // connecting to, which helps the user decide on file access prompts.
    let process_target = extract_process_target(
        process_name.unwrap_or(""),
        value
            .get("process_args")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    );

    ProvenanceLines {
        process_line: process,
        parent_line: parent,
        process_target,
    }
}

/// Extract a human-readable target from a process's command-line args.
fn extract_process_target(process_name: &str, args: Vec<String>) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    match process_name {
        "ssh" => {
            // ssh args typically: [host, command...] or [-flags, host, command...]
            // Find the first arg that looks like a host (user@host or bare hostname).
            args.iter()
                .find(|a| !a.starts_with('-') && (a.contains('@') || a.contains('.')))
                .map(|host| format!("connecting to {host}"))
        }
        "curl" | "wget" => {
            // Find the first arg that looks like a URL.
            args.iter()
                .find(|a| a.starts_with("http://") || a.starts_with("https://") || a.contains('.'))
                .map(|url| format!("fetching {url}"))
        }
        "git" => {
            // Show the git subcommand (push, pull, fetch, clone, etc.)
            args.first()
                .filter(|a| !a.starts_with('-'))
                .map(|sub| format!("git {sub}"))
        }
        _ => None,
    }
}

fn process_spawn_summary(req: &PermissionRequest) -> Vec<Line<'static>> {
    let parsed = serde_json::from_str::<Value>(&req.args).ok();
    let command = parsed
        .as_ref()
        .and_then(|value| value.get("command"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let spawn_args = parsed
        .as_ref()
        .and_then(|value| value.get("spawn_args"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();

    let fallback_request = req
        .tool
        .find('(')
        .zip(req.tool.rfind(')'))
        .and_then(|(open, close)| (close > open + 1).then(|| req.tool[open + 1..close].trim()))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| req.tool.clone());

    let request = if command.is_empty() {
        fallback_request
    } else if spawn_args.is_empty() {
        command.clone()
    } else {
        format!("{command} {spawn_args}")
    };

    let binary_name = std::path::Path::new(&request)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("spawned process")
        .to_string();

    vec![
        Line::from(vec![
            Span::styled("spawned binary: ", Style::new().fg(TEXT_DIM)),
            Span::styled(binary_name, Style::new().fg(WHITE).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![Span::styled(
            "This process spawn triggered review because it is outside the session allowlist or carries extra network risk.",
            Style::new().fg(TEXT_DIM),
        )]),
        Line::from(vec![
            Span::styled("path: ", Style::new().fg(TEXT_DIM)),
            Span::styled(request, Style::new().fg(TEXT_MID)),
        ]),
    ]
}

fn render_filter_bars(frame: &mut Frame, area: Rect, filters: &[crate::tui::state::FilterHit]) {
    if filters.is_empty() || area.height == 0 {
        return;
    }

    let max_delta = filters
        .iter()
        .map(|f| f.delta.abs())
        .fold(0.0f32, f32::max)
        .max(1.0);

    let label_width = 18usize;
    let score_width = 8usize;
    let bar_width = (area.width as usize).saturating_sub(label_width + score_width + 4);

    let lines: Vec<Line> = filters
        .iter()
        .enumerate()
        .take(area.height as usize)
        .map(|(i, f)| {
            let connector = if i + 1 < filters.len() {
                "\u{251c}\u{2500} "
            } else {
                "\u{2514}\u{2500} "
            };

            let filled = ((f.delta.abs() / max_delta) * bar_width as f32) as usize;
            let empty = bar_width.saturating_sub(filled);
            let bar_color = if f.delta.abs() <= 2.0 {
                GREEN
            } else if f.delta.abs() <= 5.0 {
                AMBER
            } else {
                RED
            };

            let name_padded = format!("{:<width$}", f.name, width = label_width);

            Line::from(vec![
                Span::styled(connector, Style::new().fg(TEXT_DIM)),
                Span::styled(name_padded, Style::new().fg(TEXT_MID)),
                Span::styled("\u{2588}".repeat(filled), Style::new().fg(bar_color)),
                Span::styled("\u{2591}".repeat(empty), Style::new().fg(TEXT_DIM)),
                Span::styled(format!("  {:+.1}", f.delta), Style::new().fg(TEXT)),
            ])
        })
        .collect();

    frame.render_widget(Paragraph::new(lines).style(Style::new().bg(BG_PANEL)), area);
}

/// Render the permission review dialog inside the bottom panel area.
///
/// Used by `grith exec` to show the dialog in an expanded log panel rather
/// than as a floating overlay, so the supervised tool's terminal is never
/// interrupted.
pub fn render_permission_panel(
    frame: &mut Frame,
    area: Rect,
    req: &PermissionRequest,
    is_deny: bool,
    show_inspect: bool,
) {
    let border_color = if is_deny { RED } else { AMBER };
    let title = if is_deny {
        " \u{2715}  ATTACK BLOCKED "
    } else {
        " \u{26a0}  PERMISSION REQUIRED "
    };

    let block = Block::default()
        .title(title)
        .title_style(Style::new().fg(border_color).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border_color))
        .style(Style::new().bg(BG_PANEL));

    frame.render_widget(block, area);

    let inner = area.inner(Margin {
        horizontal: 1,
        vertical: 1,
    });
    render_panel_body(frame, inner, req, is_deny, show_inspect);
}

fn render_panel_body(
    frame: &mut Frame,
    area: Rect,
    req: &PermissionRequest,
    is_deny: bool,
    show_inspect: bool,
) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    let inspect_rows: u16 = if show_inspect { 3 } else { 0 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),            // tool title
            Constraint::Length(1),            // score + severity
            Constraint::Length(1),            // type — detail
            Constraint::Length(1),            // blank
            Constraint::Min(2),               // filter bars
            Constraint::Length(1),            // composite score → decision
            Constraint::Min(2),               // summary / reasons / context
            Constraint::Length(inspect_rows), // inspect detail (0 if hidden)
            Constraint::Length(1),            // blank
            Constraint::Length(1),            // action keys
        ])
        .split(area);

    // Tool title with process attribution
    let max_w = area.width as usize;
    let tool_line = title_with_provenance(&req.tool, &req.args, max_w);
    frame.render_widget(
        Paragraph::new(tool_line).style(Style::new().bg(BG_PANEL)),
        chunks[0],
    );

    // Score + severity
    let severity_color = if req.score > 8.0 {
        RED
    } else if req.score > 5.0 {
        AMBER
    } else {
        GREEN
    };
    let item_span = if req.total_items > 1 {
        format!("  item {} of {}", req.item_number, req.total_items)
    } else {
        String::new()
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("score ", Style::new().fg(TEXT_DIM)),
            Span::styled(
                format!("{:.1}", req.score),
                Style::new().fg(severity_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  severity ", Style::new().fg(TEXT_DIM)),
            Span::styled(
                req.severity.as_str().to_string(),
                Style::new().fg(severity_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(item_span, Style::new().fg(TEXT_DIM)),
        ]))
        .style(Style::new().bg(BG_PANEL)),
        chunks[1],
    );

    // Type — detail (truncated, no wrap)
    let detail = req
        .tool
        .find('(')
        .and_then(|open| {
            req.tool.rfind(')').map(|close| {
                if close > open + 1 {
                    req.tool[open + 1..close].trim()
                } else {
                    ""
                }
            })
        })
        .unwrap_or("");
    let type_desc = if detail.is_empty() {
        req.call_type.clone()
    } else {
        format!("{} \u{2014} {}", req.call_type, detail)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("type  ", Style::new().fg(TEXT_DIM)),
            Span::styled(
                truncate(&type_desc, max_w.saturating_sub(6)),
                Style::new().fg(TEXT_MID),
            ),
        ]))
        .style(Style::new().bg(BG_PANEL)),
        chunks[2],
    );

    // chunks[3] is blank spacer — rendered as empty

    // Filter bars
    render_filter_bars(frame, chunks[4], &req.filters);

    // Composite score → decision
    let decision_label = if is_deny { "AUTO-DENY" } else { "QUEUED" };
    let decision_color = if is_deny { RED } else { AMBER };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("composite score", Style::new().fg(TEXT_DIM)),
            Span::styled(
                format!("  {:.1} \u{2192} {}", req.score, decision_label),
                Style::new().fg(decision_color).add_modifier(Modifier::BOLD),
            ),
        ]))
        .style(Style::new().bg(BG_PANEL)),
        chunks[5],
    );

    // Summary / reasons / context / process provenance — build lines dynamically
    let mut detail_lines: Vec<Line> = Vec::new();
    let provenance = parse_provenance(&req.args);
    let bold_white = Style::new().fg(WHITE).add_modifier(Modifier::BOLD);
    if let Some((label, value)) = provenance.process_line {
        detail_lines.push(Line::from(vec![
            Span::styled(format!("{label}: "), Style::new().fg(TEXT_DIM)),
            Span::styled(value, bold_white),
        ]));
    }
    if let Some((label, value)) = provenance.parent_line {
        detail_lines.push(Line::from(vec![
            Span::styled(format!("{label}: "), Style::new().fg(TEXT_DIM)),
            Span::styled(value, bold_white),
        ]));
    }
    if let Some(target) = provenance.process_target {
        detail_lines.push(Line::from(vec![
            Span::styled("target: ", Style::new().fg(TEXT_DIM)),
            Span::styled(target, bold_white),
        ]));
    }
    if !req.reasons.is_empty() {
        detail_lines.push(Line::from(vec![
            Span::styled("why: ", Style::new().fg(TEXT_DIM)),
            Span::styled(req.reasons[0].clone(), Style::new().fg(TEXT_MID)),
        ]));
    }
    if !req.context.is_empty() {
        detail_lines.push(Line::from(vec![
            Span::styled("context: ", Style::new().fg(TEXT_DIM)),
            Span::styled(req.context.clone(), Style::new().fg(TEXT_MID)),
        ]));
    }
    if detail_lines.is_empty() {
        detail_lines.push(Line::from(vec![Span::styled(
            "Review this request before allowing it.",
            Style::new().fg(TEXT_DIM),
        )]));
    }
    frame.render_widget(
        Paragraph::new(detail_lines)
            .style(Style::new().bg(BG_PANEL))
            .wrap(Wrap { trim: true }),
        chunks[6],
    );

    // Inspect detail (chunks[7], only rendered when show_inspect and inspect_rows > 0)
    if show_inspect && inspect_rows > 0 {
        let inspect_lines = vec![
            Line::from(vec![
                Span::styled("args: ", Style::new().fg(TEXT_DIM)),
                Span::styled(
                    truncate(&req.args, max_w.saturating_sub(6)),
                    Style::new().fg(TEXT_MID),
                ),
            ]),
            Line::from(vec![
                Span::styled("id:   ", Style::new().fg(TEXT_DIM)),
                Span::styled(req.id.to_string(), Style::new().fg(TEXT_DIM)),
            ]),
        ];
        frame.render_widget(
            Paragraph::new(inspect_lines).style(Style::new().bg(BG_PANEL)),
            chunks[7],
        );
    }

    // chunks[8] blank spacer

    // Action keys (chunks[9])
    let actions = if !is_deny {
        Line::from(vec![
            Span::styled(" [a] ", Style::new().fg(GREEN_HI)),
            Span::styled("Approve  ", Style::new().fg(TEXT_MID)),
            Span::styled(" [d] ", Style::new().fg(RED)),
            Span::styled("Deny  ", Style::new().fg(TEXT_MID)),
            Span::styled(" [l] ", Style::new().fg(BLUE)),
            Span::styled("Always allow  ", Style::new().fg(TEXT_MID)),
            Span::styled(" [i] ", Style::new().fg(TEXT_MID)),
            Span::styled(
                if show_inspect {
                    "Hide details"
                } else {
                    "Inspect"
                },
                Style::new().fg(TEXT_DIM),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(" [c] ", Style::new().fg(TEXT_MID)),
            Span::styled("Continue  ", Style::new().fg(TEXT_DIM)),
            Span::styled(" [esc] ", Style::new().fg(TEXT_MID)),
            Span::styled("Continue  ", Style::new().fg(TEXT_DIM)),
            Span::styled(" [i] ", Style::new().fg(TEXT_MID)),
            Span::styled(
                if show_inspect {
                    "Hide details"
                } else {
                    "Inspect full record"
                },
                Style::new().fg(TEXT_DIM),
            ),
        ])
    };
    frame.render_widget(
        Paragraph::new(actions).style(Style::new().bg(BG_PANEL)),
        chunks[9],
    );
}

/// Build the bold title line with process attribution when available.
///
/// Produces e.g. `FileRead(/home/dan/.ssh/id_rsa)  ← ssh → git`
fn title_with_provenance(tool: &str, args: &str, max_len: usize) -> Line<'static> {
    let provenance = parse_provenance(args);
    let bold = Style::new().fg(WHITE).add_modifier(Modifier::BOLD);

    let process_name = provenance
        .process_line
        .as_ref()
        .map(|(_, v)| {
            // Strip " (pid NNN)" suffix to get just the name.
            v.find(" (pid").map_or(v.as_str(), |i| &v[..i])
        })
        .filter(|n| !n.is_empty() && !n.starts_with("fork-from-"));
    let parent_name = provenance
        .parent_line
        .as_ref()
        .map(|(_, v)| v.find(" (pid").map_or(v.as_str(), |i| &v[..i]))
        .filter(|n| !n.is_empty() && !n.starts_with("fork-from-"));

    let target_hint = provenance.process_target.as_deref().unwrap_or("");

    let suffix = match (process_name, parent_name) {
        (Some(proc), Some(parent)) if !target_hint.is_empty() => {
            format!("  \u{2190} {proc} \u{2192} {parent} ({target_hint})")
        }
        (Some(proc), Some(parent)) => format!("  \u{2190} {proc} \u{2192} {parent}"),
        (Some(proc), None) if !target_hint.is_empty() => {
            format!("  \u{2190} {proc} ({target_hint})")
        }
        (Some(proc), None) => format!("  \u{2190} {proc}"),
        _ => String::new(),
    };

    let available = max_len.saturating_sub(suffix.len());
    let tool_text = truncate(tool, available);

    if suffix.is_empty() {
        Line::from(vec![Span::styled(tool_text, bold)])
    } else {
        Line::from(vec![
            Span::styled(tool_text, bold),
            Span::styled(
                suffix,
                Style::new().fg(TEXT_MID).add_modifier(Modifier::BOLD),
            ),
        ])
    }
}

fn centered_rect(width: u16, height_pct: u16, r: Rect) -> Rect {
    let popup_height = (r.height * height_pct / 100).max(18);
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
    use crate::tui::state::FilterHit;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use uuid::Uuid;

    fn make_request(is_deny: bool) -> PermissionRequest {
        PermissionRequest {
            id: Uuid::new_v4(),
            tool: "shell_exec".to_string(),
            args: "npm install lodash".to_string(),
            score: if is_deny { 8.5 } else { 4.2 },
            filters: vec![
                FilterHit {
                    name: "cmd_structure".to_string(),
                    delta: 1.5,
                },
                FilterHit {
                    name: "dest_reputation".to_string(),
                    delta: 2.7,
                },
            ],
            reasons: vec![
                "Routine shell execution".to_string(),
                "Unknown outbound destination from command".to_string(),
            ],
            context: "Task: modernise date formatting utilities".to_string(),
            severity: if is_deny {
                "CRITICAL".to_string()
            } else {
                "medium".to_string()
            },
            call_type: "shell \u{2013} package install".to_string(),
            item_number: 1,
            total_items: 2,
        }
    }

    #[test]
    fn test_permission_dialog_queue() {
        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let req = make_request(false);
        terminal
            .draw(|frame| render_permission_dialog(frame, &req, false, false))
            .unwrap();
    }

    #[test]
    fn test_permission_dialog_deny() {
        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let req = make_request(true);
        terminal
            .draw(|frame| render_permission_dialog(frame, &req, true, false))
            .unwrap();
    }

    #[test]
    fn test_centered_rect() {
        let r = Rect::new(0, 0, 100, 50);
        let c = centered_rect(60, 60, r);
        assert!(c.x > 0);
        assert!(c.y > 0);
        assert!(c.width <= 60);
        assert!(c.x + c.width <= r.width);
        assert!(c.y + c.height <= r.height);
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world!", 8), "hello...");
    }

    #[test]
    fn test_permission_panel() {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        let req = make_request(false);
        terminal
            .draw(|frame| render_permission_panel(frame, frame.area(), &req, false, false))
            .unwrap();
    }

    #[test]
    fn test_filter_bar_colors() {
        // Low delta -> green, medium -> amber, high -> red
        let filters = vec![
            FilterHit {
                name: "low".to_string(),
                delta: 1.0,
            },
            FilterHit {
                name: "med".to_string(),
                delta: 3.5,
            },
            FilterHit {
                name: "high".to_string(),
                delta: 7.0,
            },
        ];
        let backend = TestBackend::new(80, 5);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                render_filter_bars(frame, frame.area(), &filters);
            })
            .unwrap();
    }

    #[test]
    fn title_with_provenance_shows_process_chain() {
        let args = r#"{"pid":100,"process":"ssh","parent_pid":99,"parent_process":"git"}"#;
        let line = title_with_provenance("FileRead(/home/dan/.ssh/id_rsa)", args, 120);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("ssh"), "should show ssh: {text}");
        assert!(text.contains("git"), "should show git: {text}");
        assert!(text.contains("FileRead"), "should show FileRead: {text}");
    }

    #[test]
    fn title_with_provenance_omits_fork_from() {
        let args =
            r#"{"pid":100,"process":"fork-from-99","parent_pid":99,"parent_process":"claude"}"#;
        let line = title_with_provenance("FileRead(/tmp/foo)", args, 120);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            !text.contains("fork-from"),
            "should filter fork-from: {text}"
        );
    }

    #[test]
    fn title_with_provenance_no_args() {
        let line = title_with_provenance("FileRead(/tmp/foo)", "", 80);
        assert_eq!(line.spans.len(), 1);
        assert!(line.spans[0].content.contains("FileRead"));
    }
}
