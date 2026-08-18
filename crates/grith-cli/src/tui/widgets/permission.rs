// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Permission dialog overlay — rendered for quarantine (QUEUE) and auto-deny dialogs.

use crate::tui::state::PermissionRequest;
use crate::tui::theme::*;
use grith_digest::{PermissionReviewAction, ScopedAllowRequest};
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use serde_json::Value;

/// Mutable state for the second-step scoped permission editor.
#[derive(Debug, Clone)]
pub struct ScopeDialogState {
    /// Operation bits and editable directory.
    pub request: ScopedAllowRequest,
    focus: usize,
    /// Inline validation error from the last apply attempt.
    pub error: Option<String>,
}

impl ScopeDialogState {
    const FOCUS_COUNT: usize = 5;

    /// Create the safe operation-specific default for a permission request.
    pub fn for_request(req: &PermissionRequest) -> Option<Self> {
        if !req.scope_enabled {
            return None;
        }
        Some(Self {
            request: grith_supervisor::scoped_permissions::default_scoped_allow(&req.tool)?,
            focus: 0,
            error: None,
        })
    }

    /// Move focus to the next field or duration choice.
    pub fn focus_next(&mut self) {
        self.focus = (self.focus + 1) % Self::FOCUS_COUNT;
        self.error = None;
    }

    /// Move focus to the previous field or duration choice.
    pub fn focus_previous(&mut self) {
        self.focus = (self.focus + Self::FOCUS_COUNT - 1) % Self::FOCUS_COUNT;
        self.error = None;
    }

    /// Whether the editable directory field has focus.
    pub fn directory_focused(&self) -> bool {
        self.focus == 0
    }

    /// Whether the fixed session-duration choice has focus.
    pub fn duration_focused(&self) -> bool {
        self.focus == 4
    }

    /// Append a character to the directory field.
    pub fn push_directory_char(&mut self, ch: char) {
        self.request.directory.push(ch);
        self.error = None;
    }

    /// Remove the final character from the directory field.
    pub fn pop_directory_char(&mut self) {
        self.request.directory.pop();
        self.error = None;
    }

    /// Clear the directory field.
    pub fn clear_directory(&mut self) {
        self.request.directory.clear();
        self.error = None;
    }

    /// Toggle the focused operation checkbox.
    pub fn toggle_focused(&mut self) {
        match self.focus {
            1 => self.request.read = !self.request.read,
            2 => self.request.write = !self.request.write,
            3 => self.request.delete = !self.request.delete,
            // Persistence is not implemented, so selecting the duration row
            // reaffirms the only supported choice instead of silently
            // changing the wire request.
            4 => self.request.persist = false,
            _ => {}
        }
        self.error = None;
    }

    /// Validate the proposal and return its canonical structured action.
    pub fn apply(&mut self, req: &PermissionRequest) -> Option<PermissionReviewAction> {
        match grith_supervisor::scoped_permissions::validate_scoped_allow(&self.request, &req.tool)
        {
            Ok(validated) => {
                self.request.directory = validated.directory;
                self.error = None;
                Some(PermissionReviewAction::ScopedAllow(self.request.clone()))
            }
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }
}

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

/// Render the scoped permission editor as a centered terminal dialog.
pub fn render_scope_permission_dialog(
    frame: &mut Frame,
    req: &PermissionRequest,
    state: &ScopeDialogState,
) {
    let area = centered_rect(76, 60, frame.area());
    frame.render_widget(Clear, area);
    render_scope_container(frame, area, req, state);
}

/// Render the scoped permission editor inside the exec TUI panel.
pub fn render_scope_permission_panel(
    frame: &mut Frame,
    area: Rect,
    req: &PermissionRequest,
    state: &ScopeDialogState,
) {
    frame.render_widget(Clear, area);
    render_scope_container(frame, area, req, state);
}

/// Render the key-reference help as a centered terminal dialog.
pub fn render_permission_help_dialog(frame: &mut Frame, req: &PermissionRequest, is_deny: bool) {
    let area = centered_rect(76, 60, frame.area());
    frame.render_widget(Clear, area);
    render_help_container(frame, area, req, is_deny);
}

/// Render the key-reference help inside the exec TUI panel.
pub fn render_permission_help_panel(
    frame: &mut Frame,
    area: Rect,
    req: &PermissionRequest,
    is_deny: bool,
) {
    frame.render_widget(Clear, area);
    render_help_container(frame, area, req, is_deny);
}

fn render_help_container(frame: &mut Frame, area: Rect, req: &PermissionRequest, is_deny: bool) {
    let border_color = if is_deny { RED } else { AMBER };
    let block = Block::default()
        .title(" PERMISSION KEYS ")
        .title_style(Style::new().fg(border_color).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border_color))
        .style(Style::new().bg(BG_PANEL));
    frame.render_widget(block, area);
    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    render_help_body(frame, inner, req, is_deny);
}

fn help_line(key: &str, key_color: ratatui::style::Color, text: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {key:<7}"),
            Style::new().fg(key_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(text.to_string(), Style::new().fg(TEXT_MID)),
    ])
}

fn render_help_body(frame: &mut Frame, area: Rect, req: &PermissionRequest, is_deny: bool) {
    let mut lines: Vec<Line> = Vec::new();
    if is_deny {
        lines.push(help_line(
            "[c]",
            TEXT_MID,
            "Acknowledge the block and continue",
        ));
        lines.push(help_line(
            "[i]",
            TEXT_MID,
            "Show the full record of what was blocked",
        ));
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            " This operation scored above the auto-deny threshold and was blocked.",
            Style::new().fg(TEXT_DIM),
        )));
    } else {
        lines.push(help_line(
            "[a]",
            GREEN_HI,
            "Allow this request; the exact target stays allowed for this session",
        ));
        lines.push(help_line(
            "[d]",
            RED,
            "Block this request; identical retries are blocked for a short window",
        ));
        lines.push(help_line(
            "[l]",
            BLUE,
            "Allow and save a permanent rule for this exact target",
        ));
        if ScopeDialogState::for_request(req).is_some() {
            lines.push(help_line(
                "[s]",
                AMBER,
                "Allow a directory for operations you pick, this session only",
            ));
        }
        lines.push(help_line("[t]", RED, "Deny and stop the supervised tool"));
        lines.push(help_line(
            "[i]",
            TEXT_MID,
            "Show raw arguments and the request id",
        ));
        lines.push(help_line("[esc]", TEXT_MID, "Deny this request"));
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            " Nothing outlives the session unless saved with [l]; sensitive targets are never saved.",
            Style::new().fg(TEXT_DIM),
        )));
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        " [h/esc] Back to the request",
        Style::new().fg(TEXT_DIM),
    )));
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::new().bg(BG_PANEL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_scope_container(
    frame: &mut Frame,
    area: Rect,
    req: &PermissionRequest,
    state: &ScopeDialogState,
) {
    let block = Block::default()
        .title(" SCOPE PERMISSION ")
        .title_style(Style::new().fg(AMBER).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(AMBER))
        .style(Style::new().bg(BG_PANEL));
    frame.render_widget(block, area);
    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    render_scope_body(frame, inner, req, state);
}

fn render_scope_body(
    frame: &mut Frame,
    area: Rect,
    req: &PermissionRequest,
    state: &ScopeDialogState,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);
    let width = area.width as usize;
    let field_style = if state.directory_focused() {
        Style::new().fg(WHITE).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(TEXT_MID)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("directory: ", Style::new().fg(TEXT_DIM)),
            Span::styled(
                truncate(
                    &state.request.directory,
                    width.saturating_sub("directory: ".len() + 1),
                ),
                field_style,
            ),
            Span::styled(
                if state.directory_focused() { "▏" } else { "" },
                Style::new().fg(AMBER),
            ),
        ]))
        .style(Style::new().bg(BG_PANEL)),
        chunks[0],
    );

    let preview =
        grith_supervisor::scoped_permissions::preview_scope_path(&state.request.directory);
    let (resolved, preview_error, exists) = match preview {
        Ok(preview) => (preview.resolved_directory, None, preview.exists),
        Err(error) => (String::new(), Some(error), false),
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("resolved:  ", Style::new().fg(TEXT_DIM)),
            Span::styled(
                truncate(&resolved, width.saturating_sub("resolved:  ".len())),
                Style::new().fg(TEXT_MID),
            ),
        ]))
        .style(Style::new().bg(BG_PANEL)),
        chunks[1],
    );

    let operation_line = Line::from(vec![
        checkbox_span("read", state.request.read, state.focus == 1),
        Span::raw("   "),
        checkbox_span("write/create", state.request.write, state.focus == 2),
        Span::raw("   "),
        checkbox_span("delete/rename", state.request.delete, state.focus == 3),
    ]);
    frame.render_widget(
        Paragraph::new(operation_line).style(Style::new().bg(BG_PANEL)),
        chunks[3],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "(*) this session only",
                Style::new()
                    .fg(if state.duration_focused() {
                        WHITE
                    } else {
                        GREEN_HI
                    })
                    .add_modifier(if state.duration_focused() {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ),
            Span::styled("   not saved to the profile", Style::new().fg(TEXT_DIM)),
        ]))
        .style(Style::new().bg(BG_PANEL)),
        chunks[4],
    );

    let rename_detail = if let Some(body) = req
        .tool
        .strip_prefix("FileRename(")
        .and_then(|value| value.strip_suffix(')'))
    {
        body.split_once(" -> ").map(|(old, new)| {
            let old_path = std::path::Path::new(old);
            let new_path = std::path::Path::new(new);
            let old_parent = old_path.parent().unwrap_or(old_path);
            let new_parent = new_path.parent().unwrap_or(new_path);
            format!(
                "removes from: {}  creates in: {}",
                old_parent.display(),
                new_parent.display()
            )
        })
    } else {
        None
    };
    if let Some(detail) = rename_detail {
        frame.render_widget(
            Paragraph::new(truncate(&detail, width)).style(Style::new().fg(TEXT_DIM).bg(BG_PANEL)),
            chunks[5],
        );
    }

    let message = state
        .error
        .clone()
        .or(preview_error)
        .or_else(|| (!exists).then(|| "Warning: directory does not exist yet".to_string()));
    if let Some(message) = message {
        frame.render_widget(
            Paragraph::new(truncate(&message, width)).style(
                Style::new()
                    .fg(if state.error.is_some() { RED } else { AMBER })
                    .bg(BG_PANEL),
            ),
            chunks[6],
        );
    }

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" [tab/↑↓] ", Style::new().fg(TEXT_MID)),
            Span::styled("Select  ", Style::new().fg(TEXT_DIM)),
            Span::styled("[space] ", Style::new().fg(TEXT_MID)),
            Span::styled("Toggle  ", Style::new().fg(TEXT_DIM)),
            Span::styled("[enter] ", Style::new().fg(GREEN_HI)),
            Span::styled("Apply scope  ", Style::new().fg(TEXT_MID)),
            Span::styled("[esc] ", Style::new().fg(TEXT_MID)),
            Span::styled("Back", Style::new().fg(TEXT_DIM)),
        ]))
        .style(Style::new().bg(BG_PANEL))
        .wrap(Wrap { trim: true }),
        chunks[8],
    );
}

fn checkbox_span(label: &str, checked: bool, focused: bool) -> Span<'static> {
    Span::styled(
        format!("[{}] {label}", if checked { 'x' } else { ' ' }),
        Style::new()
            .fg(if checked { GREEN_HI } else { TEXT_MID })
            .add_modifier(if focused {
                Modifier::BOLD
            } else {
                Modifier::empty()
            }),
    )
}

/// Risk tier for an action verb — selects the badge colour on the header.
#[derive(Clone, Copy, PartialEq)]
enum VerbRole {
    /// read / list — informational, no state change.
    Read,
    /// write / append / move / link / mkdir / chown — changes state.
    Mutate,
    /// delete / chmod — destructive or permission-altering.
    Destroy,
    /// run / shell — code execution.
    Execute,
    /// connect / listen / http / dns — network egress or exposure.
    Network,
    /// ptrace / namespace / mount — privileged operation.
    Privileged,
}

impl VerbRole {
    fn color(self) -> ratatui::style::Color {
        match self {
            VerbRole::Read => BLUE,
            VerbRole::Mutate | VerbRole::Execute | VerbRole::Network => AMBER_HI,
            VerbRole::Destroy | VerbRole::Privileged => RED,
        }
    }
}

/// One labelled target line rendered under the header. `label` is empty for
/// single-target operations (the value needs no prefix).
struct TargetRow {
    label: &'static str,
    value: String,
}

/// Presentation-ready decomposition of a queued call: the action verb, its risk
/// tier, a short headline identifier (basename / host), the full target rows,
/// and any command arguments. Built once by [`call_summary`] and rendered by
/// both the exec panel and the floating dialog, so neither re-parses the raw
/// `ToolCallType` string inline.
struct CallSummary {
    verb: String,
    role: VerbRole,
    headline: String,
    targets: Vec<TargetRow>,
    args: Option<String>,
}

/// The final path component (or the whole string when there is no `/`).
fn basename_of(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return path.to_string();
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_string()
}

/// The host[:port] portion of a URL, for use as a compact headline.
fn url_host(url: &str) -> String {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme)
        .to_string()
}

/// Build a single-target summary (one path, no secondary).
fn single_target(verb: &str, role: VerbRole, path: &str) -> CallSummary {
    CallSummary {
        verb: verb.to_string(),
        role,
        headline: basename_of(path),
        targets: if path.is_empty() {
            Vec::new()
        } else {
            vec![TargetRow {
                label: "",
                value: path.to_string(),
            }]
        },
        args: None,
    }
}

/// Decompose a queued request into a verb + target(s) for display. Keyed on the
/// call-type category (`req.call_type`, the `ToolCallType` variant name), so the
/// parse of the canonical `Display` detail is unambiguous per variant.
fn call_summary(req: &PermissionRequest) -> CallSummary {
    let detail = tool_call_detail(&req.tool);
    match req.call_type.as_str() {
        "FileRead" => single_target("READ", VerbRole::Read, detail),
        "DirList" => single_target("LIST", VerbRole::Read, detail),
        "FileWrite" => single_target("WRITE", VerbRole::Mutate, detail),
        "FileAppend" => single_target("APPEND", VerbRole::Mutate, detail),
        "DirCreate" => single_target("CREATE DIR", VerbRole::Mutate, detail),
        "FileDelete" => single_target("DELETE", VerbRole::Destroy, detail),
        "FileChmod" => {
            // detail = "<path>, <octal-mode>"
            let (path, mode) = detail.rsplit_once(", ").unwrap_or((detail, ""));
            CallSummary {
                verb: "CHMOD".to_string(),
                role: VerbRole::Destroy,
                headline: basename_of(path),
                targets: vec![TargetRow {
                    label: "",
                    value: path.to_string(),
                }],
                args: (!mode.is_empty()).then(|| format!("mode {mode}")),
            }
        }
        "OwnershipChange" => {
            // detail = "<target> uid=<n> gid=<n>"
            let target = detail.split(" uid=").next().unwrap_or(detail);
            let rest = detail[target.len()..].trim().to_string();
            CallSummary {
                verb: "CHOWN".to_string(),
                role: VerbRole::Mutate,
                headline: basename_of(target),
                targets: vec![TargetRow {
                    label: "",
                    value: target.to_string(),
                }],
                args: (!rest.is_empty()).then_some(rest),
            }
        }
        "FileRename" => {
            // detail = "<old> -> <new>"
            let (old, new) = detail.split_once(" -> ").unwrap_or((detail, ""));
            CallSummary {
                verb: "MOVE".to_string(),
                role: VerbRole::Mutate,
                headline: basename_of(if new.is_empty() { old } else { new }),
                targets: vec![
                    TargetRow {
                        label: "from",
                        value: old.to_string(),
                    },
                    TargetRow {
                        label: "to",
                        value: new.to_string(),
                    },
                ],
                args: None,
            }
        }
        "FileLink" => {
            // detail = "<symbolic|hard> <link_path> -> <target>"
            let (kind, rest) = detail.split_once(' ').unwrap_or(("", detail));
            let (link_path, target) = rest.split_once(" -> ").unwrap_or((rest, ""));
            let verb = if kind == "symbolic" {
                "SYMLINK"
            } else {
                "HARD-LINK"
            };
            CallSummary {
                verb: verb.to_string(),
                role: VerbRole::Mutate,
                headline: basename_of(link_path),
                targets: vec![
                    TargetRow {
                        label: "link",
                        value: link_path.to_string(),
                    },
                    TargetRow {
                        label: "target",
                        value: target.to_string(),
                    },
                ],
                args: None,
            }
        }
        "NetConnect" => CallSummary {
            verb: "CONNECT".to_string(),
            role: VerbRole::Network,
            headline: detail.to_string(),
            targets: Vec::new(),
            args: None,
        },
        "NetListen" => CallSummary {
            verb: "LISTEN".to_string(),
            role: VerbRole::Network,
            headline: detail.to_string(),
            targets: Vec::new(),
            args: None,
        },
        "DnsQuery" => {
            // detail = "<domain> <type>"
            let (domain, qtype) = detail.split_once(' ').unwrap_or((detail, ""));
            CallSummary {
                verb: "DNS".to_string(),
                role: VerbRole::Network,
                headline: domain.to_string(),
                targets: Vec::new(),
                args: (!qtype.is_empty()).then(|| format!("{qtype} record")),
            }
        }
        "HttpRequest" => {
            // detail = "<method> <url>"
            let (method, url) = detail.split_once(' ').unwrap_or(("", detail));
            let verb = if method.is_empty() {
                "HTTP".to_string()
            } else {
                format!("HTTP {method}")
            };
            CallSummary {
                verb,
                role: VerbRole::Network,
                headline: url_host(url),
                targets: if url.is_empty() {
                    Vec::new()
                } else {
                    vec![TargetRow {
                        label: "",
                        value: url.to_string(),
                    }]
                },
                args: None,
            }
        }
        "ProcessSpawn" | "ShellExec" => spawn_summary(req, detail),
        "CrossProcessAccess" => {
            // detail = "<op> target_pid=<n>"
            let (op, pid) = detail.split_once(" target_pid=").unwrap_or((detail, ""));
            CallSummary {
                verb: "INSPECT PROC".to_string(),
                role: VerbRole::Privileged,
                headline: if pid.is_empty() {
                    op.to_string()
                } else {
                    format!("pid {pid}")
                },
                targets: Vec::new(),
                args: (!op.is_empty()).then(|| format!("via {op}")),
            }
        }
        "NamespaceOp" => {
            // detail = "<syscall> flags=0x.."
            let (syscall, flags) = detail.split_once(" flags=").unwrap_or((detail, ""));
            CallSummary {
                verb: "NAMESPACE".to_string(),
                role: VerbRole::Privileged,
                headline: syscall.to_string(),
                targets: Vec::new(),
                args: (!flags.is_empty()).then(|| format!("flags {flags}")),
            }
        }
        "FilesystemMutation" => {
            // detail = "<op> src=<s> target=<t> fstype=<f>"
            let op = detail.split_whitespace().next().unwrap_or("mount");
            let between = |start: &str, end: &str| -> String {
                let Some(from) = detail.find(start) else {
                    return String::new();
                };
                let rest = &detail[from + start.len()..];
                let slice = rest.find(end).map_or(rest, |e| &rest[..e]);
                slice.trim().to_string()
            };
            let target = between("target=", " fstype=");
            let source = between("src=", " target=");
            let mut targets = vec![TargetRow {
                label: "",
                value: target.clone(),
            }];
            if !source.is_empty() {
                targets.push(TargetRow {
                    label: "from",
                    value: source,
                });
            }
            CallSummary {
                verb: op.to_uppercase(),
                role: VerbRole::Privileged,
                headline: basename_of(&target),
                targets,
                args: None,
            }
        }
        other => single_target(&other.to_uppercase(), VerbRole::Mutate, detail),
    }
}

/// Decompose a `ProcessSpawn` / `ShellExec` request. Prefers the structured
/// JSON `command` / `spawn_args` (unambiguous even when a path contains a
/// space); falls back to splitting the `Display` detail on the first space.
fn spawn_summary(req: &PermissionRequest, detail: &str) -> CallSummary {
    let parsed = serde_json::from_str::<Value>(&req.args).ok();
    let json_command = parsed
        .as_ref()
        .and_then(|v| v.get("command"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let json_args = parsed
        .as_ref()
        .and_then(|v| v.get("spawn_args"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        });

    let (command, args) = match json_command {
        Some(cmd) => (cmd.to_string(), json_args.unwrap_or_default()),
        None => match detail.split_once(char::is_whitespace) {
            Some((cmd, rest)) => (cmd.to_string(), rest.trim().to_string()),
            None => (detail.to_string(), String::new()),
        },
    };

    let verb = if req.call_type == "ShellExec" {
        "SHELL"
    } else {
        "RUN"
    };
    CallSummary {
        verb: verb.to_string(),
        role: VerbRole::Execute,
        headline: basename_of(&command),
        targets: if command.is_empty() {
            Vec::new()
        } else {
            vec![TargetRow {
                label: "",
                value: command,
            }]
        },
        args: (!args.is_empty()).then_some(args),
    }
}

/// Render a [`CallSummary`] into header + target + args lines: a bold,
/// risk-coloured verb badge next to the identifier, then each full target on
/// its own line, middle-truncated so the basename / host always survives.
fn call_block_lines(summary: &CallSummary, width: usize) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();

    // Header: bold verb badge + bold identifier.
    let head_budget = width
        .saturating_sub(summary.verb.chars().count() + 2)
        .max(4);
    let headline = truncate_middle(&summary.headline, head_budget);
    lines.push(Line::from(vec![
        Span::styled(
            summary.verb.clone(),
            Style::new()
                .fg(summary.role.color())
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            headline,
            Style::new().fg(WHITE).add_modifier(Modifier::BOLD),
        ),
    ]));

    // Target rows.
    for row in &summary.targets {
        let mut spans = vec![Span::styled("  ", Style::new().fg(TEXT_DIM))];
        let mut budget = width.saturating_sub(2);
        if !row.label.is_empty() {
            let label = format!("{}  ", row.label);
            budget = budget.saturating_sub(label.chars().count());
            spans.push(Span::styled(label, Style::new().fg(TEXT_DIM)));
        }
        let budget = budget.max(4);
        let value = if is_path_like(&row.value) {
            shorten_path_middle(&row.value, budget)
        } else {
            truncate_middle(&row.value, budget)
        };
        spans.push(Span::styled(value, Style::new().fg(TEXT_MID)));
        lines.push(Line::from(spans));
    }

    // Command arguments.
    if let Some(args) = &summary.args {
        let label = "  args  ";
        let budget = width.saturating_sub(label.chars().count()).max(4);
        lines.push(Line::from(vec![
            Span::styled(label, Style::new().fg(TEXT_DIM)),
            Span::styled(truncate_middle(args, budget), Style::new().fg(TEXT_MID)),
        ]));
    }

    lines
}

fn render_dialog_body(
    frame: &mut Frame,
    area: Rect,
    req: &PermissionRequest,
    is_deny: bool,
    show_inspect: bool,
) {
    let detail_height = if show_inspect { 12 } else { 9 };
    let max_w = (area.width as usize).saturating_sub(2);
    let summary = call_summary(req);
    let call_lines = call_block_lines(&summary, max_w);
    let call_rows = (call_lines.len() as u16).clamp(1, 4);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(call_rows),     // action verb + target(s)
            Constraint::Length(1),             // score line
            Constraint::Length(0),             // (former type line — folded into the header)
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

    // Action verb + target(s)
    frame.render_widget(
        Paragraph::new(call_lines).style(Style::new().bg(BG_PANEL)),
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
    if let Some(note) = unresolved_ip_note_line(&req.tool) {
        detail_text.push(note);
    }
    if !req.context.is_empty() {
        detail_text.push(Line::from(vec![
            Span::styled("context: ", Style::new().fg(TEXT_DIM)),
            Span::styled(req.context.as_str(), Style::new().fg(TEXT_MID)),
        ]));
    }
    for reason in visible_reasons(req).into_iter().take(2) {
        detail_text.push(Line::from(vec![
            Span::styled("why queued: ", Style::new().fg(TEXT_DIM)),
            Span::styled(reason, Style::new().fg(TEXT_MID)),
        ]));
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
        let mut actions = vec![
            Span::styled(" [a] ", Style::new().fg(GREEN_HI)),
            Span::styled("Approve   ", Style::new().fg(TEXT_MID)),
            Span::styled(" [d] ", Style::new().fg(RED)),
            Span::styled("Deny   ", Style::new().fg(TEXT_MID)),
            Span::styled(" [l] ", Style::new().fg(BLUE)),
            Span::styled("Always allow  ", Style::new().fg(TEXT_MID)),
        ];
        if ScopeDialogState::for_request(req).is_some() {
            actions.extend([
                Span::styled(" [s] ", Style::new().fg(AMBER)),
                Span::styled("Scope...  ", Style::new().fg(TEXT_MID)),
            ]);
        }
        actions.extend([
            Span::styled(" [i] ", Style::new().fg(TEXT_MID)),
            Span::styled(
                if show_inspect {
                    "Hide details"
                } else {
                    "Inspect details"
                },
                Style::new().fg(TEXT_DIM),
            ),
            Span::styled("  [h] ", Style::new().fg(TEXT_MID)),
            Span::styled("Help", Style::new().fg(TEXT_DIM)),
        ]);
        frame.render_widget(
            Paragraph::new(Line::from(actions))
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
            Span::styled("  [h] ", Style::new().fg(TEXT_MID)),
            Span::styled("Help", Style::new().fg(TEXT_DIM)),
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
        let mut lines = vec![Line::from(vec![Span::styled(
            "Held because this spawn is outside the session allowlist or carries extra network risk.",
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
    let max_w = area.width as usize;
    let summary = call_summary(req);
    let call_lines = call_block_lines(&summary, max_w);
    let call_rows = (call_lines.len() as u16).clamp(1, 3);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(call_rows),    // action verb + target(s)
            Constraint::Length(1),            // score + severity
            Constraint::Length(0),            // (former type line — folded into the header)
            Constraint::Length(1),            // blank
            Constraint::Min(2),               // filter bars
            Constraint::Length(1),            // composite score → decision
            Constraint::Min(2),               // summary / reasons / context
            Constraint::Length(inspect_rows), // inspect detail (0 if hidden)
            Constraint::Length(1),            // blank
            Constraint::Length(1),            // action keys
        ])
        .split(area);

    // Action verb + target(s)
    frame.render_widget(
        Paragraph::new(call_lines).style(Style::new().bg(BG_PANEL)),
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

    // chunks[2] (former type line) is folded into the header; chunks[3] is a
    // blank spacer — both render as empty.

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
    if let Some(reason) = primary_reason(req) {
        detail_lines.push(Line::from(vec![
            Span::styled("why: ", Style::new().fg(TEXT_DIM)),
            Span::styled(reason, Style::new().fg(TEXT_MID)),
        ]));
    }
    if let Some(note) = unresolved_ip_note_line(&req.tool) {
        detail_lines.push(note);
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
        let mut actions = vec![
            Span::styled(" [a] ", Style::new().fg(GREEN_HI)),
            Span::styled("Approve  ", Style::new().fg(TEXT_MID)),
            Span::styled(" [d] ", Style::new().fg(RED)),
            Span::styled("Deny  ", Style::new().fg(TEXT_MID)),
            Span::styled(" [l] ", Style::new().fg(BLUE)),
            Span::styled("Always allow  ", Style::new().fg(TEXT_MID)),
        ];
        if ScopeDialogState::for_request(req).is_some() {
            actions.extend([
                Span::styled(" [s] ", Style::new().fg(AMBER)),
                Span::styled("Scope...  ", Style::new().fg(TEXT_MID)),
            ]);
        }
        actions.extend([
            Span::styled(" [i] ", Style::new().fg(TEXT_MID)),
            Span::styled(
                if show_inspect {
                    "Hide details"
                } else {
                    "Inspect"
                },
                Style::new().fg(TEXT_DIM),
            ),
            Span::styled("  [h] ", Style::new().fg(TEXT_MID)),
            Span::styled("Help", Style::new().fg(TEXT_DIM)),
        ]);
        Line::from(actions)
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
            Span::styled("  [h] ", Style::new().fg(TEXT_MID)),
            Span::styled("Help", Style::new().fg(TEXT_DIM)),
        ])
    };
    frame.render_widget(
        Paragraph::new(actions).style(Style::new().bg(BG_PANEL)),
        chunks[9],
    );
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
    if s.chars().count() <= max {
        s.to_string()
    } else if max > 3 {
        format!("{}...", take_chars(s, max - 3))
    } else {
        take_chars(s, max)
    }
}

/// Note shown when a network request is still displayed as a bare IP address.
///
/// By the time a `NetConnect` reaches a review dialog its address has already
/// been through every name-attribution source — DNS answers observed during
/// the session, a fresh re-resolve of the profile's trusted destinations, and
/// reverse DNS. A bare IP here means all of them came up empty. Saying so
/// makes the raw address read as a deliberate finding rather than a display
/// bug. (Hostname and candidate-list attributions never parse as an IP, so
/// they get no note.)
const UNRESOLVED_IP_NOTE: &str = "unresolved IP \u{2014} not seen in any DNS answer this session, \
     no reverse-DNS name, and not matching the profile's trusted destinations";

/// Whether this request is a `NetConnect` whose destination is a bare IP.
fn is_unresolved_ip_net_connect(tool: &str) -> bool {
    if !tool.starts_with("NetConnect") {
        return false;
    }
    let detail = tool_call_detail(tool);
    if detail.is_empty() {
        return false;
    }
    // Strip a trailing ":port"; unbracketed IPv6 with a port also parses as an
    // IPv6 literal on its own, so checking both forms covers every rendering.
    let host = detail.rsplit_once(':').map_or(detail, |(host, _)| host);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse::<std::net::IpAddr>().is_ok() || detail.parse::<std::net::IpAddr>().is_ok()
}

fn unresolved_ip_note_line(tool: &str) -> Option<Line<'static>> {
    is_unresolved_ip_net_connect(tool).then(|| {
        Line::from(vec![
            Span::styled("dns: ", Style::new().fg(TEXT_DIM)),
            Span::styled(UNRESOLVED_IP_NOTE, Style::new().fg(TEXT_DIM)),
        ])
    })
}

fn tool_call_detail(tool: &str) -> &str {
    tool.find('(')
        .and_then(|open| {
            tool.rfind(')').map(|close| {
                if close > open + 1 {
                    tool[open + 1..close].trim()
                } else {
                    ""
                }
            })
        })
        .unwrap_or("")
}

/// Keep the head and tail of `s`, dropping the middle. For argument lists the
/// tail (the target URL or final path) is usually the informative part.
fn truncate_middle(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    if max <= 3 {
        return take_chars(s, max);
    }
    let keep = max - 3;
    let head = keep / 2;
    let tail = keep - head;
    format!("{}...{}", take_chars(s, head), take_last_chars(s, tail))
}

fn shorten_path_middle(path: &str, max: usize) -> String {
    if path.chars().count() <= max {
        return path.to_string();
    }
    if max <= 3 {
        return ".".repeat(max);
    }

    // Search from the last *non-empty* component so a trailing slash
    // ("/long/path/dir/") keeps "dir/" visible instead of reducing the
    // preserved suffix to just "/".
    let trimmed = path.trim_end_matches('/');
    let search = if trimmed.is_empty() { path } else { trimmed };
    let Some(last_slash) = search.rfind('/') else {
        return truncate(path, max);
    };
    let suffix = &path[last_slash..];
    let suffix_len = suffix.chars().count();

    if suffix_len + 3 >= max {
        let filename = &path[last_slash + 1..];
        if filename.chars().count() + 4 <= max {
            return format!(".../{filename}");
        }
        return format!("...{}", take_last_chars(filename, max - 3));
    }

    let prefix_budget = max - suffix_len - 3;
    format!("{}...{suffix}", take_chars(path, prefix_budget))
}

fn is_path_like(s: &str) -> bool {
    s.starts_with('/') || s.starts_with("~/")
}

fn take_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn take_last_chars(s: &str, n: usize) -> String {
    let mut chars = s.chars().rev().take(n).collect::<Vec<_>>();
    chars.reverse();
    chars.into_iter().collect()
}

fn primary_reason(req: &PermissionRequest) -> Option<String> {
    let decision_reason = req.decision_reason.trim();
    if !decision_reason.is_empty() {
        return Some(decision_reason.to_string());
    }
    req.reasons
        .iter()
        .find(|reason| !reason.trim().is_empty())
        .map(|reason| reason.trim().to_string())
}

fn visible_reasons(req: &PermissionRequest) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(reason) = primary_reason(req) {
        out.push(reason);
    }
    for reason in req
        .reasons
        .iter()
        .map(|r| r.trim())
        .filter(|r| !r.is_empty())
    {
        if !out.iter().any(|existing| existing == reason) {
            out.push(reason.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::FilterHit;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use uuid::Uuid;

    #[test]
    fn unresolved_ip_note_only_for_raw_ip_net_connects() {
        // Raw IPv4 and IPv6 destinations get the note.
        assert!(is_unresolved_ip_net_connect(
            "NetConnect(20.26.156.210:443)"
        ));
        assert!(is_unresolved_ip_net_connect(
            "NetConnect(2607:6bc0::10:443)"
        ));
        assert!(is_unresolved_ip_net_connect(
            "NetConnect([2607:6bc0::10]:443)"
        ));
        assert!(is_unresolved_ip_net_connect("NetConnect(20.26.156.210)"));

        // Attributed hostnames, ambiguous candidate arrays, and non-network
        // calls do not.
        assert!(!is_unresolved_ip_net_connect(
            "NetConnect(api.github.com:443)"
        ));
        assert!(!is_unresolved_ip_net_connect(
            "NetConnect([\"anthropic.com\", \"claude.ai\"]:443)"
        ));
        assert!(!is_unresolved_ip_net_connect("NetConnect(localhost:443)"));
        assert!(!is_unresolved_ip_net_connect("FileRead(/etc/passwd)"));
        assert!(!is_unresolved_ip_net_connect("NetConnect()"));
    }

    fn make_request(is_deny: bool) -> PermissionRequest {
        PermissionRequest {
            id: Uuid::new_v4(),
            tool: "ShellExec(npm install lodash)".to_string(),
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
            decision_reason: "review required".to_string(),
            context: "Task: modernise date formatting utilities".to_string(),
            severity: if is_deny {
                "CRITICAL".to_string()
            } else {
                "medium".to_string()
            },
            call_type: "ShellExec".to_string(),
            item_number: 1,
            total_items: 2,
            scope_enabled: false,
        }
    }

    fn summary_for(tool: &str, call_type: &str, args: &str) -> CallSummary {
        let mut req = make_request(false);
        req.tool = tool.to_string();
        req.call_type = call_type.to_string();
        req.args = args.to_string();
        call_summary(&req)
    }

    #[test]
    fn call_summary_single_path_uses_verb_and_basename() {
        let s = summary_for("FileRead(/etc/passwd)", "FileRead", "");
        assert_eq!(s.verb, "READ");
        assert_eq!(s.headline, "passwd");
        assert_eq!(s.targets.len(), 1);
        assert_eq!(s.targets[0].value, "/etc/passwd");
        assert!(s.args.is_none());
    }

    #[test]
    fn call_summary_delete_is_destructive_tier() {
        let s = summary_for("FileDelete(/repo/target/deps/foo.o)", "FileDelete", "");
        assert_eq!(s.verb, "DELETE");
        assert_eq!(s.role.color(), RED);
    }

    #[test]
    fn call_summary_link_keeps_both_sides_labelled() {
        let s = summary_for(
            "FileLink(hard /home/dan/project/.git/objects/pack/tmp_obj_0BIXVU -> /home/dan/project/.git/objects/ab/cdef)",
            "FileLink",
            "",
        );
        assert_eq!(s.verb, "HARD-LINK");
        assert_eq!(s.headline, "tmp_obj_0BIXVU");
        assert_eq!(s.targets.len(), 2);
        assert_eq!(s.targets[0].label, "link");
        assert!(s.targets[0]
            .value
            .ends_with(".git/objects/pack/tmp_obj_0BIXVU"));
        assert_eq!(s.targets[1].label, "target");
        assert!(s.targets[1].value.ends_with(".git/objects/ab/cdef"));
    }

    #[test]
    fn call_summary_symlink_verb() {
        let s = summary_for(
            "FileLink(symbolic /tmp/x -> /home/dan/.ssh/id_rsa)",
            "FileLink",
            "",
        );
        assert_eq!(s.verb, "SYMLINK");
    }

    #[test]
    fn call_summary_rename_shows_from_and_to() {
        let s = summary_for(
            "FileRename(/tmp/node-compile/66a34524.keyBMG -> /tmp/node-compile/66a34524)",
            "FileRename",
            "",
        );
        assert_eq!(s.verb, "MOVE");
        assert_eq!(s.headline, "66a34524");
        assert_eq!(s.targets[0].label, "from");
        assert!(s.targets[0].value.ends_with("66a34524.keyBMG"));
        assert_eq!(s.targets[1].label, "to");
        assert!(s.targets[1].value.ends_with("66a34524"));
    }

    #[test]
    fn call_summary_spawn_splits_binary_and_args_from_detail() {
        let s = summary_for(
            "ProcessSpawn(/snap/snapd/27710/usr/lib/snapd/snap-confine --output json)",
            "ProcessSpawn",
            "not json",
        );
        assert_eq!(s.verb, "RUN");
        assert_eq!(s.headline, "snap-confine");
        assert_eq!(
            s.targets[0].value,
            "/snap/snapd/27710/usr/lib/snapd/snap-confine"
        );
        assert_eq!(s.args.as_deref(), Some("--output json"));
    }

    #[test]
    fn call_summary_spawn_prefers_structured_json() {
        // The Display detail glues command+args; the JSON keeps them distinct.
        let s = summary_for(
            "ProcessSpawn(/opt/my app/bin --flag)",
            "ProcessSpawn",
            r#"{"command":"/opt/my app/bin","spawn_args":["--flag","x"]}"#,
        );
        assert_eq!(s.headline, "bin");
        assert_eq!(s.targets[0].value, "/opt/my app/bin");
        assert_eq!(s.args.as_deref(), Some("--flag x"));
    }

    #[test]
    fn call_summary_net_connect_headline_is_host_port() {
        let s = summary_for("NetConnect(api.anthropic.com:443)", "NetConnect", "");
        assert_eq!(s.verb, "CONNECT");
        assert_eq!(s.headline, "api.anthropic.com:443");
        assert!(s.targets.is_empty());
    }

    #[test]
    fn call_summary_chmod_surfaces_mode() {
        let s = summary_for("FileChmod(/usr/local/bin/tool, 4755)", "FileChmod", "");
        assert_eq!(s.verb, "CHMOD");
        assert_eq!(s.targets[0].value, "/usr/local/bin/tool");
        assert_eq!(s.args.as_deref(), Some("mode 4755"));
    }

    #[test]
    fn call_block_lines_keep_filename_on_long_paths() {
        let s = summary_for(
            "FileWrite(/tmp/node-compile-cache/v22.22.2-x64-9ac5647c-1000/66a34524.keyBMG)",
            "FileWrite",
            "",
        );
        let lines = call_block_lines(&s, 50);
        // Header line carries the verb badge and the filename headline.
        let header: String = lines[0]
            .spans
            .iter()
            .map(|sp| sp.content.as_ref())
            .collect();
        assert!(header.starts_with("WRITE"), "{header}");
        assert!(header.contains("66a34524.keyBMG"), "{header}");
        // The full-path row keeps the basename despite the width budget.
        let path_row: String = lines[1]
            .spans
            .iter()
            .map(|sp| sp.content.as_ref())
            .collect();
        assert!(path_row.contains("..."), "{path_row}");
        assert!(
            path_row.trim_end().ends_with("66a34524.keyBMG"),
            "{path_row}"
        );
        assert!(path_row.chars().count() <= 50, "{path_row}");
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

    /// A single path with a trailing slash keeps its last component visible
    /// rather than reducing the preserved suffix to "/".
    #[test]
    fn trailing_slash_path_keeps_last_component() {
        let text = shorten_path_middle(
            "/tmp/claude-1000/-home-dan-projects/752e1529-b778-4917/scratchpad/chromium-92.0.4515.107/",
            48,
        );
        assert!(
            text.ends_with("/chromium-92.0.4515.107/"),
            "last component lost: {text}"
        );
        assert!(text.chars().count() <= 48, "{text}");
    }

    #[test]
    fn truncate_middle_keeps_head_and_tail() {
        assert_eq!(truncate_middle("hello", 10), "hello");
        let out = truncate_middle("--headless --disable-gpu http://localhost:5173/", 30);
        assert!(out.starts_with("--headless"), "{out}");
        assert!(out.ends_with("host:5173/"), "{out}");
        assert!(out.chars().count() <= 30, "{out}");
    }

    #[test]
    fn visible_reasons_prefer_decision_reason_and_skip_blanks() {
        let mut req = make_request(false);
        req.decision_reason = "mass-destruction signal: 25 distinct out-of-tree deletions".into();
        req.reasons = vec![String::new(), "File delete requires review".into()];

        let reasons = visible_reasons(&req);
        assert_eq!(
            reasons.first().map(String::as_str),
            Some("mass-destruction signal: 25 distinct out-of-tree deletions")
        );
        assert_eq!(
            reasons.get(1).map(String::as_str),
            Some("File delete requires review")
        );
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
    fn scoped_permission_panel_fits_compact_exec_height() {
        let backend = TestBackend::new(80, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut req = make_request(false);
        req.tool = "FileDelete(/repo/target/debug/deps/foo.o)".to_string();
        req.call_type = "FileDelete".to_string();
        req.scope_enabled = true;
        let state = ScopeDialogState::for_request(&req).unwrap();

        terminal
            .draw(|frame| {
                render_scope_permission_panel(frame, frame.area(), &req, &state);
            })
            .unwrap();

        let contents: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(contents.contains("SCOPE PERMISSION"));
        assert!(contents.contains("delete/rename"));
        assert!(contents.contains("this session only"));
        assert!(contents.contains("not saved to the profile"));
        assert!(contents.contains("Apply scope"));
    }

    fn buffer_contents(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn help_panel_explains_every_review_key() {
        let backend = TestBackend::new(80, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let req = make_request(false);

        terminal
            .draw(|frame| render_permission_help_panel(frame, frame.area(), &req, false))
            .unwrap();

        let contents = buffer_contents(&terminal);
        assert!(contents.contains("PERMISSION KEYS"));
        assert!(contents.contains("stays allowed for this session"));
        assert!(contents.contains("blocked for a short window"));
        assert!(contents.contains("permanent rule"));
        assert!(contents.contains("stop the supervised tool"));
        assert!(contents.contains("Back to the request"));
        // scope_enabled is false on the fixture — no [s] row.
        assert!(!contents.contains("[s]"));
    }

    #[test]
    fn help_panel_lists_scope_key_for_file_operations() {
        let backend = TestBackend::new(80, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut req = make_request(false);
        req.tool = "FileDelete(/repo/target/debug/deps/foo.o)".to_string();
        req.call_type = "FileDelete".to_string();
        req.scope_enabled = true;

        terminal
            .draw(|frame| render_permission_help_panel(frame, frame.area(), &req, false))
            .unwrap();

        let contents = buffer_contents(&terminal);
        assert!(contents.contains("[s]"));
        assert!(contents.contains("this session only"));
    }

    #[test]
    fn help_dialog_deny_variant_explains_continue() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let req = make_request(true);

        terminal
            .draw(|frame| render_permission_help_dialog(frame, &req, true))
            .unwrap();

        let contents = buffer_contents(&terminal);
        assert!(contents.contains("Acknowledge the block"));
        assert!(contents.contains("what was blocked"));
        // Decision keys must not be advertised on the auto-deny help.
        assert!(!contents.contains("permanent rule"));
    }

    #[test]
    fn action_rows_advertise_the_help_key() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let req = make_request(false);
        terminal
            .draw(|frame| render_permission_panel(frame, frame.area(), &req, false, false))
            .unwrap();
        let contents = buffer_contents(&terminal);
        assert!(contents.contains("[h]"), "panel action row must list Help");

        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_permission_dialog(frame, &req, false, false))
            .unwrap();
        let contents = buffer_contents(&terminal);
        assert!(contents.contains("[h]"), "dialog action row must list Help");
    }

    #[test]
    fn scope_focus_reaches_session_duration_and_wraps() {
        let mut req = make_request(false);
        req.tool = "FileRead(/repo/src/lib.rs)".to_string();
        req.call_type = "FileRead".to_string();
        req.scope_enabled = true;
        let mut state = ScopeDialogState::for_request(&req).unwrap();

        assert!(state.directory_focused());
        for _ in 0..4 {
            state.focus_next();
        }
        assert!(state.duration_focused());

        state.toggle_focused();
        assert!(!state.request.persist);
        state.focus_next();
        assert!(state.directory_focused());
        state.focus_previous();
        assert!(state.duration_focused());
    }

    #[test]
    fn invalid_scope_stays_in_editor_with_inline_error() {
        let mut req = make_request(false);
        req.tool = "FileRead(/repo/src/lib.rs)".to_string();
        req.call_type = "FileRead".to_string();
        req.scope_enabled = true;
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        state.request.directory = "/".to_string();

        assert!(state.apply(&req).is_none());
        assert!(state.error.is_some());
    }

    #[test]
    fn spawn_provenance_chain_appears_in_summary() {
        let mut req = make_request(false);
        req.tool = "ProcessSpawn(/usr/bin/ssh git@github.com)".to_string();
        req.call_type = "ProcessSpawn".to_string();
        req.args =
            r#"{"pid":100,"process":"ssh","parent_pid":99,"parent_process":"git"}"#.to_string();
        let lines = summary_lines(&req);
        let text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(text.contains("ssh"), "should show process: {text}");
        assert!(text.contains("git"), "should show parent: {text}");
    }
}
