// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Permission dialog overlay — rendered for quarantine (QUEUE) and auto-deny dialogs.

use crate::tui::state::PermissionRequest;
use crate::tui::theme::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use grith_digest::{PermissionReviewAction, ScopedAllowRequest, ScopedDenyRequest};
use grith_supervisor::scoped_permissions::ScopeMode;
use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use serde_json::Value;

/// What a keystroke did to the scope editor.
///
/// Both review hosts (`exec_tui.rs` and the REPL dialog in `tui/mod.rs`) used
/// to carry their own copy of the key match, which is how they drifted apart.
/// They now both call [`ScopeDialogState::handle_key`] and act on this.
#[derive(Debug, Clone, PartialEq)]
pub enum ScopeKeyOutcome {
    /// Stay in the editor and redraw.
    Continue,
    /// Close the editor and go back to the request dialog.
    Cancel,
    /// The proposal validated; dismiss the review with this action.
    Applied(PermissionReviewAction),
}

/// The next wider scope, or why there isn't one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WidenProbe {
    /// Widening is allowed and would produce this directory.
    Available(String),
    /// The breadth floor refuses it. Carries a hint-sized reason so the
    /// editor can grey the control and say why, rather than letting the
    /// reviewer walk one component too far and discover it on Enter.
    Blocked(String),
}

/// Mutable state for the second-step scoped permission editor.
#[derive(Debug, Clone)]
pub struct ScopeDialogState {
    /// Operation bits and editable directory.
    pub request: ScopedAllowRequest,
    focus: usize,
    /// Inline validation error from the last apply attempt.
    pub error: Option<String>,
    /// Caret position, as a char index into `request.directory`.
    ///
    /// The old field had none: it drew a caret glyph after a head-truncating
    /// ellipsis while every edit landed in the invisible tail, so on a path
    /// longer than the field the editor looked frozen.
    cursor: usize,
    /// Whether the directory row is a free-text field.
    ///
    /// Off by default. The primary interaction is walking whole path
    /// components, which cannot land on the partial component that the
    /// containment check rejects; free text is the escape hatch behind `[e]`.
    editing: bool,
    /// The reviewed target's own directory — the narrowest scope on offer,
    /// and the anchor the "narrower" control walks back toward.
    narrowest: String,
    /// Whether `narrowest` existed when the dialog opened. The reviewed call
    /// is frozen while this dialog is up but nothing else is, so a concurrent
    /// `git worktree remove` can delete the directory mid-review; this is
    /// what lets the status line name that race instead of reporting the
    /// directory as one that was never created.
    default_existed: bool,
    /// work/85: whether this editor is granting or withholding.
    mode: ScopeMode,
    /// The operation ticks the dialog opened with, so switching back out of
    /// deny mode restores the reviewed operation rather than leaving all three
    /// ticked — deny mode ticks everything, and silently carrying that into a
    /// grant would widen an approval the reviewer never asked for.
    allow_defaults: (bool, bool, bool),
}

impl ScopeDialogState {
    const FOCUS_COUNT: usize = 6;
    /// Focus index of the allow/deny row.
    ///
    /// Last in the tab cycle, first on screen. The directory keeps focus 0
    /// because the editor's "just start typing a path" behaviour depends on
    /// it, and one shift-tab (or ctrl-b from anywhere) reaches the mode row
    /// without costing that.
    const FOCUS_MODE: usize = 5;

    /// Create the safe operation-specific default for a permission request.
    pub fn for_request(req: &PermissionRequest) -> Option<Self> {
        Self::for_request_in_mode(req, ScopeMode::Allow)
    }

    /// Open the editor already set to block the directory — the `[b]` entry
    /// point on the permission dialog.
    pub fn blocking_for_request(req: &PermissionRequest) -> Option<Self> {
        Self::for_request_in_mode(req, ScopeMode::Deny)
    }

    fn for_request_in_mode(req: &PermissionRequest, mode: ScopeMode) -> Option<Self> {
        if !req.scope_enabled {
            return None;
        }
        let request = grith_supervisor::scoped_permissions::default_scoped_allow(&req.tool)?;
        let narrowest = request.directory.clone();
        let default_existed = std::path::Path::new(&narrowest).is_dir();
        let mut state = Self {
            cursor: request.directory.chars().count(),
            allow_defaults: (request.read, request.write, request.delete),
            request,
            focus: 0,
            error: None,
            editing: false,
            narrowest,
            default_existed,
            mode: ScopeMode::Allow,
        };
        state.set_mode(mode);
        Some(state)
    }

    /// Which direction the editor currently points.
    #[must_use]
    pub fn mode(&self) -> ScopeMode {
        self.mode
    }

    /// Whether the editor is withholding rather than granting.
    #[must_use]
    pub fn is_blocking(&self) -> bool {
        matches!(self.mode, ScopeMode::Deny)
    }

    /// Whether the allow/deny row has focus.
    #[must_use]
    pub fn mode_focused(&self) -> bool {
        self.focus == Self::FOCUS_MODE
    }

    /// Switch direction.
    ///
    /// Deny ticks all three operations: an operator blocking a directory
    /// almost always means the whole directory, and the alternative — a block
    /// that silently covers reads only because the prompt happened to be a
    /// read — is the kind of half-applied rule that sends them back to the
    /// dialog. Returning to allow restores the operation the dialog opened
    /// with, so a grant is never widened by a visit to deny mode.
    pub fn set_mode(&mut self, mode: ScopeMode) {
        if self.mode == mode {
            return;
        }
        self.mode = mode;
        match mode {
            ScopeMode::Deny => {
                self.request.read = true;
                self.request.write = true;
                self.request.delete = true;
            }
            ScopeMode::Allow => {
                let (read, write, delete) = self.allow_defaults;
                self.request.read = read;
                self.request.write = write;
                self.request.delete = delete;
            }
        }
        self.error = None;
    }

    /// Flip between granting and blocking.
    pub fn toggle_mode(&mut self) {
        self.set_mode(match self.mode {
            ScopeMode::Allow => ScopeMode::Deny,
            ScopeMode::Deny => ScopeMode::Allow,
        });
    }

    /// The proposal as a refusal, for the deny-mode preview and validation.
    fn deny_request(&self) -> ScopedDenyRequest {
        ScopedDenyRequest {
            directory: self.request.directory.clone(),
            read: self.request.read,
            write: self.request.write,
            delete: self.request.delete,
        }
    }

    /// Live verdict for the current proposal, in the current mode.
    #[must_use]
    pub fn status(
        &self,
        req: &PermissionRequest,
    ) -> grith_supervisor::scoped_permissions::ScopeStatus {
        match self.mode {
            ScopeMode::Allow => grith_supervisor::scoped_permissions::preview_scoped_allow(
                &self.request,
                &req.tool,
                self.default_directory_existed(),
            ),
            ScopeMode::Deny => grith_supervisor::scoped_permissions::preview_scoped_deny(
                &self.deny_request(),
                &req.tool,
                self.default_directory_existed(),
            ),
        }
    }

    /// Move focus to the next field or duration choice.
    pub fn focus_next(&mut self) {
        self.focus = (self.focus + 1) % Self::FOCUS_COUNT;
        self.editing = false;
        self.error = None;
    }

    /// Move focus to the previous field or duration choice.
    pub fn focus_previous(&mut self) {
        self.focus = (self.focus + Self::FOCUS_COUNT - 1) % Self::FOCUS_COUNT;
        self.editing = false;
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

    /// Whether the directory row is currently a free-text field.
    pub fn editing(&self) -> bool {
        self.editing
    }

    /// Caret position as a char index into the directory field.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Whether the dialog's own default directory existed when it opened and
    /// the field still names it.
    ///
    /// Only the untouched default can report the mid-review deletion race: a
    /// directory the reviewer typed or walked to was never shown as existing,
    /// so a missing one there is just "not created yet".
    pub fn default_directory_existed(&self) -> bool {
        self.default_existed && self.request.directory == self.narrowest
    }

    /// The next wider scope, or why the breadth floor refuses one.
    pub fn widen_probe(&self, req: &PermissionRequest) -> WidenProbe {
        let Some(candidate) = self.widen_candidate() else {
            return WidenProbe::Blocked("already at the filesystem root".to_string());
        };
        // `false`: a walk candidate is never the dialog's own default, so the
        // "removed while frozen" wording cannot apply to it.
        let status = match self.mode {
            ScopeMode::Allow => {
                let probe = ScopedAllowRequest {
                    directory: candidate.clone(),
                    ..self.request.clone()
                };
                grith_supervisor::scoped_permissions::preview_scoped_allow(&probe, &req.tool, false)
            }
            ScopeMode::Deny => {
                let probe = ScopedDenyRequest {
                    directory: candidate.clone(),
                    ..self.deny_request()
                };
                grith_supervisor::scoped_permissions::preview_scoped_deny(&probe, &req.tool, false)
            }
        };
        if !status.blocks_apply() {
            return WidenProbe::Available(candidate);
        }
        let shown = candidate.trim_end_matches('/');
        let shown = if shown.is_empty() { "/" } else { shown };
        WidenProbe::Blocked(match status {
            grith_supervisor::scoped_permissions::ScopeStatus::TooBroad { .. } => {
                format!("{shown} is too broad")
            }
            grith_supervisor::scoped_permissions::ScopeStatus::Sensitive { .. } => {
                format!("{shown} is sensitive")
            }
            other => other.message(),
        })
    }

    /// The next scope back toward the reviewed target, if any.
    pub fn narrow_candidate(&self) -> Option<String> {
        if !self.request.directory.starts_with('/') || !self.narrowest.starts_with('/') {
            return None;
        }
        let current = path_components(&self.request.directory);
        let target = path_components(&self.narrowest);
        if target.len() <= current.len() || target[..current.len()] != current[..] {
            return None;
        }
        Some(format!("/{}/", target[..=current.len()].join("/")))
    }

    /// Widen the scope by one path component. Returns whether it moved.
    pub fn walk_wider(&mut self, req: &PermissionRequest) -> bool {
        match self.widen_probe(req) {
            WidenProbe::Available(directory) => {
                self.set_directory(directory);
                true
            }
            WidenProbe::Blocked(_) => false,
        }
    }

    /// Narrow the scope by one path component, back toward the reviewed
    /// target. Never needs a floor check: every candidate is a descendant of
    /// the current directory, so it can only get tighter.
    pub fn walk_narrower(&mut self) -> bool {
        match self.narrow_candidate() {
            Some(directory) => {
                self.set_directory(directory);
                true
            }
            None => false,
        }
    }

    /// Enter free-text editing with the caret at the end of the field.
    pub fn start_editing(&mut self) {
        self.editing = true;
        self.cursor = self.request.directory.chars().count();
    }

    /// Insert a character at the caret.
    pub fn insert_char(&mut self, ch: char) {
        let at = byte_index(&self.request.directory, self.cursor);
        self.request.directory.insert(at, ch);
        self.cursor += 1;
        self.error = None;
    }

    /// Delete the character before the caret.
    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let start = byte_index(&self.request.directory, self.cursor - 1);
        let end = byte_index(&self.request.directory, self.cursor);
        self.request.directory.replace_range(start..end, "");
        self.cursor -= 1;
        self.error = None;
    }

    /// Ctrl-W: delete the whole path component before the caret.
    ///
    /// The component-at-a-time unit matters because the containment check is
    /// component-wise: deleting "grith-analytics-local" one character at a
    /// time passes through thirteen partial components that all validate as
    /// "does not contain the target".
    pub fn delete_previous_component(&mut self) {
        let chars: Vec<char> = self.request.directory.chars().collect();
        let mut start = self.cursor.min(chars.len());
        while start > 0 && chars[start - 1] == '/' {
            start -= 1;
        }
        while start > 0 && chars[start - 1] != '/' {
            start -= 1;
        }
        let from = byte_index(&self.request.directory, start);
        let to = byte_index(&self.request.directory, self.cursor);
        self.request.directory.replace_range(from..to, "");
        self.cursor = start;
        self.error = None;
    }

    /// Clear the directory field.
    pub fn clear_directory(&mut self) {
        self.request.directory.clear();
        self.cursor = 0;
        self.error = None;
    }

    /// Move the caret one character left.
    pub fn move_cursor_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    /// Move the caret one character right.
    pub fn move_cursor_right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.request.directory.chars().count());
    }

    /// Move the caret to the start of the field.
    pub fn move_cursor_home(&mut self) {
        self.cursor = 0;
    }

    /// Move the caret to the end of the field.
    pub fn move_cursor_end(&mut self) {
        self.cursor = self.request.directory.chars().count();
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
            Self::FOCUS_MODE => self.toggle_mode(),
            _ => {}
        }
        self.error = None;
    }

    /// Handle one keystroke. The single key map both review hosts share.
    pub fn handle_key(&mut self, key: &KeyEvent, req: &PermissionRequest) -> ScopeKeyOutcome {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        match key.code {
            // Esc leaves the free-text field before it leaves the dialog, so
            // the escape hatch is never a trap door out of the review.
            KeyCode::Esc if self.editing => self.editing = false,
            KeyCode::Esc => return ScopeKeyOutcome::Cancel,
            KeyCode::Enter => {
                if let Some(action) = self.apply(req) {
                    return ScopeKeyOutcome::Applied(action);
                }
            }
            KeyCode::Tab if shift => self.focus_previous(),
            KeyCode::Tab | KeyCode::Down => self.focus_next(),
            KeyCode::BackTab | KeyCode::Up => self.focus_previous(),
            KeyCode::Left if self.editing => self.move_cursor_left(),
            KeyCode::Right if self.editing => self.move_cursor_right(),
            KeyCode::Home if self.editing => self.move_cursor_home(),
            KeyCode::End if self.editing => self.move_cursor_end(),
            // Ctrl-B works from anywhere, including mid-edit, so the
            // reviewer never has to leave the path field to change direction.
            KeyCode::Char('b') if ctrl => self.toggle_mode(),
            KeyCode::Left if self.mode_focused() => self.set_mode(ScopeMode::Allow),
            KeyCode::Right if self.mode_focused() => self.set_mode(ScopeMode::Deny),
            KeyCode::Left if self.directory_focused() => {
                self.walk_wider(req);
            }
            KeyCode::Right if self.directory_focused() => {
                self.walk_narrower();
            }
            KeyCode::Backspace if self.directory_focused() => {
                self.editing = true;
                self.backspace();
            }
            KeyCode::Char('w') if ctrl && self.directory_focused() => {
                self.editing = true;
                self.delete_previous_component();
            }
            KeyCode::Char('u') if ctrl && self.directory_focused() => {
                self.editing = true;
                self.clear_directory();
            }
            KeyCode::Char(' ') if !self.directory_focused() => self.toggle_focused(),
            KeyCode::Char(ch) if self.editing && (key.modifiers.is_empty() || shift) => {
                self.insert_char(ch);
            }
            // `[e]` opens the field, as the footer advertises. Any other
            // printable key opens it and types itself, so a reviewer who
            // starts typing a path is not silently ignored the way the old
            // walk-less field ignored cursor keys.
            KeyCode::Char('e' | 'E') if self.directory_focused() && key.modifiers.is_empty() => {
                self.start_editing();
            }
            KeyCode::Char(ch)
                if self.directory_focused() && (key.modifiers.is_empty() || shift) =>
            {
                self.start_editing();
                self.insert_char(ch);
            }
            _ => {}
        }
        ScopeKeyOutcome::Continue
    }

    /// Validate the proposal and return its canonical structured action.
    pub fn apply(&mut self, req: &PermissionRequest) -> Option<PermissionReviewAction> {
        let validated = match self.mode {
            ScopeMode::Allow => grith_supervisor::scoped_permissions::validate_scoped_allow(
                &self.request,
                &req.tool,
            )
            .map(|validated| validated.directory),
            ScopeMode::Deny => grith_supervisor::scoped_permissions::validate_scoped_deny(
                &self.deny_request(),
                &req.tool,
            )
            .map(|validated| validated.directory),
        };
        match validated {
            Ok(directory) => {
                self.request.directory = directory;
                self.cursor = self.request.directory.chars().count();
                self.error = None;
                Some(match self.mode {
                    ScopeMode::Allow => PermissionReviewAction::ScopedAllow(self.request.clone()),
                    ScopeMode::Deny => PermissionReviewAction::ScopedDeny(self.deny_request()),
                })
            }
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }

    /// The parent of the current scope, in directory form.
    fn widen_candidate(&self) -> Option<String> {
        if !self.request.directory.starts_with('/') {
            return None;
        }
        let trimmed = self.request.directory.trim_end_matches('/');
        let parent = std::path::Path::new(trimmed).parent()?;
        let parent = parent.to_string_lossy();
        if parent.is_empty() {
            return None;
        }
        Some(directory_form(&parent))
    }

    fn set_directory(&mut self, directory: String) {
        self.request.directory = directory;
        self.cursor = self.request.directory.chars().count();
        self.error = None;
    }
}

/// Non-empty path components of an absolute path.
fn path_components(path: &str) -> Vec<&str> {
    path.split('/').filter(|part| !part.is_empty()).collect()
}

/// A path with exactly one trailing separator, which is the form every
/// `*-prefix:` session rule is stored in.
fn directory_form(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("{trimmed}/")
    }
}

fn byte_index(text: &str, char_index: usize) -> usize {
    text.char_indices()
        .nth(char_index)
        .map_or_else(|| text.len(), |(index, _)| index)
}

/// A slice of a text field guaranteed to contain the caret.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FieldWindow {
    /// Text to draw, including any clip markers.
    text: String,
    /// Column of the caret within `text`.
    cursor_col: usize,
}

/// Window a single-line field so the caret is always on screen.
///
/// The old field rendered `truncate(head) + "..."` and drew its caret after
/// the ellipsis, so on any path longer than the field every keystroke landed
/// somewhere the reviewer could not see. Clipped ends are marked so the
/// reviewer knows the value continues past the window.
fn field_window(text: &str, cursor: usize, width: usize) -> FieldWindow {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let cursor = cursor.min(len);
    if width == 0 {
        return FieldWindow {
            text: String::new(),
            cursor_col: 0,
        };
    }
    // `len < width` rather than `<=`: the caret needs a column of its own
    // when it sits past the final character.
    if len < width {
        return FieldWindow {
            text: text.to_string(),
            cursor_col: cursor,
        };
    }

    // Marker columns come out of the text budget, which can itself change
    // whether a side is clipped; two passes always settle it.
    let (mut left, mut right) = (0usize, 0usize);
    let (mut offset, mut text_width) = (0usize, width);
    for _ in 0..3 {
        text_width = width.saturating_sub(left + right).max(1);
        offset = cursor.saturating_sub(text_width - 1);
        let next_left = usize::from(offset > 0);
        let next_right = usize::from(offset + text_width < len);
        if next_left == left && next_right == right {
            break;
        }
        left = next_left;
        right = next_right;
    }

    let end = (offset + text_width).min(len);
    let mut rendered = String::new();
    if left == 1 {
        rendered.push('\u{2039}');
    }
    rendered.extend(chars[offset..end].iter());
    if right == 1 {
        rendered.push('\u{203a}');
    }
    FieldWindow {
        text: rendered,
        cursor_col: left + (cursor - offset),
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
    let area = centered_rect(scope_dialog_width(state), 60, frame.area());
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
            if req.sticky_grant_available {
                "Allow this request; the exact target stays allowed for this session"
            } else {
                "Allow this request only; this kind of call is asked every time"
            },
        ));
        lines.push(help_line(
            "[d]",
            RED,
            "Block this request; identical retries are blocked for a short window",
        ));
        if req.sticky_grant_available {
            lines.push(help_line(
                "[l]",
                BLUE,
                "Allow and save a permanent rule for this exact target",
            ));
        }
        if ScopeDialogState::for_request(req).is_some() {
            lines.push(help_line(
                "[s]",
                AMBER,
                "Allow a directory for operations you pick, this session only",
            ));
            lines.push(help_line(
                "[b]",
                RED,
                "Block a directory for the rest of the session — no more prompts for it",
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
            if req.sticky_grant_available {
                " Nothing outlives the session unless saved with [l]; sensitive targets are never saved."
            } else {
                " No answer to this request is remembered — it is a class grith asks about every time."
            },
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
    // A block and a grant must not look alike. The reviewer is about to
    // install a standing session rule either way, and the title bar is the
    // one part of the dialog that is always on screen.
    let (title, colour) = if state.is_blocking() {
        (" BLOCK DIRECTORY ", RED)
    } else {
        (" SCOPE PERMISSION ", AMBER)
    };
    let block = Block::default()
        .title(title)
        .title_style(Style::new().fg(colour).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(colour))
        .style(Style::new().bg(BG_PANEL));
    frame.render_widget(block, area);
    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    render_scope_body(frame, inner, req, state);
}

/// Label in front of the editable directory. Its width is the field's left
/// margin, so the walk hints and the resolved path line up under the path.
const SCOPE_LABEL: &str = "scope:    ";

/// Width the scope dialog wants.
///
/// 76 columns was hard-coded, which is ~58 usable characters for a path; the
/// recorded failure case was 85 characters long, so the value the reviewer
/// was editing could not be shown at any caret position. Grow with the path
/// and let `centered_rect` clamp to the terminal.
fn scope_dialog_width(state: &ScopeDialogState) -> u16 {
    let needed = state
        .request
        .directory
        .chars()
        .count()
        .saturating_add(SCOPE_LABEL.len() + 8);
    u16::try_from(needed).unwrap_or(u16::MAX).max(76)
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
            Constraint::Length(1), // 0 allow / block
            Constraint::Length(1), // 1 editable directory
            Constraint::Length(1), // 2 walk controls
            Constraint::Length(1), // 3 resolved path, when it differs
            Constraint::Length(1), // 4 operation checkboxes
            Constraint::Length(1), // 5 duration
            Constraint::Length(1), // 6 rename detail
            Constraint::Length(1), // 7 what will be granted or blocked
            Constraint::Min(1),    // 8 status, wrapped
            Constraint::Length(2), // 9 footer, wrapped
        ])
        .split(area);
    let width = area.width as usize;
    let label_width = SCOPE_LABEL.chars().count();
    frame.render_widget(
        Paragraph::new(scope_mode_line(state, label_width)).style(Style::new().bg(BG_PANEL)),
        chunks[0],
    );
    let field_width = width.saturating_sub(label_width);
    let field_style = if state.directory_focused() {
        Style::new().fg(WHITE).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(TEXT_MID)
    };

    let mut field_spans = vec![Span::styled(SCOPE_LABEL, Style::new().fg(TEXT_DIM))];
    if state.editing() {
        let window = field_window(&state.request.directory, state.cursor(), field_width);
        let chars: Vec<char> = window.text.chars().collect();
        let before: String = chars.iter().take(window.cursor_col).collect();
        field_spans.push(Span::styled(before, field_style));
        match chars.get(window.cursor_col) {
            // The caret is drawn ON the character it is over, not after an
            // ellipsis somewhere else in the string.
            Some(under) => {
                field_spans.push(Span::styled(
                    under.to_string(),
                    Style::new().fg(BG_PANEL).bg(AMBER),
                ));
                let after: String = chars.iter().skip(window.cursor_col + 1).collect();
                field_spans.push(Span::styled(after, field_style));
            }
            None => field_spans.push(Span::styled("\u{258f}", Style::new().fg(AMBER))),
        }
    } else {
        // Not editing: keep the basename, which is the part that tells the
        // reviewer which directory this is.
        field_spans.push(Span::styled(
            shorten_path_middle(&state.request.directory, field_width),
            field_style,
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(field_spans)).style(Style::new().bg(BG_PANEL)),
        chunks[1],
    );

    frame.render_widget(
        Paragraph::new(scope_walk_line(req, state, label_width)).style(Style::new().bg(BG_PANEL)),
        chunks[2],
    );

    // Show the resolved path only when it differs from what is typed: a
    // symlinked scope directory resolves somewhere broader, and work/70
    // requires that never be silent.
    let preview =
        grith_supervisor::scoped_permissions::preview_scope_path(&state.request.directory);
    if let Ok(preview) = &preview {
        if preview.resolved_directory != directory_form(&state.request.directory) {
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("resolves:  ", Style::new().fg(TEXT_DIM)),
                    Span::styled(
                        shorten_path_middle(
                            &preview.resolved_directory,
                            width.saturating_sub("resolves:  ".len()),
                        ),
                        Style::new().fg(TEXT_MID),
                    ),
                ]))
                .style(Style::new().bg(BG_PANEL)),
                chunks[3],
            );
        }
    }

    let operation_line = Line::from(vec![
        checkbox_span("read", state.request.read, state.focus == 1),
        Span::raw("   "),
        checkbox_span("write/create", state.request.write, state.focus == 2),
        Span::raw("   "),
        checkbox_span("delete/rename", state.request.delete, state.focus == 3),
    ]);
    frame.render_widget(
        Paragraph::new(operation_line).style(Style::new().bg(BG_PANEL)),
        chunks[4],
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
        chunks[5],
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
            chunks[6],
        );
    }

    let status = state.status(req);

    // Say what will be granted, in the rule's own terms, so "apply" is not a
    // leap of faith about which directory the rule ends up naming.
    if !status.blocks_apply() {
        let granted = preview.as_ref().map_or_else(
            |_| directory_form(&state.request.directory),
            |preview| preview.resolved_directory.clone(),
        );
        // "everything" rather than three comma-separated labels: block mode
        // ticks all three by default, and spelling them out consumed the room
        // the DIRECTORY needs — the one value on this line the reviewer has to
        // read before pressing enter.
        let labels = selected_operation_labels(state);
        let operations = if labels.len() == 3 {
            "everything".to_string()
        } else {
            labels.join(", ")
        };
        let head = if state.is_blocking() {
            format!("will BLOCK: {operations} under ")
        } else {
            format!("will allow: {operations} under ")
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    head.clone(),
                    Style::new().fg(if state.is_blocking() { RED } else { TEXT_DIM }),
                ),
                Span::styled(
                    shorten_path_middle(&granted, width.saturating_sub(head.chars().count() + 16)),
                    Style::new().fg(TEXT_MID),
                ),
                Span::styled(" (this session)", Style::new().fg(TEXT_DIM)),
            ]))
            .style(Style::new().bg(BG_PANEL)),
            chunks[7],
        );
    }

    // One status line that always reflects the current field. Enter can no
    // longer surprise the reviewer with a check that only ran on Enter.
    let (glyph, colour, message) = if let Some(error) = &state.error {
        ("\u{2717}", RED, error.clone())
    } else if status.blocks_apply() {
        ("\u{2717}", RED, status.message())
    } else if status.is_warning() {
        ("\u{26a0}", AMBER, status.message())
    } else {
        ("\u{2713}", GREEN_HI, status.message())
    };
    frame.render_widget(
        // Wrapped, not truncated: the failure the reviewer is being asked to
        // fix used to be cut off mid-sentence at the dialog's edge.
        Paragraph::new(Line::from(vec![
            Span::styled(format!("{glyph} "), Style::new().fg(colour)),
            Span::styled(message, Style::new().fg(colour)),
        ]))
        .style(Style::new().bg(BG_PANEL))
        .wrap(Wrap { trim: true }),
        chunks[8],
    );

    frame.render_widget(
        Paragraph::new(Line::from(scope_footer_spans(state)))
            .style(Style::new().bg(BG_PANEL))
            .wrap(Wrap { trim: true }),
        chunks[9],
    );
}

/// The `[<-] wider / [->] narrower` control row.
///
/// Walking whole components is the primary interaction: it replaces thirteen
/// invisible backspaces with two keystrokes and cannot produce the partial
/// component that the containment check rejects.
fn scope_walk_line(
    req: &PermissionRequest,
    state: &ScopeDialogState,
    indent: usize,
) -> Line<'static> {
    let mut spans = vec![Span::raw(" ".repeat(indent))];
    if state.editing() {
        spans.push(Span::styled(
            "editing \u{2014} [esc] returns to component walking",
            Style::new().fg(TEXT_DIM),
        ));
        return Line::from(spans);
    }

    let widen = state.widen_probe(req);
    let can_widen = matches!(widen, WidenProbe::Available(_));
    spans.push(Span::styled(
        "[\u{2190}] wider",
        Style::new().fg(if can_widen && state.directory_focused() {
            TEXT_MID
        } else {
            TEXT_DIM
        }),
    ));
    spans.push(Span::raw("   "));
    spans.push(Span::styled(
        "[\u{2192}] narrower",
        Style::new().fg(
            if state.narrow_candidate().is_some() && state.directory_focused() {
                TEXT_MID
            } else {
                TEXT_DIM
            },
        ),
    ));
    if let WidenProbe::Blocked(reason) = widen {
        spans.push(Span::styled(
            format!("   \u{2014} {reason}"),
            Style::new().fg(TEXT_DIM),
        ));
    }
    Line::from(spans)
}

/// The `allow / block` row.
///
/// Rendered first because it changes what every row under it means, and drawn
/// as two mutually exclusive choices rather than a checkbox: "block" as a tick
/// box next to three operation tick boxes would read as a fourth operation.
fn scope_mode_line(state: &ScopeDialogState, indent: usize) -> Line<'static> {
    let focused = state.mode_focused();
    let blocking = state.is_blocking();
    let choice = |label: &str, selected: bool, colour| {
        Span::styled(
            format!("({}) {label}", if selected { '\u{25cf}' } else { ' ' }),
            Style::new()
                .fg(if selected { colour } else { TEXT_DIM })
                .add_modifier(if focused && selected {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        )
    };
    let mut spans = vec![Span::styled(
        format!("{:<indent$}", "action:"),
        Style::new().fg(TEXT_DIM),
    )];
    spans.push(choice("allow", !blocking, GREEN_HI));
    spans.push(Span::raw("   "));
    spans.push(choice("block", blocking, RED));
    spans.push(Span::styled(
        if focused {
            "   [\u{2190}\u{2192}] choose"
        } else {
            "   [ctrl-b] switch"
        },
        Style::new().fg(TEXT_DIM),
    ));
    Line::from(spans)
}

fn selected_operation_labels(state: &ScopeDialogState) -> Vec<&'static str> {
    let mut labels = Vec::with_capacity(3);
    if state.request.read {
        labels.push("read");
    }
    if state.request.write {
        labels.push("write/create");
    }
    if state.request.delete {
        labels.push("delete/rename");
    }
    labels
}

/// The key hints. The old footer never mentioned that the directory was a
/// text field at all, which is half of why it read as frozen.
fn scope_footer_spans(state: &ScopeDialogState) -> Vec<Span<'static>> {
    if state.editing() {
        return vec![
            Span::styled(" [\u{2190}\u{2192}] ", Style::new().fg(TEXT_MID)),
            Span::styled("Move  ", Style::new().fg(TEXT_DIM)),
            Span::styled("[home/end] ", Style::new().fg(TEXT_MID)),
            Span::styled("Ends  ", Style::new().fg(TEXT_DIM)),
            Span::styled("[ctrl-w] ", Style::new().fg(TEXT_MID)),
            Span::styled("Drop component  ", Style::new().fg(TEXT_DIM)),
            Span::styled("[ctrl-u] ", Style::new().fg(TEXT_MID)),
            Span::styled("Clear  ", Style::new().fg(TEXT_DIM)),
            Span::styled("[enter] ", Style::new().fg(GREEN_HI)),
            Span::styled("Apply  ", Style::new().fg(TEXT_MID)),
            Span::styled("[esc] ", Style::new().fg(TEXT_MID)),
            Span::styled("Done editing", Style::new().fg(TEXT_DIM)),
        ];
    }
    vec![
        Span::styled(" [\u{2190}\u{2192}] ", Style::new().fg(AMBER)),
        Span::styled("Scope  ", Style::new().fg(TEXT_DIM)),
        Span::styled("[tab] ", Style::new().fg(TEXT_MID)),
        Span::styled("Select  ", Style::new().fg(TEXT_DIM)),
        Span::styled("[space] ", Style::new().fg(TEXT_MID)),
        Span::styled("Toggle  ", Style::new().fg(TEXT_DIM)),
        Span::styled("[e] ", Style::new().fg(TEXT_MID)),
        Span::styled("Edit path  ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            "[enter] ",
            Style::new().fg(if state.is_blocking() { RED } else { GREEN_HI }),
        ),
        Span::styled("Apply  ", Style::new().fg(TEXT_MID)),
        Span::styled("[esc] ", Style::new().fg(TEXT_MID)),
        Span::styled("Back", Style::new().fg(TEXT_DIM)),
    ]
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
        "DbusMethodCall" => {
            // detail = "<socket> <destination> <interface>.<member>"
            let mut parts = detail.splitn(3, ' ');
            let socket = parts.next().unwrap_or_default();
            let destination = parts.next().unwrap_or_default();
            let call = parts.next().unwrap_or_default();
            // The member is what the operator is actually deciding about, so
            // it leads; the interface it hangs off is long, repetitive and
            // reverse-DNS, and reads as noise in a headline.
            let member = call.rsplit('.').next().unwrap_or(call);
            let mut targets = Vec::new();
            if !destination.is_empty() && destination != "?" {
                targets.push(TargetRow {
                    label: "service",
                    value: destination.to_string(),
                });
            }
            if !call.is_empty() && call != "?.?" {
                targets.push(TargetRow {
                    label: "method",
                    value: call.to_string(),
                });
            }
            targets.push(TargetRow {
                label: "bus",
                value: socket.to_string(),
            });
            CallSummary {
                verb: "D-BUS CALL".to_string(),
                role: VerbRole::Privileged,
                headline: member.to_string(),
                targets,
                args: None,
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
        ];
        // A call with no session-allowlist key cannot carry a grant, so
        // offering [l] would promise something the supervisor discards.
        if req.sticky_grant_available {
            actions.extend([
                Span::styled(" [l] ", Style::new().fg(BLUE)),
                Span::styled("Always allow  ", Style::new().fg(TEXT_MID)),
            ]);
        }
        if ScopeDialogState::for_request(req).is_some() {
            actions.extend([
                Span::styled(" [s] ", Style::new().fg(AMBER)),
                Span::styled("Scope...  ", Style::new().fg(TEXT_MID)),
                Span::styled(" [b] ", Style::new().fg(RED)),
                Span::styled("Block dir...  ", Style::new().fg(TEXT_MID)),
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
        push_process_target(&mut lines, provenance.process_target.as_ref());
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
        // The destination the process is reaching (e.g. "connecting to
        // git@host") — the single most decision-relevant fact for a NetConnect
        // prompt. Previously computed but only rendered in the REPL panel, so
        // an operator answering the exec-TUI dialog could not see where ssh was
        // going.
        push_process_target(&mut lines, provenance.process_target.as_ref());
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

/// Push the `process_target` phrase ("connecting to <host>", "fetching <url>")
/// as a `detail:` line when present. Shared by the exec-TUI dialog branches so
/// the destination is visible wherever a supervised connect/spawn is reviewed.
/// Takes the field by ref (not the whole struct) so it composes after the
/// `process_line` / `parent_line` fields have been moved out.
fn push_process_target(lines: &mut Vec<Line<'static>>, target: Option<&String>) {
    if let Some(target) = target {
        lines.push(Line::from(vec![
            Span::styled("detail: ", Style::new().fg(TEXT_DIM)),
            Span::styled(target.clone(), Style::new().fg(TEXT_MID)),
        ]));
    }
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
        ];
        // See the sibling action row: no key, no grant, no [l].
        if req.sticky_grant_available {
            actions.extend([
                Span::styled(" [l] ", Style::new().fg(BLUE)),
                Span::styled("Always allow  ", Style::new().fg(TEXT_MID)),
            ]);
        }
        if ScopeDialogState::for_request(req).is_some() {
            actions.extend([
                Span::styled(" [s] ", Style::new().fg(AMBER)),
                Span::styled("Scope...  ", Style::new().fg(TEXT_MID)),
                Span::styled(" [b] ", Style::new().fg(RED)),
                Span::styled("Block dir...  ", Style::new().fg(TEXT_MID)),
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
            sticky_grant_available: true,
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
    fn call_summary_dbus_leads_with_the_method() {
        let s = summary_for(
            "DbusMethodCall(unix:/run/user/1000/bus org.freedesktop.systemd1 \
             org.freedesktop.systemd1.Manager.StartTransientUnit)",
            "DbusMethodCall",
            "",
        );
        assert_eq!(s.verb, "D-BUS CALL");
        // The member, not the reverse-DNS interface, is what is being decided.
        assert_eq!(s.headline, "StartTransientUnit");
        assert_eq!(s.targets[0].label, "service");
        assert_eq!(s.targets[0].value, "org.freedesktop.systemd1");
        assert_eq!(s.targets[1].label, "method");
        assert_eq!(s.targets[2].label, "bus");
        assert_eq!(s.targets[2].value, "unix:/run/user/1000/bus");
    }

    #[test]
    fn call_summary_dbus_tolerates_unnamed_parts() {
        // The decoder renders missing header fields as `?`; the prompt must
        // still say something rather than showing a bare question mark row.
        let s = summary_for(
            "DbusMethodCall(unix:/run/user/1000/bus ? ?.?)",
            "DbusMethodCall",
            "",
        );
        assert_eq!(s.verb, "D-BUS CALL");
        assert_eq!(s.targets.len(), 1);
        assert_eq!(s.targets[0].label, "bus");
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
        assert!(contents.contains("Apply"));
        // The footer has to fit the exec panel's 18 rows while still saying
        // the directory is editable and walkable.
        assert!(contents.contains("Edit path"));
        assert!(contents.contains("wider"));
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

    /// A D-Bus method call has no session-allowlist key, so the supervisor
    /// discards any grant recorded for it. Offering "[l] Always allow" there
    /// tells the operator their answer will be remembered when it will not —
    /// the shape of the `StartTransientUnit` prompts that re-asked after
    /// every approval in supervised session 433ba7c7 (2026-08-25).
    #[test]
    fn dialog_hides_always_allow_when_no_grant_can_be_recorded() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut req = make_request(false);
        req.tool = "DbusMethodCall(unix:/run/user/1000/bus org.freedesktop.systemd1 \
             org.freedesktop.systemd1.Manager.StartTransientUnit)"
            .to_string();
        req.call_type = "DbusMethodCall".to_string();
        req.sticky_grant_available = false;

        terminal
            .draw(|frame| render_permission_dialog(frame, &req, false, false))
            .unwrap();

        let contents = buffer_contents(&terminal);
        assert!(
            contents.contains("[a]") && contents.contains("[d]"),
            "approve and deny must still be offered"
        );
        assert!(
            !contents.contains("Always allow"),
            "a grant that cannot be recorded must not be offered: {contents}"
        );
    }

    /// The default — anything with a key keeps the option.
    #[test]
    fn dialog_offers_always_allow_when_a_grant_sticks() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let req = make_request(false);
        assert!(req.sticky_grant_available);

        terminal
            .draw(|frame| render_permission_dialog(frame, &req, false, false))
            .unwrap();

        assert!(buffer_contents(&terminal).contains("Always allow"));
    }

    /// The help overlay must not promise a durable answer either — including
    /// the `[a]` line, which claims the target "stays allowed for this
    /// session".
    #[test]
    fn help_panel_drops_the_permanence_promise_without_a_grant() {
        let backend = TestBackend::new(80, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut req = make_request(false);
        req.call_type = "DbusMethodCall".to_string();
        req.sticky_grant_available = false;

        terminal
            .draw(|frame| render_permission_help_panel(frame, frame.area(), &req, false))
            .unwrap();

        let contents = buffer_contents(&terminal);
        assert!(
            !contents.contains("permanent rule"),
            "no [l] row: {contents}"
        );
        assert!(
            !contents.contains("stays allowed for this session"),
            "[a] must not promise session persistence either: {contents}"
        );
        assert!(contents.contains("asked every time"), "{contents}");
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
        // work/85: the allow/block row is the last stop before the cycle
        // wraps, so the directory keeps focus 0 and "just start typing a
        // path" still works when the editor opens.
        state.focus_next();
        assert!(state.mode_focused());
        state.focus_next();
        assert!(state.directory_focused());
        state.focus_previous();
        assert!(state.mode_focused());
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

    fn scope_request(tool: &str, call_type: &str) -> PermissionRequest {
        let mut req = make_request(false);
        req.tool = tool.to_string();
        req.call_type = call_type.to_string();
        req.scope_enabled = true;
        req
    }

    /// The exec-TUI dialog must show WHERE a supervised connect is going, so an
    /// operator can decide. Previously the destination was computed but rendered
    /// only in the REPL panel, leaving the exec dialog showing just `process:
    /// ssh (pid N)`.
    #[test]
    fn netconnect_dialog_shows_the_ssh_destination() {
        let mut req = make_request(false);
        req.tool = "NetConnect(terminus.pelygo.com:22)".to_string();
        req.call_type = "NetConnect".to_string();
        req.args = serde_json::json!({
            "pid": 4242,
            "process": "ssh",
            "process_args": ["ssh", "git@terminus.pelygo.com"],
            "address": "terminus.pelygo.com",
            "port": 22,
        })
        .to_string();

        let rendered: String = summary_lines(&req)
            .iter()
            .flat_map(|line| line.spans.iter().map(|s| s.content.to_string()))
            .collect();

        assert!(
            rendered.contains("git@terminus.pelygo.com"),
            "dialog must name the ssh destination; got: {rendered}"
        );
        assert!(
            rendered.contains("connecting to"),
            "dialog should describe the connect intent; got: {rendered}"
        );
    }

    // ---- work/85: block mode ------------------------------------------

    #[test]
    fn block_entry_point_opens_in_deny_mode_with_every_operation_ticked() {
        let req = scope_request("FileRead(/repo/secrets/token)", "FileRead");
        let state = ScopeDialogState::blocking_for_request(&req).unwrap();

        assert!(state.is_blocking());
        // A reviewer blocking a directory over a read prompt means the
        // directory, not "reads of the directory".
        assert!(state.request.read);
        assert!(state.request.write);
        assert!(state.request.delete);
        assert_eq!(state.request.directory, "/repo/secrets/");
    }

    #[test]
    fn toggling_back_to_allow_restores_the_reviewed_operation() {
        let req = scope_request("FileRead(/repo/secrets/token)", "FileRead");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        assert!(!state.is_blocking());
        assert!(state.request.read && !state.request.write && !state.request.delete);

        assert_eq!(
            state.handle_key(&ctrl('b'), &req),
            ScopeKeyOutcome::Continue
        );
        assert!(state.is_blocking());
        assert!(state.request.write && state.request.delete);

        // A visit to block mode must not widen the grant on the way back.
        assert_eq!(
            state.handle_key(&ctrl('b'), &req),
            ScopeKeyOutcome::Continue
        );
        assert!(!state.is_blocking());
        assert!(state.request.read && !state.request.write && !state.request.delete);
    }

    #[test]
    fn the_mode_row_picks_a_direction_with_the_arrow_keys() {
        let req = scope_request("FileRead(/repo/secrets/token)", "FileRead");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        // Shift-tab from the directory row reaches the mode row directly.
        state.handle_key(&KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT), &req);
        assert!(state.mode_focused());

        state.handle_key(&press(KeyCode::Right), &req);
        assert!(state.is_blocking());
        state.handle_key(&press(KeyCode::Right), &req);
        assert!(state.is_blocking(), "choosing block twice stays on block");
        state.handle_key(&press(KeyCode::Left), &req);
        assert!(!state.is_blocking());
        state.handle_key(&press(KeyCode::Char(' ')), &req);
        assert!(state.is_blocking(), "space toggles the focused row");
    }

    #[test]
    fn applying_in_block_mode_returns_a_scoped_deny() {
        let req = scope_request("FileRead(/repo/secrets/token)", "FileRead");
        let mut state = ScopeDialogState::blocking_for_request(&req).unwrap();

        match state.handle_key(&press(KeyCode::Enter), &req) {
            ScopeKeyOutcome::Applied(PermissionReviewAction::ScopedDeny(request)) => {
                assert_eq!(request.directory, "/repo/secrets/");
                assert!(request.read && request.write && request.delete);
            }
            other => panic!("expected a scoped deny, got {other:?}"),
        }
    }

    #[test]
    fn block_mode_accepts_a_directory_allow_mode_refuses() {
        let home = dirs::home_dir().expect("home directory");
        let ssh = home.join(".ssh");
        let req = scope_request(
            &format!("FileRead({}/id_ed25519)", ssh.display()),
            "FileRead",
        );

        let mut granting = ScopeDialogState::for_request(&req).unwrap();
        granting.request.write = true;
        assert!(
            granting.apply(&req).is_none(),
            "write authority over ~/.ssh must stay refused"
        );

        let mut blocking = ScopeDialogState::blocking_for_request(&req).unwrap();
        assert!(
            matches!(
                blocking.apply(&req),
                Some(PermissionReviewAction::ScopedDeny(_))
            ),
            "blocking ~/.ssh is exactly what the mode is for"
        );
    }

    #[test]
    fn block_mode_says_so_on_screen() {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        let req = scope_request("FileRead(/repo/secrets/token)", "FileRead");
        let state = ScopeDialogState::blocking_for_request(&req).unwrap();

        terminal
            .draw(|frame| render_scope_permission_panel(frame, frame.area(), &req, &state))
            .unwrap();

        let contents = buffer_contents(&terminal);
        assert!(contents.contains("BLOCK DIRECTORY"));
        assert!(contents.contains("action:"));
        assert!(!contents.contains("will allow"));
        // The directory has to survive the summary line's truncation budget:
        // it is the value the reviewer must read before pressing enter.
        assert!(
            contents.contains("will BLOCK: everything under /repo/secrets/"),
            "the blocked directory must be legible in the summary"
        );
    }

    #[test]
    fn the_action_row_offers_the_block_entry_point() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let req = scope_request("FileRead(/repo/secrets/token)", "FileRead");

        terminal
            .draw(|frame| render_permission_dialog(frame, &req, false, false))
            .unwrap();

        let contents = buffer_contents(&terminal);
        assert!(contents.contains("[b]"));
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(ch: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL)
    }

    /// The caret has to be on screen and on the character it is actually
    /// over. The old field failed both: it drew the caret after a
    /// head-truncating ellipsis while edits landed in the invisible tail.
    fn assert_caret_visible(text: &str, cursor: usize, width: usize) {
        let window = field_window(text, cursor, width);
        assert!(
            window.text.chars().count() <= width,
            "window overflows the field: {:?}",
            window.text
        );
        assert!(
            window.cursor_col < width,
            "caret at {} is off the {width}-column field for {text:?}",
            window.cursor_col
        );
        let full: Vec<char> = text.chars().collect();
        let shown: Vec<char> = window.text.chars().collect();
        if cursor < full.len() {
            assert_eq!(
                shown[window.cursor_col], full[cursor],
                "caret is drawn over the wrong character in {:?}",
                window.text
            );
        }
    }

    #[test]
    fn scope_walk_widens_one_component_at_a_time_and_stops_at_the_floor() {
        let req = scope_request("FileWrite(/a/b/c/d/file.txt)", "FileWrite");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        assert_eq!(state.request.directory, "/a/b/c/d/");

        assert_eq!(
            state.handle_key(&press(KeyCode::Left), &req),
            ScopeKeyOutcome::Continue
        );
        assert_eq!(state.request.directory, "/a/b/c/");
        state.handle_key(&press(KeyCode::Left), &req);
        assert_eq!(state.request.directory, "/a/b/");

        // The floor `reject_broad_or_sensitive_scope` defines. The control is
        // greyed and says why instead of letting the reviewer walk into an
        // Enter-time rejection.
        let WidenProbe::Blocked(reason) = state.widen_probe(&req) else {
            panic!("widening past /a/b/ must be refused");
        };
        assert!(
            reason.contains("/a"),
            "the reason must name the floor: {reason}"
        );
        state.handle_key(&press(KeyCode::Left), &req);
        assert_eq!(
            state.request.directory, "/a/b/",
            "the walk must stop at the floor"
        );

        // A component walk can never land on a partial component, so it can
        // never produce the "does not contain the target" rejection.
        let status = grith_supervisor::scoped_permissions::preview_scoped_allow(
            &state.request,
            &req.tool,
            false,
        );
        assert!(
            !status.blocks_apply(),
            "walked scope must stay applicable: {status:?}"
        );
    }

    #[test]
    fn scope_walk_narrows_back_toward_the_reviewed_target() {
        let req = scope_request("FileWrite(/a/b/c/d/file.txt)", "FileWrite");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        for _ in 0..2 {
            state.handle_key(&press(KeyCode::Left), &req);
        }
        assert_eq!(state.request.directory, "/a/b/");

        state.handle_key(&press(KeyCode::Right), &req);
        assert_eq!(state.request.directory, "/a/b/c/");
        state.handle_key(&press(KeyCode::Right), &req);
        assert_eq!(state.request.directory, "/a/b/c/d/");

        // The reviewed target's own directory is the narrowest scope offered.
        assert!(state.narrow_candidate().is_none());
        state.handle_key(&press(KeyCode::Right), &req);
        assert_eq!(state.request.directory, "/a/b/c/d/");
    }

    #[test]
    fn directory_field_keeps_the_caret_visible_while_typing_and_backspacing() {
        let long =
            "/home/dan/projects/PersonalProjects/Grith/worktrees/grith-analytics-local/work/todos/";
        let req = scope_request(&format!("FileWrite({long}notes.md)"), "FileWrite");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        // 58 columns is what the old fixed-width dialog left for a path; the
        // recorded value is 85 characters long.
        let field = 58;
        assert!(state.request.directory.chars().count() > field);

        state.handle_key(&press(KeyCode::Char('e')), &req);
        assert!(state.editing());
        assert_caret_visible(&state.request.directory, state.cursor(), field);

        for _ in 0..13 {
            state.handle_key(&press(KeyCode::Backspace), &req);
            assert_caret_visible(&state.request.directory, state.cursor(), field);
        }
        for ch in "worktree/".chars() {
            state.handle_key(&press(KeyCode::Char(ch)), &req);
            assert_caret_visible(&state.request.directory, state.cursor(), field);
        }

        // Clipped ends are marked so the value is visibly longer than the box.
        let window = field_window(&state.request.directory, state.cursor(), field);
        assert!(
            window.text.starts_with('\u{2039}'),
            "left clip marker missing: {:?}",
            window.text
        );
    }

    #[test]
    fn cursor_keys_move_within_the_directory_field() {
        let req = scope_request("FileWrite(/a/b/c/d/file.txt)", "FileWrite");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        state.handle_key(&press(KeyCode::Char('e')), &req);
        let end = state.request.directory.chars().count();
        assert_eq!(state.cursor(), end);

        state.handle_key(&press(KeyCode::Left), &req);
        state.handle_key(&press(KeyCode::Left), &req);
        assert_eq!(state.cursor(), end - 2);
        state.handle_key(&press(KeyCode::Right), &req);
        assert_eq!(state.cursor(), end - 1);
        state.handle_key(&press(KeyCode::Home), &req);
        assert_eq!(state.cursor(), 0);
        state.handle_key(&press(KeyCode::Left), &req);
        assert_eq!(state.cursor(), 0, "the caret must not run off the front");
        state.handle_key(&press(KeyCode::End), &req);
        assert_eq!(state.cursor(), end);

        // Typing lands at the caret, not at the end of an invisible tail.
        state.handle_key(&press(KeyCode::Home), &req);
        state.handle_key(&press(KeyCode::Right), &req);
        state.handle_key(&press(KeyCode::Char('x')), &req);
        assert!(
            state.request.directory.starts_with("/xa/"),
            "{}",
            state.request.directory
        );
    }

    #[test]
    fn ctrl_w_deletes_a_whole_component() {
        let req = scope_request("FileWrite(/a/b/c/todos/file.txt)", "FileWrite");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        assert_eq!(state.request.directory, "/a/b/c/todos/");

        state.handle_key(&ctrl('w'), &req);
        assert_eq!(state.request.directory, "/a/b/c/");
        state.handle_key(&ctrl('w'), &req);
        assert_eq!(state.request.directory, "/a/b/");
        assert_eq!(state.cursor(), state.request.directory.chars().count());
    }

    #[test]
    fn status_line_reports_a_missing_target_before_enter() {
        let req = scope_request("FileWrite(/a/b/c/todos/file.txt)", "FileWrite");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        state.handle_key(&press(KeyCode::Char('e')), &req);
        // Overshoot the component boundary the way blind backspacing did.
        for _ in 0..3 {
            state.handle_key(&press(KeyCode::Backspace), &req);
        }
        assert_eq!(state.request.directory, "/a/b/c/tod");
        assert!(state.error.is_none(), "nothing has been applied yet");

        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_scope_permission_panel(frame, frame.area(), &req, &state))
            .unwrap();
        let contents = buffer_contents(&terminal);
        assert!(
            contents.contains("does not contain the target: file.txt"),
            "status line must explain the real cause before Enter: {contents}"
        );

        // And Enter agrees with what the status line said.
        assert_eq!(
            state.handle_key(&press(KeyCode::Enter), &req),
            ScopeKeyOutcome::Continue
        );
        assert!(state.error.is_some());
    }

    /// M6 defect 5: the refusal was rendered with `truncate(&message, width)`,
    /// so the sentence the reviewer was being asked to act on was cut off at
    /// the panel edge. It wraps now, which is only useful if the tail
    /// actually survives.
    #[test]
    fn a_long_refusal_wraps_instead_of_being_cut_off() {
        let name = "a-very-long-file-name-that-pushes-the-status-line-past-the-panel-edge.txt";
        let req = scope_request(&format!("FileWrite(/a/b/c/todos/{name})"), "FileWrite");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        state.handle_key(&press(KeyCode::Char('e')), &req);
        for _ in 0..3 {
            state.handle_key(&press(KeyCode::Backspace), &req);
        }
        // Apply so the inline error path is exercised too, not just the live
        // status: both used to go through the same truncating renderer.
        assert_eq!(
            state.handle_key(&press(KeyCode::Enter), &req),
            ScopeKeyOutcome::Continue
        );
        assert!(state.error.is_some());

        let backend = TestBackend::new(80, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_scope_permission_panel(frame, frame.area(), &req, &state))
            .unwrap();
        let contents = buffer_contents(&terminal);
        assert!(
            contents.contains(name),
            "the refusal was cut off before it named the target: {contents}"
        );
    }

    /// A `[token]` directory is a Next.js dynamic route segment, not a glob.
    /// Session rules match literally, so scoping one works — and these paths
    /// are all over the tree that generated this work item, so refusing them
    /// would take the escape hatch away exactly where it is needed.
    #[test]
    fn a_dynamic_route_segment_is_still_scopable() {
        let req = scope_request("FileRead(/srv/app/api/[token]/route.ts)", "FileRead");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        assert_eq!(state.request.directory, "/srv/app/api/[token]/");

        let status = grith_supervisor::scoped_permissions::preview_scoped_allow(
            &state.request,
            &req.tool,
            false,
        );
        assert!(
            !status.blocks_apply(),
            "a bracketed route segment must stay scopable: {status:?}"
        );
        assert!(matches!(
            state.handle_key(&press(KeyCode::Enter), &req),
            ScopeKeyOutcome::Applied(_)
        ));
    }

    #[test]
    fn glob_directory_is_refused_with_the_teaching_message() {
        let req = scope_request("FileWrite(/a/b/c/todos/file.txt)", "FileWrite");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        state.handle_key(&press(KeyCode::Char('e')), &req);
        for ch in "**".chars() {
            state.handle_key(&press(KeyCode::Char(ch)), &req);
        }

        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_scope_permission_panel(frame, frame.area(), &req, &state))
            .unwrap();
        let contents = buffer_contents(&terminal);
        assert!(
            contents.contains("already covers everything beneath it"),
            "the glob refusal must teach the model: {contents}"
        );
        assert_eq!(
            state.handle_key(&press(KeyCode::Enter), &req),
            ScopeKeyOutcome::Continue,
            "a glob scope must never be applied: it produces a rule that cannot match"
        );
    }

    #[test]
    fn applied_scope_always_covers_the_reviewed_call() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("build");
        std::fs::create_dir(&directory).unwrap();
        let target = directory.join("out.o");
        let req = scope_request(&format!("FileWrite({})", target.display()), "FileWrite");
        let mut state = ScopeDialogState::for_request(&req).unwrap();

        let ScopeKeyOutcome::Applied(PermissionReviewAction::ScopedAllow(applied)) =
            state.handle_key(&press(KeyCode::Enter), &req)
        else {
            panic!("the default scope must apply");
        };
        let validated =
            grith_supervisor::scoped_permissions::validate_scoped_allow(&applied, &req.tool)
                .unwrap();
        // Mirror the supervisor's own target resolution: canonical parent
        // plus the (possibly not-yet-created) leaf.
        let resolved = std::fs::canonicalize(&directory)
            .unwrap()
            .join("out.o")
            .to_string_lossy()
            .into_owned();
        assert!(
            validated.rules.iter().any(|rule| {
                rule.strip_prefix("write-prefix:").is_some_and(|dir| {
                    resolved
                        .strip_prefix(dir.trim_end_matches('/'))
                        .is_some_and(|rest| rest.starts_with('/'))
                })
            }),
            "applied scope installs no rule that matches the reviewed call: {:?}",
            validated.rules
        );
    }

    #[test]
    fn scope_footer_advertises_walking_and_editing() {
        let req = scope_request("FileWrite(/a/b/c/todos/file.txt)", "FileWrite");
        let state = ScopeDialogState::for_request(&req).unwrap();
        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_scope_permission_panel(frame, frame.area(), &req, &state))
            .unwrap();
        let contents = buffer_contents(&terminal);
        assert!(
            contents.contains("wider"),
            "walk control missing: {contents}"
        );
        assert!(
            contents.contains("narrower"),
            "walk control missing: {contents}"
        );
        assert!(
            contents.contains("Edit path"),
            "the footer never said the field was editable: {contents}"
        );
        assert!(
            contents.contains("will allow:"),
            "grant summary missing: {contents}"
        );
    }

    #[test]
    fn typing_opens_the_field_rather_than_being_swallowed() {
        let req = scope_request("FileWrite(/a/b/c/todos/file.txt)", "FileWrite");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        assert!(!state.editing());
        state.handle_key(&press(KeyCode::Char('x')), &req);
        assert!(state.editing(), "a printable key must open the field");
        assert_eq!(state.request.directory, "/a/b/c/todos/x");
    }

    /// work/70: an edited path must never be followed into a broader target
    /// silently. A symlinked scope directory grants authority over wherever
    /// it resolves to, so the resolved path is shown whenever it differs.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_scope_directory_shows_where_it_resolves() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let req = scope_request(
            &format!("FileWrite({})", link.join("out.o").display()),
            "FileWrite",
        );
        let state = ScopeDialogState::for_request(&req).unwrap();
        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_scope_permission_panel(frame, frame.area(), &req, &state))
            .unwrap();
        let contents = buffer_contents(&terminal);
        assert!(
            contents.contains("resolves:"),
            "a symlinked scope must say where it lands: {contents}"
        );
        assert!(contents.contains("/real/"), "{contents}");
    }

    #[test]
    fn escape_leaves_the_field_before_it_leaves_the_dialog() {
        let req = scope_request("FileWrite(/a/b/c/todos/file.txt)", "FileWrite");
        let mut state = ScopeDialogState::for_request(&req).unwrap();
        assert_eq!(
            state.handle_key(&press(KeyCode::Esc), &req),
            ScopeKeyOutcome::Cancel
        );

        state.handle_key(&press(KeyCode::Char('e')), &req);
        assert!(state.editing());
        assert_eq!(
            state.handle_key(&press(KeyCode::Esc), &req),
            ScopeKeyOutcome::Continue
        );
        assert!(!state.editing());
        assert_eq!(
            state.handle_key(&press(KeyCode::Esc), &req),
            ScopeKeyOutcome::Cancel
        );
    }

    #[test]
    fn scope_dialog_widens_for_a_path_the_default_cannot_show() {
        let long =
            "/home/dan/projects/PersonalProjects/Grith/worktrees/grith-analytics-local/work/todos/";
        let req = scope_request(&format!("FileWrite({long}notes.md)"), "FileWrite");
        let state = ScopeDialogState::for_request(&req).unwrap();
        assert!(
            scope_dialog_width(&state) > 76,
            "an 85-character path must not be squeezed into the fixed 76 columns"
        );

        let short = scope_request("FileWrite(/a/b/c.txt)", "FileWrite");
        let short = ScopeDialogState::for_request(&short).unwrap();
        assert_eq!(scope_dialog_width(&short), 76);
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
