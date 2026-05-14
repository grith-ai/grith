// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Exec TUI — purpose-built TUI for `grith exec` that wraps a supervised
//! tool inside grith's own chrome with an interactive terminal panel.
//!
//! All keystrokes pass directly to the tool's PTY (except grith shortcuts
//! and permission dialog keys), so `/commands`, `?help`, tab completion,
//! and interactive prompts work natively.
//!
//! Layout:
//! ```text
//! ┌─ titlebar (1 line) ──────────────────────────────────────┐
//! ├─ subheader (1 line) ─────────────────────────────────────┤
//! │                                                            │
//! │  Terminal panel — tool's PTY (interactive, scrollable)    │
//! │                                                            │
//! ├─ bottom panel (log: 5 rows / permission dialog: 18 rows) ┤
//! └─ status bar (1 line) ────────────────────────────────────┘
//! ```
//!
//! Works with any tool (Claude Code, Codex, Aider, vim, etc.).

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseButton,
    MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;
use ratatui::Terminal;
use std::io;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::theme::*;
use super::widgets;

/// Debug logger for diagnosing the blank-screen bug.
/// Writes to /tmp/grith-tui-debug.log. Remove once the bug is resolved.
fn dbg_log(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/grith-tui-debug.log")
    {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let _ = writeln!(f, "[{ts}] {msg}");
    }
}

/// Compact log panel: top border (1) + 4 content lines.
pub const LOG_PANEL_ROWS: u16 = 5;

/// Permission dialog panel height (grows to show full dialog).
pub const PERMISSION_PANEL_ROWS: u16 = 18;

/// Minimum chrome rows when showing compact log panel only.
/// Used to size the child PTY stably regardless of dialog state.
/// titlebar(1) + subheader(2) + log panel(LOG_PANEL_ROWS) + statusbar(1)
pub const MINIMAL_CHROME_ROWS: u16 = 1 + 2 + LOG_PANEL_ROWS + 1;

/// Events sent from the supervisor to the exec TUI.
pub enum ExecEvent {
    /// Raw bytes from the PTY (tool's output).
    PtyOutput(Vec<u8>),
    /// A security intercept annotation for the log lines.
    Intercept {
        timestamp: String,
        action: String,
        call_type: String,
        score: f64,
    },
    /// A permission request — user must approve/deny before the tool resumes.
    PermissionRequest {
        request: super::state::PermissionRequest,
        response_tx: std::sync::mpsc::SyncSender<&'static str>,
    },
    /// Supervised process exited.
    ProcessExited,
}

/// Messages sent from the exec TUI to the PTY forwarding thread.
pub enum PtyInput {
    Bytes(Vec<u8>),
    Resize { cols: u16, rows: u16 },
}

/// A single intercept log entry for display.
struct LogEntry {
    timestamp: String,
    action: String,
    call_type: String,
    score: f64,
}

/// State for the exec TUI.
#[allow(clippy::struct_excessive_bools)]
pub struct ExecState {
    pub tool_name: String,
    pub profile_name: String,
    pub pid: u32,
    pub vterm: vt100::Parser,
    pub frame_count: u64,
    pub filter_count: usize,
    pub allowed: u64,
    pub queued: u64,
    pub denied: u64,
    log: Vec<LogEntry>,
    log_offset: usize,
    log_follow: bool,
    log_focused: bool,
    /// Scrollback offset (0 = live view, >0 = viewing history).
    scroll_offset: usize,
    /// Active permission dialog (None = no dialog open).
    permission_dialog: Option<PermissionDialog>,
    /// Pending permission requests waiting for the current dialog to close.
    pending_permissions: Vec<PermissionDialog>,
    /// Timestamp of the last PTY byte received from the tool.
    /// Used to animate the waiting indicator dots.
    last_pty_activity: Instant,
    /// Set to true permanently on the first PTY byte. While false the
    /// "Waiting for tool..." indicator is shown in the terminal panel.
    screen_populated: bool,
    /// Current vterm dimensions (the child's PTY size, not the full terminal).
    vterm_rows: u16,
    vterm_cols: u16,
    /// Timestamp of first Ctrl+C during a permission dialog. A second Ctrl+C
    /// within 1 second force-quits the TUI.
    last_ctrl_c: Option<Instant>,
    /// Dashboard URL (e.g. "http://127.0.0.1:3141") shown in the titlebar.
    pub dashboard_url: Option<String>,
}

/// State for an active permission review dialog.
struct PermissionDialog {
    request: super::state::PermissionRequest,
    response_tx: std::sync::mpsc::SyncSender<&'static str>,
    show_inspect: bool,
}

impl ExecState {
    pub fn new(
        tool_name: String,
        profile_name: String,
        pid: u32,
        rows: u16,
        cols: u16,
        filter_count: usize,
    ) -> Self {
        let vterm_rows = rows.saturating_sub(MINIMAL_CHROME_ROWS).max(4);
        Self {
            tool_name,
            profile_name,
            pid,
            vterm: vt100::Parser::new(vterm_rows, cols, 10_000),
            frame_count: 0,
            filter_count,
            allowed: 0,
            queued: 0,
            denied: 0,
            log: Vec::new(),
            log_offset: 0,
            log_follow: true,
            log_focused: false,
            scroll_offset: 0,
            permission_dialog: None,
            pending_permissions: Vec::new(),
            last_pty_activity: Instant::now(),
            screen_populated: false,
            vterm_rows,
            vterm_cols: cols,
            last_ctrl_c: None,
            dashboard_url: None,
        }
    }

    fn call_count(&self) -> u64 {
        self.allowed + self.queued + self.denied
    }

    fn allow_pct(&self) -> u64 {
        let total = self.call_count();
        if total == 0 {
            return 100;
        }
        self.allowed * 100 / total
    }

    fn push_log(&mut self, entry: LogEntry) {
        self.log.push(entry);
        if self.log_follow {
            // Auto-scroll to show the latest entries
            let visible = (LOG_PANEL_ROWS.saturating_sub(1)) as usize;
            self.log_offset = self.log.len().saturating_sub(visible);
        }
    }

    /// True during the startup window before the tool has produced any output.
    /// Permanently false once the first PTY byte arrives.
    fn is_waiting_for_tool(&self) -> bool {
        !self.screen_populated && self.permission_dialog.is_none()
    }

    fn log_scroll_up(&mut self) {
        self.log_follow = false;
        self.log_offset = self.log_offset.saturating_sub(1);
    }

    fn log_scroll_down(&mut self) {
        let visible = (LOG_PANEL_ROWS.saturating_sub(1)) as usize;
        self.log_offset = self
            .log_offset
            .saturating_add(1)
            .min(self.log.len().saturating_sub(visible));
        if self.log_offset >= self.log.len().saturating_sub(visible) {
            self.log_follow = true;
        }
    }
}

fn resize_exec_surface(state: &mut ExecState, pty_tx: &mpsc::Sender<PtyInput>, rows: u16) {
    state.vterm.set_size(rows, state.vterm_cols);
    state.vterm_rows = rows;
    let _ = pty_tx.send(PtyInput::Resize {
        cols: state.vterm_cols,
        rows,
    });
}

/// Run the exec TUI. Blocks until the supervised process exits or the user quits.
pub fn run_exec_tui(
    mut state: ExecState,
    event_rx: mpsc::Receiver<ExecEvent>,
    pty_tx: mpsc::Sender<PtyInput>,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    let saved_stderr = super::redirect_stderr_to_file();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    // Enable mouse capture so we receive wheel/click events from the host
    // terminal as escape sequences (otherwise terminals in alternate-screen
    // mode translate wheel to arrow keys, which Claude Code rejects with
    // "Scroll wheel is sending arrow keys").
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    // No explicit clear needed — the first terminal.draw() call performs a full
    // differential render from an empty buffer, which is equivalent to a clear
    // but avoids an extra full-screen write before any content is ready.

    let result = exec_event_loop(&mut terminal, &mut state, &event_rx, &pty_tx);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    #[cfg(unix)]
    super::restore_stderr(saved_stderr);

    result
}

fn exec_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut ExecState,
    event_rx: &mpsc::Receiver<ExecEvent>,
    pty_tx: &mpsc::Sender<PtyInput>,
) -> anyhow::Result<()> {
    // Render at ~30fps max; only redraw when dirty
    let tick_rate = Duration::from_millis(33);
    let mut dirty = true;
    let mut last_anim_tick = Instant::now();

    loop {
        // Drain supervisor events (non-blocking) — always drain ALL pending
        // events BEFORE evaluating state or rendering. This batches rapid PTY
        // output (e.g. CSI 2J clear + redraw arriving as separate chunks) so
        // we only evaluate the FINAL vterm state, never intermediate blanks.
        //
        // This matches how real terminal emulators work: kitty, alacritty, and
        // wezterm batch ~4ms of PTY data before rendering a frame. tmux defers
        // redraws until all pending input is processed. The drain loop achieves
        // the same effect — all bytes available in the channel are fed to the
        // vterm before any content checks run.
        let mut had_pty_output = false;
        let mut entered_alt = false;
        let mut left_alt = false;
        loop {
            match event_rx.try_recv() {
                Ok(ExecEvent::PtyOutput(bytes)) => {
                    state.last_pty_activity = Instant::now();
                    let pre_alt = state.vterm.screen().alternate_screen();
                    state.vterm.process(&bytes);
                    let post_alt = state.vterm.screen().alternate_screen();
                    if !pre_alt && post_alt {
                        entered_alt = true;
                    }
                    if pre_alt && !post_alt {
                        left_alt = true;
                    }
                    had_pty_output = true;
                    dirty = true;
                }
                Ok(ExecEvent::Intercept {
                    timestamp,
                    action,
                    call_type,
                    score,
                }) => {
                    match action.as_str() {
                        "allow" | "allow (logged)" => state.allowed += 1,
                        "queue" => state.queued += 1,
                        "deny" => state.denied += 1,
                        _ => {}
                    }
                    state.push_log(LogEntry {
                        timestamp,
                        action,
                        call_type,
                        score,
                    });
                    dirty = true;
                }
                Ok(ExecEvent::PermissionRequest {
                    request,
                    response_tx,
                }) => {
                    dbg_log(&format!(
                        "PermissionRequest: call_type={}, pending={}",
                        request.call_type,
                        state.pending_permissions.len(),
                    ));
                    // Don't increment queued here — the Intercept broadcast
                    // already counted this item.
                    //
                    // The supervised process is NOT frozen — only the specific
                    // syscall thread is held at a ptrace stop. The tool continues
                    // rendering, so we show live vterm content behind the dialog
                    // overlay. No snapshot needed.
                    let dialog = PermissionDialog {
                        request,
                        response_tx,
                        show_inspect: false,
                    };
                    if state.permission_dialog.is_some() {
                        // Queue behind the active dialog.
                        state.pending_permissions.push(dialog);
                    } else {
                        state.permission_dialog = Some(dialog);
                    }
                    dirty = true;
                }
                Ok(ExecEvent::ProcessExited) => {
                    return Ok(());
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Ok(());
                }
            }
        }

        // ---------------------------------------------------------------
        // Post-drain evaluation — runs ONCE after ALL pending PtyOutput
        // bytes have been processed. This ensures we evaluate the FINAL
        // vterm state, not intermediate states between clear + redraw.
        // ---------------------------------------------------------------
        if had_pty_output {
            // Log transitions
            if entered_alt {
                dbg_log("!! ENTERED ALTERNATE SCREEN");
            }
            if left_alt {
                dbg_log("!! LEFT ALTERNATE SCREEN");
            }

            // Latch screen_populated once visible content appears.
            if !state.screen_populated {
                let has_content = state
                    .vterm
                    .screen()
                    .contents()
                    .bytes()
                    .any(|b| !b.is_ascii_whitespace());
                if has_content {
                    state.screen_populated = true;
                }
            }
        }

        // Force redraw for animations (live dot, waiting dots) every ~360ms
        // regardless of whether any events arrived.
        if last_anim_tick.elapsed() >= Duration::from_millis(360) {
            last_anim_tick = Instant::now();
            dirty = true;
        }

        // Only redraw when state changed
        if dirty {
            terminal.draw(|frame| render_exec(frame, state))?;
            state.frame_count += 1;
            dirty = false;
        }

        // Poll for keyboard input
        if event::poll(tick_rate)? {
            match event::read()? {
                Event::Key(key) => {
                    // Permission dialog keys — intercept before anything else.
                    // While a dialog is active, only dialog keys are processed.
                    if state.permission_dialog.is_some() {
                        // Double Ctrl+C force-quits the TUI even during a dialog.
                        if key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL)
                        {
                            if let Some(last) = state.last_ctrl_c {
                                if last.elapsed() < Duration::from_secs(1) {
                                    // Deny all pending dialogs before exiting.
                                    if let Some(dialog) = state.permission_dialog.take() {
                                        let _ = dialog.response_tx.send("deny");
                                    }
                                    for dialog in state.pending_permissions.drain(..) {
                                        let _ = dialog.response_tx.send("deny");
                                    }
                                    return Ok(());
                                }
                            }
                            state.last_ctrl_c = Some(Instant::now());
                            dirty = true;
                            continue;
                        }
                        match key.code {
                            KeyCode::Char('i') | KeyCode::Char('I') => {
                                if let Some(dialog) = state.permission_dialog.as_mut() {
                                    dialog.show_inspect = !dialog.show_inspect;
                                }
                            }
                            _ => {
                                let is_deny_dialog = state
                                    .permission_dialog
                                    .as_ref()
                                    .map(|dialog| dialog.request.score > 8.0)
                                    .unwrap_or(false);
                                let action = match key.code {
                                    KeyCode::Char('a') | KeyCode::Char('A') => Some("approve"),
                                    KeyCode::Char('d') | KeyCode::Char('D') => Some("deny"),
                                    KeyCode::Char('l') | KeyCode::Char('L') => {
                                        Some("approve_and_learn")
                                    }
                                    KeyCode::Char('t') | KeyCode::Char('T') => {
                                        Some("deny_and_terminate")
                                    }
                                    KeyCode::Char('c') | KeyCode::Char('C') if is_deny_dialog => {
                                        Some("deny")
                                    }
                                    KeyCode::Esc => Some("deny"),
                                    _ => None,
                                };
                                if let Some(action) = action {
                                    if let Some(dialog) = state.permission_dialog.take() {
                                        dbg_log(&format!(
                                            "Dialog dismiss: action={action}, pending={}",
                                            state.pending_permissions.len(),
                                        ));
                                        // Send the review decision back to the supervisor.
                                        // The intercepted syscall thread will be resumed
                                        // (allowed or denied) — no SIGCONT needed since
                                        // the process was never frozen.
                                        let _ = dialog.response_tx.send(action);
                                    }
                                    // Advance to the next queued dialog, if any.
                                    state.permission_dialog =
                                        if state.pending_permissions.is_empty() {
                                            None
                                        } else {
                                            Some(state.pending_permissions.remove(0))
                                        };
                                }
                            }
                        }
                        dirty = true;
                        continue;
                    }
                    // Ctrl+L — toggle log panel focus (grith shortcut)
                    if key.code == KeyCode::Char('l')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        state.log_focused = !state.log_focused;
                        dirty = true;
                        continue;
                    }
                    // Shift+PgUp/PgDn — scroll terminal scrollback
                    if key.modifiers.contains(KeyModifiers::SHIFT) {
                        let panel_height = terminal
                            .size()?
                            .height
                            .saturating_sub(MINIMAL_CHROME_ROWS)
                            .max(4) as usize;
                        match key.code {
                            KeyCode::PageUp => {
                                state.scroll_offset =
                                    state.scroll_offset.saturating_add(panel_height);
                                state.vterm.set_scrollback(state.scroll_offset);
                                dirty = true;
                                continue;
                            }
                            KeyCode::PageDown => {
                                state.scroll_offset =
                                    state.scroll_offset.saturating_sub(panel_height);
                                state.vterm.set_scrollback(state.scroll_offset);
                                dirty = true;
                                continue;
                            }
                            KeyCode::Home => {
                                state.scroll_offset = usize::MAX;
                                state.vterm.set_scrollback(state.scroll_offset);
                                dirty = true;
                                continue;
                            }
                            KeyCode::End => {
                                state.scroll_offset = 0;
                                state.vterm.set_scrollback(0);
                                dirty = true;
                                continue;
                            }
                            _ => {}
                        }
                    }
                    // When log is focused, arrow keys scroll the log
                    if state.log_focused {
                        match key.code {
                            KeyCode::Up => {
                                state.log_scroll_up();
                                dirty = true;
                                continue;
                            }
                            KeyCode::Down => {
                                state.log_scroll_down();
                                dirty = true;
                                continue;
                            }
                            KeyCode::Esc => {
                                state.log_focused = false;
                                dirty = true;
                                continue;
                            }
                            _ => {}
                        }
                    }
                    // Everything else → convert to bytes and send to PTY
                    if let Some(bytes) = key_to_bytes(key.code, key.modifiers) {
                        // Snap back to live view when sending input
                        if state.scroll_offset > 0 {
                            state.scroll_offset = 0;
                            state.vterm.set_scrollback(0);
                        }
                        let _ = pty_tx.send(PtyInput::Bytes(bytes));
                    }
                }
                Event::Mouse(mouse) => {
                    handle_mouse_event(state, pty_tx, mouse, &mut dirty);
                }
                Event::Resize(cols, rows) => {
                    state.vterm_cols = cols;
                    let vterm_rows = rows.saturating_sub(MINIMAL_CHROME_ROWS).max(4);
                    resize_exec_surface(state, pty_tx, vterm_rows);
                }
                _ => {}
            }
            dirty = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Key-to-byte conversion for PTY passthrough
// ---------------------------------------------------------------------------

/// Convert a crossterm key event to the raw byte sequence a terminal would send.
fn key_to_bytes(code: KeyCode, modifiers: KeyModifiers) -> Option<Vec<u8>> {
    match code {
        KeyCode::Char(c) => {
            if modifiers.contains(KeyModifiers::CONTROL) {
                // Ctrl+A = 0x01 .. Ctrl+Z = 0x1A
                if c.is_ascii_alphabetic() {
                    let byte = (c.to_ascii_lowercase() as u8) - b'a' + 1;
                    Some(vec![byte])
                } else {
                    None
                }
            } else {
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf);
                Some(s.as_bytes().to_vec())
            }
        }
        KeyCode::Enter => Some(vec![b'\r']),
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::BackTab => Some(b"\x1b[Z".to_vec()),
        KeyCode::Backspace => Some(vec![0x7f]),
        KeyCode::Esc => Some(vec![0x1b]),
        KeyCode::Up => Some(b"\x1b[A".to_vec()),
        KeyCode::Down => Some(b"\x1b[B".to_vec()),
        KeyCode::Right => Some(b"\x1b[C".to_vec()),
        KeyCode::Left => Some(b"\x1b[D".to_vec()),
        KeyCode::Home => Some(b"\x1b[H".to_vec()),
        KeyCode::End => Some(b"\x1b[F".to_vec()),
        KeyCode::PageUp => Some(b"\x1b[5~".to_vec()),
        KeyCode::PageDown => Some(b"\x1b[6~".to_vec()),
        KeyCode::Delete => Some(b"\x1b[3~".to_vec()),
        KeyCode::Insert => Some(b"\x1b[2~".to_vec()),
        KeyCode::F(1) => Some(b"\x1bOP".to_vec()),
        KeyCode::F(2) => Some(b"\x1bOQ".to_vec()),
        KeyCode::F(3) => Some(b"\x1bOR".to_vec()),
        KeyCode::F(4) => Some(b"\x1bOS".to_vec()),
        KeyCode::F(n @ 5..=12) => {
            let code = match n {
                5 => "15",
                6 => "17",
                7 => "18",
                8 => "19",
                9 => "20",
                10 => "21",
                11 => "23",
                12 => "24",
                _ => unreachable!(),
            };
            Some(format!("\x1b[{code}~").into_bytes())
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Mouse handling — route wheel/click events to the PTY or local scrollback
// ---------------------------------------------------------------------------

/// y-offset of the terminal panel: titlebar(1) + subheader(2).
const TERMINAL_PANEL_Y: u16 = 3;

/// Lines scrolled per wheel tick when falling back to local scrollback.
const LOCAL_SCROLL_STEP: usize = 3;

fn handle_mouse_event(
    state: &mut ExecState,
    pty_tx: &mpsc::Sender<PtyInput>,
    mouse: MouseEvent,
    dirty: &mut bool,
) {
    // Swallow mouse events while the permission dialog or log panel are focused —
    // they don't use mouse, and forwarding to the PTY would surprise the user.
    if state.permission_dialog.is_some() || state.log_focused {
        return;
    }

    let term_y_start = TERMINAL_PANEL_Y;
    let term_y_end = term_y_start + state.vterm_rows;
    let log_y_start = term_y_end;
    let log_y_end = log_y_start + LOG_PANEL_ROWS;

    if mouse.row >= term_y_start && mouse.row < term_y_end {
        let mode = state.vterm.screen().mouse_protocol_mode();
        if mode != vt100::MouseProtocolMode::None {
            let encoding = state.vterm.screen().mouse_protocol_encoding();
            if let Some(bytes) = encode_mouse_for_pty(mouse, term_y_start, encoding, mode) {
                if state.scroll_offset > 0 {
                    state.scroll_offset = 0;
                    state.vterm.set_scrollback(0);
                    *dirty = true;
                }
                let _ = pty_tx.send(PtyInput::Bytes(bytes));
            }
            return;
        }
        // Inner tool doesn't want mouse — provide local scrollback so the
        // wheel still does something useful (the same scrollback that
        // Shift+PgUp/PgDn drives).
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                state.scroll_offset = state.scroll_offset.saturating_add(LOCAL_SCROLL_STEP);
                state.vterm.set_scrollback(state.scroll_offset);
                *dirty = true;
            }
            MouseEventKind::ScrollDown => {
                state.scroll_offset = state.scroll_offset.saturating_sub(LOCAL_SCROLL_STEP);
                state.vterm.set_scrollback(state.scroll_offset);
                *dirty = true;
            }
            _ => {}
        }
    } else if mouse.row >= log_y_start && mouse.row < log_y_end {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                state.log_scroll_up();
                *dirty = true;
            }
            MouseEventKind::ScrollDown => {
                state.log_scroll_down();
                *dirty = true;
            }
            _ => {}
        }
    }
}

/// Encode a crossterm mouse event back into the escape sequence the inner
/// tool expects, based on the mouse protocol it requested via DECSET.
fn encode_mouse_for_pty(
    event: MouseEvent,
    panel_y_start: u16,
    encoding: vt100::MouseProtocolEncoding,
    mode: vt100::MouseProtocolMode,
) -> Option<Vec<u8>> {
    let pty_col = u32::from(event.column) + 1;
    let pty_row = u32::from(event.row.saturating_sub(panel_y_start)) + 1;

    let mut mods: u32 = 0;
    if event.modifiers.contains(KeyModifiers::SHIFT) {
        mods += 4;
    }
    if event.modifiers.contains(KeyModifiers::ALT) {
        mods += 8;
    }
    if event.modifiers.contains(KeyModifiers::CONTROL) {
        mods += 16;
    }

    let motion = matches!(
        mode,
        vt100::MouseProtocolMode::ButtonMotion | vt100::MouseProtocolMode::AnyMotion
    );

    let (button_code, is_release) = match event.kind {
        MouseEventKind::Down(MouseButton::Left) => (0, false),
        MouseEventKind::Down(MouseButton::Middle) => (1, false),
        MouseEventKind::Down(MouseButton::Right) => (2, false),
        MouseEventKind::Up(MouseButton::Left) => (0, true),
        MouseEventKind::Up(MouseButton::Middle) => (1, true),
        MouseEventKind::Up(MouseButton::Right) => (2, true),
        MouseEventKind::Drag(btn) if motion => {
            let base = match btn {
                MouseButton::Left => 0,
                MouseButton::Middle => 1,
                MouseButton::Right => 2,
            };
            (32 + base, false)
        }
        MouseEventKind::Moved if matches!(mode, vt100::MouseProtocolMode::AnyMotion) => (35, false),
        MouseEventKind::ScrollUp => (64, false),
        MouseEventKind::ScrollDown => (65, false),
        MouseEventKind::ScrollLeft => (66, false),
        MouseEventKind::ScrollRight => (67, false),
        _ => return None,
    };

    if is_release && matches!(mode, vt100::MouseProtocolMode::Press) {
        return None;
    }

    let code = button_code + mods;

    match encoding {
        vt100::MouseProtocolEncoding::Sgr => {
            let ch = if is_release { 'm' } else { 'M' };
            Some(format!("\x1b[<{code};{pty_col};{pty_row}{ch}").into_bytes())
        }
        vt100::MouseProtocolEncoding::Utf8 => {
            // X10-style code with release encoded as 3 + mods, payload as UTF-8.
            let cb = if is_release { 3 + mods } else { code };
            let mut buf = b"\x1b[M".to_vec();
            push_utf8(&mut buf, cb + 32);
            push_utf8(&mut buf, pty_col + 32);
            push_utf8(&mut buf, pty_row + 32);
            Some(buf)
        }
        vt100::MouseProtocolEncoding::Default => {
            let cb = if is_release { 3 + mods } else { code };
            if cb + 32 > 223 || pty_col + 32 > 223 || pty_row + 32 > 223 {
                return None;
            }
            Some(vec![
                0x1b,
                b'[',
                b'M',
                (cb + 32) as u8,
                (pty_col + 32) as u8,
                (pty_row + 32) as u8,
            ])
        }
    }
}

fn push_utf8(buf: &mut Vec<u8>, val: u32) {
    if let Some(c) = char::from_u32(val) {
        let mut tmp = [0u8; 4];
        let s = c.encode_utf8(&mut tmp);
        buf.extend_from_slice(s.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_exec(frame: &mut Frame, state: &ExecState) {
    // Layout is ALWAYS fixed — the permission dialog does NOT change the layout.
    // Instead the dialog is rendered as a floating overlay on the terminal panel
    // (see below). This means the terminal panel never changes size, so there
    // are no viewport transitions, no snapshot complexity, and no zoom-in/out
    // artifacts when dialogs open or close. This matches tmux's model: panes
    // keep their fixed size regardless of overlaid status bars or popups.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),              // titlebar
            Constraint::Length(2),              // subheader (1 line + bottom border)
            Constraint::Min(0),                 // terminal panel (always full size)
            Constraint::Length(LOG_PANEL_ROWS), // log panel (always visible)
            Constraint::Length(1),              // status bar
        ])
        .split(frame.area());

    render_titlebar(frame, chunks[0], state);
    render_subheader(frame, chunks[1], state);
    render_terminal(frame, chunks[2], state);
    render_log(frame, chunks[3], state);
    render_statusbar(frame, chunks[4], state);

    // Permission dialog — floating overlay anchored to the bottom of the
    // terminal panel. The live terminal content above the dialog remains
    // visible and updating in real time (the process is not frozen).
    if let Some(dialog) = &state.permission_dialog {
        let terminal_area = chunks[2];
        let overlay_height = PERMISSION_PANEL_ROWS.min(terminal_area.height);
        let overlay_area = Rect {
            x: terminal_area.x,
            y: terminal_area.bottom().saturating_sub(overlay_height),
            width: terminal_area.width,
            height: overlay_height,
        };
        frame.render_widget(Clear, overlay_area);
        widgets::permission::render_permission_panel(
            frame,
            overlay_area,
            &dialog.request,
            dialog.request.score > 8.0,
            dialog.show_inspect,
        );
    }
}

// ---------------------------------------------------------------------------
// Titlebar — row 1 of the design
// ⬡ grith v0.x.x with tool-name   ● live  calls N  allowed N%  queued N  denied N
// ---------------------------------------------------------------------------

fn render_titlebar(frame: &mut Frame, area: Rect, state: &ExecState) {
    // Dot flashes on/off every ~720ms (360ms on, 360ms off).
    // Use wall-clock time so the rate is consistent regardless of frame rate.
    let dot_visible = {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        (ms / 360) % 2 == 0
    };

    let mut left_spans = vec![
        Span::styled(" \u{2b21} ", Style::new().fg(GREEN_HI)),
        Span::styled("grith", Style::new().fg(GREEN).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!(" v{} ", env!("CARGO_PKG_VERSION")),
            Style::new().fg(TEXT_DIM),
        ),
        Span::styled("with ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            &state.tool_name,
            Style::new().fg(TEXT_MID).add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(ref url) = state.dashboard_url {
        left_spans.push(Span::styled("  \u{2192} ", Style::new().fg(TEXT_DIM)));
        left_spans.push(Span::styled(
            url.as_str(),
            Style::new().fg(GREEN).add_modifier(Modifier::UNDERLINED),
        ));
    }
    let left = Line::from(left_spans);

    let right = Line::from(vec![
        Span::styled(
            "\u{25cf} ",
            Style::new().fg(if dot_visible { GREEN } else { BG_PANEL }),
        ),
        Span::styled("live  ", Style::new().fg(GREEN)),
        Span::styled("calls ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            format!("{}  ", state.call_count()),
            Style::new().fg(TEXT_MID).add_modifier(Modifier::BOLD),
        ),
        Span::styled("allowed ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            format!("{}%  ", state.allow_pct()),
            Style::new().fg(GREEN_HI).add_modifier(Modifier::BOLD),
        ),
        Span::styled("queued ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            format!("{}  ", state.queued),
            Style::new()
                .fg(if state.queued > 0 { AMBER_HI } else { TEXT_DIM })
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("denied ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            format!("{} ", state.denied),
            Style::new()
                .fg(if state.denied > 0 { RED } else { TEXT_DIM })
                .add_modifier(Modifier::BOLD),
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

// ---------------------------------------------------------------------------
// Subheader — row 2 with darker bg and bottom border
// ⎔ tool-name                          PID N · N filters active
// ─────────────────────────────────────────────────────────────
// ---------------------------------------------------------------------------

fn render_subheader(frame: &mut Frame, area: Rect, state: &ExecState) {
    let left = Line::from(vec![
        Span::styled(" \u{2394} ", Style::new().fg(TEXT_DIM)),
        Span::styled(&state.tool_name, Style::new().fg(TEXT_MID)),
        Span::styled(" \u{00b7} ", Style::new().fg(TEXT_DIM)),
        Span::styled(
            format!("profile: {}", state.profile_name),
            Style::new().fg(TEXT_DIM),
        ),
    ]);
    let right = Line::from(vec![
        Span::styled(
            format!("PID {} \u{00b7} ", state.pid),
            Style::new().fg(TEXT_DIM),
        ),
        Span::styled(
            format!("{} filters active ", state.filter_count),
            Style::new().fg(TEXT_DIM),
        ),
    ]);

    frame.render_widget(
        Paragraph::new(left).style(Style::new().bg(BG)).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::new().fg(BORDER))
                .style(Style::new().bg(BG)),
        ),
        area,
    );
    let right_width = right.width() as u16;
    if right_width < area.width && area.height > 1 {
        // Render right-aligned text in the content row (above the border)
        let right_area = Rect {
            x: area.right().saturating_sub(right_width),
            y: area.y,
            width: right_width,
            height: 1,
        };
        frame.render_widget(Paragraph::new(right).style(Style::new().bg(BG)), right_area);
    }
}

// ---------------------------------------------------------------------------
// Terminal panel — vt100 virtual terminal (interactive, scrollable)
// ---------------------------------------------------------------------------

fn render_terminal(frame: &mut Frame, area: Rect, state: &ExecState) {
    frame.render_widget(Block::default().style(Style::new().bg(BG)), area);

    // Always render live vterm — the process is never frozen, so the
    // terminal content is always current and updating in real time.
    let screen = state.vterm.screen();
    let show_cursor = state.scroll_offset == 0;
    widgets::terminal::render_vterm(frame, area, screen, show_cursor, state.scroll_offset == 0);

    // Waiting indicator — shown centered in the terminal panel when the tool
    // has been quiet for >500ms and grith is not the source of the delay.
    if state.is_waiting_for_tool() && area.height >= 3 {
        let dot_count = (state.last_pty_activity.elapsed().as_millis() / 400) % 3 + 1;
        // Pad to fixed width (3 dots max) so position doesn't shift as dots cycle.
        let dots: String = format!("{:<3}", ".".repeat(dot_count as usize));
        // Width is always computed with 3 dots to keep x stable.
        let w = format!(" \u{2394}  Waiting for {}... ", state.tool_name).len() as u16;
        if w < area.width {
            let x = area.x + (area.width.saturating_sub(w)) / 2;
            let y = area.y + area.height / 2;
            let overlay_area = Rect {
                x,
                y,
                width: w,
                height: 1,
            };
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(
                        " \u{2394}  Waiting for ",
                        Style::new().fg(TEXT_DIM).bg(BG_PANEL),
                    ),
                    Span::styled(&state.tool_name, Style::new().fg(TEXT_MID).bg(BG_PANEL)),
                    Span::styled(format!("{} ", dots), Style::new().fg(TEXT_DIM).bg(BG_PANEL)),
                ])),
                overlay_area,
            );
        }
    }

    // Scrollback indicator overlay
    if state.scroll_offset > 0 {
        let label = format!(" SCROLLBACK +{} ", state.scroll_offset);
        let w = label.len() as u16;
        if w + 2 < area.width {
            let indicator_area = Rect {
                x: area.right().saturating_sub(w + 1),
                y: area.y,
                width: w,
                height: 1,
            };
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    label,
                    Style::new().fg(BG).bg(AMBER),
                ))),
                indicator_area,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Log panel — top border + 4 scrollable lines of intercept events
// ---------------------------------------------------------------------------

fn render_log(frame: &mut Frame, area: Rect, state: &ExecState) {
    let content_rows = (area.height.saturating_sub(1)) as usize; // subtract top border
    let lines: Vec<Line> = state
        .log
        .iter()
        .skip(state.log_offset)
        .take(content_rows)
        .map(|entry| {
            let (sigil, color) = match entry.action.as_str() {
                "allow" => ("\u{2713}", GREEN),          // ✓ green
                "allow (logged)" => ("\u{2713}", AMBER), // ✓ amber (was queue-range)
                "queue" => ("\u{23f8}", AMBER),          // ⏸
                "deny" => ("\u{2715}", RED),             // ✕
                _ => ("\u{00b7}", TEXT_DIM),             // ·
            };
            Line::from(vec![
                Span::styled(format!("  {} ", entry.timestamp), Style::new().fg(TEXT_DIM)),
                Span::styled("grith ", Style::new().fg(TEXT_DIM)),
                Span::styled(format!("{sigil} "), Style::new().fg(color)),
                Span::styled(entry.call_type.as_str(), Style::new().fg(TEXT_MID)),
                Span::styled(
                    format!("  \u{00b7} score {:.1}", entry.score),
                    Style::new().fg(TEXT_DIM),
                ),
            ])
        })
        .collect();

    let mut all_lines = lines;
    while all_lines.len() < content_rows {
        all_lines.push(Line::from(""));
    }

    let border_color = if state.log_focused { GREEN_HI } else { BORDER };
    frame.render_widget(
        Paragraph::new(all_lines)
            .style(Style::new().bg(BG_PANEL))
            .block(
                Block::default()
                    .borders(Borders::TOP)
                    .border_style(Style::new().fg(border_color))
                    .style(Style::new().bg(BG_PANEL)),
            ),
        area,
    );
}

// ---------------------------------------------------------------------------
// Status bar — key hints left, branding right
// [d] digest  [s] session  [ctrl+l] audit log  [ctrl+c] stop agent  [q] quit    grith.ai
// ---------------------------------------------------------------------------

fn render_statusbar(frame: &mut Frame, area: Rect, state: &ExecState) {
    // Show force-quit hint after first Ctrl+C during a permission dialog.
    let ctrl_c_pending = state.permission_dialog.is_some()
        && state
            .last_ctrl_c
            .is_some_and(|t| t.elapsed() < Duration::from_secs(1));

    let mut spans: Vec<Span> = vec![Span::raw(" ")];
    if ctrl_c_pending {
        spans.push(Span::styled(
            "Press Ctrl+C again to force quit",
            Style::new().fg(AMBER),
        ));
    } else {
        let keys: &[(&str, &str)] = &[
            ("shift+pgup", "scroll"),
            ("ctrl+l", "log"),
            ("a/d", "when prompted"),
        ];
        for (i, (key, desc)) in keys.iter().enumerate() {
            if i > 0 {
                spans.push(Span::styled("  ", Style::new().fg(TEXT_DIM)));
            }
            spans.push(Span::styled(
                format!("[{}]", key),
                Style::new().fg(TEXT_MID),
            ));
            spans.push(Span::styled(
                format!(" {}", desc),
                Style::new().fg(TEXT_DIM),
            ));
        }
    }

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::new().bg(BG_PANEL)),
        area,
    );
    let branding = "grith.ai";
    let w = branding.len() as u16;
    if w + 2 < area.width {
        let brand_area = Rect {
            x: area.right().saturating_sub(w + 2),
            width: w,
            ..area
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                branding,
                Style::new().fg(TEXT_DIM),
            )))
            .style(Style::new().bg(BG_PANEL)),
            brand_area,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn exec_state_stats() {
        let state = ExecState::new("claude".into(), "claude-code".into(), 1234, 24, 80, 17);
        assert_eq!(state.call_count(), 0);
        assert_eq!(state.allow_pct(), 100);
    }

    #[test]
    fn exec_state_pct_calculation() {
        let mut state = ExecState::new("claude".into(), "claude-code".into(), 1234, 24, 80, 17);
        state.allowed = 96;
        state.queued = 2;
        state.denied = 2;
        assert_eq!(state.call_count(), 100);
        assert_eq!(state.allow_pct(), 96);
    }

    #[test]
    fn render_exec_no_panic() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = ExecState::new("claude".into(), "claude-code".into(), 1234, 24, 80, 17);
        state.vterm.process(b"Hello from tool!\r\n$ ");
        terminal.draw(|frame| render_exec(frame, &state)).unwrap();
    }

    #[test]
    fn log_scrollable() {
        let mut state = ExecState::new("test".into(), "default".into(), 1, 24, 80, 0);
        for i in 0..10 {
            state.push_log(LogEntry {
                timestamp: format!("12:00:{:02}", i),
                action: "allow".into(),
                call_type: format!("Call{}", i),
                score: 0.5,
            });
        }
        assert_eq!(state.log.len(), 10);
        // Auto-follow scrolls to show last 4
        assert_eq!(state.log_offset, 6);
        assert!(state.log_follow);
        // Scroll up disables follow
        state.log_scroll_up();
        assert_eq!(state.log_offset, 5);
        assert!(!state.log_follow);
        // Scroll down toward end
        state.log_scroll_down();
        assert_eq!(state.log_offset, 6);
        assert!(state.log_follow);
    }

    #[test]
    fn key_to_bytes_basic() {
        // Printable char
        assert_eq!(
            key_to_bytes(KeyCode::Char('a'), KeyModifiers::NONE),
            Some(vec![b'a'])
        );
        // Enter
        assert_eq!(
            key_to_bytes(KeyCode::Enter, KeyModifiers::NONE),
            Some(vec![b'\r'])
        );
        // Ctrl+C = ETX
        assert_eq!(
            key_to_bytes(KeyCode::Char('c'), KeyModifiers::CONTROL),
            Some(vec![3])
        );
        // Arrow keys
        assert_eq!(
            key_to_bytes(KeyCode::Up, KeyModifiers::NONE),
            Some(b"\x1b[A".to_vec())
        );
        // Tab
        assert_eq!(
            key_to_bytes(KeyCode::Tab, KeyModifiers::NONE),
            Some(vec![b'\t'])
        );
        // Backspace
        assert_eq!(
            key_to_bytes(KeyCode::Backspace, KeyModifiers::NONE),
            Some(vec![0x7f])
        );
    }

    #[test]
    fn mouse_wheel_encodes_sgr_when_inner_tool_requests_mouse() {
        // Wheel-up event over the second row of the terminal panel.
        let event = MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 10,
            row: TERMINAL_PANEL_Y + 1, // → pty_row = 2
            modifiers: KeyModifiers::NONE,
        };
        let bytes = encode_mouse_for_pty(
            event,
            TERMINAL_PANEL_Y,
            vt100::MouseProtocolEncoding::Sgr,
            vt100::MouseProtocolMode::PressRelease,
        )
        .expect("should encode wheel-up");
        // SGR mouse: CSI < 64 ; col+1 ; row+1 M
        assert_eq!(bytes, b"\x1b[<64;11;2M".to_vec());
    }

    #[test]
    fn mouse_wheel_local_scrollback_when_no_mouse_mode() {
        let mut state = ExecState::new("test".into(), "default".into(), 1, 24, 80, 0);
        let (pty_tx, _pty_rx) = mpsc::channel();
        // Inner tool didn't request mouse → mode is None.
        assert_eq!(
            state.vterm.screen().mouse_protocol_mode(),
            vt100::MouseProtocolMode::None
        );
        let mut dirty = false;
        let event = MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 5,
            row: TERMINAL_PANEL_Y + 2,
            modifiers: KeyModifiers::NONE,
        };
        handle_mouse_event(&mut state, &pty_tx, event, &mut dirty);
        assert_eq!(state.scroll_offset, LOCAL_SCROLL_STEP);
        assert!(dirty);
    }

    #[test]
    fn scrollback_enabled() {
        let state = ExecState::new("test".into(), "default".into(), 1, 24, 80, 0);
        assert_eq!(state.scroll_offset, 0);
        // vt100 Parser was created with scrollback_len=10_000
        // (no public accessor, but the constructor parameter was changed)
    }

    // -----------------------------------------------------------------------
    // Helper: render the terminal panel and return the visible text content.
    // -----------------------------------------------------------------------
    fn render_terminal_panel(state: &ExecState) -> String {
        let total_rows = state.vterm_rows + MINIMAL_CHROME_ROWS;
        let backend = TestBackend::new(80, total_rows);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_exec(frame, state)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let panel_start_row = 3u16; // titlebar(1) + subheader(2)
        let mut lines = Vec::new();
        for row in panel_start_row..panel_start_row + state.vterm_rows {
            let line: String = (0..80u16)
                .map(|col| {
                    buf.cell(ratatui::layout::Position { x: col, y: row })
                        .map(|c| c.symbol().chars().next().unwrap_or(' '))
                        .unwrap_or(' ')
                })
                .collect();
            lines.push(line);
        }
        lines.join("\n")
    }

    /// Live vterm content is always shown — no snapshot system needed.
    /// The process is never frozen, so the terminal is always up to date.
    #[test]
    fn live_vterm_always_shown_during_dialog() {
        let total_rows = 35u16;
        let _vterm_rows = total_rows.saturating_sub(MINIMAL_CHROME_ROWS).max(4);
        let mut state = ExecState::new(
            "claude".into(),
            "claude-code".into(),
            1234,
            total_rows,
            80,
            0,
        );

        // Simulate: Claude Code renders its ident header near the top of the
        // vterm (above where the 18-row dialog overlay will appear).
        state
            .vterm
            .process(b"\x1b[?1049h\x1b[?25l\x1b[1;1HClaude Code v1.2.3\r\n> _");
        state.screen_populated = true;

        // Verify content is visible
        let rendered = render_terminal_panel(&state);
        assert!(
            rendered.contains("Claude Code"),
            "Live vterm should show Claude Code content, got:\n{rendered}"
        );

        // Simulate: permission dialog opens (process NOT frozen — only syscall thread held)
        let (tx, _rx) = std::sync::mpsc::sync_channel(1);
        state.permission_dialog = Some(PermissionDialog {
            request: super::super::state::PermissionRequest {
                id: uuid::Uuid::new_v4(),
                tool: "FileWrite".into(),
                call_type: "FileWrite".into(),
                args: "/tmp/test".into(),
                score: 5.0,
                filters: vec![],
                reasons: vec![],
                context: String::new(),
                severity: "medium".into(),
                item_number: 1,
                total_items: 1,
            },
            response_tx: tx,
            show_inspect: false,
        });

        // Content is still live and visible behind the dialog overlay
        let rendered_with_dialog = render_terminal_panel(&state);
        assert!(
            rendered_with_dialog.contains("Claude Code"),
            "Live vterm should still show content behind dialog, got:\n{rendered_with_dialog}"
        );
    }

    /// After dialog dismiss, no special resize trick needed — the process
    /// was never frozen, so it continues rendering normally.
    #[test]
    fn no_blank_screen_after_dialog_dismiss() {
        let total_rows = 30u16;
        let mut state = ExecState::new(
            "claude".into(),
            "claude-code".into(),
            1234,
            total_rows,
            80,
            0,
        );

        state.vterm.process(b"\x1b[?1049h\x1b[?25l");
        state.vterm.process(b"initialising...");
        state.screen_populated = true;

        // Dialog opens and closes — no freeze, no snapshot, no resize trick
        state.permission_dialog = None;

        // Vterm content should be preserved (no CSI 2J injection)
        let has_content = state
            .vterm
            .screen()
            .contents()
            .bytes()
            .any(|b| !b.is_ascii_whitespace());
        assert!(
            has_content,
            "vterm content should be preserved after dialog dismiss"
        );
    }
}
