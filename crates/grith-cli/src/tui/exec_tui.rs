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
    DisableFocusChange, DisableMouseCapture, EnableFocusChange, EnableMouseCapture, Event, KeyCode,
    KeyModifiers, KeyboardEnhancementFlags, MouseButton, MouseEvent, MouseEventKind,
    PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, supports_keyboard_enhancement, EnterAlternateScreen,
    LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;
use ratatui::Terminal;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{unbounded, Receiver as CbReceiver, Select, TryRecvError};
use grith_digest::PermissionReviewAction;

use super::fullscreen_scrollback::FullscreenScrollback;
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
///
/// Note: permission requests are NOT carried on this channel — they have
/// their own dedicated `PermissionEvent` channel so a backlog of `PtyOutput`
/// events under heavy load cannot delay a user-facing permission prompt.
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
    /// Supervised process exited.
    ProcessExited,
}

/// A permission request — user must approve/deny before the tool resumes.
/// Carried on a dedicated channel; the TUI's `select!` arm for permissions
/// is biased ahead of supervisor events so prompt latency stays sub-frame
/// regardless of `ExecEvent` queue depth.
pub struct PermissionEvent {
    pub request: super::state::PermissionRequest,
    pub response_tx: std::sync::mpsc::SyncSender<PermissionReviewAction>,
}

/// Messages on the dedicated permission channel.
pub enum PermissionMessage {
    /// A new permission request awaiting an operator decision.
    Request(Box<PermissionEvent>),
    /// The reviewer stopped waiting for the identified request (the review
    /// timed out and the operation was denied). The dialog is stale —
    /// answering it would change nothing — so the TUI drops it, letting any
    /// queued prompts surface instead of stacking behind a dead one.
    Cancel(uuid::Uuid),
}

/// Supervisor-event drain budget per loop iteration. After `DRAIN_BUDGET`
/// elapses OR `DRAIN_MAX` events have been processed (whichever first),
/// the loop yields to input/render/pacing. Keeps the loop from monopolising
/// on PTY-output bursts during heavy syscall load (cargo install, mold link).
const DRAIN_BUDGET: Duration = Duration::from_millis(8);
const DRAIN_MAX: usize = 256;
/// Re-check the input channel after every Nth supervisor event during a
/// drain pass — bounds in-pass keystroke latency to ~N events worth of vterm
/// processing time.
const INPUT_RECHECK_INTERVAL: usize = 64;

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
    /// Line-oriented `vt100` scrollback offset (0 = live view, >0 = viewing
    /// rows that scrolled off the top of the grid). Used for normal shell
    /// output, line-by-line tools, and (when fullscreen-mirror is active)
    /// the mirror's accumulated frame history. A single offset drives
    /// whichever backing scrollback applies to the current tool.
    scroll_offset: usize,
    /// Parallel "scrollback mirror" `vt100::Parser`. Frame contents from
    /// fullscreen-repaint tools (Codex etc.) are appended row-by-row into
    /// the mirror's primary grid, where vt100's built-in scrollback
    /// machinery handles the actual scroll buffer. Active only when the
    /// supervised tool emits fullscreen repaint signals.
    fullscreen_scrollback: FullscreenScrollback,
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
    /// DECSET ?1007 alternate-scroll mode requested by the child.
    ///
    /// `vt100` 0.15 tracks xterm mouse modes but not alternate-scroll mode.
    /// Full-screen TUIs such as Codex use ?1007 so terminals translate wheel
    /// movement into cursor-key input. Grith has to emulate that translation
    /// because the outer terminal's mouse capture sends wheel events to us.
    alternate_scroll_mode: bool,
    /// DECSET ?1004 focus-event reporting requested by the child.
    ///
    /// The vt100 parser swallows the request, so grith must play the
    /// terminal's role: reply with the current focus state when the mode is
    /// enabled and forward host focus transitions while it stays on.
    /// Claude Code gates prompt-suggestion generation on a focus-in report —
    /// without this, focus stays "unknown" and suggestions never appear.
    focus_reporting_mode: bool,
    /// Last known host-terminal focus state. Defaults to focused: the user
    /// just launched us from this terminal, and a host that doesn't support
    /// ?1004 will never report a transition.
    host_focused: bool,
    /// Tail bytes retained so the ?1007 scanner handles CSI sequences split
    /// across PTY chunks.
    mode_scan_tail: Vec<u8>,
    /// Timestamp of first Ctrl+C during a permission dialog. A second Ctrl+C
    /// within 1 second force-quits the TUI.
    last_ctrl_c: Option<Instant>,
    /// Dashboard URL (e.g. "http://127.0.0.1:3141") shown in the titlebar.
    pub dashboard_url: Option<String>,
    /// Whether host-terminal mouse capture is currently active.
    ///
    /// Default `true`: grith grabs wheel/click events so the scroll wheel drives
    /// our scrollback (instead of the host translating it to arrow keys the tool
    /// rejects). The side effect of capture is that the terminal routes click +
    /// drag to grith too, so native text selection ("highlight to copy") stops
    /// working. Toggling this off (Ctrl+T) issues `DisableMouseCapture`, handing
    /// the mouse back to the terminal so plain drag-selects again — at the cost
    /// of the wheel falling back to the host's default until re-enabled.
    mouse_capture: bool,
}

/// State for an active permission review dialog.
struct PermissionDialog {
    request: super::state::PermissionRequest,
    response_tx: std::sync::mpsc::SyncSender<PermissionReviewAction>,
    show_inspect: bool,
    scope: Option<widgets::permission::ScopeDialogState>,
    /// The key-reference overlay is showing. Modal: while open, decision
    /// keys are inert so nobody approves by accident mid-read.
    show_help: bool,
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
            fullscreen_scrollback: {
                let mut fs = FullscreenScrollback::with_default_capacity();
                fs.resize_mirror(vterm_rows, cols);
                fs
            },
            permission_dialog: None,
            pending_permissions: Vec::new(),
            last_pty_activity: Instant::now(),
            screen_populated: false,
            vterm_rows,
            vterm_cols: cols,
            alternate_scroll_mode: false,
            focus_reporting_mode: false,
            host_focused: true,
            mode_scan_tail: Vec::new(),
            last_ctrl_c: None,
            dashboard_url: None,
            mouse_capture: true,
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

    /// True if the supervised tool is repainting full frames and we have at
    /// least one captured snapshot — scrollback navigation should walk that
    /// ring instead of the (mostly empty) `vt100` scrollback grid.
    fn use_fullscreen_history(&self) -> bool {
        // Claude Code prints its conversation as line-oriented output, which
        // lands in vt100's 10k-line scrollback (proven: scrolling it natively
        // shows the real transcript). It only trips `repaint_mode` because it
        // repaints its input box / status line in place — but that chrome
        // never enters scrollback. Routing its wheel to the fullscreen-FRAME
        // history would show captured repaints (startup banners, menus)
        // instead of the actual chat. So keep Claude Code on the vt100
        // line-scrollback path. (The frame-history path remains for genuine
        // fullscreen repainters whose content never reaches vt100 scrollback.)
        self.fullscreen_scrollback.repaint_mode()
            && !self.fullscreen_scrollback.is_empty()
            && !is_claude_code_tool(self)
    }

    /// Reset all scrollback paths so input snaps back to the live screen.
    fn snap_to_live(&mut self) {
        if self.scroll_offset != 0 {
            self.scroll_offset = 0;
            self.vterm.set_scrollback(0);
        }
    }

    fn observe_pty_modes(&mut self, bytes: &[u8]) {
        let mut combined = Vec::with_capacity(self.mode_scan_tail.len() + bytes.len());
        combined.extend_from_slice(&self.mode_scan_tail);
        combined.extend_from_slice(bytes);
        update_private_modes(
            &combined,
            &mut self.alternate_scroll_mode,
            &mut self.focus_reporting_mode,
        );

        const MODE_SCAN_TAIL_MAX: usize = 48;
        let keep = combined.len().min(MODE_SCAN_TAIL_MAX);
        self.mode_scan_tail.clear();
        self.mode_scan_tail
            .extend_from_slice(&combined[combined.len().saturating_sub(keep)..]);
    }
}

fn update_private_modes(bytes: &[u8], alternate_scroll: &mut bool, focus_reporting: &mut bool) {
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] != 0x1b || bytes[i + 1] != b'[' || bytes[i + 2] != b'?' {
            i += 1;
            continue;
        }

        let mut j = i + 3;
        while j < bytes.len() {
            let b = bytes[j];
            if (0x40..=0x7e).contains(&b) {
                if matches!(b, b'h' | b'l') {
                    let params = &bytes[i + 3..j];
                    if csi_params_include(params, b"1007") {
                        *alternate_scroll = b == b'h';
                    }
                    if csi_params_include(params, b"1004") {
                        *focus_reporting = b == b'h';
                    }
                }
                i = j;
                break;
            }
            j += 1;
        }
        i += 1;
    }
}

fn csi_params_include(params: &[u8], mode: &[u8]) -> bool {
    params.split(|b| *b == b';').any(|part| part == mode)
}

/// The focus report a terminal sends for the given focus state:
/// `CSI I` (focus in) or `CSI O` (focus out).
fn focus_report_bytes(focused: bool) -> &'static [u8] {
    if focused {
        b"\x1b[I"
    } else {
        b"\x1b[O"
    }
}

fn resize_exec_surface(state: &mut ExecState, pty_tx: &mpsc::Sender<PtyInput>, rows: u16) {
    state.vterm.set_size(rows, state.vterm_cols);
    state.vterm_rows = rows;
    state
        .fullscreen_scrollback
        .resize_mirror(rows, state.vterm_cols);
    let _ = pty_tx.send(PtyInput::Resize {
        cols: state.vterm_cols,
        rows,
    });
}

/// Feed PTY bytes through the vt100 parser, catching panics from the
/// upstream wide-character handling path.
///
/// vt100 0.15.2 panics with `Option::unwrap() on a None value` at
/// `src/screen.rs:934` inside `fn text` when a wide-character cell
/// lookup misses the grid — most commonly observed after a terminal
/// resize while a tool is writing wide characters near the right edge.
/// The bug persists in upstream 0.16.2; no clean fix has been published.
/// See `work/futurework/vt100-panic-followup.md`.
///
/// We swallow the panic, log it (without spamming on repeat hits),
/// re-create the parser at current dimensions, and drop the offending
/// byte chunk. Lossy on the failing render but keeps the TUI alive —
/// the alternative is the host process exiting raw mode mid-session.
fn process_pty_bytes_resilient(state: &mut ExecState, bytes: &[u8]) {
    // Take ownership of the parser so we can replace it on panic without
    // satisfying UnwindSafe on the whole ExecState.
    let mut parser = std::mem::replace(
        &mut state.vterm,
        vt100::Parser::new(state.vterm_rows, state.vterm_cols, 10_000),
    );
    let bytes_vec = bytes.to_vec();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        parser.process(&bytes_vec);
    }));
    match outcome {
        Ok(()) => {
            state.vterm = parser;
        }
        Err(_) => {
            // Parser is poisoned; keep the fresh replacement that's
            // already in state.vterm. Log the recovery so we can spot
            // a flood — anything more than one or two per session
            // means the upstream bug is hitting a hot path and we
            // should consider migrating to a maintained fork.
            tracing::error!(
                rows = state.vterm_rows,
                cols = state.vterm_cols,
                dropped_bytes = bytes_vec.len(),
                "vt100 parser panicked; reset to fresh parser (terminal content may be lost for this chunk)"
            );
        }
    }
}

/// Run the exec TUI. Blocks until the supervised process exits or the user quits.
///
/// `event_rx` carries bulk supervisor events (PTY output, intercept log entries,
/// process-exit). `permission_rx` carries permission-request prompts on a
/// dedicated channel so they aren't queued behind a backlog of PTY output
/// under heavy syscall load.
pub fn run_exec_tui(
    mut state: ExecState,
    event_rx: CbReceiver<ExecEvent>,
    permission_rx: CbReceiver<PermissionMessage>,
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
    // EnableFocusChange asks the host for ?1004 focus reports so we can
    // relay real focus transitions to the child. Hosts without support
    // simply never report; `host_focused` then stays at its focused default.
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableFocusChange
    )?;

    // Request keyboard disambiguation so the host terminal reports
    // Ctrl+Enter / Shift+Enter as distinct events. Legacy terminals send a
    // bare CR for these, indistinguishable from plain Enter, so the modifier
    // never reaches us and `key_to_bytes` can't emit the newline form.
    // DISAMBIGUATE_ESCAPE_CODES alone does NOT enable key-release reporting,
    // so it won't double keystrokes. Probe support first (this issues a
    // terminal query and must run before the input thread starts consuming
    // stdin) and only push when the terminal advertises support, so we can
    // pop exactly what we pushed on teardown.
    let pushed_kbd_enhancement = matches!(supports_keyboard_enhancement(), Ok(true));
    if pushed_kbd_enhancement {
        execute!(
            stdout,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        )?;
    }

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    // No explicit clear needed — the first terminal.draw() call performs a full
    // differential render from an empty buffer, which is equivalent to a clear
    // but avoids an extra full-screen write before any content is ready.

    // Spawn a dedicated input thread. Moves crossterm's blocking event::read
    // off the main loop so the loop wakes immediately on either supervisor
    // events or keystrokes via crossbeam select! — instead of polling stdin
    // only after draining the supervisor channel.
    let (input_tx, input_rx) = unbounded::<Event>();
    let input_shutdown = Arc::new(AtomicBool::new(false));
    let input_handle = super::input_thread::spawn(input_tx, input_shutdown.clone());

    let result = exec_event_loop(
        &mut terminal,
        &mut state,
        &event_rx,
        &permission_rx,
        &input_rx,
        &pty_tx,
    );

    // Tell the input thread to exit, then join it so we leave the stdin
    // reader in a clean state before disabling raw mode.
    input_shutdown.store(true, Ordering::Relaxed);
    drop(input_rx); // close receiver so any in-flight send returns Err
    let _ = input_handle.join();

    if pushed_kbd_enhancement {
        // Restore the host terminal's keyboard mode before leaving raw mode.
        let _ = execute!(terminal.backend_mut(), PopKeyboardEnhancementFlags);
    }
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableFocusChange,
        DisableMouseCapture,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    #[cfg(unix)]
    super::restore_stderr(saved_stderr);

    result
}

/// Outcome of processing a keyboard/mouse/resize event.
enum InputOutcome {
    /// Normal event handled, continue loop.
    Continue,
    /// User requested exit (double Ctrl+C during a permission dialog).
    Exit,
}

fn exec_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut ExecState,
    event_rx: &CbReceiver<ExecEvent>,
    permission_rx: &CbReceiver<PermissionMessage>,
    input_rx: &CbReceiver<Event>,
    pty_tx: &mpsc::Sender<PtyInput>,
) -> anyhow::Result<()> {
    // Render at ~30fps max; only redraw when dirty
    let tick_rate = Duration::from_millis(33);
    let mut dirty = true;
    let mut last_anim_tick = Instant::now();

    loop {
        // ─── Phase 1: drain input (priority, non-blocking, fully) ─────────
        // Human typing rate is tiny, so drain everything. Permission-dialog
        // keys, scrollback navigation, and PTY-bound keystrokes all flow
        // through here before any supervisor backlog is touched.
        while let Ok(ev) = input_rx.try_recv() {
            match handle_input_event(state, pty_tx, terminal, ev, &mut dirty)? {
                InputOutcome::Continue => {}
                InputOutcome::Exit => return Ok(()),
            }
        }

        // ─── Phase 2: drain permission requests (high priority) ───────────
        // Permission prompts are user-facing and block the supervised tool
        // until answered. Drain ahead of bulk events so a 256-event PTY-out
        // backlog never delays a prompt.
        while let Ok(msg) = permission_rx.try_recv() {
            match msg {
                PermissionMessage::Request(perm) => enqueue_permission(state, *perm),
                PermissionMessage::Cancel(id) => cancel_permission(state, id),
            }
            dirty = true;
        }

        // ─── Phase 3: drain supervisor events (bounded) ───────────────────
        // Always drain pending events BEFORE rendering — batching rapid PTY
        // output (e.g. CSI 2J clear + redraw arriving as separate chunks) so
        // the final vterm state is what we render, never an intermediate
        // blank. This matches kitty/alacritty/wezterm's 4ms batch behaviour.
        //
        // Bounded by both wall-clock (DRAIN_BUDGET) and event count
        // (DRAIN_MAX) so a sustained burst (mold linker under ptrace) can't
        // monopolise the loop and starve input/render. Input is re-checked
        // mid-pass every INPUT_RECHECK_INTERVAL events for sub-pass latency.
        let drain_start = Instant::now();
        let mut drained = 0usize;
        let mut had_pty_output = false;
        let mut entered_alt = false;
        let mut left_alt = false;
        let mut should_exit = false;
        'drain: while drained < DRAIN_MAX && drain_start.elapsed() < DRAIN_BUDGET {
            match event_rx.try_recv() {
                Ok(ExecEvent::PtyOutput(bytes)) => {
                    state.last_pty_activity = Instant::now();
                    let focus_reporting_was_on = state.focus_reporting_mode;
                    state.observe_pty_modes(&bytes);
                    // The child just enabled ?1004 focus reporting. A real
                    // terminal reports the current focus state on enable, so
                    // do the same — Claude Code waits on this focus-in before
                    // it will generate prompt suggestions.
                    if !focus_reporting_was_on && state.focus_reporting_mode {
                        dbg_log(&format!(
                            "child enabled ?1004; synthesizing focus report focused={}",
                            state.host_focused
                        ));
                        let _ = pty_tx.send(PtyInput::Bytes(
                            focus_report_bytes(state.host_focused).to_vec(),
                        ));
                    }
                    state.fullscreen_scrollback.observe_bytes(&bytes);
                    let pre_alt = state.vterm.screen().alternate_screen();
                    process_pty_bytes_resilient(state, &bytes);
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
                    if should_display_intercept_log(&action, &call_type, score) {
                        state.push_log(LogEntry {
                            timestamp,
                            action,
                            call_type,
                            score,
                        });
                    }
                    dirty = true;
                }
                Ok(ExecEvent::ProcessExited) => {
                    should_exit = true;
                    break 'drain;
                }
                Err(TryRecvError::Empty) => break 'drain,
                Err(TryRecvError::Disconnected) => {
                    should_exit = true;
                    break 'drain;
                }
            }
            drained += 1;

            // Interleaved input re-check during a long batch — bounds
            // in-pass keystroke latency to ~INPUT_RECHECK_INTERVAL events.
            if drained % INPUT_RECHECK_INTERVAL == 0 {
                while let Ok(ev) = input_rx.try_recv() {
                    match handle_input_event(state, pty_tx, terminal, ev, &mut dirty)? {
                        InputOutcome::Continue => {}
                        InputOutcome::Exit => return Ok(()),
                    }
                }
            }
        }
        if should_exit {
            return Ok(());
        }

        // ---------------------------------------------------------------
        // Post-drain evaluation — runs ONCE after a drain pass. This
        // ensures we evaluate the FINAL vterm state (within the batch),
        // not intermediate states between clear + redraw.
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

            // Capture a fullscreen-history frame if the batch closed on a
            // repaint boundary. Done once per drain pass so we evaluate the
            // FINAL post-batch screen, never an intermediate.
            state
                .fullscreen_scrollback
                .capture_if_boundary_reached(state.vterm.screen(), state.last_pty_activity);
        }

        // Force redraw for animations (live dot, waiting dots) every ~360ms
        // regardless of whether any events arrived.
        if last_anim_tick.elapsed() >= Duration::from_millis(360) {
            last_anim_tick = Instant::now();
            dirty = true;
        }

        // ─── Phase 4: render if dirty ─────────────────────────────────────
        // While in select mode (mouse capture off via Ctrl+T) we FREEZE
        // repaints: a redraw would wipe the terminal's drag-selection the
        // instant it's made. The PTY keeps being parsed into `state.vterm`; we
        // just don't paint. Exiting select mode (or a permission dialog that
        // must be shown) repaints and catches up. A permission dialog overrides
        // the freeze so a queued decision is never hidden behind a frozen frame.
        let frozen_for_selection = !state.mouse_capture && state.permission_dialog.is_none();
        if dirty && !frozen_for_selection {
            terminal.draw(|frame| render_exec(frame, state))?;
            state.frame_count += 1;
            dirty = false;
        }

        // ─── Phase 5: pace via Select::ready_timeout ──────────────────────
        // Park until any channel has data or the tick elapses. `ready_timeout`
        // is readiness-only — it does NOT consume the message, so the next
        // loop iteration's try_recv drains pick it up. Using the consuming
        // `select!` macro here would eat PTY-output bytes (blank TUI) and
        // keystrokes (unresponsive input) that arrived during pacing.
        let mut sel = Select::new();
        sel.recv(input_rx);
        sel.recv(permission_rx);
        sel.recv(event_rx);
        let _ = sel.ready_timeout(tick_rate);
    }
}

/// Enqueue a permission request from the dedicated channel into the TUI's
/// dialog state. If a dialog is already showing, the new request queues
/// behind it; otherwise it becomes the active dialog.
fn enqueue_permission(state: &mut ExecState, perm: PermissionEvent) {
    dbg_log(&format!(
        "PermissionRequest: call_type={}, pending={}",
        perm.request.call_type,
        state.pending_permissions.len(),
    ));
    // Don't increment queued here — the Intercept broadcast already
    // counted this item.
    //
    // The supervised process is NOT frozen — only the specific syscall
    // thread is held at a ptrace stop. The tool continues rendering, so
    // we show live vterm content behind the dialog overlay.
    let dialog = PermissionDialog {
        request: perm.request,
        response_tx: perm.response_tx,
        show_inspect: false,
        scope: None,
        show_help: false,
    };
    if state.permission_dialog.is_some() {
        state.pending_permissions.push(dialog);
    } else {
        state.permission_dialog = Some(dialog);
    }
}

/// Drop a stale permission dialog whose review the supervisor abandoned
/// (timeout). The active dialog is replaced by the next queued one; a
/// queued dialog is removed in place. A decision the user is about to make
/// on a cancelled dialog would be sent into a closed channel and ignored —
/// dropping the dialog makes that visible instead of silent.
fn cancel_permission(state: &mut ExecState, id: uuid::Uuid) {
    dbg_log(&format!(
        "PermissionCancel: id={id}, pending={}",
        state.pending_permissions.len(),
    ));
    if state
        .permission_dialog
        .as_ref()
        .is_some_and(|d| d.request.id == id)
    {
        state.permission_dialog = if state.pending_permissions.is_empty() {
            None
        } else {
            Some(state.pending_permissions.remove(0))
        };
        return;
    }
    state.pending_permissions.retain(|d| d.request.id != id);
}

/// Handle a single keyboard/mouse/resize event from the input thread.
/// Returns `InputOutcome::Exit` when the user requests a force-quit
/// (double Ctrl+C during a permission dialog).
fn handle_input_event(
    state: &mut ExecState,
    pty_tx: &mpsc::Sender<PtyInput>,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ev: Event,
    dirty: &mut bool,
) -> anyhow::Result<InputOutcome> {
    match ev {
        Event::Key(key) => {
            // Permission dialog keys — intercept before anything else.
            // While a dialog is active, only dialog keys are processed.
            if state.permission_dialog.is_some() {
                // Double Ctrl+C force-quits the TUI even during a dialog.
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    if let Some(last) = state.last_ctrl_c {
                        if last.elapsed() < Duration::from_secs(1) {
                            // Deny all pending dialogs before exiting.
                            if let Some(dialog) = state.permission_dialog.take() {
                                let _ = dialog.response_tx.send(PermissionReviewAction::Deny);
                            }
                            for dialog in state.pending_permissions.drain(..) {
                                let _ = dialog.response_tx.send(PermissionReviewAction::Deny);
                            }
                            return Ok(InputOutcome::Exit);
                        }
                    }
                    state.last_ctrl_c = Some(Instant::now());
                    *dirty = true;
                    return Ok(InputOutcome::Continue);
                }
                // Help overlay: modal — only closing keys act; everything
                // else is swallowed so a decision can't be made blind.
                if state
                    .permission_dialog
                    .as_ref()
                    .is_some_and(|dialog| dialog.show_help)
                {
                    if let Some(dialog) = state.permission_dialog.as_mut() {
                        if matches!(
                            key.code,
                            KeyCode::Char('h')
                                | KeyCode::Char('H')
                                | KeyCode::Char('q')
                                | KeyCode::Esc
                        ) {
                            dialog.show_help = false;
                        }
                    }
                    *dirty = true;
                    return Ok(InputOutcome::Continue);
                }
                if state
                    .permission_dialog
                    .as_ref()
                    .is_some_and(|dialog| dialog.scope.is_some())
                {
                    let mut applied = None;
                    if let Some(dialog) = state.permission_dialog.as_mut() {
                        let scope = dialog.scope.as_mut().expect("scope checked above");
                        match key.code {
                            KeyCode::Esc => dialog.scope = None,
                            KeyCode::Enter => {
                                applied = scope.apply(&dialog.request);
                            }
                            KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
                                scope.focus_previous();
                            }
                            KeyCode::Tab | KeyCode::Down => scope.focus_next(),
                            KeyCode::BackTab | KeyCode::Up => scope.focus_previous(),
                            KeyCode::Backspace if scope.directory_focused() => {
                                scope.pop_directory_char();
                            }
                            KeyCode::Char('u')
                                if scope.directory_focused()
                                    && key.modifiers.contains(KeyModifiers::CONTROL) =>
                            {
                                scope.clear_directory();
                            }
                            KeyCode::Char(' ') if !scope.directory_focused() => {
                                scope.toggle_focused();
                            }
                            KeyCode::Char(ch)
                                if scope.directory_focused() && key.modifiers.is_empty() =>
                            {
                                scope.push_directory_char(ch);
                            }
                            _ => {}
                        }
                    }
                    if let Some(action) = applied {
                        dismiss_permission_dialog(state, action);
                    }
                    *dirty = true;
                    return Ok(InputOutcome::Continue);
                }
                match key.code {
                    KeyCode::Char('i') | KeyCode::Char('I') => {
                        if let Some(dialog) = state.permission_dialog.as_mut() {
                            dialog.show_inspect = !dialog.show_inspect;
                        }
                    }
                    KeyCode::Char('h') | KeyCode::Char('H') => {
                        if let Some(dialog) = state.permission_dialog.as_mut() {
                            dialog.show_help = true;
                        }
                    }
                    KeyCode::Char('s') | KeyCode::Char('S') => {
                        if let Some(dialog) = state.permission_dialog.as_mut() {
                            if dialog.request.score <= 8.0 {
                                dialog.scope = widgets::permission::ScopeDialogState::for_request(
                                    &dialog.request,
                                );
                            }
                        }
                    }
                    _ => {
                        let is_deny_dialog = state
                            .permission_dialog
                            .as_ref()
                            .map(|dialog| dialog.request.score > 8.0)
                            .unwrap_or(false);
                        let action = match key.code {
                            KeyCode::Char('a') | KeyCode::Char('A') => {
                                Some(PermissionReviewAction::Approve)
                            }
                            KeyCode::Char('d') | KeyCode::Char('D') => {
                                Some(PermissionReviewAction::Deny)
                            }
                            KeyCode::Char('l') | KeyCode::Char('L') => {
                                Some(PermissionReviewAction::ApproveAndLearn)
                            }
                            KeyCode::Char('t') | KeyCode::Char('T') => {
                                Some(PermissionReviewAction::DenyAndTerminate)
                            }
                            KeyCode::Char('c') | KeyCode::Char('C') if is_deny_dialog => {
                                Some(PermissionReviewAction::Deny)
                            }
                            KeyCode::Esc => Some(PermissionReviewAction::Deny),
                            _ => None,
                        };
                        if let Some(action) = action {
                            dismiss_permission_dialog(state, action);
                        }
                    }
                }
                *dirty = true;
                return Ok(InputOutcome::Continue);
            }
            // Ctrl+L — toggle log panel focus (grith shortcut)
            if key.code == KeyCode::Char('l') && key.modifiers.contains(KeyModifiers::CONTROL) {
                state.log_focused = !state.log_focused;
                *dirty = true;
                return Ok(InputOutcome::Continue);
            }
            // Ctrl+T — toggle host-terminal mouse capture (grith shortcut).
            // Capture ON  → wheel drives grith's scrollback (the scroll fix),
            //               but the terminal routes drag to us, disabling native
            //               text selection.
            // Capture OFF → hand the mouse back so plain drag selects/copies;
            //               the wheel reverts to the host default until re-enabled.
            if key.code == KeyCode::Char('t') && key.modifiers.contains(KeyModifiers::CONTROL) {
                state.mouse_capture = !state.mouse_capture;
                let mut out = io::stdout();
                let _ = if state.mouse_capture {
                    execute!(out, EnableMouseCapture)
                } else {
                    execute!(out, DisableMouseCapture)
                };
                // Repaint once now so the footer reflects the new mode. When
                // entering select mode this is the LAST paint until the user
                // toggles back — the loop freezes repaints so a drag-selection
                // isn't wiped. When leaving, the loop resumes live repaints.
                terminal.draw(|frame| render_exec(frame, state))?;
                *dirty = false;
                return Ok(InputOutcome::Continue);
            }
            // Shift+PgUp/PgDn — scroll terminal scrollback. Fullscreen
            // history mode (paginated repaint TUIs) walks the snapshot
            // ring by frame; line-oriented output falls through to vt100
            // scrollback as before.
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                let panel_height = terminal
                    .size()?
                    .height
                    .saturating_sub(MINIMAL_CHROME_ROWS)
                    .max(4) as usize;
                let history_active = state.use_fullscreen_history();
                match key.code {
                    KeyCode::PageUp => {
                        state.scroll_offset = state.scroll_offset.saturating_add(panel_height);
                        if history_active {
                            // Clamp to available history so we don't
                            // walk off the top.
                            let max = state.fullscreen_scrollback.max_scroll_offset(panel_height);
                            state.scroll_offset = state.scroll_offset.min(max);
                        } else {
                            state.vterm.set_scrollback(state.scroll_offset);
                        }
                        *dirty = true;
                        return Ok(InputOutcome::Continue);
                    }
                    KeyCode::PageDown => {
                        state.scroll_offset = state.scroll_offset.saturating_sub(panel_height);
                        if !history_active {
                            state.vterm.set_scrollback(state.scroll_offset);
                        }
                        *dirty = true;
                        return Ok(InputOutcome::Continue);
                    }
                    KeyCode::Home => {
                        // Scroll to top of available history.
                        if history_active {
                            state.scroll_offset =
                                state.fullscreen_scrollback.max_scroll_offset(panel_height);
                        } else {
                            state.scroll_offset = usize::MAX;
                            state.vterm.set_scrollback(state.scroll_offset);
                        }
                        *dirty = true;
                        return Ok(InputOutcome::Continue);
                    }
                    KeyCode::End => {
                        state.snap_to_live();
                        *dirty = true;
                        return Ok(InputOutcome::Continue);
                    }
                    _ => {}
                }
            }
            // When log is focused, arrow keys scroll the log
            if state.log_focused {
                match key.code {
                    KeyCode::Up => {
                        state.log_scroll_up();
                        *dirty = true;
                        return Ok(InputOutcome::Continue);
                    }
                    KeyCode::Down => {
                        state.log_scroll_down();
                        *dirty = true;
                        return Ok(InputOutcome::Continue);
                    }
                    KeyCode::Esc => {
                        state.log_focused = false;
                        *dirty = true;
                        return Ok(InputOutcome::Continue);
                    }
                    _ => {}
                }
            }
            // Everything else → convert to bytes and send to PTY
            if let Some(bytes) = key_to_bytes(key.code, key.modifiers) {
                // Snap back to live view when sending input — covers both
                // line-oriented scrollback and fullscreen history modes.
                state.snap_to_live();
                let _ = pty_tx.send(PtyInput::Bytes(bytes));
            }
        }
        Event::Mouse(mouse) => {
            handle_mouse_event(state, pty_tx, mouse, dirty);
        }
        Event::Resize(cols, rows) => {
            state.vterm_cols = cols;
            let vterm_rows = rows.saturating_sub(MINIMAL_CHROME_ROWS).max(4);
            resize_exec_surface(state, pty_tx, vterm_rows);
        }
        Event::FocusGained | Event::FocusLost => {
            let focused = matches!(ev, Event::FocusGained);
            dbg_log(&format!(
                "host focus event: focused={focused} child_1004={}",
                state.focus_reporting_mode
            ));
            state.host_focused = focused;
            // Relay host focus transitions, but only while the child has
            // ?1004 reporting on — a tool that never asked would see stray
            // `CSI I`/`CSI O` bytes as keyboard input.
            if state.focus_reporting_mode {
                let _ = pty_tx.send(PtyInput::Bytes(focus_report_bytes(focused).to_vec()));
            }
            return Ok(InputOutcome::Continue);
        }
        _ => {}
    }
    *dirty = true;
    Ok(InputOutcome::Continue)
}

fn dismiss_permission_dialog(state: &mut ExecState, action: PermissionReviewAction) {
    if let Some(dialog) = state.permission_dialog.take() {
        dbg_log(&format!(
            "Dialog dismiss: action={}, pending={}",
            action.to_storage_value(),
            state.pending_permissions.len(),
        ));
        // Send the review decision back to the supervisor. The intercepted
        // syscall thread resumes after the digest status is updated.
        let _ = dialog.response_tx.send(action);
    }
    state.permission_dialog = if state.pending_permissions.is_empty() {
        None
    } else {
        Some(state.pending_permissions.remove(0))
    };
}

// ---------------------------------------------------------------------------
// Key-to-byte conversion for PTY passthrough
// ---------------------------------------------------------------------------

/// Build the xterm "modifyOtherKeys"-style modifier parameter for
/// CSI-encoded special keys: `1 + bit-OR(shift=1, alt=2, ctrl=4)`.
/// Returns `None` when no relevant modifiers are held — caller emits
/// the unmodified form.
fn xterm_modifier_param(modifiers: KeyModifiers) -> Option<u8> {
    let mut bits = 0u8;
    if modifiers.contains(KeyModifiers::SHIFT) {
        bits |= 1;
    }
    if modifiers.contains(KeyModifiers::ALT) {
        bits |= 2;
    }
    if modifiers.contains(KeyModifiers::CONTROL) {
        bits |= 4;
    }
    if bits == 0 {
        None
    } else {
        Some(1 + bits)
    }
}

/// CSI-encode a cursor / function-key keystroke with optional modifiers.
///
/// `final_char` is the trailing letter (A/B/C/D for arrows, H/F for
/// Home/End). When no modifiers are held, the short form `\x1b[<final>`
/// is emitted to match what bare `xterm` would send and what every
/// readline/Bash test expects. When modifiers are held, the
/// xterm-compatible long form `\x1b[1;<mod><final>` is emitted —
/// readline, fish, zsh, and the JS line-editors in claude / codex all
/// parse this and map Ctrl+Left → backward-word, etc.
fn csi_with_modifier(modifiers: KeyModifiers, final_char: u8) -> Vec<u8> {
    match xterm_modifier_param(modifiers) {
        None => vec![0x1b, b'[', final_char],
        Some(m) => format!("\x1b[1;{m}{}", final_char as char).into_bytes(),
    }
}

/// CSI-encode a `~`-terminated key (PageUp/Down, Delete, Insert) with
/// optional modifiers. Same convention: `\x1b[<n>~` bare, `\x1b[<n>;<mod>~`
/// when modified.
fn csi_tilde_with_modifier(modifiers: KeyModifiers, n: u8) -> Vec<u8> {
    match xterm_modifier_param(modifiers) {
        None => format!("\x1b[{n}~").into_bytes(),
        Some(m) => format!("\x1b[{n};{m}~").into_bytes(),
    }
}

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
        KeyCode::Enter => {
            // Bare Enter submits (CR, 0x0d). Any held modifier means the user
            // wants to insert a literal newline rather than submit — emit the
            // "meta-Enter" sequence (ESC + CR) that Claude Code, Codex, and
            // readline-based line editors all map to newline-insert. This is
            // protocol-agnostic: it produces a newline whether or not the
            // inner tool negotiated the kitty keyboard protocol on its PTY.
            // The modifier must reach us first; legacy host terminals collapse
            // Ctrl/Shift+Enter to a bare CR, which is why `run_exec_tui` pushes
            // DISAMBIGUATE_ESCAPE_CODES. Alt+Enter is reported even on legacy
            // terminals (ESC-prefix), so it works regardless.
            if modifiers.intersects(KeyModifiers::ALT | KeyModifiers::CONTROL | KeyModifiers::SHIFT)
            {
                Some(vec![0x1b, b'\r'])
            } else {
                Some(vec![b'\r'])
            }
        }
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::BackTab => Some(b"\x1b[Z".to_vec()),
        KeyCode::Backspace => Some(vec![0x7f]),
        KeyCode::Esc => Some(vec![0x1b]),
        KeyCode::Up => Some(csi_with_modifier(modifiers, b'A')),
        KeyCode::Down => Some(csi_with_modifier(modifiers, b'B')),
        KeyCode::Right => Some(csi_with_modifier(modifiers, b'C')),
        KeyCode::Left => Some(csi_with_modifier(modifiers, b'D')),
        KeyCode::Home => Some(csi_with_modifier(modifiers, b'H')),
        KeyCode::End => Some(csi_with_modifier(modifiers, b'F')),
        KeyCode::PageUp => Some(csi_tilde_with_modifier(modifiers, 5)),
        KeyCode::PageDown => Some(csi_tilde_with_modifier(modifiers, 6)),
        KeyCode::Delete => Some(csi_tilde_with_modifier(modifiers, 3)),
        KeyCode::Insert => Some(csi_tilde_with_modifier(modifiers, 2)),
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
        let wheel_event = is_wheel_event(mouse.kind);
        if wheel_event
            && should_send_wheel_as_arrow_keys(state)
            && send_wheel_as_arrow_keys(state, pty_tx, mouse.kind, dirty)
        {
            return;
        }
        if wheel_event && should_use_local_scrollback_for_wheel(state) {
            scroll_local_scrollback(state, mouse.kind, dirty);
            return;
        }
        if mode != vt100::MouseProtocolMode::None {
            let encoding = state.vterm.screen().mouse_protocol_encoding();
            if let Some(bytes) = encode_mouse_for_pty(mouse, term_y_start, encoding, mode) {
                if state.scroll_offset > 0 {
                    state.snap_to_live();
                    *dirty = true;
                }
                let _ = pty_tx.send(PtyInput::Bytes(bytes));
            }
            return;
        }
        // Inner tool doesn't want mouse — provide local scrollback so the
        // wheel still does something useful (the same scrollback that
        // Shift+PgUp/PgDn drives).
        scroll_local_scrollback(state, mouse.kind, dirty);
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

fn is_wheel_event(kind: MouseEventKind) -> bool {
    matches!(
        kind,
        MouseEventKind::ScrollUp
            | MouseEventKind::ScrollDown
            | MouseEventKind::ScrollLeft
            | MouseEventKind::ScrollRight
    )
}

fn should_use_local_scrollback_for_wheel(_state: &ExecState) -> bool {
    // Tools that enabled mouse reporting receive the raw mouse event
    // via encode_mouse_for_pty further down. Tools that didn't fall
    // through to grith's local vterm scrollback as the final default.
    // No tool currently needs an early opt-in here.
    false
}

fn should_send_wheel_as_arrow_keys(state: &ExecState) -> bool {
    // Translate the wheel to arrow keys ONLY when ALL hold:
    //  1. the tool enabled alternate-scroll mode (DECSET 1007), AND
    //  2. it is NOT raw-mouse-reporting right now — otherwise the raw-mouse
    //     branch in handle_mouse_event must own the wheel, and this branch
    //     (checked first) would wrongly preempt it. The original code dropped
    //     this check despite the comment promising it, so a tool with BOTH
    //     1007 and mouse reporting got arrow keys instead of the mouse event
    //     it asked for, and the wheel "scrolled prompt history" intermittently
    //     as the tool toggled modes between UI states.
    //  3. the tool is not one that handles its own scrolling / rejects
    //     arrow-wheel. Codex consumes wheel natively via raw mouse; Claude
    //     Code errors with "Scroll wheel is sending arrow keys" and maps Up/
    //     Down to prompt history — arrow-wheel is never correct for either, so
    //     they fall through to the raw-mouse branch (mouse on) or grith's own
    //     local scrollback (mouse off).
    state.alternate_scroll_mode
        && !rejects_wheel_as_arrow_keys(state)
        && state.vterm.screen().mouse_protocol_mode() == vt100::MouseProtocolMode::None
}

fn is_codex_tool(state: &ExecState) -> bool {
    state.profile_name == "codex" || state.tool_name == "codex"
}

fn is_claude_code_tool(state: &ExecState) -> bool {
    state.profile_name == "claude-code"
        || state.tool_name == "claude"
        || state.tool_name == "claude-code"
}

/// Tools whose input editor misuses arrow keys for the wheel (prompt-history
/// navigation, or an outright "scroll wheel is sending arrow keys" rejection).
/// These never want wheel-as-arrows regardless of alternate-scroll mode.
fn rejects_wheel_as_arrow_keys(state: &ExecState) -> bool {
    is_codex_tool(state) || is_claude_code_tool(state)
}

fn send_wheel_as_arrow_keys(
    state: &mut ExecState,
    pty_tx: &mpsc::Sender<PtyInput>,
    kind: MouseEventKind,
    dirty: &mut bool,
) -> bool {
    let bytes = match kind {
        MouseEventKind::ScrollUp => b"\x1b[A".to_vec(),
        MouseEventKind::ScrollDown => b"\x1b[B".to_vec(),
        MouseEventKind::ScrollLeft => b"\x1b[D".to_vec(),
        MouseEventKind::ScrollRight => b"\x1b[C".to_vec(),
        _ => return false,
    };

    if state.scroll_offset > 0 {
        state.snap_to_live();
        *dirty = true;
    }

    let _ = pty_tx.send(PtyInput::Bytes(bytes));
    true
}

/// Build a viewport-sized `vt100::Parser` populated with the given
/// scrollback lines. The parser is rendered through the existing
/// `render_vterm` widget, so the visible result is consistent with
/// the live view (just plain-text — colour preservation is a tracked
/// follow-up that requires per-cell attr emission per line).
///
/// Important: `\r\n` is emitted only BETWEEN lines, never after the
/// last one. If we emitted a trailing newline, the cursor would
/// advance past the last row, scrolling the first line off the top
/// into the parser's scrollback (which we don't render). The result
/// would be a mostly-blank viewport with the meaningful first line
/// invisible.
fn build_history_viewport(rows: u16, cols: u16, lines: &[&str]) -> vt100::Parser {
    let mut parser = vt100::Parser::new(rows, cols, 0);
    let total = lines.len();
    for (idx, line) in lines.iter().enumerate() {
        parser.process(line.as_bytes());
        if idx + 1 < total {
            parser.process(b"\r\n");
        }
    }
    parser
}

fn scroll_local_scrollback(state: &mut ExecState, kind: MouseEventKind, dirty: &mut bool) {
    // Single unified scroll_offset driven against the live vterm or the
    // fullscreen-mirror, depending on which has actual content. The
    // fullscreen mirror accumulates frame text into its own primary-grid
    // scrollback; the live vterm's built-in scrollback handles
    // line-oriented tools. Either way the user-visible behaviour is the
    // same: wheel up = older content, wheel down = newer.
    let history_active = state.use_fullscreen_history();
    match kind {
        MouseEventKind::ScrollUp => {
            state.scroll_offset = state.scroll_offset.saturating_add(LOCAL_SCROLL_STEP);
            if history_active {
                let viewport_rows = state.vterm_rows as usize;
                let max = state.fullscreen_scrollback.max_scroll_offset(viewport_rows);
                state.scroll_offset = state.scroll_offset.min(max);
            } else {
                state.vterm.set_scrollback(state.scroll_offset);
            }
            *dirty = true;
        }
        MouseEventKind::ScrollDown => {
            state.scroll_offset = state.scroll_offset.saturating_sub(LOCAL_SCROLL_STEP);
            if !history_active {
                state.vterm.set_scrollback(state.scroll_offset);
            }
            *dirty = true;
        }
        _ => {}
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

fn should_display_intercept_log(action: &str, call_type: &str, score: f64) -> bool {
    if action != "allow" {
        return true;
    }
    if score > 0.5 {
        return true;
    }
    !is_runtime_scratch_call(call_type)
}

fn is_runtime_scratch_call(call_type: &str) -> bool {
    let Some(pathish) = call_type
        .strip_prefix("FileWrite(")
        .or_else(|| call_type.strip_prefix("FileAppend("))
        .or_else(|| call_type.strip_prefix("FileDelete("))
        .or_else(|| call_type.strip_prefix("FileRename("))
    else {
        return false;
    };

    pathish.starts_with("/var/tmp/etilqs_")
        || pathish.starts_with("/tmp/etilqs_")
        || pathish.starts_with("/tmp/sqlite_")
        || pathish.starts_with("/tmp/node-compile-cache/")
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
        if dialog.show_help {
            widgets::permission::render_permission_help_panel(
                frame,
                overlay_area,
                &dialog.request,
                dialog.request.score > 8.0,
            );
        } else if let Some(scope) = &dialog.scope {
            widgets::permission::render_scope_permission_panel(
                frame,
                overlay_area,
                &dialog.request,
                scope,
            );
        } else {
            widgets::permission::render_permission_panel(
                frame,
                overlay_area,
                &dialog.request,
                dialog.request.score > 8.0,
                dialog.show_inspect,
            );
        }
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
        Paragraph::new(left).style(Style::new().bg(BG_PANEL)).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::new().fg(BORDER))
                .style(Style::new().bg(BG_PANEL)),
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
        frame.render_widget(
            Paragraph::new(right).style(Style::new().bg(BG_PANEL)),
            right_area,
        );
    }
}

// ---------------------------------------------------------------------------
// Terminal panel — vt100 virtual terminal (interactive, scrollable)
// ---------------------------------------------------------------------------

fn render_terminal(frame: &mut Frame, area: Rect, state: &ExecState) {
    frame.render_widget(Block::default().style(Style::new().bg(BG)), area);

    // Render path resolution:
    //   scroll_offset > 0 + repaint_mode → build a synthetic parser
    //     populated with the visible scrollback window's lines, render
    //     from that. This bypasses vt100's one-viewport scrollback
    //     limitation and gives truly unbounded scroll-back through the
    //     accumulated frame history.
    //   otherwise                        → live vterm.
    let history_active = state.use_fullscreen_history();
    let synthetic = if state.scroll_offset > 0 && history_active && area.height > 0 {
        Some(build_history_viewport(
            area.height,
            area.width.max(1),
            &state
                .fullscreen_scrollback
                .visible_window(area.height as usize, state.scroll_offset),
        ))
    } else {
        None
    };
    let screen = synthetic
        .as_ref()
        .map(|p| p.screen())
        .unwrap_or_else(|| state.vterm.screen());
    let is_live = state.scroll_offset == 0;
    // Cursor is only suppressed when we're rendering a synthetic
    // (scrolled-back) screen — the synthetic parser's cursor would
    // land at the end of the last scrollback line, which is not where
    // the user is interacting. On the live screen the cursor must
    // always be visible regardless of whether fullscreen-history mode
    // is otherwise eligible for scrollback navigation.
    let show_cursor = synthetic.is_none() && is_live;
    widgets::terminal::render_vterm(frame, area, screen, show_cursor, is_live);

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

    // Scrollback indicator overlay — single unified label since the
    // underlying scroll model is now the same (driven by scroll_offset
    // against either the live vterm or the fullscreen mirror).
    let indicator_label = if state.scroll_offset > 0 {
        Some(format!(" SCROLLBACK +{} ", state.scroll_offset))
    } else {
        None
    };
    if let Some(label) = indicator_label {
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

/// Status-bar key hints shown when mouse capture is on (the default). Kept as a
/// const so tests can assert the select-text toggle stays advertised.
const EXEC_FOOTER_KEYS: &[(&str, &str)] = &[
    ("shift+pgup", "scroll"),
    ("ctrl+t", "select text"),
    ("ctrl+l", "log"),
    ("a/d", "when prompted"),
];

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
    } else if !state.mouse_capture {
        // Mouse capture is off so the user can drag-select/copy. Make it
        // obvious that the scroll wheel is paused and how to restore it.
        spans.push(Span::styled(
            "SELECT MODE — drag to copy · wheel-scroll paused · ",
            Style::new().fg(AMBER),
        ));
        spans.push(Span::styled("[ctrl+t]", Style::new().fg(TEXT_MID)));
        spans.push(Span::styled(" resume scroll", Style::new().fg(TEXT_DIM)));
    } else {
        for (i, (key, desc)) in EXEC_FOOTER_KEYS.iter().enumerate() {
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
    fn mouse_capture_defaults_on() {
        // Default-on preserves the scroll fix (wheel drives grith scrollback).
        let state = ExecState::new("claude".into(), "claude-code".into(), 1, 24, 80, 0);
        assert!(state.mouse_capture);
    }

    #[test]
    fn footer_advertises_select_text_toggle() {
        // The Ctrl+T select-text affordance must stay discoverable in the footer.
        assert!(
            EXEC_FOOTER_KEYS
                .iter()
                .any(|(k, d)| *k == "ctrl+t" && d.contains("select")),
            "footer should advertise the ctrl+t select-text toggle"
        );
    }

    #[test]
    fn render_select_mode_footer_no_panic() {
        // Renders the SELECT MODE branch (mouse capture off) without panicking.
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = ExecState::new("claude".into(), "claude-code".into(), 1, 24, 80, 0);
        state.mouse_capture = false;
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
    fn key_to_bytes_modified_enter_inserts_newline() {
        // Bare Enter still submits with a carriage return.
        assert_eq!(
            key_to_bytes(KeyCode::Enter, KeyModifiers::NONE),
            Some(vec![b'\r'])
        );
        // Alt+Enter, Ctrl+Enter, Shift+Enter each insert a newline via the
        // meta-Enter sequence (ESC + CR) rather than submitting.
        for m in [
            KeyModifiers::ALT,
            KeyModifiers::CONTROL,
            KeyModifiers::SHIFT,
        ] {
            assert_eq!(
                key_to_bytes(KeyCode::Enter, m),
                Some(vec![0x1b, b'\r']),
                "modifier {m:?} should produce meta-Enter newline",
            );
        }
        // Combined modifiers still resolve to the single newline form.
        assert_eq!(
            key_to_bytes(KeyCode::Enter, KeyModifiers::CONTROL | KeyModifiers::SHIFT),
            Some(vec![0x1b, b'\r'])
        );
    }

    #[test]
    fn key_to_bytes_emits_modified_arrows() {
        // Ctrl+Left = word-back. Standard xterm sequence \x1b[1;5D.
        assert_eq!(
            key_to_bytes(KeyCode::Left, KeyModifiers::CONTROL),
            Some(b"\x1b[1;5D".to_vec()),
        );
        assert_eq!(
            key_to_bytes(KeyCode::Right, KeyModifiers::CONTROL),
            Some(b"\x1b[1;5C".to_vec()),
        );
        // Alt+Left = word-back in some shells.
        assert_eq!(
            key_to_bytes(KeyCode::Left, KeyModifiers::ALT),
            Some(b"\x1b[1;3D".to_vec()),
        );
        // Shift+Up — claude / codex / less treat as scroll-back.
        assert_eq!(
            key_to_bytes(KeyCode::Up, KeyModifiers::SHIFT),
            Some(b"\x1b[1;2A".to_vec()),
        );
        // Combo: Ctrl+Shift+Right = 1 + 4 + 1 = 6.
        assert_eq!(
            key_to_bytes(KeyCode::Right, KeyModifiers::CONTROL | KeyModifiers::SHIFT),
            Some(b"\x1b[1;6C".to_vec()),
        );
        // Plain Left stays in the short form so it matches what bare
        // xterm sends and what readline tests expect.
        assert_eq!(
            key_to_bytes(KeyCode::Left, KeyModifiers::NONE),
            Some(b"\x1b[D".to_vec()),
        );
    }

    #[test]
    fn key_to_bytes_emits_modified_home_end_delete() {
        assert_eq!(
            key_to_bytes(KeyCode::Home, KeyModifiers::CONTROL),
            Some(b"\x1b[1;5H".to_vec()),
        );
        assert_eq!(
            key_to_bytes(KeyCode::End, KeyModifiers::SHIFT),
            Some(b"\x1b[1;2F".to_vec()),
        );
        assert_eq!(
            key_to_bytes(KeyCode::Delete, KeyModifiers::CONTROL),
            Some(b"\x1b[3;5~".to_vec()),
        );
        assert_eq!(
            key_to_bytes(KeyCode::PageUp, KeyModifiers::SHIFT),
            Some(b"\x1b[5;2~".to_vec()),
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
    fn alternate_scroll_mode_toggles_on_complete_sequence() {
        let mut state = ExecState::new("test".into(), "default".into(), 1, 24, 80, 0);
        state.observe_pty_modes(b"\x1b[?1007h");
        assert!(state.alternate_scroll_mode);

        state.observe_pty_modes(b"\x1b[?1007l");
        assert!(!state.alternate_scroll_mode);
    }

    #[test]
    fn wheel_arrows_suppressed_for_claude_code() {
        // Claude Code rejects/misuses arrow-wheel (maps Up/Down to prompt
        // history). Even with alternate-scroll mode on, never translate.
        let mut state = ExecState::new("claude".into(), "claude-code".into(), 1, 24, 80, 0);
        state.observe_pty_modes(b"\x1b[?1007h");
        assert!(state.alternate_scroll_mode);
        assert!(!should_send_wheel_as_arrow_keys(&state));
    }

    #[test]
    fn wheel_arrows_suppressed_when_mouse_reporting_active() {
        // A tool with BOTH 1007 and raw mouse reporting must get the raw mouse
        // event (handled by the later branch), not arrow keys — the arrow path
        // must not preempt it. This is the regression that produced the
        // content/prompt-history mixture.
        let mut state = ExecState::new("test".into(), "default".into(), 1, 24, 80, 0);
        state.observe_pty_modes(b"\x1b[?1007h");
        state.vterm.process(b"\x1b[?1000h"); // enable mouse reporting
        assert_ne!(
            state.vterm.screen().mouse_protocol_mode(),
            vt100::MouseProtocolMode::None
        );
        assert!(state.alternate_scroll_mode);
        assert!(!should_send_wheel_as_arrow_keys(&state));
    }

    #[test]
    fn wheel_arrows_kept_for_generic_alt_scroll_without_mouse() {
        // The legitimate case is preserved: a non-special tool that enabled
        // alternate-scroll and is NOT mouse-reporting still gets wheel→arrows.
        let mut state = ExecState::new("test".into(), "default".into(), 1, 24, 80, 0);
        state.observe_pty_modes(b"\x1b[?1007h");
        assert_eq!(
            state.vterm.screen().mouse_protocol_mode(),
            vt100::MouseProtocolMode::None
        );
        assert!(should_send_wheel_as_arrow_keys(&state));
    }

    #[test]
    fn alternate_scroll_mode_detects_split_sequences() {
        let mut state = ExecState::new("test".into(), "default".into(), 1, 24, 80, 0);
        state.observe_pty_modes(b"\x1b[?10");
        assert!(!state.alternate_scroll_mode);

        state.observe_pty_modes(b"07h");
        assert!(state.alternate_scroll_mode);

        state.observe_pty_modes(b"\x1b[?100");
        state.observe_pty_modes(b"7l");
        assert!(!state.alternate_scroll_mode);
    }

    #[test]
    fn focus_reporting_mode_toggles_on_1004_sequences() {
        let mut state = ExecState::new("test".into(), "default".into(), 1, 24, 80, 0);
        assert!(!state.focus_reporting_mode);

        state.observe_pty_modes(b"\x1b[?1004h");
        assert!(state.focus_reporting_mode);

        state.observe_pty_modes(b"\x1b[?1004l");
        assert!(!state.focus_reporting_mode);

        // Split across chunks, like Claude Code's startup burst.
        state.observe_pty_modes(b"\x1b[?10");
        state.observe_pty_modes(b"04h");
        assert!(state.focus_reporting_mode);
    }

    #[test]
    fn focus_reporting_and_alternate_scroll_track_independently() {
        let mut state = ExecState::new("test".into(), "default".into(), 1, 24, 80, 0);
        state.observe_pty_modes(b"\x1b[?1004h\x1b[?1007h");
        assert!(state.focus_reporting_mode);
        assert!(state.alternate_scroll_mode);

        state.observe_pty_modes(b"\x1b[?1007l");
        assert!(state.focus_reporting_mode);
        assert!(!state.alternate_scroll_mode);
    }

    #[test]
    fn focus_report_bytes_match_terminal_encoding() {
        assert_eq!(focus_report_bytes(true), b"\x1b[I");
        assert_eq!(focus_report_bytes(false), b"\x1b[O");
    }

    #[test]
    fn codex_mouse_wheel_forwards_sgr_event_not_arrow_keys() {
        // Codex enables raw mouse reporting (mode 1006) and handles
        // wheel events natively in its TUI. grith must forward the
        // raw SGR-encoded mouse event — NOT translate to arrow keys
        // (which codex's input editor would consume as prompt-history
        // navigation) and NOT use grith's local scrollback (alt-screen
        // means there's nothing pre-alt to show). This matches how
        // codex behaves when run without grith in the loop.
        let mut state = ExecState::new("codex".into(), "codex".into(), 1, 24, 80, 0);
        state.alternate_scroll_mode = true;
        state.vterm.process(b"\x1b[?1000h\x1b[?1006h");
        let (pty_tx, pty_rx) = mpsc::channel();
        let mut dirty = false;
        let event = MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 5,
            row: TERMINAL_PANEL_Y + 2,
            modifiers: KeyModifiers::NONE,
        };

        handle_mouse_event(&mut state, &pty_tx, event, &mut dirty);

        // No local-scrollback movement, no arrow-key translation.
        assert_eq!(state.scroll_offset, 0);
        let bytes = pty_rx
            .try_recv()
            .ok()
            .and_then(|msg| match msg {
                PtyInput::Bytes(b) => Some(b),
                PtyInput::Resize { .. } => None,
            })
            .expect("codex should receive an SGR-encoded mouse event");
        // SGR mouse encoding starts with ESC [ < — assert that's what
        // codex sees (rather than e.g. ESC [ A for arrow-up).
        assert!(
            bytes.starts_with(b"\x1b[<"),
            "expected SGR-encoded mouse event, got {bytes:?}"
        );
    }

    #[test]
    fn non_codex_mouse_wheel_still_forwards_when_mouse_mode_enabled() {
        let mut state = ExecState::new("vim".into(), "default".into(), 1, 24, 80, 0);
        state.vterm.process(b"\x1b[?1000h\x1b[?1006h");
        let (pty_tx, pty_rx) = mpsc::channel();
        let mut dirty = false;
        let event = MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 5,
            row: TERMINAL_PANEL_Y + 2,
            modifiers: KeyModifiers::NONE,
        };

        handle_mouse_event(&mut state, &pty_tx, event, &mut dirty);

        assert_eq!(state.scroll_offset, 0);
        assert!(
            pty_rx.try_recv().is_ok(),
            "non-Codex tools that request mouse mode should receive wheel events"
        );
    }

    #[test]
    fn intercept_log_hides_low_score_runtime_scratch_allows() {
        assert!(!should_display_intercept_log(
            "allow",
            "FileWrite(/var/tmp/etilqs_123123123123123)",
            0.5,
        ));
        assert!(!should_display_intercept_log(
            "allow",
            "FileRename(/tmp/node-compile-cache/v22/foo.tmp -> /tmp/node-compile-cache/v22/foo)",
            0.3,
        ));
        assert!(should_display_intercept_log(
            "queue",
            "FileWrite(/var/tmp/etilqs_123123123123123)",
            3.5,
        ));
        assert!(should_display_intercept_log(
            "allow",
            "FileWrite(/home/u/project/src/main.rs)",
            0.5,
        ));
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
                decision_reason: String::new(),
                context: String::new(),
                severity: "medium".into(),
                item_number: 1,
                total_items: 1,
                scope_enabled: true,
            },
            response_tx: tx,
            show_inspect: false,
            scope: None,
            show_help: false,
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

    fn dialog_with_id(id: uuid::Uuid) -> PermissionDialog {
        let (tx, _rx) = std::sync::mpsc::sync_channel(1);
        PermissionDialog {
            request: super::super::state::PermissionRequest {
                id,
                tool: "FileWrite".into(),
                call_type: "FileWrite".into(),
                args: "/tmp/test".into(),
                score: 5.0,
                filters: vec![],
                reasons: vec![],
                decision_reason: String::new(),
                context: String::new(),
                severity: "medium".into(),
                item_number: 1,
                total_items: 1,
                scope_enabled: true,
            },
            response_tx: tx,
            show_inspect: false,
            scope: None,
            show_help: false,
        }
    }

    /// Cancelling the ACTIVE dialog promotes the next queued prompt; the
    /// stale one never lingers on screen soaking up an answer that would go
    /// nowhere.
    #[test]
    fn cancel_active_dialog_promotes_next_pending() {
        let mut state = ExecState::new("claude".into(), "claude-code".into(), 1234, 30, 80, 0);
        let stale = uuid::Uuid::new_v4();
        let queued = uuid::Uuid::new_v4();
        state.permission_dialog = Some(dialog_with_id(stale));
        state.pending_permissions.push(dialog_with_id(queued));

        cancel_permission(&mut state, stale);

        assert_eq!(
            state.permission_dialog.as_ref().map(|d| d.request.id),
            Some(queued),
            "the queued prompt must surface when the stale one is cancelled"
        );
        assert!(state.pending_permissions.is_empty());
    }

    /// Cancelling a QUEUED dialog removes it in place; the active dialog is
    /// untouched. Cancelling an unknown id is a no-op.
    #[test]
    fn cancel_queued_dialog_removes_in_place() {
        let mut state = ExecState::new("claude".into(), "claude-code".into(), 1234, 30, 80, 0);
        let active = uuid::Uuid::new_v4();
        let stale = uuid::Uuid::new_v4();
        state.permission_dialog = Some(dialog_with_id(active));
        state.pending_permissions.push(dialog_with_id(stale));

        cancel_permission(&mut state, stale);
        assert_eq!(
            state.permission_dialog.as_ref().map(|d| d.request.id),
            Some(active)
        );
        assert!(state.pending_permissions.is_empty());

        // Unknown id: nothing changes.
        cancel_permission(&mut state, uuid::Uuid::new_v4());
        assert_eq!(
            state.permission_dialog.as_ref().map(|d| d.request.id),
            Some(active)
        );
    }

    /// Cancelling the last dialog leaves no dialog showing.
    #[test]
    fn cancel_last_dialog_clears_overlay() {
        let mut state = ExecState::new("claude".into(), "claude-code".into(), 1234, 30, 80, 0);
        let stale = uuid::Uuid::new_v4();
        state.permission_dialog = Some(dialog_with_id(stale));

        cancel_permission(&mut state, stale);
        assert!(state.permission_dialog.is_none());
        assert!(state.pending_permissions.is_empty());
    }

    // -----------------------------------------------------------------------
    // Fullscreen-repaint scrollback integration tests (Phase F).
    // -----------------------------------------------------------------------

    /// Drive `state.fullscreen_scrollback` end-to-end through two overlapping
    /// Codex-style repaints. Scrolling back must reveal the row displaced from
    /// the first screen without duplicating the rows present in both screens.
    #[test]
    fn fullscreen_history_reconstructs_overlapping_codex_repaints() {
        let total_rows = 24u16;
        let mut state = ExecState::new("codex".into(), "codex".into(), 7777, total_rows, 80, 0);
        state.screen_populated = true;

        let emit = |s: &mut ExecState, payload: &[u8]| {
            s.fullscreen_scrollback.observe_bytes(payload);
            s.vterm.process(payload);
            s.fullscreen_scrollback
                .capture_if_boundary_reached(s.vterm.screen(), s.last_pty_activity);
        };

        // Frame 1 contains one row that will leave the viewport plus three
        // stable transcript rows.
        emit(
            &mut state,
            b"\x1b[?1049h\x1b[?2026h\x1b[2J\x1b[H\x1b[1;24r\
              OLDEST_ROW\r\nSHARED_ALPHA\r\nSHARED_BETA\r\nSHARED_GAMMA\x1b[?2026l",
        );
        assert!(state.fullscreen_scrollback.repaint_mode());
        assert_eq!(state.fullscreen_scrollback.frames_pushed(), 1);

        // Frame 2 moves the shared rows upward and adds one new bottom row.
        emit(
            &mut state,
            b"\x1b[?2026h\x1b[2J\x1b[H\
              SHARED_ALPHA\r\nSHARED_BETA\r\nSHARED_GAMMA\r\nNEWEST_ROW\x1b[?2026l",
        );
        assert_eq!(state.fullscreen_scrollback.frames_pushed(), 2);

        // Live rendering is still the untouched vt100 screen.
        let live = render_terminal_panel(&state);
        assert!(
            live.contains("NEWEST_ROW"),
            "live screen should show latest frame, got:\n{live}"
        );
        assert!(!live.contains("OLDEST_ROW"));

        // Scrolling to the oldest reconstructed row surfaces OLDEST_ROW.
        let viewport_rows = state.vterm_rows as usize;
        state.scroll_offset = state.fullscreen_scrollback.max_scroll_offset(viewport_rows);
        let backed = render_terminal_panel(&state);
        assert!(
            backed.contains("OLDEST_ROW"),
            "scrolling to top should reveal first frame's content, got:\n{backed}"
        );
        assert_eq!(
            backed.matches("SHARED_ALPHA").count(),
            1,
            "overlapping transcript rows must not repeat in scrollback:\n{backed}"
        );
    }

    /// Repaint heuristics fire without alt-screen enter — primary-screen
    /// fullscreen redrawers (Codex with `tui.alternate_screen = "never"`)
    /// still get a capture once the screen has gone idle past the
    /// REPAINT_IDLE_WINDOW.
    #[test]
    fn primary_screen_repaint_captures_via_idle_fallback() {
        let total_rows = 24u16;
        let mut state = ExecState::new("codex".into(), "codex".into(), 7777, total_rows, 80, 0);
        state.screen_populated = true;

        // Pure primary-screen fullscreen repaint sequence: no ?1049h.
        let payload = b"\x1b[2J\x1b[H\x1b[1;24rPRIMARY_FRAME";
        state.fullscreen_scrollback.observe_bytes(payload);
        state.vterm.process(payload);
        assert!(state.fullscreen_scrollback.repaint_mode());

        // Simulate idle: shift last_pty_activity well into the past so the
        // capture decision's idle-window precondition is satisfied.
        state.last_pty_activity = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_millis(500))
            .unwrap_or_else(std::time::Instant::now);
        state
            .fullscreen_scrollback
            .capture_if_boundary_reached(state.vterm.screen(), state.last_pty_activity);
        assert_eq!(
            state.fullscreen_scrollback.frames_pushed(),
            1,
            "primary-screen repaint with idle window should produce a captured frame"
        );
    }

    /// Captured frame content is stored as lines in the scrollback. After
    /// capture, the accumulated lines contain the frame's text tokens.
    #[test]
    fn captured_frame_text_stored_as_lines() {
        let total_rows = 24u16;
        let mut state = ExecState::new("codex".into(), "codex".into(), 7777, total_rows, 80, 0);
        state.screen_populated = true;

        let payload = b"\x1b[?2026h\x1b[2J\x1b[H\x1b[1;24rrender parity payload\x1b[?2026l";
        state.fullscreen_scrollback.observe_bytes(payload);
        state.vterm.process(payload);
        state
            .fullscreen_scrollback
            .capture_if_boundary_reached(state.vterm.screen(), state.last_pty_activity);
        assert_eq!(state.fullscreen_scrollback.frames_pushed(), 1);

        let live_text = state.vterm.screen().contents();
        // visible_window returning all accumulated lines should include
        // the same tokens as the live screen text.
        let stored = state
            .fullscreen_scrollback
            .visible_window(usize::MAX, 0)
            .join("\n");
        for token in live_text.split_whitespace() {
            if !token.is_empty() {
                assert!(
                    stored.contains(token),
                    "stored scrollback missing token {token:?}; stored=\n{stored}",
                );
            }
        }
    }

    /// Snap-to-live resets the unified scroll offset.
    #[test]
    fn snap_to_live_resets_offsets() {
        let mut state = ExecState::new("codex".into(), "codex".into(), 1234, 24, 80, 0);
        state.scroll_offset = 12;
        state.vterm.set_scrollback(12);

        state.snap_to_live();
        assert_eq!(state.scroll_offset, 0);
    }

    /// `use_fullscreen_history` flips on only when both repaint_mode is
    /// active and at least one snapshot exists. A repaint-active session
    /// with an empty ring still falls back to the vt100 scrollback path.
    #[test]
    fn use_fullscreen_history_requires_repaint_mode_and_snapshots() {
        let mut state = ExecState::new("codex".into(), "codex".into(), 1234, 24, 80, 0);
        assert!(!state.use_fullscreen_history());

        // Repaint signals alone: still false because no captures yet.
        state
            .fullscreen_scrollback
            .observe_bytes(b"\x1b[2J\x1b[H\x1b[1;24r");
        assert!(state.fullscreen_scrollback.repaint_mode());
        assert!(!state.use_fullscreen_history());

        // After capturing one frame, fullscreen-history mode becomes active.
        state
            .fullscreen_scrollback
            .observe_bytes(b"\x1b[?2026h\x1b[?2026l");
        state.vterm.process(b"some content");
        state
            .fullscreen_scrollback
            .capture_if_boundary_reached(state.vterm.screen(), state.last_pty_activity);
        assert!(state.use_fullscreen_history());
    }

    /// Claude Code's conversation is line-oriented and lives in vt100
    /// scrollback, so it must stay on the vt100 line-scrollback path even when
    /// it trips repaint_mode and has captured frames — otherwise the wheel
    /// scrolls captured repaints (banners/menus) instead of the real chat.
    #[test]
    fn claude_code_stays_on_line_scrollback_not_fullscreen_history() {
        let mut state = ExecState::new("claude".into(), "claude-code".into(), 1234, 24, 80, 0);
        // Drive it into the exact state that turns fullscreen-history ON for
        // codex: repaint_mode active + at least one captured frame.
        state
            .fullscreen_scrollback
            .observe_bytes(b"\x1b[2J\x1b[H\x1b[1;24r");
        state
            .fullscreen_scrollback
            .observe_bytes(b"\x1b[?2026h\x1b[?2026l");
        state.vterm.process(b"some content");
        state
            .fullscreen_scrollback
            .capture_if_boundary_reached(state.vterm.screen(), state.last_pty_activity);
        assert!(state.fullscreen_scrollback.repaint_mode());
        assert!(!state.fullscreen_scrollback.is_empty());
        // ...but Claude Code is excluded, so it uses vt100 line scrollback.
        assert!(!state.use_fullscreen_history());
    }

    /// Protect the actual Claude wheel/render path, not only the routing
    /// predicate: even after Claude trips repaint detection and captures a
    /// frame, wheel-up must reveal its native vt100 transcript.
    #[test]
    fn claude_code_wheel_still_renders_native_line_scrollback() {
        let mut state = ExecState::new("claude".into(), "claude-code".into(), 1234, 24, 80, 0);
        for i in 0..40 {
            state
                .vterm
                .process(format!("CLAUDE_TRANSCRIPT_{i:02}\r\n").as_bytes());
        }
        state.screen_populated = true;

        // Claude's input/status repaint can activate frame capture, but must
        // never switch this profile away from native line scrollback.
        state
            .fullscreen_scrollback
            .observe_bytes(b"\x1b[2J\x1b[H\x1b[1;24r\x1b[?2026h\x1b[?2026l");
        state
            .fullscreen_scrollback
            .capture_if_boundary_reached(state.vterm.screen(), state.last_pty_activity);
        assert!(!state.use_fullscreen_history());

        let mut dirty = false;
        scroll_local_scrollback(&mut state, MouseEventKind::ScrollUp, &mut dirty);
        let backed = render_terminal_panel(&state);
        assert!(dirty);
        assert!(
            backed.contains("CLAUDE_TRANSCRIPT_23"),
            "Claude wheel must render native vt100 history, got:\n{backed}"
        );
    }
}
