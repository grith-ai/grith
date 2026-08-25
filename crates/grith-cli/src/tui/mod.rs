// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Ratatui-based TUI for grith. One layout, one code path — identical
//! whether running the built-in agent (REPL) or wrapping an external tool.

pub mod events;
pub mod exec_tui;
pub mod fullscreen_scrollback;
pub mod input_thread;
pub(crate) mod osc52;
pub mod render;
pub mod state;
pub mod theme;
pub mod widgets;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use events::{AgentEvent, TuiEvent, TuiInput};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use state::{AppState, ModalState, OutputLine};
use std::io;
use std::time::Duration;

/// Redirect stderr to a log file so tracing output doesn't corrupt the TUI.
/// Returns the saved stderr fd to restore later.
#[cfg(unix)]
fn redirect_stderr_to_file() -> i32 {
    use std::os::unix::io::AsRawFd;
    unsafe {
        let saved = libc::dup(2);
        let log_dir = dirs::config_dir().unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
        let log_path = log_dir.join("grith").join("tui.log");
        // Ensure parent dir exists
        let _ = std::fs::create_dir_all(log_path.parent().unwrap_or(std::path::Path::new("/tmp")));
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            libc::dup2(file.as_raw_fd(), 2);
        }
        saved
    }
}

/// Restore stderr from a saved fd.
#[cfg(unix)]
fn restore_stderr(saved_fd: i32) {
    unsafe {
        libc::dup2(saved_fd, 2);
        libc::close(saved_fd);
    }
}

/// Run the TUI event loop on the current thread (blocking).
/// Enters the alternate screen and raw mode. Restores terminal on exit.
///
/// `agent_rx` receives events from the agent/supervisor loop.
/// `input_tx` (if provided) sends user input back to the main thread.
pub fn run_tui(
    mut state: AppState,
    agent_rx: std::sync::mpsc::Receiver<AgentEvent>,
    input_tx: Option<tokio::sync::mpsc::Sender<TuiInput>>,
) -> anyhow::Result<()> {
    // Redirect stderr to a file so tracing logs don't corrupt the TUI
    #[cfg(unix)]
    let saved_stderr = redirect_stderr_to_file();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let result = event_loop(&mut terminal, &mut state, &agent_rx, input_tx.as_ref());

    // Always restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    // Restore stderr
    #[cfg(unix)]
    restore_stderr(saved_stderr);

    result
}

/// Show the ratatui permission dialog over the current screen (no alternate screen).
/// Blocks until the user selects a review action.
/// Used by `TerminalQueueReviewer` for styled review prompts.
///
/// Does NOT use alternate screen — nested alt screens break with TUI tools
/// that already use alt screen (e.g. Claude Code). Instead, clears and draws
/// directly. After exit, the caller is responsible for triggering SIGWINCH
/// so the tool redraws.
pub fn run_review_dialog(
    req: &state::PermissionRequest,
) -> Option<grith_digest::PermissionReviewAction> {
    use crossterm::event::{self, Event, KeyCode};
    use grith_digest::PermissionReviewAction;

    #[cfg(unix)]
    let saved_stderr = redirect_stderr_to_file();

    if enable_raw_mode().is_err() {
        #[cfg(unix)]
        restore_stderr(saved_stderr);
        return None;
    }

    let stdout = io::stdout();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(_) => {
            let _ = disable_raw_mode();
            #[cfg(unix)]
            restore_stderr(saved_stderr);
            return None;
        }
    };
    let _ = terminal.clear();

    let is_deny = req.score > 8.0;
    let result;
    let mut show_inspect = false;
    let mut show_help = false;
    let mut scope_dialog: Option<widgets::permission::ScopeDialogState> = None;

    loop {
        let _ = terminal.draw(|frame| {
            frame.render_widget(
                ratatui::widgets::Block::default()
                    .style(ratatui::style::Style::new().bg(crate::tui::theme::BG)),
                frame.area(),
            );
            if show_help {
                crate::tui::widgets::permission::render_permission_help_dialog(frame, req, is_deny);
            } else if let Some(scope) = &scope_dialog {
                crate::tui::widgets::permission::render_scope_permission_dialog(frame, req, scope);
            } else {
                crate::tui::widgets::permission::render_permission_dialog(
                    frame,
                    req,
                    is_deny,
                    show_inspect,
                );
            }
        });

        if let Ok(true) = event::poll(Duration::from_millis(50)) {
            if let Ok(Event::Key(key)) = event::read() {
                // Help overlay: modal — only closing keys act, so a
                // decision can't be made blind while reading.
                if show_help {
                    if matches!(
                        key.code,
                        KeyCode::Char('h') | KeyCode::Char('H') | KeyCode::Char('q') | KeyCode::Esc
                    ) {
                        show_help = false;
                    }
                    continue;
                }
                // One key map, shared with the exec TUI host in `exec_tui.rs`
                // so the two cannot drift apart again.
                if let Some(scope) = scope_dialog.as_mut() {
                    match scope.handle_key(&key, req) {
                        widgets::permission::ScopeKeyOutcome::Cancel => scope_dialog = None,
                        widgets::permission::ScopeKeyOutcome::Applied(action) => {
                            result = Some(action);
                            break;
                        }
                        widgets::permission::ScopeKeyOutcome::Continue => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('a') | KeyCode::Char('A') if !is_deny => {
                        result = Some(PermissionReviewAction::Approve);
                        break;
                    }
                    KeyCode::Char('d') | KeyCode::Char('D') if !is_deny => {
                        result = Some(PermissionReviewAction::Deny);
                        break;
                    }
                    // Gated on the same flag the action row renders from: a
                    // key the dialog does not offer must not still act.
                    KeyCode::Char('l') | KeyCode::Char('L')
                        if !is_deny && req.sticky_grant_available =>
                    {
                        result = Some(PermissionReviewAction::ApproveAndLearn);
                        break;
                    }
                    KeyCode::Char('t') | KeyCode::Char('T') if !is_deny => {
                        result = Some(PermissionReviewAction::DenyAndTerminate);
                        break;
                    }
                    KeyCode::Char('c') | KeyCode::Char('C') if is_deny => {
                        result = Some(PermissionReviewAction::Deny);
                        break;
                    }
                    KeyCode::Char('s') | KeyCode::Char('S') if !is_deny => {
                        scope_dialog = widgets::permission::ScopeDialogState::for_request(req);
                    }
                    KeyCode::Char('b') | KeyCode::Char('B') if !is_deny => {
                        scope_dialog =
                            widgets::permission::ScopeDialogState::blocking_for_request(req);
                    }
                    KeyCode::Char('i') | KeyCode::Char('I') => {
                        show_inspect = !show_inspect;
                    }
                    KeyCode::Char('h') | KeyCode::Char('H') => {
                        show_help = true;
                    }
                    KeyCode::Esc => {
                        result = Some(PermissionReviewAction::Deny);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    drop(terminal);
    let _ = disable_raw_mode();

    #[cfg(unix)]
    restore_stderr(saved_stderr);

    result
}

/// Show a temporary TUI overlay for exec/supervisor mode.
/// Enters alternate screen on demand (Ctrl+G), renders shared state,
/// exits when dismissed. The supervised tool keeps running underneath.
pub fn run_tui_overlay(shared_state: &std::sync::Mutex<AppState>) -> anyhow::Result<()> {
    #[cfg(unix)]
    let saved_stderr = redirect_stderr_to_file();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let result = overlay_event_loop(&mut terminal, shared_state);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    #[cfg(unix)]
    restore_stderr(saved_stderr);

    result
}

fn overlay_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    shared_state: &std::sync::Mutex<AppState>,
) -> anyhow::Result<()> {
    loop {
        {
            let mut state = shared_state
                .lock()
                .map_err(|e| anyhow::anyhow!("lock: {e}"))?;
            state.frame_count += 1;
            terminal.draw(|frame| render::render(frame, &state))?;
        }

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                let mut state = shared_state
                    .lock()
                    .map_err(|e| anyhow::anyhow!("lock: {e}"))?;
                // Ctrl+G always dismisses the overlay
                if key.code == KeyCode::Char('g') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(());
                }
                // handle_key_event returns true on quit — treat as dismiss
                if handle_key_event(&mut state, key) {
                    return Ok(());
                }
            }
        }
    }
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut AppState,
    agent_rx: &std::sync::mpsc::Receiver<AgentEvent>,
    input_tx: Option<&tokio::sync::mpsc::Sender<TuiInput>>,
) -> anyhow::Result<()> {
    let tick_rate = Duration::from_millis(50);

    loop {
        // Render
        terminal.draw(|frame| render::render(frame, state))?;
        state.frame_count += 1;

        // Drain agent events (non-blocking)
        loop {
            match agent_rx.try_recv() {
                Ok(event) => handle_agent_event(state, event),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Main thread has exited, shut down TUI
                    return Ok(());
                }
            }
        }

        // Check for pending digest items needing review (TUI permission dialog)
        check_pending_digest(state);

        // Poll for crossterm events
        let tui_event = poll_tui_event(tick_rate)?;

        match tui_event {
            Some(TuiEvent::Key(key)) => {
                if handle_key_event(state, key) {
                    // User wants to quit
                    if let Some(tx) = input_tx {
                        let _ = tx.blocking_send(TuiInput::Quit);
                    }
                    return Ok(());
                }
                // Check if user submitted input via Enter
                if let Some(text) = state.pending_input.take() {
                    if let Some(tx) = input_tx {
                        let _ = tx.blocking_send(TuiInput::Prompt(text));
                    }
                }
            }
            Some(TuiEvent::Resize(_, _)) => {
                // Ratatui handles resize on next draw
            }
            Some(TuiEvent::Tick) | None => {}
        }
    }
}

fn poll_tui_event(timeout: Duration) -> io::Result<Option<TuiEvent>> {
    if event::poll(timeout)? {
        match event::read()? {
            Event::Key(key) => Ok(Some(TuiEvent::Key(key))),
            Event::Resize(w, h) => Ok(Some(TuiEvent::Resize(w, h))),
            _ => Ok(None),
        }
    } else {
        Ok(Some(TuiEvent::Tick))
    }
}

fn handle_agent_event(state: &mut AppState, event: AgentEvent) {
    match event {
        AgentEvent::TextChunk { text, dim } => {
            state.output.push(OutputLine::AgentText { text, dim });
        }
        AgentEvent::ToolCallStart { name, args } => {
            state.output.push(OutputLine::TreeLine {
                text: format!("{name}({args})"),
            });
        }
        AgentEvent::Decision {
            name,
            args: _,
            decision,
        } => {
            let detail = events::format_intercept_detail(&decision);
            state.intercept_log.push(state::InterceptEntry {
                decision,
                name,
                detail,
                timestamp: chrono::Local::now(),
            });
            state.session.call_count += 1;
        }
        AgentEvent::Resumed => {
            state.output.push(OutputLine::TreeLine {
                text: "resumed after approval".to_string(),
            });
        }
        AgentEvent::Complete(_) => {
            state.modal = ModalState::SessionSummary;
        }
        AgentEvent::CostUpdate { cost_delta } => {
            state.session.cost_usd += cost_delta;
        }
        AgentEvent::TokenUpdate {
            prompt_tokens,
            completion_tokens,
        } => {
            state.session.prompt_tokens += prompt_tokens;
            state.session.completion_tokens += completion_tokens;
        }
        AgentEvent::Error(msg) => {
            state.output.push(OutputLine::AgentText {
                text: format!("Error: {msg}"),
                dim: false,
            });
        }
        AgentEvent::ToolOutput(line) => {
            state.output.push(OutputLine::AgentText {
                text: line,
                dim: true,
            });
        }
    }
}

/// Convert a crossterm KeyEvent to raw bytes suitable for PTY stdin.
fn key_to_pty_bytes(key: &KeyEvent) -> Option<Vec<u8>> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        if let KeyCode::Char(c) = key.code {
            // Ctrl+A = 0x01, Ctrl+B = 0x02, ..., Ctrl+Z = 0x1A
            let ctrl_byte = (c as u8).wrapping_sub(b'a').wrapping_add(1);
            return Some(vec![ctrl_byte]);
        }
    }
    match key.code {
        KeyCode::Char(c) => {
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            Some(s.as_bytes().to_vec())
        }
        KeyCode::Enter => Some(vec![b'\r']),
        KeyCode::Backspace => Some(vec![0x7f]),
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::Esc => Some(vec![0x1b]),
        KeyCode::Up => Some(b"\x1b[A".to_vec()),
        KeyCode::Down => Some(b"\x1b[B".to_vec()),
        KeyCode::Right => Some(b"\x1b[C".to_vec()),
        KeyCode::Left => Some(b"\x1b[D".to_vec()),
        KeyCode::Home => Some(b"\x1b[H".to_vec()),
        KeyCode::End => Some(b"\x1b[F".to_vec()),
        KeyCode::Delete => Some(b"\x1b[3~".to_vec()),
        _ => None,
    }
}

/// Handle a key event. Returns `true` if the TUI should exit.
fn handle_key_event(state: &mut AppState, key: KeyEvent) -> bool {
    // Passthrough mode: forward all keys to PTY, except Ctrl+G (toggle)
    if state.passthrough {
        if key.code == KeyCode::Char('g') && key.modifiers.contains(KeyModifiers::CONTROL) {
            state.passthrough = false;
            return false;
        }
        if let Some(bytes) = key_to_pty_bytes(&key) {
            if let Some(ref tx) = state.pty_tx {
                let _ = tx.send(bytes);
            }
        }
        return false;
    }

    // Ctrl+C always quits
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return true;
    }

    // Ctrl+G enters passthrough mode (supervisor only)
    if key.code == KeyCode::Char('g')
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(state.mode, state::AppMode::Supervisor { .. })
    {
        state.passthrough = true;
        return false;
    }

    // Ctrl+U clears input line
    if key.code == KeyCode::Char('u') && key.modifiers.contains(KeyModifiers::CONTROL) {
        state.input_buffer.clear();
        state.input_cursor = 0;
        return false;
    }

    // Ctrl+W deletes previous word
    if key.code == KeyCode::Char('w') && key.modifiers.contains(KeyModifiers::CONTROL) {
        let trimmed = state.input_buffer.trim_end();
        if let Some(pos) = trimmed.rfind(' ') {
            state.input_buffer.truncate(pos + 1);
        } else {
            state.input_buffer.clear();
        }
        state.input_cursor = state.input_buffer.len();
        return false;
    }

    // Handle modals first
    if !matches!(state.modal, ModalState::None) {
        return handle_modal_key(state, key);
    }

    match key.code {
        // Global keys
        KeyCode::Char('q') if state.input_buffer.is_empty() => return true,
        KeyCode::Char('d') if state.input_buffer.is_empty() => {
            state.modal = ModalState::DigestQueue;
        }
        KeyCode::Char('s') if state.input_buffer.is_empty() => {
            state.modal = ModalState::SessionSummary;
        }
        KeyCode::Char('a') if state.input_buffer.is_empty() => {
            state.modal = ModalState::AuditLog;
        }
        KeyCode::Char('?') if state.input_buffer.is_empty() => {
            state.modal = ModalState::Help;
        }

        // Scroll keys (when input buffer is empty)
        KeyCode::Char('k') if state.input_buffer.is_empty() => {
            state.output.scroll_up();
        }
        KeyCode::Char('j') if state.input_buffer.is_empty() => {
            state.output.scroll_down();
        }
        KeyCode::PageUp if state.input_buffer.is_empty() => {
            state.output.page_up(20);
        }
        KeyCode::PageDown if state.input_buffer.is_empty() => {
            state.output.page_down(20);
        }
        KeyCode::Char('G') if state.input_buffer.is_empty() => {
            state.output.jump_bottom();
        }
        KeyCode::Char('g') if state.input_buffer.is_empty() => {
            state.output.jump_top();
        }

        // Input editing
        KeyCode::Char(c) => {
            state.input_buffer.push(c);
            state.input_cursor = state.input_buffer.len();
        }
        KeyCode::Backspace => {
            state.input_buffer.pop();
            state.input_cursor = state.input_buffer.len();
        }
        KeyCode::Enter if !state.input_buffer.is_empty() => {
            let text = state.input_buffer.clone();
            state.input_history.push(text.clone());
            state.history_idx = None;
            state.output.push(OutputLine::Prompt { text: text.clone() });
            state.input_buffer.clear();
            state.input_cursor = 0;

            // In supervisor mode, send input directly to PTY
            if matches!(state.mode, state::AppMode::Supervisor { .. }) {
                if let Some(ref tx) = state.pty_tx {
                    let mut bytes = text.into_bytes();
                    bytes.push(b'\r');
                    let _ = tx.send(bytes);
                }
            } else {
                state.pending_input = Some(text);
            }
        }
        KeyCode::Up if !state.input_history.is_empty() => {
            // History navigation
            let idx = match state.history_idx {
                Some(i) => i.saturating_sub(1),
                None => state.input_history.len() - 1,
            };
            state.history_idx = Some(idx);
            state.input_buffer = state.input_history[idx].clone();
            state.input_cursor = state.input_buffer.len();
        }
        KeyCode::Down if state.history_idx.is_some() => {
            if let Some(idx) = state.history_idx {
                if idx + 1 < state.input_history.len() {
                    let new_idx = idx + 1;
                    state.history_idx = Some(new_idx);
                    state.input_buffer = state.input_history[new_idx].clone();
                } else {
                    state.history_idx = None;
                    state.input_buffer.clear();
                }
                state.input_cursor = state.input_buffer.len();
            }
        }
        KeyCode::Esc => {
            state.input_buffer.clear();
            state.input_cursor = 0;
        }
        _ => {}
    }

    false
}

fn handle_modal_key(state: &mut AppState, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            state.modal = ModalState::None;
        }
        KeyCode::Enter => {
            state.modal = ModalState::None;
        }
        // Permission dialog keys — approve, deny, learn
        KeyCode::Char('a') if matches!(state.modal, ModalState::PermissionDialog(_)) => {
            if let ModalState::PermissionDialog(ref req) = state.modal {
                review_digest_item(state.digest_store.as_ref(), req.id, "approve", true);
            }
            state.modal = ModalState::None;
        }
        KeyCode::Char('d') if matches!(state.modal, ModalState::PermissionDialog(_)) => {
            if let ModalState::PermissionDialog(ref req) = state.modal {
                review_digest_item(state.digest_store.as_ref(), req.id, "deny", false);
            }
            state.modal = ModalState::None;
        }
        KeyCode::Char('l') if matches!(state.modal, ModalState::PermissionDialog(ref r) if r.sticky_grant_available) =>
        {
            if let ModalState::PermissionDialog(ref req) = state.modal {
                review_digest_item(
                    state.digest_store.as_ref(),
                    req.id,
                    "approve_and_learn",
                    true,
                );
            }
            state.modal = ModalState::None;
        }
        KeyCode::Char('t') if matches!(state.modal, ModalState::PermissionDialog(_)) => {
            if let ModalState::PermissionDialog(ref req) = state.modal {
                review_digest_item(
                    state.digest_store.as_ref(),
                    req.id,
                    "deny_and_terminate",
                    false,
                );
            }
            state.modal = ModalState::None;
        }
        _ => {}
    }
    false
}

/// Check the digest queue for pending items and show a permission dialog if found.
fn check_pending_digest(state: &mut AppState) {
    // Only show if no modal is currently open
    if !matches!(state.modal, ModalState::None) {
        return;
    }
    let dq = match state.digest_store.as_ref() {
        Some(dq) => dq,
        None => return,
    };
    let pending = match dq.get_pending(1, 0) {
        Ok(items) => items,
        Err(_) => return,
    };
    let item = match pending.first() {
        Some(item) => item,
        None => return,
    };

    let total = dq.get_pending(100, 0).map(|v| v.len()).unwrap_or(1);
    let filters: Vec<state::FilterHit> = item
        .filter_breakdown
        .iter()
        .map(|f| state::FilterHit {
            name: f.filter_name.clone(),
            delta: f.score as f32,
        })
        .collect();

    let severity = match item.composite_score {
        s if s >= 8.0 => "CRITICAL",
        s if s >= 5.0 => "WARNING",
        _ => "INFO",
    };
    let call_type_category = item
        .tool_call_type
        .find('(')
        .map(|i| item.tool_call_type[..i].to_string())
        .unwrap_or_else(|| item.tool_call_type.clone());

    state.modal = ModalState::PermissionDialog(Box::new(state::PermissionRequest {
        id: item.id,
        tool: item.tool_call_type.clone(),
        args: item.arguments_summary.clone(),
        score: item.composite_score as f32,
        filters,
        reasons: item
            .filter_breakdown
            .iter()
            .map(|f| f.message.clone())
            .collect(),
        decision_reason: item.decision_reason.clone().unwrap_or_default(),
        context: item.task_context.clone().unwrap_or_default(),
        severity: severity.to_string(),
        call_type: call_type_category,
        item_number: 1,
        total_items: total,
        scope_enabled: false,
        sticky_grant_available: true,
    }));
}

/// Update digest queue status in response to a review decision.
fn review_digest_item(
    digest_queue: Option<&std::sync::Arc<grith_digest::queue::DigestQueue>>,
    item_id: uuid::Uuid,
    action: &str,
    approved: bool,
) {
    let dq = match digest_queue {
        Some(dq) => dq,
        None => return,
    };
    let status = if approved {
        grith_digest::types::DigestStatus::Approved
    } else {
        grith_digest::types::DigestStatus::Denied
    };
    let note = format!("{action} via TUI");
    let _ = dq.update_status(&item_id, status, Some(action), Some(&note));
}

#[cfg(test)]
mod tests {
    use super::*;
    use state::{AppMode, Decision};

    fn test_state() -> AppState {
        AppState::new(
            AppMode::Repl {
                model: "test-model".to_string(),
            },
            6,
        )
    }

    #[test]
    fn test_handle_key_quit() {
        let mut state = test_state();
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(handle_key_event(&mut state, key));
    }

    #[test]
    fn test_handle_key_quit_blocked_by_input() {
        let mut state = test_state();
        state.input_buffer = "hello".to_string();
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        // 'q' should be added to input, not quit
        assert!(!handle_key_event(&mut state, key));
        assert!(state.input_buffer.contains('q'));
    }

    #[test]
    fn test_handle_key_ctrl_c_quits() {
        let mut state = test_state();
        let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(handle_key_event(&mut state, key));
    }

    #[test]
    fn test_handle_key_typing() {
        let mut state = test_state();
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE),
        );
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE),
        );
        assert_eq!(state.input_buffer, "hi");
    }

    #[test]
    fn test_handle_key_backspace() {
        let mut state = test_state();
        state.input_buffer = "hello".to_string();
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
        );
        assert_eq!(state.input_buffer, "hell");
    }

    #[test]
    fn test_handle_key_enter_submits() {
        let mut state = test_state();
        state.input_buffer = "test prompt".to_string();
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        assert!(state.input_buffer.is_empty());
        assert_eq!(state.input_history.len(), 1);
        // Should have pushed a Prompt line to output
        assert!(matches!(
            state.output.lines.last(),
            Some(OutputLine::Prompt { .. })
        ));
        // Should set pending_input
        assert_eq!(state.pending_input, Some("test prompt".to_string()));
    }

    #[test]
    fn test_handle_key_ctrl_u_clears() {
        let mut state = test_state();
        state.input_buffer = "some text".to_string();
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
        );
        assert!(state.input_buffer.is_empty());
    }

    #[test]
    fn test_handle_key_ctrl_w_delete_word() {
        let mut state = test_state();
        state.input_buffer = "hello world foo".to_string();
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL),
        );
        assert_eq!(state.input_buffer, "hello world ");
    }

    #[test]
    fn test_handle_key_scroll() {
        let mut state = test_state();
        for i in 0..50 {
            state.output.push(OutputLine::AgentText {
                text: format!("line {i}"),
                dim: false,
            });
        }
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE),
        );
        assert!(!state.output.follow);

        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE),
        );
        assert!(state.output.follow);
    }

    #[test]
    fn test_handle_key_modal_digest() {
        let mut state = test_state();
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
        );
        assert!(matches!(state.modal, ModalState::DigestQueue));

        // Esc dismisses
        handle_key_event(&mut state, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(state.modal, ModalState::None));
    }

    #[test]
    fn test_handle_key_modal_session() {
        let mut state = test_state();
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
        );
        assert!(matches!(state.modal, ModalState::SessionSummary));
    }

    #[test]
    fn test_handle_key_modal_help() {
        let mut state = test_state();
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
        );
        assert!(matches!(state.modal, ModalState::Help));
    }

    #[test]
    fn test_handle_agent_event_text_chunk() {
        let mut state = test_state();
        handle_agent_event(
            &mut state,
            AgentEvent::TextChunk {
                text: "hello".to_string(),
                dim: false,
            },
        );
        assert_eq!(state.output.lines.len(), 1);
    }

    #[test]
    fn test_handle_agent_event_decision() {
        let mut state = test_state();
        handle_agent_event(
            &mut state,
            AgentEvent::Decision {
                name: "fs.read".to_string(),
                args: "/tmp/test".to_string(),
                decision: Decision::Allow,
            },
        );
        assert_eq!(state.session.call_count, 1);
        assert_eq!(state.intercept_log.entries.len(), 1);
    }

    #[test]
    fn test_handle_agent_event_complete() {
        let mut state = test_state();
        let session_copy = state.session.clone();
        handle_agent_event(&mut state, AgentEvent::Complete(session_copy));
        assert!(matches!(state.modal, ModalState::SessionSummary));
    }

    #[test]
    fn test_handle_agent_event_cost() {
        let mut state = test_state();
        handle_agent_event(&mut state, AgentEvent::CostUpdate { cost_delta: 0.50 });
        assert!((state.session.cost_usd - 0.50).abs() < f64::EPSILON);
    }

    #[test]
    fn test_handle_agent_event_error() {
        let mut state = test_state();
        handle_agent_event(
            &mut state,
            AgentEvent::Error("something went wrong".to_string()),
        );
        assert_eq!(state.output.lines.len(), 1);
        if let OutputLine::AgentText { text, .. } = &state.output.lines[0] {
            assert!(text.contains("something went wrong"));
        } else {
            panic!("expected AgentText");
        }
    }

    #[test]
    fn test_handle_agent_event_tool_output() {
        let mut state = test_state();
        handle_agent_event(
            &mut state,
            AgentEvent::ToolOutput("output line".to_string()),
        );
        assert_eq!(state.output.lines.len(), 1);
    }

    #[test]
    fn test_history_navigation() {
        let mut state = test_state();
        state.input_history = vec!["first".to_string(), "second".to_string()];

        // Up arrow from empty buffer -> last item
        handle_key_event(&mut state, KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(state.input_buffer, "second");
        assert_eq!(state.history_idx, Some(1));

        // Up again -> first item
        handle_key_event(&mut state, KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(state.input_buffer, "first");

        // Down -> back to second
        handle_key_event(&mut state, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(state.input_buffer, "second");

        // Down again -> clear
        handle_key_event(&mut state, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert!(state.input_buffer.is_empty());
        assert_eq!(state.history_idx, None);
    }

    #[test]
    fn test_passthrough_mode_forwards_keys() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut state = AppState::new(
            state::AppMode::Supervisor {
                tool: "claude".to_string(),
                pid: 1234,
            },
            6,
        );
        state.passthrough = true;
        state.pty_tx = Some(tx);

        // Regular character should be forwarded to PTY
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE),
        );
        let bytes = rx.try_recv().unwrap();
        assert_eq!(bytes, b"h");

        // Enter should send \r
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        let bytes = rx.try_recv().unwrap();
        assert_eq!(bytes, b"\r");
    }

    #[test]
    fn test_passthrough_ctrl_g_toggles() {
        let mut state = AppState::new(
            state::AppMode::Supervisor {
                tool: "claude".to_string(),
                pid: 1234,
            },
            6,
        );
        state.passthrough = true;

        // Ctrl+G should exit passthrough
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL),
        );
        assert!(!state.passthrough);

        // Ctrl+G again should enter passthrough
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL),
        );
        assert!(state.passthrough);
    }

    #[test]
    fn test_passthrough_not_in_repl() {
        let mut state = test_state();
        // Ctrl+G should NOT enter passthrough in REPL mode
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL),
        );
        assert!(!state.passthrough);
    }

    #[test]
    fn test_enter_sets_pending_input() {
        let mut state = test_state();
        state.input_buffer = "hello".to_string();
        handle_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        assert_eq!(state.pending_input, Some("hello".to_string()));
    }

    #[test]
    fn test_key_to_pty_bytes() {
        // Regular char
        let bytes = key_to_pty_bytes(&KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        assert_eq!(bytes, Some(b"a".to_vec()));

        // Ctrl+C
        let bytes = key_to_pty_bytes(&KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert_eq!(bytes, Some(vec![3])); // ETX

        // Arrow up
        let bytes = key_to_pty_bytes(&KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(bytes, Some(b"\x1b[A".to_vec()));

        // Enter
        let bytes = key_to_pty_bytes(&KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(bytes, Some(vec![b'\r']));
    }
}
