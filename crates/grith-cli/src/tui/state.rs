// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! TUI application state: mode, output panel, session stats, modal state.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

/// Top-level mode — determines prompt prefix and subheader labels.
#[derive(Debug, Clone)]
pub enum AppMode {
    Repl { model: String },
    Supervisor { tool: String, pid: u32 },
}

impl AppMode {
    pub fn method_label(&self) -> &str {
        match self {
            AppMode::Repl { .. } => "repl",
            AppMode::Supervisor { tool, .. } => tool.as_str(),
        }
    }
}

/// Which modal overlay is currently open.
#[derive(Debug, Clone)]
pub enum ModalState {
    None,
    PermissionDialog(Box<PermissionRequest>),
    SessionSummary,
    DigestQueue,
    AuditLog,
    Help,
}

/// Main application state for the TUI.
pub struct AppState {
    pub mode: AppMode,
    pub modal: ModalState,
    pub output: OutputPanel,
    pub intercept_log: InterceptLog,
    pub input_buffer: String,
    pub input_history: Vec<String>,
    pub history_idx: Option<usize>,
    pub digest_queue: VecDeque<PermissionRequest>,
    pub session: SessionStats,
    pub filter_count: usize,
    pub frame_count: u64,
    pub input_cursor: usize,
    pub pending_input: Option<String>,
    /// In supervisor mode: when true, all keystrokes go directly to the PTY.
    /// Ctrl+G toggles back to grith UI mode.
    pub passthrough: bool,
    /// Channel to send raw bytes to the PTY writer (supervisor mode only).
    pub pty_tx: Option<std::sync::mpsc::Sender<Vec<u8>>>,
    /// Digest queue store for reviewing pending permission requests (TUI mode).
    pub digest_store: Option<Arc<grith_digest::queue::DigestQueue>>,
}

impl AppState {
    pub fn new(mode: AppMode, filter_count: usize) -> Self {
        Self {
            mode,
            modal: ModalState::None,
            output: OutputPanel::new(),
            intercept_log: InterceptLog::new(3),
            input_buffer: String::new(),
            input_history: Vec::new(),
            history_idx: None,
            digest_queue: VecDeque::new(),
            session: SessionStats::new(),
            filter_count,
            frame_count: 0,
            input_cursor: 0,
            pending_input: None,
            passthrough: false,
            pty_tx: None,
            digest_store: None,
        }
    }

    pub fn method_label(&self) -> &str {
        self.mode.method_label()
    }
}

/// Aggregated session statistics displayed in titlebar and session summary.
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub call_count: u64,
    pub allow_count: u64,
    pub queue_count: u64,
    pub deny_count: u64,
    pub cost_usd: f64,
    pub start: Instant,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub attacks_blocked: u64,
    pub provider: String,
    pub model: String,
}

impl SessionStats {
    pub fn new() -> Self {
        Self {
            call_count: 0,
            allow_count: 0,
            queue_count: 0,
            deny_count: 0,
            cost_usd: 0.0,
            start: Instant::now(),
            prompt_tokens: 0,
            completion_tokens: 0,
            attacks_blocked: 0,
            provider: String::new(),
            model: String::new(),
        }
    }

    pub fn allow_pct(&self) -> u64 {
        if self.call_count == 0 {
            return 100;
        }
        self.allow_count * 100 / self.call_count
    }

    pub fn queued_count(&self) -> u64 {
        self.queue_count
    }

    pub fn duration_display(&self) -> String {
        let secs = self.start.elapsed().as_secs();
        if secs < 60 {
            format!("{secs}s")
        } else {
            let m = secs / 60;
            let s = secs % 60;
            format!("{m}m {s:02}s")
        }
    }
}

impl Default for SessionStats {
    fn default() -> Self {
        Self::new()
    }
}

/// A single line in the output panel.
#[derive(Debug, Clone)]
pub enum OutputLine {
    /// User prompt (REPL mode).
    Prompt { text: String },
    /// Agent narrative text.
    AgentText { text: String, dim: bool },
    /// Sub-item with tree connector.
    TreeLine { text: String },
    /// Security intercept annotation inline after a tool call.
    Intercept { decision: Decision, detail: String },
    /// Blank spacer between logical groups.
    Blank,
}

/// Proxy decision for a tool call.
#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Queue { score: f32, filters: Vec<FilterHit> },
    Deny { score: f32, filters: Vec<FilterHit> },
}

/// A single filter contribution to a score.
#[derive(Debug, Clone)]
pub struct FilterHit {
    pub name: String,
    pub delta: f32,
}

/// Small ring buffer of recent grith intercept messages (shown above the input bar).
pub struct InterceptLog {
    pub entries: VecDeque<InterceptEntry>,
    pub capacity: usize,
}

/// A single intercept log entry.
#[derive(Debug, Clone)]
pub struct InterceptEntry {
    pub decision: Decision,
    pub name: String,
    pub detail: String,
    pub timestamp: chrono::DateTime<chrono::Local>,
}

impl InterceptLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, entry: InterceptEntry) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }
}

impl Default for InterceptLog {
    fn default() -> Self {
        Self::new(3)
    }
}

/// Scrollable output panel.
pub struct OutputPanel {
    pub lines: Vec<OutputLine>,
    pub offset: usize,
    pub follow: bool,
}

impl OutputPanel {
    pub fn new() -> Self {
        Self {
            lines: Vec::new(),
            offset: 0,
            follow: true,
        }
    }

    pub fn push(&mut self, line: OutputLine) {
        self.lines.push(line);
    }

    pub fn scroll_up(&mut self) {
        self.follow = false;
        self.offset = self.offset.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        self.offset += 1;
    }

    pub fn page_up(&mut self, page_size: usize) {
        self.follow = false;
        self.offset = self.offset.saturating_sub(page_size);
    }

    pub fn page_down(&mut self, page_size: usize) {
        self.offset += page_size;
    }

    pub fn jump_bottom(&mut self) {
        self.follow = true;
    }

    pub fn jump_top(&mut self) {
        self.follow = false;
        self.offset = 0;
    }
}

impl Default for OutputPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// A queued permission request displayed in the dialog.
#[derive(Debug, Clone)]
pub struct PermissionRequest {
    pub id: Uuid,
    pub tool: String,
    pub args: String,
    pub score: f32,
    pub filters: Vec<FilterHit>,
    pub reasons: Vec<String>,
    pub decision_reason: String,
    pub context: String,
    pub severity: String,
    pub call_type: String,
    pub item_number: usize,
    pub total_items: usize,
    /// Whether the exec reviewer may offer session directory scoping.
    pub scope_enabled: bool,
    /// Whether approving this request can be remembered at all.
    ///
    /// D-Bus method calls (and the built-in agent's `ShellExec`/`HttpRequest`)
    /// have no session-allowlist key, so neither `[a]` nor `[l]` can outlive
    /// the single call. The dialog hides `[l]` and softens the `[a]` wording
    /// when this is false — offering a grant that silently cannot be recorded
    /// reads as grith forgetting the operator's answer.
    ///
    /// Defaults to `true` so a construction site that does not know stays on
    /// today's behaviour rather than losing the option.
    pub sticky_grant_available: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_mode_labels() {
        let repl = AppMode::Repl {
            model: "claude-sonnet-4-5".to_string(),
        };
        assert_eq!(repl.method_label(), "repl");

        let sup = AppMode::Supervisor {
            tool: "claude-code".to_string(),
            pid: 1234,
        };
        assert_eq!(sup.method_label(), "claude-code");
    }

    #[test]
    fn test_session_stats_allow_pct() {
        let mut stats = SessionStats::new();
        assert_eq!(stats.allow_pct(), 100);

        stats.call_count = 100;
        stats.allow_count = 96;
        assert_eq!(stats.allow_pct(), 96);
    }

    #[test]
    fn test_output_panel_scroll() {
        let mut panel = OutputPanel::new();
        for i in 0..50 {
            panel.push(OutputLine::AgentText {
                text: format!("line {i}"),
                dim: false,
            });
        }
        assert!(panel.follow);
        panel.scroll_up();
        assert!(!panel.follow);
        panel.jump_bottom();
        assert!(panel.follow);
        panel.jump_top();
        assert_eq!(panel.offset, 0);
        assert!(!panel.follow);
    }

    #[test]
    fn test_output_panel_page_scroll() {
        let mut panel = OutputPanel::new();
        for i in 0..100 {
            panel.push(OutputLine::AgentText {
                text: format!("line {i}"),
                dim: false,
            });
        }
        panel.follow = false;
        panel.offset = 50;
        panel.page_up(20);
        assert_eq!(panel.offset, 30);
        panel.page_down(10);
        assert_eq!(panel.offset, 40);
    }

    #[test]
    fn test_app_state_creation() {
        let state = AppState::new(
            AppMode::Repl {
                model: "test".to_string(),
            },
            17,
        );
        assert_eq!(state.filter_count, 17);
        assert_eq!(state.method_label(), "repl");
        assert!(state.input_buffer.is_empty());
    }

    #[test]
    fn test_duration_display() {
        let stats = SessionStats::new();
        let display = stats.duration_display();
        // Just created, should be "0s"
        assert!(display.ends_with('s'));
    }

    #[test]
    fn test_filter_hit_construction() {
        let hit = FilterHit {
            name: "path-match".to_string(),
            delta: 5.0,
        };
        assert_eq!(hit.name, "path-match");
        assert!((hit.delta - 5.0).abs() < f32::EPSILON);
    }
}
