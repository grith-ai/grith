// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Interactive terminal UI for reviewing queued digest items.

use crate::render::render_separator;
use crossterm::style::{Color, Stylize};
use grith_digest::actions::DigestActions;
use grith_digest::{DigestItem, DigestQueue, DigestStatus, ReviewAction, ReviewOutcome};
use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::time::Duration;

/// A digest review session state.
#[derive(Debug)]
pub struct DigestReviewSession {
    items: Vec<DigestItem>,
    cursor: usize,
    view_mode: ViewMode,
}

/// View mode in the digest UI.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ViewMode {
    /// Table listing all pending items.
    List,
    /// Detailed view of a single item.
    Detail,
}

/// Result of a user action in the digest UI.
#[derive(Debug, Clone, PartialEq)]
pub enum DigestAction {
    /// Approve the item at the given index.
    Approve(usize),
    /// Deny the item at the given index.
    Deny(usize),
    /// Approve and learn from the item.
    Learn(usize),
    /// Escalate the item for senior review.
    Escalate(usize),
    /// Approve and unlock egress containment for the session.
    UnlockEgress(usize),
    /// Deny and terminate the supervised process.
    DenyAndTerminate(usize),
    /// Approve and add to permanent allowlist.
    AllowAlways(usize),
    /// Skip to the next item.
    Skip,
    /// Quit the digest UI.
    Quit,
    /// Toggle between list and detail view.
    ToggleView,
    /// Navigate to the next item.
    Next,
    /// Navigate to the previous item.
    Previous,
}

impl DigestReviewSession {
    /// Create a new review session from pending digest items.
    pub fn new(items: Vec<DigestItem>) -> Self {
        Self {
            items,
            cursor: 0,
            view_mode: ViewMode::List,
        }
    }

    /// Get the number of pending items.
    pub fn pending_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.status == DigestStatus::Pending || i.status == DigestStatus::Escalated)
            .count()
    }

    /// Get the current cursor position.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Get the current view mode.
    pub fn view_mode(&self) -> ViewMode {
        self.view_mode
    }

    /// Get all items.
    pub fn items(&self) -> &[DigestItem] {
        &self.items
    }

    /// Get the currently selected item.
    pub fn current_item(&self) -> Option<&DigestItem> {
        self.items.get(self.cursor)
    }

    /// Apply a navigation or view action.
    pub fn apply_action(&mut self, action: &DigestAction) {
        match action {
            DigestAction::Next if self.cursor + 1 < self.items.len() => {
                self.cursor += 1;
            }
            DigestAction::Previous if self.cursor > 0 => {
                self.cursor -= 1;
            }
            DigestAction::ToggleView => {
                self.view_mode = match self.view_mode {
                    ViewMode::List => ViewMode::Detail,
                    ViewMode::Detail => ViewMode::List,
                };
            }
            DigestAction::Skip if self.cursor + 1 < self.items.len() => {
                self.cursor += 1;
            }
            _ => {}
        }
    }

    /// Mark an item as reviewed.
    pub fn mark_reviewed(&mut self, index: usize, action: ReviewAction) {
        if let Some(item) = self.items.get_mut(index) {
            item.status = match action {
                ReviewAction::Approve
                | ReviewAction::ApproveAndLearn
                | ReviewAction::UnlockEgress
                | ReviewAction::AllowAlways => DigestStatus::Approved,
                ReviewAction::Deny | ReviewAction::DenyAndTerminate => DigestStatus::Denied,
                ReviewAction::Escalate => DigestStatus::Escalated,
            };
            item.review_action = Some(action.to_string());
            item.reviewed_at = Some(chrono::Utc::now());
        }
    }
}

/// Parse a single keypress character into a digest action.
pub fn parse_digest_key(ch: char) -> Option<DigestAction> {
    match ch {
        'a' | 'A' => Some(DigestAction::Approve(0)), // index filled by caller
        'd' | 'D' => Some(DigestAction::Deny(0)),
        'l' | 'L' => Some(DigestAction::Learn(0)),
        'e' | 'E' => Some(DigestAction::Escalate(0)),
        'u' | 'U' => Some(DigestAction::UnlockEgress(0)),
        't' | 'T' => Some(DigestAction::DenyAndTerminate(0)),
        'p' | 'P' => Some(DigestAction::AllowAlways(0)),
        's' | 'S' => Some(DigestAction::Skip),
        'q' | 'Q' => Some(DigestAction::Quit),
        'v' | 'V' => Some(DigestAction::ToggleView),
        'j' | 'J' => Some(DigestAction::Next),
        'k' | 'K' => Some(DigestAction::Previous),
        _ => None,
    }
}

/// Render the digest list view.
pub fn render_digest_list(
    w: &mut impl Write,
    session: &DigestReviewSession,
) -> std::io::Result<()> {
    let pending = session.pending_count();
    writeln!(
        w,
        "{}",
        format!("Digest Review ({pending} pending)").with(Color::Cyan)
    )?;
    render_separator(w)?;

    if session.items().is_empty() {
        writeln!(w, "  No pending digest items.")?;
        return Ok(());
    }

    // Header
    writeln!(w, "  {:<4} {:<8} {:<20} Summary", "#", "Score", "Type")?;
    writeln!(w, "  {}", "-".repeat(70))?;

    for (i, item) in session.items().iter().enumerate() {
        let marker = if i == session.cursor() { ">" } else { " " };
        let score_color = score_color(item.composite_score);
        let score_str = format!("{:.1}", item.composite_score)
            .with(score_color)
            .to_string();

        let status_indicator = match item.status {
            DigestStatus::Pending => " ",
            DigestStatus::Approved => "v",
            DigestStatus::Denied => "x",
            DigestStatus::Expired => "~",
            DigestStatus::Escalated => "^",
        };

        let summary = truncate(&item.arguments_summary, 35);

        writeln!(
            w,
            "{marker} {status_indicator}{:<3} {:<8} {:<20} {}",
            i + 1,
            score_str,
            item.tool_call_type,
            summary
        )?;
    }

    render_separator(w)?;
    writeln!(
        w,
        "  [a]pprove [d]eny [l]earn [e]scalate [s]kip [v]iew detail [j/k]nav [q]uit"
    )?;
    writeln!(w, "  [u]nlock egress [t]erminate [p]ermanent allow")?;

    Ok(())
}

/// Render the digest detail view for a single item.
pub fn render_digest_detail(w: &mut impl Write, item: &DigestItem) -> std::io::Result<()> {
    writeln!(w, "{}", "Digest Item Detail".with(Color::Cyan))?;
    render_separator(w)?;

    writeln!(w, "  ID:          {}", item.id)?;
    writeln!(
        w,
        "  Created:     {}",
        item.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    )?;
    writeln!(w, "  Type:        {}", item.tool_call_type)?;
    writeln!(w, "  Arguments:   {}", item.arguments_summary)?;

    let sc_color = score_color(item.composite_score);
    let score_str = format!("{:.1}", item.composite_score)
        .with(sc_color)
        .to_string();
    writeln!(w, "  Score:       {} ({:?})", score_str, item.severity)?;
    writeln!(w, "  Status:      {}", item.status)?;

    if let Some(ref ctx) = item.task_context {
        writeln!(w, "  Task:        {ctx}")?;
    }
    if !item.plugin_id.is_empty() {
        writeln!(w, "  Plugin:      {}", item.plugin_id)?;
    }

    // Score bar
    write!(w, "  Score bar:   ")?;
    render_score_bar(w, item.composite_score)?;
    writeln!(w)?;

    // Filter breakdown
    if !item.filter_breakdown.is_empty() {
        writeln!(w)?;
        writeln!(w, "  Filter Breakdown:")?;
        writeln!(w, "  {:<30} {:<8} Details", "Filter", "Score")?;
        writeln!(w, "  {}", "-".repeat(65))?;

        for fb in &item.filter_breakdown {
            let color = score_color(fb.score);
            let fb_score = format!("{:.1}", fb.score).with(color).to_string();
            writeln!(w, "  {:<30} {:<8} {}", fb.filter_name, fb_score, fb.message)?;
        }
    }

    render_separator(w)?;
    writeln!(
        w,
        "  [a]pprove [d]eny [l]earn [e]scalate [s]kip [v]iew list [q]uit"
    )?;
    writeln!(w, "  [u]nlock egress [t]erminate [p]ermanent allow")?;

    Ok(())
}

/// Render a score bar visualization.
pub fn render_score_bar(w: &mut impl Write, score: f64) -> std::io::Result<()> {
    let bar_width = 20;
    let filled = ((score / 10.0) * bar_width as f64).round() as usize;
    let filled = filled.min(bar_width);
    let empty = bar_width - filled;

    let color = score_color(score);
    let bar = format!("[{}{}]", "#".repeat(filled), ".".repeat(empty));
    write!(w, "{}", bar.with(color))
}

/// Get the color for a score value.
pub fn score_color(score: f64) -> Color {
    if score < 4.0 {
        Color::Green
    } else if score < 5.5 {
        Color::Yellow
    } else if score < 7.0 {
        Color::DarkYellow
    } else {
        Color::Red
    }
}

/// Truncate a string to a maximum length with ellipsis.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

/// Run an inline interactive review for a single queued digest item.
///
/// Renders the item detail, enters crossterm raw mode, and races keypresses
/// against a polling interval that checks for external reviews (dashboard/webhook).
/// Falls back to silent polling if raw mode cannot be entered (piped stdin / non-tty).
pub async fn run_inline_review(
    digest_queue: &Arc<DigestQueue>,
    item: &DigestItem,
    timeout: Duration,
) -> ReviewOutcome {
    // Show the item detail
    let mut stdout = std::io::stdout();
    if render_digest_detail(&mut stdout, item).is_err() {
        return silent_poll(digest_queue, item.id, timeout).await;
    }
    let _ = stdout.flush();

    // Try to enter raw mode; fall back to silent poll if not a tty
    if !std::io::stdin().is_terminal() {
        return silent_poll(digest_queue, item.id, timeout).await;
    }

    match crossterm::terminal::enable_raw_mode() {
        Ok(()) => {
            let outcome = run_inline_raw_mode(digest_queue, item.id, timeout).await;
            let _ = crossterm::terminal::disable_raw_mode();
            // Print a newline after raw mode to restore normal output
            println!();
            outcome
        }
        Err(_) => silent_poll(digest_queue, item.id, timeout).await,
    }
}

/// Core inline review loop running in raw mode.
async fn run_inline_raw_mode(
    digest_queue: &Arc<DigestQueue>,
    item_id: uuid::Uuid,
    timeout: Duration,
) -> ReviewOutcome {
    use crossterm::event::{Event, EventStream, KeyCode, KeyEvent};
    use futures::StreamExt;
    use std::time::Instant;

    let start = Instant::now();
    let mut event_stream = EventStream::new();
    let mut poll_interval = tokio::time::interval(Duration::from_millis(250));
    poll_interval.tick().await; // consume immediate first tick

    loop {
        // Check overall timeout
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            auto_deny(digest_queue, item_id);
            return ReviewOutcome::TimedOut;
        }

        tokio::select! {
            maybe_event = event_stream.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(KeyEvent { code: KeyCode::Char(ch), .. }))) => {
                        if let Some(action) = parse_digest_key(ch) {
                            if let Some(outcome) = apply_inline_action(digest_queue, item_id, &action) {
                                return outcome;
                            }
                        }
                    }
                    Some(Ok(Event::Key(KeyEvent { code: KeyCode::Esc, .. }))) => {
                        // Esc = deny
                        auto_deny(digest_queue, item_id);
                        return ReviewOutcome::Denied;
                    }
                    None => {
                        // Stream ended (stdin closed)
                        auto_deny(digest_queue, item_id);
                        return ReviewOutcome::Denied;
                    }
                    _ => {} // ignore other events
                }
            }
            _ = poll_interval.tick() => {
                if let Some(outcome) = check_resolved(digest_queue, item_id) {
                    return outcome;
                }
            }
        }
    }
}

/// Apply a digest action from an inline review keypress.
/// Returns `Some(ReviewOutcome)` if the action resolves the item, `None` otherwise.
fn apply_inline_action(
    digest_queue: &Arc<DigestQueue>,
    item_id: uuid::Uuid,
    action: &DigestAction,
) -> Option<ReviewOutcome> {
    let review_action = match action {
        DigestAction::Approve(_) => ReviewAction::Approve,
        DigestAction::Deny(_) => ReviewAction::Deny,
        DigestAction::Learn(_) => ReviewAction::ApproveAndLearn,
        DigestAction::Escalate(_) => ReviewAction::Escalate,
        DigestAction::UnlockEgress(_) => ReviewAction::UnlockEgress,
        DigestAction::DenyAndTerminate(_) => ReviewAction::DenyAndTerminate,
        DigestAction::AllowAlways(_) => ReviewAction::AllowAlways,
        DigestAction::Quit => {
            auto_deny(digest_queue, item_id);
            return Some(ReviewOutcome::Denied);
        }
        // Skip/navigation not meaningful for single-item inline review
        _ => return None,
    };

    let actions = DigestActions::new(digest_queue);
    if actions.review(&item_id, review_action, None).is_ok() {
        return match review_action {
            ReviewAction::Approve
            | ReviewAction::ApproveAndLearn
            | ReviewAction::UnlockEgress
            | ReviewAction::AllowAlways => Some(ReviewOutcome::Approved),
            ReviewAction::Deny | ReviewAction::DenyAndTerminate => Some(ReviewOutcome::Denied),
            ReviewAction::Escalate => None, // escalated, keep waiting
        };
    }
    None
}

/// Check if the item was resolved externally (dashboard, webhook, etc.).
fn check_resolved(digest_queue: &Arc<DigestQueue>, item_id: uuid::Uuid) -> Option<ReviewOutcome> {
    let status = digest_queue
        .get_by_id(&item_id)
        .ok()
        .map(|item| item.status);

    match status {
        Some(DigestStatus::Approved) => Some(ReviewOutcome::Approved),
        Some(DigestStatus::Denied) | Some(DigestStatus::Expired) => Some(ReviewOutcome::Denied),
        _ => None,
    }
}

/// Auto-deny an item (timeout or user quit).
fn auto_deny(digest_queue: &Arc<DigestQueue>, item_id: uuid::Uuid) {
    let now = chrono::Utc::now().to_rfc3339();
    if let Err(e) = digest_queue.update_status(
        &item_id,
        DigestStatus::Denied,
        Some("auto_deny_timeout"),
        Some(&format!("auto denied at {now}")),
    ) {
        tracing::warn!(
            item_id = %item_id,
            error = %e,
            "failed to auto-deny digest item; item may remain in Pending state"
        );
    }
}

/// Silent polling fallback (no tty / raw mode failed).
async fn silent_poll(
    digest_queue: &Arc<DigestQueue>,
    item_id: uuid::Uuid,
    timeout: Duration,
) -> ReviewOutcome {
    use std::time::Instant;
    let start = Instant::now();

    loop {
        if start.elapsed() >= timeout {
            auto_deny(digest_queue, item_id);
            return ReviewOutcome::TimedOut;
        }

        if let Some(outcome) = check_resolved(digest_queue, item_id) {
            return outcome;
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Run a full interactive digest review session for multiple pending items.
///
/// Used by the `/digest` REPL command and `grith digest review` CLI subcommand.
/// Loads actionable items, enters raw mode, and lets the user navigate and review.
pub async fn run_digest_review_session(digest_queue: &Arc<DigestQueue>) -> std::io::Result<()> {
    let items = digest_queue.get_actionable(100, 0).unwrap_or_default();

    if items.is_empty() {
        println!("No pending digest items to review.");
        return Ok(());
    }

    let mut session = DigestReviewSession::new(items);
    let mut stdout = std::io::stdout();

    // Try raw mode; if unavailable, just render the list statically
    if !std::io::stdin().is_terminal() {
        render_digest_list(&mut stdout, &session)?;
        return Ok(());
    }

    if crossterm::terminal::enable_raw_mode().is_err() {
        render_digest_list(&mut stdout, &session)?;
        return Ok(());
    }

    let result = run_review_session_raw(&mut session, digest_queue, &mut stdout).await;
    let _ = crossterm::terminal::disable_raw_mode();
    println!();
    result
}

/// Writer wrapper that converts bare `\n` to `\r\n` for raw-mode output.
/// In terminal raw mode, `\n` moves the cursor down without returning to
/// column 0, causing progressive indentation. This wrapper ensures each
/// newline also performs a carriage return.
struct RawModeWriter<W: Write>(W);

impl<W: Write> Write for RawModeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Replace lone \n (not preceded by \r) with \r\n
        let mut last = 0;
        for i in 0..buf.len() {
            if buf[i] == b'\n' && (i == 0 || buf[i - 1] != b'\r') {
                self.0.write_all(&buf[last..i])?;
                self.0.write_all(b"\r\n")?;
                last = i + 1;
            }
        }
        self.0.write_all(&buf[last..])?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// Inner raw-mode loop for the multi-item review session.
async fn run_review_session_raw(
    session: &mut DigestReviewSession,
    digest_queue: &Arc<DigestQueue>,
    stdout: &mut impl Write,
) -> std::io::Result<()> {
    use crossterm::event::{Event, EventStream, KeyCode, KeyEvent};
    use crossterm::terminal::{Clear, ClearType};
    use crossterm::ExecutableCommand;
    use futures::StreamExt;

    let mut event_stream = EventStream::new();

    // Initial render (wrap in RawModeWriter for \n → \r\n conversion)
    render_session_view(&mut RawModeWriter(&mut *stdout), session)?;
    stdout.flush()?;

    loop {
        let maybe_event = event_stream.next().await;
        match maybe_event {
            Some(Ok(Event::Key(KeyEvent {
                code: KeyCode::Char(ch),
                ..
            }))) => {
                if let Some(action) = parse_digest_key(ch) {
                    match &action {
                        DigestAction::Quit => break,
                        DigestAction::Next
                        | DigestAction::Previous
                        | DigestAction::Skip
                        | DigestAction::ToggleView => {
                            session.apply_action(&action);
                        }
                        _ => {
                            // Review action — apply to current item
                            if let Some(item) = session.current_item() {
                                let item_id = item.id;
                                let review_action = match &action {
                                    DigestAction::Approve(_) => Some(ReviewAction::Approve),
                                    DigestAction::Deny(_) => Some(ReviewAction::Deny),
                                    DigestAction::Learn(_) => Some(ReviewAction::ApproveAndLearn),
                                    DigestAction::Escalate(_) => Some(ReviewAction::Escalate),
                                    DigestAction::UnlockEgress(_) => {
                                        Some(ReviewAction::UnlockEgress)
                                    }
                                    DigestAction::DenyAndTerminate(_) => {
                                        Some(ReviewAction::DenyAndTerminate)
                                    }
                                    DigestAction::AllowAlways(_) => Some(ReviewAction::AllowAlways),
                                    _ => None,
                                };

                                if let Some(ra) = review_action {
                                    let actions = DigestActions::new(digest_queue);
                                    if let Err(e) = actions.review(&item_id, ra, None) {
                                        tracing::warn!(
                                            item_id = %item_id,
                                            action = ?ra,
                                            error = %e,
                                            "failed to persist review action to digest database"
                                        );
                                    }
                                    session.mark_reviewed(session.cursor(), ra);

                                    // Auto-advance to next pending item
                                    if session.pending_count() == 0 {
                                        break;
                                    }
                                    session.apply_action(&DigestAction::Next);
                                }
                            }
                        }
                    }
                }
            }
            Some(Ok(Event::Key(KeyEvent {
                code: KeyCode::Esc, ..
            }))) => break,
            None => break,
            _ => continue,
        }

        // Re-render
        let _ = stdout.execute(Clear(ClearType::All));
        let _ = stdout.execute(crossterm::cursor::MoveTo(0, 0));
        render_session_view(&mut RawModeWriter(&mut *stdout), session)?;
        stdout.flush()?;
    }

    if session.pending_count() == 0 {
        // Temporarily leave raw mode to print summary
        let _ = crossterm::terminal::disable_raw_mode();
        println!("All items reviewed.");
        let _ = crossterm::terminal::enable_raw_mode();
    }

    Ok(())
}

/// Render the appropriate view for the current session state.
fn render_session_view(w: &mut impl Write, session: &DigestReviewSession) -> std::io::Result<()> {
    match session.view_mode() {
        ViewMode::List => render_digest_list(w, session),
        ViewMode::Detail => {
            if let Some(item) = session.current_item() {
                render_digest_detail(w, item)
            } else {
                render_digest_list(w, session)
            }
        }
    }
}

/// Format a count badge for the terminal prompt.
pub fn digest_badge(pending_count: usize) -> String {
    if pending_count == 0 {
        String::new()
    } else {
        format!(
            " {}",
            format!("[{pending_count} pending]").with(Color::Yellow)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grith_digest::types::{FilterBreakdown, ScoreSeverity};
    use uuid::Uuid;

    fn make_item(score: f64, tool_type: &str, summary: &str) -> DigestItem {
        DigestItem {
            id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            session_id: None,
            tool_call_type: tool_type.to_string(),
            arguments_summary: summary.to_string(),
            composite_score: score,
            severity: ScoreSeverity::from_score(score),
            filter_breakdown: vec![],
            task_context: None,
            plugin_id: String::new(),
            status: DigestStatus::Pending,
            reviewed_at: None,
            review_action: None,
            reviewer_notes: None,
            informational_only: false,
            escalated_at: None,
            escalated_by: None,
        }
    }

    #[test]
    fn test_session_creation() {
        let items = vec![
            make_item(4.5, "fs_write", "Write to /tmp/test.txt"),
            make_item(6.2, "shell_exec", "Run: curl example.com"),
        ];
        let session = DigestReviewSession::new(items);
        assert_eq!(session.pending_count(), 2);
        assert_eq!(session.cursor(), 0);
        assert_eq!(session.view_mode(), ViewMode::List);
    }

    #[test]
    fn test_session_navigation() {
        let items = vec![
            make_item(4.5, "fs_write", "Write to /tmp/test.txt"),
            make_item(6.2, "shell_exec", "Run: curl example.com"),
            make_item(3.5, "fs_read", "Read /etc/hosts"),
        ];
        let mut session = DigestReviewSession::new(items);

        assert_eq!(session.cursor(), 0);
        session.apply_action(&DigestAction::Next);
        assert_eq!(session.cursor(), 1);
        session.apply_action(&DigestAction::Next);
        assert_eq!(session.cursor(), 2);
        session.apply_action(&DigestAction::Next); // at end, stays
        assert_eq!(session.cursor(), 2);
        session.apply_action(&DigestAction::Previous);
        assert_eq!(session.cursor(), 1);
    }

    #[test]
    fn test_session_toggle_view() {
        let mut session = DigestReviewSession::new(vec![make_item(4.5, "fs_write", "test")]);
        assert_eq!(session.view_mode(), ViewMode::List);
        session.apply_action(&DigestAction::ToggleView);
        assert_eq!(session.view_mode(), ViewMode::Detail);
        session.apply_action(&DigestAction::ToggleView);
        assert_eq!(session.view_mode(), ViewMode::List);
    }

    #[test]
    fn test_mark_reviewed() {
        let mut session = DigestReviewSession::new(vec![
            make_item(4.5, "fs_write", "test"),
            make_item(6.2, "shell_exec", "test2"),
        ]);

        session.mark_reviewed(0, ReviewAction::Approve);
        assert_eq!(session.items()[0].status, DigestStatus::Approved);
        assert_eq!(
            session.items()[0].review_action,
            Some("approve".to_string())
        );
        assert!(session.items()[0].reviewed_at.is_some());
        assert_eq!(session.pending_count(), 1);

        session.mark_reviewed(1, ReviewAction::Deny);
        assert_eq!(session.items()[1].status, DigestStatus::Denied);
        assert_eq!(session.pending_count(), 0);
    }

    #[test]
    fn test_parse_digest_key() {
        assert!(matches!(
            parse_digest_key('a'),
            Some(DigestAction::Approve(_))
        ));
        assert!(matches!(parse_digest_key('d'), Some(DigestAction::Deny(_))));
        assert!(matches!(
            parse_digest_key('l'),
            Some(DigestAction::Learn(_))
        ));
        assert_eq!(parse_digest_key('s'), Some(DigestAction::Skip));
        assert_eq!(parse_digest_key('q'), Some(DigestAction::Quit));
        assert_eq!(parse_digest_key('v'), Some(DigestAction::ToggleView));
        assert_eq!(parse_digest_key('j'), Some(DigestAction::Next));
        assert_eq!(parse_digest_key('k'), Some(DigestAction::Previous));
        assert_eq!(parse_digest_key('z'), None);
    }

    #[test]
    fn test_render_digest_list_empty() {
        let session = DigestReviewSession::new(vec![]);
        let mut buf = Vec::new();
        render_digest_list(&mut buf, &session).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("0 pending"));
        assert!(output.contains("No pending digest items"));
    }

    #[test]
    fn test_render_digest_list_with_items() {
        let items = vec![
            make_item(4.5, "fs_write", "Write to /tmp/test.txt"),
            make_item(6.2, "shell_exec", "Run: curl example.com"),
        ];
        let session = DigestReviewSession::new(items);
        let mut buf = Vec::new();
        render_digest_list(&mut buf, &session).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("2 pending"));
        assert!(output.contains("fs_write"));
        assert!(output.contains("shell_exec"));
        assert!(output.contains("[a]pprove"));
    }

    #[test]
    fn test_render_digest_detail() {
        let mut item = make_item(5.5, "shell_exec", "Run: rm -rf /tmp/test");
        item.task_context = Some("Clean up temp files".to_string());
        item.filter_breakdown = vec![FilterBreakdown {
            filter_name: "path-denylist".to_string(),
            score: 3.0,
            rule_id: "deny-rm-rf".to_string(),
            message: "Destructive command detected".to_string(),
        }];

        let mut buf = Vec::new();
        render_digest_detail(&mut buf, &item).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("shell_exec"));
        assert!(output.contains("Clean up temp files"));
        assert!(output.contains("path-denylist"));
        assert!(output.contains("Destructive command"));
    }

    #[test]
    fn test_score_color() {
        assert_eq!(score_color(2.0), Color::Green);
        assert_eq!(score_color(4.5), Color::Yellow);
        assert_eq!(score_color(6.0), Color::DarkYellow);
        assert_eq!(score_color(8.0), Color::Red);
    }

    #[test]
    fn test_score_bar() {
        let mut buf = Vec::new();
        render_score_bar(&mut buf, 5.0).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("["));
        assert!(output.contains("]"));
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world!", 8), "hello...");
        assert_eq!(truncate("ab", 2), "ab");
    }

    #[test]
    fn test_digest_badge() {
        assert_eq!(digest_badge(0), "");
        let badge = digest_badge(3);
        assert!(badge.contains("3 pending"));
    }

    #[test]
    fn test_learn_action() {
        let mut session = DigestReviewSession::new(vec![make_item(4.5, "fs_write", "test")]);
        session.mark_reviewed(0, ReviewAction::ApproveAndLearn);
        assert_eq!(session.items()[0].status, DigestStatus::Approved);
        assert_eq!(
            session.items()[0].review_action,
            Some("approve_and_learn".to_string())
        );
    }

    #[test]
    fn test_escalate_key_parsing() {
        assert!(matches!(
            parse_digest_key('e'),
            Some(DigestAction::Escalate(_))
        ));
        assert!(matches!(
            parse_digest_key('E'),
            Some(DigestAction::Escalate(_))
        ));
    }

    #[test]
    fn test_escalate_action() {
        let mut session = DigestReviewSession::new(vec![make_item(4.5, "fs_write", "test")]);
        session.mark_reviewed(0, ReviewAction::Escalate);
        assert_eq!(session.items()[0].status, DigestStatus::Escalated);
        assert_eq!(
            session.items()[0].review_action,
            Some("escalate".to_string())
        );
    }

    #[test]
    fn test_escalated_status_indicator() {
        let mut item = make_item(4.5, "fs_write", "test");
        item.status = DigestStatus::Escalated;
        let session = DigestReviewSession::new(vec![item]);
        let mut buf = Vec::new();
        render_digest_list(&mut buf, &session).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Escalated items still count as actionable
        assert!(output.contains("1 pending"));
        assert!(output.contains("[e]scalate"));
    }

    #[test]
    fn test_pending_count_includes_escalated() {
        let mut items = vec![
            make_item(4.5, "fs_write", "test1"),
            make_item(6.2, "shell_exec", "test2"),
        ];
        items[1].status = DigestStatus::Escalated;
        let session = DigestReviewSession::new(items);
        assert_eq!(session.pending_count(), 2);
    }
}
