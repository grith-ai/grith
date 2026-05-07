// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Terminal-based queue reviewer for `grith exec` sessions.
//!
//! When running in an interactive terminal, this reviewer uses the ratatui
//! permission dialog to prompt the user. The stdin→PTY forwarding thread is
//! paused via an [`AtomicBool`] so it doesn't compete for terminal input.
//!
//! After the review dialog is dismissed, SIGWINCH is sent to the supervised
//! tool to force it to redraw its TUI.
//!
//! Falls back to [`PollingQueueReviewer`] when `/dev/tty` is unavailable
//! (CI, Docker, etc.).

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use grith_digest::types::{DigestItem, DigestStatus, ReviewOutcome};
use grith_supervisor::reviewer::{DigestStore, PollingQueueReviewer, QueueReviewer};

// ---------------------------------------------------------------------------
// ExecTuiQueueReviewer — sends permission requests to the exec TUI overlay
// ---------------------------------------------------------------------------

/// A queue reviewer that sends permission requests to the exec TUI's
/// permission dialog overlay and waits for the user's response.
pub struct ExecTuiQueueReviewer {
    event_tx: std::sync::mpsc::Sender<grith_cli::tui::exec_tui::ExecEvent>,
    digest_store: Arc<dyn DigestStore>,
}

impl ExecTuiQueueReviewer {
    pub fn new(
        event_tx: std::sync::mpsc::Sender<grith_cli::tui::exec_tui::ExecEvent>,
        digest_store: Arc<dyn DigestStore>,
    ) -> Self {
        Self {
            event_tx,
            digest_store,
        }
    }
}

#[async_trait]
impl QueueReviewer for ExecTuiQueueReviewer {
    async fn review(&self, item: &DigestItem, timeout: Duration) -> ReviewOutcome {
        // Build a PermissionRequest for the TUI dialog.
        let filters: Vec<grith_cli::tui::state::FilterHit> = item
            .filter_breakdown
            .iter()
            .map(|f| grith_cli::tui::state::FilterHit {
                name: f.filter_name.clone(),
                delta: f.score as f32,
            })
            .collect();

        let severity = match item.composite_score {
            s if s >= 8.0 => "CRITICAL",
            s if s >= 5.0 => "WARNING",
            _ => "INFO",
        };

        // Extract category name (e.g. "ProcessSpawn") from "ProcessSpawn(/path/...)".
        let call_type_category = item
            .tool_call_type
            .find('(')
            .map(|i| &item.tool_call_type[..i])
            .unwrap_or(&item.tool_call_type)
            .to_string();

        let req = grith_cli::tui::state::PermissionRequest {
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
            context: item.task_context.clone().unwrap_or_default(),
            severity: severity.to_string(),
            call_type: call_type_category,
            item_number: 1,
            total_items: 1,
        };

        // Create a response channel.
        let (response_tx, response_rx) = std::sync::mpsc::sync_channel::<&'static str>(1);

        // Send the request to the TUI.
        let event = grith_cli::tui::exec_tui::ExecEvent::PermissionRequest {
            request: req,
            response_tx,
        };
        if self.event_tx.send(event).is_err() {
            return ReviewOutcome::Denied;
        }

        // Wait for the user's response (blocking — wrapped in spawn_blocking
        // so we don't block the tokio runtime).
        let digest_store = self.digest_store.clone();
        let item_id = item.id;

        let handle = tokio::task::spawn_blocking(move || match response_rx.recv_timeout(timeout) {
            Ok(action) => {
                let (status, outcome) = match action {
                    "approve" | "approve_and_learn" => {
                        (DigestStatus::Approved, ReviewOutcome::Approved)
                    }
                    _ => (DigestStatus::Denied, ReviewOutcome::Denied),
                };
                let note = format!("{action} via exec TUI dialog");
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(rt) = rt {
                    let _ = rt.block_on(digest_store.update_status(
                        item_id,
                        status,
                        Some(action),
                        Some(&note),
                    ));
                }
                outcome
            }
            Err(_) => ReviewOutcome::TimedOut,
        });

        match handle.await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::error!(error = %e, "exec TUI review task panicked");
                ReviewOutcome::Denied
            }
        }
    }
}

/// A queue reviewer that prompts the user on the terminal using the ratatui
/// permission dialog.
pub struct TerminalQueueReviewer {
    digest_store: Arc<dyn DigestStore>,
    fallback: PollingQueueReviewer,
    stdin_paused: Arc<AtomicBool>,
    output_paused: Arc<AtomicBool>,
    /// PID of the supervised tool's root process, used to send SIGWINCH
    /// after the review dialog so the tool redraws its TUI.
    root_pid: u32,
}

impl TerminalQueueReviewer {
    pub fn new(
        digest_store: Arc<dyn DigestStore>,
        stdin_paused: Arc<AtomicBool>,
        output_paused: Arc<AtomicBool>,
        root_pid: u32,
    ) -> Self {
        let fallback = PollingQueueReviewer::new(digest_store.clone());
        Self {
            digest_store,
            fallback,
            stdin_paused,
            output_paused,
            root_pid,
        }
    }
}

#[async_trait]
impl QueueReviewer for TerminalQueueReviewer {
    async fn review(&self, item: &DigestItem, timeout: Duration) -> ReviewOutcome {
        if std::fs::File::open("/dev/tty").is_err() {
            return self.fallback.review(item, timeout).await;
        }

        // Pause both stdin forwarding and PTY output.
        self.stdin_paused.store(true, Ordering::SeqCst);
        self.output_paused.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Build a PermissionRequest for the ratatui dialog.
        let filters: Vec<grith_cli::tui::state::FilterHit> = item
            .filter_breakdown
            .iter()
            .map(|f| grith_cli::tui::state::FilterHit {
                name: f.filter_name.clone(),
                delta: f.score as f32,
            })
            .collect();

        let severity = match item.composite_score {
            s if s >= 8.0 => "CRITICAL",
            s if s >= 5.0 => "WARNING",
            _ => "INFO",
        };

        // Extract category name (e.g. "ProcessSpawn") from "ProcessSpawn(/path/...)".
        let call_type_category = item
            .tool_call_type
            .find('(')
            .map(|i| &item.tool_call_type[..i])
            .unwrap_or(&item.tool_call_type)
            .to_string();

        let req = grith_cli::tui::state::PermissionRequest {
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
            context: item.task_context.clone().unwrap_or_default(),
            severity: severity.to_string(),
            call_type: call_type_category,
            item_number: 1,
            total_items: 1,
        };

        let digest_store = self.digest_store.clone();
        let item_id = item.id;
        let stdin_paused = self.stdin_paused.clone();
        let output_paused = self.output_paused.clone();
        let root_pid = self.root_pid;

        let handle = tokio::task::spawn_blocking(move || {
            // The outer terminal is in raw mode for PTY passthrough.
            // Disable it so run_review_dialog can manage its own raw mode.
            let _ = crossterm::terminal::disable_raw_mode();

            let action = grith_cli::tui::run_review_dialog(&req);

            let (status, outcome) = match action.unwrap_or("deny") {
                "approve" | "approve_and_learn" => {
                    (DigestStatus::Approved, ReviewOutcome::Approved)
                }
                _ => (DigestStatus::Denied, ReviewOutcome::Denied),
            };

            let action_str = action.unwrap_or("deny");
            let note = format!("{action_str} via TUI dialog");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            if let Ok(rt) = rt {
                let _ = rt.block_on(digest_store.update_status(
                    item_id,
                    status,
                    Some(action_str),
                    Some(&note),
                ));
            }

            // Re-enable raw mode for PTY passthrough.
            let _ = crossterm::terminal::enable_raw_mode();

            // The dialog cleared the screen. The tool was on the alternate
            // screen, so re-enter it so the tool's redraw goes to the right
            // buffer. Then send SIGWINCH to trigger the redraw.
            {
                let mut stdout = std::io::stdout().lock();
                // Re-enter alternate screen for the tool
                let _ = stdout.write_all(b"\x1b[?1049h");
                let _ = stdout.flush();
            }

            // Resume PTY forwarding.
            stdin_paused.store(false, Ordering::SeqCst);
            output_paused.store(false, Ordering::SeqCst);

            // Send SIGWINCH to the tool so it redraws its TUI.
            #[cfg(unix)]
            unsafe {
                libc::kill(root_pid as i32, libc::SIGWINCH);
            }

            outcome
        });

        match handle.await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::error!(error = %e, "terminal review task panicked");
                self.stdin_paused.store(false, Ordering::SeqCst);
                self.output_paused.store(false, Ordering::SeqCst);
                ReviewOutcome::Denied
            }
        }
    }
}
