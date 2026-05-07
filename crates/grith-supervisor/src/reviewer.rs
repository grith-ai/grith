// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Queue reviewer abstraction for digest items awaiting human review.
//!
//! The [`QueueReviewer`] trait decouples the supervisor event loop from the
//! mechanism used to solicit and wait for review decisions. Two built-in
//! implementations are provided:
//!
//! - [`PollingQueueReviewer`] — polls the [`DigestQueue`] for status changes
//!   (used by the dashboard HTTP API workflow).
//! - `TerminalQueueReviewer` (in grith-core) — prompts the user interactively
//!   on the terminal when no dashboard is running.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use uuid::Uuid;

use grith_digest::types::{DigestItem, DigestStatus, ReviewOutcome};
use grith_digest::DigestQueue;

/// Async abstraction over the digest queue backend used by the supervisor.
#[async_trait]
pub trait DigestStore: Send + Sync {
    async fn enqueue(&self, item: &DigestItem) -> std::result::Result<(), String>;
    async fn get(&self, item_id: Uuid) -> std::result::Result<Option<DigestItem>, String>;
    async fn update_status(
        &self,
        item_id: Uuid,
        status: DigestStatus,
        review_action: Option<&str>,
        reviewer_notes: Option<&str>,
    ) -> std::result::Result<(), String>;
}

/// Local `DigestStore` backed by the on-disk SQLite digest queue.
pub struct LocalDigestStore {
    digest_queue: Arc<DigestQueue>,
}

impl LocalDigestStore {
    pub fn new(digest_queue: Arc<DigestQueue>) -> Self {
        Self { digest_queue }
    }

    pub fn queue(&self) -> Arc<DigestQueue> {
        Arc::clone(&self.digest_queue)
    }
}

#[async_trait]
impl DigestStore for LocalDigestStore {
    async fn enqueue(&self, item: &DigestItem) -> std::result::Result<(), String> {
        self.digest_queue.enqueue(item).map_err(|e| e.to_string())
    }

    async fn get(&self, item_id: Uuid) -> std::result::Result<Option<DigestItem>, String> {
        Ok(self.digest_queue.get_by_id(&item_id).ok())
    }

    async fn update_status(
        &self,
        item_id: Uuid,
        status: DigestStatus,
        review_action: Option<&str>,
        reviewer_notes: Option<&str>,
    ) -> std::result::Result<(), String> {
        self.digest_queue
            .update_status(&item_id, status, review_action, reviewer_notes)
            .map_err(|e| e.to_string())
    }
}

/// Trait for reviewing queued digest items.
///
/// Implementations receive the full [`DigestItem`] and a timeout, and must
/// return a [`ReviewOutcome`]. The implementation is responsible for updating
/// the [`DigestQueue`] status so that side-effects (approve_and_learn, etc.)
/// can read the stored `review_action`.
#[async_trait]
pub trait QueueReviewer: Send + Sync {
    async fn review(&self, item: &DigestItem, timeout: Duration) -> ReviewOutcome;
}

/// Polls the [`DigestQueue`] for status changes at 250ms intervals.
///
/// This is the default reviewer used when no interactive terminal is available
/// (e.g., dashboard-driven sessions). It reproduces the original polling
/// behaviour that existed before the `QueueReviewer` trait was introduced.
pub struct PollingQueueReviewer {
    digest_store: Arc<dyn DigestStore>,
}

impl PollingQueueReviewer {
    pub fn new(digest_store: Arc<dyn DigestStore>) -> Self {
        Self { digest_store }
    }
}

#[async_trait]
impl QueueReviewer for PollingQueueReviewer {
    async fn review(&self, item: &DigestItem, timeout: Duration) -> ReviewOutcome {
        let item_id = item.id;
        let digest_store = self.digest_store.clone();

        let handle =
            tokio::spawn(async move { poll_digest_status(digest_store, item_id, timeout).await });

        match handle.await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::error!(error = %e, "digest review polling task panicked");
                ReviewOutcome::Denied
            }
        }
    }
}

/// Internal polling loop for digest review status.
async fn poll_digest_status(
    digest_store: Arc<dyn DigestStore>,
    item_id: Uuid,
    timeout: Duration,
) -> ReviewOutcome {
    let start = Instant::now();

    loop {
        if start.elapsed() >= timeout {
            let now = chrono::Utc::now().to_rfc3339();
            if let Err(e) = digest_store
                .update_status(
                    item_id,
                    DigestStatus::Denied,
                    Some("auto_deny_timeout"),
                    Some(&format!("auto denied after timeout at {now}")),
                )
                .await
            {
                tracing::error!(
                    error = %e,
                    item_id = %item_id,
                    "failed to update digest status to Denied on timeout"
                );
            }
            return ReviewOutcome::TimedOut;
        }

        let status = match digest_store.get(item_id).await {
            Ok(Some(item)) => Some(item.status),
            Ok(None) => None,
            Err(e) => {
                tracing::error!(error = %e, item_id = %item_id, "failed to read digest item");
                None
            }
        };

        match status {
            Some(DigestStatus::Approved) => return ReviewOutcome::Approved,
            Some(DigestStatus::Denied) | Some(DigestStatus::Expired) => {
                return ReviewOutcome::Denied
            }
            Some(DigestStatus::Pending) | Some(DigestStatus::Escalated) => {}
            None => return ReviewOutcome::Denied,
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
