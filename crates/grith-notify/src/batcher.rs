// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Time-window batching of digest items before notification delivery.

use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use grith_digest::DigestItem;

/// A pending batch entry.
#[derive(Debug, Clone)]
struct BatchEntry {
    item: DigestItem,
    queued_at: DateTime<Utc>,
}

/// Batches low-severity notifications over a configurable time window
/// to avoid notification fatigue.
pub struct Batcher {
    /// Pending items not yet dispatched
    pending: Mutex<Vec<BatchEntry>>,
    /// How long to wait before flushing a batch
    window: Duration,
    /// Maximum batch size before force-flushing
    max_batch_size: usize,
}

impl Batcher {
    pub fn new(window: Duration, max_batch_size: usize) -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
            window,
            max_batch_size,
        }
    }

    /// Add an item to the batch. Returns `true` if the batch should be
    /// flushed immediately (max size reached).
    pub fn add(&self, item: DigestItem) -> bool {
        let mut pending = self.pending.lock().unwrap();
        pending.push(BatchEntry {
            item,
            queued_at: Utc::now(),
        });
        pending.len() >= self.max_batch_size
    }

    /// Check if any pending items have been waiting longer than the window.
    /// Returns items to flush (if any), leaving remaining items in place.
    pub fn flush_ready(&self) -> Vec<DigestItem> {
        let now = Utc::now();
        let mut pending = self.pending.lock().unwrap();

        // Check if oldest entry has exceeded the window
        let should_flush = pending
            .first()
            .map(|e| {
                let elapsed = now.signed_duration_since(e.queued_at);
                elapsed >= chrono::Duration::from_std(self.window).unwrap_or(chrono::TimeDelta::MAX)
            })
            .unwrap_or(false);

        if should_flush || pending.len() >= self.max_batch_size {
            let items: Vec<DigestItem> = pending.iter().map(|e| e.item.clone()).collect();
            pending.clear();
            items
        } else {
            Vec::new()
        }
    }

    /// Force flush all pending items regardless of window.
    pub fn flush_all(&self) -> Vec<DigestItem> {
        let mut pending = self.pending.lock().unwrap();
        let items: Vec<DigestItem> = pending.iter().map(|e| e.item.clone()).collect();
        pending.clear();
        items
    }

    /// Number of items currently batched.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Remove a specific item from the batch (e.g. if it was resolved before
    /// the batch was flushed).
    pub fn remove(&self, item_id: Uuid) -> bool {
        let mut pending = self.pending.lock().unwrap();
        let before = pending.len();
        pending.retain(|e| e.item.id != item_id);
        pending.len() < before
    }

    /// The configured batch window duration.
    pub fn window(&self) -> Duration {
        self.window
    }
}

impl Default for Batcher {
    fn default() -> Self {
        // Default: 5 minute window, max 10 items per batch
        Self::new(Duration::from_secs(300), 10)
    }
}

impl std::fmt::Debug for Batcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Batcher")
            .field("window", &self.window)
            .field("max_batch_size", &self.max_batch_size)
            .field("pending", &self.pending_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grith_digest::types::{DigestStatus, ScoreSeverity};

    fn make_item() -> DigestItem {
        DigestItem {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            session_id: None,
            tool_call_type: "ShellExec".into(),
            arguments_summary: "test".into(),
            composite_score: 4.0,
            severity: ScoreSeverity::Medium,
            filter_breakdown: vec![],
            task_context: None,
            plugin_id: "test".into(),
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
    fn test_add_and_flush_all() {
        let batcher = Batcher::new(Duration::from_secs(300), 10);
        batcher.add(make_item());
        batcher.add(make_item());
        assert_eq!(batcher.pending_count(), 2);

        let items = batcher.flush_all();
        assert_eq!(items.len(), 2);
        assert_eq!(batcher.pending_count(), 0);
    }

    #[test]
    fn test_max_batch_triggers_flush() {
        let batcher = Batcher::new(Duration::from_secs(300), 2);
        assert!(!batcher.add(make_item()));
        assert!(batcher.add(make_item())); // returns true: max reached
    }

    #[test]
    fn test_remove() {
        let batcher = Batcher::new(Duration::from_secs(300), 10);
        let item = make_item();
        let id = item.id;
        batcher.add(item);
        batcher.add(make_item());

        assert!(batcher.remove(id));
        assert_eq!(batcher.pending_count(), 1);
        assert!(!batcher.remove(id)); // already removed
    }

    #[test]
    fn test_flush_ready_not_expired() {
        let batcher = Batcher::new(Duration::from_secs(300), 10);
        batcher.add(make_item());

        // Window hasn't elapsed
        let items = batcher.flush_ready();
        assert!(items.is_empty());
        assert_eq!(batcher.pending_count(), 1);
    }
}
