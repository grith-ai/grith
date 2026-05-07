// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Periodic and on-demand delivery scheduling for digest batches.
//!
//! The scheduler supports two modes:
//! - **Active mode**: delivers at `active_interval` (default 30 min).
//! - **Idle mode**: delivers at `idle_interval` (default 24 h) after
//!   `idle_timeout` (default 1 h) of no digest activity.
//!
//! Call [`DigestScheduler::notify_activity`] when new items are enqueued or
//! reviewed to keep the scheduler in active mode (or wake it from idle).

use crate::delivery::DigestDelivery;
use crate::queue::DigestQueue;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Configuration for the digest scheduler.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Delivery interval when user is active (default: 30 minutes).
    pub active_interval: Duration,
    /// Delivery interval when user is idle (default: 24 hours).
    pub idle_interval: Duration,
    /// Time without interaction before switching to idle (default: 1 hour).
    pub idle_timeout: Duration,
    /// Maximum queue size before forced delivery.
    pub max_queue_size: usize,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            active_interval: Duration::from_secs(30 * 60),
            idle_interval: Duration::from_secs(24 * 60 * 60),
            idle_timeout: Duration::from_secs(60 * 60),
            max_queue_size: 100,
        }
    }
}

/// Manages digest delivery timing with idle detection.
pub struct DigestScheduler {
    config: SchedulerConfig,
    /// Notifier for immediate delivery.
    immediate: Arc<Notify>,
    /// Notifier for digest activity (enqueue, review, etc.).
    activity: Arc<Notify>,
    /// Shutdown signal.
    shutdown: Arc<Notify>,
}

impl DigestScheduler {
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            config,
            immediate: Arc::new(Notify::new()),
            activity: Arc::new(Notify::new()),
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Trigger immediate delivery (e.g., for high-priority items or queue overflow).
    pub fn trigger_immediate(&self) {
        self.immediate.notify_one();
    }

    /// Signal that digest activity occurred (item enqueued, reviewed, etc.).
    ///
    /// Resets the idle timer. If the scheduler is in idle mode, this wakes it
    /// and transitions back to active mode.
    pub fn notify_activity(&self) {
        self.activity.notify_one();
    }

    /// Signal shutdown.
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// Run the scheduler loop. Should be spawned as a tokio task.
    pub async fn run(&self, queue: Arc<DigestQueue>, delivery: Arc<dyn DigestDelivery>) {
        let max_size = self.config.max_queue_size;
        let active_interval = self.config.active_interval;
        let idle_interval = self.config.idle_interval;
        let idle_timeout = self.config.idle_timeout;

        let mut last_activity_at = tokio::time::Instant::now();
        let mut idle = false;

        loop {
            let interval = if idle { idle_interval } else { active_interval };

            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    let delivered = self.deliver_pending(&queue, delivery.as_ref()).await;
                    if delivered {
                        last_activity_at = tokio::time::Instant::now();
                        if idle {
                            idle = false;
                            tracing::info!("digest scheduler switching to active mode (items delivered)");
                        }
                    }
                }
                _ = self.activity.notified() => {
                    last_activity_at = tokio::time::Instant::now();
                    if idle {
                        idle = false;
                        tracing::info!("digest scheduler switching to active mode (activity notified)");
                    }
                    // Deliver immediately on activity to keep latency low.
                    self.deliver_pending(&queue, delivery.as_ref()).await;
                }
                _ = self.immediate.notified() => {
                    self.deliver_pending(&queue, delivery.as_ref()).await;
                }
                _ = self.shutdown.notified() => {
                    tracing::info!("digest scheduler shutting down");
                    // Final delivery before shutdown
                    self.deliver_pending(&queue, delivery.as_ref()).await;
                    break;
                }
            }

            // Check for idle transition
            if !idle && last_activity_at.elapsed() >= idle_timeout {
                idle = true;
                tracing::info!(
                    idle_interval_secs = idle_interval.as_secs(),
                    "digest scheduler switching to idle mode (no activity for {}s)",
                    idle_timeout.as_secs()
                );
            }

            // Check for queue overflow
            if let Ok(count) = queue.count_pending() {
                if count >= max_size {
                    tracing::info!(count, max_size, "queue overflow, forcing delivery");
                    self.deliver_pending(&queue, delivery.as_ref()).await;
                }
            }
        }
    }

    /// Deliver pending items. Returns `true` if items were actually delivered.
    async fn deliver_pending(
        &self,
        queue: &DigestQueue,
        delivery: &(dyn DigestDelivery + '_),
    ) -> bool {
        let items = queue.get_pending(self.config.max_queue_size, 0).ok();

        match items {
            Some(items) if !items.is_empty() => {
                tracing::info!(
                    count = items.len(),
                    channel = delivery.name(),
                    "delivering digest"
                );
                if let Err(e) = delivery.deliver(&items) {
                    tracing::error!(error = %e, "digest delivery failed");
                }
                true
            }
            Some(_) => false,
            None => {
                tracing::error!("failed to fetch pending digest items");
                false
            }
        }
    }

    /// Check if queue has exceeded max size (for external callers).
    pub fn should_force_delivery(&self, queue: &DigestQueue) -> bool {
        queue
            .count_pending()
            .map(|c| c >= self.config.max_queue_size)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::CliDelivery;
    use crate::types::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_item(score: f64) -> DigestItem {
        DigestItem {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            session_id: None,
            tool_call_type: "FileRead".into(),
            arguments_summary: "test".into(),
            composite_score: score,
            severity: ScoreSeverity::from_score(score),
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
    fn test_scheduler_config_defaults() {
        let config = SchedulerConfig::default();
        assert_eq!(config.active_interval, Duration::from_secs(30 * 60));
        assert_eq!(config.idle_interval, Duration::from_secs(24 * 60 * 60));
        assert_eq!(config.idle_timeout, Duration::from_secs(60 * 60));
        assert_eq!(config.max_queue_size, 100);
    }

    #[test]
    fn test_should_force_delivery() {
        let queue = DigestQueue::open_in_memory().unwrap();
        let config = SchedulerConfig {
            max_queue_size: 3,
            ..Default::default()
        };
        let scheduler = DigestScheduler::new(config);

        assert!(!scheduler.should_force_delivery(&queue));

        for _ in 0..3 {
            queue.enqueue(&make_item(5.0)).unwrap();
        }
        assert!(scheduler.should_force_delivery(&queue));
    }

    #[tokio::test]
    async fn test_immediate_trigger() {
        let queue = Arc::new(DigestQueue::open_in_memory().unwrap());
        queue.enqueue(&make_item(5.0)).unwrap();

        let config = SchedulerConfig {
            active_interval: Duration::from_secs(3600), // Long interval
            ..Default::default()
        };
        let scheduler = DigestScheduler::new(config);

        // Trigger immediate then shutdown
        let shutdown = scheduler.shutdown.clone();
        let immediate = scheduler.immediate.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            immediate.notify_one();
            tokio::time::sleep(Duration::from_millis(50)).await;
            shutdown.notify_one();
        });

        scheduler.run(queue, Arc::new(CliDelivery)).await;
    }

    #[tokio::test]
    async fn test_scheduler_transitions_to_idle_after_timeout() {
        // Use very short durations to make the test fast.
        tokio::time::pause();

        let queue = Arc::new(DigestQueue::open_in_memory().unwrap());
        let config = SchedulerConfig {
            active_interval: Duration::from_millis(100),
            idle_interval: Duration::from_secs(10),
            idle_timeout: Duration::from_millis(300),
            max_queue_size: 100,
        };
        let scheduler = DigestScheduler::new(config);
        let shutdown = scheduler.shutdown.clone();

        // Track deliveries via a counting delivery channel.
        let delivery = Arc::new(CountingDelivery::new());
        let delivery_clone = Arc::clone(&delivery);

        let handle = tokio::spawn(async move {
            scheduler.run(queue, delivery_clone).await;
        });

        // Let the scheduler run through several active-mode ticks with no
        // pending items (no activity). After idle_timeout (300ms) it should
        // switch to idle mode and sleep for idle_interval (10s).
        // Advance past the idle_timeout boundary.
        tokio::time::advance(Duration::from_millis(500)).await;
        tokio::task::yield_now().await;

        // Now the scheduler should be in idle mode, sleeping for 10s.
        // Record the delivery count, then advance only 1s (less than idle_interval).
        let count_before = delivery.count();
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        let count_after = delivery.count();

        // No additional deliveries should have happened in 1s because
        // idle_interval is 10s.
        assert_eq!(
            count_before, count_after,
            "scheduler should not have delivered during idle sleep"
        );

        shutdown.notify_one();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_activity_switches_scheduler_back_to_active() {
        tokio::time::pause();

        let queue = Arc::new(DigestQueue::open_in_memory().unwrap());
        let config = SchedulerConfig {
            active_interval: Duration::from_millis(100),
            idle_interval: Duration::from_secs(60),
            idle_timeout: Duration::from_millis(300),
            max_queue_size: 100,
        };
        let scheduler = DigestScheduler::new(config);
        let shutdown = scheduler.shutdown.clone();
        let activity = scheduler.activity.clone();
        let delivery = Arc::new(CountingDelivery::new());
        let delivery_clone = Arc::clone(&delivery);

        let q = Arc::clone(&queue);
        let handle = tokio::spawn(async move {
            scheduler.run(q, delivery_clone).await;
        });

        // Let the scheduler go idle (advance past idle_timeout).
        tokio::time::advance(Duration::from_millis(500)).await;
        tokio::task::yield_now().await;

        // Now enqueue an item and signal activity.
        queue.enqueue(&make_item(5.0)).unwrap();
        activity.notify_one();
        // Allow the scheduler to wake and process the activity notification.
        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;

        // The scheduler should have switched back to active mode and delivered.
        // Advance by active_interval to trigger the next tick.
        let count_before = delivery.count();
        tokio::time::advance(Duration::from_millis(110)).await;
        tokio::task::yield_now().await;

        // The scheduler should have ticked at active_interval (not idle_interval),
        // confirming it's back in active mode.
        let count_after = delivery.count();
        assert!(
            count_after > count_before,
            "scheduler should have delivered after returning to active mode \
             (before={count_before}, after={count_after})"
        );

        shutdown.notify_one();
        handle.await.unwrap();
    }

    /// A delivery channel that counts how many times `deliver` is called.
    struct CountingDelivery {
        count: std::sync::atomic::AtomicUsize,
    }

    impl CountingDelivery {
        fn new() -> Self {
            Self {
                count: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn count(&self) -> usize {
            self.count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl crate::delivery::DigestDelivery for CountingDelivery {
        fn deliver(&self, _items: &[DigestItem]) -> crate::error::Result<()> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn name(&self) -> &str {
            "counting"
        }
    }
}
