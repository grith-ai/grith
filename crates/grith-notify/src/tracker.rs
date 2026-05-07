// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Notification delivery tracking and acknowledgment state management.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use grith_digest::notification::NotificationEvent;

/// Per-channel delivery status for a single digest item.
#[derive(Debug, Clone)]
pub struct ChannelDelivery {
    pub channel_id: String,
    pub external_id: Option<String>,
    pub sent_at: DateTime<Utc>,
    pub delivered: bool,
    pub error: Option<String>,
}

/// Tracks delivery status and events across all channels for all items.
pub struct DeliveryTracker {
    /// item_id → list of per-channel delivery records
    deliveries: Mutex<HashMap<Uuid, Vec<ChannelDelivery>>>,
    /// Recent notification events (ring buffer using VecDeque for O(1) pop_front).
    events: Mutex<VecDeque<NotificationEvent>>,
    max_events: usize,
}

impl DeliveryTracker {
    pub fn new(max_events: usize) -> Self {
        Self {
            deliveries: Mutex::new(HashMap::new()),
            events: Mutex::new(VecDeque::new()),
            max_events,
        }
    }

    /// Record a successful delivery to a channel.
    pub fn record_sent(&self, item_id: Uuid, channel_id: &str, external_id: Option<String>) {
        let delivery = ChannelDelivery {
            channel_id: channel_id.to_string(),
            external_id: external_id.clone(),
            sent_at: Utc::now(),
            delivered: true,
            error: None,
        };

        if let Ok(mut map) = self.deliveries.lock() {
            map.entry(item_id).or_default().push(delivery);
        }

        self.push_event(NotificationEvent::sent(item_id, channel_id, external_id));
    }

    /// Record a failed delivery to a channel.
    pub fn record_failed(&self, item_id: Uuid, channel_id: &str, error: &str) {
        let delivery = ChannelDelivery {
            channel_id: channel_id.to_string(),
            external_id: None,
            sent_at: Utc::now(),
            delivered: false,
            error: Some(error.to_string()),
        };

        if let Ok(mut map) = self.deliveries.lock() {
            map.entry(item_id).or_default().push(delivery);
        }

        self.push_event(NotificationEvent::failed(item_id, channel_id, error));
    }

    /// Record an interactive response from a channel.
    pub fn record_interactive_response(
        &self,
        item_id: Uuid,
        channel_id: &str,
        action: grith_digest::ReviewAction,
        reviewer: &str,
    ) {
        self.push_event(NotificationEvent::interactive_response(
            item_id, channel_id, action, reviewer,
        ));
    }

    /// Get delivery records for an item.
    pub fn get_deliveries(&self, item_id: Uuid) -> Vec<ChannelDelivery> {
        self.deliveries
            .lock()
            .ok()
            .and_then(|map| map.get(&item_id).cloned())
            .unwrap_or_default()
    }

    /// Get the channel ids that an item was successfully sent to.
    pub fn sent_channels(&self, item_id: Uuid) -> Vec<String> {
        self.get_deliveries(item_id)
            .iter()
            .filter(|d| d.delivered)
            .map(|d| d.channel_id.clone())
            .collect()
    }

    /// Get recent notification events (newest last).
    pub fn recent_events(&self, limit: usize) -> Vec<NotificationEvent> {
        self.events
            .lock()
            .ok()
            .map(|events| {
                let start = events.len().saturating_sub(limit);
                events.iter().skip(start).cloned().collect()
            })
            .unwrap_or_default()
    }

    /// Remove tracking data for items older than the given cutoff.
    pub fn cleanup_before(&self, cutoff: DateTime<Utc>) {
        if let Ok(mut map) = self.deliveries.lock() {
            map.retain(|_, deliveries| deliveries.iter().any(|d| d.sent_at >= cutoff));
        }
    }

    fn push_event(&self, event: NotificationEvent) {
        if let Ok(mut events) = self.events.lock() {
            if events.len() >= self.max_events {
                events.pop_front(); // O(1) with VecDeque
            }
            events.push_back(event);
        }
    }
}

impl Default for DeliveryTracker {
    fn default() -> Self {
        Self::new(1000)
    }
}

impl std::fmt::Debug for DeliveryTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let item_count = self.deliveries.lock().map(|m| m.len()).unwrap_or(0);
        let event_count = self.events.lock().map(|e| e.len()).unwrap_or(0);
        f.debug_struct("DeliveryTracker")
            .field("tracked_items", &item_count)
            .field("events", &event_count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_sent() {
        let tracker = DeliveryTracker::new(100);
        let id = Uuid::new_v4();

        tracker.record_sent(id, "slack", Some("msg_123".into()));
        tracker.record_sent(id, "telegram", None);

        let deliveries = tracker.get_deliveries(id);
        assert_eq!(deliveries.len(), 2);
        assert!(deliveries[0].delivered);

        let channels = tracker.sent_channels(id);
        assert_eq!(channels.len(), 2);
    }

    #[test]
    fn test_record_failed() {
        let tracker = DeliveryTracker::new(100);
        let id = Uuid::new_v4();

        tracker.record_failed(id, "email", "SMTP timeout");

        let deliveries = tracker.get_deliveries(id);
        assert_eq!(deliveries.len(), 1);
        assert!(!deliveries[0].delivered);
        assert_eq!(deliveries[0].error.as_deref(), Some("SMTP timeout"));
    }

    #[test]
    fn test_events_ring_buffer() {
        let tracker = DeliveryTracker::new(3);

        for i in 0..5 {
            tracker.record_sent(Uuid::new_v4(), &format!("ch-{i}"), None);
        }

        let events = tracker.recent_events(10);
        assert_eq!(events.len(), 3); // capped at max_events
    }

    #[test]
    fn test_recent_events_limit() {
        let tracker = DeliveryTracker::new(100);

        for _ in 0..10 {
            tracker.record_sent(Uuid::new_v4(), "slack", None);
        }

        let events = tracker.recent_events(3);
        assert_eq!(events.len(), 3);
    }
}
