// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Notification channel trait and types for real-time digest delivery.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{DigestItem, ReviewAction};

// ---------------------------------------------------------------------------
// PlanTier
// ---------------------------------------------------------------------------

/// License plan tier controlling which notification channels are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanTier {
    Community,
    Pro,
    Enterprise,
}

impl PlanTier {
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pro" => Self::Pro,
            "enterprise" => Self::Enterprise,
            _ => Self::Community,
        }
    }
}

impl std::fmt::Display for PlanTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Community => write!(f, "community"),
            Self::Pro => write!(f, "pro"),
            Self::Enterprise => write!(f, "enterprise"),
        }
    }
}

// ---------------------------------------------------------------------------
// FeatureGate
// ---------------------------------------------------------------------------

/// Controls feature access and session limits based on license tier.
#[derive(Debug, Clone)]
pub struct FeatureGate {
    pub tier: PlanTier,
    pub seats: u32,
}

impl FeatureGate {
    /// Check whether a named feature is allowed for this tier.
    pub fn allows(&self, feature: &str) -> bool {
        match feature {
            // Core features available to all tiers
            "proxy" | "audit" | "digest" | "supervisor" | "filters" | "cli" | "dashboard" => true,

            // Pro features
            "adaptive_scoring"
            | "notification_channels"
            | "usage_analytics"
            | "cloud_sync"
            | "extended_retention"
            | "policy_editor" => self.tier >= PlanTier::Pro,

            // Enterprise features
            "pagerduty" | "opsgenie" | "team_scope" | "sso" | "custom_filters" => {
                self.tier >= PlanTier::Enterprise
            }

            // Unknown features are denied
            _ => false,
        }
    }

    /// Maximum concurrent supervisor sessions allowed by the license.
    ///
    /// Community: 2, Pro: seats * 4 (min 4), Enterprise: seats * 8 (min 8).
    pub fn max_sessions(&self) -> usize {
        match self.tier {
            PlanTier::Community => 2,
            PlanTier::Pro => (self.seats as usize * 4).max(4),
            PlanTier::Enterprise => (self.seats as usize * 8).max(8),
        }
    }

    /// Return a list of (feature_name, is_enabled) pairs for API exposure.
    pub fn feature_list(&self) -> Vec<(&'static str, bool)> {
        let features = [
            "proxy",
            "audit",
            "digest",
            "supervisor",
            "filters",
            "cli",
            "dashboard",
            "adaptive_scoring",
            "notification_channels",
            "usage_analytics",
            "cloud_sync",
            "extended_retention",
            "policy_editor",
            "pagerduty",
            "opsgenie",
            "team_scope",
            "sso",
            "custom_filters",
        ];
        features.iter().map(|&f| (f, self.allows(f))).collect()
    }
}

// ---------------------------------------------------------------------------
// License refresh state
// ---------------------------------------------------------------------------

/// Category of refresh failure. Used by the daemon to drive its hard/transient
/// response policy and surface a stable label to operators.
///
/// Defined here (alongside [`FeatureGate`]) so both the daemon (`grith-core`)
/// and the API server (`grith-server`) — which don't share a higher crate —
/// can reference the same type without a cyclic dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshFailureKind {
    /// Network, DNS, TLS, or 5xx. Retry with backoff.
    Transient,
    /// Server explicitly returned `valid:false` for an active subscription.
    Revoked,
    /// 401/403 from the API.
    Unauthorized,
    /// Server replied 2xx but the response shape was unexpected.
    Protocol,
}

impl RefreshFailureKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Revoked => "revoked",
            Self::Unauthorized => "unauthorized",
            Self::Protocol => "protocol",
        }
    }
}

/// Snapshot of the daemon's licence-refresh state. Used by /api/license/status
/// and by `grith pro status` to surface health to operators without leaking
/// API keys or signed bytes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RefreshState {
    /// RFC3339 timestamp of the last successful refresh, if any.
    pub last_success: Option<String>,
    /// RFC3339 timestamp of the last failed refresh, if any.
    pub last_failure: Option<String>,
    /// Stable category of the last failure.
    pub last_failure_kind: Option<RefreshFailureKind>,
    /// Sanitized human-readable reason returned by the server.
    pub last_failure_reason: Option<String>,
    /// RFC3339 timestamp of the next scheduled refresh attempt.
    pub next_attempt: Option<String>,
    /// True when the licence carries `air_gapped:true`; scheduled refresh disabled.
    pub air_gapped: bool,
    /// Counter of successful refreshes since daemon start.
    pub successes_total: u64,
    /// Counter of failed refreshes since daemon start.
    pub failures_total: u64,
}

// ---------------------------------------------------------------------------
// NotifyResult / ChannelHealth / CallbackPayload
// ---------------------------------------------------------------------------

/// Result of sending a notification to a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyResult {
    /// Channel-specific external message identifier (e.g. Slack message_ts).
    pub external_id: Option<String>,
    /// Whether delivery was confirmed.
    pub delivered: bool,
}

/// Health status of a notification channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelHealth {
    /// Whether the channel is currently connected / reachable.
    pub connected: bool,
    /// Round-trip latency of the last health probe in milliseconds.
    pub latency_ms: Option<u64>,
    /// Human-readable error if not connected.
    pub error: Option<String>,
}

/// Payload received from an interactive callback (Slack button, Telegram
/// inline keyboard, webhook POST, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackPayload {
    /// The digest item UUID this callback is for.
    pub item_id: Uuid,
    /// The review action the user selected.
    pub action: ReviewAction,
    /// Identifier of the reviewer (channel-specific username/id).
    pub reviewer: String,
    /// Optional reviewer notes.
    pub notes: Option<String>,
    /// One-time nonce proving this callback is legitimate.
    pub nonce: String,
    /// Which notification channel sent this callback.
    pub channel_id: String,
    /// Numeric user ID from the channel (e.g. Telegram user ID) for
    /// authorization checks.
    #[serde(default)]
    pub user_id: Option<i64>,
}

// ---------------------------------------------------------------------------
// NotificationChannel trait
// ---------------------------------------------------------------------------

/// Async trait implemented by every notification channel.
///
/// This extends the concept of the existing sync `DigestDelivery` trait but is
/// fully async and supports interactive (two-way) channels.
#[async_trait::async_trait]
pub trait NotificationChannel: Send + Sync {
    /// Unique identifier for this channel (e.g. "slack", "telegram").
    fn id(&self) -> &str;

    /// Human-readable display name (e.g. "Slack", "Telegram Bot").
    fn display_name(&self) -> &str;

    /// Minimum plan tier required to use this channel.
    fn required_tier(&self) -> PlanTier;

    /// Whether this channel supports interactive approve/deny callbacks.
    fn supports_interactive(&self) -> bool;

    /// Send a notification about a new permission request (queued digest item).
    ///
    /// Interactive channels receive a `Some(nonce)` that must be embedded in
    /// callback payloads (buttons, URLs) so the dispatcher can verify authenticity.
    /// Non-interactive channels receive `None` and should ignore the parameter.
    async fn notify_permission_request(
        &self,
        item: &DigestItem,
        nonce: Option<&str>,
    ) -> Result<NotifyResult, Error>;

    /// Notify that a previously-queued item has been resolved (approved/denied).
    /// Channels should update or edit the original message where possible.
    async fn notify_resolution(&self, item: &DigestItem) -> Result<(), Error>;

    /// Send an escalation notification (higher urgency than the original).
    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error>;

    /// Handle an inbound interactive callback from this channel.
    /// Returns `Some(action)` if the callback was valid and an action should be
    /// applied, or `None` if the callback was invalid / already consumed.
    async fn handle_callback(
        &self,
        payload: &CallbackPayload,
    ) -> Result<Option<ReviewAction>, Error>;

    /// Probe whether the channel is reachable and healthy.
    async fn health_check(&self) -> Result<ChannelHealth, Error>;
}

// ---------------------------------------------------------------------------
// CallbackNonceStore
// ---------------------------------------------------------------------------

struct NonceEntry {
    item_id: Uuid,
    // Stored for diagnostics and future per-channel nonce queries.
    #[allow(dead_code)]
    channel_id: String,
    created_at: Instant,
    ttl: Duration,
    consumed: bool,
}

/// Thread-safe store for one-time callback nonces.
///
/// Each interactive notification generates a unique nonce that must be
/// presented in the callback to prove authenticity. Nonces expire after a
/// configurable TTL and can only be consumed once.
pub struct CallbackNonceStore {
    entries: DashMap<String, NonceEntry>,
    default_ttl: Duration,
}

impl CallbackNonceStore {
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            default_ttl,
        }
    }

    /// Generate a nonce for the given item and channel.
    /// Returns the nonce string (a UUID v4).
    pub fn generate(&self, item_id: Uuid, channel_id: &str) -> String {
        self.generate_with_ttl(item_id, channel_id, self.default_ttl)
    }

    /// Generate a nonce with a custom TTL.
    pub fn generate_with_ttl(&self, item_id: Uuid, channel_id: &str, ttl: Duration) -> String {
        let nonce = Uuid::new_v4().to_string();
        self.entries.insert(
            nonce.clone(),
            NonceEntry {
                item_id,
                channel_id: channel_id.to_string(),
                created_at: Instant::now(),
                ttl,
                consumed: false,
            },
        );
        nonce
    }

    /// Validate and consume a nonce. Returns `true` if the nonce was valid,
    /// belonged to the expected item and channel, and had not yet been consumed
    /// or expired.
    pub fn validate_and_consume(&self, item_id: Uuid, nonce: &str, channel_id: &str) -> bool {
        if let Some(mut entry) = self.entries.get_mut(nonce) {
            if entry.consumed {
                return false;
            }
            if entry.item_id != item_id {
                return false;
            }
            if entry.channel_id != channel_id {
                return false;
            }
            if entry.created_at.elapsed() > entry.ttl {
                return false;
            }
            entry.consumed = true;
            true
        } else {
            false
        }
    }

    /// Remove all expired or consumed entries. Call periodically to reclaim
    /// memory.
    pub fn cleanup(&self) {
        self.entries
            .retain(|_, entry| !entry.consumed && entry.created_at.elapsed() <= entry.ttl);
    }

    /// Number of entries currently stored (including expired/consumed).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl std::fmt::Debug for CallbackNonceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackNonceStore")
            .field("entries", &self.entries.len())
            .field("default_ttl", &self.default_ttl)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// NotificationEvent (audit / tracking)
// ---------------------------------------------------------------------------

/// Events emitted during notification delivery for audit and tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NotificationEvent {
    /// Notification was submitted to the channel.
    Sent {
        item_id: Uuid,
        channel_id: String,
        external_id: Option<String>,
        timestamp: DateTime<Utc>,
    },
    /// Channel confirmed delivery (if applicable).
    Delivered {
        item_id: Uuid,
        channel_id: String,
        timestamp: DateTime<Utc>,
    },
    /// Delivery failed.
    Failed {
        item_id: Uuid,
        channel_id: String,
        error: String,
        timestamp: DateTime<Utc>,
    },
    /// An interactive response was received from this channel.
    InteractiveResponse {
        item_id: Uuid,
        channel_id: String,
        action: ReviewAction,
        reviewer: String,
        timestamp: DateTime<Utc>,
    },
}

impl NotificationEvent {
    pub fn sent(item_id: Uuid, channel_id: &str, external_id: Option<String>) -> Self {
        Self::Sent {
            item_id,
            channel_id: channel_id.to_string(),
            external_id,
            timestamp: Utc::now(),
        }
    }

    pub fn delivered(item_id: Uuid, channel_id: &str) -> Self {
        Self::Delivered {
            item_id,
            channel_id: channel_id.to_string(),
            timestamp: Utc::now(),
        }
    }

    pub fn failed(item_id: Uuid, channel_id: &str, error: impl Into<String>) -> Self {
        Self::Failed {
            item_id,
            channel_id: channel_id.to_string(),
            error: error.into(),
            timestamp: Utc::now(),
        }
    }

    pub fn interactive_response(
        item_id: Uuid,
        channel_id: &str,
        action: ReviewAction,
        reviewer: impl Into<String>,
    ) -> Self {
        Self::InteractiveResponse {
            item_id,
            channel_id: channel_id.to_string(),
            action,
            reviewer: reviewer.into(),
            timestamp: Utc::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors specific to the notification subsystem.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("channel {0} is not available on the {1} plan tier")]
    TierRestriction(String, PlanTier),

    #[error("channel {0} is not enabled")]
    ChannelDisabled(String),

    #[error("channel {0} is not configured")]
    ChannelNotConfigured(String),

    #[error("channel {0} is not healthy: {1}")]
    ChannelUnhealthy(String, String),

    #[error("callback nonce is invalid or expired")]
    InvalidNonce,

    #[error("callback item {0} is no longer actionable")]
    ItemNotActionable(Uuid),

    #[error("rate limited on channel {0}: next allowed in {1:?}")]
    RateLimited(String, Duration),

    #[error("delivery failed on channel {0}: {1}")]
    DeliveryFailed(String, String),

    #[error("http error: {0}")]
    Http(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// ChannelInfo (for listing/display)
// ---------------------------------------------------------------------------

/// Summary information about a registered notification channel, suitable for
/// API responses and CLI display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub id: String,
    pub display_name: String,
    pub required_tier: PlanTier,
    pub supports_interactive: bool,
    pub enabled: bool,
    pub health: Option<ChannelHealth>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_tier_ordering() {
        assert!(PlanTier::Community < PlanTier::Pro);
        assert!(PlanTier::Pro < PlanTier::Enterprise);
    }

    #[test]
    fn test_plan_tier_from_str_lossy() {
        assert_eq!(PlanTier::from_str_lossy("community"), PlanTier::Community);
        assert_eq!(PlanTier::from_str_lossy("pro"), PlanTier::Pro);
        assert_eq!(PlanTier::from_str_lossy("PRO"), PlanTier::Pro);
        assert_eq!(PlanTier::from_str_lossy("Enterprise"), PlanTier::Enterprise);
        assert_eq!(PlanTier::from_str_lossy("unknown"), PlanTier::Community);
    }

    #[test]
    fn test_plan_tier_display() {
        assert_eq!(PlanTier::Community.to_string(), "community");
        assert_eq!(PlanTier::Pro.to_string(), "pro");
        assert_eq!(PlanTier::Enterprise.to_string(), "enterprise");
    }

    #[test]
    fn test_nonce_store_generate_and_validate() {
        let store = CallbackNonceStore::new(Duration::from_secs(300));
        let item_id = Uuid::new_v4();
        let nonce = store.generate(item_id, "slack");

        assert_eq!(store.len(), 1);
        assert!(store.validate_and_consume(item_id, &nonce, "slack"));
        // Cannot consume again
        assert!(!store.validate_and_consume(item_id, &nonce, "slack"));
    }

    #[test]
    fn test_nonce_store_wrong_item() {
        let store = CallbackNonceStore::new(Duration::from_secs(300));
        let item_id = Uuid::new_v4();
        let wrong_id = Uuid::new_v4();
        let nonce = store.generate(item_id, "telegram");

        assert!(!store.validate_and_consume(wrong_id, &nonce, "telegram"));
        // Original item can still consume
        assert!(store.validate_and_consume(item_id, &nonce, "telegram"));
    }

    #[test]
    fn test_nonce_store_wrong_channel() {
        let store = CallbackNonceStore::new(Duration::from_secs(300));
        let item_id = Uuid::new_v4();
        let nonce = store.generate(item_id, "slack");

        // Wrong channel should fail
        assert!(!store.validate_and_consume(item_id, &nonce, "telegram"));
        // Correct channel should still work (nonce not consumed by wrong channel)
        assert!(store.validate_and_consume(item_id, &nonce, "slack"));
    }

    #[test]
    fn test_nonce_store_expired() {
        let store = CallbackNonceStore::new(Duration::from_secs(300));
        let item_id = Uuid::new_v4();
        // Generate with zero TTL — immediately expired
        let nonce = store.generate_with_ttl(item_id, "webhook", Duration::from_secs(0));

        // Small sleep to ensure expiration
        std::thread::sleep(Duration::from_millis(1));
        assert!(!store.validate_and_consume(item_id, &nonce, "webhook"));
    }

    #[test]
    fn test_nonce_store_cleanup() {
        let store = CallbackNonceStore::new(Duration::from_secs(300));
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        // One expired, one consumed, one valid
        let _n1 = store.generate_with_ttl(id1, "slack", Duration::from_secs(0));
        let n2 = store.generate(id2, "telegram");
        let _n3 = store.generate(Uuid::new_v4(), "discord");

        std::thread::sleep(Duration::from_millis(1));
        store.validate_and_consume(id2, &n2, "telegram");
        store.cleanup();

        // Only the valid, unconsumed entry should remain
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_nonce_store_nonexistent() {
        let store = CallbackNonceStore::new(Duration::from_secs(300));
        assert!(!store.validate_and_consume(Uuid::new_v4(), "nonexistent", "any"));
    }

    #[test]
    fn test_notification_event_constructors() {
        let id = Uuid::new_v4();

        let sent = NotificationEvent::sent(id, "slack", Some("msg_123".into()));
        assert!(matches!(sent, NotificationEvent::Sent { .. }));

        let delivered = NotificationEvent::delivered(id, "telegram");
        assert!(matches!(delivered, NotificationEvent::Delivered { .. }));

        let failed = NotificationEvent::failed(id, "email", "SMTP timeout");
        assert!(matches!(failed, NotificationEvent::Failed { .. }));

        let response = NotificationEvent::interactive_response(
            id,
            "slack",
            ReviewAction::Approve,
            "user@company.com",
        );
        assert!(matches!(
            response,
            NotificationEvent::InteractiveResponse { .. }
        ));
    }

    #[test]
    fn test_error_display() {
        let e = Error::TierRestriction("slack".into(), PlanTier::Community);
        assert!(e.to_string().contains("community"));

        let e = Error::InvalidNonce;
        assert!(e.to_string().contains("nonce"));
    }
}
