// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Integration tests for the grith-notify notification system.
//!
//! Tests cover: dispatcher creation, channel registration, notification routing,
//! plan tier gating, and webhook HMAC verification.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use grith_digest::notification::{
    CallbackNonceStore, CallbackPayload, ChannelHealth, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::types::{DigestItem, DigestStatus, FilterBreakdown, ScoreSeverity};
use grith_digest::{DigestQueue, ReviewAction};
use grith_notify::batcher::Batcher;
use grith_notify::rate_limiter::RateLimiter;
use grith_notify::{ChannelRegistry, NotificationDispatcher, RoutingEngine};

// ---------------------------------------------------------------------------
// Mock channel
// ---------------------------------------------------------------------------

struct MockChannel {
    id: String,
    tier: PlanTier,
    interactive: bool,
    call_count: Arc<AtomicU32>,
}

impl MockChannel {
    fn new(id: &str, tier: PlanTier, interactive: bool) -> Self {
        Self {
            id: id.to_string(),
            tier,
            interactive,
            call_count: Arc::new(AtomicU32::new(0)),
        }
    }

    fn call_count_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.call_count)
    }
}

#[async_trait]
impl NotificationChannel for MockChannel {
    fn id(&self) -> &str {
        &self.id
    }

    fn display_name(&self) -> &str {
        &self.id
    }

    fn required_tier(&self) -> PlanTier {
        self.tier
    }

    fn supports_interactive(&self) -> bool {
        self.interactive
    }

    async fn notify_permission_request(
        &self,
        _item: &DigestItem,
        _nonce: Option<&str>,
    ) -> Result<NotifyResult, grith_digest::notification::Error> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(NotifyResult {
            external_id: Some(format!("mock-{}", Uuid::new_v4())),
            delivered: true,
        })
    }

    async fn notify_resolution(
        &self,
        _item: &DigestItem,
    ) -> Result<(), grith_digest::notification::Error> {
        Ok(())
    }

    async fn notify_escalation(
        &self,
        _item: &DigestItem,
    ) -> Result<(), grith_digest::notification::Error> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn handle_callback(
        &self,
        _payload: &CallbackPayload,
    ) -> Result<Option<ReviewAction>, grith_digest::notification::Error> {
        Ok(None)
    }

    async fn health_check(&self) -> Result<ChannelHealth, grith_digest::notification::Error> {
        Ok(ChannelHealth {
            connected: true,
            latency_ms: Some(1),
            error: None,
        })
    }
}

/// Interactive mock channel that returns the action from callbacks.
struct InteractiveMockChannel {
    id: String,
    tier: PlanTier,
    call_count: Arc<AtomicU32>,
}

impl InteractiveMockChannel {
    fn new(id: &str, tier: PlanTier) -> Self {
        Self {
            id: id.to_string(),
            tier,
            call_count: Arc::new(AtomicU32::new(0)),
        }
    }

    fn call_count_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.call_count)
    }
}

#[async_trait]
impl NotificationChannel for InteractiveMockChannel {
    fn id(&self) -> &str {
        &self.id
    }

    fn display_name(&self) -> &str {
        &self.id
    }

    fn required_tier(&self) -> PlanTier {
        self.tier
    }

    fn supports_interactive(&self) -> bool {
        true
    }

    async fn notify_permission_request(
        &self,
        _item: &DigestItem,
        _nonce: Option<&str>,
    ) -> Result<NotifyResult, grith_digest::notification::Error> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(NotifyResult {
            external_id: Some(format!("mock-{}", Uuid::new_v4())),
            delivered: true,
        })
    }

    async fn notify_resolution(
        &self,
        _item: &DigestItem,
    ) -> Result<(), grith_digest::notification::Error> {
        Ok(())
    }

    async fn notify_escalation(
        &self,
        _item: &DigestItem,
    ) -> Result<(), grith_digest::notification::Error> {
        Ok(())
    }

    async fn handle_callback(
        &self,
        payload: &CallbackPayload,
    ) -> Result<Option<ReviewAction>, grith_digest::notification::Error> {
        Ok(Some(payload.action))
    }

    async fn health_check(&self) -> Result<ChannelHealth, grith_digest::notification::Error> {
        Ok(ChannelHealth {
            connected: true,
            latency_ms: Some(1),
            error: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_item(score: f64) -> DigestItem {
    DigestItem {
        id: Uuid::new_v4(),
        created_at: chrono::Utc::now(),
        session_id: None,
        tool_call_type: "ShellExec".into(),
        arguments_summary: "echo 'test'".into(),
        decision_reason: None,
        composite_score: score,
        severity: ScoreSeverity::from_score(score),
        filter_breakdown: vec![FilterBreakdown {
            filter_name: "command".into(),
            score,
            rule_id: "test-rule".into(),
            message: "test match".into(),
        }],
        task_context: Some("notification-test".into()),
        plugin_id: "shell".into(),
        status: DigestStatus::Pending,
        reviewed_at: None,
        review_action: None,
        reviewer_notes: None,
        informational_only: false,
        escalated_at: None,
        escalated_by: None,
    }
}

fn make_dispatcher(
    registry: ChannelRegistry,
    routing: RoutingEngine,
    plan_tier: PlanTier,
) -> NotificationDispatcher {
    make_dispatcher_with_policy(
        registry,
        routing,
        plan_tier,
        Duration::from_secs(300),
        Duration::from_secs(300),
        10,
    )
    .0
}

fn make_dispatcher_with_ttl(
    registry: ChannelRegistry,
    routing: RoutingEngine,
    plan_tier: PlanTier,
    nonce_ttl: Duration,
) -> (NotificationDispatcher, Arc<DigestQueue>) {
    make_dispatcher_with_policy(
        registry,
        routing,
        plan_tier,
        nonce_ttl,
        Duration::from_secs(300),
        10,
    )
}

fn make_dispatcher_with_policy(
    registry: ChannelRegistry,
    routing: RoutingEngine,
    plan_tier: PlanTier,
    nonce_ttl: Duration,
    batch_window: Duration,
    max_batch_size: usize,
) -> (NotificationDispatcher, Arc<DigestQueue>) {
    let digest_queue =
        Arc::new(DigestQueue::open_in_memory().expect("failed to create in-memory digest queue"));
    let nonce_store = Arc::new(CallbackNonceStore::new(nonce_ttl));
    let dispatcher = NotificationDispatcher::new(
        registry,
        routing,
        nonce_store,
        plan_tier,
        Arc::clone(&digest_queue),
        RateLimiter::default(),
        Batcher::new(batch_window, max_batch_size),
        Duration::from_secs(300),
        ScoreSeverity::High,
    );
    (dispatcher, digest_queue)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that a dispatcher can be created with an in-memory DigestQueue,
/// and that it reports the correct plan tier and empty registry.
#[tokio::test]
async fn test_notification_dispatcher_creation() {
    let registry = ChannelRegistry::new();
    let routing = RoutingEngine::default();
    let dispatcher = make_dispatcher(registry, routing, PlanTier::Community);

    assert_eq!(dispatcher.plan_tier(), PlanTier::Community);
    assert!(dispatcher.registry().is_empty());

    let channels = dispatcher.list_channels().await;
    assert!(
        channels.is_empty(),
        "new dispatcher should have no channels"
    );
}

/// Register a mock channel and verify it appears in `list_channels()`.
#[tokio::test]
async fn test_channel_registration_and_listing() {
    let registry = ChannelRegistry::new();
    let routing = RoutingEngine::default();
    let dispatcher = make_dispatcher(registry, routing, PlanTier::Pro);

    let mock = MockChannel::new("mock-desktop", PlanTier::Community, false);
    dispatcher.register_channel(Arc::new(mock), true);

    assert_eq!(dispatcher.registry().len(), 1);

    let channels = dispatcher.list_channels().await;
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].id, "mock-desktop");
    assert!(channels[0].enabled);
    assert_eq!(channels[0].required_tier, PlanTier::Community);
    assert!(!channels[0].supports_interactive);
}

/// Register a mock channel, create a digest item, call `notify_permission_request()`,
/// and verify the mock was invoked.
#[tokio::test]
async fn test_notification_routing() {
    let registry = ChannelRegistry::new();

    // Set up routing so High severity goes to our mock channel
    let mut routing = RoutingEngine::new();
    routing.set_severity_route(ScoreSeverity::High, vec!["mock-channel".to_string()]);

    let dispatcher = make_dispatcher(registry, routing, PlanTier::Community);

    let mock = MockChannel::new("mock-channel", PlanTier::Community, false);
    let count_handle = mock.call_count_handle();
    dispatcher.register_channel(Arc::new(mock), true);

    // Create a High severity item (score 6.0 maps to High)
    let item = make_item(6.0);
    assert_eq!(item.severity, ScoreSeverity::High);

    dispatcher.notify_permission_request(&item).await.unwrap();

    assert_eq!(
        count_handle.load(Ordering::SeqCst),
        1,
        "mock channel should have been called once"
    );
}

/// Verify medium-severity notifications are queued for batched delivery.
#[tokio::test]
async fn test_medium_notifications_are_batched() {
    let registry = ChannelRegistry::new();
    let mut routing = RoutingEngine::new();
    routing.set_severity_route(ScoreSeverity::Medium, vec!["batch-channel".to_string()]);

    let (dispatcher, _queue) = make_dispatcher_with_policy(
        registry,
        routing,
        PlanTier::Community,
        Duration::from_secs(300),
        Duration::from_secs(300),
        10,
    );

    let mock = MockChannel::new("batch-channel", PlanTier::Community, false);
    let count_handle = mock.call_count_handle();
    dispatcher.register_channel(Arc::new(mock), true);

    let item = make_item(4.5);
    assert_eq!(item.severity, ScoreSeverity::Medium);
    dispatcher.notify_permission_request(&item).await.unwrap();

    assert_eq!(
        count_handle.load(Ordering::SeqCst),
        0,
        "medium-severity item should be queued for batched delivery"
    );
    assert_eq!(
        dispatcher.batcher().pending_count(),
        1,
        "batcher should contain queued medium-severity item"
    );
}

/// Verify medium-severity batches flush immediately when max batch size is reached.
#[tokio::test]
async fn test_medium_batch_flushes_when_max_size_reached() {
    let registry = ChannelRegistry::new();
    let mut routing = RoutingEngine::new();
    routing.set_severity_route(ScoreSeverity::Medium, vec!["batch-channel".to_string()]);

    let (dispatcher, _queue) = make_dispatcher_with_policy(
        registry,
        routing,
        PlanTier::Community,
        Duration::from_secs(300),
        Duration::from_secs(300),
        2,
    );

    let mock = MockChannel::new("batch-channel", PlanTier::Community, false);
    let count_handle = mock.call_count_handle();
    dispatcher.register_channel(Arc::new(mock), true);

    dispatcher
        .notify_permission_request(&make_item(4.5))
        .await
        .unwrap();
    assert_eq!(
        count_handle.load(Ordering::SeqCst),
        0,
        "first medium-severity item should still be batched"
    );

    dispatcher
        .notify_permission_request(&make_item(4.8))
        .await
        .unwrap();
    assert_eq!(
        count_handle.load(Ordering::SeqCst),
        2,
        "second medium-severity item should trigger flush of both batched items"
    );
    assert_eq!(
        dispatcher.batcher().pending_count(),
        0,
        "batcher should be empty after max-size-triggered flush"
    );
}

/// Register a Pro-tier mock channel with a Community plan tier dispatcher.
/// Verify the notification is skipped due to tier gating.
#[tokio::test]
async fn test_tier_gating() {
    let registry = ChannelRegistry::new();

    // Route High severity to our pro-only channel
    let mut routing = RoutingEngine::new();
    routing.set_severity_route(ScoreSeverity::High, vec!["pro-channel".to_string()]);

    // Dispatcher is Community tier
    let dispatcher = make_dispatcher(registry, routing, PlanTier::Community);

    let mock = MockChannel::new("pro-channel", PlanTier::Pro, true);
    let count_handle = mock.call_count_handle();
    dispatcher.register_channel(Arc::new(mock), true);

    let item = make_item(6.0);
    dispatcher.notify_permission_request(&item).await.unwrap();

    assert_eq!(
        count_handle.load(Ordering::SeqCst),
        0,
        "pro-tier channel should be skipped on community plan"
    );
}

/// Use `grith_notify::hmac_verify` to sign a payload, verify it passes,
/// and verify a bad signature fails.
#[test]
fn test_webhook_hmac_verification() {
    let secret = b"test-webhook-secret-key";
    let payload = b"{\"item_id\":\"abc-123\",\"action\":\"approve\"}";

    // Sign the payload
    let signature = grith_notify::hmac_verify::sign(secret, payload);

    // Verify with the correct secret and payload
    assert!(
        grith_notify::hmac_verify::verify(secret, payload, &signature),
        "valid signature should pass verification"
    );

    // Verify with wrong secret fails
    assert!(
        !grith_notify::hmac_verify::verify(b"wrong-secret", payload, &signature),
        "wrong secret should fail verification"
    );

    // Verify with wrong payload fails
    assert!(
        !grith_notify::hmac_verify::verify(secret, b"tampered-payload", &signature),
        "wrong payload should fail verification"
    );

    // Verify header format roundtrip
    let header = grith_notify::hmac_verify::signature_header(secret, payload);
    assert!(header.starts_with("sha256="));
    assert!(
        grith_notify::hmac_verify::verify_header(secret, payload, &header),
        "header format roundtrip should succeed"
    );

    // Verify bad hex string fails gracefully
    assert!(
        !grith_notify::hmac_verify::verify(secret, payload, "not-valid-hex!@#"),
        "invalid hex should fail verification"
    );
}

// ===========================================================================
// Nonce orchestration and callback tests
// ===========================================================================

/// Dispatch a notification to an interactive channel and verify that a nonce
/// is generated in the store.
#[tokio::test]
async fn test_nonce_generated_for_interactive_channel() {
    let registry = ChannelRegistry::new();
    let mut routing = RoutingEngine::new();
    routing.set_severity_route(ScoreSeverity::High, vec!["interactive-ch".to_string()]);

    let (dispatcher, _queue) = make_dispatcher_with_ttl(
        registry,
        routing,
        PlanTier::Community,
        Duration::from_secs(300),
    );

    let mock = InteractiveMockChannel::new("interactive-ch", PlanTier::Community);
    let count = mock.call_count_handle();
    dispatcher.register_channel(Arc::new(mock), true);

    assert!(
        dispatcher.nonce_store().is_empty(),
        "nonce store should start empty"
    );

    let item = make_item(6.0);
    dispatcher.notify_permission_request(&item).await.unwrap();

    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(
        dispatcher.nonce_store().len(),
        1,
        "dispatcher should have generated one nonce for the interactive channel"
    );
}

/// Dispatch a notification to a non-interactive channel and verify that no
/// nonce is generated.
#[tokio::test]
async fn test_nonce_not_generated_for_non_interactive_channel() {
    let registry = ChannelRegistry::new();
    let mut routing = RoutingEngine::new();
    routing.set_severity_route(ScoreSeverity::High, vec!["non-interactive".to_string()]);

    let (dispatcher, _queue) = make_dispatcher_with_ttl(
        registry,
        routing,
        PlanTier::Community,
        Duration::from_secs(300),
    );

    let mock = MockChannel::new("non-interactive", PlanTier::Community, false);
    let count = mock.call_count_handle();
    dispatcher.register_channel(Arc::new(mock), true);

    let item = make_item(6.0);
    dispatcher.notify_permission_request(&item).await.unwrap();

    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(
        dispatcher.nonce_store().is_empty(),
        "no nonce should be generated for non-interactive channel"
    );
}

/// Generate a nonce, build a valid callback payload, and verify the action
/// is applied successfully.
#[tokio::test]
async fn test_callback_with_valid_nonce() {
    let registry = ChannelRegistry::new();
    let routing = RoutingEngine::new();
    let (dispatcher, queue) = make_dispatcher_with_ttl(
        registry,
        routing,
        PlanTier::Community,
        Duration::from_secs(300),
    );

    let mock = InteractiveMockChannel::new("test-ch", PlanTier::Community);
    dispatcher.register_channel(Arc::new(mock), true);

    let item = make_item(6.0);
    queue.enqueue(&item).unwrap();

    let nonce = dispatcher.nonce_store().generate(item.id, "test-ch");
    let payload = CallbackPayload {
        item_id: item.id,
        action: ReviewAction::Approve,
        reviewer: "tester".into(),
        notes: None,
        nonce,
        channel_id: "test-ch".into(),
        user_id: None,
    };

    let result = dispatcher.handle_callback(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some(ReviewAction::Approve));
}

/// Submit a callback with a fabricated (invalid) nonce and verify it is rejected.
#[tokio::test]
async fn test_callback_rejects_invalid_nonce() {
    let registry = ChannelRegistry::new();
    let routing = RoutingEngine::new();
    let (dispatcher, _queue) = make_dispatcher_with_ttl(
        registry,
        routing,
        PlanTier::Community,
        Duration::from_secs(300),
    );

    let mock = InteractiveMockChannel::new("test-ch", PlanTier::Community);
    dispatcher.register_channel(Arc::new(mock), true);

    let payload = CallbackPayload {
        item_id: Uuid::new_v4(),
        action: ReviewAction::Approve,
        reviewer: "tester".into(),
        notes: None,
        nonce: "fabricated-nonce".into(),
        channel_id: "test-ch".into(),
        user_id: None,
    };

    let result = dispatcher.handle_callback(&payload).await;
    assert!(result.is_err(), "fabricated nonce should be rejected");
    assert!(
        result.unwrap_err().to_string().contains("nonce"),
        "error should mention nonce"
    );
}

/// Generate a nonce with zero TTL, wait for expiry, and verify it is rejected.
#[tokio::test]
async fn test_callback_rejects_expired_nonce() {
    let registry = ChannelRegistry::new();
    let routing = RoutingEngine::new();
    let (dispatcher, _queue) = make_dispatcher_with_ttl(
        registry,
        routing,
        PlanTier::Community,
        Duration::from_secs(300),
    );

    let mock = InteractiveMockChannel::new("test-ch", PlanTier::Community);
    dispatcher.register_channel(Arc::new(mock), true);

    let item_id = Uuid::new_v4();
    let nonce =
        dispatcher
            .nonce_store()
            .generate_with_ttl(item_id, "test-ch", Duration::from_secs(0));

    tokio::time::sleep(Duration::from_millis(5)).await;

    let payload = CallbackPayload {
        item_id,
        action: ReviewAction::Approve,
        reviewer: "tester".into(),
        notes: None,
        nonce,
        channel_id: "test-ch".into(),
        user_id: None,
    };

    let result = dispatcher.handle_callback(&payload).await;
    assert!(result.is_err(), "expired nonce should be rejected");
}

/// Generate a nonce, consume it, then try to use it again.
#[tokio::test]
async fn test_callback_rejects_consumed_nonce() {
    let registry = ChannelRegistry::new();
    let routing = RoutingEngine::new();
    let (dispatcher, queue) = make_dispatcher_with_ttl(
        registry,
        routing,
        PlanTier::Community,
        Duration::from_secs(300),
    );

    let mock = InteractiveMockChannel::new("test-ch", PlanTier::Community);
    dispatcher.register_channel(Arc::new(mock), true);

    let item = make_item(6.0);
    queue.enqueue(&item).unwrap();

    let nonce = dispatcher.nonce_store().generate(item.id, "test-ch");
    let payload = CallbackPayload {
        item_id: item.id,
        action: ReviewAction::Approve,
        reviewer: "tester".into(),
        notes: None,
        nonce: nonce.clone(),
        channel_id: "test-ch".into(),
        user_id: None,
    };

    // First use succeeds
    let result = dispatcher.handle_callback(&payload).await;
    assert!(result.is_ok());

    // Second use with same nonce fails
    let payload2 = CallbackPayload {
        item_id: item.id,
        action: ReviewAction::Deny,
        reviewer: "tester".into(),
        notes: None,
        nonce,
        channel_id: "test-ch".into(),
        user_id: None,
    };

    let result2 = dispatcher.handle_callback(&payload2).await;
    assert!(
        result2.is_err(),
        "consumed nonce should be rejected on reuse"
    );
}

/// Generate a nonce for channel "slack" but attempt callback from channel
/// "telegram" — should be rejected because channel_id doesn't match.
#[tokio::test]
async fn test_callback_wrong_channel_rejected() {
    let registry = ChannelRegistry::new();
    let routing = RoutingEngine::new();
    let (dispatcher, _queue) = make_dispatcher_with_ttl(
        registry,
        routing,
        PlanTier::Community,
        Duration::from_secs(300),
    );

    let mock_slack = InteractiveMockChannel::new("slack", PlanTier::Community);
    let mock_telegram = InteractiveMockChannel::new("telegram", PlanTier::Community);
    dispatcher.register_channel(Arc::new(mock_slack), true);
    dispatcher.register_channel(Arc::new(mock_telegram), true);

    let item_id = Uuid::new_v4();
    let nonce = dispatcher.nonce_store().generate(item_id, "slack");

    // Try to use slack's nonce from telegram channel
    let payload = CallbackPayload {
        item_id,
        action: ReviewAction::Approve,
        reviewer: "tester".into(),
        notes: None,
        nonce: nonce.clone(),
        channel_id: "telegram".into(),
        user_id: None,
    };

    let result = dispatcher.handle_callback(&payload).await;
    assert!(
        result.is_err(),
        "nonce from slack should not work for telegram"
    );

    // Nonce should still be valid for the correct channel
    assert!(
        dispatcher
            .nonce_store()
            .validate_and_consume(item_id, &nonce, "slack"),
        "nonce should still be usable for the correct channel"
    );
}

/// Verify that a callback with an unknown channel_id is rejected WITHOUT
/// consuming the nonce (channel validation happens before nonce consumption).
#[tokio::test]
async fn test_callback_channel_validated_before_nonce_consumed() {
    let registry = ChannelRegistry::new();
    let routing = RoutingEngine::new();
    let (dispatcher, _queue) = make_dispatcher_with_ttl(
        registry,
        routing,
        PlanTier::Community,
        Duration::from_secs(300),
    );

    let mock = InteractiveMockChannel::new("real-channel", PlanTier::Community);
    dispatcher.register_channel(Arc::new(mock), true);

    let item_id = Uuid::new_v4();
    let nonce = dispatcher.nonce_store().generate(item_id, "real-channel");

    // Attempt callback from a non-existent channel
    let payload = CallbackPayload {
        item_id,
        action: ReviewAction::Approve,
        reviewer: "tester".into(),
        notes: None,
        nonce: nonce.clone(),
        channel_id: "nonexistent-channel".into(),
        user_id: None,
    };

    let result = dispatcher.handle_callback(&payload).await;
    assert!(result.is_err(), "unknown channel should be rejected");

    // The nonce should NOT have been consumed — still valid for the real channel
    assert!(
        dispatcher
            .nonce_store()
            .validate_and_consume(item_id, &nonce, "real-channel"),
        "nonce should not be burned by a failed channel validation"
    );
}
