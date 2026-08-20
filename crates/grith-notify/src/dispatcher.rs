// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Central notification dispatcher orchestrating channel delivery and callbacks.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use grith_digest::notification::{CallbackNonceStore, CallbackPayload, ChannelInfo, PlanTier};
use grith_digest::types::ScoreSeverity;
use grith_digest::{DigestItem, DigestQueue, ReviewAction};

use crate::batcher::Batcher;
use crate::error::{Error, Result};
use crate::rate_limiter::RateLimiter;
use crate::registry::ChannelRegistry;
use crate::routing::RoutingEngine;
use crate::tracker::DeliveryTracker;

/// Convert a `ScoreSeverity` to a numeric level for comparison.
fn severity_level(severity: ScoreSeverity) -> u8 {
    match severity {
        ScoreSeverity::Low => 0,
        ScoreSeverity::Medium => 1,
        ScoreSeverity::High => 2,
        ScoreSeverity::Critical => 3,
    }
}

/// Central notification orchestrator.
///
/// Routes digest items to the appropriate channels based on severity,
/// manages delivery tracking, rate limiting, batching, and handles
/// interactive callbacks from two-way channels.
pub struct NotificationDispatcher {
    registry: Arc<ChannelRegistry>,
    routing: RoutingEngine,
    tracker: Arc<DeliveryTracker>,
    rate_limiter: Arc<RateLimiter>,
    batcher: Arc<Batcher>,
    nonce_store: Arc<CallbackNonceStore>,
    plan_tier: Arc<RwLock<PlanTier>>,
    digest_queue: Arc<DigestQueue>,
    auto_escalate_timeout: Duration,
    auto_escalate_min_severity: ScoreSeverity,
    /// Grace period before a pending permission request is pushed to the
    /// notification channels. A prompt resolved at the local TUI within this
    /// window is never sent remotely. See `with_remote_delay`.
    remote_delay: Duration,
}

impl NotificationDispatcher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: ChannelRegistry,
        routing: RoutingEngine,
        nonce_store: Arc<CallbackNonceStore>,
        plan_tier: PlanTier,
        digest_queue: Arc<DigestQueue>,
        rate_limiter: RateLimiter,
        batcher: Batcher,
        auto_escalate_timeout: Duration,
        auto_escalate_min_severity: ScoreSeverity,
    ) -> Self {
        Self {
            registry: Arc::new(registry),
            routing,
            tracker: Arc::new(DeliveryTracker::default()),
            rate_limiter: Arc::new(rate_limiter),
            batcher: Arc::new(batcher),
            nonce_store,
            plan_tier: Arc::new(RwLock::new(plan_tier)),
            digest_queue,
            auto_escalate_timeout,
            auto_escalate_min_severity,
            remote_delay: Duration::from_secs(15),
        }
    }

    /// Set the grace period before a pending permission request is pushed to
    /// the notification channels. A prompt resolved at the local TUI within
    /// this window is never sent remotely (no redundant/stale phone alert).
    /// `Duration::ZERO` restores immediate delivery.
    #[must_use]
    pub fn with_remote_delay(mut self, delay: Duration) -> Self {
        self.remote_delay = delay;
        self
    }

    fn current_plan_tier(&self) -> PlanTier {
        self.plan_tier
            .read()
            .map(|tier| *tier)
            .unwrap_or(PlanTier::Community)
    }

    /// Whether this permission request should be batched before delivery.
    ///
    /// Current policy:
    /// - Medium/Low severity can batch
    /// - High/Critical always dispatch immediately
    /// - A zero batch window disables batching entirely
    fn should_batch_permission_request(&self, item: &DigestItem) -> bool {
        self.batcher.window() > Duration::ZERO
            && severity_level(item.severity) <= severity_level(ScoreSeverity::Medium)
    }

    /// Dispatch a permission request notification immediately to all routed channels.
    async fn dispatch_permission_request_now(&self, item: &DigestItem) -> Result<()> {
        let filter_names: Vec<String> = item
            .filter_breakdown
            .iter()
            .map(|f| f.filter_name.clone())
            .collect();

        let channel_ids = self.routing.resolve(item.severity, &filter_names);

        if channel_ids.is_empty() {
            debug!(item_id = %item.id, "no channels matched for routing");
            return Ok(());
        }

        for channel_id in &channel_ids {
            // Tier gating
            let channel = match self.registry.get_enabled(channel_id) {
                Ok(ch) => {
                    if ch.required_tier() > self.current_plan_tier() {
                        debug!(
                            channel = channel_id,
                            required = %ch.required_tier(),
                            current = %self.current_plan_tier(),
                            "channel skipped due to tier restriction"
                        );
                        continue;
                    }
                    ch
                }
                Err(_) => {
                    debug!(channel = channel_id, "channel not available, skipping");
                    continue;
                }
            };

            // Rate limiting
            if let Err(wait) = self.rate_limiter.check(channel_id) {
                warn!(
                    channel = channel_id,
                    wait_secs = wait.as_secs(),
                    "rate limited, skipping"
                );
                self.tracker.record_failed(
                    item.id,
                    channel_id,
                    &format!("rate limited, next allowed in {}s", wait.as_secs()),
                );
                continue;
            }

            // Generate a one-time nonce for interactive channels so callbacks
            // can be validated. Non-interactive channels receive None.
            let nonce = if channel.supports_interactive() {
                Some(self.nonce_store.generate(item.id, channel_id))
            } else {
                None
            };

            match channel
                .notify_permission_request(item, nonce.as_deref())
                .await
            {
                Ok(result) => {
                    self.rate_limiter.record(channel_id);
                    self.tracker
                        .record_sent(item.id, channel_id, result.external_id);
                    info!(
                        item_id = %item.id,
                        channel = channel_id,
                        "notification sent"
                    );
                }
                Err(e) => {
                    error!(
                        item_id = %item.id,
                        channel = channel_id,
                        error = %e,
                        "notification delivery failed"
                    );
                    self.tracker
                        .record_failed(item.id, channel_id, &e.to_string());
                }
            }
        }

        Ok(())
    }

    /// Send notifications for a new permission request (queued digest item).
    ///
    /// Routes by severity, fans out to matched channels concurrently,
    /// respects rate limits, quiet hours, and plan tier gating.
    pub async fn notify_permission_request(&self, item: &DigestItem) -> Result<()> {
        // M-29: Check quiet hours. During quiet hours only Critical-severity
        // notifications are allowed through.
        if self.rate_limiter.is_quiet_hours()
            && severity_level(item.severity) < severity_level(ScoreSeverity::Critical)
        {
            debug!(
                item_id = %item.id,
                severity = ?item.severity,
                "suppressed during quiet hours (only Critical allowed)"
            );
            return Ok(());
        }

        if self.should_batch_permission_request(item) {
            let flush_now = self.batcher.add(item.clone());
            debug!(
                item_id = %item.id,
                severity = ?item.severity,
                pending = self.batcher.pending_count(),
                flush_now,
                "queued notification item for batched delivery"
            );
            if !flush_now {
                return Ok(());
            }

            let batched_items = self.batcher.flush_all();
            info!(
                count = batched_items.len(),
                "batch size reached; flushing queued notification items"
            );
            for batched in &batched_items {
                self.dispatch_permission_request_now(batched).await?;
            }
            return Ok(());
        }

        self.dispatch_permission_request_now(item).await
    }

    /// Notify all channels that previously received a notification for this
    /// item that it has been resolved.
    pub async fn notify_resolution(&self, item: &DigestItem) -> Result<()> {
        // If the item was still waiting in the batch queue (not yet delivered),
        // drop it so stale permission requests are never dispatched later.
        self.batcher.remove(item.id);

        let sent_channels = self.tracker.sent_channels(item.id);

        for channel_id in &sent_channels {
            if let Ok(channel) = self.registry.get_enabled(channel_id) {
                if let Err(e) = channel.notify_resolution(item).await {
                    warn!(
                        item_id = %item.id,
                        channel = channel_id,
                        error = %e,
                        "failed to send resolution notification"
                    );
                }
            }
        }

        Ok(())
    }

    /// Send escalation notifications to the configured escalation channels.
    pub async fn notify_escalation(&self, item: &DigestItem) -> Result<()> {
        let channel_ids = self.routing.resolve_escalation();

        for channel_id in &channel_ids {
            if let Ok(channel) = self.registry.get_enabled(channel_id) {
                if channel.required_tier() > self.current_plan_tier() {
                    continue;
                }
                if let Err(e) = channel.notify_escalation(item).await {
                    error!(
                        item_id = %item.id,
                        channel = channel_id,
                        error = %e,
                        "escalation notification failed"
                    );
                }
            }
        }

        Ok(())
    }

    /// Handle an inbound interactive callback from a channel.
    ///
    /// Validates the nonce, applies the review action via DigestActions,
    /// and broadcasts resolution to all channels.
    pub async fn handle_callback(&self, payload: &CallbackPayload) -> Result<Option<ReviewAction>> {
        // Validate channel exists and is enabled FIRST (non-destructive check).
        // This prevents burning a valid nonce on a request from an unknown or
        // disabled channel.
        let channel = self.registry.get_enabled(&payload.channel_id)?;

        // Now validate and consume the nonce (destructive — only after channel
        // is confirmed valid).
        if !self.nonce_store.validate_and_consume(
            payload.item_id,
            &payload.nonce,
            &payload.channel_id,
        ) {
            warn!(
                item_id = %payload.item_id,
                channel = &payload.channel_id,
                "invalid or expired callback nonce"
            );
            return Err(Error::Notification(
                grith_digest::notification::Error::InvalidNonce,
            ));
        }

        // Delegate to the channel for any channel-specific validation
        let action = channel.handle_callback(payload).await?;

        if let Some(action) = action {
            // Apply the review action using the sync DigestActions API
            let result = {
                let actions = grith_digest::actions::DigestActions::new(&self.digest_queue);

                match action {
                    ReviewAction::Approve => actions.approve(&payload.item_id),
                    ReviewAction::Deny => actions.deny(&payload.item_id),
                    ReviewAction::ApproveAndLearn => actions.approve_and_learn(&payload.item_id),
                    ReviewAction::Escalate => {
                        actions.escalate(&payload.item_id, Some(&payload.reviewer))
                    }
                    _ => actions.review(&payload.item_id, action, payload.notes.as_deref()),
                }
            };

            match result {
                Ok(()) => {
                    self.tracker.record_interactive_response(
                        payload.item_id,
                        &payload.channel_id,
                        action,
                        &payload.reviewer,
                    );

                    // Broadcast resolution to all channels that received the
                    // original notification
                    let item = self.digest_queue.get_by_id(&payload.item_id).ok();
                    if let Some(item) = item {
                        let _ = self.notify_resolution(&item).await;
                    }

                    info!(
                        item_id = %payload.item_id,
                        channel = &payload.channel_id,
                        action = %action,
                        reviewer = &payload.reviewer,
                        "interactive callback processed"
                    );

                    Ok(Some(action))
                }
                Err(e) => {
                    warn!(
                        item_id = %payload.item_id,
                        error = %e,
                        "failed to apply review action from callback"
                    );
                    Err(Error::Notification(
                        grith_digest::notification::Error::ItemNotActionable(payload.item_id),
                    ))
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Run health checks on all registered channels.
    pub async fn health_check(&self) -> Vec<(String, grith_digest::notification::ChannelHealth)> {
        let mut results = Vec::new();
        for id in self.registry.channel_ids() {
            if let Some(ch) = self.registry.get(&id) {
                match ch.health_check().await {
                    Ok(health) => results.push((id, health)),
                    Err(e) => results.push((
                        id.clone(),
                        grith_digest::notification::ChannelHealth {
                            connected: false,
                            latency_ms: None,
                            error: Some(e.to_string()),
                        },
                    )),
                }
            }
        }
        results
    }

    /// List all channels with their info and health status.
    pub async fn list_channels(&self) -> Vec<ChannelInfo> {
        self.registry.list_channels(self.current_plan_tier()).await
    }

    /// Send a test notification to a specific channel.
    pub async fn test_channel(&self, channel_id: &str) -> Result<()> {
        let channel = self
            .registry
            .get(channel_id)
            .ok_or_else(|| Error::ChannelNotFound(channel_id.to_string()))?;

        let test_item = DigestItem {
            id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            session_id: None,
            tool_call_type: "ShellExec".into(),
            arguments_summary: "echo 'test notification from grith'".into(),
            decision_reason: Some("test notification".into()),
            composite_score: 5.5,
            severity: grith_digest::types::ScoreSeverity::High,
            filter_breakdown: vec![],
            task_context: Some("Test notification".into()),
            plugin_id: "test".into(),
            status: grith_digest::DigestStatus::Pending,
            reviewed_at: None,
            review_action: None,
            reviewer_notes: None,
            informational_only: true,
            escalated_at: None,
            escalated_by: None,
        };

        match channel.notify_permission_request(&test_item, None).await {
            Ok(result) => {
                info!(
                    channel = channel_id,
                    delivered = result.delivered,
                    "test notification sent"
                );
                Ok(())
            }
            Err(e) => {
                error!(channel = channel_id, error = %e, "test notification failed");
                Err(Error::Notification(e))
            }
        }
    }

    /// Get the delivery tracker for inspecting notification status.
    pub fn tracker(&self) -> &DeliveryTracker {
        &self.tracker
    }

    /// Get the nonce store for generating callback nonces.
    pub fn nonce_store(&self) -> &Arc<CallbackNonceStore> {
        &self.nonce_store
    }

    /// Get the batcher for adding low-severity items.
    pub fn batcher(&self) -> &Batcher {
        &self.batcher
    }

    /// Get the current plan tier.
    pub fn plan_tier(&self) -> PlanTier {
        self.current_plan_tier()
    }

    /// Update the active plan tier for runtime feature gating.
    pub fn set_plan_tier(&self, tier: PlanTier) {
        if let Ok(mut current) = self.plan_tier.write() {
            *current = tier;
        }
    }

    /// Register a notification channel with the dispatcher.
    pub fn register_channel(
        &self,
        channel: std::sync::Arc<dyn grith_digest::notification::NotificationChannel>,
        enabled: bool,
    ) {
        self.registry.register(channel, enabled);
    }

    /// Get the channel registry.
    pub fn registry(&self) -> &ChannelRegistry {
        &self.registry
    }

    /// Spawn background tasks (nonce cleanup, auto-escalation, batcher flush).
    /// Returns join handles for the spawned tasks.
    pub fn spawn_background_tasks(
        self: &Arc<Self>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        // Create resubscriptions before moving shutdown_rx
        let mut escalation_shutdown_rx = shutdown_rx.resubscribe();
        let mut batcher_shutdown_rx = shutdown_rx.resubscribe();
        let mut notify_scan_shutdown_rx = shutdown_rx.resubscribe();

        // New-pending notify loop. The daemon is the single owner of the
        // registered channels and the notification config, so it — not the
        // caller that queued the item — watches the shared digest queue and
        // sends the initial permission-request notification for any pending
        // item that has not been notified yet. This is what makes BOTH paths
        // notify: the built-in agent (`grith run`) AND the CLI supervisor
        // (`grith exec`), which both enqueue to the same digest DB but only the
        // agent used to call `notify_permission_request` directly. Dedup is a
        // per-run in-memory set (pruned to still-pending ids) plus the delivery
        // tracker, so an item is announced once; a daemon restart re-announces
        // items still pending, which is the desired "you have N waiting" nudge.
        let scan_dispatcher = Arc::clone(self);
        handles.push(tokio::spawn(async move {
            use std::collections::HashSet;
            let mut announced: HashSet<uuid::Uuid> = HashSet::new();
            let mut ticker = tokio::time::interval(Duration::from_secs(3));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let pending = match scan_dispatcher.digest_queue.get_pending(200, 0) {
                            Ok(p) => p,
                            Err(e) => {
                                error!("notify scan: get_pending failed: {e}");
                                continue;
                            }
                        };
                        let pending_ids: HashSet<uuid::Uuid> =
                            pending.iter().map(|i| i.id).collect();

                        // Expire remote prompts resolved out-of-band. Any item
                        // we announced that is no longer pending was
                        // approved/denied somewhere else (the local TUI, the
                        // dashboard) — broadcast the resolution so channels
                        // that carry buttons (Telegram, ...) drop them and
                        // show the outcome instead of a stale, tappable prompt.
                        let resolved: Vec<uuid::Uuid> = announced
                            .iter()
                            .filter(|id| !pending_ids.contains(id))
                            .copied()
                            .collect();
                        for id in resolved {
                            if let Ok(item) = scan_dispatcher.digest_queue.get_by_id(&id) {
                                if let Err(e) = scan_dispatcher.notify_resolution(&item).await {
                                    debug!(item_id = %id, error = %e,
                                        "notify scan: resolution broadcast failed");
                                }
                            }
                            announced.remove(&id);
                        }

                        let now = chrono::Utc::now();
                        let remote_delay = chrono::Duration::from_std(scan_dispatcher.remote_delay)
                            .unwrap_or_else(|_| chrono::Duration::zero());
                        for item in &pending {
                            if item.informational_only || announced.contains(&item.id) {
                                continue;
                            }
                            if !scan_dispatcher.tracker.sent_channels(item.id).is_empty() {
                                announced.insert(item.id);
                                continue;
                            }
                            // Grace period: hold the item back from the
                            // notification channels until it has been pending
                            // for `remote_delay`. A prompt answered at the
                            // local TUI within the window is resolved (and so
                            // leaves `pending`) before it is ever sent — no
                            // redundant phone alert, no stale prompt to expire.
                            // It is picked up on a later tick once it ages past
                            // the window.
                            if now.signed_duration_since(item.created_at) < remote_delay {
                                continue;
                            }
                            // Dispatch immediately (not via the batcher): a
                            // permission prompt is time-sensitive — you need it
                            // to approve/deny remotely, not 5 minutes later.
                            match scan_dispatcher.dispatch_permission_request_now(item).await {
                                Ok(()) => {
                                    announced.insert(item.id);
                                }
                                Err(e) => {
                                    error!(item_id = %item.id, error = %e,
                                        "notify scan: permission-request dispatch failed");
                                }
                            }
                        }
                        // Bound memory: drop any remaining ids that are no
                        // longer pending (e.g. announced this run then resolved,
                        // or an item whose get_by_id failed above).
                        announced.retain(|id| pending_ids.contains(id));
                    }
                    _ = notify_scan_shutdown_rx.recv() => {
                        debug!("notify scan loop shutting down");
                        break;
                    }
                }
            }
        }));

        // Nonce cleanup loop
        let nonce_store = Arc::clone(&self.nonce_store);
        handles.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.tick().await;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        nonce_store.cleanup();
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("nonce cleanup loop shutting down");
                        break;
                    }
                }
            }
        }));

        // Auto-escalation loop
        let digest_queue = Arc::clone(&self.digest_queue);
        let escalation_timeout = self.auto_escalate_timeout;
        let min_severity = self.auto_escalate_min_severity;
        let routing = self.routing.clone();
        let registry = Arc::clone(&self.registry);
        let plan_tier = Arc::clone(&self.plan_tier);
        handles.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            ticker.tick().await;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let items_to_escalate = {
                            let actionable = match digest_queue.get_actionable(100, 0) {
                                Ok(items) => items,
                                Err(e) => {
                                    error!("auto-escalation: failed to get actionable items: {e}");
                                    continue;
                                }
                            };

                            let now = chrono::Utc::now();
                            let timeout = chrono::Duration::from_std(escalation_timeout)
                                .unwrap_or(chrono::TimeDelta::MAX);
                            let min_level = severity_level(min_severity);

                            let qualifying: Vec<DigestItem> = actionable
                                .into_iter()
                                .filter(|item| {
                                    item.status == grith_digest::DigestStatus::Pending
                                        && !item.informational_only
                                        && severity_level(item.severity) >= min_level
                                        && (now - item.created_at) >= timeout
                                })
                                .collect();

                            // Escalate each qualifying item
                            let mut escalated = Vec::new();
                            for item in &qualifying {
                                let actions = grith_digest::actions::DigestActions::new(&digest_queue);
                                match actions.escalate(&item.id, Some("auto-escalation")) {
                                    Ok(()) => {
                                        info!(
                                            item_id = %item.id,
                                            severity = ?item.severity,
                                            age_secs = (now - item.created_at).num_seconds(),
                                            "auto-escalated pending item"
                                        );
                                        // Re-fetch the item to get updated status
                                        if let Ok(updated) = digest_queue.get_by_id(&item.id) {
                                            escalated.push(updated);
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            item_id = %item.id,
                                            error = %e,
                                            "auto-escalation failed for item"
                                        );
                                    }
                                }
                            }

                            escalated
                        };

                        // Send escalation notifications (async)
                        let escalation_channel_ids = routing.resolve_escalation();
                        for item in &items_to_escalate {
                            for channel_id in &escalation_channel_ids {
                                if let Some(channel) = registry.get(channel_id) {
                                    let current_tier = plan_tier
                                        .read()
                                        .map(|tier| *tier)
                                        .unwrap_or(PlanTier::Community);
                                    if channel.required_tier() > current_tier {
                                        continue;
                                    }
                                    if let Err(e) = channel.notify_escalation(item).await {
                                        error!(
                                            item_id = %item.id,
                                            channel = channel_id,
                                            error = %e,
                                            "auto-escalation notification failed"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    _ = escalation_shutdown_rx.recv() => {
                        debug!("auto-escalation loop shutting down");
                        break;
                    }
                }
            }
        }));

        // Batcher flush loop: periodically checks for items that have been
        // waiting longer than the batch window and dispatches them.
        let batcher_window = self.batcher.window();
        // Use a shorter interval than the window so we don't miss the deadline
        let flush_interval = batcher_window / 2;
        let flush_interval = if flush_interval < Duration::from_secs(1) {
            Duration::from_secs(1)
        } else {
            flush_interval
        };
        let batcher_ref = Arc::clone(&self.batcher);
        let flush_registry = Arc::clone(&self.registry);
        let flush_routing = self.routing.clone();
        let flush_tracker = Arc::clone(&self.tracker);
        let flush_rate_limiter_ref = Arc::clone(&self.rate_limiter);
        let flush_nonce_store = Arc::clone(&self.nonce_store);
        let flush_plan_tier = Arc::clone(&self.plan_tier);
        handles.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(flush_interval);
            ticker.tick().await; // skip first immediate tick

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let items = batcher_ref.flush_ready();
                        if !items.is_empty() {
                            info!(count = items.len(), "flushing batched notifications");
                            for item in &items {
                                let filter_names: Vec<String> = item
                                    .filter_breakdown
                                    .iter()
                                    .map(|f| f.filter_name.clone())
                                    .collect();
                                let channel_ids = flush_routing.resolve(item.severity, &filter_names);
                                for channel_id in &channel_ids {
                                    let channel = match flush_registry.get_enabled(channel_id) {
                                        Ok(ch) => {
                                            let current_tier = flush_plan_tier
                                                .read()
                                                .map(|tier| *tier)
                                                .unwrap_or(PlanTier::Community);
                                            if ch.required_tier() > current_tier {
                                                continue;
                                            }
                                            ch
                                        }
                                        Err(_) => continue,
                                    };

                                    if flush_rate_limiter_ref.check(channel_id).is_err() {
                                        continue;
                                    }

                                    let nonce = if channel.supports_interactive() {
                                        Some(flush_nonce_store.generate(item.id, channel_id))
                                    } else {
                                        None
                                    };

                                    match channel
                                        .notify_permission_request(item, nonce.as_deref())
                                        .await
                                    {
                                        Ok(result) => {
                                            flush_rate_limiter_ref.record(channel_id);
                                            flush_tracker.record_sent(
                                                item.id,
                                                channel_id,
                                                result.external_id,
                                            );
                                            info!(
                                                item_id = %item.id,
                                                channel = channel_id,
                                                "batched notification sent"
                                            );
                                        }
                                        Err(e) => {
                                            error!(
                                                item_id = %item.id,
                                                channel = channel_id,
                                                error = %e,
                                                "batched notification delivery failed"
                                            );
                                            flush_tracker.record_failed(
                                                item.id,
                                                channel_id,
                                                &e.to_string(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ = batcher_shutdown_rx.recv() => {
                        debug!("batcher flush loop shutting down");
                        // Flush remaining items on shutdown
                        let remaining = batcher_ref.flush_all();
                        if !remaining.is_empty() {
                            info!(count = remaining.len(), "flushing remaining batched items on shutdown");
                        }
                        break;
                    }
                }
            }
        }));

        handles
    }
}

impl std::fmt::Debug for NotificationDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationDispatcher")
            .field("plan_tier", &self.current_plan_tier())
            .field("registry", &self.registry)
            .field("tracker", &self.tracker)
            .field("batcher", &self.batcher)
            .finish()
    }
}
