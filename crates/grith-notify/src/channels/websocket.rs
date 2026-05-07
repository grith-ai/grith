// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! WebSocket broadcast notification channel.

use tokio::sync::broadcast;

use grith_digest::notification::{
    CallbackPayload, ChannelHealth, Error, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::{DigestItem, ReviewAction};

/// WebSocket notification channel.
///
/// Broadcasts events to the dashboard via the existing `ws_tx` broadcast
/// channel. The dashboard handles interactive review through its own UI.
pub struct WebSocketChannel {
    ws_tx: broadcast::Sender<String>,
}

impl WebSocketChannel {
    pub fn new(ws_tx: broadcast::Sender<String>) -> Self {
        Self { ws_tx }
    }

    fn broadcast(&self, payload: &serde_json::Value) -> Result<(), Error> {
        let msg =
            serde_json::to_string(payload).map_err(|e| Error::Serialization(e.to_string()))?;

        // Only send if there are receivers; don't error if no one is listening
        if self.ws_tx.receiver_count() > 0 {
            self.ws_tx
                .send(msg)
                .map_err(|e| Error::DeliveryFailed("websocket".into(), e.to_string()))?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl NotificationChannel for WebSocketChannel {
    fn id(&self) -> &str {
        "websocket"
    }

    fn display_name(&self) -> &str {
        "Dashboard WebSocket"
    }

    fn required_tier(&self) -> PlanTier {
        PlanTier::Community
    }

    fn supports_interactive(&self) -> bool {
        true // Dashboard handles interactive review
    }

    async fn notify_permission_request(
        &self,
        item: &DigestItem,
        _nonce: Option<&str>,
    ) -> Result<NotifyResult, Error> {
        let payload = serde_json::json!({
            "type": "digest_queued",
            "item": item,
        });

        self.broadcast(&payload)?;

        Ok(NotifyResult {
            external_id: Some(item.id.to_string()),
            delivered: self.ws_tx.receiver_count() > 0,
        })
    }

    async fn notify_resolution(&self, item: &DigestItem) -> Result<(), Error> {
        let payload = serde_json::json!({
            "type": "digest_reviewed",
            "item": item,
        });

        self.broadcast(&payload)
    }

    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error> {
        let payload = serde_json::json!({
            "type": "digest_escalated",
            "item": item,
        });

        self.broadcast(&payload)
    }

    async fn handle_callback(
        &self,
        _payload: &CallbackPayload,
    ) -> Result<Option<ReviewAction>, Error> {
        // WebSocket callbacks are handled via the normal HTTP API, not here
        Ok(None)
    }

    async fn health_check(&self) -> Result<ChannelHealth, Error> {
        let has_receivers = self.ws_tx.receiver_count() > 0;
        Ok(ChannelHealth {
            connected: has_receivers,
            // In-process broadcast channel has negligible latency; return None
            // rather than a misleading hardcoded zero.
            latency_ms: None,
            error: if has_receivers {
                None
            } else {
                Some("no active WebSocket receivers".into())
            },
        })
    }
}
