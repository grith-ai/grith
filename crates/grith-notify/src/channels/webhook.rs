// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Generic webhook notification channel.

use std::time::Duration;

use grith_digest::notification::{
    CallbackPayload, ChannelHealth, Error, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::{DigestItem, ReviewAction};

use crate::hmac_verify;

/// Maximum backoff duration for webhook retries (60 seconds).
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Configuration for the generic webhook notification channel.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// URL to POST notifications to.
    pub url: String,
    /// HMAC-SHA256 signing secret for the X-Grith-Signature-256 header.
    pub secret: String,
    /// Optional callback URL for two-way approval.
    /// The webhook recipient can POST to this URL to approve/deny.
    pub callback_url: Option<String>,
    /// Additional headers to include in the request.
    pub headers: Vec<(String, String)>,
    /// Maximum retry attempts on failure.
    pub max_retries: u32,
}

/// Generic webhook notification channel.
///
/// POSTs a JSON payload with HMAC-SHA256 signature. Optionally supports
/// two-way approval via a callback URL.
pub struct WebhookChannel {
    config: WebhookConfig,
    client: reqwest::Client,
}

impl WebhookChannel {
    pub fn new(config: WebhookConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { config, client }
    }

    fn build_payload(&self, item: &DigestItem, event_type: &str) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "event": event_type,
            "item": item,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        if let Some(callback_url) = &self.config.callback_url {
            payload["callback_url"] = serde_json::json!(format!("{}/{}", callback_url, item.id));
        }

        payload
    }

    async fn send_with_retry(
        &self,
        payload: &serde_json::Value,
        event_type: &str,
    ) -> Result<reqwest::Response, Error> {
        let body = serde_json::to_vec(payload).map_err(|e| Error::Serialization(e.to_string()))?;

        let signature = hmac_verify::signature_header(self.config.secret.as_bytes(), &body);

        let mut last_err = None;
        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                // Exponential backoff capped at MAX_BACKOFF with jitter
                let base_ms = 500u64.saturating_mul(2u64.saturating_pow(attempt - 1));
                let capped = Duration::from_millis(base_ms).min(MAX_BACKOFF);
                // Add jitter: random value in 0..50% of the capped delay
                let jitter_ms = {
                    // Simple pseudo-random jitter using timestamp nanoseconds
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos() as u64;
                    nanos % (capped.as_millis() as u64 / 2).max(1)
                };
                let delay = capped + Duration::from_millis(jitter_ms);
                tokio::time::sleep(delay).await;
            }

            let mut req = self
                .client
                .post(&self.config.url)
                .header("Content-Type", "application/json")
                .header("X-Grith-Signature-256", &signature)
                .header("X-Grith-Event", event_type);

            for (key, value) in &self.config.headers {
                req = req.header(key, value);
            }

            match req.body(body.clone()).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(resp),
                Ok(resp) => {
                    last_err = Some(format!("HTTP {}", resp.status()));
                }
                Err(e) => {
                    last_err = Some(e.to_string());
                }
            }
        }

        Err(Error::DeliveryFailed(
            "webhook".into(),
            last_err.unwrap_or_else(|| "unknown error".into()),
        ))
    }
}

#[async_trait::async_trait]
impl NotificationChannel for WebhookChannel {
    fn id(&self) -> &str {
        "webhook"
    }

    fn display_name(&self) -> &str {
        "Generic Webhook"
    }

    fn required_tier(&self) -> PlanTier {
        PlanTier::Pro
    }

    fn supports_interactive(&self) -> bool {
        self.config.callback_url.is_some()
    }

    async fn notify_permission_request(
        &self,
        item: &DigestItem,
        nonce: Option<&str>,
    ) -> Result<NotifyResult, Error> {
        let mut payload = self.build_payload(item, "permission_request");
        if let Some(nonce) = nonce {
            payload["nonce"] = serde_json::json!(nonce);
            if let Some(callback_url) = &self.config.callback_url {
                payload["callback_url"] =
                    serde_json::json!(format!("{}/{}?nonce={}", callback_url, item.id, nonce));
            }
        }
        self.send_with_retry(&payload, "permission_request").await?;

        Ok(NotifyResult {
            external_id: Some(item.id.to_string()),
            delivered: true,
        })
    }

    async fn notify_resolution(&self, item: &DigestItem) -> Result<(), Error> {
        let payload = self.build_payload(item, "resolution");
        self.send_with_retry(&payload, "resolution").await?;
        Ok(())
    }

    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error> {
        let payload = self.build_payload(item, "escalation");
        self.send_with_retry(&payload, "escalation").await?;
        Ok(())
    }

    async fn handle_callback(
        &self,
        payload: &CallbackPayload,
    ) -> Result<Option<ReviewAction>, Error> {
        Ok(Some(payload.action))
    }

    async fn health_check(&self) -> Result<ChannelHealth, Error> {
        let start = std::time::Instant::now();
        let resp = self.client.head(&self.config.url).send().await;

        match resp {
            Ok(r) => Ok(ChannelHealth {
                connected: r.status().is_success() || r.status().as_u16() == 405,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                error: if r.status().is_success() || r.status().as_u16() == 405 {
                    None
                } else {
                    Some(format!("HTTP {}", r.status()))
                },
            }),
            Err(e) => Ok(ChannelHealth {
                connected: false,
                latency_ms: None,
                error: Some(e.to_string()),
            }),
        }
    }
}
