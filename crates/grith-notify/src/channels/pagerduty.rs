// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! PagerDuty incident notification channel.

use std::time::Duration;

use tracing::warn;

use grith_digest::notification::{
    CallbackPayload, ChannelHealth, Error, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::{DigestItem, ReviewAction};

/// Configuration for the PagerDuty notification channel.
#[derive(Debug, Clone)]
pub struct PagerDutyConfig {
    /// PagerDuty Events API v2 routing key (integration key).
    pub routing_key: String,
    /// Dashboard URL for review links.
    pub dashboard_url: String,
}

/// PagerDuty Events API v2 notification channel.
///
/// Triggers incidents on Critical+ items, resolves on review.
/// Uses `dedup_key` based on the item UUID for correlation.
pub struct PagerDutyChannel {
    config: PagerDutyConfig,
    client: reqwest::Client,
}

impl PagerDutyChannel {
    pub fn new(config: PagerDutyConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { config, client }
    }

    fn dedup_key(item: &DigestItem) -> String {
        format!("grith-permission-{}", item.id)
    }

    fn severity_string(item: &DigestItem) -> &'static str {
        match item.severity {
            grith_digest::types::ScoreSeverity::Low => "info",
            grith_digest::types::ScoreSeverity::Medium => "warning",
            grith_digest::types::ScoreSeverity::High => "error",
            grith_digest::types::ScoreSeverity::Critical => "critical",
        }
    }
}

#[async_trait::async_trait]
impl NotificationChannel for PagerDutyChannel {
    fn id(&self) -> &str {
        "pagerduty"
    }

    fn display_name(&self) -> &str {
        "PagerDuty"
    }

    fn required_tier(&self) -> PlanTier {
        PlanTier::Enterprise
    }

    fn supports_interactive(&self) -> bool {
        false
    }

    async fn notify_permission_request(
        &self,
        item: &DigestItem,
        _nonce: Option<&str>,
    ) -> Result<NotifyResult, Error> {
        let body = serde_json::json!({
            "routing_key": self.config.routing_key,
            "event_action": "trigger",
            "dedup_key": Self::dedup_key(item),
            "payload": {
                "summary": format!(
                    "grith: {} review needed — {} (score {:.1})",
                    Self::severity_string(item),
                    item.tool_call_type,
                    item.composite_score,
                ),
                "source": "grith",
                "severity": Self::severity_string(item),
                "component": "security-proxy",
                "group": "permission-review",
                "custom_details": {
                    "tool_call_type": item.tool_call_type,
                    "arguments_summary": item.arguments_summary,
                    "composite_score": item.composite_score,
                    "item_id": item.id.to_string(),
                    "filter_breakdown": item.filter_breakdown.iter()
                        .map(|f| format!("{}: {:.1} ({})", f.filter_name, f.score, f.message))
                        .collect::<Vec<_>>(),
                },
            },
            "links": [{
                "href": format!("{}/digest/{}", self.config.dashboard_url, item.id),
                "text": "Review in grith Dashboard",
            }],
        });

        let resp = self
            .client
            .post("https://events.pagerduty.com/v2/enqueue")
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::DeliveryFailed(
                "pagerduty".into(),
                format!("{}: {}", status, text),
            ));
        }

        let resp_json: serde_json::Value =
            resp.json().await.map_err(|e| Error::Http(e.to_string()))?;

        Ok(NotifyResult {
            external_id: resp_json["dedup_key"].as_str().map(|s| s.to_string()),
            delivered: true,
        })
    }

    async fn notify_resolution(&self, item: &DigestItem) -> Result<(), Error> {
        let body = serde_json::json!({
            "routing_key": self.config.routing_key,
            "event_action": "resolve",
            "dedup_key": Self::dedup_key(item),
        });

        let resp = self
            .client
            .post("https://events.pagerduty.com/v2/enqueue")
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            warn!(
                item_id = %item.id,
                status = %status,
                body = %text,
                "PagerDuty resolve request failed"
            );
            return Err(Error::DeliveryFailed(
                "pagerduty".into(),
                format!("{}: {}", status, text),
            ));
        }

        Ok(())
    }

    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error> {
        // Re-trigger with higher urgency (PagerDuty will update existing incident)
        self.notify_permission_request(item, None).await?;
        Ok(())
    }

    async fn handle_callback(
        &self,
        _payload: &CallbackPayload,
    ) -> Result<Option<ReviewAction>, Error> {
        Ok(None)
    }

    async fn health_check(&self) -> Result<ChannelHealth, Error> {
        // PagerDuty Events API doesn't have a health endpoint;
        // we just verify we can reach it.
        let start = std::time::Instant::now();
        let resp = self
            .client
            .post("https://events.pagerduty.com/v2/enqueue")
            .json(&serde_json::json!({}))
            .send()
            .await;

        match resp {
            Ok(r) => {
                let latency = start.elapsed().as_millis() as u64;
                // PD returns 400 for invalid payload, which means it's reachable
                Ok(ChannelHealth {
                    connected: r.status().as_u16() == 400 || r.status().is_success(),
                    latency_ms: Some(latency),
                    error: None,
                })
            }
            Err(e) => Ok(ChannelHealth {
                connected: false,
                latency_ms: None,
                error: Some(e.to_string()),
            }),
        }
    }
}
