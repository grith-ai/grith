// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Microsoft Teams webhook notification channel.

use std::time::Duration;

use grith_digest::notification::{
    CallbackPayload, ChannelHealth, Error, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::{DigestItem, ReviewAction};

/// Configuration for the Microsoft Teams notification channel.
#[derive(Debug, Clone)]
pub struct TeamsConfig {
    /// Incoming Webhook URL for the Teams channel.
    pub webhook_url: String,
    /// Dashboard URL for review links.
    pub dashboard_url: String,
}

/// Microsoft Teams notification channel via Incoming Webhook.
///
/// Posts Adaptive Card JSON. One-way only (no interactive buttons without
/// a Bot registration).
pub struct TeamsChannel {
    config: TeamsConfig,
    client: reqwest::Client,
}

impl TeamsChannel {
    pub fn new(config: TeamsConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { config, client }
    }

    fn build_adaptive_card(&self, item: &DigestItem, is_escalation: bool) -> serde_json::Value {
        let severity_color = match item.severity {
            grith_digest::types::ScoreSeverity::Low => "warning",
            grith_digest::types::ScoreSeverity::Medium => "warning",
            grith_digest::types::ScoreSeverity::High => "attention",
            grith_digest::types::ScoreSeverity::Critical => "attention",
        };

        let title = if is_escalation {
            "ESCALATED — Immediate Review Needed"
        } else {
            "grith Permission Request"
        };

        let mut facts = vec![
            serde_json::json!({ "title": "Tool", "value": &item.tool_call_type }),
            serde_json::json!({ "title": "Score", "value": format!("{:.1} ({:?})", item.composite_score, item.severity) }),
            serde_json::json!({ "title": "Arguments", "value": &item.arguments_summary }),
        ];

        for f in &item.filter_breakdown {
            facts.push(serde_json::json!({
                "title": &f.filter_name,
                "value": format!("{:.1}: {}", f.score, f.message),
            }));
        }

        serde_json::json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": null,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Large",
                            "weight": "Bolder",
                            "text": title,
                            "color": severity_color,
                        },
                        {
                            "type": "FactSet",
                            "facts": facts,
                        },
                    ],
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "Review in Dashboard",
                            "url": format!("{}/digest/{}", self.config.dashboard_url, item.id),
                        },
                    ],
                }
            }]
        })
    }
}

#[async_trait::async_trait]
impl NotificationChannel for TeamsChannel {
    fn id(&self) -> &str {
        "teams"
    }

    fn display_name(&self) -> &str {
        "Microsoft Teams"
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
        let card = self.build_adaptive_card(item, false);

        let resp = self
            .client
            .post(&self.config.webhook_url)
            .json(&card)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Error::DeliveryFailed(
                "teams".into(),
                format!("webhook returned {}", resp.status()),
            ));
        }

        Ok(NotifyResult {
            external_id: None,
            delivered: true,
        })
    }

    async fn notify_resolution(&self, _item: &DigestItem) -> Result<(), Error> {
        // Teams Incoming Webhooks don't support updating messages
        Ok(())
    }

    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error> {
        let card = self.build_adaptive_card(item, true);

        self.client
            .post(&self.config.webhook_url)
            .json(&card)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        Ok(())
    }

    async fn handle_callback(
        &self,
        _payload: &CallbackPayload,
    ) -> Result<Option<ReviewAction>, Error> {
        Ok(None)
    }

    async fn health_check(&self) -> Result<ChannelHealth, Error> {
        // Attempt a HEAD request to the webhook URL to verify connectivity.
        // Teams webhooks may not support HEAD, so we treat both success and
        // 405 Method Not Allowed as "connected" (the endpoint is reachable).
        let start = std::time::Instant::now();
        match self.client.head(&self.config.webhook_url).send().await {
            Ok(r) => {
                let latency = start.elapsed().as_millis() as u64;
                // Teams returns 400 for empty/HEAD requests, which still means reachable.
                let reachable = r.status().is_success()
                    || r.status().as_u16() == 405
                    || r.status().as_u16() == 400;
                Ok(ChannelHealth {
                    connected: reachable,
                    latency_ms: Some(latency),
                    error: if reachable {
                        None
                    } else {
                        Some(format!("webhook returned HTTP {}", r.status()))
                    },
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
