// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Slack webhook notification channel.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tracing::warn;
use uuid::Uuid;

use grith_digest::notification::{
    CallbackPayload, ChannelHealth, Error, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::{DigestItem, ReviewAction};

/// Configuration for the Slack notification channel.
#[derive(Debug, Clone)]
pub struct SlackConfig {
    /// Bot token (xoxb-...) for chat.postMessage / chat.update.
    pub bot_token: String,
    /// Default channel ID to post to.
    pub channel_id: String,
    /// Optional webhook URL for one-way mode (no interactive buttons).
    pub webhook_url: Option<String>,
    /// Dashboard URL for "Review in Dashboard" links.
    pub dashboard_url: String,
}

/// Tracks posted messages so we can update them on resolution.
struct MessageRecord {
    channel: String,
    ts: String,
}

/// Slack notification channel.
///
/// Two modes:
/// - **Bot mode** (bot_token set): Posts via `chat.postMessage` with Block Kit
///   interactive buttons. Updates messages via `chat.update` on resolution.
/// - **Webhook mode** (webhook_url set): One-way POST to Slack Incoming Webhook.
pub struct SlackChannel {
    config: SlackConfig,
    client: reqwest::Client,
    /// item_id → message record for updates
    messages: Mutex<HashMap<Uuid, MessageRecord>>,
}

impl SlackChannel {
    pub fn new(config: SlackConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            config,
            client,
            messages: Mutex::new(HashMap::new()),
        }
    }

    fn build_blocks(&self, item: &DigestItem, nonce: Option<&str>) -> serde_json::Value {
        let severity_emoji = match item.severity {
            grith_digest::types::ScoreSeverity::Low => ":large_yellow_circle:",
            grith_digest::types::ScoreSeverity::Medium => ":large_orange_circle:",
            grith_digest::types::ScoreSeverity::High => ":red_circle:",
            grith_digest::types::ScoreSeverity::Critical => ":rotating_light:",
        };

        let mut blocks = vec![
            serde_json::json!({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": format!("{} grith Permission Request", severity_emoji),
                }
            }),
            serde_json::json!({
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": format!("*Tool:* `{}`", item.tool_call_type),
                    },
                    {
                        "type": "mrkdwn",
                        "text": format!("*Score:* {:.1} ({:?})", item.composite_score, item.severity),
                    },
                ]
            }),
            serde_json::json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("*Arguments:*\n```{}```", item.arguments_summary),
                }
            }),
        ];

        // Filter breakdown
        if !item.filter_breakdown.is_empty() {
            let breakdown: String = item
                .filter_breakdown
                .iter()
                .map(|f| format!("• {} ({:.1}): {}", f.filter_name, f.score, f.message))
                .collect::<Vec<_>>()
                .join("\n");
            blocks.push(serde_json::json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("*Filter Breakdown:*\n{}", breakdown),
                }
            }));
        }

        // Interactive buttons (only in bot mode with nonce)
        if let Some(nonce) = nonce {
            blocks.push(serde_json::json!({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": { "type": "plain_text", "text": "Approve" },
                        "style": "primary",
                        "action_id": "grith_approve",
                        "value": format!("{}:{}", item.id, nonce),
                    },
                    {
                        "type": "button",
                        "text": { "type": "plain_text", "text": "Deny" },
                        "style": "danger",
                        "action_id": "grith_deny",
                        "value": format!("{}:{}", item.id, nonce),
                    },
                    {
                        "type": "button",
                        "text": { "type": "plain_text", "text": "Review in Dashboard" },
                        "url": format!("{}/digest/{}", self.config.dashboard_url, item.id),
                        "action_id": "grith_dashboard",
                    },
                ]
            }));
        } else {
            blocks.push(serde_json::json!({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": { "type": "plain_text", "text": "Review in Dashboard" },
                        "url": format!("{}/digest/{}", self.config.dashboard_url, item.id),
                        "action_id": "grith_dashboard",
                    },
                ]
            }));
        }

        serde_json::json!(blocks)
    }

    fn build_resolution_blocks(&self, item: &DigestItem) -> serde_json::Value {
        let action = item.review_action.as_deref().unwrap_or("resolved");
        let reviewer = item.reviewer_notes.as_deref().unwrap_or("");

        serde_json::json!([
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!(
                        ":white_check_mark: *Resolved:* `{}` — *{}*{}",
                        item.tool_call_type,
                        action,
                        if reviewer.is_empty() { String::new() } else { format!("\n_{}_", reviewer) },
                    ),
                }
            }
        ])
    }

    async fn post_via_bot(
        &self,
        item: &DigestItem,
        nonce: Option<&str>,
    ) -> Result<NotifyResult, Error> {
        let blocks = self.build_blocks(item, nonce);

        let body = serde_json::json!({
            "channel": self.config.channel_id,
            "text": format!("grith: {} review needed for {}", format!("{:?}", item.severity), item.tool_call_type),
            "blocks": blocks,
        });

        let resp = self
            .client
            .post("https://slack.com/api/chat.postMessage")
            .bearer_auth(&self.config.bot_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        let resp_json: serde_json::Value =
            resp.json().await.map_err(|e| Error::Http(e.to_string()))?;

        if resp_json["ok"].as_bool() != Some(true) {
            let err = resp_json["error"]
                .as_str()
                .unwrap_or("unknown error")
                .to_string();
            return Err(Error::DeliveryFailed("slack".into(), err));
        }

        let ts = resp_json["ts"].as_str().unwrap_or("").to_string();
        let channel = resp_json["channel"]
            .as_str()
            .unwrap_or(&self.config.channel_id)
            .to_string();

        // Store for later update
        if let Ok(mut msgs) = self.messages.lock() {
            msgs.insert(
                item.id,
                MessageRecord {
                    channel: channel.clone(),
                    ts: ts.clone(),
                },
            );
        }

        Ok(NotifyResult {
            external_id: Some(ts),
            delivered: true,
        })
    }

    async fn post_via_webhook(&self, item: &DigestItem) -> Result<NotifyResult, Error> {
        let webhook_url = self
            .config
            .webhook_url
            .as_ref()
            .ok_or_else(|| Error::ChannelNotConfigured("slack webhook_url not set".into()))?;

        let blocks = self.build_blocks(item, None);

        let body = serde_json::json!({
            "text": format!("grith: {:?} review needed for {}", item.severity, item.tool_call_type),
            "blocks": blocks,
        });

        let resp = self
            .client
            .post(webhook_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Error::DeliveryFailed(
                "slack".into(),
                format!("webhook returned {}", resp.status()),
            ));
        }

        Ok(NotifyResult {
            external_id: None,
            delivered: true,
        })
    }
}

#[async_trait::async_trait]
impl NotificationChannel for SlackChannel {
    fn id(&self) -> &str {
        "slack"
    }

    fn display_name(&self) -> &str {
        "Slack"
    }

    fn required_tier(&self) -> PlanTier {
        PlanTier::Pro
    }

    fn supports_interactive(&self) -> bool {
        // Interactive if a bot token is configured (even if a webhook is also
        // set). The previous check `webhook_url.is_none()` incorrectly
        // returned false when both were configured.
        !self.config.bot_token.is_empty()
    }

    async fn notify_permission_request(
        &self,
        item: &DigestItem,
        nonce: Option<&str>,
    ) -> Result<NotifyResult, Error> {
        if self.config.webhook_url.is_some() {
            self.post_via_webhook(item).await
        } else {
            self.post_via_bot(item, nonce).await
        }
    }

    async fn notify_resolution(&self, item: &DigestItem) -> Result<(), Error> {
        // Update the original message if we have a record of it
        let record = self.messages.lock().ok().and_then(|msgs| {
            msgs.get(&item.id)
                .map(|r| (r.channel.clone(), r.ts.clone()))
        });

        if let Some((channel, ts)) = record {
            let blocks = self.build_resolution_blocks(item);
            let body = serde_json::json!({
                "channel": channel,
                "ts": ts,
                "text": format!("grith: {} resolved", item.tool_call_type),
                "blocks": blocks,
            });

            let resp = self
                .client
                .post("https://slack.com/api/chat.update")
                .bearer_auth(&self.config.bot_token)
                .json(&body)
                .send()
                .await
                .map_err(|e| Error::Http(e.to_string()))?;

            let resp_json: serde_json::Value =
                resp.json().await.map_err(|e| Error::Http(e.to_string()))?;

            if resp_json["ok"].as_bool() != Some(true) {
                warn!(
                    error = resp_json["error"].as_str().unwrap_or("unknown"),
                    "failed to update Slack message"
                );
            }
        }

        Ok(())
    }

    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error> {
        let text = format!(
            ":rotating_light: *ESCALATED* — `{}` (score {:.1}) needs immediate review\n{}",
            item.tool_call_type, item.composite_score, item.arguments_summary,
        );

        let body = serde_json::json!({
            "channel": self.config.channel_id,
            "text": &text,
            "blocks": [{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": text,
                }
            }],
        });

        let resp = self
            .client
            .post("https://slack.com/api/chat.postMessage")
            .bearer_auth(&self.config.bot_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        let resp_json: serde_json::Value =
            resp.json().await.map_err(|e| Error::Http(e.to_string()))?;

        if resp_json["ok"].as_bool() != Some(true) {
            let err = resp_json["error"]
                .as_str()
                .unwrap_or("unknown error")
                .to_string();
            return Err(Error::DeliveryFailed("slack".into(), err));
        }

        Ok(())
    }

    async fn handle_callback(
        &self,
        payload: &CallbackPayload,
    ) -> Result<Option<ReviewAction>, Error> {
        // The dispatcher handles nonce validation; we just return the action
        Ok(Some(payload.action))
    }

    async fn health_check(&self) -> Result<ChannelHealth, Error> {
        if let Some(webhook_url) = &self.config.webhook_url {
            // Attempt a HEAD request to the webhook URL to verify connectivity.
            // Slack webhooks may not support HEAD, so we treat both success and
            // 405 Method Not Allowed as "connected" (the endpoint is reachable).
            let start = std::time::Instant::now();
            match self.client.head(webhook_url).send().await {
                Ok(r) => {
                    let latency = start.elapsed().as_millis() as u64;
                    let reachable = r.status().is_success()
                        || r.status().as_u16() == 405
                        || r.status().as_u16() == 400;
                    return Ok(ChannelHealth {
                        connected: reachable,
                        latency_ms: Some(latency),
                        error: if reachable {
                            None
                        } else {
                            Some(format!("webhook returned HTTP {}", r.status()))
                        },
                    });
                }
                Err(e) => {
                    return Ok(ChannelHealth {
                        connected: false,
                        latency_ms: None,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        let start = std::time::Instant::now();
        let resp = self
            .client
            .post("https://slack.com/api/auth.test")
            .bearer_auth(&self.config.bot_token)
            .send()
            .await;

        match resp {
            Ok(r) => {
                let latency = start.elapsed().as_millis() as u64;
                let body: serde_json::Value = r.json().await.unwrap_or_default();
                if body["ok"].as_bool() == Some(true) {
                    Ok(ChannelHealth {
                        connected: true,
                        latency_ms: Some(latency),
                        error: None,
                    })
                } else {
                    Ok(ChannelHealth {
                        connected: false,
                        latency_ms: Some(latency),
                        error: Some(
                            body["error"]
                                .as_str()
                                .unwrap_or("auth.test failed")
                                .to_string(),
                        ),
                    })
                }
            }
            Err(e) => Ok(ChannelHealth {
                connected: false,
                latency_ms: None,
                error: Some(e.to_string()),
            }),
        }
    }
}
