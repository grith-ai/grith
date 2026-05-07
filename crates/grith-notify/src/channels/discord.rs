// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Discord webhook notification channel.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tracing::warn;
use uuid::Uuid;

use grith_digest::notification::{
    CallbackPayload, ChannelHealth, Error, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::{DigestItem, ReviewAction};

/// Configuration for the Discord notification channel.
#[derive(Debug, Clone)]
pub struct DiscordConfig {
    /// Bot token for authenticated API access (interactive mode).
    pub bot_token: Option<String>,
    /// Webhook URL for one-way notifications.
    pub webhook_url: Option<String>,
    /// Channel ID for bot mode.
    pub channel_id: Option<String>,
    /// Dashboard URL for review links.
    pub dashboard_url: String,
}

struct MessageRecord {
    channel_id: String,
    message_id: String,
}

/// Discord notification channel.
///
/// Two modes:
/// - **Bot mode**: Posts embeds with message components (buttons).
/// - **Webhook mode**: Posts embeds via webhook (one-way, no buttons).
pub struct DiscordChannel {
    config: DiscordConfig,
    client: reqwest::Client,
    messages: Mutex<HashMap<Uuid, MessageRecord>>,
}

impl DiscordChannel {
    pub fn new(config: DiscordConfig) -> Self {
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

    fn severity_color(&self, item: &DigestItem) -> u32 {
        match item.severity {
            grith_digest::types::ScoreSeverity::Low => 0xFEE75C, // yellow
            grith_digest::types::ScoreSeverity::Medium => 0xE67E22, // orange
            grith_digest::types::ScoreSeverity::High => 0xED4245, // red
            grith_digest::types::ScoreSeverity::Critical => 0x992D22, // dark red
        }
    }

    fn build_embed(&self, item: &DigestItem) -> serde_json::Value {
        let mut fields = vec![
            serde_json::json!({
                "name": "Tool",
                "value": format!("`{}`", item.tool_call_type),
                "inline": true,
            }),
            serde_json::json!({
                "name": "Score",
                "value": format!("{:.1} ({:?})", item.composite_score, item.severity),
                "inline": true,
            }),
            serde_json::json!({
                "name": "Arguments",
                "value": format!("```{}```", item.arguments_summary),
                "inline": false,
            }),
        ];

        if !item.filter_breakdown.is_empty() {
            let breakdown: String = item
                .filter_breakdown
                .iter()
                .map(|f| format!("• **{}** ({:.1}): {}", f.filter_name, f.score, f.message))
                .collect::<Vec<_>>()
                .join("\n");
            fields.push(serde_json::json!({
                "name": "Filter Breakdown",
                "value": breakdown,
                "inline": false,
            }));
        }

        serde_json::json!({
            "title": "grith Permission Request",
            "color": self.severity_color(item),
            "fields": fields,
            "footer": { "text": format!("Item {}", item.id) },
            "timestamp": item.created_at.to_rfc3339(),
        })
    }

    fn build_components(&self, item: &DigestItem, nonce: &str) -> serde_json::Value {
        serde_json::json!([{
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "style": 3,
                    "label": "Approve",
                    "custom_id": format!("grith_approve:{}:{}", item.id, nonce),
                },
                {
                    "type": 2,
                    "style": 4,
                    "label": "Deny",
                    "custom_id": format!("grith_deny:{}:{}", item.id, nonce),
                },
                {
                    "type": 2,
                    "style": 5,
                    "label": "Dashboard",
                    "url": format!("{}/digest/{}", self.config.dashboard_url, item.id),
                },
            ]
        }])
    }
}

#[async_trait::async_trait]
impl NotificationChannel for DiscordChannel {
    fn id(&self) -> &str {
        "discord"
    }

    fn display_name(&self) -> &str {
        "Discord"
    }

    fn required_tier(&self) -> PlanTier {
        PlanTier::Pro
    }

    fn supports_interactive(&self) -> bool {
        self.config.bot_token.is_some()
    }

    async fn notify_permission_request(
        &self,
        item: &DigestItem,
        nonce: Option<&str>,
    ) -> Result<NotifyResult, Error> {
        let embed = self.build_embed(item);

        if let Some(webhook_url) = &self.config.webhook_url {
            // Webhook mode (one-way)
            let body = serde_json::json!({
                "embeds": [embed],
                "username": "grith",
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
                    "discord".into(),
                    format!("webhook returned {}", resp.status()),
                ));
            }

            Ok(NotifyResult {
                external_id: None,
                delivered: true,
            })
        } else if let (Some(bot_token), Some(channel_id)) =
            (&self.config.bot_token, &self.config.channel_id)
        {
            // Bot mode with components
            let effective_nonce = nonce.unwrap_or("none");
            let components = self.build_components(item, effective_nonce);

            let body = serde_json::json!({
                "embeds": [embed],
                "components": components,
            });

            let resp = self
                .client
                .post(format!(
                    "https://discord.com/api/v10/channels/{}/messages",
                    channel_id
                ))
                .header("Authorization", format!("Bot {}", bot_token))
                .json(&body)
                .send()
                .await
                .map_err(|e| Error::Http(e.to_string()))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::DeliveryFailed(
                    "discord".into(),
                    format!("{}: {}", status, text),
                ));
            }

            let resp_json: serde_json::Value =
                resp.json().await.map_err(|e| Error::Http(e.to_string()))?;

            let message_id = resp_json["id"].as_str().unwrap_or("").to_string();

            if let Ok(mut msgs) = self.messages.lock() {
                msgs.insert(
                    item.id,
                    MessageRecord {
                        channel_id: channel_id.clone(),
                        message_id: message_id.clone(),
                    },
                );
            }

            Ok(NotifyResult {
                external_id: Some(message_id),
                delivered: true,
            })
        } else {
            Err(Error::ChannelNotConfigured(
                "discord: neither webhook_url nor bot_token+channel_id configured".into(),
            ))
        }
    }

    async fn notify_resolution(&self, item: &DigestItem) -> Result<(), Error> {
        let record = self.messages.lock().ok().and_then(|msgs| {
            msgs.get(&item.id)
                .map(|r| (r.channel_id.clone(), r.message_id.clone()))
        });

        if let (Some(bot_token), Some((channel_id, message_id))) = (&self.config.bot_token, record)
        {
            let action = item.review_action.as_deref().unwrap_or("resolved");
            let embed = serde_json::json!({
                "title": format!("grith: {} — {}", item.tool_call_type, action),
                "color": 0x57F287,
                "footer": { "text": format!("Item {}", item.id) },
            });

            let body = serde_json::json!({
                "embeds": [embed],
                "components": [],
            });

            if let Err(e) = self
                .client
                .patch(format!(
                    "https://discord.com/api/v10/channels/{}/messages/{}",
                    channel_id, message_id
                ))
                .header("Authorization", format!("Bot {}", bot_token))
                .json(&body)
                .send()
                .await
            {
                warn!(
                    item_id = %item.id,
                    error = %e,
                    "failed to update Discord message on resolution"
                );
            }
        }

        Ok(())
    }

    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error> {
        let embed = serde_json::json!({
            "title": "🚨 ESCALATED — Immediate Review Needed",
            "description": format!(
                "`{}` (score {:.1})\n```{}```",
                item.tool_call_type, item.composite_score, item.arguments_summary,
            ),
            "color": 0x992D22,
        });

        if let Some(webhook_url) = &self.config.webhook_url {
            let body = serde_json::json!({
                "embeds": [embed],
                "username": "grith",
            });

            self.client
                .post(webhook_url)
                .json(&body)
                .send()
                .await
                .map_err(|e| Error::Http(e.to_string()))?;
        } else if let (Some(bot_token), Some(channel_id)) =
            (&self.config.bot_token, &self.config.channel_id)
        {
            let body = serde_json::json!({ "embeds": [embed] });

            self.client
                .post(format!(
                    "https://discord.com/api/v10/channels/{}/messages",
                    channel_id
                ))
                .header("Authorization", format!("Bot {}", bot_token))
                .json(&body)
                .send()
                .await
                .map_err(|e| Error::Http(e.to_string()))?;
        }

        Ok(())
    }

    async fn handle_callback(
        &self,
        payload: &CallbackPayload,
    ) -> Result<Option<ReviewAction>, Error> {
        Ok(Some(payload.action))
    }

    async fn health_check(&self) -> Result<ChannelHealth, Error> {
        if self.config.webhook_url.is_some() {
            return Ok(ChannelHealth {
                connected: true,
                latency_ms: None,
                error: None,
            });
        }

        if let Some(bot_token) = &self.config.bot_token {
            let start = std::time::Instant::now();
            let resp = self
                .client
                .get("https://discord.com/api/v10/users/@me")
                .header("Authorization", format!("Bot {}", bot_token))
                .send()
                .await;

            match resp {
                Ok(r) => {
                    let latency = start.elapsed().as_millis() as u64;
                    Ok(ChannelHealth {
                        connected: r.status().is_success(),
                        latency_ms: Some(latency),
                        error: if r.status().is_success() {
                            None
                        } else {
                            Some(format!("status {}", r.status()))
                        },
                    })
                }
                Err(e) => Ok(ChannelHealth {
                    connected: false,
                    latency_ms: None,
                    error: Some(e.to_string()),
                }),
            }
        } else {
            Ok(ChannelHealth {
                connected: false,
                latency_ms: None,
                error: Some("not configured".into()),
            })
        }
    }
}
