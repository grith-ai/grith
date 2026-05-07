// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! WhatsApp Business API notification channel.

use std::time::Duration;

use grith_digest::notification::{
    CallbackPayload, ChannelHealth, Error, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::{DigestItem, ReviewAction};

/// Default WhatsApp Cloud API version. Override via `WhatsAppConfig::api_version`.
const DEFAULT_API_VERSION: &str = "v18.0";

/// Configuration for the WhatsApp Cloud API notification channel.
#[derive(Debug, Clone)]
pub struct WhatsAppConfig {
    /// WhatsApp Cloud API access token.
    pub access_token: String,
    /// Phone number ID (the business number).
    pub phone_number_id: String,
    /// Recipient phone number (with country code, e.g. "+1234567890").
    pub recipient_number: String,
    /// Dashboard URL for review links.
    pub dashboard_url: String,
    /// WhatsApp Cloud API version (e.g. "v18.0", "v19.0").
    /// Defaults to `DEFAULT_API_VERSION` if not set.
    pub api_version: Option<String>,
}

/// WhatsApp Cloud API notification channel.
///
/// Sends interactive messages with quick reply buttons for approve/deny.
pub struct WhatsAppChannel {
    config: WhatsAppConfig,
    client: reqwest::Client,
}

impl WhatsAppChannel {
    pub fn new(config: WhatsAppConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { config, client }
    }

    fn api_version(&self) -> &str {
        self.config
            .api_version
            .as_deref()
            .unwrap_or(DEFAULT_API_VERSION)
    }

    fn api_url(&self) -> String {
        format!(
            "https://graph.facebook.com/{}/{}/messages",
            self.api_version(),
            self.config.phone_number_id
        )
    }

    fn format_text(&self, item: &DigestItem) -> String {
        format!(
            "*grith Permission Request*\n\n\
             *Severity:* {:?}\n\
             *Tool:* `{}`\n\
             *Score:* {:.1}\n\
             *Args:* {}\n\n\
             Review: {}/digest/{}",
            item.severity,
            item.tool_call_type,
            item.composite_score,
            item.arguments_summary,
            self.config.dashboard_url,
            item.id,
        )
    }
}

#[async_trait::async_trait]
impl NotificationChannel for WhatsAppChannel {
    fn id(&self) -> &str {
        "whatsapp"
    }

    fn display_name(&self) -> &str {
        "WhatsApp"
    }

    fn required_tier(&self) -> PlanTier {
        PlanTier::Enterprise
    }

    fn supports_interactive(&self) -> bool {
        true
    }

    async fn notify_permission_request(
        &self,
        item: &DigestItem,
        nonce: Option<&str>,
    ) -> Result<NotifyResult, Error> {
        let effective_nonce = nonce.unwrap_or("none");
        let body = serde_json::json!({
            "messaging_product": "whatsapp",
            "to": self.config.recipient_number,
            "type": "interactive",
            "interactive": {
                "type": "button",
                "header": {
                    "type": "text",
                    "text": format!("{:?} — grith Review", item.severity),
                },
                "body": {
                    "text": self.format_text(item),
                },
                "action": {
                    "buttons": [
                        {
                            "type": "reply",
                            "reply": {
                                "id": format!("approve:{}:{}", item.id, effective_nonce),
                                "title": "Approve",
                            }
                        },
                        {
                            "type": "reply",
                            "reply": {
                                "id": format!("deny:{}:{}", item.id, effective_nonce),
                                "title": "Deny",
                            }
                        },
                    ]
                }
            }
        });

        let resp = self
            .client
            .post(self.api_url())
            .bearer_auth(&self.config.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::DeliveryFailed(
                "whatsapp".into(),
                format!("{}: {}", status, text),
            ));
        }

        let resp_json: serde_json::Value =
            resp.json().await.map_err(|e| Error::Http(e.to_string()))?;

        let message_id = resp_json["messages"][0]["id"]
            .as_str()
            .map(|s| s.to_string());

        Ok(NotifyResult {
            external_id: message_id,
            delivered: true,
        })
    }

    async fn notify_resolution(&self, item: &DigestItem) -> Result<(), Error> {
        let action = item.review_action.as_deref().unwrap_or("resolved");
        let body = serde_json::json!({
            "messaging_product": "whatsapp",
            "to": self.config.recipient_number,
            "type": "text",
            "text": {
                "body": format!(
                    "✅ *Resolved:* `{}` — *{}*",
                    item.tool_call_type, action,
                ),
            }
        });

        self.client
            .post(self.api_url())
            .bearer_auth(&self.config.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        Ok(())
    }

    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error> {
        let body = serde_json::json!({
            "messaging_product": "whatsapp",
            "to": self.config.recipient_number,
            "type": "text",
            "text": {
                "body": format!(
                    "🚨 *ESCALATED* — `{}` (score {:.1})\n{}\n\n_Immediate review required_\n\nReview: {}/digest/{}",
                    item.tool_call_type,
                    item.composite_score,
                    item.arguments_summary,
                    self.config.dashboard_url,
                    item.id,
                ),
            }
        });

        self.client
            .post(self.api_url())
            .bearer_auth(&self.config.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

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
        let resp = self
            .client
            .get(format!(
                "https://graph.facebook.com/{}/{}",
                self.api_version(),
                self.config.phone_number_id
            ))
            .bearer_auth(&self.config.access_token)
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
                        Some(format!("HTTP {}", r.status()))
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
