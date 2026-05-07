// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! OpsGenie incident notification channel.

use std::time::Duration;

use grith_digest::notification::{
    CallbackPayload, ChannelHealth, Error, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::{DigestItem, ReviewAction};

/// Configuration for the Opsgenie notification channel.
#[derive(Debug, Clone)]
pub struct OpsgenieConfig {
    /// Opsgenie API key.
    pub api_key: String,
    /// Dashboard URL for review links.
    pub dashboard_url: String,
    /// Use EU endpoint (api.eu.opsgenie.com) instead of US.
    pub eu_endpoint: bool,
}

/// Opsgenie Alert API notification channel.
///
/// Creates alerts on high-severity items, closes them on resolution.
pub struct OpsgenieChannel {
    config: OpsgenieConfig,
    client: reqwest::Client,
}

impl OpsgenieChannel {
    pub fn new(config: OpsgenieConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { config, client }
    }

    fn base_url(&self) -> &str {
        if self.config.eu_endpoint {
            "https://api.eu.opsgenie.com/v2"
        } else {
            "https://api.opsgenie.com/v2"
        }
    }

    fn alert_alias(item: &DigestItem) -> String {
        format!("grith-{}", item.id)
    }

    fn priority(item: &DigestItem) -> &'static str {
        match item.severity {
            grith_digest::types::ScoreSeverity::Low => "P4",
            grith_digest::types::ScoreSeverity::Medium => "P3",
            grith_digest::types::ScoreSeverity::High => "P2",
            grith_digest::types::ScoreSeverity::Critical => "P1",
        }
    }
}

#[async_trait::async_trait]
impl NotificationChannel for OpsgenieChannel {
    fn id(&self) -> &str {
        "opsgenie"
    }

    fn display_name(&self) -> &str {
        "Opsgenie"
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
            "message": format!(
                "grith: {} review needed — {}",
                format!("{:?}", item.severity),
                item.tool_call_type,
            ),
            "alias": Self::alert_alias(item),
            "description": format!(
                "Tool: {}\nScore: {:.1}\nArguments: {}\n\nDashboard: {}/digest/{}",
                item.tool_call_type,
                item.composite_score,
                item.arguments_summary,
                self.config.dashboard_url,
                item.id,
            ),
            "priority": Self::priority(item),
            "source": "grith",
            "tags": ["grith", "permission-review"],
            "details": {
                "item_id": item.id.to_string(),
                "tool_call_type": &item.tool_call_type,
                "composite_score": item.composite_score.to_string(),
            },
        });

        let resp = self
            .client
            .post(format!("{}/alerts", self.base_url()))
            .header("Authorization", format!("GenieKey {}", self.config.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::DeliveryFailed(
                "opsgenie".into(),
                format!("{}: {}", status, text),
            ));
        }

        let resp_json: serde_json::Value =
            resp.json().await.map_err(|e| Error::Http(e.to_string()))?;

        Ok(NotifyResult {
            external_id: resp_json["requestId"].as_str().map(|s| s.to_string()),
            delivered: true,
        })
    }

    async fn notify_resolution(&self, item: &DigestItem) -> Result<(), Error> {
        let alias = Self::alert_alias(item);
        let body = serde_json::json!({
            "source": "grith",
            "note": format!(
                "Resolved via grith: {}",
                item.review_action.as_deref().unwrap_or("resolved")
            ),
        });

        let resp = self
            .client
            .post(format!(
                "{}/alerts/{}/close?identifierType=alias",
                self.base_url(),
                alias
            ))
            .header("Authorization", format!("GenieKey {}", self.config.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !resp.status().is_success() {
            tracing::warn!(
                status = %resp.status(),
                "failed to close Opsgenie alert"
            );
        }

        Ok(())
    }

    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error> {
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
        let start = std::time::Instant::now();
        let resp = self
            .client
            .get(format!("{}/heartbeats", self.base_url()))
            .header("Authorization", format!("GenieKey {}", self.config.api_key))
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
