// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Email notification channel.

use grith_digest::notification::{
    CallbackPayload, ChannelHealth, Error, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::{DigestItem, ReviewAction};

/// Configuration for the email notification channel.
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// SMTP server hostname.
    pub smtp_host: String,
    /// SMTP server port (587 for STARTTLS, 465 for TLS).
    pub smtp_port: u16,
    /// SMTP username.
    pub smtp_username: String,
    /// SMTP password.
    pub smtp_password: String,
    /// From address.
    pub from_address: String,
    /// Recipient addresses.
    pub to_addresses: Vec<String>,
    /// Dashboard URL for review links.
    pub dashboard_url: String,
    /// Use STARTTLS (true) or implicit TLS (false).
    pub starttls: bool,
}

/// Email notification channel using SMTP.
///
/// Sends HTML emails with item summary and dashboard link.
/// Does not support interactive callbacks.
pub struct EmailChannel {
    config: EmailConfig,
}

impl EmailChannel {
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }

    fn build_html(&self, item: &DigestItem) -> String {
        let severity_color = match item.severity {
            grith_digest::types::ScoreSeverity::Low => "#FEE75C",
            grith_digest::types::ScoreSeverity::Medium => "#E67E22",
            grith_digest::types::ScoreSeverity::High => "#ED4245",
            grith_digest::types::ScoreSeverity::Critical => "#992D22",
        };

        let filter_rows: String = item
            .filter_breakdown
            .iter()
            .map(|f| {
                format!(
                    "<tr><td>{}</td><td>{:.1}</td><td>{}</td></tr>",
                    html_escape(&f.filter_name),
                    f.score,
                    html_escape(&f.message),
                )
            })
            .collect();

        format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <div style="border-left: 4px solid {severity_color}; padding: 12px 16px; margin-bottom: 16px; background: #f8f9fa;">
    <h2 style="margin: 0 0 8px 0;">grith Permission Request</h2>
    <p style="margin: 0; color: #666;">Severity: <strong style="color: {severity_color};">{severity:?}</strong> — Score: {score:.1}</p>
  </div>

  <table style="width: 100%; border-collapse: collapse; margin-bottom: 16px;">
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Tool</strong></td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;"><code>{tool}</code></td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Arguments</strong></td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;"><code>{args}</code></td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Item ID</strong></td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;">{id}</td>
    </tr>
  </table>

  {filter_table}

  <p>
    <a href="{dashboard_url}/digest/{id}" style="display: inline-block; padding: 10px 20px; background: #5865F2; color: white; text-decoration: none; border-radius: 4px;">
      Review in Dashboard
    </a>
  </p>

  <p style="color: #999; font-size: 12px; margin-top: 24px;">
    Sent by grith notification system
  </p>
</body>
</html>"#,
            severity_color = severity_color,
            severity = item.severity,
            score = item.composite_score,
            tool = html_escape(&item.tool_call_type),
            args = html_escape(&item.arguments_summary),
            id = item.id,
            dashboard_url = self.config.dashboard_url,
            filter_table = if filter_rows.is_empty() {
                String::new()
            } else {
                format!(
                    r#"<table style="width: 100%; border-collapse: collapse; margin-bottom: 16px;">
                    <tr style="background: #f0f0f0;"><th style="padding: 8px; text-align: left;">Filter</th><th style="padding: 8px;">Score</th><th style="padding: 8px; text-align: left;">Detail</th></tr>
                    {filter_rows}
                    </table>"#
                )
            },
        )
    }
}

#[async_trait::async_trait]
impl NotificationChannel for EmailChannel {
    fn id(&self) -> &str {
        "email"
    }

    fn display_name(&self) -> &str {
        "Email (SMTP)"
    }

    fn required_tier(&self) -> PlanTier {
        PlanTier::Pro
    }

    fn supports_interactive(&self) -> bool {
        false
    }

    async fn notify_permission_request(
        &self,
        item: &DigestItem,
        _nonce: Option<&str>,
    ) -> Result<NotifyResult, Error> {
        let html = self.build_html(item);
        let subject = format!(
            "grith: {:?} review needed — {}",
            item.severity, item.tool_call_type
        );

        let config = self.config.clone();
        let to_addrs = self.config.to_addresses.clone();

        let result = tokio::task::spawn_blocking(move || {
            use lettre::message::header::ContentType;
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::{Message, SmtpTransport, Transport};

            let creds =
                Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

            let builder = if config.starttls {
                SmtpTransport::starttls_relay(&config.smtp_host)
                    .map_err(|e| Error::DeliveryFailed("email".into(), e.to_string()))?
                    .port(config.smtp_port)
            } else {
                SmtpTransport::relay(&config.smtp_host)
                    .map_err(|e| Error::DeliveryFailed("email".into(), e.to_string()))?
                    .port(config.smtp_port)
            };

            let mailer = builder.credentials(creds).build();

            for to_addr in &to_addrs {
                let email = Message::builder()
                    .from(config.from_address.parse().map_err(
                        |e: lettre::address::AddressError| {
                            Error::DeliveryFailed("email".into(), e.to_string())
                        },
                    )?)
                    .to(to_addr
                        .parse()
                        .map_err(|e: lettre::address::AddressError| {
                            Error::DeliveryFailed("email".into(), e.to_string())
                        })?)
                    .subject(&subject)
                    .header(ContentType::TEXT_HTML)
                    .body(html.clone())
                    .map_err(|e| Error::DeliveryFailed("email".into(), e.to_string()))?;

                mailer
                    .send(&email)
                    .map_err(|e| Error::DeliveryFailed("email".into(), e.to_string()))?;
            }

            Ok::<(), Error>(())
        })
        .await
        .map_err(|e| Error::DeliveryFailed("email".into(), e.to_string()))?;

        result?;

        Ok(NotifyResult {
            external_id: None,
            delivered: true,
        })
    }

    async fn notify_resolution(&self, _item: &DigestItem) -> Result<(), Error> {
        // Email doesn't support updating sent messages
        Ok(())
    }

    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error> {
        // Reuse the permission request flow with escalation subject
        let html = self.build_html(item);
        let subject = format!(
            "🚨 ESCALATED grith: {:?} — {} — IMMEDIATE REVIEW NEEDED",
            item.severity, item.tool_call_type
        );

        let config = self.config.clone();
        let to_addrs = self.config.to_addresses.clone();

        tokio::task::spawn_blocking(move || {
            use lettre::message::header::ContentType;
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::{Message, SmtpTransport, Transport};

            let creds =
                Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

            let builder = if config.starttls {
                SmtpTransport::starttls_relay(&config.smtp_host)
                    .map_err(|e| Error::DeliveryFailed("email".into(), e.to_string()))?
                    .port(config.smtp_port)
            } else {
                SmtpTransport::relay(&config.smtp_host)
                    .map_err(|e| Error::DeliveryFailed("email".into(), e.to_string()))?
                    .port(config.smtp_port)
            };

            let mailer = builder.credentials(creds).build();

            for to_addr in &to_addrs {
                let email = Message::builder()
                    .from(config.from_address.parse().map_err(
                        |e: lettre::address::AddressError| {
                            Error::DeliveryFailed("email".into(), e.to_string())
                        },
                    )?)
                    .to(to_addr
                        .parse()
                        .map_err(|e: lettre::address::AddressError| {
                            Error::DeliveryFailed("email".into(), e.to_string())
                        })?)
                    .subject(&subject)
                    .header(ContentType::TEXT_HTML)
                    .body(html.clone())
                    .map_err(|e| Error::DeliveryFailed("email".into(), e.to_string()))?;

                mailer
                    .send(&email)
                    .map_err(|e| Error::DeliveryFailed("email".into(), e.to_string()))?;
            }

            Ok::<(), Error>(())
        })
        .await
        .map_err(|e| Error::DeliveryFailed("email".into(), e.to_string()))??;

        Ok(())
    }

    async fn handle_callback(
        &self,
        _payload: &CallbackPayload,
    ) -> Result<Option<ReviewAction>, Error> {
        Ok(None)
    }

    async fn health_check(&self) -> Result<ChannelHealth, Error> {
        let config = self.config.clone();

        let result = tokio::task::spawn_blocking(move || {
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::SmtpTransport;

            let start = std::time::Instant::now();
            let creds =
                Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

            let builder = if config.starttls {
                SmtpTransport::starttls_relay(&config.smtp_host)
                    .map_err(|e| e.to_string())?
                    .port(config.smtp_port)
            } else {
                SmtpTransport::relay(&config.smtp_host)
                    .map_err(|e| e.to_string())?
                    .port(config.smtp_port)
            };

            let mailer = builder.credentials(creds).build();
            match mailer.test_connection() {
                Ok(true) => Ok(ChannelHealth {
                    connected: true,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    error: None,
                }),
                Ok(false) => Ok(ChannelHealth {
                    connected: false,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    error: Some("SMTP test connection returned false".into()),
                }),
                Err(e) => Ok(ChannelHealth {
                    connected: false,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    error: Some(e.to_string()),
                }),
            }
        })
        .await
        .map_err(|e| Error::DeliveryFailed("email".into(), e.to_string()))?;

        result.map_err(|e: String| Error::DeliveryFailed("email".into(), e))
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
