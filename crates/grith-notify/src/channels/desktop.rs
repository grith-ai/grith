// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Desktop notification channel using OS-native notifications.

use grith_digest::notification::{
    CallbackPayload, ChannelHealth, Error, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::{DigestItem, ReviewAction};

/// Desktop OS notification channel.
///
/// Shows native desktop notifications using `notify-rust`. Click action opens
/// the dashboard URL in the browser.
pub struct DesktopChannel {
    dashboard_url: String,
}

impl DesktopChannel {
    pub fn new(dashboard_url: String) -> Self {
        Self { dashboard_url }
    }
}

#[async_trait::async_trait]
impl NotificationChannel for DesktopChannel {
    fn id(&self) -> &str {
        "desktop"
    }

    fn display_name(&self) -> &str {
        "Desktop Notifications"
    }

    fn required_tier(&self) -> PlanTier {
        PlanTier::Community
    }

    fn supports_interactive(&self) -> bool {
        false
    }

    async fn notify_permission_request(
        &self,
        item: &DigestItem,
        _nonce: Option<&str>,
    ) -> Result<NotifyResult, Error> {
        let title = format!("grith: {} review needed", item.severity_label());
        let body = format!(
            "{}\nScore: {:.1} | {}\nReview in dashboard: {}",
            item.tool_call_type, item.composite_score, item.arguments_summary, self.dashboard_url,
        );

        // notify-rust is sync, run in blocking task
        let dashboard_url = self.dashboard_url.clone();
        let result = tokio::task::spawn_blocking(move || {
            #[cfg(not(target_os = "windows"))]
            {
                let _ = notify_rust::Notification::new()
                    .summary(&title)
                    .body(&body)
                    .icon("dialog-warning")
                    .timeout(notify_rust::Timeout::Milliseconds(10000))
                    .show();
            }
            #[cfg(target_os = "windows")]
            {
                let _ = notify_rust::Notification::new()
                    .summary(&title)
                    .body(&body)
                    .show();
            }
            let _ = open::that(&dashboard_url);
        })
        .await;

        match result {
            Ok(()) => Ok(NotifyResult {
                external_id: None,
                delivered: true,
            }),
            Err(e) => Err(Error::DeliveryFailed("desktop".into(), e.to_string())),
        }
    }

    async fn notify_resolution(&self, item: &DigestItem) -> Result<(), Error> {
        let status = item.review_action.as_deref().unwrap_or("resolved");
        let title = format!("grith: {} {}", item.tool_call_type, status);
        let body = format!("Item {} has been {status}", item.id);

        tokio::task::spawn_blocking(move || {
            let _ = notify_rust::Notification::new()
                .summary(&title)
                .body(&body)
                .icon("dialog-information")
                .timeout(notify_rust::Timeout::Milliseconds(5000))
                .show();
        })
        .await
        .map_err(|e| Error::DeliveryFailed("desktop".into(), e.to_string()))?;

        Ok(())
    }

    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error> {
        let title = "grith: ESCALATED - Immediate review needed";
        let body = format!(
            "ESCALATED: {} (score {:.1})\n{}",
            item.tool_call_type, item.composite_score, item.arguments_summary,
        );

        let title = title.to_string();
        tokio::task::spawn_blocking(move || {
            let _ = notify_rust::Notification::new()
                .summary(&title)
                .body(&body)
                .icon("dialog-error")
                .urgency(notify_rust::Urgency::Critical)
                .timeout(notify_rust::Timeout::Never)
                .show();
        })
        .await
        .map_err(|e| Error::DeliveryFailed("desktop".into(), e.to_string()))?;

        Ok(())
    }

    async fn handle_callback(
        &self,
        _payload: &CallbackPayload,
    ) -> Result<Option<ReviewAction>, Error> {
        // Desktop doesn't support interactive callbacks
        Ok(None)
    }

    async fn health_check(&self) -> Result<ChannelHealth, Error> {
        // Check whether a display server is available. On headless servers
        // (e.g. CI, containers) desktop notifications will silently fail.
        let has_display = has_display_server();
        Ok(ChannelHealth {
            connected: has_display,
            latency_ms: None,
            error: if has_display {
                None
            } else {
                Some("no display server detected (headless environment)".into())
            },
        })
    }
}

/// Check whether a display server is available on the current platform.
fn has_display_server() -> bool {
    #[cfg(target_os = "linux")]
    {
        // On Linux, check for DISPLAY (X11) or WAYLAND_DISPLAY (Wayland).
        std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        // macOS always has a display when a user session is running.
        // Check for a windowserver process by looking at the TERM_PROGRAM
        // or simply return true (macOS servers are rare).
        true
    }
    #[cfg(target_os = "windows")]
    {
        // Windows desktop is generally always available when running a
        // user session.
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

/// Extension to get a human-readable severity label.
trait SeverityLabel {
    fn severity_label(&self) -> &str;
}

impl SeverityLabel for DigestItem {
    fn severity_label(&self) -> &str {
        match self.severity {
            grith_digest::types::ScoreSeverity::Low => "Low",
            grith_digest::types::ScoreSeverity::Medium => "Medium",
            grith_digest::types::ScoreSeverity::High => "High",
            grith_digest::types::ScoreSeverity::Critical => "CRITICAL",
        }
    }
}
