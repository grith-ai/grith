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

        // Detached, not awaited: on Linux we wait for the click before opening
        // the dashboard, and that wait blocks until the notification is
        // dismissed (up to the timeout). Blocking the dispatch loop here would
        // stall every channel routed after desktop, so we fire-and-forget and
        // report delivered optimistically — matching the previous best-effort
        // show (which ignored the show Result).
        //
        // A plain OS thread, NOT `spawn_blocking`. `wait_for_action` blocks
        // until the notification server reports the notification closed or
        // actioned — and GNOME never reports either for a notification that
        // expires into the tray unclicked, so this wait can be PERMANENT.
        // The 10s expiry below is a display hint the server is free to
        // ignore, not a bound on the wait. On the tokio blocking pool each
        // such wait pinned a pool thread forever, and `Runtime::drop` joins
        // that pool with no timeout: one expired, unclicked notification was
        // enough to hang daemon shutdown after its drain completed — port
        // released, audit writer lock held, process immortal. A detached OS
        // thread is invisible to runtime teardown and to process exit.
        let dashboard_url = self.dashboard_url.clone();
        std::thread::Builder::new()
            .name("grith-notify-click".to_string())
            .spawn(move || {
                show_permission_request(&title, &body, &dashboard_url);
            })
            .map_err(|e| Error::DeliveryFailed("desktop".into(), e.to_string()))?;

        Ok(NotifyResult {
            external_id: None,
            delivered: true,
        })
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

/// Show a permission-request desktop notification, opening the dashboard only
/// when the notification is *clicked*.
///
/// The previous implementation called `open::that(dashboard_url)`
/// unconditionally right after `show()`, so every notification spawned a fresh
/// browser tab — stacking tabs on a machine that already had the dashboard
/// open. On Linux we now register the freedesktop `"default"` action (invoked
/// when the notification body is clicked) and open the dashboard from its
/// handler. This call blocks until the notification is dismissed, so the
/// caller runs it on a detached blocking task.
#[cfg(all(unix, not(target_os = "macos")))]
fn show_permission_request(title: &str, body: &str, dashboard_url: &str) {
    if let Ok(handle) = notify_rust::Notification::new()
        .summary(title)
        .body(body)
        .icon("dialog-warning")
        // "default" is the special freedesktop action key fired when the
        // notification body itself is clicked.
        .action("default", "Open dashboard")
        .timeout(notify_rust::Timeout::Milliseconds(10000))
        .show()
    {
        let url = dashboard_url.to_string();
        handle.wait_for_action(|action| {
            if action == "default" {
                let _ = open::that(&url);
            }
        });
    }
}

/// macOS/Windows fall back to a plain notification (their notify-rust backends
/// do not expose the freedesktop click-action model). No auto-open — the
/// dashboard URL is in the body.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn show_permission_request(title: &str, body: &str, _dashboard_url: &str) {
    let mut builder = notify_rust::Notification::new();
    builder.summary(title).body(body);
    #[cfg(target_os = "macos")]
    builder
        .icon("dialog-warning")
        .timeout(notify_rust::Timeout::Milliseconds(10000));
    let _ = builder.show();
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
