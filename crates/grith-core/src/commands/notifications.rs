// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith notifications` subcommand — list channels, check status, and send test alerts.

use crate::daemon;

pub fn cmd_notifications(
    daemon: &daemon::Daemon,
    action: crate::NotificationsAction,
) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    match action {
        crate::NotificationsAction::Status => {
            let channels = runtime.block_on(daemon.notification_dispatcher.list_channels());
            let enabled: Vec<_> = channels.iter().filter(|c| c.enabled).collect();

            if enabled.is_empty() {
                println!("No notification channels are enabled.");
                println!("Enable channels in your config or set notifications.enabled = true");
                return Ok(());
            }

            println!("Notification Channels ({} enabled):\n", enabled.len());
            for ch in &enabled {
                let health_icon = match &ch.health {
                    Some(h) if h.connected => "[ok]",
                    Some(_) => "[!!]",
                    None => "[??]",
                };
                let interactive = if ch.supports_interactive {
                    " (interactive)"
                } else {
                    ""
                };
                let latency = ch
                    .health
                    .as_ref()
                    .and_then(|h| h.latency_ms)
                    .map(|ms| format!(" {ms}ms"))
                    .unwrap_or_default();
                println!(
                    "  {health_icon} {name}{interactive}{latency}",
                    name = ch.display_name,
                );
                if let Some(ref h) = ch.health {
                    if let Some(ref err) = h.error {
                        println!("        error: {err}");
                    }
                }
            }
        }
        crate::NotificationsAction::Channels => {
            let channels = runtime.block_on(daemon.notification_dispatcher.list_channels());

            println!("All Notification Channels:\n");
            println!(
                "  {:<14} {:<24} {:<12} {:<12} Status",
                "ID", "Name", "Tier", "Interactive"
            );
            println!("  {}", "-".repeat(70));
            for ch in &channels {
                let status = if ch.enabled { "enabled" } else { "disabled" };
                let tier = format!("{}", ch.required_tier);
                let interactive = if ch.supports_interactive { "yes" } else { "no" };
                println!(
                    "  {:<14} {:<24} {:<12} {:<12} {}",
                    ch.id, ch.display_name, tier, interactive, status,
                );
            }
            println!("\nPlan tier: {}", daemon.config.general.plan_tier);
        }
        crate::NotificationsAction::Test { channel } => {
            println!("Sending test notification to '{channel}'...");
            match runtime.block_on(daemon.notification_dispatcher.test_channel(&channel)) {
                Ok(()) => {
                    println!("Test notification sent successfully to '{channel}'.");
                }
                Err(e) => {
                    eprintln!("Failed to send test notification: {e}");
                }
            }
        }
    }
    Ok(())
}
