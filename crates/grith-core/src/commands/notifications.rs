// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith notifications` subcommand — placeholder while managed notifications
//! are being built (see work/84).
//!
//! The previous implementation inspected the dispatcher built for THIS CLI
//! process, which never registers channels (registration only runs in the
//! server/daemon path), so `status`/`channels` always printed "no channels"
//! and `test` failed — a broken-looking surface for a feature that isn't
//! finished. Until managed, dashboard-configured notifications ship, every
//! action prints an honest "coming soon". This does NOT affect notification
//! delivery, which is driven by the daemon independently of this command.

pub fn cmd_notifications(
    _daemon: &crate::daemon::Daemon,
    _action: crate::NotificationsAction,
) -> anyhow::Result<()> {
    println!("Notifications are coming soon.");
    println!();
    println!("Get alerts — and approve or deny — from Telegram, Slack and more,");
    println!("set up from your dashboard with no local configuration. It's on the");
    println!("way; this command will light up when it arrives.");
    Ok(())
}
