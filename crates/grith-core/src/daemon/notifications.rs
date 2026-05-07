// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Notification channel registration.
//!
//! Registers notification channels (desktop, websocket, email, Slack, Telegram,
//! Discord, webhook, PagerDuty, Opsgenie, Teams, WhatsApp) with the dispatcher
//! based on the current configuration and plan tier.

use super::Daemon;
use std::sync::Arc;

impl Daemon {
    /// Register notification channels with the dispatcher based on the current
    /// configuration. Call this after the server has started (so `ws_tx` is available).
    ///
    /// When interactive channels (e.g. Telegram) are enabled, their callback
    /// polling tasks are spawned automatically using `self.shutdown_tx` for
    /// graceful shutdown.
    pub fn register_notification_channels(
        &self,
        ws_tx: Option<tokio::sync::broadcast::Sender<String>>,
    ) {
        if !self.config.notifications.enabled {
            return;
        }

        let dispatcher = &self.notification_dispatcher;
        let cfg = &self.config.notifications;
        let dashboard_url = format!(
            "http://{}:{}",
            self.config.server.host, self.config.server.port
        );

        // Desktop notifications (Community tier)
        if cfg.desktop.enabled {
            dispatcher.register_channel(
                Arc::new(grith_notify::channels::desktop::DesktopChannel::new(
                    dashboard_url.clone(),
                )),
                true,
            );
            tracing::debug!("registered desktop notification channel");
        }

        // WebSocket channel (Community tier) -- needs ws_tx from the server
        if let Some(ws_tx) = ws_tx {
            dispatcher.register_channel(
                Arc::new(grith_notify::channels::websocket::WebSocketChannel::new(
                    ws_tx,
                )),
                true,
            );
            tracing::debug!("registered websocket notification channel");
        }

        // Email channel (Pro tier)
        if cfg.email.enabled && !cfg.email.smtp_host.is_empty() {
            let email_config = grith_notify::channels::email::EmailConfig {
                smtp_host: cfg.email.smtp_host.clone(),
                smtp_port: cfg.email.smtp_port,
                smtp_username: cfg.email.smtp_username.clone(),
                smtp_password: cfg.email.smtp_password.clone(),
                from_address: cfg.email.from_address.clone(),
                to_addresses: cfg.email.to_addresses.clone(),
                dashboard_url: dashboard_url.clone(),
                starttls: cfg.email.starttls,
            };
            dispatcher.register_channel(
                Arc::new(grith_notify::channels::email::EmailChannel::new(
                    email_config,
                )),
                true,
            );
            tracing::debug!("registered email notification channel");
        }

        // Slack channel (Pro tier)
        if cfg.slack.enabled
            && (!cfg.slack.bot_token.is_empty() || !cfg.slack.webhook_url.is_empty())
        {
            let slack_config = grith_notify::channels::slack::SlackConfig {
                bot_token: cfg.slack.bot_token.clone(),
                channel_id: cfg.slack.channel_id.clone(),
                webhook_url: if cfg.slack.webhook_url.is_empty() {
                    None
                } else {
                    Some(cfg.slack.webhook_url.clone())
                },
                dashboard_url: dashboard_url.clone(),
            };
            dispatcher.register_channel(
                Arc::new(grith_notify::channels::slack::SlackChannel::new(
                    slack_config,
                )),
                true,
            );
            tracing::debug!("registered slack notification channel");
        }

        // Telegram channel (Pro tier)
        if cfg.telegram.enabled && !cfg.telegram.bot_token.is_empty() {
            let telegram_config = grith_notify::channels::telegram::TelegramConfig {
                bot_token: cfg.telegram.bot_token.clone(),
                chat_id: cfg.telegram.chat_id.clone(),
                authorized_user_ids: cfg.telegram.authorized_user_ids.clone(),
                dashboard_url: dashboard_url.clone(),
                polling_interval_secs: cfg.telegram.polling_interval_secs,
            };
            dispatcher.register_channel(
                Arc::new(grith_notify::channels::telegram::TelegramChannel::new(
                    telegram_config.clone(),
                )),
                true,
            );

            // Start the long-polling callback receiver so interactive
            // approve/deny buttons work end-to-end.
            let poller = grith_notify::channels::telegram::TelegramPoller::new(&telegram_config);
            let shutdown_rx = self.subscribe_shutdown();
            poller.spawn(Arc::clone(&self.notification_dispatcher), shutdown_rx);
            tracing::debug!("registered telegram notification channel with callback polling");
        }

        // Discord channel (Pro tier)
        if cfg.discord.enabled
            && (!cfg.discord.bot_token.is_empty() || !cfg.discord.webhook_url.is_empty())
        {
            let discord_config = grith_notify::channels::discord::DiscordConfig {
                bot_token: if cfg.discord.bot_token.is_empty() {
                    None
                } else {
                    Some(cfg.discord.bot_token.clone())
                },
                channel_id: if cfg.discord.channel_id.is_empty() {
                    None
                } else {
                    Some(cfg.discord.channel_id.clone())
                },
                webhook_url: if cfg.discord.webhook_url.is_empty() {
                    None
                } else {
                    Some(cfg.discord.webhook_url.clone())
                },
                dashboard_url: dashboard_url.clone(),
            };
            dispatcher.register_channel(
                Arc::new(grith_notify::channels::discord::DiscordChannel::new(
                    discord_config,
                )),
                true,
            );
            tracing::debug!("registered discord notification channel");
        }

        // Webhook channel (Pro tier)
        if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
            let headers: Vec<(String, String)> = cfg
                .webhook
                .headers
                .iter()
                .filter(|h| h.len() == 2)
                .map(|h| (h[0].clone(), h[1].clone()))
                .collect();
            let webhook_config = grith_notify::channels::webhook::WebhookConfig {
                url: cfg.webhook.url.clone(),
                secret: cfg.webhook.secret.clone(),
                callback_url: if cfg.webhook.callback_url.is_empty() {
                    None
                } else {
                    Some(cfg.webhook.callback_url.clone())
                },
                max_retries: cfg.webhook.max_retries,
                headers,
            };
            dispatcher.register_channel(
                Arc::new(grith_notify::channels::webhook::WebhookChannel::new(
                    webhook_config,
                )),
                true,
            );
            tracing::debug!("registered webhook notification channel");
        }

        // PagerDuty channel (Enterprise tier)
        if cfg.pagerduty.enabled && !cfg.pagerduty.routing_key.is_empty() {
            let pd_config = grith_notify::channels::pagerduty::PagerDutyConfig {
                routing_key: cfg.pagerduty.routing_key.clone(),
                dashboard_url: dashboard_url.clone(),
            };
            dispatcher.register_channel(
                Arc::new(grith_notify::channels::pagerduty::PagerDutyChannel::new(
                    pd_config,
                )),
                true,
            );
            tracing::debug!("registered pagerduty notification channel");
        }

        // Opsgenie channel (Enterprise tier)
        if cfg.opsgenie.enabled && !cfg.opsgenie.api_key.is_empty() {
            let og_config = grith_notify::channels::opsgenie::OpsgenieConfig {
                api_key: cfg.opsgenie.api_key.clone(),
                eu_endpoint: cfg.opsgenie.eu_endpoint,
                dashboard_url: dashboard_url.clone(),
            };
            dispatcher.register_channel(
                Arc::new(grith_notify::channels::opsgenie::OpsgenieChannel::new(
                    og_config,
                )),
                true,
            );
            tracing::debug!("registered opsgenie notification channel");
        }

        // Teams channel (Enterprise tier)
        if cfg.teams.enabled && !cfg.teams.webhook_url.is_empty() {
            let teams_config = grith_notify::channels::teams::TeamsConfig {
                webhook_url: cfg.teams.webhook_url.clone(),
                dashboard_url: dashboard_url.clone(),
            };
            dispatcher.register_channel(
                Arc::new(grith_notify::channels::teams::TeamsChannel::new(
                    teams_config,
                )),
                true,
            );
            tracing::debug!("registered teams notification channel");
        }

        // WhatsApp channel (Enterprise tier)
        if cfg.whatsapp.enabled && !cfg.whatsapp.access_token.is_empty() {
            let wa_config = grith_notify::channels::whatsapp::WhatsAppConfig {
                access_token: cfg.whatsapp.access_token.clone(),
                phone_number_id: cfg.whatsapp.phone_number_id.clone(),
                recipient_number: cfg.whatsapp.recipient_number.clone(),
                dashboard_url: dashboard_url.clone(),
                api_version: None,
            };
            dispatcher.register_channel(
                Arc::new(grith_notify::channels::whatsapp::WhatsAppChannel::new(
                    wa_config,
                )),
                true,
            );
            tracing::debug!("registered whatsapp notification channel");
        }

        let count = dispatcher.registry().len();
        if count > 0 {
            tracing::info!(channels = count, "notification channels registered");
        }
    }
}
