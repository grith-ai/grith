// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Telegram bot notification channel with long-polling callback receiver.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use tracing::{debug, info, warn};
use uuid::Uuid;

use grith_digest::notification::{
    CallbackPayload, ChannelHealth, Error, NotificationChannel, NotifyResult, PlanTier,
};
use grith_digest::{DigestItem, ReviewAction};

/// Configuration for the Telegram notification channel.
#[derive(Debug, Clone)]
pub struct TelegramConfig {
    /// Bot token from @BotFather.
    pub bot_token: String,
    /// Chat ID to send notifications to.
    pub chat_id: String,
    /// Dashboard URL for review links.
    pub dashboard_url: String,
    /// Optional list of authorized user IDs that can approve/deny.
    pub authorized_user_ids: Vec<i64>,
    /// Polling interval in seconds for the `getUpdates` long-polling loop.
    /// Defaults to 2. The Telegram API itself uses a separate `timeout`
    /// parameter (set to 30 s) so the effective cycle is
    /// `polling_interval + long_poll_timeout`.
    pub polling_interval_secs: u64,
}

struct MessageRecord {
    chat_id: String,
    message_id: i64,
}

/// Telegram Bot API notification channel.
///
/// Sends messages with inline keyboard buttons for approve/deny.
/// Receives callbacks via long polling in a background task started by
/// [`TelegramPoller::spawn`].
pub struct TelegramChannel {
    config: TelegramConfig,
    client: reqwest::Client,
    messages: Mutex<HashMap<Uuid, MessageRecord>>,
}

impl TelegramChannel {
    pub fn new(config: TelegramConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            config,
            client,
            messages: Mutex::new(HashMap::new()),
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!(
            "https://api.telegram.org/bot{}/{}",
            self.config.bot_token, method
        )
    }

    /// Build a concise, phone-friendly permission prompt.
    ///
    /// The old format dumped the raw `ToolCallType` Display, the full argument
    /// JSON, and every filter line — a wall of absolute paths that is unusable
    /// on a phone. This shows only what a human needs to decide from their
    /// pocket: which project and tool is asking, a plain-language action with a
    /// shortened target, and the single strongest reason. Full detail lives one
    /// tap away behind the Dashboard button.
    fn format_message(&self, item: &DigestItem) -> String {
        let (emoji, severity_word) = match item.severity {
            grith_digest::types::ScoreSeverity::Low => ("🟡", "Low"),
            grith_digest::types::ScoreSeverity::Medium => ("🟠", "Medium"),
            grith_digest::types::ScoreSeverity::High => ("🔴", "High"),
            grith_digest::types::ScoreSeverity::Critical => ("🚨", "Critical"),
        };

        let project = project_label(item);
        let tool = tool_label(item);
        let (op, inner) = split_call(&item.tool_call_type);
        let friendly = friendly_operation(op);
        let target = shorten_call_target(inner);

        let mut text = format!(
            "{emoji} <b>{}</b> · {} needs approval\n\n<b>{}</b>",
            html_escape(project),
            html_escape(tool),
            html_escape(&friendly),
        );
        if !target.is_empty() {
            text.push_str(&format!("\n<code>{}</code>", html_escape(&target)));
        }
        match top_reason(item) {
            Some(reason) => text.push_str(&format!(
                "\n\n<i>{}</i> · score {:.1} ({severity_word})",
                html_escape(&reason),
                item.composite_score,
            )),
            None => text.push_str(&format!(
                "\n\nscore {:.1} ({severity_word})",
                item.composite_score
            )),
        }
        text
    }

    fn build_inline_keyboard(&self, item: &DigestItem, nonce: &str) -> serde_json::Value {
        serde_json::json!({
            "inline_keyboard": [[
                {
                    "text": "✅ Approve",
                    "callback_data": format!("approve:{}:{}", item.id.simple(), nonce),
                },
                {
                    "text": "❌ Deny",
                    "callback_data": format!("deny:{}:{}", item.id.simple(), nonce),
                },
                {
                    "text": "🔗 Dashboard",
                    "url": format!("{}/digest/{}", self.config.dashboard_url, item.id),
                },
            ]]
        })
    }
}

#[async_trait::async_trait]
impl NotificationChannel for TelegramChannel {
    fn id(&self) -> &str {
        "telegram"
    }

    fn display_name(&self) -> &str {
        "Telegram Bot"
    }

    fn required_tier(&self) -> PlanTier {
        PlanTier::Pro
    }

    fn supports_interactive(&self) -> bool {
        true
    }

    async fn notify_permission_request(
        &self,
        item: &DigestItem,
        nonce: Option<&str>,
    ) -> Result<NotifyResult, Error> {
        let text = self.format_message(item);
        let effective_nonce = nonce.unwrap_or("none");
        let keyboard = self.build_inline_keyboard(item, effective_nonce);

        let body = serde_json::json!({
            "chat_id": self.config.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": keyboard,
        });

        let resp = self
            .client
            .post(self.api_url("sendMessage"))
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        let resp_json: serde_json::Value =
            resp.json().await.map_err(|e| Error::Http(e.to_string()))?;

        if resp_json["ok"].as_bool() != Some(true) {
            return Err(Error::DeliveryFailed(
                "telegram".into(),
                resp_json["description"]
                    .as_str()
                    .unwrap_or("unknown error")
                    .to_string(),
            ));
        }

        let message_id = resp_json["result"]["message_id"].as_i64().unwrap_or(0);

        if let Ok(mut msgs) = self.messages.lock() {
            msgs.insert(
                item.id,
                MessageRecord {
                    chat_id: self.config.chat_id.clone(),
                    message_id,
                },
            );
        }

        Ok(NotifyResult {
            external_id: Some(message_id.to_string()),
            delivered: true,
        })
    }

    async fn notify_resolution(&self, item: &DigestItem) -> Result<(), Error> {
        // Consume the record (remove, not get): resolution can be broadcast
        // more than once for the same item — the interactive callback path and
        // the daemon's out-of-band-resolution scan both fire — and the first
        // call to reach here owns the edit. A second call finds no record and
        // is a silent no-op, so buttons are removed and "Resolved" posted once.
        let record = self
            .messages
            .lock()
            .ok()
            .and_then(|mut msgs| msgs.remove(&item.id).map(|r| (r.chat_id, r.message_id)));

        if let Some((chat_id, message_id)) = record {
            // Remove inline keyboard (buttons)
            let body = serde_json::json!({
                "chat_id": chat_id,
                "message_id": message_id,
                "reply_markup": { "inline_keyboard": [] },
            });

            if let Err(e) = self
                .client
                .post(self.api_url("editMessageReplyMarkup"))
                .json(&body)
                .send()
                .await
            {
                warn!(
                    item_id = %item.id,
                    error = %e,
                    "failed to remove Telegram inline keyboard on resolution"
                );
            }

            // Send follow-up with resolution
            let action = item.review_action.as_deref().unwrap_or("resolved");
            let denied = action.starts_with("deny");
            let (res_emoji, verb) = if denied {
                ("🚫", "Denied")
            } else {
                ("✅", "Approved")
            };
            let (op, _) = split_call(&item.tool_call_type);
            let text = format!(
                "{res_emoji} <b>{verb}</b> — {}",
                html_escape(&friendly_operation(op)),
            );

            let body = serde_json::json!({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "reply_to_message_id": message_id,
            });

            if let Err(e) = self
                .client
                .post(self.api_url("sendMessage"))
                .json(&body)
                .send()
                .await
            {
                warn!(
                    item_id = %item.id,
                    error = %e,
                    "failed to send Telegram resolution message"
                );
            }
        }

        Ok(())
    }

    async fn notify_escalation(&self, item: &DigestItem) -> Result<(), Error> {
        let project = project_label(item);
        let tool = tool_label(item);
        let (op, inner) = split_call(&item.tool_call_type);
        let text = format!(
            "🚨 <b>ESCALATED</b> · <b>{}</b> · {}\n\n<b>{}</b>\n<code>{}</code>\n\nscore {:.1} — <i>immediate review required</i>",
            html_escape(project),
            html_escape(tool),
            html_escape(&friendly_operation(op)),
            html_escape(&shorten_call_target(inner)),
            item.composite_score,
        );

        let body = serde_json::json!({
            "chat_id": self.config.chat_id,
            "text": text,
            "parse_mode": "HTML",
        });

        self.client
            .post(self.api_url("sendMessage"))
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
        // Enforce authorized_user_ids if configured.
        if !self.config.authorized_user_ids.is_empty() {
            if let Some(user_id) = payload.user_id {
                if !self.config.authorized_user_ids.contains(&user_id) {
                    return Err(Error::DeliveryFailed(
                        "telegram".into(),
                        format!("user {user_id} is not authorized to review digest items"),
                    ));
                }
            } else {
                return Err(Error::DeliveryFailed(
                    "telegram".into(),
                    "callback missing user_id; cannot verify authorization".into(),
                ));
            }
        }
        Ok(Some(payload.action))
    }

    async fn health_check(&self) -> Result<ChannelHealth, Error> {
        let start = std::time::Instant::now();
        let resp = self.client.get(self.api_url("getMe")).send().await;

        match resp {
            Ok(r) => {
                let latency = start.elapsed().as_millis() as u64;
                let body: serde_json::Value = r.json().await.unwrap_or_default();
                if body["ok"].as_bool() == Some(true) {
                    Ok(ChannelHealth {
                        connected: true,
                        latency_ms: Some(latency),
                        error: None,
                    })
                } else {
                    Ok(ChannelHealth {
                        connected: false,
                        latency_ms: Some(latency),
                        error: Some("getMe failed".into()),
                    })
                }
            }
            Err(e) => Ok(ChannelHealth {
                connected: false,
                latency_ms: None,
                error: Some(e.to_string()),
            }),
        }
    }
}

/// Basic HTML escaping for Telegram messages.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The project a digest item belongs to. The supervisor sets `task_context`
/// to the session's project name (derived from the launch cwd); fall back to a
/// generic label so the line is never blank.
fn project_label(item: &DigestItem) -> &str {
    item.task_context
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("grith")
}

/// The tool that made the call. Supervisor items carry `supervisor:<tool>`;
/// the built-in agent carries its own plugin id.
fn tool_label(item: &DigestItem) -> &str {
    let tool = item
        .plugin_id
        .strip_prefix("supervisor:")
        .unwrap_or(&item.plugin_id)
        .trim();
    if tool.is_empty() {
        "grith"
    } else {
        tool
    }
}

/// Split a `ToolCallType` Display string (`Op(inner...)`) into `(op, inner)`.
/// A form without parentheses yields `(whole, "")`.
fn split_call(tool_call_type: &str) -> (&str, &str) {
    match tool_call_type.find('(') {
        Some(open) => (
            &tool_call_type[..open],
            tool_call_type[open + 1..].trim_end_matches(')'),
        ),
        None => (tool_call_type, ""),
    }
}

/// Plain-language verb for a `ToolCallType` discriminant. Falls back to the raw
/// discriminant so a new variant still renders something sensible.
fn friendly_operation(op: &str) -> String {
    let label = match op {
        "FileLink" => "Link file",
        "FileWrite" => "Write file",
        "FileAppend" => "Append to file",
        "FileRead" => "Read file",
        "FileDelete" => "Delete file",
        "FileChmod" => "Change file permissions",
        "FileChown" | "OwnershipChange" => "Change file owner",
        "FileRename" | "FileMove" => "Rename file",
        "DirCreate" => "Create directory",
        "DirList" => "List directory",
        "DirDelete" => "Delete directory",
        "NetConnect" => "Network connection",
        "NetListen" | "NetBind" => "Open network listener",
        "DnsQuery" => "DNS lookup",
        "ProcessSpawn" => "Run command",
        "ProcessFork" => "Fork process",
        "CrossProcessAccess" => "Access another process",
        "NamespaceOp" => "Namespace operation",
        "FilesystemMutation" => "Modify filesystem",
        other => other,
    };
    label.to_string()
}

/// Shorten a call's argument text for a phone notification: absolute paths
/// collapse to `…/basename`, the `->` link arrow becomes `→`, and the whole
/// thing is capped so it never becomes a wall of text. Full detail stays
/// available behind the Dashboard button.
fn shorten_call_target(inner: &str) -> String {
    const MAX_CHARS: usize = 90;
    const MAX_COMPONENT: usize = 44;

    let shortened: Vec<String> = inner
        .split_whitespace()
        .map(|tok| {
            if tok == "->" {
                return "→".to_string();
            }
            // A filesystem path (has a slash, not a URL). Keep the last
            // component; a hugely long basename is itself truncated.
            if tok.contains('/') && !tok.contains("://") {
                let trimmed = tok.trim_end_matches([')', ',', ';']);
                if let Some(base) = trimmed.rsplit('/').next() {
                    if !base.is_empty() {
                        let base = truncate_middle(base, MAX_COMPONENT);
                        return format!("…/{base}");
                    }
                }
            }
            tok.to_string()
        })
        .collect();

    let mut out = shortened.join(" ");
    if out.chars().count() > MAX_CHARS {
        out = out.chars().take(MAX_CHARS).collect::<String>();
        out.push('…');
    }
    out
}

/// Truncate a long token in the middle (`start…end`) so both the meaningful
/// prefix and the distinguishing suffix survive.
fn truncate_middle(s: &str, max: usize) -> String {
    let len = s.chars().count();
    if len <= max {
        return s.to_string();
    }
    let head = max / 2;
    let tail = max - head - 1;
    let start: String = s.chars().take(head).collect();
    let end: String = s.chars().skip(len - tail).collect();
    format!("{start}…{end}")
}

/// The single strongest reason the call was flagged: the highest-magnitude
/// filter message, with any paths shortened. Falls back to the decision reason.
fn top_reason(item: &DigestItem) -> Option<String> {
    item.filter_breakdown
        .iter()
        .filter(|f| !f.message.trim().is_empty())
        .max_by(|a, b| {
            a.score
                .abs()
                .partial_cmp(&b.score.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|f| shorten_call_target(&f.message))
        .or_else(|| {
            item.decision_reason
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .map(shorten_call_target)
        })
}

// ---------------------------------------------------------------------------
// Long-polling callback receiver
// ---------------------------------------------------------------------------

/// Subset of the Telegram `getUpdates` response we care about.
#[derive(Debug, Deserialize)]
struct GetUpdatesResponse {
    ok: bool,
    #[serde(default)]
    result: Vec<TelegramUpdate>,
}

#[derive(Debug, Clone, Deserialize)]
struct TelegramUpdate {
    update_id: i64,
    callback_query: Option<TelegramCallbackQuery>,
}

#[derive(Debug, Clone, Deserialize)]
struct TelegramCallbackQuery {
    id: String,
    from: TelegramUser,
    data: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TelegramUser {
    id: i64,
    #[serde(default)]
    first_name: String,
    username: Option<String>,
}

/// Parse the `callback_data` string embedded in inline keyboard buttons.
///
/// Expected format: `"action:uuid:nonce"` where action is one of
/// `approve`, `deny`, or `escalate`.
///
/// Returns `(ReviewAction, item_id, nonce)` on success.
fn parse_callback_data(data: &str) -> Option<(ReviewAction, Uuid, String)> {
    let mut parts = data.splitn(3, ':');
    let action_str = parts.next()?;
    let uuid_str = parts.next()?;
    let nonce = parts.next()?;

    let action = match action_str {
        "approve" => ReviewAction::Approve,
        "deny" => ReviewAction::Deny,
        "escalate" => ReviewAction::Escalate,
        _ => return None,
    };

    let item_id = Uuid::parse_str(uuid_str).ok()?;

    Some((action, item_id, nonce.to_string()))
}

/// Background long-polling task that receives interactive callbacks from
/// Telegram and routes them through the notification dispatcher.
///
/// Uses the Telegram Bot API `getUpdates` endpoint with a long-poll
/// `timeout` parameter to efficiently wait for new updates without
/// busy-looping.
pub struct TelegramPoller {
    bot_token: String,
    client: reqwest::Client,
    polling_interval: Duration,
}

impl TelegramPoller {
    /// Create a new poller from a Telegram channel config.
    pub fn new(config: &TelegramConfig) -> Self {
        // Use a longer timeout for the polling client so the long-poll
        // `timeout` parameter (30 s) can complete without the HTTP client
        // aborting the request.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            bot_token: config.bot_token.clone(),
            client,
            polling_interval: Duration::from_secs(config.polling_interval_secs),
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.bot_token, method)
    }

    /// Spawn the long-polling loop as a background tokio task.
    ///
    /// The task listens for `callback_query` updates, parses the
    /// `callback_data`, answers the callback to dismiss the spinner in
    /// the Telegram client, and routes the action through the provided
    /// notification dispatcher.
    ///
    /// The loop runs until a message is received on `shutdown_rx`.
    pub fn spawn(
        self,
        dispatcher: Arc<crate::NotificationDispatcher>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!("telegram callback poller started");
            let mut offset: Option<i64> = None;

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("telegram callback poller shutting down");
                        break;
                    }
                    updates = self.poll_updates(offset) => {
                        match updates {
                            Ok(items) => {
                                for update in items {
                                    // Always advance the offset so we don't
                                    // re-process this update.
                                    offset = Some(update.update_id + 1);

                                    if let Some(ref cb) = update.callback_query {
                                        self.handle_callback_query(cb, &dispatcher).await;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "telegram getUpdates failed");
                                // Back off on error to avoid hammering the API.
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                continue;
                            }
                        }
                    }
                }

                tokio::time::sleep(self.polling_interval).await;
            }

            info!("telegram callback poller stopped");
        })
    }

    /// Call `getUpdates` with long-polling.
    async fn poll_updates(&self, offset: Option<i64>) -> Result<Vec<TelegramUpdate>, String> {
        let mut params = serde_json::json!({
            "timeout": 30,
            "allowed_updates": ["callback_query"],
        });
        if let Some(off) = offset {
            params["offset"] = serde_json::json!(off);
        }

        let resp = self
            .client
            .post(self.api_url("getUpdates"))
            .json(&params)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {e}"))?;

        let body: GetUpdatesResponse = resp
            .json()
            .await
            .map_err(|e| format!("JSON decode error: {e}"))?;

        if !body.ok {
            return Err("Telegram API returned ok=false".into());
        }

        Ok(body.result)
    }

    /// Process a single `callback_query` update.
    async fn handle_callback_query(
        &self,
        cb: &TelegramCallbackQuery,
        dispatcher: &Arc<crate::NotificationDispatcher>,
    ) {
        let data = match &cb.data {
            Some(d) => d,
            None => {
                debug!(
                    callback_id = &cb.id,
                    "callback_query without data, ignoring"
                );
                return;
            }
        };

        let (action, item_id, nonce) = match parse_callback_data(data) {
            Some(parsed) => parsed,
            None => {
                warn!(callback_data = data, "unparseable callback_data, ignoring");
                self.answer_callback(&cb.id, Some("Invalid callback data"))
                    .await;
                return;
            }
        };

        // Build the reviewer identifier from Telegram user info.
        let reviewer = cb
            .from
            .username
            .as_deref()
            .unwrap_or(&cb.from.first_name)
            .to_string();

        let payload = CallbackPayload {
            item_id,
            action,
            reviewer,
            notes: None,
            nonce,
            channel_id: "telegram".into(),
            user_id: Some(cb.from.id),
        };

        match dispatcher.handle_callback(&payload).await {
            Ok(Some(applied_action)) => {
                let label = match applied_action {
                    ReviewAction::Approve => "Approved",
                    ReviewAction::Deny => "Denied",
                    ReviewAction::Escalate => "Escalated",
                    _ => "Action applied",
                };
                info!(
                    item_id = %item_id,
                    action = %applied_action,
                    user_id = cb.from.id,
                    "telegram callback processed"
                );
                self.answer_callback(&cb.id, Some(label)).await;
            }
            Ok(None) => {
                self.answer_callback(&cb.id, Some("No action taken")).await;
            }
            Err(e) => {
                warn!(
                    item_id = %item_id,
                    error = %e,
                    "telegram callback dispatch failed"
                );
                self.answer_callback(&cb.id, Some("Error processing action"))
                    .await;
            }
        }
    }

    /// Call `answerCallbackQuery` to dismiss the loading spinner on the
    /// user's Telegram client.
    async fn answer_callback(&self, callback_query_id: &str, text: Option<&str>) {
        let mut body = serde_json::json!({
            "callback_query_id": callback_query_id,
        });
        if let Some(t) = text {
            body["text"] = serde_json::json!(t);
        }

        if let Err(e) = self
            .client
            .post(self.api_url("answerCallbackQuery"))
            .json(&body)
            .send()
            .await
        {
            warn!(
                callback_query_id,
                error = %e,
                "failed to answer Telegram callback query"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grith_digest::types::{DigestStatus, FilterBreakdown, ScoreSeverity};

    /// A digest item shaped like the real screenshot: a hard-link create under
    /// a Cargo target dir, with two filters, from the `grith` project /
    /// `claude` tool.
    fn filelink_item() -> DigestItem {
        let long = "/home/dan/projects/PersonalProjects/Grith/grith/.claude/worktrees/\
                    control-socket-unix-class/target/debug/deps/\
                    fp_credential_then_tool-c44b1d25a0385cf5.4ylg70ch3j7spx06urf4o5id4.0c6r46d.rcgu.o";
        let src = "/home/dan/projects/PersonalProjects/Grith/grith/.claude/worktrees/\
                   control-socket-unix-class/target/debug/incremental/\
                   fp_credential_then_tool-0lrjcx9q6lz73/s-hliigsc081-1jjrcc6-working/4ylg70ch3j7spx06urf4o5id4.o";
        DigestItem {
            id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            session_id: Some(Uuid::new_v4()),
            tool_call_type: format!("FileLink(hard {src} -> {long})"),
            arguments_summary: "{\"link_symbolic\":false}".into(),
            decision_reason: None,
            composite_score: 3.3,
            severity: ScoreSeverity::Low,
            filter_breakdown: vec![
                FilterBreakdown {
                    filter_name: "operation-risk".into(),
                    score: 0.5,
                    rule_id: "op-risk".into(),
                    message: format!("Hard link created: {src} -> {long}"),
                },
                FilterBreakdown {
                    filter_name: "sensitive-path-heuristic".into(),
                    score: 2.8,
                    rule_id: "sph".into(),
                    message: "read access to sensitive-looking filename".into(),
                },
            ],
            task_context: Some("grith".into()),
            plugin_id: "supervisor:claude".into(),
            status: DigestStatus::Pending,
            reviewed_at: None,
            review_action: None,
            reviewer_notes: None,
            informational_only: false,
            escalated_at: None,
            escalated_by: None,
        }
    }

    fn test_channel() -> TelegramChannel {
        TelegramChannel::new(TelegramConfig {
            bot_token: "t".into(),
            chat_id: "1".into(),
            dashboard_url: "http://localhost:3141".into(),
            authorized_user_ids: vec![],
            polling_interval_secs: 2,
        })
    }

    #[test]
    fn format_message_is_concise_and_names_the_project() {
        let msg = test_channel().format_message(&filelink_item());

        // Names the project and the tool.
        assert!(msg.contains("grith"), "should name the project: {msg}");
        assert!(msg.contains("claude"), "should name the tool: {msg}");
        // Plain-language action, not the raw discriminant.
        assert!(msg.contains("Link file"), "friendly op: {msg}");
        // The strongest reason (2.8 > 0.5) is surfaced.
        assert!(
            msg.contains("sensitive-looking filename"),
            "top reason: {msg}"
        );
        // Paths are shortened, never the full absolute path.
        assert!(msg.contains("…/"), "paths shortened: {msg}");
        assert!(
            !msg.contains("/home/dan/projects/PersonalProjects"),
            "must not dump full paths: {msg}"
        );
        // The link arrow is normalised.
        assert!(msg.contains('→'), "arrow normalised: {msg}");
        // Score is present.
        assert!(msg.contains("3.3"), "score present: {msg}");
        // The whole thing stays short enough for a phone.
        assert!(
            msg.chars().count() < 320,
            "message too long ({} chars): {msg}",
            msg.chars().count()
        );
    }

    #[test]
    fn helpers_extract_project_tool_and_op() {
        let item = filelink_item();
        assert_eq!(project_label(&item), "grith");
        assert_eq!(tool_label(&item), "claude");
        let (op, inner) = split_call(&item.tool_call_type);
        assert_eq!(op, "FileLink");
        assert!(inner.starts_with("hard /home/dan"));
        assert_eq!(friendly_operation("NetConnect"), "Network connection");
        assert_eq!(friendly_operation("TotallyNewOp"), "TotallyNewOp");
    }

    #[test]
    fn tool_label_falls_back_for_agent_and_blank() {
        let mut item = filelink_item();
        item.plugin_id = "grith-agent".into();
        assert_eq!(tool_label(&item), "grith-agent");
        item.task_context = None;
        assert_eq!(project_label(&item), "grith");
    }

    #[test]
    fn shorten_keeps_last_component_and_caps_length() {
        let s = shorten_call_target("hard /a/b/c/really.o -> /x/y/z/other.o");
        assert!(s.contains("…/really.o"), "{s}");
        assert!(s.contains("…/other.o"), "{s}");
        assert!(s.contains('→'), "{s}");
        // A non-path stays intact.
        assert_eq!(shorten_call_target("example.com:22"), "example.com:22");
    }

    #[test]
    fn truncate_middle_preserves_both_ends() {
        let out = truncate_middle("abcdefghijklmnopqrstuvwxyz", 11);
        assert!(out.starts_with("abc"), "{out}");
        assert!(out.ends_with("xyz"), "{out}");
        assert!(out.contains('…'), "{out}");
        assert_eq!(truncate_middle("short", 40), "short");
    }

    #[test]
    fn parse_callback_data_approve() {
        let id = Uuid::new_v4();
        let nonce = "abc123";
        let data = format!("approve:{id}:{nonce}");
        let (action, parsed_id, parsed_nonce) = parse_callback_data(&data).unwrap();
        assert_eq!(action, ReviewAction::Approve);
        assert_eq!(parsed_id, id);
        assert_eq!(parsed_nonce, nonce);
    }

    #[test]
    fn parse_callback_data_deny() {
        let id = Uuid::new_v4();
        let nonce = "xyz789";
        let data = format!("deny:{id}:{nonce}");
        let (action, parsed_id, parsed_nonce) = parse_callback_data(&data).unwrap();
        assert_eq!(action, ReviewAction::Deny);
        assert_eq!(parsed_id, id);
        assert_eq!(parsed_nonce, nonce);
    }

    #[test]
    fn parse_callback_data_escalate() {
        let id = Uuid::new_v4();
        let nonce = "esc-nonce";
        let data = format!("escalate:{id}:{nonce}");
        let (action, parsed_id, parsed_nonce) = parse_callback_data(&data).unwrap();
        assert_eq!(action, ReviewAction::Escalate);
        assert_eq!(parsed_id, id);
        assert_eq!(parsed_nonce, nonce);
    }

    #[test]
    fn parse_callback_data_unknown_action() {
        let id = Uuid::new_v4();
        let data = format!("pause:{id}:nonce");
        assert!(parse_callback_data(&data).is_none());
    }

    #[test]
    fn parse_callback_data_invalid_uuid() {
        let data = "approve:not-a-uuid:nonce";
        assert!(parse_callback_data(data).is_none());
    }

    #[test]
    fn parse_callback_data_missing_parts() {
        assert!(parse_callback_data("approve").is_none());
        assert!(parse_callback_data("approve:only-two").is_none());
        assert!(parse_callback_data("").is_none());
    }

    #[test]
    fn parse_callback_data_nonce_with_colons() {
        // Nonces could theoretically contain colons; splitn(3, ':') ensures
        // the third part captures everything after the second colon.
        let id = Uuid::new_v4();
        let data = format!("approve:{id}:nonce:with:colons");
        let (action, parsed_id, parsed_nonce) = parse_callback_data(&data).unwrap();
        assert_eq!(action, ReviewAction::Approve);
        assert_eq!(parsed_id, id);
        assert_eq!(parsed_nonce, "nonce:with:colons");
    }

    #[test]
    fn deserialize_get_updates_response() {
        let json = serde_json::json!({
            "ok": true,
            "result": [
                {
                    "update_id": 100,
                    "callback_query": {
                        "id": "cb-1",
                        "from": {
                            "id": 42,
                            "first_name": "Alice",
                            "username": "alice"
                        },
                        "data": "approve:550e8400-e29b-41d4-a716-446655440000:nonce123"
                    }
                },
                {
                    "update_id": 101,
                    "callback_query": {
                        "id": "cb-2",
                        "from": {
                            "id": 99,
                            "first_name": "Bob"
                        },
                        "data": "deny:550e8400-e29b-41d4-a716-446655440000:nonce456"
                    }
                }
            ]
        });

        let resp: GetUpdatesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.result.len(), 2);

        let first = &resp.result[0];
        assert_eq!(first.update_id, 100);
        let cb = first.callback_query.as_ref().unwrap();
        assert_eq!(cb.id, "cb-1");
        assert_eq!(cb.from.id, 42);
        assert_eq!(cb.from.username.as_deref(), Some("alice"));
        assert_eq!(
            cb.data.as_deref(),
            Some("approve:550e8400-e29b-41d4-a716-446655440000:nonce123")
        );

        let second = &resp.result[1];
        let cb2 = second.callback_query.as_ref().unwrap();
        assert_eq!(cb2.from.id, 99);
        assert!(cb2.from.username.is_none());
    }

    #[test]
    fn deserialize_empty_updates() {
        let json = serde_json::json!({ "ok": true, "result": [] });
        let resp: GetUpdatesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.ok);
        assert!(resp.result.is_empty());
    }

    #[test]
    fn deserialize_update_without_callback_query() {
        let json = serde_json::json!({
            "ok": true,
            "result": [{ "update_id": 200 }]
        });
        let resp: GetUpdatesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.result.len(), 1);
        assert!(resp.result[0].callback_query.is_none());
    }
}
