// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Daemon IPC client for thin grith sessions.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use grith_audit::types::AuditRecord;
use grith_digest::types::{DigestItem, DigestStatus};
use grith_proxy::reputation::ReputationTable;
use grith_proxy::types::{ProxyDecision, QueuePriority, Severity, ToolCallContext};
use grith_supervisor::supervisor::{SessionStats, SupervisorSession};
use serde::Deserialize;
use uuid::Uuid;

/// HTTP client for communicating with the grith daemon.
#[derive(Clone)]
pub struct DaemonClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteSessionSummary {
    pub id: Uuid,
    pub tool_name: String,
    #[serde(default)]
    pub project_name: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub tty: Option<String>,
    pub root_pid: u32,
    pub uptime_seconds: u64,
    #[serde(default)]
    pub last_activity_seconds: u64,
    pub stats: SessionStats,
    pub containment_remaining_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteSessionDetail {
    pub id: String,
    pub tool_name: String,
    pub root_pid: u32,
    pub uptime_seconds: u64,
    pub process_tree_pids: Vec<u32>,
    pub stats: SessionStats,
    pub containment_remaining_seconds: Option<u64>,
}

#[derive(Deserialize)]
struct SessionsResponse {
    sessions: Vec<RemoteSessionSummary>,
}

#[derive(Debug, Clone, Deserialize)]
struct PruneResponse {
    reaped: u32,
    remaining: u32,
}

/// Structured session-limit (429) rejection returned by the daemon when the
/// concurrency cap is reached. Drives the CLI upgrade prompt.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionLimitRejection {
    pub tier: String,
    pub current_limit: usize,
    pub active_sessions: usize,
    #[serde(default)]
    pub remediation: Vec<String>,
    pub upgrade_url: Option<String>,
    pub message: String,
}

/// Outcome of attempting to register a session with the daemon.
#[derive(Debug)]
pub enum RegisterOutcome {
    Registered,
    LimitReached(SessionLimitRejection),
}

#[derive(Deserialize)]
struct ReputationTableResponse {
    table_json: String,
}

#[derive(Deserialize)]
struct ProxyStatusFullResponse {
    filter_count: usize,
}

impl DaemonClient {
    /// Attempt to connect to a running daemon.
    pub fn connect() -> Option<Self> {
        let (_pid, port) = super::pid::is_dashboard_running()?;
        let token = super::token::read_token()?;
        let base_url = format!("http://127.0.0.1:{port}");

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(8)
            .build()
            .ok()?;

        let client = Self {
            base_url,
            token,
            http,
        };

        let rt = tokio::runtime::Handle::try_current();
        let healthy = match rt {
            Ok(handle) => {
                tokio::task::block_in_place(|| handle.block_on(client.authenticated_health_check()))
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok()?;
                rt.block_on(client.authenticated_health_check())
            }
        };

        healthy.then_some(client)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn health_check(&self) -> bool {
        self.http
            .get(format!("{}/health", self.base_url))
            .timeout(Duration::from_millis(500))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
    }

    async fn authenticated_health_check(&self) -> bool {
        self.request_typed::<ProxyStatusFullResponse>(
            self.http
                .get(format!("{}/api/proxy/status/full", self.base_url))
                .timeout(Duration::from_millis(500)),
        )
        .await
        .is_ok()
    }

    pub async fn evaluate(
        &self,
        ctx: &ToolCallContext,
    ) -> Result<ProxyDecision, DaemonClientError> {
        let body = self
            .request_json(
                self.http
                    .post(format!("{}/api/proxy/evaluate", self.base_url))
                    .json(&serde_json::json!({ "context": ctx })),
            )
            .await?;

        parse_evaluate_response(&body)
    }

    pub async fn observe_reputation(
        &self,
        keys: &[(u8, String)],
        outcome: &str,
    ) -> Result<(), DaemonClientError> {
        self.request_empty(
            self.http
                .post(format!("{}/api/reputation/observe", self.base_url))
                .json(&serde_json::json!({
                    "keys": keys,
                    "outcome": outcome,
                })),
        )
        .await
    }

    pub async fn load_reputation_table(&self) -> Result<ReputationTable, DaemonClientError> {
        let body: ReputationTableResponse = self
            .request_typed(
                self.http
                    .get(format!("{}/api/reputation/table", self.base_url)),
            )
            .await?;
        serde_json::from_str(&body.table_json).map_err(|e| DaemonClientError::Parse(e.to_string()))
    }

    pub async fn reset_reputation(&self, profile: Option<&str>) -> Result<(), DaemonClientError> {
        self.request_empty(
            self.http
                .post(format!("{}/api/reputation/reset", self.base_url))
                .json(&serde_json::json!({ "profile": profile })),
        )
        .await
    }

    pub async fn proxy_filter_count(&self) -> Result<usize, DaemonClientError> {
        let body: ProxyStatusFullResponse = self
            .request_typed(
                self.http
                    .get(format!("{}/api/proxy/status/full", self.base_url)),
            )
            .await?;
        Ok(body.filter_count)
    }

    pub async fn ingest_audit(&self, record: &AuditRecord) -> Result<(), DaemonClientError> {
        self.request_empty(
            self.http
                .post(format!("{}/api/ipc/audit/ingest", self.base_url))
                .json(&serde_json::json!({ "record": record })),
        )
        .await
    }

    pub async fn install_inventory(
        &self,
        scope: grith_proxy::types::SessionScopeKey,
        entries: Vec<(String, String)>,
        total_scanned: usize,
        truncated: bool,
    ) -> Result<(), DaemonClientError> {
        self.request_empty(
            self.http
                .post(format!("{}/api/ipc/inventory/install", self.base_url))
                .json(&serde_json::json!({
                    "scope": scope.to_string(),
                    "entries": entries.into_iter()
                        .map(|(p, h)| serde_json::json!({ "path": p, "sha256": h }))
                        .collect::<Vec<_>>(),
                    "total_scanned": total_scanned,
                    "truncated": truncated,
                })),
        )
        .await
    }

    pub async fn enqueue_digest(&self, item: &DigestItem) -> Result<(), DaemonClientError> {
        self.request_empty(
            self.http
                .post(format!("{}/api/ipc/digest/items", self.base_url))
                .json(&serde_json::json!({ "item": item })),
        )
        .await
    }

    pub async fn get_digest(&self, item_id: Uuid) -> Result<Option<DigestItem>, DaemonClientError> {
        let response = self
            .http
            .get(format!("{}/api/ipc/digest/items/{item_id}", self.base_url))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| DaemonClientError::Network(e.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(DaemonClientError::Http(format!("{status}: {body}")));
        }
        response
            .json::<DigestItem>()
            .await
            .map(Some)
            .map_err(|e| DaemonClientError::Parse(e.to_string()))
    }

    pub async fn update_digest_status(
        &self,
        item_id: Uuid,
        status: DigestStatus,
        review_action: Option<&str>,
        reviewer_notes: Option<&str>,
    ) -> Result<(), DaemonClientError> {
        self.request_empty(
            self.http
                .post(format!(
                    "{}/api/ipc/digest/items/{item_id}/status",
                    self.base_url
                ))
                .json(&serde_json::json!({
                    "status": status,
                    "review_action": review_action,
                    "reviewer_notes": reviewer_notes,
                })),
        )
        .await
    }

    pub async fn expire_stale_digests(
        &self,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, DaemonClientError> {
        #[derive(Deserialize)]
        struct ExpireResponse {
            expired: u64,
        }
        let body: ExpireResponse = self
            .request_typed(
                self.http
                    .post(format!("{}/api/ipc/digest/expire", self.base_url))
                    .json(&serde_json::json!({
                        "before_rfc3339": before.to_rfc3339(),
                    })),
            )
            .await?;
        Ok(body.expired)
    }

    pub async fn register_session(
        &self,
        session: &SupervisorSession,
    ) -> Result<(), DaemonClientError> {
        self.request_empty(
            self.http
                .post(format!("{}/api/ipc/sessions", self.base_url))
                .json(&session_snapshot_json(session)),
        )
        .await
    }

    /// Register a session, distinguishing a session-limit rejection from other
    /// failures so the caller can render an upgrade prompt instead of a raw
    /// error. Parses the structured 429 envelope when present.
    pub async fn register_session_checked(
        &self,
        session: &SupervisorSession,
    ) -> Result<RegisterOutcome, DaemonClientError> {
        let response = self
            .http
            .post(format!("{}/api/ipc/sessions", self.base_url))
            .bearer_auth(&self.token)
            .json(&session_snapshot_json(session))
            .send()
            .await
            .map_err(|e| DaemonClientError::Network(e.to_string()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(RegisterOutcome::Registered);
        }
        let body = response.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            if let Ok(rej) = serde_json::from_str::<SessionLimitRejection>(&body) {
                return Ok(RegisterOutcome::LimitReached(rej));
            }
        }
        Err(DaemonClientError::Http(format!("{status}: {body}")))
    }

    /// Ask the daemon to reap dead sessions on demand. Returns (reaped, remaining).
    pub async fn prune_sessions(&self) -> Result<(u32, u32), DaemonClientError> {
        let body: PruneResponse = self
            .request_typed(
                self.http
                    .post(format!("{}/api/ipc/sessions-prune", self.base_url)),
            )
            .await?;
        Ok((body.reaped, body.remaining))
    }

    pub async fn sync_session(&self, session: &SupervisorSession) -> Result<(), DaemonClientError> {
        self.request_empty(
            self.http
                .put(format!("{}/api/ipc/sessions/{}", self.base_url, session.id))
                .json(&session_snapshot_json(session)),
        )
        .await
    }

    pub async fn unregister_session(&self, session_id: Uuid) -> Result<(), DaemonClientError> {
        self.request_empty(
            self.http
                .delete(format!("{}/api/ipc/sessions/{session_id}", self.base_url)),
        )
        .await
    }

    pub async fn list_sessions(&self) -> Result<Vec<RemoteSessionSummary>, DaemonClientError> {
        let body: SessionsResponse = self
            .request_typed(self.http.get(format!("{}/api/ipc/sessions", self.base_url)))
            .await?;
        Ok(body.sessions)
    }

    pub async fn get_session(
        &self,
        session_id: Uuid,
    ) -> Result<RemoteSessionDetail, DaemonClientError> {
        self.request_typed(
            self.http
                .get(format!("{}/api/ipc/sessions/{session_id}", self.base_url)),
        )
        .await
    }

    pub async fn kill_session(&self, session_id: Uuid) -> Result<(), DaemonClientError> {
        self.request_empty(self.http.post(format!(
            "{}/api/ipc/sessions/{session_id}/kill",
            self.base_url
        )))
        .await
    }

    async fn request_json(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<serde_json::Value, DaemonClientError> {
        self.request_typed(request).await
    }

    async fn request_typed<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, DaemonClientError> {
        let response = request
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| DaemonClientError::Network(e.to_string()))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(DaemonClientError::Http(format!("{status}: {body}")));
        }
        response
            .json::<T>()
            .await
            .map_err(|e| DaemonClientError::Parse(e.to_string()))
    }

    async fn request_empty(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<(), DaemonClientError> {
        let response = request
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| DaemonClientError::Network(e.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(DaemonClientError::Http(format!("{status}: {body}")))
        }
    }

    /// Forward a supervisor event to the daemon for WebSocket broadcast.
    pub async fn forward_event(&self, event: &serde_json::Value) -> Result<(), DaemonClientError> {
        self.request_empty(
            self.http
                .post(format!("{}/api/ipc/events", self.base_url))
                .json(event)
                .timeout(Duration::from_secs(2)),
        )
        .await
    }
}

fn session_snapshot_json(session: &SupervisorSession) -> serde_json::Value {
    serde_json::json!({
        "id": session.id.to_string(),
        "tool_name": session.tool_name.clone(),
        "profile_name": session.profile_name.clone(),
        "policy_scope": session.policy_scope.clone(),
        "launcher_overlay_name": session.launcher_overlay_name.clone(),
        "provider_overlay_name": session.provider_overlay_name.clone(),
        "root_pid": session.root_pid,
        "project_name": session.project_name.clone(),
        "cwd": session.cwd.clone(),
        "tty": session.tty.clone(),
        "process_tree_pids": session.process_tree.all_pids(),
        "stats": session.stats.clone(),
    })
}

#[derive(Debug)]
pub enum DaemonClientError {
    Network(String),
    Http(String),
    Parse(String),
}

impl std::fmt::Display for DaemonClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "daemon network error: {e}"),
            Self::Http(e) => write!(f, "daemon HTTP error: {e}"),
            Self::Parse(e) => write!(f, "daemon response parse error: {e}"),
        }
    }
}

impl std::error::Error for DaemonClientError {}

fn parse_evaluate_response(body: &serde_json::Value) -> Result<ProxyDecision, DaemonClientError> {
    let composite_score = body["composite_score"]
        .as_f64()
        .ok_or_else(|| DaemonClientError::Parse("missing composite_score".into()))?;
    let action_str = body["action"]
        .as_str()
        .ok_or_else(|| DaemonClientError::Parse("missing action".into()))?;

    let action = if action_str == "allow" {
        grith_proxy::types::ProxyAction::Allow
    } else if let Some(rest) = action_str.strip_prefix("deny:") {
        grith_proxy::types::ProxyAction::Deny {
            reason: rest.to_string(),
        }
    } else if action_str.starts_with("queue:") {
        let priority = if action_str.contains("Critical") {
            QueuePriority::Critical
        } else if action_str.contains("High") {
            QueuePriority::High
        } else if action_str.contains("Medium") {
            QueuePriority::Medium
        } else {
            QueuePriority::Low
        };
        grith_proxy::types::ProxyAction::Queue { priority }
    } else {
        return Err(DaemonClientError::Parse(format!(
            "unknown action: {action_str}"
        )));
    };

    let filter_results = body["filter_results"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|fr| {
                    Some(grith_proxy::types::FilterResult {
                        filter_name: fr["filter_name"].as_str()?.to_string(),
                        matched: fr["matched"].as_bool()?,
                        score: fr["score"].as_f64()?,
                        rule_id: String::new(),
                        severity: Severity::Notice,
                        message: String::new(),
                        metadata: std::collections::HashMap::new(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(ProxyDecision {
        action,
        composite_score,
        filter_results,
        evaluation_time: Duration::from_secs_f64(
            body["evaluation_time_ms"].as_f64().unwrap_or(0.0) / 1000.0,
        ),
        decision_reason: body["decision_reason"].as_str().unwrap_or("").to_string(),
    })
}

/// Remote audit sink for daemon-owned audit storage.
pub struct RemoteAuditSink {
    client: DaemonClient,
}

impl RemoteAuditSink {
    pub fn new(client: DaemonClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl grith_supervisor::AuditSink for RemoteAuditSink {
    async fn log(&self, record: AuditRecord) -> std::result::Result<(), String> {
        self.client
            .ingest_audit(&record)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Pushes the session-pinned binary inventory to the daemon so the
/// dashboard's `/api/inventory` endpoint (which reads from the daemon's
/// per-process `SessionStateRegistry::global()`) can render it. The
/// supervisor's own registry is already populated by
/// `set_pinned_inventory` — this push is purely for cross-process UI.
pub struct RemoteInventorySink {
    client: DaemonClient,
}

impl RemoteInventorySink {
    pub fn new(client: DaemonClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl grith_supervisor::InventorySink for RemoteInventorySink {
    async fn install(
        &self,
        scope: grith_proxy::types::SessionScopeKey,
        inventory: grith_proxy::session_state::SessionPinnedInventory,
    ) -> std::result::Result<(), String> {
        let entries: Vec<(String, String)> = inventory
            .iter()
            .map(|(p, h)| (p.to_string(), h.to_string()))
            .collect();
        self.client
            .install_inventory(scope, entries, inventory.total_scanned, inventory.truncated)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Remote digest backend for daemon-owned review state.
pub struct RemoteDigestStore {
    client: DaemonClient,
}

impl RemoteDigestStore {
    pub fn new(client: DaemonClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl grith_supervisor::DigestStore for RemoteDigestStore {
    async fn enqueue(&self, item: &DigestItem) -> std::result::Result<(), String> {
        self.client
            .enqueue_digest(item)
            .await
            .map_err(|e| e.to_string())
    }

    async fn get(&self, item_id: Uuid) -> std::result::Result<Option<DigestItem>, String> {
        self.client
            .get_digest(item_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn update_status(
        &self,
        item_id: Uuid,
        status: DigestStatus,
        review_action: Option<&str>,
        reviewer_notes: Option<&str>,
    ) -> std::result::Result<(), String> {
        self.client
            .update_digest_status(item_id, status, review_action, reviewer_notes)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Remote session-state synchroniser for thin exec sessions.
pub struct RemoteSessionSync {
    client: DaemonClient,
    min_interval: Duration,
    last_sync: Mutex<Option<Instant>>,
}

impl RemoteSessionSync {
    pub fn new(client: DaemonClient, min_interval: Duration) -> Self {
        Self {
            client,
            min_interval,
            last_sync: Mutex::new(None),
        }
    }
}

#[async_trait]
impl grith_supervisor::SessionSync for RemoteSessionSync {
    async fn sync(&self, session: &SupervisorSession) -> std::result::Result<(), String> {
        if let Ok(mut last_sync) = self.last_sync.lock() {
            if let Some(last) = *last_sync {
                if last.elapsed() < self.min_interval {
                    return Ok(());
                }
            }
            *last_sync = Some(Instant::now());
        }
        self.client
            .sync_session(session)
            .await
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_evaluate_response_roundtrips_allow() {
        let body = serde_json::json!({
            "composite_score": 1.25,
            "action": "allow",
            "decision_reason": "trusted",
            "filter_results": [
                {
                    "filter_name": "allowlist",
                    "matched": true,
                    "score": 0.0
                }
            ],
            "evaluation_time_ms": 2.5
        });

        let decision = parse_evaluate_response(&body).expect("allow response should parse");
        assert!(matches!(
            decision.action,
            grith_proxy::types::ProxyAction::Allow
        ));
        assert_eq!(decision.composite_score, 1.25);
        assert_eq!(decision.filter_results.len(), 1);
        assert_eq!(decision.filter_results[0].filter_name, "allowlist");
        assert_eq!(decision.evaluation_time, Duration::from_micros(2500));
    }

    #[test]
    fn parse_evaluate_response_roundtrips_queue_priority() {
        let body = serde_json::json!({
            "composite_score": 6.5,
            "action": "queue:Critical",
            "decision_reason": "review required",
            "filter_results": [],
            "evaluation_time_ms": 4.0
        });

        let decision = parse_evaluate_response(&body).expect("queue response should parse");
        assert!(matches!(
            decision.action,
            grith_proxy::types::ProxyAction::Queue {
                priority: QueuePriority::Critical
            }
        ));
        assert_eq!(decision.decision_reason, "review required");
    }

    #[test]
    fn parse_evaluate_response_roundtrips_deny_reason() {
        let body = serde_json::json!({
            "composite_score": 9.8,
            "action": "deny:daemon_unreachable",
            "decision_reason": "denied",
            "filter_results": [],
            "evaluation_time_ms": 0.0
        });

        let decision = parse_evaluate_response(&body).expect("deny response should parse");
        assert!(matches!(
            decision.action,
            grith_proxy::types::ProxyAction::Deny { ref reason } if reason == "daemon_unreachable"
        ));
    }

    #[test]
    fn parse_evaluate_response_rejects_unknown_action() {
        let body = serde_json::json!({
            "composite_score": 1.0,
            "action": "bogus",
            "decision_reason": "bad",
            "filter_results": [],
            "evaluation_time_ms": 1.0
        });

        let error = parse_evaluate_response(&body).expect_err("unknown action must fail");
        assert!(matches!(error, DaemonClientError::Parse(_)));
        assert!(error.to_string().contains("unknown action"));
    }
}
