// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Daemon IPC client for thin grith sessions.

use std::sync::{Arc, Mutex};
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
    /// Bearer token for daemon IPC. Shared and refreshable: a daemon restart
    /// rotates the token on disk, and the first 401/403 triggers a re-read so
    /// every clone of this client heals together instead of failing until the
    /// session ends (the stale-token DNS outage of 2026-08-13, where a live
    /// daemon rejected every audit enqueue and fail-closed DNS denied all
    /// resolution for the supervised tool).
    token: Arc<Mutex<String>>,
    http: reqwest::Client,
    /// Instance id of the daemon this client admitted the session against,
    /// captured once at [`DaemonClient::connect`] time (B12 #77). Stamped
    /// into every session snapshot so the daemon's adopt-on-heartbeat path can
    /// detect a session whose authority is crossing a daemon-instance boundary
    /// (the original daemon restarted). Deliberately *not* refreshed on
    /// reconnect — refreshing would capture the replacement daemon's id and
    /// mask the very transition it exists to reveal. `None` when the daemon
    /// published no identity we could read.
    instance_id: Option<String>,
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

/// Outcome of asking the daemon to reserve a capacity slot before spawning
/// (work/74 Phase 1).
#[derive(Debug)]
pub enum ReserveOutcome {
    /// A seat is held for us; the caller must activate or cancel it.
    Reserved(Uuid),
    /// The cap is full — refuse *before* spawning anything.
    LimitReached(SessionLimitRejection),
    /// The daemon predates reservations (no such route). The caller falls
    /// back to the legacy register-after-spawn path for one release, because
    /// hard-failing a new CLI against an older daemon would repeat the
    /// stale-daemon lockout incident.
    Unsupported,
}

#[derive(Debug, Clone, Deserialize)]
struct ReservationResponse {
    reservation_id: String,
}

#[derive(Deserialize)]
struct ReputationTableResponse {
    table_json: String,
}

#[derive(Deserialize)]
struct ProxyStatusFullResponse {
    filter_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteTierSummary {
    pub tier: String,
}

impl RemoteTierSummary {
    pub fn is_paid(&self) -> bool {
        matches!(
            self.tier.trim().to_ascii_lowercase().as_str(),
            "pro" | "pro_trial" | "enterprise"
        )
    }
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

        let mut client = Self {
            base_url,
            token: Arc::new(Mutex::new(token)),
            http,
            instance_id: None,
        };

        let rt = tokio::runtime::Handle::try_current();
        let (healthy, instance_id) = match rt {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let healthy = client.authenticated_health_check().await;
                    let id = client.fetch_daemon_instance_id().await;
                    (healthy, id)
                })
            }),
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok()?;
                rt.block_on(async {
                    let healthy = client.authenticated_health_check().await;
                    let id = client.fetch_daemon_instance_id().await;
                    (healthy, id)
                })
            }
        };

        // B12 #77: capture the admitting daemon's identity once. A daemon that
        // published no identity leaves this None — the adopt path treats that
        // as "cannot compare" rather than blocking the session.
        client.instance_id = instance_id;
        healthy.then_some(client)
    }

    /// Best-effort read of the daemon's `instance_id` from `/health`. Any
    /// failure (older daemon, no identity published, transport error) yields
    /// `None`; the caller never treats that as a match.
    async fn fetch_daemon_instance_id(&self) -> Option<String> {
        let resp = self
            .http
            .get(format!("{}/health", self.base_url))
            .timeout(Duration::from_millis(500))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        body.get("instance_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
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

    pub async fn tier_summary(&self) -> Result<RemoteTierSummary, DaemonClientError> {
        self.request_typed(self.http.get(format!("{}/api/tier", self.base_url)))
            .await
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
            .send_authorized(
                self.http
                    .get(format!("{}/api/ipc/digest/items/{item_id}", self.base_url)),
            )
            .await?;
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
                .json(&self.session_snapshot_json(session)),
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
            .send_authorized(
                self.http
                    .post(format!("{}/api/ipc/sessions", self.base_url))
                    .json(&self.session_snapshot_json(session)),
            )
            .await?;
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

    /// Reserve a capacity slot before spawning the supervised target
    /// (work/74 Phase 1, go-live review B12 item 1).
    ///
    /// Returns [`ReserveOutcome::Unsupported`] against a daemon that predates
    /// the route so the caller can fall back to registering after the spawn.
    pub async fn reserve_session(
        &self,
        tool_name: &str,
        profile_name: Option<&str>,
    ) -> Result<ReserveOutcome, DaemonClientError> {
        let response = self
            .send_authorized(
                self.http
                    .post(format!("{}/api/ipc/session-reservations", self.base_url))
                    .json(&serde_json::json!({
                        "tool_name": tool_name,
                        "profile_name": profile_name,
                    })),
            )
            .await?;
        let status = response.status();
        if status.is_success() {
            let body: ReservationResponse = response
                .json()
                .await
                .map_err(|e| DaemonClientError::Parse(e.to_string()))?;
            let id = Uuid::parse_str(&body.reservation_id)
                .map_err(|e| DaemonClientError::Parse(e.to_string()))?;
            return Ok(ReserveOutcome::Reserved(id));
        }
        // An older daemon has no such route. Axum answers an unknown path
        // with 404 and an unknown method with 405; treat both as "this
        // daemon can't reserve" rather than as a hard failure.
        if status == reqwest::StatusCode::NOT_FOUND
            || status == reqwest::StatusCode::METHOD_NOT_ALLOWED
        {
            return Ok(ReserveOutcome::Unsupported);
        }
        let body = response.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            if let Ok(rej) = serde_json::from_str::<SessionLimitRejection>(&body) {
                return Ok(ReserveOutcome::LimitReached(rej));
            }
        }
        Err(DaemonClientError::Http(format!("{status}: {body}")))
    }

    /// Activate a held reservation once the spawn has succeeded.
    ///
    /// Idempotent server-side, so a retry after a lost response does not
    /// consume a second seat.
    pub async fn activate_session(
        &self,
        reservation_id: Uuid,
        session: &SupervisorSession,
    ) -> Result<RegisterOutcome, DaemonClientError> {
        let response = self
            .send_authorized(
                self.http
                    .post(format!(
                        "{}/api/ipc/session-reservations/{reservation_id}/activate",
                        self.base_url
                    ))
                    .json(&self.session_snapshot_json(session)),
            )
            .await?;
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

    /// Release a reservation whose spawn failed. Best-effort: the daemon's
    /// TTL reaper reclaims the seat regardless, so callers log and move on.
    pub async fn cancel_session_reservation(
        &self,
        reservation_id: Uuid,
    ) -> Result<(), DaemonClientError> {
        self.request_empty(self.http.delete(format!(
            "{}/api/ipc/session-reservations/{reservation_id}",
            self.base_url
        )))
        .await
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
                .json(&self.session_snapshot_json(session)),
        )
        .await
    }

    /// Heartbeat that distinguishes an authoritative refusal from a transport
    /// failure (work/74 Phase 3).
    ///
    /// A 409 means the daemon answered and is not accounting for this
    /// session; anything else that fails is treated as retryable, because a
    /// daemon that is merely restarting must not be mistaken for one that has
    /// disowned us.
    pub async fn sync_session_checked(
        &self,
        session: &SupervisorSession,
    ) -> Result<(), grith_supervisor::SyncFailure> {
        let response = self
            .send_authorized(
                self.http
                    .put(format!("{}/api/ipc/sessions/{}", self.base_url, session.id))
                    .json(&self.session_snapshot_json(session)),
            )
            .await
            .map_err(|e| grith_supervisor::SyncFailure::Transport(e.to_string()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = response.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::CONFLICT {
            let message = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| {
                    v.get("message")
                        .and_then(|m| m.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| format!("daemon refused to track this session: {body}"));
            return Err(grith_supervisor::SyncFailure::AuthorityLost(message));
        }
        // B12 #79 LOW: classify by status class rather than treating every
        // non-409 as retryable Transport. A 4xx means the daemon *answered*
        // and rejected the request — an authoritative refusal that retrying
        // will not fix — so it is AuthorityLost, mirroring the 409 case.
        // 408/429 are the transient 4xx exceptions (timeout / rate limit), and
        // 5xx means the daemon is unhealthy or restarting; both stay Transport
        // so a blip is not mistaken for disownment.
        let transient = status.is_server_error()
            || status == reqwest::StatusCode::REQUEST_TIMEOUT
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
        if status.is_client_error() && !transient {
            return Err(grith_supervisor::SyncFailure::AuthorityLost(format!(
                "daemon refused this session with {status}: {body}"
            )));
        }
        Err(grith_supervisor::SyncFailure::Transport(format!(
            "{status}: {body}"
        )))
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

    fn current_token(&self) -> String {
        self.token
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Re-read the IPC token from disk after an auth rejection.
    fn refreshed_token(&self, just_used: &str) -> Option<String> {
        Self::adopt_refreshed_token(&self.token, just_used, super::token::read_token()?)
    }

    /// Adopt a freshly read token only when it differs from the one the
    /// daemon just rejected — retrying with an identical token cannot
    /// succeed, so the caller lets the original rejection stand.
    fn adopt_refreshed_token(
        shared: &Arc<Mutex<String>>,
        just_used: &str,
        fresh: String,
    ) -> Option<String> {
        if fresh == just_used {
            return None;
        }
        if let Ok(mut guard) = shared.lock() {
            *guard = fresh.clone();
        }
        tracing::info!(
            event = "ipc_token_refreshed",
            "daemon IPC token reloaded from disk after auth rejection"
        );
        Some(fresh)
    }

    /// Send `request` with bearer auth, retrying once with a token re-read
    /// from disk when the daemon answers 401/403. A daemon restart rotates
    /// the IPC token; without the retry, every long-lived session keeps
    /// failing against a perfectly healthy daemon even though the current
    /// token sits on disk the whole time.
    async fn send_authorized(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, DaemonClientError> {
        let retry = request.try_clone();
        let used = self.current_token();
        let response = request
            .bearer_auth(&used)
            .send()
            .await
            .map_err(|e| DaemonClientError::Network(e.to_string()))?;
        let status = response.status();
        if status != reqwest::StatusCode::UNAUTHORIZED && status != reqwest::StatusCode::FORBIDDEN {
            return Ok(response);
        }
        let (Some(retry), Some(fresh)) = (retry, self.refreshed_token(&used)) else {
            return Ok(response);
        };
        retry
            .bearer_auth(&fresh)
            .send()
            .await
            .map_err(|e| DaemonClientError::Network(e.to_string()))
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
        let response = self.send_authorized(request).await?;
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
        let response = self.send_authorized(request).await?;
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

impl DaemonClient {
    /// Build the session snapshot wire body, stamping the admitting daemon's
    /// instance id (B12 #77) so the daemon can detect an authority transfer
    /// across a restart on the adopt-on-heartbeat path.
    fn session_snapshot_json(&self, session: &SupervisorSession) -> serde_json::Value {
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
            "admitting_instance_id": self.instance_id.clone(),
        })
    }
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
    async fn sync(
        &self,
        session: &SupervisorSession,
    ) -> std::result::Result<grith_supervisor::SyncOutcome, grith_supervisor::SyncFailure> {
        if let Ok(mut last_sync) = self.last_sync.lock() {
            if let Some(last) = *last_sync {
                if last.elapsed() < self.min_interval {
                    // B12 #79: a throttled beat contacts nobody, so it proves
                    // nothing about daemon authority. Report it as Throttled —
                    // NOT Ok — so the supervisor does not mistake a skipped
                    // heartbeat for the daemon confirming it still tracks us.
                    return Ok(grith_supervisor::SyncOutcome::Throttled);
                }
            }
            *last_sync = Some(Instant::now());
        }
        self.client
            .sync_session_checked(session)
            .await
            .map(|()| grith_supervisor::SyncOutcome::Confirmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B12 #77: every session snapshot the CLI sends carries the admitting
    /// daemon's instance id, so the daemon's adopt path can detect an
    /// authority transfer across a restart. A client with no captured
    /// identity emits null, which the daemon reads as "cannot compare".
    #[test]
    fn snapshot_json_stamps_the_admitting_instance_id() {
        let client = DaemonClient {
            base_url: "http://127.0.0.1:0".into(),
            token: Arc::new(Mutex::new("t".into())),
            http: reqwest::Client::new(),
            instance_id: Some("inst-123".into()),
        };
        let session = SupervisorSession::new("claude-code", 4242);
        let body = client.session_snapshot_json(&session);
        assert_eq!(body["admitting_instance_id"], serde_json::json!("inst-123"));

        let anon = DaemonClient {
            instance_id: None,
            ..client
        };
        let body = anon.session_snapshot_json(&session);
        assert!(
            body["admitting_instance_id"].is_null(),
            "a client without a captured identity must emit null"
        );
    }

    /// B12 #79: a heartbeat skipped by the throttle must report `Throttled`,
    /// never `Confirmed`. Reporting a skipped beat as confirmed is what let
    /// the supervisor read it as "the daemon is tracking us again" and flap.
    #[tokio::test]
    async fn throttled_heartbeat_reports_throttled_not_confirmed() {
        use grith_supervisor::{SessionSync, SyncOutcome};

        let client = DaemonClient {
            // Nothing is listening on port 1 — the first (unthrottled) beat
            // fails transport immediately, which is all we need: it arms the
            // throttle window.
            base_url: "http://127.0.0.1:1".into(),
            token: Arc::new(Mutex::new("t".into())),
            http: reqwest::Client::new(),
            instance_id: None,
        };
        let sync = RemoteSessionSync::new(client, Duration::from_secs(3600));
        let session = SupervisorSession::new("claude-code", 4242);

        // First beat attempts a send (and fails transport — no daemon), arming
        // the min-interval window.
        let _ = sync.sync(&session).await;
        // Second beat, well within the interval, is skipped — and must be
        // reported Throttled, never Confirmed.
        assert_eq!(
            sync.sync(&session).await.unwrap(),
            SyncOutcome::Throttled,
            "a throttled heartbeat must not masquerade as a confirmed one"
        );
    }

    /// Stale-token recovery: a token re-read from disk is adopted (and shared
    /// with every clone) only when it differs from the one the daemon just
    /// rejected — an identical token cannot make the retry succeed.
    #[test]
    fn adopt_refreshed_token_only_on_change() {
        let shared = Arc::new(Mutex::new("stale".to_string()));

        // Same token on disk as the rejected one: nothing to adopt.
        assert_eq!(
            DaemonClient::adopt_refreshed_token(&shared, "stale", "stale".into()),
            None
        );
        assert_eq!(*shared.lock().unwrap(), "stale");

        // Rotated token on disk: adopted and visible to every clone.
        assert_eq!(
            DaemonClient::adopt_refreshed_token(&shared, "stale", "fresh".into()),
            Some("fresh".to_string())
        );
        assert_eq!(*shared.lock().unwrap(), "fresh");
    }

    #[test]
    fn remote_tier_summary_distinguishes_paid_accounts() {
        for tier in ["pro", "Pro", "pro_trial", "enterprise"] {
            assert!(RemoteTierSummary {
                tier: tier.to_string()
            }
            .is_paid());
        }
        assert!(!RemoteTierSummary {
            tier: "community".to_string()
        }
        .is_paid());
    }

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
