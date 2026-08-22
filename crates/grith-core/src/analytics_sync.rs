// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Cloud analytics upload worker — the client half of the analytics-v2
//! protocol.
//!
//! Ships the local analytics projection to the team's cloud dashboard on a
//! 30-second cadence: device registration, heartbeats, dirty-day snapshot
//! uploads with byte-exact retries, acknowledgement bookkeeping and
//! source-epoch reset handshakes. Uploads carry aggregated metrics only —
//! never commands, file paths, prompts or payloads.
//!
//! The worker runs only in the audit-owner daemon process and never uploads
//! without all four gates: an active Pro entitlement, `general.audit_sync`,
//! a signed-in account, and a consent receipt. Cloud analytics is part of
//! the paid plan, so a signed-in entitled account with no recorded choice
//! defaults ON (the receipt is written at that moment); `grith analytics
//! disable` records the opt-out and is always honoured.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDate, Utc};
use grith_analytics::contract::{
    CompletenessTier, ConsentReceipt, DestinationPolicy, HeartbeatRequest, HeartbeatResponse,
    RegistrationRequest, RegistrationResponse, RequestContext, SnapshotRequest, SnapshotResponse,
    SourceResetReason, SourceResetRequest, SourceResetResponse, StateResponse, StructuredError,
};
use grith_audit::AuditStorage;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::license::{api_url, config_dir, load_credentials, Credentials, FeatureGate};

/// Version of the consent text the user accepted. Bump when the scope of
/// uploaded data changes; an older recorded version stops uploads until the
/// user re-consents.
pub const CONSENT_VERSION: u16 = 1;

/// Default upload/heartbeat cadence; the server may adjust it per response.
const DEFAULT_TICK_SECONDS: u64 = 30;
/// Idle re-check cadence while any gate (login, consent, plan) is closed.
const IDLE_TICK_SECONDS: u64 = 60;
/// Back-off after hard authentication/entitlement failures, so a revoked or
/// lapsed device does not hammer the API every tick.
const HARD_FAILURE_BACKOFF: Duration = Duration::from_secs(15 * 60);
/// Back-off for a day the server rejected as invalid, so a poison snapshot
/// cannot wedge the queue into a tight retry loop.
const REJECTED_DAY_BACKOFF: Duration = Duration::from_secs(60 * 60);
/// Wire cap on security events per request (per-request cap only).
const MAX_SECURITY_EVENTS_PER_REQUEST: usize = 500;
/// Wire cap on configuration versions per request.
const MAX_CONFIG_VERSIONS_PER_REQUEST: usize = 64;

// ---------------------------------------------------------------------------
// Durable consent + device identity files
// ---------------------------------------------------------------------------

/// The user's recorded analytics-upload consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyticsConsent {
    pub consent_version: u16,
    pub accepted_at: DateTime<Utc>,
    pub enabled: bool,
}

impl AnalyticsConsent {
    /// Consent that authorises uploads right now.
    pub fn authorises_upload(&self) -> bool {
        self.enabled && self.consent_version >= CONSENT_VERSION
    }
}

/// Server-issued device identity. The secret authenticates every device
/// route and is stored with owner-only permissions, like the API key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyticsDevice {
    pub device_id: Uuid,
    pub device_secret: String,
    pub credential_version: u16,
    pub team_id: Uuid,
    pub actor_user_id: String,
    /// The source epoch the server currently considers active for this
    /// device. When the local projection rotates away from it, the worker
    /// performs the source-reset handshake before uploading again.
    pub source_epoch: Uuid,
    pub registered_at: DateTime<Utc>,
    pub destination_policy: DestinationPolicy,
    /// Whether the one-shot "sync disabled" heartbeat has been delivered
    /// since uploads were last disabled.
    #[serde(default)]
    pub disabled_heartbeat_sent: bool,
    /// Set when the server reports the device revoked; stops retries until
    /// the user re-enables analytics (which re-registers).
    #[serde(default)]
    pub revoked: bool,
}

pub fn consent_path() -> PathBuf {
    config_dir().join("analytics-consent.json")
}

pub fn device_path() -> PathBuf {
    config_dir().join("analytics-device.json")
}

pub fn load_consent() -> Option<AnalyticsConsent> {
    let data = std::fs::read_to_string(consent_path()).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn save_consent(consent: &AnalyticsConsent) -> std::io::Result<()> {
    write_private_json(&consent_path(), consent)
}

pub fn load_device() -> Option<AnalyticsDevice> {
    let data = std::fs::read_to_string(device_path()).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn save_device(device: &AnalyticsDevice) -> std::io::Result<()> {
    write_private_json(&device_path(), device)
}

pub fn remove_device() -> std::io::Result<()> {
    match std::fs::remove_file(device_path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn write_private_json<T: Serialize>(path: &std::path::Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(value)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(data.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)
}

// ---------------------------------------------------------------------------
// HTTP transport
// ---------------------------------------------------------------------------

/// A failed analytics API call, split so the worker can tell transport
/// trouble (retry next tick) from server verdicts (typed recovery).
#[derive(Debug)]
pub enum UploadError {
    /// Network/transport failure or an unparseable response.
    Transport(String),
    /// The server answered with a structured analytics error.
    Api {
        status: u16,
        code: String,
        message: String,
    },
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(message) => write!(f, "transport: {message}"),
            Self::Api {
                status,
                code,
                message,
                ..
            } => write!(f, "{status} {code}: {message}"),
        }
    }
}

impl UploadError {
    fn code(&self) -> &str {
        match self {
            Self::Transport(_) => "",
            Self::Api { code, .. } => code,
        }
    }
}

fn build_client() -> Result<reqwest::Client, UploadError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(format!("grith-daemon/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| UploadError::Transport(error.to_string()))
}

async fn read_error(response: reqwest::Response) -> UploadError {
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    match serde_json::from_str::<StructuredError>(&body) {
        Ok(structured) => {
            let mut message = structured.error.message;
            if !structured.error.field_violations.is_empty() {
                let detail = structured
                    .error
                    .field_violations
                    .iter()
                    .map(|violation| format!("{}: {}", violation.field, violation.rule))
                    .collect::<Vec<_>>()
                    .join("; ");
                message = format!("{message} ({detail})");
            }
            UploadError::Api {
                status,
                code: structured.error.code,
                message,
            }
        }
        Err(_) => UploadError::Api {
            status,
            // Plan-gate middleware answers with its own body shape; map the
            // status class so callers can still route on it.
            code: match status {
                401 => "authentication_required".into(),
                402 | 403 => "entitlement_required".into(),
                429 => "rate_limited".into(),
                _ => "http_error".into(),
            },
            message: body.chars().take(200).collect(),
        },
    }
}

async fn post_raw<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    path: &str,
    api_key: &str,
    device_secret: Option<&str>,
    body: String,
) -> Result<T, UploadError> {
    let mut request = client
        .post(api_url(path))
        .header("x-grith-api-key", api_key)
        .header("content-type", "application/json")
        .body(body);
    if let Some(secret) = device_secret {
        request = request.header("x-grith-device-secret", secret);
    }
    let response = request
        .send()
        .await
        .map_err(|error| UploadError::Transport(error.to_string()))?;
    if !response.status().is_success() {
        return Err(read_error(response).await);
    }
    response
        .json::<T>()
        .await
        .map_err(|error| UploadError::Transport(error.to_string()))
}

async fn post_json<B: Serialize, T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    path: &str,
    api_key: &str,
    device_secret: Option<&str>,
    body: &B,
) -> Result<T, UploadError> {
    let body =
        serde_json::to_string(body).map_err(|error| UploadError::Transport(error.to_string()))?;
    post_raw(client, path, api_key, device_secret, body).await
}

async fn fetch_state(
    client: &reqwest::Client,
    creds: &Credentials,
    device: &AnalyticsDevice,
) -> Result<StateResponse, UploadError> {
    let response = client
        .get(api_url(&format!(
            "/api/analytics/v2/state?device_id={}",
            device.device_id
        )))
        .header("x-grith-api-key", &creds.api_key)
        .header("x-grith-device-secret", &device.device_secret)
        .send()
        .await
        .map_err(|error| UploadError::Transport(error.to_string()))?;
    if !response.status().is_success() {
        return Err(read_error(response).await);
    }
    response
        .json::<StateResponse>()
        .await
        .map_err(|error| UploadError::Transport(error.to_string()))
}

// ---------------------------------------------------------------------------
// Request assembly (pure with respect to the network)
// ---------------------------------------------------------------------------

/// A serialized snapshot request persisted to the outbox before first send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedUpload {
    pub request_seq: u64,
    pub source_epoch: Uuid,
    pub day: Option<NaiveDate>,
    pub body: String,
}

/// Build, durably enqueue and return the next snapshot request: the oldest
/// pending day (if any) plus unacknowledged security events and recent
/// configuration versions. Returns `Ok(None)` when nothing needs uploading.
pub fn prepare_next_upload(
    storage: &mut AuditStorage,
    device: &AnalyticsDevice,
    runtime_instance_id: Uuid,
    completeness: CompletenessTier,
    skip_day: impl Fn(NaiveDate) -> bool,
) -> Result<Option<PreparedUpload>, grith_audit::Error> {
    let epoch = device.source_epoch;
    let pending = storage
        .analytics_upload_pending_days(epoch, 8)?
        .into_iter()
        .find(|candidate| !skip_day(candidate.day));
    let security_events =
        storage.analytics_unacked_security_events(epoch, MAX_SECURITY_EVENTS_PER_REQUEST)?;
    if pending.is_none() && security_events.is_empty() {
        return Ok(None);
    }
    let day_snapshots = match &pending {
        Some(day) => vec![storage.analytics_build_day_snapshot(epoch, day.day)?],
        None => Vec::new(),
    };
    let config_versions =
        storage.analytics_config_versions_recent(MAX_CONFIG_VERSIONS_PER_REQUEST)?;
    let request_seq = storage.analytics_allocate_request_seq()?;
    let request = SnapshotRequest {
        context: RequestContext::v2(
            device.device_id,
            epoch,
            request_seq,
            runtime_instance_id,
            Utc::now(),
            env!("CARGO_PKG_VERSION"),
            completeness,
        ),
        config_versions,
        day_snapshots,
        security_events,
    };
    let body = serde_json::to_string(&request)
        .map_err(|error| grith_audit::Error::Analytics(error.to_string()))?;
    let day = pending.as_ref().map(|value| value.day);
    storage.analytics_outbox_put(request_seq, "snapshot", epoch, day, &body)?;
    Ok(Some(PreparedUpload {
        request_seq,
        source_epoch: epoch,
        day,
        body,
    }))
}

/// Apply a successful snapshot response: record day and security-event
/// acknowledgements, then retire the outbox entry.
pub fn apply_snapshot_response(
    storage: &mut AuditStorage,
    source_epoch: Uuid,
    response: &SnapshotResponse,
) -> Result<(), grith_audit::Error> {
    for day in &response.accepted_days {
        storage.analytics_record_day_ack(source_epoch, day.day, day.day_revision)?;
    }
    let acks: Vec<(Uuid, u32)> = response
        .security_event_acknowledgements
        .iter()
        .map(|ack| (ack.event_id, ack.event_revision))
        .collect();
    if !acks.is_empty() {
        storage.analytics_record_security_acks(&acks)?;
    }
    storage.analytics_outbox_delete(response.accepted_request_seq)?;
    Ok(())
}

/// Reconcile local acknowledgement state against the server's `/state` view
/// for the given epoch: adopt every day revision the server already accepted.
pub fn reconcile_state(
    storage: &mut AuditStorage,
    source_epoch: Uuid,
    state: &StateResponse,
) -> Result<(), grith_audit::Error> {
    for day in &state.days {
        if day.source_epoch == source_epoch {
            storage.analytics_reconcile_server_day(
                source_epoch,
                day.day,
                day.accepted_day_revision,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn completeness_tier(value: crate::config::AuditCompleteness) -> CompletenessTier {
    match value {
        crate::config::AuditCompleteness::Decisions => CompletenessTier::Decisions,
        crate::config::AuditCompleteness::Spawns => CompletenessTier::Spawns,
        crate::config::AuditCompleteness::Io => CompletenessTier::Io,
        crate::config::AuditCompleteness::All => CompletenessTier::All,
    }
}

fn device_display_name() -> String {
    #[cfg(unix)]
    if let Ok(name) = std::fs::read_to_string("/etc/hostname") {
        let name = name.trim();
        if !name.is_empty() {
            return name.chars().take(64).collect();
        }
    }
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .map(|name| name.chars().take(64).collect())
        .unwrap_or_else(|_| "grith-device".into())
}

fn map_reset_reason(raw: Option<&str>) -> SourceResetReason {
    match raw {
        Some("audit_history_lost") => SourceResetReason::AuditHistoryLost,
        Some("audit_database_generation_changed") => {
            SourceResetReason::AuditDatabaseGenerationChanged
        }
        Some("manual_reset") => SourceResetReason::ManualReset,
        _ => SourceResetReason::LocalProjectionLost,
    }
}

// ---------------------------------------------------------------------------
// The worker loop
// ---------------------------------------------------------------------------

/// Everything the worker needs from the daemon.
pub struct AnalyticsSyncDeps {
    pub audit_storage: Arc<Mutex<AuditStorage>>,
    pub feature_gate: Arc<RwLock<FeatureGate>>,
    /// `general.audit_sync` at daemon start; config changes need a restart.
    pub audit_sync_enabled: bool,
    /// `audit.completeness` at daemon start.
    pub completeness: CompletenessTier,
}

/// Long-running upload loop. Runs until the shutdown broadcast fires.
pub async fn analytics_upload_task(
    deps: AnalyticsSyncDeps,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    // A fresh id per daemon process: the server's 90-second runtime lease
    // guarantees at most one live uploader per device.
    let runtime_instance_id = Uuid::new_v4();
    let client = match build_client() {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(error = %error, "analytics upload disabled: HTTP client failed");
            return;
        }
    };
    let mut worker = Worker {
        deps,
        client,
        runtime_instance_id,
        rejected_days: HashMap::new(),
        backoff_until: None,
        tick_seconds: DEFAULT_TICK_SECONDS,
    };
    loop {
        let sleep_for = Duration::from_secs(worker.tick_seconds);
        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {}
            _ = shutdown_rx.recv() => break,
        }
        if let Some(until) = worker.backoff_until {
            if Instant::now() < until {
                continue;
            }
            worker.backoff_until = None;
        }
        worker.tick().await;
    }
}

struct Worker {
    deps: AnalyticsSyncDeps,
    client: reqwest::Client,
    runtime_instance_id: Uuid,
    /// Days the server rejected as invalid, with their retry deadline.
    rejected_days: HashMap<(Uuid, NaiveDate), Instant>,
    backoff_until: Option<Instant>,
    tick_seconds: u64,
}

impl Worker {
    async fn tick(&mut self) {
        let Ok(Some(creds)) = load_credentials() else {
            self.tick_seconds = IDLE_TICK_SECONDS;
            return; // Not signed in; nothing to sync and no way to say so.
        };
        let entitled = {
            let gate = self.deps.feature_gate.read().unwrap();
            gate.allows("cloud_sync") && gate.allows("usage_analytics")
        };
        // Cloud analytics is part of the paid plan: with no recorded choice,
        // an entitled account defaults ON and the receipt is written here
        // (the server requires one at registration). `grith analytics
        // disable` records the opt-out; an explicit enabled=false is always
        // honoured. A consent-version bump deliberately does NOT re-default —
        // it means the scope of uploaded data changed, so uploads stop until
        // the user re-accepts via `grith analytics enable`.
        let consent = match load_consent() {
            Some(consent) => Some(consent),
            None if self.deps.audit_sync_enabled && entitled => {
                let consent = AnalyticsConsent {
                    consent_version: CONSENT_VERSION,
                    accepted_at: Utc::now(),
                    enabled: true,
                };
                match save_consent(&consent) {
                    Ok(()) => {
                        tracing::info!(
                            "cloud analytics sync enabled with your plan; \
                             turn it off with `grith analytics disable`"
                        );
                        Some(consent)
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "could not record analytics consent");
                        None
                    }
                }
            }
            None => None,
        };
        let consent_ok = consent
            .as_ref()
            .is_some_and(AnalyticsConsent::authorises_upload);
        let enabled = self.deps.audit_sync_enabled && entitled && consent_ok;

        if !enabled {
            self.tick_seconds = IDLE_TICK_SECONDS;
            self.send_disabled_heartbeat_once(&creds).await;
            return;
        }

        let mut device = match load_device() {
            Some(device) if !device.revoked => device,
            Some(_) => {
                // Revoked: stay quiet until the user re-enables (the enable
                // command clears the device file so registration reruns).
                self.tick_seconds = IDLE_TICK_SECONDS;
                return;
            }
            None => match self.register(&creds, consent.as_ref().unwrap()).await {
                Some(device) => device,
                None => return,
            },
        };
        if device.disabled_heartbeat_sent {
            device.disabled_heartbeat_sent = false;
            let _ = save_device(&device);
        }

        if !self.reconcile_epoch(&creds, &mut device).await {
            return;
        }
        if !self.heartbeat(&creds, &device).await {
            return;
        }
        self.upload_once(&creds, &device).await;
    }

    /// One-shot courtesy signal: when uploads stop but a registered device
    /// exists, tell the server sync is off so the team dashboard shows
    /// "sync disabled" instead of ageing into "offline".
    async fn send_disabled_heartbeat_once(&mut self, creds: &Credentials) {
        let Some(mut device) = load_device() else {
            return;
        };
        if device.disabled_heartbeat_sent || device.revoked {
            return;
        }
        let Some(request) = self.heartbeat_request(&device, false) else {
            return;
        };
        match post_json::<_, HeartbeatResponse>(
            &self.client,
            "/api/analytics/v2/heartbeat",
            &creds.api_key,
            Some(&device.device_secret),
            &request,
        )
        .await
        {
            Ok(_) => {
                device.disabled_heartbeat_sent = true;
                if let Err(error) = save_device(&device) {
                    tracing::warn!(error = %error, "could not persist analytics device state");
                }
                tracing::info!("reported analytics sync disabled to the server");
            }
            Err(error) => {
                self.handle_device_error(&error, &mut device);
                tracing::debug!(error = %error, "sync-disabled heartbeat failed");
            }
        }
    }

    async fn register(
        &mut self,
        creds: &Credentials,
        consent: &AnalyticsConsent,
    ) -> Option<AnalyticsDevice> {
        let identity = {
            let mut storage = self.deps.audit_storage.lock().ok()?;
            let identity = match storage.analytics_projection_identity() {
                Ok(identity) => identity,
                Err(error) => {
                    tracing::warn!(error = %error, "analytics registration: no projection identity");
                    return None;
                }
            };
            // Cloud coverage is prospective: it never precedes consent (the
            // server enforces this at registration). A projection older than
            // the consent receipt — the common case on an existing install —
            // rotates to a fresh epoch starting now. The closed epoch's
            // history stays fully queryable in the LOCAL dashboards; it is
            // simply never uploaded.
            if identity.coverage_start < consent.accepted_at {
                match storage.analytics_rotate_epoch_to_now(SourceResetReason::ManualReset) {
                    Ok(rotated) => {
                        tracing::info!(
                            closed_epoch = %identity.source_epoch,
                            new_epoch = %rotated.source_epoch,
                            "cloud analytics coverage starts at consent; \
                             earlier local history stays on this machine"
                        );
                        rotated
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "analytics registration: epoch rotation failed");
                        return None;
                    }
                }
            } else {
                identity
            }
        };
        let request = RegistrationRequest {
            protocol_version: grith_analytics::limits::PROTOCOL_VERSION,
            schema_version: grith_analytics::limits::SCHEMA_VERSION,
            source_epoch: identity.source_epoch,
            runtime_instance_id: self.runtime_instance_id,
            device_display_name: device_display_name(),
            client_version: env!("CARGO_PKG_VERSION").into(),
            materializer_version: grith_analytics::limits::MATERIALIZER_VERSION,
            completeness: self.deps.completeness,
            coverage_start: identity.coverage_start,
            baseline_chain_sequence: identity.baseline_chain_sequence,
            baseline_chain_hash: identity.baseline_chain_hash.clone(),
            audit_database_generation: identity.audit_database_generation,
            consent: ConsentReceipt {
                consent_version: consent.consent_version,
                accepted_at: consent.accepted_at,
            },
            signing_public_key: None,
        };
        match post_json::<_, RegistrationResponse>(
            &self.client,
            "/api/analytics/v2/devices/register",
            &creds.api_key,
            None,
            &request,
        )
        .await
        {
            Ok(response) => {
                let device = AnalyticsDevice {
                    device_id: response.device_id,
                    device_secret: response.device_secret,
                    credential_version: response.credential_version,
                    team_id: response.team_id,
                    actor_user_id: response.actor_user_id,
                    source_epoch: response.source_epoch,
                    registered_at: Utc::now(),
                    destination_policy: response.destination_policy,
                    disabled_heartbeat_sent: false,
                    revoked: false,
                };
                if let Err(error) = save_device(&device) {
                    // Without the persisted secret the identity is lost on
                    // restart and the device cap fills with orphans — do not
                    // proceed on a secret we could not store.
                    tracing::error!(error = %error, "could not persist analytics device identity");
                    return None;
                }
                tracing::info!(
                    device_id = %device.device_id,
                    "registered this machine for cloud analytics"
                );
                Some(device)
            }
            Err(error) => {
                match error.code() {
                    "device_limit_exceeded" => {
                        tracing::warn!(
                            "cloud analytics device limit reached for this team; \
                             revoke an unused device from the team dashboard"
                        );
                        self.backoff_until = Some(Instant::now() + HARD_FAILURE_BACKOFF);
                    }
                    "authentication_required" | "entitlement_required" => {
                        self.backoff_until = Some(Instant::now() + HARD_FAILURE_BACKOFF);
                        tracing::warn!(error = %error, "cloud analytics registration refused");
                    }
                    _ => {
                        tracing::warn!(error = %error, "cloud analytics registration failed; retrying each tick");
                    }
                }
                None
            }
        }
    }

    /// Bring the server's active epoch in line with the local projection.
    /// Returns false when uploading must not continue this tick.
    async fn reconcile_epoch(&mut self, creds: &Credentials, device: &mut AnalyticsDevice) -> bool {
        let (identity, closed_end, closed_reason, request_seq) = {
            let mut storage = match self.deps.audit_storage.lock() {
                Ok(storage) => storage,
                Err(_) => return false,
            };
            let identity = match storage.analytics_projection_identity() {
                Ok(identity) => identity,
                Err(error) => {
                    tracing::warn!(error = %error, "analytics upload: no projection identity");
                    return false;
                }
            };
            if identity.source_epoch == device.source_epoch {
                return true;
            }
            // The local projection rotated to a new epoch. Find the closed
            // predecessor's coverage end and the new epoch's reset reason.
            let epochs = match storage.analytics_source_epochs() {
                Ok(epochs) => epochs,
                Err(error) => {
                    tracing::warn!(error = %error, "analytics upload: cannot read source epochs");
                    return false;
                }
            };
            let closed_end = epochs
                .iter()
                .find(|epoch| epoch.source_epoch == device.source_epoch)
                .and_then(|epoch| epoch.coverage_end)
                .unwrap_or(identity.coverage_start - chrono::Duration::microseconds(1));
            let reason = storage.analytics_reset_reason_for(identity.source_epoch);
            let seq = match storage.analytics_allocate_request_seq() {
                Ok(seq) => seq,
                Err(error) => {
                    tracing::warn!(error = %error, "analytics upload: sequence allocation failed");
                    return false;
                }
            };
            (identity, closed_end, reason, seq)
        };
        let request = SourceResetRequest {
            context: RequestContext::v2(
                device.device_id,
                device.source_epoch,
                request_seq,
                self.runtime_instance_id,
                Utc::now(),
                env!("CARGO_PKG_VERSION"),
                self.deps.completeness,
            ),
            closing_source_epoch: device.source_epoch,
            closing_coverage_end: closed_end,
            new_source_epoch: identity.source_epoch,
            new_coverage_start: identity.coverage_start,
            new_baseline_chain_sequence: identity.baseline_chain_sequence,
            new_baseline_chain_hash: identity.baseline_chain_hash.clone(),
            new_audit_database_generation: identity.audit_database_generation,
            reason: map_reset_reason(closed_reason.as_deref()),
            lost_event_count: None,
        };
        match post_json::<_, SourceResetResponse>(
            &self.client,
            "/api/analytics/v2/source/reset",
            &creds.api_key,
            Some(&device.device_secret),
            &request,
        )
        .await
        {
            Ok(response) => {
                device.source_epoch = response.active_source_epoch;
                let _ = save_device(device);
                tracing::info!(
                    epoch = %response.active_source_epoch,
                    "cloud analytics source epoch rotated"
                );
                true
            }
            Err(error) if error.code() == "source_epoch_not_active" => {
                // A previous reset already landed (or another runtime raced
                // us). Adopt the server's view when it matches local reality.
                match fetch_state(&self.client, creds, device).await {
                    Ok(state) if state.active_source_epoch == identity.source_epoch => {
                        device.source_epoch = state.active_source_epoch;
                        let _ = save_device(device);
                        true
                    }
                    Ok(state) => {
                        tracing::warn!(
                            server_epoch = %state.active_source_epoch,
                            local_epoch = %identity.source_epoch,
                            "cloud analytics epoch mismatch needs a fresh handshake"
                        );
                        false
                    }
                    Err(error) => {
                        tracing::debug!(error = %error, "analytics state fetch failed");
                        false
                    }
                }
            }
            Err(error) => {
                self.handle_device_error(&error, device);
                tracing::warn!(error = %error, "analytics source reset failed; will retry");
                false
            }
        }
    }

    fn heartbeat_request(
        &self,
        device: &AnalyticsDevice,
        sync_enabled: bool,
    ) -> Option<HeartbeatRequest> {
        let storage = self.deps.audit_storage.lock().ok()?;
        let stats = match storage.analytics_sync_stats() {
            Ok(stats) => stats,
            Err(error) => {
                tracing::debug!(error = %error, "analytics sync stats unavailable");
                return None;
            }
        };
        let request_seq = storage.analytics_peek_request_seq().unwrap_or(1);
        Some(HeartbeatRequest {
            context: RequestContext::v2(
                device.device_id,
                device.source_epoch,
                request_seq,
                self.runtime_instance_id,
                Utc::now(),
                env!("CARGO_PKG_VERSION"),
                self.deps.completeness,
            ),
            sync_enabled,
            latest_local_event_at: stats.latest_local_event_at,
            materialized_through_sequence: stats.materialized_through_sequence,
            materialized_through_hash: stats.materialized_through_hash,
            dirty_day_count: stats.pending_upload_days.min(u64::from(u16::MAX)) as u16,
            oldest_dirty_day: stats.oldest_pending_day,
            unacknowledged_security_events: stats.unacked_security_events.min(u64::from(u32::MAX))
                as u32,
            unacknowledged_archive_days: 0,
            dropped_event_count: stats.gap_count,
            audit_database_generation: stats.audit_database_generation,
        })
    }

    /// Returns false when the tick should stop (lease conflict, auth failure).
    async fn heartbeat(&mut self, creds: &Credentials, device: &AnalyticsDevice) -> bool {
        let Some(request) = self.heartbeat_request(device, true) else {
            return false;
        };
        match post_json::<_, HeartbeatResponse>(
            &self.client,
            "/api/analytics/v2/heartbeat",
            &creds.api_key,
            Some(&device.device_secret),
            &request,
        )
        .await
        {
            Ok(response) => {
                self.tick_seconds = response.next_heartbeat_seconds.clamp(5, 300);
                if let Some(policy) = response.destination_policy {
                    let mut updated = device.clone();
                    updated.destination_policy = policy;
                    let _ = save_device(&updated);
                }
                true
            }
            Err(error) => {
                let mut updated = device.clone();
                self.handle_device_error(&error, &mut updated);
                if error.code() == "runtime_instance_conflict" {
                    // Another daemon holds the 90-second lease; let it expire.
                    self.backoff_until = Some(Instant::now() + Duration::from_secs(120));
                    tracing::warn!(
                        "another grith daemon is uploading analytics for this device; standing by"
                    );
                } else {
                    tracing::debug!(error = %error, "analytics heartbeat failed");
                }
                false
            }
        }
    }

    /// Send at most one snapshot request per tick: the outbox entry if one is
    /// in flight, else a freshly prepared one.
    async fn upload_once(&mut self, creds: &Credentials, device: &AnalyticsDevice) {
        let prepared = {
            let mut storage = match self.deps.audit_storage.lock() {
                Ok(storage) => storage,
                Err(_) => return,
            };
            match storage.analytics_outbox_oldest() {
                Ok(Some(entry)) if entry.source_epoch != device.source_epoch => {
                    // Enqueued under an epoch that has since closed; the reset
                    // handshake already declared that coverage gap.
                    let _ = storage.analytics_outbox_delete(entry.request_seq);
                    return;
                }
                Ok(Some(entry)) => Some(PreparedUpload {
                    request_seq: entry.request_seq,
                    source_epoch: entry.source_epoch,
                    day: entry.day,
                    body: entry.body,
                }),
                Ok(None) => {
                    let now = Instant::now();
                    self.rejected_days.retain(|_, until| *until > now);
                    let rejected = &self.rejected_days;
                    let epoch = device.source_epoch;
                    match prepare_next_upload(
                        &mut storage,
                        device,
                        self.runtime_instance_id,
                        self.deps.completeness,
                        |day| rejected.contains_key(&(epoch, day)),
                    ) {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            tracing::warn!(error = %error, "analytics snapshot assembly failed");
                            None
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(error = %error, "analytics outbox read failed");
                    None
                }
            }
        };
        let Some(prepared) = prepared else {
            return;
        };
        match post_raw::<SnapshotResponse>(
            &self.client,
            "/api/analytics/v2/snapshots",
            &creds.api_key,
            Some(&device.device_secret),
            prepared.body.clone(),
        )
        .await
        {
            Ok(response) => {
                let mut storage = match self.deps.audit_storage.lock() {
                    Ok(storage) => storage,
                    Err(_) => return,
                };
                if let Err(error) =
                    apply_snapshot_response(&mut storage, prepared.source_epoch, &response)
                {
                    tracing::warn!(error = %error, "analytics acknowledgement bookkeeping failed");
                } else {
                    tracing::debug!(
                        request_seq = prepared.request_seq,
                        days = response.accepted_days.len(),
                        security_events = response.security_event_acknowledgements.len(),
                        "analytics snapshot accepted"
                    );
                }
            }
            Err(error) => {
                self.handle_upload_failure(creds, device, &prepared, error)
                    .await;
            }
        }
    }

    async fn handle_upload_failure(
        &mut self,
        creds: &Credentials,
        device: &AnalyticsDevice,
        prepared: &PreparedUpload,
        error: UploadError,
    ) {
        match error.code() {
            // The server already holds this or a newer state; resynchronise
            // from /state and retire the entry. A stale day is marked dirty
            // locally so its next rebuild republishes above the server's
            // revision.
            "stale_day_revision" | "request_seq_digest_conflict" => {
                tracing::warn!(error = %error, "analytics snapshot superseded; reconciling");
                let state = fetch_state(&self.client, creds, device).await;
                let mut storage = match self.deps.audit_storage.lock() {
                    Ok(storage) => storage,
                    Err(_) => return,
                };
                if let Ok(state) = state {
                    let _ = reconcile_state(&mut storage, prepared.source_epoch, &state);
                }
                let _ = storage.analytics_outbox_delete(prepared.request_seq);
            }
            // The epoch closed between assembly and send; the next tick's
            // reset handshake supersedes this entry.
            "source_epoch_not_active" => {
                if let Ok(mut storage) = self.deps.audit_storage.lock() {
                    let _ = storage.analytics_outbox_delete(prepared.request_seq);
                }
            }
            // Permanent rejection of this exact body: drop it and quarantine
            // the day so re-assembly does not spin.
            "invalid_request" | "payload_violation" | "request_too_large" => {
                tracing::error!(
                    error = %error,
                    day = ?prepared.day,
                    "server rejected an analytics snapshot as invalid"
                );
                if let Some(day) = prepared.day {
                    self.rejected_days.insert(
                        (prepared.source_epoch, day),
                        Instant::now() + REJECTED_DAY_BACKOFF,
                    );
                }
                if let Ok(mut storage) = self.deps.audit_storage.lock() {
                    let _ = storage.analytics_outbox_delete(prepared.request_seq);
                }
            }
            "rate_limited" => {
                tracing::debug!("analytics upload rate limited; retrying next tick");
            }
            _ => {
                let mut updated = device.clone();
                self.handle_device_error(&error, &mut updated);
                tracing::warn!(error = %error, "analytics snapshot upload failed; will retry");
            }
        }
    }

    /// Mutate the persisted device on fatal device-scoped verdicts.
    fn handle_device_error(&mut self, error: &UploadError, device: &mut AnalyticsDevice) {
        match error.code() {
            "device_revoked" => {
                device.revoked = true;
                let _ = save_device(device);
                self.backoff_until = Some(Instant::now() + HARD_FAILURE_BACKOFF);
                tracing::warn!(
                    "this device's cloud analytics access was revoked; \
                     run `grith analytics enable` to register again"
                );
            }
            "authentication_required" | "device_binding_mismatch" | "entitlement_required" => {
                self.backoff_until = Some(Instant::now() + HARD_FAILURE_BACKOFF);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grith_analytics::contract::{AcceptedDay, SecurityEventAcknowledgement};
    use grith_audit::{
        AuditAnalyticsMetadata, AuditConfigVersion, AuditRecord, FilterResultSummary,
        ProxyActionSummary,
    };

    fn seeded_storage() -> AuditStorage {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let mut record = AuditRecord::new(
            Uuid::new_v4(),
            "supervisor".into(),
            "FileWrite".into(),
            &serde_json::json!({"path": "/never/uploaded"}),
            4.25,
            ProxyActionSummary::Queue,
            vec![FilterResultSummary {
                filter_name: "secret_scan".into(),
                matched: true,
                score: 2.0,
                rule_id: "rule".into(),
                severity: "warning".into(),
                message: "redacted".into(),
            }],
            1.0,
            None,
        )
        .with_project_name(Some("project".into()))
        .with_analytics_metadata(AuditAnalyticsMetadata {
            metadata_version: 1,
            completeness: grith_analytics::contract::CompletenessTier::Spawns,
            record_class: grith_analytics::contract::RecordClass::Decision,
            category: grith_analytics::contract::Category::FileMutation,
            config: AuditConfigVersion {
                profile_id: "default".into(),
                profile_version: "1".into(),
                config_hash: "a".repeat(64),
                policy_version: "1".into(),
                auto_allow_threshold_micros: 3_000_000,
                auto_deny_threshold_micros: 8_000_000,
                queue_policy: "review".into(),
                team_default_config_version: "1".into(),
            },
            filter_set_version: Some(1),
            llm_pricing: None,
            destination: None,
            security: None,
        });
        record.timestamp = Utc::now();
        storage.insert_record(&record).unwrap();
        storage.catch_up_analytics().unwrap();
        storage
    }

    fn test_device(source_epoch: Uuid) -> AnalyticsDevice {
        AnalyticsDevice {
            device_id: Uuid::new_v4(),
            device_secret: "secret".into(),
            credential_version: 1,
            team_id: Uuid::new_v4(),
            actor_user_id: "user".into(),
            source_epoch,
            registered_at: Utc::now(),
            destination_policy: DestinationPolicy {
                mode: grith_analytics::contract::DestinationPolicyMode::TeamHmac,
                key_version: 1,
                team_hmac_key_base64: "a2V5".into(),
                effective_at: Utc::now(),
            },
            disabled_heartbeat_sent: false,
            revoked: false,
        }
    }

    #[test]
    fn prepared_upload_is_wire_valid_and_acknowledgement_clears_the_queue() {
        let mut storage = seeded_storage();
        let epoch = storage
            .analytics_projection_identity()
            .unwrap()
            .source_epoch;
        let device = test_device(epoch);
        let runtime = Uuid::new_v4();

        let prepared = prepare_next_upload(
            &mut storage,
            &device,
            runtime,
            CompletenessTier::Spawns,
            |_| false,
        )
        .unwrap()
        .expect("one pending day");
        assert_eq!(prepared.request_seq, 1);
        assert_eq!(prepared.source_epoch, epoch);
        assert!(prepared.day.is_some());

        // The body round-trips through the frozen wire contract and never
        // carries operands.
        let request: SnapshotRequest = serde_json::from_str(&prepared.body).unwrap();
        assert_eq!(request.context.request_seq, 1);
        assert_eq!(request.context.device_id, device.device_id);
        assert_eq!(request.context.source_epoch, epoch);
        assert_eq!(request.day_snapshots.len(), 1);
        assert_eq!(request.security_events.len(), 1);
        assert_eq!(request.config_versions.len(), 1);
        assert!(!prepared.body.contains("/never/uploaded"));

        // The outbox holds the exact bytes for retry.
        let entry = storage.analytics_outbox_oldest().unwrap().unwrap();
        assert_eq!(entry.body, prepared.body);

        // A server acknowledgement retires the day, the events and the entry.
        let snapshot = &request.day_snapshots[0];
        let response = SnapshotResponse {
            device_id: device.device_id,
            source_epoch: epoch,
            accepted_request_seq: prepared.request_seq,
            request_digest_sha256: "d".repeat(64),
            accepted_days: vec![AcceptedDay {
                day: snapshot.day,
                day_revision: snapshot.day_revision,
                read_model_generation: snapshot.read_model_generation,
                row_checksum_sha256: snapshot.row_checksum_sha256.clone(),
                accepted_at: Utc::now(),
            }],
            security_event_acknowledgements: request
                .security_events
                .iter()
                .map(|event| SecurityEventAcknowledgement {
                    event_id: event.event_id,
                    event_revision: event.event_revision,
                    accepted_at: Utc::now(),
                })
                .collect(),
            server_time: Utc::now(),
        };
        apply_snapshot_response(&mut storage, epoch, &response).unwrap();

        assert!(storage.analytics_outbox_oldest().unwrap().is_none());
        assert!(storage
            .analytics_upload_pending_days(epoch, 10)
            .unwrap()
            .is_empty());
        assert!(storage
            .analytics_unacked_security_events(epoch, 500)
            .unwrap()
            .is_empty());
        assert_eq!(
            prepare_next_upload(
                &mut storage,
                &device,
                runtime,
                CompletenessTier::Spawns,
                |_| false,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn skip_day_filter_falls_back_to_event_only_uploads() {
        let mut storage = seeded_storage();
        let epoch = storage
            .analytics_projection_identity()
            .unwrap()
            .source_epoch;
        let device = test_device(epoch);
        let prepared = prepare_next_upload(
            &mut storage,
            &device,
            Uuid::new_v4(),
            CompletenessTier::Spawns,
            |_| true, // every day quarantined
        )
        .unwrap()
        .expect("event-only upload");
        assert_eq!(prepared.day, None);
        let request: SnapshotRequest = serde_json::from_str(&prepared.body).unwrap();
        assert!(request.day_snapshots.is_empty());
        assert_eq!(request.security_events.len(), 1);
    }

    #[test]
    fn consent_authorisation_requires_enabled_and_current_version() {
        let consent = AnalyticsConsent {
            consent_version: CONSENT_VERSION,
            accepted_at: Utc::now(),
            enabled: true,
        };
        assert!(consent.authorises_upload());
        assert!(!AnalyticsConsent {
            enabled: false,
            ..consent.clone()
        }
        .authorises_upload());
        assert!(!AnalyticsConsent {
            consent_version: CONSENT_VERSION - 1,
            ..consent
        }
        .authorises_upload());
    }

    #[test]
    fn reset_reason_mapping_defaults_to_projection_lost() {
        assert_eq!(
            map_reset_reason(Some("audit_history_lost")),
            SourceResetReason::AuditHistoryLost
        );
        assert_eq!(
            map_reset_reason(Some("audit_database_generation_changed")),
            SourceResetReason::AuditDatabaseGenerationChanged
        );
        assert_eq!(
            map_reset_reason(None),
            SourceResetReason::LocalProjectionLost
        );
        assert_eq!(
            map_reset_reason(Some("unknown")),
            SourceResetReason::LocalProjectionLost
        );
    }
}
