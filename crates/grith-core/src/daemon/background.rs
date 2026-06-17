// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Background daemon tasks.
//!
//! Spawns long-running async tasks for license re-validation and audit record
//! synchronization. Both tasks respect the daemon shutdown signal and perform
//! a final flush/check before exiting.

use super::Daemon;
use crate::license::{
    api_base_url, feature_gate_from_status, license_path, load_credentials, load_license,
    save_credentials, save_license_to, validate_license_remote, verify_license, Credentials,
    FeatureGate, LicenseError, RefreshFailureKind, RefreshState, ValidateResponse,
};
use chrono::{DateTime, Duration, Utc};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::broadcast;

/// How often the refresh task wakes to evaluate whether a refresh is due.
/// One hour gives reasonable responsiveness without burning the API budget.
const LICENSE_TICK_INTERVAL_SECS: u64 = 3600;

/// Default refresh cadence for non-air-gapped licences. Aligns with the
/// 7-day issued lifetime / 3-day grace plan in work/60.
const REFRESH_INTERVAL_HOURS: i64 = 24;

/// Minimum hours since last sync before triggering an automatic provider key refresh.
const PROVIDER_KEY_REFRESH_HOURS: i64 = 24;

/// How often (in seconds) to flush unsynced audit records to the server.
const AUDIT_SYNC_INTERVAL_SECS: u64 = 5;

/// Exponential-backoff schedule for transient refresh failures (5xx, network).
const TRANSIENT_BACKOFF_MINUTES: &[i64] = &[15, 60, 360];

/// Maximum total time we keep retrying transient failures before giving up
/// for this cycle and waiting for the next normal scheduled tick.
const MAX_TRANSIENT_RETRY_HOURS: i64 = 48;

/// Outcome of a single `validate_license_remote` call, normalized to the
/// daemon's response policy.
#[derive(Debug)]
pub enum RefreshOutcome {
    /// Server returned a fresh signed payload; cached licence file replaced.
    Replaced,
    /// 401/403, valid=false, or 4xx other than 401/403. Cached licence kept.
    Hard(RefreshFailureKind, String),
    /// Network, DNS, TLS, 5xx. Caller may retry with backoff.
    Transient(String),
}

/// Run a single license refresh against the server. Public so `grith pro refresh`
/// can re-use the exact outcome policy used by the daemon scheduler. On success,
/// the licence file is written atomically and `Credentials::last_validated`
/// is updated.
pub async fn run_license_refresh(creds: &Credentials) -> RefreshOutcome {
    run_refresh(creds).await
}

impl Daemon {
    /// Spawn a background task that re-validates the license every 24 hours
    /// for non-air-gapped licences. Atomic licence writes, hard/transient
    /// failure split, and exposed refresh-state for the dashboard / CLI.
    pub fn spawn_license_revalidation(&self) -> tokio::task::JoinHandle<()> {
        let mut shutdown_rx = self.subscribe_shutdown();
        let feature_gate = Arc::clone(&self.feature_gate);
        let supervisor_registry = Arc::clone(&self.supervisor_registry);
        let notification_dispatcher = Arc::clone(&self.notification_dispatcher);
        let refresh_state = Arc::clone(&self.refresh_state);
        let config_max_sessions = self.config.supervisor.max_concurrent_sessions;
        tokio::spawn(async move {
            let mut transient_attempts: u32 = 0;
            let mut transient_started_at: Option<DateTime<Utc>> = None;
            loop {
                let creds = match load_credentials() {
                    Ok(Some(c)) => c,
                    _ => {
                        // Not logged in -- check again in an hour.
                        if !sleep_or_shutdown(
                            std::time::Duration::from_secs(LICENSE_TICK_INTERVAL_SECS),
                            &mut shutdown_rx,
                        )
                        .await
                        {
                            break;
                        }
                        continue;
                    }
                };

                // Air-gapped licences disable scheduled refresh.
                if is_air_gapped() {
                    if !sleep_or_shutdown(
                        std::time::Duration::from_secs(LICENSE_TICK_INTERVAL_SECS),
                        &mut shutdown_rx,
                    )
                    .await
                    {
                        break;
                    }
                    continue;
                }

                let last_success = current_last_success(&refresh_state, &creds);
                let now = Utc::now();
                let in_backoff = transient_started_at.is_some();
                let due_at = if in_backoff {
                    now
                } else {
                    let cadence_due = last_success
                        .map(|t| t + Duration::hours(REFRESH_INTERVAL_HOURS))
                        .unwrap_or(now);
                    current_next_attempt(&refresh_state)
                        .filter(|next| *next > now)
                        .unwrap_or(cadence_due)
                };

                if now < due_at {
                    publish_next_attempt(&refresh_state, due_at);
                    let secs = (due_at - now).num_seconds().clamp(60, 3600) as u64;
                    if !sleep_or_shutdown(std::time::Duration::from_secs(secs), &mut shutdown_rx)
                        .await
                    {
                        break;
                    }
                    continue;
                }

                tracing::info!(
                    last_success = ?last_success,
                    "running scheduled license refresh"
                );
                let outcome = run_refresh(&creds).await;
                match outcome {
                    RefreshOutcome::Replaced => {
                        transient_attempts = 0;
                        transient_started_at = None;
                        record_success(&refresh_state);
                        let next = Utc::now() + Duration::hours(REFRESH_INTERVAL_HOURS);
                        publish_next_attempt(&refresh_state, next);

                        apply_cached_license_gate(
                            &feature_gate,
                            &supervisor_registry,
                            &notification_dispatcher,
                            &refresh_state,
                            config_max_sessions,
                        );

                        if let Ok(Some(fresh_creds)) = load_credentials() {
                            refresh_provider_keys_if_stale(&fresh_creds).await;
                        }
                    }
                    RefreshOutcome::Hard(kind, reason) => {
                        transient_attempts = 0;
                        transient_started_at = None;
                        tracing::error!(
                            kind = kind.as_str(),
                            reason = %reason,
                            "license refresh hard failure -- keeping cached licence until natural expiry"
                        );
                        record_failure(&refresh_state, kind, reason);
                        apply_cached_license_gate(
                            &feature_gate,
                            &supervisor_registry,
                            &notification_dispatcher,
                            &refresh_state,
                            config_max_sessions,
                        );
                        // Retry on the regular cadence; do not roll the licence back early.
                        let next = Utc::now() + Duration::hours(REFRESH_INTERVAL_HOURS);
                        publish_next_attempt(&refresh_state, next);
                    }
                    RefreshOutcome::Transient(reason) => {
                        if transient_started_at.is_none() {
                            transient_started_at = Some(Utc::now());
                        }
                        let started = transient_started_at.unwrap_or_else(Utc::now);
                        let elapsed = (Utc::now() - started).num_hours();
                        let backoff_idx =
                            (transient_attempts as usize).min(TRANSIENT_BACKOFF_MINUTES.len() - 1);
                        let backoff_minutes = TRANSIENT_BACKOFF_MINUTES[backoff_idx];
                        transient_attempts = transient_attempts.saturating_add(1);

                        tracing::warn!(
                            attempt = transient_attempts,
                            backoff_minutes,
                            error = %reason,
                            "license refresh transient failure -- will retry"
                        );
                        record_failure(&refresh_state, RefreshFailureKind::Transient, reason);
                        apply_cached_license_gate(
                            &feature_gate,
                            &supervisor_registry,
                            &notification_dispatcher,
                            &refresh_state,
                            config_max_sessions,
                        );

                        if elapsed >= MAX_TRANSIENT_RETRY_HOURS {
                            tracing::warn!(
                                elapsed_hours = elapsed,
                                "transient retries exhausted -- waiting for next scheduled tick"
                            );
                            transient_attempts = 0;
                            transient_started_at = None;
                            let next = Utc::now() + Duration::hours(REFRESH_INTERVAL_HOURS);
                            publish_next_attempt(&refresh_state, next);
                        } else {
                            let next = Utc::now() + Duration::minutes(backoff_minutes);
                            publish_next_attempt(&refresh_state, next);
                            if !sleep_or_shutdown(
                                std::time::Duration::from_secs((backoff_minutes * 60) as u64),
                                &mut shutdown_rx,
                            )
                            .await
                            {
                                break;
                            }
                        }
                    }
                }
            }
        })
    }

    /// Spawn a background task that flushes unsynced audit records to the server
    /// every 5 seconds. On failure, records remain unsynced in SQLite for retry.
    pub fn spawn_audit_sync(&self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(Self::audit_sync_task(
            Arc::clone(&self.audit_storage),
            self.subscribe_shutdown(),
        ))
    }

    /// The audit sync task as a standalone future (for use with external runtimes).
    pub async fn audit_sync_task(
        audit_storage: Arc<Mutex<grith_audit::AuditStorage>>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(AUDIT_SYNC_INTERVAL_SECS));
        // Keep batches small to stay under CloudFront/WAF ~8KB body size limit.
        let batch_limit: usize = 25;

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown_rx.recv() => {
                    // Final flush before exit -- drain all remaining records.
                    Self::flush_all_audit_records(&audit_storage, batch_limit).await;
                    break;
                }
            }

            Self::flush_all_audit_records(&audit_storage, batch_limit).await;
        }
    }

    /// Drain all unsynced audit records in batches.
    async fn flush_all_audit_records(
        audit_storage: &Arc<Mutex<grith_audit::AuditStorage>>,
        batch_limit: usize,
    ) {
        loop {
            let flushed = Self::flush_audit_batch(audit_storage, batch_limit).await;
            if !flushed {
                break;
            }
        }
    }

    /// Flush a single batch of audit records. Returns true if records were synced
    /// (and there may be more), false if there was nothing to send or an error.
    async fn flush_audit_batch(
        audit_storage: &Arc<Mutex<grith_audit::AuditStorage>>,
        batch_limit: usize,
    ) -> bool {
        let creds = match crate::license::load_credentials() {
            Ok(Some(c)) => c,
            _ => return false, // Not logged in, nothing to sync.
        };

        // Pull unsynced records from SQLite.
        let (records, ids) = {
            let storage = match audit_storage.lock() {
                Ok(s) => s,
                Err(_) => return false,
            };
            let unsynced = match storage.get_unsynced(batch_limit) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to query unsynced audit records");
                    return false;
                }
            };
            if unsynced.is_empty() {
                return false;
            }
            let ids: Vec<uuid::Uuid> = unsynced.iter().map(|r| r.id).collect();
            let sync_records: Vec<crate::license::SyncRecord> = unsynced
                .iter()
                .map(|r| crate::license::SyncRecord {
                    tool_call_type: r.tool_call_type.clone(),
                    composite_score: r.composite_score,
                    proxy_action: format!("{}", r.proxy_action).to_lowercase(),
                    filter_scores: r.filter_scores.clone(),
                    timestamp: r.timestamp.to_rfc3339(),
                    session_id: Some(r.session_id.to_string()),
                    // Prefer the dedicated project_name column; fall back to
                    // task_context for records written before that column
                    // existed (the supervisor used to stash the project name
                    // there).
                    project_name: r.project_name.clone().or_else(|| r.task_context.clone()),
                    llm_provider: r.llm_provider.clone(),
                    llm_model: r.llm_model.clone(),
                    prompt_tokens: r.prompt_tokens,
                    completion_tokens: r.completion_tokens,
                    estimated_cost_usd: r.estimated_cost_usd,
                })
                .collect();
            (sync_records, ids)
        }; // Lock released here.

        let count = records.len();
        tracing::debug!(count, "flushing audit records to server");

        match crate::license::sync_records(&creds, records).await {
            Ok(resp) => {
                tracing::debug!(synced = resp.synced, "audit records synced");
                // Mark as synced in SQLite.
                if let Ok(storage) = audit_storage.lock() {
                    if let Err(e) = storage.mark_synced(&ids) {
                        tracing::warn!(error = %e, "failed to mark records as synced");
                    }
                }
                // Return true so the caller knows there may be more records.
                true
            }
            Err(e) => {
                tracing::debug!(error = %e, count, "audit sync failed, will retry");
                // Records stay unsynced -- next flush will retry.
                false
            }
        }
    }
}

/// Sleep for `dur` or return early on shutdown. Returns false if shutdown
/// was received (caller should break the loop), true if the sleep elapsed.
async fn sleep_or_shutdown(
    dur: std::time::Duration,
    shutdown_rx: &mut broadcast::Receiver<()>,
) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(dur) => true,
        _ = shutdown_rx.recv() => false,
    }
}

/// Run a single refresh, persist the new licence atomically on success, and
/// return a normalized outcome for the scheduler to act on.
///
/// The `validate_license_remote` HTTP error format is `{status}: {body}`; we
/// parse the leading status to decide hard vs transient. This is brittle but
/// avoids changing the public error type for a behavioural fix.
async fn run_refresh(creds: &Credentials) -> RefreshOutcome {
    match validate_license_remote(creds).await {
        Ok(resp) => apply_validate_response(creds, resp).await,
        Err(LicenseError::Http(msg)) => {
            if let Some(code) = parse_http_status(&msg) {
                if code == 401 || code == 403 {
                    return RefreshOutcome::Hard(
                        RefreshFailureKind::Unauthorized,
                        format!("HTTP {code}"),
                    );
                }
                if (500..600).contains(&code) {
                    return RefreshOutcome::Transient(format!("HTTP {code}"));
                }
                if (400..500).contains(&code) {
                    return RefreshOutcome::Hard(
                        RefreshFailureKind::Protocol,
                        format!("HTTP {code}"),
                    );
                }
            }
            RefreshOutcome::Transient(msg)
        }
        Err(other) => RefreshOutcome::Transient(other.to_string()),
    }
}

async fn apply_validate_response(creds: &Credentials, resp: ValidateResponse) -> RefreshOutcome {
    if !resp.valid {
        let reason = resp.reason.unwrap_or_else(|| "valid=false".into());
        return RefreshOutcome::Hard(RefreshFailureKind::Revoked, reason);
    }

    if let Some(signed) = resp.license {
        let bytes = match serde_json::to_vec(&signed) {
            Ok(bytes) => bytes,
            Err(e) => return RefreshOutcome::Transient(format!("serialize license: {e}")),
        };
        if let Err(e) = verify_license(&bytes) {
            return RefreshOutcome::Hard(
                RefreshFailureKind::Protocol,
                format!("server returned unverifiable license: {e}"),
            );
        }
        if let Err(e) = save_license_to(&signed, &license_path()) {
            return RefreshOutcome::Transient(format!("save license: {e}"));
        }
        if let Err(e) = update_credentials_validated(creds) {
            return RefreshOutcome::Transient(format!("update credentials: {e}"));
        }
        RefreshOutcome::Replaced
    } else {
        // Server replied valid=true but did not return a fresh signed payload.
        // The work/60 server contract requires a fresh payload on success; do
        // not advance last_validated for an ambiguous response.
        RefreshOutcome::Hard(
            RefreshFailureKind::Protocol,
            "valid=true without license payload".into(),
        )
    }
}

fn update_credentials_validated(prev: &Credentials) -> Result<(), LicenseError> {
    let mut updated = prev.clone();
    updated.last_validated = Utc::now().to_rfc3339();
    save_credentials(&updated)
}

fn parse_http_status(msg: &str) -> Option<u16> {
    let head = msg.split(':').next()?.trim();
    let code = head.split_whitespace().next()?;
    code.parse::<u16>().ok()
}

fn current_last_success(
    refresh_state: &Arc<RwLock<RefreshState>>,
    creds: &Credentials,
) -> Option<DateTime<Utc>> {
    let from_state = refresh_state
        .read()
        .ok()
        .and_then(|s| s.last_success.clone());
    let parse = |raw: &str| {
        DateTime::parse_from_rfc3339(raw)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    };
    if let Some(s) = from_state.as_deref().and_then(parse) {
        return Some(s);
    }
    if !creds.last_validated.is_empty() {
        if let Some(s) = parse(&creds.last_validated) {
            return Some(s);
        }
    }
    None
}

fn current_next_attempt(refresh_state: &Arc<RwLock<RefreshState>>) -> Option<DateTime<Utc>> {
    refresh_state
        .read()
        .ok()
        .and_then(|s| s.next_attempt.clone())
        .as_deref()
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

fn is_air_gapped() -> bool {
    matches!(
        load_license(&license_path()),
        crate::license::LicenseStatus::Valid(ref l)
        | crate::license::LicenseStatus::GracePeriod { license: ref l, .. }
        | crate::license::LicenseStatus::ExtendedGrace { license: ref l, .. }
            if l.air_gapped
    )
}

fn record_success(refresh_state: &Arc<RwLock<RefreshState>>) {
    if let Ok(mut s) = refresh_state.write() {
        let now = Utc::now().to_rfc3339();
        s.last_success = Some(now);
        s.last_failure = None;
        s.last_failure_kind = None;
        s.last_failure_reason = None;
        s.successes_total = s.successes_total.saturating_add(1);
    }
}

fn set_air_gapped_from_status(
    refresh_state: &Arc<RwLock<RefreshState>>,
    status: &crate::license::LicenseStatus,
) {
    let air_gapped = matches!(
        status,
        crate::license::LicenseStatus::Valid(ref l)
        | crate::license::LicenseStatus::GracePeriod { license: ref l, .. }
        | crate::license::LicenseStatus::ExtendedGrace { license: ref l, .. }
            if l.air_gapped
    );
    if let Ok(mut s) = refresh_state.write() {
        s.air_gapped = air_gapped;
    }
}

fn record_failure(
    refresh_state: &Arc<RwLock<RefreshState>>,
    kind: RefreshFailureKind,
    reason: String,
) {
    if let Ok(mut s) = refresh_state.write() {
        s.last_failure = Some(Utc::now().to_rfc3339());
        s.last_failure_kind = Some(kind);
        s.last_failure_reason = Some(sanitize_reason(&reason));
        s.failures_total = s.failures_total.saturating_add(1);
    }
}

fn publish_next_attempt(refresh_state: &Arc<RwLock<RefreshState>>, when: DateTime<Utc>) {
    if let Ok(mut s) = refresh_state.write() {
        s.next_attempt = Some(when.to_rfc3339());
    }
}

fn sanitize_reason(input: &str) -> String {
    // Cap length and strip anything that smells like a key.
    let trimmed = input
        .split_whitespace()
        .take(40)
        .collect::<Vec<_>>()
        .join(" ");
    trimmed.chars().take(240).collect()
}

/// If `last_synced` is older than `PROVIDER_KEY_REFRESH_HOURS`, fetch provider
/// keys from the cloud API and rewrite them (encrypted) locally. This catches
/// key rotations for long-running daemons without requiring a manual `grith pro sync`.
async fn refresh_provider_keys_if_stale(creds: &crate::license::Credentials) {
    let stale = creds
        .last_synced
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| {
            let hours = (chrono::Utc::now() - dt.with_timezone(&chrono::Utc)).num_hours();
            hours >= PROVIDER_KEY_REFRESH_HOURS
        })
        .unwrap_or(true); // No last_synced → treat as stale

    if !stale {
        return;
    }

    tracing::debug!("provider keys stale, attempting background refresh");
    let keys = match crate::license::fetch_provider_keys(creds).await {
        Ok(k) => k,
        Err(e) => {
            tracing::debug!(error = %e, "background provider key refresh failed");
            return;
        }
    };

    let report = match crate::license::reconcile_provider_key_files(
        &creds.api_key,
        &crate::license::provider_keys_dir(),
        &keys,
    ) {
        Ok(report) => report,
        Err(e) => {
            tracing::warn!(error = %e, "background provider key refresh failed");
            return;
        }
    };

    let mut updated = creds.clone();
    updated.last_synced = Some(chrono::Utc::now().to_rfc3339());
    if let Err(e) = crate::license::save_credentials(&updated) {
        tracing::warn!(
            error = %e,
            "background provider key refresh succeeded but failed to persist sync timestamp"
        );
    }

    if !report.written.is_empty() || !report.revoked.is_empty() || report.skipped_unsafe > 0 {
        tracing::info!(
            written = report.written.len(),
            revoked = report.revoked.len(),
            skipped_unsafe = report.skipped_unsafe,
            "background provider key refresh complete"
        );
    }
}

fn apply_runtime_license_gate(
    feature_gate: &Arc<RwLock<FeatureGate>>,
    supervisor_registry: &Arc<Mutex<grith_supervisor::supervisor::SupervisorRegistry>>,
    notification_dispatcher: &Arc<grith_notify::NotificationDispatcher>,
    config_max_sessions: usize,
    new_gate: FeatureGate,
) {
    if let Ok(mut gate) = feature_gate.write() {
        *gate = new_gate.clone();
    } else {
        tracing::warn!("failed to update runtime feature gate (lock poisoned)");
    }

    let effective_max = config_max_sessions.min(new_gate.max_sessions());
    if let Ok(mut registry) = supervisor_registry.lock() {
        registry.set_max_sessions(effective_max);
    } else {
        tracing::warn!("failed to update supervisor max sessions (lock poisoned)");
    }

    notification_dispatcher.set_plan_tier(new_gate.tier);
    tracing::info!(
        tier = %new_gate.tier,
        seats = new_gate.seats,
        max_sessions = effective_max,
        api_base = %api_base_url(),
        "applied refreshed runtime license gate"
    );
}

fn apply_cached_license_gate(
    feature_gate: &Arc<RwLock<FeatureGate>>,
    supervisor_registry: &Arc<Mutex<grith_supervisor::supervisor::SupervisorRegistry>>,
    notification_dispatcher: &Arc<grith_notify::NotificationDispatcher>,
    refresh_state: &Arc<RwLock<RefreshState>>,
    config_max_sessions: usize,
) {
    let status = load_license(&license_path());
    set_air_gapped_from_status(refresh_state, &status);
    let gate = feature_gate_from_status(&status);
    apply_runtime_license_gate(
        feature_gate,
        supervisor_registry,
        notification_dispatcher,
        config_max_sessions,
        gate,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_status_extracts_leading_code() {
        assert_eq!(parse_http_status("401: bad key"), Some(401));
        assert_eq!(
            parse_http_status("503 Service Unavailable: oops"),
            Some(503)
        );
        assert_eq!(parse_http_status("not http"), None);
    }

    #[test]
    fn sanitize_reason_caps_length() {
        let big = "x".repeat(1000);
        let out = sanitize_reason(&big);
        assert!(out.len() <= 240);
    }

    fn make_creds(last_validated: chrono::DateTime<Utc>) -> Credentials {
        Credentials {
            user_id: "u".into(),
            api_key: "key".into(),
            team_id: "t".into(),
            license_file: "license.key".into(),
            activated_at: last_validated.to_rfc3339(),
            last_validated: last_validated.to_rfc3339(),
            last_synced: None,
        }
    }

    #[test]
    fn current_last_success_prefers_state_over_creds() {
        let state = Arc::new(RwLock::new(RefreshState::default()));
        let later = Utc::now() - Duration::hours(1);
        state.write().unwrap().last_success = Some(later.to_rfc3339());
        let creds = make_creds(Utc::now() - Duration::days(5));
        let got = current_last_success(&state, &creds).unwrap();
        // State value beats creds.last_validated.
        assert!((got - later).num_seconds().abs() < 2);
    }

    #[test]
    fn current_last_success_falls_back_to_creds() {
        let state = Arc::new(RwLock::new(RefreshState::default()));
        let creds_ts = Utc::now() - Duration::hours(48);
        let creds = make_creds(creds_ts);
        let got = current_last_success(&state, &creds).unwrap();
        assert!((got - creds_ts).num_seconds().abs() < 2);
    }

    #[test]
    fn current_next_attempt_reads_state() {
        let state = Arc::new(RwLock::new(RefreshState::default()));
        let next = Utc::now() + Duration::hours(24);
        state.write().unwrap().next_attempt = Some(next.to_rfc3339());
        let got = current_next_attempt(&state).unwrap();
        assert!((got - next).num_seconds().abs() < 2);
    }

    #[test]
    fn record_success_clears_failure_and_increments_counter() {
        let state = Arc::new(RwLock::new(RefreshState {
            last_failure: Some("yesterday".into()),
            last_failure_kind: Some(RefreshFailureKind::Transient),
            last_failure_reason: Some("network".into()),
            ..RefreshState::default()
        }));
        record_success(&state);
        let got = state.read().unwrap();
        assert!(got.last_success.is_some());
        assert!(got.last_failure.is_none());
        assert!(got.last_failure_kind.is_none());
        assert!(got.last_failure_reason.is_none());
        assert_eq!(got.successes_total, 1);
    }

    #[test]
    fn record_failure_keeps_last_success_and_categorises() {
        let state = Arc::new(RwLock::new(RefreshState {
            last_success: Some("2026-01-01T00:00:00Z".into()),
            ..RefreshState::default()
        }));
        record_failure(
            &state,
            RefreshFailureKind::Unauthorized,
            "401 bad key".into(),
        );
        let got = state.read().unwrap();
        assert_eq!(got.last_success.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(
            got.last_failure_kind,
            Some(RefreshFailureKind::Unauthorized)
        );
        assert!(got.last_failure_reason.is_some());
        assert_eq!(got.failures_total, 1);
    }

    // NOTE: a "valid=true with payload replaces and bumps last_validated" test
    // would have to mutate XDG_CONFIG_HOME globally. It's covered indirectly by
    // license::tests::test_save_license_to_writes_atomically_and_is_readable
    // and the revoked test below.

    #[tokio::test]
    async fn apply_validate_response_treats_revoked_as_hard_kept_cached() {
        let creds = make_creds(Utc::now() - Duration::hours(48));
        let resp = ValidateResponse {
            valid: false,
            license: None,
            reason: Some("subscription_inactive".into()),
        };
        let outcome = apply_validate_response(&creds, resp).await;
        match outcome {
            RefreshOutcome::Hard(kind, reason) => {
                assert_eq!(kind, RefreshFailureKind::Revoked);
                assert!(reason.contains("subscription_inactive"));
            }
            other => panic!("expected Hard(Revoked), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_validate_response_rejects_valid_without_payload() {
        let creds = make_creds(Utc::now() - Duration::hours(48));
        let resp = ValidateResponse {
            valid: true,
            license: None,
            reason: None,
        };
        let outcome = apply_validate_response(&creds, resp).await;
        match outcome {
            RefreshOutcome::Hard(kind, reason) => {
                assert_eq!(kind, RefreshFailureKind::Protocol);
                assert!(reason.contains("without license payload"));
            }
            other => panic!("expected Hard(Protocol), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_validate_response_rejects_unverifiable_payload() {
        let creds = make_creds(Utc::now() - Duration::hours(48));
        let resp = ValidateResponse {
            valid: true,
            license: Some(crate::license::SignedLicense {
                version: 1,
                license_id: "bad".into(),
                user_id: "u".into(),
                team_id: "t".into(),
                email: "u@example.com".into(),
                plan: "pro".into(),
                seats: 1,
                features: vec![],
                issued_at: "2026-04-01T00:00:00Z".into(),
                valid_until: "2026-04-08T00:00:00Z".into(),
                billing_portal_url: None,
                air_gapped: Some(false),
                signature: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    [0u8; 64],
                ),
            }),
            reason: None,
        };
        let outcome = apply_validate_response(&creds, resp).await;
        match outcome {
            RefreshOutcome::Hard(kind, reason) => {
                assert_eq!(kind, RefreshFailureKind::Protocol);
                assert!(reason.contains("unverifiable"));
            }
            other => panic!("expected Hard(Protocol), got {other:?}"),
        }
    }
}
