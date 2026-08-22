// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Serializable analytics-v2/schema-v1 contract types.

use std::cmp::{max, min};

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::limits::{MATERIALIZER_VERSION, PROTOCOL_VERSION, SCHEMA_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordClass {
    Decision,
    RoutineSpawn,
    RoutineIo,
    Noise,
    LlmUsage,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletenessTier {
    Decisions,
    Spawns,
    Io,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    FileRead,
    FileMutation,
    Process,
    NetworkEgress,
    NetworkListen,
    CrossProcess,
    Namespace,
    Llm,
    System,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Queue,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotState {
    Partial,
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    Queue,
    Deny,
    Canary,
    Gap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Escalated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationKind {
    Domain,
    HostPort,
    UrlOrigin,
    UnixSocketClass,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainHealth {
    Healthy,
    Gap,
    Broken,
    Quarantined,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceSyncStatus {
    Current,
    Stale,
    Offline,
    SyncDisabled,
    EntitlementExpired,
    QuotaRejected,
    Revoked,
    Gap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceResetReason {
    LocalProjectionLost,
    AuditHistoryLost,
    AuditDatabaseGenerationChanged,
    ManualReset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Json,
    Csv,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    pub protocol_version: u16,
    pub schema_version: u16,
    pub device_id: Uuid,
    pub source_epoch: Uuid,
    pub request_seq: u64,
    pub runtime_instance_id: Uuid,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub generated_at: DateTime<Utc>,
    pub client_version: String,
    pub materializer_version: u16,
    pub completeness: CompletenessTier,
}

impl RequestContext {
    pub fn v2(
        device_id: Uuid,
        source_epoch: Uuid,
        request_seq: u64,
        runtime_instance_id: Uuid,
        generated_at: DateTime<Utc>,
        client_version: impl Into<String>,
        completeness: CompletenessTier,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            schema_version: SCHEMA_VERSION,
            device_id,
            source_epoch,
            request_seq,
            runtime_instance_id,
            generated_at,
            client_version: client_version.into(),
            materializer_version: MATERIALIZER_VERSION,
            completeness,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentReceipt {
    pub consent_version: u16,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub accepted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub protocol_version: u16,
    pub schema_version: u16,
    pub source_epoch: Uuid,
    pub runtime_instance_id: Uuid,
    pub device_display_name: String,
    pub client_version: String,
    pub materializer_version: u16,
    pub completeness: CompletenessTier,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub coverage_start: DateTime<Utc>,
    pub baseline_chain_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_chain_hash: Option<String>,
    pub audit_database_generation: Uuid,
    pub consent: ConsentReceipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationPolicy {
    pub mode: DestinationPolicyMode,
    pub key_version: u16,
    /// Delivered in every mode: destination rollup rows always carry the
    /// team-scoped HMAC; `clear_label` only adds approved display labels on
    /// top of it. A key-less clear_label policy would leave the device unable
    /// to produce any destination row at all.
    pub team_hmac_key_base64: String,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub effective_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationPolicyMode {
    TeamHmac,
    ClearLabel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub protocol_version: u16,
    pub schema_version: u16,
    pub device_id: Uuid,
    pub actor_user_id: String,
    pub team_id: Uuid,
    pub source_epoch: Uuid,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub coverage_start: DateTime<Utc>,
    pub credential_version: u16,
    /// Returned once. It must not be logged or returned by subsequent state calls.
    pub device_secret: String,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub runtime_lease_expires_at: DateTime<Utc>,
    pub destination_policy: DestinationPolicy,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRotationRequest {
    #[serde(flatten)]
    pub context: RequestContext,
    pub current_credential_version: u16,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRotationResponse {
    pub device_id: Uuid,
    pub credential_version: u16,
    /// Returned once; the prior secret is invalid after the grace deadline.
    pub device_secret: String,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub previous_secret_valid_until: DateTime<Utc>,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRevocationRequest {
    #[serde(flatten)]
    pub context: RequestContext,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRevocationResponse {
    pub device_id: Uuid,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub revoked_at: DateTime<Utc>,
    pub future_uploads_accepted: bool,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    #[serde(flatten)]
    pub context: RequestContext,
    pub sync_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::timestamps::ts_micros_opt", default)]
    pub latest_local_event_at: Option<DateTime<Utc>>,
    pub materialized_through_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materialized_through_hash: Option<String>,
    pub dirty_day_count: u16,
    pub oldest_dirty_day: Option<NaiveDate>,
    pub unacknowledged_security_events: u32,
    pub unacknowledged_archive_days: u16,
    pub dropped_event_count: u64,
    pub audit_database_generation: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub device_id: Uuid,
    pub status: DeviceSyncStatus,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub runtime_lease_expires_at: DateTime<Utc>,
    pub next_heartbeat_seconds: u64,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub server_time: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_policy: Option<DestinationPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConfigVersion {
    pub config_hash: String,
    pub profile_id: String,
    pub profile_version: String,
    pub policy_version: String,
    pub auto_allow_threshold_micros: i64,
    pub auto_deny_threshold_micros: i64,
    pub queue_policy: String,
    pub team_default_config_version: String,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub first_seen_at: DateTime<Utc>,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FilterContribution {
    pub filter_id: String,
    pub score_micros: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmUsageEvent {
    pub provider: String,
    pub model: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cost_micros: u64,
    pub currency: String,
    pub price_source: String,
    pub pricing_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationEvent {
    pub kind: DestinationKind,
    /// Team-scoped HMAC. Key rotations intentionally create separate segments.
    pub destination_hmac: String,
    pub hmac_key_version: u16,
    /// Present only after the team's clear-label policy effective time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_display_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityResolution {
    pub status: ResolutionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::timestamps::ts_micros_opt", default)]
    pub resolved_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityResolutionWire {
    pub status: ResolutionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::timestamps::ts_micros_opt", default)]
    pub resolved_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_code: Option<String>,
}

impl From<SecurityResolution> for SecurityResolutionWire {
    fn from(value: SecurityResolution) -> Self {
        Self {
            status: value.status,
            resolved_at: value.resolved_at,
            resolution_code: value.resolution_code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: Uuid,
    pub event_revision: u32,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub occurred_at: DateTime<Utc>,
    pub event_type: SecurityEventType,
    /// Immutable initial policy verdict used by headline verdict analytics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_verdict: Option<Verdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<SecurityResolutionWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    pub project: String,
    pub profile_id: String,
    pub supervised_tool: String,
    pub category: Category,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_micros: Option<i64>,
    pub top_filter_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_outcome_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap_count: Option<u64>,
    // The frozen schema declares these optional-but-non-nullable: an absent
    // field is valid, an explicit null is rejected. Chain-less audit records
    // (legacy rows, NULL sequences) really produce None here.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chain_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chain_hash: Option<String>,
}

/// Safe, row-level input to the shared accumulator. The later audit adapter
/// constructs this without copying operands, paths, prompts, or payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyticsEvent {
    pub event_id: Uuid,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub occurred_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    pub project: String,
    pub profile_id: String,
    pub config_hash: String,
    pub supervised_tool: String,
    pub completeness: CompletenessTier,
    pub record_class: RecordClass,
    pub category: Category,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_verdict: Option<Verdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_micros: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_set_version: Option<u16>,
    pub evaluated_filter_ids: Vec<String>,
    pub positive_filter_contributions: Vec<FilterContribution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_usage: Option<LlmUsageEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<DestinationEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_event: Option<SecurityEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UsageRollupRow {
    #[serde(with = "crate::timestamps::ts_micros")]
    pub bucket_start: DateTime<Utc>,
    pub project: String,
    pub profile_id: String,
    pub config_hash: String,
    pub supervised_tool: String,
    pub record_class: RecordClass,
    pub category: Category,
    pub verdict: Option<Verdict>,
    pub score_bin_version: u16,
    pub score_bucket: Option<u8>,
    pub event_count: u64,
    pub score_sum_micros: i64,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub first_event_at: DateTime<Utc>,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub last_event_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FilterRollupRow {
    pub day: NaiveDate,
    pub project: String,
    pub profile_id: String,
    pub config_hash: String,
    pub filter_set_version: u16,
    pub filter_id: String,
    pub evaluated_events: u64,
    pub triggered_events: u64,
    pub denied_evaluated_events: u64,
    pub denied_positive_contributions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SessionDayRow {
    pub day: NaiveDate,
    pub session_id: Uuid,
    pub project: String,
    pub profile_id: String,
    pub config_hash: String,
    pub supervised_tool: String,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub first_event_at: DateTime<Utc>,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub last_event_at: DateTime<Utc>,
    pub decision_count: u64,
    pub queue_count: u64,
    pub deny_count: u64,
    pub llm_calls: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cost_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LlmRollupRow {
    pub day: NaiveDate,
    pub project: String,
    pub provider: String,
    pub model: String,
    pub currency: String,
    pub price_source: String,
    pub pricing_version: String,
    pub calls: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cost_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DestinationRollupRow {
    pub day: NaiveDate,
    pub kind: DestinationKind,
    pub destination_hmac: String,
    pub hmac_key_version: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_display_label: Option<String>,
    pub verdict: Verdict,
    pub event_count: u64,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub first_event_at: DateTime<Utc>,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub last_event_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaySnapshot {
    pub day: NaiveDate,
    pub day_revision: u64,
    pub read_model_generation: u64,
    pub state: SnapshotState,
    pub source_event_count: u64,
    #[serde(with = "crate::timestamps::ts_micros_opt", default)]
    pub first_event_at: Option<DateTime<Utc>>,
    #[serde(with = "crate::timestamps::ts_micros_opt", default)]
    pub last_event_at: Option<DateTime<Utc>>,
    pub first_chain_sequence: Option<u64>,
    pub last_chain_sequence: Option<u64>,
    pub last_chain_hash: Option<String>,
    pub usage_rows: Vec<UsageRollupRow>,
    pub filter_rows: Vec<FilterRollupRow>,
    pub session_rows: Vec<SessionDayRow>,
    pub llm_rows: Vec<LlmRollupRow>,
    pub destination_rows: Vec<DestinationRollupRow>,
    pub row_checksum_sha256: String,
}

impl DaySnapshot {
    /// Canonical row ordering is part of schema-v1 and is shared by snapshot,
    /// archive, and rebuild checksums.
    pub fn canonicalize(&mut self) {
        // The frozen sort keys (canonical-ordering-and-checksums.md "Snapshot
        // row order") are compared first; the remaining fields break only ties
        // the contract leaves unspecified, so a rebuild from re-ordered input
        // still produces byte-identical checksums. The derived Ord on the row
        // structs compares in declaration order and must not be used here.
        self.usage_rows.sort_by(|a, b| {
            (
                a.bucket_start,
                &a.project,
                &a.profile_id,
                &a.config_hash,
                &a.supervised_tool,
                a.record_class,
                a.category,
                a.verdict,
                a.score_bucket,
            )
                .cmp(&(
                    b.bucket_start,
                    &b.project,
                    &b.profile_id,
                    &b.config_hash,
                    &b.supervised_tool,
                    b.record_class,
                    b.category,
                    b.verdict,
                    b.score_bucket,
                ))
                .then_with(|| a.cmp(b))
        });
        self.filter_rows.sort_by(|a, b| {
            (
                a.day,
                &a.project,
                &a.profile_id,
                &a.config_hash,
                a.filter_set_version,
                &a.filter_id,
            )
                .cmp(&(
                    b.day,
                    &b.project,
                    &b.profile_id,
                    &b.config_hash,
                    b.filter_set_version,
                    &b.filter_id,
                ))
                .then_with(|| a.cmp(b))
        });
        self.session_rows.sort_by(|a, b| {
            (
                a.day,
                a.session_id,
                &a.project,
                &a.profile_id,
                &a.config_hash,
                &a.supervised_tool,
            )
                .cmp(&(
                    b.day,
                    b.session_id,
                    &b.project,
                    &b.profile_id,
                    &b.config_hash,
                    &b.supervised_tool,
                ))
                .then_with(|| a.cmp(b))
        });
        self.llm_rows.sort_by(|a, b| {
            (
                a.day,
                &a.project,
                &a.provider,
                &a.model,
                &a.currency,
                &a.price_source,
                &a.pricing_version,
            )
                .cmp(&(
                    b.day,
                    &b.project,
                    &b.provider,
                    &b.model,
                    &b.currency,
                    &b.price_source,
                    &b.pricing_version,
                ))
                .then_with(|| a.cmp(b))
        });
        self.destination_rows.sort_by(|a, b| {
            (
                a.day,
                a.kind,
                &a.destination_hmac,
                a.hmac_key_version,
                &a.approved_display_label,
                a.verdict,
            )
                .cmp(&(
                    b.day,
                    b.kind,
                    &b.destination_hmac,
                    b.hmac_key_version,
                    &b.approved_display_label,
                    b.verdict,
                ))
                .then_with(|| a.cmp(b))
        });
    }

    pub fn compute_row_checksum(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct CanonicalRows<'a> {
            day: NaiveDate,
            source_event_count: u64,
            #[serde(with = "crate::timestamps::ts_micros_opt")]
            first_event_at: Option<DateTime<Utc>>,
            #[serde(with = "crate::timestamps::ts_micros_opt")]
            last_event_at: Option<DateTime<Utc>>,
            first_chain_sequence: Option<u64>,
            last_chain_sequence: Option<u64>,
            last_chain_hash: &'a Option<String>,
            usage_rows: &'a [UsageRollupRow],
            filter_rows: &'a [FilterRollupRow],
            session_rows: &'a [SessionDayRow],
            llm_rows: &'a [LlmRollupRow],
            destination_rows: &'a [DestinationRollupRow],
        }

        let canonical = CanonicalRows {
            day: self.day,
            source_event_count: self.source_event_count,
            first_event_at: self.first_event_at,
            last_event_at: self.last_event_at,
            first_chain_sequence: self.first_chain_sequence,
            last_chain_sequence: self.last_chain_sequence,
            last_chain_hash: &self.last_chain_hash,
            usage_rows: &self.usage_rows,
            filter_rows: &self.filter_rows,
            session_rows: &self.session_rows,
            llm_rows: &self.llm_rows,
            destination_rows: &self.destination_rows,
        };
        let bytes = serde_json::to_vec(&canonical)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn refresh_checksum(&mut self) -> Result<(), serde_json::Error> {
        self.canonicalize();
        self.row_checksum_sha256 = self.compute_row_checksum()?;
        Ok(())
    }

    pub fn total_rollup_rows(&self) -> usize {
        self.usage_rows.len()
            + self.filter_rows.len()
            + self.session_rows.len()
            + self.llm_rows.len()
            + self.destination_rows.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRequest {
    #[serde(flatten)]
    pub context: RequestContext,
    pub config_versions: Vec<ConfigVersion>,
    /// At most one complete day replacement. May be empty for event-only sends.
    pub day_snapshots: Vec<DaySnapshot>,
    /// May be non-empty when `day_snapshots` is empty.
    pub security_events: Vec<SecurityEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedDay {
    pub day: NaiveDate,
    pub day_revision: u64,
    pub read_model_generation: u64,
    pub row_checksum_sha256: String,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub accepted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEventAcknowledgement {
    pub event_id: Uuid,
    pub event_revision: u32,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub accepted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotResponse {
    pub device_id: Uuid,
    pub source_epoch: Uuid,
    pub accepted_request_seq: u64,
    pub request_digest_sha256: String,
    pub accepted_days: Vec<AcceptedDay>,
    pub security_event_acknowledgements: Vec<SecurityEventAcknowledgement>,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateQuery {
    pub device_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceEpochState {
    pub source_epoch: Uuid,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub coverage_start: DateTime<Utc>,
    #[serde(with = "crate::timestamps::ts_micros_opt", default)]
    pub coverage_end: Option<DateTime<Utc>>,
    pub baseline_chain_sequence: u64,
    pub baseline_chain_hash: Option<String>,
    pub audit_database_generation: Uuid,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DayState {
    pub source_epoch: Uuid,
    pub day: NaiveDate,
    pub accepted_day_revision: u64,
    pub read_model_generation: u64,
    pub row_checksum_sha256: String,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub accepted_at: DateTime<Utc>,
    pub active_archive_revision: Option<u64>,
    pub active_archive_day_revision: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateResponse {
    pub device_id: Uuid,
    pub actor_user_id: String,
    pub team_id: Uuid,
    pub status: DeviceSyncStatus,
    pub active_source_epoch: Uuid,
    pub last_accepted_request_seq: u64,
    #[serde(with = "crate::timestamps::ts_micros_opt", default)]
    pub latest_local_event_at: Option<DateTime<Utc>>,
    #[serde(with = "crate::timestamps::ts_micros_opt", default)]
    pub latest_snapshot_accepted_at: Option<DateTime<Utc>>,
    pub latest_archive_day: Option<NaiveDate>,
    #[serde(with = "crate::timestamps::ts_micros_opt", default)]
    pub last_contact_at: Option<DateTime<Utc>>,
    pub source_epochs: Vec<SourceEpochState>,
    pub days: Vec<DayState>,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceResetRequest {
    #[serde(flatten)]
    pub context: RequestContext,
    pub closing_source_epoch: Uuid,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub closing_coverage_end: DateTime<Utc>,
    pub new_source_epoch: Uuid,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub new_coverage_start: DateTime<Utc>,
    pub new_baseline_chain_sequence: u64,
    pub new_baseline_chain_hash: Option<String>,
    pub new_audit_database_generation: Uuid,
    pub reason: SourceResetReason,
    pub lost_event_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceResetResponse {
    pub device_id: Uuid,
    pub closed_source_epoch: Uuid,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub closed_coverage_end: DateTime<Utc>,
    pub active_source_epoch: Uuid,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub active_coverage_start: DateTime<Utc>,
    pub gap_recorded: bool,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveDeclaration {
    pub day: NaiveDate,
    pub day_revision: u64,
    pub archive_revision: u64,
    pub projection_schema_version: u16,
    pub materializer_version: u16,
    pub row_checksum_sha256: String,
    pub content_sha256: String,
    pub byte_size: u64,
    pub row_count: u64,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub min_event_at: DateTime<Utc>,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub max_event_at: DateTime<Utc>,
    pub first_chain_sequence: Option<u64>,
    pub last_chain_sequence: Option<u64>,
    pub last_chain_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivePresignRequest {
    #[serde(flatten)]
    pub context: RequestContext,
    pub archive: ArchiveDeclaration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivePresignResponse {
    pub device_id: Uuid,
    pub source_epoch: Uuid,
    pub day: NaiveDate,
    pub day_revision: u64,
    pub archive_revision: u64,
    pub object_key: String,
    pub upload_url: String,
    pub required_headers: Vec<HeaderValue>,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HeaderValue {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveFinalizeRequest {
    #[serde(flatten)]
    pub context: RequestContext,
    pub archive: ArchiveDeclaration,
    pub object_key: String,
    pub object_etag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_version: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveFinalizeResponse {
    pub manifest_id: Uuid,
    pub device_id: Uuid,
    pub source_epoch: Uuid,
    pub day: NaiveDate,
    pub day_revision: u64,
    pub active_archive_revision: u64,
    pub content_sha256: String,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub verified_at: DateTime<Utc>,
    pub superseded_archive_revision: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldViolation {
    pub field: String,
    pub rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredError {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub request_id: String,
    pub field_violations: Vec<FieldViolation>,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtcWindow {
    pub start_day: NaiveDate,
    pub end_day: NaiveDate,
    pub current_day_partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictCounts {
    pub total: u64,
    pub allow: u64,
    pub queue: u64,
    pub deny: u64,
    pub allow_rate_ppm: u32,
    pub queue_rate_ppm: u32,
    pub deny_rate_ppm: u32,
}

impl VerdictCounts {
    pub fn from_counts(allow: u64, queue: u64, deny: u64) -> Self {
        let total = allow.saturating_add(queue).saturating_add(deny);
        let rate = |count: u64| -> u32 {
            if total == 0 {
                0
            } else {
                ((u128::from(count) * 1_000_000) / u128::from(total)) as u32
            }
        };
        Self {
            total,
            allow,
            queue,
            deny,
            allow_rate_ppm: rate(allow),
            queue_rate_ppm: rate(queue),
            deny_rate_ppm: rate(deny),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalFreshness {
    #[serde(with = "crate::timestamps::ts_micros_opt", default)]
    pub materialized_through_at: Option<DateTime<Utc>>,
    pub materialized_through_sequence: u64,
    pub dirty_day_count: u16,
    pub rebuilding: bool,
    pub gap_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalFreeAnalyticsResponse {
    pub protocol_version: u16,
    pub schema_version: u16,
    pub access: String,
    pub window: UtcWindow,
    pub decisions: VerdictCounts,
    pub chain_health: ChainHealth,
    #[serde(with = "crate::timestamps::ts_micros_opt", default)]
    pub latest_audit_record_at: Option<DateTime<Utc>>,
    pub recent_queue_and_deny: Vec<SecurityEvent>,
    pub freshness: LocalFreshness,
    pub pro_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalProAnalyticsResponse {
    pub protocol_version: u16,
    pub schema_version: u16,
    pub access: String,
    #[serde(with = "crate::timestamps::ts_micros")]
    pub generated_at: DateTime<Utc>,
    pub windows: Vec<UtcWindow>,
    pub usage_rows: Vec<UsageRollupRow>,
    pub filter_rows: Vec<FilterRollupRow>,
    pub session_rows: Vec<SessionDayRow>,
    pub llm_rows: Vec<LlmRollupRow>,
    pub destination_rows: Vec<DestinationRollupRow>,
    pub security_events: Vec<SecurityEvent>,
    pub freshness: LocalFreshness,
    pub export_formats: Vec<ExportFormat>,
    pub export_max_days: u32,
    /// True when any rollup family was clipped to its schema row cap; the
    /// dropped rows are the oldest days, never a silent middle slice.
    #[serde(default)]
    pub truncated: bool,
}

/// Merge event bounds without relying on a sentinel timestamp.
pub(crate) fn merge_bounds(
    first: &mut Option<DateTime<Utc>>,
    last: &mut Option<DateTime<Utc>>,
    occurred_at: DateTime<Utc>,
) {
    *first = Some(first.map_or(occurred_at, |current| min(current, occurred_at)));
    *last = Some(last.map_or(occurred_at, |current| max(current, occurred_at)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_rates_use_exact_integer_denominator() {
        let counts = VerdictCounts::from_counts(1, 1, 1);
        assert_eq!(counts.total, 3);
        assert_eq!(counts.allow_rate_ppm, 333_333);
        assert_eq!(counts.queue_rate_ppm, 333_333);
        assert_eq!(counts.deny_rate_ppm, 333_333);
    }

    #[test]
    fn request_context_stamps_frozen_versions() {
        let now = Utc::now();
        let context = RequestContext::v2(
            Uuid::nil(),
            Uuid::nil(),
            1,
            Uuid::nil(),
            now,
            "0.2.5",
            CompletenessTier::Decisions,
        );
        assert_eq!(context.protocol_version, PROTOCOL_VERSION);
        assert_eq!(context.schema_version, SCHEMA_VERSION);
        assert_eq!(context.materializer_version, MATERIALIZER_VERSION);
    }

    /// Cross-language checksum vector with sub-second timestamps. Any
    /// serializer that formats these with other than exactly six fractional
    /// digits computes a different digest and must not ship.
    #[test]
    fn row_checksum_vector_pins_subsecond_timestamp_form() {
        use chrono::TimeZone;
        let base = chrono::Utc
            .with_ymd_and_hms(2026, 8, 20, 10, 15, 0)
            .unwrap()
            + chrono::Duration::microseconds(123_456);
        let snapshot = DaySnapshot {
            day: chrono::NaiveDate::from_ymd_opt(2026, 8, 20).unwrap(),
            day_revision: 3,
            read_model_generation: 1,
            state: SnapshotState::Partial,
            source_event_count: 1,
            first_event_at: Some(base),
            last_event_at: Some(base),
            first_chain_sequence: Some(41),
            last_chain_sequence: Some(41),
            last_chain_hash: Some("a".repeat(64)),
            usage_rows: vec![UsageRollupRow {
                bucket_start: chrono::Utc.with_ymd_and_hms(2026, 8, 20, 10, 0, 0).unwrap(),
                project: "project".into(),
                profile_id: "default".into(),
                config_hash: "b".repeat(64),
                supervised_tool: "claude-code".into(),
                record_class: RecordClass::Decision,
                category: Category::FileRead,
                verdict: Some(Verdict::Allow),
                score_bin_version: 1,
                score_bucket: Some(2),
                event_count: 1,
                score_sum_micros: 1_250_000,
                first_event_at: base,
                last_event_at: base,
            }],
            filter_rows: Vec::new(),
            session_rows: Vec::new(),
            llm_rows: Vec::new(),
            destination_rows: Vec::new(),
            row_checksum_sha256: String::new(),
        };
        assert_eq!(
            snapshot.compute_row_checksum().unwrap(),
            "e41de95cb44e73abe0d3c2a40b190cf5ba6c4df2bd1f5ecbc608801a6c5f759b"
        );
    }
}
