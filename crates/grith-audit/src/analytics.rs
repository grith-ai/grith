// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Restart-safe local analytics-v2 projection.
//!
//! The projection is deliberately co-located with the audit writer's SQLite
//! connection. Only the process holding the audit writer lock may call the
//! mutating methods; read-only handles can serve already-materialized rows.
//! Source rows contain the operand-free [`AnalyticsEvent`] contract only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use grith_analytics::accumulator::DayAccumulator;
use grith_analytics::contract::{
    AnalyticsEvent, Category, ChainHealth, CompletenessTier, ConfigVersion, DaySnapshot,
    DestinationEvent, ExportFormat, LlmUsageEvent, LocalFreeAnalyticsResponse, LocalFreshness,
    LocalProAnalyticsResponse, RecordClass, SecurityEvent, SecurityEventType,
    SecurityResolutionWire, SnapshotState, SourceEpochState, SourceResetReason, UtcWindow, Verdict,
    VerdictCounts,
};
use grith_analytics::limits::{
    FREE_RECENT_SECURITY_EVENTS, FREE_WINDOW_DAYS, MAX_DESTINATION_ROWS, MAX_EXPORT_DAYS,
    MAX_FILTER_ROWS, MAX_LLM_ROWS, MAX_SECURITY_EVENTS, MAX_SESSION_ROWS, MAX_USAGE_ROWS,
    PROTOCOL_VERSION, PRO_LONG_WINDOW_DAYS, PRO_SHORT_WINDOW_DAYS, SCHEMA_VERSION,
};
use grith_analytics::normalize::{category_for_tool_kind, normalize_dimension, score_to_micros};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::record_parser::row_to_record;
use crate::storage::AuditStorage;
use crate::types::{
    AuditAnalyticsMetadata, AuditRecord, ChainVerification, ProxyActionSummary, RecordType,
};

/// Maximum audit rows examined by one incremental materializer transaction.
pub const DEFAULT_MATERIALIZER_BATCH: usize = 512;
/// Maximum records accepted by one local audit IPC request.
pub const MAX_AUDIT_IPC_BATCH: usize = 256;

/// Whether the adapter may use explicit, privacy-safe legacy fallbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterMode {
    /// Powers local operational statistics. Unknown historic dimensions are
    /// labelled as such and non-reconstructible panels are left empty.
    Local,
    /// Cloud producers require the prospective envelope and never invent
    /// historic configuration, pricing, destination or resolution facts.
    CloudStrict,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdapterError {
    #[error("record {0} has no prospective analytics metadata")]
    MissingProspectiveMetadata(Uuid),
    #[error("record {record_id} has invalid analytics metadata: {reason}")]
    InvalidMetadata { record_id: Uuid, reason: String },
    #[error("record {record_id} cannot be normalized: {reason}")]
    Normalization { record_id: Uuid, reason: String },
}

/// Stable producer boundary shared by the local materializer and later cloud
/// upload code. It returns operand-free canonical events only.
pub struct AuditAnalyticsAdapter;

impl AuditAnalyticsAdapter {
    pub fn adapt(
        record: &AuditRecord,
        mode: AdapterMode,
    ) -> std::result::Result<AnalyticsEvent, AdapterError> {
        let metadata = match (&record.analytics_metadata, mode) {
            (Some(metadata), _) => Some(metadata),
            (None, AdapterMode::Local) => None,
            (None, AdapterMode::CloudStrict) => {
                return Err(AdapterError::MissingProspectiveMetadata(record.id));
            }
        };

        if metadata.is_some_and(|value| value.metadata_version != 1) {
            return Err(AdapterError::InvalidMetadata {
                record_id: record.id,
                reason: "metadata_version must be 1".into(),
            });
        }

        let record_class = metadata.map_or_else(|| legacy_record_class(record), |m| m.record_class);
        let category = metadata.map_or_else(
            || category_for_tool_kind(&record.tool_call_type),
            |m| m.category,
        );
        let completeness = metadata.map_or(CompletenessTier::Decisions, |m| m.completeness);

        let (profile_id, config_hash) = if let Some(metadata) = metadata {
            validate_metadata(record.id, metadata)?;
            (
                normalize_dimension(Some(&metadata.config.profile_id), "profile_id", 64),
                metadata.config.config_hash.clone(),
            )
        } else {
            (
                normalize_dimension(None, "profile_id", 64),
                legacy_unknown_config_hash(),
            )
        };
        let profile_id = profile_id.map_err(|error| AdapterError::Normalization {
            record_id: record.id,
            reason: error.to_string(),
        })?;
        let project = normalize_dimension(record.project_name.as_deref(), "project", 128).map_err(
            |error| AdapterError::Normalization {
                record_id: record.id,
                reason: error.to_string(),
            },
        )?;
        let supervised_tool = normalize_dimension(
            record
                .supervised_tool
                .as_deref()
                .or(Some(&record.plugin_id)),
            "supervised_tool",
            64,
        )
        .map_err(|error| AdapterError::Normalization {
            record_id: record.id,
            reason: error.to_string(),
        })?;

        let decision = record_class == RecordClass::Decision;
        let initial_verdict = decision.then(|| verdict(record.proxy_action.clone()));
        let score_micros = decision
            .then(|| score_to_micros(record.composite_score))
            .transpose()
            .map_err(|error| AdapterError::Normalization {
                record_id: record.id,
                reason: error.to_string(),
            })?;

        let evaluated_filter_ids = if decision {
            let mut ids: Vec<String> = record
                .filter_results
                .iter()
                .map(|result| canonical_audit_filter_id(&result.filter_name))
                .collect();
            ids.sort();
            ids.dedup();
            ids.truncate(grith_analytics::limits::MAX_EVALUATED_FILTERS);
            ids
        } else {
            Vec::new()
        };
        let evaluated: BTreeSet<&str> = evaluated_filter_ids.iter().map(String::as_str).collect();
        let mut contribution_scores = BTreeMap::new();
        if decision {
            for result in &record.filter_results {
                let filter_id = canonical_audit_filter_id(&result.filter_name);
                if result.matched && result.score > 0.0 && evaluated.contains(filter_id.as_str()) {
                    let score_micros = score_to_micros(result.score).map_err(|error| {
                        AdapterError::Normalization {
                            record_id: record.id,
                            reason: error.to_string(),
                        }
                    })?;
                    contribution_scores
                        .entry(filter_id)
                        .and_modify(|current: &mut i64| *current = (*current).max(score_micros))
                        .or_insert(score_micros);
                }
            }
        }
        let contributions: Vec<grith_analytics::contract::FilterContribution> = contribution_scores
            .into_iter()
            .map(
                |(filter_id, score_micros)| grith_analytics::contract::FilterContribution {
                    filter_id,
                    score_micros,
                },
            )
            .collect();

        let llm_usage = match (record_class, metadata.and_then(|m| m.llm_pricing.as_ref())) {
            (RecordClass::LlmUsage, Some(pricing)) => Some(LlmUsageEvent {
                provider: normalize_dimension(record.llm_provider.as_deref(), "provider", 32)
                    .map_err(|error| AdapterError::Normalization {
                        record_id: record.id,
                        reason: error.to_string(),
                    })?,
                model: normalize_dimension(record.llm_model.as_deref(), "model", 128).map_err(
                    |error| AdapterError::Normalization {
                        record_id: record.id,
                        reason: error.to_string(),
                    },
                )?,
                prompt_tokens: u64::try_from(record.prompt_tokens.unwrap_or_default()).map_err(
                    |_| AdapterError::InvalidMetadata {
                        record_id: record.id,
                        reason: "prompt token count does not fit u64".into(),
                    },
                )?,
                completion_tokens: u64::try_from(record.completion_tokens.unwrap_or_default())
                    .map_err(|_| AdapterError::InvalidMetadata {
                        record_id: record.id,
                        reason: "completion token count does not fit u64".into(),
                    })?,
                cost_micros: pricing.cost_micros,
                currency: "USD".into(),
                price_source: pricing.price_source.clone(),
                pricing_version: pricing.pricing_version.clone(),
            }),
            (RecordClass::LlmUsage, None) => {
                if mode == AdapterMode::CloudStrict {
                    return Err(AdapterError::InvalidMetadata {
                        record_id: record.id,
                        reason: "llm_usage records require exact price source and version".into(),
                    });
                }
                // Pre-analytics `grith run` wrote LLM cost records without a
                // prospective envelope. Every upgraded install has them, so a
                // hard error here would wedge the materializer cursor on the
                // first legacy row and freeze retention with it. The cost the
                // record itself carries is preserved under an explicitly
                // legacy price source.
                Some(LlmUsageEvent {
                    provider: normalize_dimension(record.llm_provider.as_deref(), "provider", 32)
                        .map_err(|error| AdapterError::Normalization {
                        record_id: record.id,
                        reason: error.to_string(),
                    })?,
                    model: normalize_dimension(record.llm_model.as_deref(), "model", 128).map_err(
                        |error| AdapterError::Normalization {
                            record_id: record.id,
                            reason: error.to_string(),
                        },
                    )?,
                    prompt_tokens: u64::try_from(record.prompt_tokens.unwrap_or_default())
                        .unwrap_or_default(),
                    completion_tokens: u64::try_from(record.completion_tokens.unwrap_or_default())
                        .unwrap_or_default(),
                    cost_micros: record
                        .estimated_cost_usd
                        .and_then(|cost| grith_analytics::normalize::cost_usd_to_micros(cost).ok())
                        .unwrap_or_default(),
                    currency: "USD".into(),
                    price_source: "legacy-local".into(),
                    pricing_version: "unversioned".into(),
                })
            }
            (_, _) => None,
        };

        let destination = metadata
            .and_then(|m| m.destination.as_ref())
            .map(|destination| DestinationEvent {
                kind: destination.kind,
                destination_hmac: destination.destination_hmac.clone(),
                hmac_key_version: destination.hmac_key_version,
                approved_display_label: destination.approved_display_label.clone(),
            });
        let security_event = build_security_event(
            record,
            metadata,
            &project,
            &profile_id,
            &supervised_tool,
            category,
            score_micros,
            &evaluated_filter_ids,
            &contributions,
            initial_verdict,
        );

        Ok(AnalyticsEvent {
            event_id: record.id,
            occurred_at: grith_analytics::timestamps::truncate_to_micros(record.timestamp),
            session_id: (record.session_id != Uuid::nil()).then_some(record.session_id),
            project,
            profile_id,
            config_hash,
            supervised_tool,
            completeness,
            record_class,
            category,
            initial_verdict,
            score_micros,
            filter_set_version: decision
                .then(|| metadata.and_then(|m| m.filter_set_version).unwrap_or(1)),
            evaluated_filter_ids,
            positive_filter_contributions: contributions,
            llm_usage,
            destination,
            security_event,
            chain_sequence: record
                .chain_sequence
                .and_then(|value| u64::try_from(value).ok()),
            chain_hash: record.record_hash.clone(),
        })
    }
}

fn validate_metadata(
    record_id: Uuid,
    metadata: &AuditAnalyticsMetadata,
) -> std::result::Result<(), AdapterError> {
    if metadata.config.config_hash.len() != 64
        || !metadata
            .config
            .config_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AdapterError::InvalidMetadata {
            record_id,
            reason: "config_hash must be 64 hexadecimal characters".into(),
        });
    }
    if metadata.config.profile_id.trim().is_empty()
        || metadata.config.profile_version.trim().is_empty()
        || metadata.config.policy_version.trim().is_empty()
        || metadata.config.queue_policy.trim().is_empty()
        || metadata
            .config
            .team_default_config_version
            .trim()
            .is_empty()
    {
        return Err(AdapterError::InvalidMetadata {
            record_id,
            reason: "configuration dimensions must be non-empty".into(),
        });
    }
    if metadata.record_class == RecordClass::Decision
        && (metadata.config.auto_allow_threshold_micros
            >= metadata.config.auto_deny_threshold_micros
            || metadata.config.auto_allow_threshold_micros.unsigned_abs()
                > grith_analytics::limits::MAX_ABS_SCORE_MICROS as u64
            || metadata.config.auto_deny_threshold_micros.unsigned_abs()
                > grith_analytics::limits::MAX_ABS_SCORE_MICROS as u64)
    {
        return Err(AdapterError::InvalidMetadata {
            record_id,
            reason: "configuration thresholds are invalid".into(),
        });
    }
    if metadata.record_class == RecordClass::Decision
        && metadata
            .filter_set_version
            .is_none_or(|version| version == 0)
    {
        return Err(AdapterError::InvalidMetadata {
            record_id,
            reason: "decision records require a non-zero filter_set_version".into(),
        });
    }
    if metadata.destination.as_ref().is_some_and(|destination| {
        destination.destination_hmac.is_empty() || destination.hmac_key_version == 0
    }) {
        return Err(AdapterError::InvalidMetadata {
            record_id,
            reason: "destination metadata requires an HMAC and key version".into(),
        });
    }
    if metadata.llm_pricing.as_ref().is_some_and(|pricing| {
        pricing.price_source.trim().is_empty() || pricing.pricing_version.trim().is_empty()
    }) {
        return Err(AdapterError::InvalidMetadata {
            record_id,
            reason: "LLM pricing requires source and version".into(),
        });
    }
    if metadata
        .security
        .as_ref()
        .is_some_and(|security| security.event_revision == 0)
    {
        return Err(AdapterError::InvalidMetadata {
            record_id,
            reason: "security event revision must be positive".into(),
        });
    }
    Ok(())
}

fn legacy_record_class(record: &AuditRecord) -> RecordClass {
    let kind = record.tool_call_type.to_ascii_lowercase();
    if kind.contains("auditgap") || kind.contains("session_start") || kind.contains("session_end") {
        RecordClass::System
    } else if record.llm_provider.is_some() || record.llm_model.is_some() {
        // Without prospective pricing this will fail closed instead of
        // fabricating a cost; producers should attach AuditLlmPricing.
        RecordClass::LlmUsage
    } else if record.record_type == RecordType::Full {
        RecordClass::Decision
    } else if kind.contains("processspawn") {
        RecordClass::RoutineSpawn
    } else if kind.contains("noise_path") {
        RecordClass::Noise
    } else {
        RecordClass::RoutineIo
    }
}

/// Re-exported from the contract crate so the adapter and the archive
/// exporter cannot drift: the exporter resolves exactly this hash to its
/// explicitly-unknown configuration instead of failing closed.
fn legacy_unknown_config_hash() -> String {
    grith_analytics::archive::unknown_config_hash()
}

fn canonical_audit_filter_id(raw: &str) -> String {
    grith_analytics::normalize::normalize_filter_id(raw).unwrap_or_else(|_| {
        let digest = hex::encode(Sha256::digest(raw.as_bytes()));
        format!("unknown-{}", &digest[..16])
    })
}

fn verdict(action: ProxyActionSummary) -> Verdict {
    match action {
        ProxyActionSummary::Allow => Verdict::Allow,
        ProxyActionSummary::Queue => Verdict::Queue,
        ProxyActionSummary::Deny => Verdict::Deny,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_security_event(
    record: &AuditRecord,
    metadata: Option<&AuditAnalyticsMetadata>,
    project: &str,
    profile_id: &str,
    supervised_tool: &str,
    category: Category,
    score_micros: Option<i64>,
    evaluated_filter_ids: &[String],
    contributions: &[grith_analytics::contract::FilterContribution],
    initial_verdict: Option<Verdict>,
) -> Option<SecurityEvent> {
    let explicit = metadata.and_then(|metadata| metadata.security.as_ref());
    let event_type = explicit
        .map(|security| security.event_type)
        .or(match initial_verdict {
            Some(Verdict::Queue) => Some(SecurityEventType::Queue),
            Some(Verdict::Deny) => Some(SecurityEventType::Deny),
            _ => None,
        })?;
    let resolution = explicit.and_then(|security| {
        security
            .resolution_status
            .map(|status| SecurityResolutionWire {
                status,
                resolved_at: security
                    .resolved_at
                    .map(grith_analytics::timestamps::truncate_to_micros),
                resolution_code: security.resolution_code.clone(),
            })
    });
    // Selection is by contribution (largest first); the wire order is the
    // schema's canonical ascending-bytes order. Only when nothing contributed
    // do the evaluated IDs stand in, so a zero-score queue still names what
    // ran.
    let mut top_filter_ids: Vec<String> = if contributions.is_empty() {
        evaluated_filter_ids.iter().take(8).cloned().collect()
    } else {
        let mut ranked: Vec<_> = contributions.iter().collect();
        ranked.sort_by(|a, b| {
            b.score_micros
                .cmp(&a.score_micros)
                .then_with(|| a.filter_id.cmp(&b.filter_id))
        });
        ranked
            .into_iter()
            .take(8)
            .map(|contribution| contribution.filter_id.clone())
            .collect()
    };
    top_filter_ids.sort();
    Some(SecurityEvent {
        event_id: record.id,
        event_revision: explicit.map_or(1, |security| security.event_revision.max(1)),
        occurred_at: grith_analytics::timestamps::truncate_to_micros(record.timestamp),
        event_type,
        initial_verdict,
        resolution,
        session_id: (record.session_id != Uuid::nil()).then_some(record.session_id),
        project: project.into(),
        profile_id: profile_id.into(),
        supervised_tool: supervised_tool.into(),
        category,
        score_micros,
        top_filter_ids,
        enforcement_outcome_code: explicit
            .and_then(|security| security.enforcement_outcome_code.clone())
            .or_else(|| record.enforcement_outcome.clone()),
        gap_count: explicit.and_then(|security| security.gap_count),
        chain_sequence: record
            .chain_sequence
            .and_then(|value| u64::try_from(value).ok()),
        chain_hash: record.record_hash.clone(),
    })
}

/// Persisted identity/cursor values used by later archive and upload stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyticsProjectionIdentity {
    pub source_epoch: Uuid,
    pub audit_database_generation: Uuid,
    pub coverage_start: DateTime<Utc>,
    pub baseline_chain_sequence: u64,
    pub baseline_chain_hash: Option<String>,
    pub materialized_through_sequence: u64,
}

/// One locally aggregated, cloud-unacknowledged day awaiting snapshot upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingUploadDay {
    pub source_epoch: Uuid,
    pub day: NaiveDate,
    pub day_revision: u64,
}

/// A durable, byte-exact upload request awaiting server acknowledgement.
/// Retries must resend these bytes unchanged: the server binds each accepted
/// `request_seq` to the SHA-256 of the body it first saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadOutboxEntry {
    pub request_seq: u64,
    pub kind: String,
    pub source_epoch: Uuid,
    pub day: Option<NaiveDate>,
    pub body: String,
}

/// Heartbeat-facing summary of local projection and upload-queue state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyticsSyncStats {
    pub source_epoch: Uuid,
    pub audit_database_generation: Uuid,
    pub latest_local_event_at: Option<DateTime<Utc>>,
    pub materialized_through_sequence: u64,
    pub materialized_through_hash: Option<String>,
    /// Days in the active epoch that are locally dirty or not yet
    /// server-acknowledged at their current revision.
    pub pending_upload_days: u64,
    pub oldest_pending_day: Option<NaiveDate>,
    pub unacked_security_events: u64,
    /// Sealed, server-accepted days whose archive object has not been
    /// activated at their current revision. Surfaces archive backlog in the
    /// team dashboard's freshness view; distinct from `pending_upload_days`,
    /// because a rollup acknowledgement is not an archive acknowledgement.
    pub unacked_archive_days: u64,
    pub gap_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializerCrashPoint {
    None,
    AfterSafeEvents,
    BeforeCursor,
}

/// Create all local projection state. Called only by writable AuditStorage
/// initialisation, before the writer lock owner begins accepting events.
pub(crate) fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS analytics_projection_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            source_epoch TEXT NOT NULL,
            audit_database_generation TEXT NOT NULL,
            coverage_start TEXT NOT NULL,
            baseline_chain_sequence INTEGER NOT NULL,
            baseline_chain_hash TEXT,
            materialized_through_sequence INTEGER NOT NULL DEFAULT 0,
            materialized_through_hash TEXT,
            materialized_through_at TEXT,
            read_model_generation INTEGER NOT NULL DEFAULT 1,
            rebuilding INTEGER NOT NULL DEFAULT 0,
            gap_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT
        );
        CREATE TABLE IF NOT EXISTS analytics_source_epochs (
            source_epoch TEXT PRIMARY KEY,
            coverage_start TEXT NOT NULL,
            coverage_end TEXT,
            baseline_chain_sequence INTEGER NOT NULL,
            baseline_chain_hash TEXT,
            audit_database_generation TEXT NOT NULL,
            reset_reason TEXT,
            active INTEGER NOT NULL CHECK(active IN (0, 1))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_analytics_one_active_epoch
            ON analytics_source_epochs(active) WHERE active = 1;
        CREATE TABLE IF NOT EXISTS analytics_source_events (
            event_id TEXT PRIMARY KEY,
            source_epoch TEXT NOT NULL,
            event_digest TEXT NOT NULL,
            day TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            chain_sequence INTEGER,
            prospective_metadata INTEGER NOT NULL CHECK(prospective_metadata IN (0, 1)),
            event_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_analytics_source_day
            ON analytics_source_events(source_epoch, day, occurred_at, event_id);
        CREATE INDEX IF NOT EXISTS idx_analytics_source_sequence
            ON analytics_source_events(chain_sequence);
        CREATE TABLE IF NOT EXISTS analytics_config_versions (
            config_hash TEXT PRIMARY KEY,
            config_json TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS analytics_day_state (
            source_epoch TEXT NOT NULL,
            day TEXT NOT NULL,
            day_revision INTEGER NOT NULL,
            read_model_generation INTEGER NOT NULL,
            snapshot_state TEXT NOT NULL,
            dirty INTEGER NOT NULL DEFAULT 0 CHECK(dirty IN (0, 1)),
            source_event_count INTEGER NOT NULL,
            first_event_at TEXT,
            last_event_at TEXT,
            first_chain_sequence INTEGER,
            last_chain_sequence INTEGER,
            last_chain_hash TEXT,
            row_checksum_sha256 TEXT NOT NULL,
            snapshot_ack_revision INTEGER,
            archive_revision INTEGER,
            archive_day_revision INTEGER,
            archive_content_sha256 TEXT,
            archive_ack_revision INTEGER,
            upload_ack_revision INTEGER,
            archive_state TEXT NOT NULL DEFAULT 'not_built',
            updated_at TEXT NOT NULL,
            PRIMARY KEY(source_epoch, day)
        );
        CREATE TABLE IF NOT EXISTS analytics_usage_hourly (
            source_epoch TEXT NOT NULL,
            day TEXT NOT NULL,
            row_key TEXT NOT NULL,
            row_json TEXT NOT NULL,
            PRIMARY KEY(source_epoch, day, row_key)
        );
        CREATE TABLE IF NOT EXISTS analytics_filter_daily (
            source_epoch TEXT NOT NULL,
            day TEXT NOT NULL,
            row_key TEXT NOT NULL,
            row_json TEXT NOT NULL,
            PRIMARY KEY(source_epoch, day, row_key)
        );
        CREATE TABLE IF NOT EXISTS analytics_session_day (
            source_epoch TEXT NOT NULL,
            day TEXT NOT NULL,
            row_key TEXT NOT NULL,
            row_json TEXT NOT NULL,
            PRIMARY KEY(source_epoch, day, row_key)
        );
        CREATE TABLE IF NOT EXISTS analytics_llm_daily (
            source_epoch TEXT NOT NULL,
            day TEXT NOT NULL,
            row_key TEXT NOT NULL,
            row_json TEXT NOT NULL,
            PRIMARY KEY(source_epoch, day, row_key)
        );
        CREATE TABLE IF NOT EXISTS analytics_destination_daily (
            source_epoch TEXT NOT NULL,
            day TEXT NOT NULL,
            row_key TEXT NOT NULL,
            row_json TEXT NOT NULL,
            PRIMARY KEY(source_epoch, day, row_key)
        );
        CREATE TABLE IF NOT EXISTS analytics_security_events (
            event_id TEXT PRIMARY KEY,
            source_epoch TEXT NOT NULL,
            event_revision INTEGER NOT NULL,
            day TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            initial_verdict TEXT,
            event_json TEXT NOT NULL,
            upload_ack_revision INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_analytics_security_recent
            ON analytics_security_events(occurred_at DESC, event_id DESC);
        CREATE INDEX IF NOT EXISTS idx_analytics_usage_day ON analytics_usage_hourly(day);
        CREATE INDEX IF NOT EXISTS idx_analytics_filter_day ON analytics_filter_daily(day);
        CREATE INDEX IF NOT EXISTS idx_analytics_session_day_day ON analytics_session_day(day);
        CREATE INDEX IF NOT EXISTS idx_analytics_llm_day ON analytics_llm_daily(day);
        CREATE INDEX IF NOT EXISTS idx_analytics_destination_day ON analytics_destination_daily(day);
        CREATE TABLE IF NOT EXISTS analytics_upload_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            next_request_seq INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS analytics_upload_outbox (
            request_seq INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            source_epoch TEXT NOT NULL,
            day TEXT,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );",
    )?;

    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM analytics_projection_state WHERE singleton = 1)",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        let generation = Uuid::new_v4();
        let source_epoch = Uuid::new_v4();
        let first: Option<(i64, Option<String>, String)> = conn
            .query_row(
                "SELECT chain_sequence, prev_hash, timestamp FROM audit_log
                 WHERE chain_sequence IS NOT NULL ORDER BY chain_sequence ASC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (baseline_sequence, baseline_hash, coverage_start) = first.map_or_else(
            || (0, None, Utc::now().to_rfc3339()),
            |(sequence, previous_hash, timestamp)| {
                (sequence.saturating_sub(1), previous_hash, timestamp)
            },
        );
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO analytics_projection_state (
                singleton, source_epoch, audit_database_generation, coverage_start,
                baseline_chain_sequence, baseline_chain_hash
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                source_epoch.to_string(),
                generation.to_string(),
                coverage_start,
                baseline_sequence,
                baseline_hash,
            ],
        )?;
        tx.execute(
            "INSERT INTO analytics_source_epochs (
                source_epoch, coverage_start, baseline_chain_sequence,
                baseline_chain_hash, audit_database_generation, active
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![
                source_epoch.to_string(),
                coverage_start,
                baseline_sequence,
                baseline_hash,
                generation.to_string(),
            ],
        )?;
        tx.commit()?;
    }
    Ok(())
}

impl AuditStorage {
    /// Materialize at most `batch_size` newly committed audit rows. The safe
    /// event inserts, complete touched-day replacements and cursor update are
    /// one IMMEDIATE transaction, so every injected crash point rolls back to
    /// a restartable state.
    pub fn materialize_analytics_tail(&mut self, batch_size: usize) -> Result<usize> {
        self.materialize_analytics_tail_with_crash(batch_size, MaterializerCrashPoint::None)
    }

    #[doc(hidden)]
    pub fn materialize_analytics_tail_with_crash(
        &mut self,
        batch_size: usize,
        crash_point: MaterializerCrashPoint,
    ) -> Result<usize> {
        if self.is_read_only() {
            return Err(Error::Analytics(
                "read-only audit handles cannot mutate the analytics projection".into(),
            ));
        }
        let limit = batch_size.clamp(1, DEFAULT_MATERIALIZER_BATCH * 4);
        let cursor: i64 = self.connection().query_row(
            "SELECT materialized_through_sequence FROM analytics_projection_state
             WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let records = read_tail(self.connection(), cursor, limit)?;
        if records.is_empty() {
            return Ok(0);
        }
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        project_records(&tx, &records, false, crash_point, DayRebuild::Defer)?;
        tx.commit()?;
        Ok(records.len())
    }

    /// Rebuild the rollups of up to `max_days` dirty UTC days, one bounded
    /// transaction per day, oldest first. Tail materialization only appends
    /// source events and marks days dirty; this is where the aggregation
    /// actually happens, off the audit writer's per-batch path.
    pub fn rebuild_dirty_days(&mut self, max_days: usize) -> Result<usize> {
        if self.is_read_only() {
            return Err(Error::Analytics(
                "read-only audit handles cannot mutate the analytics projection".into(),
            ));
        }
        let limit = i64::try_from(max_days).unwrap_or(i64::MAX);
        let dirty: Vec<(String, String)> = {
            let mut statement = self.connection().prepare(
                "SELECT source_epoch, day FROM analytics_day_state
                 WHERE dirty = 1 ORDER BY day ASC LIMIT ?1",
            )?;
            let rows = statement.query_map(params![limit], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut rebuilt = 0usize;
        for (source_epoch, day) in dirty {
            let day = day
                .parse::<NaiveDate>()
                .map_err(|error| Error::Analytics(format!("invalid day state key: {error}")))?;
            let tx = self
                .connection_mut()
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let generation: i64 = tx.query_row(
                "SELECT read_model_generation FROM analytics_projection_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?;
            rebuild_day(&tx, &source_epoch, day, generation.max(0) as u64)?;
            tx.commit()?;
            rebuilt += 1;
        }
        Ok(rebuilt)
    }

    /// Drain all currently committed rows in bounded transactions, then
    /// rebuild every dirty day so the read models are current.
    pub fn catch_up_analytics(&mut self) -> Result<usize> {
        let mut total = 0usize;
        loop {
            let count = self.materialize_analytics_tail(DEFAULT_MATERIALIZER_BATCH)?;
            total = total.saturating_add(count);
            if count < DEFAULT_MATERIALIZER_BATCH {
                break;
            }
        }
        self.rebuild_dirty_days(usize::MAX)?;
        Ok(total)
    }

    /// Bounded catch-up for interactive read paths and the background
    /// worker: at most `max_batches` tail batches and `max_days` day
    /// rebuilds per call, so a first read over a large backlog cannot hold
    /// the storage lock for minutes. Returns `(records_materialized,
    /// days_rebuilt)`; the freshness block reports whatever lag remains.
    pub fn catch_up_analytics_bounded(
        &mut self,
        max_batches: usize,
        max_days: usize,
    ) -> Result<(usize, usize)> {
        let mut total = 0usize;
        for _ in 0..max_batches {
            let count = self.materialize_analytics_tail(DEFAULT_MATERIALIZER_BATCH)?;
            total = total.saturating_add(count);
            if count < DEFAULT_MATERIALIZER_BATCH {
                break;
            }
        }
        let rebuilt = self.rebuild_dirty_days(max_days)?;
        Ok((total, rebuilt))
    }

    /// Rebuild from the union of active SQLite rows and user-managed cold
    /// archives. Duplicate archive frames are deduplicated by event_id;
    /// conflicting content under one ID fails closed.
    pub fn rebuild_analytics_from_active_and_cold(&mut self, cold_dir: &Path) -> Result<usize> {
        if self.is_read_only() {
            return Err(Error::Analytics(
                "read-only audit handles cannot rebuild analytics".into(),
            ));
        }
        let mut by_id: BTreeMap<Uuid, AuditRecord> = BTreeMap::new();
        for path in crate::retention::list_archive_files(cold_dir) {
            for record in crate::retention::read_zstd_jsonl(&path)? {
                merge_rebuild_record(&mut by_id, record)?;
            }
        }
        for record in read_all_active(self.connection())? {
            merge_rebuild_record(&mut by_id, record)?;
        }
        let mut records: Vec<AuditRecord> = by_id.into_values().collect();
        records.sort_by_key(|record| (record.chain_sequence.unwrap_or(i64::MAX), record.timestamp));

        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE analytics_projection_state SET
                rebuilding = 1, last_error = NULL,
                read_model_generation = read_model_generation + 1
             WHERE singleton = 1",
            [],
        )?;
        clear_projection(&tx)?;
        project_records(
            &tx,
            &records,
            true,
            MaterializerCrashPoint::None,
            DayRebuild::Inline,
        )?;
        // The cursor tracks the ACTIVE chain only. Cold archives can carry
        // sequences from a previous chain generation that exceed the live
        // head (chain re-genesis restarts at 1); letting them set the cursor
        // would make every new row invisible to materialization while
        // analytics_covers_sequence keeps authorizing retention to prune
        // rows the projection never saw.
        let head: Option<(i64, Option<String>, String)> = tx
            .query_row(
                "SELECT chain_sequence, record_hash, timestamp FROM audit_log
                 WHERE chain_sequence IS NOT NULL
                 ORDER BY chain_sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        match head {
            Some((sequence, hash, at)) => tx.execute(
                "UPDATE analytics_projection_state SET
                    materialized_through_sequence = ?1,
                    materialized_through_hash = ?2,
                    materialized_through_at = ?3,
                    rebuilding = 0
                 WHERE singleton = 1",
                params![sequence, hash, at],
            )?,
            None => tx.execute(
                "UPDATE analytics_projection_state SET
                    materialized_through_sequence = baseline_chain_sequence,
                    materialized_through_hash = baseline_chain_hash,
                    materialized_through_at = NULL,
                    rebuilding = 0
                 WHERE singleton = 1",
                [],
            )?,
        };
        tx.commit()?;
        // Days that existed before the rebuild but no longer have any source
        // events were only marked dirty by clear_projection; settle them into
        // empty snapshots with bumped revisions.
        self.rebuild_dirty_days(usize::MAX)?;
        Ok(records.len())
    }

    pub fn analytics_projection_identity(&self) -> Result<AnalyticsProjectionIdentity> {
        self.connection()
            .query_row(
                "SELECT source_epoch, audit_database_generation, coverage_start,
                    baseline_chain_sequence, baseline_chain_hash,
                    materialized_through_sequence
             FROM analytics_projection_state WHERE singleton = 1",
                [],
                |row| {
                    let source_epoch: String = row.get(0)?;
                    let generation: String = row.get(1)?;
                    let coverage_start: String = row.get(2)?;
                    Ok(AnalyticsProjectionIdentity {
                        source_epoch: parse_uuid_sql(source_epoch)?,
                        audit_database_generation: parse_uuid_sql(generation)?,
                        coverage_start: parse_time_sql(coverage_start)?,
                        baseline_chain_sequence: row.get::<_, i64>(3)?.max(0) as u64,
                        baseline_chain_hash: row.get(4)?,
                        materialized_through_sequence: row.get::<_, i64>(5)?.max(0) as u64,
                    })
                },
            )
            .map_err(Into::into)
    }

    /// Close the active source epoch and begin a non-overlapping successor.
    /// Used when the audit database generation or coverage baseline changes;
    /// prior epoch rows remain queryable but can never overlap this coverage
    /// interval. Cloud registration can consume the returned identity later.
    /// Rotate the source epoch to begin coverage NOW, baselined at the live
    /// chain head so only records appended from here on materialize into the
    /// new epoch. Used when cloud registration requires prospective coverage
    /// (the frozen rule: coverage never precedes consent) — the closed
    /// epoch's rollups stay locally queryable, and its rows are simply never
    /// uploaded.
    pub fn analytics_rotate_epoch_to_now(
        &mut self,
        reason: SourceResetReason,
    ) -> Result<AnalyticsProjectionIdentity> {
        let identity = self.analytics_projection_identity()?;
        let head: Option<(i64, Option<String>)> = self
            .connection()
            .query_row(
                "SELECT chain_sequence, record_hash FROM audit_log
                 WHERE chain_sequence IS NOT NULL
                 ORDER BY chain_sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (baseline_sequence, baseline_hash) = head
            .map(|(sequence, hash)| (sequence.max(0) as u64, hash))
            .unwrap_or((
                identity.baseline_chain_sequence,
                identity.baseline_chain_hash,
            ));
        self.rotate_analytics_source_epoch(
            reason,
            identity.audit_database_generation,
            Utc::now(),
            baseline_sequence,
            baseline_hash,
        )
    }

    pub fn rotate_analytics_source_epoch(
        &mut self,
        reason: SourceResetReason,
        audit_database_generation: Uuid,
        coverage_start: DateTime<Utc>,
        baseline_chain_sequence: u64,
        baseline_chain_hash: Option<String>,
    ) -> Result<AnalyticsProjectionIdentity> {
        if self.is_read_only() {
            return Err(Error::Analytics(
                "read-only audit handles cannot rotate source epochs".into(),
            ));
        }
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior_start: String = tx.query_row(
            "SELECT coverage_start FROM analytics_source_epochs WHERE active = 1",
            [],
            |row| row.get(0),
        )?;
        let prior_start = parse_time(prior_start)?;
        if coverage_start <= prior_start {
            return Err(Error::Analytics(
                "new source epoch coverage must begin after the active epoch".into(),
            ));
        }
        let prior_end = coverage_start - Duration::microseconds(1);
        tx.execute(
            "UPDATE analytics_source_epochs
             SET coverage_end = ?1, active = 0 WHERE active = 1",
            params![prior_end.to_rfc3339()],
        )?;
        let source_epoch = Uuid::new_v4();
        tx.execute(
            "INSERT INTO analytics_source_epochs (
                source_epoch, coverage_start, baseline_chain_sequence,
                baseline_chain_hash, audit_database_generation, reset_reason, active
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
            params![
                source_epoch.to_string(),
                coverage_start.to_rfc3339(),
                baseline_chain_sequence as i64,
                baseline_chain_hash,
                audit_database_generation.to_string(),
                source_reset_reason_name(reason),
            ],
        )?;
        tx.execute(
            "UPDATE analytics_projection_state SET
                source_epoch = ?1,
                audit_database_generation = ?2,
                coverage_start = ?3,
                baseline_chain_sequence = ?4,
                baseline_chain_hash = ?5,
                materialized_through_sequence = ?4,
                materialized_through_hash = ?5,
                materialized_through_at = NULL,
                read_model_generation = read_model_generation + 1,
                rebuilding = 0,
                last_error = NULL
             WHERE singleton = 1",
            params![
                source_epoch.to_string(),
                audit_database_generation.to_string(),
                coverage_start.to_rfc3339(),
                baseline_chain_sequence as i64,
                baseline_chain_hash,
            ],
        )?;
        tx.commit()?;
        Ok(AnalyticsProjectionIdentity {
            source_epoch,
            audit_database_generation,
            coverage_start,
            baseline_chain_sequence,
            baseline_chain_hash,
            materialized_through_sequence: baseline_chain_sequence,
        })
    }

    pub fn analytics_source_epochs(&self) -> Result<Vec<SourceEpochState>> {
        let mut statement = self.connection().prepare(
            "SELECT source_epoch, coverage_start, coverage_end,
                    baseline_chain_sequence, baseline_chain_hash,
                    audit_database_generation, active
             FROM analytics_source_epochs ORDER BY coverage_start ASC",
        )?;
        let rows = statement.query_map([], |row| {
            let source_epoch: String = row.get(0)?;
            let coverage_start: String = row.get(1)?;
            let coverage_end: Option<String> = row.get(2)?;
            let generation: String = row.get(5)?;
            Ok(SourceEpochState {
                source_epoch: parse_uuid_sql(source_epoch)?,
                coverage_start: parse_time_sql(coverage_start)?,
                coverage_end: coverage_end.map(parse_time_sql).transpose()?,
                baseline_chain_sequence: row.get::<_, i64>(3)?.max(0) as u64,
                baseline_chain_hash: row.get(4)?,
                audit_database_generation: parse_uuid_sql(generation)?,
                active: row.get::<_, i64>(6)? != 0,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Durably allocate the next upload `request_seq`. A sequence consumed
    /// here is never reused, even when the request it was minted for is lost
    /// before it reaches the outbox — the server keys idempotency receipts by
    /// `(device, request_seq, body digest)`, so gaps are harmless but reuse
    /// with different bytes is a permanent conflict.
    pub fn analytics_allocate_request_seq(&mut self) -> Result<u64> {
        if self.is_read_only() {
            return Err(Error::Analytics(
                "read-only audit handles cannot allocate upload sequences".into(),
            ));
        }
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO analytics_upload_state (singleton) VALUES (1)",
            [],
        )?;
        let seq: i64 = tx.query_row(
            "UPDATE analytics_upload_state SET next_request_seq = next_request_seq + 1
             WHERE singleton = 1 RETURNING next_request_seq - 1",
            [],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(seq.max(0) as u64)
    }

    /// The sequence the next [`Self::analytics_allocate_request_seq`] call
    /// would return. Used for request contexts that the server does not
    /// receipt (heartbeats), which therefore need no durable allocation.
    pub fn analytics_peek_request_seq(&self) -> Result<u64> {
        let seq: Option<i64> = self
            .connection()
            .query_row(
                "SELECT next_request_seq FROM analytics_upload_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(seq.unwrap_or(1).max(0) as u64)
    }

    /// Persist the exact serialized bytes of an upload request before its
    /// first send, so every retry is byte-identical.
    pub fn analytics_outbox_put(
        &mut self,
        request_seq: u64,
        kind: &str,
        source_epoch: Uuid,
        day: Option<NaiveDate>,
        body: &str,
    ) -> Result<()> {
        self.connection().execute(
            "INSERT INTO analytics_upload_outbox (
                request_seq, kind, source_epoch, day, body, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request_seq as i64,
                kind,
                source_epoch.to_string(),
                day.map(|value| value.to_string()),
                body,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn analytics_outbox_oldest(&self) -> Result<Option<UploadOutboxEntry>> {
        self.connection()
            .query_row(
                "SELECT request_seq, kind, source_epoch, day, body
                 FROM analytics_upload_outbox ORDER BY request_seq ASC LIMIT 1",
                [],
                |row| {
                    let source_epoch: String = row.get(2)?;
                    let day: Option<String> = row.get(3)?;
                    Ok(UploadOutboxEntry {
                        request_seq: row.get::<_, i64>(0)?.max(0) as u64,
                        kind: row.get(1)?,
                        source_epoch: parse_uuid_sql(source_epoch)?,
                        day: day.map(parse_day_sql).transpose()?,
                        body: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn analytics_outbox_delete(&mut self, request_seq: u64) -> Result<()> {
        self.connection().execute(
            "DELETE FROM analytics_upload_outbox WHERE request_seq = ?1",
            params![request_seq as i64],
        )?;
        Ok(())
    }

    /// Days in `source_epoch` whose current local aggregation the server has
    /// not acknowledged, oldest first. Locally dirty days are excluded — they
    /// are mid-rebuild and will reappear here at their next revision.
    pub fn analytics_upload_pending_days(
        &self,
        source_epoch: Uuid,
        limit: usize,
    ) -> Result<Vec<PendingUploadDay>> {
        let mut statement = self.connection().prepare(
            "SELECT day, day_revision FROM analytics_day_state
             WHERE source_epoch = ?1 AND dirty = 0
               AND (snapshot_ack_revision IS NULL OR snapshot_ack_revision < day_revision)
             ORDER BY day ASC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![source_epoch.to_string(), limit as i64], |row| {
            let day: String = row.get(0)?;
            Ok(PendingUploadDay {
                source_epoch,
                day: parse_day_sql(day)?,
                day_revision: row.get::<_, i64>(1)?.max(0) as u64,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Assemble the wire [`DaySnapshot`] for one day from the local
    /// projection, verifying that the reassembled rows still hash to the
    /// checksum recorded when the day was aggregated.
    pub fn analytics_build_day_snapshot(
        &self,
        source_epoch: Uuid,
        day: NaiveDate,
    ) -> Result<DaySnapshot> {
        let connection = self.connection();
        let epoch = source_epoch.to_string();
        let day_key = day.to_string();
        let mut snapshot = connection.query_row(
            "SELECT day_revision, read_model_generation, snapshot_state,
                    source_event_count, first_event_at, last_event_at,
                    first_chain_sequence, last_chain_sequence, last_chain_hash,
                    row_checksum_sha256
             FROM analytics_day_state WHERE source_epoch = ?1 AND day = ?2",
            params![epoch, day_key],
            |row| {
                let state: String = row.get(2)?;
                let first_event_at: Option<String> = row.get(4)?;
                let last_event_at: Option<String> = row.get(5)?;
                Ok(DaySnapshot {
                    day,
                    day_revision: row.get::<_, i64>(0)?.max(0) as u64,
                    read_model_generation: row.get::<_, i64>(1)?.max(0) as u64,
                    state: parse_snapshot_state_sql(state)?,
                    source_event_count: row.get::<_, i64>(3)?.max(0) as u64,
                    first_event_at: first_event_at.map(parse_time_sql).transpose()?,
                    last_event_at: last_event_at.map(parse_time_sql).transpose()?,
                    first_chain_sequence: row
                        .get::<_, Option<i64>>(6)?
                        .and_then(|value| u64::try_from(value).ok()),
                    last_chain_sequence: row
                        .get::<_, Option<i64>>(7)?
                        .and_then(|value| u64::try_from(value).ok()),
                    last_chain_hash: row.get(8)?,
                    usage_rows: Vec::new(),
                    filter_rows: Vec::new(),
                    session_rows: Vec::new(),
                    llm_rows: Vec::new(),
                    destination_rows: Vec::new(),
                    row_checksum_sha256: row.get(9)?,
                })
            },
        )?;
        snapshot.usage_rows =
            load_family_rows(connection, "analytics_usage_hourly", &epoch, &day_key)?;
        snapshot.filter_rows =
            load_family_rows(connection, "analytics_filter_daily", &epoch, &day_key)?;
        snapshot.session_rows =
            load_family_rows(connection, "analytics_session_day", &epoch, &day_key)?;
        snapshot.llm_rows = load_family_rows(connection, "analytics_llm_daily", &epoch, &day_key)?;
        snapshot.destination_rows =
            load_family_rows(connection, "analytics_destination_daily", &epoch, &day_key)?;
        snapshot.canonicalize();
        let recomputed = snapshot
            .compute_row_checksum()
            .map_err(|error| Error::Analytics(error.to_string()))?;
        if recomputed != snapshot.row_checksum_sha256 {
            return Err(Error::Analytics(format!(
                "day {day} rows no longer match their recorded checksum \
                 (stored {}, recomputed {recomputed})",
                snapshot.row_checksum_sha256
            )));
        }
        Ok(snapshot)
    }

    /// Security events in `source_epoch` whose current revision the server
    /// has not acknowledged, oldest first, capped at `limit` (the wire cap is
    /// per-request; a storm day drains across successive requests).
    pub fn analytics_unacked_security_events(
        &self,
        source_epoch: Uuid,
        limit: usize,
    ) -> Result<Vec<SecurityEvent>> {
        let mut statement = self.connection().prepare(
            "SELECT event_json FROM analytics_security_events
             WHERE source_epoch = ?1
               AND (upload_ack_revision IS NULL OR upload_ack_revision < event_revision)
             ORDER BY occurred_at ASC, event_id ASC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![source_epoch.to_string(), limit as i64], |row| {
            row.get::<_, String>(0)
        })?;
        let mut events = Vec::new();
        for row in rows {
            events.push(serde_json::from_str(&row?)?);
        }
        Ok(events)
    }

    /// Most recently seen configuration versions, bounded to the wire cap.
    pub fn analytics_config_versions_recent(&self, limit: usize) -> Result<Vec<ConfigVersion>> {
        let mut statement = self.connection().prepare(
            "SELECT config_json FROM analytics_config_versions
             ORDER BY last_seen_at DESC, config_hash ASC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as i64], |row| row.get::<_, String>(0))?;
        let mut versions = Vec::new();
        for row in rows {
            versions.push(serde_json::from_str(&row?)?);
        }
        Ok(versions)
    }

    /// Record a server day acknowledgement. Acks only move forward: a late
    /// response for an older revision must not lower a newer one.
    pub fn analytics_record_day_ack(
        &mut self,
        source_epoch: Uuid,
        day: NaiveDate,
        revision: u64,
    ) -> Result<()> {
        self.connection().execute(
            "UPDATE analytics_day_state
             SET snapshot_ack_revision = MAX(COALESCE(snapshot_ack_revision, 0), ?3)
             WHERE source_epoch = ?1 AND day = ?2",
            params![source_epoch.to_string(), day.to_string(), revision as i64],
        )?;
        Ok(())
    }

    /// Record server security-event acknowledgements (event id + the
    /// revision the ack covered).
    pub fn analytics_record_security_acks(&mut self, acks: &[(Uuid, u32)]) -> Result<()> {
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (event_id, revision) in acks {
            tx.execute(
                "UPDATE analytics_security_events
                 SET upload_ack_revision = MAX(COALESCE(upload_ack_revision, 0), ?2)
                 WHERE event_id = ?1",
                params![event_id.to_string(), i64::from(*revision)],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Reconcile a day whose upload the server rejected as stale: the server
    /// already holds `server_revision` (a restored backup or second runtime
    /// raced ahead of this projection). Adopt the server revision as both the
    /// acknowledgement floor and the local revision floor, then mark the day
    /// dirty so the next rebuild republishes it at `server_revision + 1`.
    pub fn analytics_reconcile_server_day(
        &mut self,
        source_epoch: Uuid,
        day: NaiveDate,
        server_revision: u64,
    ) -> Result<()> {
        self.connection().execute(
            "UPDATE analytics_day_state SET
                snapshot_ack_revision = MAX(COALESCE(snapshot_ack_revision, 0), ?3),
                day_revision = MAX(day_revision, ?3),
                dirty = 1,
                updated_at = ?4
             WHERE source_epoch = ?1 AND day = ?2",
            params![
                source_epoch.to_string(),
                day.to_string(),
                server_revision as i64,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// A sealed day ready for archive: the day is materialized (not dirty),
    /// its snapshot was accepted by the server at this revision, and the
    /// archive has not been built for that revision yet.
    ///
    /// Sealed means the day is complete and past: today is still partial, so
    /// archiving it would immediately be superseded. A late record reopens
    /// the day, bumps its revision, and this returns it again.
    pub fn analytics_archivable_days(
        &self,
        source_epoch: Uuid,
        today: NaiveDate,
        limit: usize,
    ) -> Result<Vec<PendingUploadDay>> {
        let mut statement = self.connection().prepare(
            "SELECT day, day_revision FROM analytics_day_state
             WHERE source_epoch = ?1 AND dirty = 0 AND day < ?2
               AND snapshot_ack_revision IS NOT NULL
               AND snapshot_ack_revision >= day_revision
               AND archive_state <> 'unarchivable'
               AND (archive_ack_revision IS NULL OR archive_day_revision IS NULL
                    OR archive_day_revision < day_revision)
             ORDER BY day ASC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![source_epoch.to_string(), today.to_string(), limit as i64],
            |row| {
                let day: String = row.get(0)?;
                Ok(PendingUploadDay {
                    source_epoch,
                    day: parse_day_sql(day)?,
                    day_revision: row.get::<_, i64>(1)?.max(0) as u64,
                })
            },
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Every operand-free event the archive object for one day must carry,
    /// in insertion order (the writer re-sorts into the frozen order), plus
    /// the configuration versions those events reference.
    pub fn analytics_day_export(
        &self,
        source_epoch: Uuid,
        day: NaiveDate,
    ) -> Result<(Vec<AnalyticsEvent>, BTreeMap<String, ConfigVersion>)> {
        let connection = self.connection();
        let mut statement = connection.prepare(
            "SELECT event_json FROM analytics_source_events
             WHERE source_epoch = ?1 AND day = ?2
             ORDER BY occurred_at ASC, event_id ASC",
        )?;
        let rows = statement
            .query_map(params![source_epoch.to_string(), day.to_string()], |row| {
                row.get::<_, String>(0)
            })?;
        let mut events: Vec<AnalyticsEvent> = Vec::new();
        let mut wanted: BTreeSet<String> = BTreeSet::new();
        for row in rows {
            let event: AnalyticsEvent = serde_json::from_str(&row?)?;
            wanted.insert(event.config_hash.clone());
            events.push(event);
        }

        let mut configs = BTreeMap::new();
        let mut config_statement = connection
            .prepare("SELECT config_json FROM analytics_config_versions WHERE config_hash = ?1")?;
        for hash in wanted {
            let json: Option<String> = config_statement
                .query_row(params![hash], |row| row.get(0))
                .optional()?;
            if let Some(json) = json {
                let config: ConfigVersion = serde_json::from_str(&json)?;
                configs.insert(config.config_hash.clone(), config);
            }
        }
        Ok((events, configs))
    }

    /// Record that an archive object was built for a day (pre-upload), so a
    /// crash between build and finalize does not lose the content identity
    /// the presigned key was minted for.
    pub fn analytics_record_archive_built(
        &mut self,
        source_epoch: Uuid,
        day: NaiveDate,
        day_revision: u64,
        revision: u64,
        content_sha256: &str,
    ) -> Result<()> {
        self.connection().execute(
            "UPDATE analytics_day_state SET
                archive_revision = ?3,
                archive_day_revision = ?4,
                archive_content_sha256 = ?5,
                archive_state = 'uploading',
                updated_at = ?6
             WHERE source_epoch = ?1 AND day = ?2",
            params![
                source_epoch.to_string(),
                day.to_string(),
                revision as i64,
                day_revision as i64,
                content_sha256,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Mark a day as permanently unarchivable: the projection can no longer
    /// produce a complete archive object for it (its configuration versions
    /// were lost before this fix, and the audit records that could re-derive
    /// them have aged out). The day stays queryable locally; it leaves the
    /// archive queue instead of failing on every pass forever.
    ///
    /// This is a recorded gap, not a silent skip — the cloud archive simply
    /// has no object for that day, which is the honest outcome.
    pub fn analytics_mark_day_unarchivable(
        &mut self,
        source_epoch: Uuid,
        day: NaiveDate,
        reason: &str,
    ) -> Result<()> {
        tracing::warn!(
            %day,
            reason,
            "analytics day cannot be archived; recording a permanent gap"
        );
        self.connection().execute(
            "UPDATE analytics_day_state SET
                archive_state = 'unarchivable',
                updated_at = ?3
             WHERE source_epoch = ?1 AND day = ?2",
            params![
                source_epoch.to_string(),
                day.to_string(),
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Adopt the archive revision the server says comes next for a day.
    ///
    /// The server sequences archive revisions strictly (`next = max + 1`) and
    /// names the expected value when it refuses one. A device whose local
    /// counter has run ahead — its manifests were removed server-side, or a
    /// restored backup carries a higher number — would otherwise re-send the
    /// same rejected revision forever. Setting the counter to `expected - 1`
    /// makes the next attempt ask for exactly what the server wants.
    pub fn analytics_adopt_archive_revision(
        &mut self,
        source_epoch: Uuid,
        day: NaiveDate,
        expected_next: u64,
    ) -> Result<()> {
        self.connection().execute(
            "UPDATE analytics_day_state SET
                archive_revision = ?3,
                archive_state = 'not_built',
                updated_at = ?4
             WHERE source_epoch = ?1 AND day = ?2",
            params![
                source_epoch.to_string(),
                day.to_string(),
                expected_next.saturating_sub(1) as i64,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Record a server archive activation. Acknowledgement is per archive
    /// revision and is NOT the same as the rollup acknowledgement: local
    /// pruning of the forensic chain must not read one as the other.
    pub fn analytics_record_archive_ack(
        &mut self,
        source_epoch: Uuid,
        day: NaiveDate,
        revision: u64,
    ) -> Result<()> {
        self.connection().execute(
            "UPDATE analytics_day_state SET
                archive_ack_revision = MAX(COALESCE(archive_ack_revision, 0), ?3),
                archive_state = 'active',
                updated_at = ?4
             WHERE source_epoch = ?1 AND day = ?2",
            params![
                source_epoch.to_string(),
                day.to_string(),
                revision as i64,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// The next archive revision for a day: one past whatever was built
    /// last, so a correction never overwrites an activated object.
    pub fn analytics_next_archive_revision(
        &self,
        source_epoch: Uuid,
        day: NaiveDate,
    ) -> Result<u64> {
        let current: Option<i64> = self
            .connection()
            .query_row(
                "SELECT archive_revision FROM analytics_day_state
                 WHERE source_epoch = ?1 AND day = ?2",
                params![source_epoch.to_string(), day.to_string()],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(current.unwrap_or(0).max(0) as u64 + 1)
    }

    /// The recorded reset reason for a source epoch, when it has one (the
    /// initial epoch does not). Best-effort: absence and read errors both
    /// read as "unknown".
    pub fn analytics_reset_reason_for(&self, source_epoch: Uuid) -> Option<String> {
        self.connection()
            .query_row(
                "SELECT reset_reason FROM analytics_source_epochs WHERE source_epoch = ?1",
                params![source_epoch.to_string()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .ok()
            .flatten()
            .flatten()
    }

    /// Heartbeat-facing summary of local projection and upload-queue state.
    pub fn analytics_sync_stats(&self) -> Result<AnalyticsSyncStats> {
        let identity = self.analytics_projection_identity()?;
        let connection = self.connection();
        let materialized_through_hash: Option<String> = connection.query_row(
            "SELECT materialized_through_hash FROM analytics_projection_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let gap_count: i64 = connection.query_row(
            "SELECT gap_count FROM analytics_projection_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let epoch = identity.source_epoch.to_string();
        let (pending_upload_days, oldest_pending_day): (i64, Option<String>) = connection
            .query_row(
                "SELECT COUNT(*), MIN(day) FROM analytics_day_state
                 WHERE source_epoch = ?1
                   AND (dirty = 1 OR snapshot_ack_revision IS NULL
                        OR snapshot_ack_revision < day_revision)",
                params![epoch],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
        let unacked_archive_days: i64 = connection.query_row(
            "SELECT COUNT(*) FROM analytics_day_state
             WHERE source_epoch = ?1 AND dirty = 0
               AND day < ?2
               AND snapshot_ack_revision IS NOT NULL
               AND snapshot_ack_revision >= day_revision
               AND archive_state <> 'unarchivable'
               AND (archive_ack_revision IS NULL OR archive_day_revision IS NULL
                    OR archive_day_revision < day_revision)",
            params![epoch, Utc::now().date_naive().to_string()],
            |row| row.get(0),
        )?;
        let unacked_security_events: i64 = connection.query_row(
            "SELECT COUNT(*) FROM analytics_security_events
             WHERE source_epoch = ?1
               AND (upload_ack_revision IS NULL OR upload_ack_revision < event_revision)",
            params![epoch],
            |row| row.get(0),
        )?;
        Ok(AnalyticsSyncStats {
            source_epoch: identity.source_epoch,
            audit_database_generation: identity.audit_database_generation,
            latest_local_event_at: latest_audit_at(connection)?,
            materialized_through_sequence: identity.materialized_through_sequence,
            materialized_through_hash,
            pending_upload_days: pending_upload_days.max(0) as u64,
            oldest_pending_day: oldest_pending_day.map(parse_day_sql).transpose()?,
            unacked_security_events: unacked_security_events.max(0) as u64,
            unacked_archive_days: unacked_archive_days.max(0) as u64,
            gap_count: gap_count.max(0) as u64,
        })
    }

    /// Detect an audit-chain re-genesis and rotate the analytics source
    /// epoch when one happened. Called from writable open.
    ///
    /// A quarantine repair or database recreation restarts the chain at
    /// sequence 1 while the projection's cursor still names a sequence from
    /// the previous generation — every new row then fails `chain_sequence >
    /// cursor` and analytics silently freezes while `analytics_covers_sequence`
    /// keeps authorizing retention against rows the projection never saw.
    /// The signals, checked in order:
    ///
    /// - the live head is BELOW the cursor (the chain got shorter);
    /// - the row AT the cursor exists with a different `record_hash` (a
    ///   different chain now occupies the same sequences);
    /// - the table is empty and the archive boundary does not account for
    ///   everything the projection materialized (rows vanished unarchived).
    ///
    /// An empty table whose archive boundary covers the cursor is legitimate
    /// retention, not a re-genesis. A pruned cursor row on a longer chain is
    /// also legitimate: generation sequences are contiguous, so a regenerated
    /// chain that reaches the cursor necessarily has a row there.
    ///
    /// Rotation starts a fresh epoch with a zero baseline so the new
    /// generation's rows (1..head) materialize into it; the prior epoch's
    /// rollups remain queryable under their closed coverage interval.
    pub fn reconcile_analytics_epoch(&mut self) -> Result<bool> {
        if self.is_read_only() {
            return Ok(false);
        }
        let identity = self.analytics_projection_identity()?;
        let cursor = identity.materialized_through_sequence;
        if cursor == 0 {
            return Ok(false);
        }
        let head: Option<i64> = self
            .connection()
            .query_row(
                "SELECT MAX(chain_sequence) FROM audit_log
                 WHERE chain_sequence IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        let (regenerated, reason) = match head {
            None => {
                let archived_through = self
                    .load_archive_boundary()?
                    .map_or(0, |boundary| boundary.last_archived_sequence.max(0) as u64);
                (
                    archived_through < cursor,
                    SourceResetReason::AuditHistoryLost,
                )
            }
            Some(head) if (head.max(0) as u64) < cursor => {
                (true, SourceResetReason::AuditDatabaseGenerationChanged)
            }
            Some(_) => {
                let at_cursor: Option<Option<String>> = self
                    .connection()
                    .query_row(
                        "SELECT record_hash FROM audit_log WHERE chain_sequence = ?1",
                        params![cursor as i64],
                        |row| row.get(0),
                    )
                    .optional()?;
                let recorded: Option<String> = self.connection().query_row(
                    "SELECT materialized_through_hash FROM analytics_projection_state
                     WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )?;
                match (at_cursor, recorded) {
                    (Some(actual), Some(recorded)) if actual.as_deref() != Some(&*recorded) => {
                        (true, SourceResetReason::AuditDatabaseGenerationChanged)
                    }
                    _ => (false, SourceResetReason::AuditDatabaseGenerationChanged),
                }
            }
        };
        if !regenerated {
            return Ok(false);
        }
        let rotated =
            self.rotate_analytics_source_epoch(reason, Uuid::new_v4(), Utc::now(), 0, None)?;
        tracing::warn!(
            event = "analytics_epoch_rotated",
            new_epoch = %rotated.source_epoch,
            previous_cursor = cursor,
            reason = ?reason,
            "audit chain re-genesis detected; analytics continues in a new source epoch"
        );
        Ok(true)
    }

    /// True only when the atomic projection cursor proves every row through
    /// the proposed raw-retention boundary was processed.
    pub fn analytics_covers_sequence(&self, sequence: i64) -> Result<bool> {
        let cursor: i64 = self.connection().query_row(
            "SELECT materialized_through_sequence FROM analytics_projection_state
             WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let dirty: i64 = self.connection().query_row(
            "SELECT COUNT(*) FROM analytics_day_state WHERE dirty = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(cursor >= sequence && dirty == 0)
    }

    /// Keep local Pro projections for exactly 90 calendar days. This never
    /// touches cold audit archives, which remain user-managed.
    pub fn prune_analytics_projection(&mut self, now: DateTime<Utc>) -> Result<usize> {
        let oldest = window(now.date_naive(), PRO_LONG_WINDOW_DAYS).start_day;
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut deleted = tx.execute(
            "DELETE FROM analytics_source_events WHERE day < ?1",
            params![oldest.to_string()],
        )?;
        for table in [
            "analytics_usage_hourly",
            "analytics_filter_daily",
            "analytics_session_day",
            "analytics_llm_daily",
            "analytics_destination_daily",
            "analytics_security_events",
            "analytics_day_state",
        ] {
            deleted = deleted.saturating_add(tx.execute(
                &format!("DELETE FROM {table} WHERE day < ?1"),
                params![oldest.to_string()],
            )?);
        }
        tx.commit()?;
        Ok(deleted)
    }

    /// True when this handle's database contains the analytics projection
    /// tables. A read-only handle over a database whose writer is an older
    /// grith has none — schema creation is a writer-only operation.
    pub fn analytics_schema_present(&self) -> Result<bool> {
        let count: i64 = self.connection().query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'analytics_projection_state'",
            [],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Explicit Free response: seven UTC dates and the exact newest twenty
    /// queue/deny events. No Pro row families are serialized.
    pub fn local_free_analytics_response(
        &self,
        now: DateTime<Utc>,
        pro_available: bool,
    ) -> Result<LocalFreeAnalyticsResponse> {
        if !self.analytics_schema_present()? {
            return Err(Error::AnalyticsUnavailable);
        }
        let selected = window(now.date_naive(), FREE_WINDOW_DAYS);
        let usage = load_rows::<grith_analytics::contract::UsageRollupRow>(
            self.connection(),
            "analytics_usage_hourly",
            selected.start_day,
            selected.end_day,
        )?;
        let mut allow = 0u64;
        let mut queue = 0u64;
        let mut deny = 0u64;
        for row in usage
            .into_iter()
            .filter(|row| row.record_class == RecordClass::Decision)
        {
            match row.verdict {
                Some(Verdict::Allow) => allow = allow.saturating_add(row.event_count),
                Some(Verdict::Queue) => queue = queue.saturating_add(row.event_count),
                Some(Verdict::Deny) => deny = deny.saturating_add(row.event_count),
                None => {}
            }
        }
        let recent = load_recent_security(self.connection(), FREE_RECENT_SECURITY_EVENTS, true)?;
        Ok(LocalFreeAnalyticsResponse {
            protocol_version: PROTOCOL_VERSION,
            schema_version: SCHEMA_VERSION,
            access: "free".into(),
            window: selected,
            decisions: VerdictCounts::from_counts(allow, queue, deny),
            chain_health: chain_health(self),
            latest_audit_record_at: latest_audit_at(self.connection())?,
            recent_queue_and_deny: recent,
            freshness: load_freshness(self.connection())?,
            pro_available,
        })
    }

    /// Approved Pro panels over the 30/90-day UTC windows. Every query is
    /// bounded by the frozen 90-day contract and reads projection tables only.
    pub fn local_pro_analytics_response(
        &self,
        now: DateTime<Utc>,
    ) -> Result<LocalProAnalyticsResponse> {
        if !self.analytics_schema_present()? {
            return Err(Error::AnalyticsUnavailable);
        }
        let short = window(now.date_naive(), PRO_SHORT_WINDOW_DAYS);
        let long = window(now.date_naive(), PRO_LONG_WINDOW_DAYS);
        let mut truncated = false;
        let mut usage_rows: Vec<grith_analytics::contract::UsageRollupRow> = load_rows(
            self.connection(),
            "analytics_usage_hourly",
            long.start_day,
            long.end_day,
        )?;
        let mut filter_rows: Vec<grith_analytics::contract::FilterRollupRow> = load_rows(
            self.connection(),
            "analytics_filter_daily",
            long.start_day,
            long.end_day,
        )?;
        let mut session_rows: Vec<grith_analytics::contract::SessionDayRow> = load_rows(
            self.connection(),
            "analytics_session_day",
            long.start_day,
            long.end_day,
        )?;
        let mut llm_rows: Vec<grith_analytics::contract::LlmRollupRow> = load_rows(
            self.connection(),
            "analytics_llm_daily",
            long.start_day,
            long.end_day,
        )?;
        let mut destination_rows: Vec<grith_analytics::contract::DestinationRollupRow> = load_rows(
            self.connection(),
            "analytics_destination_daily",
            long.start_day,
            long.end_day,
        )?;
        // The response schema caps each family; a 90-day heavy device can
        // exceed them. Clip the OLDEST rows so the recent view survives, and
        // say so — a schema-invalid payload or a silent middle slice are the
        // two failure modes this exists to prevent.
        truncated |= clip_oldest(&mut usage_rows, MAX_USAGE_ROWS, |row| {
            row.bucket_start.date_naive()
        });
        truncated |= clip_oldest(&mut filter_rows, MAX_FILTER_ROWS, |row| row.day);
        truncated |= clip_oldest(&mut session_rows, MAX_SESSION_ROWS, |row| row.day);
        truncated |= clip_oldest(&mut llm_rows, MAX_LLM_ROWS, |row| row.day);
        truncated |= clip_oldest(&mut destination_rows, MAX_DESTINATION_ROWS, |row| row.day);
        Ok(LocalProAnalyticsResponse {
            protocol_version: PROTOCOL_VERSION,
            schema_version: SCHEMA_VERSION,
            access: "pro".into(),
            generated_at: now,
            windows: vec![short, long],
            usage_rows,
            filter_rows,
            session_rows,
            llm_rows,
            destination_rows,
            security_events: load_recent_security(self.connection(), MAX_SECURITY_EVENTS, false)?,
            freshness: load_freshness(self.connection())?,
            export_formats: vec![ExportFormat::Json, ExportFormat::Csv],
            export_max_days: MAX_EXPORT_DAYS,
            truncated,
        })
    }
}

fn read_tail(conn: &Connection, cursor: i64, limit: usize) -> Result<Vec<AuditRecord>> {
    let mut statement = conn.prepare(
        "SELECT * FROM audit_log WHERE chain_sequence > ?1
         ORDER BY chain_sequence ASC LIMIT ?2",
    )?;
    let rows = statement.query_map(params![cursor, limit as i64], |row| {
        row_to_record(row).map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn read_all_active(conn: &Connection) -> Result<Vec<AuditRecord>> {
    let mut statement =
        conn.prepare("SELECT * FROM audit_log ORDER BY chain_sequence ASC, timestamp ASC, id ASC")?;
    let rows = statement.query_map([], |row| {
        row_to_record(row).map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn merge_rebuild_record(
    records: &mut BTreeMap<Uuid, AuditRecord>,
    record: AuditRecord,
) -> Result<()> {
    if let Some(existing) = records.get(&record.id) {
        // Compare as serde_json::Value: struct-level byte digests are not
        // stable because HashMap-backed fields serialize in per-instance
        // iteration order, and the interrupted-pruning safe-duplicate case
        // this function exists for would then spuriously fail the rebuild.
        if serde_json::to_value(existing)? != serde_json::to_value(&record)? {
            return Err(Error::Analytics(format!(
                "conflicting active/cold audit rows for event {}",
                record.id
            )));
        }
        return Ok(());
    }
    records.insert(record.id, record);
    Ok(())
}

/// Whether `project_records` rebuilds touched day rollups inside the same
/// transaction or only marks them dirty for a later `rebuild_dirty_days`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DayRebuild {
    /// Full rebuild passes: each day is touched once with all its events.
    Inline,
    /// Tail materialization: an inline rebuild would re-aggregate the whole
    /// current day per batch — O(day-size) work per batch on the audit writer
    /// thread, which is exactly the backpressure that drops audit records.
    Defer,
}

fn project_records(
    tx: &Transaction<'_>,
    records: &[AuditRecord],
    rebuilding: bool,
    crash_point: MaterializerCrashPoint,
    day_rebuild: DayRebuild,
) -> Result<()> {
    let generation: i64 = tx.query_row(
        "SELECT read_model_generation FROM analytics_projection_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let source_epoch: String = tx.query_row(
        "SELECT source_epoch FROM analytics_projection_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let mut touched = BTreeSet::new();
    let mut last_sequence = None;
    let mut last_hash = None;
    let mut last_at = None;
    let mut skipped: u64 = 0;
    let mut last_skip_reason: Option<String> = None;
    for record in records {
        // A record the adapter cannot express is counted and skipped, never
        // allowed to pin the cursor: a single bad row would otherwise freeze
        // analytics AND raw-audit retention forever. The raw record itself is
        // untouched — it stays in the chain and reaches cold archives.
        let event = match AuditAnalyticsAdapter::adapt(record, AdapterMode::Local) {
            Ok(event) => event,
            Err(error) => {
                skipped += 1;
                last_skip_reason = Some(format!("skipped record {}: {error}", record.id));
                tracing::warn!(
                    event = "analytics_record_skipped",
                    record_id = %record.id,
                    error = %error,
                    "audit record cannot be projected into analytics; counted as a gap"
                );
                if record.chain_sequence >= last_sequence {
                    last_sequence = record.chain_sequence;
                    last_hash.clone_from(&record.record_hash);
                    last_at = Some(record.timestamp);
                }
                continue;
            }
        };
        let event_json = serde_json::to_string(&event)?;
        let digest = hex::encode(Sha256::digest(event_json.as_bytes()));
        let day = event.occurred_at.date_naive();
        let existing: Option<String> = tx
            .query_row(
                "SELECT event_digest FROM analytics_source_events WHERE event_id = ?1",
                params![event.event_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(existing) if existing != digest => {
                return Err(Error::Analytics(format!(
                    "analytics event {} replayed with different content",
                    event.event_id
                )));
            }
            Some(_) => {}
            None => {
                tx.execute(
                    "INSERT INTO analytics_source_events (
                        event_id, source_epoch, event_digest, day, occurred_at, chain_sequence,
                        prospective_metadata, event_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        event.event_id.to_string(),
                        source_epoch,
                        digest,
                        day.to_string(),
                        event.occurred_at.to_rfc3339(),
                        event.chain_sequence.map(|value| value as i64),
                        i64::from(record.analytics_metadata.is_some()),
                        event_json,
                    ],
                )?;
                touched.insert((source_epoch.clone(), day));
            }
        }
        if let Some(metadata) = &record.analytics_metadata {
            upsert_config(tx, metadata, event.occurred_at)?;
        }
        if record.chain_sequence >= last_sequence {
            last_sequence = record.chain_sequence;
            last_hash.clone_from(&record.record_hash);
            last_at = Some(record.timestamp);
        }
    }

    if crash_point == MaterializerCrashPoint::AfterSafeEvents {
        return Err(Error::Analytics(
            "injected crash after safe-event writes".into(),
        ));
    }

    for (source_epoch, day) in touched {
        tx.execute(
            "INSERT INTO analytics_day_state (
                source_epoch, day, day_revision, read_model_generation, snapshot_state, dirty,
                source_event_count, row_checksum_sha256, updated_at
             ) VALUES (?1, ?2, 0, ?3, 'partial', 1, 0, '', ?4)
             ON CONFLICT(source_epoch, day) DO UPDATE
             SET dirty = 1, updated_at = excluded.updated_at",
            params![
                source_epoch,
                day.to_string(),
                generation,
                Utc::now().to_rfc3339()
            ],
        )?;
        if day_rebuild == DayRebuild::Inline {
            rebuild_day(tx, &source_epoch, day, generation as u64)?;
        }
    }

    if crash_point == MaterializerCrashPoint::BeforeCursor {
        return Err(Error::Analytics(
            "injected crash before cursor update".into(),
        ));
    }
    if let Some(sequence) = last_sequence {
        tx.execute(
            "UPDATE analytics_projection_state
             SET materialized_through_sequence = ?1,
                 materialized_through_hash = ?2,
                 materialized_through_at = ?3,
                 rebuilding = ?4,
                 last_error = ?6,
                 gap_count = CASE WHEN ?4 = 1 THEN ?7
                                  ELSE gap_count + ?7 END,
                 coverage_start = MIN(coverage_start, ?5)
             WHERE singleton = 1",
            params![
                sequence,
                last_hash,
                last_at.map(|value| value.to_rfc3339()),
                i64::from(rebuilding),
                records.first().map(|record| record.timestamp.to_rfc3339()),
                last_skip_reason,
                skipped as i64,
            ],
        )?;
        tx.execute(
            "UPDATE analytics_source_epochs
             SET coverage_start = MIN(coverage_start, ?1)
             WHERE active = 1",
            params![records.first().map(|record| record.timestamp.to_rfc3339())],
        )?;
    }
    Ok(())
}

fn upsert_config(
    tx: &Transaction<'_>,
    metadata: &AuditAnalyticsMetadata,
    seen_at: DateTime<Utc>,
) -> Result<()> {
    let config = ConfigVersion {
        config_hash: metadata.config.config_hash.clone(),
        profile_id: metadata.config.profile_id.clone(),
        profile_version: metadata.config.profile_version.clone(),
        policy_version: metadata.config.policy_version.clone(),
        auto_allow_threshold_micros: metadata.config.auto_allow_threshold_micros,
        auto_deny_threshold_micros: metadata.config.auto_deny_threshold_micros,
        queue_policy: metadata.config.queue_policy.clone(),
        team_default_config_version: metadata.config.team_default_config_version.clone(),
        first_seen_at: seen_at,
        last_seen_at: seen_at,
    };
    let existing: Option<String> = tx
        .query_row(
            "SELECT config_json FROM analytics_config_versions WHERE config_hash = ?1",
            params![config.config_hash],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        let existing: ConfigVersion = serde_json::from_str(&existing)?;
        let mut merged = config.clone();
        merged.first_seen_at = existing.first_seen_at.min(config.first_seen_at);
        merged.last_seen_at = existing.last_seen_at.max(config.last_seen_at);
        if existing.config_hash != config.config_hash
            || existing.profile_id != config.profile_id
            || existing.profile_version != config.profile_version
            || existing.policy_version != config.policy_version
            || existing.auto_allow_threshold_micros != config.auto_allow_threshold_micros
            || existing.auto_deny_threshold_micros != config.auto_deny_threshold_micros
            || existing.queue_policy != config.queue_policy
            || existing.team_default_config_version != config.team_default_config_version
        {
            return Err(Error::Analytics(format!(
                "config hash {} was reused for different configuration facts",
                config.config_hash
            )));
        }
        tx.execute(
            "UPDATE analytics_config_versions
             SET config_json = ?2, first_seen_at = ?3, last_seen_at = ?4
             WHERE config_hash = ?1",
            params![
                merged.config_hash,
                serde_json::to_string(&merged)?,
                merged.first_seen_at.to_rfc3339(),
                merged.last_seen_at.to_rfc3339(),
            ],
        )?;
    } else {
        tx.execute(
            "INSERT INTO analytics_config_versions (
                config_hash, config_json, first_seen_at, last_seen_at
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                config.config_hash,
                serde_json::to_string(&config)?,
                config.first_seen_at.to_rfc3339(),
                config.last_seen_at.to_rfc3339(),
            ],
        )?;
    }
    Ok(())
}

fn rebuild_day(
    tx: &Transaction<'_>,
    source_epoch: &str,
    day: NaiveDate,
    generation: u64,
) -> Result<()> {
    let mut statement = tx.prepare(
        "SELECT event_json FROM analytics_source_events
         WHERE source_epoch = ?1 AND day = ?2 ORDER BY occurred_at ASC, event_id ASC",
    )?;
    // Stream the day's events; never materialize them all at once. This used
    // to `.collect()` every `event_json` into a `Vec<String>` before parsing
    // any of them, so one rebuild's floor was the day's entire JSON — 579 MB
    // for the worst day observed on a developer machine (634,665 events), and
    // the rebuild runs on every catch-up pass, not once. Rows are consumed
    // one at a time now, so the resident cost is the accumulator alone.
    let rows = statement.query_map(params![source_epoch, day.to_string()], |row| {
        row.get::<_, String>(0)
    })?;
    let mut accumulator = DayAccumulator::new(day);
    for json in rows {
        let event: AnalyticsEvent = serde_json::from_str(&json?)?;
        accumulator
            .ingest(&event)
            .map_err(|error| Error::Analytics(error.to_string()))?;
    }
    let revision: i64 = tx.query_row(
        "SELECT day_revision + 1 FROM analytics_day_state
         WHERE source_epoch = ?1 AND day = ?2",
        params![source_epoch, day.to_string()],
        |row| row.get(0),
    )?;
    let state = if day == Utc::now().date_naive() {
        SnapshotState::Partial
    } else {
        SnapshotState::Final
    };
    let (snapshot, security_events) = accumulator
        .snapshot(revision as u64, generation, state)
        .map_err(|error| Error::Analytics(error.to_string()))?;
    replace_snapshot(tx, source_epoch, &snapshot, &security_events)?;
    Ok(())
}

fn replace_snapshot(
    tx: &Transaction<'_>,
    source_epoch: &str,
    snapshot: &DaySnapshot,
    security_events: &[SecurityEvent],
) -> Result<()> {
    let day = snapshot.day.to_string();
    replace_family(
        tx,
        "analytics_usage_hourly",
        source_epoch,
        &day,
        &snapshot.usage_rows,
    )?;
    replace_family(
        tx,
        "analytics_filter_daily",
        source_epoch,
        &day,
        &snapshot.filter_rows,
    )?;
    replace_family(
        tx,
        "analytics_session_day",
        source_epoch,
        &day,
        &snapshot.session_rows,
    )?;
    replace_family(
        tx,
        "analytics_llm_daily",
        source_epoch,
        &day,
        &snapshot.llm_rows,
    )?;
    replace_family(
        tx,
        "analytics_destination_daily",
        source_epoch,
        &day,
        &snapshot.destination_rows,
    )?;
    // Upload acknowledgements are durable per-event state, not derived rows:
    // a day rebuild replaces the event content but must not force every
    // already-acknowledged security event back into the upload queue. An ack
    // for an older revision than the rebuilt one still (correctly) reads as
    // "needs re-upload" because the ack column names the revision it covered.
    let mut acks: BTreeMap<String, Option<i64>> = BTreeMap::new();
    {
        let mut statement = tx.prepare(
            "SELECT event_id, upload_ack_revision FROM analytics_security_events
             WHERE source_epoch = ?1 AND day = ?2",
        )?;
        let rows = statement.query_map(params![source_epoch, day], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?))
        })?;
        for row in rows {
            let (event_id, ack) = row?;
            acks.insert(event_id, ack);
        }
    }
    tx.execute(
        "DELETE FROM analytics_security_events WHERE source_epoch = ?1 AND day = ?2",
        params![source_epoch, day],
    )?;
    for event in security_events {
        let event_id = event.event_id.to_string();
        let ack = acks.get(&event_id).copied().flatten();
        tx.execute(
            "INSERT INTO analytics_security_events (
                event_id, source_epoch, event_revision, day, occurred_at, initial_verdict,
                event_json, upload_ack_revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event_id,
                source_epoch,
                event.event_revision,
                day,
                event.occurred_at.to_rfc3339(),
                event.initial_verdict.map(verdict_name),
                serde_json::to_string(event)?,
                ack,
            ],
        )?;
    }
    tx.execute(
        "UPDATE analytics_day_state SET
            day_revision = ?3,
            read_model_generation = ?4,
            snapshot_state = ?5,
            dirty = 0,
            source_event_count = ?6,
            first_event_at = ?7,
            last_event_at = ?8,
            first_chain_sequence = ?9,
            last_chain_sequence = ?10,
            last_chain_hash = ?11,
            row_checksum_sha256 = ?12,
            updated_at = ?13
         WHERE source_epoch = ?1 AND day = ?2",
        params![
            source_epoch,
            day,
            snapshot.day_revision,
            snapshot.read_model_generation,
            snapshot_state_name(snapshot.state),
            snapshot.source_event_count,
            snapshot.first_event_at.map(|value| value.to_rfc3339()),
            snapshot.last_event_at.map(|value| value.to_rfc3339()),
            snapshot.first_chain_sequence,
            snapshot.last_chain_sequence,
            snapshot.last_chain_hash,
            snapshot.row_checksum_sha256,
            Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn replace_family<T: Serialize>(
    tx: &Transaction<'_>,
    table: &str,
    source_epoch: &str,
    day: &str,
    rows: &[T],
) -> Result<()> {
    tx.execute(
        &format!("DELETE FROM {table} WHERE source_epoch = ?1 AND day = ?2"),
        params![source_epoch, day],
    )?;
    for row in rows {
        let json = serde_json::to_string(row)?;
        let key = hex::encode(Sha256::digest(json.as_bytes()));
        tx.execute(
            &format!(
                "INSERT INTO {table} (source_epoch, day, row_key, row_json) VALUES (?1, ?2, ?3, ?4)"
            ),
            params![source_epoch, day, key, json],
        )?;
    }
    Ok(())
}

fn clear_projection(tx: &Transaction<'_>) -> Result<()> {
    // analytics_config_versions is deliberately NOT cleared. Its rows are
    // content-addressed and immutable, and they are re-derived only by the
    // tail materializer from audit records. A rebuild replays SOURCE EVENTS,
    // which it keeps — so clearing configs orphaned every retained day whose
    // audit rows had already aged out of the 30-day forensic window, and the
    // day archive (which must carry the effective thresholds) could never be
    // built for it again.
    for table in [
        "analytics_source_events",
        "analytics_usage_hourly",
        "analytics_filter_daily",
        "analytics_session_day",
        "analytics_llm_daily",
        "analytics_destination_daily",
        "analytics_security_events",
    ] {
        tx.execute(&format!("DELETE FROM {table}"), [])?;
    }
    // A day previously marked unarchivable gets another chance: a rebuild
    // replays audit records, which is exactly what re-derives the
    // configuration versions whose absence made it unarchivable. If they are
    // still unavailable afterwards the export marks it again.
    tx.execute(
        "UPDATE analytics_day_state SET archive_state = 'not_built'
         WHERE archive_state = 'unarchivable'",
        [],
    )?;
    // Day state survives a rebuild on purpose: day_revision must stay
    // monotonic within a source epoch (a server that accepted revision 5
    // rejects a post-rebuild revision 1 as stale forever), and the snapshot/
    // archive acknowledgement columns are durable upload state, not derived
    // rows. Marking every day dirty forces each one through rebuild_day,
    // which bumps its revision past whatever the server last accepted.
    tx.execute("UPDATE analytics_day_state SET dirty = 1", [])?;
    tx.execute(
        "UPDATE analytics_projection_state SET
            materialized_through_sequence = baseline_chain_sequence,
            materialized_through_hash = baseline_chain_hash,
            materialized_through_at = NULL",
        [],
    )?;
    Ok(())
}

/// Drop the oldest UTC days from `rows` until the family fits its response
/// cap. Whole days are dropped (set-deterministic regardless of load order);
/// only when the newest day alone exceeds the cap is that day itself clipped.
/// Returns true when anything was removed.
fn clip_oldest<T>(rows: &mut Vec<T>, cap: usize, day_of: impl Fn(&T) -> chrono::NaiveDate) -> bool {
    if rows.len() <= cap {
        return false;
    }
    let mut counts: BTreeMap<chrono::NaiveDate, usize> = BTreeMap::new();
    for row in rows.iter() {
        *counts.entry(day_of(row)).or_default() += 1;
    }
    let mut budget = cap;
    let mut keep_from: Option<chrono::NaiveDate> = None;
    for (day, count) in counts.iter().rev() {
        if *count > budget {
            break;
        }
        budget -= count;
        keep_from = Some(*day);
    }
    match keep_from {
        Some(cutoff) => rows.retain(|row| day_of(row) >= cutoff),
        None => {
            rows.sort_by_key(|row| std::cmp::Reverse(day_of(row)));
            rows.truncate(cap);
        }
    }
    true
}

fn load_rows<T: DeserializeOwned>(
    conn: &Connection,
    table: &str,
    start: NaiveDate,
    end: NaiveDate,
) -> Result<Vec<T>> {
    let mut statement = conn.prepare(&format!(
        "SELECT row_json FROM {table} WHERE day >= ?1 AND day <= ?2 ORDER BY day, row_key"
    ))?;
    let json = statement
        .query_map(params![start.to_string(), end.to_string()], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    json.into_iter()
        .map(|value| serde_json::from_str(&value).map_err(Into::into))
        .collect()
}

fn load_recent_security(
    conn: &Connection,
    limit: usize,
    queue_deny_only: bool,
) -> Result<Vec<SecurityEvent>> {
    let sql = if queue_deny_only {
        "SELECT event_json FROM analytics_security_events
         WHERE initial_verdict IN ('queue', 'deny')
         ORDER BY occurred_at DESC, event_id DESC LIMIT ?1"
    } else {
        "SELECT event_json FROM analytics_security_events
         ORDER BY occurred_at DESC, event_id DESC LIMIT ?1"
    };
    let mut statement = conn.prepare(sql)?;
    let json = statement
        .query_map(params![limit as i64], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    json.into_iter()
        .map(|value| serde_json::from_str(&value).map_err(Into::into))
        .collect()
}

fn load_freshness(conn: &Connection) -> Result<LocalFreshness> {
    conn.query_row(
        "SELECT materialized_through_at, materialized_through_sequence,
                (SELECT COUNT(*) FROM analytics_day_state WHERE dirty = 1),
                rebuilding, gap_count
         FROM analytics_projection_state WHERE singleton = 1",
        [],
        |row| {
            let at: Option<String> = row.get(0)?;
            Ok(LocalFreshness {
                materialized_through_at: at.map(parse_time_sql).transpose()?,
                materialized_through_sequence: row.get::<_, i64>(1)?.max(0) as u64,
                dirty_day_count: row.get::<_, i64>(2)?.clamp(0, u16::MAX as i64) as u16,
                rebuilding: row.get::<_, i64>(3)? != 0,
                gap_count: row.get::<_, i64>(4)?.max(0) as u64,
            })
        },
    )
    .map_err(Into::into)
}

fn latest_audit_at(conn: &Connection) -> Result<Option<DateTime<Utc>>> {
    let value: Option<String> =
        conn.query_row("SELECT MAX(timestamp) FROM audit_log", [], |row| row.get(0))?;
    value.map(parse_time).transpose()
}

fn chain_health(storage: &AuditStorage) -> ChainHealth {
    if storage.is_quarantined() {
        return ChainHealth::Quarantined;
    }
    match storage.cached_verify_chain() {
        Ok(ChainVerification::Valid { .. } | ChainVerification::Empty) => ChainHealth::Healthy,
        Ok(ChainVerification::Broken { .. } | ChainVerification::AnchorMismatch { .. }) => {
            ChainHealth::Broken
        }
        Ok(ChainVerification::Unanchored { .. }) => ChainHealth::Gap,
        Err(_) => ChainHealth::Unknown,
    }
}

fn window(today: NaiveDate, days: u32) -> UtcWindow {
    UtcWindow {
        start_day: today - Duration::days(i64::from(days.saturating_sub(1))),
        end_day: today,
        current_day_partial: true,
    }
}

fn parse_time(value: String) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| Error::Analytics(format!("invalid analytics timestamp: {error}")))
}

fn parse_time_sql(value: String) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                value.len(),
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })
}

fn parse_uuid_sql(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn parse_day_sql(value: String) -> rusqlite::Result<NaiveDate> {
    NaiveDate::parse_from_str(&value, "%Y-%m-%d").map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn parse_snapshot_state_sql(value: String) -> rusqlite::Result<SnapshotState> {
    match value.as_str() {
        "partial" => Ok(SnapshotState::Partial),
        "final" => Ok(SnapshotState::Final),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            format!("unknown snapshot state {value:?}").into(),
        )),
    }
}

fn load_family_rows<T: DeserializeOwned>(
    conn: &Connection,
    table: &str,
    source_epoch: &str,
    day: &str,
) -> Result<Vec<T>> {
    let mut statement = conn.prepare(&format!(
        "SELECT row_json FROM {table} WHERE source_epoch = ?1 AND day = ?2 ORDER BY row_key"
    ))?;
    let json = statement
        .query_map(params![source_epoch, day], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut rows = Vec::with_capacity(json.len());
    for value in json {
        rows.push(serde_json::from_str(&value)?);
    }
    Ok(rows)
}

const fn verdict_name(value: Verdict) -> &'static str {
    match value {
        Verdict::Allow => "allow",
        Verdict::Queue => "queue",
        Verdict::Deny => "deny",
    }
}

const fn snapshot_state_name(value: SnapshotState) -> &'static str {
    match value {
        SnapshotState::Partial => "partial",
        SnapshotState::Final => "final",
    }
}

const fn source_reset_reason_name(value: SourceResetReason) -> &'static str {
    match value {
        SourceResetReason::LocalProjectionLost => "local_projection_lost",
        SourceResetReason::AuditHistoryLost => "audit_history_lost",
        SourceResetReason::AuditDatabaseGenerationChanged => "audit_database_generation_changed",
        SourceResetReason::ManualReset => "manual_reset",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AuditConfigVersion, AuditDestinationMetadata, AuditLlmPricing, AuditSecurityMetadata,
        FilterResultSummary,
    };
    use std::io::Write as _;

    fn metadata(category: Category) -> AuditAnalyticsMetadata {
        AuditAnalyticsMetadata {
            metadata_version: 1,
            completeness: CompletenessTier::All,
            record_class: RecordClass::Decision,
            category,
            config: AuditConfigVersion {
                profile_id: "default".into(),
                profile_version: "1".into(),
                config_hash: hex::encode(Sha256::digest(b"config")),
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
        }
    }

    fn record(at: DateTime<Utc>, action: ProxyActionSummary) -> AuditRecord {
        let mut record = AuditRecord::new(
            Uuid::new_v4(),
            "supervisor".into(),
            "FileWrite".into(),
            &serde_json::json!({"path": "/must/not/reach/analytics"}),
            4.25,
            action,
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
        .with_analytics_metadata(metadata(Category::FileMutation));
        record.timestamp = at;
        record
    }

    #[test]
    fn adapter_is_operand_free_and_cloud_strict() {
        let record = record(Utc::now(), ProxyActionSummary::Queue);
        let event = AuditAnalyticsAdapter::adapt(&record, AdapterMode::CloudStrict).unwrap();
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("must/not/reach"));
        assert_eq!(event.category, Category::FileMutation);
        assert!(matches!(event.initial_verdict, Some(Verdict::Queue)));

        let mut missing = record;
        missing.analytics_metadata = None;
        assert!(matches!(
            AuditAnalyticsAdapter::adapt(&missing, AdapterMode::CloudStrict),
            Err(AdapterError::MissingProspectiveMetadata(_))
        ));
    }

    #[test]
    fn incremental_restart_and_crash_points_are_idempotent() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let at = Utc::now();
        storage
            .insert_batch(&[
                record(at, ProxyActionSummary::Allow),
                record(at, ProxyActionSummary::Queue),
            ])
            .unwrap();
        assert!(storage
            .materialize_analytics_tail_with_crash(
                DEFAULT_MATERIALIZER_BATCH,
                MaterializerCrashPoint::BeforeCursor,
            )
            .is_err());
        assert_eq!(
            storage
                .analytics_projection_identity()
                .unwrap()
                .materialized_through_sequence,
            0
        );
        assert_eq!(storage.catch_up_analytics().unwrap(), 2);
        assert_eq!(storage.catch_up_analytics().unwrap(), 0);
        let free = storage.local_free_analytics_response(at, true).unwrap();
        assert_eq!(free.decisions.total, 2);
        assert_eq!(free.recent_queue_and_deny.len(), 1);
    }

    #[test]
    fn late_day_rebuild_increments_revision_without_double_counting() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let today = Utc::now();
        let yesterday = today - Duration::days(1);
        storage
            .insert_record(&record(yesterday, ProxyActionSummary::Deny))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        storage
            .insert_record(&record(yesterday, ProxyActionSummary::Allow))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let revision: i64 = storage
            .connection()
            .query_row(
                "SELECT day_revision FROM analytics_day_state WHERE day = ?1",
                params![yesterday.date_naive().to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revision, 2);
        let free = storage.local_free_analytics_response(today, true).unwrap();
        assert_eq!(free.decisions.total, 2);
    }

    #[test]
    fn resolution_is_separate_from_initial_verdict() {
        let mut record = record(Utc::now(), ProxyActionSummary::Queue);
        record.analytics_metadata.as_mut().unwrap().security = Some(AuditSecurityMetadata {
            event_type: SecurityEventType::Queue,
            event_revision: 2,
            resolution_status: Some(grith_analytics::contract::ResolutionStatus::Approved),
            resolved_at: Some(Utc::now()),
            resolution_code: Some("operator-approved".into()),
            enforcement_outcome_code: Some("executed".into()),
            gap_count: None,
        });
        let event = AuditAnalyticsAdapter::adapt(&record, AdapterMode::CloudStrict).unwrap();
        let security = event.security_event.unwrap();
        assert_eq!(security.initial_verdict, Some(Verdict::Queue));
        assert_eq!(
            security.resolution.unwrap().status,
            grith_analytics::contract::ResolutionStatus::Approved
        );
    }

    #[test]
    fn adapter_validates_config_and_canonicalizes_duplicate_unknown_filters() {
        let mut record = record(Utc::now(), ProxyActionSummary::Deny);
        record.filter_results = vec![
            FilterResultSummary {
                filter_name: "secret_scan".into(),
                matched: false,
                score: 0.0,
                rule_id: "one".into(),
                severity: "notice".into(),
                message: "one".into(),
            },
            FilterResultSummary {
                filter_name: "secret_scan".into(),
                matched: true,
                score: 3.0,
                rule_id: "two".into(),
                severity: "warning".into(),
                message: "two".into(),
            },
            FilterResultSummary {
                filter_name: "Future Filter / unsafe".into(),
                matched: true,
                score: 1.0,
                rule_id: "future".into(),
                severity: "warning".into(),
                message: "future".into(),
            },
        ];
        let event = AuditAnalyticsAdapter::adapt(&record, AdapterMode::CloudStrict).unwrap();
        assert_eq!(event.evaluated_filter_ids.len(), 2);
        assert!(event.evaluated_filter_ids.contains(&"secret-scan".into()));
        assert!(event
            .evaluated_filter_ids
            .iter()
            .any(|value| value.starts_with("unknown-")));
        assert_eq!(event.positive_filter_contributions.len(), 2);

        record
            .analytics_metadata
            .as_mut()
            .unwrap()
            .config
            .config_hash = "not-a-hash".into();
        assert!(matches!(
            AuditAnalyticsAdapter::adapt(&record, AdapterMode::CloudStrict),
            Err(AdapterError::InvalidMetadata { .. })
        ));
    }

    fn write_cold(path: &Path, lines: &[String]) {
        let file = std::fs::File::create(path).unwrap();
        let mut encoder = zstd::stream::Encoder::new(file, 3).unwrap();
        for line in lines {
            writeln!(encoder, "{line}").unwrap();
        }
        encoder.finish().unwrap();
    }

    #[test]
    fn active_and_cold_rebuild_deduplicates_and_malformed_cold_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let cold = tempfile::tempdir().unwrap();
        let mut storage = AuditStorage::open(dir.path().join("audit.db")).unwrap();
        let original = record(Utc::now(), ProxyActionSummary::Allow);
        let id = original.id;
        storage.insert_record(&original).unwrap();
        let persisted = storage.get_by_id(&id).unwrap();
        write_cold(
            &cold.path().join("2026-01-01.jsonl.zst"),
            &[serde_json::to_string(&persisted).unwrap()],
        );
        assert_eq!(
            storage
                .rebuild_analytics_from_active_and_cold(cold.path())
                .unwrap(),
            1
        );
        let projected: i64 = storage
            .connection()
            .query_row("SELECT COUNT(*) FROM analytics_source_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(projected, 1);

        write_cold(
            &cold.path().join("2026-01-02.jsonl.zst"),
            &["{malformed".into()],
        );
        assert!(storage
            .rebuild_analytics_from_active_and_cold(cold.path())
            .is_err());
        let still_projected: i64 = storage
            .connection()
            .query_row("SELECT COUNT(*) FROM analytics_source_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(still_projected, 1, "failed rebuild must not clear state");
    }

    #[test]
    fn source_epoch_rotation_pins_non_overlapping_generation_boundaries() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let first = storage.analytics_projection_identity().unwrap();
        let next_start = first.coverage_start + Duration::seconds(1);
        let generation = Uuid::new_v4();
        let next = storage
            .rotate_analytics_source_epoch(
                SourceResetReason::AuditDatabaseGenerationChanged,
                generation,
                next_start,
                42,
                Some("baseline".into()),
            )
            .unwrap();
        assert_ne!(first.source_epoch, next.source_epoch);
        assert_eq!(next.audit_database_generation, generation);
        assert_eq!(next.materialized_through_sequence, 42);
        let epochs = storage.analytics_source_epochs().unwrap();
        assert_eq!(epochs.len(), 2);
        assert!(!epochs[0].active);
        assert!(epochs[1].active);
        assert!(epochs[0].coverage_end.unwrap() < epochs[1].coverage_start);
        assert!(storage
            .rotate_analytics_source_epoch(
                SourceResetReason::ManualReset,
                Uuid::new_v4(),
                next_start,
                0,
                None,
            )
            .is_err());
    }

    /// A repair/recreation that leaves the chain SHORTER than the cursor —
    /// without rotation, every new row fails `chain_sequence > cursor` and
    /// analytics silently freezes forever.
    #[test]
    fn regenerated_shorter_chain_rotates_epoch_and_analytics_continue() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        {
            let mut storage = AuditStorage::open(&path).unwrap();
            for _ in 0..3 {
                storage
                    .insert_record(&record(Utc::now(), ProxyActionSummary::Allow))
                    .unwrap();
            }
            storage.catch_up_analytics().unwrap();
            assert_eq!(
                storage
                    .analytics_projection_identity()
                    .unwrap()
                    .materialized_through_sequence,
                3
            );
            // Simulate the re-genesis: history vanishes with no archive
            // boundary to account for it (the 0.1.4 repair shape).
            storage
                .connection()
                .execute("DELETE FROM audit_log", [])
                .unwrap();
        }

        let mut storage = AuditStorage::open(&path).unwrap();
        let epochs = storage.analytics_source_epochs().unwrap();
        assert_eq!(epochs.len(), 2, "open must have rotated the epoch");
        assert!(!epochs[0].active && epochs[1].active);
        assert_eq!(
            storage
                .analytics_projection_identity()
                .unwrap()
                .materialized_through_sequence,
            0,
            "the new epoch materializes the new generation from its start"
        );

        // The new generation's rows (restarting at sequence 1) are visible.
        storage
            .insert_record(&record(Utc::now(), ProxyActionSummary::Deny))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let free = storage
            .local_free_analytics_response(Utc::now(), false)
            .unwrap();
        assert_eq!(free.decisions.deny, 1, "post-regenesis rows must project");
        // The prior generation's projections stay queryable.
        assert_eq!(free.decisions.allow, 3);
    }

    /// A regenerated chain that has already grown back PAST the old cursor:
    /// only the hash at the cursor betrays that different records now occupy
    /// the same sequences.
    #[test]
    fn regenerated_same_length_chain_rotates_on_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        {
            let mut storage = AuditStorage::open(&path).unwrap();
            for _ in 0..3 {
                storage
                    .insert_record(&record(Utc::now(), ProxyActionSummary::Allow))
                    .unwrap();
            }
            storage.catch_up_analytics().unwrap();
            storage
                .connection()
                .execute("DELETE FROM audit_log", [])
                .unwrap();
            // The new generation reuses sequences 1..=3 with different
            // records; the same-length chain hides the shrink.
            for _ in 0..3 {
                storage
                    .insert_record(&record(Utc::now(), ProxyActionSummary::Queue))
                    .unwrap();
            }
        }

        let mut storage = AuditStorage::open(&path).unwrap();
        assert_eq!(
            storage.analytics_source_epochs().unwrap().len(),
            2,
            "hash mismatch at the cursor must rotate"
        );
        storage.catch_up_analytics().unwrap();
        let free = storage
            .local_free_analytics_response(Utc::now(), false)
            .unwrap();
        assert_eq!(free.decisions.queue, 3, "new-generation rows project");
        assert_eq!(free.decisions.allow, 3, "old-epoch projections survive");
    }

    /// Retention emptying the table is NOT a re-genesis: the archive
    /// boundary accounts for everything the projection materialized.
    #[test]
    fn fully_pruned_table_with_boundary_does_not_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let cold = tempfile::tempdir().unwrap();
        {
            let mut storage = AuditStorage::open(&path).unwrap();
            for _ in 0..3 {
                storage
                    .insert_record(&record(
                        Utc::now() - Duration::days(40),
                        ProxyActionSummary::Allow,
                    ))
                    .unwrap();
            }
            let stats = crate::retention::prune_and_archive(
                &mut storage,
                Utc::now() - Duration::days(30),
                cold.path(),
                true,
                false,
            )
            .unwrap();
            assert_eq!(stats.archived_rows, 3);
            assert_eq!(storage.count().unwrap(), 0, "table is legitimately empty");
        }

        let storage = AuditStorage::open(&path).unwrap();
        assert_eq!(
            storage.analytics_source_epochs().unwrap().len(),
            1,
            "legitimate retention must not open a new epoch"
        );
    }

    #[test]
    fn unchanged_database_reopens_without_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        {
            let mut storage = AuditStorage::open(&path).unwrap();
            storage
                .insert_record(&record(Utc::now(), ProxyActionSummary::Allow))
                .unwrap();
            storage.catch_up_analytics().unwrap();
        }
        let storage = AuditStorage::open(&path).unwrap();
        assert_eq!(storage.analytics_source_epochs().unwrap().len(), 1);
        assert_eq!(
            storage
                .analytics_projection_identity()
                .unwrap()
                .materialized_through_sequence,
            1
        );
    }

    #[test]
    fn rotate_to_now_starts_prospective_coverage_at_the_chain_head() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let earlier = Utc::now() - Duration::days(3);
        storage
            .insert_record(&record(earlier, ProxyActionSummary::Queue))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let before = storage.analytics_projection_identity().unwrap();
        assert_eq!(
            storage
                .analytics_upload_pending_days(before.source_epoch, 10)
                .unwrap()
                .len(),
            1
        );

        let rotated = storage
            .analytics_rotate_epoch_to_now(SourceResetReason::ManualReset)
            .unwrap();
        assert_ne!(rotated.source_epoch, before.source_epoch);
        assert!(rotated.coverage_start > before.coverage_start);
        // Baselined at the live head: the old record never re-materializes.
        assert_eq!(rotated.baseline_chain_sequence, 1);
        assert!(rotated.baseline_chain_hash.is_some());
        // The new epoch starts with nothing pending; pre-rotation history is
        // local-only under the closed epoch.
        assert!(storage
            .analytics_upload_pending_days(rotated.source_epoch, 10)
            .unwrap()
            .is_empty());
        assert!(storage
            .analytics_unacked_security_events(rotated.source_epoch, 10)
            .unwrap()
            .is_empty());

        // A record appended after rotation lands in the new epoch.
        storage
            .insert_record(&record(Utc::now(), ProxyActionSummary::Allow))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let pending = storage
            .analytics_upload_pending_days(rotated.source_epoch, 10)
            .unwrap();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn archivable_days_require_a_sealed_accepted_day_and_track_revisions() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let today = Utc::now();
        let yesterday = today - Duration::days(1);
        storage
            .insert_record(&record(yesterday, ProxyActionSummary::Allow))
            .unwrap();
        storage
            .insert_record(&record(today, ProxyActionSummary::Queue))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let epoch = storage
            .analytics_projection_identity()
            .unwrap()
            .source_epoch;
        let day = yesterday.date_naive();

        // Not yet accepted by the server: nothing to archive.
        assert!(storage
            .analytics_archivable_days(epoch, today.date_naive(), 10)
            .unwrap()
            .is_empty());

        let pending = storage.analytics_upload_pending_days(epoch, 10).unwrap();
        let accepted = pending.iter().find(|row| row.day == day).unwrap();
        storage
            .analytics_record_day_ack(epoch, day, accepted.day_revision)
            .unwrap();

        // Accepted and sealed (today is still partial and never listed).
        let archivable = storage
            .analytics_archivable_days(epoch, today.date_naive(), 10)
            .unwrap();
        assert_eq!(archivable.len(), 1);
        assert_eq!(archivable[0].day, day);
        // The heartbeat's archive backlog tracks the same sealed days.
        assert_eq!(
            storage.analytics_sync_stats().unwrap().unacked_archive_days,
            1
        );

        assert_eq!(
            storage.analytics_next_archive_revision(epoch, day).unwrap(),
            1
        );
        storage
            .analytics_record_archive_built(epoch, day, accepted.day_revision, 1, &"a".repeat(64))
            .unwrap();
        storage.analytics_record_archive_ack(epoch, day, 1).unwrap();
        assert_eq!(
            storage.analytics_sync_stats().unwrap().unacked_archive_days,
            0
        );
        assert!(storage
            .analytics_archivable_days(epoch, today.date_naive(), 10)
            .unwrap()
            .is_empty());
        // A correction writes a higher revision, never an overwrite.
        assert_eq!(
            storage.analytics_next_archive_revision(epoch, day).unwrap(),
            2
        );

        // A late record reopens the day: it needs archiving again.
        storage
            .insert_record(&record(yesterday, ProxyActionSummary::Deny))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let reopened = storage.analytics_upload_pending_days(epoch, 10).unwrap();
        let row = reopened.iter().find(|row| row.day == day).unwrap();
        storage
            .analytics_record_day_ack(epoch, day, row.day_revision)
            .unwrap();
        let archivable = storage
            .analytics_archivable_days(epoch, today.date_naive(), 10)
            .unwrap();
        assert_eq!(archivable.len(), 1);
        assert_eq!(archivable[0].day_revision, row.day_revision);
    }

    #[test]
    fn a_rebuild_keeps_the_config_versions_its_days_still_reference() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let at = Utc::now() - Duration::days(1);
        storage
            .insert_record(&record(at, ProxyActionSummary::Allow))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let epoch = storage
            .analytics_projection_identity()
            .unwrap()
            .source_epoch;
        let before: i64 = storage
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM analytics_config_versions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(before > 0);

        // A rebuild replays SOURCE EVENTS. Audit records are pruned at 30
        // days while source events live 90, so a rebuild that cleared the
        // content-addressed config rows could never re-derive them — and the
        // day archive, which must carry the effective thresholds, could never
        // be built again.
        let cold = tempfile::tempdir().unwrap();
        storage
            .rebuild_analytics_from_active_and_cold(cold.path())
            .unwrap();
        let after: i64 = storage
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM analytics_config_versions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after, before, "configs must survive a rebuild");

        let (events, configs) = storage
            .analytics_day_export(epoch, at.date_naive())
            .unwrap();
        for event in &events {
            assert!(configs.contains_key(&event.config_hash));
        }
    }

    #[test]
    fn a_rebuild_gives_an_unarchivable_day_another_chance() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let today = Utc::now();
        let yesterday = today - Duration::days(1);
        storage
            .insert_record(&record(yesterday, ProxyActionSummary::Allow))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let epoch = storage
            .analytics_projection_identity()
            .unwrap()
            .source_epoch;
        let day = yesterday.date_naive();
        let pending = storage.analytics_upload_pending_days(epoch, 10).unwrap();
        let accepted = pending.iter().find(|row| row.day == day).unwrap();
        storage
            .analytics_record_day_ack(epoch, day, accepted.day_revision)
            .unwrap();
        storage
            .analytics_mark_day_unarchivable(epoch, day, "configs unavailable")
            .unwrap();
        assert!(storage
            .analytics_archivable_days(epoch, today.date_naive(), 10)
            .unwrap()
            .is_empty());

        // The audit records are still inside the forensic window, so a
        // rebuild re-derives the configs the export needs. The day must be
        // eligible again rather than staying permanently excluded.
        let cold = tempfile::tempdir().unwrap();
        storage
            .rebuild_analytics_from_active_and_cold(cold.path())
            .unwrap();
        let rebuilt = storage.analytics_upload_pending_days(epoch, 10).unwrap();
        let row = rebuilt.iter().find(|row| row.day == day).unwrap();
        storage
            .analytics_record_day_ack(epoch, day, row.day_revision)
            .unwrap();
        assert_eq!(
            storage
                .analytics_archivable_days(epoch, today.date_naive(), 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn an_unarchivable_day_leaves_the_queue_and_the_backlog_count() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let today = Utc::now();
        let yesterday = today - Duration::days(1);
        storage
            .insert_record(&record(yesterday, ProxyActionSummary::Allow))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let epoch = storage
            .analytics_projection_identity()
            .unwrap()
            .source_epoch;
        let day = yesterday.date_naive();
        let pending = storage.analytics_upload_pending_days(epoch, 10).unwrap();
        let accepted = pending.iter().find(|row| row.day == day).unwrap();
        storage
            .analytics_record_day_ack(epoch, day, accepted.day_revision)
            .unwrap();
        assert_eq!(
            storage
                .analytics_archivable_days(epoch, today.date_naive(), 10)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            storage.analytics_sync_stats().unwrap().unacked_archive_days,
            1
        );

        storage
            .analytics_mark_day_unarchivable(epoch, day, "configs unavailable")
            .unwrap();

        // Recorded as a permanent gap: out of the queue, out of the backlog,
        // and never retried on every pass forever.
        assert!(storage
            .analytics_archivable_days(epoch, today.date_naive(), 10)
            .unwrap()
            .is_empty());
        assert_eq!(
            storage.analytics_sync_stats().unwrap().unacked_archive_days,
            0
        );
    }

    #[test]
    fn day_export_yields_operand_free_events_with_their_configs() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let at = Utc::now();
        storage
            .insert_batch(&[
                record(at, ProxyActionSummary::Allow),
                record(at, ProxyActionSummary::Deny),
            ])
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let epoch = storage
            .analytics_projection_identity()
            .unwrap()
            .source_epoch;

        let (events, configs) = storage
            .analytics_day_export(epoch, at.date_naive())
            .unwrap();
        assert_eq!(events.len(), 2);
        assert!(!configs.is_empty());
        for event in &events {
            assert!(configs.contains_key(&event.config_hash));
        }
        // The projection never carried operands; the archive cannot either.
        let json = serde_json::to_string(&events).unwrap();
        assert!(!json.contains("must/not/reach"));

        // The writer accepts exactly this pair.
        let object = grith_analytics::archive::write_day_archive(
            &grith_analytics::archive::ArchiveIdentity {
                team_id: Uuid::from_u128(1),
                actor_user_id: "user".into(),
                device_id: Uuid::from_u128(2),
                source_epoch: epoch,
                day: at.date_naive(),
            },
            &events,
            &configs,
        )
        .unwrap();
        assert_eq!(object.row_count, 2);
        assert_eq!(object.content_sha256.len(), 64);
    }

    #[test]
    fn upload_pending_days_respect_acks_and_dirty_state() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let today = Utc::now();
        let yesterday = today - Duration::days(1);
        storage
            .insert_record(&record(yesterday, ProxyActionSummary::Allow))
            .unwrap();
        storage
            .insert_record(&record(today, ProxyActionSummary::Queue))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let epoch = storage
            .analytics_projection_identity()
            .unwrap()
            .source_epoch;

        let pending = storage.analytics_upload_pending_days(epoch, 10).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].day, yesterday.date_naive(), "oldest first");

        storage
            .analytics_record_day_ack(epoch, pending[0].day, pending[0].day_revision)
            .unwrap();
        let pending = storage.analytics_upload_pending_days(epoch, 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].day, today.date_naive());

        // A late ack for an older revision must not lower the recorded one.
        storage
            .analytics_record_day_ack(epoch, yesterday.date_naive(), 0)
            .unwrap();
        assert_eq!(
            storage
                .analytics_upload_pending_days(epoch, 10)
                .unwrap()
                .len(),
            1
        );

        // Locally dirty days are mid-rebuild and not uploadable; the rebuild
        // returns them to the queue at a higher revision.
        storage
            .connection()
            .execute(
                "UPDATE analytics_day_state SET dirty = 1 WHERE day = ?1",
                params![today.date_naive().to_string()],
            )
            .unwrap();
        assert!(storage
            .analytics_upload_pending_days(epoch, 10)
            .unwrap()
            .is_empty());
        storage.rebuild_dirty_days(8).unwrap();
        let pending = storage.analytics_upload_pending_days(epoch, 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].day, today.date_naive());
    }

    #[test]
    fn day_snapshot_reassembles_to_the_recorded_checksum() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let at = Utc::now();
        storage
            .insert_batch(&[
                record(at, ProxyActionSummary::Allow),
                record(at, ProxyActionSummary::Queue),
                record(at, ProxyActionSummary::Deny),
            ])
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let epoch = storage
            .analytics_projection_identity()
            .unwrap()
            .source_epoch;
        let day = at.date_naive();

        let snapshot = storage.analytics_build_day_snapshot(epoch, day).unwrap();
        assert_eq!(snapshot.day, day);
        assert_eq!(snapshot.source_event_count, 3);
        assert!(!snapshot.usage_rows.is_empty());
        assert!(!snapshot.filter_rows.is_empty());
        assert_eq!(
            snapshot.compute_row_checksum().unwrap(),
            snapshot.row_checksum_sha256
        );

        // A tampered stored row must fail closed, not upload silently.
        let raw: String = storage
            .connection()
            .query_row(
                "SELECT row_json FROM analytics_usage_hourly LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut row: serde_json::Value = serde_json::from_str(&raw).unwrap();
        row["event_count"] = serde_json::json!(999);
        storage
            .connection()
            .execute(
                "UPDATE analytics_usage_hourly SET row_json = ?1 WHERE row_json = ?2",
                params![serde_json::to_string(&row).unwrap(), raw],
            )
            .unwrap();
        assert!(storage.analytics_build_day_snapshot(epoch, day).is_err());
    }

    #[test]
    fn security_event_acks_gate_selection_and_rebuilds_requeue() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let at = Utc::now();
        storage
            .insert_record(&record(at, ProxyActionSummary::Queue))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let epoch = storage
            .analytics_projection_identity()
            .unwrap()
            .source_epoch;

        let events = storage
            .analytics_unacked_security_events(epoch, 500)
            .unwrap();
        assert_eq!(events.len(), 1);
        let acks: Vec<(Uuid, u32)> = events
            .iter()
            .map(|event| (event.event_id, event.event_revision))
            .collect();
        storage.analytics_record_security_acks(&acks).unwrap();
        assert!(storage
            .analytics_unacked_security_events(epoch, 500)
            .unwrap()
            .is_empty());

        // A day rebuild keeps per-event revisions stable for unchanged
        // events, so the acknowledged event stays out of the queue and only
        // the new event needs uploading.
        storage
            .insert_record(&record(at, ProxyActionSummary::Deny))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let events = storage
            .analytics_unacked_security_events(epoch, 500)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_ne!(events[0].event_id, acks[0].0);
    }

    #[test]
    fn request_seq_allocation_is_durable_and_outbox_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let epoch = Uuid::new_v4();
        let day = Utc::now().date_naive();
        {
            let mut storage = AuditStorage::open(&path).unwrap();
            assert_eq!(storage.analytics_peek_request_seq().unwrap(), 1);
            assert_eq!(storage.analytics_allocate_request_seq().unwrap(), 1);
            assert_eq!(storage.analytics_allocate_request_seq().unwrap(), 2);
            storage
                .analytics_outbox_put(2, "snapshot", epoch, Some(day), "{\"exact\":\"bytes\"}")
                .unwrap();
        }
        let mut storage = AuditStorage::open(&path).unwrap();
        assert_eq!(storage.analytics_peek_request_seq().unwrap(), 3);
        assert_eq!(storage.analytics_allocate_request_seq().unwrap(), 3);
        let entry = storage.analytics_outbox_oldest().unwrap().unwrap();
        assert_eq!(entry.request_seq, 2);
        assert_eq!(entry.kind, "snapshot");
        assert_eq!(entry.source_epoch, epoch);
        assert_eq!(entry.day, Some(day));
        assert_eq!(entry.body, "{\"exact\":\"bytes\"}");
        storage.analytics_outbox_delete(2).unwrap();
        assert!(storage.analytics_outbox_oldest().unwrap().is_none());
    }

    #[test]
    fn reconcile_server_day_forces_republish_above_server_revision() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let at = Utc::now();
        storage
            .insert_record(&record(at, ProxyActionSummary::Allow))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let epoch = storage
            .analytics_projection_identity()
            .unwrap()
            .source_epoch;
        let day = at.date_naive();

        // The server already holds revision 7 (e.g. this projection was
        // restored from a backup). Adopt it, then republish above it.
        storage
            .analytics_reconcile_server_day(epoch, day, 7)
            .unwrap();
        assert!(storage
            .analytics_upload_pending_days(epoch, 10)
            .unwrap()
            .is_empty());
        storage.rebuild_dirty_days(8).unwrap();
        let pending = storage.analytics_upload_pending_days(epoch, 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].day_revision, 8);
    }

    #[test]
    fn sync_stats_summarize_pending_upload_state() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let at = Utc::now();
        storage
            .insert_record(&record(at, ProxyActionSummary::Queue))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let stats = storage.analytics_sync_stats().unwrap();
        assert_eq!(stats.pending_upload_days, 1);
        assert_eq!(stats.oldest_pending_day, Some(at.date_naive()));
        assert_eq!(stats.unacked_security_events, 1);
        // Today is still partial, so it is not archivable and not backlog.
        assert_eq!(stats.unacked_archive_days, 0);
        assert_eq!(stats.gap_count, 0);
        assert_eq!(stats.materialized_through_sequence, 1);
        assert!(stats.latest_local_event_at.is_some());
    }

    #[test]
    fn all_rollup_families_preserve_midnight_pricing_destination_and_denominators() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let today = Utc::now().date_naive();
        let midnight = today.and_hms_opt(0, 0, 0).unwrap().and_utc();
        let session = Uuid::new_v4();

        let mut before = record(midnight - Duration::seconds(1), ProxyActionSummary::Allow);
        before.session_id = session;
        before.filter_results[0].matched = false;
        before.filter_results[0].score = 0.0;
        before.analytics_metadata.as_mut().unwrap().destination = Some(AuditDestinationMetadata {
            kind: grith_analytics::contract::DestinationKind::Domain,
            destination_hmac: "team-hmac".into(),
            hmac_key_version: 1,
            approved_display_label: None,
        });

        let mut after = record(midnight + Duration::seconds(1), ProxyActionSummary::Deny);
        after.session_id = session;
        after.analytics_metadata.as_mut().unwrap().destination = before
            .analytics_metadata
            .as_ref()
            .unwrap()
            .destination
            .clone();

        // Same plugin as the decision records: a real session's LLM usage and
        // decisions share one supervised_tool, and the frozen session_day
        // grain includes that dimension, so the LLM record must merge into
        // the same session row rather than open a parallel one.
        let mut llm = AuditRecord::new(
            session,
            "supervisor".into(),
            "LlmCompletion".into(),
            &serde_json::json!({}),
            0.0,
            ProxyActionSummary::Allow,
            Vec::new(),
            0.0,
            None,
        )
        .with_project_name(Some("project".into()))
        .with_llm_cost("openai", "gpt-test", 10, 5, 0.001_234);
        llm.timestamp = midnight + Duration::seconds(2);
        let mut llm_metadata = metadata(Category::Llm);
        llm_metadata.record_class = RecordClass::LlmUsage;
        llm_metadata.filter_set_version = None;
        llm_metadata.llm_pricing = Some(AuditLlmPricing {
            cost_micros: 1_234,
            price_source: "catalog".into(),
            pricing_version: "2026-08".into(),
        });
        llm.analytics_metadata = Some(llm_metadata);

        storage.insert_batch(&[before, after, llm]).unwrap();
        storage.catch_up_analytics().unwrap();
        let pro = storage.local_pro_analytics_response(Utc::now()).unwrap();
        assert!(!pro.usage_rows.is_empty());
        assert!(!pro.filter_rows.is_empty());
        assert_eq!(pro.session_rows.len(), 2, "session is exact per UTC day");
        let today_session = pro
            .session_rows
            .iter()
            .find(|row| row.day == today)
            .unwrap();
        assert_eq!(
            today_session.decision_count, 1,
            "the post-midnight decision lands on today's session row"
        );
        assert_eq!(today_session.deny_count, 1);
        assert_eq!(
            today_session.llm_calls, 1,
            "LLM usage merges into the SAME session row — cost panels restrict \
             session counts to llm_calls > 0 on it"
        );
        assert_eq!(today_session.cost_micros, 1_234);
        assert_eq!(pro.llm_rows.len(), 1);
        assert_eq!(pro.llm_rows[0].cost_micros, 1_234);
        assert_eq!(pro.llm_rows[0].price_source, "catalog");
        assert_eq!(pro.llm_rows[0].pricing_version, "2026-08");
        assert_eq!(pro.destination_rows.len(), 2);
        assert!(!pro.truncated);

        let filter = pro.filter_rows.iter().find(|row| row.day == today).unwrap();
        assert_eq!(filter.evaluated_events, 1);
        assert_eq!(filter.triggered_events, 1);
        assert_eq!(filter.denied_evaluated_events, 1);
        assert_eq!(filter.denied_positive_contributions, 1);
    }

    #[test]
    fn rebuild_can_lower_counts_and_removes_obsolete_score_bucket() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let at = Utc::now();
        let mut low = record(at, ProxyActionSummary::Allow);
        low.composite_score = 1.0;
        let mut obsolete = record(at, ProxyActionSummary::Deny);
        obsolete.composite_score = 12.0;
        let obsolete_id = obsolete.id;
        storage.insert_batch(&[low, obsolete]).unwrap();
        storage.catch_up_analytics().unwrap();
        assert_eq!(
            storage
                .local_free_analytics_response(at, true)
                .unwrap()
                .decisions
                .total,
            2
        );
        storage
            .connection()
            .execute(
                "DELETE FROM audit_log WHERE id = ?1",
                params![obsolete_id.to_string()],
            )
            .unwrap();
        let cold = tempfile::tempdir().unwrap();
        storage
            .rebuild_analytics_from_active_and_cold(cold.path())
            .unwrap();
        let pro = storage.local_pro_analytics_response(at).unwrap();
        let obsolete_bucket = grith_analytics::normalize::score_micros_to_bin(12_000_000);
        assert_eq!(
            pro.usage_rows
                .iter()
                .filter(|row| row.record_class == RecordClass::Decision)
                .map(|row| row.event_count)
                .sum::<u64>(),
            1
        );
        assert!(!pro
            .usage_rows
            .iter()
            .any(|row| row.score_bucket == Some(obsolete_bucket)));
    }

    #[test]
    fn raw_30_day_archive_and_projection_90_day_retention_are_independent() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let now = Utc::now();
        for age in [100, 45, 10] {
            storage
                .insert_record(&record(
                    now - Duration::days(age),
                    ProxyActionSummary::Allow,
                ))
                .unwrap();
        }
        storage.catch_up_analytics().unwrap();
        let cold = tempfile::tempdir().unwrap();
        let stats = crate::retention::prune_and_archive(
            &mut storage,
            now - Duration::days(30),
            cold.path(),
            true,
            false,
        )
        .unwrap();
        assert_eq!(stats.archived_rows, 2);
        assert_eq!(storage.count().unwrap(), 1);
        let projected_before: i64 = storage
            .connection()
            .query_row("SELECT COUNT(*) FROM analytics_source_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(projected_before, 3);
        storage.prune_analytics_projection(now).unwrap();
        let projected_after: i64 = storage
            .connection()
            .query_row("SELECT COUNT(*) FROM analytics_source_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(projected_after, 2, "45d projection survives; 100d does not");
    }

    #[test]
    fn unmaterializable_record_is_skipped_counted_and_still_archived() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let mut invalid = record(Utc::now() - Duration::days(40), ProxyActionSummary::Allow);
        invalid
            .analytics_metadata
            .as_mut()
            .unwrap()
            .config
            .config_hash = "invalid".into();
        let valid = record(Utc::now() - Duration::days(40), ProxyActionSummary::Allow);
        storage.insert_batch(&[invalid, valid]).unwrap();

        // The bad record must not pin the cursor: the good record projects,
        // the bad one becomes a counted gap with a durable reason.
        assert_eq!(storage.catch_up_analytics().unwrap(), 2);
        let projected: i64 = storage
            .connection()
            .query_row("SELECT COUNT(*) FROM analytics_source_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(projected, 1);
        let (gaps, last_error): (i64, Option<String>) = storage
            .connection()
            .query_row(
                "SELECT gap_count, last_error FROM analytics_projection_state
                 WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(gaps, 1);
        assert!(last_error.unwrap().contains("skipped record"));
        let free = storage
            .local_free_analytics_response(Utc::now(), false)
            .unwrap();
        assert_eq!(free.freshness.gap_count, 1, "the gap is user-visible");

        // Retention proceeds — the raw row is preserved in the cold archive
        // even though analytics could not express it.
        let cold = tempfile::tempdir().unwrap();
        let stats = crate::retention::prune_and_archive(
            &mut storage,
            Utc::now() - Duration::days(30),
            cold.path(),
            true,
            false,
        )
        .unwrap();
        assert_eq!(stats.archived_rows, 2);
        assert_eq!(storage.count().unwrap(), 0);
    }

    /// work/82 Phase 1 parity requirement: the projection's numbers must
    /// equal a direct raw-table aggregation over the same window and class.
    #[test]
    fn free_verdict_counts_match_raw_audit_query_parity() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let now = Utc::now();
        let mut records = Vec::new();
        for (offset_days, action) in [
            (0, ProxyActionSummary::Allow),
            (1, ProxyActionSummary::Allow),
            (2, ProxyActionSummary::Queue),
            (3, ProxyActionSummary::Deny),
            (6, ProxyActionSummary::Allow),
            (9, ProxyActionSummary::Deny), // outside the 7-date window
        ] {
            records.push(record(now - Duration::days(offset_days), action));
        }
        // A routine observation must not enter the decision denominator.
        let mut routine = record(now, ProxyActionSummary::Allow);
        routine.analytics_metadata.as_mut().unwrap().record_class = RecordClass::RoutineIo;
        routine
            .analytics_metadata
            .as_mut()
            .unwrap()
            .filter_set_version = None;
        routine.filter_results.clear();
        records.push(routine);
        storage.insert_batch(&records).unwrap();
        storage.catch_up_analytics().unwrap();

        let free = storage.local_free_analytics_response(now, false).unwrap();
        let window_start = free.window.start_day.to_string();
        let raw = |verdict: &str| -> u64 {
            storage
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM audit_log
                     WHERE proxy_action = ?1
                       AND date(timestamp) >= ?2
                       AND json_extract(analytics_metadata, '$.record_class') = 'decision'",
                    params![verdict, window_start],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap() as u64
        };
        assert_eq!(free.decisions.allow, raw("allow"));
        assert_eq!(free.decisions.queue, raw("queue"));
        assert_eq!(free.decisions.deny, raw("deny"));
        assert_eq!(
            free.decisions.total,
            raw("allow") + raw("queue") + raw("deny")
        );
        assert_eq!(free.decisions.deny, 1, "day-9 deny is outside the window");
        assert_eq!(free.decisions.total, 5, "routine records are not decisions");
    }

    #[test]
    fn legacy_llm_cost_record_projects_instead_of_wedging_the_cursor() {
        // Pre-analytics `grith run` wrote LLM cost records with no
        // prospective metadata — the exact rows every upgraded install has.
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let mut legacy = AuditRecord::new(
            Uuid::new_v4(),
            "agent".into(),
            "LlmCompletion".into(),
            &serde_json::json!({}),
            0.0,
            ProxyActionSummary::Allow,
            Vec::new(),
            0.0,
            None,
        )
        .with_llm_cost("openai", "gpt-test", 10, 5, 0.002);
        legacy.analytics_metadata = None;
        storage.insert_record(&legacy).unwrap();
        storage.catch_up_analytics().unwrap();
        let (gaps, projected): (i64, i64) = storage
            .connection()
            .query_row(
                "SELECT (SELECT gap_count FROM analytics_projection_state),
                        (SELECT COUNT(*) FROM analytics_source_events)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(gaps, 0, "a legacy cost record is data, not a gap");
        assert_eq!(projected, 1);
        let pro = storage.local_pro_analytics_response(Utc::now()).unwrap();
        assert_eq!(pro.llm_rows.len(), 1);
        assert_eq!(pro.llm_rows[0].cost_micros, 2_000);
        assert_eq!(pro.llm_rows[0].price_source, "legacy-local");

        // CloudStrict still refuses to invent pricing facts.
        assert!(matches!(
            AuditAnalyticsAdapter::adapt(&legacy, AdapterMode::CloudStrict),
            Err(AdapterError::MissingProspectiveMetadata(_))
        ));
    }

    #[test]
    fn free_recent_is_exactly_20_and_pro_window_is_bounded_to_90_dates() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let now = Utc::now();
        for offset in 0..25 {
            storage
                .insert_record(&record(
                    now - Duration::seconds(offset),
                    ProxyActionSummary::Queue,
                ))
                .unwrap();
        }
        storage
            .insert_record(&record(now - Duration::days(90), ProxyActionSummary::Allow))
            .unwrap();
        storage.catch_up_analytics().unwrap();
        let free = storage.local_free_analytics_response(now, false).unwrap();
        assert_eq!(free.recent_queue_and_deny.len(), 20);
        let free_json = serde_json::to_value(&free).unwrap();
        for pro_only in ["usage_rows", "filter_rows", "llm_rows", "export_formats"] {
            assert!(free_json.get(pro_only).is_none());
        }
        let pro = storage.local_pro_analytics_response(now).unwrap();
        let decision_total: u64 = pro
            .usage_rows
            .iter()
            .filter(|row| row.record_class == RecordClass::Decision)
            .map(|row| row.event_count)
            .sum();
        assert_eq!(decision_total, 25, "the 91st UTC date must be excluded");
        assert_eq!(
            pro.windows[1].start_day,
            now.date_naive() - Duration::days(89)
        );
    }
}
