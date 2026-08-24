// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Parquet day-archive writer (work/82 Plan 5).
//!
//! Produces the cloud analytics projection object for one sealed UTC day:
//! the row-level, operand-free event projection that the archive contract
//! (`contracts/analytics-v2/parquet-schema.json`) freezes at 50 columns.
//! It is the source of truth for CLOUD analytics — the local audit chain
//! remains the source of truth for device forensics — so the column set,
//! ordering, sort order and compression are contract, not preference.
//!
//! Everything here is derived from data already accepted by the server:
//! the same operand-free [`AnalyticsEvent`] rows the snapshot upload sends,
//! plus the device identity and the configuration versions they reference.
//! The contract's `excluded_fields` (commands, paths, prompts, payloads)
//! have no representation in this module by construction.

use std::collections::BTreeMap;
use std::sync::Arc;

use arrow_array::builder::{
    FixedSizeBinaryBuilder, Int64Builder, ListBuilder, StringBuilder, StructBuilder,
    TimestampMicrosecondBuilder, UInt16Builder, UInt32Builder, UInt64Builder,
};
use arrow_array::{
    Array, ArrayRef, FixedSizeBinaryArray, Int64Array, ListArray, RecordBatch, StringArray,
    StructArray, TimestampMicrosecondArray, UInt16Array, UInt64Array,
};
use arrow_schema::{DataType, Field, Fields, Schema, TimeUnit};
use chrono::{DateTime, NaiveDate, Utc};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::contract::{
    AnalyticsEvent, Category, CompletenessTier, ConfigVersion, DestinationKind, FilterContribution,
    LlmUsageEvent, RecordClass, ResolutionStatus, SecurityEventType, Verdict,
};
use crate::limits::{MATERIALIZER_VERSION, PROTOCOL_VERSION, SCHEMA_VERSION};

/// The configuration hash the audit adapter assigns to a record carrying no
/// prospective analytics metadata — supervisor DNS-query and similar compact
/// records, which are real events with no effective configuration to
/// describe. A fixed constant, so any consumer can identify these rows:
/// threshold-drift analysis MUST filter it out, because there is no
/// configuration behind them to compare.
pub fn unknown_config_hash() -> String {
    hex::encode(Sha256::digest(b"grith-analytics-v2:unknown-config"))
}

/// The explicitly-unknown configuration used for rows carrying
/// [`unknown_config_hash`]. String fields use the contract's `<unknown>`
/// sentinel; the thresholds are zero and carry no meaning — the hash is what
/// marks them unusable, not the values.
fn unknown_config(seen_at: DateTime<Utc>) -> ConfigVersion {
    ConfigVersion {
        config_hash: unknown_config_hash(),
        profile_id: "<unknown>".into(),
        profile_version: "<unknown>".into(),
        policy_version: "<unknown>".into(),
        auto_allow_threshold_micros: 0,
        auto_deny_threshold_micros: 0,
        queue_policy: "<unknown>".into(),
        team_default_config_version: "<unknown>".into(),
        first_seen_at: seen_at,
        last_seen_at: seen_at,
    }
}

/// Row-group target from the frozen schema.
const ROW_GROUP_ROWS: usize = 65_536;
/// The archive carries the audit hash version its rows were written under.
pub const AUDIT_HASH_VERSION: u8 = 3;

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("parquet write failed: {0}")]
    Parquet(String),
    #[error("event {event_id} references configuration {config_hash}, which was not supplied")]
    MissingConfig { event_id: Uuid, config_hash: String },
    #[error("event {0} has a config hash that is not 32 bytes of hex")]
    MalformedConfigHash(Uuid),
    #[error("event {0} has a chain hash that is not 32 bytes of hex")]
    MalformedChainHash(Uuid),
    #[error("event {0} has a destination HMAC that is not 32 bytes of hex")]
    MalformedDestinationHmac(Uuid),
}

/// Identity every row in one archive object shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveIdentity {
    pub team_id: Uuid,
    pub actor_user_id: String,
    pub device_id: Uuid,
    pub source_epoch: Uuid,
    pub day: NaiveDate,
}

/// What the writer produced: the object bytes plus the manifest facts the
/// presign/finalize handshake declares. Bounds come from the rows, never
/// from the caller, so a manifest cannot claim coverage the object lacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveObject {
    pub bytes: Vec<u8>,
    pub content_sha256: String,
    pub byte_size: u64,
    pub row_count: u64,
    pub min_event_at: DateTime<Utc>,
    pub max_event_at: DateTime<Utc>,
    pub first_chain_sequence: Option<u64>,
    pub last_chain_sequence: Option<u64>,
    pub last_chain_hash: Option<String>,
}

const fn verdict_name(value: Verdict) -> &'static str {
    match value {
        Verdict::Allow => "allow",
        Verdict::Queue => "queue",
        Verdict::Deny => "deny",
    }
}

const fn completeness_name(value: CompletenessTier) -> &'static str {
    match value {
        CompletenessTier::Decisions => "decisions",
        CompletenessTier::Spawns => "spawns",
        CompletenessTier::Io => "io",
        CompletenessTier::All => "all",
    }
}

const fn record_class_name(value: RecordClass) -> &'static str {
    match value {
        RecordClass::Decision => "decision",
        RecordClass::RoutineSpawn => "routine_spawn",
        RecordClass::RoutineIo => "routine_io",
        RecordClass::Noise => "noise",
        RecordClass::LlmUsage => "llm_usage",
        RecordClass::System => "system",
    }
}

const fn category_name(value: Category) -> &'static str {
    match value {
        Category::FileRead => "file_read",
        Category::FileMutation => "file_mutation",
        Category::Process => "process",
        Category::NetworkEgress => "network_egress",
        Category::NetworkListen => "network_listen",
        Category::CrossProcess => "cross_process",
        Category::Namespace => "namespace",
        Category::Llm => "llm",
        Category::System => "system",
        Category::Other => "other",
    }
}

const fn destination_kind_name(value: DestinationKind) -> &'static str {
    match value {
        DestinationKind::Domain => "domain",
        DestinationKind::HostPort => "host_port",
        DestinationKind::UrlOrigin => "url_origin",
        DestinationKind::UnixSocketClass => "unix_socket_class",
        DestinationKind::Other => "other",
    }
}

const fn security_event_type_name(value: SecurityEventType) -> &'static str {
    match value {
        SecurityEventType::Queue => "queue",
        SecurityEventType::Deny => "deny",
        SecurityEventType::Canary => "canary",
        SecurityEventType::Gap => "gap",
    }
}

const fn resolution_status_name(value: ResolutionStatus) -> &'static str {
    match value {
        ResolutionStatus::Pending => "pending",
        ResolutionStatus::Approved => "approved",
        ResolutionStatus::Denied => "denied",
        ResolutionStatus::Expired => "expired",
        ResolutionStatus::Escalated => "escalated",
    }
}

fn contribution_fields() -> Fields {
    Fields::from(vec![
        Field::new("filter_id", DataType::Utf8, false),
        Field::new("score_micros", DataType::Int64, false),
    ])
}

/// The frozen column set, in contract order. Field order is part of the
/// schema: a reader may bind by position.
pub fn archive_schema() -> Schema {
    let ts = || DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));
    Schema::new(vec![
        Field::new("protocol_version", DataType::UInt16, false),
        Field::new("schema_version", DataType::UInt16, false),
        Field::new("materializer_version", DataType::UInt16, false),
        Field::new("event_id", DataType::FixedSizeBinary(16), false),
        Field::new("occurred_at", ts(), false),
        Field::new("team_id", DataType::FixedSizeBinary(16), false),
        Field::new("actor_user_id", DataType::Utf8, false),
        Field::new("device_id", DataType::FixedSizeBinary(16), false),
        Field::new("source_epoch", DataType::FixedSizeBinary(16), false),
        Field::new("session_id", DataType::FixedSizeBinary(16), true),
        Field::new("project", DataType::Utf8, false),
        Field::new("profile_id", DataType::Utf8, false),
        Field::new("profile_version", DataType::Utf8, false),
        Field::new("config_hash", DataType::FixedSizeBinary(32), false),
        Field::new("policy_version", DataType::Utf8, false),
        Field::new("auto_allow_threshold_micros", DataType::Int64, false),
        Field::new("auto_deny_threshold_micros", DataType::Int64, false),
        Field::new("queue_policy", DataType::Utf8, false),
        Field::new("team_default_config_version", DataType::Utf8, false),
        Field::new("supervised_tool", DataType::Utf8, false),
        Field::new("completeness", DataType::Utf8, false),
        Field::new("record_class", DataType::Utf8, false),
        Field::new("category", DataType::Utf8, false),
        Field::new("initial_verdict", DataType::Utf8, true),
        Field::new("score_micros", DataType::Int64, true),
        Field::new("filter_set_version", DataType::UInt16, true),
        Field::new(
            "evaluated_filter_ids",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, false))),
            false,
        ),
        Field::new(
            "positive_filter_contributions",
            DataType::List(Arc::new(Field::new(
                "item",
                DataType::Struct(contribution_fields()),
                false,
            ))),
            false,
        ),
        Field::new("enforcement_outcome_code", DataType::Utf8, true),
        Field::new("provider", DataType::Utf8, true),
        Field::new("model", DataType::Utf8, true),
        Field::new("prompt_tokens", DataType::UInt64, true),
        Field::new("completion_tokens", DataType::UInt64, true),
        Field::new("cost_micros", DataType::UInt64, true),
        Field::new("currency", DataType::Utf8, true),
        Field::new("price_source", DataType::Utf8, true),
        Field::new("pricing_version", DataType::Utf8, true),
        Field::new("destination_kind", DataType::Utf8, true),
        Field::new("destination_hmac", DataType::FixedSizeBinary(32), true),
        Field::new("destination_hmac_key_version", DataType::UInt16, true),
        Field::new("approved_destination_label", DataType::Utf8, true),
        Field::new("security_event_type", DataType::Utf8, true),
        Field::new("security_event_revision", DataType::UInt32, true),
        Field::new("resolution_status", DataType::Utf8, true),
        Field::new("resolved_at", ts(), true),
        Field::new("resolution_code", DataType::Utf8, true),
        Field::new("gap_count", DataType::UInt64, true),
        Field::new("chain_sequence", DataType::UInt64, true),
        Field::new("chain_hash", DataType::FixedSizeBinary(32), true),
        Field::new("audit_hash_version", DataType::UInt16, false),
    ])
}

fn hex32(
    value: &str,
    event_id: Uuid,
    what: fn(Uuid) -> ArchiveError,
) -> Result<[u8; 32], ArchiveError> {
    let bytes = hex::decode(value).map_err(|_| what(event_id))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| what(event_id))
}

/// Write one sealed day's events as a Parquet object.
///
/// `events` are sorted into the contract's frozen order
/// (`occurred_at`, then `chain_sequence` NULLS LAST, then `event_id`) so a
/// re-export of identical input is byte-identical and reuses its
/// content-addressed object key.
pub fn write_day_archive(
    identity: &ArchiveIdentity,
    events: &[AnalyticsEvent],
    configs: &BTreeMap<String, ConfigVersion>,
) -> Result<ArchiveObject, ArchiveError> {
    let mut ordered: Vec<&AnalyticsEvent> = events.iter().collect();
    ordered.sort_by(|a, b| {
        a.occurred_at
            .cmp(&b.occurred_at)
            .then_with(|| match (a.chain_sequence, b.chain_sequence) {
                (Some(left), Some(right)) => left.cmp(&right),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
            .then_with(|| a.event_id.cmp(&b.event_id))
    });

    let schema = Arc::new(archive_schema());
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::default()))
        .set_max_row_group_row_count(Some(ROW_GROUP_ROWS))
        .build();
    let mut buffer: Vec<u8> = Vec::new();
    {
        let mut writer = ArrowWriter::try_new(&mut buffer, Arc::clone(&schema), Some(properties))
            .map_err(|error| ArchiveError::Parquet(error.to_string()))?;
        for chunk in ordered.chunks(ROW_GROUP_ROWS) {
            let batch = build_batch(&schema, identity, chunk, configs)?;
            writer
                .write(&batch)
                .map_err(|error| ArchiveError::Parquet(error.to_string()))?;
        }
        writer
            .close()
            .map_err(|error| ArchiveError::Parquet(error.to_string()))?;
    }

    let min_event_at = ordered.first().map_or(
        DateTime::<Utc>::from_naive_utc_and_offset(
            identity.day.and_hms_opt(0, 0, 0).unwrap_or_default(),
            Utc,
        ),
        |event| event.occurred_at,
    );
    let max_event_at = ordered
        .last()
        .map_or(min_event_at, |event| event.occurred_at);
    let chained: Vec<&&AnalyticsEvent> = ordered
        .iter()
        .filter(|event| event.chain_sequence.is_some())
        .collect();

    Ok(ArchiveObject {
        content_sha256: hex::encode(Sha256::digest(&buffer)),
        byte_size: buffer.len() as u64,
        row_count: ordered.len() as u64,
        min_event_at,
        max_event_at,
        first_chain_sequence: chained.first().and_then(|event| event.chain_sequence),
        last_chain_sequence: chained.last().and_then(|event| event.chain_sequence),
        last_chain_hash: chained.last().and_then(|event| event.chain_hash.clone()),
        bytes: buffer,
    })
}

#[allow(clippy::too_many_lines)]
fn build_batch(
    schema: &Arc<Schema>,
    identity: &ArchiveIdentity,
    events: &[&AnalyticsEvent],
    configs: &BTreeMap<String, ConfigVersion>,
) -> Result<RecordBatch, ArchiveError> {
    let rows = events.len();
    let mut protocol = UInt16Builder::with_capacity(rows);
    let mut schema_version = UInt16Builder::with_capacity(rows);
    let mut materializer = UInt16Builder::with_capacity(rows);
    let mut event_id = FixedSizeBinaryBuilder::with_capacity(rows, 16);
    let mut occurred_at = TimestampMicrosecondBuilder::with_capacity(rows);
    let mut team_id = FixedSizeBinaryBuilder::with_capacity(rows, 16);
    let mut actor = StringBuilder::new();
    let mut device_id = FixedSizeBinaryBuilder::with_capacity(rows, 16);
    let mut source_epoch = FixedSizeBinaryBuilder::with_capacity(rows, 16);
    let mut session_id = FixedSizeBinaryBuilder::with_capacity(rows, 16);
    let mut project = StringBuilder::new();
    let mut profile_id = StringBuilder::new();
    let mut profile_version = StringBuilder::new();
    let mut config_hash = FixedSizeBinaryBuilder::with_capacity(rows, 32);
    let mut policy_version = StringBuilder::new();
    let mut auto_allow = Int64Builder::with_capacity(rows);
    let mut auto_deny = Int64Builder::with_capacity(rows);
    let mut queue_policy = StringBuilder::new();
    let mut team_default = StringBuilder::new();
    let mut supervised_tool = StringBuilder::new();
    let mut completeness = StringBuilder::new();
    let mut record_class = StringBuilder::new();
    let mut category = StringBuilder::new();
    let mut initial_verdict = StringBuilder::new();
    let mut score_micros = Int64Builder::with_capacity(rows);
    let mut filter_set_version = UInt16Builder::with_capacity(rows);
    // Item fields are non-null by contract (no null filter id, no null
    // contribution): the builders must be told, or arrow emits
    // List(nullable item) and the batch no longer matches the schema.
    let mut evaluated = ListBuilder::new(StringBuilder::new()).with_field(Arc::new(Field::new(
        "item",
        DataType::Utf8,
        false,
    )));
    let mut contributions = ListBuilder::new(StructBuilder::new(
        contribution_fields(),
        vec![
            Box::new(StringBuilder::new()),
            Box::new(Int64Builder::new()),
        ],
    ))
    .with_field(Arc::new(Field::new(
        "item",
        DataType::Struct(contribution_fields()),
        false,
    )));
    let mut enforcement = StringBuilder::new();
    let mut provider = StringBuilder::new();
    let mut model = StringBuilder::new();
    let mut prompt_tokens = UInt64Builder::with_capacity(rows);
    let mut completion_tokens = UInt64Builder::with_capacity(rows);
    let mut cost_micros = UInt64Builder::with_capacity(rows);
    let mut currency = StringBuilder::new();
    let mut price_source = StringBuilder::new();
    let mut pricing_version = StringBuilder::new();
    let mut destination_kind = StringBuilder::new();
    let mut destination_hmac = FixedSizeBinaryBuilder::with_capacity(rows, 32);
    let mut hmac_key_version = UInt16Builder::with_capacity(rows);
    let mut approved_label = StringBuilder::new();
    let mut security_type = StringBuilder::new();
    let mut security_revision = UInt32Builder::with_capacity(rows);
    let mut resolution_status = StringBuilder::new();
    let mut resolved_at = TimestampMicrosecondBuilder::with_capacity(rows);
    let mut resolution_code = StringBuilder::new();
    let mut gap_count = UInt64Builder::with_capacity(rows);
    let mut chain_sequence = UInt64Builder::with_capacity(rows);
    let mut chain_hash = FixedSizeBinaryBuilder::with_capacity(rows, 32);
    let mut audit_hash_version = UInt16Builder::with_capacity(rows);

    for event in events {
        // A missing definition is fatal EXCEPT for the one hash defined to
        // have none: the adapter mints it for records without prospective
        // metadata (supervisor DNS queries and similar), and the accepted
        // rollups already carry it as a plain dimension. Failing here would
        // make every ordinary day unarchivable and leave the archive unable
        // to reproduce the rollups it exists to rebuild.
        let sentinel;
        let config = match configs.get(&event.config_hash) {
            Some(config) => config,
            None if event.config_hash == unknown_config_hash() => {
                sentinel = unknown_config(event.occurred_at);
                &sentinel
            }
            None => {
                return Err(ArchiveError::MissingConfig {
                    event_id: event.event_id,
                    config_hash: event.config_hash.clone(),
                })
            }
        };

        protocol.append_value(PROTOCOL_VERSION);
        schema_version.append_value(SCHEMA_VERSION);
        materializer.append_value(MATERIALIZER_VERSION);
        event_id
            .append_value(event.event_id.as_bytes())
            .map_err(|error| ArchiveError::Parquet(error.to_string()))?;
        occurred_at.append_value(event.occurred_at.timestamp_micros());
        team_id
            .append_value(identity.team_id.as_bytes())
            .map_err(|error| ArchiveError::Parquet(error.to_string()))?;
        actor.append_value(&identity.actor_user_id);
        device_id
            .append_value(identity.device_id.as_bytes())
            .map_err(|error| ArchiveError::Parquet(error.to_string()))?;
        source_epoch
            .append_value(identity.source_epoch.as_bytes())
            .map_err(|error| ArchiveError::Parquet(error.to_string()))?;
        match event.session_id {
            Some(value) => session_id
                .append_value(value.as_bytes())
                .map_err(|error| ArchiveError::Parquet(error.to_string()))?,
            None => session_id.append_null(),
        }
        project.append_value(&event.project);
        profile_id.append_value(&event.profile_id);
        profile_version.append_value(&config.profile_version);
        config_hash
            .append_value(hex32(
                &event.config_hash,
                event.event_id,
                ArchiveError::MalformedConfigHash,
            )?)
            .map_err(|error| ArchiveError::Parquet(error.to_string()))?;
        policy_version.append_value(&config.policy_version);
        auto_allow.append_value(config.auto_allow_threshold_micros);
        auto_deny.append_value(config.auto_deny_threshold_micros);
        queue_policy.append_value(&config.queue_policy);
        team_default.append_value(&config.team_default_config_version);
        supervised_tool.append_value(&event.supervised_tool);
        completeness.append_value(completeness_name(event.completeness));
        record_class.append_value(record_class_name(event.record_class));
        category.append_value(category_name(event.category));
        initial_verdict.append_option(event.initial_verdict.map(verdict_name));
        score_micros.append_option(event.score_micros);
        filter_set_version.append_option(event.filter_set_version);

        for filter in &event.evaluated_filter_ids {
            evaluated.values().append_value(filter);
        }
        evaluated.append(true);

        for contribution in &event.positive_filter_contributions {
            let builder = contributions.values();
            builder
                .field_builder::<StringBuilder>(0)
                .expect("contribution filter_id builder")
                .append_value(&contribution.filter_id);
            builder
                .field_builder::<Int64Builder>(1)
                .expect("contribution score builder")
                .append_value(contribution.score_micros);
            builder.append(true);
        }
        contributions.append(true);

        let security = event.security_event.as_ref();
        enforcement
            .append_option(security.and_then(|value| value.enforcement_outcome_code.as_deref()));

        let llm = event.llm_usage.as_ref();
        provider.append_option(llm.map(|value| value.provider.as_str()));
        model.append_option(llm.map(|value| value.model.as_str()));
        prompt_tokens.append_option(llm.map(|value| value.prompt_tokens));
        completion_tokens.append_option(llm.map(|value| value.completion_tokens));
        cost_micros.append_option(llm.map(|value| value.cost_micros));
        currency.append_option(llm.map(|value| value.currency.as_str()));
        price_source.append_option(llm.map(|value| value.price_source.as_str()));
        pricing_version.append_option(llm.map(|value| value.pricing_version.as_str()));

        let destination = event.destination.as_ref();
        destination_kind.append_option(destination.map(|value| destination_kind_name(value.kind)));
        match destination {
            Some(value) => destination_hmac
                .append_value(hex32(
                    &value.destination_hmac,
                    event.event_id,
                    ArchiveError::MalformedDestinationHmac,
                )?)
                .map_err(|error| ArchiveError::Parquet(error.to_string()))?,
            None => destination_hmac.append_null(),
        }
        hmac_key_version.append_option(destination.map(|value| value.hmac_key_version));
        approved_label
            .append_option(destination.and_then(|value| value.approved_display_label.as_deref()));

        security_type
            .append_option(security.map(|value| security_event_type_name(value.event_type)));
        security_revision.append_option(security.map(|value| value.event_revision));
        let resolution = security.and_then(|value| value.resolution.as_ref());
        resolution_status
            .append_option(resolution.map(|value| resolution_status_name(value.status)));
        resolved_at.append_option(
            resolution.and_then(|value| value.resolved_at.map(|at| at.timestamp_micros())),
        );
        resolution_code
            .append_option(resolution.and_then(|value| value.resolution_code.as_deref()));
        gap_count.append_option(security.and_then(|value| value.gap_count));

        chain_sequence.append_option(event.chain_sequence);
        match event.chain_hash.as_deref() {
            Some(value) => chain_hash
                .append_value(hex32(
                    value,
                    event.event_id,
                    ArchiveError::MalformedChainHash,
                )?)
                .map_err(|error| ArchiveError::Parquet(error.to_string()))?,
            None => chain_hash.append_null(),
        }
        audit_hash_version.append_value(u16::from(AUDIT_HASH_VERSION));
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(protocol.finish()),
        Arc::new(schema_version.finish()),
        Arc::new(materializer.finish()),
        Arc::new(event_id.finish()),
        Arc::new(occurred_at.finish().with_timezone("UTC")),
        Arc::new(team_id.finish()),
        Arc::new(actor.finish()),
        Arc::new(device_id.finish()),
        Arc::new(source_epoch.finish()),
        Arc::new(session_id.finish()),
        Arc::new(project.finish()),
        Arc::new(profile_id.finish()),
        Arc::new(profile_version.finish()),
        Arc::new(config_hash.finish()),
        Arc::new(policy_version.finish()),
        Arc::new(auto_allow.finish()),
        Arc::new(auto_deny.finish()),
        Arc::new(queue_policy.finish()),
        Arc::new(team_default.finish()),
        Arc::new(supervised_tool.finish()),
        Arc::new(completeness.finish()),
        Arc::new(record_class.finish()),
        Arc::new(category.finish()),
        Arc::new(initial_verdict.finish()),
        Arc::new(score_micros.finish()),
        Arc::new(filter_set_version.finish()),
        Arc::new(evaluated.finish()),
        Arc::new(contributions.finish()),
        Arc::new(enforcement.finish()),
        Arc::new(provider.finish()),
        Arc::new(model.finish()),
        Arc::new(prompt_tokens.finish()),
        Arc::new(completion_tokens.finish()),
        Arc::new(cost_micros.finish()),
        Arc::new(currency.finish()),
        Arc::new(price_source.finish()),
        Arc::new(pricing_version.finish()),
        Arc::new(destination_kind.finish()),
        Arc::new(destination_hmac.finish()),
        Arc::new(hmac_key_version.finish()),
        Arc::new(approved_label.finish()),
        Arc::new(security_type.finish()),
        Arc::new(security_revision.finish()),
        Arc::new(resolution_status.finish()),
        Arc::new(resolved_at.finish().with_timezone("UTC")),
        Arc::new(resolution_code.finish()),
        Arc::new(gap_count.finish()),
        Arc::new(chain_sequence.finish()),
        Arc::new(chain_hash.finish()),
        Arc::new(audit_hash_version.finish()),
    ];

    RecordBatch::try_new(Arc::clone(schema), columns)
        .map_err(|error| ArchiveError::Parquet(error.to_string()))
}

/// The content-addressed object key. Immutable per (identity, revision,
/// content): a retry of identical content reuses it; a correction writes a
/// higher revision rather than overwriting.
pub fn object_key(identity: &ArchiveIdentity, revision: u64, content_sha256: &str) -> String {
    format!(
        "team={}/device={}/epoch={}/day={}/revision={}/{}.parquet",
        identity.team_id,
        identity.device_id,
        identity.source_epoch,
        identity.day,
        revision,
        content_sha256
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        DestinationEvent, FilterContribution, LlmUsageEvent, SecurityEvent, SecurityResolutionWire,
    };
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use parquet::file::reader::{FileReader, SerializedFileReader};

    fn identity() -> ArchiveIdentity {
        ArchiveIdentity {
            team_id: Uuid::from_u128(1),
            actor_user_id: "user-a".into(),
            device_id: Uuid::from_u128(2),
            source_epoch: Uuid::from_u128(3),
            day: NaiveDate::from_ymd_opt(2026, 8, 22).unwrap(),
        }
    }

    fn config() -> (String, BTreeMap<String, ConfigVersion>) {
        let hash = "a".repeat(64);
        let mut configs = BTreeMap::new();
        configs.insert(
            hash.clone(),
            ConfigVersion {
                config_hash: hash.clone(),
                profile_id: "default".into(),
                profile_version: "1".into(),
                policy_version: "1".into(),
                auto_allow_threshold_micros: 3_000_000,
                auto_deny_threshold_micros: 8_000_000,
                queue_policy: "review".into(),
                team_default_config_version: "1".into(),
                first_seen_at: Utc::now(),
                last_seen_at: Utc::now(),
            },
        );
        (hash, configs)
    }

    fn event(hash: &str, at: DateTime<Utc>, sequence: Option<u64>) -> AnalyticsEvent {
        AnalyticsEvent {
            event_id: Uuid::new_v4(),
            occurred_at: at,
            session_id: Some(Uuid::from_u128(9)),
            project: "proj".into(),
            profile_id: "default".into(),
            config_hash: hash.to_string(),
            supervised_tool: "claude-code".into(),
            completeness: CompletenessTier::Spawns,
            record_class: RecordClass::Decision,
            category: Category::FileRead,
            initial_verdict: Some(Verdict::Allow),
            score_micros: Some(1_250_000),
            filter_set_version: Some(1),
            evaluated_filter_ids: vec!["secret-scan".into(), "path-policy".into()],
            positive_filter_contributions: vec![FilterContribution {
                filter_id: "secret-scan".into(),
                score_micros: 1_250_000,
            }],
            llm_usage: None,
            destination: None,
            security_event: None,
            chain_sequence: sequence,
            chain_hash: sequence.map(|_| "b".repeat(64)),
        }
    }

    #[test]
    fn schema_matches_the_frozen_column_contract() {
        let frozen: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/analytics-v2/parquet-schema.json"
        ))
        .unwrap();
        let expected: Vec<String> = frozen["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field["name"].as_str().unwrap().to_string())
            .collect();
        let actual: Vec<String> = archive_schema()
            .fields()
            .iter()
            .map(|field| field.name().clone())
            .collect();
        assert_eq!(actual, expected, "column set and order are contract");
    }

    #[test]
    fn day_archive_round_trips_and_is_deterministic() {
        let (hash, configs) = config();
        let base = DateTime::parse_from_rfc3339("2026-08-22T09:00:00.000000Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut llm = event(&hash, base + chrono::Duration::seconds(2), Some(8));
        llm.record_class = RecordClass::LlmUsage;
        llm.category = Category::Llm;
        llm.initial_verdict = None;
        llm.score_micros = None;
        llm.filter_set_version = None;
        llm.evaluated_filter_ids.clear();
        llm.positive_filter_contributions.clear();
        llm.llm_usage = Some(LlmUsageEvent {
            provider: "anthropic".into(),
            model: "claude-x".into(),
            prompt_tokens: 100,
            completion_tokens: 50,
            cost_micros: 12_345,
            currency: "USD".into(),
            price_source: "live".into(),
            pricing_version: "1".into(),
        });
        let mut denied = event(&hash, base + chrono::Duration::seconds(1), Some(7));
        denied.initial_verdict = Some(Verdict::Deny);
        denied.destination = Some(DestinationEvent {
            kind: DestinationKind::Domain,
            destination_hmac: "c".repeat(64),
            hmac_key_version: 1,
            approved_display_label: Some("example.com".into()),
        });
        denied.security_event = Some(SecurityEvent {
            event_id: denied.event_id,
            event_revision: 1,
            occurred_at: denied.occurred_at,
            event_type: SecurityEventType::Deny,
            initial_verdict: Some(Verdict::Deny),
            resolution: Some(SecurityResolutionWire {
                status: ResolutionStatus::Denied,
                resolved_at: Some(denied.occurred_at),
                resolution_code: Some("auto-deny".into()),
            }),
            session_id: denied.session_id,
            project: denied.project.clone(),
            profile_id: denied.profile_id.clone(),
            supervised_tool: denied.supervised_tool.clone(),
            category: denied.category,
            score_micros: Some(9_500_000),
            top_filter_ids: vec!["secret-scan".into()],
            enforcement_outcome_code: Some("eperm".into()),
            gap_count: None,
            chain_sequence: denied.chain_sequence,
            chain_hash: denied.chain_hash.clone(),
        });
        // Deliberately out of contract order on the way in.
        let events = vec![llm, event(&hash, base, Some(6)), denied];

        let object = write_day_archive(&identity(), &events, &configs).unwrap();
        assert_eq!(object.row_count, 3);
        assert_eq!(object.min_event_at, base);
        assert_eq!(object.first_chain_sequence, Some(6));
        assert_eq!(object.last_chain_sequence, Some(8));
        assert_eq!(object.byte_size, object.bytes.len() as u64);

        // Same input, same bytes: a retry reuses the content-addressed key.
        let again = write_day_archive(&identity(), &events, &configs).unwrap();
        assert_eq!(again.content_sha256, object.content_sha256);
        assert_eq!(
            object_key(&identity(), 1, &object.content_sha256),
            format!(
                "team={}/device={}/epoch={}/day=2026-08-22/revision=1/{}.parquet",
                Uuid::from_u128(1),
                Uuid::from_u128(2),
                Uuid::from_u128(3),
                object.content_sha256
            )
        );

        // The object is real Parquet: read it back and check row order and
        // the nested columns survived.
        let bytes = bytes::Bytes::from(object.bytes.clone());
        let reader = SerializedFileReader::new(bytes.clone()).unwrap();
        assert_eq!(reader.metadata().file_metadata().num_rows(), 3);
        let mut batches = ParquetRecordBatchReaderBuilder::try_new(bytes)
            .unwrap()
            .build()
            .unwrap();
        let batch = batches.next().unwrap().unwrap();
        assert_eq!(batch.num_columns(), 50);
        let sequences = batch
            .column_by_name("chain_sequence")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow_array::UInt64Array>()
            .unwrap();
        assert_eq!(
            (0..3).map(|i| sequences.value(i)).collect::<Vec<_>>(),
            vec![6, 7, 8],
            "rows are written in the frozen sort order"
        );
        let evaluated = batch
            .column_by_name("evaluated_filter_ids")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow_array::ListArray>()
            .unwrap();
        assert_eq!(evaluated.value_length(0), 2);
    }

    #[test]
    fn the_unknown_config_sentinel_is_archivable_but_marked() {
        let (_hash, configs) = config();
        // A record with no prospective metadata: the adapter gives it the
        // sentinel hash, and no configuration row exists for it anywhere.
        let mut compact = event(&unknown_config_hash(), Utc::now(), Some(3));
        compact.record_class = RecordClass::RoutineIo;
        compact.category = Category::NetworkEgress;
        assert!(!configs.contains_key(&unknown_config_hash()));

        let object = write_day_archive(&identity(), &[compact], &configs).unwrap();
        assert_eq!(object.row_count, 1, "an ordinary day must stay archivable");

        let bytes = bytes::Bytes::from(object.bytes);
        let batch = ParquetRecordBatchReaderBuilder::try_new(bytes)
            .unwrap()
            .build()
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let profile_version = batch
            .column_by_name("profile_version")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow_array::StringArray>()
            .unwrap();
        // Explicitly unknown, never fabricated as a real configuration.
        assert_eq!(profile_version.value(0), "<unknown>");
        let hash = batch
            .column_by_name("config_hash")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow_array::FixedSizeBinaryArray>()
            .unwrap();
        assert_eq!(
            hex::encode(hash.value(0)),
            unknown_config_hash(),
            "the sentinel hash identifies these rows for exclusion"
        );
    }

    #[test]
    fn a_rebuilt_day_reproduces_the_original_rollup_checksum() {
        use crate::accumulator::DayAccumulator;
        use crate::contract::SnapshotState;

        let (hash, configs) = config();
        let base = DateTime::parse_from_rfc3339("2026-08-22T09:00:00.000000Z")
            .unwrap()
            .with_timezone(&Utc);
        let day = base.date_naive();

        // A day with the shapes that actually vary: several verdicts, an LLM
        // usage row, a compact record on the unknown-config sentinel, and a
        // scoreless event.
        let mut events = vec![
            event(&hash, base, Some(10)),
            event(&hash, base + chrono::Duration::seconds(5), Some(11)),
            event(
                &unknown_config_hash(),
                base + chrono::Duration::seconds(7),
                Some(12),
            ),
        ];
        // The accumulator requires a canonical (sorted) evaluated-filter set;
        // the edge always produces one.
        for event in &mut events {
            event.evaluated_filter_ids.sort();
        }
        events[1].initial_verdict = Some(Verdict::Deny);
        events[1].score_micros = Some(9_500_000);
        events[2].record_class = RecordClass::RoutineIo;
        events[2].category = Category::NetworkEgress;
        events[2].initial_verdict = None;
        events[2].score_micros = None;
        events[2].filter_set_version = None;
        events[2].evaluated_filter_ids.clear();
        events[2].positive_filter_contributions.clear();

        let mut llm = event(&hash, base + chrono::Duration::seconds(9), Some(13));
        llm.record_class = RecordClass::LlmUsage;
        llm.category = Category::Llm;
        llm.initial_verdict = None;
        llm.score_micros = None;
        llm.filter_set_version = None;
        llm.evaluated_filter_ids.clear();
        llm.positive_filter_contributions.clear();
        llm.llm_usage = Some(LlmUsageEvent {
            provider: "anthropic".into(),
            model: "claude-x".into(),
            prompt_tokens: 100,
            completion_tokens: 50,
            cost_micros: 12_345,
            currency: "USD".into(),
            price_source: "live".into(),
            pricing_version: "1".into(),
        });
        events.push(llm);

        // What the edge computed and the server accepted.
        let mut original = DayAccumulator::new(day);
        for event in &events {
            original.ingest(event).unwrap();
        }
        let (original_snapshot, _) = original.snapshot(1, 1, SnapshotState::Final).unwrap();

        // Round-trip through a real archive object.
        let object = write_day_archive(&identity(), &events, &configs).unwrap();
        let recovered = read_day_archive(&object.bytes).unwrap();
        assert_eq!(recovered.len(), events.len());

        // Replay through the SAME accumulator — this is the whole point: a
        // rebuild is computed by identical code, not a second implementation.
        let mut rebuilt = DayAccumulator::new(day);
        for event in &recovered {
            rebuilt.ingest(event).unwrap();
        }
        let (rebuilt_snapshot, _) = rebuilt.snapshot(1, 1, SnapshotState::Final).unwrap();

        assert_eq!(
            rebuilt_snapshot.row_checksum_sha256, original_snapshot.row_checksum_sha256,
            "a rebuild from the archive must reproduce the accepted rollup checksum"
        );
        assert_eq!(
            rebuilt_snapshot.source_event_count,
            original_snapshot.source_event_count
        );
        assert_eq!(rebuilt_snapshot.usage_rows, original_snapshot.usage_rows);
        assert_eq!(rebuilt_snapshot.llm_rows, original_snapshot.llm_rows);
        assert_eq!(rebuilt_snapshot.filter_rows, original_snapshot.filter_rows);
        assert_eq!(
            rebuilt_snapshot.session_rows,
            original_snapshot.session_rows
        );
    }

    #[test]
    fn archive_identity_round_trips() {
        let (hash, configs) = config();
        let at = Utc::now();
        let object =
            write_day_archive(&identity(), &[event(&hash, at, Some(1))], &configs).unwrap();
        let recovered = read_archive_identity(&object.bytes, identity().day)
            .unwrap()
            .unwrap();
        assert_eq!(recovered, identity());
    }

    #[test]
    fn an_event_referencing_an_unknown_config_fails_closed() {
        let (hash, configs) = config();
        let mut orphan = event(&hash, Utc::now(), None);
        orphan.config_hash = "d".repeat(64);
        let error = write_day_archive(&identity(), &[orphan], &configs).unwrap_err();
        assert!(matches!(error, ArchiveError::MissingConfig { .. }));
    }

    #[test]
    fn excluded_content_has_no_column_to_land_in() {
        let frozen: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/analytics-v2/parquet-schema.json"
        ))
        .unwrap();
        let columns: Vec<String> = archive_schema()
            .fields()
            .iter()
            .map(|field| field.name().clone())
            .collect();
        for excluded in frozen["excluded_fields"].as_array().unwrap() {
            let name = excluded.as_str().unwrap();
            assert!(!columns.iter().any(|column| column == name), "{name}");
        }
    }
}

// ---------------------------------------------------------------------------
// Reading an archive back
// ---------------------------------------------------------------------------

/// Recover the analytics events from an archive object.
///
/// This is the read side of the archive contract: the cloud rebuild replays
/// these rows through the SAME [`crate::accumulator::DayAccumulator`] the edge
/// used, so a rebuilt day is computed by identical code rather than by a
/// second implementation that could drift.
///
/// Only the fields the accumulator consumes are recovered. Identity columns
/// (team, actor, device, source epoch) are properties of the object, not of
/// individual events, and are returned separately by [`read_archive_identity`].
pub fn read_day_archive(bytes: &[u8]) -> Result<Vec<AnalyticsEvent>, ArchiveError> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::copy_from_slice(bytes))
        .map_err(|error| ArchiveError::Parquet(error.to_string()))?
        .build()
        .map_err(|error| ArchiveError::Parquet(error.to_string()))?;

    let mut events = Vec::new();
    for batch in reader {
        let batch = batch.map_err(|error| ArchiveError::Parquet(error.to_string()))?;
        let columns = ArchiveColumns::bind(&batch)?;
        for row in 0..batch.num_rows() {
            events.push(columns.event(row)?);
        }
    }
    Ok(events)
}

/// The identity every row in an archive object shares, recovered from its
/// first row. Returns `None` for an empty object.
pub fn read_archive_identity(
    bytes: &[u8],
    day: NaiveDate,
) -> Result<Option<ArchiveIdentity>, ArchiveError> {
    let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::copy_from_slice(bytes))
        .map_err(|error| ArchiveError::Parquet(error.to_string()))?
        .build()
        .map_err(|error| ArchiveError::Parquet(error.to_string()))?;
    let Some(batch) = reader.next() else {
        return Ok(None);
    };
    let batch = batch.map_err(|error| ArchiveError::Parquet(error.to_string()))?;
    if batch.num_rows() == 0 {
        return Ok(None);
    }
    let columns = ArchiveColumns::bind(&batch)?;
    Ok(Some(ArchiveIdentity {
        team_id: columns.uuid_at(columns.team_id, 0)?,
        actor_user_id: columns.actor.value(0).to_string(),
        device_id: columns.uuid_at(columns.device_id, 0)?,
        source_epoch: columns.uuid_at(columns.source_epoch, 0)?,
        day,
    }))
}

/// Column handles bound once per record batch, by NAME rather than position,
/// so a reader keeps working if a future schema version appends columns.
struct ArchiveColumns<'a> {
    event_id: &'a FixedSizeBinaryArray,
    occurred_at: &'a TimestampMicrosecondArray,
    team_id: &'a FixedSizeBinaryArray,
    actor: &'a StringArray,
    device_id: &'a FixedSizeBinaryArray,
    source_epoch: &'a FixedSizeBinaryArray,
    session_id: &'a FixedSizeBinaryArray,
    project: &'a StringArray,
    profile_id: &'a StringArray,
    config_hash: &'a FixedSizeBinaryArray,
    supervised_tool: &'a StringArray,
    completeness: &'a StringArray,
    record_class: &'a StringArray,
    category: &'a StringArray,
    initial_verdict: &'a StringArray,
    score_micros: &'a Int64Array,
    filter_set_version: &'a UInt16Array,
    evaluated: &'a ListArray,
    contributions: &'a ListArray,
    provider: &'a StringArray,
    model: &'a StringArray,
    prompt_tokens: &'a UInt64Array,
    completion_tokens: &'a UInt64Array,
    cost_micros: &'a UInt64Array,
    currency: &'a StringArray,
    price_source: &'a StringArray,
    pricing_version: &'a StringArray,
    chain_sequence: &'a UInt64Array,
    chain_hash: &'a FixedSizeBinaryArray,
}

impl<'a> ArchiveColumns<'a> {
    fn bind(batch: &'a RecordBatch) -> Result<Self, ArchiveError> {
        fn col<'b, T: 'static>(batch: &'b RecordBatch, name: &str) -> Result<&'b T, ArchiveError> {
            batch
                .column_by_name(name)
                .and_then(|column| column.as_any().downcast_ref::<T>())
                .ok_or_else(|| {
                    ArchiveError::Parquet(format!(
                        "archive column {name} is missing or has an unexpected type"
                    ))
                })
        }
        Ok(Self {
            event_id: col(batch, "event_id")?,
            occurred_at: col(batch, "occurred_at")?,
            team_id: col(batch, "team_id")?,
            actor: col(batch, "actor_user_id")?,
            device_id: col(batch, "device_id")?,
            source_epoch: col(batch, "source_epoch")?,
            session_id: col(batch, "session_id")?,
            project: col(batch, "project")?,
            profile_id: col(batch, "profile_id")?,
            config_hash: col(batch, "config_hash")?,
            supervised_tool: col(batch, "supervised_tool")?,
            completeness: col(batch, "completeness")?,
            record_class: col(batch, "record_class")?,
            category: col(batch, "category")?,
            initial_verdict: col(batch, "initial_verdict")?,
            score_micros: col(batch, "score_micros")?,
            filter_set_version: col(batch, "filter_set_version")?,
            evaluated: col(batch, "evaluated_filter_ids")?,
            contributions: col(batch, "positive_filter_contributions")?,
            provider: col(batch, "provider")?,
            model: col(batch, "model")?,
            prompt_tokens: col(batch, "prompt_tokens")?,
            completion_tokens: col(batch, "completion_tokens")?,
            cost_micros: col(batch, "cost_micros")?,
            currency: col(batch, "currency")?,
            price_source: col(batch, "price_source")?,
            pricing_version: col(batch, "pricing_version")?,
            chain_sequence: col(batch, "chain_sequence")?,
            chain_hash: col(batch, "chain_hash")?,
        })
    }

    fn uuid_at(&self, array: &FixedSizeBinaryArray, row: usize) -> Result<Uuid, ArchiveError> {
        let bytes: [u8; 16] = array
            .value(row)
            .try_into()
            .map_err(|_| ArchiveError::Parquet("uuid column is not 16 bytes".into()))?;
        Ok(Uuid::from_bytes(bytes))
    }

    fn opt_str(array: &StringArray, row: usize) -> Option<String> {
        (!array.is_null(row)).then(|| array.value(row).to_string())
    }

    fn event(&self, row: usize) -> Result<AnalyticsEvent, ArchiveError> {
        let occurred_at = DateTime::from_timestamp_micros(self.occurred_at.value(row))
            .ok_or_else(|| ArchiveError::Parquet("occurred_at is out of range".into()))?;

        let evaluated_filter_ids = match self.evaluated.is_null(row) {
            true => Vec::new(),
            false => {
                let values = self.evaluated.value(row);
                let strings = values
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .ok_or_else(|| {
                        ArchiveError::Parquet("evaluated_filter_ids is not a string list".into())
                    })?;
                (0..strings.len())
                    .map(|i| strings.value(i).to_string())
                    .collect()
            }
        };

        let positive_filter_contributions = match self.contributions.is_null(row) {
            true => Vec::new(),
            false => {
                let values = self.contributions.value(row);
                let entries = values
                    .as_any()
                    .downcast_ref::<StructArray>()
                    .ok_or_else(|| {
                        ArchiveError::Parquet("filter contributions are not structs".into())
                    })?;
                let ids = entries
                    .column_by_name("filter_id")
                    .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                    .ok_or_else(|| {
                        ArchiveError::Parquet("contribution filter_id is missing".into())
                    })?;
                let scores = entries
                    .column_by_name("score_micros")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .ok_or_else(|| {
                        ArchiveError::Parquet("contribution score_micros is missing".into())
                    })?;
                (0..entries.len())
                    .map(|i| FilterContribution {
                        filter_id: ids.value(i).to_string(),
                        score_micros: scores.value(i),
                    })
                    .collect()
            }
        };

        let llm_usage = (!self.provider.is_null(row)).then(|| LlmUsageEvent {
            provider: self.provider.value(row).to_string(),
            model: self.model.value(row).to_string(),
            prompt_tokens: self.prompt_tokens.value(row),
            completion_tokens: self.completion_tokens.value(row),
            cost_micros: self.cost_micros.value(row),
            currency: self.currency.value(row).to_string(),
            price_source: self.price_source.value(row).to_string(),
            pricing_version: self.pricing_version.value(row).to_string(),
        });

        Ok(AnalyticsEvent {
            event_id: self.uuid_at(self.event_id, row)?,
            occurred_at,
            session_id: (!self.session_id.is_null(row))
                .then(|| self.uuid_at(self.session_id, row))
                .transpose()?,
            project: self.project.value(row).to_string(),
            profile_id: self.profile_id.value(row).to_string(),
            config_hash: hex::encode(self.config_hash.value(row)),
            supervised_tool: self.supervised_tool.value(row).to_string(),
            completeness: parse_completeness(self.completeness.value(row))?,
            record_class: parse_record_class(self.record_class.value(row))?,
            category: parse_category(self.category.value(row))?,
            initial_verdict: Self::opt_str(self.initial_verdict, row)
                .map(|value| parse_verdict(&value))
                .transpose()?,
            score_micros: (!self.score_micros.is_null(row)).then(|| self.score_micros.value(row)),
            filter_set_version: (!self.filter_set_version.is_null(row))
                .then(|| self.filter_set_version.value(row)),
            evaluated_filter_ids,
            positive_filter_contributions,
            llm_usage,
            // Destination and security metadata are carried by the archive but
            // are not accumulator inputs: the accumulator derives destination
            // and security rows from the same columns during replay, so they
            // are recovered by the rebuild's own mapping rather than here.
            destination: None,
            security_event: None,
            chain_sequence: (!self.chain_sequence.is_null(row))
                .then(|| self.chain_sequence.value(row)),
            chain_hash: (!self.chain_hash.is_null(row))
                .then(|| hex::encode(self.chain_hash.value(row))),
        })
    }
}

fn parse_completeness(value: &str) -> Result<CompletenessTier, ArchiveError> {
    match value {
        "decisions" => Ok(CompletenessTier::Decisions),
        "spawns" => Ok(CompletenessTier::Spawns),
        "io" => Ok(CompletenessTier::Io),
        "all" => Ok(CompletenessTier::All),
        other => Err(ArchiveError::Parquet(format!(
            "unknown completeness {other:?}"
        ))),
    }
}

fn parse_record_class(value: &str) -> Result<RecordClass, ArchiveError> {
    match value {
        "decision" => Ok(RecordClass::Decision),
        "routine_spawn" => Ok(RecordClass::RoutineSpawn),
        "routine_io" => Ok(RecordClass::RoutineIo),
        "noise" => Ok(RecordClass::Noise),
        "llm_usage" => Ok(RecordClass::LlmUsage),
        "system" => Ok(RecordClass::System),
        other => Err(ArchiveError::Parquet(format!(
            "unknown record class {other:?}"
        ))),
    }
}

fn parse_category(value: &str) -> Result<Category, ArchiveError> {
    match value {
        "file_read" => Ok(Category::FileRead),
        "file_mutation" => Ok(Category::FileMutation),
        "process" => Ok(Category::Process),
        "network_egress" => Ok(Category::NetworkEgress),
        "network_listen" => Ok(Category::NetworkListen),
        "cross_process" => Ok(Category::CrossProcess),
        "namespace" => Ok(Category::Namespace),
        "llm" => Ok(Category::Llm),
        "system" => Ok(Category::System),
        "other" => Ok(Category::Other),
        other => Err(ArchiveError::Parquet(format!("unknown category {other:?}"))),
    }
}

fn parse_verdict(value: &str) -> Result<Verdict, ArchiveError> {
    match value {
        "allow" => Ok(Verdict::Allow),
        "queue" => Ok(Verdict::Queue),
        "deny" => Ok(Verdict::Deny),
        other => Err(ArchiveError::Parquet(format!("unknown verdict {other:?}"))),
    }
}
