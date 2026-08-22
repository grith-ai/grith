// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Shared SQLite row-to-record deserialization used by storage and query modules.

use crate::types::{
    AuditAnalyticsMetadata, AuditRecord, FilterResultSummary, ProxyActionSummary, RecordType,
};
use chrono::{DateTime, Utc};
use rusqlite::types::ValueRef;
use std::collections::HashMap;
use uuid::Uuid;

/// Read a column whose stored form may be either TEXT (legacy plaintext)
/// or BLOB (zstd-compressed payload written post-Stage 3). rusqlite's
/// `Vec<u8>` extractor only accepts BLOB cells; this helper reads the
/// underlying bytes for either type so the downstream decompressor can
/// run unchanged.
fn read_text_or_blob(
    row: &rusqlite::Row,
    name: &str,
) -> std::result::Result<Vec<u8>, crate::error::Error> {
    match row.get_ref(name)? {
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => Ok(bytes.to_vec()),
        ValueRef::Null => Err(crate::error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("audit column {name} was unexpectedly NULL"),
        ))),
        other => Err(crate::error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("audit column {name} had unexpected type {other:?}"),
        ))),
    }
}

fn read_text_or_blob_opt(
    row: &rusqlite::Row,
    name: &str,
) -> std::result::Result<Option<Vec<u8>>, crate::error::Error> {
    match row.get_ref(name)? {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => Ok(Some(bytes.to_vec())),
        other => Err(crate::error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("audit column {name} had unexpected type {other:?}"),
        ))),
    }
}

/// Parse a SQLite row into an [`AuditRecord`].
///
/// This is the single canonical implementation used by both [`crate::storage`]
/// and [`crate::query`] to avoid duplicated deserialization logic.
///
/// Returns `crate::error::Error` so both database and serialization errors
/// are propagated instead of panicking on schema mismatches.
pub(crate) fn row_to_record(
    row: &rusqlite::Row,
) -> std::result::Result<AuditRecord, crate::error::Error> {
    // CR-5: Replace all get_unwrap calls with safe get() that return errors.
    let id_str: String = row.get("id")?;
    let timestamp_str: String = row.get("timestamp")?;
    let session_str: String = row.get("session_id")?;
    // Stage 3: the three big JSON columns are read via TEXT-or-BLOB
    // because legacy rows wrote them as TEXT and post-Stage-3 rows write
    // them as BLOB (zstd magic prefix). `decompress_string` sniffs the
    // magic and falls back to UTF-8 for plaintext.
    let filter_results_blob = read_text_or_blob(row, "filter_results")?;
    let filter_results_json = crate::compression::decompress_string(&filter_results_blob)?;

    let proxy_action_str: String = row.get("proxy_action")?;
    let proxy_action = match proxy_action_str.as_str() {
        "allow" => ProxyActionSummary::Allow,
        "queue" => ProxyActionSummary::Queue,
        "deny" => ProxyActionSummary::Deny,
        other => {
            // H-9: Log a warning when an unknown action is encountered.
            tracing::warn!(
                action = other,
                "unknown proxy_action string, defaulting to Allow"
            );
            ProxyActionSummary::Allow
        }
    };

    let filter_results: Vec<FilterResultSummary> = serde_json::from_str(&filter_results_json)?;

    let filter_scores_blob = read_text_or_blob_opt(row, "filter_scores")?;
    let filter_scores_json = filter_scores_blob
        .as_deref()
        .map(crate::compression::decompress_string)
        .transpose()?;
    let filter_scores: Option<HashMap<String, f64>> = filter_scores_json
        .map(|json| serde_json::from_str(&json))
        .transpose()?;

    // L-9: Log warnings when UUID parse fails instead of silently returning nil.
    let id = Uuid::parse_str(&id_str).unwrap_or_else(|e| {
        tracing::warn!(error = %e, value = %id_str, "failed to parse audit record id as UUID, using nil");
        Uuid::default()
    });
    let session_id = Uuid::parse_str(&session_str).unwrap_or_else(|e| {
        tracing::warn!(error = %e, value = %session_str, "failed to parse session_id as UUID, using nil");
        Uuid::default()
    });

    let correlation_id_opt: Option<String> = row.get("correlation_id")?;
    let correlation_id = correlation_id_opt.and_then(|s| {
        Uuid::parse_str(&s)
            .map_err(|e| {
                tracing::warn!(error = %e, value = %s, "failed to parse correlation_id as UUID, ignoring");
                e
            })
            .ok()
    });

    let prompt_tokens: Option<i64> = row.get("prompt_tokens")?;
    let completion_tokens: Option<i64> = row.get("completion_tokens")?;

    Ok(AuditRecord {
        id,
        timestamp: DateTime::parse_from_rfc3339(&timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        session_id,
        plugin_id: row.get("plugin_id")?,
        tool_call_type: row.get("tool_call_type")?,
        arguments_summary: {
            let blob = read_text_or_blob(row, "arguments_summary")?;
            crate::compression::decompress_string(&blob)?
        },
        arguments_hash: row.get("arguments_hash")?,
        composite_score: row.get("composite_score")?,
        proxy_action,
        decision_reason: row
            .get::<_, Option<String>>("decision_reason")
            .ok()
            .flatten(),
        enforcement_outcome: row
            .get::<_, Option<String>>("enforcement_outcome")
            .ok()
            .flatten(),
        filter_results,
        filter_scores,
        execution_result: row.get("execution_result")?,
        evaluation_time_ms: row.get("evaluation_time_ms")?,
        task_context: row.get("task_context")?,
        source: row.get("source")?,
        supervised_tool: row.get("supervised_tool")?,
        supervised_pid: row.get("supervised_pid")?,
        // `try_get` so a record loaded from a pre-migration snapshot (no
        // column) round-trips with None instead of erroring.
        project_name: row.get::<_, Option<String>>("project_name").ok().flatten(),
        correlation_id,
        record_hash: row.get("record_hash")?,
        prev_hash: row.get("prev_hash")?,
        chain_sequence: row.get("chain_sequence")?,
        llm_provider: row.get("llm_provider")?,
        llm_model: row.get("llm_model")?,
        prompt_tokens: prompt_tokens.map(|v| v as usize),
        completion_tokens: completion_tokens.map(|v| v as usize),
        estimated_cost_usd: row.get("estimated_cost_usd")?,
        // PR 4 Phase F: routine-spawn forensic fields. `try_get` so a
        // record loaded from a pre-Phase-F snapshot (no columns) still
        // round-trips with None instead of erroring.
        spawn_sha256: row.get::<_, Option<String>>("spawn_sha256").ok().flatten(),
        matched_routine_root: row
            .get::<_, Option<String>>("matched_routine_root")
            .ok()
            .flatten(),
        shadow_phase3_filters: row
            .get::<_, Option<String>>("shadow_phase3_filters")
            .ok()
            .flatten(),
        // PR 5 Phase E: listener-rewrite forensic fields. Same
        // try_get pattern as the Phase F fields above so pre-Phase-E
        // snapshots round-trip with None.
        original_addr: row.get::<_, Option<String>>("original_addr").ok().flatten(),
        rewritten_addr: row
            .get::<_, Option<String>>("rewritten_addr")
            .ok()
            .flatten(),
        clamp_profile_entry: row
            .get::<_, Option<String>>("clamp_profile_entry")
            .ok()
            .flatten(),
        // Compact-record classification. Older rows without the column
        // round-trip as `Full` thanks to `RecordType::default()`.
        record_type: row
            .get::<_, Option<String>>("record_type")
            .ok()
            .flatten()
            .map(|s| RecordType::from_str_lenient(&s))
            .unwrap_or_default(),
        // B12 item 5. A missing column or a NULL value both mean the row
        // predates hash versioning, so its hash was produced by the legacy
        // canonical form and must be verified with it.
        hash_version: row
            .get::<_, Option<i64>>("hash_version")
            .ok()
            .flatten()
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(crate::types::LEGACY_HASH_VERSION),
        analytics_metadata: row
            .get::<_, Option<String>>("analytics_metadata")
            .ok()
            .flatten()
            .map(|json| serde_json::from_str::<AuditAnalyticsMetadata>(&json))
            .transpose()?,
    })
}
