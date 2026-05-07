// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Shared SQLite row-to-record deserialization used by storage and query modules.

use crate::types::{AuditRecord, FilterResultSummary, ProxyActionSummary};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

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
    let filter_results_json: String = row.get("filter_results")?;

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

    let filter_scores_json: Option<String> = row.get("filter_scores")?;
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
        arguments_summary: row.get("arguments_summary")?,
        arguments_hash: row.get("arguments_hash")?,
        composite_score: row.get("composite_score")?,
        proxy_action,
        filter_results,
        filter_scores,
        execution_result: row.get("execution_result")?,
        evaluation_time_ms: row.get("evaluation_time_ms")?,
        task_context: row.get("task_context")?,
        source: row.get("source")?,
        supervised_tool: row.get("supervised_tool")?,
        supervised_pid: row.get("supervised_pid")?,
        correlation_id,
        record_hash: row.get("record_hash")?,
        prev_hash: row.get("prev_hash")?,
        chain_sequence: row.get("chain_sequence")?,
        llm_provider: row.get("llm_provider")?,
        llm_model: row.get("llm_model")?,
        prompt_tokens: prompt_tokens.map(|v| v as usize),
        completion_tokens: completion_tokens.map(|v| v as usize),
        estimated_cost_usd: row.get("estimated_cost_usd")?,
    })
}
