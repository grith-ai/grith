// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Audit log REST endpoints.

use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use super::{
    api_error, default_limit, parse_uuid_or_400, DEFAULT_EXPORT_LIMIT, EXFIL_STATS_RECENT_COUNT,
    MAX_PAGE_LIMIT, TOP_DESTINATIONS_LIMIT,
};

#[allow(clippy::result_large_err)]
fn enforce_chain_integrity(
    storage: &grith_audit::AuditStorage,
) -> Result<(), axum::response::Response> {
    match storage.cached_verify_chain() {
        Ok(grith_audit::ChainVerification::Valid { .. } | grith_audit::ChainVerification::Empty) => {
            Ok(())
        }
        Ok(grith_audit::ChainVerification::Broken {
            at_sequence,
            record_id,
            reason,
        }) => Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "audit chain verification failed at sequence {at_sequence} for record {record_id}: {reason}"
            ),
            "AUDIT_CHAIN_BROKEN",
        )
        .into_response()),
        // work/74 Phase 6: a genuine discontinuity between archived and active
        // history. Distinct code from BROKEN so operators can tell "the two
        // segments don't join" apart from "a record was altered".
        Ok(grith_audit::ChainVerification::AnchorMismatch {
            boundary_sequence,
            expected_prev_hash,
            found_prev_hash,
            first_sequence,
        }) => Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "audit archive boundary at sequence {boundary_sequence} expects prev_hash \
                 {expected_prev_hash} but active segment starts at {first_sequence} with \
                 {found_prev_hash:?}"
            ),
            "AUDIT_CHAIN_ANCHOR_MISMATCH",
        )
        .into_response()),
        // work/74 §9: the anchor is missing, not the data. The daemon recovers
        // this at startup from cold storage; if a read arrives first, report it
        // as unavailable rather than as tampering — and never repair here.
        Ok(grith_audit::ChainVerification::Unanchored { first_sequence }) => Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "audit chain is unanchored: active segment starts at sequence {first_sequence} \
                 with no archive boundary. Records are intact; run `grith audit diagnose`."
            ),
            "AUDIT_CHAIN_UNANCHORED",
        )
        .into_response()),
        Err(e) => Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("audit chain verification failed: {e}"),
            "AUDIT_CHAIN_ERROR",
        )
        .into_response()),
    }
}

#[derive(Deserialize)]
pub(super) struct AuditQueryParams {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    session_id: Option<String>,
    /// `full` (default) — only proxy-decision rows. `all` — include
    /// compact short-circuit rows. Anything else falls back to `full`.
    #[serde(default)]
    include: Option<String>,
}

impl AuditQueryParams {
    fn include_compact(&self) -> bool {
        matches!(self.include.as_deref(), Some("all"))
    }
}

pub(crate) async fn list_audit(
    State(state): State<AppState>,
    Query(params): Query<AuditQueryParams>,
) -> impl IntoResponse {
    let storage = state.audit_storage.lock().map_err(|e| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("lock poisoned: {e}"),
            "LOCK_ERROR",
        )
        .into_response()
    });
    let storage = match storage {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_chain_integrity(&storage) {
        return resp;
    }
    if let Some(ref session_str) = params.session_id {
        let uuid = match parse_uuid_or_400(session_str) {
            Ok(u) => u,
            Err(resp) => return resp,
        };
        match storage.get_by_session(&uuid) {
            Ok(records) => {
                let total = records.len();
                Json(serde_json::json!({
                    "records": records,
                    "total": total,
                }))
                .into_response()
            }
            Err(e) => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                e.to_string(),
                "AUDIT_ERROR",
            )
            .into_response(),
        }
    } else {
        let effective_limit = params.limit.min(MAX_PAGE_LIMIT);
        let include_compact = params.include_compact();
        let result = if params.offset == 0 {
            storage.get_recent_filtered(effective_limit, include_compact)
        } else {
            storage.get_page_filtered(params.offset, effective_limit, include_compact)
        };
        match result {
            Ok(records) => {
                let total = storage.count_filtered(include_compact).unwrap_or(0);
                Json(serde_json::json!({
                    "records": records,
                    "total": total,
                    "limit": effective_limit,
                    "offset": params.offset,
                    "include": if include_compact { "all" } else { "full" },
                }))
                .into_response()
            }
            Err(e) => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                e.to_string(),
                "AUDIT_ERROR",
            )
            .into_response(),
        }
    }
}

#[derive(Deserialize)]
pub(super) struct ExportParams {
    #[serde(default = "default_format")]
    format: String,
    #[serde(default = "default_export_limit")]
    limit: usize,
    /// When true, also read cold-storage archives from `<audit_dir>/cold/`
    /// and merge their rows with the active-DB results. Default false to
    /// keep the hot path cheap.
    #[serde(default)]
    include_cold: bool,
    /// Optional `YYYY-MM-DD` date filter. When set with `include_cold`,
    /// only archive files whose date is >= `from_date` are read. Active-DB
    /// records are not filtered by date here (callers can post-filter
    /// the response).
    #[serde(default)]
    from_date: Option<String>,
}

fn default_format() -> String {
    "json".into()
}

fn default_export_limit() -> usize {
    DEFAULT_EXPORT_LIMIT
}

pub(crate) async fn export_audit(
    State(state): State<AppState>,
    Query(params): Query<ExportParams>,
) -> impl IntoResponse {
    let storage = match state.audit_storage.lock().map_err(|e| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("lock poisoned: {e}"),
            "LOCK_ERROR",
        )
        .into_response()
    }) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_chain_integrity(&storage) {
        return resp;
    }
    let mut records = match storage.get_recent(params.limit) {
        Ok(r) => r,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{e}"),
                "AUDIT_ERROR",
            )
            .into_response();
        }
    };

    // Cold-archive stitching. Defaults off so the hot Export button
    // continues to be cheap; opt-in via `?include_cold=true`.
    if params.include_cold {
        let cold_dir = state
            .audit_db_path
            .parent()
            .map(|p| p.join("cold"))
            .unwrap_or_else(|| std::path::PathBuf::from("cold"));
        let from_date = params.from_date.as_deref();
        let mut cold_rows: Vec<_> = grith_audit::retention::list_archive_files(&cold_dir)
            .into_iter()
            .filter(|p| {
                from_date.is_none_or(|fd| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .and_then(|n| n.strip_suffix(".jsonl.zst"))
                        .is_some_and(|date| date >= fd)
                })
            })
            .filter_map(|p| grith_audit::retention::read_zstd_jsonl(&p).ok())
            .flatten()
            .collect();
        records.append(&mut cold_rows);
        // Newest-first ordering for response consistency with active-DB
        // get_recent. Tie-break by id to keep the order deterministic.
        records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp).then_with(|| b.id.cmp(&a.id)));
    }

    match params.format.as_str() {
        "csv" => {
            let mut csv_bytes = Vec::new();
            if let Err(e) = grith_audit::export::export_csv(&records, &mut csv_bytes) {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to export CSV: {e}"),
                    "AUDIT_EXPORT_ERROR",
                )
                .into_response();
            }
            let csv = match String::from_utf8(csv_bytes) {
                Ok(data) => data,
                Err(e) => {
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to encode CSV output as UTF-8: {e}"),
                        "AUDIT_EXPORT_ENCODING_ERROR",
                    )
                    .into_response();
                }
            };
            (
                StatusCode::OK,
                [("content-type", "text/csv; charset=utf-8")],
                csv,
            )
                .into_response()
        }
        _ => Json(serde_json::json!({
            "records": records,
            "count": records.len(),
        }))
        .into_response(),
    }
}

/// Aggregate exfiltration attempt stats from recent audit records.
pub(crate) async fn exfil_stats(State(state): State<AppState>) -> impl IntoResponse {
    let storage = match state.audit_storage.lock().map_err(|e| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("lock poisoned: {e}"),
            "LOCK_ERROR",
        )
        .into_response()
    }) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_chain_integrity(&storage) {
        return resp;
    }
    let records = match storage.get_recent(EXFIL_STATS_RECENT_COUNT) {
        Ok(r) => r,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{e}"),
                "AUDIT_ERROR",
            )
            .into_response();
        }
    };

    // Aggregate blocked/queued records by protocol and destination.
    let mut by_protocol: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut by_destination: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();
    let mut total_blocked: u64 = 0;
    let mut total_queued: u64 = 0;
    let mut total_redacted: u64 = 0;

    for record in &records {
        let is_blocked = record.proxy_action == grith_audit::ProxyActionSummary::Deny;
        let is_queued = record.proxy_action == grith_audit::ProxyActionSummary::Queue;

        if !is_blocked && !is_queued {
            continue;
        }

        // Check for exfil-related filter hits.
        let has_exfil = record.filter_results.iter().any(|fr| {
            fr.matched
                && (fr.filter_name.contains("egress")
                    || fr.filter_name.contains("dlp")
                    || fr.filter_name.contains("canary")
                    || fr.filter_name.contains("containment"))
        });

        if !has_exfil {
            continue;
        }

        if is_blocked {
            total_blocked += 1;
        }
        if is_queued {
            total_queued += 1;
        }

        // Check for DLP redaction.
        let has_dlp = record
            .filter_results
            .iter()
            .any(|fr| fr.matched && fr.filter_name.contains("dlp"));
        if has_dlp {
            total_redacted += 1;
        }

        // Classify protocol from tool_call_type.
        let protocol = match record.tool_call_type.as_str() {
            "HttpRequest" => "http",
            "NetConnect" => "network",
            "ProcessSpawn" | "ShellExec" => "shell-transport",
            _ => "other",
        };
        *by_protocol.entry(protocol.to_string()).or_default() += 1;

        // Extract destination from arguments summary (best-effort).
        if record.arguments_summary.contains("://") {
            if let Some(start) = record.arguments_summary.find("://") {
                let after = &record.arguments_summary[start + 3..];
                let end = after.find(['/', ':', ' ', '"']).unwrap_or(after.len());
                let domain = &after[..end];
                if !domain.is_empty() && domain.len() < 256 {
                    *by_destination.entry(domain.to_string()).or_default() += 1;
                }
            }
        }
    }

    // Sort destinations by count (descending), take top N.
    let mut dest_vec: Vec<(String, u64)> = by_destination.into_iter().collect();
    dest_vec.sort_by_key(|b| std::cmp::Reverse(b.1));
    dest_vec.truncate(TOP_DESTINATIONS_LIMIT);
    let top_destinations: Vec<serde_json::Value> = dest_vec
        .into_iter()
        .map(|(domain, count)| serde_json::json!({"domain": domain, "count": count}))
        .collect();

    Json(serde_json::json!({
        "total_blocked": total_blocked,
        "total_queued": total_queued,
        "total_redacted": total_redacted,
        "by_protocol": by_protocol,
        "top_blocked_destinations": top_destinations,
    }))
    .into_response()
}

pub(crate) async fn get_audit(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match parse_uuid_or_400(&id) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let storage = match state.audit_storage.lock().map_err(|e| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("lock poisoned: {e}"),
            "LOCK_ERROR",
        )
        .into_response()
    }) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_chain_integrity(&storage) {
        return resp;
    }

    let result = storage.get_by_id(&uuid).map_err(|e| e.to_string());

    match result {
        Ok(record) => Json(record).into_response(),
        Err(e) => api_error(StatusCode::NOT_FOUND, e, "NOT_FOUND").into_response(),
    }
}
