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
    match storage.verify_chain() {
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
    session_id: Option<String>,
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
        match storage.get_recent(effective_limit) {
            Ok(records) => {
                let total = storage.count().unwrap_or(0);
                Json(serde_json::json!({
                    "records": records,
                    "total": total,
                    "limit": effective_limit,
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
    let records = match storage.get_recent(params.limit) {
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
