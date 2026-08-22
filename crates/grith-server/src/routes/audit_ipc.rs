// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! IPC audit ingestion routes for daemon-owned audit storage.

use crate::ipc_auth::IpcAuth;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use grith_audit::types::AuditRecord;
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct IngestAuditRequest {
    pub record: AuditRecord,
}

#[derive(Deserialize)]
pub(crate) struct IngestAuditBatchRequest {
    pub records: Vec<AuditRecord>,
}

/// POST /api/ipc/audit/ingest
pub(crate) async fn ingest_audit(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(body): Json<IngestAuditRequest>,
) -> impl IntoResponse {
    match state.audit_storage.lock() {
        Ok(mut storage) => {
            // A read-only handle (another process owns the writer lock) can
            // never serve an ingest. Say so with a structured 503 the client
            // can distinguish from a transient insert failure, instead of the
            // raw SQLITE_READONLY 500 every attempt would otherwise produce.
            if storage.is_read_only() {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "audit_read_only",
                        "message": "this daemon cannot write audit records: \
                                    another grith process owns the audit database",
                        "remediation": "grith daemon restart",
                    })),
                )
                    .into_response();
            }
            match storage.insert_record(&body.record) {
                Ok(()) => {
                    if let Err(error) = storage.materialize_analytics_tail(
                        grith_audit::analytics::DEFAULT_MATERIALIZER_BATCH,
                    ) {
                        tracing::warn!(
                            error = %error,
                            "IPC audit committed; analytics cursor will retry"
                        );
                    }
                    StatusCode::CREATED.into_response()
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("audit insert failed: {e}"),
                )
                    .into_response(),
            }
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "audit storage lock poisoned",
        )
            .into_response(),
    }
}

/// POST /api/ipc/audit/ingest-batch
///
/// One bounded request maps to one atomic audit-chain transaction. Required
/// security records may continue to use the single-record route and retain
/// their synchronous durability semantics.
pub(crate) async fn ingest_audit_batch(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(body): Json<IngestAuditBatchRequest>,
) -> impl IntoResponse {
    if body.records.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "audit batch must contain at least one record",
        )
            .into_response();
    }
    if body.records.len() > grith_audit::analytics::MAX_AUDIT_IPC_BATCH {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "audit batch exceeds maximum of {} records",
                grith_audit::analytics::MAX_AUDIT_IPC_BATCH
            ),
        )
            .into_response();
    }
    match state.audit_storage.lock() {
        Ok(mut storage) => {
            if storage.is_read_only() {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "audit_read_only",
                        "message": "this daemon cannot write audit records: another grith process owns the audit database",
                        "remediation": "grith daemon restart",
                    })),
                )
                    .into_response();
            }
            match storage.insert_batch(&body.records) {
                Ok(()) => {
                    if let Err(error) = storage.materialize_analytics_tail(
                        grith_audit::analytics::DEFAULT_MATERIALIZER_BATCH,
                    ) {
                        tracing::warn!(
                            error = %error,
                            "IPC audit batch committed; analytics cursor will retry"
                        );
                    }
                    StatusCode::CREATED.into_response()
                }
                Err(error) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("audit batch insert failed: {error}"),
                )
                    .into_response(),
            }
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "audit storage lock poisoned",
        )
            .into_response(),
    }
}
