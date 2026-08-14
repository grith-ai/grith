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

/// POST /api/ipc/audit/ingest
pub(crate) async fn ingest_audit(
    _auth: IpcAuth,
    State(state): State<AppState>,
    Json(body): Json<IngestAuditRequest>,
) -> impl IntoResponse {
    match state.audit_storage.lock() {
        Ok(storage) => {
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
                Ok(()) => StatusCode::CREATED.into_response(),
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
