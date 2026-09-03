// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Usage analytics endpoints (Pro feature).
//!
//! Provides summary, cost, and compliance analytics computed from the local
//! audit database. All endpoints are gated behind the `usage_analytics`
//! feature (Pro+).

use super::api_error;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

macro_rules! lock_audit {
    ($state:expr) => {
        match $state.audit_storage.lock() {
            Ok(s) => s,
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to acquire audit storage lock",
                    "INTERNAL_ERROR",
                )
                .into_response();
            }
        }
    };
}

// --- Analytics v2 explicit tier contracts ---

/// GET /api/analytics/v2/free
///
/// Free is a first-class server response, not a client-side mask over Pro.
/// Per-request catch-up bounds: enough to stay fresh in steady state, small
/// enough that a first read over a large backlog cannot hold the storage
/// mutex for minutes (the daemon's background worker drains the rest; the
/// freshness block reports any remaining lag honestly).
const CATCH_UP_MAX_BATCHES: usize = 4;
const CATCH_UP_MAX_DAYS: usize = 8;

fn analytics_error_response(error: &grith_audit::Error, surface: &str) -> axum::response::Response {
    if matches!(error, grith_audit::Error::AnalyticsUnavailable) {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "{surface} analytics is unavailable: the process that owns the audit database \
                 is an older grith version. Restart it to enable analytics: grith daemon restart"
            ),
            "ANALYTICS_UNAVAILABLE",
        )
        .into_response();
    }
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("failed to read {surface} analytics: {error}"),
        "INTERNAL_ERROR",
    )
    .into_response()
}

/// Bring the projection up to date before an analytics read, and hand back
/// any heap the rebuild freed.
///
/// A day rebuild allocates one small object per event in the day and frees
/// them all; glibc keeps those on the arena's free list, so a read that
/// rebuilds a busy day permanently raises the resident size of whichever
/// tokio worker served it. With one arena per worker thread that ratchet
/// multiplies across the pool — the shape behind a daemon found holding
/// 9.8 GB against a 150 MB target. Trimming only when a day was actually
/// rebuilt keeps it off the common path, where reads rebuild nothing.
fn catch_up_before_read(storage: &mut grith_audit::AuditStorage, surface: &str) {
    if storage.is_read_only() {
        return;
    }
    match storage.catch_up_analytics_bounded(CATCH_UP_MAX_BATCHES, CATCH_UP_MAX_DAYS) {
        Ok((_, days)) if days > 0 => grith_audit::release_free_heap(),
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(error = %error, surface, "analytics v2 catch-up failed before read");
        }
    }
}

pub(crate) async fn analytics_v2_free(State(state): State<AppState>) -> impl IntoResponse {
    let pro_available = state
        .feature_gate
        .read()
        .map(|gate| gate.allows("usage_analytics"))
        .unwrap_or(false);
    let mut storage = lock_audit!(state);
    catch_up_before_read(&mut storage, "Free");
    match storage.local_free_analytics_response(chrono::Utc::now(), pro_available) {
        Ok(response) => Json(response).into_response(),
        Err(error) => analytics_error_response(&error, "Free"),
    }
}

/// GET /api/analytics/v2/pro
///
/// The feature check happens before storage access, so Free clients cannot
/// receive richer rows for a browser to hide later.
pub(crate) async fn analytics_v2_pro(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(response) = super::require_feature(&state, "usage_analytics", "Pro") {
        return response;
    }
    let mut storage = lock_audit!(state);
    catch_up_before_read(&mut storage, "Pro");
    match storage.local_pro_analytics_response(chrono::Utc::now()) {
        Ok(response) => Json(response).into_response(),
        Err(error) => analytics_error_response(&error, "Pro"),
    }
}
