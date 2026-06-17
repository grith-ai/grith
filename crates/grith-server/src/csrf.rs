// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Dashboard CSRF / browser-origin isolation middleware.
//!
//! Browser-facing dashboard mutations (digest actions, config writes, policy
//! and canary changes, supervisor session control, proxy-test, event
//! injection) must carry a non-simple request header,
//! [`DASHBOARD_CSRF_HEADER`].
//!
//! Requiring a custom header has two effects:
//!
//! 1. **Forces a CORS preflight** for any cross-origin `fetch`. The dashboard
//!    [`CorsLayer`](tower_http::cors::CorsLayer) only allows the loopback
//!    dashboard origin, so a drive-by web page's preflight is rejected and the
//!    mutating request never executes — closing the browser-origin CSRF gap for
//!    no-body / simple POSTs that would otherwise skip preflight entirely.
//! 2. Gives JSON writes an explicit application-level invariant instead of
//!    relying on the fragile "a preflight must happen and must fail" property.
//!
//! This middleware is **method-aware**: safe methods (GET/HEAD/OPTIONS/TRACE)
//! pass through untouched, so it can be layered onto routers that mix reads and
//! writes (e.g. the supervisor sub-router) without gating reads.
//!
//! It is applied ONLY to browser-facing dashboard routers — never to IPC
//! bearer-token routes (`/api/ipc/*`, `/api/server/shutdown`) or external
//! webhook callbacks (`/api/digest/:id/webhook-review`), which carry their own
//! proofs (see [`crate::ipc_auth`] and the digest webhook nonce).

use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use serde::Serialize;

use crate::AppState;

/// Custom header carrying the dashboard CSRF / auth proof.
pub const DASHBOARD_CSRF_HEADER: &str = "x-grith-csrf";

/// Fixed, non-secret sentinel the SPA sends when no per-server dashboard token
/// is configured.
///
/// Its value carries **no authority** — the security property is that *some*
/// custom header forces a CORS preflight that the locked-origin `CorsLayer`
/// rejects for non-dashboard origins. Item 2 of the dashboard-auth work
/// replaces this presence check with constant-time equality against a
/// per-server secret token.
pub const DASHBOARD_CSRF_SENTINEL: &str = "grith-dashboard";

#[derive(Serialize)]
struct CsrfError {
    error: String,
    code: String,
}

/// Returns true when the request carries an acceptable dashboard proof.
///
/// - When a per-server dashboard token is configured (`state.dashboard_token`
///   non-empty — the production default), the header must equal it, compared
///   in **constant time** to avoid a timing side channel on the secret.
/// - When no token is configured (zero-config / test mode), the header must
///   equal the public [`DASHBOARD_CSRF_SENTINEL`]. The sentinel carries no
///   authority; it only forces the CORS preflight that blocks cross-origin
///   pages.
fn dashboard_proof_valid(request: &Request, state: &AppState) -> bool {
    let Some(header) = request
        .headers()
        .get(DASHBOARD_CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };

    if state.dashboard_token.is_empty() {
        header == DASHBOARD_CSRF_SENTINEL
    } else {
        crate::ipc_auth::constant_time_eq(header.as_bytes(), state.dashboard_token.as_bytes())
    }
}

/// Method-aware CSRF guard for browser-facing dashboard mutations.
///
/// Layer this onto dashboard-write routers only. Safe methods pass through, so
/// it is also safe on routers that mix reads and writes.
pub async fn require_dashboard_csrf(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Safe, non-mutating methods never need the proof. This also lets any CORS
    // preflight (OPTIONS) the `CorsLayer` did not already short-circuit pass.
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) {
        return next.run(request).await;
    }

    if dashboard_proof_valid(&request, &state) {
        next.run(request).await
    } else {
        (
            StatusCode::FORBIDDEN,
            Json(CsrfError {
                error: format!(
                    "missing or invalid {DASHBOARD_CSRF_HEADER} header; browser-facing \
                     dashboard mutations must carry it"
                ),
                code: "CSRF_REQUIRED".into(),
            }),
        )
            .into_response()
    }
}

/// Token guard for **sensitive read** routes (item 4 — two-tier read gating).
///
/// Unlike [`require_dashboard_csrf`], this requires the dashboard proof on
/// *every* method (reads included), so audit argv, queued tool calls, session
/// / process metadata, canary values, etc. are not readable by a local
/// process — or a tokenless browser tab — that lacks the dashboard token. Only
/// `OPTIONS` (CORS preflight) passes. When no token is configured (zero-config
/// dev) the public sentinel is accepted, so the gate is inert until an
/// operator provisions a token. Low-sensitivity status routes are not layered
/// with this guard and stay open.
pub async fn require_dashboard_token(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Zero-config (no token configured): sensitive reads stay open. The
    // multi-user threat this gate addresses only exists once a token is
    // provisioned, and CORS already blocks a cross-origin browser page from
    // reading the JSON response, so a sentinel-forces-preflight trick (as used
    // for writes) is unnecessary here.
    if state.dashboard_token.is_empty() {
        return next.run(request).await;
    }

    if *request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    if dashboard_proof_valid(&request, &state) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(CsrfError {
                error: format!(
                    "missing or invalid {DASHBOARD_CSRF_HEADER} header; this dashboard \
                     resource requires the per-server dashboard token"
                ),
                code: "DASHBOARD_AUTH_REQUIRED".into(),
            }),
        )
            .into_response()
    }
}
