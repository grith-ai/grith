// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Browser pairing: hand the dashboard token to a browser without ever
//! printing the long-lived secret to a terminal.
//!
//! Two endpoints cooperate:
//!
//! - `POST /api/ipc/dashboard/pair-code` ([`mint_pair_code`]) — IPC-bearer
//!   authed. A same-uid CLI (which holds the daemon token) asks the running
//!   daemon to mint a fresh **single-use** pairing code, then builds a
//!   `…/#pair=<code>` URL to open or print.
//! - `POST /api/dashboard/pair` ([`redeem_pair_code`]) — open / self-authing.
//!   The SPA posts the code it captured from the URL fragment and receives the
//!   real dashboard token, which it stores in `localStorage`. The code is
//!   consumed on first success, so a later screenshot of the URL is worthless.
//!
//! Why the redeem endpoint can be open: the code is high-entropy (122-bit
//! UUID), single-use, loopback-only, and yields only the dashboard token (not
//! the daemon IPC token). A drive-by web page cannot guess it, and the JSON
//! body forces a CORS preflight the locked-origin layer rejects cross-origin.

use crate::ipc_auth::IpcAuth;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct PairCodeResponse {
    /// Freshly minted single-use pairing code.
    code: String,
}

/// IPC: mint a fresh single-use pairing code and return it. Gated by
/// [`IpcAuth`] (daemon bearer token) so only a same-uid CLI can request one.
pub(crate) async fn mint_pair_code(
    _auth: IpcAuth,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let code = state.mint_pair_code();
    (StatusCode::OK, Json(PairCodeResponse { code }))
}

#[derive(Deserialize)]
pub(crate) struct PairRequest {
    code: String,
}

#[derive(Serialize)]
struct PairResponse {
    /// The dashboard token the SPA stores in `localStorage` and sends in
    /// `x-grith-csrf` thereafter.
    token: String,
}

#[derive(Serialize)]
struct PairError {
    error: String,
    code: String,
}

/// Open: exchange a single-use pairing code for the dashboard token.
///
/// Returns `200 {token}` on a valid, outstanding code (consuming it), or
/// `401 PAIR_CODE_INVALID` otherwise. Not gated by the CSRF/token guard — it
/// *is* the bootstrap that gives the browser its token, so requiring the token
/// here would be circular. The code itself is the proof.
pub(crate) async fn redeem_pair_code(
    State(state): State<AppState>,
    Json(req): Json<PairRequest>,
) -> impl IntoResponse {
    match state.redeem_pair_code(&req.code) {
        Some(token) => (StatusCode::OK, Json(PairResponse { token })).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(PairError {
                error: "invalid or already-used pairing code".into(),
                code: "PAIR_CODE_INVALID".into(),
            }),
        )
            .into_response(),
    }
}
