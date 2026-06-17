// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! WebSocket upgrade authorization for the dashboard live streams.
//!
//! Browser WebSockets are **not** covered by CORS, so a malicious page could
//! open `ws://127.0.0.1:3141/ws/live` (or `/ws/supervisor/:id`) and read the
//! live syscall / proxy-decision stream. Two checks defend the upgrade:
//!
//! 1. **Origin-vs-Host.** Browsers always send `Origin` on a WS handshake. A
//!    same-origin dashboard page sends an `Origin` whose authority equals the
//!    `Host` header; a cross-origin page (`evil.com`, or another local port
//!    the operator happens to have open) does not, and is rejected. This is
//!    stateless — no configured origin to thread — and fully defeats the
//!    browser cross-origin hijack. Non-browser clients (which omit `Origin`)
//!    pass this check and are gated by the token instead.
//! 2. **Dashboard token.** When a per-server token is configured, the client
//!    must present it as the `token` query parameter (browsers cannot set
//!    custom WS request headers), compared in constant time. This gates other
//!    local users — who cannot read the 0600 token file — on multi-user hosts.

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};

use crate::AppState;

/// Middleware that authorizes a WebSocket upgrade **before** the
/// `WebSocketUpgrade` extractor or any handler runs, so an unauthorized
/// handshake is rejected with a plain HTTP error and never reaches the
/// upgrade machinery. Layer this onto the WS routers only.
pub async fn require_ws_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Tokens are URL-safe (hex or the fixed sentinel), so the raw query value
    // needs no percent-decoding.
    let token = request.uri().query().and_then(|q| query_param(q, "token"));

    match authorize_ws(request.headers(), token.as_deref(), &state) {
        Ok(()) => next.run(request).await,
        Err((status, code)) => (
            status,
            Json(serde_json::json!({
                "error": "websocket upgrade not authorized",
                "code": code,
            })),
        )
            .into_response(),
    }
}

/// Extract a single query parameter value by key from a raw query string.
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

/// Authorize a WebSocket upgrade. Returns `Err((status, code))` to reject the
/// handshake before any data flows.
pub fn authorize_ws(
    headers: &HeaderMap,
    token: Option<&str>,
    state: &AppState,
) -> Result<(), (StatusCode, &'static str)> {
    if !origin_matches_host(headers) {
        return Err((StatusCode::FORBIDDEN, "WS_ORIGIN_FORBIDDEN"));
    }

    if !state.dashboard_token.is_empty() {
        let ok = token.is_some_and(|t| {
            crate::ipc_auth::constant_time_eq(t.as_bytes(), state.dashboard_token.as_bytes())
        });
        if !ok {
            return Err((StatusCode::UNAUTHORIZED, "WS_TOKEN_REQUIRED"));
        }
    }

    Ok(())
}

/// True when the request has no `Origin` (a non-browser client) or its
/// `Origin` authority matches the `Host` header (a same-origin browser page).
fn origin_matches_host(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        // No Origin → not a browser page (browsers always set it on a WS
        // handshake). Token gating still applies below.
        return true;
    };

    // `Origin` is `scheme://authority`; compare its authority to `Host`.
    let Some((_scheme, origin_authority)) = origin.split_once("://") else {
        return false;
    };

    match headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        Some(host) => origin_authority.eq_ignore_ascii_case(host),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn no_origin_passes_origin_check() {
        assert!(origin_matches_host(&headers(&[("host", "127.0.0.1:3141")])));
    }

    #[test]
    fn same_origin_passes() {
        assert!(origin_matches_host(&headers(&[
            ("host", "127.0.0.1:3141"),
            ("origin", "http://127.0.0.1:3141"),
        ])));
    }

    #[test]
    fn cross_origin_rejected() {
        assert!(!origin_matches_host(&headers(&[
            ("host", "127.0.0.1:3141"),
            ("origin", "http://evil.com"),
        ])));
    }

    #[test]
    fn other_local_port_rejected() {
        assert!(!origin_matches_host(&headers(&[
            ("host", "127.0.0.1:3141"),
            ("origin", "http://localhost:9999"),
        ])));
    }

    #[test]
    fn origin_null_rejected() {
        // Sandboxed iframes / file:// contexts send the literal `Origin: null`,
        // which must never be treated as same-origin.
        assert!(!origin_matches_host(&headers(&[
            ("host", "127.0.0.1:3141"),
            ("origin", "null"),
        ])));
    }

    #[test]
    fn origin_without_host_rejected() {
        assert!(!origin_matches_host(&headers(&[(
            "origin",
            "http://127.0.0.1:3141",
        )])));
    }

    #[test]
    fn query_param_extracts_token() {
        assert_eq!(query_param("token=abc", "token").as_deref(), Some("abc"));
        assert_eq!(
            query_param("foo=1&token=abc&bar=2", "token").as_deref(),
            Some("abc")
        );
        assert_eq!(query_param("foo=1", "token"), None);
        assert_eq!(query_param("", "token"), None);
    }
}
