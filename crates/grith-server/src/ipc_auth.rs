// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! IPC bearer token authentication for daemon-client endpoints.
//!
//! Validates the `Authorization: Bearer {token}` header against the
//! daemon's IPC token stored in `AppState::ipc_token`. Endpoints that
//! require IPC auth should include `IpcAuth` as a parameter.

use crate::AppState;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;

/// Extractor that validates the IPC bearer token.
///
/// Include this as a parameter in any handler that requires IPC auth:
/// ```ignore
/// async fn my_handler(_auth: IpcAuth, State(state): State<AppState>) { ... }
/// ```
pub struct IpcAuth;

#[axum::async_trait]
impl FromRequestParts<AppState> for IpcAuth {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // If no token is configured, skip auth (allows dashboard UI access).
        if state.ipc_token.is_empty() {
            return Ok(IpcAuth);
        }

        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        let Some(header) = auth_header else {
            return Err((StatusCode::UNAUTHORIZED, "Missing Authorization header"));
        };

        let Some(token) = header.strip_prefix("Bearer ") else {
            return Err((StatusCode::UNAUTHORIZED, "Invalid Authorization format"));
        };

        // Constant-time comparison to prevent timing attacks.
        if !constant_time_eq(token.as_bytes(), state.ipc_token.as_bytes()) {
            return Err((StatusCode::FORBIDDEN, "Invalid IPC token"));
        }

        Ok(IpcAuth)
    }
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(constant_time_eq(b"", b""));
    }
}
