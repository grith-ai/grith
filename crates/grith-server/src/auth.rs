// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Localhost-only authentication middleware for the dashboard API.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Json};
use serde::Serialize;
use std::net::SocketAddr;

use crate::AppState;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Whether to require API key authentication.
    pub require_api_key: bool,
    /// The expected API key (if authentication is enabled).
    pub api_key: Option<String>,
    /// Whether to restrict to localhost connections only.
    pub localhost_only: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            require_api_key: false,
            api_key: None,
            localhost_only: true,
        }
    }
}

impl AuthConfig {
    /// Validate the auth configuration for security.
    ///
    /// Returns an error if the configuration would expose the API without
    /// authentication — specifically if `localhost_only` is disabled while
    /// no API key auth is configured.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !self.localhost_only && !self.require_api_key {
            return Err(
                "SECURITY RISK: localhost_only is disabled but no API key authentication is \
                 configured. This would expose all API endpoints — including PUT /config, \
                 POST /digest/:id/approve, and POST /server/shutdown — to the network without \
                 authentication. Either set localhost_only = true or configure require_api_key \
                 = true with a strong api_key."
                    .into(),
            );
        }
        if self.require_api_key
            && self
                .api_key
                .as_deref()
                .map(str::trim)
                .filter(|k| !k.is_empty())
                .is_none()
        {
            return Err(
                "API key authentication is enabled (require_api_key = true) but no api_key is \
                 configured. Set a strong api_key value."
                    .into(),
            );
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct AuthError {
    error: String,
    code: String,
}

/// Middleware to check localhost-only access.
///
/// Rejects non-loopback connections. When `ConnectInfo` is absent (e.g. in
/// unit tests that don't use `into_make_service_with_connect_info`), the
/// request is allowed so test harnesses keep working.
pub async fn localhost_guard(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    if !state.auth_config.localhost_only {
        return next.run(request).await.into_response();
    }

    if let Some(addr) = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
    {
        let ip = addr.ip();
        if !ip.is_loopback() {
            return (
                StatusCode::FORBIDDEN,
                Json(AuthError {
                    error: "access restricted to localhost".into(),
                    code: "LOCALHOST_ONLY".into(),
                }),
            )
                .into_response();
        }
    }
    // If no ConnectInfo (e.g., in tests), allow the request
    next.run(request).await.into_response()
}

/// Middleware to check API key authentication.
///
/// When `auth_config.require_api_key` is true, validates the
/// `x-grith-api-key` header against the configured key. When API key
/// authentication is disabled, all requests pass through.
pub async fn api_key_guard(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    if !state.auth_config.require_api_key {
        return next.run(request).await.into_response();
    }

    let expected = match &state.auth_config.api_key {
        Some(k) => k.as_str(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthError {
                    error: "API key authentication enabled but no key configured".into(),
                    code: "AUTH_MISCONFIGURED".into(),
                }),
            )
                .into_response();
        }
    };

    if let Some(key) = request.headers().get("x-grith-api-key") {
        if let Ok(val) = key.to_str() {
            if val == expected {
                return next.run(request).await.into_response();
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(AuthError {
            error: "API key required".into(),
            code: "AUTH_REQUIRED".into(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_auth_config() {
        let config = AuthConfig::default();
        assert!(!config.require_api_key);
        assert!(config.api_key.is_none());
        assert!(config.localhost_only);
    }

    #[test]
    fn test_default_config_validates() {
        let config = AuthConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_localhost_only_without_api_key_validates() {
        let config = AuthConfig {
            localhost_only: true,
            require_api_key: false,
            api_key: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_non_localhost_with_api_key_validates() {
        let config = AuthConfig {
            localhost_only: false,
            require_api_key: true,
            api_key: Some("secret-key".into()),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_non_localhost_without_api_key_rejects() {
        let config = AuthConfig {
            localhost_only: false,
            require_api_key: false,
            api_key: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("SECURITY RISK"));
        assert!(err.contains("localhost_only"));
    }

    #[test]
    fn test_api_key_enabled_without_key_rejects() {
        let config = AuthConfig {
            localhost_only: true,
            require_api_key: true,
            api_key: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("no api_key"));
    }

    #[test]
    fn test_api_key_enabled_with_blank_key_rejects() {
        let config = AuthConfig {
            localhost_only: false,
            require_api_key: true,
            api_key: Some("   ".into()),
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("no api_key"));
    }
}
