// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Error types and HTTP response checking for LLM providers.

use thiserror::Error;

/// Unified error type for LLM provider operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("provider error: {provider}: {message}")]
    Provider { provider: String, message: String },

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("no provider available for request")]
    NoProvider,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Check an HTTP response for errors and return an appropriate [`Error`].
///
/// This is the single canonical implementation for HTTP error handling across
/// all LLM providers, replacing duplicated status-code checks.
///
/// Behaviour:
/// - **429 Too Many Requests**: extracts the `retry-after` header and returns a
///   rate-limit error.
/// - **Any other non-2xx status**: reads the response body for diagnostics and
///   returns a provider error. If reading the body fails, emits a
///   `tracing::warn!` and uses an empty string instead.
///
/// Returns `Ok(resp)` when the status code indicates success.
pub async fn check_http_response(
    resp: reqwest::Response,
    provider: &str,
) -> Result<reqwest::Response> {
    let status = resp.status();

    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");
        return Err(Error::Provider {
            provider: provider.into(),
            message: format!("rate limited, retry after: {retry_after}"),
        });
    }

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_else(|e| {
            tracing::warn!(
                provider = provider,
                status = %status,
                error = %e,
                "failed to read error response body from provider"
            );
            String::new()
        });
        return Err(Error::Provider {
            provider: provider.into(),
            message: format!("HTTP {status}: {body}"),
        });
    }

    Ok(resp)
}
