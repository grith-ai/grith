// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Unified error type that aggregates errors from all grith subsystem crates.

use thiserror::Error;

/// Unified error type for the grith daemon.
#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("proxy error: {0}")]
    Proxy(#[from] grith_proxy::Error),

    #[error("LLM error: {0}")]
    Llm(#[from] grith_llm::Error),

    #[error("digest error: {0}")]
    Digest(#[from] grith_digest::Error),

    #[error("audit error: {0}")]
    Audit(#[from] grith_audit::Error),

    #[error("server error: {0}")]
    Server(#[from] grith_server::Error),

    #[error("CLI error: {0}")]
    Cli(#[from] grith_cli::Error),

    #[error("supervisor error: {0}")]
    Supervisor(#[from] grith_supervisor::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
