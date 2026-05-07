// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Error types for the grith-server crate.

use thiserror::Error;

/// Unified error type for server operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("server error: {0}")]
    Server(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("audit error: {0}")]
    Audit(#[from] grith_audit::Error),

    #[error("digest error: {0}")]
    Digest(#[from] grith_digest::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
