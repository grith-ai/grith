// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Error types for the grith-proxy crate.

use thiserror::Error;

/// Unified error type for proxy operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("filter error: {filter}: {message}")]
    Filter { filter: String, message: String },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
