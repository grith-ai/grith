// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Error types for the grith-digest crate.

use thiserror::Error;

/// Unified error type for digest operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("digest item not found: {0}")]
    NotFound(String),

    #[error("invalid action: {0}")]
    InvalidAction(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("delivery error: {0}")]
    Delivery(String),
}

pub type Result<T> = std::result::Result<T, Error>;
