// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Error types for the grith-audit crate.

use thiserror::Error;

/// Unified error type for audit operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("audit record not found: {0}")]
    NotFound(String),

    #[error("channel send error: audit logger channel closed")]
    ChannelClosed,

    #[error("channel full: audit logger backpressure")]
    ChannelFull,

    /// The chain is quarantined (integrity unverifiable); new appends are
    /// refused so broken evidence is preserved rather than extended (B-CORE-1).
    #[error("audit chain quarantined: {0}")]
    ChainQuarantined(String),

    #[error("analytics projection error: {0}")]
    Analytics(String),

    /// The projection tables do not exist in this database — the writer-lock
    /// owner is an older grith that never created them. Distinct from
    /// `Analytics` so HTTP surfaces can answer 503 with remediation instead
    /// of a bare 500.
    #[error("analytics is unavailable: the process that owns the audit database predates local analytics")]
    AnalyticsUnavailable,
}

pub type Result<T> = std::result::Result<T, Error>;
