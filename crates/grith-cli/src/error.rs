// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Error types for the grith-cli crate.

use thiserror::Error;

/// Unified error type for CLI operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("terminal error: {0}")]
    Terminal(String),

    #[error("digest error: {0}")]
    Digest(#[from] grith_digest::Error),

    #[error("LLM error: {0}")]
    Llm(#[from] grith_llm::Error),

    #[error("audit error: {0}")]
    Audit(#[from] grith_audit::Error),

    #[error("unknown command: {0}")]
    UnknownCommand(String),
}

pub type Result<T> = std::result::Result<T, Error>;
