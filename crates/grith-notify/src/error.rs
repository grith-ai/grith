// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Error types for the grith-notify crate.

use grith_digest::notification;

/// Top-level error type for the grith-notify crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Notification(#[from] notification::Error),

    #[error("channel not found: {0}")]
    ChannelNotFound(String),

    #[error("no channels matched for routing")]
    NoChannelsMatched,

    #[error("dispatcher not initialized")]
    NotInitialized,

    #[error("background task failed: {0}")]
    BackgroundTask(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("hmac verification failed")]
    HmacVerificationFailed,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
