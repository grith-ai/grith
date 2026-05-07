// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Tracing subscriber initialization for the grith daemon.

use std::sync::OnceLock;
use tracing_subscriber::{fmt, prelude::*, reload, EnvFilter};

type FilterHandle = reload::Handle<EnvFilter, tracing_subscriber::Registry>;

static FILTER_HANDLE: OnceLock<FilterHandle> = OnceLock::new();

/// Initialize the tracing subscriber for structured logging.
///
/// Reads log level from the config, with `GRITH_LOG_LEVEL` env var as override.
/// The filter can be changed at runtime via [`suppress()`] and [`restore()`].
pub fn init(log_level: &str) {
    let env_filter =
        EnvFilter::try_from_env("GRITH_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new(log_level));

    let (filter_layer, reload_handle) = reload::Layer::new(env_filter);

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false),
        )
        .init();

    let _ = FILTER_HANDLE.set(reload_handle);
}

/// Suppress all tracing output (sets filter to "off").
/// Used by `grith exec` to keep the terminal clean during supervised sessions.
pub fn suppress() {
    if let Some(handle) = FILTER_HANDLE.get() {
        let _ = handle.modify(|filter| *filter = EnvFilter::new("off"));
    }
}

/// Restore tracing output to the default level.
pub fn restore(log_level: &str) {
    if let Some(handle) = FILTER_HANDLE.get() {
        let _ = handle.modify(|filter| {
            *filter = EnvFilter::try_from_env("GRITH_LOG_LEVEL")
                .unwrap_or_else(|_| EnvFilter::new(log_level));
        });
    }
}
