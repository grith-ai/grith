// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Terminal REPL, rendering, and interactive UI components for grith.
//!
//! Provides the interactive command-line experience including the REPL loop,
//! digest review session, supervisor session display, and diff rendering.

pub mod commands;
pub mod diff;
pub mod digest_ui;
pub mod error;
pub mod render;
pub mod repl;
pub mod supervisor_ui;
pub mod tui;

pub use commands::{parse_input, Command, InputType};
pub use diff::{DiffLine, DiffResult};
pub use digest_ui::{
    run_digest_review_session, run_inline_review, DigestAction, DigestReviewSession, ViewMode,
};
pub use error::Error;
pub use render::Decision;
pub use repl::{ProcessResult, ReplConfig, ReplSession};
pub use supervisor_ui::{
    format_stats_bar, format_uptime, render_session_detail, render_session_list,
};
