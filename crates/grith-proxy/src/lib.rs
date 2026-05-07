// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Multi-filter security proxy for evaluating tool calls.
//!
//! Scores each call through a phased pipeline of filters, producing
//! allow / queue / deny decisions with full audit trails.

pub mod allowlist_persistence;
pub mod annotations;
pub mod audit_bridge;
pub mod engine;
pub mod error;
pub mod exfil;
pub mod filters;
pub mod meta_rules;
pub mod reputation;
pub mod scoring;
pub mod types;

pub use error::Error;
