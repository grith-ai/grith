// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Analytics-v2 contract types and deterministic aggregation primitives.
//!
//! This crate deliberately has no daemon, SQLite, HTTP, or audit-writer
//! dependencies. Edge materialisation and cloud rebuilds use the same
//! accumulator, while adapters own persistence and transport concerns.

pub mod accumulator;
#[cfg(feature = "archive")]
pub mod archive;
pub mod contract;
pub mod limits;
pub mod normalize;
pub mod timestamps;

pub use accumulator::{AccumulatorError, DayAccumulator};
pub use contract::*;
pub use normalize::{
    canonical_filter_ids, category_for_tool_kind, cost_usd_to_micros, normalize_dimension,
    normalize_filter_id, score_micros_to_bin, score_to_micros, NormalizationError,
};
