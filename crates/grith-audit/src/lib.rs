// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Tamper-evident audit logging for the grith security proxy.
//!
//! Provides SQLite-backed storage, async logging, querying, statistics,
//! export (JSON/CSV/JSONL), and source-to-sink correlation tracking.

pub mod analytics;
pub mod compression;
pub mod correlation;
pub mod error;
pub mod export;
pub mod logger;
pub mod query;
pub(crate) mod record_parser;
pub mod retention;
pub mod stats;
pub mod storage;
pub mod types;
pub mod writer_lock;

pub use correlation::CorrelationTracker;
pub use error::Error;
pub use logger::AuditLogger;
pub use query::AuditQuery;
pub use stats::AuditStats;
pub use storage::{AuditStorage, ForkRecord};
pub use types::{
    AuditAnalyticsMetadata, AuditConfigVersion, AuditDestinationMetadata, AuditLlmPricing,
    AuditRecord, AuditSecurityMetadata, ChainVerification, FilterResultSummary, ProxyActionSummary,
    RecordType, SegmentHistory,
};
