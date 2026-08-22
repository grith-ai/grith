// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Frozen protocol and product limits for analytics-v2/schema-v1.

pub const PROTOCOL_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const MATERIALIZER_VERSION: u16 = 1;

pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DAY_SNAPSHOTS_PER_REQUEST: usize = 1;
pub const MAX_TOTAL_ROLLUP_ROWS: usize = 50_000;
pub const MAX_USAGE_ROWS: usize = 20_000;
pub const MAX_FILTER_ROWS: usize = 10_000;
pub const MAX_SESSION_ROWS: usize = 10_000;
pub const MAX_LLM_ROWS: usize = 5_000;
pub const MAX_DESTINATION_ROWS: usize = 5_000;
pub const MAX_SECURITY_EVENTS: usize = 500;
pub const MAX_CONFIG_VERSIONS: usize = 64;
pub const MAX_EVALUATED_FILTERS: usize = 64;

pub const MAX_PROJECT_BYTES: usize = 128;
pub const MAX_PROFILE_BYTES: usize = 64;
pub const MAX_TOOL_BYTES: usize = 64;
pub const MAX_PROVIDER_BYTES: usize = 32;
pub const MAX_MODEL_BYTES: usize = 128;
pub const MAX_FILTER_ID_BYTES: usize = 64;
pub const MAX_DESTINATION_ID_BYTES: usize = 128;

pub const DEVICE_REQUESTS_PER_MINUTE: u32 = 6;
pub const DEVICE_REQUEST_BURST: u32 = 12;
pub const TEAM_REQUESTS_PER_MINUTE: u32 = 300;
pub const TEAM_REQUEST_BURST: u32 = 600;
pub const ACTIVE_ARCHIVE_BYTES_PER_TEAM: u64 = 250 * 1024 * 1024 * 1024;

pub const DEVICES_PER_SEAT: u32 = 2;
pub const MAX_TEAM_SEATS: u32 = 25;
pub const MAX_TEAM_DEVICES: u32 = DEVICES_PER_SEAT * MAX_TEAM_SEATS;

pub const HEARTBEAT_INTERVAL_SECONDS: u64 = 30;
pub const DEVICE_STALE_AFTER_SECONDS: u64 = 60;
pub const RUNTIME_INSTANCE_LEASE_SECONDS: u64 = 90;
pub const SNAPSHOT_INTERVAL_SECONDS: u64 = 30;
pub const CLOUD_VISIBILITY_SLO_SECONDS: u64 = 60;

pub const FREE_WINDOW_DAYS: u32 = 7;
pub const PRO_SHORT_WINDOW_DAYS: u32 = 30;
pub const PRO_LONG_WINDOW_DAYS: u32 = 90;
pub const FREE_RECENT_SECURITY_EVENTS: usize = 20;
pub const MAX_EXPORT_DAYS: u32 = 90;

pub const SCORE_SCALE: i64 = 1_000_000;
pub const COST_SCALE: u64 = 1_000_000;
pub const SCORE_BIN_COUNT: u8 = 30;
pub const SCORE_HISTOGRAM_MIN_MICROS: i64 = 0;
pub const SCORE_HISTOGRAM_MAX_MICROS: i64 = 15 * SCORE_SCALE;
pub const SCORE_BIN_WIDTH_MICROS: i64 = 500_000;
pub const MAX_ABS_SCORE_MICROS: i64 = 100 * SCORE_SCALE;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub const POSTGRES_ROLLUP_RETENTION_DAYS: u32 = 90;
pub const SECURITY_EVENT_RETENTION_DAYS: u32 = 90;
pub const ACTIVE_ARCHIVE_RETENTION_DAYS: u32 = 90;
pub const SUPERSEDED_ARCHIVE_RETENTION_DAYS: u32 = 7;
pub const LOCAL_ANALYTICS_RETENTION_DAYS: u32 = 90;
pub const LOCAL_ACTIVE_AUDIT_RETENTION_DAYS: u32 = 30;
pub const LAPSE_REACTIVATION_RETENTION_DAYS: u32 = 30;

pub const UNKNOWN_DIMENSION: &str = "<unknown>";
pub const NOT_APPLICABLE_DIMENSION: &str = "<not-applicable>";
pub const CURRENCY_USD: &str = "USD";
