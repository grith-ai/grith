// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Per-session rate limiting filter for tool call frequency.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};
use std::collections::HashMap;
// NOTE(M-4): std::sync::Mutex is intentionally used here instead of
// tokio::sync::Mutex because the lock is never held across .await points.
// The evaluate() method delegates to the synchronous evaluate_at(), so
// std::sync::Mutex is the more efficient choice.
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Configuration for a single rate limit rule.
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Maximum number of calls per minute.
    pub max_per_minute: u32,
    /// Burst threshold: if this many calls occur within a 5-second window,
    /// it is flagged as a burst.
    pub burst_threshold: u32,
}

/// Filter that enforces per-call-type rate limits and detects burst patterns.
///
/// Runs in Phase 3 (Context) because rate limiting depends on accumulated
/// session state (call timestamps).
///
/// Scoring:
/// - `+1.0` approaching the per-minute limit (>80% of max)
/// - `+2.0` exceeding the per-minute limit
/// - `+3.0` burst detected (many calls in a very short window)
pub struct RateLimitFilter {
    windows: Mutex<HashMap<String, Vec<Instant>>>,
    limits: HashMap<String, RateLimit>,
}

impl RateLimitFilter {
    pub fn new(limits: HashMap<String, RateLimit>) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            limits,
        }
    }

    /// Create a filter with sensible default rate limits.
    pub fn with_defaults() -> Self {
        let mut limits = HashMap::new();
        limits.insert(
            "file_read".to_string(),
            RateLimit {
                max_per_minute: 60,
                burst_threshold: 15,
            },
        );
        limits.insert(
            "file_write".to_string(),
            RateLimit {
                max_per_minute: 30,
                burst_threshold: 10,
            },
        );
        limits.insert(
            "file_append".to_string(),
            RateLimit {
                max_per_minute: 30,
                burst_threshold: 10,
            },
        );
        limits.insert(
            "file_delete".to_string(),
            RateLimit {
                max_per_minute: 20,
                burst_threshold: 5,
            },
        );
        limits.insert(
            "dir_list".to_string(),
            RateLimit {
                max_per_minute: 60,
                burst_threshold: 15,
            },
        );
        limits.insert(
            "shell_exec".to_string(),
            RateLimit {
                max_per_minute: 20,
                burst_threshold: 5,
            },
        );
        limits.insert(
            "http_request".to_string(),
            RateLimit {
                max_per_minute: 60,
                burst_threshold: 15,
            },
        );
        Self::new(limits)
    }

    /// Classify a `ToolCallType` into a string category for rate limiting.
    fn classify_call(call_type: &ToolCallType) -> String {
        match call_type {
            ToolCallType::FileRead { .. } => "file_read".to_string(),
            ToolCallType::FileWrite { .. } => "file_write".to_string(),
            ToolCallType::FileAppend { .. } => "file_append".to_string(),
            ToolCallType::FileDelete { .. } => "file_delete".to_string(),
            ToolCallType::DirList { .. } => "dir_list".to_string(),
            ToolCallType::ShellExec { .. } => "shell_exec".to_string(),
            ToolCallType::HttpRequest { .. } => "http_request".to_string(),
            ToolCallType::FileRename { .. } => "file_rename".to_string(),
            ToolCallType::FileChmod { .. } => "file_chmod".to_string(),
            ToolCallType::DirCreate { .. } => "dir_create".to_string(),
            ToolCallType::NetConnect { .. } => "net_connect".to_string(),
            ToolCallType::NetListen { .. } => "net_listen".to_string(),
            ToolCallType::ProcessSpawn { .. } => "process_spawn".to_string(),
            ToolCallType::DnsQuery { .. } => "dns_query".to_string(),
        }
    }

    /// Record a call and return (calls_in_last_minute, calls_in_burst_window).
    fn record_and_count(&self, category: &str, now: Instant) -> (u32, u32) {
        let mut windows = self.windows.lock().expect("lock poisoned");
        let timestamps = windows.entry(category.to_string()).or_default();

        // Record current call.
        timestamps.push(now);

        // Prune timestamps older than 1 minute.
        let one_minute_ago = now - Duration::from_secs(60);
        timestamps.retain(|t| *t >= one_minute_ago);

        let minute_count = timestamps.len() as u32;

        // Count calls in the burst window (last 5 seconds).
        let burst_window = now - Duration::from_secs(5);
        let burst_count = timestamps.iter().filter(|t| **t >= burst_window).count() as u32;

        (minute_count, burst_count)
    }

    /// Evaluate rate limiting using a specific `Instant` (for testability).
    fn evaluate_at(
        &self,
        ctx: &ToolCallContext,
        now: Instant,
    ) -> crate::error::Result<FilterResult> {
        let category = Self::classify_call(&ctx.call_type);

        let limit = match self.limits.get(&category) {
            Some(l) => l,
            None => return Ok(FilterResult::no_match("rate_limit")),
        };

        let (minute_count, burst_count) = self.record_and_count(&category, now);

        // Check for burst first (highest severity).
        if burst_count >= limit.burst_threshold {
            return Ok(FilterResult::matched(
                "rate_limit",
                "burst-detected",
                3.0,
                Severity::Error,
                format!(
                    "Burst detected: {burst_count} '{category}' calls in 5s (threshold: {})",
                    limit.burst_threshold
                ),
            ));
        }

        // Check if over the per-minute limit.
        if minute_count > limit.max_per_minute {
            return Ok(FilterResult::matched(
                "rate_limit",
                "rate-exceeded",
                2.0,
                Severity::Warning,
                format!(
                    "Rate exceeded: {minute_count} '{category}' calls/min (limit: {})",
                    limit.max_per_minute
                ),
            ));
        }

        // Check if approaching the per-minute limit (>80%).
        let threshold_80 = (limit.max_per_minute as f64 * 0.8) as u32;
        if minute_count > threshold_80 {
            return Ok(FilterResult::matched(
                "rate_limit",
                "rate-approaching",
                1.0,
                Severity::Notice,
                format!(
                    "Approaching rate limit: {minute_count} '{category}' calls/min (limit: {})",
                    limit.max_per_minute
                ),
            ));
        }

        Ok(FilterResult::no_match("rate_limit"))
    }
}

#[async_trait::async_trait]
impl SecurityFilter for RateLimitFilter {
    fn name(&self) -> &str {
        "rate_limit"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Context
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        self.evaluate_at(ctx, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCallType;
    use uuid::Uuid;

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    fn small_limit_filter() -> RateLimitFilter {
        let mut limits = HashMap::new();
        limits.insert(
            "shell_exec".to_string(),
            RateLimit {
                max_per_minute: 5,
                burst_threshold: 3,
            },
        );
        limits.insert(
            "file_read".to_string(),
            RateLimit {
                max_per_minute: 10,
                burst_threshold: 5,
            },
        );
        RateLimitFilter::new(limits)
    }

    #[tokio::test]
    async fn test_under_limit_no_match() {
        let filter = small_limit_filter();
        let now = Instant::now();
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec![],
        });
        let result = filter.evaluate_at(&ctx, now).unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_approaching_limit() {
        let filter = small_limit_filter();
        let now = Instant::now();

        // shell_exec limit is 5/min, 80% = 4.
        // Make 4 calls (spaced out) to avoid burst.
        for i in 0..4 {
            let ctx = make_ctx(ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec![],
            });
            let t = now + Duration::from_secs(i * 10); // 10s apart
            let _ = filter.evaluate_at(&ctx, t).unwrap();
        }

        // 5th call should trigger "approaching" (5 > 4 = 80% of 5).
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "echo".into(),
            args: vec!["test".into()],
        });
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_secs(50))
            .unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 1.0);
        assert_eq!(result.rule_id, "rate-approaching");
    }

    #[tokio::test]
    async fn test_rate_exceeded() {
        let filter = small_limit_filter();
        let now = Instant::now();

        // Make 5 calls spaced out (to avoid burst).
        for i in 0..5 {
            let ctx = make_ctx(ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec![],
            });
            let t = now + Duration::from_secs(i * 10);
            let _ = filter.evaluate_at(&ctx, t).unwrap();
        }

        // 6th call exceeds the 5/min limit.
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "pwd".into(),
            args: vec![],
        });
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_secs(55))
            .unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 2.0);
        assert_eq!(result.rule_id, "rate-exceeded");
    }

    #[tokio::test]
    async fn test_burst_detected() {
        let filter = small_limit_filter();
        let now = Instant::now();

        // Make 3 calls within 5 seconds (burst threshold is 3 for shell_exec).
        for i in 0..3 {
            let ctx = make_ctx(ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec![],
            });
            let t = now + Duration::from_millis(i * 100); // 100ms apart
            let _ = filter.evaluate_at(&ctx, t).unwrap();
        }

        // This triggers burst since 3 calls happened within 5s.
        // The 3rd call already had burst_count=3 which equals burst_threshold=3.
        // Let's check state by making one more call.
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "echo".into(),
            args: vec!["burst".into()],
        });
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_millis(500))
            .unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 3.0);
        assert_eq!(result.rule_id, "burst-detected");
    }

    #[tokio::test]
    async fn test_unknown_category_no_match() {
        // Create filter with limits only for shell_exec.
        let mut limits = HashMap::new();
        limits.insert(
            "shell_exec".to_string(),
            RateLimit {
                max_per_minute: 5,
                burst_threshold: 3,
            },
        );
        let filter = RateLimitFilter::new(limits);

        // HTTP request has no limit configured.
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://example.com".into(),
        });
        let result = filter.evaluate_at(&ctx, Instant::now()).unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_with_defaults_creates_limits() {
        let filter = RateLimitFilter::with_defaults();
        assert!(filter.limits.contains_key("shell_exec"));
        assert!(filter.limits.contains_key("file_write"));
        assert!(filter.limits.contains_key("http_request"));
        assert!(filter.limits.contains_key("file_read"));
        assert_eq!(filter.limits["shell_exec"].max_per_minute, 20);
        assert_eq!(filter.limits["file_write"].max_per_minute, 30);
        assert_eq!(filter.limits["http_request"].max_per_minute, 60);
    }

    #[tokio::test]
    async fn test_old_entries_pruned() {
        let filter = small_limit_filter();
        let now = Instant::now();

        // Make 5 calls that are more than 60 seconds old.
        let old_time = now - Duration::from_secs(120);
        for i in 0..5 {
            let ctx = make_ctx(ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec![],
            });
            let t = old_time + Duration::from_secs(i);
            let _ = filter.evaluate_at(&ctx, t).unwrap();
        }

        // A new call at `now` should not be affected by old calls.
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec![],
        });
        let result = filter.evaluate_at(&ctx, now).unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_classify_call_types() {
        assert_eq!(
            RateLimitFilter::classify_call(&ToolCallType::FileWrite {
                path: "/tmp".into(),
                content_hash: "abc".into()
            }),
            "file_write"
        );
        assert_eq!(
            RateLimitFilter::classify_call(&ToolCallType::FileDelete {
                path: "/tmp".into()
            }),
            "file_delete"
        );
    }
}
