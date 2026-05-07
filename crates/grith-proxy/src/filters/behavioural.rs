// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Behavioural profiling filter tracking session-level patterns.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
// NOTE(M-4): std::sync::Mutex is intentionally used here instead of
// tokio::sync::Mutex because the lock is never held across .await points.
// All lock acquisitions are scoped to synchronous blocks within the async
// evaluate() method, making std::sync::Mutex the more efficient choice.
use std::sync::Mutex;

/// A record of a past tool call for behavioural profiling.
#[derive(Debug, Clone)]
pub struct CallRecord {
    pub call_type: String,
    pub timestamp: DateTime<Utc>,
}

/// Maximum number of call records retained in the sliding window.
/// When exceeded, the oldest entries are trimmed to maintain a bounded
/// memory footprint and ensure the baseline reflects recent behaviour
/// rather than degrading over long sessions (L-11).
const MAX_HISTORY_SIZE: usize = 1000;

/// Filter that profiles agent behaviour over time, detecting deviations
/// from established baselines.
///
/// Runs in Phase 3 (Context) because it depends on accumulated session state.
///
/// During the cold-start period (fewer than `min_calls_for_profiling` calls),
/// the filter records data but always returns a zero score. Once the baseline
/// is established, it compares the current call type distribution against
/// the historical baseline and flags significant deviations.
///
/// The call history is capped at `MAX_HISTORY_SIZE` entries, creating a
/// sliding window so the baseline reflects recent session behaviour and
/// does not degrade over long-running sessions.
///
/// Scoring:
/// - `0.0` during cold-start (not enough data)
/// - `+1.0` for mild deviation (call type is rare but seen before)
/// - `+2.0` for moderate deviation (call type proportion is far from baseline)
/// - `+3.0` for significant anomaly (call type never seen before in baseline)
pub struct BehaviouralFilter {
    call_history: Mutex<Vec<CallRecord>>,
    min_calls_for_profiling: usize,
    max_history_size: usize,
}

impl BehaviouralFilter {
    pub fn new(min_calls_for_profiling: usize) -> Self {
        Self {
            call_history: Mutex::new(Vec::new()),
            min_calls_for_profiling,
            max_history_size: MAX_HISTORY_SIZE,
        }
    }

    /// Create a filter with the default warm-up period (200 calls).
    pub fn with_defaults() -> Self {
        Self::new(200)
    }

    /// Whether the filter has accumulated enough data to produce meaningful scores.
    pub fn is_profiling_ready(&self) -> bool {
        let history = self.call_history.lock().expect("lock poisoned");
        history.len() >= self.min_calls_for_profiling
    }

    /// Get the number of recorded calls.
    pub fn call_count(&self) -> usize {
        let history = self.call_history.lock().expect("lock poisoned");
        history.len()
    }

    /// Classify a `ToolCallType` into a static string category for profiling.
    fn classify_call(call_type: &ToolCallType) -> &'static str {
        match call_type {
            ToolCallType::FileRead { .. } => "file_read",
            ToolCallType::FileWrite { .. } => "file_write",
            ToolCallType::FileAppend { .. } => "file_append",
            ToolCallType::FileDelete { .. } => "file_delete",
            ToolCallType::DirList { .. } => "dir_list",
            ToolCallType::ShellExec { .. } => "shell_exec",
            ToolCallType::HttpRequest { .. } => "http_request",
            ToolCallType::FileRename { .. } => "file_rename",
            ToolCallType::FileChmod { .. } => "file_chmod",
            ToolCallType::DirCreate { .. } => "dir_create",
            ToolCallType::NetConnect { .. } => "net_connect",
            ToolCallType::NetListen { .. } => "net_listen",
            ToolCallType::ProcessSpawn { .. } => "process_spawn",
            ToolCallType::DnsQuery { .. } => "dns_query",
        }
    }

    /// Compute the baseline distribution from the call history.
    fn compute_baseline(history: &[CallRecord]) -> HashMap<String, f64> {
        let total = history.len() as f64;
        if total == 0.0 {
            return HashMap::new();
        }

        let mut counts: HashMap<String, usize> = HashMap::new();
        for record in history {
            *counts.entry(record.call_type.clone()).or_default() += 1;
        }

        counts
            .into_iter()
            .map(|(k, v)| (k, v as f64 / total))
            .collect()
    }
}

#[async_trait::async_trait]
impl SecurityFilter for BehaviouralFilter {
    fn name(&self) -> &str {
        "behavioural"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Context
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let call_category = Self::classify_call(&ctx.call_type);

        // Always record the call for future profiling.
        // Trim oldest entries when the history exceeds the maximum size,
        // creating a sliding window that keeps the baseline fresh (M-1, L-11).
        {
            let mut history = self.call_history.lock().expect("lock poisoned");
            history.push(CallRecord {
                call_type: call_category.to_string(),
                timestamp: ctx.timestamp,
            });
            if history.len() > self.max_history_size {
                let excess = history.len() - self.max_history_size;
                history.drain(..excess);
            }
        }

        // During cold-start, return no-match (zero score).
        let history = self.call_history.lock().expect("lock poisoned");
        if history.len() < self.min_calls_for_profiling {
            return Ok(FilterResult::no_match("behavioural"));
        }

        // Compute baseline from all history except the current call (last entry).
        let baseline_history = &history[..history.len() - 1];
        let baseline = Self::compute_baseline(baseline_history);

        let baseline_proportion = baseline.get(call_category).copied().unwrap_or(0.0);

        // Score based on how unusual this call type is relative to baseline.
        if baseline_proportion == 0.0 {
            // Call type never seen before in baseline period - significant anomaly.
            Ok(FilterResult::matched(
                "behavioural",
                "unseen-call-type",
                3.0,
                Severity::Warning,
                format!(
                    "Call type '{call_category}' never observed in baseline of {} calls",
                    baseline_history.len()
                ),
            ))
        } else if baseline_proportion < 0.02 {
            // Very rare call type (less than 2% of baseline) - moderate deviation.
            Ok(FilterResult::matched(
                "behavioural",
                "rare-call-type",
                2.0,
                Severity::Warning,
                format!(
                    "Call type '{call_category}' is rare ({:.1}% of baseline)",
                    baseline_proportion * 100.0
                ),
            ))
        } else if baseline_proportion < 0.05 {
            // Uncommon call type (less than 5% of baseline) - mild deviation.
            Ok(FilterResult::matched(
                "behavioural",
                "uncommon-call-type",
                1.0,
                Severity::Notice,
                format!(
                    "Call type '{call_category}' is uncommon ({:.1}% of baseline)",
                    baseline_proportion * 100.0
                ),
            ))
        } else {
            // Normal call type - no flag.
            Ok(FilterResult::no_match("behavioural"))
        }
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

    #[tokio::test]
    async fn test_cold_start_returns_no_match() {
        let filter = BehaviouralFilter::new(10);
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/test.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
        assert_eq!(result.score, 0.0);
    }

    #[tokio::test]
    async fn test_records_calls_during_cold_start() {
        let filter = BehaviouralFilter::new(100);
        for _ in 0..5 {
            let ctx = make_ctx(ToolCallType::FileRead {
                path: "/tmp/test.txt".into(),
            });
            let _ = filter.evaluate(&ctx).await.unwrap();
        }
        assert_eq!(filter.call_count(), 5);
        assert!(!filter.is_profiling_ready());
    }

    #[tokio::test]
    async fn test_normal_call_after_warmup() {
        let filter = BehaviouralFilter::new(10);

        // Build a baseline of mostly file reads.
        for _ in 0..10 {
            let ctx = make_ctx(ToolCallType::FileRead {
                path: "/tmp/test.txt".into(),
            });
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        // Another file read should be normal.
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/other.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_unseen_call_type_flagged() {
        let filter = BehaviouralFilter::new(10);

        // Build a baseline of only file reads.
        for _ in 0..10 {
            let ctx = make_ctx(ToolCallType::FileRead {
                path: "/tmp/test.txt".into(),
            });
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        // An HTTP request has never been seen - should be flagged as anomaly.
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://evil.com/data".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 3.0);
        assert_eq!(result.rule_id, "unseen-call-type");
    }

    #[tokio::test]
    async fn test_rare_call_type_flagged() {
        let filter = BehaviouralFilter::new(100);

        // Build a baseline: 99 file reads, 1 shell exec.
        for _ in 0..99 {
            let ctx = make_ctx(ToolCallType::FileRead {
                path: "/tmp/test.txt".into(),
            });
            let _ = filter.evaluate(&ctx).await.unwrap();
        }
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec![],
        });
        let _ = filter.evaluate(&ctx).await.unwrap();

        // Now shell_exec is ~1% of baseline (1/100) - should be rare.
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "echo".into(),
            args: vec!["hello".into()],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 2.0);
        assert_eq!(result.rule_id, "rare-call-type");
    }

    #[tokio::test]
    async fn test_is_profiling_ready() {
        let filter = BehaviouralFilter::new(5);
        assert!(!filter.is_profiling_ready());

        for _ in 0..5 {
            let ctx = make_ctx(ToolCallType::FileRead {
                path: "/tmp/test.txt".into(),
            });
            let _ = filter.evaluate(&ctx).await.unwrap();
        }
        assert!(filter.is_profiling_ready());
    }

    #[tokio::test]
    async fn test_classify_call_categories() {
        assert_eq!(
            BehaviouralFilter::classify_call(&ToolCallType::FileRead {
                path: "/tmp".into()
            }),
            "file_read"
        );
        assert_eq!(
            BehaviouralFilter::classify_call(&ToolCallType::FileWrite {
                path: "/tmp".into(),
                content_hash: "abc".into()
            }),
            "file_write"
        );
        assert_eq!(
            BehaviouralFilter::classify_call(&ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec![]
            }),
            "shell_exec"
        );
        assert_eq!(
            BehaviouralFilter::classify_call(&ToolCallType::HttpRequest {
                method: "GET".into(),
                url: "https://x.com".into()
            }),
            "http_request"
        );
    }

    #[tokio::test]
    async fn test_history_trimmed_at_max_size() {
        // M-1 & L-11: Verify that the call history is bounded and acts
        // as a sliding window rather than growing unboundedly.
        let mut filter = BehaviouralFilter::new(5);
        filter.max_history_size = 20; // Small cap for testing

        // Push 25 calls — history should be trimmed to 20.
        for _ in 0..25 {
            let ctx = make_ctx(ToolCallType::FileRead {
                path: "/tmp/test.txt".into(),
            });
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        assert_eq!(filter.call_count(), 20);
    }
}
