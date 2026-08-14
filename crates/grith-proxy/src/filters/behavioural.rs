// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Behavioural profiling filter tracking session-level patterns.
//!
//! # Scoping (PR 1)
//!
//! Call histories key by `session_scope` — each supervised session builds its
//! own baseline. Unlike `taint`, this filter does NOT honour `conversation_id`:
//! a behavioural baseline is intrinsically per-process-lifetime, and an
//! OpenClaw conversation that crosses daemon sessions correctly cold-starts
//! a fresh baseline in each.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, SessionScopeKey, Severity, ToolCallContext, ToolCallType};
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

/// PR 69 Change 2: routine ToolCallType categories that are part of every
/// agent's normal traffic. The cold-start anomaly rules
/// (`unseen-call-type` / `rare-call-type` / `uncommon-call-type`) do not
/// fire when the current call's category is in this set, because warming
/// the baseline through routine startup traffic should not score the next
/// instance of an ordinary file/net/process op.
///
/// PR 6 authority-changing categories (`ownership_change`,
/// `filesystem_mutation`, `cross_process_access`, `namespace_op`) are
/// **intentionally absent** so the anomaly rules still fire for them.
const ROUTINE_CALL_CATEGORIES: &[&str] = &[
    "file_read",
    "file_write",
    "file_append",
    "file_delete",
    "file_rename",
    "file_chmod",
    "dir_create",
    "dir_list",
    "shell_exec",
    "process_spawn",
    "net_connect",
    "net_listen",
    "dns_query",
    "http_request",
];

fn is_routine_call_category(category: &str) -> bool {
    ROUTINE_CALL_CATEGORIES.contains(&category)
}

/// PR 69 Change 1: operator-tunable scoring parameters. The previous
/// daemon constructor hard-coded `min_calls_for_baseline = 20` while
/// `config/default.toml` advertised 200; this struct is the bridge that
/// makes the runtime match the declared config.
#[derive(Debug, Clone)]
pub struct BehaviouralConfig {
    /// Minimum per-session call count before any anomaly rule fires.
    pub min_calls_for_baseline: usize,
    /// Score assigned to `uncommon-call-type` matches (< 5% of baseline).
    pub mild_deviation_score: f64,
    /// Score assigned to `unseen-call-type` matches (never observed in
    /// baseline). `rare-call-type` (< 2% of baseline) keeps a fixed
    /// midpoint score of 2.0; making it operator-tunable was not part of
    /// the PR 69 work item.
    pub significant_deviation_score: f64,
}

impl Default for BehaviouralConfig {
    fn default() -> Self {
        Self {
            min_calls_for_baseline: 200,
            mild_deviation_score: 1.0,
            significant_deviation_score: 3.0,
        }
    }
}

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
/// Scoring (after warm-up):
/// - `mild_deviation_score` for uncommon call types (< 5% of baseline)
/// - `2.0` for rare call types (< 2% of baseline) — fixed midpoint
/// - `significant_deviation_score` for unseen call types
///
/// PR 69 Change 2: when the current call's category is in
/// [`ROUTINE_CALL_CATEGORIES`], all three rules are suppressed even
/// after warm-up. PR 6 authority-changing categories are excluded from
/// the routine set so their anomaly signal still fires.
pub struct BehaviouralFilter {
    /// Per-session call history. PR 1 keys behavioural baselines by scope so
    /// one session cannot influence another's anomaly detector.
    call_history: Mutex<HashMap<SessionScopeKey, Vec<CallRecord>>>,
    min_calls_for_profiling: usize,
    mild_deviation_score: f64,
    significant_deviation_score: f64,
    max_history_size: usize,
}

impl BehaviouralFilter {
    pub fn new(min_calls_for_profiling: usize) -> Self {
        Self::from_config(&BehaviouralConfig {
            min_calls_for_baseline: min_calls_for_profiling,
            ..BehaviouralConfig::default()
        })
    }

    /// PR 69 Change 1: build the filter from an operator-supplied config.
    pub fn from_config(cfg: &BehaviouralConfig) -> Self {
        Self {
            call_history: Mutex::new(HashMap::new()),
            min_calls_for_profiling: cfg.min_calls_for_baseline,
            mild_deviation_score: cfg.mild_deviation_score,
            significant_deviation_score: cfg.significant_deviation_score,
            max_history_size: MAX_HISTORY_SIZE,
        }
    }

    /// Create a filter with the default warm-up period (200 calls).
    pub fn with_defaults() -> Self {
        Self::from_config(&BehaviouralConfig::default())
    }

    /// Whether *any* session has accumulated enough data to produce meaningful
    /// scores. For per-session readiness, use [`is_profiling_ready_for`].
    pub fn is_profiling_ready(&self) -> bool {
        let history = self.call_history.lock().expect("lock poisoned");
        history
            .values()
            .any(|v| v.len() >= self.min_calls_for_profiling)
    }

    /// Whether the specific session has accumulated enough data.
    pub fn is_profiling_ready_for(&self, scope: SessionScopeKey) -> bool {
        let history = self.call_history.lock().expect("lock poisoned");
        history
            .get(&scope)
            .map(|v| v.len() >= self.min_calls_for_profiling)
            .unwrap_or(false)
    }

    /// Total recorded calls across all sessions. For per-session counts, use
    /// [`call_count_for`].
    pub fn call_count(&self) -> usize {
        let history = self.call_history.lock().expect("lock poisoned");
        history.values().map(|v| v.len()).sum()
    }

    /// Per-session recorded call count.
    pub fn call_count_for(&self, scope: SessionScopeKey) -> usize {
        let history = self.call_history.lock().expect("lock poisoned");
        history.get(&scope).map(|v| v.len()).unwrap_or(0)
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
            ToolCallType::FileLink { .. } => "file_link",
            ToolCallType::FileChmod { .. } => "file_chmod",
            ToolCallType::DirCreate { .. } => "dir_create",
            ToolCallType::NetConnect { .. } => "net_connect",
            ToolCallType::NetListen { .. } => "net_listen",
            ToolCallType::ProcessSpawn { .. } => "process_spawn",
            ToolCallType::DnsQuery { .. } => "dns_query",
            // PR 6 Phase B: category-2 syscalls.
            ToolCallType::OwnershipChange { .. } => "ownership_change",
            ToolCallType::FilesystemMutation { .. } => "filesystem_mutation",
            ToolCallType::CrossProcessAccess { .. } => "cross_process_access",
            ToolCallType::NamespaceOp { .. } => "namespace_op",
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

    /// Drop this session's per-scope call history. Used by the session-end
    /// hook and session-start sweep. Returns the number of records dropped
    /// for telemetry — useful for spotting unusually large session
    /// histories (e.g. an LLM that's been spamming calls).
    fn evict_session_state(&self, scope: crate::types::SessionScopeKey) -> usize {
        match self.call_history.lock() {
            Ok(mut history) => history.remove(&scope).map(|v| v.len()).unwrap_or(0),
            Err(_) => 0,
        }
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let call_category = Self::classify_call(&ctx.call_type);
        let scope = ctx.scope_or_warn("behavioural");

        // Always record the call for future profiling, scoped to this session.
        // Trim oldest entries when the per-session history exceeds the max,
        // creating a sliding window that keeps the baseline fresh (M-1, L-11).
        {
            let mut history = self.call_history.lock().expect("lock poisoned");
            let entry = history.entry(scope).or_default();
            entry.push(CallRecord {
                call_type: call_category.to_string(),
                timestamp: ctx.timestamp,
            });
            if entry.len() > self.max_history_size {
                let excess = entry.len() - self.max_history_size;
                entry.drain(..excess);
            }
        }

        // During cold-start (for this session), return no-match (zero score).
        let history = self.call_history.lock().expect("lock poisoned");
        let session_history = match history.get(&scope) {
            Some(h) => h,
            None => return Ok(FilterResult::no_match("behavioural")),
        };
        if session_history.len() < self.min_calls_for_profiling {
            return Ok(FilterResult::no_match("behavioural"));
        }

        // Compute baseline from this session's history except the current call.
        let baseline_history = &session_history[..session_history.len() - 1];
        let baseline = Self::compute_baseline(baseline_history);

        let baseline_proportion = baseline.get(call_category).copied().unwrap_or(0.0);

        // PR 69 Change 2: routine call categories are part of every
        // agent's normal traffic. Skip the anomaly rules for them so
        // ordinary file/net/process ops don't queue post-warmup.
        if is_routine_call_category(call_category) {
            return Ok(FilterResult::no_match("behavioural"));
        }

        // Score based on how unusual this call type is relative to baseline.
        if baseline_proportion == 0.0 {
            // Call type never seen before in baseline period - significant anomaly.
            Ok(FilterResult::matched(
                "behavioural",
                "unseen-call-type",
                self.significant_deviation_score,
                Severity::Warning,
                format!(
                    "Call type '{call_category}' never observed in baseline of {} calls",
                    baseline_history.len()
                ),
            ))
        } else if baseline_proportion < 0.02 {
            // Very rare call type (less than 2% of baseline) - moderate deviation.
            // Fixed midpoint score (operator-tunable scores cover only the
            // mild/significant ends; PR 69 Change 1 work-doc).
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
                self.mild_deviation_score,
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

    /// Build a context that shares an existing session UUID. After PR 1 the
    /// behavioural baseline is keyed by session_scope, so warm-up calls must
    /// all share the same session_id to accumulate in one baseline.
    fn make_ctx_in_session(call_type: ToolCallType, session_id: Uuid) -> ToolCallContext {
        ToolCallContext::new("test", call_type, session_id)
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
        let session = Uuid::new_v4();
        for _ in 0..5 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }
        assert_eq!(filter.call_count(), 5);
        assert!(!filter.is_profiling_ready());
    }

    #[tokio::test]
    async fn test_normal_call_after_warmup() {
        let filter = BehaviouralFilter::new(10);
        let session = Uuid::new_v4();

        // Build a baseline of mostly file reads.
        for _ in 0..10 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        // Another file read should be normal.
        let ctx = make_ctx_in_session(
            ToolCallType::FileRead {
                path: "/tmp/other.txt".into(),
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    /// PR 69 Change 2: after warm-up, a non-routine category (PR 6
    /// authority-changing op such as `NamespaceOp`) that the baseline
    /// has never seen still fires `unseen-call-type`.
    #[tokio::test]
    async fn test_unseen_call_type_flagged() {
        let filter = BehaviouralFilter::new(10);
        let session = Uuid::new_v4();

        // Build a baseline of only file reads.
        for _ in 0..10 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        // A namespace op has never been seen and is NOT in the routine
        // category set — should fire as unseen.
        let ctx = make_ctx_in_session(
            ToolCallType::NamespaceOp {
                syscall: "unshare".into(),
                flags: 0,
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 3.0);
        assert_eq!(result.rule_id, "unseen-call-type");
    }

    /// PR 69 Change 2: after warm-up, a non-routine category at <2%
    /// of baseline still fires `rare-call-type`.
    #[tokio::test]
    async fn test_rare_call_type_flagged() {
        let filter = BehaviouralFilter::new(100);
        let session = Uuid::new_v4();

        // Build a baseline: 99 file reads, 1 ownership change.
        for _ in 0..99 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }
        let ctx = make_ctx_in_session(
            ToolCallType::OwnershipChange {
                target: "/etc/passwd".into(),
                new_uid: 0,
                new_gid: 0,
            },
            session,
        );
        let _ = filter.evaluate(&ctx).await.unwrap();

        // Now ownership_change is ~1% of baseline and is NOT routine —
        // should fire as rare.
        let ctx = make_ctx_in_session(
            ToolCallType::OwnershipChange {
                target: "/tmp/foo".into(),
                new_uid: 1000,
                new_gid: 1000,
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 2.0);
        assert_eq!(result.rule_id, "rare-call-type");
    }

    /// PR 69 Change 2: routine categories (FileRead/Write/Rename, etc.)
    /// must NOT fire any of the anomaly rules even after warm-up,
    /// regardless of whether the baseline has seen them. This is the
    /// fix for the codex prompt-flood — first FileWrite/FileRead in a
    /// session should not score behaviourally.
    #[tokio::test]
    async fn test_routine_category_never_fires_after_warmup() {
        let filter = BehaviouralFilter::new(10);
        let session = Uuid::new_v4();

        // Warm baseline with shell_exec (also routine, but the point is
        // that file_write never appears in the baseline).
        for _ in 0..15 {
            let ctx = make_ctx_in_session(
                ToolCallType::ShellExec {
                    command: "ls".into(),
                    args: vec![],
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        // First file_write — would be `unseen-call-type` under the old
        // logic. With the routine guard, no_match.
        let ctx = make_ctx_in_session(
            ToolCallType::FileWrite {
                path: "/var/tmp/etilqs_abc".into(),
                content_hash: "abc".into(),
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched, "routine FileWrite must not fire");

        // First file_rename — same story.
        let ctx = make_ctx_in_session(
            ToolCallType::FileRename {
                old_path: "/tmp/node-compile-cache/v22/abc.tmp".into(),
                new_path: "/tmp/node-compile-cache/v22/abc".into(),
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched, "routine FileRename must not fire");
    }

    /// PR 69 Change 2: PR 6 authority-changing categories must STILL
    /// fire the anomaly rules — they are intentionally excluded from
    /// the routine set.
    #[tokio::test]
    async fn test_pr6_categories_still_fire_after_warmup() {
        let filter = BehaviouralFilter::new(10);
        let session = Uuid::new_v4();

        for _ in 0..15 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/x".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        for (call, label) in [
            (
                ToolCallType::OwnershipChange {
                    target: "/etc/x".into(),
                    new_uid: 0,
                    new_gid: 0,
                },
                "OwnershipChange",
            ),
            (
                ToolCallType::FilesystemMutation {
                    op: "mount".into(),
                    source: None,
                    target: "/mnt/x".into(),
                    fstype: Some("tmpfs".into()),
                },
                "FilesystemMutation",
            ),
            (
                ToolCallType::CrossProcessAccess {
                    op: "ptrace".into(),
                    target_pid: 999,
                },
                "CrossProcessAccess",
            ),
            (
                ToolCallType::NamespaceOp {
                    syscall: "unshare".into(),
                    flags: 0,
                },
                "NamespaceOp",
            ),
        ] {
            let ctx = make_ctx_in_session(call, session);
            let result = filter.evaluate(&ctx).await.unwrap();
            assert!(
                result.matched,
                "{label} must still fire (not in routine set)"
            );
            assert_eq!(result.rule_id, "unseen-call-type", "{label}");
        }
    }

    /// PR 69 Change 1: `from_config` honours operator-supplied scores.
    #[tokio::test]
    async fn test_from_config_overrides_scores() {
        let cfg = BehaviouralConfig {
            min_calls_for_baseline: 10,
            mild_deviation_score: 0.25,
            significant_deviation_score: 1.75,
        };
        let filter = BehaviouralFilter::from_config(&cfg);
        let session = Uuid::new_v4();

        for _ in 0..10 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/x".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        let ctx = make_ctx_in_session(
            ToolCallType::NamespaceOp {
                syscall: "unshare".into(),
                flags: 0,
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(result.score, 1.75, "significant_deviation_score honoured");
    }

    #[tokio::test]
    async fn test_is_profiling_ready() {
        let filter = BehaviouralFilter::new(5);
        let session = Uuid::new_v4();
        assert!(!filter.is_profiling_ready());

        for _ in 0..5 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }
        assert!(filter.is_profiling_ready());
        assert!(filter.is_profiling_ready_for(SessionScopeKey::from_session_id(session)));
    }

    /// PR 1 Phase F: `evict_session_state(scope)` drops the per-session
    /// history vector entirely. Other sessions' histories remain.
    #[tokio::test]
    async fn test_evict_drops_only_matching_session() {
        let filter = BehaviouralFilter::new(10);
        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();

        for _ in 0..5 {
            let ctx_a = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/a.txt".into(),
                },
                session_a,
            );
            let _ = filter.evaluate(&ctx_a).await.unwrap();

            let ctx_b = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/b.txt".into(),
                },
                session_b,
            );
            let _ = filter.evaluate(&ctx_b).await.unwrap();
        }
        assert_eq!(filter.call_count(), 10);

        let removed = filter.evict_session_state(SessionScopeKey::from_session_id(session_a));
        assert_eq!(removed, 5, "session A had 5 entries");
        assert_eq!(filter.call_count(), 5, "session B's 5 entries remain");
        assert_eq!(
            filter.call_count_for(SessionScopeKey::from_session_id(session_b)),
            5
        );
        assert_eq!(
            filter.call_count_for(SessionScopeKey::from_session_id(session_a)),
            0
        );
    }

    /// PR 1 isolation: warming session A's baseline must not make session B
    /// look "ready", and an anomaly in session B (where the baseline is cold)
    /// must not fire — there's no baseline to deviate from yet.
    #[tokio::test]
    async fn test_cross_session_isolation() {
        let filter = BehaviouralFilter::new(10);
        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();

        // Warm session A with 10 file reads.
        for _ in 0..10 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session_a,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        // First call in session B (HTTP) — would have fired "unseen-call-type"
        // under the old global-state behaviour. Under PR 1 the session B
        // baseline is empty, so cold-start returns no-match.
        let ctx = make_ctx_in_session(
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://evil.com".into(),
            },
            session_b,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            !result.matched,
            "session B should be in cold-start despite session A being warm"
        );
        assert!(!filter.is_profiling_ready_for(SessionScopeKey::from_session_id(session_b)));
        assert!(filter.is_profiling_ready_for(SessionScopeKey::from_session_id(session_a)));
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
        // as a sliding window rather than growing unboundedly. After PR 1
        // the cap applies per-session, so all 25 calls share one session.
        let mut filter = BehaviouralFilter::new(5);
        filter.max_history_size = 20; // Small cap for testing
        let session = Uuid::new_v4();

        // Push 25 calls — history should be trimmed to 20.
        for _ in 0..25 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        assert_eq!(filter.call_count(), 20);
    }
}
