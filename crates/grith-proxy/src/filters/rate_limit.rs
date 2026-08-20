// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Per-session rate limiting filter for tool call frequency.
//!
//! # Scoping (PR 1)
//!
//! Rate-limit counters key by `(session_scope, category)`. Unlike `taint`,
//! this filter does NOT honour `conversation_id` — rate windows are
//! intrinsically per-process-lifetime, and an OpenClaw conversation that
//! crosses daemon sessions correctly resets its rate budget per session.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, TaintLevel, ToolCallContext, ToolCallType};
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
    /// When true, the volume penalties (burst/rate/approaching) fire only for
    /// *risk-bearing* operations (`is_burst_risk_relevant`), not every category
    /// burst — so routine churn never escalates and the per-pattern scratch /
    /// `.git` / `~/.cache` exemptions are no longer needed (they were retired).
    /// The untainted destructive-spree case this gate drops is covered by the
    /// supervisor's mass-destruction signal. See
    /// work/futurework/rate-limit-burst-redesign.md.
    ///
    /// **Production defaults to ON** via `ProxyRateLimitConfig` (rollout
    /// step 4), set through `with_risk_gated_burst`. This in-struct default
    /// stays `false` so direct test construction (`new`/`with_defaults`)
    /// exercises the legacy counter unless a test opts in.
    risk_gated_burst: bool,
}

impl RateLimitFilter {
    pub fn new(limits: HashMap<String, RateLimit>) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            limits,
            risk_gated_burst: false,
        }
    }

    /// Enable the risk-gated burst prototype (see module/redesign doc).
    #[must_use]
    pub fn with_risk_gated_burst(mut self, enabled: bool) -> Self {
        self.risk_gated_burst = enabled;
        self
    }

    /// Whether a burst of this operation is worth escalating. Volume is only a
    /// useful signal when the operations themselves bear risk; a burst of
    /// untainted routine file churn (builds, `~/.cache`, `.git/` metadata) is
    /// noise. Risk-bearing = tainted, network egress, or egress-capable spawn.
    fn is_burst_risk_relevant(ctx: &ToolCallContext) -> bool {
        if ctx.source_taint != TaintLevel::None {
            return true;
        }
        match &ctx.call_type {
            // Network egress: volume matters (brute-force / staged exfil).
            ToolCallType::NetConnect { .. } | ToolCallType::HttpRequest { .. } => true,
            // Spawns only when they can leave the machine (PR2 classification
            // via the supervisor-computed provenance flag).
            ToolCallType::ProcessSpawn { .. } => ctx
                .spawn_provenance
                .as_ref()
                .is_some_and(|p| p.is_outbound_capable),
            // File churn etc.: risk-bearing only if tainted (handled above).
            _ => false,
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

    /// Build the per-session, per-category key used to look up the timestamp
    /// window. PR 1 keys rate-limit state by `(session_scope, category)` so
    /// that bursts in one supervised session do not raise the counter for
    /// the next session. Falls back to a deterministic session-id-derived
    /// scope when `session_scope` is absent (e.g. legacy IPC callers).
    fn window_key(ctx: &ToolCallContext, category: &str) -> String {
        let scope = ctx.scope_or_warn("rate-limit");
        format!("{}\x00{}", scope.as_uuid(), category)
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
            ToolCallType::FileLink { .. } => "file_link".to_string(),
            ToolCallType::FileChmod { .. } => "file_chmod".to_string(),
            ToolCallType::DirCreate { .. } => "dir_create".to_string(),
            ToolCallType::NetConnect { .. } => "net_connect".to_string(),
            ToolCallType::NetListen { .. } => "net_listen".to_string(),
            ToolCallType::ProcessSpawn { .. } => "process_spawn".to_string(),
            ToolCallType::DnsQuery { .. } => "dns_query".to_string(),
            // PR 6 Phase B: category-2 syscalls.
            ToolCallType::OwnershipChange { .. } => "ownership_change".to_string(),
            ToolCallType::FilesystemMutation { .. } => "filesystem_mutation".to_string(),
            ToolCallType::CrossProcessAccess { .. } => "cross_process_access".to_string(),
            ToolCallType::NamespaceOp { .. } => "namespace_op".to_string(),
            ToolCallType::DbusMethodCall { .. } => "dbus_method_call".to_string(),
        }
    }

    /// Record a call and return (calls_in_last_minute, calls_in_burst_window).
    /// `window_key` is `(session_scope, category)` per PR 1; the lookup is
    /// session-scoped so bursts can't bleed across sessions.
    fn record_and_count(&self, window_key: &str, now: Instant) -> (u32, u32) {
        let mut windows = self.windows.lock().expect("lock poisoned");
        let timestamps = windows.entry(window_key.to_string()).or_default();

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
            None => return Ok(FilterResult::no_match("rate-limit")),
        };

        // Risk-gated burst (default on; rollout step 4): volume is only a
        // useful signal for *risk-bearing* operations. Skip recording AND all
        // volume penalties (burst/rate/approaching) for non-risk-relevant ops,
        // so a burst of untainted routine churn (builds, `~/.cache`, `.git/`
        // metadata, SQLite/scratch files) never escalates. This subsumes the
        // per-pattern scratch/`.git`/`~/.cache` exemptions PR 3 carved out one
        // at a time (now retired). The untainted *destructive-spree* case this
        // gate drops is covered by the supervisor's target-aware
        // mass-destruction signal. See work/futurework/rate-limit-burst-redesign.md.
        //
        // Skipped before `record_and_count` so non-risk ops don't inflate the
        // window a later risk-bearing op of the same category is measured
        // against — the burst window then counts only risk-bearing ops.
        if self.risk_gated_burst && !Self::is_burst_risk_relevant(ctx) {
            return Ok(FilterResult::no_match("rate-limit"));
        }

        let window_key = Self::window_key(ctx, &category);
        let (minute_count, burst_count) = self.record_and_count(&window_key, now);

        // Check for burst first (highest severity).
        if burst_count >= limit.burst_threshold {
            return Ok(FilterResult::matched(
                "rate-limit",
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
                "rate-limit",
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
                "rate-limit",
                "rate-approaching",
                1.0,
                Severity::Notice,
                format!(
                    "Approaching rate limit: {minute_count} '{category}' calls/min (limit: {})",
                    limit.max_per_minute
                ),
            ));
        }

        Ok(FilterResult::no_match("rate-limit"))
    }
}

#[async_trait::async_trait]
impl SecurityFilter for RateLimitFilter {
    fn name(&self) -> &str {
        "rate-limit"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Context
    }

    /// Drop rate-limit windows whose key starts with `<scope_uuid>\x00`.
    /// Called at session-end so burst counters do not survive into the next
    /// session, and during the session-start sweep for crashed-session
    /// recovery.
    fn evict_session_state(&self, scope: crate::types::SessionScopeKey) -> usize {
        let prefix = format!("{}\x00", scope.as_uuid());
        match self.windows.lock() {
            Ok(mut windows) => {
                let before = windows.len();
                windows.retain(|k, _| !k.starts_with(&prefix));
                before - windows.len()
            }
            Err(_) => 0,
        }
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        self.evaluate_at(ctx, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SessionScopeKey, ToolCallType};
    use uuid::Uuid;

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    /// Build a context that shares an existing session UUID. After PR 1 the
    /// rate-limit window is keyed by `(session_scope, category)`, so tests
    /// that accumulate calls in a window must use the same `session_id` for
    /// every call.
    fn make_ctx_in_session(call_type: ToolCallType, session_id: Uuid) -> ToolCallContext {
        ToolCallContext::new("test", call_type, session_id)
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
        let session = Uuid::new_v4();

        // shell_exec limit is 5/min, 80% = 4.
        // Make 4 calls (spaced out) to avoid burst.
        for i in 0..4 {
            let ctx = make_ctx_in_session(
                ToolCallType::ShellExec {
                    command: "ls".into(),
                    args: vec![],
                },
                session,
            );
            let t = now + Duration::from_secs(i * 10); // 10s apart
            let _ = filter.evaluate_at(&ctx, t).unwrap();
        }

        // 5th call should trigger "approaching" (5 > 4 = 80% of 5).
        let ctx = make_ctx_in_session(
            ToolCallType::ShellExec {
                command: "echo".into(),
                args: vec!["test".into()],
            },
            session,
        );
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
        let session = Uuid::new_v4();

        // Make 5 calls spaced out (to avoid burst).
        for i in 0..5 {
            let ctx = make_ctx_in_session(
                ToolCallType::ShellExec {
                    command: "ls".into(),
                    args: vec![],
                },
                session,
            );
            let t = now + Duration::from_secs(i * 10);
            let _ = filter.evaluate_at(&ctx, t).unwrap();
        }

        // 6th call exceeds the 5/min limit.
        let ctx = make_ctx_in_session(
            ToolCallType::ShellExec {
                command: "pwd".into(),
                args: vec![],
            },
            session,
        );
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
        let session = Uuid::new_v4();

        // Make 3 calls within 5 seconds (burst threshold is 3 for shell_exec).
        for i in 0..3 {
            let ctx = make_ctx_in_session(
                ToolCallType::ShellExec {
                    command: "ls".into(),
                    args: vec![],
                },
                session,
            );
            let t = now + Duration::from_millis(i * 100); // 100ms apart
            let _ = filter.evaluate_at(&ctx, t).unwrap();
        }

        // This triggers burst since 3 calls happened within 5s.
        // The 3rd call already had burst_count=3 which equals burst_threshold=3.
        // Let's check state by making one more call.
        let ctx = make_ctx_in_session(
            ToolCallType::ShellExec {
                command: "echo".into(),
                args: vec!["burst".into()],
            },
            session,
        );
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

    fn ctx_supervised_write(path: &str, session: Uuid, pid: u64) -> ToolCallContext {
        let mut ctx = ToolCallContext::new(
            "test",
            ToolCallType::FileWrite {
                path: path.into(),
                content_hash: "x".into(),
            },
            session,
        );
        ctx.arguments = serde_json::json!({"pid": pid});
        ctx
    }

    /// PR 3 Phase D: a tight burst of writes to `/var/tmp/etilqs_*`
    /// does NOT trip the rate-limit burst counter when the call is a
    /// supervisor event (pid in arguments).
    #[tokio::test]
    async fn scratch_etilqs_burst_does_not_trip_rate_limit() {
        let filter = small_limit_filter();
        let now = Instant::now();
        let session = Uuid::new_v4();
        let pid: u64 = 4242;

        for i in 0..20 {
            let ctx = ctx_supervised_write(&format!("/var/tmp/etilqs_{i:08x}"), session, pid);
            let result = filter
                .evaluate_at(&ctx, now + Duration::from_millis(i as u64 * 5))
                .unwrap();
            assert!(
                !result.matched,
                "scratch etilqs write #{i} must not fire rate-limit"
            );
        }
    }

    /// PR 3 Phase D: identical burst against a non-scratch path DOES
    /// trip the rate-limit. This is the regression guard that the
    /// exemption doesn't accidentally silence all writes.
    #[tokio::test]
    async fn non_scratch_burst_still_trips_rate_limit() {
        // Custom small-limit filter for file_write so the burst
        // threshold is achievable.
        let mut limits = HashMap::new();
        limits.insert(
            "file_write".to_string(),
            RateLimit {
                max_per_minute: 5,
                burst_threshold: 3,
            },
        );
        let filter = RateLimitFilter::new(limits);
        let now = Instant::now();
        let session = Uuid::new_v4();
        let pid: u64 = 4242;

        let mut tripped = false;
        for i in 0..10 {
            let ctx = ctx_supervised_write(&format!("/home/u/notes-{i}.txt"), session, pid);
            let result = filter
                .evaluate_at(&ctx, now + Duration::from_millis(i as u64 * 10))
                .unwrap();
            if result.matched {
                tripped = true;
                break;
            }
        }
        assert!(
            tripped,
            "non-scratch writes must still trip burst rate-limit"
        );
    }

    /// PR 3 Phase D: scratch exemption applies only to supervisor
    /// events (pid in arguments). LLM-path writes without a pid still
    /// hit the rate limiter.
    #[tokio::test]
    async fn scratch_exemption_requires_pid_in_arguments() {
        let mut limits = HashMap::new();
        limits.insert(
            "file_write".to_string(),
            RateLimit {
                max_per_minute: 5,
                burst_threshold: 3,
            },
        );
        let filter = RateLimitFilter::new(limits);
        let now = Instant::now();
        let session = Uuid::new_v4();

        let mut tripped = false;
        for i in 0..10 {
            // No pid in arguments — LLM-path shape.
            let ctx = make_ctx_in_session(
                ToolCallType::FileWrite {
                    path: format!("/var/tmp/etilqs_{i:08x}"),
                    content_hash: "x".into(),
                },
                session,
            );
            let result = filter
                .evaluate_at(&ctx, now + Duration::from_millis(i as u64 * 5))
                .unwrap();
            if result.matched {
                tripped = true;
                break;
            }
        }
        assert!(
            tripped,
            "LLM-path writes without a pid must not get the scratch exemption"
        );
    }

    fn file_write_burst_filter() -> RateLimitFilter {
        let mut limits = HashMap::new();
        limits.insert(
            "file_write".to_string(),
            RateLimit {
                max_per_minute: 5,
                burst_threshold: 3,
            },
        );
        RateLimitFilter::new(limits)
    }

    /// Prototype: with risk-gating ON, a burst of UNTAINTED routine writes
    /// does not escalate, but a burst of TAINTED writes still does.
    #[tokio::test]
    async fn risk_gated_burst_ignores_untainted_churn_fires_on_tainted() {
        let filter = file_write_burst_filter().with_risk_gated_burst(true);
        let now = Instant::now();

        // (1) Untainted routine burst (non-scratch path) → no escalation.
        let s1 = Uuid::new_v4();
        let mut tripped = false;
        for i in 0..10 {
            let ctx = ctx_supervised_write(&format!("/home/u/proj/build-{i}.o"), s1, 7);
            if filter
                .evaluate_at(&ctx, now + Duration::from_millis(i as u64 * 5))
                .unwrap()
                .matched
            {
                tripped = true;
                break;
            }
        }
        assert!(
            !tripped,
            "untainted routine burst must NOT escalate under risk-gating"
        );

        // (2) Tainted burst → still escalates.
        let s2 = Uuid::new_v4();
        let mut tripped2 = false;
        for i in 0..10 {
            let mut ctx = ctx_supervised_write(&format!("/home/u/proj/out-{i}.o"), s2, 7);
            ctx.source_taint = TaintLevel::High;
            if filter
                .evaluate_at(&ctx, now + Duration::from_millis(i as u64 * 5))
                .unwrap()
                .matched
            {
                tripped2 = true;
                break;
            }
        }
        assert!(
            tripped2,
            "tainted burst must still escalate under risk-gating"
        );
    }

    /// With risk-gating OFF (default), an untainted burst still trips — the
    /// prototype is opt-in and does not change shipped behaviour.
    #[tokio::test]
    async fn risk_gating_off_preserves_untainted_burst() {
        let filter = file_write_burst_filter(); // risk_gated_burst defaults false
        let now = Instant::now();
        let s = Uuid::new_v4();
        let mut tripped = false;
        for i in 0..10 {
            let ctx = ctx_supervised_write(&format!("/home/u/proj/x-{i}.o"), s, 7);
            if filter
                .evaluate_at(&ctx, now + Duration::from_millis(i as u64 * 5))
                .unwrap()
                .matched
            {
                tripped = true;
                break;
            }
        }
        assert!(
            tripped,
            "with gating off, untainted burst still trips (unchanged)"
        );
    }

    /// PR 1 Phase F: `evict_session_state(scope)` drops every window whose
    /// key starts with `<scope-uuid>\x00`. Other sessions' windows survive.
    #[tokio::test]
    async fn test_evict_drops_only_matching_session() {
        let filter = small_limit_filter();
        let now = Instant::now();
        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();

        // Populate both sessions' windows.
        for sid in [session_a, session_b] {
            let ctx = make_ctx_in_session(
                ToolCallType::ShellExec {
                    command: "ls".into(),
                    args: vec![],
                },
                sid,
            );
            let _ = filter.evaluate_at(&ctx, now).unwrap();
        }
        assert_eq!(filter.windows.lock().unwrap().len(), 2);

        // Evict only session A.
        let removed = filter.evict_session_state(SessionScopeKey::from_session_id(session_a));
        assert_eq!(removed, 1, "exactly one window should be removed");

        // Session B's window must still exist.
        let after = filter.windows.lock().unwrap();
        assert_eq!(after.len(), 1);
        let remaining_key = after.keys().next().unwrap().clone();
        assert!(
            remaining_key.starts_with(&format!("{}\x00", session_b)),
            "remaining window must belong to session B, was {remaining_key:?}"
        );
    }

    /// PR 1 isolation: a burst in session A must not raise the counter for a
    /// fresh session B. Before PR 1 the rate-limit map was keyed by category
    /// only, so this is a regression test against that bug.
    #[tokio::test]
    async fn test_cross_session_isolation() {
        let filter = small_limit_filter();
        let now = Instant::now();
        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();

        // Burst in session A — fires "burst-detected".
        for i in 0..3 {
            let ctx = make_ctx_in_session(
                ToolCallType::ShellExec {
                    command: "ls".into(),
                    args: vec![],
                },
                session_a,
            );
            let _ = filter
                .evaluate_at(&ctx, now + Duration::from_millis(i * 100))
                .unwrap();
        }

        // First call in session B should not see session A's burst.
        let ctx = make_ctx_in_session(
            ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec![],
            },
            session_b,
        );
        let result = filter
            .evaluate_at(&ctx, now + Duration::from_millis(500))
            .unwrap();
        assert!(
            !result.matched,
            "session B must not inherit session A's burst counter"
        );
    }
}
