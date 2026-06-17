// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Security proxy pipeline engine.
//!
//! Evaluates tool calls through multi-phase filter execution with additive scoring.

use crate::filters::{FilterInfo, FilterPhase, FilterRegistry};
use crate::meta_rules::MetaRuleEngine;
use crate::scoring::{self, ScoringConfig};
use crate::types::{FilterResult, ProxyAction, ProxyDecision, ToolCallContext};
use futures::future::join_all;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// The security proxy pipeline orchestrator.
pub struct SecurityProxy {
    registry: FilterRegistry,
    scoring: ScoringConfig,
    meta_rules: MetaRuleEngine,
    call_count: AtomicU64,
    allow_count: AtomicU64,
    queue_count: AtomicU64,
    deny_count: AtomicU64,
}

impl SecurityProxy {
    /// Create a new security proxy with the given filters, scoring config, and meta-rules.
    ///
    pub fn new(
        registry: FilterRegistry,
        scoring: ScoringConfig,
        meta_rules: MetaRuleEngine,
    ) -> Self {
        Self {
            registry,
            scoring,
            meta_rules,
            call_count: AtomicU64::new(0),
            allow_count: AtomicU64::new(0),
            queue_count: AtomicU64::new(0),
            deny_count: AtomicU64::new(0),
        }
    }

    /// Drop scope-keyed filter state for `scope` AND the corresponding entry
    /// in `SessionStateRegistry`. Returns the number of entries removed
    /// across all filters (for telemetry — useful for spotting unusually
    /// large session footprints).
    ///
    /// PR 1 Phase F: called by the supervisor at session-end and for each
    /// stale scope discovered at session-start.
    pub fn evict_session_state(&self, scope: crate::types::SessionScopeKey) -> usize {
        let removed = self.registry.evict_session_state(scope);
        crate::session_state::SessionStateRegistry::global().evict(scope);
        removed
    }

    /// Evaluate a tool call through the full filter pipeline.
    pub async fn evaluate(&self, ctx: &ToolCallContext) -> ProxyDecision {
        let start = Instant::now();
        self.call_count.fetch_add(1, Ordering::Relaxed);
        let (allow_threshold, deny_threshold) = self.scoring.thresholds();

        let mut all_results = Vec::new();

        // Phase 1: Static filters (parallel)
        let phase1 = self.run_phase(FilterPhase::Static, ctx).await;
        all_results.extend(phase1);
        let score = scoring::aggregate(&all_results);
        if scoring::exceeds_deny(score, deny_threshold) {
            let decision = scoring::route_decision(
                score,
                all_results,
                allow_threshold,
                deny_threshold,
                start.elapsed(),
            );
            self.record_decision(&decision);
            return decision;
        }

        // Phase 2: Pattern filters (parallel)
        let phase2 = self.run_phase(FilterPhase::Pattern, ctx).await;
        all_results.extend(phase2);
        let score = scoring::aggregate(&all_results);
        if scoring::exceeds_deny(score, deny_threshold) {
            let decision = scoring::route_decision(
                score,
                all_results,
                allow_threshold,
                deny_threshold,
                start.elapsed(),
            );
            self.record_decision(&decision);
            return decision;
        }

        // Phase 3: Context filters (parallel, only if ready)
        let phase3 = self.run_phase(FilterPhase::Context, ctx).await;
        all_results.extend(phase3);

        // Meta-rules: composite adjustments
        let mut score = scoring::aggregate(&all_results);
        score += self.meta_rules.evaluate(&all_results, ctx);

        // Note: adaptive scoring is now handled by the reputation system
        // in the supervisor event handler, not in the proxy pipeline.

        let decision = scoring::route_decision(
            score,
            all_results,
            allow_threshold,
            deny_threshold,
            start.elapsed(),
        );
        self.record_decision(&decision);
        decision
    }

    fn record_decision(&self, decision: &ProxyDecision) {
        match decision.action {
            ProxyAction::Allow => {
                self.allow_count.fetch_add(1, Ordering::Relaxed);
            }
            ProxyAction::Queue { .. } => {
                self.queue_count.fetch_add(1, Ordering::Relaxed);
            }
            ProxyAction::Deny { .. } => {
                self.deny_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Run all filters in a given phase concurrently, recording per-filter metrics.
    ///
    /// Uses `futures::future::join_all` to run filters concurrently within the
    /// current task, avoiding the `'static` requirement of `tokio::spawn`.
    async fn run_phase(&self, phase: FilterPhase, ctx: &ToolCallContext) -> Vec<FilterResult> {
        let filters_with_metrics = self.registry.filters_for_phase_with_metrics(phase);
        if filters_with_metrics.is_empty() {
            return Vec::new();
        }

        let futures: Vec<_> = filters_with_metrics
            .iter()
            .map(|(filter, metrics)| {
                let metrics = metrics.clone();
                async move {
                    let start = Instant::now();
                    let result = match filter.evaluate(ctx).await {
                        Ok(result) => result,
                        Err(e) => {
                            tracing::warn!(
                                filter = %filter.name(),
                                error = %e,
                                "filter evaluation failed"
                            );
                            FilterResult::no_match(filter.name())
                        }
                    };
                    metrics.record(start.elapsed());
                    result
                }
            })
            .collect();

        join_all(futures).await
    }

    pub fn call_count(&self) -> u64 {
        self.call_count.load(Ordering::Relaxed)
    }

    pub fn allow_count(&self) -> u64 {
        self.allow_count.load(Ordering::Relaxed)
    }

    pub fn queue_count(&self) -> u64 {
        self.queue_count.load(Ordering::Relaxed)
    }

    pub fn deny_count(&self) -> u64 {
        self.deny_count.load(Ordering::Relaxed)
    }

    pub fn filter_count(&self) -> usize {
        self.registry.count()
    }

    pub fn scoring_config(&self) -> &ScoringConfig {
        &self.scoring
    }

    pub fn filter_info(&self) -> Vec<FilterInfo> {
        self.registry.filter_info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::SecurityFilter;
    use crate::types::*;

    /// A test filter that always returns a fixed result.
    struct FixedFilter {
        name: String,
        phase: FilterPhase,
        result: FilterResult,
    }

    #[async_trait::async_trait]
    impl SecurityFilter for FixedFilter {
        fn name(&self) -> &str {
            &self.name
        }
        fn phase(&self) -> FilterPhase {
            self.phase
        }
        async fn evaluate(&self, _ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
            Ok(self.result.clone())
        }
    }

    fn make_ctx() -> ToolCallContext {
        ToolCallContext::new(
            "test",
            ToolCallType::FileRead {
                path: "/tmp/safe.txt".into(),
            },
            uuid::Uuid::new_v4(),
        )
    }

    fn make_proxy(filters: Vec<Box<dyn SecurityFilter>>) -> SecurityProxy {
        make_proxy_with_scoring(filters, ScoringConfig::default())
    }

    fn make_proxy_with_scoring(
        filters: Vec<Box<dyn SecurityFilter>>,
        scoring: ScoringConfig,
    ) -> SecurityProxy {
        let mut registry = FilterRegistry::new();
        for f in filters {
            registry.register(f);
        }
        SecurityProxy::new(registry, scoring, MetaRuleEngine::new(vec![]))
    }

    /// PR 1 Phase F: `SecurityProxy::evict_session_state` walks every
    /// registered filter and clears the corresponding `SessionStateRegistry`
    /// entry. Filters that opt into the default `evict_session_state`
    /// (no-op) contribute zero; scoping filters return their counts.
    #[tokio::test]
    async fn evict_session_state_fans_out_to_filters() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingFilter {
            calls: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl SecurityFilter for CountingFilter {
            fn name(&self) -> &str {
                "counting"
            }
            fn phase(&self) -> FilterPhase {
                FilterPhase::Static
            }
            async fn evaluate(&self, _ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
                Ok(FilterResult::no_match("counting"))
            }
            fn evict_session_state(&self, _scope: SessionScopeKey) -> usize {
                self.calls.fetch_add(1, Ordering::SeqCst);
                7 // deterministic non-zero count
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let proxy = make_proxy(vec![Box::new(CountingFilter {
            calls: calls.clone(),
        })]);
        let scope = SessionScopeKey::fresh();

        // Prime the SessionStateRegistry so we can confirm the proxy clears it.
        crate::session_state::SessionStateRegistry::global().activate_containment(
            scope,
            crate::session_state::ContainmentReason::Manual {
                actor: "test".into(),
            },
        );
        assert!(crate::session_state::SessionStateRegistry::global().is_containment_active(scope));

        let removed = proxy.evict_session_state(scope);
        assert_eq!(removed, 7, "filter's evict count must propagate up");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "filter called exactly once"
        );
        assert!(
            !crate::session_state::SessionStateRegistry::global().is_containment_active(scope),
            "SessionStateRegistry entry must also be evicted"
        );
    }

    #[tokio::test]
    async fn test_empty_pipeline_allows() {
        let proxy = make_proxy(vec![]);
        let decision = proxy.evaluate(&make_ctx()).await;
        assert!(decision.is_allowed());
        assert_eq!(decision.composite_score, 0.0);
    }

    #[tokio::test]
    async fn test_low_score_allows() {
        let proxy = make_proxy(vec![Box::new(FixedFilter {
            name: "low".into(),
            phase: FilterPhase::Static,
            result: FilterResult::matched("low", "r1", 1.0, Severity::Notice, "minor"),
        })]);
        let decision = proxy.evaluate(&make_ctx()).await;
        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn test_medium_score_queues() {
        let proxy = make_proxy(vec![Box::new(FixedFilter {
            name: "med".into(),
            phase: FilterPhase::Static,
            result: FilterResult::matched("med", "r1", 5.0, Severity::Warning, "medium risk"),
        })]);
        proxy.call_count.store(300, Ordering::Relaxed);
        let decision = proxy.evaluate(&make_ctx()).await;
        assert!(matches!(decision.action, ProxyAction::Queue { .. }));
    }

    #[tokio::test]
    async fn test_high_score_denies() {
        let proxy = make_proxy(vec![Box::new(FixedFilter {
            name: "high".into(),
            phase: FilterPhase::Static,
            result: FilterResult::matched("high", "r1", 9.0, Severity::Critical, "dangerous"),
        })]);
        proxy.call_count.store(300, Ordering::Relaxed);
        let decision = proxy.evaluate(&make_ctx()).await;
        assert!(decision.is_denied());
    }

    #[tokio::test]
    async fn test_scores_are_additive() {
        let proxy = make_proxy(vec![
            Box::new(FixedFilter {
                name: "f1".into(),
                phase: FilterPhase::Static,
                result: FilterResult::matched("f1", "r1", 2.0, Severity::Warning, "a"),
            }),
            Box::new(FixedFilter {
                name: "f2".into(),
                phase: FilterPhase::Pattern,
                result: FilterResult::matched("f2", "r2", 2.5, Severity::Warning, "b"),
            }),
        ]);
        proxy.call_count.store(300, Ordering::Relaxed);
        let decision = proxy.evaluate(&make_ctx()).await;
        assert_eq!(decision.composite_score, 4.5);
        assert!(matches!(decision.action, ProxyAction::Queue { .. }));
    }

    #[tokio::test]
    async fn test_early_termination_on_phase1_deny() {
        let proxy = make_proxy(vec![
            Box::new(FixedFilter {
                name: "blocker".into(),
                phase: FilterPhase::Static,
                result: FilterResult::matched("blocker", "r1", 9.0, Severity::Critical, "blocked"),
            }),
            Box::new(FixedFilter {
                name: "phase2".into(),
                phase: FilterPhase::Pattern,
                result: FilterResult::matched("phase2", "r2", 1.0, Severity::Notice, "skipped"),
            }),
        ]);
        proxy.call_count.store(300, Ordering::Relaxed);
        let decision = proxy.evaluate(&make_ctx()).await;
        assert!(decision.is_denied());
        // Phase 2 filter should not have run, so only 1 result
        assert_eq!(decision.filter_results.len(), 1);
    }

    #[tokio::test]
    async fn test_call_counter_increments() {
        let proxy = make_proxy(vec![]);
        assert_eq!(proxy.call_count(), 0);
        proxy.evaluate(&make_ctx()).await;
        assert_eq!(proxy.call_count(), 1);
        proxy.evaluate(&make_ctx()).await;
        assert_eq!(proxy.call_count(), 2);
    }

    #[tokio::test]
    async fn test_per_filter_telemetry_in_evaluate() {
        let proxy = make_proxy(vec![
            Box::new(FixedFilter {
                name: "f1".into(),
                phase: FilterPhase::Static,
                result: FilterResult::matched("f1", "r1", 1.0, Severity::Notice, "a"),
            }),
            Box::new(FixedFilter {
                name: "f2".into(),
                phase: FilterPhase::Pattern,
                result: FilterResult::matched("f2", "r2", 1.0, Severity::Notice, "b"),
            }),
        ]);

        // Before evaluation, all counts should be zero
        let info = proxy.filter_info();
        assert!(info.iter().all(|f| f.evaluation_count == 0));

        // After one evaluation, each filter should have count 1
        proxy.evaluate(&make_ctx()).await;
        let info = proxy.filter_info();
        let f1 = info.iter().find(|f| f.name == "f1").unwrap();
        let f2 = info.iter().find(|f| f.name == "f2").unwrap();
        assert_eq!(f1.evaluation_count, 1);
        assert_eq!(f2.evaluation_count, 1);
        assert!(f1.avg_latency_ms >= 0.0);
        assert!(f2.avg_latency_ms >= 0.0);

        // After second evaluation, counts should be 2
        proxy.evaluate(&make_ctx()).await;
        let info = proxy.filter_info();
        let f1 = info.iter().find(|f| f.name == "f1").unwrap();
        assert_eq!(f1.evaluation_count, 2);
    }

    #[test]
    fn test_filter_metrics_recording() {
        use crate::filters::FilterMetrics;
        let metrics = FilterMetrics::new();
        assert_eq!(metrics.evaluation_count(), 0);
        assert_eq!(metrics.avg_latency_ms(), 0.0);

        metrics.record(std::time::Duration::from_millis(10));
        assert_eq!(metrics.evaluation_count(), 1);
        assert!((metrics.avg_latency_ms() - 10.0).abs() < 1.0);

        metrics.record(std::time::Duration::from_millis(20));
        assert_eq!(metrics.evaluation_count(), 2);
        // Average should be ~15ms
        assert!((metrics.avg_latency_ms() - 15.0).abs() < 1.0);
    }
}
