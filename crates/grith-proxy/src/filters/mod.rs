// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Security filter trait, registry, and all filter implementations.

pub mod allowlist;
pub mod argument;
pub mod behavioural;
pub mod canary;
pub mod capability;
pub mod command;
pub mod destructive_action;
pub mod dlp_gate;
pub mod egress_policy;
pub mod egress_rate;
pub mod operation_risk;
pub mod outbound_binaries;
pub mod path_match;
pub mod rate_limit;
pub mod reputation;
pub mod secret_scan;
pub mod semantic;
pub mod sensitive_path;
pub mod session_containment;
pub mod taint;

use crate::types::{FilterResult, ToolCallContext};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The phase in which a filter executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FilterPhase {
    /// Phase 1: pure string ops, zero external deps (~0.1ms)
    Static,
    /// Phase 2: heavier pattern matching, CPU-bound (~1-5ms)
    Pattern,
    /// Phase 3: session-state-dependent, may use local LLM (~5-10ms) [v1.5]
    Context,
}

/// Trait that all security filters implement.
#[async_trait]
pub trait SecurityFilter: Send + Sync {
    /// Unique name of this filter (kebab-case, e.g., `"secret-scan"`).
    fn name(&self) -> &str;
    /// Execution phase (Static, Pattern, or Context).
    fn phase(&self) -> FilterPhase;

    /// Whether this filter is safe to run concurrently with others in its phase.
    fn can_run_parallel(&self) -> bool {
        true
    }

    /// Whether the filter is initialized and ready to evaluate.
    fn is_ready(&self) -> bool {
        true
    }

    /// Evaluate a tool call and return a filter result with a score contribution.
    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult>;

    /// Drop any scope-keyed state for `scope`. Default implementation does
    /// nothing — filters without per-session state can ignore this hook.
    /// PR 1 Phase F calls this from the supervisor at session-end and from
    /// the session-start stale-state sweep.
    ///
    /// Returns a best-effort entry count, for telemetry. The unit varies
    /// per filter (taint counts registry rows + recent_sensitive_read rows,
    /// rate_limit counts windows, behavioural counts dropped history records)
    /// — the sum across filters is a coarse "session footprint" indicator,
    /// not a strict byte- or row-count.
    fn evict_session_state(&self, _scope: crate::types::SessionScopeKey) -> usize {
        0
    }
}

/// Per-filter evaluation metrics tracked with atomic counters.
pub struct FilterMetrics {
    evaluation_count: AtomicU64,
    total_latency_nanos: AtomicU64,
}

impl FilterMetrics {
    /// Create a new zero-initialized metrics tracker.
    pub fn new() -> Self {
        Self {
            evaluation_count: AtomicU64::new(0),
            total_latency_nanos: AtomicU64::new(0),
        }
    }

    /// Record one evaluation with the given latency.
    pub fn record(&self, latency: std::time::Duration) {
        self.evaluation_count.fetch_add(1, Ordering::Relaxed);
        self.total_latency_nanos
            .fetch_add(latency.as_nanos() as u64, Ordering::Relaxed);
    }

    /// Total number of evaluations recorded.
    pub fn evaluation_count(&self) -> u64 {
        self.evaluation_count.load(Ordering::Relaxed)
    }

    /// Average latency in milliseconds, or 0.0 if no evaluations.
    pub fn avg_latency_ms(&self) -> f64 {
        let count = self.evaluation_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        let total_ns = self.total_latency_nanos.load(Ordering::Relaxed);
        (total_ns as f64) / (count as f64) / 1_000_000.0
    }
}

impl Default for FilterMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Registry of all active filters.
pub struct FilterRegistry {
    filters: Vec<Box<dyn SecurityFilter>>,
    metrics: HashMap<String, Arc<FilterMetrics>>,
}

impl FilterRegistry {
    /// Create an empty filter registry.
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
            metrics: HashMap::new(),
        }
    }

    /// Add a filter to the registry.
    pub fn register(&mut self, filter: Box<dyn SecurityFilter>) {
        let name = filter.name().to_string();
        self.metrics
            .entry(name)
            .or_insert_with(|| Arc::new(FilterMetrics::new()));
        self.filters.push(filter);
    }

    /// Return all ready filters for the given execution phase, paired with their metrics.
    pub fn filters_for_phase_with_metrics(
        &self,
        phase: FilterPhase,
    ) -> Vec<(&dyn SecurityFilter, Arc<FilterMetrics>)> {
        self.filters
            .iter()
            .filter(|f| f.phase() == phase && f.is_ready())
            .map(|f| {
                let metrics = self.metrics.get(f.name()).cloned().unwrap_or_default();
                (f.as_ref(), metrics)
            })
            .collect()
    }

    /// Total number of registered filters.
    pub fn count(&self) -> usize {
        self.filters.len()
    }

    /// Tell every registered filter to drop any scope-keyed state for `scope`.
    /// Returns the sum of entries removed across all filters, for telemetry.
    ///
    /// PR 1 Phase F calls this from the supervisor at session-end (immediate
    /// per-scope eviction) and from the session-start sweep (for each stale
    /// scope discovered by `SessionStateRegistry::snapshot_stale`).
    pub fn evict_session_state(&self, scope: crate::types::SessionScopeKey) -> usize {
        self.filters
            .iter()
            .map(|f| f.evict_session_state(scope))
            .sum()
    }

    /// Summary information about all registered filters.
    pub fn filter_info(&self) -> Vec<FilterInfo> {
        self.filters
            .iter()
            .map(|f| {
                let name = f.name().to_string();
                let (eval_count, avg_latency) = self
                    .metrics
                    .get(&name)
                    .map(|m| (m.evaluation_count(), m.avg_latency_ms()))
                    .unwrap_or((0, 0.0));
                FilterInfo {
                    name,
                    phase: f.phase(),
                    is_ready: f.is_ready(),
                    evaluation_count: eval_count,
                    avg_latency_ms: avg_latency,
                }
            })
            .collect()
    }
}

/// Summary information about a registered filter.
pub struct FilterInfo {
    pub name: String,
    pub phase: FilterPhase,
    pub is_ready: bool,
    pub evaluation_count: u64,
    pub avg_latency_ms: f64,
}

impl Default for FilterRegistry {
    fn default() -> Self {
        Self::new()
    }
}
