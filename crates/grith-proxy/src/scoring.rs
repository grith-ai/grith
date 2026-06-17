// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Additive score aggregation and threshold-based decision mapping.

use crate::types::{FilterResult, ProxyDecision, Severity};
use std::time::Duration;

/// Default score threshold below which a tool call is auto-allowed.
pub const SCORE_QUEUE_THRESHOLD: f64 = 3.0;

/// Default score threshold above which a tool call is auto-denied.
pub const SCORE_DENY_THRESHOLD: f64 = 8.0;

/// Map a numeric score to a severity level.
///
/// Shared by filters that derive severity from a computed score
/// (e.g. `egress_policy`, `session_containment`).
pub fn severity_for(score: f64) -> Severity {
    if score >= SCORE_DENY_THRESHOLD {
        Severity::Critical
    } else if score >= 5.0 {
        Severity::Error
    } else if score >= SCORE_QUEUE_THRESHOLD {
        Severity::Warning
    } else {
        Severity::Notice
    }
}

/// Proxy scoring configuration.
///
/// Every tool call is evaluated against the same fixed thresholds — there is no
/// call-count-dependent "cold-start" widening. A consistent single regime means
/// the first call in a session is filtered identically to the thousandth, so a
/// destructive or exfiltrating operation issued early is never under-scored.
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    pub auto_allow_threshold: f64,
    pub auto_deny_threshold: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            auto_allow_threshold: SCORE_QUEUE_THRESHOLD,
            auto_deny_threshold: SCORE_DENY_THRESHOLD,
        }
    }
}

impl ScoringConfig {
    /// The allow/deny thresholds applied to every call.
    pub fn thresholds(&self) -> (f64, f64) {
        (self.auto_allow_threshold, self.auto_deny_threshold)
    }
}

/// Aggregate scores from filter results (sum of matched scores).
pub fn aggregate(results: &[FilterResult]) -> f64 {
    results.iter().filter(|r| r.matched).map(|r| r.score).sum()
}

/// Route a composite score to a proxy decision.
pub fn route_decision(
    score: f64,
    results: Vec<FilterResult>,
    allow_threshold: f64,
    deny_threshold: f64,
    evaluation_time: Duration,
) -> ProxyDecision {
    if score > deny_threshold {
        let reason = build_deny_reason(&results);
        ProxyDecision::deny(score, results, reason, evaluation_time)
    } else if score > allow_threshold {
        ProxyDecision::queue(score, results, evaluation_time)
    } else {
        ProxyDecision::allow(score, results, evaluation_time)
    }
}

/// Build a human-readable deny reason from filter results.
fn build_deny_reason(results: &[FilterResult]) -> String {
    let triggers: Vec<&str> = results
        .iter()
        .filter(|r| r.matched && r.score > 0.0)
        .map(|r| r.message.as_str())
        .collect();
    if triggers.is_empty() {
        "Score exceeds auto-deny threshold".into()
    } else {
        triggers.join("; ")
    }
}

/// Check if a score exceeds the deny threshold (for early termination).
pub fn exceeds_deny(score: f64, deny_threshold: f64) -> bool {
    score > deny_threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FilterResult, ProxyAction, Severity};

    #[test]
    fn test_aggregate_empty() {
        assert_eq!(aggregate(&[]), 0.0);
    }

    #[test]
    fn test_aggregate_no_matches() {
        let results = vec![FilterResult::no_match("f1"), FilterResult::no_match("f2")];
        assert_eq!(aggregate(&results), 0.0);
    }

    #[test]
    fn test_aggregate_with_matches() {
        let results = vec![
            FilterResult::matched("f1", "r1", 2.0, Severity::Warning, "msg"),
            FilterResult::no_match("f2"),
            FilterResult::matched("f3", "r2", 3.5, Severity::Error, "msg"),
        ];
        assert_eq!(aggregate(&results), 5.5);
    }

    #[test]
    fn test_route_allow() {
        let decision = route_decision(1.0, vec![], 3.0, 8.0, Duration::from_millis(1));
        assert_eq!(decision.action, ProxyAction::Allow);
    }

    #[test]
    fn test_route_queue() {
        let decision = route_decision(5.0, vec![], 3.0, 8.0, Duration::from_millis(1));
        assert!(matches!(decision.action, ProxyAction::Queue { .. }));
    }

    #[test]
    fn test_route_deny() {
        let decision = route_decision(9.0, vec![], 3.0, 8.0, Duration::from_millis(1));
        assert!(matches!(decision.action, ProxyAction::Deny { .. }));
    }

    #[test]
    fn test_thresholds_are_fixed() {
        // No call-count dependence: the same thresholds apply to every call.
        let config = ScoringConfig::default();
        assert_eq!(config.thresholds(), (3.0, 8.0));
    }

    #[test]
    fn test_boundary_scores() {
        // Exactly at allow threshold — should NOT allow (> not >=)
        let decision = route_decision(3.0, vec![], 3.0, 8.0, Duration::from_millis(1));
        assert_eq!(decision.action, ProxyAction::Allow);

        // Just above allow threshold
        let decision = route_decision(3.01, vec![], 3.0, 8.0, Duration::from_millis(1));
        assert!(matches!(decision.action, ProxyAction::Queue { .. }));

        // Exactly at deny threshold — should NOT deny
        let decision = route_decision(8.0, vec![], 3.0, 8.0, Duration::from_millis(1));
        assert!(matches!(decision.action, ProxyAction::Queue { .. }));

        // Just above deny threshold
        let decision = route_decision(8.01, vec![], 3.0, 8.0, Duration::from_millis(1));
        assert!(matches!(decision.action, ProxyAction::Deny { .. }));
    }

    #[test]
    fn test_severity_for() {
        assert_eq!(severity_for(1.0), Severity::Notice);
        assert_eq!(severity_for(2.9), Severity::Notice);
        assert_eq!(severity_for(3.0), Severity::Warning);
        assert_eq!(severity_for(4.9), Severity::Warning);
        assert_eq!(severity_for(5.0), Severity::Error);
        assert_eq!(severity_for(7.9), Severity::Error);
        assert_eq!(severity_for(8.0), Severity::Critical);
        assert_eq!(severity_for(10.0), Severity::Critical);
    }

    #[test]
    fn test_score_threshold_constants() {
        assert_eq!(SCORE_QUEUE_THRESHOLD, 3.0);
        assert_eq!(SCORE_DENY_THRESHOLD, 8.0);
    }
}
