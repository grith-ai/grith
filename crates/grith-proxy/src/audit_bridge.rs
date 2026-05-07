// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Conversions between proxy types and audit-facing compact summary types.
//!
//! This lives in `grith-proxy` (not `grith-audit`) to avoid a dependency cycle:
//! `grith-audit` must not depend on `grith-proxy`.

use crate::types::{FilterResult, ProxyAction};

/// Map `ProxyAction` to the compact audit summary enum.
pub fn to_action_summary(action: &ProxyAction) -> grith_audit::types::ProxyActionSummary {
    match action {
        ProxyAction::Allow => grith_audit::types::ProxyActionSummary::Allow,
        ProxyAction::Queue { .. } => grith_audit::types::ProxyActionSummary::Queue,
        ProxyAction::Deny { .. } => grith_audit::types::ProxyActionSummary::Deny,
    }
}

/// Convert proxy filter results into the compact `FilterResultSummary` used by
/// the audit subsystem.
pub fn to_filter_summaries(
    results: &[FilterResult],
) -> Vec<grith_audit::types::FilterResultSummary> {
    results
        .iter()
        .map(|r| grith_audit::types::FilterResultSummary {
            filter_name: r.filter_name.clone(),
            matched: r.matched,
            score: r.score,
            rule_id: r.rule_id.clone(),
            severity: r.severity.to_string(),
            message: r.message.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_action_summary_maps_correctly() {
        assert_eq!(
            to_action_summary(&ProxyAction::Allow),
            grith_audit::types::ProxyActionSummary::Allow
        );
        assert_eq!(
            to_action_summary(&ProxyAction::Queue {
                priority: crate::types::QueuePriority::High,
            }),
            grith_audit::types::ProxyActionSummary::Queue
        );
        assert_eq!(
            to_action_summary(&ProxyAction::Deny {
                reason: "no".into()
            }),
            grith_audit::types::ProxyActionSummary::Deny
        );
    }
}
