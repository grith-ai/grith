// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Core audit data types shared across the crate.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// A complete audit record for a single proxy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique record identifier.
    pub id: Uuid,
    /// When the proxy evaluation occurred.
    pub timestamp: DateTime<Utc>,
    /// Session that produced this evaluation.
    pub session_id: Uuid,
    /// Identifier of the plugin or tool origin.
    pub plugin_id: String,
    /// The type of tool call evaluated (e.g., `FileRead`, `ShellExec`).
    pub tool_call_type: String,
    /// Truncated human-readable summary of the call arguments.
    pub arguments_summary: String,
    /// SHA-256 hash of the full arguments for tamper detection.
    pub arguments_hash: String,
    /// Composite risk score from the filter pipeline.
    pub composite_score: f64,
    /// Final proxy decision (allow / queue / deny).
    pub proxy_action: ProxyActionSummary,
    /// Per-filter breakdown of the evaluation.
    pub filter_results: Vec<FilterResultSummary>,
    /// Simplified per-filter score map (filter_name → score) for quick querying,
    /// cloud sync payloads, and team dashboards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_scores: Option<HashMap<String, f64>>,
    /// Result of actual execution, if the call was allowed.
    pub execution_result: Option<String>,
    /// Wall-clock time spent in the proxy evaluation (milliseconds).
    pub evaluation_time_ms: f64,
    /// Optional task description for context.
    pub task_context: Option<String>,
    /// Origin of the evaluation (`"wasm"` for built-in agent, `"supervisor"` for CLI).
    #[serde(default = "default_source")]
    pub source: String,
    /// Name of the supervised CLI tool, if source is `"supervisor"`.
    #[serde(default)]
    pub supervised_tool: Option<String>,
    /// PID of the supervised process, if source is `"supervisor"`.
    #[serde(default)]
    pub supervised_pid: Option<u32>,
    /// Correlation ID linking related source-read and outbound-sink events.
    /// Events in the same source→sink chain share a correlation ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<Uuid>,

    /// SHA-256 hash of the canonical record content for tamper evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_hash: Option<String>,
    /// `record_hash` of the previous record in the chain. `None` for genesis records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    /// Monotonically increasing sequence number within the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_sequence: Option<i64>,

    // ── LLM cost tracking fields ──
    /// LLM provider name (e.g. `"anthropic"`, `"openai"`, `"ollama"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_provider: Option<String>,
    /// LLM model identifier (e.g. `"claude-3-opus-20240229"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_model: Option<String>,
    /// Number of prompt (input) tokens for this LLM call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<usize>,
    /// Number of completion (output) tokens for this LLM call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<usize>,
    /// Estimated cost in USD for this LLM call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd: Option<f64>,
}

fn default_source() -> String {
    "wasm".to_string()
}

/// Compact summary of a proxy action for storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyActionSummary {
    /// Tool call was permitted.
    Allow,
    /// Tool call was queued for human review.
    Queue,
    /// Tool call was denied.
    Deny,
}

impl std::fmt::Display for ProxyActionSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Queue => write!(f, "queue"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

/// Compact form of FilterResult for storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterResultSummary {
    /// Name of the security filter that produced this result.
    pub filter_name: String,
    /// Whether the filter matched (contributed a non-zero score).
    pub matched: bool,
    /// Score contribution from this filter.
    pub score: f64,
    /// Identifier of the specific rule that matched, if any.
    pub rule_id: String,
    /// Severity level of the match (e.g., `"notice"`, `"warning"`, `"critical"`).
    pub severity: String,
    /// Human-readable description of why the filter matched.
    pub message: String,
}

/// Result of verifying the audit hash chain integrity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChainVerification {
    /// The chain is valid and all hashes link correctly.
    Valid {
        /// Total number of chained records verified.
        record_count: usize,
    },
    /// The chain is broken at a specific point.
    Broken {
        /// The chain_sequence where the break was detected.
        at_sequence: i64,
        /// The record ID at the break point.
        record_id: Uuid,
        /// Human-readable description of the integrity failure.
        reason: String,
    },
    /// No chained records exist (empty or pre-chaining database).
    Empty,
}

/// Compute SHA-256 hash of arbitrary data, returning hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Summarize tool call arguments for display (truncated to 256 chars).
///
/// M-8: Uses `char_indices` for safe truncation instead of byte slicing,
/// which would panic on multi-byte (non-ASCII) characters.
pub fn summarize_arguments(args: &serde_json::Value) -> String {
    let s = args.to_string();
    if s.len() > 256 {
        // Find the last char boundary at or before byte index 253
        let truncate_at = s
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= 253)
            .last()
            .unwrap_or(0);
        format!("{}...", &s[..truncate_at])
    } else {
        s
    }
}

impl AuditRecord {
    /// Create a new audit record from proxy evaluation data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: Uuid,
        plugin_id: String,
        tool_call_type: String,
        arguments: &serde_json::Value,
        composite_score: f64,
        proxy_action: ProxyActionSummary,
        filter_results: Vec<FilterResultSummary>,
        evaluation_time_ms: f64,
        task_context: Option<String>,
    ) -> Self {
        let arguments_summary = summarize_arguments(arguments);
        let arguments_hash = sha256_hex(arguments.to_string().as_bytes());
        let filter_scores = if filter_results.is_empty() {
            None
        } else {
            Some(
                filter_results
                    .iter()
                    .map(|fr| (fr.filter_name.clone(), fr.score))
                    .collect(),
            )
        };
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            session_id,
            plugin_id,
            tool_call_type,
            arguments_summary,
            arguments_hash,
            composite_score,
            proxy_action,
            filter_results,
            filter_scores,
            execution_result: None,
            evaluation_time_ms,
            task_context,
            source: default_source(),
            supervised_tool: None,
            supervised_pid: None,
            correlation_id: None,
            record_hash: None,
            prev_hash: None,
            chain_sequence: None,
            llm_provider: None,
            llm_model: None,
            prompt_tokens: None,
            completion_tokens: None,
            estimated_cost_usd: None,
        }
    }

    /// Compute a deterministic hash of this record's content for chain integrity.
    ///
    /// The hash covers all immutable fields that constitute the record's identity
    /// and content. Uses `arguments_hash` rather than raw arguments for determinism.
    pub fn compute_record_hash(&self) -> String {
        let prev = self.prev_hash.as_deref().unwrap_or("GENESIS");
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.id,
            self.timestamp.to_rfc3339(),
            self.session_id,
            self.plugin_id,
            self.tool_call_type,
            self.arguments_hash,
            self.composite_score,
            self.proxy_action,
            prev,
        );
        sha256_hex(canonical.as_bytes())
    }

    /// Set the correlation ID linking this event to a source→sink chain.
    pub fn with_correlation(mut self, id: Uuid) -> Self {
        self.correlation_id = Some(id);
        self
    }

    /// Mark this audit record as originating from a supervisor session.
    pub fn with_supervisor_source(mut self, tool: impl Into<String>, pid: u32) -> Self {
        self.source = "supervisor".to_string();
        self.supervised_tool = Some(tool.into());
        self.supervised_pid = Some(pid);
        self
    }

    /// Attach LLM cost tracking data to this audit record.
    pub fn with_llm_cost(
        mut self,
        provider: impl Into<String>,
        model: impl Into<String>,
        prompt_tokens: usize,
        completion_tokens: usize,
        cost_usd: f64,
    ) -> Self {
        self.llm_provider = Some(provider.into());
        self.llm_model = Some(model.into());
        self.prompt_tokens = Some(prompt_tokens);
        self.completion_tokens = Some(completion_tokens);
        self.estimated_cost_usd = Some(cost_usd);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello world");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_summarize_arguments_short() {
        let args = serde_json::json!({"path": "/tmp/test.txt"});
        let summary = summarize_arguments(&args);
        assert!(summary.len() <= 256);
        assert!(summary.contains("/tmp/test.txt"));
    }

    #[test]
    fn test_summarize_arguments_long() {
        let long = "x".repeat(300);
        let args = serde_json::json!({"data": long});
        let summary = summarize_arguments(&args);
        assert_eq!(summary.len(), 256);
        assert!(summary.ends_with("..."));
    }

    #[test]
    fn test_audit_record_creation() {
        let record = AuditRecord::new(
            Uuid::new_v4(),
            "file-ops".into(),
            "FileRead".into(),
            &serde_json::json!({"path": "/etc/passwd"}),
            2.5,
            ProxyActionSummary::Allow,
            vec![],
            1.5,
            None,
        );
        assert!(!record.arguments_hash.is_empty());
        assert!(record.arguments_summary.contains("/etc/passwd"));
        assert_eq!(record.composite_score, 2.5);
    }

    #[test]
    fn test_serde_roundtrip() {
        let record = AuditRecord::new(
            Uuid::new_v4(),
            "shell".into(),
            "ShellExec".into(),
            &serde_json::json!({"command": "ls"}),
            0.5,
            ProxyActionSummary::Allow,
            vec![FilterResultSummary {
                filter_name: "path_match".into(),
                matched: false,
                score: 0.0,
                rule_id: String::new(),
                severity: "notice".into(),
                message: String::new(),
            }],
            0.8,
            Some("testing".into()),
        );
        let json = serde_json::to_string(&record).unwrap();
        let parsed: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, record.id);
        assert_eq!(parsed.composite_score, record.composite_score);
        assert_eq!(parsed.filter_results.len(), 1);
        assert_eq!(parsed.source, "wasm");
        assert!(parsed.supervised_tool.is_none());
        assert!(parsed.supervised_pid.is_none());
    }

    #[test]
    fn test_proxy_action_summary_display() {
        assert_eq!(ProxyActionSummary::Allow.to_string(), "allow");
        assert_eq!(ProxyActionSummary::Queue.to_string(), "queue");
        assert_eq!(ProxyActionSummary::Deny.to_string(), "deny");
    }

    #[test]
    fn test_with_supervisor_source_sets_fields() {
        let record = AuditRecord::new(
            Uuid::new_v4(),
            "supervisor:claude-code".into(),
            "FileRead".into(),
            &serde_json::json!({"path": "/tmp/test"}),
            4.2,
            ProxyActionSummary::Queue,
            vec![],
            1.1,
            Some("testing".into()),
        )
        .with_supervisor_source("claude-code", 4321);

        assert_eq!(record.source, "supervisor");
        assert_eq!(record.supervised_tool.as_deref(), Some("claude-code"));
        assert_eq!(record.supervised_pid, Some(4321));
    }
}
