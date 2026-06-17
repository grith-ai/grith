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
    /// Project name for the session — from the `--project` override or the cwd
    /// basename at session start. Captured on every evaluation so audit history
    /// can be grouped/labelled by project even after the session ends and ages
    /// out of the in-memory live-session registry. `None` for the built-in
    /// agent path (which has no project concept).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
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

    // ── PR 4 Phase F: routine-spawn forensic fields ──
    /// SHA-256 hex of the spawned binary's canonical path content at
    /// the moment of the spawn decision. Populated for every
    /// `ProcessSpawn` evaluation so post-incident review can spot
    /// hash drift across sessions. `None` for non-spawn calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawn_sha256: Option<String>,
    /// Profile-declared routine root that matched the spawned binary's
    /// canonical path, or `None` if no routine root matched. Populated
    /// only on `ProcessSpawn`. Operators can grep this column to
    /// understand which root grants trust in their environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_routine_root: Option<String>,
    /// JSON-encoded list of phase-3 filter names that fired on this
    /// decision (matched, non-zero score). Populated only when the
    /// routine signal applied (i.e. score `0.5` on a ProcessSpawn) so
    /// operators can see what *would have* tripped at the higher
    /// `1.0` baseline. Schema: `[{"filter": "taint", "score": 3.0}, …]`.
    ///
    /// **Sentinel semantics:**
    /// * `None` — routine signal did NOT apply (or non-spawn call).
    /// * `Some("[]")` — routine signal applied AND no phase-3 filter
    ///   matched: a clean routine-rooted spawn. Distinct from `None`.
    /// * `Some("[…]")` — routine signal applied AND phase-3 filters
    ///   matched: shows which ones, for "what would have queued at
    ///   +1.0?" analysis.
    ///
    /// Queries that want "spawns that earned the routine signal"
    /// should use `shadow_phase3_filters IS NOT NULL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow_phase3_filters: Option<String>,

    // ── PR 5 Phase E: listener-rewrite forensic fields ──
    /// Original (pre-rewrite) bind address the tracee passed to
    /// `bind(2)`. Populated only when the supervisor performed a
    /// wildcard → loopback clamp on a `NetListen` decision. Format:
    /// `"<address>:<port>"` (e.g. `"0.0.0.0:8080"`). `None` for
    /// non-clamp calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_addr: Option<String>,
    /// Address the kernel actually saw after the clamp (e.g.
    /// `"127.0.0.1:8080"`). Always set when `original_addr` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewritten_addr: Option<String>,
    /// Description from the `local_listener_policy` entry that
    /// authorised the clamp — copied verbatim from
    /// `LocalListenerEntry::desc`. Surfaced in the dashboard so
    /// operators can trace a clamp back to the TOML rule that
    /// allowed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clamp_profile_entry: Option<String>,

    // ── Compact-record support (options 2 + 3 / "audit completeness") ──
    /// Indicates whether this record carries the full proxy evaluation
    /// (`Full`) or is a compact bookkeeping row emitted by the
    /// session-allowed / noise-path short-circuits (`Compact`).
    ///
    /// Compact records have empty `filter_results`, no `filter_scores`,
    /// no `composite_score` contribution, and a minimal
    /// `arguments_summary`. They exist so analytics / compliance
    /// workflows can still see every `bash`, `find`, `grep`, … the
    /// session ran, without bloating the per-row payload to the size
    /// of a fully-evaluated record.
    #[serde(default)]
    pub record_type: RecordType,
}

fn default_source() -> String {
    "wasm".to_string()
}

/// Classification of an audit row by what it carries.
///
/// `Full` is the historical default — a complete proxy decision, including
/// all per-filter scores and the full arguments summary. `Compact` is a
/// short bookkeeping row emitted when an event short-circuits ahead of the
/// proxy pipeline (session-allowlist match, noise-path filter) but
/// completeness-tier configuration still wants the event recorded for
/// "what did the session actually do?" analysis.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecordType {
    /// Full proxy evaluation. Default for backwards compatibility.
    #[default]
    Full,
    /// Short-circuit bookkeeping row — no filter detail, minimal args.
    Compact,
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Compact => write!(f, "compact"),
        }
    }
}

impl RecordType {
    /// Parse a record-type tag from its string form (used at the SQLite
    /// boundary). Unknown values default to `Full` to keep deserialisation
    /// of older or hand-written rows robust.
    pub fn from_str_lenient(s: &str) -> Self {
        match s {
            "compact" => Self::Compact,
            _ => Self::Full,
        }
    }
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

/// Default argument-summary truncation limit (bytes). Tuned for the
/// historical "summary" shape: path + handful of flags fits comfortably,
/// long argv blobs get the `...` suffix.
pub const DEFAULT_SUMMARY_LIMIT: usize = 256;

/// Extended truncation limit used for `ProcessSpawn` rows where the
/// useful information lives deep in argv (e.g. the base64-encoded
/// command inside a `bash -c "... eval $(echo … | base64 -d)"`
/// wrapper). 4096 captures Claude Code / Codex wrappers in full.
///
/// Used by callers (typically the supervisor's `build_audit_record` and
/// `maybe_log_compact`) that swap the default summary for the extended
/// one after constructing an `AuditRecord`.
pub const SPAWN_SUMMARY_LIMIT: usize = 4096;

/// Summarize tool call arguments for display, truncated to the default
/// limit (256 chars). For ProcessSpawn rows callers should reach for
/// [`summarize_arguments_with_limit`] with [`SPAWN_SUMMARY_LIMIT`].
///
/// M-8: Uses `char_indices` for safe truncation instead of byte slicing,
/// which would panic on multi-byte (non-ASCII) characters.
pub fn summarize_arguments(args: &serde_json::Value) -> String {
    summarize_arguments_with_limit(args, DEFAULT_SUMMARY_LIMIT)
}

/// Summarize tool call arguments for display, truncated to `limit`
/// bytes (char-boundary safe).
pub fn summarize_arguments_with_limit(args: &serde_json::Value, limit: usize) -> String {
    let s = args.to_string();
    if s.len() > limit {
        // Find the last char boundary at or before byte index `limit - 3`
        // (leave room for the trailing "..." marker).
        let target = limit.saturating_sub(3);
        let truncate_at = s
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= target)
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
            project_name: None,
            correlation_id: None,
            record_hash: None,
            prev_hash: None,
            chain_sequence: None,
            llm_provider: None,
            llm_model: None,
            prompt_tokens: None,
            completion_tokens: None,
            estimated_cost_usd: None,
            spawn_sha256: None,
            matched_routine_root: None,
            shadow_phase3_filters: None,
            original_addr: None,
            rewritten_addr: None,
            clamp_profile_entry: None,
            record_type: RecordType::Full,
        }
    }

    /// Build a compact audit row.
    ///
    /// Used by the supervisor's short-circuit paths (session-allowlist
    /// match, noise-path filter) when the operator has opted into
    /// completeness levels above `decisions`. Compact rows record the
    /// fact that *something* happened and *what* it was, without paying
    /// the storage cost of a full filter breakdown.
    ///
    /// Callers must follow up with `.with_supervisor_source(...)` so the
    /// row carries `source = "supervisor"` and the pid/tool labels.
    pub fn new_compact(
        session_id: Uuid,
        plugin_id: String,
        tool_call_type: String,
        arguments: &serde_json::Value,
        action: ProxyActionSummary,
    ) -> Self {
        let arguments_summary = summarize_arguments(arguments);
        let arguments_hash = sha256_hex(arguments.to_string().as_bytes());
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            session_id,
            plugin_id,
            tool_call_type,
            arguments_summary,
            arguments_hash,
            composite_score: 0.0,
            proxy_action: action,
            filter_results: Vec::new(),
            filter_scores: None,
            execution_result: None,
            evaluation_time_ms: 0.0,
            task_context: None,
            source: default_source(),
            supervised_tool: None,
            supervised_pid: None,
            project_name: None,
            correlation_id: None,
            record_hash: None,
            prev_hash: None,
            chain_sequence: None,
            llm_provider: None,
            llm_model: None,
            prompt_tokens: None,
            completion_tokens: None,
            estimated_cost_usd: None,
            spawn_sha256: None,
            matched_routine_root: None,
            shadow_phase3_filters: None,
            original_addr: None,
            rewritten_addr: None,
            clamp_profile_entry: None,
            record_type: RecordType::Compact,
        }
    }

    /// PR 5 Phase E: attach listener-rewrite forensic data to an
    /// audit record. Called from the supervisor's clamp path when a
    /// wildcard `NetListen` was rewritten to loopback. All three
    /// arguments must be `Some` together — pass `None` if no clamp
    /// happened.
    pub fn with_listener_rewrite(
        mut self,
        original_addr: impl Into<String>,
        rewritten_addr: impl Into<String>,
        clamp_profile_entry: impl Into<String>,
    ) -> Self {
        self.original_addr = Some(original_addr.into());
        self.rewritten_addr = Some(rewritten_addr.into());
        self.clamp_profile_entry = Some(clamp_profile_entry.into());
        self
    }

    /// PR 4 Phase F: attach routine-spawn provenance to an audit record.
    ///
    /// * `spawn_sha256` — always set on `ProcessSpawn` decisions when
    ///   `SpawnProvenance` was computed (Phase D plumbs this).
    /// * `matched_routine_root` — `Some` when the canonical path was
    ///   under a profile-declared root.
    /// * `shadow_phase3_filters` — JSON list of `{filter, score}` for
    ///   every phase-3 filter that matched. Caller passes `None` to
    ///   skip when the routine signal didn't apply.
    pub fn with_spawn_provenance(
        mut self,
        spawn_sha256: Option<String>,
        matched_routine_root: Option<String>,
        shadow_phase3_filters: Option<String>,
    ) -> Self {
        self.spawn_sha256 = spawn_sha256;
        self.matched_routine_root = matched_routine_root;
        self.shadow_phase3_filters = shadow_phase3_filters;
        self
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

    /// Attach the session's project name (from `--project` or the cwd basename)
    /// so audit history can be labelled by project after the session ends.
    pub fn with_project_name(mut self, project_name: Option<String>) -> Self {
        self.project_name = project_name;
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
    fn summarize_arguments_with_limit_respects_higher_cap() {
        // 1 KB payload that the default 256-byte limit would chop. With
        // the spawn-limit (4096 B) the full payload fits without
        // truncation.
        let payload = "a".repeat(1024);
        let args = serde_json::json!({"data": payload});
        let small = summarize_arguments_with_limit(&args, DEFAULT_SUMMARY_LIMIT);
        let big = summarize_arguments_with_limit(&args, SPAWN_SUMMARY_LIMIT);
        assert!(small.ends_with("..."));
        assert_eq!(small.len(), DEFAULT_SUMMARY_LIMIT);
        assert!(
            !big.ends_with("..."),
            "1 KB payload fits inside 4 KB spawn limit without truncation"
        );
        assert!(big.contains(&"a".repeat(1024)));
    }

    #[test]
    fn summarize_arguments_with_limit_chops_above_cap() {
        // 8 KB payload exceeds even the spawn limit — must truncate.
        let payload = "b".repeat(8 * 1024);
        let args = serde_json::json!({"data": payload});
        let big = summarize_arguments_with_limit(&args, SPAWN_SUMMARY_LIMIT);
        assert!(big.ends_with("..."));
        assert!(big.len() <= SPAWN_SUMMARY_LIMIT);
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
