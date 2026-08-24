// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Core audit data types shared across the crate.

use chrono::{DateTime, Utc};
use grith_analytics::contract::{
    Category, CompletenessTier, DestinationKind, RecordClass, ResolutionStatus, SecurityEventType,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// Configuration facts that cannot be reconstructed after a policy/profile
/// changes. Producers attach this envelope while handling the event; the
/// analytics adapter never mines free-form arguments or current config files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditConfigVersion {
    pub profile_id: String,
    pub profile_version: String,
    pub config_hash: String,
    pub policy_version: String,
    pub auto_allow_threshold_micros: i64,
    pub auto_deny_threshold_micros: i64,
    pub queue_policy: String,
    pub team_default_config_version: String,
}

/// Exact pricing provenance captured with an LLM accounting event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLlmPricing {
    pub cost_micros: u64,
    pub price_source: String,
    pub pricing_version: String,
}

/// Privacy-safe destination identity. Raw URLs, hosts, ports and Unix socket
/// paths are deliberately not representable in the analytics envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditDestinationMetadata {
    pub kind: DestinationKind,
    pub destination_hmac: String,
    pub hmac_key_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_display_label: Option<String>,
}

/// Mutable security-workflow facts captured separately from the immutable
/// initial policy verdict used by headline analytics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSecurityMetadata {
    pub event_type: SecurityEventType,
    pub event_revision: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_status: Option<ResolutionStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_outcome_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap_count: Option<u64>,
}

/// Prospective, operand-free analytics metadata persisted with an audit row.
///
/// Rows that predate this envelope remain valid audit evidence, but strict
/// cloud producers must reject them rather than inventing historic profile,
/// configuration, pricing or destination facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnalyticsMetadata {
    pub metadata_version: u16,
    pub completeness: CompletenessTier,
    pub record_class: RecordClass,
    pub category: Category,
    pub config: AuditConfigVersion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_set_version: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_pricing: Option<AuditLlmPricing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<AuditDestinationMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<AuditSecurityMetadata>,
}

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
    /// Redacted human-readable reason for the final policy decision.
    ///
    /// Optional for backwards compatibility and for callers that do not
    /// produce a stable reason. Security-sensitive callers should redact this
    /// field before constructing the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    /// Stable description of what enforcement did after policy evaluation.
    ///
    /// This is distinct from `proxy_action`: a queued DNS decision, for
    /// example, may be refused or forwarded depending on compatibility policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_outcome: Option<String>,
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

    /// Which canonical form produced `record_hash` (B12 item 5).
    ///
    /// * `1` — the legacy 9-field pipe-joined form. Covers only id,
    ///   timestamp, session, plugin, call type, arguments hash, score,
    ///   action and `prev_hash`; every other field could be rewritten
    ///   while verification stayed green.
    /// * `2` — [`AuditRecord::compute_record_hash_v2`], covering every
    ///   persisted evidence field that existed before analytics-v2.
    /// * `3` — v2's frozen canonical digest plus every field in the
    ///   prospective analytics metadata envelope.
    ///
    /// Rows written before this field existed deserialize (and read back
    /// from a NULL column) as `1`, so archived history keeps verifying
    /// without a single row being rewritten. New records stamp
    /// [`CURRENT_HASH_VERSION`].
    #[serde(default = "default_hash_version")]
    pub hash_version: u8,

    /// Safe analytics dimensions captured at event time. Kept optional so
    /// v1/v2 databases and cold archives continue to deserialize unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analytics_metadata: Option<AuditAnalyticsMetadata>,
}

fn default_source() -> String {
    "wasm".to_string()
}

/// Canonical form used for records written by this build.
pub const CURRENT_HASH_VERSION: u8 = 3;

/// Frozen full-record canonical form used before analytics metadata existed.
pub const HASH_VERSION_V2: u8 = 2;

/// Canonical form assumed for rows that predate `hash_version`.
pub const LEGACY_HASH_VERSION: u8 = 1;

fn default_hash_version() -> u8 {
    LEGACY_HASH_VERSION
}

const fn completeness_name(value: CompletenessTier) -> &'static str {
    match value {
        CompletenessTier::Decisions => "decisions",
        CompletenessTier::Spawns => "spawns",
        CompletenessTier::Io => "io",
        CompletenessTier::All => "all",
    }
}

const fn record_class_name(value: RecordClass) -> &'static str {
    match value {
        RecordClass::Decision => "decision",
        RecordClass::RoutineSpawn => "routine_spawn",
        RecordClass::RoutineIo => "routine_io",
        RecordClass::Noise => "noise",
        RecordClass::LlmUsage => "llm_usage",
        RecordClass::System => "system",
    }
}

const fn category_name(value: Category) -> &'static str {
    match value {
        Category::FileRead => "file_read",
        Category::FileMutation => "file_mutation",
        Category::Process => "process",
        Category::NetworkEgress => "network_egress",
        Category::NetworkListen => "network_listen",
        Category::CrossProcess => "cross_process",
        Category::Namespace => "namespace",
        Category::Llm => "llm",
        Category::System => "system",
        Category::Other => "other",
    }
}

const fn destination_kind_name(value: DestinationKind) -> &'static str {
    match value {
        DestinationKind::Domain => "domain",
        DestinationKind::HostPort => "host_port",
        DestinationKind::UrlOrigin => "url_origin",
        DestinationKind::UnixSocketClass => "unix_socket_class",
        DestinationKind::Other => "other",
    }
}

const fn security_event_type_name(value: SecurityEventType) -> &'static str {
    match value {
        SecurityEventType::Queue => "queue",
        SecurityEventType::Deny => "deny",
        SecurityEventType::Canary => "canary",
        SecurityEventType::Gap => "gap",
    }
}

const fn resolution_status_name(value: ResolutionStatus) -> &'static str {
    match value {
        ResolutionStatus::Pending => "pending",
        ResolutionStatus::Approved => "approved",
        ResolutionStatus::Denied => "denied",
        ResolutionStatus::Expired => "expired",
        ResolutionStatus::Escalated => "escalated",
    }
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

/// Aggregate allow / queue / deny counts over a time window.
///
/// Powers the dashboard hero, which must show one internally consistent set
/// of numbers: `total` and the three verdict counts always describe the same
/// window of the same table. (`total` can exceed `allow + queue + deny` if a
/// row carries a non-canonical `proxy_action` — the chain verifier reports
/// that as tampering rather than this aggregate silently absorbing it.)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionSummary {
    /// Rows in the window, whatever their verdict.
    pub total: usize,
    /// Rows the proxy allowed.
    pub allow: usize,
    /// Rows the proxy queued for review.
    pub queue: usize,
    /// Rows the proxy denied.
    pub deny: usize,
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
    /// The active segment does not begin at sequence 1 and no archive
    /// boundary anchor is available to prove it continues an archived prefix.
    ///
    /// work/74 §9: this is the state that previously produced a false
    /// `Broken` and triggered destructive `repair_chain()`. It is **not**
    /// evidence of tampering — the anchor is missing, not the data. It is
    /// recoverable without rewriting a single row by re-deriving the boundary
    /// from cold archives (`retention::resolve_boundary_from_archives`).
    Unanchored {
        /// Lowest `chain_sequence` present in the active database.
        first_sequence: i64,
    },
    /// An archive boundary anchor exists but does not link to the active
    /// segment. Unlike `Unanchored`, this *is* a genuine discontinuity: the
    /// archived history and the active segment cannot be joined.
    AnchorMismatch {
        /// Terminal sequence recorded by the archive boundary.
        boundary_sequence: i64,
        /// Terminal record hash recorded by the archive boundary.
        expected_prev_hash: String,
        /// `prev_hash` actually found on the first active row.
        found_prev_hash: Option<String>,
        /// Lowest `chain_sequence` present in the active database.
        first_sequence: i64,
    },
}

impl ChainVerification {
    /// True when the chain is in a state the daemon may write to.
    ///
    /// `Unanchored` is deliberately **not** healthy: the daemon should first
    /// attempt boundary recovery from cold archives, and quarantine only if
    /// that fails. It is separated from `Broken` so an operator can tell a
    /// missing anchor apart from actual tampering.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Valid { .. } | Self::Empty)
    }

    /// True when the outcome represents genuine evidence of corruption or
    /// tampering, as opposed to a recoverable missing anchor.
    #[must_use]
    pub fn is_tamper_evidence(&self) -> bool {
        matches!(self, Self::Broken { .. } | Self::AnchorMismatch { .. })
    }

    /// Short stable identifier for logs, metrics and diagnostics.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Valid { .. } => "valid",
            Self::Broken { .. } => "broken",
            Self::Empty => "empty",
            Self::Unanchored { .. } => "unanchored",
            Self::AnchorMismatch { .. } => "anchor_mismatch",
        }
    }
}

/// Durable link from the archived (cold) prefix to the active segment.
///
/// work/74 Phase 6. Before this existed, the *only* thing tying the active
/// database to its archived prefix was the `verified_head` performance
/// checkpoint — and `repair_chain()` deletes that, so a single false break
/// was enough to sever the chain permanently (§9).
///
/// This anchor is written atomically with the prune that creates it and is
/// never removed by verification or repair. It is the authority for "the
/// active segment legitimately starts above sequence 1".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveBoundary {
    /// Highest `chain_sequence` that was moved to cold storage.
    pub last_archived_sequence: i64,
    /// `record_hash` of that terminal archived record. The first surviving
    /// active row must carry this as its `prev_hash`.
    pub last_archived_record_hash: String,
    /// When this boundary was last written.
    pub updated_at: DateTime<Utc>,
}

/// Durable record that the local audit history spans more than one
/// segment (B12 item 7).
///
/// The 0.1.4 automatic `repair_chain()` could leave an archived prefix
/// ending at one sequence while the active database restarted from
/// sequence 1 with `prev_hash = NULL`. Verification reads that active
/// segment as a legitimate genesis and reports `Valid`, which is true of
/// the segment but silent about the discontinuity — the compliance claim
/// "one unbroken chain" does not hold on such a machine.
///
/// Recording the fact is the honest response: the history is not
/// reconnectable without rewriting records, and rewriting evidence to make
/// a verifier happy is the behaviour that caused the incident. Operators
/// and `grith audit diagnose` can then see two segments and say so.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentHistory {
    /// Highest `chain_sequence` found in cold archives at classification.
    pub archive_terminal_sequence: i64,
    /// `record_hash` of that archived terminal record, when it carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_terminal_hash: Option<String>,
    /// Lowest `chain_sequence` in the active segment (1 for a re-genesis).
    pub active_genesis_sequence: i64,
    /// Machine-readable cause, e.g. `"active_regenesis_with_archives"`.
    pub cause: String,
    /// Human-readable explanation shown by diagnose.
    pub reason: String,
    /// When the discontinuity was classified.
    pub classified_at: DateTime<Utc>,
}

/// Compute SHA-256 hash of arbitrary data, returning hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Length-prefixed canonical encoder for the v2 record hash.
///
/// Every entry is written as `name<US>tag<byte-len><US>value<RS>`, so the
/// byte length delimits each value and no field content can forge a
/// boundary — unlike a delimiter-joined form, where a value containing the
/// delimiter lets an attacker shift content between fields while keeping
/// the concatenation (and therefore the hash) identical.
struct Canonical {
    buf: String,
}

const UNIT_SEP: char = '\u{1f}';
const REC_SEP: char = '\u{1e}';

impl Canonical {
    fn new(domain: &str) -> Self {
        let mut buf = String::with_capacity(1024);
        buf.push_str(domain);
        buf.push(REC_SEP);
        Self { buf }
    }

    /// A present string value.
    fn text(&mut self, name: &str, value: &str) {
        use std::fmt::Write as _;
        let _ = write!(
            self.buf,
            "{name}{UNIT_SEP}+{}{UNIT_SEP}{value}{REC_SEP}",
            value.len()
        );
    }

    /// An explicitly absent optional value. Distinct from `text(name, "")`
    /// because the tag differs, so `None` and `Some("")` never collide.
    fn absent(&mut self, name: &str) {
        use std::fmt::Write as _;
        let _ = write!(self.buf, "{name}{UNIT_SEP}-{UNIT_SEP}{REC_SEP}");
    }

    fn opt_text(&mut self, name: &str, value: Option<&str>) {
        match value {
            Some(v) => self.text(name, v),
            None => self.absent(name),
        }
    }

    /// A float, encoded as its IEEE-754 bit pattern.
    ///
    /// Bits rather than a decimal rendering: the encoding is then exact by
    /// construction, independent of any formatting behaviour that could
    /// drift between Rust versions, and it keeps `0.0`/`-0.0` distinct.
    fn float(&mut self, name: &str, value: f64) {
        self.text(name, &format!("{:016x}", value.to_bits()));
    }

    /// Element count for a sequence, so a truncated sequence cannot hash
    /// the same as the original.
    fn count(&mut self, name: &str, n: usize) {
        self.text(&format!("{name}.len"), &n.to_string());
    }

    fn finish(self) -> String {
        self.buf
    }
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
            decision_reason: None,
            enforcement_outcome: None,
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
            hash_version: CURRENT_HASH_VERSION,
            analytics_metadata: None,
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
            decision_reason: None,
            enforcement_outcome: None,
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
            hash_version: CURRENT_HASH_VERSION,
            analytics_metadata: None,
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

    /// Attach the redacted policy reason and final enforcement outcome.
    pub fn with_decision_enforcement(
        mut self,
        decision_reason: Option<String>,
        enforcement_outcome: impl Into<String>,
    ) -> Self {
        self.decision_reason = decision_reason;
        self.enforcement_outcome = Some(enforcement_outcome.into());
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
    /// Dispatches on [`AuditRecord::hash_version`] so a database holding
    /// both legacy and current rows verifies end to end without rewriting
    /// history. An unrecognised version yields a non-hash marker string,
    /// which can never equal a stored SHA-256 and therefore surfaces as a
    /// loud `Broken` at that row rather than being silently accepted.
    pub fn compute_record_hash(&self) -> String {
        match self.hash_version {
            LEGACY_HASH_VERSION => self.compute_record_hash_v1(),
            HASH_VERSION_V2 => self.compute_record_hash_v2(),
            CURRENT_HASH_VERSION => self.compute_record_hash_v3(),
            other => format!("UNSUPPORTED_HASH_VERSION:{other}"),
        }
    }

    /// The original canonical form. Frozen — every archived record ever
    /// written depends on these exact bytes.
    ///
    /// Covers nine fields; `filter_results`, scores, decision reason,
    /// enforcement outcome, execution result, record type, provenance and
    /// the forensic spawn/clamp columns are all absent, which is why v2
    /// exists (B12 item 5).
    fn compute_record_hash_v1(&self) -> String {
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

    /// Full-record canonical form: every persisted evidence field.
    ///
    /// Excludes only `record_hash` (this function's own output). There is
    /// no sync bookkeeping on the model — `synced_at` lives in the schema
    /// alone — so nothing mutable is covered and a sync pass never
    /// invalidates a hash.
    ///
    /// `hash_version` is itself hashed, so an attacker cannot downgrade a
    /// v2 row to v1 to gain access to the fields v1 leaves uncovered.
    ///
    /// Encoding is length-prefixed rather than delimiter-joined: each
    /// field contributes `name<US>tag<len><US>value<RS>`, so no field
    /// value can forge a boundary by containing the separator (a latent
    /// weakness of the v1 pipe-join). `HashMap` fields are emitted in
    /// sorted key order because iteration order is not stable across
    /// processes.
    fn compute_record_hash_v2(&self) -> String {
        let mut c = Canonical::new("grith-audit-record-v2");

        c.text("id", &self.id.to_string());
        c.text("timestamp", &self.timestamp.to_rfc3339());
        c.text("session_id", &self.session_id.to_string());
        c.text("plugin_id", &self.plugin_id);
        c.text("tool_call_type", &self.tool_call_type);
        c.text("arguments_summary", &self.arguments_summary);
        c.text("arguments_hash", &self.arguments_hash);
        c.float("composite_score", self.composite_score);
        c.text("proxy_action", &self.proxy_action.to_string());
        c.opt_text("decision_reason", self.decision_reason.as_deref());
        c.opt_text("enforcement_outcome", self.enforcement_outcome.as_deref());

        // Ordered: filter order is meaningful evidence and is preserved
        // through persistence.
        c.count("filter_results", self.filter_results.len());
        for fr in &self.filter_results {
            c.text("fr.filter_name", &fr.filter_name);
            c.text("fr.matched", if fr.matched { "1" } else { "0" });
            c.float("fr.score", fr.score);
            c.text("fr.rule_id", &fr.rule_id);
            c.text("fr.severity", &fr.severity);
            c.text("fr.message", &fr.message);
        }

        match &self.filter_scores {
            None => c.absent("filter_scores"),
            Some(scores) => {
                let mut keys: Vec<&String> = scores.keys().collect();
                keys.sort();
                c.count("filter_scores", keys.len());
                for k in keys {
                    c.text("fs.key", k);
                    c.float("fs.score", scores[k]);
                }
            }
        }

        c.opt_text("execution_result", self.execution_result.as_deref());
        c.float("evaluation_time_ms", self.evaluation_time_ms);
        c.opt_text("task_context", self.task_context.as_deref());
        c.text("source", &self.source);
        c.opt_text("supervised_tool", self.supervised_tool.as_deref());
        c.opt_text(
            "supervised_pid",
            self.supervised_pid.map(|v| v.to_string()).as_deref(),
        );
        c.opt_text("project_name", self.project_name.as_deref());
        c.opt_text(
            "correlation_id",
            self.correlation_id.map(|v| v.to_string()).as_deref(),
        );
        c.opt_text("prev_hash", self.prev_hash.as_deref());
        c.opt_text(
            "chain_sequence",
            self.chain_sequence.map(|v| v.to_string()).as_deref(),
        );

        c.opt_text("llm_provider", self.llm_provider.as_deref());
        c.opt_text("llm_model", self.llm_model.as_deref());
        c.opt_text(
            "prompt_tokens",
            self.prompt_tokens.map(|v| v.to_string()).as_deref(),
        );
        c.opt_text(
            "completion_tokens",
            self.completion_tokens.map(|v| v.to_string()).as_deref(),
        );
        match self.estimated_cost_usd {
            None => c.absent("estimated_cost_usd"),
            Some(v) => c.float("estimated_cost_usd", v),
        }

        c.opt_text("spawn_sha256", self.spawn_sha256.as_deref());
        c.opt_text("matched_routine_root", self.matched_routine_root.as_deref());
        c.opt_text(
            "shadow_phase3_filters",
            self.shadow_phase3_filters.as_deref(),
        );
        c.opt_text("original_addr", self.original_addr.as_deref());
        c.opt_text("rewritten_addr", self.rewritten_addr.as_deref());
        c.opt_text("clamp_profile_entry", self.clamp_profile_entry.as_deref());
        c.text("record_type", &self.record_type.to_string());
        c.text("hash_version", &self.hash_version.to_string());

        sha256_hex(c.finish().as_bytes())
    }

    /// Analytics-aware canonical form.
    ///
    /// The first value is the digest of the byte-for-byte frozen v2 encoder
    /// over this record. The metadata is then encoded field-by-field with the
    /// same length-prefixed primitive; the hash never depends on JSON object
    /// ordering or serde's incidental formatting.
    fn compute_record_hash_v3(&self) -> String {
        let mut c = Canonical::new("grith-audit-record-v3");
        c.text("v2_canonical_digest", &self.compute_record_hash_v2());
        match &self.analytics_metadata {
            None => c.absent("analytics_metadata"),
            Some(metadata) => {
                c.text("analytics_metadata.present", "1");
                c.text("metadata_version", &metadata.metadata_version.to_string());
                c.text("completeness", completeness_name(metadata.completeness));
                c.text("record_class", record_class_name(metadata.record_class));
                c.text("category", category_name(metadata.category));
                c.text("config.profile_id", &metadata.config.profile_id);
                c.text("config.profile_version", &metadata.config.profile_version);
                c.text("config.config_hash", &metadata.config.config_hash);
                c.text("config.policy_version", &metadata.config.policy_version);
                c.text(
                    "config.auto_allow_threshold_micros",
                    &metadata.config.auto_allow_threshold_micros.to_string(),
                );
                c.text(
                    "config.auto_deny_threshold_micros",
                    &metadata.config.auto_deny_threshold_micros.to_string(),
                );
                c.text("config.queue_policy", &metadata.config.queue_policy);
                c.text(
                    "config.team_default_config_version",
                    &metadata.config.team_default_config_version,
                );
                c.opt_text(
                    "filter_set_version",
                    metadata
                        .filter_set_version
                        .map(|v| v.to_string())
                        .as_deref(),
                );
                match &metadata.llm_pricing {
                    None => c.absent("llm_pricing"),
                    Some(pricing) => {
                        c.text("llm_pricing.present", "1");
                        c.text("llm_pricing.cost_micros", &pricing.cost_micros.to_string());
                        c.text("llm_pricing.price_source", &pricing.price_source);
                        c.text("llm_pricing.pricing_version", &pricing.pricing_version);
                    }
                }
                match &metadata.destination {
                    None => c.absent("destination"),
                    Some(destination) => {
                        c.text("destination.present", "1");
                        c.text("destination.kind", destination_kind_name(destination.kind));
                        c.text("destination.hmac", &destination.destination_hmac);
                        c.text(
                            "destination.key_version",
                            &destination.hmac_key_version.to_string(),
                        );
                        c.opt_text(
                            "destination.approved_display_label",
                            destination.approved_display_label.as_deref(),
                        );
                    }
                }
                match &metadata.security {
                    None => c.absent("security"),
                    Some(security) => {
                        c.text("security.present", "1");
                        c.text(
                            "security.event_type",
                            security_event_type_name(security.event_type),
                        );
                        c.text(
                            "security.event_revision",
                            &security.event_revision.to_string(),
                        );
                        c.opt_text(
                            "security.resolution_status",
                            security.resolution_status.map(resolution_status_name),
                        );
                        c.opt_text(
                            "security.resolved_at",
                            security.resolved_at.map(|v| v.to_rfc3339()).as_deref(),
                        );
                        c.opt_text(
                            "security.resolution_code",
                            security.resolution_code.as_deref(),
                        );
                        c.opt_text(
                            "security.enforcement_outcome_code",
                            security.enforcement_outcome_code.as_deref(),
                        );
                        c.opt_text(
                            "security.gap_count",
                            security.gap_count.map(|v| v.to_string()).as_deref(),
                        );
                    }
                }
            }
        }
        sha256_hex(c.finish().as_bytes())
    }

    /// Attach the complete prospective analytics context before persistence.
    #[must_use]
    pub fn with_analytics_metadata(mut self, metadata: AuditAnalyticsMetadata) -> Self {
        self.analytics_metadata = Some(metadata);
        self
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
                filter_name: "path-match".into(),
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
