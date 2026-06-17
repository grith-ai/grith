// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Integration test helpers and fixtures for the grith workspace.
//!
//! Provides pre-configured subsystems for writing integration tests across
//! all grith crates. The [`TestFixtures`] struct sets up an in-memory audit
//! storage, in-memory digest queue, and a fully populated security proxy with
//! all default filters.

use std::sync::{Arc, Mutex};

// Re-export commonly used types from workspace crates.
pub use grith_audit::{AuditRecord, AuditStorage, FilterResultSummary, ProxyActionSummary};
pub use grith_digest::{DigestItem, DigestQueue, DigestStatus, ReviewAction};
pub use grith_proxy::engine::SecurityProxy;
pub use grith_proxy::filters::allowlist::{AllowlistConfig, AllowlistFilter};
pub use grith_proxy::filters::argument::ArgumentFilter;
pub use grith_proxy::filters::canary::{CanaryFilter, CanaryRegistry};
pub use grith_proxy::filters::capability::{CapabilityFilter, CapabilityGrant};
pub use grith_proxy::filters::command::{CommandFilter, CommandRule};
pub use grith_proxy::filters::destructive_action::DestructiveActionFilter;
pub use grith_proxy::filters::dlp_gate::DlpGateFilter;
pub use grith_proxy::filters::egress_policy::{EgressPolicyConfig, EgressPolicyFilter};
pub use grith_proxy::filters::egress_rate::EgressRateFilter;
pub use grith_proxy::filters::operation_risk::OperationRiskFilter;
pub use grith_proxy::filters::path_match::{PathMatchFilter, PathRule};
pub use grith_proxy::filters::rate_limit::RateLimitFilter;
pub use grith_proxy::filters::reputation::ReputationFilter;
pub use grith_proxy::filters::secret_scan::{SecretPattern, SecretScanFilter};
pub use grith_proxy::filters::sensitive_path::SensitivePathHeuristicFilter;
pub use grith_proxy::filters::session_containment::SessionContainmentFilter;
pub use grith_proxy::filters::taint::TaintFilter;
pub use grith_proxy::filters::FilterRegistry;
pub use grith_proxy::meta_rules::MetaRuleEngine;
pub use grith_proxy::scoring::ScoringConfig;
pub use grith_proxy::types::{
    FilterResult, ProxyAction, ProxyDecision, QueuePriority, Severity, TaintLevel, ToolCallContext,
    ToolCallType,
};

/// Build a `SecurityProxy` from the **real shipped `config/filters/*.toml`** —
/// the FP-research §6.3 fidelity harness. Unlike [`TestFixtures::default_filter_registry`]
/// (simplified inline rules), this loads the production path-match, secret-scan
/// (full ~1600-pattern corpus), command, and egress configs, and wires the
/// static + context filters with the same flags `config/default.toml` ships
/// after the FP fixes (`taint_data_flow_only = true`,
/// `taint_outbound_requires_data_flow = true`, `risk_gated_burst = true`,
/// `routine_provenance_signal = false`). `ScoringConfig::default()` matches the
/// shipped fixed `3.0`/`8.0` thresholds (there is no cold-start widening).
///
/// Included filters: operation_risk, path_match, sensitive_path, argument,
/// secret_scan, command, destructive_action, egress_policy, **reputation** (static safe/malicious
/// lists + raw-IP/suspicious-TLD scoring — it can ADD score on a single
/// stateless op, so it is registered for fidelity), taint, rate_limit.
///
/// Deliberately EXCLUDED (documented fidelity gaps): allowlist + capability
/// (reduce/neutralise — omission OVER-counts, safe); dlp_gate + canary +
/// session_containment (exfil-specific); behavioural + egress_rate (per-session
/// STATEFUL — cold on the fresh-session corpus); the meta-rule engine (its only
/// score-ADDING rule, `env-exfiltration-risk +5.0`, needs accumulated env-file
/// taint, which the fresh-session corpus never builds).
///
/// **Fidelity caveat:** because the corpus replays each op in a FRESH session
/// (no taint/rate/behavioural accumulation), this harness validates the
/// *single-op, cold-state* regime only. Taint-accumulation FP floods (read a
/// credential → N tainted ops → meta-rule `env-exfiltration-risk`) are NOT
/// exercised here and need a separate stateful-sequence fixture.
pub fn production_filter_registry() -> SecurityProxy {
    use serde::Deserialize;
    let dir =
        std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/filters"));
    let read = |f: &str| {
        let p = dir.join(f);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    };

    #[derive(Deserialize)]
    struct Rules<T> {
        rules: Vec<T>,
    }
    #[derive(Deserialize)]
    struct Patterns {
        patterns: Vec<SecretPattern>,
    }
    #[derive(Deserialize)]
    struct EgressFile {
        egress: EgressPolicyConfig,
    }
    #[derive(Deserialize, Default)]
    struct DomainList {
        #[serde(default)]
        domains: Vec<String>,
    }
    #[derive(Deserialize)]
    struct DomainsFile {
        #[serde(default)]
        known_safe: DomainList,
        #[serde(default)]
        known_malicious: DomainList,
    }

    let path_rules: Rules<PathRule> = toml::from_str(&read("paths.toml")).expect("paths.toml");
    let command_rules: Rules<CommandRule> =
        toml::from_str(&read("commands.toml")).expect("commands.toml");
    let secrets: Patterns = toml::from_str(&read("secrets.toml")).expect("secrets.toml");
    let egress: EgressFile = toml::from_str(&read("egress.toml")).expect("egress.toml");
    let domains: DomainsFile = toml::from_str(&read("domains.toml")).expect("domains.toml");
    let safe: std::collections::HashSet<String> = domains
        .known_safe
        .domains
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect();
    let malicious: std::collections::HashSet<String> = domains
        .known_malicious
        .domains
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect();

    let mut reg = FilterRegistry::new();
    // Phase 1 (static)
    reg.register(Box::new(OperationRiskFilter::with_routine_signal(false)));
    reg.register(Box::new(PathMatchFilter::new(path_rules.rules)));
    reg.register(Box::new(SensitivePathHeuristicFilter::new()));
    reg.register(Box::new(ArgumentFilter::new()));
    // Phase 2 (pattern)
    reg.register(Box::new(SecretScanFilter::new(secrets.patterns)));
    reg.register(Box::new(CommandFilter::new(command_rules.rules)));
    reg.register(Box::new(DestructiveActionFilter::new()));
    if egress.egress.enabled {
        reg.register(Box::new(EgressPolicyFilter::from_config(egress.egress)));
    }
    // Phase 3 (context) — flags as shipped post-FP-fixes.
    reg.register(Box::new(ReputationFilter::new(malicious, safe)));
    reg.register(Box::new(
        TaintFilter::with_defaults()
            .with_spawn_data_flow_only(true)
            .with_outbound_taint_requires_data_flow(true),
    ));
    reg.register(Box::new(
        RateLimitFilter::with_defaults().with_risk_gated_burst(true),
    ));

    SecurityProxy::new(reg, ScoringConfig::default(), MetaRuleEngine::new(vec![]))
}

/// Pre-configured test environment with all subsystems ready for integration testing.
pub struct TestFixtures {
    /// In-memory audit storage, wrapped in Arc<Mutex> for shared access.
    pub audit_storage: Arc<Mutex<AuditStorage>>,
    /// In-memory digest queue, wrapped in Arc for shared access.
    pub digest_queue: Arc<DigestQueue>,
    /// Security proxy with all 6 default filters registered.
    pub proxy: SecurityProxy,
}

impl TestFixtures {
    /// Create a new test environment with default configuration.
    ///
    /// Sets up:
    /// - In-memory AuditStorage
    /// - In-memory DigestQueue
    /// - SecurityProxy with all 6 default filters (path_match, secret_scan,
    ///   command, allowlist, argument, capability)
    /// - Default ScoringConfig and empty MetaRuleEngine
    pub fn new() -> Self {
        let audit_storage = Arc::new(Mutex::new(
            AuditStorage::open_in_memory().expect("failed to create in-memory audit storage"),
        ));

        let digest_queue = Arc::new(
            DigestQueue::open_in_memory().expect("failed to create in-memory digest queue"),
        );

        let registry = Self::default_filter_registry();
        let scoring = ScoringConfig::default();
        let meta_rules = MetaRuleEngine::new(vec![]);
        let proxy = SecurityProxy::new(registry, scoring, meta_rules);

        Self {
            audit_storage,
            digest_queue,
            proxy,
        }
    }

    /// Create a new test environment with custom scoring configuration.
    pub fn with_scoring(scoring: ScoringConfig) -> Self {
        let audit_storage = Arc::new(Mutex::new(
            AuditStorage::open_in_memory().expect("failed to create in-memory audit storage"),
        ));

        let digest_queue = Arc::new(
            DigestQueue::open_in_memory().expect("failed to create in-memory digest queue"),
        );

        let registry = Self::default_filter_registry();
        let meta_rules = MetaRuleEngine::new(vec![]);
        let proxy = SecurityProxy::new(registry, scoring, meta_rules);

        Self {
            audit_storage,
            digest_queue,
            proxy,
        }
    }

    /// Create a test environment with all filters including Phase 16 exfiltration
    /// containment filters (egress_policy, dlp_gate, session_containment, egress_rate, canary).
    pub fn with_all_filters() -> Self {
        let audit_storage = Arc::new(Mutex::new(
            AuditStorage::open_in_memory().expect("failed to create in-memory audit storage"),
        ));

        let digest_queue = Arc::new(
            DigestQueue::open_in_memory().expect("failed to create in-memory digest queue"),
        );

        let registry = Self::full_filter_registry();
        let scoring = ScoringConfig::default();
        let meta_rules = MetaRuleEngine::new(vec![]);
        let proxy = SecurityProxy::new(registry, scoring, meta_rules);

        Self {
            audit_storage,
            digest_queue,
            proxy,
        }
    }

    /// Create a test environment with all filters and custom scoring configuration.
    pub fn with_all_filters_and_scoring(scoring: ScoringConfig) -> Self {
        let audit_storage = Arc::new(Mutex::new(
            AuditStorage::open_in_memory().expect("failed to create in-memory audit storage"),
        ));

        let digest_queue = Arc::new(
            DigestQueue::open_in_memory().expect("failed to create in-memory digest queue"),
        );

        let registry = Self::full_filter_registry();
        let meta_rules = MetaRuleEngine::new(vec![]);
        let proxy = SecurityProxy::new(registry, scoring, meta_rules);

        Self {
            audit_storage,
            digest_queue,
            proxy,
        }
    }

    /// Build a FilterRegistry with all default filters plus Phase 16 exfiltration filters.
    pub fn full_filter_registry() -> FilterRegistry {
        let mut registry = Self::default_filter_registry();

        // Phase 1: heuristic sensitive-path filter (production ships it).
        registry.register(Box::new(SensitivePathHeuristicFilter::new()));

        // Phase 2: Pattern filters (v1.6)
        registry.register(Box::new(DestructiveActionFilter::new()));
        registry.register(Box::new(EgressPolicyFilter::with_defaults()));
        registry.register(Box::new(DlpGateFilter::with_defaults()));
        registry.register(Box::new(CanaryFilter::new(Arc::new(
            CanaryRegistry::empty(),
        ))));

        // Phase 3: Context filters (v1.6)
        let (containment, _tracker) = SessionContainmentFilter::with_defaults();
        registry.register(Box::new(containment));
        registry.register(Box::new(EgressRateFilter::with_defaults()));

        registry
    }

    /// Build a FilterRegistry populated with all 6 default filter instances.
    ///
    /// Filters registered:
    /// - **path_match** (Phase 1 Static): Detects access to sensitive paths
    ///   (SSH keys, .env files, PEM certificates)
    /// - **allowlist** (Phase 1 Static): User-defined allow/deny lists
    ///   (empty defaults, permissive)
    /// - **argument** (Phase 1 Static): Validates argument structure, detects
    ///   injection and traversal patterns
    /// - **capability** (Phase 1 Static): Plugin capability token validation
    ///   (empty grants, permissive)
    /// - **secret_scan** (Phase 2 Pattern): Regex-based secret detection
    ///   (AWS keys, GitHub tokens, private key blocks, generic API keys)
    /// - **command** (Phase 2 Pattern): Dangerous shell command pattern
    ///   detection (pipe-to-curl, sudo, chmod+s, base64 decode)
    pub fn default_filter_registry() -> FilterRegistry {
        let mut registry = FilterRegistry::new();

        // Phase 1: Static filters
        registry.register(Box::new(PathMatchFilter::new(default_path_rules())));
        registry.register(Box::new(AllowlistFilter::new(AllowlistConfig::default())));
        registry.register(Box::new(ArgumentFilter::new()));
        registry.register(Box::new(CapabilityFilter::new(vec![])));

        // Phase 2: Pattern filters
        registry.register(Box::new(SecretScanFilter::new(default_secret_patterns())));
        registry.register(Box::new(CommandFilter::new(default_command_rules())));

        registry
    }
}

impl Default for TestFixtures {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a [`ToolCallContext`] for use in tests.
///
/// Creates a context with a new random session ID and sequence number 0.
///
/// # Arguments
///
/// * `call_type` - The type of tool call (FileRead, ShellExec, etc.)
/// * `args_json` - JSON value to attach as arguments
///
/// # Example
///
/// ```
/// use grith_tests::{make_tool_call_context, ToolCallType};
///
/// let ctx = make_tool_call_context(
///     ToolCallType::FileRead { path: "/etc/passwd".into() },
///     serde_json::json!({"path": "/etc/passwd"}),
/// );
/// assert_eq!(ctx.path(), Some("/etc/passwd"));
/// ```
pub fn make_tool_call_context(
    call_type: ToolCallType,
    args_json: serde_json::Value,
) -> ToolCallContext {
    let mut ctx = ToolCallContext::new("test-plugin", call_type, uuid::Uuid::new_v4());
    ctx.arguments = args_json;
    ctx
}

/// Default path matching rules used by [`TestFixtures`].
///
/// Includes rules for SSH private keys, SSH directory, .env files, and PEM files.
pub fn default_path_rules() -> Vec<PathRule> {
    vec![
        PathRule {
            id: "ssh-private-key".into(),
            pattern: "~/.ssh/id_*".into(),
            operations: vec!["read".into(), "write".into(), "delete".into()],
            score: 5.0,
            severity: "critical".into(),
            message: "Access to SSH private key".into(),
            exclude: vec![],
        },
        PathRule {
            id: "ssh-dir".into(),
            pattern: "~/.ssh/*".into(),
            operations: vec![
                "read".into(),
                "write".into(),
                "delete".into(),
                "list".into(),
            ],
            score: 3.0,
            severity: "warning".into(),
            message: "Access to SSH directory".into(),
            exclude: vec![],
        },
        PathRule {
            id: "env-file".into(),
            pattern: ".env".into(),
            operations: vec!["read".into(), "write".into(), "delete".into()],
            score: 3.0,
            severity: "warning".into(),
            message: "Access to environment file".into(),
            exclude: vec![],
        },
        PathRule {
            id: "pem-files".into(),
            pattern: "*.pem".into(),
            operations: vec!["read".into(), "write".into(), "delete".into()],
            score: 4.0,
            severity: "error".into(),
            message: "Access to PEM file".into(),
            exclude: vec![],
        },
    ]
}

/// Default secret scanning patterns used by [`TestFixtures`].
///
/// Includes patterns for AWS access keys, GitHub tokens, private key blocks,
/// and generic API keys.
pub fn default_secret_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            id: "aws-access-key".into(),
            regex: "AKIA[0-9A-Z]{16}".into(),
            score: 5.0,
            severity: "critical".into(),
            message: "AWS access key ID detected".into(),
        },
        SecretPattern {
            id: "github-token".into(),
            regex: "gh[ps]_[A-Za-z0-9_]{36,}".into(),
            score: 5.0,
            severity: "critical".into(),
            message: "GitHub token detected".into(),
        },
        SecretPattern {
            id: "private-key-block".into(),
            regex: "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----".into(),
            score: 5.0,
            severity: "critical".into(),
            message: "Private key block detected".into(),
        },
        SecretPattern {
            id: "generic-api-key".into(),
            regex: r#"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9]{20,}['"]?"#.into(),
            score: 3.0,
            severity: "warning".into(),
            message: "Potential API key detected".into(),
        },
    ]
}

/// Default command analysis rules used by [`TestFixtures`].
///
/// Includes rules for pipe-to-curl, pipe-to-nc, sudo, chmod+s, and base64 decode.
pub fn default_command_rules() -> Vec<CommandRule> {
    vec![
        CommandRule {
            id: "pipe-to-curl".into(),
            pattern: "| curl".into(),
            score: 4.0,
            severity: "error".into(),
            message: "Pipe output to curl (potential exfiltration)".into(),
        },
        CommandRule {
            id: "pipe-to-nc".into(),
            pattern: "| nc".into(),
            score: 4.0,
            severity: "error".into(),
            message: "Pipe output to netcat".into(),
        },
        CommandRule {
            id: "sudo".into(),
            pattern: "sudo".into(),
            score: 3.0,
            severity: "warning".into(),
            message: "Privilege escalation via sudo".into(),
        },
        CommandRule {
            id: "chmod-suid".into(),
            pattern: "chmod +s".into(),
            score: 4.0,
            severity: "error".into(),
            message: "Setting SUID bit".into(),
        },
        CommandRule {
            id: "base64-decode".into(),
            pattern: "base64 -d".into(),
            score: 2.0,
            severity: "warning".into(),
            message: "Base64 decode (potential encoded payload)".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixtures_creation() {
        let fixtures = TestFixtures::new();
        assert_eq!(fixtures.proxy.filter_count(), 6);
        assert_eq!(fixtures.proxy.call_count(), 0);
    }

    #[test]
    fn test_fixtures_default_trait() {
        let fixtures = TestFixtures::default();
        assert_eq!(fixtures.proxy.filter_count(), 6);
    }

    #[test]
    fn test_fixtures_with_scoring() {
        let scoring = ScoringConfig {
            auto_allow_threshold: 5.0,
            auto_deny_threshold: 9.0,
        };
        let fixtures = TestFixtures::with_scoring(scoring);
        assert_eq!(fixtures.proxy.filter_count(), 6);
    }

    #[test]
    fn test_audit_storage_accessible() {
        let fixtures = TestFixtures::new();
        let storage = fixtures.audit_storage.lock().unwrap();
        assert_eq!(storage.count().unwrap(), 0);
    }

    #[test]
    fn test_digest_queue_accessible() {
        let fixtures = TestFixtures::new();
        assert_eq!(fixtures.digest_queue.count_pending().unwrap(), 0);
    }

    #[test]
    fn test_make_tool_call_context_file_read() {
        let ctx = make_tool_call_context(
            ToolCallType::FileRead {
                path: "/etc/passwd".into(),
            },
            serde_json::json!({"path": "/etc/passwd"}),
        );
        assert_eq!(ctx.path(), Some("/etc/passwd"));
        assert_eq!(ctx.plugin_id, "test-plugin");
    }

    #[test]
    fn test_make_tool_call_context_shell_exec() {
        let ctx = make_tool_call_context(
            ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec!["-la".into()],
            },
            serde_json::json!({"command": "ls", "args": ["-la"]}),
        );
        assert_eq!(ctx.command(), Some("ls"));
        assert_eq!(ctx.full_command(), Some("ls -la".into()));
    }

    #[test]
    fn test_make_tool_call_context_http_request() {
        let ctx = make_tool_call_context(
            ToolCallType::HttpRequest {
                method: "GET".into(),
                url: "https://api.example.com".into(),
            },
            serde_json::json!({}),
        );
        assert_eq!(ctx.url(), Some("https://api.example.com"));
    }

    #[tokio::test]
    async fn test_proxy_evaluates_safe_call() {
        let fixtures = TestFixtures::new();
        let ctx = make_tool_call_context(
            ToolCallType::FileRead {
                path: "/tmp/safe.txt".into(),
            },
            serde_json::json!({}),
        );
        let decision = fixtures.proxy.evaluate(&ctx).await;
        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn test_proxy_flags_sensitive_path() {
        let fixtures = TestFixtures::new();
        let ctx = make_tool_call_context(
            ToolCallType::FileRead {
                path: "/home/user/.ssh/id_rsa".into(),
            },
            serde_json::json!({}),
        );
        let decision = fixtures.proxy.evaluate(&ctx).await;
        // SSH key access should produce a non-zero score
        assert!(decision.composite_score > 0.0);
    }

    #[test]
    fn test_default_filter_registry_count() {
        let registry = TestFixtures::default_filter_registry();
        assert_eq!(registry.count(), 6);
    }

    #[test]
    fn test_default_path_rules_count() {
        assert_eq!(default_path_rules().len(), 4);
    }

    #[test]
    fn test_default_secret_patterns_count() {
        assert_eq!(default_secret_patterns().len(), 4);
    }

    #[test]
    fn test_default_command_rules_count() {
        assert_eq!(default_command_rules().len(), 5);
    }
}
