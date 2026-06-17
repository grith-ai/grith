// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Path pattern matching filter for filesystem access control.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};
use serde::Deserialize;

/// Configuration for a single path matching rule.
#[derive(Debug, Clone, Deserialize)]
pub struct PathRule {
    pub id: String,
    pub pattern: String,
    pub operations: Vec<String>,
    pub score: f64,
    pub severity: String,
    pub message: String,
    /// FP §5.7: file BASENAMES that exempt a path from this rule even though
    /// `pattern` matched — e.g. the `env-file` rule matches `.env` but excludes
    /// the basename `.env.example` (template scaffolding). Matched basename-
    /// exact (not a path substring), so `.env.example.bak` is NOT exempt.
    /// Default empty.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Path matching filter using linear substring scanning.
///
/// Converts glob-style patterns from configuration into normalized substring
/// fragments. Each path is checked against all rules via `str::contains()`
/// (O(n*m) where n = rules, m = path length), selecting the highest-scoring
/// match. This approach handles overlapping patterns correctly (e.g. ".ssh/"
/// and ".ssh/id_") where all matching rules must be considered.
pub struct PathMatchFilter {
    rules: Vec<PathRule>,
    normalized: Vec<String>,
}

impl PathMatchFilter {
    pub fn new(rules: Vec<PathRule>) -> Self {
        let normalized: Vec<String> = rules
            .iter()
            .map(|r| normalize_pattern(&r.pattern))
            .collect();

        Self { rules, normalized }
    }

    fn operation_for_call_type(call_type: &ToolCallType) -> &str {
        match call_type {
            ToolCallType::FileRead { .. } => "read",
            ToolCallType::FileWrite { .. } => "write",
            ToolCallType::FileAppend { .. } => "write",
            ToolCallType::FileDelete { .. } => "delete",
            ToolCallType::DirList { .. } => "list",
            ToolCallType::ShellExec { .. } => "exec",
            ToolCallType::HttpRequest { .. } => "http",
            ToolCallType::FileRename { .. } => "write",
            ToolCallType::FileChmod { .. } => "write",
            ToolCallType::DirCreate { .. } => "write",
            ToolCallType::NetConnect { .. } => "http",
            ToolCallType::NetListen { .. } => "http",
            ToolCallType::ProcessSpawn { .. } => "exec",
            ToolCallType::DnsQuery { .. } => "dns",
            // PR 6 Phase B: category-2 syscalls.
            ToolCallType::OwnershipChange { .. } => "write",
            ToolCallType::FilesystemMutation { .. } => "write",
            ToolCallType::CrossProcessAccess { .. } => "process",
            ToolCallType::NamespaceOp { .. } => "namespace",
        }
    }
}

/// Normalize a glob-like pattern into a substring for Aho-Corasick matching.
///
/// Examples:
///   "~/.ssh/id_*" → ".ssh/id_"
///   "*.pem"       → ".pem"
///   ".env"        → ".env"
///   ".env.*"      → ".env."
///   "*credentials*" → "credentials"
fn normalize_pattern(pattern: &str) -> String {
    let p = pattern.replace("~/", "");
    let p = p.trim_start_matches('*');
    let p = p.trim_end_matches('*');
    p.to_string()
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        _ => Severity::Notice,
    }
}

#[async_trait::async_trait]
impl SecurityFilter for PathMatchFilter {
    fn name(&self) -> &str {
        "path_match"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Static
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let path = match ctx.path() {
            Some(p) => p,
            None => return Ok(FilterResult::no_match("path_match")),
        };

        let operation = Self::operation_for_call_type(&ctx.call_type);

        // Check all rules for matches and select the highest-scoring one.
        // We use direct substring matching rather than Aho-Corasick's find_iter
        // here because overlapping patterns (e.g. ".ssh/" and ".ssh/id_") need
        // to all be considered. The automaton is kept for potential future use
        // with batch scanning.
        let mut best_match: Option<&PathRule> = None;

        // FP §5.7: the file's basename, for the exclude check below.
        let basename = path.rsplit('/').next().unwrap_or(path);
        for (i, rule) in self.rules.iter().enumerate() {
            if path.contains(self.normalized[i].as_str())
                && rule.operations.iter().any(|op| op == operation)
                // FP §5.7: skip when the file's BASENAME exactly equals one of
                // the rule's exclude entries (e.g. `.env` rule excludes the
                // basename `.env.example`). Basename-exact, NOT a path substring:
                // a substring check would over-exclude `.env.example.bak` (a
                // backup that may hold real values) or a real `.env` inside a
                // directory named `.env.example/`.
                && !rule.exclude.iter().any(|ex| basename == ex.as_str())
            {
                match &best_match {
                    Some(current) if current.score >= rule.score => {}
                    _ => best_match = Some(rule),
                }
            }
        }

        match best_match {
            Some(rule) => {
                let severity = parse_severity(&rule.severity);
                Ok(FilterResult::matched(
                    "path_match",
                    &rule.id,
                    rule.score,
                    severity,
                    &rule.message,
                ))
            }
            None => Ok(FilterResult::no_match("path_match")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCallType;
    use uuid::Uuid;

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    fn default_rules() -> Vec<PathRule> {
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
                operations: vec!["write".into(), "delete".into(), "list".into()],
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

    #[tokio::test]
    async fn test_ssh_key_read_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.ssh/id_rsa".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "ssh-private-key");
        assert_eq!(result.score, 5.0);
    }

    // FP §5.7: `exclude` is matched basename-EXACT, so it exempts `.env.example`
    // but NOT `.env.example.bak` (a backup that may hold real values) and NOT a
    // real `.env` whose parent dir happens to be named `.env.example/`.
    #[tokio::test]
    async fn exclude_is_basename_exact_not_substring() {
        let rules = vec![PathRule {
            id: "env-file".into(),
            pattern: ".env".into(),
            operations: vec!["read".into()],
            score: 3.0,
            severity: "warning".into(),
            message: "env".into(),
            exclude: vec![".env.example".into(), ".env.sample".into()],
        }];
        let filter = PathMatchFilter::new(rules);
        let read = |p: &str| make_ctx(ToolCallType::FileRead { path: p.into() });

        // Exempt: exact template basenames.
        for p in ["/home/u/proj/.env.example", "/home/u/proj/.env.sample"] {
            assert!(
                !filter.evaluate(&read(p)).await.unwrap().matched,
                "{p} (template) must be exempt"
            );
        }
        // NOT exempt (over-exclusion guards): backup, overlay, and a real .env
        // inside a directory named after the template.
        for p in [
            "/home/u/proj/.env",
            "/home/u/proj/.env.production",
            "/home/u/proj/.env.example.bak",
            "/home/u/proj/.env.example.local",
            "/home/u/proj/.env.example/.env",
        ] {
            assert!(
                filter.evaluate(&read(p)).await.unwrap().matched,
                "{p} must still fire env-file"
            );
        }
    }

    #[tokio::test]
    async fn test_ssh_dir_list_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::DirList {
            path: "/home/user/.ssh/".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "ssh-dir");
    }

    #[tokio::test]
    async fn test_ssh_config_read_does_not_match_ssh_dir_rule() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.ssh/config".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_env_file_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/project/.env".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "env-file");
    }

    #[tokio::test]
    async fn test_pem_file_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/etc/ssl/cert.pem".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "pem-files");
        assert_eq!(result.score, 4.0);
    }

    #[tokio::test]
    async fn test_pr6_ownership_change_path_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::OwnershipChange {
            target: "/home/user/.ssh/id_ed25519".into(),
            new_uid: 1000,
            new_gid: 1000,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "ssh-private-key");
    }

    #[tokio::test]
    async fn test_pr6_filesystem_mutation_path_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FilesystemMutation {
            op: "mount".into(),
            source: Some("/dev/sda1".into()),
            target: "/project/.env.mount".into(),
            fstype: Some("ext4".into()),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "env-file");
    }

    #[tokio::test]
    async fn test_safe_path_no_match() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/safe.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_wrong_operation_no_match() {
        let filter = PathMatchFilter::new(default_rules());
        // exec is not in the ssh-private-key operations list
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "cat".into(),
            args: vec![],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched); // ShellExec has no path
    }

    #[tokio::test]
    async fn test_no_path_returns_no_match() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://example.com".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_highest_score_wins() {
        let filter = PathMatchFilter::new(default_rules());
        // This path matches both "ssh-private-key" (5.0) and "ssh-dir" (3.0)
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.ssh/id_ed25519".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "ssh-private-key");
        assert_eq!(result.score, 5.0);
    }

    #[test]
    fn test_normalize_pattern() {
        assert_eq!(normalize_pattern("~/.ssh/id_*"), ".ssh/id_");
        assert_eq!(normalize_pattern("*.pem"), ".pem");
        assert_eq!(normalize_pattern(".env"), ".env");
        assert_eq!(normalize_pattern(".env.*"), ".env.");
        assert_eq!(normalize_pattern("*credentials*"), "credentials");
    }
}
