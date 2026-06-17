// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Capability enforcement filter for plugin permission gates.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

/// A capability grant defining what operations a plugin may perform.
#[derive(Debug, Clone, Deserialize)]
pub struct CapabilityGrant {
    pub plugin: String,
    pub capabilities: Vec<String>,
}

/// Filter that validates plugin capability tokens.
///
/// Each plugin must have explicit capability grants for the operations it
/// performs. A missing grant results in a score of 10.0 (auto-deny).
/// If no grants are configured at all, the filter is permissive (unconfigured).
///
/// Capability format: `category:action` (e.g., `fs:read`, `shell:exec`, `net:http`).
/// The wildcard `*` grants all capabilities.
pub struct CapabilityFilter {
    grants: HashMap<String, HashSet<String>>,
    config_error: Option<String>,
}

impl CapabilityFilter {
    pub fn new(grants: Vec<CapabilityGrant>) -> Self {
        let mut map: HashMap<String, HashSet<String>> = HashMap::new();
        for grant in grants {
            let caps: HashSet<String> = grant.capabilities.into_iter().collect();
            map.entry(grant.plugin)
                .and_modify(|existing| existing.extend(caps.clone()))
                .or_insert(caps);
        }
        Self {
            grants: map,
            config_error: None,
        }
    }

    /// Construct a fail-closed filter state when grants config is unreadable.
    pub fn fail_closed(error: impl Into<String>) -> Self {
        Self {
            grants: HashMap::new(),
            config_error: Some(error.into()),
        }
    }

    fn required_capability(call_type: &ToolCallType) -> &str {
        match call_type {
            ToolCallType::FileRead { .. } => "fs:read",
            ToolCallType::FileWrite { .. } => "fs:write",
            ToolCallType::FileAppend { .. } => "fs:write",
            ToolCallType::FileDelete { .. } => "fs:delete",
            ToolCallType::DirList { .. } => "fs:list",
            ToolCallType::ShellExec { .. } => "shell:exec",
            ToolCallType::HttpRequest { .. } => "net:http",
            ToolCallType::FileRename { .. } => "fs:write",
            ToolCallType::FileChmod { .. } => "fs:write",
            ToolCallType::DirCreate { .. } => "fs:write",
            ToolCallType::NetConnect { .. } => "net:connect",
            ToolCallType::NetListen { .. } => "net:listen",
            ToolCallType::ProcessSpawn { .. } => "shell:exec",
            ToolCallType::DnsQuery { .. } => "net:connect",
            // PR 6 Phase B: category-2 syscalls. Use dedicated
            // capability strings so a profile can grant them
            // explicitly without overloading existing fs:* / net:*
            // capabilities.
            ToolCallType::OwnershipChange { .. } => "fs:ownership",
            ToolCallType::FilesystemMutation { .. } => "fs:mount",
            ToolCallType::CrossProcessAccess { .. } => "process:ptrace",
            ToolCallType::NamespaceOp { .. } => "process:namespace",
        }
    }
}

#[async_trait::async_trait]
impl SecurityFilter for CapabilityFilter {
    fn name(&self) -> &str {
        "capability"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Static
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let required = Self::required_capability(&ctx.call_type);

        // If no grants defined at all, pass through (unconfigured = permissive)
        if self.grants.is_empty() {
            if let Some(err) = &self.config_error {
                return Ok(FilterResult::matched(
                    "capability",
                    "config-error",
                    10.0,
                    Severity::Critical,
                    format!("Capability configuration invalid; denying until fixed: {err}"),
                ));
            }
            return Ok(FilterResult::no_match("capability"));
        }

        match self.grants.get(&ctx.plugin_id) {
            Some(caps) => {
                if caps.contains(required) || caps.contains("*") {
                    Ok(FilterResult::no_match("capability"))
                } else {
                    Ok(FilterResult::matched(
                        "capability",
                        "missing-capability",
                        10.0,
                        Severity::Critical,
                        format!("Plugin '{}' lacks capability '{}'", ctx.plugin_id, required),
                    ))
                }
            }
            None => Ok(FilterResult::matched(
                "capability",
                "unknown-plugin",
                10.0,
                Severity::Critical,
                format!("Plugin '{}' has no capability grants", ctx.plugin_id),
            )),
        }
    }
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
    async fn test_granted_capability_passes() {
        let filter = CapabilityFilter::new(vec![CapabilityGrant {
            plugin: "file-ops".into(),
            capabilities: vec!["fs:read".into(), "fs:write".into()],
        }]);
        let ctx = make_ctx(
            "file-ops",
            ToolCallType::FileRead {
                path: "/tmp/test".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_missing_capability_denies() {
        let filter = CapabilityFilter::new(vec![CapabilityGrant {
            plugin: "file-ops".into(),
            capabilities: vec!["fs:read".into()],
        }]);
        let ctx = make_ctx(
            "file-ops",
            ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec![],
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "missing-capability");
        assert_eq!(result.score, 10.0);
    }

    #[tokio::test]
    async fn test_unknown_plugin_denies() {
        let filter = CapabilityFilter::new(vec![CapabilityGrant {
            plugin: "known-plugin".into(),
            capabilities: vec!["fs:read".into()],
        }]);
        let ctx = make_ctx(
            "rogue-plugin",
            ToolCallType::FileRead {
                path: "/tmp/test".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "unknown-plugin");
        assert_eq!(result.score, 10.0);
    }

    #[tokio::test]
    async fn test_wildcard_grants_all() {
        let filter = CapabilityFilter::new(vec![CapabilityGrant {
            plugin: "superuser".into(),
            capabilities: vec!["*".into()],
        }]);
        let ctx = make_ctx(
            "superuser",
            ToolCallType::ShellExec {
                command: "rm".into(),
                args: vec!["-rf".into(), "/".into()],
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_unconfigured_is_permissive() {
        let filter = CapabilityFilter::new(vec![]);
        let ctx = make_ctx(
            "any-plugin",
            ToolCallType::FileRead {
                path: "/etc/passwd".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_file_write_needs_fs_write() {
        let filter = CapabilityFilter::new(vec![CapabilityGrant {
            plugin: "writer".into(),
            capabilities: vec!["fs:read".into()],
        }]);
        let ctx = make_ctx(
            "writer",
            ToolCallType::FileWrite {
                path: "/tmp/out".into(),
                content_hash: "abc123".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "missing-capability");
    }

    #[tokio::test]
    async fn test_http_needs_net_http() {
        let filter = CapabilityFilter::new(vec![CapabilityGrant {
            plugin: "http-plugin".into(),
            capabilities: vec!["net:http".into()],
        }]);
        let ctx = make_ctx(
            "http-plugin",
            ToolCallType::HttpRequest {
                method: "GET".into(),
                url: "https://api.example.com".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_fail_closed_config_error_denies() {
        let filter = CapabilityFilter::fail_closed("parse error");
        let ctx = make_ctx(
            "any-plugin",
            ToolCallType::FileRead {
                path: "/tmp/test".into(),
            },
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "config-error");
        assert_eq!(result.score, 10.0);
    }
}
