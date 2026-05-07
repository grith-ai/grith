// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Baseline operation risk scoring filter.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};
use std::net::IpAddr;

/// Filter that assigns baseline risk scores based on the inherent
/// riskiness of the operation type.
///
/// Runs in Phase 1 (Static) because it is a pure function of the
/// `ToolCallType` variant with no external dependencies.
///
/// This filter ensures that every non-trivial operation gets a small
/// but non-zero score reflecting its inherent risk level. Without this
/// filter, most normal operations (reading project files, listing
/// directories, running safe commands) would score 0.0 because none
/// of the pattern-specific filters match.
///
/// Scoring (baseline, additive with other filters):
/// - `0.0` for safe reads: `FileRead`, `DirList`
/// - `0.2` for mild mutations: `DirCreate`
/// - `0.3` for renames/appends: `FileRename`, `FileAppend`
/// - `0.5` for writes and HTTP: `FileWrite`, `HttpRequest`, `NetConnect`
/// - `1.0` for risky ops: `ShellExec`, `ProcessSpawn`, `FileDelete`, `FileChmod`
/// - `4.0` for non-loopback listeners that expose services beyond the local machine
pub struct OperationRiskFilter;

impl OperationRiskFilter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OperationRiskFilter {
    fn default() -> Self {
        Self::new()
    }
}

fn is_loopback_listen_target(address: &str) -> bool {
    if address.eq_ignore_ascii_case("localhost") {
        return true;
    }

    match address.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

#[async_trait::async_trait]
impl SecurityFilter for OperationRiskFilter {
    fn name(&self) -> &str {
        "operation_risk"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Static
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let (score, rule_id, severity, message) = match &ctx.call_type {
            // Safe read-only operations: no baseline risk.
            ToolCallType::FileRead { .. } | ToolCallType::DirList { .. } => {
                return Ok(FilterResult::no_match("operation_risk"));
            }

            // Mild mutations.
            ToolCallType::DirCreate { path } => (
                0.2,
                "dir-create-baseline",
                Severity::Notice,
                format!("Directory creation: {path}"),
            ),

            // Moderate mutations.
            ToolCallType::FileAppend { path } => (
                0.3,
                "file-append-baseline",
                Severity::Notice,
                format!("File append: {path}"),
            ),
            ToolCallType::FileRename {
                old_path, new_path, ..
            } => (
                0.3,
                "file-rename-baseline",
                Severity::Notice,
                format!("File rename: {old_path} -> {new_path}"),
            ),

            // Writes and network access.
            ToolCallType::FileWrite { path, .. } => (
                0.5,
                "file-write-baseline",
                Severity::Notice,
                format!("File write: {path}"),
            ),
            ToolCallType::HttpRequest { method, url } => (
                0.5,
                "http-request-baseline",
                Severity::Notice,
                format!("HTTP request: {method} {url}"),
            ),
            ToolCallType::NetConnect { address, port } => (
                0.5,
                "net-connect-baseline",
                Severity::Notice,
                format!("Network connection: {address}:{port}"),
            ),

            // Risky operations: shell execution, deletion, permission changes.
            ToolCallType::ShellExec { command, args } => {
                let msg = if args.is_empty() {
                    format!("Shell execution: {command}")
                } else {
                    format!("Shell execution: {} {}", command, args.join(" "))
                };
                (1.0, "shell-exec-baseline", Severity::Notice, msg)
            }
            ToolCallType::ProcessSpawn { command, args } => {
                let msg = if args.is_empty() {
                    format!("Process spawn: {command}")
                } else {
                    format!("Process spawn: {} {}", command, args.join(" "))
                };
                (1.0, "process-spawn-baseline", Severity::Notice, msg)
            }
            ToolCallType::FileDelete { path } => (
                1.0,
                "file-delete-baseline",
                Severity::Warning,
                format!("File deletion: {path}"),
            ),
            ToolCallType::FileChmod { path, mode } => (
                1.0,
                "file-chmod-baseline",
                Severity::Warning,
                format!("Permission change: {path} (mode {mode:o})"),
            ),
            ToolCallType::NetListen { address, port } => {
                if is_loopback_listen_target(address) {
                    (
                        0.5,
                        "loopback-net-listen",
                        Severity::Notice,
                        format!("Loopback-only network listen: {address}:{port}"),
                    )
                } else {
                    (
                        4.0,
                        "remote-net-listen",
                        Severity::Warning,
                        format!("Non-loopback network listen requires review: {address}:{port}"),
                    )
                }
            }
            ToolCallType::DnsQuery { domain, query_type } => (
                0.5,
                "dns-query-baseline",
                Severity::Notice,
                format!("DNS query: {domain} ({query_type})"),
            ),
        };

        Ok(FilterResult::matched(
            "operation_risk",
            rule_id,
            score,
            severity,
            message,
        ))
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

    #[tokio::test]
    async fn test_file_read_zero_score() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/test.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
        assert_eq!(result.score, 0.0);
    }

    #[tokio::test]
    async fn test_dir_list_zero_score() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::DirList {
            path: "/tmp".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
        assert_eq!(result.score, 0.0);
    }

    #[tokio::test]
    async fn test_file_write_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::FileWrite {
            path: "/tmp/out.txt".into(),
            content_hash: "abc".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.5);
        assert_eq!(result.rule_id, "file-write-baseline");
    }

    #[tokio::test]
    async fn test_shell_exec_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "grep".into(),
            args: vec!["foo".into(), "bar.txt".into()],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 1.0);
        assert_eq!(result.rule_id, "shell-exec-baseline");
    }

    #[tokio::test]
    async fn test_file_delete_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::FileDelete {
            path: "/tmp/trash.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 1.0);
        assert_eq!(result.rule_id, "file-delete-baseline");
    }

    #[tokio::test]
    async fn test_http_request_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://example.com".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.5);
    }

    #[tokio::test]
    async fn test_net_listen_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::NetListen {
            address: "0.0.0.0".into(),
            port: 8080,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 4.0);
        assert_eq!(result.rule_id, "remote-net-listen");
    }

    #[tokio::test]
    async fn test_loopback_net_listen_is_low_risk() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::NetListen {
            address: "127.0.0.1".into(),
            port: 8080,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.5);
        assert_eq!(result.rule_id, "loopback-net-listen");
    }

    #[tokio::test]
    async fn test_file_chmod_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::FileChmod {
            path: "/tmp/script.sh".into(),
            mode: 0o755,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 1.0);
    }

    #[tokio::test]
    async fn test_dir_create_baseline() {
        let filter = OperationRiskFilter::new();
        let ctx = make_ctx(ToolCallType::DirCreate {
            path: "/tmp/newdir".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 0.2);
    }
}
