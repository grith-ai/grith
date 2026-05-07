// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Argument structure analysis and injection detection filter.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};

/// Filter that checks argument structure and detects potential injection attacks.
///
/// Validates argument lengths against configurable maximums and inspects file
/// paths for shell metacharacters and deep traversal patterns that may indicate
/// injection attempts.
pub struct ArgumentFilter {
    max_path_length: usize,
    max_command_length: usize,
    max_url_length: usize,
}

impl ArgumentFilter {
    pub fn new() -> Self {
        Self {
            max_path_length: 4096,
            max_command_length: 8192,
            max_url_length: 2048,
        }
    }
}

impl Default for ArgumentFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Shell metacharacters that suggest injection when found in file paths.
const PATH_INJECTION_CHARS: &[char] = &['|', '`', '$', ';', '&', '>', '<'];

/// Patterns that suggest path traversal attacks.
const TRAVERSAL_PATTERNS: &[&str] = &["../../../", "..\\..\\..\\"];

#[async_trait::async_trait]
impl SecurityFilter for ArgumentFilter {
    fn name(&self) -> &str {
        "argument"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Static
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        match &ctx.call_type {
            ToolCallType::FileRead { path }
            | ToolCallType::FileWrite { path, .. }
            | ToolCallType::FileAppend { path }
            | ToolCallType::FileDelete { path }
            | ToolCallType::DirList { path }
            | ToolCallType::FileChmod { path, .. }
            | ToolCallType::DirCreate { path } => self.check_path(path),
            ToolCallType::FileRename { old_path, new_path } => {
                let result = self.check_path(old_path)?;
                if result.matched {
                    return Ok(result);
                }
                self.check_path(new_path)
            }
            ToolCallType::ShellExec { .. } | ToolCallType::ProcessSpawn { .. } => {
                match ctx.full_command() {
                    Some(full) => self.check_command(&full),
                    None => Ok(FilterResult::no_match("argument")),
                }
            }
            ToolCallType::HttpRequest { url, .. } => self.check_url(url),
            ToolCallType::NetConnect { .. }
            | ToolCallType::NetListen { .. }
            | ToolCallType::DnsQuery { .. } => Ok(FilterResult::no_match("argument")),
        }
    }
}

impl ArgumentFilter {
    fn check_path(&self, path: &str) -> crate::error::Result<FilterResult> {
        if path.len() > self.max_path_length {
            return Ok(FilterResult::matched(
                "argument",
                "path-too-long",
                2.0,
                Severity::Warning,
                format!(
                    "Path length {} exceeds maximum {}",
                    path.len(),
                    self.max_path_length
                ),
            ));
        }

        // Check for injection characters in paths
        if path.chars().any(|c| PATH_INJECTION_CHARS.contains(&c)) {
            return Ok(FilterResult::matched(
                "argument",
                "path-injection",
                2.0,
                Severity::Warning,
                "Path contains shell metacharacters",
            ));
        }

        // Check for deep traversal
        for pattern in TRAVERSAL_PATTERNS {
            if path.contains(pattern) {
                return Ok(FilterResult::matched(
                    "argument",
                    "path-traversal",
                    2.0,
                    Severity::Warning,
                    "Path contains deep traversal pattern",
                ));
            }
        }

        Ok(FilterResult::no_match("argument"))
    }

    fn check_command(&self, command: &str) -> crate::error::Result<FilterResult> {
        if command.len() > self.max_command_length {
            return Ok(FilterResult::matched(
                "argument",
                "command-too-long",
                2.0,
                Severity::Warning,
                format!(
                    "Command length {} exceeds maximum {}",
                    command.len(),
                    self.max_command_length
                ),
            ));
        }

        Ok(FilterResult::no_match("argument"))
    }

    fn check_url(&self, url: &str) -> crate::error::Result<FilterResult> {
        if url.len() > self.max_url_length {
            return Ok(FilterResult::matched(
                "argument",
                "url-too-long",
                1.0,
                Severity::Notice,
                format!(
                    "URL length {} exceeds maximum {}",
                    url.len(),
                    self.max_url_length
                ),
            ));
        }

        Ok(FilterResult::no_match("argument"))
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
    async fn test_safe_path_passes() {
        let filter = ArgumentFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/project/src/main.rs".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_path_injection_detected() {
        let filter = ArgumentFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/file; rm -rf /".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "path-injection");
    }

    #[tokio::test]
    async fn test_pipe_in_path_detected() {
        let filter = ArgumentFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/file | cat /etc/passwd".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "path-injection");
    }

    #[tokio::test]
    async fn test_backtick_in_path_detected() {
        let filter = ArgumentFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/`whoami`".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "path-injection");
    }

    #[tokio::test]
    async fn test_deep_traversal_detected() {
        let filter = ArgumentFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/project/../../../../etc/passwd".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "path-traversal");
    }

    #[tokio::test]
    async fn test_path_too_long() {
        let filter = ArgumentFilter::new();
        let long_path = "/tmp/".to_string() + &"a".repeat(5000);
        let ctx = make_ctx(ToolCallType::FileRead { path: long_path });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "path-too-long");
    }

    #[tokio::test]
    async fn test_command_too_long() {
        let filter = ArgumentFilter::new();
        let long_cmd = "echo ".to_string() + &"x".repeat(9000);
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: long_cmd,
            args: vec![],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "command-too-long");
    }

    #[tokio::test]
    async fn test_url_too_long() {
        let filter = ArgumentFilter::new();
        let long_url = "https://example.com/".to_string() + &"a".repeat(3000);
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: long_url,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "url-too-long");
    }

    #[tokio::test]
    async fn test_normal_command_passes() {
        let filter = ArgumentFilter::new();
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec!["-la".into(), "/tmp".into()],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_normal_url_passes() {
        let filter = ArgumentFilter::new();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://api.example.com/v1/data".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }
}
