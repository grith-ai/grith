// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Secret scanning filter with 1600+ regex patterns.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};
use regex::{Regex, RegexSet, RegexSetBuilder};
use serde::Deserialize;

/// Configuration for a single secret scanning pattern.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretPattern {
    pub id: String,
    pub regex: String,
    pub score: f64,
    pub severity: String,
    pub message: String,
}

/// Per-pattern metadata stored parallel to compiled matchers.
struct PatternMeta {
    id: String,
    score: f64,
    severity: Severity,
    message: String,
}

/// Fallback matcher used if building the combined `RegexSet` fails.
struct CompiledPattern {
    regex: Regex,
    meta: PatternMeta,
}

enum Matcher {
    Set {
        set: RegexSet,
        metadata: Vec<PatternMeta>,
    },
    Individual(Vec<CompiledPattern>),
}

/// Filter that scans arguments and content for secrets using regex patterns.
///
/// Runs in Phase 2 (Pattern) since regex evaluation is heavier than simple
/// string matching. Scans JSON arguments, shell commands, and URLs for
/// patterns matching known secret formats (API keys, tokens, private keys, etc.).
///
/// Uses `regex::RegexSet` so all patterns are compiled into a single NFA —
/// faster startup than N individual `Regex::new()` calls and O(input) evaluation
/// regardless of pattern count.
pub struct SecretScanFilter {
    matcher: Matcher,
}

impl SecretScanFilter {
    pub fn new(patterns: Vec<SecretPattern>) -> Self {
        let regex_strings: Vec<String> = patterns.iter().map(|p| p.regex.clone()).collect();
        let metadata: Vec<PatternMeta> = patterns
            .iter()
            .map(|p| PatternMeta {
                id: p.id.clone(),
                score: p.score,
                severity: parse_severity(&p.severity),
                message: p.message.clone(),
            })
            .collect();

        let matcher = match RegexSetBuilder::new(&regex_strings)
            .size_limit(64 * (1 << 20))
            .dfa_size_limit(64 * (1 << 20))
            .build()
        {
            Ok(set) => Matcher::Set { set, metadata },
            Err(set_err) => {
                tracing::warn!(
                    error = %set_err,
                    "failed to build combined secret-scan RegexSet; falling back to per-pattern matching"
                );
                Matcher::Individual(compile_individual_patterns(patterns))
            }
        };

        Self { matcher }
    }

    pub fn pattern_count(&self) -> usize {
        match &self.matcher {
            Matcher::Set { set, .. } => set.len(),
            Matcher::Individual(patterns) => patterns.len(),
        }
    }
}

#[async_trait::async_trait]
impl SecurityFilter for SecretScanFilter {
    fn name(&self) -> &str {
        "secret_scan"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Pattern
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let text = extract_scannable_text(ctx);
        if text.is_empty() {
            return Ok(FilterResult::no_match("secret_scan"));
        }

        let best = match &self.matcher {
            Matcher::Set { set, metadata } => {
                let matched_indices = set.matches(&text);
                if !matched_indices.matched_any() {
                    return Ok(FilterResult::no_match("secret_scan"));
                }

                matched_indices.iter().map(|i| &metadata[i]).max_by(|a, b| {
                    a.score
                        .partial_cmp(&b.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
            }
            Matcher::Individual(patterns) => patterns
                .iter()
                .filter(|pattern| pattern.regex.is_match(&text))
                .map(|pattern| &pattern.meta)
                .max_by(|a, b| {
                    a.score
                        .partial_cmp(&b.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }),
        };

        match best {
            Some(m) => Ok(FilterResult::matched(
                "secret_scan",
                &m.id,
                m.score,
                m.severity,
                &m.message,
            )),
            None => Ok(FilterResult::no_match("secret_scan")),
        }
    }
}

fn compile_individual_patterns(patterns: Vec<SecretPattern>) -> Vec<CompiledPattern> {
    patterns
        .into_iter()
        .filter_map(|p| match Regex::new(&p.regex) {
            Ok(regex) => Some(CompiledPattern {
                regex,
                meta: PatternMeta {
                    id: p.id,
                    score: p.score,
                    severity: parse_severity(&p.severity),
                    message: p.message,
                },
            }),
            Err(e) => {
                tracing::warn!(pattern = %p.id, error = %e, "failed to compile secret pattern");
                None
            }
        })
        .collect()
}

/// Extract text content from the context for scanning.
fn extract_scannable_text(ctx: &ToolCallContext) -> String {
    let args_text = ctx.arguments.to_string();

    match &ctx.call_type {
        ToolCallType::ShellExec { command, args }
        | ToolCallType::ProcessSpawn { command, args } => {
            format!("{} {} {}", args_text, command, args.join(" "))
        }
        ToolCallType::HttpRequest { url, .. } => {
            format!("{} {}", args_text, url)
        }
        ToolCallType::NetConnect { address, .. } => {
            format!("{} {}", args_text, address)
        }
        ToolCallType::DnsQuery { domain, .. } => {
            format!("{} {}", args_text, domain)
        }
        _ => args_text,
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        _ => Severity::Notice,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCallType;
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    #[derive(Deserialize)]
    struct SecretPatternsFile {
        patterns: Vec<SecretPattern>,
    }

    fn make_ctx_with_args(call_type: ToolCallType, args: serde_json::Value) -> ToolCallContext {
        let mut ctx = ToolCallContext::new("test", call_type, Uuid::new_v4());
        ctx.arguments = args;
        ctx
    }

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    fn test_patterns() -> Vec<SecretPattern> {
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

    fn load_real_secret_patterns() -> Vec<SecretPattern> {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/filters/secrets.toml");
        let raw = fs::read_to_string(path).expect("read real secret corpus");
        toml::from_str::<SecretPatternsFile>(&raw)
            .expect("parse real secret corpus")
            .patterns
    }

    #[tokio::test]
    async fn test_aws_key_detected() {
        let filter = SecretScanFilter::new(test_patterns());
        let ctx = make_ctx_with_args(
            ToolCallType::FileWrite {
                path: "/tmp/config".into(),
                content_hash: "abc".into(),
            },
            serde_json::json!({
                "content": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
            }),
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "aws-access-key");
        assert_eq!(result.score, 5.0);
    }

    #[tokio::test]
    async fn test_github_token_in_command() {
        let filter = SecretScanFilter::new(test_patterns());
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "curl".into(),
            args: vec![
                "-H".into(),
                "Authorization: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn".into(),
                "https://api.github.com".into(),
            ],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "github-token");
    }

    #[tokio::test]
    async fn test_private_key_detected() {
        let filter = SecretScanFilter::new(test_patterns());
        let ctx = make_ctx_with_args(
            ToolCallType::FileWrite {
                path: "/tmp/key".into(),
                content_hash: "abc".into(),
            },
            serde_json::json!({
                "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
            }),
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "private-key-block");
    }

    #[tokio::test]
    async fn test_generic_api_key_detected() {
        let filter = SecretScanFilter::new(test_patterns());
        let ctx = make_ctx_with_args(
            ToolCallType::FileWrite {
                path: "/tmp/config".into(),
                content_hash: "abc".into(),
            },
            serde_json::json!({
                "content": "api_key = ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            }),
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "generic-api-key");
        assert_eq!(result.score, 3.0);
    }

    #[tokio::test]
    async fn test_clean_content_passes() {
        let filter = SecretScanFilter::new(test_patterns());
        let ctx = make_ctx_with_args(
            ToolCallType::FileWrite {
                path: "/tmp/readme.md".into(),
                content_hash: "abc".into(),
            },
            serde_json::json!({
                "content": "Hello, world! This is a normal file."
            }),
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_invalid_regex_skipped() {
        let patterns = vec![SecretPattern {
            id: "bad-regex".into(),
            regex: "[invalid".into(),
            score: 5.0,
            severity: "critical".into(),
            message: "should not compile".into(),
        }];
        let filter = SecretScanFilter::new(patterns);
        assert_eq!(filter.pattern_count(), 0);
    }

    #[tokio::test]
    async fn test_mixed_valid_and_invalid_patterns_still_detect_valid_secret() {
        let patterns = vec![
            SecretPattern {
                id: "bad-regex".into(),
                regex: "[invalid".into(),
                score: 5.0,
                severity: "critical".into(),
                message: "should not compile".into(),
            },
            SecretPattern {
                id: "github-token".into(),
                regex: "gh[ps]_[A-Za-z0-9_]{36,}".into(),
                score: 5.0,
                severity: "critical".into(),
                message: "GitHub token detected".into(),
            },
        ];
        let filter = SecretScanFilter::new(patterns);
        assert_eq!(filter.pattern_count(), 1);

        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "curl".into(),
            args: vec![
                "-H".into(),
                "Authorization: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn".into(),
            ],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "github-token");
    }

    #[test]
    fn test_real_secret_corpus_builds_regex_set_with_full_count() {
        let patterns = load_real_secret_patterns();
        assert_eq!(patterns.len(), 1620);

        let filter = SecretScanFilter::new(patterns);

        assert!(matches!(filter.matcher, Matcher::Set { .. }));
        assert_eq!(filter.pattern_count(), 1620);
    }

    #[tokio::test]
    async fn test_highest_score_wins() {
        let filter = SecretScanFilter::new(test_patterns());
        // Content has both an AWS key (5.0) and a generic api_key (3.0)
        let ctx = make_ctx_with_args(
            ToolCallType::FileWrite {
                path: "/tmp/config".into(),
                content_hash: "abc".into(),
            },
            serde_json::json!({
                "content": "api_key = AKIAIOSFODNN7EXAMPLE123"
            }),
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        // AWS key pattern (5.0) should win over generic api_key (3.0)
        assert_eq!(result.score, 5.0);
    }
}
