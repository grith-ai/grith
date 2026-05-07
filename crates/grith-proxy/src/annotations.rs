// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Exfiltration-related annotations for CLI/log output.
//!
//! Examines proxy filter results and produces human-readable annotation
//! strings for blocked or redacted outbound attempts. These annotations
//! are emitted as structured `tracing` events in the supervisor and daemon
//! loops.

use crate::types::FilterResult;

/// Filter name prefixes that indicate exfiltration-related detections.
const EXFIL_FILTERS: &[&str] = &[
    "egress_policy",
    "dlp_gate",
    "canary",
    "session_containment",
    "egress_rate",
];

/// Examine filter results and return human-readable annotation strings
/// for any exfiltration-related filter hits.
pub fn exfil_annotations(results: &[FilterResult]) -> Vec<String> {
    results
        .iter()
        .filter(|r| r.matched && is_exfil_filter(&r.filter_name))
        .map(|r| {
            format!(
                "[EXFIL] {}: {} (rule: {}, score: {:.1})",
                r.filter_name, r.message, r.rule_id, r.score
            )
        })
        .collect()
}

/// Check if a filter result has exfil-related annotations.
pub fn has_exfil_detections(results: &[FilterResult]) -> bool {
    results
        .iter()
        .any(|r| r.matched && is_exfil_filter(&r.filter_name))
}

fn is_exfil_filter(name: &str) -> bool {
    EXFIL_FILTERS.iter().any(|prefix| name.contains(prefix))
}

/// Classify the protocol of an exfil attempt from filter results.
/// Returns a protocol label suitable for aggregation.
pub fn classify_protocol(filter_results: &[FilterResult]) -> Option<&'static str> {
    for r in filter_results.iter().filter(|r| r.matched) {
        let rule_lower = r.rule_id.to_lowercase();
        let msg_lower = r.message.to_lowercase();
        if rule_lower.contains("http") || msg_lower.contains("http") {
            return Some("http");
        }
        if rule_lower.contains("dns") || msg_lower.contains("dns") {
            return Some("dns");
        }
        if rule_lower.contains("ftp") || rule_lower.contains("sftp") || msg_lower.contains("ftp") {
            return Some("ftp");
        }
        if rule_lower.contains("smtp") || msg_lower.contains("smtp") {
            return Some("smtp");
        }
        if rule_lower.contains("websocket") || rule_lower.contains("ws://") {
            return Some("websocket");
        }
        if rule_lower.contains("ssh") || rule_lower.contains("scp") {
            return Some("ssh");
        }
        if rule_lower.contains("curl")
            || rule_lower.contains("wget")
            || rule_lower.contains("nc")
            || rule_lower.contains("netcat")
        {
            return Some("shell-transport");
        }
    }
    None
}

/// Extract destination information from filter results, if available.
pub fn extract_destination(filter_results: &[FilterResult]) -> Option<String> {
    for r in filter_results.iter().filter(|r| r.matched) {
        // Look for domain/URL info in the message
        if r.message.contains("://") {
            // Try to extract a domain from a URL mention
            if let Some(start) = r.message.find("://") {
                let after = &r.message[start + 3..];
                let end = after.find(['/', ':', ' ', ')']).unwrap_or(after.len());
                let domain = &after[..end];
                if !domain.is_empty() {
                    return Some(domain.to_string());
                }
            }
        }
        // Check rule_id for destination info
        if (r.rule_id.contains("destination") || r.rule_id.contains("domain"))
            && !r.message.is_empty()
        {
            return Some(r.message.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FilterResult, Severity};

    #[test]
    fn test_exfil_annotations_empty() {
        let results: Vec<FilterResult> = vec![];
        assert!(exfil_annotations(&results).is_empty());
    }

    #[test]
    fn test_exfil_annotations_non_exfil_filter() {
        let results = vec![FilterResult::matched(
            "path_match",
            "ssh-key",
            5.0,
            Severity::Critical,
            "SSH key access",
        )];
        assert!(exfil_annotations(&results).is_empty());
    }

    #[test]
    fn test_exfil_annotations_egress_policy() {
        let results = vec![FilterResult::matched(
            "egress_policy",
            "untrusted-destination",
            4.0,
            Severity::Warning,
            "Outbound to untrusted destination",
        )];
        let annotations = exfil_annotations(&results);
        assert_eq!(annotations.len(), 1);
        assert!(annotations[0].contains("[EXFIL]"));
        assert!(annotations[0].contains("egress_policy"));
        assert!(annotations[0].contains("untrusted-destination"));
    }

    #[test]
    fn test_exfil_annotations_dlp_gate() {
        let results = vec![FilterResult::matched(
            "dlp_gate",
            "api-key-detected",
            6.0,
            Severity::Error,
            "API key detected in outbound arguments",
        )];
        let annotations = exfil_annotations(&results);
        assert_eq!(annotations.len(), 1);
        assert!(annotations[0].contains("dlp_gate"));
    }

    #[test]
    fn test_exfil_annotations_canary() {
        let results = vec![FilterResult::matched(
            "canary",
            "canary-secret-detected",
            9.5,
            Severity::Critical,
            "Canary token detected in arguments",
        )];
        let annotations = exfil_annotations(&results);
        assert_eq!(annotations.len(), 1);
        assert!(annotations[0].contains("canary"));
    }

    #[test]
    fn test_exfil_annotations_multiple() {
        let results = vec![
            FilterResult::matched(
                "egress_policy",
                "untrusted-dest",
                3.0,
                Severity::Warning,
                "untrusted",
            ),
            FilterResult::no_match("path_match"),
            FilterResult::matched(
                "dlp_gate",
                "token-found",
                5.0,
                Severity::Error,
                "token in args",
            ),
            FilterResult::matched(
                "command",
                "curl",
                1.0,
                Severity::Notice,
                "HTTP data transfer (curl)",
            ),
        ];
        let annotations = exfil_annotations(&results);
        assert_eq!(annotations.len(), 2);
    }

    #[test]
    fn test_has_exfil_detections() {
        let no_exfil = vec![FilterResult::matched(
            "path_match",
            "test",
            1.0,
            Severity::Notice,
            "test",
        )];
        assert!(!has_exfil_detections(&no_exfil));

        let with_exfil = vec![FilterResult::matched(
            "egress_rate",
            "burst",
            4.0,
            Severity::Warning,
            "egress burst",
        )];
        assert!(has_exfil_detections(&with_exfil));
    }

    #[test]
    fn test_classify_protocol_http() {
        let results = vec![FilterResult::matched(
            "egress_policy",
            "http-outbound",
            3.0,
            Severity::Warning,
            "HTTP outbound detected",
        )];
        assert_eq!(classify_protocol(&results), Some("http"));
    }

    #[test]
    fn test_classify_protocol_ssh() {
        let results = vec![FilterResult::matched(
            "command",
            "ssh-command",
            2.0,
            Severity::Warning,
            "SSH connection",
        )];
        assert_eq!(classify_protocol(&results), Some("ssh"));
    }

    #[test]
    fn test_classify_protocol_shell_transport() {
        let results = vec![FilterResult::matched(
            "command",
            "curl-exfil",
            4.0,
            Severity::Warning,
            "curl data transfer",
        )];
        assert_eq!(classify_protocol(&results), Some("shell-transport"));
    }

    #[test]
    fn test_classify_protocol_none() {
        let results = vec![FilterResult::matched(
            "path_match",
            "generic",
            1.0,
            Severity::Notice,
            "generic file access",
        )];
        assert_eq!(classify_protocol(&results), None);
    }

    #[test]
    fn test_extract_destination_from_url() {
        let results = vec![FilterResult::matched(
            "egress_policy",
            "untrusted",
            3.0,
            Severity::Warning,
            "Outbound to https://evil.example.com/data",
        )];
        let dest = extract_destination(&results);
        assert_eq!(dest.as_deref(), Some("evil.example.com"));
    }

    #[test]
    fn test_extract_destination_none() {
        let results = vec![FilterResult::matched(
            "egress_rate",
            "burst",
            4.0,
            Severity::Warning,
            "egress burst detected",
        )];
        assert!(extract_destination(&results).is_none());
    }

    #[test]
    fn test_unmatched_exfil_filter_not_annotated() {
        let results = vec![FilterResult::no_match("egress_policy")];
        assert!(exfil_annotations(&results).is_empty());
        assert!(!has_exfil_detections(&results));
    }
}
