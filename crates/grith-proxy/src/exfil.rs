// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Shared exfiltration-related helper logic used by multiple runtimes.
//!
//! This module exists to avoid drift between the built-in agent loop (core)
//! and the syscall supervisor execution path. Keep functions small and pure.

use crate::types::ToolCallType;

/// Return `true` if the path looks like a sensitive source read.
///
/// Note: this is a conservative heuristic intended for containment/correlation
/// triggers, not a complete secret detector.
pub fn is_sensitive_source_path(path: &str) -> bool {
    // Keep the list stable across runtimes.
    const NEEDLES: &[&str] = &[
        ".env",
        ".ssh",
        ".aws",
        ".gnupg",
        ".kube/config",
        "id_rsa",
        "id_ed25519",
        "credentials",
        "secrets",
        "passwd",
        "shadow",
        "keychain",
        "/windows/system32/config/sam",
    ];

    let lowered = path.to_lowercase();
    NEEDLES.iter().any(|needle| lowered.contains(needle))
}

/// If the tool call is a sensitive "source" event, return a human-readable tag
/// for correlation logs/audit.
pub fn correlation_source_event(call_type: &ToolCallType) -> Option<String> {
    match call_type {
        ToolCallType::FileRead { path } if is_sensitive_source_path(path) => {
            Some(format!("FileRead({path})"))
        }
        _ => None,
    }
}

fn is_ident_byte(b: u8) -> bool {
    // ASCII-only; all tokens we care about are ASCII.
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn contains_keyword(full: &str, keyword: &str) -> bool {
    let kw = keyword.as_bytes();
    let bytes = full.as_bytes();
    if kw.is_empty() || kw.len() > bytes.len() {
        return false;
    }

    // Naive scan with boundary checks, avoids regex overhead.
    let mut i = 0usize;
    while i + kw.len() <= bytes.len() {
        if &bytes[i..i + kw.len()] == kw {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after_idx = i + kw.len();
            let after_ok = after_idx == bytes.len() || !is_ident_byte(bytes[after_idx]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Return `true` if the call type is an outbound sink that should link to an
/// existing source correlation chain.
pub fn is_outbound_sink(call_type: &ToolCallType) -> bool {
    match call_type {
        ToolCallType::HttpRequest { .. } | ToolCallType::NetConnect { .. } => true,
        ToolCallType::ShellExec { command, args }
        | ToolCallType::ProcessSpawn { command, args } => {
            let full = if args.is_empty() {
                command.to_lowercase()
            } else {
                format!("{command} {}", args.join(" ")).to_lowercase()
            };

            // Keywords representing common egress/exfil tools or transports.
            // Include DNS tooling explicitly (`dig`, `nslookup`) since it is
            // frequently used for covert channels.
            const KEYWORDS: &[&str] = &[
                "curl", "wget", "nc", "netcat", "scp", "sftp", "ftp", "ssh", "nslookup", "dig",
            ];
            KEYWORDS.iter().any(|kw| contains_keyword(&full, kw))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_source_detects_env_and_ssh() {
        assert!(is_sensitive_source_path(".env"));
        assert!(is_sensitive_source_path("/home/me/.ssh/id_ed25519"));
        assert!(!is_sensitive_source_path("src/main.rs"));
    }

    #[test]
    fn outbound_sink_detects_dig_at_start() {
        let call = ToolCallType::ShellExec {
            command: "dig".into(),
            args: vec!["example.com".into()],
        };
        assert!(is_outbound_sink(&call));
    }

    #[test]
    fn outbound_sink_detects_dig_inside_shell_wrapper() {
        let call = ToolCallType::ShellExec {
            command: "bash".into(),
            args: vec!["-lc".into(), "dig example.com +short".into()],
        };
        assert!(is_outbound_sink(&call));
    }

    #[test]
    fn outbound_sink_does_not_false_match_substrings() {
        let call = ToolCallType::ShellExec {
            command: "sync".into(),
            args: vec![],
        };
        assert!(!is_outbound_sink(&call));
    }
}
