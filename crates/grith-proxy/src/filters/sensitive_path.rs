// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Heuristic path-risk filter for sensitive filesystem locations.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};

/// Heuristic path-risk filter.
///
/// Unlike `path_match` (explicit TOML rules), this filter uses broad built-in
/// heuristics to catch common sensitive targets without requiring an exhaustive
/// list of patterns.
pub struct SensitivePathHeuristicFilter;

impl SensitivePathHeuristicFilter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SensitivePathHeuristicFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct HeuristicHit {
    rule_id: &'static str,
    score: f64,
    severity: Severity,
    message: String,
}

#[async_trait::async_trait]
impl SecurityFilter for SensitivePathHeuristicFilter {
    fn name(&self) -> &str {
        "sensitive_path_heuristic"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Static
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let path = match ctx.path() {
            Some(p) => p,
            None => return Ok(FilterResult::no_match(self.name())),
        };
        let op = match operation_for_call_type(&ctx.call_type) {
            Some(op) => op,
            None => return Ok(FilterResult::no_match(self.name())),
        };

        let path_lc = normalize_path_for_match(path);
        let file_name_lc = normalized_file_name(&path_lc);
        let destructive = matches!(op, "write" | "delete");
        let ssh_metadata_read = op == "read"
            && matches!(
                file_name_lc.as_str(),
                "config" | "known_hosts" | "known_hosts2"
            )
            && path_lc.contains("/.ssh/");

        let mut hits = Vec::new();

        // System configuration and kernel interfaces.
        if path_lc.starts_with("/etc/") {
            hits.push(HeuristicHit {
                rule_id: "system-etc-path",
                score: if destructive { 4.0 } else { 3.0 },
                severity: if destructive {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                message: format!("{op} access to system config path"),
            });
        }

        if path_lc.contains("/windows/system32/config/sam")
            || path_lc.contains("/windows/system32/config/security")
            || path_lc.contains("/windows/system32/config/system")
            || path_lc.contains("/etc/krb5.keytab")
            || path_lc.contains("/var/lib/sss/")
            || path_lc.contains("/library/keychains/")
            || path_lc.contains("/system/library/keychains/")
            || path_lc.contains("/appdata/microsoft/credentials/")
            || path_lc.contains("/appdata/microsoft/crypto/rsa/")
        {
            hits.push(HeuristicHit {
                rule_id: "os-secret-store",
                score: if destructive { 5.0 } else { 4.2 },
                severity: Severity::Critical,
                message: format!("{op} access to OS credential store"),
            });
        }

        if path_lc.starts_with("/proc/") || path_lc.starts_with("/sys/") {
            hits.push(HeuristicHit {
                rule_id: "kernel-interface-path",
                score: if destructive { 4.0 } else { 2.5 },
                severity: Severity::Warning,
                message: format!("{op} access to kernel interface path"),
            });
        }

        // Credential-bearing directories.
        for marker in [
            "/.ssh/",
            "/.gnupg/",
            "/.pki/",
            "/.aws/",
            "/.azure/",
            "/.kube/",
            "/.docker/",
            "/.config/gcloud/",
            "/appdata/gcloud/",
            "/appdata/gnupg/",
            "/appdata/roaming/gnupg/",
        ] {
            if path_lc.contains(marker) {
                if marker == "/.ssh/" && ssh_metadata_read {
                    break;
                }
                hits.push(HeuristicHit {
                    rule_id: "credential-directory",
                    score: if destructive { 4.5 } else { 4.0 },
                    severity: Severity::Error,
                    message: format!("{op} access to credential directory"),
                });
                break;
            }
        }

        if path_lc.contains("/var/run/docker.sock")
            || path_lc.contains("/etc/systemd/")
            || path_lc.starts_with("/boot/")
            || path_lc.starts_with("/usr/bin/")
            || path_lc.starts_with("/system/")
            || path_lc.contains("/library/launchdaemons/")
            || path_lc.contains("/programdata/microsoft/windows/start menu/programs/startup/")
        {
            hits.push(HeuristicHit {
                rule_id: "persistence-or-control-path",
                score: if destructive { 4.0 } else { 3.0 },
                severity: Severity::Warning,
                message: format!("{op} access to persistence/control path"),
            });
        }

        // Browser profile directories — path match covers directory listings and
        // any file within the profile regardless of name.  Filename match below
        // catches the same high-value files even when accessed by absolute path
        // outside the expected directory (e.g., a copy or backup).
        let browser_profile_path = path_lc.contains("/google/chrome/user data/")
            || path_lc.contains("/microsoft/edge/user data/")
            || path_lc.contains("/mozilla/firefox/")
            // Linux Chromium-family browsers
            || path_lc.contains("/.config/chromium/")
            || path_lc.contains("/.config/google-chrome/")
            || path_lc.contains("/.config/microsoft-edge/")
            || path_lc.contains("/.config/brave/")
            || path_lc.contains("/.config/vivaldi/")
            || path_lc.contains("/.config/opera/")
            || path_lc.contains("/snap/chromium/")
            // macOS Chromium-family browsers
            || path_lc.contains("/library/application support/google/chrome/")
            || path_lc.contains("/library/application support/chromium/")
            || path_lc.contains("/library/application support/microsoft edge/")
            || path_lc.contains("/library/application support/brave browser/")
            || path_lc.contains("/library/application support/vivaldi/")
            // Windows Chromium paths (non-UWP)
            || path_lc.contains("/appdata/local/google/chrome/")
            || path_lc.contains("/appdata/local/microsoft/edge/");

        // High-value browser credential and session filenames.  These are
        // meaningful wherever they appear, not just inside a browser profile.
        let browser_credential_file = matches!(
            file_name_lc.as_str(),
            // Chromium session and auth tokens
            "cookies"
            | "login data"
            | "web data"           // autofill + saved payment methods
            | "local state"        // master key used to decrypt saved passwords
            | "secure preferences" // security-sensitive Chrome prefs
            | "network persistent state"
            | "wallet"             // Chrome Web3 wallet
            // Firefox credential stores
            | "key4.db"            // Firefox password manager key
            | "cert9.db"           // Firefox/NSS certificate store (incl. private keys)
            | "cert8.db"           // Older Firefox cert store
            | "logins.json"        // Firefox saved logins
            | "signons.sqlite"     // Very old Firefox passwords
            | "signedinusers.json" // Firefox Accounts session tokens
        );

        if browser_profile_path || browser_credential_file {
            hits.push(HeuristicHit {
                rule_id: "browser-session-data",
                score: if destructive { 4.0 } else { 3.0 },
                severity: Severity::Warning,
                message: format!("{op} access to browser session/credential data"),
            });
        }

        // Key/certificate-like filenames.
        if file_name_lc.ends_with(".pem")
            || file_name_lc.ends_with(".key")
            || file_name_lc.ends_with(".p12")
            || file_name_lc.ends_with(".pfx")
            || matches!(
                file_name_lc.as_str(),
                "id_rsa" | "id_ed25519" | "id_dsa" | "id_ecdsa"
            )
        {
            hits.push(HeuristicHit {
                rule_id: "key-material-file",
                score: if destructive { 5.0 } else { 4.0 },
                severity: Severity::Error,
                message: format!("{op} access to key/certificate file"),
            });
        }

        // Common secret-bearing file names.
        if file_name_lc == ".env" || file_name_lc.starts_with(".env.") {
            hits.push(HeuristicHit {
                rule_id: "env-file-heuristic",
                score: if destructive { 3.5 } else { 3.0 },
                severity: Severity::Warning,
                message: format!("{op} access to environment file"),
            });
        }
        if ["secret", "credential", "token", "passwd", "apikey", "auth"]
            .iter()
            .any(|kw| file_name_lc.contains(kw))
        {
            hits.push(HeuristicHit {
                rule_id: "secretish-filename",
                score: if destructive { 3.5 } else { 2.8 },
                severity: Severity::Warning,
                message: format!("{op} access to sensitive-looking filename"),
            });
        }

        let Some(best) = hits.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            return Ok(FilterResult::no_match(self.name()));
        };

        Ok(FilterResult::matched(
            self.name(),
            best.rule_id,
            best.score,
            best.severity,
            best.message,
        ))
    }
}

fn normalize_path_for_match(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

fn normalized_file_name(path_lc: &str) -> String {
    path_lc
        .split('/')
        .next_back()
        .unwrap_or_default()
        .to_string()
}

fn operation_for_call_type(call_type: &ToolCallType) -> Option<&'static str> {
    match call_type {
        ToolCallType::FileRead { .. } => Some("read"),
        ToolCallType::FileWrite { .. } => Some("write"),
        ToolCallType::FileAppend { .. } => Some("write"),
        ToolCallType::FileDelete { .. } => Some("delete"),
        ToolCallType::DirList { .. } => Some("list"),
        ToolCallType::FileRename { .. } => Some("write"),
        ToolCallType::FileChmod { .. } => Some("write"),
        ToolCallType::DirCreate { .. } => Some("write"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    #[tokio::test]
    async fn test_etc_hosts_read_queues_zone() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/etc/hosts".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "system-etc-path");
        assert!((result.score - 3.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_ssh_key_is_high_risk() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dev/.ssh/id_rsa".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert!(result.score >= 4.0);
    }

    #[tokio::test]
    async fn test_ssh_config_read_is_not_flagged_by_heuristic() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dev/.ssh/config".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_known_hosts_read_is_not_flagged_by_heuristic() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dev/.ssh/known_hosts".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_env_file_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/workspace/app/.env.production".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "env-file-heuristic");
        assert!((result.score - 3.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_non_sensitive_path_no_match() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/workspace/src/main.rs".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_windows_path_normalization_and_ssh_match() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: r"C:\Users\dan\.ssh\id_ed25519".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert!(result.score >= 4.0);
    }

    #[tokio::test]
    async fn test_macos_keychain_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/Users/dan/Library/Keychains/login.keychain-db".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "os-secret-store");
    }

    #[tokio::test]
    async fn test_windows_sam_hive_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: r"C:\Windows\System32\config\SAM".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "os-secret-store");
        assert!(result.score >= 4.0);
    }

    #[tokio::test]
    async fn test_browser_cookie_store_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/.config/google-chrome/Default/Cookies".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    #[tokio::test]
    async fn test_linux_brave_profile_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/.config/brave/Default/Login Data".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    #[tokio::test]
    async fn test_linux_chromium_snap_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/snap/chromium/current/.config/chromium/Default/Cookies".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    #[tokio::test]
    async fn test_macos_chrome_profile_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/Users/dan/Library/Application Support/Google/Chrome/Default/Cookies".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    #[tokio::test]
    async fn test_firefox_logins_json_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/.mozilla/firefox/abc123.default/logins.json".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    #[tokio::test]
    async fn test_firefox_key4_db_detected_by_filename() {
        // key4.db is high-value wherever it appears, not just in profile dirs.
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/backup/key4.db".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    #[tokio::test]
    async fn test_chrome_local_state_detected_by_filename() {
        // "local state" contains the master key for decrypting saved passwords.
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/.config/google-chrome/Local State".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }
}
