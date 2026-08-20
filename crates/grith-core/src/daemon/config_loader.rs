// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Configuration loading and path expansion helpers.
//!
//! This module handles TOML configuration file loading from multiple candidate
//! paths, tilde expansion in path strings, and conversion between the core
//! config types and the supervisor crate's config types.

use grith_proxy::filters::allowlist::{AllowlistConfig, ListEntry};
use grith_proxy::filters::canary::CanaryConfig;
use grith_proxy::filters::capability::CapabilityGrant;
use grith_proxy::filters::command::CommandRule;
use grith_proxy::filters::dlp_gate::DlpGateConfig;
use grith_proxy::filters::egress_policy::EgressPolicyConfig;
use grith_proxy::filters::path_match::PathRule;
use grith_proxy::filters::secret_scan::SecretPattern;
use grith_proxy::filters::session_containment::SessionContainmentConfig;
use grith_proxy::meta_rules::MetaRule;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::Error;

// ---------------------------------------------------------------------------
// TOML file wrapper types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct PathRulesFile {
    pub rules: Vec<PathRule>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SecretPatternsFile {
    pub patterns: Vec<SecretPattern>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CommandRulesFile {
    pub rules: Vec<CommandRule>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MetaRulesFile {
    pub meta_rules: Vec<MetaRule>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct DomainSection {
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct DomainsFile {
    #[serde(default)]
    pub known_safe: DomainSection,
    #[serde(default)]
    pub known_malicious: DomainSection,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EgressPolicyFile {
    pub egress: EgressPolicyConfig,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DlpGateFile {
    pub dlp: DlpGateConfig,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SessionContainmentFile {
    pub containment: SessionContainmentConfig,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CanaryFile {
    pub canary: CanaryConfig,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AllowlistFile {
    #[serde(default)]
    pub allow: Vec<ListEntry>,
    #[serde(default)]
    pub deny: Vec<ListEntry>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct CapabilityGrantsFile {
    #[serde(default)]
    pub grants: Vec<CapabilityGrant>,
}

pub(crate) enum CapabilityGrantsLoad {
    Grants(Vec<CapabilityGrant>),
    ConfigError(String),
}

// ---------------------------------------------------------------------------
// TOML file loading from candidate paths
// ---------------------------------------------------------------------------

/// Entire `config/` tree, baked into the binary at build time. Used as
/// the final fallback when neither the cwd-relative nor repo-relative
/// disk path exists — which is the normal case for users who install
/// via `curl https://grith.ai/install | sh` and don't have a source
/// checkout. The path passed to `include_dir!` MUST be a build-time
/// directory; the contents are captured then.
static EMBEDDED_CONFIG: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/../../config");

fn embedded_config_contents(repo_relative: &str) -> Option<&'static str> {
    // Strip the `config/` prefix because EMBEDDED_CONFIG is rooted at
    // the config dir itself, but call sites pass repo-relative paths
    // like "config/filters/paths.toml".
    let inside_config = repo_relative.strip_prefix("config/")?;
    EMBEDDED_CONFIG
        .get_file(inside_config)
        .and_then(|f| f.contents_utf8())
}

pub(crate) fn load_toml_from_candidates<T>(relative_path: &str) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let candidates = config_path_candidates(relative_path);
    let mut last_error = String::new();

    for path in candidates {
        if !path.exists() {
            last_error = format!("{} does not exist", path.display());
            continue;
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => match toml::from_str::<T>(&content) {
                Ok(parsed) => return Ok(parsed),
                Err(e) => {
                    last_error = format!("failed to parse {}: {e}", path.display());
                }
            },
            Err(e) => {
                last_error = format!("failed to read {}: {e}", path.display());
            }
        }
    }

    // Final fallback: load from the embedded config bundle.
    if let Some(content) = embedded_config_contents(relative_path) {
        return toml::from_str::<T>(content)
            .map_err(|e| format!("failed to parse embedded {relative_path}: {e}"));
    }

    Err(last_error)
}

fn config_path_candidates(relative_path: &str) -> [PathBuf; 2] {
    let cwd_relative = PathBuf::from(relative_path);
    let repo_relative = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(relative_path);
    [cwd_relative, repo_relative]
}

// ---------------------------------------------------------------------------
// Config-specific loaders
// ---------------------------------------------------------------------------

pub(crate) fn load_path_rules() -> Result<Vec<PathRule>, Error> {
    load_toml_from_candidates::<PathRulesFile>("config/filters/paths.toml")
        .map(|file| file.rules)
        .map_err(|e| {
            Error::Config(format!(
                "required config/filters/paths.toml unavailable: {e}"
            ))
        })
}

pub(crate) fn load_secret_patterns() -> Result<Vec<SecretPattern>, Error> {
    load_toml_from_candidates::<SecretPatternsFile>("config/filters/secrets.toml")
        .map(|file| file.patterns)
        .map_err(|e| {
            Error::Config(format!(
                "required config/filters/secrets.toml unavailable: {e}"
            ))
        })
}

pub(crate) fn load_command_rules() -> Result<Vec<CommandRule>, Error> {
    load_toml_from_candidates::<CommandRulesFile>("config/filters/commands.toml")
        .map(|file| file.rules)
        .map_err(|e| {
            Error::Config(format!(
                "required config/filters/commands.toml unavailable: {e}"
            ))
        })
}

pub(crate) fn load_meta_rules() -> Result<Vec<MetaRule>, Error> {
    load_toml_from_candidates::<MetaRulesFile>("config/filters/meta_rules.toml")
        .map(|file| file.meta_rules)
        .map_err(|e| {
            Error::Config(format!(
                "required config/filters/meta_rules.toml unavailable: {e}"
            ))
        })
}

pub(crate) fn load_reputation_domains() -> Result<(HashSet<String>, HashSet<String>), Error> {
    let file =
        load_toml_from_candidates::<DomainsFile>("config/filters/domains.toml").map_err(|e| {
            Error::Config(format!(
                "required config/filters/domains.toml unavailable: {e}"
            ))
        })?;

    let malicious = file
        .known_malicious
        .domains
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect::<HashSet<_>>();
    let safe = file
        .known_safe
        .domains
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect::<HashSet<_>>();
    Ok((malicious, safe))
}

/// Build a map of profile name -> trusted destination domains by loading
/// supervisor profiles from the effective bundled configuration source.
pub(crate) fn build_profile_trusted_domains(
) -> Result<std::collections::HashMap<String, Vec<String>>, Error> {
    Ok(load_supervisor_profiles()?
        .into_iter()
        .filter(|p| !p.routine_destinations.is_empty())
        .map(|p| (p.name, p.routine_destinations))
        .collect())
}

/// Load supervisor profiles from the bundled configuration source.
///
/// A repo-local filesystem override is only consulted when
/// `GRITH_DEV_PROFILE_OVERRIDE` is explicitly enabled.
pub(crate) fn load_supervisor_profiles(
) -> Result<Vec<grith_supervisor::profiles::SupervisorProfile>, Error> {
    grith_supervisor::profiles::SupervisorProfile::load_from_config()
        .map_err(|e| Error::Config(format!("supervisor profiles unavailable: {e}")))
}

pub(crate) fn load_egress_policy_config() -> Result<EgressPolicyConfig, Error> {
    load_toml_from_candidates::<EgressPolicyFile>("config/filters/egress.toml")
        .map(|file| file.egress)
        .map_err(|e| {
            Error::Config(format!(
                "required config/filters/egress.toml unavailable: {e}"
            ))
        })
}

pub(crate) fn load_dlp_gate_config() -> Result<DlpGateConfig, Error> {
    load_toml_from_candidates::<DlpGateFile>("config/filters/dlp.toml")
        .map(|file| file.dlp)
        .map_err(|e| Error::Config(format!("required config/filters/dlp.toml unavailable: {e}")))
}

pub(crate) fn load_canary_config() -> Result<CanaryConfig, Error> {
    load_toml_from_candidates::<CanaryFile>("config/filters/canary.toml")
        .map(|file| file.canary)
        .map_err(|e| {
            Error::Config(format!(
                "required config/filters/canary.toml unavailable: {e}"
            ))
        })
}

pub(crate) fn load_session_containment_config() -> Result<SessionContainmentConfig, Error> {
    load_toml_from_candidates::<SessionContainmentFile>("config/filters/containment.toml")
        .map(|file| file.containment)
        .map_err(|e| {
            Error::Config(format!(
                "required config/filters/containment.toml unavailable: {e}"
            ))
        })
}

pub(crate) fn load_allowlist_config() -> AllowlistConfig {
    let mut merged = AllowlistConfig::default();

    if let Ok(file) = load_toml_from_candidates::<AllowlistFile>("config/filters/allowlist.toml") {
        merged.allow.extend(file.allow);
        merged.deny.extend(file.deny);
    }

    match grith_proxy::allowlist_persistence::load_user_allowlist() {
        Ok(user_cfg) => {
            merged.allow.extend(user_cfg.allow);
            merged.deny.extend(user_cfg.deny);
        }
        Err(e) => match e {
            grith_proxy::allowlist_persistence::AllowlistPersistenceError::ConfigDirUnavailable => {
                tracing::debug!("user config dir unavailable; skipping persistent allowlist");
            }
            _ => tracing::warn!(error = %e, "failed to load user allowlist file"),
        },
    }

    merged
}

pub(crate) fn load_capability_grants() -> CapabilityGrantsLoad {
    let path = "config/filters/capabilities.toml";
    match load_toml_from_candidates::<CapabilityGrantsFile>(path) {
        Ok(file) => CapabilityGrantsLoad::Grants(file.grants),
        Err(e) => CapabilityGrantsLoad::ConfigError(e),
    }
}

// ---------------------------------------------------------------------------
// Path expansion
// ---------------------------------------------------------------------------

/// Expand ~ to home directory in a path string.
pub(crate) fn expand_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

// ---------------------------------------------------------------------------
// Supervisor config conversion
// ---------------------------------------------------------------------------

/// Convert the core config's supervisor section into the supervisor crate's config type.
pub(crate) fn to_supervisor_config(
    core: &crate::config::SupervisorCoreConfig,
) -> grith_supervisor::config::SupervisorConfig {
    grith_supervisor::config::SupervisorConfig {
        enabled: core.enabled,
        default_profile: core.default_profile.clone(),
        freeze_timeout_seconds: core.freeze_timeout_seconds,
        deny_replay_seconds: core.deny_replay_seconds,
        approve_replay_seconds: core.approve_replay_seconds,
        max_concurrent_sessions: core.max_concurrent_sessions,
        pty_forwarding: core.pty_forwarding,
        require_sandbox: core.require_sandbox,
        attach_mode: match core.attach_mode {
            crate::config::AttachMode::Traceme => grith_supervisor::config::AttachMode::Traceme,
            crate::config::AttachMode::Seize => grith_supervisor::config::AttachMode::Seize,
        },
        platform: grith_supervisor::config::PlatformConfig {
            linux_mechanism: core.platform.linux_mechanism.clone(),
            macos_mechanism: core.platform.macos_mechanism.clone(),
            seccomp_pre_filter: core.platform.seccomp_pre_filter,
        },
        noise_reduction: grith_supervisor::config::NoiseConfig {
            ignore_read_only: core.noise_reduction.ignore_read_only,
            batch_rapid_reads: core.noise_reduction.batch_rapid_reads,
            batch_window_ms: core.noise_reduction.batch_window_ms,
        },
        dns_inspection: grith_supervisor::config::DnsInspectionConfig {
            enabled: core.dns_inspection.enabled,
            upstream_resolver: core.dns_inspection.upstream_resolver.clone(),
            observe_responses: core.dns_inspection.observe_responses,
            block_tcp_dns: core.dns_inspection.block_tcp_dns,
            connected_udp_proxy: core.dns_inspection.connected_udp_proxy,
            accept_proxy_network_authority: core.dns_inspection.accept_proxy_network_authority,
            proxy_queue_action: match core.dns_inspection.proxy_queue_action {
                crate::config::SupervisorDnsProxyQueueAction::Refuse => {
                    grith_supervisor::config::DnsProxyQueueAction::Refuse
                }
                crate::config::SupervisorDnsProxyQueueAction::Forward => {
                    grith_supervisor::config::DnsProxyQueueAction::Forward
                }
            },
            proxy_max_response_bytes: core.dns_inspection.proxy_max_response_bytes,
            proxy_policy_timeout_ms: core.dns_inspection.proxy_policy_timeout_ms,
            proxy_upstream_timeout_ms: core.dns_inspection.proxy_upstream_timeout_ms,
            proxy_shutdown_timeout_ms: core.dns_inspection.proxy_shutdown_timeout_ms,
            proxy_route_capacity: core.dns_inspection.proxy_route_capacity,
            proxy_query_capacity: core.dns_inspection.proxy_query_capacity,
            proxy_control_capacity: core.dns_inspection.proxy_control_capacity,
            proxy_policy_capacity: core.dns_inspection.proxy_policy_capacity,
        },
        interactive_queue_action: grith_supervisor::config::InteractiveQueueAction::default(),
        syscall_log_file: None,
        trace_syscalls_jsonl_file: None,
        reputation_config: grith_proxy::reputation::ReputationConfig::default(),
        // PR 6 Phase F: map core CoverageConfig → supervisor CoverageConfig.
        coverage: grith_supervisor::config::CoverageConfig {
            category1_hard_deny: core.coverage.category1_hard_deny,
            category2_proxy: core.coverage.category2_proxy,
            category2_crossprocess: core.coverage.category2_crossprocess,
            category3_namespace: core.coverage.category3_namespace,
            category4_arch_priv: core.coverage.category4_arch_priv,
            deny_self_seccomp_notify: core.coverage.deny_self_seccomp_notify,
            observe_self_seccomp_filter: core.coverage.observe_self_seccomp_filter,
        },
        // Default tier — callers that need an audit-completeness setting
        // should reach for `to_runtime_supervisor_config_with_audit`
        // instead. This loader-side path is used for legacy/test sites
        // and inherits today's "Spawns" default.
        audit_completeness: grith_supervisor::config::AuditCompletenessLevel::default(),
        pty_ownership_enforce: core.pty_ownership_enforce,
        enforce_authority_delegating_spawn: core.enforce_authority_delegating_spawn,
        enforce_control_socket_connect: core.enforce_control_socket_connect,
        dbus_message_inspection: core.dbus_message_inspection,
        authority_lost_terminate_after_seconds: core.authority_lost_terminate_after_seconds,
    }
}

// ---------------------------------------------------------------------------
// Provider key mtime
// ---------------------------------------------------------------------------

/// Return the maximum modification time of files in the provider-keys directory.
/// Used for rotation detection — if the mtime changes, keys may have been updated.
pub(crate) fn provider_keys_dir_mtime() -> Option<std::time::SystemTime> {
    let dir = crate::license::provider_keys_dir();
    let entries = std::fs::read_dir(&dir).ok()?;
    entries
        .flatten()
        .filter_map(|e| e.metadata().ok()?.modified().ok())
        .max()
}

// ---------------------------------------------------------------------------
// API key resolution
// ---------------------------------------------------------------------------

/// Resolve an API key: check config `api_key` first, then fall back to the env var named by `api_key_env`.
pub(crate) fn resolve_api_key(
    provider: &str,
    config_key: Option<&str>,
    env_var_name: &str,
) -> anyhow::Result<String> {
    fn read_key_file(path: &std::path::Path) -> Option<String> {
        let data = std::fs::read(path).ok()?;

        // Try encrypted envelope first
        if crate::license::is_encrypted_envelope(&data) {
            let api_key = crate::license::load_credentials()
                .ok()
                .flatten()
                .map(|c| c.api_key)?;
            let plaintext = crate::license::decrypt_provider_key(&api_key, &data)
                .map_err(|e| {
                    tracing::warn!(path = %path.display(), error = %e, "failed to decrypt provider key");
                    e
                })
                .ok()?;
            let parsed = serde_json::from_slice::<serde_json::Value>(&plaintext).ok()?;
            let key = parsed.get("key").and_then(|v| v.as_str())?;
            if key.is_empty() {
                return None;
            }
            tracing::info!(path = %path.display(), "loaded encrypted team-synced provider key");
            return Some(key.to_string());
        }

        // Fallback: plaintext JSON (legacy / migration)
        let parsed = serde_json::from_slice::<serde_json::Value>(&data).ok()?;
        let key = parsed.get("key").and_then(|v| v.as_str())?;
        if key.is_empty() {
            None
        } else {
            Some(key.to_string())
        }
    }

    // 1. Direct key in config
    if let Some(key) = config_key {
        if !key.is_empty() {
            return Ok(key.to_string());
        }
    }
    // 2. Environment variable
    if let Ok(key) = std::env::var(env_var_name) {
        if !key.is_empty() {
            return Ok(key);
        }
    }
    // 3. Cached provider key from vault (synced via `grith pro sync`)
    {
        let provider_name = match provider {
            "Anthropic" => "anthropic",
            "OpenAI" => "openai",
            "OpenRouter" => "openrouter",
            "Ollama" => "ollama",
            other => other,
        };
        let key_dir = crate::license::provider_keys_dir();
        let key_path = key_dir.join(format!("{provider_name}.json"));
        if key_path.exists() {
            if let Some(key) = read_key_file(&key_path) {
                return Ok(key);
            }
        } else if let Ok(entries) = std::fs::read_dir(&key_dir) {
            let mut candidates = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|v| v.to_str())
                        .map(|name| {
                            name.starts_with(&format!("{provider_name}--"))
                                && name.ends_with(".json")
                        })
                        .unwrap_or(false)
                })
                .collect::<Vec<_>>();
            candidates.sort();
            for candidate in candidates {
                if let Some(key) = read_key_file(&candidate) {
                    return Ok(key);
                }
            }
        }
    }
    anyhow::bail!(
        "{provider} API key not found. Either:\n  \
         1. Set api_key in your config (~/.config/grith/config.toml):\n     \
            [llm.{}]\n     \
            api_key = \"your-key-here\"\n  \
         2. Or set the {env_var_name} environment variable:\n     \
            export {env_var_name}=\"your-key-here\"\n  \
         3. Or sync provider keys from your team dashboard:\n     \
            grith pro sync",
        provider.to_lowercase()
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_expand_path_home() {
        let path = expand_path("/tmp/test");
        assert_eq!(path, PathBuf::from("/tmp/test"));
    }

    #[test]
    fn test_expand_path_tilde() {
        let path = expand_path("~/test");
        assert!(!path.to_string_lossy().starts_with('~'));
    }

    #[test]
    fn test_expand_path_no_tilde() {
        let path = expand_path("/absolute/path");
        assert_eq!(path, PathBuf::from("/absolute/path"));
    }

    #[test]
    fn test_to_supervisor_config_maps_dns_inspection() {
        let mut core = crate::config::SupervisorCoreConfig::default();
        core.dns_inspection.enabled = false;
        core.dns_inspection.upstream_resolver = Some("1.1.1.1:53".to_string());
        core.dns_inspection.connected_udp_proxy = true;
        core.dns_inspection.accept_proxy_network_authority = true;
        core.dns_inspection.proxy_queue_action =
            crate::config::SupervisorDnsProxyQueueAction::Forward;
        core.dns_inspection.proxy_max_response_bytes = 1232;
        core.dns_inspection.proxy_policy_timeout_ms = 250;
        core.dns_inspection.proxy_upstream_timeout_ms = 750;
        core.dns_inspection.proxy_shutdown_timeout_ms = 500;
        core.dns_inspection.proxy_route_capacity = 8;
        core.dns_inspection.proxy_query_capacity = 32;
        core.dns_inspection.proxy_control_capacity = 16;
        core.dns_inspection.proxy_policy_capacity = 4;

        let mapped = to_supervisor_config(&core);
        assert!(!mapped.dns_inspection.enabled);
        assert_eq!(
            mapped.dns_inspection.upstream_resolver.as_deref(),
            Some("1.1.1.1:53")
        );
        assert!(mapped.dns_inspection.connected_udp_proxy);
        assert!(mapped.dns_inspection.accept_proxy_network_authority);
        assert_eq!(
            mapped.dns_inspection.proxy_queue_action,
            grith_supervisor::config::DnsProxyQueueAction::Forward
        );
        assert_eq!(mapped.dns_inspection.proxy_max_response_bytes, 1232);
        assert_eq!(mapped.dns_inspection.proxy_policy_timeout_ms, 250);
        assert_eq!(mapped.dns_inspection.proxy_upstream_timeout_ms, 750);
        assert_eq!(mapped.dns_inspection.proxy_shutdown_timeout_ms, 500);
        assert_eq!(mapped.dns_inspection.proxy_route_capacity, 8);
        assert_eq!(mapped.dns_inspection.proxy_query_capacity, 32);
        assert_eq!(mapped.dns_inspection.proxy_control_capacity, 16);
        assert_eq!(mapped.dns_inspection.proxy_policy_capacity, 4);
    }

    #[test]
    fn test_load_secret_patterns_real_corpus_has_expected_count_and_is_deduplicated() {
        // 1618 after S1 (2026-08-07) removed the two looser unanchored FaunaDB /
        // Resend duplicates (`fauna-secret-bare`, `resend-api-key-bare`).
        let patterns = load_secret_patterns().expect("load real secret corpus");
        assert_eq!(patterns.len(), 1618);

        let ids = patterns
            .iter()
            .map(|pattern| pattern.id.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(
            ids.len(),
            patterns.len(),
            "duplicate secret pattern ids detected"
        );

        let regexes = patterns
            .iter()
            .map(|pattern| pattern.regex.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(
            regexes.len(),
            patterns.len(),
            "duplicate secret regex bodies detected"
        );
    }

    // --- Provider key file reading tests ---

    #[test]
    fn test_read_key_file_plaintext_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("anthropic.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "provider": "anthropic",
                "label": "default",
                "key": "sk-ant-legacy-plain"
            })
            .to_string(),
        )
        .unwrap();

        // Use the resolve function indirectly — we test read_key_file through it.
        // Since resolve_api_key is the public interface, we test it directly here
        // by reading the file manually with the same logic.
        let data = std::fs::read(&path).unwrap();
        assert!(!crate::license::is_encrypted_envelope(&data));
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        let key = parsed["key"].as_str().unwrap();
        assert_eq!(key, "sk-ant-legacy-plain");
    }

    #[test]
    fn test_read_key_file_encrypted_format() {
        let api_key = "test-api-key-for-config-loader";
        let plaintext = serde_json::json!({
            "provider": "anthropic",
            "label": "default",
            "key": "sk-ant-encrypted-123"
        })
        .to_string();

        let encrypted =
            crate::license::encrypt_provider_key(api_key, "anthropic", plaintext.as_bytes())
                .unwrap();

        // Verify it's detected as encrypted
        assert!(crate::license::is_encrypted_envelope(&encrypted));

        // Verify round-trip decryption
        let decrypted = crate::license::decrypt_provider_key(api_key, &encrypted).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(parsed["key"].as_str().unwrap(), "sk-ant-encrypted-123");
    }
}
