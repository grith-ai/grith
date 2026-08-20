// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Persistent learned allowlist rules.
//!
//! When a user presses `[l]` (Learn & approve) in the permission dialog,
//! the approved operation is persisted as a learned rule. On future session
//! starts, learned rules are loaded and merged into the session allowlist
//! so the user is never prompted for the same operation again.
//!
//! Rules are profile-scoped: a rule learned in `claude-code` profile only
//! applies to `claude-code` sessions.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// A single persistent learned allowlist rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LearnedRule {
    /// Allowlist pattern: `ro:`, `rw:`, `exec:`, `exec-prefix:`, `net:`, or `dns:` prefixed.
    pub pattern: String,
    /// Profile this rule applies to (e.g., "claude-code").
    pub profile: String,
    /// Whether this is a user-local or team-synced rule.
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Human-readable reason captured at learn time.
    #[serde(default)]
    pub reason: String,
    /// ISO 8601 timestamp of when the rule was created.
    #[serde(default)]
    pub created_at: String,
    /// User ID or email of the creator (empty for local rules).
    #[serde(default)]
    pub created_by: String,
}

fn default_scope() -> String {
    "user".to_string()
}

/// Team-synced learned rule cached locally as JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TeamLearnedRule {
    pub pattern: String,
    pub profile: String,
    pub scope: String,
    pub reason: String,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LearnedRulesFile {
    #[serde(default)]
    rules: Vec<LearnedRule>,
}

/// Validate that a pattern is a persistable learned rule.
///
/// Only namespaced patterns are allowed — bare filesystem paths (which would
/// inherit prefix-matching behavior) are rejected.
/// Validate that a pattern is a persistable learned rule.
///
/// Only namespaced patterns are allowed — bare filesystem paths (which would
/// inherit prefix-matching behavior) are rejected. `exec-prefix:` rules are
/// rejected for user-local rules (v1 only allows admin-created team rules
/// for vetted roots). `dns:` is rejected because the runtime matching logic
/// only checks `net:` entries for DNS keys.
pub fn validate_persisted_rule(pattern: &str) -> Result<()> {
    validate_persisted_rule_with_scope(pattern, "user")
}

/// Validate with explicit scope. `exec-prefix:` is only allowed for `"team"` scope.
pub fn validate_persisted_rule_with_scope(pattern: &str, scope: &str) -> Result<()> {
    if pattern.is_empty() {
        return Err(Error::LearnedRuleError(
            "pattern must not be empty".to_string(),
        ));
    }
    if pattern.len() > 512 {
        return Err(Error::LearnedRuleError(
            "pattern must not exceed 512 characters".to_string(),
        ));
    }

    // dns: rules are rejected — runtime matching only checks net: entries.
    let valid_prefixes = ["ro:", "rw:", "exec:", "exec-prefix:", "net:", "ipc-socket:"];
    if !valid_prefixes.iter().any(|p| pattern.starts_with(p)) {
        return Err(Error::LearnedRuleError(format!(
            "pattern must start with one of: {}. Bare filesystem paths and dns: are not persistable.",
            valid_prefixes.join(", ")
        )));
    }

    // exec-prefix: requires additional validation.
    if let Some(suffix) = pattern.strip_prefix("exec-prefix:") {
        // User-local exec-prefix: rules are forbidden in v1.
        if scope != "team" {
            return Err(Error::LearnedRuleError(
                "exec-prefix: rules can only be created by team admins, not user-local [l] actions"
                    .to_string(),
            ));
        }
        // The suffix must be a non-empty absolute path.
        if suffix.is_empty() || !suffix.starts_with('/') {
            return Err(Error::LearnedRuleError(
                "exec-prefix: pattern must contain a non-empty absolute path (e.g., exec-prefix:/usr/lib/git-core/)"
                    .to_string(),
            ));
        }
    }

    // ipc-socket: is the durable exe-bound control-socket grant:
    // `ipc-socket:<rendered socket address>|<absolute client exe>`. The
    // address keeps the runtime `unix:` render (pathname `unix:/run/…` or
    // abstract `unix:@/tmp/…`) because the grant is consumed by exact
    // string equality against the same render. Privileged daemon sockets
    // (docker.sock, systemd/private, …) are rejected here so a hand-edited
    // rules file cannot grant what the [a]/[l] flow refuses to mint. The
    // write-path validation covers the load path too — `load_learned_rules`
    // re-validates every rule.
    if let Some(suffix) = pattern.strip_prefix("ipc-socket:") {
        let Some((socket, exe)) = suffix.split_once('|') else {
            return Err(Error::LearnedRuleError(
                "ipc-socket: pattern must be `ipc-socket:<socket address>|<client exe>`"
                    .to_string(),
            ));
        };
        let bare = socket
            .strip_prefix("unix:")
            .map(|p| p.strip_prefix('@').unwrap_or(p));
        let Some(bare) = bare else {
            return Err(Error::LearnedRuleError(
                "ipc-socket: socket address must start with `unix:`".to_string(),
            ));
        };
        if !bare.starts_with('/') {
            return Err(Error::LearnedRuleError(
                "ipc-socket: socket address must contain an absolute path".to_string(),
            ));
        }
        if crate::supervisor::is_sensitive_unix_socket(bare) {
            return Err(Error::LearnedRuleError(
                "ipc-socket: privileged daemon sockets are not grantable".to_string(),
            ));
        }
        if !exe.starts_with('/') {
            return Err(Error::LearnedRuleError(
                "ipc-socket: client exe must be an absolute path".to_string(),
            ));
        }
    }

    // ro: and rw: must have absolute paths.
    if let Some(suffix) = pattern.strip_prefix("ro:") {
        if !suffix.starts_with('/') {
            return Err(Error::LearnedRuleError(
                "ro: pattern must contain an absolute path".to_string(),
            ));
        }
    }
    if let Some(suffix) = pattern.strip_prefix("rw:") {
        if !suffix.starts_with('/') {
            return Err(Error::LearnedRuleError(
                "rw: pattern must contain an absolute path".to_string(),
            ));
        }
    }

    // exec: must have an absolute path.
    if pattern.starts_with("exec:") && !pattern.starts_with("exec-prefix:") {
        if let Some(suffix) = pattern.strip_prefix("exec:") {
            if !suffix.starts_with('/') {
                return Err(Error::LearnedRuleError(
                    "exec: pattern must contain an absolute path".to_string(),
                ));
            }
        }
    }

    // A persisted allowlist rule is consumed BEFORE the proxy and before taint
    // registration — it auto-allows. So a rule targeting a sensitive path (ssh
    // keys, .env, cloud creds, /etc/shadow, …) would silently grant access to
    // secrets for every future session, bypassing the proxy. Reject such rules
    // outright (research doc §5.1 #6): a sensitive access must always be
    // evaluated, never short-circuited by a learned rule.
    if let Some(path) = pattern
        .strip_prefix("ro:")
        .or_else(|| pattern.strip_prefix("rw:"))
        .or_else(|| pattern.strip_prefix("exec-prefix:"))
        .or_else(|| pattern.strip_prefix("exec:"))
    {
        if path_targets_sensitive(path) {
            return Err(Error::LearnedRuleError(format!(
                "refusing to persist a rule targeting a sensitive path ({path}): \
                 sensitive accesses must go through the proxy, not an auto-allow rule"
            )));
        }
    }

    Ok(())
}

/// True when a learned-rule target path points at credential/secret material.
/// Erring toward rejection is the safe bias for a security gate: a wrongly
/// rejected rule just means the access goes through the proxy.
fn path_targets_sensitive(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    // Match the actual secret MATERIAL, not the whole credential directory:
    // `.ssh/config`/`known_hosts` are benign config (and the existing design
    // treats `ro:~/.ssh/config` as a valid persistable rule), whereas a private
    // key, `authorized_keys`, or `.aws/credentials` is the secret the hole was
    // about (`rw:~/.ssh/id_rsa`). Erring toward rejection within this set.
    const SENSITIVE_MARKERS: &[&str] = &[
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "/.ssh/authorized_keys",
        "/.aws/credentials",
        "/.gnupg/", // entire gnupg home is key material
        "/.kube/config",
        "/.docker/config.json",
        "/.config/gcloud/",
        "/.git-credentials",
        "/.netrc",
        "/.pgpass",
        "/.npmrc",
        "/.pypirc",
        "/etc/shadow",
        "/etc/gshadow",
        "private_key",
        "/credentials",
        "/secrets",
        "/.env",
    ];
    SENSITIVE_MARKERS.iter().any(|m| p.contains(m))
}

fn normalize_loaded_pattern(pattern: &str) -> String {
    for prefix in &["ro:", "rw:"] {
        if let Some(path) = pattern.strip_prefix(prefix) {
            if let Ok(canonical) = std::fs::canonicalize(path) {
                if let Some(s) = canonical.to_str() {
                    return format!("{prefix}{s}");
                }
            }
        }
    }
    pattern.to_string()
}

/// Load learned rules from a TOML file.
///
/// Returns an empty vec if the file does not exist or is empty.
/// Logs a warning and returns empty on parse errors (not fatal).
pub fn load_learned_rules(path: impl AsRef<Path>) -> Vec<LearnedRule> {
    let path = path.as_ref();
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(path) {
        Ok(content) if content.trim().is_empty() => Vec::new(),
        Ok(content) => match toml::from_str::<LearnedRulesFile>(&content) {
            Ok(file) => file
                .rules
                .into_iter()
                .filter(|r| {
                    if validate_persisted_rule(&r.pattern).is_err() {
                        tracing::warn!(
                            pattern = r.pattern,
                            "ignoring invalid learned rule on load"
                        );
                        false
                    } else {
                        true
                    }
                })
                .collect(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "failed to parse learned rules file; starting with empty rules"
                );
                Vec::new()
            }
        },
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "failed to read learned rules file"
            );
            Vec::new()
        }
    }
}

/// Append a learned rule to the TOML file.
///
/// Deduplicates on `(pattern, profile)` — if an entry with the same pattern
/// and profile already exists, this is a no-op.
///
/// The write is atomic (temp + fsync + rename) and uses a lock file to
/// prevent concurrent writers from losing updates.
pub fn append_learned_rule(path: impl AsRef<Path>, rule: LearnedRule) -> Result<()> {
    validate_persisted_rule(&rule.pattern)?;

    let path = path.as_ref();

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::LearnedRuleError(format!(
                "failed to create directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    // Acquire a file lock to prevent concurrent writers from racing.
    let lock_path = path.with_extension("toml.lock");
    let _lock = acquire_file_lock(&lock_path)?;

    // Load existing rules for dedup check.
    // If the file exists but can't be parsed, abort rather than silently
    // discarding existing rules.
    let mut file = if path.exists() {
        match std::fs::read_to_string(path) {
            Ok(content) if content.trim().is_empty() => LearnedRulesFile::default(),
            Ok(content) => toml::from_str::<LearnedRulesFile>(&content).map_err(|e| {
                Error::LearnedRuleError(format!(
                    "existing learned rules file is corrupted and cannot be parsed: {e}. \
                     Fix or delete {} before learning new rules.",
                    path.display()
                ))
            })?,
            Err(e) => {
                return Err(Error::LearnedRuleError(format!(
                    "failed to read existing rules file: {e}"
                )));
            }
        }
    } else {
        LearnedRulesFile::default()
    };

    // Dedup: skip if (pattern, profile) already exists.
    if file
        .rules
        .iter()
        .any(|r| r.pattern == rule.pattern && r.profile == rule.profile)
    {
        tracing::debug!(
            pattern = rule.pattern,
            profile = rule.profile,
            "learned rule already exists, skipping"
        );
        return Ok(());
    }

    file.rules.push(rule);

    let content = toml::to_string_pretty(&file)
        .map_err(|e| Error::LearnedRuleError(format!("failed to serialize rules: {e}")))?;

    // Atomic write: temp file + fsync + rename.
    let tmp_path = path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, &content)
        .map_err(|e| Error::LearnedRuleError(format!("failed to write temp file: {e}")))?;

    // Set restrictive permissions (0600) on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(&tmp_path, perms);
    }

    // fsync the temp file.
    if let Ok(f) = std::fs::File::open(&tmp_path) {
        let _ = f.sync_all();
    }

    std::fs::rename(&tmp_path, path)
        .map_err(|e| Error::LearnedRuleError(format!("failed to rename temp file: {e}")))?;

    Ok(())
}

/// Load cached team learned rules from the JSON cache file.
pub fn load_team_learned_rules(path: impl AsRef<Path>) -> Vec<TeamLearnedRule> {
    let path = path.as_ref();
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(path) {
        Ok(content) if content.trim().is_empty() => Vec::new(),
        Ok(content) => match serde_json::from_str::<Vec<TeamLearnedRule>>(&content) {
            Ok(rules) => rules
                .into_iter()
                .filter(|r| {
                    if validate_persisted_rule_with_scope(&r.pattern, &r.scope).is_err() {
                        tracing::warn!(
                            pattern = r.pattern,
                            scope = r.scope,
                            "ignoring invalid team learned rule from cache"
                        );
                        false
                    } else {
                        true
                    }
                })
                .collect(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "failed to parse team learned rules cache; starting with empty rules"
                );
                Vec::new()
            }
        },
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "failed to read team learned rules cache"
            );
            Vec::new()
        }
    }
}

/// Atomically write the team learned-rules cache to disk.
pub fn write_team_learned_rules_cache(
    path: impl AsRef<Path>,
    rules: &[TeamLearnedRule],
) -> Result<()> {
    let path = path.as_ref();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::LearnedRuleError(format!(
                "failed to create directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    let json = serde_json::to_string_pretty(rules)
        .map_err(|e| Error::LearnedRuleError(format!("failed to serialize team rules: {e}")))?;

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)
        .map_err(|e| Error::LearnedRuleError(format!("failed to write team rule cache: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }

    if let Ok(f) = std::fs::File::open(&tmp) {
        let _ = f.sync_all();
    }

    std::fs::rename(&tmp, path).map_err(|e| {
        Error::LearnedRuleError(format!("failed to rename team rule cache into place: {e}"))
    })?;

    Ok(())
}

/// Simple file-based lock using a lock file with exclusive create.
/// Returns a guard that removes the lock file on drop.
struct FileLockGuard(std::path::PathBuf);

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn acquire_file_lock(lock_path: &Path) -> Result<FileLockGuard> {
    // Try to create the lock file exclusively. Retry briefly on contention.
    for attempt in 0..20 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(lock_path)
        {
            Ok(_) => return Ok(FileLockGuard(lock_path.to_path_buf())),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Check if the lock is stale (older than 10 seconds).
                if let Ok(meta) = std::fs::metadata(lock_path) {
                    if let Some(age) = meta.modified().ok().and_then(|m| m.elapsed().ok()) {
                        if age.as_secs() > 10 {
                            let _ = std::fs::remove_file(lock_path);
                            continue;
                        }
                    }
                }
                if attempt < 19 {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                return Err(Error::LearnedRuleError(
                    "could not acquire lock for learned rules file (another process holds it)"
                        .to_string(),
                ));
            }
            Err(e) => {
                return Err(Error::LearnedRuleError(format!(
                    "failed to create lock file: {e}"
                )));
            }
        }
    }
    Err(Error::LearnedRuleError(
        "exhausted lock attempts".to_string(),
    ))
}

/// Filter rules to those matching the given profile name.
pub fn rules_for_profile<'a>(rules: &'a [LearnedRule], profile_name: &str) -> Vec<&'a LearnedRule> {
    rules.iter().filter(|r| r.profile == profile_name).collect()
}

/// Return the default path for the learned rules file.
///
/// Falls back to a temporary directory if `$HOME` is unset, but logs a warning
/// because `/tmp` is not a suitable persistence location.
pub fn default_learned_rules_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("GRITH_CONFIG_DIR") {
        return std::path::PathBuf::from(path).join("learned_rules.toml");
    }

    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home)
            .join(".config/grith")
            .join("learned_rules.toml");
    }

    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return std::path::PathBuf::from(profile)
            .join(".config/grith")
            .join("learned_rules.toml");
    }

    std::path::PathBuf::from(".grith").join("learned_rules.toml")
}

/// Return the default path for the team learned-rules cache.
pub fn team_learned_rules_cache_path() -> std::path::PathBuf {
    default_learned_rules_path().with_file_name("team_learned_rules.json")
}

/// Merge local and cached team learned rules for a profile into an allowlist.
///
/// Returns `(local_loaded, team_loaded)`.
pub fn merge_cached_rules_for_profile(
    allowlist: &mut HashSet<String>,
    profile_name: &str,
    local_path: impl AsRef<Path>,
    team_cache_path: impl AsRef<Path>,
) -> (usize, usize) {
    let local_rules = load_learned_rules(local_path);
    let local_for_profile = rules_for_profile(&local_rules, profile_name);
    for rule in &local_for_profile {
        allowlist.insert(normalize_loaded_pattern(&rule.pattern));
    }

    let team_rules = load_team_learned_rules(team_cache_path);
    let mut team_loaded = 0usize;
    for rule in &team_rules {
        if rule.profile == profile_name
            && validate_persisted_rule_with_scope(&rule.pattern, &rule.scope).is_ok()
        {
            allowlist.insert(normalize_loaded_pattern(&rule.pattern));
            team_loaded += 1;
        }
    }

    (local_for_profile.len(), team_loaded)
}

/// Merge local and cached team learned rules for a profile using default paths.
pub fn merge_default_cached_rules_for_profile(
    allowlist: &mut HashSet<String>,
    profile_name: &str,
) -> (usize, usize) {
    merge_cached_rules_for_profile(
        allowlist,
        profile_name,
        default_learned_rules_path(),
        team_learned_rules_cache_path(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_rule(pattern: &str, profile: &str) -> LearnedRule {
        LearnedRule {
            pattern: pattern.to_string(),
            profile: profile.to_string(),
            scope: "user".to_string(),
            reason: "test".to_string(),
            created_at: "2026-03-18T00:00:00Z".to_string(),
            created_by: String::new(),
        }
    }

    fn test_team_rule(pattern: &str, profile: &str, scope: &str) -> TeamLearnedRule {
        TeamLearnedRule {
            pattern: pattern.to_string(),
            profile: profile.to_string(),
            scope: scope.to_string(),
            reason: "team".to_string(),
            created_at: "2026-03-18T00:00:00Z".to_string(),
            created_by: "admin@example.com".to_string(),
        }
    }

    #[test]
    fn validate_rejects_empty_pattern() {
        assert!(validate_persisted_rule("").is_err());
    }

    #[test]
    fn validate_rejects_bare_path() {
        assert!(validate_persisted_rule("/home/dan/.ssh/config").is_err());
    }

    #[test]
    fn validate_rejects_wildcard() {
        assert!(validate_persisted_rule("/home/dan/.ssh/*").is_err());
    }

    #[test]
    fn validate_accepts_ro_prefix() {
        assert!(validate_persisted_rule("ro:/home/dan/.ssh/config").is_ok());
    }

    /// The exe-bound control-socket grant: pathname and abstract renders
    /// are persistable; privileged daemon sockets, malformed shapes, and
    /// relative exes are not (a hand-edited rules file must not grant what
    /// the [a]/[l] flow refuses to mint).
    #[test]
    fn validate_ipc_socket_grants() {
        assert!(validate_persisted_rule("ipc-socket:unix:/run/user/1000/bus|/usr/bin/gh").is_ok());
        assert!(
            validate_persisted_rule("ipc-socket:unix:@/tmp/.X11-unix/X1|/usr/bin/xclip").is_ok()
        );

        for pat in [
            // Privileged daemon sockets are un-grantable.
            "ipc-socket:unix:/var/run/docker.sock|/usr/bin/docker",
            "ipc-socket:unix:/run/user/1000/systemd/private|/usr/bin/systemd-run",
            // Abstract render mimicking a privileged path: same rejection.
            "ipc-socket:unix:@/var/run/docker.sock|/usr/bin/docker",
            // Malformed: no exe separator, missing unix: render, relative
            // socket path, relative exe.
            "ipc-socket:unix:/run/user/1000/bus",
            "ipc-socket:/run/user/1000/bus|/usr/bin/gh",
            "ipc-socket:unix:bus|/usr/bin/gh",
            "ipc-socket:unix:/run/user/1000/bus|gh",
        ] {
            assert!(validate_persisted_rule(pat).is_err(), "must reject {pat}");
        }
    }

    // Protection suite (research doc §5.1 #6): a learned rule auto-allows
    // BEFORE the proxy + taint, so one targeting secret material must be
    // rejected — otherwise injecting `rw:~/.ssh/id_rsa` silently grants it.
    #[test]
    fn validate_rejects_sensitive_path_learned_rules() {
        for pat in [
            "rw:/home/dan/.ssh/id_rsa",
            "ro:/home/dan/.ssh/id_ed25519",
            "ro:/home/dan/.ssh/authorized_keys",
            "ro:/home/dan/.aws/credentials",
            "rw:/home/dan/.gnupg/secring.gpg",
            "ro:/home/dan/.git-credentials",
            "ro:/home/dan/project/.env",
            "ro:/etc/shadow",
            "ro:/home/dan/.kube/config",
            "exec:/home/dan/.local/bin/id_rsa-stealer", // contains id_rsa marker
        ] {
            assert!(
                validate_persisted_rule(pat).is_err(),
                "{pat} targets sensitive material and must be rejected"
            );
        }
    }

    // Benign counterparts must still validate (no over-rejection of common
    // config/data paths).
    #[test]
    fn validate_accepts_benign_paths_near_sensitive_dirs() {
        for pat in [
            "ro:/home/dan/.ssh/config",      // ssh client config (not a key)
            "ro:/home/dan/.ssh/known_hosts", // not a key
            "ro:/home/dan/.aws/config",      // region/profile config, not creds
            "rw:/home/dan/project/main.rs",
            "exec:/usr/bin/git",
        ] {
            assert!(
                validate_persisted_rule(pat).is_ok(),
                "{pat} is benign and must validate"
            );
        }
    }

    #[test]
    fn validate_accepts_rw_prefix() {
        assert!(validate_persisted_rule("rw:/home/dan/project/file.rs").is_ok());
    }

    #[test]
    fn validate_accepts_exec_prefix() {
        assert!(validate_persisted_rule("exec:/usr/bin/ssh").is_ok());
    }

    #[test]
    fn validate_rejects_user_exec_prefix() {
        // User-local exec-prefix: rules are forbidden in v1.
        assert!(validate_persisted_rule("exec-prefix:/usr/lib/git-core/").is_err());
    }

    #[test]
    fn validate_accepts_team_exec_prefix() {
        assert!(
            validate_persisted_rule_with_scope("exec-prefix:/usr/lib/git-core/", "team").is_ok()
        );
    }

    #[test]
    fn validate_rejects_empty_exec_prefix() {
        assert!(validate_persisted_rule_with_scope("exec-prefix:", "team").is_err());
    }

    #[test]
    fn validate_rejects_relative_exec_prefix() {
        assert!(validate_persisted_rule_with_scope("exec-prefix:relative/path/", "team").is_err());
    }

    #[test]
    fn validate_accepts_net() {
        assert!(validate_persisted_rule("net:github.com").is_ok());
    }

    #[test]
    fn validate_rejects_dns() {
        // dns: rules are rejected — runtime only matches net: entries for DNS keys.
        assert!(validate_persisted_rule("dns:api.anthropic.com").is_err());
    }

    #[test]
    fn validate_rejects_long_pattern() {
        let long = format!("ro:{}", "a".repeat(512));
        assert!(validate_persisted_rule(&long).is_err());
    }

    #[test]
    fn validate_rejects_relative_ro_path() {
        assert!(validate_persisted_rule("ro:relative/path").is_err());
    }

    #[test]
    fn validate_rejects_relative_rw_path() {
        assert!(validate_persisted_rule("rw:not-absolute").is_err());
    }

    #[test]
    fn validate_rejects_relative_exec_path() {
        assert!(validate_persisted_rule("exec:relative-binary").is_err());
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let rules = load_learned_rules("/nonexistent/path/rules.toml");
        assert!(rules.is_empty());
    }

    #[test]
    fn load_empty_file_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("rules.toml");
        std::fs::write(&path, "").unwrap();
        let rules = load_learned_rules(&path);
        assert!(rules.is_empty());
    }

    #[test]
    fn append_and_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("rules.toml");

        let rule = test_rule("ro:/home/dan/.ssh/config", "claude-code");
        append_learned_rule(&path, rule.clone()).unwrap();

        let loaded = load_learned_rules(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].pattern, "ro:/home/dan/.ssh/config");
        assert_eq!(loaded[0].profile, "claude-code");
    }

    #[test]
    fn append_deduplicates() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("rules.toml");

        let rule = test_rule("ro:/home/dan/.ssh/config", "claude-code");
        append_learned_rule(&path, rule.clone()).unwrap();
        append_learned_rule(&path, rule.clone()).unwrap();

        let loaded = load_learned_rules(&path);
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn append_allows_same_pattern_different_profile() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("rules.toml");

        append_learned_rule(&path, test_rule("ro:/home/dan/.ssh/config", "claude-code")).unwrap();
        append_learned_rule(&path, test_rule("ro:/home/dan/.ssh/config", "codex")).unwrap();

        let loaded = load_learned_rules(&path);
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn load_team_rules_filters_invalid_scope_sensitive_entries() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("team_rules.json");
        let rules = vec![
            test_team_rule("exec-prefix:/usr/lib/git-core/", "claude-code", "team"),
            test_team_rule("exec-prefix:/usr/lib/git-core/", "claude-code", "user"),
        ];
        std::fs::write(&path, serde_json::to_string_pretty(&rules).unwrap()).unwrap();

        let loaded = load_team_learned_rules(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].scope, "team");
    }

    #[test]
    fn merge_cached_rules_recanonicalizes_local_and_team_entries() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("real.txt");
        std::fs::write(&target, "ok").unwrap();

        #[cfg(unix)]
        let learned_pattern = {
            let symlink_path = tmp.path().join("symlink.txt");
            std::os::unix::fs::symlink(&target, &symlink_path).unwrap();
            format!("ro:{}", symlink_path.display())
        };
        #[cfg(not(unix))]
        let learned_pattern = format!("ro:{}", target.display());

        let learned_path = tmp.path().join("learned_rules.toml");
        append_learned_rule(&learned_path, test_rule(&learned_pattern, "claude-code")).unwrap();

        let team_cache = tmp.path().join("team_rules.json");
        write_team_learned_rules_cache(
            &team_cache,
            &[test_team_rule(
                &format!("rw:{}", target.display()),
                "claude-code",
                "team",
            )],
        )
        .unwrap();

        let mut allowlist = HashSet::new();
        let (local_loaded, team_loaded) = merge_cached_rules_for_profile(
            &mut allowlist,
            "claude-code",
            &learned_path,
            &team_cache,
        );

        assert_eq!(local_loaded, 1);
        assert_eq!(team_loaded, 1);
        let canonical = std::fs::canonicalize(&target).unwrap();
        let canonical = canonical.to_string_lossy();
        assert!(allowlist.contains(&format!("ro:{canonical}")));
        assert!(allowlist.contains(&format!("rw:{canonical}")));
    }

    #[test]
    fn append_rejects_bare_path() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("rules.toml");

        let rule = test_rule("/home/dan/.ssh/config", "claude-code");
        assert!(append_learned_rule(&path, rule).is_err());
    }

    #[test]
    fn load_filters_invalid_rules() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("rules.toml");

        // Write a file with one valid and one invalid rule.
        let content = r#"
[[rules]]
pattern = "ro:/home/dan/.ssh/config"
profile = "claude-code"
scope = "user"

[[rules]]
pattern = "/bare/path/invalid"
profile = "claude-code"
scope = "user"
"#;
        std::fs::write(&path, content).unwrap();

        let loaded = load_learned_rules(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].pattern, "ro:/home/dan/.ssh/config");
    }

    #[test]
    fn rules_for_profile_filters_correctly() {
        let rules = vec![
            test_rule("ro:/home/dan/.ssh/config", "claude-code"),
            test_rule("ro:/home/dan/.ssh/known_hosts", "claude-code"),
            test_rule("exec:/usr/bin/ssh", "codex"),
        ];

        let claude = rules_for_profile(&rules, "claude-code");
        assert_eq!(claude.len(), 2);

        let codex = rules_for_profile(&rules, "codex");
        assert_eq!(codex.len(), 1);

        let generic = rules_for_profile(&rules, "generic");
        assert!(generic.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("rules.toml");

        append_learned_rule(&path, test_rule("ro:/tmp/test", "claude-code")).unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file should have 0600 permissions");
    }
}
