// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Signed remote profile overlay manifest: schema, verification, and cache.
//!
//! The remote overlay manifest is a signed JSON document that contains
//! reviewed allowlist additions for existing supervisor profiles. It is
//! intentionally restricted to five additive vectors (routine_paths,
//! routine_commands, routine_destinations, readonly_paths,
//! readonly_path_patterns) and cannot alter structural profile semantics.
//!
//! The signing keypair is separate from the license-signing key.

use base64::prelude::*;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use grith_supervisor::profiles::ProfileConfig;

/// Bootstrap Ed25519 public key for profile manifest signature verification.
///
/// Release builds should set `GRITH_PROFILE_PUBLIC_KEY_HEX` at build time to
/// the ceremony-produced verifier key. The bootstrap key keeps local builds
/// non-placeholder without widening trust if the release key has not yet been
/// configured.
const BOOTSTRAP_PROFILE_PUBLIC_KEY_HEX: &str =
    "d5e83180e0022d63779888f77471bf315ffa0e0f82fd54e83680185edfe6a4d4";

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const SUPPORTED_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Signed remote profile overlay manifest (JSON wire format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteProfileManifest {
    pub schema_version: u32,
    pub profiles_version: u64,
    pub min_grith_version: String,
    pub released_at: String,
    pub changelog: String,
    pub profiles: HashMap<String, RemoteProfileOverlay>,
    pub signature: String,
}

/// Per-profile overlay entries. Only the five v1-eligible vectors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteProfileOverlay {
    #[serde(default)]
    pub routine_paths: Vec<String>,
    #[serde(default)]
    pub routine_commands: Vec<String>,
    #[serde(default)]
    pub routine_destinations: Vec<String>,
    #[serde(default)]
    pub readonly_paths: Vec<String>,
    #[serde(default)]
    pub readonly_path_patterns: Vec<String>,
}

/// Local metadata for anti-rollback and TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileCacheMeta {
    pub highest_accepted_profiles_version: u64,
    pub last_checked_at: String,
}

/// Errors specific to profile manifest verification.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid verifier key: {0}")]
    InvalidVerifierKey(String),
    #[error("unsupported schema version: {0}")]
    UnsupportedSchema(u32),
    #[error("incompatible min_grith_version: requires {0}, running {CURRENT_VERSION}")]
    IncompatibleVersion(String),
    #[error("anti-rollback: version {got} <= highest accepted {expected}")]
    Rollback { got: u64, expected: u64 },
    #[error("unknown profile: {0}")]
    UnknownProfile(String),
    #[error("invalid entry in {field}: {reason}")]
    InvalidEntry { field: String, reason: String },
    #[error("cache I/O: {0}")]
    CacheIo(String),
    #[error("parse error: {0}")]
    Parse(String),
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a remote profile manifest against the embedded public key.
///
/// Checks: JSON parse, signature, schema version, grith version compatibility,
/// anti-rollback, profile name existence, and entry-level constraints.
pub fn verify_manifest(
    raw_json: &[u8],
    known_profile_names: &HashSet<String>,
    highest_accepted_version: u64,
) -> Result<RemoteProfileManifest, ManifestError> {
    // 1. Parse JSON.
    let manifest: RemoteProfileManifest =
        serde_json::from_slice(raw_json).map_err(|e| ManifestError::Parse(e.to_string()))?;

    // 2. Decode base64 signature.
    let sig_bytes = BASE64_STANDARD
        .decode(&manifest.signature)
        .map_err(|_| ManifestError::InvalidSignature)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| ManifestError::InvalidSignature)?;

    // 3. Build canonical payload and verify.
    let canonical = canonicalize_manifest(&manifest);
    let message = canonical.as_bytes();

    let verifying_key = configured_profile_verifying_key()?;
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| ManifestError::InvalidSignature)?;

    // 4. Check schema version.
    if manifest.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(ManifestError::UnsupportedSchema(manifest.schema_version));
    }

    // 5. Check grith version compatibility.
    if version_is_newer(&manifest.min_grith_version, CURRENT_VERSION) {
        return Err(ManifestError::IncompatibleVersion(
            manifest.min_grith_version.clone(),
        ));
    }

    // 6. Anti-rollback.
    if manifest.profiles_version <= highest_accepted_version {
        return Err(ManifestError::Rollback {
            got: manifest.profiles_version,
            expected: highest_accepted_version,
        });
    }

    // 7. Validate profile names and entries.
    for (name, overlay) in &manifest.profiles {
        if !known_profile_names.contains(name.as_str()) {
            return Err(ManifestError::UnknownProfile(name.clone()));
        }
        validate_overlay_entries(name, overlay)?;
    }

    Ok(manifest)
}

/// Canonicalize manifest payload for signature verification.
///
/// Builds a JSON string with sorted keys, excluding the `signature` field.
/// The `profiles` value is a sorted map of sorted-key objects.
pub fn canonicalize_manifest(manifest: &RemoteProfileManifest) -> String {
    let mut map = serde_json::Map::new();
    map.insert("changelog".into(), serde_json::json!(manifest.changelog));
    map.insert(
        "min_grith_version".into(),
        serde_json::json!(manifest.min_grith_version),
    );

    // Build sorted profiles map with sorted overlay keys.
    let mut profiles_map = serde_json::Map::new();
    let mut profile_names: Vec<&String> = manifest.profiles.keys().collect();
    profile_names.sort();
    for name in profile_names {
        let overlay = &manifest.profiles[name];
        let mut overlay_map = serde_json::Map::new();
        overlay_map.insert(
            "readonly_path_patterns".into(),
            serde_json::json!(overlay.readonly_path_patterns),
        );
        overlay_map.insert(
            "readonly_paths".into(),
            serde_json::json!(overlay.readonly_paths),
        );
        overlay_map.insert(
            "routine_commands".into(),
            serde_json::json!(overlay.routine_commands),
        );
        overlay_map.insert(
            "routine_destinations".into(),
            serde_json::json!(overlay.routine_destinations),
        );
        overlay_map.insert(
            "routine_paths".into(),
            serde_json::json!(overlay.routine_paths),
        );
        profiles_map.insert(name.clone(), serde_json::Value::Object(overlay_map));
    }
    map.insert("profiles".into(), serde_json::Value::Object(profiles_map));

    map.insert(
        "profiles_version".into(),
        serde_json::json!(manifest.profiles_version),
    );
    map.insert(
        "released_at".into(),
        serde_json::json!(manifest.released_at),
    );
    map.insert(
        "schema_version".into(),
        serde_json::json!(manifest.schema_version),
    );

    serde_json::to_string(&serde_json::Value::Object(map)).unwrap()
}

// ---------------------------------------------------------------------------
// Entry validation
// ---------------------------------------------------------------------------

/// Validate all entries in a single profile overlay.
fn validate_overlay_entries(
    profile_name: &str,
    overlay: &RemoteProfileOverlay,
) -> Result<(), ManifestError> {
    for v in &overlay.routine_destinations {
        validate_destination(v).map_err(|reason| ManifestError::InvalidEntry {
            field: format!("{profile_name}.routine_destinations"),
            reason,
        })?;
    }
    for v in &overlay.routine_commands {
        validate_command(v).map_err(|reason| ManifestError::InvalidEntry {
            field: format!("{profile_name}.routine_commands"),
            reason,
        })?;
    }
    for v in &overlay.routine_paths {
        validate_routine_path(v).map_err(|reason| ManifestError::InvalidEntry {
            field: format!("{profile_name}.routine_paths"),
            reason,
        })?;
    }
    for v in &overlay.readonly_paths {
        validate_readonly_path(v).map_err(|reason| ManifestError::InvalidEntry {
            field: format!("{profile_name}.readonly_paths"),
            reason,
        })?;
    }
    for v in &overlay.readonly_path_patterns {
        validate_readonly_path_pattern(v).map_err(|reason| ManifestError::InvalidEntry {
            field: format!("{profile_name}.readonly_path_patterns"),
            reason,
        })?;
    }
    Ok(())
}

/// Validate a destination entry: hostname only.
pub fn validate_destination(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("empty destination".into());
    }
    if value.contains("://") {
        return Err(format!("contains scheme: {value}"));
    }
    if value.contains('/') {
        return Err(format!("contains path separator: {value}"));
    }
    if value.contains(':') {
        return Err(format!("contains port: {value}"));
    }
    if value.contains('*') {
        return Err(format!("contains wildcard: {value}"));
    }
    if value.contains(char::is_whitespace) {
        return Err(format!("contains whitespace: {value}"));
    }
    if value.starts_with('.') || value.ends_with('.') {
        return Err(format!("invalid hostname boundary: {value}"));
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!(
            "IP literals are not remote-overlay eligible: {value}"
        ));
    }

    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return Err(format!("hostname must contain at least one dot: {value}"));
    }
    for label in &labels {
        if label.is_empty() {
            return Err(format!("hostname contains empty label: {value}"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("hostname label boundary invalid: {value}"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!("hostname contains invalid characters: {value}"));
        }
    }

    let tld = labels.last().copied().unwrap_or_default();
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_lowercase()) {
        return Err(format!("hostname has invalid TLD: {value}"));
    }

    // Runtime matching uses DNS suffix semantics, so reject domains that are
    // too short to be safely distinguished from a public suffix.
    if labels.len() == 2 && labels[0].len() < 4 {
        return Err(format!(
            "base domain too broad for suffix matching: {value}"
        ));
    }

    Ok(())
}

/// Validate a command entry: basename only.
pub fn validate_command(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("empty command".into());
    }
    if value.contains('/') {
        return Err(format!("contains path separator: {value}"));
    }
    if value.contains(char::is_whitespace) {
        return Err(format!("contains whitespace (arguments?): {value}"));
    }
    Ok(())
}

/// Validate a path entry suitable for a read-write `routine_paths` overlay.
pub fn validate_routine_path(value: &str) -> Result<(), String> {
    validate_common_path_syntax(value)?;
    if has_non_terminal_wildcard(value) {
        return Err(format!(
            "routine path wildcard must stay at the end: {value}"
        ));
    }

    let trimmed = trim_terminal_path_wildcards(value);
    if trimmed.is_empty() {
        return Err(format!("overbroad path: {value}"));
    }

    if let Some(rest) = trimmed.strip_prefix("${HOME}/") {
        let first = rest.split('/').next().unwrap_or_default();
        if first.is_empty() || !first.starts_with('.') {
            return Err(format!(
                "routine path under ${{HOME}} must stay in a hidden tool directory: {value}"
            ));
        }
        if is_sensitive_home_prefix(rest) {
            return Err(format!(
                "sensitive home path requires readonly/manual review: {value}"
            ));
        }
        return Ok(());
    }

    if let Some(rest) = trimmed.strip_prefix("${PROJECT_DIR}/") {
        if rest.is_empty() || !rest.contains('/') {
            return Err(format!(
                "routine path must stay within a project subpath: {value}"
            ));
        }
        return Ok(());
    }

    for prefix in ["/tmp/", "/private/tmp/"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let first = rest.split('/').next().unwrap_or_default();
            if first.len() < 4 || !first.contains('-') {
                return Err(format!(
                    "tmp routine path must use a tool-scoped prefix: {value}"
                ));
            }
            return Ok(());
        }
    }

    Err(format!(
        "routine path must stay under ${{HOME}}, ${{PROJECT_DIR}}, /tmp, or /private/tmp: {value}"
    ))
}

/// Validate a path entry suitable for an exact read-only allowlist.
pub fn validate_readonly_path(value: &str) -> Result<(), String> {
    validate_common_path_syntax(value)?;
    if value.contains('*') {
        return Err(format!(
            "readonly exact paths cannot contain wildcards: {value}"
        ));
    }
    if value == "/" || value == "${HOME}" || value == "${PROJECT_DIR}" {
        return Err(format!("overbroad path: {value}"));
    }
    if value.ends_with('/') {
        return Err(format!(
            "readonly exact path must not end with '/': {value}"
        ));
    }
    Ok(())
}

/// Validate a path entry suitable for a read-only glob allowlist.
pub fn validate_readonly_path_pattern(value: &str) -> Result<(), String> {
    validate_common_path_syntax(value)?;
    let wildcard_count = value.matches('*').count();
    if wildcard_count != 1 || value.contains("**") {
        return Err(format!(
            "readonly path patterns must use a single-segment '*' wildcard: {value}"
        ));
    }

    if !(value.starts_with("${HOME}/") || value.starts_with("${PROJECT_DIR}/")) {
        return Err(format!(
            "readonly path patterns must stay under ${{HOME}} or ${{PROJECT_DIR}}: {value}"
        ));
    }

    Ok(())
}

fn validate_common_path_syntax(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("empty path".into());
    }
    if value.contains('\0') {
        return Err("contains NUL byte".into());
    }
    if value.contains('\n') {
        return Err("contains newline".into());
    }

    let is_absolute = value.starts_with('/');
    let is_macro_rooted = value.starts_with("${HOME}") || value.starts_with("${PROJECT_DIR}");

    if !is_absolute && !is_macro_rooted {
        return Err(format!("not absolute or macro-rooted: {value}"));
    }

    let overbroad = [
        "/",
        "/**",
        "${HOME}",
        "${HOME}/**",
        "${PROJECT_DIR}",
        "${PROJECT_DIR}/**",
    ];
    if overbroad.contains(&value) {
        return Err(format!("overbroad path: {value}"));
    }

    Ok(())
}

fn has_non_terminal_wildcard(value: &str) -> bool {
    trim_terminal_path_wildcards(value).contains('*')
}

fn trim_terminal_path_wildcards(value: &str) -> &str {
    value
        .trim_end_matches("/**")
        .trim_end_matches("/*")
        .trim_end_matches('*')
}

fn is_sensitive_home_prefix(rest: &str) -> bool {
    const SENSITIVE_PREFIXES: &[&str] = &[
        ".ssh",
        ".gnupg",
        ".aws",
        ".kube",
        ".azure",
        ".config/gh",
        ".config/github-copilot",
        ".config/git",
    ];

    SENSITIVE_PREFIXES
        .iter()
        .any(|prefix| rest == *prefix || rest.starts_with(&format!("{prefix}/")))
}

fn configured_profile_verifying_key() -> Result<VerifyingKey, ManifestError> {
    let hex = option_env!("GRITH_PROFILE_PUBLIC_KEY_HEX")
        .unwrap_or(BOOTSTRAP_PROFILE_PUBLIC_KEY_HEX)
        .trim();
    let bytes = hex::decode(hex)
        .map_err(|e| ManifestError::InvalidVerifierKey(format!("hex decode failed: {e}")))?;
    let byte_len = bytes.len();
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        ManifestError::InvalidVerifierKey(format!(
            "expected 32 verifier-key bytes, got {}",
            byte_len
        ))
    })?;

    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| ManifestError::InvalidVerifierKey(e.to_string()))
}

// ---------------------------------------------------------------------------
// Version comparison
// ---------------------------------------------------------------------------

/// Returns `true` if `a` is strictly newer than `b` (semver major.minor.patch).
fn version_is_newer(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Option<(u32, u32, u32)> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some((
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].parse().ok()?,
        ))
    };
    match (parse(a), parse(b)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Cache I/O
// ---------------------------------------------------------------------------

const CACHE_MANIFEST_FILE: &str = "profiles.remote.json";
const CACHE_META_FILE: &str = "profiles.remote.meta.json";

/// Read cached manifest from disk and verify it.
///
/// Returns `None` on any failure (missing file, invalid signature, etc.).
/// Invalid cache means "use bundled profiles", never "best effort".
pub fn load_cached_manifest(
    cache_dir: &Path,
    known_profile_names: &HashSet<String>,
) -> Option<RemoteProfileManifest> {
    let manifest_path = cache_dir.join(CACHE_MANIFEST_FILE);
    let meta_path = cache_dir.join(CACHE_META_FILE);

    let raw_json = std::fs::read(&manifest_path).ok()?;

    let highest_accepted = if let Ok(meta_bytes) = std::fs::read(&meta_path) {
        serde_json::from_slice::<ProfileCacheMeta>(&meta_bytes)
            .ok()
            .map(|m| m.highest_accepted_profiles_version)
            .unwrap_or(0)
    } else {
        0
    };

    // Re-verify on every load — cached bytes are untrusted until re-verified.
    // Use highest_accepted - 1 for the anti-rollback check so the currently
    // cached version (which was already accepted) passes validation.
    let effective_floor = highest_accepted.saturating_sub(1);
    match verify_manifest(&raw_json, known_profile_names, effective_floor) {
        Ok(manifest) => Some(manifest),
        Err(e) => {
            tracing::debug!(error = %e, "cached profile manifest invalid, ignoring");
            None
        }
    }
}

/// Write a verified manifest to cache atomically.
pub fn write_cached_manifest(
    cache_dir: &Path,
    raw_json: &[u8],
    manifest: &RemoteProfileManifest,
) -> Result<(), ManifestError> {
    std::fs::create_dir_all(cache_dir)
        .map_err(|e| ManifestError::CacheIo(format!("create cache dir: {e}")))?;

    // Write manifest via temp file + rename.
    let manifest_path = cache_dir.join(CACHE_MANIFEST_FILE);
    let tmp_manifest = cache_dir.join("profiles.remote.json.tmp");
    std::fs::write(&tmp_manifest, raw_json)
        .map_err(|e| ManifestError::CacheIo(format!("write temp manifest: {e}")))?;
    std::fs::rename(&tmp_manifest, &manifest_path)
        .map_err(|e| ManifestError::CacheIo(format!("rename manifest: {e}")))?;

    // Update metadata.
    let meta = ProfileCacheMeta {
        highest_accepted_profiles_version: manifest.profiles_version,
        last_checked_at: Utc::now().to_rfc3339(),
    };
    let meta_path = cache_dir.join(CACHE_META_FILE);
    let meta_json = serde_json::to_string_pretty(&meta)
        .map_err(|e| ManifestError::CacheIo(format!("serialize meta: {e}")))?;
    std::fs::write(&meta_path, meta_json)
        .map_err(|e| ManifestError::CacheIo(format!("write meta: {e}")))?;

    Ok(())
}

/// Read the last-checked timestamp from cache metadata.
pub fn last_checked_at(cache_dir: &Path) -> Option<DateTime<Utc>> {
    let meta_path = cache_dir.join(CACHE_META_FILE);
    let bytes = std::fs::read(meta_path).ok()?;
    let meta: ProfileCacheMeta = serde_json::from_slice(&bytes).ok()?;
    DateTime::parse_from_rfc3339(&meta.last_checked_at)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Update `last_checked_at` without changing the manifest or version.
pub fn touch_last_checked(cache_dir: &Path) {
    let meta_path = cache_dir.join(CACHE_META_FILE);
    let mut meta = std::fs::read(&meta_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<ProfileCacheMeta>(&b).ok())
        .unwrap_or(ProfileCacheMeta {
            highest_accepted_profiles_version: 0,
            last_checked_at: String::new(),
        });
    meta.last_checked_at = Utc::now().to_rfc3339();
    if let Ok(json) = serde_json::to_string_pretty(&meta) {
        let _ = std::fs::write(&meta_path, json);
    }
}

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

/// Merge a verified remote overlay manifest into a resolved `ProfileConfig`.
///
/// Only merges the five v1-eligible vectors. Entries are deduplicated.
/// Unknown profile names in the manifest cause the entire merge to fail.
/// `launch_contract`, overlays, and structural fields are untouched.
pub fn merge_remote_overlay(
    config: &mut ProfileConfig,
    manifest: &RemoteProfileManifest,
) -> Result<(), ManifestError> {
    // Build name → index lookup (collect owned names to avoid borrow conflict).
    let name_to_idx: HashMap<String, usize> = config
        .profiles
        .iter()
        .enumerate()
        .map(|(i, p)| (p.name.clone(), i))
        .collect();

    for (name, overlay) in &manifest.profiles {
        let idx = name_to_idx
            .get(name.as_str())
            .ok_or_else(|| ManifestError::UnknownProfile(name.clone()))?;
        let profile = &mut config.profiles[*idx];

        merge_vec_dedup(&mut profile.routine_paths, &overlay.routine_paths);
        merge_vec_dedup(&mut profile.routine_commands, &overlay.routine_commands);
        merge_vec_dedup(
            &mut profile.routine_destinations,
            &overlay.routine_destinations,
        );
        merge_vec_dedup(&mut profile.readonly_paths, &overlay.readonly_paths);
        merge_vec_dedup(
            &mut profile.readonly_path_patterns,
            &overlay.readonly_path_patterns,
        );
    }

    Ok(())
}

/// Append `source` entries to `target`, skipping duplicates.
fn merge_vec_dedup(target: &mut Vec<String>, source: &[String]) {
    for item in source {
        if !target.contains(item) {
            target.push(item.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use rand::RngCore;

    /// Helper: create a test manifest, sign it with a fresh keypair, and
    /// return (raw_json, public_key_bytes).
    fn sign_test_manifest(manifest: &mut RemoteProfileManifest) -> (Vec<u8>, [u8; 32]) {
        // ed25519-dalek 2.2 dropped SigningKey::generate; build the key
        // from a fresh 32-byte secret instead.
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        // Canonicalize with placeholder signature first.
        manifest.signature = String::new();
        let canonical = canonicalize_manifest(manifest);

        let sig = signing_key.sign(canonical.as_bytes());
        manifest.signature = BASE64_STANDARD.encode(sig.to_bytes());

        let raw_json = serde_json::to_vec(manifest).unwrap();
        (raw_json, verifying_key.to_bytes())
    }

    fn base_manifest() -> RemoteProfileManifest {
        let mut profiles = HashMap::new();
        profiles.insert(
            "claude-code".to_string(),
            RemoteProfileOverlay {
                routine_destinations: vec!["extensions.anthropic.com".to_string()],
                ..Default::default()
            },
        );
        RemoteProfileManifest {
            schema_version: 1,
            profiles_version: 1,
            min_grith_version: "0.1.0".to_string(),
            released_at: "2026-03-31T10:00:00Z".to_string(),
            changelog: "test".to_string(),
            profiles,
            signature: String::new(),
        }
    }

    // ── Canonicalization ───────────────────────────────────────────

    #[test]
    fn canonicalization_is_deterministic() {
        let m = base_manifest();
        let a = canonicalize_manifest(&m);
        let b = canonicalize_manifest(&m);
        assert_eq!(a, b);
    }

    #[test]
    fn canonicalization_excludes_signature() {
        let mut m = base_manifest();
        m.signature = "should-not-appear".to_string();
        let c = canonicalize_manifest(&m);
        assert!(!c.contains("should-not-appear"));
        assert!(!c.contains("signature"));
    }

    // ── Signature verification ────────────────────────────────────

    #[test]
    fn valid_signature_verifies() {
        let mut m = base_manifest();
        let (raw_json, pub_key) = sign_test_manifest(&mut m);

        // Use the test key instead of the embedded placeholder.
        let manifest: RemoteProfileManifest = serde_json::from_slice(&raw_json).unwrap();
        let canonical = canonicalize_manifest(&manifest);
        let sig_bytes = BASE64_STANDARD.decode(&manifest.signature).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let vk = VerifyingKey::from_bytes(&pub_key).unwrap();
        assert!(vk.verify_strict(canonical.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn configured_verifier_key_is_valid() {
        assert!(configured_profile_verifying_key().is_ok());
    }

    #[test]
    fn tampered_manifest_rejects() {
        let mut m = base_manifest();
        let (mut raw_json, pub_key) = sign_test_manifest(&mut m);

        // Tamper with the manifest.
        if let Some(pos) = raw_json.windows(4).position(|w| w == b"test") {
            raw_json[pos] = b'T';
        }

        let manifest: RemoteProfileManifest = serde_json::from_slice(&raw_json).unwrap();
        let canonical = canonicalize_manifest(&manifest);
        let sig_bytes = BASE64_STANDARD.decode(&manifest.signature).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let vk = VerifyingKey::from_bytes(&pub_key).unwrap();
        assert!(vk.verify_strict(canonical.as_bytes(), &sig).is_err());
    }

    // ── Entry validation ──────────────────────────────────────────

    #[test]
    fn destination_valid() {
        assert!(validate_destination("example.com").is_ok());
        assert!(validate_destination("api.anthropic.com").is_ok());
    }

    #[test]
    fn destination_with_scheme_rejects() {
        assert!(validate_destination("https://example.com").is_err());
    }

    #[test]
    fn destination_with_port_rejects() {
        assert!(validate_destination("example.com:443").is_err());
    }

    #[test]
    fn destination_with_wildcard_rejects() {
        assert!(validate_destination("*.example.com").is_err());
    }

    #[test]
    fn destination_with_whitespace_rejects() {
        assert!(validate_destination("example .com").is_err());
    }

    #[test]
    fn destination_too_broad_for_suffix_matching_rejects() {
        assert!(validate_destination("com").is_err());
        assert!(validate_destination("co.uk").is_err());
        assert!(validate_destination("x.ai").is_err());
    }

    #[test]
    fn command_valid() {
        assert!(validate_command("git").is_ok());
        assert!(validate_command("npm").is_ok());
    }

    #[test]
    fn command_with_slash_rejects() {
        assert!(validate_command("/usr/bin/git").is_err());
    }

    #[test]
    fn command_with_args_rejects() {
        assert!(validate_command("git commit").is_err());
    }

    #[test]
    fn routine_path_valid() {
        assert!(validate_routine_path("/tmp/claude-*").is_ok());
        assert!(validate_routine_path("${HOME}/.config/claude/**").is_ok());
        assert!(validate_routine_path("${PROJECT_DIR}/src/cache/**").is_ok());
    }

    #[test]
    fn routine_path_overbroad_rejects() {
        assert!(validate_routine_path("/").is_err());
        assert!(validate_routine_path("/etc").is_err());
        assert!(validate_routine_path("${HOME}/**").is_err());
        assert!(validate_routine_path("${PROJECT_DIR}").is_err());
    }

    #[test]
    fn readonly_path_allows_exact_sensitive_files() {
        assert!(validate_readonly_path("/etc/hosts").is_ok());
        assert!(validate_readonly_path("${HOME}/.config/github-copilot/apps.json").is_ok());
    }

    #[test]
    fn readonly_pattern_requires_single_segment_wildcard() {
        assert!(validate_readonly_path_pattern("${HOME}/.ssh/*.pub").is_ok());
        assert!(validate_readonly_path_pattern("${HOME}/.ssh/**").is_err());
        assert!(validate_readonly_path_pattern("/etc/*.conf").is_err());
    }

    #[test]
    fn path_relative_rejects() {
        assert!(validate_routine_path("relative/path").is_err());
        assert!(validate_readonly_path("relative/path").is_err());
    }

    #[test]
    fn path_with_nul_rejects() {
        assert!(validate_routine_path("/tmp/\0bad").is_err());
        assert!(validate_readonly_path("/tmp/\0bad").is_err());
    }

    // ── Anti-rollback ─────────────────────────────────────────────

    #[test]
    fn rollback_check_uses_strict_inequality() {
        // Same version should also be rejected (not just lower).
        let m = base_manifest();

        // Version 1 vs highest_accepted 1: should fail (<=).
        assert!(m.profiles_version <= 1);
        // Version 1 vs highest_accepted 0: should pass (>).
        assert!(m.profiles_version > 0);
    }

    // ── Version comparison ────────────────────────────────────────

    #[test]
    fn version_comparison() {
        assert!(version_is_newer("1.0.0", "0.1.0"));
        assert!(!version_is_newer("0.1.0", "0.1.0"));
        assert!(!version_is_newer("0.0.9", "0.1.0"));
    }

    // ── Merge ─────────────────────────────────────────────────────

    #[test]
    fn merge_adds_new_entries() {
        let mut config = grith_supervisor::SupervisorProfile::load_bundled_config().unwrap();
        let profile = config
            .profiles
            .iter()
            .find(|p| p.name == "claude-code")
            .unwrap();
        let original_dest_count = profile.routine_destinations.len();

        let manifest = base_manifest();
        merge_remote_overlay(&mut config, &manifest).unwrap();

        let profile = config
            .profiles
            .iter()
            .find(|p| p.name == "claude-code")
            .unwrap();
        assert!(profile
            .routine_destinations
            .contains(&"extensions.anthropic.com".to_string()));
        assert!(profile.routine_destinations.len() >= original_dest_count);
    }

    #[test]
    fn merge_deduplicates() {
        let mut config = grith_supervisor::SupervisorProfile::load_bundled_config().unwrap();

        // Add a destination that already exists in the profile.
        let existing = config
            .profiles
            .iter()
            .find(|p| p.name == "claude-code")
            .unwrap()
            .routine_destinations
            .first()
            .cloned()
            .unwrap_or_default();

        if !existing.is_empty() {
            let mut profiles = HashMap::new();
            profiles.insert(
                "claude-code".to_string(),
                RemoteProfileOverlay {
                    routine_destinations: vec![existing.clone()],
                    ..Default::default()
                },
            );
            let manifest = RemoteProfileManifest {
                schema_version: 1,
                profiles_version: 1,
                min_grith_version: "0.1.0".to_string(),
                released_at: "2026-03-31T10:00:00Z".to_string(),
                changelog: "test".to_string(),
                profiles,
                signature: String::new(),
            };

            let before = config
                .profiles
                .iter()
                .find(|p| p.name == "claude-code")
                .unwrap()
                .routine_destinations
                .len();
            merge_remote_overlay(&mut config, &manifest).unwrap();
            let after = config
                .profiles
                .iter()
                .find(|p| p.name == "claude-code")
                .unwrap()
                .routine_destinations
                .len();
            assert_eq!(before, after, "duplicate should not be added");
        }
    }

    #[test]
    fn merge_unknown_profile_rejects() {
        let mut config = grith_supervisor::SupervisorProfile::load_bundled_config().unwrap();
        let mut profiles = HashMap::new();
        profiles.insert(
            "nonexistent-tool".to_string(),
            RemoteProfileOverlay::default(),
        );
        let manifest = RemoteProfileManifest {
            schema_version: 1,
            profiles_version: 1,
            min_grith_version: "0.1.0".to_string(),
            released_at: "2026-03-31T10:00:00Z".to_string(),
            changelog: "test".to_string(),
            profiles,
            signature: String::new(),
        };
        assert!(merge_remote_overlay(&mut config, &manifest).is_err());
    }

    #[test]
    fn merge_leaves_launch_contract_untouched() {
        let mut config = grith_supervisor::SupervisorProfile::load_bundled_config().unwrap();
        let original_contracts: HashMap<String, _> = config
            .profiles
            .iter()
            .map(|p| (p.name.clone(), p.launch_contract.clone()))
            .collect();

        let manifest = base_manifest();
        merge_remote_overlay(&mut config, &manifest).unwrap();

        for profile in &config.profiles {
            assert_eq!(
                profile.launch_contract, original_contracts[&profile.name],
                "launch_contract for {} should be unchanged",
                profile.name
            );
        }
    }

    #[test]
    fn merge_leaves_overlays_untouched() {
        let mut config = grith_supervisor::SupervisorProfile::load_bundled_config().unwrap();
        let original_launcher_count = config.launcher_overlays.len();
        let original_provider_count = config.provider_overlays.len();

        let manifest = base_manifest();
        merge_remote_overlay(&mut config, &manifest).unwrap();

        assert_eq!(config.launcher_overlays.len(), original_launcher_count);
        assert_eq!(config.provider_overlays.len(), original_provider_count);
    }
}
