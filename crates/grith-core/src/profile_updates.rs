// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Runtime profile refresh and effective profile loading.
//!
//! Fetches the latest signed remote profile overlay manifest, verifies it,
//! and caches it locally. On subsequent starts, the cached overlay is merged
//! into the bundled profile config to produce the effective session policy.
//!
//! Refresh is TTL-gated (6 hours) and fails silently — it never blocks
//! session startup or downgrades to unverified data.

use crate::profile_manifest;
use grith_supervisor::profiles::ProfileConfig;
use grith_supervisor::SupervisorProfile;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROFILE_FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const PROFILE_REFRESH_TTL_SECS: i64 = 6 * 3600; // 6 hours

/// Return the cache directory for profile overlay data.
fn cache_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("grith")
}

/// Check if a profile refresh is due and attempt it silently.
///
/// Checks the TTL, fetches the latest manifest from the API, verifies it,
/// and writes it to cache. On any failure, logs at debug level and returns
/// without error so session startup is never blocked.
pub fn maybe_refresh() {
    let cache = cache_dir();

    // Check TTL — skip if we checked recently.
    if let Some(last) = profile_manifest::last_checked_at(&cache) {
        let elapsed = chrono::Utc::now().signed_duration_since(last).num_seconds();
        if elapsed < PROFILE_REFRESH_TTL_SECS {
            tracing::debug!(
                elapsed_secs = elapsed,
                ttl_secs = PROFILE_REFRESH_TTL_SECS,
                "profile refresh not due yet"
            );
            return;
        }
    }

    // Touch last-checked even on failure so we don't retry every launch.
    profile_manifest::touch_last_checked(&cache);

    // Fetch from API.
    let api_base = crate::license::api_base_url();
    let url = format!("{api_base}/v1/profiles/latest");

    let raw_json = match fetch_manifest(&url) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::debug!(error = %e, "profile refresh: fetch failed");
            return;
        }
    };

    // Get known profile names from bundled config.
    let known_names: HashSet<String> = match SupervisorProfile::load_bundled_config() {
        Ok(cfg) => cfg.profiles.iter().map(|p| p.name.clone()).collect(),
        Err(e) => {
            tracing::debug!(error = %e, "profile refresh: bundled config unavailable");
            return;
        }
    };

    // Read current highest accepted version for anti-rollback.
    let highest = profile_manifest::last_checked_at(&cache)
        .map(|_| {
            // Re-read meta for version.
            std::fs::read(cache.join("profiles.remote.meta.json"))
                .ok()
                .and_then(|b| serde_json::from_slice::<profile_manifest::ProfileCacheMeta>(&b).ok())
                .map(|m| m.highest_accepted_profiles_version)
                .unwrap_or(0)
        })
        .unwrap_or(0);

    // Verify.
    let manifest = match profile_manifest::verify_manifest(&raw_json, &known_names, highest) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(error = %e, "profile refresh: verification failed");
            return;
        }
    };

    // Cache.
    if let Err(e) = profile_manifest::write_cached_manifest(&cache, &raw_json, &manifest) {
        tracing::debug!(error = %e, "profile refresh: cache write failed");
        return;
    }

    tracing::info!(
        version = manifest.profiles_version,
        "updated supervisor profiles to v{}",
        manifest.profiles_version
    );
}

/// Fetch manifest bytes from the API endpoint.
fn fetch_manifest(url: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(PROFILE_FETCH_TIMEOUT)
        .user_agent(format!("grith-cli/{CURRENT_VERSION}"))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let resp = client
        .get(url)
        .send()
        .map_err(|e| format!("request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("API returned {}", resp.status()));
    }

    resp.bytes()
        .map(|b| b.to_vec())
        .map_err(|e| format!("read body: {e}"))
}

/// Load profiles with the full resolution order:
///
/// 1. Bundled profiles (embedded in binary)
/// 2. Filesystem override (for development)
/// 3. Cached verified remote overlay (merged additively)
///
/// This is the preferred replacement for `SupervisorProfile::load_config()`
/// in all session-starting code paths.
pub fn load_effective_profiles() -> Result<ProfileConfig, anyhow::Error> {
    let mut config = SupervisorProfile::load_config()?;

    let cache = cache_dir();
    let known_names: HashSet<String> = config.profiles.iter().map(|p| p.name.clone()).collect();

    if let Some(manifest) = profile_manifest::load_cached_manifest(&cache, &known_names) {
        if let Err(e) = profile_manifest::merge_remote_overlay(&mut config, &manifest) {
            tracing::debug!(error = %e, "remote overlay merge failed, using bundled profiles");
        }
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_effective_profiles_succeeds_without_cache() {
        // Should succeed using bundled profiles when no cache exists.
        let config = load_effective_profiles().expect("should load effective profiles");
        assert!(!config.profiles.is_empty());
    }

    #[test]
    fn cache_dir_is_reasonable() {
        let dir = cache_dir();
        let dir_str = dir.to_string_lossy();
        assert!(
            dir_str.contains("grith"),
            "cache dir should contain 'grith': {dir_str}"
        );
    }
}
