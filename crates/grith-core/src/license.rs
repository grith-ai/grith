// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! License key validation and plan tier resolution.
//!
//! Verifies Ed25519-signed license keys issued by the grith.ai website,
//! extracts plan metadata, and controls feature gating (e.g. enterprise
//! notification channels, extended retention).

use base64::prelude::*;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Ed25519 public key for license signature verification.
/// Derived from the private key seed stored in the website's LICENSE_PRIVATE_KEY env var.
const LICENSE_PUBLIC_KEY: [u8; 32] = [
    0x57, 0xcc, 0xcf, 0x88, 0x23, 0x59, 0x57, 0xe7, 0x0b, 0xdd, 0x8d, 0x8f, 0xd9, 0xb8, 0x13, 0xdb,
    0xbd, 0xaa, 0xc6, 0xb6, 0x59, 0x4f, 0x29, 0x37, 0xe9, 0x23, 0xa0, 0xa2, 0x3b, 0x4a, 0x35, 0x45,
];

/// Default base URL for the grith cloud API. Points at the dedicated API host
/// (api.grith.ai, the Hono service) rather than the marketing site: the daemon
/// only ever calls machine endpoints (`/api/license`, `/api/sync`,
/// `/api/device*`), which are served there. Overridable via `GRITH_API_BASE_URL`.
const DEFAULT_API_BASE_URL: &str = "https://api.grith.ai";

/// Default base URL for the grith web app (marketing site + dashboard). Human
/// pages (dashboard, billing, pricing) live here, NOT on the API host.
/// Overridable via `GRITH_WEB_BASE_URL` (e.g. `https://dev.grith.ai` pre-launch
/// while grith.ai is in holding mode).
const DEFAULT_WEB_BASE_URL: &str = "https://grith.ai";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const NATIVE_CREDENTIAL_SERVICE: &str = "ai.grith.cli";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const NATIVE_CREDENTIAL_ACCOUNT: &str = "default";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Signed license as received from the server (JSON on disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicense {
    pub version: u32,
    pub license_id: String,
    pub user_id: String,
    pub team_id: String,
    pub email: String,
    pub plan: String,
    pub seats: u32,
    pub features: Vec<String>,
    pub issued_at: String,
    pub valid_until: String,
    #[serde(default)]
    pub billing_portal_url: Option<String>,
    /// Air-gapped enterprise contract licence. When true, the daemon
    /// disables scheduled refresh and uses extended grace windows.
    ///
    /// `None` means a legacy payload omitted the field and must be
    /// canonicalized without it. New server-issued payloads must include
    /// `Some(false)` or `Some(true)` so the field remains covered by the
    /// signature after the licence is persisted locally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub air_gapped: Option<bool>,
    pub signature: String,
}

/// Verified license with parsed dates.
///
/// All fields are populated during verification. Some fields (version, license_id,
/// seats, issued_at) are not yet consumed but are part of the public API contract
/// and will be used by future feature-gating and audit trail logic.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct License {
    pub version: u32,
    pub license_id: String,
    pub user_id: String,
    pub team_id: String,
    pub email: String,
    pub plan: String,
    /// Seat count from the license. Enforced via `FeatureGate::max_sessions()`
    /// which limits concurrent supervisor sessions based on `seats × tier_multiplier`.
    pub seats: u32,
    pub features: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub billing_portal_url: Option<String>,
    pub air_gapped: bool,
}

/// Result of evaluating a license against the current time.
#[derive(Debug, Clone)]
pub enum LicenseStatus {
    /// Valid license, full Pro features.
    Valid(License),
    /// Expired within the soft grace window. Pro features + warning.
    /// Default licences: 1 day. Air-gapped contract licences: 7 days.
    GracePeriod { license: License, expired_days: i64 },
    /// Expired within the extended grace window. Pro features + strong warning.
    /// Default licences: 1–3 days. Air-gapped contract licences: 7–30 days.
    ExtendedGrace { license: License, expired_days: i64 },
    /// Expired beyond the extended grace window. Downgrade to Community.
    Expired,
    /// No license file found.
    NotFound,
    /// License file exists but is invalid.
    Invalid(String),
}

/// Stored CLI credentials.
///
/// Linux/other: `~/.config/grith/credentials.json`
/// macOS/Windows: native credential store (Keychain/Credential Manager)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub user_id: String,
    pub api_key: String,
    pub team_id: String,
    pub license_file: String,
    pub activated_at: String,
    pub last_validated: String,
    #[serde(default)]
    pub last_synced: Option<String>,
}

/// Response from `POST /api/device` to start browser-based device authorization.
#[derive(Debug, Deserialize)]
pub struct DeviceAuthStartResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// Response from `POST /api/device/poll` once device authorization succeeds.
#[derive(Debug, Deserialize)]
pub struct DeviceAuthPollSuccessResponse {
    pub api_key: String,
    pub license: SignedLicense,
}

/// Poll status for device authorization.
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceAuthPollStatus {
    Pending,
    Expired,
    Approved,
    /// The user authorized successfully but their team has no active
    /// license (expired trial, lapsed subscription, or community plan).
    NoActiveLicense,
}

/// API response from the policy fetch endpoint. All fields required for deserialization.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PolicyResponse {
    pub name: String,
    pub version: i32,
    pub content: serde_json::Value,
    pub created_at: String,
}

/// API response from the shared config fetch endpoint. All fields required for deserialization.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ConfigResponse {
    pub name: String,
    pub config: serde_json::Value,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// API response from the learned-rules sync endpoint.
#[derive(Debug, serde::Serialize, Deserialize)]
pub struct LearnedRuleResponse {
    pub pattern: String,
    pub profile: String,
    pub scope: String,
    pub reason: String,
    pub created_by: String,
    pub created_at: String,
}

/// API response from the provider key sync endpoint.
#[derive(Debug, Deserialize)]
pub struct ProviderKeyResponse {
    pub provider: String,
    pub label: String,
    pub key: String,
}

/// API response from the license validation endpoint. All fields required for deserialization.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ValidateResponse {
    pub valid: bool,
    pub license: Option<SignedLicense>,
    pub reason: Option<String>,
}

/// Re-export of the daemon's licence-refresh state types from `grith-digest`,
/// where they live alongside [`FeatureGate`] so both `grith-core` (writer) and
/// `grith-server` (reader) can share them without a cyclic dependency.
pub use grith_digest::notification::{RefreshFailureKind, RefreshState};

#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid base64 in signature: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid date format: {0}")]
    InvalidDate(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    Http(String),
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[error("credential store error: {0}")]
    Storage(String),
    #[error("crypto error: {0}")]
    CryptoError(String),
}

/// Resolve API base URL from `GRITH_API_BASE_URL` or default.
pub fn api_base_url() -> String {
    std::env::var("GRITH_API_BASE_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
}

/// Build a full API URL from the configured base URL.
pub(crate) fn api_url(path: &str) -> String {
    format!("{}/{}", api_base_url(), path.trim_start_matches('/'))
}

/// Resolve the web app base URL from `GRITH_WEB_BASE_URL` or default. Distinct
/// from [`api_base_url`]: human-facing pages (dashboard, billing, pricing) are
/// served by the web app (grith.ai), not the API host (api.grith.ai).
pub fn web_base_url() -> String {
    std::env::var("GRITH_WEB_BASE_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_WEB_BASE_URL.to_string())
}

// ---------------------------------------------------------------------------
// License verification
// ---------------------------------------------------------------------------

/// Verify a signed license against the embedded public key.
/// Returns a parsed `License` if the signature is valid.
///
/// Backward-compatible verification: payloads that include `air_gapped` are
/// verified with that field in the canonical message, while legacy payloads
/// that omit it are verified with the old canonical field set.
pub fn verify_license(bytes: &[u8]) -> Result<License, LicenseError> {
    let raw: serde_json::Value = serde_json::from_slice(bytes)?;
    let has_air_gapped_in_payload = raw.get("air_gapped").is_some();
    let signed: SignedLicense = serde_json::from_value(raw)?;

    let sig_bytes = BASE64_STANDARD.decode(&signed.signature)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| LicenseError::InvalidSignature)?;

    let verifying_key = VerifyingKey::from_bytes(&LICENSE_PUBLIC_KEY)
        .map_err(|_| LicenseError::InvalidPublicKey)?;

    let canonical = canonicalize_payload(&signed, has_air_gapped_in_payload);
    verifying_key
        .verify_strict(canonical.as_bytes(), &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    // Parse dates.
    let issued_at = DateTime::parse_from_rfc3339(&signed.issued_at)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| LicenseError::InvalidDate(e.to_string()))?;
    let valid_until = DateTime::parse_from_rfc3339(&signed.valid_until)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| LicenseError::InvalidDate(e.to_string()))?;

    Ok(License {
        version: signed.version,
        license_id: signed.license_id,
        user_id: signed.user_id,
        team_id: signed.team_id,
        email: signed.email,
        plan: signed.plan,
        seats: signed.seats,
        features: signed.features,
        issued_at,
        valid_until,
        billing_portal_url: signed.billing_portal_url,
        air_gapped: signed.air_gapped.unwrap_or(false),
    })
}

/// Canonicalize a signed license payload for signature verification.
/// Reproduces TypeScript's `JSON.stringify(payload, Object.keys(payload).sort())`.
///
/// `include_air_gapped` controls backward compatibility: legacy payloads
/// (signed before the field existed) must canonicalize without it, while
/// new payloads include `air_gapped` in the alphabetical key order.
fn canonicalize_payload(signed: &SignedLicense, include_air_gapped: bool) -> String {
    let mut map = serde_json::Map::new();
    if include_air_gapped {
        map.insert(
            "air_gapped".into(),
            serde_json::json!(signed.air_gapped.unwrap_or(false)),
        );
    }
    map.insert("email".into(), serde_json::json!(signed.email));
    map.insert("features".into(), serde_json::json!(signed.features));
    map.insert("issued_at".into(), serde_json::json!(signed.issued_at));
    map.insert("license_id".into(), serde_json::json!(signed.license_id));
    map.insert("plan".into(), serde_json::json!(signed.plan));
    map.insert("seats".into(), serde_json::json!(signed.seats));
    map.insert("team_id".into(), serde_json::json!(signed.team_id));
    map.insert("user_id".into(), serde_json::json!(signed.user_id));
    map.insert("valid_until".into(), serde_json::json!(signed.valid_until));
    map.insert("version".into(), serde_json::json!(signed.version));
    serde_json::to_string(&serde_json::Value::Object(map)).unwrap()
}

/// Soft grace window (Pro features + warning) for default licences, in days.
const GRACE_PERIOD_DAYS_DEFAULT: i64 = 1;
/// Extended grace window (Pro features + strong warning) for default licences, in days.
const EXTENDED_GRACE_DAYS_DEFAULT: i64 = 3;
/// Soft grace window for air-gapped contract licences, in days.
const GRACE_PERIOD_DAYS_AIR_GAPPED: i64 = 7;
/// Extended grace window for air-gapped contract licences, in days.
const EXTENDED_GRACE_DAYS_AIR_GAPPED: i64 = 30;

/// Evaluate a verified license against the current time.
///
/// Default licences refresh every 24h, so grace windows are tight (1 day soft,
/// 3 day extended). Air-gapped contract licences cannot refresh, so they use
/// the legacy generous windows (7 day soft, 30 day extended).
pub fn evaluate_license(license: &License) -> LicenseStatus {
    let now = Utc::now();
    if license.valid_until >= now {
        return LicenseStatus::Valid(license.clone());
    }

    let (soft, extended) = if license.air_gapped {
        (GRACE_PERIOD_DAYS_AIR_GAPPED, EXTENDED_GRACE_DAYS_AIR_GAPPED)
    } else {
        (GRACE_PERIOD_DAYS_DEFAULT, EXTENDED_GRACE_DAYS_DEFAULT)
    };

    let expired_days = (now - license.valid_until).num_days();
    if expired_days < soft {
        LicenseStatus::GracePeriod {
            license: license.clone(),
            expired_days,
        }
    } else if expired_days <= extended {
        LicenseStatus::ExtendedGrace {
            license: license.clone(),
            expired_days,
        }
    } else {
        LicenseStatus::Expired
    }
}

/// Load and verify a license file from disk.
pub fn load_license(path: &Path) -> LicenseStatus {
    if !path.exists() {
        return LicenseStatus::NotFound;
    }
    match std::fs::read(path) {
        Ok(bytes) => match verify_license(&bytes) {
            Ok(license) => evaluate_license(&license),
            Err(e) => LicenseStatus::Invalid(e.to_string()),
        },
        Err(e) => LicenseStatus::Invalid(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Feature gating
// ---------------------------------------------------------------------------

/// Re-export from grith-digest for convenience.
pub use grith_digest::notification::{FeatureGate, PlanTier};

/// Build a [`FeatureGate`] from the evaluated license status.
pub fn feature_gate_from_status(status: &LicenseStatus) -> FeatureGate {
    match status {
        LicenseStatus::Valid(lic)
        | LicenseStatus::GracePeriod { license: lic, .. }
        | LicenseStatus::ExtendedGrace { license: lic, .. } => {
            let tier = match lic.plan.as_str() {
                "enterprise" => PlanTier::Enterprise,
                "pro" | "pro_trial" => PlanTier::Pro,
                _ => PlanTier::Community,
            };
            FeatureGate {
                tier,
                seats: lic.seats.max(1),
            }
        }
        _ => FeatureGate {
            tier: PlanTier::Community,
            seats: 1,
        },
    }
}

/// Determine the config plan_tier string from a license status.
pub fn plan_tier_from_status(status: &LicenseStatus) -> &str {
    match status {
        LicenseStatus::Valid(lic)
        | LicenseStatus::GracePeriod { license: lic, .. }
        | LicenseStatus::ExtendedGrace { license: lic, .. } => match lic.plan.as_str() {
            "pro" | "pro_trial" => "pro",
            "enterprise" => "enterprise",
            _ => "community",
        },
        _ => "community",
    }
}

/// Days until expiry (negative = already expired).
pub fn days_until_expiry(license: &License) -> i64 {
    (license.valid_until - Utc::now()).num_days()
}

/// Hours until expiry (negative = already expired).
#[allow(dead_code)]
pub fn hours_until_expiry(license: &License) -> i64 {
    (license.valid_until - Utc::now()).num_hours()
}

/// Billing portal URL from a current license status, if provided by metadata.
pub fn billing_portal_url_from_status(status: &LicenseStatus) -> Option<String> {
    match status {
        LicenseStatus::Valid(lic)
        | LicenseStatus::GracePeriod { license: lic, .. }
        | LicenseStatus::ExtendedGrace { license: lic, .. } => lic.billing_portal_url.clone(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Credential I/O
// ---------------------------------------------------------------------------

/// Default config directory: ~/.config/grith/
pub(crate) fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("grith")
}

/// Credentials file path: ~/.config/grith/credentials.json
pub fn credentials_path() -> PathBuf {
    config_dir().join("credentials.json")
}

/// License file path: ~/.config/grith/license.key
pub fn license_path() -> PathBuf {
    config_dir().join("license.key")
}

/// Policies directory: ~/.config/grith/policies/
pub fn policies_dir() -> PathBuf {
    config_dir().join("policies")
}

/// Shared configs directory: ~/.config/grith/configs/
pub fn configs_dir() -> PathBuf {
    config_dir().join("configs")
}

/// Provider keys directory: ~/.config/grith/provider-keys/
pub fn provider_keys_dir() -> PathBuf {
    config_dir().join("provider-keys")
}

/// A provider key file written during reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderKeyFile {
    pub provider: String,
    pub label: String,
    pub path: PathBuf,
}

/// Summary of a provider-key reconciliation pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderKeyReconcileReport {
    pub written: Vec<ProviderKeyFile>,
    pub revoked: Vec<PathBuf>,
    pub skipped_unsafe: usize,
}

pub(crate) fn sanitize_sync_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut out = String::with_capacity(trimmed.len());
    let mut last_dash = false;
    for ch in trimmed.chars() {
        let mapped = match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => ch,
            _ => '-',
        };
        if mapped == '-' {
            if !last_dash {
                out.push(mapped);
            }
            last_dash = true;
        } else {
            out.push(mapped);
            last_dash = false;
        }
    }

    let out = out.trim_matches('-').trim_matches('_').to_string();
    if out.is_empty() {
        None
    } else {
        Some(out.chars().take(96).collect())
    }
}

pub(crate) fn provider_file_name(provider: &str, label: &str, index: usize) -> Option<String> {
    let provider = sanitize_sync_name(provider)?;
    if index == 1 {
        return Some(format!("{provider}.json"));
    }
    let label = sanitize_sync_name(label).unwrap_or_else(|| format!("key-{index}"));
    Some(format!("{provider}--{label}-{index}.json"))
}

/// Reconcile the provider-key directory against the latest server response.
///
/// This is intentionally shared by both `grith pro sync` and the daemon's
/// background refresh path so revocation cleanup, filename hardening, and
/// encryption-at-rest stay identical.
pub fn reconcile_provider_key_files(
    api_key: &str,
    dir: &Path,
    keys: &[ProviderKeyResponse],
) -> Result<ProviderKeyReconcileReport, LicenseError> {
    std::fs::create_dir_all(dir)?;

    let mut existing_files: HashSet<PathBuf> = HashSet::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                existing_files.insert(path);
            }
        }
    }

    let mut report = ProviderKeyReconcileReport::default();
    let mut provider_counts: HashMap<String, usize> = HashMap::new();

    for key in keys {
        let provider_slug = match sanitize_sync_name(&key.provider) {
            Some(v) => v,
            None => {
                report.skipped_unsafe += 1;
                tracing::warn!(
                    provider = %key.provider,
                    "skipping provider key with unsafe provider name"
                );
                continue;
            }
        };
        let count = provider_counts.entry(provider_slug.clone()).or_insert(0);
        *count += 1;

        let Some(file_name) = provider_file_name(&provider_slug, &key.label, *count) else {
            report.skipped_unsafe += 1;
            tracing::warn!(
                provider = %key.provider,
                label = %key.label,
                "skipping provider key with unsafe file name"
            );
            continue;
        };
        let key_path = dir.join(file_name);

        let plaintext = serde_json::to_vec(&serde_json::json!({
            "provider": key.provider,
            "label": key.label,
            "key": key.key
        }))?;
        let encrypted = encrypt_provider_key(api_key, &key.provider, &plaintext)?;

        std::fs::write(&key_path, &encrypted)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }

        existing_files.remove(&key_path);
        report.written.push(ProviderKeyFile {
            provider: key.provider.clone(),
            label: key.label.clone(),
            path: key_path,
        });
    }

    let mut revoked: Vec<PathBuf> = existing_files.into_iter().collect();
    revoked.sort();
    for stale in &revoked {
        std::fs::remove_file(stale)?;
        tracing::info!(path = %stale.display(), "removed revoked provider key");
    }
    report.revoked = revoked;

    Ok(report)
}

// ---------------------------------------------------------------------------
// Provider Key Encryption
// ---------------------------------------------------------------------------

/// Derive a 256-bit AES-GCM encryption key from the user's Grith API key
/// using HKDF-SHA256. This avoids requiring a passphrase or OS keyring.
pub fn derive_provider_key_encryption_key(api_key: &str) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let salt = b"grith-prov-key-v1"; // fixed salt
    let info = b"provider-key-file-encryption";
    let hk = Hkdf::<Sha256>::new(Some(salt), api_key.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Encrypt a provider key payload and return the JSON envelope as bytes.
///
/// Envelope format: `{"version":1,"nonce":"<b64>","ciphertext":"<b64>","provider":"<name>"}`
pub fn encrypt_provider_key(
    api_key: &str,
    provider: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, LicenseError> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use rand::RngCore;

    let derived = derive_provider_key_encryption_key(api_key);
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|e| LicenseError::CryptoError(format!("AES-GCM init: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| LicenseError::CryptoError(format!("AES-GCM encrypt: {e}")))?;

    let envelope = serde_json::json!({
        "version": 1,
        "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes),
        "ciphertext": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ciphertext),
        "provider": provider,
    });

    serde_json::to_vec_pretty(&envelope)
        .map_err(|e| LicenseError::CryptoError(format!("envelope serialize: {e}")))
}

/// Decrypt a provider key envelope. Returns the original JSON payload bytes.
pub fn decrypt_provider_key(api_key: &str, envelope_json: &[u8]) -> Result<Vec<u8>, LicenseError> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let envelope: serde_json::Value = serde_json::from_slice(envelope_json)
        .map_err(|e| LicenseError::CryptoError(format!("envelope parse: {e}")))?;

    // Check for encrypted envelope marker
    if envelope.get("version").and_then(|v| v.as_u64()) != Some(1) {
        return Err(LicenseError::CryptoError(
            "not an encrypted envelope (missing version:1)".into(),
        ));
    }

    let nonce_b64 = envelope
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LicenseError::CryptoError("missing nonce".into()))?;
    let ct_b64 = envelope
        .get("ciphertext")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LicenseError::CryptoError("missing ciphertext".into()))?;

    let nonce_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, nonce_b64)
        .map_err(|e| LicenseError::CryptoError(format!("nonce decode: {e}")))?;
    let ciphertext = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ct_b64)
        .map_err(|e| LicenseError::CryptoError(format!("ciphertext decode: {e}")))?;

    if nonce_bytes.len() != 12 {
        return Err(LicenseError::CryptoError(format!(
            "nonce must be 12 bytes, got {}",
            nonce_bytes.len()
        )));
    }

    let derived = derive_provider_key_encryption_key(api_key);
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|e| LicenseError::CryptoError(format!("AES-GCM init: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| LicenseError::CryptoError(format!("AES-GCM decrypt: {e}")))
}

/// Check if a file contains an encrypted provider key envelope (has "version" and "ciphertext").
pub fn is_encrypted_envelope(data: &[u8]) -> bool {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        v.get("version").and_then(|v| v.as_u64()) == Some(1) && v.get("ciphertext").is_some()
    } else {
        false
    }
}

fn load_credentials_file() -> Result<Option<Credentials>, LicenseError> {
    let path = credentials_path();
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)?;
    let creds: Credentials = serde_json::from_str(&data)?;
    Ok(Some(creds))
}

fn save_credentials_file(creds: &Credentials) -> Result<(), LicenseError> {
    let path = credentials_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(creds)?;
    std::fs::write(&path, data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn remove_credentials_file() -> Result<(), LicenseError> {
    let creds = credentials_path();
    if creds.exists() {
        std::fs::remove_file(&creds)?;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn native_credential_entry() -> Result<keyring::Entry, LicenseError> {
    keyring::Entry::new(NATIVE_CREDENTIAL_SERVICE, NATIVE_CREDENTIAL_ACCOUNT)
        .map_err(|e| LicenseError::Storage(e.to_string()))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn load_credentials_native() -> Result<Option<Credentials>, LicenseError> {
    let entry = native_credential_entry()?;
    match entry.get_password() {
        Ok(payload) => {
            let creds = serde_json::from_str::<Credentials>(&payload)?;
            Ok(Some(creds))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(LicenseError::Storage(e.to_string())),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn save_credentials_native(creds: &Credentials) -> Result<(), LicenseError> {
    let payload = serde_json::to_string(creds)?;
    let entry = native_credential_entry()?;
    entry
        .set_password(&payload)
        .map_err(|e| LicenseError::Storage(e.to_string()))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn remove_credentials_native() -> Result<(), LicenseError> {
    let entry = native_credential_entry()?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(LicenseError::Storage(e.to_string())),
    }
}

/// Load credentials from native secure storage on macOS/Windows, falling back
/// to file-based storage for Linux and migration.
pub fn load_credentials() -> Result<Option<Credentials>, LicenseError> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        if let Some(creds) = load_credentials_native()? {
            return Ok(Some(creds));
        }

        // One-time migration path for older file-based credentials.
        if let Some(creds) = load_credentials_file()? {
            if save_credentials_native(&creds).is_ok() {
                let _ = remove_credentials_file();
            }
            return Ok(Some(creds));
        }

        return Ok(None);
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        load_credentials_file()
    }
}

/// Save credentials to native secure storage on macOS/Windows, file-based
/// storage on Linux/other.
pub fn save_credentials(creds: &Credentials) -> Result<(), LicenseError> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        save_credentials_native(creds)?;
        // Remove legacy file copy if present.
        let _ = remove_credentials_file();
        return Ok(());
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        save_credentials_file(creds)
    }
}

/// Save a signed license to the license file.
///
/// Writes atomically: serialize to a sibling temp file, fsync, then rename
/// over the destination so a crash mid-write cannot leave a truncated or
/// half-written licence file. Permissions are restricted to 0600 on Unix.
pub fn save_license(license: &SignedLicense) -> Result<PathBuf, LicenseError> {
    let path = license_path();
    save_license_to(license, &path)?;
    Ok(path)
}

/// Atomically save a signed license to the given path. Used by the daemon
/// background refresh and unit tests. Public for cross-crate testability.
pub fn save_license_to(license: &SignedLicense, path: &Path) -> Result<(), LicenseError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(license)?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("license.key");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp_name = format!(".{file_name}.{pid}.{nanos}.tmp");
    let tmp_path = match path.parent() {
        Some(parent) => parent.join(tmp_name),
        None => PathBuf::from(tmp_name),
    };

    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)?;
        file.write_all(data.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
    }

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(LicenseError::Io(e));
    }

    Ok(())
}

/// Remove credentials and license files.
pub fn remove_credentials() -> Result<(), LicenseError> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        remove_credentials_native()?;
    }

    remove_credentials_file()?;

    let lic = license_path();
    if lic.exists() {
        std::fs::remove_file(&lic)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP client functions
// ---------------------------------------------------------------------------

fn build_client() -> Result<reqwest::Client, LicenseError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(format!("grith-cli/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| LicenseError::Http(e.to_string()))
}

/// Fetch the license from the server.
pub async fn fetch_license(api_key: &str) -> Result<SignedLicense, LicenseError> {
    let client = build_client()?;
    let resp = client
        .get(api_url("/api/license"))
        .header("x-grith-api-key", api_key)
        .send()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(LicenseError::Http(format!("{status}: {body}")));
    }

    resp.json::<SignedLicense>()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))
}

/// Validate and refresh the license with the server.
pub async fn validate_license_remote(
    creds: &Credentials,
) -> Result<ValidateResponse, LicenseError> {
    let client = build_client()?;
    let resp = client
        .post(api_url("/api/license/validate"))
        .header("x-grith-api-key", &creds.api_key)
        .send()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(LicenseError::Http(format!("{status}: {body}")));
    }

    resp.json::<ValidateResponse>()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))
}

/// Fetch the latest team policy from the server.
pub async fn fetch_policies(creds: &Credentials) -> Result<PolicyResponse, LicenseError> {
    let client = build_client()?;
    let resp = client
        .get(api_url("/api/sync/policies"))
        .header("x-grith-api-key", &creds.api_key)
        .send()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(LicenseError::Http(format!("{status}: {body}")));
    }

    resp.json::<PolicyResponse>()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))
}

/// Fetch all shared configs for the user's team.
pub async fn fetch_configs(creds: &Credentials) -> Result<Vec<ConfigResponse>, LicenseError> {
    let client = build_client()?;
    let resp = client
        .get(api_url("/api/sync/configs"))
        .header("x-grith-api-key", &creds.api_key)
        .send()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(LicenseError::Http(format!("{status}: {body}")));
    }

    resp.json::<Vec<ConfigResponse>>()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))
}

/// Push reputation entries to the team backend.
pub async fn sync_reputation(
    creds: &Credentials,
    entries: Vec<serde_json::Value>,
) -> Result<usize, LicenseError> {
    let client = build_client()?;
    let resp = client
        .post(api_url("/api/sync/reputation"))
        .header("x-grith-api-key", &creds.api_key)
        .json(&serde_json::json!({ "entries": entries }))
        .send()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(LicenseError::Http(format!("{status}: {body}")));
    }

    #[derive(Deserialize)]
    struct SyncResult {
        synced: usize,
    }
    let result = resp
        .json::<SyncResult>()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))?;
    Ok(result.synced)
}

/// Fetch learned rules for the user's team.
pub async fn fetch_learned_rules(
    creds: &Credentials,
) -> Result<Vec<LearnedRuleResponse>, LicenseError> {
    let client = build_client()?;
    let resp = client
        .get(api_url("/api/sync/learned-rules"))
        .header("x-grith-api-key", &creds.api_key)
        .send()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(LicenseError::Http(format!("{status}: {body}")));
    }

    resp.json::<Vec<LearnedRuleResponse>>()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))
}

/// Fetch decrypted provider keys for the user's team.
pub async fn fetch_provider_keys(
    creds: &Credentials,
) -> Result<Vec<ProviderKeyResponse>, LicenseError> {
    let client = build_client()?;
    let resp = client
        .get(api_url("/api/sync/provider-keys"))
        .header("x-grith-api-key", &creds.api_key)
        .send()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(LicenseError::Http(format!("{status}: {body}")));
    }

    resp.json::<Vec<ProviderKeyResponse>>()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))
}

/// Start browser-based device authorization.
pub async fn start_device_authorization() -> Result<DeviceAuthStartResponse, LicenseError> {
    let client = build_client()?;
    let resp = client
        .post(api_url("/api/device"))
        .send()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(LicenseError::Http(format!("{status}: {body}")));
    }

    resp.json::<DeviceAuthStartResponse>()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))
}

/// Poll browser-based device authorization status.
pub async fn poll_device_authorization(
    device_code: &str,
) -> Result<(DeviceAuthPollStatus, Option<DeviceAuthPollSuccessResponse>), LicenseError> {
    let client = build_client()?;
    let resp = client
        .post(api_url("/api/device/poll"))
        .json(&serde_json::json!({ "device_code": device_code }))
        .send()
        .await
        .map_err(|e| LicenseError::Http(e.to_string()))?;

    match resp.status().as_u16() {
        200 => {
            let success = resp
                .json::<DeviceAuthPollSuccessResponse>()
                .await
                .map_err(|e| LicenseError::Http(e.to_string()))?;
            Ok((DeviceAuthPollStatus::Approved, Some(success)))
        }
        428 => Ok((DeviceAuthPollStatus::Pending, None)),
        410 => Ok((DeviceAuthPollStatus::Expired, None)),
        404 => {
            // The server distinguishes "no team" / "no active license" from
            // transport-level 404s via the error code in the body. Both mean
            // the sign-in itself worked but there is no entitlement to issue.
            let body = resp.text().await.unwrap_or_default();
            if body.contains("no_active_license") || body.contains("no_team_found") {
                Ok((DeviceAuthPollStatus::NoActiveLicense, None))
            } else {
                Err(LicenseError::Http(format!("404 Not Found: {body}")))
            }
        }
        _ => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(LicenseError::Http(format!("{status}: {body}")))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_canonicalize_payload_legacy() {
        let signed = SignedLicense {
            version: 1,
            license_id: "lic_test".into(),
            user_id: "user_1".into(),
            team_id: "team_1".into(),
            email: "test@example.com".into(),
            plan: "pro_trial".into(),
            seats: 1,
            features: vec!["team_dashboard".into()],
            issued_at: "2026-02-12T00:00:00.000Z".into(),
            valid_until: "2026-02-26T00:00:00.000Z".into(),
            billing_portal_url: None,
            air_gapped: None,
            signature: "test".into(),
        };
        let canonical = canonicalize_payload(&signed, false);
        // Keys must be in alphabetical order.
        let parsed: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "keys must be alphabetically sorted");
        // Must not contain 'signature' or 'air_gapped' for legacy.
        assert!(!canonical.contains("signature"));
        assert!(!canonical.contains("air_gapped"));
    }

    #[test]
    fn test_canonicalize_payload_with_air_gapped() {
        let signed = SignedLicense {
            version: 1,
            license_id: "lic_test".into(),
            user_id: "user_1".into(),
            team_id: "team_1".into(),
            email: "test@example.com".into(),
            plan: "enterprise".into(),
            seats: 5,
            features: vec!["team_dashboard".into()],
            issued_at: "2026-02-12T00:00:00.000Z".into(),
            valid_until: "2027-02-12T00:00:00.000Z".into(),
            billing_portal_url: None,
            air_gapped: Some(true),
            signature: "test".into(),
        };
        let canonical = canonicalize_payload(&signed, true);
        let parsed: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "keys must be alphabetically sorted");
        // air_gapped must be the first key (alphabetically) when present.
        assert_eq!(keys.first().map(|s| s.as_str()), Some("air_gapped"));
        assert!(canonical.contains("\"air_gapped\":true"));
    }

    #[test]
    fn test_canonicalize_payload_with_air_gapped_false() {
        let signed = SignedLicense {
            version: 1,
            license_id: "lic_test".into(),
            user_id: "user_1".into(),
            team_id: "team_1".into(),
            email: "test@example.com".into(),
            plan: "pro".into(),
            seats: 1,
            features: vec![],
            issued_at: "2026-02-12T00:00:00.000Z".into(),
            valid_until: "2026-02-19T00:00:00.000Z".into(),
            billing_portal_url: None,
            air_gapped: Some(false),
            signature: "test".into(),
        };
        let canonical = canonicalize_payload(&signed, true);
        assert!(canonical.contains("\"air_gapped\":false"));
    }

    #[test]
    fn test_evaluate_license_valid() {
        let future = Utc::now() + chrono::Duration::days(14);
        let lic = License {
            version: 1,
            license_id: "lic_test".into(),
            user_id: "u".into(),
            team_id: "t".into(),
            email: "e@e.com".into(),
            plan: "pro".into(),
            seats: 1,
            features: vec![],
            issued_at: Utc::now(),
            valid_until: future,
            billing_portal_url: None,
            air_gapped: false,
        };
        assert!(matches!(evaluate_license(&lic), LicenseStatus::Valid(_)));
    }

    fn license_expired_by(hours: i64, air_gapped: bool) -> License {
        License {
            version: 1,
            license_id: "lic_test".into(),
            user_id: "u".into(),
            team_id: "t".into(),
            email: "e@e.com".into(),
            plan: "pro".into(),
            seats: 1,
            features: vec![],
            issued_at: Utc::now() - chrono::Duration::days(30),
            valid_until: Utc::now() - chrono::Duration::hours(hours),
            billing_portal_url: None,
            air_gapped,
        }
    }

    #[test]
    fn test_evaluate_license_grace_default_window() {
        // Expired by 6 hours -> GracePeriod (1-day window).
        assert!(matches!(
            evaluate_license(&license_expired_by(6, false)),
            LicenseStatus::GracePeriod { .. }
        ));
    }

    #[test]
    fn test_evaluate_license_extended_grace_default_window() {
        // Expired by ~2 days -> ExtendedGrace (1-3 day window).
        assert!(matches!(
            evaluate_license(&license_expired_by(48, false)),
            LicenseStatus::ExtendedGrace { .. }
        ));
    }

    #[test]
    fn test_evaluate_license_expired_default_window() {
        // Expired by 4 days -> Expired (past 3-day extended grace).
        assert!(matches!(
            evaluate_license(&license_expired_by(96, false)),
            LicenseStatus::Expired
        ));
    }

    #[test]
    fn test_evaluate_license_air_gapped_extended_grace() {
        // Air-gapped expired by 15 days -> ExtendedGrace (7-30 day window).
        assert!(matches!(
            evaluate_license(&license_expired_by(15 * 24, true)),
            LicenseStatus::ExtendedGrace { .. }
        ));
    }

    #[test]
    fn test_evaluate_license_air_gapped_grace_period() {
        // Air-gapped expired by 3 days -> still GracePeriod (7-day window).
        assert!(matches!(
            evaluate_license(&license_expired_by(3 * 24, true)),
            LicenseStatus::GracePeriod { .. }
        ));
    }

    #[test]
    fn test_evaluate_license_air_gapped_expired() {
        // Air-gapped expired by 31 days -> Expired (past 30-day window).
        assert!(matches!(
            evaluate_license(&license_expired_by(31 * 24, true)),
            LicenseStatus::Expired
        ));
    }

    #[test]
    fn test_plan_tier_from_status() {
        let lic = License {
            version: 1,
            license_id: "lic_test".into(),
            user_id: "u".into(),
            team_id: "t".into(),
            email: "e@e.com".into(),
            plan: "pro_trial".into(),
            seats: 1,
            features: vec![],
            issued_at: Utc::now(),
            valid_until: Utc::now() + chrono::Duration::days(14),
            billing_portal_url: None,
            air_gapped: false,
        };
        assert_eq!(plan_tier_from_status(&LicenseStatus::Valid(lic)), "pro");
        assert_eq!(plan_tier_from_status(&LicenseStatus::NotFound), "community");
        assert_eq!(plan_tier_from_status(&LicenseStatus::Expired), "community");
    }

    #[test]
    fn test_load_license_not_found() {
        let status = load_license(Path::new("/tmp/nonexistent_grith_license.key"));
        assert!(matches!(status, LicenseStatus::NotFound));
    }

    fn make_signed_license() -> SignedLicense {
        SignedLicense {
            version: 1,
            license_id: "lic_test".into(),
            user_id: "u1".into(),
            team_id: "t1".into(),
            email: "a@b.com".into(),
            plan: "pro".into(),
            seats: 2,
            features: vec![],
            issued_at: "2026-04-01T00:00:00Z".into(),
            valid_until: "2026-04-08T00:00:00Z".into(),
            billing_portal_url: None,
            air_gapped: Some(false),
            signature: "sig".into(),
        }
    }

    #[test]
    fn test_save_license_to_writes_atomically_and_is_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("license.key");
        save_license_to(&make_signed_license(), &path).unwrap();
        assert!(path.exists());
        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: SignedLicense = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.license_id, "lic_test");
        assert_eq!(parsed.air_gapped, Some(false));
        assert!(
            raw.contains("\"air_gapped\""),
            "new payloads must preserve signed air_gapped:false"
        );
        // No leftover .tmp files.
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|s| s.ends_with(".tmp"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(leftover.is_empty(), "stale .tmp file left after rename");
    }

    #[test]
    fn test_save_license_to_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("license.key");
        std::fs::write(&path, b"old contents").unwrap();
        save_license_to(&make_signed_license(), &path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("lic_test"));
        assert!(!raw.contains("old contents"));
    }

    #[cfg(unix)]
    #[test]
    fn test_save_license_to_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("license.key");
        save_license_to(&make_signed_license(), &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_verify_license_rejects_legacy_payload_with_bad_signature() {
        // Verify_license must fail on bad sig regardless of `air_gapped` presence.
        let mut signed = make_signed_license();
        signed.signature =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);
        let bytes = serde_json::to_vec(&signed).unwrap();
        assert!(matches!(
            verify_license(&bytes),
            Err(LicenseError::InvalidSignature)
        ));

        // Same with air_gapped present in the payload.
        let mut signed = make_signed_license();
        signed.air_gapped = Some(true);
        signed.signature =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);
        let bytes = serde_json::to_vec(&signed).unwrap();
        assert!(matches!(
            verify_license(&bytes),
            Err(LicenseError::InvalidSignature)
        ));
    }

    #[test]
    fn test_canonicalize_legacy_omits_air_gapped_for_backcompat() {
        // A signed payload without air_gapped (legacy) must canonicalize without it,
        // regardless of the value of the in-memory air_gapped field. This is what
        // lets old long-lived licences continue to verify after the upgrade.
        let mut signed = make_signed_license();
        signed.air_gapped = None;
        let legacy = canonicalize_payload(&signed, false);
        assert!(!legacy.contains("air_gapped"));

        signed.air_gapped = Some(true);
        let new_payload = canonicalize_payload(&signed, true);
        assert!(new_payload.contains("\"air_gapped\":true"));
    }

    #[test]
    fn test_credentials_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let creds = Credentials {
            user_id: "u1".into(),
            api_key: "grith_test".into(),
            team_id: "t1".into(),
            license_file: "~/.config/grith/license.key".into(),
            activated_at: "2026-02-12T00:00:00Z".into(),
            last_validated: "2026-02-12T00:00:00Z".into(),
            last_synced: None,
        };
        let data = serde_json::to_string_pretty(&creds).unwrap();
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(data.as_bytes()).unwrap();

        let loaded: Credentials =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.user_id, "u1");
        assert_eq!(loaded.api_key, "grith_test");
    }

    fn make_license(plan: &str, seats: u32) -> License {
        License {
            version: 1,
            license_id: "lic_test".into(),
            user_id: "u".into(),
            team_id: "t".into(),
            email: "e@e.com".into(),
            plan: plan.into(),
            seats,
            features: vec![],
            issued_at: Utc::now(),
            valid_until: Utc::now() + chrono::Duration::days(14),
            billing_portal_url: None,
            air_gapped: false,
        }
    }

    #[test]
    fn test_feature_gate_community() {
        let gate = feature_gate_from_status(&LicenseStatus::NotFound);
        assert_eq!(gate.tier, PlanTier::Community);
        assert!(gate.allows("proxy"));
        assert!(gate.allows("dashboard"));
        assert!(!gate.allows("notification_channels"));
        assert!(!gate.allows("policy_editor"));
        assert!(!gate.allows("unknown_feature"));
    }

    #[test]
    fn test_feature_gate_pro() {
        let lic = make_license("pro", 2);
        let gate = feature_gate_from_status(&LicenseStatus::Valid(lic));
        assert_eq!(gate.tier, PlanTier::Pro);
        assert!(gate.allows("proxy"));
        assert!(gate.allows("notification_channels"));
        assert!(gate.allows("usage_analytics"));
        assert!(gate.allows("cloud_sync"));
        assert!(gate.allows("policy_editor"));
        assert!(!gate.allows("pagerduty"));
    }

    #[test]
    fn test_feature_gate_enterprise() {
        let lic = make_license("enterprise", 5);
        let gate = feature_gate_from_status(&LicenseStatus::Valid(lic));
        assert_eq!(gate.tier, PlanTier::Enterprise);
        assert!(gate.allows("proxy"));
        assert!(gate.allows("policy_editor"));
        assert!(gate.allows("pagerduty"));
        assert!(gate.allows("opsgenie"));
    }

    #[test]
    fn test_max_sessions_by_tier() {
        // Community: a hard cap of 2 (the free-tier lever).
        let gate = feature_gate_from_status(&LicenseStatus::NotFound);
        assert_eq!(gate.max_sessions(), 2);

        // Paid tiers get a flat, generous 64 regardless of seats — local
        // session concurrency is not a per-seat monetisation axis.
        for (tier, seats) in [("pro", 1), ("pro", 3), ("enterprise", 1), ("enterprise", 2)] {
            let lic = make_license(tier, seats);
            let gate = feature_gate_from_status(&LicenseStatus::Valid(lic));
            assert_eq!(
                gate.max_sessions(),
                64,
                "{tier} with {seats} seat(s) should get the flat paid cap"
            );
        }
    }

    #[test]
    fn test_from_license_status_variants() {
        // Expired → community
        let gate = feature_gate_from_status(&LicenseStatus::Expired);
        assert_eq!(gate.tier, PlanTier::Community);

        // Invalid → community
        let gate = feature_gate_from_status(&LicenseStatus::Invalid("bad".into()));
        assert_eq!(gate.tier, PlanTier::Community);

        // GracePeriod → retains tier
        let lic = make_license("pro", 2);
        let gate = feature_gate_from_status(&LicenseStatus::GracePeriod {
            license: lic,
            expired_days: 3,
        });
        assert_eq!(gate.tier, PlanTier::Pro);
        assert_eq!(gate.seats, 2);

        // pro_trial → Pro tier
        let lic = make_license("pro_trial", 1);
        let gate = feature_gate_from_status(&LicenseStatus::Valid(lic));
        assert_eq!(gate.tier, PlanTier::Pro);
    }

    #[test]
    fn test_feature_list_completeness() {
        let gate = feature_gate_from_status(&LicenseStatus::NotFound);
        let list = gate.feature_list();
        assert!(
            list.len() >= 13,
            "expected at least 13 features, got {}",
            list.len()
        );
        // All core features should be enabled for community
        let core_enabled: Vec<_> = list
            .iter()
            .filter(|(f, _)| ["proxy", "audit", "digest"].contains(f))
            .collect();
        assert!(core_enabled.iter().all(|(_, enabled)| *enabled));
        // Pro features should be disabled for community
        let pro_feature = list
            .iter()
            .find(|(f, _)| *f == "notification_channels")
            .unwrap();
        assert!(!pro_feature.1);
        // Retired/unbuilt features must not be advertised any more.
        for retired in ["adaptive_scoring", "extended_retention", "sso"] {
            assert!(
                !list.iter().any(|(f, _)| *f == retired),
                "{retired} should no longer appear in the feature list"
            );
        }
    }

    // --- Provider key encryption tests ---

    #[test]
    fn test_derive_encryption_key_deterministic() {
        let key1 = derive_provider_key_encryption_key("test-api-key-123");
        let key2 = derive_provider_key_encryption_key("test-api-key-123");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_encryption_key_different_inputs() {
        let key1 = derive_provider_key_encryption_key("api-key-aaa");
        let key2 = derive_provider_key_encryption_key("api-key-bbb");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let api_key = "test-api-key-round-trip";
        let plaintext =
            b"{\"provider\":\"anthropic\",\"label\":\"default\",\"key\":\"sk-ant-abc123\"}";
        let encrypted = encrypt_provider_key(api_key, "anthropic", plaintext).unwrap();
        let decrypted = decrypt_provider_key(api_key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_api_key_fails() {
        let plaintext = b"{\"key\":\"secret\"}";
        let encrypted = encrypt_provider_key("correct-key", "test", plaintext).unwrap();
        let result = decrypt_provider_key("wrong-key", &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let plaintext = b"{\"key\":\"secret\"}";
        let encrypted = encrypt_provider_key("my-key", "test", plaintext).unwrap();

        // Tamper with the ciphertext
        let mut envelope: serde_json::Value = serde_json::from_slice(&encrypted).unwrap();
        let ct = envelope["ciphertext"].as_str().unwrap().to_string();
        let mut ct_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &ct).unwrap();
        if let Some(byte) = ct_bytes.first_mut() {
            *byte ^= 0xFF;
        }
        envelope["ciphertext"] = serde_json::Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &ct_bytes,
        ));
        let tampered = serde_json::to_vec(&envelope).unwrap();

        let result = decrypt_provider_key("my-key", &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_unique_nonces() {
        let api_key = "nonce-test-key";
        let plaintext = b"{\"key\":\"same-content\"}";
        let enc1 = encrypt_provider_key(api_key, "test", plaintext).unwrap();
        let enc2 = encrypt_provider_key(api_key, "test", plaintext).unwrap();
        // Different nonces → different ciphertexts
        assert_ne!(enc1, enc2);
        // But both decrypt to the same plaintext
        assert_eq!(
            decrypt_provider_key(api_key, &enc1).unwrap(),
            decrypt_provider_key(api_key, &enc2).unwrap()
        );
    }

    #[test]
    fn test_is_encrypted_envelope() {
        let encrypted = encrypt_provider_key("key", "test", b"{\"key\":\"x\"}").unwrap();
        assert!(is_encrypted_envelope(&encrypted));

        let plaintext = b"{\"provider\":\"test\",\"key\":\"x\"}";
        assert!(!is_encrypted_envelope(plaintext));
    }

    fn make_provider_key(provider: &str, label: &str, key: &str) -> ProviderKeyResponse {
        ProviderKeyResponse {
            provider: provider.to_string(),
            label: label.to_string(),
            key: key.to_string(),
        }
    }

    #[test]
    fn test_reconcile_provider_key_files_removes_revoked_files() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("anthropic.json");
        let keep = dir.path().join("openai.json");
        std::fs::write(&stale, b"{\"key\":\"old-anthropic\"}").unwrap();
        std::fs::write(&keep, b"{\"key\":\"old-openai\"}").unwrap();

        let report = reconcile_provider_key_files(
            "grith-api-key",
            dir.path(),
            &[make_provider_key("openai", "primary", "sk-openai-new")],
        )
        .unwrap();

        assert_eq!(report.written.len(), 1);
        assert_eq!(report.revoked, vec![stale.clone()]);
        assert!(!stale.exists());
        assert!(keep.exists());
        let encrypted = std::fs::read(&keep).unwrap();
        assert!(is_encrypted_envelope(&encrypted));
    }

    #[test]
    fn test_reconcile_provider_key_files_empty_response_cleans_all() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("openai.json");
        let second = dir.path().join("anthropic--backup-2.json");
        std::fs::write(&first, b"{\"key\":\"old-openai\"}").unwrap();
        std::fs::write(&second, b"{\"key\":\"old-anthropic\"}").unwrap();

        let report = reconcile_provider_key_files("grith-api-key", dir.path(), &[]).unwrap();

        assert!(report.written.is_empty());
        assert_eq!(
            report.revoked,
            vec![second.clone(), first.clone()]
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert!(!first.exists());
        assert!(!second.exists());
    }

    #[test]
    fn test_reconcile_provider_key_files_sanitizes_path_traversal_provider_name() {
        let dir = tempfile::tempdir().unwrap();

        let report = reconcile_provider_key_files(
            "grith-api-key",
            dir.path(),
            &[make_provider_key(
                "../../etc/passwd",
                "production",
                "sk-safe",
            )],
        )
        .unwrap();

        assert_eq!(report.skipped_unsafe, 0);
        assert_eq!(report.written.len(), 1);
        let written = &report.written[0].path;
        assert_eq!(
            written.file_name().and_then(|name| name.to_str()),
            Some("etc-passwd.json")
        );
        assert_eq!(written.parent(), Some(dir.path()));
        let encrypted = std::fs::read(written).unwrap();
        assert!(is_encrypted_envelope(&encrypted));
    }

    #[test]
    fn test_reconcile_provider_key_files_skips_empty_provider_name() {
        let dir = tempfile::tempdir().unwrap();

        let report = reconcile_provider_key_files(
            "grith-api-key",
            dir.path(),
            &[make_provider_key("   ", "production", "sk-skipped")],
        )
        .unwrap();

        assert!(report.written.is_empty());
        assert!(report.revoked.is_empty());
        assert_eq!(report.skipped_unsafe, 1);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
