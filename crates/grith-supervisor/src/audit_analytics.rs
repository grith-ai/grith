// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Prospective analytics metadata construction for supervisor producers.

use grith_analytics::contract::{Category, CompletenessTier, RecordClass};
use grith_analytics::normalize::score_to_micros;
use grith_audit::{AuditAnalyticsMetadata, AuditConfigVersion};
use sha2::{Digest, Sha256};

/// Build a versioned effective-config envelope without including operands.
/// `config_fingerprint` is serialized effective policy/configuration, never an
/// event argument; it is hashed before persistence.
///
/// Serialization + SHA-256 make this too expensive for the supervisor's
/// per-syscall budget; callers must compute it once per session/service and
/// reuse it through [`metadata`].
pub(crate) fn config_envelope(
    profile_id: &str,
    config_fingerprint: &[u8],
    allow_threshold: f64,
    deny_threshold: f64,
    queue_policy: &str,
) -> AuditConfigVersion {
    let mut hasher = Sha256::new();
    hasher.update(b"grith-analytics-v2:effective-supervisor-config\0");
    hasher.update(profile_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(config_fingerprint);
    hasher.update(b"\0");
    hasher.update(allow_threshold.to_bits().to_be_bytes());
    hasher.update(deny_threshold.to_bits().to_be_bytes());
    hasher.update(queue_policy.as_bytes());
    let config_hash = hex::encode(hasher.finalize());
    AuditConfigVersion {
        profile_id: profile_id.into(),
        // These identify the versioned producer/config canonical forms;
        // config_hash distinguishes each effective instance exactly.
        profile_version: "supervisor-profile-v1".into(),
        config_hash,
        policy_version: "proxy-policy-v1".into(),
        auto_allow_threshold_micros: score_to_micros(allow_threshold).unwrap_or_default(),
        auto_deny_threshold_micros: score_to_micros(deny_threshold).unwrap_or_default(),
        queue_policy: queue_policy.into(),
        team_default_config_version: "standalone-local-v1".into(),
    }
}

/// Cheap per-record metadata constructor around a precomputed envelope.
pub(crate) fn metadata(
    config: &AuditConfigVersion,
    completeness: CompletenessTier,
    record_class: RecordClass,
    category: Category,
) -> AuditAnalyticsMetadata {
    AuditAnalyticsMetadata {
        metadata_version: 1,
        completeness,
        record_class,
        category,
        config: config.clone(),
        filter_set_version: (record_class == RecordClass::Decision).then_some(1),
        llm_pricing: None,
        destination: None,
        security: None,
    }
}
