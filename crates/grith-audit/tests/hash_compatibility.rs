use chrono::{DateTime, Utc};
use grith_analytics::contract::{
    Category, CompletenessTier, DestinationKind, RecordClass, ResolutionStatus, SecurityEventType,
};
use grith_audit::{
    AuditAnalyticsMetadata, AuditConfigVersion, AuditDestinationMetadata, AuditLlmPricing,
    AuditRecord, AuditSecurityMetadata, ProxyActionSummary,
};
use uuid::Uuid;

fn pinned_record() -> AuditRecord {
    let mut record = AuditRecord::new(
        Uuid::nil(),
        "file-ops".into(),
        "FileRead".into(),
        &serde_json::json!({"path":"/tmp/a"}),
        1.5,
        ProxyActionSummary::Allow,
        vec![],
        2.25,
        None,
    );
    record.id = Uuid::nil();
    record.timestamp = DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc);
    record.arguments_summary = "{\"path\":\"/tmp/a\"}".into();
    record.arguments_hash = "abc123".into();
    record
}

#[test]
fn v2_vector_remains_byte_for_byte_frozen() {
    let mut record = pinned_record();
    record.hash_version = grith_audit::types::HASH_VERSION_V2;
    assert_eq!(
        record.compute_record_hash(),
        "48ec76d6a508a4e55d9f11aaac932781f00d4cd7038b724fb95d6f8ba91e4155"
    );
}

/// The minimal vector above cannot catch a canonicalization change in the
/// optional field encodings, so this one pins a record exercising filter
/// results, supervisor source, project labelling and LLM cost accounting.
#[test]
fn v2_vector_with_populated_optionals_remains_frozen() {
    let mut record = grith_audit::AuditRecord::new(
        Uuid::nil(),
        "supervisor".into(),
        "ProcessSpawn".into(),
        &serde_json::json!({"command":"redacted"}),
        4.25,
        ProxyActionSummary::Queue,
        vec![grith_audit::types::FilterResultSummary {
            filter_name: "secret_scan".into(),
            matched: true,
            score: 2.0,
            rule_id: "aws-key".into(),
            severity: "warning".into(),
            message: "redacted".into(),
        }],
        1.5,
        Some("queued for review".into()),
    )
    .with_supervisor_source("claude-code", 4242)
    .with_project_name(Some("grith".into()))
    .with_llm_cost("openai", "gpt-test", 100, 50, 0.001_5);
    record.id = Uuid::nil();
    record.timestamp = DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc);
    record.arguments_summary = "{\"command\":\"redacted\"}".into();
    record.arguments_hash = "def456".into();
    record.hash_version = grith_audit::types::HASH_VERSION_V2;
    assert_eq!(
        record.compute_record_hash(),
        "16a2d3399a08da2c2053f033bd1b1401dc520b2f96db8ba3540ebd22d3e11e6c"
    );
}

#[test]
fn v3_vectors_pin_absent_and_complete_metadata_encodings() {
    let mut record = pinned_record();
    record.hash_version = grith_audit::types::CURRENT_HASH_VERSION;
    assert_eq!(
        record.compute_record_hash(),
        "944ebcd33b385fb0a82c5d2fd49a427581fe2c82a133c2e62f5dc72be18bbdae"
    );

    record.analytics_metadata = Some(AuditAnalyticsMetadata {
        metadata_version: 1,
        completeness: CompletenessTier::All,
        record_class: RecordClass::Decision,
        category: Category::FileRead,
        config: AuditConfigVersion {
            profile_id: "default".into(),
            profile_version: "1".into(),
            config_hash: "a".repeat(64),
            policy_version: "p1".into(),
            auto_allow_threshold_micros: 3_000_000,
            auto_deny_threshold_micros: 8_000_000,
            queue_policy: "review".into(),
            team_default_config_version: "t1".into(),
        },
        filter_set_version: Some(7),
        llm_pricing: Some(AuditLlmPricing {
            cost_micros: 42,
            price_source: "catalog".into(),
            pricing_version: "2026-01".into(),
        }),
        destination: Some(AuditDestinationMetadata {
            kind: DestinationKind::Domain,
            destination_hmac: "hmac".into(),
            hmac_key_version: 2,
            approved_display_label: Some("example".into()),
        }),
        security: Some(AuditSecurityMetadata {
            event_type: SecurityEventType::Queue,
            event_revision: 3,
            resolution_status: Some(ResolutionStatus::Approved),
            resolved_at: Some(record.timestamp),
            resolution_code: Some("ok".into()),
            enforcement_outcome_code: Some("ran".into()),
            gap_count: None,
        }),
    });
    assert_eq!(
        record.compute_record_hash(),
        "c012e65bb4e6b2fbe14187a8b4cca78ae5a21e1f62cb6431f249236599e3855f"
    );
}
