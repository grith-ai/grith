// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

use std::fs;
use std::path::{Path, PathBuf};

use grith_analytics::{
    Category, CompletenessTier, DestinationKind, LocalFreeAnalyticsResponse,
    LocalProAnalyticsResponse, RegistrationRequest, RegistrationResponse, ResolutionStatus,
    SnapshotRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
struct Fixture {
    case: String,
    schema: String,
    valid: bool,
    #[serde(default)]
    semantic: Option<String>,
    value: Value,
}

fn contract_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("contracts/analytics-v2")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("invalid JSON in {}: {error}", path.display()))
}

fn semantic_valid(fixture: &Fixture) -> bool {
    match fixture.semantic.as_deref() {
        None => true,
        Some("score_sum_bound") => {
            let count = fixture.value["event_count"].as_u64().unwrap();
            let sum = fixture.value["score_sum_micros"].as_i64().unwrap();
            i128::from(sum).abs() <= i128::from(count) * 100_000_000
        }
        Some(other) => panic!("unknown semantic validator {other}"),
    }
}

#[test]
fn schemas_are_valid_draft_2020_12_and_all_wrappers_resolve() {
    let root = contract_root();
    let common = read_json(&root.join("schema/common.schema.json"));
    assert!(jsonschema::draft202012::meta::is_valid(&common));
    let definitions = common["$defs"].as_object().unwrap();

    for entry in fs::read_dir(root.join("schema")).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().unwrap() == "common.schema.json" {
            continue;
        }
        let wrapper = read_json(&path);
        assert!(
            jsonschema::draft202012::meta::is_valid(&wrapper),
            "{} is not a valid schema",
            path.display()
        );
        let reference = wrapper["$ref"].as_str().unwrap();
        let definition = reference
            .strip_prefix("common.schema.json#/$defs/")
            .unwrap_or_else(|| panic!("unexpected ref {reference} in {}", path.display()));
        assert!(
            definitions.contains_key(definition),
            "{} references missing definition {definition}",
            path.display()
        );
    }
}

#[test]
fn shared_valid_and_invalid_fixtures_match_schema_and_semantic_rules() {
    let root = contract_root();
    let common = read_json(&root.join("schema/common.schema.json"));
    let definitions = common["$defs"].clone();

    for validity in ["valid", "invalid"] {
        for entry in fs::read_dir(root.join("fixtures").join(validity)).unwrap() {
            let path = entry.unwrap().path();
            let fixture: Fixture = serde_json::from_value(read_json(&path)).unwrap();
            let schema = json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$defs": definitions.clone(),
                "$ref": format!("#/$defs/{}", fixture.schema),
            });
            let validator = jsonschema::draft202012::options()
                .should_validate_formats(true)
                .build(&schema)
                .unwrap_or_else(|error| {
                    panic!(
                        "could not build {} for {}: {error}",
                        fixture.schema,
                        path.display()
                    )
                });
            let schema_valid = validator.is_valid(&fixture.value);
            let actual = schema_valid && semantic_valid(&fixture);
            assert_eq!(
                actual,
                fixture.valid,
                "fixture '{}' ({}) schema_valid={schema_valid}; errors: {:?}",
                fixture.case,
                path.display(),
                validator
                    .iter_errors(&fixture.value)
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
            );

            if fixture.valid {
                match fixture.schema.as_str() {
                    "RegistrationRequest" => {
                        let _: RegistrationRequest = round_trip(&fixture);
                    }
                    "RegistrationResponse" => {
                        let _: RegistrationResponse = round_trip(&fixture);
                    }
                    "SnapshotRequest" => {
                        let request: SnapshotRequest = round_trip(&fixture);
                        for snapshot in request.day_snapshots {
                            assert_eq!(
                                snapshot.compute_row_checksum().unwrap(),
                                snapshot.row_checksum_sha256,
                                "{} carries a non-canonical row checksum",
                                path.display()
                            );
                            let mut canonical = snapshot.clone();
                            canonical.canonicalize();
                            assert_eq!(
                                snapshot,
                                canonical,
                                "{} has non-canonical rows",
                                path.display()
                            );
                        }
                    }
                    "LocalFreeResponse" => {
                        let _: LocalFreeAnalyticsResponse = round_trip(&fixture);
                    }
                    "LocalProResponse" => {
                        let _: LocalProAnalyticsResponse = round_trip(&fixture);
                    }
                    "StructuredError" => {
                        let _: grith_analytics::contract::StructuredError = round_trip(&fixture);
                    }
                    // Round-tripping a chain-less event proves absent chain
                    // fields stay absent — an explicit null violates the
                    // frozen schema.
                    "SecurityEvent" => {
                        let _: grith_analytics::contract::SecurityEvent = round_trip(&fixture);
                    }
                    other => panic!("add a Rust fixture decoder for {other}"),
                }
            }
        }
    }
}

fn round_trip<T>(fixture: &Fixture) -> T
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let decoded: T = serde_json::from_value(fixture.value.clone())
        .unwrap_or_else(|error| panic!("Rust rejected '{}': {error}", fixture.case));
    assert_eq!(
        serde_json::to_value(&decoded).unwrap(),
        fixture.value,
        "Rust rewrote fixture '{}'",
        fixture.case
    );
    decoded
}

#[test]
fn exact_registry_values_match_rust_serialization() {
    let registries = read_json(&contract_root().join("registries.json"));
    assert_eq!(
        registries["categories"],
        serde_json::to_value([
            Category::FileRead,
            Category::FileMutation,
            Category::Process,
            Category::NetworkEgress,
            Category::NetworkListen,
            Category::CrossProcess,
            Category::Namespace,
            Category::Llm,
            Category::System,
            Category::Other,
        ])
        .unwrap()
    );
    assert_eq!(
        registries["completeness_tiers"],
        serde_json::to_value([
            CompletenessTier::Decisions,
            CompletenessTier::Spawns,
            CompletenessTier::Io,
            CompletenessTier::All,
        ])
        .unwrap()
    );
    assert_eq!(
        registries["resolution_statuses"],
        serde_json::to_value([
            ResolutionStatus::Pending,
            ResolutionStatus::Approved,
            ResolutionStatus::Denied,
            ResolutionStatus::Expired,
            ResolutionStatus::Escalated,
        ])
        .unwrap()
    );
    assert_eq!(
        registries["destination_kinds"],
        serde_json::to_value([
            DestinationKind::Domain,
            DestinationKind::HostPort,
            DestinationKind::UrlOrigin,
            DestinationKind::UnixSocketClass,
            DestinationKind::Other,
        ])
        .unwrap()
    );
    assert_eq!(
        registries["device_sync_statuses"],
        serde_json::to_value([
            grith_analytics::contract::DeviceSyncStatus::Current,
            grith_analytics::contract::DeviceSyncStatus::Stale,
            grith_analytics::contract::DeviceSyncStatus::Offline,
            grith_analytics::contract::DeviceSyncStatus::SyncDisabled,
            grith_analytics::contract::DeviceSyncStatus::EntitlementExpired,
            grith_analytics::contract::DeviceSyncStatus::QuotaRejected,
            grith_analytics::contract::DeviceSyncStatus::Revoked,
            grith_analytics::contract::DeviceSyncStatus::Gap,
        ])
        .unwrap()
    );
}

#[test]
fn parquet_projection_freezes_identity_pricing_and_excluded_content() {
    let parquet = read_json(&contract_root().join("parquet-schema.json"));
    let fields = parquet["fields"].as_array().unwrap();
    let actor = fields
        .iter()
        .find(|field| field["name"] == "actor_user_id")
        .unwrap();
    assert_eq!(actor["physical_type"], "BYTE_ARRAY");
    assert_eq!(actor["logical_type"], "STRING");
    for required in ["price_source", "pricing_version"] {
        assert!(fields.iter().any(|field| field["name"] == required));
    }
    let excluded = parquet["excluded_fields"].as_array().unwrap();
    for field in [
        "command",
        "arguments",
        "raw_path",
        "raw_url",
        "prompt",
        "model_response",
    ] {
        assert!(excluded.iter().any(|value| value == field));
    }
}
