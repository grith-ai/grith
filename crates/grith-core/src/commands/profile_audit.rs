// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Profile audit command: normalizes forensic traces and classifies events
//! into remote-overlay-eligible, bundled-change-required, or manual-review
//! buckets.
//!
//! Usage:
//!   grith profile audit --profile claude-code --trace /tmp/trace.jsonl

use crate::profile_manifest;
use crate::profile_updates;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One fully-normalized audited event collapsed from multi-stage JSONL records.
#[derive(Debug)]
#[allow(dead_code)]
pub struct AuditedEvent {
    pub event_id: String,
    pub timestamp: String,
    pub session_id: String,
    pub root_pid: u32,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub exe_path: Option<String>,
    pub exe_canonical_path: Option<String>,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub comm: Option<String>,
    // Subject fields (backfilled from captured stage).
    pub event_kind: Option<String>,
    pub path: Option<String>,
    pub path_canonical: Option<String>,
    pub domain: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub spawn_path: Option<String>,
    pub spawn_argv: Option<Vec<String>>,
    pub listen_address: Option<String>,
    pub listen_port: Option<u16>,
    pub dns_name: Option<String>,
    pub dns_query_type: Option<String>,
    // Decision fields (from latest stage with decision).
    pub tool_call_type: Option<String>,
    pub decision: Option<String>,
    pub score: Option<f64>,
    pub decision_reason: Option<String>,
    pub stages_seen: Vec<String>,
}

/// Classification bucket for an audited event.
#[derive(Debug, PartialEq)]
pub enum AuditBucket {
    /// Can be expressed in the OTA remote overlay schema.
    RemoteOverlayCandidate { target_field: String, value: String },
    /// Requires editing profiles.toml and shipping a binary update.
    BundledChangeRequired { reason: String },
    /// Suspicious or ambiguous — needs human investigation.
    ManualReviewOnly { reason: String },
}

/// A raw trace record as read from JSONL. Mirrors ForensicsTraceRecord.
#[derive(Debug, Deserialize)]
struct RawTraceRecord {
    event_id: String,
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    root_pid: u32,
    #[serde(default)]
    pid: u32,
    #[serde(default)]
    ppid: Option<u32>,
    #[serde(default)]
    stage: String,
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    decision_reason: Option<String>,
    #[serde(default)]
    tool_call_type: Option<String>,
    #[serde(default)]
    exe_path: Option<String>,
    #[serde(default)]
    exe_canonical_path: Option<String>,
    #[serde(default)]
    argv: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    comm: Option<String>,
    // Subject fields (flattened in trace output).
    #[serde(default)]
    event_kind: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    path_canonical: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    spawn_path: Option<String>,
    #[serde(default)]
    spawn_argv: Option<Vec<String>>,
    #[serde(default)]
    listen_address: Option<String>,
    #[serde(default)]
    listen_port: Option<u16>,
    #[serde(default)]
    dns_name: Option<String>,
    #[serde(default)]
    dns_query_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// Parse a JSONL trace file and normalize records by event_id.
///
/// Groups multi-stage records into one `AuditedEvent` per unique event_id.
/// Decision fields are taken from the latest record that has them.
/// Subject fields are backfilled from the captured stage.
pub fn normalize_trace(trace_path: &Path) -> anyhow::Result<Vec<AuditedEvent>> {
    let content = std::fs::read_to_string(trace_path)?;

    // Group raw records by event_id.
    let mut groups: HashMap<String, Vec<RawTraceRecord>> = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<RawTraceRecord>(line) {
            Ok(record) => {
                groups
                    .entry(record.event_id.clone())
                    .or_default()
                    .push(record);
            }
            Err(e) => {
                tracing::debug!(error = %e, "skipping malformed trace line");
            }
        }
    }

    let mut events = Vec::new();
    for (_event_id, records) in groups {
        if let Some(event) = merge_records(records) {
            events.push(event);
        }
    }

    // Sort by timestamp for stable output.
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(events)
}

/// Merge multiple records with the same event_id into one AuditedEvent.
fn merge_records(records: Vec<RawTraceRecord>) -> Option<AuditedEvent> {
    if records.is_empty() {
        return None;
    }

    // Start with the first (usually "captured") record as base.
    let base = &records[0];
    let mut event = AuditedEvent {
        event_id: base.event_id.clone(),
        timestamp: base.timestamp.clone(),
        session_id: base.session_id.clone(),
        root_pid: base.root_pid,
        pid: base.pid,
        ppid: base.ppid,
        exe_path: base.exe_path.clone(),
        exe_canonical_path: base.exe_canonical_path.clone(),
        argv: base.argv.clone(),
        cwd: base.cwd.clone(),
        comm: base.comm.clone(),
        event_kind: base.event_kind.clone(),
        path: base.path.clone(),
        path_canonical: base.path_canonical.clone(),
        domain: base.domain.clone(),
        address: base.address.clone(),
        port: base.port,
        spawn_path: base.spawn_path.clone(),
        spawn_argv: base.spawn_argv.clone(),
        listen_address: base.listen_address.clone(),
        listen_port: base.listen_port,
        dns_name: base.dns_name.clone(),
        dns_query_type: base.dns_query_type.clone(),
        tool_call_type: base.tool_call_type.clone(),
        decision: base.decision.clone(),
        score: base.score,
        decision_reason: base.decision_reason.clone(),
        stages_seen: vec![base.stage.clone()],
    };

    // Apply later records, preferring the latest for decision fields.
    for record in records.iter().skip(1) {
        event.stages_seen.push(record.stage.clone());

        // Backfill subject fields from captured record if missing.
        if event.event_kind.is_none() {
            event.event_kind = record.event_kind.clone();
        }
        if event.path.is_none() {
            event.path = record.path.clone();
        }
        if event.path_canonical.is_none() {
            event.path_canonical = record.path_canonical.clone();
        }
        if event.domain.is_none() {
            event.domain = record.domain.clone();
        }
        if event.address.is_none() {
            event.address = record.address.clone();
        }
        if event.port.is_none() {
            event.port = record.port;
        }
        if event.spawn_path.is_none() {
            event.spawn_path = record.spawn_path.clone();
        }
        if event.spawn_argv.is_none() {
            event.spawn_argv = record.spawn_argv.clone();
        }
        if event.listen_address.is_none() {
            event.listen_address = record.listen_address.clone();
        }
        if event.listen_port.is_none() {
            event.listen_port = record.listen_port;
        }
        if event.dns_name.is_none() {
            event.dns_name = record.dns_name.clone();
        }

        // Later records with decision override earlier ones.
        if record.decision.is_some() {
            event.decision = record.decision.clone();
            event.score = record.score;
            event.decision_reason = record.decision_reason.clone();
        }

        // Later records with tool_call_type override.
        if record.tool_call_type.is_some() {
            event.tool_call_type = record.tool_call_type.clone();
        }
    }

    // Discard events where both subject and classification are missing.
    if event.event_kind.is_none() && event.decision.is_none() {
        return None;
    }

    Some(event)
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Classify an audited event into one of three buckets.
pub fn classify_event(
    event: &AuditedEvent,
    profile: &grith_supervisor::profiles::SupervisorProfile,
) -> AuditBucket {
    let kind = event.event_kind.as_deref().unwrap_or("");

    match kind {
        "FileRead" | "FileWrite" | "DirCreate" | "DirList" | "FileAppend" | "FileChmod"
        | "FileDelete" | "FileRename" => classify_file_event(event, profile),
        "NetConnect" => classify_net_event(event, profile),
        "DnsQuery" => classify_dns_event(event, profile),
        "ProcessSpawn" => classify_spawn_event(event, profile),
        "NetListen" => AuditBucket::BundledChangeRequired {
            reason: format!(
                "listener policy: {}:{}",
                event.listen_address.as_deref().unwrap_or("?"),
                event.listen_port.unwrap_or(0)
            ),
        },
        _ => AuditBucket::ManualReviewOnly {
            reason: format!("unknown event kind: {kind}"),
        },
    }
}

fn classify_file_event(
    event: &AuditedEvent,
    profile: &grith_supervisor::profiles::SupervisorProfile,
) -> AuditBucket {
    let raw_path = event
        .path
        .as_deref()
        .or(event.path_canonical.as_deref())
        .unwrap_or("");

    if raw_path.is_empty() {
        return AuditBucket::ManualReviewOnly {
            reason: "file event with no path".into(),
        };
    }
    let path = normalize_candidate_path(raw_path);

    if profile_routine_paths_cover(&path, profile) {
        return AuditBucket::RemoteOverlayCandidate {
            target_field: "routine_paths".into(),
            value: path,
        };
    }
    if profile.readonly_paths.iter().any(|p| p == &path)
        || profile_readonly_patterns_cover(&path, profile)
    {
        return AuditBucket::RemoteOverlayCandidate {
            target_field: "readonly_paths".into(),
            value: path,
        };
    }

    // Check if the path is OTA-eligible.
    let kind = event.event_kind.as_deref().unwrap_or("");
    if kind == "FileRead" {
        return match profile_manifest::validate_readonly_path(&path) {
            Ok(()) => AuditBucket::RemoteOverlayCandidate {
                target_field: "readonly_paths".into(),
                value: path,
            },
            Err(reason) => AuditBucket::ManualReviewOnly { reason },
        };
    }

    match profile_manifest::validate_routine_path(&path) {
        Ok(()) => AuditBucket::RemoteOverlayCandidate {
            target_field: "routine_paths".into(),
            value: path,
        },
        Err(reason) => AuditBucket::ManualReviewOnly { reason },
    }
}

fn normalize_candidate_path(path: &str) -> String {
    if let Ok(home) = std::env::var("HOME") {
        if path == home {
            return "${HOME}".into();
        }
        if let Some(rest) = path.strip_prefix(home.as_str()) {
            if rest.is_empty() {
                return "${HOME}".into();
            }
            if rest.starts_with('/') {
                return format!("${{HOME}}{rest}");
            }
        }
    }

    if let Ok(project_dir) = std::env::current_dir() {
        if let Some(project_dir) = project_dir.to_str() {
            if path == project_dir {
                return "${PROJECT_DIR}".into();
            }
            if let Some(rest) = path.strip_prefix(project_dir) {
                if rest.is_empty() {
                    return "${PROJECT_DIR}".into();
                }
                if rest.starts_with('/') {
                    return format!("${{PROJECT_DIR}}{rest}");
                }
            }
        }
    }

    path.to_string()
}

fn profile_routine_paths_cover(
    path: &str,
    profile: &grith_supervisor::profiles::SupervisorProfile,
) -> bool {
    profile.routine_paths.iter().any(|pattern| {
        let prefix = pattern
            .trim_end_matches("/**")
            .trim_end_matches("/*")
            .trim_end_matches('*');
        !prefix.is_empty() && path.starts_with(prefix)
    })
}

fn profile_readonly_patterns_cover(
    path: &str,
    profile: &grith_supervisor::profiles::SupervisorProfile,
) -> bool {
    profile
        .readonly_path_patterns
        .iter()
        .any(|pattern| audit_glob_match(path, pattern))
}

fn audit_glob_match(path: &str, pattern: &str) -> bool {
    if let Some(star_pos) = pattern.find('*') {
        let prefix = &pattern[..star_pos];
        let suffix = &pattern[star_pos + 1..];
        path.starts_with(prefix)
            && path.ends_with(suffix)
            && !path[prefix.len()..path.len() - suffix.len()].contains('/')
    } else {
        path == pattern
    }
}

fn classify_net_event(
    event: &AuditedEvent,
    _profile: &grith_supervisor::profiles::SupervisorProfile,
) -> AuditBucket {
    // Prefer domain from DNS resolution, fall back to address.
    let host = event
        .domain
        .as_deref()
        .or(event.dns_name.as_deref())
        .unwrap_or("");

    if !host.is_empty() {
        match profile_manifest::validate_destination(host) {
            Ok(()) => {
                return AuditBucket::RemoteOverlayCandidate {
                    target_field: "routine_destinations".into(),
                    value: host.into(),
                };
            }
            Err(reason) => {
                return AuditBucket::ManualReviewOnly { reason };
            }
        }
    }

    // IP-only connect — manual review.
    let addr = event.address.as_deref().unwrap_or("?");
    AuditBucket::ManualReviewOnly {
        reason: format!("IP-only connect: {}:{}", addr, event.port.unwrap_or(0)),
    }
}

fn classify_dns_event(
    event: &AuditedEvent,
    _profile: &grith_supervisor::profiles::SupervisorProfile,
) -> AuditBucket {
    let name = event.dns_name.as_deref().unwrap_or("");
    if name.is_empty() {
        return AuditBucket::ManualReviewOnly {
            reason: "DNS query with no name".into(),
        };
    }

    match profile_manifest::validate_destination(name) {
        Ok(()) => AuditBucket::RemoteOverlayCandidate {
            target_field: "routine_destinations".into(),
            value: name.into(),
        },
        Err(reason) => AuditBucket::ManualReviewOnly { reason },
    }
}

fn classify_spawn_event(
    event: &AuditedEvent,
    profile: &grith_supervisor::profiles::SupervisorProfile,
) -> AuditBucket {
    let spawn_path = event.spawn_path.as_deref().unwrap_or("");
    if spawn_path.is_empty() {
        return AuditBucket::ManualReviewOnly {
            reason: "spawn event with no path".into(),
        };
    }

    // Extract basename.
    let basename = spawn_path.rsplit('/').next().unwrap_or(spawn_path);

    // Check if the basename needs a new exec root.
    let in_known_exec_root = profile
        .routine_exec_roots
        .iter()
        .any(|root| spawn_path.starts_with(root.trim_end_matches('/')));

    // If it's a basename on PATH (no path component in the command), it's
    // potentially a routine_commands candidate.
    if !spawn_path.contains('/') || in_known_exec_root {
        match profile_manifest::validate_command(basename) {
            Ok(()) => {
                return AuditBucket::RemoteOverlayCandidate {
                    target_field: "routine_commands".into(),
                    value: basename.into(),
                };
            }
            Err(reason) => {
                return AuditBucket::ManualReviewOnly { reason };
            }
        }
    }

    // Full path not in any known exec root — requires bundled change.
    if !in_known_exec_root {
        return AuditBucket::BundledChangeRequired {
            reason: format!("new exec root required for: {spawn_path}"),
        };
    }

    AuditBucket::RemoteOverlayCandidate {
        target_field: "routine_commands".into(),
        value: basename.into(),
    }
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

/// Run the full audit pipeline and print results.
pub fn run_audit(profile_name: &str, trace_path: &Path) -> anyhow::Result<()> {
    let config = profile_updates::load_effective_profiles()?;
    let profile = config
        .profiles
        .iter()
        .find(|p| p.name == profile_name)
        .ok_or_else(|| anyhow::anyhow!("unknown profile: {profile_name}"))?;

    let events = normalize_trace(trace_path)?;

    let mut remote_candidates: Vec<(String, String)> = Vec::new();
    let mut bundled_changes: Vec<String> = Vec::new();
    let mut manual_review: Vec<String> = Vec::new();
    let mut approved = 0u64;
    let mut denied = 0u64;
    let mut other = 0u64;

    for event in &events {
        match event.decision.as_deref() {
            Some(d) if d.contains("allow") => approved += 1,
            Some(d) if d.contains("deny") => denied += 1,
            _ => other += 1,
        }

        let bucket = classify_event(event, profile);
        match bucket {
            AuditBucket::RemoteOverlayCandidate {
                target_field,
                value,
            } => {
                if !remote_candidates
                    .iter()
                    .any(|(f, v)| f == &target_field && v == &value)
                {
                    remote_candidates.push((target_field, value));
                }
            }
            AuditBucket::BundledChangeRequired { reason } => {
                if !bundled_changes.contains(&reason) {
                    bundled_changes.push(reason);
                }
            }
            AuditBucket::ManualReviewOnly { reason } => {
                if !manual_review.contains(&reason) {
                    manual_review.push(reason);
                }
            }
        }
    }

    // Print results.
    println!("Profile Audit: {profile_name}");
    println!("Trace: {}", trace_path.display());
    println!();
    println!("Events analyzed: {}", events.len());
    println!("  Approved: {approved}  Denied: {denied}  Other: {other}");
    println!();

    if !remote_candidates.is_empty() {
        println!("Remote Overlay Candidates ({}):", remote_candidates.len());
        // Group by target field.
        let mut by_field: HashMap<&str, Vec<&str>> = HashMap::new();
        for (field, value) in &remote_candidates {
            by_field
                .entry(field.as_str())
                .or_default()
                .push(value.as_str());
        }
        let mut fields: Vec<&str> = by_field.keys().copied().collect();
        fields.sort();
        for field in &fields {
            println!("  {field}:");
            for value in &by_field[field] {
                println!("    + {value}");
            }
        }
        println!();
    }

    if !bundled_changes.is_empty() {
        println!(
            "Bundled-Profile Changes Required ({}):",
            bundled_changes.len()
        );
        for reason in &bundled_changes {
            println!("  {reason}");
        }
        println!();
    }

    if !manual_review.is_empty() {
        println!("Manual Review Required ({}):", manual_review.len());
        for reason in &manual_review {
            println!("  {reason}");
        }
        println!();
    }

    // Report unused existing entries (observed 0 times).
    let event_dests: Vec<&str> = events
        .iter()
        .filter_map(|e| {
            e.domain
                .as_deref()
                .or(e.dns_name.as_deref())
                .or(e.address.as_deref())
        })
        .collect();

    let mut unused = Vec::new();
    for dest in &profile.routine_destinations {
        if !event_dests.contains(&dest.as_str()) {
            unused.push(format!("routine_destinations: {dest}"));
        }
    }

    if !unused.is_empty() {
        println!("Unused Existing Entries (observed 0 times):");
        for entry in &unused {
            println!("  {entry}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(
        kind: &str,
        path: Option<&str>,
        address: Option<&str>,
        domain: Option<&str>,
        port: Option<u16>,
        spawn_path: Option<&str>,
        listen_address: Option<&str>,
        listen_port: Option<u16>,
        decision: Option<&str>,
    ) -> AuditedEvent {
        AuditedEvent {
            event_id: "test-id".into(),
            timestamp: "2026-03-31T10:00:00Z".into(),
            session_id: "test-session".into(),
            root_pid: 100,
            pid: 101,
            ppid: None,
            exe_path: None,
            exe_canonical_path: None,
            argv: vec![],
            cwd: None,
            comm: None,
            event_kind: Some(kind.into()),
            path: path.map(String::from),
            path_canonical: None,
            domain: domain.map(String::from),
            address: address.map(String::from),
            port,
            spawn_path: spawn_path.map(String::from),
            spawn_argv: None,
            listen_address: listen_address.map(String::from),
            listen_port,
            dns_name: None,
            dns_query_type: None,
            tool_call_type: None,
            decision: decision.map(String::from),
            score: None,
            decision_reason: None,
            stages_seen: vec!["captured".into()],
        }
    }

    fn test_profile() -> grith_supervisor::profiles::SupervisorProfile {
        grith_supervisor::profiles::SupervisorProfile {
            name: "test".into(),
            display_name: "Test".into(),
            rationale: None,
            extends: None,
            routine_paths: vec!["${PROJECT_DIR}/**".into()],
            routine_commands: vec!["git".into(), "npm".into()],
            routine_destinations: vec!["api.example.com".into()],
            routine_listen_addresses: vec![],
            routine_exec_roots: vec!["/usr/bin/".into(), "/usr/lib/git-core/".into()],
            readonly_paths: vec![],
            readonly_path_patterns: vec![],
            launch_contract: None,
        }
    }

    #[test]
    fn normalize_joins_stages() {
        let jsonl = r#"{"event_id":"a","timestamp":"2026-01-01T00:00:00Z","session_id":"s","root_pid":1,"pid":2,"tid":2,"stage":"captured","raw_syscall_nr":257,"raw_syscall_kind":"FileOpen","event_kind":"FileRead","path":"/tmp/test"}
{"event_id":"a","timestamp":"2026-01-01T00:00:01Z","session_id":"s","root_pid":1,"pid":2,"tid":2,"stage":"proxy_scored","decision":"auto-allow","score":1.5,"tool_call_type":"FileRead(/tmp/test)"}"#;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), jsonl).unwrap();

        let events = normalize_trace(tmp.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "a");
        assert_eq!(events[0].path.as_deref(), Some("/tmp/test"));
        assert_eq!(events[0].decision.as_deref(), Some("auto-allow"));
        assert_eq!(events[0].score, Some(1.5));
        assert_eq!(events[0].stages_seen.len(), 2);
    }

    #[test]
    fn normalize_backfills_subject() {
        let jsonl = r#"{"event_id":"b","timestamp":"2026-01-01T00:00:00Z","session_id":"s","root_pid":1,"pid":2,"tid":2,"stage":"captured","raw_syscall_nr":42,"raw_syscall_kind":"NetConnect","address":"1.2.3.4","port":443,"event_kind":"NetConnect"}
{"event_id":"b","timestamp":"2026-01-01T00:00:01Z","session_id":"s","root_pid":1,"pid":2,"tid":2,"stage":"proxy_scored","decision":"auto-deny","score":9.0}"#;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), jsonl).unwrap();

        let events = normalize_trace(tmp.path()).unwrap();
        assert_eq!(events.len(), 1);
        // Subject backfilled from captured stage.
        assert_eq!(events[0].address.as_deref(), Some("1.2.3.4"));
        assert_eq!(events[0].port, Some(443));
        // Decision from scored stage.
        assert_eq!(events[0].decision.as_deref(), Some("auto-deny"));
    }

    #[test]
    fn classify_new_destination_as_remote() {
        let event = make_event(
            "NetConnect",
            None,
            Some("93.184.216.34"),
            Some("new-api.example.com"),
            Some(443),
            None,
            None,
            None,
            None,
        );
        let profile = test_profile();
        let bucket = classify_event(&event, &profile);
        assert!(matches!(
            bucket,
            AuditBucket::RemoteOverlayCandidate {
                target_field,
                ..
            } if target_field == "routine_destinations"
        ));
    }

    #[test]
    fn classify_ip_only_connect_as_manual() {
        let event = make_event(
            "NetConnect",
            None,
            Some("192.168.1.100"),
            None,
            Some(8080),
            None,
            None,
            None,
            None,
        );
        let profile = test_profile();
        let bucket = classify_event(&event, &profile);
        assert!(matches!(bucket, AuditBucket::ManualReviewOnly { .. }));
    }

    #[test]
    fn classify_new_exec_root_as_bundled() {
        let event = make_event(
            "ProcessSpawn",
            None,
            None,
            None,
            None,
            Some("/opt/custom/bin/tool"),
            None,
            None,
            None,
        );
        let profile = test_profile();
        let bucket = classify_event(&event, &profile);
        assert!(matches!(bucket, AuditBucket::BundledChangeRequired { .. }));
    }

    #[test]
    fn classify_listener_as_bundled() {
        let event = make_event(
            "NetListen",
            None,
            None,
            None,
            None,
            None,
            Some("127.0.0.1"),
            Some(9222),
            None,
        );
        let profile = test_profile();
        let bucket = classify_event(&event, &profile);
        assert!(matches!(bucket, AuditBucket::BundledChangeRequired { .. }));
    }

    #[test]
    fn classify_file_read_as_readonly() {
        let event = make_event(
            "FileRead",
            Some("/etc/hosts"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let profile = test_profile();
        let bucket = classify_event(&event, &profile);
        assert!(matches!(
            bucket,
            AuditBucket::RemoteOverlayCandidate {
                target_field,
                ..
            } if target_field == "readonly_paths"
        ));
    }

    #[test]
    fn classify_overbroad_path_as_manual() {
        let event = make_event(
            "FileWrite",
            Some("/"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let profile = test_profile();
        let bucket = classify_event(&event, &profile);
        assert!(matches!(bucket, AuditBucket::ManualReviewOnly { .. }));
    }

    #[test]
    fn classify_command_in_known_exec_root() {
        let event = make_event(
            "ProcessSpawn",
            None,
            None,
            None,
            None,
            Some("/usr/bin/curl"),
            None,
            None,
            None,
        );
        let profile = test_profile();
        let bucket = classify_event(&event, &profile);
        assert!(matches!(
            bucket,
            AuditBucket::RemoteOverlayCandidate {
                target_field,
                value,
            } if target_field == "routine_commands" && value == "curl"
        ));
    }
}
