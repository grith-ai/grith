// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Audit record export in JSON, JSONL, CSV, and incident snapshot formats.

use crate::correlation::CorrelationInfo;
use crate::error::Result;
use crate::types::AuditRecord;
use chrono::Utc;
use serde::Serialize;
use std::io::Write;
use uuid::Uuid;

/// Export audit records as JSON array.
pub fn export_json(records: &[AuditRecord], writer: &mut dyn Write) -> Result<()> {
    let json = serde_json::to_string_pretty(records)?;
    writer.write_all(json.as_bytes())?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Export audit records as JSON lines (one JSON object per line, for streaming).
pub fn export_jsonl(records: &[AuditRecord], writer: &mut dyn Write) -> Result<()> {
    for record in records {
        let line = serde_json::to_string(record)?;
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

/// Export audit records as CSV.
pub fn export_csv(records: &[AuditRecord], writer: &mut dyn Write) -> Result<()> {
    // Header
    writeln!(
        writer,
        "id,timestamp,session_id,plugin_id,tool_call_type,composite_score,proxy_action,filter_scores,evaluation_time_ms,task_context,source,supervised_tool,supervised_pid,project_name,correlation_id,record_hash,prev_hash,chain_sequence,llm_provider,llm_model,prompt_tokens,completion_tokens,estimated_cost_usd"
    )?;
    for record in records {
        let filter_scores_str = record
            .filter_scores
            .as_ref()
            .map(|fs| serde_json::to_string(fs).unwrap_or_default())
            .unwrap_or_default();
        writeln!(
            writer,
            "{},{},{},{},{},{:.2},{},{},{:.2},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            record.id,
            record.timestamp.to_rfc3339(),
            record.session_id,
            csv_escape(&record.plugin_id),
            csv_escape(&record.tool_call_type),
            record.composite_score,
            record.proxy_action,
            csv_escape(&filter_scores_str),
            record.evaluation_time_ms,
            csv_escape(record.task_context.as_deref().unwrap_or("")),
            csv_escape(&record.source),
            csv_escape(record.supervised_tool.as_deref().unwrap_or("")),
            record
                .supervised_pid
                .map_or_else(String::new, |p| p.to_string()),
            csv_escape(record.project_name.as_deref().unwrap_or("")),
            record
                .correlation_id
                .map_or_else(String::new, |id| id.to_string()),
            record.record_hash.as_deref().unwrap_or(""),
            record.prev_hash.as_deref().unwrap_or(""),
            record
                .chain_sequence
                .map_or_else(String::new, |s| s.to_string()),
            csv_escape(record.llm_provider.as_deref().unwrap_or("")),
            csv_escape(record.llm_model.as_deref().unwrap_or("")),
            record
                .prompt_tokens
                .map_or_else(String::new, |v| v.to_string()),
            record
                .completion_tokens
                .map_or_else(String::new, |v| v.to_string()),
            record
                .estimated_cost_usd
                .map_or_else(String::new, |v| format!("{v:.6}")),
        )?;
    }
    Ok(())
}

/// An incident snapshot bundle suitable for SOC ingestion.
///
/// Contains all audit records in a correlated source→sink chain, plus metadata
/// about the incident, the correlation chain, and the session.
#[derive(Debug, Serialize)]
pub struct IncidentSnapshot {
    pub incident_id: Uuid,
    pub generated_at: String,
    pub correlation_id: Uuid,
    pub session_id: Uuid,
    pub source_event: String,
    pub sink_count: u32,
    pub chain_age_seconds: u64,
    pub records: Vec<AuditRecord>,
}

/// Build an incident snapshot from a correlation chain and its associated
/// audit records.
pub fn build_incident_snapshot(
    correlation: &CorrelationInfo,
    records: Vec<AuditRecord>,
) -> IncidentSnapshot {
    IncidentSnapshot {
        incident_id: Uuid::new_v4(),
        generated_at: Utc::now().to_rfc3339(),
        correlation_id: correlation.correlation_id,
        session_id: correlation.session_id,
        source_event: correlation.source_event.clone(),
        sink_count: correlation.sink_count,
        chain_age_seconds: correlation.age_seconds,
        records,
    }
}

/// Export an incident snapshot as a JSON bundle.
pub fn export_incident_json(snapshot: &IncidentSnapshot, writer: &mut dyn Write) -> Result<()> {
    let json = serde_json::to_string_pretty(snapshot)?;
    writer.write_all(json.as_bytes())?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuditRecord, ProxyActionSummary};
    use uuid::Uuid;

    fn make_records() -> Vec<AuditRecord> {
        vec![
            AuditRecord::new(
                Uuid::new_v4(),
                "file-ops".into(),
                "FileRead".into(),
                &serde_json::json!({"path": "/tmp/test"}),
                1.5,
                ProxyActionSummary::Allow,
                vec![],
                0.8,
                Some("task1".into()),
            ),
            AuditRecord::new(
                Uuid::new_v4(),
                "shell".into(),
                "ShellExec".into(),
                &serde_json::json!({"command": "ls"}),
                5.0,
                ProxyActionSummary::Queue,
                vec![],
                1.2,
                None,
            ),
        ]
    }

    #[test]
    fn test_export_json() {
        let records = make_records();
        let mut buf = Vec::new();
        export_json(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: Vec<AuditRecord> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn test_export_jsonl() {
        let records = make_records();
        let mut buf = Vec::new();
        export_jsonl(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let _: AuditRecord = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn test_export_csv() {
        let records = make_records();
        let mut buf = Vec::new();
        export_csv(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.trim().split('\n').collect();
        // Header + 2 records
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("id,timestamp"));
        assert!(lines[0].contains("filter_scores"));
        assert!(lines[1].contains("file-ops"));
        assert!(lines[2].contains("shell"));
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_build_incident_snapshot() {
        let correlation = CorrelationInfo {
            session_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            source_event: "FileRead(/etc/shadow)".into(),
            age_seconds: 30,
            sink_count: 2,
        };
        let records = make_records();
        let snapshot = build_incident_snapshot(&correlation, records);
        assert_eq!(snapshot.correlation_id, correlation.correlation_id);
        assert_eq!(snapshot.session_id, correlation.session_id);
        assert_eq!(snapshot.records.len(), 2);
        assert_eq!(snapshot.sink_count, 2);
    }

    #[test]
    fn test_export_incident_json() {
        let correlation = CorrelationInfo {
            session_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            source_event: "FileRead(/etc/shadow)".into(),
            age_seconds: 45,
            sink_count: 1,
        };
        let snapshot = build_incident_snapshot(&correlation, make_records());
        let mut buf = Vec::new();
        export_incident_json(&snapshot, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed["incident_id"].is_string());
        assert!(parsed["correlation_id"].is_string());
        assert_eq!(parsed["records"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["source_event"], "FileRead(/etc/shadow)");
    }
}
