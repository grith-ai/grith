// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith audit` subcommand — browse, export, and query audit log records.

use crate::daemon;
use grith_audit::types::AuditRecord;

fn verify_audit_chain(daemon: &daemon::Daemon) -> anyhow::Result<()> {
    let storage = daemon
        .audit_storage
        .lock()
        .map_err(|_| anyhow::anyhow!("audit storage lock poisoned"))?;
    match storage.verify_chain()? {
        grith_audit::ChainVerification::Valid { .. } | grith_audit::ChainVerification::Empty => {
            Ok(())
        }
        grith_audit::ChainVerification::Broken {
            at_sequence,
            record_id,
            reason,
        } => anyhow::bail!(
            "audit chain verification failed at sequence {at_sequence} for record {record_id}: {reason}"
        ),
    }
}

pub(crate) fn recent_entries_verified(
    daemon: &daemon::Daemon,
    count: usize,
) -> anyhow::Result<(usize, Vec<AuditRecord>)> {
    verify_audit_chain(daemon)?;
    let storage = daemon
        .audit_storage
        .lock()
        .map_err(|_| anyhow::anyhow!("audit storage lock poisoned"))?;
    let total = storage.count().unwrap_or(0);
    let recent = storage.get_recent(count).unwrap_or_default();
    Ok((total, recent))
}

pub fn cmd_audit(
    daemon: &daemon::Daemon,
    action: Option<crate::AuditAction>,
) -> anyhow::Result<()> {
    match action {
        None => {
            tracing::info!("browsing audit logs");
            let (count, recent) = recent_entries_verified(daemon, 10)?;
            println!("Audit log: {count} total entries");
            if recent.is_empty() {
                println!("  No audit entries yet.");
            } else {
                for record in &recent {
                    println!(
                        "  [{}] {} {} -> {} (score: {:.1})",
                        record.timestamp.format("%H:%M:%S"),
                        record.plugin_id,
                        record.tool_call_type,
                        record.proxy_action,
                        record.composite_score,
                    );
                }
            }
        }
        Some(crate::AuditAction::Export {
            format,
            offset,
            limit,
        }) => {
            verify_audit_chain(daemon)?;
            tracing::info!(%format, offset, limit, "exporting audit logs");
            let storage = daemon
                .audit_storage
                .lock()
                .map_err(|_| anyhow::anyhow!("audit storage lock poisoned"))?;
            let total = storage.count().unwrap_or(0);
            let records = storage.get_page(offset, limit).unwrap_or_default();
            drop(storage);
            eprintln!(
                "Showing {count} records (offset {offset}, limit {limit}, total {total})",
                count = records.len(),
            );
            match format.as_str() {
                "json" => {
                    let json = serde_json::to_string_pretty(&records)?;
                    println!("{json}");
                }
                "csv" => {
                    println!("timestamp,plugin_id,tool_call_type,decision,score");
                    for r in &records {
                        println!(
                            "{},{},{},{},{:.1}",
                            r.timestamp,
                            r.plugin_id,
                            r.tool_call_type,
                            r.proxy_action,
                            r.composite_score,
                        );
                    }
                }
                other => {
                    eprintln!("Unknown export format: {other}. Use 'json' or 'csv'.");
                }
            }
        }
    }
    Ok(())
}
