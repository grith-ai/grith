// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith audit` subcommand — browse, export, and query audit log records.

use crate::daemon;
use grith_audit::types::AuditRecord;
use std::collections::HashMap;

fn verify_audit_chain(daemon: &daemon::Daemon) -> anyhow::Result<()> {
    // work/74 Phase 5: when startup verification quarantined the chain, say so
    // directly. Re-verifying here would report the same failure with less
    // context, and the operator's next step is recovery, not another read.
    if !daemon.chain_status.is_writable() {
        if let crate::daemon::ChainStatus::Quarantined { reason } = &daemon.chain_status {
            anyhow::bail!(
                "audit chain is quarantined: {reason}\n\n\
                 Every record has been preserved unmodified — grith did not rewrite the chain. \
                 Run `grith audit diagnose` to inspect the break."
            );
        }
    }
    let storage = daemon
        .audit_storage
        .lock()
        .map_err(|_| anyhow::anyhow!("audit storage lock poisoned"))?;
    // Use the cached/incremental verify so post-retention prunes (where
    // chain_sequence no longer starts at 1) still verify correctly via
    // the persisted checkpoint. Operators wanting a full revalidation
    // can call `storage.verify_chain()` directly.
    match storage.cached_verify_chain()? {
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
        // work/74 Phase 6 — genuine discontinuity between archived and active
        // history.
        grith_audit::ChainVerification::AnchorMismatch {
            boundary_sequence,
            expected_prev_hash,
            found_prev_hash,
            first_sequence,
        } => anyhow::bail!(
            "audit archive boundary at sequence {boundary_sequence} expects prev_hash \
             {expected_prev_hash}, but the active segment starts at {first_sequence} with \
             {found_prev_hash:?}. The archived and active histories do not join; records are \
             preserved unmodified."
        ),
        // work/74 §9 — recoverable: the anchor is missing, not the data. The
        // daemon re-derives this from cold storage at startup.
        grith_audit::ChainVerification::Unanchored { first_sequence } => anyhow::bail!(
            "audit chain is unanchored: the active segment starts at sequence {first_sequence} \
             with no archive boundary. Every record is intact — the link to archived history is \
             what is missing. Restart the daemon to re-derive it from cold storage."
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
        Some(crate::AuditAction::Diagnose) => cmd_audit_diagnose(daemon)?,
        Some(crate::AuditAction::Compact { yes }) => cmd_audit_compact(daemon, yes)?,
        Some(crate::AuditAction::RebuildAnalytics { yes }) => {
            cmd_audit_rebuild_analytics(daemon, yes)?;
        }
    }
    Ok(())
}

/// `grith audit rebuild-analytics` — discard and rebuild the derived analytics
/// projection from the active audit database plus the cold archives. A WRITE
/// maintenance op on derived data only — it never modifies audit records —
/// but it still requires exclusive write access (no daemon running) and
/// refuses to touch a quarantined chain's database.
fn cmd_audit_rebuild_analytics(daemon: &daemon::Daemon, yes: bool) -> anyhow::Result<()> {
    // Gate 1: writer ownership. Rebuilding under a live daemon would rewrite
    // the analytics tables out from under the daemon's open handle.
    if !daemon.audit_role.can_write() {
        anyhow::bail!(
            "audit rebuild-analytics needs exclusive write access, but another grith process \
             owns the audit database (the daemon). Stop it first: `grith daemon stop`."
        );
    }
    // Gate 2: no writes of any kind into a quarantined chain's database until
    // the operator has inspected it.
    if let crate::daemon::ChainStatus::Quarantined { reason } = &daemon.chain_status {
        anyhow::bail!(
            "audit chain is quarantined; the analytics rebuild is refused until the chain is \
             inspected. Run `grith audit diagnose`.\n  {reason}"
        );
    }

    // Confirmation: the rebuild discards and rewrites derived data only. A
    // non-interactive invocation without --yes reads an empty line and aborts
    // safely.
    if !yes {
        print!(
            "Rebuild the analytics projection from the audit database and cold archives? \
             Audit records themselves are never modified. [y/N] "
        );
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    // The daemon's retention thread archives to `<audit_dir>/cold/`; rebuild
    // from the same place.
    let cold_dir =
        crate::daemon::config_loader::expand_path(&daemon.config.general.audit_dir).join("cold");

    let mut storage = daemon
        .audit_storage
        .lock()
        .map_err(|_| anyhow::anyhow!("audit storage lock poisoned"))?;
    let processed = storage.rebuild_analytics_from_active_and_cold(&cold_dir)?;
    drop(storage);

    println!("Analytics rebuild complete: {processed} source records processed.");
    Ok(())
}

/// `grith audit compact` — reclaim free pages left by pruning (H-19 residual).
/// A WRITE maintenance op, deliberately manual (never on a timer): it rewrites
/// and atomically swaps the audit database, so it runs only when THIS process
/// owns the writer lock (no daemon running) and the chain is not quarantined.
fn cmd_audit_compact(daemon: &daemon::Daemon, yes: bool) -> anyhow::Result<()> {
    // Gate 1: writer ownership. Compacting under a live daemon would VACUUM the
    // database file out from under the daemon's open handle.
    if !daemon.audit_role.can_write() {
        anyhow::bail!(
            "audit compact needs exclusive write access, but another grith process owns the \
             audit database (the daemon). Stop it first: `grith daemon stop`."
        );
    }
    // Gate 2: never rewrite a quarantined chain — preserve every byte for the
    // operator to inspect.
    if let crate::daemon::ChainStatus::Quarantined { reason } = &daemon.chain_status {
        anyhow::bail!(
            "audit chain is quarantined; compaction is refused so the evidence is preserved \
             unmodified. Run `grith audit diagnose`.\n  {reason}"
        );
    }

    // Confirmation: compaction rewrites the audit database. A non-interactive
    // invocation without --yes reads an empty line and aborts safely.
    if !yes {
        print!("Compact the audit database (rewrites + atomically swaps the file)? [y/N] ");
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let mut storage = daemon
        .audit_storage
        .lock()
        .map_err(|_| anyhow::anyhow!("audit storage lock poisoned"))?;
    // compact() rewrites into a temp copy, verifies its chain, and atomically
    // swaps it in; on any failure the original is left untouched.
    let (before, after) = storage.compact()?;
    drop(storage);

    let file_reclaimed = before
        .total_disk_bytes()
        .saturating_sub(after.total_disk_bytes());
    let free_reclaimed = before.free_bytes.saturating_sub(after.free_bytes);
    println!(
        "Compaction complete.\n  On-disk: {} -> {} bytes ({file_reclaimed} reclaimed)\n  \
         Free pages inside DB: {} -> {} bytes ({free_reclaimed} reclaimed)",
        before.total_disk_bytes(),
        after.total_disk_bytes(),
        before.free_bytes,
        after.free_bytes,
    );
    Ok(())
}

/// `grith audit diagnose` — read-only inspection of the audit chain (work/74
/// Phase 5). This is the command the quarantine messages advertise, so unlike
/// every other audit action it must work *in* the quarantined state and never
/// gates on `verify_audit_chain`.
fn cmd_audit_diagnose(daemon: &daemon::Daemon) -> anyhow::Result<()> {
    // When another process owns the audit database, this one never ran
    // startup verification — so the status below is not its finding to
    // report. Say so rather than printing a "writable" that means nothing.
    // The full verification further down is performed here and read-only, so
    // it remains authoritative either way.
    if !daemon.audit_role.can_write() {
        println!("Audit database owner: another grith process (this check is read-only)");
        println!();
    } else {
        match &daemon.chain_status {
            crate::daemon::ChainStatus::Quarantined { reason } => {
                println!(
                    "Chain status: QUARANTINED (writes refused, records preserved unmodified)"
                );
                println!("  {reason}");
            }
            crate::daemon::ChainStatus::Recovered { boundary_sequence } => {
                println!(
                    "Chain status: writable (archive anchor re-derived at sequence \
                     {boundary_sequence} on startup)"
                );
            }
            crate::daemon::ChainStatus::SegmentDiscontinuity {
                archive_terminal_sequence,
                active_genesis_sequence,
            } => {
                println!("Chain status: writable (history spans 2 segments)");
                println!(
                    "  Archived history ends at sequence {archive_terminal_sequence}; the active \
                     database restarts at sequence {active_genesis_sequence}."
                );
            }
            crate::daemon::ChainStatus::Ready => println!("Chain status: writable"),
        }
    }

    let storage = daemon
        .audit_storage
        .lock()
        .map_err(|_| anyhow::anyhow!("audit storage lock poisoned"))?;

    println!();
    let verification = storage.verify_chain()?;
    let verified_valid = matches!(
        verification,
        grith_audit::ChainVerification::Valid { .. } | grith_audit::ChainVerification::Empty
    );
    match verification {
        grith_audit::ChainVerification::Valid { record_count } => {
            println!("Full verification: VALID — {record_count} records, every hash links.");
        }
        grith_audit::ChainVerification::Empty => {
            println!("Full verification: chain is empty.");
        }
        grith_audit::ChainVerification::Broken {
            at_sequence,
            record_id,
            reason,
        } => {
            println!("Full verification: BROKEN at sequence {at_sequence} (record {record_id})");
            println!("  {reason}");
        }
        grith_audit::ChainVerification::AnchorMismatch {
            boundary_sequence,
            expected_prev_hash,
            found_prev_hash,
            first_sequence,
        } => {
            println!("Full verification: ARCHIVE ANCHOR MISMATCH");
            println!(
                "  The archive boundary at sequence {boundary_sequence} expects prev_hash \
                 {expected_prev_hash}, but the active segment starts at {first_sequence} \
                 with {found_prev_hash:?}."
            );
        }
        grith_audit::ChainVerification::Unanchored { first_sequence } => {
            println!(
                "Full verification: UNANCHORED — the active segment starts at sequence \
                 {first_sequence} with no archive boundary."
            );
            println!("  Restart the daemon to re-derive the anchor from cold storage.");
        }
    }

    // Segment history. A "valid" chain can still be only the newest of
    // several segments; saying "every hash links" without saying how much
    // history that covers would overstate what was checked.
    println!();
    match storage.load_segment_history()? {
        Some(history) => {
            println!("Segments: 2 (history is not one continuous chain)");
            println!(
                "  Archived segment ends at sequence {}{}",
                history.archive_terminal_sequence,
                history
                    .archive_terminal_hash
                    .as_deref()
                    .map(|h| format!(" (hash {h})"))
                    .unwrap_or_default()
            );
            println!(
                "  Active segment begins at sequence {}",
                history.active_genesis_sequence
            );
            println!("  {}", history.reason);
            println!(
                "  Recorded {}",
                history.classified_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }
        None => println!("Segments: 1 (continuous history)"),
    }

    // Fork analysis. Duplicated sequences are the signature of a second
    // writer racing the chain. Branch membership is resolved by walking
    // `prev_hash` links backwards from the record just after each fork: in a
    // sustained fork the losing branch's interior records also have
    // successors (the next loser), so successor-count alone cannot
    // distinguish the branches.
    let forks = storage.duplicate_sequence_records()?;
    println!();
    let mut fork_branch_records = 0usize;
    let mut fork_runs = 0usize;
    let mut clean_fork_shape = true;
    if forks.is_empty() {
        println!("Duplicate sequences: none.");
    } else {
        println!("Duplicate sequences (evidence of a concurrent second writer):");
        let mut groups: Vec<(i64, Vec<&grith_audit::ForkRecord>)> = Vec::new();
        for r in &forks {
            match groups.last_mut() {
                Some((seq, group)) if *seq == r.chain_sequence => group.push(r),
                _ => groups.push((r.chain_sequence, vec![r])),
            }
        }
        // Process maximal runs of consecutive duplicated sequences together —
        // one run is one fork event, however many sequences it spans.
        let mut run_start = 0usize;
        while run_start < groups.len() {
            let mut run_end = run_start;
            while run_end + 1 < groups.len() && groups[run_end + 1].0 == groups[run_end].0 + 1 {
                run_end += 1;
            }
            fork_runs += 1;

            // Walk backwards from the unique record after the run to find
            // the main-chain record at each duplicated sequence. A fork at
            // the chain head has no successor to walk from, so membership
            // stays undetermined there.
            let mut main_chain_ids: HashMap<i64, String> = HashMap::new();
            let mut expected = storage.prev_hash_at(groups[run_end].0 + 1)?;
            for (seq, group) in groups[run_start..=run_end].iter().rev() {
                let winner = expected.as_ref().and_then(|hash| {
                    group
                        .iter()
                        .find(|r| r.record_hash.as_deref() == Some(hash.as_str()))
                });
                match winner {
                    Some(w) => {
                        main_chain_ids.insert(*seq, w.id.clone());
                        expected.clone_from(&w.prev_hash);
                    }
                    None => {
                        clean_fork_shape = false;
                        expected = None;
                    }
                }
            }

            for (seq, group) in &groups[run_start..=run_end] {
                println!("  sequence {seq}:");
                for r in group {
                    let hash = r.record_hash.as_deref().unwrap_or("-");
                    let membership = match main_chain_ids.get(seq) {
                        Some(id) if *id == r.id => "on the main chain",
                        Some(_) => {
                            fork_branch_records += 1;
                            "ABANDONED FORK BRANCH — not part of the main chain"
                        }
                        None => "branch membership undetermined",
                    };
                    println!(
                        "    {}  {}  hash {:.12}…  {}",
                        r.id, r.timestamp, hash, membership
                    );
                }
            }
            run_start = run_end + 1;
        }
    }

    let gaps = storage.sequence_gaps(10)?;
    if gaps.is_empty() {
        println!("Sequence gaps: none.");
    } else {
        println!("Sequence gaps (up to 10 shown):");
        for (before, after) in &gaps {
            println!("  {before} → {after} ({} missing)", after - before - 1);
        }
    }
    drop(storage);

    println!();
    if verified_valid && forks.is_empty() && gaps.is_empty() {
        println!("Assessment: no integrity problems detected.");
        if !daemon.chain_status.is_writable() {
            println!(
                "  The quarantine reflects the chain state at daemon startup; \
                 restart the daemon to re-verify and clear it."
            );
        }
    } else if fork_runs > 0 && clean_fork_shape && gaps.is_empty() {
        let events = if fork_runs == 1 {
            "one fork event".to_string()
        } else {
            format!("{fork_runs} fork events")
        };
        println!(
            "Assessment: your audit history is intact. A second process wrote to the \
             audit log at the same time as the daemon ({events}), leaving \
             {fork_branch_records} extra record(s) on abandoned branches. The main \
             chain is complete and unbroken — no records are missing."
        );
        println!(
            "  All records, including the abandoned-branch ones, are preserved \
             unmodified. Back up the audit directory before any manual intervention."
        );
    } else {
        println!(
            "Assessment: the audit chain has integrity problems that need manual review. \
             Nothing has been altered — every record is preserved exactly as written. \
             Back up the audit directory before any intervention."
        );
    }
    Ok(())
}
