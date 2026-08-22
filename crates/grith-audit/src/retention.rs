// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Retention + cold-storage archival for the audit DB.
//!
//! Stage 2 of audit-completeness-scaling W0. Periodically prunes a
//! contiguous prefix of the hash chain (rows older than `retain_days`)
//! from the active DB, optionally writing the deleted rows to
//! `<audit_dir>/cold/YYYY-MM-DD.jsonl.zst` for offline forensics.
//!
//! Chain integrity: prune updates the `chain_metadata` checkpoint to the
//! head of the deleted range so incremental verify seeds from the boundary
//! hash and the remaining chain still validates. Compact rows share the
//! same cutoff as full rows until dual-chain support lands (W2 follow-up).

use crate::error::Result;
use crate::export::export_jsonl;
use crate::storage::AuditStorage;
use crate::types::{ArchiveBoundary, AuditRecord, LEGACY_HASH_VERSION};
use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

/// Outcome of one prune-and-archive run.
#[derive(Debug, Clone, Default)]
pub struct PruneStats {
    /// Number of rows removed from the active DB.
    pub archived_rows: usize,
    /// Number of date-partitioned archive files written or appended.
    pub archive_files: usize,
    /// Highest chain_sequence that was pruned (0 if nothing).
    pub max_pruned_sequence: i64,
}

/// Run a single prune-and-archive pass.
///
/// - `cutoff`: rows whose `timestamp < cutoff` are eligible.
/// - `cold_dir`: where to write archives. Created if missing.
/// - `cold_storage_enabled`: when false, rows are deleted without writing
///   archives (useful for tests / explicit operator opt-out).
/// - `respect_sync_state`: when true, never prune past the highest
///   chain_sequence whose `synced_at IS NOT NULL`. Protects unsynced
///   rows from being archived before they reach the grith.ai cloud
///   API for pro/teams sync. Wire it from `general.audit_sync` in the
///   daemon — `true` keeps the safety net on, `false` lets fully-local
///   deployments prune time-based only.
pub fn prune_and_archive(
    storage: &mut AuditStorage,
    cutoff: DateTime<Utc>,
    cold_dir: &Path,
    cold_storage_enabled: bool,
    respect_sync_state: bool,
) -> Result<PruneStats> {
    // With cold storage disabled the user has chosen age-based deletion
    // without archives; honouring the configured retention window matters
    // more than forcing archives they opted out of (a silent no-op would
    // grow the active database forever while the docs promise 30 days).
    // Deletion still never outruns the analytics projection: the coverage
    // gate below holds in both modes, so every pruned row was materialized
    // first.
    if !cold_storage_enabled {
        tracing::info!(
            "audit retention: cold storage is disabled; pruned rows are deleted without an archive"
        );
    }

    // The writer-lock owner catches the projection up before calculating a
    // deletion boundary. Projection snapshot acknowledgements and archive
    // acknowledgements are intentionally not consulted here: local materialized
    // coverage plus a verified cold file are the two independent requirements.
    storage.catch_up_analytics()?;
    // 1. Find the highest chain_sequence whose timestamp is strictly
    //    older than `cutoff`. We delete a contiguous prefix
    //    [1..=max_pruned_sequence]. Rows with NULL chain_sequence (the
    //    legacy backfill case) are not touched here; backfill on
    //    startup gives them sequences before this runs.
    let conn = storage.connection_mut();
    let time_max: Option<i64> = conn
        .query_row(
            "SELECT MAX(chain_sequence) FROM audit_log \
             WHERE chain_sequence IS NOT NULL AND timestamp < ?1",
            rusqlite::params![cutoff.to_rfc3339()],
            |row| row.get(0),
        )
        .ok()
        .flatten();
    let Some(time_max_sequence) = time_max else {
        return Ok(PruneStats::default());
    };
    if time_max_sequence <= 0 {
        return Ok(PruneStats::default());
    }

    // 2. When the daemon has audit_sync enabled, additionally clamp at
    //    the highest fully-synced chain_sequence. Unsynced rows are
    //    always a chronological *suffix* (rows insert in order; offline
    //    rows are the most recent), so clamping preserves the
    //    contiguous-prefix invariant the chain checkpoint relies on.
    //    A long offline period (>retain_full_days) thus delays the
    //    prune rather than losing unsynced data.
    //    work/74 Phase 8: use the highest CONTIGUOUSLY synced sequence, not
    //    MAX(synced). `MAX` is only safe while synced rows are guaranteed to
    //    form an unbroken prefix; a retry, an out-of-order acknowledgement,
    //    an import, or any future parallel sync creates a synced row above an
    //    unsynced gap, and `MAX` would then authorise archiving the unsynced
    //    rows below it. The contiguous boundary is `first unsynced - 1`.
    let max_pruned_sequence = if respect_sync_state {
        let first_unsynced: Option<i64> = conn
            .query_row(
                "SELECT MIN(chain_sequence) FROM audit_log \
                 WHERE chain_sequence IS NOT NULL AND synced_at IS NULL",
                [],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        let synced_prefix_max = match first_unsynced {
            // Everything below the first unsynced row is safe to prune.
            Some(gap) => gap - 1,
            // No unsynced rows at all: the whole chain is acknowledged.
            None => conn
                .query_row(
                    "SELECT MAX(chain_sequence) FROM audit_log \
                     WHERE chain_sequence IS NOT NULL",
                    [],
                    |row| row.get(0),
                )
                .ok()
                .flatten()
                .unwrap_or(0),
        };
        if synced_prefix_max <= 0 {
            // Nothing acknowledged yet — either the user has not logged in /
            // activated a plan, or sync is broken. Either way we must not
            // archive rows the server has never seen.
            return Ok(PruneStats::default());
        }
        time_max_sequence.min(synced_prefix_max)
    } else {
        time_max_sequence
    };
    if max_pruned_sequence <= 0 {
        return Ok(PruneStats::default());
    }
    if !storage.analytics_covers_sequence(max_pruned_sequence)? {
        tracing::warn!(
            max_pruned_sequence,
            "audit retention skipped: analytics projection has not atomically covered the prefix"
        );
        return Ok(PruneStats::default());
    }

    // 3. Archive BEFORE deleting.
    //
    //    The original order drained (and committed the DELETE) first and wrote
    //    the archive afterwards. A crash, a full disk, or a permissions error
    //    in between destroyed those rows with no archive to show for them —
    //    and, now that prune also writes the durable boundary anchor, would
    //    leave that anchor naming a record present in neither the active
    //    database nor cold storage, which verification would correctly report
    //    as an unrecoverable discontinuity.
    //
    //    Writing the archive first makes the failure mode benign: a crash
    //    leaves rows in both places, and the next prune re-appends them. The
    //    archive reader tolerates that (see `read_zstd_jsonl`, concatenated
    //    frames), and duplicate archived rows are strictly safer than lost
    //    ones.
    let mut by_date: BTreeMap<String, Vec<AuditRecord>> = BTreeMap::new();
    let mut count = 0usize;
    storage.read_prefix_into(max_pruned_sequence, |record| {
        count += 1;
        if cold_storage_enabled {
            let date_key = record.timestamp.format("%Y-%m-%d").to_string();
            by_date.entry(date_key).or_default().push(record.clone());
        }
        Ok(())
    })?;

    if count == 0 {
        return Ok(PruneStats::default());
    }

    let mut archive_files = 0usize;
    if cold_storage_enabled && !by_date.is_empty() {
        fs::create_dir_all(cold_dir)?;
        for (date_key, records) in &by_date {
            let path = cold_dir.join(format!("{date_key}.jsonl.zst"));
            append_zstd_jsonl(&path, records)?;
            prove_archived_records(&path, records)?;
            archive_files += 1;
        }
    }

    // 4. Only now that the rows are durably archived, delete them and publish
    //    the boundary anchor.
    let deleted = storage.delete_prefix(max_pruned_sequence)?;
    debug_assert_eq!(deleted, count, "archived and deleted row counts must agree");

    Ok(PruneStats {
        archived_rows: count,
        archive_files,
        max_pruned_sequence,
    })
}

/// Prove that every just-appended row can be read back from cold storage with
/// the same stored hash and a valid record-content hash before any active row
/// is deleted. Concatenated frames may contain older duplicates, so identity
/// is keyed by event id rather than by file position.
fn prove_archived_records(path: &Path, expected: &[AuditRecord]) -> Result<()> {
    let restored = read_zstd_jsonl(path)?;
    let by_id: std::collections::HashMap<_, _> =
        restored.iter().map(|record| (record.id, record)).collect();
    for record in expected {
        let Some(cold) = by_id.get(&record.id) else {
            return Err(crate::error::Error::Analytics(format!(
                "cold archive {} did not contain appended record {}",
                path.display(),
                record.id
            )));
        };
        let recomputed = cold.compute_record_hash();
        if cold.record_hash != record.record_hash
            || cold.record_hash.as_deref() != Some(recomputed.as_str())
        {
            return Err(crate::error::Error::Analytics(format!(
                "cold archive {} failed hash proof for record {}",
                path.display(),
                record.id
            )));
        }
    }
    Ok(())
}

/// Append `records` to an existing `<date>.jsonl.zst` archive, or create
/// a new one if absent.
///
/// zstd supports concatenated frames, so we open the file in append mode
/// and write a new compressed frame per call. Readers (`read_zstd_jsonl`)
/// decode all frames transparently.
fn append_zstd_jsonl(path: &Path, records: &[AuditRecord]) -> Result<()> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let mut writer = BufWriter::new(file);
    {
        // Level 3 is the default zstd preset — good ratio + cheap. Audit
        // JSON compresses 8-12× at this level; bumping higher buys <10%
        // ratio for 2-4× CPU.
        let mut encoder = zstd::stream::Encoder::new(&mut writer, 3)?;
        export_jsonl(records, &mut encoder)?;
        encoder.finish()?;
    }
    writer.flush()?;
    Ok(())
}

/// Read every record from a date-partitioned archive.
///
/// Returns an empty Vec if the file doesn't exist. Decodes all
/// concatenated zstd frames so multi-append archives round-trip cleanly.
pub fn read_zstd_jsonl(path: &Path) -> Result<Vec<AuditRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(path)?;
    let decoder = zstd::stream::Decoder::new(file)?;
    let reader = std::io::BufReader::new(decoder);
    let mut out = Vec::new();
    for line in std::io::BufRead::lines(reader) {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditRecord = serde_json::from_str(&line)?;
        out.push(record);
    }
    Ok(out)
}

/// Enumerate every archive file in `cold_dir`, returning their paths
/// sorted by date (oldest first). Non-archive files are ignored.
pub fn list_archive_files(cold_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(cold_dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".jsonl.zst"))
        })
        .collect();
    paths.sort();
    paths
}

/// Re-derive the archive boundary anchor by reading cold storage.
///
/// work/74 Phase 5/6 recovery path. When the active segment starts above
/// sequence 1 but carries no [`ArchiveBoundary`] — the state of every
/// database written before Phase 6, and of any database whose
/// `chain_metadata` was lost — this reconstructs the anchor from the
/// archives themselves rather than quarantining or (as before) renumbering.
///
/// The archives are the source of truth: each holds complete records
/// including `chain_sequence` and `record_hash`. We look for the record
/// immediately preceding the active segment and confirm the active segment's
/// first `prev_hash` links to it.
///
/// Returns:
/// - `Ok(Some(boundary))` — the predecessor was found and it links. Caller
///   should persist it with [`AuditStorage::store_archive_boundary`].
/// - `Ok(None)` — no archive holds the predecessor. The caller must NOT
///   invent an anchor; quarantine and require explicit operator recovery.
/// - `Err(..)` — the archives could not be read.
///
/// A predecessor that is found but does *not* link is reported as `None`
/// too: a mismatching hash is discontinuity evidence, and silently adopting
/// it would launder exactly the break we are trying to surface. The caller
/// distinguishes the two cases by inspecting `mismatch`.
pub fn resolve_boundary_from_archives(
    cold_dir: &Path,
    first_active_sequence: i64,
    first_active_prev_hash: Option<&str>,
) -> Result<BoundaryResolution> {
    if first_active_sequence <= 1 {
        return Ok(BoundaryResolution::NotNeeded);
    }
    let target_sequence = first_active_sequence - 1;

    // Newest archives first: the predecessor is almost always in the most
    // recently written partition, so this short-circuits after one file in
    // the common case.
    let mut files = list_archive_files(cold_dir);
    files.reverse();

    for path in files {
        let records = read_zstd_jsonl(&path)?;
        let Some(predecessor) = records
            .iter()
            .find(|r| r.chain_sequence == Some(target_sequence))
        else {
            continue;
        };
        let Some(archived_hash) = predecessor.record_hash.as_deref() else {
            // An archived record with no hash cannot anchor anything.
            return Ok(BoundaryResolution::Unresolved);
        };
        // B12 item 6: recompute the predecessor rather than trusting the
        // hash text stored beside it. Adopting a stored hash unverified
        // would let anyone who can edit a cold archive mint an anchor for
        // a forged active segment — the archive is a plain file on disk,
        // so its hash text is exactly as editable as its content.
        //
        // B12 #71 (residual): `compute_record_hash` dispatches on each
        // record's own `hash_version`. A record archived under the legacy
        // v1 hash is re-verified with the v1 canonical form, which covers
        // only nine fields (id, timestamp, session_id, plugin_id,
        // tool_call_type, arguments_hash, composite_score, proxy_action,
        // prev_hash). Tampering confined to any *other* field of a v1
        // archived record — decision_reason, enforcement_outcome,
        // record_type, the forensic spawn/listener columns, and the rest —
        // is NOT detected by this recompute. The gap cannot be closed
        // without rewriting the archived record to a v2 hash, and rewriting
        // archived evidence is precisely what this module refuses to do.
        // Fail-safe: we still anchor (refusing would brick retention on
        // every pre-v2 deployment) but flag the reduced assurance below so
        // the anchor never silently rests on weaker coverage.
        let recomputed = predecessor.compute_record_hash();
        if recomputed != archived_hash {
            return Ok(BoundaryResolution::TamperedArchive {
                boundary_sequence: target_sequence,
                stored_hash: archived_hash.to_string(),
                recomputed_hash: recomputed,
                archive: path.display().to_string(),
            });
        }
        // The predecessor is authentic; confirm the archive segment it sits
        // in is internally consistent too, so a boundary is never derived
        // from a file whose interior links have been rewritten.
        if let Some(break_at) = first_internal_break(&records) {
            return Ok(BoundaryResolution::TamperedArchive {
                boundary_sequence: break_at,
                stored_hash: String::new(),
                recomputed_hash: String::new(),
                archive: path.display().to_string(),
            });
        }
        if first_active_prev_hash != Some(archived_hash) {
            return Ok(BoundaryResolution::Mismatch {
                boundary_sequence: target_sequence,
                archived_hash: archived_hash.to_string(),
                found_prev_hash: first_active_prev_hash.map(str::to_string),
            });
        }
        // B12 #71: surface reduced tamper-assurance when the anchor — or any
        // chained record in the segment it sits in — was hashed under the
        // legacy v1 form (see the residual note above). Fail-safe: we still
        // anchor, but never silently.
        let legacy_records = records
            .iter()
            .filter(|r| r.chain_sequence.is_some() && r.hash_version == LEGACY_HASH_VERSION)
            .count();
        if legacy_records > 0 {
            tracing::warn!(
                boundary_sequence = target_sequence,
                anchor_hash_version = predecessor.hash_version,
                legacy_records,
                archive = %path.display(),
                "audit boundary anchored to a cold archive containing legacy v1 records; the \
                 v1 hash covers only nine fields, so tampering confined to the remaining \
                 fields of those archived records is not detected here (residual: cannot be \
                 closed without rewriting archived evidence, which is forbidden)"
            );
        }
        return Ok(BoundaryResolution::Resolved(ArchiveBoundary {
            last_archived_sequence: target_sequence,
            last_archived_record_hash: archived_hash.to_string(),
            updated_at: Utc::now(),
        }));
    }

    Ok(BoundaryResolution::Unresolved)
}

/// Highest `chain_sequence` held across all cold archives, with that
/// record's stored hash.
///
/// Used to describe the archived prefix when classifying a multi-segment
/// history (B12 item 7). Returns `None` when no archive holds a chained
/// record.
pub fn archive_terminal_record(cold_dir: &Path) -> Result<Option<(i64, Option<String>)>> {
    let mut best: Option<(i64, Option<String>)> = None;
    for path in list_archive_files(cold_dir) {
        for record in read_zstd_jsonl(&path)? {
            let Some(seq) = record.chain_sequence else {
                continue;
            };
            if best.as_ref().is_none_or(|(b, _)| seq > *b) {
                best = Some((seq, record.record_hash.clone()));
            }
        }
    }
    Ok(best)
}

/// Walk an archive segment's internal `prev_hash` links and recompute each
/// record's hash, returning the sequence of the first inconsistency.
///
/// Records are compared in `chain_sequence` order. Rows without a sequence
/// are pre-chaining legacy rows and are skipped rather than treated as
/// evidence of tampering. A gap between consecutive sequences is expected —
/// an archive partition need not be contiguous with its neighbours — so
/// only the hash of each record and the link between *adjacent archived*
/// records is checked.
fn first_internal_break(records: &[AuditRecord]) -> Option<i64> {
    let mut chained: Vec<&AuditRecord> = records
        .iter()
        .filter(|r| r.chain_sequence.is_some())
        .collect();
    chained.sort_by_key(|r| r.chain_sequence);

    let mut prev: Option<&AuditRecord> = None;
    for record in chained {
        let seq = record.chain_sequence.unwrap_or_default();
        if record.record_hash.as_deref() != Some(record.compute_record_hash().as_str()) {
            return Some(seq);
        }
        if let Some(p) = prev {
            let contiguous = p.chain_sequence.map(|s| s + 1) == Some(seq);
            if contiguous && record.prev_hash != p.record_hash {
                return Some(seq);
            }
        }
        prev = Some(record);
    }
    None
}

/// Outcome of [`resolve_boundary_from_archives`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryResolution {
    /// The active segment starts at sequence 1; it needs no anchor.
    NotNeeded,
    /// The archive that holds the predecessor is itself inconsistent: a
    /// record's stored hash does not match its recomputed content, or the
    /// segment's internal links do not hold. No anchor may be derived from
    /// it — this is tamper evidence about the archive, not about the
    /// active segment.
    TamperedArchive {
        /// Sequence at which the inconsistency was found.
        boundary_sequence: i64,
        /// Hash text stored beside the record (empty for an internal-link
        /// break, where the failure is not a single record's own hash).
        stored_hash: String,
        /// Hash recomputed from the record's content (empty likewise).
        recomputed_hash: String,
        /// Archive file the inconsistency was found in.
        archive: String,
    },
    /// The predecessor was found in cold storage and links correctly.
    Resolved(ArchiveBoundary),
    /// The predecessor was found but its hash does not match the active
    /// segment's `prev_hash`. Genuine discontinuity — do not adopt.
    Mismatch {
        /// Sequence of the archived record that should have linked.
        boundary_sequence: i64,
        /// `record_hash` found in cold storage.
        archived_hash: String,
        /// `prev_hash` carried by the first active row.
        found_prev_hash: Option<String>,
    },
    /// No archive contains the predecessor record.
    Unresolved,
}

/// Compute the absolute cutoff timestamp from a "retain N days" value.
/// Returns `None` when `retain_days == 0` (retention disabled).
pub fn cutoff_for_retention(retain_days: u32) -> Option<DateTime<Utc>> {
    if retain_days == 0 {
        return None;
    }
    Some(Utc::now() - Duration::days(i64::from(retain_days)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuditRecord, ChainVerification, ProxyActionSummary};
    use chrono::TimeZone;
    use uuid::Uuid;

    fn record_at(ts: DateTime<Utc>) -> AuditRecord {
        let mut r = AuditRecord::new(
            Uuid::new_v4(),
            "test".into(),
            "FileRead".into(),
            &serde_json::json!({"path": "/tmp/x"}),
            1.0,
            ProxyActionSummary::Allow,
            vec![],
            0.5,
            None,
        );
        r.timestamp = ts;
        r
    }

    #[test]
    fn prune_with_empty_db_returns_zero() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let stats = prune_and_archive(&mut storage, Utc::now(), dir.path(), true, false).unwrap();
        assert_eq!(stats.archived_rows, 0);
        assert_eq!(stats.archive_files, 0);
    }

    #[test]
    fn prune_archives_then_deletes_chain_prefix() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let old = Utc.with_ymd_and_hms(2020, 1, 15, 12, 0, 0).unwrap();
        let recent = Utc::now();
        for _ in 0..3 {
            storage.insert_record(&record_at(old)).unwrap();
        }
        for _ in 0..2 {
            storage.insert_record(&record_at(recent)).unwrap();
        }
        assert_eq!(storage.count().unwrap(), 5);

        let dir = tempfile::tempdir().unwrap();
        let cutoff = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let stats = prune_and_archive(&mut storage, cutoff, dir.path(), true, false).unwrap();
        assert_eq!(stats.archived_rows, 3);
        assert_eq!(stats.archive_files, 1);
        assert_eq!(stats.max_pruned_sequence, 3);
        assert_eq!(storage.count().unwrap(), 2);

        // Archive round-trips.
        let archive_path = dir.path().join("2020-01-15.jsonl.zst");
        assert!(archive_path.exists());
        let restored = read_zstd_jsonl(&archive_path).unwrap();
        assert_eq!(restored.len(), 3);

        // Chain still verifies — checkpoint seeds from the deleted-prefix head.
        let v = storage.incremental_verify_chain().unwrap();
        assert_eq!(v, ChainVerification::Valid { record_count: 5 });
    }

    // =======================================================================
    // work/74 §9 — post-retention verification without a checkpoint.
    //
    // The test directly above proves the happy path: after pruning, the
    // `verified_head` checkpoint anchors the surviving suffix and the chain
    // verifies. That checkpoint is a performance cache and `repair_chain()`
    // deletes it, so it cannot be the authority for "this segment starts
    // above sequence 1" — relying on it is what severed the production chain
    // on 2026-07-28 (archive ended at 126575, active renumbered to 1 with a
    // NULL prev_hash).
    //
    // Phase 6 adds a DURABLE `ArchiveBoundary` anchor written atomically with
    // the prune. These tests cover the anchor and every state around it.
    // =======================================================================

    /// Seed `old_count` prunable records plus `keep_count` recent ones, prune
    /// the old prefix into `dir`, then drop the verification checkpoint —
    /// leaving a valid segment whose only remaining anchor is the durable
    /// archive boundary.
    fn pruned_storage_without_checkpoint(
        dir: &std::path::Path,
        old_count: usize,
        keep_count: usize,
    ) -> AuditStorage {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let old = Utc.with_ymd_and_hms(2020, 1, 15, 12, 0, 0).unwrap();
        let recent = Utc.with_ymd_and_hms(2030, 6, 1, 12, 0, 0).unwrap();
        for _ in 0..old_count {
            storage.insert_record(&record_at(old)).unwrap();
        }
        for _ in 0..keep_count {
            storage.insert_record(&record_at(recent)).unwrap();
        }

        let cutoff = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let stats = prune_and_archive(&mut storage, cutoff, dir, true, false).unwrap();
        assert_eq!(
            stats.max_pruned_sequence, old_count as i64,
            "precondition: the old prefix should have been archived"
        );

        // Lose the performance checkpoint. `repair_chain()` does exactly this,
        // and a restored backup or an interrupted write reaches the same state.
        storage
            .connection()
            .execute("DELETE FROM chain_metadata WHERE key = 'verified_head'", [])
            .unwrap();
        storage
    }

    /// work/74 §9 REGRESSION. This is the test that would have prevented the
    /// production chain severance. It must never be deleted or weakened.
    #[test]
    fn post_retention_without_checkpoint_verifies_valid() {
        let dir = tempfile::tempdir().unwrap();
        let storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);

        // Losing the checkpoint costs a fast path, not integrity. The durable
        // boundary anchors the surviving suffix.
        let verification = storage.incremental_verify_chain().unwrap();
        assert_eq!(
            verification,
            ChainVerification::Valid { record_count: 5 },
            "a pruned chain with no checkpoint must verify as Valid, not Broken"
        );

        // And nothing was rewritten: still sequences 4 and 5, still linked.
        let (first_seq, first_prev): (i64, Option<String>) = storage
            .connection()
            .query_row(
                "SELECT chain_sequence, prev_hash FROM audit_log \
                 WHERE chain_sequence IS NOT NULL ORDER BY chain_sequence ASC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            first_seq, 4,
            "verification must not renumber a valid suffix"
        );
        assert!(
            first_prev.is_some(),
            "the link to the archived prefix must be preserved"
        );
    }

    #[test]
    fn prune_writes_a_durable_archive_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);

        let boundary = storage
            .load_archive_boundary()
            .unwrap()
            .expect("prune must write a durable boundary anchor");
        assert_eq!(boundary.last_archived_sequence, 3);

        // The anchor must name the archived terminal record.
        let archived = read_zstd_jsonl(&dir.path().join("2020-01-15.jsonl.zst")).unwrap();
        let terminal = archived.last().unwrap();
        assert_eq!(terminal.chain_sequence, Some(3));
        assert_eq!(
            Some(boundary.last_archived_record_hash.as_str()),
            terminal.record_hash.as_deref()
        );
    }

    /// The anchor must survive `repair_chain()`. The checkpoint does not —
    /// that asymmetry is the entire point of Phase 6.
    #[test]
    fn archive_boundary_survives_repair_chain() {
        let dir = tempfile::tempdir().unwrap();
        let storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);
        let before = storage.load_archive_boundary().unwrap().unwrap();

        storage.repair_chain().unwrap();

        let after = storage
            .load_archive_boundary()
            .unwrap()
            .expect("repair must not delete the durable boundary");
        assert_eq!(before, after);
    }

    /// A boundary that does not link is genuine discontinuity evidence and
    /// must be reported as such — never silently adopted or repaired.
    #[test]
    fn boundary_that_does_not_link_reports_anchor_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);

        storage
            .store_archive_boundary(&crate::types::ArchiveBoundary {
                last_archived_sequence: 3,
                last_archived_record_hash:
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                updated_at: Utc::now(),
            })
            .unwrap();

        match storage.incremental_verify_chain().unwrap() {
            ChainVerification::AnchorMismatch {
                boundary_sequence,
                first_sequence,
                ..
            } => {
                assert_eq!(boundary_sequence, 3);
                assert_eq!(first_sequence, 4);
            }
            other => panic!("expected AnchorMismatch, got {other:?}"),
        }
    }

    /// No checkpoint AND no boundary: recoverable, not tampering. Must report
    /// `Unanchored` so the daemon can rebuild from archives instead of
    /// renumbering.
    #[test]
    fn missing_boundary_reports_unanchored_not_broken() {
        let dir = tempfile::tempdir().unwrap();
        let storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);
        storage
            .connection()
            .execute(
                "DELETE FROM chain_metadata WHERE key = 'archive_boundary'",
                [],
            )
            .unwrap();

        let v = storage.incremental_verify_chain().unwrap();
        assert_eq!(v, ChainVerification::Unanchored { first_sequence: 4 });
        assert!(!v.is_tamper_evidence(), "a missing anchor is not evidence");
        assert!(!v.is_healthy(), "but it is not healthy either");
    }

    /// The recovery path: rebuild the anchor by reading cold storage.
    #[test]
    fn boundary_is_recoverable_from_cold_archives() {
        let dir = tempfile::tempdir().unwrap();
        let storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);
        storage
            .connection()
            .execute(
                "DELETE FROM chain_metadata WHERE key = 'archive_boundary'",
                [],
            )
            .unwrap();

        let (first_seq, first_prev) = storage.first_chained_row().unwrap().unwrap();
        let resolution =
            resolve_boundary_from_archives(dir.path(), first_seq, first_prev.as_deref()).unwrap();

        let BoundaryResolution::Resolved(boundary) = resolution else {
            panic!("expected the predecessor to be recoverable, got {resolution:?}");
        };
        assert_eq!(boundary.last_archived_sequence, 3);

        // Persisting it restores normal verification with no row rewritten.
        storage.store_archive_boundary(&boundary).unwrap();
        assert_eq!(
            storage.incremental_verify_chain().unwrap(),
            ChainVerification::Valid { record_count: 5 }
        );
    }

    /// Recovery must refuse to launder a real break: a predecessor whose hash
    /// disagrees is reported as a mismatch, not adopted.
    #[test]
    fn boundary_recovery_refuses_a_mismatching_predecessor() {
        let dir = tempfile::tempdir().unwrap();
        let _storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);

        let resolution = resolve_boundary_from_archives(dir.path(), 4, Some("deadbeef")).unwrap();
        assert!(
            matches!(
                resolution,
                BoundaryResolution::Mismatch {
                    boundary_sequence: 3,
                    ..
                }
            ),
            "expected Mismatch, got {resolution:?}"
        );
    }

    #[test]
    fn boundary_recovery_reports_unresolved_when_archives_lack_the_predecessor() {
        let empty = tempfile::tempdir().unwrap();
        let resolution = resolve_boundary_from_archives(empty.path(), 4, Some("abc")).unwrap();
        assert_eq!(resolution, BoundaryResolution::Unresolved);
    }

    /// B12 item 6: the boundary must be *verified*, not merely read.
    ///
    /// Rewrite an archived record's content while leaving its stored hash
    /// alone — the shape produced by anyone who can edit a cold archive
    /// file, which is a plain file on disk. The old code adopted the stored
    /// hash text and minted a valid-looking anchor from tampered history.
    #[test]
    fn boundary_recovery_rejects_an_archive_whose_content_was_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);
        let (first_seq, first_prev) = storage.first_chained_row().unwrap().unwrap();

        // Sanity: it resolves cleanly before tampering.
        assert!(matches!(
            resolve_boundary_from_archives(dir.path(), first_seq, first_prev.as_deref()).unwrap(),
            BoundaryResolution::Resolved(_)
        ));

        // Rewrite the predecessor's content, keeping its stored record_hash.
        let archive = list_archive_files(dir.path()).pop().expect("an archive");
        let mut records = read_zstd_jsonl(&archive).unwrap();
        for r in &mut records {
            if r.chain_sequence == Some(3) {
                r.tool_call_type = "ShellExec".into();
                r.arguments_summary = "rm -rf /".into();
            }
        }
        rewrite_archive_for_test(&archive, &records);

        let resolution =
            resolve_boundary_from_archives(dir.path(), first_seq, first_prev.as_deref()).unwrap();
        assert!(
            matches!(
                resolution,
                BoundaryResolution::TamperedArchive {
                    boundary_sequence: 3,
                    ..
                }
            ),
            "expected TamperedArchive, got {resolution:?}"
        );
    }

    /// The predecessor itself can be authentic while an *earlier* record in
    /// the same archive has been rewritten. Deriving a boundary from such a
    /// file would vouch for history that no longer verifies.
    #[test]
    fn boundary_recovery_rejects_an_archive_with_a_broken_interior() {
        let dir = tempfile::tempdir().unwrap();
        let storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);
        let (first_seq, first_prev) = storage.first_chained_row().unwrap().unwrap();

        let archive = list_archive_files(dir.path()).pop().expect("an archive");
        let mut records = read_zstd_jsonl(&archive).unwrap();
        // Tamper with an interior record, not the predecessor at seq 3.
        for r in &mut records {
            if r.chain_sequence == Some(1) {
                r.tool_call_type = "ShellExec".into();
            }
        }
        rewrite_archive_for_test(&archive, &records);

        let resolution =
            resolve_boundary_from_archives(dir.path(), first_seq, first_prev.as_deref()).unwrap();
        assert!(
            matches!(resolution, BoundaryResolution::TamperedArchive { .. }),
            "expected TamperedArchive for a broken interior, got {resolution:?}"
        );
    }

    /// An untampered archive still resolves — the added verification must
    /// not make legitimate recovery impossible.
    #[test]
    fn boundary_recovery_still_succeeds_on_an_intact_archive() {
        let dir = tempfile::tempdir().unwrap();
        let storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);
        storage
            .connection()
            .execute(
                "DELETE FROM chain_metadata WHERE key = 'archive_boundary'",
                [],
            )
            .unwrap();
        let (first_seq, first_prev) = storage.first_chained_row().unwrap().unwrap();

        let BoundaryResolution::Resolved(boundary) =
            resolve_boundary_from_archives(dir.path(), first_seq, first_prev.as_deref()).unwrap()
        else {
            panic!("intact archive must still resolve");
        };
        assert_eq!(boundary.last_archived_sequence, 3);
    }

    /// B12 #71: a boundary anchored to a *legacy v1* archive still resolves
    /// (fail-safe — refusing would brick retention on every pre-v2 machine),
    /// but the verification it rests on covers only the nine v1 fields. This
    /// test pins both halves of that contract: recovery succeeds, tampering a
    /// v1-*covered* field is still caught, and — the documented residual —
    /// tampering a v1-*uncovered* field of a v1 record is NOT caught. The
    /// resolve path emits a `tracing::warn!` when it anchors to such a
    /// segment (asserted structurally by the successful resolution here).
    #[test]
    fn v1_archive_anchors_fail_safe_and_leaves_a_documented_residual() {
        let dir = tempfile::tempdir().unwrap();
        let _storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);
        let archive = list_archive_files(dir.path()).pop().expect("an archive");

        // Downgrade the whole archived segment to a consistent v1 chain and
        // take the (new) predecessor hash the active segment would link to.
        let mut records = read_zstd_jsonl(&archive).unwrap();
        downgrade_archive_to_v1(&mut records);
        let predecessor_hash = records
            .iter()
            .find(|r| r.chain_sequence == Some(3))
            .and_then(|r| r.record_hash.clone())
            .expect("predecessor hash");
        rewrite_archive_for_test(&archive, &records);

        // (1) Fail-safe: a clean v1 archive still anchors.
        let BoundaryResolution::Resolved(boundary) =
            resolve_boundary_from_archives(dir.path(), 4, Some(&predecessor_hash)).unwrap()
        else {
            panic!("a clean v1 archive must still resolve (fail-safe anchoring)");
        };
        assert_eq!(boundary.last_archived_sequence, 3);

        // (2) Residual: tamper a field the v1 hash does NOT cover
        // (decision_reason) while leaving record_hash untouched. The v1
        // recompute omits this field, so the tamper is undetected and the
        // boundary still resolves. This is the accepted, documented gap.
        let mut tampered = records.clone();
        for r in &mut tampered {
            if r.chain_sequence == Some(3) {
                r.decision_reason = Some("silently rewritten".into());
            }
        }
        rewrite_archive_for_test(&archive, &tampered);
        assert!(
            matches!(
                resolve_boundary_from_archives(dir.path(), 4, Some(&predecessor_hash)).unwrap(),
                BoundaryResolution::Resolved(_)
            ),
            "v1 hash does not cover decision_reason — this residual is expected to be undetected"
        );

        // (3) Protection retained: tamper a field the v1 hash DOES cover
        // (tool_call_type) and the recompute diverges — TamperedArchive.
        let mut tampered = records.clone();
        for r in &mut tampered {
            if r.chain_sequence == Some(3) {
                r.tool_call_type = "ShellExec".into();
            }
        }
        rewrite_archive_for_test(&archive, &tampered);
        assert!(
            matches!(
                resolve_boundary_from_archives(dir.path(), 4, Some(&predecessor_hash)).unwrap(),
                BoundaryResolution::TamperedArchive { .. }
            ),
            "a v1-covered field tamper must still be detected"
        );
    }

    /// Stamp every record in an archive segment as legacy v1, relink
    /// `prev_hash` in sequence order, and recompute each `record_hash` under
    /// the v1 form so the segment is internally consistent as a v1 chain.
    fn downgrade_archive_to_v1(records: &mut [AuditRecord]) {
        records.sort_by_key(|r| r.chain_sequence);
        let mut prev: Option<String> = None;
        for r in records.iter_mut() {
            r.hash_version = LEGACY_HASH_VERSION;
            r.prev_hash = prev.clone();
            let h = r.compute_record_hash();
            r.record_hash = Some(h.clone());
            prev = Some(h);
        }
    }

    #[test]
    fn archive_terminal_record_reports_the_highest_archived_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let _storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);

        let (seq, hash) = archive_terminal_record(dir.path()).unwrap().unwrap();
        assert_eq!(seq, 3);
        assert!(hash.is_some(), "the terminal record should carry a hash");
    }

    #[test]
    fn archive_terminal_record_is_none_without_archives() {
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(archive_terminal_record(empty.path()).unwrap(), None);
    }

    /// Helper: rewrite an archive file in place with the given records,
    /// simulating an operator or attacker editing cold storage.
    fn rewrite_archive_for_test(path: &std::path::Path, records: &[AuditRecord]) {
        use std::io::Write as _;
        let mut buf = Vec::new();
        for r in records {
            buf.extend_from_slice(serde_json::to_string(r).unwrap().as_bytes());
            buf.push(b'\n');
        }
        let compressed = zstd::encode_all(&buf[..], 3).unwrap();
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(&compressed).unwrap();
    }

    /// `repair_chain()` remains available as a forensic tool, and remains
    /// destructive — which is exactly why work/74 Phase 5 removes it from the
    /// daemon startup path. This pins that it creates new evidence.
    #[test]
    fn repair_chain_is_destructive_and_must_never_be_automatic() {
        let dir = tempfile::tempdir().unwrap();
        let storage = pruned_storage_without_checkpoint(dir.path(), 3, 2);

        storage.repair_chain().unwrap();

        let (first_seq, first_prev): (i64, Option<String>) = storage
            .connection()
            .query_row(
                "SELECT chain_sequence, prev_hash FROM audit_log \
                 WHERE chain_sequence IS NOT NULL ORDER BY chain_sequence ASC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(first_seq, 1, "repair renumbers the suffix to genesis");
        assert!(first_prev.is_none(), "repair nulls the archive link");
    }

    #[test]
    fn prune_groups_archives_by_date() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let day1 = Utc.with_ymd_and_hms(2020, 1, 15, 12, 0, 0).unwrap();
        let day2 = Utc.with_ymd_and_hms(2020, 1, 16, 12, 0, 0).unwrap();
        for _ in 0..2 {
            storage.insert_record(&record_at(day1)).unwrap();
        }
        for _ in 0..3 {
            storage.insert_record(&record_at(day2)).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let cutoff = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let stats = prune_and_archive(&mut storage, cutoff, dir.path(), true, false).unwrap();
        assert_eq!(stats.archived_rows, 5);
        assert_eq!(stats.archive_files, 2);
        let files = list_archive_files(dir.path());
        assert_eq!(files.len(), 2);
        let restored_d1 = read_zstd_jsonl(&dir.path().join("2020-01-15.jsonl.zst")).unwrap();
        let restored_d2 = read_zstd_jsonl(&dir.path().join("2020-01-16.jsonl.zst")).unwrap();
        assert_eq!(restored_d1.len(), 2);
        assert_eq!(restored_d2.len(), 3);
    }

    #[test]
    fn prune_append_round_trips_via_concatenated_zstd_frames() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let day = Utc.with_ymd_and_hms(2020, 1, 15, 12, 0, 0).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cutoff = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();

        for _ in 0..2 {
            storage.insert_record(&record_at(day)).unwrap();
        }
        prune_and_archive(&mut storage, cutoff, dir.path(), true, false).unwrap();
        // Second batch lands in the same day-keyed file — exercises append.
        for _ in 0..3 {
            storage.insert_record(&record_at(day)).unwrap();
        }
        prune_and_archive(&mut storage, cutoff, dir.path(), true, false).unwrap();

        let restored = read_zstd_jsonl(&dir.path().join("2020-01-15.jsonl.zst")).unwrap();
        assert_eq!(restored.len(), 5);
    }

    #[test]
    fn prune_without_cold_storage_deletes_on_age_after_materialization() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let old = Utc.with_ymd_and_hms(2020, 1, 15, 12, 0, 0).unwrap();
        for _ in 0..3 {
            storage.insert_record(&record_at(old)).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let cutoff = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let stats = prune_and_archive(&mut storage, cutoff, dir.path(), false, false).unwrap();
        assert_eq!(
            stats.archived_rows, 3,
            "age-based deletion still counts rows"
        );
        assert_eq!(
            stats.archive_files, 0,
            "no archive is written when cold storage is off"
        );
        assert_eq!(storage.count().unwrap(), 0);
        assert!(!dir.path().join("2020-01-15.jsonl.zst").exists());
        // The analytics projection kept the rows' events even though the raw
        // rows are gone: coverage gating ran before deletion.
        let projected: i64 = storage
            .connection()
            .query_row("SELECT COUNT(*) FROM analytics_source_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(projected, 3);
    }

    #[test]
    fn cutoff_for_retention_zero_disables() {
        assert!(cutoff_for_retention(0).is_none());
        assert!(cutoff_for_retention(30).is_some());
    }

    fn mark_first_n_synced(storage: &AuditStorage, n: usize) {
        let ids: Vec<uuid::Uuid> = storage
            .get_recent(1000)
            .unwrap()
            .into_iter()
            .rev() // oldest first
            .take(n)
            .map(|r| r.id)
            .collect();
        storage.mark_synced(&ids).unwrap();
    }

    #[test]
    fn sync_safe_prune_skips_unsynced_rows() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let old = Utc.with_ymd_and_hms(2020, 1, 15, 12, 0, 0).unwrap();
        // 5 rows old enough to be eligible by time.
        for _ in 0..5 {
            storage.insert_record(&record_at(old)).unwrap();
        }
        // Only the first 3 have been synced. Rows 4-5 are unsynced suffix.
        mark_first_n_synced(&storage, 3);

        let dir = tempfile::tempdir().unwrap();
        let cutoff = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let stats = prune_and_archive(&mut storage, cutoff, dir.path(), true, true).unwrap();
        assert_eq!(
            stats.archived_rows, 3,
            "only synced rows should be archived"
        );
        assert_eq!(stats.max_pruned_sequence, 3);
        assert_eq!(storage.count().unwrap(), 2, "2 unsynced rows should remain");
    }

    #[test]
    fn sync_safe_prune_with_no_synced_rows_is_noop() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let old = Utc.with_ymd_and_hms(2020, 1, 15, 12, 0, 0).unwrap();
        for _ in 0..3 {
            storage.insert_record(&record_at(old)).unwrap();
        }
        // Zero rows marked synced — refuse to prune.
        let dir = tempfile::tempdir().unwrap();
        let cutoff = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let stats = prune_and_archive(&mut storage, cutoff, dir.path(), true, true).unwrap();
        assert_eq!(stats.archived_rows, 0);
        assert_eq!(storage.count().unwrap(), 3);
    }

    #[test]
    fn sync_safe_off_prunes_regardless_of_sync_state() {
        // Same scenario as above, but respect_sync_state=false. All 3 rows
        // should be archived since the safety guard is disabled.
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let old = Utc.with_ymd_and_hms(2020, 1, 15, 12, 0, 0).unwrap();
        for _ in 0..3 {
            storage.insert_record(&record_at(old)).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let cutoff = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let stats = prune_and_archive(&mut storage, cutoff, dir.path(), true, false).unwrap();
        assert_eq!(stats.archived_rows, 3);
    }
}
