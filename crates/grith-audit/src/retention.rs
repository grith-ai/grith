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
use crate::types::AuditRecord;
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
    let max_pruned_sequence = if respect_sync_state {
        let synced_max: Option<i64> = conn
            .query_row(
                "SELECT MAX(chain_sequence) FROM audit_log \
                 WHERE chain_sequence IS NOT NULL AND synced_at IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        match synced_max {
            Some(s) => time_max_sequence.min(s),
            // No rows synced yet — refuse to prune. Either the user
            // hasn't logged in / activated a plan, or sync is broken;
            // either way we shouldn't archive rows the server has not
            // acknowledged.
            None => return Ok(PruneStats::default()),
        }
    } else {
        time_max_sequence
    };
    if max_pruned_sequence <= 0 {
        return Ok(PruneStats::default());
    }

    // 2. Stream rows out. When cold storage is enabled, group by date and
    //    accumulate; otherwise just count.
    let mut by_date: BTreeMap<String, Vec<AuditRecord>> = BTreeMap::new();
    let mut count = 0usize;
    storage.drain_prefix_into(max_pruned_sequence, |record| {
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
            archive_files += 1;
        }
    }

    Ok(PruneStats {
        archived_rows: count,
        archive_files,
        max_pruned_sequence,
    })
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
    fn prune_without_cold_storage_just_deletes() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let old = Utc.with_ymd_and_hms(2020, 1, 15, 12, 0, 0).unwrap();
        for _ in 0..3 {
            storage.insert_record(&record_at(old)).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let cutoff = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let stats = prune_and_archive(&mut storage, cutoff, dir.path(), false, false).unwrap();
        assert_eq!(stats.archived_rows, 3);
        assert_eq!(stats.archive_files, 0);
        assert!(!dir.path().join("2020-01-15.jsonl.zst").exists());
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
