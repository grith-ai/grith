// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! SQLite-backed persistent storage for audit records with auto-rotation.

use crate::error::Result;
use crate::record_parser::row_to_record;
use crate::types::{ArchiveBoundary, AuditRecord, ChainVerification, SegmentHistory};
use chrono::Utc;
use rusqlite::{
    params, params_from_iter, Connection, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use uuid::Uuid;

/// Persisted high-water mark for incremental chain verification.
///
/// Walking the chain from sequence 1 every time is O(n) in the DB; once
/// a contiguous prefix has been verified, we only need to re-check rows
/// appended since. The marker stores the last verified sequence and its
/// record_hash so the next walk can seed `prev_hash` without re-reading
/// the prefix. See `audit-completeness-scaling.md` Stage 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainCheckpoint {
    last_verified_sequence: i64,
    last_verified_record_hash: Option<String>,
}

/// How verification seeds itself when no performance checkpoint exists.
///
/// work/74 §9. Separating "no anchor available" from "anchor disagrees" is
/// the whole point: the first is a recoverable bookkeeping loss, the second
/// is evidence. Collapsing both into `Broken` is what let startup renumber a
/// valid chain.
enum AnchorResolution {
    /// The active segment is its own genesis; verify from sequence 0.
    Genesis,
    /// The active segment continues an archived prefix; verify from the
    /// boundary.
    Anchored(ArchiveBoundary),
    /// No usable anchor. Carries the verification outcome to report; never
    /// repair in this state.
    Unresolved(ChainVerification),
}

/// SQLite-backed audit storage with auto-rotation.
pub struct AuditStorage {
    conn: Connection,
    db_path: PathBuf,
    max_size_bytes: u64,
    max_rotations: usize,
    /// Memoised result of the most recent chain verification.
    /// Invalidated on every write path; refilled on next `cached_verify_chain`.
    verify_cache: Mutex<Option<ChainVerification>>,
    /// Whether the partial UNIQUE index on `chain_sequence` is active.
    ///
    /// Legacy databases that already contain duplicate sequences (the
    /// 2026-07 fork incident) cannot accept the index; opening them must
    /// still succeed, with the degraded state surfaced through
    /// [`AuditStorage::has_unique_sequence_index`] and `grith audit
    /// diagnose` rather than a startup failure.
    unique_sequence_index: AtomicBool,
    /// `Some(reason)` once the daemon has determined the chain is quarantined
    /// (integrity unverifiable). While set, every record-insert path refuses new
    /// appends (B-CORE-1) so `grith run`/REPL and the daemon IPC ingest route
    /// cannot extend broken evidence — mirroring the session-admission refusal on
    /// the supervisor side. Set once at startup via `set_quarantined` under the
    /// outer `Arc<Mutex<AuditStorage>>`; a plain field (not an atomic like
    /// `unique_sequence_index`) suffices because it is only mutated through
    /// `&mut self` while that Mutex is held, and read on insert paths serialized
    /// by the same Mutex. `set_quarantined(None)` clears it (e.g. after a
    /// successful recovery); in the daemon, a restart also re-derives the chain
    /// status and simply does not re-arm the flag on a now-writable chain.
    quarantine: Option<String>,
    /// Whether this handle was opened via [`AuditStorage::open_read_only`].
    ///
    /// SQLite already enforces read-only at the connection level; this flag
    /// exists so callers (the daemon's IPC ingest route) can refuse a write
    /// up front with a structured "read-only" error instead of surfacing a
    /// raw SQLITE_READONLY failure after the fact.
    read_only: bool,
}

/// Apply recommended PRAGMAs for reliability and concurrency.
///
/// H-7: Set WAL mode, synchronous=NORMAL, and a 5-second busy timeout
/// on every connection (both file-backed and in-memory).
/// Whether a raw rusqlite error is any constraint violation.
fn is_constraint_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(ffi, _)
            if ffi.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

/// Whether an error is specifically the duplicate-`chain_sequence`
/// UNIQUE violation raised by `idx_audit_chain_seq_unique`.
fn is_unique_sequence_violation(e: &crate::error::Error) -> bool {
    matches!(
        e,
        crate::error::Error::Database(rusqlite::Error::SqliteFailure(ffi, Some(msg)))
            if ffi.code == rusqlite::ErrorCode::ConstraintViolation
                && msg.contains("chain_sequence")
    )
}

/// Upper bound on the WAL file after a checkpoint, in bytes.
///
/// H-19: WAL growth is unbounded by default. SQLite truncates the WAL back
/// to this size when a checkpoint completes, so a burst of audit writes
/// cannot leave a multi-gigabyte journal behind indefinitely. 64 MiB is
/// comfortably above normal steady-state traffic, so the limit only bites
/// after an unusual burst.
const WAL_SIZE_LIMIT_BYTES: i64 = 64 * 1024 * 1024;

fn apply_pragmas(conn: &Connection) -> Result<()> {
    conn.execute_batch(&format!(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;
         PRAGMA journal_size_limit={WAL_SIZE_LIMIT_BYTES};"
    ))?;
    Ok(())
}

/// B12 #69. Returns a chain-break reason when a persisted enum column holds a
/// non-canonical byte sequence that the lenient read path would silently fold
/// back onto the same variant.
///
/// The record hash covers only the canonical `to_string()` form, so a
/// case- or whitespace-variant (`record_type` 'full' -> 'Full',
/// `proxy_action` 'allow' -> 'Allow', or an unknown value that defaults back
/// to a known variant) survives hash verification unchanged while diverging
/// from the case-sensitive queries the dashboard runs (`WHERE record_type =
/// 'full'`). Legitimate writes always persist the canonical form, so any
/// divergence is tampering or corruption and must break the chain.
///
/// A `None` raw value means the column was absent or NULL — a legacy row that
/// predates the column — which legitimately maps to the enum default and is
/// not flagged.
fn noncanonical_enum_reason(
    raw_record_type: Option<&str>,
    canonical_record_type: &str,
    raw_proxy_action: Option<&str>,
    canonical_proxy_action: &str,
) -> Option<String> {
    if let Some(raw) = raw_record_type {
        if raw != canonical_record_type {
            return Some(format!(
                "record_type {raw:?} is non-canonical (folds to {canonical_record_type:?}); \
                 hash-invariant tamper that hides the row from the default audit view"
            ));
        }
    }
    if let Some(raw) = raw_proxy_action {
        if raw != canonical_proxy_action {
            return Some(format!(
                "proxy_action {raw:?} is non-canonical (folds to {canonical_proxy_action:?}); \
                 hash-invariant tamper"
            ));
        }
    }
    None
}

/// Physical footprint of the audit database on disk.
///
/// H-19: the incident reached ~1.4 GiB for ~53k rows because free pages,
/// the WAL and a backup file were never reclaimed. Logical retention
/// (deleting rows) does not shrink a SQLite file — the pages go on the
/// freelist and are reused, so file length alone says nothing about how
/// much live data is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StorageFootprint {
    /// Bytes in pages holding live data (`(page_count - freelist) * page_size`).
    pub live_bytes: u64,
    /// Bytes in pages on the freelist — reclaimable by a compaction.
    pub free_bytes: u64,
    /// Size of the main database file.
    pub db_file_bytes: u64,
    /// Size of the write-ahead log, if present.
    pub wal_file_bytes: u64,
}

impl StorageFootprint {
    /// Total bytes occupied on disk by the database and its journal.
    #[must_use]
    pub fn total_disk_bytes(&self) -> u64 {
        self.db_file_bytes.saturating_add(self.wal_file_bytes)
    }

    /// Fraction of the main file that is reclaimable free space, 0.0–1.0.
    #[must_use]
    pub fn free_ratio(&self) -> f64 {
        let total = self.live_bytes + self.free_bytes;
        if total == 0 {
            return 0.0;
        }
        self.free_bytes as f64 / total as f64
    }
}

impl AuditStorage {
    /// Open or create the audit database at the given path.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let db_path = path.into();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&db_path)?;
        apply_pragmas(&conn)?;
        let mut storage = Self {
            conn,
            db_path,
            max_size_bytes: 100 * 1024 * 1024, // 100 MB
            max_rotations: 5,
            verify_cache: Mutex::new(None),
            unique_sequence_index: AtomicBool::new(false),
            quarantine: None,
            read_only: false,
        };
        storage.init_schema()?;
        // Best-effort: a chain re-genesis (quarantine repair, recreated
        // database) must rotate the analytics source epoch or analytics
        // silently freezes at the old generation's cursor. Analytics is
        // derived state — its failure must never stop the audit log opening.
        if let Err(error) = storage.reconcile_analytics_epoch() {
            tracing::warn!(
                error = %error,
                "could not reconcile the analytics source epoch at open"
            );
        }
        Ok(storage)
    }

    /// Open the audit database **read-only** (work/74 Phase 4).
    ///
    /// Used by every command that is not the daemon holding the writer lock.
    /// SQLite enforces this at the connection level, so a bug that tries to
    /// write returns an error instead of silently becoming a second writer —
    /// which is the condition that forked the chain in the first place.
    ///
    /// The schema is *not* initialised: creating tables is a write, and a
    /// read-only opener must never be the thing that brings a database into
    /// existence. A missing file is an error, as it should be.
    pub fn open_read_only(path: impl Into<PathBuf>) -> Result<Self> {
        use rusqlite::OpenFlags;
        let db_path = path.into();
        let conn = Connection::open_with_flags(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?;
        // Only the busy timeout applies: journal_mode and synchronous are
        // writer properties, and setting journal_mode on a read-only
        // connection fails.
        conn.execute_batch("PRAGMA busy_timeout=5000;")?;
        Ok(Self {
            conn,
            db_path,
            max_size_bytes: 100 * 1024 * 1024,
            max_rotations: 5,
            verify_cache: Mutex::new(None),
            // A read-only opener cannot run the index-detection migration
            // (it writes), so it conservatively reports "no unique index".
            unique_sequence_index: AtomicBool::new(false),
            quarantine: None,
            read_only: true,
        })
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        apply_pragmas(&conn)?;
        let storage = Self {
            conn,
            db_path: PathBuf::from(":memory:"),
            max_size_bytes: 100 * 1024 * 1024,
            max_rotations: 5,
            verify_cache: Mutex::new(None),
            unique_sequence_index: AtomicBool::new(false),
            quarantine: None,
            read_only: false,
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Measure the database's physical footprint (H-19).
    ///
    /// Page counts come from SQLite rather than the filesystem, so the
    /// result distinguishes live data from reclaimable free pages — a
    /// distinction `std::fs::metadata` cannot make and the one that matters
    /// when deciding whether a compaction would help.
    pub fn footprint(&self) -> Result<StorageFootprint> {
        let page_size: i64 = self
            .conn
            .query_row("PRAGMA page_size", [], |row| row.get(0))?;
        let page_count: i64 = self
            .conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let freelist: i64 = self
            .conn
            .query_row("PRAGMA freelist_count", [], |row| row.get(0))?;

        let page_size = page_size.max(0) as u64;
        let live_pages = page_count.saturating_sub(freelist).max(0) as u64;
        let free_pages = freelist.max(0) as u64;

        let (db_file_bytes, wal_file_bytes) = if self.db_path.as_os_str() == ":memory:" {
            (0, 0)
        } else {
            let db = std::fs::metadata(&self.db_path)
                .map(|m| m.len())
                .unwrap_or(0);
            let wal_path = self.db_path.with_extension("db-wal");
            let wal = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
            (db, wal)
        };

        Ok(StorageFootprint {
            live_bytes: live_pages * page_size,
            free_bytes: free_pages * page_size,
            db_file_bytes,
            wal_file_bytes,
        })
    }

    /// Reclaim free pages by rewriting the database, verifying the rewrite,
    /// then swapping it in (H-19).
    ///
    /// Deliberately **not** automatic. `VACUUM INTO` is safe (it only reads
    /// the live database), but the swap that follows replaces the operator's
    /// audit evidence, and an interruption mid-swap is the one moment the
    /// original could be lost. Running it on a timer would put that moment
    /// on a schedule nobody chose; it is exposed as an explicit maintenance
    /// operation instead.
    ///
    /// Ordering is chosen so every failure is survivable:
    /// 1. `VACUUM INTO` a temporary file — the live database is untouched.
    /// 2. Open the copy and verify its chain end to end. A copy that does
    ///    not verify is discarded, and the original is kept.
    /// 3. Hard-link the original to a `.pre-compact` backup, then atomically
    ///    rename the verified copy over it. POSIX `rename` replaces the
    ///    destination in one step, so `db_path` names either the original or
    ///    the compacted copy at every instant — a crash never leaves it
    ///    absent — and the backup survives an interrupted run (B12 #73 LOW).
    ///
    /// Returns the footprint before and after.
    ///
    /// The caller must hold exclusive access — this reopens the connection
    /// underneath itself, so concurrent readers on other handles would see
    /// the file swapped beneath them.
    pub fn compact(&mut self) -> Result<(StorageFootprint, StorageFootprint)> {
        if self.db_path.as_os_str() == ":memory:" {
            let f = self.footprint()?;
            return Ok((f, f));
        }
        let before = self.footprint()?;

        let parent = self
            .db_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let stamp = Utc::now().format("%Y%m%dT%H%M%S");
        let staged = parent.join(format!("audit-compact-{stamp}.db"));
        let preserved = parent.join(format!("audit-{stamp}.pre-compact.db"));

        if staged.exists() {
            std::fs::remove_file(&staged)?;
        }

        // 1. Write the compacted copy. Reads only; the original is intact
        //    whatever happens here.
        self.conn.execute_batch(&format!(
            "VACUUM INTO '{}';",
            staged.to_string_lossy().replace('\'', "''")
        ))?;

        // 2. Prove the copy before trusting it with the evidence.
        let verification = {
            let copy = Self::open(&staged)?;
            copy.verify_chain()?
        };
        if !matches!(
            verification,
            ChainVerification::Valid { .. } | ChainVerification::Empty
        ) {
            let _ = std::fs::remove_file(&staged);
            return Err(crate::error::Error::Io(std::io::Error::other(format!(
                "compacted copy failed verification ({verification:?}); \
                 original database left untouched"
            ))));
        }

        // 3. Swap atomically. Close our handle first so the file is not held
        //    open across the rename. Back the original up via a hard link
        //    (same inode, no bytes copied), then let one `rename` replace it
        //    in place — `db_path` is never absent, unlike the previous
        //    move-aside/move-in pair whose gap could leave no database at all
        //    if interrupted (B12 #73 LOW).
        self.conn = Connection::open_in_memory()?;
        // Best-effort backup. A filesystem without hard-link support still
        // gets the atomic swap below; it just forgoes the .pre-compact copy.
        let backed_up = std::fs::hard_link(&self.db_path, &preserved).is_ok();
        if let Err(e) = std::fs::rename(&staged, &self.db_path) {
            // The rename failed, so the original is still in place at
            // db_path. Reopen it and clean up the copy and any backup.
            self.conn = Connection::open(&self.db_path)?;
            apply_pragmas(&self.conn)?;
            if backed_up {
                let _ = std::fs::remove_file(&preserved);
            }
            let _ = std::fs::remove_file(&staged);
            return Err(e.into());
        }
        self.conn = Connection::open(&self.db_path)?;
        apply_pragmas(&self.conn)?;
        self.invalidate_verify_cache();

        // The pre-compaction backup is only removed once the new database is
        // open in place.
        let after = self.footprint()?;
        if backed_up {
            std::fs::remove_file(&preserved)?;
        }

        Ok((before, after))
    }

    /// Checkpoint the write-ahead log and truncate it.
    ///
    /// H-19: without this the WAL only shrinks when SQLite happens to
    /// checkpoint on its own, which a steady write stream can defer
    /// indefinitely. Called from the retention pass so journal size is
    /// bounded by the same schedule that bounds row count.
    ///
    /// `TRUNCATE` blocks on active readers; a busy database simply leaves
    /// the WAL for the next pass rather than stalling writes, so a failure
    /// here is logged by the caller and is never fatal.
    pub fn checkpoint_wal(&self) -> Result<()> {
        if self.db_path.as_os_str() == ":memory:" {
            return Ok(());
        }
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Set the maximum database size before rotation (in bytes).
    pub fn with_max_size(mut self, bytes: u64) -> Self {
        self.max_size_bytes = bytes;
        self
    }

    /// Set the maximum number of rotated files to keep.
    pub fn with_max_rotations(mut self, count: usize) -> Self {
        self.max_rotations = count;
        self
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                session_id TEXT NOT NULL,
                plugin_id TEXT NOT NULL,
                tool_call_type TEXT NOT NULL,
                arguments_summary TEXT NOT NULL,
                arguments_hash TEXT NOT NULL,
                composite_score REAL NOT NULL,
                proxy_action TEXT NOT NULL,
                filter_results TEXT NOT NULL,
                filter_scores TEXT,
                execution_result TEXT,
                evaluation_time_ms REAL NOT NULL,
                task_context TEXT,
                source TEXT NOT NULL DEFAULT 'wasm',
                supervised_tool TEXT,
                supervised_pid INTEGER,
                correlation_id TEXT,
                synced_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_score ON audit_log(composite_score);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(proxy_action);",
        )?;
        self.ensure_supervisor_columns()?;
        // Create indexes after migration ensures the columns exist.
        self.conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_audit_synced ON audit_log(synced_at);
             CREATE INDEX IF NOT EXISTS idx_audit_chain_seq ON audit_log(chain_sequence);",
        )?;
        // B12 item 4: a second writer racing the chain used to be able to
        // derive the same sequence twice (the 2026-07 fork incident). The
        // partial UNIQUE index makes that impossible at the storage layer.
        // Legacy databases that already hold duplicates cannot accept it;
        // open() must never fail on them, so the constraint degrades soft
        // and `grith audit diagnose` reports the fork instead.
        match self.conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_seq_unique \
             ON audit_log(chain_sequence) WHERE chain_sequence IS NOT NULL",
            [],
        ) {
            Ok(_) => self.unique_sequence_index.store(true, Ordering::Relaxed),
            Err(e) if is_constraint_violation(&e) => {
                tracing::warn!(
                    error = %e,
                    "audit chain holds historical duplicate sequences; \
                     unique-sequence index not installed — run `grith audit diagnose`"
                );
                self.unique_sequence_index.store(false, Ordering::Relaxed);
            }
            Err(e) => return Err(e.into()),
        }
        // Stage-1 incremental-verify checkpoint storage. Single-row kv;
        // we use a table rather than PRAGMA user_version so the value can
        // be a small JSON blob holding both sequence and hash atomically.
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chain_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;
        crate::analytics::init_schema(&self.conn)?;
        Ok(())
    }

    fn load_chain_checkpoint(&self) -> Result<Option<ChainCheckpoint>> {
        let value: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM chain_metadata WHERE key = 'verified_head'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match value {
            Some(s) => Ok(serde_json::from_str(&s)?),
            None => Ok(None),
        }
    }

    fn store_chain_checkpoint(&self, ckpt: &ChainCheckpoint) -> Result<()> {
        let value = serde_json::to_string(ckpt)?;
        self.conn.execute(
            "INSERT INTO chain_metadata (key, value) VALUES ('verified_head', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![value],
        )?;
        Ok(())
    }

    /// How verification should seed itself when no performance checkpoint
    /// exists. See [`AuditStorage::resolve_verification_anchor`].
    ///
    /// work/74 Phase 5/6.
    fn resolve_verification_anchor(&self) -> Result<AnchorResolution> {
        let Some((first_sequence, first_prev_hash)) = self.first_chained_row()? else {
            // No chained rows at all. `verify_chain_from` reports Empty (or a
            // legacy-unchained Broken), which is the correct answer here.
            return Ok(AnchorResolution::Genesis);
        };

        // A segment that starts at 1 is its own genesis — the historical case
        // and still the common one.
        if first_sequence <= 1 {
            return Ok(AnchorResolution::Genesis);
        }

        // The segment starts above 1, so it can only be valid as the
        // continuation of an archived prefix. Require a durable anchor.
        match self.load_archive_boundary()? {
            Some(boundary) => {
                let sequence_links = boundary.last_archived_sequence + 1 == first_sequence;
                let hash_links =
                    first_prev_hash.as_deref() == Some(boundary.last_archived_record_hash.as_str());
                if sequence_links && hash_links {
                    Ok(AnchorResolution::Anchored(boundary))
                } else {
                    // A boundary exists but does not join. This is genuine
                    // discontinuity evidence, not a missing anchor.
                    Ok(AnchorResolution::Unresolved(
                        ChainVerification::AnchorMismatch {
                            boundary_sequence: boundary.last_archived_sequence,
                            expected_prev_hash: boundary.last_archived_record_hash,
                            found_prev_hash: first_prev_hash,
                            first_sequence,
                        },
                    ))
                }
            }
            // No anchor. Recoverable without touching any row by re-deriving
            // the boundary from cold archives — see
            // `retention::resolve_boundary_from_archives`. Never repair.
            None => Ok(AnchorResolution::Unresolved(
                ChainVerification::Unanchored { first_sequence },
            )),
        }
    }

    /// Read the durable archive boundary anchor, if one has been written.
    ///
    /// work/74 Phase 6. Unlike the `verified_head` checkpoint this is never
    /// deleted by verification or repair — it is the authority for "the
    /// active segment legitimately begins above sequence 1".
    pub fn load_archive_boundary(&self) -> Result<Option<ArchiveBoundary>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM chain_metadata WHERE key = 'archive_boundary'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match raw {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    /// Read the durable segment-history marker, if one has been written.
    ///
    /// B12 item 7. Records that the local audit history is known to consist
    /// of more than one segment — an archived prefix that the active
    /// segment does *not* continue. Written once, by explicit
    /// classification; never by a verification pass.
    pub fn load_segment_history(&self) -> Result<Option<SegmentHistory>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM chain_metadata WHERE key = 'segment_history'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match raw {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    /// Persist the segment-history marker.
    ///
    /// Idempotent by design: re-classifying an already-marked database
    /// overwrites the record with the same facts rather than accumulating
    /// duplicates.
    pub fn store_segment_history(&self, history: &SegmentHistory) -> Result<()> {
        let value = serde_json::to_string(history)?;
        self.conn.execute(
            "INSERT INTO chain_metadata (key, value) VALUES ('segment_history', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![value],
        )?;
        Ok(())
    }

    /// Persist the archive boundary anchor.
    ///
    /// Used by retention (atomically with the prune that creates it) and by
    /// boundary recovery when the anchor is re-derived from cold archives.
    pub fn store_archive_boundary(&self, boundary: &ArchiveBoundary) -> Result<()> {
        let value = serde_json::to_string(boundary)?;
        self.conn.execute(
            "INSERT INTO chain_metadata (key, value) VALUES ('archive_boundary', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![value],
        )?;
        self.invalidate_verify_cache();
        Ok(())
    }

    /// Lowest `chain_sequence` in the active database with its `prev_hash`.
    ///
    /// `None` when the database holds no chained rows.
    pub fn first_chained_row(&self) -> Result<Option<(i64, Option<String>)>> {
        let row: Option<(i64, Option<String>)> = self
            .conn
            .query_row(
                "SELECT chain_sequence, prev_hash FROM audit_log \
                 WHERE chain_sequence IS NOT NULL \
                 ORDER BY chain_sequence ASC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(row)
    }

    fn invalidate_verify_cache(&self) {
        if let Ok(mut guard) = self.verify_cache.lock() {
            *guard = None;
        }
    }

    /// Whether the duplicate-sequence UNIQUE backstop is active.
    ///
    /// `false` means this database predates the constraint and still holds
    /// historical duplicate sequences — `grith audit diagnose` reports the
    /// fork records themselves.
    pub fn has_unique_sequence_index(&self) -> bool {
        self.unique_sequence_index.load(Ordering::Relaxed)
    }

    fn ensure_supervisor_columns(&self) -> Result<()> {
        let mut stmt = self.conn.prepare("PRAGMA table_info(audit_log)")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;

        let mut cols = HashSet::new();
        for row in rows {
            cols.insert(row?);
        }

        if !cols.contains("source") {
            self.conn.execute(
                "ALTER TABLE audit_log ADD COLUMN source TEXT NOT NULL DEFAULT 'wasm'",
                [],
            )?;
        }
        if !cols.contains("supervised_tool") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN supervised_tool TEXT", [])?;
        }
        if !cols.contains("supervised_pid") {
            self.conn.execute(
                "ALTER TABLE audit_log ADD COLUMN supervised_pid INTEGER",
                [],
            )?;
        }
        if !cols.contains("project_name") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN project_name TEXT", [])?;
        }
        if !cols.contains("filter_scores") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN filter_scores TEXT", [])?;
        }
        if !cols.contains("correlation_id") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN correlation_id TEXT", [])?;
        }
        if !cols.contains("synced_at") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN synced_at TEXT", [])?;
        }
        if !cols.contains("record_hash") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN record_hash TEXT", [])?;
        }
        if !cols.contains("prev_hash") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT", [])?;
        }
        if !cols.contains("chain_sequence") {
            self.conn.execute(
                "ALTER TABLE audit_log ADD COLUMN chain_sequence INTEGER",
                [],
            )?;
        }
        if !cols.contains("llm_provider") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN llm_provider TEXT", [])?;
        }
        if !cols.contains("llm_model") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN llm_model TEXT", [])?;
        }
        if !cols.contains("prompt_tokens") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN prompt_tokens INTEGER", [])?;
        }
        if !cols.contains("completion_tokens") {
            self.conn.execute(
                "ALTER TABLE audit_log ADD COLUMN completion_tokens INTEGER",
                [],
            )?;
        }
        if !cols.contains("estimated_cost_usd") {
            self.conn.execute(
                "ALTER TABLE audit_log ADD COLUMN estimated_cost_usd REAL",
                [],
            )?;
        }
        // PR 4 Phase F: routine-spawn forensic fields. Idempotent ALTERs
        // so existing audit DBs migrate forward without manual steps.
        if !cols.contains("spawn_sha256") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN spawn_sha256 TEXT", [])?;
        }
        if !cols.contains("matched_routine_root") {
            self.conn.execute(
                "ALTER TABLE audit_log ADD COLUMN matched_routine_root TEXT",
                [],
            )?;
        }
        if !cols.contains("shadow_phase3_filters") {
            self.conn.execute(
                "ALTER TABLE audit_log ADD COLUMN shadow_phase3_filters TEXT",
                [],
            )?;
        }
        // PR 5 Phase E: listener-rewrite forensic fields. Idempotent
        // ALTERs so existing audit DBs migrate forward.
        if !cols.contains("original_addr") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN original_addr TEXT", [])?;
        }
        if !cols.contains("rewritten_addr") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN rewritten_addr TEXT", [])?;
        }
        if !cols.contains("clamp_profile_entry") {
            self.conn.execute(
                "ALTER TABLE audit_log ADD COLUMN clamp_profile_entry TEXT",
                [],
            )?;
        }
        // H-16: policy reason and enforcement outcome existed on the model
        // but were silently dropped at persistence. Idempotent ALTERs so
        // existing DBs migrate forward; both are nullable for legacy rows.
        if !cols.contains("decision_reason") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN decision_reason TEXT", [])?;
        }
        if !cols.contains("enforcement_outcome") {
            self.conn.execute(
                "ALTER TABLE audit_log ADD COLUMN enforcement_outcome TEXT",
                [],
            )?;
        }
        // B12 item 5: which canonical form produced record_hash. NULL means
        // a row written before versioning existed, which verification reads
        // back as version 1 — archived history keeps verifying untouched.
        if !cols.contains("hash_version") {
            self.conn
                .execute("ALTER TABLE audit_log ADD COLUMN hash_version INTEGER", [])?;
        }
        if !cols.contains("analytics_metadata") {
            self.conn.execute(
                "ALTER TABLE audit_log ADD COLUMN analytics_metadata TEXT",
                [],
            )?;
        }
        // Compact-record classification. Idempotent ALTER + default 'full'
        // so existing rows remain visible to the standard audit page query.
        if !cols.contains("record_type") {
            self.conn.execute(
                "ALTER TABLE audit_log ADD COLUMN record_type TEXT NOT NULL DEFAULT 'full'",
                [],
            )?;
            // Index by record_type so compact-vs-full filtering doesn't
            // table-scan once volume picks up under completeness = "io" or
            // "all". WHERE clause keeps the index small (full rows are the
            // common case and benefit from idx_audit_timestamp instead).
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_compact ON audit_log(record_type) \
                 WHERE record_type = 'compact'",
                [],
            )?;
        }

        Ok(())
    }

    /// Get the current chain head: (last_record_hash, last_chain_sequence).
    /// Returns `(None, 0)` if the table is empty or has no chained records.
    ///
    /// B12 item 4: callers that are about to *allocate* the next sequence
    /// must read the head inside the same IMMEDIATE transaction as their
    /// insert — reading it outside is exactly the race that forked the
    /// chain. `conn` accepts a `Transaction` (derefs to `Connection`).
    fn chain_head_on(conn: &Connection) -> Result<(Option<String>, i64)> {
        let result = conn.query_row(
            "SELECT record_hash, chain_sequence FROM audit_log \
             WHERE chain_sequence IS NOT NULL \
             ORDER BY chain_sequence DESC LIMIT 1",
            [],
            |row| {
                let hash: Option<String> = row.get(0)?;
                let seq: i64 = row.get(1)?;
                Ok((hash, seq))
            },
        );
        match result {
            Ok((hash, seq)) => Ok((hash, seq)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok((None, 0)),
            Err(e) => Err(e.into()),
        }
    }

    /// Bind and execute the canonical single-record INSERT on `conn`.
    ///
    /// The record must already carry its chain fields
    /// (`chain_sequence` / `prev_hash` / `record_hash`).
    fn execute_insert(conn: &Connection, record: &AuditRecord) -> Result<()> {
        let filter_results_json = serde_json::to_string(&record.filter_results)?;
        let filter_scores_json = record
            .filter_scores
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let analytics_metadata_json = record
            .analytics_metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        // Stage 3: compress the three biggest JSON columns. Below the
        // threshold or if compression doesn't shrink, the bytes stay
        // plain UTF-8 — readers detect via the zstd magic prefix.
        let args_summary_blob = crate::compression::compress_string(&record.arguments_summary);
        let filter_results_blob = crate::compression::compress_string(&filter_results_json);
        let filter_scores_blob = filter_scores_json
            .as_deref()
            .map(crate::compression::compress_string);
        conn.execute(
            "INSERT INTO audit_log (
                id, timestamp, session_id, plugin_id, tool_call_type,
                arguments_summary, arguments_hash, composite_score, proxy_action,
                filter_results, filter_scores, execution_result, evaluation_time_ms, task_context,
                source, supervised_tool, supervised_pid, correlation_id,
                record_hash, prev_hash, chain_sequence,
                llm_provider, llm_model, prompt_tokens, completion_tokens, estimated_cost_usd,
                spawn_sha256, matched_routine_root, shadow_phase3_filters,
                original_addr, rewritten_addr, clamp_profile_entry,
                record_type, project_name, decision_reason, enforcement_outcome,
                hash_version, analytics_metadata
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38)",
            params![
                record.id.to_string(),
                record.timestamp.to_rfc3339(),
                record.session_id.to_string(),
                record.plugin_id,
                record.tool_call_type,
                args_summary_blob,
                record.arguments_hash,
                record.composite_score,
                record.proxy_action.to_string(),
                filter_results_blob,
                filter_scores_blob,
                record.execution_result,
                record.evaluation_time_ms,
                record.task_context,
                record.source,
                record.supervised_tool,
                record.supervised_pid,
                record.correlation_id.map(|id| id.to_string()),
                record.record_hash,
                record.prev_hash,
                record.chain_sequence,
                record.llm_provider,
                record.llm_model,
                record.prompt_tokens.map(|v| v as i64),
                record.completion_tokens.map(|v| v as i64),
                record.estimated_cost_usd,
                record.spawn_sha256,
                record.matched_routine_root,
                record.shadow_phase3_filters,
                record.original_addr,
                record.rewritten_addr,
                record.clamp_profile_entry,
                record.record_type.to_string(),
                record.project_name,
                record.decision_reason,
                record.enforcement_outcome,
                record.hash_version,
                analytics_metadata_json,
            ],
        )?;
        Ok(())
    }

    /// Insert a single audit record with hash-chain linking.
    ///
    /// Sequence allocation is transactional: the chain head is read inside
    /// a `BEGIN IMMEDIATE` transaction so no concurrent writer can derive
    /// the same predecessor (B12 item 4). The partial UNIQUE index is the
    /// backstop; on the (now unreachable via this path) duplicate-sequence
    /// constraint the insert re-reads the head and retries.
    /// Refuse (or re-allow) new record appends because the chain is quarantined
    /// (B-CORE-1). `Some(reason)` arms the refusal; `None` clears it after a
    /// successful recovery re-derives a writable chain status.
    pub fn set_quarantined(&mut self, reason: Option<String>) {
        self.quarantine = reason;
    }

    /// Whether new appends are currently refused due to chain quarantine.
    #[must_use]
    pub fn is_quarantined(&self) -> bool {
        self.quarantine.is_some()
    }

    /// Whether this handle was opened read-only (work/74 Phase 4).
    ///
    /// True only for [`AuditStorage::open_read_only`] handles — the ones a
    /// process holds when another process owns the writer lock. Callers use
    /// this to refuse a write with a structured error before SQLite refuses
    /// it with a raw SQLITE_READONLY failure.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn insert_record(&self, record: &AuditRecord) -> Result<()> {
        // B-CORE-1: never append to a quarantined chain (broken evidence).
        if let Some(reason) = &self.quarantine {
            return Err(crate::error::Error::ChainQuarantined(reason.clone()));
        }
        const MAX_ATTEMPTS: u32 = 3;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let result = (|| -> Result<()> {
                let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
                let (prev_hash, last_seq) = Self::chain_head_on(&tx)?;
                let mut record = record.clone();
                record.chain_sequence = Some(last_seq + 1);
                record.prev_hash = prev_hash;
                record.record_hash = Some(record.compute_record_hash());
                Self::execute_insert(&tx, &record)?;
                tx.commit()?;
                Ok(())
            })();
            match result {
                Err(e) if attempt < MAX_ATTEMPTS && is_unique_sequence_violation(&e) => {
                    tracing::warn!(
                        attempt,
                        error = %e,
                        "duplicate chain sequence despite transactional allocation; retrying"
                    );
                    continue;
                }
                other => {
                    if other.is_ok() {
                        self.invalidate_verify_cache();
                    }
                    return other;
                }
            }
        }
    }

    /// Insert multiple records in a single transaction with hash-chain linking.
    ///
    /// Like [`AuditStorage::insert_record`], the chain head is read inside
    /// the `BEGIN IMMEDIATE` transaction so concurrent writers serialize on
    /// sequence allocation instead of forking the chain (B12 item 4).
    pub fn insert_batch(&mut self, records: &[AuditRecord]) -> Result<()> {
        // B-CORE-1: the supervisor's batched writer path must also refuse a
        // quarantined chain, not just the single-record ingest path.
        if let Some(reason) = &self.quarantine {
            return Err(crate::error::Error::ChainQuarantined(reason.clone()));
        }
        const MAX_ATTEMPTS: u32 = 3;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let result = (|| -> Result<()> {
                let tx = self
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let (mut prev_hash, mut last_seq) = Self::chain_head_on(&tx)?;
                for record in records {
                    let mut record = record.clone();
                    last_seq += 1;
                    record.chain_sequence = Some(last_seq);
                    record.prev_hash = prev_hash;
                    record.record_hash = Some(record.compute_record_hash());
                    prev_hash = record.record_hash.clone();
                    Self::execute_insert(&tx, &record)?;
                }
                tx.commit()?;
                Ok(())
            })();
            match result {
                Err(e) if attempt < MAX_ATTEMPTS && is_unique_sequence_violation(&e) => {
                    tracing::warn!(
                        attempt,
                        error = %e,
                        "duplicate chain sequence despite transactional allocation; retrying"
                    );
                    continue;
                }
                other => {
                    if other.is_ok() {
                        self.invalidate_verify_cache();
                    }
                    return other;
                }
            }
        }
    }

    /// Get a single record by ID.
    pub fn get_by_id(&self, id: &Uuid) -> Result<AuditRecord> {
        let row = self.conn.query_row(
            "SELECT * FROM audit_log WHERE id = ?1",
            params![id.to_string()],
            |row| row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into())),
        )?;
        Ok(row)
    }

    /// Get the most recent N records.
    pub fn get_recent(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        self.get_recent_filtered(limit, false)
    }

    /// Recent records, optionally including compact rows.
    ///
    /// When `include_compact` is false (the default audit-page view) only
    /// rows with `record_type = 'full'` are returned. When true, both
    /// full and compact rows interleave by timestamp.
    pub fn get_recent_filtered(
        &self,
        limit: usize,
        include_compact: bool,
    ) -> Result<Vec<AuditRecord>> {
        let sql = if include_compact {
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?1"
        } else {
            "SELECT * FROM audit_log WHERE record_type = 'full' \
             ORDER BY timestamp DESC LIMIT ?1"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Get records with offset-based pagination (newest first).
    pub fn get_page(&self, offset: usize, limit: usize) -> Result<Vec<AuditRecord>> {
        self.get_page_filtered(offset, limit, false)
    }

    /// Page through records, optionally including compact rows.
    pub fn get_page_filtered(
        &self,
        offset: usize,
        limit: usize,
        include_compact: bool,
    ) -> Result<Vec<AuditRecord>> {
        let sql = if include_compact {
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2"
        } else {
            "SELECT * FROM audit_log WHERE record_type = 'full' \
             ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Total record count, optionally including compact rows.
    pub fn count_filtered(&self, include_compact: bool) -> Result<usize> {
        let sql = if include_compact {
            "SELECT COUNT(*) FROM audit_log"
        } else {
            "SELECT COUNT(*) FROM audit_log WHERE record_type = 'full'"
        };
        let count: i64 = self.conn.query_row(sql, [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get all records for a session.
    pub fn get_by_session(&self, session_id: &Uuid) -> Result<Vec<AuditRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM audit_log WHERE session_id = ?1 ORDER BY timestamp ASC")?;
        let rows = stmt.query_map(params![session_id.to_string()], |row| {
            row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Count total records in the database.
    pub fn count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Check if rotation is needed and perform it.
    pub fn check_rotation(&mut self) -> Result<bool> {
        if self.db_path.as_os_str() == ":memory:" {
            return Ok(false);
        }
        // H-19: rotate on *live* bytes, not file length. A file that is
        // mostly freelist after a retention pass will be reused by
        // subsequent writes, so rotating it would start a new chain segment
        // (and a new discontinuity to explain) to reclaim space SQLite was
        // about to reuse anyway. Compaction is the right answer to free
        // pages; rotation is for genuinely large live data.
        let size = match self.footprint() {
            Ok(f) => f.live_bytes,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %self.db_path.display(),
                    "failed to measure audit database footprint, skipping rotation check"
                );
                0
            }
        };
        if size >= self.max_size_bytes {
            self.rotate()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// H-10: Rotation is wrapped in a logical transaction so that a failure
    /// at any step rolls back to the previous state (connection restored,
    /// file rename reverted).
    fn rotate(&mut self) -> Result<()> {
        let timestamp = Utc::now().format("%Y%m%dT%H%M%S");
        let parent = self.db_path.parent().unwrap_or(Path::new("."));
        let rotated = parent.join(format!("audit-{timestamp}.db"));

        // Close current connection by swapping in a temporary in-memory one
        let temp_conn = Connection::open_in_memory()?;
        let old_conn = std::mem::replace(&mut self.conn, temp_conn);
        drop(old_conn);

        // Rename current file; if this fails, re-open the original file
        if let Err(e) = std::fs::rename(&self.db_path, &rotated) {
            tracing::error!(
                error = %e,
                from = %self.db_path.display(),
                to = %rotated.display(),
                "failed to rename audit database during rotation, rolling back"
            );
            // Rollback: re-open the existing database file
            self.conn = Connection::open(&self.db_path)?;
            apply_pragmas(&self.conn)?;
            return Err(e.into());
        }

        // Open a fresh database; if this fails, undo the rename
        match Connection::open(&self.db_path) {
            Ok(new_conn) => {
                self.conn = new_conn;
                apply_pragmas(&self.conn)?;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "failed to open new audit database after rotation, rolling back"
                );
                // Rollback: move the rotated file back
                let _ = std::fs::rename(&rotated, &self.db_path);
                self.conn = Connection::open(&self.db_path)?;
                apply_pragmas(&self.conn)?;
                return Err(e.into());
            }
        }

        if let Err(e) = self.init_schema() {
            tracing::error!(
                error = %e,
                "failed to initialize schema after rotation, rolling back"
            );
            // Rollback: drop the new (empty) file, restore the old one
            drop(std::mem::replace(
                &mut self.conn,
                Connection::open_in_memory()?,
            ));
            let _ = std::fs::remove_file(&self.db_path);
            let _ = std::fs::rename(&rotated, &self.db_path);
            self.conn = Connection::open(&self.db_path)?;
            apply_pragmas(&self.conn)?;
            return Err(e);
        }

        // Clean up old rotations
        self.cleanup_old_rotations(parent)?;
        Ok(())
    }

    fn cleanup_old_rotations(&self, dir: &Path) -> Result<()> {
        let mut rotated: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("audit-") && n.ends_with(".db"))
                    .unwrap_or(false)
            })
            .collect();
        rotated.sort();
        while rotated.len() > self.max_rotations {
            if let Some(old) = rotated.first() {
                // L-10: Log a warning when deletion of old rotation files fails.
                if let Err(e) = std::fs::remove_file(old) {
                    tracing::warn!(
                        error = %e,
                        path = %old.display(),
                        "failed to delete old audit rotation file"
                    );
                }
                rotated.remove(0);
            }
        }
        Ok(())
    }

    /// Get unsynced records (synced_at IS NULL), ordered oldest-first, up to `limit`.
    pub fn get_unsynced(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT * FROM audit_log WHERE synced_at IS NULL ORDER BY timestamp ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Count unsynced records.
    pub fn count_unsynced(&self) -> Result<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE synced_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Mark a set of records as synced (by their IDs).
    pub fn mark_synced(&self, ids: &[Uuid]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        let placeholders: Vec<String> = (1..=ids.len()).map(|i| format!("?{}", i + 1)).collect();
        let sql = format!(
            "UPDATE audit_log SET synced_at = ?1 WHERE id IN ({})",
            placeholders.join(", ")
        );
        let mut param_values: Vec<String> = vec![now];
        for id in ids {
            param_values.push(id.to_string());
        }
        self.conn
            .execute(&sql, params_from_iter(param_values.iter()))?;
        Ok(())
    }

    /// Backfill chain fields for legacy rows created before hash chaining existed.
    ///
    /// Returns the number of rows updated.
    pub fn backfill_chain_for_legacy_rows(&self) -> Result<usize> {
        let mut stmt = self.conn.prepare(
            "SELECT * FROM audit_log WHERE chain_sequence IS NULL ORDER BY timestamp ASC, id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?;
        let mut legacy = Vec::new();
        for row in rows {
            legacy.push(row?);
        }
        if legacy.is_empty() {
            return Ok(0);
        }

        // Head read + sequence assignment inside one IMMEDIATE transaction:
        // a concurrent writer allocating from a stale head is the fork
        // mechanism this file exists to prevent (B12 item 4).
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let (mut prev_hash, mut last_seq) = Self::chain_head_on(&tx)?;
        let mut updated = 0usize;
        for mut record in legacy {
            last_seq += 1;
            record.chain_sequence = Some(last_seq);
            record.prev_hash = prev_hash;
            record.record_hash = Some(record.compute_record_hash());
            tx.execute(
                "UPDATE audit_log
                 SET record_hash = ?2, prev_hash = ?3, chain_sequence = ?4
                 WHERE id = ?1",
                params![
                    record.id.to_string(),
                    record.record_hash,
                    record.prev_hash,
                    record.chain_sequence
                ],
            )?;
            prev_hash = record.record_hash;
            updated += 1;
        }
        tx.commit()?;

        self.invalidate_verify_cache();
        Ok(updated)
    }

    /// Repair gaps and hash mismatches in the audit chain.
    ///
    /// Walks all chained records in sequence order, re-assigns contiguous
    /// sequence numbers, recomputes hashes, and fixes prev_hash links.
    /// Returns the number of records repaired (0 if the chain was clean).
    pub fn repair_chain(&self) -> Result<usize> {
        let mut stmt = self.conn.prepare(
            "SELECT * FROM audit_log WHERE chain_sequence IS NOT NULL \
             ORDER BY chain_sequence ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }

        if records.is_empty() {
            return Ok(0);
        }

        let mut prev_hash: Option<String> = None;
        let mut repaired = 0usize;

        // The whole repair is one transaction. Renumbering assigns each
        // repaired row a *negative* placeholder sequence first, then flips
        // sign in a single statement: with the partial UNIQUE index on
        // chain_sequence active, a direct rewrite could transiently collide
        // with a not-yet-renumbered row (e.g. duplicates [1,1,2,3]: the
        // third row's new sequence 3 collides with the still-unprocessed
        // fourth row). Negatives can never collide with live positives.
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;

        for (i, record) in records.iter_mut().enumerate() {
            let expected_seq = (i as i64) + 1;
            let expected_hash = {
                // Temporarily set correct chain fields for hash computation
                record.chain_sequence = Some(expected_seq);
                record.prev_hash = prev_hash.clone();
                record.compute_record_hash()
            };

            let needs_repair = record.chain_sequence != Some(expected_seq)
                || record.prev_hash != prev_hash
                || record.record_hash.as_deref() != Some(&expected_hash);

            // Always rewrite — the hash depends on sequence + prev_hash, so
            // even a simple gap fix cascades through all subsequent records.
            record.chain_sequence = Some(expected_seq);
            record.prev_hash = prev_hash.clone();
            record.record_hash = Some(expected_hash.clone());

            if needs_repair {
                tx.execute(
                    "UPDATE audit_log
                     SET chain_sequence = ?2, prev_hash = ?3, record_hash = ?4
                     WHERE id = ?1",
                    params![
                        record.id.to_string(),
                        -expected_seq,
                        record.prev_hash,
                        record.record_hash,
                    ],
                )?;
                repaired += 1;
            }

            prev_hash = record.record_hash.clone();
        }

        // Flip the negative placeholders to their final sequences. Rows
        // that were already correct kept their positive sequence, and a
        // repaired row's final sequence is never one of those (each
        // expected_seq is unique across the walk), so the flip cannot
        // violate the UNIQUE constraint.
        tx.execute(
            "UPDATE audit_log SET chain_sequence = -chain_sequence WHERE chain_sequence < 0",
            [],
        )?;

        if repaired > 0 {
            // Repair may rewrite hashes anywhere in the chain, so the
            // existing checkpoint is no longer trustworthy. Reset it so
            // the next incremental verify walks the whole repaired chain
            // once before re-establishing the high-water mark.
            tx.execute("DELETE FROM chain_metadata WHERE key = 'verified_head'", [])?;
        }
        tx.commit()?;
        self.invalidate_verify_cache();
        Ok(repaired)
    }

    /// Verify the integrity of the audit hash chain.
    ///
    /// Walks all records ordered by `chain_sequence`, recomputes each record's
    /// hash, and verifies it matches the stored `record_hash` and that `prev_hash`
    /// links to the previous record correctly. O(n) — for read paths that run
    /// every request, prefer `cached_verify_chain` / `incremental_verify_chain`.
    pub fn verify_chain(&self) -> Result<ChainVerification> {
        // work/74 §9: this used to hardcode `start_sequence = 0`, which asserts
        // that the active database begins at sequence 1. That stops being true
        // after the first retention archive, so the operator-facing full
        // verify reported `Broken` on every pruned database — the same false
        // positive that drove startup to renumber a valid chain. Resolve the
        // anchor first, exactly as the incremental path does; the difference
        // between the two is that this one ignores the performance checkpoint
        // and re-walks the whole active segment.
        match self.resolve_verification_anchor()? {
            AnchorResolution::Genesis => self.verify_chain_from(0, None, 0),
            AnchorResolution::Anchored(boundary) => self.verify_chain_from(
                boundary.last_archived_sequence,
                Some(boundary.last_archived_record_hash),
                boundary.last_archived_sequence.max(0) as usize,
            ),
            AnchorResolution::Unresolved(outcome) => Ok(outcome),
        }
    }

    /// Records sharing a `chain_sequence` with at least one other record —
    /// the signature of a second writer racing the chain — ordered by
    /// sequence then timestamp.
    ///
    /// Read-only diagnostic for `grith audit diagnose`: each record carries
    /// how many records chain off its hash, so a fork's winner
    /// (`successors > 0`) and its dangling losers (`successors == 0`) are
    /// distinguishable without touching the chain.
    pub fn duplicate_sequence_records(&self) -> Result<Vec<ForkRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT a.id, a.chain_sequence, a.timestamp, a.record_hash, a.prev_hash,
                    (SELECT COUNT(*) FROM audit_log s WHERE s.prev_hash = a.record_hash)
             FROM audit_log a
             WHERE a.chain_sequence IN (
                 SELECT chain_sequence FROM audit_log
                 WHERE chain_sequence IS NOT NULL
                 GROUP BY chain_sequence
                 HAVING COUNT(*) > 1)
             ORDER BY a.chain_sequence ASC, a.timestamp ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ForkRecord {
                id: row.get(0)?,
                chain_sequence: row.get(1)?,
                timestamp: row.get(2)?,
                record_hash: row.get(3)?,
                prev_hash: row.get(4)?,
                successors: row.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// `prev_hash` of the record at `sequence`. Diagnostic helper for
    /// fork-branch resolution in `grith audit diagnose`; callers pass a
    /// sequence known to hold exactly one record.
    pub fn prev_hash_at(&self, sequence: i64) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT prev_hash FROM audit_log WHERE chain_sequence = ?1 LIMIT 1",
                params![sequence],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    /// Gaps in the active chain's sequence numbering, as
    /// `(sequence_before_gap, sequence_after_gap)` pairs, capped at `limit`.
    /// Read-only diagnostic for `grith audit diagnose`.
    pub fn sequence_gaps(&self, limit: usize) -> Result<Vec<(i64, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, nxt FROM (
                 SELECT seq, LEAD(seq) OVER (ORDER BY seq) AS nxt
                 FROM (SELECT DISTINCT chain_sequence AS seq FROM audit_log
                       WHERE chain_sequence IS NOT NULL))
             WHERE nxt > seq + 1
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Verify the chain only from `start_sequence + 1` onward, seeded with
    /// `seed_prev_hash` (the record_hash at `start_sequence`).
    ///
    /// When `start_sequence == 0` and `seed_prev_hash == None` this is
    /// equivalent to `verify_chain`. When the marker points partway through
    /// the chain it walks only the suffix — the common case after the first
    /// verification. Already-verified rows ahead of `start_sequence` count
    /// toward the returned `record_count`.
    fn verify_chain_from(
        &self,
        start_sequence: i64,
        seed_prev_hash: Option<String>,
        already_verified: usize,
    ) -> Result<ChainVerification> {
        let total_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
        if total_count == 0 {
            return Ok(ChainVerification::Empty);
        }

        // Detect un-chained legacy rows. We only flag this when we're doing
        // a from-scratch verify; a partial verify trusts that prior calls
        // already validated the prefix.
        if start_sequence == 0 {
            let unchained_id: Option<String> = self
                .conn
                .query_row(
                    "SELECT id FROM audit_log WHERE chain_sequence IS NULL
                     ORDER BY timestamp ASC, id ASC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = unchained_id {
                let parsed = Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::nil());
                return Ok(ChainVerification::Broken {
                    at_sequence: 0,
                    record_id: parsed,
                    reason: "found record without chain_sequence".to_string(),
                });
            }
        }

        let mut stmt = self.conn.prepare(
            "SELECT * FROM audit_log WHERE chain_sequence IS NOT NULL \
                 AND chain_sequence > ?1 \
             ORDER BY chain_sequence ASC",
        )?;
        let rows = stmt.query_map(params![start_sequence], |row| {
            let record = row_to_record(row)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            // B12 #69: the record hash covers only the *canonical* enum form
            // (`to_string()`), while the read path (`from_str_lenient` and the
            // lenient `proxy_action` match) folds any case- or whitespace-
            // variant back onto the same variant. A DB tamper that rewrites
            // `record_type` 'full' -> 'Full' (or `proxy_action` 'allow' ->
            // 'Allow') therefore leaves the recomputed hash unchanged, yet
            // hides the row from the case-sensitive default audit view
            // (`WHERE record_type = 'full'`). Capture the raw persisted bytes
            // so the verify loop can flag exactly that evasion class.
            let raw_record_type: Option<String> =
                row.get::<_, Option<String>>("record_type").ok().flatten();
            let raw_proxy_action: Option<String> = row.get("proxy_action").ok();
            let noncanonical = noncanonical_enum_reason(
                raw_record_type.as_deref(),
                &record.record_type.to_string(),
                raw_proxy_action.as_deref(),
                &record.proxy_action.to_string(),
            );
            Ok((record, noncanonical))
        })?;

        let mut prev_record_hash: Option<String> = seed_prev_hash;
        let mut count = already_verified;

        for (expected_sequence, row_result) in (start_sequence + 1..).zip(rows) {
            let (record, noncanonical) = row_result?;
            count += 1;

            let seq = record.chain_sequence.unwrap_or(0);
            if seq != expected_sequence {
                return Ok(ChainVerification::Broken {
                    at_sequence: seq,
                    record_id: record.id,
                    reason: format!(
                        "non-contiguous chain sequence: expected {expected_sequence}, found {seq}"
                    ),
                });
            }

            // Verify prev_hash links correctly
            if record.prev_hash != prev_record_hash {
                return Ok(ChainVerification::Broken {
                    at_sequence: seq,
                    record_id: record.id,
                    reason: format!(
                        "prev_hash mismatch: expected {:?}, found {:?}",
                        prev_record_hash, record.prev_hash
                    ),
                });
            }

            // Recompute the hash and verify it matches stored
            let expected_hash = record.compute_record_hash();
            if record.record_hash.as_deref() != Some(&expected_hash) {
                return Ok(ChainVerification::Broken {
                    at_sequence: seq,
                    record_id: record.id,
                    reason: format!(
                        "record_hash mismatch: stored {:?}, computed {expected_hash}",
                        record.record_hash,
                    ),
                });
            }

            // B12 #69: hash-invariant enum tamper. A case/whitespace variant
            // that folds back onto the same variant passes the hash check
            // above (the hash covers only the canonical form) while diverging
            // from the case-sensitive queries the dashboard runs. This is the
            // dedicated catch for that evasion class.
            if let Some(reason) = noncanonical {
                return Ok(ChainVerification::Broken {
                    at_sequence: seq,
                    record_id: record.id,
                    reason,
                });
            }

            prev_record_hash = record.record_hash;
        }

        Ok(ChainVerification::Valid {
            record_count: count,
        })
    }

    /// Incremental chain verification.
    ///
    /// Reads the persisted `chain_metadata` checkpoint (set by the previous
    /// successful verify), walks only the rows appended since, and advances
    /// the checkpoint on success. For a clean already-verified DB with no
    /// new rows this is a constant-time `COUNT(*)` + one row read.
    ///
    /// Documented trade-off: a tamper applied to a row at sequence ≤ marker
    /// is not re-detected here (operator must run `verify_chain` for a full
    /// pass). Markers and rows live in the same DB, so an attacker with
    /// write access can already rewrite both — the security boundary is
    /// the DB file, not the marker.
    pub fn incremental_verify_chain(&self) -> Result<ChainVerification> {
        let checkpoint = self.load_chain_checkpoint()?;
        let (start_seq, seed_hash, prefix_count) = match &checkpoint {
            Some(c) => (
                c.last_verified_sequence,
                c.last_verified_record_hash.clone(),
                c.last_verified_sequence.max(0) as usize,
            ),
            // work/74 §9: with no checkpoint we must NOT blindly restart from
            // sequence 0. That assumes the active database begins at 1, which
            // is false after any retention archive, and produced a false
            // `Broken` that startup then "repaired" by renumbering a perfectly
            // valid chain into a second genesis segment. Resolve an anchor
            // first; only genesis databases verify from 0.
            None => match self.resolve_verification_anchor()? {
                AnchorResolution::Genesis => (0, None, 0),
                AnchorResolution::Anchored(boundary) => (
                    boundary.last_archived_sequence,
                    Some(boundary.last_archived_record_hash),
                    boundary.last_archived_sequence.max(0) as usize,
                ),
                AnchorResolution::Unresolved(outcome) => return Ok(outcome),
            },
        };

        let verification = self.verify_chain_from(start_seq, seed_hash, prefix_count)?;

        if let ChainVerification::Valid { record_count } = &verification {
            // Look up the new head (sequence + record_hash) so the next
            // call can start where we left off.
            let head: Option<(i64, Option<String>)> = self
                .conn
                .query_row(
                    "SELECT chain_sequence, record_hash FROM audit_log \
                     WHERE chain_sequence IS NOT NULL \
                     ORDER BY chain_sequence DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((seq, hash)) = head {
                let new_ckpt = ChainCheckpoint {
                    last_verified_sequence: seq,
                    last_verified_record_hash: hash,
                };
                // Only write if the marker actually moved — avoids a SQLite
                // write on every cached-verify path that hits a no-op.
                if checkpoint
                    .as_ref()
                    .is_none_or(|c| c.last_verified_sequence != new_ckpt.last_verified_sequence)
                {
                    self.store_chain_checkpoint(&new_ckpt)?;
                }
            }
            // record_count includes the prefix from the marker plus the
            // newly walked tail, matching what verify_chain would report.
            let _ = record_count;
        }

        Ok(verification)
    }

    /// Cached + incremental chain verification.
    ///
    /// Returns the most recent `ChainVerification` result if the cache is
    /// warm; otherwise calls `incremental_verify_chain` and caches the
    /// result. Cache is invalidated on every write path (insert / mark_synced
    /// / repair / backfill).
    pub fn cached_verify_chain(&self) -> Result<ChainVerification> {
        if let Ok(guard) = self.verify_cache.lock() {
            if let Some(cached) = guard.as_ref() {
                return Ok(cached.clone());
            }
        }
        let result = self.incremental_verify_chain()?;
        if let Ok(mut guard) = self.verify_cache.lock() {
            *guard = Some(result.clone());
        }
        Ok(result)
    }

    /// Return the oldest still-chained `(chain_sequence, timestamp)` pair,
    /// or `None` if the table is empty / unchained.
    pub fn chain_tail(&self) -> Result<Option<(i64, chrono::DateTime<chrono::Utc>)>> {
        let row: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT chain_sequence, timestamp FROM audit_log \
                 WHERE chain_sequence IS NOT NULL \
                 ORDER BY chain_sequence ASC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            Some((seq, ts)) => {
                let parsed = chrono::DateTime::parse_from_rfc3339(&ts)
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?
                    .with_timezone(&chrono::Utc);
                Ok(Some((seq, parsed)))
            }
            None => Ok(None),
        }
    }

    /// Iterate every chained row in `[1..=max_sequence]`, applying `f` to
    /// each, then in a single transaction delete those rows and overwrite
    /// the verification checkpoint to `(max_sequence, head_hash_at_max)`.
    ///
    /// Used by the retention module: stream archived rows out to NDJSON.zst
    /// before deleting them. The checkpoint update means incremental verify
    /// starts at `max_sequence + 1` with `seed_hash = head_hash_at_max`,
    /// which matches the next-remaining row's `prev_hash` — chain integrity
    /// preserved across the partition boundary.
    /// Stream the chained prefix `[1..=max_sequence]` to `f` **without**
    /// deleting anything.
    ///
    /// work/74: retention archives before it deletes, so reading and deleting
    /// are separate operations. A crash between them re-archives rows on the
    /// next pass, which is recoverable; the previous drain-then-archive order
    /// lost them outright.
    pub fn read_prefix_into<F>(&self, max_sequence: i64, mut f: F) -> Result<usize>
    where
        F: FnMut(&AuditRecord) -> Result<()>,
    {
        if max_sequence <= 0 {
            return Ok(0);
        }
        // No row at the boundary means there is nothing coherent to archive.
        let head_exists: Option<String> = self
            .conn
            .query_row(
                "SELECT record_hash FROM audit_log WHERE chain_sequence = ?1",
                params![max_sequence],
                |row| row.get(0),
            )
            .optional()?;
        if head_exists.is_none() {
            return Ok(0);
        }

        let mut stmt = self.conn.prepare(
            "SELECT * FROM audit_log WHERE chain_sequence IS NOT NULL \
                 AND chain_sequence <= ?1 \
             ORDER BY chain_sequence ASC",
        )?;
        let rows = stmt.query_map(params![max_sequence], |row| {
            row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?;
        let mut count = 0usize;
        for row in rows {
            let record = row?;
            f(&record)?;
            count += 1;
        }
        Ok(count)
    }

    /// Delete the chained prefix `[1..=max_sequence]` and publish both the
    /// verification checkpoint and the durable archive boundary, atomically.
    ///
    /// Callers must have durably archived the rows first — see
    /// [`AuditStorage::read_prefix_into`].
    pub fn delete_prefix(&mut self, max_sequence: i64) -> Result<usize> {
        if max_sequence <= 0 {
            return Ok(0);
        }

        // Capture the head hash BEFORE deleting: it becomes both the
        // checkpoint seed and the durable boundary anchor.
        let head_hash: Option<String> = self
            .conn
            .query_row(
                "SELECT record_hash FROM audit_log WHERE chain_sequence = ?1",
                params![max_sequence],
                |row| row.get(0),
            )
            .optional()?;
        if head_hash.is_none() {
            return Ok(0);
        }

        let count: usize = self.conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE chain_sequence IS NOT NULL \
                 AND chain_sequence <= ?1",
            params![max_sequence],
            |row| row.get(0),
        )?;
        if count == 0 {
            return Ok(0);
        }

        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM audit_log WHERE chain_sequence IS NOT NULL \
                 AND chain_sequence <= ?1",
            params![max_sequence],
        )?;
        let ckpt = ChainCheckpoint {
            last_verified_sequence: max_sequence,
            last_verified_record_hash: head_hash.clone(),
        };
        let value = serde_json::to_string(&ckpt)?;
        tx.execute(
            "INSERT INTO chain_metadata (key, value) VALUES ('verified_head', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![value],
        )?;

        // work/74 Phase 6: write the DURABLE boundary anchor in the same
        // transaction as the delete that creates it. The `verified_head`
        // checkpoint above is a performance cache and is deleted by
        // `repair_chain()`; this anchor is not, and is what proves the
        // surviving segment legitimately starts above sequence 1.
        if let Some(hash) = head_hash {
            let boundary = ArchiveBoundary {
                last_archived_sequence: max_sequence,
                last_archived_record_hash: hash,
                updated_at: Utc::now(),
            };
            tx.execute(
                "INSERT INTO chain_metadata (key, value) VALUES ('archive_boundary', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![serde_json::to_string(&boundary)?],
            )?;
        }
        tx.commit()?;
        self.invalidate_verify_cache();
        Ok(count)
    }

    /// Access the underlying connection (for query module).
    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Mutable connection accessor for the retention module (needs to run
    /// transactional deletes within the same connection used by other
    /// operations so the chain checkpoint update is atomic with the prune).
    pub(crate) fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

/// A record at a chain sequence occupied by more than one record, with the
/// fork-linkage information `grith audit diagnose` reports. Produced by
/// [`AuditStorage::duplicate_sequence_records`].
#[derive(Debug, Clone)]
pub struct ForkRecord {
    /// Record id (UUID string).
    pub id: String,
    /// The duplicated chain sequence.
    pub chain_sequence: i64,
    /// Record timestamp as stored (RFC 3339 text).
    pub timestamp: String,
    /// This record's hash.
    pub record_hash: Option<String>,
    /// Hash of the record this one chains from.
    pub prev_hash: Option<String>,
    /// Number of records whose `prev_hash` is this record's `record_hash`.
    /// `0` means the record is a dangling fork loser: nothing chains off it.
    pub successors: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuditRecord, FilterResultSummary, ProxyActionSummary};
    use chrono::DateTime;
    use std::collections::HashMap;

    fn make_record() -> AuditRecord {
        AuditRecord::new(
            Uuid::new_v4(),
            "file-ops".into(),
            "FileRead".into(),
            &serde_json::json!({"path": "/tmp/test.txt"}),
            1.5,
            ProxyActionSummary::Allow,
            vec![FilterResultSummary {
                filter_name: "path-match".into(),
                matched: false,
                score: 0.0,
                rule_id: String::new(),
                severity: "notice".into(),
                message: String::new(),
            }],
            0.8,
            Some("test context".into()),
        )
    }

    #[test]
    fn test_open_in_memory() {
        let storage = AuditStorage::open_in_memory().unwrap();
        assert_eq!(storage.count().unwrap(), 0);
    }

    /// B-CORE-1: a quarantined chain refuses every append path (single + batch)
    /// so `grith run`/REPL and the daemon IPC ingest route cannot extend broken
    /// evidence; recovery clears the flag and writes resume.
    #[test]
    fn insert_refused_when_quarantined() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        storage.insert_record(&make_record()).unwrap();
        assert_eq!(storage.count().unwrap(), 1);

        storage.set_quarantined(Some("chain broken at seq 42".into()));
        assert!(storage.is_quarantined());

        let err = storage.insert_record(&make_record()).unwrap_err();
        assert!(
            matches!(err, crate::error::Error::ChainQuarantined(_)),
            "single insert on a quarantined chain must be refused, got {err:?}"
        );
        // Nothing was appended onto the quarantined chain.
        assert_eq!(storage.count().unwrap(), 1);

        // The supervisor's batched writer path is refused too.
        let err = storage
            .insert_batch(&[make_record(), make_record()])
            .unwrap_err();
        assert!(matches!(err, crate::error::Error::ChainQuarantined(_)));
        assert_eq!(storage.count().unwrap(), 1);

        // Recovery clears quarantine; writes resume.
        storage.set_quarantined(None);
        assert!(!storage.is_quarantined());
        storage.insert_record(&make_record()).unwrap();
        assert_eq!(storage.count().unwrap(), 2);
    }

    /// Inject a fork loser at `sequence`: chained off the same parent as the
    /// real record at that sequence, but with a hash nothing links to —
    /// the row shape a second writer racing the chain leaves behind.
    ///
    /// Live databases can no longer produce this shape (the partial UNIQUE
    /// index forbids it), so the helper first drops the index to simulate a
    /// legacy pre-constraint database — which is exactly what diagnose
    /// tooling runs against.
    fn inject_fork_loser(storage: &AuditStorage, sequence: i64) {
        storage
            .conn
            .execute("DROP INDEX IF EXISTS idx_audit_chain_seq_unique", [])
            .unwrap();
        let real_prev: Option<String> = storage
            .conn
            .query_row(
                "SELECT prev_hash FROM audit_log WHERE chain_sequence = ?1",
                params![sequence],
                |row| row.get(0),
            )
            .unwrap();
        storage
            .conn
            .execute(
                "INSERT INTO audit_log (id, timestamp, session_id, plugin_id,
                     tool_call_type, arguments_summary, arguments_hash,
                     composite_score, proxy_action, filter_results,
                     evaluation_time_ms, chain_sequence, prev_hash, record_hash)
                 VALUES (?1, ?2, 'test-session', 'file-ops', 'FileRead', '{}',
                     'hash', 1.0, 'allow', '[]', 1.0, ?3, ?4, ?5)",
                params![
                    Uuid::new_v4().to_string(),
                    "2026-07-29T23:59:59Z",
                    sequence,
                    real_prev,
                    format!("dangling-{sequence}"),
                ],
            )
            .unwrap();
    }

    #[test]
    fn duplicate_sequence_records_labels_winner_and_dangler() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..3 {
            storage.insert_record(&make_record()).unwrap();
        }
        assert!(storage.duplicate_sequence_records().unwrap().is_empty());

        inject_fork_loser(&storage, 2);

        let forks = storage.duplicate_sequence_records().unwrap();
        assert_eq!(forks.len(), 2);
        assert!(forks.iter().all(|f| f.chain_sequence == 2));
        // The real sequence-2 record has sequence 3 chaining off it; the
        // injected loser has nothing.
        let winner = forks.iter().find(|f| f.successors > 0).unwrap();
        assert_ne!(winner.record_hash.as_deref(), Some("dangling-2"));
        let loser = forks.iter().find(|f| f.successors == 0).unwrap();
        assert_eq!(loser.record_hash.as_deref(), Some("dangling-2"));
    }

    /// B12 item 4 regression — the executable form of the 2026-07-29 fork
    /// incident: two independent file-backed handles (= two connections,
    /// exactly like a daemon and a stray CLI command) interleaving writes
    /// must never derive the same predecessor or sequence.
    #[test]
    fn concurrent_writers_produce_no_duplicate_sequences() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        // Create the schema before racing so neither thread pays migration cost.
        drop(AuditStorage::open(&db_path).unwrap());

        let path_a = db_path.clone();
        let a = std::thread::spawn(move || {
            let storage = AuditStorage::open(&path_a).unwrap();
            for _ in 0..40 {
                storage.insert_record(&make_record()).unwrap();
            }
        });
        let path_b = db_path.clone();
        let b = std::thread::spawn(move || {
            let mut storage = AuditStorage::open(&path_b).unwrap();
            for _ in 0..30 {
                storage.insert_record(&make_record()).unwrap();
            }
            let batch: Vec<AuditRecord> = (0..10).map(|_| make_record()).collect();
            storage.insert_batch(&batch).unwrap();
        });
        a.join().unwrap();
        b.join().unwrap();

        let storage = AuditStorage::open(&db_path).unwrap();
        assert_eq!(storage.count().unwrap(), 80);
        let distinct: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(DISTINCT chain_sequence) FROM audit_log",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(distinct, 80, "every chain_sequence must be unique");
        let (_, head_seq) = AuditStorage::chain_head_on(&storage.conn).unwrap();
        assert_eq!(head_seq, 80, "sequences must be gapless to the head");
        assert!(storage.duplicate_sequence_records().unwrap().is_empty());
        assert!(matches!(
            storage.verify_chain().unwrap(),
            ChainVerification::Valid { .. }
        ));
    }

    /// A legacy database that already holds duplicate sequences (pre-index
    /// fork damage) must still open — the constraint degrades soft and the
    /// fork stays visible to diagnose.
    #[test]
    fn open_succeeds_on_legacy_db_with_duplicate_sequences() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        {
            let storage = AuditStorage::open(&db_path).unwrap();
            for _ in 0..3 {
                storage.insert_record(&make_record()).unwrap();
            }
            // Simulates the 0.1.4 dual-writer damage on a pre-constraint DB.
            inject_fork_loser(&storage, 2);
        }

        let storage = AuditStorage::open(&db_path).expect("open must not fail on legacy forks");
        assert!(
            !storage.has_unique_sequence_index(),
            "constraint must degrade soft on a forked legacy DB"
        );
        assert_eq!(storage.duplicate_sequence_records().unwrap().len(), 2);
        // Writes must still work in the degraded state.
        storage.insert_record(&make_record()).unwrap();
    }

    #[test]
    fn unique_index_rejects_raw_duplicate_sequence() {
        let storage = AuditStorage::open_in_memory().unwrap();
        assert!(storage.has_unique_sequence_index());
        for _ in 0..2 {
            storage.insert_record(&make_record()).unwrap();
        }
        let err = storage
            .conn
            .execute(
                "INSERT INTO audit_log (id, timestamp, session_id, plugin_id,
                     tool_call_type, arguments_summary, arguments_hash,
                     composite_score, proxy_action, filter_results,
                     evaluation_time_ms, chain_sequence)
                 VALUES (?1, '2026-07-29T00:00:00Z', 's', 'p', 'FileRead', '{}',
                     'h', 1.0, 'allow', '[]', 1.0, 2)",
                params![Uuid::new_v4().to_string()],
            )
            .unwrap_err();
        assert!(is_constraint_violation(&err));
    }

    /// H-16: `decision_reason` and `enforcement_outcome` existed on the
    /// model but were dropped at persistence. Both insert paths must
    /// round-trip them now.
    #[test]
    fn decision_enforcement_round_trips_single_and_batch() {
        let mut storage = AuditStorage::open_in_memory().unwrap();

        let single = make_record()
            .with_decision_enforcement(Some("score 4.2 over queue threshold".into()), "denied");
        let single_id = single.id;
        storage.insert_record(&single).unwrap();

        let batched =
            make_record().with_decision_enforcement(Some("routine destination".into()), "allowed");
        let batched_id = batched.id;
        storage.insert_batch(&[batched]).unwrap();

        let got = storage.get_by_id(&single_id).unwrap();
        assert_eq!(
            got.decision_reason.as_deref(),
            Some("score 4.2 over queue threshold")
        );
        assert_eq!(got.enforcement_outcome.as_deref(), Some("denied"));

        let got = storage.get_by_id(&batched_id).unwrap();
        assert_eq!(got.decision_reason.as_deref(), Some("routine destination"));
        assert_eq!(got.enforcement_outcome.as_deref(), Some("allowed"));
    }

    /// H-16: batch-inserted compact records used to silently take the
    /// schema's `full` default because the batch INSERT omitted the column.
    #[test]
    fn batch_insert_persists_record_type_compact() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let mut record = make_record();
        record.record_type = crate::types::RecordType::Compact;
        let id = record.id;
        storage.insert_batch(&[record]).unwrap();

        let got = storage.get_by_id(&id).unwrap();
        assert_eq!(got.record_type, crate::types::RecordType::Compact);
    }

    #[test]
    fn sequence_gaps_reports_missing_ranges() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..5 {
            storage.insert_record(&make_record()).unwrap();
        }
        assert!(storage.sequence_gaps(10).unwrap().is_empty());

        storage
            .conn
            .execute("DELETE FROM audit_log WHERE chain_sequence IN (3, 4)", [])
            .unwrap();
        assert_eq!(storage.sequence_gaps(10).unwrap(), vec![(2, 5)]);
    }

    #[test]
    fn test_insert_and_retrieve() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let correlation_id = Uuid::new_v4();
        let record = make_record().with_correlation(correlation_id);
        let id = record.id;

        storage.insert_record(&record).unwrap();
        assert_eq!(storage.count().unwrap(), 1);

        let retrieved = storage.get_by_id(&id).unwrap();
        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.plugin_id, "file-ops");
        assert_eq!(retrieved.composite_score, 1.5);
        assert_eq!(retrieved.correlation_id, Some(correlation_id));
    }

    #[test]
    fn project_name_roundtrips_single_and_batch() {
        // Single insert.
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = make_record().with_project_name(Some("acme-backend".to_string()));
        let id = record.id;
        storage.insert_record(&record).unwrap();
        assert_eq!(
            storage.get_by_id(&id).unwrap().project_name.as_deref(),
            Some("acme-backend"),
        );

        // Batch insert — exercises the separate INSERT statement.
        let mut batch_storage = AuditStorage::open_in_memory().unwrap();
        let batched = make_record().with_project_name(Some("acme-frontend".to_string()));
        let batched_id = batched.id;
        batch_storage.insert_batch(&[batched]).unwrap();
        assert_eq!(
            batch_storage
                .get_by_id(&batched_id)
                .unwrap()
                .project_name
                .as_deref(),
            Some("acme-frontend"),
        );

        // A record with no project (built-in agent path) round-trips as None.
        let none_record = make_record();
        let none_id = none_record.id;
        storage.insert_record(&none_record).unwrap();
        assert_eq!(storage.get_by_id(&none_id).unwrap().project_name, None);
    }

    #[test]
    fn test_batch_insert() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let records: Vec<AuditRecord> = (0..10).map(|_| make_record()).collect();
        storage.insert_batch(&records).unwrap();
        assert_eq!(storage.count().unwrap(), 10);
    }

    #[test]
    fn test_filter_scores_persisted_and_retrieved() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = AuditRecord::new(
            Uuid::new_v4(),
            "shell".into(),
            "ShellExec".into(),
            &serde_json::json!({"command": "rm -rf /"}),
            7.5,
            ProxyActionSummary::Deny,
            vec![
                FilterResultSummary {
                    filter_name: "path-match".into(),
                    matched: true,
                    score: 3.0,
                    rule_id: "dangerous-path".into(),
                    severity: "critical".into(),
                    message: "destructive path pattern".into(),
                },
                FilterResultSummary {
                    filter_name: "command_structure".into(),
                    matched: true,
                    score: 4.5,
                    rule_id: "rm-rf".into(),
                    severity: "critical".into(),
                    message: "recursive force delete".into(),
                },
            ],
            2.1,
            Some("test".into()),
        );
        let id = record.id;

        // Verify filter_scores was populated from filter_results
        assert!(record.filter_scores.is_some());
        let scores = record.filter_scores.as_ref().unwrap();
        assert_eq!(scores.get("path-match"), Some(&3.0));
        assert_eq!(scores.get("command_structure"), Some(&4.5));

        // Insert and retrieve
        storage.insert_record(&record).unwrap();
        let retrieved = storage.get_by_id(&id).unwrap();

        // Verify filter_scores round-trips through SQLite
        assert!(retrieved.filter_scores.is_some());
        let retrieved_scores = retrieved.filter_scores.as_ref().unwrap();
        assert_eq!(retrieved_scores.get("path-match"), Some(&3.0));
        assert_eq!(retrieved_scores.get("command_structure"), Some(&4.5));
        assert_eq!(retrieved_scores.len(), 2);
    }

    // ---- PR 4 Phase F: routine-spawn forensic field round-trip ----

    #[test]
    fn phase_f_spawn_provenance_round_trips() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let mut record = make_record();
        record = record.with_spawn_provenance(
            Some("a".repeat(64)),
            Some("/usr/lib/node_modules/@openai/codex/".into()),
            Some("[{\"filter\":\"taint\",\"rule_id\":\"r\",\"score\":3.0}]".into()),
        );
        let id = record.id;
        storage.insert_record(&record).unwrap();
        let retrieved = storage.get_by_id(&id).unwrap();
        assert_eq!(
            retrieved.spawn_sha256.as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(
            retrieved.matched_routine_root.as_deref(),
            Some("/usr/lib/node_modules/@openai/codex/")
        );
        assert!(retrieved
            .shadow_phase3_filters
            .as_deref()
            .unwrap_or("")
            .contains("\"filter\":\"taint\""));
    }

    #[test]
    fn phase_f_spawn_fields_default_to_none_on_legacy_records() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = make_record(); // doesn't call with_spawn_provenance
        let id = record.id;
        storage.insert_record(&record).unwrap();
        let retrieved = storage.get_by_id(&id).unwrap();
        assert!(retrieved.spawn_sha256.is_none());
        assert!(retrieved.matched_routine_root.is_none());
        assert!(retrieved.shadow_phase3_filters.is_none());
    }

    // ---- PR 5 Phase E: listener-rewrite forensic field round-trip ----

    #[test]
    fn phase_e_listener_rewrite_round_trips() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = make_record().with_listener_rewrite(
            "0.0.0.0:41234",
            "127.0.0.1:41234",
            "MCP local server",
        );
        let id = record.id;
        storage.insert_record(&record).unwrap();
        let retrieved = storage.get_by_id(&id).unwrap();
        assert_eq!(retrieved.original_addr.as_deref(), Some("0.0.0.0:41234"));
        assert_eq!(retrieved.rewritten_addr.as_deref(), Some("127.0.0.1:41234"));
        assert_eq!(
            retrieved.clamp_profile_entry.as_deref(),
            Some("MCP local server")
        );
    }

    #[test]
    fn phase_e_listener_rewrite_fields_default_to_none() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = make_record(); // doesn't call with_listener_rewrite
        let id = record.id;
        storage.insert_record(&record).unwrap();
        let retrieved = storage.get_by_id(&id).unwrap();
        assert!(retrieved.original_addr.is_none());
        assert!(retrieved.rewritten_addr.is_none());
        assert!(retrieved.clamp_profile_entry.is_none());
    }

    #[test]
    fn phase_e_migration_adds_columns_to_legacy_schema() {
        // Simulate a pre-Phase-E DB: hand-crafted schema with all
        // Phase F columns but not the Phase E ones. Verify migration
        // adds them and a record with the new fields round-trips.
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("legacy.db");
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    plugin_id TEXT NOT NULL,
                    tool_call_type TEXT NOT NULL,
                    arguments_summary TEXT NOT NULL,
                    arguments_hash TEXT NOT NULL,
                    composite_score REAL NOT NULL,
                    proxy_action TEXT NOT NULL,
                    filter_results TEXT NOT NULL,
                    filter_scores TEXT,
                    execution_result TEXT,
                    evaluation_time_ms REAL NOT NULL,
                    task_context TEXT,
                    source TEXT NOT NULL DEFAULT 'wasm',
                    supervised_tool TEXT,
                    supervised_pid INTEGER,
                    correlation_id TEXT,
                    synced_at TEXT,
                    record_hash TEXT,
                    prev_hash TEXT,
                    chain_sequence INTEGER,
                    llm_provider TEXT,
                    llm_model TEXT,
                    prompt_tokens INTEGER,
                    completion_tokens INTEGER,
                    estimated_cost_usd REAL,
                    spawn_sha256 TEXT,
                    matched_routine_root TEXT,
                    shadow_phase3_filters TEXT
                );",
            )
            .unwrap();
        }
        let storage = AuditStorage::open(&db_path).unwrap();
        let record = make_record().with_listener_rewrite("0.0.0.0:8080", "127.0.0.1:8080", "");
        let id = record.id;
        storage.insert_record(&record).unwrap();
        let retrieved = storage.get_by_id(&id).unwrap();
        assert_eq!(retrieved.original_addr.as_deref(), Some("0.0.0.0:8080"));
        assert_eq!(retrieved.rewritten_addr.as_deref(), Some("127.0.0.1:8080"));
    }

    #[test]
    fn phase_f_migration_adds_columns_to_legacy_schema() {
        // Simulate a pre-Phase-F audit DB: create the legacy schema
        // (no spawn_sha256/matched_routine_root/shadow_phase3_filters),
        // then run AuditStorage::open() over it and verify the new
        // columns are added and rows insert / round-trip.
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("legacy.db");
        // Step 1: create just the legacy schema (mirror what shipped
        // before PR 4 Phase F).
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    plugin_id TEXT NOT NULL,
                    tool_call_type TEXT NOT NULL,
                    arguments_summary TEXT NOT NULL,
                    arguments_hash TEXT NOT NULL,
                    composite_score REAL NOT NULL,
                    proxy_action TEXT NOT NULL,
                    filter_results TEXT NOT NULL,
                    filter_scores TEXT,
                    execution_result TEXT,
                    evaluation_time_ms REAL NOT NULL,
                    task_context TEXT,
                    source TEXT NOT NULL DEFAULT 'wasm',
                    supervised_tool TEXT,
                    supervised_pid INTEGER,
                    correlation_id TEXT,
                    synced_at TEXT,
                    record_hash TEXT,
                    prev_hash TEXT,
                    chain_sequence INTEGER,
                    llm_provider TEXT,
                    llm_model TEXT,
                    prompt_tokens INTEGER,
                    completion_tokens INTEGER,
                    estimated_cost_usd REAL
                );",
            )
            .unwrap();
        }
        // Step 2: open via AuditStorage — the migration runs.
        let storage = AuditStorage::open(&db_path).unwrap();
        // Step 3: insert + retrieve with new fields populated.
        let record = make_record().with_spawn_provenance(
            Some("d".repeat(64)),
            Some("/usr/lib/node_modules/x/".into()),
            Some("[]".into()),
        );
        let id = record.id;
        storage.insert_record(&record).unwrap();
        let retrieved = storage.get_by_id(&id).unwrap();
        assert_eq!(
            retrieved.spawn_sha256.as_deref(),
            Some("d".repeat(64).as_str())
        );
        assert_eq!(
            retrieved.matched_routine_root.as_deref(),
            Some("/usr/lib/node_modules/x/")
        );
        assert_eq!(retrieved.shadow_phase3_filters.as_deref(), Some("[]"));
    }

    #[test]
    fn phase_f_idempotent_migration_against_preexisting_columns() {
        // Open + close twice — `ensure_supervisor_columns` must be
        // idempotent on the new columns.
        let _ = AuditStorage::open_in_memory().unwrap();
        let storage2 = AuditStorage::open_in_memory().unwrap();
        let record = make_record().with_spawn_provenance(Some("c".repeat(64)), None, None);
        let id = record.id;
        storage2.insert_record(&record).unwrap();
        let retrieved = storage2.get_by_id(&id).unwrap();
        assert_eq!(
            retrieved.spawn_sha256.as_deref(),
            Some("c".repeat(64).as_str())
        );
        assert!(retrieved.matched_routine_root.is_none());
    }

    #[test]
    fn test_filter_scores_none_for_empty_results() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = AuditRecord::new(
            Uuid::new_v4(),
            "file-ops".into(),
            "FileRead".into(),
            &serde_json::json!({"path": "/tmp/safe.txt"}),
            0.0,
            ProxyActionSummary::Allow,
            vec![],
            0.5,
            None,
        );
        let id = record.id;
        assert!(record.filter_scores.is_none());

        storage.insert_record(&record).unwrap();
        let retrieved = storage.get_by_id(&id).unwrap();
        assert!(retrieved.filter_scores.is_none());
    }

    #[test]
    fn test_get_recent() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..5 {
            storage.insert_record(&make_record()).unwrap();
        }
        let recent = storage.get_recent(3).unwrap();
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn test_get_by_session() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let mut record = make_record();
        record.session_id = session;
        storage.insert_record(&record).unwrap();
        storage.insert_record(&make_record()).unwrap(); // different session

        let results = storage.get_by_session(&session).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].session_id, session);
    }

    #[test]
    fn test_rotation_check_in_memory() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        assert!(!storage.check_rotation().unwrap());
    }

    #[test]
    fn test_get_unsynced() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..5 {
            storage.insert_record(&make_record()).unwrap();
        }
        let unsynced = storage.get_unsynced(10).unwrap();
        assert_eq!(unsynced.len(), 5);
        assert_eq!(storage.count_unsynced().unwrap(), 5);
    }

    #[test]
    fn test_mark_synced() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let mut ids = Vec::new();
        for _ in 0..5 {
            let r = make_record();
            ids.push(r.id);
            storage.insert_record(&r).unwrap();
        }
        // Mark first 3 as synced
        storage.mark_synced(&ids[..3]).unwrap();
        assert_eq!(storage.count_unsynced().unwrap(), 2);
        let remaining = storage.get_unsynced(10).unwrap();
        assert_eq!(remaining.len(), 2);
    }

    // --- Hash-chaining tests ---

    #[test]
    fn test_chain_single_insert() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = make_record();
        let id = record.id;
        storage.insert_record(&record).unwrap();

        let retrieved = storage.get_by_id(&id).unwrap();
        assert!(retrieved.record_hash.is_some(), "record_hash should be set");
        assert!(
            retrieved.prev_hash.is_none(),
            "first record has no prev_hash"
        );
        assert_eq!(retrieved.chain_sequence, Some(1));
    }

    #[test]
    fn test_chain_multiple_inserts() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let mut ids = Vec::new();
        for _ in 0..3 {
            let r = make_record();
            ids.push(r.id);
            storage.insert_record(&r).unwrap();
        }

        let r1 = storage.get_by_id(&ids[0]).unwrap();
        let r2 = storage.get_by_id(&ids[1]).unwrap();
        let r3 = storage.get_by_id(&ids[2]).unwrap();

        assert_eq!(r1.chain_sequence, Some(1));
        assert_eq!(r2.chain_sequence, Some(2));
        assert_eq!(r3.chain_sequence, Some(3));

        // Chain links: r2.prev_hash == r1.record_hash
        assert_eq!(r2.prev_hash, r1.record_hash);
        assert_eq!(r3.prev_hash, r2.record_hash);

        // First record has no prev
        assert!(r1.prev_hash.is_none());
    }

    #[test]
    fn test_chain_batch_insert() {
        let mut storage = AuditStorage::open_in_memory().unwrap();
        let records: Vec<AuditRecord> = (0..5).map(|_| make_record()).collect();
        let ids: Vec<Uuid> = records.iter().map(|r| r.id).collect();
        storage.insert_batch(&records).unwrap();

        let r1 = storage.get_by_id(&ids[0]).unwrap();
        let r2 = storage.get_by_id(&ids[1]).unwrap();
        let r5 = storage.get_by_id(&ids[4]).unwrap();

        assert_eq!(r1.chain_sequence, Some(1));
        assert_eq!(r5.chain_sequence, Some(5));
        assert_eq!(r2.prev_hash, r1.record_hash);
        assert!(r1.prev_hash.is_none());
    }

    #[test]
    fn test_chain_verify_valid() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..5 {
            storage.insert_record(&make_record()).unwrap();
        }
        let result = storage.verify_chain().unwrap();
        assert_eq!(result, ChainVerification::Valid { record_count: 5 });
    }

    #[test]
    fn test_chain_verify_empty() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let result = storage.verify_chain().unwrap();
        assert_eq!(result, ChainVerification::Empty);
    }

    #[test]
    fn test_backfill_legacy_rows_and_verify() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = make_record();
        let filter_results_json = serde_json::to_string(&record.filter_results).unwrap();
        storage
            .conn
            .execute(
                "INSERT INTO audit_log (
                    id, timestamp, session_id, plugin_id, tool_call_type,
                    arguments_summary, arguments_hash, composite_score, proxy_action,
                    filter_results, execution_result, evaluation_time_ms, task_context,
                    source, supervised_tool, supervised_pid, correlation_id,
                    record_hash, prev_hash, chain_sequence
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, NULL, NULL, NULL)",
                params![
                    record.id.to_string(),
                    record.timestamp.to_rfc3339(),
                    record.session_id.to_string(),
                    record.plugin_id,
                    record.tool_call_type,
                    record.arguments_summary,
                    record.arguments_hash,
                    record.composite_score,
                    record.proxy_action.to_string(),
                    filter_results_json,
                    record.execution_result,
                    record.evaluation_time_ms,
                    record.task_context,
                    record.source,
                    record.supervised_tool,
                    record.supervised_pid,
                    record.correlation_id.map(|id| id.to_string()),
                ],
            )
            .unwrap();

        let before = storage.verify_chain().unwrap();
        assert!(
            matches!(before, ChainVerification::Broken { at_sequence: 0, .. }),
            "expected legacy row to fail chain verification, got {before:?}"
        );

        let updated = storage.backfill_chain_for_legacy_rows().unwrap();
        assert_eq!(updated, 1);

        let after = storage.verify_chain().unwrap();
        assert_eq!(after, ChainVerification::Valid { record_count: 1 });
    }

    #[test]
    fn test_chain_verify_tampered() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..3 {
            storage.insert_record(&make_record()).unwrap();
        }

        // Tamper with the second record's hash
        storage
            .conn
            .execute(
                "UPDATE audit_log SET record_hash = 'tampered' WHERE chain_sequence = 2",
                [],
            )
            .unwrap();

        let result = storage.verify_chain().unwrap();
        match result {
            ChainVerification::Broken {
                at_sequence,
                reason,
                ..
            } => {
                // The break could be detected at seq 2 (hash mismatch) or seq 3 (prev_hash mismatch)
                assert!(
                    at_sequence >= 2,
                    "break should be at sequence 2 or 3, got {at_sequence}"
                );
                assert!(!reason.is_empty());
            }
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    #[test]
    fn test_chain_rotation_resets() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let mut storage = AuditStorage::open(&db_path).unwrap().with_max_size(500);

        // Insert enough records to trigger rotation
        for _ in 0..50 {
            storage.insert_record(&make_record()).unwrap();
        }

        let rotated = storage.check_rotation().unwrap();
        if rotated {
            // New chain starts fresh
            let result = storage.verify_chain().unwrap();
            assert_eq!(result, ChainVerification::Empty);

            // Insert into new DB and verify chain starts from genesis
            storage.insert_record(&make_record()).unwrap();
            let result = storage.verify_chain().unwrap();
            assert_eq!(result, ChainVerification::Valid { record_count: 1 });
        }
    }

    #[test]
    fn test_rotation_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let mut storage = AuditStorage::open(&db_path).unwrap().with_max_size(500);

        // Insert enough records to exceed 500 bytes
        for _ in 0..50 {
            storage.insert_record(&make_record()).unwrap();
        }

        let rotated = storage.check_rotation().unwrap();
        if rotated {
            // Verify new db is fresh
            assert_eq!(storage.count().unwrap(), 0);
            // Verify rotated file exists
            let rotated_files: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .map(|n| n.starts_with("audit-"))
                        .unwrap_or(false)
                })
                .collect();
            assert!(!rotated_files.is_empty());
        }
    }

    // ---- Stage 1: incremental verify + cache ----

    fn read_checkpoint_seq(storage: &AuditStorage) -> Option<i64> {
        storage
            .load_chain_checkpoint()
            .unwrap()
            .map(|c| c.last_verified_sequence)
    }

    #[test]
    fn incremental_verify_on_empty_db_returns_empty_and_writes_no_checkpoint() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let result = storage.incremental_verify_chain().unwrap();
        assert_eq!(result, ChainVerification::Empty);
        assert_eq!(read_checkpoint_seq(&storage), None);
    }

    #[test]
    fn incremental_verify_advances_checkpoint_to_head() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..5 {
            storage.insert_record(&make_record()).unwrap();
        }
        let r = storage.incremental_verify_chain().unwrap();
        assert_eq!(r, ChainVerification::Valid { record_count: 5 });
        assert_eq!(read_checkpoint_seq(&storage), Some(5));
    }

    #[test]
    fn incremental_verify_walks_only_new_rows_on_second_call() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..3 {
            storage.insert_record(&make_record()).unwrap();
        }
        let r1 = storage.incremental_verify_chain().unwrap();
        assert_eq!(r1, ChainVerification::Valid { record_count: 3 });
        for _ in 0..2 {
            storage.insert_record(&make_record()).unwrap();
        }
        let r2 = storage.incremental_verify_chain().unwrap();
        // Walk reports cumulative count (prefix carried via checkpoint).
        assert_eq!(r2, ChainVerification::Valid { record_count: 5 });
        assert_eq!(read_checkpoint_seq(&storage), Some(5));
    }

    #[test]
    fn incremental_verify_no_op_when_no_new_rows() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..3 {
            storage.insert_record(&make_record()).unwrap();
        }
        storage.incremental_verify_chain().unwrap();
        // Second call: no new rows, checkpoint stays at 3.
        let r = storage.incremental_verify_chain().unwrap();
        assert_eq!(r, ChainVerification::Valid { record_count: 3 });
        assert_eq!(read_checkpoint_seq(&storage), Some(3));
    }

    #[test]
    fn incremental_verify_catches_tamper_after_checkpoint() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..3 {
            storage.insert_record(&make_record()).unwrap();
        }
        storage.incremental_verify_chain().unwrap();
        // Append more rows, then tamper one of them.
        for _ in 0..3 {
            storage.insert_record(&make_record()).unwrap();
        }
        storage
            .conn
            .execute(
                "UPDATE audit_log SET record_hash = 'tampered' WHERE chain_sequence = 5",
                [],
            )
            .unwrap();
        let r = storage.incremental_verify_chain().unwrap();
        assert!(matches!(r, ChainVerification::Broken { .. }));
        // Checkpoint must not have advanced past the break.
        assert_eq!(read_checkpoint_seq(&storage), Some(3));
        // Retry catches it again — marker still stuck at 3.
        let r2 = storage.incremental_verify_chain().unwrap();
        assert!(matches!(r2, ChainVerification::Broken { .. }));
    }

    #[test]
    fn incremental_verify_misses_tamper_before_checkpoint_full_verify_catches_it() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..5 {
            storage.insert_record(&make_record()).unwrap();
        }
        // Establish marker at head.
        storage.incremental_verify_chain().unwrap();
        assert_eq!(read_checkpoint_seq(&storage), Some(5));
        // Tamper a row BELOW the marker.
        storage
            .conn
            .execute(
                "UPDATE audit_log SET record_hash = 'tampered' WHERE chain_sequence = 2",
                [],
            )
            .unwrap();
        // Incremental misses it (documented limitation).
        let r_inc = storage.incremental_verify_chain().unwrap();
        assert!(
            matches!(r_inc, ChainVerification::Valid { .. }),
            "incremental should still report Valid: {r_inc:?}"
        );
        // Full verify catches it — operator's escape hatch.
        let r_full = storage.verify_chain().unwrap();
        assert!(
            matches!(r_full, ChainVerification::Broken { .. }),
            "full verify should report Broken: {r_full:?}"
        );
    }

    #[test]
    fn cached_verify_reuses_result_until_invalidated() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..3 {
            storage.insert_record(&make_record()).unwrap();
        }
        let r1 = storage.cached_verify_chain().unwrap();
        assert_eq!(r1, ChainVerification::Valid { record_count: 3 });
        // Cache populated — direct check.
        assert!(storage.verify_cache.lock().unwrap().is_some());
        // Tamper directly (bypass insert path so cache is NOT invalidated).
        storage
            .conn
            .execute(
                "UPDATE audit_log SET record_hash = 'tampered' WHERE chain_sequence = 2",
                [],
            )
            .unwrap();
        // Cache still returns the prior Valid result — proof the cache is hot.
        let r2 = storage.cached_verify_chain().unwrap();
        assert_eq!(r2, ChainVerification::Valid { record_count: 3 });
        // Now go through the proper insert path → cache invalidated.
        storage.insert_record(&make_record()).unwrap();
        assert!(storage.verify_cache.lock().unwrap().is_none());
    }

    #[test]
    fn repair_chain_clears_checkpoint() {
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..3 {
            storage.insert_record(&make_record()).unwrap();
        }
        storage.incremental_verify_chain().unwrap();
        assert_eq!(read_checkpoint_seq(&storage), Some(3));
        // Tamper, then repair — repair rewrites the chain so the
        // checkpoint must be cleared.
        storage
            .conn
            .execute(
                "UPDATE audit_log SET record_hash = 'tampered' WHERE chain_sequence = 2",
                [],
            )
            .unwrap();
        let repaired = storage.repair_chain().unwrap();
        assert!(repaired > 0);
        assert_eq!(read_checkpoint_seq(&storage), None);
        // Post-repair verify rebuilds the marker.
        let r = storage.incremental_verify_chain().unwrap();
        assert_eq!(r, ChainVerification::Valid { record_count: 3 });
        assert_eq!(read_checkpoint_seq(&storage), Some(3));
    }

    // ---- Stage 3: per-row column compression ----

    fn make_record_with_large_filter_results() -> AuditRecord {
        let filters: Vec<FilterResultSummary> = (0..30)
            .map(|i| FilterResultSummary {
                filter_name: format!("filter_{i}"),
                matched: true,
                score: 1.0 + i as f64 * 0.1,
                rule_id: format!("rule-{i}"),
                severity: "warning".into(),
                message: format!("filter {i} matched on aaaaaaaaaaaaaaaa{i}aaaaaaaaaaaaaaaa"),
            })
            .collect();
        AuditRecord::new(
            Uuid::new_v4(),
            "supervisor".into(),
            "ShellExec".into(),
            &serde_json::json!({"command": "rm -rf /tmp/aaaaaaaaaaaaaaaaaaaa"}),
            6.5,
            ProxyActionSummary::Queue,
            filters,
            1.5,
            Some("scenario test".into()),
        )
    }

    #[test]
    fn stage3_round_trips_compressed_columns() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = make_record_with_large_filter_results();
        let id = record.id;
        storage.insert_record(&record).unwrap();
        let retrieved = storage.get_by_id(&id).unwrap();
        assert_eq!(retrieved.arguments_summary, record.arguments_summary);
        assert_eq!(retrieved.filter_results.len(), record.filter_results.len());
        for (a, b) in retrieved
            .filter_results
            .iter()
            .zip(record.filter_results.iter())
        {
            assert_eq!(a.filter_name, b.filter_name);
            assert_eq!(a.message, b.message);
        }
        // Maps must have the same keys + approximately the same values.
        // Exact f64 equality is too brittle: serializing through JSON can
        // shift the last ULP on `1.0 + 28*0.1`-style accumulated values,
        // unrelated to compression.
        let lhs = retrieved.filter_scores.as_ref().unwrap();
        let rhs = record.filter_scores.as_ref().unwrap();
        assert_eq!(lhs.len(), rhs.len());
        for (k, v) in rhs {
            let got = lhs.get(k).copied().unwrap_or(f64::NAN);
            assert!((got - v).abs() < 1e-9, "key {k}: {got} vs {v}");
        }
    }

    #[test]
    fn stage3_actually_compresses_in_storage() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = make_record_with_large_filter_results();
        storage.insert_record(&record).unwrap();
        // Verify the raw column starts with the zstd magic — proving
        // compression ran and didn't fall back to plaintext.
        let blob: Vec<u8> = storage
            .conn
            .query_row("SELECT filter_results FROM audit_log LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(
            crate::compression::is_compressed(&blob),
            "expected filter_results to be zstd-compressed; first 4 bytes: {:?}",
            &blob[..blob.len().min(4)]
        );
    }

    #[test]
    fn stage3_legacy_plaintext_rows_still_read() {
        // Simulate a row written before Stage 3: raw TEXT column.
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = make_record_with_large_filter_results();
        let id = record.id;
        storage.insert_record(&record).unwrap();
        // Overwrite the compressed columns with their plaintext form,
        // emulating a legacy row that survived a Stage 3 deployment.
        let filter_results_json = serde_json::to_string(&record.filter_results).unwrap();
        let filter_scores_json = serde_json::to_string(&record.filter_scores).unwrap();
        storage
            .conn
            .execute(
                "UPDATE audit_log SET arguments_summary = ?1, \
                     filter_results = ?2, filter_scores = ?3 WHERE id = ?4",
                rusqlite::params![
                    record.arguments_summary,
                    filter_results_json,
                    filter_scores_json,
                    id.to_string(),
                ],
            )
            .unwrap();
        // Decoder must accept the legacy TEXT form transparently.
        let retrieved = storage.get_by_id(&id).unwrap();
        assert_eq!(retrieved.arguments_summary, record.arguments_summary);
        assert_eq!(retrieved.filter_results.len(), record.filter_results.len());
    }

    #[test]
    fn stage3_chain_verify_unaffected_by_compression() {
        // Hash chain uses arguments_hash, not arguments_summary, so
        // compressed and plaintext rows must verify together.
        let storage = AuditStorage::open_in_memory().unwrap();
        for _ in 0..3 {
            storage
                .insert_record(&make_record_with_large_filter_results())
                .unwrap();
        }
        // Tamper-free chain still verifies.
        let v = storage.verify_chain().unwrap();
        assert_eq!(v, ChainVerification::Valid { record_count: 3 });
    }

    #[test]
    fn cached_verify_initially_empty() {
        let storage = AuditStorage::open_in_memory().unwrap();
        assert!(storage.verify_cache.lock().unwrap().is_none());
        let r = storage.cached_verify_chain().unwrap();
        assert_eq!(r, ChainVerification::Empty);
    }

    // ── H-19: physical footprint lifecycle ───────────────────────────────

    /// Deleting rows does not shrink a SQLite file — the pages move to the
    /// freelist. Measuring live vs free bytes is what makes that visible;
    /// file length alone reports the peak and never recovers.
    #[test]
    fn footprint_separates_live_data_from_reclaimable_free_pages() {
        let dir = tempfile::tempdir().unwrap();
        let storage = AuditStorage::open(dir.path().join("audit.db")).unwrap();
        for _ in 0..200 {
            storage
                .insert_record(&make_record_with_large_filter_results())
                .unwrap();
        }
        let full = storage.footprint().unwrap();
        assert!(full.live_bytes > 0);

        storage.conn.execute("DELETE FROM audit_log", []).unwrap();

        let emptied = storage.footprint().unwrap();
        assert!(
            emptied.free_bytes > 0,
            "deleted pages should be on the freelist, saw {emptied:?}"
        );
        assert!(
            emptied.live_bytes < full.live_bytes,
            "live bytes should fall after deletion: {} -> {}",
            full.live_bytes,
            emptied.live_bytes
        );
        assert!(
            emptied.free_ratio() > 0.0,
            "free ratio should be non-zero, saw {emptied:?}"
        );
    }

    /// Compaction must reclaim free pages and leave a chain that still
    /// verifies — the copy is proven before it replaces the original.
    #[test]
    fn compact_reclaims_free_pages_and_preserves_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let mut storage = AuditStorage::open(&db).unwrap();
        for _ in 0..200 {
            storage
                .insert_record(&make_record_with_large_filter_results())
                .unwrap();
        }
        // Delete most of the rows, leaving a large freelist behind.
        storage
            .conn
            .execute("DELETE FROM audit_log WHERE chain_sequence > 5", [])
            .unwrap();
        storage.invalidate_verify_cache();

        let before_free = storage.footprint().unwrap().free_bytes;
        assert!(before_free > 0, "expected free pages before compaction");

        let (before, after) = storage.compact().unwrap();
        assert_eq!(before.free_bytes, before_free);
        assert!(
            after.free_bytes < before.free_bytes,
            "compaction should reclaim free pages: {} -> {}",
            before.free_bytes,
            after.free_bytes
        );
        assert!(
            after.db_file_bytes < before.db_file_bytes,
            "the file should shrink: {} -> {}",
            before.db_file_bytes,
            after.db_file_bytes
        );

        // The surviving records still verify, and the database is usable.
        assert_eq!(
            storage.verify_chain().unwrap(),
            ChainVerification::Valid { record_count: 5 }
        );
        storage.insert_record(&make_record()).unwrap();
        assert_eq!(storage.count().unwrap(), 6);

        // No temporary or preserved copy is left behind on success.
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("compact") || n.contains("pre-compact"))
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    /// B12 #73 LOW: the compact swap is atomic — after it returns, `db_path`
    /// holds a clean, standalone database with no `.pre-compact` backup left
    /// behind, and it reopens correctly from a *fresh* handle (proving the
    /// swapped-in file is self-consistent and not shadowed by a stale WAL
    /// from the pre-compaction database).
    #[test]
    fn compact_swaps_in_a_clean_standalone_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        {
            let mut storage = AuditStorage::open(&db).unwrap();
            for _ in 0..50 {
                storage
                    .insert_record(&make_record_with_large_filter_results())
                    .unwrap();
            }
            storage
                .conn
                .execute("DELETE FROM audit_log WHERE chain_sequence > 3", [])
                .unwrap();
            storage.invalidate_verify_cache();
            storage.compact().unwrap();
            // db_path is present the entire time and no backup lingers.
            assert!(db.exists(), "db_path must never be absent after compaction");
        }

        // Reopen from scratch — a stale WAL or a half-swapped file would
        // surface here as a verification break or a missing row.
        let reopened = AuditStorage::open(&db).unwrap();
        assert_eq!(
            reopened.verify_chain().unwrap(),
            ChainVerification::Valid { record_count: 3 }
        );

        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("pre-compact") || n.contains("audit-compact-"))
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    /// Rotation must key off live data, not file length. A database that is
    /// mostly freelist would otherwise rotate — starting a new chain segment
    /// to reclaim space SQLite was about to reuse anyway.
    #[test]
    fn rotation_ignores_reclaimable_free_space() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = AuditStorage::open(dir.path().join("audit.db")).unwrap();
        for _ in 0..200 {
            storage
                .insert_record(&make_record_with_large_filter_results())
                .unwrap();
        }
        let grown = storage.footprint().unwrap();
        storage.conn.execute("DELETE FROM audit_log", []).unwrap();

        // Threshold between live-after-delete and the file's peak size: the
        // old file-length check would trip, the live-bytes check must not.
        storage.max_size_bytes = grown.db_file_bytes / 2;
        let after = storage.footprint().unwrap();
        assert!(
            after.live_bytes < storage.max_size_bytes,
            "fixture invalid: live {} should be under threshold {}",
            after.live_bytes,
            storage.max_size_bytes
        );
        assert!(
            after.db_file_bytes >= storage.max_size_bytes,
            "fixture invalid: file {} should exceed threshold {}",
            after.db_file_bytes,
            storage.max_size_bytes
        );

        assert!(
            !storage.check_rotation().unwrap(),
            "must not rotate a database whose bulk is reclaimable free space"
        );
    }

    /// The journal must not be allowed to grow without bound, and a
    /// checkpoint must leave the chain intact.
    #[test]
    fn checkpoint_bounds_the_write_ahead_log() {
        let dir = tempfile::tempdir().unwrap();
        let storage = AuditStorage::open(dir.path().join("audit.db")).unwrap();

        let limit: i64 = storage
            .conn
            .query_row("PRAGMA journal_size_limit", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            limit, WAL_SIZE_LIMIT_BYTES,
            "journal size limit not applied"
        );

        for _ in 0..100 {
            storage
                .insert_record(&make_record_with_large_filter_results())
                .unwrap();
        }
        storage.checkpoint_wal().unwrap();

        let after = storage.footprint().unwrap();
        assert!(
            after.wal_file_bytes <= WAL_SIZE_LIMIT_BYTES as u64,
            "WAL should be bounded after checkpoint, saw {}",
            after.wal_file_bytes
        );
        assert!(matches!(
            storage.verify_chain().unwrap(),
            ChainVerification::Valid { .. }
        ));
    }

    // ── B12 item 5: full-record hash v2 ──────────────────────────────────

    /// Build a record with EVERY optional field populated, so the
    /// round-trip and mutation suites below exercise the whole surface
    /// rather than the handful of fields a default record sets.
    fn make_fully_populated_record() -> AuditRecord {
        let mut r = make_record();
        r.decision_reason = Some("matched ssh-private-key".into());
        r.enforcement_outcome = Some("denied".into());
        r.filter_scores = Some(HashMap::from([
            ("path-match".to_string(), 5.0),
            ("sensitive_path".to_string(), 4.0),
            ("taint".to_string(), 0.5),
        ]));
        r.execution_result = Some("EPERM".into());
        r.task_context = Some("audit hash coverage".into());
        r.source = "supervisor".into();
        r.supervised_tool = Some("claude-code".into());
        r.supervised_pid = Some(4242);
        r.project_name = Some("grith".into());
        r.correlation_id = Some(Uuid::new_v4());
        r.llm_provider = Some("anthropic".into());
        r.llm_model = Some("claude-opus-5".into());
        r.prompt_tokens = Some(1234);
        r.completion_tokens = Some(567);
        r.estimated_cost_usd = Some(0.0421);
        r.spawn_sha256 = Some("a".repeat(64));
        r.matched_routine_root = Some("/usr/lib/node_modules".into());
        r.shadow_phase3_filters = Some(r#"[{"filter":"taint","score":3.0}]"#.into());
        r.original_addr = Some("0.0.0.0:8080".into());
        r.rewritten_addr = Some("127.0.0.1:8080".into());
        r.clamp_profile_entry = Some("dashboard listener".into());
        r.filter_results = vec![
            FilterResultSummary {
                filter_name: "path-match".into(),
                matched: true,
                score: 5.0,
                rule_id: "ssh-private-key".into(),
                severity: "critical".into(),
                message: "private key access".into(),
            },
            FilterResultSummary {
                filter_name: "sensitive_path".into(),
                matched: true,
                score: 4.0,
                rule_id: "key-material-file".into(),
                severity: "warning".into(),
                message: "key material".into(),
            },
        ];
        r
    }

    /// The hard prerequisite for v2: every field the hash covers must
    /// survive the write→read round trip byte-for-byte. If any did not,
    /// the recomputed hash would differ from the stored one on the very
    /// next verify and the daemon would quarantine a healthy chain.
    #[test]
    fn every_hashed_field_round_trips_through_persistence() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = make_fully_populated_record();
        storage.insert_record(&record).unwrap();

        let loaded = storage.get_by_id(&record.id).unwrap();

        // Re-hashing the loaded row under the same chain position must
        // reproduce the stored hash. This is the property verification
        // depends on, stated directly.
        assert_eq!(
            loaded.compute_record_hash(),
            loaded.record_hash.clone().unwrap(),
            "recomputed hash of the persisted row differs from the stored hash"
        );
        assert_eq!(loaded.hash_version, crate::types::CURRENT_HASH_VERSION);

        // Field-level equality, so a future column that silently fails to
        // persist is named by the failing assertion rather than showing up
        // as an opaque hash mismatch.
        assert_eq!(loaded.decision_reason, record.decision_reason);
        assert_eq!(loaded.enforcement_outcome, record.enforcement_outcome);
        assert_eq!(loaded.filter_scores, record.filter_scores);
        assert_eq!(loaded.execution_result, record.execution_result);
        assert_eq!(loaded.task_context, record.task_context);
        assert_eq!(loaded.source, record.source);
        assert_eq!(loaded.supervised_tool, record.supervised_tool);
        assert_eq!(loaded.supervised_pid, record.supervised_pid);
        assert_eq!(loaded.project_name, record.project_name);
        assert_eq!(loaded.correlation_id, record.correlation_id);
        assert_eq!(loaded.llm_provider, record.llm_provider);
        assert_eq!(loaded.llm_model, record.llm_model);
        assert_eq!(loaded.prompt_tokens, record.prompt_tokens);
        assert_eq!(loaded.completion_tokens, record.completion_tokens);
        assert_eq!(loaded.estimated_cost_usd, record.estimated_cost_usd);
        assert_eq!(loaded.spawn_sha256, record.spawn_sha256);
        assert_eq!(loaded.matched_routine_root, record.matched_routine_root);
        assert_eq!(loaded.shadow_phase3_filters, record.shadow_phase3_filters);
        assert_eq!(loaded.original_addr, record.original_addr);
        assert_eq!(loaded.rewritten_addr, record.rewritten_addr);
        assert_eq!(loaded.clamp_profile_entry, record.clamp_profile_entry);
        assert_eq!(loaded.record_type, record.record_type);
        assert_eq!(loaded.arguments_summary, record.arguments_summary);
        assert_eq!(loaded.filter_results.len(), record.filter_results.len());
        assert_eq!(loaded.evaluation_time_ms, record.evaluation_time_ms);
        assert_eq!(loaded.composite_score, record.composite_score);
    }

    /// Mutate one persisted field at a time on a committed v2 row and
    /// assert verification reports `Broken` at that row. This is the test
    /// the go-live review asks for by name: it is what makes "the hash
    /// covers the record" a checked claim rather than an assertion.
    #[test]
    fn v2_hash_detects_mutation_of_every_persisted_field() {
        // (column, SQL literal that differs from what the record stores)
        let mutations: &[(&str, &str)] = &[
            ("plugin_id", "'tampered'"),
            ("tool_call_type", "'ShellExec'"),
            ("arguments_hash", "'0000'"),
            ("composite_score", "9.9"),
            ("proxy_action", "'deny'"),
            ("decision_reason", "'looked fine to me'"),
            ("enforcement_outcome", "'allowed'"),
            ("execution_result", "'ok'"),
            ("evaluation_time_ms", "99.5"),
            ("task_context", "'other'"),
            ("source", "'wasm'"),
            ("supervised_tool", "'codex'"),
            ("supervised_pid", "1"),
            ("project_name", "'other-project'"),
            ("correlation_id", "'00000000-0000-0000-0000-000000000001'"),
            ("llm_provider", "'openai'"),
            ("llm_model", "'gpt-4'"),
            ("prompt_tokens", "1"),
            ("completion_tokens", "1"),
            ("estimated_cost_usd", "0.0"),
            ("spawn_sha256", "'deadbeef'"),
            ("matched_routine_root", "'/tmp'"),
            ("shadow_phase3_filters", "'[]'"),
            ("original_addr", "'10.0.0.1:8080'"),
            ("rewritten_addr", "'10.0.0.1:8080'"),
            ("clamp_profile_entry", "'other rule'"),
            ("record_type", "'compact'"),
            ("timestamp", "'2020-01-01T00:00:00+00:00'"),
            ("session_id", "'00000000-0000-0000-0000-000000000002'"),
            // Content columns are stored compressed-or-plain; plain TEXT
            // reads back fine through read_text_or_blob.
            ("arguments_summary", "'{\"path\":\"/etc/passwd\"}'"),
            ("filter_results", "'[]'"),
            ("filter_scores", "'{\"path-match\":0.0}'"),
            // Downgrading the version must not buy an attacker the weaker
            // v1 coverage: hash_version is itself inside the v2 hash.
            ("hash_version", "1"),
        ];

        for (column, value) in mutations {
            let storage = AuditStorage::open_in_memory().unwrap();
            let record = make_fully_populated_record();
            storage.insert_record(&record).unwrap();
            assert!(
                matches!(
                    storage.verify_chain().unwrap(),
                    ChainVerification::Valid { .. }
                ),
                "chain should be valid before mutating {column}"
            );

            storage
                .conn
                .execute(
                    &format!("UPDATE audit_log SET {column} = {value} WHERE id = ?1"),
                    params![record.id.to_string()],
                )
                .unwrap();
            storage.invalidate_verify_cache();

            let verdict = storage.verify_chain().unwrap();
            assert!(
                matches!(verdict, ChainVerification::Broken { .. }),
                "mutating {column} was NOT detected — verification returned {verdict:?}"
            );
        }
    }

    /// B12 #69: the mutation battery above changes an enum's *semantics*
    /// ('full' -> 'compact'), which the recomputed hash already catches. The
    /// subtler attack keeps the same variant but a non-canonical byte form —
    /// a case or whitespace variant, or an unknown value the lenient reader
    /// folds back to the default. Such a value leaves the recomputed hash
    /// identical (the hash covers only `to_string()`) yet hides the row from
    /// the case-sensitive default audit view (`WHERE record_type = 'full'`)
    /// or silently reclassifies a decision. Verify must treat it as a break.
    #[test]
    fn v2_hash_invariant_enum_case_tamper_is_detected() {
        // (column, non-canonical literal that folds back to the row's own
        // variant so the record hash is unchanged). The base record is
        // record_type=Full, proxy_action=Allow.
        let evasions: &[(&str, &str)] = &[
            ("record_type", "'Full'"), // case variant -> Full via `_`
            ("record_type", "'FULL'"),
            ("record_type", "' full '"),  // whitespace variant
            ("record_type", "'Compact'"), // unknown case -> defaults to Full
            ("proxy_action", "'Allow'"),  // case variant -> Allow (lenient)
            ("proxy_action", "'ALLOW'"),
            ("proxy_action", "'unknown-action'"), // unknown -> defaults to Allow
        ];

        for (column, value) in evasions {
            let storage = AuditStorage::open_in_memory().unwrap();
            let record = make_fully_populated_record();
            storage.insert_record(&record).unwrap();

            storage
                .conn
                .execute(
                    &format!("UPDATE audit_log SET {column} = {value} WHERE id = ?1"),
                    params![record.id.to_string()],
                )
                .unwrap();
            storage.invalidate_verify_cache();

            // Prove the tamper is genuinely hash-invariant: the recomputed
            // record hash still matches what is stored, so without the
            // raw-byte check in verify this row would report Valid.
            let reloaded = storage.get_by_id(&record.id).unwrap();
            assert_eq!(
                reloaded.record_hash.as_deref(),
                Some(reloaded.compute_record_hash().as_str()),
                "{column}={value} should be hash-invariant (folds to same variant)"
            );

            let verdict = storage.verify_chain().unwrap();
            assert!(
                matches!(verdict, ChainVerification::Broken { .. }),
                "hash-invariant tamper {column}={value} was NOT detected — got {verdict:?}"
            );
        }
    }

    /// A database written entirely by an older build keeps verifying: its
    /// rows carry no `hash_version`, so they are read as v1 and checked
    /// with the legacy canonical form. Nothing is rewritten.
    #[test]
    fn legacy_v1_rows_still_verify_untouched() {
        let storage = AuditStorage::open_in_memory().unwrap();

        // Write three rows the way the old build did: v1 hashes, and the
        // column left NULL as a pre-migration row would have it.
        let mut prev: Option<String> = None;
        for seq in 1..=3i64 {
            let mut r = make_record();
            r.hash_version = crate::types::LEGACY_HASH_VERSION;
            r.chain_sequence = Some(seq);
            r.prev_hash = prev.clone();
            r.record_hash = Some(r.compute_record_hash());
            prev = r.record_hash.clone();
            AuditStorage::execute_insert(&storage.conn, &r).unwrap();
            storage
                .conn
                .execute(
                    "UPDATE audit_log SET hash_version = NULL WHERE id = ?1",
                    params![r.id.to_string()],
                )
                .unwrap();
        }
        storage.invalidate_verify_cache();

        assert_eq!(
            storage.verify_chain().unwrap(),
            ChainVerification::Valid { record_count: 3 }
        );
    }

    /// The upgrade path: a database that already holds v1 history keeps
    /// verifying end to end once new v2 rows are appended on top. The link
    /// across the boundary works because `prev_hash` is opaque text — the
    /// v2 row hashes the v1 row's hash without caring how it was made.
    #[test]
    fn mixed_v1_and_v2_chain_verifies_end_to_end() {
        let storage = AuditStorage::open_in_memory().unwrap();

        let mut prev: Option<String> = None;
        for seq in 1..=2i64 {
            let mut r = make_record();
            r.hash_version = crate::types::LEGACY_HASH_VERSION;
            r.chain_sequence = Some(seq);
            r.prev_hash = prev.clone();
            r.record_hash = Some(r.compute_record_hash());
            prev = r.record_hash.clone();
            AuditStorage::execute_insert(&storage.conn, &r).unwrap();
        }
        storage.invalidate_verify_cache();

        // Append explicit v2 rows. New constructors now stamp v3, so pinning
        // the version here keeps this compatibility boundary meaningful.
        let mut first_v2 = make_fully_populated_record();
        first_v2.hash_version = crate::types::HASH_VERSION_V2;
        let mut second_v2 = make_record();
        second_v2.hash_version = crate::types::HASH_VERSION_V2;
        storage.insert_record(&first_v2).unwrap();
        storage.insert_record(&second_v2).unwrap();

        assert_eq!(
            storage.verify_chain().unwrap(),
            ChainVerification::Valid { record_count: 4 }
        );

        let versions: Vec<i64> = storage
            .conn
            .prepare("SELECT COALESCE(hash_version, 1) FROM audit_log ORDER BY chain_sequence")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(versions, vec![1, 1, 2, 2], "expected a v1→v2 boundary");
    }

    /// An unrecognised version must fail loudly rather than being waved
    /// through by a permissive fallback.
    #[test]
    fn unknown_hash_version_fails_closed() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let record = make_record();
        storage.insert_record(&record).unwrap();
        storage
            .conn
            .execute(
                "UPDATE audit_log SET hash_version = 99 WHERE id = ?1",
                params![record.id.to_string()],
            )
            .unwrap();
        storage.invalidate_verify_cache();

        assert!(matches!(
            storage.verify_chain().unwrap(),
            ChainVerification::Broken { .. }
        ));
    }

    /// `filter_scores` is a `HashMap`, whose iteration order differs run to
    /// run. If the canonical form inherited that order the hash would be
    /// unstable and every restart would report tampering.
    #[test]
    fn v2_hash_is_stable_across_hashmap_iteration_order() {
        let mut a = make_fully_populated_record();
        let mut b = a.clone();

        // Same pairs, built by different insertion orders.
        a.filter_scores = Some(HashMap::from([
            ("zzz".to_string(), 1.0),
            ("aaa".to_string(), 2.0),
            ("mmm".to_string(), 3.0),
        ]));
        let mut rebuilt = HashMap::new();
        rebuilt.insert("mmm".to_string(), 3.0);
        rebuilt.insert("aaa".to_string(), 2.0);
        rebuilt.insert("zzz".to_string(), 1.0);
        b.filter_scores = Some(rebuilt);

        assert_eq!(a.compute_record_hash(), b.compute_record_hash());
    }

    /// The canonical form is length-prefixed precisely so field content
    /// cannot forge a boundary. Moving text across a field edge must
    /// change the hash.
    #[test]
    fn v2_canonical_form_resists_field_boundary_forgery() {
        let mut a = make_record();
        a.plugin_id = "file".into();
        a.tool_call_type = "opsFileRead".into();

        let mut b = a.clone();
        b.plugin_id = "file-ops".into();
        b.tool_call_type = "FileRead".into();

        assert_ne!(
            a.compute_record_hash(),
            b.compute_record_hash(),
            "field boundaries must not be forgeable by shifting content"
        );
    }

    /// `None` and `Some("")` are different evidence and must hash
    /// differently — "no reason recorded" is not "empty reason recorded".
    #[test]
    fn v2_distinguishes_absent_from_empty() {
        let mut absent = make_record();
        absent.decision_reason = None;
        let mut empty = absent.clone();
        empty.decision_reason = Some(String::new());

        assert_ne!(absent.compute_record_hash(), empty.compute_record_hash());
    }

    /// A truncated `filter_results` must not hash the same as the full
    /// list — the element count is part of the canonical form.
    #[test]
    fn v2_detects_dropped_filter_results() {
        let full = make_fully_populated_record();
        let mut truncated = full.clone();
        truncated.filter_results.pop();

        assert_ne!(full.compute_record_hash(), truncated.compute_record_hash());
    }

    /// v1's bytes are frozen: any drift would invalidate every archived
    /// record ever written. Pinned against a literal.
    #[test]
    fn v1_canonical_form_is_frozen() {
        let mut r = make_record();
        r.hash_version = crate::types::LEGACY_HASH_VERSION;
        r.id = Uuid::nil();
        r.session_id = Uuid::nil();
        r.timestamp = DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        r.plugin_id = "file-ops".into();
        r.tool_call_type = "FileRead".into();
        r.arguments_hash = "abc123".into();
        r.composite_score = 1.5;
        r.proxy_action = ProxyActionSummary::Allow;
        r.prev_hash = None;

        let expected = crate::types::sha256_hex(
            "00000000-0000-0000-0000-000000000000|2026-01-01T00:00:00+00:00|\
             00000000-0000-0000-0000-000000000000|file-ops|FileRead|abc123|1.5|allow|GENESIS"
                .replace(' ', "")
                .as_bytes(),
        );
        assert_eq!(r.compute_record_hash(), expected);
    }
}
