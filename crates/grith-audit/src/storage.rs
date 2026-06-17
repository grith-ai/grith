// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! SQLite-backed persistent storage for audit records with auto-rotation.

use crate::error::Result;
use crate::record_parser::row_to_record;
use crate::types::{AuditRecord, ChainVerification};
use chrono::Utc;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
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

/// SQLite-backed audit storage with auto-rotation.
pub struct AuditStorage {
    conn: Connection,
    db_path: PathBuf,
    max_size_bytes: u64,
    max_rotations: usize,
    /// Memoised result of the most recent chain verification.
    /// Invalidated on every write path; refilled on next `cached_verify_chain`.
    verify_cache: Mutex<Option<ChainVerification>>,
}

/// Apply recommended PRAGMAs for reliability and concurrency.
///
/// H-7: Set WAL mode, synchronous=NORMAL, and a 5-second busy timeout
/// on every connection (both file-backed and in-memory).
fn apply_pragmas(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;",
    )?;
    Ok(())
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
        let storage = Self {
            conn,
            db_path,
            max_size_bytes: 100 * 1024 * 1024, // 100 MB
            max_rotations: 5,
            verify_cache: Mutex::new(None),
        };
        storage.init_schema()?;
        Ok(storage)
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
        };
        storage.init_schema()?;
        Ok(storage)
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
        // Stage-1 incremental-verify checkpoint storage. Single-row kv;
        // we use a table rather than PRAGMA user_version so the value can
        // be a small JSON blob holding both sequence and hash atomically.
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chain_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;
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

    fn invalidate_verify_cache(&self) {
        if let Ok(mut guard) = self.verify_cache.lock() {
            *guard = None;
        }
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
    fn chain_head(&self) -> Result<(Option<String>, i64)> {
        let result = self.conn.query_row(
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

    /// Insert a single audit record with hash-chain linking.
    pub fn insert_record(&self, record: &AuditRecord) -> Result<()> {
        let (prev_hash, last_seq) = self.chain_head()?;
        let mut record = record.clone();
        record.chain_sequence = Some(last_seq + 1);
        record.prev_hash = prev_hash;
        record.record_hash = Some(record.compute_record_hash());

        let filter_results_json = serde_json::to_string(&record.filter_results)?;
        let filter_scores_json = record
            .filter_scores
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
        self.conn.execute(
            "INSERT INTO audit_log (
                id, timestamp, session_id, plugin_id, tool_call_type,
                arguments_summary, arguments_hash, composite_score, proxy_action,
                filter_results, filter_scores, execution_result, evaluation_time_ms, task_context,
                source, supervised_tool, supervised_pid, correlation_id,
                record_hash, prev_hash, chain_sequence,
                llm_provider, llm_model, prompt_tokens, completion_tokens, estimated_cost_usd,
                spawn_sha256, matched_routine_root, shadow_phase3_filters,
                original_addr, rewritten_addr, clamp_profile_entry,
                record_type, project_name
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34)",
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
            ],
        )?;
        self.invalidate_verify_cache();
        Ok(())
    }

    /// Insert multiple records in a single transaction with hash-chain linking.
    pub fn insert_batch(&mut self, records: &[AuditRecord]) -> Result<()> {
        let (mut prev_hash, mut last_seq) = self.chain_head()?;
        let tx = self.conn.transaction()?;
        for record in records {
            let mut record = record.clone();
            last_seq += 1;
            record.chain_sequence = Some(last_seq);
            record.prev_hash = prev_hash;
            record.record_hash = Some(record.compute_record_hash());
            prev_hash = record.record_hash.clone();

            let filter_results_json = serde_json::to_string(&record.filter_results)?;
            let filter_scores_json = record
                .filter_scores
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            // Stage 3: mirror the compression done in insert_record.
            let args_summary_blob = crate::compression::compress_string(&record.arguments_summary);
            let filter_results_blob = crate::compression::compress_string(&filter_results_json);
            let filter_scores_blob = filter_scores_json
                .as_deref()
                .map(crate::compression::compress_string);
            tx.execute(
                "INSERT INTO audit_log (
                    id, timestamp, session_id, plugin_id, tool_call_type,
                    arguments_summary, arguments_hash, composite_score, proxy_action,
                    filter_results, filter_scores, execution_result, evaluation_time_ms, task_context,
                    source, supervised_tool, supervised_pid, correlation_id,
                    record_hash, prev_hash, chain_sequence,
                    llm_provider, llm_model, prompt_tokens, completion_tokens, estimated_cost_usd,
                    spawn_sha256, matched_routine_root, shadow_phase3_filters,
                    original_addr, rewritten_addr, clamp_profile_entry,
                    project_name
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33)",
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
                    record.project_name,
                ],
            )?;
        }
        tx.commit()?;
        self.invalidate_verify_cache();
        Ok(())
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
        // M-9: Log metadata errors instead of silently suppressing them.
        let size = match std::fs::metadata(&self.db_path) {
            Ok(m) => m.len(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %self.db_path.display(),
                    "failed to read audit database metadata, skipping rotation check"
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

        let (mut prev_hash, mut last_seq) = self.chain_head()?;
        let mut updated = 0usize;
        for mut record in legacy {
            last_seq += 1;
            record.chain_sequence = Some(last_seq);
            record.prev_hash = prev_hash;
            record.record_hash = Some(record.compute_record_hash());
            self.conn.execute(
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
                self.conn.execute(
                    "UPDATE audit_log
                     SET chain_sequence = ?2, prev_hash = ?3, record_hash = ?4
                     WHERE id = ?1",
                    params![
                        record.id.to_string(),
                        record.chain_sequence,
                        record.prev_hash,
                        record.record_hash,
                    ],
                )?;
                repaired += 1;
            }

            prev_hash = record.record_hash.clone();
        }

        if repaired > 0 {
            // Repair may rewrite hashes anywhere in the chain, so the
            // existing checkpoint is no longer trustworthy. Reset it so
            // the next incremental verify walks the whole repaired chain
            // once before re-establishing the high-water mark.
            self.conn
                .execute("DELETE FROM chain_metadata WHERE key = 'verified_head'", [])?;
        }
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
        self.verify_chain_from(0, None, 0)
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
            row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?;

        let mut prev_record_hash: Option<String> = seed_prev_hash;
        let mut count = already_verified;

        for (expected_sequence, row_result) in (start_sequence + 1..).zip(rows) {
            let record = row_result?;
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
            None => (0, None, 0),
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
    pub fn drain_prefix_into<F>(&mut self, max_sequence: i64, mut f: F) -> Result<usize>
    where
        F: FnMut(&AuditRecord) -> Result<()>,
    {
        if max_sequence <= 0 {
            return Ok(0);
        }

        // Capture the head hash at max_sequence BEFORE deleting, so we can
        // write it to the checkpoint and the next incremental verify can
        // seed from it.
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

        // Stream rows to the caller's callback. Done outside the transaction
        // so we don't hold a long write lock while serialising to zstd.
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
        drop(stmt);

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
            last_verified_record_hash: head_hash,
        };
        let value = serde_json::to_string(&ckpt)?;
        tx.execute(
            "INSERT INTO chain_metadata (key, value) VALUES ('verified_head', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![value],
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuditRecord, FilterResultSummary, ProxyActionSummary};

    fn make_record() -> AuditRecord {
        AuditRecord::new(
            Uuid::new_v4(),
            "file-ops".into(),
            "FileRead".into(),
            &serde_json::json!({"path": "/tmp/test.txt"}),
            1.5,
            ProxyActionSummary::Allow,
            vec![FilterResultSummary {
                filter_name: "path_match".into(),
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
                    filter_name: "path_match".into(),
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
        assert_eq!(scores.get("path_match"), Some(&3.0));
        assert_eq!(scores.get("command_structure"), Some(&4.5));

        // Insert and retrieve
        storage.insert_record(&record).unwrap();
        let retrieved = storage.get_by_id(&id).unwrap();

        // Verify filter_scores round-trips through SQLite
        assert!(retrieved.filter_scores.is_some());
        let retrieved_scores = retrieved.filter_scores.as_ref().unwrap();
        assert_eq!(retrieved_scores.get("path_match"), Some(&3.0));
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
}
