// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! SQLite-backed persistent storage for audit records with auto-rotation.

use crate::error::Result;
use crate::record_parser::row_to_record;
use crate::types::{AuditRecord, ChainVerification};
use chrono::Utc;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// SQLite-backed audit storage with auto-rotation.
pub struct AuditStorage {
    conn: Connection,
    db_path: PathBuf,
    max_size_bytes: u64,
    max_rotations: usize,
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
        Ok(())
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
        self.conn.execute(
            "INSERT INTO audit_log (
                id, timestamp, session_id, plugin_id, tool_call_type,
                arguments_summary, arguments_hash, composite_score, proxy_action,
                filter_results, filter_scores, execution_result, evaluation_time_ms, task_context,
                source, supervised_tool, supervised_pid, correlation_id,
                record_hash, prev_hash, chain_sequence,
                llm_provider, llm_model, prompt_tokens, completion_tokens, estimated_cost_usd
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)",
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
                filter_scores_json,
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
            ],
        )?;
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
            tx.execute(
                "INSERT INTO audit_log (
                    id, timestamp, session_id, plugin_id, tool_call_type,
                    arguments_summary, arguments_hash, composite_score, proxy_action,
                    filter_results, filter_scores, execution_result, evaluation_time_ms, task_context,
                    source, supervised_tool, supervised_pid, correlation_id,
                    record_hash, prev_hash, chain_sequence,
                    llm_provider, llm_model, prompt_tokens, completion_tokens, estimated_cost_usd
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)",
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
                    filter_scores_json,
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
                ],
            )?;
        }
        tx.commit()?;
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
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?1")?;
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
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2")?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
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

        Ok(repaired)
    }

    /// Verify the integrity of the audit hash chain.
    ///
    /// Walks all records ordered by `chain_sequence`, recomputes each record's
    /// hash, and verifies it matches the stored `record_hash` and that `prev_hash`
    /// links to the previous record correctly.
    pub fn verify_chain(&self) -> Result<ChainVerification> {
        let total_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
        if total_count == 0 {
            return Ok(ChainVerification::Empty);
        }

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

        let mut stmt = self.conn.prepare(
            "SELECT * FROM audit_log WHERE chain_sequence IS NOT NULL \
             ORDER BY chain_sequence ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?;

        let mut prev_record_hash: Option<String> = None;
        let mut count = 0usize;

        for (expected_sequence, row_result) in (1i64..).zip(rows) {
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

    /// Access the underlying connection (for query module).
    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
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
}
