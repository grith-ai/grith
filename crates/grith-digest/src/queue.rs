// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! SQLite-backed queue for digest items with status tracking and pagination.
//!
//! Uses an internal connection pool with WAL mode so that read operations
//! (query, get_by_id, count) can execute concurrently without blocking writes.
//! Callers can share a `DigestQueue` via `Arc<DigestQueue>` — no external
//! `Mutex` is required.

use crate::error::Result;
use crate::types::{DigestItem, DigestStatus, FilterBreakdown, ScoreSeverity};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OpenFlags};
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

/// Maximum number of idle connections kept in the pool.
const MAX_POOL_SIZE: usize = 4;

/// Apply recommended PRAGMAs for WAL mode, reliability, and concurrency.
///
/// `shared_cache` should be true for in-memory URIs opened with `cache=shared`.
/// In shared-cache mode, `read_uncommitted = ON` prevents reader connections
/// from taking table-level read locks that would conflict with writers.
fn apply_pragmas(conn: &Connection, shared_cache: bool) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;",
    )?;
    if shared_cache {
        conn.execute_batch("PRAGMA read_uncommitted=ON;")?;
    }
    Ok(())
}

/// SQLite-backed digest queue for quarantined tool calls.
///
/// Thread-safe: uses an internal connection pool with WAL mode. Read operations
/// can execute concurrently; writes are serialized by SQLite's WAL writer lock.
/// Share via `Arc<DigestQueue>` without an external `Mutex`.
pub struct DigestQueue {
    /// Database URI (file path or shared-cache in-memory URI).
    db_uri: String,
    /// Flags used when opening new connections.
    open_flags: OpenFlags,
    /// Whether this is a shared-cache in-memory database (affects PRAGMAs).
    shared_cache: bool,
    /// Pool of reusable connections. The mutex is held only for the instant
    /// it takes to push/pop a `Connection` from the `Vec` — actual database
    /// I/O happens outside the lock.
    pool: Mutex<Vec<Connection>>,
}

/// RAII guard that borrows a connection from the pool and returns it on drop.
struct PoolGuard<'a> {
    queue: &'a DigestQueue,
    conn: Option<Connection>,
}

impl std::ops::Deref for PoolGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("connection taken before drop")
    }
}

impl Drop for PoolGuard<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            if let Ok(mut pool) = self.queue.pool.lock() {
                if pool.len() < MAX_POOL_SIZE {
                    pool.push(conn);
                }
                // else: drop the connection (pool is full)
            }
        }
    }
}

impl DigestQueue {
    /// Open or create the digest queue database at the given path.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let db_path = path.into();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db_uri = db_path.to_string_lossy().to_string();
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;

        let conn = Connection::open_with_flags(&db_uri, flags)?;
        apply_pragmas(&conn, false)?;
        init_schema(&conn)?;

        Ok(Self {
            db_uri,
            open_flags: flags,
            shared_cache: false,
            pool: Mutex::new(vec![conn]),
        })
    }

    /// Open an in-memory queue (for testing).
    ///
    /// Uses a shared-cache in-memory URI so that multiple pooled connections
    /// see the same database.
    pub fn open_in_memory() -> Result<Self> {
        let unique = Uuid::new_v4().as_simple().to_string();
        let db_uri = format!("file:grith_digest_{unique}?mode=memory&cache=shared");
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_URI;

        let conn = Connection::open_with_flags(&db_uri, flags)?;
        apply_pragmas(&conn, true)?;
        init_schema(&conn)?;

        Ok(Self {
            db_uri,
            open_flags: flags,
            shared_cache: true,
            pool: Mutex::new(vec![conn]),
        })
    }

    /// Borrow a connection from the pool, or create a new one if the pool is empty.
    fn conn(&self) -> Result<PoolGuard<'_>> {
        let cached = {
            let mut pool = self.pool.lock().expect("digest pool lock poisoned");
            pool.pop()
        };
        let conn = match cached {
            Some(c) => c,
            None => {
                let c = Connection::open_with_flags(&self.db_uri, self.open_flags)?;
                apply_pragmas(&c, self.shared_cache)?;
                c
            }
        };
        Ok(PoolGuard {
            queue: self,
            conn: Some(conn),
        })
    }

    /// Add a queued proxy decision to the digest.
    pub fn enqueue(&self, item: &DigestItem) -> Result<()> {
        let conn = self.conn()?;
        let breakdown_json = serde_json::to_string(&item.filter_breakdown)?;
        conn.execute(
            "INSERT INTO digest_queue (
                id, created_at, session_id, tool_call_type, arguments_summary,
                decision_reason, composite_score, filter_breakdown, task_context, plugin_id,
                status, informational_only
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                item.id.to_string(),
                item.created_at.to_rfc3339(),
                item.session_id.map(|id| id.to_string()),
                item.tool_call_type,
                item.arguments_summary,
                item.decision_reason,
                item.composite_score,
                breakdown_json,
                item.task_context,
                item.plugin_id,
                item.status.to_string(),
                item.informational_only as i32,
            ],
        )?;
        Ok(())
    }

    /// Fetch pending items ordered by score descending (highest priority first).
    pub fn get_pending(&self, limit: usize, offset: usize) -> Result<Vec<DigestItem>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM digest_queue WHERE status = 'pending'
             ORDER BY composite_score DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            Ok(row_to_item(row))
        })?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row?.map_err(crate::error::Error::Serialization)?);
        }
        Ok(items)
    }

    /// Get a single item by ID.
    pub fn get_by_id(&self, id: &Uuid) -> Result<DigestItem> {
        let conn = self.conn()?;
        let row = conn.query_row(
            "SELECT * FROM digest_queue WHERE id = ?1",
            params![id.to_string()],
            |row| Ok(row_to_item(row)),
        );
        match row {
            Ok(parsed) => parsed.map_err(crate::error::Error::Serialization),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(crate::error::Error::NotFound(id.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Count pending items.
    pub fn count_pending(&self) -> Result<usize> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM digest_queue WHERE status = 'pending'",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Count all items.
    pub fn count_all(&self) -> Result<usize> {
        let conn = self.conn()?;
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM digest_queue", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Update item status and review action.
    pub fn update_status(
        &self,
        id: &Uuid,
        status: DigestStatus,
        action: Option<&str>,
        notes: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn()?;
        let now = Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE digest_queue SET status = ?2, reviewed_at = ?3, review_action = ?4, reviewer_notes = ?5
             WHERE id = ?1",
            params![
                id.to_string(),
                status.to_string(),
                now,
                action,
                notes,
            ],
        )?;
        if rows == 0 {
            return Err(crate::error::Error::NotFound(id.to_string()));
        }
        Ok(())
    }

    /// Expire items older than the given timestamp.
    pub fn expire_before(&self, cutoff: DateTime<Utc>) -> Result<usize> {
        let conn = self.conn()?;
        let rows = conn.execute(
            "UPDATE digest_queue SET status = 'expired'
             WHERE status = 'pending' AND created_at < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        Ok(rows)
    }

    /// Clear all actionable items — an operator "dismiss all" that removes
    /// every pending and escalated item from the queue without approving
    /// (executing) or denying them. Marks them `expired` but stamps
    /// `reviewed_at` + `review_action = 'clear'`, so the audit trail
    /// distinguishes an operator clear from a TTL expiry (which leaves
    /// `reviewed_at` / `review_action` NULL). Returns the number cleared.
    pub fn bulk_clear_pending(&self) -> Result<usize> {
        let conn = self.conn()?;
        let now = Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE digest_queue SET status = 'expired', reviewed_at = ?1, review_action = 'clear'
             WHERE status IN ('pending', 'escalated')",
            params![now],
        )?;
        Ok(rows)
    }

    /// Set an item's status to escalated with metadata.
    pub fn update_escalation(&self, id: &Uuid, escalated_by: Option<&str>) -> Result<()> {
        let conn = self.conn()?;
        let now = Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE digest_queue SET status = 'escalated', escalated_at = ?2, escalated_by = ?3
             WHERE id = ?1",
            params![id.to_string(), now, escalated_by],
        )?;
        if rows == 0 {
            return Err(crate::error::Error::NotFound(id.to_string()));
        }
        Ok(())
    }

    /// Fetch items that need action (pending or escalated), ordered by score descending.
    pub fn get_actionable(&self, limit: usize, offset: usize) -> Result<Vec<DigestItem>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM digest_queue WHERE status IN ('pending', 'escalated')
             ORDER BY composite_score DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            Ok(row_to_item(row))
        })?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row?.map_err(crate::error::Error::Serialization)?);
        }
        Ok(items)
    }

    /// Count escalated items.
    pub fn count_escalated(&self) -> Result<usize> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM digest_queue WHERE status = 'escalated'",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Count all actionable items (pending + escalated).
    pub fn count_actionable(&self) -> Result<usize> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM digest_queue WHERE status IN ('pending', 'escalated')",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }
}

/// Initialize the digest queue schema on a connection.
fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS digest_queue (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            session_id TEXT,
            tool_call_type TEXT NOT NULL,
            arguments_summary TEXT NOT NULL,
            decision_reason TEXT,
            composite_score REAL NOT NULL,
            filter_breakdown TEXT NOT NULL,
            task_context TEXT,
            plugin_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            reviewed_at TEXT,
            review_action TEXT,
            reviewer_notes TEXT,
            informational_only INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_digest_status ON digest_queue(status);
        CREATE INDEX IF NOT EXISTS idx_digest_created ON digest_queue(created_at);
        CREATE INDEX IF NOT EXISTS idx_digest_score ON digest_queue(composite_score);",
    )?;

    // Migration: add escalation columns if not present (backward-compatible).
    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(digest_queue)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .collect();
    if !columns.contains(&"escalated_at".to_string()) {
        conn.execute_batch(
            "ALTER TABLE digest_queue ADD COLUMN escalated_at TEXT;
             ALTER TABLE digest_queue ADD COLUMN escalated_by TEXT;",
        )?;
    }
    if !columns.contains(&"session_id".to_string()) {
        conn.execute_batch("ALTER TABLE digest_queue ADD COLUMN session_id TEXT;")?;
    }
    if !columns.contains(&"decision_reason".to_string()) {
        conn.execute_batch("ALTER TABLE digest_queue ADD COLUMN decision_reason TEXT;")?;
    }

    Ok(())
}

/// Errors that can occur when converting a database row to a DigestItem.
#[derive(Debug)]
enum RowConvertError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for RowConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite column error: {e}"),
            Self::Json(e) => write!(f, "json deserialization error: {e}"),
        }
    }
}

impl From<rusqlite::Error> for RowConvertError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<serde_json::Error> for RowConvertError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

fn row_to_item(row: &rusqlite::Row) -> std::result::Result<DigestItem, serde_json::Error> {
    match row_to_item_inner(row) {
        Ok(item) => Ok(item),
        Err(RowConvertError::Json(e)) => Err(e),
        Err(RowConvertError::Sqlite(e)) => {
            // Surface SQLite column errors as a serialization error so callers
            // that already handle serde_json::Error receive a meaningful message.
            Err(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("database schema mismatch: {e}"),
            )))
        }
    }
}

fn row_to_item_inner(row: &rusqlite::Row) -> std::result::Result<DigestItem, RowConvertError> {
    let id_str: String = row.get("id")?;
    let created_str: String = row.get("created_at")?;
    let session_str: Option<String> = row.get("session_id")?;
    let breakdown_json: String = row.get("filter_breakdown")?;
    let status_str: String = row.get("status")?;
    let reviewed_str: Option<String> = row.get("reviewed_at")?;
    let info_only: i32 = row.get("informational_only")?;

    let filter_breakdown: Vec<FilterBreakdown> = serde_json::from_str(&breakdown_json)?;
    let composite_score: f64 = row.get("composite_score")?;

    let id = match Uuid::parse_str(&id_str) {
        Ok(uuid) => uuid,
        Err(e) => {
            tracing::warn!(
                raw_id = %id_str,
                error = %e,
                "corrupt UUID in digest queue row, falling back to nil UUID"
            );
            Uuid::default()
        }
    };

    let created_at = match DateTime::parse_from_rfc3339(&created_str) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(e) => {
            tracing::warn!(
                raw_timestamp = %created_str,
                error = %e,
                "corrupt created_at timestamp in digest queue row, falling back to Utc::now()"
            );
            Utc::now()
        }
    };

    Ok(DigestItem {
        id,
        created_at,
        session_id: session_str.and_then(|s| Uuid::parse_str(&s).ok()),
        tool_call_type: row.get("tool_call_type")?,
        arguments_summary: row.get("arguments_summary")?,
        decision_reason: row.get("decision_reason")?,
        composite_score,
        severity: ScoreSeverity::from_score(composite_score),
        filter_breakdown,
        task_context: row.get("task_context")?,
        plugin_id: row.get("plugin_id")?,
        status: DigestStatus::from_str_lossy(&status_str),
        reviewed_at: reviewed_str.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        }),
        review_action: row.get("review_action")?,
        reviewer_notes: row.get("reviewer_notes")?,
        informational_only: info_only != 0,
        escalated_at: {
            let s: Option<String> = row.get("escalated_at")?;
            s.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .ok()
            })
        },
        escalated_by: row.get("escalated_by")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_item(score: f64, informational: bool) -> DigestItem {
        DigestItem {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            session_id: None,
            tool_call_type: "ShellExec".into(),
            arguments_summary: "ls -la".into(),
            decision_reason: Some("test decision".into()),
            composite_score: score,
            severity: ScoreSeverity::from_score(score),
            filter_breakdown: vec![FilterBreakdown {
                filter_name: "command".into(),
                score,
                rule_id: "test-rule".into(),
                message: "test match".into(),
            }],
            task_context: Some("testing".into()),
            plugin_id: "shell".into(),
            status: DigestStatus::Pending,
            reviewed_at: None,
            review_action: None,
            reviewer_notes: None,
            informational_only: informational,
            escalated_at: None,
            escalated_by: None,
        }
    }

    #[test]
    fn test_enqueue_and_retrieve() {
        let queue = DigestQueue::open_in_memory().unwrap();
        let item = make_item(5.0, false);
        let id = item.id;
        queue.enqueue(&item).unwrap();

        let retrieved = queue.get_by_id(&id).unwrap();
        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.composite_score, 5.0);
        assert_eq!(retrieved.decision_reason.as_deref(), Some("test decision"));
        assert_eq!(retrieved.status, DigestStatus::Pending);
    }

    #[test]
    fn test_count_pending() {
        let queue = DigestQueue::open_in_memory().unwrap();
        queue.enqueue(&make_item(3.5, false)).unwrap();
        queue.enqueue(&make_item(6.0, false)).unwrap();
        queue.enqueue(&make_item(9.5, true)).unwrap();
        assert_eq!(queue.count_pending().unwrap(), 3);
    }

    #[test]
    fn test_get_pending_ordered() {
        let queue = DigestQueue::open_in_memory().unwrap();
        queue.enqueue(&make_item(3.5, false)).unwrap();
        queue.enqueue(&make_item(7.0, false)).unwrap();
        queue.enqueue(&make_item(5.0, false)).unwrap();

        let items = queue.get_pending(10, 0).unwrap();
        assert_eq!(items.len(), 3);
        assert!(items[0].composite_score >= items[1].composite_score);
        assert!(items[1].composite_score >= items[2].composite_score);
    }

    #[test]
    fn test_get_pending_pagination() {
        let queue = DigestQueue::open_in_memory().unwrap();
        for i in 0..5 {
            queue.enqueue(&make_item(3.0 + i as f64, false)).unwrap();
        }
        let page1 = queue.get_pending(2, 0).unwrap();
        assert_eq!(page1.len(), 2);
        let page2 = queue.get_pending(2, 2).unwrap();
        assert_eq!(page2.len(), 2);
    }

    #[test]
    fn test_expire_old() {
        let queue = DigestQueue::open_in_memory().unwrap();
        queue.enqueue(&make_item(5.0, false)).unwrap();
        queue.enqueue(&make_item(6.0, false)).unwrap();

        // Expire everything before far future
        let future = Utc::now() + chrono::Duration::hours(1);
        let expired = queue.expire_before(future).unwrap();
        assert_eq!(expired, 2);
        assert_eq!(queue.count_pending().unwrap(), 0);
    }

    #[test]
    fn test_informational_only() {
        let queue = DigestQueue::open_in_memory().unwrap();
        let item = make_item(9.5, true);
        queue.enqueue(&item).unwrap();

        let retrieved = queue.get_by_id(&item.id).unwrap();
        assert!(retrieved.informational_only);
        assert!(!retrieved.is_actionable());
    }

    #[test]
    fn test_update_escalation() {
        let queue = DigestQueue::open_in_memory().unwrap();
        let item = make_item(5.0, false);
        let id = item.id;
        queue.enqueue(&item).unwrap();

        queue.update_escalation(&id, Some("dashboard")).unwrap();
        let retrieved = queue.get_by_id(&id).unwrap();
        assert_eq!(retrieved.status, DigestStatus::Escalated);
        assert!(retrieved.escalated_at.is_some());
        assert_eq!(retrieved.escalated_by.as_deref(), Some("dashboard"));
    }

    #[test]
    fn test_get_actionable() {
        let queue = DigestQueue::open_in_memory().unwrap();
        let item1 = make_item(5.0, false);
        let item2 = make_item(6.0, false);
        let id2 = item2.id;
        queue.enqueue(&item1).unwrap();
        queue.enqueue(&item2).unwrap();

        // Escalate item2
        queue.update_escalation(&id2, None).unwrap();

        // get_actionable returns both pending and escalated
        let actionable = queue.get_actionable(10, 0).unwrap();
        assert_eq!(actionable.len(), 2);

        // get_pending returns only the pending one
        let pending = queue.get_pending(10, 0).unwrap();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_count_escalated() {
        let queue = DigestQueue::open_in_memory().unwrap();
        let item = make_item(5.0, false);
        let id = item.id;
        queue.enqueue(&item).unwrap();
        queue.enqueue(&make_item(6.0, false)).unwrap();

        assert_eq!(queue.count_escalated().unwrap(), 0);
        queue.update_escalation(&id, None).unwrap();
        assert_eq!(queue.count_escalated().unwrap(), 1);
        assert_eq!(queue.count_actionable().unwrap(), 2);
    }

    #[test]
    fn test_bulk_clear_pending_clears_pending_and_escalated() {
        let queue = DigestQueue::open_in_memory().unwrap();
        let pending1 = make_item(4.0, false);
        let pending2 = make_item(5.0, false);
        let escalated = make_item(6.0, false);
        let esc_id = escalated.id;
        queue.enqueue(&pending1).unwrap();
        queue.enqueue(&pending2).unwrap();
        queue.enqueue(&escalated).unwrap();
        queue.update_escalation(&esc_id, None).unwrap();

        // 2 pending + 1 escalated = 3 actionable before clearing.
        assert_eq!(queue.count_actionable().unwrap(), 3);

        // Clear all removes both pending and escalated items.
        let cleared = queue.bulk_clear_pending().unwrap();
        assert_eq!(cleared, 3);
        assert_eq!(queue.count_actionable().unwrap(), 0);
        assert!(queue.get_actionable(10, 0).unwrap().is_empty());
    }

    #[test]
    fn test_concurrent_readers_dont_block_writer() {
        use std::sync::Arc;

        let queue = Arc::new(DigestQueue::open_in_memory().unwrap());

        // Seed some data
        for i in 0..20 {
            queue.enqueue(&make_item(3.0 + i as f64, false)).unwrap();
        }

        let mut handles = vec![];

        // Spawn reader threads
        for _ in 0..4 {
            let q = Arc::clone(&queue);
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let _items = q.get_pending(10, 0).unwrap();
                    let _count = q.count_pending().unwrap();
                    let _all = q.count_all().unwrap();
                }
            }));
        }

        // Spawn writer thread concurrently with readers
        {
            let q = Arc::clone(&queue);
            handles.push(std::thread::spawn(move || {
                for i in 0..50 {
                    q.enqueue(&make_item(10.0 + i as f64, false)).unwrap();
                }
            }));
        }

        // All threads must complete without deadlock or error
        for h in handles {
            h.join().expect("thread panicked");
        }

        // Verify data integrity
        let total = queue.count_all().unwrap();
        assert_eq!(total, 70); // 20 initial + 50 from writer
    }

    #[test]
    fn test_throughput_benchmark_baseline_vs_concurrent_load() {
        use std::sync::Arc;
        use std::time::Instant;

        const SEED_ITEMS: usize = 100;
        const WRITE_OPS: usize = 600;
        const READ_THREADS: usize = 4;
        const READ_LOOPS_PER_THREAD: usize = 400;

        let baseline_queue = DigestQueue::open_in_memory().unwrap();
        for i in 0..SEED_ITEMS {
            baseline_queue
                .enqueue(&make_item(3.0 + i as f64, false))
                .unwrap();
        }

        let baseline_start = Instant::now();
        for i in 0..WRITE_OPS {
            baseline_queue
                .enqueue(&make_item(10.0 + i as f64, false))
                .unwrap();
            let _ = baseline_queue.get_pending(20, 0).unwrap();
            let _ = baseline_queue.count_pending().unwrap();
        }
        let baseline_elapsed = baseline_start.elapsed();
        let baseline_total_ops = WRITE_OPS * 3;
        let baseline_ops_per_sec =
            baseline_total_ops as f64 / baseline_elapsed.as_secs_f64().max(0.001);

        let concurrent_queue = Arc::new(DigestQueue::open_in_memory().unwrap());
        for i in 0..SEED_ITEMS {
            concurrent_queue
                .enqueue(&make_item(3.0 + i as f64, false))
                .unwrap();
        }

        let concurrent_start = Instant::now();
        let writer_queue = Arc::clone(&concurrent_queue);
        let writer = std::thread::spawn(move || {
            for i in 0..WRITE_OPS {
                writer_queue
                    .enqueue(&make_item(20.0 + i as f64, false))
                    .unwrap();
            }
        });

        let mut readers = Vec::new();
        for _ in 0..READ_THREADS {
            let reader_queue = Arc::clone(&concurrent_queue);
            readers.push(std::thread::spawn(move || {
                for _ in 0..READ_LOOPS_PER_THREAD {
                    let _ = reader_queue.get_pending(20, 0).unwrap();
                    let _ = reader_queue.count_pending().unwrap();
                }
            }));
        }

        writer.join().expect("writer thread panicked");
        for reader in readers {
            reader.join().expect("reader thread panicked");
        }
        let concurrent_elapsed = concurrent_start.elapsed();
        let concurrent_total_ops = WRITE_OPS + (READ_THREADS * READ_LOOPS_PER_THREAD * 2);
        let concurrent_ops_per_sec =
            concurrent_total_ops as f64 / concurrent_elapsed.as_secs_f64().max(0.001);

        eprintln!(
            "digest throughput benchmark: baseline={} ops/s ({} ops in {:?}), concurrent={} ops/s ({} ops in {:?})",
            baseline_ops_per_sec as u64,
            baseline_total_ops,
            baseline_elapsed,
            concurrent_ops_per_sec as u64,
            concurrent_total_ops,
            concurrent_elapsed
        );

        assert!(baseline_ops_per_sec > 0.0);
        assert!(concurrent_ops_per_sec > 0.0);
        assert_eq!(
            concurrent_queue.count_all().unwrap(),
            SEED_ITEMS + WRITE_OPS
        );
    }

    #[test]
    fn test_pool_connections_are_reused() {
        let queue = DigestQueue::open_in_memory().unwrap();
        queue.enqueue(&make_item(5.0, false)).unwrap();
        queue.enqueue(&make_item(6.0, false)).unwrap();

        // Multiple sequential operations should reuse connections
        for _ in 0..10 {
            let _count = queue.count_pending().unwrap();
        }

        // Pool should have at most MAX_POOL_SIZE connections
        let pool_size = queue.pool.lock().unwrap().len();
        assert!(pool_size <= MAX_POOL_SIZE);
        assert!(pool_size >= 1); // At least one connection should be cached
    }
}
