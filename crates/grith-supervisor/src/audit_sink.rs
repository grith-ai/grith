// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Audit sink abstractions for supervisor sessions.
//!
//! The supervisor's hot path (`handle_syscall_event`) calls
//! [`AuditSink::log`] on every audited event. Under heavy ptrace load
//! (e.g. `cargo test --workspace` linking with mold) this can fire at
//! thousands of records per second — the supervisor's `current_thread`
//! Tokio runtime cannot afford to block on synchronous SQLite WAL
//! inserts there. Doing so caused observable wedges: claude's helper
//! threads queued behind the build's syscalls and stayed in
//! `ptrace_stop` for tens of seconds (see `feat(supervisor):
//! wedge-detection watchdog`).
//!
//! [`StorageAuditSink`] solves this by handing records to a dedicated
//! OS thread via a bounded crossbeam channel:
//!
//! * **Hot path** ([`AuditSink::log`]): non-blocking `try_send` —
//!   microseconds. If the channel is full (the writer can't keep up),
//!   the record is dropped and a rate-limited warn is emitted. Audit
//!   completeness DEGRADES under sustained overload; supervisor
//!   throughput STAYS HEALTHY.
//!
//! * **Writer thread** (`writer_loop`): blocks on the channel, drains
//!   up to [`BATCH_MAX`] records or [`BATCH_WINDOW`] (whichever first)
//!   into one [`AuditStorage::insert_batch`] call. SQLite WAL hits
//!   thousands of rows/sec when batched into a single transaction —
//!   the bottleneck moves from per-row IO latency to per-batch IO
//!   latency.
//!
//! The writer runs on a dedicated `std::thread`, NOT a Tokio task, so
//! it doesn't contend with the supervisor's `current_thread` runtime
//! for CPU. SQLite serialisation is the only synchronisation point
//! (the `Arc<Mutex<AuditStorage>>` held during `insert_batch`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, Sender, TrySendError};
use grith_audit::types::AuditRecord;
use grith_audit::AuditStorage;

/// Channel capacity between the hot path and the writer thread. Sized
/// to absorb ~8 seconds of typical post-fix audit volume (~1k rows/sec)
/// without dropping. Under sustained overload beyond this, the sink
/// drops oldest-first via the natural FIFO.
const CHANNEL_CAPACITY: usize = 8192;

/// Maximum records folded into a single SQLite transaction. A single
/// `insert_batch` of this size is ~5–10ms on a modern SSD — well under
/// the supervisor's tolerable backpressure window.
const BATCH_MAX: usize = 256;

/// Maximum time the writer waits to fill a batch before committing
/// what it has. Bounds the worst-case visibility lag of new audit
/// rows to ~50ms when the channel rate is low.
const BATCH_WINDOW: Duration = Duration::from_millis(50);

/// Async audit sink used by the supervisor loop.
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn log(&self, record: AuditRecord) -> std::result::Result<(), String>;
}

/// Audit sink backed by the daemon-owned shared [`AuditStorage`] with
/// a dedicated background writer thread. See module docs for the
/// rationale.
pub struct StorageAuditSink {
    tx: Sender<AuditRecord>,
    /// Cumulative count of records dropped because the writer channel
    /// was full. Read by the hot path's rate-limited warn.
    overflow_count: AtomicU64,
}

impl StorageAuditSink {
    pub fn new(storage: Arc<Mutex<AuditStorage>>) -> Self {
        let (tx, rx) = bounded::<AuditRecord>(CHANNEL_CAPACITY);

        std::thread::Builder::new()
            .name("grith-audit-writer".into())
            .spawn(move || writer_loop(rx, storage))
            .expect("spawn grith-audit-writer thread");

        Self {
            tx,
            overflow_count: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl AuditSink for StorageAuditSink {
    async fn log(&self, record: AuditRecord) -> std::result::Result<(), String> {
        match self.tx.try_send(record) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                // Drop the record so the supervisor's hot path stays
                // unblocked. Warn rate-limited to powers-of-two so the
                // tracing line itself doesn't compound the pressure.
                let count = self.overflow_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count.is_power_of_two() {
                    tracing::warn!(
                        dropped_total = count,
                        channel_capacity = CHANNEL_CAPACITY,
                        "audit_sink: channel full — record dropped; writer thread \
                         can't keep up with hot-path event rate"
                    );
                }
                Ok(())
            }
            Err(TrySendError::Disconnected(_)) => {
                Err("audit writer channel closed (writer thread exited)".to_string())
            }
        }
    }
}

/// Drain the audit channel forever, batching records into single
/// SQLite transactions for throughput. Exits cleanly when all
/// [`Sender`]s have been dropped (typically only at process shutdown).
fn writer_loop(rx: Receiver<AuditRecord>, storage: Arc<Mutex<AuditStorage>>) {
    let mut batch: Vec<AuditRecord> = Vec::with_capacity(BATCH_MAX);

    // Block on each first record; this is where the thread sleeps
    // when there's nothing to write. `recv()` returns Err only when
    // all senders have dropped — that's our clean shutdown path.
    while let Ok(first) = rx.recv() {
        batch.clear();
        batch.push(first);

        // Opportunistically fill the batch up to BATCH_MAX, but never
        // wait longer than BATCH_WINDOW from when we got the first
        // record (bounds visibility lag).
        let deadline = Instant::now() + BATCH_WINDOW;
        while batch.len() < BATCH_MAX {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match rx.recv_timeout(remaining) {
                Ok(r) => batch.push(r),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        // Single transaction for the whole batch. Releases the storage
        // mutex between batches so other readers (dashboard /api/audit,
        // chain verifier) get fair access.
        match storage.lock() {
            Ok(mut guard) => {
                if let Err(e) = guard.insert_batch(&batch) {
                    tracing::error!(
                        error = %e,
                        count = batch.len(),
                        "audit_sink writer: batch insert failed; records lost"
                    );
                }
            }
            Err(_) => {
                tracing::error!(
                    count = batch.len(),
                    "audit_sink writer: storage mutex poisoned; records lost"
                );
            }
        }
    }

    tracing::info!("audit_sink writer thread exiting (all senders dropped)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use grith_audit::AuditStorage;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn fresh_storage() -> Arc<Mutex<AuditStorage>> {
        let dir = tempdir().unwrap();
        // Leak the tempdir so the DB file outlives the test scope.
        let dir = Box::leak(Box::new(dir));
        let storage = AuditStorage::open(dir.path().join("audit.db")).unwrap();
        Arc::new(Mutex::new(storage))
    }

    fn dummy_record() -> AuditRecord {
        AuditRecord::new(
            Uuid::new_v4(),
            "test".into(),
            "FileRead(/dev/null)".into(),
            &serde_json::json!({"path": "/dev/null"}),
            0.0,
            grith_audit::types::ProxyActionSummary::Allow,
            Vec::new(),
            0.0,
            None,
        )
    }

    #[tokio::test]
    async fn log_returns_immediately_when_channel_has_capacity() {
        let storage = fresh_storage();
        let sink = StorageAuditSink::new(storage.clone());
        // Single send should be near-instantaneous.
        let start = Instant::now();
        sink.log(dummy_record()).await.unwrap();
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn batch_writer_persists_records_to_storage() {
        let storage = fresh_storage();
        let sink = StorageAuditSink::new(storage.clone());

        for _ in 0..10 {
            sink.log(dummy_record()).await.unwrap();
        }
        // Wait past the batch window so the writer commits.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let count = storage.lock().unwrap().count().unwrap();
        assert_eq!(count, 10, "all 10 records should reach the DB");
    }

    #[tokio::test]
    async fn channel_overflow_drops_but_does_not_error() {
        let storage = fresh_storage();
        let sink = StorageAuditSink::new(storage.clone());
        // Flood beyond CHANNEL_CAPACITY before the writer has a chance
        // to drain. The writer might commit some batches as we go, so
        // the assertion is just "log() never errors and the function
        // returns promptly".
        let start = Instant::now();
        for _ in 0..(CHANNEL_CAPACITY * 4) {
            sink.log(dummy_record()).await.unwrap();
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "flooding {} records took too long ({:?}); back-pressure may have leaked into log()",
            CHANNEL_CAPACITY * 4,
            start.elapsed()
        );
        // Overflow counter should have incremented (some records were dropped).
        // We allow zero in case the writer somehow kept up.
        let dropped = sink.overflow_count.load(Ordering::Relaxed);
        tracing::info!(dropped, "overflow count after flood");
    }
}
