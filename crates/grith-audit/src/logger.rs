// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Async, channel-backed audit logger with batched writes.

use crate::error::Result;
use crate::storage::AuditStorage;
use crate::types::AuditRecord;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing;

/// Maximum number of write retry attempts before dropping a batch.
const MAX_WRITE_RETRIES: u32 = 3;

/// Async audit logger that writes records via a non-blocking channel.
pub struct AuditLogger {
    sender: mpsc::Sender<AuditRecord>,
    _handle: tokio::task::JoinHandle<()>,
}

impl AuditLogger {
    /// Create a new audit logger that writes to the given database path.
    pub fn new(db_path: impl Into<PathBuf>) -> Result<Self> {
        let db_path = db_path.into();
        let (sender, receiver) = mpsc::channel(1024);

        let handle = tokio::spawn(async move {
            Self::writer_loop(db_path, receiver).await;
        });

        Ok(Self {
            sender,
            _handle: handle,
        })
    }

    /// Create an audit logger backed by an in-memory database (for testing).
    pub fn new_in_memory() -> Result<Self> {
        let (sender, receiver) = mpsc::channel(1024);
        let handle = tokio::spawn(async move {
            Self::writer_loop_in_memory(receiver).await;
        });
        Ok(Self {
            sender,
            _handle: handle,
        })
    }

    /// Log an audit record (non-blocking).
    pub async fn log(&self, record: AuditRecord) -> Result<()> {
        self.sender
            .send(record)
            .await
            .map_err(|_| crate::error::Error::ChannelClosed)
    }

    /// Try to log without waiting (returns error if channel is full or closed).
    ///
    /// M-7: Distinguishes between backpressure (channel full) and failure
    /// (channel closed) by returning different error variants.
    pub fn try_log(&self, record: AuditRecord) -> Result<()> {
        self.sender.try_send(record).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => crate::error::Error::ChannelFull,
            mpsc::error::TrySendError::Closed(_) => crate::error::Error::ChannelClosed,
        })
    }

    /// Flush by waiting for the channel to drain.
    /// Call this during graceful shutdown.
    pub async fn flush(self) {
        drop(self.sender);
        let _ = self._handle.await;
    }

    async fn writer_loop(db_path: PathBuf, mut receiver: mpsc::Receiver<AuditRecord>) {
        let mut storage = match AuditStorage::open(&db_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to open audit database");
                return;
            }
        };

        let mut batch = Vec::with_capacity(64);
        let mut batch_count = 0u64;

        loop {
            // Try to receive, batching up to 64 records
            match receiver.recv().await {
                Some(record) => {
                    batch.push(record);
                    // Drain any additional pending records
                    while batch.len() < 64 {
                        match receiver.try_recv() {
                            Ok(r) => batch.push(r),
                            Err(_) => break,
                        }
                    }
                    // H-8: Retry write up to MAX_WRITE_RETRIES times before
                    // dropping the batch, and log every failure.
                    let mut written = false;
                    for attempt in 1..=MAX_WRITE_RETRIES {
                        match storage.insert_batch(&batch) {
                            Ok(()) => {
                                written = true;
                                break;
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    attempt = attempt,
                                    max_attempts = MAX_WRITE_RETRIES,
                                    count = batch.len(),
                                    "failed to write audit batch (attempt {}/{})",
                                    attempt,
                                    MAX_WRITE_RETRIES,
                                );
                            }
                        }
                    }
                    if written {
                        if let Err(error) = storage.materialize_analytics_tail(
                            crate::analytics::DEFAULT_MATERIALIZER_BATCH,
                        ) {
                            tracing::warn!(
                                error = %error,
                                "analytics materializer tail failed; cursor will retry"
                            );
                        }
                        batch_count += batch.len() as u64;
                        if batch_count.is_multiple_of(1000) {
                            tracing::debug!(total = batch_count, "audit records written");
                        }
                    } else {
                        tracing::error!(
                            count = batch.len(),
                            "dropping audit batch after {} failed write attempts",
                            MAX_WRITE_RETRIES,
                        );
                    }
                    batch.clear();

                    // Periodic rotation check
                    if batch_count.is_multiple_of(500) {
                        if let Err(e) = storage.check_rotation() {
                            tracing::warn!(error = %e, "audit rotation check failed");
                        }
                    }
                }
                None => {
                    tracing::info!(total = batch_count, "audit logger shutting down");
                    break;
                }
            }
        }
    }

    async fn writer_loop_in_memory(mut receiver: mpsc::Receiver<AuditRecord>) {
        let mut storage = match AuditStorage::open_in_memory() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to open in-memory audit db");
                return;
            }
        };

        while let Some(record) = receiver.recv().await {
            // H-8: Retry write up to MAX_WRITE_RETRIES times for in-memory too.
            for attempt in 1..=MAX_WRITE_RETRIES {
                match storage.insert_record(&record) {
                    Ok(()) => {
                        if let Err(error) = storage.materialize_analytics_tail(
                            crate::analytics::DEFAULT_MATERIALIZER_BATCH,
                        ) {
                            tracing::warn!(error = %error, "analytics materializer tail failed");
                        }
                        break;
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            attempt = attempt,
                            max_attempts = MAX_WRITE_RETRIES,
                            "failed to write audit record (attempt {}/{})",
                            attempt,
                            MAX_WRITE_RETRIES,
                        );
                        if attempt == MAX_WRITE_RETRIES {
                            tracing::error!(
                                "dropping audit record after {} failed write attempts",
                                MAX_WRITE_RETRIES
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuditRecord, ProxyActionSummary};
    use uuid::Uuid;

    fn make_record() -> AuditRecord {
        AuditRecord::new(
            Uuid::new_v4(),
            "test-plugin".into(),
            "FileRead".into(),
            &serde_json::json!({"path": "/tmp/test"}),
            1.0,
            ProxyActionSummary::Allow,
            vec![],
            0.5,
            None,
        )
    }

    #[tokio::test]
    async fn test_logger_creation() {
        let logger = AuditLogger::new_in_memory().unwrap();
        logger.log(make_record()).await.unwrap();
        logger.flush().await;
    }

    #[tokio::test]
    async fn test_logger_multiple_records() {
        let logger = AuditLogger::new_in_memory().unwrap();
        for _ in 0..100 {
            logger.log(make_record()).await.unwrap();
        }
        logger.flush().await;
    }

    #[tokio::test]
    async fn test_logger_try_log() {
        let logger = AuditLogger::new_in_memory().unwrap();
        logger.try_log(make_record()).unwrap();
        logger.flush().await;
    }

    #[tokio::test]
    async fn test_logger_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let logger = AuditLogger::new(&db_path).unwrap();

        for _ in 0..10 {
            logger.log(make_record()).await.unwrap();
        }
        logger.flush().await;

        // Verify records were written
        let storage = AuditStorage::open(&db_path).unwrap();
        assert_eq!(storage.count().unwrap(), 10);
    }
}
