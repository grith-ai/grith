// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Audit sink abstractions for supervisor sessions.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use grith_audit::types::AuditRecord;
use grith_audit::AuditStorage;

/// Async audit sink used by the supervisor loop.
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn log(&self, record: AuditRecord) -> std::result::Result<(), String>;
}

/// Audit sink backed by the daemon-owned shared `AuditStorage`.
pub struct StorageAuditSink {
    storage: Arc<Mutex<AuditStorage>>,
}

impl StorageAuditSink {
    pub fn new(storage: Arc<Mutex<AuditStorage>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl AuditSink for StorageAuditSink {
    async fn log(&self, record: AuditRecord) -> std::result::Result<(), String> {
        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || {
            let guard = storage
                .lock()
                .map_err(|_| "audit storage lock poisoned".to_string())?;
            guard.insert_record(&record).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    }
}
