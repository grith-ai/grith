// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Source-to-sink correlation tracking for exfiltration detection.
//!
//! Links sensitive source reads to subsequent outbound operations within
//! a configurable time window, enabling audit trail reconstruction.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Tracks source→sink correlation chains per session.
///
/// When a sensitive source read occurs (e.g., reading `/etc/shadow`), a new
/// correlation chain is opened for that session. Subsequent outbound calls
/// within the correlation window are tagged with the same correlation ID,
/// linking them to the original source read in audit logs.
///
/// Chains expire after `window` seconds of inactivity.
pub struct CorrelationTracker {
    /// Map of session_id → active correlation chain.
    chains: Mutex<HashMap<Uuid, CorrelationChain>>,
    /// How long a correlation chain stays active after the last event.
    window: Duration,
}

#[derive(Debug, Clone)]
struct CorrelationChain {
    /// The correlation ID shared by all events in this chain.
    correlation_id: Uuid,
    /// Source event description (e.g., "FileRead(/etc/shadow)").
    source_event: String,
    /// When the chain was opened.
    opened_at: Instant,
    /// When the chain was last extended by a sink event.
    last_activity: Instant,
    /// Number of sink events linked to this chain.
    sink_count: u32,
}

impl CorrelationTracker {
    /// Create a new tracker with the given inactivity window.
    pub fn new(window: Duration) -> Self {
        Self {
            chains: Mutex::new(HashMap::new()),
            window,
        }
    }

    /// Create a tracker with the default 120-second inactivity window.
    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(120))
    }

    /// Open a new correlation chain for a session after a sensitive source read.
    /// Returns the correlation ID.
    pub fn open_chain(&self, session_id: Uuid, source_event: impl Into<String>) -> Uuid {
        let mut chains = self.chains.lock().expect("lock poisoned");
        let now = Instant::now();
        let correlation_id = Uuid::new_v4();
        chains.insert(
            session_id,
            CorrelationChain {
                correlation_id,
                source_event: source_event.into(),
                opened_at: now,
                last_activity: now,
                sink_count: 0,
            },
        );
        correlation_id
    }

    /// Check if a session has an active correlation chain and return its ID.
    /// Extends the chain's last_activity timestamp.
    /// Returns `None` if no active chain exists or it has expired.
    pub fn link_sink(&self, session_id: Uuid) -> Option<Uuid> {
        let mut chains = self.chains.lock().expect("lock poisoned");
        let chain = chains.get_mut(&session_id)?;
        let now = Instant::now();
        if now.duration_since(chain.last_activity) > self.window {
            chains.remove(&session_id);
            return None;
        }
        chain.last_activity = now;
        chain.sink_count += 1;
        Some(chain.correlation_id)
    }

    /// Get the current correlation ID for a session without extending it.
    ///
    /// M-6: If the chain for this session is expired, it is removed from the
    /// map instead of being left around indefinitely.
    pub fn current_correlation(&self, session_id: Uuid) -> Option<Uuid> {
        let mut chains = self.chains.lock().expect("lock poisoned");
        let chain = chains.get(&session_id)?;
        let now = Instant::now();
        if now.duration_since(chain.last_activity) > self.window {
            chains.remove(&session_id);
            return None;
        }
        Some(chain.correlation_id)
    }

    /// List all active correlation chains with their metadata.
    pub fn list_active(&self) -> Vec<CorrelationInfo> {
        let chains = self.chains.lock().expect("lock poisoned");
        let now = Instant::now();
        chains
            .iter()
            .filter(|(_, c)| now.duration_since(c.last_activity) <= self.window)
            .map(|(session_id, c)| CorrelationInfo {
                session_id: *session_id,
                correlation_id: c.correlation_id,
                source_event: c.source_event.clone(),
                age_seconds: now.duration_since(c.opened_at).as_secs(),
                sink_count: c.sink_count,
            })
            .collect()
    }

    /// Remove expired chains. Called periodically or on access.
    pub fn prune(&self) {
        let mut chains = self.chains.lock().expect("lock poisoned");
        let now = Instant::now();
        chains.retain(|_, c| now.duration_since(c.last_activity) <= self.window);
    }
}

/// Summary of an active correlation chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CorrelationInfo {
    pub session_id: Uuid,
    pub correlation_id: Uuid,
    pub source_event: String,
    pub age_seconds: u64,
    pub sink_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn open_chain_returns_correlation_id() {
        let tracker = CorrelationTracker::with_defaults();
        let session = Uuid::new_v4();
        let cid = tracker.open_chain(session, "FileRead(/etc/shadow)");
        assert_ne!(cid, Uuid::nil());
    }

    #[test]
    fn link_sink_returns_same_correlation_id() {
        let tracker = CorrelationTracker::with_defaults();
        let session = Uuid::new_v4();
        let cid = tracker.open_chain(session, "FileRead(/etc/shadow)");
        let linked = tracker.link_sink(session);
        assert_eq!(linked, Some(cid));
    }

    #[test]
    fn link_sink_increments_count() {
        let tracker = CorrelationTracker::with_defaults();
        let session = Uuid::new_v4();
        tracker.open_chain(session, "FileRead(/etc/shadow)");
        tracker.link_sink(session);
        tracker.link_sink(session);
        let active = tracker.list_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].sink_count, 2);
    }

    #[test]
    fn no_chain_returns_none() {
        let tracker = CorrelationTracker::with_defaults();
        assert!(tracker.link_sink(Uuid::new_v4()).is_none());
    }

    #[test]
    fn expired_chain_returns_none() {
        let tracker = CorrelationTracker::new(Duration::from_millis(50));
        let session = Uuid::new_v4();
        tracker.open_chain(session, "FileRead(/etc/shadow)");
        sleep(Duration::from_millis(100));
        assert!(tracker.link_sink(session).is_none());
    }

    #[test]
    fn new_chain_replaces_old() {
        let tracker = CorrelationTracker::with_defaults();
        let session = Uuid::new_v4();
        let cid1 = tracker.open_chain(session, "FileRead(/etc/shadow)");
        let cid2 = tracker.open_chain(session, "FileRead(/etc/passwd)");
        assert_ne!(cid1, cid2);
        assert_eq!(tracker.current_correlation(session), Some(cid2));
    }

    #[test]
    fn sessions_are_independent() {
        let tracker = CorrelationTracker::with_defaults();
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        let cid1 = tracker.open_chain(s1, "read1");
        let cid2 = tracker.open_chain(s2, "read2");
        assert_ne!(cid1, cid2);
        assert_eq!(tracker.link_sink(s1), Some(cid1));
        assert_eq!(tracker.link_sink(s2), Some(cid2));
    }

    #[test]
    fn list_active_filters_expired() {
        let tracker = CorrelationTracker::new(Duration::from_millis(50));
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        tracker.open_chain(s1, "read1");
        sleep(Duration::from_millis(100));
        tracker.open_chain(s2, "read2");
        let active = tracker.list_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].session_id, s2);
    }

    #[test]
    fn prune_removes_expired() {
        let tracker = CorrelationTracker::new(Duration::from_millis(50));
        let session = Uuid::new_v4();
        tracker.open_chain(session, "read");
        sleep(Duration::from_millis(100));
        tracker.prune();
        assert!(tracker.list_active().is_empty());
    }

    #[test]
    fn current_correlation_does_not_extend() {
        let tracker = CorrelationTracker::with_defaults();
        let session = Uuid::new_v4();
        let cid = tracker.open_chain(session, "read");
        assert_eq!(tracker.current_correlation(session), Some(cid));
        // It should still be the same without extending
        assert_eq!(tracker.current_correlation(session), Some(cid));
    }
}
