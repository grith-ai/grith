// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Session state synchronisation for supervisor sessions.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::supervisor::{SupervisorRegistry, SupervisorSession};

/// Why a heartbeat failed (work/74 Phase 3, go-live review B12 item 2).
///
/// The distinction is the whole point. A transport error means we could not
/// reach the daemon — it may be restarting, and the session is still
/// legitimate. An authoritative rejection means the daemon *answered* and
/// refused to account for this session: nothing is recording its decisions,
/// so it is no longer supervised in any meaningful sense.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncFailure {
    /// Could not reach or parse a response from the daemon. Retryable.
    Transport(String),
    /// The daemon answered and refused to track this session — it is at
    /// capacity and could not adopt us, or it is a different instance that
    /// never admitted us.
    AuthorityLost(String),
}

impl std::fmt::Display for SyncFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "{e}"),
            Self::AuthorityLost(e) => write!(f, "{e}"),
        }
    }
}

/// Result of a heartbeat that did not fail (go-live review B12 item 2, #79).
///
/// The distinction closes an authority-flap: a rate-limited heartbeat used to
/// return the same `Ok(())` as one the daemon actually acknowledged, so the
/// supervisor read a *skipped* beat as "the daemon is tracking us again" —
/// clearing the authority-loss state and resetting its grace clock on every
/// throttle. A `Throttled` beat carries no authority information and must
/// leave the loss state untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The daemon answered and is accounting for this session. Only this
    /// clears an authority-loss episode.
    Confirmed,
    /// The heartbeat was skipped to honour the minimum interval; nothing was
    /// sent, so it says nothing about whether the daemon still tracks us.
    Throttled,
}

/// Propagates live session state updates to an external owner.
#[async_trait]
pub trait SessionSync: Send + Sync {
    async fn sync(
        &self,
        session: &SupervisorSession,
    ) -> std::result::Result<SyncOutcome, SyncFailure>;
}

/// Sync implementation backed by the local daemon registry.
pub struct RegistrySessionSync {
    registry: Arc<Mutex<SupervisorRegistry>>,
}

impl RegistrySessionSync {
    pub fn new(registry: Arc<Mutex<SupervisorRegistry>>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl SessionSync for RegistrySessionSync {
    async fn sync(
        &self,
        session: &SupervisorSession,
    ) -> std::result::Result<SyncOutcome, SyncFailure> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| SyncFailure::Transport("supervisor registry lock poisoned".to_string()))?;
        if let Some(existing) = registry.get_mut(&session.id) {
            // Bump idle age only when the proxy evaluated a real (non-noise)
            // call since the last sync; noise-only traffic must not reset idle.
            if session.stats.proxy_evals() > existing.stats.proxy_evals() {
                existing.last_activity_at = std::time::Instant::now();
            }
            existing.stats = session.stats.clone();
            existing.process_tree = session.process_tree.clone();
            existing.profile_name = session.profile_name.clone();
            existing.policy_scope = session.policy_scope.clone();
            existing.launcher_overlay_name = session.launcher_overlay_name.clone();
            existing.provider_overlay_name = session.provider_overlay_name.clone();
            existing.project_name = session.project_name.clone();
        }
        // The local registry always answers authoritatively — there is no
        // throttling on the in-process path.
        Ok(SyncOutcome::Confirmed)
    }
}
