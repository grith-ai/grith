// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Session state synchronisation for supervisor sessions.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::supervisor::{SupervisorRegistry, SupervisorSession};

/// Propagates live session state updates to an external owner.
#[async_trait]
pub trait SessionSync: Send + Sync {
    async fn sync(&self, session: &SupervisorSession) -> std::result::Result<(), String>;
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
    async fn sync(&self, session: &SupervisorSession) -> std::result::Result<(), String> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "supervisor registry lock poisoned".to_string())?;
        if let Some(existing) = registry.get_mut(&session.id) {
            existing.stats = session.stats.clone();
            existing.process_tree = session.process_tree.clone();
            existing.profile_name = session.profile_name.clone();
            existing.policy_scope = session.policy_scope.clone();
            existing.launcher_overlay_name = session.launcher_overlay_name.clone();
            existing.provider_overlay_name = session.provider_overlay_name.clone();
            existing.project_name = session.project_name.clone();
        }
        Ok(())
    }
}
