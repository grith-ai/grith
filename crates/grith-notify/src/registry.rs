// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Thread-safe registry of notification channel implementations.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use grith_digest::notification::{ChannelInfo, NotificationChannel, PlanTier};

use crate::error::{Error, Result};

/// Stores registered notification channel implementations.
///
/// Thread-safe via `RwLock`, allowing channels to be registered after the
/// containing `NotificationDispatcher` has been wrapped in an `Arc`.
pub struct ChannelRegistry {
    inner: RwLock<RegistryInner>,
}

struct RegistryInner {
    channels: HashMap<String, Arc<dyn NotificationChannel>>,
    enabled: HashMap<String, bool>,
}

impl ChannelRegistry {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(RegistryInner {
                channels: HashMap::new(),
                enabled: HashMap::new(),
            }),
        }
    }

    /// Register a channel implementation. Overwrites any existing channel with
    /// the same id.
    pub fn register(&self, channel: Arc<dyn NotificationChannel>, enabled: bool) {
        let id = channel.id().to_string();
        let mut inner = self.inner.write().unwrap();
        inner.enabled.insert(id.clone(), enabled);
        inner.channels.insert(id, channel);
    }

    /// Get a channel by id, regardless of enabled status.
    pub fn get(&self, id: &str) -> Option<Arc<dyn NotificationChannel>> {
        let inner = self.inner.read().unwrap();
        inner.channels.get(id).cloned()
    }

    /// Get a channel by id, returning an error if not found or not enabled.
    pub fn get_enabled(&self, id: &str) -> Result<Arc<dyn NotificationChannel>> {
        let inner = self.inner.read().unwrap();
        let ch = inner
            .channels
            .get(id)
            .ok_or_else(|| Error::ChannelNotFound(id.to_string()))?;
        if !inner.enabled.get(id).copied().unwrap_or(false) {
            return Err(Error::Notification(
                grith_digest::notification::Error::ChannelDisabled(id.to_string()),
            ));
        }
        Ok(ch.clone())
    }

    /// Check whether a channel is enabled.
    pub fn is_enabled(&self, id: &str) -> bool {
        let inner = self.inner.read().unwrap();
        inner.enabled.get(id).copied().unwrap_or(false)
    }

    /// Set the enabled status of a channel.
    pub fn set_enabled(&self, id: &str, enabled: bool) {
        let mut inner = self.inner.write().unwrap();
        inner.enabled.insert(id.to_string(), enabled);
    }

    /// Return ids of all registered channels.
    pub fn channel_ids(&self) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        inner.channels.keys().cloned().collect()
    }

    /// Return ids of all enabled channels.
    pub fn enabled_channel_ids(&self) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        inner
            .channels
            .keys()
            .filter(|id| inner.enabled.get(*id).copied().unwrap_or(false))
            .cloned()
            .collect()
    }

    /// Return ids of all enabled channels whose required tier is at or below
    /// the given plan tier.
    pub fn available_channel_ids(&self, plan_tier: PlanTier) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        inner
            .channels
            .iter()
            .filter(|(id, ch)| {
                inner.enabled.get(*id).copied().unwrap_or(false) && ch.required_tier() <= plan_tier
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Return summary info for all registered channels.
    pub async fn list_channels(&self, plan_tier: PlanTier) -> Vec<ChannelInfo> {
        let channels: Vec<(String, Arc<dyn NotificationChannel>, bool)> = {
            let inner = self.inner.read().unwrap();
            inner
                .channels
                .iter()
                .map(|(id, ch)| {
                    let enabled = inner.enabled.get(id).copied().unwrap_or(false)
                        && ch.required_tier() <= plan_tier;
                    (id.clone(), ch.clone(), enabled)
                })
                .collect()
        };

        let mut infos = Vec::with_capacity(channels.len());
        for (id, ch, enabled) in &channels {
            let health = ch.health_check().await.ok();
            infos.push(ChannelInfo {
                id: id.clone(),
                display_name: ch.display_name().to_string(),
                required_tier: ch.required_tier(),
                supports_interactive: ch.supports_interactive(),
                enabled: *enabled,
                health,
            });
        }
        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }

    /// Number of registered channels.
    pub fn len(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.channels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ChannelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ChannelRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read().unwrap();
        f.debug_struct("ChannelRegistry")
            .field("channels", &inner.channels.keys().collect::<Vec<_>>())
            .field("enabled", &inner.enabled)
            .finish()
    }
}
