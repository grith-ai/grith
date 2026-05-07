// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Severity-based routing of digest items to notification channels.

use std::collections::{HashMap, HashSet};

use grith_digest::types::ScoreSeverity;

/// Routes digest items to notification channels based on severity and filters.
#[derive(Debug, Clone)]
pub struct RoutingEngine {
    /// Default channels per severity level.
    severity_routes: HashMap<ScoreSeverity, Vec<String>>,
    /// Channels to use for escalation events.
    escalation_channels: Vec<String>,
    /// Override: when a specific filter name fires, route to these channels
    /// instead of (or in addition to) the default severity routes.
    filter_overrides: HashMap<String, Vec<String>>,
}

impl RoutingEngine {
    pub fn new() -> Self {
        Self {
            severity_routes: HashMap::new(),
            escalation_channels: Vec::new(),
            filter_overrides: HashMap::new(),
        }
    }

    /// Build from a routing configuration.
    pub fn from_config(
        severity_routes: HashMap<String, Vec<String>>,
        escalation_channels: Vec<String>,
        filter_overrides: HashMap<String, Vec<String>>,
    ) -> Self {
        let severity_routes = severity_routes
            .into_iter()
            .filter_map(|(k, v)| {
                let sev = match k.to_lowercase().as_str() {
                    "low" => Some(ScoreSeverity::Low),
                    "medium" => Some(ScoreSeverity::Medium),
                    "high" => Some(ScoreSeverity::High),
                    "critical" => Some(ScoreSeverity::Critical),
                    _ => None,
                };
                sev.map(|s| (s, v))
            })
            .collect();

        Self {
            severity_routes,
            escalation_channels,
            filter_overrides,
        }
    }

    /// Set channels for a severity level.
    pub fn set_severity_route(&mut self, severity: ScoreSeverity, channels: Vec<String>) {
        self.severity_routes.insert(severity, channels);
    }

    /// Set channels for escalation events.
    pub fn set_escalation_channels(&mut self, channels: Vec<String>) {
        self.escalation_channels = channels;
    }

    /// Add a filter-name override.
    pub fn add_filter_override(&mut self, filter_name: String, channels: Vec<String>) {
        self.filter_overrides.insert(filter_name, channels);
    }

    /// Resolve which channel ids should receive a notification for a digest
    /// item, given its severity and the filter names that fired.
    pub fn resolve(&self, severity: ScoreSeverity, filter_names: &[String]) -> Vec<String> {
        let mut channel_set = HashSet::new();

        // Start with severity-based routes
        if let Some(channels) = self.severity_routes.get(&severity) {
            for ch in channels {
                channel_set.insert(ch.clone());
            }
        }

        // Add filter-specific overrides
        for filter in filter_names {
            if let Some(channels) = self.filter_overrides.get(filter) {
                for ch in channels {
                    channel_set.insert(ch.clone());
                }
            }
        }

        // If nothing matched, fall back to all severity routes for "low"
        // to ensure at least dashboard/desktop get notified
        if channel_set.is_empty() {
            if let Some(channels) = self.severity_routes.get(&ScoreSeverity::Low) {
                for ch in channels {
                    channel_set.insert(ch.clone());
                }
            }
        }

        let mut result: Vec<String> = channel_set.into_iter().collect();
        result.sort();
        result
    }

    /// Resolve channels for an escalation event.
    pub fn resolve_escalation(&self) -> Vec<String> {
        self.escalation_channels.clone()
    }
}

impl Default for RoutingEngine {
    fn default() -> Self {
        // Sensible defaults: dashboard (websocket) for everything, desktop for medium+
        let mut engine = Self::new();
        engine.set_severity_route(ScoreSeverity::Low, vec!["websocket".into()]);
        engine.set_severity_route(
            ScoreSeverity::Medium,
            vec!["websocket".into(), "desktop".into()],
        );
        engine.set_severity_route(
            ScoreSeverity::High,
            vec!["websocket".into(), "desktop".into()],
        );
        engine.set_severity_route(
            ScoreSeverity::Critical,
            vec!["websocket".into(), "desktop".into()],
        );
        engine.set_escalation_channels(vec!["websocket".into(), "desktop".into()]);
        engine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_routing() {
        let engine = RoutingEngine::default();

        let low = engine.resolve(ScoreSeverity::Low, &[]);
        assert!(low.contains(&"websocket".to_string()));
        assert!(!low.contains(&"desktop".to_string()));

        let high = engine.resolve(ScoreSeverity::High, &[]);
        assert!(high.contains(&"websocket".to_string()));
        assert!(high.contains(&"desktop".to_string()));
    }

    #[test]
    fn test_filter_override() {
        let mut engine = RoutingEngine::default();
        engine.add_filter_override(
            "secret-scan".to_string(),
            vec!["slack".to_string(), "pagerduty".to_string()],
        );

        let channels = engine.resolve(ScoreSeverity::Low, &["secret-scan".to_string()]);
        assert!(channels.contains(&"websocket".to_string()));
        assert!(channels.contains(&"slack".to_string()));
        assert!(channels.contains(&"pagerduty".to_string()));
    }

    #[test]
    fn test_deduplication() {
        let mut engine = RoutingEngine::new();
        engine.set_severity_route(ScoreSeverity::High, vec!["slack".into(), "desktop".into()]);
        engine.add_filter_override("ssh-key".into(), vec!["slack".into(), "email".into()]);

        let channels = engine.resolve(ScoreSeverity::High, &["ssh-key".into()]);
        // "slack" should appear only once
        assert_eq!(channels.iter().filter(|c| *c == "slack").count(), 1);
        assert!(channels.contains(&"desktop".to_string()));
        assert!(channels.contains(&"email".to_string()));
    }

    #[test]
    fn test_from_config() {
        let mut sev = HashMap::new();
        sev.insert("critical".into(), vec!["pagerduty".into(), "slack".into()]);

        let engine = RoutingEngine::from_config(sev, vec!["pagerduty".into()], HashMap::new());

        let channels = engine.resolve(ScoreSeverity::Critical, &[]);
        assert!(channels.contains(&"pagerduty".to_string()));
        assert!(channels.contains(&"slack".to_string()));

        let esc = engine.resolve_escalation();
        assert_eq!(esc, vec!["pagerduty".to_string()]);
    }

    #[test]
    fn test_escalation_channels() {
        let mut engine = RoutingEngine::new();
        engine.set_escalation_channels(vec!["pagerduty".into(), "email".into()]);
        let esc = engine.resolve_escalation();
        assert_eq!(esc.len(), 2);
    }
}
