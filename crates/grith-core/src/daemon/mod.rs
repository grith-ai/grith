// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Daemon initialization, health checking, and lifecycle management.
//!
//! This module owns the [`Daemon`] struct which holds all initialized subsystem
//! handles and coordinates their startup, health monitoring, and shutdown.

pub(crate) mod background;
#[allow(dead_code)]
pub mod client;
pub(crate) mod config_loader;
mod filter_registry;
mod health;
mod notifications;
mod pid;
#[allow(dead_code)]
pub mod token;

// Re-export public items so external `use crate::daemon::*` paths remain valid.
pub use health::format_health_report;
pub use pid::{is_dashboard_running, remove_dashboard_pid, write_dashboard_pid};

use crate::config::GrithConfig;
use crate::error::Error;
use config_loader::{expand_path, resolve_api_key, to_supervisor_config};
use filter_registry::{build_filter_registry_with_config_result, build_meta_rule_engine_result};
use grith_audit::AuditStorage;
use grith_audit::CorrelationTracker as AuditCorrelationTracker;
use grith_digest::DigestQueue;
use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::dlp_gate::DlpRedactor;
use grith_proxy::filters::session_containment::ContainmentTracker;
use grith_proxy::scoring::ScoringConfig;
use grith_supervisor::supervisor::SupervisorRegistry;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::broadcast;

/// Subsystem health status.
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded(String),
    Unhealthy(String),
}

/// Individual subsystem health.
#[derive(Debug, Clone)]
pub struct SubsystemHealth {
    pub name: String,
    pub status: HealthStatus,
}

/// Overall daemon health report.
#[derive(Debug, Clone)]
pub struct HealthReport {
    pub subsystems: Vec<SubsystemHealth>,
}

impl HealthReport {
    pub fn is_healthy(&self) -> bool {
        self.subsystems
            .iter()
            .all(|s| s.status == HealthStatus::Healthy)
    }

    pub fn is_degraded(&self) -> bool {
        self.subsystems
            .iter()
            .any(|s| matches!(s.status, HealthStatus::Degraded(_)))
            && !self
                .subsystems
                .iter()
                .any(|s| matches!(s.status, HealthStatus::Unhealthy(_)))
    }
}

/// Holds all initialized subsystem handles.
pub struct Daemon {
    pub config: GrithConfig,
    pub account_id: String,
    pub audit_storage: Arc<Mutex<AuditStorage>>,
    pub digest_queue: Arc<DigestQueue>,
    pub proxy: Arc<SecurityProxy>,
    pub supervisor_registry: Arc<Mutex<SupervisorRegistry>>,
    pub dlp_redactor: Arc<DlpRedactor>,
    pub containment_tracker: Arc<ContainmentTracker>,
    pub correlation_tracker: Arc<AuditCorrelationTracker>,
    pub canary_registry: Arc<grith_proxy::filters::canary::CanaryRegistry>,
    pub notification_dispatcher: Arc<grith_notify::NotificationDispatcher>,
    pub feature_gate: Arc<RwLock<crate::license::FeatureGate>>,
    /// License renewal date (YYYY-MM-DD) when a Pro/Enterprise license is active.
    pub license_valid_until: Option<String>,
    /// Billing portal URL from license metadata, if provided.
    pub billing_portal_url: Option<String>,
    // Retained for runtime diagnostics and future refresh logic.
    #[allow(dead_code)]
    pub license_status: crate::license::LicenseStatus,
    /// Live licence-refresh state shared with the API/CLI.
    pub refresh_state: Arc<RwLock<crate::license::RefreshState>>,
    /// Shared reputation table — owned by the daemon, shared across all
    /// supervisor sessions. Loaded from disk on startup, saved periodically
    /// and on shutdown.
    pub reputation_table: Arc<Mutex<grith_proxy::reputation::ReputationTable>>,
    /// Mtime of the provider-keys directory at last load, for rotation detection.
    provider_keys_mtime: Option<std::time::SystemTime>,
    pub(crate) shutdown_tx: broadcast::Sender<()>,
    // Held to keep the broadcast channel alive; receivers are created via subscribe_shutdown().
    #[allow(dead_code)]
    shutdown_rx: broadcast::Receiver<()>,
}

/// Initialization result with optional warnings.
pub struct InitResult {
    pub daemon: Daemon,
    pub warnings: Vec<String>,
}

impl Daemon {
    /// Initialize all subsystems in dependency order.
    pub fn start(mut config: GrithConfig) -> Result<InitResult, Error> {
        let mut warnings = Vec::new();

        tracing::info!("initializing subsystems");

        // 0. License check -- plan tier is always derived from the signed license status.
        // The daemon's background `spawn_license_revalidation()` task is the
        // single place that contacts grith.ai for refresh; startup just reads
        // the cached signed licence so init stays fast and offline-tolerant.
        let license_status = crate::license::load_license(&crate::license::license_path());

        let derived_tier = crate::license::plan_tier_from_status(&license_status);
        config.general.plan_tier = derived_tier.to_string();
        match &license_status {
            crate::license::LicenseStatus::Valid(lic) => {
                tracing::info!(
                    plan = %lic.plan,
                    expires = %lic.valid_until.format("%Y-%m-%d"),
                    "pro license active"
                );
            }
            crate::license::LicenseStatus::GracePeriod { expired_days, .. } => {
                tracing::warn!(
                    expired_days,
                    "license expired -- grace period active, run `grith pro refresh`"
                );
            }
            crate::license::LicenseStatus::ExtendedGrace { expired_days, .. } => {
                let renew_url = format!("{}/dashboard/settings", crate::license::api_base_url());
                tracing::warn!(
                    expired_days,
                    %renew_url,
                    "license expired -- extended grace window, renew in dashboard"
                );
            }
            crate::license::LicenseStatus::Expired => {
                tracing::warn!(
                    "license expired beyond grace window, falling back to community tier"
                );
            }
            crate::license::LicenseStatus::Invalid(reason) => {
                tracing::warn!(
                    reason,
                    "invalid license file, falling back to community tier"
                );
            }
            crate::license::LicenseStatus::NotFound => {
                tracing::debug!("no license file found, using community tier");
            }
        }
        let initial_feature_gate = crate::license::feature_gate_from_status(&license_status);
        let account_id = resolve_account_id(&license_status);

        // Build initial refresh state, seeded from credentials' last_validated.
        let mut initial_refresh_state = crate::license::RefreshState::default();
        if let Ok(Some(creds)) = crate::license::load_credentials() {
            if !creds.last_validated.is_empty() {
                initial_refresh_state.last_success = Some(creds.last_validated.clone());
            }
        }
        if let crate::license::LicenseStatus::Valid(ref lic)
        | crate::license::LicenseStatus::GracePeriod {
            license: ref lic, ..
        }
        | crate::license::LicenseStatus::ExtendedGrace {
            license: ref lic, ..
        } = license_status
        {
            initial_refresh_state.air_gapped = lic.air_gapped;
            if lic.air_gapped {
                tracing::info!(
                    license_id = %lic.license_id,
                    "air-gapped licence active — scheduled refresh disabled"
                );
            }
        }

        // Extract license renewal date for API responses.
        let license_valid_until = match &license_status {
            crate::license::LicenseStatus::Valid(lic)
            | crate::license::LicenseStatus::GracePeriod { license: lic, .. }
            | crate::license::LicenseStatus::ExtendedGrace { license: lic, .. } => {
                Some(lic.valid_until.format("%Y-%m-%d").to_string())
            }
            _ => None,
        };
        let billing_portal_url = crate::license::billing_portal_url_from_status(&license_status);

        // 1. Resolve paths
        let audit_dir = expand_path(&config.general.audit_dir);

        // 2. Create directories
        if let Err(e) = std::fs::create_dir_all(&audit_dir) {
            warnings.push(format!(
                "could not create audit dir {}: {e}",
                audit_dir.display()
            ));
        }

        // 3 & 4. Open audit and digest databases in parallel — both are
        // independent SQLite files so there is no ordering constraint.
        let audit_db_path = audit_dir.join("audit.db");
        let digest_db_path = audit_dir.join("digest.db");

        let (audit_result, digest_result) = std::thread::scope(|s| {
            let t_audit = s.spawn(|| AuditStorage::open(&audit_db_path));
            let t_digest = s.spawn(|| DigestQueue::open(&digest_db_path));
            (
                t_audit.join().expect("audit open thread panicked"),
                t_digest.join().expect("digest open thread panicked"),
            )
        });

        let audit_storage =
            Arc::new(Mutex::new(audit_result.map_err(|e| {
                Error::Config(format!("failed to open audit database: {e}"))
            })?));
        let digest_queue = Arc::new(
            digest_result
                .map_err(|e| Error::Config(format!("failed to open digest database: {e}")))?,
        );

        // Backfill legacy unchained rows, then repair any gaps or hash
        // mismatches in the chain. Both must complete before the HTTP server
        // starts, otherwise audit endpoints return 500 via enforce_chain_integrity().
        {
            let storage = Arc::clone(&audit_storage);
            let repair_result: Result<(usize, usize), String> = std::thread::scope(|scope| {
                let worker = scope.spawn(move || match storage.lock() {
                    Ok(s) => {
                        let backfilled = s
                            .backfill_chain_for_legacy_rows()
                            .map_err(|e| format!("backfill: {e}"))?;
                        let repaired = s.repair_chain().map_err(|e| format!("repair: {e}"))?;
                        Ok((backfilled, repaired))
                    }
                    Err(_) => Err("audit storage lock poisoned".to_string()),
                });

                // Show a spinner on stderr while the repair runs.
                let frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
                let mut i = 0;
                while !worker.is_finished() {
                    eprint!("\r  {} Verifying audit chain...", frames[i % frames.len()]);
                    i += 1;
                    std::thread::sleep(std::time::Duration::from_millis(80));
                }
                if i > 0 {
                    eprint!("\r{}\r", " ".repeat(40));
                }

                worker.join().expect("audit chain repair thread panicked")
            });

            match repair_result {
                Ok((0, 0)) => {}
                Ok((backfilled, repaired)) => {
                    if backfilled > 0 {
                        tracing::info!(count = backfilled, "backfilled legacy audit chain rows");
                    }
                    if repaired > 0 {
                        tracing::info!(count = repaired, "repaired audit chain gaps");
                    }
                }
                Err(e) => {
                    warnings.push(format!("audit chain repair failed: {e}"));
                    tracing::warn!(error = %e, "audit chain repair failed");
                }
            }
        }

        tracing::info!(path = %audit_db_path.display(), "audit storage initialized");
        tracing::info!(path = %digest_db_path.display(), "digest queue initialized");

        // 5. Initialize security proxy
        let (registry, containment_tracker, canary_registry, dlp_redactor) =
            build_filter_registry_with_config_result(&config.proxy.filters)?;
        let scoring = ScoringConfig {
            auto_allow_threshold: config.proxy.auto_allow_threshold,
            auto_deny_threshold: config.proxy.auto_deny_threshold,
            cold_start_calls: config.proxy.cold_start_calls,
            cold_start_escalation_low: config.proxy.cold_start_escalation_low,
            cold_start_escalation_high: config.proxy.cold_start_escalation_high,
        };
        let meta_rules = build_meta_rule_engine_result()?;
        let filter_count = registry.count();
        let proxy = Arc::new(SecurityProxy::new(registry, scoring, meta_rules));
        tracing::info!(
            allow = config.proxy.auto_allow_threshold,
            deny = config.proxy.auto_deny_threshold,
            filters = filter_count,
            "security proxy initialized"
        );

        // 6. Initialize supervisor registry
        let supervisor_config = to_supervisor_config(&config.supervisor);
        if config.supervisor.enabled {
            if let Err(msg) = supervisor_config.validate() {
                return Err(Error::Config(format!(
                    "supervisor config validation: {msg}"
                )));
            }
        }
        let mut registry_inner = SupervisorRegistry::new(supervisor_config);
        let license_max = initial_feature_gate.max_sessions();
        let config_max = config.supervisor.max_concurrent_sessions;
        let effective_max = config_max.min(license_max);
        registry_inner.set_max_sessions(effective_max);
        let supervisor_registry = Arc::new(Mutex::new(registry_inner));
        if config.supervisor.enabled {
            tracing::info!(
                max_sessions = effective_max,
                config_max,
                license_max,
                profile = %config.supervisor.default_profile,
                "supervisor subsystem initialized"
            );
        } else {
            tracing::info!("supervisor subsystem disabled");
        }

        // 7. Correlation tracker for source->sink evidence chaining
        let correlation_tracker = Arc::new(AuditCorrelationTracker::with_defaults());

        // 8. Initialize notification dispatcher
        let notification_dispatcher = {
            use grith_digest::notification::CallbackNonceStore;
            use grith_notify::{ChannelRegistry, RoutingEngine};

            let plan_tier = initial_feature_gate.tier;
            let nonce_store = Arc::new(CallbackNonceStore::new(std::time::Duration::from_secs(
                config.proxy.review_timeout_seconds,
            )));

            let routing = if config.notifications.routing.severity_routes.is_empty() {
                RoutingEngine::default()
            } else {
                RoutingEngine::from_config(
                    config.notifications.routing.severity_routes.clone(),
                    config.notifications.routing.escalation_channels.clone(),
                    config.notifications.routing.filter_overrides.clone(),
                )
            };

            let mut rate_limiter = grith_notify::rate_limiter::RateLimiter::new(
                config.notifications.rate_limits.max_per_window,
                std::time::Duration::from_secs(config.notifications.rate_limits.window_seconds),
            );
            if config.notifications.rate_limits.quiet_hours_start != 0
                || config.notifications.rate_limits.quiet_hours_end != 0
            {
                rate_limiter.set_quiet_hours(
                    config.notifications.rate_limits.quiet_hours_start,
                    config.notifications.rate_limits.quiet_hours_end,
                );
            }

            let batcher = grith_notify::batcher::Batcher::new(
                std::time::Duration::from_secs(
                    config.notifications.escalation.batch_window_seconds,
                ),
                config.notifications.escalation.max_batch_size,
            );

            let registry = ChannelRegistry::new();
            // Note: channels are registered later when the server starts and ws_tx is available.

            let auto_escalate_timeout = std::time::Duration::from_secs(
                config
                    .notifications
                    .escalation
                    .auto_escalate_timeout_seconds,
            );
            let auto_escalate_min_severity = match config
                .notifications
                .escalation
                .auto_escalate_min_severity
                .to_lowercase()
                .as_str()
            {
                "low" => grith_digest::types::ScoreSeverity::Low,
                "medium" => grith_digest::types::ScoreSeverity::Medium,
                "critical" => grith_digest::types::ScoreSeverity::Critical,
                _ => grith_digest::types::ScoreSeverity::High,
            };

            let dispatcher = grith_notify::NotificationDispatcher::new(
                registry,
                routing,
                nonce_store,
                plan_tier,
                digest_queue.clone(),
                rate_limiter,
                batcher,
                auto_escalate_timeout,
                auto_escalate_min_severity,
            );
            Arc::new(dispatcher)
        };
        if config.notifications.enabled {
            tracing::info!("notification dispatcher initialized");
        }

        // 9. Shutdown channel
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        {
            let enabled_count = initial_feature_gate
                .feature_list()
                .iter()
                .filter(|(_, enabled)| *enabled)
                .count();
            tracing::info!(
                tier = %initial_feature_gate.tier,
                seats = initial_feature_gate.seats,
                enabled_features = enabled_count,
                max_sessions = effective_max,
                "feature gating active"
            );
        }

        let feature_gate = Arc::new(RwLock::new(initial_feature_gate));

        // Load shared reputation table from disk.
        let reputation_table = {
            let rep_path = grith_proxy::reputation::default_reputation_path();
            let table = grith_proxy::reputation::ReputationTable::load(&rep_path);
            tracing::info!(
                entries = table.len(),
                path = %rep_path.display(),
                "loaded shared reputation table"
            );
            Arc::new(Mutex::new(table))
        };

        tracing::info!("all subsystems initialized");

        let daemon = Daemon {
            config,
            account_id,
            audit_storage,
            digest_queue,
            proxy,
            supervisor_registry,
            dlp_redactor,
            containment_tracker,
            correlation_tracker,
            canary_registry,
            notification_dispatcher,
            feature_gate,
            license_valid_until,
            billing_portal_url,
            license_status,
            refresh_state: Arc::new(RwLock::new(initial_refresh_state)),
            reputation_table,
            provider_keys_mtime: config_loader::provider_keys_dir_mtime(),
            shutdown_tx,
            shutdown_rx,
        };

        Ok(InitResult { daemon, warnings })
    }

    /// Perform a health check across all subsystems.
    pub fn health_check(&self) -> HealthReport {
        let mut subsystems = Vec::new();

        // Audit storage
        subsystems.push(SubsystemHealth {
            name: "audit".to_string(),
            status: health::check_audit_health(&self.audit_storage),
        });

        // Digest queue
        subsystems.push(SubsystemHealth {
            name: "digest".to_string(),
            status: health::check_digest_health(&self.digest_queue),
        });

        // Security proxy
        subsystems.push(SubsystemHealth {
            name: "proxy".to_string(),
            status: HealthStatus::Healthy, // proxy is in-memory, always healthy if constructed
        });

        // Supervisor
        subsystems.push(SubsystemHealth {
            name: "supervisor".to_string(),
            status: if self.config.supervisor.enabled {
                if grith_supervisor::platform::is_supported() {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Degraded("platform not supported".to_string())
                }
            } else {
                HealthStatus::Degraded("disabled in config".to_string())
            },
        });

        HealthReport { subsystems }
    }

    /// Get a receiver for the shutdown signal.
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        tracing::info!("initiating graceful shutdown");
        let _ = self.shutdown_tx.send(());
    }

    /// Get the filter count from the proxy.
    pub fn filter_count(&self) -> usize {
        self.proxy.filter_count()
    }

    /// Create an LLM router from the current configuration.
    pub fn create_llm_router(&self) -> anyhow::Result<grith_llm::LlmRouter> {
        // Check if provider keys have been rotated since last load.
        let current_mtime = config_loader::provider_keys_dir_mtime();
        if current_mtime != self.provider_keys_mtime && current_mtime.is_some() {
            tracing::info!("provider key files updated — loading rotated keys");
        }

        let provider_name = &self.config.llm.default_provider;
        let provider: Arc<dyn grith_llm::LlmProvider> = match provider_name.as_str() {
            "ollama" => Arc::new(grith_llm::ollama::OllamaProvider::new(
                &self.config.llm.ollama.base_url,
                &self.config.llm.ollama.model,
            )?),
            "anthropic" => {
                let api_key = resolve_api_key(
                    "Anthropic",
                    self.config.llm.anthropic.api_key.as_deref(),
                    &self.config.llm.anthropic.api_key_env,
                )?;
                Arc::new(grith_llm::anthropic::AnthropicProvider::new(
                    api_key,
                    &self.config.llm.anthropic.model,
                )?)
            }
            "openai" => {
                let api_key = resolve_api_key(
                    "OpenAI",
                    self.config.llm.openai.api_key.as_deref(),
                    &self.config.llm.openai.api_key_env,
                )?;
                Arc::new(
                    grith_llm::openai_compat::OpenAiCompatProvider::new(
                        "https://api.openai.com",
                        &self.config.llm.openai.model,
                        Some(api_key),
                    )?
                    .with_name("openai"),
                )
            }
            "openrouter" => {
                let api_key = resolve_api_key(
                    "OpenRouter",
                    self.config.llm.openrouter.api_key.as_deref(),
                    &self.config.llm.openrouter.api_key_env,
                )?;
                Arc::new(
                    grith_llm::openai_compat::OpenAiCompatProvider::new(
                        "https://openrouter.ai/api",
                        &self.config.llm.openrouter.model,
                        Some(api_key),
                    )?
                    .with_name("openrouter"),
                )
            }
            other => anyhow::bail!("unsupported LLM provider: {other}"),
        };
        tracing::info!(provider = %provider_name, "LLM router created");
        Ok(grith_llm::LlmRouter::fixed(provider_name, provider))
    }

    /// Get the model name from config.
    pub fn model_name(&self) -> &str {
        match self.config.llm.default_provider.as_str() {
            "ollama" => &self.config.llm.ollama.model,
            "openai" => &self.config.llm.openai.model,
            "anthropic" => &self.config.llm.anthropic.model,
            "openrouter" => &self.config.llm.openrouter.model,
            _ => &self.config.llm.ollama.model,
        }
    }
}

/// Set up signal handlers for graceful shutdown.
pub async fn wait_for_shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {
                        tracing::info!("received SIGINT (Ctrl+C)");
                    }
                    _ = sigterm.recv() => {
                        tracing::info!("received SIGTERM");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to register SIGTERM handler, falling back to Ctrl+C only");
                if let Err(e) = ctrl_c.await {
                    tracing::error!(error = %e, "failed to listen for Ctrl+C signal");
                } else {
                    tracing::info!("received SIGINT (Ctrl+C)");
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        match ctrl_c.await {
            Ok(()) => tracing::info!("received Ctrl+C"),
            Err(e) => tracing::error!(error = %e, "failed to listen for Ctrl+C signal"),
        }
    }
}

fn resolve_account_id(status: &crate::license::LicenseStatus) -> String {
    let from_status = match status {
        crate::license::LicenseStatus::Valid(lic)
        | crate::license::LicenseStatus::GracePeriod { license: lic, .. }
        | crate::license::LicenseStatus::ExtendedGrace { license: lic, .. } => {
            let user_id = lic.user_id.trim();
            if user_id.is_empty() {
                None
            } else {
                Some(user_id.to_string())
            }
        }
        _ => None,
    };
    if let Some(user_id) = from_status {
        return format!("user:{user_id}");
    }

    if let Ok(Some(creds)) = crate::license::load_credentials() {
        let user_id = creds.user_id.trim();
        if !user_id.is_empty() {
            return format!("user:{user_id}");
        }
    }

    "local:community".to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_start() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.general.audit_dir = dir.path().join("audit").to_string_lossy().to_string();

        let result = Daemon::start(config).unwrap();
        assert!(result.warnings.is_empty());

        let health = result.daemon.health_check();
        let audit_health = health
            .subsystems
            .iter()
            .find(|s| s.name == "audit")
            .unwrap();
        assert_eq!(audit_health.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_daemon_model_name() {
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.llm.default_provider = "ollama".to_string();
        config.llm.ollama.model = "llama3.1:8b".to_string();

        let dir = tempfile::tempdir().unwrap();
        config.general.audit_dir = dir.path().join("audit").to_string_lossy().to_string();

        let result = Daemon::start(config).unwrap();
        assert_eq!(result.daemon.model_name(), "llama3.1:8b");
    }

    #[test]
    fn test_daemon_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.general.audit_dir = dir.path().join("audit").to_string_lossy().to_string();

        let result = Daemon::start(config).unwrap();
        let mut rx = result.daemon.subscribe_shutdown();

        result.daemon.shutdown();
        // The receiver should get the signal
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_daemon_filter_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.general.audit_dir = dir.path().join("audit").to_string_lossy().to_string();

        let result = Daemon::start(config).unwrap();
        // Default proxy has the built-in filters
        let count = result.daemon.filter_count();
        assert!(
            count >= 6,
            "expected default proxy to register filters, got {count}"
        );
    }

    #[test]
    fn test_daemon_ignores_config_plan_tier_override_and_uses_license_tier() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.general.audit_dir = dir.path().join("audit").to_string_lossy().to_string();
        config.general.plan_tier = "enterprise".to_string();

        let status = crate::license::load_license(&crate::license::license_path());
        let expected_tier = crate::license::plan_tier_from_status(&status).to_string();

        let result = Daemon::start(config).unwrap();
        assert_eq!(result.daemon.config.general.plan_tier, expected_tier);

        let gate = result.daemon.feature_gate.read().unwrap();
        let expected_gate_tier = match result.daemon.config.general.plan_tier.as_str() {
            "enterprise" => crate::license::PlanTier::Enterprise,
            "pro" => crate::license::PlanTier::Pro,
            _ => crate::license::PlanTier::Community,
        };
        assert_eq!(gate.tier, expected_gate_tier);
    }
}
