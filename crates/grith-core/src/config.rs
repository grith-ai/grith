// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Top-level configuration model for the grith daemon.
//!
//! Defines the nested `GrithConfig` struct tree that maps one-to-one with the
//! TOML configuration file.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level configuration for the grith daemon.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GrithConfig {
    pub general: GeneralConfig,
    pub llm: LlmConfig,
    pub proxy: ProxyConfig,
    pub reputation: ReputationConfig,
    pub digest: DigestConfig,
    pub server: ServerConfig,
    pub supervisor: SupervisorCoreConfig,
    pub notifications: NotificationConfig,
}

/// General daemon settings (log level, audit directory, plan tier).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub log_level: String,
    pub audit_dir: String,
    /// Plan tier: "community", "pro", or "enterprise".
    pub plan_tier: String,
    /// Check for new releases on startup. Defaults to `true`.
    pub update_check: bool,
    /// Sync audit records to the grith cloud API. Defaults to `true`.
    /// Set to `false` to keep audit records local-only. This does not disable
    /// license revalidation or other explicit API calls.
    pub audit_sync: bool,
    /// Check for remote profile updates on startup. Defaults to `true`.
    /// Set to `false` to disable OTA supervisor profile overlay checks.
    pub profile_update_check: bool,
}

/// LLM provider configuration (provider selection, credentials, routing).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    pub default_provider: String,
    pub ollama: OllamaConfig,
    pub openai: OpenAiConfig,
    pub anthropic: AnthropicConfig,
    pub openrouter: OpenRouterConfig,
    pub routing: RoutingConfig,
}

/// Ollama local LLM provider settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OllamaConfig {
    pub base_url: String,
    pub model: String,
}

/// OpenAI API provider settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OpenAiConfig {
    pub api_key: Option<String>,
    pub api_key_env: String,
    pub model: String,
}

/// Anthropic API provider settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnthropicConfig {
    pub api_key: Option<String>,
    pub api_key_env: String,
    pub model: String,
}

/// OpenRouter API provider settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OpenRouterConfig {
    pub api_key: Option<String>,
    pub api_key_env: String,
    pub model: String,
}

/// LLM request routing strategy (simple/complex classification).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    pub strategy: String,
    pub simple_threshold: usize,
    pub complex_keywords: Vec<String>,
}

/// Security proxy scoring thresholds and cold-start parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub auto_allow_threshold: f64,
    pub auto_deny_threshold: f64,
    pub cold_start_calls: u64,
    pub cold_start_escalation_low: f64,
    pub cold_start_escalation_high: f64,
    /// Seconds to wait for human review before auto-denying a queued tool call.
    /// Used by the agent loop (not supervisor, which has its own freeze_timeout_seconds).
    pub review_timeout_seconds: u64,
    /// Per-filter enable/disable overrides.
    pub filters: FilterGroupConfig,
}

/// Per-filter enable/disable toggles for Phase 3 (context) filters.
///
/// Phase 1 (static) and Phase 2 (pattern) filters are always active.
/// Phase 3 filters can be individually disabled here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterGroupConfig {
    pub reputation: FilterToggle,
    pub behavioural: FilterToggle,
    pub taint: FilterToggle,
    pub rate_limit: FilterToggle,
    pub egress: FilterToggle,
    pub session_containment: FilterToggle,
}

/// Single filter enable/disable toggle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterToggle {
    pub enabled: bool,
}

/// Feature-tuple Beta Reputation System configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReputationConfig {
    pub enabled: bool,
    pub decay_lambda: f64,
    pub deny_weight: f64,
    pub auto_allow_trust: f64,
    pub auto_allow_min_observations: usize,
    pub max_score_reduction: f64,
    pub ceiling_filter_threshold: f64,
    pub max_auto_allow_raw_score: f64,
    pub save_interval_seconds: u64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            decay_lambda: 0.98,
            deny_weight: 3.0,
            auto_allow_trust: 0.92,
            auto_allow_min_observations: 8,
            max_score_reduction: 4.0,
            ceiling_filter_threshold: 5.0,
            max_auto_allow_raw_score: 7.0,
            save_interval_seconds: 300,
        }
    }
}

impl ReputationConfig {
    /// Convert to the proxy-layer reputation config struct.
    pub fn to_proxy_config(&self) -> grith_proxy::reputation::ReputationConfig {
        grith_proxy::reputation::ReputationConfig {
            enabled: self.enabled,
            decay_lambda: self.decay_lambda,
            deny_weight: self.deny_weight,
            auto_allow_trust: self.auto_allow_trust,
            auto_allow_min_observations: self.auto_allow_min_observations,
            max_score_reduction: self.max_score_reduction,
            ceiling_filter_threshold: self.ceiling_filter_threshold,
            save_interval_seconds: self.save_interval_seconds,
            max_auto_allow_raw_score: self.max_auto_allow_raw_score,
        }
    }
}

/// Digest queue settings (review intervals, delivery method, capacity).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DigestConfig {
    pub interval_active: String,
    pub interval_idle: String,
    pub delivery: String,
    pub max_queue_size: usize,
}

/// TLS configuration for native HTTPS support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// HTTP/WebSocket server and dashboard settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub dashboard_dir: Option<String>,
    pub tls: Option<TlsConfig>,
    pub rate_limit: RateLimitConfig,
    /// Seconds to wait after the last supervisor session exits before
    /// auto-shutting down the daemon. Set to 0 to disable idle shutdown.
    pub idle_shutdown_seconds: u64,
}

/// Per-bucket API rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    /// Max requests per second for read-only / general endpoints.
    pub general_rps: u32,
    /// Max requests per second for write/mutation endpoints.
    pub write_rps: u32,
    /// Max requests per second for the /proxy/test endpoint.
    pub proxy_test_rps: u32,
    /// Max requests per second for daemon IPC endpoints used by local clients.
    pub ipc_rps: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            general_rps: 100,
            write_rps: 10,
            proxy_test_rps: 20,
            ipc_rps: 10_000,
        }
    }
}

/// Supervisor configuration (v1.5 — CLI supervisor mode).
/// Maps to `grith_supervisor::config::SupervisorConfig` at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SupervisorCoreConfig {
    pub enabled: bool,
    pub default_profile: String,
    pub freeze_timeout_seconds: u64,
    pub max_concurrent_sessions: usize,
    pub pty_forwarding: bool,
    /// Refuse startup if the platform cannot provide full per-syscall interception.
    /// When `true`, `grith exec` aborts if the supervision backend is degraded
    /// (macOS lifecycle-only) or unavailable (ptrace blocked). Defaults to `false`.
    pub require_sandbox: bool,
    pub platform: SupervisorPlatformConfig,
    pub noise_reduction: SupervisorNoiseConfig,
    pub dns_inspection: SupervisorDnsInspectionConfig,
}

/// Platform-specific interception mechanism configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SupervisorPlatformConfig {
    pub linux_mechanism: String,
    pub macos_mechanism: String,
    pub seccomp_pre_filter: bool,
}

/// Noise reduction tuning for supervisor syscall filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SupervisorNoiseConfig {
    pub ignore_read_only: bool,
    pub batch_rapid_reads: bool,
    pub batch_window_ms: u64,
}

/// DNS inspection settings for supervisor DNS proxy interception.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SupervisorDnsInspectionConfig {
    pub enabled: bool,
    pub upstream_resolver: Option<String>,
}

// --- Notification Config ---

/// Multi-channel notification system configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub desktop: DesktopNotifyConfig,
    pub email: EmailNotifyConfig,
    pub slack: SlackNotifyConfig,
    pub telegram: TelegramNotifyConfig,
    pub discord: DiscordNotifyConfig,
    pub whatsapp: WhatsAppNotifyConfig,
    pub teams: TeamsNotifyConfig,
    pub pagerduty: PagerDutyNotifyConfig,
    pub opsgenie: OpsgenieNotifyConfig,
    pub webhook: WebhookNotifyConfig,
    pub routing: NotifyRoutingConfig,
    pub rate_limits: NotifyRateLimitConfig,
    pub escalation: EscalationConfig,
}

/// Desktop notification channel (libnotify / osascript).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DesktopNotifyConfig {
    pub enabled: bool,
}

/// Email notification channel (SMTP).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailNotifyConfig {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    /// Use `smtp_password_env` to specify an env var name instead of a raw password.
    pub smtp_password: String,
    pub smtp_password_env: String,
    pub from_address: String,
    pub to_addresses: Vec<String>,
    pub starttls: bool,
}

/// Slack notification channel (bot token or webhook).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SlackNotifyConfig {
    pub enabled: bool,
    /// Bot token (xoxb-...). Use `bot_token_env` to read from env.
    pub bot_token: String,
    pub bot_token_env: String,
    pub channel_id: String,
    /// Optional webhook URL for one-way mode.
    pub webhook_url: String,
}

/// Telegram notification channel (bot API).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelegramNotifyConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub bot_token_env: String,
    pub chat_id: String,
    pub authorized_user_ids: Vec<i64>,
    /// Polling interval in seconds for the callback long-polling loop.
    pub polling_interval_secs: u64,
}

/// Discord notification channel (bot token or webhook).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscordNotifyConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub bot_token_env: String,
    pub channel_id: String,
    pub webhook_url: String,
}

/// WhatsApp notification channel (Cloud API).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WhatsAppNotifyConfig {
    pub enabled: bool,
    pub access_token: String,
    pub access_token_env: String,
    pub phone_number_id: String,
    pub recipient_number: String,
}

/// Microsoft Teams notification channel (incoming webhook).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TeamsNotifyConfig {
    pub enabled: bool,
    pub webhook_url: String,
}

/// PagerDuty notification channel (Events API v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PagerDutyNotifyConfig {
    pub enabled: bool,
    pub routing_key: String,
    pub routing_key_env: String,
}

/// Opsgenie notification channel (Alert API).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OpsgenieNotifyConfig {
    pub enabled: bool,
    pub api_key: String,
    pub api_key_env: String,
    pub eu_endpoint: bool,
}

/// Generic webhook notification channel with HMAC signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookNotifyConfig {
    pub enabled: bool,
    pub url: String,
    pub secret: String,
    pub secret_env: String,
    pub callback_url: String,
    pub max_retries: u32,
    pub headers: Vec<Vec<String>>,
}

/// Severity-based routing rules for notification delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotifyRoutingConfig {
    /// Severity → list of channel IDs.
    pub severity_routes: std::collections::HashMap<String, Vec<String>>,
    /// Channel IDs for escalation events.
    pub escalation_channels: Vec<String>,
    /// Filter name → list of additional channel IDs.
    pub filter_overrides: std::collections::HashMap<String, Vec<String>>,
}

/// Per-channel notification rate limiting and quiet hours.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotifyRateLimitConfig {
    /// Max notifications per channel per window.
    pub max_per_window: u32,
    /// Window duration in seconds.
    pub window_seconds: u64,
    /// Quiet hours start (UTC hour, 0-23). Set both to 0 to disable.
    pub quiet_hours_start: u8,
    /// Quiet hours end (UTC hour, 0-23).
    pub quiet_hours_end: u8,
}

/// Automatic escalation and batching policy for digest items.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EscalationConfig {
    /// Auto-escalate items older than this many seconds.
    pub auto_escalate_timeout_seconds: u64,
    /// Minimum severity for auto-escalation ("low", "medium", "high", "critical").
    pub auto_escalate_min_severity: String,
    /// Batch window for low-severity notifications (seconds).
    pub batch_window_seconds: u64,
    /// Max items per batch before force-flushing.
    pub max_batch_size: usize,
}

// --- Defaults ---

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: "info".into(),
            audit_dir: "~/.local/share/grith/audit".into(),
            plan_tier: "community".into(),
            update_check: true,
            audit_sync: true,
            profile_update_check: true,
        }
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            default_provider: "ollama".into(),
            ollama: OllamaConfig::default(),
            openai: OpenAiConfig::default(),
            anthropic: AnthropicConfig::default(),
            openrouter: OpenRouterConfig::default(),
            routing: RoutingConfig::default(),
        }
    }
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:11434".into(),
            model: "llama3.1:8b".into(),
        }
    }
}

impl Default for OpenAiConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            api_key_env: "OPENAI_API_KEY".into(),
            model: "gpt-4o".into(),
        }
    }
}

impl Default for AnthropicConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            api_key_env: "ANTHROPIC_API_KEY".into(),
            model: "claude-sonnet-4-20250514".into(),
        }
    }
}

impl Default for OpenRouterConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            api_key_env: "OPENROUTER_API_KEY".into(),
            model: "auto".into(),
        }
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            strategy: "rule".into(),
            simple_threshold: 500,
            complex_keywords: vec![
                "refactor".into(),
                "architect".into(),
                "security review".into(),
            ],
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            auto_allow_threshold: 3.0,
            auto_deny_threshold: 8.0,
            cold_start_calls: 0,
            cold_start_escalation_low: 2.0,
            cold_start_escalation_high: 10.0,
            review_timeout_seconds: 300,
            filters: FilterGroupConfig::default(),
        }
    }
}

impl Default for FilterGroupConfig {
    fn default() -> Self {
        Self {
            reputation: FilterToggle { enabled: true },
            behavioural: FilterToggle { enabled: true },
            taint: FilterToggle { enabled: true },
            rate_limit: FilterToggle { enabled: true },
            egress: FilterToggle { enabled: true },
            session_containment: FilterToggle { enabled: true },
        }
    }
}

impl Default for FilterToggle {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for DigestConfig {
    fn default() -> Self {
        Self {
            interval_active: "30m".into(),
            interval_idle: "24h".into(),
            delivery: "cli".into(),
            max_queue_size: 100,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 3141,
            dashboard_dir: Some("dashboard/dist".into()),
            tls: None,
            rate_limit: RateLimitConfig::default(),
            idle_shutdown_seconds: 30,
        }
    }
}

impl Default for SupervisorCoreConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_profile: String::new(),
            freeze_timeout_seconds: 300,
            max_concurrent_sessions: 4,
            pty_forwarding: true,
            require_sandbox: false,
            platform: SupervisorPlatformConfig::default(),
            noise_reduction: SupervisorNoiseConfig::default(),
            dns_inspection: SupervisorDnsInspectionConfig::default(),
        }
    }
}

impl Default for SupervisorPlatformConfig {
    fn default() -> Self {
        Self {
            linux_mechanism: "ptrace".into(),
            macos_mechanism: "endpoint-security".into(),
            seccomp_pre_filter: false,
        }
    }
}

impl Default for SupervisorNoiseConfig {
    fn default() -> Self {
        Self {
            ignore_read_only: true,
            batch_rapid_reads: true,
            batch_window_ms: 50,
        }
    }
}

impl Default for SupervisorDnsInspectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            upstream_resolver: None,
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            desktop: DesktopNotifyConfig::default(),
            email: EmailNotifyConfig::default(),
            slack: SlackNotifyConfig::default(),
            telegram: TelegramNotifyConfig::default(),
            discord: DiscordNotifyConfig::default(),
            whatsapp: WhatsAppNotifyConfig::default(),
            teams: TeamsNotifyConfig::default(),
            pagerduty: PagerDutyNotifyConfig::default(),
            opsgenie: OpsgenieNotifyConfig::default(),
            webhook: WebhookNotifyConfig::default(),
            routing: NotifyRoutingConfig::default(),
            rate_limits: NotifyRateLimitConfig::default(),
            escalation: EscalationConfig::default(),
        }
    }
}

impl Default for DesktopNotifyConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for EmailNotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_password_env: "GRITH_SMTP_PASSWORD".into(),
            from_address: String::new(),
            to_addresses: Vec::new(),
            starttls: true,
        }
    }
}

impl Default for SlackNotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            bot_token_env: "GRITH_SLACK_BOT_TOKEN".into(),
            channel_id: String::new(),
            webhook_url: String::new(),
        }
    }
}

impl Default for TelegramNotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            bot_token_env: "GRITH_TELEGRAM_BOT_TOKEN".into(),
            chat_id: String::new(),
            authorized_user_ids: Vec::new(),
            polling_interval_secs: 2,
        }
    }
}

impl Default for DiscordNotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            bot_token_env: "GRITH_DISCORD_BOT_TOKEN".into(),
            channel_id: String::new(),
            webhook_url: String::new(),
        }
    }
}

impl Default for WhatsAppNotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            access_token: String::new(),
            access_token_env: "GRITH_WHATSAPP_ACCESS_TOKEN".into(),
            phone_number_id: String::new(),
            recipient_number: String::new(),
        }
    }
}

impl Default for PagerDutyNotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            routing_key: String::new(),
            routing_key_env: "GRITH_PAGERDUTY_ROUTING_KEY".into(),
        }
    }
}

impl Default for OpsgenieNotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: String::new(),
            api_key_env: "GRITH_OPSGENIE_API_KEY".into(),
            eu_endpoint: false,
        }
    }
}

impl Default for WebhookNotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            secret: String::new(),
            secret_env: "GRITH_WEBHOOK_SECRET".into(),
            callback_url: String::new(),
            max_retries: 3,
            headers: Vec::new(),
        }
    }
}

impl Default for NotifyRoutingConfig {
    fn default() -> Self {
        let mut severity_routes = std::collections::HashMap::new();
        severity_routes.insert("low".into(), vec!["websocket".into()]);
        severity_routes.insert("medium".into(), vec!["websocket".into(), "desktop".into()]);
        severity_routes.insert("high".into(), vec!["websocket".into(), "desktop".into()]);
        severity_routes.insert(
            "critical".into(),
            vec!["websocket".into(), "desktop".into()],
        );
        Self {
            severity_routes,
            escalation_channels: vec!["websocket".into(), "desktop".into()],
            filter_overrides: std::collections::HashMap::new(),
        }
    }
}

impl Default for NotifyRateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_window: 60,
            window_seconds: 3600,
            quiet_hours_start: 0,
            quiet_hours_end: 0,
        }
    }
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            auto_escalate_timeout_seconds: 600,
            auto_escalate_min_severity: "high".into(),
            batch_window_seconds: 300,
            max_batch_size: 10,
        }
    }
}

// --- Loading ---

impl GrithConfig {
    /// Load configuration with the standard precedence chain:
    /// env vars (GRITH_*) > explicit config > project .grith/config.toml > user config > required config/default.toml
    pub fn load(config_path: Option<&Path>) -> Result<Self, crate::error::Error> {
        let mut config = load_required_base_config()?;

        // Layer 1: User config (~/.config/grith/config.toml)
        let user_config_path = dirs_path("~/.config/grith/config.toml");
        if user_config_path.exists() {
            let user = Self::from_file(&user_config_path)?;
            config = merge_config(config, user);
        }

        // Layer 2: Project-local config (.grith/config.toml)
        let project_config = PathBuf::from(".grith/config.toml");
        if project_config.exists() {
            let project = Self::from_file(&project_config)?;
            config = merge_config(config, project);
        }

        // Layer 3: Explicit config file (--config flag)
        if let Some(path) = config_path {
            let explicit = Self::from_file(path)?;
            config = merge_config(config, explicit);
        }

        // Layer 4: Environment variable overrides
        config = apply_env_overrides(config);

        Ok(config)
    }

    /// Parse config from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, crate::error::Error> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::error::Error::Config(format!("failed to read {}: {e}", path.display()))
        })?;
        toml::from_str(&content).map_err(|e| {
            crate::error::Error::Config(format!("failed to parse {}: {e}", path.display()))
        })
    }

    /// Serialize config to TOML string.
    pub fn to_toml(&self) -> Result<String, crate::error::Error> {
        toml::to_string_pretty(self)
            .map_err(|e| crate::error::Error::Config(format!("failed to serialize config: {e}")))
    }

    /// Set a dot-separated config key to a new value.
    /// Returns the old value as a string, or an error if the key is unknown.
    pub fn set_value(&mut self, key: &str, value: &str) -> Result<String, crate::error::Error> {
        /// Helper macro to generate the match arms for `set_value()`.
        ///
        /// Supports three field types:
        /// - `str`: String fields (clone old, assign `value.to_string()`)
        /// - `parse`: Parseable fields (`.to_string()` old, `.parse()` new with error)
        /// - `opt_str`: `Option<String>` fields (unwrap old to String, assign `Some(...)`)
        macro_rules! config_set_match {
            (
                $self:ident, $key:ident, $value:ident;
                $( str $str_key:literal => $($str_path:ident).+ ; )*
                $( parse($type_name:literal) $parse_key:literal => $($parse_path:ident).+ ; )*
                $( opt_str $opt_key:literal => $($opt_path:ident).+ ; )*
            ) => {
                match $key {
                    // String fields
                    $( $str_key => {
                        let old = $self.$($str_path).+.clone();
                        $self.$($str_path).+ = $value.to_string();
                        Ok(old)
                    } )*
                    // Parseable fields (bool, u16, u64, usize, f64, etc.)
                    $( $parse_key => {
                        let old = $self.$($parse_path).+.to_string();
                        $self.$($parse_path).+ = $value
                            .parse()
                            .map_err(|_| Error::Config(
                                format!(concat!("invalid ", $type_name, ": {}"), $value)
                            ))?;
                        Ok(old)
                    } )*
                    // Option<String> fields
                    $( $opt_key => {
                        let old = $self.$($opt_path).+.clone().unwrap_or_default();
                        $self.$($opt_path).+ = Some($value.to_string());
                        Ok(old)
                    } )*
                    _ => Err(Error::Config(format!("unknown config key: {}", $key))),
                }
            };
        }

        // Validated field: plan_tier must be one of the allowed values.
        if key == "general.plan_tier" {
            let valid_tiers = ["community", "pro", "enterprise"];
            if !valid_tiers.contains(&value) {
                return Err(Error::Config(format!(
                    "invalid plan_tier '{value}', expected one of: {valid_tiers:?}"
                )));
            }
            let old = self.general.plan_tier.clone();
            self.general.plan_tier = value.to_string();
            return Ok(old);
        }

        config_set_match! {
            self, key, value;

            // --- String fields ---
            str "general.log_level"             => general.log_level;
            str "general.audit_dir"             => general.audit_dir;
            str "llm.default_provider"          => llm.default_provider;
            str "llm.ollama.model"              => llm.ollama.model;
            str "llm.ollama.base_url"           => llm.ollama.base_url;
            str "llm.openai.model"              => llm.openai.model;
            str "llm.anthropic.model"           => llm.anthropic.model;
            str "server.host"                   => server.host;
            str "supervisor.default_profile"    => supervisor.default_profile;
            str "notifications.slack.channel_id"    => notifications.slack.channel_id;
            str "notifications.telegram.chat_id"    => notifications.telegram.chat_id;
            str "notifications.webhook.url"         => notifications.webhook.url;

            // --- Parseable fields ---
            parse("bool")   "general.audit_sync"                => general.audit_sync;
            parse("bool")   "general.update_check"              => general.update_check;
            parse("bool")   "general.profile_update_check"      => general.profile_update_check;
            parse("float")  "proxy.auto_allow_threshold"        => proxy.auto_allow_threshold;
            parse("float")  "proxy.auto_deny_threshold"         => proxy.auto_deny_threshold;
            parse("u64")    "proxy.review_timeout_seconds"      => proxy.review_timeout_seconds;
            parse("bool")   "server.enabled"                    => server.enabled;
            parse("port")   "server.port"                       => server.port;
            parse("bool")   "supervisor.enabled"                => supervisor.enabled;
            parse("u64")    "supervisor.freeze_timeout_seconds" => supervisor.freeze_timeout_seconds;
            parse("usize")  "supervisor.max_concurrent_sessions" => supervisor.max_concurrent_sessions;
            parse("bool")   "supervisor.pty_forwarding"         => supervisor.pty_forwarding;
            parse("bool")   "supervisor.dns_inspection.enabled" => supervisor.dns_inspection.enabled;
            parse("bool")   "notifications.enabled"             => notifications.enabled;
            parse("bool")   "notifications.desktop.enabled"     => notifications.desktop.enabled;
            parse("bool")   "notifications.slack.enabled"       => notifications.slack.enabled;
            parse("bool")   "notifications.telegram.enabled"    => notifications.telegram.enabled;
            parse("u64")    "notifications.telegram.polling_interval_secs" => notifications.telegram.polling_interval_secs;
            parse("bool")   "notifications.discord.enabled"     => notifications.discord.enabled;
            parse("bool")   "notifications.email.enabled"       => notifications.email.enabled;
            parse("bool")   "notifications.webhook.enabled"     => notifications.webhook.enabled;
            parse("bool")   "notifications.pagerduty.enabled"   => notifications.pagerduty.enabled;
            parse("bool")   "notifications.opsgenie.enabled"    => notifications.opsgenie.enabled;
            parse("bool")   "notifications.teams.enabled"       => notifications.teams.enabled;
            parse("bool")   "notifications.whatsapp.enabled"    => notifications.whatsapp.enabled;

            // --- Option<String> fields ---
            opt_str "server.dashboard_dir"      => server.dashboard_dir;
            opt_str "supervisor.dns_inspection.upstream_resolver" => supervisor.dns_inspection.upstream_resolver;
        }
    }

    /// Validate the configuration for common issues.
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();

        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.general.log_level.as_str()) {
            issues.push(format!(
                "invalid log_level '{}', expected one of: {valid_levels:?}",
                self.general.log_level
            ));
        }

        let valid_providers = ["ollama", "openai", "anthropic", "openrouter"];
        if !valid_providers.contains(&self.llm.default_provider.as_str()) {
            issues.push(format!(
                "invalid llm.default_provider '{}', expected one of: {valid_providers:?}",
                self.llm.default_provider
            ));
        }

        if self.proxy.auto_allow_threshold >= self.proxy.auto_deny_threshold {
            issues.push(format!(
                "proxy.auto_allow_threshold ({}) must be less than auto_deny_threshold ({})",
                self.proxy.auto_allow_threshold, self.proxy.auto_deny_threshold
            ));
        }

        if self.proxy.auto_allow_threshold < 0.0 || self.proxy.auto_deny_threshold > 10.0 {
            issues.push("proxy thresholds must be in range [0.0, 10.0]".to_string());
        }

        if self.server.port == 0 {
            issues.push("server.port must be > 0".to_string());
        }

        if self.server.rate_limit.enabled {
            if self.server.rate_limit.general_rps == 0 {
                issues.push("server.rate_limit.general_rps must be > 0 when enabled".to_string());
            }
            if self.server.rate_limit.write_rps == 0 {
                issues.push("server.rate_limit.write_rps must be > 0 when enabled".to_string());
            }
            if self.server.rate_limit.proxy_test_rps == 0 {
                issues
                    .push("server.rate_limit.proxy_test_rps must be > 0 when enabled".to_string());
            }
            if self.server.rate_limit.ipc_rps == 0 {
                issues.push("server.rate_limit.ipc_rps must be > 0 when enabled".to_string());
            }
        }

        if self.supervisor.default_profile.trim().is_empty() {
            issues.push(
                "supervisor.default_profile must be set in TOML or via GRITH_SUPERVISOR_PROFILE"
                    .to_string(),
            );
        }

        issues
    }

    /// Write the user config file.
    pub fn save_user_config(&self) -> Result<PathBuf, crate::error::Error> {
        let path = dirs_path("~/.config/grith/config.toml");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let toml_str = self.to_toml()?;
        std::fs::write(&path, toml_str)?;
        Ok(path)
    }
}

use crate::error::Error;

/// Expand ~ to home directory.
fn dirs_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn load_required_base_config() -> Result<GrithConfig, crate::error::Error> {
    let candidates = [
        PathBuf::from("config/default.toml"),
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../")
            .join("config/default.toml"),
    ];

    let mut last_error = String::new();
    for path in &candidates {
        if !path.exists() {
            last_error = format!("{} does not exist", path.display());
            continue;
        }

        match GrithConfig::from_file(path) {
            Ok(config) => return Ok(config),
            Err(e) => last_error = e.to_string(),
        }
    }

    // Final fallback: parse the embedded default.toml bundled into the
    // binary at build time. This is the normal path for users who
    // installed via `curl https://grith.ai/install | sh`.
    if let Some(content) = embedded_default_toml() {
        return toml::from_str(content).map_err(|e| {
            crate::error::Error::Config(format!(
                "failed to parse embedded config/default.toml: {e}"
            ))
        });
    }

    Err(crate::error::Error::Config(format!(
        "required config/default.toml unavailable: {last_error}"
    )))
}

/// Returns the bytes of `config/default.toml` baked into the binary.
/// Used as a fallback when no disk copy is present. Kept colocated
/// here so the lookup logic stays next to the disk-candidate logic.
fn embedded_default_toml() -> Option<&'static str> {
    static EMBEDDED: include_dir::Dir<'_> =
        include_dir::include_dir!("$CARGO_MANIFEST_DIR/../../config");
    EMBEDDED
        .get_file("default.toml")
        .and_then(|f| f.contents_utf8())
}

/// Merge two configs via TOML-level deep merge.
/// Values from `overlay` take precedence, but unset fields
/// (absent from the overlay TOML) keep their base values.
fn merge_config(base: GrithConfig, overlay: GrithConfig) -> GrithConfig {
    // Serialize both to TOML Value, deep merge, then deserialize back.
    let base_val = toml::Value::try_from(&base).unwrap_or(toml::Value::Table(Default::default()));
    let overlay_val =
        toml::Value::try_from(&overlay).unwrap_or(toml::Value::Table(Default::default()));
    let merged = deep_merge_toml(base_val, overlay_val);
    merged.try_into().unwrap_or(base)
}

/// Recursively merge two TOML values. Tables are merged field-by-field;
/// other types are replaced by the overlay.
fn deep_merge_toml(base: toml::Value, overlay: toml::Value) -> toml::Value {
    match (base, overlay) {
        (toml::Value::Table(mut base_map), toml::Value::Table(overlay_map)) => {
            for (key, overlay_val) in overlay_map {
                let merged_val = if let Some(base_val) = base_map.remove(&key) {
                    deep_merge_toml(base_val, overlay_val)
                } else {
                    overlay_val
                };
                base_map.insert(key, merged_val);
            }
            toml::Value::Table(base_map)
        }
        (_base, overlay) => overlay,
    }
}

/// Apply a string environment variable override.
macro_rules! env_str {
    ($config:expr, $env:literal => $($path:ident).+) => {
        if let Ok(v) = std::env::var($env) {
            $config.$($path).+ = v;
        }
    };
}

/// Apply a parsed (bool/integer/float) environment variable override.
macro_rules! env_parse {
    ($config:expr, $env:literal => $($path:ident).+) => {
        if let Ok(v) = std::env::var($env) {
            if let Ok(p) = v.parse() {
                $config.$($path).+ = p;
            }
        }
    };
}

/// Resolve a credential from the configured environment variable name, but
/// only if the field is currently empty (explicit config takes precedence).
macro_rules! env_credential {
    ($config:expr, $($field:ident).+ , $($env_field:ident).+) => {
        if $config.$($field).+.is_empty() {
            if let Ok(v) = std::env::var(&$config.$($env_field).+) {
                $config.$($field).+ = v;
            }
        }
    };
}

/// Apply GRITH_* environment variable overrides.
fn apply_env_overrides(mut config: GrithConfig) -> GrithConfig {
    // Direct string overrides
    env_str!(config, "GRITH_LOG_LEVEL"         => general.log_level);
    env_str!(config, "GRITH_AUDIT_DIR"         => general.audit_dir);
    env_str!(config, "GRITH_PLAN_TIER"         => general.plan_tier);
    env_str!(config, "GRITH_LLM_PROVIDER"      => llm.default_provider);
    env_str!(config, "GRITH_SERVER_HOST"        => server.host);
    env_str!(config, "GRITH_SUPERVISOR_PROFILE" => supervisor.default_profile);

    // Parsed overrides
    env_parse!(config, "GRITH_AUDIT_SYNC"                  => general.audit_sync);
    env_parse!(config, "GRITH_PROXY_ALLOW_THRESHOLD"         => proxy.auto_allow_threshold);
    env_parse!(config, "GRITH_PROXY_DENY_THRESHOLD"          => proxy.auto_deny_threshold);
    env_parse!(config, "GRITH_PROXY_REVIEW_TIMEOUT"          => proxy.review_timeout_seconds);
    env_parse!(config, "GRITH_SERVER_PORT"                   => server.port);
    env_parse!(config, "GRITH_SERVER_ENABLED"                => server.enabled);
    env_parse!(config, "GRITH_SUPERVISOR_ENABLED"            => supervisor.enabled);
    env_parse!(config, "GRITH_SUPERVISOR_TIMEOUT"            => supervisor.freeze_timeout_seconds);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_INSPECTION_ENABLED" => supervisor.dns_inspection.enabled);
    env_parse!(config, "GRITH_NOTIFICATIONS_ENABLED"         => notifications.enabled);
    env_parse!(config, "GRITH_NOTIFICATIONS_DESKTOP_ENABLED" => notifications.desktop.enabled);
    env_parse!(config, "GRITH_NOTIFICATIONS_SLACK_ENABLED"   => notifications.slack.enabled);

    if let Ok(v) = std::env::var("GRITH_SUPERVISOR_DNS_UPSTREAM") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            config.supervisor.dns_inspection.upstream_resolver = Some(trimmed.to_string());
        }
    }

    // Credential fallbacks (only applied when the field is empty)
    env_credential!(
        config,
        notifications.slack.bot_token,
        notifications.slack.bot_token_env
    );
    env_credential!(
        config,
        notifications.telegram.bot_token,
        notifications.telegram.bot_token_env
    );
    env_credential!(
        config,
        notifications.discord.bot_token,
        notifications.discord.bot_token_env
    );
    env_credential!(
        config,
        notifications.email.smtp_password,
        notifications.email.smtp_password_env
    );
    env_credential!(
        config,
        notifications.pagerduty.routing_key,
        notifications.pagerduty.routing_key_env
    );
    env_credential!(
        config,
        notifications.opsgenie.api_key,
        notifications.opsgenie.api_key_env
    );
    env_credential!(
        config,
        notifications.webhook.secret,
        notifications.webhook.secret_env
    );
    env_credential!(
        config,
        notifications.whatsapp.access_token,
        notifications.whatsapp.access_token_env
    );

    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_config() {
        let config = GrithConfig::default();
        assert_eq!(config.general.log_level, "info");
        assert!(config.general.audit_sync);
        assert_eq!(config.proxy.auto_allow_threshold, 3.0);
        assert_eq!(config.proxy.auto_deny_threshold, 8.0);
        assert_eq!(config.server.port, 3141);
        assert_eq!(config.llm.default_provider, "ollama");
    }

    #[test]
    fn test_from_toml_string() {
        let toml_str = r#"
[general]
log_level = "debug"

[proxy]
auto_allow_threshold = 2.0

[server]
port = 9999
"#;
        let config: GrithConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.general.log_level, "debug");
        assert_eq!(config.proxy.auto_allow_threshold, 2.0);
        assert_eq!(config.server.port, 9999);
        // Unset fields use defaults
        assert_eq!(config.proxy.auto_deny_threshold, 8.0);
        assert_eq!(config.llm.default_provider, "ollama");
    }

    #[test]
    fn test_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
[general]
log_level = "trace"

[server]
enabled = false
"#
        )
        .unwrap();

        let config = GrithConfig::from_file(&path).unwrap();
        assert_eq!(config.general.log_level, "trace");
        assert!(!config.server.enabled);
    }

    #[test]
    fn test_env_overrides() {
        std::env::set_var("GRITH_LOG_LEVEL", "warn");
        std::env::set_var("GRITH_AUDIT_SYNC", "false");
        std::env::set_var("GRITH_SERVER_PORT", "5555");

        let config = apply_env_overrides(GrithConfig::default());
        assert_eq!(config.general.log_level, "warn");
        assert!(!config.general.audit_sync);
        assert_eq!(config.server.port, 5555);

        std::env::remove_var("GRITH_LOG_LEVEL");
        std::env::remove_var("GRITH_AUDIT_SYNC");
        std::env::remove_var("GRITH_SERVER_PORT");
    }

    #[test]
    fn test_to_toml_roundtrip() {
        let config = GrithConfig::default();
        let toml_str = config.to_toml().unwrap();
        let parsed: GrithConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.server.port, config.server.port);
        assert_eq!(
            parsed.proxy.auto_deny_threshold,
            config.proxy.auto_deny_threshold
        );
    }

    #[test]
    fn test_deep_merge() {
        let mut base = GrithConfig::default();
        base.general.log_level = "info".to_string();
        base.server.port = 3141;
        base.proxy.auto_allow_threshold = 3.0;

        let mut overlay = GrithConfig::default();
        overlay.general.log_level = "debug".to_string();
        // overlay keeps default port, should still preserve overlay's value

        let merged = merge_config(base, overlay);
        assert_eq!(merged.general.log_level, "debug");
        assert_eq!(merged.server.port, 3141);
        assert_eq!(merged.proxy.auto_allow_threshold, 3.0);
    }

    #[test]
    fn test_set_value() {
        let mut config = GrithConfig::default();

        let old = config.set_value("general.log_level", "debug").unwrap();
        assert_eq!(old, "info");
        assert_eq!(config.general.log_level, "debug");

        let old = config.set_value("general.audit_sync", "false").unwrap();
        assert_eq!(old, "true");
        assert!(!config.general.audit_sync);

        let old = config.set_value("server.port", "9999").unwrap();
        assert_eq!(old, "3141");
        assert_eq!(config.server.port, 9999);

        let old = config
            .set_value("proxy.auto_allow_threshold", "2.5")
            .unwrap();
        assert_eq!(old, "3");
        assert_eq!(config.proxy.auto_allow_threshold, 2.5);

        let old = config.set_value("server.enabled", "false").unwrap();
        assert_eq!(old, "true");
        assert!(!config.server.enabled);
    }

    #[test]
    fn test_set_value_unknown_key() {
        let mut config = GrithConfig::default();
        assert!(config.set_value("unknown.key", "value").is_err());
    }

    #[test]
    fn test_set_value_invalid_type() {
        let mut config = GrithConfig::default();
        assert!(config.set_value("server.port", "not_a_number").is_err());
        assert!(config
            .set_value("proxy.auto_allow_threshold", "bad")
            .is_err());
    }

    #[test]
    fn test_validate_default() {
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        let issues = config.validate();
        assert!(
            issues.is_empty(),
            "default config should be valid: {issues:?}"
        );
    }

    #[test]
    fn test_validate_bad_log_level() {
        let mut config = GrithConfig::default();
        config.general.log_level = "verbose".to_string();
        let issues = config.validate();
        assert!(issues.iter().any(|i| i.contains("log_level")));
    }

    #[test]
    fn test_validate_bad_provider() {
        let mut config = GrithConfig::default();
        config.llm.default_provider = "gemini".to_string();
        let issues = config.validate();
        assert!(issues.iter().any(|i| i.contains("default_provider")));
    }

    #[test]
    fn test_filter_group_config_defaults() {
        let config = GrithConfig::default();
        assert!(config.proxy.filters.reputation.enabled);
        assert!(config.proxy.filters.behavioural.enabled);
        assert!(config.proxy.filters.taint.enabled);
        assert!(config.proxy.filters.rate_limit.enabled);
    }

    #[test]
    fn test_filter_group_config_from_toml() {
        let toml_str = r#"
[proxy.filters.reputation]
enabled = false

[proxy.filters.behavioural]
enabled = true
"#;
        let config: GrithConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.proxy.filters.reputation.enabled);
        assert!(config.proxy.filters.behavioural.enabled);
        // Unset filters use default (true)
        assert!(config.proxy.filters.taint.enabled);
    }

    #[test]
    fn test_validate_bad_thresholds() {
        let mut config = GrithConfig::default();
        config.proxy.auto_allow_threshold = 9.0;
        config.proxy.auto_deny_threshold = 5.0;
        let issues = config.validate();
        assert!(issues.iter().any(|i| i.contains("threshold")));
    }

    #[test]
    fn test_validate_rejects_zero_server_rate_limits_when_enabled() {
        let mut config = GrithConfig::default();
        config.server.rate_limit.enabled = true;
        config.server.rate_limit.general_rps = 0;
        config.server.rate_limit.write_rps = 0;
        config.server.rate_limit.proxy_test_rps = 0;
        config.server.rate_limit.ipc_rps = 0;

        let issues = config.validate();
        assert!(issues.iter().any(|i| i.contains("general_rps")));
        assert!(issues.iter().any(|i| i.contains("write_rps")));
        assert!(issues.iter().any(|i| i.contains("proxy_test_rps")));
        assert!(issues.iter().any(|i| i.contains("ipc_rps")));
    }

    #[test]
    fn test_validate_allows_zero_server_rate_limits_when_disabled() {
        let mut config = GrithConfig::default();
        config.server.rate_limit.enabled = false;
        config.server.rate_limit.general_rps = 0;
        config.server.rate_limit.write_rps = 0;
        config.server.rate_limit.proxy_test_rps = 0;
        config.server.rate_limit.ipc_rps = 0;

        let issues = config.validate();
        assert!(!issues.iter().any(|i| i.contains("server.rate_limit")));
    }
}
