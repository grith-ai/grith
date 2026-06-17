// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Configuration types for the grith-supervisor crate.
//!
//! These structs are deserialized from the `[supervisor]` section of the grith
//! TOML configuration file.
//!
//! # Example TOML
//!
//! ```toml
//! [supervisor]
//! enabled = true
//! default_profile = "generic"
//! freeze_timeout_seconds = 300
//! max_concurrent_sessions = 4
//! pty_forwarding = true
//!
//! [supervisor.platform]
//! linux_mechanism = "ptrace"
//! macos_mechanism = "endpoint-security"
//! seccomp_pre_filter = true
//!
//! [supervisor.noise_reduction]
//! ignore_read_only = true
//! batch_rapid_reads = true
//! batch_window_ms = 50
//! ```

use serde::{Deserialize, Serialize};

/// Top-level supervisor configuration.
///
/// Lives under the `[supervisor]` key in the grith TOML config.
// Each bool is an independent operator knob (enabled / require_sandbox /
// pty_forwarding / pty_ownership_enforce); collapsing them would hide that.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SupervisorConfig {
    /// Whether the supervisor subsystem is enabled at all.
    pub enabled: bool,

    /// Default tool profile to apply when no specific profile is matched.
    /// Profiles define per-tool noise-reduction and allowlist hints.
    pub default_profile: String,

    /// How long (in seconds) a frozen process waits for human approval
    /// before being automatically denied and killed.
    pub freeze_timeout_seconds: u64,

    /// Maximum number of concurrently supervised sessions. Attempting to
    /// start a new session beyond this limit returns
    /// [`Error::SessionLimitReached`](crate::error::Error::SessionLimitReached).
    pub max_concurrent_sessions: usize,

    /// Whether to allocate a PTY and forward stdin/stdout/stderr so the
    /// supervised tool behaves as if running in an interactive terminal.
    pub pty_forwarding: bool,

    /// Platform-specific configuration knobs.
    pub platform: PlatformConfig,

    /// Noise-reduction settings to avoid flooding the proxy with
    /// low-value events.
    pub noise_reduction: NoiseConfig,

    /// DNS inspection proxy settings.
    pub dns_inspection: DnsInspectionConfig,

    /// Refuse to launch a supervised process if the platform cannot provide
    /// full per-syscall interception.
    ///
    /// When `true`, [`grith exec`](crate) checks [`platform_capability`] before
    /// spawning the tool. Startup is aborted if the result is
    /// [`Degraded`](crate::platform::PlatformCapability::Degraded) (macOS
    /// lifecycle-only) or
    /// [`Unavailable`](crate::platform::PlatformCapability::Unavailable)
    /// (ptrace blocked or unsupported OS), with a clear error message
    /// explaining what to fix.
    ///
    /// Defaults to `false` so existing deployments are unaffected. Set to
    /// `true` in any environment where silently running without enforcement
    /// is unacceptable (e.g., a ClawProtect or CI hardening deployment).
    ///
    /// # Example
    ///
    /// ```toml
    /// [supervisor]
    /// require_sandbox = true
    /// ```
    pub require_sandbox: bool,

    /// Linux attach mechanism (`traceme` | `seize`). See [`AttachMode`].
    /// Defaults to `Traceme`; `Seize` is scaffolded but not yet implemented.
    pub attach_mode: AttachMode,

    /// How to handle QUEUE-range proxy decisions (score between allow and deny
    /// thresholds) in interactive PTY sessions.
    ///
    /// - `"freeze"` (default): Freeze the process tree and prompt the user
    ///   for approval via the terminal dialog. This is the most secure option
    ///   but interrupts the supervised tool's TUI.
    ///
    /// - `"log"`: Allow the syscall to proceed, log it as an informational
    ///   digest item for post-session review. The tool runs uninterrupted.
    ///   Use this when supervising interactive TUI tools (Claude Code, etc.)
    ///   where freezing would destroy the user experience.
    pub interactive_queue_action: InteractiveQueueAction,

    /// Optional path to a file where every syscall request and its decision
    /// are logged for post-session review.
    #[serde(skip)]
    pub syscall_log_file: Option<std::path::PathBuf>,

    /// Optional path to a JSONL file where raw forensics trace events are
    /// emitted before filtering, plus later decision-stage records.
    #[serde(skip)]
    pub trace_syscalls_jsonl_file: Option<std::path::PathBuf>,

    /// Reputation system configuration (injected at runtime, not from TOML).
    #[serde(skip)]
    pub reputation_config: grith_proxy::reputation::ReputationConfig,

    /// PR 6 Phase F: per-category coverage flags for the staged
    /// rollout of syscall-coverage expansion. See [`CoverageConfig`].
    pub coverage: CoverageConfig,

    /// Audit-completeness tier. Controls whether session-allowed,
    /// routine-I/O, and noise-path short-circuits emit compact audit
    /// rows. Mirrors `grith_core::config::AuditCompleteness` to avoid
    /// a supervisor → core dependency cycle.
    #[serde(default)]
    pub audit_completeness: AuditCompletenessLevel,

    /// H2 Option 1 (IPC-delegated authority): enforce PTY ownership. When
    /// `false` (default), writes to a `/dev/pts/N` that is **not** the
    /// supervised tool's own controlling terminal are detected and
    /// forensically logged (`event = "foreign_pts_write"`) but still allowed
    /// — audit-only, to measure the false-positive budget. When `true`, such
    /// writes are denied (the `echo cmd > /dev/pts/<sibling-pane>` injection
    /// vector). Default off until the FP budget is measured.
    #[serde(default)]
    pub pty_ownership_enforce: bool,
}

/// Linux attach mechanism (supervisor-local mirror of
/// `grith_core::config::AttachMode`).
///
/// Migration knob for the `PTRACE_SEIZE` work. `Traceme` is the shipped
/// path; `Seize` is being built behind the flag. The spawn path consults
/// this and, while `Seize` is unimplemented, fails closed with a clear
/// error rather than silently using `Traceme`.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AttachMode {
    /// `fork` + child `PTRACE_TRACEME` + `execve` (current, shipped).
    #[default]
    Traceme,
    /// Parent `PTRACE_SEIZE` after a pre-exec barrier (work in progress).
    Seize,
}

/// Audit completeness tier (supervisor-local mirror of
/// `grith_core::config::AuditCompleteness`).
///
/// Ordered from least to most data. The supervisor consults this on
/// every short-circuit path to decide whether to emit a compact audit
/// row. The full proxy-evaluation path always writes a full row.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuditCompletenessLevel {
    /// Only proxy decisions are audited. Default historical behaviour
    /// before the compact-record work.
    Decisions,
    /// + every routine `ProcessSpawn` short-circuit.
    #[default]
    Spawns,
    /// + every routine file-I/O short-circuit.
    Io,
    /// + every noise-path short-circuit.
    All,
}

impl AuditCompletenessLevel {
    pub fn records_routine_spawns(&self) -> bool {
        matches!(self, Self::Spawns | Self::Io | Self::All)
    }
    pub fn records_routine_io(&self) -> bool {
        matches!(self, Self::Io | Self::All)
    }
    pub fn records_noise_paths(&self) -> bool {
        matches!(self, Self::All)
    }
}

/// PR 6 Phase F: per-category coverage feature flags.
///
/// Mirrors `grith_core::config::CoverageConfig` so the supervisor
/// owns its own type without depending on `grith-core` (avoids the
/// dependency cycle that would otherwise force core → supervisor).
///
/// Defaults: categories 1 and 4 ON (extreme ops with no compatibility
/// risk); categories 2 and 3 OFF until operator calibration.
///
/// The four bools are intentional — each represents an independent
/// staged-rollout knob with its own threat model. Refactoring to a
/// state machine or bitflag enum would hide that independence.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoverageConfig {
    /// Category 1: hard-deny kernel-module load/unload + kexec.
    pub category1_hard_deny: bool,
    /// Category 2: proxy-evaluated chown / mount / ptrace family.
    pub category2_proxy: bool,
    /// Category 3: namespace primitives (unshare/setns) + namespace_users
    /// carveout.
    pub category3_namespace: bool,
    /// Category 4: hard-deny arch-privileged ops (sethostname / iopl /
    /// swapon / reboot, etc.).
    pub category4_arch_priv: bool,
}

impl Default for CoverageConfig {
    fn default() -> Self {
        Self {
            category1_hard_deny: true,
            category2_proxy: false,
            category3_namespace: false,
            category4_arch_priv: true,
        }
    }
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_profile: String::new(),
            freeze_timeout_seconds: 300,
            max_concurrent_sessions: 4,
            pty_forwarding: true,
            platform: PlatformConfig::default(),
            noise_reduction: NoiseConfig::default(),
            require_sandbox: false,
            attach_mode: AttachMode::default(),
            dns_inspection: DnsInspectionConfig::default(),
            interactive_queue_action: InteractiveQueueAction::default(),
            syscall_log_file: None,
            trace_syscalls_jsonl_file: None,
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            coverage: CoverageConfig::default(),
            audit_completeness: AuditCompletenessLevel::default(),
            pty_ownership_enforce: false,
        }
    }
}

impl SupervisorConfig {
    /// Validate config values, rejecting unsupported options at startup
    /// rather than silently ignoring them at runtime.
    ///
    /// Returns `Ok(())` if the configuration is valid, or `Err(message)`
    /// describing the unsupported or invalid option.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.default_profile.trim().is_empty() {
            return Err(
                "supervisor.default_profile must be provided by TOML or environment override"
                    .into(),
            );
        }

        if self.platform.seccomp_pre_filter {
            return Err(
                "supervisor.platform.seccomp_pre_filter = true is not yet supported. \
                 seccomp-BPF pre-filtering has not been implemented; set to false or omit. \
                 See work/todos/seccomp-pre-filter.md for the roadmap."
                    .into(),
            );
        }

        match self.platform.linux_mechanism.as_str() {
            "ptrace" => {} // supported
            "ebpf" => {
                return Err(
                    "supervisor.platform.linux_mechanism = \"ebpf\" is not yet supported. \
                     eBPF-based interception has not been implemented; use \"ptrace\" instead. \
                     See work/todos/ebpf-interception.md for the roadmap."
                        .into(),
                );
            }
            other => {
                return Err(format!(
                    "supervisor.platform.linux_mechanism = \"{other}\" is not a recognized \
                     mechanism. Supported values: \"ptrace\"."
                ));
            }
        }

        Ok(())
    }
}

/// Platform-specific mechanism configuration.
///
/// Lives under `[supervisor.platform]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformConfig {
    /// Interception mechanism to use on Linux. Currently only `"ptrace"` is
    /// supported; future options may include `"ebpf"`.
    pub linux_mechanism: String,

    /// Interception mechanism to use on macOS. Currently only
    /// `"endpoint-security"` is supported.
    pub macos_mechanism: String,

    /// Whether to install a seccomp-BPF pre-filter on Linux to reduce
    /// ptrace overhead by only trapping security-relevant syscalls.
    pub seccomp_pre_filter: bool,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            linux_mechanism: "ptrace".into(),
            macos_mechanism: "endpoint-security".into(),
            // Default to false — seccomp-BPF pre-filtering is not yet implemented.
            // See work/todos/seccomp-pre-filter.md for the roadmap.
            seccomp_pre_filter: false,
        }
    }
}

/// Noise-reduction settings.
///
/// Supervised processes often generate thousands of low-value syscalls per
/// second (e.g., repeated reads from the same file). These settings let the
/// supervisor elide or batch events before sending them to the proxy.
///
/// Lives under `[supervisor.noise_reduction]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NoiseConfig {
    /// If `true`, pure read-only file opens (`O_RDONLY`) are allowed without
    /// consulting the proxy, unless they match a sensitive-path pattern.
    pub ignore_read_only: bool,

    /// If `true`, consecutive read events to the same fd within
    /// `batch_window_ms` are coalesced into a single proxy evaluation.
    pub batch_rapid_reads: bool,

    /// Time window in milliseconds for batching rapid reads.
    pub batch_window_ms: u64,
}

impl Default for NoiseConfig {
    fn default() -> Self {
        Self {
            ignore_read_only: true,
            batch_rapid_reads: true,
            batch_window_ms: 50,
        }
    }
}

/// How to handle QUEUE-range decisions in interactive PTY sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum InteractiveQueueAction {
    /// Freeze the process tree and show a blocking approval dialog.
    #[default]
    Freeze,
    /// Allow the syscall, log it as informational for post-session review.
    Log,
}

/// DNS inspection proxy configuration.
///
/// When enabled, the supervisor runs a local DNS proxy that intercepts
/// port-53 traffic from supervised processes, extracts domain names from
/// DNS wire format, and evaluates them through the security proxy before
/// forwarding to the upstream resolver.
///
/// Lives under `[supervisor.dns_inspection]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsInspectionConfig {
    /// Whether DNS inspection is enabled.
    pub enabled: bool,

    /// Override the auto-discovered upstream DNS resolver.
    /// Format: `"IP:PORT"` or just `"IP"` (port defaults to 53).
    /// If not set, the resolver is discovered from `/etc/resolv.conf`.
    pub upstream_resolver: Option<String>,
}

impl Default for DnsInspectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            upstream_resolver: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Default values --

    #[test]
    fn supervisor_config_defaults() {
        let cfg = SupervisorConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.default_profile.is_empty());
        assert_eq!(cfg.freeze_timeout_seconds, 300);
        assert_eq!(cfg.max_concurrent_sessions, 4);
        assert!(cfg.pty_forwarding);
        // require_sandbox defaults to false so existing deployments are unaffected.
        assert!(!cfg.require_sandbox);
    }

    #[test]
    fn platform_config_defaults() {
        let cfg = PlatformConfig::default();
        assert_eq!(cfg.linux_mechanism, "ptrace");
        assert_eq!(cfg.macos_mechanism, "endpoint-security");
        assert!(!cfg.seccomp_pre_filter);
    }

    #[test]
    fn noise_config_defaults() {
        let cfg = NoiseConfig::default();
        assert!(cfg.ignore_read_only);
        assert!(cfg.batch_rapid_reads);
        assert_eq!(cfg.batch_window_ms, 50);
    }

    // -- TOML deserialization --

    #[test]
    fn deserialize_full_toml() {
        let toml_str = r#"
            enabled = false
            default_profile = "claude-code"
            freeze_timeout_seconds = 60
            max_concurrent_sessions = 8
            pty_forwarding = false

            [platform]
            linux_mechanism = "ebpf"
            macos_mechanism = "endpoint-security"
            seccomp_pre_filter = false

            [noise_reduction]
            ignore_read_only = true
            batch_rapid_reads = false
            batch_window_ms = 100
        "#;
        let cfg: SupervisorConfig = toml::from_str(toml_str).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.default_profile, "claude-code");
        assert_eq!(cfg.freeze_timeout_seconds, 60);
        assert_eq!(cfg.max_concurrent_sessions, 8);
        assert!(!cfg.pty_forwarding);
        assert_eq!(cfg.platform.linux_mechanism, "ebpf");
        assert!(!cfg.platform.seccomp_pre_filter);
        assert!(cfg.noise_reduction.ignore_read_only);
        assert!(!cfg.noise_reduction.batch_rapid_reads);
        assert_eq!(cfg.noise_reduction.batch_window_ms, 100);
    }

    #[test]
    fn deserialize_empty_toml_uses_defaults() {
        let cfg: SupervisorConfig = toml::from_str("").unwrap();
        assert!(cfg.enabled);
        assert!(cfg.default_profile.is_empty());
        assert_eq!(cfg.freeze_timeout_seconds, 300);
        assert_eq!(cfg.max_concurrent_sessions, 4);
        assert!(cfg.pty_forwarding);
        assert_eq!(cfg.platform.linux_mechanism, "ptrace");
        assert!(!cfg.platform.seccomp_pre_filter);
        assert!(cfg.noise_reduction.ignore_read_only);
        assert!(cfg.noise_reduction.batch_rapid_reads);
        assert_eq!(cfg.noise_reduction.batch_window_ms, 50);
    }

    #[test]
    fn deserialize_partial_toml_fills_defaults() {
        let toml_str = r#"
            enabled = false
            max_concurrent_sessions = 2
        "#;
        let cfg: SupervisorConfig = toml::from_str(toml_str).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.max_concurrent_sessions, 2);
        // Remaining fields should be defaults.
        assert!(cfg.default_profile.is_empty());
        assert_eq!(cfg.freeze_timeout_seconds, 300);
        assert!(cfg.pty_forwarding);
    }

    // -- TOML serialization round-trip --

    #[test]
    fn serde_roundtrip_toml() {
        let original = SupervisorConfig {
            enabled: false,
            default_profile: "aider".into(),
            freeze_timeout_seconds: 120,
            max_concurrent_sessions: 2,
            pty_forwarding: false,
            require_sandbox: false,
            attach_mode: AttachMode::Seize,
            platform: PlatformConfig {
                linux_mechanism: "ebpf".into(),
                macos_mechanism: "endpoint-security".into(),
                seccomp_pre_filter: false,
            },
            noise_reduction: NoiseConfig {
                ignore_read_only: true,
                batch_rapid_reads: false,
                batch_window_ms: 200,
            },
            dns_inspection: DnsInspectionConfig::default(),
            interactive_queue_action: InteractiveQueueAction::Log,
            syscall_log_file: None,
            trace_syscalls_jsonl_file: None,
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            coverage: CoverageConfig::default(),
            audit_completeness: AuditCompletenessLevel::default(),
            pty_ownership_enforce: false,
        };
        let toml_str = toml::to_string(&original).unwrap();
        let parsed: SupervisorConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.enabled, original.enabled);
        assert_eq!(parsed.default_profile, original.default_profile);
        assert_eq!(
            parsed.freeze_timeout_seconds,
            original.freeze_timeout_seconds
        );
        assert_eq!(
            parsed.max_concurrent_sessions,
            original.max_concurrent_sessions
        );
        assert_eq!(parsed.pty_forwarding, original.pty_forwarding);
        assert_eq!(
            parsed.platform.linux_mechanism,
            original.platform.linux_mechanism
        );
        assert_eq!(
            parsed.platform.seccomp_pre_filter,
            original.platform.seccomp_pre_filter
        );
        assert_eq!(
            parsed.noise_reduction.ignore_read_only,
            original.noise_reduction.ignore_read_only
        );
        assert_eq!(
            parsed.noise_reduction.batch_rapid_reads,
            original.noise_reduction.batch_rapid_reads
        );
        assert_eq!(
            parsed.noise_reduction.batch_window_ms,
            original.noise_reduction.batch_window_ms
        );
    }

    // -- JSON serialization round-trip (for API transport) --

    #[test]
    fn serde_roundtrip_json() {
        let original = SupervisorConfig::default();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: SupervisorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enabled, original.enabled);
        assert_eq!(parsed.default_profile, original.default_profile);
        assert_eq!(
            parsed.max_concurrent_sessions,
            original.max_concurrent_sessions
        );
    }

    // -- Clone --

    #[test]
    fn config_is_clone() {
        let cfg = SupervisorConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cloned.enabled, cfg.enabled);
        assert_eq!(cloned.default_profile, cfg.default_profile);
    }

    // -- Debug --

    #[test]
    fn config_is_debug() {
        let cfg = SupervisorConfig::default();
        let debug = format!("{cfg:?}");
        assert!(debug.contains("SupervisorConfig"));
        assert!(debug.contains("default_profile"));
    }

    // -- Validation --

    #[test]
    fn validate_default_config_requires_profile() {
        let cfg = SupervisorConfig::default();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_seccomp_pre_filter() {
        let mut cfg = SupervisorConfig::default();
        cfg.default_profile = "generic".into();
        cfg.platform.seccomp_pre_filter = true;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("seccomp_pre_filter"));
    }

    #[test]
    fn validate_rejects_ebpf_mechanism() {
        let mut cfg = SupervisorConfig::default();
        cfg.default_profile = "generic".into();
        cfg.platform.seccomp_pre_filter = false;
        cfg.platform.linux_mechanism = "ebpf".into();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("ebpf"));
    }

    #[test]
    fn validate_rejects_unknown_mechanism() {
        let mut cfg = SupervisorConfig::default();
        cfg.default_profile = "generic".into();
        cfg.platform.seccomp_pre_filter = false;
        cfg.platform.linux_mechanism = "magic".into();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("magic"));
        assert!(err.contains("not a recognized mechanism"));
    }

    #[test]
    fn validate_accepts_ptrace_mechanism() {
        let mut cfg = SupervisorConfig::default();
        cfg.default_profile = "generic".into();
        cfg.platform.seccomp_pre_filter = false;
        cfg.platform.linux_mechanism = "ptrace".into();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn require_sandbox_defaults_to_false() {
        let cfg: SupervisorConfig = toml::from_str("").unwrap();
        assert!(!cfg.require_sandbox);
    }

    #[test]
    fn require_sandbox_can_be_set_true() {
        let toml_str = "require_sandbox = true";
        let cfg: SupervisorConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.require_sandbox);
    }

    #[test]
    fn require_sandbox_round_trips_toml() {
        let original = SupervisorConfig {
            require_sandbox: true,
            attach_mode: AttachMode::Seize,
            ..SupervisorConfig::default()
        };
        let serialized = toml::to_string(&original).unwrap();
        let parsed: SupervisorConfig = toml::from_str(&serialized).unwrap();
        assert!(parsed.require_sandbox);
    }
}
