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

    /// How long (in seconds) an operator's deny of a specific request keeps
    /// auto-denying identical retries without a fresh prompt. A tool that
    /// hammers the same denied operation would otherwise re-prompt once per
    /// retry. `0` disables replay (every identical retry prompts again).
    /// The window is measured from the reviewed decision and is not
    /// refreshed by replays, so the operator is re-asked after it lapses.
    pub deny_replay_seconds: u64,

    /// How long (in seconds) an operator's approval of a specific request
    /// keeps auto-allowing identical retries without a fresh prompt. Most
    /// approvals also add a session allowlist grant, but grant keys can
    /// fail to match (exec provenance rejections, unresolvable paths) and
    /// some call types carry no grant — each identical retry would re-open
    /// the dialog. Keyed on the exact call identity shown in the prompt.
    /// Not consulted while session containment is active. `0` disables
    /// replay. Like deny replay, the window is measured from the reviewed
    /// decision and is not refreshed by replays.
    pub approve_replay_seconds: u64,

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

    /// Seconds to keep running after the daemon disowns this session before
    /// terminating it automatically. `0` (the default) means never — the
    /// session keeps running with a loud warning and the operator decides
    /// (work/74 Phase 3, go-live review B12 item 2).
    ///
    /// Terminating by default would destroy in-progress agent work because of
    /// a daemon-side event the user did not cause. CI, where nobody is
    /// watching the banner, can opt into a grace period instead.
    #[serde(default)]
    pub authority_lost_terminate_after_seconds: u64,

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

    /// Enforce the authority-delegating-binary-spawn detection. When `false`
    /// (default) a spawn of `systemd-run` / `at` / `docker` / `systemctl` /
    /// `dbus-send` / … is detected and forensically logged but still allowed
    /// (audit-only). When `true`, such a spawn is escalated Allow→QUEUE unless
    /// the profile's `permit_authority_delegating` list authorises the binary
    /// — closing the `systemd-run --user … -- <cmd>` supervision-escape class.
    /// Off by default until the FP budget is measured. Env override:
    /// `GRITH_ENFORCE_AUTHORITY_DELEGATING_SPAWN`.
    #[serde(default)]
    pub enforce_authority_delegating_spawn: bool,

    /// Enforce the control-injection-IPC-socket-connect detection. When
    /// `false` (default) a connect to the session D-Bus / tmux / screen / X11
    /// socket is forensically logged but auto-allowed as local IPC. When
    /// `true`, such a connect is routed to the proxy and escalated
    /// Allow→QUEUE unless the profile's `permit_control_sockets` list
    /// authorises it. Higher false-positive surface than the spawn flag
    /// (desktop tooling touches the session bus routinely), so it is an
    /// independent knob. Env override:
    /// `GRITH_ENFORCE_CONTROL_SOCKET_CONNECT`.
    #[serde(default)]
    pub enforce_control_socket_connect: bool,
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
    /// Category 2 (filesystem subset): proxy-evaluated chown / mount family.
    /// Off by default — sandboxes/rootless runtimes do real mount/chown work.
    pub category2_proxy: bool,
    /// Category 2 (cross-process subset): proxy-evaluated ptrace /
    /// process_vm_readv / process_vm_writev against a target OUTSIDE the
    /// supervised process tree. On by default — a supervised tool has no
    /// legitimate reason to read a non-descendant process's memory, so this is
    /// ~0 false positives and closes the scope-0 secret-theft path. In-tree
    /// descendant/sibling reads (sanitizers, crash handlers) are allowed and
    /// recorded; PTRACE_TRACEME and self-targeted process_vm are carved in
    /// classify.
    pub category2_crossprocess: bool,
    /// Category 3: namespace primitives (unshare/setns) + namespace_users
    /// carveout.
    pub category3_namespace: bool,
    /// Category 4: hard-deny arch-privileged ops (sethostname / iopl /
    /// swapon / reboot, etc.).
    pub category4_arch_priv: bool,
    /// Deny a tracee's own `NEW_LISTENER` seccomp filter (the escape that
    /// out-ranks grith's interception). On by default — it is a proven
    /// bypass and its only collateral is rootless container runtimes using
    /// seccomp-notify, which fail loudly rather than silently. Off restores
    /// the pre-fix behaviour for an operator who needs those runtimes and
    /// accepts the exposure.
    pub deny_self_seccomp_notify: bool,
    /// Also observe (audit-only) a tracee installing a plain seccomp filter.
    /// A plain filter cannot grant authority — it can only make the tracee's
    /// own syscalls fail invisibly — so this blinds the audit log rather than
    /// escaping the sandbox. Off by default: bwrap, Chrome/Electron and
    /// Node/Bun sandboxes self-filter routinely, and until the volume is
    /// measured, surfacing every one is noise. Turning it on records them
    /// without denying them.
    pub observe_self_seccomp_filter: bool,
}

impl Default for CoverageConfig {
    fn default() -> Self {
        Self {
            category1_hard_deny: true,
            category2_proxy: false,
            category2_crossprocess: true,
            category3_namespace: false,
            category4_arch_priv: true,
            deny_self_seccomp_notify: true,
            observe_self_seccomp_filter: false,
        }
    }
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_profile: String::new(),
            freeze_timeout_seconds: 300,
            deny_replay_seconds: 60,
            approve_replay_seconds: 60,
            max_concurrent_sessions: 4,
            pty_forwarding: true,
            platform: PlatformConfig::default(),
            noise_reduction: NoiseConfig::default(),
            require_sandbox: false,
            attach_mode: AttachMode::default(),
            dns_inspection: DnsInspectionConfig::default(),
            interactive_queue_action: InteractiveQueueAction::default(),
            authority_lost_terminate_after_seconds: 0,
            syscall_log_file: None,
            trace_syscalls_jsonl_file: None,
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            coverage: CoverageConfig::default(),
            audit_completeness: AuditCompletenessLevel::default(),
            pty_ownership_enforce: false,
            enforce_authority_delegating_spawn: false,
            enforce_control_socket_connect: false,
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

        let dns = &self.dns_inspection;
        if dns.connected_udp_proxy && !dns.enabled {
            return Err(
                "supervisor.dns_inspection.connected_udp_proxy requires dns_inspection.enabled = true"
                    .into(),
            );
        }
        if dns.connected_udp_proxy && !dns.accept_proxy_network_authority {
            return Err("supervisor.dns_inspection.connected_udp_proxy requires \
                 accept_proxy_network_authority = true after reviewing cgroup/firewall/socket \
                 authority differences"
                .into());
        }
        if !(512..=65_535).contains(&dns.proxy_max_response_bytes) {
            return Err(
                "supervisor.dns_inspection.proxy_max_response_bytes must be in 512..=65535".into(),
            );
        }
        if dns.proxy_policy_timeout_ms == 0
            || dns.proxy_upstream_timeout_ms == 0
            || dns.proxy_shutdown_timeout_ms == 0
        {
            return Err("supervisor DNS proxy timeouts must be > 0".into());
        }
        if dns.proxy_route_capacity == 0
            || dns.proxy_query_capacity == 0
            || dns.proxy_control_capacity == 0
            || dns.proxy_policy_capacity == 0
        {
            return Err("supervisor DNS proxy capacities must be > 0".into());
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
    /// Deny the syscall immediately and log it. Used for non-interactive
    /// sessions (no TTY / no reviewer) so a queued op fails closed at once
    /// instead of freezing the process tree waiting for a dialog that can
    /// never be answered.
    Deny,
}

/// Enforcement used by both in-line and connected-proxy DNS inspection when
/// policy requires asynchronous review.
///
/// `Refuse` is the secure default: the review item is queued, but the current
/// DNS operation is blocked (an in-line syscall denial or a proxy REFUSED
/// response). `Forward` is an explicit compatibility mode and permits the
/// query before review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsProxyQueueAction {
    #[default]
    Refuse,
    Forward,
}

/// DNS inspection configuration.
///
/// When enabled, the Linux supervisor inspects UDP port-53 traffic in-line,
/// extracts domain names from DNS wire format, and evaluates them before the
/// original syscall is allowed. The connected-UDP proxy is a separate,
/// off-by-default path for sockets whose DNS traffic later uses untrapped
/// `write`/`read` calls.
///
/// Lives under `[supervisor.dns_inspection]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)] // Independent operator-facing feature switches.
pub struct DnsInspectionConfig {
    /// Whether DNS inspection is enabled. In-line inspection tracks `:53`
    /// sockets, parses `sendto`/`sendmsg`/`sendmmsg` queries (blocking bad
    /// domains), and lets allowed queries reach the real resolver untouched.
    pub enabled: bool,

    /// Override the auto-discovered upstream DNS resolver. Retained for config
    /// compatibility but unused by both inspection owners: the in-line path
    /// reaches the tracee-selected resolver directly, and connected routes
    /// capture that exact resolver from `connect(2)`.
    pub upstream_resolver: Option<String>,

    /// Observe DNS *responses* to populate the exact IP→domain cache. This
    /// promotes tracked `recvfrom`/`recvmsg`/`recvmmsg` calls to catch their
    /// exits (one tightly scoped `PTRACE_SYSCALL` step). Query inspection and
    /// blocking do not depend on it, so it can be disabled independently.
    pub observe_responses: bool,

    /// Deny TCP-DNS (force the inspected UDP path). TCP-DNS can't be
    /// content-inspected (query/response ride `write`/`read`, which are too hot
    /// to trap), so allowing it would leave query blocking bypassable. Default
    /// on. The rare cost is a domain whose answer exceeds EDNS0-UDP size failing
    /// to resolve (surfaces as a visible deny).
    pub block_tcp_dns: bool,

    /// Route connected UDP/53 sockets through the managed DNS proxy. This is a
    /// canary feature and defaults off; unconnected explicit-destination DNS
    /// remains on the existing in-line path.
    pub connected_udp_proxy: bool,

    /// Explicitly accept that supervisor-owned upstream sockets may have more
    /// network authority than the tracee due to cgroup, firewall, socket mark,
    /// interface binding, or policy-routing differences.
    pub accept_proxy_network_authority: bool,

    /// What the proxy returns for a policy QUEUE decision.
    pub proxy_queue_action: DnsProxyQueueAction,

    /// Largest UDP DNS response the proxy will relay. Larger datagrams fail
    /// explicitly rather than being silently truncated.
    pub proxy_max_response_bytes: usize,

    /// Maximum time allowed for a policy decision before SERVFAIL.
    pub proxy_policy_timeout_ms: u64,

    /// Maximum time allowed for the exact upstream resolver to respond.
    pub proxy_upstream_timeout_ms: u64,

    /// Maximum time allowed to drain route tasks during managed shutdown.
    /// The owning worker thread is then joined rather than detached.
    pub proxy_shutdown_timeout_ms: u64,

    /// Maximum number of live connected-DNS routes in one session.
    pub proxy_route_capacity: usize,

    /// Maximum number of outstanding proxied DNS transactions in one session.
    pub proxy_query_capacity: usize,

    /// Capacity of the route create/register/release control channel.
    pub proxy_control_capacity: usize,

    /// Maximum number of concurrent proxy policy evaluations.
    pub proxy_policy_capacity: usize,
}

impl Default for DnsInspectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            upstream_resolver: None,
            observe_responses: true,
            block_tcp_dns: true,
            connected_udp_proxy: false,
            accept_proxy_network_authority: false,
            proxy_queue_action: DnsProxyQueueAction::Refuse,
            proxy_max_response_bytes: 4096,
            proxy_policy_timeout_ms: 1_000,
            proxy_upstream_timeout_ms: 5_000,
            proxy_shutdown_timeout_ms: 2_000,
            proxy_route_capacity: 256,
            proxy_query_capacity: 1_024,
            proxy_control_capacity: 256,
            proxy_policy_capacity: 128,
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

    #[test]
    fn connected_dns_proxy_defaults_are_conservative() {
        let cfg = DnsInspectionConfig::default();
        assert!(!cfg.connected_udp_proxy);
        assert!(!cfg.accept_proxy_network_authority);
        assert_eq!(cfg.proxy_queue_action, DnsProxyQueueAction::Refuse);
        assert_eq!(cfg.proxy_max_response_bytes, 4096);
        assert_eq!(cfg.proxy_policy_timeout_ms, 1_000);
        assert_eq!(cfg.proxy_upstream_timeout_ms, 5_000);
        assert_eq!(cfg.proxy_shutdown_timeout_ms, 2_000);
        assert_eq!(cfg.proxy_route_capacity, 256);
        assert_eq!(cfg.proxy_query_capacity, 1_024);
        assert_eq!(cfg.proxy_control_capacity, 256);
        assert_eq!(cfg.proxy_policy_capacity, 128);
    }

    #[test]
    fn connected_dns_proxy_toml_surface_deserializes() {
        let cfg: DnsInspectionConfig = toml::from_str(
            r#"
                connected_udp_proxy = true
                accept_proxy_network_authority = true
                proxy_queue_action = "forward"
                proxy_max_response_bytes = 1232
                proxy_policy_timeout_ms = 250
                proxy_upstream_timeout_ms = 750
                proxy_shutdown_timeout_ms = 500
                proxy_route_capacity = 8
                proxy_query_capacity = 32
                proxy_control_capacity = 16
                proxy_policy_capacity = 4
            "#,
        )
        .unwrap();
        assert!(cfg.connected_udp_proxy);
        assert!(cfg.accept_proxy_network_authority);
        assert_eq!(cfg.proxy_queue_action, DnsProxyQueueAction::Forward);
        assert_eq!(cfg.proxy_max_response_bytes, 1232);
        assert_eq!(cfg.proxy_policy_timeout_ms, 250);
        assert_eq!(cfg.proxy_upstream_timeout_ms, 750);
        assert_eq!(cfg.proxy_shutdown_timeout_ms, 500);
        assert_eq!(cfg.proxy_route_capacity, 8);
        assert_eq!(cfg.proxy_query_capacity, 32);
        assert_eq!(cfg.proxy_control_capacity, 16);
        assert_eq!(cfg.proxy_policy_capacity, 4);
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
            deny_replay_seconds: 45,
            approve_replay_seconds: 30,
            max_concurrent_sessions: 2,
            authority_lost_terminate_after_seconds: 90,
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
            enforce_authority_delegating_spawn: false,
            enforce_control_socket_connect: false,
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
    fn validate_connected_dns_proxy_requires_authority_acceptance() {
        let mut cfg = SupervisorConfig::default();
        cfg.default_profile = "generic".into();
        cfg.dns_inspection.connected_udp_proxy = true;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("accept_proxy_network_authority"));
        cfg.dns_inspection.accept_proxy_network_authority = true;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_connected_dns_proxy_rejects_zero_or_invalid_bounds() {
        let mut cfg = SupervisorConfig::default();
        cfg.default_profile = "generic".into();
        cfg.dns_inspection.proxy_max_response_bytes = 0;
        assert!(cfg
            .validate()
            .unwrap_err()
            .contains("proxy_max_response_bytes"));

        cfg.dns_inspection.proxy_max_response_bytes = 4096;
        cfg.dns_inspection.proxy_policy_timeout_ms = 0;
        assert!(cfg.validate().unwrap_err().contains("timeouts"));

        cfg.dns_inspection.proxy_policy_timeout_ms = 1_000;
        cfg.dns_inspection.proxy_route_capacity = 0;
        assert!(cfg.validate().unwrap_err().contains("capacities"));
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
