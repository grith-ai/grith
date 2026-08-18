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
    pub audit: AuditConfig,
}

/// Audit-log completeness configuration.
///
/// Controls how much of the supervisor's intercepted activity is persisted
/// to the audit log. Higher levels add forensic / analytics value at the
/// cost of audit-DB growth and supervisor-thread overhead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Completeness tier — see `AuditCompleteness` for the level semantics.
    pub completeness: AuditCompleteness,
    /// Days of full + compact audit rows to retain in the active DB.
    /// Older rows get archived (if `cold_storage_enabled`) and deleted
    /// in a contiguous-prefix prune that preserves chain integrity.
    /// Set to 0 to disable retention entirely.
    pub retain_full_days: u32,
    /// Days of compact rows to retain. NOTE: not independently enforced
    /// today — the single hash chain only supports prefix prunes, so the
    /// effective compact cutoff matches `retain_full_days`. Reserved for
    /// the dual-chain follow-up (audit-completeness-scaling.md W2).
    pub retain_compact_days: u32,
    /// When true, prune writes archive files to `<audit_dir>/cold/` as
    /// date-partitioned NDJSON.zst before deleting from the active DB.
    pub cold_storage_enabled: bool,
    /// How often the daemon's prune task runs (hours). 0 disables periodic
    /// pruning entirely; the daemon still prunes once on startup unless
    /// `retain_full_days = 0`.
    pub prune_interval_hours: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            completeness: AuditCompleteness::Spawns,
            retain_full_days: 30,
            retain_compact_days: 7,
            cold_storage_enabled: true,
            prune_interval_hours: 24,
        }
    }
}

/// Audit completeness tiers, from least to most data.
///
/// * `Decisions` — historical default. Only events that reach the proxy
///   pipeline produce audit rows. Routine activity (anything matched by
///   `session_allowed` or the noise filter) is filtered without trace.
/// * `Spawns` — adds a compact audit row for every routine ProcessSpawn
///   short-circuit. Answers "what binaries did the session actually
///   execute?" with modest write volume. Default.
/// * `Io` — additionally records routine file reads / writes. Forensic-ish.
///   Expect ~100-1000× audit-DB growth versus `Decisions`.
/// * `All` — additionally records noise-path events
///   (`/proc/`, `/dev/null`, `/var/cache/`, …). Best for compliance / SIEM
///   exports; requires retention tuning.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuditCompleteness {
    Decisions,
    #[default]
    Spawns,
    Io,
    All,
}

impl AuditCompleteness {
    // The core-side methods mirror the supervisor-side
    // `AuditCompletenessLevel` for API symmetry. The supervisor crate
    // owns its own enum to avoid a dependency cycle; the bridge
    // function in `to_runtime_supervisor_config_with_audit` maps
    // between them. Hot-path callers go through the supervisor mirror,
    // so these methods are kept as part of the public surface but
    // aren't called from within `grith-core` itself.
    /// Whether the level wants a compact row for routine `ProcessSpawn`
    /// events that short-circuit ahead of the proxy pipeline.
    #[allow(dead_code)]
    pub fn records_routine_spawns(&self) -> bool {
        matches!(self, Self::Spawns | Self::Io | Self::All)
    }

    /// Whether the level wants a compact row for routine file-I/O events
    /// (FileRead / FileWrite / FileAppend / FileDelete / FileChmod /
    /// DirCreate / DirList) that short-circuit ahead of the proxy.
    #[allow(dead_code)]
    pub fn records_routine_io(&self) -> bool {
        matches!(self, Self::Io | Self::All)
    }

    /// Whether the level wants a compact row for events the noise filter
    /// (`is_noise_path`) discards before any policy evaluation.
    #[allow(dead_code)]
    pub fn records_noise_paths(&self) -> bool {
        matches!(self, Self::All)
    }
}

/// General daemon settings (log level, audit directory, plan tier).
// These are independent on/off daemon settings (update checks, audit sync,
// profile updates, onboarding state), not a state machine that should be an
// enum — so the bool count is intentional.
#[allow(clippy::struct_excessive_bools)]
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
    /// Whether the interactive first-run onboarding flow has completed.
    /// Defaults to `false` on a brand-new install so `grith` / `grith run`
    /// can offer guided setup once. Set to `true` by the onboarding flow,
    /// by `grith init`, and by `scripts/setup.sh`. Pre-flag user configs
    /// (those that predate this key) are migrated to `true` at load time so
    /// existing users are never re-prompted after an upgrade — see
    /// `GrithConfig::load`.
    pub onboarded: bool,
    /// Whether the one-line first-run notice has already been shown on a
    /// `grith exec` invocation. Tracked separately from `onboarded` because
    /// supervising an external tool is not the same as completing setup.
    /// Flipped to `true` after the notice prints once.
    pub exec_notice_seen: bool,
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

/// Security proxy scoring thresholds (fixed; applied to every call).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub auto_allow_threshold: f64,
    pub auto_deny_threshold: f64,
    /// Seconds to wait for human review before auto-denying a queued tool call.
    /// Used by the agent loop (not supervisor, which has its own freeze_timeout_seconds).
    pub review_timeout_seconds: u64,
    /// Per-filter enable/disable overrides.
    pub filters: FilterGroupConfig,
    /// PR 4 Phase H: ProcessSpawn-specific settings.
    pub spawn: SpawnConfig,
    /// Rate-limit / volume-detection rollout settings. See the
    /// risk-gated-burst redesign in
    /// `work/futurework/rate-limit-burst-redesign.md`.
    pub rate_limit: ProxyRateLimitConfig,
    /// Destructive-action coverage settings (work item 68).
    pub destructive_action: DestructiveActionConfig,
}

/// Destructive-action coverage configuration (work item 68). Gates the
/// `destructive-action` filter that hard-denies catastrophic host/storage
/// destruction and escalates destructive-against-production to DENY.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DestructiveActionConfig {
    /// Enable the destructive-action filter. Default **`true`** — this is the
    /// coverage that backs grith's public "blocks the destructive step"
    /// claim. Operators who hit a false positive on a specific verb can
    /// disable the whole filter here; per-rule disable is a follow-up.
    pub enabled: bool,
}

impl Default for DestructiveActionConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Rate-limit volume-detection rollout configuration. Holds the rollout
/// flag for the risk-gated burst signal — the FP-reduction reshape
/// documented in [`work/futurework/rate-limit-burst-redesign.md`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyRateLimitConfig {
    /// Gate the `rate_limit` filter's volume penalties (burst `+3.0`,
    /// per-minute `+2.0`, approaching `+1.0`) on per-op risk: they only
    /// apply to operations carrying a risk signal (tainted source, network
    /// egress, or egress-capable spawn). A burst of untainted routine file
    /// churn (`~/.cache`, `.git/` internals, build outputs) never escalates,
    /// which subsumes the per-pattern scratch exemptions (now retired).
    ///
    /// Default **`true`** (rollout step 4): the supervisor's target-aware
    /// mass-destruction signal backfills the one case risk-gating drops (an
    /// untainted destructive spree). Operators can set `false` to restore the
    /// legacy frequency-blind burst counter — note that doing so also forfeits
    /// the per-pattern scratch/`~/.cache`/`.git` exemptions, which were retired
    /// in favour of this gate.
    ///
    /// Implementation reads this through `RateLimitFilter`'s
    /// `with_risk_gated_burst` builder so the runtime cost on the hot path
    /// is a single field load.
    pub risk_gated_burst: bool,
}

impl Default for ProxyRateLimitConfig {
    fn default() -> Self {
        Self {
            risk_gated_burst: true,
        }
    }
}

/// PR 4 Phase H: ProcessSpawn-specific proxy configuration. Holds the
/// rollout flag for the provenance-backed routine-spawn signal — the
/// `+0.5` reduction documented in [`work/64-pr4-provenance-routine-spawn-work.md`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SpawnConfig {
    /// Enable the provenance-backed routine-spawn signal added in PR 4.
    /// Default `false` until operators have verified the session-pinned
    /// inventory (Phase C) and audit-log routing (Phase F) are emitting
    /// the data the dashboard needs. See the rollout doc for the order
    /// of enablement.
    ///
    /// Implementation reads this through `OperationRiskFilter`'s
    /// `routine_signal_enabled` constructor argument so the runtime
    /// cost on the spawn hot path is a single field load.
    pub routine_provenance_signal: bool,
    /// Enable PR 2's data-flow-based taint-on-spawn rule. When false,
    /// taint keeps the legacy behavior: any active session taint adds
    /// `+3.0` to every spawn. When true, the taint score applies only
    /// when argv/env/fd-lineage/outbound-binary/shell-pattern checks
    /// show plausible flow from tainted data to the spawn.
    ///
    /// Default **`true`** (FP research §5.2): the legacy "any taint → +3.0 on
    /// every spawn/connect" flagged read-credential-then-use-credential as a
    /// false positive (read `~/.npmrc` then `npm install`, `~/.kube/config`
    /// then `kubectl`, `~/.aws/credentials` then `aws`). The data-flow rule
    /// still catches genuine exfil (it fires when argv references the tainted
    /// path/env or a pipe/redirect carries it). Operators can set `false` to
    /// restore the legacy behavior.
    pub taint_data_flow_only: bool,
    /// Narrow condition 4 of the data-flow taint rule (FP research §5.2).
    /// When true, an outbound-capable binary under taint (`git push`,
    /// `aws s3 ls`, `npm publish`) only fires when the spawn actually
    /// references the tainted data (argv path/env, pipe/redirect, or
    /// shell-pattern) — not merely because a credential was read earlier and
    /// the tool is outbound-capable. Genuine exfil of the tainted data still
    /// fires (conditions 1–3/5), and outbound-to-untrusted-destination is
    /// independently scored by the egress filter.
    ///
    /// Default **`true`**: the standalone outbound-binary trigger was the
    /// dominant own-credential false positive (read `~/.aws/credentials` then
    /// `aws s3 ls`). Operators can set `false` to restore the standalone fire.
    pub taint_outbound_requires_data_flow: bool,
}

impl Default for SpawnConfig {
    fn default() -> Self {
        Self {
            routine_provenance_signal: false,
            taint_data_flow_only: true,
            taint_outbound_requires_data_flow: true,
        }
    }
}

/// Per-filter enable/disable toggles for Phase 3 (context) filters.
///
/// Phase 1 (static) and Phase 2 (pattern) filters are always active.
/// Phase 3 filters can be individually disabled here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterGroupConfig {
    pub reputation: FilterToggle,
    /// PR 69 Change 1: behavioural now carries tunable knobs alongside
    /// the on/off toggle — previously `FilterToggle`, so `min_calls_for_baseline`
    /// and the deviation scores in `config/default.toml` were ignored
    /// by the daemon at construction time.
    pub behavioural: BehaviouralFilterConfig,
    pub taint: FilterToggle,
    pub rate_limit: FilterToggle,
    pub egress: FilterToggle,
    pub session_containment: FilterToggle,
}

/// PR 69 Change 1: operator-tunable behavioural filter config.
/// Mirrors `grith_proxy::filters::behavioural::BehaviouralConfig` plus
/// the `enabled` toggle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BehaviouralFilterConfig {
    pub enabled: bool,
    pub min_calls_for_baseline: usize,
    pub mild_deviation_score: f64,
    pub significant_deviation_score: f64,
}

impl Default for BehaviouralFilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_calls_for_baseline: 200,
            mild_deviation_score: 1.0,
            significant_deviation_score: 3.0,
        }
    }
}

impl BehaviouralFilterConfig {
    /// Convert to the proxy-layer behavioural config struct.
    pub fn to_proxy_config(&self) -> grith_proxy::filters::behavioural::BehaviouralConfig {
        grith_proxy::filters::behavioural::BehaviouralConfig {
            min_calls_for_baseline: self.min_calls_for_baseline,
            mild_deviation_score: self.mild_deviation_score,
            significant_deviation_score: self.significant_deviation_score,
        }
    }
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
    /// Open the dashboard in the operator's default browser when the server
    /// starts, handing off the dashboard token via the URL fragment so it is
    /// never rendered to the terminal. Skipped automatically on headless /
    /// SSH sessions (no `$DISPLAY` / `$SSH_CONNECTION` set). When disabled, or
    /// when no browser can be opened, the CLI prints a single-use pairing URL
    /// instead of the raw token. Defaults to `true`.
    pub auto_open_dashboard: bool,
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

/// How the Linux supervisor attaches to the supervised process tree.
///
/// Migration knob for the `PTRACE_SEIZE` work (see
/// `work/futurework/ptrace-seize-migration.md`). `traceme` is the current,
/// shipped mechanism; `seize` is being built behind this flag so the two
/// paths can coexist during rollout. Defaults to `traceme` — selecting
/// `seize` today aborts the session with a clear "not yet implemented"
/// error rather than silently falling back, so the flag's effect is
/// observable. No effect on macOS/Windows (their interceptors don't use
/// ptrace).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AttachMode {
    /// `fork` + child `PTRACE_TRACEME` + `execve` (current, shipped).
    #[default]
    Traceme,
    /// Parent `PTRACE_SEIZE` of the child after a pre-exec barrier (WIP).
    Seize,
}

/// Supervisor configuration (v1.5 — CLI supervisor mode).
/// Maps to `grith_supervisor::config::SupervisorConfig` at runtime.
// Independent operator knobs (enabled / pty_forwarding / require_sandbox /
// pty_ownership_enforce) — collapsing them would hide that independence.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SupervisorCoreConfig {
    pub enabled: bool,
    pub default_profile: String,
    pub freeze_timeout_seconds: u64,
    /// Seconds an operator's deny keeps auto-denying identical retries
    /// without a fresh prompt. `0` disables replay.
    pub deny_replay_seconds: u64,
    /// Seconds an operator's approval keeps auto-allowing identical retries
    /// without a fresh prompt. `0` disables replay.
    pub approve_replay_seconds: u64,
    /// Local safety valve for concurrent supervised sessions. The daemon
    /// enforces the *lower* of this and the license entitlement (Community 2,
    /// paid 64), so it only tightens the cap. Defaults to the paid cap (64) so
    /// it does not silently clamp a paid entitlement; lower it for a hard local
    /// ceiling.
    pub max_concurrent_sessions: usize,
    pub pty_forwarding: bool,
    /// Linux attach mechanism (`traceme` | `seize`). See [`AttachMode`].
    pub attach_mode: AttachMode,
    /// Refuse startup if the platform cannot provide full per-syscall interception.
    /// When `true`, `grith exec` aborts if the supervision backend is degraded
    /// (macOS lifecycle-only) or unavailable (ptrace blocked). Defaults to `false`.
    pub require_sandbox: bool,
    pub platform: SupervisorPlatformConfig,
    pub noise_reduction: SupervisorNoiseConfig,
    pub dns_inspection: SupervisorDnsInspectionConfig,
    /// PR 6: per-category coverage flags for the staged rollout of
    /// syscall-coverage expansion. See `CoverageConfig`.
    pub coverage: CoverageConfig,
    /// H2 Option 1: enforce PTY ownership. When `false` (default), writes to a
    /// `/dev/pts/N` that is not the supervised tool's own controlling terminal
    /// are detected + forensically logged but still allowed (audit-only); when
    /// `true`, they are denied (the `echo > /dev/pts/<sibling-pane>` injection
    /// vector). Off by default until the false-positive budget is measured.
    #[serde(default)]
    pub pty_ownership_enforce: bool,
    /// Enforce the authority-delegating-binary-spawn detection (`systemd-run`
    /// / `at` / `docker` / `systemctl` / `dbus-send` / …). When `false`
    /// (default) such a spawn is audit-only; when `true` it is escalated
    /// Allow→QUEUE unless the profile's `permit_authority_delegating` list
    /// authorises the binary. Closes the `systemd-run --user` supervision
    /// escape. Env override `GRITH_ENFORCE_AUTHORITY_DELEGATING_SPAWN`.
    #[serde(default)]
    pub enforce_authority_delegating_spawn: bool,
    /// Enforce the control-injection-IPC-socket-connect detection (session
    /// D-Bus / tmux / screen / X11). When `false` (default) such a connect is
    /// audit-only; when `true` it is routed to the proxy and escalated
    /// Allow→QUEUE unless the profile's `permit_control_sockets` list
    /// authorises it. Independent knob (higher FP surface than the spawn
    /// flag). Env override `GRITH_ENFORCE_CONTROL_SOCKET_CONNECT`.
    #[serde(default)]
    pub enforce_control_socket_connect: bool,
    /// Seconds to keep running after the daemon stops accounting for this
    /// session before terminating it automatically. `0` (the default) means
    /// never — the session keeps running with a loud warning and the operator
    /// decides (work/74 Phase 3).
    ///
    /// Terminating by default would destroy in-progress agent work because of
    /// a daemon-side event the user did not cause. CI, where nobody is
    /// watching the banner, can opt into a grace period.
    #[serde(default)]
    pub authority_lost_terminate_after_seconds: u64,
}

/// PR 6 Phase F: per-category coverage feature flags.
///
/// Each PR 6 category can be enabled or disabled independently so
/// operators can stage the rollout. When a category is disabled, its
/// syscalls fall through to the "not security-relevant" branch (silent
/// allow), matching pre-PR-6 behaviour.
///
/// Defaults reflect the work-doc's recommended rollout:
///   - Categories 1 and 4 are extreme ops with no legitimate dev-tool
///     use → ON by default (the kernel-module / kexec / reboot
///     family).
///   - Categories 2 and 3 may queue legitimate operations until
///     operator profiles are calibrated → OFF by default.
///
/// The four bools are intentional — each represents an independent
/// staged-rollout knob with its own threat model.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoverageConfig {
    /// Category 1: hard-deny kernel-module load/unload + kexec.
    /// No legitimate use in supervised AI tools. **Default ON.**
    pub category1_hard_deny: bool,
    /// Category 2 (filesystem subset): proxy-evaluated chown / mount
    /// family. May QUEUE legitimate operations during calibration.
    /// **Default OFF** — sandboxes and rootless container runtimes do
    /// real mount/chown work. Enable once the relevant profile
    /// capability grants (fs:ownership / fs:mount) are wired.
    pub category2_proxy: bool,
    /// Category 2 (cross-process subset): proxy-evaluated ptrace /
    /// process_vm_readv / process_vm_writev against a target OUTSIDE the
    /// supervised process tree. **Default ON** — a supervised tool has
    /// no legitimate reason to read a *non-descendant* process's memory,
    /// so this is ~0 false positives and closes the scope-0 secret-theft
    /// path (lifting decrypted secrets from another app's address space,
    /// which `process_vm_readv` can do at `ptrace_scope=0` with no tracer
    /// slot). Reads of an *in-tree* descendant/sibling (LeakSanitizer at
    /// exit, crash handlers, fork/trace test harnesses) are allowed and
    /// audit-recorded — the target is already inside the session sandbox.
    /// `PTRACE_TRACEME` and self-targeted `process_vm` are carved out in
    /// classify.
    pub category2_crossprocess: bool,
    /// Category 3: namespace primitives (unshare/setns) with the
    /// profile-declared `namespace_users` carveout. **Default OFF.**
    /// Enable once the profile's `namespace_users` and
    /// `routine_exec_roots` have been audited together.
    pub category3_namespace: bool,
    /// Category 4: hard-deny arch-privileged ops (sethostname /
    /// iopl / swapon / reboot, etc.). **Default ON** — same threat
    /// profile as Category 1.
    pub category4_arch_priv: bool,
    /// Deny a tracee installing its own `NEW_LISTENER` seccomp filter — the
    /// proven escape that out-ranks grith's interception. **Default ON.**
    /// Its only collateral is rootless container runtimes using
    /// seccomp-notify, which fail loudly. Turn OFF only if you must run those
    /// under supervision and accept the exposure.
    pub deny_self_seccomp_notify: bool,
    /// Audit-only observation of a tracee installing a plain seccomp filter
    /// (audit-blinding, not an escape). **Default OFF** — sandboxes
    /// self-filter routinely, so this is noise until the volume is measured.
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

/// Enforcement used by both the in-line and connected-proxy DNS paths when a
/// policy decision is queued for review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SupervisorDnsProxyQueueAction {
    #[default]
    Refuse,
    Forward,
}

impl std::fmt::Display for SupervisorDnsProxyQueueAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refuse => f.write_str("refuse"),
            Self::Forward => f.write_str("forward"),
        }
    }
}

impl std::str::FromStr for SupervisorDnsProxyQueueAction {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "refuse" => Ok(Self::Refuse),
            "forward" => Ok(Self::Forward),
            _ => Err(()),
        }
    }
}

/// DNS inspection settings for supervisor DNS interception.
// Each bool is an independent operator-facing TOML toggle; grouping them into
// sub-structs would break the flat config schema for no benefit.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SupervisorDnsInspectionConfig {
    pub enabled: bool,
    pub upstream_resolver: Option<String>,
    /// Observe DNS responses to populate the exact IP→domain cache (promotes
    /// the recvfrom syscall to catch its exit). Query blocking is independent.
    pub observe_responses: bool,
    /// Deny TCP-DNS (force the inspected UDP path). TCP-DNS can't be
    /// content-inspected, so allowing it would leave query blocking bypassable.
    pub block_tcp_dns: bool,
    /// Canary connected-UDP proxy. Defaults off.
    pub connected_udp_proxy: bool,
    /// Explicit acceptance of any network authority gained by proxy-owned
    /// upstream sockets. Defaults false.
    pub accept_proxy_network_authority: bool,
    /// Wire result for QUEUE-range decisions.
    pub proxy_queue_action: SupervisorDnsProxyQueueAction,
    /// Largest proxied UDP response, in bytes.
    pub proxy_max_response_bytes: usize,
    /// Policy decision timeout before SERVFAIL.
    pub proxy_policy_timeout_ms: u64,
    /// Upstream response timeout before SERVFAIL.
    pub proxy_upstream_timeout_ms: u64,
    /// Route-task drain timeout before the worker aborts remaining tasks and
    /// joins its owning thread.
    pub proxy_shutdown_timeout_ms: u64,
    /// Maximum live routes per session.
    pub proxy_route_capacity: usize,
    /// Maximum outstanding queries per session.
    pub proxy_query_capacity: usize,
    /// Proxy control-channel capacity.
    pub proxy_control_capacity: usize,
    /// Maximum concurrent policy evaluations.
    pub proxy_policy_capacity: usize,
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

impl NotifyRoutingConfig {
    /// `filter_overrides` with legacy snake_case filter names normalised to
    /// their kebab-case equivalents. Routing matches override keys against
    /// live filter names, so a pre-rename config entry like
    /// `"dlp_gate" = ["slack"]` would silently stop routing without this.
    pub fn canonical_filter_overrides(&self) -> std::collections::HashMap<String, Vec<String>> {
        self.filter_overrides
            .iter()
            .map(|(name, channels)| {
                (
                    grith_proxy::filters::canonical_filter_name(name).to_string(),
                    channels.clone(),
                )
            })
            .collect()
    }
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
            onboarded: false,
            exec_notice_seen: false,
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
            review_timeout_seconds: 300,
            filters: FilterGroupConfig::default(),
            spawn: SpawnConfig::default(),
            rate_limit: ProxyRateLimitConfig::default(),
            destructive_action: DestructiveActionConfig::default(),
        }
    }
}

impl Default for FilterGroupConfig {
    fn default() -> Self {
        Self {
            reputation: FilterToggle { enabled: true },
            behavioural: BehaviouralFilterConfig::default(),
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
            auto_open_dashboard: true,
        }
    }
}

impl Default for SupervisorCoreConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_profile: String::new(),
            freeze_timeout_seconds: 300,
            deny_replay_seconds: 60,
            approve_replay_seconds: 60,
            max_concurrent_sessions: 64,
            pty_forwarding: true,
            attach_mode: AttachMode::default(),
            require_sandbox: false,
            platform: SupervisorPlatformConfig::default(),
            noise_reduction: SupervisorNoiseConfig::default(),
            dns_inspection: SupervisorDnsInspectionConfig::default(),
            coverage: CoverageConfig::default(),
            pty_ownership_enforce: false,
            enforce_authority_delegating_spawn: false,
            enforce_control_socket_connect: false,
            authority_lost_terminate_after_seconds: 0,
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
            observe_responses: true,
            block_tcp_dns: true,
            connected_udp_proxy: false,
            accept_proxy_network_authority: false,
            proxy_queue_action: SupervisorDnsProxyQueueAction::Refuse,
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
        let user_config_exists = user_config_path.exists();
        // Whether the user's *raw* config file explicitly declares the
        // onboarding flag. We must inspect the raw TOML (not the merged
        // struct) because `#[serde(default)]` silently fills a missing
        // `onboarded` with `false`, which `merge_config` would then treat as
        // an explicit override — indistinguishable from a real choice.
        let user_declares_onboarded =
            user_config_exists && raw_config_declares_general_key(&user_config_path, "onboarded");
        if user_config_exists {
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

        // Onboarding migration: a user config that predates the onboarding
        // flag must NOT trigger the first-run wizard after an upgrade.
        migrate_onboarding_flags(&mut config, user_config_exists, user_declares_onboarded);

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
            parse("bool")   "general.onboarded"                 => general.onboarded;
            parse("bool")   "general.exec_notice_seen"          => general.exec_notice_seen;
            parse("float")  "proxy.auto_allow_threshold"        => proxy.auto_allow_threshold;
            parse("float")  "proxy.auto_deny_threshold"         => proxy.auto_deny_threshold;
            parse("u64")    "proxy.review_timeout_seconds"      => proxy.review_timeout_seconds;
            parse("bool")   "server.enabled"                    => server.enabled;
            parse("bool")   "server.auto_open_dashboard"        => server.auto_open_dashboard;
            parse("port")   "server.port"                       => server.port;
            parse("bool")   "supervisor.enabled"                => supervisor.enabled;
            parse("u64")    "supervisor.freeze_timeout_seconds" => supervisor.freeze_timeout_seconds;
            parse("u64")    "supervisor.deny_replay_seconds"    => supervisor.deny_replay_seconds;
            parse("u64")    "supervisor.approve_replay_seconds" => supervisor.approve_replay_seconds;
            parse("usize")  "supervisor.max_concurrent_sessions" => supervisor.max_concurrent_sessions;
            parse("bool")   "supervisor.pty_forwarding"         => supervisor.pty_forwarding;
            parse("bool")   "supervisor.dns_inspection.enabled" => supervisor.dns_inspection.enabled;
            parse("bool")   "supervisor.dns_inspection.observe_responses" => supervisor.dns_inspection.observe_responses;
            parse("bool")   "supervisor.dns_inspection.block_tcp_dns" => supervisor.dns_inspection.block_tcp_dns;
            parse("bool")   "supervisor.dns_inspection.connected_udp_proxy" => supervisor.dns_inspection.connected_udp_proxy;
            parse("bool")   "supervisor.dns_inspection.accept_proxy_network_authority" => supervisor.dns_inspection.accept_proxy_network_authority;
            parse("DNS proxy queue action") "supervisor.dns_inspection.proxy_queue_action" => supervisor.dns_inspection.proxy_queue_action;
            parse("usize")  "supervisor.dns_inspection.proxy_max_response_bytes" => supervisor.dns_inspection.proxy_max_response_bytes;
            parse("u64")    "supervisor.dns_inspection.proxy_policy_timeout_ms" => supervisor.dns_inspection.proxy_policy_timeout_ms;
            parse("u64")    "supervisor.dns_inspection.proxy_upstream_timeout_ms" => supervisor.dns_inspection.proxy_upstream_timeout_ms;
            parse("u64")    "supervisor.dns_inspection.proxy_shutdown_timeout_ms" => supervisor.dns_inspection.proxy_shutdown_timeout_ms;
            parse("usize")  "supervisor.dns_inspection.proxy_route_capacity" => supervisor.dns_inspection.proxy_route_capacity;
            parse("usize")  "supervisor.dns_inspection.proxy_query_capacity" => supervisor.dns_inspection.proxy_query_capacity;
            parse("usize")  "supervisor.dns_inspection.proxy_control_capacity" => supervisor.dns_inspection.proxy_control_capacity;
            parse("usize")  "supervisor.dns_inspection.proxy_policy_capacity" => supervisor.dns_inspection.proxy_policy_capacity;
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

        let dns = &self.supervisor.dns_inspection;
        if dns.connected_udp_proxy && !dns.enabled {
            issues.push(
                "supervisor.dns_inspection.connected_udp_proxy requires \
                 dns_inspection.enabled = true"
                    .to_string(),
            );
        }
        if dns.connected_udp_proxy && !dns.accept_proxy_network_authority {
            issues.push(
                "supervisor.dns_inspection.connected_udp_proxy requires \
                 accept_proxy_network_authority = true after reviewing cgroup/firewall/socket \
                 authority differences"
                    .to_string(),
            );
        }
        if !(512..=65_535).contains(&dns.proxy_max_response_bytes) {
            issues.push(
                "supervisor.dns_inspection.proxy_max_response_bytes must be in 512..=65535"
                    .to_string(),
            );
        }
        if dns.proxy_policy_timeout_ms == 0
            || dns.proxy_upstream_timeout_ms == 0
            || dns.proxy_shutdown_timeout_ms == 0
        {
            issues.push("supervisor DNS proxy timeouts must be > 0".to_string());
        }
        if dns.proxy_route_capacity == 0
            || dns.proxy_query_capacity == 0
            || dns.proxy_control_capacity == 0
            || dns.proxy_policy_capacity == 0
        {
            issues.push("supervisor DNS proxy capacities must be > 0".to_string());
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
/// In-memory onboarding normalization applied after config layering.
///
/// If the user already has a config file but it does not declare
/// `general.onboarded`, the install predates the onboarding flag — treat that
/// machine as already onboarded (and suppress the one-time exec notice) so an
/// upgrade never surprises the user with a first-run wizard. A fresh install
/// (no user config file) keeps the embedded default of `false` and stays
/// eligible. This never rewrites the user's file — it is purely in-memory.
///
/// Edge case: because the decision is keyed only on whether the *user* config
/// file declares the flag, a pre-flag user config combined with a project-local
/// `.grith/config.toml` or `--config` file that explicitly sets
/// `general.onboarded = false` will have that downstream `false` normalized to
/// `true`. `onboarded` is a managed flag not meant to be hand-set in project /
/// explicit layers, so this is acceptable.
fn migrate_onboarding_flags(
    config: &mut GrithConfig,
    user_config_exists: bool,
    user_declares_onboarded: bool,
) {
    if user_config_exists && !user_declares_onboarded {
        config.general.onboarded = true;
        config.general.exec_notice_seen = true;
    }
}

/// Returns `true` if the raw TOML at `path` explicitly declares
/// `[general].<key>`. Used by onboarding migration to distinguish "the user
/// chose a value" from "serde defaulted a missing key". Any read/parse error
/// is treated as "not declared" (the caller's safe-by-default branch).
fn raw_config_declares_general_key(path: &Path, key: &str) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = content.parse::<toml::Value>() else {
        return false;
    };
    value
        .get("general")
        .and_then(toml::Value::as_table)
        .is_some_and(|general| general.contains_key(key))
}

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
    env_parse!(config, "GRITH_AUTO_OPEN_DASHBOARD"           => server.auto_open_dashboard);
    env_parse!(config, "GRITH_SUPERVISOR_ENABLED"            => supervisor.enabled);
    env_parse!(config, "GRITH_SUPERVISOR_TIMEOUT"            => supervisor.freeze_timeout_seconds);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_INSPECTION_ENABLED" => supervisor.dns_inspection.enabled);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_CONNECTED_UDP_PROXY" => supervisor.dns_inspection.connected_udp_proxy);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_ACCEPT_PROXY_NETWORK_AUTHORITY" => supervisor.dns_inspection.accept_proxy_network_authority);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_PROXY_QUEUE_ACTION" => supervisor.dns_inspection.proxy_queue_action);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_PROXY_MAX_RESPONSE_BYTES" => supervisor.dns_inspection.proxy_max_response_bytes);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_PROXY_POLICY_TIMEOUT_MS" => supervisor.dns_inspection.proxy_policy_timeout_ms);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_PROXY_UPSTREAM_TIMEOUT_MS" => supervisor.dns_inspection.proxy_upstream_timeout_ms);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_PROXY_SHUTDOWN_TIMEOUT_MS" => supervisor.dns_inspection.proxy_shutdown_timeout_ms);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_PROXY_ROUTE_CAPACITY" => supervisor.dns_inspection.proxy_route_capacity);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_PROXY_QUERY_CAPACITY" => supervisor.dns_inspection.proxy_query_capacity);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_PROXY_CONTROL_CAPACITY" => supervisor.dns_inspection.proxy_control_capacity);
    env_parse!(config, "GRITH_SUPERVISOR_DNS_PROXY_POLICY_CAPACITY" => supervisor.dns_inspection.proxy_policy_capacity);
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
        // A brand-new install is not yet onboarded.
        assert!(!config.general.onboarded);
        assert!(!config.general.exec_notice_seen);
    }

    #[test]
    fn test_connected_dns_proxy_defaults_and_toml_surface() {
        let defaults = GrithConfig::default();
        let dns = &defaults.supervisor.dns_inspection;
        assert!(!dns.connected_udp_proxy);
        assert!(!dns.accept_proxy_network_authority);
        assert_eq!(
            dns.proxy_queue_action,
            SupervisorDnsProxyQueueAction::Refuse
        );
        assert_eq!(dns.proxy_max_response_bytes, 4096);
        assert_eq!(dns.proxy_policy_timeout_ms, 1_000);
        assert_eq!(dns.proxy_upstream_timeout_ms, 5_000);
        assert_eq!(dns.proxy_shutdown_timeout_ms, 2_000);
        assert_eq!(dns.proxy_route_capacity, 256);
        assert_eq!(dns.proxy_query_capacity, 1_024);
        assert_eq!(dns.proxy_control_capacity, 256);
        assert_eq!(dns.proxy_policy_capacity, 128);

        let parsed: GrithConfig = toml::from_str(
            r#"
                [supervisor.dns_inspection]
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
        let dns = &parsed.supervisor.dns_inspection;
        assert!(dns.connected_udp_proxy);
        assert!(dns.accept_proxy_network_authority);
        assert_eq!(
            dns.proxy_queue_action,
            SupervisorDnsProxyQueueAction::Forward
        );
        assert_eq!(dns.proxy_max_response_bytes, 1232);
        assert_eq!(dns.proxy_policy_timeout_ms, 250);
        assert_eq!(dns.proxy_upstream_timeout_ms, 750);
        assert_eq!(dns.proxy_shutdown_timeout_ms, 500);
        assert_eq!(dns.proxy_route_capacity, 8);
        assert_eq!(dns.proxy_query_capacity, 32);
        assert_eq!(dns.proxy_control_capacity, 16);
        assert_eq!(dns.proxy_policy_capacity, 4);
    }

    #[test]
    fn test_checked_in_default_toml_keeps_connected_dns_proxy_off() {
        let parsed: GrithConfig =
            toml::from_str(include_str!("../../../config/default.toml")).unwrap();
        let dns = &parsed.supervisor.dns_inspection;
        assert!(!dns.connected_udp_proxy);
        assert!(!dns.accept_proxy_network_authority);
        assert_eq!(
            dns.proxy_queue_action,
            SupervisorDnsProxyQueueAction::Refuse
        );
        assert_eq!(dns.proxy_max_response_bytes, 4096);
        assert_eq!(dns.proxy_policy_timeout_ms, 1_000);
        assert_eq!(dns.proxy_upstream_timeout_ms, 5_000);
        assert_eq!(dns.proxy_shutdown_timeout_ms, 2_000);
        assert_eq!(dns.proxy_route_capacity, 256);
        assert_eq!(dns.proxy_query_capacity, 1_024);
        assert_eq!(dns.proxy_control_capacity, 256);
        assert_eq!(dns.proxy_policy_capacity, 128);
    }

    #[test]
    fn test_connected_dns_proxy_set_value_surface() {
        let mut config = GrithConfig::default();
        config
            .set_value("supervisor.dns_inspection.connected_udp_proxy", "true")
            .unwrap();
        config
            .set_value(
                "supervisor.dns_inspection.accept_proxy_network_authority",
                "true",
            )
            .unwrap();
        config
            .set_value("supervisor.dns_inspection.proxy_queue_action", "forward")
            .unwrap();
        config
            .set_value("supervisor.dns_inspection.proxy_max_response_bytes", "1232")
            .unwrap();
        assert!(config.supervisor.dns_inspection.connected_udp_proxy);
        assert!(
            config
                .supervisor
                .dns_inspection
                .accept_proxy_network_authority
        );
        assert_eq!(
            config.supervisor.dns_inspection.proxy_queue_action,
            SupervisorDnsProxyQueueAction::Forward
        );
        assert_eq!(
            config.supervisor.dns_inspection.proxy_max_response_bytes,
            1232
        );
        assert!(config
            .set_value("supervisor.dns_inspection.proxy_queue_action", "wait",)
            .is_err());
    }

    #[test]
    fn test_set_onboarding_flags() {
        let mut config = GrithConfig::default();
        let old = config.set_value("general.onboarded", "true").unwrap();
        assert_eq!(old, "false");
        assert!(config.general.onboarded);
        let old = config
            .set_value("general.exec_notice_seen", "true")
            .unwrap();
        assert_eq!(old, "false");
        assert!(config.general.exec_notice_seen);
    }

    #[test]
    fn test_raw_config_declares_general_key() {
        let dir = tempfile::tempdir().unwrap();
        let with_key = dir.path().join("with.toml");
        std::fs::write(&with_key, "[general]\nonboarded = false\n").unwrap();
        assert!(raw_config_declares_general_key(&with_key, "onboarded"));

        let without_key = dir.path().join("without.toml");
        std::fs::write(&without_key, "[general]\nlog_level = \"info\"\n").unwrap();
        assert!(!raw_config_declares_general_key(&without_key, "onboarded"));

        let no_general = dir.path().join("none.toml");
        std::fs::write(&no_general, "[proxy]\nauto_allow_threshold = 1.0\n").unwrap();
        assert!(!raw_config_declares_general_key(&no_general, "onboarded"));

        let missing = dir.path().join("missing.toml");
        assert!(!raw_config_declares_general_key(&missing, "onboarded"));

        // TOML dotted-key form parses into a `general` table, so it is
        // correctly detected as a declaration.
        let dotted = dir.path().join("dotted.toml");
        std::fs::write(&dotted, "general.onboarded = true\n").unwrap();
        assert!(raw_config_declares_general_key(&dotted, "onboarded"));

        // Inline-table form likewise.
        let inline = dir.path().join("inline.toml");
        std::fs::write(&inline, "general = { onboarded = true }\n").unwrap();
        assert!(raw_config_declares_general_key(&inline, "onboarded"));
    }

    #[test]
    fn test_migrate_onboarding_flags_preflag_config_treated_as_onboarded() {
        // Existing user config that predates the flag → migrate to onboarded,
        // and suppress the one-time exec notice, so upgrades never re-prompt.
        let mut config = GrithConfig::default();
        assert!(!config.general.onboarded);
        migrate_onboarding_flags(&mut config, true, false);
        assert!(config.general.onboarded);
        assert!(config.general.exec_notice_seen);
    }

    #[test]
    fn test_migrate_onboarding_flags_fresh_install_stays_eligible() {
        // No user config file → fresh install → stays not-onboarded.
        let mut config = GrithConfig::default();
        migrate_onboarding_flags(&mut config, false, false);
        assert!(!config.general.onboarded);
        assert!(!config.general.exec_notice_seen);
    }

    #[test]
    fn test_migrate_onboarding_flags_explicit_choice_respected() {
        // User config explicitly declares the key → respect their value
        // (here: explicitly not onboarded, e.g. they want the wizard).
        let mut config = GrithConfig::default();
        config.general.onboarded = false;
        migrate_onboarding_flags(&mut config, true, true);
        assert!(!config.general.onboarded);
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
    fn test_validate_connected_dns_proxy_requires_authority_acceptance_and_bounds() {
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.supervisor.dns_inspection.connected_udp_proxy = true;
        let issues = config.validate();
        assert!(issues
            .iter()
            .any(|issue| issue.contains("accept_proxy_network_authority")));

        config
            .supervisor
            .dns_inspection
            .accept_proxy_network_authority = true;
        config.supervisor.dns_inspection.proxy_max_response_bytes = 0;
        config.supervisor.dns_inspection.proxy_query_capacity = 0;
        config.supervisor.dns_inspection.proxy_policy_timeout_ms = 0;
        let issues = config.validate();
        assert!(issues
            .iter()
            .any(|issue| issue.contains("proxy_max_response_bytes")));
        assert!(issues.iter().any(|issue| issue.contains("capacities")));
        assert!(issues.iter().any(|issue| issue.contains("timeouts")));
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

    /// Risk-gated-burst rollout flag: defaults off, and `proxy.rate_limit.
    /// risk_gated_burst = true` from TOML must reach `ProxyConfig` so the
    /// filter registry can pass it to `RateLimitFilter::with_risk_gated_burst`.
    /// See work/futurework/rate-limit-burst-redesign.md.
    #[test]
    fn test_risk_gated_burst_flag_wired() {
        // Default is ON (rollout step 4): risk-gating is the shipped behaviour.
        assert!(GrithConfig::default().proxy.rate_limit.risk_gated_burst);

        // Operators can opt out via TOML.
        let toml_str = r#"
[proxy.rate_limit]
risk_gated_burst = false
"#;
        let config: GrithConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.proxy.rate_limit.risk_gated_burst);

        // Round-trips through serialization.
        let serialized = toml::to_string(&config).unwrap();
        let reparsed: GrithConfig = toml::from_str(&serialized).unwrap();
        assert!(!reparsed.proxy.rate_limit.risk_gated_burst);
    }

    /// PR 69 Change 1: `min_calls_for_baseline` from TOML must reach the
    /// proxy config struct (previously the daemon hard-coded 20 even when
    /// `config/default.toml` advertised 200).
    #[test]
    fn test_behavioural_config_keys_wired() {
        let toml_str = r#"
[proxy.filters.behavioural]
enabled = true
min_calls_for_baseline = 200
mild_deviation_score = 0.75
significant_deviation_score = 4.25
"#;
        let config: GrithConfig = toml::from_str(toml_str).unwrap();
        assert!(config.proxy.filters.behavioural.enabled);
        assert_eq!(config.proxy.filters.behavioural.min_calls_for_baseline, 200);
        let proxy_cfg = config.proxy.filters.behavioural.to_proxy_config();
        assert_eq!(proxy_cfg.min_calls_for_baseline, 200);
        assert_eq!(proxy_cfg.mild_deviation_score, 0.75);
        assert_eq!(proxy_cfg.significant_deviation_score, 4.25);
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

    #[test]
    fn test_notify_routing_canonicalises_legacy_filter_override_keys() {
        // A pre-rename config carries snake_case filter names in
        // notifications.routing.filter_overrides. The routing engine
        // matches keys against live kebab-case filter names, so the
        // handoff must normalise them.
        let mut routing = NotifyRoutingConfig::default();
        routing
            .filter_overrides
            .insert("dlp_gate".to_string(), vec!["slack".to_string()]);
        routing
            .filter_overrides
            .insert("secret_scan".to_string(), vec!["email".to_string()]);
        routing
            .filter_overrides
            .insert("canary".to_string(), vec!["pagerduty".to_string()]);

        let canonical = routing.canonical_filter_overrides();
        assert_eq!(canonical.get("dlp-gate"), Some(&vec!["slack".to_string()]));
        assert_eq!(
            canonical.get("secret-scan"),
            Some(&vec!["email".to_string()])
        );
        assert_eq!(
            canonical.get("canary"),
            Some(&vec!["pagerduty".to_string()])
        );
        assert!(!canonical.contains_key("dlp_gate"));
        assert!(!canonical.contains_key("secret_scan"));
    }
}
