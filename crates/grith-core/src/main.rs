// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Entry point for the grith daemon binary.
//!
//! Parses CLI arguments, loads configuration, initializes the daemon, and
//! dispatches to the appropriate subcommand or interactive REPL.

mod agent;
mod analytics_sync;
mod browser;
mod commands;
mod config;
mod daemon;
mod error;
mod helpers;
mod license;
mod logging;
mod profile_manifest;
mod profile_updates;
mod update_check;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "grith", version, about = "Zero Trust for AI Agents")]
struct Cli {
    /// Path to configuration file
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, global = true)]
    log_level: Option<String>,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    /// Override the project name (defaults to current directory name)
    #[arg(long, global = true)]
    project: Option<String>,

    /// Skip the first-run onboarding flow (also via GRITH_SKIP_ONBOARDING)
    #[arg(long, global = true)]
    skip_onboarding: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Execute a single task non-interactively
    Run {
        /// The task to execute
        task: String,
    },
    /// Run the interactive first-run setup (welcome, provider, trial, guide)
    #[command(alias = "onboarding")]
    Setup,
    /// Create default configuration
    Init,
    /// Show or modify configuration
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    /// Browse audit logs
    Audit {
        #[command(subcommand)]
        action: Option<AuditAction>,
    },
    /// Manage digest queue
    Digest {
        #[command(subcommand)]
        action: Option<DigestAction>,
    },
    /// Manage canary tokens used for exfiltration trap detection
    Canary {
        #[command(subcommand)]
        action: CanaryAction,
    },
    /// Security proxy commands
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },
    /// Supervise an external CLI tool with OS-level syscall interception
    Exec {
        /// Tool profile to use (e.g., claude-code, codex, aider, generic)
        #[arg(long)]
        profile: Option<String>,

        /// Attach to an existing process by PID instead of spawning
        #[arg(long)]
        attach: Option<u32>,

        /// Log every syscall request and decision to a file for post-session review
        #[arg(long)]
        syscall_log: Option<std::path::PathBuf>,

        /// Write raw pre-filter syscall forensics records to a JSONL file
        #[arg(long)]
        trace_syscalls_jsonl: Option<std::path::PathBuf>,

        /// In a non-interactive session (no terminal), allow + log queued
        /// operations instead of the default fail-closed auto-deny. Has no
        /// effect in an interactive session (the approval dialog is shown).
        #[arg(long)]
        allow_queued: bool,

        /// Restrict file access to the workspace: the directory grith exec was
        /// launched in, its linked git worktrees, and any configured
        /// additional_project_roots. Reads and writes anywhere else are denied
        /// instead of scored. System runtime paths stay readable and the
        /// profile's routine paths still work, or the tool could not run.
        #[arg(long)]
        workspace_only: bool,

        /// The command and arguments to supervise (after --)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// List or manage active supervisor sessions
    Supervisor {
        #[command(subcommand)]
        action: Option<SupervisorAction>,
    },
    /// Manage the grith daemon (dashboard server + shared subsystems)
    #[command(alias = "dashboard")]
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Manage Pro plan: login, status, sync, activate, logout
    Pro {
        #[command(subcommand)]
        action: ProAction,
    },
    /// Manage cloud analytics sync for this machine
    Analytics {
        #[command(subcommand)]
        action: AnalyticsAction,
    },
    /// Manage notification channels
    Notifications {
        #[command(subcommand)]
        action: NotificationsAction,
    },
    /// View audit-backed session logs
    Log {
        /// Follow new log entries (tail mode)
        #[arg(long)]
        tail: bool,
        /// Session filter: UUID session_id or session name (task context)
        #[arg(long)]
        session: Option<String>,
        /// Max records to read per poll / view
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Manage supervisor profiles
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Manage the reputation system
    Reputation {
        #[command(subcommand)]
        action: ReputationAction,
    },
    /// Generate a shell completion script for grith
    Completions {
        /// Target shell (bash, zsh, fish, elvish, powershell)
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Set a configuration value
    Set {
        /// Configuration key (dot-separated, e.g. proxy.auto_deny_threshold)
        key: String,
        /// Value to set
        value: String,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Inspect the audit chain: verification outcome, forks, gaps (read-only)
    Diagnose,
    /// Export audit logs as JSON or CSV
    Export {
        /// Output format
        #[arg(long, default_value = "json")]
        format: String,
        /// Number of records to skip (newest first)
        #[arg(long, default_value = "0")]
        offset: usize,
        /// Maximum number of records to return
        #[arg(long, default_value = "1000")]
        limit: usize,
    },
    /// Reclaim free pages left by pruning: rewrites + atomically swaps the audit
    /// database. A manual maintenance op (never automatic); requires that no
    /// daemon is running and the chain is not quarantined.
    Compact {
        /// Proceed without the interactive confirmation prompt (for scripts).
        #[arg(long)]
        yes: bool,
    },
    /// Rebuild the analytics projection from the audit database and cold archives
    RebuildAnalytics {
        /// Proceed without the interactive confirmation prompt (for scripts).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum DigestAction {
    /// Interactive digest review
    Review,
}

#[derive(Subcommand)]
enum CanaryAction {
    /// List registered canary tokens
    List,
    /// Add a canary token
    Add {
        /// Human-readable canary label
        #[arg(long)]
        label: String,
        /// Canary value to detect (omit with --generate)
        #[arg(long)]
        value: Option<String>,
        /// Generate a random canary value
        #[arg(long)]
        generate: bool,
    },
    /// Remove a canary token by ID
    Remove {
        /// Canary token ID
        id: String,
    },
    /// Rotate a canary token by ID (keeps label, replaces value)
    Rotate {
        /// Canary token ID
        id: String,
        /// New canary value (omit with --generate)
        #[arg(long)]
        value: Option<String>,
        /// Generate a random replacement value
        #[arg(long)]
        generate: bool,
    },
}

#[derive(Subcommand)]
enum ProxyAction {
    /// Dry-run a tool call against the proxy.
    ///
    /// Exit codes: 0 = allow, 1 = queue, 2 = deny.
    Test {
        /// Tool call to test (JSON)
        call: String,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon (dashboard server + shared subsystems) as a background process
    Start,
    /// Stop the running daemon
    Stop,
    /// Restart the daemon (stop the running one, then start this build)
    Restart,
    /// Check if the daemon is running
    Status,
    /// Authorise a browser for the dashboard (mints a single-use pairing link)
    Pair,
}

#[derive(Subcommand)]
enum ProAction {
    /// Authenticate with grith.ai (device auth by default, API key optional)
    Login {
        /// API key from dashboard Settings (optional; when omitted, uses browser device auth)
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Show plan status, license expiry, team info
    Status,
    /// Fetch and activate a fresh license
    Activate,
    /// Force an on-demand license refresh against grith.ai
    Refresh,
    /// Remove credentials and license
    Logout,
    /// Pull team policies, shared configs and provider keys; push reputation data
    Sync,
    /// Open the upgrade/pricing page in the default browser
    Upgrade,
    /// Start a free Pro trial (one-click when available, else opens signup)
    #[command(name = "start-trial")]
    StartTrial,
    /// Show current plan and billing details; open billing portal in browser
    Billing,
}

#[derive(Subcommand)]
enum SupervisorAction {
    /// List active supervisor sessions
    List,
    /// Show details of a specific session
    Status {
        /// Session ID (UUID)
        session_id: String,
    },
    /// Terminate a supervisor session and detach from the process
    Kill {
        /// Session ID (UUID)
        session_id: String,
    },
}

#[derive(Subcommand)]
pub enum AnalyticsAction {
    /// Show cloud analytics sync status for this machine
    Status,
    /// Rebuild archived days from cloud storage and check they still match
    /// the analytics the server accepted
    VerifyArchives {
        /// First UTC day to check (YYYY-MM-DD). Defaults to 30 days ago.
        #[arg(long)]
        from: Option<String>,
        /// Last UTC day to check (YYYY-MM-DD). Defaults to yesterday.
        #[arg(long)]
        to: Option<String>,
    },
    /// Turn on cloud analytics sync (records your consent)
    Enable {
        /// Skip the interactive confirmation prompt (for scripts)
        #[arg(long)]
        yes: bool,
    },
    /// Turn off cloud analytics sync on this machine
    Disable,
}

#[derive(Subcommand)]
enum NotificationsAction {
    /// Show notification channel status and health
    Status,
    /// List all available notification channels
    Channels,
    /// Send a test notification to a specific channel
    Test {
        /// Channel ID to test (e.g., desktop, slack, telegram)
        channel: String,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    /// Audit a forensic trace file against a profile
    Audit {
        /// Profile name to audit against (e.g., claude-code)
        #[arg(long)]
        profile: String,
        /// Path to the JSONL trace file from --trace-syscalls-jsonl
        #[arg(long)]
        trace: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum ReputationAction {
    /// Show the learned reputation table with trust scores
    Show {
        /// Filter by profile name
        #[arg(long)]
        profile: Option<String>,
    },
    /// Reset all learned reputation data
    Reset {
        /// Only reset reputation for a specific profile
        #[arg(long)]
        profile: Option<String>,
    },
}

/// Commands that can host the interactive upgrade prompt: it reads stdin and
/// exits the process on accept, so it only belongs where the user is sitting
/// at a prompt and re-running is one keystroke.
fn command_supports_update_check(command: Option<&Command>) -> bool {
    matches!(command, None | Some(Command::Run { .. }))
}

/// Commands that get the non-interactive notice instead. `exec` hands stdin to
/// the supervised tool and must go on to actually launch it, so it cannot take
/// the prompt — but its users are the ones least likely to open a REPL and see
/// one, so silence would leave them on an old binary indefinitely.
fn command_supports_update_notice(command: Option<&Command>) -> bool {
    matches!(command, Some(Command::Exec { .. }))
}

fn command_supports_profile_refresh(command: Option<&Command>) -> bool {
    matches!(
        command,
        None | Some(Command::Run { .. }) | Some(Command::Exec { .. })
    )
}

/// Whether the first-run onboarding wizard should auto-trigger. Restricted to
/// the interactive entry points (REPL / `grith run`) on a real TTY, when the
/// install is not yet onboarded and the user has not opted out.
#[allow(clippy::fn_params_excessive_bools)]
fn should_auto_run_onboarding(
    command: Option<&Command>,
    onboarded: bool,
    stdin_is_tty: bool,
    stdout_is_tty: bool,
    skip: bool,
) -> bool {
    !onboarded
        && !skip
        && stdin_is_tty
        && stdout_is_tty
        && matches!(command, None | Some(Command::Run { .. }))
}

/// Whether a `grith exec` invocation is actually launching/attaching to a
/// supervised tool (as opposed to a session-management alias like
/// `grith exec list|kill|prune`). Mirrors the management-verb dispatch in
/// `commands::exec`, which only treats bare verbs as management when there is
/// no `--` separator, profile, or attach target.
fn exec_launches_supervised_tool(
    profile: Option<&str>,
    attach: Option<u32>,
    command: &[String],
    has_separator: bool,
) -> bool {
    if attach.is_some() {
        return true; // attaching to a live pid is supervision
    }
    if profile.is_some() || has_separator {
        return !command.is_empty();
    }
    // No profile / attach / separator: a bare management verb is not a launch.
    let is_management = matches!(command, [v] if v == "list" || v == "kill" || v == "prune")
        || matches!(command, [v, _] if v == "kill");
    !command.is_empty() && !is_management
}

/// The tool name to surface in the exec first-run notice, if one is being
/// launched (the first non-separator argument).
fn exec_tool_name(command: &[String]) -> Option<&str> {
    command.first().map(String::as_str)
}

/// Whether an environment variable is set to a truthy value
/// (`1`/`true`/`yes`/`on`, case-insensitive). Absent or any other value
/// (including `0`/`false`) is falsy.
fn env_truthy(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| value_is_truthy(&v))
}

/// Pure truthiness check for a config/env string value.
fn value_is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn should_refresh_profiles(
    command: Option<&Command>,
    profile_update_check_enabled: bool,
    env_disabled: bool,
) -> bool {
    profile_update_check_enabled && !env_disabled && command_supports_profile_refresh(command)
}

/// Gating for the notice. Deliberately not the same set as
/// [`should_check_updates`]: there is no stdin requirement because nothing is
/// read from it. stderr must still be a terminal, so redirected logs and CI
/// output stay clean.
fn should_notify_update(
    command: Option<&Command>,
    stderr_is_tty: bool,
    update_check_enabled: bool,
    env_disabled: bool,
) -> bool {
    update_check_enabled
        && stderr_is_tty
        && !env_disabled
        && command_supports_update_notice(command)
}

#[allow(clippy::fn_params_excessive_bools)]
fn should_check_updates(
    command: Option<&Command>,
    stdin_is_tty: bool,
    stderr_is_tty: bool,
    update_check_enabled: bool,
    env_disabled: bool,
) -> bool {
    update_check_enabled
        && stdin_is_tty
        && stderr_is_tty
        && !env_disabled
        && command_supports_update_check(command)
}

/// Publish the PID file, IPC token and identity file for a dashboard hosted
/// **in-process** by `grith run` / the REPL (rather than by a spawned daemon).
///
/// Returns whether all three landed: a partial publish is retracted here, so
/// callers only ever see "this process is discoverable as the daemon" or
/// "nothing was claimed".
fn publish_in_process_daemon(
    ipc_token: &str,
    port: u16,
    identity: &crate::daemon::identity::DaemonIdentity,
) -> bool {
    let pid = std::process::id();
    if let Err(e) = daemon::write_dashboard_pid(pid, port) {
        tracing::warn!(error = %e, "failed to write dashboard PID file");
        return false;
    }
    if let Err(e) = crate::daemon::token::write_token(ipc_token) {
        tracing::warn!(error = %e, "failed to write daemon IPC token");
        let _ = daemon::remove_dashboard_pid();
        return false;
    }
    if let Err(e) = crate::daemon::identity::publish(identity) {
        // Same degradation `cmd_dashboard_start` accepts: the daemon is still
        // reachable and authenticable, only the restart path's identity check
        // falls back to "unidentified".
        tracing::warn!(error = %e, "failed to publish the daemon identity file");
    }
    tracing::info!(event = "in_process_daemon_published", pid, port);
    true
}

/// Retract what [`publish_in_process_daemon`] wrote.
///
/// Every removal is guarded on the artefact still being *ours*: a successor
/// daemon that took the port while we were shutting down must keep its own
/// identity, and deleting its token would lock out every session it is
/// serving.
fn retract_in_process_daemon(ipc_token: &str) {
    let self_pid = std::process::id();
    if crate::daemon::pid::read_dashboard_pid().is_some_and(|(pid, _)| pid == self_pid) {
        let _ = daemon::remove_dashboard_pid();
        daemon::remove_dashboard_opened();
    }
    if crate::daemon::token::read_token().is_some_and(|t| t == ipc_token) {
        let _ = crate::daemon::token::remove_token();
    }
    if crate::daemon::identity::read().is_some_and(|id| id.pid == self_pid) {
        crate::daemon::identity::remove();
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let enable_color = helpers::color_enabled(cli.no_color);
    let project_override = cli.project.clone();

    if matches!(&cli.command, Some(Command::Init)) {
        return cmd_init();
    }

    // Completion-script generation is a pure stdout emit — handle it before any
    // config load or logging init so it works regardless of config state.
    if let Some(Command::Completions { shell }) = &cli.command {
        let mut cmd = Cli::command();
        let bin_name = cmd.get_name().to_string();
        clap_complete::generate(*shell, &mut cmd, bin_name, &mut std::io::stdout());
        return Ok(());
    }

    // Load configuration
    // Warnings are carried to after logging init rather than emitted here:
    // `logging::init` is a dozen lines below, so anything raised now is
    // dropped. They must NOT go through `validate()` either - main bails on
    // any issue it returns, so a stale key would lock an operator out of
    // their own tool over a diagnostic.
    let (mut cfg, config_key_warnings) =
        config::GrithConfig::load_reporting_unknown(cli.config.as_deref())?;

    // CLI flag override for log level
    if let Some(level) = &cli.log_level {
        cfg.general.log_level = level.clone();
    }

    // Reported before `validate()`, and on stderr rather than through
    // tracing: a key in the wrong section is a plausible REASON for an
    // invalid config, so the operator must see it even on the path that
    // bails. Logging is not initialised yet either, so a `warn!` here would
    // be dropped.
    //
    // Never routed through `validate()` itself - main bails on any issue it
    // returns, and locking an operator out of their own tool over a stale key
    // is a worse failure than the key being ignored.
    if !config_key_warnings.is_empty() {
        // `grith exec` on a TTY and `grith setup` are the sessions run most
        // often; a line per key would push the supervised tool down the
        // screen on every launch. They get the count and the fix instead.
        let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
        let stdout_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
        let terse =
            (matches!(&cli.command, Some(Command::Exec { .. })) && stdout_is_tty && stdin_is_tty)
                || matches!(&cli.command, Some(Command::Setup));
        if terse {
            let sources: std::collections::BTreeSet<&str> = config_key_warnings
                .iter()
                .map(|w| w.source.as_str())
                .collect();
            eprintln!(
                "grith: {} setting(s) in {} are being ignored; run any other \
                 grith command to list them",
                config_key_warnings.len(),
                sources.into_iter().collect::<Vec<_>>().join(", ")
            );
        } else {
            for warning in &config_key_warnings {
                eprintln!("grith: {warning}");
            }
        }
    }

    // Validate configuration
    let issues = cfg.validate();
    if !issues.is_empty() {
        anyhow::bail!("configuration invalid:\n{}", issues.join("\n"));
    }

    // Initialize logging
    logging::init(&cfg.general.log_level);

    // Suppress tracing for `exec` sessions with a TTY so logs don't clutter
    // the terminal while the supervised tool runs.
    let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let stdout_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let stderr_is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let exec_quiet =
        matches!(&cli.command, Some(Command::Exec { .. })) && stdout_is_tty && stdin_is_tty;
    // `grith setup` is a clean interactive screen — suppress the startup log
    // line so it doesn't print above the welcome.
    let setup_quiet = matches!(&cli.command, Some(Command::Setup));
    if !exec_quiet && !setup_quiet {
        tracing::info!(version = env!("CARGO_PKG_VERSION"), "grith starting");
    } else {
        logging::suppress();
    }

    // Onboarding opt-out, resolved once (CLI flag or truthy env var).
    let skip_onboarding = cli.skip_onboarding || env_truthy("GRITH_SKIP_ONBOARDING");

    // First-run notice for `grith exec`: a single non-blocking line, never a
    // wizard. Shown at most once, then the supervised tool launches normally.
    if let Some(Command::Exec {
        profile,
        attach,
        command,
        ..
    }) = &cli.command
    {
        let has_separator = std::env::args_os().any(|a| a == "--");
        if !cfg.general.onboarded
            && !cfg.general.exec_notice_seen
            && !skip_onboarding
            && exec_launches_supervised_tool(profile.as_deref(), *attach, command, has_separator)
        {
            commands::onboarding::show_exec_notice_once(&mut cfg, exec_tool_name(command));
        }
    }

    // Check for updates on REPL / `run` launches when interactive and enabled.
    if should_check_updates(
        cli.command.as_ref(),
        stdin_is_tty,
        stderr_is_tty,
        cfg.general.update_check,
        std::env::var_os("GRITH_NO_UPDATE_CHECK").is_some(),
    ) && update_check::check_and_prompt(enable_color)?
    {
        return Ok(()); // user upgraded — exit so they re-run with new binary
    }

    // Supervised launches get the same news without the prompt: one line from
    // a cached answer, then straight on to the tool.
    if should_notify_update(
        cli.command.as_ref(),
        stderr_is_tty,
        cfg.general.update_check,
        std::env::var_os("GRITH_NO_UPDATE_CHECK").is_some(),
    ) {
        update_check::maybe_notify(enable_color);
    }

    // Check for remote profile overlay updates (silent, TTL-gated).
    // Unlike binary updates, this has no TTY requirement and includes `exec`.
    if should_refresh_profiles(
        cli.command.as_ref(),
        cfg.general.profile_update_check,
        std::env::var_os("GRITH_NO_PROFILE_UPDATE").is_some(),
    ) {
        profile_updates::maybe_refresh();
    }

    // Handle commands that don't need daemon initialization
    match &cli.command {
        Some(Command::Setup) => {
            return commands::onboarding::run_setup(&mut cfg, enable_color);
        }
        Some(Command::Config { action: None }) => {
            println!("{}", cfg.to_toml()?);
            return Ok(());
        }
        Some(Command::Config {
            action: Some(ConfigAction::Set { key, value }),
        }) => return cmd_config_set(&mut cfg, key, value),
        Some(Command::Daemon {
            action: DaemonAction::Stop,
        }) => {
            return commands::dashboard::cmd_dashboard_stop(cfg.server.port);
        }
        Some(Command::Daemon {
            action: DaemonAction::Restart,
        }) => {
            if !cfg.server.enabled {
                println!("Dashboard server is disabled (server.enabled = false in config).");
                return Ok(());
            }
            return commands::dashboard::cmd_dashboard_restart(
                cfg.server.port,
                cfg.server.auto_open_dashboard,
                cli.config.as_deref(),
            );
        }
        Some(Command::Daemon {
            action: DaemonAction::Status,
        }) => {
            return commands::dashboard::cmd_dashboard_status(cfg.server.port);
        }
        Some(Command::Daemon {
            action: DaemonAction::Pair,
        }) => {
            return commands::dashboard::cmd_dashboard_pair(cfg.server.auto_open_dashboard);
        }
        // User-invoked `grith dashboard start`: background-spawn the daemon and
        // print connection details here, BEFORE constructing a daemon in this
        // parent process (which would spam tracing logs the user shouldn't see).
        // The detached child carries GRITH_DASHBOARD_CHILD and falls through to
        // run the server in the foreground below.
        Some(Command::Daemon {
            action: DaemonAction::Start,
        }) if std::env::var_os("GRITH_DASHBOARD_CHILD").is_none() => {
            if cfg.server.enabled {
                commands::dashboard::ensure_dashboard_running_with_port(
                    cfg.server.port,
                    cfg.server.auto_open_dashboard,
                    true, // explicit start → persist until `grith dashboard stop`
                    cli.config.as_deref(),
                );
            } else {
                println!("Dashboard server is disabled (server.enabled = false in config).");
            }
            return Ok(());
        }
        Some(Command::Pro {
            action: ProAction::Login { ref api_key },
        }) => return commands::pro::cmd_pro_login(api_key.as_deref()),
        Some(Command::Pro {
            action: ProAction::Status,
        }) => return commands::pro::cmd_pro_status(),
        Some(Command::Pro {
            action: ProAction::Activate,
        }) => return commands::pro::cmd_pro_activate(),
        Some(Command::Pro {
            action: ProAction::Refresh,
        }) => return commands::pro::cmd_pro_refresh(),
        Some(Command::Pro {
            action: ProAction::Logout,
        }) => return commands::pro::cmd_pro_logout(),
        Some(Command::Pro {
            action: ProAction::Upgrade,
        }) => return commands::pro::cmd_pro_upgrade(),
        Some(Command::Pro {
            action: ProAction::StartTrial,
        }) => return commands::pro::cmd_pro_start_trial(),
        Some(Command::Pro {
            action: ProAction::Billing,
        }) => return commands::pro::cmd_pro_billing(),
        Some(Command::Profile {
            action:
                ProfileAction::Audit {
                    ref profile,
                    ref trace,
                },
        }) => return commands::profile_audit::run_audit(profile, trace),
        _ => {}
    }

    let thin_client_command = matches!(
        cli.command,
        Some(Command::Exec { .. })
            | Some(Command::Supervisor { .. })
            | Some(Command::Reputation { .. })
    );
    if thin_client_command && cfg.server.enabled {
        // work/74 Phase 0: `grith exec` must fail closed. Establish an
        // authenticated, version-compatible daemon connection or refuse to
        // run — never fall through to an in-process daemon, which would give
        // this process its own empty session registry (bypassing the plan's
        // concurrent-session cap) and a second writer on the audit chain.
        let is_exec = matches!(cli.command, Some(Command::Exec { .. }));
        let config_path = cli.config.clone();
        let server_port = cfg.server.port;
        let auto_open = cfg.server.auto_open_dashboard;
        let readiness = crate::daemon::readiness::ensure_daemon_ready(server_port, || {
            commands::dashboard::ensure_dashboard_running_with_port(
                server_port,
                auto_open,
                // Auto-started for `grith exec`/supervisor — idle-shutdown
                // after the session ends.
                false,
                config_path.as_deref(),
            )
            .map(|_| ())
            .ok_or_else(|| "daemon auto-start did not report a listener".to_string())
        });

        let daemon_client = match readiness {
            Ok(client) => Some(client),
            Err(unready) => {
                if is_exec {
                    // Fail closed: no in-process fallback, no target started.
                    tracing::error!(
                        event = "daemon_unready_exec_refused",
                        code = unready.code(),
                        "refusing to start a supervised session without a daemon"
                    );
                    eprintln!("{}", unready.user_message());
                    return Err(anyhow::anyhow!(
                        "daemon not ready ({}) — no supervised session was started",
                        unready.code()
                    ));
                }
                // Non-exec thin commands (`supervisor`, `reputation`) are
                // read-mostly and may still run locally; they do not admit
                // sessions. Surface why the remote path was unavailable.
                tracing::warn!(
                    event = "daemon_unready",
                    code = unready.code(),
                    "daemon unavailable for thin-client command"
                );
                None
            }
        };

        if let Some(daemon_client) = daemon_client {
            match cli.command {
                Some(Command::Exec {
                    profile,
                    attach,
                    syscall_log,
                    trace_syscalls_jsonl,
                    allow_queued,
                    workspace_only,
                    command,
                }) => {
                    return commands::exec::cmd_exec_thin(
                        &cfg,
                        daemon_client,
                        profile,
                        attach,
                        syscall_log,
                        trace_syscalls_jsonl,
                        allow_queued,
                        workspace_only,
                        command,
                        project_override.as_deref(),
                        cli.config.as_deref(),
                    );
                }
                Some(Command::Supervisor { action }) => {
                    return commands::supervisor::cmd_supervisor_remote(&daemon_client, action);
                }
                Some(Command::Reputation { action }) => {
                    return cmd_reputation_remote(&daemon_client, action);
                }
                _ => {}
            }
        }
    }

    // First-run onboarding auto-trigger. Runs only on the interactive entry
    // points (REPL / `grith run`) on a real TTY, before the daemon starts —
    // so any provider / audit-sync choices apply to this same process. The
    // flow persists `onboarded = true` so it does not re-trigger.
    if should_auto_run_onboarding(
        cli.command.as_ref(),
        cfg.general.onboarded,
        stdin_is_tty,
        stdout_is_tty,
        skip_onboarding,
    ) {
        commands::onboarding::run_onboarding(&mut cfg, enable_color)?;
    }

    // Initialize the daemon for commands that need subsystems.
    //
    // The `daemon start` command only reaches this point as the detached
    // serving child, which must own the audit database or fail loudly: a
    // daemon that cannot write audit records breaks every session it admits
    // (required DNS audit records fail, and DNS is denied fail-closed).
    // Every other command degrades to a read-only audit view as before.
    let start_options = if matches!(
        cli.command,
        Some(Command::Daemon {
            action: DaemonAction::Start
        })
    ) {
        daemon::StartOptions::serving_daemon()
    } else {
        daemon::StartOptions::default()
    };
    // The detached daemon child's stderr is on /dev/null, so a fatal startup
    // error here — most often "another process still owns the audit database,
    // held by pid N" — would otherwise vanish, leaving the spawner to report
    // only "did not become ready". Record it where the spawner can print it.
    let dashboard_child = std::env::var_os("GRITH_DASHBOARD_CHILD").is_some();
    let init_result = daemon::Daemon::start(cfg, start_options).inspect_err(|e| {
        if dashboard_child {
            daemon::last_error::record(&e.to_string());
        }
    })?;

    for warning in &init_result.warnings {
        tracing::warn!("{warning}");
    }

    let daemon = init_result.daemon;

    // Handle `grith dashboard start` — run server in foreground (for background spawning).
    if matches!(
        cli.command,
        Some(Command::Daemon {
            action: DaemonAction::Start
        })
    ) {
        // Only reached for the detached child (GRITH_DASHBOARD_CHILD set); the
        // user-invoked case background-spawned and returned in the early match
        // above. Run the server in the foreground (this process's stdout is
        // /dev/null, redirected by the parent that spawned it).
        return commands::dashboard::cmd_dashboard_start(&daemon).inspect_err(|e| {
            if dashboard_child {
                daemon::last_error::record(&format!("{e:#}"));
            }
        });
    }

    // Auto-start the dashboard for commands that benefit from web UI monitoring.
    // This includes `grith run`, `grith` (REPL), and `grith exec`.
    let wants_dashboard = matches!(
        cli.command,
        None | Some(Command::Run { .. }) | Some(Command::Exec { .. })
    );
    let dashboard_url = if wants_dashboard && daemon.config.server.enabled {
        commands::dashboard::ensure_dashboard_running(&daemon, cli.config.as_deref())
    } else {
        None
    };

    let wants_agent = matches!(cli.command, None | Some(Command::Run { .. }));
    let wants_server = wants_agent && daemon.config.server.enabled && dashboard_url.is_none();

    if wants_server {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let server_config = to_server_config(&daemon.config.server);
        let server_config_port = server_config.port;
        let sync_api_key = crate::license::load_credentials()
            .ok()
            .flatten()
            .map(|creds| creds.api_key);
        let sync_api_base_url = Some(crate::license::api_base_url());
        let ipc_token = crate::daemon::token::generate_token();
        // Reuse the persisted dashboard token across restarts so an open
        // browser tab stays authorised (see `get_or_create_dashboard_token`).
        let dashboard_token = crate::daemon::token::get_or_create_dashboard_token();

        let deps = grith_server::ServerDeps {
            audit_storage: daemon.audit_storage.clone(),
            digest_queue: daemon.digest_queue.clone(),
            proxy: daemon.proxy.clone(),
            supervisor_registry: daemon.supervisor_registry.clone(),
            containment_tracker: daemon.containment_tracker.clone(),
            correlation_tracker: daemon.correlation_tracker.clone(),
            canary_registry: daemon.canary_registry.clone(),
            notification_dispatcher: daemon.notification_dispatcher.clone(),
            audit_db_path: helpers::expand_user_path(&daemon.config.general.audit_dir)
                .join("audit.db"),
            dns_seed_domains: daemon::config_loader::load_egress_policy_config()?.trusted_domains,
            reputation_table: daemon.reputation_table.clone(),
            reputation_config: daemon.config.reputation.to_proxy_config(),
            sync_api_key: sync_api_key.clone(),
            sync_api_base_url: sync_api_base_url.clone(),
        };
        // This process *is* the daemon for as long as it runs: it owns the
        // audit writer lock and serves the same IPC routes a spawned daemon
        // would. Until now it published nothing, so it was a listener no
        // other grith process could authenticate to or identify — a
        // `grith exec` in another terminal met a Grith daemon of the right
        // version, found no PID file and no token on disk, and failed with
        // `token_rejected` naming a `dashboard restart` that could not stop
        // it either. Publish the same three artefacts `cmd_dashboard_start`
        // does, on the same terms: only into a port nothing else owns, and
        // before the listener starts, so a `grith exec` racing us finds a
        // complete identity or none at all. (Publishing from the
        // `on_listening` callback instead loses that race the other way: a
        // short-lived `grith run` can finish before the server task is even
        // polled, and would then leave the files behind unretracted.)
        let identity = crate::daemon::identity::DaemonIdentity::new(
            server_config_port,
            env!("CARGO_PKG_VERSION"),
            Some(
                helpers::expand_user_path(&daemon.config.general.audit_dir)
                    .join("audit.db")
                    .to_string_lossy()
                    .into_owned(),
            ),
        );
        let published = matches!(
            crate::daemon::readiness::probe_port(server_config_port),
            crate::daemon::readiness::PortProbe::Vacant
        ) && publish_in_process_daemon(&ipc_token, server_config_port, &identity);
        let server = grith_server::GrithServer::new(
            server_config,
            deps,
            env!("CARGO_PKG_VERSION"),
            daemon.subscribe_shutdown(),
        )
        .with_instance_identity(
            identity.instance_id.to_string(),
            crate::daemon::identity::IPC_PROTOCOL_VERSION,
        )
        .with_plan_tier(&daemon.config.general.plan_tier)
        .with_account_id(&daemon.account_id)
        .with_feature_gate(daemon.feature_gate.clone())
        .with_license_valid_until(daemon.license_valid_until.clone())
        .with_billing_portal_url(daemon.billing_portal_url.clone())
        .with_refresh_state(daemon.refresh_state.clone())
        .with_ipc_token(ipc_token.clone())
        .with_dashboard_token(dashboard_token.clone())
        .with_sync_api(sync_api_key, sync_api_base_url);

        let addr = server.address();
        let ws_tx = server.ws_sender();
        // Mint the browser pairing code before `server` is moved into the spawn
        // below; the token is handed off via a single-use `#pair=` code, never
        // printed.
        let pair_code = server.mint_pair_code();

        {
            // Enter the runtime: the telegram channel's callback poller uses
            // `tokio::spawn`, which needs an active runtime context. This call
            // sits outside `runtime.block_on`/`spawn`, so without the guard it
            // panics and crashes the daemon when telegram is enabled.
            let _enter = runtime.enter();
            daemon.register_notification_channels(Some(ws_tx.clone()));
        }

        runtime.spawn({
            let ipc_token = ipc_token.clone();
            async move {
                if let Err(e) = server.start().await {
                    // Most often EADDRINUSE from a listener that appeared
                    // between our probe and the bind. We published a PID file
                    // and token for a listener that does not exist, so take
                    // them back rather than leaving the next `grith exec`
                    // authenticating at nothing.
                    tracing::error!(error = %e, "server failed");
                    if published {
                        retract_in_process_daemon(&ipc_token);
                    }
                }
            }
        });

        let (license_handle, mut notification_handles) = runtime.block_on(async {
            let license_handle = daemon.spawn_license_revalidation();
            // Re-apply the license gate immediately on SIGHUP (sent by
            // `grith pro login`/`refresh` after writing a new license), so a
            // fresh upgrade takes effect without a 24h wait or restart. The
            // task detaches and self-terminates on the shutdown broadcast.
            let _regate_handle = daemon.spawn_license_regate_on_sighup();
            // Cloud analytics upload worker — owner only (one uploader per
            // audit database); it self-gates on entitlement + consent. This
            // replaced the raw audit-record sync, which was retired with the
            // server's /sync route.
            if daemon.audit_role.can_write() {
                let _analytics_handle = daemon.spawn_analytics_upload();
            }
            let notification_handles = daemon
                .notification_dispatcher
                .spawn_background_tasks(daemon.subscribe_shutdown());
            (license_handle, notification_handles)
        });

        tracing::info!(address = %addr, "dashboard available at http://{}", addr);
        // Hand the token to the browser via a single-use `#pair=` code (never
        // the raw token), auto-opening at most once per daemon (keyed by PID).
        let base = format!("http://{addr}");
        let self_pid = std::process::id();
        if crate::daemon::dashboard_already_opened(self_pid) {
            println!("Dashboard: {base}");
        } else {
            let pair = format!("{base}/#pair={pair_code}");
            if browser::maybe_open_dashboard(daemon.config.server.auto_open_dashboard, &pair) {
                println!("Dashboard: {base}  (opened in your browser)");
                crate::daemon::mark_dashboard_opened(self_pid);
            } else {
                println!("Dashboard: {base}");
                println!("  Open this once to authorise your browser: {pair}");
            }
        }

        let result = match cli.command {
            None => commands::run::cmd_repl(
                &daemon,
                Some(ws_tx),
                None,
                project_override.as_deref(),
                enable_color,
            ),
            Some(Command::Run { task }) => commands::run::cmd_run(
                &daemon,
                &task,
                Some(ws_tx),
                None,
                project_override.as_deref(),
                enable_color,
            ),
            _ => unreachable!(),
        };

        daemon.shutdown();

        // Retract what we published, so the next invocation does not chase a
        // daemon that has gone. Guarded on the files still being ours: a
        // successor daemon that took the port while we were shutting down
        // must keep its own identity.
        if published {
            retract_in_process_daemon(&ipc_token);
        }

        // Join background task handles to surface any panics rather than
        // silently swallowing them.
        runtime.block_on(async {
            if let Err(e) = license_handle.await {
                tracing::warn!(error = %e, "license revalidation task panicked");
            }
            for handle in notification_handles.drain(..) {
                if let Err(e) = handle.await {
                    tracing::warn!(error = %e, "notification background task panicked");
                }
            }
        });
        runtime.shutdown_timeout(std::time::Duration::from_secs(2));
        return result;
    }

    match cli.command {
        None => commands::run::cmd_repl(
            &daemon,
            None,
            dashboard_url.as_deref(),
            project_override.as_deref(),
            enable_color,
        ),
        Some(Command::Run { task }) => commands::run::cmd_run(
            &daemon,
            &task,
            None,
            dashboard_url.as_deref(),
            project_override.as_deref(),
            enable_color,
        ),
        Some(Command::Audit { action }) => commands::audit::cmd_audit(&daemon, action),
        Some(Command::Digest { action }) => commands::digest::cmd_digest(&daemon, action),
        Some(Command::Canary { action }) => commands::canary::cmd_canary(&daemon, action),
        Some(Command::Proxy { action }) => commands::proxy::cmd_proxy(&daemon, action),
        // work/74 Phase 0 + invariant 4: there is no in-process fallback for
        // supervised execution. Reaching here means the thin-client block
        // above did not run — which only happens when the server is disabled
        // in config, since any other failure already returned a fail-closed
        // error. Supervision without a daemon cannot enforce a host-wide
        // session cap or keep a single audit writer, so refuse rather than
        // silently supervising with weaker guarantees.
        Some(Command::Exec { .. }) => {
            eprintln!(
                "Supervised execution requires the local Grith daemon, but `server.enabled` \
                 is false in your configuration.\n\n\
                 No supervised session was started.\n\
                 Set `server.enabled = true` (or remove the override) and retry."
            );
            Err(anyhow::anyhow!(
                "server.enabled = false — no supervised session was started"
            ))
        }
        Some(Command::Supervisor { action }) => {
            commands::supervisor::cmd_supervisor(&daemon, action)
        }
        Some(Command::Analytics { action }) => commands::analytics::cmd_analytics(&daemon, action),
        Some(Command::Notifications { action }) => {
            commands::notifications::cmd_notifications(&daemon, action)
        }
        Some(Command::Pro {
            action: ProAction::Sync,
        }) => commands::pro::cmd_pro_sync(&daemon),
        Some(Command::Log {
            tail,
            session,
            limit,
        }) => commands::log::cmd_log(&daemon, tail, session.as_deref(), limit, enable_color),
        Some(Command::Reputation { action }) => cmd_reputation(action),
        // Already handled above
        Some(Command::Setup)
        | Some(Command::Init)
        | Some(Command::Completions { .. })
        | Some(Command::Config { .. })
        | Some(Command::Daemon { .. })
        | Some(Command::Pro { .. })
        | Some(Command::Profile { .. }) => {
            unreachable!()
        }
    }
}

// --- Simple command handlers that don't need their own file ---

fn cmd_init() -> anyhow::Result<()> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let path = home.join(".config").join("grith").join("config.toml");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let default_toml = {
        let candidates = [
            PathBuf::from("config/default.toml"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../")
                .join("config/default.toml"),
        ];
        let mut last_error = String::new();
        let mut content: Option<String> = None;
        for candidate in &candidates {
            if !candidate.exists() {
                last_error = format!("{} does not exist", candidate.display());
                continue;
            }
            match std::fs::read_to_string(candidate) {
                Ok(raw) => {
                    content = Some(raw);
                    break;
                }
                Err(e) => last_error = format!("failed to read {}: {e}", candidate.display()),
            }
        }
        // Final fallback: read the default.toml baked into the binary
        // at build time. Normal path for users installing via
        // `curl https://grith.ai/install | sh` who have no source
        // checkout on disk.
        if content.is_none() {
            static EMBEDDED: include_dir::Dir<'_> =
                include_dir::include_dir!("$CARGO_MANIFEST_DIR/../../config");
            if let Some(file) = EMBEDDED.get_file("default.toml") {
                if let Some(s) = file.contents_utf8() {
                    content = Some(s.to_string());
                }
            }
        }
        content.ok_or_else(|| {
            anyhow::anyhow!("required config/default.toml unavailable: {last_error}")
        })?
    };
    // A manual `grith init` is an explicit setup action, so mark the config
    // as onboarded — otherwise the next interactive `grith` would launch the
    // first-run wizard on top of the config the user just created. Text
    // insertion (rather than parse/serialize) preserves the template's
    // documentation comments.
    let default_toml = insert_general_flag(&default_toml, "onboarded", "true");
    std::fs::write(&path, default_toml)?;
    println!("Created default config at {}", path.display());
    Ok(())
}

/// Insert `key = value` into the `[general]` table of a TOML document while
/// preserving comments and layout. No-op if an active (non-comment)
/// declaration of `key` already exists. If there is no `[general]` table, one
/// is prepended.
fn insert_general_flag(toml_text: &str, key: &str, value: &str) -> String {
    // The declaration scan is intentionally table-agnostic: it is only ever
    // called with `key = "onboarded"` against the grith config template, where
    // no other table declares that key. A bare-key TOML document before the
    // first table header is not produced by any grith code path.
    let already_declared = toml_text.lines().any(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with('#')
            && trimmed.starts_with(key)
            && trimmed[key.len()..].trim_start().starts_with('=')
    });
    if already_declared {
        return toml_text.to_string();
    }

    let mut out = String::with_capacity(toml_text.len() + key.len() + value.len() + 8);
    let mut inserted = false;
    for line in toml_text.lines() {
        out.push_str(line);
        out.push('\n');
        if !inserted && line.trim() == "[general]" {
            out.push_str(key);
            out.push_str(" = ");
            out.push_str(value);
            out.push('\n');
            inserted = true;
        }
    }
    if !inserted {
        return format!("[general]\n{key} = {value}\n\n{toml_text}");
    }
    out
}

fn cmd_config_set(cfg: &mut config::GrithConfig, key: &str, value: &str) -> anyhow::Result<()> {
    let old = cfg.set_value(key, value)?;
    let path = cfg.save_user_config()?;
    println!("Set {key}: {old} -> {value}");
    println!("Saved to {}", path.display());
    Ok(())
}

// --- Config conversion helpers ---

fn to_server_config(core: &config::ServerConfig) -> grith_server::ServerConfig {
    grith_server::ServerConfig {
        host: core.host.clone(),
        port: core.port,
        enabled: core.enabled,
        dashboard_dir: core.dashboard_dir.clone(),
        tls: core.tls.as_ref().map(|t| grith_server::TlsConfig {
            cert_path: t.cert_path.clone(),
            key_path: t.key_path.clone(),
        }),
        rate_limit: grith_server::RateLimitConfig {
            enabled: core.rate_limit.enabled,
            general_rps: core.rate_limit.general_rps,
            write_rps: core.rate_limit.write_rps,
            proxy_test_rps: core.rate_limit.proxy_test_rps,
            ipc_rps: core.rate_limit.ipc_rps,
        },
    }
}

fn cmd_reputation(action: ReputationAction) -> anyhow::Result<()> {
    let path = grith_proxy::reputation::default_reputation_path();

    match action {
        ReputationAction::Show { profile } => {
            let table = grith_proxy::reputation::ReputationTable::load(&path);
            if table.is_empty() {
                println!("No reputation data. Data is learned from approve/deny decisions during grith exec sessions.");
                return Ok(());
            }

            let mut entries: Vec<_> = table
                .entries
                .iter()
                .filter(|(key, _)| {
                    if let Some(ref p) = profile {
                        key.starts_with(&format!("{p}|"))
                    } else {
                        true
                    }
                })
                .collect();
            entries.sort_by(|a, b| b.1.trust_score().partial_cmp(&a.1.trust_score()).unwrap());

            println!("{:<60} {:>6} {:>6} {:>8}", "KEY", "TRUST", "OBS", "STATUS");
            println!("{}", "-".repeat(84));
            for (key, entry) in &entries {
                let trust = entry.trust_score();
                let obs = entry.observation_count();
                let status = if trust >= 0.92 && obs >= 8.0 {
                    "auto-allow"
                } else if trust < 0.3 && obs >= 5.0 {
                    "distrusted"
                } else {
                    "prompting"
                };
                let truncated = if key.len() > 58 {
                    format!("{}...", &key[..55])
                } else {
                    (*key).clone()
                };
                println!(
                    "{:<60} {:>5.0}% {:>6.1} {:>8}",
                    truncated,
                    trust * 100.0,
                    obs,
                    status
                );
            }
            println!("\n{} entries total.", entries.len());
        }
        ReputationAction::Reset { profile } => {
            let mut table = grith_proxy::reputation::ReputationTable::load(&path);
            if let Some(ref p) = profile {
                let before = table.len();
                table
                    .entries
                    .retain(|key, _| !key.starts_with(&format!("{p}|")));
                let removed = before - table.len();
                table.save(&path)?;
                println!("Reset {removed} reputation entries for profile '{p}'.");
            } else {
                table.reset();
                table.save(&path)?;
                println!("Reset all reputation data.");
            }
        }
    }
    Ok(())
}

fn cmd_reputation_remote(
    daemon_client: &crate::daemon::client::DaemonClient,
    action: ReputationAction,
) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    match action {
        ReputationAction::Show { profile } => {
            let table = runtime.block_on(daemon_client.load_reputation_table())?;
            if table.is_empty() {
                println!("No reputation data. Data is learned from approve/deny decisions during grith exec sessions.");
                return Ok(());
            }

            let mut entries: Vec<_> = table
                .entries
                .iter()
                .filter(|(key, _)| {
                    if let Some(ref p) = profile {
                        key.starts_with(&format!("{p}|"))
                    } else {
                        true
                    }
                })
                .collect();
            entries.sort_by(|a, b| b.1.trust_score().partial_cmp(&a.1.trust_score()).unwrap());

            println!("{:<60} {:>6} {:>6} {:>8}", "KEY", "TRUST", "OBS", "STATUS");
            println!("{}", "-".repeat(84));
            for (key, entry) in &entries {
                let trust = entry.trust_score();
                let obs = entry.observation_count();
                let status = if trust >= 0.92 && obs >= 8.0 {
                    "auto-allow"
                } else if trust < 0.3 && obs >= 5.0 {
                    "distrusted"
                } else {
                    "prompting"
                };
                let truncated = if key.len() > 58 {
                    format!("{}...", &key[..55])
                } else {
                    (*key).clone()
                };
                println!(
                    "{:<60} {:>5.0}% {:>6.1} {:>8}",
                    truncated,
                    trust * 100.0,
                    obs,
                    status
                );
            }
            println!("\n{} entries total.", entries.len());
        }
        ReputationAction::Reset { profile } => {
            runtime.block_on(daemon_client.reset_reputation(profile.as_deref()))?;
            match profile {
                Some(profile) => {
                    println!("Reset daemon-owned reputation entries for profile '{profile}'.");
                }
                None => println!("Reset all daemon-owned reputation data."),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
fn to_runtime_supervisor_config(
    core: &config::SupervisorCoreConfig,
) -> grith_supervisor::config::SupervisorConfig {
    to_runtime_supervisor_config_with_audit(core, &config::AuditConfig::default())
}

fn to_runtime_supervisor_config_with_audit(
    core: &config::SupervisorCoreConfig,
    audit: &config::AuditConfig,
) -> grith_supervisor::config::SupervisorConfig {
    grith_supervisor::config::SupervisorConfig {
        enabled: core.enabled,
        default_profile: core.default_profile.clone(),
        freeze_timeout_seconds: core.freeze_timeout_seconds,
        unattended_review_streak: core.unattended_review_streak,
        unattended_review_timeout_seconds: core.unattended_review_timeout_seconds,
        deny_replay_seconds: core.deny_replay_seconds,
        approve_replay_seconds: core.approve_replay_seconds,
        max_concurrent_sessions: core.max_concurrent_sessions,
        pty_forwarding: core.pty_forwarding,
        require_sandbox: core.require_sandbox,
        attach_mode: match core.attach_mode {
            config::AttachMode::Traceme => grith_supervisor::config::AttachMode::Traceme,
            config::AttachMode::Seize => grith_supervisor::config::AttachMode::Seize,
        },
        platform: grith_supervisor::config::PlatformConfig {
            linux_mechanism: core.platform.linux_mechanism.clone(),
            macos_mechanism: core.platform.macos_mechanism.clone(),
            seccomp_pre_filter: core.platform.seccomp_pre_filter,
        },
        noise_reduction: grith_supervisor::config::NoiseConfig {
            ignore_read_only: core.noise_reduction.ignore_read_only,
            batch_rapid_reads: core.noise_reduction.batch_rapid_reads,
            batch_window_ms: core.noise_reduction.batch_window_ms,
        },
        dns_inspection: grith_supervisor::config::DnsInspectionConfig {
            enabled: core.dns_inspection.enabled,
            upstream_resolver: core.dns_inspection.upstream_resolver.clone(),
            observe_responses: core.dns_inspection.observe_responses,
            block_tcp_dns: core.dns_inspection.block_tcp_dns,
            connected_udp_proxy: core.dns_inspection.connected_udp_proxy,
            accept_proxy_network_authority: core.dns_inspection.accept_proxy_network_authority,
            proxy_queue_action: match core.dns_inspection.proxy_queue_action {
                config::SupervisorDnsProxyQueueAction::Refuse => {
                    grith_supervisor::config::DnsProxyQueueAction::Refuse
                }
                config::SupervisorDnsProxyQueueAction::Forward => {
                    grith_supervisor::config::DnsProxyQueueAction::Forward
                }
            },
            proxy_max_response_bytes: core.dns_inspection.proxy_max_response_bytes,
            proxy_policy_timeout_ms: core.dns_inspection.proxy_policy_timeout_ms,
            proxy_upstream_timeout_ms: core.dns_inspection.proxy_upstream_timeout_ms,
            proxy_shutdown_timeout_ms: core.dns_inspection.proxy_shutdown_timeout_ms,
            proxy_route_capacity: core.dns_inspection.proxy_route_capacity,
            proxy_query_capacity: core.dns_inspection.proxy_query_capacity,
            proxy_control_capacity: core.dns_inspection.proxy_control_capacity,
            proxy_policy_capacity: core.dns_inspection.proxy_policy_capacity,
        },
        interactive_queue_action: grith_supervisor::config::InteractiveQueueAction::default(),
        syscall_log_file: None,
        trace_syscalls_jsonl_file: None,
        reputation_config: grith_proxy::reputation::ReputationConfig::default(),
        // PR 6 Phase F: map core CoverageConfig → supervisor CoverageConfig.
        coverage: grith_supervisor::config::CoverageConfig {
            category1_hard_deny: core.coverage.category1_hard_deny,
            category2_proxy: core.coverage.category2_proxy,
            category2_crossprocess: core.coverage.category2_crossprocess,
            category3_namespace: core.coverage.category3_namespace,
            category4_arch_priv: core.coverage.category4_arch_priv,
            deny_self_seccomp_notify: core.coverage.deny_self_seccomp_notify,
            observe_self_seccomp_filter: core.coverage.observe_self_seccomp_filter,
        },
        // work/83 F4: map core TrustConfig -> supervisor TrustConfig.
        trust: grith_supervisor::config::TrustConfig {
            include_linked_worktrees: core.trust.include_linked_worktrees,
            additional_project_roots: core.trust.additional_project_roots.clone(),
            restrict_to_workspace: core.trust.restrict_to_workspace,
        },
        audit_completeness: match audit.completeness {
            config::AuditCompleteness::Decisions => {
                grith_supervisor::config::AuditCompletenessLevel::Decisions
            }
            config::AuditCompleteness::Spawns => {
                grith_supervisor::config::AuditCompletenessLevel::Spawns
            }
            config::AuditCompleteness::Io => grith_supervisor::config::AuditCompletenessLevel::Io,
            config::AuditCompleteness::All => grith_supervisor::config::AuditCompletenessLevel::All,
        },
        pty_ownership_enforce: core.pty_ownership_enforce,
        enforce_authority_delegating_spawn: core.enforce_authority_delegating_spawn,
        enforce_control_socket_connect: core.enforce_control_socket_connect,
        dbus_message_inspection: core.dbus_message_inspection,
        authority_lost_terminate_after_seconds: core.authority_lost_terminate_after_seconds,
    }
}

#[cfg(test)]
mod session_summary_tests {
    use crate::agent::telemetry::*;
    use crate::agent::tool_execution::{self, *};
    use grith_audit::CorrelationTracker;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// work/83 F4: `grith exec` builds its supervisor config through
    /// `to_runtime_supervisor_config_with_audit`, so this is the mapping that
    /// decides whether the operator's trust settings reach a live session.
    #[test]
    fn to_runtime_supervisor_config_maps_trust() {
        let mut core = crate::config::SupervisorCoreConfig::default();
        core.trust.include_linked_worktrees = false;
        core.trust.additional_project_roots = vec!["/srv/other-repo".to_string()];

        let mapped = crate::to_runtime_supervisor_config(&core);
        assert!(!mapped.trust.include_linked_worktrees);
        assert_eq!(
            mapped.trust.additional_project_roots,
            vec!["/srv/other-repo"]
        );
    }

    #[test]
    fn to_runtime_supervisor_config_maps_dns_inspection() {
        let mut core = crate::config::SupervisorCoreConfig::default();
        core.dns_inspection.enabled = false;
        core.dns_inspection.upstream_resolver = Some("9.9.9.9".to_string());
        core.dns_inspection.connected_udp_proxy = true;
        core.dns_inspection.accept_proxy_network_authority = true;
        core.dns_inspection.proxy_queue_action =
            crate::config::SupervisorDnsProxyQueueAction::Forward;
        core.dns_inspection.proxy_max_response_bytes = 1232;
        core.dns_inspection.proxy_policy_timeout_ms = 250;
        core.dns_inspection.proxy_upstream_timeout_ms = 750;
        core.dns_inspection.proxy_shutdown_timeout_ms = 500;
        core.dns_inspection.proxy_route_capacity = 8;
        core.dns_inspection.proxy_query_capacity = 32;
        core.dns_inspection.proxy_control_capacity = 16;
        core.dns_inspection.proxy_policy_capacity = 4;

        let mapped = super::to_runtime_supervisor_config(&core);
        assert!(!mapped.dns_inspection.enabled);
        assert_eq!(
            mapped.dns_inspection.upstream_resolver.as_deref(),
            Some("9.9.9.9")
        );
        assert!(mapped.dns_inspection.connected_udp_proxy);
        assert!(mapped.dns_inspection.accept_proxy_network_authority);
        assert_eq!(
            mapped.dns_inspection.proxy_queue_action,
            grith_supervisor::config::DnsProxyQueueAction::Forward
        );
        assert_eq!(mapped.dns_inspection.proxy_max_response_bytes, 1232);
        assert_eq!(mapped.dns_inspection.proxy_policy_timeout_ms, 250);
        assert_eq!(mapped.dns_inspection.proxy_upstream_timeout_ms, 750);
        assert_eq!(mapped.dns_inspection.proxy_shutdown_timeout_ms, 500);
        assert_eq!(mapped.dns_inspection.proxy_route_capacity, 8);
        assert_eq!(mapped.dns_inspection.proxy_query_capacity, 32);
        assert_eq!(mapped.dns_inspection.proxy_control_capacity, 16);
        assert_eq!(mapped.dns_inspection.proxy_policy_capacity, 4);
    }

    #[test]
    fn update_check_only_runs_for_repl_and_run() {
        let run = super::Command::Run {
            task: "hello".to_string(),
        };
        let exec = super::Command::Exec {
            profile: None,
            attach: None,
            syscall_log: None,
            trace_syscalls_jsonl: None,
            allow_queued: false,
            workspace_only: false,
            command: vec!["echo".to_string(), "hi".to_string()],
        };
        let config = super::Command::Config { action: None };

        assert!(super::command_supports_update_check(None));
        assert!(super::command_supports_update_check(Some(&run)));
        assert!(!super::command_supports_update_check(Some(&exec)));
        assert!(!super::command_supports_update_check(Some(&config)));
    }

    #[test]
    fn update_notice_only_runs_for_exec() {
        let run = super::Command::Run {
            task: "hello".to_string(),
        };
        let exec = super::Command::Exec {
            profile: None,
            attach: None,
            syscall_log: None,
            trace_syscalls_jsonl: None,
            allow_queued: false,
            workspace_only: false,
            command: vec!["echo".to_string(), "hi".to_string()],
        };
        let config = super::Command::Config { action: None };

        assert!(super::command_supports_update_notice(Some(&exec)));

        // The REPL and `run` take the interactive prompt instead — offering
        // both would print the notice and then ask the same question.
        assert!(!super::command_supports_update_notice(None));
        assert!(!super::command_supports_update_notice(Some(&run)));
        assert!(!super::command_supports_update_notice(Some(&config)));
    }

    #[test]
    fn update_notice_requires_tty_config_and_env_gate() {
        let exec = super::Command::Exec {
            profile: None,
            attach: None,
            syscall_log: None,
            trace_syscalls_jsonl: None,
            allow_queued: false,
            workspace_only: false,
            command: vec!["echo".to_string(), "hi".to_string()],
        };

        assert!(super::should_notify_update(Some(&exec), true, true, false));
        // stderr not a terminal — redirected logs and CI output stay clean.
        assert!(!super::should_notify_update(
            Some(&exec),
            false,
            true,
            false
        ));
        // disabled in config
        assert!(!super::should_notify_update(
            Some(&exec),
            true,
            false,
            false
        ));
        // GRITH_NO_UPDATE_CHECK set
        assert!(!super::should_notify_update(Some(&exec), true, true, true));
    }

    #[test]
    fn update_check_requires_tty_config_and_env_gate() {
        let run = super::Command::Run {
            task: "hello".to_string(),
        };

        assert!(super::should_check_updates(
            Some(&run),
            true,
            true,
            true,
            false
        ));
        assert!(!super::should_check_updates(
            Some(&run),
            false,
            true,
            true,
            false
        ));
        assert!(!super::should_check_updates(
            Some(&run),
            true,
            false,
            true,
            false
        ));
        assert!(!super::should_check_updates(
            Some(&run),
            true,
            true,
            false,
            false
        ));
        assert!(!super::should_check_updates(
            Some(&run),
            true,
            true,
            true,
            true
        ));
    }

    #[test]
    fn test_normalize_tool_call_label() {
        assert_eq!(
            crate::helpers::normalize_tool_call_type_label("FileRead(/tmp/demo.txt)"),
            "file_read"
        );
        assert_eq!(
            crate::helpers::normalize_tool_call_type_label("DirList(.)"),
            "dir_list"
        );
    }

    #[test]
    fn test_parse_shell_exec_args_from_string() {
        let parsed = parse_shell_exec_args(Some(&serde_json::json!("-la README.md")));
        assert_eq!(parsed, vec!["-la".to_string(), "README.md".to_string()]);
    }

    #[test]
    fn test_parse_tool_call_shell_exec_accepts_string_args() {
        let tool_call = grith_llm::ToolCall {
            id: "call_2".to_string(),
            name: "shell_exec".to_string(),
            arguments: serde_json::json!({
                "command": "ls",
                "args": "-la README.md",
            }),
        };

        let parsed = parse_tool_call(&tool_call).expect("shell_exec should parse");
        match parsed.0 {
            grith_proxy::types::ToolCallType::ShellExec { command, args } => {
                assert_eq!(command, "ls");
                assert_eq!(args, vec!["-la".to_string(), "README.md".to_string()]);
            }
            other => panic!("expected shell exec, got {other:?}"),
        }
    }

    #[test]
    fn test_sanitize_session_name_keeps_dashes() {
        assert_eq!(
            crate::helpers::sanitize_session_name("grith-website".to_string()),
            "grith-website"
        );
        assert_eq!(
            crate::helpers::sanitize_session_name("my weird repo".to_string()),
            "my-weird-repo"
        );
    }

    fn queue_everything_proxy() -> grith_proxy::engine::SecurityProxy {
        let filters = grith_proxy::filters::FilterRegistry::new();
        let scoring = grith_proxy::scoring::ScoringConfig {
            auto_allow_threshold: -1.0,
            auto_deny_threshold: 10.0,
        };
        let meta_rules = grith_proxy::meta_rules::MetaRuleEngine::new(vec![]);
        grith_proxy::engine::SecurityProxy::new(filters, scoring, meta_rules)
    }

    fn test_dispatcher(
        digest_queue: Arc<grith_digest::DigestQueue>,
    ) -> Arc<grith_notify::NotificationDispatcher> {
        Arc::new(grith_notify::NotificationDispatcher::new(
            grith_notify::ChannelRegistry::new(),
            grith_notify::RoutingEngine::default(),
            Arc::new(grith_digest::notification::CallbackNonceStore::new(
                Duration::from_secs(300),
            )),
            grith_digest::notification::PlanTier::Community,
            digest_queue,
            grith_notify::rate_limiter::RateLimiter::default(),
            grith_notify::batcher::Batcher::default(),
            Duration::from_secs(300),
            grith_digest::types::ScoreSeverity::High,
        ))
    }

    fn read_file_call(path: &std::path::Path) -> grith_llm::ToolCall {
        grith_llm::ToolCall {
            id: "call_read".to_string(),
            name: "read_file".to_string(),
            arguments: serde_json::json!({
                "path": path.display().to_string()
            }),
        }
    }

    async fn wait_for_pending_item(digest_queue: &Arc<grith_digest::DigestQueue>) -> uuid::Uuid {
        let started = std::time::Instant::now();
        loop {
            let pending = digest_queue
                .get_pending(1, 0)
                .expect("failed to query pending digest items");
            if let Some(item) = pending.first() {
                return item.id;
            }
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "timed out waiting for queued digest item"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    #[tokio::test]
    async fn test_execute_tool_call_pauses_and_resumes_after_inline_approval() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file_path = temp.path().join("queued-inline.txt");
        tokio::fs::write(&file_path, "inline-approved")
            .await
            .expect("write temp file");

        let proxy = queue_everything_proxy();
        let audit_storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().expect("audit storage"),
        ));
        let digest_queue =
            Arc::new(grith_digest::DigestQueue::open_in_memory().expect("digest queue"));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = CorrelationTracker::with_defaults();
        let containment_tracker = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::with_defaults(),
        );
        let notification_dispatcher = test_dispatcher(Arc::clone(&digest_queue));
        let tool_call = read_file_call(&file_path);
        let session_id = uuid::Uuid::new_v4();

        let handle = tokio::spawn({
            let audit_storage = Arc::clone(&audit_storage);
            let digest_queue = Arc::clone(&digest_queue);
            let notification_dispatcher = Arc::clone(&notification_dispatcher);
            let containment_tracker = Arc::clone(&containment_tracker);
            async move {
                let mut call_seq = 0;
                let mut ctx = tool_execution::ToolCallContext {
                    proxy: &proxy,
                    audit_storage: &audit_storage,
                    can_write_audit: true,
                    audit_ingest: None,
                    digest_queue: &digest_queue,
                    dlp_redactor: &dlp_redactor,
                    correlation_tracker: &correlation_tracker,
                    notification_dispatcher: &notification_dispatcher,
                    containment_tracker: &containment_tracker,
                    ws_tx: None,
                    dashboard_url: None,
                    session_id,
                    session_name: "inline-test",
                    policy_scope: None,
                    call_seq: &mut call_seq,
                    review_timeout: Duration::from_secs(5),
                    tui_tx: None,
                };
                execute_tool_call(&tool_call, &mut ctx).await
            }
        });

        let item_id = wait_for_pending_item(&digest_queue).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !handle.is_finished(),
            "queued tool call should pause while waiting for review"
        );

        {
            let actions = grith_digest::actions::DigestActions::new(&digest_queue);
            actions.approve(&item_id).expect("approve queued item");
        }

        let result = handle.await.expect("join execute_tool_call");
        assert_eq!(result, "inline-approved");
    }

    #[tokio::test]
    async fn test_execute_tool_call_pauses_and_resumes_after_remote_callback() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file_path = temp.path().join("queued-remote.txt");
        tokio::fs::write(&file_path, "remote-approved")
            .await
            .expect("write temp file");

        let proxy = queue_everything_proxy();
        let audit_storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().expect("audit storage"),
        ));
        let digest_queue =
            Arc::new(grith_digest::DigestQueue::open_in_memory().expect("digest queue"));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = CorrelationTracker::with_defaults();
        let containment_tracker = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::with_defaults(),
        );
        let notification_dispatcher = test_dispatcher(Arc::clone(&digest_queue));
        let tool_call = read_file_call(&file_path);
        let session_id = uuid::Uuid::new_v4();

        let webhook_channel = grith_notify::channels::webhook::WebhookChannel::new(
            grith_notify::channels::webhook::WebhookConfig {
                url: "http://127.0.0.1:9".to_string(),
                secret: "test-secret".to_string(),
                callback_url: Some("http://localhost/callback".to_string()),
                headers: vec![],
                max_retries: 0,
            },
        );
        notification_dispatcher.register_channel(Arc::new(webhook_channel), true);

        let handle = tokio::spawn({
            let audit_storage = Arc::clone(&audit_storage);
            let digest_queue = Arc::clone(&digest_queue);
            let notification_dispatcher = Arc::clone(&notification_dispatcher);
            let containment_tracker = Arc::clone(&containment_tracker);
            async move {
                let mut call_seq = 0;
                let mut ctx = tool_execution::ToolCallContext {
                    proxy: &proxy,
                    audit_storage: &audit_storage,
                    can_write_audit: true,
                    audit_ingest: None,
                    digest_queue: &digest_queue,
                    dlp_redactor: &dlp_redactor,
                    correlation_tracker: &correlation_tracker,
                    notification_dispatcher: &notification_dispatcher,
                    containment_tracker: &containment_tracker,
                    ws_tx: None,
                    dashboard_url: None,
                    session_id,
                    session_name: "remote-test",
                    policy_scope: None,
                    call_seq: &mut call_seq,
                    review_timeout: Duration::from_secs(5),
                    tui_tx: None,
                };
                execute_tool_call(&tool_call, &mut ctx).await
            }
        });

        let item_id = wait_for_pending_item(&digest_queue).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !handle.is_finished(),
            "queued tool call should pause while waiting for callback review"
        );

        let nonce = notification_dispatcher
            .nonce_store()
            .generate(item_id, "webhook");
        let payload = grith_digest::notification::CallbackPayload {
            item_id,
            action: grith_digest::ReviewAction::Approve,
            reviewer: "remote-reviewer".to_string(),
            notes: Some("approved from remote callback".to_string()),
            nonce,
            channel_id: "webhook".to_string(),
            user_id: None,
        };
        let action = notification_dispatcher
            .handle_callback(&payload)
            .await
            .expect("handle callback");
        assert_eq!(action, Some(grith_digest::ReviewAction::Approve));

        let result = handle.await.expect("join execute_tool_call");
        assert_eq!(result, "remote-approved");
    }
}

#[cfg(test)]
mod profile_refresh_tests {
    use super::*;

    #[test]
    fn exec_included_in_profile_refresh_gate() {
        let cmd = Command::Exec {
            profile: None,
            attach: None,
            syscall_log: None,
            trace_syscalls_jsonl: None,
            allow_queued: false,
            workspace_only: false,
            command: vec!["echo".into()],
        };
        assert!(command_supports_profile_refresh(Some(&cmd)));
    }

    #[test]
    fn run_included_in_profile_refresh_gate() {
        let cmd = Command::Run {
            task: "test".into(),
        };
        assert!(command_supports_profile_refresh(Some(&cmd)));
    }

    #[test]
    fn repl_included_in_profile_refresh_gate() {
        assert!(command_supports_profile_refresh(None));
    }

    #[test]
    fn config_excluded_from_profile_refresh_gate() {
        let cmd = Command::Config { action: None };
        assert!(!command_supports_profile_refresh(Some(&cmd)));
    }

    #[test]
    fn daemon_excluded_from_profile_refresh_gate() {
        let cmd = Command::Daemon {
            action: DaemonAction::Status,
        };
        assert!(!command_supports_profile_refresh(Some(&cmd)));
    }

    #[test]
    fn env_disables_profile_refresh() {
        assert!(!should_refresh_profiles(None, true, true));
    }

    #[test]
    fn config_disables_profile_refresh() {
        assert!(!should_refresh_profiles(None, false, false));
    }

    #[test]
    fn no_tty_still_refreshes() {
        // Unlike binary update check, profile refresh has no TTY requirement.
        assert!(should_refresh_profiles(None, true, false));
    }
}

#[cfg(test)]
mod init_onboarding_tests {
    use super::*;

    #[test]
    fn insert_general_flag_inserts_under_general_header() {
        let input = "[general]\nlog_level = \"info\"\n\n[proxy]\nx = 1\n";
        let out = insert_general_flag(input, "onboarded", "true");
        assert!(out.contains("[general]\nonboarded = true\n"));
        // Existing content preserved.
        assert!(out.contains("log_level = \"info\""));
        assert!(out.contains("[proxy]"));
        // The value parses back as the active general.onboarded key.
        let parsed: toml::Value = out.parse().unwrap();
        assert_eq!(parsed["general"]["onboarded"].as_bool(), Some(true));
    }

    #[test]
    fn insert_general_flag_noop_when_already_declared() {
        let input = "[general]\nonboarded = false\nlog_level = \"info\"\n";
        let out = insert_general_flag(input, "onboarded", "true");
        // An explicit declaration is respected; we do not add a duplicate.
        assert_eq!(out, input);
        assert_eq!(out.matches("onboarded").count(), 1);
    }

    #[test]
    fn insert_general_flag_ignores_commented_declaration() {
        let input = "[general]\n# onboarded = false\nlog_level = \"info\"\n";
        let out = insert_general_flag(input, "onboarded", "true");
        let parsed: toml::Value = out.parse().unwrap();
        assert_eq!(parsed["general"]["onboarded"].as_bool(), Some(true));
    }

    #[test]
    fn insert_general_flag_prepends_section_when_absent() {
        let input = "[proxy]\nx = 1\n";
        let out = insert_general_flag(input, "onboarded", "true");
        let parsed: toml::Value = out.parse().unwrap();
        assert_eq!(parsed["general"]["onboarded"].as_bool(), Some(true));
        assert_eq!(parsed["proxy"]["x"].as_integer(), Some(1));
    }
}

#[cfg(test)]
mod onboarding_gate_tests {
    use super::*;

    fn run_cmd() -> Command {
        Command::Run { task: "x".into() }
    }

    fn exec_cmd(command: Vec<&str>) -> Command {
        Command::Exec {
            profile: None,
            attach: None,
            syscall_log: None,
            trace_syscalls_jsonl: None,
            allow_queued: false,
            workspace_only: false,
            command: command.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn auto_onboarding_fires_for_fresh_interactive_repl() {
        // None command (REPL), TTY, not onboarded, not skipped → fire.
        assert!(should_auto_run_onboarding(None, false, true, true, false));
        // `grith run` is also interactive.
        assert!(should_auto_run_onboarding(
            Some(&run_cmd()),
            false,
            true,
            true,
            false
        ));
    }

    #[test]
    fn auto_onboarding_suppressed_when_already_onboarded_or_opted_out() {
        assert!(!should_auto_run_onboarding(None, true, true, true, false)); // onboarded
        assert!(!should_auto_run_onboarding(None, false, true, true, true)); // skip flag
    }

    #[test]
    fn auto_onboarding_requires_tty() {
        assert!(!should_auto_run_onboarding(None, false, false, true, false)); // no stdin tty
        assert!(!should_auto_run_onboarding(None, false, true, false, false)); // no stdout tty
    }

    #[test]
    fn auto_onboarding_never_fires_for_exec_or_management() {
        assert!(!should_auto_run_onboarding(
            Some(&exec_cmd(vec!["claude-code"])),
            false,
            true,
            true,
            false
        ));
    }

    #[test]
    fn exec_notice_fires_for_real_tool_launch() {
        // `grith exec -- claude-code "task"` → separator present, real tool.
        assert!(exec_launches_supervised_tool(
            None,
            None,
            &["claude-code".into(), "task".into()],
            true
        ));
        // Even without an explicit separator, a non-management binary launches.
        assert!(exec_launches_supervised_tool(
            None,
            None,
            &["aider".into()],
            false
        ));
    }

    #[test]
    fn exec_notice_skips_management_verbs() {
        for verb in [vec!["list"], vec!["prune"], vec!["kill"]] {
            assert!(
                !exec_launches_supervised_tool(
                    None,
                    None,
                    &verb.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    false
                ),
                "expected management verb {verb:?} to be skipped"
            );
        }
        // `kill <session-id>` form.
        assert!(!exec_launches_supervised_tool(
            None,
            None,
            &["kill".into(), "abc123".into()],
            false
        ));
    }

    #[test]
    fn exec_notice_management_verb_is_a_launch_with_separator_or_profile() {
        // With a `--` separator a tool literally named "list" is supervised.
        assert!(exec_launches_supervised_tool(
            None,
            None,
            &["list".into()],
            true
        ));
        // A profile forces tool-launch interpretation too.
        assert!(exec_launches_supervised_tool(
            Some("codex"),
            None,
            &["list".into()],
            false
        ));
    }

    #[test]
    fn exec_notice_fires_for_attach() {
        assert!(exec_launches_supervised_tool(None, Some(4242), &[], false));
    }

    #[test]
    fn exec_notice_skips_empty_command() {
        assert!(!exec_launches_supervised_tool(None, None, &[], false));
    }

    #[test]
    fn env_truthiness() {
        assert!(value_is_truthy("1"));
        assert!(value_is_truthy("true"));
        assert!(value_is_truthy("YES"));
        assert!(value_is_truthy(" on "));
        assert!(!value_is_truthy("0"));
        assert!(!value_is_truthy("false"));
        assert!(!value_is_truthy(""));
    }

    #[test]
    fn exec_tool_name_is_first_arg() {
        assert_eq!(
            exec_tool_name(&["claude-code".into(), "task".into()]),
            Some("claude-code")
        );
        assert_eq!(exec_tool_name(&[]), None);
    }

    #[test]
    fn setup_is_network_free() {
        // `grith setup` must not trigger update checks or profile refreshes —
        // it runs in the daemon-free early path.
        assert!(!command_supports_update_check(Some(&Command::Setup)));
        assert!(!command_supports_profile_refresh(Some(&Command::Setup)));
    }

    #[test]
    fn pro_start_trial_subcommand_parses() {
        // The hyphenated subcommand name resolves to ProAction::StartTrial.
        let cli = Cli::try_parse_from(["grith", "pro", "start-trial"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Pro {
                action: ProAction::StartTrial
            })
        ));
    }
}
