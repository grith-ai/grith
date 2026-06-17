// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith exec` subcommand — launch or attach to a process under OS-level supervision.

use crate::{daemon, helpers};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// `profile_name` is the supervisor profile provided by the caller (CLI flag or
/// auto-detected). `None` means no explicit profile was set; a default will be used.
fn validate_supervisor_startup(
    config: &crate::config::SupervisorCoreConfig,
    capability: grith_supervisor::platform::PlatformCapability,
    profile_name: Option<&str>,
) -> anyhow::Result<()> {
    use grith_supervisor::platform::PlatformCapability;

    if config.require_sandbox {
        match capability {
            PlatformCapability::Full => {
                tracing::info!(
                    "[grith] Protected mode active — platform capability: {:?}",
                    capability
                );

                // Warn when the seccomp-BPF pre-filter is not active.  Until
                // seccomp-BPF pre-filtering is implemented, enforcement relies
                // entirely on ptrace, which has higher per-syscall overhead and
                // cannot block syscalls before they reach the kernel on every path.
                if !config.platform.seccomp_pre_filter {
                    tracing::warn!(
                        "Protected mode active without seccomp-BPF pre-filter — \
                         enforcement relies on ptrace only. \
                         Set supervisor.platform.seccomp_pre_filter = true once the \
                         feature is available for stronger kernel-level enforcement."
                    );
                }

                // Warn when no explicit supervisor profile is configured.  Without
                // a profile the session allowlist is empty, so every syscall hits
                // the full proxy pipeline and generates noise rather than leveraging
                // per-tool noise-reduction allowlists.
                if profile_name.is_none() {
                    tracing::warn!(
                        "Protected mode is active but no supervisor profile is \
                         configured — all syscalls will hit the full proxy pipeline \
                         with no allowlist noise reduction"
                    );
                }

                Ok(())
            }
            PlatformCapability::Degraded => anyhow::bail!(
                "supervisor.require_sandbox = true but {} only provides degraded \
                 supervision (lifecycle tracking only, not per-syscall interception). \
                 Run on a supported Linux host or set supervisor.require_sandbox = false \
                 to proceed without full sandbox enforcement.",
                std::env::consts::OS
            ),
            PlatformCapability::Unavailable => anyhow::bail!(
                "supervisor.require_sandbox = true but no syscall interception \
                 mechanism is available. On Linux, check that ptrace_scope is 0 or 1 \
                 (cat /proc/sys/kernel/yama/ptrace_scope) or run with CAP_SYS_PTRACE. \
                 Set supervisor.require_sandbox = false to proceed without enforcement."
            ),
        }
    } else if capability == PlatformCapability::Unavailable {
        anyhow::bail!(
            "supervisor is not supported on this platform ({})",
            std::env::consts::OS
        );
    } else {
        Ok(())
    }
}

async fn refresh_team_learned_rules_cache_for_session() {
    let creds = match crate::license::load_credentials() {
        Ok(Some(creds)) => creds,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load credentials before learned-rule sync");
            return;
        }
    };

    match crate::license::fetch_learned_rules(&creds).await {
        Ok(rules) => match super::pro::persist_team_learned_rules_cache(&rules) {
            Ok(path) => {
                tracing::debug!(
                    count = rules.len(),
                    path = %path.display(),
                    "refreshed team learned-rules cache for session startup"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to persist team learned-rules cache");
            }
        },
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to refresh team learned-rules cache, falling back to cached copy"
            );
        }
    }
}

fn load_effective_policy(
    profile_name: &str,
    launcher_override: Option<&str>,
    provider_override: Option<&str>,
) -> anyhow::Result<grith_supervisor::profiles::EffectivePolicy> {
    let profile_config = crate::profile_updates::load_effective_profiles()?;
    profile_config
        .build_effective_policy(profile_name, launcher_override, provider_override)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn apply_launch_contract_to_command(
    command: &mut Vec<String>,
    contract: &grith_supervisor::profiles::LaunchContract,
) -> anyhow::Result<bool> {
    let cmd_name = command
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing command"))?;
    let mut args = command.iter().skip(1).cloned().collect::<Vec<_>>();
    let modified = grith_supervisor::profiles::enforce_launch_contract(&mut args, contract)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if modified {
        command.clear();
        command.push(cmd_name);
        command.extend(args);
    }
    Ok(modified)
}

fn prepare_command_and_effective_policy(
    profile_name: &str,
    attach: Option<u32>,
    mut command: Vec<String>,
) -> anyhow::Result<(Vec<String>, grith_supervisor::profiles::EffectivePolicy)> {
    let effective_policy = load_effective_policy(profile_name, None, None)?;
    if attach.is_none() {
        if let Some(ref contract) = effective_policy.merged_profile.launch_contract {
            if apply_launch_contract_to_command(&mut command, contract)? {
                tracing::info!(
                    profile = profile_name,
                    injected_args = ?contract.required_args,
                    "auto-injected required launch args per profile contract"
                );
            }
        }
    }
    Ok((command, effective_policy))
}

/// Capture the controlling terminal of the launching CLI as a short label
/// (e.g. "pts/21") so an operator can locate an orphaned session. Returns
/// `None` when stdin is not a tty (piped/redirected) or on non-Linux.
fn capture_launch_tty() -> Option<String> {
    let target = std::fs::read_link("/proc/self/fd/0").ok()?;
    let s = target.to_string_lossy();
    let name = s.strip_prefix("/dev/").unwrap_or(&s);
    if name.starts_with("pts/") || name.starts_with("tty") {
        Some(name.to_string())
    } else {
        None
    }
}

/// Absolute working directory the supervised tool is being launched from.
fn capture_launch_cwd() -> Option<String> {
    std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Format a duration in seconds as a compact human label (e.g. "2d21h", "6m").
fn format_duration_secs(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    if d > 0 {
        format!("{d}d{h}h")
    } else if h > 0 {
        format!("{h}h{m}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{secs}s")
    }
}

/// Render a framed session-limit upgrade prompt instead of a bare 429 error.
/// Shows the already-running sessions (so the user can see what to close) and
/// the remediation options the daemon advertised.
fn render_session_limit_upsell(
    rej: &crate::daemon::client::SessionLimitRejection,
    sessions: &[crate::daemon::client::RemoteSessionSummary],
) {
    eprintln!();
    eprintln!(
        "  \u{26a0}  Session limit reached — {} of {} on the {} plan.",
        rej.active_sessions, rej.current_limit, rej.tier
    );
    if !sessions.is_empty() {
        eprintln!();
        eprintln!("  Already running:");
        for s in sessions {
            let location = s
                .project_name
                .as_deref()
                .or(s.cwd.as_deref())
                .unwrap_or("?");
            let tty = s
                .tty
                .as_deref()
                .map(|t| format!(" ({t})"))
                .unwrap_or_default();
            eprintln!(
                "    {}  {}  {}{}  up {}",
                &s.id.to_string()[..8],
                s.tool_name,
                location,
                tty,
                format_duration_secs(s.uptime_seconds),
            );
        }
    }
    eprintln!();
    eprintln!("  Options:");
    eprintln!("    • Close one:  grith exec kill <id>");
    eprintln!("    • Clear dead: grith exec prune");
    if let Some(url) = &rej.upgrade_url {
        eprintln!("    • Upgrade:    {url}");
    }
    eprintln!();
}

fn print_remote_sessions(
    sessions: &[crate::daemon::client::RemoteSessionSummary],
) -> anyhow::Result<()> {
    if sessions.is_empty() {
        println!("No active supervisor sessions.");
    } else {
        println!("Active supervisor sessions ({}):", sessions.len());
        for s in sessions {
            let containment = s
                .containment_remaining_seconds
                .map(|r| format!(" | CONTAINED ({r}s)"))
                .unwrap_or_default();
            // Prefer the project/cwd + tty as the human "where to find it" hint.
            let location = s
                .project_name
                .as_deref()
                .or(s.cwd.as_deref())
                .unwrap_or("?");
            let tty = s
                .tty
                .as_deref()
                .map(|t| format!(" {t}"))
                .unwrap_or_default();
            let idle = if s.last_activity_seconds >= 60 {
                format!(" | idle {}", format_duration_secs(s.last_activity_seconds))
            } else {
                String::new()
            };
            println!(
                "  {} | {} | {}{} | pid {} | up {}{} | {} intercepted ({} allowed, {} queued, {} denied){}",
                &s.id.to_string()[..8],
                s.tool_name,
                location,
                tty,
                s.root_pid,
                format_duration_secs(s.uptime_seconds),
                idle,
                s.stats.total_intercepted,
                s.stats.total_allowed,
                s.stats.total_queued,
                s.stats.total_denied,
                containment,
            );
        }
    }
    Ok(())
}

pub fn cmd_exec_thin(
    cfg: &crate::config::GrithConfig,
    daemon_client: crate::daemon::client::DaemonClient,
    profile: Option<String>,
    attach: Option<u32>,
    syscall_log: Option<std::path::PathBuf>,
    trace_syscalls_jsonl: Option<std::path::PathBuf>,
    command: Vec<String>,
    project_override: Option<&str>,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let exec_start = std::time::Instant::now();
    let has_separator = std::env::args_os().any(|arg| arg == "--");
    if attach.is_none() && profile.is_none() && !has_separator {
        match command.as_slice() {
            [cmd] if cmd == "list" => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let sessions = runtime.block_on(daemon_client.list_sessions())?;
                print_remote_sessions(&sessions)?;
                println!(
                    "Capacity: {} sessions visible via daemon registry",
                    sessions.len()
                );
                return Ok(());
            }
            [cmd, session_id] if cmd == "kill" => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let id = uuid::Uuid::parse_str(session_id)
                    .map_err(|_| anyhow::anyhow!("invalid session ID: {session_id}"))?;
                runtime.block_on(daemon_client.kill_session(id))?;
                println!(
                    "Terminated session {}",
                    &session_id[..8.min(session_id.len())]
                );
                return Ok(());
            }
            [cmd] if cmd == "kill" => {
                anyhow::bail!("usage: grith exec kill <session-id>");
            }
            [cmd] if cmd == "prune" => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let (reaped, remaining) = runtime.block_on(daemon_client.prune_sessions())?;
                if reaped == 0 {
                    println!("No dead sessions to prune ({remaining} active).");
                } else {
                    println!("Pruned {reaped} dead session(s); {remaining} remaining.");
                }
                return Ok(());
            }
            _ => {}
        }
    }

    if !cfg.supervisor.enabled {
        anyhow::bail!("supervisor is disabled in configuration (set supervisor.enabled = true)");
    }
    if attach.is_none() && command.is_empty() {
        anyhow::bail!(
            "usage: grith exec list | grith exec kill <session-id> | grith exec prune | \
             grith exec [--profile <name>] [--attach <pid>] -- <command> [args...]"
        );
    }

    let tool_name = if let Some(cmd) = command.first() {
        cmd.clone()
    } else {
        format!("pid-{}", attach.unwrap_or(0))
    };
    let profile_name = profile
        .or_else(|| grith_supervisor::profiles::SupervisorProfile::detect_profile(&tool_name))
        .unwrap_or_else(|| cfg.supervisor.default_profile.clone());

    validate_supervisor_startup(
        &cfg.supervisor,
        grith_supervisor::platform::platform_capability(),
        Some(profile_name.as_str()),
    )?;

    let (command, effective_policy) =
        prepare_command_and_effective_policy(&profile_name, attach, command)?;

    let scope_key = effective_policy.scope_key.clone();
    let launcher_overlay_name = effective_policy.launcher_overlay_name.clone();
    let provider_overlay_name = effective_policy.provider_overlay_name.clone();
    let merged_profile = effective_policy.merged_profile.clone();
    if let Some(ref launcher) = effective_policy.launcher_overlay_name {
        tracing::info!(
            launcher_overlay = launcher,
            "detected launcher overlay for session"
        );
    }

    let has_tty = std::io::IsTerminal::is_terminal(&std::io::stdout())
        && std::io::IsTerminal::is_terminal(&std::io::stdin());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        refresh_team_learned_rules_cache_for_session().await;

        let mut interceptor = grith_supervisor::platform::create_interceptor()?;
        let stdin_paused = Arc::new(AtomicBool::new(false));
        let output_paused = Arc::new(AtomicBool::new(false));

        let mut exec_tui_tx: Option<crossbeam_channel::Sender<grith_cli::tui::exec_tui::ExecEvent>> =
            None;
        let mut exec_tui_rx: Option<
            crossbeam_channel::Receiver<grith_cli::tui::exec_tui::ExecEvent>,
        > = None;
        let mut exec_permission_tx: Option<
            crossbeam_channel::Sender<grith_cli::tui::exec_tui::PermissionEvent>,
        > = None;
        let mut exec_permission_rx: Option<
            crossbeam_channel::Receiver<grith_cli::tui::exec_tui::PermissionEvent>,
        > = None;
        let mut exec_pty_input_tx: Option<
            std::sync::mpsc::Sender<grith_cli::tui::exec_tui::PtyInput>,
        > = None;
        let mut exec_tui_rows: u16 = 24;
        let mut exec_tui_cols: u16 = 80;

        let root_pid = if let Some(pid) = attach {
            println!("Attaching to PID {pid} with profile '{profile_name}'...");
            interceptor.attach(pid).await?;
            pid
        } else {
            let cmd = command
                .first()
                .ok_or_else(|| anyhow::anyhow!("missing command"))?
                .clone();
            let args = command.iter().skip(1).cloned().collect::<Vec<_>>();

            #[cfg(unix)]
            if cfg.supervisor.pty_forwarding {
                let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
                let inner_rows = rows
                    .saturating_sub(grith_cli::tui::exec_tui::MINIMAL_CHROME_ROWS)
                    .max(4);
                let (pid, pty_reader, pty_writer) = interceptor
                    .spawn_supervised_pty(&cmd, &args, &[], cols, inner_rows)
                    .await
                    .map_err(|e| anyhow::anyhow!("PTY spawn failed: {e}"))?;

                if has_tty {
                    let (exec_event_tx, exec_event_rx) = crossbeam_channel::unbounded();
                    let (permission_tx, permission_rx) = crossbeam_channel::unbounded();
                    let (pty_input_tx, pty_input_rx) =
                        std::sync::mpsc::channel::<grith_cli::tui::exec_tui::PtyInput>();
                    let event_tx_clone = exec_event_tx.clone();
                    spawn_pty_reader_thread(pty_reader, event_tx_clone);
                    spawn_pty_writer_thread(pty_writer, pty_input_rx, pid);
                    exec_tui_tx = Some(exec_event_tx);
                    exec_tui_rx = Some(exec_event_rx);
                    exec_permission_tx = Some(permission_tx);
                    exec_permission_rx = Some(permission_rx);
                    exec_pty_input_tx = Some(pty_input_tx);
                    exec_tui_rows = rows;
                    exec_tui_cols = cols;
                } else {
                    crate::logging::suppress();
                    spawn_pty_io_threads(
                        pty_reader,
                        pty_writer,
                        stdin_paused.clone(),
                        output_paused.clone(),
                    );
                }
                pid
            } else {
                interceptor.spawn_supervised(&cmd, &args, &[]).await?
            }

            #[cfg(not(unix))]
            {
                interceptor.spawn_supervised(&cmd, &args, &[]).await?
            }
        };

        let tool_display = Path::new(&tool_name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&tool_name)
            .to_string();

        let mut session =
            grith_supervisor::supervisor::SupervisorSession::new(tool_display.clone(), root_pid);
        session.profile_name = Some(profile_name.clone());
        session.policy_scope = Some(scope_key.clone());
        session.launcher_overlay_name = launcher_overlay_name.clone();
        session.provider_overlay_name = provider_overlay_name.clone();
        session.project_name = Some(
            project_override
                .map(|s| s.to_string())
                .unwrap_or_else(helpers::derive_session_name_from_cwd),
        );
        session.cwd = capture_launch_cwd();
        session.tty = capture_launch_tty();
        let session_id = session.id;

        match daemon_client.register_session_checked(&session).await? {
            crate::daemon::client::RegisterOutcome::Registered => {}
            crate::daemon::client::RegisterOutcome::LimitReached(rej) => {
                let running = daemon_client.list_sessions().await.unwrap_or_default();
                render_session_limit_upsell(&rej, &running);
                anyhow::bail!("session limit reached");
            }
        }

        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(60);
        match daemon_client.expire_stale_digests(cutoff).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(count = n, "expired stale pending digest items in daemon"),
            Err(e) => tracing::warn!(error = %e, "failed to expire stale digest items in daemon"),
        }

        let mut supervisor_cfg =
            crate::to_runtime_supervisor_config_with_audit(&cfg.supervisor, &cfg.audit);
        supervisor_cfg.syscall_log_file = syscall_log;
        supervisor_cfg.trace_syscalls_jsonl_file = trace_syscalls_jsonl;
        supervisor_cfg.reputation_config = cfg.reputation.to_proxy_config();
        // Select the attach mechanism (traceme | seize) before the first spawn.
        interceptor.set_attach_mode(supervisor_cfg.attach_mode);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

        let (broadcast_tx, _broadcast_rx) = tokio::sync::broadcast::channel::<String>(256);
        let event_tx = Some(broadcast_tx.clone());

        if let Some(ref tui_tx) = exec_tui_tx {
            let mut broadcast_rx = broadcast_tx.subscribe();
            let tui_tx_clone = tui_tx.clone();
            tokio::spawn(async move {
                while let Ok(json_str) = broadcast_rx.recv().await {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        let action = val["action"].as_str().unwrap_or("").to_string();
                        let call_type = val["call_type"].as_str().unwrap_or("").to_string();
                        let score = val["score"].as_f64().unwrap_or(0.0);
                        let timestamp = val["timestamp"]
                            .as_str()
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            .map(|dt| dt.format("%H:%M:%S").to_string())
                            .unwrap_or_default();
                        let event = grith_cli::tui::exec_tui::ExecEvent::Intercept {
                            timestamp,
                            action,
                            call_type,
                            score,
                        };
                        if tui_tx_clone.send(event).is_err() {
                            break;
                        }
                    }
                }
            });
        }

        // Forward supervisor events to the dashboard's WebSocket via the
        // daemon's /api/ipc/events endpoint so the Live Monitor shows activity.
        {
            let mut dashboard_rx = broadcast_tx.subscribe();
            let fwd_client = daemon_client.clone();
            tokio::spawn(async move {
                while let Ok(json_str) = dashboard_rx.recv().await {
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        let _ = fwd_client.forward_event(&event).await;
                    }
                }
            });
        }

        let digest_store: Arc<dyn grith_supervisor::DigestStore> = Arc::new(
            crate::daemon::client::RemoteDigestStore::new(daemon_client.clone()),
        );
        let audit_sink: Arc<dyn grith_supervisor::AuditSink> = Arc::new(
            crate::daemon::client::RemoteAuditSink::new(daemon_client.clone()),
        );
        let session_sync: Arc<dyn grith_supervisor::SessionSync> = Arc::new(
            crate::daemon::client::RemoteSessionSync::new(
                daemon_client.clone(),
                std::time::Duration::from_millis(250),
            ),
        );

        let queue_reviewer: Option<Arc<dyn grith_supervisor::QueueReviewer>> =
            if let Some(ref perm_tx) = exec_permission_tx {
                Some(Arc::new(super::exec_reviewer::ExecTuiQueueReviewer::new(
                    perm_tx.clone(),
                    digest_store.clone(),
                )))
            } else if has_tty {
                Some(Arc::new(super::exec_reviewer::TerminalQueueReviewer::new(
                    digest_store.clone(),
                    stdin_paused.clone(),
                    output_paused.clone(),
                    root_pid,
                )))
            } else {
                None
            };

        let mut dns_seed_domains =
            crate::daemon::config_loader::load_egress_policy_config()?.trusted_domains;
        for dest in &merged_profile.routine_destinations {
            if !dns_seed_domains.contains(dest) {
                dns_seed_domains.push(dest.clone());
            }
        }

        let mut session_allowed = merged_profile.build_session_allowlist();
        {
            // Use scope_key for learned-rule isolation so overlays don't
            // bleed rules between different effective policies.
            let (local_count, team_count) =
                grith_supervisor::learned_rules::merge_default_cached_rules_for_profile(
                    &mut session_allowed,
                    &scope_key,
                );
            if local_count > 0 {
                tracing::info!(
                    count = local_count,
                    scope = scope_key,
                    "loaded persistent learned rules into session allowlist"
                );
            }
            if team_count > 0 {
                tracing::info!(
                    count = team_count,
                    scope = scope_key,
                    "loaded team learned rules from cache into session allowlist"
                );
            }
        }

        let filter_count = daemon_client.proxy_filter_count().await.unwrap_or(0);
        let tui_handle = if let (Some(event_rx), Some(permission_rx), Some(pty_input_tx)) = (
            exec_tui_rx.take(),
            exec_permission_rx.take(),
            exec_pty_input_tx.take(),
        ) {
            let tui_tool = tool_display.clone();
            let tui_profile = scope_key.clone();
            let tui_pid = root_pid;
            let tui_rows = exec_tui_rows;
            let tui_cols = exec_tui_cols;
            // Bare URL only — the token is handed to the browser out-of-band
            // (auto-open / pairing), never rendered in the always-visible TUI
            // header where it could leak into screenshots or recordings.
            let tui_dashboard_url = Some(daemon_client.base_url().to_string());
            Some(std::thread::spawn(move || {
                let mut state = grith_cli::tui::exec_tui::ExecState::new(
                    tui_tool,
                    tui_profile,
                    tui_pid,
                    tui_rows,
                    tui_cols,
                    filter_count,
                );
                state.dashboard_url = tui_dashboard_url;
                grith_cli::tui::exec_tui::run_exec_tui(
                    state,
                    event_rx,
                    permission_rx,
                    pty_input_tx,
                )
            }))
        } else {
            None
        };

        let thin_proxy = Arc::new(grith_proxy::engine::SecurityProxy::new(
            grith_proxy::filters::FilterRegistry::new(),
            grith_proxy::scoring::ScoringConfig::default(),
            grith_proxy::meta_rules::MetaRuleEngine::new(vec![]),
        ));
        let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let containment_tracker = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::with_defaults(),
        );
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let daemon_proxy_token = crate::daemon::token::read_token()
            .ok_or_else(|| anyhow::anyhow!("daemon token unavailable"))?;
        let daemon_restart = grith_supervisor::supervisor::DaemonRestartConfig {
            executable: std::env::current_exe()
                .map_err(|e| anyhow::anyhow!("failed to resolve current executable: {e}"))?,
            config_path: config_path.map(|p| p.to_path_buf()),
            token_path: crate::daemon::token::token_path(),
        };

        tracing::info!(
            startup_ms = exec_start.elapsed().as_millis(),
            remote_proxy = true,
            "grith exec ready — thin supervisor loop starting"
        );

        let inventory_sink: std::sync::Arc<dyn grith_supervisor::InventorySink> =
            std::sync::Arc::new(crate::daemon::client::RemoteInventorySink::new(
                daemon_client.clone(),
            ));
        let run_result = grith_supervisor::supervisor::run_supervisor_loop(
            &mut interceptor,
            &mut session,
            thin_proxy,
            audit_sink,
            digest_store,
            &dlp_redactor,
            correlation_tracker,
            containment_tracker,
            &supervisor_cfg,
            shutdown_rx,
            event_tx,
            queue_reviewer,
            Some(session_sync),
            &dns_seed_domains,
            session_allowed,
            None,
            Some(daemon_client.base_url().to_string()),
            Some(daemon_proxy_token),
            Some(daemon_restart),
            Some(inventory_sink),
        )
        .await;

        if let Err(e) = daemon_client.unregister_session(session_id).await {
            tracing::warn!(session_id = %session_id, error = %e, "failed to unregister thin exec session from daemon");
        }

        if let Some(ref tx) = exec_tui_tx {
            let _ = tx.send(grith_cli::tui::exec_tui::ExecEvent::ProcessExited);
        }

        if let Some(handle) = tui_handle {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "exec TUI error"),
                Err(_) => tracing::warn!("exec TUI thread panicked"),
            }
        } else if has_tty {
            let _ = crossterm::terminal::disable_raw_mode();
        }

        run_result.map_err(|e| anyhow::anyhow!("supervisor loop failed: {e}"))?;

        if has_tty {
            crate::logging::restore(&cfg.general.log_level);
        }
        println!("Supervisor session {} completed.", session_id);
        Ok(())
    })
}

pub fn cmd_exec(
    daemon: &daemon::Daemon,
    profile: Option<String>,
    attach: Option<u32>,
    syscall_log: Option<std::path::PathBuf>,
    trace_syscalls_jsonl: Option<std::path::PathBuf>,
    command: Vec<String>,
    project_override: Option<&str>,
) -> anyhow::Result<()> {
    let exec_start = std::time::Instant::now();
    // Support supervisor session management aliases
    let has_separator = std::env::args_os().any(|arg| arg == "--");
    if attach.is_none() && profile.is_none() && !has_separator {
        match command.as_slice() {
            [cmd] if cmd == "list" => {
                return super::supervisor::cmd_supervisor(
                    daemon,
                    Some(crate::SupervisorAction::List),
                );
            }
            [cmd, session_id] if cmd == "kill" => {
                return super::supervisor::cmd_supervisor(
                    daemon,
                    Some(crate::SupervisorAction::Kill {
                        session_id: session_id.clone(),
                    }),
                );
            }
            [cmd] if cmd == "kill" => {
                anyhow::bail!("usage: grith exec kill <session-id>");
            }
            [cmd] if cmd == "prune" => {
                let (reaped, remaining) = {
                    let mut registry = daemon
                        .supervisor_registry
                        .lock()
                        .map_err(|_| anyhow::anyhow!("supervisor registry lock poisoned"))?;
                    let reaped = registry.reap_dead();
                    (reaped, registry.count())
                };
                if reaped == 0 {
                    println!("No dead sessions to prune ({remaining} active).");
                } else {
                    println!("Pruned {reaped} dead session(s); {remaining} remaining.");
                }
                return Ok(());
            }
            _ => {}
        }
    }

    if !daemon.config.supervisor.enabled {
        anyhow::bail!("supervisor is disabled in configuration (set supervisor.enabled = true)");
    }

    if attach.is_none() && command.is_empty() {
        anyhow::bail!(
            "usage: grith exec list | grith exec kill <session-id> | grith exec prune | \
             grith exec [--profile <name>] [--attach <pid>] -- <command> [args...]"
        );
    }

    let tool_name = if let Some(cmd) = command.first() {
        cmd.clone()
    } else {
        format!("pid-{}", attach.unwrap_or(0))
    };

    let profile_name = profile
        .or_else(|| grith_supervisor::profiles::SupervisorProfile::detect_profile(&tool_name))
        .unwrap_or_else(|| daemon.config.supervisor.default_profile.clone());

    validate_supervisor_startup(
        &daemon.config.supervisor,
        grith_supervisor::platform::platform_capability(),
        Some(profile_name.as_str()),
    )?;

    tracing::info!(
        %tool_name,
        %profile_name,
        attach = ?attach,
        "starting supervised session"
    );

    let (command, effective_policy) =
        prepare_command_and_effective_policy(&profile_name, attach, command)?;
    let scope_key = effective_policy.scope_key.clone();
    let launcher_overlay_name = effective_policy.launcher_overlay_name.clone();
    let provider_overlay_name = effective_policy.provider_overlay_name.clone();
    let merged_profile = effective_policy.merged_profile.clone();

    {
        let registry = daemon
            .supervisor_registry
            .lock()
            .map_err(|_| anyhow::anyhow!("supervisor registry lock poisoned"))?;
        let active = registry.count();
        let max = registry.max_sessions();
        if active >= max {
            anyhow::bail!(
                "supervisor session limit reached ({active}/{max}). \
                 Use `grith exec list` to see active sessions."
            );
        }
    }

    let has_tty = std::io::IsTerminal::is_terminal(&std::io::stdout())
        && std::io::IsTerminal::is_terminal(&std::io::stdin());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async {
        let _sync_handle = if daemon.config.general.audit_sync {
            tokio::spawn(daemon::Daemon::audit_sync_task(
                daemon.audit_storage.clone(),
                daemon.subscribe_shutdown(),
            ))
        } else {
            tokio::spawn(async {})
        };

        refresh_team_learned_rules_cache_for_session().await;

        let mut interceptor = grith_supervisor::platform::create_interceptor()?;
        let stdin_paused = Arc::new(AtomicBool::new(false));
        let output_paused = Arc::new(AtomicBool::new(false));

        // Exec TUI channels (set when PTY + TTY available)
        let mut exec_tui_tx: Option<
            crossbeam_channel::Sender<grith_cli::tui::exec_tui::ExecEvent>,
        > = None;
        let mut exec_tui_rx: Option<
            crossbeam_channel::Receiver<grith_cli::tui::exec_tui::ExecEvent>,
        > = None;
        let mut exec_permission_tx: Option<
            crossbeam_channel::Sender<grith_cli::tui::exec_tui::PermissionEvent>,
        > = None;
        let mut exec_permission_rx: Option<
            crossbeam_channel::Receiver<grith_cli::tui::exec_tui::PermissionEvent>,
        > = None;
        let mut exec_pty_input_tx: Option<
            std::sync::mpsc::Sender<grith_cli::tui::exec_tui::PtyInput>,
        > = None;
        let mut exec_tui_rows: u16 = 24;
        let mut exec_tui_cols: u16 = 80;

        let root_pid = if let Some(pid) = attach {
            println!("Attaching to PID {pid} with profile '{profile_name}'...");
            interceptor.attach(pid).await?;
            pid
        } else {
            let cmd = command
                .first()
                .ok_or_else(|| anyhow::anyhow!("missing command"))?
                .clone();
            let args = command.iter().skip(1).cloned().collect::<Vec<_>>();

            #[cfg(unix)]
            if daemon.config.supervisor.pty_forwarding {
                // Reserve rows for grith's chrome (titlebar + log + statusbar).
                // Use MINIMAL_CHROME_ROWS (log-only height) so the child gets the
                // maximum stable PTY height; permission dialogs expand into the
                // viewport without resizing the child.
                let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
                let inner_rows = rows
                    .saturating_sub(grith_cli::tui::exec_tui::MINIMAL_CHROME_ROWS)
                    .max(4);
                let (pid, pty_reader, pty_writer) = interceptor
                    .spawn_supervised_pty(&cmd, &args, &[], cols, inner_rows)
                    .await
                    .map_err(|e| anyhow::anyhow!("PTY spawn failed: {e}"))?;

                if has_tty {
                    // Channels for TUI ↔ PTY communication. Bulk supervisor
                    // events and permission requests are split across two
                    // crossbeam channels so the TUI's biased select! can
                    // prioritise permission prompts over PTY-output backlog.
                    let (exec_event_tx, exec_event_rx) = crossbeam_channel::unbounded();
                    let (permission_tx, permission_rx) = crossbeam_channel::unbounded();
                    let (pty_input_tx, pty_input_rx) =
                        std::sync::mpsc::channel::<grith_cli::tui::exec_tui::PtyInput>();

                    // PTY reader thread → TUI
                    let event_tx_clone = exec_event_tx.clone();
                    spawn_pty_reader_thread(pty_reader, event_tx_clone);

                    // TUI → PTY writer thread
                    spawn_pty_writer_thread(pty_writer, pty_input_rx, pid);

                    // Store channels for the supervisor to signal process exit
                    exec_tui_tx = Some(exec_event_tx);
                    exec_tui_rx = Some(exec_event_rx);
                    exec_permission_tx = Some(permission_tx);
                    exec_permission_rx = Some(permission_rx);
                    exec_pty_input_tx = Some(pty_input_tx);
                    exec_tui_rows = rows;
                    exec_tui_cols = cols;
                } else {
                    // No TTY — fallback to raw passthrough
                    crate::logging::suppress();
                    spawn_pty_io_threads(
                        pty_reader,
                        pty_writer,
                        stdin_paused.clone(),
                        output_paused.clone(),
                    );
                }
                pid
            } else {
                interceptor.spawn_supervised(&cmd, &args, &[]).await?
            }

            #[cfg(not(unix))]
            {
                interceptor.spawn_supervised(&cmd, &args, &[]).await?
            }
        };

        let tool_display = Path::new(&tool_name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&tool_name)
            .to_string();

        let mut session =
            grith_supervisor::supervisor::SupervisorSession::new(tool_display.clone(), root_pid);
        session.profile_name = Some(profile_name.clone());
        session.policy_scope = Some(scope_key.clone());
        session.launcher_overlay_name = launcher_overlay_name.clone();
        session.provider_overlay_name = provider_overlay_name.clone();
        session.project_name = Some(
            project_override
                .map(|s| s.to_string())
                .unwrap_or_else(helpers::derive_session_name_from_cwd),
        );
        session.cwd = capture_launch_cwd();
        session.tty = capture_launch_tty();
        let session_id = session.id;

        {
            let mut registry = daemon
                .supervisor_registry
                .lock()
                .map_err(|_| anyhow::anyhow!("supervisor registry lock poisoned"))?;
            let registry_view = grith_supervisor::supervisor::SupervisorSession {
                id: session.id,
                tool_name: session.tool_name.clone(),
                profile_name: session.profile_name.clone(),
                policy_scope: session.policy_scope.clone(),
                launcher_overlay_name: session.launcher_overlay_name.clone(),
                provider_overlay_name: session.provider_overlay_name.clone(),
                root_pid: session.root_pid,
                process_tree: grith_supervisor::process_tree::ProcessTree::new(
                    root_pid,
                    &session.tool_name,
                ),
                started_at: session.started_at,
                last_synced_at: session.last_synced_at,
                last_activity_at: session.last_activity_at,
                stats: session.stats.clone(),
                project_name: session.project_name.clone(),
                cwd: session.cwd.clone(),
                tty: session.tty.clone(),
                wedge_reported_tids: std::collections::HashSet::new(),
                controlling_pts: std::sync::OnceLock::new(),
            };
            registry.register(registry_view)?;
        }

        // Expire stale pending digest items from previous crashed sessions.
        {
            let cutoff = chrono::Utc::now() - chrono::Duration::seconds(60);
            match daemon.digest_queue.expire_before(cutoff) {
                Ok(0) => {}
                Ok(n) => tracing::info!(count = n, "expired stale pending digest items"),
                Err(e) => tracing::warn!(error = %e, "failed to expire stale digest items"),
            }
        }

        let mut supervisor_cfg = crate::to_runtime_supervisor_config_with_audit(
            &daemon.config.supervisor,
            &daemon.config.audit,
        );
        supervisor_cfg.syscall_log_file = syscall_log;
        supervisor_cfg.trace_syscalls_jsonl_file = trace_syscalls_jsonl;
        supervisor_cfg.reputation_config = daemon.config.reputation.to_proxy_config();
        // Select the attach mechanism (traceme | seize) before the first spawn.
        interceptor.set_attach_mode(supervisor_cfg.attach_mode);
        let shutdown_rx = daemon.subscribe_shutdown();

        // Event broadcast channel for proxy decisions
        let (broadcast_tx, _broadcast_rx) = tokio::sync::broadcast::channel::<String>(256);
        let event_tx = Some(broadcast_tx.clone());
        let digest_store: Arc<dyn grith_supervisor::DigestStore> = Arc::new(
            grith_supervisor::LocalDigestStore::new(daemon.digest_queue.clone()),
        );
        let audit_sink: Arc<dyn grith_supervisor::AuditSink> = Arc::new(
            grith_supervisor::StorageAuditSink::new(daemon.audit_storage.clone()),
        );
        let session_sync: Arc<dyn grith_supervisor::SessionSync> = Arc::new(
            grith_supervisor::RegistrySessionSync::new(daemon.supervisor_registry.clone()),
        );

        // Bridge: forward broadcast events to exec TUI as Intercept events
        if let Some(ref tui_tx) = exec_tui_tx {
            let mut broadcast_rx = broadcast_tx.subscribe();
            let tui_tx_clone = tui_tx.clone();
            tokio::spawn(async move {
                while let Ok(json_str) = broadcast_rx.recv().await {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        let action = val["action"].as_str().unwrap_or("").to_string();
                        let call_type = val["call_type"].as_str().unwrap_or("").to_string();
                        let score = val["score"].as_f64().unwrap_or(0.0);
                        let timestamp = val["timestamp"]
                            .as_str()
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            .map(|dt| dt.format("%H:%M:%S").to_string())
                            .unwrap_or_default();

                        let event = grith_cli::tui::exec_tui::ExecEvent::Intercept {
                            timestamp,
                            action,
                            call_type,
                            score,
                        };
                        if tui_tx_clone.send(event).is_err() {
                            break;
                        }
                    }
                }
            });
        }

        // Use ExecTuiQueueReviewer when exec TUI is active (permission dialog
        // rendered as overlay), otherwise fall back to TerminalQueueReviewer
        // for raw PTY passthrough mode.
        let queue_reviewer: Option<Arc<dyn grith_supervisor::QueueReviewer>> =
            if let Some(ref perm_tx) = exec_permission_tx {
                Some(Arc::new(super::exec_reviewer::ExecTuiQueueReviewer::new(
                    perm_tx.clone(),
                    digest_store.clone(),
                )))
            } else if has_tty {
                Some(Arc::new(super::exec_reviewer::TerminalQueueReviewer::new(
                    digest_store.clone(),
                    stdin_paused.clone(),
                    output_paused.clone(),
                    root_pid,
                )))
            } else {
                None
            };

        // Get trusted domains from the egress filter TOML config for DNS cache seeding.
        let mut dns_seed_domains =
            crate::daemon::config_loader::load_egress_policy_config()?.trusted_domains;
        for dest in &merged_profile.routine_destinations {
            if !dns_seed_domains.contains(dest) {
                dns_seed_domains.push(dest.clone());
            }
        }

        // Build comprehensive session allowlist from the profile so routine
        // operations bypass the proxy entirely (no scoring, no rate limiting).
        let mut session_allowed = merged_profile.build_session_allowlist();

        // Merge persistent local and team-synced learned rules into the
        // session allowlist.
        {
            let (local_count, team_count) =
                grith_supervisor::learned_rules::merge_default_cached_rules_for_profile(
                    &mut session_allowed,
                    &scope_key,
                );
            if local_count > 0 {
                tracing::info!(
                    count = local_count,
                    scope = scope_key,
                    "loaded persistent learned rules into session allowlist"
                );
            }
            if team_count > 0 {
                tracing::info!(
                    count = team_count,
                    scope = scope_key,
                    "loaded team learned rules from cache into session allowlist"
                );
            }
        }

        // Start the exec TUI on a separate thread if channels are set up
        let tui_handle = if let (Some(event_rx), Some(permission_rx), Some(pty_input_tx)) = (
            exec_tui_rx.take(),
            exec_permission_rx.take(),
            exec_pty_input_tx.take(),
        ) {
            let tui_tool = tool_display.clone();
            let tui_profile = scope_key.clone();
            let tui_pid = root_pid;
            let tui_rows = exec_tui_rows;
            let tui_cols = exec_tui_cols;
            let filter_count = daemon.proxy.filter_count();
            let tui_dashboard_url = if daemon.config.server.enabled {
                // Bare URL only — see the note at the other TUI construction
                // site; the token never appears in the persistent header.
                Some(format!(
                    "http://{}:{}",
                    daemon.config.server.host, daemon.config.server.port
                ))
            } else {
                None
            };
            Some(std::thread::spawn(move || {
                let mut state = grith_cli::tui::exec_tui::ExecState::new(
                    tui_tool,
                    tui_profile,
                    tui_pid,
                    tui_rows,
                    tui_cols,
                    filter_count,
                );
                state.dashboard_url = tui_dashboard_url;
                grith_cli::tui::exec_tui::run_exec_tui(state, event_rx, permission_rx, pty_input_tx)
            }))
        } else {
            None
        };

        tracing::info!(
            startup_ms = exec_start.elapsed().as_millis(),
            remote_proxy = false,
            "grith exec ready — supervisor loop starting"
        );

        let run_result = grith_supervisor::supervisor::run_supervisor_loop(
            &mut interceptor,
            &mut session,
            daemon.proxy.clone(),
            audit_sink,
            digest_store,
            &daemon.dlp_redactor,
            daemon.correlation_tracker.clone(),
            daemon.containment_tracker.clone(),
            &supervisor_cfg,
            shutdown_rx,
            event_tx,
            queue_reviewer,
            Some(session_sync),
            &dns_seed_domains,
            session_allowed,
            Some(daemon.reputation_table.clone()),
            None,
            None,
            None,
            None, // in-process exec: SessionStateRegistry is shared here, no IPC push needed
        )
        .await;

        {
            let mut registry = daemon
                .supervisor_registry
                .lock()
                .map_err(|_| anyhow::anyhow!("supervisor registry lock poisoned"))?;
            registry.remove(&session_id);
        }

        // Signal the TUI that the process has exited
        if let Some(ref tx) = exec_tui_tx {
            let _ = tx.send(grith_cli::tui::exec_tui::ExecEvent::ProcessExited);
        }

        // Wait for the TUI thread to finish (restores terminal)
        if let Some(handle) = tui_handle {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "exec TUI error"),
                Err(_) => tracing::warn!("exec TUI thread panicked"),
            }
        } else {
            // No TUI — restore terminal from raw mode
            if has_tty {
                let _ = crossterm::terminal::disable_raw_mode();
            }
        }

        run_result.map_err(|e| anyhow::anyhow!("supervisor loop failed: {e}"))?;

        if has_tty {
            crate::logging::restore(&daemon.config.general.log_level);
        }
        println!("Supervisor session {} completed.", session_id);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::{apply_launch_contract_to_command, validate_supervisor_startup};
    use crate::config::SupervisorCoreConfig;
    use grith_supervisor::platform::PlatformCapability;
    use grith_supervisor::profiles::{LaunchContract, SupervisorProfile};

    #[test]
    fn require_sandbox_rejects_degraded_platform() {
        let cfg = SupervisorCoreConfig {
            require_sandbox: true,
            ..SupervisorCoreConfig::default()
        };

        let err =
            validate_supervisor_startup(&cfg, PlatformCapability::Degraded, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("require_sandbox = true"));
        assert!(msg.contains("degraded supervision"));
    }

    #[test]
    fn require_sandbox_rejects_unavailable_platform_with_fix_hint() {
        let cfg = SupervisorCoreConfig {
            require_sandbox: true,
            ..SupervisorCoreConfig::default()
        };

        let err =
            validate_supervisor_startup(&cfg, PlatformCapability::Unavailable, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("require_sandbox = true"));
        assert!(msg.contains("ptrace_scope"));
        assert!(msg.contains("CAP_SYS_PTRACE"));
    }

    #[test]
    fn degraded_platform_is_allowed_without_require_sandbox() {
        let cfg = SupervisorCoreConfig::default();
        validate_supervisor_startup(&cfg, PlatformCapability::Degraded, None).unwrap();
    }

    #[test]
    fn unavailable_platform_is_generic_error_without_require_sandbox() {
        let cfg = SupervisorCoreConfig::default();

        let err =
            validate_supervisor_startup(&cfg, PlatformCapability::Unavailable, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("supervisor is not supported on this platform"));
    }

    #[test]
    fn require_sandbox_full_capability_succeeds() {
        let cfg = SupervisorCoreConfig {
            require_sandbox: true,
            ..SupervisorCoreConfig::default()
        };
        // Full platform capability + require_sandbox should succeed (warnings logged but no error).
        validate_supervisor_startup(&cfg, PlatformCapability::Full, Some("openclaw")).unwrap();
    }

    #[test]
    fn require_sandbox_full_capability_without_profile_succeeds() {
        // No profile provided — warns but does not error.
        let cfg = SupervisorCoreConfig {
            require_sandbox: true,
            ..SupervisorCoreConfig::default()
        };
        validate_supervisor_startup(&cfg, PlatformCapability::Full, None).unwrap();
    }

    #[test]
    fn no_require_sandbox_full_capability_succeeds() {
        let cfg = SupervisorCoreConfig::default(); // require_sandbox = false
        validate_supervisor_startup(&cfg, PlatformCapability::Full, None).unwrap();
    }

    #[test]
    fn session_allowlist_does_not_include_home_root() {
        let home = std::env::var("HOME").unwrap_or_default();
        let profile = SupervisorProfile {
            name: "openclaw".into(),
            display_name: "OpenClaw".into(),
            rationale: None,
            extends: None,
            routine_paths: vec!["${HOME}/.openclaw/**".into()],
            routine_commands: vec!["openclaw".into()],
            routine_destinations: vec!["api.openai.com".into()],
            routine_listen_addresses: vec!["127.0.0.1".into()],
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            readonly_paths: Vec::new(),
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
        };

        let allowed = profile.build_session_allowlist();
        assert!(!home.is_empty(), "HOME must be set for this test");
        assert!(
            !allowed.contains(&home),
            "session allowlist must not contain the entire home directory"
        );
        assert!(allowed.contains(&format!("{home}/.openclaw")));
    }

    #[test]
    fn session_allowlist_does_not_implicitly_include_cwd() {
        let cwd = std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let profile = SupervisorProfile {
            name: "test".into(),
            display_name: "Test".into(),
            rationale: None,
            extends: None,
            routine_paths: vec![],
            routine_commands: vec![],
            routine_destinations: vec![],
            routine_listen_addresses: vec![],
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            readonly_paths: Vec::new(),
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
        };

        let allowed = profile.build_session_allowlist();
        assert!(
            !allowed.contains(&cwd),
            "session allowlist must not implicitly include current working directory"
        );
    }

    #[test]
    fn session_allowlist_only_includes_profile_network_destinations() {
        let profile = SupervisorProfile {
            name: "test".into(),
            display_name: "Test".into(),
            rationale: None,
            extends: None,
            routine_paths: vec![],
            routine_commands: vec![],
            routine_destinations: vec!["api.example.com".into()],
            routine_listen_addresses: vec!["127.0.0.1".into()],
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            readonly_paths: Vec::new(),
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
        };

        let allowed = profile.build_session_allowlist();
        assert!(allowed.contains("net:api.example.com"));
        assert!(allowed.contains("net:127.0.0.1"));
        assert!(
            !allowed.contains("net:github.com"),
            "global egress trusted domains must not be promoted into the session allowlist"
        );
    }

    #[test]
    fn session_allowlist_prefers_exact_exec_paths_over_bare_names() {
        let profile = SupervisorProfile {
            name: "openclaw".into(),
            display_name: "OpenClaw".into(),
            rationale: None,
            extends: None,
            routine_paths: vec![],
            routine_commands: vec!["sh".into()],
            routine_destinations: vec![],
            routine_listen_addresses: vec![],
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            readonly_paths: Vec::new(),
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
        };

        let allowed = profile.build_session_allowlist();
        assert!(
            allowed.iter().any(|entry| entry.starts_with("exec:/")),
            "resolved executable path should be allowlisted when available"
        );
        assert!(
            !allowed.contains("exec:sh"),
            "bare command names must not be allowlisted when a resolved path exists"
        );
    }

    #[test]
    fn session_allowlist_includes_exec_prefix_entries() {
        let profile = SupervisorProfile {
            name: "claude-code".into(),
            display_name: "Claude Code".into(),
            rationale: None,
            extends: None,
            routine_paths: vec![],
            routine_commands: vec![],
            routine_destinations: vec![],
            routine_listen_addresses: vec![],
            routine_exec_roots: vec!["/usr/lib/git-core/".into()],
            scratch_roots: Vec::new(),
            readonly_paths: Vec::new(),
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
        };

        let allowed = profile.build_session_allowlist();
        assert!(
            allowed.contains("exec-prefix:/usr/lib/git-core/"),
            "system exec root should be in allowlist"
        );
    }

    #[test]
    fn session_allowlist_exec_prefix_adds_trailing_slash() {
        let profile = SupervisorProfile {
            name: "test".into(),
            display_name: "Test".into(),
            rationale: None,
            extends: None,
            routine_paths: vec![],
            routine_commands: vec![],
            routine_destinations: vec![],
            routine_listen_addresses: vec![],
            routine_exec_roots: vec!["/usr/lib/git-core".into()],
            scratch_roots: Vec::new(),
            readonly_paths: Vec::new(),
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
        };

        let allowed = profile.build_session_allowlist();
        assert!(
            allowed.contains("exec-prefix:/usr/lib/git-core/"),
            "exec-prefix entries should have trailing slash"
        );
    }

    #[test]
    fn apply_launch_contract_to_command_mutates_spawned_command() {
        let mut command = vec!["cursor-agent".into(), "task".into()];
        let contract = LaunchContract {
            required_args: vec!["--sandbox".into(), "disabled".into()],
        };

        let modified = apply_launch_contract_to_command(&mut command, &contract).unwrap();
        assert!(modified);
        assert_eq!(
            command,
            vec!["cursor-agent", "--sandbox", "disabled", "task"]
        );
    }

    #[test]
    fn apply_launch_contract_to_command_rejects_conflicting_args() {
        let mut command = vec![
            "cursor-agent".into(),
            "--sandbox".into(),
            "enabled".into(),
            "task".into(),
        ];
        let contract = LaunchContract {
            required_args: vec!["--sandbox".into(), "disabled".into()],
        };

        let err = apply_launch_contract_to_command(&mut command, &contract).unwrap_err();
        assert!(err.to_string().contains("launch contract conflict"));
    }
}

// ---------------------------------------------------------------------------
// PTY I/O threads — pure passthrough, tool gets full terminal control
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn spawn_pty_io_threads(
    mut pty_reader: Box<dyn Read + Send>,
    mut pty_writer: Box<dyn Write + Send>,
    stdin_paused: Arc<AtomicBool>,
    output_paused: Arc<AtomicBool>,
) {
    use std::os::unix::io::AsRawFd;

    // PTY master → user stdout (raw passthrough)
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut pending: Vec<u8> = Vec::new();
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) => break,
                Err(_) => break,
                Ok(n) => {
                    if output_paused.load(Ordering::SeqCst) {
                        pending.extend_from_slice(&buf[..n]);
                        continue;
                    }
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();
                    if !pending.is_empty() {
                        let _ = stdout.write_all(&pending);
                        pending.clear();
                    }
                    if stdout.write_all(&buf[..n]).is_err() || stdout.flush().is_err() {
                        break;
                    }
                }
            }
        }
    });

    // User stdin → PTY master
    std::thread::spawn(move || {
        let stdin_fd = std::io::stdin().as_raw_fd();
        let mut buf = [0u8; 4096];
        loop {
            if stdin_paused.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }

            let mut pollfd = libc::pollfd {
                fd: stdin_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ret = unsafe { libc::poll(std::ptr::from_mut(&mut pollfd), 1, 100) };

            if ret < 0 {
                break;
            }
            if ret == 0 {
                continue;
            }

            if stdin_paused.load(Ordering::SeqCst) {
                continue;
            }

            if pollfd.revents & libc::POLLIN != 0 {
                let n = unsafe {
                    libc::read(stdin_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len())
                };
                if n <= 0 {
                    break;
                }
                let n = n as usize;
                if pty_writer.write_all(&buf[..n]).is_err() || pty_writer.flush().is_err() {
                    break;
                }
            }
            if pollfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                break;
            }
        }
    });
}

// ---------------------------------------------------------------------------
// PTY I/O threads for exec TUI — route through channels instead of stdout
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn spawn_pty_reader_thread(
    mut pty_reader: Box<dyn Read + Send>,
    event_tx: crossbeam_channel::Sender<grith_cli::tui::exec_tui::ExecEvent>,
) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let bytes = buf[..n].to_vec();
                    if event_tx
                        .send(grith_cli::tui::exec_tui::ExecEvent::PtyOutput(bytes))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
}

#[cfg(unix)]
fn spawn_pty_writer_thread(
    mut pty_writer: Box<dyn Write + Send>,
    input_rx: std::sync::mpsc::Receiver<grith_cli::tui::exec_tui::PtyInput>,
    root_pid: u32,
) {
    std::thread::spawn(move || {
        while let Ok(input) = input_rx.recv() {
            match input {
                grith_cli::tui::exec_tui::PtyInput::Bytes(bytes) => {
                    if pty_writer.write_all(&bytes).is_err() || pty_writer.flush().is_err() {
                        break;
                    }
                }
                grith_cli::tui::exec_tui::PtyInput::Resize { cols, rows } => {
                    let _ = resize_child_pty(root_pid, cols, rows);
                }
            }
        }
    });
}

#[cfg(unix)]
fn resize_child_pty(pid: u32, cols: u16, rows: u16) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;

    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/proc/{pid}/fd/0"))?;
    let winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let rc = unsafe { libc::ioctl(tty.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "TIOCSWINSZ failed for pid {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }

    let rc = unsafe { libc::kill(pid as i32, libc::SIGWINCH) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "SIGWINCH failed for pid {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PATH resolution helper
// ---------------------------------------------------------------------------
