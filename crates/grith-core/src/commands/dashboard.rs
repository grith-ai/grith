// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith dashboard` subcommand — start, stop, and query the web dashboard server.

use crate::daemon;
use grith_supervisor::supervisor::SupervisorRegistry;
use std::sync::{Arc, Mutex};

/// How often the idle watchdog checks the session registry.
const IDLE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Check whether a PID is still alive. Returns `true` on EPERM (process
/// exists but we lack signal permission, e.g. ptraced children).
fn session_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) checks existence. Returns 0 on success.
        // EPERM means the process exists but we can't signal it.
        // ESRCH means the process is gone.
        let ret = unsafe { libc::kill(pid as i32, 0) };
        if ret == 0 {
            return true;
        }
        let err = std::io::Error::last_os_error();
        err.raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Run the dashboard server in the foreground. This is the entry point when
/// `grith dashboard start` is used — typically spawned as a detached process.
pub fn cmd_dashboard_start(daemon: &daemon::Daemon) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let server_config = crate::to_server_config(&daemon.config.server);
    let port = server_config.port;

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let ipc_token = crate::daemon::token::generate_token();
    // Separate per-server token authorising the dashboard SPA (browser) to
    // mutate state, distinct from the IPC token. The CLI surfaces it to the
    // browser via the `#token=` launch fragment. Persisted and reused across
    // restarts so open tabs stay authorised (see `get_or_create_dashboard_token`).
    let dashboard_token = crate::daemon::token::get_or_create_dashboard_token();

    let sync_api_key = crate::license::load_credentials()
        .ok()
        .flatten()
        .map(|creds| creds.api_key);
    let sync_api_base_url = Some(crate::license::api_base_url());

    let deps = grith_server::ServerDeps {
        audit_storage: daemon.audit_storage.clone(),
        digest_queue: daemon.digest_queue.clone(),
        proxy: daemon.proxy.clone(),
        supervisor_registry: daemon.supervisor_registry.clone(),
        containment_tracker: daemon.containment_tracker.clone(),
        correlation_tracker: daemon.correlation_tracker.clone(),
        canary_registry: daemon.canary_registry.clone(),
        notification_dispatcher: daemon.notification_dispatcher.clone(),
        audit_db_path: crate::helpers::expand_user_path(&daemon.config.general.audit_dir)
            .join("audit.db"),
        dns_seed_domains: crate::daemon::config_loader::load_egress_policy_config()?
            .trusted_domains,
        reputation_table: daemon.reputation_table.clone(),
        reputation_config: daemon.config.reputation.to_proxy_config(),
        sync_api_key: sync_api_key.clone(),
        sync_api_base_url: sync_api_base_url.clone(),
    };
    let server =
        grith_server::GrithServer::new(server_config, deps, env!("CARGO_PKG_VERSION"), shutdown_rx)
            .with_shutdown_sender(shutdown_tx.clone())
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

    daemon.register_notification_channels(Some(server.ws_sender()));

    let pid = std::process::id();
    if let Err(e) = daemon::write_dashboard_pid(pid, port) {
        tracing::warn!(error = %e, "failed to write dashboard PID file");
    }

    if let Err(e) = crate::daemon::token::write_token(&ipc_token) {
        tracing::warn!(error = %e, "failed to write daemon IPC token");
    }
    // `get_or_create_dashboard_token` already persisted the token if it was
    // newly minted; no separate write needed here.

    println!("Daemon starting on http://{addr}");
    println!("  PID: {pid}");
    println!("  Stop with: grith daemon stop");

    // Auto-open the dashboard for a *direct* `grith dashboard start`. When this
    // daemon was spawned as a detached child by `ensure_dashboard_running_*`,
    // the parent owns the browser handoff and user-facing print (this process's
    // stdout is /dev/null), so it sets GRITH_DASHBOARD_CHILD to suppress a
    // double-open here.
    if std::env::var_os("GRITH_DASHBOARD_CHILD").is_none() {
        let base = format!("http://{addr}");
        let code = server.mint_pair_code();
        announce_with_pairing(
            "Dashboard: ",
            &base,
            pid,
            Some(&code),
            daemon.config.server.auto_open_dashboard,
        );
    }

    runtime.block_on(async {
        let server_shutdown = shutdown_tx.clone();
        let server_handle = tokio::spawn(async move {
            if let Err(e) = server.start().await {
                // Most commonly a bind failure (EADDRINUSE) when another daemon
                // — or a stale orphan — already holds the port. Trigger a clean
                // shutdown so this process exits instead of lingering as a
                // listener-less zombie the parent would mis-report as "started".
                tracing::error!(error = %e, "dashboard server failed to start; shutting down");
                let _ = server_shutdown.send(());
            }
        });

        let license_handle = daemon.spawn_license_revalidation();
        let sync_handle = if daemon.config.general.audit_sync {
            daemon.spawn_audit_sync()
        } else {
            tracing::info!("audit sync disabled by configuration");
            tokio::spawn(async {})
        };
        let mut notification_handles = daemon
            .notification_dispatcher
            .spawn_background_tasks(daemon.subscribe_shutdown());

        // Idle auto-shutdown: when all supervisor sessions exit, the daemon
        // shuts down after a grace period. This prevents stale daemons from
        // lingering after all CLI instances have exited.
        //
        // An *explicit* `grith dashboard start` (GRITH_DASHBOARD_PERSISTENT)
        // must persist until `grith dashboard stop`, so disable idle shutdown
        // (grace=0). Otherwise the watchdog would kill it ~5s after the
        // user's `dashboard start` command returns: its spawner has exited and
        // the dashboard alone registers no supervisor session. Auto-started
        // dashboards (from `grith exec` / `grith run`) keep the configured
        // idle behaviour so they don't linger after the session ends.
        let idle_grace_secs = if std::env::var_os("GRITH_DASHBOARD_PERSISTENT").is_some() {
            0
        } else {
            daemon.config.server.idle_shutdown_seconds
        };
        let idle_registry = daemon.supervisor_registry.clone();
        let idle_shutdown = shutdown_tx.clone();
        let idle_handle = tokio::spawn(async move {
            idle_auto_shutdown(idle_registry, idle_shutdown, idle_grace_secs).await;
        });

        // Always-on session reaper: evicts sessions whose root PID is dead and
        // whose heartbeat has gone stale. Independent of the idle watchdog so
        // dead sessions are reclaimed even when idle auto-shutdown is disabled
        // (idle_shutdown_seconds = 0).
        let reaper_registry = daemon.supervisor_registry.clone();
        let reaper_shutdown = shutdown_tx.subscribe();
        let reaper_handle = tokio::spawn(async move {
            session_reaper_loop(reaper_registry, reaper_shutdown).await;
        });

        // Wait for any shutdown trigger: OS signal (SIGINT/SIGTERM), idle
        // watchdog, or API-driven shutdown via /api/server/shutdown.
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::select! {
            _ = daemon::wait_for_shutdown_signal() => {}
            _ = shutdown_rx.recv() => {
                tracing::info!("shutdown triggered via broadcast (idle watchdog or API)");
            }
        }
        idle_handle.abort();
        reaper_handle.abort();
        daemon.shutdown();
        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
        if let Err(e) = license_handle.await {
            tracing::warn!(error = %e, "license revalidation task panicked");
        }
        if let Err(e) = sync_handle.await {
            tracing::warn!(error = %e, "audit sync task panicked");
        }
        for handle in notification_handles.drain(..) {
            if let Err(e) = handle.await {
                tracing::warn!(error = %e, "notification background task panicked");
            }
        }
    });

    let _ = daemon::remove_dashboard_pid();
    daemon::remove_dashboard_opened();
    let _ = crate::daemon::token::remove_token();
    // Intentionally NOT removing the dashboard token: it is reused across
    // restarts so an already-open browser tab stays authorised. Delete
    // ~/.config/grith/dashboard.token manually to force a rotation.
    println!("Daemon stopped.");
    Ok(())
}

/// Authorise a browser: mint a fresh single-use pairing code from the running
/// daemon and either open the browser at the `#pair=` URL or print it for
/// manual opening. Use this to pair a new browser, after clearing site data, or
/// on a second machine — the persistent token already survives restarts, so a
/// once-paired browser needs this only when its stored token is gone.
pub fn cmd_dashboard_pair(auto_open: bool) -> anyhow::Result<()> {
    let Some((_pid, port)) = daemon::is_dashboard_running() else {
        println!("Dashboard is not running. Start it with: grith dashboard start");
        return Ok(());
    };
    let base = format!("http://127.0.0.1:{port}");
    match fetch_pair_code(port) {
        Some(code) => {
            let url = pair_url(&base, &code);
            if crate::browser::maybe_open_dashboard(auto_open, &url) {
                println!("Opened the dashboard in your browser to authorise this session.");
            } else {
                println!("Open this once to authorise your browser (single-use):");
                println!("  {url}");
            }
        }
        None => {
            eprintln!(
                "Could not reach the dashboard daemon to mint a pairing code. \
                 Is it running? (grith dashboard status)"
            );
        }
    }
    Ok(())
}

/// Stop the running dashboard server.
pub fn cmd_dashboard_stop() -> anyhow::Result<()> {
    let Some((pid, port)) = daemon::is_dashboard_running() else {
        println!("Dashboard is not running.");
        return Ok(());
    };

    let url = format!("http://127.0.0.1:{port}/api/server/shutdown");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let shutdown_ok = runtime.block_on(async {
        let mut request = reqwest::Client::new()
            .post(&url)
            .timeout(std::time::Duration::from_secs(5));
        if let Some(token) = crate::daemon::token::read_token() {
            request = request.bearer_auth(token);
        }
        matches!(request.send().await, Ok(resp) if resp.status().is_success())
    });

    if shutdown_ok {
        println!("Dashboard server (PID {pid}, port {port}) is shutting down.");
    } else {
        #[cfg(unix)]
        {
            // SAFETY: `libc::kill` with `SIGTERM` requests graceful termination
            // of the target process. The `pid` value was read from our own PID
            // file (`~/.config/grith/dashboard.pid`) which we wrote during
            // `dashboard start`, so it refers to a grith dashboard process.
            // The cast to `libc::pid_t` (i32) is safe because OS-assigned PIDs
            // fit in i32 on all supported platforms. If the process has already
            // exited, `kill` returns -1 with `ESRCH`, which we handle
            // gracefully in the `else` branch below. No signal is sent to
            // unrelated processes because we verified the PID via
            // `is_dashboard_running()` before reaching this point.
            let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
            if ret == 0 {
                println!("Sent SIGTERM to dashboard server (PID {pid}).");
            } else {
                eprintln!(
                    "Failed to stop dashboard server (PID {pid}). It may have already exited."
                );
            }
        }
        #[cfg(not(unix))]
        {
            eprintln!("Could not reach dashboard server at {url}. It may have already exited.");
        }
    }

    let _ = daemon::remove_dashboard_pid();
    daemon::remove_dashboard_opened();
    Ok(())
}

/// Print the dashboard server's status.
pub fn cmd_dashboard_status() -> anyhow::Result<()> {
    match daemon::is_dashboard_running() {
        Some((pid, port)) => {
            let base = format!("http://127.0.0.1:{port}");
            println!("Dashboard is running.");
            println!("  URL:   {base}");
            println!("  PID:   {pid}");
            println!("  Pair:  grith dashboard pair   (authorise a browser)");
            println!("  Stop:  grith dashboard stop");
        }
        None => {
            println!("Dashboard is not running.");
            println!("  Start: grith dashboard start");
        }
    }
    Ok(())
}

/// Build the single-use `…/#pair=<code>` URL the browser captures to redeem the
/// dashboard token. The fragment is never sent to the server; the SPA exchanges
/// the code at `/api/dashboard/pair`, stores the token, and strips the URL.
fn pair_url(base: &str, code: &str) -> String {
    format!("{}/#pair={code}", base.trim_end_matches('/'))
}

/// Ask the running daemon (over IPC, daemon-bearer authed) to mint a fresh
/// single-use pairing code. Used by the separate-process paths (parent
/// auto-start, `dashboard status`, `dashboard pair`) which can't reach the
/// server's in-memory state directly. Retries briefly because the HTTP server
/// may still be coming up right after spawn. Returns `None` if the daemon is
/// unreachable or has no IPC token.
fn fetch_pair_code(port: u16) -> Option<String> {
    let token = crate::daemon::token::read_token()?;
    let url = format!("http://127.0.0.1:{port}/api/ipc/dashboard/pair-code");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(async {
        let client = reqwest::Client::new();
        for attempt in 0..5 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            let resp = client
                .post(&url)
                .bearer_auth(&token)
                .timeout(std::time::Duration::from_secs(3))
                .send()
                .await;
            if let Ok(resp) = resp {
                if resp.status().is_success() {
                    if let Ok(v) = resp.json::<serde_json::Value>().await {
                        if let Some(code) = v.get("code").and_then(|c| c.as_str()) {
                            return Some(code.to_string());
                        }
                    }
                }
            }
        }
        None
    })
}

/// Surface the dashboard to the operator, handing the token off via a single-use
/// pairing code and auto-opening the browser **at most once per daemon
/// instance**.
///
/// `daemon_pid` identifies the running dashboard process: if we've already
/// auto-opened for it (recorded in the `dashboard.opened` marker), we just print
/// the bare URL — so a second `grith exec` against the same daemon never pops a
/// new tab. On the first open for a daemon we record the marker.
///
/// When `auto_open` is set and the session is local (not headless/SSH), open the
/// browser at the `#pair=` URL — never rendered to the terminal. Otherwise print
/// the pairing URL for manual opening (single-use, so a later screenshot is
/// inert). With no code available (daemon unreachable) we fall back to the bare
/// URL.
fn announce_with_pairing(
    prefix: &str,
    base: &str,
    daemon_pid: u32,
    code: Option<&str>,
    auto_open: bool,
) {
    if daemon::dashboard_already_opened(daemon_pid) {
        // Already handed off to a browser for this daemon — don't re-open.
        println!("{prefix}{base}");
        return;
    }
    match code {
        Some(code) => {
            let url = pair_url(base, code);
            if crate::browser::maybe_open_dashboard(auto_open, &url) {
                println!("{prefix}{base}  (opened in your browser)");
                daemon::mark_dashboard_opened(daemon_pid);
            } else {
                println!("{prefix}{base}");
                println!("  Open this once to authorise your browser: {url}");
            }
        }
        None => {
            // Couldn't mint a pairing code (daemon not serving yet, or an older
            // daemon without the pairing endpoint). Point the operator at the
            // explicit command rather than leaving a bare, unauthorised URL.
            println!("{prefix}{base}");
            println!("  To authorise your browser, run: grith dashboard pair");
        }
    }
}

/// Ensure the dashboard is running as a background process.
/// Returns `Some(url)` if the dashboard is available, `None` otherwise.
/// `auto_open` (from `server.auto_open_dashboard`) controls whether a freshly
/// started dashboard is opened in the browser (token via URL fragment, never
/// printed). `persistent` marks an explicit `grith dashboard start`, which must
/// outlive its launching command (idle shutdown disabled); auto-starts from
/// `grith exec` / `grith run` pass `false` so the daemon still idles out after
/// the session ends. If `config_path` is provided, it is forwarded to the
/// spawned child via `--config`.
pub fn ensure_dashboard_running_with_port(
    port: u16,
    auto_open: bool,
    persistent: bool,
    config_path: Option<&std::path::Path>,
) -> Option<String> {
    if let Some((pid, running_port)) = daemon::is_dashboard_running() {
        tracing::info!(port = running_port, "dashboard already running");
        let url = format!("http://127.0.0.1:{running_port}");
        // Already running: open at most once per daemon (keyed by PID). If we
        // already auto-opened for this daemon, `announce_with_pairing` just
        // prints the bare URL — no new tab on every `grith exec`. If not (e.g.
        // a daemon first started in a headless context), a local terminal can
        // still trigger the one-time open.
        let code = fetch_pair_code(running_port);
        announce_with_pairing("Dashboard: ", &url, pid, code.as_deref(), auto_open);
        return Some(url);
    }

    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "could not determine executable path for dashboard auto-start");
            return None;
        }
    };

    let mut args = Vec::new();
    if let Some(cfg_path) = config_path {
        args.push("--config".to_string());
        args.push(cfg_path.display().to_string());
    }
    args.push("dashboard".to_string());
    args.push("start".to_string());

    const STARTUP_POLL_INTERVAL_MS: u64 = 500;

    let mut command = std::process::Command::new(&exe);
    command
        .args(&args)
        // The parent (this process) performs the browser auto-open and the
        // user-facing print below; tell the detached child to skip its own so
        // we don't open two tabs.
        .env("GRITH_DASHBOARD_CHILD", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if persistent {
        // Explicit `grith dashboard start`: the daemon must persist until
        // `grith dashboard stop`, not idle-shutdown when our (the spawner's)
        // process exits a moment from now.
        command.env("GRITH_DASHBOARD_PERSISTENT", "1");
    }
    match command.spawn() {
        Ok(_child) => {
            std::thread::sleep(std::time::Duration::from_millis(STARTUP_POLL_INTERVAL_MS));
            if let Some((pid, running_port)) = daemon::is_dashboard_running() {
                let url = format!("http://127.0.0.1:{running_port}");
                let code = fetch_pair_code(running_port);
                announce_with_pairing("Dashboard started: ", &url, pid, code.as_deref(), auto_open);
                println!("  Stop with: grith dashboard stop");
                Some(url)
            } else {
                // PID file not yet visible; fall back to our target port and a
                // 0 sentinel pid (no marker recorded, so a later call still
                // opens once the daemon is up).
                let url = format!("http://127.0.0.1:{port}");
                let code = fetch_pair_code(port);
                announce_with_pairing(
                    "Dashboard starting at: ",
                    &url,
                    0,
                    code.as_deref(),
                    auto_open,
                );
                Some(url)
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to start dashboard as background process");
            eprintln!("Warning: could not auto-start dashboard: {e}");
            None
        }
    }
}

pub fn ensure_dashboard_running(
    daemon: &daemon::Daemon,
    config_path: Option<&std::path::Path>,
) -> Option<String> {
    ensure_dashboard_running_with_port(
        daemon.config.server.port,
        daemon.config.server.auto_open_dashboard,
        // Auto-started alongside `grith run` / REPL — keep idle-shutdown so it
        // doesn't outlive the session.
        false,
        config_path,
    )
}

/// Idle auto-shutdown watchdog.
///
/// Monitors the supervisor session registry. Once at least one session has
/// registered and then all sessions have exited, starts a grace period
/// countdown. If no new sessions register before the grace period expires,
/// triggers daemon shutdown. This ensures the daemon doesn't linger
/// indefinitely after all CLI instances have exited.
///
/// Set `grace_secs` to 0 to disable idle auto-shutdown entirely.
async fn idle_auto_shutdown(
    registry: Arc<Mutex<SupervisorRegistry>>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    grace_secs: u64,
) {
    if grace_secs == 0 {
        tracing::info!("idle watchdog: disabled (idle_shutdown_seconds = 0)");
        // Park forever — the task will be aborted on normal shutdown.
        std::future::pending::<()>().await;
        return;
    }
    let grace_period = std::time::Duration::from_secs(grace_secs);

    // Phase 1: Wait for a session to register. Track registrations via the
    // reap count so we catch the case where a session registers then
    // immediately dies before the next poll. The spawning grith process is
    // tracked via its PID — if it exits before any session registers, the
    // daemon shuts down (prevents orphans from failed startups).
    let spawner_pid = {
        #[cfg(unix)]
        {
            unsafe { libc::getppid() as u32 }
        }
        #[cfg(not(unix))]
        {
            0u32
        }
    };
    let mut ever_registered = false;
    loop {
        tokio::time::sleep(IDLE_POLL_INTERVAL).await;

        let (count, reaped) = registry
            .lock()
            .map(|mut r| {
                let reaped = r.reap_dead();
                (r.count(), reaped)
            })
            .unwrap_or((0, 0));

        if reaped > 0 {
            ever_registered = true;
        }

        if count > 0 {
            tracing::debug!(
                sessions = count,
                "idle watchdog: first session detected, armed"
            );
            break;
        }

        if ever_registered {
            tracing::info!("idle watchdog: session registered then exited, starting grace period");
            break;
        }

        // Check if the process that spawned the daemon is still alive.
        // If it exited before registering a session, this daemon is orphaned.
        if spawner_pid > 1 && !session_alive(spawner_pid) {
            tracing::info!(
                spawner_pid,
                "idle watchdog: spawner process exited before registering a session, shutting down"
            );
            let _ = shutdown_tx.send(());
            return;
        }
    }

    // Phase 2: Monitor for the registry going empty. Once all sessions exit,
    // start the grace timer.
    let mut idle_since: Option<tokio::time::Instant> = None;
    loop {
        tokio::time::sleep(IDLE_POLL_INTERVAL).await;
        let count = registry
            .lock()
            .map(|mut r| {
                let reaped = r.reap_dead();
                if reaped > 0 {
                    tracing::info!(reaped, "idle watchdog: removed dead sessions");
                }
                r.count()
            })
            .unwrap_or(0);

        if count > 0 {
            if idle_since.is_some() {
                tracing::debug!(
                    sessions = count,
                    "idle watchdog: sessions active, timer reset"
                );
            }
            idle_since = None;
            continue;
        }

        let since = *idle_since.get_or_insert_with(|| {
            tracing::info!(
                grace_secs,
                "idle watchdog: all sessions exited, grace period started"
            );
            tokio::time::Instant::now()
        });

        if since.elapsed() >= grace_period {
            tracing::info!("idle watchdog: grace period expired, initiating daemon shutdown");
            let _ = shutdown_tx.send(());
            return;
        }
    }
}

/// Always-on reaper that evicts dead sessions from the registry.
///
/// Runs for the lifetime of the daemon, independent of the idle-shutdown
/// watchdog (which only reaps as a side effect and parks forever when
/// `idle_shutdown_seconds = 0`). Reaping only removes sessions whose root PID
/// is dead AND whose heartbeat is stale — a live supervised process is never
/// evicted. Exits when a shutdown is broadcast.
async fn session_reaper_loop(
    registry: Arc<Mutex<SupervisorRegistry>>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(IDLE_POLL_INTERVAL) => {
                let reaped = registry
                    .lock()
                    .map(|mut r| r.reap_dead())
                    .unwrap_or(0);
                if reaped > 0 {
                    tracing::info!(reaped, "session reaper: removed dead sessions");
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::debug!("session reaper: shutdown received, exiting");
                return;
            }
        }
    }
}
