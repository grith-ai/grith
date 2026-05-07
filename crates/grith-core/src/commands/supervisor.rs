// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith supervisor` subcommand — list, inspect, and manage active supervisor sessions.

use crate::daemon;

pub fn cmd_supervisor_remote(
    daemon_client: &crate::daemon::client::DaemonClient,
    action: Option<crate::SupervisorAction>,
) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    match action {
        None | Some(crate::SupervisorAction::List) => {
            let sessions = runtime.block_on(daemon_client.list_sessions())?;
            if sessions.is_empty() {
                println!("No active supervisor sessions.");
            } else {
                println!("Active supervisor sessions ({}):", sessions.len());
                for s in &sessions {
                    let containment = s
                        .containment_remaining_seconds
                        .map(|r| format!(" | CONTAINED ({r}s)"))
                        .unwrap_or_default();
                    println!(
                        "  {} | {} | pid {} | up {}s | {} intercepted ({} allowed, {} queued, {} denied){}",
                        &s.id.to_string()[..8],
                        s.tool_name,
                        s.root_pid,
                        s.uptime_seconds,
                        s.stats.total_intercepted,
                        s.stats.total_allowed,
                        s.stats.total_queued,
                        s.stats.total_denied,
                        containment,
                    );
                }
            }
            println!(
                "Capacity: {} sessions visible via daemon registry",
                sessions.len()
            );
        }
        Some(crate::SupervisorAction::Status { session_id }) => {
            let id: uuid::Uuid = session_id
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid session ID: {session_id}"))?;
            let session = runtime.block_on(daemon_client.get_session(id))?;
            println!("Session: {}", session.id);
            println!("  Tool: {}", session.tool_name);
            println!("  Root PID: {}", session.root_pid);
            println!("  Uptime: {:.1}s", session.uptime_seconds as f64);
            println!("  Intercepted: {}", session.stats.total_intercepted);
            println!("  Allowed: {}", session.stats.total_allowed);
            println!("  Queued: {}", session.stats.total_queued);
            println!("  Denied: {}", session.stats.total_denied);
            println!("  Noise filtered: {}", session.stats.total_filtered_noise);
            match session.containment_remaining_seconds {
                Some(remaining) => println!("  Containment: ACTIVE ({remaining}s remaining)"),
                None => println!("  Containment: inactive"),
            }
            println!(
                "  Process tree: {} processes",
                session.process_tree_pids.len()
            );
        }
        Some(crate::SupervisorAction::Kill { session_id }) => {
            let id: uuid::Uuid = session_id
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid session ID: {session_id}"))?;
            runtime.block_on(daemon_client.kill_session(id))?;
            println!(
                "Terminated session {}",
                &session_id[..8.min(session_id.len())]
            );
        }
    }
    Ok(())
}

pub fn cmd_supervisor(
    daemon: &daemon::Daemon,
    action: Option<crate::SupervisorAction>,
) -> anyhow::Result<()> {
    let registry = daemon
        .supervisor_registry
        .lock()
        .map_err(|_| anyhow::anyhow!("supervisor registry lock poisoned"))?;
    let tracker = &daemon.containment_tracker;

    match action {
        None | Some(crate::SupervisorAction::List) => {
            let sessions = registry.list();
            if sessions.is_empty() {
                println!("No active supervisor sessions.");
            } else {
                println!("Active supervisor sessions ({}):", sessions.len());
                for s in &sessions {
                    let containment = tracker
                        .remaining_seconds(s.id)
                        .map(|r| format!(" | CONTAINED ({r}s)"))
                        .unwrap_or_default();
                    println!(
                        "  {} | {} | pid {} | up {}s | {} intercepted ({} allowed, {} queued, {} denied){}",
                        &s.id.to_string()[..8],
                        s.tool_name,
                        s.root_pid,
                        s.uptime_seconds,
                        s.stats.total_intercepted,
                        s.stats.total_allowed,
                        s.stats.total_queued,
                        s.stats.total_denied,
                        containment,
                    );
                }
            }
            println!(
                "Capacity: {}/{} sessions",
                sessions.len(),
                registry.max_sessions(),
            );
        }
        Some(crate::SupervisorAction::Status { session_id }) => {
            let id: uuid::Uuid = session_id
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid session ID: {session_id}"))?;
            match registry.get(&id) {
                Some(session) => {
                    println!("Session: {}", session.id);
                    println!("  Tool: {}", session.tool_name);
                    println!("  Root PID: {}", session.root_pid);
                    println!("  Uptime: {:.1}s", session.uptime().as_secs_f64());
                    println!("  Intercepted: {}", session.stats.total_intercepted);
                    println!("  Allowed: {}", session.stats.total_allowed);
                    println!("  Queued: {}", session.stats.total_queued);
                    println!("  Denied: {}", session.stats.total_denied);
                    println!("  Noise filtered: {}", session.stats.total_filtered_noise);
                    match tracker.remaining_seconds(session.id) {
                        Some(remaining) => {
                            println!("  Containment: ACTIVE ({remaining}s remaining)");
                        }
                        None => {
                            println!("  Containment: inactive");
                        }
                    }
                    let all_pids = session.process_tree.all_pids();
                    println!("  Process tree: {} processes", all_pids.len());
                }
                None => {
                    eprintln!("Session not found: {session_id}");
                    eprintln!("Use `grith exec list` to see active sessions.");
                }
            }
        }
        Some(crate::SupervisorAction::Kill { session_id }) => {
            drop(registry);
            let id: uuid::Uuid = session_id
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid session ID: {session_id}"))?;
            let mut registry = daemon
                .supervisor_registry
                .lock()
                .map_err(|_| anyhow::anyhow!("supervisor registry lock poisoned"))?;
            match registry.remove(&id) {
                Some(session) => {
                    let pid = session.root_pid;

                    // Send SIGTERM to the root process so it actually stops,
                    // not just removed from the registry.
                    #[cfg(unix)]
                    {
                        // SAFETY: `libc::kill` with `SIGTERM` sends a graceful
                        // termination signal. `pid` came from our own supervisor
                        // registry (we spawned or attached to it). The cast to
                        // `libc::pid_t` (i32) is safe for OS-assigned PIDs.
                        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
                        if ret != 0 {
                            let err = std::io::Error::last_os_error();
                            tracing::warn!(pid, error = %err, "failed to send SIGTERM to supervised process");
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        tracing::warn!(pid, "process signaling not supported on this platform; session removed from registry but process may still be running");
                    }

                    println!(
                        "Terminated session {} (tool: {}, pid: {})",
                        &session.id.to_string()[..8],
                        session.tool_name,
                        pid,
                    );
                }
                None => {
                    eprintln!("Session not found: {session_id}");
                    eprintln!("Use `grith exec list` to see active sessions.");
                }
            }
        }
    }
    Ok(())
}
