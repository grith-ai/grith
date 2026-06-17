// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Dashboard PID file management.
//!
//! Provides functions to write, read, check, and remove the PID file that
//! tracks the background dashboard server process. The PID file is stored at
//! `~/.config/grith/dashboard.pid` and contains the process ID and port number.

use std::path::PathBuf;

/// Directory for grith runtime state files (PID files, etc.).
pub fn runtime_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config").join("grith")
}

/// Write the dashboard PID file.
pub fn write_dashboard_pid(pid: u32, port: u16) -> std::io::Result<()> {
    let dir = runtime_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("dashboard.pid"), format!("{pid}\n{port}"))?;
    Ok(())
}

/// Read the dashboard PID and port from the PID file.
pub fn read_dashboard_pid() -> Option<(u32, u16)> {
    let content = std::fs::read_to_string(runtime_dir().join("dashboard.pid")).ok()?;
    let mut lines = content.lines();
    let pid: u32 = lines.next()?.parse().ok()?;
    let port: u16 = lines.next()?.parse().ok()?;
    Some((pid, port))
}

/// Check if the dashboard process is still alive.
pub fn is_dashboard_running() -> Option<(u32, u16)> {
    let (pid, port) = read_dashboard_pid()?;

    // Check if the process exists by sending signal 0.
    #[cfg(unix)]
    {
        // SAFETY: `libc::kill` with signal 0 does not actually send a signal.
        // It is a standard POSIX liveness probe that returns 0 if the process
        // exists and the caller has permission to signal it, or -1 with errno
        // set to ESRCH if the process does not exist. The `pid` value is read
        // from a PID file we wrote ourselves, so it is a valid pid_t. The cast
        // to `libc::pid_t` (i32) is safe for any u32 process ID assigned by
        // the OS (which fits in i32 on all supported platforms).
        let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
        if alive {
            Some((pid, port))
        } else {
            // Stale PID file -- clean up.
            let _ = remove_dashboard_pid();
            None
        }
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, we cannot use `kill(pid, 0)` to probe liveness.
        // Instead, treat PID files older than 24 hours as stale to prevent a
        // leftover file from permanently blocking dashboard auto-start.
        let pid_path = runtime_dir().join("dashboard.pid");
        if let Ok(meta) = std::fs::metadata(&pid_path) {
            if let Ok(modified) = meta.modified() {
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                if age > std::time::Duration::from_secs(24 * 60 * 60) {
                    tracing::warn!(
                        pid,
                        age_hours = age.as_secs() / 3600,
                        "stale dashboard PID file detected (>24h old), removing"
                    );
                    let _ = remove_dashboard_pid();
                    return None;
                }
            }
        }
        Some((pid, port))
    }
}

/// Remove the dashboard PID file.
pub fn remove_dashboard_pid() -> std::io::Result<()> {
    let path = runtime_dir().join("dashboard.pid");
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

// --- "Browser already auto-opened" marker ---
//
// Records the daemon PID we last auto-opened the dashboard for, so auto-open
// fires at most once per daemon instance. A second `grith exec` against the
// same running daemon won't pop a new tab; a fresh daemon (new PID) will open
// again. Keyed by PID, not a boolean, so a leftover marker from a crashed
// previous daemon doesn't suppress the new one's open.

fn opened_marker_path() -> PathBuf {
    runtime_dir().join("dashboard.opened")
}

/// Record that we auto-opened the dashboard for the daemon with this PID.
pub fn mark_dashboard_opened(daemon_pid: u32) {
    let dir = runtime_dir();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(opened_marker_path(), daemon_pid.to_string());
}

/// Returns true if we have already auto-opened the dashboard for this exact
/// daemon PID. A marker for a different (older/crashed) PID — or a missing /
/// corrupt one — returns false, so the current daemon still gets its one open.
pub fn dashboard_already_opened(daemon_pid: u32) -> bool {
    match std::fs::read_to_string(opened_marker_path()) {
        Ok(content) => opened_marker_matches(&content, daemon_pid),
        Err(_) => false,
    }
}

/// Pure marker-match: does the marker file content name exactly `daemon_pid`?
/// A non-numeric / empty / mismatched marker is treated as "not opened".
fn opened_marker_matches(content: &str, daemon_pid: u32) -> bool {
    content.trim().parse::<u32>() == Ok(daemon_pid)
}

/// Remove the auto-open marker (on daemon shutdown).
pub fn remove_dashboard_opened() {
    let _ = std::fs::remove_file(opened_marker_path());
}

#[cfg(test)]
mod tests {
    use super::opened_marker_matches;

    #[test]
    fn marker_matches_only_the_exact_pid() {
        assert!(opened_marker_matches("4321", 4321));
        assert!(opened_marker_matches("4321\n", 4321)); // trailing newline tolerated
        assert!(!opened_marker_matches("4321", 9999)); // different daemon
    }

    #[test]
    fn corrupt_or_empty_marker_means_not_opened() {
        // A garbage marker must not suppress the current daemon's one open.
        assert!(!opened_marker_matches("", 4321));
        assert!(!opened_marker_matches("not-a-pid", 4321));
    }
}
