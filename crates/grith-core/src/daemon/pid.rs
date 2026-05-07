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
