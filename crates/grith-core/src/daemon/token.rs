// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Daemon IPC bearer token management.
//!
//! Generates, writes, reads, and removes a random bearer token used to
//! authenticate IPC requests between `grith exec` clients and the daemon.
//! The token is stored at `~/.config/grith/daemon.token` with 0600 permissions.

use std::path::PathBuf;

/// Return the path to the daemon token file.
pub fn token_path() -> PathBuf {
    super::pid::runtime_dir().join("daemon.token")
}

/// Generate a cryptographically random 256-bit hex token.
pub fn generate_token() -> String {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut bytes);
    } else {
        // Fallback: use system time + pid as entropy source (weaker).
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            ^ (std::process::id() as u128);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = ((seed >> (i % 16 * 8)) & 0xFF) as u8;
        }
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write a daemon token to disk with restrictive permissions.
pub fn write_token(token: &str) -> std::io::Result<()> {
    let dir = super::pid::runtime_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("daemon.token");
    std::fs::write(&path, token)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Read the daemon token from disk.
pub fn read_token() -> Option<String> {
    let path = token_path();
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Remove the daemon token file.
pub fn remove_token() -> std::io::Result<()> {
    let path = token_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Return the path to the dashboard browser-auth token file.
///
/// This token is **distinct** from the daemon IPC token: it authorises the
/// dashboard SPA (running in the operator's browser) to perform mutations,
/// without granting the broader authority of an IPC client. The browser
/// learns it from the `#token=` fragment the CLI prints on launch.
pub fn dashboard_token_path() -> PathBuf {
    super::pid::runtime_dir().join("dashboard.token")
}

/// Write the dashboard token to disk with restrictive permissions (0600).
pub fn write_dashboard_token(token: &str) -> std::io::Result<()> {
    let dir = super::pid::runtime_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("dashboard.token");
    std::fs::write(&path, token)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Read the dashboard token from disk. Returns `None` if absent or empty.
pub fn read_dashboard_token() -> Option<String> {
    std::fs::read_to_string(dashboard_token_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Return the persisted dashboard token, generating and writing a fresh one
/// only if none exists yet.
///
/// Unlike the daemon IPC token — which CLI clients re-read from disk on every
/// invocation, so rotating it per launch is harmless — the dashboard token is
/// cached in the operator's *browser* `localStorage` (captured from the
/// `#token=` launch fragment). Minting a new token on every server start would
/// silently invalidate every open dashboard tab, forcing the operator to
/// re-open the printed URL after each restart. Keeping the token **stable
/// across restarts** makes the `#token=` bootstrap a genuine one-time step.
///
/// The token still lives in a `0600` file, so the multi-user trust boundary is
/// unchanged; only the needless per-launch rotation is dropped. To force a new
/// token, delete `~/.config/grith/dashboard.token`.
pub fn get_or_create_dashboard_token() -> String {
    if let Some(existing) = read_dashboard_token() {
        return existing;
    }
    let token = generate_token();
    if let Err(e) = write_dashboard_token(&token) {
        // Non-fatal: the in-memory token still authorises this launch and the
        // browser can bootstrap from the printed `#token=` URL. Only
        // cross-process discovery (status URL, exec TUI link) is degraded.
        tracing::warn!(error = %e, "failed to persist dashboard token; using in-memory token for this launch");
    }
    token
}

/// Remove the dashboard token file.
pub fn remove_dashboard_token() -> std::io::Result<()> {
    let path = dashboard_token_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
