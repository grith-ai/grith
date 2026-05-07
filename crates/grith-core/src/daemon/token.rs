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
