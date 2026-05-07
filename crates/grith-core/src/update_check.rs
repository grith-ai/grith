// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Startup update checker.
//!
//! On each launch, queries the GitHub Releases API for the latest version.
//! If a newer version is available, prompts the user to upgrade via the
//! install script. Fails silently on network errors so offline usage is
//! never blocked.

use std::io::{self, Write};
use std::time::Duration;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = "grith-ai/grith";
const CHECK_TIMEOUT: Duration = Duration::from_secs(3);

/// Check GitHub for a newer release and prompt the user to upgrade.
///
/// Returns `Ok(true)` if the user chose to upgrade (the caller should exit
/// after the upgrade command runs), `Ok(false)` if no update or user declined,
/// and silently returns `Ok(false)` on any network/parse error.
pub fn check_and_prompt(enable_color: bool) -> anyhow::Result<bool> {
    let latest = match fetch_latest_version() {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, "update check skipped");
            return Ok(false);
        }
    };

    if !is_newer(&latest, CURRENT_VERSION) {
        tracing::debug!(current = CURRENT_VERSION, latest = %latest, "up to date");
        return Ok(false);
    }

    // Display update prompt
    let (bold, cyan, reset) = if enable_color {
        ("\x1b[1m", "\x1b[36m", "\x1b[0m")
    } else {
        ("", "", "")
    };

    eprintln!();
    eprintln!(
        "  {bold}Update available:{reset} {cyan}{CURRENT_VERSION}{reset} → {cyan}{latest}{reset}"
    );
    eprintln!("  {cyan}https://github.com/{REPO}/releases/tag/v{latest}{reset}");
    eprintln!();

    eprint!("  Install now? [y/N] ");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    if !answer.trim().eq_ignore_ascii_case("y") {
        return Ok(false);
    }

    eprintln!();
    run_upgrade()
}

/// Fetch the latest release tag from GitHub.
fn fetch_latest_version() -> Result<String, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");

    let client = reqwest::blocking::Client::builder()
        .timeout(CHECK_TIMEOUT)
        .user_agent(format!("grith-cli/{CURRENT_VERSION}"))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API returned {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .map_err(|e| format!("failed to parse response: {e}"))?;

    let tag = body["tag_name"]
        .as_str()
        .ok_or("missing tag_name in response")?;

    // Strip leading 'v' if present
    Ok(tag.strip_prefix('v').unwrap_or(tag).to_string())
}

/// Compare two semver-like version strings (major.minor.patch).
/// Returns `true` if `latest` is strictly newer than `current`.
fn is_newer(latest: &str, current: &str) -> bool {
    let parse = |s: &str| -> Option<(u32, u32, u32)> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some((
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].parse().ok()?,
        ))
    };

    match (parse(latest), parse(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// Execute the install script to perform the upgrade.
fn run_upgrade() -> anyhow::Result<bool> {
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg("curl -fsSL https://grith.ai/install | sh")
        .status();

    match status {
        Ok(s) if s.success() => {
            eprintln!();
            eprintln!("  Upgrade complete. Please re-run your command.");
            eprintln!();
            Ok(true)
        }
        Ok(s) => {
            eprintln!("  Upgrade failed (exit code: {})", s.code().unwrap_or(-1));
            Ok(false)
        }
        Err(e) => {
            eprintln!("  Could not run install script: {e}");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_version_detected() {
        assert!(is_newer("1.0.0", "0.1.0"));
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("0.1.1", "0.1.0"));
    }

    #[test]
    fn same_version_not_newer() {
        assert!(!is_newer("0.1.0", "0.1.0"));
    }

    #[test]
    fn older_version_not_newer() {
        assert!(!is_newer("0.0.9", "0.1.0"));
    }

    #[test]
    fn malformed_version_not_newer() {
        assert!(!is_newer("abc", "0.1.0"));
        assert!(!is_newer("0.1.0", "xyz"));
        assert!(!is_newer("1.0", "0.1.0"));
    }
}
