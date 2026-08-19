// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Startup update checker.
//!
//! On each launch, queries the GitHub Releases API for the latest version.
//! If a newer version is available, prompts the user to upgrade via the
//! install script. Fails silently on network errors so offline usage is
//! never blocked.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = "grith-ai/grith";
const CHECK_TIMEOUT: Duration = Duration::from_secs(3);
const INSTALL_URL: &str = "https://grith.ai/install";
/// Budget for downloading the install script itself (a few KB). The tarball it
/// then fetches is on the script's own clock, not this one.
const INSTALL_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const INSTALL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Where `install.sh --global` writes the binary.
const GLOBAL_INSTALL_DIR: &str = "/usr/local/bin";

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

    // The installer replaces the binary in its own install directory. If this
    // copy lives somewhere else, running it would install alongside rather
    // than over this one — the update would look like it worked while every
    // launch kept running the old binary and re-offering the same update.
    let install_flag = match resolve_install_dest() {
        InstallDest::UserLocal => None,
        InstallDest::Global => Some("--global"),
        InstallDest::Unmanaged(dir) => {
            eprintln!("  This copy runs from:");
            eprintln!("    {}", dir.display());
            eprintln!();
            eprintln!("  The installer does not manage that directory, so it");
            eprintln!("  cannot replace this binary. Update it from the release");
            eprintln!("  above, or install to ~/.local/bin with:");
            eprintln!();
            eprintln!("    {cyan}curl -fsSL {INSTALL_URL} | sh{reset}");
            eprintln!();
            return Ok(false);
        }
    };

    eprint!("  Install now? [y/N] ");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    if !answer.trim().eq_ignore_ascii_case("y") {
        return Ok(false);
    }

    eprintln!();
    run_upgrade(install_flag)
}

/// Which install directory, if any, owns the running binary.
#[derive(Debug, PartialEq, Eq)]
enum InstallDest {
    /// `~/.local/bin` — the installer's default destination.
    UserLocal,
    /// `/usr/local/bin` — the installer's `--global` destination.
    Global,
    /// Anywhere else: a cargo build, a system package, a hand-placed copy.
    Unmanaged(PathBuf),
}

/// Classify the directory the running binary was launched from. Falls back to
/// `UserLocal` (the pre-existing behaviour) when the path cannot be read.
fn resolve_install_dest() -> InstallDest {
    let Some(exe_dir) = current_exe_dir() else {
        return InstallDest::UserLocal;
    };
    classify_install_dest(&exe_dir, dirs::home_dir().as_deref())
}

fn current_exe_dir() -> Option<PathBuf> {
    let exe = canonical_or_self(std::env::current_exe().ok()?);
    exe.parent().map(Path::to_path_buf)
}

/// Both sides of the comparison are canonicalised so a symlinked `$HOME` (or a
/// symlinked install directory) still matches the path `current_exe` reports.
fn classify_install_dest(exe_dir: &Path, home: Option<&Path>) -> InstallDest {
    let exe_dir = canonical_or_self(exe_dir.to_path_buf());

    if exe_dir == canonical_or_self(PathBuf::from(GLOBAL_INSTALL_DIR)) {
        return InstallDest::Global;
    }
    if let Some(home) = home {
        if exe_dir == canonical_or_self(home.join(".local").join("bin")) {
            return InstallDest::UserLocal;
        }
    }
    InstallDest::Unmanaged(exe_dir)
}

fn canonical_or_self(path: PathBuf) -> PathBuf {
    path.canonicalize().unwrap_or(path)
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

/// Download the install script and run it under `sh`.
///
/// The script is fetched in-process rather than through `curl … | sh` so the
/// download gets a real timeout and a failed download is actually detected: a
/// pipeline reports only the exit status of `sh`, which exits 0 on an empty
/// script, so a curl failure used to read as a successful upgrade.
fn run_upgrade(install_flag: Option<&str>) -> anyhow::Result<bool> {
    let script = match fetch_install_script() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  Could not download the installer: {e}");
            return Ok(false);
        }
    };

    let mut command = std::process::Command::new("sh");
    command.arg("-s");
    if let Some(flag) = install_flag {
        command.arg("--").arg(flag);
    }
    command.stdin(std::process::Stdio::piped());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("  Could not run install script: {e}");
            return Ok(false);
        }
    };

    // Scoped so the pipe is closed before `wait` — `sh` reads the script to
    // EOF, so holding stdin open would deadlock.
    let write_result = {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("installer stdin unavailable"))?;
        stdin.write_all(script.as_bytes())
    };

    let status = child.wait();

    if let Err(e) = write_result {
        eprintln!("  Could not run install script: {e}");
        return Ok(false);
    }

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

/// Download the install script, refusing anything that is not one.
fn fetch_install_script() -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(INSTALL_CONNECT_TIMEOUT)
        .timeout(INSTALL_FETCH_TIMEOUT)
        .user_agent(format!("grith-cli/{CURRENT_VERSION}"))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let resp = client
        .get(INSTALL_URL)
        .send()
        .map_err(|e| format!("request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("{INSTALL_URL} returned {}", resp.status()));
    }

    let body = resp
        .text()
        .map_err(|e| format!("failed to read installer: {e}"))?;

    // A captive portal or error page can answer 200 with HTML. Piping that
    // into `sh` is not useful, so require a shebang before running it.
    if !body.trim_start().starts_with("#!") {
        return Err("downloaded installer is not a shell script".to_string());
    }

    Ok(body)
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

    #[test]
    fn default_install_dir_is_user_local() {
        let home = Path::new("/home/example");
        assert_eq!(
            classify_install_dest(&home.join(".local").join("bin"), Some(home)),
            InstallDest::UserLocal
        );
    }

    #[test]
    fn global_install_dir_detected() {
        // Recognised as global whether or not a home directory resolves.
        assert_eq!(
            classify_install_dest(
                Path::new(GLOBAL_INSTALL_DIR),
                Some(Path::new("/home/example"))
            ),
            InstallDest::Global
        );
        assert_eq!(
            classify_install_dest(Path::new(GLOBAL_INSTALL_DIR), None),
            InstallDest::Global
        );
    }

    #[test]
    fn unmanaged_dirs_are_not_upgraded_in_place() {
        // A cargo build, another user's ~/.local/bin, and a hand-placed copy
        // all fall outside what the installer writes to.
        let home = Path::new("/home/example");
        for dir in [
            "/home/example/projects/grith/target/release",
            "/home/other/.local/bin",
            "/opt/grith/bin",
        ] {
            assert_eq!(
                classify_install_dest(Path::new(dir), Some(home)),
                InstallDest::Unmanaged(PathBuf::from(dir)),
                "{dir} should be unmanaged"
            );
        }
    }

    #[test]
    fn user_local_without_home_is_unmanaged() {
        // No home directory means ~/.local/bin cannot be confirmed, so the
        // installer must not be trusted to replace this copy.
        let dir = Path::new("/home/example/.local/bin");
        assert_eq!(
            classify_install_dest(dir, None),
            InstallDest::Unmanaged(dir.to_path_buf())
        );
    }
}
