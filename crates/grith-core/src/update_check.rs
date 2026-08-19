// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Startup update checker.
//!
//! Two launch paths, because they can afford different things:
//!
//! * [`check_and_prompt`] — the interactive path (REPL / `grith run`). Queries
//!   the GitHub Releases API inline and offers to upgrade, exiting the process
//!   if the user accepts.
//! * [`maybe_notify`] — the non-interactive path (`grith exec`). Prints a
//!   one-line notice from a cached answer and returns. It never reads stdin
//!   (which belongs to the supervised tool), never exits (which would swallow
//!   the launch), and never waits on the network.
//!
//! Both fail silently on network errors so offline usage is never blocked.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
/// Where the background refresh records what the release feed last reported.
const NOTICE_CACHE_FILE: &str = "update-check.json";
/// How long a recorded answer is served before a refresh is due. The notice
/// itself is printed from whatever is cached, however old — a release that
/// exists does not stop existing because the record of it went stale.
const NOTICE_REFRESH_TTL_SECS: i64 = 24 * 3600;

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

    // Seed the cache the non-interactive notice reads, so REPL and `run`
    // launches keep it warm for supervised sessions on the same machine.
    write_cache(&latest);

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

/// Print a one-line "update available" notice, without prompting or blocking.
///
/// This is the launch path for supervised sessions (`grith exec`), where
/// [`check_and_prompt`] cannot be used: it reads a `y/N` answer from stdin,
/// which the supervised tool owns, and on accept returns a value that makes
/// `main` exit — so the launch the user actually asked for would never run.
///
/// The notice is printed from the cached answer, so it costs no network time
/// on a path that runs before every supervised tool. When that answer is older
/// than [`NOTICE_REFRESH_TTL_SECS`] a refresh runs on a detached background
/// thread and lands in time for the next launch.
pub fn maybe_notify(enable_color: bool) {
    let cached = read_cache();

    if let Some(entry) = &cached {
        if is_newer(&entry.latest_version, CURRENT_VERSION) {
            eprintln!("{}", notice_line(&entry.latest_version, enable_color));
        }
    }

    if refresh_due(
        cached.as_ref().and_then(UpdateCheckCache::checked_at),
        Utc::now(),
    ) {
        spawn_cache_refresh(cached.map(|c| c.latest_version));
    }
}

/// The notice itself. One line: this prints ahead of a supervised tool taking
/// over the terminal, so it has to be readable in the moment before that and
/// in the scrollback afterwards, without pushing anything off screen.
fn notice_line(latest: &str, enable_color: bool) -> String {
    let (bold, cyan, reset) = if enable_color {
        ("\x1b[1m", "\x1b[36m", "\x1b[0m")
    } else {
        ("", "", "")
    };

    format!(
        "  {bold}Update available:{reset} {cyan}{CURRENT_VERSION}{reset} \u{2192} \
{cyan}{latest}{reset} \u{b7} install with {cyan}curl -fsSL {INSTALL_URL} | sh{reset}"
    )
}

/// Whether the cached answer is old enough to refresh.
///
/// A timestamp in the future (a clock that moved backwards, a cache copied
/// from another machine) counts as due — otherwise the check would be stuck
/// until real time caught up with it.
fn refresh_due(checked_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    let Some(checked_at) = checked_at else {
        return true;
    };
    let elapsed = now.signed_duration_since(checked_at).num_seconds();
    !(0..NOTICE_REFRESH_TTL_SECS).contains(&elapsed)
}

/// Refresh the cached answer on a detached background thread.
///
/// Never joined: the launch path must not wait on the network. If the process
/// exits before the fetch finishes, nothing is written and the next launch
/// tries again. `previous` is carried in so a failed fetch can re-record the
/// last known answer rather than discarding it.
fn spawn_cache_refresh(previous: Option<String>) {
    let spawned = std::thread::Builder::new()
        .name("grith-update-check".to_string())
        .spawn(move || refresh_cache(&cache_dir(), previous, fetch_latest_version));

    if let Err(e) = spawned {
        tracing::debug!(error = %e, "update notice refresh not started");
    }
}

/// Body of the refresh, split out from the thread so it can be driven with a
/// stub fetcher in tests.
///
/// A failed fetch still writes: the timestamp is what makes the next launch
/// wait out the TTL instead of retrying immediately, and `previous` is carried
/// forward so a machine that goes offline does not forget a release it had
/// already been told about.
fn refresh_cache<F>(dir: &Path, previous: Option<String>, fetch: F)
where
    F: FnOnce() -> Result<String, String>,
{
    match fetch() {
        Ok(latest) => write_cache_to(dir, &latest),
        Err(e) => {
            tracing::debug!(error = %e, "update notice refresh failed");
            write_cache_to(dir, previous.as_deref().unwrap_or(CURRENT_VERSION));
        }
    }
}

/// The last answer the release feed gave, and when it gave it.
#[derive(Debug, Serialize, Deserialize)]
struct UpdateCheckCache {
    /// Newest version reported at `checked_at`.
    latest_version: String,
    /// RFC3339 timestamp of the last completed attempt, successful or not.
    checked_at: String,
}

impl UpdateCheckCache {
    fn checked_at(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.checked_at)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    }
}

fn cache_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("grith")
}

fn read_cache() -> Option<UpdateCheckCache> {
    read_cache_from(&cache_dir())
}

fn write_cache(latest: &str) {
    write_cache_to(&cache_dir(), latest);
}

/// Read the cached answer. Any failure — missing, unreadable, written by a
/// different schema — reads as "nothing cached", which suppresses the notice
/// and schedules a refresh.
fn read_cache_from(dir: &Path) -> Option<UpdateCheckCache> {
    let bytes = std::fs::read(dir.join(NOTICE_CACHE_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Record `latest` against the current time, replacing any previous answer.
///
/// Staged through a pid-suffixed temporary file in the same directory and
/// renamed into place, so a launch reading the cache while another writes it
/// sees the old entry or the new one, never a half-written file.
fn write_cache_to(dir: &Path, latest: &str) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::debug!(error = %e, "update notice cache dir unavailable");
        return;
    }

    let entry = UpdateCheckCache {
        latest_version: latest.to_string(),
        checked_at: Utc::now().to_rfc3339(),
    };
    let Ok(json) = serde_json::to_string_pretty(&entry) else {
        return;
    };

    let tmp = dir.join(format!("{NOTICE_CACHE_FILE}.{}.tmp", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, json) {
        tracing::debug!(error = %e, "update notice cache write failed");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, dir.join(NOTICE_CACHE_FILE)) {
        tracing::debug!(error = %e, "update notice cache rename failed");
        let _ = std::fs::remove_file(&tmp);
    }
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
    fn refresh_due_when_nothing_cached() {
        assert!(refresh_due(None, Utc::now()));
    }

    #[test]
    fn fresh_cache_does_not_refresh() {
        let now = Utc::now();
        let checked = now - chrono::Duration::seconds(NOTICE_REFRESH_TTL_SECS - 60);
        assert!(!refresh_due(Some(checked), now));
    }

    #[test]
    fn stale_cache_refreshes() {
        let now = Utc::now();
        let checked = now - chrono::Duration::seconds(NOTICE_REFRESH_TTL_SECS + 1);
        assert!(refresh_due(Some(checked), now));
    }

    /// A cache stamped in the future must not pin the check shut until the
    /// clock catches up with it.
    #[test]
    fn future_cache_refreshes() {
        let now = Utc::now();
        assert!(refresh_due(Some(now + chrono::Duration::hours(72)), now));
    }

    #[test]
    fn notice_names_both_versions_and_the_install_command() {
        let line = notice_line("9.9.9", false);
        assert!(line.contains(CURRENT_VERSION), "missing current: {line}");
        assert!(line.contains("9.9.9"), "missing latest: {line}");
        assert!(line.contains(INSTALL_URL), "missing installer: {line}");
    }

    /// The notice prints straight ahead of a supervised tool taking the
    /// terminal, so it stays a single line whatever the version strings are.
    #[test]
    fn notice_is_one_line() {
        assert!(!notice_line("10.20.30", true).contains('\n'));
    }

    #[test]
    fn notice_honours_no_color() {
        assert!(!notice_line("9.9.9", false).contains('\x1b'));
        assert!(notice_line("9.9.9", true).contains('\x1b'));
    }

    #[test]
    fn cache_survives_a_write_read_cycle_on_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            read_cache_from(dir.path()).is_none(),
            "empty dir has no cache"
        );

        write_cache_to(dir.path(), "1.2.3");
        let entry = read_cache_from(dir.path()).expect("cache written");
        assert_eq!(entry.latest_version, "1.2.3");
        assert!(!refresh_due(entry.checked_at(), Utc::now()), "just written");

        // A second write replaces the answer rather than accumulating files.
        write_cache_to(dir.path(), "4.5.6");
        assert_eq!(
            read_cache_from(dir.path())
                .expect("cache rewritten")
                .latest_version,
            "4.5.6"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "staging files left behind: {leftovers:?}"
        );
    }

    #[test]
    fn refresh_records_what_the_feed_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        refresh_cache(dir.path(), None, || Ok("7.8.9".to_string()));
        assert_eq!(
            read_cache_from(dir.path()).expect("cache").latest_version,
            "7.8.9"
        );
    }

    /// Going offline must not lose a release the machine already knew about,
    /// and must not retry on every launch either.
    #[test]
    fn failed_refresh_keeps_the_previous_answer_and_stamps_the_attempt() {
        let dir = tempfile::tempdir().expect("tempdir");
        refresh_cache(dir.path(), Some("7.8.9".to_string()), || {
            Err("offline".to_string())
        });

        let entry = read_cache_from(dir.path()).expect("cache");
        assert_eq!(entry.latest_version, "7.8.9");
        assert!(!refresh_due(entry.checked_at(), Utc::now()));
    }

    /// With nothing known and no answer, the recorded version is our own — so
    /// no notice is printed on the strength of a failed check.
    #[test]
    fn failed_first_refresh_records_current_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        refresh_cache(dir.path(), None, || Err("offline".to_string()));

        let entry = read_cache_from(dir.path()).expect("cache");
        assert_eq!(entry.latest_version, CURRENT_VERSION);
        assert!(!is_newer(&entry.latest_version, CURRENT_VERSION));
    }

    /// Garbage in the cache must not surface as a notice — it reads as
    /// "nothing known", which is the same as a first run.
    #[test]
    fn corrupt_cache_reads_as_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(NOTICE_CACHE_FILE), b"{ not json").expect("write");
        assert!(read_cache_from(dir.path()).is_none());
    }

    /// The cache directory is created on demand: a fresh install has a config
    /// dir only once something writes to it.
    #[test]
    fn write_creates_missing_cache_dir() {
        let root = tempfile::tempdir().expect("tempdir");
        let nested = root.path().join("grith");
        write_cache_to(&nested, "1.2.3");
        assert_eq!(
            read_cache_from(&nested)
                .expect("cache written")
                .latest_version,
            "1.2.3"
        );
    }

    #[test]
    fn cache_round_trips() {
        let entry = UpdateCheckCache {
            latest_version: "1.2.3".to_string(),
            checked_at: Utc::now().to_rfc3339(),
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let back: UpdateCheckCache = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.latest_version, "1.2.3");
        assert!(back.checked_at().is_some());
    }

    /// An unparseable timestamp must read as "no idea when", which schedules a
    /// refresh rather than trusting the entry forever.
    #[test]
    fn unparseable_timestamp_refreshes() {
        let entry = UpdateCheckCache {
            latest_version: "1.2.3".to_string(),
            checked_at: "not-a-timestamp".to_string(),
        };
        assert!(entry.checked_at().is_none());
        assert!(refresh_due(entry.checked_at(), Utc::now()));
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
