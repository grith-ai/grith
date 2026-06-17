// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Best-effort "open the dashboard in the operator's browser" helper.
//!
//! Used to hand the dashboard auth token to the browser via the URL fragment
//! **without ever rendering the secret to the terminal** (so it cannot leak
//! into scrollback, screenshots, screen-shares, or session recordings). The
//! fragment is consumed by the SPA and stripped from the address bar; it is
//! never transmitted to the server.
//!
//! Gated by `server.auto_open_dashboard` (config) and auto-skipped on headless
//! / SSH sessions where there is no local browser to open. When this path is
//! unavailable the caller falls back to printing a single-use pairing URL.

/// Returns `true` when this looks like a headless or remote session where
/// auto-opening a browser would be pointless (or would open a browser on the
/// wrong machine).
///
/// Heuristics, any of which mark the session non-local:
/// - `$SSH_CONNECTION` / `$SSH_TTY` set → remote shell.
/// - Linux/BSD with neither `$DISPLAY` nor `$WAYLAND_DISPLAY` → no GUI.
///
/// macOS and Windows always have a window server, so the display check is
/// skipped there.
#[must_use]
pub fn is_headless_session() -> bool {
    let ssh = std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some();

    // Only X11/Wayland platforms need a display to open a browser; macOS and
    // Windows always have a window server.
    let needs_display = cfg!(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd"
    ));
    let has_display =
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();

    headless_decision(ssh, needs_display, has_display)
}

/// Pure headless decision, factored out for testing. A session is headless if
/// it is an SSH/remote shell, or if the platform needs a display server and
/// none is present.
fn headless_decision(ssh: bool, needs_display: bool, has_display: bool) -> bool {
    ssh || (needs_display && !has_display)
}

/// Platform opener command + leading args. Returns `None` on unsupported
/// platforms.
fn opener_command() -> Option<(&'static str, &'static [&'static str])> {
    #[cfg(target_os = "macos")]
    {
        Some(("open", &[]))
    }
    #[cfg(target_os = "windows")]
    {
        // `cmd /c start "" <url>` — the empty title arg prevents `start` from
        // treating a quoted URL as the window title.
        Some(("cmd", &["/C", "start", ""]))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Some(("xdg-open", &[]))
    }
}

/// Attempt to open `url` in the operator's default browser.
///
/// Returns `true` if the opener process was spawned successfully. This does
/// **not** prove a browser actually rendered the page — only that the platform
/// handler accepted the URL — so callers should treat `false` as "fall back to
/// the printed pairing URL" and `true` as "browser handoff attempted".
///
/// Best-effort and non-blocking: the opener is spawned detached; we do not wait
/// for the browser. Any spawn error (no `xdg-open`, sandboxed env, etc.) yields
/// `false` rather than propagating.
#[must_use]
pub fn open_url(url: &str) -> bool {
    let Some((cmd, args)) = opener_command() else {
        return false;
    };

    let mut command = std::process::Command::new(cmd);
    command.args(args).arg(url);

    // Detach stdio so a chatty opener can't scribble on the TUI / token-free
    // terminal output.
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    match command.spawn() {
        Ok(mut child) => {
            // Reap on platforms where the opener exits immediately (xdg-open
            // returns once the handler is launched). Don't block on GUI ones.
            let _ = child.try_wait();
            true
        }
        Err(e) => {
            tracing::debug!(error = %e, opener = cmd, "failed to spawn browser opener");
            false
        }
    }
}

/// Open the dashboard if auto-open is enabled and the session is local.
///
/// `enabled` is the `server.auto_open_dashboard` config value. Returns `true`
/// when a browser handoff was attempted (so the caller can suppress the
/// fallback pairing print), `false` when skipped (disabled / headless / opener
/// failed).
#[must_use]
pub fn maybe_open_dashboard(enabled: bool, tokenized_url: &str) -> bool {
    if !enabled {
        tracing::debug!("auto-open dashboard disabled by config");
        return false;
    }
    if is_headless_session() {
        tracing::debug!("auto-open dashboard skipped: headless/SSH session");
        return false;
    }
    open_url(tokenized_url)
}

#[cfg(test)]
mod tests {
    use super::headless_decision;

    #[test]
    fn ssh_is_always_headless() {
        // SSH session wins regardless of a forwarded display.
        assert!(headless_decision(true, true, true));
        assert!(headless_decision(true, false, false));
    }

    #[test]
    fn display_platform_needs_a_display() {
        // Linux/BSD: no display => headless; display present => local.
        assert!(headless_decision(false, true, false));
        assert!(!headless_decision(false, true, true));
    }

    #[test]
    fn non_display_platform_is_always_local_without_ssh() {
        // macOS/Windows: a window server always exists, so display state is
        // irrelevant.
        assert!(!headless_decision(false, false, false));
        assert!(!headless_decision(false, false, true));
    }

    #[test]
    fn maybe_open_disabled_never_spawns() {
        // The disabled short-circuit must return false without consulting the
        // environment or spawning an opener.
        assert!(!super::maybe_open_dashboard(
            false,
            "http://127.0.0.1:3141/#token=x"
        ));
    }

    // `open_url` end-to-end: point PATH at a fake opener of the platform's
    // opener name and assert it is invoked with the exact URL (fragment
    // included). Unix-only: faking the Windows `cmd` shell is unsafe.
    #[cfg(unix)]
    #[test]
    fn open_url_invokes_platform_opener_with_url() {
        use std::io::Write;
        let (opener_name, _) = super::opener_command().expect("unix opener");

        let dir = std::env::temp_dir().join(format!("grith-opener-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("captured");
        let fake = dir.join(opener_name);
        {
            let mut f = std::fs::File::create(&fake).unwrap();
            // Record every argument, one per line, into the marker file.
            writeln!(f, "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}", marker.display()).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Serialise the PATH mutation against other env-touching tests in this
        // binary; PATH is process-global.
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        let saved_path = std::env::var_os("PATH");
        std::env::set_var("PATH", &dir);

        let url = "http://127.0.0.1:3141/#token=secret-abc";
        let spawned = super::open_url(url);

        // Restore PATH before assertions so a failure can't leave it broken.
        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        drop(_guard);

        assert!(spawned, "open_url should report a spawned opener");
        // The opener exits ~immediately; give it a beat to write the marker.
        for _ in 0..50 {
            if marker.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let captured = std::fs::read_to_string(&marker).unwrap_or_default();
        assert!(
            captured.contains(url),
            "opener should receive the full tokenised URL; got {captured:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
