//! Authority-delegating spawn + control-injection socket enforcement.
//!
//! Some operations do their real work in a process that is **not** a
//! descendant of the supervised tool, so the supervisor's ptrace tree never
//! sees the effect:
//!
//!   * spawning an *authority-delegating binary* (`systemd-run`, `at`,
//!     `docker`, `systemctl`, `dbus-send`, …) hands the command to the init
//!     system / a container daemon / an at-queue / the session bus, which
//!     forks and executes it outside the traced tree;
//!   * connecting to a *control-injection IPC socket* (session D-Bus, tmux,
//!     screen, X11) lets the tool drive a more-privileged peer that runs
//!     commands on its behalf.
//!
//! This is the `systemd-run --user … -- <cmd>` supervision-escape class: the
//! escaping command reads secrets, opens network connections, and mutates
//! files with none of it intercepted or scored.
//!
//! These two detections shipped **audit-only** (a forensics tag, then allow)
//! while their false-positive budget was measured. This module promotes them
//! to real enforcement: when the owning config flag is on and the profile has
//! not explicitly permitted the target, an `Allow` decision is escalated to
//! `Queue { High }` **after** proxy evaluation — reusing the exact
//! freeze/prompt/digest/reputation/audit machinery as
//! [`crate::supervisor::mass_destruction`]. Escalation is deliberately QUEUE,
//! not DENY, so an operator can approve legitimate use once and the session
//! allowlist remembers it; a non-interactive session fails safe (the queue
//! falls back to deny with nobody to answer).
//!
//! ## Curation policy
//!
//! [`is_authority_delegating_binary`] and [`is_control_injection_socket`] are
//! **security-relevant**. Adding or removing an entry changes what escapes
//! supervision; changes here are gated on security-team review. The binary
//! classifier is basename-keyed and therefore does not defeat a renamed copy
//! (`cp /usr/bin/systemd-run /tmp/x && /tmp/x`); canonical-path/content-hash
//! hardening (mirroring `grith_proxy::filters::outbound_binaries`) and proxy-
//! side scoring that would also cover the built-in-agent (Path 1) path are
//! tracked follow-ups. The reported escape uses the binary under its real
//! name and is caught.

use grith_proxy::types::{ProxyAction, ProxyDecision, QueuePriority};

/// Emergency env kill-switch for spawn enforcement. See [`env_override`].
const SPAWN_ENV: &str = "GRITH_ENFORCE_AUTHORITY_DELEGATING_SPAWN";
/// Emergency env kill-switch for control-socket enforcement.
const CONTROL_SOCKET_ENV: &str = "GRITH_ENFORCE_CONTROL_SOCKET_CONNECT";

/// Control-injection IPC sockets — a connect here drives a more-privileged
/// peer that can run commands on the tool's behalf (tmux/screen pane
/// injection, X11 input synthesis, session D-Bus method calls). ssh-agent /
/// gpg-agent are deliberately excluded — they are covered by
/// `is_sensitive_unix_socket` and route to the proxy already.
///
/// KNOWN GAP: abstract-namespace unix sockets (`sun_path[0] == '\0'`) render as
/// an empty `unix:` address upstream (the tracee-string read stops at the
/// leading NUL), so an abstract-socket session bus (`unix:abstract=…`) is not
/// matched here. Pathname sockets (`unix:path=/run/user/<uid>/bus`, the modern
/// default) are covered. Rendering abstract sockets as `unix:@<name>` so they
/// can be matched is a tracked follow-up; the primary escape (an authority-
/// delegating *binary spawn*) does not depend on socket rendering.
pub(super) fn is_control_injection_socket(address: &str) -> bool {
    let path = address
        .strip_prefix("unix:")
        .unwrap_or(address)
        .to_ascii_lowercase();
    // Path-component-anchored markers so we don't over-match unrelated sockets
    // (e.g. `/screen` must not fire on `.../screenshots/x.sock`).
    const MARKERS: &[&str] = &["/tmux-", "/.x11-unix/", "/screen/", "/dbus-", "/dbus/"];
    MARKERS.iter().any(|m| path.contains(m))
        || (path.starts_with("/run/user/") && path.ends_with("/bus")) // session D-Bus
}

/// Authority-delegating binaries — their effect is executed by a privileged
/// or unsupervised peer (a daemon, the init system, the session bus, an
/// `at`/`cron` queue) rather than in the supervised tree. Basename-keyed;
/// see the module curation-policy note on the spoofing limitation.
pub(super) fn is_authority_delegating_binary(command: &str) -> bool {
    matches!(
        basename(command),
        "docker"
            | "podman"
            | "nerdctl"
            | "kubectl"
            | "tmux"
            | "screen"
            | "systemctl"
            | "systemd-run"
            | "dbus-send"
            | "gdbus"
            | "busctl"
            | "at"
            | "batch"
            | "crontab"
            | "flatpak"
            | "nsenter"
            | "machinectl"
            | "loginctl"
    )
}

fn basename(command: &str) -> &str {
    std::path::Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command)
}

/// Parse an env override with the same semantics as the routine-signal
/// override (`operation_risk`): unset/empty → `None` (config wins); any value
/// that is not case-insensitively `0`/`false`/`no` → `Some(true)`; those three
/// → `Some(false)`. Lets an operator force the flag on or off without a config
/// redeploy, in either direction.
fn env_override(var: &str) -> Option<bool> {
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => {
            let v = v.trim().to_ascii_lowercase();
            Some(!matches!(v.as_str(), "0" | "false" | "no"))
        }
        _ => None,
    }
}

/// Effective spawn-enforcement state: env override wins over `config_flag`.
pub(super) fn spawn_enforcement_enabled(config_flag: bool) -> bool {
    env_override(SPAWN_ENV).unwrap_or(config_flag)
}

/// Effective control-socket-enforcement state: env override wins over config.
pub(super) fn control_socket_enforcement_enabled(config_flag: bool) -> bool {
    env_override(CONTROL_SOCKET_ENV).unwrap_or(config_flag)
}

/// True when the profile's `permit_authority_delegating` list authorises this
/// binary (basename match — an operator writes `"systemd-run"`).
fn spawn_permitted(command: &str, permit: &[String]) -> bool {
    let b = basename(command);
    permit.iter().any(|p| basename(p) == b)
}

/// True when the profile's `permit_control_sockets` list authorises this
/// socket. Each entry is a substring of the (case-insensitive) socket path,
/// so `"/run/user/1000/bus"` or a broader `"/tmux-"` both work.
fn control_socket_permitted(address: &str, permit: &[String]) -> bool {
    let path = address
        .strip_prefix("unix:")
        .unwrap_or(address)
        .to_ascii_lowercase();
    permit
        .iter()
        .any(|p| !p.is_empty() && path.contains(&p.to_ascii_lowercase()))
}

/// Whether an authority-delegating spawn of `command` should be escalated
/// under this profile: it is authority-delegating AND not explicitly
/// permitted. (Caller has already checked the enforce flag.)
pub(super) fn spawn_should_escalate(command: &str, permit: &[String]) -> bool {
    is_authority_delegating_binary(command) && !spawn_permitted(command, permit)
}

/// Whether a control-injection socket connect to `address` should be escalated
/// under this profile. (Caller has already checked the enforce flag.)
pub(super) fn control_socket_should_escalate(address: &str, permit: &[String]) -> bool {
    is_control_injection_socket(address) && !control_socket_permitted(address, permit)
}

/// Escalate an `Allow` decision for an authority-delegating spawn to
/// `Queue { High }`. Returns `true` if it escalated. Only touches `Allow`
/// decisions (a call the proxy already queued/denied is left as-is), mirroring
/// [`mass_destruction::maybe_escalate`]. The caller must have confirmed the
/// enforce flag is on before calling.
pub(super) fn maybe_escalate_spawn(
    decision: &mut ProxyDecision,
    command: &str,
    permit: &[String],
) -> bool {
    if !spawn_should_escalate(command, permit) {
        return false;
    }
    if !matches!(decision.action, ProxyAction::Allow) {
        return false;
    }
    decision.action = ProxyAction::Queue {
        priority: QueuePriority::High,
    };
    decision.decision_reason = format!(
        "authority-delegating spawn queued for review: `{}` runs its effect in a privileged or \
         unsupervised peer, outside supervision",
        basename(command)
    );
    true
}

/// Escalate an `Allow` decision for a control-injection socket connect to
/// `Queue { High }`. Returns `true` if it escalated.
pub(super) fn maybe_escalate_control_socket(
    decision: &mut ProxyDecision,
    address: &str,
    permit: &[String],
) -> bool {
    if !control_socket_should_escalate(address, permit) {
        return false;
    }
    if !matches!(decision.action, ProxyAction::Allow) {
        return false;
    }
    decision.action = ProxyAction::Queue {
        priority: QueuePriority::High,
    };
    decision.decision_reason = format!(
        "control-injection IPC socket connect queued for review: `{address}` can drive a \
         more-privileged peer that runs commands on the tool's behalf"
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use grith_proxy::types::FilterResult;
    use std::time::Duration;

    fn allow_decision() -> ProxyDecision {
        ProxyDecision {
            action: ProxyAction::Allow,
            composite_score: 1.0,
            filter_results: Vec::<FilterResult>::new(),
            evaluation_time: Duration::from_millis(0),
            decision_reason: "allowed".into(),
        }
    }

    #[test]
    fn control_injection_socket_recognised() {
        for addr in [
            "unix:/tmp/tmux-1000/default",
            "unix:/tmp/.X11-unix/X0",
            "unix:/run/screen/S-user/12345.pts-0",
            "unix:/run/user/1000/bus",
            "unix:/run/user/1000/dbus/session_bus_socket",
        ] {
            assert!(is_control_injection_socket(addr), "{addr:?} should match");
        }
        for addr in [
            "unix:/var/run/nscd/socket",
            "unix:/run/user/1000/gnupg/S.gpg-agent", // agent socket: handled elsewhere
            "unix:/tmp/app/screenshots/x.sock",      // must not match on "/screen"
            "unix:/run/foo/screen-share.sock",       // must not match on "/screen"
            "127.0.0.1",
        ] {
            assert!(
                !is_control_injection_socket(addr),
                "{addr:?} should NOT match"
            );
        }
    }

    #[test]
    fn authority_delegating_binary_recognised() {
        for cmd in [
            "/usr/bin/docker",
            "kubectl",
            "/usr/bin/tmux",
            "systemctl",
            "dbus-send",
            "crontab",
            "/usr/bin/systemd-run",
        ] {
            assert!(is_authority_delegating_binary(cmd), "{cmd:?} should match");
        }
        for cmd in ["/bin/ls", "cat", "/usr/bin/git", "node"] {
            assert!(
                !is_authority_delegating_binary(cmd),
                "{cmd:?} should NOT match"
            );
        }
    }

    #[test]
    fn env_override_semantics() {
        // Only the three falsey spellings force off; everything else forces on.
        assert_eq!(env_override_from("1"), Some(true));
        assert_eq!(env_override_from("yes"), Some(true));
        assert_eq!(env_override_from("on"), Some(true));
        assert_eq!(env_override_from("0"), Some(false));
        assert_eq!(env_override_from("false"), Some(false));
        assert_eq!(env_override_from("NO"), Some(false));
        assert_eq!(env_override_from(""), None);
        assert_eq!(env_override_from("   "), None);
    }

    // Mirror of `env_override` that reads a literal instead of the process
    // environment, so the parse logic is testable without env mutation.
    fn env_override_from(v: &str) -> Option<bool> {
        if v.trim().is_empty() {
            return None;
        }
        let v = v.trim().to_ascii_lowercase();
        Some(!matches!(v.as_str(), "0" | "false" | "no"))
    }

    #[test]
    fn spawn_escalates_unpermitted_authority_binary() {
        let mut d = allow_decision();
        assert!(maybe_escalate_spawn(&mut d, "/usr/bin/systemd-run", &[]));
        assert!(matches!(
            d.action,
            ProxyAction::Queue {
                priority: QueuePriority::High
            }
        ));
    }

    #[test]
    fn spawn_permit_list_suppresses_escalation() {
        let mut d = allow_decision();
        let permit = vec!["systemd-run".to_string()];
        assert!(!maybe_escalate_spawn(
            &mut d,
            "/usr/bin/systemd-run",
            &permit
        ));
        assert!(matches!(d.action, ProxyAction::Allow));
    }

    #[test]
    fn spawn_does_not_escalate_ordinary_binary() {
        let mut d = allow_decision();
        assert!(!maybe_escalate_spawn(&mut d, "/usr/bin/git", &[]));
        assert!(matches!(d.action, ProxyAction::Allow));
    }

    #[test]
    fn spawn_never_downgrades_a_non_allow_decision() {
        // A deny must survive even for an authority-delegating binary.
        let mut d = allow_decision();
        d.action = ProxyAction::Deny {
            reason: "already denied".into(),
        };
        assert!(!maybe_escalate_spawn(&mut d, "systemd-run", &[]));
        assert!(matches!(d.action, ProxyAction::Deny { .. }));
    }

    #[test]
    fn control_socket_escalates_and_permit_suppresses() {
        let mut d = allow_decision();
        assert!(maybe_escalate_control_socket(
            &mut d,
            "unix:/run/user/1000/bus",
            &[]
        ));
        assert!(matches!(d.action, ProxyAction::Queue { .. }));

        let mut d2 = allow_decision();
        let permit = vec!["/run/user/1000/bus".to_string()];
        assert!(!maybe_escalate_control_socket(
            &mut d2,
            "unix:/run/user/1000/bus",
            &permit
        ));
        assert!(matches!(d2.action, ProxyAction::Allow));
    }
}
