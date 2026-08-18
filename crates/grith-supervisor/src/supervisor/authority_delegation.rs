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
//! supervision; changes here are gated on security-team review. The basename
//! classifier is generalised at the escalation sites by
//! [`spawn_should_escalate_full`], which also fires on the **canonical**
//! (symlink-resolved) basename — defeating `run0`→`systemd-run` and
//! `ln -s systemd-run x` — and on a **content SHA-256** match against the
//! session-start-pinned set of the listed binaries ([`build_pinned_authority_metadata`])
//! — defeating an unmodified `cp /usr/bin/systemd-run /tmp/x && /tmp/x`. A
//! hash-only match is deliberately NOT basename-permittable.
//!
//! The content hash catches only **byte-identical** copies/hardlinks; known
//! residuals (all strictly better than the prior basename-only behaviour, not
//! regressions): (1) a content mutation that keeps the binary runnable — e.g.
//! appending a NUL to an ELF — changes the hash and evades; (2) an
//! execute-only (unreadable) disguised copy cannot be hashed, so the hash arm
//! fails open; (3) the ssh/scp/sftp-to-loopback detector is basename-only, so
//! a renamed `ssh` copy evades it; (4) a from-scratch reimplementation under a
//! novel name; (5) proxy-side scoring covering the built-in-agent (Path 1)
//! path. Multicall dispatchers (busybox/toybox) are deliberately NOT pinned —
//! see [`build_pinned_authority_metadata`].

use grith_proxy::types::{ProxyAction, ProxyDecision, QueuePriority};
use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;

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
/// Abstract-namespace unix sockets (`sun_path[0] == '\0'`) are now rendered
/// `unix:@<name>` by `classify::read_sockaddr` (previously they stopped at the
/// leading NUL and rendered a bare `unix:` that never matched). The substring
/// markers below match the `@`-prefixed render directly (abstract X11 =
/// `@/tmp/.X11-unix/X0`, abstract D-Bus = `@/tmp/dbus-…`, the shapes libX11 /
/// libdbus try first); the leading-`@` strip below keeps the exact-suffix
/// session-bus check robust to an abstract bus too. Rendering fidelity depends
/// on the tracee-supplied `addrlen`, but grith reads the same length the kernel
/// uses, so it matches what the kernel actually binds/connects to.
pub(super) fn is_control_injection_socket(address: &str) -> bool {
    let path = address
        .strip_prefix("unix:")
        .unwrap_or(address)
        .to_ascii_lowercase();
    // Strip a leading `@` (abstract-namespace marker) so the exact-suffix
    // session-bus check matches an abstract bus; the substring markers already
    // match `@`-prefixed renders via `contains`.
    let path = path.strip_prefix('@').unwrap_or(&path);
    // Path-component-anchored markers so we don't over-match unrelated sockets
    // (e.g. `/screen` must not fire on `.../screenshots/x.sock`).
    const MARKERS: &[&str] = &["/tmux-", "/.x11-unix/", "/screen/", "/dbus-", "/dbus/"];
    MARKERS.iter().any(|m| path.contains(m))
        || (path.starts_with("/run/user/") && path.ends_with("/bus")) // session D-Bus
}

/// Curated authority-delegating binary basenames. A `const` slice (rather than
/// the old inline `matches!`) so [`build_pinned_authority_metadata`] can resolve
/// and hash each one on `$PATH` at session start. Security-relevant — see the
/// module curation policy. `run0` is systemd's `systemd-run`-equivalent
/// (pkexec-style peer exec); `qdbus*` drive an *existing* session bus like
/// `dbus-send`/`gdbus`/`busctl`. NB: `dbus-launch`/`dbus-run-session` are
/// deliberately NOT here — they start a *private* bus and run their child
/// in-tree (no escape), so listing them would only QUEUE common test wrappers
/// like `dbus-run-session -- meson test`.
pub(super) const AUTHORITY_DELEGATING_BINARIES: &[&str] = &[
    "docker",
    "podman",
    "nerdctl",
    "kubectl",
    "tmux",
    "screen",
    "systemctl",
    "systemd-run",
    "run0",
    "dbus-send",
    "gdbus",
    "busctl",
    "qdbus",
    "qdbus-qt5",
    "qdbus-qt6",
    "qdbus6",
    "at",
    "batch",
    "crontab",
    "flatpak",
    "nsenter",
    "machinectl",
    "loginctl",
];

/// True when `command`'s basename is a curated authority-delegating binary.
/// Raw-basename keyed; the canonical-basename and content-hash generalisations
/// live in [`spawn_should_escalate_full`].
pub(super) fn is_authority_delegating_binary(command: &str) -> bool {
    AUTHORITY_DELEGATING_BINARIES.contains(&basename(command))
}

/// The basename under which `command` (or its canonical, symlink-resolved path)
/// is a curated delegating binary, if any — the key for the read-only
/// subcommand policy. Prefers the raw argv[0] basename; falls back to canonical.
fn matched_delegating_name<'a>(
    command: &'a str,
    canonical_path: Option<&'a str>,
) -> Option<&'a str> {
    if is_authority_delegating_binary(command) {
        Some(basename(command))
    } else if canonical_path.is_some_and(is_authority_delegating_binary) {
        canonical_path.map(basename)
    } else {
        None
    }
}

fn basename(command: &str) -> &str {
    std::path::Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command)
}

/// Resolve every curated authority-delegating binary on `$PATH` at session
/// start and pin its content SHA-256 + file size. The hash set defeats a
/// copy/hardlink placed under a novel name; the size set is a cheap prefilter
/// so the per-spawn gate only hashes a candidate whose size actually collides
/// with a delegating binary (routine build spawns stat+return without hashing).
/// Built only when spawn enforcement is on (caller-gated) so the default-off
/// deployment pays nothing.
///
/// Multiple names can canonicalise to one file (`run0`→`systemd-run`); the hash
/// set dedups. A binary not installed at session start is simply absent — you
/// cannot copy what is not present. Symlinks are resolved so the pinned hash is
/// the real target's.
pub(super) fn build_pinned_authority_metadata() -> (HashSet<String>, HashSet<u64>) {
    build_pinned_from_path(&std::env::var_os("PATH").unwrap_or_default())
}

/// Core of [`build_pinned_authority_metadata`], parameterised on the search
/// path so it is testable without mutating the process-global `PATH`.
fn build_pinned_from_path(path_var: &std::ffi::OsStr) -> (HashSet<String>, HashSet<u64>) {
    let mut hashes = HashSet::new();
    let mut sizes = HashSet::new();
    let mut seen_canonical: HashSet<String> = HashSet::new();
    for name in AUTHORITY_DELEGATING_BINARIES {
        for dir in std::env::split_paths(path_var) {
            let candidate = dir.join(name);
            let Ok(canonical) = std::fs::canonicalize(&candidate) else {
                continue;
            };
            let canonical_str = canonical.to_string_lossy().into_owned();
            // Skip MULTICALL dispatchers. If a delegating NAME resolves (via a
            // symlink) to a file whose OWN basename is not a delegating name —
            // e.g. Alpine/BusyBox `crontab`/`nsenter` → `/bin/busybox`, or
            // toybox — pinning that file's content hash would collide with
            // EVERY applet (`ls`/`cat`/`sh`/...) and QUEUE-storm the tool. Such
            // a symlinked delegator is still caught by the canonical-BASENAME
            // check at spawn time; only pin files whose canonical basename is
            // itself a delegating name (genuinely that binary, not a shared
            // dispatcher). This keeps copy/hardlink detection for real,
            // singly-named delegating binaries while making the fix safe on
            // busybox-based images.
            if !is_authority_delegating_binary(&canonical_str) {
                continue;
            }
            if !seen_canonical.insert(canonical_str) {
                continue; // already hashed this file via another name/dir
            }
            let Ok(meta) = std::fs::metadata(&canonical) else {
                continue;
            };
            if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
                continue;
            }
            if let Ok(sha) = crate::provenance::sha256_file(&canonical) {
                hashes.insert(sha);
                sizes.insert(meta.len());
            }
        }
    }
    (hashes, sizes)
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

/// Permit check that honours both the raw argv[0] basename AND the resolved
/// canonical basename, so an operator who permitted `systemd-run` also
/// suppresses the escalation for its `run0` symlink. A hash-only match (a
/// byte-copy under a disguised name) is deliberately NOT basename-permittable.
fn spawn_permitted_full(command: &str, canonical_path: Option<&str>, permit: &[String]) -> bool {
    spawn_permitted(command, permit) || canonical_path.is_some_and(|p| spawn_permitted(p, permit))
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

// ---------------------------------------------------------------------------
// Read-only subcommand exemption
// ---------------------------------------------------------------------------
//
// Several delegating binaries are ALSO the standard way to *query* their
// subsystem read-only: `docker ps`, `systemctl status`, `kubectl get`,
// `flatpak list`, `tmux list-sessions`. Those invocations delegate no work to an
// unsupervised peer — they read and return — so escalating them is pure
// false-positive friction (dev tools probe them on nearly every startup, once
// per project, once per session). This exempts a curated per-binary set of
// read-only subcommands from the escalation.
//
// **Security-relevant, fail-safe by construction** (curation gated on
// security-team review, like the binary list): an invocation is exempt ONLY
// when it is unambiguously read-only — its subcommand is on the binary's
// read-only allowlist AND no explicitly-delegating verb or delegating global
// option appears anywhere in argv. Anything else — an unknown subcommand, a
// binary with no table, an argv we cannot parse, a disguised-name copy (its
// basename is not a table key), a `run`/`exec`/`start`/… verb — escalates. So a
// curation gap can only ADD a false positive, never open an escape.

/// Per-binary subcommand policy. `read_only` are the query verbs that delegate
/// nothing; `delegating` are the verbs that DO hand work to an unsupervised peer
/// (their presence forces escalation even if a read-only verb also appears, e.g.
/// a container literally named `ps`); `delegating_flags` are global options that
/// themselves delegate with no subcommand (`tmux -c <cmd>`); `value_flags` are
/// global options whose following token is a value to skip when locating the
/// subcommand; `options_only_is_read_only` is whether a bare/options-only
/// invocation is a query (`docker`, `flatpak --version`) or an action (bare
/// `tmux` starts a session).
struct SubcommandPolicy {
    read_only: &'static [&'static str],
    delegating: &'static [&'static str],
    delegating_flags: &'static [&'static str],
    value_flags: &'static [&'static str],
    options_only_is_read_only: bool,
}

fn subcommand_policy(bin: &str) -> Option<SubcommandPolicy> {
    match bin {
        "flatpak" => Some(SubcommandPolicy {
            read_only: &[
                "list",
                "info",
                "ps",
                "history",
                "remotes",
                "remote-info",
                "remote-ls",
                "search",
                "documents",
                "permissions",
                "permission-show",
                "permission-list",
            ],
            delegating: &[
                "run",
                "enter",
                "install",
                "update",
                "upgrade",
                "uninstall",
                "override",
                "make-current",
                "mask",
                "repair",
                "kill",
                "remote-add",
                "remote-modify",
                "remote-delete",
                "config",
                "permission-set",
                "permission-reset",
                "permission-remove",
                "create-usb",
                "build",
                "build-init",
                "build-finish",
                "build-export",
                "build-bundle",
                "build-import-bundle",
                "build-sign",
                "build-update-repo",
                "build-commit-from",
            ],
            delegating_flags: &[],
            value_flags: &["--installation", "--arch"],
            options_only_is_read_only: true,
        }),
        "docker" | "podman" | "nerdctl" => Some(SubcommandPolicy {
            read_only: &[
                "ps", "images", "info", "version", "inspect", "logs", "top", "stats", "port",
                "diff", "history", "events", "search",
            ],
            // Includes the subcommand GROUPS (container/image/volume/network/
            // system/context/…): they nest mutating actions (`docker image rm`),
            // so the whole group escalates rather than trying to parse the
            // nested verb. `docker image ls` therefore still prompts — a
            // tolerable false positive; `docker image rm` must never be exempt.
            delegating: &[
                "run",
                "exec",
                "create",
                "start",
                "restart",
                "stop",
                "kill",
                "pause",
                "unpause",
                "rm",
                "rmi",
                "build",
                "buildx",
                "cp",
                "commit",
                "attach",
                "import",
                "load",
                "save",
                "export",
                "rename",
                "update",
                "push",
                "pull",
                "tag",
                "login",
                "compose",
                "service",
                "swarm",
                "node",
                "stack",
                "plugin",
                "secret",
                "config",
                "container",
                "image",
                "volume",
                "network",
                "system",
                "context",
                "builder",
                "manifest",
                "trust",
                "wait",
            ],
            delegating_flags: &[],
            value_flags: &[
                "-H",
                "--host",
                "--context",
                "--config",
                "-l",
                "--log-level",
                "--tlscacert",
                "--tlscert",
                "--tlskey",
            ],
            options_only_is_read_only: true,
        }),
        "kubectl" => Some(SubcommandPolicy {
            read_only: &[
                "get",
                "describe",
                "logs",
                "top",
                "explain",
                "api-resources",
                "api-versions",
                "version",
                "cluster-info",
                "events",
            ],
            delegating: &[
                "exec",
                "run",
                "apply",
                "create",
                "delete",
                "edit",
                "patch",
                "replace",
                "scale",
                "autoscale",
                "rollout",
                "port-forward",
                "proxy",
                "cp",
                "attach",
                "drain",
                "cordon",
                "uncordon",
                "taint",
                "label",
                "annotate",
                "set",
                "expose",
                "wait",
                "debug",
                "certificate",
                "config",
                "auth",
                "diff",
            ],
            delegating_flags: &[],
            value_flags: &[
                "-n",
                "--namespace",
                "--context",
                "--cluster",
                "--kubeconfig",
                "-s",
                "--server",
                "--user",
                "--token",
                "--as",
                "--request-timeout",
                "--cache-dir",
            ],
            options_only_is_read_only: true,
        }),
        "systemctl" => Some(SubcommandPolicy {
            read_only: &[
                "status",
                "show",
                "list-units",
                "list-unit-files",
                "is-active",
                "is-enabled",
                "is-failed",
                "is-system-running",
                "cat",
                "get-default",
                "list-timers",
                "list-sockets",
                "list-jobs",
                "list-dependencies",
                "list-machines",
                "list-paths",
                "list-automounts",
                "show-environment",
                "help",
            ],
            delegating: &[
                "start",
                "stop",
                "restart",
                "try-restart",
                "reload",
                "reload-or-restart",
                "enable",
                "disable",
                "reenable",
                "preset",
                "preset-all",
                "mask",
                "unmask",
                "kill",
                "set-property",
                "set-default",
                "isolate",
                "daemon-reload",
                "daemon-reexec",
                "edit",
                "revert",
                "reset-failed",
                "add-wants",
                "add-requires",
                "link",
                "switch-root",
                "kexec",
                "reboot",
                "poweroff",
                "halt",
                "suspend",
                "hibernate",
                "hybrid-sleep",
                "emergency",
                "rescue",
                "default",
                "set-environment",
                "unset-environment",
                "import-environment",
            ],
            delegating_flags: &[],
            value_flags: &[
                "-t",
                "--type",
                "--state",
                "-p",
                "--property",
                "-M",
                "--machine",
                "-H",
                "--host",
                "--root",
                "--when",
                "--signal",
                "-s",
                "--job-mode",
            ],
            options_only_is_read_only: true,
        }),
        "tmux" => Some(SubcommandPolicy {
            read_only: &[
                "list-sessions",
                "ls",
                "list-windows",
                "lsw",
                "list-panes",
                "lsp",
                "list-clients",
                "lsc",
                "list-commands",
                "lscm",
                "list-keys",
                "lsk",
                "list-buffers",
                "lsb",
                "show-options",
                "show",
                "show-window-options",
                "showw",
                "show-environment",
                "showenv",
                "display-message",
                "display",
                "info",
                "has-session",
                "has",
            ],
            delegating: &[
                "new-session",
                "new",
                "new-window",
                "neww",
                "send-keys",
                "send",
                "split-window",
                "splitw",
                "run-shell",
                "run",
                "attach-session",
                "attach",
                "at",
                "respawn-pane",
                "respawnp",
                "respawn-window",
                "respawnw",
                "if-shell",
                "command-prompt",
                "source-file",
                "source",
                "set-hook",
                "pipe-pane",
                "pipep",
            ],
            // `tmux -c <cmd>` runs a shell command with no subcommand.
            delegating_flags: &["-c"],
            value_flags: &["-f", "-L", "-S"],
            // Bare `tmux` starts (and attaches) a new session — that is an action.
            options_only_is_read_only: false,
        }),
        _ => None,
    }
}

/// The subcommand of an invocation: the first positional token, skipping argv[0]
/// (the binary name — `args` is the full `/proc/cmdline`) and any leading global
/// options (plus the value of a space-form `value_flag`). `None` when the argv
/// carries no subcommand (options only, or empty).
fn subcommand<'a>(args: &'a [String], value_flags: &[&str]) -> Option<&'a str> {
    let mut iter = args.iter();
    iter.next(); // argv[0] is the binary itself, never the subcommand
    while let Some(tok) = iter.next() {
        if tok == "--" {
            return iter.next().map(String::as_str);
        }
        if tok.starts_with('-') {
            // A space-form value option (`-n foo`, `--namespace foo`) consumes
            // its following token; `--opt=val`, bundled, and boolean options
            // carry (or lack) their value in-token, so skip only the token.
            if value_flags.contains(&tok.as_str()) {
                iter.next();
            }
            continue;
        }
        return Some(tok.as_str());
    }
    None
}

/// True when a spawn of delegating binary `bin` (basename) with `args` (the full
/// argv incl. argv[0]) is a read-only query that delegates nothing, and is thus
/// exempt from escalation. Fail-safe: see the section comment.
pub(super) fn invocation_is_read_only(bin: &str, args: &[String]) -> bool {
    let Some(policy) = subcommand_policy(bin) else {
        return false;
    };
    // A delegating verb or delegating global option ANYWHERE forces escalation,
    // even if a read-only verb is also present (a container named `ps`, etc.).
    let has_delegating_token = args.iter().any(|tok| {
        let head = tok.split('=').next().unwrap_or(tok.as_str());
        policy.delegating.contains(&tok.as_str())
            || policy.delegating_flags.contains(&tok.as_str())
            || policy.delegating_flags.contains(&head)
    });
    if has_delegating_token {
        return false;
    }
    match subcommand(args, policy.value_flags) {
        None => policy.options_only_is_read_only,
        Some(sub) => policy.read_only.contains(&sub),
    }
}

/// Whether an authority-delegating spawn of `command` should be escalated
/// under this profile: it is authority-delegating AND not explicitly
/// permitted. (Caller has already checked the enforce flag.)
///
/// Raw-basename overload (no canonical/hash provenance) used by the
/// forensic-tagging site and tests.
pub(super) fn spawn_should_escalate(command: &str, args: &[String], permit: &[String]) -> bool {
    spawn_should_escalate_full(command, args, None, None, permit, &HashSet::new())
}

/// Full escalation predicate: the spawn is authority-delegating by ANY of
/// (1) raw argv[0] basename, (2) canonical (symlink-resolved) basename —
/// defeats `run0`→`systemd-run`, (3) content SHA-256 present in the session-
/// start pinned set — defeats copy/hardlink under a novel name — AND it is not
/// permitted (basename or canonical basename). Caller checked the enforce flag.
pub(super) fn spawn_should_escalate_full(
    command: &str,
    args: &[String],
    canonical_path: Option<&str>,
    sha256: Option<&str>,
    permit: &[String],
    pinned_hashes: &HashSet<String>,
) -> bool {
    if let Some(matched) = matched_delegating_name(command, canonical_path) {
        // Read-only queries (`flatpak list`, `docker ps`, …) delegate nothing —
        // exempt before the permit check so a bare query never escalates.
        if invocation_is_read_only(matched, args) {
            return false;
        }
        // Delegating by raw or canonical basename — an operator can permit it
        // by name (basename or canonical basename).
        return !spawn_permitted_full(command, canonical_path, permit);
    }
    // Delegating ONLY by content hash = a byte-identical copy/hardlink of a
    // delegating binary wearing a disguised name. Deliberately NOT
    // basename-permittable, so a permit entry for whatever name it wears cannot
    // suppress it. (A content mutation changes the hash and evades — a known
    // residual documented in the module header.)
    sha256.is_some_and(|h| pinned_hashes.contains(h))
}

/// Whether the spawn *targets* an authority-delegating binary, by raw or
/// canonical basename or by pinned content hash — the same identity test as
/// [`spawn_should_escalate_full`] but WITHOUT the permit check.
///
/// Used to decide `kill_on_deny`: the `permit_authority_delegating` list is an
/// opt-out of the delegation *escalation signal* (don't add a QUEUE just for
/// being delegating), NOT a grant of immunity from other filters' verdicts. If
/// a permitted delegating binary is nonetheless DENIED on independent grounds
/// (a secret in argv, a taint data-flow, a reviewer deny), that deny must still
/// be enforced — and for a spawn at `PTRACE_EVENT_EXEC` the only effective
/// enforcement is SIGKILL, since `deny_syscall` is a no-op there and the binary
/// would otherwise hand its work to an untraced peer. (Caller checks the
/// enforce flag.)
pub(super) fn spawn_targets_delegating_binary(
    command: &str,
    args: &[String],
    canonical_path: Option<&str>,
    sha256: Option<&str>,
    pinned_hashes: &HashSet<String>,
) -> bool {
    // A read-only query is not a delegating action even for kill-on-deny: it
    // hands nothing to a peer, so a deny of it needs no SIGKILL. Hash-only
    // (disguised-copy) matches skip the exemption — the basename is unknown to
    // the policy table anyway, so `matched_delegating_name` returns None.
    if let Some(matched) = matched_delegating_name(command, canonical_path) {
        return !invocation_is_read_only(matched, args);
    }
    sha256.is_some_and(|h| pinned_hashes.contains(h))
}

/// Whether a control-injection socket connect to `address` should be escalated
/// under this profile. (Caller has already checked the enforce flag.)
pub(super) fn control_socket_should_escalate(address: &str, permit: &[String]) -> bool {
    is_control_injection_socket(address) && !control_socket_permitted(address, permit)
}

/// Raw-basename escalation convenience (no canonical/hash inputs). Production
/// code calls [`maybe_escalate_spawn_full`] with the spawn's provenance; this
/// wrapper is retained only for the unit tests that predate the provenance
/// generalisation.
#[cfg(test)]
pub(super) fn maybe_escalate_spawn(
    decision: &mut ProxyDecision,
    command: &str,
    args: &[String],
    permit: &[String],
) -> bool {
    maybe_escalate_spawn_full(decision, command, args, None, None, permit, &HashSet::new())
}

/// Provenance-aware escalation: like [`maybe_escalate_spawn`] but also fires on
/// a canonical-basename or content-hash match. The escalation site passes
/// `ctx.spawn_provenance.canonical_path` / `.sha256` (already computed by PR 4 —
/// zero extra cost) plus the session-start pinned hash set.
pub(super) fn maybe_escalate_spawn_full(
    decision: &mut ProxyDecision,
    command: &str,
    args: &[String],
    canonical_path: Option<&str>,
    sha256: Option<&str>,
    permit: &[String],
    pinned_hashes: &HashSet<String>,
) -> bool {
    if !spawn_should_escalate_full(command, args, canonical_path, sha256, permit, pinned_hashes) {
        return false;
    }
    if !matches!(decision.action, ProxyAction::Allow) {
        return false;
    }
    decision.action = ProxyAction::Queue {
        priority: QueuePriority::High,
    };
    // Prefer the canonical basename so a disguised copy/symlink is named by what
    // it really is in the operator prompt.
    let display = canonical_path.map_or_else(|| basename(command), basename);
    decision.decision_reason = format!(
        "authority-delegating spawn queued for review: `{display}` runs its effect in a privileged \
         or unsupervised peer, outside supervision"
    );
    true
}

// ---------------------------------------------------------------------------
// ssh/scp/sftp-to-loopback supervision escape
// ---------------------------------------------------------------------------
//
// `ssh localhost <cmd>` (and scp/sftp to a loopback host) runs its real work
// inside the *local* sshd, which is not a ptrace descendant of the supervised
// tool, so the command's file/network/process syscalls are never intercepted
// or scored -- the authority-delegating escape class. REMOTE ssh is
// intentionally NOT handled here: its off-host connection is already scored by
// the egress filter (`grith_proxy::filters::outbound_binaries` carries curated
// ssh/scp/sftp rules). Blanket-listing ssh would double-score legitimate remote
// use and is high-FP. We fire ONLY when the argv destination host is *provably*
// loopback; an ambiguous or unparseable argv never escalates.

/// Value-taking single-letter options per ssh-family tool. Skipping the next
/// token for these prevents mis-reading an option value (`-b 127.0.0.1` bind
/// address, `-J localhost` jump host -- neither makes the *destination* local)
/// as the destination host. Per-tool because `-p` is a value (port) for ssh but
/// a boolean (preserve) for scp, and `-P` is the value form for scp/sftp.
/// Over-inclusion only risks a missed detection, never a false escalation.
fn ssh_value_flags(tool: &str) -> &'static [u8] {
    match tool {
        "ssh" => b"BbcDEeFIiJLlmOopQRSWw",
        "scp" => b"cDFiJloPS",
        "sftp" => b"BbcDFiJloPRSsX",
        _ => b"",
    }
}

/// True when `host` is a loopback destination: literal `localhost`, anything in
/// `127.0.0.0/8`, `::1`, or an IPv4-mapped loopback.
fn host_is_loopback(host: &str) -> bool {
    let h = host.trim();
    if h.is_empty() {
        return false;
    }
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            return true;
        }
        if let std::net::IpAddr::V6(v6) = ip {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback();
            }
        }
    }
    false
}

/// Strip a leading `user@` (up to and including the LAST `@`).
fn strip_user(token: &str) -> &str {
    match token.rfind('@') {
        Some(i) => &token[i + 1..],
        None => token,
    }
}

/// Host from a remote-endpoint token `[user@]host[:path]` -- the shape scp/sftp
/// use for a *remote* file spec. Returns `None` for a bare local path (no `:`,
/// or a `/` before the first `:` -- the standard scp local-vs-remote rule).
/// Bracketed IPv6 (`[::1]:path`) and bare IP literals are recognised.
fn remote_spec_host(token: &str) -> Option<&str> {
    let rest = strip_user(token);
    if let Some(after_bracket) = rest.strip_prefix('[') {
        let host = after_bracket.split(']').next().unwrap_or("");
        return (!host.is_empty()).then_some(host);
    }
    if rest.parse::<std::net::IpAddr>().is_ok() {
        // Bare literal incl. unbracketed IPv6 `::1` (whose colons must not be
        // mistaken for a `host:path` separator).
        return Some(rest);
    }
    let colon = rest.find(':')?;
    if rest[..colon].contains('/') {
        return None; // local path such as `./a:b` or `/tmp/x:y`
    }
    Some(&rest[..colon])
}

/// True when an ssh/scp/sftp spawn's argv names a *loopback* destination host.
/// Conservative: parses only enough to positively identify a loopback host;
/// anything ambiguous returns false. `command` is the binary path, `args` is
/// argv[1..] (as the supervisor's ProcessSpawn carries it).
pub(super) fn ssh_family_loopback_destination(command: &str, args: &[String]) -> bool {
    let tool = basename(command);
    if !matches!(tool, "ssh" | "scp" | "sftp") {
        return false;
    }
    let value_flags = ssh_value_flags(tool);
    let mut options_ended = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        if !options_ended {
            if tok == "--" {
                options_ended = true;
                continue;
            }
            // `-X value` (exactly `-X`, value-taking) also consumes the next
            // token; `-Xvalue` / bundled `-4v` carry any value in-token. `-`
            // alone (len 1) is a positional (stdin) and falls through.
            if tok.len() >= 2 && tok.as_bytes()[0] == b'-' {
                if tok.len() == 2 && value_flags.contains(&tok.as_bytes()[1]) {
                    iter.next();
                }
                continue;
            }
        }
        if tool == "scp" {
            // scp: any positional may be a remote endpoint; scan all, but only
            // genuine remote-spec shapes (a bare local filename is never a host,
            // so `scp localhost remote:/x` does not fire on "localhost").
            if remote_spec_host(tok).is_some_and(host_is_loopback) {
                return true;
            }
            options_ended = true; // options precede file args in scp
            continue;
        }
        // ssh / sftp: destination is the FIRST positional. A remote-spec shape
        // wins (sftp `host:path`); otherwise the whole token (minus `user@`) is
        // the bare host. Remote-command tokens after the host are never scanned.
        let host = remote_spec_host(tok).unwrap_or_else(|| strip_user(tok));
        return host_is_loopback(host);
    }
    false
}

/// Whether an ssh-family loopback spawn should escalate under this profile: its
/// destination is loopback AND the profile has not permitted the binary (reuses
/// `permit_authority_delegating` -- an operator scripting `ssh localhost` adds
/// `"ssh"` there). Caller has checked the enforce flag.
pub(super) fn ssh_loopback_should_escalate(
    command: &str,
    args: &[String],
    permit: &[String],
) -> bool {
    ssh_family_loopback_destination(command, args) && !spawn_permitted(command, permit)
}

/// Escalate an `Allow` decision for an ssh/scp/sftp-to-loopback spawn to
/// `Queue { High }`. Returns `true` if it escalated. Mirrors
/// [`maybe_escalate_spawn`]: only touches `Allow` decisions.
pub(super) fn maybe_escalate_ssh_loopback_spawn(
    decision: &mut ProxyDecision,
    command: &str,
    args: &[String],
    permit: &[String],
) -> bool {
    if !ssh_loopback_should_escalate(command, args, permit) {
        return false;
    }
    if !matches!(decision.action, ProxyAction::Allow) {
        return false;
    }
    decision.action = ProxyAction::Queue {
        priority: QueuePriority::High,
    };
    decision.decision_reason = format!(
        "ssh-family spawn to a loopback host queued for review: `{}` runs its command via the \
         local sshd, outside supervision",
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
            // Abstract-namespace renders (classify now emits `unix:@<name>`):
            // the shapes libX11 / libdbus try FIRST.
            "unix:@/tmp/.X11-unix/X0",
            "unix:@/tmp/dbus-AbCdEf",
            "unix:@/run/user/1000/bus", // abstract session bus (via @-strip)
        ] {
            assert!(is_control_injection_socket(addr), "{addr:?} should match");
        }
        for addr in [
            "unix:/var/run/nscd/socket",
            "unix:/run/user/1000/gnupg/S.gpg-agent", // agent socket: handled elsewhere
            "unix:/tmp/app/screenshots/x.sock",      // must not match on "/screen"
            "unix:/run/foo/screen-share.sock",       // must not match on "/screen"
            "unix:@nvidia-uvm",                      // benign abstract name
            "unix:@/tmp/app/screenshots/x.sock",     // abstract, must not match "/screen"
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
            // Added: run0 (systemd-run analog) + qdbus family.
            "run0",
            "/usr/bin/qdbus",
            "qdbus-qt5",
            "qdbus-qt6",
            "qdbus6",
        ] {
            assert!(is_authority_delegating_binary(cmd), "{cmd:?} should match");
        }
        for cmd in [
            "/bin/ls",
            "cat",
            "/usr/bin/git",
            "node",
            "qdbusx",           // near-miss must not match qdbus
            "rundir",           // near-miss must not match run0
            "dbus-launch",      // starts a private bus, runs child in-tree
            "dbus-run-session", // ditto — NOT a delegator
        ] {
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
        assert!(maybe_escalate_spawn(
            &mut d,
            "/usr/bin/systemd-run",
            &[],
            &[]
        ));
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
            &[],
            &permit
        ));
        assert!(matches!(d.action, ProxyAction::Allow));
    }

    #[test]
    fn spawn_does_not_escalate_ordinary_binary() {
        let mut d = allow_decision();
        assert!(!maybe_escalate_spawn(&mut d, "/usr/bin/git", &[], &[]));
        assert!(matches!(d.action, ProxyAction::Allow));
    }

    #[test]
    fn spawn_never_downgrades_a_non_allow_decision() {
        // A deny must survive even for an authority-delegating binary.
        let mut d = allow_decision();
        d.action = ProxyAction::Deny {
            reason: "already denied".into(),
        };
        assert!(!maybe_escalate_spawn(&mut d, "systemd-run", &[], &[]));
        assert!(matches!(d.action, ProxyAction::Deny { .. }));
    }

    // ---- read-only subcommand exemption ----

    /// Build an argv (incl. argv[0]) the way the supervisor carries it.
    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn flatpak_read_only_subcommands_are_exempt() {
        // The reported case: `flatpak --installations` (options only, no
        // subcommand) plus the common query verbs.
        for a in [
            argv(&["flatpak", "--installations"]),
            argv(&["flatpak", "--version"]),
            argv(&["flatpak", "list"]),
            argv(&["flatpak", "info", "org.foo.Bar"]),
            argv(&["flatpak", "--user", "list"]),
            argv(&["flatpak", "ps"]),
            argv(&["flatpak", "remotes"]),
        ] {
            assert!(
                invocation_is_read_only("flatpak", &a),
                "should be read-only: {a:?}"
            );
        }
    }

    #[test]
    fn flatpak_delegating_subcommands_still_escalate() {
        for a in [
            argv(&["flatpak", "run", "org.foo.Bar"]),
            argv(&["flatpak", "install", "flathub", "org.foo.Bar"]),
            argv(&["flatpak", "enter", "12345", "bash"]),
            argv(&["flatpak", "uninstall", "org.foo.Bar"]),
            argv(&["flatpak", "--user", "run", "org.foo.Bar"]),
            // Unknown subcommand → fail-safe escalate.
            argv(&["flatpak", "some-new-verb"]),
        ] {
            assert!(
                !invocation_is_read_only("flatpak", &a),
                "should escalate: {a:?}"
            );
        }
    }

    #[test]
    fn docker_read_only_vs_delegating() {
        for a in [
            argv(&["docker", "ps"]),
            argv(&["docker", "images"]),
            argv(&["docker", "inspect", "abc"]),
            argv(&["docker", "-H", "unix:///run/d.sock", "ps"]),
            argv(&["docker", "version"]),
        ] {
            assert!(invocation_is_read_only("docker", &a), "read-only: {a:?}");
        }
        for a in [
            argv(&["docker", "run", "-it", "alpine", "sh"]),
            argv(&["docker", "exec", "c1", "sh"]),
            argv(&["docker", "build", "."]),
            // A container literally named `ps` must not exempt a `run`.
            argv(&["docker", "run", "--name", "ps", "alpine"]),
            // Group subcommands nest mutating actions → escalate the group.
            argv(&["docker", "image", "rm", "abc"]),
        ] {
            assert!(!invocation_is_read_only("docker", &a), "escalate: {a:?}");
        }
    }

    #[test]
    fn kubectl_value_flag_before_subcommand_is_parsed() {
        // `-n ns` must not be mistaken for the subcommand.
        assert!(invocation_is_read_only(
            "kubectl",
            &argv(&["kubectl", "-n", "kube-system", "get", "pods"])
        ));
        assert!(invocation_is_read_only(
            "kubectl",
            &argv(&["kubectl", "--namespace=default", "describe", "pod", "p"])
        ));
        assert!(!invocation_is_read_only(
            "kubectl",
            &argv(&["kubectl", "-n", "kube-system", "exec", "p", "--", "sh"])
        ));
        assert!(!invocation_is_read_only(
            "kubectl",
            &argv(&["kubectl", "apply", "-f", "x.yaml"])
        ));
    }

    #[test]
    fn systemctl_read_only_vs_delegating() {
        assert!(invocation_is_read_only(
            "systemctl",
            &argv(&["systemctl", "status", "nginx"])
        ));
        assert!(invocation_is_read_only(
            "systemctl",
            &argv(&["systemctl", "is-active", "nginx"])
        ));
        assert!(!invocation_is_read_only(
            "systemctl",
            &argv(&["systemctl", "restart", "nginx"])
        ));
        assert!(!invocation_is_read_only(
            "systemctl",
            &argv(&["systemctl", "--user", "start", "foo"])
        ));
    }

    #[test]
    fn tmux_queries_exempt_but_actions_and_bare_and_dash_c_escalate() {
        assert!(invocation_is_read_only(
            "tmux",
            &argv(&["tmux", "list-sessions"])
        ));
        assert!(invocation_is_read_only("tmux", &argv(&["tmux", "ls"])));
        assert!(invocation_is_read_only(
            "tmux",
            &argv(&["tmux", "-L", "mysock", "has-session", "-t", "x"])
        ));
        // Bare `tmux` starts (and attaches) a session — an action.
        assert!(!invocation_is_read_only("tmux", &argv(&["tmux"])));
        // `tmux -c <cmd>` runs a shell command with no subcommand.
        assert!(!invocation_is_read_only(
            "tmux",
            &argv(&["tmux", "-c", "rm -rf /tmp/x"])
        ));
        assert!(!invocation_is_read_only(
            "tmux",
            &argv(&["tmux", "new-session", "-d"])
        ));
    }

    #[test]
    fn binary_without_a_policy_table_is_never_read_only() {
        // systemd-run/at/dbus-send always delegate — no read-only mode.
        assert!(!invocation_is_read_only(
            "systemd-run",
            &argv(&["systemd-run", "--version"])
        ));
        assert!(!invocation_is_read_only("at", &argv(&["at", "-l"])));
        // A non-delegating binary is irrelevant here (no table).
        assert!(!invocation_is_read_only("git", &argv(&["git", "status"])));
    }

    #[test]
    fn read_only_invocation_does_not_escalate_but_delegating_does() {
        // End-to-end through the escalation predicate: `flatpak --installations`
        // (the reported false positive) must NOT escalate; `flatpak run` must.
        assert!(!spawn_should_escalate(
            "/usr/bin/flatpak",
            &argv(&["flatpak", "--installations"]),
            &[],
        ));
        assert!(spawn_should_escalate(
            "/usr/bin/flatpak",
            &argv(&["flatpak", "run", "org.foo.Bar"]),
            &[],
        ));
    }

    #[test]
    fn read_only_exemption_ignores_disguised_copies() {
        // A hash-matched disguised copy (`/tmp/x` whose bytes are flatpak's) has
        // no policy table for basename "x", so the read-only exemption never
        // applies — the hash match still escalates even with read-only-looking
        // args.
        let pinned: HashSet<String> = ["cafef00d".to_string()].into_iter().collect();
        assert!(spawn_should_escalate_full(
            "/tmp/x",
            &argv(&["x", "list"]),
            Some("/tmp/x"),
            Some("cafef00d"),
            &[],
            &pinned,
        ));
    }

    // ---- fix #1: canonical-basename + content-hash bypass hardening ----

    /// A copy/symlink under a novel name whose CANONICAL basename is a
    /// delegating binary escalates (defeats run0 / `ln -s systemd-run x`).
    #[test]
    fn spawn_escalates_on_canonical_basename() {
        assert!(spawn_should_escalate_full(
            "/tmp/x",
            &[],
            Some("/usr/bin/systemd-run"),
            None,
            &[],
            &HashSet::new(),
        ));
    }

    /// A byte-copy under a novel name (raw + canonical basenames both benign)
    /// escalates on a session-pinned content-hash match.
    #[test]
    fn spawn_escalates_on_pinned_hash() {
        let pinned: HashSet<String> = ["deadbeef".to_string()].into_iter().collect();
        assert!(spawn_should_escalate_full(
            "/routineroot/notes",
            &[],
            Some("/routineroot/notes"),
            Some("deadbeef"),
            &[],
            &pinned,
        ));
    }

    /// A basename permit suppresses a canonical match (permit `systemd-run`
    /// also covers its `run0` symlink)...
    #[test]
    fn permit_suppresses_canonical_but_not_hash() {
        let permit = vec!["systemd-run".to_string()];
        assert!(!spawn_should_escalate_full(
            "/usr/bin/run0",
            &[],
            Some("/usr/bin/systemd-run"),
            None,
            &permit,
            &HashSet::new(),
        ));
        // ...but a hash-only match (disguised copy) is NOT basename-permittable:
        // permitting "git" cannot excuse a copy whose bytes are systemd-run's.
        let permit = vec!["git".to_string()];
        let pinned: HashSet<String> = ["abc".to_string()].into_iter().collect();
        assert!(spawn_should_escalate_full(
            "/tmp/git",
            &[],
            Some("/tmp/git"),
            Some("abc"),
            &permit,
            &pinned,
        ));
    }

    /// build_pinned_from_path hashes a fake delegating binary placed on a temp
    /// path, and a differently-named byte-copy hashes into the same set.
    #[test]
    fn pinned_metadata_hashes_path_binaries_and_copies() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("systemd-run");
        let mut f = std::fs::File::create(&bin).unwrap();
        f.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        drop(f);

        let (hashes, sizes) = build_pinned_from_path(dir.path().as_os_str());

        let sha = crate::provenance::sha256_file(&bin).unwrap();
        assert!(
            hashes.contains(&sha),
            "pinned set must contain the binary hash"
        );
        assert!(sizes.contains(&std::fs::metadata(&bin).unwrap().len()));
        // A byte-identical copy under a novel name hashes into the same set.
        let copy = dir.path().join("totally-innocent");
        std::fs::copy(&bin, &copy).unwrap();
        assert_eq!(crate::provenance::sha256_file(&copy).unwrap(), sha);
    }

    /// MULTICALL GUARD (busybox/Alpine): a delegating NAME that is a symlink to
    /// a file whose own basename is non-delegating (`crontab` → `busybox`) must
    /// NOT be pinned — otherwise every applet (ls/cat/sh, byte-identical to
    /// busybox) would hash-match and QUEUE-storm the tool.
    #[test]
    fn pinned_metadata_skips_multicall_dispatcher() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // The multicall binary (its own basename `busybox` is non-delegating).
        let busybox = dir.path().join("busybox");
        let mut f = std::fs::File::create(&busybox).unwrap();
        f.write_all(b"#!/bin/sh\napplet\n").unwrap();
        std::fs::set_permissions(&busybox, std::fs::Permissions::from_mode(0o755)).unwrap();
        drop(f);
        // A delegating NAME symlinked to it (Alpine ships crontab this way).
        std::os::unix::fs::symlink(&busybox, dir.path().join("crontab")).unwrap();

        let (hashes, _sizes) = build_pinned_from_path(dir.path().as_os_str());
        let busybox_sha = crate::provenance::sha256_file(&busybox).unwrap();
        assert!(
            !hashes.contains(&busybox_sha),
            "busybox hash must NOT be pinned (would collide with every applet)"
        );
    }

    // ---- fix #4: ssh/scp/sftp-to-loopback ----

    #[test]
    fn host_is_loopback_classifies() {
        for h in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.5.6.7",
            "::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(host_is_loopback(h), "{h:?} should be loopback");
        }
        for h in [
            "example.com",
            "10.0.0.1",
            "0.0.0.0",
            "::",
            "192.168.1.1",
            "",
        ] {
            assert!(!host_is_loopback(h), "{h:?} should NOT be loopback");
        }
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn ssh_loopback_destination_fires_only_on_loopback() {
        // Fires: first positional is a loopback host.
        for a in [
            vec!["localhost"],
            vec!["user@localhost"],
            vec!["127.0.0.1"],
            vec!["127.0.0.5"],
            vec!["::1"],
            vec!["[::1]"],
            vec!["-p", "2222", "localhost"],
            vec!["--", "localhost"],
        ] {
            assert!(
                ssh_family_loopback_destination("/usr/bin/ssh", &args(&a)),
                "{a:?} should fire"
            );
        }
        // Does NOT fire: remote host, option values, remote command 'localhost'.
        for a in [
            vec!["example.com"],
            vec!["user@10.0.0.5"],
            vec!["example.com", "ssh", "localhost"], // only first positional scanned
            vec!["-b", "127.0.0.1", "example.com"],  // bind addr skipped
            vec!["-J", "localhost", "example.com"],  // jump host skipped
            vec!["-L", "8080:localhost:80", "example.com"],
        ] {
            assert!(
                !ssh_family_loopback_destination("/usr/bin/ssh", &args(&a)),
                "{a:?} should NOT fire"
            );
        }
    }

    #[test]
    fn scp_and_sftp_loopback_shapes() {
        assert!(ssh_family_loopback_destination(
            "scp",
            &args(&["f", "localhost:/tmp"])
        ));
        assert!(ssh_family_loopback_destination(
            "scp",
            &args(&["f", "user@127.0.0.1:/x"])
        ));
        // scp -p is boolean (preserve), must not consume the destination.
        assert!(ssh_family_loopback_destination(
            "scp",
            &args(&["-p", "f", "localhost:/x"])
        ));
        // scp -P is a value (port), skips the next token.
        assert!(!ssh_family_loopback_destination(
            "scp",
            &args(&["-P", "2222", "f", "example.com:/x"])
        ));
        // A bare local file literally named 'localhost' is not a host.
        assert!(!ssh_family_loopback_destination(
            "scp",
            &args(&["localhost", "remote:/x"])
        ));
        assert!(ssh_family_loopback_destination(
            "sftp",
            &args(&["localhost"])
        ));
        assert!(ssh_family_loopback_destination(
            "sftp",
            &args(&["localhost:/dir"])
        ));
        assert!(!ssh_family_loopback_destination(
            "sftp",
            &args(&["example.com"])
        ));
        // Non-ssh-family binaries are not handled here (curl → egress filter).
        assert!(!ssh_family_loopback_destination(
            "/usr/bin/curl",
            &args(&["localhost"])
        ));
    }

    #[test]
    fn ssh_loopback_escalation_and_permit() {
        let mut d = allow_decision();
        assert!(maybe_escalate_ssh_loopback_spawn(
            &mut d,
            "/usr/bin/ssh",
            &args(&["localhost"]),
            &[],
        ));
        assert!(matches!(d.action, ProxyAction::Queue { .. }));

        // permit "ssh" suppresses.
        let mut d = allow_decision();
        let permit = vec!["ssh".to_string()];
        assert!(!maybe_escalate_ssh_loopback_spawn(
            &mut d,
            "/usr/bin/ssh",
            &args(&["localhost"]),
            &permit,
        ));
        assert!(matches!(d.action, ProxyAction::Allow));

        // remote ssh does not escalate; a non-ssh binary does not either.
        let mut d = allow_decision();
        assert!(!maybe_escalate_ssh_loopback_spawn(
            &mut d,
            "/usr/bin/ssh",
            &args(&["example.com"]),
            &[],
        ));
        assert!(!maybe_escalate_ssh_loopback_spawn(
            &mut d,
            "/usr/bin/git",
            &args(&["localhost"]),
            &[],
        ));
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
