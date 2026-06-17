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
        // Raw-socket sendto (AF_PACKET / AF_NETLINK): the address was set by
        // classify.rs to "raw:af_packet" / "raw:af_netlink". Map through to
        // NetConnect so the egress filter can evaluate and deny it.
        SyscallKind::NetSendTo { address, port } if address.starts_with("raw:") => {
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
        // PR 6 Phase D: ArchPrivilegedOp is hard-denied in
        // event_handler before reaching here.
        SyscallKind::ArchPrivilegedOp { .. } => None,
        // PR 6 Phase B: category-2 syscalls map to dedicated
        // ToolCallType variants. operation_risk scores +5.0 baseline
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
        // the call reaches the proxy and `operation_risk` scores
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

/// Check if a path targets a security-sensitive location that should always
/// be evaluated by the proxy, even when `ignore_read_only` noise reduction
/// is enabled.
///
/// Mirrors the heuristics in `grith_proxy::filters::sensitive_path` but as a
/// lightweight boolean gate (no scoring, no severity).
pub fn is_sensitive_path(path: &str) -> bool {
    let path_lc = path.replace('\\', "/").to_lowercase();
    let file_name = path_lc.split('/').next_back().unwrap_or_default();

    // Grith's own configuration files — self-protection.
    // A supervised tool must never silently read or modify grith's
    // configuration, learned rules, reputation data, or credentials.
    if path_lc.contains("/.config/grith/") || path_lc.contains("/config/grith/") {
        return true;
    }

    // Credential-bearing directories
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
    if credential_dirs.iter().any(|d| path_lc.contains(d)) {
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

    // Another process's environment/memory under /proc is a cross-process
    // secret-theft vector and must reach the proxy despite the /proc fast-paths
    // and ignore_read_only (research doc §5.1 #1).
    if is_cross_process_secret_proc_path(path) {
        return true;
    }
    // Substring-keyword rule: a filename merely *containing* a
    // credential-ish word. This is the broadest, weakest signal and the
    // biggest false-positive source. Two carveouts keep it from mass-
    // misfiring on ordinary code:
    //
    //   * `node_modules/` (PR 69 Change 5) — library filenames like
    //     `tokenize.js` / `tokenTypes.js`.
    //   * Source-code files — a class/module file whose NAME contains
    //     "token"/"auth"/etc. (`AccessToken.php`, `RefreshToken.ts`,
    //     `OAuth2Client.java`, `Tokenizer.go`) is code, not a credential
    //     store. Real secrets live in `.env` / key files / credential dirs
    //     (handled above, regardless of this carveout) — not in a `.php`
    //     source file's *name*. Without this, an AI assistant reading a
    //     vendored OAuth/SDK library floods the operator with prompts.
    //
    // The strong rules above (.env, key/cert files, credential dirs, system
    // stores, /proc cross-process) are unaffected by both carveouts.
    if ["secret", "credential", "token", "apikey"]
        .iter()
        .any(|kw| file_name.contains(kw))
        && !path_contains_node_modules(&path_lc)
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

/// PR 69 Change 5: returns true if the symlink-resolved canonical path
/// contains `/node_modules/` as a path component. Falls back to the raw
/// path when canonicalisation fails — fail-safe because the carveout
/// only suppresses one boolean rule; everything else still fires.
fn path_contains_node_modules(path_lc: &str) -> bool {
    if let Ok(canonical) = std::fs::canonicalize(path_lc) {
        if let Some(s) = canonical.to_str() {
            return s
                .replace('\\', "/")
                .to_lowercase()
                .contains("/node_modules/");
        }
    }
    path_lc.contains("/node_modules/")
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn net_send_to_is_filtered() {
        let kind = SyscallKind::NetSendTo {
            address: "10.0.0.1".into(),
            port: 53,
        };
        assert_eq!(to_tool_call_type(&kind), None);
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
    fn net_send_to_raw_af_netlink_maps_to_net_connect() {
        let kind = SyscallKind::NetSendTo {
            address: "raw:af_netlink".into(),
            port: 0,
        };
        assert_eq!(
            to_tool_call_type(&kind),
            Some(ToolCallType::NetConnect {
                address: "raw:af_netlink".into(),
                port: 0,
            })
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
        //   - Linux: x86_64 only (ARM64 uses different syscall numbers/register layout)
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

    #[test]
    fn system_credential_files_are_sensitive() {
        assert!(is_sensitive_path("/etc/shadow"));
        // /etc/passwd is world-readable, not sensitive
        assert!(!is_sensitive_path("/etc/passwd"));
        assert!(is_sensitive_path("/etc/sudoers"));
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
}
