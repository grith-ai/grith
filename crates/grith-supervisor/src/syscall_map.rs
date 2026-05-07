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
        // Filtered out: fd-only reads/writes without path, ProcessFork,
        // regular NetSendTo (connected datagrams), PipeCreate, SocketPair
        _ => None,
    }
}

/// Check if a path should be filtered as noise (internal temp files, etc.).
///
/// These are paths that are accessed frequently by runtime internals but are
/// not meaningful from a security perspective.
pub fn is_noise_path(path: &str) -> bool {
    path.starts_with("/proc/")
        || path.starts_with("/sys/")
        || path.starts_with("/dev/null")
        || path.starts_with("/dev/urandom")
        || path.starts_with("/dev/random")
        || path.starts_with("/dev/pts/")
        || path.starts_with("/dev/tty")
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
    if ["secret", "credential", "token", "apikey"]
        .iter()
        .any(|kw| file_name.contains(kw))
    {
        return true;
    }

    false
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
}
