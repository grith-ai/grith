// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Identify the local process that owns the daemon port's listening socket.
//!
//! `probe_port` decides "this is a Grith daemon" from the `/api/health`
//! payload alone. That is a statement about whatever answers the port, not
//! about *where it runs*: a forwarded loopback port answers exactly like a
//! local daemon. VS Code Remote auto-forwards a remote workspace's ports to
//! the laptop's loopback; so do `ssh -L`, `kubectl port-forward`, a published
//! container port, and socat.
//!
//! When that happens the CLI meets a real Grith daemon of the right version
//! whose IPC token lives on the *other* machine, and every local remedy is
//! wrong: there is no PID file to identify, the daemon cannot be restarted
//! from here, and `/api/server/shutdown` would (correctly) refuse the token we
//! hold. Worse, a restart that did succeed would kill someone's remote daemon.
//!
//! So before offering a local remedy we ask the kernel who actually owns the
//! socket. A tunnel is owned by the tunnelling process (`code`, `ssh`, …); our
//! own daemon is owned by a `grith` binary. Anything we cannot resolve stays
//! [`ListenerLocality::Unknown`] and callers fall back to their previous
//! behaviour — this module only ever adds precision, never removes a remedy.

use std::path::PathBuf;

/// A local process holding the listening socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerOwner {
    /// PID of the owning process, when a `/proc/<pid>/fd` entry named the
    /// socket. `None` when the socket's inode belongs to another user's
    /// process (whose `fd` directory we cannot read).
    pub pid: Option<u32>,
    /// Owning uid, straight from `/proc/net/tcp`.
    pub uid: u32,
    /// Resolved `/proc/<pid>/exe`, when readable.
    pub exe: Option<PathBuf>,
    /// `/proc/<pid>/comm` — present far more often than `exe`, since it needs
    /// no ptrace-level access.
    pub comm: Option<String>,
}

impl ListenerOwner {
    /// Operator-facing name: `code (pid 2433878)`, `pid 4321`, or `uid 1000`.
    #[must_use]
    pub fn describe(&self) -> String {
        let name = self
            .comm
            .clone()
            .or_else(|| {
                self.exe
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
            })
            .filter(|n| !n.is_empty());
        match (name, self.pid) {
            (Some(name), Some(pid)) => format!("`{name}` (pid {pid})"),
            (Some(name), None) => format!("`{name}`"),
            (None, Some(pid)) => format!("pid {pid}"),
            (None, None) => format!("a process running as uid {}", self.uid),
        }
    }

    /// Whether this process is a `grith` binary.
    ///
    /// Deliberately conservative: only an exe path or comm we can actually
    /// read counts. An unreadable owner is not "not grith" — it is unknown,
    /// and [`listener_locality`] reports it as such.
    fn looks_like_grith(&self) -> Option<bool> {
        if let Some(exe) = self.exe.as_ref() {
            let stem = exe
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .map(|n| strip_deleted_suffix(&n).to_string());
            // The running binary may be a versioned or suffixed copy
            // (`grith-0.3.3`, `grith.tmp` mid-upgrade), and cargo test builds
            // run as `grith-<hash>`. Prefix-match rather than demand equality.
            return Some(stem.is_some_and(|s| s == "grith" || s.starts_with("grith-")));
        }
        // `comm` is truncated to 15 bytes by the kernel, which "grith" never
        // reaches, so an exact match is safe here.
        self.comm.as_ref().map(|c| c == "grith")
    }
}

/// Strip the kernel's marker for a binary that has been unlinked.
///
/// `/proc/<pid>/exe` for a process whose executable was replaced reads back as
/// `<path> (deleted)`. That is the *normal* state of a long-lived daemon after
/// an upgrade or a developer rebuild-and-install — precisely the daemon this
/// module exists to recognise — so the marker comes off before the name is
/// matched. Left on, the daemon's own `grith (deleted)` fails the name test
/// and the port it owns is reported as forwarded from another machine, with a
/// remedy (stop the port forward) that has nothing to stop.
fn strip_deleted_suffix(name: &str) -> &str {
    name.strip_suffix(" (deleted)").unwrap_or(name)
}

/// What owns the listening socket on a port that answered as a Grith daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerLocality {
    /// A local `grith` process — our daemon, and every local remedy applies.
    LocalGrith(ListenerOwner),
    /// A local process that is not grith. Since the port answers as a Grith
    /// daemon, that process is relaying to a daemon somewhere else.
    Forwarded(ListenerOwner),
    /// Not resolvable: no `/proc` (non-Linux), an unreadable owner, or a
    /// socket that vanished between the probe and the lookup. Callers must
    /// keep their pre-existing behaviour.
    Unknown,
}

/// Classify the owner of the loopback listening socket on `port`.
#[must_use]
pub fn listener_locality(port: u16) -> ListenerLocality {
    let Some(owner) = listener_owner(port) else {
        return ListenerLocality::Unknown;
    };
    match owner.looks_like_grith() {
        Some(true) => ListenerLocality::LocalGrith(owner),
        Some(false) => ListenerLocality::Forwarded(owner),
        None => ListenerLocality::Unknown,
    }
}

/// Resolve the process holding the loopback listening socket on `port`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn listener_owner(port: u16) -> Option<ListenerOwner> {
    let (inode, uid) = listening_socket(port)?;
    let pid = pid_owning_inode(inode);
    Some(ListenerOwner {
        pid,
        uid,
        exe: pid.and_then(|p| std::fs::read_link(format!("/proc/{p}/exe")).ok()),
        comm: pid.and_then(|p| {
            std::fs::read_to_string(format!("/proc/{p}/comm"))
                .ok()
                .map(|c| c.trim().to_string())
        }),
    })
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn listener_owner(_port: u16) -> Option<ListenerOwner> {
    // No `/proc`. Callers treat this as `Unknown` and keep their previous
    // behaviour rather than guessing at ownership.
    None
}

/// Find the `(inode, uid)` of a loopback/wildcard socket LISTENing on `port`.
#[cfg(target_os = "linux")]
fn listening_socket(port: u16) -> Option<(u64, u32)> {
    for (path, ipv6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Some(found) = parse_listening_socket(&content, port, ipv6) {
            return Some(found);
        }
    }
    None
}

/// Pure parser for a `/proc/net/tcp{,6}` table (split out so the column
/// layout is testable without a live socket).
///
/// Columns: `sl local_address rem_address st tx:rx tr:tm->when retrnsmt uid
/// timeout inode`. We accept loopback and wildcard binds — both serve a
/// `127.0.0.1` connect.
#[cfg(target_os = "linux")]
fn parse_listening_socket(table: &str, port: u16, ipv6: bool) -> Option<(u64, u32)> {
    const LISTEN: &str = "0A";
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 || fields[3] != LISTEN {
            continue;
        }
        // A line we cannot parse is skipped, never fatal: aborting the scan
        // on one odd row would hide every listener below it.
        let Some((addr_hex, port_hex)) = fields[1].rsplit_once(':') else {
            continue;
        };
        if u16::from_str_radix(port_hex, 16) != Ok(port) {
            continue;
        }
        let local = if ipv6 {
            // ::1 and :: — the same two forms the supervisor's listener scan
            // accepts, in the kernel's word-swapped hex.
            addr_hex == "00000000000000000000000000000000"
                || addr_hex == "00000000000000000000000001000000"
        } else {
            // 127.x.x.x little-endian ends in `7F`; `00000000` is 0.0.0.0.
            addr_hex.ends_with("7F") || addr_hex == "00000000"
        };
        if !local {
            continue;
        }
        let (Ok(uid), Ok(inode)) = (fields[7].parse(), fields[9].parse()) else {
            continue;
        };
        return Some((inode, uid));
    }
    None
}

/// Scan `/proc/*/fd` for the process holding `inode`.
///
/// Only processes whose `fd` directory we may read are visible — in practice
/// our own uid's, which covers both the tunnelling client and our daemon.
#[cfg(target_os = "linux")]
fn pid_owning_inode(inode: u64) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue; // another user's process, or it exited mid-scan
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|l| l.to_string_lossy() == target) {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(exe: Option<&str>, comm: Option<&str>) -> ListenerOwner {
        ListenerOwner {
            pid: Some(4321),
            uid: 1000,
            exe: exe.map(PathBuf::from),
            comm: comm.map(str::to_string),
        }
    }

    #[test]
    fn our_own_daemon_is_recognised_by_exe_and_comm() {
        assert_eq!(
            owner(Some("/home/dan/.local/bin/grith"), Some("grith")).looks_like_grith(),
            Some(true)
        );
        assert_eq!(owner(None, Some("grith")).looks_like_grith(), Some(true));
        // A versioned or mid-upgrade copy is still our daemon.
        assert_eq!(
            owner(Some("/usr/local/bin/grith-0.3.3"), None).looks_like_grith(),
            Some(true)
        );
    }

    #[test]
    fn a_tunnelling_process_is_not_mistaken_for_the_daemon() {
        assert_eq!(
            owner(Some("/usr/share/code/code"), Some("code")).looks_like_grith(),
            Some(false)
        );
        assert_eq!(
            owner(Some("/usr/bin/ssh"), Some("ssh")).looks_like_grith(),
            Some(false)
        );
    }

    /// A daemon whose binary was replaced while it ran is still our daemon.
    ///
    /// The kernel appends ` (deleted)` to `/proc/<pid>/exe` after the
    /// executable is unlinked, which every upgrade and every developer
    /// rebuild-and-install does to a running daemon. Observed 2026-09-02: a
    /// daemon started at 15:49 had its binary reinstalled at 15:52, and the
    /// next `grith exec` whose fast-path connect happened to miss reported
    /// `port_forwarded` against `grith (pid 1798596)` — its own daemon.
    #[test]
    fn a_daemon_whose_binary_was_replaced_is_still_our_daemon() {
        assert_eq!(
            owner(Some("/home/dan/.local/bin/grith (deleted)"), Some("grith")).looks_like_grith(),
            Some(true)
        );
        assert_eq!(
            owner(Some("/usr/local/bin/grith-0.3.3 (deleted)"), None).looks_like_grith(),
            Some(true)
        );
        assert_eq!(
            listener_locality_of(ListenerOwner {
                pid: Some(1798596),
                uid: 1000,
                exe: Some(PathBuf::from("/home/dan/.local/bin/grith (deleted)")),
                comm: Some("grith".to_string()),
            }),
            ListenerLocality::LocalGrith(ListenerOwner {
                pid: Some(1798596),
                uid: 1000,
                exe: Some(PathBuf::from("/home/dan/.local/bin/grith (deleted)")),
                comm: Some("grith".to_string()),
            })
        );
    }

    /// Stripping the marker must not launder a tunnel into our daemon: a
    /// deleted `code` is still not grith.
    #[test]
    fn a_deleted_tunnel_binary_is_still_not_the_daemon() {
        assert_eq!(
            owner(Some("/usr/share/code/code (deleted)"), Some("code")).looks_like_grith(),
            Some(false)
        );
    }

    /// An owner we cannot read is *unknown*, never "foreign" — reporting a
    /// forwarded port on no evidence would send an operator chasing a tunnel
    /// that does not exist.
    #[test]
    fn an_unreadable_owner_is_unknown_not_foreign() {
        assert_eq!(owner(None, None).looks_like_grith(), None);
        assert_eq!(
            listener_locality_of(ListenerOwner {
                pid: None,
                uid: 0,
                exe: None,
                comm: None,
            }),
            ListenerLocality::Unknown
        );
    }

    /// Mirror of `listener_locality`'s match, for owners built by hand.
    fn listener_locality_of(owner: ListenerOwner) -> ListenerLocality {
        match owner.looks_like_grith() {
            Some(true) => ListenerLocality::LocalGrith(owner),
            Some(false) => ListenerLocality::Forwarded(owner),
            None => ListenerLocality::Unknown,
        }
    }

    #[test]
    fn describe_names_the_process_the_operator_will_see_in_ss() {
        assert_eq!(
            owner(Some("/usr/share/code/code"), Some("code")).describe(),
            "`code` (pid 4321)"
        );
        assert_eq!(
            ListenerOwner {
                pid: Some(4321),
                uid: 1000,
                exe: None,
                comm: None,
            }
            .describe(),
            "pid 4321"
        );
        assert_eq!(
            ListenerOwner {
                pid: None,
                uid: 1000,
                exe: None,
                comm: None,
            }
            .describe(),
            "a process running as uid 1000"
        );
    }

    #[cfg(target_os = "linux")]
    mod proc_table {
        use super::super::parse_listening_socket;

        const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

        #[test]
        fn finds_a_loopback_listener_and_reads_its_inode_and_uid() {
            // 127.0.0.1:3141 (0C45), LISTEN, uid 1000, inode 987654.
            let table = format!(
                "{HEADER}\n   0: 0100007F:0C45 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 987654 1 0000 100 0 0 10 0\n"
            );
            assert_eq!(
                parse_listening_socket(&table, 3141, false),
                Some((987654, 1000))
            );
        }

        #[test]
        fn ignores_established_connections_on_the_same_port() {
            // st = 01 (ESTABLISHED): a client socket, not the listener.
            let table = format!(
                "{HEADER}\n   0: 0100007F:0C45 0100007F:9999 01 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000 100 0 0 10 0\n"
            );
            assert_eq!(parse_listening_socket(&table, 3141, false), None);
        }

        #[test]
        fn ignores_a_listener_on_a_different_port() {
            let table = format!(
                "{HEADER}\n   0: 0100007F:0C46 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 222 1 0000 100 0 0 10 0\n"
            );
            assert_eq!(parse_listening_socket(&table, 3141, false), None);
        }

        #[test]
        fn accepts_a_wildcard_bind_which_also_serves_loopback() {
            let table = format!(
                "{HEADER}\n   0: 00000000:0C45 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 333 1 0000 100 0 0 10 0\n"
            );
            assert_eq!(
                parse_listening_socket(&table, 3141, false),
                Some((333, 1000))
            );
        }

        #[test]
        fn ipv6_loopback_listener_is_found() {
            let table = format!(
                "{HEADER}\n   0: 00000000000000000000000001000000:0C45 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 444 1 0000 100 0 0 10 0\n"
            );
            assert_eq!(
                parse_listening_socket(&table, 3141, true),
                Some((444, 1000))
            );
        }

        #[test]
        fn a_truncated_or_empty_table_yields_nothing_rather_than_panicking() {
            assert_eq!(parse_listening_socket("", 3141, false), None);
            assert_eq!(parse_listening_socket(HEADER, 3141, false), None);
            assert_eq!(
                parse_listening_socket(&format!("{HEADER}\n   0: 0100007F:0C45 0A\n"), 3141, false),
                None
            );
        }
    }

    /// End-to-end over the real `/proc` pipeline: bind a loopback listener in
    /// this process, then prove the lookup finds *this* process through the
    /// socket inode. Exercises the table parse, the inode scan and the exe
    /// resolution together — the parts a table-only test cannot cover.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolves_this_process_as_the_owner_of_its_own_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();

        let owner = listener_owner(port).expect("owner of a socket we hold");
        assert_eq!(owner.pid, Some(std::process::id()));
        assert_eq!(owner.uid, unsafe { libc::getuid() });

        // The test binary is `grith-<hash>`, so the daemon check must accept
        // it — the same prefix rule that keeps a versioned or mid-upgrade
        // `grith-0.3.3` from being mistaken for a foreign process.
        assert!(
            matches!(listener_locality(port), ListenerLocality::LocalGrith(_)),
            "a grith-owned listener must classify as local"
        );
    }

    /// A port with nothing on it has no owner — the lookup must say so rather
    /// than returning a stale or arbitrary process.
    #[test]
    fn a_vacant_port_has_no_owner() {
        // Port 1 is privileged and unbound in test environments.
        assert_eq!(listener_owner(1), None);
        assert_eq!(listener_locality(1), ListenerLocality::Unknown);
    }
}
