// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Syscall classification -- mapping raw x86_64 syscall numbers and register
//! state to [`SyscallKind`] variants.
//!
//! This module contains the `classify_syscall` method implementation and all
//! supporting helpers: `read_sockaddr`, `decode_open_flags`, path resolution,
//! and fd-to-path lookup.

#![cfg(target_os = "linux")]

use std::path::PathBuf;

use nix::libc;
use nix::sys::ptrace;
use nix::unistd::Pid;
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::interceptor::{NetProtocol, OpenFlags, SyscallKind};

use super::syscall_nr;
use super::PtraceSupervisor;

// ---------------------------------------------------------------------------
// Classification entry point
// ---------------------------------------------------------------------------

impl PtraceSupervisor {
    /// Classify the current syscall (identified by register state) into a
    /// [`SyscallKind`].
    ///
    /// The x86_64 calling convention places the syscall number in `orig_rax`
    /// and the first six arguments in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`.
    ///
    /// Returns `None` for syscalls that we do not classify (should not happen
    /// for numbers in the `SECURITY_RELEVANT` set, but handled gracefully).
    pub(super) fn classify_syscall(
        &self,
        pid: Pid,
        regs: &libc::user_regs_struct,
    ) -> Result<Option<SyscallKind>> {
        let nr = regs.orig_rax as i64;
        let pid_u32 = pid.as_raw() as u32;

        match nr {
            // ---------------------------------------------------------------
            // File open family
            // ---------------------------------------------------------------
            syscall_nr::OPEN => {
                // open(pathname, flags, mode)
                let path = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let path = Self::canonicalize_for_tracee(pid_u32, &path);
                let flags = Self::decode_open_flags(regs.rsi);
                Ok(Some(SyscallKind::FileOpen { path, flags }))
            }
            syscall_nr::OPENAT => {
                // openat(dirfd, pathname, flags, mode)
                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let dirfd = regs.rdi as i32;
                let path = Self::resolve_at_path(pid_u32, dirfd, &raw_path);
                let flags = Self::decode_open_flags(regs.rdx);
                Ok(Some(SyscallKind::FileOpen { path, flags }))
            }

            // ---------------------------------------------------------------
            // File read / write
            // ---------------------------------------------------------------
            syscall_nr::READ => {
                // read(fd, buf, count)
                let fd = regs.rdi as i32;
                let path = Self::resolve_fd_path(pid_u32, fd);
                Ok(Some(SyscallKind::FileRead { fd, path }))
            }
            syscall_nr::WRITE => {
                // write(fd, buf, count)
                let fd = regs.rdi as i32;
                let path = Self::resolve_fd_path(pid_u32, fd);
                Ok(Some(SyscallKind::FileWrite { fd, path }))
            }

            // ---------------------------------------------------------------
            // Memory-mapped file read
            // ---------------------------------------------------------------
            syscall_nr::MMAP => {
                // mmap(addr, length, prot, flags, fd, offset)
                // rdi=addr, rsi=length, rdx=prot, r10=flags, r8=fd, r9=offset
                let flags = regs.r10 as i32;
                let fd = regs.r8 as i32;
                const MAP_ANONYMOUS: i32 = 0x20;
                if fd < 0 || (flags & MAP_ANONYMOUS != 0) {
                    // Anonymous mapping — not file-backed, no security relevance.
                    return Ok(None);
                }
                // File-backed mmap: treat as a file read for taint tracking purposes.
                let path = Self::resolve_fd_path(pid_u32, fd);
                Ok(Some(SyscallKind::FileRead { fd, path }))
            }

            // ---------------------------------------------------------------
            // File delete
            // ---------------------------------------------------------------
            syscall_nr::UNLINK => {
                // unlink(pathname)
                let path = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let path = Self::canonicalize_for_tracee(pid_u32, &path);
                Ok(Some(SyscallKind::FileDelete { path }))
            }
            syscall_nr::UNLINKAT => {
                // unlinkat(dirfd, pathname, flags)
                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let dirfd = regs.rdi as i32;
                let path = Self::resolve_at_path(pid_u32, dirfd, &raw_path);
                Ok(Some(SyscallKind::FileDelete { path }))
            }

            // ---------------------------------------------------------------
            // File rename
            // ---------------------------------------------------------------
            syscall_nr::RENAME => {
                // rename(oldpath, newpath)
                let old_path = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let new_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let old_path = Self::canonicalize_for_tracee(pid_u32, &old_path);
                let new_path = Self::canonicalize_for_tracee(pid_u32, &new_path);
                Ok(Some(SyscallKind::FileRename { old_path, new_path }))
            }
            syscall_nr::RENAMEAT => {
                // renameat(olddirfd, oldpath, newdirfd, newpath)
                let old_raw = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let new_raw = self.read_tracee_string(pid, regs.r10, 4096)?;
                let old_dirfd = regs.rdi as i32;
                let new_dirfd = regs.rdx as i32;
                let old_path = Self::resolve_at_path(pid_u32, old_dirfd, &old_raw);
                let new_path = Self::resolve_at_path(pid_u32, new_dirfd, &new_raw);
                Ok(Some(SyscallKind::FileRename { old_path, new_path }))
            }
            syscall_nr::RENAMEAT2 => {
                // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
                let old_raw = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let new_raw = self.read_tracee_string(pid, regs.r10, 4096)?;
                let old_dirfd = regs.rdi as i32;
                let new_dirfd = regs.rdx as i32;
                let old_path = Self::resolve_at_path(pid_u32, old_dirfd, &old_raw);
                let new_path = Self::resolve_at_path(pid_u32, new_dirfd, &new_raw);
                Ok(Some(SyscallKind::FileRename { old_path, new_path }))
            }

            // ---------------------------------------------------------------
            // File chmod
            // ---------------------------------------------------------------
            syscall_nr::CHMOD => {
                // chmod(pathname, mode)
                let path = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let path = Self::canonicalize_for_tracee(pid_u32, &path);
                let mode = regs.rsi as u32;
                Ok(Some(SyscallKind::FileChmod { path, mode }))
            }
            syscall_nr::FCHMODAT => {
                // fchmodat(dirfd, pathname, mode, flags)
                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let dirfd = regs.rdi as i32;
                let path = Self::resolve_at_path(pid_u32, dirfd, &raw_path);
                let mode = regs.rdx as u32;
                Ok(Some(SyscallKind::FileChmod { path, mode }))
            }

            // ---------------------------------------------------------------
            // Directory create
            // ---------------------------------------------------------------
            syscall_nr::MKDIR => {
                // mkdir(pathname, mode)
                let path = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let path = Self::canonicalize_for_tracee(pid_u32, &path);
                let mode = regs.rsi as u32;
                Ok(Some(SyscallKind::DirCreate { path, mode }))
            }
            syscall_nr::MKDIRAT => {
                // mkdirat(dirfd, pathname, mode)
                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let dirfd = regs.rdi as i32;
                let path = Self::resolve_at_path(pid_u32, dirfd, &raw_path);
                let mode = regs.rdx as u32;
                Ok(Some(SyscallKind::DirCreate { path, mode }))
            }

            // ---------------------------------------------------------------
            // Directory list
            // ---------------------------------------------------------------
            syscall_nr::GETDENTS64 => {
                // getdents64(fd, dirp, count)
                let fd = regs.rdi as i32;
                let path =
                    Self::resolve_fd_path(pid_u32, fd).unwrap_or_else(|| format!("<fd:{fd}>"));
                Ok(Some(SyscallKind::DirList { path }))
            }

            // ---------------------------------------------------------------
            // Process exec
            // ---------------------------------------------------------------
            syscall_nr::EXECVE => {
                // execve(pathname, argv, envp)
                let path = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let args = self.read_tracee_string_array(pid, regs.rsi, 256)?;
                Ok(Some(SyscallKind::ProcessExec { path, args }))
            }

            syscall_nr::EXECVEAT => {
                // execveat(dirfd, pathname, argv, envp, flags)
                // rdi = dirfd, rsi = pathname, rdx = argv
                let dirfd = regs.rdi as i32;
                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let args = self.read_tracee_string_array(pid, regs.rdx, 256)?;

                // Resolve relative to dirfd. If the pathname is absolute the
                // dirfd is ignored (kernel semantics). For relative paths,
                // resolve via /proc/<pid>/fd/<dirfd>.
                let path = if raw_path.starts_with('/') {
                    raw_path
                } else if raw_path.is_empty() {
                    // AT_EMPTY_PATH: the fd itself is the executable (fexecve).
                    Self::resolve_fd_path(pid_u32, dirfd).unwrap_or_else(|| format!("<fd:{dirfd}>"))
                } else {
                    let base = Self::resolve_fd_path(pid_u32, dirfd)
                        .unwrap_or_else(|| format!("<fd:{dirfd}>"));
                    format!("{base}/{raw_path}")
                };

                Ok(Some(SyscallKind::ProcessExec { path, args }))
            }

            // ---------------------------------------------------------------
            // Process fork / clone
            // ---------------------------------------------------------------
            syscall_nr::FORK | syscall_nr::CLONE => {
                // At syscall-entry the child PID is not yet known (the
                // kernel has not assigned it). We emit child_pid: 0 here.
                //
                // The actual child PID is captured asynchronously by the
                // PTRACE_EVENT_FORK / PTRACE_EVENT_CLONE handler in
                // `next_event` -> `handle_ptrace_event`, which calls
                // `ptrace::getevent()` to read the new PID from the kernel.
                // That handler registers the child in `supervised` and, for
                // process-tree tracking, the event_handler module records
                // the parent-child relationship when it receives this
                // ProcessFork event.
                //
                // Consumers should treat child_pid == 0 as "not yet known"
                // and rely on the process-tree or PTRACE_EVENT for the
                // actual child PID.
                Ok(Some(SyscallKind::ProcessFork { child_pid: 0 }))
            }

            // ---------------------------------------------------------------
            // Networking
            // ---------------------------------------------------------------
            syscall_nr::CONNECT => {
                // connect(sockfd, addr, addrlen)
                let sockfd = regs.rdi as i32;
                match self.read_sockaddr(
                    pid,
                    regs.rsi,
                    regs.rdx as usize,
                    Some((pid_u32, sockfd)),
                )? {
                    Some((address, port, protocol)) => Ok(Some(SyscallKind::NetConnect {
                        address,
                        port,
                        protocol,
                    })),
                    None => Ok(None), // Non-internet socket family — silently allow
                }
            }
            syscall_nr::BIND => {
                // bind(sockfd, addr, addrlen)
                let sockfd = regs.rdi as i32;
                match self.read_sockaddr(
                    pid,
                    regs.rsi,
                    regs.rdx as usize,
                    Some((pid_u32, sockfd)),
                )? {
                    Some((address, port, protocol)) => Ok(Some(SyscallKind::NetBind {
                        address,
                        port,
                        protocol,
                    })),
                    None => Ok(None),
                }
            }
            syscall_nr::SENDTO => {
                // sendto(sockfd, buf, len, flags, dest_addr, addrlen)
                if regs.r8 != 0 {
                    let sockfd = regs.rdi as i32;
                    match self.read_sockaddr(
                        pid,
                        regs.r8,
                        regs.r9 as usize,
                        Some((pid_u32, sockfd)),
                    )? {
                        Some((address, port, _protocol)) => {
                            Ok(Some(SyscallKind::NetSendTo { address, port }))
                        }
                        None => Ok(None),
                    }
                } else {
                    // No destination address -- behaves like `send()` on a
                    // connected socket.
                    Ok(Some(SyscallKind::NetSendTo {
                        address: String::new(),
                        port: 0,
                    }))
                }
            }

            // ---------------------------------------------------------------
            // Raw socket creation
            //
            // socket(domain, type, protocol) is intercepted only for raw-socket
            // families. AF_PACKET (17) provides direct link-layer access —
            // a process with this socket can capture or inject arbitrary frames,
            // bypassing the normal IP stack. AF_NETLINK (16) gives direct
            // kernel subsystem access.
            //
            // Normal socket families (AF_INET=2, AF_INET6=10, AF_UNIX=1) are
            // returned as None — they are already intercepted at connect()/bind()
            // time, so intercepting socket() for them would add noise and overhead
            // without security benefit.
            // ---------------------------------------------------------------
            syscall_nr::SOCKET => {
                // socket(domain, type, protocol)
                let domain = regs.rdi as i32;
                let socket_type = regs.rsi as i32;
                let protocol = regs.rdx as i32;
                const AF_NETLINK: i32 = 16;
                const AF_PACKET: i32 = 17;
                if domain == AF_PACKET || domain == AF_NETLINK {
                    Ok(Some(SyscallKind::RawSocketCreate {
                        domain,
                        socket_type,
                        protocol,
                    }))
                } else {
                    // AF_INET, AF_INET6, AF_UNIX — intercepted at connect/bind.
                    Ok(None)
                }
            }

            // ---------------------------------------------------------------
            // Pipes and socket pairs
            // ---------------------------------------------------------------
            syscall_nr::PIPE | syscall_nr::PIPE2 => Ok(Some(SyscallKind::PipeCreate)),
            syscall_nr::SOCKETPAIR => Ok(Some(SyscallKind::SocketPair)),

            // ---------------------------------------------------------------
            // Kernel-bypass fd-to-fd transfers
            //
            // sendfile, splice, and tee copy data between file descriptors
            // entirely within the kernel, bypassing the userspace write()/sendto()
            // path. Without interception a process can:
            //   1. openat() a sensitive file  → taint registered ✓
            //   2. connect() to attacker       → taint scored   ✓
            //   3. sendfile(sock, file)         → invisible      ✗
            //
            // We emit FileRead on the source fd so the existing taint filter
            // evaluates the path with its normal scoring logic. If the source
            // is an anonymous pipe or socket, resolve_fd_path returns None and
            // the filter produces a near-zero score, which is correct.
            // ---------------------------------------------------------------
            syscall_nr::SENDFILE => {
                // sendfile(out_fd, in_fd, offset, count)
                // rdi = out_fd (destination, often a socket)
                // rsi = in_fd  (source, often a file)
                let in_fd = regs.rsi as i32;
                let path = Self::resolve_fd_path(pid_u32, in_fd);
                Ok(Some(SyscallKind::FileRead { fd: in_fd, path }))
            }
            syscall_nr::SPLICE => {
                // splice(fd_in, off_in, fd_out, off_out, len, flags)
                // rdi = fd_in (source)
                let in_fd = regs.rdi as i32;
                let path = Self::resolve_fd_path(pid_u32, in_fd);
                Ok(Some(SyscallKind::FileRead { fd: in_fd, path }))
            }
            syscall_nr::TEE => {
                // tee(fd_in, fd_out, len, flags)
                // rdi = fd_in (source pipe)
                let in_fd = regs.rdi as i32;
                let path = Self::resolve_fd_path(pid_u32, in_fd);
                Ok(Some(SyscallKind::FileRead { fd: in_fd, path }))
            }

            // ---------------------------------------------------------------
            // io_uring — deny ring creation and use unconditionally.
            //
            // io_uring submissions bypass the normal per-syscall ptrace stop
            // model: file reads, writes, and network operations queued in the
            // ring buffer execute without individual ptrace entry stops, making
            // them invisible to grith's interception layer.
            //
            // io_uring_setup is the critical gate — denying it prevents the
            // ring fd from being created at all. io_uring_enter and
            // io_uring_register are included as defence-in-depth.
            //
            // Node.js/libuv (used by all supervised AI tools) probes
            // io_uring_setup at startup and falls back to epoll + standard
            // syscalls on EPERM, so this has no practical compatibility cost.
            // ---------------------------------------------------------------
            syscall_nr::IO_URING_SETUP
            | syscall_nr::IO_URING_ENTER
            | syscall_nr::IO_URING_REGISTER => Ok(Some(SyscallKind::IoUringSetup)),

            // ---------------------------------------------------------------
            // Unrecognised (should not reach here for SECURITY_RELEVANT nrs)
            // ---------------------------------------------------------------
            _ => Ok(None),
        }
    }

    /// Map a non-standard socket family to a `raw:<name>` address label so
    /// the proxy pipeline can evaluate and score the syscall, rather than
    /// silently allowing it.
    ///
    /// Returns `None` for families that are genuinely kernel-internal and
    /// cannot be used for off-host data exfiltration.
    pub(super) fn raw_socket_label(family: i32) -> Option<&'static str> {
        match family {
            // AF_PACKET (17): raw Ethernet-level sockets. Can send arbitrary
            // frames to any network interface, bypassing the IP stack entirely.
            // A direct exfiltration vector — must go through the proxy.
            libc::AF_PACKET => Some("raw:af_packet"),
            // AF_NETLINK (16): kernel↔userspace messaging. Cannot send traffic
            // off-host directly, but can manipulate routing tables, firewall
            // rules, and interface state — surface for review.
            libc::AF_NETLINK => Some("raw:af_netlink"),
            _ => None,
        }
    }

    /// Read a `sockaddr` structure from the tracee and extract the address,
    /// port, and protocol family.
    ///
    /// Supports:
    /// - `AF_INET`  (IPv4) -- extracts dotted-quad address and port.
    /// - `AF_INET6` (IPv6) -- extracts colon-hex address and port.
    /// - `AF_UNIX`  -- extracts the socket path.
    /// - `AF_PACKET` / `AF_NETLINK` -- returns a `raw:<family>` address so
    ///   the proxy can score and potentially deny the operation.
    ///
    /// Returns `None` only for socket families that cannot exfiltrate data
    /// off the host and do not require proxy evaluation.
    pub(super) fn read_sockaddr(
        &self,
        pid: Pid,
        addr: u64,
        _addrlen: usize,
        sock_info: Option<(u32, i32)>,
    ) -> Result<Option<(String, u16, NetProtocol)>> {
        if addr == 0 {
            return Ok(Some((String::new(), 0, NetProtocol::Tcp)));
        }

        // Read the first 8 bytes which cover the family + port + IPv4 addr.
        let word0 = ptrace::read(pid, addr as *mut libc::c_void).map_err(|e| {
            Error::InterceptionError(format!(
                "failed to read sockaddr at {addr:#x} for pid {pid}: {e}"
            ))
        })?;
        let bytes0 = word0.to_ne_bytes();

        // sa_family is the first 2 bytes (u16 in native endian).
        let family = u16::from_ne_bytes([bytes0[0], bytes0[1]]);

        match family as i32 {
            libc::AF_INET => {
                // struct sockaddr_in { sa_family_t(2), in_port_t(2), in_addr(4) }
                let port = u16::from_be_bytes([bytes0[2], bytes0[3]]);
                let ip = format!("{}.{}.{}.{}", bytes0[4], bytes0[5], bytes0[6], bytes0[7]);
                let protocol = sock_info
                    .map(|(p, fd)| Self::resolve_socket_protocol(p, fd))
                    .unwrap_or(NetProtocol::Tcp);
                Ok(Some((ip, port, protocol)))
            }
            libc::AF_INET6 => {
                // struct sockaddr_in6 {
                //   family(2), port(2), flowinfo(4), addr(16), scope_id(4)
                // }
                let port = u16::from_be_bytes([bytes0[2], bytes0[3]]);
                // The 16-byte in6_addr starts at byte offset 8 from the
                // struct base. On x86_64 a ptrace PEEKDATA word is 8 bytes,
                // so we need two reads to cover the full 16-byte address.
                let word1 = ptrace::read(pid, (addr + 8) as *mut libc::c_void).unwrap_or(0);
                let word2 = ptrace::read(pid, (addr + 16) as *mut libc::c_void).unwrap_or(0);
                let b1 = word1.to_ne_bytes();
                let b2 = word2.to_ne_bytes();
                // Each word is 8 bytes = 4 u16 segments. word1 covers
                // segments 0..4, word2 covers segments 4..8.
                let segments: Vec<String> = (0..8)
                    .map(|i| {
                        let (src, off) = if i < 4 {
                            (&b1, i * 2)
                        } else {
                            (&b2, (i - 4) * 2)
                        };
                        format!("{:x}", u16::from_be_bytes([src[off], src[off + 1]]))
                    })
                    .collect();
                let ip = segments.join(":");
                let protocol = sock_info
                    .map(|(p, fd)| Self::resolve_socket_protocol(p, fd))
                    .unwrap_or(NetProtocol::Tcp);
                Ok(Some((ip, port, protocol)))
            }
            libc::AF_UNIX => {
                // struct sockaddr_un { family(2), sun_path(108) }
                //
                // Prefix the path with "unix:" so callers can distinguish
                // Unix domain socket addresses from IP addresses without
                // inspecting the protocol field.  Abstract-namespace sockets
                // (sun_path[0] == '\0') produce an empty path component,
                // yielding "unix:" which is treated as local/benign.
                let path = self.read_tracee_string(pid, addr + 2, 108)?;
                Ok(Some((format!("unix:{path}"), 0, NetProtocol::Unix)))
            }
            other => {
                if let Some(label) = Self::raw_socket_label(other) {
                    // Raw/unusual socket family that must go through the proxy.
                    Ok(Some((label.to_string(), 0, NetProtocol::Tcp)))
                } else {
                    // Genuinely kernel-internal family (AF_TIPC, AF_ALG, etc.) —
                    // no data can leave the host. Silently allow.
                    debug!(
                        family = other,
                        pid = pid.as_raw(),
                        "skipping kernel-internal sockaddr family"
                    );
                    Ok(None)
                }
            }
        }
    }

    /// Try to determine whether the socket is TCP or UDP by inspecting
    /// the socket fd's inode in `/proc/<pid>/net/{tcp,udp,tcp6,udp6}`.
    ///
    /// Falls back to `Tcp` if the socket type cannot be determined (e.g.,
    /// process has already exited or fd is not a socket).
    fn resolve_socket_protocol(pid: u32, sockfd: i32) -> NetProtocol {
        // Step 1: resolve the socket fd to its inode via /proc/<pid>/fd/<fd>.
        let link_path = format!("/proc/{pid}/fd/{sockfd}");
        let target = match std::fs::read_link(&link_path) {
            Ok(t) => t.to_string_lossy().into_owned(),
            Err(_) => return NetProtocol::Tcp,
        };

        // The symlink target for a socket looks like "socket:[<inode>]".
        let inode_str = match target
            .strip_prefix("socket:[")
            .and_then(|s| s.strip_suffix(']'))
        {
            Some(s) => s,
            None => return NetProtocol::Tcp,
        };

        // Step 2: search the UDP tables for this inode. If found, it's UDP.
        // Otherwise default to TCP.
        for udp_table in &[
            format!("/proc/{pid}/net/udp"),
            format!("/proc/{pid}/net/udp6"),
        ] {
            if let Ok(contents) = std::fs::read_to_string(udp_table) {
                // Each line after the header has the inode as one of the
                // whitespace-delimited fields (field index 9, 0-based).
                for line in contents.lines().skip(1) {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() > 9 && fields[9] == inode_str {
                        return NetProtocol::Udp;
                    }
                }
            }
        }

        NetProtocol::Tcp
    }

    // -------------------------------------------------------------------
    // Path and flag helpers
    // -------------------------------------------------------------------

    /// Resolve a file descriptor to its filesystem path by reading the
    /// `/proc/<pid>/fd/<fd>` symlink.
    ///
    /// Returns `None` if:
    /// - The symlink does not exist (fd was closed or PID is invalid).
    /// - The fd refers to a non-filesystem object (pipe, socket, anon_inode)
    ///   whose target does not start with `/`.
    pub(super) fn resolve_fd_path(pid: u32, fd: i32) -> Option<String> {
        let link = format!("/proc/{pid}/fd/{fd}");
        match std::fs::read_link(&link) {
            Ok(target) => {
                let path_str = match target.into_os_string().into_string() {
                    Ok(s) => s,
                    Err(os_str) => {
                        warn!(
                            pid,
                            fd,
                            "fd path contains non-UTF8 bytes; lossy conversion applied: {:?}",
                            os_str
                        );
                        os_str.to_string_lossy().into_owned()
                    }
                };
                // Filter out pseudo-paths like "pipe:[12345]" or "socket:[67890]".
                if path_str.starts_with('/') {
                    Some(path_str)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Resolve the current working directory of a tracee via `/proc/<pid>/cwd`.
    pub(super) fn resolve_cwd(pid: u32) -> Option<PathBuf> {
        let link = format!("/proc/{pid}/cwd");
        std::fs::read_link(link).ok()
    }

    /// Canonicalize a path relative to the tracee's working directory.
    ///
    /// If `path` is already absolute it is returned unchanged. Otherwise it
    /// is joined with the tracee's `/proc/<pid>/cwd` target.
    pub(super) fn canonicalize_for_tracee(pid: u32, path: &str) -> String {
        if path.starts_with('/') {
            return path.to_string();
        }
        match Self::resolve_cwd(pid) {
            Some(cwd) => cwd.join(path).to_string_lossy().into_owned(),
            None => path.to_string(),
        }
    }

    /// Resolve a path argument from a `*at` syscall that takes a `dirfd`.
    ///
    /// The `*at` family of syscalls (openat, unlinkat, mkdirat, fchmodat,
    /// renameat2) interpret their path relative to `dirfd`. If `dirfd` is
    /// `AT_FDCWD` (-100) the path is relative to the process CWD. If the
    /// path is absolute, `dirfd` is ignored entirely.
    pub(super) fn resolve_at_path(pid: u32, dirfd: i32, raw_path: &str) -> String {
        if raw_path.starts_with('/') {
            raw_path.to_string()
        } else if dirfd == libc::AT_FDCWD {
            Self::canonicalize_for_tracee(pid, raw_path)
        } else {
            match Self::resolve_fd_path(pid, dirfd) {
                Some(dir) => format!("{dir}/{raw_path}"),
                None => raw_path.to_string(),
            }
        }
    }

    /// Map a raw Linux `O_*` flags bitmask to our [`OpenFlags`] enum.
    ///
    /// The precedence is: access mode first (`O_RDONLY`, `O_WRONLY`, `O_RDWR`),
    /// then modifier flags (`O_APPEND` > `O_TRUNC` > `O_CREAT`) for write-mode
    /// opens.
    pub(super) fn decode_open_flags(raw: u64) -> OpenFlags {
        let access_mode = (raw as i32) & libc::O_ACCMODE;
        if access_mode == libc::O_RDONLY {
            OpenFlags::ReadOnly
        } else if access_mode == libc::O_WRONLY {
            if raw as i32 & libc::O_APPEND != 0 {
                OpenFlags::Append
            } else if raw as i32 & libc::O_TRUNC != 0 {
                OpenFlags::Truncate
            } else if raw as i32 & libc::O_CREAT != 0 {
                OpenFlags::Create
            } else {
                OpenFlags::WriteOnly
            }
        } else if access_mode == libc::O_RDWR {
            OpenFlags::ReadWrite
        } else {
            // Fallback for unusual flag combinations.
            OpenFlags::ReadOnly
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::platform::linux::{is_security_relevant, SECURITY_RELEVANT};

    // -- Syscall number constants -------------------------------------------

    #[test]
    fn syscall_nr_read_is_0() {
        assert_eq!(syscall_nr::READ, 0);
    }

    #[test]
    fn syscall_nr_write_is_1() {
        assert_eq!(syscall_nr::WRITE, 1);
    }

    #[test]
    fn syscall_nr_open_is_2() {
        assert_eq!(syscall_nr::OPEN, 2);
    }

    #[test]
    fn syscall_nr_pipe_is_22() {
        assert_eq!(syscall_nr::PIPE, 22);
    }

    #[test]
    fn syscall_nr_connect_is_42() {
        assert_eq!(syscall_nr::CONNECT, 42);
    }

    #[test]
    fn syscall_nr_sendto_is_44() {
        assert_eq!(syscall_nr::SENDTO, 44);
    }

    #[test]
    fn syscall_nr_bind_is_49() {
        assert_eq!(syscall_nr::BIND, 49);
    }

    #[test]
    fn syscall_nr_socketpair_is_53() {
        assert_eq!(syscall_nr::SOCKETPAIR, 53);
    }

    #[test]
    fn syscall_nr_clone_is_56() {
        assert_eq!(syscall_nr::CLONE, 56);
    }

    #[test]
    fn syscall_nr_fork_is_57() {
        assert_eq!(syscall_nr::FORK, 57);
    }

    #[test]
    fn syscall_nr_execve_is_59() {
        assert_eq!(syscall_nr::EXECVE, 59);
    }

    #[test]
    fn syscall_nr_rename_is_82() {
        assert_eq!(syscall_nr::RENAME, 82);
    }

    #[test]
    fn syscall_nr_mkdir_is_83() {
        assert_eq!(syscall_nr::MKDIR, 83);
    }

    #[test]
    fn syscall_nr_unlink_is_87() {
        assert_eq!(syscall_nr::UNLINK, 87);
    }

    #[test]
    fn syscall_nr_chmod_is_90() {
        assert_eq!(syscall_nr::CHMOD, 90);
    }

    #[test]
    fn syscall_nr_getdents64_is_217() {
        assert_eq!(syscall_nr::GETDENTS64, 217);
    }

    #[test]
    fn syscall_nr_openat_is_257() {
        assert_eq!(syscall_nr::OPENAT, 257);
    }

    #[test]
    fn syscall_nr_mkdirat_is_258() {
        assert_eq!(syscall_nr::MKDIRAT, 258);
    }

    #[test]
    fn syscall_nr_unlinkat_is_263() {
        assert_eq!(syscall_nr::UNLINKAT, 263);
    }

    #[test]
    fn syscall_nr_fchmodat_is_268() {
        assert_eq!(syscall_nr::FCHMODAT, 268);
    }

    #[test]
    fn syscall_nr_pipe2_is_293() {
        assert_eq!(syscall_nr::PIPE2, 293);
    }

    #[test]
    fn syscall_nr_renameat2_is_316() {
        assert_eq!(syscall_nr::RENAMEAT2, 316);
    }

    #[test]
    fn syscall_nr_mmap_is_9() {
        assert_eq!(syscall_nr::MMAP, 9);
    }

    #[test]
    fn syscall_nr_io_uring_setup_is_425() {
        assert_eq!(syscall_nr::IO_URING_SETUP, 425);
    }

    #[test]
    fn syscall_nr_io_uring_enter_is_426() {
        assert_eq!(syscall_nr::IO_URING_ENTER, 426);
    }

    #[test]
    fn syscall_nr_io_uring_register_is_427() {
        assert_eq!(syscall_nr::IO_URING_REGISTER, 427);
    }

    #[test]
    fn syscall_nr_sendfile_is_40() {
        assert_eq!(syscall_nr::SENDFILE, 40);
    }

    #[test]
    fn syscall_nr_splice_is_275() {
        assert_eq!(syscall_nr::SPLICE, 275);
    }

    #[test]
    fn syscall_nr_tee_is_276() {
        assert_eq!(syscall_nr::TEE, 276);
    }

    // -- Security relevance predicate ---------------------------------------

    #[test]
    fn all_listed_syscalls_are_security_relevant() {
        let expected: Vec<i64> = vec![
            // READ (0) and WRITE (1) intentionally excluded — see SECURITY_RELEVANT.
            2, // mmap(9): file-backed mmaps only
            9, 22, 42, 44, 49, 53, 56, 57, 59, 82, 83, 87, 90, 217, 257, 258, 263, 264, 268, 293,
            316, // io_uring (425/426/427)
            425, 426, 427,
            // sendfile(40), splice(275), tee(276): kernel-bypass fd-to-fd transfers
            40, 275, 276, // socket(41): raw-socket creation (AF_PACKET/AF_NETLINK only)
            41,
        ];
        for nr in &expected {
            assert!(
                is_security_relevant(*nr),
                "syscall number {nr} should be classified as security-relevant"
            );
        }
    }

    #[test]
    fn common_non_security_syscalls_are_not_relevant() {
        // read(0), write(1), close(3), fstat(5), lseek(8),
        // mprotect(10), brk(12), ioctl(16), access(21), nanosleep(35),
        // exit_group(231).
        // Note: mmap(9) is now security-relevant (file-backed mmaps).
        let innocuous = [0, 1, 3, 5, 8, 10, 12, 16, 21, 35, 100, 200, 231, 500];
        for nr in &innocuous {
            assert!(
                !is_security_relevant(*nr),
                "syscall number {nr} should NOT be classified as security-relevant"
            );
        }
    }

    #[test]
    fn security_relevant_list_has_expected_count() {
        // 30 distinct syscall numbers are tracked (READ/WRITE excluded;
        // mmap added for file-backed mmaps; io_uring_setup/enter/register added;
        // sendfile/splice/tee added for kernel-bypass fd-to-fd transfers;
        // socket(41) added for raw-socket creation detection;
        // execveat(322) added alongside execve for exec provenance).
        assert_eq!(SECURITY_RELEVANT.len(), 30);
    }

    #[test]
    fn security_relevant_list_has_no_duplicates() {
        let mut seen = HashSet::new();
        for &nr in SECURITY_RELEVANT {
            assert!(seen.insert(nr), "duplicate entry {nr} in SECURITY_RELEVANT");
        }
    }

    // -- OpenFlags decoding -------------------------------------------------

    #[test]
    fn decode_open_flags_rdonly() {
        let flags = PtraceSupervisor::decode_open_flags(libc::O_RDONLY as u64);
        assert_eq!(flags, OpenFlags::ReadOnly);
    }

    #[test]
    fn decode_open_flags_wronly() {
        let flags = PtraceSupervisor::decode_open_flags(libc::O_WRONLY as u64);
        assert_eq!(flags, OpenFlags::WriteOnly);
    }

    #[test]
    fn decode_open_flags_rdwr() {
        let flags = PtraceSupervisor::decode_open_flags(libc::O_RDWR as u64);
        assert_eq!(flags, OpenFlags::ReadWrite);
    }

    #[test]
    fn decode_open_flags_wronly_append() {
        let raw = (libc::O_WRONLY | libc::O_APPEND) as u64;
        let flags = PtraceSupervisor::decode_open_flags(raw);
        assert_eq!(flags, OpenFlags::Append);
    }

    #[test]
    fn decode_open_flags_wronly_trunc() {
        let raw = (libc::O_WRONLY | libc::O_TRUNC) as u64;
        let flags = PtraceSupervisor::decode_open_flags(raw);
        assert_eq!(flags, OpenFlags::Truncate);
    }

    #[test]
    fn decode_open_flags_wronly_creat() {
        let raw = (libc::O_WRONLY | libc::O_CREAT) as u64;
        let flags = PtraceSupervisor::decode_open_flags(raw);
        assert_eq!(flags, OpenFlags::Create);
    }

    #[test]
    fn decode_open_flags_zero_is_rdonly() {
        // O_RDONLY is typically 0 on Linux.
        let flags = PtraceSupervisor::decode_open_flags(0);
        assert_eq!(flags, OpenFlags::ReadOnly);
    }

    // -- fd-to-path resolution ----------------------------------------------

    #[test]
    fn resolve_fd_path_returns_none_for_invalid_pid() {
        // PID 0 (swapper) does not have an accessible /proc fd table.
        let result = PtraceSupervisor::resolve_fd_path(0, 999);
        assert!(result.is_none());
    }

    #[test]
    fn resolve_fd_path_returns_none_for_nonexistent_fd() {
        let our_pid = std::process::id();
        // A very high fd number that almost certainly does not exist.
        let result = PtraceSupervisor::resolve_fd_path(our_pid, 99999);
        assert!(result.is_none());
    }

    #[test]
    fn resolve_fd_path_does_not_panic_for_stdout() {
        // fd 1 (stdout) might be a TTY, pipe, or file depending on the
        // test runner. We just verify it does not panic.
        let our_pid = std::process::id();
        let _result = PtraceSupervisor::resolve_fd_path(our_pid, 1);
    }

    // -- Canonicalize helper ------------------------------------------------

    #[test]
    fn canonicalize_absolute_path_unchanged() {
        let result = PtraceSupervisor::canonicalize_for_tracee(1, "/etc/passwd");
        assert_eq!(result, "/etc/passwd");
    }

    #[test]
    fn canonicalize_relative_path_prepends_cwd() {
        // Use our own PID so /proc/<pid>/cwd is readable.
        let our_pid = std::process::id();
        let result = PtraceSupervisor::canonicalize_for_tracee(our_pid, "foo/bar.txt");
        assert!(
            result.starts_with('/'),
            "canonicalized path should be absolute, got: {result}"
        );
        assert!(
            result.ends_with("foo/bar.txt"),
            "canonicalized path should end with the relative component, got: {result}"
        );
    }

    #[test]
    fn canonicalize_for_nonexistent_pid_returns_original() {
        // PID 0 won't have a readable /proc/0/cwd for a normal user.
        let result = PtraceSupervisor::canonicalize_for_tracee(0, "relative.txt");
        assert_eq!(result, "relative.txt");
    }

    // -- resolve_at_path helper ---------------------------------------------

    #[test]
    fn resolve_at_path_absolute_ignores_dirfd() {
        let result = PtraceSupervisor::resolve_at_path(1, 42, "/absolute/path");
        assert_eq!(result, "/absolute/path");
    }

    #[test]
    fn resolve_at_path_at_fdcwd_uses_cwd() {
        let our_pid = std::process::id();
        let result = PtraceSupervisor::resolve_at_path(our_pid, libc::AT_FDCWD, "relative.txt");
        assert!(
            result.starts_with('/'),
            "AT_FDCWD resolution should produce an absolute path, got: {result}"
        );
    }

    // -- mmap classification ------------------------------------------------

    /// mmap with fd=-1 and MAP_ANONYMOUS → anonymous allocation, not security-relevant.
    #[test]
    fn classify_mmap_anonymous_returns_none() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::MMAP as u64;
        regs.r10 = 0x20; // MAP_ANONYMOUS
        regs.r8 = u64::MAX; // fd = -1 as u64

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(
            result.is_none(),
            "anonymous mmap should return None, got {result:?}"
        );
    }

    /// mmap with MAP_ANONYMOUS cleared even if fd looks valid → still anonymous
    /// because the flag dominates.
    #[test]
    fn classify_mmap_anonymous_flag_dominates() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::MMAP as u64;
        regs.r10 = 0x20; // MAP_ANONYMOUS set
        regs.r8 = 0; // fd = 0 (stdin) — but MAP_ANONYMOUS dominates

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(
            result.is_none(),
            "MAP_ANONYMOUS mmap should return None regardless of fd, got {result:?}"
        );
    }

    /// mmap with a real file fd and no MAP_ANONYMOUS → FileRead with resolved path.
    #[test]
    fn classify_mmap_file_backed_returns_file_read() {
        use nix::libc;
        use std::io::Write;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        // Create a real temp file and keep the fd open.
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(b"test").unwrap();
        let fd = std::os::unix::io::IntoRawFd::into_raw_fd(tmp.reopen().expect("reopen"));

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::MMAP as u64;
        regs.r10 = 0x01; // MAP_SHARED — no MAP_ANONYMOUS bit
        regs.r8 = fd as u64;

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(result.is_some(), "file-backed mmap should return Some(...)");
        match result.unwrap() {
            SyscallKind::FileRead { fd: got_fd, path } => {
                assert_eq!(got_fd, fd, "fd should match");
                // The path may be None if the temp file was already unlinked,
                // but the variant must be FileRead.
                let _ = path;
            }
            other => panic!("expected FileRead, got {other:?}"),
        }

        // Close the fd we opened above.
        unsafe { libc::close(fd) };
    }

    // -- sendfile / splice / tee classification -----------------------------

    /// sendfile with a real file fd is classified as FileRead with the fd's path.
    #[test]
    fn classify_sendfile_file_fd_returns_file_read_with_path() {
        use nix::libc;
        use std::io::Write;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        // Create a real temp file and keep an open fd to it.
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(b"secret").unwrap();
        let file = tmp.reopen().expect("reopen");
        let in_fd = std::os::unix::io::IntoRawFd::into_raw_fd(file);

        // sendfile(out_fd=99, in_fd=<file>, offset=0, count=6)
        // rdi = out_fd, rsi = in_fd
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::SENDFILE as u64;
        regs.rdi = 99; // fake socket fd
        regs.rsi = in_fd as u64;

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(result.is_some(), "sendfile should classify as Some(...)");
        match result.unwrap() {
            SyscallKind::FileRead { fd, path } => {
                assert_eq!(fd, in_fd, "fd should be the in_fd (source)");
                assert!(
                    path.is_some(),
                    "path should resolve for an open temp file fd"
                );
            }
            other => panic!("expected FileRead, got {other:?}"),
        }

        unsafe { libc::close(in_fd) };
    }

    /// sendfile with an anonymous/socket source fd (path not resolvable) yields
    /// FileRead with path=None, which the taint filter scores as near-zero.
    #[test]
    fn classify_sendfile_anonymous_fd_returns_file_read_with_none_path() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        // Use fd 99999 which almost certainly does not exist → resolve_fd_path → None.
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::SENDFILE as u64;
        regs.rdi = 88888; // fake out_fd
        regs.rsi = 99999; // nonexistent in_fd

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(
            result.is_some(),
            "sendfile should always classify as Some(...)"
        );
        match result.unwrap() {
            SyscallKind::FileRead { fd, path } => {
                assert_eq!(fd, 99999_i32, "fd should be the in_fd");
                assert!(
                    path.is_none(),
                    "path should be None for an unresolvable fd, got {path:?}"
                );
            }
            other => panic!("expected FileRead, got {other:?}"),
        }
    }

    /// splice with a real file fd on the input side is classified as FileRead.
    #[test]
    fn classify_splice_returns_file_read() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        // splice(fd_in=99999, ...) with unresolvable fd → FileRead { path: None }
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::SPLICE as u64;
        regs.rdi = 99999; // fd_in

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            SyscallKind::FileRead { fd, path: _ } => {
                assert_eq!(fd, 99999_i32);
            }
            other => panic!("expected FileRead, got {other:?}"),
        }
    }

    /// tee with a pipe fd is classified as FileRead.
    #[test]
    fn classify_tee_returns_file_read() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::TEE as u64;
        regs.rdi = 99999; // fd_in

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            SyscallKind::FileRead { fd, path: _ } => {
                assert_eq!(fd, 99999_i32);
            }
            other => panic!("expected FileRead, got {other:?}"),
        }
    }

    // -- raw_socket_label classification -----------------------------------

    #[test]
    fn raw_socket_label_af_packet_is_17() {
        // AF_PACKET is 17 on Linux x86_64. Verify the constant maps correctly.
        assert_eq!(nix::libc::AF_PACKET, 17);
        assert_eq!(
            PtraceSupervisor::raw_socket_label(17),
            Some("raw:af_packet"),
            "AF_PACKET (17) must map to raw:af_packet"
        );
    }

    #[test]
    fn raw_socket_label_af_netlink_is_16() {
        assert_eq!(nix::libc::AF_NETLINK, 16);
        assert_eq!(
            PtraceSupervisor::raw_socket_label(16),
            Some("raw:af_netlink"),
            "AF_NETLINK (16) must map to raw:af_netlink"
        );
    }

    #[test]
    fn raw_socket_label_kernel_internal_families_return_none() {
        // AF_TIPC (33), AF_ALG (38) — no off-host exfiltration possible.
        assert_eq!(PtraceSupervisor::raw_socket_label(33), None);
        assert_eq!(PtraceSupervisor::raw_socket_label(38), None);
        assert_eq!(PtraceSupervisor::raw_socket_label(99), None);
    }

    #[test]
    fn raw_socket_label_internet_families_are_handled_by_read_sockaddr_not_here() {
        // AF_INET (2) and AF_INET6 (10) are handled by dedicated arms
        // in read_sockaddr, not by raw_socket_label.
        assert_eq!(PtraceSupervisor::raw_socket_label(2), None);
        assert_eq!(PtraceSupervisor::raw_socket_label(10), None);
        assert_eq!(PtraceSupervisor::raw_socket_label(1), None); // AF_UNIX
    }

    // -- Syscall number to kind mapping completeness ------------------------

    /// Verify that every syscall number in the SECURITY_RELEVANT list has
    /// a corresponding match arm in `classify_syscall` by checking that the
    /// syscall_nr module exports a constant for each.
    #[test]
    fn syscall_nr_module_covers_all_security_relevant_numbers() {
        let from_module: Vec<i64> = vec![
            // READ and WRITE intentionally excluded from SECURITY_RELEVANT.
            syscall_nr::OPEN,
            syscall_nr::MMAP,
            syscall_nr::PIPE,
            syscall_nr::CONNECT,
            syscall_nr::SENDTO,
            syscall_nr::BIND,
            syscall_nr::SOCKETPAIR,
            syscall_nr::CLONE,
            syscall_nr::FORK,
            syscall_nr::EXECVE,
            syscall_nr::RENAME,
            syscall_nr::MKDIR,
            syscall_nr::UNLINK,
            syscall_nr::CHMOD,
            syscall_nr::GETDENTS64,
            syscall_nr::OPENAT,
            syscall_nr::MKDIRAT,
            syscall_nr::UNLINKAT,
            syscall_nr::RENAMEAT,
            syscall_nr::FCHMODAT,
            syscall_nr::PIPE2,
            syscall_nr::RENAMEAT2,
            syscall_nr::IO_URING_SETUP,
            syscall_nr::IO_URING_ENTER,
            syscall_nr::IO_URING_REGISTER,
            syscall_nr::SENDFILE,
            syscall_nr::SPLICE,
            syscall_nr::TEE,
            syscall_nr::SOCKET,
            syscall_nr::EXECVEAT,
        ];

        let relevant_set: HashSet<i64> = SECURITY_RELEVANT.iter().copied().collect();
        let module_set: HashSet<i64> = from_module.into_iter().collect();

        assert_eq!(
            relevant_set, module_set,
            "SECURITY_RELEVANT and syscall_nr module must list the same numbers"
        );
    }

    // -- socket() classification -------------------------------------------

    #[test]
    fn syscall_nr_socket_is_41() {
        assert_eq!(syscall_nr::SOCKET, 41);
    }

    /// socket(AF_PACKET, ...) → RawSocketCreate (raw link-layer access).
    #[test]
    fn classify_socket_af_packet_returns_raw_socket_create() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::SOCKET as u64;
        regs.rdi = 17; // AF_PACKET
        regs.rsi = 3; // SOCK_RAW
        regs.rdx = 0; // htons(ETH_P_ALL) — 0 for test

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(
            result.is_some(),
            "AF_PACKET socket() should return Some(...)"
        );
        match result.unwrap() {
            SyscallKind::RawSocketCreate {
                domain,
                socket_type,
                protocol,
            } => {
                assert_eq!(domain, 17, "domain should be AF_PACKET");
                assert_eq!(socket_type, 3, "socket_type should be SOCK_RAW");
                assert_eq!(protocol, 0);
            }
            other => panic!("expected RawSocketCreate, got {other:?}"),
        }
    }

    /// socket(AF_NETLINK, ...) → RawSocketCreate (kernel netlink access).
    #[test]
    fn classify_socket_af_netlink_returns_raw_socket_create() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::SOCKET as u64;
        regs.rdi = 16; // AF_NETLINK
        regs.rsi = 3; // SOCK_RAW
        regs.rdx = 0;

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(
            result.is_some(),
            "AF_NETLINK socket() should return Some(...)"
        );
        assert!(matches!(
            result.unwrap(),
            SyscallKind::RawSocketCreate { domain: 16, .. }
        ));
    }

    /// socket(AF_INET, ...) → None (intercepted at connect/bind instead).
    #[test]
    fn classify_socket_af_inet_returns_none() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::SOCKET as u64;
        regs.rdi = 2; // AF_INET
        regs.rsi = 1; // SOCK_STREAM
        regs.rdx = 0; // protocol

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(
            result.is_none(),
            "AF_INET socket() should return None (handled at connect/bind), got {result:?}"
        );
    }

    /// socket(AF_INET6, ...) → None.
    #[test]
    fn classify_socket_af_inet6_returns_none() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::SOCKET as u64;
        regs.rdi = 10; // AF_INET6
        regs.rsi = 2; // SOCK_DGRAM
        regs.rdx = 0;

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(
            result.is_none(),
            "AF_INET6 socket() should return None, got {result:?}"
        );
    }

    /// socket(AF_UNIX, ...) → None.
    #[test]
    fn classify_socket_af_unix_returns_none() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::SOCKET as u64;
        regs.rdi = 1; // AF_UNIX
        regs.rsi = 1; // SOCK_STREAM
        regs.rdx = 0;

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(
            result.is_none(),
            "AF_UNIX socket() should return None, got {result:?}"
        );
    }
}
