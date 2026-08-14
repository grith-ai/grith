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
                // O_NOFOLLOW makes the kernel refuse to follow a final-
                // component symlink (it returns ELOOP), so scoring the
                // target would be a false read of a file that was never
                // opened. Resolve the link itself in that case.
                let path = if Self::open_is_nofollow(regs.rsi) {
                    Self::canonicalize_for_tracee_nofollow(pid_u32, &path)
                } else {
                    Self::canonicalize_for_tracee(pid_u32, &path)
                };
                let flags = Self::decode_open_flags(regs.rsi);
                Ok(Some(SyscallKind::FileOpen { path, flags }))
            }
            syscall_nr::OPENAT => {
                // openat(dirfd, pathname, flags, mode)
                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let dirfd = regs.rdi as i32;
                let path = if Self::open_is_nofollow(regs.rdx) {
                    Self::resolve_at_path_nofollow(pid_u32, dirfd, &raw_path)
                } else {
                    Self::resolve_at_path(pid_u32, dirfd, &raw_path)
                };
                let flags = Self::decode_open_flags(regs.rdx);
                Ok(Some(SyscallKind::FileOpen { path, flags }))
            }
            syscall_nr::OPENAT2 => {
                // openat2(dirfd, pathname, how, size)
                //
                // `how` is a `struct open_how { __u64 flags, mode, resolve }`
                // in tracee memory rather than a register, so both the flags
                // and the resolution mode have to be read from the tracee.
                //
                // The kernel rejects `size < sizeof(struct open_how)` with
                // EINVAL, so a short struct never reaches the filesystem;
                // treating it as a read-only open of nothing is harmless and
                // keeps a bad pointer from being dereferenced.
                //
                // The `resolve` field is deliberately NOT used to decide how
                // the path is interpreted. It lives in tracee-writable memory,
                // so a sibling thread — never ptrace-stopped, since only the
                // calling thread stops at syscall-entry — can flip it between
                // this read and the kernel's own copy (measured: a ~5ms flip
                // inside a 30ms evaluation window). An earlier version that
                // stripped the leading "/" under RESOLVE_IN_ROOT turned this
                // TOCTOU into a working path DOWNGRADE: grith scored the
                // sandbox-confined path while the kernel, after the flip,
                // opened the real absolute path.
                //
                // Instead grith always scores the WORST-CASE interpretation —
                // the path as absolute (unconfined). If the open really is
                // confined by RESOLVE_IN_ROOT/BENEATH, scoring the absolute
                // path only over-restricts a benign confined open (fail-safe);
                // if it is NOT confined, grith scored exactly what the kernel
                // opens. Whichever the kernel does, grith saw the dangerous
                // reading.
                //
                // The kernel rejects `size < sizeof(struct open_how)` with
                // EINVAL, so a short struct never opens anything; treating it
                // as a read-only open of nothing keeps a bad pointer from
                // being dereferenced.
                const OPEN_HOW_SIZE: u64 = 24;

                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let dirfd = regs.rdi as i32;
                let how_ptr = regs.rdx;
                let size = regs.r10;

                let flags = if how_ptr == 0 || size < OPEN_HOW_SIZE {
                    OpenFlags::ReadOnly
                } else {
                    // Fail closed: an unreadable open_how flags word is an
                    // unclassifiable syscall, and the caller denies on Err.
                    let raw_flags = ptrace::read(pid, how_ptr as *mut libc::c_void)
                        .map(|w| w as u64)
                        .map_err(|e| {
                            Error::InterceptionError(format!(
                                "failed to read open_how at {how_ptr:#x} for pid {pid}: {e}"
                            ))
                        })?;
                    Self::decode_open_flags(raw_flags)
                };

                // `resolve_at_path` treats an absolute path as absolute — the
                // worst case — exactly as intended.
                let path = Self::resolve_at_path(pid_u32, dirfd, &raw_path);
                Ok(Some(SyscallKind::FileOpen { path, flags }))
            }
            syscall_nr::RMDIR => {
                // rmdir(pathname) — the legacy directory removal. Its
                // numeric neighbours were added for B2; leaving this out
                // would have left the same class of gap one syscall over.
                //
                // rmdir does NOT follow a final symlink — it acts on the name
                // itself and returns ENOTDIR for a symlink — so it uses the
                // no-follow resolver like unlink/rename. Following would
                // report a delete of the symlink's target for a syscall the
                // kernel refuses.
                let path = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let path = Self::canonicalize_for_tracee_nofollow(pid_u32, &path);
                Ok(Some(SyscallKind::FileDelete { path }))
            }
            syscall_nr::CREAT => {
                // creat(pathname, mode) == open(path, O_CREAT|O_WRONLY|O_TRUNC)
                let path = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let path = Self::canonicalize_for_tracee(pid_u32, &path);
                Ok(Some(SyscallKind::FileOpen {
                    path,
                    flags: OpenFlags::Truncate,
                }))
            }

            // ---------------------------------------------------------------
            // Truncation — destructive writes that never pass through
            // open()/write().
            // ---------------------------------------------------------------
            syscall_nr::TRUNCATE => {
                // truncate(pathname, length)
                let path = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let path = Self::canonicalize_for_tracee(pid_u32, &path);
                Ok(Some(SyscallKind::FileWrite {
                    fd: -1,
                    path: Some(path),
                }))
            }
            syscall_nr::FTRUNCATE => {
                // ftruncate(fd, length)
                //
                // ftruncate is its own control point — unlike write(2), there
                // is no earlier open to have scored the fd — so an
                // unresolvable path must NOT vanish. `FileWrite{path: None}`
                // maps to noise (allow-and-forget); a `<fd:N>` placeholder
                // keeps the destructive resize visible and audited, as fchmod
                // already does for an unresolvable fd.
                let fd = regs.rdi as i32;
                let path = Some(
                    Self::resolve_fd_path(pid_u32, fd).unwrap_or_else(|| format!("<fd:{fd}>")),
                );
                Ok(Some(SyscallKind::FileWrite { fd, path }))
            }

            // ---------------------------------------------------------------
            // Link creation — scored by target (see SyscallKind::FileLink)
            // ---------------------------------------------------------------
            syscall_nr::SYMLINK => {
                // symlink(target, linkpath)
                let target = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let link_raw = self.read_tracee_string(pid, regs.rsi, 4096)?;
                Ok(Some(SyscallKind::FileLink {
                    // Resolve the target the way a later open of the link
                    // will: fully, including any symlink chain. A symlink
                    // target is stored verbatim and resolved relative to the
                    // link's own directory at traversal time, so this is
                    // exact for absolute targets and for the common
                    // cwd-relative case.
                    target: Self::canonicalize_for_tracee(pid_u32, &target),
                    // The new name does not exist yet and is not followed.
                    link_path: Self::canonicalize_for_tracee_nofollow(pid_u32, &link_raw),
                    symbolic: true,
                }))
            }
            syscall_nr::SYMLINKAT => {
                // symlinkat(target, newdirfd, linkpath)
                let target = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let link_raw = self.read_tracee_string(pid, regs.rdx, 4096)?;
                let newdirfd = regs.rsi as i32;
                Ok(Some(SyscallKind::FileLink {
                    target: Self::canonicalize_for_tracee(pid_u32, &target),
                    link_path: Self::resolve_at_path_nofollow(pid_u32, newdirfd, &link_raw),
                    symbolic: true,
                }))
            }
            syscall_nr::LINK => {
                // link(oldpath, newpath) — Linux does not follow oldpath, so
                // the hard link is created against the link itself. Report
                // what the kernel will act on.
                let target = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let link_raw = self.read_tracee_string(pid, regs.rsi, 4096)?;
                Ok(Some(SyscallKind::FileLink {
                    target: Self::canonicalize_for_tracee_nofollow(pid_u32, &target),
                    link_path: Self::canonicalize_for_tracee_nofollow(pid_u32, &link_raw),
                    symbolic: false,
                }))
            }
            syscall_nr::LINKAT => {
                // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
                //
                // AT_SYMLINK_FOLLOW (0x400) in `flags` makes linkat resolve
                // oldpath, which is how a hard link to a symlink's *target*
                // is created — score what the kernel will link to.
                let target_raw = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let link_raw = self.read_tracee_string(pid, regs.r10, 4096)?;
                let olddirfd = regs.rdi as i32;
                let newdirfd = regs.rdx as i32;
                let follow = regs.r8 as i32 & libc::AT_SYMLINK_FOLLOW != 0;
                let target = if follow {
                    Self::resolve_at_path(pid_u32, olddirfd, &target_raw)
                } else {
                    Self::resolve_at_path_nofollow(pid_u32, olddirfd, &target_raw)
                };
                Ok(Some(SyscallKind::FileLink {
                    target,
                    link_path: Self::resolve_at_path_nofollow(pid_u32, newdirfd, &link_raw),
                    symbolic: false,
                }))
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
                // unlink(pathname) — removes the link, never its target.
                let path = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let path = Self::canonicalize_for_tracee_nofollow(pid_u32, &path);
                Ok(Some(SyscallKind::FileDelete { path }))
            }
            syscall_nr::UNLINKAT => {
                // unlinkat(dirfd, pathname, flags)
                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let dirfd = regs.rdi as i32;
                let path = Self::resolve_at_path_nofollow(pid_u32, dirfd, &raw_path);
                Ok(Some(SyscallKind::FileDelete { path }))
            }

            // ---------------------------------------------------------------
            // File rename
            // ---------------------------------------------------------------
            syscall_nr::RENAME => {
                // rename(oldpath, newpath)
                let old_path = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let new_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                // rename operates on the links themselves.
                let old_path = Self::canonicalize_for_tracee_nofollow(pid_u32, &old_path);
                let new_path = Self::canonicalize_for_tracee_nofollow(pid_u32, &new_path);
                Ok(Some(SyscallKind::FileRename { old_path, new_path }))
            }
            syscall_nr::RENAMEAT => {
                // renameat(olddirfd, oldpath, newdirfd, newpath)
                let old_raw = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let new_raw = self.read_tracee_string(pid, regs.r10, 4096)?;
                let old_dirfd = regs.rdi as i32;
                let new_dirfd = regs.rdx as i32;
                let old_path = Self::resolve_at_path_nofollow(pid_u32, old_dirfd, &old_raw);
                let new_path = Self::resolve_at_path_nofollow(pid_u32, new_dirfd, &new_raw);
                Ok(Some(SyscallKind::FileRename { old_path, new_path }))
            }
            syscall_nr::RENAMEAT2 => {
                // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
                let old_raw = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let new_raw = self.read_tracee_string(pid, regs.r10, 4096)?;
                let old_dirfd = regs.rdi as i32;
                let new_dirfd = regs.rdx as i32;
                let old_path = Self::resolve_at_path_nofollow(pid_u32, old_dirfd, &old_raw);
                let new_path = Self::resolve_at_path_nofollow(pid_u32, new_dirfd, &new_raw);
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
            syscall_nr::FCHMOD => {
                // fchmod(fd, mode)
                let fd = regs.rdi as i32;
                let path =
                    Self::resolve_fd_path(pid_u32, fd).unwrap_or_else(|| format!("<fd:{fd}>"));
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
            syscall_nr::FORK | syscall_nr::CLONE | syscall_nr::CLONE3 => {
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
                let sockaddr_ptr = regs.rsi;
                let addrlen = regs.rdx as u32;
                match self.read_sockaddr(
                    pid,
                    sockaddr_ptr,
                    addrlen as usize,
                    Some((pid_u32, sockfd)),
                )? {
                    Some((address, port, protocol)) => Ok(Some(SyscallKind::NetBind {
                        address,
                        port,
                        protocol,
                        // PR 5 Phase D: forward the tracee-side
                        // sockaddr pointer so the supervisor's
                        // allow path can clamp the bind to loopback
                        // when the profile authorises it.
                        sockaddr_ptr: Some(sockaddr_ptr),
                        addrlen: Some(addrlen),
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

            // recvfrom is handled specially by the interceptor loop: on a
            // tracked DNS socket it is promoted to catch its syscall-exit so the
            // kernel-filled response buffer can be read for the DNS cache. Here
            // (and for any non-DNS recvfrom) it is noise → immediately resumed.
            syscall_nr::RECVFROM | syscall_nr::RECVMSG | syscall_nr::RECVMMSG => Ok(None),

            // sendmsg/sendmmsg on a DNS or connected socket are handled in the
            // interceptor loop before classify is reached. What reaches here
            // is an UNCONNECTED send, and its `msg_name` is an explicit
            // destination exactly like sendto's `dest_addr` — scoring sendto
            // but not these left a one-syscall exfiltration path (go-live
            // review round 2). A send with no `msg_name` (msg_namelen == 0)
            // stays noise.
            //
            // sendmsg: rsi = *msghdr. sendmmsg: rsi = *mmsghdr[], and mmsghdr
            // begins with its msghdr, so the first message's header is at the
            // same offset — reading the first message covers the common
            // single-message case (a full batch scan would be unbounded
            // PEEKDATA on the hot path; documented residual).
            syscall_nr::SENDMSG | syscall_nr::SENDMMSG => {
                match self.read_msghdr_destination(pid, regs.rsi)? {
                    Some((address, port)) => Ok(Some(SyscallKind::NetSendTo { address, port })),
                    None => Ok(None),
                }
            }

            // Socket FD lifecycle is consumed by the DNS socket tracker in
            // events.rs. It is security-relevant only for maintaining exact
            // attribution state and does not produce a policy event itself.
            syscall_nr::CLOSE
            | syscall_nr::CLOSE_RANGE
            | syscall_nr::DUP
            | syscall_nr::DUP2
            | syscall_nr::DUP3
            | syscall_nr::FCNTL => Ok(None),

            // ---------------------------------------------------------------
            // Raw socket creation
            //
            // socket(domain, type, protocol) is intercepted only for raw-socket
            // families. AF_PACKET (17) provides direct link-layer access —
            // a process with this socket can capture or inject arbitrary frames,
            // bypassing the normal IP stack. AF_NETLINK (16) gives kernel
            // subsystem access — but its routine NETLINK_ROUTE family is allowed
            // (see below); the less-common netlink families stay denied.
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
                const NETLINK_ROUTE: i32 = 0;
                // AF_PACKET can capture/inject raw ethernet frames — always a
                // hard-deny. AF_NETLINK gives kernel-subsystem access, but the
                // NETLINK_ROUTE family (protocol 0) is routine: glibc opens it on
                // every getaddrinfo()/getifaddrs() to enumerate interfaces and
                // pick source addresses, so denying it breaks ordinary DNS /
                // networking (and floods the audit). Allow NETLINK_ROUTE; keep
                // the deny for AF_PACKET and the less-common netlink families
                // (netfilter, xfrm, …) an AI tool has no routine reason to open.
                if domain == AF_PACKET || (domain == AF_NETLINK && protocol != NETLINK_ROUTE) {
                    Ok(Some(SyscallKind::RawSocketCreate {
                        domain,
                        socket_type,
                        protocol,
                    }))
                } else {
                    // AF_INET, AF_INET6, AF_UNIX (evaluated at connect/bind) and
                    // AF_NETLINK/NETLINK_ROUTE (routine interface enumeration).
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
            // Self-filter install (go-live review round 2).
            //
            // A tracee that installs its own seccomp filter can out-rank
            // grith's SECCOMP_RET_TRACE. Both the op and the flags are in
            // registers, so this decision cannot be raced by a sibling thread
            // the way an openat2 open_how can.
            // ---------------------------------------------------------------
            syscall_nr::SECCOMP => {
                // seccomp(op, flags, args) — rdi=op, rsi=flags.
                const SECCOMP_SET_MODE_FILTER: u64 = 1;
                const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 1 << 3;
                if regs.rdi != SECCOMP_SET_MODE_FILTER {
                    // SET_MODE_STRICT / GET_ACTION_AVAIL / GET_NOTIF_SIZES —
                    // none can hide syscalls from grith.
                    return Ok(None);
                }
                Ok(Some(SyscallKind::SeccompInstall {
                    via: crate::interceptor::SeccompInstallVia::Seccomp,
                    new_listener: regs.rsi & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0,
                }))
            }
            syscall_nr::PRCTL => {
                // prctl(option, arg2, ...) — rdi=option, rsi=arg2.
                // Only PR_SET_SECCOMP(SECCOMP_MODE_FILTER) installs a filter;
                // it has no flags argument, so it can never create a listener.
                const PR_SET_SECCOMP: u64 = 22;
                const SECCOMP_MODE_FILTER: u64 = 2;
                if regs.rdi != PR_SET_SECCOMP || regs.rsi != SECCOMP_MODE_FILTER {
                    return Ok(None);
                }
                Ok(Some(SyscallKind::SeccompInstall {
                    via: crate::interceptor::SeccompInstallVia::Prctl,
                    new_listener: false,
                }))
            }

            // ---------------------------------------------------------------
            // PR 6 Phase A: kernel-module load/unload — hard-denied
            // ---------------------------------------------------------------
            syscall_nr::INIT_MODULE => Ok(Some(SyscallKind::KernelModuleOp {
                op: crate::interceptor::KernelModuleOpKind::Init,
            })),
            syscall_nr::FINIT_MODULE => Ok(Some(SyscallKind::KernelModuleOp {
                op: crate::interceptor::KernelModuleOpKind::Finit,
            })),
            syscall_nr::DELETE_MODULE => Ok(Some(SyscallKind::KernelModuleOp {
                op: crate::interceptor::KernelModuleOpKind::Delete,
            })),

            // ---------------------------------------------------------------
            // PR 6 Phase A: kernel-image replacement — hard-denied
            // ---------------------------------------------------------------
            syscall_nr::KEXEC_LOAD => Ok(Some(SyscallKind::KexecLoad { from_fd: false })),
            syscall_nr::KEXEC_FILE_LOAD => Ok(Some(SyscallKind::KexecLoad { from_fd: true })),

            // ---------------------------------------------------------------
            // PR 6 Phase B: ownership change family.
            //
            // chown/lchown(path, uid, gid)        — rdi=path, rsi=uid, rdx=gid
            // fchown(fd, uid, gid)                — rdi=fd,   rsi=uid, rdx=gid
            // fchownat(dirfd, path, uid, gid, ..) — rdi=dirfd, rsi=path, rdx=uid, r10=gid
            // ---------------------------------------------------------------
            syscall_nr::CHOWN | syscall_nr::LCHOWN => {
                let raw = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let is_chown = regs.orig_rax as i64 == syscall_nr::CHOWN;
                // `chown` follows the final symlink; `lchown` deliberately
                // does not — it changes the link itself. Resolving lchown's
                // final component would report an ownership change on a file
                // the kernel never touches: the same mis-attribution this
                // change argues against for unlink and rename.
                let path = if is_chown {
                    Self::canonicalize_for_tracee(pid_u32, &raw)
                } else {
                    Self::canonicalize_for_tracee_nofollow(pid_u32, &raw)
                };
                Ok(Some(SyscallKind::OwnershipChange {
                    op: if is_chown {
                        crate::interceptor::OwnershipOp::Chown
                    } else {
                        crate::interceptor::OwnershipOp::Lchown
                    },
                    path,
                    new_uid: regs.rsi as i64,
                    new_gid: regs.rdx as i64,
                }))
            }
            syscall_nr::FCHOWN => {
                let fd = regs.rdi as i32;
                let path =
                    Self::resolve_fd_path(pid_u32, fd).unwrap_or_else(|| format!("<fd:{fd}>"));
                Ok(Some(SyscallKind::OwnershipChange {
                    op: crate::interceptor::OwnershipOp::Fchown,
                    path,
                    new_uid: regs.rsi as i64,
                    new_gid: regs.rdx as i64,
                }))
            }
            syscall_nr::FCHOWNAT => {
                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let dirfd = regs.rdi as i32;
                // AT_SYMLINK_NOFOLLOW (0x100) in `flags` (r8) makes fchownat
                // act on the link rather than its target, exactly like lchown.
                let follows = regs.r8 as i32 & libc::AT_SYMLINK_NOFOLLOW == 0;
                let path = if follows {
                    Self::resolve_at_path(pid_u32, dirfd, &raw_path)
                } else {
                    Self::resolve_at_path_nofollow(pid_u32, dirfd, &raw_path)
                };
                Ok(Some(SyscallKind::OwnershipChange {
                    op: crate::interceptor::OwnershipOp::Fchownat,
                    path,
                    new_uid: regs.rdx as i64,
                    new_gid: regs.r10 as i64,
                }))
            }

            // ---------------------------------------------------------------
            // PR 6 Phase B: filesystem mutation.
            //
            // mount(src, target, fstype, flags, data) — rdi=src, rsi=target, rdx=fstype
            // umount2(target, flags)                  — rdi=target
            // pivot_root(new_root, put_old)           — rdi=new_root, rsi=put_old
            // chroot(path)                            — rdi=path
            // open_tree(dfd, filename, flags)         — rdi=dfd, rsi=filename
            // move_mount(from_dfd, from, to_dfd, to)  — rdi/rsi, rdx/r10
            // fsopen/fsconfig/fsmount                 — fd/context-based mount API
            // fspick(dfd, path, flags)                — rdi=dfd, rsi=path
            // mount_setattr(dfd, path, flags, ...)    — rdi=dfd, rsi=path
            // ---------------------------------------------------------------
            syscall_nr::MOUNT => {
                let source = self.read_tracee_string(pid, regs.rdi, 4096).ok();
                let target = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let target = Self::canonicalize_for_tracee(pid_u32, &target);
                let fstype = self.read_tracee_string(pid, regs.rdx, 256).ok();
                Ok(Some(SyscallKind::FilesystemMutation {
                    op: crate::interceptor::FsMutationOp::Mount,
                    source,
                    target,
                    fstype,
                }))
            }
            syscall_nr::UMOUNT2 => {
                let target = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let target = Self::canonicalize_for_tracee(pid_u32, &target);
                Ok(Some(SyscallKind::FilesystemMutation {
                    op: crate::interceptor::FsMutationOp::Umount2,
                    source: None,
                    target,
                    fstype: None,
                }))
            }
            syscall_nr::PIVOT_ROOT => {
                let target = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let target = Self::canonicalize_for_tracee(pid_u32, &target);
                Ok(Some(SyscallKind::FilesystemMutation {
                    op: crate::interceptor::FsMutationOp::PivotRoot,
                    source: None,
                    target,
                    fstype: None,
                }))
            }
            syscall_nr::CHROOT => {
                let target = self.read_tracee_string(pid, regs.rdi, 4096)?;
                let target = Self::canonicalize_for_tracee(pid_u32, &target);
                Ok(Some(SyscallKind::FilesystemMutation {
                    op: crate::interceptor::FsMutationOp::Chroot,
                    source: None,
                    target,
                    fstype: None,
                }))
            }
            syscall_nr::OPEN_TREE => {
                let dirfd = regs.rdi as i32;
                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let target = Self::resolve_at_path(pid_u32, dirfd, &raw_path);
                Ok(Some(SyscallKind::FilesystemMutation {
                    op: crate::interceptor::FsMutationOp::OpenTree,
                    source: None,
                    target,
                    fstype: None,
                }))
            }
            syscall_nr::MOVE_MOUNT => {
                let from_dfd = regs.rdi as i32;
                let raw_from = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let to_dfd = regs.rdx as i32;
                let raw_to = self.read_tracee_string(pid, regs.r10, 4096)?;
                let source = if raw_from.is_empty() {
                    Some(format!("<fd:{from_dfd}>"))
                } else {
                    Some(Self::resolve_at_path(pid_u32, from_dfd, &raw_from))
                };
                let target = if raw_to.is_empty() {
                    format!("<fd:{to_dfd}>")
                } else {
                    Self::resolve_at_path(pid_u32, to_dfd, &raw_to)
                };
                Ok(Some(SyscallKind::FilesystemMutation {
                    op: crate::interceptor::FsMutationOp::MoveMount,
                    source,
                    target,
                    fstype: None,
                }))
            }
            syscall_nr::FSOPEN => {
                let fs_name = self.read_tracee_string(pid, regs.rdi, 256)?;
                Ok(Some(SyscallKind::FilesystemMutation {
                    op: crate::interceptor::FsMutationOp::Fsopen,
                    source: None,
                    target: "<fsopen>".into(),
                    fstype: if fs_name.is_empty() {
                        None
                    } else {
                        Some(fs_name)
                    },
                }))
            }
            syscall_nr::FSCONFIG => {
                let fd = regs.rdi as i32;
                let key = self.read_tracee_string(pid, regs.rdx, 256).ok();
                Ok(Some(SyscallKind::FilesystemMutation {
                    op: crate::interceptor::FsMutationOp::Fsconfig,
                    source: None,
                    target: format!("<fsconfig:{fd}>"),
                    fstype: key,
                }))
            }
            syscall_nr::FSMOUNT => {
                let fd = regs.rdi as i32;
                Ok(Some(SyscallKind::FilesystemMutation {
                    op: crate::interceptor::FsMutationOp::Fsmount,
                    source: None,
                    target: format!("<fsmount:{fd}>"),
                    fstype: None,
                }))
            }
            syscall_nr::FSPICK => {
                let dirfd = regs.rdi as i32;
                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let target = Self::resolve_at_path(pid_u32, dirfd, &raw_path);
                Ok(Some(SyscallKind::FilesystemMutation {
                    op: crate::interceptor::FsMutationOp::Fspick,
                    source: None,
                    target,
                    fstype: None,
                }))
            }
            syscall_nr::MOUNT_SETATTR => {
                let dirfd = regs.rdi as i32;
                let raw_path = self.read_tracee_string(pid, regs.rsi, 4096)?;
                let target = Self::resolve_at_path(pid_u32, dirfd, &raw_path);
                Ok(Some(SyscallKind::FilesystemMutation {
                    op: crate::interceptor::FsMutationOp::MountSetattr,
                    source: None,
                    target,
                    fstype: None,
                }))
            }

            // ---------------------------------------------------------------
            // PR 6 Phase B: cross-process access.
            //
            // ptrace(request, pid, addr, data)              — rsi=target_pid
            // process_vm_readv(pid, ...)                    — rdi=target_pid
            // process_vm_writev(pid, ...)                   — rdi=target_pid
            //
            // Self-target carveout: process_vm_* against the caller's
            // own pid is benign (used by some allocators for memory
            // copying); filter it out so we don't QUEUE the
            // supervised tool's own internal use.
            //
            // PTRACE_TRACEME carveout: `ptrace(PTRACE_TRACEME)` has
            // request(rdi) == 0 and reads no other process's memory —
            // the caller merely volunteers to be traced by its own
            // parent (crash handlers, fork/trace/exec test harnesses).
            // It grants no cross-process authority and would EPERM under
            // grith anyway (grith already holds the tracer slot), so we
            // carve it out. Note we key on the request (rdi == 0), NOT
            // the pid argument (rsi), which TRACEME leaves as 0.
            // ---------------------------------------------------------------
            syscall_nr::PTRACE => {
                if regs.rdi == 0 {
                    return Ok(None);
                }
                Ok(Some(SyscallKind::CrossProcessAccess {
                    op: crate::interceptor::CrossProcessOp::Ptrace,
                    target_pid: regs.rsi as u32,
                }))
            }
            syscall_nr::PROCESS_VM_READV => {
                let target = regs.rdi as u32;
                if target == pid_u32 {
                    return Ok(None);
                }
                Ok(Some(SyscallKind::CrossProcessAccess {
                    op: crate::interceptor::CrossProcessOp::ProcessVmReadv,
                    target_pid: target,
                }))
            }
            syscall_nr::PROCESS_VM_WRITEV => {
                let target = regs.rdi as u32;
                if target == pid_u32 {
                    return Ok(None);
                }
                Ok(Some(SyscallKind::CrossProcessAccess {
                    op: crate::interceptor::CrossProcessOp::ProcessVmWritev,
                    target_pid: target,
                }))
            }

            // ---------------------------------------------------------------
            // PR 6 Phase C: namespace primitives.
            //
            // unshare(flags)   — rdi = CLONE_NEW* bitmap
            // setns(fd, nstype) — rdi = fd, rsi = nstype (CLONE_NEW* bit
            //                     or 0 to defer to the fd's link)
            //
            // We always emit `NamespaceOp` regardless of which flag
            // bits are set; the supervisor's bwrap-carveout in
            // `event_handler.rs` does the per-bit check against the
            // profile's namespace_users list. Reporting *every*
            // `unshare`/`setns` keeps the audit log honest — even a
            // call with `flags = 0` is worth logging since it shows
            // the tool was probing.
            // ---------------------------------------------------------------
            syscall_nr::UNSHARE => Ok(Some(SyscallKind::NamespaceOp {
                syscall: crate::interceptor::NamespaceSyscall::Unshare,
                flags: regs.rdi,
            })),
            syscall_nr::SETNS => Ok(Some(SyscallKind::NamespaceOp {
                syscall: crate::interceptor::NamespaceSyscall::Setns,
                flags: regs.rsi,
            })),

            // ---------------------------------------------------------------
            // PR 6 Phase D: architecture-specific privileged ops.
            // Hard-denied unconditionally in event_handler.rs. We don't
            // bother extracting arguments; the audit record carries the
            // syscall identity, which is sufficient for forensics.
            // ---------------------------------------------------------------
            syscall_nr::SETHOSTNAME => Ok(Some(SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::SetHostname,
            })),
            syscall_nr::SETDOMAINNAME => Ok(Some(SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::SetDomainName,
            })),
            syscall_nr::IOPL => Ok(Some(SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::Iopl,
            })),
            syscall_nr::IOPERM => Ok(Some(SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::Ioperm,
            })),
            syscall_nr::SWAPON => Ok(Some(SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::Swapon,
            })),
            syscall_nr::SWAPOFF => Ok(Some(SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::Swapoff,
            })),
            syscall_nr::REBOOT => Ok(Some(SyscallKind::ArchPrivilegedOp {
                op: crate::interceptor::ArchPrivOp::Reboot,
            })),

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
            // off-host, so it fits the "kernel-internal, no exfil → allow"
            // contract above. glibc bind()s + sendto()s a NETLINK_ROUTE socket
            // on every getaddrinfo()/getifaddrs(); treating that bind as a
            // network "listener" (egress-policy +7.0) breaks DNS / interface
            // enumeration. Route/firewall *mutation* needs CAP_NET_ADMIN, which
            // a non-root supervised tool lacks, and the socket() classifier
            // still denies AF_PACKET and non-route netlink families.
            libc::AF_NETLINK => None,
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
    /// - `AF_PACKET` -- returns a `raw:af_packet` address so the proxy can
    ///   score and potentially deny the operation.
    /// - `AF_NETLINK` -- `None` (allowed): kernel↔userspace messaging, cannot
    ///   exfiltrate off-host; glibc uses it for getaddrinfo/getifaddrs.
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
                let ip = sockaddr_in_to_string([bytes0[4], bytes0[5], bytes0[6], bytes0[7]]);
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
                // PR 5 Phase A: see `sockaddr_in6_to_string` for the canonical
                // form contract (zero-compressed `::`, `::1`,
                // `::ffff:127.0.0.1`).
                let ip = sockaddr_in6_to_string(b1, b2);
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
    ///
    /// The result is then fully resolved (`..`, `.` and symlinks, including
    /// the final component) because the overwhelming majority of callers are
    /// syscalls that follow the final symlink. Arms that operate on the link
    /// itself — delete, rename, and a new link's name — must call
    /// [`canonicalize_for_tracee_nofollow`](Self::canonicalize_for_tracee_nofollow)
    /// instead. Defaulting to the stronger resolution means an arm added
    /// later without thinking about symlinks still gets protection.
    pub(super) fn canonicalize_for_tracee(pid: u32, path: &str) -> String {
        Self::resolve_follow(&Self::absolutise_for_tracee(pid, path))
    }

    /// As [`canonicalize_for_tracee`](Self::canonicalize_for_tracee) but
    /// leaves the final component unresolved — for syscalls that act on the
    /// link rather than its target.
    pub(super) fn canonicalize_for_tracee_nofollow(pid: u32, path: &str) -> String {
        Self::resolve_nofollow(&Self::absolutise_for_tracee(pid, path))
    }

    /// Make `path` absolute against the tracee's cwd, without resolving
    /// symlinks or `..`.
    fn absolutise_for_tracee(pid: u32, path: &str) -> String {
        if path.starts_with('/') {
            return path.to_string();
        }
        match Self::resolve_cwd(pid) {
            Some(cwd) => cwd.join(path).to_string_lossy().into_owned(),
            None => path.to_string(),
        }
    }

    /// True for paths whose resolution is pointless or actively wrong.
    ///
    /// `/proc` entries are per-process and frequently magic symlinks whose
    /// targets are meaningless to a filter (`/proc/self/fd/3` →
    /// `socket:[12345]`), and `/proc/self` resolved in the *supervisor*
    /// would name the supervisor, not the tracee. `/sys` and `/dev` are
    /// high-traffic pseudo-filesystems where the lstat walk buys nothing.
    fn skip_resolution(path: &str) -> bool {
        // A path with a `..` component is NOT skipped even under /proc, /sys
        // or /dev: `truncate("/proc/self/../../home/u/.ssh/id_rsa")` escapes
        // the pseudo-filesystem, and because `is_noise_path` treats anything
        // under `/proc/` as noise, skipping resolution would auto-allow the
        // laundered real target with no evaluation (proven: a private key
        // destroyed through the /proc noise exemption). Resolving collapses
        // the `..` and reveals the target; a genuine /proc access has no
        // `..` and stays skipped so it is not rewritten to the supervisor's
        // own identity.
        if Self::has_parent_traversal(path) {
            return false;
        }
        path.starts_with("/proc/") || path.starts_with("/sys/") || path.starts_with("/dev/")
    }

    /// True when `path` contains a `..` path component.
    fn has_parent_traversal(path: &str) -> bool {
        path.split('/').any(|c| c == "..")
    }

    /// Resolve `..`, `.` and symlinks **including the final component**.
    ///
    /// Used for syscalls that follow the final symlink — the open family,
    /// `truncate`, `chmod`, and a link's *target*. This is what closes the
    /// path-string laundering hole (go-live review B3):
    /// `ln -s ~/.ssh/id_rsa /tmp/x && cat /tmp/x` previously reached the
    /// filters as the literal string `/tmp/x`, matching nothing.
    ///
    /// A path that does not exist yet (an `O_CREAT` open of a new file) is
    /// resolved via its parent so `..` traversal and symlinked parent
    /// directories are still collapsed. If even the parent cannot be
    /// resolved the input is returned unchanged — that is exactly today's
    /// behaviour, so resolution can never score *less* than before.
    ///
    /// Resolution happens in the supervisor's mount namespace. A tracee in
    /// its own namespace (e.g. under `bwrap`) may see a different target;
    /// resolving in ours is strictly better than not resolving, and the
    /// no-follow variant keeps the divergence from mis-attributing deletes.
    pub(super) fn resolve_follow(path: &str) -> String {
        if Self::skip_resolution(path) {
            return path.to_string();
        }
        let resolved = match std::fs::canonicalize(path) {
            Ok(resolved) => resolved.to_string_lossy().into_owned(),
            Err(_) => Self::resolve_parent_only(path),
        };
        Self::post_resolve(path, resolved)
    }

    /// Resolve `..`, `.` and symlinks in the **parent directories only**,
    /// leaving the final component as written.
    ///
    /// Used for syscalls that operate on the link itself rather than what it
    /// points at: `unlink`/`unlinkat`, `rename`, and the *new name* of a
    /// link being created. Resolving the final component here would be a
    /// mis-attribution — `rm /tmp/x` where `/tmp/x -> ~/.ssh/id_rsa` deletes
    /// the link, not the key, and reporting it as a delete of the key would
    /// be both a false positive and a false audit record.
    pub(super) fn resolve_nofollow(path: &str) -> String {
        if Self::skip_resolution(path) {
            return path.to_string();
        }
        Self::post_resolve(path, Self::resolve_parent_only(path))
    }

    /// Common post-processing for a resolved path.
    ///
    /// * **Trailing slash** — `canonicalize` drops it, but a tracee that
    ///   opened `~/.ssh/` (an `O_DIRECTORY` open) means the directory, and the
    ///   credential-directory rules match on `"/.ssh/"` *with* the slash. Drop
    ///   it and the read is auto-allowed as noise. Re-append it so the
    ///   resolved form still matches.
    /// * **Result inside `/proc`** — resolving in the supervisor's own process
    ///   turns a `/proc/self/*` symlink into the *supervisor's* identity
    ///   (`/etc/mtab` → `/proc/<supervisor-pid>/mounts`), which would attribute
    ///   the supervisor's `/proc/<pid>/environ`/`mem` to the tracee. If
    ///   resolution lands in `/proc` and the input did not, keep the input.
    fn post_resolve(input: &str, resolved: String) -> String {
        let mut resolved = resolved;
        if resolved.starts_with("/proc/") && !input.starts_with("/proc/") {
            return input.to_string();
        }
        if input.ends_with('/') && !resolved.ends_with('/') {
            resolved.push('/');
        }
        resolved
    }

    /// Canonicalize the parent directory and re-append the final component.
    fn resolve_parent_only(path: &str) -> String {
        // `Path::parent`/`file_name` ignore a trailing slash, so strip it
        // first and restore it via `post_resolve`.
        let trimmed = path.strip_suffix('/').unwrap_or(path);
        let p = std::path::Path::new(trimmed);
        match (p.parent(), p.file_name()) {
            (Some(parent), Some(name)) => match std::fs::canonicalize(parent) {
                Ok(dir) => dir.join(name).to_string_lossy().into_owned(),
                Err(_) => path.to_string(),
            },
            // No parent (the path is `/`) or no final component (a trailing
            // `..`): nothing safe to do beyond what we already have.
            _ => path.to_string(),
        }
    }

    /// Resolve a path argument from a `*at` syscall that takes a `dirfd`.
    ///
    /// The `*at` family of syscalls (openat, unlinkat, mkdirat, fchmodat,
    /// renameat2) interpret their path relative to `dirfd`. If `dirfd` is
    /// `AT_FDCWD` (-100) the path is relative to the process CWD. If the
    /// path is absolute, `dirfd` is ignored entirely.
    ///
    /// Symlink-resolving, like
    /// [`canonicalize_for_tracee`](Self::canonicalize_for_tracee); use
    /// [`resolve_at_path_nofollow`](Self::resolve_at_path_nofollow) for
    /// syscalls that act on the link itself.
    pub(super) fn resolve_at_path(pid: u32, dirfd: i32, raw_path: &str) -> String {
        Self::resolve_follow(&Self::absolutise_at_path(pid, dirfd, raw_path))
    }

    /// As [`resolve_at_path`](Self::resolve_at_path) but leaves the final
    /// component unresolved.
    pub(super) fn resolve_at_path_nofollow(pid: u32, dirfd: i32, raw_path: &str) -> String {
        Self::resolve_nofollow(&Self::absolutise_at_path(pid, dirfd, raw_path))
    }

    /// Make a `*at` path argument absolute, without resolving symlinks.
    fn absolutise_at_path(pid: u32, dirfd: i32, raw_path: &str) -> String {
        if raw_path.starts_with('/') {
            raw_path.to_string()
        } else if dirfd == libc::AT_FDCWD {
            Self::absolutise_for_tracee(pid, raw_path)
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
    /// Read the explicit destination from a `struct msghdr` at `msghdr_ptr`.
    ///
    /// `struct msghdr` on x86_64 begins `void *msg_name; socklen_t
    /// msg_namelen;` — `msg_name` at offset 0, `msg_namelen` at offset 8. A
    /// zero `msg_namelen` (or NULL `msg_name`) means the send carries no
    /// destination — the field must be honoured, or a msghdr reused from
    /// recvmsg with stale bytes yields a fabricated destination scored as
    /// egress. Returns `None` for such sends and for a loopback/empty
    /// destination.
    pub(super) fn read_msghdr_destination(
        &self,
        pid: Pid,
        msghdr_ptr: u64,
    ) -> Result<Option<(String, u16)>> {
        if msghdr_ptr == 0 {
            return Ok(None);
        }
        let name_ptr = ptrace::read(pid, msghdr_ptr as *mut libc::c_void)
            .map(|w| w as u64)
            .unwrap_or(0);
        // msg_namelen is the low 32 bits of the word at offset 8.
        let namelen = ptrace::read(pid, (msghdr_ptr + 8) as *mut libc::c_void)
            .map(|w| (w as u64) as u32)
            .unwrap_or(0);
        if name_ptr == 0 || namelen == 0 {
            return Ok(None);
        }
        match self.read_sockaddr(pid, name_ptr, namelen as usize, None)? {
            Some((address, port, _)) if !address.is_empty() => Ok(Some((address, port))),
            _ => Ok(None),
        }
    }

    /// True when an open's `flags` word requests `O_NOFOLLOW` — the kernel
    /// will refuse to follow a final-component symlink (ELOOP), so grith
    /// should score the link, not its target.
    fn open_is_nofollow(raw: u64) -> bool {
        raw as i32 & libc::O_NOFOLLOW != 0
    }

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
// PR 5 Phase A — sockaddr address-byte → string helpers
// ---------------------------------------------------------------------------
//
// Extracted from `read_sockaddr` so unit tests can drive the byte-pattern
// → string conversion deterministically without a real ptracee.

/// PR 5 Phase A: convert the 4 network-byte-order octets of an
/// `in_addr` into dotted-quad string form. `[0, 0, 0, 0]` →
/// `"0.0.0.0"` (INADDR_ANY); `[127, 0, 0, 1]` → `"127.0.0.1"`
/// (INADDR_LOOPBACK).
pub(super) fn sockaddr_in_to_string(octets: [u8; 4]) -> String {
    std::net::Ipv4Addr::from(octets).to_string()
}

/// PR 5 Phase A: convert the two 8-byte halves of an `in6_addr`
/// (network byte order) into canonical zero-compressed string form.
///
/// Uses `Ipv6Addr::Display` so well-known addresses render canonically:
///   - in6addr_any (all zeros) → `"::"`.
///   - in6addr_loopback (`...:0:0:0:1`) → `"::1"`.
///   - IPv4-mapped (`::ffff:a.b.c.d`) → `"::ffff:a.b.c.d"`.
///
/// The previous implementation produced the expanded form
/// (`"0:0:0:0:0:0:0:1"`) which broke `is_loopback_bind_address`'s
/// literal-string match. PR 5 Phase A unifies on the canonical form.
pub(super) fn sockaddr_in6_to_string(high: [u8; 8], low: [u8; 8]) -> String {
    let mut octets = [0u8; 16];
    octets[..8].copy_from_slice(&high);
    octets[8..].copy_from_slice(&low);
    std::net::Ipv6Addr::from(octets).to_string()
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

    // -- PR 6 Phase A: kernel-module + kexec syscall numbers ----------------

    #[test]
    fn syscall_nr_init_module_is_175() {
        assert_eq!(syscall_nr::INIT_MODULE, 175);
    }

    #[test]
    fn syscall_nr_finit_module_is_313() {
        assert_eq!(syscall_nr::FINIT_MODULE, 313);
    }

    #[test]
    fn syscall_nr_delete_module_is_176() {
        assert_eq!(syscall_nr::DELETE_MODULE, 176);
    }

    #[test]
    fn syscall_nr_kexec_load_is_246() {
        assert_eq!(syscall_nr::KEXEC_LOAD, 246);
    }

    #[test]
    fn syscall_nr_kexec_file_load_is_320() {
        assert_eq!(syscall_nr::KEXEC_FILE_LOAD, 320);
    }

    #[test]
    fn phase_a_kernel_module_syscalls_are_security_relevant() {
        assert!(is_security_relevant(syscall_nr::INIT_MODULE));
        assert!(is_security_relevant(syscall_nr::FINIT_MODULE));
        assert!(is_security_relevant(syscall_nr::DELETE_MODULE));
    }

    #[test]
    fn phase_a_kexec_syscalls_are_security_relevant() {
        assert!(is_security_relevant(syscall_nr::KEXEC_LOAD));
        assert!(is_security_relevant(syscall_nr::KEXEC_FILE_LOAD));
    }

    // -- B2: open/truncate/link family coverage --------------------------
    //
    // Inverted from the go-live review's verification snippet
    // (`work/verification/b1-b2-seccomp-arch-tests.rs.txt`), which asserted
    // every one of these was *absent* from the trap set. Each was a way to
    // reach the filesystem without passing the file policy.

    #[test]
    fn b2_syscall_numbers_are_correct() {
        assert_eq!(syscall_nr::OPENAT2, 437);
        assert_eq!(syscall_nr::CREAT, 85);
        assert_eq!(syscall_nr::TRUNCATE, 76);
        assert_eq!(syscall_nr::FTRUNCATE, 77);
        assert_eq!(syscall_nr::SYMLINK, 88);
        assert_eq!(syscall_nr::SYMLINKAT, 266);
        assert_eq!(syscall_nr::LINK, 86);
        assert_eq!(syscall_nr::LINKAT, 265);
    }

    #[test]
    fn b2_open_truncate_and_link_family_are_security_relevant() {
        for nr in [
            syscall_nr::OPENAT2,
            syscall_nr::CREAT,
            syscall_nr::TRUNCATE,
            syscall_nr::FTRUNCATE,
            syscall_nr::SYMLINK,
            syscall_nr::SYMLINKAT,
            syscall_nr::LINK,
            syscall_nr::LINKAT,
            syscall_nr::RMDIR,
        ] {
            assert!(
                is_security_relevant(nr),
                "syscall {nr} must be intercepted — it reaches the filesystem"
            );
        }
        // Control: openat was already covered.
        assert!(is_security_relevant(syscall_nr::OPENAT));
    }

    // -- PR 6 Phase B: ownership / fs / cross-process syscall numbers ----

    #[test]
    fn syscall_nr_chown_is_92() {
        assert_eq!(syscall_nr::CHOWN, 92);
    }

    #[test]
    fn syscall_nr_fchown_is_93() {
        assert_eq!(syscall_nr::FCHOWN, 93);
    }

    #[test]
    fn syscall_nr_lchown_is_94() {
        assert_eq!(syscall_nr::LCHOWN, 94);
    }

    #[test]
    fn syscall_nr_fchownat_is_260() {
        assert_eq!(syscall_nr::FCHOWNAT, 260);
    }

    #[test]
    fn syscall_nr_fchmod_is_91() {
        assert_eq!(syscall_nr::FCHMOD, 91);
    }

    #[test]
    fn syscall_nr_mount_is_165() {
        assert_eq!(syscall_nr::MOUNT, 165);
    }

    #[test]
    fn syscall_nr_umount2_is_166() {
        assert_eq!(syscall_nr::UMOUNT2, 166);
    }

    #[test]
    fn syscall_nr_pivot_root_is_155() {
        assert_eq!(syscall_nr::PIVOT_ROOT, 155);
    }

    #[test]
    fn syscall_nr_chroot_is_161() {
        assert_eq!(syscall_nr::CHROOT, 161);
    }

    #[test]
    fn syscall_nr_new_mount_api_numbers_are_correct() {
        assert_eq!(syscall_nr::OPEN_TREE, 428);
        assert_eq!(syscall_nr::MOVE_MOUNT, 429);
        assert_eq!(syscall_nr::FSOPEN, 430);
        assert_eq!(syscall_nr::FSCONFIG, 431);
        assert_eq!(syscall_nr::FSMOUNT, 432);
        assert_eq!(syscall_nr::FSPICK, 433);
        assert_eq!(syscall_nr::MOUNT_SETATTR, 442);
    }

    #[test]
    fn syscall_nr_ptrace_is_101() {
        assert_eq!(syscall_nr::PTRACE, 101);
    }

    #[test]
    fn syscall_nr_process_vm_readv_is_310() {
        assert_eq!(syscall_nr::PROCESS_VM_READV, 310);
    }

    #[test]
    fn syscall_nr_process_vm_writev_is_311() {
        assert_eq!(syscall_nr::PROCESS_VM_WRITEV, 311);
    }

    #[test]
    fn phase_b_ownership_syscalls_are_security_relevant() {
        assert!(is_security_relevant(syscall_nr::CHOWN));
        assert!(is_security_relevant(syscall_nr::FCHOWN));
        assert!(is_security_relevant(syscall_nr::LCHOWN));
        assert!(is_security_relevant(syscall_nr::FCHOWNAT));
        assert!(is_security_relevant(syscall_nr::FCHMOD));
    }

    #[test]
    fn phase_b_filesystem_mutation_syscalls_are_security_relevant() {
        assert!(is_security_relevant(syscall_nr::MOUNT));
        assert!(is_security_relevant(syscall_nr::UMOUNT2));
        assert!(is_security_relevant(syscall_nr::PIVOT_ROOT));
        assert!(is_security_relevant(syscall_nr::CHROOT));
        assert!(is_security_relevant(syscall_nr::OPEN_TREE));
        assert!(is_security_relevant(syscall_nr::MOVE_MOUNT));
        assert!(is_security_relevant(syscall_nr::FSOPEN));
        assert!(is_security_relevant(syscall_nr::FSCONFIG));
        assert!(is_security_relevant(syscall_nr::FSMOUNT));
        assert!(is_security_relevant(syscall_nr::FSPICK));
        assert!(is_security_relevant(syscall_nr::MOUNT_SETATTR));
    }

    #[test]
    fn phase_b_cross_process_syscalls_are_security_relevant() {
        assert!(is_security_relevant(syscall_nr::PTRACE));
        assert!(is_security_relevant(syscall_nr::PROCESS_VM_READV));
        assert!(is_security_relevant(syscall_nr::PROCESS_VM_WRITEV));
    }

    // -- PR 6 Phase C: namespace primitive syscall numbers ----

    #[test]
    fn syscall_nr_unshare_is_272() {
        assert_eq!(syscall_nr::UNSHARE, 272);
    }

    #[test]
    fn syscall_nr_setns_is_308() {
        assert_eq!(syscall_nr::SETNS, 308);
    }

    #[test]
    fn phase_c_namespace_syscalls_are_security_relevant() {
        assert!(is_security_relevant(syscall_nr::UNSHARE));
        assert!(is_security_relevant(syscall_nr::SETNS));
    }

    // -- PR 6 Phase D: architecture-specific syscall numbers ----

    #[test]
    fn syscall_nr_sethostname_is_170() {
        assert_eq!(syscall_nr::SETHOSTNAME, 170);
    }

    #[test]
    fn syscall_nr_setdomainname_is_171() {
        assert_eq!(syscall_nr::SETDOMAINNAME, 171);
    }

    #[test]
    fn syscall_nr_iopl_is_172() {
        assert_eq!(syscall_nr::IOPL, 172);
    }

    #[test]
    fn syscall_nr_ioperm_is_173() {
        assert_eq!(syscall_nr::IOPERM, 173);
    }

    #[test]
    fn syscall_nr_swapon_is_167() {
        assert_eq!(syscall_nr::SWAPON, 167);
    }

    #[test]
    fn syscall_nr_swapoff_is_168() {
        assert_eq!(syscall_nr::SWAPOFF, 168);
    }

    #[test]
    fn syscall_nr_reboot_is_169() {
        assert_eq!(syscall_nr::REBOOT, 169);
    }

    #[test]
    fn phase_d_arch_privileged_syscalls_are_security_relevant() {
        assert!(is_security_relevant(syscall_nr::SETHOSTNAME));
        assert!(is_security_relevant(syscall_nr::SETDOMAINNAME));
        assert!(is_security_relevant(syscall_nr::IOPL));
        assert!(is_security_relevant(syscall_nr::IOPERM));
        assert!(is_security_relevant(syscall_nr::SWAPON));
        assert!(is_security_relevant(syscall_nr::SWAPOFF));
        assert!(is_security_relevant(syscall_nr::REBOOT));
    }

    #[test]
    fn phase_c_clone_new_ns_mask_covers_all_namespace_bits() {
        // CLONE_NEWNS (0x00020000), NEWCGROUP (0x02000000),
        // NEWUTS (0x04000000), NEWIPC (0x08000000),
        // NEWUSER (0x10000000), NEWPID (0x20000000), NEWNET (0x40000000)
        let expected: u64 = 0x00020000
            | 0x02000000
            | 0x04000000
            | 0x08000000
            | 0x10000000
            | 0x20000000
            | 0x40000000;
        assert_eq!(crate::platform::linux::CLONE_NEW_NS_MASK, expected);
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
        // read(0), write(1), fstat(5), lseek(8),
        // mprotect(10), brk(12), ioctl(16), access(21), nanosleep(35),
        // exit_group(231).
        // Note: mmap(9) is now security-relevant (file-backed mmaps).
        let innocuous = [0, 1, 5, 8, 10, 12, 16, 21, 35, 100, 200, 231, 500];
        for nr in &innocuous {
            assert!(
                !is_security_relevant(*nr),
                "syscall number {nr} should NOT be classified as security-relevant"
            );
        }
    }

    #[test]
    fn security_relevant_list_has_expected_count() {
        // 63 distinct syscall numbers are tracked:
        //   - 30 from PR 1..5.
        //   - PR 6 Phase A: 5 hard-denied (init/finit/delete_module +
        //     kexec_load/kexec_file_load).
        //   - PR 6 Phase B: 19 proxy-evaluated (4 chown + fchmod + 3
        //     original fs + chroot + 7 new mount-api + 3 cross-process).
        //   - PR 6 Phase C: 2 namespace primitives (unshare, setns).
        //   - PR 6 Phase D: 7 architecture-specific privileged ops
        //     (sethostname, setdomainname, iopl, ioperm, swapon, swapoff,
        //     reboot).
        //   - Go-live review B2: 8 file-family syscalls that reached the
        //     filesystem without passing the file policy (openat2, creat,
        //     truncate, ftruncate, symlink, symlinkat, link, linkat).
        // DNS hardening adds recvmsg/recvmmsg plus six FD-lifecycle forms;
        // clone3 is included so modern thread creation cannot bypass the
        // entry-time FD-table inheritance snapshot.
        assert_eq!(SECURITY_RELEVANT.len(), 86);
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

    // -- B3: symlink / `..` resolution --------------------------------------

    #[test]
    fn resolve_follow_resolves_symlink_to_target() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("id_rsa");
        std::fs::write(&secret, "key").unwrap();
        let link = dir.path().join("notes.txt");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let resolved = PtraceSupervisor::resolve_follow(link.to_str().unwrap());
        assert!(
            resolved.ends_with("id_rsa"),
            "an open through a symlink must be scored on the target, got {resolved}"
        );
    }

    /// The mis-attribution guard: `rm /tmp/x` where `/tmp/x -> ~/.ssh/id_rsa`
    /// deletes the link. Reporting a delete of the key would be a false
    /// positive AND a false audit record.
    #[test]
    fn resolve_nofollow_keeps_the_link_itself() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("id_rsa");
        std::fs::write(&secret, "key").unwrap();
        let link = dir.path().join("notes.txt");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let resolved = PtraceSupervisor::resolve_nofollow(link.to_str().unwrap());
        assert!(
            resolved.ends_with("notes.txt"),
            "unlink/rename act on the link, got {resolved}"
        );
    }

    #[test]
    fn resolution_collapses_parent_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("project");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(dir.path().join("id_rsa"), "key").unwrap();

        let traversal = format!("{}/../id_rsa", sub.to_str().unwrap());
        let resolved = PtraceSupervisor::resolve_follow(&traversal);
        assert!(!resolved.contains(".."), "`..` must collapse: {resolved}");
        assert!(resolved.ends_with("id_rsa"));
    }

    /// An `O_CREAT` open of a file that does not exist yet still gets its
    /// parent resolved, so traversal through a symlinked directory cannot
    /// hide a write.
    #[test]
    fn nonexistent_target_resolves_through_its_parent() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let linked_dir = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &linked_dir).unwrap();

        let resolved =
            PtraceSupervisor::resolve_follow(&format!("{}/new.txt", linked_dir.to_str().unwrap()));
        assert!(
            resolved.contains("/real/") && resolved.ends_with("new.txt"),
            "the symlinked parent must resolve even when the file is new, got {resolved}"
        );
    }

    /// Resolution must never *lose* information: an unresolvable path falls
    /// back to the string we would have scored before B3.
    #[test]
    fn unresolvable_path_falls_back_to_input() {
        let input = "/nonexistent-root-xyz/deeper/file.txt";
        assert_eq!(PtraceSupervisor::resolve_follow(input), input);
        assert_eq!(PtraceSupervisor::resolve_nofollow(input), input);
    }

    /// `/proc/self/*` resolved in the supervisor would name the *supervisor*,
    /// not the tracee, and `/proc/self/fd/N` targets are not filesystem paths.
    #[test]
    fn pseudo_filesystems_are_not_resolved() {
        assert_eq!(
            PtraceSupervisor::resolve_follow("/proc/self/environ"),
            "/proc/self/environ"
        );
        assert_eq!(
            PtraceSupervisor::resolve_follow("/sys/kernel/security/x"),
            "/sys/kernel/security/x"
        );
        assert_eq!(PtraceSupervisor::resolve_follow("/dev/pts/3"), "/dev/pts/3");
    }

    /// Round-2 regression: a `/proc/…/..` path escapes the pseudo-filesystem,
    /// and skipping its resolution auto-allowed the laundered real target
    /// (a private key was destroyed through the /proc noise exemption). The
    /// `..` must be collapsed so the true target is what gets scored.
    #[test]
    fn proc_traversal_escaping_proc_is_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("id_rsa");
        std::fs::write(&secret, "key").unwrap();
        // Build "/proc/self/../..<abs path to the real secret>", which the
        // kernel collapses to the secret.
        let laundered = format!("/proc/self/../..{}", secret.to_str().unwrap());
        let resolved = PtraceSupervisor::resolve_follow(&laundered);
        assert!(
            !resolved.starts_with("/proc/"),
            "the /proc/.. escape must not stay a /proc path (which is noise): {resolved}"
        );
        assert!(
            resolved.ends_with("id_rsa"),
            "the collapsed path must name the real target: {resolved}"
        );
        // And skip_resolution itself must refuse to skip it.
        assert!(!PtraceSupervisor::skip_resolution(&laundered));
        assert!(PtraceSupervisor::skip_resolution("/proc/self/environ"));
    }

    /// Round-2 regression: canonicalize drops a trailing slash, but the
    /// credential-directory rules match on `"/.ssh/"` *with* the slash, so an
    /// `O_DIRECTORY` open of `~/.ssh/` stopped matching and was auto-allowed.
    /// The resolved form must keep the trailing slash.
    #[test]
    fn resolution_preserves_a_trailing_slash() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sensitive");
        std::fs::create_dir(&sub).unwrap();
        let with_slash = format!("{}/", sub.to_str().unwrap());
        let resolved = PtraceSupervisor::resolve_follow(&with_slash);
        assert!(
            resolved.ends_with('/'),
            "a directory open with a trailing slash must keep it: {resolved}"
        );
    }

    /// Round-2 regression: resolving in the supervisor's own process turns a
    /// `/proc/self`-terminating symlink into the *supervisor's* identity.
    /// `/etc/mtab` → `/proc/<supervisor-pid>/mounts` on this machine; the
    /// result must fall back to the input rather than attribute the
    /// supervisor's pid to the tracee.
    #[test]
    fn resolution_into_proc_falls_back_to_input() {
        // /etc/mtab is a symlink to /proc/self/mounts on typical distros.
        if std::fs::symlink_metadata("/etc/mtab")
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            let resolved = PtraceSupervisor::resolve_follow("/etc/mtab");
            assert_eq!(
                resolved, "/etc/mtab",
                "a path resolving into /proc must keep the input, not the supervisor identity"
            );
        }
    }

    #[test]
    fn open_nofollow_flag_is_detected() {
        assert!(PtraceSupervisor::open_is_nofollow(
            (libc::O_RDONLY | libc::O_NOFOLLOW) as u64
        ));
        assert!(!PtraceSupervisor::open_is_nofollow(libc::O_RDONLY as u64));
    }

    /// End-to-end through `classify_syscall`: an openat of a symlink must
    /// produce the target path in the emitted `SyscallKind`.
    #[test]
    fn classify_openat_resolves_symlink_target() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("id_rsa");
        std::fs::write(&secret, "key").unwrap();
        let link = dir.path().join("notes.txt");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        // `resolve_at_path` is the function the openat arm uses; drive it
        // directly rather than fabricating tracee memory for the path read.
        let resolved = PtraceSupervisor::resolve_at_path(
            std::process::id(),
            libc::AT_FDCWD,
            link.to_str().unwrap(),
        );
        assert!(
            resolved.ends_with("id_rsa"),
            "openat through a symlink must classify as the target, got {resolved}"
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

    /// AF_NETLINK/NETLINK_ROUTE (glibc getaddrinfo/getifaddrs) is routine and
    /// must be allowed; AF_PACKET and other netlink families stay hard-denied.
    #[test]
    fn classify_netlink_route_allowed_packet_and_other_netlink_denied() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let pid = nix::unistd::Pid::from_raw(std::process::id() as i32);

        let socket_regs = |domain: u64, proto: u64| {
            let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            regs.orig_rax = syscall_nr::SOCKET as u64;
            regs.rdi = domain;
            regs.rsi = 3; // SOCK_RAW
            regs.rdx = proto;
            regs
        };

        // AF_NETLINK (16) + NETLINK_ROUTE (0) → allowed (routine DNS/iface enum).
        assert!(
            sup.classify_syscall(pid, &socket_regs(16, 0))
                .unwrap()
                .is_none(),
            "NETLINK_ROUTE socket must be allowed"
        );
        // AF_PACKET (17) → RawSocketCreate (frame capture/injection).
        assert!(matches!(
            sup.classify_syscall(pid, &socket_regs(17, 0)).unwrap(),
            Some(SyscallKind::RawSocketCreate { .. })
        ));
        // AF_NETLINK (16) + non-ROUTE family (NETLINK_NETFILTER=12) → denied.
        assert!(matches!(
            sup.classify_syscall(pid, &socket_regs(16, 12)).unwrap(),
            Some(SyscallKind::RawSocketCreate { .. })
        ));
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
    fn raw_socket_label_af_netlink_is_none() {
        // AF_NETLINK is kernel↔userspace messaging (glibc getaddrinfo/
        // getifaddrs), not an off-host exfil vector, so it is allowed (None)
        // rather than routed through the egress filter as a raw address.
        assert_eq!(nix::libc::AF_NETLINK, 16);
        assert_eq!(
            PtraceSupervisor::raw_socket_label(16),
            None,
            "AF_NETLINK (16) must be allowed (None), not raw-labelled"
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
            syscall_nr::RECVFROM,
            syscall_nr::SENDMSG,
            syscall_nr::SENDMMSG,
            syscall_nr::RECVMSG,
            syscall_nr::RECVMMSG,
            syscall_nr::CLOSE,
            syscall_nr::CLOSE_RANGE,
            syscall_nr::DUP,
            syscall_nr::DUP2,
            syscall_nr::DUP3,
            syscall_nr::FCNTL,
            syscall_nr::BIND,
            syscall_nr::SOCKETPAIR,
            syscall_nr::CLONE,
            syscall_nr::CLONE3,
            syscall_nr::FORK,
            syscall_nr::EXECVE,
            syscall_nr::RENAME,
            syscall_nr::MKDIR,
            syscall_nr::UNLINK,
            syscall_nr::CHMOD,
            syscall_nr::FCHMOD,
            syscall_nr::GETDENTS64,
            syscall_nr::OPENAT,
            syscall_nr::MKDIRAT,
            syscall_nr::UNLINKAT,
            syscall_nr::RENAMEAT,
            syscall_nr::FCHMODAT,
            syscall_nr::PIPE2,
            syscall_nr::RENAMEAT2,
            // Go-live review B2: open/truncate/link family.
            syscall_nr::OPENAT2,
            syscall_nr::RMDIR,
            syscall_nr::CREAT,
            syscall_nr::TRUNCATE,
            syscall_nr::FTRUNCATE,
            syscall_nr::SYMLINK,
            syscall_nr::SYMLINKAT,
            syscall_nr::LINK,
            syscall_nr::LINKAT,
            syscall_nr::IO_URING_SETUP,
            syscall_nr::IO_URING_ENTER,
            syscall_nr::IO_URING_REGISTER,
            syscall_nr::SECCOMP,
            syscall_nr::PRCTL,
            syscall_nr::SENDFILE,
            syscall_nr::SPLICE,
            syscall_nr::TEE,
            syscall_nr::SOCKET,
            syscall_nr::EXECVEAT,
            // PR 6 Phase A: category-1 hard-deny syscalls.
            syscall_nr::INIT_MODULE,
            syscall_nr::FINIT_MODULE,
            syscall_nr::DELETE_MODULE,
            syscall_nr::KEXEC_LOAD,
            syscall_nr::KEXEC_FILE_LOAD,
            // PR 6 Phase B: category-2 proxy-evaluated syscalls.
            syscall_nr::CHOWN,
            syscall_nr::FCHOWN,
            syscall_nr::LCHOWN,
            syscall_nr::FCHOWNAT,
            syscall_nr::MOUNT,
            syscall_nr::UMOUNT2,
            syscall_nr::PIVOT_ROOT,
            syscall_nr::CHROOT,
            syscall_nr::OPEN_TREE,
            syscall_nr::MOVE_MOUNT,
            syscall_nr::FSOPEN,
            syscall_nr::FSCONFIG,
            syscall_nr::FSMOUNT,
            syscall_nr::FSPICK,
            syscall_nr::MOUNT_SETATTR,
            syscall_nr::PTRACE,
            syscall_nr::PROCESS_VM_READV,
            syscall_nr::PROCESS_VM_WRITEV,
            // PR 6 Phase C.
            syscall_nr::UNSHARE,
            syscall_nr::SETNS,
            // PR 6 Phase D.
            syscall_nr::SETHOSTNAME,
            syscall_nr::SETDOMAINNAME,
            syscall_nr::IOPL,
            syscall_nr::IOPERM,
            syscall_nr::SWAPON,
            syscall_nr::SWAPOFF,
            syscall_nr::REBOOT,
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

    /// socket(AF_NETLINK, <non-route family>) → RawSocketCreate (kernel netlink
    /// access). The routine NETLINK_ROUTE family is allowed instead — see
    /// `classify_netlink_route_allowed_packet_and_other_netlink_denied`.
    #[test]
    fn classify_socket_af_netlink_nonroute_returns_raw_socket_create() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::SOCKET as u64;
        regs.rdi = 16; // AF_NETLINK
        regs.rsi = 3; // SOCK_RAW
        regs.rdx = 12; // NETLINK_NETFILTER (not NETLINK_ROUTE)

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(
            result.is_some(),
            "non-route AF_NETLINK socket() should return Some(...)"
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

    // ---- PR 6 Phase B: cross-process access carveouts ----

    /// ptrace(PTRACE_TRACEME) — request(rdi) == 0 — is carved out (None): the
    /// caller volunteers to be traced by its parent and reads no other
    /// process's memory. Keyed on rdi, NOT on rsi (which TRACEME leaves 0).
    #[test]
    fn classify_ptrace_traceme_returns_none() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let pid = nix::unistd::Pid::from_raw(std::process::id() as i32);

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::PTRACE as u64;
        regs.rdi = 0; // PTRACE_TRACEME
        regs.rsi = 0; // pid arg ignored

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(
            result.is_none(),
            "PTRACE_TRACEME must be carved out (None), got {result:?}"
        );
    }

    /// ptrace(PTRACE_ATTACH, target) — a real cross-process attach — classifies
    /// as CrossProcessAccess carrying the target pid from rsi.
    #[test]
    fn classify_ptrace_attach_returns_cross_process() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let pid = nix::unistd::Pid::from_raw(std::process::id() as i32);
        let target = std::process::id() + 1;

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::PTRACE as u64;
        regs.rdi = 16; // PTRACE_ATTACH
        regs.rsi = u64::from(target);

        match sup.classify_syscall(pid, &regs).unwrap() {
            Some(SyscallKind::CrossProcessAccess { op, target_pid }) => {
                assert!(matches!(op, crate::interceptor::CrossProcessOp::Ptrace));
                assert_eq!(target_pid, target);
            }
            other => panic!("expected CrossProcessAccess, got {other:?}"),
        }
    }

    /// process_vm_readv against the caller's OWN pid is carved out (None) —
    /// benign intra-process memory copying.
    #[test]
    fn classify_process_vm_readv_self_returns_none() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::PROCESS_VM_READV as u64;
        regs.rdi = u64::from(our_pid); // target == self

        let result = sup.classify_syscall(pid, &regs).unwrap();
        assert!(
            result.is_none(),
            "process_vm_readv against self must be carved out (None), got {result:?}"
        );
    }

    /// process_vm_readv against a DIFFERENT pid classifies as CrossProcessAccess.
    #[test]
    fn classify_process_vm_readv_other_returns_cross_process() {
        use nix::libc;
        let sup = PtraceSupervisor::new();
        let our_pid = std::process::id();
        let pid = nix::unistd::Pid::from_raw(our_pid as i32);
        let target = our_pid + 1;

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.orig_rax = syscall_nr::PROCESS_VM_READV as u64;
        regs.rdi = u64::from(target); // target != self

        match sup.classify_syscall(pid, &regs).unwrap() {
            Some(SyscallKind::CrossProcessAccess { op, target_pid }) => {
                assert!(matches!(
                    op,
                    crate::interceptor::CrossProcessOp::ProcessVmReadv
                ));
                assert_eq!(target_pid, target);
            }
            other => panic!("expected CrossProcessAccess, got {other:?}"),
        }
    }

    // ---- PR 5 Phase A: sockaddr address-byte → string contract ----

    #[test]
    fn af_inet_inaddr_any_renders_as_dotted_zero() {
        // INADDR_ANY is the all-zeros network-order word; the
        // dotted-quad form is "0.0.0.0".
        assert_eq!(sockaddr_in_to_string([0, 0, 0, 0]), "0.0.0.0");
    }

    #[test]
    fn af_inet_inaddr_loopback_renders_as_127_0_0_1() {
        // INADDR_LOOPBACK is 0x7f000001 in host order; network-order
        // bytes are [0x7f, 0x00, 0x00, 0x01].
        assert_eq!(sockaddr_in_to_string([127, 0, 0, 1]), "127.0.0.1");
    }

    #[test]
    fn af_inet_arbitrary_address() {
        assert_eq!(sockaddr_in_to_string([192, 168, 1, 10]), "192.168.1.10");
    }

    #[test]
    fn af_inet6_in6addr_any_renders_as_canonical_double_colon() {
        // in6addr_any = 16 zero octets; canonical form is "::".
        let zeros = [0u8; 8];
        assert_eq!(sockaddr_in6_to_string(zeros, zeros), "::");
    }

    #[test]
    fn af_inet6_in6addr_loopback_renders_as_double_colon_one() {
        // in6addr_loopback = [0; 15, 1]; canonical form is "::1".
        let high = [0u8; 8];
        let low = [0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(sockaddr_in6_to_string(high, low), "::1");
    }

    #[test]
    fn af_inet6_ipv4_mapped_v6_renders_with_dotted_quad_tail() {
        // IPv4-mapped IPv6: ::ffff:a.b.c.d. The 80 leading bits are
        // zero, then 16 bits of 1s, then the v4 address in network
        // order. The `Display` impl chooses the dotted-quad tail
        // for these.
        let high = [0u8; 8];
        let low = [0, 0, 0xff, 0xff, 127, 0, 0, 1];
        assert_eq!(sockaddr_in6_to_string(high, low), "::ffff:127.0.0.1");
    }

    #[test]
    fn af_inet6_ipv4_mapped_wildcard_renders_with_zero_dotted_quad() {
        let high = [0u8; 8];
        let low = [0, 0, 0xff, 0xff, 0, 0, 0, 0];
        assert_eq!(sockaddr_in6_to_string(high, low), "::ffff:0.0.0.0");
    }

    /// Regression guard for the original PR 5 Phase A bug: the
    /// expanded-form string `"0:0:0:0:0:0:0:1"` (what the previous
    /// implementation produced) is NOT a substring of the canonical
    /// `"::1"`. Asserts the helper returns the canonical form so
    /// downstream literal-string matchers keep working.
    #[test]
    fn af_inet6_loopback_does_not_use_expanded_form() {
        let high = [0u8; 8];
        let low = [0, 0, 0, 0, 0, 0, 0, 1];
        let out = sockaddr_in6_to_string(high, low);
        assert!(out == "::1", "expected canonical \"::1\", got {out:?}");
        assert!(
            out != "0:0:0:0:0:0:0:1",
            "must NOT return expanded form — the previous bug",
        );
    }
}
