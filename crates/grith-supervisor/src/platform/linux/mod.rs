// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Linux platform implementation of the [`SyscallInterceptor`] trait.
//!
//! This module provides [`PtraceSupervisor`], which uses the Linux `ptrace(2)` API
//! to intercept syscalls made by supervised child processes. Every security-relevant
//! syscall (file I/O, networking, process spawning) is trapped at the kernel boundary
//! before it executes, giving the grith proxy an opportunity to allow, deny, or queue
//! the operation for human review.
//!
//! # Mechanism
//!
//! The interception pipeline works in three stages:
//!
//! 1. **Spawn / Attach** -- The supervised process is either forked from the daemon
//!    (with `PTRACE_TRACEME` in the child) or attached to an existing PID via
//!    `PTRACE_ATTACH`. In both cases the tracer configures `PTRACE_SETOPTIONS` to
//!    receive `PTRACE_EVENT_FORK`, `PTRACE_EVENT_VFORK`, and `PTRACE_EVENT_CLONE`
//!    notifications so the entire process tree is automatically supervised.
//!
//! 2. **Intercept** -- The tracer loops on `waitpid(-1, ...)`. When a syscall-entry
//!    stop is detected (signalled by `SIGTRAP | 0x80` thanks to
//!    `PTRACE_O_TRACESYSGOOD`), the tracer reads the general-purpose registers via
//!    `PTRACE_GETREGS` to identify the syscall number and its arguments.
//!
//! 3. **Classify** -- The raw syscall number is mapped to a [`SyscallKind`] variant.
//!    String arguments (paths, addresses) are read from the tracee's address space
//!    one word at a time via `PTRACE_PEEKDATA`. File-descriptor arguments are
//!    resolved to filesystem paths by reading the `/proc/<pid>/fd/<fd>` symlink.
//!
//! # Register layout (x86_64 System V ABI)
//!
//! | Register    | Purpose at syscall-entry       |
//! |-------------|--------------------------------|
//! | `orig_rax`  | Syscall number                 |
//! | `rdi`       | Argument 1                     |
//! | `rsi`       | Argument 2                     |
//! | `rdx`       | Argument 3                     |
//! | `r10`       | Argument 4                     |
//! | `r8`        | Argument 5                     |
//! | `r9`        | Argument 6                     |
//!
//! # Limitations
//!
//! - This implementation targets **x86_64** only. The syscall number table and
//!   register layout assume the System V AMD64 ABI.
//! - `ptrace` is single-threaded by nature: only one tracer thread may wait on a
//!   given tracee. The [`PtraceSupervisor`] must therefore be owned by a single
//!   async task (it is `Send` but not `Sync`-safe for concurrent `next_event` calls).
//! - Reading tracee memory word-by-word is slower than `process_vm_readv`. In
//!   practice this is acceptable because we only read short strings (paths, addresses).
//!
//! # Requirements
//!
//! - Linux kernel 4.8+ (for `PTRACE_O_TRACESYSGOOD` and process-creation tracking).
//! - Either `CAP_SYS_PTRACE` capability or Yama LSM configured to allow tracing
//!   (`/proc/sys/kernel/yama/ptrace_scope` set to 0 or 1).

#![allow(clippy::duplicated_attributes)]
#![cfg(target_os = "linux")]

mod child;
pub(crate) mod clamp;
mod classify;
mod dns_redirect;
mod dns_socket_tracker;
mod events;
pub(crate) mod seccomp;

use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// x86_64 syscall number constants
// ---------------------------------------------------------------------------

/// Syscall numbers for the x86_64 Linux ABI.
///
/// These constants correspond to the entries in
/// `/usr/include/asm/unistd_64.h` (or `ausyscall --dump` output). Only
/// the syscalls that grith considers security-relevant are listed here;
/// all other syscall numbers are passed through without interception.
pub(crate) mod syscall_nr {
    /// `read(fd, buf, count)` -- read from a file descriptor.
    pub const READ: i64 = 0;
    /// `write(fd, buf, count)` -- write to a file descriptor.
    pub const WRITE: i64 = 1;
    /// `writev(fd, iov, iovcnt)` -- gathered write to a file descriptor.
    ///
    /// Like `WRITE`, deliberately outside the seccomp trap set; both are
    /// surfaced only for threads stepped under `ConnectedDgramStepping`, where
    /// a write to a connected datagram socket is an egress the proxy must
    /// judge (go-live review B13).
    pub const WRITEV: i64 = 20;
    /// `close(fd)` -- close a descriptor.
    pub const CLOSE: i64 = 3;
    /// `open(pathname, flags, mode)` -- legacy file open (prefer `openat`).
    pub const OPEN: i64 = 2;
    /// `mmap(addr, length, prot, flags, fd, offset)` -- map files or devices into memory.
    ///
    /// Only file-backed mmaps (fd >= 0, !MAP_ANONYMOUS) are security-relevant.
    /// Anonymous allocations (fd == -1 or MAP_ANONYMOUS set) are passed through without
    /// interception to avoid unacceptable overhead (mmap is called very frequently for
    /// heap/stack allocations).
    pub const MMAP: i64 = 9;
    /// `pipe(pipefd)` -- create a unidirectional pipe.
    pub const PIPE: i64 = 22;
    /// `socket(domain, type, protocol)` -- create an endpoint for communication.
    ///
    /// Intercepted to catch raw-socket creation (AF_PACKET=17, AF_NETLINK=16)
    /// at the earliest possible point — before any data is sent. AF_PACKET
    /// sockets bypass the normal IP stack and can capture or inject arbitrary
    /// link-layer frames, making them a high-severity capability. Normal
    /// sockets (AF_INET, AF_INET6, AF_UNIX) are filtered out in classify_syscall
    /// and intercepted later at connect()/bind() instead.
    pub const SOCKET: i64 = 41;
    /// `connect(sockfd, addr, addrlen)` -- initiate a network connection.
    pub const CONNECT: i64 = 42;
    /// `sendto(sockfd, buf, len, flags, dest_addr, addrlen)` -- send a datagram.
    pub const SENDTO: i64 = 44;
    /// `recvfrom(sockfd, buf, len, flags, src_addr, addrlen)` -- receive a
    /// datagram. Trapped for in-line DNS response observation (glibc/c-ares read
    /// DNS answers via recvfrom; the buffer is kernel-filled, so it is read at
    /// syscall *exit*).
    pub const RECVFROM: i64 = 45;
    /// `sendmsg(sockfd, msg, flags)` -- send a message. Trapped for in-line DNS
    /// query inspection (some resolvers send via sendmsg).
    pub const SENDMSG: i64 = 46;
    /// `recvmsg(sockfd, msg, flags)` -- receive a message.
    pub const RECVMSG: i64 = 47;
    /// `dup(oldfd)` -- duplicate a descriptor.
    pub const DUP: i64 = 32;
    /// `dup2(oldfd, newfd)` -- duplicate to a selected descriptor.
    pub const DUP2: i64 = 33;
    /// `fcntl(fd, cmd, ...)` -- descriptor control, including `F_DUPFD*`.
    pub const FCNTL: i64 = 72;
    /// `sendmmsg(sockfd, msgvec, vlen, flags)` -- send multiple messages in one
    /// call. Trapped for in-line DNS query inspection: glibc `getaddrinfo`
    /// batches the A + AAAA queries into a single `sendmmsg`.
    pub const SENDMMSG: i64 = 307;
    /// `recvmmsg(sockfd, msgvec, vlen, flags, timeout)` -- receive a batch.
    pub const RECVMMSG: i64 = 299;
    /// `dup3(oldfd, newfd, flags)` -- duplicate with flags.
    pub const DUP3: i64 = 292;
    /// `close_range(first, last, flags)` -- close a descriptor interval.
    pub const CLOSE_RANGE: i64 = 436;
    /// `clone3(args, size)` -- modern process/thread creation. Like `clone`,
    /// this is observed through `PTRACE_EVENT_CLONE`, not seccomp.
    pub const CLONE3: i64 = 435;
    /// `seccomp(op, flags, args)` -- install a seccomp filter.
    ///
    /// Trapped so a supervised process cannot install its own filter that
    /// out-ranks grith's. `SECCOMP_RET_USER_NOTIF` (0x7fc00000) beats grith's
    /// `SECCOMP_RET_TRACE` (0x7ff00000) in seccomp action precedence (lowest
    /// value wins), so a tracee that adds a `NEW_LISTENER` filter and answers
    /// its own notifications with `USER_NOTIF_FLAG_CONTINUE` executes syscalls
    /// grith never sees. Denying the `NEW_LISTENER` install closes that
    /// escape (go-live review, round-2 finding).
    pub const SECCOMP: i64 = 317;
    /// `prctl(option, ...)` -- trapped only to catch
    /// `PR_SET_SECCOMP(SECCOMP_MODE_FILTER)`, the legacy filter-install path.
    /// It has no flags argument and so cannot create a listener, but it is
    /// still the route by which a tracee could install an audit-blinding
    /// `ERRNO`/`TRAP` filter, so it is surfaced for observation.
    pub const PRCTL: i64 = 157;
    /// `bind(sockfd, addr, addrlen)` -- bind a socket to an address.
    pub const BIND: i64 = 49;
    /// `socketpair(domain, type, protocol, sv)` -- create a pair of connected sockets.
    pub const SOCKETPAIR: i64 = 53;
    /// `clone(flags, stack, ...)` -- create a child process or thread.
    pub const CLONE: i64 = 56;
    /// `fork()` -- create a child process (legacy; typically uses `clone`).
    pub const FORK: i64 = 57;
    /// `execve(pathname, argv, envp)` -- execute a program.
    pub const EXECVE: i64 = 59;
    /// `rename(oldpath, newpath)` -- rename a file (legacy; prefer `renameat2`).
    pub const RENAME: i64 = 82;
    /// `mkdir(pathname, mode)` -- create a directory.
    pub const MKDIR: i64 = 83;
    /// `unlink(pathname)` -- delete a file.
    pub const UNLINK: i64 = 87;
    /// `rmdir(pathname)` -- remove a directory.
    pub const RMDIR: i64 = 84;
    /// `chmod(pathname, mode)` -- change file permissions.
    pub const CHMOD: i64 = 90;
    /// `fchmod(fd, mode)` -- change file permissions by fd.
    pub const FCHMOD: i64 = 91;
    /// `getdents64(fd, dirp, count)` -- read directory entries.
    pub const GETDENTS64: i64 = 217;
    /// `openat(dirfd, pathname, flags, mode)` -- open a file relative to a directory fd.
    pub const OPENAT: i64 = 257;
    /// `openat2(dirfd, pathname, how, size)` -- open with an extensible
    /// `struct open_how` instead of a flags word (kernel 5.6+).
    ///
    /// Functionally equivalent to `openat` for policy purposes, and one
    /// `syscall()` away in Python/Go/Rust — without it, file policy is
    /// bypassed by choosing a different open syscall.
    pub const OPENAT2: i64 = 437;
    /// `creat(pathname, mode)` -- legacy create; equivalent to
    /// `open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`.
    pub const CREAT: i64 = 85;
    /// `truncate(pathname, length)` -- resize a file by path. A destructive
    /// write that never goes through `open`/`write`.
    pub const TRUNCATE: i64 = 76;
    /// `ftruncate(fd, length)` -- resize a file by descriptor.
    pub const FTRUNCATE: i64 = 77;
    /// `symlink(target, linkpath)` -- create a symbolic link.
    ///
    /// Link creation is scored by its *target*: `ln -s ~/.ssh/id_rsa /tmp/x`
    /// followed by reading `/tmp/x` launders a sensitive path past any
    /// path-string filter, so the creation itself is the control point.
    pub const SYMLINK: i64 = 88;
    /// `symlinkat(target, newdirfd, linkpath)` -- create a symlink relative
    /// to a directory fd.
    pub const SYMLINKAT: i64 = 266;
    /// `link(oldpath, newpath)` -- create a hard link. Same laundering
    /// concern as `symlink`, and a hard link survives deletion of the
    /// original name.
    pub const LINK: i64 = 86;
    /// `linkat(olddirfd, oldpath, newdirfd, newpath, flags)` -- create a
    /// hard link relative to directory fds.
    pub const LINKAT: i64 = 265;
    /// `mkdirat(dirfd, pathname, mode)` -- create a directory relative to a directory fd.
    pub const MKDIRAT: i64 = 258;
    /// `unlinkat(dirfd, pathname, flags)` -- delete a file relative to a directory fd.
    pub const UNLINKAT: i64 = 263;
    /// `renameat(olddirfd, oldpath, newdirfd, newpath)` -- rename relative to directory fds.
    pub const RENAMEAT: i64 = 264;
    /// `fchmodat(dirfd, pathname, mode, flags)` -- change permissions relative to a directory fd.
    pub const FCHMODAT: i64 = 268;
    /// `pipe2(pipefd, flags)` -- create a pipe with `O_CLOEXEC`/`O_NONBLOCK`.
    pub const PIPE2: i64 = 293;
    /// `renameat2(olddirfd, oldpath, newdirfd, newpath, flags)` -- rename with flags.
    pub const RENAMEAT2: i64 = 316;
    /// `io_uring_setup(entries, params)` -- create an io_uring context.
    ///
    /// io_uring operations bypass per-syscall ptrace stops: I/O submitted via
    /// the ring buffer executes without individual entry stops. Grith denies
    /// this syscall so supervised processes cannot obtain invisible I/O channels.
    pub const IO_URING_SETUP: i64 = 425;
    /// `io_uring_enter(fd, to_submit, min_complete, flags, sig)` -- submit/wait for io_uring operations.
    pub const IO_URING_ENTER: i64 = 426;
    /// `io_uring_register(fd, opcode, arg, nr_args)` -- register buffers/files with io_uring.
    pub const IO_URING_REGISTER: i64 = 427;
    /// `sendfile(out_fd, in_fd, offset, count)` -- copy between file descriptors in kernel space.
    ///
    /// sendfile transfers data directly from `in_fd` to `out_fd` without passing through
    /// userspace buffers. A process can open a sensitive file then sendfile its contents
    /// directly to a network socket, bypassing write()/sendto() interception entirely.
    pub const SENDFILE: i64 = 40;
    /// `splice(fd_in, off_in, fd_out, off_out, len, flags)` -- move data between fds via pipe.
    ///
    /// splice moves data between two file descriptors via an in-kernel pipe buffer,
    /// also bypassing userspace. Used to exfiltrate data without a write() syscall.
    pub const SPLICE: i64 = 275;
    /// `tee(fd_in, fd_out, len, flags)` -- duplicate pipe data without consuming it.
    ///
    /// tee copies data between two pipe file descriptors in kernel space. Lower risk
    /// than sendfile/splice (pipe-to-pipe only) but tracked for completeness.
    pub const TEE: i64 = 276;
    /// `execveat(dirfd, pathname, argv, envp, flags)` -- execute a program
    /// relative to a directory file descriptor.
    ///
    /// Similar to `execve` but resolves `pathname` relative to `dirfd`. Also
    /// used by glibc's `fexecve()`. Must be intercepted alongside `execve` to
    /// prevent bypassing exec provenance checks.
    pub const EXECVEAT: i64 = 322;
    /// PR 6 Phase A: kernel-module load. Loads an ELF module from a
    /// user-space buffer into the running kernel — has no legitimate
    /// use in supervised AI tools.
    pub const INIT_MODULE: i64 = 175;
    /// PR 6 Phase A: kernel-module load from a file descriptor.
    /// Sibling of `init_module`; equally privileged.
    pub const FINIT_MODULE: i64 = 313;
    /// PR 6 Phase A: kernel-module unload. Symmetric to `init_module`
    /// — supervised tools should not be removing kernel modules.
    pub const DELETE_MODULE: i64 = 176;
    /// PR 6 Phase A: replace the running kernel with a new image at
    /// the next reboot. The "atomic boot kit" syscall — no legitimate
    /// use in dev tools.
    pub const KEXEC_LOAD: i64 = 246;
    /// PR 6 Phase A: kexec from a file descriptor. Sibling of
    /// `kexec_load`.
    pub const KEXEC_FILE_LOAD: i64 = 320;

    // ── PR 6 Phase B: ownership change family ──
    /// `chown(path, uid, gid)` — change file owner/group by path.
    pub const CHOWN: i64 = 92;
    /// `fchown(fd, uid, gid)` — change file owner/group by fd.
    pub const FCHOWN: i64 = 93;
    /// `lchown(path, uid, gid)` — like `chown` but doesn't follow symlinks.
    pub const LCHOWN: i64 = 94;
    /// `fchownat(dirfd, path, uid, gid, flags)` — change owner/group
    /// relative to a directory fd.
    pub const FCHOWNAT: i64 = 260;

    // ── PR 6 Phase B: filesystem mutation family ──
    /// `mount(src, target, fstype, flags, data)` — mount a filesystem.
    pub const MOUNT: i64 = 165;
    /// `umount2(target, flags)` — unmount with flags. x86_64 has no
    /// separate `umount`; `umount2` covers both shapes.
    pub const UMOUNT2: i64 = 166;
    /// `pivot_root(new_root, put_old)` — change the root filesystem.
    pub const PIVOT_ROOT: i64 = 155;
    /// `chroot(path)` — change the process root directory.
    pub const CHROOT: i64 = 161;
    /// `open_tree(dfd, filename, flags)` — clone/open a mount tree.
    pub const OPEN_TREE: i64 = 428;
    /// `move_mount(from_dfd, from_pathname, to_dfd, to_pathname, flags)`.
    pub const MOVE_MOUNT: i64 = 429;
    /// `fsopen(fs_name, flags)` — create a new filesystem context.
    pub const FSOPEN: i64 = 430;
    /// `fsconfig(fd, cmd, key, value, aux)` — configure a filesystem context.
    pub const FSCONFIG: i64 = 431;
    /// `fsmount(fd, flags, ms_flags)` — create a mount from a filesystem context.
    pub const FSMOUNT: i64 = 432;
    /// `fspick(dfd, path, flags)` — select a mount for reconfiguration.
    pub const FSPICK: i64 = 433;
    /// `mount_setattr(dfd, path, flags, attr, size)` — change mount attributes.
    pub const MOUNT_SETATTR: i64 = 442;

    // ── PR 6 Phase B: cross-process access family ──
    /// `ptrace(request, pid, addr, data)` — attach/detach/read/write
    /// memory of another process.
    pub const PTRACE: i64 = 101;
    /// `process_vm_readv(pid, local_iov, ..., remote_iov, ...)` — read
    /// memory directly from another process.
    pub const PROCESS_VM_READV: i64 = 310;
    /// `process_vm_writev(pid, local_iov, ..., remote_iov, ...)` —
    /// write memory directly into another process.
    pub const PROCESS_VM_WRITEV: i64 = 311;

    // ── PR 6 Phase C: namespace primitives ──
    /// `unshare(flags)` — disassociate parts of the caller's execution
    /// context (mount/uts/pid/net/user/ipc/cgroup namespaces).
    pub const UNSHARE: i64 = 272;
    /// `setns(fd, nstype)` — re-associate the caller with the namespace
    /// referred to by `fd`.
    pub const SETNS: i64 = 308;

    // ── PR 6 Phase D: architecture-specific privileged ops ──
    // All hard-denied unconditionally. Each represents a host-wide
    // authority change that no supervised AI tool has any reason to
    // attempt; if a tool is calling these, it's either a bug or an
    // exploit. The supervisor blocks at the source.

    /// `sethostname(name, len)` — set the system hostname. Global
    /// identity change visible to every other process on the host.
    pub const SETHOSTNAME: i64 = 170;
    /// `setdomainname(name, len)` — set the NIS domain name.
    /// Same shape as `sethostname`.
    pub const SETDOMAINNAME: i64 = 171;
    /// `iopl(level)` — set the I/O privilege level (x86 only).
    /// Grants direct access to all I/O ports. Hard-deny.
    pub const IOPL: i64 = 172;
    /// `ioperm(from, num, turn_on)` — toggle access to specific
    /// I/O ports (x86 only). Same threat as `iopl`.
    pub const IOPERM: i64 = 173;
    /// `swapon(path, flags)` — bring a swap area online.
    /// Kernel resource-management; no dev-tool use.
    pub const SWAPON: i64 = 167;
    /// `swapoff(path)` — disable a swap area.
    pub const SWAPOFF: i64 = 168;
    /// `reboot(magic1, magic2, cmd, arg)` — reboot, halt, or change
    /// reboot semantics. Obvious hard-deny.
    pub const REBOOT: i64 = 169;
}

// ─────────────────────────────────────────────────────────────────────
// PR 6 Phase C: CLONE_NEW* flag bits (must match Linux uapi).
// ─────────────────────────────────────────────────────────────────────

/// Bitmask covering every `CLONE_NEW*` namespace-creation flag.
/// A `flags` argument intersecting any bit here is a namespace
/// primitive (regardless of which syscall delivered it).
///
/// Currently used only by tests; the production
/// `unshare`/`setns` arms in classify.rs forward the full flag
/// word to the proxy and let downstream code interpret it.
#[allow(dead_code)]
pub(crate) const CLONE_NEW_NS_MASK: u64 = 0x0000_0000_7E02_0000;

/// The complete set of syscall numbers that grith classifies as
/// security-relevant. Used by [`is_security_relevant`] for fast lookup.
pub(crate) const SECURITY_RELEVANT: &[i64] = &[
    // READ (0) and WRITE (1) are intentionally excluded — they account for
    // the vast majority of syscalls during tool startup (e.g. 20K+ for
    // Node.js) but add no security value because OPEN/OPENAT already
    // captures the file-access decision.  Removing them dramatically
    // reduces ptrace overhead.  See the security analysis in the commit
    // that introduced this change.
    syscall_nr::OPEN,
    // mmap(9): only file-backed mmaps (fd >= 0, !MAP_ANONYMOUS) are intercepted.
    // Anonymous allocations are filtered out in classify_syscall before proxy
    // evaluation so the per-syscall overhead remains acceptable.
    syscall_nr::MMAP,
    syscall_nr::PIPE,
    syscall_nr::CONNECT,
    syscall_nr::SENDTO,
    // DNS receives are trapped only so in-line inspection can read tracked
    // resolver responses at syscall exit. Non-DNS receives resume immediately.
    syscall_nr::RECVFROM,
    // SENDMSG (46) / SENDMMSG (307): trapped for in-line DNS query inspection on
    // a tracked DNS socket (getaddrinfo batches A+AAAA via sendmmsg). Non-DNS
    // sends classify as noise and resume immediately.
    syscall_nr::SENDMSG,
    syscall_nr::SENDMMSG,
    syscall_nr::RECVMSG,
    syscall_nr::RECVMMSG,
    // Socket descriptor lifecycle. These are consumed internally by the
    // process-scoped socket tracker and classify as noise.
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
    // openat2(437): the modern open. Classified identically to openat —
    // omitting it let a tool bypass file policy by choosing a different
    // open syscall (go-live review B2).
    syscall_nr::OPENAT2,
    // creat(85): legacy O_CREAT|O_WRONLY|O_TRUNC open.
    syscall_nr::CREAT,
    // truncate(76)/ftruncate(77): destructive writes that never pass
    // through open()/write().
    syscall_nr::TRUNCATE,
    syscall_nr::FTRUNCATE,
    // Link creation (go-live review B2/B3). Scored by link *target*, so a
    // symlink or hard link pointed at a sensitive path is a decision point
    // rather than a silent laundering primitive.
    syscall_nr::RMDIR,
    syscall_nr::SYMLINK,
    syscall_nr::SYMLINKAT,
    syscall_nr::LINK,
    syscall_nr::LINKAT,
    syscall_nr::MKDIRAT,
    syscall_nr::UNLINKAT,
    syscall_nr::RENAMEAT,
    syscall_nr::FCHMODAT,
    syscall_nr::PIPE2,
    syscall_nr::RENAMEAT2,
    // io_uring: ring-buffer I/O bypasses per-syscall ptrace stops entirely.
    // All three syscalls are intercepted so the ring cannot be created,
    // used, or configured. io_uring_setup is the critical gate — blocking it
    // prevents ring creation; the others are defence-in-depth.
    // Self-filter defence (go-live review round 2): a tracee installing its
    // own seccomp filter can out-rank grith's TRACE with USER_NOTIF and
    // execute syscalls invisibly. Both are trapped so the install is seen.
    syscall_nr::SECCOMP,
    syscall_nr::PRCTL,
    syscall_nr::IO_URING_SETUP,
    syscall_nr::IO_URING_ENTER,
    syscall_nr::IO_URING_REGISTER,
    // socket(41): intercepted to detect raw-socket creation (AF_PACKET/AF_NETLINK)
    // at the earliest point — before any frames are sent. Normal socket families
    // (AF_INET, AF_INET6, AF_UNIX) are filtered out in classify_syscall.
    syscall_nr::SOCKET,
    // sendfile/splice/tee: kernel-level fd-to-fd transfers that bypass userspace
    // buffers. A process can exfiltrate sensitive file data to a socket without
    // making any write()/sendto() call, making taint tracking incomplete without
    // intercepting these. Emitted as FileRead on the source fd so the existing
    // taint filter evaluates them using the same scoring path.
    syscall_nr::SENDFILE,
    syscall_nr::SPLICE,
    syscall_nr::TEE,
    // execveat(322): like execve but relative to a directory fd. Used by
    // glibc fexecve(). Must be intercepted to prevent exec provenance bypass.
    syscall_nr::EXECVEAT,
    // PR 6 Phase A: kernel-module load/unload + kexec replacement.
    // No legitimate use in supervised AI tools. Hard-denied in
    // event_handler.rs before proxy evaluation, mirroring io_uring.
    syscall_nr::INIT_MODULE,
    syscall_nr::FINIT_MODULE,
    syscall_nr::DELETE_MODULE,
    syscall_nr::KEXEC_LOAD,
    syscall_nr::KEXEC_FILE_LOAD,
    // PR 6 Phase B: ownership change (chown family). LLM-escapable
    // path to make a file owner-writable by itself. Proxy-evaluated
    // with +5.0 baseline → QUEUE by default.
    syscall_nr::CHOWN,
    syscall_nr::FCHOWN,
    syscall_nr::LCHOWN,
    syscall_nr::FCHOWNAT,
    // PR 6 Phase B: filesystem mutation. mount/umount2/pivot_root
    // can reshape the supervised process's filesystem view to bypass
    // path-based filters.
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
    // PR 6 Phase B: cross-process access. ptrace + process_vm_*
    // bypass file/network filters by reading/writing sibling-process
    // memory directly. process_vm_* against self (target_pid == own
    // PID) is filtered out in classify so the supervisor's own use
    // doesn't trip.
    syscall_nr::PTRACE,
    syscall_nr::PROCESS_VM_READV,
    syscall_nr::PROCESS_VM_WRITEV,
    // PR 6 Phase C: namespace primitives. `unshare`/`setns` are
    // proxy-evaluated unless the calling binary lives in a routine
    // root AND its canonical path is in the profile's
    // `namespace_users` list (bwrap/bubblewrap/firejail by default).
    // `clone` is already in this list as a ProcessFork producer;
    // clone-with-CLONE_NEW* flag detection is intentionally deferred
    // (would require parsing the flags argument inside the existing
    // clone arm and routing the namespace-flagged variant
    // separately).
    syscall_nr::UNSHARE,
    syscall_nr::SETNS,
    // PR 6 Phase D: architecture-specific privileged ops. All hard-
    // denied unconditionally in event_handler.rs before proxy
    // evaluation, mirroring the io_uring / kernel-module pattern.
    // iopl/ioperm are x86-only but the syscall numbers exist on the
    // x86_64 ABI we target; on other architectures the entries are
    // simply never reached by classify_syscall.
    syscall_nr::SETHOSTNAME,
    syscall_nr::SETDOMAINNAME,
    syscall_nr::IOPL,
    syscall_nr::IOPERM,
    syscall_nr::SWAPON,
    syscall_nr::SWAPOFF,
    syscall_nr::REBOOT,
];

/// Returns `true` if the given raw syscall number is one grith wants to
/// intercept and classify.
pub(crate) fn is_security_relevant(nr: i64) -> bool {
    SECURITY_RELEVANT.contains(&nr)
}

// ---------------------------------------------------------------------------
// PtraceSupervisor
// ---------------------------------------------------------------------------

/// Linux syscall interceptor built on `ptrace(2)`.
///
/// This struct owns the set of traced PIDs and exposes the
/// [`SyscallInterceptor`] interface for the supervisor orchestrator.
///
/// # Thread safety
///
/// `PtraceSupervisor` is `Send` so it can be moved between async tasks, but
/// it must only be driven from a single task at a time (ptrace requires the
/// tracer to be the same thread that attached). Wrap in a `Mutex` if shared
/// access is needed, though the canonical usage is single-owner.
///
/// # Usage
///
/// ```rust,no_run
/// use grith_supervisor::platform::linux::PtraceSupervisor;
/// use grith_supervisor::interceptor::SyscallInterceptor;
///
/// let mut sup = PtraceSupervisor::new();
/// // sup.spawn_supervised("/usr/bin/ls", &["-la".into()], &[]).await?;
/// // loop { let event = sup.next_event().await?; /* ... */ }
/// ```
pub struct PtraceSupervisor {
    /// Set of all PIDs/TIDs currently being traced. This includes both
    /// process PIDs and thread TIDs; use `thread_tids` to distinguish.
    pub(crate) supervised: HashSet<u32>,

    /// TIDs that were created via `PTRACE_EVENT_CLONE` (thread creation)
    /// rather than fork/vfork. These are still in `supervised` (they need
    /// ptrace management) but are not separate processes for process-tree
    /// tracking purposes.
    pub(crate) thread_tids: HashSet<u32>,

    /// Kernel thread-group identity captured while each TID is live.
    ///
    /// `/proc/<tid>/status` may disappear before `waitpid(2)` reports the
    /// exit. Retaining the last exact TGID prevents a thread-group leader's
    /// early exit from tearing down the shared DNS FD table while sibling
    /// threads are still running.
    pub(crate) tid_tgids: HashMap<u32, u32>,

    /// Exact, entry-time `clone`/`clone3` FD-sharing flags. `clone3` reads its
    /// flags from mutable tracee memory, so the snapshot must be taken at the
    /// seccomp stop before the kernel executes the syscall.
    pub(crate) pending_clone_fd_table: HashMap<u32, CloneFdTablePending>,

    /// Clone children whose own initial stop was observed before the parent's
    /// PTRACE_EVENT_* stop. These children remain stopped until FD-table
    /// inheritance has been installed.
    pub(crate) pending_child_initial_stops: HashSet<u32>,

    /// Tracks whether we are currently at a syscall-entry (`true`) or
    /// syscall-exit (`false`) stop for each traced PID.
    ///
    /// ptrace generates two stops per syscall (entry and exit). We only
    /// report events on syscall-entry because that is when we can still
    /// modify or cancel the syscall before the kernel executes it.
    ///
    /// Only used for the `PTRACE_SYSCALL` fallback path (attached
    /// processes without seccomp). Spawned processes use seccomp-BPF
    /// which delivers a single stop per syscall.
    pub(crate) in_syscall_entry: HashSet<u32>,

    /// Tracees using seccomp-BPF pre-filtering.
    ///
    /// Resume mode must be tracked per tracee rather than globally because a
    /// single supervisor can mix spawned processes (seccomp + `PTRACE_CONT`)
    /// and attached processes (`PTRACE_SYSCALL` fallback).
    pub(crate) seccomp_tracees: HashSet<u32>,

    /// SIGCHLD signal stream for event-driven waitpid.
    ///
    /// Initialized lazily on first `next_event()` call. When a child
    /// stops or exits, the kernel sends SIGCHLD to the parent. We await
    /// this signal instead of polling with a sleep loop, giving near-zero
    /// latency wakeups.
    pub(crate) sigchld: Option<tokio::signal::unix::Signal>,

    /// PID of the root supervised process (the one originally spawned or
    /// attached). When this process exits, the supervisor loop terminates
    /// immediately — orphaned children are cleaned up via `PTRACE_O_EXITKILL`.
    pub(crate) root_pid: Option<u32>,

    /// Wedge-detection bookkeeping: timestamp of the most recent ptrace
    /// event we've recorded for each supervised tid. Used by `wedge_scan`
    /// to identify tracees that have gone silent. Updated at every event
    /// boundary in `next_event` and at every `allow`/`deny`/`detach`.
    pub(crate) last_event_at: HashMap<u32, std::time::Instant>,

    /// Wedge-detection bookkeeping: short label of the last event recorded
    /// for each supervised tid (e.g. `"seccomp"`, `"stopped"`,
    /// `"ptrace-event:3"`). Carried into `WedgedTracee` forensic dumps so
    /// the investigator sees what we last saw the tracee do.
    pub(crate) last_event_kind: HashMap<u32, String>,

    /// Attach mechanism for spawned tracees. `Traceme` is the shipped path;
    /// `Seize` is scaffolded but not yet implemented (the spawn path returns
    /// a clear error for it). Set from config via `set_attach_mode` before
    /// the first spawn. See `work/futurework/ptrace-seize-migration.md`.
    pub(crate) attach_mode: crate::config::AttachMode,

    /// Wedge forensics: the ptrace resume primitive last issued for each tid —
    /// `"CONT"` (PTRACE_CONT, seccomp path) or `"SYSCALL"` (PTRACE_SYSCALL,
    /// fallback/attach path). Recorded in `resume_tracee`; surfaced in
    /// `WedgedTracee`. Discriminates the clone-child wrong-primitive race: a
    /// wedged freshly-cloned child showing `"SYSCALL"` was resumed before its
    /// seccomp membership was registered (the H1 fingerprint).
    pub(crate) last_resume_primitive: HashMap<u32, &'static str>,

    /// True when the supervised root was spawned with a TSYNC'd seccomp-BPF
    /// filter (the `grith exec` path). Because TSYNC propagates the filter to
    /// every thread and `fork`/`clone` child, ALL tracees in such a session
    /// must be resumed with `PTRACE_CONT`, not `PTRACE_SYSCALL`. Resuming a
    /// per-tid decision on `seccomp_tracees` set-membership races the clone
    /// window (a child's own stop can be handled before its parent's CLONE
    /// event registers it), which wedged clone children on `PTRACE_SYSCALL`.
    /// `false` for attach-without-seccomp sessions, which keep the
    /// `PTRACE_SYSCALL` fallback path.
    pub(crate) seccomp_session: bool,

    /// Process/FD-table scoped socket, resolver, transaction and lifecycle
    /// state. This is deliberately not keyed by TID: threads share FDs.
    pub(crate) dns_tracker: dns_socket_tracker::DnsSocketTracker,

    /// Per-tid receive-exit bookkeeping for tracked DNS sockets.
    pub(crate) pending_dns_recv_exit: HashMap<u32, DnsRecvPending>,

    /// Per-tid transaction for a connected UDP/53 peer rewritten to a pending
    /// proxy route. The original tracee sockaddr must be restored at every
    /// terminal path before user code or a signal handler can run.
    pub(crate) pending_dns_connect_exit: HashMap<u32, DnsConnectPending>,

    /// Successful-exit tracking for ordinary UDP connect/reconnect/disconnect.
    /// This prevents a failed connect from corrupting shared socket state.
    pub(crate) pending_udp_connect_exit: HashMap<u32, UdpConnectPending>,

    /// Threads temporarily stepped with `PTRACE_SYSCALL` so `write(2)` and
    /// `writev(2)` on a connected datagram socket become visible.
    ///
    /// `write`/`read` are deliberately outside the seccomp trap set — they are
    /// the hottest syscalls in any workload — so a
    /// `socket(SOCK_DGRAM) → connect(attacker) → write(fd, secret)` sequence
    /// egressed with no evaluation and no audit record (go-live review B13).
    /// A seccomp filter cannot be narrowed to "trap write on fd 7" after
    /// install, so the fd-specific check has to happen in the tracer.
    ///
    /// Stepping is deliberately short-lived: it starts when a datagram socket
    /// connects to a **non-loopback** destination and ends as soon as the
    /// destination has been evaluated and allowed. See
    /// [`ConnectedDgramStepping`].
    pub(crate) stepping: HashMap<u32, ConnectedDgramStepping>,

    /// Shared DNS cache (IP → domain) for egress correlation. `None` disables
    /// in-line DNS inspection (no query parsing, no response observation).
    pub(crate) dns_cache: Option<std::sync::Arc<std::sync::Mutex<crate::dns_cache::DnsCache>>>,

    /// Whether to observe DNS responses via targeted receive-exit promotion.
    /// Query inspection/blocking does not depend on this — it gates only the
    /// exact-IP cache population, so the one syscall-exit promotion (the
    /// wedge-class-sensitive part) can be disabled without losing query
    /// blocking.
    pub(crate) dns_observe_responses: bool,

    /// Per-tid result from inspecting every query carried by one DNS send,
    /// consumed by the event handler before that syscall is resumed.
    pub(crate) pending_dns_query: HashMap<u32, crate::interceptor::DnsQueryInspection>,

    /// Response-correlation records staged for an in-line DNS send. They are
    /// retained only if the policy owner allows the syscall.
    pub(crate) pending_inline_dns_transactions: HashMap<u32, PendingInlineDnsTransactions>,

    /// Per-tid bookkeeping for a promoted `socket()`: the socket is `SOCK_STREAM`
    /// (`true`) or not, awaiting the exit stop to learn the returned fd.
    pub(crate) pending_socket_exit: HashMap<u32, SocketPending>,

    /// Descriptor lifecycle syscalls promoted to an exit stop so failed
    /// close/dup operations cannot corrupt tracker state.
    pub(crate) pending_fd_exit: HashMap<u32, FdLifecyclePending>,

    /// tids whose current `connect` to `:53` is on a stream socket and must be
    /// denied by the event handler (TCP-DNS block). Consumed via
    /// `take_tcp_dns_deny`.
    pub(crate) pending_tcp_dns_deny: HashSet<u32>,

    /// Deny TCP-DNS (force the inspected UDP path). Since TCP-DNS can't be
    /// content-inspected, allowing it would leave query blocking bypassable.
    pub(crate) block_tcp_dns: bool,

    /// Session-local connected UDP DNS data-plane control. `None` retains the
    /// current in-line-only behaviour.
    pub(crate) connected_dns_proxy: Option<crate::connected_dns_proxy::ConnectedDnsProxyControl>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SocketPending {
    pub tgid: u32,
    pub socket_type: dns_socket_tracker::SocketType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CloneFdTablePending {
    pub syscall_nr: i64,
    pub flags: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingInlineDnsTransactions {
    pub socket_id: dns_socket_tracker::SocketId,
    pub queries: Vec<dns_socket_tracker::QueryMetadata>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum FdLifecyclePending {
    Close {
        tgid: u32,
        fd: i32,
    },
    CloseRange {
        tgid: u32,
        first: u32,
        last: u32,
    },
    Dup {
        tgid: u32,
        source_socket: Option<dns_socket_tracker::SocketId>,
    },
}

impl FdLifecyclePending {
    pub(crate) fn held_socket(self) -> Option<dns_socket_tracker::SocketId> {
        match self {
            Self::Dup { source_socket, .. } => source_socket,
            Self::Close { .. } | Self::CloseRange { .. } => None,
        }
    }
}

/// Entry-time bookkeeping for a promoted DNS receive syscall.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DnsRecvPending {
    pub tgid: u32,
    pub fd: i32,
    pub socket_id: dns_socket_tracker::SocketId,
    pub kind: DnsRecvKind,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum DnsRecvKind {
    From { buf_ptr: u64, buf_len: usize },
    Msg { msghdr_ptr: u64 },
    Mmsg { msgvec_ptr: u64, vlen: usize },
}

pub(crate) struct DnsConnectPending {
    pub tgid: u32,
    pub fd: i32,
    pub socket_id: dns_socket_tracker::SocketId,
    pub original_resolver: std::net::SocketAddr,
    pub route: crate::connected_dns_proxy::PendingDnsRoute,
    pub sockaddr: dns_redirect::SavedSockaddr,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UdpConnectPending {
    pub socket_id: dns_socket_tracker::SocketId,
    /// `None` represents a successful `connect(AF_UNSPEC)` disconnect.
    pub destination: Option<std::net::SocketAddr>,
    /// The fd being connected, captured at the entry stop. Used at exit to
    /// start or stop connected-datagram write stepping (go-live review B13).
    pub fd: i32,
}

/// Why a thread is being stepped, and when it can stop being stepped
/// (go-live review B13).
///
/// Stepping costs two ptrace stops per syscall on that thread, which is the
/// wedge-sensitive dance that once made supervising Claude Code on Bun ~150x
/// slower. The window is therefore bounded on both ends:
///
/// * It **opens** only when a datagram socket connects to a non-loopback
///   destination. Loopback traffic — DNS to `127.0.0.53`, local services — is
///   the bulk of connected-UDP volume and never steps.
/// * It **closes** as soon as the destination has been evaluated and allowed,
///   because the decision is then cached for the session and later writes to
///   the same destination would re-derive it. A QUIC client pays stepping for
///   the handful of syscalls between connect and first write, then runs at
///   full speed.
///
/// If the write is *denied*, stepping continues: the thread has demonstrated
/// intent to egress to a destination policy rejected, and every subsequent
/// write must be rejected too.
///
/// `getaddrinfo`'s RFC-3484 source-selection probe (connect → getsockname →
/// close, no data) stays prompt-free: no write ever occurs, so nothing is
/// scored, and the close demotes. That path is the reason connected-datagram
/// `connect` itself is not scored, and this preserves it.
#[derive(Debug, Clone, Default)]
pub(crate) struct ConnectedDgramStepping {
    /// Every connected non-loopback datagram fd the process currently holds.
    /// A set, not one fd: a process may connect several sockets, and tracking
    /// only the most recent would silently un-cover the earlier ones.
    pub fds: HashSet<i32>,
    /// Threads whose surfaced write is awaiting a proxy decision. An `allow`
    /// for one of these ends stepping for the fd it named; a `deny` clears
    /// the entry but keeps stepping, because a thread that has tried to reach
    /// a rejected destination will try again.
    pub awaiting: HashMap<u32, i32>,
}

impl PtraceSupervisor {
    /// Create a new `PtraceSupervisor` with no attached processes.
    pub fn new() -> Self {
        Self {
            supervised: HashSet::new(),
            thread_tids: HashSet::new(),
            tid_tgids: HashMap::new(),
            pending_clone_fd_table: HashMap::new(),
            pending_child_initial_stops: HashSet::new(),
            in_syscall_entry: HashSet::new(),
            seccomp_tracees: HashSet::new(),
            sigchld: None,
            root_pid: None,
            last_event_at: HashMap::new(),
            last_event_kind: HashMap::new(),
            attach_mode: crate::config::AttachMode::Traceme,
            last_resume_primitive: HashMap::new(),
            seccomp_session: false,
            dns_tracker: dns_socket_tracker::DnsSocketTracker::new(),
            pending_dns_recv_exit: HashMap::new(),
            pending_dns_connect_exit: HashMap::new(),
            pending_udp_connect_exit: HashMap::new(),
            stepping: HashMap::new(),
            dns_cache: None,
            dns_observe_responses: false,
            pending_dns_query: HashMap::new(),
            pending_inline_dns_transactions: HashMap::new(),
            pending_socket_exit: HashMap::new(),
            pending_fd_exit: HashMap::new(),
            pending_tcp_dns_deny: HashSet::new(),
            block_tcp_dns: false,
            connected_dns_proxy: None,
        }
    }

    /// Enable in-line DNS inspection with the shared cache. Called by the
    /// supervisor wiring after the interceptor is created and before the loop.
    pub(crate) fn enable_dns_inspection(
        &mut self,
        cache: std::sync::Arc<std::sync::Mutex<crate::dns_cache::DnsCache>>,
        observe_responses: bool,
        block_tcp_dns: bool,
    ) {
        self.dns_cache = Some(cache);
        self.dns_observe_responses = observe_responses;
        self.block_tcp_dns = block_tcp_dns;
    }

    pub(crate) fn enable_connected_dns_proxy(
        &mut self,
        control: crate::connected_dns_proxy::ConnectedDnsProxyControl,
    ) {
        self.connected_dns_proxy = Some(control);
    }

    /// Spawn a supervised process inside a PTY.
    ///
    /// Combines ptrace `PTRACE_TRACEME` with PTY setup so the child
    /// gets a real terminal while being traced from birth (avoiding
    /// `PTRACE_ATTACH` and YAMA restrictions).
    pub async fn spawn_supervised_pty(
        &mut self,
        command: &str,
        args: &[String],
        env: &[(String, String)],
        cols: u16,
        rows: u16,
    ) -> crate::error::Result<child::PtySpawnResult> {
        child::do_spawn_supervised_pty(self, command, args, env, cols, rows).await
    }
}

impl Default for PtraceSupervisor {
    fn default() -> Self {
        Self::new()
    }
}
