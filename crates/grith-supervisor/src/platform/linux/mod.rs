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
mod classify;
mod events;
pub(crate) mod seccomp;

use std::collections::HashSet;

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
    /// `chmod(pathname, mode)` -- change file permissions.
    pub const CHMOD: i64 = 90;
    /// `getdents64(fd, dirp, count)` -- read directory entries.
    pub const GETDENTS64: i64 = 217;
    /// `openat(dirfd, pathname, flags, mode)` -- open a file relative to a directory fd.
    pub const OPENAT: i64 = 257;
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
}

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
    // io_uring: ring-buffer I/O bypasses per-syscall ptrace stops entirely.
    // All three syscalls are intercepted so the ring cannot be created,
    // used, or configured. io_uring_setup is the critical gate — blocking it
    // prevents ring creation; the others are defence-in-depth.
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
}

impl PtraceSupervisor {
    /// Create a new `PtraceSupervisor` with no attached processes.
    pub fn new() -> Self {
        Self {
            supervised: HashSet::new(),
            thread_tids: HashSet::new(),
            in_syscall_entry: HashSet::new(),
            seccomp_tracees: HashSet::new(),
            sigchld: None,
            root_pid: None,
        }
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
