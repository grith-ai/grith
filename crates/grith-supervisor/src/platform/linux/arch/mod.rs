// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Architecture seam for the Linux ptrace backend.
//!
//! Everything above this module — the event loop, classify semantics, DNS
//! stepping, fd/socket tracking, suppressions — is arch-neutral and shared.
//! Everything that knows a register name, a `PTRACE_GETREGS`-vs-`GETREGSET`
//! calling convention, or how to skip a syscall on a given CPU lives behind
//! the free functions re-exported here from the per-arch module.
//!
//! # The primary source: `PTRACE_GET_SYSCALL_INFO`
//!
//! On kernels >= 5.3, [`get_syscall_info`] returns the kernel's own record of
//! a stopped tracee's syscall: the audit arch, the number, all six arguments
//! (entry/seccomp stops) and the return value (exit stops) — with an
//! arch-independent layout. [`read_syscall_regs`] and [`read_return_value`]
//! prefer it and fall back to per-arch register reads only when the record is
//! unavailable (pre-5.3 kernels, or stops that carry no syscall record such
//! as `PTRACE_EVENT_FORK`/`CLONE` stops, where the per-arch registers still
//! hold the entry-time values).
//!
//! # What is deliberately NOT here
//!
//! Tracee memory access (`PTRACE_PEEKDATA`/`POKEDATA` word loops) is portable
//! on every LP64 Linux target and stays in the shared code. The OS seam
//! (`SyscallInterceptor` / `SyscallKind`) is a different boundary entirely —
//! macOS/Windows backends never see this module.

#![cfg(target_os = "linux")]

use nix::libc;
use nix::unistd::Pid;

use crate::error::Result;

// Both per-arch modules compile on every architecture — the identity tables
// are plain data whose integrity tests should run everywhere (an x86 host
// validates the aarch64 table and vice versa). Only each module's ptrace
// register primitives are gated to its own arch, and only the native
// module's symbols are re-exported here.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) mod x86_64;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::{
    deny_syscall, nr_of, read_raw_syscall_nr, read_return_value_fallback,
    read_syscall_regs_fallback, sys_id, NATIVE_AUDIT_ARCH,
};

#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) mod aarch64;
#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::{
    deny_syscall, nr_of, read_raw_syscall_nr, read_return_value_fallback,
    read_syscall_regs_fallback, sys_id, NATIVE_AUDIT_ARCH,
};

// Native number constants: production code keys on [`SysId`]; the constants
// are consumed only by in-crate tests (numeric pinning, sample events).
#[cfg(test)]
#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::syscall_nr;
#[cfg(test)]
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::syscall_nr;

// ---------------------------------------------------------------------------
// Arch-neutral view of a stopped tracee's syscall
// ---------------------------------------------------------------------------

/// Arch-neutral view of a syscall stop, built once per stop.
///
/// `nr` is the raw **native** syscall number (meaningful only on the arch the
/// binary was built for); `args` are the six syscall arguments in ABI order.
/// Classification code reads `args[N]` and never a register name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct SyscallRegs {
    /// Raw native syscall number (entry/seccomp stops).
    pub nr: i64,
    /// The six syscall arguments in ABI order.
    pub args: [u64; 6],
    /// Instruction pointer at the stop (forensics only).
    pub ip: u64,
    /// Stack pointer at the stop (forensics only).
    pub sp: u64,
    /// The return-value register, populated ONLY when the per-arch register
    /// file was the source (pre-5.3 fallback; `PTRACE_EVENT_*` stops). The
    /// kernel's entry/seccomp record carries no return value, and no caller
    /// needs one when that record is available. Exists so the pre-5.3
    /// entry/exit heuristic (`retval == -ENOSYS` at entry) reads the same
    /// register fetch as the arguments — a second fetch would race tracee
    /// death and change which forensics path a dying thread takes.
    pub retval_hint: Option<i64>,
}

// ---------------------------------------------------------------------------
// PTRACE_GET_SYSCALL_INFO — the shared, arch-portable primary source
// ---------------------------------------------------------------------------

/// `ptrace(2)` request number for `PTRACE_GET_SYSCALL_INFO` (kernel >= 5.3).
const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;

/// `ptrace_syscall_info.op` values (uapi/linux/ptrace.h).
pub(crate) const PTRACE_SYSCALL_INFO_ENTRY: u8 = 1;
pub(crate) const PTRACE_SYSCALL_INFO_EXIT: u8 = 2;
pub(crate) const PTRACE_SYSCALL_INFO_SECCOMP: u8 = 3;

/// `struct ptrace_syscall_info`, flattened.
///
/// The kernel struct ends in a union; both the ENTRY and SECCOMP variants
/// place `nr` then `args[6]` at the same offsets, and the EXIT variant places
/// `rval` where `nr` sits. `data` therefore reads as:
///
/// - entry/seccomp stop: `data[0]` = syscall nr, `data[1..7]` = args.
/// - exit stop: `data[0]` = `rval` (as `i64`), low byte of `data[1]` =
///   `is_error`.
///
/// The seccomp variant's trailing `ret_data` field is deliberately not read:
/// `SECCOMP_RET_DATA` is forgeable by a tracee-installed filter and grith
/// never trusts it on >= 5.3 kernels.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RawSyscallInfo {
    pub op: u8,
    _pad: [u8; 3],
    pub arch: u32,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub data: [u64; 7],
}

/// Outcome of a `PTRACE_GET_SYSCALL_INFO` request.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SyscallInfoResult {
    /// The kernel answered; inspect `op` to learn what kind of stop this is.
    Info(RawSyscallInfo),
    /// The tracee died in its stop (ESRCH) — there is no record to read, and
    /// that is NOT a licence to guess from weaker sources.
    TraceeGone,
    /// The request itself is unknown (pre-5.3 kernel, EIO).
    Unsupported,
}

/// Ask the kernel for its own record of the current stop.
///
/// This is the one source of syscall identity no tracee-installed seccomp
/// filter can influence, and its layout is identical on every architecture.
pub(crate) fn get_syscall_info(pid: Pid) -> SyscallInfoResult {
    let mut info = RawSyscallInfo::default();
    // SAFETY: `info` is a live, correctly-aligned allocation and we pass its
    // exact size; the kernel writes at most that many bytes.
    let ret = unsafe {
        libc::ptrace(
            // `as _` so the request adapts to `libc::ptrace`'s first argument
            // type, which is `c_uint` on glibc but `c_int` on musl — the
            // mismatch that failed the musl release build.
            PTRACE_GET_SYSCALL_INFO as _,
            pid.as_raw(),
            std::mem::size_of::<RawSyscallInfo>(),
            std::ptr::addr_of_mut!(info),
        )
    };
    if ret <= 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            SyscallInfoResult::TraceeGone
        } else {
            SyscallInfoResult::Unsupported
        };
    }
    SyscallInfoResult::Info(info)
}

/// Verify the running kernel supports this backend, probed against a
/// stopped tracee at session start.
///
/// x86_64 keeps its 4.8+ floor: `PTRACE_GET_SYSCALL_INFO` is preferred but
/// the pre-5.3 register fallbacks cover its absence, so the probe is a
/// no-op. aarch64 has no such fallbacks — the pre-5.3 paths are x86-shaped
/// (`rax == -ENOSYS` reads an *argument* on arm64) and are compiled out —
/// so a kernel that cannot answer `PTRACE_GET_SYSCALL_INFO` is refused with
/// a clear error instead of degrading into misclassification.
pub(crate) fn verify_kernel_support(pid: Pid) -> Result<()> {
    #[cfg(target_arch = "aarch64")]
    if matches!(get_syscall_info(pid), SyscallInfoResult::Unsupported) {
        return Err(crate::error::Error::InterceptionError(
            "aarch64 supervision requires PTRACE_GET_SYSCALL_INFO (Linux kernel 5.3 or newer); \
             this kernel does not support it"
                .into(),
        ));
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = pid;
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared readers (primary source + per-arch fallback)
// ---------------------------------------------------------------------------

/// Read the syscall number and arguments of a stopped tracee.
///
/// Prefers the kernel's `PTRACE_GET_SYSCALL_INFO` entry/seccomp record; falls
/// back to per-arch register reads when the record is unavailable — a pre-5.3
/// kernel, or a stop with no syscall record (`PTRACE_EVENT_FORK`/`CLONE`
/// stops), where the registers still hold the entry-time values.
///
/// Returns `Ok(None)` when the tracee no longer exists (ESRCH). A tracee can
/// be SIGKILLed — including by a sibling thread's `exit_group(2)` — even
/// while sitting in a ptrace stop, so a queued wait status can outlive its
/// thread. That race is benign and must never end the session.
pub(crate) fn read_syscall_regs(pid: Pid) -> Result<Option<SyscallRegs>> {
    match get_syscall_info(pid) {
        SyscallInfoResult::Info(info)
            if info.op == PTRACE_SYSCALL_INFO_ENTRY || info.op == PTRACE_SYSCALL_INFO_SECCOMP =>
        {
            Ok(Some(SyscallRegs {
                nr: info.data[0] as i64,
                args: [
                    info.data[1],
                    info.data[2],
                    info.data[3],
                    info.data[4],
                    info.data[5],
                    info.data[6],
                ],
                ip: info.instruction_pointer,
                sp: info.stack_pointer,
                retval_hint: None,
            }))
        }
        SyscallInfoResult::TraceeGone => {
            tracing::trace!(
                pid = pid.as_raw(),
                event = "tracee_gone_at_stop",
                "PTRACE_GET_SYSCALL_INFO: tracee gone (ESRCH); treating stop as stale"
            );
            Ok(None)
        }
        // Exit stop, non-syscall stop, or pre-5.3 kernel: the per-arch
        // registers are the (only) honest source left.
        SyscallInfoResult::Info(_) | SyscallInfoResult::Unsupported => {
            read_syscall_regs_fallback(pid)
        }
    }
}

/// Read the return value of the syscall a tracee just completed (exit stop).
///
/// Prefers the `PTRACE_GET_SYSCALL_INFO` EXIT record; falls back to the
/// per-arch return-value register. `Ok(None)` = tracee gone (ESRCH).
pub(crate) fn read_return_value(pid: Pid) -> Result<Option<i64>> {
    match get_syscall_info(pid) {
        SyscallInfoResult::Info(info) if info.op == PTRACE_SYSCALL_INFO_EXIT => {
            Ok(Some(info.data[0] as i64))
        }
        SyscallInfoResult::TraceeGone => {
            tracing::trace!(
                pid = pid.as_raw(),
                event = "tracee_gone_at_stop",
                "PTRACE_GET_SYSCALL_INFO: tracee gone (ESRCH); treating stop as stale"
            );
            Ok(None)
        }
        SyscallInfoResult::Info(_) | SyscallInfoResult::Unsupported => {
            read_return_value_fallback(pid)
        }
    }
}

// ---------------------------------------------------------------------------
// Portable syscall identity
// ---------------------------------------------------------------------------

/// Portable identity of every syscall grith knows about.
///
/// Classification and the event loop match on THIS, never on raw numbers —
/// raw numbers collide across architectures (167 is `swapon` on x86_64 but
/// `prctl` on aarch64; 56 is `clone` on x86_64 but `openat` on aarch64), so
/// a leaked number would classify as a *different, wrong* syscall rather
/// than failing. Raw native numbers are confined to the per-arch tables;
/// [`sys_id`] / [`nr_of`] convert at the boundary, and `nr_of` returns
/// `None` for syscalls the current architecture does not have (the legacy
/// non-`at` family and iopl/ioperm are x86_64-only).
///
/// The per-variant commentary is the curated security rationale for
/// intercepting each syscall; it is arch-neutral and lives here so the
/// per-arch tables stay bare number lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SysId {
    /// `read(fd, buf, count)` -- read from a file descriptor.
    Read,
    /// `write(fd, buf, count)` -- write to a file descriptor.
    Write,
    /// `writev(fd, iov, iovcnt)` -- gathered write to a file descriptor.
    ///
    /// Like `WRITE`, deliberately outside the seccomp trap set; both are
    /// surfaced only for threads stepped under `ConnectedDgramStepping`, where
    /// a write to a connected datagram socket is an egress the proxy must
    /// judge (go-live review B13).
    Writev,
    /// `close(fd)` -- close a descriptor.
    Close,
    /// `open(pathname, flags, mode)` -- legacy file open (prefer `openat`).
    Open,
    /// `mmap(addr, length, prot, flags, fd, offset)` -- map files or devices into memory.
    ///
    /// Only file-backed mmaps (fd >= 0, !MAP_ANONYMOUS) are security-relevant.
    /// Anonymous allocations (fd == -1 or MAP_ANONYMOUS set) are passed through without
    /// interception to avoid unacceptable overhead (mmap is called very frequently for
    /// heap/stack allocations).
    Mmap,
    /// `pipe(pipefd)` -- create a unidirectional pipe.
    Pipe,
    /// `socket(domain, type, protocol)` -- create an endpoint for communication.
    ///
    /// Intercepted to catch raw-socket creation (AF_PACKET=17, AF_NETLINK=16)
    /// at the earliest possible point — before any data is sent. AF_PACKET
    /// sockets bypass the normal IP stack and can capture or inject arbitrary
    /// link-layer frames, making them a high-severity capability. Normal
    /// sockets (AF_INET, AF_INET6, AF_UNIX) are filtered out in classify_syscall
    /// and intercepted later at connect()/bind() instead.
    Socket,
    /// `connect(sockfd, addr, addrlen)` -- initiate a network connection.
    Connect,
    /// `sendto(sockfd, buf, len, flags, dest_addr, addrlen)` -- send a datagram.
    Sendto,
    /// `recvfrom(sockfd, buf, len, flags, src_addr, addrlen)` -- receive a
    /// datagram. Trapped for in-line DNS response observation (glibc/c-ares read
    /// DNS answers via recvfrom; the buffer is kernel-filled, so it is read at
    /// syscall *exit*).
    Recvfrom,
    /// `sendmsg(sockfd, msg, flags)` -- send a message. Trapped for in-line DNS
    /// query inspection (some resolvers send via sendmsg).
    Sendmsg,
    /// `recvmsg(sockfd, msg, flags)` -- receive a message.
    Recvmsg,
    /// `dup(oldfd)` -- duplicate a descriptor.
    Dup,
    /// `dup2(oldfd, newfd)` -- duplicate to a selected descriptor.
    Dup2,
    /// `fcntl(fd, cmd, ...)` -- descriptor control, including `F_DUPFD*`.
    Fcntl,
    /// `sendmmsg(sockfd, msgvec, vlen, flags)` -- send multiple messages in one
    /// call. Trapped for in-line DNS query inspection: glibc `getaddrinfo`
    /// batches the A + AAAA queries into a single `sendmmsg`.
    Sendmmsg,
    /// `recvmmsg(sockfd, msgvec, vlen, flags, timeout)` -- receive a batch.
    Recvmmsg,
    /// `dup3(oldfd, newfd, flags)` -- duplicate with flags.
    Dup3,
    /// `close_range(first, last, flags)` -- close a descriptor interval.
    CloseRange,
    /// `clone3(args, size)` -- modern process/thread creation. Like `clone`,
    /// this is observed through `PTRACE_EVENT_CLONE`, not seccomp.
    Clone3,
    /// `seccomp(op, flags, args)` -- install a seccomp filter.
    ///
    /// Trapped so a supervised process cannot install its own filter that
    /// out-ranks grith's. `SECCOMP_RET_USER_NOTIF` (0x7fc00000) beats grith's
    /// `SECCOMP_RET_TRACE` (0x7ff00000) in seccomp action precedence (lowest
    /// value wins), so a tracee that adds a `NEW_LISTENER` filter and answers
    /// its own notifications with `USER_NOTIF_FLAG_CONTINUE` executes syscalls
    /// grith never sees. Denying the `NEW_LISTENER` install closes that
    /// escape (go-live review, round-2 finding).
    Seccomp,
    /// `prctl(option, ...)` -- trapped only to catch
    /// `PR_SET_SECCOMP(SECCOMP_MODE_FILTER)`, the legacy filter-install path.
    /// It has no flags argument and so cannot create a listener, but it is
    /// still the route by which a tracee could install an audit-blinding
    /// `ERRNO`/`TRAP` filter, so it is surfaced for observation.
    Prctl,
    /// `bind(sockfd, addr, addrlen)` -- bind a socket to an address.
    Bind,
    /// `socketpair(domain, type, protocol, sv)` -- create a pair of connected sockets.
    Socketpair,
    /// `clone(flags, stack, ...)` -- create a child process or thread.
    Clone,
    /// `fork()` -- create a child process (legacy; typically uses `clone`).
    Fork,
    /// `execve(pathname, argv, envp)` -- execute a program.
    Execve,
    /// `rename(oldpath, newpath)` -- rename a file (legacy; prefer `renameat2`).
    Rename,
    /// `mkdir(pathname, mode)` -- create a directory.
    Mkdir,
    /// `unlink(pathname)` -- delete a file.
    Unlink,
    /// `rmdir(pathname)` -- remove a directory.
    Rmdir,
    /// `chmod(pathname, mode)` -- change file permissions.
    Chmod,
    /// `fchmod(fd, mode)` -- change file permissions by fd.
    Fchmod,
    /// `getdents64(fd, dirp, count)` -- read directory entries.
    Getdents64,
    /// `openat(dirfd, pathname, flags, mode)` -- open a file relative to a directory fd.
    Openat,
    /// `openat2(dirfd, pathname, how, size)` -- open with an extensible
    /// `struct open_how` instead of a flags word (kernel 5.6+).
    ///
    /// Functionally equivalent to `openat` for policy purposes, and one
    /// `syscall()` away in Python/Go/Rust — without it, file policy is
    /// bypassed by choosing a different open syscall.
    Openat2,
    /// `creat(pathname, mode)` -- legacy create; equivalent to
    /// `open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`.
    Creat,
    /// `truncate(pathname, length)` -- resize a file by path. A destructive
    /// write that never goes through `open`/`write`.
    Truncate,
    /// `ftruncate(fd, length)` -- resize a file by descriptor.
    Ftruncate,
    /// `symlink(target, linkpath)` -- create a symbolic link.
    ///
    /// Link creation is scored by its *target*: `ln -s ~/.ssh/id_rsa /tmp/x`
    /// followed by reading `/tmp/x` launders a sensitive path past any
    /// path-string filter, so the creation itself is the control point.
    Symlink,
    /// `symlinkat(target, newdirfd, linkpath)` -- create a symlink relative
    /// to a directory fd.
    Symlinkat,
    /// `link(oldpath, newpath)` -- create a hard link. Same laundering
    /// concern as `symlink`, and a hard link survives deletion of the
    /// original name.
    Link,
    /// `linkat(olddirfd, oldpath, newdirfd, newpath, flags)` -- create a
    /// hard link relative to directory fds.
    Linkat,
    /// `mkdirat(dirfd, pathname, mode)` -- create a directory relative to a directory fd.
    Mkdirat,
    /// `unlinkat(dirfd, pathname, flags)` -- delete a file relative to a directory fd.
    Unlinkat,
    /// `renameat(olddirfd, oldpath, newdirfd, newpath)` -- rename relative to directory fds.
    Renameat,
    /// `fchmodat(dirfd, pathname, mode, flags)` -- change permissions relative to a directory fd.
    Fchmodat,
    /// `pipe2(pipefd, flags)` -- create a pipe with `O_CLOEXEC`/`O_NONBLOCK`.
    Pipe2,
    /// `renameat2(olddirfd, oldpath, newdirfd, newpath, flags)` -- rename with flags.
    Renameat2,
    /// `io_uring_setup(entries, params)` -- create an io_uring context.
    ///
    /// io_uring operations bypass per-syscall ptrace stops: I/O submitted via
    /// the ring buffer executes without individual entry stops. Grith denies
    /// this syscall so supervised processes cannot obtain invisible I/O channels.
    IoUringSetup,
    /// `io_uring_enter(fd, to_submit, min_complete, flags, sig)` -- submit/wait for io_uring operations.
    IoUringEnter,
    /// `io_uring_register(fd, opcode, arg, nr_args)` -- register buffers/files with io_uring.
    IoUringRegister,
    /// `sendfile(out_fd, in_fd, offset, count)` -- copy between file descriptors in kernel space.
    ///
    /// sendfile transfers data directly from `in_fd` to `out_fd` without passing through
    /// userspace buffers. A process can open a sensitive file then sendfile its contents
    /// directly to a network socket, bypassing write()/sendto() interception entirely.
    Sendfile,
    /// `splice(fd_in, off_in, fd_out, off_out, len, flags)` -- move data between fds via pipe.
    ///
    /// splice moves data between two file descriptors via an in-kernel pipe buffer,
    /// also bypassing userspace. Used to exfiltrate data without a write() syscall.
    Splice,
    /// `tee(fd_in, fd_out, len, flags)` -- duplicate pipe data without consuming it.
    ///
    /// tee copies data between two pipe file descriptors in kernel space. Lower risk
    /// than sendfile/splice (pipe-to-pipe only) but tracked for completeness.
    Tee,
    /// `execveat(dirfd, pathname, argv, envp, flags)` -- execute a program
    /// relative to a directory file descriptor.
    ///
    /// Similar to `execve` but resolves `pathname` relative to `dirfd`. Also
    /// used by glibc's `fexecve()`. Must be intercepted alongside `execve` to
    /// prevent bypassing exec provenance checks.
    Execveat,
    /// PR 6 Phase A: kernel-module load. Loads an ELF module from a
    /// user-space buffer into the running kernel — has no legitimate
    /// use in supervised AI tools.
    InitModule,
    /// PR 6 Phase A: kernel-module load from a file descriptor.
    /// Sibling of `init_module`; equally privileged.
    FinitModule,
    /// PR 6 Phase A: kernel-module unload. Symmetric to `init_module`
    /// — supervised tools should not be removing kernel modules.
    DeleteModule,
    /// PR 6 Phase A: replace the running kernel with a new image at
    /// the next reboot. The "atomic boot kit" syscall — no legitimate
    /// use in dev tools.
    KexecLoad,
    /// PR 6 Phase A: kexec from a file descriptor. Sibling of
    /// `kexec_load`.
    KexecFileLoad,
    // ── PR 6 Phase B: ownership change family ──
    /// `chown(path, uid, gid)` — change file owner/group by path.
    Chown,
    /// `fchown(fd, uid, gid)` — change file owner/group by fd.
    Fchown,
    /// `lchown(path, uid, gid)` — like `chown` but doesn't follow symlinks.
    Lchown,
    /// `fchownat(dirfd, path, uid, gid, flags)` — change owner/group
    /// relative to a directory fd.
    Fchownat,
    // ── PR 6 Phase B: filesystem mutation family ──
    /// `mount(src, target, fstype, flags, data)` — mount a filesystem.
    Mount,
    /// `umount2(target, flags)` — unmount with flags. x86_64 has no
    /// separate `umount`; `umount2` covers both shapes.
    Umount2,
    /// `pivot_root(new_root, put_old)` — change the root filesystem.
    PivotRoot,
    /// `chroot(path)` — change the process root directory.
    Chroot,
    /// `open_tree(dfd, filename, flags)` — clone/open a mount tree.
    OpenTree,
    /// `move_mount(from_dfd, from_pathname, to_dfd, to_pathname, flags)`.
    MoveMount,
    /// `fsopen(fs_name, flags)` — create a new filesystem context.
    Fsopen,
    /// `fsconfig(fd, cmd, key, value, aux)` — configure a filesystem context.
    Fsconfig,
    /// `fsmount(fd, flags, ms_flags)` — create a mount from a filesystem context.
    Fsmount,
    /// `fspick(dfd, path, flags)` — select a mount for reconfiguration.
    Fspick,
    /// `mount_setattr(dfd, path, flags, attr, size)` — change mount attributes.
    MountSetattr,
    // ── PR 6 Phase B: cross-process access family ──
    /// `ptrace(request, pid, addr, data)` — attach/detach/read/write
    /// memory of another process.
    Ptrace,
    /// `process_vm_readv(pid, local_iov, ..., remote_iov, ...)` — read
    /// memory directly from another process.
    ProcessVmReadv,
    /// `process_vm_writev(pid, local_iov, ..., remote_iov, ...)` —
    /// write memory directly into another process.
    ProcessVmWritev,
    /// `pidfd_getfd(pidfd, targetfd, flags)` — steal a live file descriptor
    /// out of the process referenced by `pidfd` (ptrace access mode required).
    /// Same cross-boundary secret-theft class as `process_vm_readv`; the target
    /// pid is resolved from the pidfd's `/proc/<pid>/fdinfo/<fd>` `Pid:` field.
    PidfdGetfd,
    // ── PR 6 Phase C: namespace primitives ──
    /// `unshare(flags)` — disassociate parts of the caller's execution
    /// context (mount/uts/pid/net/user/ipc/cgroup namespaces).
    Unshare,
    /// `setns(fd, nstype)` — re-associate the caller with the namespace
    /// referred to by `fd`.
    Setns,
    // ── PR 6 Phase D: architecture-specific privileged ops ──
    // All hard-denied unconditionally. Each represents a host-wide
    // authority change that no supervised AI tool has any reason to
    // attempt; if a tool is calling these, it's either a bug or an
    // exploit. The supervisor blocks at the source.
    /// `sethostname(name, len)` — set the system hostname. Global
    /// identity change visible to every other process on the host.
    Sethostname,
    /// `setdomainname(name, len)` — set the NIS domain name.
    /// Same shape as `sethostname`.
    Setdomainname,
    /// `iopl(level)` — set the I/O privilege level (x86 only).
    /// Grants direct access to all I/O ports. Hard-deny.
    Iopl,
    /// `ioperm(from, num, turn_on)` — toggle access to specific
    /// I/O ports (x86 only). Same threat as `iopl`.
    Ioperm,
    /// `swapon(path, flags)` — bring a swap area online.
    /// Kernel resource-management; no dev-tool use.
    Swapon,
    /// `swapoff(path)` — disable a swap area.
    Swapoff,
    /// `reboot(magic1, magic2, cmd, arg)` — reboot, halt, or change
    /// reboot semantics. Obvious hard-deny.
    Reboot,
}

/// The complete set of syscall identities grith classifies as
/// security-relevant, in the same curated order as the historical
/// `SECURITY_RELEVANT` number list. Arch-neutral: the per-arch trap list is
/// derived via [`nr_of`], which drops identities absent on that arch
/// (see [`security_relevant_nrs`]).
///
/// `Read`/`Write`/`Writev` are deliberately NOT here — they are the hottest
/// syscalls in any workload and are surfaced only for stepped threads
/// (go-live review B13).
pub(crate) const SECURITY_RELEVANT_IDS: &[SysId] = &[
    SysId::Open,
    SysId::Mmap,
    SysId::Pipe,
    SysId::Connect,
    SysId::Sendto,
    SysId::Recvfrom,
    SysId::Sendmsg,
    SysId::Sendmmsg,
    SysId::Recvmsg,
    SysId::Recvmmsg,
    SysId::Close,
    SysId::CloseRange,
    SysId::Dup,
    SysId::Dup2,
    SysId::Dup3,
    SysId::Fcntl,
    SysId::Bind,
    SysId::Socketpair,
    SysId::Clone,
    SysId::Clone3,
    SysId::Fork,
    SysId::Execve,
    SysId::Rename,
    SysId::Mkdir,
    SysId::Unlink,
    SysId::Chmod,
    SysId::Fchmod,
    SysId::Getdents64,
    SysId::Openat,
    SysId::Openat2,
    SysId::Creat,
    SysId::Truncate,
    SysId::Ftruncate,
    SysId::Rmdir,
    SysId::Symlink,
    SysId::Symlinkat,
    SysId::Link,
    SysId::Linkat,
    SysId::Mkdirat,
    SysId::Unlinkat,
    SysId::Renameat,
    SysId::Fchmodat,
    SysId::Pipe2,
    SysId::Renameat2,
    SysId::Seccomp,
    SysId::Prctl,
    SysId::IoUringSetup,
    SysId::IoUringEnter,
    SysId::IoUringRegister,
    SysId::Socket,
    SysId::Sendfile,
    SysId::Splice,
    SysId::Tee,
    SysId::Execveat,
    SysId::InitModule,
    SysId::FinitModule,
    SysId::DeleteModule,
    SysId::KexecLoad,
    SysId::KexecFileLoad,
    SysId::Chown,
    SysId::Fchown,
    SysId::Lchown,
    SysId::Fchownat,
    SysId::Mount,
    SysId::Umount2,
    SysId::PivotRoot,
    SysId::Chroot,
    SysId::OpenTree,
    SysId::MoveMount,
    SysId::Fsopen,
    SysId::Fsconfig,
    SysId::Fsmount,
    SysId::Fspick,
    SysId::MountSetattr,
    SysId::Ptrace,
    SysId::ProcessVmReadv,
    SysId::ProcessVmWritev,
    SysId::PidfdGetfd,
    SysId::Unshare,
    SysId::Setns,
    SysId::Sethostname,
    SysId::Setdomainname,
    SysId::Iopl,
    SysId::Ioperm,
    SysId::Swapon,
    SysId::Swapoff,
    SysId::Reboot,
];

/// Syscall identities handled by ptrace events (`PTRACE_O_TRACE*`) rather
/// than seccomp, excluded from the BPF trap list:
/// - `Execve`/`Execveat`: `PTRACE_EVENT_EXEC` (trapping execve before
///   `PTRACE_O_TRACESECCOMP` is set causes ENOSYS).
/// - `Clone`/`Fork`: `PTRACE_EVENT_CLONE`/`FORK`/`VFORK`. `Fork` drops out
///   of the derived list on arches without a fork syscall (aarch64).
pub(crate) const PTRACE_EVENT_HANDLED_IDS: &[SysId] =
    &[SysId::Execve, SysId::Execveat, SysId::Clone, SysId::Fork];

/// Native syscall numbers for [`SECURITY_RELEVANT_IDS`] on this
/// architecture, for the seccomp builder and [`is_security_relevant`].
pub(crate) fn security_relevant_nrs() -> &'static [i64] {
    static NRS: std::sync::OnceLock<Vec<i64>> = std::sync::OnceLock::new();
    NRS.get_or_init(|| {
        SECURITY_RELEVANT_IDS
            .iter()
            .filter_map(|&id| nr_of(id))
            .collect()
    })
}

/// Native syscall numbers for [`PTRACE_EVENT_HANDLED_IDS`] on this
/// architecture.
pub(crate) fn ptrace_event_handled_nrs() -> &'static [i64] {
    static NRS: std::sync::OnceLock<Vec<i64>> = std::sync::OnceLock::new();
    NRS.get_or_init(|| {
        PTRACE_EVENT_HANDLED_IDS
            .iter()
            .filter_map(|&id| nr_of(id))
            .collect()
    })
}

/// Returns `true` if the given raw native syscall number is one grith wants
/// to intercept and classify.
pub(crate) fn is_security_relevant(nr: i64) -> bool {
    security_relevant_nrs().contains(&nr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flattened struct must cover the kernel record up to and including
    /// the entry/seccomp `args` tail: 8 (op+pad+arch) + 16 (ip+sp) + 56
    /// (nr + 6 args). The seccomp `ret_data` u32 beyond it is deliberately
    /// not read (forgeable; never trusted).
    #[test]
    fn raw_syscall_info_layout_matches_kernel_prefix() {
        assert_eq!(std::mem::size_of::<RawSyscallInfo>(), 80);
        assert_eq!(std::mem::align_of::<RawSyscallInfo>(), 8);
        assert_eq!(std::mem::offset_of!(RawSyscallInfo, op), 0);
        assert_eq!(std::mem::offset_of!(RawSyscallInfo, arch), 4);
        assert_eq!(std::mem::offset_of!(RawSyscallInfo, instruction_pointer), 8);
        assert_eq!(std::mem::offset_of!(RawSyscallInfo, stack_pointer), 16);
        assert_eq!(std::mem::offset_of!(RawSyscallInfo, data), 24);
    }

    /// A never-allocated PID must read as "tracee gone", not a panic or a
    /// fatal error (mirrors the events.rs dead-tracee tolerance tests).
    #[test]
    fn get_syscall_info_on_dead_tracee_reports_gone() {
        // Well above /proc/sys/kernel/pid_max — guaranteed not to exist.
        let dead = Pid::from_raw(0x3fff_ffff);
        assert!(matches!(
            get_syscall_info(dead),
            SyscallInfoResult::TraceeGone
        ));
        assert!(matches!(read_syscall_regs(dead), Ok(None)));
        assert!(matches!(read_return_value(dead), Ok(None)));
    }
    /// Exhaustive round-trip over every identity the native arch has:
    /// `sys_id(nr_of(id)) == id`. Also proves no two identities share a
    /// native number (a collision would break the round-trip).
    #[test]
    fn table_round_trips_and_has_no_duplicate_numbers() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let mut present = 0usize;
        for &id in SECURITY_RELEVANT_IDS
            .iter()
            .chain([SysId::Read, SysId::Write, SysId::Writev].iter())
        {
            let Some(nr) = nr_of(id) else { continue };
            present += 1;
            assert!(seen.insert(nr), "duplicate native number {nr} for {id:?}");
            assert_eq!(
                sys_id(nr),
                Some(id),
                "round-trip failed for {id:?} (nr {nr})"
            );
        }
        assert!(present > 0);
    }

    /// The derived trap list has no duplicates and excludes the hot-path
    /// read/write/writev identities.
    #[test]
    fn security_relevant_nrs_is_duplicate_free_and_excludes_hot_path() {
        use std::collections::HashSet;
        let nrs = security_relevant_nrs();
        let set: HashSet<i64> = nrs.iter().copied().collect();
        assert_eq!(set.len(), nrs.len(), "duplicate numbers in trap list");
        for hot in [SysId::Read, SysId::Write, SysId::Writev] {
            if let Some(nr) = nr_of(hot) {
                assert!(
                    !set.contains(&nr),
                    "hot-path syscall {hot:?} must not be in the trap list"
                );
            }
        }
    }

    /// `is_security_relevant` agrees with the derived list, and rejects
    /// numbers with no identity.
    #[test]
    fn is_security_relevant_agrees_with_derived_list() {
        for &nr in security_relevant_nrs() {
            assert!(is_security_relevant(nr));
        }
        assert!(!is_security_relevant(-1));
        assert!(!is_security_relevant(100_000));
    }
}
