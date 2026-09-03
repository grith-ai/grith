// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Platform-agnostic syscall interception abstraction.
//!
//! This module defines the core types and trait that every platform backend
//! (Linux ptrace, macOS Endpoint Security, etc.) must implement. The
//! [`SyscallInterceptor`] trait provides a uniform async interface for:
//!
//! - Attaching to running processes or spawning new ones under supervision.
//! - Receiving classified [`SyscallEvent`]s as they occur.
//! - Allowing, denying, freezing, or thawing individual processes.
//! - Detaching cleanly when supervision ends.
//!
//! All types in this module are serialisable so that events can be forwarded to
//! the audit log and digest queue via grith-audit / grith-digest.

use async_trait::async_trait;
use std::time::Duration;

use crate::error::{Error, Result};

/// Forensic snapshot of a tracee that appears wedged in a ptrace stop.
///
/// Produced by [`SyscallInterceptor::wedge_scan`] on every watchdog tick so
/// the next investigation has live `/proc` state for any tracee that's been
/// silent for longer than the configured threshold. The watchdog is
/// observation-only — it does NOT auto-release the tracee, on the basis
/// that masking the wedge would also mask the underlying bug.
#[derive(Debug, Clone)]
pub struct WedgedTracee {
    /// Tracee tid that hasn't produced an event in `since_last_event`.
    pub tid: u32,
    /// Elapsed time since the supervisor last recorded an event for this
    /// tid (received from the kernel or sent back via allow/deny).
    pub since_last_event: Duration,
    /// Last event-kind string the supervisor recorded for this tid (e.g.
    /// `"seccomp"`, `"stopped"`, `"ptrace-event:3"`, `"allow"`). `None`
    /// when nothing has ever been recorded — typically a tid that was
    /// just added to `supervised` but hasn't seen its first event.
    pub last_event_kind: Option<String>,
    /// `/proc/<tid>/comm` — short thread name (e.g. `"HeapHelper"`).
    pub comm: String,
    /// State letter from `/proc/<tid>/status` State line (e.g. `"t"`).
    pub state: String,
    /// `/proc/<tid>/syscall` contents — empty when stopped between syscalls
    /// (i.e. at a non-syscall ptrace event boundary).
    pub syscall_info: String,
    /// `/proc/<tid>/stack` — first few kernel-stack frames at the stop point.
    pub stack_summary: String,
    /// Pending/blocked signal masks from `/proc/<tid>/status`
    /// (`SigPnd`/`ShdPnd`/`SigBlk`), as `"SigPnd=… ShdPnd=… SigBlk=…"`.
    /// Diagnoses whether the tracee is held by a pending signal the
    /// supervisor's resume didn't clear (e.g. a group-stop the doc's
    /// PTRACE_SEIZE theory predicted but which the seize validation did not
    /// observe — see the wedge root-cause investigation).
    pub signal_summary: String,
    /// True when a job-control stop signal (SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU)
    /// is **pending** in `SigPnd | ShdPnd`.
    ///
    /// IMPORTANT: `false` does NOT rule out a group-stop. A thread that has
    /// already *entered* a group-stop has consumed the SIGSTOP, so nothing is
    /// pending — yet `PTRACE_CONT(sig=0)` still won't lift it. Use the `state`
    /// letter ('T' = TASK_STOPPED group-stop vs 't' = TASK_TRACED ptrace-stop)
    /// to distinguish, not this field alone.
    pub jobctl_stop_pending: bool,
    /// The ptrace resume primitive last issued for this tid: `"CONT"`,
    /// `"SYSCALL"`, or `"none"` (never resumed). A wedged freshly-cloned child
    /// (`is_thread`) showing `"SYSCALL"` is the clone-child wrong-primitive
    /// race: it was resumed before its seccomp membership was registered.
    pub resume_primitive: String,
    /// True if this tid is a clone()'d thread (in `thread_tids`) rather than a
    /// process — the population most exposed to the out-of-order clone race.
    pub is_thread: bool,
    /// True if the supervisor believes this tid is mid-`PTRACE_SYSCALL`
    /// entry/exit (in `in_syscall_entry`) — a desync indicator.
    pub in_syscall_stop: bool,
}

// ---------------------------------------------------------------------------
// Syscall event types
// ---------------------------------------------------------------------------

/// A single intercepted syscall event from a supervised process.
///
/// Every OS-level operation that passes through the supervisor is wrapped in
/// this struct before being routed to grith-proxy for evaluation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyscallEvent {
    /// Process ID that issued the syscall.
    pub pid: u32,
    /// Thread ID (may equal `pid` on single-threaded processes).
    pub tid: u32,
    /// Wall-clock time at which the event was captured.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// High-level classification of the syscall.
    pub kind: SyscallKind,
    /// Raw platform syscall number (e.g., `__NR_openat` on Linux).
    pub raw_syscall_nr: i64,
}

/// Classification of intercepted syscalls into grith-proxy-compatible
/// categories.
///
/// Each variant carries the decoded arguments so that downstream filters can
/// evaluate the call without touching raw register values.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SyscallKind {
    /// `open` / `openat` — file being opened.
    FileOpen {
        /// Resolved absolute path.
        path: String,
        /// Decoded open flags.
        flags: OpenFlags,
    },
    /// `write` / `pwrite64` — data written to a file descriptor.
    FileWrite {
        /// File descriptor number.
        fd: i32,
        /// Resolved path if the fd-to-path mapping is known.
        path: Option<String>,
    },
    /// `read` / `pread64` — data read from a file descriptor.
    FileRead {
        /// File descriptor number.
        fd: i32,
        /// Resolved path if the fd-to-path mapping is known.
        path: Option<String>,
    },
    /// `unlink` / `unlinkat` — file deletion.
    FileDelete {
        /// Resolved absolute path of the file being removed.
        path: String,
    },
    /// `rename` / `renameat2` — file or directory rename.
    /// Symbolic or hard link creation (`symlink`, `symlinkat`, `link`,
    /// `linkat`). Routed to the proxy as `ToolCallType::FileLink`, which
    /// scores the **target** — link creation is the point at which a
    /// sensitive path becomes reachable under a benign name.
    FileLink {
        /// What the link points at.
        target: String,
        /// The new name being created.
        link_path: String,
        /// `true` for symlinks, `false` for hard links.
        symbolic: bool,
    },
    FileRename {
        /// Original path.
        old_path: String,
        /// Destination path.
        new_path: String,
    },
    /// `chmod` / `fchmodat` — permission change.
    FileChmod {
        /// Target path.
        path: String,
        /// New permission mode bits.
        mode: u32,
    },
    /// `mkdir` / `mkdirat` — directory creation.
    DirCreate {
        /// Path of the new directory.
        path: String,
        /// Permission mode bits.
        mode: u32,
    },
    /// `getdents64` — directory listing.
    DirList {
        /// Directory being listed.
        path: String,
    },
    /// `execve` / `execveat` — process execution.
    ProcessExec {
        /// Executable path.
        path: String,
        /// Argument vector (argv).
        args: Vec<String>,
    },
    /// `fork` / `clone` — child process creation.
    ProcessFork {
        /// PID of the newly created child.
        child_pid: u32,
    },
    /// `connect` — outbound network connection.
    NetConnect {
        /// Remote address (IP or hostname).
        address: String,
        /// Remote port number.
        port: u16,
        /// Protocol family.
        protocol: NetProtocol,
    },
    /// A D-Bus method call the tracee is about to write to a control socket.
    ///
    /// Emitted instead of scoring the `connect(2)` when D-Bus message
    /// inspection is armed for the channel: the connection is not the unit of
    /// risk, the call is. Only calls the curated allowlist does not vouch for
    /// reach the proxy — see [`crate::dbus`].
    DbusMethodCall {
        /// Rendered socket address of the bus, e.g. `unix:/run/user/1000/bus`.
        socket: String,
        /// Bus name being addressed (`org.freedesktop.systemd1`), when the
        /// message carried a `DESTINATION` header field.
        destination: Option<String>,
        /// Interface (`org.freedesktop.systemd1.Manager`).
        interface: Option<String>,
        /// Method name (`StartTransientUnit`).
        member: Option<String>,
        /// Object path, for operator context.
        path: Option<String>,
    },
    /// `bind` — socket bind (server listen).
    NetBind {
        /// Local address being bound.
        address: String,
        /// Local port number.
        port: u16,
        /// Protocol family.
        protocol: NetProtocol,
        /// PR 5 Phase D: tracee-side pointer to the sockaddr struct
        /// the kernel will read. `None` for non-Linux platforms or
        /// when the classifier can't extract the pointer. The
        /// supervisor reads this on the allow path to rewrite the
        /// sockaddr in-place when `allow_clamp` applies.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sockaddr_ptr: Option<u64>,
        /// PR 5 Phase D: companion to `sockaddr_ptr`. Length the
        /// tracee passed to `bind(2)`. Used to verify the buffer is
        /// large enough before writing; smaller than expected → fail
        /// closed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        addrlen: Option<u32>,
    },
    /// `sendto` — datagram sent to a specific address.
    NetSendTo {
        /// Destination address.
        address: String,
        /// Destination port.
        port: u16,
    },
    /// `pipe` / `pipe2` — anonymous pipe creation.
    PipeCreate,
    /// `socketpair` — paired socket creation.
    SocketPair,
    /// `io_uring_setup` / `io_uring_enter` / `io_uring_register` — attempt to
    /// create or operate on an io_uring ring.
    ///
    /// io_uring submissions bypass the normal per-syscall ptrace stop model:
    /// file I/O and network operations queued in the ring buffer execute
    /// without individual ptrace entry stops. These are denied unconditionally
    /// so that supervised processes cannot obtain invisible I/O channels.
    /// Node.js/libuv falls back to epoll + standard syscalls transparently.
    IoUringSetup,
    /// `socket(domain, type, protocol)` — creation of a raw-socket endpoint.
    ///
    /// Emitted only when `domain` is `AF_PACKET` (17) or `AF_NETLINK` (16).
    /// These families bypass the normal IP stack and can capture or inject
    /// arbitrary link-layer frames, or manipulate kernel subsystems directly.
    /// Normal socket families (AF_INET, AF_INET6, AF_UNIX) are filtered out
    /// in classify_syscall — they are already intercepted at connect()/bind().
    ///
    /// Denied unconditionally before proxy evaluation (same pattern as
    /// `IoUringSetup`): no legitimate supervised AI tool needs raw sockets.
    RawSocketCreate {
        /// Socket address family (AF_PACKET=17, AF_NETLINK=16).
        domain: i32,
        /// Socket type flags (SOCK_RAW, SOCK_DGRAM, etc.).
        socket_type: i32,
        /// Protocol number (e.g. ETH_P_ALL=3 for AF_PACKET).
        protocol: i32,
    },
    /// A tracee attempting to install its own seccomp filter.
    ///
    /// A filter can out-rank grith's `SECCOMP_RET_TRACE` and hide syscalls
    /// from it. The `NEW_LISTENER` form is an outright escape (the tracee
    /// answers its own notifications with `USER_NOTIF_FLAG_CONTINUE` and the
    /// syscall runs unseen); a plain filter can only make the tracee's own
    /// syscalls fail invisibly, which blinds the audit log without granting
    /// authority. `event_handler.rs` hard-denies the escape form and, by
    /// default, observes the rest (go-live review round 2).
    SeccompInstall {
        /// Which install path fired.
        via: SeccompInstallVia,
        /// `true` when the install requests a userspace notification listener
        /// (`SECCOMP_FILTER_FLAG_NEW_LISTENER`) — the escape form. Always
        /// `false` for the `prctl` path, which has no flags argument.
        new_listener: bool,
    },
    /// PR 6 Phase A: kernel-module load/unload.
    ///
    /// Covers `init_module`, `finit_module`, and `delete_module`. No
    /// legitimate use in supervised AI tools — these privileged
    /// syscalls modify the running kernel's code. Hard-denied in
    /// `event_handler.rs` before proxy evaluation (mirrors
    /// `IoUringSetup` and `RawSocketCreate`).
    KernelModuleOp {
        /// Which of the three module syscalls fired. Used in the
        /// audit log so operators can see whether the tool tried to
        /// load (init/finit) or unload (delete) a module.
        op: KernelModuleOpKind,
    },
    /// PR 6 Phase A: kernel-image replacement via `kexec_load` or
    /// `kexec_file_load`. Hard-denied — supervised AI tools have no
    /// reason to stage a new kernel for next boot.
    KexecLoad {
        /// Whether the load came from a buffer (`kexec_load`) or a
        /// file descriptor (`kexec_file_load`). Audit-log only;
        /// neither shape is permitted.
        from_fd: bool,
    },
    /// PR 6 Phase B: chown-family ownership change.
    ///
    /// Routed through the proxy as `ToolCallType::OwnershipChange`
    /// with a `+5.0` baseline so a chown outside profile-declared
    /// scope queues for review. An LLM that escapes file-write
    /// filters can no longer escalate via `chown` to make a target
    /// file owner-writable by itself.
    OwnershipChange {
        /// Which chown variant fired.
        op: OwnershipOp,
        /// Target path. For `fchown` (by-fd) the supervisor reports
        /// the fd-resolved path when known; otherwise a `<fd:N>`
        /// placeholder.
        path: String,
        /// New owner uid, or `-1` for "leave unchanged".
        new_uid: i64,
        /// New group gid, or `-1` for "leave unchanged".
        new_gid: i64,
    },
    /// PR 6 Phase B: mount/umount2/pivot_root filesystem mutation.
    ///
    /// Routed through the proxy as
    /// `ToolCallType::FilesystemMutation` with `+5.0` baseline so
    /// any filesystem-reshape attempt queues. Defeats the path-
    /// filter-bypass via remount.
    FilesystemMutation {
        /// Which mutation fired.
        op: FsMutationOp,
        /// Source path (for `mount`) or `None` for `umount2` /
        /// `pivot_root`.
        source: Option<String>,
        /// Target mount point.
        target: String,
        /// Filesystem type (for `mount`) — `None` for other ops.
        fstype: Option<String>,
    },
    /// PR 6 Phase B: ptrace + process_vm_readv/writev against a
    /// non-self target. `process_vm_*` calls where `target_pid` is
    /// the caller's own pid are filtered out in `classify_syscall`
    /// before this variant is constructed.
    ///
    /// Routed through the proxy as
    /// `ToolCallType::CrossProcessAccess` with `+5.0` baseline.
    CrossProcessAccess {
        /// Which cross-process op fired.
        op: CrossProcessOp,
        /// Target pid (never the calling pid — that case is filtered
        /// upstream).
        target_pid: u32,
    },
    /// PR 6 Phase C: `unshare(2)` / `setns(2)` — namespace primitives.
    ///
    /// The supervisor's decision flow on this variant is:
    ///   1. If the calling binary's `SpawnProvenance` has
    ///      `matched_routine_root` set AND its canonical path is in
    ///      the profile's `namespace_users` list (e.g. `bwrap`,
    ///      `bubblewrap`, `firejail`), allow silently.
    ///   2. Otherwise route to the proxy as
    ///      `ToolCallType::NamespaceOp` with `+5.0` baseline.
    ///
    /// `clone`/`clone3` with `CLONE_NEW*` flags would conceptually fit
    /// here too; the existing clone path emits `ProcessFork` and is
    /// not yet routed through this variant — deferred as a follow-up.
    NamespaceOp {
        /// Which syscall fired (`unshare` or `setns`).
        syscall: NamespaceSyscall,
        /// `unshare`: the `flags` argument (a `CLONE_NEW*` bitmap).
        /// `setns`:   the `nstype` argument (a single `CLONE_NEW*` bit
        ///            or `0` to derive from the fd's namespace link).
        flags: u64,
    },
    /// PR 6 Phase D: architecture-specific privileged op.
    /// Hard-denied in event_handler.rs before proxy evaluation,
    /// mirroring the kernel-module / kexec pattern. The op kind is
    /// recorded for forensic audit only — neither shape is permitted.
    ArchPrivilegedOp {
        /// Which architecture-specific privileged syscall fired.
        op: ArchPrivOp,
    },
    /// Go-live review B1: a syscall issued under a foreign ABI — a
    /// non-native audit arch (x86_64: `int 0x80` / a 32-bit binary;
    /// aarch64: 32-bit compat EL0) or, on x86_64 only, x32 syscall
    /// numbering. The seccomp filter cannot interpret these numbers, so
    /// it fails closed and the supervisor hard-denies in
    /// `event_handler.rs` before classification, mirroring the
    /// kernel-module pattern.
    ForeignAbiSyscall {
        /// Which foreign shape fired.
        abi: ForeignAbiKind,
        /// Raw untranslated syscall number from the number register
        /// (foreign table for `CompatArch`; `nr | 0x40000000` for
        /// `X32`), or `-1` when registers were unreadable. Forensic
        /// only — must never be looked up in the native table.
        raw_nr: i64,
    },
}

/// Go-live review B1: discriminator for `SyscallKind::ForeignAbiSyscall`.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ForeignAbiKind {
    /// Non-native audit arch: `int 0x80` from a 64-bit process or a
    /// 32-bit binary after exec (x86_64); a compat-ARM EL0 binary on a
    /// CONFIG_COMPAT arm64 kernel (aarch64).
    CompatArch,
    /// x32 ABI: `AUDIT_ARCH_X86_64` with syscall bit 30 set. x86_64
    /// only — no other architecture has an x32 analog.
    X32,
}

/// Discriminator for `SyscallKind::SeccompInstall`.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SeccompInstallVia {
    /// `seccomp(SECCOMP_SET_MODE_FILTER, flags, …)` — the modern path, and
    /// the only one that can request a `NEW_LISTENER`.
    Seccomp,
    /// `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, …)` — the legacy path, no
    /// flags, cannot create a listener.
    Prctl,
}

/// PR 6 Phase A: discriminator for `SyscallKind::KernelModuleOp`.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum KernelModuleOpKind {
    /// `init_module(2)` — load a module from a user buffer.
    Init,
    /// `finit_module(2)` — load a module from a file descriptor.
    Finit,
    /// `delete_module(2)` — unload a module.
    Delete,
}

/// PR 6 Phase B: discriminator for `SyscallKind::OwnershipChange`.
/// Records which chown-family syscall fired so the audit log can
/// distinguish "by path" vs "by fd" vs "by path-relative" attempts.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum OwnershipOp {
    /// `chown(2)` — by path, follows symlinks.
    Chown,
    /// `fchown(2)` — by file descriptor.
    Fchown,
    /// `lchown(2)` — by path, does NOT follow symlinks.
    Lchown,
    /// `fchownat(2)` — by path relative to a directory fd.
    Fchownat,
}

/// PR 6 Phase B: discriminator for `SyscallKind::FilesystemMutation`.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum FsMutationOp {
    /// `mount(2)` — bring a new filesystem online.
    Mount,
    /// `umount2(2)` — unmount. On x86_64 there is no separate
    /// `umount` syscall; `umount2` carries the legacy semantics
    /// when `flags == 0`.
    Umount2,
    /// `pivot_root(2)` — change the root filesystem of the calling
    /// process's namespace.
    PivotRoot,
    /// `chroot(2)` — change the process root directory.
    Chroot,
    /// `open_tree(2)` — clone/open a mount tree.
    OpenTree,
    /// `move_mount(2)` — move/attach a mount tree.
    MoveMount,
    /// `fsopen(2)` — create a filesystem context.
    Fsopen,
    /// `fsconfig(2)` — configure a filesystem context.
    Fsconfig,
    /// `fsmount(2)` — create a mount from a filesystem context.
    Fsmount,
    /// `fspick(2)` — select a mount for reconfiguration.
    Fspick,
    /// `mount_setattr(2)` — change mount attributes.
    MountSetattr,
}

/// PR 6 Phase B: discriminator for `SyscallKind::CrossProcessAccess`.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum CrossProcessOp {
    /// `ptrace(2)` — attach/read/write another process. Any ptrace
    /// request against a non-self target is high-risk.
    Ptrace,
    /// `process_vm_readv(2)` against a non-self target.
    ProcessVmReadv,
    /// `process_vm_writev(2)` against a non-self target.
    ProcessVmWritev,
    /// `pidfd_getfd(2)` — steal a file descriptor out of the process a pidfd
    /// refers to. The target is resolved from the pidfd's fdinfo, not a
    /// register pid argument.
    PidfdGetfd,
}

/// PR 6 Phase C: discriminator for `SyscallKind::NamespaceOp`.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum NamespaceSyscall {
    /// `unshare(flags)` — disassociate from caller's namespaces.
    Unshare,
    /// `setns(fd, nstype)` — join an existing namespace.
    Setns,
}

/// PR 6 Phase D: discriminator for `SyscallKind::ArchPrivilegedOp` —
/// the architecture-specific privileged operations that are
/// unconditionally hard-denied. Each represents a host-wide
/// authority change that supervised AI tools have no legitimate
/// reason to invoke.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ArchPrivOp {
    /// `sethostname(2)` — set the system hostname (global identity).
    SetHostname,
    /// `setdomainname(2)` — set the NIS domain name.
    SetDomainName,
    /// `iopl(2)` — set the I/O privilege level (x86 only).
    Iopl,
    /// `ioperm(2)` — toggle access to specific I/O ports (x86 only).
    Ioperm,
    /// `swapon(2)` — enable a swap area.
    Swapon,
    /// `swapoff(2)` — disable a swap area.
    Swapoff,
    /// `reboot(2)` — reboot/halt/etc.
    Reboot,
}

/// Decoded file-open flags.
///
/// The supervisor maps platform-specific `O_*` constants into this portable
/// enum so that filters do not need platform-aware logic.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum OpenFlags {
    /// `O_RDONLY`
    ReadOnly,
    /// `O_WRONLY`
    WriteOnly,
    /// `O_RDWR`
    ReadWrite,
    /// `O_APPEND`
    Append,
    /// `O_CREAT`
    Create,
    /// `O_TRUNC`
    Truncate,
    /// `O_RDONLY | O_DIRECTORY` — an open that can only succeed on a
    /// directory, and whose fd can only be enumerated.
    ///
    /// Kept distinct from [`Self::ReadOnly`] because the kernel has already
    /// settled the question the filters would otherwise have to guess at:
    /// `read(2)` on the resulting fd returns `EISDIR`, so no file content can
    /// come out of it. Folding it into `ReadOnly` priced `find -type d`
    /// walking past `~/.gnupg/private-keys-v1.d` exactly like opening a
    /// private key to read it.
    ReadOnlyDirectory,
}

/// Network protocol family.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum NetProtocol {
    /// TCP (SOCK_STREAM, AF_INET / AF_INET6).
    Tcp,
    /// UDP (SOCK_DGRAM, AF_INET / AF_INET6).
    Udp,
    /// Unix domain socket (AF_UNIX).
    Unix,
}

// ---------------------------------------------------------------------------
// Syscall response
// ---------------------------------------------------------------------------

/// The action the supervisor should take in response to an intercepted syscall.
///
/// This is the supervisor-internal decision — it is derived from the
/// [`grith_proxy::types::ProxyAction`] returned by the proxy pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallResponse {
    /// Let the syscall proceed normally.
    Allow,
    /// Inject an `EPERM` error return and skip the syscall.
    Deny,
    /// Freeze the process (SIGSTOP) pending human approval via the digest.
    Freeze,
}

// ---------------------------------------------------------------------------
// Platform trait
// ---------------------------------------------------------------------------

/// Platform abstraction for OS-level syscall interception.
///
/// Implementors provide the low-level mechanism for trapping syscalls (e.g.,
/// `ptrace` on Linux, Endpoint Security on macOS) while the supervisor
/// orchestrator handles proxy evaluation, freeze/thaw policy, and audit
/// logging.
///
/// # Lifecycle
///
/// 1. Create an instance via the platform-specific constructor.
/// 2. Call [`attach`](Self::attach) or [`spawn_supervised`](Self::spawn_supervised).
/// 3. Loop on [`next_event`](Self::next_event), calling [`allow`](Self::allow),
///    [`deny`](Self::deny), or [`freeze`](Self::freeze) for each event.
/// 4. Call [`detach`](Self::detach) or [`detach_all`](Self::detach_all) to
///    release processes.
#[async_trait]
pub trait SyscallInterceptor: Send + Sync {
    /// Select the attach mechanism for spawned processes
    /// (`traceme` | `seize`). Default is a no-op: only the Linux ptrace
    /// backend honours it; macOS/Windows interceptors don't use ptrace.
    /// Called once after construction, before the first spawn. See
    /// `work/futurework/ptrace-seize-migration.md`.
    fn set_attach_mode(&mut self, _mode: crate::config::AttachMode) {}

    /// Enable in-line DNS inspection with a shared IP→domain cache. Default is
    /// a no-op (only the Linux ptrace backend inspects DNS at the syscall
    /// level). `observe_responses` gates targeted receive-exit promotion that
    /// populates the exact-IP cache; query inspection/blocking is independent.
    /// Called once after construction, before the loop.
    fn set_dns_inspection(
        &mut self,
        _cache: std::sync::Arc<std::sync::Mutex<crate::dns_cache::DnsCache>>,
        _observe_responses: bool,
        _block_tcp_dns: bool,
    ) {
    }

    /// Decide D-Bus control-socket access per method call rather than per
    /// connect. Called once after construction, before the loop, and only when
    /// control-socket enforcement is itself on.
    ///
    /// Returns whether inspection is actually armed. This is a **capability
    /// report, not an acknowledgement**: a backend that cannot see what a
    /// tracee writes to a socket must return `false` so the caller keeps
    /// enforcing at the connect. Silently accepting would convert "decide per
    /// message" into "decide never". The default is `false` — only the Linux
    /// ptrace backend can read tracee memory mid-syscall.
    fn set_dbus_inspection(&mut self) -> bool {
        false
    }

    /// Install the session-local connected UDP DNS proxy control plane.
    ///
    /// The worker itself is owned and joined by the supervisor orchestrator.
    /// Backends must reject installation unless they can redirect connected
    /// UDP/53 `connect` calls before any query can leave the tracee.
    fn set_connected_dns_proxy(
        &mut self,
        _control: crate::connected_dns_proxy::ConnectedDnsProxyControl,
    ) -> Result<()> {
        Err(Error::PlatformNotSupported(
            "connected UDP DNS proxy requires Linux seccomp-ptrace supervision".into(),
        ))
    }

    /// Terminate every process in the supervised tree.
    ///
    /// Used when a mandatory enforcement component cannot start. The default
    /// rejects the request; supported backends must implement a fail-closed
    /// termination path.
    async fn terminate_all(&mut self) -> Result<()> {
        Err(Error::PlatformNotSupported(
            "supervised process-tree termination is unavailable".into(),
        ))
    }

    /// Take whether the current `connect` to `:53` for `tid` is on a stream
    /// (TCP) socket and must be blocked (TCP-DNS can't be content-inspected, so
    /// it's denied to force the inspected UDP path). The event handler calls
    /// this on a `NetConnect` to port 53. Default `false`.
    fn take_tcp_dns_deny(&mut self, _tid: u32) -> bool {
        false
    }

    /// Take all parsed DNS queries (or an explicit parse failure) from the
    /// tracee's most recent DNS send for `tid`.
    fn take_dns_query(&mut self, _tid: u32) -> Option<DnsQueryInspection> {
        None
    }

    /// Take the D-Bus method calls escalated by `tid`'s stopped write.
    ///
    /// Returns every call on that write the policy layer refused, not only the
    /// one named in the event: a client may batch several messages into one
    /// syscall, and approving the first must not silently send the rest. Empty
    /// when the escalation came from an undecodable channel rather than from a
    /// specific call.
    fn take_dbus_method_calls(&mut self, _tid: u32) -> Vec<DbusCallSummary> {
        Vec::new()
    }

    /// Complete ownership of an in-line DNS inspection.
    ///
    /// `allowed=false` removes any response-correlation state staged while the
    /// query was parsed, because the corresponding packet never reached the
    /// resolver. The default is a no-op for interceptors without in-line DNS.
    fn finish_dns_query(&mut self, _tid: u32, _allowed: bool) {}

    /// Attach to an existing process by PID.
    ///
    /// The process will be stopped and syscall tracing enabled. Returns an
    /// error if attachment fails (e.g., insufficient privileges, process does
    /// not exist).
    async fn attach(&mut self, pid: u32) -> Result<()>;

    /// Spawn a new process under supervision.
    ///
    /// The child is created with syscall tracing active from the first
    /// instruction. Returns the child's PID.
    async fn spawn_supervised(
        &mut self,
        command: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<u32>;

    /// Wait for the next syscall event from any supervised process.
    ///
    /// Returns `None` when all supervised processes have exited.
    async fn next_event(&mut self) -> Result<Option<SyscallEvent>>;

    /// Allow a previously intercepted syscall to proceed.
    async fn allow(&mut self, pid: u32) -> Result<()>;

    /// Deny a previously intercepted syscall.
    ///
    /// The process receives `EPERM` as the syscall's return value and continues
    /// execution.
    async fn deny(&mut self, pid: u32) -> Result<()>;

    /// Kill the intercepted process with `SIGKILL`.
    ///
    /// Used when a DENY decision must actually STOP the process rather than
    /// EPERM one syscall. A `ProcessSpawn` is intercepted at
    /// `PTRACE_EVENT_EXEC` — AFTER the new program image has loaded — where
    /// [`deny`](Self::deny) is a no-op (there is no in-flight syscall to
    /// convert to EPERM) and the program would otherwise run its first
    /// instruction. Killing the tracee at that stop stops it before it can act
    /// (e.g. before an authority-delegating `systemd-run` connects to the
    /// session manager and delegates the real work to an untraced peer).
    async fn kill(&mut self, pid: u32) -> Result<()>;

    /// Freeze (pause) a process.
    ///
    /// On Unix this sends `SIGSTOP`. The process remains stopped until
    /// [`thaw`](Self::thaw) is called.
    async fn freeze(&mut self, pid: u32) -> Result<()>;

    /// Thaw (resume) a previously frozen process.
    ///
    /// On Unix this sends `SIGCONT`.
    async fn thaw(&mut self, pid: u32) -> Result<()>;

    /// Detach from a single supervised process, allowing it to run unsupervised.
    async fn detach(&mut self, pid: u32) -> Result<()>;

    /// Detach from all supervised processes.
    async fn detach_all(&mut self) -> Result<()>;

    /// Return the list of PIDs currently under supervision.
    fn supervised_pids(&self) -> Vec<u32>;

    /// Check whether the underlying platform mechanism is available at runtime.
    ///
    /// For example, Linux ptrace requires `CAP_SYS_PTRACE` or `YAMA`
    /// configured to allow non-root tracing.
    fn is_available() -> bool
    where
        Self: Sized;

    /// Spawn a new process under supervision inside a pseudo-terminal.
    ///
    /// Returns `(pid, pty_reader, pty_writer)`. The reader/writer are the
    /// master side of the PTY — the caller forwards bytes between these
    /// and the user's terminal.
    ///
    /// Not all platforms support PTY spawning. The default implementation
    /// returns an error.
    async fn spawn_supervised_pty(
        &mut self,
        _command: &str,
        _args: &[String],
        _env: &[(String, String)],
        _cols: u16,
        _rows: u16,
    ) -> Result<(
        u32,
        Box<dyn std::io::Read + Send>,
        Box<dyn std::io::Write + Send>,
    )> {
        Err(Error::PlatformNotSupported(
            "PTY spawning not supported on this platform".into(),
        ))
    }

    /// Human-readable name of the interception mechanism (e.g., `"ptrace"`,
    /// `"endpoint-security"`).
    fn mechanism_name(&self) -> &str;

    /// Scan supervised tracees for ones that appear wedged in a ptrace stop.
    ///
    /// "Wedged" = no event has been recorded for the tracee in at least
    /// `threshold`, AND its `/proc/<tid>/status` state begins with `t`/`T`
    /// (tracing stop). Returns a forensic snapshot for each such tracee.
    ///
    /// Observation-only by design: detection logs the wedge but does not
    /// release the tracee, so the underlying bug remains visible for
    /// debugging. The supervisor's main loop calls this on a fixed interval
    /// and emits a structured audit row per detected wedge.
    ///
    /// Default implementation returns an empty Vec (platforms without
    /// `ptrace`-style stop tracking).
    fn wedge_scan(&self, _threshold: Duration) -> Vec<WedgedTracee> {
        Vec::new()
    }
}

/// Result of inspecting every DNS message in one outbound syscall.
///
/// A parse error is explicit so positively identified UDP port-53 traffic can
/// fail closed instead of falling through as ordinary network noise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQueryInspection {
    pub queries: Vec<(String, String)>,
    pub parse_error: Option<String>,
}

/// One escalated D-Bus method call, rendered for the audit record and the
/// operator prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbusCallSummary {
    /// `<destination> → <interface>.<member>`, with missing parts elided.
    pub description: String,
    pub destination: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
}

// ---------------------------------------------------------------------------
// Display implementations
// ---------------------------------------------------------------------------

impl std::fmt::Display for SyscallKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileOpen { path, flags } => write!(f, "FileOpen({path}, {flags:?})"),
            Self::FileWrite { fd, path } => {
                if let Some(p) = path {
                    write!(f, "FileWrite(fd={fd}, {p})")
                } else {
                    write!(f, "FileWrite(fd={fd})")
                }
            }
            Self::FileRead { fd, path } => {
                if let Some(p) = path {
                    write!(f, "FileRead(fd={fd}, {p})")
                } else {
                    write!(f, "FileRead(fd={fd})")
                }
            }
            Self::FileDelete { path } => write!(f, "FileDelete({path})"),
            Self::FileLink {
                target,
                link_path,
                symbolic,
            } => write!(
                f,
                "FileLink({kind} {link_path} -> {target})",
                kind = if *symbolic { "symbolic" } else { "hard" }
            ),
            Self::FileRename { old_path, new_path } => {
                write!(f, "FileRename({old_path} -> {new_path})")
            }
            Self::FileChmod { path, mode } => write!(f, "FileChmod({path}, {mode:o})"),
            Self::DirCreate { path, mode } => write!(f, "DirCreate({path}, {mode:o})"),
            Self::DirList { path } => write!(f, "DirList({path})"),
            Self::ProcessExec { path, args } => {
                write!(f, "ProcessExec({path} {})", args.join(" "))
            }
            Self::ProcessFork { child_pid } => write!(f, "ProcessFork(child={child_pid})"),
            Self::NetConnect {
                address,
                port,
                protocol,
            } => write!(f, "NetConnect({protocol:?} {address}:{port})"),
            Self::DbusMethodCall {
                socket,
                destination,
                interface,
                member,
                ..
            } => {
                let dest = destination.as_deref().unwrap_or("?");
                let iface = interface.as_deref().unwrap_or("?");
                let member = member.as_deref().unwrap_or("?");
                write!(f, "DbusMethodCall({socket} {dest} {iface}.{member})")
            }
            Self::NetBind {
                address,
                port,
                protocol,
                ..
            } => write!(f, "NetBind({protocol:?} {address}:{port})"),
            Self::NetSendTo { address, port } => write!(f, "NetSendTo({address}:{port})"),
            Self::PipeCreate => write!(f, "PipeCreate"),
            Self::SocketPair => write!(f, "SocketPair"),
            Self::IoUringSetup => write!(f, "IoUringSetup"),
            Self::RawSocketCreate {
                domain,
                socket_type,
                protocol,
            } => write!(
                f,
                "RawSocketCreate(domain={domain}, type={socket_type}, proto={protocol})"
            ),
            Self::SeccompInstall { via, new_listener } => {
                write!(f, "SeccompInstall({via:?}, new_listener={new_listener})")
            }
            Self::KernelModuleOp { op } => write!(f, "KernelModuleOp({op:?})"),
            Self::KexecLoad { from_fd } => {
                if *from_fd {
                    write!(f, "KexecLoad(file)")
                } else {
                    write!(f, "KexecLoad(buffer)")
                }
            }
            Self::OwnershipChange {
                op,
                path,
                new_uid,
                new_gid,
            } => write!(
                f,
                "OwnershipChange({op:?} path={path} uid={new_uid} gid={new_gid})"
            ),
            Self::FilesystemMutation {
                op,
                source,
                target,
                fstype,
            } => write!(
                f,
                "FilesystemMutation({op:?} src={src} target={target} fstype={fs})",
                src = source.as_deref().unwrap_or(""),
                fs = fstype.as_deref().unwrap_or(""),
            ),
            Self::CrossProcessAccess { op, target_pid } => {
                write!(f, "CrossProcessAccess({op:?} target_pid={target_pid})")
            }
            Self::NamespaceOp { syscall, flags } => {
                write!(f, "NamespaceOp({syscall:?} flags={flags:#x})")
            }
            Self::ArchPrivilegedOp { op } => write!(f, "ArchPrivilegedOp({op:?})"),
            Self::ForeignAbiSyscall { abi, raw_nr } => {
                write!(f, "ForeignAbiSyscall({abi:?} raw_nr={raw_nr})")
            }
        }
    }
}

impl std::fmt::Display for SyscallResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
            Self::Freeze => write!(f, "freeze"),
        }
    }
}

impl std::fmt::Display for NetProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Unix => write!(f, "unix"),
        }
    }
}

impl std::fmt::Display for OpenFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "O_RDONLY"),
            Self::WriteOnly => write!(f, "O_WRONLY"),
            Self::ReadWrite => write!(f, "O_RDWR"),
            Self::Append => write!(f, "O_APPEND"),
            Self::Create => write!(f, "O_CREAT"),
            Self::Truncate => write!(f, "O_TRUNC"),
            Self::ReadOnlyDirectory => write!(f, "O_RDONLY|O_DIRECTORY"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// Helper to build a test event with sensible defaults.
    fn make_event(kind: SyscallKind) -> SyscallEvent {
        SyscallEvent {
            pid: 1000,
            tid: 1000,
            timestamp: Utc::now(),
            kind,
            raw_syscall_nr: 0,
        }
    }

    // -- SyscallEvent construction --

    #[test]
    fn syscall_event_file_open() {
        let event = make_event(SyscallKind::FileOpen {
            path: "/etc/passwd".into(),
            flags: OpenFlags::ReadOnly,
        });
        assert_eq!(event.pid, 1000);
        if let SyscallKind::FileOpen { path, flags } = &event.kind {
            assert_eq!(path, "/etc/passwd");
            assert_eq!(*flags, OpenFlags::ReadOnly);
        } else {
            panic!("expected FileOpen");
        }
    }

    #[test]
    fn syscall_event_process_exec() {
        let event = make_event(SyscallKind::ProcessExec {
            path: "/usr/bin/curl".into(),
            args: vec!["-s".into(), "https://evil.com".into()],
        });
        if let SyscallKind::ProcessExec { path, args } = &event.kind {
            assert_eq!(path, "/usr/bin/curl");
            assert_eq!(args.len(), 2);
        } else {
            panic!("expected ProcessExec");
        }
    }

    #[test]
    fn syscall_event_net_connect() {
        let event = make_event(SyscallKind::NetConnect {
            address: "93.184.216.34".into(),
            port: 443,
            protocol: NetProtocol::Tcp,
        });
        if let SyscallKind::NetConnect {
            address,
            port,
            protocol,
        } = &event.kind
        {
            assert_eq!(address, "93.184.216.34");
            assert_eq!(*port, 443);
            assert_eq!(*protocol, NetProtocol::Tcp);
        } else {
            panic!("expected NetConnect");
        }
    }

    #[test]
    fn syscall_event_file_rename() {
        let event = make_event(SyscallKind::FileRename {
            old_path: "/tmp/a.txt".into(),
            new_path: "/tmp/b.txt".into(),
        });
        if let SyscallKind::FileRename { old_path, new_path } = &event.kind {
            assert_eq!(old_path, "/tmp/a.txt");
            assert_eq!(new_path, "/tmp/b.txt");
        } else {
            panic!("expected FileRename");
        }
    }

    #[test]
    fn syscall_event_pipe_and_socketpair() {
        let pipe = make_event(SyscallKind::PipeCreate);
        assert_eq!(pipe.kind, SyscallKind::PipeCreate);

        let pair = make_event(SyscallKind::SocketPair);
        assert_eq!(pair.kind, SyscallKind::SocketPair);
    }

    // -- Serde round-trips --

    #[test]
    fn serde_roundtrip_syscall_kind() {
        let variants: Vec<SyscallKind> = vec![
            SyscallKind::FileOpen {
                path: "/foo".into(),
                flags: OpenFlags::Create,
            },
            SyscallKind::FileWrite {
                fd: 3,
                path: Some("/bar".into()),
            },
            SyscallKind::FileRead { fd: 0, path: None },
            SyscallKind::FileDelete {
                path: "/baz".into(),
            },
            SyscallKind::FileRename {
                old_path: "/a".into(),
                new_path: "/b".into(),
            },
            SyscallKind::FileChmod {
                path: "/x".into(),
                mode: 0o755,
            },
            SyscallKind::DirCreate {
                path: "/d".into(),
                mode: 0o755,
            },
            SyscallKind::DirList {
                path: "/tmp".into(),
            },
            SyscallKind::ProcessExec {
                path: "/bin/sh".into(),
                args: vec!["-c".into(), "echo hi".into()],
            },
            SyscallKind::ProcessFork { child_pid: 9999 },
            SyscallKind::NetConnect {
                address: "1.2.3.4".into(),
                port: 80,
                protocol: NetProtocol::Tcp,
            },
            SyscallKind::NetBind {
                address: "0.0.0.0".into(),
                port: 8080,
                protocol: NetProtocol::Tcp,
                sockaddr_ptr: None,
                addrlen: None,
            },
            SyscallKind::NetSendTo {
                address: "10.0.0.1".into(),
                port: 53,
            },
            SyscallKind::PipeCreate,
            SyscallKind::SocketPair,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let parsed: SyscallKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, variant);
        }
    }

    #[test]
    fn serde_roundtrip_open_flags() {
        let flags = vec![
            OpenFlags::ReadOnly,
            OpenFlags::WriteOnly,
            OpenFlags::ReadWrite,
            OpenFlags::Append,
            OpenFlags::Create,
            OpenFlags::Truncate,
        ];
        for flag in &flags {
            let json = serde_json::to_string(flag).unwrap();
            let parsed: OpenFlags = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, flag);
        }
    }

    #[test]
    fn serde_roundtrip_net_protocol() {
        let protos = vec![NetProtocol::Tcp, NetProtocol::Udp, NetProtocol::Unix];
        for proto in &protos {
            let json = serde_json::to_string(proto).unwrap();
            let parsed: NetProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, proto);
        }
    }

    #[test]
    fn serde_roundtrip_full_event() {
        let event = make_event(SyscallKind::ProcessExec {
            path: "/usr/bin/git".into(),
            args: vec!["push".into(), "origin".into(), "main".into()],
        });
        let json = serde_json::to_string(&event).unwrap();
        let parsed: SyscallEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pid, event.pid);
        assert_eq!(parsed.tid, event.tid);
        assert_eq!(parsed.kind, event.kind);
        assert_eq!(parsed.raw_syscall_nr, event.raw_syscall_nr);
    }

    // -- Display implementations --

    #[test]
    fn display_syscall_kind_file_open() {
        let kind = SyscallKind::FileOpen {
            path: "/etc/shadow".into(),
            flags: OpenFlags::ReadOnly,
        };
        assert_eq!(kind.to_string(), "FileOpen(/etc/shadow, ReadOnly)");
    }

    #[test]
    fn display_syscall_kind_file_write_with_path() {
        let kind = SyscallKind::FileWrite {
            fd: 5,
            path: Some("/tmp/out.log".into()),
        };
        assert_eq!(kind.to_string(), "FileWrite(fd=5, /tmp/out.log)");
    }

    #[test]
    fn display_syscall_kind_file_write_without_path() {
        let kind = SyscallKind::FileWrite { fd: 1, path: None };
        assert_eq!(kind.to_string(), "FileWrite(fd=1)");
    }

    #[test]
    fn display_syscall_kind_process_exec() {
        let kind = SyscallKind::ProcessExec {
            path: "/bin/ls".into(),
            args: vec!["-la".into(), "/tmp".into()],
        };
        assert_eq!(kind.to_string(), "ProcessExec(/bin/ls -la /tmp)");
    }

    #[test]
    fn display_syscall_kind_net_connect() {
        let kind = SyscallKind::NetConnect {
            address: "8.8.8.8".into(),
            port: 53,
            protocol: NetProtocol::Udp,
        };
        assert_eq!(kind.to_string(), "NetConnect(Udp 8.8.8.8:53)");
    }

    #[test]
    fn display_syscall_kind_pipe_and_socketpair() {
        assert_eq!(SyscallKind::PipeCreate.to_string(), "PipeCreate");
        assert_eq!(SyscallKind::SocketPair.to_string(), "SocketPair");
    }

    #[test]
    fn display_syscall_response() {
        assert_eq!(SyscallResponse::Allow.to_string(), "allow");
        assert_eq!(SyscallResponse::Deny.to_string(), "deny");
        assert_eq!(SyscallResponse::Freeze.to_string(), "freeze");
    }

    #[test]
    fn display_net_protocol() {
        assert_eq!(NetProtocol::Tcp.to_string(), "tcp");
        assert_eq!(NetProtocol::Udp.to_string(), "udp");
        assert_eq!(NetProtocol::Unix.to_string(), "unix");
    }

    #[test]
    fn display_open_flags() {
        assert_eq!(OpenFlags::ReadOnly.to_string(), "O_RDONLY");
        assert_eq!(OpenFlags::WriteOnly.to_string(), "O_WRONLY");
        assert_eq!(OpenFlags::ReadWrite.to_string(), "O_RDWR");
        assert_eq!(OpenFlags::Append.to_string(), "O_APPEND");
        assert_eq!(OpenFlags::Create.to_string(), "O_CREAT");
        assert_eq!(OpenFlags::Truncate.to_string(), "O_TRUNC");
    }

    // -- Equality checks --

    #[test]
    fn syscall_response_equality() {
        assert_eq!(SyscallResponse::Allow, SyscallResponse::Allow);
        assert_ne!(SyscallResponse::Allow, SyscallResponse::Deny);
        assert_ne!(SyscallResponse::Deny, SyscallResponse::Freeze);
    }

    #[test]
    fn open_flags_equality() {
        assert_eq!(OpenFlags::ReadOnly, OpenFlags::ReadOnly);
        assert_ne!(OpenFlags::ReadOnly, OpenFlags::WriteOnly);
    }

    #[test]
    fn net_protocol_equality() {
        assert_eq!(NetProtocol::Tcp, NetProtocol::Tcp);
        assert_ne!(NetProtocol::Tcp, NetProtocol::Udp);
    }

    // -- Trait bounds --

    #[test]
    fn event_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SyscallEvent>();
        assert_send_sync::<SyscallKind>();
        assert_send_sync::<SyscallResponse>();
    }
}
