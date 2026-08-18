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
//!    `PTRACE_O_TRACESYSGOOD`), the tracer reads the syscall number and its
//!    arguments into an arch-neutral [`arch::SyscallRegs`] — from the kernel's
//!    `PTRACE_GET_SYSCALL_INFO` record where available, else from the per-arch
//!    register file (x86_64: `PTRACE_GETREGS`).
//!
//! 3. **Classify** -- The raw syscall number is mapped to a [`SyscallKind`] variant.
//!    String arguments (paths, addresses) are read from the tracee's address space
//!    one word at a time via `PTRACE_PEEKDATA`. File-descriptor arguments are
//!    resolved to filesystem paths by reading the `/proc/<pid>/fd/<fd>` symlink.
//!
//! Register names and per-arch ptrace calling conventions are confined to the
//! [`arch`] module; the shared code deals only in syscall numbers and
//! `args[N]` argument slots.
//!
//! # Limitations
//!
//! - Supported architectures: **x86_64** (kernel 4.8+) and **aarch64**
//!   (kernel 5.3+ — `PTRACE_GET_SYSCALL_INFO` is required and probed at
//!   session start; the pre-5.3 fallbacks are x86-shaped and compiled out).
//!   Per-arch syscall tables and register access live behind [`arch`].
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

pub(crate) mod arch;
mod child;
pub(crate) mod clamp;
mod classify;
mod dns_redirect;
mod dns_socket_tracker;
mod events;
pub(crate) mod seccomp;

// The per-arch native syscall-number table and the derived security-
// relevance predicate. `syscall_nr` re-exports the native constants so
// existing `platform::linux::syscall_nr::X` paths keep working; new code
// should key on `arch::SysId` instead of raw numbers.
pub(crate) use arch::is_security_relevant;
// Native syscall-number constants are only consumed by in-crate tests now —
// production code keys on `arch::SysId`.
#[cfg(test)]
pub(crate) use arch::syscall_nr;

use std::collections::{HashMap, HashSet};

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
