// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Event handling and ptrace operations for the Linux interceptor.
//!
//! Contains the [`SyscallInterceptor`] trait implementation for
//! [`PtraceSupervisor`], including `next_event`, `attach`, `allow`, `deny`,
//! `freeze`, `thaw`, `detach`, and `detach_all`.

#![cfg(target_os = "linux")]

use async_trait::async_trait;
use chrono::Utc;
use nix::libc;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tracing::{debug, error, info, trace, warn};

use crate::error::{Error, Result};
use crate::interceptor::{SyscallEvent, SyscallInterceptor, WedgedTracee};

use super::arch::SysId;
use super::{is_security_relevant, PtraceSupervisor};

/// Record that we've just observed (or acted on) an event for `tid`.
/// Used by `wedge_scan` to identify tracees that have gone silent.
///
/// Kept short and `#[inline]` because it fires at every event boundary
/// (~17k/sec under heavy load).
#[inline]
fn record_event(sup: &mut PtraceSupervisor, tid: u32, kind: &'static str) {
    sup.last_event_at.insert(tid, std::time::Instant::now());
    sup.last_event_kind.insert(tid, kind.to_string());
}

/// Decide whether a syscall should be classified in the fallback
/// `PTRACE_SYSCALL` path.
///
/// Spawned processes use seccomp-BPF and do not rely on this path.
/// Attached processes do use this path and must continue to classify
/// `read(2)`/`write(2)` to preserve prior attach-mode visibility.
fn is_fallback_relevant_syscall(nr: i64, use_seccomp: bool) -> bool {
    is_security_relevant(nr)
        || (!use_seccomp && matches!(super::arch::sys_id(nr), Some(SysId::Read | SysId::Write)))
}

#[inline]
fn is_thread_group_child(parent_tgid: u32, child_tgid: u32) -> bool {
    parent_tgid == child_tgid
}

#[inline]
fn clone_shares_fd_table(flags: Option<u64>) -> bool {
    flags.is_some_and(|flags| flags & libc::CLONE_FILES as u64 != 0)
}

#[inline]
fn clone_creates_private_thread_fd_table(
    parent_tgid: u32,
    child_tgid: u32,
    flags: Option<u64>,
) -> bool {
    is_thread_group_child(parent_tgid, child_tgid) && !clone_shares_fd_table(flags)
}

/// Cap on the number of bytes read from a tracee DNS query/response buffer.
/// DNS messages are bounded well under this (EDNS0 typically advertises
/// 1232/4096); the cap bounds the per-message PTRACE_PEEKDATA work.
const MAX_DNS_MSG: usize = 4096;
const MAX_DNS_BATCH: usize = 32;
/// Aggregate iovec cap for one `sendmmsg(2)` inspection. Without a batch-wide
/// bound, the per-message limit permits tens of thousands of synchronous
/// ptrace metadata reads in one stopped syscall.
const MAX_DNS_BATCH_IOVECS: usize = 1024;
const MSGHDR_SIZE: u64 = 56;
const MMSGHDR_SIZE: u64 = 64;

// ---------------------------------------------------------------------------
// Internal ptrace helpers
// ---------------------------------------------------------------------------

/// The kernel's record of a stopped tracee's syscall entry
/// (`PTRACE_GET_SYSCALL_INFO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyscallEntryInfo {
    /// A syscall-entry or seccomp stop: the audit arch and number of the
    /// syscall about to be dispatched, from the kernel's own bookkeeping.
    Entry { arch: u32, nr: u64 },
    /// The stop carries no entry record — a syscall-exit stop, a stop that is
    /// not a syscall stop at all, or a tracee that died in its stop.
    NotEntry,
    /// `PTRACE_GET_SYSCALL_INFO` itself is not supported (pre-5.3 kernel).
    Unsupported,
}

/// The ptrace options every supervised tracee is set with. Extracted so the
/// fail-closed invariant — `PTRACE_O_EXITKILL` is always present, so tracees
/// are SIGKILL'd if the supervisor dies rather than escaping all controls —
/// can be asserted in a unit test (protection suite §6.4).
pub(super) fn trace_options() -> nix::sys::ptrace::Options {
    use nix::sys::ptrace::Options;
    Options::PTRACE_O_TRACESYSGOOD
        | Options::PTRACE_O_TRACEEXEC
        | Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACESECCOMP
        | Options::PTRACE_O_EXITKILL
}

impl PtraceSupervisor {
    /// Configure ptrace options on a newly-stopped tracee.
    ///
    /// Enables:
    /// - `PTRACE_O_TRACESYSGOOD` -- sets bit 7 in the signal number on
    ///   syscall stops, allowing us to distinguish syscall traps from
    ///   regular `SIGTRAP` deliveries.
    /// - `PTRACE_O_TRACEFORK` / `TRACEVFORK` / `TRACECLONE` -- automatically
    ///   traces child processes so the entire process tree is supervised.
    /// - `PTRACE_O_TRACESECCOMP` -- receive `PTRACE_EVENT_SECCOMP` stops
    ///   when the seccomp-BPF filter returns `SECCOMP_RET_TRACE`.
    /// - `PTRACE_O_EXITKILL` -- send `SIGKILL` to all tracees if the tracer
    ///   exits unexpectedly, preventing supervised processes from escaping
    ///   all security controls when the supervisor crashes or is killed.
    pub(super) fn set_trace_options(&self, pid: Pid) -> Result<()> {
        ptrace::setoptions(pid, trace_options()).map_err(|e| {
            Error::InterceptionError(format!("PTRACE_SETOPTIONS failed for pid {pid}: {e}"))
        })
    }

    /// Resume the tracee and ask the kernel to stop it again at the next
    /// syscall entry or exit boundary.
    pub(super) fn resume_to_next_syscall(&self, pid: Pid, signal: Option<Signal>) -> Result<()> {
        match ptrace::syscall(pid, signal) {
            Ok(()) => Ok(()),
            // The tracee exited or was group-killed (`exit_group`) while stopped,
            // between its stop and this resume — a benign ptrace race, not a
            // supervisor failure. Resuming a dead tracee is a no-op; its exit is
            // reaped by the next `waitpid`. Never fatal (matches how the SIGKILL
            // path and `arch::read_syscall_regs` tolerate ESRCH).
            Err(nix::errno::Errno::ESRCH) => {
                trace!(
                    pid = pid.as_raw(),
                    "PTRACE_SYSCALL: tracee gone (ESRCH); ignoring"
                );
                Ok(())
            }
            Err(e) => Err(Error::InterceptionError(format!(
                "PTRACE_SYSCALL failed for pid {pid}: {e}"
            ))),
        }
    }

    /// Resume the tracee with `PTRACE_CONT`. Used with seccomp-BPF
    /// pre-filtering: the seccomp filter handles syscall selection, so we
    /// only need `PTRACE_CONT` instead of `PTRACE_SYSCALL`.
    pub(super) fn resume_continue(&self, pid: Pid, signal: Option<Signal>) -> Result<()> {
        match ptrace::cont(pid, signal) {
            Ok(()) => Ok(()),
            // See `resume_to_next_syscall`: a tracee that died in its stop
            // window yields ESRCH here. Benign — never fatal.
            Err(nix::errno::Errno::ESRCH) => {
                trace!(
                    pid = pid.as_raw(),
                    "PTRACE_CONT: tracee gone (ESRCH); ignoring"
                );
                Ok(())
            }
            Err(e) => Err(Error::InterceptionError(format!(
                "PTRACE_CONT failed for pid {pid}: {e}"
            ))),
        }
    }

    /// Resume the tracee using the appropriate method based on whether
    /// seccomp-BPF is active for it.
    ///
    /// Records the chosen primitive per-tid (wedge forensics): a clone child
    /// whose own initial stop is processed before its parent's CLONE event is
    /// not yet in `seccomp_tracees`, so it would be resumed here with
    /// `PTRACE_SYSCALL` ("SYSCALL") instead of `PTRACE_CONT` ("CONT") — the
    /// suspected wedge race. The recorded value is surfaced in `WedgedTracee`.
    pub(super) fn resume_tracee(&mut self, pid: Pid, signal: Option<Signal>) -> Result<()> {
        let tid = pid.as_raw() as u32;
        // In a spawned-with-seccomp session, EVERY tracee is under the TSYNC'd
        // filter — including clone children whose own initial stop is handled
        // before their parent's CLONE event registers them in `seccomp_tracees`
        // (the out-of-order race). Gate on the session flag, not per-tid set
        // membership, so such a child is never resumed with PTRACE_SYSCALL (the
        // confirmed wedge: clone threads landed in the syscall-fallback arm and
        // desynced). The PTRACE_SYSCALL fallback remains for attach-without-
        // seccomp sessions only.
        // B13: a thread holding a connected datagram socket aimed at a
        // non-loopback destination is stepped so its write/writev become
        // visible. Checked before the seccomp gate — those syscalls are not in
        // the filter, so PTRACE_CONT would run them unobserved. The window is
        // bounded by ConnectedDgramStepping (opened at connect to a
        // non-loopback peer, closed once the destination is allowed).
        if self.tid_is_stepping(tid) {
            self.last_resume_primitive.insert(tid, "SYSCALL");
            return self.resume_to_next_syscall(pid, signal);
        }
        if self.seccomp_session || self.seccomp_tracees.contains(&tid) {
            self.last_resume_primitive.insert(tid, "CONT");
            self.resume_continue(pid, signal)
        } else {
            self.last_resume_primitive.insert(tid, "SYSCALL");
            self.resume_to_next_syscall(pid, signal)
        }
    }

    /// True for destinations whose traffic never needs stepping: loopback and
    /// the unspecified address. This is the volume carve-out — DNS to
    /// `127.0.0.53` and local services are the bulk of connected-datagram
    /// traffic, and a loopback peer is not egress. IPv4-mapped IPv6 loopback
    /// (`::ffff:127.0.0.1`) is unwrapped so it cannot be used to dodge the
    /// check in the other direction.
    pub(super) fn is_loopback_destination(destination: &std::net::SocketAddr) -> bool {
        let ip = match destination.ip() {
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or(destination.ip(), std::net::IpAddr::V4),
            other => other,
        };
        ip.is_loopback() || ip.is_unspecified()
    }

    /// Whether the thread `tid` should be resumed with `PTRACE_SYSCALL`.
    ///
    /// Keyed by the *process*, not the thread: the fd table is shared across a
    /// thread group, so a sibling that never issued the `connect` can still
    /// write the socket. Every thread of a process holding such a socket is
    /// stepped.
    pub(super) fn tid_is_stepping(&self, tid: u32) -> bool {
        self.tid_tgids
            .get(&tid)
            .is_some_and(|tgid| self.stepping.contains_key(tgid))
    }

    /// Begin surfacing writes to `fd` — a datagram socket in `tgid` now
    /// connected to a non-loopback peer (go-live review B13).
    pub(super) fn promote_stepping(
        &mut self,
        tgid: u32,
        fd: i32,
        destination: std::net::SocketAddr,
    ) {
        let state = self.stepping.entry(tgid).or_default();
        if state.fds.insert(fd) {
            debug!(
                tgid,
                fd,
                %destination,
                tracked_fds = state.fds.len(),
                event = "connected_dgram_stepping_promoted",
                "stepping process so writes to a connected datagram socket are scored"
            );
        }
    }

    /// Begin stepping `tgid` so writes to a D-Bus channel on `fd` are decoded
    /// before the kernel sends them.
    ///
    /// Unlike the connected-datagram window this one closes only when the
    /// channel does (close, exec, exit) — see `ConnectedDgramStepping::dbus_fds`.
    pub(super) fn promote_dbus_stepping(&mut self, tgid: u32, fd: i32, address: &str) {
        let state = self.stepping.entry(tgid).or_default();
        if state.dbus_fds.insert(fd) {
            debug!(
                tgid,
                fd,
                address,
                tracked_fds = state.dbus_fds.len(),
                event = "dbus_stepping_promoted",
                "stepping process so D-Bus method calls are decoded before they are sent"
            );
        }
    }

    /// Stop stepping a D-Bus channel. Mirrors [`Self::demote_stepping_fd`]:
    /// the process keeps being stepped while it holds any other tracked fd.
    pub(super) fn demote_dbus_stepping(&mut self, tgid: u32, fd: i32, reason: &'static str) {
        let Some(state) = self.stepping.get_mut(&tgid) else {
            return;
        };
        if !state.dbus_fds.remove(&fd) {
            return;
        }
        let remaining = state.dbus_fds.len() + state.fds.len();
        if remaining == 0 {
            self.stepping.remove(&tgid);
        }
        debug!(
            tgid,
            fd,
            reason,
            remaining,
            event = "dbus_stepping_demoted",
            "stopped inspecting a D-Bus channel"
        );
    }

    /// Stop tracking one fd. Stepping ends only when the process has no
    /// tracked fds left — a process may hold several connected sockets at
    /// once, and forgetting one must not un-cover the others.
    pub(super) fn demote_stepping_fd(&mut self, tgid: u32, fd: i32, reason: &'static str) {
        let Some(state) = self.stepping.get_mut(&tgid) else {
            return;
        };
        if !state.fds.remove(&fd) {
            return;
        }
        // A D-Bus channel keeps the process stepped even with no datagram fds
        // left: its window closes on the connection, not on a write decision.
        let remaining = state.fds.len() + state.dbus_fds.len();
        if remaining == 0 {
            self.stepping.remove(&tgid);
        }
        debug!(
            tgid,
            fd,
            reason,
            remaining,
            event = "connected_dgram_stepping_demoted",
            "stopped tracking a connected datagram socket"
        );
    }

    /// Stop stepping the socket that `fd` refers to, by socket identity.
    ///
    /// `dup(2)` gives one socket several fd numbers, and the tracked fd is the
    /// one the `connect` was on. A write through a *different* alias must
    /// still demote the original, or the whole process stays two-stopped for
    /// the rest of its life (go-live review round 2). The tracker shares
    /// identity across dups, so this removes every tracked fd of the same
    /// socket, plus the written fd itself as a fallback.
    pub(super) fn demote_stepping_socket(&mut self, tgid: u32, fd: i32) {
        let target = self.dns_tracker.socket_id(tgid, fd);
        let Some(state) = self.stepping.get(&tgid) else {
            return;
        };
        let tracked: Vec<i32> = state.fds.iter().copied().collect();
        let mut to_remove: Vec<i32> = Vec::new();
        for tracked_fd in tracked {
            if tracked_fd == fd
                || (target.is_some() && self.dns_tracker.socket_id(tgid, tracked_fd) == target)
            {
                to_remove.push(tracked_fd);
            }
        }
        // The written fd may itself be tracked (the common, non-dup case).
        if !to_remove.contains(&fd) {
            to_remove.push(fd);
        }
        for f in to_remove {
            self.demote_stepping_fd(tgid, f, "connected-datagram socket no longer stepped");
        }
    }

    /// Stop tracking every fd of `tgid` (the process going away).
    pub(super) fn demote_stepping_tgid(&mut self, tgid: u32, reason: &'static str) {
        if self.stepping.remove(&tgid).is_some() {
            debug!(
                tgid,
                reason,
                event = "connected_dgram_stepping_demoted",
                "stopped stepping process for connected-datagram writes"
            );
        }
    }

    /// Re-evaluate connected-datagram stepping across an `execve` (go-live
    /// review B13 residual).
    ///
    /// A connected non-loopback datagram socket the pre-exec image opened
    /// survives exec unless it was `FD_CLOEXEC`; callers prune the tracker to the
    /// surviving fds *before* invoking this. Stepping is re-derived from the
    /// sockets that survive **in the tracker**, not from the pre-exec
    /// `state.fds`: a `dup`'d non-CLOEXEC alias shares socket identity but is a
    /// distinct fd number absent from `state.fds`, and can be the ONLY survivor
    /// when the fd the `connect` happened on was `FD_CLOEXEC`. Missing that alias
    /// reopened the exact per-write bypass B13 closes. The old image's threads
    /// are gone, so the whole stepping entry (fds + pending `awaiting`
    /// decisions) is cleared before re-arming survivors.
    fn resync_stepping_after_exec(&mut self, tgid: u32) {
        if !self.stepping.contains_key(&tgid) {
            return;
        }
        self.demote_stepping_tgid(tgid, "re-evaluating stepping across exec");
        self.rearm_surviving_connected_dgram_fds(tgid);
    }

    /// (Re-)arm stepping for every fd of `tgid` that is *currently* a connected
    /// off-host datagram socket in the tracker — including `dup`'d aliases,
    /// resolved through shared socket identity. Additive and idempotent (it
    /// never demotes), so it is safe to call after any targeted demote without
    /// disturbing pending write decisions on other threads. This is what keeps a
    /// surviving alias stepped after the fd the connect happened on is closed
    /// (no-exec variant) or `FD_CLOEXEC`-dropped across exec.
    fn rearm_surviving_connected_dgram_fds(&mut self, tgid: u32) {
        let mut survivors = 0usize;
        for fd in self.dns_tracker.tracked_fds(tgid) {
            if let Some(dest) = self.connected_dgram_egress_target(tgid, fd) {
                self.promote_stepping(tgid, fd, dest);
                survivors += 1;
            }
        }
        if survivors > 0 {
            debug!(
                tgid,
                survivors,
                event = "connected_dgram_stepping_rearmed",
                "re-armed stepping for surviving connected datagram sockets, including dup aliases (B13)"
            );
        }
    }

    /// Resolve the pending write decision for `tid`.
    ///
    /// `allowed` ends tracking for the fd that write named; a denial keeps it,
    /// because a thread that has tried to reach a rejected destination will
    /// try again. Either way the awaiting entry is cleared — leaving it set
    /// would make the next unrelated allowed syscall on this thread look like
    /// the decision and end stepping without one.
    pub(super) fn settle_stepping_decision(&mut self, tid: u32, allowed: bool) {
        let Some(tgid) = self.tid_tgids.get(&tid).copied() else {
            return;
        };
        let Some(state) = self.stepping.get_mut(&tgid) else {
            return;
        };
        let Some(fd) = state.awaiting.remove(&tid) else {
            return;
        };
        if allowed {
            // Demote by socket identity: the awaiting fd may be a dup'd alias
            // whose number is not the one in `state.fds`.
            self.demote_stepping_socket(tgid, fd);
        }
    }

    /// The destination a write to `fd` would reach, if that fd is a connected
    /// datagram socket aimed off-host.
    ///
    /// Resolved from the fd being written rather than from any fd recorded
    /// earlier: `dup(2)` gives one socket several descriptor numbers, and the
    /// tracker shares socket identity across them, so this catches every
    /// alias. It also re-checks liveness — the fd may have been closed and
    /// reused, or reconnected, since.
    pub(super) fn connected_dgram_egress_target(
        &self,
        tgid: u32,
        fd: i32,
    ) -> Option<std::net::SocketAddr> {
        if self.dns_tracker.socket_type(tgid, fd)
            != Some(super::dns_socket_tracker::SocketType::Datagram)
        {
            return None;
        }
        self.dns_tracker
            .connected_destination(tgid, fd)
            .filter(|d| !Self::is_loopback_destination(d))
    }

    /// Build the egress event for a write on a connected datagram socket.
    ///
    /// Reusing `NetConnect` means the whole existing path applies unchanged:
    /// the local carve-out, reverse-DNS enrichment, scoring, audit, and
    /// allow/deny of this very syscall.
    pub(super) fn connected_dgram_write_event(
        tgid: u32,
        tid: u32,
        fd: i32,
        destination: std::net::SocketAddr,
        nr: i64,
    ) -> SyscallEvent {
        warn!(
            tid,
            tgid,
            fd,
            %destination,
            syscall_nr = nr,
            event = "connected_dgram_write_scored",
            "write(2) on a connected datagram socket surfaced as egress"
        );
        SyscallEvent {
            pid: tgid,
            tid,
            timestamp: Utc::now(),
            kind: crate::interceptor::SyscallKind::NetConnect {
                address: destination.ip().to_string(),
                port: destination.port(),
                protocol: crate::interceptor::NetProtocol::Udp,
            },
            raw_syscall_nr: nr,
        }
    }

    // -- D-Bus message inspection -------------------------------------------

    /// Read the payload one outbound syscall is about to write.
    ///
    /// `None` means the payload could not be read out of tracee memory, which
    /// the caller must treat as a decode failure (poison → escalate), never as
    /// "nothing was sent".
    fn read_outbound_payload(
        &self,
        pid: Pid,
        nr: i64,
        regs: &super::arch::SyscallRegs,
    ) -> Option<Vec<u8>> {
        let limit = crate::dbus::wire::MAX_MESSAGE_LEN;
        match super::arch::sys_id(nr) {
            // write(fd, buf, count) / send(fd, buf, len, flags)
            Some(SysId::Write) | Some(SysId::Sendto) => {
                let len = (regs.args[2] as usize).min(limit);
                self.read_tracee_bytes(pid, regs.args[1], len).ok()
            }
            // writev(fd, iov, iovcnt)
            Some(SysId::Writev) => {
                self.read_iovecs(pid, regs.args[1], regs.args[2] as usize, limit)
            }
            // sendmsg(fd, msghdr, flags) — the payload is the iovec array at
            // offset 16 of the header. `msg_name` is meaningless on a
            // connected stream socket and is ignored.
            Some(SysId::Sendmsg) => {
                let iov_ptr = self.read_tracee_u64(pid, regs.args[1] + 16)?;
                let iovlen = self.read_tracee_u64(pid, regs.args[1] + 24)? as usize;
                self.read_iovecs(pid, iov_ptr, iovlen, limit)
            }
            // sendmmsg batches: the messages are contiguous on the wire, so
            // concatenating them in order reconstructs the byte stream. A
            // batch too large to walk is refused rather than partially read —
            // a valid prefix must not vouch for an uninspected suffix.
            Some(SysId::Sendmmsg) => {
                let vlen = regs.args[2] as usize;
                if vlen == 0 || vlen > crate::dbus::wire::MAX_MESSAGES_PER_CALL {
                    return None;
                }
                let mut out = Vec::new();
                for index in 0..vlen {
                    let header = regs.args[1].checked_add((index as u64) * MMSGHDR_SIZE)?;
                    let iov_ptr = self.read_tracee_u64(pid, header + 16)?;
                    let iovlen = self.read_tracee_u64(pid, header + 24)? as usize;
                    let remaining = limit.checked_sub(out.len())?;
                    out.extend(self.read_iovecs(pid, iov_ptr, iovlen, remaining)?);
                }
                Some(out)
            }
            _ => None,
        }
    }

    /// Decode what a tracee is about to write to a D-Bus channel and decide
    /// whether any of it needs a human.
    ///
    /// Returns `Some(event)` when at least one message must be scored — the
    /// caller stops the syscall and routes the event through the ordinary
    /// proxy path. `None` means every message on this write is curated as
    /// non-delegating (or the write carried only handshake bytes or a partial
    /// message), and the syscall proceeds with no prompt and no proxy round
    /// trip.
    ///
    /// A channel that cannot be decoded is poisoned and escalated. That is the
    /// same outcome `enforce_control_socket_connect` produced for the whole
    /// connection before inspection existed, so every failure path here is a
    /// fallback to the previous behaviour rather than a new hole.
    fn inspect_dbus_write(
        &mut self,
        pid: Pid,
        tgid: u32,
        tid: u32,
        fd: i32,
        nr: i64,
        regs: &super::arch::SyscallRegs,
    ) -> Option<SyscallEvent> {
        let socket = self.dbus_channels.address(tgid, fd)?.to_string();

        // An already-poisoned channel escalates every write without re-reading
        // tracee memory.
        if self.dbus_channels.is_poisoned(tgid, fd) {
            return Some(
                self.dbus_escalation_event(
                    tgid,
                    tid,
                    fd,
                    nr,
                    &socket,
                    Vec::new(),
                    self.dbus_channels
                        .poison_tag_for(tgid, fd)
                        .unwrap_or("poisoned"),
                ),
            );
        }

        let Some(payload) = self.read_outbound_payload(pid, nr, regs) else {
            self.dbus_channels.poison(tgid, fd, "payload-unreadable");
            return Some(self.dbus_escalation_event(
                tgid,
                tid,
                fd,
                nr,
                &socket,
                Vec::new(),
                "payload-unreadable",
            ));
        };

        // Decoded but not committed: the kernel has not accepted these bytes
        // yet, and may accept only some of them. The exit stop commits exactly
        // what went out — see `commit_dbus_write`.
        let outcome = self.dbus_channels.peek(tgid, fd, &payload);
        self.pending_dbus_write.insert(
            tid,
            super::PendingDbusWrite {
                tgid,
                fd,
                payload: payload.clone(),
            },
        );

        match outcome {
            crate::dbus::Feed::NotTracked => None,
            crate::dbus::Feed::Poisoned(tag) => {
                Some(self.dbus_escalation_event(tgid, tid, fd, nr, &socket, Vec::new(), tag))
            }
            crate::dbus::Feed::Messages(messages) => {
                let escalated: Vec<_> = messages
                    .into_iter()
                    .filter(|message| {
                        let escalate = matches!(
                            crate::dbus::classify(message),
                            crate::dbus::Verdict::Escalate { .. }
                        );
                        // The scope-only StartTransientUnit carve is the one
                        // body-dependent silent allow in the policy table, so
                        // leave a forensic marker with the unit name — a
                        // misclassification here must be findable after the
                        // fact without a packet capture.
                        if !escalate && message.member.as_deref() == Some("StartTransientUnit") {
                            tracing::info!(
                                event = "dbus_scope_transient_allowed",
                                unit = message.body_first_string.as_deref().unwrap_or("?"),
                                "transient .scope unit allowed — scope units cannot \
                                 execute outside the supervised tree"
                            );
                        }
                        escalate
                    })
                    .collect();
                if escalated.is_empty() {
                    return None;
                }
                Some(self.dbus_escalation_event(tgid, tid, fd, nr, &socket, escalated, "policy"))
            }
        }
    }

    /// Advance a D-Bus channel by the bytes its write actually delivered.
    ///
    /// Called at the syscall-exit stop, which a stepped process reaches for
    /// free. A negative return means the write failed and nothing reached the
    /// socket; a short count means the client will re-send the remainder.
    /// Either way the decoder must end up exactly where the socket is.
    fn commit_dbus_write(&mut self, tid: u32, result: i64) {
        let Some(pending) = self.pending_dbus_write.remove(&tid) else {
            return;
        };
        let accepted = usize::try_from(result).unwrap_or(0);
        self.dbus_channels
            .commit(pending.tgid, pending.fd, &pending.payload, accepted);
    }

    /// Build the event for a D-Bus write that needs a decision, and stage the
    /// pending record the event handler consumes.
    ///
    /// `escalated` is every message on this write the policy layer refused —
    /// possibly none, when the channel itself became undecodable. The operator
    /// is asked about the first; the rest ride along so one approval cannot
    /// cover a second call batched into the same syscall.
    fn dbus_escalation_event(
        &mut self,
        tgid: u32,
        tid: u32,
        fd: i32,
        nr: i64,
        socket: &str,
        escalated: Vec<crate::dbus::wire::DbusMessage>,
        reason: &'static str,
    ) -> SyscallEvent {
        let first = escalated.first().cloned().unwrap_or_default();
        warn!(
            tid,
            tgid,
            fd,
            socket,
            reason,
            call = %first.describe(),
            batched = escalated.len(),
            event = "dbus_method_call_escalated",
            "D-Bus method call surfaced for review"
        );
        self.pending_dbus_call.insert(
            tid,
            super::PendingDbusCall {
                escalated: escalated.clone(),
            },
        );
        SyscallEvent {
            pid: tgid,
            tid,
            timestamp: Utc::now(),
            kind: crate::interceptor::SyscallKind::DbusMethodCall {
                socket: socket.to_string(),
                destination: first.destination,
                interface: first.interface,
                member: first.member,
                path: first.path,
            },
            raw_syscall_nr: nr,
        }
    }

    /// Classify the ABI of the syscall a stopped tracee is entering, using the
    /// kernel's own syscall-entry record rather than the seccomp filter's
    /// return data (go-live review B1).
    ///
    /// Returns `None` for an ordinary x86_64 syscall, `Some(kind)` for one the
    /// x86_64 syscall table cannot describe.
    ///
    /// Why not the filter's `SECCOMP_RET_DATA`: a supervised process can
    /// install its own seccomp filter — `seccomp(2)` is not trapped, and grith
    /// itself sets `PR_SET_NO_NEW_PRIVS`, so nothing stands in the way. When
    /// several filters return the same action, the tracer sees the data of the
    /// most recently installed one, which is the tracee's. It could therefore
    /// zero grith's marker and have an `int 0x80` classified through the
    /// x86_64 table. `PTRACE_GET_SYSCALL_INFO` is filled in by the kernel from
    /// its own entry bookkeeping and no filter can influence it.
    ///
    /// Why not the `cs` selector: `int 0x80` issued from 64-bit code keeps
    /// `cs == 0x33`, so it does not distinguish the compat entry (measured).
    ///
    /// On a kernel without `PTRACE_GET_SYSCALL_INFO` (pre-5.3) this falls back
    /// to the filter data at seccomp stops — the only place that data is
    /// current — and to the syscall number register elsewhere.
    ///
    /// `at_seccomp_stop` must be true only when the current stop is a
    /// `PTRACE_EVENT_SECCOMP` stop. See `classify_foreign_abi` for why the
    /// distinction is load-bearing.
    pub(super) fn foreign_abi_at_stop(
        &self,
        pid: Pid,
        at_seccomp_stop: bool,
    ) -> Option<crate::interceptor::ForeignAbiKind> {
        Self::classify_foreign_abi(
            Self::syscall_info(pid),
            at_seccomp_stop,
            || ptrace::getevent(pid).map(|d| d as u64).unwrap_or(0),
            || super::arch::read_raw_syscall_nr(pid).map(|nr| nr as u64),
        )
    }

    /// The pure decision behind `foreign_abi_at_stop`: kernel entry record
    /// first, weaker sources only where they are actually meaningful.
    ///
    /// `event_data` (`PTRACE_GETEVENTMSG`) is consulted ONLY when the entry
    /// record is unsupported (pre-5.3) AND the stop is a seccomp stop — the
    /// one place the message is that stop's `SECCOMP_RET_DATA`. At syscall
    /// stops on ≥5.3 the kernel sets the message itself, to
    /// `PTRACE_EVENTMSG_SYSCALL_ENTRY` (1) / `PTRACE_EVENTMSG_SYSCALL_EXIT`
    /// (2) — and 2 is numerically equal to `SECCOMP_TRACE_DATA_X32`.
    /// Consulting the message at a syscall stop therefore classified every
    /// exit stop as an x32 syscall: the resulting hard-deny injected EPERM
    /// into ordinary completing syscalls, and on `futex(2)` glibc responded
    /// by aborting the whole supervised tree (B1 round 3).
    ///
    /// `entry_nr` (`orig_rax`) is the pre-5.3 fallback at non-seccomp stops:
    /// an x32 syscall is identifiable from bit 30 of the number the tracee
    /// itself loaded, while `int 0x80` cannot be told apart from a 64-bit
    /// call there (`cs` reads 0x33 for both) — a documented pre-5.3
    /// attach-mode gap.
    fn classify_foreign_abi(
        info: SyscallEntryInfo,
        at_seccomp_stop: bool,
        event_data: impl FnOnce() -> u64,
        entry_nr: impl FnOnce() -> Option<u64>,
    ) -> Option<crate::interceptor::ForeignAbiKind> {
        use crate::interceptor::ForeignAbiKind;

        match info {
            SyscallEntryInfo::Entry { arch, nr } => {
                if arch != super::arch::NATIVE_AUDIT_ARCH {
                    Some(ForeignAbiKind::CompatArch)
                } else if cfg!(target_arch = "x86_64")
                    && nr & u64::from(super::seccomp::X32_SYSCALL_BIT) != 0
                {
                    // x86_64-only: x32 is a second numbering under the native
                    // audit arch. No other architecture has an analog — on
                    // aarch64 the compat-ARM surface reports its own audit
                    // arch and is caught by the branch above.
                    Some(ForeignAbiKind::X32)
                } else {
                    // An ordinary x86_64 syscall, including an unknown or
                    // negative number. Those are left to normal
                    // classification, which declines to handle them and lets
                    // the kernel answer ENOSYS — turning a feature probe into
                    // EPERM would break `#define __NR_foo -1` idioms and fill
                    // the audit log with denials of nothing.
                    None
                }
            }
            // No entry record at this stop: nothing is about to execute, so
            // there is nothing to classify — and neither fallback source is
            // trustworthy here.
            SyscallEntryInfo::NotEntry => None,
            SyscallEntryInfo::Unsupported if at_seccomp_stop => {
                if cfg!(not(target_arch = "x86_64")) {
                    // Statically dead off x86_64: verify_kernel_support
                    // refuses pre-5.3 kernels at session start on the
                    // aarch64 backend, and the marker values are x86-shaped.
                    return None;
                }
                // Pre-5.3 seccomp stop: the event message is this stop's
                // filter marker, the best signal left. (A tracee-installed
                // filter can forge it on an action tie — accepted for
                // pre-5.3 kernels only; ≥5.3 never reaches this arm.)
                let data = event_data();
                if data == u64::from(super::seccomp::SECCOMP_TRACE_DATA_X32) {
                    Some(ForeignAbiKind::X32)
                } else if data == u64::from(super::seccomp::SECCOMP_TRACE_DATA_FOREIGN_ARCH) {
                    Some(ForeignAbiKind::CompatArch)
                } else {
                    None
                }
            }
            SyscallEntryInfo::Unsupported => {
                if cfg!(not(target_arch = "x86_64")) {
                    // See the seccomp-stop arm above: dead off x86_64.
                    return None;
                }
                // Pre-5.3 syscall stop (attach mode): the number the tracee
                // loaded is the only honest signal. Bit 30 marks x32; any
                // bit above it marks a negative or garbage value that is not
                // a syscall number at all and gets the kernel's own ENOSYS.
                match entry_nr() {
                    Some(nr)
                        if nr >> 31 == 0
                            && nr & u64::from(super::seccomp::X32_SYSCALL_BIT) != 0 =>
                    {
                        Some(crate::interceptor::ForeignAbiKind::X32)
                    }
                    _ => None,
                }
            }
        }
    }

    /// `PTRACE_GET_SYSCALL_INFO` → the kernel's syscall-entry record.
    ///
    /// The three-way split matters: "this stop carries no entry record"
    /// (`NotEntry`) and "the kernel cannot answer at all" (`Unsupported`,
    /// pre-5.3) demand different fallbacks. Conflating them let a stale
    /// `PTRACE_GETEVENTMSG` marker condemn an ordinary syscall on a modern
    /// kernel whenever a syscall-exit stop was misjudged as an entry
    /// (B1 round 3).
    fn syscall_info(pid: Pid) -> SyscallEntryInfo {
        use super::arch::{
            get_syscall_info, SyscallInfoResult, PTRACE_SYSCALL_INFO_ENTRY,
            PTRACE_SYSCALL_INFO_SECCOMP,
        };
        match get_syscall_info(pid) {
            SyscallInfoResult::Info(info)
                if info.op == PTRACE_SYSCALL_INFO_ENTRY
                    || info.op == PTRACE_SYSCALL_INFO_SECCOMP =>
            {
                SyscallEntryInfo::Entry {
                    arch: info.arch,
                    nr: info.data[0],
                }
            }
            // A non-entry op, or ESRCH: the tracee died in its stop — there
            // is no entry record to read, and that is `NotEntry`, not a
            // licence to guess from weaker sources.
            SyscallInfoResult::Info(_) | SyscallInfoResult::TraceeGone => {
                SyscallEntryInfo::NotEntry
            }
            // EIO on pre-5.3: the request itself is unknown.
            SyscallInfoResult::Unsupported => SyscallEntryInfo::Unsupported,
        }
    }

    /// Whether a `PTRACE_SYSCALL` stop is a syscall **exit** rather than an
    /// entry — from the kernel's own record, so no per-tid entry/exit toggle
    /// is needed (that toggle desynchronised whenever a promoted syscall's
    /// exit was consumed by another handler first — go-live review round 2).
    ///
    /// `Some(true)` = exit, `Some(false)` = entry/seccomp, `None` = the
    /// request is unsupported (pre-5.3), where the caller falls back to the
    /// `rax == -ENOSYS` entry heuristic.
    fn syscall_stop_is_exit(pid: Pid) -> Option<bool> {
        use super::arch::{get_syscall_info, SyscallInfoResult, PTRACE_SYSCALL_INFO_EXIT};
        match get_syscall_info(pid) {
            SyscallInfoResult::Info(info) => Some(info.op == PTRACE_SYSCALL_INFO_EXIT),
            // Tracee gone, or the request is unsupported (pre-5.3): the
            // caller falls back to its heuristic.
            SyscallInfoResult::TraceeGone | SyscallInfoResult::Unsupported => None,
        }
    }

    /// Read a null-terminated C string from the tracee's virtual address space.
    ///
    /// Reads one `c_long` (8 bytes on x86_64) at a time using
    /// `PTRACE_PEEKDATA` and scans each word for a null terminator. The
    /// read is capped at `max_len` bytes to prevent runaway reads on
    /// corrupted pointers.
    pub(super) fn read_tracee_string(&self, pid: Pid, addr: u64, max_len: usize) -> Result<String> {
        if addr == 0 {
            return Ok(String::new());
        }

        let mut buf: Vec<u8> = Vec::with_capacity(256);
        let mut offset: u64 = 0;
        let word_size = std::mem::size_of::<libc::c_long>() as u64;

        loop {
            if buf.len() >= max_len {
                break;
            }

            let word = ptrace::read(pid, (addr + offset) as *mut libc::c_void).map_err(|e| {
                Error::InterceptionError(format!(
                    "PTRACE_PEEKDATA at {:#x} failed for pid {pid}: {e}",
                    addr + offset
                ))
            })?;

            let bytes = word.to_ne_bytes();
            for &b in &bytes {
                if b == 0 {
                    return Ok(String::from_utf8_lossy(&buf).into_owned());
                }
                buf.push(b);
                if buf.len() >= max_len {
                    break;
                }
            }

            offset += word_size;
        }

        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    /// Read a null-pointer-terminated array of C string pointers from the
    /// tracee (e.g., `argv` or `envp`).
    pub(super) fn read_tracee_string_array(
        &self,
        pid: Pid,
        array_addr: u64,
        max_entries: usize,
    ) -> Result<Vec<String>> {
        let mut result = Vec::new();
        let ptr_size = std::mem::size_of::<u64>() as u64;

        for i in 0..max_entries {
            let ptr_addr = array_addr + (i as u64) * ptr_size;
            let raw = ptrace::read(pid, ptr_addr as *mut libc::c_void).map_err(|e| {
                Error::InterceptionError(format!(
                    "PTRACE_PEEKDATA (argv[{i}]) failed for pid {pid}: {e}"
                ))
            })?;

            let str_ptr = raw as u64;
            if str_ptr == 0 {
                break;
            }
            result.push(self.read_tracee_string(pid, str_ptr, 4096)?);
        }

        Ok(result)
    }

    fn read_tracee_u32(&self, pid: Pid, addr: u64) -> Option<u32> {
        let bytes = self.read_tracee_bytes(pid, addr, 4).ok()?;
        Some(u32::from_ne_bytes(bytes.try_into().ok()?))
    }

    fn read_tracee_u64(&self, pid: Pid, addr: u64) -> Option<u64> {
        let bytes = self.read_tracee_bytes(pid, addr, 8).ok()?;
        Some(u64::from_ne_bytes(bytes.try_into().ok()?))
    }

    fn read_socket_addr(&self, pid: Pid, addr: u64, len: usize) -> Option<SocketAddr> {
        if addr == 0 || len < 2 {
            return None;
        }
        let bytes = self.read_tracee_bytes(pid, addr, len.min(28)).ok()?;
        let family = u16::from_ne_bytes(bytes.get(0..2)?.try_into().ok()?) as i32;
        match family {
            libc::AF_INET if bytes.len() >= 16 => {
                let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
                let octets: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
            }
            libc::AF_INET6 if bytes.len() >= 28 => {
                let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
                let octets: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
                let scope_id = u32::from_ne_bytes(bytes.get(24..28)?.try_into().ok()?);
                Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    port,
                    0,
                    scope_id,
                )))
            }
            _ => None,
        }
    }

    /// Read and concatenate an x86_64 `iovec[]`, bounded by `limit`.
    fn read_iovecs(&self, pid: Pid, iov_ptr: u64, iovlen: usize, limit: usize) -> Option<Vec<u8>> {
        if iov_ptr == 0 || iovlen == 0 || iovlen > 1024 {
            return None;
        }
        let mut out = Vec::new();
        for index in 0..iovlen {
            if out.len() >= limit {
                break;
            }
            let entry = iov_ptr.checked_add((index as u64).checked_mul(16)?)?;
            let base = self.read_tracee_u64(pid, entry)?;
            let len = self.read_tracee_u64(pid, entry + 8)? as usize;
            if base == 0 && len != 0 {
                return None;
            }
            let take = len.min(limit - out.len());
            if take > 0 {
                out.extend(self.read_tracee_bytes(pid, base, take).ok()?);
            }
        }
        Some(out)
    }

    /// Read a send-side `iovec[]` and report whether the kernel-visible
    /// payload exceeds the inspection bound. Every entry is examined even
    /// after the byte buffer fills so a valid DNS prefix cannot hide an
    /// uninspected suffix.
    fn read_send_iovecs(
        &self,
        pid: Pid,
        iov_ptr: u64,
        iovlen: usize,
        limit: usize,
    ) -> Option<(Vec<u8>, bool)> {
        if iov_ptr == 0 || iovlen == 0 || iovlen > 1024 {
            return None;
        }
        let mut out = Vec::new();
        let mut total_len = 0usize;
        for index in 0..iovlen {
            let entry = iov_ptr.checked_add((index as u64).checked_mul(16)?)?;
            let base = self.read_tracee_u64(pid, entry)?;
            let len = usize::try_from(self.read_tracee_u64(pid, entry + 8)?).ok()?;
            if base == 0 && len != 0 {
                return None;
            }
            total_len = total_len.checked_add(len)?;
            let take = len.min(limit.saturating_sub(out.len()));
            if take > 0 {
                out.extend(self.read_tracee_bytes(pid, base, take).ok()?);
            }
        }
        Some((out, total_len > limit))
    }

    /// Decode the destination and payload from one x86_64 `msghdr`.
    fn read_msghdr(
        &self,
        pid: Pid,
        msghdr_ptr: u64,
        payload_limit: usize,
    ) -> Option<(Option<SocketAddr>, bool, Vec<u8>, bool)> {
        let name_ptr = self.read_tracee_u64(pid, msghdr_ptr)?;
        let name_len = self.read_tracee_u32(pid, msghdr_ptr + 8)? as usize;
        let iov_ptr = self.read_tracee_u64(pid, msghdr_ptr + 16)?;
        let iovlen = self.read_tracee_u64(pid, msghdr_ptr + 24)? as usize;
        let has_explicit_destination = name_ptr != 0;
        let destination = if !has_explicit_destination {
            None
        } else {
            let family_bytes = self.read_tracee_bytes(pid, name_ptr, 2).ok()?;
            let family = u16::from_ne_bytes(family_bytes.try_into().ok()?) as i32;
            if matches!(family, libc::AF_INET | libc::AF_INET6) {
                Some(self.read_socket_addr(pid, name_ptr, name_len)?)
            } else {
                None
            }
        };
        let (payload, oversized) = self.read_send_iovecs(pid, iov_ptr, iovlen, payload_limit)?;
        Some((destination, has_explicit_destination, payload, oversized))
    }

    fn read_recv_msghdr(&self, pid: Pid, msghdr_ptr: u64, returned_len: usize) -> Option<Vec<u8>> {
        let iov_ptr = self.read_tracee_u64(pid, msghdr_ptr + 16)?;
        let iovlen = self.read_tracee_u64(pid, msghdr_ptr + 24)? as usize;
        self.read_iovecs(pid, iov_ptr, iovlen, returned_len.min(MAX_DNS_MSG))
    }

    /// Read exactly `len` bytes from tracee memory at `addr`, word-by-word via
    /// `PTRACE_PEEKDATA`. Used to read the DNS query buffer (at `sendto`) and
    /// a kernel-filled response buffer (at a receive exit). `len` is
    /// capped by the caller (DNS messages are bounded).
    pub(super) fn read_tracee_bytes(&self, pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>> {
        let word_size = std::mem::size_of::<i64>();
        let mut out = Vec::with_capacity(len);
        let mut offset = 0usize;
        while offset < len {
            let current_addr = addr + offset as u64;
            let word = ptrace::read(pid, current_addr as *mut libc::c_void).map_err(|e| {
                Error::InterceptionError(format!(
                    "PTRACE_PEEKDATA at {current_addr:#x} for pid {pid}: {e}"
                ))
            })?;
            let bytes = word.to_ne_bytes();
            let take = word_size.min(len - offset);
            out.extend_from_slice(&bytes[..take]);
            offset += word_size;
        }
        Ok(out)
    }

    /// Handle a ptrace process-creation event (fork/vfork/clone) by
    /// extracting the new child PID and registering it for supervision.
    ///
    /// Thread/process identity is derived from the kernel-reported TGIDs, not
    /// from the ptrace event number. `PTRACE_EVENT_CLONE` can describe a
    /// separate process when its exit signal is not `SIGCHLD`.
    pub(super) fn handle_ptrace_event(&mut self, pid: Pid, event: i32) -> Result<Option<u32>> {
        let child_pid = ptrace::getevent(pid).map_err(|e| {
            Error::InterceptionError(format!("PTRACE_GETEVENTMSG failed for pid {pid}: {e}"))
        })? as u32;

        // Register first so a later fail-closed error still lets the outer
        // supervisor terminate the newly-created tracee.
        self.supervised.insert(child_pid);
        if self.seccomp_tracees.contains(&(pid.as_raw() as u32)) {
            self.seccomp_tracees.insert(child_pid);
        }

        // Belt-and-suspenders: re-assert the trace options on the new child
        // rather than trusting kernel inheritance of `PTRACE_O_TRACEEXEC`. If
        // the child's very first act is `execve` (the `posix_spawn`
        // fork-then-exec shape), a missing TRACEEXEC would drop its
        // `PTRACE_EVENT_EXEC` and the spawn would go untagged. Best-effort: the
        // child may not be individually ptrace-stopped yet (ESRCH) — options
        // are idempotent and the provenance backfill in the event handler is
        // the durable safety net, so a failure here is not fatal.
        let _ = self.set_trace_options(Pid::from_raw(child_pid as i32));

        let parent_tid = pid.as_raw() as u32;
        let clone_snapshot = self.pending_clone_fd_table.remove(&parent_tid);
        let exact_identity_required = self.connected_dns_proxy.is_some();
        let parent_tgid = match Self::resolve_tgid(parent_tid) {
            Some(tgid) => tgid,
            None if exact_identity_required => {
                return Err(Error::InterceptionError(format!(
                    "could not resolve parent TGID for clone event from tid {parent_tid}"
                )));
            }
            None => parent_tid,
        };
        let child_tgid = match Self::resolve_tgid(child_pid) {
            Some(tgid) => tgid,
            None if exact_identity_required => {
                return Err(Error::InterceptionError(format!(
                    "could not resolve child TGID for clone event child {child_pid}"
                )));
            }
            None => child_pid,
        };
        self.tid_tgids.insert(parent_tid, parent_tgid);
        self.tid_tgids.insert(child_pid, child_tgid);

        // `vfork(2)` has fixed non-CLONE_FILES semantics. Every other child
        // event in a proxy-enabled seccomp session must be backed by the exact
        // entry-time snapshot. In particular, never re-read clone3's mutable
        // `struct clone_args` after the child already exists.
        let clone_flags = if event == libc::PTRACE_EVENT_VFORK {
            Some(0)
        } else if let Some(snapshot) = clone_snapshot {
            debug!(
                parent = parent_tid,
                syscall_nr = snapshot.syscall_nr,
                clone_flags = snapshot.flags,
                "using entry-time clone FD-table snapshot"
            );
            Some(snapshot.flags)
        } else if exact_identity_required {
            return Err(self.terminate_after_dns_redirect_failure(
                parent_tgid,
                "child creation lacked an exact entry-time FD-table snapshot",
            ));
        } else {
            // A PTRACE_EVENT stop carries no syscall-info record, so this
            // reads the entry-time values still held in the registers.
            super::arch::read_syscall_regs(pid)
                .ok()
                .flatten()
                .and_then(|regs| match super::arch::sys_id(regs.nr) {
                    Some(SysId::Fork) => Some(0),
                    Some(SysId::Clone) => Some(regs.args[0]),
                    _ => None,
                })
        };
        let is_thread_clone = is_thread_group_child(parent_tgid, child_tgid);

        // The current tracker has one FD-table identity per TGID. Linux permits
        // CLONE_THREAD without CLONE_FILES, which would create two tables in
        // one TGID and make subsequent DNS ownership ambiguous. The clone has
        // already happened by this ptrace event, so a proxy-enabled session
        // must terminate rather than resume either task.
        if self.connected_dns_proxy.is_some()
            && clone_creates_private_thread_fd_table(parent_tgid, child_tgid, clone_flags)
        {
            self.thread_tids.insert(child_pid);
            return Err(self.terminate_after_dns_redirect_failure(
                parent_tgid,
                "CLONE_THREAD without a provable CLONE_FILES share is unsupported \
                 while connected DNS proxying is active",
            ));
        }

        if is_thread_clone {
            debug!(
                parent = parent_tid,
                parent_tgid,
                thread_tid = child_pid,
                "new thread detected from matching TGID"
            );
            self.thread_tids.insert(child_pid);
        } else {
            info!(
                parent = parent_tid,
                parent_tgid,
                child = child_pid,
                child_tgid,
                "new child process detected via ptrace event"
            );
        }
        if child_tgid != parent_tgid {
            let released = self.dns_tracker.inherit_process(
                parent_tgid,
                child_tgid,
                clone_shares_fd_table(clone_flags),
            );
            for route_id in released {
                let Some(control) = &self.connected_dns_proxy else {
                    return Err(Error::InterceptionError(format!(
                        "inherited FD-table replacement released connected DNS route {} without a live control plane",
                        route_id.0
                    )));
                };
                control
                    .release_route(Self::connected_route_id(route_id))
                    .map_err(|error| {
                        Error::InterceptionError(format!(
                            "failed to release connected DNS route {} displaced by child inheritance: {error}",
                            route_id.0
                        ))
                    })?;
            }

            // B13: a fork child inherits the fd table — including any
            // connected non-loopback datagram socket — but gets a new TGID,
            // and stepping is keyed by TGID. Without propagating, the child's
            // write egresses unobserved (go-live review round 2). The child
            // holds the same fd numbers, and `inherit_process` above copied
            // the tracker's socket identity, so the parent's tracked fds are
            // the child's connected sockets too.
            if let Some(parent_state) = self.stepping.get(&parent_tgid) {
                let inherited: Vec<i32> = parent_state.fds.iter().copied().collect();
                if !inherited.is_empty() {
                    let child_state = self.stepping.entry(child_tgid).or_default();
                    for fd in &inherited {
                        child_state.fds.insert(*fd);
                    }
                    debug!(
                        parent_tgid,
                        child_tgid,
                        fds = inherited.len(),
                        event = "connected_dgram_stepping_inherited",
                        "fork child inherits connected-datagram stepping"
                    );
                }
            }

            // The child inherits the parent's bus descriptors too. They are
            // copied poisoned — parent and child now share one open file
            // description, so their writes interleave and neither side's
            // reassembly can be trusted — and stepped, so the child's writes
            // are seen and escalate rather than vanishing.
            let inherited = self.dbus_channels.inherit_process(parent_tgid, child_tgid);
            if !inherited.is_empty() {
                debug!(
                    parent_tgid,
                    child_tgid,
                    fds = inherited.len(),
                    event = "dbus_channel_inherited",
                    "fork child inherits D-Bus channels, poisoned"
                );
                for fd in inherited {
                    self.promote_dbus_stepping(child_tgid, fd, "inherited across fork");
                }
            }
        }

        // The kernel may report a clone child's initial stop before the
        // parent's PTRACE_EVENT_* stop. Only release that child after its exact
        // TGID and FD-table inheritance are committed above.
        if self.pending_child_initial_stops.remove(&child_pid) {
            record_event(self, child_pid, "ptrace-event:child-inheritance-ready");
            self.resume_tracee(Pid::from_raw(child_pid as i32), None)?;
        }

        Ok(Some(child_pid))
    }

    /// Resolve the thread-group leader PID (TGID) for a given TID by
    /// reading `/proc/<tid>/status`.
    ///
    /// Returns `None` if the file cannot be read or parsed (e.g., the
    /// process has already exited).
    fn resolve_tgid(tid: u32) -> Option<u32> {
        let status = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("Tgid:") {
                return value.trim().parse::<u32>().ok();
            }
        }
        None
    }

    /// Inspect every DNS message carried by one outbound syscall. `None`
    /// means the syscall did not target DNS. `Some` always routes through the
    /// handler's allow/deny path, including explicit parse failures.
    fn inspect_dns_send(
        &mut self,
        pid: Pid,
        tgid: u32,
        fd: i32,
        nr: i64,
        regs: &super::arch::SyscallRegs,
    ) -> Option<crate::interceptor::DnsQueryInspection> {
        // Ownership is selected by shared socket route, not syscall shape.
        // A proxy-owned send is inspected by the route worker even when libc
        // lowers `send()` to sendto/sendmsg. Recording it here would create a
        // duplicate policy decision and inline transaction.
        if self.dns_tracker.is_connected_proxy(tgid, fd) {
            return None;
        }
        if self.dns_tracker.socket_type(tgid, fd)
            == Some(super::dns_socket_tracker::SocketType::Other)
        {
            return None;
        }
        let sid = super::arch::sys_id(nr);
        let mut messages: Vec<(Option<SocketAddr>, bool, Vec<u8>, bool)> = Vec::new();
        match sid {
            Some(SysId::Sendto) => {
                let destination = if regs.args[4] == 0 {
                    None
                } else {
                    match self.read_socket_addr(pid, regs.args[4], regs.args[5] as usize) {
                        Some(addr) => Some(addr),
                        None => {
                            // A non-null, unreadable destination is a
                            // classification failure. The caller will deny the
                            // syscall through the normal fail-closed path.
                            return None;
                        }
                    }
                };
                let payload = match self.read_tracee_bytes(
                    pid,
                    regs.args[1],
                    (regs.args[2] as usize).min(MAX_DNS_MSG),
                ) {
                    Ok(payload) => payload,
                    Err(_)
                        if destination.is_some_and(|addr| addr.port() == 53)
                            || self.dns_tracker.is_dns(tgid, fd) =>
                    {
                        return Some(crate::interceptor::DnsQueryInspection {
                            queries: Vec::new(),
                            parse_error: Some("dns-port53-payload-read-failed".into()),
                        });
                    }
                    Err(_) => return None,
                };
                messages.push((
                    destination,
                    regs.args[4] != 0,
                    payload,
                    regs.args[2] as usize > MAX_DNS_MSG,
                ));
            }
            Some(SysId::Sendmsg) => {
                let Some(message) = self.read_msghdr(pid, regs.args[1], MAX_DNS_MSG) else {
                    return Some(crate::interceptor::DnsQueryInspection {
                        queries: Vec::new(),
                        parse_error: Some("sendmsg-inspection-failed".into()),
                    });
                };
                messages.push(message);
            }
            Some(SysId::Sendmmsg) => {
                let vlen = regs.args[2] as usize;
                if vlen == 0 {
                    return None;
                }
                if vlen > MAX_DNS_BATCH {
                    // A tracked DNS socket proves the entire oversized batch is
                    // DNS. For an unconnected socket we cannot safely exclude a
                    // port-53 destination hidden beyond the cap, so fail closed
                    // while DNS inspection is active.
                    return Some(crate::interceptor::DnsQueryInspection {
                        queries: Vec::new(),
                        parse_error: Some(format!(
                            "dns-sendmmsg-batch-too-large:{vlen}>{MAX_DNS_BATCH}"
                        )),
                    });
                }
                let mut total_iovecs = 0usize;
                for index in 0..vlen {
                    let header = regs.args[1].checked_add((index as u64) * MMSGHDR_SIZE)?;
                    let iovlen = self.read_tracee_u64(pid, header + 24)? as usize;
                    total_iovecs = total_iovecs.checked_add(iovlen)?;
                    if total_iovecs > MAX_DNS_BATCH_IOVECS {
                        return Some(crate::interceptor::DnsQueryInspection {
                            queries: Vec::new(),
                            parse_error: Some(format!(
                                "sendmmsg-iovec-budget-exceeded:{}>{MAX_DNS_BATCH_IOVECS}",
                                total_iovecs
                            )),
                        });
                    }
                    let Some(message) = self.read_msghdr(pid, header, MAX_DNS_MSG) else {
                        return Some(crate::interceptor::DnsQueryInspection {
                            queries: Vec::new(),
                            parse_error: Some(format!(
                                "sendmmsg-inspection-failed-at-index:{index}"
                            )),
                        });
                    };
                    messages.push(message);
                }
            }
            _ => return None,
        }

        let connected = self.dns_tracker.connected_destination(tgid, fd);
        let mut dns_payloads = Vec::new();
        let mut saw_non_dns = false;
        for (explicit_destination, has_explicit_destination, payload, oversized) in messages {
            let effective = if has_explicit_destination {
                explicit_destination
            } else {
                connected
            };
            if effective.is_some_and(|addr| addr.port() == 53)
                || (effective.is_none() && self.dns_tracker.is_dns(tgid, fd))
            {
                if oversized {
                    return Some(crate::interceptor::DnsQueryInspection {
                        queries: Vec::new(),
                        parse_error: Some(format!("dns-payload-too-large:>{MAX_DNS_MSG}")),
                    });
                }
                if let Some(destination) = effective {
                    self.dns_tracker.discover_dns(tgid, fd, destination);
                    trace!(
                        tgid,
                        tid = pid.as_raw(),
                        fd,
                        resolver = %destination,
                        source = if explicit_destination.is_some() { "message" } else { "connect" },
                        "DNS socket discovered"
                    );
                }
                dns_payloads.push(payload);
            } else {
                saw_non_dns = true;
            }
        }
        if dns_payloads.is_empty() {
            return None;
        }
        if saw_non_dns {
            return Some(crate::interceptor::DnsQueryInspection {
                queries: Vec::new(),
                parse_error: Some("dns-sendmmsg-mixed-destinations".into()),
            });
        }

        let mut queries = Vec::with_capacity(dns_payloads.len());
        let mut transactions = Vec::with_capacity(dns_payloads.len());
        for payload in dns_payloads {
            let Some(parsed) = crate::dns_proxy::parse_query(&payload) else {
                warn!(
                    tgid,
                    tid = pid.as_raw(),
                    fd,
                    syscall_nr = nr,
                    "outbound port-53 payload is not valid DNS"
                );
                return Some(crate::interceptor::DnsQueryInspection {
                    queries: Vec::new(),
                    parse_error: Some("dns-port53-unparseable".into()),
                });
            };
            trace!(
                tgid,
                tid = pid.as_raw(),
                fd,
                dns_id = parsed.id,
                qtype = %parsed.query_type,
                "DNS query inspected"
            );
            transactions.push(super::dns_socket_tracker::QueryMetadata {
                id: parsed.id,
                domain: parsed.domain.clone(),
                qtype: parsed.qtype,
            });
            queries.push((parsed.domain, parsed.query_type));
        }
        let Some(socket_id) = self.dns_tracker.socket_id(tgid, fd) else {
            return Some(crate::interceptor::DnsQueryInspection {
                queries: Vec::new(),
                parse_error: Some("dns-socket-identity-lost".into()),
            });
        };
        for transaction in transactions.iter().cloned() {
            self.dns_tracker
                .remember_query_for_socket(socket_id, transaction);
        }
        self.pending_inline_dns_transactions.insert(
            pid.as_raw() as u32,
            super::PendingInlineDnsTransactions {
                socket_id,
                queries: transactions,
            },
        );
        Some(crate::interceptor::DnsQueryInspection {
            queries,
            parse_error: None,
        })
    }

    /// Return true only for a send form whose peer cannot be changed through
    /// mutable tracee memory after this ptrace stop.
    ///
    /// `send()` lowers to `sendto(..., NULL, 0)`, so a null `dest_addr`
    /// argument safely uses the socket's connected proxy peer. `sendmsg` and
    /// `sendmmsg` keep `msg_name` in caller-owned memory; a sibling could turn
    /// a checked null pointer into an explicit direct destination before the
    /// kernel copies the header. Deny both message APIs until the supervisor
    /// can substitute an immutable/scratch header.
    fn proxy_send_uses_supported_connected_form(nr: i64, regs: &super::arch::SyscallRegs) -> bool {
        super::arch::sys_id(nr) == Some(SysId::Sendto) && regs.args[4] == 0
    }

    fn record_dns_response(&mut self, pending: super::DnsRecvPending, response: &[u8]) {
        let response_api = match pending.kind {
            super::DnsRecvKind::From { .. } => "recvfrom",
            super::DnsRecvKind::Msg { .. } => "recvmsg",
            super::DnsRecvKind::Mmsg { .. } => "recvmmsg",
        };
        let Some(parsed) = crate::dns_proxy::parse_response(response) else {
            warn!(
                tgid = pending.tgid,
                fd = pending.fd,
                response_api,
                "DNS response parse failed; response ignored"
            );
            return;
        };
        let Some(query) = self.dns_tracker.take_matching_query_for_socket(
            pending.socket_id,
            parsed.id,
            &parsed.domain,
            parsed.qtype,
        ) else {
            warn!(
                tgid = pending.tgid,
                fd = pending.fd,
                dns_id = parsed.id,
                "unsolicited or conflicting DNS response ignored"
            );
            return;
        };
        let answer_count = parsed.answers.len();
        if let Some(cache) = &self.dns_cache {
            match cache.lock() {
                Ok(mut cache) => {
                    if let Err(error) = cache.commit_observed_batch(
                        &query.domain,
                        parsed
                            .answers
                            .into_iter()
                            .map(|answer| (answer.ip, answer.ttl)),
                        pending.tgid,
                    ) {
                        warn!(
                            tgid = pending.tgid,
                            fd = pending.fd,
                            error = %error,
                            "DNS response cache batch rejected"
                        );
                        return;
                    }
                }
                Err(_) => {
                    warn!(
                        tgid = pending.tgid,
                        fd = pending.fd,
                        "DNS response cache lock poisoned"
                    );
                    return;
                }
            }
        }
        trace!(
            tgid = pending.tgid,
            fd = pending.fd,
            dns_id = parsed.id,
            answer_count,
            response_api,
            "DNS response attributed"
        );
    }

    fn connected_route_id(
        route_id: super::dns_socket_tracker::DnsRouteId,
    ) -> crate::connected_dns_proxy::ConnectedDnsRouteId {
        crate::connected_dns_proxy::ConnectedDnsRouteId(route_id.0)
    }

    /// Not `async`: releasing a route is a synchronous call into the proxy's
    /// control plane. Rust 1.98's `clippy::unused_async_trait_impl` refuses an
    /// `async fn` with no `.await` in it, and every caller is already on an
    /// async task, so dropping the `async` costs them nothing.
    fn release_connected_route(
        &self,
        route_id: super::dns_socket_tracker::DnsRouteId,
    ) -> Result<()> {
        let Some(control) = &self.connected_dns_proxy else {
            return Err(Error::InterceptionError(format!(
                "connected DNS route {} has no live proxy control plane",
                route_id.0
            )));
        };
        control
            .release_route(Self::connected_route_id(route_id))
            .map_err(|error| {
                Error::InterceptionError(format!(
                    "failed to release connected DNS route {}: {error}",
                    route_id.0
                ))
            })
    }

    /// Synchronous for the same reason as [`Self::release_connected_route`],
    /// which it loops over.
    fn release_connected_routes(
        &self,
        route_ids: impl IntoIterator<Item = super::dns_socket_tracker::DnsRouteId>,
    ) -> Result<()> {
        for route_id in route_ids {
            self.release_connected_route(route_id)?;
        }
        Ok(())
    }

    fn sockaddr_family(&self, pid: Pid, sockaddr_ptr: u64) -> Option<i32> {
        if sockaddr_ptr == 0 {
            return None;
        }
        let word = ptrace::read(pid, sockaddr_ptr as *mut libc::c_void).ok()?;
        let bytes = word.to_ne_bytes();
        Some(u16::from_ne_bytes([bytes[0], bytes[1]]) as i32)
    }

    fn terminate_after_dns_redirect_failure(&self, tgid: u32, reason: &str) -> Error {
        if let Err(error) = nix::sys::signal::kill(Pid::from_raw(tgid as i32), Signal::SIGKILL) {
            warn!(
                tgid,
                error = %error,
                "failed to terminate tracee after connected DNS redirect failure"
            );
        }
        Error::InterceptionError(format!(
            "fatal connected DNS redirect failure for tgid {tgid}: {reason}"
        ))
    }

    fn proxy_route_requires_session_termination_on_detach(&self) -> bool {
        self.dns_tracker.has_connected_proxy_routes() || !self.pending_dns_connect_exit.is_empty()
    }

    /// Read the executable path and command-line arguments for a process
    /// from `/proc/<pid>/exe` and `/proc/<pid>/cmdline`.
    ///
    /// Used after `PTRACE_EVENT_EXEC` when the original `execve` register
    /// arguments are no longer available.
    fn read_exec_info(pid: u32) -> (String, Vec<String>) {
        let path = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| format!("<pid:{pid}>"));

        let args = std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|data| {
                data.split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect()
            })
            .unwrap_or_default();

        (path, args)
    }
}

// ---------------------------------------------------------------------------
// SyscallInterceptor trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl SyscallInterceptor for PtraceSupervisor {
    fn set_attach_mode(&mut self, mode: crate::config::AttachMode) {
        self.attach_mode = mode;
    }

    fn set_dns_inspection(
        &mut self,
        cache: std::sync::Arc<std::sync::Mutex<crate::dns_cache::DnsCache>>,
        observe_responses: bool,
        block_tcp_dns: bool,
    ) {
        self.enable_dns_inspection(cache, observe_responses, block_tcp_dns);
    }

    fn set_dbus_inspection(&mut self) -> bool {
        self.enable_dbus_inspection()
    }

    fn set_connected_dns_proxy(
        &mut self,
        control: crate::connected_dns_proxy::ConnectedDnsProxyControl,
    ) -> Result<()> {
        if !self.seccomp_session {
            return Err(Error::ConfigError(
                "connected UDP DNS proxy is supported only for processes \
                 spawned under the seccomp-ptrace path; attach sessions cannot \
                 guarantee pre-connect redirection"
                    .into(),
            ));
        }
        self.enable_connected_dns_proxy(control);
        Ok(())
    }

    async fn terminate_all(&mut self) -> Result<()> {
        let tgids: std::collections::HashSet<u32> = self
            .supervised
            .iter()
            .map(|tid| Self::resolve_tgid(*tid).unwrap_or(*tid))
            .collect();
        let mut first_error = None;
        for tgid in tgids {
            if let Err(error) = nix::sys::signal::kill(Pid::from_raw(tgid as i32), Signal::SIGKILL)
            {
                if error != nix::errno::Errno::ESRCH && first_error.is_none() {
                    first_error = Some((tgid, error));
                }
            }
        }
        if let Some((tgid, error)) = first_error {
            return Err(Error::InterceptionError(format!(
                "failed to terminate supervised process {tgid}: {error}"
            )));
        }
        Ok(())
    }

    fn take_tcp_dns_deny(&mut self, tid: u32) -> bool {
        self.pending_tcp_dns_deny.remove(&tid)
    }

    fn take_dns_query(&mut self, tid: u32) -> Option<crate::interceptor::DnsQueryInspection> {
        self.pending_dns_query.remove(&tid)
    }

    fn take_dbus_method_calls(&mut self, tid: u32) -> Vec<crate::interceptor::DbusCallSummary> {
        // Peeked, not removed: `allow`/`deny` consume the entry, and they need
        // it to decide whether an approved write may proceed as-is.
        self.pending_dbus_call
            .get(&tid)
            .map(|pending| {
                pending
                    .escalated
                    .iter()
                    .map(|message| crate::interceptor::DbusCallSummary {
                        description: message.describe(),
                        destination: message.destination.clone(),
                        interface: message.interface.clone(),
                        member: message.member.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn finish_dns_query(&mut self, tid: u32, allowed: bool) {
        let Some(pending) = self.pending_inline_dns_transactions.remove(&tid) else {
            return;
        };
        if !allowed {
            for query in &pending.queries {
                self.dns_tracker
                    .forget_query_for_socket(pending.socket_id, query);
            }
        }
    }

    /// Attach to an already-running process by PID.
    ///
    /// Sends `PTRACE_ATTACH` which delivers a `SIGSTOP` to the target. The
    /// tracer waits for the initial stop, configures tracing options, then
    /// returns. The caller should proceed to call [`next_event`] in a loop.
    async fn attach(&mut self, pid: u32) -> Result<()> {
        let nix_pid = Pid::from_raw(pid as i32);

        ptrace::attach(nix_pid).map_err(|e| Error::AttachFailed {
            pid,
            reason: format!("PTRACE_ATTACH: {e}"),
        })?;

        // Wait for the initial SIGSTOP delivered by PTRACE_ATTACH.
        waitpid(nix_pid, None).map_err(|e| Error::AttachFailed {
            pid,
            reason: format!("waitpid after attach: {e}"),
        })?;

        // Attached tracee is stopped: probe required kernel capabilities
        // (aarch64 >= 5.3 floor; no-op on x86_64) before classifying anything.
        super::arch::verify_kernel_support(nix_pid)?;
        self.set_trace_options(nix_pid)?;
        self.supervised.insert(pid);
        self.tid_tgids
            .insert(pid, Self::resolve_tgid(pid).unwrap_or(pid));
        if self.root_pid.is_none() {
            self.root_pid = Some(pid);
        }

        // Resume the tracee so it continues execution (and stops at its
        // next syscall entry/exit).  Without this, the process stays in
        // the SIGSTOP delivered by PTRACE_ATTACH and never runs.
        self.resume_to_next_syscall(nix_pid, None)?;

        info!(pid, "attached to process via ptrace");
        Ok(())
    }

    /// Spawn a child process under full ptrace supervision.
    ///
    /// Uses the classic fork-and-trace pattern. See [`child::spawn_supervised`]
    /// for the fork implementation.
    async fn spawn_supervised(
        &mut self,
        command: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<u32> {
        super::child::do_spawn_supervised(self, command, args, env).await
    }

    /// Block until the next security-relevant syscall event from any
    /// supervised process.
    ///
    /// Uses SIGCHLD-driven wakeups instead of polling: the kernel sends
    /// SIGCHLD when any child stops or exits, and we await that signal
    /// via Tokio. This gives near-zero latency wakeups with zero CPU
    /// waste between events.
    ///
    /// After waking, drains all ready events via `waitpid(-1, WNOHANG)`
    /// to handle SIGCHLD coalescing (multiple children stopping between
    /// signal deliveries).
    async fn next_event(&mut self) -> Result<Option<SyscallEvent>> {
        if self.supervised.is_empty() {
            return Ok(None);
        }

        // Lazily initialize the SIGCHLD signal stream.
        if self.sigchld.is_none() {
            self.sigchld = Some(
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child()).map_err(
                    |e| {
                        Error::InterceptionError(format!("failed to register SIGCHLD handler: {e}"))
                    },
                )?,
            );
        }

        loop {
            if let Some(control) = &self.connected_dns_proxy {
                match control.health() {
                    crate::connected_dns_proxy::ConnectedDnsProxyHealth::Ready => {}
                    crate::connected_dns_proxy::ConnectedDnsProxyHealth::Starting => {
                        return Err(Error::InterceptionError(
                            "connected DNS proxy returned to starting state".into(),
                        ));
                    }
                    crate::connected_dns_proxy::ConnectedDnsProxyHealth::Unhealthy(reason) => {
                        let tgids: std::collections::HashSet<u32> = self
                            .supervised
                            .iter()
                            .map(|tid| Self::resolve_tgid(*tid).unwrap_or(*tid))
                            .collect();
                        for tgid in tgids {
                            let _ =
                                nix::sys::signal::kill(Pid::from_raw(tgid as i32), Signal::SIGKILL);
                        }
                        return Err(Error::InterceptionError(format!(
                            "connected DNS proxy became unhealthy: {reason}"
                        )));
                    }
                    crate::connected_dns_proxy::ConnectedDnsProxyHealth::Stopped => {
                        let tgids: std::collections::HashSet<u32> = self
                            .supervised
                            .iter()
                            .map(|tid| Self::resolve_tgid(*tid).unwrap_or(*tid))
                            .collect();
                        for tgid in tgids {
                            let _ =
                                nix::sys::signal::kill(Pid::from_raw(tgid as i32), Signal::SIGKILL);
                        }
                        return Err(Error::InterceptionError(
                            "connected DNS proxy stopped during an active session".into(),
                        ));
                    }
                }
            }

            // Drain all ready events (non-blocking). SIGCHLD can coalesce,
            // so we must drain everything before waiting for the next signal.
            let status = match waitpid(
                Pid::from_raw(-1),
                Some(WaitPidFlag::WNOHANG | WaitPidFlag::__WALL),
            ) {
                Ok(WaitStatus::StillAlive) => {
                    // No events ready — wait for SIGCHLD from kernel.
                    if let Some(ref mut sigchld) = self.sigchld {
                        sigchld.recv().await;
                    }
                    continue;
                }
                Ok(status) => status,
                Err(nix::errno::Errno::ECHILD) => {
                    // No more children to wait for.
                    self.supervised.clear();
                    self.in_syscall_entry.clear();
                    self.thread_tids.clear();
                    self.tid_tgids.clear();
                    self.pending_clone_fd_table.clear();
                    self.pending_child_initial_stops.clear();
                    self.seccomp_tracees.clear();
                    let released = self.dns_tracker.clear();
                    self.release_connected_routes(released)?;
                    self.pending_dns_recv_exit.clear();
                    self.pending_dns_connect_exit.clear();
                    self.pending_udp_connect_exit.clear();
                    self.pending_dns_query.clear();
                    self.pending_inline_dns_transactions.clear();
                    self.pending_socket_exit.clear();
                    self.pending_fd_exit.clear();
                    self.pending_tcp_dns_deny.clear();
                    return Ok(None);
                }
                Err(e) => {
                    return Err(Error::InterceptionError(format!(
                        "waitpid(-1, WNOHANG) failed: {e}"
                    )));
                }
            };

            match status {
                // -- Ptrace events ------------------------------------------------
                // With seccomp-BPF, security-relevant syscalls arrive as
                // PTRACE_EVENT_SECCOMP events. Fork/clone/exec events are
                // also delivered here.
                WaitStatus::PtraceEvent(pid, _sig, event) => {
                    let pid_u32 = pid.as_raw() as u32;
                    debug!(tid = pid_u32, event_id = event, "ptrace event received");
                    if event == libc::PTRACE_EVENT_SECCOMP {
                        // Seccomp stop: a security-relevant syscall.
                        // The process is stopped *before* the syscall
                        // executes — no entry/exit toggle needed.
                        //
                        // The filter routes syscalls it cannot interpret to
                        // TRACE so they produce a stop at all (go-live review
                        // B1); the *decision* is made here, from the kernel's
                        // own record of the syscall entry.
                        //
                        // It deliberately does NOT trust the filter's
                        // SECCOMP_RET_DATA. A tracee may install its own
                        // seccomp filter — `seccomp(2)` is not trapped, and
                        // grith itself sets PR_SET_NO_NEW_PRIVS — and when
                        // two filters return the same action the data of the
                        // most recently installed one is what the tracer
                        // sees. A supervised process could therefore zero
                        // grith's marker and have its foreign-ABI syscall
                        // classified through the x86_64 table.
                        // PTRACE_GET_SYSCALL_INFO comes from the kernel's
                        // syscall-entry bookkeeping instead, so no filter the
                        // tracee installs can influence it.
                        let abi = self.foreign_abi_at_stop(pid, true);
                        if let Some(abi) = abi {
                            let tid = pid_u32;
                            let tgid = Self::resolve_tgid(tid).unwrap_or(tid);
                            self.tid_tgids.insert(tid, tgid);
                            // Registers are well-defined even for compat
                            // tracees; the *number* is foreign. Record it for
                            // forensics only. `None` (tracee killed at the
                            // stop) records -1.
                            let raw_nr = super::arch::read_raw_syscall_nr(pid).unwrap_or(-1);
                            warn!(
                                pid = tgid,
                                tid,
                                abi = ?abi,
                                raw_nr,
                                "foreign-ABI syscall trapped by seccomp fail-closed arch check"
                            );
                            record_event(self, tid, "seccomp-foreign-abi");
                            return Ok(Some(SyscallEvent {
                                pid: tgid,
                                tid,
                                timestamp: Utc::now(),
                                kind: crate::interceptor::SyscallKind::ForeignAbiSyscall {
                                    abi,
                                    raw_nr,
                                },
                                raw_syscall_nr: raw_nr,
                            }));
                        }
                        // The tracee can be killed (sibling exit_group,
                        // SIGKILL) while sitting in this stop, leaving a
                        // queued event with no thread behind it. Skip it;
                        // the exit is reaped by the next waitpid and no
                        // syscall executes.
                        let Some(regs) = super::arch::read_syscall_regs(pid)? else {
                            record_event(self, pid_u32, "seccomp-stop:tracee-gone");
                            continue;
                        };
                        let nr = regs.nr;
                        let sid = super::arch::sys_id(nr);
                        let tid = pid_u32;
                        let tgid = Self::resolve_tgid(tid).unwrap_or(tid);
                        self.tid_tgids.insert(tid, tgid);
                        let fd = regs.args[0] as i32;

                        // Capture clone FD-sharing at the pre-exec seccomp
                        // stop. clone3's flags are supplied through mutable
                        // tracee memory; reading them later at the ptrace
                        // child event is too late to establish provenance.
                        self.pending_clone_fd_table.remove(&tid);
                        if matches!(
                            sid,
                            Some(SysId::Fork) | Some(SysId::Clone) | Some(SysId::Clone3)
                        ) {
                            let snapshot = match sid {
                                Some(SysId::Fork) => Some(super::CloneFdTablePending {
                                    syscall_nr: nr,
                                    flags: 0,
                                }),
                                Some(SysId::Clone) => Some(super::CloneFdTablePending {
                                    syscall_nr: nr,
                                    flags: regs.args[0],
                                }),
                                Some(SysId::Clone3) if regs.args[0] != 0 && regs.args[1] >= 8 => {
                                    self.read_tracee_u64(pid, regs.args[0]).map(|flags| {
                                        super::CloneFdTablePending {
                                            syscall_nr: nr,
                                            flags,
                                        }
                                    })
                                }
                                _ => None,
                            };
                            if let Some(snapshot) = snapshot {
                                self.pending_clone_fd_table.insert(tid, snapshot);
                            } else if self.connected_dns_proxy.is_some()
                                && sid == Some(SysId::Clone3)
                            {
                                warn!(
                                    tgid,
                                    tid,
                                    "denying clone3 because its entry-time flags were unreadable"
                                );
                                self.deny(tid).await?;
                                continue;
                            }
                        }

                        // These operations create a private FD table for one
                        // thread without changing its TGID. Until the tracker
                        // carries per-thread table identities, allowing them
                        // would make later DNS state ambiguous. Fail closed
                        // instead of silently losing inspection coverage.
                        if (sid == Some(SysId::CloseRange) && regs.args[2] & 2 != 0)
                            || (sid == Some(SysId::Unshare)
                                && regs.args[0] & libc::CLONE_FILES as u64 != 0)
                        {
                            warn!(
                                tgid,
                                tid,
                                syscall_nr = nr,
                                "denying FD-table unshare unsupported by DNS tracker"
                            );
                            self.deny(tid).await?;
                            continue;
                        }

                        // Maintain socket descriptor lifecycle at successful
                        // syscall exit. Only lifecycle operations are promoted;
                        // ordinary reads/writes remain outside the trap set.
                        let lifecycle = match sid {
                            // Only promote a close(2) to the two-stop exit dance
                            // when `fd` is a *tracked socket*. The exit handler
                            // (`dns_tracker.close`) is a no-op for any other fd,
                            // so promoting a non-socket close buys nothing and
                            // costs a second ptrace stop. Runtimes with heavy fd
                            // churn (e.g. Bun, which Claude Code runs on) close
                            // thousands of files/pipes; promoting each one was
                            // ~2x the ptrace cost per close and a wedge surface
                            // (the two-stop dance is where threads wedge under
                            // concurrency). An unpromoted close falls through to
                            // `classify_syscall`, which returns `Ok(None)` for
                            // CLOSE (see classify.rs) -> allowed. Behaviourally
                            // equivalent; validated by the fd-lifecycle repro.
                            // A tracked D-Bus channel joins the same gate: its
                            // exit handler is not a no-op (the channel must be
                            // forgotten and stepping demoted), and leaving it
                            // registered would keep the process stepped for an
                            // fd that no longer exists.
                            Some(SysId::Close)
                                if self.dns_tracker.socket_type(tgid, fd).is_some()
                                    || self.dbus_channels.is_tracked(tgid, fd) =>
                            {
                                Some(super::FdLifecyclePending::Close { tgid, fd })
                            }
                            Some(SysId::CloseRange) if regs.args[2] & 4 == 0 => {
                                Some(super::FdLifecyclePending::CloseRange {
                                    tgid,
                                    first: regs.args[0] as u32,
                                    last: regs.args[1] as u32,
                                })
                            }
                            // FOLLOW-UP (deferred by decision, 2026-07-27): dup*
                            // is still promoted unconditionally, unlike close(2)
                            // above. A socket-membership gate would trim the
                            // two-stop dance here too, but the safe gate is more
                            // than close's single check: promote iff the SOURCE
                            // fd is a tracked socket OR (for dup2/dup3) the TARGET
                            // fd (regs.args[1]) is a tracked socket — because dup2/dup3
                            // silently close an already-open target, which the
                            // tracker must observe to untrack it. Must fail toward
                            // promoting when uncertain: a missed promotion leaves
                            // the fd->socket map stale, which is a DNS-inspection
                            // blind spot (not an enforcement bypass — classify.rs
                            // returns Ok(None) for dup, so it is never scored). Low
                            // value (close was the dominant fd-churn win); treat as
                            // security-relevant and validate with the fdchurn repro
                            // + ptrace_* tests before shipping. See memory
                            // fd-lifecycle-promotion-wedge.
                            Some(SysId::Dup) | Some(SysId::Dup2) | Some(SysId::Dup3) => {
                                Some(super::FdLifecyclePending::Dup {
                                    tgid,
                                    source_socket: self.dns_tracker.hold_socket_identity(tgid, fd),
                                    source_fd: fd,
                                })
                            }
                            Some(SysId::Fcntl)
                                if matches!(
                                    regs.args[1] as i32,
                                    libc::F_DUPFD | libc::F_DUPFD_CLOEXEC
                                ) =>
                            {
                                Some(super::FdLifecyclePending::Dup {
                                    tgid,
                                    source_socket: self.dns_tracker.hold_socket_identity(tgid, fd),
                                    source_fd: fd,
                                })
                            }
                            _ => None,
                        };
                        if let Some(pending) = lifecycle {
                            self.pending_fd_exit.insert(tid, pending);
                            record_event(self, tid, "fd-lifecycle-promote");
                            self.resume_to_next_syscall(pid, None)?;
                            continue;
                        }

                        // A proxy-routed socket has exactly one inspection
                        // owner. Only sendto with a register-level null peer
                        // (including libc send()) is safe to resume. Message
                        // headers live in mutable tracee memory, so sendmsg and
                        // sendmmsg fail closed even when msg_name currently
                        // appears null.
                        if self.dns_tracker.is_connected_proxy(tgid, fd)
                            && matches!(
                                sid,
                                Some(SysId::Sendto) | Some(SysId::Sendmsg) | Some(SysId::Sendmmsg)
                            )
                        {
                            if Self::proxy_send_uses_supported_connected_form(nr, &regs) {
                                record_event(self, tid, "dns-proxy-send");
                                self.resume_continue(pid, None)?;
                                continue;
                            }
                            self.pending_dns_query.insert(
                                tid,
                                crate::interceptor::DnsQueryInspection {
                                    queries: Vec::new(),
                                    parse_error: Some(
                                        "dns-proxy-unsupported-send-form-denied".into(),
                                    ),
                                },
                            );
                            record_event(self, tid, "dns-proxy-send-deny");
                            return Ok(Some(SyscallEvent {
                                pid: tgid,
                                tid,
                                timestamp: Utc::now(),
                                kind: crate::interceptor::SyscallKind::NetSendTo {
                                    address: String::new(),
                                    port: 53,
                                },
                                raw_syscall_nr: nr,
                            }));
                        }

                        // ---- In-line DNS owner (direct resolver path) ----
                        // A receive on a tracked DNS socket: promote this ONE
                        // syscall to PTRACE_SYSCALL so we catch its EXIT and read
                        // the kernel-filled response for exact IP→domain. CONT is
                        // restored at the exit stop. Read-only — never denies.
                        // Safe against the clone-child wedge: this is an existing
                        // tid mid-recvfrom, not a freshly-cloned child racing its
                        // seccomp registration.
                        if self.dns_cache.is_some()
                            && self.dns_observe_responses
                            && matches!(
                                sid,
                                Some(SysId::Recvfrom)
                                    | Some(SysId::Recvmsg)
                                    | Some(SysId::Recvmmsg)
                            )
                            && self.dns_tracker.is_dns(tgid, fd)
                            && !self.dns_tracker.is_connected_proxy(tgid, fd)
                        {
                            let Some(socket_id) = self.dns_tracker.hold_socket(tgid, fd) else {
                                warn!(
                                    tgid,
                                    tid,
                                    fd,
                                    "DNS receive raced a socket peer mutation; skipping attribution"
                                );
                                self.resume_continue(pid, None)?;
                                continue;
                            };
                            let kind = match sid {
                                Some(SysId::Recvfrom) => super::DnsRecvKind::From {
                                    buf_ptr: regs.args[1],
                                    buf_len: (regs.args[2] as usize).min(MAX_DNS_MSG),
                                },
                                Some(SysId::Recvmsg) => super::DnsRecvKind::Msg {
                                    msghdr_ptr: regs.args[1],
                                },
                                Some(SysId::Recvmmsg) => super::DnsRecvKind::Mmsg {
                                    msgvec_ptr: regs.args[1],
                                    vlen: (regs.args[2] as usize).min(MAX_DNS_BATCH),
                                },
                                _ => unreachable!(),
                            };
                            self.pending_dns_recv_exit.insert(
                                tid,
                                super::DnsRecvPending {
                                    tgid,
                                    fd,
                                    socket_id,
                                    kind,
                                },
                            );
                            record_event(self, tid, "dns-recv-promote");
                            self.resume_to_next_syscall(pid, None)?;
                            continue;
                        }
                        // socket(): learn the type (stream/datagram) of every
                        // AF_INET/AF_INET6 socket by promoting to catch the
                        // returned fd at exit. The type is unreliable at
                        // connect-entry via /proc/net (a fresh socket isn't in
                        // the tables yet), so we record it from the socket() type
                        // arg. Used for TCP-DNS detection at a :53 connect AND to
                        // distinguish TCP vs UDP connects so UDP egress can be
                        // deferred to the send.
                        if sid == Some(SysId::Socket)
                            && matches!(regs.args[0] as i32, libc::AF_INET | libc::AF_INET6)
                        {
                            let socket_type = match (regs.args[1] as i32) & 0xFF {
                                libc::SOCK_STREAM => super::dns_socket_tracker::SocketType::Stream,
                                libc::SOCK_DGRAM => super::dns_socket_tracker::SocketType::Datagram,
                                _ => super::dns_socket_tracker::SocketType::Other,
                            };
                            self.pending_socket_exit
                                .insert(tid, super::SocketPending { tgid, socket_type });
                            record_event(self, tid, "inet-socket-promote");
                            self.resume_to_next_syscall(pid, None)?;
                            continue;
                        }
                        // A send on a D-Bus channel is inspected per message.
                        // These syscalls ARE in the seccomp trap set, so this
                        // arm catches the client libraries that use sendmsg
                        // (GDBus, sd-bus, libdbus when passing fds); the
                        // write/writev shapes are caught by the stepped path.
                        if self.dbus_channels.is_tracked(tgid, fd)
                            && matches!(
                                sid,
                                Some(SysId::Sendto) | Some(SysId::Sendmsg) | Some(SysId::Sendmmsg)
                            )
                        {
                            if let Some(event) =
                                self.inspect_dbus_write(pid, tgid, tid, fd, nr, &regs)
                            {
                                record_event(self, tid, "dbus-send");
                                return Ok(Some(event));
                            }
                            record_event(self, tid, "dbus-send-allowed");
                            self.resume_tracee(pid, None)?;
                            continue;
                        }

                        // Discover DNS from either a prior connect or the
                        // syscall's explicit destination, then strictly inspect
                        // every message in the send before allowing it.
                        if self.dns_cache.is_some()
                            && matches!(
                                sid,
                                Some(SysId::Sendto) | Some(SysId::Sendmsg) | Some(SysId::Sendmmsg)
                            )
                        {
                            if let Some(inspection) =
                                self.inspect_dns_send(pid, tgid, fd, nr, &regs)
                            {
                                self.pending_dns_query.insert(tid, inspection);
                                record_event(self, tid, "seccomp");
                                return Ok(Some(SyscallEvent {
                                    pid: tgid,
                                    tid,
                                    timestamp: Utc::now(),
                                    kind: crate::interceptor::SyscallKind::NetSendTo {
                                        address: String::new(),
                                        port: 53,
                                    },
                                    raw_syscall_nr: nr,
                                }));
                            }
                        }
                        // Non-DNS connected-UDP send: egress is judged HERE (the
                        // send carries data), not at the connect. Surface the dest
                        // recorded at connect AS a NetConnect so it flows through
                        // the normal egress path (reverse-map + score + audit +
                        // allow/deny of this send). A connected UDP socket that
                        // never sends (getaddrinfo's source-selection probe) is
                        // thus never scored. The session allowlist / reputation
                        // cache the decision so repeated sends don't re-prompt.
                        if matches!(
                            sid,
                            Some(SysId::Sendto) | Some(SysId::Sendmsg) | Some(SysId::Sendmmsg)
                        ) {
                            if let Some(peer) = self.dns_tracker.connected_destination(tgid, fd) {
                                if self.dns_tracker.socket_type(tgid, fd)
                                    == Some(super::dns_socket_tracker::SocketType::Datagram)
                                {
                                    // The explicit destination WINS over the
                                    // connected peer: Linux delivers a
                                    // connected UDP send to the address the
                                    // send names, so scoring the recorded peer
                                    // would name the wrong host and let the
                                    // real egress through (go-live review
                                    // round 2). sendto: dest_addr in a4 /
                                    // addrlen in a5. sendmsg/sendmmsg: msg_name
                                    // in the (first) msghdr at a1.
                                    let explicit = match sid {
                                        Some(SysId::Sendto) if regs.args[4] != 0 => self
                                            .read_sockaddr(
                                                pid,
                                                regs.args[4],
                                                regs.args[5] as usize,
                                                None,
                                            )?
                                            .filter(|(a, _, _)| !a.is_empty())
                                            .map(|(a, p, _)| (a, p)),
                                        Some(SysId::Sendmsg) | Some(SysId::Sendmmsg) => {
                                            self.read_msghdr_destination(pid, regs.args[1])?
                                        }
                                        _ => None,
                                    };
                                    let (address, port) = explicit
                                        .unwrap_or_else(|| (peer.ip().to_string(), peer.port()));

                                    record_event(self, tid, "seccomp");
                                    // Register the pending decision so an allow
                                    // ends stepping for a send-only socket
                                    // (which never issues write/writev),
                                    // otherwise the process stays two-stopped
                                    // for the socket's whole lifetime.
                                    if let Some(state) = self.stepping.get_mut(&tgid) {
                                        if state.fds.contains(&fd) {
                                            state.awaiting.insert(tid, fd);
                                        }
                                    }
                                    return Ok(Some(SyscallEvent {
                                        pid: tgid,
                                        tid,
                                        timestamp: Utc::now(),
                                        kind: crate::interceptor::SyscallKind::NetConnect {
                                            address,
                                            port,
                                            protocol: crate::interceptor::NetProtocol::Udp,
                                        },
                                        raw_syscall_nr: nr,
                                    }));
                                }
                            }
                        }

                        // Track datagram connect state only after the kernel
                        // reports success. Connected DNS routes additionally
                        // substitute the peer for one syscall and register the
                        // resulting local tuple before the caller resumes.
                        if sid == Some(SysId::Connect)
                            && self.dns_tracker.socket_type(tgid, fd)
                                == Some(super::dns_socket_tracker::SocketType::Datagram)
                        {
                            let family = self.sockaddr_family(pid, regs.args[1]);
                            if family == Some(libc::AF_UNSPEC) {
                                let Some(socket_id) = self.dns_tracker.pin_socket(tgid, fd) else {
                                    self.deny(tid).await?;
                                    continue;
                                };
                                self.pending_udp_connect_exit.insert(
                                    tid,
                                    super::UdpConnectPending {
                                        socket_id,
                                        destination: None,
                                        fd,
                                    },
                                );
                                record_event(self, tid, "udp-disconnect-promote");
                                self.resume_to_next_syscall(pid, None)?;
                                continue;
                            }

                            if let (Some(control), Some(original_resolver)) = (
                                self.connected_dns_proxy.clone(),
                                self.read_socket_addr(pid, regs.args[1], regs.args[2] as usize),
                            ) {
                                if original_resolver.port() == 53 {
                                    match super::dns_redirect::shares_supervisor_netns(tid) {
                                        Ok(true) => {}
                                        Ok(false) => {
                                            warn!(
                                                tgid,
                                                tid,
                                                "denying connected DNS across network namespaces"
                                            );
                                            self.deny(tid).await?;
                                            continue;
                                        }
                                        Err(error) => {
                                            warn!(
                                                tgid,
                                                tid,
                                                error = %error,
                                                "network namespace check failed; denying connected DNS"
                                            );
                                            self.deny(tid).await?;
                                            continue;
                                        }
                                    }

                                    let Some(socket_id) = self.dns_tracker.pin_socket(tgid, fd)
                                    else {
                                        self.deny(tid).await?;
                                        continue;
                                    };
                                    let provenance =
                                        crate::connected_dns_proxy::DnsRouteProvenance {
                                            tgid,
                                            creator_tid: tid,
                                            socket_id: socket_id.0,
                                        };
                                    let route = match control
                                        .create_route(original_resolver, provenance)
                                    {
                                        Ok(route) => route,
                                        Err(error) => {
                                            self.dns_tracker.unpin_socket(socket_id);
                                            warn!(
                                                tgid,
                                                tid,
                                                error = %error,
                                                "connected DNS route creation failed; denying connect"
                                            );
                                            self.deny(tid).await?;
                                            continue;
                                        }
                                    };
                                    let sockaddr =
                                        match super::dns_redirect::replace_connect_sockaddr(
                                            pid,
                                            regs.args[1],
                                            regs.args[2] as u32,
                                            route.endpoint,
                                        ) {
                                            Ok(sockaddr) => sockaddr,
                                            Err(error) => {
                                                let _ = control.release_route(route.route_id);
                                                self.dns_tracker.unpin_socket(socket_id);
                                                return Err(self
                                                    .terminate_after_dns_redirect_failure(
                                                        tgid,
                                                        &format!(
                                                            "connected DNS sockaddr rewrite failed: {error}"
                                                        ),
                                                    ));
                                            }
                                        };
                                    self.pending_dns_connect_exit.insert(
                                        tid,
                                        super::DnsConnectPending {
                                            tgid,
                                            fd,
                                            socket_id,
                                            original_resolver,
                                            route,
                                            sockaddr,
                                        },
                                    );
                                    record_event(self, tid, "dns-connect-promote");
                                    self.resume_to_next_syscall(pid, None)?;
                                    continue;
                                } else if self.dns_tracker.is_connected_proxy(tgid, fd) {
                                    warn!(
                                        tgid,
                                        tid,
                                        %original_resolver,
                                        "denying non-DNS reconnect of a proxy-owned UDP socket"
                                    );
                                    self.deny(tid).await?;
                                    continue;
                                }
                            }
                        }

                        if sid == Some(SysId::Connect)
                            && self.connected_dns_proxy.is_some()
                            && matches!(
                                self.dns_tracker.socket_type(tgid, fd),
                                None | Some(super::dns_socket_tracker::SocketType::Other)
                            )
                            && self
                                .read_socket_addr(pid, regs.args[1], regs.args[2] as usize)
                                .is_some_and(|destination| destination.port() == 53)
                        {
                            warn!(
                                tgid,
                                tid,
                                fd,
                                "denying UDP/53-capable connect on an untracked socket while connected DNS proxy is required"
                            );
                            self.deny(tid).await?;
                            continue;
                        }

                        match self.classify_syscall(pid, &regs) {
                            Ok(Some(kind)) => {
                                let tgid = Self::resolve_tgid(tid).unwrap_or(tid);

                                // Connect handling:
                                // - `:53` (DNS on): route to the in-line DNS path
                                //   (stream → TCP-DNS deny flag; datagram → tracked
                                //   DNS socket). Returned as an event + allowed.
                                // - any other UDP connect: defer egress to the
                                //   send. Record the dest and allow the connect
                                //   WITHOUT scoring — a UDP connect sends no data,
                                //   so scoring it (as today) false-positives on
                                //   getaddrinfo's source-selection probe.
                                // - TCP / other: fall through, scored at connect.
                                if let crate::interceptor::SyscallKind::NetConnect {
                                    address,
                                    port,
                                    protocol,
                                } = &kind
                                {
                                    let fd = regs.args[0] as i32;

                                    // A connect to a D-Bus endpoint arms
                                    // message inspection instead of being the
                                    // decision itself. The connect still flows
                                    // through the proxy below — it is scored
                                    // as the local IPC it is — but the event
                                    // handler will not escalate it, because
                                    // the authority it might carry is now
                                    // judged per method call.
                                    //
                                    // Registered at the entry stop rather than
                                    // on a promoted exit: a failed connect
                                    // leaves a channel on an fd that cannot be
                                    // written to, which costs nothing and
                                    // escalates if it somehow is, whereas a
                                    // second ptrace stop per bus connect is
                                    // the wedge-sensitive dance we keep rare.
                                    if self.dbus_inspection
                                        && *protocol == crate::interceptor::NetProtocol::Unix
                                        && crate::dbus::is_dbus_socket(address)
                                    {
                                        self.dbus_channels.register(tgid, fd, address.clone());
                                        self.promote_dbus_stepping(tgid, fd, address);
                                    }

                                    let mut known_type = self.dns_tracker.socket_type(tgid, fd);
                                    if known_type.is_none()
                                        && matches!(
                                            protocol,
                                            crate::interceptor::NetProtocol::Tcp
                                                | crate::interceptor::NetProtocol::Udp
                                        )
                                    {
                                        let socket_type =
                                            if *protocol == crate::interceptor::NetProtocol::Udp {
                                                super::dns_socket_tracker::SocketType::Datagram
                                            } else {
                                                super::dns_socket_tracker::SocketType::Stream
                                            };
                                        self.dns_tracker.observe_socket(tgid, fd, socket_type);
                                        known_type = Some(socket_type);
                                    }
                                    let is_udp = known_type
                                        == Some(super::dns_socket_tracker::SocketType::Datagram);
                                    if *port == 53 && self.dns_cache.is_some() {
                                        // TCP-DNS deny only on a CONFIRMED stream
                                        // socket — never deny a UDP DNS socket.
                                        if self.block_tcp_dns
                                            && known_type
                                                == Some(
                                                    super::dns_socket_tracker::SocketType::Stream,
                                                )
                                        {
                                            self.pending_tcp_dns_deny.insert(tid);
                                        }
                                    }
                                    if is_udp {
                                        let Some(destination) = address
                                            .parse::<IpAddr>()
                                            .ok()
                                            .map(|ip| SocketAddr::new(ip, *port))
                                        else {
                                            self.deny(tid).await?;
                                            continue;
                                        };
                                        let Some(socket_id) = self.dns_tracker.pin_socket(tgid, fd)
                                        else {
                                            self.deny(tid).await?;
                                            continue;
                                        };
                                        self.pending_udp_connect_exit.insert(
                                            tid,
                                            super::UdpConnectPending {
                                                socket_id,
                                                destination: Some(destination),
                                                fd,
                                            },
                                        );
                                        // Defer UDP egress to the send, but
                                        // catch connect exit before committing
                                        // shared peer state.
                                        record_event(self, tid, "udp-connect-promote");
                                        self.resume_to_next_syscall(pid, None)?;
                                        continue;
                                    }
                                }

                                trace!(
                                    pid = tgid,
                                    tid = tid,
                                    syscall_nr = nr,
                                    "intercepted security-relevant syscall (seccomp)"
                                );
                                record_event(self, tid, "seccomp");
                                return Ok(Some(SyscallEvent {
                                    pid: tgid,
                                    tid,
                                    timestamp: Utc::now(),
                                    kind,
                                    raw_syscall_nr: nr,
                                }));
                            }
                            Ok(None) => {
                                record_event(self, pid_u32, "seccomp-noop");
                                self.resume_continue(pid, None)?;
                                continue;
                            }
                            Err(e) => {
                                // Fail-closed: we cannot determine what this
                                // syscall is, so we must deny it rather than
                                // allow it through.  A classify error is most
                                // commonly a failed PTRACE_PEEKDATA (invalid or
                                // unmapped pointer in the tracee register), not
                                // a catastrophic supervisor failure.  The
                                // tracee sees EPERM, which is intentional.
                                warn!(
                                    pid = pid.as_raw(),
                                    syscall_nr = nr,
                                    error = %e,
                                    "classify_syscall failed; denying syscall (fail-closed)"
                                );
                                if let Err(deny_err) = self.deny(pid_u32).await {
                                    warn!(
                                        pid = pid.as_raw(),
                                        syscall_nr = nr,
                                        error = %deny_err,
                                        "deny after classify failure also failed; tracee may have exited"
                                    );
                                }
                                continue;
                            }
                        }
                    }

                    // Exec event — generate a ProcessExec event from
                    // /proc since execve is handled by PTRACE_O_TRACEEXEC
                    // (not seccomp) and the original args are gone.
                    if event == libc::PTRACE_EVENT_EXEC {
                        let tgid = Self::resolve_tgid(pid_u32).unwrap_or(pid_u32);
                        if let Ok(entries) = std::fs::read_dir(format!("/proc/{pid_u32}/fd")) {
                            let live_fds = entries
                                .filter_map(|entry| {
                                    entry
                                        .ok()?
                                        .file_name()
                                        .to_string_lossy()
                                        .parse::<i32>()
                                        .ok()
                                })
                                .collect();
                            let released = self.dns_tracker.retain_fds(tgid, &live_fds);
                            self.release_connected_routes(released)?;
                            // B13 (exec-survival residual): a connected non-loopback
                            // datagram socket the OLD image opened survives execve
                            // unless it was FD_CLOEXEC — the tracker was just pruned
                            // to the live fds above, so a survivor keeps its
                            // Datagram type + connected destination. A blanket
                            // demote here would stop stepping the survivor, so a
                            // `write(fd, secret)` in the NEW image would egress
                            // untrapped and unaudited. Re-evaluate per fd instead:
                            // keep stepping every fd that is still a connected
                            // off-host datagram socket (mirror of the fork-child
                            // re-arm), demote the rest. There is no "next connect"
                            // for an already-connected socket, so this is the only
                            // place stepping can be re-armed across exec.
                            self.resync_stepping_after_exec(tgid);
                            // Same survival question for D-Bus channels, with a
                            // different answer: a surviving bus fd is kept and
                            // poisoned (the new image inherits a socket
                            // mid-stream that cannot be framed), and stepping
                            // is re-armed for it so its writes are still seen
                            // and escalate. `resync_stepping_after_exec` just
                            // cleared the whole stepping entry, so this must
                            // run after it.
                            for fd in self.dbus_channels.retain_and_poison(tgid, &live_fds) {
                                self.promote_dbus_stepping(tgid, fd, "survived exec");
                            }
                        }
                        let (path, args) = Self::read_exec_info(pid_u32);
                        let kind = crate::interceptor::SyscallKind::ProcessExec { path, args };
                        trace!(
                            pid = tgid,
                            tid = pid_u32,
                            "intercepted exec via PTRACE_EVENT_EXEC"
                        );
                        record_event(self, pid_u32, "ptrace-event:exec");
                        return Ok(Some(SyscallEvent {
                            pid: tgid,
                            tid: pid_u32,
                            timestamp: Utc::now(),
                            kind,
                            raw_syscall_nr: super::arch::nr_of(SysId::Execve).unwrap_or(-1),
                        }));
                    }

                    // Fork/vfork/clone event — track the new child. Errors are
                    // session-fatal: resuming after an ambiguous FD-table
                    // inheritance would make connected-DNS ownership unsafe.
                    if matches!(
                        event,
                        libc::PTRACE_EVENT_FORK
                            | libc::PTRACE_EVENT_VFORK
                            | libc::PTRACE_EVENT_CLONE
                    ) {
                        if let Some(child_pid) = self.handle_ptrace_event(pid, event)? {
                            debug!(
                                parent = pid.as_raw(),
                                child = child_pid,
                                "auto-tracing new child"
                            );
                            // Emit a ProcessFork event with the actual child PID.
                            let tgid = Self::resolve_tgid(pid_u32).unwrap_or(pid_u32);
                            let kind = crate::interceptor::SyscallKind::ProcessFork { child_pid };
                            record_event(self, pid_u32, "ptrace-event:fork-or-clone");
                            // Initialise the new child's tracking so the watchdog
                            // doesn't false-positive it as "never seen any event"
                            // before its own first stop arrives.
                            record_event(self, child_pid, "ptrace-event:child-of");
                            return Ok(Some(SyscallEvent {
                                pid: tgid,
                                tid: pid_u32,
                                timestamp: Utc::now(),
                                kind,
                                raw_syscall_nr: super::arch::nr_of(SysId::Clone).unwrap_or(-1),
                            }));
                        }
                    }
                    // Unhandled PTRACE_EVENT_* — release the tracee but
                    // surface a warn so the next investigation has the event
                    // ID. Previously this branch was silent, which made any
                    // unhandled event type invisible as a wedge cause.
                    warn!(
                        tid = pid_u32,
                        event_id = event,
                        "unhandled ptrace event — releasing tracee; report to grith maintainers"
                    );
                    record_event(self, pid_u32, "ptrace-event:unhandled");
                    self.resume_tracee(pid, None)?;
                    continue;
                }

                // -- Syscall stop (SIGTRAP | 0x80) --------------------------------
                // With seccomp active, this should not fire for normal
                // syscalls. Kept as a fallback for attached processes
                // (without seccomp) and edge cases.
                WaitStatus::PtraceSyscall(pid) => {
                    let pid_u32 = pid.as_raw() as u32;

                    if let Some(pending) = self.pending_dns_connect_exit.remove(&pid_u32) {
                        self.in_syscall_entry.remove(&pid_u32);
                        record_event(self, pid_u32, "dns-connect-exit");
                        let result = super::arch::read_return_value(pid)
                            .ok()
                            .flatten()
                            .unwrap_or(-(libc::EIO as i64));

                        if let Err(error) = pending.sockaddr.restore(pid) {
                            if let Some(control) = &self.connected_dns_proxy {
                                let _ = control.release_route(pending.route.route_id);
                            }
                            self.dns_tracker.unpin_socket(pending.socket_id);
                            return Err(self.terminate_after_dns_redirect_failure(
                                pending.tgid,
                                &format!("sockaddr restoration failed: {error}"),
                            ));
                        }

                        if result < 0 {
                            if let Some(control) = &self.connected_dns_proxy {
                                control
                                    .release_route(pending.route.route_id)
                                    .map_err(|error| {
                                        Error::InterceptionError(format!(
                                            "failed to release route after DNS connect error: {error}"
                                        ))
                                    })?;
                            }
                            if let Some(route_id) = self.dns_tracker.unpin_socket(pending.socket_id)
                            {
                                self.release_connected_route(route_id)?;
                            }
                            self.resume_tracee(pid, None)?;
                            continue;
                        }

                        if !self.dns_tracker.socket_matches(
                            pending.tgid,
                            pending.fd,
                            pending.socket_id,
                        ) {
                            if let Some(control) = &self.connected_dns_proxy {
                                let _ = control.release_route(pending.route.route_id);
                            }
                            self.dns_tracker.unpin_socket(pending.socket_id);
                            return Err(self.terminate_after_dns_redirect_failure(
                                pending.tgid,
                                "socket descriptor was closed or reused before route registration",
                            ));
                        }

                        let family = if pending.original_resolver.is_ipv4() {
                            libc::AF_INET
                        } else {
                            libc::AF_INET6
                        };
                        let client = match super::dns_redirect::socket_local_addr(
                            pending.tgid,
                            pending.fd,
                            family,
                        ) {
                            Ok(client) => client,
                            Err(error) => {
                                if let Some(control) = &self.connected_dns_proxy {
                                    let _ = control.release_route(pending.route.route_id);
                                }
                                self.dns_tracker.unpin_socket(pending.socket_id);
                                return Err(self.terminate_after_dns_redirect_failure(
                                    pending.tgid,
                                    &format!("client tuple registration lookup failed: {error}"),
                                ));
                            }
                        };
                        let Some(control) = self.connected_dns_proxy.clone() else {
                            self.dns_tracker.unpin_socket(pending.socket_id);
                            return Err(self.terminate_after_dns_redirect_failure(
                                pending.tgid,
                                "proxy control plane disappeared after connect",
                            ));
                        };
                        if let Err(error) = control.register_client(pending.route.route_id, client)
                        {
                            let _ = control.release_route(pending.route.route_id);
                            self.dns_tracker.unpin_socket(pending.socket_id);
                            return Err(self.terminate_after_dns_redirect_failure(
                                pending.tgid,
                                &format!("client tuple registration failed: {error}"),
                            ));
                        }

                        let transition = match self.dns_tracker.set_connected_proxy_for_socket(
                            pending.socket_id,
                            super::dns_socket_tracker::DnsRouteId(pending.route.route_id.get()),
                            pending.original_resolver,
                            pending.route.endpoint,
                        ) {
                            Some(transition) => transition,
                            None => {
                                let _ = control.release_route(pending.route.route_id);
                                self.dns_tracker.unpin_socket(pending.socket_id);
                                return Err(self.terminate_after_dns_redirect_failure(
                                    pending.tgid,
                                    "shared socket state disappeared before route commit",
                                ));
                            }
                        };
                        if let Err(error) = control.activate_route(pending.route.route_id) {
                            let _ = control.release_route(pending.route.route_id);
                            self.dns_tracker.unpin_socket(pending.socket_id);
                            return Err(self.terminate_after_dns_redirect_failure(
                                pending.tgid,
                                &format!("client route activation failed: {error}"),
                            ));
                        }
                        if let Some(route_id) = transition.released_route {
                            self.release_connected_route(route_id)?;
                        }
                        if let Some(route_id) = self.dns_tracker.unpin_socket(pending.socket_id) {
                            self.release_connected_route(route_id)?;
                        }
                        trace!(
                            tgid = pending.tgid,
                            tid = pid_u32,
                            fd = pending.fd,
                            route_id = pending.route.route_id.get(),
                            %client,
                            resolver = %pending.original_resolver,
                            endpoint = %pending.route.endpoint,
                            "connected DNS proxy route committed"
                        );
                        self.resume_tracee(pid, None)?;
                        continue;
                    }

                    if let Some(pending) = self.pending_udp_connect_exit.remove(&pid_u32) {
                        self.in_syscall_entry.remove(&pid_u32);
                        record_event(self, pid_u32, "udp-connect-exit");
                        let succeeded = super::arch::read_return_value(pid)
                            .ok()
                            .flatten()
                            .is_some_and(|result| result >= 0);
                        if succeeded {
                            let released = match pending.destination {
                                Some(destination) => self
                                    .dns_tracker
                                    .connect_socket(pending.socket_id, destination),
                                None => self.dns_tracker.disconnect_socket(pending.socket_id),
                            };
                            if let Some(route_id) = released {
                                self.release_connected_route(route_id)?;
                            }
                            // B13: once this socket is pointed at a
                            // non-loopback peer, a plain write(2) on it is an
                            // egress the proxy never sees. Step this thread
                            // until that write is judged. A disconnect or a
                            // loopback re-connect ends the need.
                            let tgid = Self::resolve_tgid(pid_u32).unwrap_or(pid_u32);
                            match pending.destination {
                                Some(destination)
                                    if !Self::is_loopback_destination(&destination) =>
                                {
                                    self.promote_stepping(tgid, pending.fd, destination);
                                }
                                _ => self.demote_stepping_fd(
                                    tgid,
                                    pending.fd,
                                    "datagram socket disconnected or aimed at loopback",
                                ),
                            }
                        }
                        if let Some(route_id) = self.dns_tracker.unpin_socket(pending.socket_id) {
                            self.release_connected_route(route_id)?;
                        }
                        self.resume_tracee(pid, None)?;
                        continue;
                    }

                    // In-line DNS: the EXIT stop of a receive we promoted at its
                    // seccomp entry. Read the kernel-filled response, record exact
                    // IP→domain, restore CONT. MUST run before the fallback
                    // in_syscall_entry toggle so it doesn't corrupt that
                    // bookkeeping. Read-only — any failure just skips the cache
                    // and still restores the tracee.
                    if let Some(pending) = self.pending_dns_recv_exit.remove(&pid_u32) {
                        self.in_syscall_entry.remove(&pid_u32);
                        record_event(self, pid_u32, "dns-recv-exit");
                        if let Ok(Some(n)) = super::arch::read_return_value(pid) {
                            if n > 0 {
                                match pending.kind {
                                    super::DnsRecvKind::From { buf_ptr, buf_len } => {
                                        if n as usize <= MAX_DNS_MSG {
                                            let len = (n as usize).min(buf_len);
                                            if let Ok(response) =
                                                self.read_tracee_bytes(pid, buf_ptr, len)
                                            {
                                                self.record_dns_response(pending, &response);
                                            }
                                        }
                                    }
                                    super::DnsRecvKind::Msg { msghdr_ptr } => {
                                        if n as usize <= MAX_DNS_MSG {
                                            if let Some(response) =
                                                self.read_recv_msghdr(pid, msghdr_ptr, n as usize)
                                            {
                                                self.record_dns_response(pending, &response);
                                            }
                                        }
                                    }
                                    super::DnsRecvKind::Mmsg { msgvec_ptr, vlen } => {
                                        let count = (n as usize).min(vlen);
                                        for index in 0..count {
                                            let header = msgvec_ptr + (index as u64) * MMSGHDR_SIZE;
                                            let Some(len) =
                                                self.read_tracee_u32(pid, header + MSGHDR_SIZE)
                                            else {
                                                break;
                                            };
                                            if len as usize <= MAX_DNS_MSG {
                                                if let Some(response) =
                                                    self.read_recv_msghdr(pid, header, len as usize)
                                                {
                                                    self.record_dns_response(pending, &response);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(route_id) =
                            self.dns_tracker.release_socket_hold(pending.socket_id)
                        {
                            self.release_connected_route(route_id)?;
                        }
                        self.resume_tracee(pid, None)?;
                        continue;
                    }

                    // socket() exit we promoted at its seccomp entry: learn the
                    // returned fd and record whether it's a stream (TCP) socket,
                    // so a later connect to :53 on it can be blocked as TCP-DNS.
                    // Kept accurate across fd reuse (stream → insert, dgram →
                    // remove). Runs before the fallback in_syscall_entry toggle.
                    if let Some(pending) = self.pending_socket_exit.remove(&pid_u32) {
                        self.in_syscall_entry.remove(&pid_u32);
                        record_event(self, pid_u32, "inet-socket-exit");
                        if let Ok(Some(fd)) = super::arch::read_return_value(pid) {
                            if fd >= 0 {
                                let released = self.dns_tracker.observe_socket(
                                    pending.tgid,
                                    fd as i32,
                                    pending.socket_type,
                                );
                                if let Some(route_id) = released {
                                    self.release_connected_route(route_id)?;
                                }
                            }
                        }
                        self.resume_tracee(pid, None)?;
                        continue;
                    }

                    if let Some(pending) = self.pending_fd_exit.remove(&pid_u32) {
                        self.in_syscall_entry.remove(&pid_u32);
                        record_event(self, pid_u32, "fd-lifecycle-exit");
                        let held_source = match pending {
                            super::FdLifecyclePending::Dup { source_socket, .. } => source_socket,
                            super::FdLifecyclePending::Close { .. }
                            | super::FdLifecyclePending::CloseRange { .. } => None,
                        };
                        // Tracee died in this exit stop. Mirror the Exited-arm
                        // cleanup for a pending fd event: release any held
                        // source socket so route holds stay balanced; the reap
                        // of this tid handles the rest.
                        let Some(result) = super::arch::read_return_value(pid)? else {
                            if let Some(socket_id) = held_source {
                                if let Some(route_id) =
                                    self.dns_tracker.release_socket_hold(socket_id)
                                {
                                    self.release_connected_route(route_id)?;
                                }
                            }
                            record_event(self, pid_u32, "fd-lifecycle-exit:tracee-gone");
                            continue;
                        };
                        let released = match pending {
                            // Linux releases an FD early in close(2), even
                            // when later flush/writeback reports EINTR or
                            // I/O failure. EBADF also proves any tracked
                            // mapping was stale, so reconcile every close
                            // result.
                            super::FdLifecyclePending::Close { tgid, fd } => {
                                self.dns_tracker.close(tgid, fd).into_iter().collect()
                            }
                            super::FdLifecyclePending::CloseRange { tgid, first, last }
                                if result >= 0 =>
                            {
                                self.dns_tracker.close_range(tgid, first, last)
                            }
                            super::FdLifecyclePending::Dup {
                                tgid,
                                source_socket,
                                ..
                            } if result >= 0 => match source_socket {
                                Some(socket_id) => self.dns_tracker.duplicate_socket(
                                    tgid,
                                    socket_id,
                                    result as i32,
                                ),
                                None => self.dns_tracker.close(tgid, result as i32),
                            }
                            .into_iter()
                            .collect(),
                            super::FdLifecyclePending::CloseRange { .. }
                            | super::FdLifecyclePending::Dup { .. } => Vec::new(),
                        };
                        if !released.is_empty() {
                            self.release_connected_routes(released)?;
                        }
                        if let Some(socket_id) = held_source {
                            if let Some(route_id) = self.dns_tracker.release_socket_hold(socket_id)
                            {
                                self.release_connected_route(route_id)?;
                            }
                        }
                        // B13: a closed fd cannot be written to, so nothing
                        // needs stepping for it any more. Closing the window
                        // promptly is what keeps the wedge-sensitive two-stop
                        // dance rare.
                        match pending {
                            super::FdLifecyclePending::Close { tgid, fd } => {
                                let was_stepping = self.stepping.contains_key(&tgid);
                                self.demote_stepping_fd(tgid, fd, "tracked fd closed");
                                // B13 (no-exec dup variant): a dup'd non-CLOEXEC
                                // alias can outlive the fd the connect happened
                                // on. The tracker already dropped the closed fd
                                // (above); if the socket survives on another live
                                // fd, keep stepping it — demote_stepping_fd only
                                // removed the closed fd number, not the alias.
                                if was_stepping {
                                    self.rearm_surviving_connected_dgram_fds(tgid);
                                }
                            }
                            super::FdLifecyclePending::CloseRange { tgid, first, last } => {
                                let closed: Vec<i32> = self
                                    .stepping
                                    .get(&tgid)
                                    .map(|state| {
                                        state
                                            .fds
                                            .iter()
                                            .copied()
                                            .filter(|fd| *fd >= first as i32 && *fd <= last as i32)
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                for fd in closed {
                                    self.demote_stepping_fd(
                                        tgid,
                                        fd,
                                        "tracked fd closed by close_range",
                                    );
                                }
                            }
                            // A dup ADDS an alias for the same socket; the
                            // write check resolves any alias through the
                            // tracker, so nothing to add or remove here.
                            super::FdLifecyclePending::Dup { .. } => {}
                        }
                        // D-Bus channels track by descriptor, so each of these
                        // needs its own reconciliation. A dup'd bus fd is
                        // tracked-but-poisoned rather than ignored: writes
                        // through the alias stay visible and escalate.
                        match pending {
                            super::FdLifecyclePending::Close { tgid, fd } => {
                                self.dbus_channels.close(tgid, fd);
                                self.demote_dbus_stepping(tgid, fd, "bus fd closed");
                            }
                            super::FdLifecyclePending::CloseRange { tgid, first, last }
                                if result >= 0 =>
                            {
                                for fd in self.dbus_channels.tracked_fds(tgid) {
                                    if fd >= 0 && (fd as u32) >= first && (fd as u32) <= last {
                                        self.demote_dbus_stepping(
                                            tgid,
                                            fd,
                                            "bus fd closed by close_range",
                                        );
                                    }
                                }
                                self.dbus_channels.close_range(tgid, first, last);
                            }
                            super::FdLifecyclePending::Dup {
                                tgid, source_fd, ..
                            } if result >= 0 => {
                                let new_fd = result as i32;
                                // dup2/dup3 silently close an already-open
                                // target, so a channel on the target number is
                                // gone whatever the source was.
                                if new_fd != source_fd {
                                    self.dbus_channels.close(tgid, new_fd);
                                    self.demote_dbus_stepping(
                                        tgid,
                                        new_fd,
                                        "bus fd closed by dup2 target reuse",
                                    );
                                }
                                if self.dbus_channels.is_tracked(tgid, source_fd) {
                                    self.dbus_channels.alias(tgid, source_fd, new_fd);
                                    self.promote_dbus_stepping(
                                        tgid,
                                        new_fd,
                                        "duplicated bus descriptor",
                                    );
                                }
                            }
                            super::FdLifecyclePending::CloseRange { .. }
                            | super::FdLifecyclePending::Dup { .. } => {}
                        }
                        self.resume_tracee(pid, None)?;
                        continue;
                    }

                    // B13: a thread of a process holding a connected
                    // non-loopback datagram socket. Only in a seccomp
                    // session — an attach session already stops on every
                    // syscall and classifies it below, so short-circuiting
                    // here would leave such a process effectively
                    // unsupervised for everything except the write.
                    //
                    // Stop ordering matters. The kernel reports the
                    // syscall-entry stop *before* the seccomp stop
                    // (`syscall_trace_enter` calls the ptrace report first,
                    // "to catch any tracer changes"), so a security-relevant
                    // syscall on a stepped thread produces entry → seccomp →
                    // exit. Only write/writev are acted on here; everything
                    // else is waved through so the seccomp stop remains the
                    // single place a syscall is classified.
                    if self.seccomp_session && self.tid_is_stepping(pid_u32) {
                        // Entry vs exit comes from the kernel's own record, not
                        // a per-tid toggle — the toggle desynced whenever a
                        // promoted syscall's exit stop was consumed by another
                        // handler (socket/connect/dns/fd-lifecycle) before
                        // reaching here, after which every write was judged at
                        // its exit, i.e. after the datagram was already sent
                        // (go-live review round 2).
                        let is_exit = Self::syscall_stop_is_exit(pid);
                        // The stepped thread can be killed (sibling exit_group,
                        // SIGKILL) while stopped here; its stepping state is
                        // reaped with its thread-exit, so skip the stale stop.
                        let Some(regs) = super::arch::read_syscall_regs(pid)? else {
                            record_event(self, pid_u32, "dgram-write-step:tracee-gone");
                            continue;
                        };
                        // Fallback for pre-5.3 kernels: at entry the kernel
                        // seeds the return register with -ENOSYS; at exit it
                        // holds the return value. `retval_hint` comes from the
                        // same register fetch as the arguments (pre-5.3 always
                        // reads the register file), so a tracee dying between
                        // reads cannot flip the judgment.
                        let at_entry = match is_exit {
                            Some(exit) => !exit,
                            None => regs
                                .retval_hint
                                .is_some_and(|retval| retval == -(libc::ENOSYS as i64)),
                        };
                        if !at_entry {
                            // Exit stop — the write already ran (or was
                            // cancelled by deny). This is where a D-Bus
                            // channel learns how many of the bytes it judged
                            // at entry the kernel actually accepted, so its
                            // decoder stays level with the socket. A denied
                            // write reports -EPERM and commits nothing.
                            if let Some(retval) = super::arch::read_return_value(pid)
                                .ok()
                                .flatten()
                                .or(regs.retval_hint)
                            {
                                self.commit_dbus_write(pid_u32, retval);
                            } else {
                                // Without a return value we cannot know the
                                // stream position; the channel must stop
                                // claiming to.
                                if let Some(pending) = self.pending_dbus_write.remove(&pid_u32) {
                                    self.dbus_channels.poison(
                                        pending.tgid,
                                        pending.fd,
                                        "write-result-unreadable",
                                    );
                                }
                            }
                            self.resume_tracee(pid, None)?;
                            continue;
                        }
                        record_event(self, pid_u32, "dgram-write-step");

                        let nr = regs.nr;
                        let sid = super::arch::sys_id(nr);
                        if !matches!(sid, Some(SysId::Write) | Some(SysId::Writev)) {
                            self.resume_to_next_syscall(pid, None)?;
                            continue;
                        }

                        let tgid = Self::resolve_tgid(pid_u32).unwrap_or(pid_u32);
                        let write_fd = regs.args[0] as i32;

                        // A D-Bus channel is checked first: it is not a
                        // connected datagram socket, so the egress-target
                        // check below would not recognise it and would demote
                        // the stepping this inspection depends on.
                        if self.dbus_channels.is_tracked(tgid, write_fd) {
                            if let Some(event) =
                                self.inspect_dbus_write(pid, tgid, pid_u32, write_fd, nr, &regs)
                            {
                                record_event(self, pid_u32, "dbus-write-step");
                                return Ok(Some(event));
                            }
                            // Curated as non-delegating: send it without a
                            // proxy round trip. This is the path that makes
                            // `gh auth token` stop prompting.
                            self.resume_to_next_syscall(pid, None)?;
                            continue;
                        }

                        let Some(destination) = self.connected_dgram_egress_target(tgid, write_fd)
                        else {
                            // Not egress: an ordinary file, the PTY, or a
                            // socket that is no longer a non-loopback connected
                            // datagram. Stop stepping the underlying socket
                            // (resolved through the tracker so a dup'd alias
                            // demotes the original, not a phantom fd — go-live
                            // review round 2), then keep going.
                            self.demote_stepping_socket(tgid, write_fd);
                            self.resume_to_next_syscall(pid, None)?;
                            continue;
                        };

                        if let Some(state) = self.stepping.get_mut(&tgid) {
                            state.awaiting.insert(pid_u32, write_fd);
                        }
                        return Ok(Some(Self::connected_dgram_write_event(
                            tgid,
                            pid_u32,
                            write_fd,
                            destination,
                            nr,
                        )));
                    }

                    record_event(self, pid_u32, "syscall-fallback");

                    // Entry vs exit comes from the kernel's own record, like
                    // the stepped-write path above — the per-tid toggle
                    // desyncs whenever another handler consumes a stop out of
                    // pattern, after which every exit was judged as an entry
                    // (and fed to the foreign-ABI check below with no entry
                    // record behind it — B1 round 3). The toggle is still
                    // maintained (insert at entry, remove at exit) because it
                    // doubles as the "inside a syscall" marker elsewhere, but
                    // it only *decides* on pre-5.3 kernels.
                    let at_exit = Self::syscall_stop_is_exit(pid)
                        .unwrap_or_else(|| self.in_syscall_entry.contains(&pid_u32));
                    if at_exit {
                        self.in_syscall_entry.remove(&pid_u32);
                        self.resume_tracee(pid, None)?;
                        continue;
                    }
                    self.in_syscall_entry.insert(pid_u32);

                    // B1 round-2: the attach-mode fallback (no seccomp) has no
                    // arch check, so `int 0x80` was classified straight
                    // through the x86_64 table and ran unsupervised under
                    // `grith exec --attach`. Take the ABI from the kernel's
                    // own syscall-entry record — the same source the seccomp
                    // arm uses — and route a foreign-ABI syscall to the
                    // hard-deny path. deny() cancels the syscall; its exit
                    // stop is consumed by the exit branch above.
                    if let Some(abi) = self.foreign_abi_at_stop(pid, false) {
                        let tgid = Self::resolve_tgid(pid_u32).unwrap_or(pid_u32);
                        self.tid_tgids.insert(pid_u32, tgid);
                        let raw_nr = super::arch::read_raw_syscall_nr(pid).unwrap_or(-1);
                        warn!(
                            pid = tgid,
                            tid = pid_u32,
                            abi = ?abi,
                            raw_nr,
                            "foreign-ABI syscall trapped in attach-mode fallback"
                        );
                        record_event(self, pid_u32, "syscall-fallback-foreign-abi");
                        return Ok(Some(SyscallEvent {
                            pid: tgid,
                            tid: pid_u32,
                            timestamp: Utc::now(),
                            kind: crate::interceptor::SyscallKind::ForeignAbiSyscall {
                                abi,
                                raw_nr,
                            },
                            raw_syscall_nr: raw_nr,
                        }));
                    }

                    // Tracee died in this stop; undo the entry toggle so a
                    // reused tid cannot inherit a stale entry/exit phase.
                    let Some(regs) = super::arch::read_syscall_regs(pid)? else {
                        self.in_syscall_entry.remove(&pid_u32);
                        record_event(self, pid_u32, "syscall-fallback:tracee-gone");
                        continue;
                    };
                    let nr = regs.nr;
                    let sid = super::arch::sys_id(nr);
                    let tgid = Self::resolve_tgid(pid_u32).unwrap_or(pid_u32);
                    let fd = regs.args[0] as i32;

                    if (sid == Some(SysId::CloseRange) && regs.args[2] & 2 != 0)
                        || (sid == Some(SysId::Unshare)
                            && regs.args[0] & libc::CLONE_FILES as u64 != 0)
                    {
                        warn!(
                            tgid,
                            tid = pid_u32,
                            syscall_nr = nr,
                            "denying FD-table unshare unsupported by DNS tracker"
                        );
                        self.deny(pid_u32).await?;
                        continue;
                    }

                    // B13 attach-mode parity: an attach session stops on
                    // every syscall already, so the connected-datagram write
                    // is surfaced inline rather than by stepping.
                    if matches!(sid, Some(SysId::Write) | Some(SysId::Writev)) {
                        if let Some(destination) = self.connected_dgram_egress_target(tgid, fd) {
                            return Ok(Some(Self::connected_dgram_write_event(
                                tgid,
                                pid_u32,
                                fd,
                                destination,
                                nr,
                            )));
                        }
                    }

                    // Attach-mode parity for targeted DNS and FD tracking.
                    // This fallback already stops at syscall boundaries, but
                    // uses the same pending-exit records as the seccomp path.
                    let lifecycle = match sid {
                        Some(SysId::Close) => Some(super::FdLifecyclePending::Close { tgid, fd }),
                        Some(SysId::CloseRange) if regs.args[2] & 4 == 0 => {
                            Some(super::FdLifecyclePending::CloseRange {
                                tgid,
                                first: regs.args[0] as u32,
                                last: regs.args[1] as u32,
                            })
                        }
                        Some(SysId::Dup) | Some(SysId::Dup2) | Some(SysId::Dup3) => {
                            Some(super::FdLifecyclePending::Dup {
                                tgid,
                                source_socket: self.dns_tracker.hold_socket_identity(tgid, fd),
                                source_fd: fd,
                            })
                        }
                        Some(SysId::Fcntl)
                            if matches!(
                                regs.args[1] as i32,
                                libc::F_DUPFD | libc::F_DUPFD_CLOEXEC
                            ) =>
                        {
                            Some(super::FdLifecyclePending::Dup {
                                tgid,
                                source_socket: self.dns_tracker.hold_socket_identity(tgid, fd),
                                source_fd: fd,
                            })
                        }
                        _ => None,
                    };
                    if let Some(pending) = lifecycle {
                        self.pending_fd_exit.insert(pid_u32, pending);
                        self.resume_to_next_syscall(pid, None)?;
                        continue;
                    }

                    if sid == Some(SysId::Socket)
                        && matches!(regs.args[0] as i32, libc::AF_INET | libc::AF_INET6)
                    {
                        let socket_type = match (regs.args[1] as i32) & 0xFF {
                            libc::SOCK_STREAM => super::dns_socket_tracker::SocketType::Stream,
                            libc::SOCK_DGRAM => super::dns_socket_tracker::SocketType::Datagram,
                            _ => super::dns_socket_tracker::SocketType::Other,
                        };
                        self.pending_socket_exit
                            .insert(pid_u32, super::SocketPending { tgid, socket_type });
                        self.resume_to_next_syscall(pid, None)?;
                        continue;
                    }

                    if self.dns_tracker.is_connected_proxy(tgid, fd)
                        && matches!(
                            sid,
                            Some(SysId::Sendto) | Some(SysId::Sendmsg) | Some(SysId::Sendmmsg)
                        )
                    {
                        if Self::proxy_send_uses_supported_connected_form(nr, &regs) {
                            self.resume_tracee(pid, None)?;
                            continue;
                        }
                        self.pending_dns_query.insert(
                            pid_u32,
                            crate::interceptor::DnsQueryInspection {
                                queries: Vec::new(),
                                parse_error: Some("dns-proxy-unsupported-send-form-denied".into()),
                            },
                        );
                        return Ok(Some(SyscallEvent {
                            pid: tgid,
                            tid: pid_u32,
                            timestamp: Utc::now(),
                            kind: crate::interceptor::SyscallKind::NetSendTo {
                                address: String::new(),
                                port: 53,
                            },
                            raw_syscall_nr: nr,
                        }));
                    }

                    if self.dns_cache.is_some()
                        && self.dns_observe_responses
                        && self.dns_tracker.is_dns(tgid, fd)
                        && !self.dns_tracker.is_connected_proxy(tgid, fd)
                        && matches!(
                            sid,
                            Some(SysId::Recvfrom) | Some(SysId::Recvmsg) | Some(SysId::Recvmmsg)
                        )
                    {
                        let Some(socket_id) = self.dns_tracker.hold_socket(tgid, fd) else {
                            warn!(
                                tgid,
                                tid = pid_u32,
                                fd,
                                "DNS receive raced a socket peer mutation; skipping attribution"
                            );
                            self.resume_tracee(pid, None)?;
                            continue;
                        };
                        let kind = match sid {
                            Some(SysId::Recvfrom) => super::DnsRecvKind::From {
                                buf_ptr: regs.args[1],
                                buf_len: (regs.args[2] as usize).min(MAX_DNS_MSG),
                            },
                            Some(SysId::Recvmsg) => super::DnsRecvKind::Msg {
                                msghdr_ptr: regs.args[1],
                            },
                            Some(SysId::Recvmmsg) => super::DnsRecvKind::Mmsg {
                                msgvec_ptr: regs.args[1],
                                vlen: (regs.args[2] as usize).min(MAX_DNS_BATCH),
                            },
                            _ => unreachable!(),
                        };
                        self.pending_dns_recv_exit.insert(
                            pid_u32,
                            super::DnsRecvPending {
                                tgid,
                                fd,
                                socket_id,
                                kind,
                            },
                        );
                        self.resume_to_next_syscall(pid, None)?;
                        continue;
                    }

                    if self.dns_cache.is_some()
                        && matches!(
                            sid,
                            Some(SysId::Sendto) | Some(SysId::Sendmsg) | Some(SysId::Sendmmsg)
                        )
                    {
                        if let Some(inspection) = self.inspect_dns_send(pid, tgid, fd, nr, &regs) {
                            self.pending_dns_query.insert(pid_u32, inspection);
                            return Ok(Some(SyscallEvent {
                                pid: tgid,
                                tid: pid_u32,
                                timestamp: Utc::now(),
                                kind: crate::interceptor::SyscallKind::NetSendTo {
                                    address: String::new(),
                                    port: 53,
                                },
                                raw_syscall_nr: nr,
                            }));
                        }
                    }

                    if sid == Some(SysId::Connect)
                        && self.dns_tracker.socket_type(tgid, fd)
                            == Some(super::dns_socket_tracker::SocketType::Datagram)
                        && self.sockaddr_family(pid, regs.args[1]) == Some(libc::AF_UNSPEC)
                    {
                        let Some(socket_id) = self.dns_tracker.pin_socket(tgid, fd) else {
                            self.deny(pid_u32).await?;
                            continue;
                        };
                        self.pending_udp_connect_exit.insert(
                            pid_u32,
                            super::UdpConnectPending {
                                socket_id,
                                destination: None,
                                fd,
                            },
                        );
                        self.resume_to_next_syscall(pid, None)?;
                        continue;
                    }

                    let uses_seccomp = self.seccomp_tracees.contains(&pid_u32);
                    if !is_fallback_relevant_syscall(nr, uses_seccomp) {
                        self.resume_tracee(pid, None)?;
                        continue;
                    }

                    match self.classify_syscall(pid, &regs) {
                        Ok(Some(kind)) => {
                            let tid = pid_u32;
                            if let crate::interceptor::SyscallKind::NetConnect {
                                address,
                                port,
                                protocol,
                            } = &kind
                            {
                                let socket_type = self.dns_tracker.socket_type(tgid, fd).unwrap_or(
                                    if *protocol == crate::interceptor::NetProtocol::Udp {
                                        super::dns_socket_tracker::SocketType::Datagram
                                    } else {
                                        super::dns_socket_tracker::SocketType::Stream
                                    },
                                );
                                if self.dns_tracker.socket_type(tgid, fd).is_none() {
                                    self.dns_tracker.observe_socket(tgid, fd, socket_type);
                                }
                                if *port == 53
                                    && self.block_tcp_dns
                                    && socket_type == super::dns_socket_tracker::SocketType::Stream
                                {
                                    self.pending_tcp_dns_deny.insert(tid);
                                }
                                if socket_type == super::dns_socket_tracker::SocketType::Datagram {
                                    let Some(destination) = address
                                        .parse::<IpAddr>()
                                        .ok()
                                        .map(|ip| SocketAddr::new(ip, *port))
                                    else {
                                        self.deny(pid_u32).await?;
                                        continue;
                                    };
                                    let Some(socket_id) = self.dns_tracker.pin_socket(tgid, fd)
                                    else {
                                        self.deny(pid_u32).await?;
                                        continue;
                                    };
                                    self.pending_udp_connect_exit.insert(
                                        pid_u32,
                                        super::UdpConnectPending {
                                            socket_id,
                                            destination: Some(destination),
                                            fd,
                                        },
                                    );
                                    self.resume_to_next_syscall(pid, None)?;
                                    continue;
                                }
                            }

                            trace!(
                                pid = tgid,
                                tid = tid,
                                syscall_nr = nr,
                                "intercepted security-relevant syscall (fallback)"
                            );
                            return Ok(Some(SyscallEvent {
                                pid: tgid,
                                tid,
                                timestamp: Utc::now(),
                                kind,
                                raw_syscall_nr: nr,
                            }));
                        }
                        Ok(None) => {
                            self.resume_tracee(pid, None)?;
                            continue;
                        }
                        Err(e) => {
                            // Fail-closed: same rationale as the seccomp path
                            // above — deny rather than allow when we cannot
                            // classify the syscall.
                            warn!(
                                pid = pid.as_raw(),
                                syscall_nr = nr,
                                error = %e,
                                "classify_syscall failed; denying syscall (fail-closed)"
                            );
                            if let Err(deny_err) = self.deny(pid_u32).await {
                                warn!(
                                    pid = pid.as_raw(),
                                    syscall_nr = nr,
                                    error = %deny_err,
                                    "deny after classify failure also failed; tracee may have exited"
                                );
                            }
                            continue;
                        }
                    }
                }

                // -- Normal signal delivery ---------------------------------------
                WaitStatus::Stopped(pid, sig) => {
                    let pid_u32 = pid.as_raw() as u32;
                    debug!(
                        tid = pid_u32,
                        signal = ?sig,
                        "signal-delivery-stop"
                    );

                    // A clone child's initial ptrace stop can arrive before
                    // the parent's PTRACE_EVENT_CLONE/FORK stop. Quarantine
                    // that child while the proxy is enabled — resuming it now
                    // would let it mutate inherited descriptors before the
                    // tracker installs the exact parent table mapping — and
                    // also whenever any process is being stepped for
                    // connected-datagram writes (B13, go-live review round 2):
                    // an unknown child could be a fork of a stepping process,
                    // and resuming it before its tgid and inherited stepping
                    // state are committed leaves a window in which its first
                    // write egresses unobserved.
                    if (self.connected_dns_proxy.is_some() || !self.stepping.is_empty())
                        && !self.supervised.contains(&pid_u32)
                    {
                        self.supervised.insert(pid_u32);
                        self.pending_child_initial_stops.insert(pid_u32);
                        record_event(self, pid_u32, "ptrace-event:child-before-parent");
                        continue;
                    }

                    // A signal-delivery-stop can preempt the exit stop of a
                    // syscall we promoted to two-stop tracking: a connected-DNS
                    // connect/redirect (`pending_dns_connect_exit`), a tracked
                    // UDP connect/reconnect (`pending_udp_connect_exit`), or an
                    // FD-lifecycle close/dup/close_range (`pending_fd_exit`). We
                    // resumed the entry with PTRACE_SYSCALL, so the kernel stops
                    // at a pending signal *before* the syscall-exit stop — the
                    // syscall has not executed yet. Each `pending_*_exit` record
                    // is cleared only by the exit handler, so its presence here
                    // proves the exit was not seen.
                    //
                    // The previous behaviour terminated the whole session fail
                    // closed here, which turned a routine `SIGCHLD` arriving
                    // during a close/dup or a DNS connect into a fatal supervisor
                    // crash for any multi-process tracee (`grith exec codex` /
                    // `claude`). Instead, keep the pending record, forward the
                    // signal (job-control/trap stops are suppressed, as on the
                    // general path below), and resume back to the syscall
                    // boundary: the exit stop is still delivered and reconciled
                    // by the normal exit handler. On a transparent restart
                    // (ERESTARTSYS) the connect re-runs with the redirect rewrite
                    // still in tracee memory, so DNS route bookkeeping is not
                    // bypassed — strictly safer than restoring direct-DNS bytes.
                    // A fatal signal instead exits the tracee, and the Exited arm
                    // clears the pending record.
                    if self.pending_dns_connect_exit.contains_key(&pid_u32)
                        || self.pending_udp_connect_exit.contains_key(&pid_u32)
                        || self.pending_fd_exit.contains_key(&pid_u32)
                    {
                        record_event(self, pid_u32, "tracked-syscall-signal-deferred");
                        let forward = if sig == Signal::SIGSTOP || sig == Signal::SIGTRAP {
                            None
                        } else {
                            Some(sig)
                        };
                        self.resume_to_next_syscall(pid, forward)?;
                        continue;
                    }

                    // A promoted response receive is read-only, so losing one
                    // cache observation is safe. `socket()` creates previously
                    // unknown state and remains a documented residual here.
                    if let Some(pending) = self.pending_dns_recv_exit.remove(&pid_u32) {
                        self.in_syscall_entry.remove(&pid_u32);
                        if let Some(route_id) =
                            self.dns_tracker.release_socket_hold(pending.socket_id)
                        {
                            let _ = self.release_connected_route(route_id);
                        }
                    }
                    self.pending_socket_exit.remove(&pid_u32);

                    // Capture the PREVIOUS event kind for this tid before
                    // we overwrite it with "stopped". Used below to gate
                    // SIGCONT injection: an initial post-clone stop on a
                    // brand-new helper thread has previous kind
                    // "ptrace-event:child-of" (or no entry at all),
                    // whereas a thread that has previously executed
                    // syscalls has kinds like "seccomp" / "allow" /
                    // "deny" / "syscall-fallback".
                    let prev_kind = self.last_event_kind.get(&pid_u32).cloned();

                    record_event(self, pid_u32, "stopped");
                    let forward = if sig == Signal::SIGSTOP || sig == Signal::SIGTRAP {
                        None
                    } else {
                        Some(sig)
                    };
                    self.resume_tracee(pid, forward)?;

                    // Group-stop wedge fix (2026-05-26 investigation):
                    //
                    // For job-control stop signals (SIGSTOP, SIGTSTP,
                    // SIGTTIN, SIGTTOU), `PTRACE_CONT(sig=0)` only clears
                    // the ptrace-stop bit. The kernel-level group-stop
                    // bit (`TASK_STOPPED`) stays set until a SIGCONT
                    // delivery reaches the process / thread group.
                    // Multi-threaded tracees like Node.js (claude) hit
                    // this when one thread sends SIGSTOP to a sibling
                    // for internal coordination: the supervisor sees
                    // the signal-delivery-stop, calls PTRACE_CONT to
                    // suppress, but the tracee stays in kernel
                    // TASK_STOPPED indefinitely because nothing ever
                    // sends SIGCONT.
                    //
                    // Observed: 6+ tracee threads stuck for >250s with
                    // `last_event_kind=stopped`, supervisor's PTRACE_CONT
                    // returned Ok but the tracee never resumed.
                    //
                    // Fix: when we suppress a job-control stop signal on
                    // an *established* tracee (one that has previously
                    // executed syscalls), also deliver SIGCONT to clear
                    // the kernel-level group-stop. Skip SIGCONT for the
                    // initial post-clone stop of brand-new helper
                    // threads — they're in TASK_TRACED only (no group-
                    // stop bit), so SIGCONT would be a no-op vs the
                    // kernel but visible to the application's signal
                    // handler. Node.js' claude has a SIGCONT handler
                    // that re-paints its welcome banner; injecting on
                    // every new helper thread's initial stop produced
                    // a duplicated banner at startup (~30 helpers ×
                    // SIGCONT delivery = many redraws).
                    let is_jobctl_stop = matches!(
                        sig,
                        Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
                    );
                    let is_established = matches!(
                        prev_kind.as_deref(),
                        Some("seccomp")
                            | Some("seccomp-noop")
                            | Some("syscall-fallback")
                            | Some("allow")
                            | Some("deny")
                            | Some("ptrace-event:exec")
                            // A thread stepped for connected-datagram writes
                            // (B13) is as established as any other, and it is
                            // the one paying two stops per syscall — omitting
                            // it would disable this wedge fix for precisely
                            // the threads most exposed to the wedge.
                            | Some("dgram-write-step")
                            // Likewise a thread stopped on a foreign-ABI
                            // syscall (B1).
                            | Some("seccomp-foreign-abi")
                    );
                    if is_jobctl_stop && is_established {
                        if let Err(e) = nix::sys::signal::kill(pid, Signal::SIGCONT) {
                            debug!(
                                tid = pid_u32,
                                error = %e,
                                "SIGCONT injection failed (tracee may have exited)"
                            );
                        }
                    }
                    continue;
                }

                // -- Process exited normally --------------------------------------
                WaitStatus::Exited(pid, code) => {
                    let pid_u32 = pid.as_raw() as u32;
                    let exited_tgid = self
                        .tid_tgids
                        .remove(&pid_u32)
                        .or_else(|| Self::resolve_tgid(pid_u32))
                        .unwrap_or(pid_u32);
                    self.supervised.remove(&pid_u32);
                    self.in_syscall_entry.remove(&pid_u32);
                    self.thread_tids.remove(&pid_u32);
                    self.pending_child_initial_stops.remove(&pid_u32);
                    self.pending_clone_fd_table.remove(&pid_u32);
                    self.seccomp_tracees.remove(&pid_u32);
                    // B13: this tid may have had a write awaiting a decision;
                    // clear it from its process's stepping state (keyed by
                    // tgid, not tid).
                    if let Some(state) = self.stepping.get_mut(&exited_tgid) {
                        state.awaiting.remove(&pid_u32);
                    }
                    // The thread group is gone only when its leader exits.
                    if exited_tgid == pid_u32 {
                        self.demote_stepping_tgid(pid_u32, "process exited");
                        self.pending_dbus_call.remove(&pid_u32);
                        self.pending_dbus_write.remove(&pid_u32);
                        self.dbus_channels.remove_process(pid_u32);
                    }
                    self.last_event_at.remove(&pid_u32);
                    self.last_event_kind.remove(&pid_u32);
                    if let Some(pending) = self.pending_dns_recv_exit.remove(&pid_u32) {
                        if let Some(route_id) =
                            self.dns_tracker.release_socket_hold(pending.socket_id)
                        {
                            self.release_connected_route(route_id)?;
                        }
                    }
                    if let Some(pending) = self.pending_dns_connect_exit.remove(&pid_u32) {
                        if let Some(control) = &self.connected_dns_proxy {
                            let _ = control.release_route(pending.route.route_id);
                        }
                        if let Some(route_id) = self.dns_tracker.unpin_socket(pending.socket_id) {
                            self.release_connected_route(route_id)?;
                        }
                        return Err(self.terminate_after_dns_redirect_failure(
                            pending.tgid,
                            &format!(
                                "tid {pid_u32} exited during connected DNS sockaddr replacement"
                            ),
                        ));
                    }
                    if let Some(pending) = self.pending_udp_connect_exit.remove(&pid_u32) {
                        if let Some(route_id) = self.dns_tracker.unpin_socket(pending.socket_id) {
                            self.release_connected_route(route_id)?;
                        }
                    }
                    self.pending_dns_query.remove(&pid_u32);
                    self.pending_inline_dns_transactions.remove(&pid_u32);
                    self.pending_socket_exit.remove(&pid_u32);
                    if let Some(pending) = self.pending_fd_exit.remove(&pid_u32) {
                        if let Some(socket_id) = pending.held_socket() {
                            if let Some(route_id) = self.dns_tracker.release_socket_hold(socket_id)
                            {
                                self.release_connected_route(route_id)?;
                            }
                        }
                    }
                    self.pending_tcp_dns_deny.remove(&pid_u32);
                    let tgid_still_live = self.tid_tgids.values().any(|tgid| *tgid == exited_tgid);
                    if !tgid_still_live {
                        let released = self.dns_tracker.remove_process(exited_tgid);
                        self.release_connected_routes(released)?;
                    }
                    info!(pid = pid_u32, exit_code = code, "supervised process exited");

                    if self.supervised.is_empty() || self.root_pid == Some(pid_u32) {
                        if !self.supervised.is_empty() {
                            info!(
                                remaining = self.supervised.len(),
                                "root process exited, terminating remaining children"
                            );
                            self.terminate_all().await?;
                        }
                        return Ok(None);
                    }
                    continue;
                }

                // -- Process killed by signal -------------------------------------
                WaitStatus::Signaled(pid, sig, _core_dumped) => {
                    let pid_u32 = pid.as_raw() as u32;
                    let exited_tgid = self
                        .tid_tgids
                        .remove(&pid_u32)
                        .or_else(|| Self::resolve_tgid(pid_u32))
                        .unwrap_or(pid_u32);
                    self.supervised.remove(&pid_u32);
                    self.in_syscall_entry.remove(&pid_u32);
                    self.thread_tids.remove(&pid_u32);
                    self.pending_child_initial_stops.remove(&pid_u32);
                    self.pending_clone_fd_table.remove(&pid_u32);
                    self.seccomp_tracees.remove(&pid_u32);
                    // B13: this tid may have had a write awaiting a decision;
                    // clear it from its process's stepping state (keyed by
                    // tgid, not tid).
                    if let Some(state) = self.stepping.get_mut(&exited_tgid) {
                        state.awaiting.remove(&pid_u32);
                    }
                    // The thread group is gone only when its leader exits.
                    if exited_tgid == pid_u32 {
                        self.demote_stepping_tgid(pid_u32, "process exited");
                        self.pending_dbus_call.remove(&pid_u32);
                        self.pending_dbus_write.remove(&pid_u32);
                        self.dbus_channels.remove_process(pid_u32);
                    }
                    self.last_event_at.remove(&pid_u32);
                    self.last_event_kind.remove(&pid_u32);
                    if let Some(pending) = self.pending_dns_recv_exit.remove(&pid_u32) {
                        if let Some(route_id) =
                            self.dns_tracker.release_socket_hold(pending.socket_id)
                        {
                            self.release_connected_route(route_id)?;
                        }
                    }
                    if let Some(pending) = self.pending_dns_connect_exit.remove(&pid_u32) {
                        if let Some(control) = &self.connected_dns_proxy {
                            let _ = control.release_route(pending.route.route_id);
                        }
                        if let Some(route_id) = self.dns_tracker.unpin_socket(pending.socket_id) {
                            self.release_connected_route(route_id)?;
                        }
                        return Err(self.terminate_after_dns_redirect_failure(
                            pending.tgid,
                            &format!(
                                "tid {pid_u32} was killed by {sig:?} during connected DNS sockaddr replacement"
                            ),
                        ));
                    }
                    if let Some(pending) = self.pending_udp_connect_exit.remove(&pid_u32) {
                        if let Some(route_id) = self.dns_tracker.unpin_socket(pending.socket_id) {
                            self.release_connected_route(route_id)?;
                        }
                    }
                    self.pending_dns_query.remove(&pid_u32);
                    self.pending_inline_dns_transactions.remove(&pid_u32);
                    self.pending_socket_exit.remove(&pid_u32);
                    if let Some(pending) = self.pending_fd_exit.remove(&pid_u32) {
                        if let Some(socket_id) = pending.held_socket() {
                            if let Some(route_id) = self.dns_tracker.release_socket_hold(socket_id)
                            {
                                self.release_connected_route(route_id)?;
                            }
                        }
                    }
                    self.pending_tcp_dns_deny.remove(&pid_u32);
                    let tgid_still_live = self.tid_tgids.values().any(|tgid| *tgid == exited_tgid);
                    if !tgid_still_live {
                        let released = self.dns_tracker.remove_process(exited_tgid);
                        self.release_connected_routes(released)?;
                    }
                    warn!(
                        pid = pid_u32,
                        signal = ?sig,
                        "supervised process killed by signal"
                    );

                    if self.supervised.is_empty() || self.root_pid == Some(pid_u32) {
                        if !self.supervised.is_empty() {
                            info!(
                                remaining = self.supervised.len(),
                                "root process killed, terminating remaining children"
                            );
                            self.terminate_all().await?;
                        }
                        return Ok(None);
                    }
                    continue;
                }

                // -- Continued (SIGCONT after stop) -------------------------------
                // We don't request WCONTINUED in waitpid flags, so this
                // branch should never fire today. Logged in case kernel/nix
                // semantics shift.
                WaitStatus::Continued(pid) => {
                    let pid_u32 = pid.as_raw() as u32;
                    debug!(
                        tid = pid_u32,
                        "WaitStatus::Continued — unexpected without WCONTINUED"
                    );
                    continue;
                }

                // -- Catch-all for future nix variants ----------------------------
                // Previously this was silent. If a future nix-rs release
                // adds a WaitStatus variant we don't recognise, ANY tracee
                // emitting it would wedge in ptrace_stop with no log trail.
                // Warn here so the next wedge investigation has a starting
                // point. We still `continue` rather than release blindly,
                // because we can't reliably extract a pid from an unknown
                // variant — the watchdog will detect and report.
                other => {
                    warn!(
                        wait_status = ?other,
                        "unrecognised WaitStatus variant — possible wedge source; \
                         report to grith maintainers"
                    );
                    continue;
                }
            }
        }
    }

    /// Allow the intercepted syscall to proceed.
    async fn allow(&mut self, pid: u32) -> Result<()> {
        let nix_pid = Pid::from_raw(pid as i32);
        trace!(pid, "allowing syscall to proceed");
        record_event(self, pid, "allow");
        // B13: a surfaced write on this thread has been allowed, so its
        // destination is decided for the session and later writes to that fd
        // would only re-derive the same answer — stop paying two ptrace stops
        // per syscall for it.
        self.settle_stepping_decision(pid, true);
        // A D-Bus channel is NOT settled by an allow: the next method call on
        // the same connection is a fresh decision, and it is exactly where a
        // second, less benign call would hide. `pending_dbus_write` survives
        // to the exit stop, which commits the bytes the kernel accepted.
        self.pending_dbus_call.remove(&pid);
        // Route through resume_tracee so the resume primitive is recorded for
        // wedge forensics (and the CONT/SYSCALL selection stays in one place).
        self.resume_tracee(nix_pid, None)
    }

    /// Deny the intercepted syscall and force an `EPERM` return value.
    async fn deny(&mut self, pid: u32) -> Result<()> {
        let nix_pid = Pid::from_raw(pid as i32);
        trace!(pid, "denying syscall");
        // A denied clone/fork will not produce a ptrace child event; discard
        // any entry-time inheritance snapshot so it cannot be paired with a
        // later, unrelated event.
        self.pending_clone_fd_table.remove(&pid);
        // B13: a DENIED write keeps its fd tracked — a thread that has tried
        // to reach a rejected destination will try again, and every attempt
        // must be rejected. The awaiting entry is still cleared, or the next
        // unrelated allowed syscall on this thread would be mistaken for the
        // decision and end stepping silently.
        self.settle_stepping_decision(pid, false);
        self.pending_dbus_call.remove(&pid);

        // Replace the syscall with an invalid number so the kernel skips
        // execution, and pre-seed the return register with -EPERM so the
        // tracee sees a real permission error instead of ENOSYS. The
        // register mechanics are per-arch (`arch::deny_syscall`).
        //
        // A tracee that died in its stop cannot execute the syscall, so the
        // denial is vacuously enforced — never fatal. This is also the path
        // the fail-closed classify-error handler takes, so an error here
        // would turn a benign thread death into full session teardown.
        if !super::arch::deny_syscall(nix_pid, libc::EPERM)? {
            record_event(self, pid, "deny:tracee-gone");
            return Ok(());
        }

        record_event(self, pid, "deny");
        self.resume_tracee(nix_pid, None)
    }

    /// Kill the intercepted tracee with `SIGKILL`.
    ///
    /// Makes a DENY effective for a `ProcessSpawn` stopped at
    /// `PTRACE_EVENT_EXEC`, where `deny_syscall` cannot un-exec the process
    /// (there is no in-flight syscall to convert to EPERM). We SIGKILL, then
    /// resume the tracee so the kernel processes the now-pending fatal signal:
    /// a `SIGKILL` cannot be suppressed by `PTRACE_CONT` and is delivered on
    /// the return-to-userspace path, so the tracee dies **before** it executes
    /// the new image's first instruction (`systemd-run` never connects to the
    /// session manager). Resuming rather than relying on the stop-and-reap is
    /// portable across kernels that hold a ptrace-stopped tracee until its next
    /// resumption. The event loop's next `waitpid` reaps the exit and prunes
    /// the process tree. A tracee that `SIGKILL` already reaped makes the
    /// resume a no-op (`ESRCH`), which is expected and not an error (mirrors the
    /// tracee-gone handling in `deny`).
    async fn kill(&mut self, pid: u32) -> Result<()> {
        let nix_pid = Pid::from_raw(pid as i32);
        trace!(pid, "killing tracee (SIGKILL)");
        // A killed spawn will not produce further ptrace events for its intended
        // work; discard any entry-time inheritance snapshot (mirrors `deny`).
        self.pending_clone_fd_table.remove(&pid);
        self.settle_stepping_decision(pid, false);
        match nix::sys::signal::kill(nix_pid, Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
            Err(e) => {
                return Err(Error::InterceptionError(format!(
                    "SIGKILL to pid {pid} failed: {e}"
                )));
            }
        }
        // Resume so the pending SIGKILL is processed. On a kernel that already
        // reaped the tracee this fails with ESRCH (or a benign resume error) —
        // the kill is vacuously satisfied, so log at trace and carry on rather
        // than propagate. The kill itself has already been delivered above.
        if let Err(e) = self.resume_tracee(nix_pid, None) {
            trace!(
                pid,
                error = %e,
                "resume after SIGKILL failed (tracee already reaped) — ignoring"
            );
        }
        record_event(self, pid, "kill");
        Ok(())
    }

    /// Freeze a process by sending `SIGSTOP`.
    async fn freeze(&mut self, pid: u32) -> Result<()> {
        let nix_pid = Pid::from_raw(pid as i32);
        nix::sys::signal::kill(nix_pid, Signal::SIGSTOP)
            .map_err(|e| Error::FreezeError(format!("SIGSTOP to pid {pid} failed: {e}")))?;
        info!(pid, "process frozen via SIGSTOP");
        Ok(())
    }

    /// Thaw a previously frozen process by sending `SIGCONT`.
    async fn thaw(&mut self, pid: u32) -> Result<()> {
        let nix_pid = Pid::from_raw(pid as i32);
        nix::sys::signal::kill(nix_pid, Signal::SIGCONT)
            .map_err(|e| Error::FreezeError(format!("SIGCONT to pid {pid} failed: {e}")))?;
        info!(pid, "process thawed via SIGCONT");
        Ok(())
    }

    /// Detach from a single supervised process.
    async fn detach(&mut self, pid: u32) -> Result<()> {
        if self.proxy_route_requires_session_termination_on_detach() {
            warn!(
                requested_pid = pid,
                "refusing to detach while a connected DNS proxy route owns a \
                 kernel socket peer; terminating the supervised session"
            );
            self.terminate_all().await?;
            return Ok(());
        }

        let nix_pid = Pid::from_raw(pid as i32);
        if let Some(pending) = self.pending_dns_connect_exit.remove(&pid) {
            if let Err(error) = pending.sockaddr.restore(nix_pid) {
                if let Some(control) = &self.connected_dns_proxy {
                    let _ = control.release_route(pending.route.route_id);
                }
                self.dns_tracker.unpin_socket(pending.socket_id);
                return Err(self.terminate_after_dns_redirect_failure(
                    pending.tgid,
                    &format!("detach could not restore DNS connect sockaddr: {error}"),
                ));
            }
            if let Some(control) = &self.connected_dns_proxy {
                control
                    .release_route(pending.route.route_id)
                    .map_err(|error| {
                        Error::InterceptionError(format!(
                            "detach could not release pending DNS route: {error}"
                        ))
                    })?;
            }
            if let Some(route_id) = self.dns_tracker.unpin_socket(pending.socket_id) {
                self.release_connected_route(route_id)?;
            }
        }
        if let Some(pending) = self.pending_udp_connect_exit.remove(&pid) {
            if let Some(route_id) = self.dns_tracker.unpin_socket(pending.socket_id) {
                self.release_connected_route(route_id)?;
            }
        }
        if let Some(pending) = self.pending_dns_recv_exit.remove(&pid) {
            if let Some(route_id) = self.dns_tracker.release_socket_hold(pending.socket_id) {
                self.release_connected_route(route_id)?;
            }
        }
        self.pending_dns_query.remove(&pid);
        self.pending_inline_dns_transactions.remove(&pid);
        self.pending_clone_fd_table.remove(&pid);
        self.pending_child_initial_stops.remove(&pid);
        if let Some(pending) = self.pending_fd_exit.remove(&pid) {
            if let Some(socket_id) = pending.held_socket() {
                if let Some(route_id) = self.dns_tracker.release_socket_hold(socket_id) {
                    self.release_connected_route(route_id)?;
                }
            }
        }
        ptrace::detach(nix_pid, None).map_err(|e| {
            Error::InterceptionError(format!("PTRACE_DETACH failed for pid {pid}: {e}"))
        })?;
        self.supervised.remove(&pid);
        self.tid_tgids.remove(&pid);
        self.in_syscall_entry.remove(&pid);
        self.thread_tids.remove(&pid);
        self.seccomp_tracees.remove(&pid);
        self.last_event_at.remove(&pid);
        self.last_event_kind.remove(&pid);
        info!(pid, "detached from process");
        Ok(())
    }

    async fn spawn_supervised_pty(
        &mut self,
        command: &str,
        args: &[String],
        env: &[(String, String)],
        cols: u16,
        rows: u16,
    ) -> Result<(
        u32,
        Box<dyn std::io::Read + Send>,
        Box<dyn std::io::Write + Send>,
    )> {
        let result =
            super::child::do_spawn_supervised_pty(self, command, args, env, cols, rows).await?;
        Ok((
            result.pid,
            Box::new(result.master_read),
            Box::new(result.master_write),
        ))
    }

    /// Detach from all supervised processes.
    async fn detach_all(&mut self) -> Result<()> {
        if self.proxy_route_requires_session_termination_on_detach() {
            warn!(
                "shutdown requested with connected DNS proxy routes; terminating \
                 tracees instead of detaching them with loopback-owned peers"
            );
            self.terminate_all().await?;

            // The processes are no longer allowed to continue, so no tracee
            // memory restoration is required. Tear down every pending and
            // committed route best-effort; the session-owned worker shutdown
            // remains the final cleanup backstop.
            let pending_route_ids: Vec<_> = self
                .pending_dns_connect_exit
                .drain()
                .map(|(_, pending)| pending.route.route_id)
                .collect();
            if let Some(control) = &self.connected_dns_proxy {
                for route_id in pending_route_ids {
                    if let Err(error) = control.release_route(route_id) {
                        warn!(
                            route_id = route_id.get(),
                            error = %error,
                            "failed to release pending DNS route after terminating tracees"
                        );
                    }
                }
            }
            self.pending_udp_connect_exit.clear();
            self.pending_dns_recv_exit.clear();
            self.pending_dns_query.clear();
            self.pending_inline_dns_transactions.clear();
            self.pending_fd_exit.clear();
            self.pending_clone_fd_table.clear();
            self.pending_child_initial_stops.clear();
            self.tid_tgids.clear();
            let released = self.dns_tracker.clear();
            for route_id in released {
                if let Err(error) = self.release_connected_route(route_id) {
                    warn!(
                        route_id = route_id.0,
                        error = %error,
                        "failed to release committed DNS route after terminating tracees"
                    );
                }
            }
            return Ok(());
        }

        let pids: Vec<u32> = self.supervised.iter().copied().collect();
        for pid in pids {
            if let Err(e) = self.detach(pid).await {
                error!(
                    pid,
                    error = %e,
                    "failed to detach from process (continuing with remaining)"
                );
            }
        }
        let released = self.dns_tracker.clear();
        self.release_connected_routes(released)?;
        Ok(())
    }

    /// Return all currently supervised PIDs.
    fn supervised_pids(&self) -> Vec<u32> {
        self.supervised.iter().copied().collect()
    }

    /// Check whether ptrace-based interception is available on this system.
    fn is_available() -> bool {
        match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
            Ok(contents) => contents
                .trim()
                .parse::<u32>()
                .map_or(true, |scope| scope <= 1),
            Err(_) => {
                // Yama LSM not present or file not readable. Defaulting to
                // available, but this may indicate an unusual kernel config.
                warn!(
                    "could not read /proc/sys/kernel/yama/ptrace_scope; \
                     assuming ptrace is available (Yama LSM may not be enabled)"
                );
                true
            }
        }
    }

    /// Return the human-readable name of the interception mechanism.
    fn mechanism_name(&self) -> &str {
        "ptrace"
    }

    /// Scan supervised tracees for ones wedged in `ptrace_stop` for longer
    /// than `threshold`. Observation-only: returns forensic snapshots, does
    /// NOT release the tracees (masking the wedge would also mask the bug).
    ///
    /// Per-tid cost: 3 small `/proc` reads (status, syscall, stack). With
    /// ~30 supervised tids and a 10s scan interval, this is ~free vs. the
    /// supervisor's main syscall-processing load.
    fn wedge_scan(&self, threshold: std::time::Duration) -> Vec<WedgedTracee> {
        let now = std::time::Instant::now();
        let mut wedged = Vec::new();

        for &tid in &self.supervised {
            let last_at = match self.last_event_at.get(&tid).copied() {
                Some(t) => t,
                // No recorded event yet — the tracee was just added (e.g.
                // first attach, or fresh child whose first stop hasn't
                // arrived). Skip rather than false-positive.
                None => continue,
            };
            let since_last = now.saturating_duration_since(last_at);
            if since_last < threshold {
                continue;
            }

            // Read /proc state. If the tracee is gone, /proc reads fail
            // with ENOENT — skip silently (the supervisor will reap it
            // via WaitStatus::Exited shortly).
            let status_text = match std::fs::read_to_string(format!("/proc/{tid}/status")) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let state = extract_state_letter(&status_text);
            // Only flag tracees in ptrace tracing-stop. The kernel reports
            // this as 't' (lowercase) in modern kernels; the historical
            // 'T' (uppercase) means "stopped by signal" which can also
            // indicate a stuck tracee. Both warrant a forensic snapshot.
            if !state.starts_with('t') && !state.starts_with('T') {
                continue;
            }

            let comm = std::fs::read_to_string(format!("/proc/{tid}/comm"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let syscall_info = std::fs::read_to_string(format!("/proc/{tid}/syscall"))
                .unwrap_or_default()
                .trim()
                .to_string();
            // Truncate kernel stack to first 5 frames — enough to see what
            // syscall the thread is parked at without flooding the audit
            // row.
            let stack_summary = std::fs::read_to_string(format!("/proc/{tid}/stack"))
                .unwrap_or_default()
                .lines()
                .take(5)
                .collect::<Vec<_>>()
                .join(" | ");

            // Signal forensics: is the tracee being held by a pending signal
            // the supervisor's resume didn't clear? `SigPnd` = per-thread
            // pending, `ShdPnd` = process-shared pending, `SigBlk` = blocked.
            let sig_pnd = extract_status_hex(&status_text, "SigPnd");
            let shd_pnd = extract_status_hex(&status_text, "ShdPnd");
            let sig_blk = extract_status_hex(&status_text, "SigBlk");
            let signal_summary =
                format!("SigPnd={sig_pnd:016x} ShdPnd={shd_pnd:016x} SigBlk={sig_blk:016x}");
            // Job-control stop signals occupy bits (signum-1): SIGSTOP(19),
            // SIGTSTP(20), SIGTTIN(21), SIGTTOU(22) → bits 18..=21 → 0x3C0000.
            const JOBCTL_STOP_MASK: u64 = 0x003C_0000;
            let jobctl_stop_pending = (sig_pnd | shd_pnd) & JOBCTL_STOP_MASK != 0;

            wedged.push(WedgedTracee {
                tid,
                since_last_event: since_last,
                last_event_kind: self.last_event_kind.get(&tid).cloned(),
                comm,
                state,
                syscall_info,
                stack_summary,
                signal_summary,
                jobctl_stop_pending,
                resume_primitive: self
                    .last_resume_primitive
                    .get(&tid)
                    .copied()
                    .unwrap_or("none")
                    .to_string(),
                is_thread: self.thread_tids.contains(&tid),
                in_syscall_stop: self.in_syscall_entry.contains(&tid),
            });
        }

        wedged
    }
}

/// Extract the state letter from a `/proc/<tid>/status` blob.
/// Returns the first whitespace-trimmed token after `State:\t`, or an
/// empty string when the format doesn't match.
fn extract_state_letter(status_text: &str) -> String {
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix("State:") {
            return rest
                .trim()
                .chars()
                .next()
                .map(|c| c.to_string())
                .unwrap_or_default();
        }
    }
    String::new()
}

/// Parse a hex signal-mask field (e.g. `SigPnd:\t0000000000000000`) from a
/// `/proc/<tid>/status` blob into a `u64`. Returns 0 when the field is absent
/// or unparseable.
fn extract_status_hex(status_text: &str, field: &str) -> u64 {
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            // Format is "<field>:\t<hex>"; take the trailing whitespace-
            // separated token and parse it as base-16.
            if let Some(tok) = rest.trim_start_matches(':').split_whitespace().next() {
                return u64::from_str_radix(tok, 16).unwrap_or(0);
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interceptor::{NetProtocol, OpenFlags, SyscallKind};
    use crate::platform::linux::syscall_nr;

    // Protection suite (§6.4) — fail-closed lock: every tracee MUST be set with
    // PTRACE_O_EXITKILL so a supervisor crash SIGKILLs the tracees instead of
    // leaving them running with no security controls. Dropping it is a silent,
    // critical regression.
    #[test]
    fn trace_options_always_include_exitkill() {
        assert!(
            trace_options().contains(nix::sys::ptrace::Options::PTRACE_O_EXITKILL),
            "PTRACE_O_EXITKILL must always be set — tracees must not survive supervisor death"
        );
        // The seccomp-event + clone-tracing options the supervisor depends on.
        assert!(trace_options().contains(nix::sys::ptrace::Options::PTRACE_O_TRACESECCOMP));
        assert!(trace_options().contains(nix::sys::ptrace::Options::PTRACE_O_TRACECLONE));
    }

    /// An attach-mode session has no stepped-write path — `write`/`writev`
    /// reach `classify_syscall`, which returns `Ok(None)` for them — so a bus
    /// write would pass unseen. Arming inspection there would suppress the
    /// connect-time prompt while nothing downstream watched, turning "decide
    /// per message" into "decide never". The backend must report that it
    /// cannot, so the caller keeps enforcing at the connect.
    #[test]
    fn dbus_inspection_arms_only_for_a_seccomp_session() {
        let mut attach = PtraceSupervisor::new();
        assert!(!attach.seccomp_session);
        assert!(
            !attach.enable_dbus_inspection(),
            "an attach-mode session cannot see bus writes and must say so"
        );
        assert!(!attach.dbus_inspection);

        let mut spawned = PtraceSupervisor::new();
        spawned.seccomp_session = true;
        assert!(spawned.enable_dbus_inspection());
        assert!(spawned.dbus_inspection);
    }

    // -- D-Bus message inspection: stepping lifetime -------------------------
    //
    // Inspection is only as good as the window in which writes are visible. A
    // bus channel that stops being stepped is not "allowed", it is *invisible*
    // — the method calls on it stop reaching any decision at all. These tests
    // pin the window against the events that could close it early.

    /// A D-Bus channel's window closes on the *connection*, not on a write
    /// decision. Sharing `ConnectedDgramStepping::fds` with the datagram path
    /// would let `settle_stepping_decision` retire a bus channel the moment its
    /// first `Hello` was allowed — after which `StartTransientUnit` on the same
    /// connection would never be seen.
    #[test]
    fn allowing_a_dbus_write_does_not_end_stepping() {
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        sup.tid_tgids.insert(70, 70);
        sup.dbus_channels
            .register(70, 5, "unix:/run/user/1000/bus".into());
        sup.promote_dbus_stepping(70, 5, "unix:/run/user/1000/bus");
        assert!(sup.tid_is_stepping(70));

        // An allowed write settles the datagram decision for this tid...
        sup.settle_stepping_decision(70, true);

        assert!(
            sup.tid_is_stepping(70),
            "the bus channel must stay stepped so the NEXT method call is judged"
        );
    }

    /// The mirror for the datagram path: a process holding both kinds keeps
    /// being stepped after its datagram fd retires, and only stops when both
    /// are gone. Getting this wrong would silently un-cover one or the other.
    #[test]
    fn stepping_ends_only_when_both_kinds_are_gone() {
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        sup.tid_tgids.insert(71, 71);
        sup.promote_stepping(71, 3, addr("1.2.3.4:9999"));
        sup.dbus_channels
            .register(71, 5, "unix:/run/user/1000/bus".into());
        sup.promote_dbus_stepping(71, 5, "unix:/run/user/1000/bus");

        sup.demote_stepping_fd(71, 3, "datagram write allowed");
        assert!(
            sup.tid_is_stepping(71),
            "the surviving bus channel must keep the process stepped"
        );

        sup.demote_dbus_stepping(71, 5, "bus fd closed");
        assert!(
            !sup.tid_is_stepping(71),
            "with neither kind left the process returns to PTRACE_CONT"
        );
    }

    /// A bus fd that survives `execve` (non-CLOEXEC) must stay *visible*. The
    /// new image inherits a socket mid-stream that cannot be framed, so the
    /// channel is poisoned rather than trusted — but forgetting it entirely
    /// would make its writes invisible, which is the worse failure.
    #[test]
    fn dbus_channel_surviving_exec_is_poisoned_and_still_stepped() {
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        sup.tid_tgids.insert(72, 72);
        sup.dbus_channels
            .register(72, 5, "unix:/run/user/1000/bus".into());
        sup.dbus_channels
            .register(72, 6, "unix:/run/user/1000/bus".into());
        sup.promote_dbus_stepping(72, 5, "unix:/run/user/1000/bus");
        sup.promote_dbus_stepping(72, 6, "unix:/run/user/1000/bus");

        // fd 5 survived exec; fd 6 was FD_CLOEXEC.
        let live: std::collections::HashSet<i32> = [5].into_iter().collect();
        sup.demote_stepping_tgid(72, "exec");
        for fd in sup.dbus_channels.retain_and_poison(72, &live) {
            sup.promote_dbus_stepping(72, fd, "survived exec");
        }

        assert!(sup.dbus_channels.is_tracked(72, 5));
        assert!(
            sup.dbus_channels.is_poisoned(72, 5),
            "an inherited mid-stream connection cannot be framed"
        );
        assert!(
            !sup.dbus_channels.is_tracked(72, 6),
            "a CLOEXEC'd bus fd is gone, not poisoned"
        );
        assert!(
            sup.tid_is_stepping(72),
            "the survivor must stay stepped so its writes still escalate"
        );
    }

    /// A fork child shares the parent's open file description, so both sides'
    /// writes interleave on the wire. Neither decoder can be trusted, but the
    /// child's writes must still be seen — poisoned and stepped, not dropped.
    #[test]
    fn forked_dbus_channel_is_inherited_poisoned_and_stepped() {
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        sup.tid_tgids.insert(73, 73);
        sup.tid_tgids.insert(74, 74);
        sup.dbus_channels
            .register(73, 5, "unix:/run/user/1000/bus".into());
        sup.promote_dbus_stepping(73, 5, "unix:/run/user/1000/bus");

        for fd in sup.dbus_channels.inherit_process(73, 74) {
            sup.promote_dbus_stepping(74, fd, "inherited across fork");
        }

        assert!(sup.dbus_channels.is_poisoned(74, 5));
        assert!(sup.tid_is_stepping(74), "the child must be stepped too");
        assert!(
            !sup.dbus_channels.is_poisoned(73, 5),
            "the parent's own channel is untouched by the copy"
        );
    }

    // -- B13: connected-datagram write stepping -----------------------------
    //
    // `socket(AF_INET, SOCK_DGRAM) → connect(attacker) → write(fd, secret)`
    // egressed with no proxy evaluation and no audit record: write/read are
    // outside the seccomp trap set, and a connected datagram `connect` is
    // deliberately unscored so `getaddrinfo`'s source-selection probe does not
    // prompt. These tests pin the state machine that closes it.

    fn addr(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_destinations_never_step() {
        // The volume carve-out: DNS to 127.0.0.53 and local services are the
        // bulk of connected-datagram traffic. Stepping them would pay two
        // ptrace stops per syscall for no security benefit.
        for local in [
            "127.0.0.1:53",
            "127.0.0.53:53",
            "[::1]:8080",
            "0.0.0.0:0",
            "[::ffff:127.0.0.1]:53",
        ] {
            assert!(
                PtraceSupervisor::is_loopback_destination(&addr(local)),
                "{local} must be treated as loopback"
            );
        }
        for remote in ["8.8.8.8:53", "[2001:4860:4860::8888]:53", "1.2.3.4:9999"] {
            assert!(
                !PtraceSupervisor::is_loopback_destination(&addr(remote)),
                "{remote} must be treated as egress"
            );
        }
    }

    #[test]
    fn promote_then_demote_restores_normal_resume() {
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        sup.tid_tgids.insert(42, 42);
        assert!(!sup.tid_is_stepping(42));

        sup.promote_stepping(42, 7, addr("1.2.3.4:9999"));
        assert!(sup.tid_is_stepping(42));

        sup.demote_stepping_fd(42, 7, "test");
        assert!(
            !sup.tid_is_stepping(42),
            "with no tracked fds left the process goes back to PTRACE_CONT"
        );
    }

    /// B13 (exec-survival residual): a connected off-host datagram socket that
    /// survives an `execve` (non-CLOEXEC, still in the tracker after the caller's
    /// `retain_fds` prune) must KEEP being stepped, so a `write(2)` on it in the
    /// new image is still trapped and scored. A blanket demote here was the hole.
    #[test]
    fn connected_dgram_stepping_survives_exec() {
        use crate::platform::linux::dns_socket_tracker::SocketType;
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        sup.tid_tgids.insert(50, 50);
        // A connected off-host datagram socket, stepped (the pre-exec state).
        sup.dns_tracker.observe_socket(50, 3, SocketType::Datagram);
        sup.dns_tracker.connect(50, 3, addr("1.2.3.4:1234"));
        sup.promote_stepping(50, 3, addr("1.2.3.4:1234"));
        assert!(sup.tid_is_stepping(50));
        assert!(sup.connected_dgram_egress_target(50, 3).is_some());

        // Exec: the tracker still holds the survivor (retain_fds kept it).
        sup.resync_stepping_after_exec(50);

        assert!(
            sup.tid_is_stepping(50),
            "a connected off-host datagram socket that survived exec must stay stepped (B13)"
        );
    }

    /// The mirror: an fd with no surviving connected off-host datagram socket
    /// (CLOEXEC'd, closed, or reconnected to loopback — pruned from the tracker
    /// before resync) is demoted across exec, restoring PTRACE_CONT.
    #[test]
    fn stepping_dropped_after_exec_when_socket_gone() {
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        sup.tid_tgids.insert(60, 60);
        // Stepped, but the tracker has no connected datagram socket for the fd.
        sup.promote_stepping(60, 7, addr("1.2.3.4:1234"));
        assert!(sup.tid_is_stepping(60));
        assert!(sup.connected_dgram_egress_target(60, 7).is_none());

        sup.resync_stepping_after_exec(60);

        assert!(
            !sup.tid_is_stepping(60),
            "an fd with no surviving connected datagram socket must be demoted across exec"
        );
    }

    /// Mixed survival: one connected socket survives, one does not — the survivor
    /// keeps the process stepped, the other is dropped.
    #[test]
    fn exec_keeps_survivor_and_drops_gone_socket() {
        use crate::platform::linux::dns_socket_tracker::SocketType;
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        sup.tid_tgids.insert(70, 70);
        sup.dns_tracker.observe_socket(70, 3, SocketType::Datagram);
        sup.dns_tracker.connect(70, 3, addr("1.2.3.4:1234"));
        sup.promote_stepping(70, 3, addr("1.2.3.4:1234")); // survives
        sup.promote_stepping(70, 9, addr("5.6.7.8:1234")); // no tracker entry → gone

        sup.resync_stepping_after_exec(70);

        assert!(
            sup.tid_is_stepping(70),
            "the survivor keeps the process stepped"
        );
        assert!(sup.connected_dgram_egress_target(70, 3).is_some());
    }

    /// B13 (the residual the verify workflow found): a dup'd non-CLOEXEC alias
    /// survives exec even when the fd the connect happened on was CLOEXEC. The
    /// alias is a distinct fd number NOT in state.fds, so keying re-arm on
    /// surviving tracker socket identity (not state.fds) is essential — else
    /// write(alias, secret) egresses unobserved after exec.
    #[test]
    fn dup_alias_keeps_stepping_across_exec() {
        use crate::platform::linux::dns_socket_tracker::SocketType;
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        sup.tid_tgids.insert(80, 80);
        sup.dns_tracker.observe_socket(80, 3, SocketType::Datagram);
        sup.dns_tracker.connect(80, 3, addr("1.2.3.4:1234"));
        sup.promote_stepping(80, 3, addr("1.2.3.4:1234"));
        // dup3(3, 4) — the alias shares socket identity but is not in state.fds.
        let sid = sup.dns_tracker.socket_id(80, 3).unwrap();
        sup.dns_tracker.duplicate_socket(80, sid, 4);
        // exec closes the CLOEXEC fd 3; the non-CLOEXEC alias 4 survives (the
        // tracker was pruned to live fds before resync).
        sup.dns_tracker.close(80, 3);

        sup.resync_stepping_after_exec(80);

        assert!(
            sup.tid_is_stepping(80),
            "the surviving dup alias must keep the process stepped across exec (B13)"
        );
        assert!(sup.connected_dgram_egress_target(80, 4).is_some());
        assert!(sup.connected_dgram_egress_target(80, 3).is_none());
    }

    /// The no-exec sibling the verify workflow also flagged: close the tracked
    /// fd, keep the alias — stepping must be retained on the surviving alias, no
    /// execve involved. Exercises the close-path re-arm.
    #[test]
    fn dup_alias_keeps_stepping_after_closing_tracked_fd() {
        use crate::platform::linux::dns_socket_tracker::SocketType;
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        sup.tid_tgids.insert(90, 90);
        sup.dns_tracker.observe_socket(90, 3, SocketType::Datagram);
        sup.dns_tracker.connect(90, 3, addr("5.6.7.8:1234"));
        sup.promote_stepping(90, 3, addr("5.6.7.8:1234"));
        let sid = sup.dns_tracker.socket_id(90, 3).unwrap();
        sup.dns_tracker.duplicate_socket(90, sid, 4);

        // Simulate the tracked-fd close path: tracker drops fd 3, then the event
        // handler demotes fd 3 and re-arms survivors.
        sup.dns_tracker.close(90, 3);
        sup.demote_stepping_fd(90, 3, "tracked fd closed");
        sup.rearm_surviving_connected_dgram_fds(90);

        assert!(
            sup.tid_is_stepping(90),
            "closing the tracked fd must not stop stepping while a connected alias survives (B13)"
        );
        assert!(sup.connected_dgram_egress_target(90, 4).is_some());
    }

    /// Stepping is keyed by process, not thread: the fd table is shared
    /// across a thread group, so a sibling that never issued the connect can
    /// still write the socket and must be stepped too.
    #[test]
    fn siblings_of_a_connecting_thread_are_stepped() {
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        sup.tid_tgids.insert(100, 100); // leader, does the connect
        sup.tid_tgids.insert(101, 100); // sibling
        sup.tid_tgids.insert(200, 200); // unrelated process

        sup.promote_stepping(100, 5, addr("1.2.3.4:9999"));

        assert!(sup.tid_is_stepping(100));
        assert!(
            sup.tid_is_stepping(101),
            "a sibling shares the fd table and must be stepped"
        );
        assert!(!sup.tid_is_stepping(200), "unrelated process untouched");
    }

    /// A process may hold several connected sockets. Forgetting one must not
    /// un-cover the others.
    #[test]
    fn multiple_connected_sockets_are_tracked_independently() {
        let mut sup = PtraceSupervisor::new();
        sup.tid_tgids.insert(9, 9);
        sup.promote_stepping(9, 3, addr("1.2.3.4:9999"));
        sup.promote_stepping(9, 4, addr("5.6.7.8:9999"));

        sup.demote_stepping_fd(9, 3, "test");
        assert!(
            sup.tid_is_stepping(9),
            "the second socket must keep the process stepped"
        );

        sup.demote_stepping_fd(9, 4, "test");
        assert!(!sup.tid_is_stepping(9));
    }

    /// The critical one: a DENIED write must keep its fd tracked, and must
    /// clear the awaiting entry — otherwise the next unrelated allowed
    /// syscall on that thread is mistaken for the decision and stepping ends
    /// silently, letting every later write to the rejected destination
    /// through unobserved.
    #[test]
    fn a_denied_write_keeps_stepping_and_clears_the_awaiting_entry() {
        let mut sup = PtraceSupervisor::new();
        sup.tid_tgids.insert(11, 11);
        sup.promote_stepping(11, 6, addr("203.0.113.5:4444"));
        sup.stepping.get_mut(&11).unwrap().awaiting.insert(11, 6);

        sup.settle_stepping_decision(11, false);
        assert!(
            sup.tid_is_stepping(11),
            "a rejected destination must stay covered — the thread will retry"
        );
        assert!(
            sup.stepping[&11].awaiting.is_empty(),
            "the awaiting entry must be cleared, or the next allow ends stepping"
        );

        // The next unrelated allowed syscall must NOT end stepping.
        sup.settle_stepping_decision(11, true);
        assert!(
            sup.tid_is_stepping(11),
            "an unrelated allow must not be mistaken for the write decision"
        );
    }

    #[test]
    fn an_allowed_write_ends_stepping_for_that_fd() {
        let mut sup = PtraceSupervisor::new();
        sup.tid_tgids.insert(12, 12);
        sup.promote_stepping(12, 8, addr("203.0.113.6:4444"));
        sup.stepping.get_mut(&12).unwrap().awaiting.insert(12, 8);

        sup.settle_stepping_decision(12, true);
        assert!(
            !sup.tid_is_stepping(12),
            "an allowed destination is decided for the session; stop stepping"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn writev_is_a_known_syscall_number() {
        // The gathered-write form is the obvious way around a write-only
        // check, so it must be recognised alongside write.
        assert_eq!(syscall_nr::WRITE, 1);
        assert_eq!(syscall_nr::WRITEV, 20);
    }

    /// write/writev must stay OUT of the seccomp trap set. Trapping them
    /// globally would stop on the hottest syscalls in any workload; the whole
    /// design rests on them being surfaced only for stepped threads.
    #[test]
    fn write_family_is_not_globally_trapped() {
        assert!(!crate::platform::linux::is_security_relevant(
            syscall_nr::WRITE
        ));
        assert!(!crate::platform::linux::is_security_relevant(
            syscall_nr::WRITEV
        ));
    }

    // -- Wedge forensics: signal-mask parsing -------------------------------

    #[test]
    fn extract_status_hex_parses_signal_masks() {
        let status = "Name:\tcargo\nState:\tt (tracing stop)\n\
                      SigPnd:\t0000000000040000\nShdPnd:\t0000000000000000\n\
                      SigBlk:\t0000000000000001\n";
        // SIGSTOP (signal 19) sets bit 18 = 0x40000.
        assert_eq!(extract_status_hex(status, "SigPnd"), 0x40000);
        assert_eq!(extract_status_hex(status, "ShdPnd"), 0);
        assert_eq!(extract_status_hex(status, "SigBlk"), 0x1);
        assert_eq!(extract_status_hex(status, "SigCgt"), 0); // absent → 0
                                                             // The job-control-stop mask (bits 18..=21) catches the pending SIGSTOP.
        const JOBCTL_STOP_MASK: u64 = 0x003C_0000;
        assert!(extract_status_hex(status, "SigPnd") & JOBCTL_STOP_MASK != 0);
    }

    // -- H1 fix: clone-child resume primitive in a seccomp session ----------

    #[test]
    fn seccomp_session_resumes_unregistered_tid_with_cont() {
        // The confirmed wedge: a clone child whose own stop is handled before
        // its parent's CLONE event is NOT yet in seccomp_tracees, so the old
        // membership-gated resume picked PTRACE_SYSCALL. In a seccomp session
        // it must get PTRACE_CONT regardless of set membership. resume_tracee
        // records the primitive BEFORE the ptrace syscall, so we can assert it
        // even though the bogus pid makes the actual resume error out.
        let mut sup = PtraceSupervisor::new();
        sup.seccomp_session = true;
        let tid = 2_147_400_001u32; // non-existent pid (ptrace errors; ignored)
        let _ = sup.resume_tracee(Pid::from_raw(tid as i32), None);
        assert_eq!(
            sup.last_resume_primitive.get(&tid),
            Some(&"CONT"),
            "seccomp session must resume an unregistered tid with PTRACE_CONT",
        );

        // Attach-without-seccomp session keeps the PTRACE_SYSCALL fallback.
        let mut attach = PtraceSupervisor::new(); // seccomp_session = false
        let tid2 = 2_147_400_002u32;
        let _ = attach.resume_tracee(Pid::from_raw(tid2 as i32), None);
        assert_eq!(
            attach.last_resume_primitive.get(&tid2),
            Some(&"SYSCALL"),
            "attach session keeps PTRACE_SYSCALL for non-seccomp tids",
        );
    }

    // -- Construction and defaults ------------------------------------------

    #[test]
    fn new_supervisor_has_no_supervised_pids() {
        let sup = PtraceSupervisor::new();
        assert!(sup.supervised.is_empty());
        assert!(sup.in_syscall_entry.is_empty());
        assert!(sup.thread_tids.is_empty());
    }

    /// Resuming a tracee that has already died (ESRCH) must NOT be fatal — it is
    /// a benign ptrace race (the tracee was group-killed / exited between its
    /// stop and our resume). Regression test for the supervisor loop aborting
    /// with "PTRACE_CONT failed ... ESRCH". A never-allocated PID yields ESRCH
    /// from the kernel without needing to trace anything.
    #[test]
    fn resume_of_a_dead_tracee_is_not_fatal() {
        let sup = PtraceSupervisor::new();
        // Well above /proc/sys/kernel/pid_max — guaranteed not to exist.
        let dead = Pid::from_raw(0x3fff_ffff);
        assert!(
            sup.resume_continue(dead, None).is_ok(),
            "PTRACE_CONT on a dead tracee must be tolerated, not fatal"
        );
        assert!(
            sup.resume_to_next_syscall(dead, None).is_ok(),
            "PTRACE_SYSCALL on a dead tracee must be tolerated, not fatal"
        );
    }

    /// The register-read twin of `resume_of_a_dead_tracee_is_not_fatal`: a
    /// tracee killed (sibling `exit_group` / SIGKILL) while sitting in a
    /// ptrace stop yields ESRCH from the register read, which must read as
    /// "tracee gone" (`Ok(None)`), not a fatal interception error. Regression
    /// test for the supervisor loop aborting with "PTRACE_GETREGS failed ...
    /// ESRCH".
    #[test]
    fn getregs_of_a_dead_tracee_is_not_fatal() {
        let dead = Pid::from_raw(0x3fff_ffff);
        match crate::platform::linux::arch::read_syscall_regs(dead) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("a never-allocated PID cannot have readable registers"),
            Err(e) => panic!("a register read on a dead tracee must be tolerated, got: {e}"),
        }
        match crate::platform::linux::arch::read_return_value(dead) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("a never-allocated PID cannot have a readable return value"),
            Err(e) => panic!("a return-value read on a dead tracee must be tolerated, got: {e}"),
        }
    }

    /// Denying a syscall of a tracee that died in its stop must succeed
    /// vacuously: the thread is gone, so the syscall can never execute.
    /// This is the path the fail-closed classify-error handler takes — if it
    /// errored, a benign thread death would tear down the whole session.
    #[tokio::test]
    async fn deny_of_a_dead_tracee_is_not_fatal() {
        let mut sup = PtraceSupervisor::new();
        assert!(
            sup.deny(0x3fff_ffff).await.is_ok(),
            "deny on a dead tracee must be tolerated, not fatal"
        );
    }

    #[test]
    fn default_is_same_as_new() {
        let a = PtraceSupervisor::new();
        let b = PtraceSupervisor::default();
        assert_eq!(a.supervised.len(), b.supervised.len());
        assert_eq!(a.in_syscall_entry.len(), b.in_syscall_entry.len());
        assert_eq!(a.thread_tids.len(), b.thread_tids.len());
    }

    #[test]
    fn mechanism_name_is_ptrace() {
        let sup = PtraceSupervisor::new();
        assert_eq!(sup.mechanism_name(), "ptrace");
    }

    #[test]
    fn is_available_does_not_panic() {
        let _ = PtraceSupervisor::is_available();
    }

    #[test]
    fn supervised_pids_returns_empty_vec() {
        let sup = PtraceSupervisor::new();
        assert!(sup.supervised_pids().is_empty());
    }

    #[test]
    fn fallback_mode_treats_read_write_as_relevant() {
        assert!(is_fallback_relevant_syscall(syscall_nr::READ, false));
        assert!(is_fallback_relevant_syscall(syscall_nr::WRITE, false));
    }

    #[test]
    fn seccomp_mode_keeps_read_write_irrelevant() {
        assert!(!is_fallback_relevant_syscall(syscall_nr::READ, true));
        assert!(!is_fallback_relevant_syscall(syscall_nr::WRITE, true));
        assert!(is_fallback_relevant_syscall(syscall_nr::OPENAT, true));
    }

    #[test]
    fn proxy_send_allows_only_sendto_with_register_level_null_peer() {
        let mut regs = crate::platform::linux::arch::SyscallRegs::default();
        assert!(PtraceSupervisor::proxy_send_uses_supported_connected_form(
            syscall_nr::SENDTO,
            &regs,
        ));

        regs.args[4] = 1;
        assert!(!PtraceSupervisor::proxy_send_uses_supported_connected_form(
            syscall_nr::SENDTO,
            &regs,
        ));
        regs.args[4] = 0;
        assert!(!PtraceSupervisor::proxy_send_uses_supported_connected_form(
            syscall_nr::SENDMSG,
            &regs,
        ));
        assert!(!PtraceSupervisor::proxy_send_uses_supported_connected_form(
            syscall_nr::SENDMMSG,
            &regs,
        ));
    }

    #[test]
    fn clone_identity_uses_tgid_and_rejects_private_thread_fd_table() {
        let shared_flags = libc::CLONE_THREAD as u64 | libc::CLONE_FILES as u64;
        let private_flags = libc::CLONE_THREAD as u64;

        assert!(is_thread_group_child(10, 10));
        assert!(!is_thread_group_child(10, 20));
        assert!(!clone_creates_private_thread_fd_table(
            10,
            10,
            Some(shared_flags),
        ));
        assert!(clone_creates_private_thread_fd_table(
            10,
            10,
            Some(private_flags),
        ));
        assert!(clone_creates_private_thread_fd_table(10, 10, None));
        assert!(!clone_creates_private_thread_fd_table(
            10,
            20,
            Some(private_flags),
        ));
    }

    #[test]
    fn detach_gate_activates_only_after_proxy_route_ownership() {
        use crate::platform::linux::dns_socket_tracker::{DnsRouteId, SocketType};

        let mut sup = PtraceSupervisor::new();
        assert!(!sup.proxy_route_requires_session_termination_on_detach());

        sup.dns_tracker.observe_socket(10, 4, SocketType::Datagram);
        sup.dns_tracker
            .set_connected_proxy(
                10,
                4,
                DnsRouteId(41),
                "127.0.0.53:53".parse().unwrap(),
                "127.0.0.1:40000".parse().unwrap(),
            )
            .unwrap();
        assert!(sup.proxy_route_requires_session_termination_on_detach());
    }

    // -- SyscallEvent construction ------------------------------------------

    #[test]
    fn syscall_event_can_be_constructed() {
        let event = SyscallEvent {
            pid: 1234,
            tid: 1234,
            timestamp: Utc::now(),
            kind: SyscallKind::FileOpen {
                path: "/etc/hosts".into(),
                flags: OpenFlags::ReadOnly,
            },
            raw_syscall_nr: syscall_nr::OPENAT,
        };
        assert_eq!(event.pid, 1234);
        assert_eq!(event.raw_syscall_nr, syscall_nr::OPENAT);
    }

    #[test]
    fn syscall_event_with_process_exec() {
        let event = SyscallEvent {
            pid: 5678,
            tid: 5678,
            timestamp: Utc::now(),
            kind: SyscallKind::ProcessExec {
                path: "/usr/bin/curl".into(),
                args: vec!["curl".into(), "-s".into(), "https://example.com".into()],
            },
            raw_syscall_nr: syscall_nr::EXECVE,
        };
        if let SyscallKind::ProcessExec { path, args } = &event.kind {
            assert_eq!(path, "/usr/bin/curl");
            assert_eq!(args.len(), 3);
        } else {
            panic!("expected ProcessExec variant");
        }
    }

    #[test]
    fn syscall_event_with_net_connect() {
        let event = SyscallEvent {
            pid: 9000,
            tid: 9000,
            timestamp: Utc::now(),
            kind: SyscallKind::NetConnect {
                address: "93.184.216.34".into(),
                port: 443,
                protocol: NetProtocol::Tcp,
            },
            raw_syscall_nr: syscall_nr::CONNECT,
        };
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
            panic!("expected NetConnect variant");
        }
    }

    #[test]
    fn syscall_event_with_pipe_and_socketpair() {
        let pipe = SyscallEvent {
            pid: 100,
            tid: 100,
            timestamp: Utc::now(),
            kind: SyscallKind::PipeCreate,
            raw_syscall_nr: syscall_nr::PIPE2,
        };
        assert_eq!(pipe.kind, SyscallKind::PipeCreate);

        let pair = SyscallEvent {
            pid: 200,
            tid: 200,
            timestamp: Utc::now(),
            kind: SyscallKind::SocketPair,
            raw_syscall_nr: syscall_nr::SOCKETPAIR,
        };
        assert_eq!(pair.kind, SyscallKind::SocketPair);
    }

    // -- Foreign-ABI classification (B1 round 3) ----------------------------

    #[cfg(target_arch = "x86_64")]
    use crate::interceptor::ForeignAbiKind;

    /// AUDIT_ARCH_I386 — any value other than the native arch exercises the
    /// arm. Only consumed by the x86-gated foreign-ABI tests.
    #[cfg(target_arch = "x86_64")]
    const ARCH_I386: u32 = 0x4000_0003;
    const ARCH_X86_64: u32 = crate::platform::linux::arch::NATIVE_AUDIT_ARCH;

    /// x32 futex: the ordinary number (202 = 0xca) with the x32 marker bit.
    #[cfg(target_arch = "x86_64")]
    fn x32_nr() -> u64 {
        u64::from(super::super::seccomp::X32_SYSCALL_BIT) | 0xca
    }

    fn stale_event_data_must_not_be_read() -> u64 {
        panic!("PTRACE_GETEVENTMSG must not be consulted at this stop");
    }

    fn registers_must_not_be_read() -> Option<u64> {
        panic!("registers must not be consulted at this stop");
    }

    /// The regression test for the B1 round-3 crash. A stop with no
    /// syscall-entry record (e.g. a syscall exit misjudged as an entry by a
    /// desynced toggle) arrived while the thread's `PTRACE_GETEVENTMSG`
    /// still held a stale, marker-shaped message. The stale value must never
    /// be consulted: the resulting spurious X32 hard-deny injected EPERM
    /// into a real `futex(2)` and glibc aborted the whole supervised tree.
    #[test]
    fn no_entry_record_never_consults_stale_event_data() {
        for at_seccomp_stop in [false, true] {
            assert_eq!(
                PtraceSupervisor::classify_foreign_abi(
                    SyscallEntryInfo::NotEntry,
                    at_seccomp_stop,
                    stale_event_data_must_not_be_read,
                    registers_must_not_be_read,
                ),
                None,
                "a stop without an entry record must never classify as foreign"
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn entry_record_detects_foreign_arch_and_x32() {
        assert_eq!(
            PtraceSupervisor::classify_foreign_abi(
                SyscallEntryInfo::Entry {
                    arch: ARCH_I386,
                    nr: 5,
                },
                true,
                stale_event_data_must_not_be_read,
                registers_must_not_be_read,
            ),
            Some(ForeignAbiKind::CompatArch),
        );
        assert_eq!(
            PtraceSupervisor::classify_foreign_abi(
                SyscallEntryInfo::Entry {
                    arch: ARCH_X86_64,
                    nr: x32_nr(),
                },
                false,
                stale_event_data_must_not_be_read,
                registers_must_not_be_read,
            ),
            Some(ForeignAbiKind::X32),
        );
    }

    #[test]
    fn entry_record_ordinary_x86_64_is_not_foreign() {
        // read, write, rt_sigprocmask, futex, openat — the syscalls the
        // stale-marker bug actually condemned in production.
        for nr in [0u64, 1, 14, 202, 257] {
            assert_eq!(
                PtraceSupervisor::classify_foreign_abi(
                    SyscallEntryInfo::Entry {
                        arch: ARCH_X86_64,
                        nr,
                    },
                    false,
                    stale_event_data_must_not_be_read,
                    registers_must_not_be_read,
                ),
                None,
                "ordinary x86_64 syscall {nr} must not classify as foreign"
            );
        }
    }

    /// Pre-5.3 + seccomp stop is the ONE place the filter marker is current.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn pre53_seccomp_stop_uses_the_filter_marker() {
        let cases = [
            (
                u64::from(super::super::seccomp::SECCOMP_TRACE_DATA_X32),
                Some(ForeignAbiKind::X32),
            ),
            (
                u64::from(super::super::seccomp::SECCOMP_TRACE_DATA_FOREIGN_ARCH),
                Some(ForeignAbiKind::CompatArch),
            ),
            (0, None),
            // A stale message shaped like an event payload (a child tid, an
            // exit status) matches no marker.
            (762_589, None),
        ];
        for (data, expected) in cases {
            assert_eq!(
                PtraceSupervisor::classify_foreign_abi(
                    SyscallEntryInfo::Unsupported,
                    true,
                    move || data,
                    registers_must_not_be_read,
                ),
                expected,
            );
        }
    }

    /// Pre-5.3 at a plain syscall stop: only the number register speaks —
    /// the event message is stale there and must not be touched.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn pre53_syscall_stop_classifies_from_the_number_alone() {
        let cases = [
            // A real x32 number carries bit 30 in orig_rax itself.
            (Some(x32_nr()), Some(ForeignAbiKind::X32)),
            (Some(202), None),
            // -1 feature probes (and our own deny() marker) have every high
            // bit set: not a syscall number, kernel answers ENOSYS.
            (Some(u64::MAX), None),
            // Tracee died in the stop.
            (None, None),
        ];
        for (nr, expected) in cases {
            assert_eq!(
                PtraceSupervisor::classify_foreign_abi(
                    SyscallEntryInfo::Unsupported,
                    false,
                    stale_event_data_must_not_be_read,
                    move || nr,
                ),
                expected,
                "pre-5.3 syscall-stop classification of {nr:?}"
            );
        }
    }
}
