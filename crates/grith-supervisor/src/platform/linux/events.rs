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
use tracing::{debug, error, info, trace, warn};

use crate::error::{Error, Result};
use crate::interceptor::{SyscallEvent, SyscallInterceptor};

use super::{is_security_relevant, PtraceSupervisor};

/// Decide whether a syscall should be classified in the fallback
/// `PTRACE_SYSCALL` path.
///
/// Spawned processes use seccomp-BPF and do not rely on this path.
/// Attached processes do use this path and must continue to classify
/// `read(2)`/`write(2)` to preserve prior attach-mode visibility.
fn is_fallback_relevant_syscall(nr: i64, use_seccomp: bool) -> bool {
    is_security_relevant(nr)
        || (!use_seccomp && (nr == super::syscall_nr::READ || nr == super::syscall_nr::WRITE))
}

// ---------------------------------------------------------------------------
// Internal ptrace helpers
// ---------------------------------------------------------------------------

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
        use nix::sys::ptrace::Options;

        let opts = Options::PTRACE_O_TRACESYSGOOD
            | Options::PTRACE_O_TRACEEXEC
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACESECCOMP
            | Options::PTRACE_O_EXITKILL;

        ptrace::setoptions(pid, opts).map_err(|e| {
            Error::InterceptionError(format!("PTRACE_SETOPTIONS failed for pid {pid}: {e}"))
        })
    }

    /// Resume the tracee and ask the kernel to stop it again at the next
    /// syscall entry or exit boundary.
    pub(super) fn resume_to_next_syscall(&self, pid: Pid, signal: Option<Signal>) -> Result<()> {
        ptrace::syscall(pid, signal).map_err(|e| {
            Error::InterceptionError(format!("PTRACE_SYSCALL failed for pid {pid}: {e}"))
        })
    }

    /// Resume the tracee with `PTRACE_CONT`. Used with seccomp-BPF
    /// pre-filtering: the seccomp filter handles syscall selection, so we
    /// only need `PTRACE_CONT` instead of `PTRACE_SYSCALL`.
    pub(super) fn resume_continue(&self, pid: Pid, signal: Option<Signal>) -> Result<()> {
        ptrace::cont(pid, signal)
            .map_err(|e| Error::InterceptionError(format!("PTRACE_CONT failed for pid {pid}: {e}")))
    }

    /// Resume the tracee using the appropriate method based on whether
    /// seccomp-BPF is active.
    pub(super) fn resume_tracee(&self, pid: Pid, signal: Option<Signal>) -> Result<()> {
        if self.seccomp_tracees.contains(&(pid.as_raw() as u32)) {
            self.resume_continue(pid, signal)
        } else {
            self.resume_to_next_syscall(pid, signal)
        }
    }

    /// Read the x86_64 general-purpose register file from a stopped tracee.
    pub(super) fn read_registers(&self, pid: Pid) -> Result<libc::user_regs_struct> {
        ptrace::getregs(pid).map_err(|e| {
            Error::InterceptionError(format!("PTRACE_GETREGS failed for pid {pid}: {e}"))
        })
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

    /// Write arbitrary bytes to a tracee's address space using PTRACE_POKEDATA.
    ///
    /// Writes one `i64` (8 bytes) at a time. For partial writes (< 8 bytes),
    /// reads the existing word first and merges the new bytes to avoid
    /// corrupting adjacent memory.
    pub(super) fn write_tracee_data(&self, pid: Pid, addr: u64, data: &[u8]) -> Result<()> {
        let word_size = std::mem::size_of::<i64>();
        let mut offset = 0usize;

        while offset < data.len() {
            let remaining = data.len() - offset;
            let current_addr = addr + offset as u64;

            let word: i64 = if remaining >= word_size {
                // Full word write
                i64::from_ne_bytes(data[offset..offset + word_size].try_into().unwrap())
            } else {
                // Partial word: read existing, overlay new bytes
                let existing =
                    ptrace::read(pid, current_addr as *mut libc::c_void).map_err(|e| {
                        Error::InterceptionError(format!(
                            "PTRACE_PEEKDATA at {current_addr:#x} for pid {pid}: {e}"
                        ))
                    })?;
                let mut buf = existing.to_ne_bytes();
                buf[..remaining].copy_from_slice(&data[offset..]);
                i64::from_ne_bytes(buf)
            };

            ptrace::write(pid, current_addr as *mut libc::c_void, word as libc::c_long).map_err(
                |e| {
                    Error::InterceptionError(format!(
                        "PTRACE_POKEDATA at {current_addr:#x} for pid {pid}: {e}"
                    ))
                },
            )?;

            offset += word_size;
        }

        Ok(())
    }

    /// Handle a ptrace process-creation event (fork/vfork/clone) by
    /// extracting the new child PID and registering it for supervision.
    ///
    /// The `event` parameter distinguishes forks (PTRACE_EVENT_FORK=1,
    /// PTRACE_EVENT_VFORK=2) from thread clones (PTRACE_EVENT_CLONE=3).
    /// Thread clones are tracked in `supervised` (they need ptrace
    /// management) but are also recorded in `thread_tids` so that callers
    /// can distinguish threads from processes.
    pub(super) fn handle_ptrace_event(&mut self, pid: Pid, event: i32) -> Result<Option<u32>> {
        let child_pid = ptrace::getevent(pid).map_err(|e| {
            Error::InterceptionError(format!("PTRACE_GETEVENTMSG failed for pid {pid}: {e}"))
        })? as u32;

        // PTRACE_EVENT_CLONE (3) typically indicates a new thread rather
        // than a new process. We still must trace it (it gets ptrace stops)
        // but record it separately so it is not confused with a full child
        // process in process-tree tracking.
        let is_thread_clone = event == libc::PTRACE_EVENT_CLONE;

        if is_thread_clone {
            debug!(
                parent = pid.as_raw(),
                thread_tid = child_pid,
                "new thread detected via PTRACE_EVENT_CLONE"
            );
            self.thread_tids.insert(child_pid);
        } else {
            info!(
                parent = pid.as_raw(),
                child = child_pid,
                "new child process detected via ptrace event"
            );
        }
        self.supervised.insert(child_pid);
        if self.seccomp_tracees.contains(&(pid.as_raw() as u32)) {
            self.seccomp_tracees.insert(child_pid);
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

        self.set_trace_options(nix_pid)?;
        self.supervised.insert(pid);
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
                    self.seccomp_tracees.clear();
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
                    if event == libc::PTRACE_EVENT_SECCOMP {
                        // Seccomp stop: a security-relevant syscall.
                        // The process is stopped *before* the syscall
                        // executes — no entry/exit toggle needed.
                        let pid_u32 = pid.as_raw() as u32;
                        let regs = self.read_registers(pid)?;
                        let nr = regs.orig_rax as i64;

                        match self.classify_syscall(pid, &regs) {
                            Ok(Some(kind)) => {
                                let tid = pid_u32;
                                let tgid = Self::resolve_tgid(tid).unwrap_or(tid);

                                let sockaddr_addr = match nr {
                                    super::syscall_nr::CONNECT => Some(regs.rsi),
                                    super::syscall_nr::SENDTO if regs.r8 != 0 => Some(regs.r8),
                                    _ => None,
                                };

                                trace!(
                                    pid = tgid,
                                    tid = tid,
                                    syscall_nr = nr,
                                    "intercepted security-relevant syscall (seccomp)"
                                );
                                return Ok(Some(SyscallEvent {
                                    pid: tgid,
                                    tid,
                                    timestamp: Utc::now(),
                                    kind,
                                    raw_syscall_nr: nr,
                                    sockaddr_addr,
                                }));
                            }
                            Ok(None) => {
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
                        let pid_u32 = pid.as_raw() as u32;
                        let tgid = Self::resolve_tgid(pid_u32).unwrap_or(pid_u32);
                        let (path, args) = Self::read_exec_info(pid_u32);
                        let kind = crate::interceptor::SyscallKind::ProcessExec { path, args };
                        trace!(
                            pid = tgid,
                            tid = pid_u32,
                            "intercepted exec via PTRACE_EVENT_EXEC"
                        );
                        return Ok(Some(SyscallEvent {
                            pid: tgid,
                            tid: pid_u32,
                            timestamp: Utc::now(),
                            kind,
                            raw_syscall_nr: super::syscall_nr::EXECVE,
                            sockaddr_addr: None,
                        }));
                    }

                    // Fork/vfork/clone event — track the new child.
                    if let Ok(Some(child_pid)) = self.handle_ptrace_event(pid, event) {
                        debug!(
                            parent = pid.as_raw(),
                            child = child_pid,
                            "auto-tracing new child"
                        );
                        // Emit a ProcessFork event with the actual child PID.
                        let pid_u32 = pid.as_raw() as u32;
                        let tgid = Self::resolve_tgid(pid_u32).unwrap_or(pid_u32);
                        let kind = crate::interceptor::SyscallKind::ProcessFork { child_pid };
                        return Ok(Some(SyscallEvent {
                            pid: tgid,
                            tid: pid_u32,
                            timestamp: Utc::now(),
                            kind,
                            raw_syscall_nr: super::syscall_nr::CLONE,
                            sockaddr_addr: None,
                        }));
                    }
                    self.resume_tracee(pid, None)?;
                    continue;
                }

                // -- Syscall stop (SIGTRAP | 0x80) --------------------------------
                // With seccomp active, this should not fire for normal
                // syscalls. Kept as a fallback for attached processes
                // (without seccomp) and edge cases.
                WaitStatus::PtraceSyscall(pid) => {
                    let pid_u32 = pid.as_raw() as u32;

                    if self.in_syscall_entry.contains(&pid_u32) {
                        self.in_syscall_entry.remove(&pid_u32);
                        self.resume_tracee(pid, None)?;
                        continue;
                    }
                    self.in_syscall_entry.insert(pid_u32);

                    let regs = self.read_registers(pid)?;
                    let nr = regs.orig_rax as i64;

                    let uses_seccomp = self.seccomp_tracees.contains(&pid_u32);
                    if !is_fallback_relevant_syscall(nr, uses_seccomp) {
                        self.resume_tracee(pid, None)?;
                        continue;
                    }

                    match self.classify_syscall(pid, &regs) {
                        Ok(Some(kind)) => {
                            let tid = pid_u32;
                            let tgid = Self::resolve_tgid(tid).unwrap_or(tid);

                            let sockaddr_addr = match nr {
                                super::syscall_nr::CONNECT => Some(regs.rsi),
                                super::syscall_nr::SENDTO if regs.r8 != 0 => Some(regs.r8),
                                _ => None,
                            };

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
                                sockaddr_addr,
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
                    let forward = if sig == Signal::SIGSTOP || sig == Signal::SIGTRAP {
                        None
                    } else {
                        Some(sig)
                    };
                    self.resume_tracee(pid, forward)?;
                    continue;
                }

                // -- Process exited normally --------------------------------------
                WaitStatus::Exited(pid, code) => {
                    let pid_u32 = pid.as_raw() as u32;
                    self.supervised.remove(&pid_u32);
                    self.in_syscall_entry.remove(&pid_u32);
                    self.thread_tids.remove(&pid_u32);
                    self.seccomp_tracees.remove(&pid_u32);
                    info!(pid = pid_u32, exit_code = code, "supervised process exited");

                    if self.supervised.is_empty() || self.root_pid == Some(pid_u32) {
                        if !self.supervised.is_empty() {
                            info!(
                                remaining = self.supervised.len(),
                                "root process exited, terminating remaining children"
                            );
                        }
                        return Ok(None);
                    }
                    continue;
                }

                // -- Process killed by signal -------------------------------------
                WaitStatus::Signaled(pid, sig, _core_dumped) => {
                    let pid_u32 = pid.as_raw() as u32;
                    self.supervised.remove(&pid_u32);
                    self.in_syscall_entry.remove(&pid_u32);
                    self.thread_tids.remove(&pid_u32);
                    self.seccomp_tracees.remove(&pid_u32);
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
                        }
                        return Ok(None);
                    }
                    continue;
                }

                // -- Continued (SIGCONT after stop) -------------------------------
                WaitStatus::Continued(_pid) => {
                    continue;
                }

                // -- Catch-all for future nix variants ----------------------------
                _ => {
                    continue;
                }
            }
        }
    }

    /// Allow the intercepted syscall to proceed.
    async fn allow(&mut self, pid: u32) -> Result<()> {
        let nix_pid = Pid::from_raw(pid as i32);
        trace!(pid, "allowing syscall to proceed");
        if self.seccomp_tracees.contains(&pid) {
            self.resume_continue(nix_pid, None)
        } else {
            self.resume_to_next_syscall(nix_pid, None)
        }
    }

    /// Deny the intercepted syscall and force an `EPERM` return value.
    async fn deny(&mut self, pid: u32) -> Result<()> {
        let nix_pid = Pid::from_raw(pid as i32);
        trace!(pid, "denying syscall");

        // Replace the syscall with an invalid number so the kernel skips
        // execution, and pre-seed the return register with -EPERM so the
        // tracee sees a real permission error instead of ENOSYS.
        let mut regs = self.read_registers(nix_pid)?;
        regs.orig_rax = u64::MAX; // -1 as u64 => invalid syscall number
        regs.rax = -(libc::EPERM as i64) as u64;
        ptrace::setregs(nix_pid, regs).map_err(|e| {
            Error::InterceptionError(format!("PTRACE_SETREGS (deny) failed for pid {pid}: {e}"))
        })?;

        if self.seccomp_tracees.contains(&pid) {
            self.resume_continue(nix_pid, None)
        } else {
            self.resume_to_next_syscall(nix_pid, None)
        }
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
        let nix_pid = Pid::from_raw(pid as i32);
        ptrace::detach(nix_pid, None).map_err(|e| {
            Error::InterceptionError(format!("PTRACE_DETACH failed for pid {pid}: {e}"))
        })?;
        self.supervised.remove(&pid);
        self.in_syscall_entry.remove(&pid);
        self.thread_tids.remove(&pid);
        self.seccomp_tracees.remove(&pid);
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

    /// Rewrite a tracee's sockaddr to redirect DNS to our local proxy.
    ///
    /// Rewrites both the port and the IP address to `127.0.0.1:<new_port>`.
    /// This is necessary because the original destination may be any DNS
    /// resolver IP (e.g., `127.0.0.53` for systemd-resolved), but our proxy
    /// only listens on `127.0.0.1`.
    async fn rewrite_sockaddr_port(
        &mut self,
        pid: u32,
        sockaddr_addr: u64,
        new_port: u16,
    ) -> Result<()> {
        let nix_pid = Pid::from_raw(pid as i32);
        let word0 = ptrace::read(nix_pid, sockaddr_addr as *mut libc::c_void).map_err(|e| {
            Error::InterceptionError(format!(
                "PTRACE_PEEKDATA (sockaddr family) at {sockaddr_addr:#x} for pid {pid}: {e}"
            ))
        })?;
        let bytes0 = word0.to_ne_bytes();
        let family = u16::from_ne_bytes([bytes0[0], bytes0[1]]) as i32;
        let port_be = new_port.to_be_bytes();

        match family {
            libc::AF_INET => {
                // sockaddr_in layout:
                //   offset 0: family (2)
                //   offset 2: port   (2)
                //   offset 4: addr   (4)
                let data = [port_be[0], port_be[1], 127, 0, 0, 1];
                self.write_tracee_data(nix_pid, sockaddr_addr + 2, &data)?;
                debug!(
                    pid,
                    new_port,
                    "rewrote AF_INET sockaddr to 127.0.0.1:{} for DNS proxy redirect",
                    new_port
                );
            }
            libc::AF_INET6 => {
                // sockaddr_in6 layout:
                //   offset 0:  family (2)
                //   offset 2:  port   (2)
                //   offset 8:  addr   (16)
                self.write_tracee_data(nix_pid, sockaddr_addr + 2, &port_be)?;
                let mut addr = [0u8; 16];
                addr[15] = 1; // ::1
                self.write_tracee_data(nix_pid, sockaddr_addr + 8, &addr)?;
                debug!(
                    pid,
                    new_port,
                    "rewrote AF_INET6 sockaddr to [::1]:{} for DNS proxy redirect",
                    new_port
                );
            }
            other => {
                return Err(Error::InterceptionError(format!(
                    "unsupported sockaddr family {other} for DNS rewrite (pid {pid})"
                )));
            }
        }

        Ok(())
    }

    /// Return the human-readable name of the interception mechanism.
    fn mechanism_name(&self) -> &str {
        "ptrace"
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interceptor::{NetProtocol, OpenFlags, SyscallKind};
    use crate::platform::linux::syscall_nr;

    // -- Construction and defaults ------------------------------------------

    #[test]
    fn new_supervisor_has_no_supervised_pids() {
        let sup = PtraceSupervisor::new();
        assert!(sup.supervised.is_empty());
        assert!(sup.in_syscall_entry.is_empty());
        assert!(sup.thread_tids.is_empty());
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
            sockaddr_addr: None,
        };
        assert_eq!(event.pid, 1234);
        assert_eq!(event.raw_syscall_nr, 257);
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
            sockaddr_addr: None,
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
            sockaddr_addr: None,
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
            raw_syscall_nr: syscall_nr::PIPE,
            sockaddr_addr: None,
        };
        assert_eq!(pipe.kind, SyscallKind::PipeCreate);

        let pair = SyscallEvent {
            pid: 200,
            tid: 200,
            timestamp: Utc::now(),
            kind: SyscallKind::SocketPair,
            raw_syscall_nr: syscall_nr::SOCKETPAIR,
            sockaddr_addr: None,
        };
        assert_eq!(pair.kind, SyscallKind::SocketPair);
    }
}
