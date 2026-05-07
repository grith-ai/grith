// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! macOS supervisor backend -- **FALLBACK / NO-OP MODE**.
//!
//! **WARNING:** This backend does NOT provide real syscall interception on
//! macOS. It is a **no-op fallback** that supervises process lifecycle only
//! (spawn, attach, freeze/thaw, detach). No individual file, network, or
//! process syscalls are intercepted or evaluated by the security proxy.
//!
//! The long-term target is Endpoint Security (ES) auth/notify interception,
//! but that requires entitlement provisioning at build/sign time
//! (`com.apple.developer.endpoint-security.client`). Until ES support is
//! implemented (targeted for v2.0), this backend ensures that session
//! lifecycle, freeze/thaw, and attach/spawn control paths work consistently
//! across platforms -- but all security evaluation is effectively bypassed.
//!
//! Only synthetic `ProcessExec` events are generated (on `spawn_supervised`);
//! no file I/O, network, or other syscall events are reported.

use async_trait::async_trait;
use chrono::Utc;
use nix::errno::Errno;
use nix::libc;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::collections::{HashMap, HashSet, VecDeque};
use std::process::{Child, Command};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::interceptor::{SyscallEvent, SyscallInterceptor, SyscallKind};

/// The Apple entitlement required for full Endpoint Security mode.
const ES_ENTITLEMENT: &str = "com.apple.developer.endpoint-security.client";

/// macOS interceptor implementation.
///
/// In fallback mode this supervises process lifecycle and control operations
/// (attach/spawn/freeze/thaw/deny) while returning synthetic process events.
pub struct EndpointSecuritySupervisor {
    supervised: HashSet<u32>,
    children: HashMap<u32, Child>,
    pending_events: VecDeque<SyscallEvent>,
    poll_interval: Duration,
}

impl EndpointSecuritySupervisor {
    /// Create a new, idle supervisor with no monitored processes.
    ///
    /// **Note:** This is a fallback-mode supervisor that does NOT perform
    /// real syscall interception. See the module-level documentation.
    pub fn new() -> Self {
        tracing::warn!(
            "macOS supervisor running in FALLBACK mode -- no real syscall interception. \
             Only process lifecycle (spawn/attach/freeze/thaw) is supervised. \
             Full Endpoint Security interception requires the '{}' entitlement \
             and is targeted for v2.0.",
            ES_ENTITLEMENT,
        );
        Self {
            supervised: HashSet::new(),
            children: HashMap::new(),
            pending_events: VecDeque::new(),
            poll_interval: Duration::from_millis(250),
        }
    }

    fn is_process_alive(pid: u32) -> bool {
        if pid == 0 {
            return false;
        }

        // SAFETY: `libc::kill` with signal 0 is a POSIX-defined liveness
        // probe that does not deliver any signal. It returns 0 if the process
        // exists and the caller has permission to signal it, or -1 with errno
        // set to ESRCH/EPERM otherwise. The `pid` parameter is guarded by the
        // `pid == 0` early return above, ensuring we never send to process
        // group 0. The cast `pid as i32` is safe because OS-assigned PIDs fit
        // in i32 on all supported platforms.
        let rc = unsafe { libc::kill(pid as i32, 0) };
        if rc == 0 {
            true
        } else {
            matches!(Errno::last(), Errno::EPERM)
        }
    }

    fn send_signal(pid: u32, signal: Signal, op: &str) -> Result<()> {
        match kill(Pid::from_raw(pid as i32), signal) {
            Ok(()) => Ok(()),
            Err(Errno::ESRCH) => Ok(()),
            Err(err) => Err(Error::FreezeError(format!(
                "{op} failed for pid {pid}: {err}"
            ))),
        }
    }
}

impl Default for EndpointSecuritySupervisor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SyscallInterceptor for EndpointSecuritySupervisor {
    async fn attach(&mut self, pid: u32) -> Result<()> {
        self.supervised.insert(pid);
        Ok(())
    }

    async fn spawn_supervised(
        &mut self,
        command: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<u32> {
        let mut cmd = Command::new(command);
        cmd.args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }

        let child = cmd
            .spawn()
            .map_err(|e| Error::SpawnFailed(format!("failed to spawn '{command}': {e}")))?;
        let pid = child.id();

        self.supervised.insert(pid);
        self.children.insert(pid, child);
        self.pending_events.push_back(SyscallEvent {
            pid,
            tid: pid,
            timestamp: Utc::now(),
            kind: SyscallKind::ProcessExec {
                path: command.to_string(),
                args: args.to_vec(),
            },
            raw_syscall_nr: -1,
            sockaddr_addr: None,
        });

        Ok(pid)
    }

    async fn next_event(&mut self) -> Result<Option<SyscallEvent>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(Some(event));
        }

        loop {
            if self.supervised.is_empty() {
                return Ok(None);
            }

            let pids = self.supervised.iter().copied().collect::<Vec<_>>();
            let mut exited = Vec::new();

            for pid in pids {
                if let Some(child) = self.children.get_mut(&pid) {
                    match child.try_wait() {
                        Ok(Some(_)) => exited.push(pid),
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(pid, error = %e, "failed to poll child status");
                            exited.push(pid);
                        }
                    }
                } else if !Self::is_process_alive(pid) {
                    exited.push(pid);
                }
            }

            for pid in exited {
                self.supervised.remove(&pid);
                self.children.remove(&pid);
            }

            if self.supervised.is_empty() {
                return Ok(None);
            }

            tokio::time::sleep(self.poll_interval).await;
            if let Some(event) = self.pending_events.pop_front() {
                return Ok(Some(event));
            }
        }
    }

    async fn allow(&mut self, _pid: u32) -> Result<()> {
        Ok(())
    }

    async fn deny(&mut self, pid: u32) -> Result<()> {
        self.supervised.remove(&pid);
        self.children.remove(&pid);
        match kill(Pid::from_raw(pid as i32), Signal::SIGKILL) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(err) => Err(Error::InterceptionError(format!(
                "deny failed for pid {pid}: {err}"
            ))),
        }
    }

    async fn freeze(&mut self, pid: u32) -> Result<()> {
        Self::send_signal(pid, Signal::SIGSTOP, "freeze")
    }

    async fn thaw(&mut self, pid: u32) -> Result<()> {
        Self::send_signal(pid, Signal::SIGCONT, "thaw")
    }

    async fn detach(&mut self, pid: u32) -> Result<()> {
        self.supervised.remove(&pid);
        if let Some(mut child) = self.children.remove(&pid) {
            let _ = tokio::task::spawn_blocking(move || {
                let _ = child.wait();
            });
        }
        Ok(())
    }

    async fn detach_all(&mut self) -> Result<()> {
        let pids: Vec<u32> = self.supervised.iter().copied().collect();
        for pid in pids {
            self.detach(pid).await?;
        }
        Ok(())
    }

    fn supervised_pids(&self) -> Vec<u32> {
        self.supervised.iter().copied().collect()
    }

    fn is_available() -> bool {
        cfg!(target_os = "macos")
    }

    fn mechanism_name(&self) -> &str {
        "endpoint-security-fallback"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_supervisor_has_no_pids() {
        let sup = EndpointSecuritySupervisor::new();
        assert!(sup.supervised_pids().is_empty());
    }

    #[test]
    fn default_and_new_are_equivalent() {
        let a = EndpointSecuritySupervisor::new();
        let b = EndpointSecuritySupervisor::default();
        assert_eq!(a.supervised_pids(), b.supervised_pids());
    }

    #[test]
    fn mechanism_name_is_endpoint_security() {
        let sup = EndpointSecuritySupervisor::new();
        assert_eq!(sup.mechanism_name(), "endpoint-security-fallback");
    }

    #[test]
    fn is_available_returns_true_on_macos() {
        assert!(EndpointSecuritySupervisor::is_available());
    }

    #[test]
    fn es_entitlement_constant() {
        assert_eq!(
            ES_ENTITLEMENT,
            "com.apple.developer.endpoint-security.client"
        );
    }

    #[tokio::test]
    async fn attach_adds_pid() {
        let mut sup = EndpointSecuritySupervisor::new();
        sup.attach(54321).await.unwrap();
        assert!(sup.supervised_pids().contains(&54321));
    }

    #[tokio::test]
    async fn detach_removes_pid() {
        let mut sup = EndpointSecuritySupervisor::new();
        sup.attach(100).await.unwrap();
        sup.attach(200).await.unwrap();

        sup.detach(100).await.unwrap();
        assert!(!sup.supervised_pids().contains(&100));
        assert!(sup.supervised_pids().contains(&200));
    }

    #[tokio::test]
    async fn detach_all_clears_pids() {
        let mut sup = EndpointSecuritySupervisor::new();
        sup.attach(10).await.unwrap();
        sup.attach(20).await.unwrap();

        sup.detach_all().await.unwrap();
        assert!(sup.supervised_pids().is_empty());
    }

    #[tokio::test]
    async fn next_event_returns_none_when_idle() {
        let mut sup = EndpointSecuritySupervisor::new();
        let event = sup.next_event().await.unwrap();
        assert!(event.is_none());
    }

    #[tokio::test]
    async fn spawn_supervised_returns_pid() {
        let mut sup = EndpointSecuritySupervisor::new();
        let pid = sup
            .spawn_supervised("/usr/bin/true", &["--version".into()], &[])
            .await
            .unwrap();
        assert!(pid > 0);
        sup.detach_all().await.unwrap();
    }

    #[tokio::test]
    async fn allow_and_deny_do_not_panic() {
        let mut sup = EndpointSecuritySupervisor::new();
        let pid = sup
            .spawn_supervised("/bin/sleep", &["5".into()], &[])
            .await
            .unwrap();
        sup.allow(pid).await.unwrap();
        sup.deny(pid).await.unwrap();
    }

    #[tokio::test]
    async fn freeze_and_thaw_do_not_panic() {
        let mut sup = EndpointSecuritySupervisor::new();
        let pid = sup
            .spawn_supervised("/bin/sleep", &["5".into()], &[])
            .await
            .unwrap();
        sup.freeze(pid).await.unwrap();
        sup.thaw(pid).await.unwrap();
        sup.detach(pid).await.unwrap();
    }
}
