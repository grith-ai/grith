// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Process freezing and thawing for QUEUE decisions.
//!
//! When the proxy returns a QUEUE decision (score 3.0-8.0), the supervisor
//! must freeze the offending process (and its descendants) until the user
//! reviews and approves the action via the digest. This module provides the
//! OS-level freeze/thaw primitives.
//!
//! On Unix, uses `SIGSTOP` to freeze and `SIGCONT` to thaw.
//! On non-Unix platforms, all operations return errors (unsupported).

use crate::error::{Error, Result};
use std::collections::HashSet;
use std::time::Duration;

/// Manages freezing and thawing of supervised processes.
///
/// Tracks which PIDs are currently frozen so that `thaw_all()` can reliably
/// restore all of them, and to prevent double-freeze/double-thaw issues.
pub struct Freezer {
    /// Set of PIDs currently in frozen (SIGSTOP) state.
    frozen_pids: HashSet<u32>,
    /// Maximum time a process can stay frozen before the supervisor
    /// auto-denies the action and kills the process tree.
    freeze_timeout: Duration,
}

impl Freezer {
    /// Create a new freezer with the given timeout.
    pub fn new(freeze_timeout: Duration) -> Self {
        Self {
            frozen_pids: HashSet::new(),
            freeze_timeout,
        }
    }

    /// Get the configured freeze timeout.
    pub fn freeze_timeout(&self) -> Duration {
        self.freeze_timeout
    }

    /// Freeze a single process by PID.
    ///
    /// On Unix, sends `SIGSTOP` to the process.
    #[cfg(unix)]
    pub fn freeze(&mut self, pid: u32) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        if self.frozen_pids.contains(&pid) {
            return Ok(()); // already frozen
        }

        kill(Pid::from_raw(pid as i32), Signal::SIGSTOP)
            .map_err(|e| Error::FreezeError(format!("failed to SIGSTOP pid {pid}: {e}")))?;

        self.frozen_pids.insert(pid);
        Ok(())
    }

    /// Freeze a single process by PID (non-Unix stub).
    #[cfg(not(unix))]
    pub fn freeze(&mut self, pid: u32) -> Result<()> {
        Err(Error::PlatformNotSupported(
            "process freezing requires Unix (SIGSTOP)".into(),
        ))
    }

    /// Freeze multiple processes at once (e.g., a process tree).
    ///
    /// Attempts to freeze all PIDs. If any individual freeze fails,
    /// the error is returned but already-frozen PIDs remain frozen.
    pub fn freeze_tree(&mut self, pids: &[u32]) -> Result<()> {
        for &pid in pids {
            self.freeze(pid)?;
        }
        Ok(())
    }

    /// Thaw (resume) a single process by PID.
    ///
    /// On Unix, sends `SIGCONT` to the process.
    #[cfg(unix)]
    pub fn thaw(&mut self, pid: u32) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        if !self.frozen_pids.contains(&pid) {
            return Ok(()); // not frozen, nothing to do
        }

        kill(Pid::from_raw(pid as i32), Signal::SIGCONT)
            .map_err(|e| Error::FreezeError(format!("failed to SIGCONT pid {pid}: {e}")))?;

        self.frozen_pids.remove(&pid);
        Ok(())
    }

    /// Thaw a single process by PID (non-Unix stub).
    #[cfg(not(unix))]
    pub fn thaw(&mut self, pid: u32) -> Result<()> {
        Err(Error::PlatformNotSupported(
            "process thawing requires Unix (SIGCONT)".into(),
        ))
    }

    /// Thaw all currently frozen processes.
    ///
    /// Collects errors but attempts to thaw every process. Returns the
    /// first error encountered, if any.
    pub fn thaw_all(&mut self) -> Result<()> {
        let pids: Vec<u32> = self.frozen_pids.iter().copied().collect();
        let mut first_err: Option<Error> = None;
        for pid in pids {
            if let Err(e) = self.thaw(pid) {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Check if a process is currently frozen.
    pub fn is_frozen(&self, pid: u32) -> bool {
        self.frozen_pids.contains(&pid)
    }

    /// Number of currently frozen processes.
    pub fn frozen_count(&self) -> usize {
        self.frozen_pids.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_freezer_has_no_frozen_pids() {
        let freezer = Freezer::new(Duration::from_secs(30));
        assert_eq!(freezer.frozen_count(), 0);
        assert!(!freezer.is_frozen(123));
    }

    #[test]
    fn freeze_timeout_is_stored() {
        let timeout = Duration::from_secs(60);
        let freezer = Freezer::new(timeout);
        assert_eq!(freezer.freeze_timeout(), timeout);
    }

    // On Unix, test freeze/thaw with a real child process.
    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use std::process::{Child, Command};

        /// Hard timeout for any freezer test.
        const TEST_TIMEOUT: Duration = Duration::from_secs(5);

        /// RAII guard that ensures a child process is killed and reaped
        /// even if the test panics. Without this, a panic after `freeze()`
        /// but before `thaw()`/`kill_process()` leaves SIGSTOPed zombies
        /// that consume a PID slot and can block the process table.
        struct ChildGuard {
            child: Child,
        }

        impl ChildGuard {
            fn spawn_sleep() -> Self {
                // Use short-lived sleep (2s) instead of 60s so that even if
                // cleanup fails, the process exits on its own quickly.
                let child = Command::new("sleep")
                    .arg("2")
                    .spawn()
                    .expect("failed to spawn sleep");
                Self { child }
            }

            fn pid(&self) -> u32 {
                self.child.id()
            }
        }

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;

                // SIGCONT first in case the process is stopped — a stopped
                // process ignores SIGKILL until resumed.
                let pid = Pid::from_raw(self.child.id() as i32);
                let _ = kill(pid, Signal::SIGCONT);
                let _ = kill(pid, Signal::SIGKILL);
                let _ = self.child.wait();
            }
        }

        /// Run a freezer test body with a guaranteed timeout.
        fn with_timeout<F: FnOnce() + Send + 'static>(f: F) {
            let (tx, rx) = std::sync::mpsc::channel();
            let handle = std::thread::spawn(move || {
                f();
                let _ = tx.send(());
            });
            match rx.recv_timeout(TEST_TIMEOUT) {
                Ok(()) => handle.join().expect("test thread panicked"),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    panic!(
                        "Freezer test timed out after {:?} — killed to prevent lockup",
                        TEST_TIMEOUT
                    );
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("Freezer test: sender disconnected unexpectedly");
                }
            }
        }

        #[test]
        #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
        fn freeze_and_thaw_real_process() {
            with_timeout(|| {
                let guard = ChildGuard::spawn_sleep();
                let pid = guard.pid();
                let mut freezer = Freezer::new(Duration::from_secs(30));

                freezer.freeze(pid).expect("freeze failed");
                assert!(freezer.is_frozen(pid));
                assert_eq!(freezer.frozen_count(), 1);

                freezer.thaw(pid).expect("thaw failed");
                assert!(!freezer.is_frozen(pid));
                assert_eq!(freezer.frozen_count(), 0);

                drop(guard); // explicit cleanup
            });
        }

        #[test]
        #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
        fn double_freeze_is_idempotent() {
            with_timeout(|| {
                let guard = ChildGuard::spawn_sleep();
                let pid = guard.pid();
                let mut freezer = Freezer::new(Duration::from_secs(30));

                freezer.freeze(pid).expect("first freeze failed");
                freezer.freeze(pid).expect("second freeze should be no-op");
                assert_eq!(freezer.frozen_count(), 1);

                freezer.thaw(pid).expect("thaw failed");
                drop(guard);
            });
        }

        #[test]
        #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
        fn double_thaw_is_idempotent() {
            with_timeout(|| {
                let guard = ChildGuard::spawn_sleep();
                let pid = guard.pid();
                let mut freezer = Freezer::new(Duration::from_secs(30));

                freezer.freeze(pid).expect("freeze failed");
                freezer.thaw(pid).expect("first thaw");
                freezer.thaw(pid).expect("second thaw should be no-op");
                assert_eq!(freezer.frozen_count(), 0);

                drop(guard);
            });
        }

        #[test]
        #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
        fn freeze_tree_freezes_multiple() {
            with_timeout(|| {
                let guard1 = ChildGuard::spawn_sleep();
                let guard2 = ChildGuard::spawn_sleep();
                let pid1 = guard1.pid();
                let pid2 = guard2.pid();
                let mut freezer = Freezer::new(Duration::from_secs(30));

                freezer
                    .freeze_tree(&[pid1, pid2])
                    .expect("freeze_tree failed");
                assert!(freezer.is_frozen(pid1));
                assert!(freezer.is_frozen(pid2));
                assert_eq!(freezer.frozen_count(), 2);

                freezer.thaw_all().expect("thaw_all failed");
                assert_eq!(freezer.frozen_count(), 0);

                drop(guard1);
                drop(guard2);
            });
        }

        #[test]
        #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
        fn freeze_nonexistent_pid_fails() {
            with_timeout(|| {
                let mut freezer = Freezer::new(Duration::from_secs(30));
                // Use a very unlikely PID that won't belong to a real process.
                let result = freezer.freeze(u32::MAX);
                assert!(result.is_err());
            });
        }

        #[test]
        #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
        fn thaw_all_handles_mix() {
            with_timeout(|| {
                let guard1 = ChildGuard::spawn_sleep();
                let guard2 = ChildGuard::spawn_sleep();
                let pid1 = guard1.pid();
                let pid2 = guard2.pid();
                let mut freezer = Freezer::new(Duration::from_secs(30));

                freezer.freeze(pid1).expect("freeze pid1");
                freezer.freeze(pid2).expect("freeze pid2");
                assert_eq!(freezer.frozen_count(), 2);

                freezer.thaw_all().expect("thaw_all");
                assert_eq!(freezer.frozen_count(), 0);
                assert!(!freezer.is_frozen(pid1));
                assert!(!freezer.is_frozen(pid2));

                drop(guard1);
                drop(guard2);
            });
        }
    }

    // Non-Unix: verify that tracking state works even without OS calls.
    #[test]
    fn is_frozen_false_for_untracked() {
        let freezer = Freezer::new(Duration::from_secs(30));
        assert!(!freezer.is_frozen(42));
    }

    #[test]
    fn frozen_count_starts_at_zero() {
        let freezer = Freezer::new(Duration::from_secs(10));
        assert_eq!(freezer.frozen_count(), 0);
    }
}
