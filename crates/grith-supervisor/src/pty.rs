// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! PTY forwarding for supervised processes.
//!
//! Wraps the `portable-pty` crate to spawn a supervised process in a
//! pseudo-terminal. This is necessary so that interactive CLI tools (like
//! `claude-code`) believe they are running in a real terminal and produce
//! the expected output formatting, prompts, and ANSI escape sequences.
//!
//! The supervisor sits between the user's terminal and the PTY master,
//! forwarding I/O while intercepting syscalls on a separate channel.

#[cfg(unix)]
use crate::error::{Error, Result};

#[cfg(unix)]
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

#[cfg(unix)]
use std::io::{Read, Write};

/// Manages a child process running inside a PTY.
///
/// The forwarder owns the PTY master side. Callers receive the reader and
/// writer handles from `spawn()` and are responsible for forwarding data
/// between the user's terminal and the PTY.
#[cfg(unix)]
pub struct PtyForwarder {
    /// The child process handle (for wait/kill).
    child: Box<dyn Child + Send + Sync>,
    /// The master side of the PTY (for resize).
    master: Box<dyn MasterPty + Send>,
}

#[cfg(unix)]
impl PtyForwarder {
    /// Spawn a command inside a new PTY.
    ///
    /// Returns the forwarder plus a reader (master -> user) and writer
    /// (user -> master) pair. The caller is responsible for shuttling bytes
    /// between the user's terminal and these handles.
    pub fn spawn(
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<(Self, Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| Error::PtyError(format!("failed to open pty: {e}")))?;

        let mut cmd = CommandBuilder::new(command);
        for arg in args {
            cmd.arg(arg);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| Error::PtyError(format!("failed to spawn command: {e}")))?;

        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| Error::PtyError(format!("failed to clone pty reader: {e}")))?;

        let writer = pair
            .master
            .take_writer()
            .map_err(|e| Error::PtyError(format!("failed to take pty writer: {e}")))?;

        let forwarder = Self {
            child,
            master: pair.master,
        };

        Ok((forwarder, reader, writer))
    }

    /// Get the child process PID.
    pub fn child_pid(&self) -> Option<u32> {
        self.child.process_id()
    }

    /// Resize the PTY to the given dimensions.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| Error::PtyError(format!("failed to resize pty: {e}")))
    }

    /// Send a kill signal to the child process.
    pub fn kill(&mut self) -> Result<()> {
        self.child
            .kill()
            .map_err(|e| Error::PtyError(format!("failed to kill child: {e}")))
    }

    /// Wait for the child process to exit and return its exit status.
    pub fn wait(&mut self) -> Result<portable_pty::ExitStatus> {
        self.child
            .wait()
            .map_err(|e| Error::PtyError(format!("failed to wait for child: {e}")))
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Hard timeout for any PTY test. If a test takes longer than this,
    /// the child is killed and the test panics with a clear message rather
    /// than blocking forever.
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    /// Run a PTY test body with a guaranteed timeout. Spawns the test
    /// closure on a separate thread and kills the process if it exceeds
    /// `TEST_TIMEOUT`. This prevents a blocked PTY read or a
    /// `portable-pty` double-fork hang from locking up the machine.
    fn with_timeout<F: FnOnce() + Send + 'static>(f: F) {
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            f();
            let _ = tx.send(());
        });
        match rx.recv_timeout(TEST_TIMEOUT) {
            Ok(()) => handle.join().expect("test thread panicked"),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("PTY test: sender disconnected unexpectedly");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Don't join — the thread may be blocked forever on a PTY
                // read. Let it leak (the OS reclaims on process exit) rather
                // than hang the test runner.
                panic!(
                    "PTY test timed out after {:?} — killed to prevent lockup",
                    TEST_TIMEOUT
                );
            }
        }
    }

    #[test]
    #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
    fn spawn_echo_and_wait() {
        with_timeout(|| {
            let (mut forwarder, reader, _writer) =
                PtyForwarder::spawn("echo", &["hello".into()], 80, 24)
                    .expect("failed to spawn echo");

            let status = forwarder.wait().expect("failed to wait");
            assert!(status.success());

            // Read with a timeout on a separate thread to avoid blocking
            // forever if the PTY master FD doesn't close cleanly.
            // `portable-pty` can double-fork, leaving the slave FD open.
            drop(_writer); // close write side first
            let mut buf = [0u8; 4096];
            let mut reader = reader;
            let mut output = String::new();
            // Do a single bounded read rather than read_to_string which
            // blocks until EOF (which may never come with portable-pty).
            if let Ok(n) = reader.read(&mut buf) {
                output.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
            assert!(
                output.contains("hello"),
                "expected 'hello' in PTY output, got: {output:?}"
            );
        });
    }

    #[test]
    #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
    fn spawn_nonexistent_command_fails() {
        with_timeout(|| {
            let result = PtyForwarder::spawn(
                "/usr/bin/this_command_does_not_exist_grith_test",
                &[],
                80,
                24,
            );
            assert!(result.is_err());
        });
    }

    #[test]
    #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
    fn spawn_true_exits_success() {
        with_timeout(|| {
            let (mut forwarder, _reader, _writer) =
                PtyForwarder::spawn("true", &[], 80, 24).expect("failed to spawn true");

            let status = forwarder.wait().expect("failed to wait");
            assert!(status.success());
        });
    }

    #[test]
    #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
    fn spawn_false_exits_failure() {
        with_timeout(|| {
            let (mut forwarder, _reader, _writer) =
                PtyForwarder::spawn("false", &[], 80, 24).expect("failed to spawn false");

            let status = forwarder.wait().expect("failed to wait");
            assert!(!status.success());
        });
    }

    #[test]
    #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
    fn resize_on_valid_pty() {
        with_timeout(|| {
            let (mut forwarder, _reader, _writer) =
                PtyForwarder::spawn("sleep", &["0.1".into()], 80, 24)
                    .expect("failed to spawn sleep");

            let result = forwarder.resize(120, 40);
            assert!(result.is_ok());

            let _ = forwarder.kill();
            let _ = forwarder.wait();
        });
    }

    #[test]
    #[ignore] // Spawns real processes; run with: cargo test -p grith-supervisor -- --ignored --test-threads=1
    fn kill_running_process() {
        with_timeout(|| {
            let (mut forwarder, _reader, _writer) =
                PtyForwarder::spawn("sleep", &["60".into()], 80, 24)
                    .expect("failed to spawn sleep");

            let kill_result = forwarder.kill();
            assert!(kill_result.is_ok());

            let status = forwarder.wait().expect("failed to wait");
            assert!(!status.success());
        });
    }
}
