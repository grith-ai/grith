// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Child process spawning for the Linux ptrace supervisor.
//!
//! Contains the fork-and-trace logic that creates a supervised child process
//! with `PTRACE_TRACEME` in the child and `PTRACE_SETOPTIONS` in the parent.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd};

use nix::libc;
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult};
use tracing::info;

use crate::error::{Error, Result};

use super::PtraceSupervisor;

/// Resolve a command name to its full path by searching `$PATH`.
///
/// If the command already contains a `/`, it is returned as-is (assumed to
/// be an absolute or relative path). Otherwise, each directory in `$PATH`
/// is checked for an executable file with the given name.
fn resolve_command_path(command: &str) -> Result<String> {
    if command.contains('/') {
        return Ok(command.to_string());
    }
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = std::path::Path::new(dir).join(command);
        if candidate.is_file() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    Err(Error::SpawnFailed(format!(
        "command not found in PATH: {command}"
    )))
}

/// Build the full environment array for execve by copying the current
/// environment and applying the given overrides.
///
/// This avoids calling `std::env::set_var` post-fork in a multi-threaded
/// Tokio runtime, which is technically undefined behavior on some
/// platforms (the environment block is process-global shared state, and
/// other threads may be reading it concurrently even though POSIX says
/// only the calling thread survives fork -- glibc's implementation uses
/// a global lock that may be left in an inconsistent state).
/// Environment variables that grith strips from supervised children.
///
/// These are set by parent tools and would cause the child to detect a
/// "nested session" and refuse to start. grith is a *supervisor*, not a
/// nested session, so these checks are incorrect when running under grith.
/// Exact env var names to strip from supervised children.
///
/// These are set by parent tools and would cause the child to detect a
/// "nested session" and refuse to start. grith is a *supervisor*, not a
/// nested session, so these checks are incorrect when running under grith.
const STRIPPED_ENV_VARS: &[&str] = &[
    // Claude Code
    "CLAUDECODE",
    "CODEX_SESSION",
    // Goose
    "GOOSE_TERMINAL",
    "AGENT_SESSION_ID",
    // Copilot CLI
    "COPILOT_CLI",
    "COPILOT_CLI_VERSION",
    "COPILOT_CLI_MODE",
    "GITHUB_COPILOT_CLI_MODE",
    // Cursor CLI
    "CURSOR_AGENT",
];

/// Env var prefixes to strip from supervised children.
/// Any variable starting with one of these prefixes is removed.
const STRIPPED_ENV_PREFIXES: &[&str] = &[
    // Claude Code sets CLAUDE_CODE_* vars for nesting detection / IPC
    "CLAUDE_CODE_",
];

/// Environment variables stripped only when their value matches exactly.
///
/// Used for generic env var names (like `AGENT`) that would break other
/// software if unconditionally removed.
const STRIPPED_ENV_CONDITIONS: &[(&str, &str)] = &[
    // Goose sets AGENT=goose; stripping unconditionally is too broad.
    ("AGENT", "goose"),
];

fn build_envp(extra_env: &[(String, String)]) -> Vec<CString> {
    let env_map = build_env_map(std::env::vars().collect(), extra_env);
    env_map
        .into_iter()
        .filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok())
        .collect()
}

/// Build the environment map with stripping applied.
///
/// Separated from `build_envp` so it can be unit-tested without depending
/// on the process environment.
fn build_env_map(
    mut env_map: std::collections::HashMap<String, String>,
    extra_env: &[(String, String)],
) -> std::collections::HashMap<String, String> {
    for key in STRIPPED_ENV_VARS {
        env_map.remove(*key);
    }
    env_map.retain(|k, _| {
        !STRIPPED_ENV_PREFIXES
            .iter()
            .any(|prefix| k.starts_with(prefix))
    });
    env_map.retain(|k, v| {
        !STRIPPED_ENV_CONDITIONS
            .iter()
            .any(|(name, cond_value)| k.as_str() == *name && v.as_str() == *cond_value)
    });
    for (key, val) in extra_env {
        env_map.insert(key.clone(), val.clone());
    }
    env_map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn strips_exact_match_vars() {
        let env = make_env(&[
            ("CLAUDECODE", "1"),
            ("CURSOR_AGENT", "1"),
            ("HOME", "/home/user"),
        ]);
        let result = build_env_map(env, &[]);
        assert!(!result.contains_key("CLAUDECODE"));
        assert!(!result.contains_key("CURSOR_AGENT"));
        assert!(result.contains_key("HOME"));
    }

    #[test]
    fn strips_prefix_vars() {
        let env = make_env(&[
            ("CLAUDE_CODE_VERSION", "1.0"),
            ("CLAUDE_CODE_IPC", "/tmp/ipc"),
            ("CLAUDE_OTHER", "keep"),
        ]);
        let result = build_env_map(env, &[]);
        assert!(!result.contains_key("CLAUDE_CODE_VERSION"));
        assert!(!result.contains_key("CLAUDE_CODE_IPC"));
        // CLAUDE_OTHER does NOT start with CLAUDE_CODE_
        assert!(result.contains_key("CLAUDE_OTHER"));
    }

    #[test]
    fn strips_conditional_vars() {
        let env = make_env(&[("AGENT", "goose"), ("PATH", "/usr/bin")]);
        let result = build_env_map(env, &[]);
        assert!(
            !result.contains_key("AGENT"),
            "AGENT=goose should be stripped"
        );
        assert!(result.contains_key("PATH"));
    }

    #[test]
    fn preserves_agent_when_value_differs() {
        let env = make_env(&[("AGENT", "other-tool")]);
        let result = build_env_map(env, &[]);
        assert!(
            result.contains_key("AGENT"),
            "AGENT=other-tool should be preserved"
        );
        assert_eq!(result["AGENT"], "other-tool");
    }

    #[test]
    fn preserves_unrelated_vars() {
        let env = make_env(&[
            ("HOME", "/home/user"),
            ("PATH", "/usr/bin"),
            ("EDITOR", "vim"),
            ("RUST_LOG", "debug"),
        ]);
        let result = build_env_map(env, &[]);
        assert_eq!(result.len(), 4);
        assert_eq!(result["EDITOR"], "vim");
    }

    #[test]
    fn extra_env_overrides_after_stripping() {
        let env = make_env(&[("CLAUDECODE", "1"), ("HOME", "/home/user")]);
        let extra = vec![
            ("GRITH_SESSION".to_string(), "abc".to_string()),
            ("HOME".to_string(), "/override".to_string()),
        ];
        let result = build_env_map(env, &extra);
        assert!(!result.contains_key("CLAUDECODE"));
        assert_eq!(result["GRITH_SESSION"], "abc");
        assert_eq!(result["HOME"], "/override");
    }

    #[test]
    fn strips_all_nesting_detection_vars() {
        let env = make_env(&[
            ("CLAUDECODE", "1"),
            ("CODEX_SESSION", "uuid"),
            ("GOOSE_TERMINAL", "1"),
            ("AGENT_SESSION_ID", "uuid"),
            ("COPILOT_CLI", "1"),
            ("COPILOT_CLI_VERSION", "1.0"),
            ("COPILOT_CLI_MODE", "agent"),
            ("GITHUB_COPILOT_CLI_MODE", "agent"),
            ("CURSOR_AGENT", "1"),
            ("AGENT", "goose"),
            ("CLAUDE_CODE_IPC", "/tmp/ipc"),
            ("SAFE_VAR", "keep"),
        ]);
        let result = build_env_map(env, &[]);
        // All nesting-detection vars should be gone.
        for key in STRIPPED_ENV_VARS {
            assert!(!result.contains_key(*key), "{key} should be stripped");
        }
        assert!(!result.contains_key("CLAUDE_CODE_IPC"));
        assert!(!result.contains_key("AGENT"));
        // Safe var should remain.
        assert!(result.contains_key("SAFE_VAR"));
    }
}

/// Spawn a child process under full ptrace supervision.
///
/// Uses the classic fork-and-trace pattern:
///
/// 1. The parent calls `fork()`.
/// 2. The **child** calls `PTRACE_TRACEME`, sets environment variables,
///    then calls `execvp` to replace itself with the target command. The
///    kernel stops the child at the `execve` boundary.
/// 3. The **parent** waits for the initial stop, configures tracing
///    options via `PTRACE_SETOPTIONS`, and resumes the child with
///    `PTRACE_SYSCALL`.
pub(super) async fn do_spawn_supervised(
    sup: &mut PtraceSupervisor,
    command: &str,
    args: &[String],
    env: &[(String, String)],
) -> Result<u32> {
    // Resolve command to absolute path before forking (execve does not
    // search PATH). This also gives a clear error if the command is missing.
    let resolved = resolve_command_path(command)?;

    // Build argv and envp *before* forking so we only do allocations
    // in the parent (where the Tokio runtime is still fully intact).
    let c_command = CString::new(resolved.as_bytes())
        .map_err(|e| Error::SpawnFailed(format!("command contains null byte: {e}")))?;
    // argv[0] keeps the original command name (not the resolved path).
    let c_argv0 = CString::new(command.as_bytes())
        .map_err(|e| Error::SpawnFailed(format!("command contains null byte: {e}")))?;
    let c_args: Vec<CString> = std::iter::once(c_argv0)
        .chain(
            args.iter()
                .map(|a| CString::new(a.as_bytes()).expect("argument contains null byte")),
        )
        .collect();
    let c_envp = build_envp(env);

    // SAFETY: `fork()` duplicates the calling process. This is safe
    // because:
    //
    // 1. The child process immediately calls `execve` to replace its
    //    address space, so we do not execute arbitrary Rust code with
    //    duplicated heap state or mutex guards.
    //
    // 2. Between `fork` and `exec`, the child only calls
    //    `ptrace::traceme()` and `execve` -- both are async-signal-safe.
    //    We avoid `std::env::set_var` (which touches the global
    //    environment block) and minimize allocations by building argv
    //    and envp in the parent before fork.
    //
    // 3. If `execve` fails, the child calls `panic!` (via `.expect()`)
    //    which aborts the child without returning into the caller's
    //    control flow.
    //
    // 4. In the parent branch, we only interact with the child via
    //    `waitpid` and ptrace APIs, which are safe POSIX interfaces.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // --- child process ---------------------------------------------------
            // Request that the parent trace us.
            ptrace::traceme().expect("PTRACE_TRACEME failed in child");

            // Install seccomp-BPF pre-filter so the kernel only generates
            // ptrace stops for security-relevant syscalls.
            super::seccomp::install_seccomp_filter();

            // Replace the process image with the full environment.
            // Using execve (not execvp) so we pass the pre-built envp
            // instead of modifying the process environment post-fork.
            nix::unistd::execve(&c_command, &c_args, &c_envp)
                .expect("execve failed in supervised child");
            // execve never returns on success; .expect() diverges on error.
            // The unreachable! is needed for type-checking the match arm.
            #[allow(unreachable_code)]
            {
                unreachable!()
            }
        }
        Ok(ForkResult::Parent { child }) => {
            // --- parent (tracer) process -----------------------------------------
            let child_pid = child.as_raw() as u32;

            // Wait for the child to stop at the execve boundary.
            let wait_status = waitpid(child, None).map_err(|e| {
                Error::SpawnFailed(format!("waitpid for initial stop of pid {child_pid}: {e}"))
            })?;

            // If the child exited instead of stopping, execve failed.
            match wait_status {
                nix::sys::wait::WaitStatus::Stopped(_, _)
                | nix::sys::wait::WaitStatus::PtraceEvent(_, _, _) => {}
                nix::sys::wait::WaitStatus::Exited(_, code) => {
                    return Err(Error::SpawnFailed(format!(
                        "child exited with code {code} before reaching execve stop \
                         (command: {command})"
                    )));
                }
                nix::sys::wait::WaitStatus::Signaled(_, sig, _) => {
                    return Err(Error::SpawnFailed(format!(
                        "child killed by signal {sig} before reaching execve stop \
                         (command: {command})"
                    )));
                }
                other => {
                    return Err(Error::SpawnFailed(format!(
                        "unexpected wait status {other:?} for child {child_pid}"
                    )));
                }
            }

            sup.set_trace_options(child)?;
            sup.supervised.insert(child_pid);
            sup.seccomp_tracees.insert(child_pid);
            if sup.root_pid.is_none() {
                sup.root_pid = Some(child_pid);
            }

            // Resume the child with PTRACE_CONT — seccomp handles filtering.
            sup.resume_continue(child, None)?;

            info!(
                pid = child_pid,
                command, "spawned supervised process (seccomp active)"
            );
            Ok(child_pid)
        }
        Err(e) => Err(Error::SpawnFailed(format!("fork() failed: {e}"))),
    }
}

/// Result of spawning a supervised process inside a PTY.
pub struct PtySpawnResult {
    /// The child PID.
    pub pid: u32,
    /// The master side of the PTY (for reading child output).
    pub master_read: std::fs::File,
    /// The master side of the PTY (for writing to child stdin).
    pub master_write: std::fs::File,
}

/// Spawn a child process under ptrace supervision inside a new PTY.
///
/// Combines [`do_spawn_supervised`] with PTY setup so that:
/// - The child runs in a pseudo-terminal (interactive tools get a real TTY)
/// - The child is traced from birth via `PTRACE_TRACEME` (no `PTRACE_ATTACH`)
///
/// This avoids the YAMA `ptrace_scope=1` restriction that prevents attaching
/// to processes spawned by `portable-pty` (which double-forks and reparents).
pub(super) async fn do_spawn_supervised_pty(
    sup: &mut PtraceSupervisor,
    command: &str,
    args: &[String],
    env: &[(String, String)],
    cols: u16,
    rows: u16,
) -> Result<PtySpawnResult> {
    // Resolve command to absolute path before forking (execve does not
    // search PATH). This also gives a clear error if the command is missing.
    let resolved = resolve_command_path(command)?;

    let c_command = CString::new(resolved.as_bytes())
        .map_err(|e| Error::SpawnFailed(format!("command contains null byte: {e}")))?;
    // argv[0] keeps the original command name (not the resolved path).
    let c_argv0 = CString::new(command.as_bytes())
        .map_err(|e| Error::SpawnFailed(format!("command contains null byte: {e}")))?;
    let c_args: Vec<CString> = std::iter::once(c_argv0)
        .chain(
            args.iter()
                .map(|a| CString::new(a.as_bytes()).expect("argument contains null byte")),
        )
        .collect();
    let c_envp = build_envp(env);

    // Open a PTY pair.
    let pty = nix::pty::openpty(
        Some(&nix::pty::Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }),
        None,
    )
    .map_err(|e| Error::SpawnFailed(format!("openpty() failed: {e}")))?;

    let master_fd = pty.master;
    let slave_fd = pty.slave;

    // SAFETY: Same safety arguments as do_spawn_supervised, plus:
    // - The child calls setsid(), ioctl(TIOCSCTTY), and dup2() which are
    //   all async-signal-safe.
    // - We close the master fd in the child (it only needs the slave side).
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // --- child process ---
            // Close master side — child only uses slave.
            drop(master_fd);

            // Create a new session so the child becomes session leader.
            // SAFETY: setsid is async-signal-safe.
            unsafe { libc::setsid() };

            // Set the slave PTY as the controlling terminal.
            // SAFETY: slave_fd is a valid open fd.
            let slave_raw = slave_fd.as_raw_fd();
            unsafe { libc::ioctl(slave_raw, libc::TIOCSCTTY, 0) };

            // Redirect stdin/stdout/stderr to the slave PTY.
            // SAFETY: slave_raw is valid, and 0/1/2 are standard fds.
            unsafe {
                libc::dup2(slave_raw, 0);
                libc::dup2(slave_raw, 1);
                libc::dup2(slave_raw, 2);
                if slave_raw > 2 {
                    libc::close(slave_raw);
                }
            }

            // Request ptrace tracing.
            ptrace::traceme().expect("PTRACE_TRACEME failed in child");

            // Install seccomp-BPF pre-filter so the kernel only generates
            // ptrace stops for security-relevant syscalls.
            super::seccomp::install_seccomp_filter();

            nix::unistd::execve(&c_command, &c_args, &c_envp)
                .expect("execve failed in supervised child");

            #[allow(unreachable_code)]
            {
                unreachable!()
            }
        }
        Ok(ForkResult::Parent { child }) => {
            // --- parent (tracer) process ---
            // Close slave side — parent only uses master.
            drop(slave_fd);

            let child_pid = child.as_raw() as u32;

            // Wait for the child to stop at the execve boundary.
            let wait_status = waitpid(child, None).map_err(|e| {
                Error::SpawnFailed(format!("waitpid for initial stop of pid {child_pid}: {e}"))
            })?;

            // If the child exited instead of stopping, execve failed.
            match wait_status {
                nix::sys::wait::WaitStatus::Stopped(_, _)
                | nix::sys::wait::WaitStatus::PtraceEvent(_, _, _) => {}
                nix::sys::wait::WaitStatus::Exited(_, code) => {
                    return Err(Error::SpawnFailed(format!(
                        "child exited with code {code} before reaching execve stop \
                         (command: {command})"
                    )));
                }
                nix::sys::wait::WaitStatus::Signaled(_, sig, _) => {
                    return Err(Error::SpawnFailed(format!(
                        "child killed by signal {sig} before reaching execve stop \
                         (command: {command})"
                    )));
                }
                other => {
                    return Err(Error::SpawnFailed(format!(
                        "unexpected wait status {other:?} for child {child_pid}"
                    )));
                }
            }

            sup.set_trace_options(child)?;
            sup.supervised.insert(child_pid);
            sup.seccomp_tracees.insert(child_pid);
            if sup.root_pid.is_none() {
                sup.root_pid = Some(child_pid);
            }
            sup.resume_continue(child, None)?;

            // Create reader/writer from the master fd by duplicating it.
            // SAFETY: master_fd is a valid open fd.
            let master_raw = master_fd.as_raw_fd();
            let dup_fd = nix::unistd::dup(master_raw)
                .map_err(|e| Error::SpawnFailed(format!("dup(master_fd) failed: {e}")))?;

            let master_read = unsafe { std::fs::File::from_raw_fd(master_raw) };
            // Prevent master_fd's OwnedFd from closing the fd (we gave it to master_read).
            std::mem::forget(master_fd);
            let master_write = unsafe { std::fs::File::from_raw_fd(dup_fd) };

            info!(
                pid = child_pid,
                command, "spawned supervised process in PTY"
            );
            Ok(PtySpawnResult {
                pid: child_pid,
                master_read,
                master_write,
            })
        }
        Err(e) => {
            drop(master_fd);
            drop(slave_fd);
            Err(Error::SpawnFailed(format!("fork() failed: {e}")))
        }
    }
}
