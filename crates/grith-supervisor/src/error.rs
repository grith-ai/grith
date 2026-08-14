// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Error types for the grith-supervisor crate.
//!
//! Provides a unified error enum covering every failure mode of the supervisor:
//! platform support, process attachment, spawning, interception, process tree
//! management, PTY forwarding, freeze/thaw, profile loading, configuration,
//! proxy integration, I/O, and session management.

use thiserror::Error;

/// All errors that can occur within the supervisor subsystem.
#[derive(Error, Debug)]
pub enum Error {
    /// The current operating system does not have a supported interception
    /// mechanism (e.g., running on an unsupported architecture or OS).
    #[error("platform not supported: {0}")]
    PlatformNotSupported(String),

    /// Failed to attach to an already-running process via ptrace or equivalent.
    #[error("failed to attach to process {pid}: {reason}")]
    AttachFailed {
        /// The PID we attempted to attach to.
        pid: u32,
        /// Human-readable explanation of the failure.
        reason: String,
    },

    /// Failed to spawn a child process under supervision.
    #[error("failed to spawn supervised process: {0}")]
    SpawnFailed(String),

    /// An error occurred during syscall interception (read/write of registers,
    /// unexpected ptrace state, etc.).
    #[error("interception error: {0}")]
    InterceptionError(String),

    /// An error related to process tree tracking (orphan detection, reparenting).
    #[error("process tree error: {0}")]
    ProcessTreeError(String),

    /// An error from the PTY forwarding layer.
    #[error("pty error: {0}")]
    PtyError(String),

    /// Failed to freeze or thaw a process (SIGSTOP/SIGCONT or cgroup freezer).
    #[error("freeze error: {0}")]
    FreezeError(String),

    /// Error loading or validating a tool profile.
    #[error("profile error: {0}")]
    ProfileError(String),

    /// Error in the learned-rules persistence layer.
    #[error("learned rule error: {0}")]
    LearnedRuleError(String),

    /// Configuration parsing or validation error.
    #[error("config error: {0}")]
    ConfigError(String),

    /// Error forwarding a call to or receiving a decision from grith-proxy.
    #[error("proxy error: {0}")]
    ProxyError(String),

    /// Underlying I/O error (file access, pipe, socket).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The requested supervisor session does not exist.
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// The maximum number of concurrent supervised sessions has been reached.
    #[error("session limit reached: max {0} concurrent sessions")]
    SessionLimitReached(usize),

    /// The audit chain failed startup verification, so the daemon is refusing
    /// to admit new supervised sessions.
    ///
    /// work/74 Phase 5: a session whose decisions cannot be durably and
    /// verifiably recorded is not a supervised session. Records are preserved
    /// unmodified; recovery is an explicit operator action.
    #[error("audit chain quarantined, refusing new sessions: {0}")]
    AuditQuarantined(String),

    /// This process opened the audit database read-only (another process
    /// owns the exclusive writer lock), so it cannot record supervised
    /// sessions and refuses to admit new ones.
    ///
    /// Same principle as [`Error::AuditQuarantined`], different cause and
    /// remedy: nothing is wrong with the chain — this daemon just is not its
    /// owner, and every audit write it attempted would fail. Admitting a
    /// session in that state breaks it mid-flight (required DNS audit
    /// records fail, and DNS is then denied fail-closed).
    #[error("audit database is read-only for this process, refusing new sessions: {0}")]
    AuditReadOnly(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_not_supported_displays_os_name() {
        let err = Error::PlatformNotSupported("freebsd".into());
        assert_eq!(err.to_string(), "platform not supported: freebsd");
    }

    #[test]
    fn attach_failed_displays_pid_and_reason() {
        let err = Error::AttachFailed {
            pid: 42,
            reason: "permission denied".into(),
        };
        assert_eq!(
            err.to_string(),
            "failed to attach to process 42: permission denied"
        );
    }

    #[test]
    fn spawn_failed_displays_message() {
        let err = Error::SpawnFailed("command not found".into());
        assert_eq!(
            err.to_string(),
            "failed to spawn supervised process: command not found"
        );
    }

    #[test]
    fn interception_error_displays_message() {
        let err = Error::InterceptionError("unexpected SIGTRAP".into());
        assert_eq!(err.to_string(), "interception error: unexpected SIGTRAP");
    }

    #[test]
    fn process_tree_error_displays_message() {
        let err = Error::ProcessTreeError("orphan detected".into());
        assert_eq!(err.to_string(), "process tree error: orphan detected");
    }

    #[test]
    fn pty_error_displays_message() {
        let err = Error::PtyError("pseudoterminal allocation failed".into());
        assert_eq!(
            err.to_string(),
            "pty error: pseudoterminal allocation failed"
        );
    }

    #[test]
    fn freeze_error_displays_message() {
        let err = Error::FreezeError("SIGSTOP delivery failed".into());
        assert_eq!(err.to_string(), "freeze error: SIGSTOP delivery failed");
    }

    #[test]
    fn profile_error_displays_message() {
        let err = Error::ProfileError("unknown profile 'foo'".into());
        assert_eq!(err.to_string(), "profile error: unknown profile 'foo'");
    }

    #[test]
    fn config_error_displays_message() {
        let err = Error::ConfigError("missing key 'enabled'".into());
        assert_eq!(err.to_string(), "config error: missing key 'enabled'");
    }

    #[test]
    fn proxy_error_displays_message() {
        let err = Error::ProxyError("timeout waiting for decision".into());
        assert_eq!(err.to_string(), "proxy error: timeout waiting for decision");
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err: Error = io_err.into();
        assert!(err.to_string().contains("file missing"));
    }

    #[test]
    fn session_not_found_displays_id() {
        let err = Error::SessionNotFound("abc-123".into());
        assert_eq!(err.to_string(), "session not found: abc-123");
    }

    #[test]
    fn session_limit_reached_displays_max() {
        let err = Error::SessionLimitReached(4);
        assert_eq!(
            err.to_string(),
            "session limit reached: max 4 concurrent sessions"
        );
    }

    #[test]
    fn error_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }

    #[test]
    fn result_alias_works() {
        let ok: Result<u32> = Ok(42);
        assert!(matches!(ok, Ok(42)));

        let err: Result<u32> = Err(Error::ConfigError("bad".into()));
        assert!(err.is_err());
    }
}
