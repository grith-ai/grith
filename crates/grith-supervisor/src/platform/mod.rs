// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Platform detection and factory for syscall interceptors.
//!
//! This module provides [`create_interceptor`] which returns the appropriate
//! platform-specific [`SyscallInterceptor`] implementation for the current OS,
//! [`is_supported`] for quick capability checks, and [`platform_capability`]
//! for enforcement decisions that need to distinguish full from degraded
//! supervision.
//!
//! ## Supported platforms
//!
//! | OS    | Mechanism                | Capability level            |
//! |-------|--------------------------|-----------------------------|
//! | Linux | `ptrace(2)` + seccomp    | [`PlatformCapability::Full`] (when ptrace_scope ≤ 1) |
//! | macOS | Endpoint Security        | [`PlatformCapability::Degraded`] (lifecycle-only, no syscall auth) |
//!
//! On unsupported platforms both functions return a
//! [`PlatformNotSupported`](crate::error::Error::PlatformNotSupported) error
//! or [`PlatformCapability::Unavailable`], respectively.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

use crate::error::{Error, Result};
use crate::interceptor::SyscallInterceptor;

// ---------------------------------------------------------------------------
// Platform capability level
// ---------------------------------------------------------------------------

/// The enforcement strength of the supervision mechanism available on the
/// current platform and runtime.
///
/// Used by [`platform_capability`] and consumed by startup policy checks
/// (e.g., `supervisor.require_sandbox = true` in the grith config).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformCapability {
    /// Full per-syscall interception is available.
    ///
    /// On Linux this means `ptrace(2)` is accessible (Yama `ptrace_scope`
    /// 0 or 1, or the file is absent/unreadable and the kernel is assumed
    /// permissive). Every security-relevant syscall is trapped before it
    /// reaches the kernel, giving grith the ability to allow, deny, or
    /// queue it.
    Full,

    /// Supervision is available but provides only lifecycle tracking, not
    /// per-syscall interception.
    ///
    /// On macOS the current Endpoint Security implementation can observe
    /// process creation and exit events but cannot intercept and deny
    /// individual syscalls. It is useful for audit and coarse process
    /// control, but cannot enforce fine-grained file/network policy.
    ///
    /// When `supervisor.require_sandbox = true` this level is treated as
    /// insufficient and startup is refused.
    Degraded,

    /// No supervision mechanism is available on this platform or runtime.
    ///
    /// Either the OS is unsupported, `ptrace_scope` is set to 2 or 3 and
    /// the process lacks `CAP_SYS_PTRACE`, or a required kernel feature is
    /// absent.
    Unavailable,
}

/// Return the supervision capability level available on the current platform.
///
/// Unlike [`is_supported`] (which returns a bool), this function distinguishes
/// between full syscall-level interception and degraded lifecycle-only
/// supervision. Use this when enforcement policy needs to make the distinction
/// — for example, to refuse startup when `require_sandbox = true` and only a
/// degraded backend is present.
pub fn platform_capability() -> PlatformCapability {
    #[cfg(target_os = "linux")]
    {
        if linux::PtraceSupervisor::is_available() {
            return PlatformCapability::Full;
        }
        return PlatformCapability::Unavailable;
    }

    #[cfg(target_os = "macos")]
    {
        if macos::EndpointSecuritySupervisor::is_available() {
            // macOS Endpoint Security is lifecycle-only in the current
            // implementation — process creation/exit events but no
            // per-syscall interception.
            return PlatformCapability::Degraded;
        } else {
            return PlatformCapability::Unavailable;
        }
    }

    #[allow(unreachable_code)]
    PlatformCapability::Unavailable
}

/// Create the appropriate platform-specific syscall interceptor.
///
/// This factory probes the runtime environment (kernel version, capabilities,
/// entitlements) and returns the best available mechanism. Returns an error if
/// no mechanism is available.
///
/// # Errors
///
/// Returns [`Error::PlatformNotSupported`] if the current OS has no supported
/// interception mechanism or if the mechanism exists but is not available at
/// runtime (e.g., missing `CAP_SYS_PTRACE`).
pub fn create_interceptor() -> Result<Box<dyn SyscallInterceptor>> {
    #[cfg(target_os = "linux")]
    {
        if linux::PtraceSupervisor::is_available() {
            return Ok(Box::new(linux::PtraceSupervisor::new()));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if macos::EndpointSecuritySupervisor::is_available() {
            return Ok(Box::new(macos::EndpointSecuritySupervisor::new()));
        }
    }

    Err(Error::PlatformNotSupported(format!(
        "No syscall interception mechanism available on {}",
        std::env::consts::OS
    )))
}

/// Whether the current platform supports observing syscall return values
/// (post-syscall stops) in addition to syscall entry interception.
///
/// PR 3 of the codex-startup-prompt-flood remediation plan uses this to
/// gate the failed-exec / failed-connect suppressions: only when the
/// platform can confirm the kernel returned `ENOENT` / `ECONNREFUSED`
/// can we safely suppress the QUEUE that would otherwise have prompted.
/// Without post-syscall observation we fall back to the pre-PR-3
/// behaviour (QUEUE every spawn that the proxy would queue, even when
/// the kernel is about to reject the call).
///
/// # Audit (2026-05)
///
/// - **Linux + ptrace**: yes. The seccomp-BPF path stops on entry as
///   `PTRACE_EVENT_SECCOMP`. After the supervisor allows the syscall,
///   resuming with `PTRACE_SYSCALL` instead of `PTRACE_CONT` causes the
///   kernel to deliver a second stop at syscall exit, where RAX holds
///   the return value. The fallback `PTRACE_SYSCALL` path already
///   delivers entry+exit stops natively. Either way the return value
///   is readable via `read_registers`. See
///   `crates/grith-supervisor/src/platform/linux/events.rs` for the
///   existing entry-stop machinery; the exit-stop wiring lands in
///   PR 3 Phase B/C.
/// - **macOS + Endpoint Security**: no. ES events are lifecycle-only
///   and cannot observe per-syscall return codes. macOS gets `false`
///   here; PR 3's suppressions are disabled on that platform.
/// - **Other platforms**: false (no supervision mechanism at all).
///
/// This is intentionally a separate function rather than a fourth
/// `PlatformCapability` variant because post-syscall observation is
/// orthogonal to the Full/Degraded/Unavailable axis — it's an
/// additional sub-capability that Full platforms may or may not have.
pub fn has_post_syscall_observation() -> bool {
    #[cfg(target_os = "linux")]
    {
        return linux::PtraceSupervisor::is_available();
    }

    #[cfg(target_os = "macos")]
    {
        return false;
    }

    #[allow(unreachable_code)]
    false
}

/// Check if supervisor mode is supported on the current platform.
///
/// This is a lightweight check suitable for UI feature-gating — it does not
/// allocate resources or attempt to attach to any process.
pub fn is_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        return linux::PtraceSupervisor::is_available();
    }

    #[cfg(target_os = "macos")]
    {
        return macos::EndpointSecuritySupervisor::is_available();
    }

    #[allow(unreachable_code)]
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_supported_returns_bool() {
        // On any platform this should return a bool without panicking.
        // The actual value depends on the test environment.
        let _ = is_supported();
    }

    #[test]
    fn platform_capability_does_not_panic() {
        // Smoke test: must return a value on any platform without panicking.
        let cap = platform_capability();
        // Value is environment-dependent; just assert it's one of the variants.
        assert!(matches!(
            cap,
            PlatformCapability::Full
                | PlatformCapability::Degraded
                | PlatformCapability::Unavailable
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_capability_is_full_or_unavailable() {
        // macOS-specific Degraded variant must not appear on Linux.
        let cap = platform_capability();
        assert!(
            matches!(
                cap,
                PlatformCapability::Full | PlatformCapability::Unavailable
            ),
            "unexpected capability on Linux: {cap:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_capability_consistent_with_is_supported() {
        // platform_capability() and is_supported() must agree on Linux:
        // Full ↔ is_supported() == true; Unavailable ↔ is_supported() == false.
        let cap = platform_capability();
        let supported = is_supported();
        match cap {
            PlatformCapability::Full => assert!(supported),
            PlatformCapability::Unavailable => assert!(!supported),
            PlatformCapability::Degraded => {
                panic!("Degraded must not appear on Linux")
            }
        }
    }

    #[test]
    fn platform_capability_is_copy() {
        let cap = platform_capability();
        let _copy = cap; // Copy trait — no move
        let _ = cap;
    }

    #[test]
    fn create_interceptor_returns_result() {
        // On CI this may succeed or fail depending on privileges; we just
        // verify the function does not panic.
        let result = create_interceptor();
        match result {
            Ok(interceptor) => {
                // If creation succeeded, basic trait methods should work.
                assert!(!interceptor.mechanism_name().is_empty());
                assert!(interceptor.supervised_pids().is_empty());
            }
            Err(Error::PlatformNotSupported(msg)) => {
                assert!(!msg.is_empty());
            }
            Err(other) => {
                // Unexpected error variant — still fine for a test, but log it.
                panic!("unexpected error from create_interceptor: {other}");
            }
        }
    }

    #[test]
    fn platform_not_supported_error_contains_os() {
        let err = Error::PlatformNotSupported(format!(
            "No syscall interception mechanism available on {}",
            std::env::consts::OS
        ));
        let msg = err.to_string();
        assert!(
            msg.contains(std::env::consts::OS),
            "error message should contain the OS name: {msg}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_module_accessible() {
        // Ensure the linux sub-module compiles and the type is accessible.
        let _ = linux::PtraceSupervisor::is_available();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_module_accessible() {
        // Ensure the macos sub-module compiles and the type is accessible.
        let _ = macos::EndpointSecuritySupervisor::is_available();
    }

    // PR 3 Phase A: post-syscall observation capability detection.

    #[test]
    fn post_syscall_observation_returns_bool() {
        // Smoke test: must return a value on any platform without panicking.
        let _ = has_post_syscall_observation();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_post_syscall_observation_matches_is_supported() {
        // On Linux post-syscall observation is available whenever ptrace
        // is — the seccomp-BPF + PTRACE_SYSCALL exit-stop machinery is
        // part of the standard interception path.
        assert_eq!(has_post_syscall_observation(), is_supported());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_post_syscall_observation_is_false() {
        // Endpoint Security is lifecycle-only; no per-syscall return-
        // value observation. PR 3's failed-exec / failed-connect
        // suppressions are disabled on macOS until that gap closes.
        assert!(!has_post_syscall_observation());
    }
}
