// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! PR 5 Phase D: rewrite a wildcard `bind(2)` sockaddr to the
//! loopback address at the syscall-argument level, before the kernel
//! processes the call.
//!
//! The supervisor enters here at `bind()` entry-stop when:
//!   1. The bind address is wildcard (`0.0.0.0`, `::`, or IPv4-mapped).
//!   2. The session profile's `local_listener_policy` matched the
//!      `(port, family)` AND set `allow_clamp = true`.
//!
//! We overwrite the child's sockaddr in-place via `ptrace::write` so
//! the kernel sees a loopback bind. The original (wildcard) address
//! is recorded in the audit log alongside the rewritten address — Phase E
//! plumbs the dashboard view.
//!
//! Critical: the rewrite must happen at **entry stop**, before the
//! kernel processes the bind. Doing it on exit ("allow then undo")
//! leaves the listener briefly reachable from every network interface
//! — on a public-IP machine that is the entire attack surface for the
//! clamp's lifetime. The work doc explicitly forbids the allow-then-
//! undo pattern.

use crate::error::{Error, Result};
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::os::raw::c_void;

/// Address family of the sockaddr being clamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClampFamily {
    /// AF_INET — clamp to 127.0.0.1.
    V4,
    /// AF_INET6 — clamp to ::1.
    V6,
}

/// Build the on-the-wire bytes of a loopback `sockaddr_in` /
/// `sockaddr_in6` carrying the given port. Exposed so unit tests can
/// exercise the byte pattern without a real ptracee.
///
/// IPv4: 16 bytes — `family(2) | port(2) | sin_addr(4) | sin_zero(8)`.
/// IPv6: 28 bytes — `family(2) | port(2) | flowinfo(4) | sin6_addr(16) | scope_id(4)`.
///
/// The family field is written in native byte order (Linux convention
/// for `sa_family_t`). The port is big-endian (network order). The
/// address payload is built directly from the loopback bit pattern.
pub fn build_loopback_sockaddr_bytes(family: ClampFamily, port: u16) -> Vec<u8> {
    match family {
        ClampFamily::V4 => {
            let mut buf = vec![0u8; 16];
            buf[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&port.to_be_bytes());
            buf[4..8].copy_from_slice(&[127, 0, 0, 1]); // 0x7f000001 net-order
                                                        // sin_zero (bytes 8..16) stays zero.
            buf
        }
        ClampFamily::V6 => {
            let mut buf = vec![0u8; 28];
            buf[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&port.to_be_bytes());
            // flowinfo (bytes 4..8) stays zero.
            // sin6_addr is 16 bytes starting at offset 8. ::1 = 15
            // zero bytes followed by 1.
            buf[8 + 15] = 1;
            // scope_id (bytes 24..28) stays zero.
            buf
        }
    }
}

/// PR 5 Phase D: rewrite the child's sockaddr at `sockaddr_ptr` so
/// the kernel sees a loopback bind on the original port.
///
/// Writes via `ptrace::write` (`PTRACE_POKEDATA`) word-by-word. The
/// caller MUST be at a syscall-entry stop for `bind(2)` on the
/// tracee — performing the write at exit stop leaves the listener
/// briefly reachable from every network interface.
///
/// Returns an error when:
///   - The provided `addrlen` doesn't match the family's expected
///     sockaddr size (16 for v4, 28 for v6) — caller passed inconsistent
///     metadata.
///   - `ptrace::write` fails (process has exited, no PTRACE permission,
///     etc.). The supervisor MUST treat this as fail-closed: deny the
///     syscall rather than allow with no clamp.
pub fn clamp_sockaddr_to_loopback(
    pid: Pid,
    sockaddr_ptr: u64,
    addrlen: u32,
    family: ClampFamily,
    port: u16,
) -> Result<()> {
    let buf = build_loopback_sockaddr_bytes(family, port);
    let expected_len = buf.len() as u32;
    if addrlen < expected_len {
        return Err(Error::InterceptionError(format!(
            "clamp_sockaddr_to_loopback: tracee passed addrlen={addrlen} \
             but {family:?} sockaddr requires {expected_len} bytes; \
             refusing to write a shorter buffer than the tracee allocated",
        )));
    }
    write_tracee_bytes(pid, sockaddr_ptr, &buf)
}

/// Word-by-word ptrace POKEDATA write to the tracee.
///
/// On x86_64 a ptrace word is 8 bytes. For sockaddr_in (16 bytes) we
/// issue 2 writes; for sockaddr_in6 (28 bytes) we issue 4 writes (28
/// rounds up to 32 = 4 words). The final partial word reads-modifies-
/// writes so we don't trample bytes outside the sockaddr.
fn write_tracee_bytes(pid: Pid, base: u64, data: &[u8]) -> Result<()> {
    const WORD: usize = std::mem::size_of::<libc::c_long>();
    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = data.len() - offset;
        let word = if remaining >= WORD {
            let mut chunk = [0u8; WORD];
            chunk.copy_from_slice(&data[offset..offset + WORD]);
            i64::from_ne_bytes(chunk)
        } else {
            // Partial trailing word — read what's there, splice our
            // bytes in, write back. Avoids clobbering the bytes beyond
            // the sockaddr.
            let existing =
                ptrace::read(pid, (base + offset as u64) as *mut c_void).map_err(|e| {
                    Error::InterceptionError(format!(
                        "clamp partial-word read failed at {:#x}: {e}",
                        base + offset as u64
                    ))
                })?;
            let mut chunk = existing.to_ne_bytes();
            chunk[..remaining].copy_from_slice(&data[offset..]);
            i64::from_ne_bytes(chunk)
        };
        ptrace::write(pid, (base + offset as u64) as *mut c_void, word).map_err(|e| {
            Error::InterceptionError(format!(
                "clamp ptrace::write failed at {:#x}: {e}",
                base + offset as u64
            ))
        })?;
        offset += WORD;
    }
    Ok(())
}

/// PR 5 Phase D: capability probe — environment-level signal for the
/// session_start audit line so operators can see whether the clamp
/// feature is usable in this container / host. Logged as
/// `listener_clamp_available = <bool>` at session start.
///
/// Returns `true` when the kernel's YAMA `ptrace_scope` permits
/// ptrace at all (levels 0–2); returns `false` only at level 3 (no
/// ptrace). The supervisor doesn't *act* on this value — every clamp
/// attempt is independently fail-closed (a `ptrace::write` failure
/// denies the syscall), so the probe is purely a heads-up for
/// operators. A future enhancement could downgrade `allow_clamp`
/// across the board when this returns false, switching from
/// fail-closed-per-call to queue-per-call; that's intentionally out of
/// Phase D's scope because the per-call fail-closed already preserves
/// the security invariant ("wildcard bind never proceeds without an
/// authorised clamp").
///
/// **Why YAMA-level signalling, not a real self-write?** Probing
/// `ptrace::write` would require ATTACHing to ourselves with all the
/// ptrace_scope=1 PR_SET_PTRACER dance — overkill for an audit-only
/// signal. The probe stays conservative: any uncertainty returns
/// `true` so we don't hide the supervisor's actual behaviour at
/// runtime.
pub fn clamp_capability_available() -> bool {
    // We're already running ptrace-attached on the tracee — by the
    // time this is called, the supervisor has successfully invoked
    // PTRACE_TRACEME / PTRACE_ATTACH on the child. `ptrace::write`
    // shares the same capability surface. If we can read tracee
    // memory (which the supervisor proves on every event), we can
    // write to it.
    //
    // The probe stays conservative: if any of the YAMA / euid
    // signals say "this won't work", return false.
    //
    // YAMA ptrace_scope levels:
    //   0 — classic ptrace (any process with same uid).
    //   1 — restricted ptrace (only parent or PR_SET_PTRACER target).
    //        We use this; the supervisor IS the parent of the tracee,
    //        so PTRACE_ATTACH already succeeded. Write also works.
    //   2 — admin-only (CAP_SYS_PTRACE).
    //   3 — no ptrace at all.
    //
    // We allow 0 and 1 unconditionally; for 2 we'd need to check
    // CAP_SYS_PTRACE, but the supervisor would have already failed
    // at PTRACE_ATTACH if so. So a simple check of the file suffices.
    match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(s) => {
            let level = s.trim().parse::<i32>().unwrap_or(0);
            level < 3
        }
        // No YAMA on this kernel — classic ptrace semantics apply,
        // and we already proved we can ptrace the tracee.
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_sockaddr_in_layout() {
        let buf = build_loopback_sockaddr_bytes(ClampFamily::V4, 0x1234);
        assert_eq!(buf.len(), 16);
        // AF_INET = 2.
        assert_eq!(u16::from_ne_bytes([buf[0], buf[1]]), libc::AF_INET as u16);
        // Port 0x1234 in network order is [0x12, 0x34].
        assert_eq!([buf[2], buf[3]], [0x12, 0x34]);
        // sin_addr = 127.0.0.1.
        assert_eq!(&buf[4..8], &[127, 0, 0, 1]);
        // sin_zero must be zero.
        assert!(buf[8..16].iter().all(|&b| b == 0));
    }

    #[test]
    fn loopback_sockaddr_in6_layout() {
        let buf = build_loopback_sockaddr_bytes(ClampFamily::V6, 41234);
        assert_eq!(buf.len(), 28);
        // AF_INET6 = 10.
        assert_eq!(u16::from_ne_bytes([buf[0], buf[1]]), libc::AF_INET6 as u16);
        // Port 41234 in network order.
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 41234);
        // flowinfo (bytes 4..8) must be zero.
        assert!(buf[4..8].iter().all(|&b| b == 0));
        // sin6_addr is 16 bytes at offset 8. ::1 means 15 zeros then 1.
        assert!(buf[8..23].iter().all(|&b| b == 0));
        assert_eq!(buf[23], 1);
        // scope_id (bytes 24..28) must be zero.
        assert!(buf[24..28].iter().all(|&b| b == 0));
    }

    #[test]
    fn loopback_sockaddr_port_zero() {
        let buf = build_loopback_sockaddr_bytes(ClampFamily::V4, 0);
        // Port 0 → both bytes zero. Loopback address still correct.
        assert_eq!([buf[2], buf[3]], [0, 0]);
        assert_eq!(&buf[4..8], &[127, 0, 0, 1]);
    }

    #[test]
    fn loopback_sockaddr_high_port() {
        // 65535 is the max port; tests boundary handling.
        let buf = build_loopback_sockaddr_bytes(ClampFamily::V4, 65535);
        assert_eq!([buf[2], buf[3]], [0xff, 0xff]);
    }

    #[test]
    fn capability_probe_returns_bool_without_panic() {
        // The probe must always return some bool; we don't assert
        // the value because it depends on the host kernel's YAMA
        // setting. The point is that it doesn't panic and returns
        // a stable result.
        let _ = clamp_capability_available();
    }

    #[test]
    fn ipv6_byte_pattern_matches_struct_layout() {
        // Manual cross-check that our offsets match the struct
        // layout defined by Linux's <netinet/in.h>:
        //   struct sockaddr_in6 {
        //       sa_family_t     sin6_family;   /* 2 */
        //       in_port_t       sin6_port;     /* 2 */
        //       uint32_t        sin6_flowinfo; /* 4 */
        //       struct in6_addr sin6_addr;     /* 16 */
        //       uint32_t        sin6_scope_id; /* 4 */
        //   };
        // Total = 2 + 2 + 4 + 16 + 4 = 28 bytes.
        assert_eq!(std::mem::size_of::<libc::sockaddr_in6>(), 28);
        let buf = build_loopback_sockaddr_bytes(ClampFamily::V6, 0);
        assert_eq!(buf.len(), std::mem::size_of::<libc::sockaddr_in6>());
    }

    #[test]
    fn ipv4_byte_pattern_matches_struct_layout() {
        // struct sockaddr_in:
        //   sa_family_t    sin_family;  /* 2 */
        //   in_port_t      sin_port;    /* 2 */
        //   struct in_addr sin_addr;    /* 4 */
        //   unsigned char  sin_zero[8]; /* 8 */
        // Total = 16 bytes.
        assert_eq!(std::mem::size_of::<libc::sockaddr_in>(), 16);
        let buf = build_loopback_sockaddr_bytes(ClampFamily::V4, 0);
        assert_eq!(buf.len(), std::mem::size_of::<libc::sockaddr_in>());
    }
}
