// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Seccomp-BPF pre-filter for the Linux ptrace supervisor.
//!
//! Installs a BPF program that returns `SECCOMP_RET_TRACE` for
//! security-relevant syscalls and `SECCOMP_RET_ALLOW` for everything
//! else. When combined with `PTRACE_O_TRACESECCOMP`, this means the
//! tracer only gets ptrace stops for the ~21 syscalls it cares about,
//! instead of stopping on every single syscall (hundreds of thousands
//! during Node.js startup).
//!
//! This module is called from the child process after `PTRACE_TRACEME`
//! and before `execve`.

#![cfg(target_os = "linux")]

use nix::libc;

use super::SECURITY_RELEVANT;

/// Syscall numbers that are handled by ptrace events (PTRACE_O_TRACE*)
/// rather than seccomp. These are excluded from the seccomp filter because:
/// - EXECVE: handled by PTRACE_EVENT_EXEC. Installing SECCOMP_RET_TRACE
///   for execve before PTRACE_O_TRACESECCOMP is set causes ENOSYS.
/// - CLONE/FORK: handled by PTRACE_EVENT_CLONE/FORK/VFORK.
const PTRACE_EVENT_HANDLED: &[i64] = &[
    super::syscall_nr::EXECVE,   // 59
    super::syscall_nr::EXECVEAT, // 322 — also triggers PTRACE_EVENT_EXEC
    super::syscall_nr::CLONE,    // 56
    super::syscall_nr::FORK,     // 57
];

// ── BPF constants ──────────────────────────────────────────────────────

// Instruction classes
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

// ld/st sizes
const BPF_W: u16 = 0x00;

// ld/st modes
const BPF_ABS: u16 = 0x20;

// alu/jmp source
const BPF_K: u16 = 0x00;

// jmp opcodes
const BPF_JEQ: u16 = 0x10;

// seccomp return values
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;

// seccomp data offsets (for x86_64 little-endian)
// offsetof(struct seccomp_data, nr) = 0
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
// offsetof(struct seccomp_data, arch) = 4
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

// x86_64 audit arch value
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

// seccomp operations
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
// Flag: sync filter to all threads
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;

/// A single BPF instruction.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilterInst {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program header passed to seccomp().
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilterInst,
}

fn bpf_stmt(code: u16, k: u32) -> SockFilterInst {
    SockFilterInst {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilterInst {
    SockFilterInst { code, jt, jf, k }
}

/// Build and install a seccomp-BPF filter that returns `SECCOMP_RET_TRACE`
/// for security-relevant syscalls and `SECCOMP_RET_ALLOW` for all others.
///
/// # Safety
///
/// Must be called in the child process after `PTRACE_TRACEME` and before
/// `execve`. The BPF program is static and validated at build time.
///
/// # Panics
///
/// Panics if `prctl(PR_SET_NO_NEW_PRIVS)` or `seccomp(SET_MODE_FILTER)`
/// fails, since the child cannot safely continue without the filter.
pub(super) fn install_seccomp_filter() {
    // PR_SET_NO_NEW_PRIVS is required before installing a seccomp filter
    // without CAP_SYS_ADMIN.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    assert!(ret == 0, "PR_SET_NO_NEW_PRIVS failed: {}", errno());

    let filter = build_filter();
    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            std::ptr::addr_of!(prog),
        )
    };
    // If TSYNC fails (e.g. old kernel), try without it.
    if ret != 0 {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0u64,
                std::ptr::addr_of!(prog),
            )
        };
        assert!(ret == 0, "seccomp(SET_MODE_FILTER) failed: {}", errno());
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// Build the BPF instruction array.
///
/// Structure:
/// 1. Load arch, verify x86_64 (kill if wrong arch)
/// 2. Load syscall number
/// 3. For each security-relevant syscall: JEQ → TRACE
/// 4. Fall through → ALLOW
fn build_filter() -> Vec<SockFilterInst> {
    let seccomp_syscalls: Vec<i64> = SECURITY_RELEVANT
        .iter()
        .copied()
        .filter(|nr| !PTRACE_EVENT_HANDLED.contains(nr))
        .collect();
    let num_relevant = seccomp_syscalls.len();
    // Total instructions: 2 (arch check) + 1 (load nr) + num_relevant (JEQ checks) + 2 (TRACE + ALLOW)
    let total = 2 + 1 + num_relevant + 2;
    let mut filter = Vec::with_capacity(total);

    // [0] Load architecture
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));

    // [1] Verify x86_64 — if not, allow (we can't interpret syscall numbers)
    // Jump to ALLOW (last instruction) if arch doesn't match.
    let allow_offset = (num_relevant + 1) as u8; // skip load_nr + all JEQs to reach ALLOW
    filter.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64,
        0,            // jt: continue to next instruction
        allow_offset, // jf: jump to ALLOW
    ));

    // [2] Load syscall number
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

    // [3..3+N] For each security-relevant syscall, jump to TRACE if match
    for (i, &nr) in seccomp_syscalls.iter().enumerate() {
        let remaining = num_relevant - i - 1; // JEQs remaining after this one
        let trace_offset = (remaining + 1) as u8; // skip remaining JEQs + ALLOW to reach TRACE
        filter.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            nr as u32,
            trace_offset, // jt: jump to TRACE
            0,            // jf: continue to next JEQ
        ));
    }

    // [3+N] ALLOW — default for non-security-relevant syscalls
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // [3+N+1] TRACE — for security-relevant syscalls
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_TRACE));

    debug_assert_eq!(filter.len(), total);
    filter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_has_correct_length() {
        let filter = build_filter();
        let seccomp_count = SECURITY_RELEVANT
            .iter()
            .filter(|nr| !PTRACE_EVENT_HANDLED.contains(nr))
            .count();
        let expected = 2 + 1 + seccomp_count + 2;
        assert_eq!(filter.len(), expected);
    }

    #[test]
    fn filter_starts_with_arch_check() {
        let filter = build_filter();
        // First instruction: load arch
        assert_eq!(filter[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(filter[0].k, SECCOMP_DATA_ARCH_OFFSET);
    }

    #[test]
    fn filter_ends_with_allow_then_trace() {
        let filter = build_filter();
        let n = filter.len();
        // Second-to-last: ALLOW
        assert_eq!(filter[n - 2].code, BPF_RET | BPF_K);
        assert_eq!(filter[n - 2].k, SECCOMP_RET_ALLOW);
        // Last: TRACE
        assert_eq!(filter[n - 1].code, BPF_RET | BPF_K);
        assert_eq!(filter[n - 1].k, SECCOMP_RET_TRACE);
    }

    #[test]
    fn filter_jeq_offsets_are_valid() {
        let filter = build_filter();
        let n = filter.len();
        let num_relevant = SECURITY_RELEVANT
            .iter()
            .filter(|nr| !PTRACE_EVENT_HANDLED.contains(nr))
            .count();

        // Arch check: jf should jump to ALLOW (index n-2)
        // From index 1, jf offset should reach index n-2
        let arch_jf = filter[1].jf as usize;
        assert_eq!(1 + 1 + arch_jf, n - 2, "arch check jf should reach ALLOW");

        // Each JEQ for syscall numbers: jt should reach TRACE (index n-1)
        for i in 0..num_relevant {
            let inst_idx = 3 + i;
            let jt = filter[inst_idx].jt as usize;
            assert_eq!(
                inst_idx + 1 + jt,
                n - 1,
                "JEQ at index {inst_idx} jt should reach TRACE"
            );
        }
    }

    #[test]
    fn filter_covers_seccomp_syscalls() {
        let filter = build_filter();
        let seccomp_syscalls: Vec<i64> = SECURITY_RELEVANT
            .iter()
            .copied()
            .filter(|nr| !PTRACE_EVENT_HANDLED.contains(nr))
            .collect();
        let jeq_nrs: Vec<u32> = filter[3..3 + seccomp_syscalls.len()]
            .iter()
            .map(|inst| inst.k)
            .collect();
        for &nr in &seccomp_syscalls {
            assert!(
                jeq_nrs.contains(&(nr as u32)),
                "syscall {nr} missing from BPF filter"
            );
        }
    }

    #[test]
    fn filter_excludes_ptrace_event_syscalls() {
        let filter = build_filter();
        let jeq_nrs: Vec<u32> = filter
            .iter()
            .filter(|inst| inst.code == BPF_JMP | BPF_JEQ | BPF_K)
            .map(|inst| inst.k)
            .collect();
        for &nr in PTRACE_EVENT_HANDLED {
            assert!(
                !jeq_nrs.contains(&(nr as u32)),
                "syscall {nr} should NOT be in BPF filter (handled by ptrace events)"
            );
        }
    }
}
