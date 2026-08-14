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
//! Syscalls the filter cannot interpret fail closed: a non-x86_64
//! audit arch (`int 0x80`, a 32-bit exec) or an x32 syscall number
//! (`nr & 0x40000000`) returns `SECCOMP_RET_TRACE` with a non-zero
//! `SECCOMP_RET_DATA` code so the supervisor can deny and audit the
//! attempt without interpreting foreign-ABI registers through the
//! x86_64 syscall table (go-live review B1).
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
const BPF_JGE: u16 = 0x30;

// seccomp return values
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;

/// `SECCOMP_RET_DATA` code carried on the TRACE return for a syscall
/// issued under a non-x86_64 audit arch (i386 `int 0x80` or a 32-bit
/// binary). Read by the supervisor via `PTRACE_GETEVENTMSG` at the
/// seccomp stop; the syscall number in `orig_rax` belongs to a foreign
/// syscall table and must not be classified.
///
/// CAUTION: these marker values collide with the kernel's own
/// `PTRACE_EVENTMSG_SYSCALL_ENTRY` (1) / `PTRACE_EVENTMSG_SYSCALL_EXIT`
/// (2), which ≥5.3 kernels store as the event message at every syscall
/// stop. The message is therefore only meaningful at a genuine seccomp
/// stop — reading it at a syscall stop classified every exit stop as an
/// x32 syscall and hard-denied real work (B1 round 3). Enforced in
/// `classify_foreign_abi`; pinned by the kernel-semantics test
/// `get_syscall_info_distinguishes_entry_from_exit_stops`.
pub(super) const SECCOMP_TRACE_DATA_FOREIGN_ARCH: u32 = 1;

/// `SECCOMP_RET_DATA` code for an x32-ABI syscall: the audit arch is
/// `AUDIT_ARCH_X86_64` but the number carries `X32_SYSCALL_BIT`, so it
/// matches no entry in the x86_64 table. (See the collision CAUTION on
/// `SECCOMP_TRACE_DATA_FOREIGN_ARCH`.)
pub(super) const SECCOMP_TRACE_DATA_X32: u32 = 2;

/// x32 syscall numbers are the x86_64 numbers with bit 30 set.
pub(super) const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// seccomp data offsets (for x86_64 little-endian)
// offsetof(struct seccomp_data, nr) = 0
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
// offsetof(struct seccomp_data, arch) = 4
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

// x86_64 audit arch value
pub(super) const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

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
/// 1. Load arch; on any non-x86_64 arch, fail closed → TRACE with
///    `SECCOMP_TRACE_DATA_FOREIGN_ARCH` (the supervisor denies it)
/// 2. Load syscall number; reject x32 numbers (`nr >= 0x40000000`)
///    → TRACE with `SECCOMP_TRACE_DATA_X32`
/// 3. For each security-relevant syscall: JEQ → TRACE
/// 4. Fall through → ALLOW
///
/// No path from a foreign arch or an x32 number can reach ALLOW: both
/// checks run before the first JEQ and jump directly to dedicated
/// return instructions.
fn build_filter() -> Vec<SockFilterInst> {
    let seccomp_syscalls: Vec<i64> = SECURITY_RELEVANT
        .iter()
        .copied()
        .filter(|nr| !PTRACE_EVENT_HANDLED.contains(nr))
        .collect();
    let num_relevant = seccomp_syscalls.len();
    // Total instructions: 2 (arch check) + 2 (load nr + x32 check)
    // + num_relevant (JEQ checks) + 4 (ALLOW, TRACE, TRACE|foreign, TRACE|x32)
    let total = 2 + 2 + num_relevant + 4;
    // All jump offsets are u8; the largest (arch jf) is num_relevant + 4.
    assert!(
        u8::try_from(num_relevant + 4).is_ok(),
        "seccomp filter too large for 8-bit jump offsets"
    );
    let mut filter = Vec::with_capacity(total);

    // Return-instruction indices (see layout above).
    let allow_idx = 4 + num_relevant;
    let foreign_idx = allow_idx + 2;
    let x32_idx = allow_idx + 3;

    // [0] Load architecture
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));

    // [1] Verify x86_64 — if not, fail closed: TRACE with the
    // foreign-arch data code so the supervisor denies without
    // interpreting the syscall number (which belongs to a foreign
    // syscall table). Never ALLOW what we cannot interpret.
    let foreign_offset = (foreign_idx - 2) as u8; // from instruction [1]+1
    filter.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64,
        0,              // jt: continue to next instruction
        foreign_offset, // jf: jump to TRACE|foreign-arch
    ));

    // [2] Load syscall number
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

    // [3] Reject x32 numbering: arch reads AUDIT_ARCH_X86_64 for x32
    // calls, but the number has bit 30 set and matches no JEQ below —
    // without this check it would fall through to ALLOW.
    let x32_offset = (x32_idx - 4) as u8; // from instruction [3]+1
    filter.push(bpf_jump(
        BPF_JMP | BPF_JGE | BPF_K,
        X32_SYSCALL_BIT,
        x32_offset, // jt: nr >= 0x40000000 → TRACE|x32
        0,          // jf: continue to the JEQ table
    ));

    // [4..4+N] For each security-relevant syscall, jump to TRACE if match
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

    // [4+N] ALLOW — default for non-security-relevant syscalls
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // [4+N+1] TRACE — for security-relevant syscalls
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_TRACE));

    // [4+N+2] TRACE|foreign-arch — fail-closed for non-x86_64 ABIs
    filter.push(bpf_stmt(
        BPF_RET | BPF_K,
        SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_FOREIGN_ARCH,
    ));

    // [4+N+3] TRACE|x32 — fail-closed for x32 syscall numbers
    filter.push(bpf_stmt(
        BPF_RET | BPF_K,
        SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_X32,
    ));

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
        let expected = 2 + 2 + seccomp_count + 4;
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
    fn filter_ends_with_return_block() {
        let filter = build_filter();
        let n = filter.len();
        // Return block layout: ALLOW, TRACE, TRACE|foreign, TRACE|x32.
        assert_eq!(filter[n - 4].code, BPF_RET | BPF_K);
        assert_eq!(filter[n - 4].k, SECCOMP_RET_ALLOW);
        assert_eq!(filter[n - 3].code, BPF_RET | BPF_K);
        assert_eq!(filter[n - 3].k, SECCOMP_RET_TRACE);
        assert_eq!(filter[n - 2].code, BPF_RET | BPF_K);
        assert_eq!(
            filter[n - 2].k,
            SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_FOREIGN_ARCH
        );
        assert_eq!(filter[n - 1].code, BPF_RET | BPF_K);
        assert_eq!(filter[n - 1].k, SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_X32);
    }

    #[test]
    fn filter_jump_offsets_are_valid() {
        let filter = build_filter();
        let n = filter.len();
        let num_relevant = SECURITY_RELEVANT
            .iter()
            .filter(|nr| !PTRACE_EVENT_HANDLED.contains(nr))
            .count();

        // Arch check: jf must reach TRACE|foreign (index n-2), never ALLOW.
        let arch_jf = filter[1].jf as usize;
        assert_eq!(
            1 + 1 + arch_jf,
            n - 2,
            "arch check jf should reach TRACE|foreign-arch"
        );

        // x32 check: jt must reach TRACE|x32 (index n-1).
        let x32_jt = filter[3].jt as usize;
        assert_eq!(3 + 1 + x32_jt, n - 1, "x32 check jt should reach TRACE|x32");
        assert_eq!(filter[3].code, BPF_JMP | BPF_JGE | BPF_K);
        assert_eq!(filter[3].k, X32_SYSCALL_BIT);

        // Each JEQ for syscall numbers: jt should reach TRACE (index n-3)
        for i in 0..num_relevant {
            let inst_idx = 4 + i;
            let jt = filter[inst_idx].jt as usize;
            assert_eq!(
                inst_idx + 1 + jt,
                n - 3,
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
        let jeq_nrs: Vec<u32> = filter[4..4 + seccomp_syscalls.len()]
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

    // ── BPF simulator: fail-closed regression suite (go-live review B1) ──
    // Executes the real `build_filter()` output against synthetic
    // `seccomp_data` and returns the SECCOMP_RET_* value the kernel would
    // apply. Permanent: any layout change that silently turns a fail-closed
    // TRACE into ALLOW fails here.
    fn simulate(filter: &[SockFilterInst], arch: u32, nr: u32) -> u32 {
        let mut acc: u32 = 0;
        let mut pc: usize = 0;
        for _ in 0..10_000 {
            let inst = filter[pc];
            if inst.code == BPF_LD | BPF_W | BPF_ABS {
                acc = if inst.k == SECCOMP_DATA_ARCH_OFFSET {
                    arch
                } else {
                    nr
                };
                pc += 1;
            } else if inst.code == BPF_JMP | BPF_JEQ | BPF_K {
                pc += 1 + if acc == inst.k {
                    inst.jt as usize
                } else {
                    inst.jf as usize
                };
            } else if inst.code == BPF_JMP | BPF_JGE | BPF_K {
                pc += 1 + if acc >= inst.k {
                    inst.jt as usize
                } else {
                    inst.jf as usize
                };
            } else if inst.code == BPF_RET | BPF_K {
                return inst.k;
            } else {
                panic!("unhandled opcode {:#x} at pc {pc}", inst.code);
            }
        }
        panic!("filter did not terminate");
    }

    const AUDIT_ARCH_I386: u32 = 0x4000_0003;
    const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
    const OPENAT_NR: u32 = crate::platform::linux::syscall_nr::OPENAT as u32;

    #[test]
    fn baseline_x86_64_openat_is_traced() {
        let f = build_filter();
        assert_eq!(
            simulate(&f, AUDIT_ARCH_X86_64, OPENAT_NR),
            SECCOMP_RET_TRACE,
            "control: openat on x86_64 must reach plain TRACE"
        );
    }

    #[test]
    fn foreign_arch_never_reaches_allow() {
        let f = build_filter();
        // Boundary/representative syscall numbers: the full 0..=512 range,
        // every security-relevant number, and the x32-bit edges. Under a
        // foreign arch every one of them must return TRACE|foreign — the
        // number belongs to a foreign table and must not be interpreted.
        let mut nrs: Vec<u32> = (0..=512).collect();
        nrs.extend(SECURITY_RELEVANT.iter().map(|&n| n as u32));
        nrs.extend([
            0x3fff_ffff,
            X32_SYSCALL_BIT,
            X32_SYSCALL_BIT | OPENAT_NR,
            u32::MAX,
        ]);
        for arch in [AUDIT_ARCH_I386, AUDIT_ARCH_AARCH64, 0] {
            for &nr in &nrs {
                assert_eq!(
                    simulate(&f, arch, nr),
                    SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_FOREIGN_ARCH,
                    "arch {arch:#x} nr {nr} must fail closed as foreign-arch"
                );
            }
        }
    }

    #[test]
    fn x32_numbers_never_reach_allow() {
        let f = build_filter();
        let mut nrs: Vec<u32> = vec![X32_SYSCALL_BIT, u32::MAX, X32_SYSCALL_BIT | 5];
        nrs.extend(
            SECURITY_RELEVANT
                .iter()
                .map(|&n| n as u32 | X32_SYSCALL_BIT),
        );
        for &nr in &nrs {
            assert_eq!(
                simulate(&f, AUDIT_ARCH_X86_64, nr),
                SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_X32,
                "x32 nr {nr:#x} must fail closed as x32"
            );
        }
    }

    #[test]
    fn x86_64_non_relevant_syscalls_still_allowed() {
        let f = build_filter();
        // Noise syscalls (read/write/close on ordinary fds are the hot
        // path) must keep flowing without a ptrace stop; ptrace-event
        // handled syscalls are ALLOW at the filter and trapped via
        // PTRACE_EVENT_* instead.
        for nr in (0u32..=512).filter(|&nr| {
            !SECURITY_RELEVANT.contains(&(nr as i64)) || PTRACE_EVENT_HANDLED.contains(&(nr as i64))
        }) {
            assert_eq!(
                simulate(&f, AUDIT_ARCH_X86_64, nr),
                SECCOMP_RET_ALLOW,
                "non-relevant x86_64 nr {nr} should stay ALLOW"
            );
        }
    }

    #[test]
    fn x86_64_relevant_syscalls_all_trace() {
        let f = build_filter();
        for &nr in SECURITY_RELEVANT
            .iter()
            .filter(|nr| !PTRACE_EVENT_HANDLED.contains(nr))
        {
            assert_eq!(
                simulate(&f, AUDIT_ARCH_X86_64, nr as u32),
                SECCOMP_RET_TRACE,
                "relevant x86_64 nr {nr} should TRACE"
            );
        }
    }
}
