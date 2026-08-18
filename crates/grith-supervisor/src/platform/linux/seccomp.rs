// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Seccomp-BPF pre-filter for the Linux ptrace supervisor.
//!
//! Installs a BPF program that returns `SECCOMP_RET_TRACE` for
//! security-relevant syscalls and `SECCOMP_RET_ALLOW` for everything
//! else. When combined with `PTRACE_O_TRACESECCOMP`, this means the
//! tracer only gets ptrace stops for the syscalls it cares about,
//! instead of stopping on every single syscall (hundreds of thousands
//! during Node.js startup).
//!
//! Syscalls the filter cannot interpret fail closed: a non-native
//! audit arch (`int 0x80`, a 32-bit exec, compat EL0 on arm64) or — on
//! x86_64 — an x32 syscall number (`nr & 0x40000000`) returns
//! `SECCOMP_RET_TRACE` with a non-zero `SECCOMP_RET_DATA` code so the
//! supervisor can deny and audit the attempt without interpreting
//! foreign-ABI registers through the native syscall table (go-live
//! review B1).
//!
//! The BPF opcode layer and the fail-closed return block are shared;
//! [`build_filter_for`] is parametrised on the native audit-arch value,
//! the trap list, and whether the x32 branch exists (an x86_64-only
//! escape hatch — aarch64 has no x32 analog, and its compat-ARM surface
//! is subsumed by the foreign-arch check).
//!
//! This module is called from the child process after `PTRACE_TRACEME`
//! and before `execve`.

#![cfg(target_os = "linux")]

use nix::libc;

use super::arch;

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
/// issued under a non-native audit arch (i386 `int 0x80`, a 32-bit
/// binary, compat EL0 on arm64). Read by the supervisor via
/// `PTRACE_GETEVENTMSG` at the seccomp stop; the syscall number in the
/// number register belongs to a foreign syscall table and must not be
/// classified.
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
/// `SECCOMP_TRACE_DATA_FOREIGN_ARCH`.) x86_64-only: no other arch has
/// an x32 analog.
pub(super) const SECCOMP_TRACE_DATA_X32: u32 = 2;

/// x32 syscall numbers are the x86_64 numbers with bit 30 set.
pub(super) const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// seccomp data offsets (identical on every little-endian 64-bit arch)
// offsetof(struct seccomp_data, nr) = 0
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
// offsetof(struct seccomp_data, arch) = 4
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

// seccomp operations
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
// Flag: sync filter to all threads
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;

/// Whether the native arch needs the x32 escape-hatch branch. Only
/// x86_64 has a second syscall numbering under its own audit arch.
const NATIVE_HAS_X32: bool = cfg!(target_arch = "x86_64");

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

/// The syscall numbers the seccomp filter traps on this architecture:
/// the security-relevant set minus the ptrace-event-handled syscalls
/// (execve/execveat via `PTRACE_EVENT_EXEC`; clone/fork via
/// `PTRACE_EVENT_CLONE`/`FORK`/`VFORK` — trapping execve before
/// `PTRACE_O_TRACESECCOMP` is set causes ENOSYS).
fn native_trap_nrs() -> &'static [i64] {
    static NRS: std::sync::OnceLock<Vec<i64>> = std::sync::OnceLock::new();
    NRS.get_or_init(|| {
        let event_handled = arch::ptrace_event_handled_nrs();
        arch::security_relevant_nrs()
            .iter()
            .copied()
            .filter(|nr| !event_handled.contains(nr))
            .collect()
    })
}

/// Build the BPF instruction array for the native architecture.
fn build_filter() -> Vec<SockFilterInst> {
    build_filter_for(arch::NATIVE_AUDIT_ARCH, native_trap_nrs(), NATIVE_HAS_X32)
}

/// Force-initialise the lazily-derived per-arch number lists.
///
/// `install_seccomp_filter` runs in the freshly-forked child, where a
/// first-touch `OnceLock` initialisation would allocate post-fork — a
/// deadlock risk if another parent thread held the allocator lock at fork
/// time. Called by the spawn paths in the PARENT, before `fork()`, so the
/// child's build reads only already-initialised statics — the trap list
/// itself is cached, leaving the filter `Vec` as the child's one
/// allocation (the pre-refactor code made two).
pub(super) fn prewarm_filter_tables() {
    let _ = native_trap_nrs();
    debug_assert!(!native_trap_nrs().is_empty());
}

/// Build the BPF instruction array for a given `(native audit arch,
/// trap list, x32 branch)` parameter set.
///
/// Structure:
/// 1. Load arch; on any non-native arch, fail closed → TRACE with
///    `SECCOMP_TRACE_DATA_FOREIGN_ARCH` (the supervisor denies it)
/// 2. Load syscall number; when `x32_check`, reject x32 numbers
///    (`nr >= 0x40000000`) → TRACE with `SECCOMP_TRACE_DATA_X32`
/// 3. For each trapped syscall: JEQ → TRACE
/// 4. Fall through → ALLOW
///
/// No path from a foreign arch (or, on x86_64, an x32 number) can reach
/// ALLOW: the checks run before the first JEQ and jump directly to
/// dedicated return instructions.
fn build_filter_for(native_arch: u32, trap_nrs: &[i64], x32_check: bool) -> Vec<SockFilterInst> {
    let num_relevant = trap_nrs.len();
    // Head: 2 (load arch + check) + 1 (load nr) + 1 if x32_check.
    // Tail: ALLOW, TRACE, TRACE|foreign, + TRACE|x32 if x32_check.
    let head = if x32_check { 4 } else { 3 };
    let returns = if x32_check { 4 } else { 3 };
    let total = head + num_relevant + returns;
    // All jump offsets are u8. The largest emitted offset is the arch
    // check's jf, which jumps from instruction [1] over the rest of the
    // head, the whole JEQ table, ALLOW, and TRACE to land on
    // TRACE|foreign: (head + num_relevant + 2) - 2 = head + num_relevant.
    // Asserted on that exact quantity so a future head-only instruction
    // cannot silently truncate in the `as u8` casts below.
    assert!(
        u8::try_from(head + num_relevant).is_ok(),
        "seccomp filter too large for 8-bit jump offsets"
    );
    let mut filter = Vec::with_capacity(total);

    // Return-instruction indices (see layout above).
    let allow_idx = head + num_relevant;
    let foreign_idx = allow_idx + 2;

    // [0] Load architecture
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));

    // [1] Verify the native arch — if not, fail closed: TRACE with the
    // foreign-arch data code so the supervisor denies without
    // interpreting the syscall number (which belongs to a foreign
    // syscall table). Never ALLOW what we cannot interpret.
    let foreign_offset = (foreign_idx - 2) as u8; // from instruction [1]+1
    filter.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        native_arch,
        0,              // jt: continue to next instruction
        foreign_offset, // jf: jump to TRACE|foreign-arch
    ));

    // [2] Load syscall number
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

    if x32_check {
        // [3] Reject x32 numbering: arch reads AUDIT_ARCH_X86_64 for x32
        // calls, but the number has bit 30 set and matches no JEQ below —
        // without this check it would fall through to ALLOW.
        let x32_idx = allow_idx + 3;
        let x32_offset = (x32_idx - 4) as u8; // from instruction [3]+1
        filter.push(bpf_jump(
            BPF_JMP | BPF_JGE | BPF_K,
            X32_SYSCALL_BIT,
            x32_offset, // jt: nr >= 0x40000000 → TRACE|x32
            0,          // jf: continue to the JEQ table
        ));
    }

    // [head..head+N] For each trapped syscall, jump to TRACE if match
    for (i, &nr) in trap_nrs.iter().enumerate() {
        let remaining = num_relevant - i - 1; // JEQs remaining after this one
        let trace_offset = (remaining + 1) as u8; // skip remaining JEQs + ALLOW to reach TRACE
        filter.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            nr as u32,
            trace_offset, // jt: jump to TRACE
            0,            // jf: continue to next JEQ
        ));
    }

    // [head+N] ALLOW — default for non-security-relevant syscalls
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // [head+N+1] TRACE — for security-relevant syscalls
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_TRACE));

    // [head+N+2] TRACE|foreign-arch — fail-closed for non-native ABIs
    filter.push(bpf_stmt(
        BPF_RET | BPF_K,
        SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_FOREIGN_ARCH,
    ));

    if x32_check {
        // [head+N+3] TRACE|x32 — fail-closed for x32 syscall numbers
        filter.push(bpf_stmt(
            BPF_RET | BPF_K,
            SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_X32,
        ));
    }

    debug_assert_eq!(filter.len(), total);
    filter
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trap_nrs() -> Vec<i64> {
        native_trap_nrs().to_vec()
    }

    #[test]
    fn filter_has_correct_length() {
        let filter = build_filter();
        let head = if NATIVE_HAS_X32 { 4 } else { 3 };
        let returns = if NATIVE_HAS_X32 { 4 } else { 3 };
        let expected = head + trap_nrs().len() + returns;
        assert_eq!(filter.len(), expected);
    }

    #[test]
    fn filter_starts_with_arch_check() {
        let filter = build_filter();
        // First instruction: load arch
        assert_eq!(filter[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(filter[0].k, SECCOMP_DATA_ARCH_OFFSET);
        // Second: compare against the native audit arch.
        assert_eq!(filter[1].code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(filter[1].k, arch::NATIVE_AUDIT_ARCH);
    }

    #[test]
    fn filter_ends_with_return_block() {
        let filter = build_filter_for(arch::NATIVE_AUDIT_ARCH, &trap_nrs(), true);
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
    fn no_x32_filter_ends_with_three_returns_and_no_x32_instructions() {
        let nrs = trap_nrs();
        let filter = build_filter_for(AUDIT_ARCH_AARCH64, &nrs, false);
        let n = filter.len();
        assert_eq!(n, 3 + nrs.len() + 3);
        assert_eq!(filter[n - 3].k, SECCOMP_RET_ALLOW);
        assert_eq!(filter[n - 2].k, SECCOMP_RET_TRACE);
        assert_eq!(
            filter[n - 1].k,
            SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_FOREIGN_ARCH
        );
        // No instruction references the x32 marker bit or the x32 return.
        for inst in &filter {
            assert_ne!(inst.k, X32_SYSCALL_BIT, "x32 JGE must not be emitted");
            assert_ne!(
                inst.k,
                SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_X32,
                "x32 return must not be emitted"
            );
        }
    }

    #[test]
    fn filter_jump_offsets_are_valid() {
        let filter = build_filter_for(arch::NATIVE_AUDIT_ARCH, &trap_nrs(), true);
        let n = filter.len();
        let num_relevant = trap_nrs().len();

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
    fn no_x32_filter_jump_offsets_are_valid() {
        let nrs = trap_nrs();
        let filter = build_filter_for(AUDIT_ARCH_AARCH64, &nrs, false);
        let n = filter.len();

        // Arch check: jf must reach TRACE|foreign (index n-1), never ALLOW.
        let arch_jf = filter[1].jf as usize;
        assert_eq!(
            1 + 1 + arch_jf,
            n - 1,
            "arch check jf should reach TRACE|foreign-arch"
        );

        // Each JEQ: jt should reach TRACE (index n-2).
        for i in 0..nrs.len() {
            let inst_idx = 3 + i;
            let jt = filter[inst_idx].jt as usize;
            assert_eq!(
                inst_idx + 1 + jt,
                n - 2,
                "JEQ at index {inst_idx} jt should reach TRACE"
            );
        }
    }

    #[test]
    fn filter_covers_seccomp_syscalls() {
        let filter = build_filter();
        let seccomp_syscalls = trap_nrs();
        let head = if NATIVE_HAS_X32 { 4 } else { 3 };
        let jeq_nrs: Vec<u32> = filter[head..head + seccomp_syscalls.len()]
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
        for &nr in arch::ptrace_event_handled_nrs() {
            assert!(
                !jeq_nrs.contains(&(nr as u32)),
                "syscall {nr} should NOT be in BPF filter (handled by ptrace events)"
            );
        }
    }

    // ── BPF simulator: fail-closed regression suite (go-live review B1) ──
    // Executes the real `build_filter_for()` output against synthetic
    // `seccomp_data` and returns the SECCOMP_RET_* value the kernel would
    // apply. Permanent: any layout change that silently turns a fail-closed
    // TRACE into ALLOW fails here. Runs against BOTH parameter shapes (with
    // and without the x32 branch) so the aarch64 filter is exercised on
    // x86 hosts.
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
    const AUDIT_ARCH_ARM: u32 = 0x4000_0028;

    fn openat_nr() -> u32 {
        arch::nr_of(arch::SysId::Openat).expect("openat exists on every arch") as u32
    }

    #[test]
    fn baseline_native_openat_is_traced() {
        let f = build_filter();
        assert_eq!(
            simulate(&f, arch::NATIVE_AUDIT_ARCH, openat_nr()),
            SECCOMP_RET_TRACE,
            "control: openat on the native arch must reach plain TRACE"
        );
    }

    #[test]
    fn foreign_arch_never_reaches_allow() {
        // Boundary/representative syscall numbers: the full 0..=512 range,
        // every trapped number, and the x32-bit edges. Under a foreign arch
        // every one of them must return TRACE|foreign — the number belongs
        // to a foreign table and must not be interpreted. Exercised for both
        // builder shapes.
        let mut nrs: Vec<u32> = (0..=512).collect();
        nrs.extend(trap_nrs().iter().map(|&n| n as u32));
        nrs.extend([
            0x3fff_ffff,
            X32_SYSCALL_BIT,
            X32_SYSCALL_BIT | openat_nr(),
            u32::MAX,
        ]);
        let shapes = [
            (
                build_filter_for(arch::NATIVE_AUDIT_ARCH, &trap_nrs(), true),
                arch::NATIVE_AUDIT_ARCH,
            ),
            (
                build_filter_for(AUDIT_ARCH_AARCH64, &trap_nrs(), false),
                AUDIT_ARCH_AARCH64,
            ),
        ];
        for (f, native) in &shapes {
            for foreign in [
                AUDIT_ARCH_I386,
                AUDIT_ARCH_AARCH64,
                AUDIT_ARCH_ARM,
                0,
                0xc000_003e,
            ] {
                if foreign == *native {
                    continue;
                }
                for &nr in &nrs {
                    assert_eq!(
                        simulate(f, foreign, nr),
                        SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_FOREIGN_ARCH,
                        "arch {foreign:#x} nr {nr} must fail closed as foreign-arch (native {native:#x})"
                    );
                }
            }
        }
    }

    #[test]
    fn x32_numbers_never_reach_allow() {
        let f = build_filter_for(arch::NATIVE_AUDIT_ARCH, &trap_nrs(), true);
        let mut nrs: Vec<u32> = vec![X32_SYSCALL_BIT, u32::MAX, X32_SYSCALL_BIT | 5];
        nrs.extend(trap_nrs().iter().map(|&n| n as u32 | X32_SYSCALL_BIT));
        for &nr in &nrs {
            assert_eq!(
                simulate(&f, arch::NATIVE_AUDIT_ARCH, nr),
                SECCOMP_RET_TRACE | SECCOMP_TRACE_DATA_X32,
                "x32 nr {nr:#x} must fail closed as x32"
            );
        }
    }

    #[test]
    fn native_non_relevant_syscalls_still_allowed() {
        // Noise syscalls (read/write/close on ordinary fds are the hot
        // path) must keep flowing without a ptrace stop; ptrace-event
        // handled syscalls are ALLOW at the filter and trapped via
        // PTRACE_EVENT_* instead. Both builder shapes.
        let shapes = [
            (
                build_filter_for(arch::NATIVE_AUDIT_ARCH, &trap_nrs(), true),
                arch::NATIVE_AUDIT_ARCH,
            ),
            (
                build_filter_for(AUDIT_ARCH_AARCH64, &trap_nrs(), false),
                AUDIT_ARCH_AARCH64,
            ),
        ];
        let trapped = trap_nrs();
        for (f, native) in &shapes {
            for nr in (0u32..=512).filter(|&nr| !trapped.contains(&(nr as i64))) {
                assert_eq!(
                    simulate(f, *native, nr),
                    SECCOMP_RET_ALLOW,
                    "non-relevant nr {nr} should stay ALLOW (native {native:#x})"
                );
            }
        }
    }

    #[test]
    fn native_relevant_syscalls_all_trace() {
        let shapes = [
            (
                build_filter_for(arch::NATIVE_AUDIT_ARCH, &trap_nrs(), true),
                arch::NATIVE_AUDIT_ARCH,
            ),
            (
                build_filter_for(AUDIT_ARCH_AARCH64, &trap_nrs(), false),
                AUDIT_ARCH_AARCH64,
            ),
        ];
        for (f, native) in &shapes {
            for &nr in &trap_nrs() {
                assert_eq!(
                    simulate(f, *native, nr as u32),
                    SECCOMP_RET_TRACE,
                    "relevant nr {nr} should TRACE (native {native:#x})"
                );
            }
        }
    }
}
