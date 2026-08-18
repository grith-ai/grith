// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! aarch64 register primitives for the Linux ptrace backend.
//!
//! AAPCS64 syscall ABI:
//!
//! | Register | Purpose at syscall-entry     |
//! |----------|------------------------------|
//! | `x8`     | Syscall number               |
//! | `x0..x5` | Arguments 1-6                |
//! | `x0`     | Return value at syscall-exit |
//!
//! # Why raw `GETREGSET`/`SETREGSET` instead of nix wrappers
//!
//! arm64 has no `PTRACE_GETREGS`/`SETREGS`; register access goes through
//! `PTRACE_GETREGSET(NT_PRSTATUS)` with an iovec. nix 0.29 wraps that only
//! on gnu targets — on `aarch64-unknown-linux-musl` (the release target) it
//! provides *neither* API — and `libc::user_regs_struct` availability varies
//! by libc. This module therefore defines its own kernel-shaped
//! [`UserPtRegs`] and calls `libc::ptrace` directly; one implementation
//! covers gnu and musl identically (work/78 §2.4).
//!
//! # Deny mechanics (work/78 §2.3, verified against v6.6
//! `arch/arm64/kernel/syscall.c`)
//!
//! The kernel latches the syscall number at entry, so writing `x8` cannot
//! skip a syscall. The de-facto standard skip is writing the 4-byte
//! `NT_ARM_SYSTEM_CALL` regset with -1 (`NO_SYSCALL`), then seeding
//! `x0 = -errno` via `NT_PRSTATUS`. The kernel's `-ENOSYS` pre-seed happens
//! only for a *user-issued* `syscall(-1)` before the trace stop; a
//! tracer-written -1 takes the `goto trace_exit` path, which never touches
//! `x0`, so the tracee observes exactly `-errno` (EPERM, not ENOSYS —
//! errno identity is load-bearing for the failed-exec/-connect suppressions
//! and for supervised-tool behavior; pinned by the PR D deny-errno test).
//!
//! # Kernel floor
//!
//! The aarch64 backend requires `PTRACE_GET_SYSCALL_INFO` (kernel >= 5.3),
//! probed at session start via [`verify_kernel_support`]. The pre-5.3
//! x86 fallbacks (`PTRACE_GETEVENTMSG` seccomp marker, the `rax == -ENOSYS`
//! entry heuristic) are meaningless on arm64 — `x0` holds arg0 at entry —
//! and are compiled out. Register-file reads remain as the fallback for
//! stops that carry no syscall-info record (`PTRACE_EVENT_*` stops).

#![cfg(target_os = "linux")]
// The identity table below compiles on EVERY arch so its integrity tests run
// on x86 hosts and in the cross-check CI job; only the ptrace register
// primitives are aarch64-gated (see the per-item cfg attributes).

#[cfg(target_arch = "aarch64")]
use nix::libc;
#[cfg(target_arch = "aarch64")]
use nix::unistd::Pid;
#[cfg(target_arch = "aarch64")]
use tracing::trace;

#[cfg(target_arch = "aarch64")]
use crate::error::{Error, Result};

#[cfg(target_arch = "aarch64")]
use super::{SyscallInfoResult, SyscallRegs};

/// The aarch64 native audit-arch value (`AUDIT_ARCH_AARCH64`,
/// uapi/linux/audit.h): EM_AARCH64 (183) | __AUDIT_ARCH_64BIT |
/// __AUDIT_ARCH_LE.
pub(crate) const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;

#[cfg(target_arch = "aarch64")]
/// `ptrace(2)` regset requests (uapi/linux/ptrace.h).
const PTRACE_GETREGSET: libc::c_int = 0x4204;
#[cfg(target_arch = "aarch64")]
const PTRACE_SETREGSET: libc::c_int = 0x4205;

#[cfg(target_arch = "aarch64")]
/// ELF note types selecting the regset (uapi/linux/elf.h).
const NT_PRSTATUS: libc::c_int = 1;
#[cfg(target_arch = "aarch64")]
/// The 4-byte arm64 syscall-number regset — the only way a tracer can
/// change (or cancel) the latched syscall number.
const NT_ARM_SYSTEM_CALL: libc::c_int = 0x404;

#[cfg(target_arch = "aarch64")]
/// Kernel `struct user_pt_regs` (arch/arm64/include/uapi/asm/ptrace.h).
/// Defined here rather than via `libc::user_regs_struct`, which is not
/// available on all aarch64 libc/env combinations (musl).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct UserPtRegs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[cfg(target_arch = "aarch64")]
/// `PTRACE_GETREGSET(NT_PRSTATUS)`. `Ok(None)` = tracee gone (ESRCH).
fn getregset_prstatus(pid: Pid) -> Result<Option<UserPtRegs>> {
    let mut regs = UserPtRegs::default();
    let mut iov = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(regs).cast(),
        iov_len: std::mem::size_of::<UserPtRegs>(),
    };
    // SAFETY: `regs` is a live, correctly-aligned allocation; the iovec
    // length caps how much the kernel writes.
    let ret = unsafe {
        libc::ptrace(
            // `as _`: the request parameter is `c_uint` on glibc but `c_int`
            // on musl — same pattern as the syscall-info reads.
            PTRACE_GETREGSET as _,
            pid.as_raw(),
            NT_PRSTATUS,
            std::ptr::addr_of_mut!(iov),
        )
    };
    if ret < 0 {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => {
                trace!(
                    pid = pid.as_raw(),
                    event = "tracee_gone_at_stop",
                    "PTRACE_GETREGSET: tracee gone (ESRCH); treating stop as stale"
                );
                Ok(None)
            }
            e => Err(Error::InterceptionError(format!(
                "PTRACE_GETREGSET(NT_PRSTATUS) failed for pid {pid}: errno {e:?}"
            ))),
        };
    }
    // The kernel clamps iov_len to the tracee's regset view and writes the
    // real length back. A 32-bit compat EL0 tracee's NT_PRSTATUS is the
    // 72-byte compat_gpr view — interpreting it as user_pt_regs would read
    // garbage (compat r16|r17 where x8 belongs). Fail explicitly instead;
    // compat tracees are wholesale fail-closed via CompatArch anyway.
    if iov.iov_len != std::mem::size_of::<UserPtRegs>() {
        return Err(Error::InterceptionError(format!(
            "PTRACE_GETREGSET(NT_PRSTATUS) for pid {pid} returned {} bytes (expected {}): \
             tracee register view is not native aarch64 (32-bit compat EL0?)",
            iov.iov_len,
            std::mem::size_of::<UserPtRegs>()
        )));
    }
    Ok(Some(regs))
}

#[cfg(target_arch = "aarch64")]
/// `PTRACE_SETREGSET(NT_PRSTATUS)`. `Ok(false)` = tracee gone (ESRCH).
fn setregset_prstatus(pid: Pid, regs: &UserPtRegs) -> Result<bool> {
    let mut copy = *regs;
    let mut iov = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(copy).cast(),
        iov_len: std::mem::size_of::<UserPtRegs>(),
    };
    // SAFETY: `copy` is live and correctly aligned for the write-back.
    let ret = unsafe {
        libc::ptrace(
            PTRACE_SETREGSET as _,
            pid.as_raw(),
            NT_PRSTATUS,
            std::ptr::addr_of_mut!(iov),
        )
    };
    if ret < 0 {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            e => Err(Error::InterceptionError(format!(
                "PTRACE_SETREGSET(NT_PRSTATUS) failed for pid {pid}: errno {e:?}"
            ))),
        };
    }
    Ok(true)
}

#[cfg(target_arch = "aarch64")]
/// Write the 4-byte `NT_ARM_SYSTEM_CALL` regset — the arm64 mechanism for
/// changing the latched syscall number. `Ok(false)` = tracee gone.
fn set_syscall_number(pid: Pid, nr: i32) -> Result<bool> {
    let mut value: i32 = nr;
    let mut iov = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(value).cast(),
        iov_len: std::mem::size_of::<i32>(),
    };
    // SAFETY: `value` is a live 4-byte allocation matching the regset size.
    let ret = unsafe {
        libc::ptrace(
            PTRACE_SETREGSET as _,
            pid.as_raw(),
            NT_ARM_SYSTEM_CALL,
            std::ptr::addr_of_mut!(iov),
        )
    };
    if ret < 0 {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            e => Err(Error::InterceptionError(format!(
                "PTRACE_SETREGSET(NT_ARM_SYSTEM_CALL) failed for pid {pid}: errno {e:?}"
            ))),
        };
    }
    Ok(true)
}

#[cfg(target_arch = "aarch64")]
/// Read the register file, mapped into the arch-neutral [`SyscallRegs`]
/// view. Fallback source for stops that carry no syscall-info record
/// (`PTRACE_EVENT_*` stops — e.g. the clone-flag read at a
/// `PTRACE_EVENT_CLONE` stop, where `x0` still holds arg0 because the
/// kernel writes the return value into `pt_regs` only after the syscall
/// function returns).
///
/// `retval_hint` stays `None`: it exists solely for the x86 pre-5.3
/// entry/exit heuristic, which is compiled out on aarch64 (`x0` holds arg0
/// at entry, so the heuristic would be reading an argument).
pub(crate) fn read_syscall_regs_fallback(pid: Pid) -> Result<Option<SyscallRegs>> {
    let Some(regs) = getregset_prstatus(pid)? else {
        return Ok(None);
    };
    Ok(Some(SyscallRegs {
        nr: regs.regs[8] as i64,
        args: [
            regs.regs[0],
            regs.regs[1],
            regs.regs[2],
            regs.regs[3],
            regs.regs[4],
            regs.regs[5],
        ],
        ip: regs.pc,
        sp: regs.sp,
        retval_hint: None,
    }))
}

#[cfg(target_arch = "aarch64")]
/// Read the syscall return value at an exit stop (`x0`). Fallback source
/// when the `PTRACE_GET_SYSCALL_INFO` EXIT record is unavailable.
pub(crate) fn read_return_value_fallback(pid: Pid) -> Result<Option<i64>> {
    Ok(getregset_prstatus(pid)?.map(|regs| regs.regs[0] as i64))
}

#[cfg(target_arch = "aarch64")]
/// Best-effort read of the raw native syscall number for forensics.
/// Prefers the kernel's syscall-info record (guaranteed >= 5.3 on this
/// backend); falls back to `x8`. `None` on any failure — callers record -1.
pub(crate) fn read_raw_syscall_nr(pid: Pid) -> Option<i64> {
    match super::get_syscall_info(pid) {
        SyscallInfoResult::Info(info)
            if info.op == super::PTRACE_SYSCALL_INFO_ENTRY
                || info.op == super::PTRACE_SYSCALL_INFO_SECCOMP =>
        {
            Some(info.data[0] as i64)
        }
        SyscallInfoResult::TraceeGone => None,
        _ => getregset_prstatus(pid)
            .ok()
            .flatten()
            .map(|regs| regs.regs[8] as i64),
    }
}

#[cfg(target_arch = "aarch64")]
/// Skip the syscall a tracee is entering and make it observe `-errno`.
///
/// arm64 mechanics (work/78 §2.3): write `NT_ARM_SYSTEM_CALL = -1`
/// (`NO_SYSCALL` — the number was latched at entry, so writing `x8` would
/// not work), then seed `x0 = -errno` via `NT_PRSTATUS`. The kernel's
/// trace-exit path never touches `x0` for a tracer-cancelled syscall, so
/// the tracee observes exactly `-errno`.
///
/// Must be called at a syscall-entry (or seccomp) stop. Returns `Ok(false)`
/// when the tracee died in its stop (the denial is vacuously enforced —
/// never fatal, since this is also the fail-closed classify-error path).
pub(crate) fn deny_syscall(pid: Pid, errno: i32) -> Result<bool> {
    if !set_syscall_number(pid, -1)? {
        trace!(
            pid = pid.as_raw(),
            event = "tracee_gone_at_stop",
            "NT_ARM_SYSTEM_CALL (deny): tracee gone (ESRCH); denial vacuously enforced"
        );
        return Ok(false);
    }
    let mut regs = match getregset_prstatus(pid) {
        Ok(Some(regs)) => regs,
        // Died between the two writes: the syscall is already cancelled.
        Ok(None) => return Ok(false),
        // Non-native register view (32-bit compat EL0) or another read
        // failure AFTER the cancel landed: the syscall can no longer
        // execute, so the denial holds — the tracee just observes the
        // kernel's default return for a cancelled syscall instead of the
        // seeded EPERM. Seeding through the 72-byte compat view is
        // deliberately not implemented: compat binaries are wholesale
        // fail-closed (CompatArch), and writing a native-sized regset over
        // a compat view would clobber sibling registers.
        Err(error) => {
            trace!(
                pid = pid.as_raw(),
                %error,
                "deny: syscall cancelled but errno seed skipped (non-native register view?)"
            );
            return Ok(true);
        }
    };
    regs.regs[0] = -(errno as i64) as u64;
    setregset_prstatus(pid, &regs)
}

// ---------------------------------------------------------------------------
// aarch64 syscall identity table
// ---------------------------------------------------------------------------

/// Syscall numbers for the aarch64 Linux ABI, from the asm-generic table
/// (`include/uapi/asm-generic/unistd.h`; arm64 defines
/// `__ARCH_WANT_RENAMEAT`, so `renameat` exists).
///
/// Bare numbers only: the per-syscall security rationale lives on the
/// arch-neutral [`SysId`] declaration in `arch/mod.rs`. Every number here is
/// pinned by the expected-numbers test below; the 14 legacy identities the
/// asm-generic table dropped (`open`, `creat`, `dup2`, `pipe`, `fork`,
/// `rename`, `mkdir`, `rmdir`, `unlink`, `chmod`, `chown`, `lchown`,
/// `symlink`, `link`) and the x86-only `iopl`/`ioperm` are simply absent —
/// arm64 libcs can only emit the modern `*at` forms, so this is not a
/// coverage gap (work/78 §2.5).
pub(crate) mod syscall_nr {
    pub const READ: i64 = 63;
    pub const WRITE: i64 = 64;
    pub const WRITEV: i64 = 66;
    pub const CLOSE: i64 = 57;
    pub const MMAP: i64 = 222;
    pub const SOCKET: i64 = 198;
    pub const CONNECT: i64 = 203;
    pub const SENDTO: i64 = 206;
    pub const RECVFROM: i64 = 207;
    pub const SENDMSG: i64 = 211;
    pub const RECVMSG: i64 = 212;
    pub const DUP: i64 = 23;
    pub const FCNTL: i64 = 25;
    pub const SENDMMSG: i64 = 269;
    pub const RECVMMSG: i64 = 243;
    pub const DUP3: i64 = 24;
    pub const CLOSE_RANGE: i64 = 436;
    pub const CLONE3: i64 = 435;
    pub const SECCOMP: i64 = 277;
    pub const PRCTL: i64 = 167;
    pub const BIND: i64 = 200;
    pub const SOCKETPAIR: i64 = 199;
    pub const CLONE: i64 = 220;
    pub const EXECVE: i64 = 221;
    pub const FCHMOD: i64 = 52;
    pub const GETDENTS64: i64 = 61;
    pub const OPENAT: i64 = 56;
    pub const OPENAT2: i64 = 437;
    pub const TRUNCATE: i64 = 45;
    pub const FTRUNCATE: i64 = 46;
    pub const SYMLINKAT: i64 = 36;
    pub const LINKAT: i64 = 37;
    pub const MKDIRAT: i64 = 34;
    pub const UNLINKAT: i64 = 35;
    pub const RENAMEAT: i64 = 38;
    pub const FCHMODAT: i64 = 53;
    pub const PIPE2: i64 = 59;
    pub const RENAMEAT2: i64 = 276;
    pub const IO_URING_SETUP: i64 = 425;
    pub const IO_URING_ENTER: i64 = 426;
    pub const IO_URING_REGISTER: i64 = 427;
    pub const SENDFILE: i64 = 71;
    pub const SPLICE: i64 = 76;
    pub const TEE: i64 = 77;
    pub const EXECVEAT: i64 = 281;
    pub const INIT_MODULE: i64 = 105;
    pub const FINIT_MODULE: i64 = 273;
    pub const DELETE_MODULE: i64 = 106;
    pub const KEXEC_LOAD: i64 = 104;
    pub const KEXEC_FILE_LOAD: i64 = 294;
    pub const FCHOWN: i64 = 55;
    pub const FCHOWNAT: i64 = 54;
    pub const MOUNT: i64 = 40;
    pub const UMOUNT2: i64 = 39;
    pub const PIVOT_ROOT: i64 = 41;
    pub const CHROOT: i64 = 51;
    pub const OPEN_TREE: i64 = 428;
    pub const MOVE_MOUNT: i64 = 429;
    pub const FSOPEN: i64 = 430;
    pub const FSCONFIG: i64 = 431;
    pub const FSMOUNT: i64 = 432;
    pub const FSPICK: i64 = 433;
    pub const MOUNT_SETATTR: i64 = 442;
    pub const PTRACE: i64 = 117;
    pub const PROCESS_VM_READV: i64 = 270;
    pub const PROCESS_VM_WRITEV: i64 = 271;
    pub const PIDFD_GETFD: i64 = 438;
    pub const UNSHARE: i64 = 97;
    pub const SETNS: i64 = 268;
    pub const SETHOSTNAME: i64 = 161;
    pub const SETDOMAINNAME: i64 = 162;
    pub const SWAPON: i64 = 224;
    pub const SWAPOFF: i64 = 225;
    pub const REBOOT: i64 = 142;
}

use super::SysId;

/// Identity table: every [`SysId`] the aarch64 ABI has, with its native
/// number. 73 of the 89 identities exist here; the legacy non-`at` family
/// and `iopl`/`ioperm` are absent (see the `syscall_nr` module doc).
const TABLE: &[(SysId, i64)] = &[
    (SysId::Read, syscall_nr::READ),
    (SysId::Write, syscall_nr::WRITE),
    (SysId::Writev, syscall_nr::WRITEV),
    (SysId::Close, syscall_nr::CLOSE),
    (SysId::Mmap, syscall_nr::MMAP),
    (SysId::Socket, syscall_nr::SOCKET),
    (SysId::Connect, syscall_nr::CONNECT),
    (SysId::Sendto, syscall_nr::SENDTO),
    (SysId::Recvfrom, syscall_nr::RECVFROM),
    (SysId::Sendmsg, syscall_nr::SENDMSG),
    (SysId::Recvmsg, syscall_nr::RECVMSG),
    (SysId::Dup, syscall_nr::DUP),
    (SysId::Fcntl, syscall_nr::FCNTL),
    (SysId::Sendmmsg, syscall_nr::SENDMMSG),
    (SysId::Recvmmsg, syscall_nr::RECVMMSG),
    (SysId::Dup3, syscall_nr::DUP3),
    (SysId::CloseRange, syscall_nr::CLOSE_RANGE),
    (SysId::Clone3, syscall_nr::CLONE3),
    (SysId::Seccomp, syscall_nr::SECCOMP),
    (SysId::Prctl, syscall_nr::PRCTL),
    (SysId::Bind, syscall_nr::BIND),
    (SysId::Socketpair, syscall_nr::SOCKETPAIR),
    (SysId::Clone, syscall_nr::CLONE),
    (SysId::Execve, syscall_nr::EXECVE),
    (SysId::Fchmod, syscall_nr::FCHMOD),
    (SysId::Getdents64, syscall_nr::GETDENTS64),
    (SysId::Openat, syscall_nr::OPENAT),
    (SysId::Openat2, syscall_nr::OPENAT2),
    (SysId::Truncate, syscall_nr::TRUNCATE),
    (SysId::Ftruncate, syscall_nr::FTRUNCATE),
    (SysId::Symlinkat, syscall_nr::SYMLINKAT),
    (SysId::Linkat, syscall_nr::LINKAT),
    (SysId::Mkdirat, syscall_nr::MKDIRAT),
    (SysId::Unlinkat, syscall_nr::UNLINKAT),
    (SysId::Renameat, syscall_nr::RENAMEAT),
    (SysId::Fchmodat, syscall_nr::FCHMODAT),
    (SysId::Pipe2, syscall_nr::PIPE2),
    (SysId::Renameat2, syscall_nr::RENAMEAT2),
    (SysId::IoUringSetup, syscall_nr::IO_URING_SETUP),
    (SysId::IoUringEnter, syscall_nr::IO_URING_ENTER),
    (SysId::IoUringRegister, syscall_nr::IO_URING_REGISTER),
    (SysId::Sendfile, syscall_nr::SENDFILE),
    (SysId::Splice, syscall_nr::SPLICE),
    (SysId::Tee, syscall_nr::TEE),
    (SysId::Execveat, syscall_nr::EXECVEAT),
    (SysId::InitModule, syscall_nr::INIT_MODULE),
    (SysId::FinitModule, syscall_nr::FINIT_MODULE),
    (SysId::DeleteModule, syscall_nr::DELETE_MODULE),
    (SysId::KexecLoad, syscall_nr::KEXEC_LOAD),
    (SysId::KexecFileLoad, syscall_nr::KEXEC_FILE_LOAD),
    (SysId::Fchown, syscall_nr::FCHOWN),
    (SysId::Fchownat, syscall_nr::FCHOWNAT),
    (SysId::Mount, syscall_nr::MOUNT),
    (SysId::Umount2, syscall_nr::UMOUNT2),
    (SysId::PivotRoot, syscall_nr::PIVOT_ROOT),
    (SysId::Chroot, syscall_nr::CHROOT),
    (SysId::OpenTree, syscall_nr::OPEN_TREE),
    (SysId::MoveMount, syscall_nr::MOVE_MOUNT),
    (SysId::Fsopen, syscall_nr::FSOPEN),
    (SysId::Fsconfig, syscall_nr::FSCONFIG),
    (SysId::Fsmount, syscall_nr::FSMOUNT),
    (SysId::Fspick, syscall_nr::FSPICK),
    (SysId::MountSetattr, syscall_nr::MOUNT_SETATTR),
    (SysId::Ptrace, syscall_nr::PTRACE),
    (SysId::ProcessVmReadv, syscall_nr::PROCESS_VM_READV),
    (SysId::ProcessVmWritev, syscall_nr::PROCESS_VM_WRITEV),
    (SysId::PidfdGetfd, syscall_nr::PIDFD_GETFD),
    (SysId::Unshare, syscall_nr::UNSHARE),
    (SysId::Setns, syscall_nr::SETNS),
    (SysId::Sethostname, syscall_nr::SETHOSTNAME),
    (SysId::Setdomainname, syscall_nr::SETDOMAINNAME),
    (SysId::Swapon, syscall_nr::SWAPON),
    (SysId::Swapoff, syscall_nr::SWAPOFF),
    (SysId::Reboot, syscall_nr::REBOOT),
];

/// Native aarch64 syscall number -> portable identity.
pub(crate) fn sys_id(nr: i64) -> Option<SysId> {
    TABLE.iter().find(|&&(_, n)| n == nr).map(|&(id, _)| id)
}

/// Portable identity -> native aarch64 number. `None` for the 16 identities
/// this ABI does not have.
pub(crate) fn nr_of(id: SysId) -> Option<i64> {
    TABLE.iter().find(|&&(i, _)| i == id).map(|&(_, n)| n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dead-tracee tolerance of the regset-based primitives.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn fallbacks_tolerate_a_dead_tracee() {
        // Well above /proc/sys/kernel/pid_max — guaranteed not to exist.
        let dead = Pid::from_raw(0x3fff_ffff);
        assert!(matches!(read_syscall_regs_fallback(dead), Ok(None)));
        assert!(matches!(read_return_value_fallback(dead), Ok(None)));
        assert_eq!(read_raw_syscall_nr(dead), None);
        assert!(
            matches!(deny_syscall(dead, libc::EPERM), Ok(false)),
            "deny of a dead tracee is vacuously enforced, never fatal"
        );
    }

    /// `UserPtRegs` must match kernel `struct user_pt_regs`:
    /// 31 x u64 GPRs + sp + pc + pstate = 34 * 8 = 272 bytes.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn user_pt_regs_layout_matches_kernel() {
        assert_eq!(std::mem::size_of::<UserPtRegs>(), 272);
        assert_eq!(std::mem::align_of::<UserPtRegs>(), 8);
        assert_eq!(std::mem::offset_of!(UserPtRegs, sp), 248);
        assert_eq!(std::mem::offset_of!(UserPtRegs, pc), 256);
        assert_eq!(std::mem::offset_of!(UserPtRegs, pstate), 264);
    }

    /// Every aarch64 number pinned verbatim — source of truth:
    /// asm-generic/unistd.h (v6.6), verified in work/78 §2.5.
    #[test]
    fn expected_aarch64_numbers_pinned() {
        assert_eq!(syscall_nr::OPENAT, 56);
        assert_eq!(syscall_nr::OPENAT2, 437);
        assert_eq!(syscall_nr::CLOSE, 57);
        assert_eq!(syscall_nr::CLOSE_RANGE, 436);
        assert_eq!(syscall_nr::DUP, 23);
        assert_eq!(syscall_nr::DUP3, 24);
        assert_eq!(syscall_nr::FCNTL, 25);
        assert_eq!(syscall_nr::MMAP, 222);
        assert_eq!(syscall_nr::PIPE2, 59);
        assert_eq!(syscall_nr::SOCKET, 198);
        assert_eq!(syscall_nr::CONNECT, 203);
        assert_eq!(syscall_nr::SENDTO, 206);
        assert_eq!(syscall_nr::RECVFROM, 207);
        assert_eq!(syscall_nr::SENDMSG, 211);
        assert_eq!(syscall_nr::RECVMSG, 212);
        assert_eq!(syscall_nr::SENDMMSG, 269);
        assert_eq!(syscall_nr::RECVMMSG, 243);
        assert_eq!(syscall_nr::BIND, 200);
        assert_eq!(syscall_nr::SOCKETPAIR, 199);
        assert_eq!(syscall_nr::CLONE, 220);
        assert_eq!(syscall_nr::CLONE3, 435);
        assert_eq!(syscall_nr::EXECVE, 221);
        assert_eq!(syscall_nr::EXECVEAT, 281);
        assert_eq!(syscall_nr::RENAMEAT, 38);
        assert_eq!(syscall_nr::RENAMEAT2, 276);
        assert_eq!(syscall_nr::MKDIRAT, 34);
        assert_eq!(syscall_nr::UNLINKAT, 35);
        assert_eq!(syscall_nr::FCHMOD, 52);
        assert_eq!(syscall_nr::FCHMODAT, 53);
        assert_eq!(syscall_nr::FCHOWN, 55);
        assert_eq!(syscall_nr::FCHOWNAT, 54);
        assert_eq!(syscall_nr::SYMLINKAT, 36);
        assert_eq!(syscall_nr::LINKAT, 37);
        assert_eq!(syscall_nr::TRUNCATE, 45);
        assert_eq!(syscall_nr::FTRUNCATE, 46);
        assert_eq!(syscall_nr::GETDENTS64, 61);
        assert_eq!(syscall_nr::SENDFILE, 71);
        assert_eq!(syscall_nr::SPLICE, 76);
        assert_eq!(syscall_nr::TEE, 77);
        assert_eq!(syscall_nr::SECCOMP, 277);
        assert_eq!(syscall_nr::PRCTL, 167);
        assert_eq!(syscall_nr::PTRACE, 117);
        assert_eq!(syscall_nr::PROCESS_VM_READV, 270);
        assert_eq!(syscall_nr::PROCESS_VM_WRITEV, 271);
        assert_eq!(syscall_nr::IO_URING_SETUP, 425);
        assert_eq!(syscall_nr::IO_URING_ENTER, 426);
        assert_eq!(syscall_nr::IO_URING_REGISTER, 427);
        assert_eq!(syscall_nr::INIT_MODULE, 105);
        assert_eq!(syscall_nr::FINIT_MODULE, 273);
        assert_eq!(syscall_nr::DELETE_MODULE, 106);
        assert_eq!(syscall_nr::KEXEC_LOAD, 104);
        assert_eq!(syscall_nr::KEXEC_FILE_LOAD, 294);
        assert_eq!(syscall_nr::MOUNT, 40);
        assert_eq!(syscall_nr::UMOUNT2, 39);
        assert_eq!(syscall_nr::PIVOT_ROOT, 41);
        assert_eq!(syscall_nr::CHROOT, 51);
        assert_eq!(syscall_nr::OPEN_TREE, 428);
        assert_eq!(syscall_nr::MOVE_MOUNT, 429);
        assert_eq!(syscall_nr::FSOPEN, 430);
        assert_eq!(syscall_nr::FSCONFIG, 431);
        assert_eq!(syscall_nr::FSMOUNT, 432);
        assert_eq!(syscall_nr::FSPICK, 433);
        assert_eq!(syscall_nr::MOUNT_SETATTR, 442);
        assert_eq!(syscall_nr::UNSHARE, 97);
        assert_eq!(syscall_nr::SETNS, 268);
        assert_eq!(syscall_nr::SETHOSTNAME, 161);
        assert_eq!(syscall_nr::SETDOMAINNAME, 162);
        assert_eq!(syscall_nr::SWAPON, 224);
        assert_eq!(syscall_nr::SWAPOFF, 225);
        assert_eq!(syscall_nr::REBOOT, 142);
        assert_eq!(syscall_nr::READ, 63);
        assert_eq!(syscall_nr::WRITE, 64);
        assert_eq!(syscall_nr::WRITEV, 66);
    }

    /// The 16 identities absent from the asm-generic table must map to
    /// `None` — and never appear in the derived trap list.
    #[test]
    fn absent_identities_map_to_none() {
        for id in [
            SysId::Open,
            SysId::Creat,
            SysId::Dup2,
            SysId::Pipe,
            SysId::Fork,
            SysId::Rename,
            SysId::Mkdir,
            SysId::Rmdir,
            SysId::Unlink,
            SysId::Chmod,
            SysId::Chown,
            SysId::Lchown,
            SysId::Symlink,
            SysId::Link,
            SysId::Iopl,
            SysId::Ioperm,
        ] {
            assert_eq!(nr_of(id), None, "{id:?} must be absent on aarch64");
        }
        assert_eq!(TABLE.len(), 74, "90 identities - 16 absences = 74");
    }

    /// Exhaustive round-trip over this table (runs on any host arch).
    #[test]
    fn aarch64_table_round_trips_without_duplicates() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for &(id, nr) in TABLE {
            assert!(seen.insert(nr), "duplicate aarch64 number {nr}");
            assert_eq!(sys_id(nr), Some(id));
            assert_eq!(nr_of(id), Some(nr));
        }
    }

    /// Raw-number collision containment (work/78 §2.5): the same number
    /// means different syscalls on the two ABIs. These pins document the
    /// danger the SysId boundary exists to contain.
    #[test]
    fn cross_arch_collisions_are_real() {
        // 167 = prctl here, swapon on x86_64.
        assert_eq!(sys_id(167), Some(SysId::Prctl));
        // 56 = openat here, clone on x86_64.
        assert_eq!(sys_id(56), Some(SysId::Openat));
        // 57 = close here, fork on x86_64.
        assert_eq!(sys_id(57), Some(SysId::Close));
    }

    /// The aarch64 security-relevant surface: 87 shared identities minus
    /// the 14 absent legacy ones minus iopl/ioperm = 71 numbers. Computed
    /// from this table directly so the test runs on any host arch.
    #[test]
    fn security_relevant_count_matches_aarch64_surface() {
        let count = super::super::SECURITY_RELEVANT_IDS
            .iter()
            .filter_map(|&id| nr_of(id))
            .count();
        assert_eq!(count, 71);
    }

    /// Ptrace-event-handled numbers on aarch64: execve, execveat, clone —
    /// no fork syscall exists (arm64 libcs use clone/clone3). Computed from
    /// this table directly so the test runs on any host arch.
    #[test]
    fn ptrace_event_handled_matches_aarch64_set() {
        let mut nrs: Vec<i64> = super::super::PTRACE_EVENT_HANDLED_IDS
            .iter()
            .filter_map(|&id| nr_of(id))
            .collect();
        nrs.sort_unstable();
        assert_eq!(nrs, vec![220, 221, 281]);
    }
}
