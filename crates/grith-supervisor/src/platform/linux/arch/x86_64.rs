// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! x86_64 register primitives for the Linux ptrace backend.
//!
//! System V AMD64 syscall ABI:
//!
//! | Register    | Purpose at syscall-entry       |
//! |-------------|--------------------------------|
//! | `orig_rax`  | Syscall number                 |
//! | `rdi`       | Argument 1                     |
//! | `rsi`       | Argument 2                     |
//! | `rdx`       | Argument 3                     |
//! | `r10`       | Argument 4                     |
//! | `r8`        | Argument 5                     |
//! | `r9`        | Argument 6                     |
//! | `rax`       | Return value at syscall-exit   |
//!
//! x86_64 keeps the classic `PTRACE_GETREGS`/`SETREGS` requests (available on
//! both glibc and musl via nix). `libc::user_regs_struct` never leaves this
//! file — it is unavailable on some other target/libc combinations, so the
//! shared code deals only in [`SyscallRegs`].

#![cfg(target_os = "linux")]
// The identity table below compiles on EVERY arch so its integrity tests run
// on arm64 hosts too; only the ptrace register primitives are x86_64-gated.

#[cfg(target_arch = "x86_64")]
use nix::sys::ptrace;
#[cfg(target_arch = "x86_64")]
use nix::unistd::Pid;
#[cfg(target_arch = "x86_64")]
use tracing::trace;

#[cfg(all(test, target_arch = "x86_64"))]
use nix::libc;

#[cfg(target_arch = "x86_64")]
use crate::error::{Error, Result};

#[cfg(target_arch = "x86_64")]
use super::SyscallRegs;

#[cfg(target_arch = "x86_64")]
/// Read the general-purpose register file, mapped into the arch-neutral
/// [`SyscallRegs`] view. Fallback source when `PTRACE_GET_SYSCALL_INFO`
/// carries no entry record (pre-5.3 kernels; `PTRACE_EVENT_*` stops).
///
/// `Ok(None)` = tracee gone (ESRCH) — benign, never session-fatal.
pub(crate) fn read_syscall_regs_fallback(pid: Pid) -> Result<Option<SyscallRegs>> {
    match ptrace::getregs(pid) {
        Ok(regs) => Ok(Some(SyscallRegs {
            nr: regs.orig_rax as i64,
            args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
            ip: regs.rip,
            sp: regs.rsp,
            // From the same fetch as the arguments, so the pre-5.3
            // entry/exit heuristic cannot race tracee death against a
            // second register read.
            retval_hint: Some(regs.rax as i64),
        })),
        Err(nix::errno::Errno::ESRCH) => {
            trace!(
                pid = pid.as_raw(),
                event = "tracee_gone_at_stop",
                "PTRACE_GETREGS: tracee gone (ESRCH); treating stop as stale"
            );
            Ok(None)
        }
        Err(e) => Err(Error::InterceptionError(format!(
            "PTRACE_GETREGS failed for pid {pid}: {e}"
        ))),
    }
}

#[cfg(target_arch = "x86_64")]
/// Read the syscall return value at an exit stop (`rax`). Fallback source
/// when the `PTRACE_GET_SYSCALL_INFO` EXIT record is unavailable.
///
/// `Ok(None)` = tracee gone (ESRCH).
pub(crate) fn read_return_value_fallback(pid: Pid) -> Result<Option<i64>> {
    match ptrace::getregs(pid) {
        Ok(regs) => Ok(Some(regs.rax as i64)),
        Err(nix::errno::Errno::ESRCH) => {
            trace!(
                pid = pid.as_raw(),
                event = "tracee_gone_at_stop",
                "PTRACE_GETREGS: tracee gone (ESRCH); treating stop as stale"
            );
            Ok(None)
        }
        Err(e) => Err(Error::InterceptionError(format!(
            "PTRACE_GETREGS failed for pid {pid}: {e}"
        ))),
    }
}

#[cfg(target_arch = "x86_64")]
/// Best-effort read of the raw native syscall number for forensics (the
/// foreign-ABI paths record it even when the number belongs to a foreign
/// table). `None` on any failure — callers record `-1`.
pub(crate) fn read_raw_syscall_nr(pid: Pid) -> Option<i64> {
    ptrace::getregs(pid).ok().map(|regs| regs.orig_rax as i64)
}

#[cfg(target_arch = "x86_64")]
/// Skip the syscall a tracee is entering and make it observe `-errno`.
///
/// x86_64 mechanics: set `orig_rax = -1` so dispatch matches no syscall, and
/// pre-seed `rax = -errno`. The kernel's `nr != -1` guard preserves the
/// seeded value instead of overwriting it with `-ENOSYS`
/// (`arch/x86/entry/common.c`) — verified in work/78 §2.3.
///
/// Must be called at a syscall-entry (or seccomp) stop. Returns `Ok(false)`
/// when the tracee died in its stop (the denial is vacuously enforced —
/// never fatal, since this is also the fail-closed classify-error path).
pub(crate) fn deny_syscall(pid: Pid, errno: i32) -> Result<bool> {
    let mut regs = match ptrace::getregs(pid) {
        Ok(regs) => regs,
        Err(nix::errno::Errno::ESRCH) => {
            trace!(
                pid = pid.as_raw(),
                event = "tracee_gone_at_stop",
                "PTRACE_GETREGS (deny): tracee gone (ESRCH); denial vacuously enforced"
            );
            return Ok(false);
        }
        Err(e) => {
            return Err(Error::InterceptionError(format!(
                "PTRACE_GETREGS (deny) failed for pid {pid}: {e}"
            )))
        }
    };
    regs.orig_rax = u64::MAX; // -1 as u64 => invalid syscall number
    regs.rax = -(errno as i64) as u64;
    match ptrace::setregs(pid, regs) {
        Ok(()) => Ok(true),
        // The tracee died between GETREGS and SETREGS. No syscall will
        // execute; the denial holds.
        Err(nix::errno::Errno::ESRCH) => Ok(false),
        Err(e) => Err(Error::InterceptionError(format!(
            "PTRACE_SETREGS (deny) failed for pid {pid}: {e}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// x86_64 syscall identity table
// ---------------------------------------------------------------------------

/// The x86_64 native audit-arch value (`AUDIT_ARCH_X86_64`,
/// uapi/linux/audit.h): EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE.
pub(crate) const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;

/// Syscall numbers for the x86_64 Linux ABI, from `asm/unistd_64.h`.
///
/// Bare numbers only: the per-syscall security rationale lives on the
/// arch-neutral [`SysId`] declaration in `arch/mod.rs`. Every number here is
/// pinned by the expected-numbers test in the arch table-integrity suite.
pub(crate) mod syscall_nr {
    pub const READ: i64 = 0;
    pub const WRITE: i64 = 1;
    pub const WRITEV: i64 = 20;
    pub const CLOSE: i64 = 3;
    pub const OPEN: i64 = 2;
    pub const MMAP: i64 = 9;
    pub const PIPE: i64 = 22;
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const SENDTO: i64 = 44;
    pub const RECVFROM: i64 = 45;
    pub const SENDMSG: i64 = 46;
    pub const RECVMSG: i64 = 47;
    pub const DUP: i64 = 32;
    pub const DUP2: i64 = 33;
    pub const FCNTL: i64 = 72;
    pub const SENDMMSG: i64 = 307;
    pub const RECVMMSG: i64 = 299;
    pub const DUP3: i64 = 292;
    pub const CLOSE_RANGE: i64 = 436;
    pub const CLONE3: i64 = 435;
    pub const SECCOMP: i64 = 317;
    pub const PRCTL: i64 = 157;
    pub const BIND: i64 = 49;
    pub const SOCKETPAIR: i64 = 53;
    pub const CLONE: i64 = 56;
    pub const FORK: i64 = 57;
    pub const EXECVE: i64 = 59;
    pub const RENAME: i64 = 82;
    pub const MKDIR: i64 = 83;
    pub const UNLINK: i64 = 87;
    pub const RMDIR: i64 = 84;
    pub const CHMOD: i64 = 90;
    pub const FCHMOD: i64 = 91;
    pub const GETDENTS64: i64 = 217;
    pub const OPENAT: i64 = 257;
    pub const OPENAT2: i64 = 437;
    pub const CREAT: i64 = 85;
    pub const TRUNCATE: i64 = 76;
    pub const FTRUNCATE: i64 = 77;
    pub const SYMLINK: i64 = 88;
    pub const SYMLINKAT: i64 = 266;
    pub const LINK: i64 = 86;
    pub const LINKAT: i64 = 265;
    pub const MKDIRAT: i64 = 258;
    pub const UNLINKAT: i64 = 263;
    pub const RENAMEAT: i64 = 264;
    pub const FCHMODAT: i64 = 268;
    pub const PIPE2: i64 = 293;
    pub const RENAMEAT2: i64 = 316;
    pub const IO_URING_SETUP: i64 = 425;
    pub const IO_URING_ENTER: i64 = 426;
    pub const IO_URING_REGISTER: i64 = 427;
    pub const SENDFILE: i64 = 40;
    pub const SPLICE: i64 = 275;
    pub const TEE: i64 = 276;
    pub const EXECVEAT: i64 = 322;
    pub const INIT_MODULE: i64 = 175;
    pub const FINIT_MODULE: i64 = 313;
    pub const DELETE_MODULE: i64 = 176;
    pub const KEXEC_LOAD: i64 = 246;
    pub const KEXEC_FILE_LOAD: i64 = 320;
    pub const CHOWN: i64 = 92;
    pub const FCHOWN: i64 = 93;
    pub const LCHOWN: i64 = 94;
    pub const FCHOWNAT: i64 = 260;
    pub const MOUNT: i64 = 165;
    pub const UMOUNT2: i64 = 166;
    pub const PIVOT_ROOT: i64 = 155;
    pub const CHROOT: i64 = 161;
    pub const OPEN_TREE: i64 = 428;
    pub const MOVE_MOUNT: i64 = 429;
    pub const FSOPEN: i64 = 430;
    pub const FSCONFIG: i64 = 431;
    pub const FSMOUNT: i64 = 432;
    pub const FSPICK: i64 = 433;
    pub const MOUNT_SETATTR: i64 = 442;
    pub const PTRACE: i64 = 101;
    pub const PROCESS_VM_READV: i64 = 310;
    pub const PROCESS_VM_WRITEV: i64 = 311;
    pub const PIDFD_GETFD: i64 = 438;
    pub const UNSHARE: i64 = 272;
    pub const SETNS: i64 = 308;
    pub const SETHOSTNAME: i64 = 170;
    pub const SETDOMAINNAME: i64 = 171;
    pub const IOPL: i64 = 172;
    pub const IOPERM: i64 = 173;
    pub const SWAPON: i64 = 167;
    pub const SWAPOFF: i64 = 168;
    pub const REBOOT: i64 = 169;
}

use super::SysId;

/// Identity table: every [`SysId`] paired with its x86_64 native number.
/// x86_64 has every identity grith tracks (it is the superset arch — the
/// legacy non-`at` calls and iopl/ioperm exist only here).
const TABLE: &[(SysId, i64)] = &[
    (SysId::Read, syscall_nr::READ),
    (SysId::Write, syscall_nr::WRITE),
    (SysId::Writev, syscall_nr::WRITEV),
    (SysId::Close, syscall_nr::CLOSE),
    (SysId::Open, syscall_nr::OPEN),
    (SysId::Mmap, syscall_nr::MMAP),
    (SysId::Pipe, syscall_nr::PIPE),
    (SysId::Socket, syscall_nr::SOCKET),
    (SysId::Connect, syscall_nr::CONNECT),
    (SysId::Sendto, syscall_nr::SENDTO),
    (SysId::Recvfrom, syscall_nr::RECVFROM),
    (SysId::Sendmsg, syscall_nr::SENDMSG),
    (SysId::Recvmsg, syscall_nr::RECVMSG),
    (SysId::Dup, syscall_nr::DUP),
    (SysId::Dup2, syscall_nr::DUP2),
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
    (SysId::Fork, syscall_nr::FORK),
    (SysId::Execve, syscall_nr::EXECVE),
    (SysId::Rename, syscall_nr::RENAME),
    (SysId::Mkdir, syscall_nr::MKDIR),
    (SysId::Unlink, syscall_nr::UNLINK),
    (SysId::Rmdir, syscall_nr::RMDIR),
    (SysId::Chmod, syscall_nr::CHMOD),
    (SysId::Fchmod, syscall_nr::FCHMOD),
    (SysId::Getdents64, syscall_nr::GETDENTS64),
    (SysId::Openat, syscall_nr::OPENAT),
    (SysId::Openat2, syscall_nr::OPENAT2),
    (SysId::Creat, syscall_nr::CREAT),
    (SysId::Truncate, syscall_nr::TRUNCATE),
    (SysId::Ftruncate, syscall_nr::FTRUNCATE),
    (SysId::Symlink, syscall_nr::SYMLINK),
    (SysId::Symlinkat, syscall_nr::SYMLINKAT),
    (SysId::Link, syscall_nr::LINK),
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
    (SysId::Chown, syscall_nr::CHOWN),
    (SysId::Fchown, syscall_nr::FCHOWN),
    (SysId::Lchown, syscall_nr::LCHOWN),
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
    (SysId::Iopl, syscall_nr::IOPL),
    (SysId::Ioperm, syscall_nr::IOPERM),
    (SysId::Swapon, syscall_nr::SWAPON),
    (SysId::Swapoff, syscall_nr::SWAPOFF),
    (SysId::Reboot, syscall_nr::REBOOT),
];

/// Native x86_64 syscall number -> portable identity.
pub(crate) fn sys_id(nr: i64) -> Option<SysId> {
    TABLE.iter().find(|&&(_, n)| n == nr).map(|&(id, _)| id)
}

/// Portable identity -> native x86_64 number. Always `Some` on x86_64.
pub(crate) fn nr_of(id: SysId) -> Option<i64> {
    TABLE.iter().find(|&&(i, _)| i == id).map(|&(_, n)| n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "x86_64")]
    /// Dead-tracee tolerance of the GETREGS-based fallbacks themselves. The
    /// shared `arch::read_syscall_regs`/`read_return_value` tests short-
    /// circuit at the `PTRACE_GET_SYSCALL_INFO` ESRCH on a dead pid, so the
    /// fallback paths need their own coverage.
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
    /// Every x86_64 number pinned verbatim — guards the move of the table
    /// out of `platform/linux/mod.rs` (work/78 PR B) and any future edit.
    /// Source of truth: `asm/unistd_64.h`.
    #[test]
    fn expected_x86_64_numbers_pinned() {
        assert_eq!(syscall_nr::READ, 0);
        assert_eq!(syscall_nr::WRITE, 1);
        assert_eq!(syscall_nr::WRITEV, 20);
        assert_eq!(syscall_nr::CLOSE, 3);
        assert_eq!(syscall_nr::OPEN, 2);
        assert_eq!(syscall_nr::MMAP, 9);
        assert_eq!(syscall_nr::PIPE, 22);
        assert_eq!(syscall_nr::SOCKET, 41);
        assert_eq!(syscall_nr::CONNECT, 42);
        assert_eq!(syscall_nr::SENDTO, 44);
        assert_eq!(syscall_nr::RECVFROM, 45);
        assert_eq!(syscall_nr::SENDMSG, 46);
        assert_eq!(syscall_nr::RECVMSG, 47);
        assert_eq!(syscall_nr::DUP, 32);
        assert_eq!(syscall_nr::DUP2, 33);
        assert_eq!(syscall_nr::FCNTL, 72);
        assert_eq!(syscall_nr::SENDMMSG, 307);
        assert_eq!(syscall_nr::RECVMMSG, 299);
        assert_eq!(syscall_nr::DUP3, 292);
        assert_eq!(syscall_nr::CLOSE_RANGE, 436);
        assert_eq!(syscall_nr::CLONE3, 435);
        assert_eq!(syscall_nr::SECCOMP, 317);
        assert_eq!(syscall_nr::PRCTL, 157);
        assert_eq!(syscall_nr::BIND, 49);
        assert_eq!(syscall_nr::SOCKETPAIR, 53);
        assert_eq!(syscall_nr::CLONE, 56);
        assert_eq!(syscall_nr::FORK, 57);
        assert_eq!(syscall_nr::EXECVE, 59);
        assert_eq!(syscall_nr::RENAME, 82);
        assert_eq!(syscall_nr::MKDIR, 83);
        assert_eq!(syscall_nr::UNLINK, 87);
        assert_eq!(syscall_nr::RMDIR, 84);
        assert_eq!(syscall_nr::CHMOD, 90);
        assert_eq!(syscall_nr::FCHMOD, 91);
        assert_eq!(syscall_nr::GETDENTS64, 217);
        assert_eq!(syscall_nr::OPENAT, 257);
        assert_eq!(syscall_nr::OPENAT2, 437);
        assert_eq!(syscall_nr::CREAT, 85);
        assert_eq!(syscall_nr::TRUNCATE, 76);
        assert_eq!(syscall_nr::FTRUNCATE, 77);
        assert_eq!(syscall_nr::SYMLINK, 88);
        assert_eq!(syscall_nr::SYMLINKAT, 266);
        assert_eq!(syscall_nr::LINK, 86);
        assert_eq!(syscall_nr::LINKAT, 265);
        assert_eq!(syscall_nr::MKDIRAT, 258);
        assert_eq!(syscall_nr::UNLINKAT, 263);
        assert_eq!(syscall_nr::RENAMEAT, 264);
        assert_eq!(syscall_nr::FCHMODAT, 268);
        assert_eq!(syscall_nr::PIPE2, 293);
        assert_eq!(syscall_nr::RENAMEAT2, 316);
        assert_eq!(syscall_nr::IO_URING_SETUP, 425);
        assert_eq!(syscall_nr::IO_URING_ENTER, 426);
        assert_eq!(syscall_nr::IO_URING_REGISTER, 427);
        assert_eq!(syscall_nr::SENDFILE, 40);
        assert_eq!(syscall_nr::SPLICE, 275);
        assert_eq!(syscall_nr::TEE, 276);
        assert_eq!(syscall_nr::EXECVEAT, 322);
        assert_eq!(syscall_nr::INIT_MODULE, 175);
        assert_eq!(syscall_nr::FINIT_MODULE, 313);
        assert_eq!(syscall_nr::DELETE_MODULE, 176);
        assert_eq!(syscall_nr::KEXEC_LOAD, 246);
        assert_eq!(syscall_nr::KEXEC_FILE_LOAD, 320);
        assert_eq!(syscall_nr::CHOWN, 92);
        assert_eq!(syscall_nr::FCHOWN, 93);
        assert_eq!(syscall_nr::LCHOWN, 94);
        assert_eq!(syscall_nr::FCHOWNAT, 260);
        assert_eq!(syscall_nr::MOUNT, 165);
        assert_eq!(syscall_nr::UMOUNT2, 166);
        assert_eq!(syscall_nr::PIVOT_ROOT, 155);
        assert_eq!(syscall_nr::CHROOT, 161);
        assert_eq!(syscall_nr::OPEN_TREE, 428);
        assert_eq!(syscall_nr::MOVE_MOUNT, 429);
        assert_eq!(syscall_nr::FSOPEN, 430);
        assert_eq!(syscall_nr::FSCONFIG, 431);
        assert_eq!(syscall_nr::FSMOUNT, 432);
        assert_eq!(syscall_nr::FSPICK, 433);
        assert_eq!(syscall_nr::MOUNT_SETATTR, 442);
        assert_eq!(syscall_nr::PTRACE, 101);
        assert_eq!(syscall_nr::PROCESS_VM_READV, 310);
        assert_eq!(syscall_nr::PROCESS_VM_WRITEV, 311);
        assert_eq!(syscall_nr::UNSHARE, 272);
        assert_eq!(syscall_nr::SETNS, 308);
        assert_eq!(syscall_nr::SETHOSTNAME, 170);
        assert_eq!(syscall_nr::SETDOMAINNAME, 171);
        assert_eq!(syscall_nr::IOPL, 172);
        assert_eq!(syscall_nr::IOPERM, 173);
        assert_eq!(syscall_nr::SWAPON, 167);
        assert_eq!(syscall_nr::SWAPOFF, 168);
        assert_eq!(syscall_nr::REBOOT, 169);
    }

    /// The derived per-arch security-relevant list must equal the historical
    /// x86_64 `SECURITY_RELEVANT` set exactly (87 numbers).
    #[test]
    fn security_relevant_matches_historical_x86_64_set() {
        use std::collections::HashSet;
        let expected: HashSet<i64> = [
            2i64, 9, 22, 41, 42, 44, 45, 46, 47, 299, 307, 3, 436, 32, 33, 292, 72, 49, 53, 56,
            435, 57, 59, 82, 83, 87, 90, 91, 217, 257, 437, 85, 76, 77, 84, 88, 266, 86, 265, 258,
            263, 264, 268, 293, 316, 317, 157, 425, 426, 427, 40, 275, 276, 322, 175, 313, 176,
            246, 320, 92, 93, 94, 260, 165, 166, 155, 161, 428, 429, 430, 431, 432, 433, 442, 101,
            310, 311, 438, 272, 308, 170, 171, 172, 173, 167, 168, 169,
        ]
        .into_iter()
        .collect();
        // Computed from THIS table (not the native derived list) so the
        // test also runs on arm64 hosts.
        let derived: HashSet<i64> = super::super::SECURITY_RELEVANT_IDS
            .iter()
            .filter_map(|&id| nr_of(id))
            .collect();
        assert_eq!(derived, expected);
        assert_eq!(derived.len(), 87);
    }

    /// The ptrace-event-handled numbers on x86_64: execve, execveat, clone,
    /// fork — all four exist on this arch.
    #[test]
    fn ptrace_event_handled_matches_x86_64_set() {
        let mut nrs: Vec<i64> = super::super::PTRACE_EVENT_HANDLED_IDS
            .iter()
            .filter_map(|&id| nr_of(id))
            .collect();
        nrs.sort_unstable();
        assert_eq!(nrs, vec![56, 57, 59, 322]);
    }
}
