// Integration tests pinning cross-arch kernel semantics the aarch64 port
// relies on (work/78 PR D). Table-driven — every test here runs on BOTH
// x86_64 and aarch64; the arm64 CI job is what makes the aarch64 half real.

#[cfg(target_os = "linux")]
mod linux {
    use grith_supervisor::interceptor::SyscallKind;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// True when this process already has a tracer (e.g. the test suite is
    /// itself running under `grith exec`). Linux permits one tracer per
    /// process, so `PTRACE_TRACEME` in the helper child returns `EPERM` and
    /// no ptrace test in this file can run. CI is unsupervised.
    fn already_traced() -> bool {
        fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("TracerPid:"))
                    .map(|v| v.trim() != "0")
            })
            .unwrap_or(false)
    }

    fn compile_c_program(dir: &Path, name: &str, source: &str) -> PathBuf {
        let src_path = dir.join(format!("{name}.c"));
        let bin_path = dir.join(name);
        fs::write(&src_path, source).expect("write helper source");

        let output = Command::new("cc")
            .args(["-O0", "-Wall", "-Wextra", "-o"])
            .arg(&bin_path)
            .arg(&src_path)
            .output()
            .expect("spawn cc");

        assert!(
            output.status.success(),
            "cc failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        bin_path
    }

    /// Drive the supervisor loop for `binary`, denying every event for which
    /// `should_deny` returns true and allowing the rest. Returns all events.
    async fn trace_with_policy(
        binary: &Path,
        should_deny: impl Fn(&SyscallKind) -> bool,
    ) -> Vec<SyscallKind> {
        let mut interceptor = grith_supervisor::platform::create_interceptor().unwrap();
        let pid = interceptor
            .spawn_supervised(binary.to_str().unwrap(), &[], &[])
            .await
            .expect("spawn_supervised failed");

        let mut events = Vec::new();
        let start = Instant::now();
        loop {
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "timeout waiting for helper (pid {pid}) to exit"
            );
            match interceptor.next_event().await.expect("next_event failed") {
                Some(event) => {
                    let deny = should_deny(&event.kind);
                    events.push(event.kind.clone());
                    if deny {
                        interceptor.deny(event.tid).await.expect("deny failed");
                    } else {
                        interceptor.allow(event.tid).await.expect("allow failed");
                    }
                }
                None => break,
            }
        }
        events
    }

    /// **The deny-errno identity test (work/78 §2.3).** A denied syscall must
    /// make the tracee observe exactly `EPERM` — not `ENOSYS`.
    ///
    /// On x86_64 the skip is `orig_rax = -1` with `rax = -EPERM` pre-seeded;
    /// on aarch64 it is `NT_ARM_SYSTEM_CALL = -1` with `x0 = -EPERM`, where
    /// the kernel's trace-exit path must preserve the seeded value rather
    /// than overwrite it with `-ENOSYS` (verified against v6.6
    /// `arch/arm64/kernel/syscall.c`; THIS test is what pins it against
    /// regression on real kernels). Errno identity is load-bearing: the
    /// failed-exec/failed-connect suppressions and supervised tools'
    /// fallback behavior both key on EPERM.
    #[test]
    fn denied_syscall_observes_exactly_eperm() {
        if already_traced() {
            eprintln!("SKIP denied_syscall_observes_exactly_eperm: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("grith_deny_errno_marker");
        fs::write(&marker, "sentinel").unwrap();
        let result_path = temp.path().join("deny_errno_result");

        let source = format!(
            r#"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {{
    errno = 0;
    int fd = open("{marker}", O_RDONLY);
    int saved = errno;
    if (fd >= 0) close(fd);
    FILE *out = fopen("{result}", "w");
    if (!out) return 1;
    fprintf(out, "%d %d", fd, saved);
    fclose(out);
    return 0;
}}
"#,
            marker = marker.display(),
            result = result_path.display(),
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events = runtime.block_on(async {
            let helper = compile_c_program(temp.path(), "deny_errno_helper", &source);
            trace_with_policy(&helper, |kind| {
                matches!(kind, SyscallKind::FileOpen { path, .. } if path.contains("grith_deny_errno_marker"))
            })
            .await
        });

        assert!(
            events.iter().any(|k| matches!(
                k,
                SyscallKind::FileOpen { path, .. } if path.contains("grith_deny_errno_marker")
            )),
            "the marker open was never intercepted; events: {events:?}"
        );

        let result = fs::read_to_string(&result_path)
            .expect("helper did not write its result file — did it crash?");
        let mut parts = result.split_whitespace();
        let fd: i32 = parts.next().unwrap().parse().unwrap();
        let errno_val: i32 = parts.next().unwrap().parse().unwrap();

        assert!(fd < 0, "denied open unexpectedly succeeded (fd {fd})");
        assert_eq!(
            errno_val,
            1, // EPERM
            "denied syscall must observe exactly EPERM(1); got errno {errno_val} \
             (38 = ENOSYS would mean the skip clobbered the seeded return value)"
        );
        assert_ne!(errno_val, 38, "ENOSYS leak — the deny seed was overwritten");
    }

    /// **Modern-syscall coverage (work/78 PR D).** arm64 libcs can only emit
    /// the modern `*at`/extensible forms — there is no `open`, `rename`,
    /// `chmod`, or `fork` syscall in the asm-generic table. This exercises
    /// openat2 / renameat2 / fchmodat / clone3 end-to-end and asserts each
    /// classifies as the same kind its legacy sibling would have, so a
    /// classify arm accidentally keyed to a legacy-only identity shows up as
    /// a missing event here (on BOTH arches — the helper uses raw syscall
    /// numbers via libc's SYS_* constants, which are per-target correct).
    #[test]
    fn modern_syscall_forms_classify_end_to_end() {
        if already_traced() {
            eprintln!("SKIP modern_syscall_forms_classify_end_to_end: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let src_file = temp.path().join("modern_src");
        fs::write(&src_file, "x").unwrap();
        let dst_file = temp.path().join("modern_dst");
        let open2_target = temp.path().join("modern_openat2_target");
        fs::write(&open2_target, "y").unwrap();

        let source = format!(
            r#"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Local definitions so the helper builds on any glibc version. */
struct local_open_how {{
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
}};
struct local_clone_args {{
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
}};

int main(void) {{
    /* openat2(2): the extensible open. ENOSYS on pre-5.6 kernels is
     * tolerated (result recorded as skipped). */
    struct local_open_how how;
    memset(&how, 0, sizeof(how));
    how.flags = O_RDONLY;
    long o2 = syscall(SYS_openat2, AT_FDCWD, "{open2}", &how, sizeof(how));
    int o2_errno = errno;
    if (o2 >= 0) close((int)o2);

    /* renameat2(2) with no flags — the only rename form arm64 has. */
    long rn = syscall(SYS_renameat2, AT_FDCWD, "{src}", AT_FDCWD, "{dst}", 0);

    /* fchmodat(2) — the only path-chmod form arm64 has. */
    long ch = syscall(SYS_fchmodat, AT_FDCWD, "{dst}", 0644, 0);

    /* clone3(2): modern process creation; the supervisor must snapshot its
     * flags from tracee memory at the seccomp stop and adopt the child. */
    struct local_clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.exit_signal = SIGCHLD;
    long child = syscall(SYS_clone3, &ca, sizeof(ca));
    if (child == 0) {{
        _exit(0);
    }}
    int c3_errno = errno;
    if (child > 0) {{
        int status;
        waitpid((pid_t)child, &status, 0);
    }}

    fprintf(stderr, "results: openat2=%ld/%d renameat2=%ld fchmodat=%ld clone3=%ld/%d\n",
            o2, o2_errno, rn, ch, child, c3_errno);
    return 0;
}}
"#,
            open2 = open2_target.display(),
            src = src_file.display(),
            dst = dst_file.display(),
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events = runtime.block_on(async {
            let helper = compile_c_program(temp.path(), "modern_syscalls_helper", &source);
            trace_with_policy(&helper, |_| false).await
        });

        // openat2 → FileOpen on the target (kernel >= 5.6; CI kernels are).
        assert!(
            events.iter().any(|k| matches!(
                k,
                SyscallKind::FileOpen { path, .. } if path.contains("modern_openat2_target")
            )),
            "openat2 did not classify as FileOpen; events: {events:?}"
        );
        // renameat2 → FileRename with both paths.
        assert!(
            events.iter().any(|k| matches!(
                k,
                SyscallKind::FileRename { old_path, new_path }
                    if old_path.contains("modern_src") && new_path.contains("modern_dst")
            )),
            "renameat2 did not classify as FileRename; events: {events:?}"
        );
        // fchmodat → FileChmod with the mode.
        assert!(
            events.iter().any(|k| matches!(
                k,
                SyscallKind::FileChmod { path, mode } if path.contains("modern_dst") && *mode == 0o644
            )),
            "fchmodat did not classify as FileChmod; events: {events:?}"
        );
        // clone3 → a ProcessFork with a real child pid (the PTRACE_EVENT
        // handler resolves it; entry-time events carry 0).
        assert!(
            events
                .iter()
                .any(|k| matches!(k, SyscallKind::ProcessFork { child_pid } if *child_pid != 0)),
            "clone3 child was not adopted as ProcessFork; events: {events:?}"
        );
    }

    /// **Foreign-ABI fail-closed on arm64 (work/78 PR D).** On a
    /// CONFIG_COMPAT arm64 kernel, a 32-bit EL0 (armhf) binary's syscalls
    /// report `AUDIT_ARCH_ARM` and must be denied via the CompatArch marker.
    /// Running a real armhf binary needs an armhf toolchain/rootfs the
    /// standard runners don't have, so this skips cleanly unless
    /// `GRITH_TEST_ARMHF_BIN` names a runnable static armhf executable
    /// (exercised on the section-5 validation VMs).
    #[test]
    fn armhf_compat_binary_fails_closed_on_arm64() {
        if std::env::consts::ARCH != "aarch64" {
            eprintln!("SKIP armhf_compat_binary_fails_closed_on_arm64: aarch64-only");
            return;
        }
        let Ok(armhf_bin) = std::env::var("GRITH_TEST_ARMHF_BIN") else {
            eprintln!(
                "SKIP armhf_compat_binary_fails_closed_on_arm64: set GRITH_TEST_ARMHF_BIN \
                 to a static armhf executable to run"
            );
            return;
        };
        if already_traced() {
            eprintln!("SKIP armhf_compat_binary_fails_closed_on_arm64: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Deny only the FIRST foreign-ABI event: on a compat binary EVERY
        // syscall is foreign (the seccomp filter TRACEs the whole foreign
        // arch), so denying them all would deny exit_group too and the
        // binary could never terminate. One denied syscall proves the
        // fail-closed path; the rest are allowed so the helper can exit.
        let denied_one = std::sync::atomic::AtomicBool::new(false);
        let events = runtime.block_on(async {
            trace_with_policy(Path::new(&armhf_bin), |kind| {
                matches!(kind, SyscallKind::ForeignAbiSyscall { .. })
                    && !denied_one.swap(true, std::sync::atomic::Ordering::Relaxed)
            })
            .await
        });

        assert!(
            events.iter().any(|k| matches!(
                k,
                SyscallKind::ForeignAbiSyscall {
                    abi: grith_supervisor::interceptor::ForeignAbiKind::CompatArch,
                    ..
                }
            )),
            "no CompatArch event from the armhf binary; events: {events:?}"
        );
    }
}
