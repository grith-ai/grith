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

    fn compile_c_program(dir: &Path, name: &str, source: &str) -> PathBuf {
        let src_path = dir.join(format!("{name}.c"));
        let bin_path = dir.join(name);
        fs::write(&src_path, source).expect("write helper source");

        let output = Command::new("cc")
            .arg("-O0")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-o")
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

    async fn trace_program(binary: &Path) -> Vec<SyscallKind> {
        let mut interceptor = grith_supervisor::platform::create_interceptor().unwrap();
        let pid = interceptor
            .spawn_supervised(binary.to_str().unwrap(), &[], &[])
            .await
            .expect("spawn_supervised failed");

        let mut events = Vec::new();
        let start = Instant::now();

        loop {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "timeout waiting for events from pid {pid}"
            );

            match interceptor.next_event().await.expect("next_event failed") {
                Some(event) => {
                    events.push(event.kind.clone());
                    interceptor.allow(event.tid).await.expect("allow failed");
                }
                None => break,
            }
        }

        events
    }

    #[test]
    fn execveat_generates_process_exec_event() {
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let binary = compile_c_program(
            temp.path(),
            "execveat_helper",
            r#"
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    char *argv[] = {"echo", "EXECVEAT_OK", 0};
    char *envp[] = {0};
    return execveat(AT_FDCWD, "/bin/echo", argv, envp, 0);
}
"#,
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let events = runtime.block_on(trace_program(&binary));

        assert!(
            events.iter().any(|event| matches!(
                event,
                SyscallKind::ProcessExec { path, .. } if path.ends_with("/echo")
            )),
            "expected ProcessExec(*echo), saw {events:?}"
        );
    }

    #[test]
    fn clone3_child_is_traced() {
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let binary = compile_c_program(
            temp.path(),
            "clone3_helper",
            r#"
#define _GNU_SOURCE
#include <linux/sched.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    struct clone_args args;
    memset(&args, 0, sizeof(args));
    args.exit_signal = SIGCHLD;

    long child = syscall(SYS_clone3, &args, sizeof(args));
    if (child == 0) {
        execl("/bin/echo", "echo", "CLONE3_CHILD", (char *)0);
        _exit(127);
    }
    if (child < 0) {
        return 1;
    }

    int status = 0;
    waitpid((pid_t)child, &status, 0);
    return 0;
}
"#,
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let events = runtime.block_on(trace_program(&binary));

        let saw_child_exec = events.iter().any(|event| {
            matches!(
                event,
                SyscallKind::ProcessExec { path, .. } if path.ends_with("/echo")
            )
        });

        assert!(
            saw_child_exec,
            "expected traced child exec after clone3, saw {events:?}"
        );
    }

    /// Prove that seccomp filter stacking does not prevent grith from intercepting
    /// syscalls.  Linux composes seccomp filters with AND logic: if the child
    /// installs its own SECCOMP_MODE_FILTER (even one that returns
    /// SECCOMP_RET_ALLOW for everything), grith's outer filter still delivers
    /// PTRACE_EVENT_SECCOMP stops to the tracer.
    ///
    /// The child program:
    /// 1. Installs a trivial BPF filter that ALLOW-s every syscall.
    /// 2. Calls `open("/tmp/grith_seccomp_stack_test", O_RDONLY)`.
    ///
    /// We assert that grith observed a `FileOpen` event for that path, proving
    /// the open() was intercepted despite the child's own seccomp filter.
    #[test]
    fn seccomp_stacking_does_not_block_grith_interception() {
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();

        // Ensure the target file exists so open() doesn't fail with ENOENT.
        let target = "/tmp/grith_seccomp_stack_test";
        std::fs::write(target, b"").expect("create target file");

        let binary = compile_c_program(
            temp.path(),
            "seccomp_stack_helper",
            r#"
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
    /* Install a trivial BPF filter that allows every syscall.
     * This simulates a browser-style child that has its own seccomp policy. */
    struct sock_filter filter[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = 1, .filter = filter };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);

    /* After installing our own seccomp filter, make a file-open syscall.
     * grith's outer filter must still deliver PTRACE_EVENT_SECCOMP for this. */
    int fd = open("/tmp/grith_seccomp_stack_test", O_RDONLY);
    if (fd >= 0) close(fd);
    return 0;
}
"#,
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let events = runtime.block_on(trace_program(&binary));

        assert!(
            events.iter().any(|event| matches!(
                event,
                SyscallKind::FileOpen { path, .. } if path.contains("grith_seccomp_stack_test")
            )),
            "expected FileOpen(*grith_seccomp_stack_test*) after child installed its own seccomp filter; saw {events:?}"
        );
    }

    /// Verify that `classify_syscall` errors are fail-closed: the supervisor
    /// must deny an unclassifiable syscall rather than allow it through.
    ///
    /// The test program calls `openat(AT_FDCWD, (char*)7, O_RDONLY)`.  Address
    /// 7 is non-null but below the kernel's `mmap_min_addr` (normally 65 536),
    /// so it is never mapped.  `read_tracee_string` calls `PTRACE_PEEKDATA` at
    /// that address and returns an `Err`, triggering the classify-error path.
    ///
    /// Expected outcomes:
    /// - Fail-closed (correct): supervisor denies → tracee gets `EPERM` /
    ///   `ENOSYS` → test program records a non-EFAULT errno → exits 0.
    /// - Fail-open (old bug): supervisor allows → kernel executes `openat` →
    ///   kernel returns `EFAULT` (14) to the tracee → test program exits 1.
    #[test]
    fn classify_error_denies_syscall_fail_closed() {
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let result_path = temp.path().join("classify_error_result");

        let binary = compile_c_program(
            temp.path(),
            "bad_ptr_open",
            r#"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    /* Address 7 is non-null but always unmapped on standard Linux.
     * read_tracee_string will fail at PTRACE_PEEKDATA, producing a
     * classify error in the supervisor.  Fail-closed: the supervisor must
     * deny the call so we get EPERM/ENOSYS, not EFAULT from the kernel. */
    long ret = syscall(SYS_openat, AT_FDCWD, (const char *)7L, O_RDONLY);
    int err = (ret < 0) ? errno : 0;

    if (argc > 1) {
        FILE *f = fopen(argv[1], "w");
        if (f) { (void)fprintf(f, "%d\n", err); (void)fclose(f); }
    }
    return 0;
}
"#,
        );

        let result_path_str = result_path.to_str().unwrap().to_owned();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let mut interceptor = grith_supervisor::platform::create_interceptor().unwrap();
            interceptor
                .spawn_supervised(binary.to_str().unwrap(), &[result_path_str], &[])
                .await
                .expect("spawn_supervised failed");

            let start = Instant::now();
            loop {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "timeout waiting for bad_ptr_open to exit"
                );
                match interceptor.next_event().await.expect("next_event failed") {
                    Some(event) => interceptor.allow(event.tid).await.expect("allow failed"),
                    None => break,
                }
            }
        });

        let result = fs::read_to_string(&result_path)
            .expect("result file missing — bad_ptr_open may have crashed before writing it");
        let errno_val: i32 = result
            .trim()
            .parse()
            .expect("result file did not contain a valid errno integer");

        // errno 14 (EFAULT) means the supervisor allowed the syscall through to the
        // kernel, which then rejected it — fail-open (the old behaviour).
        assert_ne!(
            errno_val, 14,
            "got EFAULT: supervisor allowed the unclassifiable syscall through (fail-open)"
        );
        // errno 0 would mean the invalid-pointer openat somehow succeeded — impossible.
        assert_ne!(
            errno_val, 0,
            "openat with unmapped pointer unexpectedly succeeded"
        );
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

    fn compile_c_program_no_pie(dir: &Path, name: &str, source: &str) -> PathBuf {
        let src_path = dir.join(format!("{name}.c"));
        let bin_path = dir.join(name);
        fs::write(&src_path, source).expect("write helper source");

        let output = Command::new("cc")
            .args(["-O0", "-Wall", "-Wextra", "-no-pie", "-fno-pie", "-o"])
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

    /// Run `binary`, denying only `ForeignAbiSyscall` events and allowing
    /// everything else. Returns the observed foreign-ABI events.
    async fn trace_denying_foreign_abi(binary: &Path, args: &[String]) -> Vec<SyscallKind> {
        let mut interceptor = grith_supervisor::platform::create_interceptor().unwrap();
        interceptor
            .spawn_supervised(binary.to_str().unwrap(), args, &[])
            .await
            .expect("spawn_supervised failed");

        let mut foreign = Vec::new();
        let start = Instant::now();
        loop {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "timeout waiting for helper to exit"
            );
            match interceptor.next_event().await.expect("next_event failed") {
                Some(event) => {
                    if matches!(event.kind, SyscallKind::ForeignAbiSyscall { .. }) {
                        foreign.push(event.kind.clone());
                        interceptor.deny(event.tid).await.expect("deny failed");
                    } else {
                        interceptor.allow(event.tid).await.expect("allow failed");
                    }
                }
                None => break,
            }
        }
        foreign
    }

    /// B1: a syscall issued through the i386 compat entry point (`int 0x80`)
    /// must be intercepted and deniable. Before the fix, the seccomp filter's
    /// arch check jumped straight to `SECCOMP_RET_ALLOW`, so a supervised
    /// process could open any file with zero interception.
    ///
    /// The helper is built `-no-pie` so its static path string lives below
    /// 4 GiB and fits the 32-bit `ebx` argument register.
    #[test]
    fn int80_compat_syscall_is_intercepted_and_deniable() {
        if already_traced() {
            eprintln!(
                "SKIP int80_compat_syscall_is_intercepted_and_deniable: process already traced"
            );
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let secret = temp.path().join("id_rsa");
        fs::write(&secret, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        let result_path = temp.path().join("int80_result");

        // i386 open(2) is nr 5: ebx=path, ecx=flags, edx=mode. The raw return
        // in eax is a negative errno, unwrapped by libc.
        let source = format!(
            r#"
#include <stdio.h>

static const char path[] = "{}";

int main(int argc, char **argv) {{
    long ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(5), "b"((int)(long)path), "c"(0), "d"(0)
        : "memory");

    if (argc > 1) {{
        FILE *f = fopen(argv[1], "w");
        if (f) {{ (void)fprintf(f, "%ld\n", ret); (void)fclose(f); }}
    }}
    return 0;
}}
"#,
            secret.to_str().unwrap()
        );

        let binary = compile_c_program_no_pie(temp.path(), "int80_open", &source);
        let args = vec![result_path.to_str().unwrap().to_owned()];

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let foreign = runtime.block_on(trace_denying_foreign_abi(&binary, &args));

        assert!(
            foreign.iter().any(|kind| matches!(
                kind,
                SyscallKind::ForeignAbiSyscall {
                    abi: grith_supervisor::interceptor::ForeignAbiKind::CompatArch,
                    ..
                }
            )),
            "int 0x80 was not intercepted as a foreign-ABI syscall: {foreign:?}"
        );

        let raw: i64 = fs::read_to_string(&result_path)
            .expect("result file missing")
            .trim()
            .parse()
            .expect("result file did not contain an integer");
        // Assert -EPERM exactly. `raw < 0` would also accept the kernel's own
        // ENOSYS (-38) or an EFAULT (-14) from a truncated pointer, so it
        // would keep passing if deny() ever stopped seeding the return
        // register — which is the one thing this test exists to prove.
        assert_eq!(
            raw, -1,
            "int 0x80 open must return -EPERM from grith's deny; got {raw} \
             (-38 = kernel ENOSYS, -14 = EFAULT, >= 0 = the key was opened)"
        );
    }

    /// B1 hardening: the tracee installs its OWN seccomp filter before
    /// issuing `int 0x80`.
    ///
    /// `seccomp(2)` is not trapped and grith already sets
    /// `PR_SET_NO_NEW_PRIVS`, so a supervised process is free to add filters.
    /// When two filters return the same action, the tracer sees the data of
    /// the most recently installed one — so a tracee filter returning
    /// `SECCOMP_RET_TRACE` with data 0 erases grith's foreign-ABI marker. If
    /// the supervisor trusted that marker, the syscall would be classified
    /// through the x86_64 table (i386 `open` is 5, which is `fstat` there) and
    /// waved through. The decision is taken from `PTRACE_GET_SYSCALL_INFO`
    /// instead, which the kernel fills in and no filter can influence.
    #[test]
    fn tracee_installed_seccomp_filter_cannot_forge_the_abi_marker() {
        if already_traced() {
            eprintln!("SKIP tracee_installed_seccomp_filter_cannot_forge_the_abi_marker: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let secret = temp.path().join("id_rsa");
        fs::write(&secret, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        let result_path = temp.path().join("forge_result");

        let source = format!(
            r#"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char path[] = "{}";

/* Return TRACE with data 0 for a foreign arch — same action as grith's
 * filter, but our data, because the newest filter's data wins a tie. */
static struct sock_filter prog[] = {{
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),                       /* arch */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
}};

int main(int argc, char **argv) {{
    struct sock_fprog fprog = {{
        .len = sizeof(prog) / sizeof(prog[0]),
        .filter = prog,
    }};
    (void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    long installed = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog);

    long ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(5), "b"((int)(long)path), "c"(0), "d"(0)
        : "memory");

    if (argc > 1) {{
        FILE *f = fopen(argv[1], "w");
        if (f) {{ (void)fprintf(f, "%ld %ld\n", installed, ret); (void)fclose(f); }}
    }}
    return 0;
}}
"#,
            secret.to_str().unwrap()
        );

        let binary = compile_c_program_no_pie(temp.path(), "forge_marker", &source);
        let args = vec![result_path.to_str().unwrap().to_owned()];

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let foreign = runtime.block_on(trace_denying_foreign_abi(&binary, &args));

        let result = fs::read_to_string(&result_path).expect("result file missing");
        let mut parts = result.split_whitespace();
        let installed: i64 = parts.next().unwrap().parse().unwrap();
        let ret: i64 = parts.next().unwrap().parse().unwrap();
        assert_eq!(
            installed, 0,
            "the tracee's own seccomp filter must install, or this test proves nothing"
        );

        assert!(
            foreign.iter().any(|kind| matches!(
                kind,
                SyscallKind::ForeignAbiSyscall {
                    abi: grith_supervisor::interceptor::ForeignAbiKind::CompatArch,
                    ..
                }
            )),
            "a tracee-installed filter must not hide the foreign ABI: {foreign:?}"
        );
        assert_eq!(
            ret, -1,
            "the int 0x80 open must still be denied with EPERM; got {ret}"
        );
    }

    /// B1: x32 syscall numbers (`nr | 0x40000000`) carry
    /// `AUDIT_ARCH_X86_64` but match no entry in the x86_64 table, so before
    /// the fix they fell through the JEQ chain to `SECCOMP_RET_ALLOW`.
    #[test]
    fn x32_syscall_number_is_intercepted() {
        if already_traced() {
            eprintln!("SKIP x32_syscall_number_is_intercepted: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let secret = temp.path().join("id_rsa");
        fs::write(&secret, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();

        let source = format!(
            r#"
#include <fcntl.h>

static const char path[] = "{}";

int main(void) {{
    long ret;
    /* openat(257) with the x32 bit set. */
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(257L | 0x40000000L), "D"(AT_FDCWD), "S"(path), "d"(0)
        : "rcx", "r11", "memory");
    (void)ret;
    return 0;
}}
"#,
            secret.to_str().unwrap()
        );

        let binary = compile_c_program(temp.path(), "x32_open", &source);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let foreign = runtime.block_on(trace_denying_foreign_abi(&binary, &[]));

        assert!(
            foreign.iter().any(|kind| matches!(
                kind,
                SyscallKind::ForeignAbiSyscall {
                    abi: grith_supervisor::interceptor::ForeignAbiKind::X32,
                    ..
                }
            )),
            "x32-numbered syscall was not intercepted as a foreign-ABI syscall: {foreign:?}"
        );
    }

    /// B1 round 3: the foreign-ABI check distinguishes "this stop carries no
    /// syscall-entry record" from "`PTRACE_GET_SYSCALL_INFO` is unsupported",
    /// and never reads `PTRACE_GETEVENTMSG` at a plain syscall stop. This
    /// test pins the kernel contract that distinction rests on (≥5.3):
    ///
    /// 1. at a syscall-entry stop the request succeeds with `op == ENTRY`
    ///    and the kernel's own record of the number;
    /// 2. at the matching exit stop the request STILL succeeds — with
    ///    `op == EXIT` — so "no entry record here" is knowable without
    ///    guessing, and must not be conflated with a pre-5.3 kernel;
    /// 3. `PTRACE_GETEVENTMSG` succeeds at BOTH stops — since 5.3 the
    ///    kernel sets the message to `PTRACE_EVENTMSG_SYSCALL_ENTRY` (1) /
    ///    `PTRACE_EVENTMSG_SYSCALL_EXIT` (2) at syscall stops, and 2 is
    ///    numerically equal to grith's `SECCOMP_TRACE_DATA_X32` marker. A
    ///    tracer consulting the message at a syscall stop therefore
    ///    classifies every exit stop as an x32 syscall — the deterministic
    ///    mechanism that hard-denied ordinary syscalls (the EPERM'd
    ///    `futex(2)` that aborted whole supervised trees).
    ///
    /// The helper is its own tracer/tracee pair; exit codes: 0 = contract
    /// holds, 42 = `PTRACE_GET_SYSCALL_INFO` unsupported (pre-5.3 — skip),
    /// 43 = the child could not `PTRACE_TRACEME` (already traced — skip).
    #[test]
    fn get_syscall_info_distinguishes_entry_from_exit_stops() {
        if already_traced() {
            eprintln!(
                "SKIP get_syscall_info_distinguishes_entry_from_exit_stops: process already traced"
            );
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();

        let source = r#"
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Defined locally so the test states the ABI it relies on, independent of
 * glibc header version. Prefix of struct ptrace_syscall_info: entry/seccomp
 * place the syscall number at this offset; at an exit stop the same bytes
 * hold the return value instead. */
#define GET_SYSCALL_INFO 0x420e
#define OP_ENTRY 1
#define OP_EXIT 2

struct info_prefix {
    uint8_t op;
    uint8_t pad[3];
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
    uint64_t nr;
};

int main(void) {
    pid_t child = fork();
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(43);
        raise(SIGSTOP);
        syscall(SYS_getppid);
        _exit(0);
    }

    int st;
    if (waitpid(child, &st, 0) != child) return 1;
    /* TRACEME refused (the child already has a tracer): propagate 43. */
    if (WIFEXITED(st)) return WEXITSTATUS(st) == 43 ? 43 : 1;
    if (!WIFSTOPPED(st)) return 1;
    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD) != 0) return 1;

    /* phase 0: wait for the getppid entry stop; phase 1: its exit stop. */
    int phase = 0;
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, child, 0, 0) != 0) return 1;
        if (waitpid(child, &st, 0) != child) return 1;
        if (WIFEXITED(st)) {
            /* Reached only after both stops verified (phase == 2). */
            return phase == 2 ? WEXITSTATUS(st) : 4;
        }
        if (!(WIFSTOPPED(st) && WSTOPSIG(st) == (SIGTRAP | 0x80))) continue;

        struct info_prefix info;
        memset(&info, 0, sizeof info);
        long ret = ptrace(GET_SYSCALL_INFO, child, (void *)sizeof info, &info);
        if (ret <= 0) {
            fprintf(stderr, "GET_SYSCALL_INFO unsupported (errno %d)\n", errno);
            kill(child, SIGKILL);
            return 42;
        }

        unsigned long msg = 0;
        long evret = ptrace(PTRACE_GETEVENTMSG, child, 0, &msg);

        if (phase == 0) {
            if (info.op == OP_ENTRY && info.nr == SYS_getppid) {
                /* (3): GETEVENTMSG succeeds at a syscall stop and returns
                 * the kernel's PTRACE_EVENTMSG_SYSCALL_ENTRY (1). */
                if (evret != 0) {
                    fprintf(stderr, "GETEVENTMSG failed at entry stop\n");
                    return 2;
                }
                if (msg != 1) {
                    fprintf(stderr, "entry-stop eventmsg %lu, expected 1\n", msg);
                    return 5;
                }
                phase = 1;
            }
            continue;
        }
        if (phase == 1) {
            /* (2): the very next syscall stop is getppid's exit — the
             * request still succeeds and says so explicitly. */
            if (info.op != OP_EXIT) {
                fprintf(stderr, "expected op EXIT (%d) at exit stop, got %d\n",
                        OP_EXIT, info.op);
                return 3;
            }
            if (evret != 0) {
                fprintf(stderr, "GETEVENTMSG failed at exit stop\n");
                return 2;
            }
            /* (3): PTRACE_EVENTMSG_SYSCALL_EXIT is 2 — numerically equal
             * to grith's SECCOMP_TRACE_DATA_X32 marker. A tracer that reads
             * the event message at a syscall stop therefore classifies
             * EVERY exit stop as an x32 syscall: the deterministic
             * mechanism behind the B1 round-3 crash, not a rare race. */
            if (msg != 2) {
                fprintf(stderr, "exit-stop eventmsg %lu, expected 2\n", msg);
                return 5;
            }
            phase = 2;
            continue;
        }
    }
}
"#;

        let binary = compile_c_program(temp.path(), "syscall_info_stops", source);
        let output = Command::new(&binary).output().expect("run helper");
        match output.status.code() {
            Some(0) => {}
            Some(42) => {
                eprintln!(
                    "SKIP get_syscall_info_distinguishes_entry_from_exit_stops: pre-5.3 kernel"
                );
            }
            Some(43) => {
                eprintln!("SKIP get_syscall_info_distinguishes_entry_from_exit_stops: child already traced");
            }
            code => panic!(
                "kernel syscall-info contract violated (exit {code:?})\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        }
    }
}
