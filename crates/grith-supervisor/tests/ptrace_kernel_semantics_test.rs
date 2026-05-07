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
}
