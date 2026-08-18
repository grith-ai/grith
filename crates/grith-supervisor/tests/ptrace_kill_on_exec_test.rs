// Integration test for the kill-on-deny primitive (fix/deny-spawn-kills-tracee).
//
// A `ProcessSpawn` is intercepted at `PTRACE_EVENT_EXEC` — after execve has
// returned into the new program image — so `deny_syscall` has no in-flight
// syscall to convert to EPERM and is a silent no-op: the exec'd program runs
// anyway. `SyscallInterceptor::kill` closes that gap by SIGKILLing the tracee
// at the exec stop, before it runs its first userspace instruction. This test
// drives the REAL ptrace supervisor over a fork+exec and asserts, on a live
// kernel, that (1) the exec'd payload never runs, (2) the child dies by
// SIGKILL, and (3) the supervisor loop terminates (no hang from a
// stopped-with-pending-SIGKILL tracee).

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

    /// True when this process already has a tracer (e.g. the suite is itself
    /// running under `grith exec`). Linux permits one tracer per process, so
    /// `PTRACE_TRACEME` in the helper child returns `EPERM` and no ptrace test
    /// here can run. CI is unsupervised.
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

    /// A denied `ProcessSpawn` (intercepted at `PTRACE_EVENT_EXEC`) must be
    /// stopped by SIGKILL, not the no-op `deny_syscall`, so the exec'd program
    /// never runs its payload — and the supervisor loop must still drain to
    /// completion.
    #[test]
    fn kill_on_exec_stops_the_payload_without_hanging() {
        if already_traced() {
            eprintln!(
                "SKIP kill_on_exec_stops_the_payload_without_hanging: process already traced"
            );
            return;
        }
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("payload_ran_marker");
        let status_path = temp.path().join("child_status");

        // The payload writes a marker iff it is allowed to run. If the kill
        // works, this file is never created.
        let payload_src = format!(
            r#"
#include <stdio.h>
int main(void) {{
    FILE *f = fopen("{marker}", "w");
    if (f) {{ fputs("ran", f); fclose(f); }}
    return 0;
}}
"#,
            marker = marker.display(),
        );

        // The spawner fork+execs the payload and records how the child died.
        let payload_bin = compile_c_program(temp.path(), "kill_payload", &payload_src);
        let spawner_src = format!(
            r#"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
int main(void) {{
    pid_t p = fork();
    if (p == 0) {{
        execl("{payload}", "kill_payload", (char *)NULL);
        _exit(127); /* exec failed */
    }}
    int st = 0;
    waitpid(p, &st, 0);
    FILE *f = fopen("{status}", "w");
    if (f) {{
        fprintf(f, "%d %d", WIFSIGNALED(st) ? 1 : 0,
                WIFSIGNALED(st) ? WTERMSIG(st) : WEXITSTATUS(st));
        fclose(f);
    }}
    return 0;
}}
"#,
            payload = payload_bin.display(),
            status = status_path.display(),
        );
        let spawner_bin = compile_c_program(temp.path(), "kill_spawner", &spawner_src);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let killed_exec = runtime.block_on(async {
            let mut interceptor = grith_supervisor::platform::create_interceptor().unwrap();
            let root_pid = interceptor
                .spawn_supervised(spawner_bin.to_str().unwrap(), &[], &[])
                .await
                .expect("spawn_supervised failed");

            let mut killed = false;
            let start = Instant::now();
            loop {
                assert!(
                    start.elapsed() < Duration::from_secs(20),
                    "timeout — the supervisor loop hung after killing the exec'd tracee (pid {root_pid})"
                );
                match interceptor.next_event().await.expect("next_event failed") {
                    Some(event) => {
                        // Kill the CHILD's exec of the payload; allow everything
                        // else (including the spawner's own initial exec).
                        let is_payload_exec = matches!(
                            &event.kind,
                            SyscallKind::ProcessExec { path, .. } if path.contains("kill_payload")
                        );
                        if is_payload_exec {
                            interceptor.kill(event.tid).await.expect("kill failed");
                            killed = true;
                        } else {
                            interceptor.allow(event.tid).await.expect("allow failed");
                        }
                    }
                    None => break,
                }
            }
            killed
        });

        assert!(
            killed_exec,
            "the payload's ProcessExec was never intercepted — nothing was killed"
        );
        assert!(
            !marker.exists(),
            "the payload RAN despite being killed at its exec stop (marker was written) — \
             kill-on-deny did not stop the spawn"
        );

        // The spawner drained to completion and recorded the child's fate.
        let status = fs::read_to_string(&status_path)
            .expect("spawner did not write child status — did the loop hang or the spawner die?");
        let mut parts = status.split_whitespace();
        let signalled: i32 = parts.next().unwrap().parse().unwrap();
        let code: i32 = parts.next().unwrap().parse().unwrap();
        assert_eq!(
            signalled, 1,
            "child should have died by signal, not a normal exit (status: {status:?})"
        );
        assert_eq!(
            code, 9,
            "child should have been terminated by SIGKILL(9); got signal {code}"
        );
    }
}
