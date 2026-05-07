// Integration test: ptrace inside a Tokio current_thread runtime
// This reproduces the exact conditions of `grith exec`.

#[cfg(target_os = "linux")]
#[test]
#[allow(unreachable_code)]
fn ptrace_works_in_tokio_current_thread() {
    use nix::sys::ptrace;
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::{fork, ForkResult, Pid};
    use std::ffi::CString;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let c_cmd = CString::new("/bin/echo").unwrap();
        let c_arg0 = CString::new("echo").unwrap();
        let c_arg1 = CString::new("HELLO_TOKIO").unwrap();

        let child_pid = match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                ptrace::traceme().expect("PTRACE_TRACEME");
                nix::unistd::execv(&c_cmd, &[c_arg0, c_arg1]).expect("execv");
                unreachable!()
            }
            Ok(ForkResult::Parent { child }) => child,
            Err(e) => panic!("fork failed: {e}"),
        };

        // Wait for initial exec stop
        let ws = waitpid(child_pid, None).unwrap();
        eprintln!("[test] initial stop: {ws:?}");

        // Set options (same as grith)
        use nix::sys::ptrace::Options;
        let opts = Options::PTRACE_O_TRACESYSGOOD
            | Options::PTRACE_O_TRACEEXEC
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACECLONE;
        ptrace::setoptions(child_pid, opts).unwrap();

        // Resume
        ptrace::syscall(child_pid, None).unwrap();

        // WNOHANG poll loop (like grith's next_event)
        let mut count = 0u32;
        let mut polls = 0u32;
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("TIMEOUT: {count} syscall stops, {polls} empty polls — process is stuck");
            }

            let status = match waitpid(
                Pid::from_raw(-1),
                Some(WaitPidFlag::WNOHANG | WaitPidFlag::__WALL),
            ) {
                Ok(WaitStatus::StillAlive) => {
                    polls += 1;
                    tokio::time::sleep(std::time::Duration::from_micros(100)).await;
                    continue;
                }
                Ok(s) => s,
                Err(nix::errno::Errno::ECHILD) => {
                    eprintln!("[test] ECHILD — no children left");
                    break;
                }
                Err(e) => panic!("waitpid error: {e}"),
            };

            match status {
                WaitStatus::PtraceSyscall(pid) => {
                    count += 1;
                    ptrace::syscall(pid, None).unwrap();
                }
                WaitStatus::PtraceEvent(pid, _sig, event) => {
                    eprintln!("[test] ptrace event: {event}");
                    ptrace::syscall(pid, None).unwrap();
                }
                WaitStatus::Stopped(pid, sig) => {
                    eprintln!("[test] stopped by signal: {sig:?}");
                    let fwd = if sig == nix::sys::signal::Signal::SIGSTOP
                        || sig == nix::sys::signal::Signal::SIGTRAP
                    {
                        None
                    } else {
                        Some(sig)
                    };
                    ptrace::syscall(pid, fwd).unwrap();
                }
                WaitStatus::Exited(pid, code) => {
                    eprintln!("[test] exited pid={pid} code={code}");
                    break;
                }
                WaitStatus::Signaled(pid, sig, _) => {
                    eprintln!("[test] signaled pid={pid} sig={sig:?}");
                    break;
                }
                _ => {}
            }
        }

        eprintln!("[test] total syscall stops: {count}, empty polls: {polls}");
        assert!(count > 10, "expected many syscall stops, got {count}");
    });
}
