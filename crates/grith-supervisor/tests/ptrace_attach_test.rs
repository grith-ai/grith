// Integration test: use grith's actual PtraceSupervisor attach path
// This mimics the PTY path used by `grith exec`

#[cfg(target_os = "linux")]
#[test]
#[allow(unreachable_code)]
fn grith_supervisor_attach_and_trace() {
    use nix::unistd::{fork, ForkResult};
    use std::ffi::CString;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        // Spawn a child that sleeps briefly (simulates PTY-spawned process)
        let child_pid = match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                // Child: sleep a bit to give parent time to attach, then do something
                let cmd = CString::new("/bin/sleep").unwrap();
                let arg0 = CString::new("sleep").unwrap();
                let arg1 = CString::new("2").unwrap();
                nix::unistd::execv(&cmd, &[arg0, arg1]).expect("execv");
                unreachable!()
            }
            Ok(ForkResult::Parent { child }) => child.as_raw() as u32,
            Err(e) => panic!("fork failed: {e}"),
        };

        eprintln!("[test] spawned child pid={child_pid}");

        // Give child a moment to exec
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut interceptor = grith_supervisor::platform::create_interceptor().unwrap();

        eprintln!("[test] attaching...");
        interceptor.attach(child_pid).await.expect("attach failed");
        eprintln!("[test] attached successfully");

        let mut count = 0u32;
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > std::time::Duration::from_secs(3) {
                // Check if process is still alive
                let status = std::fs::read_to_string(format!("/proc/{child_pid}/status"));
                eprintln!("[test] TIMEOUT after {count} events");
                if let Ok(s) = status {
                    for line in s.lines() {
                        if line.starts_with("State:") || line.starts_with("TracerPid:") {
                            eprintln!("[test] {line}");
                        }
                    }
                }
                // Kill the child and break
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(child_pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
                panic!("TIMEOUT: next_event stuck after {count} events");
            }

            match interceptor.next_event().await {
                Ok(Some(event)) => {
                    count += 1;
                    if count <= 10 {
                        eprintln!("[test] event #{count}: {:?}", event.kind);
                    }
                    interceptor.allow(event.tid).await.unwrap();
                }
                Ok(None) => {
                    eprintln!("[test] all processes exited after {count} events");
                    break;
                }
                Err(e) => {
                    eprintln!("[test] error after {count} events: {e}");
                    break;
                }
            }
        }

        eprintln!("[test] total events: {count}");
    });
}
