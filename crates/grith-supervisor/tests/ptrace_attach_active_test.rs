// Integration test: attach to a process doing active file I/O

#[cfg(target_os = "linux")]
#[test]
#[allow(unreachable_code)]
fn grith_supervisor_attach_active_process() {
    use std::ffi::CString;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        // Spawn a child that reads files (security-relevant syscalls)
        let child_pid = match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Child) => {
                // Wait a moment for parent to set up attach
                std::thread::sleep(std::time::Duration::from_millis(200));
                // Do file I/O: ls reads directory entries + opens files
                let cmd = CString::new("/bin/ls").unwrap();
                let arg0 = CString::new("ls").unwrap();
                let arg1 = CString::new("-la").unwrap();
                let arg2 = CString::new("/tmp").unwrap();
                nix::unistd::execv(&cmd, &[arg0, arg1, arg2]).expect("execv");
                unreachable!()
            }
            Ok(nix::unistd::ForkResult::Parent { child }) => child.as_raw() as u32,
            Err(e) => panic!("fork failed: {e}"),
        };

        eprintln!("[test] spawned child pid={child_pid}");

        // Give child a moment
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut interceptor = grith_supervisor::platform::create_interceptor().unwrap();

        eprintln!("[test] attaching to pid={child_pid}...");
        interceptor.attach(child_pid).await.expect("attach failed");
        eprintln!("[test] attached successfully");

        let mut count = 0u32;
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > std::time::Duration::from_secs(30) {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(child_pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
                panic!("TIMEOUT: stuck after {count} events");
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
        assert!(count >= 1, "expected at least 1 event from ls, got {count}");
    });
}
