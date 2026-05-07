// Integration test: use grith's actual PtraceSupervisor
// Tests spawn_supervised + next_event loop

#[cfg(target_os = "linux")]
#[test]
fn grith_supervisor_spawn_and_trace() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let mut interceptor = grith_supervisor::platform::create_interceptor().unwrap();

        let pid = interceptor
            .spawn_supervised("/bin/echo", &["HELLO_GRITH".into()], &[])
            .await
            .expect("spawn_supervised failed");

        eprintln!("[test] spawned pid={pid}");

        let mut count = 0u32;
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!(
                    "TIMEOUT after {count} events — next_event is stuck. \
                     Check /proc/{pid}/status if process still exists."
                );
            }

            match interceptor.next_event().await {
                Ok(Some(event)) => {
                    count += 1;
                    eprintln!("[test] event #{count}: {:?}", event.kind);
                    // Allow the syscall to proceed
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

        eprintln!("[test] total security-relevant events: {count}");
        // /bin/echo should produce at least a few events (write, etc.)
        assert!(count >= 1, "expected at least 1 event, got {count}");
    });
}
