// Integration test: spawn_supervised + run_supervisor_loop (full pipeline)
// This reproduces the exact code path of `grith exec -- /bin/echo HELLO`
// without the audit_sync_task.

#[cfg(target_os = "linux")]
#[test]
fn full_supervisor_loop_with_real_process() {
    use grith_proxy::engine::SecurityProxy;
    use grith_proxy::filters::FilterRegistry;
    use grith_proxy::meta_rules::MetaRuleEngine;
    use grith_proxy::scoring::ScoringConfig;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::broadcast;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let mut interceptor: Box<dyn grith_supervisor::interceptor::SyscallInterceptor> =
            grith_supervisor::platform::create_interceptor().unwrap();

        let pid = interceptor
            .spawn_supervised("/bin/echo", &["HELLO_FULL_LOOP".into()], &[])
            .await
            .expect("spawn_supervised failed");

        eprintln!("[test] spawned pid={pid}");

        // Create a permissive proxy (all-allow, no filters)
        let registry = FilterRegistry::new();
        let scoring = ScoringConfig {
            auto_allow_threshold: 3.0,
            auto_deny_threshold: 8.0,
        };
        let proxy = Arc::new(SecurityProxy::new(
            registry,
            scoring,
            MetaRuleEngine::new(vec![]),
        ));

        let mut session = grith_supervisor::supervisor::SupervisorSession::new("echo", pid);

        let audit_storage = Arc::new(std::sync::Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let audit_sink: Arc<dyn grith_supervisor::AuditSink> =
            Arc::new(grith_supervisor::StorageAuditSink::new(audit_storage));
        let digest_queue = Arc::new(grith_digest::queue::DigestQueue::open_in_memory().unwrap());
        let digest_store: Arc<dyn grith_supervisor::DigestStore> =
            Arc::new(grith_supervisor::LocalDigestStore::new(digest_queue));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let containment_tracker = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::with_defaults(),
        );
        let config = grith_supervisor::config::SupervisorConfig::default();
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);

        // Simulate a background task (like audit_sync_task) that does async work
        tokio::spawn(async {
            loop {
                // Simulate periodic background work
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });

        eprintln!("[test] starting supervisor loop");
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            grith_supervisor::supervisor::run_supervisor_loop(
                &mut interceptor,
                &mut session,
                proxy,
                audit_sink,
                digest_store,
                &dlp_redactor,
                correlation_tracker,
                containment_tracker,
                &config,
                shutdown_rx,
                None,
                None,
                None,
                &[],
                std::collections::HashSet::new(),
                None,
                None,
                None,
                None,
                None,
            ),
        )
        .await;

        match &result {
            Ok(Ok(())) => eprintln!("[test] supervisor loop completed successfully"),
            Ok(Err(e)) => eprintln!("[test] supervisor loop error: {e}"),
            Err(tokio::time::error::Elapsed { .. }) => {
                panic!("TIMEOUT: supervisor loop stuck for 15 seconds")
            }
        }
        result.unwrap().unwrap();

        eprintln!(
            "[test] stats: allowed={} denied={} queued={} noise={}",
            session.stats.total_allowed,
            session.stats.total_denied,
            session.stats.total_queued,
            session.stats.total_filtered_noise,
        );
    });
}
