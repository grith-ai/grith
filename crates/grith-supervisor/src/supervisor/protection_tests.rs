// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Protection / adversarial test suite (supervised-syscall level).
//!
//! These tests prove grith's *protection* behaviour end-to-end through
//! `event_handler::handle_syscall_event`: a crafted `SyscallEvent` is driven
//! through the real supervisor decision path (pre-proxy hard-denies, the
//! coverage flag gate, the proxy, then `enforce_decision`) and we assert the
//! supervisor took the intended `allow` / `deny` / `freeze` action.
//!
//! Lives in `grith-supervisor` (not `grith-tests`) because
//! `handle_syscall_event` and `SupervisorLoopContext` are `pub(super)`.
//! Proxy-filter-level protection tests (canary, taint, egress, secret-scan…)
//! live in `grith-tests` against `TestFixtures`.
//!
//! See `work/futurework/protection-test-suite-research.md` (§4 matrix, §6 plan).
//!
//! `Harness` owns the pieces the (lifetime-bearing) `SupervisorLoopContext`
//! borrows and constructs the context inline per `run`, so a test is a few
//! lines: build events, `harness.run(events).await`, assert on `Recorded`.

#![cfg(test)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;

use grith_digest::types::{DigestItem, ReviewOutcome};
use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::operation_risk::OperationRiskFilter;
use grith_proxy::filters::sensitive_path::SensitivePathHeuristicFilter;
use grith_proxy::filters::session_containment::ContainmentTracker;
use grith_proxy::filters::{FilterRegistry, SecurityFilter};
use grith_proxy::meta_rules::MetaRuleEngine;
use grith_proxy::scoring::ScoringConfig;

use super::event_handler::{handle_syscall_event, ReadBatchTracker, SupervisorLoopContext};
use super::SupervisorSession;
use crate::config::{CoverageConfig, SupervisorConfig};
use crate::dns_cache::DnsCache;
use crate::freezer::Freezer;
use crate::interceptor::{
    NamespaceSyscall, OpenFlags, OwnershipOp, SyscallEvent, SyscallInterceptor, SyscallKind,
};
use crate::reviewer::{DigestStore, QueueReviewer};

// ---------------------------------------------------------------------------
// Recording interceptor — captures the supervisor's enforcement actions
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct RecordedState {
    allow_pids: Vec<u32>,
    deny_pids: Vec<u32>,
    freeze_pids: Vec<u32>,
}

struct RecordingInterceptor {
    state: Arc<Mutex<RecordedState>>,
}

#[async_trait]
impl SyscallInterceptor for RecordingInterceptor {
    async fn attach(&mut self, pid: u32) -> crate::error::Result<()> {
        Err(crate::error::Error::AttachFailed {
            pid,
            reason: "recording interceptor does not attach".into(),
        })
    }

    async fn spawn_supervised(
        &mut self,
        _command: &str,
        _args: &[String],
        _env: &[(String, String)],
    ) -> crate::error::Result<u32> {
        Err(crate::error::Error::SpawnFailed(
            "recording interceptor does not spawn".into(),
        ))
    }

    async fn next_event(&mut self) -> crate::error::Result<Option<SyscallEvent>> {
        Ok(None)
    }

    async fn allow(&mut self, pid: u32) -> crate::error::Result<()> {
        self.state.lock().unwrap().allow_pids.push(pid);
        Ok(())
    }

    async fn deny(&mut self, pid: u32) -> crate::error::Result<()> {
        self.state.lock().unwrap().deny_pids.push(pid);
        Ok(())
    }

    async fn freeze(&mut self, pid: u32) -> crate::error::Result<()> {
        self.state.lock().unwrap().freeze_pids.push(pid);
        Ok(())
    }

    async fn thaw(&mut self, _pid: u32) -> crate::error::Result<()> {
        Ok(())
    }

    async fn detach(&mut self, _pid: u32) -> crate::error::Result<()> {
        Ok(())
    }

    async fn detach_all(&mut self) -> crate::error::Result<()> {
        Ok(())
    }

    fn supervised_pids(&self) -> Vec<u32> {
        Vec::new()
    }

    fn is_available() -> bool
    where
        Self: Sized,
    {
        true
    }

    fn mechanism_name(&self) -> &str {
        "recording"
    }
}

/// A reviewer that denies everything it is asked to review. Hard-deny tests
/// never reach review; queue-path tests get a deterministic Deny outcome.
struct DenyReviewer;

#[async_trait]
impl QueueReviewer for DenyReviewer {
    async fn review(&self, _item: &DigestItem, _timeout: Duration) -> ReviewOutcome {
        ReviewOutcome::Denied
    }
}

/// What the supervisor did, captured from the recording interceptor + session.
/// Some fields (freeze, the stat counters) are consumed by later-phase queue /
/// flag-matrix / containment tests.
#[derive(Debug)]
#[allow(dead_code)]
struct Recorded {
    allow_pids: Vec<u32>,
    deny_pids: Vec<u32>,
    freeze_pids: Vec<u32>,
    total_allowed: u64,
    total_queued: u64,
    total_denied: u64,
}

impl Recorded {
    fn denied(&self, pid: u32) -> bool {
        self.deny_pids.contains(&pid)
    }
    fn allowed(&self, pid: u32) -> bool {
        self.allow_pids.contains(&pid)
    }
}

// ---------------------------------------------------------------------------
// Harness — owns the borrowed pieces; builds the loop_ctx inline per run
// ---------------------------------------------------------------------------

struct Harness {
    proxy: Arc<SecurityProxy>,
    config: SupervisorConfig,
    routine_exec_roots: Vec<String>,
    scratch_roots: Vec<String>,
    namespace_users: Vec<String>,
    working_root: Option<PathBuf>,
    session_allowed: HashSet<String>,
}

impl Default for Harness {
    fn default() -> Self {
        Self {
            // Empty registry = "the proxy would ALLOW everything"; isolates the
            // supervisor's pre-/post-proxy decisions (hard-denies, flag gate).
            proxy: Arc::new(SecurityProxy::new(
                FilterRegistry::new(),
                ScoringConfig::default(),
                MetaRuleEngine::new(vec![]),
            )),
            config: SupervisorConfig::default(),
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            namespace_users: Vec::new(),
            working_root: None,
            session_allowed: HashSet::new(),
        }
    }
}

impl Harness {
    fn new() -> Self {
        Self::default()
    }

    /// Override the coverage feature flags (PR 6 category gating).
    #[allow(dead_code)] // used by the Phase-3 flag-state matrix
    fn with_coverage(mut self, coverage: CoverageConfig) -> Self {
        self.config.coverage = coverage;
        self
    }

    #[allow(dead_code)] // used by later phases (flag-matrix / proxy-backed scenarios)
    fn with_proxy(mut self, proxy: Arc<SecurityProxy>) -> Self {
        self.proxy = proxy;
        self
    }

    #[allow(dead_code)]
    fn with_routine_exec_roots(mut self, roots: Vec<String>) -> Self {
        self.routine_exec_roots = roots;
        self
    }

    #[allow(dead_code)]
    fn with_namespace_users(mut self, users: Vec<String>) -> Self {
        self.namespace_users = users;
        self
    }

    /// Set the session working root. Deletes/renames under it are in-tree and
    /// excluded from the mass-destruction signal — used to isolate a test from
    /// that signal so it asserts ONLY the behaviour under test.
    fn with_working_root(mut self, root: &str) -> Self {
        self.working_root = Some(PathBuf::from(root));
        self
    }

    /// Drive `events` through `handle_syscall_event` against one session and
    /// return what the supervisor did. The `SupervisorLoopContext` is built
    /// once and reused across events so cross-call session state (taint,
    /// mass-destruction window, allowlist) persists like a real session.
    async fn run(&self, events: Vec<SyscallEvent>) -> Recorded {
        let state = Arc::new(Mutex::new(RecordedState::default()));
        let mut interceptor: Box<dyn SyscallInterceptor> = Box::new(RecordingInterceptor {
            state: state.clone(),
        });
        let pid0 = events.first().map(|e| e.pid).unwrap_or(4242);
        let mut session = SupervisorSession::new("protection-test", pid0);

        // Owned locals the loop_ctx borrows for the lifetime of `run`.
        let audit_storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let audit_sink: Arc<dyn crate::audit_sink::AuditSink> =
            Arc::new(crate::audit_sink::StorageAuditSink::new(audit_storage));
        let digest_queue = Arc::new(grith_digest::queue::DigestQueue::open_in_memory().unwrap());
        let digest_store: Arc<dyn DigestStore> =
            Arc::new(crate::reviewer::LocalDigestStore::new(digest_queue));
        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let containment_tracker = Arc::new(ContainmentTracker::new(Duration::from_secs(60)));

        let loop_ctx = SupervisorLoopContext {
            proxy: &self.proxy,
            audit_sink,
            digest_store,
            dlp_redactor: &dlp_redactor,
            correlation_tracker: &correlation_tracker,
            containment_tracker: &containment_tracker,
            config: &self.config,
            event_tx: None,
            freezer: Freezer::new(Duration::from_secs(self.config.freeze_timeout_seconds)),
            read_batch_tracker: Mutex::new(ReadBatchTracker::new(10)),
            reviewer: Arc::new(DenyReviewer),
            session_sync: None,
            session_allowed: Mutex::new(self.session_allowed.clone()),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_proxy_port: None,
            dns_query_rx: None,
            syscall_log: None,
            forensics_trace: None,
            reputation_table: Arc::new(Mutex::new(grith_proxy::reputation::ReputationTable::new())),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            daemon_restart: None,
            persist_local_reputation: true,
            routine_exec_roots: self.routine_exec_roots.clone(),
            scratch_roots: self.scratch_roots.clone(),
            local_listener_policy: Vec::new(),
            namespace_users: self.namespace_users.clone(),
            working_root: self.working_root.clone(),
            mass_destruction: Mutex::new(
                super::mass_destruction::MassDestructionTracker::with_defaults(),
            ),
        };

        for event in events {
            handle_syscall_event(&mut interceptor, &mut session, &loop_ctx, event)
                .await
                .expect("handle_syscall_event should not error in protection tests");
        }

        let s = state.lock().unwrap();
        Recorded {
            allow_pids: s.allow_pids.clone(),
            deny_pids: s.deny_pids.clone(),
            freeze_pids: s.freeze_pids.clone(),
            total_allowed: session.stats.total_allowed,
            total_queued: session.stats.total_queued,
            total_denied: session.stats.total_denied,
        }
    }
}

// ---------------------------------------------------------------------------
// Event builders
// ---------------------------------------------------------------------------

fn event(pid: u32, raw_syscall_nr: i64, kind: SyscallKind) -> SyscallEvent {
    SyscallEvent {
        pid,
        tid: pid,
        timestamp: Utc::now(),
        kind,
        raw_syscall_nr,
        sockaddr_addr: None,
    }
}

// Syscall numbers (x86-64) for events whose handler keys off raw_syscall_nr.
use crate::platform::linux::syscall_nr;

// ===========================================================================
// Phase 1 — raw-socket creation is hard-denied before proxy evaluation
// (research doc §5.2: "Raw-socket hard-deny … no test")
// AF_PACKET (17) / AF_NETLINK (16) bypass the IP stack and the egress filter.
// ===========================================================================

// The raw-socket deny returns BEFORE proxy evaluation and does NOT increment
// `total_denied` (a pre-proxy hard-deny, verified at event_handler.rs:706). So
// `total_denied == 0` proves the deny came from the hard-deny branch and not
// from a proxy / `enforce_decision` deny — "mechanism, not just outcome" (§6.4).
fn assert_hard_denied(r: &Recorded, pid: u32) {
    assert_eq!(
        r.deny_pids,
        vec![pid],
        "expected exactly one deny of {pid}: {r:?}"
    );
    assert!(
        r.allow_pids.is_empty(),
        "hard-deny must not also allow: {r:?}"
    );
    assert_eq!(
        r.total_denied, 0,
        "pre-proxy hard-deny must not bump total_denied (proves it bypassed the proxy): {r:?}"
    );
    assert_eq!(r.total_queued, 0, "hard-deny must not queue: {r:?}");
}

#[tokio::test]
async fn protection_raw_socket_af_packet_is_denied() {
    let pid = 7001;
    let ev = event(
        pid,
        syscall_nr::SOCKET,
        SyscallKind::RawSocketCreate {
            domain: 17, // AF_PACKET
            socket_type: 3,
            protocol: 0,
        },
    );
    assert_hard_denied(&Harness::new().run(vec![ev]).await, pid);
}

#[tokio::test]
async fn protection_raw_socket_af_netlink_is_denied() {
    let pid = 7002;
    let ev = event(
        pid,
        syscall_nr::SOCKET,
        SyscallKind::RawSocketCreate {
            domain: 16, // AF_NETLINK
            socket_type: 3,
            protocol: 0,
        },
    );
    assert_hard_denied(&Harness::new().run(vec![ev]).await, pid);
}

// ===========================================================================
// Phase 1 — grith config-write self-protection (event_handler.rs:1033-1078)
// (research doc §5.2: claimed "covered" but no test exercised the branch)
// A prompt injection that writes grith's own config/learned-rules/creds could
// silently weaken enforcement for all future sessions. ALL mutating op shapes
// the branch handles must be covered.
//
// Unlike the pre-proxy hard-denies, this branch bumps `total_denied` (1076), so
// `total_denied == 1` is the mechanism signal that THIS branch produced the deny.
// ===========================================================================

fn assert_config_write_denied(r: &Recorded, pid: u32) {
    assert_eq!(
        r.deny_pids,
        vec![pid],
        "expected exactly one deny of {pid}: {r:?}"
    );
    assert!(
        r.allow_pids.is_empty(),
        "config-write deny must not also allow: {r:?}"
    );
    assert_eq!(
        r.total_denied, 1,
        "the config-write self-protection branch increments total_denied: {r:?}"
    );
}

#[tokio::test]
async fn protection_grith_config_overwrite_is_denied() {
    let pid = 7010;
    // The obvious attack: overwrite grith's config to weaken enforcement.
    let ev = event(
        pid,
        syscall_nr::OPENAT,
        SyscallKind::FileWrite {
            fd: 5,
            path: Some("/home/u/.config/grith/config.toml".into()),
        },
    );
    assert_config_write_denied(&Harness::new().run(vec![ev]).await, pid);
}

#[tokio::test]
async fn protection_grith_config_delete_is_denied() {
    let pid = 7011;
    let ev = event(
        pid,
        syscall_nr::UNLINK,
        SyscallKind::FileDelete {
            path: "/home/u/.config/grith/learned_rules.json".into(),
        },
    );
    assert_config_write_denied(&Harness::new().run(vec![ev]).await, pid);
}

#[tokio::test]
async fn protection_grith_config_rename_is_denied() {
    let pid = 7012;
    // Renaming a benign file ONTO a grith config path is a write to grith config.
    let ev = event(
        pid,
        syscall_nr::RENAME,
        SyscallKind::FileRename {
            old_path: "/tmp/evil.toml".into(),
            new_path: "/home/u/.config/grith/config.toml".into(),
        },
    );
    assert_config_write_denied(&Harness::new().run(vec![ev]).await, pid);
}

#[tokio::test]
async fn protection_grith_config_chmod_is_denied() {
    let pid = 7013;
    let ev = event(
        pid,
        syscall_nr::FCHMODAT,
        SyscallKind::FileChmod {
            path: "/home/u/.config/grith/credentials".into(),
            mode: 0o600,
        },
    );
    assert_config_write_denied(&Harness::new().run(vec![ev]).await, pid);
}

#[tokio::test]
async fn protection_grith_config_mkdir_is_denied() {
    let pid = 7014;
    let ev = event(
        pid,
        syscall_nr::MKDIR,
        SyscallKind::DirCreate {
            path: "/home/u/.config/grith/evil".into(),
            mode: 0o755,
        },
    );
    assert_config_write_denied(&Harness::new().run(vec![ev]).await, pid);
}

#[tokio::test]
async fn protection_grith_config_nondotfile_variant_is_denied() {
    let pid = 7015;
    // The branch also matches the non-dotfile `/config/grith/` form (e.g. a
    // system install at /usr/local/grith/config/grith/...).
    let ev = event(
        pid,
        syscall_nr::UNLINK,
        SyscallKind::FileDelete {
            path: "/usr/local/grith/config/grith/rules.toml".into(),
        },
    );
    assert_config_write_denied(&Harness::new().run(vec![ev]).await, pid);
}

// Benign counterpart (must-not-false-positive): a delete OUTSIDE grith's config
// dir is NOT tripped by the self-protection branch. `working_root` is set so the
// target is in-tree and the mass-destruction signal cannot count it either — the
// test asserts ONLY "self-protection did not fire" (allow, no queue/deny), not
// an incidental pass on the 25-distinct-target threshold.
#[tokio::test]
async fn protection_non_grith_config_delete_is_allowed() {
    let pid = 7016;
    let ev = event(
        pid,
        syscall_nr::UNLINK,
        SyscallKind::FileDelete {
            path: "/home/u/project/src/main.rs".into(),
        },
    );
    let r = Harness::new()
        .with_working_root("/home/u/project")
        .run(vec![ev])
        .await;
    assert!(
        r.allowed(pid),
        "in-tree project delete must be allowed: {r:?}"
    );
    assert!(
        !r.denied(pid),
        "in-tree project delete must not be denied: {r:?}"
    );
    assert_eq!(r.total_queued, 0, "must not queue: {r:?}");
    assert_eq!(r.total_denied, 0, "must not deny: {r:?}");
}

// ===========================================================================
// Step 3 — end-to-end supervisor coverage for two enforcement fixes that the
// proxy-level tests alone could not prove reach the supervised path past the
// noise / `ignore_read_only` fast-paths (review C1/C2/S1). A QUEUE decision is
// resolved by the harness's DenyReviewer → deny(tid), so a *blocked* op shows
// up in `deny_pids`.
// ===========================================================================

fn filters_proxy(filters: Vec<Box<dyn SecurityFilter>>) -> Arc<SecurityProxy> {
    let mut registry = FilterRegistry::new();
    for f in filters {
        registry.register(f);
    }
    Arc::new(SecurityProxy::new(
        registry,
        ScoringConfig::default(),
        MetaRuleEngine::new(vec![]),
    ))
}

#[tokio::test]
async fn protection_cross_process_environ_read_reaches_proxy_and_blocks() {
    // FileOpen(ReadOnly) of another process's environ must survive BOTH the
    // /proc noise fast-path AND ignore_read_only (default on), reach the proxy,
    // score 4.5 (cross-process-memory) → QUEUE → DenyReviewer → deny.
    //
    // Use this test process's OWN numeric pid: the path /proc/<N>/environ with
    // numeric N (not "self") is classified cross-process AND actually EXISTS +
    // is readable — so it isn't auto-allowed by the `!file_exists` clause of the
    // read-only short-circuit (a non-existent /proc/<pid> would ENOENT and is
    // correctly allowed; the danger is reading a REAL other process).
    let pid = 7100;
    let proxy = filters_proxy(vec![Box::new(SensitivePathHeuristicFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::OPENAT,
        SyscallKind::FileOpen {
            path: format!("/proc/{}/environ", std::process::id()),
            flags: OpenFlags::ReadOnly,
        },
    );
    let r = Harness::new().with_proxy(proxy).run(vec![ev]).await;
    assert!(
        r.deny_pids.contains(&pid) && !r.allow_pids.contains(&pid),
        "reading another process's environ must reach the proxy and be blocked, \
         not silently allowed by ignore_read_only: {r:?}"
    );
}

#[tokio::test]
async fn protection_own_environ_read_is_allowed_end_to_end() {
    // The caller's own /proc/self/environ is noise → silently allowed.
    let pid = 7101;
    let proxy = filters_proxy(vec![Box::new(SensitivePathHeuristicFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::OPENAT,
        SyscallKind::FileOpen {
            path: "/proc/self/environ".into(),
            flags: OpenFlags::ReadOnly,
        },
    );
    let r = Harness::new().with_proxy(proxy).run(vec![ev]).await;
    assert!(
        r.allow_pids.contains(&pid) && !r.deny_pids.contains(&pid),
        "own /proc/self/environ read must be allowed: {r:?}"
    );
}

#[tokio::test]
async fn protection_setuid_chmod_reaches_proxy_and_blocks() {
    let pid = 7102;
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::FCHMODAT,
        SyscallKind::FileChmod {
            path: "/home/u/project/tool".into(),
            mode: 0o4755,
        },
    );
    let r = Harness::new().with_proxy(proxy).run(vec![ev]).await;
    assert!(
        r.deny_pids.contains(&pid) && !r.allow_pids.contains(&pid),
        "a setuid chmod must reach the proxy (5.0 → QUEUE → review-deny): {r:?}"
    );
}

#[tokio::test]
async fn protection_plain_chmod_is_allowed_end_to_end() {
    let pid = 7103;
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::FCHMODAT,
        SyscallKind::FileChmod {
            path: "/home/u/project/run.sh".into(),
            mode: 0o755,
        },
    );
    let r = Harness::new().with_proxy(proxy).run(vec![ev]).await;
    assert!(
        r.allow_pids.contains(&pid) && !r.deny_pids.contains(&pid),
        "a plain chmod (baseline 1.0) must be allowed: {r:?}"
    );
}

// ===========================================================================
// Phase 3 — mass-destruction signal end-to-end (research doc §4.5, §5.2)
// A spree of distinct out-of-tree deletions escalates Allow→QUEUE (then the
// DenyReviewer denies). The same volume in-tree is normal refactoring.
// ===========================================================================

#[tokio::test]
async fn protection_out_of_tree_delete_spree_escalates() {
    let pid = 7200;
    let events: Vec<_> = (0..30)
        .map(|i| {
            event(
                pid,
                syscall_nr::UNLINK,
                SyscallKind::FileDelete {
                    path: format!("/home/u/Documents/keepsake-{i}.dat"),
                },
            )
        })
        .collect();
    let r = Harness::new().run(events).await;
    assert!(
        !r.deny_pids.is_empty(),
        "a 30-distinct out-of-tree delete spree must escalate to a block: {r:?}"
    );
}

#[tokio::test]
async fn protection_in_tree_bulk_delete_does_not_escalate() {
    let pid = 7201;
    let events: Vec<_> = (0..30)
        .map(|i| {
            event(
                pid,
                syscall_nr::UNLINK,
                SyscallKind::FileDelete {
                    path: format!("/home/u/project/build/obj-{i}.o"),
                },
            )
        })
        .collect();
    let r = Harness::new()
        .with_working_root("/home/u/project")
        .run(events)
        .await;
    assert!(
        r.deny_pids.is_empty(),
        "in-tree bulk delete (the agent's job) must not escalate: {r:?}"
    );
    assert_eq!(
        r.allow_pids.len(),
        30,
        "all 30 in-tree deletes must be allowed: {r:?}"
    );
}

// ===========================================================================
// Phase 3 — PR 6 coverage flag-state matrix + namespace carveout (§6.3, §4.4)
// The flag-OFF→allow cases are covered by the existing phase_f_* tests; these
// add the ON cases and the namespace_users carveout (both branches).
// CLONE_NEWUSER = 0x1000_0000.
// ===========================================================================

const CLONE_NEWUSER: u64 = 0x1000_0000;

#[tokio::test]
async fn protection_chown_with_category2_on_is_held() {
    let pid = 7300;
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::CHOWN,
        SyscallKind::OwnershipChange {
            op: OwnershipOp::Chown,
            path: "/etc/cron.d/payload".into(),
            new_uid: 0,
            new_gid: 0,
        },
    );
    let r = Harness::new()
        .with_coverage(CoverageConfig {
            category2_proxy: true,
            ..CoverageConfig::default()
        })
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    assert!(
        r.deny_pids.contains(&pid),
        "chown with category-2 ON must reach the proxy (+5.0 → QUEUE → deny): {r:?}"
    );
}

#[tokio::test]
async fn protection_unshare_with_category3_on_no_carveout_is_held() {
    let pid = 7301;
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::UNSHARE,
        SyscallKind::NamespaceOp {
            syscall: NamespaceSyscall::Unshare,
            flags: CLONE_NEWUSER,
        },
    );
    // No namespace_users declared → no carveout → routes to the proxy.
    let r = Harness::new()
        .with_coverage(CoverageConfig {
            category3_namespace: true,
            ..CoverageConfig::default()
        })
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    assert!(
        r.deny_pids.contains(&pid),
        "unshare with category-3 ON and no carveout must be held: {r:?}"
    );
}

// Carveout ALLOW: a declared namespace_user under a routine root unshares
// silently. We use THIS test binary as the namespace_user so /proc/<pid>/exe
// resolves to a real, known path, and an operation_risk proxy that WOULD hold
// it — so an "allow" outcome proves the carveout (not the proxy) decided.
#[tokio::test]
async fn protection_namespace_carveout_allows_declared_user_under_routine_root() {
    let pid = std::process::id();
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    let exe_str = exe.to_string_lossy().into_owned();
    let root = format!("{}/", exe.parent().unwrap().to_string_lossy());
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::UNSHARE,
        SyscallKind::NamespaceOp {
            syscall: NamespaceSyscall::Unshare,
            flags: CLONE_NEWUSER,
        },
    );
    let r = Harness::new()
        .with_coverage(CoverageConfig {
            category3_namespace: true,
            ..CoverageConfig::default()
        })
        .with_namespace_users(vec![exe_str])
        .with_routine_exec_roots(vec![root])
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    assert!(
        r.allow_pids.contains(&pid) && !r.deny_pids.contains(&pid),
        "a declared namespace_user under a routine root must be carved out (allowed): {r:?}"
    );
}

// Carveout FAIL-SAFE: the same binary declared as a namespace_user but NOT under
// any routine root (attacker dropped it elsewhere) must NOT be carved out.
#[tokio::test]
async fn protection_namespace_carveout_fails_safe_outside_routine_root() {
    let pid = std::process::id();
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    let exe_str = exe.to_string_lossy().into_owned();
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::UNSHARE,
        SyscallKind::NamespaceOp {
            syscall: NamespaceSyscall::Unshare,
            flags: CLONE_NEWUSER,
        },
    );
    let r = Harness::new()
        .with_coverage(CoverageConfig {
            category3_namespace: true,
            ..CoverageConfig::default()
        })
        .with_namespace_users(vec![exe_str])
        .with_routine_exec_roots(vec!["/nonexistent/routine/root/".into()])
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    assert!(
        r.deny_pids.contains(&pid),
        "a namespace_user outside every routine root must NOT be carved out (fail-safe): {r:?}"
    );
}
