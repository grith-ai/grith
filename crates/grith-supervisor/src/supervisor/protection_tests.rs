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
use grith_proxy::session_state::{ContainmentReason, SessionStateRegistry};
use grith_proxy::types::SessionScopeKey;

use super::event_handler::{handle_syscall_event, ReadBatchTracker, SupervisorLoopContext};
use super::SupervisorSession;
use crate::config::{CoverageConfig, SupervisorConfig};
use crate::dns_cache::DnsCache;
use crate::freezer::Freezer;
use crate::interceptor::{
    CrossProcessOp, NamespaceSyscall, OpenFlags, OwnershipOp, SyscallEvent, SyscallInterceptor,
    SyscallKind,
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
    /// Pids/tids the supervisor considers in-tree — seeded by the Harness so
    /// cross-process descendant-vs-non-descendant carveouts can be exercised.
    supervised: Vec<u32>,
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
        self.supervised.clone()
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

/// A reviewer that approves everything it is asked to review — used by the
/// approve-replay tests to simulate the operator pressing approve.
struct ApproveReviewer;

#[async_trait]
impl QueueReviewer for ApproveReviewer {
    async fn review(&self, _item: &DigestItem, _timeout: Duration) -> ReviewOutcome {
        ReviewOutcome::Approved
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
    supervised_pids: Vec<u32>,
    yama_ptrace_scope: Option<u8>,
    reviewer: Arc<dyn QueueReviewer>,
    containment: bool,
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
            supervised_pids: Vec::new(),
            yama_ptrace_scope: None,
            reviewer: Arc::new(DenyReviewer),
            containment: false,
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

    /// Seed the supervisor's in-tree pid/tid set (what `supervised_pids()`
    /// reports) so cross-process descendant-vs-non-descendant carveouts are
    /// exercisable.
    #[allow(dead_code)]
    fn with_supervised_pids(mut self, pids: Vec<u32>) -> Self {
        self.supervised_pids = pids;
        self
    }

    /// Simulate a session-start YAMA `ptrace_scope` probe result so the
    /// kernel-blocked cross-process suppression is exercisable.
    #[allow(dead_code)]
    fn with_deny_replay_seconds(mut self, seconds: u64) -> Self {
        self.config.deny_replay_seconds = seconds;
        self
    }

    #[allow(dead_code)]
    fn with_approve_replay_seconds(mut self, seconds: u64) -> Self {
        self.config.approve_replay_seconds = seconds;
        self
    }

    /// Replace the queue reviewer (default: `DenyReviewer`).
    #[allow(dead_code)]
    fn with_reviewer(mut self, reviewer: Arc<dyn QueueReviewer>) -> Self {
        self.reviewer = reviewer;
        self
    }

    /// Activate session containment for the run's scope before any event is
    /// processed (the global registry entry is evicted after the run).
    #[allow(dead_code)]
    fn with_containment_active(mut self) -> Self {
        self.containment = true;
        self
    }

    fn with_yama_ptrace_scope(mut self, scope: Option<u8>) -> Self {
        self.yama_ptrace_scope = scope;
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
            supervised: self.supervised_pids.clone(),
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
            reviewer: self.reviewer.clone(),
            session_sync: None,
            session_allowed: Arc::new(Mutex::new(self.session_allowed.clone())),
            dns_cache: Arc::new(Mutex::new(DnsCache::new())),
            dns_inspection_enabled: false,
            dns_decision_service: None,
            dns_forward_confirm: None,
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
            yama_ptrace_scope: self.yama_ptrace_scope,
        };

        let scope = SessionScopeKey::from_session_id(session.id);
        if self.containment {
            SessionStateRegistry::global().activate_containment(
                scope,
                ContainmentReason::SensitiveAccessOutsideScope {
                    path: "/protection-test/trigger".into(),
                    taint_level: "critical".into(),
                },
            );
        }

        for event in events {
            handle_syscall_event(&mut interceptor, &mut session, &loop_ctx, event)
                .await
                .expect("handle_syscall_event should not error in protection tests");
        }

        if self.containment {
            SessionStateRegistry::global().evict(scope);
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
    }
}

/// Event whose thread id differs from the thread-group leader — used to
/// prove the cross-process caps check keys on the syscall-issuing thread
/// (`tid`), not the leader (`pid`).
#[allow(dead_code)]
fn event_with_tid(pid: u32, tid: u32, raw_syscall_nr: i64, kind: SyscallKind) -> SyscallEvent {
    SyscallEvent {
        pid,
        tid,
        timestamp: Utc::now(),
        kind,
        raw_syscall_nr,
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
async fn protection_raw_socket_af_netlink_nonroute_is_denied() {
    // NETLINK_ROUTE (protocol 0) is allowed upstream in classify (routine
    // getaddrinfo/getifaddrs); the less-common families still classify as
    // RawSocketCreate and must be hard-denied at the enforcement layer.
    let pid = 7002;
    let ev = event(
        pid,
        syscall_nr::SOCKET,
        SyscallKind::RawSocketCreate {
            domain: 16, // AF_NETLINK
            socket_type: 3,
            protocol: 12, // NETLINK_NETFILTER (not NETLINK_ROUTE)
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

// The cross-process subset of category 2 (ptrace / process_vm) is enforced by
// DEFAULT — coding tools never debug or read another process's memory, so it
// is ~0 false positives and closes the scope-0 secret-theft path. These two
// tests pin that default-on behaviour; the flag-off escape hatch is pinned by
// `protection_crossprocess_off_by_default_flag_allows_ptrace` below.
#[tokio::test]
async fn protection_ptrace_nonself_enforced_by_default() {
    // Live caller (this process) and a live out-of-tree target: the
    // dead-target refinement must not apply, so the op reaches the proxy.
    // Fake pids would make this host-dependent (a nonexistent target is now
    // deliberately suppressed).
    let pid = std::process::id();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let target = child.id();
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::PTRACE,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::Ptrace,
            // A different pid — reading/attaching to a live non-descendant.
            target_pid: target,
        },
    );
    // Plain default coverage: category2_proxy = false (chown/mount off), but
    // category2_crossprocess = true.
    let r = Harness::new()
        .with_coverage(CoverageConfig::default())
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        r.deny_pids.contains(&pid),
        "ptrace of a live non-self target must reach the proxy by default (+5.0 → QUEUE → deny): {r:?}"
    );
}

#[tokio::test]
async fn protection_process_vm_readv_nonself_enforced_by_default() {
    let pid = std::process::id();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let target = child.id();
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::PROCESS_VM_READV,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::ProcessVmReadv,
            target_pid: target,
        },
    );
    let r = Harness::new()
        .with_coverage(CoverageConfig::default())
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        r.deny_pids.contains(&pid),
        "process_vm_readv of a live non-self target must reach the proxy by default (+5.0 → QUEUE → deny): {r:?}"
    );
}

// Dead-target refinement: a cross-process op aimed at a PID that does not
// exist can only get ESRCH — it is allowed-and-recorded instead of prompting.
// This is the exact shape of the 2026-08-13 prompt flood: the supervisor's
// own test suite probing ptrace against unallocatable PIDs, one prompt per
// probe. Caller must be live and in our PID namespace (this process); the
// target provably absent.
#[tokio::test]
async fn protection_cross_process_dead_target_allowed() {
    let pid = std::process::id();
    // Well above /proc/sys/kernel/pid_max — never allocatable.
    let dead_target = 0x3fff_fff0;
    // A proxy that WOULD hold it if reached — "allow" proves the dead-target
    // refinement short-circuited before proxy evaluation.
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::PTRACE,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::Ptrace,
            target_pid: dead_target,
        },
    );
    let r = Harness::new()
        .with_coverage(CoverageConfig::default())
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    assert!(
        r.allow_pids.contains(&pid) && !r.deny_pids.contains(&pid),
        "cross-process access to a nonexistent target is kernel-doomed (ESRCH) and must not prompt: {r:?}"
    );
}

// Deny-replay: an identical request denied moments ago is denied again
// WITHOUT a fresh review — the reviewer/prompt is consulted once, not once
// per retry. `total_queued` counts reviews reaching the queue, so two
// identical denied events must leave it at 1 while both syscalls are denied.
#[tokio::test]
async fn protection_denied_request_replays_without_second_review() {
    let pid = std::process::id();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let target = child.id();
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let make = || {
        event(
            pid,
            syscall_nr::PTRACE,
            SyscallKind::CrossProcessAccess {
                op: CrossProcessOp::Ptrace,
                target_pid: target,
            },
        )
    };
    let r = Harness::new()
        .with_proxy(proxy)
        .run(vec![make(), make()])
        .await;
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(
        r.deny_pids.iter().filter(|p| **p == pid).count(),
        2,
        "both identical requests must be denied: {r:?}"
    );
    assert_eq!(
        r.total_queued, 1,
        "the second identical request must replay the denial, not re-review: {r:?}"
    );
    assert_eq!(r.total_denied, 2, "{r:?}");
}

// The replay knob at 0 disables replay entirely: every identical retry is
// re-reviewed.
#[tokio::test]
async fn protection_deny_replay_disabled_reviews_every_retry() {
    let pid = std::process::id();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let target = child.id();
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let make = || {
        event(
            pid,
            syscall_nr::PTRACE,
            SyscallKind::CrossProcessAccess {
                op: CrossProcessOp::Ptrace,
                target_pid: target,
            },
        )
    };
    let r = Harness::new()
        .with_proxy(proxy)
        .with_deny_replay_seconds(0)
        .run(vec![make(), make()])
        .await;
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(
        r.total_queued, 2,
        "with replay disabled every identical retry must be re-reviewed: {r:?}"
    );
}

// A replayed denial must be scoped to the exact call identity: a different
// target re-prompts even while the first denial's window is open.
#[tokio::test]
async fn protection_deny_replay_keyed_on_exact_identity() {
    let pid = std::process::id();
    let mut child_a = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let mut child_b = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev_a = event(
        pid,
        syscall_nr::PTRACE,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::Ptrace,
            target_pid: child_a.id(),
        },
    );
    let ev_b = event(
        pid,
        syscall_nr::PTRACE,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::Ptrace,
            target_pid: child_b.id(),
        },
    );
    let r = Harness::new().with_proxy(proxy).run(vec![ev_a, ev_b]).await;
    let _ = child_a.kill();
    let _ = child_a.wait();
    let _ = child_b.kill();
    let _ = child_b.wait();
    assert_eq!(
        r.total_queued, 2,
        "a different target is a different decision and must be re-reviewed: {r:?}"
    );
}

// ===========================================================================
// Approve-replay: an identical request approved moments ago is allowed again
// WITHOUT a fresh review — the mirror of deny-replay for the retry-after-
// approval prompt flood. The spawn target lives under /tmp (world-writable
// ancestor), so the `exec:` session grant the approval also inserts is
// provenance-rejected and cannot mask the replay mechanism under test.
// ===========================================================================

/// A proxy whose queue threshold sits below the +1.0 ProcessSpawn baseline,
/// so a bare spawn queues for review.
fn spawn_queues_proxy() -> Arc<SecurityProxy> {
    let mut registry = FilterRegistry::new();
    registry.register(Box::new(OperationRiskFilter::new()));
    Arc::new(SecurityProxy::new(
        registry,
        ScoringConfig {
            auto_allow_threshold: 0.5,
            auto_deny_threshold: 8.0,
        },
        MetaRuleEngine::new(vec![]),
    ))
}

/// Create an executable file under /tmp (world-writable root → any `exec:`
/// grant is provenance-untrusted) and return its path. The file must exist,
/// or the failed-exec suppression would allow the spawn without a prompt.
fn tmp_executable(tag: &str) -> String {
    let path = format!("/tmp/grith-approve-replay-{tag}-{}", std::process::id());
    std::fs::write(&path, "#!/bin/sh\n").expect("write tmp executable");
    let mut perms = std::fs::metadata(&path)
        .expect("stat tmp executable")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&path, perms).expect("chmod tmp executable");
    path
}

fn spawn_event(pid: u32, target: &str) -> SyscallEvent {
    event(
        pid,
        syscall_nr::EXECVE,
        SyscallKind::ProcessExec {
            path: target.to_string(),
            args: vec![target.to_string()],
        },
    )
}

#[tokio::test]
async fn protection_approved_request_replays_without_second_review() {
    let pid = std::process::id();
    let target = tmp_executable("replays");
    let r = Harness::new()
        .with_proxy(spawn_queues_proxy())
        .with_reviewer(Arc::new(ApproveReviewer))
        .run(vec![spawn_event(pid, &target), spawn_event(pid, &target)])
        .await;
    std::fs::remove_file(&target).ok();
    assert_eq!(
        r.allow_pids.iter().filter(|p| **p == pid).count(),
        2,
        "both identical requests must be allowed: {r:?}"
    );
    assert_eq!(
        r.total_queued, 1,
        "the second identical request must replay the approval, not re-review: {r:?}"
    );
}

// The replay knob at 0 disables replay entirely: every identical retry is
// re-reviewed.
#[tokio::test]
async fn protection_approve_replay_disabled_reviews_every_retry() {
    let pid = std::process::id();
    let target = tmp_executable("disabled");
    let r = Harness::new()
        .with_proxy(spawn_queues_proxy())
        .with_reviewer(Arc::new(ApproveReviewer))
        .with_approve_replay_seconds(0)
        .run(vec![spawn_event(pid, &target), spawn_event(pid, &target)])
        .await;
    std::fs::remove_file(&target).ok();
    assert_eq!(
        r.total_queued, 2,
        "with replay disabled every identical retry must be re-reviewed: {r:?}"
    );
}

// A replayed approval must be scoped to the exact call identity: a different
// target re-prompts even while the first approval's window is open.
#[tokio::test]
async fn protection_approve_replay_keyed_on_exact_identity() {
    let pid = std::process::id();
    let target_a = tmp_executable("ident-a");
    let target_b = tmp_executable("ident-b");
    let r = Harness::new()
        .with_proxy(spawn_queues_proxy())
        .with_reviewer(Arc::new(ApproveReviewer))
        .run(vec![
            spawn_event(pid, &target_a),
            spawn_event(pid, &target_b),
        ])
        .await;
    std::fs::remove_file(&target_a).ok();
    std::fs::remove_file(&target_b).ok();
    assert_eq!(
        r.total_queued, 2,
        "a different target is a different decision and must be re-reviewed: {r:?}"
    );
}

// Containment disables approve-replay: post-contamination, session taint can
// change between retries, so every identical retry must re-score through the
// full pipeline and re-queue for review (mirroring the session-allowlist
// bypass under containment). Deny-replay is unaffected — replaying a deny is
// fail-safe.
#[tokio::test]
async fn protection_approve_replay_disabled_under_containment() {
    let pid = std::process::id();
    let target = tmp_executable("containment");
    let r = Harness::new()
        .with_proxy(spawn_queues_proxy())
        .with_reviewer(Arc::new(ApproveReviewer))
        .with_containment_active()
        .run(vec![spawn_event(pid, &target), spawn_event(pid, &target)])
        .await;
    std::fs::remove_file(&target).ok();
    assert_eq!(
        r.total_queued, 2,
        "under containment every identical retry must be re-reviewed: {r:?}"
    );
}

// Fail-safe for the dead-target refinement: an unverifiable CALLER (no
// /proc entry → PID namespace unknown) must not be suppressed even when the
// target is absent — our /proc view proves nothing about the caller's pidns.
#[tokio::test]
async fn protection_cross_process_dead_target_unverifiable_caller_still_held() {
    let pid = u32::MAX - 11;
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::PTRACE,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::Ptrace,
            target_pid: u32::MAX - 12,
        },
    );
    let r = Harness::new()
        .with_coverage(CoverageConfig::default())
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    assert!(
        r.deny_pids.contains(&pid),
        "a caller whose PID namespace cannot be verified must fail toward enforcement: {r:?}"
    );
}

// The escape hatch: an operator who must run a debugger-like tool under
// supervision can turn the cross-process subset off. When
// category2_crossprocess = false, ptrace falls through as not-security-relevant
// (matching pre-PR-6 behaviour) — allowed, not queued. This also proves the
// split is independent of category2_proxy (fs subset), which stays off.
#[tokio::test]
async fn protection_crossprocess_off_by_default_flag_allows_ptrace() {
    let pid = 7312;
    // A proxy that WOULD hold it if reached — so an "allow" proves the
    // coverage gate short-circuited before proxy evaluation.
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::PTRACE,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::Ptrace,
            target_pid: pid + 1,
        },
    );
    let r = Harness::new()
        .with_coverage(CoverageConfig {
            category2_crossprocess: false,
            ..CoverageConfig::default()
        })
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    assert!(
        r.allow_pids.contains(&pid) && !r.deny_pids.contains(&pid),
        "ptrace with the cross-process subset disabled must allow (pre-PR-6 pass-through): {r:?}"
    );
}

// The in-tree carveout: with the cross-process subset ON (default), access to
// a target INSIDE the supervised tree (a descendant/sibling — LeakSanitizer at
// exit, crash handlers, fork/trace harnesses) is allowed-and-recorded, NOT
// queued. Only out-of-tree targets reach the proxy. Proves the refinement that
// keeps blanket default-ON from prompt-storming sanitizer/debug flows.
#[tokio::test]
async fn protection_process_vm_readv_intree_target_allowed() {
    let pid = 7313;
    let target = pid + 1;
    // A proxy that WOULD hold it if reached — so "allow" proves the in-tree
    // carveout short-circuited before proxy evaluation.
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::PROCESS_VM_READV,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::ProcessVmReadv,
            target_pid: target,
        },
    );
    let r = Harness::new()
        // Default coverage → category2_crossprocess ON; both pids are in-tree.
        .with_supervised_pids(vec![pid, target])
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    assert!(
        r.allow_pids.contains(&pid) && !r.deny_pids.contains(&pid),
        "process_vm_readv of an in-tree descendant must be allowed (carveout), not queued: {r:?}"
    );
}

// Scope-probe suppression: at YAMA scope >= 2 the kernel refuses cross-process
// access for a caller without CAP_SYS_PTRACE, so an out-of-tree target draws
// no prompt — the syscall is allowed through to its guaranteed EPERM, and
// audit-recorded. Uses THIS test process as the caller (real /proc entry,
// normally capless) and a spawned `sleep` child as a real same-uid,
// same-user-namespace, out-of-tree target.
#[tokio::test]
async fn protection_cross_process_kernel_blocked_at_scope2_is_allowed() {
    let caller = std::process::id();
    // Non-vacuous in both environments: an uncapped caller (the common local
    // case) proves suppression; a capped caller (root Docker CI) proves the
    // opposite — a caller that CAN ptrace at scope 2 must still be enforced.
    let capless = super::event_handler::pid_has_cap_sys_ptrace(caller) == Some(false);
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let target = child.id();
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        caller,
        syscall_nr::PROCESS_VM_READV,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::ProcessVmReadv,
            target_pid: target,
        },
    );
    let r = Harness::new()
        .with_yama_ptrace_scope(Some(2))
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    let _ = child.kill();
    let _ = child.wait();
    if capless {
        assert!(
            r.allow_pids.contains(&caller) && !r.deny_pids.contains(&caller),
            "at scope 2 an uncapped caller's cross-process op is kernel-doomed and must not prompt: {r:?}"
        );
    } else {
        assert!(
            r.deny_pids.contains(&caller),
            "at scope 2 a CAP_SYS_PTRACE-holding caller can still ptrace, so it must NOT be suppressed: {r:?}"
        );
    }
}

// Scope 1 (the common distro default) must NOT suppress: a same-uid target
// that declared PR_SET_PTRACER is kernel-legal to read there, so the proxy
// has to evaluate it. Identical shape to the scope-2 test, differing only in
// the probed scope.
#[tokio::test]
async fn protection_cross_process_scope1_still_held() {
    let caller = std::process::id();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let target = child.id();
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        caller,
        syscall_nr::PROCESS_VM_READV,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::ProcessVmReadv,
            target_pid: target,
        },
    );
    let r = Harness::new()
        .with_yama_ptrace_scope(Some(1))
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        r.deny_pids.contains(&caller),
        "scope 1 must not suppress cross-process enforcement: {r:?}"
    );
}

// Fail-safe: when the caller's capability cannot be verified, scope 2 does
// NOT suppress — the op still routes to the proxy and is held. Uses an
// unallocatable high pid so /proc/<pid> reliably does not exist (a low pid
// like 7314 can be a live process on a busy host, flaking the assertion).
#[tokio::test]
async fn protection_cross_process_scope2_unverifiable_caller_still_held() {
    let pid = u32::MAX - 5;
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event(
        pid,
        syscall_nr::PROCESS_VM_READV,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::ProcessVmReadv,
            target_pid: pid - 1,
        },
    );
    let r = Harness::new()
        .with_yama_ptrace_scope(Some(2))
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    assert!(
        r.deny_pids.contains(&pid),
        "an unverifiable caller must fail toward enforcement even at scope 2: {r:?}"
    );
}

// Regression guard for finding #1 (capability probe must read the
// syscall-issuing thread, not the thread-group leader). The event's `tid` is
// an unallocatable id while `pid` is this live (normally capless) process.
// A correct gate reads the TID's caps -> unverifiable -> enforce (deny) on
// EVERY host, so this assertion always holds for correct code. A gate that
// (incorrectly) consulted `event.pid` would read this process's real,
// same-user-namespace caps and — on a capless host with the real `sleep`
// target below — suppress instead, flipping deny -> allow and failing here.
#[tokio::test]
async fn protection_cross_process_caps_keyed_on_calling_thread_not_leader() {
    let leader = std::process::id();
    let bogus_tid = u32::MAX - 7;
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let target = child.id();
    let proxy = filters_proxy(vec![Box::new(OperationRiskFilter::new())]);
    let ev = event_with_tid(
        leader,
        bogus_tid,
        syscall_nr::PROCESS_VM_READV,
        SyscallKind::CrossProcessAccess {
            op: CrossProcessOp::ProcessVmReadv,
            target_pid: target,
        },
    );
    let r = Harness::new()
        .with_yama_ptrace_scope(Some(2))
        .with_proxy(proxy)
        .run(vec![ev])
        .await;
    let _ = child.kill();
    let _ = child.wait();
    // Enforcement actions key on the tid; the bogus tid must be denied.
    assert!(
        r.deny_pids.contains(&bogus_tid) && !r.allow_pids.contains(&bogus_tid),
        "caps must be read from the calling thread (tid); a bogus tid must enforce: {r:?}"
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
// resolves to a real, known path, and an operation-risk proxy that WOULD hold
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
