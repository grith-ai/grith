// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! PR 1 integration tests: cross-session state isolation, containment
//! activation, and stale-state sweep behaviour exercised through the
//! `SecurityProxy` end-to-end (not just unit tests on individual filters).
//!
//! These tests intentionally use `SessionStateRegistry::fresh()` instances
//! rather than the process-wide `global()` so test cases cannot leak state
//! into each other when cargo runs them in parallel.

use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::taint::TaintFilter;
use grith_proxy::meta_rules::MetaRuleEngine;
use grith_proxy::scoring::ScoringConfig;
use grith_proxy::session_state::{ContainmentReason, SessionStateRegistry};
use grith_proxy::types::{SessionScopeKey, ToolCallContext, ToolCallType};
use grith_tests::TestFixtures;
use std::time::{Duration, Instant};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a proxy that includes the `TaintFilter` (Phase 3) on top of the
/// default fixtures. PR 1's session-scoping behaviour lives in that filter,
/// so it must be registered for these tests to exercise the right path.
fn proxy() -> SecurityProxy {
    let mut registry = TestFixtures::default_filter_registry();
    registry.register(Box::new(TaintFilter::with_defaults()));
    SecurityProxy::new(
        registry,
        ScoringConfig::default(),
        MetaRuleEngine::new(vec![]),
    )
}

fn ctx_in_session(call_type: ToolCallType, session: Uuid) -> ToolCallContext {
    ToolCallContext::new("test", call_type, session)
}

// ---------------------------------------------------------------------------
// H5: cross_session_isolation — back-to-back sessions don't share state
// ---------------------------------------------------------------------------

/// PR 1 H5: a fresh session must not inherit taint, rate-limit counters,
/// or behavioural baselines from a previous session. This is the
/// regression guard for the supervisor-side root cause of the codex
/// prompt-flood bug.
#[tokio::test]
async fn cross_session_isolation_back_to_back() {
    let proxy = proxy();

    // ----- Session A: read a sensitive file, build some rate-limit history -----
    let session_a = Uuid::new_v4();
    let scope_a = SessionScopeKey::from_session_id(session_a);

    // Sensitive read in A → registers taint AND (PR 1 Phase C) activates
    // session-lifetime containment on the global registry.
    let _ = proxy
        .evaluate(&ctx_in_session(
            ToolCallType::FileRead {
                path: "/home/u/.ssh/id_rsa".into(),
            },
            session_a,
        ))
        .await;

    // Generate some rate-limit / behavioural traffic in A.
    for _ in 0..3 {
        let _ = proxy
            .evaluate(&ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/a-data.txt".into(),
                },
                session_a,
            ))
            .await;
    }

    assert!(
        SessionStateRegistry::global().is_containment_active(scope_a),
        "session A should have containment active after high-taint read"
    );

    // ----- End session A: simulate the supervisor's session-end eviction -----
    let removed_a = proxy.evict_session_state(scope_a);
    assert!(
        removed_a > 0,
        "session A should have evicted at least one filter state entry"
    );
    assert!(
        !SessionStateRegistry::global().is_containment_active(scope_a),
        "post-evict, session A's containment must be cleared"
    );

    // ----- Session B: cold-start, must not see A's state -----
    let session_b = Uuid::new_v4();
    let scope_b = SessionScopeKey::from_session_id(session_b);

    assert!(
        !SessionStateRegistry::global().is_containment_active(scope_b),
        "session B (fresh) must not start in a contained state"
    );

    // Evaluate a benign call in B. Without session scoping (the pre-PR-1
    // bug) this would have inherited A's taint and tripped phase-3 filters.
    let decision = proxy
        .evaluate(&ctx_in_session(
            ToolCallType::FileRead {
                path: "/tmp/b-data.txt".into(),
            },
            session_b,
        ))
        .await;
    assert!(
        decision.is_allowed(),
        "session B's benign read must be allowed (got {:?})",
        decision.action
    );

    // Cleanup so we don't pollute the global registry for other tests.
    proxy.evict_session_state(scope_b);
}

// ---------------------------------------------------------------------------
// H6: containment_blocks_routine_egress — sticky containment persists
// ---------------------------------------------------------------------------

/// PR 1 H6: once a sensitive read activates containment, the flag stays
/// active for the rest of the session — it's session-lifetime-sticky,
/// not TTL-bounded.
///
/// The actual "block routine egress" gating lives in the supervisor's
/// `event_handler.rs` (Phase D), where the `session_allowed` short-
/// circuit is gated on `is_containment_active(scope)`. This test asserts
/// the property the gate relies on: the flag persists across many
/// subsequent evaluations in the same session.
#[tokio::test]
async fn containment_stays_sticky_across_subsequent_calls() {
    let proxy = proxy();
    let session = Uuid::new_v4();
    let scope = SessionScopeKey::from_session_id(session);

    // Sensitive read activates containment.
    let _ = proxy
        .evaluate(&ctx_in_session(
            ToolCallType::FileRead {
                path: "/home/u/.ssh/id_rsa".into(),
            },
            session,
        ))
        .await;
    assert!(SessionStateRegistry::global().is_containment_active(scope));

    // Many subsequent benign calls — containment must remain active.
    for i in 0..20 {
        let _ = proxy
            .evaluate(&ctx_in_session(
                ToolCallType::FileRead {
                    path: format!("/tmp/benign-{i}.txt"),
                },
                session,
            ))
            .await;
        assert!(
            SessionStateRegistry::global().is_containment_active(scope),
            "containment must stay active across {} subsequent calls",
            i + 1
        );
    }

    proxy.evict_session_state(scope);
}

/// PR 1 H6 negative case: containment on one session must NOT affect
/// another session in the same process.
#[tokio::test]
async fn containment_does_not_bleed_across_sessions() {
    let proxy = proxy();
    let session_a = Uuid::new_v4();
    let session_b = Uuid::new_v4();
    let scope_a = SessionScopeKey::from_session_id(session_a);
    let scope_b = SessionScopeKey::from_session_id(session_b);

    let _ = proxy
        .evaluate(&ctx_in_session(
            ToolCallType::FileRead {
                path: "/home/u/.ssh/id_rsa".into(),
            },
            session_a,
        ))
        .await;

    assert!(SessionStateRegistry::global().is_containment_active(scope_a));
    assert!(
        !SessionStateRegistry::global().is_containment_active(scope_b),
        "containment on session A must not appear on session B"
    );

    proxy.evict_session_state(scope_a);
    proxy.evict_session_state(scope_b);
}

// ---------------------------------------------------------------------------
// H7: crashed_session_sweep — stale state cleaned up at session start
// ---------------------------------------------------------------------------

/// PR 1 H7: a crashed previous session leaves entries in
/// `SessionStateRegistry`. The session-start sweep (using
/// `snapshot_stale` + `evict_session_state`) clears them. Verified
/// against a *fresh* registry so this test does not depend on the
/// process-global state's prior contents.
#[test]
fn crashed_session_sweep_clears_stale_entries() {
    let reg = SessionStateRegistry::fresh();

    // Simulate three crashed sessions and one live one. We activate
    // containment on each so the entries exist.
    let crashed: Vec<SessionScopeKey> = (0..3).map(|_| SessionScopeKey::fresh()).collect();
    let live = SessionScopeKey::fresh();

    for s in &crashed {
        reg.activate_containment(
            *s,
            ContainmentReason::SensitiveAccessOutsideScope {
                path: "/test".into(),
                taint_level: "high".into(),
            },
        );
    }
    reg.activate_containment(
        live,
        ContainmentReason::SensitiveAccessOutsideScope {
            path: "/live".into(),
            taint_level: "high".into(),
        },
    );
    assert_eq!(reg.len(), 4);

    // Sweep using a cutoff *just after* the last_seen of all entries —
    // every entry is "stale" by this cutoff. snapshot_stale returns the
    // list without mutating; the caller drives eviction.
    std::thread::sleep(Duration::from_millis(20));
    let cutoff = Instant::now();
    let stale = reg.snapshot_stale(cutoff);
    assert_eq!(stale.len(), 4, "all four sessions should be stale by now");
    for (scope, _) in &stale {
        assert!(reg.evict(*scope));
    }
    assert!(reg.is_empty(), "registry must be empty after sweep");

    // Activate one more — confirm the sweep didn't accidentally leave
    // sticky state somewhere.
    let post_sweep = SessionScopeKey::fresh();
    assert!(!reg.is_containment_active(post_sweep));
}

/// PR 1 H7 negative case: snapshot_stale only returns entries OLDER than
/// the cutoff. A fresh entry must not appear in the snapshot.
#[test]
fn snapshot_stale_does_not_return_fresh_entries() {
    let reg = SessionStateRegistry::fresh();
    let scope = SessionScopeKey::fresh();
    reg.activate_containment(
        scope,
        ContainmentReason::Manual {
            actor: "test".into(),
        },
    );

    // Cutoff in the past — nothing is "stale" relative to it.
    let cutoff = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now);
    let stale = reg.snapshot_stale(cutoff);
    assert!(
        stale.is_empty(),
        "fresh entry must not appear in past-cutoff snapshot, got {} entries",
        stale.len()
    );
}

// ---------------------------------------------------------------------------
// Exec exit-code propagation regression guard (E2 deferred)
// ---------------------------------------------------------------------------
//
// A true exec-exit-code integration test would spawn `grith exec` end-to-
// end via std::process::Command and inspect the exit status — feasible but
// out of scope for PR 1 because it requires building the binary in test
// setup. The supervisor invariant the PR cares about — that there is no
// auto-retry path that would silently reset the SessionScopeKey — is
// audited in Phase E and documented in
// `docs/SUPERVISOR-ONLY-SECURITY-ASSESSMENT.md`. A follow-up PR can add
// the binary-level test alongside other CLI behavioural assertions.
