// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! PR 4 Phase I — integration tests for the provenance-backed
//! routine-spawn signal.
//!
//! These tests build a real `SecurityProxy` with
//! `OperationRiskFilter::with_routine_signal(true)`, install a
//! `SessionPinnedInventory` on the global `SessionStateRegistry`, and
//! evaluate a `ProcessSpawn` context end-to-end. The goal is to catch
//! regressions where a Phase D unit test would still pass but the
//! filter pipeline as a whole would mis-score.
//!
//! Task coverage:
//! - I4: vendor binary scores 0.5; tamper component perms → 1.0.
//! - I5: critical guardrail (lives in `routine_phase3_still_queues.rs`).
//! - I6: mid-session new binary not pinned → no signal.
//! - I7: file write inside routine root still flows through filters.
//! - I8: curl-style outbound-capable binary excluded.
//! - I9: minor-version-bump simulation (different canonical path but
//!   inventory built fresh at session start covers it via glob).

use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::operation_risk::{
    OperationRiskFilter, NON_ROUTINE_SPAWN_SCORE, ROUTINE_SPAWN_SCORE,
};
use grith_proxy::filters::FilterRegistry;
use grith_proxy::meta_rules::MetaRuleEngine;
use grith_proxy::scoring::ScoringConfig;
use grith_proxy::session_state::{SessionPinnedInventory, SessionStateRegistry};
use grith_proxy::types::{
    ComponentWritability, SessionScopeKey, SpawnProvenance, ToolCallContext, ToolCallType,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn safe_component(path: &str) -> ComponentWritability {
    ComponentWritability {
        path: path.into(),
        owner_uid: 0,
        other_writable: false,
        group_writable_non_root: false,
        world_writable: false,
    }
}

/// Build a `SpawnProvenance` for a vendor-style binary under a routine
/// root (e.g. `~/.local/share/codex/bin/codex`). All component
/// writability flags are safe and `is_outbound_capable` is `false` by
/// default — fields-of-interest can be mutated by individual tests.
fn vendor_provenance() -> SpawnProvenance {
    SpawnProvenance {
        canonical_path: "/home/u/.local/share/codex/bin/codex".into(),
        sha256: "11".repeat(32),
        owner_uid: 1000,
        owner_gid: 1000,
        mode: 0o755,
        component_writability: vec![
            safe_component("/"),
            safe_component("/home"),
            safe_component("/home/u"),
            safe_component("/home/u/.local"),
            safe_component("/home/u/.local/share"),
            safe_component("/home/u/.local/share/codex"),
            safe_component("/home/u/.local/share/codex/bin"),
        ],
        matched_routine_root: Some("/home/u/.local/share/codex/".into()),
        is_outbound_capable: false,
    }
}

/// Spin up a fresh `SecurityProxy` with the operation-risk filter
/// constructed with `routine_signal_enabled = true`. Other phase-3
/// filters are intentionally absent — these tests verify the routine
/// signal in isolation; phase-3 additivity is covered separately by
/// `routine_phase3_still_queues.rs`.
fn proxy_with_signal_on() -> SecurityProxy {
    let mut registry = FilterRegistry::new();
    registry.register(Box::new(OperationRiskFilter::with_routine_signal(true)));
    SecurityProxy::new(
        registry,
        ScoringConfig::default(),
        MetaRuleEngine::new(vec![]),
    )
}

/// Same shape as `proxy_with_signal_on` but with the flag off — used
/// to confirm the default-off behaviour.
fn proxy_with_signal_off() -> SecurityProxy {
    let mut registry = FilterRegistry::new();
    registry.register(Box::new(OperationRiskFilter::new()));
    SecurityProxy::new(
        registry,
        ScoringConfig::default(),
        MetaRuleEngine::new(vec![]),
    )
}

/// Install a single-entry inventory for the given scope.
fn install_inventory(scope: SessionScopeKey, canonical: &str, sha256_hex: &str) {
    let state = SessionStateRegistry::global().get_or_create(scope);
    let inv =
        SessionPinnedInventory::from_entries([(canonical.to_string(), sha256_hex.to_string())]);
    state.set_pinned_inventory(inv);
}

/// Build a `ToolCallContext` for a `ProcessSpawn` carrying the given
/// provenance, with a fresh session scope so tests don't leak state
/// into each other via the global registry.
fn spawn_ctx(prov: SpawnProvenance) -> ToolCallContext {
    let session_id = Uuid::new_v4();
    let mut ctx = ToolCallContext::new(
        "test:integration",
        ToolCallType::ProcessSpawn {
            command: prov.canonical_path.clone(),
            args: Vec::new(),
        },
        session_id,
    );
    ctx.session_scope = Some(SessionScopeKey::from_session_id(session_id));
    ctx.spawn_provenance = Some(prov);
    ctx
}

fn approx_eq(a: f64, b: f64) -> bool {
    (a - b).abs() < f64::EPSILON
}

// ---------------------------------------------------------------------------
// I4 — vendor binary scores 0.5; tamper component perms → 1.0
// ---------------------------------------------------------------------------

#[tokio::test]
async fn i4_vendor_routine_binary_scores_zero_point_five() {
    let proxy = proxy_with_signal_on();
    let prov = vendor_provenance();
    let ctx = spawn_ctx(prov.clone());
    install_inventory(
        ctx.session_scope.unwrap(),
        &prov.canonical_path,
        &prov.sha256,
    );

    let decision = proxy.evaluate(&ctx).await;
    assert!(
        approx_eq(decision.composite_score, ROUTINE_SPAWN_SCORE),
        "expected {ROUTINE_SPAWN_SCORE}, got {}",
        decision.composite_score
    );
}

#[tokio::test]
async fn i4_world_writable_ancestor_demotes_to_baseline() {
    let proxy = proxy_with_signal_on();
    let mut prov = vendor_provenance();
    // Tamper: pretend /home/u/.local was chmod'd 0o777.
    prov.component_writability.push(ComponentWritability {
        path: "/home/u/.local".into(),
        owner_uid: 1000,
        other_writable: true,
        group_writable_non_root: false,
        world_writable: true,
    });
    let ctx = spawn_ctx(prov.clone());
    install_inventory(
        ctx.session_scope.unwrap(),
        &prov.canonical_path,
        &prov.sha256,
    );

    let decision = proxy.evaluate(&ctx).await;
    assert!(
        approx_eq(decision.composite_score, NON_ROUTINE_SPAWN_SCORE),
        "tampered ancestor must fall back to baseline {NON_ROUTINE_SPAWN_SCORE}, got {}",
        decision.composite_score
    );
}

// ---------------------------------------------------------------------------
// I6 — mid-session new binary not pinned → no signal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn i6_mid_session_new_binary_does_not_get_signal() {
    let proxy = proxy_with_signal_on();
    let pinned = vendor_provenance();
    // Build the inventory at session start with the legitimate binary.
    let scope = SessionScopeKey::fresh();
    let state = SessionStateRegistry::global().get_or_create(scope);
    let inv = SessionPinnedInventory::from_entries([(
        pinned.canonical_path.clone(),
        pinned.sha256.clone(),
    )]);
    state.set_pinned_inventory(inv);

    // Now the LLM "installs" a new binary mid-session — different path.
    let mut new_binary = vendor_provenance();
    new_binary.canonical_path = "/home/u/.local/share/codex/bin/malicious-tool".into();
    new_binary.sha256 = "ff".repeat(32);
    let mut ctx = spawn_ctx(new_binary);
    ctx.session_scope = Some(scope);

    let decision = proxy.evaluate(&ctx).await;
    assert!(
        approx_eq(decision.composite_score, NON_ROUTINE_SPAWN_SCORE),
        "binary not in inventory must score baseline, got {}",
        decision.composite_score
    );
}

#[tokio::test]
async fn i6_hash_swap_mid_session_does_not_get_signal() {
    // Same canonical path, different hash — simulates an attacker
    // replacing a pinned binary on disk between session start and
    // spawn time. Phase D re-hashes at spawn time; the mismatch must
    // deny the signal.
    let proxy = proxy_with_signal_on();
    let original = vendor_provenance();
    let scope = SessionScopeKey::fresh();
    let state = SessionStateRegistry::global().get_or_create(scope);
    let inv = SessionPinnedInventory::from_entries([(
        original.canonical_path.clone(),
        "aa".repeat(32), // pinned hash
    )]);
    state.set_pinned_inventory(inv);

    let mut tampered = original.clone();
    tampered.sha256 = "ff".repeat(32); // spawn-time hash differs
    let mut ctx = spawn_ctx(tampered);
    ctx.session_scope = Some(scope);

    let decision = proxy.evaluate(&ctx).await;
    assert!(
        approx_eq(decision.composite_score, NON_ROUTINE_SPAWN_SCORE),
        "hash drift must deny signal, got {}",
        decision.composite_score
    );
}

// ---------------------------------------------------------------------------
// I7 — file write inside routine root still flows through filters
// ---------------------------------------------------------------------------

#[tokio::test]
async fn i7_file_write_inside_routine_root_is_not_routine() {
    // The routine signal is scoped to ProcessSpawn only. A FileWrite
    // under a routine_exec_root must NOT inherit any reduction — the
    // baseline operation-risk for FileWrite is +0.5 (writes), and the
    // routine signal doesn't apply to it.
    let proxy = proxy_with_signal_on();
    let session_id = Uuid::new_v4();
    let mut ctx = ToolCallContext::new(
        "test:integration",
        ToolCallType::FileWrite {
            path: "/home/u/.local/share/codex/bin/payload".into(),
            content_hash: "00".repeat(32),
        },
        session_id,
    );
    ctx.session_scope = Some(SessionScopeKey::from_session_id(session_id));

    let decision = proxy.evaluate(&ctx).await;
    // FileWrite baseline is +0.5 from operation-risk — NOT because of
    // the routine signal, but because writes intrinsically score 0.5.
    // The point of this test is that the score reflects the FileWrite
    // baseline and isn't accidentally widened or narrowed by routine
    // signal logic.
    assert!(
        approx_eq(decision.composite_score, 0.5),
        "FileWrite must score the write baseline, got {}",
        decision.composite_score
    );
}

// ---------------------------------------------------------------------------
// I8 — outbound-capable binary excluded
// ---------------------------------------------------------------------------

#[tokio::test]
async fn i8_outbound_capable_curl_does_not_get_signal() {
    let proxy = proxy_with_signal_on();
    let mut prov = vendor_provenance();
    // Pretend curl resolves under a routine root and was pinned — the
    // outbound flag must still deny.
    prov.canonical_path = "/usr/bin/curl".into();
    prov.matched_routine_root = Some("/usr/bin/".into());
    prov.is_outbound_capable = true;
    let ctx = spawn_ctx(prov.clone());
    install_inventory(
        ctx.session_scope.unwrap(),
        &prov.canonical_path,
        &prov.sha256,
    );

    let decision = proxy.evaluate(&ctx).await;
    assert!(
        approx_eq(decision.composite_score, NON_ROUTINE_SPAWN_SCORE),
        "outbound-capable must score baseline, got {}",
        decision.composite_score
    );
}

// ---------------------------------------------------------------------------
// I9 — minor-version-bump simulation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn i9_minor_version_bump_pinned_at_session_start_gets_signal() {
    // Simulates Codex shipping v1.2.4 → v1.2.5. The new binary lives
    // at a different canonical path. Phase B's glob expansion picks
    // up the new version directory at session start; Phase C walks
    // and pins it. The spawn at v1.2.5's path therefore matches the
    // inventory and gets +0.5 — no prompt flood.
    let proxy = proxy_with_signal_on();
    let mut new_version = vendor_provenance();
    new_version.canonical_path = "/home/u/.local/share/codex/versions/1.2.5/bin/codex".into();
    new_version.matched_routine_root = Some("/home/u/.local/share/codex/versions/1.2.5/".into());
    let ctx = spawn_ctx(new_version.clone());
    // The session-start scan walked the new version dir and pinned the
    // binary — that's why this test installs the inventory with the
    // new canonical path.
    install_inventory(
        ctx.session_scope.unwrap(),
        &new_version.canonical_path,
        &new_version.sha256,
    );

    let decision = proxy.evaluate(&ctx).await;
    assert!(
        approx_eq(decision.composite_score, ROUTINE_SPAWN_SCORE),
        "version-bumped binary that's session-pinned must score routine, got {}",
        decision.composite_score
    );
}

// ---------------------------------------------------------------------------
// Default-off behaviour — sanity-check the flag actually gates the signal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flag_off_routine_binary_still_scores_baseline() {
    let proxy = proxy_with_signal_off();
    let prov = vendor_provenance();
    let ctx = spawn_ctx(prov.clone());
    install_inventory(
        ctx.session_scope.unwrap(),
        &prov.canonical_path,
        &prov.sha256,
    );

    let decision = proxy.evaluate(&ctx).await;
    // With the flag off, ProcessSpawn scores the standard baseline +1.0.
    // The env-var override may force the signal on; this test is robust
    // against a developer's shell having it set by skipping the assertion
    // in that case rather than fighting the env.
    if std::env::var_os("GRITH_PROXY_ROUTINE_SIGNAL_ENABLED").is_none() {
        assert!(
            approx_eq(decision.composite_score, NON_ROUTINE_SPAWN_SCORE),
            "flag off + no env override should score baseline, got {}",
            decision.composite_score
        );
    }
}
