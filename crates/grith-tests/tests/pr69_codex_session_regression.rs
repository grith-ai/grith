// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! PR 69 Change 7 — full-stack regression tests for the shapes recorded
//! in codex session `7f256630-6b6a-46a3-8c41-f3834953c522` (2026-05-25
//! 11:57–11:58 UTC, 162 events). These tests register the same filter
//! combination as the daemon (`OperationRiskFilter` +
//! `EgressPolicyFilter` + `BehaviouralFilter` +
//! `SensitivePathHeuristicFilter` + `RateLimitFilter`) so additive
//! filter scores cannot drift back into DENY without a test failure.
//!
//! The existing PR 5 listener-policy tests register only
//! `EgressPolicyFilter` and missed the production interaction with
//! `OperationRiskFilter` that pushed `wildcard-bind-undeclared` from
//! QUEUE (5.0) to DENY (9.0). These tests close that gap.

use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::behavioural::BehaviouralFilter;
use grith_proxy::filters::egress_policy::EgressPolicyFilter;
use grith_proxy::filters::operation_risk::OperationRiskFilter;
use grith_proxy::filters::rate_limit::RateLimitFilter;
use grith_proxy::filters::sensitive_path::SensitivePathHeuristicFilter;
use grith_proxy::filters::FilterRegistry;
use grith_proxy::meta_rules::MetaRuleEngine;
use grith_proxy::scoring::ScoringConfig;
use grith_proxy::types::{
    ListenerPolicyMatch, ProxyAction, SessionScopeKey, ToolCallContext, ToolCallType,
};
use uuid::Uuid;

/// The daemon's Phase 1 + Phase 3 stack as it pertains to the recorded
/// shapes. Excludes path-match / allowlist / capability / secret-scan /
/// command / dlp-gate / canary / reputation / taint / session-containment
/// / egress-rate because none of those contributed to the recorded
/// audit-log scores for codex.
fn daemon_like_proxy() -> SecurityProxy {
    let mut registry = FilterRegistry::new();
    registry.register(Box::new(OperationRiskFilter::new()));
    registry.register(Box::new(SensitivePathHeuristicFilter::new()));
    registry.register(Box::new(EgressPolicyFilter::with_defaults()));
    // PR 69 Change 1: the daemon's behavioural filter starts at
    // min_calls_for_baseline = 200. At session-cold-start the filter
    // returns no_match for any call (it's still recording into the
    // sliding window), so the test stays deterministic without warming
    // a 200-call baseline.
    registry.register(Box::new(BehaviouralFilter::with_defaults()));
    registry.register(Box::new(RateLimitFilter::with_defaults()));

    SecurityProxy::new(
        registry,
        ScoringConfig::default(),
        MetaRuleEngine::new(vec![]),
    )
}

fn ctx(call_type: ToolCallType) -> ToolCallContext {
    let session_id = Uuid::new_v4();
    let mut ctx = ToolCallContext::new("test:pr69-regression", call_type, session_id);
    ctx.session_scope = Some(SessionScopeKey::from_session_id(session_id));
    ctx.profile_name = Some("codex".into());
    ctx
}

// ---------------------------------------------------------------------------
// Recorded shape 1: NetListen 0.0.0.0:0 with no listener policy
// Before PR 69:            operation-risk +4.0 + egress-policy +5.0 = 9.0 → DENY
// After  PR 69:            operation-risk +0.5 + egress-policy +5.0 = 5.5 → QUEUE
// After ephemeral carveout: operation-risk +0.5 + egress-policy +0.5 = 1.0 → ALLOW
// (port 0 = kernel-assigned; the client-socket idiom UDP sockets use, which
// never call listen(2) — see the `ephemeral-port-bind` rule.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn netlisten_wildcard_undeclared_ephemeral_allows_audited() {
    let proxy = daemon_like_proxy();
    let mut c = ctx(ToolCallType::NetListen {
        address: "0.0.0.0".into(),
        port: 0,
    });
    c.listener_policy_match = None;

    let decision = proxy.evaluate(&c).await;
    assert!(
        matches!(decision.action, ProxyAction::Allow),
        "ephemeral wildcard bind must ALLOW, got {:?} (composite={})",
        decision.action,
        decision.composite_score
    );
    // Still audited — egress-policy fires the ephemeral rule, not nothing.
    let egress_rule = decision
        .filter_results
        .iter()
        .find(|r| r.matched && r.filter_name == "egress-policy")
        .expect("egress-policy must fire (audited, not silent)");
    assert_eq!(egress_rule.rule_id, "ephemeral-port-bind");
    assert!(egress_rule.score <= 0.5);
}

// ---------------------------------------------------------------------------
// A FIXED-port wildcard bind is a real reachable-service declaration and
// must keep queueing — the ephemeral carveout is port-0 only.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn netlisten_wildcard_undeclared_fixed_port_queues_not_denies() {
    let proxy = daemon_like_proxy();
    let mut c = ctx(ToolCallType::NetListen {
        address: "0.0.0.0".into(),
        port: 3124,
    });
    c.listener_policy_match = None;

    let decision = proxy.evaluate(&c).await;
    assert!(
        matches!(decision.action, ProxyAction::Queue { .. }),
        "fixed-port wildcard-undeclared must QUEUE, got {:?} (composite={})",
        decision.action,
        decision.composite_score
    );
    assert!(
        decision.composite_score < 8.0,
        "composite must stay below DENY threshold; was {}",
        decision.composite_score
    );
    // egress-policy fires the wildcard-bind-undeclared rule.
    let egress_rule = decision
        .filter_results
        .iter()
        .find(|r| r.matched && r.filter_name == "egress-policy")
        .expect("egress-policy must fire");
    assert_eq!(egress_rule.rule_id, "wildcard-bind-undeclared");
    // operation-risk fires the new low baseline rule, not the old +4.0.
    let op_rule = decision
        .filter_results
        .iter()
        .find(|r| r.matched && r.filter_name == "operation-risk")
        .expect("operation-risk must fire baseline");
    assert_eq!(op_rule.rule_id, "net-listen-baseline");
    assert!(op_rule.score <= 0.5);
}

// ---------------------------------------------------------------------------
// Recorded shape 2: NetListen 0.0.0.0:0 with codex MCP policy
// (port=0, allow_clamp=true). PR 5 clamp will rewrite; proxy returns
// the low operation-risk baseline only.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn netlisten_wildcard_declared_clamp_allows() {
    let proxy = daemon_like_proxy();
    let mut c = ctx(ToolCallType::NetListen {
        address: "0.0.0.0".into(),
        port: 0,
    });
    c.listener_policy_match = Some(ListenerPolicyMatch {
        allow_clamp: true,
        desc: "Codex MCP transport".into(),
    });

    let decision = proxy.evaluate(&c).await;
    assert!(
        matches!(decision.action, ProxyAction::Allow),
        "wildcard-declared-clamp must ALLOW, got {:?} (composite={})",
        decision.action,
        decision.composite_score
    );
    // No egress-policy rule fires (PR 69 Change 4 returns no_match).
    assert!(
        !decision
            .filter_results
            .iter()
            .any(|r| r.matched && r.filter_name == "egress-policy"),
        "egress-policy must stay silent under allow_clamp"
    );
}

// ---------------------------------------------------------------------------
// Recorded shape 3: FileRead .../node_modules/.../tokenize.js
// Before PR 69: sensitive_path +2.8 + behavioural +3.0 = 5.8 → QUEUE
// After  PR 69: behavioural pre-warmup no_match + node_modules carveout
//               on sensitive_path = 0 → ALLOW
// ---------------------------------------------------------------------------

#[tokio::test]
async fn node_modules_tokenize_read_allows() {
    let proxy = daemon_like_proxy();
    let c = ctx(ToolCallType::FileRead {
        path: "/home/u/.nvm/versions/node/v22.22.2/lib/node_modules/npm/\
              node_modules/postcss-selector-parser/dist/tokenize.js"
            .into(),
    });

    let decision = proxy.evaluate(&c).await;
    assert!(
        matches!(decision.action, ProxyAction::Allow),
        "node_modules tokenize.js read must ALLOW, got {:?} (composite={})",
        decision.action,
        decision.composite_score
    );
    assert!(
        !decision.filter_results.iter().any(|r| r.matched
            && r.filter_name == "sensitive-path-heuristic"
            && r.rule_id == "secretish-filename"),
        "secretish-filename must not fire inside node_modules"
    );
}

#[tokio::test]
async fn node_modules_token_types_read_allows() {
    let proxy = daemon_like_proxy();
    let c = ctx(ToolCallType::FileRead {
        path: "/home/u/proj/node_modules/some-lib/dist/tokenTypes.js".into(),
    });

    let decision = proxy.evaluate(&c).await;
    assert!(
        matches!(decision.action, ProxyAction::Allow),
        "tokenTypes.js read must ALLOW, got {:?}",
        decision.action,
    );
}

// ---------------------------------------------------------------------------
// Recorded shape 4: FileWrite /var/tmp/etilqs_*
// Before PR 69: operation-risk +0.5 + behavioural +3.0 (cold-start) = 3.5 → QUEUE
// After  PR 69: operation-risk +0.5 + behavioural no_match (routine) = 0.5 → ALLOW
// ---------------------------------------------------------------------------

#[tokio::test]
async fn etilqs_scratch_write_allows() {
    let proxy = daemon_like_proxy();
    let c = ctx(ToolCallType::FileWrite {
        path: "/var/tmp/etilqs_78b2cdbf39e4496a".into(),
        content_hash: "deadbeef".into(),
    });

    let decision = proxy.evaluate(&c).await;
    assert!(
        matches!(decision.action, ProxyAction::Allow),
        "etilqs scratch write must ALLOW, got {:?} (composite={})",
        decision.action,
        decision.composite_score
    );
}

// ---------------------------------------------------------------------------
// Recorded shape 5: FileRename /tmp/node-compile-cache/.../*.tmp -> *
// Before PR 69: operation-risk +0.3 + behavioural +3.0 (cold-start) = 3.3 → QUEUE
// After  PR 69: operation-risk +0.3 + behavioural no_match (routine) = 0.3 → ALLOW
// ---------------------------------------------------------------------------

#[tokio::test]
async fn node_compile_cache_rename_allows() {
    let proxy = daemon_like_proxy();
    let c = ctx(ToolCallType::FileRename {
        old_path: "/tmp/node-compile-cache/v22.22.2-x64-9ac5647c-1000/efe91134.K2lk8u".into(),
        new_path: "/tmp/node-compile-cache/v22.22.2-x64-9ac5647c-1000/efe91134".into(),
    });

    let decision = proxy.evaluate(&c).await;
    assert!(
        matches!(decision.action, ProxyAction::Allow),
        "node-compile-cache rename must ALLOW, got {:?} (composite={})",
        decision.action,
        decision.composite_score
    );
}

// ---------------------------------------------------------------------------
// Negative guard: a SSH private-key read must STILL be QUEUE/DENY even
// though it's a FileRead (routine category). Confirms PR 69 didn't
// over-suppress.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ssh_private_key_read_still_queues() {
    let proxy = daemon_like_proxy();
    let c = ctx(ToolCallType::FileRead {
        path: "/home/u/.ssh/id_rsa".into(),
    });

    let decision = proxy.evaluate(&c).await;
    assert!(
        !matches!(decision.action, ProxyAction::Allow),
        "id_rsa read must not ALLOW, got composite={}",
        decision.composite_score
    );
}
