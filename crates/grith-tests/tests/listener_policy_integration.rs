// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! PR 5 Phase F — integration tests for the wildcard-listener policy.
//!
//! These tests exercise the proxy stack end-to-end (`SecurityProxy`
//! with `EgressPolicyFilter` registered) against the `NetListen`
//! decision matrix from Phase C:
//!
//!   Loopback                  → no listener-policy rule fires.
//!   Wildcard undeclared       → `wildcard-bind-undeclared`,         +5.0 QUEUE
//!   Wildcard declared no-clamp → `wildcard-bind-declared-no-clamp`,  +5.0 QUEUE
//!   Wildcard declared + clamp → no rule fires (Phase D clamps).
//!   Specific non-loopback     → `specific-iface-bind`,               +5.0 QUEUE
//!
//! Coverage maps to the task list:
//!   F3 → listener_loopback_silent
//!   F4 → listener_wildcard_undeclared
//!   F5 → ptrace bind + getsockname round-trip (DEFERRED — see note).
//!   F6 → listener_wildcard_clamp_disabled
//!   F7 → listener_no_routine_no_clamp (same shape as F6 conceptually
//!        because the clamp decision is allow_clamp-gated, not
//!        routine-gated; egress-policy doesn't see routine state).
//!
//! **F5 (real ptrace bind + getsockname e2e) is intentionally deferred.**
//! The byte-level sockaddr construction is verified by 7 unit tests
//! in `crates/grith-supervisor/src/platform/linux/clamp.rs`. A full
//! end-to-end test would need to spawn a real tracee, attach via
//! PTRACE_TRACEME, intercept its `bind()`, run the clamp, resume the
//! syscall, and then read `getsockname` from the child. That harness
//! exists in `supervisor_test.rs` for other syscall flows but is
//! heavyweight; until the existing harness is generalised, the
//! Phase D unit tests + the proxy-side integration tests below
//! provide the right coverage for the security boundary.

use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::egress_policy::EgressPolicyFilter;
use grith_proxy::filters::FilterRegistry;
use grith_proxy::meta_rules::MetaRuleEngine;
use grith_proxy::scoring::ScoringConfig;
use grith_proxy::types::{
    ListenerPolicyMatch, ProxyAction, SessionScopeKey, ToolCallContext, ToolCallType,
};
use uuid::Uuid;

fn proxy_with_egress() -> SecurityProxy {
    let mut registry = FilterRegistry::new();
    registry.register(Box::new(EgressPolicyFilter::with_defaults()));
    SecurityProxy::new(
        registry,
        ScoringConfig::default(),
        MetaRuleEngine::new(vec![]),
    )
}

fn netlisten_ctx(address: &str, port: u16) -> ToolCallContext {
    let session_id = Uuid::new_v4();
    let mut ctx = ToolCallContext::new(
        "test:listener-integration",
        ToolCallType::NetListen {
            address: address.into(),
            port,
        },
        session_id,
    );
    ctx.session_scope = Some(SessionScopeKey::from_session_id(session_id));
    ctx.profile_name = Some("test-tool".into());
    ctx
}

// ---------------------------------------------------------------------------
// F3 — loopback bind is silent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f3_loopback_bind_does_not_fire_any_listener_policy_rule() {
    let proxy = proxy_with_egress();

    for addr in [
        "127.0.0.1",
        "127.0.0.55",
        "::1",
        "0:0:0:0:0:0:0:1",
        "localhost",
        // IPv4-mapped IPv6 loopback — kernel binds to the inner v4.
        "::ffff:127.0.0.1",
    ] {
        let ctx = netlisten_ctx(addr, 8080);
        let decision = proxy.evaluate(&ctx).await;
        assert!(
            !decision.filter_results.iter().any(|r| r.matched
                && matches!(
                    r.rule_id.as_str(),
                    "wildcard-bind-undeclared"
                        | "wildcard-bind-declared-no-clamp"
                        | "specific-iface-bind"
                )),
            "loopback {addr}: no listener-policy rule should fire; got {:?}",
            decision
                .filter_results
                .iter()
                .filter(|r| r.matched)
                .map(|r| r.rule_id.as_str())
                .collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// F4 — wildcard undeclared → queue
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f4_wildcard_undeclared_queues() {
    let proxy = proxy_with_egress();

    for addr in ["0.0.0.0", "::", "::ffff:0.0.0.0"] {
        let ctx = netlisten_ctx(addr, 8080);
        let decision = proxy.evaluate(&ctx).await;
        let listener_rule = decision
            .filter_results
            .iter()
            .find(|r| r.matched && r.filter_name == "egress-policy");
        let rule = listener_rule.unwrap_or_else(|| panic!("wildcard {addr} should fire a rule"));
        assert_eq!(rule.rule_id, "wildcard-bind-undeclared", "addr={addr}");
        assert!(rule.score >= 5.0);
        // Decision must route to QUEUE (default thresholds put 5.0 above
        // the allow threshold but below auto-deny).
        assert!(matches!(decision.action, ProxyAction::Queue { .. }));
    }
}

// ---------------------------------------------------------------------------
// F6 — wildcard declared without clamp → queue
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f6_wildcard_declared_no_clamp_queues() {
    let proxy = proxy_with_egress();
    let mut ctx = netlisten_ctx("0.0.0.0", 41234);
    ctx.listener_policy_match = Some(ListenerPolicyMatch {
        allow_clamp: false,
        desc: "MCP local server".into(),
    });

    let decision = proxy.evaluate(&ctx).await;
    let rule = decision
        .filter_results
        .iter()
        .find(|r| r.matched && r.filter_name == "egress-policy")
        .expect("rule must fire");
    assert_eq!(rule.rule_id, "wildcard-bind-declared-no-clamp");
    assert!(matches!(decision.action, ProxyAction::Queue { .. }));
}

// ---------------------------------------------------------------------------
// F4/F6 reconciliation — only the declared rule fires when matched,
// not the undeclared rule.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn declared_and_undeclared_rules_are_mutually_exclusive() {
    let proxy = proxy_with_egress();

    let mut declared = netlisten_ctx("0.0.0.0", 41234);
    declared.listener_policy_match = Some(ListenerPolicyMatch {
        allow_clamp: false,
        desc: "MCP".into(),
    });
    let declared_decision = proxy.evaluate(&declared).await;
    let undeclared = netlisten_ctx("0.0.0.0", 41234);
    let undeclared_decision = proxy.evaluate(&undeclared).await;

    let declared_rule = declared_decision
        .filter_results
        .iter()
        .find(|r| r.matched && r.filter_name == "egress-policy")
        .expect("declared rule")
        .rule_id
        .clone();
    let undeclared_rule = undeclared_decision
        .filter_results
        .iter()
        .find(|r| r.matched && r.filter_name == "egress-policy")
        .expect("undeclared rule")
        .rule_id
        .clone();

    assert_eq!(declared_rule, "wildcard-bind-declared-no-clamp");
    assert_eq!(undeclared_rule, "wildcard-bind-undeclared");
}

// ---------------------------------------------------------------------------
// F7 — wildcard declared WITH clamp → no listener-policy score (Phase D
// will handle the actual rewrite). Decision can be Allow (subject to
// other filters, which we don't register here).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f7_wildcard_declared_with_clamp_no_listener_policy_score() {
    let proxy = proxy_with_egress();
    let mut ctx = netlisten_ctx("0.0.0.0", 41234);
    ctx.listener_policy_match = Some(ListenerPolicyMatch {
        allow_clamp: true,
        desc: "MCP local server".into(),
    });

    let decision = proxy.evaluate(&ctx).await;
    let listener_rule_matched = decision.filter_results.iter().any(|r| {
        r.matched
            && matches!(
                r.rule_id.as_str(),
                "wildcard-bind-undeclared"
                    | "wildcard-bind-declared-no-clamp"
                    | "specific-iface-bind"
            )
    });
    assert!(
        !listener_rule_matched,
        "allow_clamp=true should suppress every listener-policy rule"
    );
    // The egress-policy filter may still emit unknown-destination or
    // unusual-port for this bind, but those are unrelated to the
    // listener-policy arm. The acceptance criterion is the absence
    // of the listener-policy queue, not the absence of every filter.
}

// ---------------------------------------------------------------------------
// Specific non-loopback interface bind also queues — closes the
// "specific iface" branch.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn specific_iface_bind_queues() {
    let proxy = proxy_with_egress();
    let ctx = netlisten_ctx("203.0.113.1", 9090);
    let decision = proxy.evaluate(&ctx).await;
    let listener_rule = decision.filter_results.iter().find(|r| {
        r.matched && r.filter_name == "egress-policy" && r.rule_id == "specific-iface-bind"
    });
    assert!(
        listener_rule.is_some(),
        "specific-iface-bind rule should fire on a public-IP bind"
    );
    assert!(matches!(decision.action, ProxyAction::Queue { .. }));
}

// ---------------------------------------------------------------------------
// IPv6 wildcard declared + clamp → silenced just like IPv4 wildcard.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ipv6_wildcard_declared_with_clamp_no_listener_policy_score() {
    let proxy = proxy_with_egress();
    let mut ctx = netlisten_ctx("::", 9090);
    ctx.listener_policy_match = Some(ListenerPolicyMatch {
        allow_clamp: true,
        desc: "ipv6 MCP".into(),
    });
    let decision = proxy.evaluate(&ctx).await;
    let listener_rule_matched = decision.filter_results.iter().any(|r| {
        r.matched
            && matches!(
                r.rule_id.as_str(),
                "wildcard-bind-undeclared"
                    | "wildcard-bind-declared-no-clamp"
                    | "specific-iface-bind"
            )
    });
    assert!(!listener_rule_matched);
}

// ---------------------------------------------------------------------------
// Default-port (port=0) policy entries match any-port wildcard binds
// when allow_clamp=true.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn declared_clamp_any_port_silences_arbitrary_port_bind() {
    // Simulate a profile that declares `port = 0` (any ephemeral) with
    // allow_clamp = true. The supervisor would have built a
    // ListenerPolicyMatch with allow_clamp=true regardless of the
    // tracee's chosen port; the egress filter only cares about the
    // ListenerPolicyMatch on the context.
    let proxy = proxy_with_egress();
    let mut ctx = netlisten_ctx("0.0.0.0", 51234);
    ctx.listener_policy_match = Some(ListenerPolicyMatch {
        allow_clamp: true,
        desc: "ephemeral IPC".into(),
    });
    let decision = proxy.evaluate(&ctx).await;
    assert!(!decision
        .filter_results
        .iter()
        .any(|r| r.matched && r.rule_id == "wildcard-bind-undeclared"));
}
