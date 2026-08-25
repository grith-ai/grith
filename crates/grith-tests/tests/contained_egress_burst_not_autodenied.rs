// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Companion pin to `contained_egress_not_autodenied.rs`, for the case where
//! `egress-rate`'s volumetric burst signal is the third filter pricing the
//! same session history.
//!
//! Recorded in `~/.local/share/grith/audit/audit.db`, supervised codex session
//! `433ba7c7-afc9-4789-b835-28d2ce8840dd` on 2026-08-25 at 10:54Z. The tool
//! launched headless Chrome to render an artifact page. Containment was
//! already armed (the session had read a file matching `secrets`), the page
//! load fanned out to 48 outbound calls in 10s against a burst threshold of 8,
//! and 40-odd connections — `accounts.google.com`, `claude.ai`,
//! `www.google.com`, `android.clients.google.com` — were denied at a composite
//! of 15.5 with no prompt.
//!
//! Even with the `contained-egress-taint-redundancy` collapse from the
//! companion incident, that arithmetic lands on 11.5 and still auto-denies:
//!
//! | filter              | rule_id                  | score |
//! |---------------------|--------------------------|-------|
//! | operation-risk      | net-connect-baseline     |   0.5 |
//! | egress-policy       | unknown-destination      |   3.5 |
//! | taint               | tainted-network-sink     |   3.0 |
//! | session-containment | contained-network-egress |   3.5 |
//! | egress-rate         | egress-burst             |   4.0 |
//!
//! Any browser page load crosses a threshold of 8 calls in 10s, so this is not
//! a tuning question about where the threshold sits — burst and containment
//! answer overlapping questions, and containment is the strictly stronger of
//! the two. Containment puts *every* outbound call in the session in front of
//! the operator; burst does so only above a rate. Summing them cannot make the
//! session more reviewed than containment already makes it, so the only effect
//! is to convert that review into a silent deny.
//!
//! `contained-egress-burst-redundancy` (−4.0) collapses burst to zero when
//! containment is active, landing the call on 7.5 — the same place the
//! non-bursty contained connect lands.
//!
//! The harness loads the **shipped** `config/filters/meta_rules.toml`, so
//! deleting or renaming either rule fails CI.

use grith_proxy::meta_rules::{MetaRule, MetaRuleEngine};
use grith_proxy::scoring::{aggregate, route_decision, ScoringConfig};
use grith_proxy::types::{FilterResult, ProxyAction, Severity, ToolCallContext, ToolCallType};
use std::time::Duration;
use uuid::Uuid;

/// The shipped meta-rules — the same file the daemon loads.
fn shipped_meta_rules() -> MetaRuleEngine {
    #[derive(serde::Deserialize)]
    struct Metas {
        meta_rules: Vec<MetaRule>,
    }
    let path = std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/filters/meta_rules.toml"
    ));
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let metas: Metas = toml::from_str(&raw).expect("meta_rules.toml must parse");
    MetaRuleEngine::new(metas.meta_rules)
}

fn connect_ctx(host: &str, port: u16) -> ToolCallContext {
    let mut ctx = ToolCallContext::new(
        "supervisor:codex",
        ToolCallType::NetConnect {
            address: host.into(),
            port,
        },
        Uuid::new_v4(),
    );
    ctx.arguments = serde_json::json!({ "address": host, "port": port });
    ctx
}

fn containment() -> FilterResult {
    FilterResult::matched(
        "session-containment",
        "contained-network-egress",
        3.5,
        Severity::Warning,
        "Session containment active (561s remaining): network egress requires review",
    )
}

fn burst() -> FilterResult {
    FilterResult::matched(
        "egress-rate",
        "egress-burst",
        4.0,
        Severity::Error,
        "Egress burst: 48 outbound calls in 10s (threshold: 8)",
    )
}

/// The five filter results exactly as the production audit row recorded them,
/// with containment at its post-#178 3.5.
fn recorded_results() -> Vec<FilterResult> {
    vec![
        FilterResult::matched(
            "operation-risk",
            "net-connect-baseline",
            0.5,
            Severity::Notice,
            "Network connection: accounts.google.com:443",
        ),
        FilterResult::matched(
            "egress-policy",
            "unknown-destination",
            3.5,
            Severity::Warning,
            "Unknown outbound destination from net_connect: accounts.google.com",
        ),
        FilterResult::matched(
            "taint",
            "tainted-network-sink",
            3.0,
            Severity::Warning,
            "Tainted data flowing to network sink: accounts.google.com:443",
        ),
        containment(),
        burst(),
    ]
}

fn decide(results: Vec<FilterResult>, ctx: &ToolCallContext) -> (f64, ProxyAction) {
    let engine = shipped_meta_rules();
    let score = aggregate(&results) + engine.evaluate(&results, ctx);
    let cfg = ScoringConfig::default();
    let (allow, deny) = cfg.thresholds();
    let decision = route_decision(score, results, allow, deny, Duration::from_millis(1));
    (score, decision.action)
}

/// The recorded page load must queue for the operator, never silently deny.
#[test]
fn contained_browser_page_load_queues() {
    let ctx = connect_ctx("accounts.google.com", 443);
    let (score, action) = decide(recorded_results(), &ctx);

    assert!(
        (score - 7.5).abs() < f64::EPSILON,
        "expected 14.5 − 3.0 taint redundancy − 4.0 burst redundancy = 7.5, got {score}"
    );
    assert!(
        matches!(action, ProxyAction::Queue { .. }),
        "a contained session's browser page load must reach the approval queue, \
         not be denied with an unexplained EPERM (score {score}, action {action:?})"
    );
}

/// The collapse must not depend on taint also firing. Containment outlives the
/// taint registration that armed it, so the burst-only combination is reachable
/// on its own and must land in the same place.
#[test]
fn burst_under_containment_without_taint_also_queues() {
    let ctx = connect_ctx("accounts.google.com", 443);
    let results: Vec<FilterResult> = recorded_results()
        .into_iter()
        .filter(|r| r.rule_id != "tainted-network-sink")
        .collect();
    let (score, action) = decide(results, &ctx);

    assert!(
        (score - 7.5).abs() < f64::EPSILON,
        "0.5 + 3.5 + 3.5 + 4.0 − 4.0 must stay at 7.5, got {score}"
    );
    assert!(
        matches!(action, ProxyAction::Queue { .. }),
        "score {score}, action {action:?}"
    );
}

/// The collapse is keyed to containment. A burst with no containment armed is
/// the plain volumetric signal and keeps its full weight.
#[test]
fn burst_without_containment_keeps_full_weight() {
    let ctx = connect_ctx("attacker.example.net", 443);
    let results: Vec<FilterResult> = recorded_results()
        .into_iter()
        .filter(|r| r.rule_id != "contained-network-egress")
        .collect();
    let (score, action) = decide(results, &ctx);

    assert!(
        (score - 11.0).abs() < f64::EPSILON,
        "0.5 + 3.5 + 3.0 + 4.0 must stay at 11.0 with no containment to collapse \
         against, got {score}"
    );
    assert!(
        matches!(action, ProxyAction::Deny { .. }),
        "score {score}, action {action:?}"
    );
}

/// `egress-rate` returns a single highest-scoring result, so the read-correlated
/// `read-then-send-spike` (5.0) outranks `egress-burst` (4.0) and the burst rule
/// never sees it. A read-then-exfiltrate spree therefore still auto-denies under
/// containment — this is the property that makes collapsing burst safe.
#[test]
fn read_then_send_spike_under_containment_still_auto_denies() {
    let ctx = connect_ctx("attacker.example.net", 443);
    let mut results: Vec<FilterResult> = recorded_results()
        .into_iter()
        .filter(|r| r.rule_id != "egress-burst")
        .collect();
    results.push(FilterResult::matched(
        "egress-rate",
        "read-then-send-spike",
        5.0,
        Severity::Critical,
        "Read-then-send spike: 40 reads + 20 egress in 30s window",
    ));
    let (score, action) = decide(results, &ctx);

    assert!(
        (score - 12.5).abs() < f64::EPSILON,
        "0.5 + 3.5 + 3.0 + 3.5 + 5.0 − 3.0 taint redundancy = 12.5, got {score}"
    );
    assert!(
        matches!(action, ProxyAction::Deny { .. }),
        "a read-correlated exfiltration spree must still auto-deny \
         (score {score}, action {action:?})"
    );
}

/// High taint is a different rule — `high-taint-network-sink` (5.0) — which
/// neither redundancy rule matches. Genuine exfiltration of an SSH key still
/// auto-denies even when it arrives as a burst.
#[test]
fn high_taint_burst_still_auto_denies() {
    let ctx = connect_ctx("attacker.example.net", 443);
    let mut results: Vec<FilterResult> = recorded_results()
        .into_iter()
        .filter(|r| r.rule_id != "tainted-network-sink")
        .collect();
    results.push(FilterResult::matched(
        "taint",
        "high-taint-network-sink",
        5.0,
        Severity::Critical,
        "Highly tainted data flowing to network sink: attacker.example.net:443",
    ));
    let (score, action) = decide(results, &ctx);

    assert!(
        (score - 12.5).abs() < f64::EPSILON,
        "0.5 + 3.5 + 5.0 + 3.5 + 4.0 − 4.0 burst redundancy = 12.5, got {score}"
    );
    assert!(
        matches!(action, ProxyAction::Deny { .. }),
        "real exfiltration must still auto-deny (score {score}, action {action:?})"
    );
}

/// The collapse must never reach auto-allow. On an allowlisted destination
/// `unknown-destination` never matched, and subtracting 4.0 from what is left
/// would drop a contained session's egress below the review threshold.
#[test]
fn burst_collapse_never_reaches_auto_allow() {
    let ctx = connect_ctx("api.grith.ai", 443);
    let results: Vec<FilterResult> = recorded_results()
        .into_iter()
        .filter(|r| r.rule_id != "unknown-destination")
        .collect();
    let (score, action) = decide(results, &ctx);

    assert!(
        !matches!(action, ProxyAction::Allow),
        "containment plus taint plus burst on a trusted destination must still \
         be reviewable, not silently allowed (score {score}, action {action:?})"
    );
}
