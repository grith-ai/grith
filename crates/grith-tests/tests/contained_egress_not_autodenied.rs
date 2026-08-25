// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Regression pin for the silent auto-deny of the "read credentials, then
//! connect to the database" workflow, recorded in
//! `~/.local/share/grith/audit/audit.db` on 2026-08-25 at 10:07:30Z and
//! 10:13:26Z.
//!
//! A supervised session read `.env` for its `STAGING_DB_*` keys — deliberately
//! placed there by the operator so the agent could reach their own staging
//! database — and every subsequent outbound connect was denied at a composite
//! of 11.5, past the 8.0 auto-deny threshold. Because auto-deny never prompts,
//! the supervised tool saw only `EPERM`. It concluded the *environment* forbade
//! outbound sockets ("this environment can't open arbitrary outbound sockets at
//! all"), reported that to the operator, and recommended running the work from
//! a different machine. grith had computed the true reason and discarded it.
//!
//! The 11.5 came from four filters that are not independent:
//!
//! | filter              | rule_id                  | score |
//! |---------------------|--------------------------|-------|
//! | operation-risk      | net-connect-baseline     |   0.5 |
//! | egress-policy       | unknown-destination      |   3.5 |
//! | taint               | tainted-network-sink     |   3.0 |
//! | session-containment | contained-network-egress |   4.5 |
//!
//! `session-containment` is *armed by* taint, so the last two both price the
//! same fact — that this session read something sensitive — and the operator's
//! intended workflow necessarily trips both at once. Reading the credentials is
//! what makes using them look like exfiltration.
//!
//! Two changes keep this in the queue band, where a human decides:
//!   * `network_score` 4.5 → 3.5, so containment can never reach auto-deny on
//!     its own (0.5 + 3.5 + 3.5 = 7.5 for a contained session connecting to any
//!     destination that is not on the egress allowlist), and
//!   * the `contained-egress-taint-redundancy` meta-rule (−3.0), which collapses
//!     the double-count when both fire.
//!
//! The harness loads the **shipped** `config/filters/meta_rules.toml`, so
//! deleting or renaming that rule fails CI. Scores are pinned as literals
//! because it is their *sum* relative to the threshold that regressed, not any
//! single filter's value.

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
        "supervisor:claude-code",
        ToolCallType::NetConnect {
            address: host.into(),
            port,
        },
        Uuid::new_v4(),
    );
    ctx.arguments = serde_json::json!({ "address": host, "port": port });
    ctx
}

/// The four filter results exactly as the production audit row recorded them,
/// with containment at its corrected 3.5.
fn recorded_results() -> Vec<FilterResult> {
    vec![
        FilterResult::matched(
            "operation-risk",
            "net-connect-baseline",
            0.5,
            Severity::Notice,
            "Network connection: db-staging.example.co.uk:3306",
        ),
        FilterResult::matched(
            "egress-policy",
            "unknown-destination",
            3.5,
            Severity::Warning,
            "Unknown outbound destination from net_connect: db-staging.example.co.uk",
        ),
        FilterResult::matched(
            "taint",
            "tainted-network-sink",
            3.0,
            Severity::Warning,
            "Tainted data flowing to network sink: db-staging.example.co.uk:3306",
        ),
        FilterResult::matched(
            "session-containment",
            "contained-network-egress",
            3.5,
            Severity::Warning,
            "Session containment active (489s remaining): network egress requires review",
        ),
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

/// The recorded workflow must queue for the operator, never silently deny.
#[test]
fn credential_read_then_database_connect_queues() {
    let ctx = connect_ctx("db-staging.example.co.uk", 3306);
    let (score, action) = decide(recorded_results(), &ctx);

    assert!(
        (score - 7.5).abs() < f64::EPSILON,
        "expected 10.5 − 3.0 redundancy adjustment = 7.5, got {score}"
    );
    assert!(
        matches!(action, ProxyAction::Queue { .. }),
        "the operator's own staging database must reach the approval queue, \
         not be denied with an unexplained EPERM (score {score}, action {action:?})"
    );
}

/// Containment must not reach auto-deny by itself. This is the case where the
/// taint filter's data-flow narrowing means only containment fires — strictly
/// *less* evidence than the case above, so it must not score higher.
#[test]
fn containment_alone_cannot_auto_deny() {
    let ctx = connect_ctx("db-staging.example.co.uk", 3306);
    let results: Vec<FilterResult> = recorded_results()
        .into_iter()
        .filter(|r| r.rule_id != "tainted-network-sink")
        .collect();
    let (score, action) = decide(results, &ctx);

    assert!(
        (score - 7.5).abs() < f64::EPSILON,
        "0.5 + 3.5 + 3.5 must stay at 7.5, got {score}"
    );
    assert!(
        matches!(action, ProxyAction::Queue { .. }),
        "a contained session reaching an undeclared host must queue, not \
         auto-deny with no prompt (score {score}, action {action:?})"
    );
}

/// The redundancy collapse is keyed to Medium/Low taint. Genuine exfiltration —
/// an SSH key or similar leaving the machine — raises `high-taint-network-sink`
/// (5.0), which the meta-rule does not match, and must still auto-deny.
#[test]
fn high_taint_exfiltration_still_auto_denies() {
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
        "high taint must not be collapsed by the redundancy rule, got {score}"
    );
    assert!(
        matches!(action, ProxyAction::Deny { .. }),
        "real exfiltration must still auto-deny (score {score}, action {action:?})"
    );
}

/// The redundancy rule must not fire on an allowlisted destination, where
/// `unknown-destination` never matched — that combination is already low enough
/// to allow, and subtracting from it would push a contained session's egress
/// below the review threshold entirely.
#[test]
fn redundancy_collapse_never_reaches_auto_allow() {
    let ctx = connect_ctx("api.grith.ai", 443);
    let results: Vec<FilterResult> = recorded_results()
        .into_iter()
        .filter(|r| r.rule_id != "unknown-destination")
        .collect();
    let (score, action) = decide(results, &ctx);

    assert!(
        !matches!(action, ProxyAction::Allow),
        "containment plus taint on a trusted destination must still be \
         reviewable, not silently allowed (score {score}, action {action:?})"
    );
}
