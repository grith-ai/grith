// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Risk-gated rate-limit volume detection, end-to-end through the proxy.
//!
//! These were originally PR 3's scratch-file-exemption integration tests. The
//! rate-limit-burst redesign (step 4) retired the per-pattern scratch / `.git`
//! / `~/.cache` exemptions in favour of risk-gating: the `rate_limit` filter's
//! volume penalties fire only for *risk-bearing* operations, so a burst of
//! untainted routine churn never escalates — without any per-path allowlist.
//! The pid-based supervisor-vs-LLM discrimination the old exemption used is
//! also gone (risk-gating keys on risk, not on caller).
//!
//! `proxy()` builds the filter with risk-gating ON, matching the production
//! default (`proxy.rate_limit.risk_gated_burst = true`). The untainted
//! destructive-spree case this gate intentionally drops is covered by the
//! supervisor's mass-destruction signal (see the supervisor crate's
//! `mass_destruction` unit tests).

use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::rate_limit::RateLimitFilter;
use grith_proxy::meta_rules::MetaRuleEngine;
use grith_proxy::scoring::ScoringConfig;
use grith_proxy::types::{ToolCallContext, ToolCallType};
use grith_tests::TestFixtures;
use std::time::Duration;
use uuid::Uuid;

/// Build a proxy whose `RateLimitFilter` has risk-gating enabled — the
/// production default after rollout step 4.
fn proxy() -> SecurityProxy {
    let mut registry = TestFixtures::default_filter_registry();
    registry.register(Box::new(
        RateLimitFilter::with_defaults().with_risk_gated_burst(true),
    ));
    SecurityProxy::new(
        registry,
        ScoringConfig::default(),
        MetaRuleEngine::new(vec![]),
    )
}

fn supervised_write(path: &str, session: Uuid, pid: u64) -> ToolCallContext {
    let mut ctx = ToolCallContext::new(
        "test",
        ToolCallType::FileWrite {
            path: path.to_string(),
            content_hash: "x".into(),
        },
        session,
    );
    ctx.arguments = serde_json::json!({ "pid": pid });
    ctx
}

fn supervised_delete(path: &str, session: Uuid, pid: u64) -> ToolCallContext {
    let mut ctx = ToolCallContext::new(
        "test",
        ToolCallType::FileDelete {
            path: path.to_string(),
        },
        session,
    );
    ctx.arguments = serde_json::json!({ "pid": pid });
    ctx
}

/// A network egress op — `is_burst_risk_relevant` treats `HttpRequest` as
/// risk-bearing unconditionally, so a burst of these is the legitimate volume
/// signal risk-gating must still surface.
fn http_request(url: &str, session: Uuid, pid: u64) -> ToolCallContext {
    let mut ctx = ToolCallContext::new(
        "test",
        ToolCallType::HttpRequest {
            method: "GET".into(),
            url: url.to_string(),
        },
        session,
    );
    ctx.arguments = serde_json::json!({ "pid": pid });
    ctx
}

fn rate_limit_fired(decision: &grith_proxy::types::ProxyDecision) -> bool {
    decision
        .filter_results
        .iter()
        .any(|r| r.filter_name == "rate_limit" && r.matched)
}

// ---------------------------------------------------------------------------
// Untainted routine churn never escalates (the prompt-flood fix)
// ---------------------------------------------------------------------------

/// 20 etilqs writes + 20 deletes in a session must never fire rate_limit —
/// the dominant Codex/Claude-startup flood case. Under risk-gating this holds
/// because untainted file churn is not risk-bearing (no scratch allowlist
/// needed).
#[tokio::test]
async fn untainted_scratch_churn_does_not_prompt() {
    let proxy = proxy();
    let session = Uuid::new_v4();
    let pid: u64 = 4242;

    for i in 0..20 {
        let path = format!("/var/tmp/etilqs_{i:08x}");
        let d = proxy.evaluate(&supervised_write(&path, session, pid)).await;
        assert!(
            !rate_limit_fired(&d),
            "etilqs write #{i} must not fire rate_limit"
        );
        let d = proxy
            .evaluate(&supervised_delete(&path, session, pid))
            .await;
        assert!(
            !rate_limit_fired(&d),
            "etilqs delete #{i} must not fire rate_limit"
        );
    }
}

/// The risk-gating improvement over per-pattern exemptions: untainted churn in
/// an *ordinary* directory (no scratch pattern, no allowlist entry) also never
/// escalates. The old burst counter would have flooded here.
#[tokio::test]
async fn untainted_non_scratch_churn_does_not_prompt() {
    let proxy = proxy();
    let session = Uuid::new_v4();
    let pid: u64 = 4242;

    for i in 0..40 {
        let path = format!("/home/u/proj/build/obj-{i:08x}.o");
        let d = proxy.evaluate(&supervised_write(&path, session, pid)).await;
        assert!(
            !rate_limit_fired(&d),
            "untainted non-scratch write #{i} must not fire rate_limit under risk-gating"
        );
    }
}

/// Append and delete shapes of untainted churn are equally exempt — risk-gating
/// keys on op risk, not on the specific write variant.
#[tokio::test]
async fn untainted_churn_exempt_across_write_shapes() {
    let proxy = proxy();
    let session = Uuid::new_v4();
    let pid: u64 = 4242;
    let path = "/home/u/proj/build/artifact";

    for i in 0..20 {
        let append = {
            let mut c = supervised_write(path, session, pid);
            c.call_type = ToolCallType::FileAppend { path: path.into() };
            c
        };
        let d = proxy.evaluate(&append).await;
        assert!(
            !rate_limit_fired(&d),
            "append #{i} must not fire rate_limit"
        );
        let d = proxy.evaluate(&supervised_delete(path, session, pid)).await;
        assert!(
            !rate_limit_fired(&d),
            "delete #{i} must not fire rate_limit"
        );
    }
}

// ---------------------------------------------------------------------------
// Risk-bearing volume still escalates (the signal we keep)
// ---------------------------------------------------------------------------

/// Risk-gating must NOT silence the legitimate volume signal: a burst of
/// network egress (brute-force / staged-exfil shape) still trips rate_limit.
#[tokio::test]
async fn risk_bearing_http_burst_still_trips() {
    let proxy = proxy();
    let session = Uuid::new_v4();
    let pid: u64 = 4242;

    let mut tripped = false;
    for i in 0..40 {
        let d = proxy
            .evaluate(&http_request(
                &format!("http://example.test/{i}"),
                session,
                pid,
            ))
            .await;
        if rate_limit_fired(&d) {
            tripped = true;
            break;
        }
        // Stay inside the 5s burst window.
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        tripped,
        "a burst of risk-bearing HTTP requests must still fire rate_limit"
    );
}
