// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Protection suite — Phase 4 (documented-limitation gap-tests) + Phase 5
//! (benign baselines). Research doc §5, §6.2.
//!
//! GAP-TESTS pin grith's *current* behaviour for a KNOWN hole and are named to
//! flag it (§1.3: an assert-current-behaviour test is living documentation of a
//! limitation, far better than silence). If grith later closes the hole, the
//! test flips and is updated — a deliberate tripwire.
//!
//! BENIGN BASELINES assert that ordinary developer operations are NOT flagged,
//! so the suite (and future rule tightening) can't silently regress into
//! over-blocking — the very flood the rate-limit redesign removed.

use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::operation_risk::OperationRiskFilter;
use grith_proxy::filters::sensitive_path::SensitivePathHeuristicFilter;
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

fn any_matched(d: &ProxyDecision) -> bool {
    d.filter_results.iter().any(|r| r.matched)
}

fn ctx(call_type: ToolCallType, session: Uuid) -> ToolCallContext {
    ToolCallContext::new("protection-test", call_type, session)
}

// ===========================================================================
// GAP-TEST (KNOWN LIMITATION) — path-STRING classification misses symlinked
// targets. The supervisor passes the path the tracee opened;
// `canonicalize_for_tracee` makes it absolute but does NOT resolve symlinks
// (Step-0 finding). So a sensitive file opened via an innocuous symlink path
// reaches `sensitive_path` as that innocuous STRING, and the filter matches on
// the string. Documented limitation; resolving symlinks supervisor-side
// collides with the mount-ns-divergence gap (research doc §5.1 #8/#9). If this
// is ever fixed, this test must flip. (Path-string based, hence hermetic — no
// dependence on $TMPDIR, which can itself contain filter markers.)
// ===========================================================================

#[tokio::test]
async fn gap_path_string_classification_misses_symlinked_target() {
    let proxy = proxy_with(Box::new(SensitivePathHeuristicFilter::new()));

    // Imagine `/home/u/project/notes.txt` is a symlink to `~/.ssh/id_rsa`. The
    // tracee opens `notes.txt`; the supervisor forwards that string unresolved.
    let innocuous = "/home/u/project/notes.txt";
    let d = proxy
        .evaluate(&ctx(
            ToolCallType::FileRead {
                path: innocuous.into(),
            },
            Uuid::new_v4(),
        ))
        .await;
    assert!(
        !any_matched(&d),
        "KNOWN GAP: an innocuous path string is not flagged even if it symlinks \
         to a secret — the filter matches the string, not the resolved target. \
         If symlink resolution lands, update this test + the §5.1 gap note."
    );

    // Control: the secret's REAL path IS flagged — proving it's the path-string
    // indirection (not the filter) that is the gap.
    let d2 = proxy
        .evaluate(&ctx(
            ToolCallType::FileRead {
                path: "/home/u/.ssh/id_rsa".into(),
            },
            Uuid::new_v4(),
        ))
        .await;
    assert!(any_matched(&d2), "the secret's real path must be flagged");
}

// ===========================================================================
// BENIGN BASELINES — ordinary developer operations must NOT be flagged.
// (Config-independent filters only; rule-config-dependent ops like `git clone`
// command-matching need a production-config proxy — see §6 fidelity note.)
// ===========================================================================

#[tokio::test]
async fn benign_project_file_write_is_clean() {
    let proxy = proxy_with(Box::new(SensitivePathHeuristicFilter::new()));
    let d = proxy
        .evaluate(&ctx(
            ToolCallType::FileWrite {
                path: "/home/u/project/src/main.rs".into(),
                content_hash: String::new(),
            },
            Uuid::new_v4(),
        ))
        .await;
    assert!(
        !any_matched(&d),
        "editing a project source file must be clean: {:?}",
        d.filter_results
    );
    assert!(matches!(d.action, ProxyAction::Allow));
}

#[tokio::test]
async fn benign_ssh_config_read_is_clean() {
    // sensitive_path has an explicit carveout for ~/.ssh metadata (config /
    // known_hosts) reads — git/ssh read these constantly.
    let proxy = proxy_with(Box::new(SensitivePathHeuristicFilter::new()));
    for f in ["config", "known_hosts"] {
        let d = proxy
            .evaluate(&ctx(
                ToolCallType::FileRead {
                    path: format!("/home/u/.ssh/{f}"),
                },
                Uuid::new_v4(),
            ))
            .await;
        assert!(
            d.filter_results
                .iter()
                .all(|r| !(r.matched && r.rule_id == "credential-directory")),
            "reading ~/.ssh/{f} (ssh metadata) must not trip credential-directory: {:?}",
            d.filter_results
        );
    }
}

#[tokio::test]
async fn benign_plain_chmod_is_low_risk() {
    let proxy = proxy_with(Box::new(OperationRiskFilter::new()));
    // 0o644 — no setuid/setgid bit.
    let d = proxy
        .evaluate(&ctx(
            ToolCallType::FileChmod {
                path: "/home/u/project/run.sh".into(),
                mode: 0o644,
            },
            Uuid::new_v4(),
        ))
        .await;
    assert!(
        matches!(d.action, ProxyAction::Allow),
        "a plain chmod must be allowed: {:?}",
        d.action
    );
}

// (The "ordinary read does not taint" baseline lives in
// protection_collection_persistence.rs with an HTTP POST sink — the variant
// that actually fires on a Low-taint regression — so it is not duplicated here.)
