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
// CLOSED (was a documented gap) — path-STRING classification missed symlinked
// targets. `canonicalize_for_tracee` made a path absolute but did not resolve
// symlinks, so a sensitive file opened through an innocuous symlink reached
// the filters as that innocuous STRING and matched nothing.
//
// Go-live review B3 closed it: the supervisor resolves against the tracee's
// cwd in `classify.rs`, and the LLM path resolves in
// `ToolCallType::resolve_paths()` before evaluation. This test now asserts the
// resolution rather than the hole — it uses a REAL on-disk symlink, because a
// hermetic string test cannot prove resolution happened.
//
// Mount-namespace divergence (research doc §5.1 #8/#9) remains: a tracee in
// its own namespace may resolve differently. Resolving in ours is strictly
// better than not resolving.
// ===========================================================================

#[tokio::test]
async fn symlinked_target_is_resolved_before_filtering() {
    let proxy = proxy_with(Box::new(SensitivePathHeuristicFilter::new()));

    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("id_rsa");
    std::fs::write(&secret, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
    let innocuous = dir.path().join("notes.txt");
    std::os::unix::fs::symlink(&secret, &innocuous).unwrap();

    // The laundered read: a filter fed the raw string would see "notes.txt".
    let laundered = ToolCallType::FileRead {
        path: innocuous.to_string_lossy().into_owned(),
    }
    .resolve_paths();
    let d = proxy.evaluate(&ctx(laundered, Uuid::new_v4())).await;
    assert!(
        any_matched(&d),
        "a read through a symlink to a private key must be flagged on the \
         resolved target — this is the B3 regression tripwire"
    );

    // Control: the key's real path is flagged identically, proving the
    // indirection no longer changes the outcome.
    let direct = ToolCallType::FileRead {
        path: secret.to_string_lossy().into_owned(),
    }
    .resolve_paths();
    let d2 = proxy.evaluate(&ctx(direct, Uuid::new_v4())).await;
    assert!(any_matched(&d2), "the secret's real path must be flagged");
    assert_eq!(
        d.composite_score, d2.composite_score,
        "laundered and direct reads must score identically"
    );
}

/// `..` traversal is the other half of the same hole.
#[tokio::test]
async fn parent_traversal_is_collapsed_before_filtering() {
    let proxy = proxy_with(Box::new(SensitivePathHeuristicFilter::new()));

    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("project");
    std::fs::create_dir(&sub).unwrap();
    let secret = dir.path().join("id_rsa");
    std::fs::write(&secret, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();

    let traversal = ToolCallType::FileRead {
        path: format!("{}/../id_rsa", sub.to_string_lossy()),
    }
    .resolve_paths();
    let d = proxy.evaluate(&ctx(traversal, Uuid::new_v4())).await;
    assert!(
        any_matched(&d),
        "a read reaching a private key via `..` must be flagged"
    );
}

/// Deleting a symlink must NOT be reported as deleting its target. Resolving
/// the final component for a no-follow syscall would be both a false positive
/// and a false audit record.
#[tokio::test]
async fn deleting_a_symlink_does_not_resolve_to_its_target() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("id_rsa");
    std::fs::write(&secret, "key").unwrap();
    let link = dir.path().join("notes.txt");
    std::os::unix::fs::symlink(&secret, &link).unwrap();

    let resolved = ToolCallType::FileDelete {
        path: link.to_string_lossy().into_owned(),
    }
    .resolve_paths();
    match resolved {
        ToolCallType::FileDelete { path } => assert!(
            path.ends_with("notes.txt"),
            "unlink removes the link, not the target; got {path}"
        ),
        other => panic!("expected FileDelete, got {other:?}"),
    }
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

// ===========================================================================
// PROTECTION — link creation is scored by TARGET (go-live review B2).
//
// Link creation was entirely untrapped: `symlink`/`symlinkat`/`link`/`linkat`
// were absent from `SECURITY_RELEVANT`, so `ln -s ~/.ssh/id_rsa /tmp/x` was
// invisible and the subsequent read of `/tmp/x` carried an innocuous string.
// Trapping the creation makes the laundering step itself a decision point.
// ===========================================================================

#[tokio::test]
async fn symlink_to_private_key_is_flagged_by_target() {
    let proxy = proxy_with(Box::new(SensitivePathHeuristicFilter::new()));
    let d = proxy
        .evaluate(&ctx(
            ToolCallType::FileLink {
                target: "/home/u/.ssh/id_rsa".into(),
                link_path: "/tmp/notes.txt".into(),
                symbolic: true,
            },
            Uuid::new_v4(),
        ))
        .await;
    assert!(
        any_matched(&d),
        "a symlink pointing at a private key must be scored on its target, \
         not on the innocuous link name"
    );
}

#[tokio::test]
async fn hard_link_to_private_key_is_flagged_by_target() {
    let proxy = proxy_with(Box::new(SensitivePathHeuristicFilter::new()));
    let d = proxy
        .evaluate(&ctx(
            ToolCallType::FileLink {
                target: "/home/u/.ssh/id_rsa".into(),
                link_path: "/tmp/h".into(),
                symbolic: false,
            },
            Uuid::new_v4(),
        ))
        .await;
    assert!(
        any_matched(&d),
        "a hard link to a private key must be scored on its target"
    );
}

/// A link planted AT a protected location must not be cheaper than writing
/// that location directly. Scoring only the link target made
/// `ln -s ./mine ~/.ssh/authorized_keys` an Allow where the equivalent write
/// was a critical Queue — turning link creation into the preferred way to
/// plant a file. Both paths are judged now, and the worst verdict wins.
#[tokio::test]
async fn link_planted_at_a_protected_path_scores_like_the_write() {
    for protected in [
        "/home/u/.ssh/authorized_keys",
        "/home/u/.ssh/id_rsa",
        "/home/u/.bashrc",
    ] {
        let proxy = grith_tests::production_filter_registry();

        let write = proxy
            .evaluate(&ctx(
                ToolCallType::FileWrite {
                    path: protected.into(),
                    content_hash: String::new(),
                },
                Uuid::new_v4(),
            ))
            .await;
        let link = proxy
            .evaluate(&ctx(
                ToolCallType::FileLink {
                    target: "/home/u/project/mine".into(),
                    link_path: protected.into(),
                    symbolic: true,
                },
                Uuid::new_v4(),
            ))
            .await;

        assert!(
            link.composite_score >= write.composite_score,
            "planting a link at {protected} scored {} but writing it scored {} — \
             a link must never be the cheap substitute for a protected write",
            link.composite_score,
            write.composite_score
        );
    }
}

/// The same asymmetry through the noise fast path: a link whose *target* is a
/// noise path must not carry an arbitrary link path past the filters.
#[tokio::test]
async fn link_with_a_noise_target_still_scores_its_link_path() {
    let proxy = grith_tests::production_filter_registry();
    let d = proxy
        .evaluate(&ctx(
            ToolCallType::FileLink {
                target: "/proc/self/status".into(),
                link_path: "/home/u/.ssh/authorized_keys".into(),
                symbolic: true,
            },
            Uuid::new_v4(),
        ))
        .await;
    assert!(
        any_matched(&d),
        "a benign-looking target must not shield the link path from policy"
    );
}

/// FP guard: build systems and package managers create links constantly
/// (node_modules, cargo registry caches, `ln -s` in install scripts). An
/// ordinary in-project link must stay allowed, or B2 becomes a prompt flood.
#[tokio::test]
async fn benign_project_symlink_is_allowed() {
    let proxy = proxy_with(Box::new(OperationRiskFilter::new()));
    let d = proxy
        .evaluate(&ctx(
            ToolCallType::FileLink {
                target: "/home/u/project/dist/index.js".into(),
                link_path: "/home/u/project/node_modules/.bin/app".into(),
                symbolic: true,
            },
            Uuid::new_v4(),
        ))
        .await;
    assert!(
        matches!(d.action, ProxyAction::Allow),
        "an ordinary in-project link must be allowed: {:?}",
        d.action
    );
}
