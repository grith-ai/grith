// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Regression pins for the traversal prompt-flood of 2026-09-02, recorded in
//! `~/.local/share/grith/audit/audit.db` (session
//! `f1697947-5ef5-409e-8124-250cee7d367b`, 22:01–00:27 UTC).
//!
//! A supervised agent ran `find /home/dan -maxdepth 4 -type d -name sqlglot`,
//! then the same over `/`. `find -type d` must `opendir()` every directory to
//! descend, so it opened every credential-shaped directory on the machine.
//! Each open arrived as a `FileRead`, scored 4.0 (`credential-directory`) —
//! 8.0 under `~/.aws/`, where `path-match:aws-credentials` charged 4.0 for the
//! same fact — queued, and froze the tracee for the full 300s review timeout.
//! 41 prompts in one session, every one auto-denied on timeout, and the
//! searches silently returned incomplete results.
//!
//! The harness loads the **shipped** `config/filters/paths.toml` and
//! `config/filters/meta_rules.toml`, so a config edit that re-opens this
//! cannot pass CI.

use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::destructive_action::DestructiveActionFilter;
use grith_proxy::filters::operation_risk::OperationRiskFilter;
use grith_proxy::filters::path_match::{PathMatchFilter, PathRule};
use grith_proxy::filters::sensitive_path::SensitivePathHeuristicFilter;
use grith_proxy::filters::FilterRegistry;
use grith_proxy::meta_rules::{MetaRule, MetaRuleEngine};
use grith_proxy::scoring::ScoringConfig;
use grith_proxy::types::{ProxyDecision, SessionScopeKey, ToolCallContext, ToolCallType};
use uuid::Uuid;

fn name_rule_proxy() -> SecurityProxy {
    #[derive(serde::Deserialize)]
    struct Rules {
        rules: Vec<PathRule>,
    }
    #[derive(serde::Deserialize)]
    struct Metas {
        meta_rules: Vec<MetaRule>,
    }
    let dir =
        std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/filters"));
    let read = |f: &str| {
        let p = dir.join(f);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    };
    let path_rules: Rules = toml::from_str(&read("paths.toml")).expect("paths.toml");
    let metas: Metas = toml::from_str(&read("meta_rules.toml")).expect("meta_rules.toml");

    let mut reg = FilterRegistry::new();
    reg.register(Box::new(OperationRiskFilter::with_routine_signal(false)));
    reg.register(Box::new(PathMatchFilter::new(path_rules.rules)));
    reg.register(Box::new(SensitivePathHeuristicFilter::new()));
    reg.register(Box::new(DestructiveActionFilter::new()));

    SecurityProxy::new(
        reg,
        ScoringConfig::default(),
        MetaRuleEngine::new(metas.meta_rules),
    )
}

fn ctx(call_type: ToolCallType) -> ToolCallContext {
    let session_id = Uuid::new_v4();
    let mut c = ToolCallContext::new("supervisor:claude", call_type, session_id);
    c.session_scope = Some(SessionScopeKey::from_session_id(session_id));
    c.profile_name = Some("claude-code".into());
    c
}

async fn score(call_type: ToolCallType) -> ProxyDecision {
    name_rule_proxy().evaluate(&ctx(call_type)).await
}

fn list(path: &str) -> ToolCallType {
    ToolCallType::DirList { path: path.into() }
}
fn read(path: &str) -> ToolCallType {
    ToolCallType::FileRead { path: path.into() }
}

fn fired(decision: &ProxyDecision, rule_id: &str) -> bool {
    decision
        .filter_results
        .iter()
        .any(|r| r.matched && r.rule_id == rule_id)
}

fn describe(decision: &ProxyDecision) -> String {
    let hits: Vec<String> = decision
        .filter_results
        .iter()
        .filter(|r| r.matched)
        .map(|r| format!("{}:{}={}", r.filter_name, r.rule_id, r.score))
        .collect();
    format!(
        "composite={} [{}]",
        decision.composite_score,
        hits.join(" ")
    )
}

/// `route_decision` routes on `score > allow_threshold`, so a composite of
/// exactly this value is ALLOWED. "Must queue" assertions are strictly greater.
const QUEUE: f64 = 3.0;

/// The directories `find` opened. Every one of these produced a prompt.
const TRAVERSED: &[&str] = &[
    "/home/dan/.gnupg/private-keys-v1.d",
    "/home/dan/.pki/nssdb",
    "/home/dan/.aws/login",
    "/home/dan/snap/spotify/97/.pki/nssdb",
    "/home/dan/.config/sunshine/credentials",
    "/home/dan/.docker/buildx",
    "/home/dan/.kube/cache",
    "/home/dan/.azure/logs",
    "/home/dan/.config/gcloud/logs",
];

#[tokio::test]
async fn a_directory_traversal_never_prompts() {
    for path in TRAVERSED {
        let decision = score(list(path)).await;
        assert!(
            decision.composite_score <= QUEUE,
            "walking {path} still prompts: {}",
            describe(&decision)
        );
    }
}

/// `~/.ssh` is the deliberate exception and stays one.
///
/// `ssh-dir` in `config/filters/paths.toml` is the only rule that scopes
/// itself to `list`, at 3.0/warning — knowing which keys and which hosts are
/// on a machine is the recon step operators specifically asked to see. This
/// change does not touch it: a traversal that descends into `~/.ssh/` still
/// prompts. It is cheaper than it was (3.5, down from 3.0 + 4.0 = 7.0),
/// because the read-priced rule no longer stacks on top, but it is still
/// above the band on purpose. Nothing in the 2026-09-02 incident hit this —
/// `find` listed `~/.ssh` itself, which is allowed, not anything under it.
#[tokio::test]
async fn listing_inside_ssh_still_prompts_deliberately() {
    let decision = score(list("/home/dan/.ssh/config.d")).await;
    assert!(
        decision.composite_score > QUEUE,
        "the ~/.ssh exception was lost: {}",
        describe(&decision)
    );
    assert!(fired(&decision, "ssh-dir"), "{}", describe(&decision));
    // `~/.ssh` itself is not under `~/.ssh/*` and was allowed throughout the
    // incident; that must not change either.
    let bare = score(list("/home/dan/.ssh")).await;
    assert!(
        bare.composite_score <= QUEUE,
        "listing ~/.ssh itself now prompts: {}",
        describe(&bare)
    );
}

/// The specific double charge that put `~/.aws/login` at 8.0 — one notch
/// under auto-deny — for what was only an `opendir`.
///
/// `config/filters/paths.toml` scopes the credential rules to
/// `operations = ["read", "write", "delete"]`, so classifying the open as the
/// enumeration it is takes `path-match` out of the picture without touching
/// the rules.
#[tokio::test]
async fn listing_an_aws_directory_is_not_charged_by_both_filters() {
    let decision = score(list("/home/dan/.aws/login")).await;
    assert!(
        !fired(&decision, "aws-credentials"),
        "path-match still charges a listing: {}",
        describe(&decision)
    );
    assert!(
        !fired(&decision, "credential-directory"),
        "the read-priced rule still fires on a listing: {}",
        describe(&decision)
    );
}

/// The listing is recorded, not discarded. Dropping it would blind the
/// behavioural and taint filters to credential-store reconnaissance.
#[tokio::test]
async fn the_listing_is_still_recorded() {
    let decision = score(list("/home/dan/.gnupg/private-keys-v1.d")).await;
    assert!(
        fired(&decision, "credential-directory-listing"),
        "the traversal left no trace: {}",
        describe(&decision)
    );
}

/// The downgrade is scoped to enumeration. Reading a file out of the same
/// directory is the act these rules exist for, and must still escalate.
#[tokio::test]
async fn reading_credentials_still_queues() {
    for path in [
        "/home/dan/.aws/credentials",
        "/home/dan/.aws/login/cache/abc123.json",
        "/home/dan/.gnupg/private-keys-v1.d/ABCDEF0123.key",
        "/home/dan/.ssh/id_rsa",
        "/home/dan/.docker/config.json",
        "/home/dan/.kube/config",
        "/home/dan/.config/gcloud/credentials.db",
    ] {
        let decision = score(read(path)).await;
        assert!(
            decision.composite_score > QUEUE,
            "reading {path} no longer escalates: {}",
            describe(&decision)
        );
    }
}

/// A listing of an ordinary project directory was never scored and still
/// is not — the change must not have moved the baseline.
#[tokio::test]
async fn ordinary_directories_are_untouched() {
    for path in [
        "/home/dan/projects/site/src",
        "/home/dan/projects/site/node_modules/js-tokens",
        "/usr/share/doc/base-passwd",
        "/snap/core24/1643/etc/sudoers.d",
    ] {
        let decision = score(list(path)).await;
        assert!(
            decision.composite_score <= QUEUE,
            "listing {path} prompts: {}",
            describe(&decision)
        );
    }
}
