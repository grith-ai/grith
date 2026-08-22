// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! work/83 — regression pins for the path-NAME false positives recorded in
//! `~/.local/share/grith/audit/audit.db` on 2026-08-20 (09:00–12:20 UTC).
//!
//! Every FP row below produced a modal prompt that froze a live supervised
//! session; together with the rest of the series they accounted for ~97% of
//! that morning's 1,986 queued calls. Every TP row is a real credential shape
//! that must keep its score.
//!
//! The harness loads the **shipped** `config/filters/paths.toml` and
//! `config/filters/meta_rules.toml` so a config edit that re-opens one of
//! these cannot pass CI.

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

/// The three path-NAME filters plus the shipped meta-rules — the exact stack
/// that decided every recorded row. Deliberately excludes the stateful Phase-3
/// filters (taint / rate-limit / behavioural), which are cold on a fresh
/// session and would only add noise to a name-matching pin.
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
    let mut c = ToolCallContext::new("test:fp83", call_type, session_id);
    c.session_scope = Some(SessionScopeKey::from_session_id(session_id));
    c.profile_name = Some("codex".into());
    c
}

async fn score(call_type: ToolCallType) -> ProxyDecision {
    name_rule_proxy().evaluate(&ctx(call_type)).await
}

fn read(path: &str) -> ToolCallType {
    ToolCallType::FileRead { path: path.into() }
}
fn write(path: &str) -> ToolCallType {
    ToolCallType::FileWrite {
        path: path.into(),
        content_hash: String::new(),
    }
}
fn mkdir(path: &str) -> ToolCallType {
    ToolCallType::DirCreate { path: path.into() }
}
fn hardlink(target: &str, link_path: &str) -> ToolCallType {
    ToolCallType::FileLink {
        target: target.into(),
        link_path: link_path.into(),
        symbolic: false,
    }
}

/// Did `rule_id` fire, from any filter?
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

/// The allow/queue boundary. `route_decision` routes on `score >
/// allow_threshold`, so a composite of exactly this value is ALLOWED — any
/// "must queue" assertion has to be strictly greater, never `>=`.
const QUEUE: f64 = 3.0;

// ---------------------------------------------------------------------------
// FALSE POSITIVES — each of these froze a live session. Must score < 3.0.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recorded_false_positives_stay_below_the_queue_threshold() {
    let repo = "/home/fp83user/projects/site";
    let cases: Vec<(&str, ToolCallType, &str)> = vec![
        // M1 — "authority" is not "auth"; .svg cannot be a credential store.
        (
            "hero svg",
            write(&format!(
                "{repo}/apps/web/public/hero-zero-ambient-authority-1600x900.svg"
            )),
            "secretish-filename",
        ),
        // M1 — documentation about tokens is not a token.
        (
            "docs mdx",
            write(&format!("{repo}/content/docs/concepts/canary-tokens.mdx")),
            "secretish-filename",
        ),
        // M1 — numbered schema migration.
        (
            "sql migration",
            write(&format!(
                "{repo}/packages/db/migrations/0016_better_auth_admin_two_factor.sql"
            )),
            "secretish-filename",
        ),
        // M1 + M5 — a rustc incremental hardlink whose random hash ends "auth".
        (
            "rustc hardlink",
            hardlink(
                &format!("{repo}/target/debug/deps/libx-9f1.rcgu.o"),
                &format!("{repo}/target/debug/incremental/x-0lrj/773v9mxq3ohs6twiwt1rzauth.o"),
            ),
            "secretish-filename",
        ),
        // M7 — the 277-prompts-in-87-seconds case: `/etc/*` matched
        // `node_modules/aria-query/lib/etc/roles/`.
        (
            "aria-query lib/etc write",
            write(&format!(
                "{repo}/node_modules/aria-query/lib/etc/roles/literal/alertdialogRole.js"
            )),
            "etc-system-write",
        ),
        (
            "aria-query lib/etc mkdir",
            mkdir(&format!("{repo}/node_modules/aria-query/lib/etc/roles")),
            "etc-system-write",
        ),
        // M8 — the npm package `cookies` (a Koa/Next dependency).
        (
            "node_modules/cookies mkdir",
            mkdir(&format!("{repo}/node_modules/cookies")),
            "browser-session-data",
        ),
        // F7 — a dependency tree names its own files.
        (
            "aws-sdk sso_credentials.js",
            write(&format!(
                "{repo}/node_modules/aws-sdk/lib/credentials/sso_credentials.js"
            )),
            "secretish-filename",
        ),
        (
            "aws-sdk secretsmanager.js",
            write(&format!(
                "{repo}/node_modules/aws-sdk/clients/secretsmanager.js"
            )),
            "secretish-filename",
        ),
        // M7 — a project-local `etc/` directory is not /etc.
        (
            "project etc/",
            write(&format!("{repo}/etc/config.yaml")),
            "etc-system-write",
        ),
        // Finding 1 — one filename must not be counted by two filters. The
        // duplicate is gone structurally: `secretish-filename` is the only
        // weak-name rule left, so 2.8 is the whole composite.
        (
            "bin/with-secrets read",
            read(&format!("{repo}/apps/web/bin/with-secrets")),
            "credential-file-shape", // incidental name, not a credential FILE
        ),
    ];

    for (label, call, must_not_fire) in cases {
        let decision = score(call).await;
        assert!(
            decision.composite_score < QUEUE,
            "{label}: must stay below QUEUE — {}",
            describe(&decision)
        );
        if !must_not_fire.is_empty() {
            assert!(
                !fired(&decision, must_not_fire),
                "{label}: rule `{must_not_fire}` must not fire — {}",
                describe(&decision)
            );
        }
    }
}

/// work/83 finding 1: the two de-weightings of the duplicated FILENAME signal
/// COMPOSED, and the composite landed below the boundary.
///
/// `path_match`'s `*secrets*` went 3.0 -> 1.5 **and** a `-1.5` meta-rule
/// subtracted again, so a READ of a Kubernetes Secret manifest scored exactly
/// 2.80 — which `route_decision` ALLOWS, because it routes on
/// `score > allow_threshold`. Nothing compensated: content scanning never sees
/// file bytes on a read, only syscall arguments.
///
/// The fix separates the classes instead of re-tuning a weight, and removes
/// the duplicate at the source: the weak `*credentials*` / `*secrets*` globs and
/// both `*-filename-single-signal` meta-rules are deleted, so exactly one rule
/// prices a filename.
#[tokio::test]
async fn a_credential_file_read_queues_and_an_incidental_name_does_not() {
    // The credential FILE shapes. A read must land STRICTLY above 3.0.
    for path in [
        "/home/fp83user/projects/site/deploy/secrets.yaml",
        "/home/fp83user/projects/site/deploy/secrets.yml",
        "/home/fp83user/projects/site/deploy/secrets.json",
        "/home/fp83user/projects/site/config/credentials.json",
        "/home/fp83user/projects/site/service-account-credentials.json",
    ] {
        let decision = score(read(path)).await;
        assert!(
            decision.composite_score > QUEUE,
            "{path}: a credential file read must QUEUE — {}",
            describe(&decision)
        );
        assert!(
            fired(&decision, "credential-file-shape"),
            "{path}: {}",
            describe(&decision)
        );
        // Priced ONCE: no second filter may add to the same filename.
        assert_eq!(
            decision.filter_results.iter().filter(|r| r.matched).count(),
            1,
            "{path}: one filename, one rule — {}",
            describe(&decision)
        );
    }

    // The recorded false positive: an extensionless wrapper script whose name
    // merely contains the word. Still allowed, and still on ONE rule.
    let decision = score(read(
        "/home/fp83user/projects/site/apps/web/bin/with-secrets",
    ))
    .await;
    assert!(
        fired(&decision, "secretish-filename"),
        "the weak rule still fires — {}",
        describe(&decision)
    );
    assert!(
        (decision.composite_score - 2.8).abs() < f64::EPSILON,
        "one filename must be priced once, not summed to 4.3 — {}",
        describe(&decision)
    );
}

// ---------------------------------------------------------------------------
// TRUE POSITIVES — real credential shapes. Must still reach QUEUE.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn credential_stores_still_queue() {
    let cases: Vec<(&str, ToolCallType, &str)> = vec![
        // Adversarial review: three plaintext stores the deleted weak
        // `*credentials*` glob was the ONLY thing scoring, plus the shadow
        // backup basename-anchoring dropped. Each needed an anchored LOCATION
        // rule, because a name-only signal cannot both clear the boundary here
        // and stay clear of the `bin/with-secrets` false positive below.
        (
            "cargo registry token store",
            read("/home/fp83user/.cargo/credentials.toml"),
            "cargo-credentials-store",
        ),
        (
            "git credential store (XDG location)",
            read("/home/fp83user/.config/git/credentials"),
            "git-credentials-store-xdg",
        ),
        (
            "shadow backup (same password hashes)",
            read("/etc/shadow-"),
            "etc-shadow",
        ),
        (
            "aws credentials (home)",
            read("/home/fp83user/.aws/credentials"),
            "aws-credentials",
        ),
        // Anchoring `~/` to the process $HOME alone would have stopped scoring
        // this — a protection regression, not a narrowing.
        (
            "aws credentials (root)",
            read("/root/.aws/credentials"),
            "aws-credentials",
        ),
        (
            "ssh private key",
            read("/home/fp83user/.ssh/id_rsa"),
            "ssh-private-key",
        ),
        // work/83 finding 5: a container / service home, and a path carrying
        // `//` or `/./`. `home_relative` recognised neither, so a `~/`-anchored
        // rule stopped matching and an auto-DENY fell to a QUEUE.
        (
            "ssh private key (service home)",
            read("/var/lib/svc/.ssh/id_rsa"),
            "ssh-private-key",
        ),
        (
            "ssh private key (double separator)",
            read("/home/fp83user//.ssh/id_rsa"),
            "ssh-private-key",
        ),
        (
            "ssh private key (dot component)",
            read("/home/fp83user/./.ssh/id_rsa"),
            "ssh-private-key",
        ),
        (
            "aws credentials (service home)",
            read("/var/lib/svc/.aws/credentials"),
            "aws-credentials",
        ),
        (
            "gcloud credentials (container home)",
            read("/opt/app/.config/gcloud/credentials.db"),
            "gcloud-config",
        ),
        (
            "project .env read",
            read("/home/fp83user/projects/site/.env"),
            "env-file",
        ),
        (
            "project .env write",
            write("/home/fp83user/projects/site/.env"),
            "env-file",
        ),
        (
            ".env.production",
            read("/home/fp83user/projects/site/.env.production"),
            "env-file-variants",
        ),
        (
            "/etc/nginx write",
            write("/etc/nginx/nginx.conf"),
            "etc-system-write",
        ),
        ("/etc/shadow read", read("/etc/shadow"), "etc-shadow"),
        // work/83 finding 3: Terraform writes this on every apply and it holds
        // the same plaintext provider credentials as the state file. `*.tfstate`
        // is anchored at the end of the basename, so it matched NO rule until
        // one closed backup suffix was stripped first.
        (
            "terraform state backup",
            read("/home/fp83user/projects/site/terraform.tfstate.backup"),
            "terraform-state",
        ),
        (
            "terraform state",
            read("/home/fp83user/projects/site/terraform.tfstate"),
            "terraform-state",
        ),
        // work/83 finding 4: the copy-out half of a session-hijack chain. A
        // freshly copied `Cookies` has no profile path and no siblings, and the
        // READ half is already noise-suppressed at the supervisor, so requiring
        // location evidence on the WRITE left the chain producing no scored
        // event at all.
        (
            "cookies copied out (write)",
            write("/home/fp83user/Downloads/Cookies"),
            "browser-session-data",
        ),
        (
            "wallet removed (delete)",
            ToolCallType::FileDelete {
                path: "/home/fp83user/wallet".into(),
            },
            "browser-session-data",
        ),
        (
            "chrome profile cookies",
            read("/home/fp83user/.config/google-chrome/Default/Cookies"),
            "browser-session-data",
        ),
        (
            "firefox key4.db out of profile",
            read("/home/fp83user/Downloads/key4.db"),
            "browser-session-data",
        ),
        // Anchoring `*credentials*` to the basename AND de-weighting it to 1.5
        // would together have dropped a plaintext credential store from QUEUE
        // to ALLOW — it only ever scored 3.0 because the glob matched the whole
        // path as a substring. It has an explicit rule now.
        (
            "git credential store",
            read("/home/fp83user/.git-credentials"),
            "git-credentials-store",
        ),
        // Anchoring `*.pem` / `*.key` to the basename removed the only rule
        // that scored a backed-up private key; `key-material-file` strips one
        // closed backup suffix to restore it.
        (
            "backed-up private key",
            read("/home/fp83user/projects/site/certs/server.pem.bak"),
            "key-material-file",
        ),
        (
            "rotated private key",
            read("/home/fp83user/projects/site/certs/tls.key.old"),
            "key-material-file",
        ),
    ];

    for (label, call, rule_id) in cases {
        let decision = score(call).await;
        assert!(
            decision.composite_score > QUEUE,
            "{label}: must still QUEUE — {}",
            describe(&decision)
        );
        assert!(
            fired(&decision, rule_id),
            "{label}: rule `{rule_id}` must fire — {}",
            describe(&decision)
        );
    }
}

/// The name-token rule keeps firing on genuine credential-file shapes, and a
/// WRITE to one still QUEUEs on the strength of that rule alone.
///
/// The band matters here, not just the rule: `route_decision` routes on
/// `score > allow_threshold`, so a composite of exactly 3.0 is ALLOWED (346
/// calls scored exactly 3.0 in the recorded session, every one allowed). That
/// is why the write score stays at 3.5 — 3.5 + the +0.5 write baseline = 4.0,
/// clear of the boundary, where work/83 F1.3's proposed 2.5 would have landed
/// on 3.0 and silently demoted every credential write to ALLOW.
#[tokio::test]
async fn credential_shaped_names_still_fire_the_token_rule() {
    // Structured credential FILE shapes (`secrets.yaml`,
    // `service-account-credentials.json`) are pinned by
    // `a_credential_file_read_queues_and_an_incidental_name_does_not` — they
    // fire the stronger `credential-file-shape` rule instead.
    for path in [
        "/home/fp83user/projects/site/auth.json",
        "/home/fp83user/projects/site/backups/secrets_dump.sql",
        "/home/fp83user/projects/site/config/api-token.txt",
    ] {
        let decision = score(read(path)).await;
        assert!(
            fired(&decision, "secretish-filename"),
            "{path}: token rule must fire — {}",
            describe(&decision)
        );

        // A WRITE to the same path must land strictly above the boundary.
        let decision = score(write(path)).await;
        assert!(
            fired(&decision, "secretish-filename"),
            "{path}: token rule must fire on write — {}",
            describe(&decision)
        );
        assert!(
            decision.composite_score > QUEUE,
            "{path}: a credential-shaped write must QUEUE, and `> QUEUE` is the \
             real bar because exactly 3.0 allows — {}",
            describe(&decision)
        );
    }
}

/// F7's gate is scoped to path-NAME rules. A dependency tree gets no relief
/// from a rule that keys on the credential class itself.
#[tokio::test]
async fn dependency_tree_gate_never_covers_a_real_credential_store() {
    let repo = "/home/fp83user/projects/site";
    for (path, rule_id) in [
        (
            format!("{repo}/node_modules/evil/.env"),
            "env-file-heuristic",
        ),
        (
            format!("{repo}/node_modules/evil/id_rsa"),
            "key-material-file",
        ),
        (
            format!("{repo}/target/debug/build/x/out/private.pem"),
            "key-material-file",
        ),
    ] {
        let decision = score(read(&path)).await;
        assert!(
            decision.composite_score > QUEUE,
            "{path}: must still QUEUE — {}",
            describe(&decision)
        );
        assert!(
            fired(&decision, rule_id),
            "{path}: rule `{rule_id}` must fire — {}",
            describe(&decision)
        );
    }
    // A postinstall reaching OUT of the tree at a real credential store is
    // scored exactly as it would be anywhere else.
    let decision = score(read("/home/fp83user/.ssh/id_rsa")).await;
    assert!(
        fired(&decision, "ssh-private-key"),
        "{}",
        describe(&decision)
    );
}
