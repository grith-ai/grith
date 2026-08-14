// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! False-positive RATE gate (FP research §6.5) — replays a benign developer-
//! workflow corpus through the production-fidelity filter registry
//! (`production_filter_registry`, loading the real `config/filters/*.toml`) and
//! asserts the FP rate.
//!
//! An FP = a benign op scoring ≥ 3.0 (QUEUE/DENY). Two assertions:
//!   * the FIXED-vector corpus (the workflows the FP suite addressed) must be
//!     **0 FP** end-to-end through the full registry — proving the per-filter
//!     fixes hold when all filters run together; and
//!   * the aggregate FP count is pinned to an explicit number so it cannot grow
//!     silently (the doc's §6.5 requirement). As held items land (§5.11 secret-
//!     scan carveouts), that number drops.

use grith_tests::{production_filter_registry, ProxyAction, ToolCallType};
use uuid::Uuid;

fn read(p: &str) -> ToolCallType {
    ToolCallType::FileRead { path: p.into() }
}
fn write(p: &str) -> ToolCallType {
    ToolCallType::FileWrite {
        path: p.into(),
        content_hash: String::new(),
    }
}
fn spawn(cmd: &str, args: &[&str]) -> ToolCallType {
    ToolCallType::ProcessSpawn {
        command: cmd.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
    }
}
fn shell(cmd: &str) -> ToolCallType {
    ToolCallType::ShellExec {
        command: cmd.into(),
        args: vec![],
    }
}
fn http(url: &str) -> ToolCallType {
    ToolCallType::HttpRequest {
        method: "GET".into(),
        url: url.into(),
    }
}
fn dns(domain: &str) -> ToolCallType {
    ToolCallType::DnsQuery {
        domain: domain.into(),
        query_type: "A".into(),
    }
}

/// (family, label, call). Each is a routine benign developer operation that
/// must NOT QUEUE under the shipped config + FP fixes.
fn fixed_vector_corpus() -> Vec<(&'static str, &'static str, ToolCallType)> {
    vec![
        // builds & compilers
        (
            "builds",
            "read Cargo.toml",
            read("/home/u/project/Cargo.toml"),
        ),
        (
            "builds",
            "read package.json",
            read("/home/u/project/package.json"),
        ),
        (
            "builds",
            "write build object",
            write("/home/u/project/target/debug/build/app.o"),
        ),
        (
            "builds",
            "write incremental",
            write("/home/u/project/target/debug/incremental/x.bin"),
        ),
        (
            "builds",
            "rustc spawn",
            spawn(
                "/home/u/.rustup/toolchains/stable/bin/rustc",
                &["--crate-name", "app", "-C", "incremental=/tmp/t"],
            ),
        ),
        // package managers (§5.2 / §5.4 / §5.5)
        ("pkg", "npm install", spawn("/usr/bin/npm", &["install"])),
        (
            "pkg",
            "pip install pkg",
            spawn("/usr/bin/pip", &["install", "requests"]),
        ),
        ("pkg", "cargo build", spawn("/usr/bin/cargo", &["build"])),
        (
            "pkg",
            "install new bin ~/.local/bin",
            write("/home/u/.local/bin/black"),
        ),
        (
            "pkg",
            "install new bin /usr/local/bin",
            write("/usr/local/bin/terraform"),
        ),
        // version control (§5.3 / §5.6)
        ("vcs", "git status", shell("git status --porcelain")),
        ("vcs", "git diff", shell("git diff")),
        (
            "vcs",
            "read .git/config",
            read("/home/u/project/.git/config"),
        ),
        (
            "vcs",
            "write .git/index",
            write("/home/u/project/.git/index"),
        ),
        // language runtimes
        (
            "runtime",
            "python run",
            spawn("/usr/bin/python3", &["app.py"]),
        ),
        (
            "runtime",
            "node run",
            spawn("/usr/bin/node", &["server.js"]),
        ),
        (
            "runtime",
            "read site-packages",
            read("/usr/lib/python3.11/site-packages/requests/__init__.py"),
        ),
        // sensitive-LOOKING config reads (§5.6 / §5.7)
        ("config", "read /etc/nginx", read("/etc/nginx/nginx.conf")),
        (
            "config",
            "read /etc/docker daemon",
            read("/etc/docker/daemon.json"),
        ),
        (
            "config",
            "read .env.example",
            read("/home/u/project/.env.example"),
        ),
        ("config", "read pip.conf", read("/etc/pip.conf")),
        // legitimate network (§5.3 / §5.4 / §5.9)
        (
            "net",
            "curl trusted | sh",
            spawn(
                "/usr/bin/curl",
                &["-fsSL", "https://github.com/cli/cli/releases"],
            ),
        ),
        (
            "net",
            "http anthropic",
            http("https://api.anthropic.com/v1/messages"),
        ),
        (
            "net",
            "http openai",
            http("https://api.openai.com/v1/models"),
        ),
        (
            "net",
            "http pypi",
            http("https://pypi.org/simple/requests/"),
        ),
        (
            "net",
            "dns lookup",
            dns("some-service.internal.example.com"),
        ),
        // routine admin (§5.10)
        ("admin", "sudo apt-get update", shell("sudo apt-get update")),
        (
            "admin",
            "sudo systemctl restart",
            shell("sudo systemctl restart nginx"),
        ),
        ("admin", "crontab -l", shell("crontab -l")),
        ("admin", "systemctl status", shell("systemctl status sshd")),
        // high-frequency churn
        ("churn", "write cache", write("/home/u/.cache/app/blob.bin")),
        (
            "churn",
            "write git object",
            write("/home/u/project/.git/objects/ab/cdef"),
        ),
        (
            "churn",
            "write pyc",
            write("/home/u/project/__pycache__/mod.cpython-311.pyc"),
        ),
    ]
}

/// Known-residual benign ops that DO still score under the shipped config.
/// These are honest residuals (NOT cherry-pickable away) surfaced by an
/// adversarial review of the corpus — kept in the gate so it reports the true
/// FP rate rather than a curated 0%. Each is pinned by identity in
/// `EXPECTED_RESIDUAL_FPS` so a regression that swaps one for another is caught.
///
/// Classes:
///   * `net-untrusted` — first egress to a benign host NOT in `trusted_domains`
///     (huggingface/stripe/internal services). +3.5 unknown-destination. Inherent
///     to review-mode egress + `cold_start_calls=0`; mitigations are reputation
///     warm-up, per-profile `profile_trusted_domains`, or enabling cold-start
///     (all out of scope / deferred — see §5.3 / §1.2).
///   * `cred-read` — reading a tool's own credential-adjacent config
///     (`~/.aws/config` [not credentials], `~/.docker/config.json`). Broad
///     credential-path rules. A future config-vs-credentials split (§5.x) would
///     carve these.
///   * `test-fixture` — reading a `.pem`/key test fixture. The §4.7 secret-scan-
///     false-match class (§5.11-HELD).
///   * `secret-scan` — `git show <40-hex-sha>`: FORMERLY base64-chunking on the
///     hex run. Carved by W2 (2026-08-06) — shape scoring on a ShellExec/
///     ProcessSpawn now requires an untrusted destination, so a bare SHA arg
///     with no egress target no longer FPs. Kept in the corpus, verified non-FP.
fn known_residual_corpus() -> Vec<(&'static str, &'static str, ToolCallType)> {
    vec![
        // benign egress to non-pre-trusted hosts (the dominant real FP class)
        (
            "net-untrusted",
            "http huggingface",
            http("https://huggingface.co/api/models"),
        ),
        (
            "net-untrusted",
            "http stripe api",
            http("https://api.stripe.com/v1/charges"),
        ),
        (
            "net-untrusted",
            "http internal svc",
            http("https://artifacts.corp.internal/repo"),
        ),
        // credential-adjacent config reads
        (
            "cred-read",
            "read ~/.aws/config",
            read("/home/u/.aws/config"),
        ),
        (
            "cred-read",
            "read ~/.docker/config.json",
            read("/home/u/.docker/config.json"),
        ),
        // test-fixture key material
        (
            "test-fixture",
            "read fixture .pem",
            read("/home/u/project/tests/fixtures/server.pem"),
        ),
        // secret-scan content signals (§5.11-HELD)
        (
            "secret-scan",
            "read package-lock.json",
            read("/home/u/project/package-lock.json"),
        ),
        (
            "secret-scan",
            "git show sha",
            shell("git show 5f2e8a1c9b3d4e6f7a8b9c0d1e2f3a4b5c6d7e8f:src/main.rs"),
        ),
    ]
}

/// Identity pin (FP-3 review): the EXACT set of `family/label` ops that are
/// expected to FP. Asserting the identity (not just the count) catches a
/// regression that swaps one residual for another. Update deliberately when a
/// carveout lands (a residual leaves the set) or a new residual is accepted.
const EXPECTED_RESIDUAL_FPS: &[&str] = &[
    "net-untrusted/http huggingface",
    "net-untrusted/http stripe api",
    "net-untrusted/http internal svc",
    "cred-read/read ~/.aws/config",
    "cred-read/read ~/.docker/config.json",
    "test-fixture/read fixture .pem",
    // W2 (2026-08-06): `git show <sha>` no longer FPs — egress-policy now
    // shape-scores a ShellExec/ProcessSpawn only when it targets an untrusted
    // *destination*, so a bare hex SHA arg with no egress target no longer trips
    // base64-chunking. The scenario stays in the corpus (verified non-FP).
];

async fn count_fps(corpus: &[(&str, &str, ToolCallType)]) -> Vec<(String, String, f64, String)> {
    let proxy = production_filter_registry();
    let mut fps = Vec::new();
    for (family, label, call) in corpus {
        // Fresh session per op so taint never accumulates across unrelated ops.
        let ctx = grith_tests::ToolCallContext::new("test", call.clone(), Uuid::new_v4());
        let d = proxy.evaluate(&ctx).await;
        let queued = !matches!(d.action, ProxyAction::Allow) || d.composite_score >= 3.0;
        if queued {
            let rule = d
                .filter_results
                .iter()
                .filter(|r| r.matched)
                .map(|r| format!("{}:{}", r.filter_name, r.rule_id))
                .collect::<Vec<_>>()
                .join(",");
            fps.push((
                format!("{family}/{label}"),
                rule,
                d.composite_score,
                format!("{:?}", d.action),
            ));
        }
    }
    fps
}

#[tokio::test]
async fn fixed_vector_corpus_is_zero_fp() {
    let corpus = fixed_vector_corpus();
    let total = corpus.len();
    let fps = count_fps(&corpus).await;
    if !fps.is_empty() {
        eprintln!(
            "UNEXPECTED FPs in the fixed-vector corpus ({}/{}):",
            fps.len(),
            total
        );
        for (label, rule, score, action) in &fps {
            eprintln!("  {label}  score={score}  [{rule}]  {action}");
        }
    }
    assert!(
        fps.is_empty(),
        "the FP fixes must hold end-to-end through the full registry: {} FP / {} ops",
        fps.len(),
        total
    );
}

/// Identity-keyed pin (FP-3 review): the SET of ops that FP across the whole
/// corpus must EXACTLY equal `EXPECTED_RESIDUAL_FPS`. A count-only pin would
/// pass when one residual is fixed while a new FP appears; matching identities
/// catches that swap. A new FP fails here loudly with its rule_id.
#[tokio::test]
async fn residual_fps_match_pinned_identity() {
    use std::collections::BTreeSet;
    let mut all = fixed_vector_corpus();
    all.extend(known_residual_corpus());
    let total = all.len();
    let fps = count_fps(&all).await;
    eprintln!(
        "FP rate: {}/{} = {:.1}%",
        fps.len(),
        total,
        100.0 * fps.len() as f64 / total as f64
    );
    for (label, rule, score, action) in &fps {
        eprintln!("  FP: {label}  score={score}  [{rule}]  {action}");
    }
    let actual: BTreeSet<&str> = fps.iter().map(|(label, _, _, _)| label.as_str()).collect();
    let expected: BTreeSet<&str> = EXPECTED_RESIDUAL_FPS.iter().copied().collect();

    let unexpected: Vec<&&str> = actual.difference(&expected).collect();
    let resolved: Vec<&&str> = expected.difference(&actual).collect();
    assert!(
        unexpected.is_empty(),
        "NEW/unexpected FP(s) not in the pinned residual set: {unexpected:?} — a \
         regression or new over-fire. See stderr for rule_ids."
    );
    assert!(
        resolved.is_empty(),
        "pinned residual(s) NO LONGER FP: {resolved:?} — a carveout landed; remove \
         them from EXPECTED_RESIDUAL_FPS in this change."
    );
}

/// FP research §6.5: per-FAMILY gate. Every FIXED-vector family must be 0 FP
/// (stricter than aggregate so one broken ecosystem can't hide behind healthy
/// ones). Known-residual families are allowed exactly their pinned residual
/// count (derived from `EXPECTED_RESIDUAL_FPS`), so they're documented, not
/// silently tolerated.
#[tokio::test]
async fn per_family_fp_rate_under_threshold() {
    use std::collections::BTreeMap;
    let mut all = fixed_vector_corpus();
    all.extend(known_residual_corpus());

    // Allowed FP per family = how many pinned residuals live in that family.
    let mut allowed: BTreeMap<&str, usize> = BTreeMap::new();
    for id in EXPECTED_RESIDUAL_FPS {
        let family = id.split('/').next().unwrap_or(id);
        *allowed.entry(family).or_default() += 1;
    }

    let mut totals: BTreeMap<&str, usize> = BTreeMap::new();
    for (family, _, _) in &all {
        *totals.entry(family).or_default() += 1;
    }
    let mut fp_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let proxy = production_filter_registry();
    for (family, _label, call) in &all {
        let ctx = grith_tests::ToolCallContext::new("test", call.clone(), Uuid::new_v4());
        let d = proxy.evaluate(&ctx).await;
        if !matches!(d.action, ProxyAction::Allow) || d.composite_score >= 3.0 {
            *fp_counts.entry(family).or_default() += 1;
        }
    }

    for (family, total) in &totals {
        let fp = fp_counts.get(family).copied().unwrap_or(0);
        let allow = allowed.get(family).copied().unwrap_or(0);
        let rate = 100.0 * fp as f64 / *total as f64;
        eprintln!("family {family:>14}: {fp}/{total} = {rate:.0}% FP (allowed {allow})");
        assert!(
            fp <= allow,
            "family {family} regressed: {fp} FP (allowed {allow}) — see stderr"
        );
    }
}
