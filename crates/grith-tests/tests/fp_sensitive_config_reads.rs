// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! False-positive prevention — family 4.5 (benign sensitive-LOOKING config
//! reads), covering FP research §5.6 (`/etc` two-tier) and §5.7 (`.env`
//! template carveout).
//!
//! These run the real `SensitivePathHeuristicFilter` (its rules are hardcoded,
//! not config-driven, so `::new()` is production-faithful) through a
//! `SecurityProxy` and assert the COMPOSITE routing decision — the direct
//! definition of an FP: a benign op scoring ≥ 3.0 (QUEUE). Each accept set is
//! paired with a guard set proving the relaxation did not widen into a
//! protection hole.

use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::sensitive_path::SensitivePathHeuristicFilter;
use grith_proxy::filters::FilterRegistry;
use grith_proxy::meta_rules::MetaRuleEngine;
use grith_proxy::scoring::ScoringConfig;
use grith_proxy::types::{ProxyAction, ToolCallContext, ToolCallType};
use uuid::Uuid;

/// Proxy with ONLY the sensitive-path filter, so the composite score is exactly
/// that filter's contribution and the routing decision is unambiguous.
fn sensitive_path_proxy() -> SecurityProxy {
    let mut registry = FilterRegistry::new();
    registry.register(Box::new(SensitivePathHeuristicFilter::new()));
    SecurityProxy::new(
        registry,
        ScoringConfig::default(),
        MetaRuleEngine::new(vec![]),
    )
}

fn ctx(call_type: ToolCallType) -> ToolCallContext {
    ToolCallContext::new("test", call_type, Uuid::new_v4())
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

async fn assert_allowed(proxy: &SecurityProxy, call: ToolCallType) {
    let label = format!("{call:?}");
    let d = proxy.evaluate(&ctx(call)).await;
    assert!(
        matches!(d.action, ProxyAction::Allow),
        "{label} must be ALLOWED (benign), got {:?} @ score {}",
        d.action,
        d.composite_score
    );
    assert!(
        d.composite_score < 3.0,
        "{label} must score below QUEUE (3.0), got {}",
        d.composite_score
    );
}

/// Guard assertion. The FP research defines an FP as a benign op scoring
/// **≥ 3.0**, so a *sensitive* op must score ≥ 3.0 — that is the invariant the
/// guard protects. We assert the composite band directly rather than the
/// routing action: the proxy routes with a strict `>` at the 3.0 boundary
/// (`scoring.rs`), so a single filter contributing exactly 3.0 routes to Allow
/// in isolation; production crosses the boundary via the additional filters
/// (operation_risk, taint, …) that are out of scope for this filter-isolated
/// test. The sensitive-band score is what this filter controls.
async fn assert_in_sensitive_band(proxy: &SecurityProxy, call: ToolCallType) {
    let label = format!("{call:?}");
    let d = proxy.evaluate(&ctx(call)).await;
    assert!(
        d.composite_score >= 3.0,
        "{label} must stay in the sensitive band (>= 3.0), got {}",
        d.composite_score
    );
}

// ---------------------------------------------------------------------------
// §5.7 — .env template scaffolding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn env_template_files_are_allowed() {
    let proxy = sensitive_path_proxy();
    for p in [
        "/home/u/project/.env.example",
        "/home/u/project/.env.sample",
        "/home/u/project/.env.template",
        "/home/u/project/.env.dist",
        "/home/u/project/.env.defaults",
    ] {
        assert_allowed(&proxy, read(p)).await;
    }
}

#[tokio::test]
async fn real_env_files_stay_in_sensitive_band() {
    let proxy = sensitive_path_proxy();
    // Guard: bare .env and environment-specific variants routinely hold REAL
    // secrets and must stay sensitive (Open Question #7).
    for p in [
        "/home/u/project/.env",
        "/home/u/project/.env.production",
        "/home/u/project/.env.local",
        "/home/u/project/.env.development",
        "/home/u/project/.env.test",
    ] {
        assert_in_sensitive_band(&proxy, read(p)).await;
    }
}

// ---------------------------------------------------------------------------
// §5.6 — /etc two-tier
// ---------------------------------------------------------------------------

#[tokio::test]
async fn generic_etc_app_config_reads_are_allowed() {
    let proxy = sensitive_path_proxy();
    for p in [
        "/etc/hosts",
        "/etc/nginx/nginx.conf",
        "/etc/docker/daemon.json",
        "/etc/postgresql/15/main/postgresql.conf",
        "/etc/redis/redis.conf",
        "/etc/pip.conf",
        "/etc/my.cnf",
    ] {
        assert_allowed(&proxy, read(p)).await;
    }
}

#[tokio::test]
async fn secret_etc_reads_and_etc_writes_stay_in_sensitive_band() {
    let proxy = sensitive_path_proxy();
    // Guard 1: genuinely-secret /etc paths stay high tier. The second group
    // (kubeconfigs / wifi PSKs / service admin creds) was added after an
    // adversarial review found they had dropped to the +0.5 low tier.
    for p in [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d/90-custom",
        "/etc/ssl/private/server.key",
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/krb5.keytab",
        // review-hardening group:
        "/etc/kubernetes/admin.conf",
        "/etc/rancher/k3s/k3s.yaml",
        "/etc/wpa_supplicant/wpa_supplicant.conf",
        "/etc/NetworkManager/system-connections/home-wifi.nmconnection",
        "/etc/grafana/grafana.ini",
        "/etc/gitlab/gitlab-secrets.json",
        "/etc/mysql/debian.cnf",
    ] {
        assert_in_sensitive_band(&proxy, read(p)).await;
    }
    // Guard 2: a WRITE to a generic /etc config is a system modification and
    // stays elevated (the §5.6 relaxation is read-only).
    assert_in_sensitive_band(&proxy, write("/etc/nginx/nginx.conf")).await;
}

// ---------------------------------------------------------------------------
// §5.5 — package-manager installs to PATH dirs (only PATH-shadows flagged)
// ---------------------------------------------------------------------------

/// Installing a NEW binary (one that does not collide with a system command)
/// into a PATH directory is routine `pip install --user` / `cargo install` /
/// `npm i -g` and must not be flagged — the blanket persistence sensitivity was
/// replaced (§5.5) by a PATH-shadow signal that fires only on collisions.
#[tokio::test]
async fn package_manager_installs_new_binaries_are_allowed() {
    let proxy = sensitive_path_proxy();
    for p in [
        "/home/u/.local/bin/black",
        "/home/u/.local/bin/ruff",
        "/home/u/.local/bin/poetry",
        "/home/u/.local/bin/tsc",
        "/usr/local/bin/myapp",
        "/usr/local/bin/terraform",
    ] {
        assert_allowed(&proxy, write(p)).await;
    }
}

/// Paired guard: a write whose basename SHADOWS a system command
/// (`~/.local/bin/git`, `/usr/local/bin/curl`) is a PATH-hijack and stays
/// flagged; and autostart/cron paths stay flagged regardless of name.
#[tokio::test]
async fn path_shadow_and_autostart_writes_stay_flagged() {
    let proxy = sensitive_path_proxy();
    for p in [
        "/home/u/.local/bin/git",    // shadows /usr/bin/git
        "/usr/local/bin/curl",       // shadows curl
        "/home/u/.local/bin/python", // shadows python
        "/usr/local/bin/sudo",       // shadows sudo
    ] {
        assert_in_sensitive_band(&proxy, write(p)).await;
    }
    // Autostart/cron: any file is a persistence entry regardless of name.
    for p in [
        "/home/u/.config/systemd/user/x.service",
        "/etc/cron.d/x",
        "/home/u/.config/autostart/x.desktop",
    ] {
        assert_in_sensitive_band(&proxy, write(p)).await;
    }
}
