// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Security test suite: Supply Chain & Capability Enforcement
//!
//! Tests that the capability system correctly enforces plugin permissions.
//! Plugins must have explicit capability grants for the operations they
//! perform. Missing grants result in QUEUE or DENY decisions.

use grith_tests::{
    make_tool_call_context, AllowlistConfig, AllowlistFilter, ArgumentFilter, CapabilityFilter,
    CapabilityGrant, CommandFilter, FilterRegistry, MetaRuleEngine, PathMatchFilter, ProxyAction,
    ScoringConfig, SecretScanFilter, SecurityProxy, ToolCallContext, ToolCallType,
};

/// Build a SecurityProxy with specific capability grants and all other default filters.
///
/// Uses cold_start_calls=0 so thresholds are the normal allow=3.0, deny=8.0,
/// making it easier to reason about expected outcomes. The capability filter
/// assigns score 10.0 for missing capabilities, which > 8.0 = DENY.
fn make_proxy_with_capabilities(grants: Vec<CapabilityGrant>) -> SecurityProxy {
    let mut registry = FilterRegistry::new();

    // Phase 1: Static filters
    registry.register(Box::new(PathMatchFilter::new(
        grith_tests::default_path_rules(),
    )));
    registry.register(Box::new(AllowlistFilter::new(AllowlistConfig::default())));
    registry.register(Box::new(ArgumentFilter::new()));
    registry.register(Box::new(CapabilityFilter::new(grants)));

    // Phase 2: Pattern filters
    registry.register(Box::new(SecretScanFilter::new(
        grith_tests::default_secret_patterns(),
    )));
    registry.register(Box::new(CommandFilter::new(
        grith_tests::default_command_rules(),
    )));

    let scoring = ScoringConfig {
        auto_allow_threshold: 3.0,
        auto_deny_threshold: 8.0,
        cold_start_calls: 0, // Skip cold start for predictable thresholds
        cold_start_escalation_low: 2.0,
        cold_start_escalation_high: 10.0,
    };
    let meta_rules = MetaRuleEngine::new(vec![]);
    SecurityProxy::new(registry, scoring, meta_rules)
}

/// Create a ToolCallContext with a specific plugin_id.
fn make_plugin_context(
    plugin_id: &str,
    call_type: ToolCallType,
    args_json: serde_json::Value,
) -> ToolCallContext {
    let mut ctx = ToolCallContext::new(plugin_id, call_type, uuid::Uuid::new_v4());
    ctx.arguments = args_json;
    ctx
}

// ---------------------------------------------------------------------------
// Filesystem read capability tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_file_read_with_fs_read_capability_passes() {
    // Plugin "file-reader" has fs:read capability -- file read should be allowed.
    let proxy = make_proxy_with_capabilities(vec![CapabilityGrant {
        plugin: "file-reader".into(),
        capabilities: vec!["fs:read".into()],
    }]);
    let ctx = make_plugin_context(
        "file-reader",
        ToolCallType::FileRead {
            path: "/tmp/safe.txt".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert_eq!(
        decision.action,
        ProxyAction::Allow,
        "Plugin with fs:read should be allowed to read files"
    );
    // Verify capability filter did NOT match (no score contribution)
    assert!(
        !decision
            .filter_results
            .iter()
            .any(|r| r.matched && r.filter_name == "capability"),
        "Capability filter should not match for granted capability"
    );
}

// ---------------------------------------------------------------------------
// Shell execution without capability tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_shell_exec_without_shell_capability_denied() {
    // Plugin "file-reader" only has fs:read -- shell exec should be DENIED.
    // CapabilityFilter returns score 10.0 for missing capability.
    // 10.0 > 8.0 (deny threshold) = DENY.
    let proxy = make_proxy_with_capabilities(vec![CapabilityGrant {
        plugin: "file-reader".into(),
        capabilities: vec!["fs:read".into()],
    }]);
    let ctx = make_plugin_context(
        "file-reader",
        ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec!["-la".into()],
        },
        serde_json::json!({"command": "ls", "args": ["-la"]}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_denied(),
        "Shell exec without shell capability should be DENIED, got: {}",
        decision.action,
    );
    assert!(
        decision
            .filter_results
            .iter()
            .any(|r| r.matched && r.rule_id == "missing-capability"),
        "Expected missing-capability rule to match"
    );
}

// ---------------------------------------------------------------------------
// Network access without capability tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_http_request_without_network_capability_denied() {
    // Plugin "file-reader" only has fs:read -- HTTP request should be DENIED.
    let proxy = make_proxy_with_capabilities(vec![CapabilityGrant {
        plugin: "file-reader".into(),
        capabilities: vec!["fs:read".into()],
    }]);
    let ctx = make_plugin_context(
        "file-reader",
        ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://api.example.com/data".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_denied(),
        "HTTP request without net:http capability should be DENIED, got: {}",
        decision.action,
    );
    assert!(
        decision
            .filter_results
            .iter()
            .any(|r| r.matched && r.rule_id == "missing-capability"),
        "Expected missing-capability rule to match"
    );
}

// ---------------------------------------------------------------------------
// File write without write capability tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_file_write_without_write_capability_denied() {
    // Plugin "file-reader" only has fs:read -- file write should be DENIED.
    let proxy = make_proxy_with_capabilities(vec![CapabilityGrant {
        plugin: "file-reader".into(),
        capabilities: vec!["fs:read".into()],
    }]);
    let ctx = make_plugin_context(
        "file-reader",
        ToolCallType::FileWrite {
            path: "/tmp/output.txt".into(),
            content_hash: "abc123".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_denied(),
        "File write without fs:write capability should be DENIED, got: {}",
        decision.action,
    );
    assert!(
        decision
            .filter_results
            .iter()
            .any(|r| r.matched && r.rule_id == "missing-capability"),
        "Expected missing-capability rule to match"
    );
}

// ---------------------------------------------------------------------------
// Plugin with no capabilities tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_plugin_with_no_capabilities_all_denied() {
    // Plugin "no-caps" is registered but with empty capabilities.
    // Every operation should be denied due to missing capabilities.
    let proxy = make_proxy_with_capabilities(vec![CapabilityGrant {
        plugin: "no-caps".into(),
        capabilities: vec![],
    }]);

    // File read
    let ctx = make_plugin_context(
        "no-caps",
        ToolCallType::FileRead {
            path: "/tmp/safe.txt".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_denied(),
        "File read with no capabilities should be DENIED, got: {}",
        decision.action,
    );

    // Shell exec
    let ctx = make_plugin_context(
        "no-caps",
        ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec![],
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_denied(),
        "Shell exec with no capabilities should be DENIED, got: {}",
        decision.action,
    );

    // HTTP request
    let ctx = make_plugin_context(
        "no-caps",
        ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://example.com".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_denied(),
        "HTTP request with no capabilities should be DENIED, got: {}",
        decision.action,
    );

    // File write
    let ctx = make_plugin_context(
        "no-caps",
        ToolCallType::FileWrite {
            path: "/tmp/out.txt".into(),
            content_hash: "xyz".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_denied(),
        "File write with no capabilities should be DENIED, got: {}",
        decision.action,
    );
}

// ---------------------------------------------------------------------------
// Unknown plugin tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_unknown_plugin_denied() {
    // Plugin "rogue-plugin" is not registered at all in the grants.
    // The capability filter assigns score 10.0 for unknown plugins.
    let proxy = make_proxy_with_capabilities(vec![CapabilityGrant {
        plugin: "known-plugin".into(),
        capabilities: vec!["fs:read".into()],
    }]);
    let ctx = make_plugin_context(
        "rogue-plugin",
        ToolCallType::FileRead {
            path: "/tmp/safe.txt".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_denied(),
        "Unknown plugin should be DENIED, got: {}",
        decision.action,
    );
    assert!(
        decision
            .filter_results
            .iter()
            .any(|r| r.matched && r.rule_id == "unknown-plugin"),
        "Expected unknown-plugin rule to match"
    );
}

// ---------------------------------------------------------------------------
// Wildcard capability tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_wildcard_capability_allows_all_operations() {
    // Plugin "superuser" has wildcard "*" capability -- all operations pass
    // the capability filter.
    let proxy = make_proxy_with_capabilities(vec![CapabilityGrant {
        plugin: "superuser".into(),
        capabilities: vec!["*".into()],
    }]);

    // File read
    let ctx = make_plugin_context(
        "superuser",
        ToolCallType::FileRead {
            path: "/tmp/safe.txt".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_allowed(),
        "Wildcard plugin file read should be ALLOWED, got: {}",
        decision.action,
    );

    // Shell exec
    let ctx = make_plugin_context(
        "superuser",
        ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec!["-la".into()],
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_allowed(),
        "Wildcard plugin shell exec should be ALLOWED, got: {}",
        decision.action,
    );

    // HTTP request
    let ctx = make_plugin_context(
        "superuser",
        ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://api.example.com/data".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_allowed(),
        "Wildcard plugin HTTP request should be ALLOWED, got: {}",
        decision.action,
    );

    // File write
    let ctx = make_plugin_context(
        "superuser",
        ToolCallType::FileWrite {
            path: "/tmp/output.txt".into(),
            content_hash: "abc".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_allowed(),
        "Wildcard plugin file write should be ALLOWED, got: {}",
        decision.action,
    );

    // File delete
    let ctx = make_plugin_context(
        "superuser",
        ToolCallType::FileDelete {
            path: "/tmp/output.txt".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_allowed(),
        "Wildcard plugin file delete should be ALLOWED, got: {}",
        decision.action,
    );

    // Dir list
    let ctx = make_plugin_context(
        "superuser",
        ToolCallType::DirList {
            path: "/tmp/".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_allowed(),
        "Wildcard plugin dir list should be ALLOWED, got: {}",
        decision.action,
    );
}

// ---------------------------------------------------------------------------
// Multiple capability grants tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multiple_capabilities_selective_enforcement() {
    // Plugin "web-worker" has fs:read and net:http but NOT shell:exec or fs:write.
    let proxy = make_proxy_with_capabilities(vec![CapabilityGrant {
        plugin: "web-worker".into(),
        capabilities: vec!["fs:read".into(), "net:http".into()],
    }]);

    // File read -- ALLOWED (has fs:read)
    let ctx = make_plugin_context(
        "web-worker",
        ToolCallType::FileRead {
            path: "/tmp/data.json".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_allowed(),
        "web-worker file read should be ALLOWED, got: {}",
        decision.action,
    );

    // HTTP GET -- ALLOWED (has net:http)
    let ctx = make_plugin_context(
        "web-worker",
        ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://api.example.com/data".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_allowed(),
        "web-worker HTTP GET should be ALLOWED, got: {}",
        decision.action,
    );

    // Shell exec -- DENIED (no shell:exec)
    let ctx = make_plugin_context(
        "web-worker",
        ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec![],
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_denied(),
        "web-worker shell exec should be DENIED, got: {}",
        decision.action,
    );

    // File write -- DENIED (no fs:write)
    let ctx = make_plugin_context(
        "web-worker",
        ToolCallType::FileWrite {
            path: "/tmp/output.json".into(),
            content_hash: "xyz".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_denied(),
        "web-worker file write should be DENIED, got: {}",
        decision.action,
    );
}

// ---------------------------------------------------------------------------
// Capability enforcement combined with other filters
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_capability_plus_sensitive_path_cumulative_score() {
    // Plugin "no-caps" tries to read an SSH key file. Both the capability
    // filter (10.0) and path_match filter (5.0) should fire. But due to
    // early termination (10.0 > 8.0 = DENY after Phase 1), Phase 2 filters
    // won't run. The composite score should be at least 10.0.
    let proxy = make_proxy_with_capabilities(vec![CapabilityGrant {
        plugin: "no-caps".into(),
        capabilities: vec![],
    }]);
    let ctx = make_plugin_context(
        "no-caps",
        ToolCallType::FileRead {
            path: "/home/user/.ssh/id_rsa".into(),
        },
        serde_json::json!({}),
    );
    let decision = proxy.evaluate(&ctx).await;
    assert!(
        decision.is_denied(),
        "No-capability plugin reading SSH key should be DENIED, got: {}",
        decision.action,
    );
    assert!(
        decision.composite_score >= 10.0,
        "Expected composite score >= 10.0 from capability + path_match, got: {}",
        decision.composite_score,
    );
}

// ---------------------------------------------------------------------------
// Unconfigured capability filter (default TestFixtures) tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_default_fixtures_unconfigured_capability_is_permissive() {
    // The default TestFixtures uses CapabilityFilter::new(vec![]) which is
    // permissive -- no capability enforcement. This verifies the baseline.
    let fixtures = grith_tests::TestFixtures::new();
    let ctx = make_tool_call_context(
        ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec!["-la".into()],
        },
        serde_json::json!({"command": "ls", "args": ["-la"]}),
    );
    let decision = fixtures.proxy.evaluate(&ctx).await;
    assert!(
        decision.is_allowed(),
        "Unconfigured capability filter should not block safe commands, got: {}",
        decision.action,
    );
    // The capability filter should not have matched
    assert!(
        !decision
            .filter_results
            .iter()
            .any(|r| r.matched && r.filter_name == "capability"),
        "Capability filter should be permissive when unconfigured"
    );
}
