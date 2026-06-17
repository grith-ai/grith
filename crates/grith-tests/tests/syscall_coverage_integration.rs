// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! PR 6 Phase G — integration tests for the proxy-side scoring path
//! of category-2 (chown / mount / ptrace) and category-3 (namespace
//! primitives) syscalls.
//!
//! These tests exercise the proxy stack end-to-end (`SecurityProxy`
//! with `OperationRiskFilter` registered) against the new
//! ToolCallType variants. They verify the load-bearing contract:
//! each new category-2/category-3 ToolCallType scores +5.0 →
//! QUEUE-tier action.
//!
//! **Real-ptrace end-to-end coverage (G3–G9 from the work doc) is
//! intentionally deferred.** Writing a tracee that calls
//! `chown(2)`/`mount(2)`/`unshare(2)` and verifying the supervisor's
//! response end-to-end would require generalising
//! `crates/grith-supervisor/tests/ptrace_kernel_semantics_test.rs`'s
//! harness to drive arbitrary syscall sequences. The contract is
//! already covered by:
//!   - Unit tests in `event_handler.rs` for each hard-deny path
//!     (phase_a_* and phase_d_*).
//!   - Unit tests for the gate behaviour when categories are off
//!     (phase_f_category*_*).
//!   - This file's proxy-stack tests for category-2/3 scoring.
//!   - The existing `classify_error_denies_syscall_fail_closed`
//!     integration test, which proves the fail-closed mechanism
//!     that every new variant inherits.

use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::operation_risk::OperationRiskFilter;
use grith_proxy::filters::FilterRegistry;
use grith_proxy::meta_rules::MetaRuleEngine;
use grith_proxy::scoring::ScoringConfig;
use grith_proxy::types::{ProxyAction, ToolCallContext, ToolCallType};
use uuid::Uuid;

fn proxy_with_operation_risk() -> SecurityProxy {
    let mut registry = FilterRegistry::new();
    registry.register(Box::new(OperationRiskFilter::new()));
    SecurityProxy::new(
        registry,
        ScoringConfig::default(),
        MetaRuleEngine::new(vec![]),
    )
}

fn ctx(call: ToolCallType) -> ToolCallContext {
    ToolCallContext::new("test:pr6-integration", call, Uuid::new_v4())
}

// ---------------------------------------------------------------------------
// Category 2 — chown / mount / cross-process all score +5.0 → QUEUE
// ---------------------------------------------------------------------------

#[tokio::test]
async fn category2_chown_routes_to_queue() {
    let proxy = proxy_with_operation_risk();
    let decision = proxy
        .evaluate(&ctx(ToolCallType::OwnershipChange {
            target: "/etc/passwd".into(),
            new_uid: 1000,
            new_gid: 1000,
        }))
        .await;
    assert!(decision.composite_score >= 5.0);
    assert!(
        matches!(decision.action, ProxyAction::Queue { .. }),
        "expected QUEUE, got {:?}",
        decision.action
    );
}

#[tokio::test]
async fn category2_fchown_by_fd_routes_to_queue() {
    // fchown carries a resolved path when possible and a stable fd
    // placeholder otherwise.
    let proxy = proxy_with_operation_risk();
    let decision = proxy
        .evaluate(&ctx(ToolCallType::OwnershipChange {
            target: "<fd:3>".into(),
            new_uid: 0,
            new_gid: 0,
        }))
        .await;
    assert!(decision.composite_score >= 5.0);
    assert!(matches!(decision.action, ProxyAction::Queue { .. }));
}

#[tokio::test]
async fn category2_mount_routes_to_queue() {
    let proxy = proxy_with_operation_risk();
    let decision = proxy
        .evaluate(&ctx(ToolCallType::FilesystemMutation {
            op: "mount".into(),
            source: Some("/dev/sda1".into()),
            target: "/mnt/x".into(),
            fstype: Some("ext4".into()),
        }))
        .await;
    assert!(decision.composite_score >= 5.0);
    assert!(matches!(decision.action, ProxyAction::Queue { .. }));
}

#[tokio::test]
async fn category2_pivot_root_routes_to_queue() {
    let proxy = proxy_with_operation_risk();
    let decision = proxy
        .evaluate(&ctx(ToolCallType::FilesystemMutation {
            op: "pivotroot".into(),
            source: None,
            target: "/new-root".into(),
            fstype: None,
        }))
        .await;
    assert!(decision.composite_score >= 5.0);
    assert!(matches!(decision.action, ProxyAction::Queue { .. }));
}

#[tokio::test]
async fn category2_new_mount_api_routes_to_queue() {
    let proxy = proxy_with_operation_risk();
    let decision = proxy
        .evaluate(&ctx(ToolCallType::FilesystemMutation {
            op: "mountsetattr".into(),
            source: None,
            target: "/mnt/x".into(),
            fstype: None,
        }))
        .await;
    assert!(decision.composite_score >= 5.0);
    assert!(matches!(decision.action, ProxyAction::Queue { .. }));
}

#[tokio::test]
async fn category2_ptrace_routes_to_queue() {
    let proxy = proxy_with_operation_risk();
    let decision = proxy
        .evaluate(&ctx(ToolCallType::CrossProcessAccess {
            op: "ptrace".into(),
            target_pid: 9999,
        }))
        .await;
    assert!(decision.composite_score >= 5.0);
    assert!(matches!(decision.action, ProxyAction::Queue { .. }));
}

#[tokio::test]
async fn category2_process_vm_writev_routes_to_queue() {
    let proxy = proxy_with_operation_risk();
    let decision = proxy
        .evaluate(&ctx(ToolCallType::CrossProcessAccess {
            op: "processvmwritev".into(),
            target_pid: 9999,
        }))
        .await;
    assert!(decision.composite_score >= 5.0);
    assert!(matches!(decision.action, ProxyAction::Queue { .. }));
}

// ---------------------------------------------------------------------------
// Category 3 — unshare/setns score +5.0 → QUEUE when not carved out
// ---------------------------------------------------------------------------
//
// (The namespace_users carveout that short-circuits this evaluation
// is supervisor-side and tested in event_handler::tests. These tests
// verify the proxy-side path the supervisor *falls through to* when
// the carveout doesn't apply.)

#[tokio::test]
async fn category3_unshare_routes_to_queue() {
    let proxy = proxy_with_operation_risk();
    let decision = proxy
        .evaluate(&ctx(ToolCallType::NamespaceOp {
            syscall: "unshare".into(),
            flags: 0x1002_0000, // CLONE_NEWUSER | CLONE_NEWNS
        }))
        .await;
    assert!(decision.composite_score >= 5.0);
    assert!(matches!(decision.action, ProxyAction::Queue { .. }));
}

#[tokio::test]
async fn category3_setns_routes_to_queue() {
    let proxy = proxy_with_operation_risk();
    let decision = proxy
        .evaluate(&ctx(ToolCallType::NamespaceOp {
            syscall: "setns".into(),
            flags: 0,
        }))
        .await;
    assert!(decision.composite_score >= 5.0);
    assert!(matches!(decision.action, ProxyAction::Queue { .. }));
}

// ---------------------------------------------------------------------------
// G10 — Regression: existing io_uring + raw-socket hard-deny tests
// continue to pass. These live in
// `crates/grith-supervisor/tests/ptrace_kernel_semantics_test.rs`
// and aren't re-implemented here; this comment just records that
// the regression coverage exists and was confirmed green by the
// PR 6 Phase A / D commits (workspace test suite was green at
// 1988 → 1992 tests with no io_uring regressions).
// ---------------------------------------------------------------------------
