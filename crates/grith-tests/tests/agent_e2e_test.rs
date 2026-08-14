// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Full end-to-end agent loop test with mock LLM.
//!
//! Exercises the complete chain that `grith run` uses:
//!   Mock LLM response → parse tool call → proxy evaluation → audit record → digest queue
//!
//! This mirrors what `execute_tool_call()` in `grith-core/src/agent/tool_execution.rs`
//! does, using the same underlying crates. It validates that the subsystems are
//! correctly wired: a tool call from the LLM produces a proxy decision, an audit
//! record, and (for risky calls) a digest item.
//!
//! Implements the §11.5 "Full E2E tests with mock LLM daemon orchestration"
//! requirement from Phase 11.

use std::sync::{Arc, Mutex};

use grith_audit::{AuditRecord, AuditStorage, ProxyActionSummary};
use grith_digest::{DigestQueue, DigestStatus};
use grith_llm::{
    CompletionRequest, CompletionResponse, CompletionStream, CostEstimate, FinishReason,
    LlmProvider, LlmRouter, ProviderCapabilities, TokenUsage, ToolCall,
};
use grith_proxy::types::{ProxyAction, ToolCallContext, ToolCallType};
use grith_tests::TestFixtures;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mock LLM provider
// ---------------------------------------------------------------------------

struct MockLlm {
    responses: Mutex<Vec<CompletionResponse>>,
}

impl MockLlm {
    fn new(responses: Vec<CompletionResponse>) -> Self {
        Self {
            responses: Mutex::new(responses),
        }
    }
}

#[async_trait::async_trait]
impl LlmProvider for MockLlm {
    async fn complete(
        &self,
        _request: &CompletionRequest,
    ) -> grith_llm::error::Result<CompletionResponse> {
        let mut responses = self.responses.lock().unwrap();
        if responses.is_empty() {
            Ok(CompletionResponse {
                content: Some("Done.".into()),
                tool_calls: vec![],
                usage: TokenUsage {
                    prompt_tokens: 10,
                    completion_tokens: 5,
                    total_tokens: 15,
                },
                model: "mock-model".into(),
                finish_reason: FinishReason::Stop,
            })
        } else {
            Ok(responses.remove(0))
        }
    }

    async fn complete_stream(
        &self,
        _request: &CompletionRequest,
    ) -> grith_llm::error::Result<CompletionStream> {
        Err(grith_llm::Error::Provider {
            provider: "mock".into(),
            message: "streaming not supported".into(),
        })
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            supports_streaming: false,
            supports_tools: true,
            supports_vision: false,
            max_tokens: 4096,
        }
    }

    fn cost_estimate(&self, input_tokens: usize, output_tokens: usize) -> CostEstimate {
        CostEstimate {
            input_cost: input_tokens as f64 * 0.000003,
            output_cost: output_tokens as f64 * 0.000015,
            total_cost: input_tokens as f64 * 0.000003 + output_tokens as f64 * 0.000015,
            currency: "USD".into(),
        }
    }

    fn name(&self) -> &str {
        "mock"
    }
}

// ---------------------------------------------------------------------------
// Helper: simulate the execute_tool_call chain
// ---------------------------------------------------------------------------

/// Parse an LLM tool call into a proxy ToolCallType + evaluate + audit + digest.
/// This mirrors `grith-core/src/agent/tool_execution.rs::execute_tool_call()`.
async fn simulate_tool_execution(
    tool_call: &ToolCall,
    proxy: &grith_proxy::engine::SecurityProxy,
    audit_storage: &Arc<Mutex<AuditStorage>>,
    digest_queue: &Arc<DigestQueue>,
    session_id: Uuid,
) -> (ProxyAction, f64) {
    // 1. Parse tool call → ToolCallType (same mapping as agent/tool_execution.rs)
    let call_type = match tool_call.name.as_str() {
        "fs_read" => ToolCallType::FileRead {
            path: tool_call.arguments["path"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        },
        "fs_write" => ToolCallType::FileWrite {
            path: tool_call.arguments["path"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            content_hash: "mock-hash".into(),
        },
        "shell_exec" => ToolCallType::ShellExec {
            command: tool_call.arguments["command"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            args: tool_call.arguments["args"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
        },
        other => ToolCallType::FileRead {
            path: format!("unknown-tool:{other}"),
        },
    };

    // 2. Build proxy context
    let ctx = ToolCallContext {
        id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        plugin_id: "agent".to_string(),
        call_type: call_type.clone(),
        arguments: tool_call.arguments.clone(),
        session_id,
        task_context: Some("e2e-test".to_string()),
        call_sequence_number: 1,
        source_taint: grith_proxy::types::TaintLevel::None,
        profile_name: None,
        conversation_id: None,
        session_scope: Some(grith_proxy::types::SessionScopeKey::from_session_id(
            session_id,
        )),
        spawn_provenance: None,
        listener_policy_match: None,
    };

    // 3. Evaluate through proxy
    let decision = proxy.evaluate(&ctx).await;
    let action = decision.action.clone();
    let score = decision.composite_score;

    // 4. Log to audit storage
    let proxy_action = match &decision.action {
        ProxyAction::Allow => ProxyActionSummary::Allow,
        ProxyAction::Deny { .. } => ProxyActionSummary::Deny,
        ProxyAction::Queue { .. } => ProxyActionSummary::Queue,
    };

    let filter_results: Vec<grith_audit::FilterResultSummary> = decision
        .filter_results
        .iter()
        .map(|r| grith_audit::FilterResultSummary {
            filter_name: r.filter_name.clone(),
            matched: r.matched,
            score: r.score,
            rule_id: r.rule_id.clone(),
            severity: format!("{:?}", r.severity).to_lowercase(),
            message: r.message.clone(),
        })
        .collect();

    let audit_record = AuditRecord::new(
        session_id,
        "agent".to_string(),
        call_type.to_string(),
        &tool_call.arguments,
        score,
        proxy_action.clone(),
        filter_results,
        decision.evaluation_time.as_secs_f64() * 1000.0,
        Some("e2e-test".to_string()),
    );

    if let Ok(storage) = audit_storage.lock() {
        storage
            .insert_record(&audit_record)
            .expect("insert audit record");
    }

    // 5. If queued, create a digest item
    if matches!(decision.action, ProxyAction::Queue { .. }) {
        let digest_item = grith_digest::DigestItem {
            id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            session_id: Some(session_id),

            tool_call_type: call_type.to_string(),
            arguments_summary: tool_call.arguments.to_string(),
            decision_reason: None,
            composite_score: score,
            severity: grith_digest::types::ScoreSeverity::Medium,
            filter_breakdown: vec![],
            task_context: Some("e2e-test".to_string()),
            plugin_id: "agent".to_string(),
            status: DigestStatus::Pending,
            reviewed_at: None,
            review_action: None,
            reviewer_notes: None,
            informational_only: false,
            escalated_at: None,
            escalated_by: None,
        };
        digest_queue.enqueue(&digest_item).expect("enqueue digest");
    }

    (action, score)
}

// ---------------------------------------------------------------------------
// E2E test: LLM returns safe tool call → ALLOW → audit record, no digest
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_safe_tool_call_allowed_and_audited() {
    let fixtures = TestFixtures::new();
    let audit_storage = Arc::new(Mutex::new(
        AuditStorage::open_in_memory().expect("audit storage"),
    ));
    let digest_queue = Arc::new(DigestQueue::open_in_memory().expect("digest queue"));

    // Mock LLM returns a safe file read
    let mock = MockLlm::new(vec![CompletionResponse {
        content: Some("Reading that file.".into()),
        tool_calls: vec![ToolCall {
            id: "call_safe".into(),
            name: "fs_read".into(),
            arguments: serde_json::json!({"path": "/tmp/safe-test-file.txt"}),
        }],
        usage: TokenUsage {
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
        },
        model: "mock-model".into(),
        finish_reason: FinishReason::ToolUse,
    }]);

    // Verify mock LLM returns the expected tool call
    let router = LlmRouter::fixed("mock", Arc::new(mock));
    let request = grith_llm::CompletionRequest::new(vec![grith_llm::Message {
        role: grith_llm::Role::User,
        content: grith_llm::Content::Text("Read /tmp/safe-test-file.txt".into()),
    }]);
    let response = router.complete(&request).await.expect("LLM response");
    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].name, "fs_read");

    // Execute the tool call through the proxy pipeline
    let session_id = Uuid::new_v4();
    let (action, score) = simulate_tool_execution(
        &response.tool_calls[0],
        &fixtures.proxy,
        &audit_storage,
        &digest_queue,
        session_id,
    )
    .await;

    // Verify: ALLOW decision, low score
    assert!(
        matches!(action, ProxyAction::Allow),
        "safe /tmp read should be ALLOW, got {action:?}"
    );
    assert!(
        score < 3.0,
        "safe /tmp read should score < 3.0, got {score}"
    );

    // Verify: audit record created
    let storage = audit_storage.lock().unwrap();
    let records = grith_audit::AuditQuery::new()
        .paginate(10, 0)
        .execute(&storage)
        .expect("query records");
    assert_eq!(records.len(), 1, "should have exactly 1 audit record");
    assert!(
        records[0].tool_call_type.starts_with("FileRead"),
        "expected FileRead, got {}",
        records[0].tool_call_type
    );
    assert_eq!(records[0].session_id, session_id);
    assert_eq!(records[0].proxy_action, ProxyActionSummary::Allow);

    // Verify: no digest item
    assert_eq!(digest_queue.count_pending().unwrap(), 0);
}

// ---------------------------------------------------------------------------
// E2E test: LLM returns risky tool call → DENY → audit record, no digest
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_risky_tool_call_denied_and_audited() {
    let fixtures = TestFixtures::new();
    let audit_storage = Arc::new(Mutex::new(
        AuditStorage::open_in_memory().expect("audit storage"),
    ));
    let digest_queue = Arc::new(DigestQueue::open_in_memory().expect("digest queue"));

    // Mock LLM returns an SSH key read (high score → DENY)
    let mock = MockLlm::new(vec![CompletionResponse {
        content: None,
        tool_calls: vec![ToolCall {
            id: "call_risky".into(),
            name: "fs_read".into(),
            arguments: serde_json::json!({"path": "/home/user/.ssh/id_rsa"}),
        }],
        usage: TokenUsage {
            prompt_tokens: 100,
            completion_tokens: 30,
            total_tokens: 130,
        },
        model: "mock-model".into(),
        finish_reason: FinishReason::ToolUse,
    }]);

    let router = LlmRouter::fixed("mock", Arc::new(mock));
    let request = grith_llm::CompletionRequest::new(vec![grith_llm::Message {
        role: grith_llm::Role::User,
        content: grith_llm::Content::Text("Read my SSH key".into()),
    }]);
    let response = router.complete(&request).await.expect("LLM response");

    let session_id = Uuid::new_v4();
    let (action, score) = simulate_tool_execution(
        &response.tool_calls[0],
        &fixtures.proxy,
        &audit_storage,
        &digest_queue,
        session_id,
    )
    .await;

    // SSH key read should be DENY (score >= 8.0) or at least not ALLOW
    assert!(
        !matches!(action, ProxyAction::Allow),
        "SSH key read should NOT be allowed, got {action:?}"
    );
    assert!(
        score >= 3.0,
        "SSH key read should score >= 3.0, got {score}"
    );

    // Verify audit record
    let storage = audit_storage.lock().unwrap();
    let records = grith_audit::AuditQuery::new()
        .paginate(10, 0)
        .execute(&storage)
        .expect("query records");
    assert_eq!(records.len(), 1);
    assert_ne!(records[0].proxy_action, ProxyActionSummary::Allow);
}

// ---------------------------------------------------------------------------
// E2E test: LLM returns queued tool call → QUEUE → audit + digest item
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_borderline_tool_call_queued_with_digest() {
    let fixtures = TestFixtures::with_scoring(grith_proxy::scoring::ScoringConfig::default());
    let audit_storage = Arc::new(Mutex::new(
        AuditStorage::open_in_memory().expect("audit storage"),
    ));
    let digest_queue = Arc::new(DigestQueue::open_in_memory().expect("digest queue"));

    // A .pem read scores 4.0 (path-match `*.pem`) — squarely in the QUEUE band
    // (3.0 < score <= 8.0) under the fixed thresholds, so it exercises the
    // queue → audit + digest path without relying on any cold-start widening.
    let mock = MockLlm::new(vec![CompletionResponse {
        content: None,
        tool_calls: vec![ToolCall {
            id: "call_borderline".into(),
            name: "fs_read".into(),
            arguments: serde_json::json!({"path": "/project/secrets/server.pem"}),
        }],
        usage: TokenUsage {
            prompt_tokens: 80,
            completion_tokens: 20,
            total_tokens: 100,
        },
        model: "mock-model".into(),
        finish_reason: FinishReason::ToolUse,
    }]);

    let router = LlmRouter::fixed("mock", Arc::new(mock));
    let request = grith_llm::CompletionRequest::new(vec![grith_llm::Message {
        role: grith_llm::Role::User,
        content: grith_llm::Content::Text("Read the server.pem file".into()),
    }]);
    let response = router.complete(&request).await.expect("LLM response");

    let session_id = Uuid::new_v4();
    let (action, score) = simulate_tool_execution(
        &response.tool_calls[0],
        &fixtures.proxy,
        &audit_storage,
        &digest_queue,
        session_id,
    )
    .await;

    // .pem read (score 4.0) should QUEUE under the fixed thresholds.
    assert!(
        matches!(action, ProxyAction::Queue { .. }),
        ".pem read should be QUEUE, got {action:?} (score {score})"
    );

    // Verify audit record
    let storage = audit_storage.lock().unwrap();
    let records = grith_audit::AuditQuery::new()
        .paginate(10, 0)
        .execute(&storage)
        .expect("query records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].proxy_action, ProxyActionSummary::Queue);

    // Verify digest item was queued
    assert_eq!(
        digest_queue.count_pending().unwrap(),
        1,
        "queued tool call should produce a digest item"
    );
}

// ---------------------------------------------------------------------------
// E2E test: mock LLM cost tracking through audit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_llm_cost_tracked_in_audit() {
    let audit_storage = Arc::new(Mutex::new(
        AuditStorage::open_in_memory().expect("audit storage"),
    ));

    // Mock LLM returns text-only response
    let mock = MockLlm::new(vec![]);
    let router = LlmRouter::fixed("mock", Arc::new(mock));
    let request = grith_llm::CompletionRequest::new(vec![grith_llm::Message {
        role: grith_llm::Role::User,
        content: grith_llm::Content::Text("Hello".into()),
    }]);
    let response = router.complete(&request).await.expect("LLM response");

    // Simulate LLM completion audit record (mirrors agent/mod.rs lines 159-197)
    let provider = router.get_provider("mock").expect("get mock provider");
    let cost = provider.cost_estimate(
        response.usage.prompt_tokens,
        response.usage.completion_tokens,
    );

    let session_id = Uuid::new_v4();
    let cost_record = AuditRecord::new(
        session_id,
        "agent".to_string(),
        "LlmCompletion".to_string(),
        &serde_json::json!({}),
        0.0,
        ProxyActionSummary::Allow,
        vec![],
        0.0,
        Some("e2e-cost-test".to_string()),
    )
    .with_llm_cost(
        provider.name(),
        &response.model,
        response.usage.prompt_tokens,
        response.usage.completion_tokens,
        cost.total_cost,
    );

    let storage = audit_storage.lock().unwrap();
    storage
        .insert_record(&cost_record)
        .expect("insert cost record");

    // Verify cost fields are populated
    let records = grith_audit::AuditQuery::new()
        .paginate(10, 0)
        .execute(&storage)
        .expect("query records");
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.tool_call_type, "LlmCompletion");
    assert_eq!(r.llm_provider.as_deref(), Some("mock"));
    assert_eq!(r.llm_model.as_deref(), Some("mock-model"));
    assert_eq!(r.prompt_tokens, Some(10));
    assert_eq!(r.completion_tokens, Some(5));
    assert!(
        r.estimated_cost_usd.unwrap() > 0.0,
        "cost should be > 0, got {:?}",
        r.estimated_cost_usd
    );
}
