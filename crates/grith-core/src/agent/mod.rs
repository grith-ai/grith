// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Built-in LLM agent loop, tool definitions, execution, and session telemetry.

pub mod telemetry;
pub mod tool_execution;
pub mod tools;

use grith_audit::CorrelationTracker;
use std::time::Duration;

use self::telemetry::SessionTelemetry;
use self::tool_execution::{execute_tool_call, ToolCallContext};

pub const AGENT_SYSTEM_PROMPT: &str = "\
You are grith, a security-first AI assistant. You have access to tools for \
reading files, writing files, listing directories, executing shell commands, \
and making HTTP requests. All tool calls are evaluated by a security proxy \
that may allow, queue for review, or deny operations based on risk scoring.\n\n\
Use the available tools to accomplish the user's task. Be concise and precise. \
Prefer reading files before modifying them. Avoid unnecessary operations.";

/// Maximum number of agent loop rounds before stopping.
pub const MAX_TOOL_ROUNDS: usize = 20;

/// Check if an LLM error indicates the prompt exceeded the token limit.
fn is_context_overflow(err: &grith_llm::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("too long")
        || msg.contains("too many tokens")
        || msg.contains("maximum context length")
        || msg.contains("context_length_exceeded")
        || msg.contains("max_tokens")
}

/// Shrink the largest tool-result messages in the session history.
/// Halves the content of the single largest tool result, keeping the first
/// and last portions so the LLM retains some context.
fn shrink_largest_tool_result(session: &mut grith_cli::ReplSession) -> bool {
    let mut largest_idx = None;
    let mut largest_len = 0usize;

    for (i, msg) in session.messages.iter().enumerate() {
        if let grith_llm::Content::ToolResult(tr) = &msg.content {
            if tr.content.len() > largest_len {
                largest_len = tr.content.len();
                largest_idx = Some(i);
            }
        }
    }

    let Some(idx) = largest_idx else {
        return false;
    };

    if largest_len < 2000 {
        return false;
    }

    if let grith_llm::Content::ToolResult(tr) = &mut session.messages[idx].content {
        let target = largest_len / 2;
        let half = target / 2;
        let truncated = format!(
            "{}\n\n... [output truncated from {} to ~{} chars for context fit] ...\n\n{}",
            &tr.content[..half.min(tr.content.len())],
            largest_len,
            target,
            &tr.content[tr.content.len().saturating_sub(half)..]
        );
        println!(
            "  [context] truncating tool result from {} to {} chars",
            largest_len,
            truncated.len()
        );
        tr.content = truncated;
        true
    } else {
        false
    }
}

/// Shared context for the agent loop, consolidating daemon subsystem references.
pub struct AgentLoopContext<'a> {
    pub proxy: &'a grith_proxy::engine::SecurityProxy,
    pub audit_storage: &'a std::sync::Arc<std::sync::Mutex<grith_audit::AuditStorage>>,
    /// B12 #78: whether this process owns the audit database and may write it
    /// directly. When false (a daemon owns it, so this process is a Reader),
    /// records are routed to the owner via [`AgentLoopContext::audit_ingest`].
    pub can_write_audit: bool,
    /// Client to the audit-owning daemon, used to forward records when this
    /// process is a Reader. `None` when unavailable.
    pub audit_ingest: Option<&'a crate::daemon::client::DaemonClient>,
    pub digest_queue: &'a std::sync::Arc<grith_digest::DigestQueue>,
    pub dlp_redactor: &'a grith_proxy::filters::dlp_gate::DlpRedactor,
    pub correlation_tracker: &'a CorrelationTracker,
    pub notification_dispatcher: &'a std::sync::Arc<grith_notify::NotificationDispatcher>,
    pub containment_tracker:
        &'a std::sync::Arc<grith_proxy::filters::session_containment::ContainmentTracker>,
    pub ws_tx: Option<&'a tokio::sync::broadcast::Sender<String>>,
    pub dashboard_url: Option<&'a str>,
    pub session_id: uuid::Uuid,
    pub session_name: &'a str,
    pub policy_scope: Option<&'a str>,
    pub call_seq: &'a mut u64,
    pub telemetry: &'a mut SessionTelemetry,
    pub max_rounds: usize,
    pub review_timeout: Duration,
    pub tui_tx: Option<std::sync::mpsc::Sender<grith_cli::tui::events::AgentEvent>>,
}

/// Run the LLM agent loop: send messages to LLM, execute tool calls through proxy, repeat.
pub async fn run_agent_loop(
    session: &mut grith_cli::ReplSession,
    router: &grith_llm::LlmRouter,
    tools: &[grith_llm::ToolDefinition],
    ctx: &mut AgentLoopContext<'_>,
) -> anyhow::Result<()> {
    let max_rounds = ctx.max_rounds;
    let mut round = 0;
    let max_retries = 3;

    loop {
        let (response, usage_provider) = {
            let mut last_err = None;
            let mut resp = None;
            let mut provider_for_usage: Option<std::sync::Arc<dyn grith_llm::LlmProvider>> = None;
            for attempt in 0..=max_retries {
                let req = session.build_request().with_tools(tools.to_vec());
                let routed_provider = router.route(&req).ok().map(std::sync::Arc::clone);
                match router.complete(&req).await {
                    Ok(r) => {
                        resp = Some(r);
                        provider_for_usage = routed_provider;
                        break;
                    }
                    Err(e) if is_context_overflow(&e) && attempt < max_retries => {
                        if !shrink_largest_tool_result(session) {
                            return Err(anyhow::anyhow!(
                                "LLM request failed (prompt too long, nothing to truncate): {e}"
                            ));
                        }
                    }
                    Err(e) => {
                        last_err = Some(e);
                        break;
                    }
                }
            }
            match resp {
                Some(r) => (r, provider_for_usage),
                None => {
                    return Err(anyhow::anyhow!(
                        "LLM request failed: {}",
                        last_err
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "unknown".into())
                    ));
                }
            }
        };
        ctx.telemetry
            .observe_response_usage(&response, usage_provider.as_deref());

        // Log LLM completion as an audit record for cost tracking.
        {
            let provider_name = usage_provider
                .as_deref()
                .map(|p| p.name().to_string())
                .unwrap_or_default();
            let cost_usd = usage_provider
                .as_deref()
                .map(|p| {
                    p.cost_estimate(
                        response.usage.prompt_tokens,
                        response.usage.completion_tokens,
                    )
                    .total_cost
                })
                .unwrap_or(0.0);
            let cost_record = grith_audit::AuditRecord::new(
                ctx.session_id,
                "agent".to_string(),
                "LlmCompletion".to_string(),
                &serde_json::json!({}),
                0.0,
                grith_audit::ProxyActionSummary::Allow,
                vec![],
                0.0,
                Some(ctx.session_name.to_string()),
            )
            .with_llm_cost(
                &provider_name,
                &response.model,
                response.usage.prompt_tokens,
                response.usage.completion_tokens,
                cost_usd,
            )
            .with_analytics_metadata(grith_audit::AuditAnalyticsMetadata {
                metadata_version: 1,
                completeness: grith_analytics::contract::CompletenessTier::Decisions,
                record_class: grith_analytics::contract::RecordClass::LlmUsage,
                category: grith_analytics::contract::Category::Llm,
                config: grith_audit::AuditConfigVersion {
                    profile_id: "agent".into(),
                    profile_version: "agent-v1".into(),
                    config_hash: grith_audit::types::sha256_hex(b"grith-agent-llm-v1"),
                    policy_version: "llm-accounting-v1".into(),
                    auto_allow_threshold_micros: 0,
                    auto_deny_threshold_micros: 0,
                    queue_policy: "not-applicable".into(),
                    team_default_config_version: "standalone-local-v1".into(),
                },
                filter_set_version: None,
                llm_pricing: Some(grith_audit::AuditLlmPricing {
                    cost_micros: grith_analytics::normalize::cost_usd_to_micros(cost_usd)
                        .unwrap_or_default(),
                    price_source: "grith-llm-static-table".into(),
                    pricing_version: env!("CARGO_PKG_VERSION").into(),
                }),
                destination: None,
                security: None,
            });
            // B12 #78: route the cost record to the audit owner when this
            // process is a Reader instead of dropping it against a read-only
            // handle. Unlike an enforcement record this is Allow-only cost
            // telemetry, so a forward failure is logged rather than aborting
            // the run — but it is never silently swallowed.
            if let Err(e) = tool_execution::persist_audit_record(
                ctx.audit_storage,
                ctx.can_write_audit,
                ctx.audit_ingest,
                &cost_record,
            )
            .await
            {
                tracing::warn!(error = %e, "could not persist LLM completion cost record");
            }
        }

        if !session.should_continue_tool_loop(&response, round, max_rounds) {
            if let Some(ref text) = response.content {
                if !text.is_empty() {
                    if let Some(ref tx) = ctx.tui_tx {
                        let _ = tx.send(grith_cli::tui::events::AgentEvent::TextChunk {
                            text: text.clone(),
                            dim: false,
                        });
                    } else {
                        println!("{text}");
                    }
                }
            }
            if let Some(ref text) = response.content {
                session.add_assistant_response(text);
            }
            break;
        }

        let mut parts = Vec::new();
        if let Some(ref text) = response.content {
            if !text.is_empty() {
                parts.push(grith_llm::ContentPart::Text { text: text.clone() });
                if let Some(ref tx) = ctx.tui_tx {
                    let _ = tx.send(grith_cli::tui::events::AgentEvent::TextChunk {
                        text: text.clone(),
                        dim: false,
                    });
                } else {
                    println!("{text}");
                }
            }
        }
        for tc in &response.tool_calls {
            parts.push(grith_llm::ContentPart::ToolUse(tc.clone()));
        }
        session.messages.push(grith_llm::Message {
            role: grith_llm::Role::Assistant,
            content: grith_llm::Content::Parts(parts),
        });

        for tool_call in &response.tool_calls {
            ctx.telemetry.observe_tool_call(&tool_call.name);
            let display = grith_cli::repl::format_tool_call(tool_call);
            if let Some(ref tx) = ctx.tui_tx {
                let _ = tx.send(grith_cli::tui::events::AgentEvent::ToolCallStart {
                    name: tool_call.name.clone(),
                    args: display.clone(),
                });
            } else {
                println!("[tool] {display}");
            }

            let mut tc_ctx = ToolCallContext {
                proxy: ctx.proxy,
                audit_storage: ctx.audit_storage,
                can_write_audit: ctx.can_write_audit,
                audit_ingest: ctx.audit_ingest,
                digest_queue: ctx.digest_queue,
                dlp_redactor: ctx.dlp_redactor,
                correlation_tracker: ctx.correlation_tracker,
                notification_dispatcher: ctx.notification_dispatcher,
                containment_tracker: ctx.containment_tracker,
                ws_tx: ctx.ws_tx,
                dashboard_url: ctx.dashboard_url,
                session_id: ctx.session_id,
                session_name: ctx.session_name,
                policy_scope: ctx.policy_scope,
                call_seq: ctx.call_seq,
                review_timeout: ctx.review_timeout,
                tui_tx: ctx.tui_tx.as_ref(),
            };
            let result = execute_tool_call(tool_call, &mut tc_ctx).await;
            session.add_tool_result(&tool_call.id, &result);
        }

        round += 1;
    }

    Ok(())
}
