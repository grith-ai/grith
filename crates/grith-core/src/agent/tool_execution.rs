// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Tool call execution with proxy evaluation and audit logging.
//!
//! Each tool call requested by the LLM is first routed through the security
//! proxy. Allowed calls are executed natively, queued calls are escalated
//! to the digest, and denied calls return an error to the LLM.

use grith_audit::CorrelationTracker;
use grith_proxy::{audit_bridge, exfil};
use sha2::{Digest, Sha256};
use std::time::Duration;

use super::telemetry::parse_shell_exec_args;

/// Maximum characters for a single tool result. Prevents token overflow when
/// commands produce very large output (e.g. `grep -r` on an entire codebase).
const MAX_TOOL_RESULT_CHARS: usize = 30_000;

/// Characters reserved for the truncation notice when trimming tool results.
const TRUNCATION_KEEP_CHARS: usize = 200;

/// Shared context for tool call execution, consolidating references to daemon subsystems.
pub struct ToolCallContext<'a> {
    pub proxy: &'a grith_proxy::engine::SecurityProxy,
    pub audit_storage: &'a std::sync::Arc<std::sync::Mutex<grith_audit::AuditStorage>>,
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
    pub review_timeout: Duration,
    pub tui_tx: Option<&'a std::sync::mpsc::Sender<grith_cli::tui::events::AgentEvent>>,
}

/// Execute a single tool call through the security proxy, then perform the operation if allowed.
pub async fn execute_tool_call(
    tool_call: &grith_llm::ToolCall,
    ctx: &mut ToolCallContext<'_>,
) -> String {
    let proxy = ctx.proxy;
    let audit_storage = ctx.audit_storage;
    let digest_queue = ctx.digest_queue;
    let dlp_redactor = ctx.dlp_redactor;
    let correlation_tracker = ctx.correlation_tracker;
    let notification_dispatcher = ctx.notification_dispatcher;
    let containment_tracker = ctx.containment_tracker;
    let ws_tx = ctx.ws_tx;
    let dashboard_url = ctx.dashboard_url;
    let session_id = ctx.session_id;
    let session_name = ctx.session_name;
    let policy_scope = ctx.policy_scope;
    let review_timeout = ctx.review_timeout;
    let tui_tx = ctx.tui_tx;
    *ctx.call_seq += 1;

    let (call_type, _description) = match parse_tool_call(tool_call) {
        Ok(ct) => ct,
        Err(e) => return format!("Error: invalid tool call: {e}"),
    };

    let ctx = grith_proxy::types::ToolCallContext {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        plugin_id: "agent".to_string(),
        call_type: call_type.clone(),
        arguments: tool_call.arguments.clone(),
        session_id,
        task_context: Some(session_name.to_string()),
        call_sequence_number: *ctx.call_seq,
        source_taint: grith_proxy::types::TaintLevel::None,
        profile_name: policy_scope.map(|s| s.to_string()),
        conversation_id: None,
    };

    let decision = proxy.evaluate(&ctx).await;

    // Send proxy decision to TUI if active
    if let Some(tx) = tui_tx {
        let filters: Vec<grith_cli::tui::state::FilterHit> = decision
            .filter_results
            .iter()
            .filter(|r| r.matched)
            .map(|r| grith_cli::tui::state::FilterHit {
                name: r.filter_name.clone(),
                delta: r.score as f32,
            })
            .collect();
        let tui_decision =
            grith_cli::tui::events::score_to_tui_decision(decision.composite_score, filters);
        let _ = tx.send(grith_cli::tui::events::AgentEvent::Decision {
            name: tool_call.name.clone(),
            args: format!("{}", tool_call.arguments),
            decision: tui_decision,
        });
    }

    let correlation_id = if let Some(source_event) = exfil::correlation_source_event(&ctx.call_type)
    {
        Some(correlation_tracker.open_chain(session_id, source_event))
    } else if exfil::is_outbound_sink(&ctx.call_type) {
        correlation_tracker.link_sink(session_id)
    } else {
        None
    };

    // Log to audit storage (redact secrets from summary if DLP detected any)
    let mut audit_record = grith_audit::AuditRecord::new(
        session_id,
        ctx.plugin_id.clone(),
        ctx.call_type.to_string(),
        &ctx.arguments,
        decision.composite_score,
        audit_bridge::to_action_summary(&decision.action),
        audit_bridge::to_filter_summaries(&decision.filter_results),
        decision.evaluation_time.as_secs_f64() * 1000.0,
        ctx.task_context.clone(),
    );
    if grith_proxy::filters::dlp_gate::has_dlp_detection(&decision.filter_results) {
        audit_record.arguments_summary = dlp_redactor.redact(&audit_record.arguments_summary);
    }
    if let Some(id) = correlation_id {
        audit_record = audit_record.with_correlation(id);
    }
    if let Ok(storage) = audit_storage.lock() {
        if let Err(e) = storage.insert_record(&audit_record) {
            tracing::error!(error = %e, "failed to log audit record");
        }
    }

    // Broadcast event to dashboard (in-process WebSocket or remote HTTP POST)
    let action_str = audit_bridge::to_action_summary(&decision.action).to_string();
    let event = serde_json::json!({
        "type": "proxy_evaluation",
        "call_id": ctx.id.to_string(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "composite_score": decision.composite_score,
        "action": action_str,
        "evaluation_time_ms": decision.evaluation_time.as_secs_f64() * 1000.0,
        "filter_results": decision.filter_results.iter().filter(|r| r.matched).map(|r| {
            serde_json::json!({
                "filter_name": r.filter_name,
                "rule_id": r.rule_id,
                "matched": r.matched,
                "score": r.score,
                "severity": r.severity.to_string(),
                "message": r.message,
            })
        }).collect::<Vec<_>>(),
    });
    if let Some(tx) = ws_tx {
        let _ = tx.send(event.to_string());
    } else if let Some(url) = dashboard_url {
        forward_event_to_dashboard(url, &event).await;
    }

    match &decision.action {
        grith_proxy::types::ProxyAction::Allow => {
            handle_allowed_call(&decision, &call_type, &tool_call.arguments, tui_tx).await
        }
        grith_proxy::types::ProxyAction::Queue { .. } => {
            handle_queued_call(
                &decision,
                &ctx,
                digest_queue,
                dlp_redactor,
                notification_dispatcher,
                proxy,
                containment_tracker,
                review_timeout,
                &call_type,
                &tool_call.arguments,
                tui_tx,
            )
            .await
        }
        grith_proxy::types::ProxyAction::Deny { reason } => {
            handle_denied_call(&decision, reason, tui_tx)
        }
    }
}

async fn handle_allowed_call(
    decision: &grith_proxy::types::ProxyDecision,
    call_type: &grith_proxy::types::ToolCallType,
    arguments: &serde_json::Value,
    tui_tx: Option<&std::sync::mpsc::Sender<grith_cli::tui::events::AgentEvent>>,
) -> String {
    if tui_tx.is_none() {
        println!(
            "  -> allowed (score: {:.1}, {:.0}ms)",
            decision.composite_score,
            decision.evaluation_time.as_secs_f64() * 1000.0
        );
    }
    let result = execute_operation(call_type, arguments).await;
    truncate_tool_result(result)
}

async fn handle_queued_call(
    decision: &grith_proxy::types::ProxyDecision,
    ctx: &grith_proxy::types::ToolCallContext,
    digest_queue: &std::sync::Arc<grith_digest::DigestQueue>,
    dlp_redactor: &grith_proxy::filters::dlp_gate::DlpRedactor,
    notification_dispatcher: &std::sync::Arc<grith_notify::NotificationDispatcher>,
    proxy: &grith_proxy::engine::SecurityProxy,
    containment_tracker: &std::sync::Arc<
        grith_proxy::filters::session_containment::ContainmentTracker,
    >,
    review_timeout: Duration,
    call_type: &grith_proxy::types::ToolCallType,
    arguments: &serde_json::Value,
    tui_tx: Option<&std::sync::mpsc::Sender<grith_cli::tui::events::AgentEvent>>,
) -> String {
    if tui_tx.is_none() {
        println!(
            "  -> queued for review (score: {:.1})",
            decision.composite_score
        );
    }

    // Enqueue digest item for human review (redact secrets if DLP detected any)
    let mut summary = grith_audit::types::summarize_arguments(&ctx.arguments);
    if grith_proxy::filters::dlp_gate::has_dlp_detection(&decision.filter_results) {
        summary = dlp_redactor.redact(&summary);
    }
    let digest_item = grith_digest::DigestItem {
        id: uuid::Uuid::new_v4(),
        created_at: chrono::Utc::now(),
        session_id: Some(ctx.session_id),
        tool_call_type: ctx.call_type.to_string(),
        arguments_summary: summary,
        composite_score: decision.composite_score,
        severity: grith_digest::types::ScoreSeverity::from_score(decision.composite_score),
        filter_breakdown: decision
            .filter_results
            .iter()
            .filter(|r| r.matched)
            .map(|r| grith_digest::types::FilterBreakdown {
                filter_name: r.filter_name.clone(),
                score: r.score,
                rule_id: r.rule_id.clone(),
                message: r.message.clone(),
            })
            .collect(),
        task_context: ctx.task_context.clone(),
        plugin_id: ctx.plugin_id.clone(),
        status: grith_digest::DigestStatus::Pending,
        reviewed_at: None,
        review_action: None,
        reviewer_notes: None,
        informational_only: false,
        escalated_at: None,
        escalated_by: None,
    };
    if let Err(e) = digest_queue.enqueue(&digest_item) {
        tracing::error!(error = %e, "failed to enqueue digest item");
        return format!(
            "Operation queued but failed to persist (score: {:.1}). Treating as denied.",
            decision.composite_score
        );
    }

    // Fire notification on configured channels
    if let Err(e) = notification_dispatcher
        .notify_permission_request(&digest_item)
        .await
    {
        tracing::warn!(error = %e, "failed to send permission request notification");
    }

    // Interactive inline review (shows detail + key prompt in terminal)
    let outcome = grith_cli::run_inline_review(digest_queue, &digest_item, review_timeout).await;

    // Notify resolution on configured channels
    if let Ok(resolved_item) = digest_queue.get_by_id(&digest_item.id) {
        if let Err(e) = notification_dispatcher
            .notify_resolution(&resolved_item)
            .await
        {
            tracing::warn!(error = %e, "failed to send resolution notification");
        }
    }

    // Retrieve the stored review action to dispatch side-effects.
    let review_action = digest_queue
        .get_by_id(&digest_item.id)
        .ok()
        .and_then(|item| item.review_action.clone());

    match outcome {
        grith_digest::ReviewOutcome::Approved => {
            // Dispatch side-effects based on the specific review action.
            dispatch_review_side_effects(
                review_action.as_deref(),
                proxy,
                containment_tracker,
                ctx,
                decision,
            );
            if let Some(tx) = tui_tx {
                let _ = tx.send(grith_cli::tui::events::AgentEvent::Resumed);
            } else {
                println!("  -> approved by reviewer, executing operation");
            }
            let result = execute_operation(call_type, arguments).await;
            truncate_tool_result(result)
        }
        grith_digest::ReviewOutcome::Denied => {
            if tui_tx.is_none() {
                println!("  -> denied by reviewer");
            }
            format!(
                "Operation denied by reviewer (score: {:.1}).",
                decision.composite_score
            )
        }
        grith_digest::ReviewOutcome::TimedOut => {
            if tui_tx.is_none() {
                println!(
                    "  -> auto-denied (no review within {}s)",
                    review_timeout.as_secs()
                );
            }
            format!(
                "Operation auto-denied: no review received within {}s timeout (score: {:.1}).",
                review_timeout.as_secs(),
                decision.composite_score
            )
        }
    }
}

/// Dispatch side-effects for review actions beyond simple approve/deny.
fn dispatch_review_side_effects(
    review_action: Option<&str>,
    _proxy: &grith_proxy::engine::SecurityProxy,
    containment_tracker: &std::sync::Arc<
        grith_proxy::filters::session_containment::ContainmentTracker,
    >,
    ctx: &grith_proxy::types::ToolCallContext,
    _decision: &grith_proxy::types::ProxyDecision,
) {
    let Some(action) = review_action else {
        return;
    };
    match action {
        "approve_and_learn" => {
            tracing::info!(
                session_id = %ctx.session_id,
                "approve_and_learn: reputation system handles learning"
            );
        }
        "unlock_egress" => {
            let removed = containment_tracker.unregister(ctx.session_id);
            tracing::info!(
                session_id = %ctx.session_id,
                was_contained = removed,
                "unlock_egress: lifted egress containment for session"
            );
        }
        "allow_always" => match grith_proxy::allowlist_persistence::persist_allow_always(ctx) {
            Ok(Some(path)) => {
                tracing::info!(
                    session_id = %ctx.session_id,
                    call_type = %ctx.call_type,
                    path = %path.display(),
                    "allow_always: persisted allowlist entry"
                );
            }
            Ok(None) => {
                tracing::info!(
                    session_id = %ctx.session_id,
                    call_type = %ctx.call_type,
                    "allow_always: call type has no persistable allowlist target"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    session_id = %ctx.session_id,
                    call_type = %ctx.call_type,
                    "allow_always: failed to persist allowlist entry"
                );
            }
        },
        _ => {}
    }
}

fn handle_denied_call(
    decision: &grith_proxy::types::ProxyDecision,
    reason: &str,
    tui_tx: Option<&std::sync::mpsc::Sender<grith_cli::tui::events::AgentEvent>>,
) -> String {
    if tui_tx.is_none() {
        println!(
            "  -> denied (score: {:.1}): {}",
            decision.composite_score, reason
        );
    }
    format!("Operation denied by security proxy: {reason}")
}

/// Parse an LLM tool call into a proxy ToolCallType and a human-readable description.
pub fn parse_tool_call(
    tool_call: &grith_llm::ToolCall,
) -> anyhow::Result<(grith_proxy::types::ToolCallType, String)> {
    let args = &tool_call.arguments;
    match tool_call.name.as_str() {
        "read_file" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("read_file: missing 'path'"))?;
            Ok((
                grith_proxy::types::ToolCallType::FileRead {
                    path: path.to_string(),
                },
                format!("read_file({path})"),
            ))
        }
        "write_file" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("write_file: missing 'path'"))?;
            let content = args.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let hash = Sha256::digest(content.as_bytes());
            Ok((
                grith_proxy::types::ToolCallType::FileWrite {
                    path: path.to_string(),
                    content_hash: format!("{:x}", hash),
                },
                format!("write_file({path})"),
            ))
        }
        "list_directory" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("list_directory: missing 'path'"))?;
            Ok((
                grith_proxy::types::ToolCallType::DirList {
                    path: path.to_string(),
                },
                format!("list_directory({path})"),
            ))
        }
        "shell_exec" => {
            let command = args
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("shell_exec: missing 'command'"))?;
            let cmd_args = parse_shell_exec_args(args.get("args"));
            let desc = if cmd_args.is_empty() {
                format!("shell_exec({command})")
            } else {
                format!("shell_exec({command} {})", cmd_args.join(" "))
            };
            Ok((
                grith_proxy::types::ToolCallType::ShellExec {
                    command: command.to_string(),
                    args: cmd_args,
                },
                desc,
            ))
        }
        "http_request" => {
            let method = args.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("http_request: missing 'url'"))?;
            Ok((
                grith_proxy::types::ToolCallType::HttpRequest {
                    method: method.to_string(),
                    url: url.to_string(),
                },
                format!("http_request({method} {url})"),
            ))
        }
        "append_file" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("append_file: missing 'path'"))?;
            Ok((
                grith_proxy::types::ToolCallType::FileAppend {
                    path: path.to_string(),
                },
                format!("append_file({path})"),
            ))
        }
        "delete_file" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("delete_file: missing 'path'"))?;
            Ok((
                grith_proxy::types::ToolCallType::FileDelete {
                    path: path.to_string(),
                },
                format!("delete_file({path})"),
            ))
        }
        "rename_file" => {
            let old_path = args
                .get("old_path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("rename_file: missing 'old_path'"))?;
            let new_path = args
                .get("new_path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("rename_file: missing 'new_path'"))?;
            Ok((
                grith_proxy::types::ToolCallType::FileRename {
                    old_path: old_path.to_string(),
                    new_path: new_path.to_string(),
                },
                format!("rename_file({old_path} -> {new_path})"),
            ))
        }
        "chmod" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("chmod: missing 'path'"))?;
            let mode_u64 = args
                .get("mode")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("chmod: missing 'mode'"))?;
            let mode = u32::try_from(mode_u64)
                .map_err(|_| anyhow::anyhow!("chmod: 'mode' out of range for u32"))?;
            Ok((
                grith_proxy::types::ToolCallType::FileChmod {
                    path: path.to_string(),
                    mode,
                },
                format!("chmod({path}, {mode:o})"),
            ))
        }
        "create_directory" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("create_directory: missing 'path'"))?;
            Ok((
                grith_proxy::types::ToolCallType::DirCreate {
                    path: path.to_string(),
                },
                format!("create_directory({path})"),
            ))
        }
        "net_connect" => {
            let address = args
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("net_connect: missing 'address'"))?;
            let port_u64 = args
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("net_connect: missing 'port'"))?;
            let port = u16::try_from(port_u64)
                .map_err(|_| anyhow::anyhow!("net_connect: 'port' must be <= 65535"))?;
            Ok((
                grith_proxy::types::ToolCallType::NetConnect {
                    address: address.to_string(),
                    port,
                },
                format!("net_connect({address}:{port})"),
            ))
        }
        "net_listen" => {
            let address = args
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("net_listen: missing 'address'"))?;
            let port_u64 = args
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("net_listen: missing 'port'"))?;
            let port = u16::try_from(port_u64)
                .map_err(|_| anyhow::anyhow!("net_listen: 'port' must be <= 65535"))?;
            Ok((
                grith_proxy::types::ToolCallType::NetListen {
                    address: address.to_string(),
                    port,
                },
                format!("net_listen({address}:{port})"),
            ))
        }
        "spawn_process" => {
            let command = args
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("spawn_process: missing 'command'"))?;
            let cmd_args: Vec<String> = args
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            Ok((
                grith_proxy::types::ToolCallType::ProcessSpawn {
                    command: command.to_string(),
                    args: cmd_args.clone(),
                },
                format!("spawn_process({command} {})", cmd_args.join(" ")),
            ))
        }
        other => anyhow::bail!("unknown tool: {other}"),
    }
}

/// Truncate a tool result string if it exceeds the limit.
pub fn truncate_tool_result(result: String) -> String {
    if result.len() <= MAX_TOOL_RESULT_CHARS {
        return result;
    }
    let keep = MAX_TOOL_RESULT_CHARS - TRUNCATION_KEEP_CHARS;
    let half = keep / 2;
    format!(
        "{}\n\n... [truncated: {} total chars, showing first and last {} chars] ...\n\n{}",
        &result[..half],
        result.len(),
        half,
        &result[result.len() - half..]
    )
}

/// Execute an allowed operation and return the result as a string.
pub async fn execute_operation(
    call_type: &grith_proxy::types::ToolCallType,
    arguments: &serde_json::Value,
) -> String {
    match call_type {
        grith_proxy::types::ToolCallType::FileRead { path } => {
            match tokio::fs::read_to_string(path).await {
                Ok(content) => content,
                Err(e) => format!("Error reading {path}: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::FileWrite { path, .. } => {
            let content = arguments
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(parent) = std::path::Path::new(path).parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            match tokio::fs::write(path, content).await {
                Ok(()) => format!("Wrote {} bytes to {path}", content.len()),
                Err(e) => format!("Error writing {path}: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::DirList { path } => {
            match tokio::fs::read_dir(path).await {
                Ok(mut entries) => {
                    let mut listing = Vec::new();
                    while let Ok(Some(entry)) = entries.next_entry().await {
                        let name = entry.file_name().to_string_lossy().to_string();
                        let kind = match entry.metadata().await {
                            Ok(m) if m.is_dir() => "dir",
                            Ok(_) => "file",
                            Err(_) => "?",
                        };
                        listing.push(format!("{kind}\t{name}"));
                    }
                    listing.sort();
                    listing.join("\n")
                }
                Err(e) => format!("Error listing {path}: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::ShellExec { command, args } => {
            match tokio::process::Command::new(command)
                .args(args)
                .output()
                .await
            {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let mut result = String::new();
                    if !stdout.is_empty() {
                        result.push_str(&stdout);
                    }
                    if !stderr.is_empty() {
                        if !result.is_empty() {
                            result.push('\n');
                        }
                        result.push_str("stderr: ");
                        result.push_str(&stderr);
                    }
                    if !output.status.success() {
                        if !result.is_empty() && !result.ends_with('\n') {
                            result.push('\n');
                        }
                        result.push_str(&format!(
                            "Exit code: {}",
                            output.status.code().unwrap_or(-1)
                        ));
                    }
                    if result.is_empty() {
                        format!("Exit code: {}", output.status.code().unwrap_or(-1))
                    } else {
                        result
                    }
                }
                Err(e) => format!("Error executing {command}: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::HttpRequest { method, url } => {
            let client = reqwest::Client::new();
            let builder = match method.to_uppercase().as_str() {
                "GET" => client.get(url),
                "POST" => client.post(url),
                "PUT" => client.put(url),
                "DELETE" => client.delete(url),
                "PATCH" => client.patch(url),
                "HEAD" => client.head(url),
                _ => return format!("Unsupported HTTP method: {method}"),
            };
            match builder.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    match resp.text().await {
                        Ok(body) if body.len() > 10000 => {
                            format!(
                                "HTTP {} ({} bytes)\n{}...[truncated]",
                                status,
                                body.len(),
                                &body[..5000]
                            )
                        }
                        Ok(body) => format!("HTTP {status}\n{body}"),
                        Err(e) => format!("HTTP {status} (error reading body: {e})"),
                    }
                }
                Err(e) => format!("HTTP request error: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::FileAppend { path } => {
            let content = arguments
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
            {
                Ok(mut file) => {
                    use tokio::io::AsyncWriteExt;
                    match file.write_all(content.as_bytes()).await {
                        Ok(()) => format!("Appended {} bytes to {path}", content.len()),
                        Err(e) => format!("Error appending to {path}: {e}"),
                    }
                }
                Err(e) => format!("Error opening {path} for append: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::FileDelete { path } => {
            match tokio::fs::remove_file(path).await {
                Ok(()) => format!("Deleted {path}"),
                Err(e) => format!("Error deleting {path}: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::FileRename { old_path, new_path } => {
            match tokio::fs::rename(old_path, new_path).await {
                Ok(()) => format!("Renamed {old_path} -> {new_path}"),
                Err(e) => format!("Error renaming {old_path} -> {new_path}: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::FileChmod { path, mode } => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                match tokio::fs::metadata(path).await {
                    Ok(_) => {
                        let perms = std::fs::Permissions::from_mode(*mode);
                        match tokio::fs::set_permissions(path, perms).await {
                            Ok(()) => format!("Set permissions on {path} to {mode:o}"),
                            Err(e) => format!("Error setting permissions on {path}: {e}"),
                        }
                    }
                    Err(e) => format!("Error accessing {path}: {e}"),
                }
            }
            #[cfg(not(unix))]
            {
                format!("FileChmod is not supported on this platform")
            }
        }
        grith_proxy::types::ToolCallType::DirCreate { path } => {
            match tokio::fs::create_dir_all(path).await {
                Ok(()) => format!("Created directory {path}"),
                Err(e) => format!("Error creating directory {path}: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::NetConnect { address, port } => {
            match tokio::net::TcpStream::connect((address.as_str(), *port)).await {
                Ok(_stream) => {
                    format!("Successfully connected to {address}:{port} (connection closed)")
                }
                Err(e) => format!("Error connecting to {address}:{port}: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::NetListen { address, port } => {
            match tokio::net::TcpListener::bind((address.as_str(), *port)).await {
                Ok(listener) => {
                    let local_addr = listener
                        .local_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| format!("{address}:{port}"));
                    format!("Listening on {local_addr} (listener closed)")
                }
                Err(e) => format!("Error binding to {address}:{port}: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::ProcessSpawn { command, args } => {
            match tokio::process::Command::new(command)
                .args(args)
                .output()
                .await
            {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let mut result = String::new();
                    if !stdout.is_empty() {
                        result.push_str(&stdout);
                    }
                    if !stderr.is_empty() {
                        if !result.is_empty() {
                            result.push('\n');
                        }
                        result.push_str("stderr: ");
                        result.push_str(&stderr);
                    }
                    if !output.status.success() {
                        if !result.is_empty() && !result.ends_with('\n') {
                            result.push('\n');
                        }
                        result.push_str(&format!(
                            "Exit code: {}",
                            output.status.code().unwrap_or(-1)
                        ));
                    }
                    if result.is_empty() {
                        format!("Exit code: {}", output.status.code().unwrap_or(-1))
                    } else {
                        result
                    }
                }
                Err(e) => format!("Error spawning {command}: {e}"),
            }
        }
        grith_proxy::types::ToolCallType::DnsQuery { domain, query_type } => {
            format!("DNS query not directly executable: {domain} ({query_type})")
        }
    }
}

/// Forward a proxy evaluation event to the dashboard server via HTTP POST.
/// This is used when the dashboard runs as a separate process (no in-process ws_tx).
pub async fn forward_event_to_dashboard(dashboard_url: &str, event: &serde_json::Value) {
    let url = format!("{dashboard_url}/api/events");
    let client = reqwest::Client::new();
    let _ = client
        .post(&url)
        .json(event)
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use grith_llm::ToolCall;
    use grith_proxy::types::ToolCallType;
    use tempfile::tempdir;

    fn make_tool_call(name: &str, arguments: serde_json::Value) -> ToolCall {
        ToolCall {
            id: "test-call".to_string(),
            name: name.to_string(),
            arguments,
        }
    }

    #[test]
    fn parse_tool_call_supports_all_new_variants() {
        let cases: Vec<(ToolCall, ToolCallType)> = vec![
            (
                make_tool_call(
                    "append_file",
                    serde_json::json!({"path":"/tmp/a.txt", "content":"x"}),
                ),
                ToolCallType::FileAppend {
                    path: "/tmp/a.txt".to_string(),
                },
            ),
            (
                make_tool_call("delete_file", serde_json::json!({"path":"/tmp/a.txt"})),
                ToolCallType::FileDelete {
                    path: "/tmp/a.txt".to_string(),
                },
            ),
            (
                make_tool_call(
                    "rename_file",
                    serde_json::json!({"old_path":"/tmp/a.txt", "new_path":"/tmp/b.txt"}),
                ),
                ToolCallType::FileRename {
                    old_path: "/tmp/a.txt".to_string(),
                    new_path: "/tmp/b.txt".to_string(),
                },
            ),
            (
                make_tool_call(
                    "chmod",
                    serde_json::json!({"path":"/tmp/a.txt", "mode":493}),
                ),
                ToolCallType::FileChmod {
                    path: "/tmp/a.txt".to_string(),
                    mode: 493,
                },
            ),
            (
                make_tool_call(
                    "create_directory",
                    serde_json::json!({"path":"/tmp/new-dir"}),
                ),
                ToolCallType::DirCreate {
                    path: "/tmp/new-dir".to_string(),
                },
            ),
            (
                make_tool_call(
                    "net_connect",
                    serde_json::json!({"address":"127.0.0.1", "port":8080}),
                ),
                ToolCallType::NetConnect {
                    address: "127.0.0.1".to_string(),
                    port: 8080,
                },
            ),
            (
                make_tool_call(
                    "net_listen",
                    serde_json::json!({"address":"127.0.0.1", "port":8081}),
                ),
                ToolCallType::NetListen {
                    address: "127.0.0.1".to_string(),
                    port: 8081,
                },
            ),
            (
                make_tool_call(
                    "spawn_process",
                    serde_json::json!({"command":"cargo", "args":["--version"]}),
                ),
                ToolCallType::ProcessSpawn {
                    command: "cargo".to_string(),
                    args: vec!["--version".to_string()],
                },
            ),
        ];

        for (tool_call, expected) in cases {
            let (parsed, _desc) = parse_tool_call(&tool_call).expect("parse should succeed");
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn parse_tool_call_rejects_out_of_range_ports() {
        let connect = make_tool_call(
            "net_connect",
            serde_json::json!({"address":"127.0.0.1", "port":70000}),
        );
        let err = parse_tool_call(&connect).unwrap_err().to_string();
        assert!(err.contains("must be <= 65535"));

        let listen = make_tool_call(
            "net_listen",
            serde_json::json!({"address":"127.0.0.1", "port":999999}),
        );
        let err = parse_tool_call(&listen).unwrap_err().to_string();
        assert!(err.contains("must be <= 65535"));
    }

    #[test]
    fn parse_tool_call_rejects_out_of_range_chmod_mode() {
        let chmod = make_tool_call(
            "chmod",
            serde_json::json!({"path":"/tmp/file", "mode": 4294967296u64}),
        );
        let err = parse_tool_call(&chmod).unwrap_err().to_string();
        assert!(err.contains("out of range"));
    }

    #[tokio::test]
    async fn execute_operation_file_append_rename_delete_dir_create() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("a.txt");
        let renamed = dir.path().join("b.txt");
        let nested = dir.path().join("nested/dir");

        let append = ToolCallType::FileAppend {
            path: file.to_string_lossy().to_string(),
        };
        let res = execute_operation(&append, &serde_json::json!({"content":"hello"})).await;
        assert!(res.contains("Appended"));
        let content = tokio::fs::read_to_string(&file).await.unwrap();
        assert_eq!(content, "hello");

        let rename = ToolCallType::FileRename {
            old_path: file.to_string_lossy().to_string(),
            new_path: renamed.to_string_lossy().to_string(),
        };
        let res = execute_operation(&rename, &serde_json::Value::Null).await;
        assert!(res.contains("Renamed"));
        assert!(tokio::fs::metadata(&renamed).await.is_ok());

        let create_dir = ToolCallType::DirCreate {
            path: nested.to_string_lossy().to_string(),
        };
        let res = execute_operation(&create_dir, &serde_json::Value::Null).await;
        assert!(res.contains("Created directory"));
        assert!(tokio::fs::metadata(&nested).await.unwrap().is_dir());

        let delete = ToolCallType::FileDelete {
            path: renamed.to_string_lossy().to_string(),
        };
        let res = execute_operation(&delete, &serde_json::Value::Null).await;
        assert!(res.contains("Deleted"));
        assert!(tokio::fs::metadata(&renamed).await.is_err());
    }

    #[tokio::test]
    async fn execute_operation_network_connect_and_listen() {
        let connect = ToolCallType::NetConnect {
            address: "127.0.0.1".to_string(),
            port: 65535,
        };
        let res = execute_operation(&connect, &serde_json::Value::Null).await;
        assert!(res.contains("connected") || res.contains("Error connecting"));

        let listen = ToolCallType::NetListen {
            address: "127.0.0.1".to_string(),
            port: 49152,
        };
        let res = execute_operation(&listen, &serde_json::Value::Null).await;
        assert!(res.contains("Listening on") || res.contains("Error binding"));
    }

    #[tokio::test]
    async fn execute_operation_process_spawn_runs_command() {
        let cargo_cmd = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let spawn = ToolCallType::ProcessSpawn {
            command: cargo_cmd,
            args: vec!["--version".to_string()],
        };
        let res = execute_operation(&spawn, &serde_json::Value::Null).await;
        assert!(!res.contains("Error spawning"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_operation_chmod_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let file = dir.path().join("chmod.txt");
        tokio::fs::write(&file, "x").await.unwrap();

        let chmod = ToolCallType::FileChmod {
            path: file.to_string_lossy().to_string(),
            mode: 0o600,
        };
        let res = execute_operation(&chmod, &serde_json::Value::Null).await;
        assert!(res.contains("Set permissions"));

        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn execute_operation_chmod_reports_unsupported() {
        let chmod = ToolCallType::FileChmod {
            path: "C:/tmp/chmod.txt".to_string(),
            mode: 0o600,
        };
        let res = execute_operation(&chmod, &serde_json::Value::Null).await;
        assert!(res.contains("not supported"));
    }
}
