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

/// Upper bound on how long a queued call waits for review when NO reviewer is
/// detectable (no tty, no dashboard, no notification channel). Long enough that
/// a prompt external resolver still lands; short enough that a genuinely
/// headless run (e.g. ssh queued in CI) fails in seconds, not the full
/// review_timeout. The real timeout is `review_timeout.min(this)`, so a
/// shorter configured timeout always wins.
const NO_REVIEWER_GRACE: Duration = Duration::from_secs(15);

/// Characters reserved for the truncation notice when trimming tool results.
const TRUNCATION_KEEP_CHARS: usize = 200;

/// Shared context for tool call execution, consolidating references to daemon subsystems.
pub struct ToolCallContext<'a> {
    pub proxy: &'a grith_proxy::engine::SecurityProxy,
    pub audit_storage: &'a std::sync::Arc<std::sync::Mutex<grith_audit::AuditStorage>>,
    /// B12 #78: whether this process owns the audit database (holds the writer
    /// lock) and may write it directly. When false, records must be routed to
    /// the owning daemon via [`ToolCallContext::audit_ingest`] instead of
    /// hitting a read-only handle whose insert silently fails.
    pub can_write_audit: bool,
    /// Client to the daemon that owns the audit database, used to forward
    /// records when this process is a Reader. `None` when unavailable — in
    /// which case an unrecordable call fails closed rather than executing.
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
    let can_write_audit = ctx.can_write_audit;
    let audit_ingest = ctx.audit_ingest;
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
        session_scope: Some(grith_proxy::types::SessionScopeKey::from_session_id(
            session_id,
        )),
        spawn_provenance: None,
        listener_policy_match: None,
        bind_protocol: None,
    };

    // `grith run` is a third decision surface with its own review timeout, and
    // one of the paths where the session-allowlist bypass does not apply - i.e.
    // where stateful filters matter most. Wiring only the supervisor would
    // leave them inert here.
    let attempt_at = std::time::Instant::now();
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
    // B12 #78: persist the evaluation record BEFORE enforcing the decision.
    // As a Reader (a daemon owns the audit DB), a direct insert would fail
    // read-only and, previously, was logged and dropped — leaving the security
    // audit trail with silent holes. Route to the owning daemon instead, and
    // if the record cannot be recorded either way, fail closed: refuse to run
    // the operation rather than execute it unlogged. The decision is enforced
    // below (`match &decision.action`), so returning here never runs the call.
    if let Err(e) =
        persist_audit_record(audit_storage, can_write_audit, audit_ingest, &audit_record).await
    {
        tracing::error!(
            error = %e,
            "refusing to execute tool call: its audit record could not be persisted"
        );
        // The operation is refused, so close the evaluation out as such.
        proxy.observe_outcome(
            &ctx,
            grith_proxy::types::CallOutcome::Denied,
            attempt_at.elapsed(),
        );
        return format!(
            "Error: refusing to execute this tool call because grith could not record it \
             in the audit log ({e}). grith does not run operations it cannot audit."
        );
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
            proxy.observe_outcome(
                &ctx,
                grith_proxy::types::CallOutcome::Executed,
                attempt_at.elapsed(),
            );
            handle_allowed_call(&decision, &call_type, &tool_call.arguments, tui_tx).await
        }
        grith_proxy::types::ProxyAction::Queue { .. } => {
            // The queue path settles its own outcome: it is the only arm whose
            // fate is not known here, and it can resolve minutes later.
            handle_queued_call(
                &decision,
                &ctx,
                attempt_at,
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
            proxy.observe_outcome(
                &ctx,
                grith_proxy::types::CallOutcome::Denied,
                attempt_at.elapsed(),
            );
            handle_denied_call(&decision, reason, tui_tx)
        }
    }
}

/// B12 #78: persist an audit record without ever silently dropping it.
///
/// `grith run` may execute while a daemon owns the audit database, in which
/// case this process is a Reader and a direct insert fails read-only. Route
/// the record to the owning daemon over IPC instead. When neither a local
/// write nor a forward can record the call, return an error so the caller
/// fails closed rather than proceeding as if the call had been logged.
pub(crate) async fn persist_audit_record(
    audit_storage: &std::sync::Arc<std::sync::Mutex<grith_audit::AuditStorage>>,
    can_write_local: bool,
    forward: Option<&crate::daemon::client::DaemonClient>,
    record: &grith_audit::AuditRecord,
) -> anyhow::Result<()> {
    if can_write_local {
        let storage = audit_storage
            .lock()
            .map_err(|_| anyhow::anyhow!("audit storage lock poisoned"))?;
        storage.insert_record(record)?;
        return Ok(());
    }
    match forward {
        Some(client) => client.ingest_audit(record).await.map_err(|e| {
            anyhow::anyhow!("failed to forward audit record to the owning daemon: {e}")
        }),
        None => Err(anyhow::anyhow!(
            "this process does not own the audit database and no owning daemon is reachable \
             to receive the record"
        )),
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
    attempt_at: std::time::Instant,
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
        decision_reason: (!decision.decision_reason.is_empty())
            .then(|| decision.decision_reason.clone()),
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

    // The daemon's notification scan (NotificationDispatcher::spawn_background_tasks)
    // is the single owner of channel delivery: it watches the shared digest queue
    // and sends the permission-request notification for every pending item, from
    // BOTH the built-in agent and the CLI supervisor. Notifying here as well would
    // double-fire (and only ever covered the agent path), so it is intentionally
    // not done inline.

    // A queued call is resolved by a human through one of three routes we can
    // see: the inline terminal prompt, the dashboard UI, or an approve-capable
    // notification channel. When the session is non-interactive AND none of
    // those is present, waiting out the full review_timeout usually just stalls
    // (a queued ssh in CI hangs for the whole window) before the inevitable
    // auto-deny. We can't be *certain* nobody is watching — an external process
    // can resolve the queue directly (a dashboard server without the pid file, a
    // custom integration) — so rather than deny immediately we cap the wait at a
    // short grace window: a prompt external resolver still lands, but a genuinely
    // headless run fails in seconds instead of minutes. Any detectable review
    // route keeps the full timeout.
    let has_review_route = std::io::IsTerminal::is_terminal(&std::io::stdin())
        || crate::daemon::pid::is_dashboard_running().is_some()
        || !notification_dispatcher
            .registry()
            .enabled_channel_ids()
            .is_empty();

    let effective_timeout = if has_review_route {
        review_timeout
    } else {
        let grace = review_timeout.min(NO_REVIEWER_GRACE);
        tracing::info!(
            item_id = %digest_item.id,
            score = decision.composite_score,
            grace_secs = grace.as_secs(),
            "no detectable reviewer (no tty, dashboard, or notification channel); \
             capping the review wait at a short grace before auto-deny"
        );
        grace
    };

    // Interactive inline review (shows detail + key prompt in terminal), or a
    // silent poll bounded by effective_timeout when there is no tty.
    let outcome = grith_cli::run_inline_review(digest_queue, &digest_item, effective_timeout).await;

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

    // Settle the evaluation on the fate the human (or the timeout) chose. The
    // commit is stamped at the ATTEMPT, not now: a review can take minutes,
    // far longer than the windows stateful filters read.
    proxy.observe_outcome(
        ctx,
        match outcome {
            grith_digest::ReviewOutcome::Approved => grith_proxy::types::CallOutcome::Executed,
            grith_digest::ReviewOutcome::Denied | grith_digest::ReviewOutcome::TimedOut => {
                grith_proxy::types::CallOutcome::Denied
            }
        },
        attempt_at.elapsed(),
    );

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
///
/// Paths are resolved (`..`, `.` and symlinks) before the call is returned, so
/// the proxy scores what will actually be touched and `execute_operation`
/// then acts on that same resolved path — closing the laundering hole in
/// go-live review B3 and the score-one-path/execute-another window with it.
///
/// The description keeps the path the model asked for, since that is what the
/// user recognises in the transcript; the audit record carries the resolved
/// form via the call type.
pub fn parse_tool_call(
    tool_call: &grith_llm::ToolCall,
) -> anyhow::Result<(grith_proxy::types::ToolCallType, String)> {
    let (call_type, description) = parse_tool_call_unresolved(tool_call)?;
    Ok((call_type.resolve_paths(), description))
}

fn parse_tool_call_unresolved(
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
            let mut builder = match method.to_uppercase().as_str() {
                "GET" => client.get(url),
                "POST" => client.post(url),
                "PUT" => client.put(url),
                "DELETE" => client.delete(url),
                "PATCH" => client.patch(url),
                "HEAD" => client.head(url),
                _ => return format!("Unsupported HTTP method: {method}"),
            };
            // Attach the request body for body-bearing methods. It is already in
            // `ctx.arguments` (== the tool call args), so secret_scan / dlp_gate
            // have already scanned it before this executes (C1) — a proxy DENY
            // never reaches this path.
            if let Some(body) = arguments.get("body").and_then(|v| v.as_str()) {
                if matches!(method.to_uppercase().as_str(), "POST" | "PUT" | "PATCH") {
                    builder = builder.body(body.to_string());
                }
            }
            match builder.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    match resp.text().await {
                        Ok(body) if body.len() > 10000 => {
                            // Truncate at a UTF-8 char boundary — a raw `&body[..5000]`
                            // byte slice panics when byte 5000 lands mid-codepoint.
                            let mut end = 5000.min(body.len());
                            while end > 0 && !body.is_char_boundary(end) {
                                end -= 1;
                            }
                            format!(
                                "HTTP {} ({} bytes)\n{}...[truncated]",
                                status,
                                body.len(),
                                &body[..end]
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
                    // `tokio::fs::File::write_all` buffers internally, so the
                    // bytes aren't guaranteed visible to subsequent readers
                    // until `flush()` awaits the OS write. Without this,
                    // callers (or tests) that read the file immediately
                    // after this returns can race the flush on a stressed
                    // runtime.
                    match file.write_all(content.as_bytes()).await {
                        Ok(()) => match file.flush().await {
                            Ok(()) => format!("Appended {} bytes to {path}", content.len()),
                            Err(e) => format!("Error flushing {path}: {e}"),
                        },
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
        grith_proxy::types::ToolCallType::FileLink {
            target,
            link_path,
            symbolic,
        } => {
            // Supervisor-originated call type: the built-in agent exposes no
            // link-creation tool, so this is only reachable if one is added
            // later. Refuse rather than silently creating a link, since a
            // link is a durable alias to data the proxy scored once.
            let kind = if *symbolic { "symbolic" } else { "hard" };
            format!("Link creation is not an executable operation for the built-in agent ({kind} link {link_path} -> {target})")
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
        // PR 6 Phase B: category-2 syscalls. These are supervisor-side
        // (syscall-interception) shapes, not LLM-driven; the agent
        // path never produces them. Return a placeholder rather than
        // attempting execution.
        grith_proxy::types::ToolCallType::OwnershipChange { .. }
        | grith_proxy::types::ToolCallType::FilesystemMutation { .. }
        | grith_proxy::types::ToolCallType::CrossProcessAccess { .. }
        | grith_proxy::types::ToolCallType::NamespaceOp { .. } => {
            "PR 6 syscall-interception shape not executable from the agent path".into()
        }
        // Decoded from a supervised tool's write to a D-Bus socket. Like the
        // shapes above it only exists on the interception path — the built-in
        // agent has no bus connection to write to.
        grith_proxy::types::ToolCallType::DbusMethodCall { .. } => {
            "D-Bus method call not executable from the agent path".into()
        }
    }
}

/// Forward a proxy evaluation event to the dashboard server via HTTP POST.
/// This is used when the dashboard runs as a separate process (no in-process ws_tx).
///
/// Posts to the bearer-authed `/api/ipc/events` endpoint (not the
/// browser-facing surface) using the daemon IPC token written by the dashboard
/// process to `~/.config/grith/daemon.token`, mirroring the supervisor's
/// `DaemonClient::forward_event`. Without the token the server rejects the
/// injection, so the dashboard has no unauthenticated event-injection route.
pub async fn forward_event_to_dashboard(dashboard_url: &str, event: &serde_json::Value) {
    let url = format!("{dashboard_url}/api/ipc/events");
    let client = reqwest::Client::new();
    let mut request = client
        .post(&url)
        .json(event)
        .timeout(std::time::Duration::from_secs(2));
    if let Some(token) = crate::daemon::token::read_token() {
        request = request.bearer_auth(token);
    }
    let _ = request.send().await;
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

    fn sample_audit_record() -> grith_audit::AuditRecord {
        grith_audit::AuditRecord::new(
            uuid::Uuid::new_v4(),
            "agent".into(),
            "FileRead(/tmp/x)".into(),
            &serde_json::json!({}),
            0.0,
            grith_audit::ProxyActionSummary::Allow,
            vec![],
            0.0,
            None,
        )
    }

    /// B12 #78: the Owner writes the record to its local database.
    #[tokio::test]
    async fn persist_audit_record_owner_writes_locally() {
        use std::sync::{Arc, Mutex};
        let storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let record = sample_audit_record();
        persist_audit_record(&storage, true, None, &record)
            .await
            .expect("owner must write locally");
        assert_eq!(storage.lock().unwrap().count().unwrap(), 1);
    }

    /// B12 #78: a Reader with no reachable owner fails closed — it returns an
    /// error (so the caller refuses to run the call) and writes nothing
    /// locally, rather than silently dropping the record.
    #[tokio::test]
    async fn persist_audit_record_reader_without_forward_fails_closed() {
        use std::sync::{Arc, Mutex};
        let storage = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open_in_memory().unwrap(),
        ));
        let record = sample_audit_record();
        let result = persist_audit_record(&storage, false, None, &record).await;
        assert!(
            result.is_err(),
            "a reader with no forward client must fail closed"
        );
        assert_eq!(
            storage.lock().unwrap().count().unwrap(),
            0,
            "fail-closed must not write locally"
        );
    }
}
