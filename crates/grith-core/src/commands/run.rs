// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith run` subcommand — execute a single task or start the interactive REPL.

use crate::agent::telemetry::{
    collect_session_audit_summary, print_session_summary, SessionAuditSummary, SessionTelemetry,
};
use crate::agent::{self, AgentLoopContext, AGENT_SYSTEM_PROMPT, MAX_TOOL_ROUNDS};
use crate::{daemon, helpers};
use std::io::Write;
use std::time::{Duration, Instant};

fn repl_policy_scope(default_provider: &str) -> Option<String> {
    let cfg = crate::profile_updates::load_effective_profiles().ok()?;
    let provider_override = cfg
        .provider_overlays
        .iter()
        .any(|overlay| overlay.name == default_provider)
        .then_some(default_provider);
    cfg.build_effective_policy("grith-repl", None, provider_override)
        .ok()
        .map(|policy| policy.scope_key)
}

pub fn cmd_repl(
    daemon: &daemon::Daemon,
    ws_tx: Option<tokio::sync::broadcast::Sender<String>>,
    dashboard_url: Option<&str>,
    project_override: Option<&str>,
    enable_color: bool,
) -> anyhow::Result<()> {
    tracing::info!("starting interactive REPL");

    let router = daemon.create_llm_router()?;

    let repl_config = grith_cli::ReplConfig {
        version: env!("CARGO_PKG_VERSION").to_string(),
        model_name: daemon.model_name().to_string(),
        filter_count: daemon.filter_count(),
        max_tool_rounds: MAX_TOOL_ROUNDS,
        system_prompt: Some(AGENT_SYSTEM_PROMPT.to_string()),
    };

    let mut session = grith_cli::ReplSession::new(&repl_config);

    let health = daemon.health_check();
    if !health.is_healthy() {
        let report = daemon::format_health_report(&health);
        eprintln!("{report}");
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let _sync_handle = if daemon.config.general.audit_sync {
        runtime.spawn(daemon::Daemon::audit_sync_task(
            daemon.audit_storage.clone(),
            daemon.subscribe_shutdown(),
        ))
    } else {
        runtime.spawn(async {})
    };

    let tools = agent::tools::agent_tool_definitions();
    let session_id = uuid::Uuid::new_v4();
    let session_name = project_override
        .map(|s| s.to_string())
        .unwrap_or_else(helpers::derive_session_name_from_cwd);
    let mut call_seq = 0u64;
    let session_started = Instant::now();
    let mut telemetry = SessionTelemetry::default();
    let repl_policy_scope = repl_policy_scope(&daemon.config.llm.default_provider);

    // B12 #78: when another process owns the audit database this one is a
    // Reader and cannot write it. Establish a client to the owning daemon so
    // audit records are forwarded rather than dropped against a read-only
    // handle; if the owner is unreachable, evaluation records fail closed at
    // write time rather than executing unlogged.
    let can_write_audit = daemon.audit_role.can_write();
    let audit_forward_client = (!can_write_audit)
        .then(crate::daemon::client::DaemonClient::connect)
        .flatten();

    // Detect whether we have a TTY for the TUI
    let use_tui = std::io::IsTerminal::is_terminal(&std::io::stdout())
        && std::io::IsTerminal::is_terminal(&std::io::stdin());

    if use_tui {
        // --- TUI mode: spawn TUI on separate thread, drive agent from main ---
        let (agent_tx, agent_rx) = std::sync::mpsc::channel();
        let (input_tx, mut input_rx) = tokio::sync::mpsc::channel(16);

        let tui_state = grith_cli::tui::state::AppState::new(
            grith_cli::tui::state::AppMode::Repl {
                model: daemon.model_name().to_string(),
            },
            daemon.filter_count(),
        );

        let tui_handle = std::thread::spawn(move || {
            grith_cli::tui::run_tui(tui_state, agent_rx, Some(input_tx))
        });

        let agent_tx_clone = agent_tx.clone();
        let run_result = runtime.block_on(async {
            while let Some(grith_cli::tui::events::TuiInput::Prompt(text)) = input_rx.recv().await {
                let result = session.process_input(&text);
                match result {
                    grith_cli::ProcessResult::Continue => {
                        let review_timeout =
                            Duration::from_secs(daemon.config.proxy.review_timeout_seconds);
                        let mut agent_ctx = AgentLoopContext {
                            proxy: &daemon.proxy,
                            audit_storage: &daemon.audit_storage,
                            can_write_audit,
                            audit_ingest: audit_forward_client.as_ref(),
                            digest_queue: &daemon.digest_queue,
                            dlp_redactor: &daemon.dlp_redactor,
                            correlation_tracker: daemon.correlation_tracker.as_ref(),
                            notification_dispatcher: &daemon.notification_dispatcher,
                            containment_tracker: &daemon.containment_tracker,
                            ws_tx: ws_tx.as_ref(),
                            dashboard_url,
                            session_id,
                            session_name: &session_name,
                            policy_scope: repl_policy_scope.as_deref(),
                            call_seq: &mut call_seq,
                            telemetry: &mut telemetry,
                            max_rounds: repl_config.max_tool_rounds,
                            review_timeout,
                            tui_tx: Some(agent_tx.clone()),
                        };
                        if let Err(e) =
                            agent::run_agent_loop(&mut session, &router, &tools, &mut agent_ctx)
                                .await
                        {
                            let _ = agent_tx
                                .send(grith_cli::tui::events::AgentEvent::Error(e.to_string()));
                        }
                        // Send a blank line after agent response
                        let _ = agent_tx.send(grith_cli::tui::events::AgentEvent::TextChunk {
                            text: String::new(),
                            dim: true,
                        });
                    }
                    grith_cli::ProcessResult::Exit => break,
                    grith_cli::ProcessResult::CommandOutput(output) => {
                        let _ = agent_tx.send(grith_cli::tui::events::AgentEvent::TextChunk {
                            text: output,
                            dim: true,
                        });
                    }
                    grith_cli::ProcessResult::DigestReview => {
                        let _ = agent_tx.send(grith_cli::tui::events::AgentEvent::TextChunk {
                            text: "Use [d] key to open digest queue".to_string(),
                            dim: true,
                        });
                    }
                    grith_cli::ProcessResult::AuditList { count } => {
                        match crate::commands::audit::recent_entries_verified(daemon, count) {
                            Ok((_total, recent)) => {
                                for record in &recent {
                                    let _ = agent_tx.send(
                                        grith_cli::tui::events::AgentEvent::TextChunk {
                                            text: format!(
                                                "[{}] {} {} -> {} (score: {:.1})",
                                                record.timestamp.format("%H:%M:%S"),
                                                record.plugin_id,
                                                record.tool_call_type,
                                                record.proxy_action,
                                                record.composite_score,
                                            ),
                                            dim: true,
                                        },
                                    );
                                }
                            }
                            Err(e) => {
                                let _ = agent_tx
                                    .send(grith_cli::tui::events::AgentEvent::Error(e.to_string()));
                            }
                        }
                    }
                    grith_cli::ProcessResult::ProxyTest { call_desc } => {
                        let val: serde_json::Value = match serde_json::from_str(&call_desc) {
                            Ok(v) => v,
                            Err(e) => {
                                let _ = agent_tx.send(grith_cli::tui::events::AgentEvent::Error(
                                    format!("Invalid JSON: {e}"),
                                ));
                                continue;
                            }
                        };
                        let call_type: grith_proxy::types::ToolCallType =
                            match serde_json::from_value(val.clone()) {
                                Ok(ct) => ct,
                                Err(e) => {
                                    let _ =
                                        agent_tx.send(grith_cli::tui::events::AgentEvent::Error(
                                            format!("Invalid tool call format: {e}"),
                                        ));
                                    continue;
                                }
                            };
                        let mut ctx = grith_proxy::types::ToolCallContext::new(
                            "repl-test",
                            call_type,
                            session_id,
                        );
                        ctx.arguments = val;
                        ctx.profile_name = repl_policy_scope.clone();
                        let decision = daemon.proxy.evaluate(&ctx).await;
                        let _ = agent_tx.send(grith_cli::tui::events::AgentEvent::TextChunk {
                            text: format!(
                                "Score: {:.1} -> {}",
                                decision.composite_score, decision.action
                            ),
                            dim: false,
                        });
                    }
                    _ => {}
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        // Drop the sender so the TUI thread sees Disconnected
        drop(agent_tx_clone);

        // Wait for TUI thread to finish
        match tui_handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "TUI thread returned error"),
            Err(_) => tracing::warn!("TUI thread panicked"),
        }

        run_result?;
    } else {
        // --- Fallback: plain text REPL (no TTY) ---
        let banner = session.banner(env!("CARGO_PKG_VERSION"));
        println!("{banner}");
        println!("Type /help for commands, /quit to exit\n");

        loop {
            let pending = daemon.digest_queue.count_pending().unwrap_or(0);
            let prompt = grith_cli::repl::prompt_string(pending);
            print!("{prompt}");
            std::io::stdout().flush()?;

            let mut input = String::new();
            if std::io::stdin().read_line(&mut input)? == 0 {
                break;
            }
            let input = input.trim();
            if input.is_empty() {
                continue;
            }

            let result = session.process_input(input);
            match result {
                grith_cli::ProcessResult::Continue => {
                    let review_timeout =
                        Duration::from_secs(daemon.config.proxy.review_timeout_seconds);
                    let mut agent_ctx = AgentLoopContext {
                        proxy: &daemon.proxy,
                        audit_storage: &daemon.audit_storage,
                        can_write_audit,
                        audit_ingest: audit_forward_client.as_ref(),
                        digest_queue: &daemon.digest_queue,
                        dlp_redactor: &daemon.dlp_redactor,
                        correlation_tracker: daemon.correlation_tracker.as_ref(),
                        notification_dispatcher: &daemon.notification_dispatcher,
                        containment_tracker: &daemon.containment_tracker,
                        ws_tx: ws_tx.as_ref(),
                        dashboard_url,
                        session_id,
                        session_name: &session_name,
                        policy_scope: repl_policy_scope.as_deref(),
                        call_seq: &mut call_seq,
                        telemetry: &mut telemetry,
                        max_rounds: repl_config.max_tool_rounds,
                        review_timeout,
                        tui_tx: None,
                    };
                    if let Err(e) = runtime.block_on(agent::run_agent_loop(
                        &mut session,
                        &router,
                        &tools,
                        &mut agent_ctx,
                    )) {
                        eprintln!("Error: {e}");
                    }
                    println!();
                }
                grith_cli::ProcessResult::DigestReview => {
                    if let Err(e) =
                        runtime.block_on(grith_cli::run_digest_review_session(&daemon.digest_queue))
                    {
                        eprintln!("Error opening digest review: {e}");
                    }
                }
                grith_cli::ProcessResult::CommandOutput(output) => {
                    print!("{output}");
                }
                grith_cli::ProcessResult::Exit => {
                    break;
                }
                grith_cli::ProcessResult::AuditList { count } => {
                    match crate::commands::audit::recent_entries_verified(daemon, count) {
                        Ok((total, recent)) => {
                            println!("Audit log: {total} total entries (showing last {count})");
                            if recent.is_empty() {
                                println!("  No audit entries yet.");
                            } else {
                                for record in &recent {
                                    println!(
                                        "  [{}] {} {} -> {} (score: {:.1})",
                                        record.timestamp.format("%H:%M:%S"),
                                        record.plugin_id,
                                        record.tool_call_type,
                                        record.proxy_action,
                                        record.composite_score,
                                    );
                                }
                            }
                        }
                        Err(e) => eprintln!("Error loading audit entries: {e}"),
                    }
                }
                grith_cli::ProcessResult::ProxyTest { call_desc } => {
                    let val: serde_json::Value = match serde_json::from_str(&call_desc) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!(
                                "Invalid JSON: {e}\n  Expected: {{\"type\": \"FileRead\", \"path\": \"/etc/passwd\"}}"
                            );
                            continue;
                        }
                    };
                    let call_type: grith_proxy::types::ToolCallType =
                        match serde_json::from_value(val.clone()) {
                            Ok(ct) => ct,
                            Err(e) => {
                                eprintln!("Invalid tool call format: {e}");
                                continue;
                            }
                        };
                    let mut ctx = grith_proxy::types::ToolCallContext::new(
                        "repl-test",
                        call_type,
                        session_id,
                    );
                    ctx.arguments = val;
                    ctx.profile_name = repl_policy_scope.clone();
                    let decision = runtime.block_on(daemon.proxy.evaluate(&ctx));
                    crate::commands::proxy::print_proxy_decision(&ctx, &decision, daemon);
                }
                _ => {}
            }
        }
    }

    let audit_summary = match collect_session_audit_summary(&daemon.audit_storage, session_id) {
        Ok(summary) => summary,
        Err(e) => {
            tracing::warn!(error = %e, "failed to collect session audit summary");
            SessionAuditSummary::default()
        }
    };
    print_session_summary(
        &audit_summary,
        &telemetry,
        &daemon.config.llm.default_provider,
        daemon.model_name(),
        session_started.elapsed(),
        &session_name,
        session_id,
        enable_color,
    );

    Ok(())
}

pub fn cmd_run(
    daemon: &daemon::Daemon,
    task: &str,
    ws_tx: Option<tokio::sync::broadcast::Sender<String>>,
    dashboard_url: Option<&str>,
    project_override: Option<&str>,
    enable_color: bool,
) -> anyhow::Result<()> {
    // B12 #78: resolve audit ownership and connect a forward client to the
    // owning daemon BEFORE entering the current-thread runtime — connect()
    // blocks on a health check, which must not run via block_in_place inside a
    // current_thread runtime. See cmd_repl for the same rationale.
    let can_write_audit = daemon.audit_role.can_write();
    let audit_forward_client = (!can_write_audit)
        .then(crate::daemon::client::DaemonClient::connect)
        .flatten();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(cmd_run_async(
        daemon,
        task,
        ws_tx,
        dashboard_url,
        project_override,
        enable_color,
        can_write_audit,
        audit_forward_client,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn cmd_run_async(
    daemon: &daemon::Daemon,
    task: &str,
    ws_tx: Option<tokio::sync::broadcast::Sender<String>>,
    dashboard_url: Option<&str>,
    project_override: Option<&str>,
    enable_color: bool,
    can_write_audit: bool,
    audit_forward_client: Option<crate::daemon::client::DaemonClient>,
) -> anyhow::Result<()> {
    tracing::info!(%task, "executing single task");

    let _sync_handle = if daemon.config.general.audit_sync {
        tokio::spawn(daemon::Daemon::audit_sync_task(
            daemon.audit_storage.clone(),
            daemon.subscribe_shutdown(),
        ))
    } else {
        tokio::spawn(async {})
    };

    let router = daemon.create_llm_router()?;

    let repl_config = grith_cli::ReplConfig {
        version: env!("CARGO_PKG_VERSION").to_string(),
        model_name: daemon.model_name().to_string(),
        filter_count: daemon.filter_count(),
        max_tool_rounds: MAX_TOOL_ROUNDS,
        system_prompt: Some(AGENT_SYSTEM_PROMPT.to_string()),
    };

    let mut session = grith_cli::ReplSession::new(&repl_config);
    session.process_input(task);

    let tools = agent::tools::agent_tool_definitions();
    let session_id = uuid::Uuid::new_v4();
    let session_name = project_override
        .map(|s| s.to_string())
        .unwrap_or_else(helpers::derive_session_name_from_cwd);
    let mut call_seq = 0u64;
    let session_started = Instant::now();
    let mut telemetry = SessionTelemetry::default();
    let repl_policy_scope = repl_policy_scope(&daemon.config.llm.default_provider);

    let review_timeout = Duration::from_secs(daemon.config.proxy.review_timeout_seconds);
    let mut agent_ctx = AgentLoopContext {
        proxy: &daemon.proxy,
        audit_storage: &daemon.audit_storage,
        can_write_audit,
        audit_ingest: audit_forward_client.as_ref(),
        digest_queue: &daemon.digest_queue,
        dlp_redactor: &daemon.dlp_redactor,
        correlation_tracker: daemon.correlation_tracker.as_ref(),
        notification_dispatcher: &daemon.notification_dispatcher,
        containment_tracker: &daemon.containment_tracker,
        ws_tx: ws_tx.as_ref(),
        dashboard_url,
        session_id,
        session_name: &session_name,
        policy_scope: repl_policy_scope.as_deref(),
        call_seq: &mut call_seq,
        telemetry: &mut telemetry,
        max_rounds: repl_config.max_tool_rounds,
        review_timeout,
        tui_tx: None,
    };
    let result = agent::run_agent_loop(&mut session, &router, &tools, &mut agent_ctx).await;

    let audit_summary = match collect_session_audit_summary(&daemon.audit_storage, session_id) {
        Ok(summary) => summary,
        Err(e) => {
            tracing::warn!(error = %e, "failed to collect session audit summary");
            SessionAuditSummary::default()
        }
    };
    print_session_summary(
        &audit_summary,
        &telemetry,
        &daemon.config.llm.default_provider,
        daemon.model_name(),
        session_started.elapsed(),
        &session_name,
        session_id,
        enable_color,
    );

    result
}

#[cfg(test)]
mod tests {
    use super::repl_policy_scope;

    #[test]
    fn repl_policy_scope_includes_known_provider_overlay() {
        let scope = repl_policy_scope("openai").expect("scope should resolve");
        assert!(
            scope.starts_with("grith-repl"),
            "scope should start with base profile, got: {scope}"
        );
        assert!(
            scope.contains("+provider:openai"),
            "scope should contain provider overlay, got: {scope}"
        );
    }

    #[test]
    fn repl_policy_scope_falls_back_to_base_profile_for_unknown_provider() {
        let scope = repl_policy_scope("unknown-provider").expect("base scope should resolve");
        assert!(
            scope.starts_with("grith-repl"),
            "scope should start with base profile, got: {scope}"
        );
        assert!(
            !scope.contains("+provider:"),
            "scope should not contain a provider overlay for unknown provider, got: {scope}"
        );
    }
}
