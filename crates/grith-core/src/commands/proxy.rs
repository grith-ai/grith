// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith proxy` subcommand — test tool calls against the security proxy and view status.

use crate::daemon;
use grith_proxy::types::{ProxyAction, ToolCallContext, ToolCallType};
use uuid::Uuid;

pub fn cmd_proxy(daemon: &daemon::Daemon, action: crate::ProxyAction) -> anyhow::Result<()> {
    match action {
        crate::ProxyAction::Test { call } => {
            tracing::info!(%call, "testing tool call against proxy");

            let val: serde_json::Value = serde_json::from_str(&call).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid JSON: {e}\nExpected format: {{\"type\": \"FileRead\", \"path\": \"/etc/passwd\"}}"
                )
            })?;

            let call_type: ToolCallType = serde_json::from_value(val.clone()).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid tool call format: {e}\nThe \"type\" field must be one of: \
                         FileRead, FileWrite, FileAppend, FileDelete, DirList, DirCreate, \
                         ShellExec, HttpRequest, FileRename, FileChmod, NetConnect, \
                         NetListen, ProcessSpawn"
                )
            })?;

            let mut ctx = ToolCallContext::new("cli-test", call_type, Uuid::new_v4());
            ctx.arguments = val;

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let decision = rt.block_on(daemon.proxy.evaluate(&ctx));

            print_proxy_decision(&ctx, &decision, daemon);

            match &decision.action {
                ProxyAction::Allow => std::process::exit(0),
                ProxyAction::Queue { .. } => std::process::exit(1),
                ProxyAction::Deny { .. } => std::process::exit(2),
            }
        }
    }
}

pub fn print_proxy_decision(
    ctx: &ToolCallContext,
    decision: &grith_proxy::types::ProxyDecision,
    daemon: &daemon::Daemon,
) {
    let action_str = match &decision.action {
        ProxyAction::Allow => "ALLOW",
        ProxyAction::Queue { priority } => match priority {
            grith_proxy::types::QueuePriority::Low => "QUEUE (Low)",
            grith_proxy::types::QueuePriority::Medium => "QUEUE (Medium)",
            grith_proxy::types::QueuePriority::High => "QUEUE (High)",
            grith_proxy::types::QueuePriority::Critical => "QUEUE (Critical)",
        },
        ProxyAction::Deny { .. } => "DENY",
    };

    let exit_code = match &decision.action {
        ProxyAction::Allow => 0,
        ProxyAction::Queue { .. } => 1,
        ProxyAction::Deny { .. } => 2,
    };

    println!();
    println!("Proxy Test Result");
    println!("{}", "=".repeat(50));
    println!("  Tool call:   {}", ctx.call_type);
    println!("  Score:       {:.1}", decision.composite_score);
    println!("  Decision:    {action_str}");
    println!("  Reason:      {}", decision.decision_reason);
    println!(
        "  Eval time:   {:.2}ms",
        decision.evaluation_time.as_secs_f64() * 1000.0
    );
    println!(
        "  Thresholds:  allow < {}, deny > {}",
        daemon.config.proxy.auto_allow_threshold, daemon.config.proxy.auto_deny_threshold,
    );
    println!("  Filters:     {} active", daemon.filter_count());

    if !decision.filter_results.is_empty() {
        println!();
        println!("  Filter Breakdown:");
        for fr in &decision.filter_results {
            let marker = if fr.matched { "+" } else { "." };
            if fr.matched {
                println!(
                    "    {marker} {:<20} {:>5.1}  [{:<8}]  {}",
                    fr.filter_name, fr.score, fr.severity, fr.message
                );
            } else {
                println!("    {marker} {:<20} {:>5.1}", fr.filter_name, fr.score);
            }
        }
    }

    println!();
    println!("  Exit code:   {exit_code} ({})", action_str.to_lowercase());
    println!();
}
