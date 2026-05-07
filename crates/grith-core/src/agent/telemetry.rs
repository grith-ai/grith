// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Session-level telemetry collection and summary reporting.
//!
//! Tracks token usage, tool call breakdowns, costs, proxy decisions, and timing
//! data for a single agent session, then renders a human-readable summary to
//! the terminal when the session ends.

use crossterm::style::{Color, Stylize};
use std::collections::BTreeMap;
use std::time::Duration;

use crate::helpers::{
    format_duration, format_provider_name, ordered_tool_breakdown, print_summary_row,
    printable_tool_rows, quality_indicator,
};

/// Accumulates telemetry for a single agent session (tokens, costs, tool calls, quality).
#[derive(Debug, Default, Clone)]
pub struct SessionTelemetry {
    pub tool_call_count: usize,
    pub tool_call_breakdown: BTreeMap<String, usize>,
    pub total_prompt_tokens: usize,
    pub total_completion_tokens: usize,
    pub total_tokens: usize,
    pub total_cost_usd: f64,
    pub build_attempts: usize,
    pub build_successes: usize,
    pub test_attempts: usize,
    pub test_successes: usize,
    pub error_count: usize,
}

impl SessionTelemetry {
    pub fn observe_tool_call(&mut self, tool_name: &str) {
        self.tool_call_count += 1;
        *self
            .tool_call_breakdown
            .entry(tool_name.to_lowercase())
            .or_insert(0) += 1;
    }

    pub fn observe_response_usage(
        &mut self,
        response: &grith_llm::CompletionResponse,
        provider: Option<&dyn grith_llm::LlmProvider>,
    ) {
        self.total_prompt_tokens += response.usage.prompt_tokens;
        self.total_completion_tokens += response.usage.completion_tokens;
        self.total_tokens += response.usage.total_tokens;

        if let Some(provider) = provider {
            let estimate = provider.cost_estimate(
                response.usage.prompt_tokens,
                response.usage.completion_tokens,
            );
            self.total_cost_usd += estimate.total_cost;
        }
    }

    pub fn observe_tool_result(&mut self, tool_call: &grith_llm::ToolCall, result: &str) {
        let failed = tool_result_is_failure(result);
        if failed {
            self.error_count += 1;
        }

        match classify_shell_tool_call(tool_call) {
            Some(ShellQualityKind::Build) => {
                self.build_attempts += 1;
                if !failed {
                    self.build_successes += 1;
                }
            }
            Some(ShellQualityKind::Test) => {
                self.test_attempts += 1;
                if !failed {
                    self.test_successes += 1;
                }
            }
            None => {}
        }
    }
}

/// Classification of a shell command for quality tracking (build vs test).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellQualityKind {
    Build,
    Test,
}

/// Classify a shell_exec tool call as a build or test invocation, if applicable.
pub fn classify_shell_tool_call(tool_call: &grith_llm::ToolCall) -> Option<ShellQualityKind> {
    if tool_call.name != "shell_exec" {
        return None;
    }

    let command = tool_call
        .arguments
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_lowercase();
    let args = parse_shell_exec_args(tool_call.arguments.get("args"))
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect::<Vec<_>>();
    let joined = args.join(" ");

    let is_test = (command == "cargo" && args.iter().any(|a| a == "test"))
        || (command == "go" && args.iter().any(|a| a == "test"))
        || command == "pytest"
        || command == "ctest"
        || ((command == "npm" || command == "pnpm" || command == "yarn" || command == "bun")
            && (args.iter().any(|a| a == "test")
                || (args.first().map(String::as_str) == Some("run")
                    && args.get(1).map(String::as_str) == Some("test"))))
        || joined.contains("cargo test")
        || joined.contains("pytest");

    if is_test {
        return Some(ShellQualityKind::Test);
    }

    let is_build = (command == "cargo"
        && args
            .iter()
            .any(|a| matches!(a.as_str(), "build" | "check" | "clippy")))
        || (command == "go" && args.iter().any(|a| a == "build"))
        || (command == "cmake" && args.iter().any(|a| a == "--build"))
        || (command == "make" && args.iter().any(|a| a == "build"))
        || ((command == "npm" || command == "pnpm" || command == "yarn" || command == "bun")
            && (args.iter().any(|a| a == "build")
                || (args.first().map(String::as_str) == Some("run")
                    && args.get(1).map(String::as_str) == Some("build"))))
        || joined.contains("cargo build")
        || joined.contains("cargo check")
        || joined.contains("npm run build");

    if is_build {
        Some(ShellQualityKind::Build)
    } else {
        None
    }
}

/// Parse the `args` field of a shell_exec tool call into a list of strings.
pub fn parse_shell_exec_args(raw_args: Option<&serde_json::Value>) -> Vec<String> {
    match raw_args {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        Some(serde_json::Value::String(s)) => s.split_whitespace().map(|p| p.to_string()).collect(),
        _ => Vec::new(),
    }
}

/// Heuristically determine whether a tool result string indicates failure.
pub fn tool_result_is_failure(result: &str) -> bool {
    let lower = result.to_lowercase();

    if lower.starts_with("operation denied")
        || lower.starts_with("operation queued")
        || lower.starts_with("error ")
        || lower.starts_with("http request error")
    {
        return true;
    }

    if lower.starts_with("exit code: ") && !lower.starts_with("exit code: 0") {
        return true;
    }
    if let Some(pos) = lower.rfind("exit code: ") {
        let suffix = &lower[pos..];
        if !suffix.starts_with("exit code: 0") {
            return true;
        }
    }

    false
}

/// Aggregated proxy decision counts from a session's audit records.
#[derive(Debug, Default, Clone)]
pub struct SessionAuditSummary {
    pub total_actions: usize,
    pub allowed: usize,
    pub queued: usize,
    pub denied: usize,
    pub tool_call_breakdown: BTreeMap<String, usize>,
}

/// Query audit storage and produce an aggregated summary for a given session.
pub fn collect_session_audit_summary(
    audit_storage: &std::sync::Arc<std::sync::Mutex<grith_audit::AuditStorage>>,
    session_id: uuid::Uuid,
) -> anyhow::Result<SessionAuditSummary> {
    let records = audit_storage
        .lock()
        .map_err(|_| anyhow::anyhow!("audit storage lock poisoned"))?
        .get_by_session(&session_id)
        .map_err(|e| anyhow::anyhow!("failed to fetch session audit records: {e}"))?;

    let mut summary = SessionAuditSummary::default();
    for record in records {
        summary.total_actions += 1;
        match record.proxy_action {
            grith_audit::types::ProxyActionSummary::Allow => summary.allowed += 1,
            grith_audit::types::ProxyActionSummary::Queue => summary.queued += 1,
            grith_audit::types::ProxyActionSummary::Deny => summary.denied += 1,
        }

        let label = crate::helpers::normalize_tool_call_type_label(&record.tool_call_type);
        *summary.tool_call_breakdown.entry(label).or_insert(0) += 1;
    }

    Ok(summary)
}

/// Render a formatted session summary to the terminal (tools, costs, security, quality).
pub fn print_session_summary(
    audit: &SessionAuditSummary,
    telemetry: &SessionTelemetry,
    provider: &str,
    model: &str,
    duration: Duration,
    project_name: &str,
    session_id: uuid::Uuid,
    enable_color: bool,
) {
    let total_actions = if audit.total_actions > 0 {
        audit.total_actions
    } else {
        telemetry.tool_call_count
    };
    let allowed_pct = if total_actions == 0 {
        100.0
    } else {
        (audit.allowed as f64 / total_actions as f64) * 100.0
    };

    let breakdown = if audit.tool_call_breakdown.is_empty() {
        telemetry
            .tool_call_breakdown
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect::<Vec<_>>()
    } else {
        audit
            .tool_call_breakdown
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect::<Vec<_>>()
    };
    let breakdown = ordered_tool_breakdown(&breakdown, 4);
    let tool_rows = printable_tool_rows(&breakdown);

    if enable_color {
        let dots = format!(
            "{} {} {}",
            "●".with(Color::Red),
            "●".with(Color::Yellow),
            "●".with(Color::Green)
        );
        println!();
        println!("{}  {}", dots, "SESSION SUMMARY".with(Color::Grey));
    } else {
        println!();
        println!("● ● ●  SESSION SUMMARY");
    }
    println!();
    let session_short = &session_id.to_string()[..8];
    if enable_color {
        println!(
            "{}  {}    {}  {}",
            "Project:".with(Color::Grey),
            project_name.with(Color::Green),
            "Session:".with(Color::Grey),
            session_short.with(Color::DarkGrey),
        );
    } else {
        println!("Project:  {project_name}    Session:  {session_short}");
    }
    println!();
    let headline = format!(
        "Session complete - {} actions | ${:.2} | {:.0}% allowed",
        total_actions, telemetry.total_cost_usd, allowed_pct
    );
    if enable_color {
        println!("{}", headline.with(Color::Green).bold());
    } else {
        println!("{headline}");
    }
    println!();

    print_summary_row(
        &format!("Tool calls: {:>4}", total_actions),
        &format!("Cost:      ${:.2}", telemetry.total_cost_usd),
        None,
        true,
        enable_color,
    );

    for (idx, (tool, count)) in tool_rows.iter().enumerate() {
        let branch = if idx + 1 == tool_rows.len() {
            "└"
        } else {
            "├"
        };
        let left = format!("{branch} {:<14} {:>2}", tool, count);
        let right = match idx {
            0 => format!("Provider:  {}", format_provider_name(provider)),
            1 => format!("Model:     {model}"),
            2 => format!("Duration:  {}", format_duration(duration)),
            _ => String::new(),
        };
        print_summary_row(&left, &right, Some(Color::DarkGrey), false, enable_color);
    }

    println!();
    print_summary_row("Security:", "Quality:", None, true, enable_color);
    print_summary_row(
        &format!("├ Allowed     {:>3} ({:.0}%)", audit.allowed, allowed_pct),
        &format!(
            "├ Build success  {}",
            quality_indicator(
                telemetry.build_attempts,
                telemetry.build_successes,
                enable_color
            )
        ),
        Some(Color::DarkGrey),
        false,
        enable_color,
    );
    print_summary_row(
        &format!("├ Quarantined {:>3}", audit.queued),
        &format!(
            "├ Tests passed   {}",
            quality_indicator(
                telemetry.test_attempts,
                telemetry.test_successes,
                enable_color
            )
        ),
        Some(Color::DarkGrey),
        false,
        enable_color,
    );
    print_summary_row(
        &format!("└ Denied      {:>3}", audit.denied),
        &format!("└ Errors         {}", telemetry.error_count),
        Some(Color::DarkGrey),
        false,
        enable_color,
    );
}
