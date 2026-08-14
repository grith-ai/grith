// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Session-level telemetry collection and summary reporting.
//!
//! Tracks token usage, tool call breakdowns, costs, proxy decisions, and timing
//! data for a single agent session, then renders a human-readable summary to
//! the terminal when the session ends.

use crossterm::style::{Color, Stylize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use crate::helpers::{
    format_duration, format_provider_name, ordered_tool_breakdown, print_summary_line,
    print_summary_row, printable_tool_rows,
};

/// Accumulates telemetry for a single agent session (tokens, costs, tool calls).
#[derive(Debug, Default, Clone)]
pub struct SessionTelemetry {
    pub tool_call_count: usize,
    pub tool_call_breakdown: BTreeMap<String, usize>,
    pub total_prompt_tokens: usize,
    pub total_completion_tokens: usize,
    pub total_tokens: usize,
    pub total_cost_usd: f64,
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
}

// Note: build/test "quality" inference (classifying shell calls as build/test
// and guessing success from exit codes) was removed — grith intercepts syscalls
// and cannot truthfully attest build or test outcomes, so the session summary no
// longer reports a "Quality" column.

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

/// Render a formatted session summary to the terminal (tools, costs, security).
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
    print_summary_line("Security:", None, true, enable_color);
    print_summary_line(
        &format!("├ Allowed     {:>3} ({:.0}%)", audit.allowed, allowed_pct),
        Some(Color::DarkGrey),
        false,
        enable_color,
    );
    print_summary_line(
        &format!("├ Quarantined {:>3}", audit.queued),
        Some(Color::DarkGrey),
        false,
        enable_color,
    );
    print_summary_line(
        &format!("└ Denied      {:>3}", audit.denied),
        Some(Color::DarkGrey),
        false,
        enable_color,
    );
}

/// Data for the supervisor (`grith exec`) end-of-session summary. The supervisor
/// observes OS syscalls of an external tool, so it has no LLM provider / model /
/// cost — those fields are intentionally absent here.
#[derive(Debug, Default, Clone)]
pub struct SupervisorSummary {
    pub tool_name: String,
    pub profile: Option<String>,
    /// Human-facing session name (`--project` or the working-directory name).
    pub project: Option<String>,
    pub session_id: uuid::Uuid,
    pub duration: Duration,
    /// Total OS syscalls intercepted (includes noise short-circuited pre-proxy).
    pub intercepted: u64,
    /// Syscalls short-circuited as routine noise before proxy evaluation.
    pub noise: u64,
    pub allowed: usize,
    pub queued: usize,
    pub denied: usize,
    /// Per-operation-type counts of proxy-evaluated actions (from the audit log).
    /// Empty when running thin-client (audit lives in the daemon); the tree is
    /// then omitted and only the aggregate counts are shown.
    pub breakdown: BTreeMap<String, usize>,
    /// Local dashboard deep link that opens its existing social-share menu.
    pub share_url: Option<String>,
    /// Pricing URL for Community users; absent for paid or unknown tiers.
    pub upgrade_url: Option<String>,
}

// Terminal equivalents of the dark-background palette in grith's brand guide.
const BRAND_GREEN: Color = Color::Rgb {
    r: 0,
    g: 229,
    b: 160,
};
const BRAND_TEXT: Color = Color::Rgb {
    r: 228,
    g: 228,
    b: 236,
};
const BRAND_TEXT_SECONDARY: Color = Color::Rgb {
    r: 148,
    g: 150,
    b: 168,
};
const BRAND_TEXT_DIM: Color = Color::Rgb {
    r: 92,
    g: 94,
    b: 114,
};
const BRAND_AMBER: Color = Color::Rgb {
    r: 255,
    g: 179,
    b: 71,
};
const BRAND_RED: Color = Color::Rgb {
    r: 255,
    g: 77,
    b: 106,
};
const BRAND_BLUE: Color = Color::Rgb {
    r: 77,
    g: 166,
    b: 255,
};

const METRIC_COLUMN_WIDTH: usize = 25;
const SUMMARY_BAR_WIDTH: usize = 36;
const ACTIVITY_BAR_WIDTH: usize = 24;

fn summary_style(text: impl Into<String>, color: Color, bold: bool, enabled: bool) -> String {
    let text = text.into();
    if !enabled {
        return text;
    }
    let styled = text.with(color);
    if bold {
        styled.bold().to_string()
    } else {
        styled.to_string()
    }
}

fn format_count(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    grouped
}

fn summary_percentage(part: u64, total: u64, empty_value: f64) -> f64 {
    if total == 0 {
        empty_value
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

fn format_percentage(value: f64) -> String {
    if (value - value.round()).abs() < 0.001 {
        format!("{value:.0}%")
    } else {
        format!("{value:.1}%")
    }
}

fn format_summary_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let minutes = (total % 3_600) / 60;
    let seconds = total % 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Return a fixed-width eight-step progress bar as its filled and empty spans.
fn progress_bar(ratio: f64, width: usize) -> (String, String) {
    const PARTIAL_BLOCKS: [&str; 8] = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];

    let ratio = ratio.clamp(0.0, 1.0);
    let eighths = ((ratio * (width * 8) as f64).round() as usize).max(usize::from(ratio > 0.0));
    let full_blocks = eighths / 8;
    let partial = eighths % 8;
    let mut filled = "█".repeat(full_blocks);
    if partial > 0 {
        filled.push_str(PARTIAL_BLOCKS[partial]);
    }
    let occupied = full_blocks + usize::from(partial > 0);
    let empty = "░".repeat(width.saturating_sub(occupied));
    (filled, empty)
}

fn activity_rows(breakdown: &BTreeMap<String, usize>) -> Vec<(String, usize)> {
    const MAX_ROWS: usize = 5;

    let mut rows = breakdown
        .iter()
        .map(|(name, count)| (crate::helpers::display_tool_label(name), *count))
        .collect::<Vec<_>>();
    rows.sort_by(|(a_name, a_count), (b_name, b_count)| {
        b_count.cmp(a_count).then_with(|| a_name.cmp(b_name))
    });

    if rows.len() <= MAX_ROWS {
        return rows;
    }

    let other = rows[MAX_ROWS - 1..]
        .iter()
        .map(|(_, count)| *count)
        .sum::<usize>();
    rows.truncate(MAX_ROWS - 1);
    rows.push(("other".to_string(), other));
    rows
}

/// Build the supervisor end-of-session report.
///
/// Keeping rendering separate from printing makes the no-colour output
/// deterministic and lets tests protect the claims and percentages shown to
/// operators.
pub fn render_supervisor_session_summary(
    summary: &SupervisorSummary,
    enable_color: bool,
) -> String {
    let actions = summary.allowed + summary.queued + summary.denied;
    let allowed_pct = summary_percentage(summary.allowed as u64, actions as u64, 100.0);
    let noise_pct = summary_percentage(summary.noise, summary.intercepted, 0.0);
    let policy_flags = summary.queued + summary.denied;
    let duration = format_summary_duration(summary.duration);
    let session_short = &summary.session_id.to_string()[..8];
    let profile = summary.profile.as_deref().unwrap_or("default");
    let session_name = summary.project.as_deref().unwrap_or("unnamed");
    let mut output = String::new();

    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "  {}  {}",
        summary_style("◆ grith", BRAND_GREEN, true, enable_color),
        summary_style("// SESSION REPORT", BRAND_TEXT, true, enable_color),
    );
    let _ = writeln!(
        output,
        "    {}",
        summary_style(
            "ZERO-TRUST SUPERVISION COMPLETE",
            BRAND_GREEN,
            false,
            enable_color,
        )
    );
    let _ = writeln!(output);

    let _ = writeln!(
        output,
        "  {} {}  ·  {} {}  ·  {} {}",
        summary_style("Session:", BRAND_TEXT_SECONDARY, false, enable_color),
        summary_style(session_name, BRAND_TEXT, true, enable_color),
        summary_style("ID:", BRAND_TEXT_SECONDARY, false, enable_color),
        summary_style(session_short, BRAND_TEXT, true, enable_color),
        summary_style("Duration:", BRAND_TEXT_SECONDARY, false, enable_color),
        summary_style(&duration, BRAND_TEXT, true, enable_color),
    );
    let _ = writeln!(
        output,
        "  {} {}  ·  {} {}",
        summary_style("Tool:", BRAND_TEXT_SECONDARY, false, enable_color),
        summary_style(&summary.tool_name, BRAND_TEXT, false, enable_color),
        summary_style("Profile:", BRAND_TEXT_SECONDARY, false, enable_color),
        summary_style(profile, BRAND_TEXT, false, enable_color),
    );
    let _ = writeln!(output);

    let watched = format!(
        "{:<METRIC_COLUMN_WIDTH$}",
        format_count(summary.intercepted)
    );
    let filtered = format!("{:<METRIC_COLUMN_WIDTH$}", format_count(summary.noise));
    let decisions = format_count(actions as u64);
    let _ = writeln!(
        output,
        "  {}{}{}",
        summary_style(watched, BRAND_GREEN, true, enable_color),
        summary_style(filtered, BRAND_BLUE, true, enable_color),
        summary_style(decisions, BRAND_TEXT, true, enable_color),
    );
    let _ = writeln!(
        output,
        "  {:<METRIC_COLUMN_WIDTH$}{:<METRIC_COLUMN_WIDTH$}POLICY DECISIONS",
        "SYSCALLS WATCHED", "ROUTINE NOISE FILTERED"
    );
    let _ = writeln!(output);

    let _ = writeln!(
        output,
        "  {}",
        summary_style("PROTECTION", BRAND_TEXT_SECONDARY, true, enable_color)
    );
    let (allowed_bar, allowed_remainder) = progress_bar(allowed_pct / 100.0, SUMMARY_BAR_WIDTH);
    let _ = writeln!(
        output,
        "  {}{}  {}",
        summary_style(allowed_bar, BRAND_GREEN, false, enable_color),
        summary_style(allowed_remainder, BRAND_TEXT_DIM, false, enable_color),
        summary_style(
            format!("{} allowed automatically", format_percentage(allowed_pct)),
            BRAND_GREEN,
            true,
            enable_color,
        )
    );
    let _ = writeln!(
        output,
        "  {}  {}     {}  {}     {}  {}",
        summary_style("✓", BRAND_GREEN, true, enable_color),
        summary_style(
            format!("{} allowed", format_count(summary.allowed as u64)),
            BRAND_TEXT,
            false,
            enable_color,
        ),
        summary_style("◇", BRAND_AMBER, true, enable_color),
        summary_style(
            format!("{} quarantined", format_count(summary.queued as u64)),
            BRAND_AMBER,
            false,
            enable_color,
        ),
        summary_style("◆", BRAND_RED, true, enable_color),
        summary_style(
            format!("{} denied", format_count(summary.denied as u64)),
            BRAND_RED,
            false,
            enable_color,
        ),
    );
    let protection_note = if policy_flags == 0 {
        "No policy flags — every evaluated action stayed within policy".to_string()
    } else {
        format!(
            "{} policy flags surfaced for review or enforcement",
            format_count(policy_flags as u64)
        )
    };
    let _ = writeln!(
        output,
        "  {}",
        summary_style(protection_note, BRAND_TEXT_SECONDARY, false, enable_color)
    );
    let _ = writeln!(output);

    let _ = writeln!(
        output,
        "  {}",
        summary_style("QUIET BY DESIGN", BRAND_TEXT_SECONDARY, true, enable_color)
    );
    let (noise_bar, noise_remainder) = progress_bar(noise_pct / 100.0, SUMMARY_BAR_WIDTH);
    let _ = writeln!(
        output,
        "  {}{}  {}",
        summary_style(noise_bar, BRAND_BLUE, false, enable_color),
        summary_style(noise_remainder, BRAND_TEXT_DIM, false, enable_color),
        summary_style(
            format!("{} filtered before policy", format_percentage(noise_pct)),
            BRAND_BLUE,
            true,
            enable_color,
        )
    );
    let _ = writeln!(
        output,
        "  {}",
        summary_style(
            format!(
                "{} routine events handled silently, keeping the session focused",
                format_count(summary.noise)
            ),
            BRAND_TEXT_SECONDARY,
            false,
            enable_color,
        )
    );

    let rows = activity_rows(&summary.breakdown);
    if !rows.is_empty() {
        let _ = writeln!(output);
        let _ = writeln!(
            output,
            "  {}",
            summary_style(
                "TOP POLICY ACTIVITY",
                BRAND_TEXT_SECONDARY,
                true,
                enable_color
            )
        );
        let max_count = rows.iter().map(|(_, count)| *count).max().unwrap_or(0);
        for (tool, count) in rows {
            let ratio = if max_count == 0 {
                0.0
            } else {
                count as f64 / max_count as f64
            };
            let (bar, remainder) = progress_bar(ratio, ACTIVITY_BAR_WIDTH);
            let _ = writeln!(
                output,
                "  {:<16} {}  {}{}",
                tool,
                summary_style(
                    format!("{:>8}", format_count(count as u64)),
                    BRAND_TEXT,
                    false,
                    enable_color,
                ),
                summary_style(bar, BRAND_GREEN, false, enable_color),
                summary_style(remainder, BRAND_TEXT_DIM, false, enable_color),
            );
        }
    }

    if let Some(share_url) = &summary.share_url {
        let _ = writeln!(output);
        let _ = writeln!(
            output,
            "  {}",
            summary_style(
                "SHARE YOUR RESULTS",
                BRAND_TEXT_SECONDARY,
                true,
                enable_color
            )
        );
        let _ = writeln!(
            output,
            "  {}  {}",
            summary_style(
                "↗ Open the social share menu",
                BRAND_GREEN,
                true,
                enable_color
            ),
            summary_style(share_url, BRAND_BLUE, false, enable_color),
        );
    }

    if let Some(upgrade_url) = &summary.upgrade_url {
        let _ = writeln!(output);
        let _ = writeln!(
            output,
            "  {}",
            summary_style(
                "UNLOCK MORE WITH GRITH PRO",
                BRAND_TEXT_SECONDARY,
                true,
                enable_color,
            )
        );
        let _ = writeln!(
            output,
            "  {}",
            summary_style(
                "90-day history · anomaly detection · Slack/email alerts · team policies",
                BRAND_TEXT,
                false,
                enable_color,
            )
        );
        let _ = writeln!(
            output,
            "  {}  {}",
            summary_style("↗ See plans and upgrade", BRAND_GREEN, true, enable_color),
            summary_style(upgrade_url, BRAND_BLUE, false, enable_color),
        );
    }

    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "  {}",
        summary_style(
            format!("Protected end to end for {duration} · session {session_short}"),
            BRAND_TEXT_SECONDARY,
            false,
            enable_color,
        )
    );

    output
}

/// Render the supervisor end-of-session summary to the terminal.
pub fn print_supervisor_session_summary(summary: &SupervisorSummary, enable_color: bool) {
    print!(
        "{}",
        render_supervisor_session_summary(summary, enable_color)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_summary_surfaces_the_protection_work() {
        let mut breakdown = BTreeMap::new();
        breakdown.insert("file_read".to_string(), 37);
        breakdown.insert("file_write".to_string(), 3_688);
        breakdown.insert("dir_list".to_string(), 14);
        breakdown.insert("process_spawn".to_string(), 6_570);
        let summary = SupervisorSummary {
            tool_name: "codex".to_string(),
            profile: Some("codex profile".to_string()),
            project: Some("grith".to_string()),
            session_id: uuid::Uuid::parse_str("3f715e79-0000-0000-0000-000000000000").unwrap(),
            duration: Duration::from_secs(1_834 * 60 + 16),
            intercepted: 1_426_859,
            noise: 1_412_760,
            allowed: 10_141,
            queued: 27,
            denied: 16,
            breakdown,
            share_url: Some("http://127.0.0.1:3141/?share=1".to_string()),
            upgrade_url: Some("https://grith.ai/pricing".to_string()),
        };
        let rendered = render_supervisor_session_summary(&summary, false);

        assert!(rendered.contains("◆ grith  // SESSION REPORT"));
        assert!(rendered.contains("Session: grith  ·  ID: 3f715e79  ·  Duration: 1d 6h 34m"));
        assert!(rendered.contains("Tool: codex  ·  Profile: codex profile"));
        assert!(rendered.contains("1,426,859"));
        assert!(rendered.contains("1,412,760"));
        assert!(rendered.contains("10,184"));
        assert!(rendered.contains("99.6% allowed automatically"));
        assert!(rendered.contains("99.0% filtered before policy"));
        assert!(rendered.contains("43 policy flags surfaced for review or enforcement"));
        assert!(rendered.contains("↗ Open the social share menu  http://127.0.0.1:3141/?share=1"));
        assert!(rendered.contains("↗ See plans and upgrade  https://grith.ai/pricing"));
        assert!(!rendered.contains("100% allowed"));

        let process_spawn = rendered.find("process_spawn").unwrap();
        let file_write = rendered.find("file_write").unwrap();
        let file_read = rendered.find("file_read").unwrap();
        let dir_list = rendered.find("dir_list").unwrap();
        assert!(process_spawn < file_write);
        assert!(file_write < file_read);
        assert!(file_read < dir_list);

        // Kept for a convenient `cargo test ... -- --nocapture` visual check.
        println!("{rendered}");
    }

    #[test]
    fn supervisor_summary_uses_the_website_brand_palette() {
        let summary = SupervisorSummary {
            tool_name: "codex".to_string(),
            session_id: uuid::Uuid::nil(),
            allowed: 1,
            ..Default::default()
        };
        let rendered = render_supervisor_session_summary(&summary, true);

        assert_eq!(
            BRAND_GREEN,
            Color::Rgb {
                r: 0,
                g: 229,
                b: 160
            }
        );
        assert_eq!(
            BRAND_AMBER,
            Color::Rgb {
                r: 255,
                g: 179,
                b: 71
            }
        );
        assert_eq!(
            BRAND_RED,
            Color::Rgb {
                r: 255,
                g: 77,
                b: 106
            }
        );
        assert!(rendered.contains("◆ grith"));
        if std::env::var_os("NO_COLOR").is_none() {
            assert!(rendered.contains("\u{1b}[38;2;0;229;160m"));
            assert!(rendered.contains("\u{1b}[38;2;255;179;71m"));
            assert!(rendered.contains("\u{1b}[38;2;255;77;106m"));
        }
    }

    #[test]
    fn supervisor_summary_handles_zero_actions_and_empty_breakdown() {
        let summary = SupervisorSummary {
            tool_name: "codex".to_string(),
            session_id: uuid::Uuid::nil(),
            ..Default::default()
        };
        let rendered = render_supervisor_session_summary(&summary, false);

        assert!(rendered.contains("100% allowed automatically"));
        assert!(rendered.contains("0% filtered before policy"));
        assert!(rendered.contains("No policy flags — every evaluated action stayed within policy"));
        assert!(!rendered.contains("TOP POLICY ACTIVITY"));
    }

    #[test]
    fn supervisor_summary_does_not_upsell_paid_accounts() {
        let summary = SupervisorSummary {
            tool_name: "codex".to_string(),
            project: Some("paid-project".to_string()),
            session_id: uuid::Uuid::nil(),
            allowed: 42,
            share_url: Some("http://127.0.0.1:3141/?share=1".to_string()),
            // The caller only supplies an upgrade URL for Community accounts.
            upgrade_url: None,
            ..Default::default()
        };
        let rendered = render_supervisor_session_summary(&summary, false);

        assert!(rendered.contains("SHARE YOUR RESULTS"));
        assert!(!rendered.contains("UNLOCK MORE WITH GRITH PRO"));
        assert!(!rendered.contains("See plans and upgrade"));
    }

    #[test]
    fn summary_duration_and_counts_are_human_readable() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_000), "1,000");
        assert_eq!(format_count(1_426_859), "1,426,859");

        assert_eq!(format_summary_duration(Duration::from_secs(12)), "12s");
        assert_eq!(
            format_summary_duration(Duration::from_secs(12 * 60 + 8)),
            "12m 8s"
        );
        assert_eq!(
            format_summary_duration(Duration::from_secs(3 * 3_600 + 5 * 60)),
            "3h 5m"
        );
        assert_eq!(
            format_summary_duration(Duration::from_secs(86_400 + 6 * 3_600 + 34 * 60)),
            "1d 6h 34m"
        );
    }
}
