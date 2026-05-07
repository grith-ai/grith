// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Terminal rendering for supervisor session listings and details.

use crate::render::render_separator;
use crossterm::style::{Color, Stylize};
use grith_supervisor::supervisor::{SessionStats, SessionSummary};
use std::io::Write;

/// Format an uptime duration in seconds into a human-readable string.
///
/// Examples: "0s", "45s", "3m 12s", "2h 15m 4s", "1d 3h 22m".
pub fn format_uptime(seconds: u64) -> String {
    if seconds < 60 {
        return format!("{seconds}s");
    }

    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if days > 0 {
        if hours > 0 || minutes > 0 {
            let mut parts = Vec::new();
            parts.push(format!("{days}d"));
            if hours > 0 {
                parts.push(format!("{hours}h"));
            }
            if minutes > 0 {
                parts.push(format!("{minutes}m"));
            }
            parts.join(" ")
        } else {
            format!("{days}d")
        }
    } else if hours > 0 {
        if minutes > 0 || secs > 0 {
            let mut parts = vec![format!("{hours}h")];
            if minutes > 0 {
                parts.push(format!("{minutes}m"));
            }
            if secs > 0 {
                parts.push(format!("{secs}s"));
            }
            parts.join(" ")
        } else {
            format!("{hours}h")
        }
    } else {
        format!("{minutes}m {secs}s")
    }
}

/// Build a visual proportional bar showing the distribution of allow/queue/deny
/// decisions from session statistics.
///
/// The bar is 30 characters wide and uses colored segments:
/// - Green (`=`) for allowed
/// - Yellow (`~`) for queued
/// - Red (`!`) for denied
///
/// Returns a plain string (with ANSI color codes embedded).
pub fn format_stats_bar(stats: &SessionStats) -> String {
    let total = stats.total_allowed + stats.total_queued + stats.total_denied;
    if total == 0 {
        return format!(
            "[{}] (no decisions yet)",
            ".".repeat(30).with(Color::DarkGrey)
        );
    }

    let bar_width: u64 = 30;
    let allow_width = (stats.total_allowed * bar_width / total) as usize;
    let deny_width = (stats.total_denied * bar_width / total) as usize;
    // Queue gets the remainder so the bar always sums to bar_width.
    let queue_width = (bar_width as usize).saturating_sub(allow_width + deny_width);

    let allow_seg = "=".repeat(allow_width).with(Color::Green).to_string();
    let queue_seg = "~".repeat(queue_width).with(Color::Yellow).to_string();
    let deny_seg = "!".repeat(deny_width).with(Color::Red).to_string();

    format!("[{allow_seg}{queue_seg}{deny_seg}]")
}

/// Render a table-formatted list of supervisor sessions.
///
/// Produces a header, column titles, and one row per session with columns:
/// tool name, PID, uptime, total intercepted, and a stats bar.
pub fn render_session_list(w: &mut impl Write, sessions: &[SessionSummary]) -> std::io::Result<()> {
    writeln!(
        w,
        "{}",
        format!("Supervisor Sessions ({})", sessions.len()).with(Color::Cyan)
    )?;
    render_separator(w)?;

    if sessions.is_empty() {
        writeln!(w, "  No active supervisor sessions.")?;
        return Ok(());
    }

    // Header
    writeln!(
        w,
        "  {:<20} {:<8} {:<12} {:<10} {:<14} Stats",
        "Tool", "PID", "Uptime", "Calls", "Containment"
    )?;
    writeln!(w, "  {}", "-".repeat(88))?;

    for session in sessions {
        let uptime = format_uptime(session.uptime_seconds);
        let calls = session.stats.total_intercepted;
        let bar = format_stats_bar(&session.stats);
        let containment = match session.containment_remaining_seconds {
            Some(secs) => format!("{}s", secs).with(Color::Red).to_string(),
            None => "-".with(Color::DarkGrey).to_string(),
        };

        writeln!(
            w,
            "  {:<20} {:<8} {:<12} {:<10} {:<14} {}",
            truncate(&session.tool_name, 20),
            session.root_pid,
            uptime,
            calls,
            containment,
            bar,
        )?;
    }

    render_separator(w)?;
    Ok(())
}

/// Render a detailed view of a single supervisor session, including its ID,
/// tool name, root PID, uptime, full statistics breakdown, and a visual
/// stats bar.
pub fn render_session_detail(w: &mut impl Write, session: &SessionSummary) -> std::io::Result<()> {
    writeln!(w, "{}", "Supervisor Session Detail".with(Color::Cyan))?;
    render_separator(w)?;

    writeln!(w, "  ID:           {}", session.id)?;
    writeln!(w, "  Tool:         {}", session.tool_name)?;
    writeln!(w, "  Root PID:     {}", session.root_pid)?;
    writeln!(
        w,
        "  Uptime:       {}",
        format_uptime(session.uptime_seconds)
    )?;

    // Containment
    writeln!(w)?;
    match session.containment_remaining_seconds {
        Some(secs) => {
            writeln!(
                w,
                "  Containment:  {}",
                format!("ACTIVE ({secs}s remaining)").with(Color::Red)
            )?;
        }
        None => {
            writeln!(w, "  Containment:  {}", "inactive".with(Color::DarkGrey))?;
        }
    }

    writeln!(w)?;
    writeln!(w, "  {}", "Statistics".with(Color::Cyan))?;

    let stats = &session.stats;
    writeln!(w, "  Intercepted:  {}", stats.total_intercepted)?;
    writeln!(
        w,
        "  Allowed:      {}",
        format!("{}", stats.total_allowed).with(Color::Green)
    )?;
    writeln!(
        w,
        "  Queued:       {}",
        format!("{}", stats.total_queued).with(Color::Yellow)
    )?;
    writeln!(
        w,
        "  Denied:       {}",
        format!("{}", stats.total_denied).with(Color::Red)
    )?;
    writeln!(
        w,
        "  Noise:        {}",
        format!("{}", stats.total_filtered_noise).with(Color::DarkGrey)
    )?;

    // Stats bar
    writeln!(w)?;
    writeln!(w, "  Distribution: {}", format_stats_bar(stats))?;

    // Proportions
    let decision_total = stats.total_allowed + stats.total_queued + stats.total_denied;
    if decision_total > 0 {
        let allow_pct = (stats.total_allowed as f64 / decision_total as f64) * 100.0;
        let queue_pct = (stats.total_queued as f64 / decision_total as f64) * 100.0;
        let deny_pct = (stats.total_denied as f64 / decision_total as f64) * 100.0;
        writeln!(
            w,
            "  Proportions:  {:.1}% allow / {:.1}% queue / {:.1}% deny",
            allow_pct, queue_pct, deny_pct
        )?;
    }

    render_separator(w)?;
    Ok(())
}

/// Truncate a string to a maximum length with ellipsis.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_summary(tool_name: &str, pid: u32, uptime: u64, stats: SessionStats) -> SessionSummary {
        SessionSummary {
            id: Uuid::new_v4(),
            tool_name: tool_name.to_string(),
            project_name: None,
            root_pid: pid,
            uptime_seconds: uptime,
            stats,
            containment_remaining_seconds: None,
        }
    }

    fn make_stats(
        intercepted: u64,
        allowed: u64,
        queued: u64,
        denied: u64,
        noise: u64,
    ) -> SessionStats {
        SessionStats {
            total_intercepted: intercepted,
            total_allowed: allowed,
            total_queued: queued,
            total_denied: denied,
            total_filtered_noise: noise,
        }
    }

    // --- format_uptime tests ---

    #[test]
    fn format_uptime_seconds_only() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(1), "1s");
        assert_eq!(format_uptime(59), "59s");
    }

    #[test]
    fn format_uptime_minutes_and_seconds() {
        assert_eq!(format_uptime(60), "1m 0s");
        assert_eq!(format_uptime(61), "1m 1s");
        assert_eq!(format_uptime(125), "2m 5s");
        assert_eq!(format_uptime(3599), "59m 59s");
    }

    #[test]
    fn format_uptime_hours() {
        assert_eq!(format_uptime(3600), "1h");
        assert_eq!(format_uptime(3661), "1h 1m 1s");
        assert_eq!(format_uptime(7200), "2h");
        assert_eq!(format_uptime(7320), "2h 2m");
    }

    #[test]
    fn format_uptime_days() {
        assert_eq!(format_uptime(86400), "1d");
        assert_eq!(format_uptime(90000), "1d 1h");
        assert_eq!(format_uptime(90060), "1d 1h 1m");
        assert_eq!(format_uptime(172800), "2d");
    }

    // --- format_stats_bar tests ---

    #[test]
    fn stats_bar_no_decisions() {
        let stats = make_stats(100, 0, 0, 0, 100);
        let bar = format_stats_bar(&stats);
        assert!(bar.contains("no decisions yet"));
    }

    #[test]
    fn stats_bar_all_allowed() {
        let stats = make_stats(100, 100, 0, 0, 0);
        let bar = format_stats_bar(&stats);
        // Should contain a bar (brackets), no "no decisions" text.
        assert!(bar.starts_with('['));
        assert!(bar.contains(']'));
        assert!(!bar.contains("no decisions"));
    }

    #[test]
    fn stats_bar_mixed() {
        let stats = make_stats(100, 60, 30, 10, 0);
        let bar = format_stats_bar(&stats);
        assert!(bar.starts_with('['));
        assert!(bar.contains(']'));
    }

    // --- render_session_list tests ---

    #[test]
    fn render_session_list_empty() {
        let mut buf = Vec::new();
        render_session_list(&mut buf, &[]).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Supervisor Sessions (0)"));
        assert!(output.contains("No active supervisor sessions"));
    }

    #[test]
    fn render_session_list_with_sessions() {
        let sessions = vec![
            make_summary("claude-code", 1234, 3661, make_stats(500, 400, 80, 20, 0)),
            make_summary("codex", 5678, 120, make_stats(50, 45, 3, 2, 0)),
        ];
        let mut buf = Vec::new();
        render_session_list(&mut buf, &sessions).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Supervisor Sessions (2)"));
        assert!(output.contains("claude-code"));
        assert!(output.contains("codex"));
        assert!(output.contains("1234"));
        assert!(output.contains("5678"));
        assert!(output.contains("Tool"));
        assert!(output.contains("PID"));
        assert!(output.contains("Uptime"));
    }

    #[test]
    fn render_session_list_single() {
        let sessions = vec![make_summary("aider", 42, 60, make_stats(10, 8, 1, 1, 0))];
        let mut buf = Vec::new();
        render_session_list(&mut buf, &sessions).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Supervisor Sessions (1)"));
        assert!(output.contains("aider"));
        assert!(output.contains("42"));
    }

    // --- render_session_detail tests ---

    #[test]
    fn render_session_detail_basic() {
        let session = make_summary(
            "claude-code",
            9999,
            7320,
            make_stats(1000, 800, 150, 30, 20),
        );
        let mut buf = Vec::new();
        render_session_detail(&mut buf, &session).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Supervisor Session Detail"));
        assert!(output.contains("claude-code"));
        assert!(output.contains("9999"));
        assert!(output.contains("2h 2m"));
        assert!(output.contains("1000"));
        assert!(output.contains("800"));
        assert!(output.contains("150"));
        assert!(output.contains("30"));
        assert!(output.contains("20"));
        assert!(output.contains("Distribution"));
    }

    #[test]
    fn render_session_detail_shows_proportions() {
        let session = make_summary("codex", 100, 60, make_stats(100, 80, 15, 5, 0));
        let mut buf = Vec::new();
        render_session_detail(&mut buf, &session).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Proportions"));
        assert!(output.contains("80.0% allow"));
        assert!(output.contains("15.0% queue"));
        assert!(output.contains("5.0% deny"));
    }

    #[test]
    fn render_session_detail_no_decisions_no_proportions() {
        let session = make_summary("aider", 1, 5, make_stats(50, 0, 0, 0, 50));
        let mut buf = Vec::new();
        render_session_detail(&mut buf, &session).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Should show the stats bar with "no decisions yet".
        assert!(output.contains("no decisions yet"));
        // Should NOT contain a Proportions line since decision_total is 0.
        assert!(!output.contains("Proportions"));
    }

    #[test]
    fn render_session_detail_contains_id() {
        let session = SessionSummary {
            id: Uuid::nil(),
            tool_name: "test-tool".to_string(),
            project_name: None,
            root_pid: 1,
            uptime_seconds: 0,
            stats: SessionStats::default(),
            containment_remaining_seconds: None,
        };
        let mut buf = Vec::new();
        render_session_detail(&mut buf, &session).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("00000000-0000-0000-0000-000000000000"));
    }

    // --- truncate tests ---

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello world!", 8), "hello...");
    }

    #[test]
    fn truncate_exact_length() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_very_short_max() {
        assert_eq!(truncate("hello", 3), "hel");
    }

    // --- containment display tests ---

    #[test]
    fn render_session_list_shows_containment() {
        let mut session = make_summary("claude-code", 1234, 60, make_stats(100, 80, 15, 5, 0));
        session.containment_remaining_seconds = Some(245);

        let mut buf = Vec::new();
        render_session_list(&mut buf, &[session]).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Containment"));
        assert!(output.contains("245"));
    }

    #[test]
    fn render_session_detail_shows_containment_active() {
        let mut session = make_summary("codex", 100, 60, make_stats(100, 80, 15, 5, 0));
        session.containment_remaining_seconds = Some(300);

        let mut buf = Vec::new();
        render_session_detail(&mut buf, &session).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("ACTIVE"));
        assert!(output.contains("300s remaining"));
    }

    #[test]
    fn render_session_detail_shows_containment_inactive() {
        let session = make_summary("aider", 200, 60, make_stats(50, 40, 8, 2, 0));

        let mut buf = Vec::new();
        render_session_detail(&mut buf, &session).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("inactive"));
    }
}
