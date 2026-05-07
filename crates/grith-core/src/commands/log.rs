// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith log` subcommand — display and filter recent audit log entries.

use crate::{daemon, helpers};
use crossterm::style::{Color, Stylize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Install a minimal signal handler that clears `flag` on SIGINT/SIGTERM.
/// Uses only async-signal-safe operations (atomic store).
#[cfg(unix)]
fn install_signal_flag(flag: &'static AtomicBool) {
    // SAFETY: We register a minimal, async-signal-safe handler that only performs
    // an atomic store. The flag reference is `'static` so it is guaranteed to be
    // valid for the lifetime of the signal handler.
    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            sigint_handler as *const () as libc::sighandler_t,
        );
    }
    // Store the flag pointer for the handler to use.
    TAIL_FLAG.store((flag as *const AtomicBool).cast_mut(), Ordering::Release);
}

#[cfg(unix)]
static TAIL_FLAG: std::sync::atomic::AtomicPtr<AtomicBool> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

#[cfg(unix)]
extern "C" fn sigint_handler(_sig: libc::c_int) {
    let ptr = TAIL_FLAG.load(Ordering::Acquire);
    if !ptr.is_null() {
        // SAFETY: `ptr` was set from a `&'static AtomicBool` reference and atomic
        // stores are async-signal-safe.
        unsafe {
            (*ptr).store(false, Ordering::Release);
        }
    }
}

pub fn fetch_log_records(
    daemon: &daemon::Daemon,
    session_filter: Option<&str>,
    limit: usize,
) -> anyhow::Result<Vec<grith_audit::AuditRecord>> {
    let limit = limit.clamp(1, 5000);
    let storage = daemon
        .audit_storage
        .lock()
        .map_err(|_| anyhow::anyhow!("audit storage lock poisoned"))?;

    if let Some(filter) = session_filter {
        if let Ok(sid) = uuid::Uuid::parse_str(filter) {
            let mut records = storage
                .get_by_session(&sid)
                .map_err(|e| anyhow::anyhow!("failed to fetch session logs: {e}"))?;
            if records.len() > limit {
                records = records[records.len() - limit..].to_vec();
            }
            records.reverse();
            return Ok(records);
        }

        let probe = (limit * 20).clamp(limit, 5000);
        let mut records = storage
            .get_recent(probe)
            .map_err(|e| anyhow::anyhow!("failed to fetch recent logs: {e}"))?;
        records.retain(|r| r.task_context.as_deref() == Some(filter));
        records.truncate(limit);
        return Ok(records);
    }

    storage
        .get_recent(limit)
        .map_err(|e| anyhow::anyhow!("failed to fetch recent logs: {e}"))
}

fn format_log_call_type(tool_call_type: &str) -> String {
    let inner = tool_call_type
        .split_once('(')
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .unwrap_or(tool_call_type);
    if tool_call_type.starts_with("FileRead(") {
        return format!("fs.read({inner})");
    }
    if tool_call_type.starts_with("FileWrite(") {
        return format!("fs.write({inner})");
    }
    if tool_call_type.starts_with("DirList(") {
        return format!("fs.list({inner})");
    }
    if tool_call_type.starts_with("ShellExec(") {
        return format!("shell.exec({inner})");
    }
    if tool_call_type.starts_with("HttpRequest(") {
        return format!("http.request({inner})");
    }
    helpers::normalize_tool_call_type_label(tool_call_type)
}

fn format_log_action(action: &grith_audit::ProxyActionSummary, enable_color: bool) -> String {
    let label = match action {
        grith_audit::ProxyActionSummary::Allow => "ALLOW",
        grith_audit::ProxyActionSummary::Queue => "QUEUE",
        grith_audit::ProxyActionSummary::Deny => "DENY",
    };
    if !enable_color {
        return label.to_string();
    }
    match action {
        grith_audit::ProxyActionSummary::Allow => label.with(Color::Green).to_string(),
        grith_audit::ProxyActionSummary::Queue => label.with(Color::Yellow).to_string(),
        grith_audit::ProxyActionSummary::Deny => label.with(Color::Red).to_string(),
    }
}

fn render_log_record(record: &grith_audit::AuditRecord, enable_color: bool) -> String {
    let ts = record.timestamp.format("%H:%M:%S%.3f");
    let action = format_log_action(&record.proxy_action, enable_color);
    let call = format_log_call_type(&record.tool_call_type);
    format!("[{ts}] {action:<5} {call}")
}

pub fn cmd_log(
    daemon: &daemon::Daemon,
    tail: bool,
    session_filter: Option<&str>,
    limit: usize,
    enable_color: bool,
) -> anyhow::Result<()> {
    if tail {
        tracing::info!(session = session_filter, limit, "tailing logs");
        let mut seen = HashSet::new();

        // Use an atomic flag so the loop can exit on Ctrl+C gracefully.
        static RUNNING: AtomicBool = AtomicBool::new(true);
        RUNNING.store(true, Ordering::Release);

        // Install a signal handler that flips the flag instead of aborting.
        #[cfg(unix)]
        {
            install_signal_flag(&RUNNING);
        }

        while RUNNING.load(Ordering::Acquire) {
            let records = fetch_log_records(daemon, session_filter, limit)?;
            for record in records.iter().rev() {
                if seen.insert(record.id) {
                    println!("{}", render_log_record(record, enable_color));
                }
            }
            std::thread::sleep(Duration::from_millis(900));
        }
        tracing::debug!("log tail exiting on signal");
        Ok(())
    } else {
        tracing::info!(session = session_filter, limit, "listing logs");
        let records = fetch_log_records(daemon, session_filter, limit)?;
        if records.is_empty() {
            println!("No logs found.");
            return Ok(());
        }
        for record in records.iter().rev() {
            println!("{}", render_log_record(record, enable_color));
        }
        Ok(())
    }
}
