// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith analytics` subcommand — cloud analytics sync consent and status
//! for this machine.

use std::io::Write as _;

use chrono::Utc;

use crate::analytics_sync::{
    load_consent, load_device, save_consent, AnalyticsConsent, CONSENT_VERSION,
};

pub fn cmd_analytics(
    daemon: &crate::daemon::Daemon,
    action: crate::AnalyticsAction,
) -> anyhow::Result<()> {
    match action {
        crate::AnalyticsAction::Status => cmd_status(daemon),
        crate::AnalyticsAction::Enable { yes } => cmd_enable(yes),
        crate::AnalyticsAction::Disable => cmd_disable(),
        crate::AnalyticsAction::VerifyArchives { from, to } => {
            cmd_verify_archives(daemon, from.as_deref(), to.as_deref())
        }
    }
}

fn print_data_summary() {
    println!("Cloud analytics sync sends aggregated usage metrics from this machine");
    println!("to your team's dashboard at grith.ai:");
    println!();
    println!("  - counts of allowed, queued and denied operations, by hour and day");
    println!("  - security filter activity and score distributions");
    println!("  - session, project, profile and tool names");
    println!("  - AI model usage and estimated cost");
    println!("  - security event summaries (what was blocked, and why)");
    println!();
    println!("Once a day closes, the same information for that day is also");
    println!("uploaded as a single file, one row per operation, to encrypted");
    println!("private storage. It is kept for 90 days.");
    println!();
    println!("It never includes commands, file paths, file contents, prompts or");
    println!("model responses.");
    println!();
    println!("Cloud analytics is included with paid plans and turns on");
    println!("automatically once you are signed in. Turn it off any time with");
    println!("`grith analytics disable`.");
}

fn cmd_enable(yes: bool) -> anyhow::Result<()> {
    let existing = load_consent();
    if existing
        .as_ref()
        .is_some_and(AnalyticsConsent::authorises_upload)
    {
        println!("Cloud analytics sync is already enabled on this machine.");
        return Ok(());
    }

    print_data_summary();
    println!();
    if !yes {
        print!("Enable cloud analytics sync? [y/N] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Cloud analytics sync was not enabled.");
            return Ok(());
        }
    }

    // Preserve the original acceptance time when only re-enabling under the
    // same consent version; a version bump records a fresh acceptance.
    let accepted_at = match existing {
        Some(consent) if consent.consent_version >= CONSENT_VERSION => consent.accepted_at,
        _ => Utc::now(),
    };
    save_consent(&AnalyticsConsent {
        consent_version: CONSENT_VERSION,
        accepted_at,
        enabled: true,
    })?;
    // A revoked device identity blocks the worker permanently; clearing it
    // here lets the daemon register this machine afresh.
    if load_device().is_some_and(|device| device.revoked) {
        crate::analytics_sync::remove_device()?;
    }
    println!("Cloud analytics sync is enabled.");
    println!();
    println!("While the daemon is running and you are signed in to a plan that");
    println!("includes analytics, this machine registers itself and syncs every");
    println!("30 seconds. Check progress with `grith analytics status`.");
    Ok(())
}

fn cmd_disable() -> anyhow::Result<()> {
    match load_consent() {
        Some(consent) if consent.enabled => {
            save_consent(&AnalyticsConsent {
                enabled: false,
                ..consent
            })?;
            println!("Cloud analytics sync is disabled.");
            println!();
            println!("This machine stops uploading and reports itself as sync-disabled.");
            println!("Data already synced stays in your team dashboard; manage it there.");
        }
        _ => println!("Cloud analytics sync is not enabled on this machine."),
    }
    Ok(())
}

fn cmd_status(daemon: &crate::daemon::Daemon) -> anyhow::Result<()> {
    println!("Cloud analytics sync");

    match load_consent() {
        Some(consent) if consent.authorises_upload() => println!(
            "  Consent:  granted {} (v{})",
            consent.accepted_at.format("%Y-%m-%d"),
            consent.consent_version
        ),
        Some(consent) if !consent.enabled => println!("  Consent:  disabled by user"),
        Some(_) => println!("  Consent:  out of date — run `grith analytics enable` to review"),
        None => println!(
            "  Consent:  not recorded yet — turns on automatically with a paid plan\n            \
             (or run `grith analytics enable`)"
        ),
    }

    let signed_in = matches!(crate::license::load_credentials(), Ok(Some(_)));
    println!(
        "  Account:  {}",
        if signed_in {
            "signed in"
        } else {
            "not signed in — run `grith pro login`"
        }
    );

    let entitled = {
        let gate = daemon.feature_gate.read().unwrap();
        gate.allows("cloud_sync") && gate.allows("usage_analytics")
    };
    println!(
        "  Plan:     {}",
        if entitled {
            "analytics included"
        } else {
            "requires a Pro plan"
        }
    );
    println!(
        "  Config:   audit sync {}",
        if daemon.config.general.audit_sync {
            "on"
        } else {
            "off (general.audit_sync)"
        }
    );

    match load_device() {
        Some(device) if device.revoked => println!(
            "  Device:   {} (revoked — re-enable to register again)",
            device.device_id
        ),
        Some(device) => println!(
            "  Device:   {} (registered {})",
            device.device_id,
            device.registered_at.format("%Y-%m-%d")
        ),
        None => println!("  Device:   not registered yet"),
    }

    if let Ok(storage) = daemon.audit_storage.lock() {
        if storage.analytics_schema_present().unwrap_or(false) {
            match storage.analytics_sync_stats() {
                Ok(stats) => {
                    println!(
                        "  Pending:  {} day(s) awaiting upload, {} security event(s)",
                        stats.pending_upload_days, stats.unacked_security_events
                    );
                    if let Some(latest) = stats.latest_local_event_at {
                        println!(
                            "  Local:    latest event {}",
                            latest.format("%Y-%m-%d %H:%M UTC")
                        );
                    }
                }
                Err(error) => println!("  Pending:  unavailable ({error})"),
            }
        }
    }

    Ok(())
}

/// Rebuild each archived day from cloud storage and compare it with the
/// analytics the server accepted. The archive is only the source of truth for
/// cloud analytics if it can actually reproduce them, so this reports per day
/// rather than a single pass/fail.
fn cmd_verify_archives(
    daemon: &crate::daemon::Daemon,
    from: Option<&str>,
    to: Option<&str>,
) -> anyhow::Result<()> {
    let Some(device) = load_device() else {
        println!("This machine has not registered for cloud analytics yet.");
        println!("Run `grith analytics status` to see why.");
        return Ok(());
    };
    let Ok(Some(creds)) = crate::license::load_credentials() else {
        anyhow::bail!("Not signed in. Run: grith pro login");
    };

    let today = Utc::now().date_naive();
    let parse = |value: &str| {
        chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .map_err(|_| anyhow::anyhow!("dates must look like YYYY-MM-DD, got {value:?}"))
    };
    let to_day = to
        .map(parse)
        .transpose()?
        .unwrap_or(today.pred_opt().unwrap_or(today));
    let from_day = from
        .map(parse)
        .transpose()?
        .unwrap_or_else(|| to_day - chrono::Duration::days(29));
    if from_day > to_day {
        anyhow::bail!("--from must not be after --to");
    }

    println!("Checking archived days from {from_day} to {to_day}...");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut worker = crate::analytics_sync::Worker::for_command(daemon);
    let report = runtime
        .block_on(worker.verify_archives(&creds, &device, from_day, to_day))
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    if report.days.is_empty() {
        println!();
        println!("No archived days in that range.");
        println!("Days are archived after they close, and only once the server");
        println!("has accepted them; `grith analytics status` shows the backlog.");
        return Ok(());
    }

    println!();
    for day in &report.days {
        let mark = if day.status.is_ok() { "ok" } else { "FAIL" };
        println!(
            "  [{mark}] {}  revision {}  {} rows  {}",
            day.day,
            day.archive_revision,
            day.row_count,
            day.status.label()
        );
        if let Some(detail) = &day.detail {
            println!("         {detail}");
        }
    }

    println!();
    let matched = report.matched();
    let failed = report.failed();
    if failed == 0 {
        println!("All {matched} archived day(s) rebuilt to exactly the analytics");
        println!("the server accepted.");
    } else {
        println!("{matched} day(s) rebuilt correctly, {failed} did not.");
        println!("A mismatch means the archive and the dashboard disagree about");
        println!("that day; keep the output above when reporting it.");
        anyhow::bail!("{failed} archived day(s) did not rebuild correctly");
    }
    Ok(())
}
