// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Timeline generator — turns a real supervised session's audit records into a
//! `demo_player` timeline, so the demo's scores, filter breakdowns and
//! decisions are numbers grith actually produced rather than hand-typed ones.
//!
//! Workflow:
//! ```text
//! # 1. one real supervised run, to produce the audit trail
//! grith exec --profile claude-code -- claude "<the task you want on camera>"
//!
//! # 2. find the session
//! cargo run -p grith-cli --example demo_timeline_gen -- --list-sessions
//!
//! # 3. generate, aligned to the cast you are going to play
//! cargo run -p grith-cli --example demo_timeline_gen -- \
//!     --session <uuid> --cast session.cast -o timeline.toml
//! ```
//!
//! The database is opened **read-only** so this never contends for the audit
//! writer lock — a generator run can't wedge a live daemon into read-only mode.
//!
//! One field is deliberately left for a human: `context` on a permission entry
//! is a narrative sentence. Where the record carries a `correlation_id` the
//! generator fills it from the real source→sink chain; otherwise it emits an
//! empty string and a marker comment rather than inventing a story.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use grith_audit::{AuditQuery, AuditRecord, AuditStorage, ProxyActionSummary};
use uuid::Uuid;

/// Quote and escape a string as a TOML basic string.
fn tstr(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

/// Collapse a string to a single line and bound its length, so one enormous
/// argv can't blow out a dialog or turn the timeline into a multi-line blob.
fn bounded(s: &str, max: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let kept: String = flat.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// The type prefix of an audit `tool_call_type`, dropping any parenthesised
/// detail: `ProcessSpawn(/usr/bin/dash sh -c …)` -> `ProcessSpawn`. This is the
/// shape the intercept log shows (`FileRead`, `NetConnect`, `ProcessSpawn`).
fn short_call_type(s: &str) -> String {
    s.split_once('(')
        .map_or(s, |(head, _)| head)
        .trim()
        .to_string()
}

/// Session lifecycle bookkeeping, not a tool call — never useful in a demo.
fn is_lifecycle(r: &AuditRecord) -> bool {
    let t = short_call_type(&r.tool_call_type);
    t == "session_start" || t == "session_end"
}

/// Mirrors the shipped `general.audit_dir` default (`~/.local/share/grith/audit`).
fn default_db() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("grith")
        .join("audit")
        .join("audit.db")
}

struct Args {
    db: PathBuf,
    session: Option<Uuid>,
    cast: String,
    tool: Option<String>,
    profile: String,
    offset: f64,
    speed: f64,
    idle_cap: Option<f64>,
    dashboard_url: Option<String>,
    max_intercepts: usize,
    max_permissions: usize,
    summary_file: Option<String>,
    out: Option<PathBuf>,
    list_sessions: Option<usize>,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut a = Args {
        db: default_db(),
        session: None,
        cast: "session.cast".to_string(),
        tool: None,
        profile: "claude-code".to_string(),
        offset: 0.0,
        speed: 1.0,
        idle_cap: Some(1.5),
        dashboard_url: None,
        max_intercepts: 400,
        max_permissions: 8,
        summary_file: Some("summary.txt".to_string()),
        out: None,
        list_sessions: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut next = || {
            it.next()
                .ok_or_else(|| anyhow::anyhow!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--db" => a.db = PathBuf::from(next()?),
            "--session" => a.session = Some(Uuid::parse_str(&next()?)?),
            "--cast" => a.cast = next()?,
            "--tool" => a.tool = Some(next()?),
            "--profile" => a.profile = next()?,
            "--offset" => a.offset = next()?.parse()?,
            "--speed" => a.speed = next()?.parse()?,
            "--idle-cap" => {
                let v: f64 = next()?.parse()?;
                a.idle_cap = if v > 0.0 { Some(v) } else { None };
            }
            "--dashboard-url" => a.dashboard_url = Some(next()?),
            "--max-intercepts" => a.max_intercepts = next()?.parse()?,
            "--max-permissions" => a.max_permissions = next()?.parse()?,
            "--summary-file" => a.summary_file = Some(next()?),
            "--no-summary" => a.summary_file = None,
            "-o" | "--out" => a.out = Some(PathBuf::from(next()?)),
            "--list-sessions" => a.list_sessions = Some(2000),
            "-h" | "--help" => {
                println!(
                    "usage: demo_timeline_gen --session <uuid> [options]\n\
                     \n  --list-sessions        list recent sessions and exit\
                     \n  --db <path>            audit database (default ~/.local/share/grith/audit/audit.db)\
                     \n  --cast <name>          cast filename written into meta.cast\
                     \n  --offset <secs>        shift every event (align audit clock to cast clock)\
                     \n  --tool/--profile       meta.tool / meta.profile\
                     \n  --speed <f>            meta.speed\
                     \n  --idle-cap <secs>      meta.idle_cap (0 disables)\
                     \n  --dashboard-url <url>  titlebar dashboard URL\
                     \n  --max-intercepts <n>   cap intercept lines (default 400)\
                     \n  --max-permissions <n>  cap dialogs, highest score wins (default 8)\
                     \n  --summary-file <name>  [summary].text_file (--no-summary to omit)\
                     \n  -o <path>              write here instead of stdout"
                );
                std::process::exit(0);
            }
            other => anyhow::bail!("unexpected argument: {other}"),
        }
    }
    Ok(a)
}

fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    anyhow::ensure!(
        args.db.exists(),
        "no audit database at {} (pass --db)",
        args.db.display()
    );
    // Read-only: never take the writer lock a live daemon may hold.
    let storage = AuditStorage::open_read_only(&args.db)?;

    if let Some(limit) = args.list_sessions {
        return list_sessions(&storage, limit);
    }

    let session = args.session.ok_or_else(|| {
        anyhow::anyhow!("--session <uuid> is required (use --list-sessions to find one)")
    })?;

    let mut records = storage.get_by_session(&session)?;
    anyhow::ensure!(
        !records.is_empty(),
        "no audit records for session {session}"
    );
    records.sort_by_key(|r| r.timestamp);

    let out = render_timeline(&args, session, &records);
    match &args.out {
        Some(path) => {
            std::fs::write(path, &out)?;
            eprintln!(
                "wrote {} ({} records -> {} bytes)",
                path.display(),
                records.len(),
                out.len()
            );
        }
        None => print!("{out}"),
    }
    Ok(())
}

fn list_sessions(storage: &AuditStorage, limit: usize) -> anyhow::Result<()> {
    let records = AuditQuery::new().paginate(limit, 0).execute(storage)?;
    if records.is_empty() {
        println!("no audit records found");
        return Ok(());
    }

    struct Group {
        count: usize,
        flagged: usize,
        tool: Option<String>,
        project: Option<String>,
        first: chrono::DateTime<chrono::Utc>,
        last: chrono::DateTime<chrono::Utc>,
    }
    let mut groups: BTreeMap<Uuid, Group> = BTreeMap::new();
    for r in &records {
        let g = groups.entry(r.session_id).or_insert_with(|| Group {
            count: 0,
            flagged: 0,
            tool: r.supervised_tool.clone(),
            project: r.project_name.clone(),
            first: r.timestamp,
            last: r.timestamp,
        });
        g.count += 1;
        if r.proxy_action != ProxyActionSummary::Allow {
            g.flagged += 1;
        }
        g.first = g.first.min(r.timestamp);
        g.last = g.last.max(r.timestamp);
        g.tool = g.tool.take().or_else(|| r.supervised_tool.clone());
        g.project = g.project.take().or_else(|| r.project_name.clone());
    }

    let mut rows: Vec<_> = groups.into_iter().collect();
    rows.sort_by_key(|(_, g)| std::cmp::Reverse(g.last));

    // The counts are per scanned window, not session totals — a long session
    // can easily have more records than the window holds.
    println!(
        "{:<38} {:>6} {:>7}  {:<12} {:<16} LAST SEEN (local)",
        "SESSION", "SEEN", "FLAGGED", "TOOL", "PROJECT"
    );
    for (id, g) in rows {
        println!(
            "{:<38} {:>6} {:>7}  {:<12} {:<16} {}",
            id.to_string(),
            g.count,
            g.flagged,
            g.tool.as_deref().unwrap_or("-"),
            g.project.as_deref().unwrap_or("-"),
            g.last
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
        );
    }
    println!(
        "\n(SEEN/FLAGGED are counts within the {} most recent records scanned, \n\
         not session totals)",
        records.len()
    );
    Ok(())
}

/// Per-filter contributions, preferring the detailed `filter_results` and
/// falling back to the compact `filter_scores` map.
fn filter_hits(r: &AuditRecord) -> Vec<(String, f64)> {
    let detailed: Vec<(String, f64)> = r
        .filter_results
        .iter()
        .filter(|f| f.matched && f.score.abs() > f64::EPSILON)
        .map(|f| (f.filter_name.clone(), f.score))
        .collect();
    if !detailed.is_empty() {
        return detailed;
    }
    let mut fallback: Vec<(String, f64)> = r
        .filter_scores
        .as_ref()
        .map(|m| {
            m.iter()
                .filter(|(_, s)| s.abs() > f64::EPSILON)
                .map(|(n, s)| (n.clone(), *s))
                .collect()
        })
        .unwrap_or_default();
    fallback.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    fallback
}

fn severity_for(r: &AuditRecord) -> String {
    let worst = r
        .filter_results
        .iter()
        .filter(|f| f.matched)
        .max_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|f| f.severity.clone());
    match worst {
        Some(s) if !s.is_empty() => {
            let mut c = s.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or(s)
        }
        // No per-filter severity recorded (compact record) — fall back to the
        // same threshold the TUI uses to pick its red/amber dialog.
        _ if r.composite_score > 8.0 => "Critical".to_string(),
        _ => "Warning".to_string(),
    }
}

/// The earliest *other* record sharing this record's correlation id — the
/// source end of a source→sink chain (e.g. the `.env` read that tainted the
/// session before the outbound POST).
fn chain_origin<'a>(r: &AuditRecord, all: &'a [AuditRecord]) -> Option<&'a AuditRecord> {
    let cid = r.correlation_id?;
    all.iter()
        .filter(|o| o.correlation_id == Some(cid) && o.id != r.id && o.timestamp <= r.timestamp)
        .min_by_key(|o| o.timestamp)
}

fn render_timeline(args: &Args, session: Uuid, records: &[AuditRecord]) -> String {
    let start = records[0].timestamp;
    let at =
        |r: &AuditRecord| (r.timestamp - start).num_milliseconds() as f64 / 1000.0 + args.offset;
    let clock = |r: &AuditRecord| {
        r.timestamp
            .with_timezone(&chrono::Local)
            .format("%H:%M:%S")
            .to_string()
    };

    let tool = args
        .tool
        .clone()
        .or_else(|| records.iter().find_map(|r| r.supervised_tool.clone()))
        .unwrap_or_else(|| "claude".to_string());
    let project = records.iter().find_map(|r| r.project_name.clone());

    // Every flagged call, minus exact repeats. A supervised tool probing the
    // same blocked syscall three times in one second is real, but three
    // identical dialogs would just stack up on camera.
    let mut seen = std::collections::HashSet::new();
    let mut duplicates = 0usize;
    let deduped: Vec<&AuditRecord> = records
        .iter()
        .filter(|r| r.proxy_action != ProxyActionSummary::Allow && !is_lifecycle(r))
        .filter(|r| {
            let key = (
                r.timestamp.timestamp(),
                r.tool_call_type.clone(),
                r.arguments_summary.clone(),
            );
            if seen.insert(key) {
                true
            } else {
                duplicates += 1;
                false
            }
        })
        .collect();

    // Cap the dialog count, keeping the highest-scoring (most demo-worthy)
    // rather than the first N, then restore chronological order.
    let dropped_by_cap = deduped.len().saturating_sub(args.max_permissions);
    let mut flagged: Vec<&AuditRecord> = {
        let mut by_score = deduped.clone();
        by_score.sort_by(|a, b| {
            b.composite_score
                .partial_cmp(&a.composite_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.timestamp.cmp(&b.timestamp))
        });
        by_score.truncate(args.max_permissions);
        by_score
    };
    flagged.sort_by_key(|r| r.timestamp);
    let no_breakdown = flagged.iter().filter(|r| filter_hits(r).is_empty()).count();

    let mut o = String::new();
    let _ = writeln!(
        o,
        "# Generated by demo_timeline_gen from real audit records."
    );
    let _ = writeln!(o, "# session {session}");
    if let Some(p) = &project {
        let _ = writeln!(o, "# project {p}");
    }
    let _ = writeln!(
        o,
        "# {} records, {:.1}s wall clock",
        records.len(),
        at(records.last().unwrap()) - args.offset
    );
    let _ = writeln!(
        o,
        "# {} dialogs emitted{}{}",
        flagged.len(),
        if duplicates > 0 {
            format!(" ({duplicates} exact repeats collapsed)")
        } else {
            String::new()
        },
        if dropped_by_cap > 0 {
            format!(
                ", {dropped_by_cap} more dropped by --max-permissions {} \
                 (kept the highest-scoring)",
                args.max_permissions
            )
        } else {
            String::new()
        }
    );
    if no_breakdown > 0 {
        let _ = writeln!(
            o,
            "# {no_breakdown} of them have no filter breakdown (pre-proxy hard denies);\n\
             # those render as a dialog with no score bars — see the WARN markers below."
        );
    }
    let _ = writeln!(
        o,
        "#\n# Timings are audit wall-clock rebased to the first record. Align them to\n\
         # the cast with --offset (positive shifts events later).\n"
    );

    let _ = writeln!(o, "[meta]");
    let _ = writeln!(o, "cast = {}", tstr(&args.cast));
    let _ = writeln!(o, "tool = {}", tstr(&tool));
    let _ = writeln!(o, "profile = {}", tstr(&args.profile));
    if let Some(pid) = records.iter().find_map(|r| r.supervised_pid) {
        let _ = writeln!(o, "pid = {pid}");
    }
    // `{:?}` so an integral speed still writes as `1.0` — bare `1` parses back
    // as a TOML integer and fails the player's f64 field.
    let _ = writeln!(o, "speed = {:?}", args.speed);
    if let Some(cap) = args.idle_cap {
        let _ = writeln!(o, "idle_cap = {cap:?}");
    }
    if let Some(url) = &args.dashboard_url {
        let _ = writeln!(o, "dashboard_url = {}", tstr(url));
    }

    // ---- intercept lines ----
    //
    // Allows only. Each `[[permission]]` below emits its own log line when it
    // fires (mirroring the real decision stream), so listing a flagged record
    // here as well would double-count it in the titlebar.
    let allows: Vec<&AuditRecord> = records
        .iter()
        .filter(|r| r.proxy_action == ProxyActionSummary::Allow && !is_lifecycle(r))
        .collect();
    let total_allows = allows.len();
    let keep: Vec<&AuditRecord> = if total_allows <= args.max_intercepts {
        allows.clone()
    } else {
        // Sample evenly so the log still scrolls naturally through the quiet
        // stretch instead of stopping dead partway.
        let stride = (total_allows / args.max_intercepts.max(1)).max(1);
        allows
            .iter()
            .step_by(stride)
            .take(args.max_intercepts)
            .copied()
            .collect()
    };
    if keep.len() < total_allows {
        let _ = writeln!(
            o,
            "\n# NOTE: {} of {total_allows} allow records emitted \
             ({} dropped by --max-intercepts {}), evenly sampled.\n\
             # The {} selected flagged records follow as [[permission]] entries.",
            keep.len(),
            total_allows - keep.len(),
            args.max_intercepts,
            flagged.len()
        );
    }
    for r in &keep {
        let _ = writeln!(o, "\n[[intercept]]");
        let _ = writeln!(o, "at = {:.2}", at(r));
        let _ = writeln!(o, "action = {}", tstr(&r.proxy_action.to_string()));
        let _ = writeln!(
            o,
            "call_type = {}",
            tstr(&short_call_type(&r.tool_call_type))
        );
        let _ = writeln!(o, "score = {:.1}", r.composite_score);
        let _ = writeln!(o, "timestamp = {}", tstr(&clock(r)));
    }

    // ---- permission dialogs ----
    for r in &flagged {
        let _ = writeln!(
            o,
            "\n# {} — {} (score {:.1})",
            clock(r),
            r.proxy_action,
            r.composite_score
        );
        if filter_hits(r).is_empty() {
            let _ = writeln!(
                o,
                "# WARN: no filter breakdown (pre-proxy hard deny) — this dialog will have\n\
                 # no score bars. Hand-fill `filters` or drop the entry."
            );
        }
        let _ = writeln!(o, "[[permission]]");
        let _ = writeln!(o, "at = {:.2}", at(r));
        let _ = writeln!(o, "timestamp = {}", tstr(&clock(r)));
        let _ = writeln!(o, "tool = {}", tstr(&short_call_type(&r.tool_call_type)));
        let _ = writeln!(o, "args = {}", tstr(&bounded(&r.arguments_summary, 180)));
        let _ = writeln!(o, "score = {:.1}", r.composite_score);
        let _ = writeln!(o, "severity = {}", tstr(&severity_for(r)));
        let _ = writeln!(o, "call_type = {}", tstr(&bounded(&r.tool_call_type, 90)));
        let _ = writeln!(
            o,
            "decision_reason = {}",
            tstr(r.decision_reason.as_deref().unwrap_or_default())
        );

        match chain_origin(r, records) {
            Some(origin) => {
                let _ = writeln!(
                    o,
                    "# context derived from correlation chain {}",
                    origin.correlation_id.unwrap_or_default()
                );
                let _ = writeln!(
                    o,
                    "context = {}",
                    tstr(&format!(
                        "{} at {} tainted this session",
                        bounded(&origin.arguments_summary, 90),
                        clock(origin)
                    ))
                );
            }
            None => {
                let _ = writeln!(
                    o,
                    "# context: no correlation chain recorded — write the narrative sentence here"
                );
                let _ = writeln!(o, "context = \"\"");
            }
        }

        let hits = filter_hits(r);
        let reasons: Vec<String> = r
            .filter_results
            .iter()
            .filter(|f| f.matched && !f.message.is_empty())
            .map(|f| bounded(&f.message, 110))
            .take(4)
            .collect();
        if reasons.is_empty() {
            let _ = writeln!(o, "reasons = []");
        } else {
            let _ = writeln!(
                o,
                "reasons = [{}]",
                reasons
                    .iter()
                    .map(|s| tstr(s))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if hits.is_empty() {
            let _ = writeln!(o, "filters = []");
        } else {
            let _ = writeln!(o, "filters = [");
            for (name, delta) in hits {
                let _ = writeln!(o, "  {{ name = {}, delta = {delta:.1} }},", tstr(&name));
            }
            let _ = writeln!(o, "]");
        }
    }

    // ---- summary ----
    if let Some(file) = &args.summary_file {
        let allowed = records.len() - flagged.len();
        let queued = records
            .iter()
            .filter(|r| r.proxy_action == ProxyActionSummary::Queue)
            .count();
        let denied = records
            .iter()
            .filter(|r| r.proxy_action == ProxyActionSummary::Deny)
            .count();
        // Group by type prefix, not the raw `tool_call_type` — that field
        // carries the full command, so grouping on it yields one bucket per
        // record instead of a breakdown.
        let mut breakdown: BTreeMap<String, usize> = BTreeMap::new();
        for r in records.iter().filter(|r| !is_lifecycle(r)) {
            *breakdown
                .entry(short_call_type(&r.tool_call_type))
                .or_default() += 1;
        }
        let _ = writeln!(
            o,
            "\n# Real counts for this session — check the captured summary matches:\n\
             #   allowed {allowed}  queued {queued}  denied {denied}"
        );
        for (k, v) in &breakdown {
            let _ = writeln!(o, "#   {k}: {v}");
        }
        let _ = writeln!(
            o,
            "#\n# Capture the real frame once (it is grith-core's renderer, not reproduced here):\n\
             #   grith exec --profile {} -- {tool} \"...\" | tail -n 40 > {file}",
            args.profile
        );
        let _ = writeln!(o, "[summary]");
        let _ = writeln!(o, "text_file = {}", tstr(file));
    }

    o
}
