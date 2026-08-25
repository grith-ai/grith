// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Demo player — drives the **real** `grith exec` TUI from a recorded
//! asciicast plus an authored timeline of security events.
//!
//! Nothing here reimplements the TUI. `run_exec_tui` takes four plain inputs
//! (a constructible `ExecState` and three channels), none of which touch the
//! supervisor, so a demo can supply them directly: the chrome, the permission
//! dialogs, the intercept log and the counters are all the shipping widgets.
//! Only the *timing and choice* of security events is authored.
//!
//! The recorded cast supplies the inner terminal byte-for-byte, so the panel
//! shows a genuine tool session rather than a mock-up. Record it with grith
//! absent (`asciinema rec session.cast`) so nothing interferes with the take.
//!
//! Usage:
//! ```text
//! cargo run -p grith-cli --example demo_player -- <timeline.toml> [flags]
//!
//!   --speed <f>   override meta.speed (playback multiplier)
//!   --check       print the resolved schedule and exit without a TUI
//! ```
//!
//! Permission dialogs block playback until answered, exactly as a frozen tool
//! would, and the keys are the real ones — so you drive the recording live.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use grith_cli::tui::exec_tui::{
    run_exec_tui, ExecEvent, ExecState, PermissionEvent, PermissionMessage, PtyInput,
    MINIMAL_CHROME_ROWS,
};
use grith_cli::tui::state::{FilterHit, PermissionRequest};
use grith_digest::PermissionReviewAction;
use serde::Deserialize;

// ---------------------------------------------------------------- timeline

#[derive(Deserialize)]
struct Timeline {
    meta: Meta,
    #[serde(default)]
    intercept: Vec<InterceptSpec>,
    #[serde(default)]
    permission: Vec<PermissionSpec>,
    #[serde(default)]
    hold: Vec<HoldSpec>,
    summary: Option<SummarySpec>,
}

#[derive(Deserialize)]
struct Meta {
    /// Path to the asciicast, resolved relative to the timeline file.
    cast: String,
    tool: String,
    profile: String,
    #[serde(default = "default_pid")]
    pid: u32,
    #[serde(default = "default_filter_count")]
    filter_count: usize,
    dashboard_url: Option<String>,
    #[serde(default = "default_speed")]
    speed: f64,
    /// Collapse any gap longer than this many seconds (post-production
    /// "speed up the quiet middle" without desyncing the authored events).
    idle_cap: Option<f64>,
    /// Optional opening beat: a shell prompt types out this command, then the
    /// screen switches to the grith TUI (which uses the alternate screen, just
    /// like the real `grith exec`). Establishes what is being run. e.g.
    /// "grith exec claude".
    intro_command: Option<String>,
    /// The prompt string shown before the typed command (default "$ ").
    intro_prompt: Option<String>,
}

fn default_pid() -> u32 {
    std::process::id()
}
fn default_filter_count() -> usize {
    18
}
fn default_speed() -> f64 {
    1.0
}

/// One intercept-log line. Also ticks the titlebar counters — the TUI's
/// `ExecEvent::Intercept` handler increments allowed/queued/denied from
/// `action`, so the counts animate straight off the timeline.
#[derive(Deserialize)]
struct InterceptSpec {
    at: f64,
    /// `allow` | `allow (logged)` | `queue` | `deny`
    action: String,
    call_type: String,
    #[serde(default)]
    score: f64,
    /// Clock shown in the log column, e.g. "11:04:02".
    timestamp: String,
}

#[derive(Deserialize)]
struct PermissionSpec {
    at: f64,
    tool: String,
    args: String,
    score: f32,
    #[serde(default = "default_severity")]
    severity: String,
    call_type: String,
    #[serde(default)]
    decision_reason: String,
    #[serde(default)]
    context: String,
    #[serde(default)]
    reasons: Vec<String>,
    #[serde(default)]
    scope_enabled: bool,
    #[serde(default)]
    filters: Vec<FilterSpec>,
    /// Clock for the intercept-log line this request also produces. In a real
    /// session the decision stream and the prompt are independent, so a queued
    /// or denied call shows up in the log *and* opens a dialog — without this
    /// the titlebar would still read `denied 0` after a block.
    timestamp: Option<String>,
    /// Seconds to hold the dialog on screen before auto-dismissing it, so a
    /// recording can dwell on a hero frame without a scripted keypress. When
    /// set, playback shows the dialog for this long then advances (equivalent
    /// to a review timeout — the decision was already logged, so the counters
    /// are unaffected). When absent, the dialog blocks until a real keypress.
    dwell_secs: Option<f64>,
}

fn default_severity() -> String {
    "Warning".to_string()
}

#[derive(Deserialize)]
struct FilterSpec {
    name: String,
    delta: f32,
}

/// Freeze playback on the current frame — for holding a hero frame.
#[derive(Deserialize)]
struct HoldSpec {
    at: f64,
    secs: f64,
}

/// The end-of-session summary.
///
/// Deliberately a captured file rather than a re-render: the real frame comes
/// from `render_supervisor_session_summary` in grith-core, which a grith-cli
/// example cannot reach (grith-core is bin-only, and grith-cli sits *below* it
/// in the dependency graph). Replaying real captured bytes keeps the last
/// frame permanently faithful instead of drifting from a copied renderer.
///
/// Capture it once from a real run:
/// ```text
/// grith exec --profile claude-code -- claude "..." | tail -n 40 > summary.txt
/// ```
#[derive(Deserialize)]
struct SummarySpec {
    text_file: String,
}

// ---------------------------------------------------------------- schedule

enum Action {
    Out(Vec<u8>),
    Intercept {
        timestamp: String,
        action: String,
        call_type: String,
        score: f64,
    },
    Permission {
        request: Box<PermissionRequest>,
        /// The log line this decision also produces, emitted just before the
        /// dialog opens so the counters reflect the block.
        log_action: String,
        log_timestamp: String,
        /// If set, auto-dismiss the dialog after this long instead of blocking
        /// on a keypress.
        dwell: Option<Duration>,
    },
    Hold(Duration),
}

struct Scheduled {
    at: f64,
    /// Tie-break so cast output at time T lands before an overlay at time T —
    /// the dialog should follow the line that provoked it.
    seq: usize,
    action: Action,
}

impl Action {
    fn label(&self) -> String {
        match self {
            Action::Out(b) => format!("output ({} bytes)", b.len()),
            Action::Intercept {
                action, call_type, ..
            } => format!("intercept {action} {call_type}"),
            Action::Permission {
                request,
                log_action,
                ..
            } => format!(
                "PERMISSION {log_action} score {:.1} — {}",
                request.score, request.tool
            ),
            Action::Hold(d) => format!("hold {:.1}s", d.as_secs_f64()),
        }
    }
}

// ------------------------------------------------------------------- cast

/// A parsed asciicast: the recorded terminal size plus its output events.
struct Cast {
    rows: u16,
    cols: u16,
    /// `(seconds since recording start, output bytes)`.
    events: Vec<(f64, Vec<u8>)>,
}

/// Parse an asciicast v2 file: a JSON header line followed by
/// `[time, type, data]` event lines. Only `"o"` (output) events are replayed.
fn parse_cast(path: &Path) -> anyhow::Result<Cast> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading cast {}: {e}", path.display()))?;
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());

    let header: serde_json::Value = serde_json::from_str(
        lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("cast {} is empty", path.display()))?,
    )
    .map_err(|e| anyhow::anyhow!("parsing cast header: {e}"))?;

    if header.get("version").and_then(serde_json::Value::as_u64) != Some(2) {
        anyhow::bail!(
            "only asciicast v2 is supported (got version {:?}); re-record with asciinema 2.x",
            header.get("version")
        );
    }
    let cols = header
        .get("width")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(100) as u16;
    let rows = header
        .get("height")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(30) as u16;

    let mut out = Vec::new();
    for (i, line) in lines.enumerate() {
        let ev: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| anyhow::anyhow!("parsing cast event on line {}: {e}", i + 2))?;
        let arr = match ev.as_array() {
            Some(a) if a.len() >= 3 => a,
            _ => continue,
        };
        // Ignore "i" (input), "m" (marker) and "r" (resize) — only the tool's
        // own output belongs in the vterm.
        if arr[1].as_str() != Some("o") {
            continue;
        }
        let at = arr[0].as_f64().unwrap_or(0.0);
        let data = arr[2].as_str().unwrap_or_default().as_bytes().to_vec();
        out.push((at, data));
    }
    Ok(Cast {
        rows,
        cols,
        events: out,
    })
}

// ------------------------------------------------------------------- main

/// Play the opening beat: a shell prompt, then `command` typed out one visible
/// character at a time, a beat, and a newline — so the recording shows what is
/// being run before the grith TUI (which uses the alternate screen) takes over.
/// Runs on the normal screen, before `EnterAlternateScreen`, so the TUI cleanly
/// switches away from it exactly as `grith exec` does.
fn play_intro(prompt: &str, command: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout();
    write!(out, "\r\n{prompt}")?;
    out.flush()?;
    std::thread::sleep(Duration::from_millis(500));
    for ch in command.chars() {
        write!(out, "{ch}")?;
        out.flush()?;
        // Slight jitter so it reads like typing, not a paste. Deterministic
        // (indexed), since Math.random-style entropy is neither available nor
        // wanted in a reproducible take.
        let ms = 55 + (u64::from(ch as u32) % 45);
        std::thread::sleep(Duration::from_millis(ms));
    }
    std::thread::sleep(Duration::from_millis(650));
    write!(out, "\r\n")?;
    out.flush()?;
    std::thread::sleep(Duration::from_millis(350));
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut timeline_path: Option<PathBuf> = None;
    let mut speed_override: Option<f64> = None;
    let mut check_only = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--speed" => {
                speed_override = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--speed needs a value"))?
                        .parse()?,
                );
            }
            "--check" => check_only = true,
            "-h" | "--help" => {
                eprintln!(
                    "usage: demo_player <timeline.toml> [--speed <f>] [--check]\n\
                     \n  --speed <f>  override meta.speed\n  \
                     --check      print the resolved schedule and exit"
                );
                return Ok(());
            }
            other if timeline_path.is_none() => timeline_path = Some(PathBuf::from(other)),
            other => anyhow::bail!("unexpected argument: {other}"),
        }
    }
    let timeline_path =
        timeline_path.ok_or_else(|| anyhow::anyhow!("usage: demo_player <timeline.toml>"))?;

    let timeline: Timeline = toml::from_str(&std::fs::read_to_string(&timeline_path)?)
        .map_err(|e| anyhow::anyhow!("parsing {}: {e}", timeline_path.display()))?;

    let base = timeline_path.parent().unwrap_or(Path::new("."));
    let cast = parse_cast(&base.join(&timeline.meta.cast))?;
    let (cast_rows, cast_cols) = (cast.rows, cast.cols);
    let speed = speed_override.unwrap_or(timeline.meta.speed);
    anyhow::ensure!(speed > 0.0, "speed must be positive (got {speed})");

    // ---- build the merged schedule (cast output + authored overlays) ----
    let mut schedule: Vec<Scheduled> = Vec::with_capacity(cast.events.len() + 16);
    for (seq, (at, data)) in cast.events.into_iter().enumerate() {
        schedule.push(Scheduled {
            at,
            seq,
            action: Action::Out(data),
        });
    }
    let mut seq = schedule.len();
    let mut push = |at: f64, action: Action, schedule: &mut Vec<Scheduled>| {
        schedule.push(Scheduled { at, seq, action });
        seq += 1;
    };
    for i in timeline.intercept {
        push(
            i.at,
            Action::Intercept {
                timestamp: i.timestamp,
                action: i.action,
                call_type: i.call_type,
                score: i.score,
            },
            &mut schedule,
        );
    }
    for p in timeline.permission {
        // Above the auto-deny threshold the proxy denied it outright; below, it
        // was queued for review. Either way the log line records the *proxy's*
        // decision, not what the operator subsequently pressed.
        let log_action = if p.score > 8.0 { "deny" } else { "queue" }.to_string();
        let log_timestamp = p.timestamp.clone().unwrap_or_default();
        let dwell = p.dwell_secs.map(Duration::from_secs_f64);
        push(
            p.at,
            Action::Permission {
                log_action,
                log_timestamp,
                dwell,
                request: Box::new(PermissionRequest {
                    id: uuid::Uuid::new_v4(),
                    tool: p.tool,
                    args: p.args,
                    score: p.score,
                    filters: p
                        .filters
                        .into_iter()
                        .map(|f| FilterHit {
                            name: f.name,
                            delta: f.delta,
                        })
                        .collect(),
                    reasons: p.reasons,
                    decision_reason: p.decision_reason,
                    context: p.context,
                    severity: p.severity,
                    sticky_grant_available:
                        grith_proxy::types::ToolCallType::category_supports_session_grant(
                            &p.call_type,
                        ),
                    call_type: p.call_type,
                    item_number: 1,
                    total_items: 1,
                    scope_enabled: p.scope_enabled,
                }),
            },
            &mut schedule,
        );
    }
    for h in timeline.hold {
        push(
            h.at,
            Action::Hold(Duration::from_secs_f64(h.secs)),
            &mut schedule,
        );
    }

    schedule.sort_by(|a, b| {
        a.at.partial_cmp(&b.at)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.seq.cmp(&b.seq))
    });

    // Compress idle gaps. Authored `at` values still refer to original cast
    // time — remapping happens after the sort, so events stay in sync.
    if let Some(cap) = timeline.meta.idle_cap {
        anyhow::ensure!(cap > 0.0, "idle_cap must be positive (got {cap})");
        let mut prev_original = 0.0_f64;
        let mut accumulated = 0.0_f64;
        for s in &mut schedule {
            accumulated += (s.at - prev_original).max(0.0).min(cap);
            prev_original = s.at;
            s.at = accumulated;
        }
    }

    let ideal_rows = cast_rows + MINIMAL_CHROME_ROWS;
    let held: f64 = schedule
        .iter()
        .filter_map(|s| match &s.action {
            Action::Hold(d) => Some(d.as_secs_f64()),
            _ => None,
        })
        .sum();
    let runtime = schedule.last().map_or(0.0, |s| s.at) / speed + held;

    if check_only {
        println!("timeline : {}", timeline_path.display());
        println!(
            "cast     : {} ({cast_cols}x{cast_rows})",
            timeline.meta.cast
        );
        println!(
            "speed    : {speed}x   idle_cap: {:?}",
            timeline.meta.idle_cap
        );
        println!(
            "runtime  : {runtime:.1}s over {} events \
             (excludes time dialogs wait for an operator)",
            schedule.len()
        );
        println!(
            "terminal : record at {ideal_rows} rows x {cast_cols} cols \
             (cast {cast_rows} + {MINIMAL_CHROME_ROWS} chrome)"
        );
        println!("\nauthored events:");
        for s in &schedule {
            if !matches!(s.action, Action::Out(_)) {
                println!("  {:>7.2}s  {}", s.at, s.action.label());
            }
        }
        return Ok(());
    }

    // ---- size advice ----
    // A pty that reports 0x0 (some `script`/CI harnesses) must not reach
    // ratatui — fall back to the size the cast wants.
    let (term_cols, term_rows) = match crossterm::terminal::size() {
        Ok((c, r)) if c > 0 && r > 0 => (c, r),
        _ => (cast_cols, ideal_rows),
    };
    if term_rows < ideal_rows || term_cols < cast_cols {
        println!(
            "note: terminal is {term_cols}x{term_rows}; this cast wants \
             {cast_cols}x{ideal_rows} ({cast_rows} content + {MINIMAL_CHROME_ROWS} chrome). \
             Content will wrap or clip."
        );
        std::io::stdout().flush().ok();
        std::thread::sleep(Duration::from_millis(2500));
    }

    // ---- opening beat: type the command on a shell prompt ----
    // Before any TUI setup, so it lands on the normal screen and the TUI's
    // alternate-screen switch reads as `grith exec` taking over — exactly as it
    // does for real. Done before the playback thread starts so its clock is not
    // charged for the typing time.
    if let Some(cmd) = timeline.meta.intro_command.as_deref() {
        let prompt = timeline.meta.intro_prompt.as_deref().unwrap_or("$ ");
        play_intro(prompt, cmd)?;
    }

    // ---- wire the real TUI ----
    let (event_tx, event_rx) = crossbeam_channel::unbounded::<ExecEvent>();
    let (perm_tx, perm_rx) = crossbeam_channel::unbounded::<PermissionMessage>();
    let (pty_tx, pty_rx) = mpsc::channel::<PtyInput>();

    // Drain keystrokes the TUI forwards "to the child". Keeping the receiver
    // alive matters: a dead receiver turns every forward into a send error.
    std::thread::spawn(move || while pty_rx.recv().is_ok() {});

    let playback = std::thread::spawn(move || {
        let start = Instant::now();
        // Time spent frozen (holds, and dialogs awaiting an operator) must not
        // count against the cast clock, or everything after a pause fires late.
        let mut frozen = Duration::ZERO;

        for s in schedule {
            let target = Duration::from_secs_f64(s.at / speed) + frozen;
            if let Some(wait) = target.checked_sub(start.elapsed()) {
                std::thread::sleep(wait);
            }
            match s.action {
                Action::Out(bytes) => {
                    if event_tx.send(ExecEvent::PtyOutput(bytes)).is_err() {
                        return; // TUI gone (user quit) — stop quietly.
                    }
                }
                Action::Intercept {
                    timestamp,
                    action,
                    call_type,
                    score,
                } => {
                    if event_tx
                        .send(ExecEvent::Intercept {
                            timestamp,
                            action,
                            call_type,
                            score,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                Action::Hold(d) => {
                    std::thread::sleep(d);
                    frozen += d;
                }
                Action::Permission {
                    request,
                    log_action,
                    log_timestamp,
                    dwell,
                } => {
                    // The decision reaches the log independently of the prompt,
                    // as it does in a real session — this is what moves the
                    // titlebar's queued/denied counters.
                    if event_tx
                        .send(ExecEvent::Intercept {
                            timestamp: log_timestamp,
                            action: log_action,
                            call_type: request.call_type.clone(),
                            score: f64::from(request.score),
                        })
                        .is_err()
                    {
                        return;
                    }
                    let request_id = request.id;
                    let (response_tx, response_rx) = mpsc::sync_channel(1);
                    if perm_tx
                        .send(PermissionMessage::Request(Box::new(PermissionEvent {
                            request: *request,
                            response_tx,
                        })))
                        .is_err()
                    {
                        return;
                    }
                    // A real supervised tool is frozen for exactly the interval
                    // the dialog is up, so bank that time as `frozen`.
                    let paused = Instant::now();
                    let answer = match dwell {
                        // Timeline-driven hold (for an unattended recording):
                        // show the dialog for `d`, then dismiss it exactly as a
                        // review timeout would. A real keypress arriving inside
                        // the window still wins.
                        Some(d) => match response_rx.recv_timeout(d) {
                            Ok(a) => Ok(a),
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                let _ = perm_tx.send(PermissionMessage::Cancel(request_id));
                                Err(())
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => Err(()),
                        },
                        // No dwell: block until a real keypress answers.
                        None => response_rx.recv().map_err(|_| ()),
                    };
                    frozen += paused.elapsed();
                    if matches!(answer, Ok(PermissionReviewAction::DenyAndTerminate)) {
                        break; // operator killed the run; end the take here
                    }
                }
            }
        }
        let _ = event_tx.send(ExecEvent::ProcessExited);
    });

    let mut state = ExecState::new(
        timeline.meta.tool,
        timeline.meta.profile,
        timeline.meta.pid,
        term_rows,
        term_cols,
        timeline.meta.filter_count,
    );
    state.dashboard_url = timeline.meta.dashboard_url;

    let result = run_exec_tui(state, event_rx, perm_rx, pty_tx);
    let _ = playback.join();
    result?;

    // Hero frame #2 — real captured bytes, printed after the TUI restores the
    // normal screen (which is where the real summary appears too).
    if let Some(summary) = timeline.summary {
        let path = base.join(&summary.text_file);
        match std::fs::read(&path) {
            Ok(bytes) => {
                // Clear the normal screen first so the leftover intro prompt
                // (restored when the TUI left the alternate screen) does not
                // sit above the end-card.
                print!("\x1b[2J\x1b[H");
                std::io::stdout().write_all(&bytes)?;
                std::io::stdout().flush()?;
            }
            Err(e) => eprintln!("note: could not read summary {}: {e}", path.display()),
        }
    }
    Ok(())
}
