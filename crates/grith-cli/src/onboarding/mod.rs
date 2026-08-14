// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Interactive first-run onboarding engine.
//!
//! `grith-cli` owns the *rendering and control flow*; `grith-core` supplies the
//! live behaviour (tool detection, Ollama probe, dashboard URL, trial
//! device-auth) through the [`OnboardingServices`] trait, so this crate stays
//! free of license/daemon dependencies. The flow collects the user's choices
//! into an [`OnboardingOutcome`] which the caller applies to its config.
//!
//! Skip semantics (see the CLI-copy doc):
//! - `s` skips the current step, accepting its default.
//! - `S` skips *all* remaining steps (defaults applied) and jumps to the guide;
//!   `completed` stays true.
//! - `Ctrl-C`/`Esc` aborts: `completed` is false and the caller must NOT mark
//!   the install onboarded.

pub mod render;

use render::{Opt, Prompt, Selection, Style};
use std::io::{IsTerminal, Write};

/// How the user chose to run agents under grith.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderMode {
    /// Supervise external tools via `grith exec`; no built-in provider.
    Exec,
    /// Built-in agent against a local Ollama server.
    Ollama,
    /// Built-in agent against a cloud provider (key supplied via env var).
    Cloud(CloudProvider),
}

/// Cloud providers offered for the built-in agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    Anthropic,
    OpenAI,
    OpenRouter,
}

impl CloudProvider {
    /// The `llm.default_provider` config value.
    pub fn config_key(self) -> &'static str {
        match self {
            CloudProvider::Anthropic => "anthropic",
            CloudProvider::OpenAI => "openai",
            CloudProvider::OpenRouter => "openrouter",
        }
    }
    /// The environment variable conventionally holding this provider's key.
    pub fn env_var(self) -> &'static str {
        match self {
            CloudProvider::Anthropic => "ANTHROPIC_API_KEY",
            CloudProvider::OpenAI => "OPENAI_API_KEY",
            CloudProvider::OpenRouter => "OPENROUTER_API_KEY",
        }
    }
    pub fn display(self) -> &'static str {
        match self {
            CloudProvider::Anthropic => "Anthropic",
            CloudProvider::OpenAI => "OpenAI",
            CloudProvider::OpenRouter => "OpenRouter",
        }
    }
}

/// A supervised tool detected (or not) on `PATH`.
#[derive(Debug, Clone)]
pub struct DetectedTool {
    /// Display name, e.g. "Claude Code".
    pub name: String,
    /// The binary to place after `grith exec --`, e.g. "claude-code".
    pub exec_arg: String,
    /// Whether the binary was found on `PATH`.
    pub present: bool,
}

/// Result of probing the local Ollama server.
#[derive(Debug, Clone)]
pub enum OllamaStatus {
    Running { models: usize },
    Unreachable { url: String },
}

/// Result of the trial opt-in.
#[derive(Debug, Clone)]
pub enum TrialResult {
    Activated { until: Option<String> },
    Pending,
    Failed { message: String },
}

/// Result of signing in to an existing account (or team) during onboarding.
#[derive(Debug, Clone)]
pub enum SignInResult {
    SignedIn {
        plan: String,
        team: Option<String>,
        keys_pulled: usize,
    },
    /// Browser linking didn't complete in time.
    Pending,
    Failed {
        message: String,
    },
}

/// Live behaviour supplied by `grith-core`.
pub trait OnboardingServices {
    /// Supervised tools known to the profile registry, with presence on PATH.
    fn detected_tools(&self) -> Vec<DetectedTool>;
    /// One-line platform supervision summary (e.g. "full supervision available").
    fn platform_summary(&self) -> String;
    /// Probe the local Ollama server.
    fn ollama_status(&self) -> OllamaStatus;
    /// Whether the conventional env var for `provider` is currently set.
    fn cloud_env_present(&self, provider: CloudProvider) -> bool;
    /// The local dashboard base URL, if the server is enabled.
    fn dashboard_url(&self) -> Option<String>;
    /// Begin the Pro trial: link a (possibly new) account via browser device-auth
    /// and activate a trial.
    fn start_trial(&self) -> TrialResult;
    /// Sign in to an existing account (or team) via browser device-auth, linking
    /// this CLI and pulling any team-distributed resources.
    fn sign_in(&self) -> SignInResult;
}

/// The user's collected choices, applied to config by the caller.
#[derive(Debug, Clone)]
pub struct OnboardingOutcome {
    pub mode: ProviderMode,
    pub audit_sync: bool,
    pub trial_started: bool,
    /// False if the user aborted (Ctrl-C/Esc) — caller must not mark onboarded.
    pub completed: bool,
    /// The suggested next command shown in the guide.
    pub first_command: String,
}

/// Run the interactive onboarding flow to completion (or abort).
///
/// `audit_sync_default` is the current config value, used as the welcome
/// screen's pre-selected consent choice. `enable_color` honours `--no-color`.
pub fn run(
    out: &mut impl Write,
    services: &dyn OnboardingServices,
    audit_sync_default: bool,
    enable_color: bool,
) -> std::io::Result<OnboardingOutcome> {
    let style = Style::new(enable_color);

    // On an interactive TTY, take over the full window via the alternate
    // screen so each step is clean and the user's shell history isn't visible.
    // Over a pipe/non-TTY we stay inline and emit no escape codes.
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    // RAII guard: restores the cursor and leaves the alternate screen on EVERY
    // exit path — normal return, `?`-propagated error, or panic unwind — and (on
    // unix) arms a signal handler so a Ctrl-C during the device-auth browser
    // wait can't strand the terminal either. `None` means the terminal declined
    // the switch and we render inline.
    let guard = if interactive {
        render::FullscreenGuard::enter(out)
    } else {
        None
    };
    let fullscreen = guard.is_some();

    let result = run_screens(out, style, services, audit_sync_default, fullscreen);

    // Leave the alternate screen now so the closing guide prints to the restored
    // (normal) screen and persists in scrollback. Dropping the guard here also
    // covers the error path below; a panic in `run_screens` is covered by the
    // guard's `Drop` during unwinding.
    drop(guard);
    let outcome = result?;

    // The guide prints to the now-restored screen so the cheat-sheet + next
    // step persist in scrollback after onboarding exits.
    if outcome.completed {
        guide_screen(out, style, services, &outcome.mode, &outcome.first_command)?;
    }

    Ok(outcome)
}

/// The screen sequence. Clears between steps when `fullscreen`; renders inline
/// otherwise. Does not print the closing guide — the caller does that after the
/// alternate screen is torn down.
fn run_screens(
    out: &mut impl Write,
    style: Style,
    services: &dyn OnboardingServices,
    audit_sync_default: bool,
    fullscreen: bool,
) -> std::io::Result<OnboardingOutcome> {
    let mut state = FlowState {
        mode: ProviderMode::Exec,
        audit_sync: audit_sync_default,
        trial_started: false,
    };

    // Inline mode prints the brand banner once up top; fullscreen reprints it
    // on the (cleared) welcome screen instead.
    if !fullscreen {
        brand_header(out, style)?;
    }

    // Ordered screens that collect choices. Guide is rendered after the loop.
    let screens = [Screen::Welcome, Screen::Mode, Screen::Trial];
    let mut idx = 0usize;
    let mut aborted = false;

    while idx < screens.len() {
        if fullscreen {
            render::clear(out)?;
        }
        let outcome = match screens[idx] {
            Screen::Welcome => {
                if fullscreen {
                    brand_header(out, style)?;
                }
                welcome_screen(out, style, &mut state)?
            }
            Screen::Mode => mode_screen(out, style, services, &mut state)?,
            Screen::Trial => trial_screen(out, style, services, &mut state)?,
            Screen::Guide => unreachable!("guide is rendered after the loop"),
        };
        match outcome {
            StepFlow::Next => idx += 1,
            StepFlow::Back => idx = idx.saturating_sub(1),
            StepFlow::SkipAll => break,
            StepFlow::Abort => {
                aborted = true;
                break;
            }
        }
    }

    // Let the user read the final screen (e.g. a trial-activation result)
    // before the alternate screen is restored.
    if fullscreen && !aborted {
        render::pause_for_enter(out, style)?;
    }

    let first_command = suggested_command(&state, services);
    Ok(OnboardingOutcome {
        mode: state.mode,
        audit_sync: state.audit_sync,
        trial_started: state.trial_started,
        completed: !aborted,
        first_command,
    })
}

#[derive(Clone, Copy)]
enum Screen {
    Welcome,
    Mode,
    Trial,
    #[allow(dead_code)]
    Guide,
}

struct FlowState {
    mode: ProviderMode,
    audit_sync: bool,
    trial_started: bool,
}

/// How a single screen wants the flow to proceed.
enum StepFlow {
    Next,
    Back,
    SkipAll,
    Abort,
}

/// Map a raw [`Selection`] into flow control, invoking `on_choice` for a real
/// pick. `SkipStep` is treated as "accept default and advance" by the caller
/// applying its own default before returning `Next`.
fn flow_from(selection: Selection) -> Result<usize, StepFlow> {
    match selection {
        Selection::Chosen(i) => Ok(i),
        Selection::SkipStep => Err(StepFlow::Next),
        Selection::SkipAll => Err(StepFlow::SkipAll),
        Selection::Back => Err(StepFlow::Back),
        // Unreachable: only the welcome screen sets `allow_view`, and it
        // handles `View` itself without `flow_from`. Treat as advance to stay
        // total and panic-free if that ever changes.
        Selection::View => Err(StepFlow::Next),
        Selection::Abort => Err(StepFlow::Abort),
    }
}

fn brand_header(out: &mut impl Write, style: Style) -> std::io::Result<()> {
    writeln!(out)?;
    writeln!(out, "  {}", style.green("grith — Zero Trust for AI Agents"))?;
    writeln!(out)?;
    writeln!(
        out,
        "  grith watches what your AI agents actually do — every file, network,"
    )?;
    writeln!(
        out,
        "  and process call — and stops the ones that cross the line."
    )?;
    Ok(())
}

fn welcome_screen(
    out: &mut impl Write,
    style: Style,
    state: &mut FlowState,
) -> std::io::Result<StepFlow> {
    let body = vec![
        "When you're signed in, grith can sync a reduced audit summary to".to_string(),
        "grith.ai for your dashboard & team feed. It never includes prompt".to_string(),
        "text or file contents. You can turn it off.".to_string(),
    ];
    let options = vec![
        Opt::new("Keep audit sync on   (recommended)"),
        Opt::new("Turn it off — run local-only"),
    ];
    // Pre-select based on the current config value.
    let default = usize::from(!state.audit_sync);
    let prompt = Prompt {
        step_label: None,
        title: "Privacy, up front",
        body: &body,
        options: &options,
        default,
        allow_back: false,
        allow_view: true,
        footer: "[↑/↓] choose   [Enter] continue   [v] what's synced   [S] skip setup",
    };
    // Loop so `[v]` can show the synced-data detail and re-prompt.
    loop {
        match render::select(out, style, &prompt)? {
            Selection::View => {
                render::info_block(out, &synced_data_detail())?;
                continue;
            }
            Selection::Chosen(choice) => {
                state.audit_sync = choice == 0;
                return Ok(StepFlow::Next);
            }
            Selection::SkipStep => return Ok(StepFlow::Next), // keep default
            Selection::SkipAll => return Ok(StepFlow::SkipAll),
            Selection::Back => return Ok(StepFlow::Back),
            Selection::Abort => return Ok(StepFlow::Abort),
        }
    }
}

/// The "what's synced" detail shown by `[v]` on the welcome screen. Distinguishes
/// the broader local audit log from the reduced cloud-sync records.
fn synced_data_detail() -> Vec<String> {
    vec![
        "What grith syncs to the cloud (only when signed in):".to_string(),
        "  · tool-call type, score & action (allow/queue/deny)".to_string(),
        "  · per-filter scores, timestamp, session/project".to_string(),
        "  · provider/model, token counts, estimated cost".to_string(),
        String::new(),
        "Never synced: prompt text, file contents, raw command arguments.".to_string(),
        "Your local audit log keeps the fuller record on this machine only.".to_string(),
    ]
}

fn mode_screen(
    out: &mut impl Write,
    style: Style,
    services: &dyn OnboardingServices,
    state: &mut FlowState,
) -> std::io::Result<StepFlow> {
    let tools = services.detected_tools();
    let detected = tools
        .iter()
        .map(|t| format!("{} {}", t.exec_arg, if t.present { "✓" } else { "—" }))
        .collect::<Vec<_>>()
        .join("   ");
    let ollama = services.ollama_status();
    let ollama_line = match &ollama {
        OllamaStatus::Running { models } => format!("Ollama: running ({models} model(s))"),
        OllamaStatus::Unreachable { url } => format!("Ollama: not detected at {url}"),
    };

    let options = vec![
        Opt::with_detail(
            "Supervise my existing tools          recommended",
            vec![
                "Wrap Claude Code, Codex, Aider and friends with `grith exec`.".to_string(),
                "No API key needed — your tools keep their own.".to_string(),
                format!("Detected: {detected}"),
                services.platform_summary(),
            ],
        ),
        Opt::with_detail(
            "Built-in agent — local (Ollama)",
            vec![
                "Run grith's own agent against a local model. No key.".to_string(),
                ollama_line,
            ],
        ),
        Opt::with_detail(
            "Built-in agent — cloud provider",
            vec!["Anthropic, OpenAI, or OpenRouter via an env-var key.".to_string()],
        ),
    ];
    let prompt = Prompt {
        step_label: Some("Step 1 of 2".to_string()),
        title: "How will you use grith?",
        body: &[],
        options: &options,
        default: 0,
        allow_back: false,
        allow_view: false,
        footer: "[↑/↓] choose   [Enter] select   [s] skip → exec mode",
    };
    let choice = match flow_from(render::select(out, style, &prompt)?) {
        Ok(c) => c,
        Err(StepFlow::Next) => {
            state.mode = ProviderMode::Exec; // skip default
            return Ok(StepFlow::Next);
        }
        Err(other) => return Ok(other),
    };

    state.mode = match choice {
        1 => {
            // Screen 2b: if Ollama isn't reachable, show pull guidance.
            if let OllamaStatus::Unreachable { url } = &ollama {
                render::info_block(
                    out,
                    &[
                        format!("⚠ Ollama isn't running at {url}."),
                        "The built-in agent needs Ollama up with a model pulled, e.g.:".to_string(),
                        "    ollama pull llama3.1:8b".to_string(),
                        "Saved anyway — start Ollama when you're ready.".to_string(),
                    ],
                )?;
            }
            ProviderMode::Ollama
        }
        2 => cloud_provider_screen(out, style, services)?,
        _ => ProviderMode::Exec,
    };
    Ok(StepFlow::Next)
}

/// Sub-screen: pick a cloud provider and report env-var status. Under the
/// env-var-only credential policy onboarding never stores a key — it sets the
/// default provider and guides the user to export the variable.
fn cloud_provider_screen(
    out: &mut impl Write,
    style: Style,
    services: &dyn OnboardingServices,
) -> std::io::Result<ProviderMode> {
    let providers = [
        CloudProvider::Anthropic,
        CloudProvider::OpenAI,
        CloudProvider::OpenRouter,
    ];
    let options = providers
        .iter()
        .map(|p| {
            let present = services.cloud_env_present(*p);
            let status = if present {
                format!("{} detected", p.env_var())
            } else {
                format!("set {} before running", p.env_var())
            };
            Opt::with_detail(p.display(), vec![status])
        })
        .collect::<Vec<_>>();
    let prompt = Prompt {
        step_label: Some("Step 1 of 2".to_string()),
        title: "Cloud provider",
        body: &[],
        options: &options,
        default: 0,
        allow_back: true,
        allow_view: false,
        footer: "[↑/↓] choose   [Enter] select   [b] back   [s] skip → exec mode",
    };
    let choice = match flow_from(render::select(out, style, &prompt)?) {
        Ok(c) => c,
        // Back / skip from the sub-screen fall back to exec mode.
        Err(_) => return Ok(ProviderMode::Exec),
    };
    let provider = providers[choice];
    if !services.cloud_env_present(provider) {
        render::info_block(
            out,
            &[format!(
                "Set your key before running:  export {}=…",
                provider.env_var()
            )],
        )?;
    }
    Ok(ProviderMode::Cloud(provider))
}

fn trial_screen(
    out: &mut impl Write,
    style: Style,
    services: &dyn OnboardingServices,
    state: &mut FlowState,
) -> std::io::Result<StepFlow> {
    let body = vec![
        "Community is free forever. Start a 14-day Pro trial (no card), or".to_string(),
        "sign in if you already have an account or are on a team.".to_string(),
    ];
    let options = vec![
        Opt::new("Maybe later"),
        Opt::new("Start free trial   (creates a new account)"),
        Opt::new("Sign in to an existing account or team"),
    ];
    let prompt = Prompt {
        step_label: Some("Step 2 of 2".to_string()),
        title: "Pro: start a trial or sign in",
        body: &body,
        options: &options,
        default: 0,
        allow_back: true,
        allow_view: false,
        footer: "[↑/↓] choose   [Enter] select   [b] back   [s] skip",
    };
    let choice = match flow_from(render::select(out, style, &prompt)?) {
        Ok(c) => c,
        Err(StepFlow::Next) => return Ok(StepFlow::Next), // skip → maybe later
        Err(other) => return Ok(other),
    };
    match choice {
        1 => render_trial_result(out, services, state)?,
        2 => render_sign_in_result(out, services)?,
        _ => {} // "Maybe later"
    }
    Ok(StepFlow::Next)
}

/// Render the outcome of `start_trial`.
fn render_trial_result(
    out: &mut impl Write,
    services: &dyn OnboardingServices,
    state: &mut FlowState,
) -> std::io::Result<()> {
    match services.start_trial() {
        TrialResult::Activated { until } => {
            let suffix = until.map(|u| format!(" until {u}")).unwrap_or_default();
            render::info_block(
                out,
                &[format!("✓ Pro trial active{suffix}. Welcome to Pro.")],
            )?;
            state.trial_started = true;
        }
        TrialResult::Pending => {
            render::info_block(
                out,
                &[
                    "Trial activation is still pending. Run `grith pro refresh` in a moment."
                        .to_string(),
                    "If a browser sign-in page is open, finish that first.".to_string(),
                ],
            )?;
            state.trial_started = true;
        }
        TrialResult::Failed { message } => {
            render::info_block(
                out,
                &[
                    format!("Couldn't start the trial: {message}"),
                    "You can try again later with `grith pro start-trial`.".to_string(),
                ],
            )?;
        }
    }
    Ok(())
}

/// Render the outcome of `sign_in`.
fn render_sign_in_result(
    out: &mut impl Write,
    services: &dyn OnboardingServices,
) -> std::io::Result<()> {
    match services.sign_in() {
        SignInResult::SignedIn {
            plan,
            team,
            keys_pulled,
        } => {
            let mut lines = vec![format!("✓ Signed in — {plan} plan.")];
            if let Some(team) = team {
                lines.push(format!("Team: {team}"));
            }
            if keys_pulled > 0 {
                lines.push(format!("Pulled {keys_pulled} team provider key(s)."));
            }
            render::info_block(out, &lines)?;
        }
        SignInResult::Pending => {
            render::info_block(
                out,
                &[
                    "Sign-in is still pending. Run `grith pro refresh` in a moment.".to_string(),
                    "If a browser sign-in page is open, finish that first.".to_string(),
                ],
            )?;
        }
        SignInResult::Failed { message } => {
            render::info_block(
                out,
                &[
                    format!("Couldn't sign in: {message}"),
                    "You can sign in later with `grith pro login`.".to_string(),
                ],
            )?;
        }
    }
    Ok(())
}

fn guide_screen(
    out: &mut impl Write,
    style: Style,
    services: &dyn OnboardingServices,
    mode: &ProviderMode,
    first_command: &str,
) -> std::io::Result<()> {
    let mut lines = vec![
        style.green("✓ You're set."),
        String::new(),
        "How grith works, in four lines:".to_string(),
        format!(
            "  {}   supervise an external tool",
            style.dim("grith exec -- claude-code \"…\"")
        ),
        format!(
            "  {}                   use the built-in agent",
            style.dim("grith run \"…\"")
        ),
        format!(
            "  {}                           open the interactive REPL",
            style.dim("grith")
        ),
        format!(
            "  {}                    review anything grith paused",
            style.dim("grith digest")
        ),
    ];
    // Remind cloud-mode users to export their key (env-var-only policy) when
    // the variable isn't already set.
    if let ProviderMode::Cloud(p) = mode {
        if !services.cloud_env_present(*p) {
            lines.push(String::new());
            lines.push(format!("Before `grith run`: export {}=…", p.env_var()));
        }
    }
    if let Some(url) = services.dashboard_url() {
        lines.push(String::new());
        lines.push(format!("Dashboard: {}", style.dim(&url)));
    }
    lines.push(String::new());
    lines.push("Your next step:".to_string());
    lines.push(format!("  {}", style.green(first_command)));
    render::info_block(out, &lines)?;
    Ok(())
}

/// The suggested first command for the guide, derived from the chosen mode.
fn suggested_command(state: &FlowState, services: &dyn OnboardingServices) -> String {
    match &state.mode {
        ProviderMode::Exec => {
            let tool = services
                .detected_tools()
                .into_iter()
                .find(|t| t.present)
                .map(|t| t.exec_arg)
                .unwrap_or_else(|| "claude-code".to_string());
            format!("grith exec -- {tool} \"list files in this repo\"")
        }
        ProviderMode::Ollama | ProviderMode::Cloud(_) => {
            "grith run \"summarise the files in this folder\"".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted services impl for flow tests.
    struct FakeServices {
        ollama_running: bool,
        anthropic_env: bool,
    }
    impl OnboardingServices for FakeServices {
        fn detected_tools(&self) -> Vec<DetectedTool> {
            vec![
                DetectedTool {
                    name: "Claude Code".into(),
                    exec_arg: "claude-code".into(),
                    present: true,
                },
                DetectedTool {
                    name: "Codex".into(),
                    exec_arg: "codex".into(),
                    present: false,
                },
            ]
        }
        fn platform_summary(&self) -> String {
            "full supervision available".into()
        }
        fn ollama_status(&self) -> OllamaStatus {
            if self.ollama_running {
                OllamaStatus::Running { models: 2 }
            } else {
                OllamaStatus::Unreachable {
                    url: "http://localhost:11434".into(),
                }
            }
        }
        fn cloud_env_present(&self, provider: CloudProvider) -> bool {
            matches!(provider, CloudProvider::Anthropic) && self.anthropic_env
        }
        fn dashboard_url(&self) -> Option<String> {
            Some("http://127.0.0.1:3141".into())
        }
        fn start_trial(&self) -> TrialResult {
            TrialResult::Pending
        }
        fn sign_in(&self) -> SignInResult {
            SignInResult::Pending
        }
    }

    fn fake() -> FakeServices {
        FakeServices {
            ollama_running: false,
            anthropic_env: false,
        }
    }

    #[test]
    fn cloud_provider_metadata() {
        assert_eq!(CloudProvider::Anthropic.config_key(), "anthropic");
        assert_eq!(CloudProvider::OpenAI.env_var(), "OPENAI_API_KEY");
        assert_eq!(CloudProvider::OpenRouter.display(), "OpenRouter");
    }

    #[test]
    fn suggested_command_exec_uses_first_present_tool() {
        let state = FlowState {
            mode: ProviderMode::Exec,
            audit_sync: true,
            trial_started: false,
        };
        let cmd = suggested_command(&state, &fake());
        assert_eq!(cmd, "grith exec -- claude-code \"list files in this repo\"");
    }

    #[test]
    fn suggested_command_builtin_uses_run() {
        let state = FlowState {
            mode: ProviderMode::Ollama,
            audit_sync: true,
            trial_started: false,
        };
        assert!(suggested_command(&state, &fake()).starts_with("grith run"));
    }

    #[test]
    fn synced_data_detail_discloses_reduction() {
        let text = synced_data_detail().join("\n");
        // Must promise the reduction and name what is never synced.
        assert!(text.contains("Never synced"));
        assert!(text.contains("prompt text"));
        assert!(text.contains("file contents"));
        // Lists at least one reduced field actually synced.
        assert!(text.contains("token counts") || text.contains("score"));
    }

    #[test]
    fn flow_from_maps_selection() {
        assert!(matches!(flow_from(Selection::Chosen(2)), Ok(2)));
        assert!(matches!(
            flow_from(Selection::SkipStep),
            Err(StepFlow::Next)
        ));
        assert!(matches!(
            flow_from(Selection::SkipAll),
            Err(StepFlow::SkipAll)
        ));
        assert!(matches!(flow_from(Selection::Back), Err(StepFlow::Back)));
        assert!(matches!(flow_from(Selection::Abort), Err(StepFlow::Abort)));
    }
}
