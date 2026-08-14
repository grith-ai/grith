// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! First-run onboarding flow (`grith setup`, and the auto-trigger on a fresh
//! interactive launch) plus the one-line `grith exec` first-run notice.
//!
//! This module owns the **orchestration and side effects** of onboarding: it
//! implements [`grith_cli::onboarding::OnboardingServices`] (live tool
//! detection, Ollama probe, dashboard URL, trial), runs the interactive
//! `grith-cli` engine, then applies the returned choices to config and
//! persists exactly once (unless the user aborted).

use crate::config::GrithConfig;
use grith_cli::onboarding::{
    self, CloudProvider, DetectedTool, OllamaStatus, OnboardingOutcome, OnboardingServices,
    ProviderMode, SignInResult, TrialResult,
};
use std::time::Duration;

/// Run the full onboarding flow because the user explicitly asked for it
/// (`grith setup`). Always runs regardless of the `onboarded` flag.
pub fn run_setup(cfg: &mut GrithConfig, enable_color: bool) -> anyhow::Result<()> {
    run_flow(cfg, enable_color)
}

/// Run onboarding as the first-run auto-trigger. The caller is responsible for
/// the eligibility gate (see `should_auto_run_onboarding` in `main`).
pub fn run_onboarding(cfg: &mut GrithConfig, enable_color: bool) -> anyhow::Result<()> {
    run_flow(cfg, enable_color)
}

/// The onboarding flow body: run the interactive engine, then apply + persist.
///
/// On a clean finish (including `S` skip-all) the collected choices are applied
/// to `cfg`, the install is marked onboarded, and the config is persisted once.
/// On abort (`Ctrl-C`/`Esc`) nothing is written and the install stays
/// not-onboarded.
fn run_flow(cfg: &mut GrithConfig, enable_color: bool) -> anyhow::Result<()> {
    let services = CoreOnboardingServices { cfg: cfg.clone() };
    let mut out = std::io::stdout();
    let outcome = onboarding::run(&mut out, &services, cfg.general.audit_sync, enable_color)?;

    if outcome.completed {
        apply_outcome(cfg, &outcome);
        complete_onboarding(cfg);
        persist_config(cfg)?;
    } else {
        // Aborted: discard all choices, do not mark onboarded, do not persist.
        tracing::debug!("onboarding aborted by user — no changes written");
    }
    Ok(())
}

/// Apply the engine's collected choices to the in-memory config.
fn apply_outcome(cfg: &mut GrithConfig, outcome: &OnboardingOutcome) {
    cfg.general.audit_sync = outcome.audit_sync;
    match &outcome.mode {
        // Exec mode does not use the built-in agent, so leave
        // `llm.default_provider` at its default (a real provider value, which
        // the config validator requires).
        ProviderMode::Exec => {}
        ProviderMode::Ollama => cfg.llm.default_provider = "ollama".to_string(),
        ProviderMode::Cloud(p) => cfg.llm.default_provider = p.config_key().to_string(),
    }
}

/// `grith-core`'s implementation of the engine's live-services trait. Holds a
/// snapshot of the config so probes (Ollama URL, dashboard URL, env vars) use
/// the effective values.
struct CoreOnboardingServices {
    cfg: GrithConfig,
}

impl OnboardingServices for CoreOnboardingServices {
    fn detected_tools(&self) -> Vec<DetectedTool> {
        supported_tools()
            .iter()
            .map(|(name, primary, aliases)| {
                let found = aliases.iter().copied().find(|b| binary_on_path(b));
                DetectedTool {
                    name: (*name).to_string(),
                    exec_arg: found.unwrap_or(primary).to_string(),
                    present: found.is_some(),
                }
            })
            .collect()
    }

    fn platform_summary(&self) -> String {
        use grith_supervisor::platform::{platform_capability, PlatformCapability};
        match platform_capability() {
            PlatformCapability::Full => "Platform: full supervision available".to_string(),
            PlatformCapability::Degraded => {
                "Platform: lifecycle-only supervision on this OS".to_string()
            }
            PlatformCapability::Unavailable => {
                "Platform: supervision unavailable on this OS".to_string()
            }
        }
    }

    fn ollama_status(&self) -> OllamaStatus {
        probe_ollama(&self.cfg.llm.ollama.base_url)
    }

    fn cloud_env_present(&self, provider: CloudProvider) -> bool {
        std::env::var(provider.env_var()).is_ok_and(|v| !v.is_empty())
    }

    fn dashboard_url(&self) -> Option<String> {
        dashboard_base_url(&self.cfg)
    }

    fn start_trial(&self) -> TrialResult {
        // Seamless inline trial: link the CLI to a (possibly newly signed-up)
        // account via browser device-auth, then activate. Shares the exact flow
        // used by `grith pro start-trial`.
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                return TrialResult::Failed {
                    message: format!("could not start the trial flow: {e}"),
                }
            }
        };
        use crate::commands::pro::TrialFlowOutcome;
        match crate::commands::pro::run_trial_flow(&rt) {
            TrialFlowOutcome::Activated { valid_until, .. } => {
                TrialResult::Activated { until: valid_until }
            }
            TrialFlowOutcome::AlreadyActive => TrialResult::Activated { until: None },
            TrialFlowOutcome::NeedsBrowser => TrialResult::Pending,
            TrialFlowOutcome::Failed(message) => TrialResult::Failed { message },
        }
    }

    fn sign_in(&self) -> SignInResult {
        // Link an existing account (or team) via browser device-auth, then pull
        // team-distributed resources. Shares `grith pro login`'s machinery.
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                return SignInResult::Failed {
                    message: format!("could not start sign-in: {e}"),
                }
            }
        };
        use crate::commands::pro::SignInOutcome;
        match crate::commands::pro::run_sign_in_flow(&rt) {
            SignInOutcome::SignedIn {
                plan,
                team,
                keys_pulled,
            } => SignInResult::SignedIn {
                plan,
                team,
                keys_pulled,
            },
            SignInOutcome::NeedsBrowser => SignInResult::Pending,
            SignInOutcome::Failed(message) => SignInResult::Failed { message },
        }
    }
}

/// Curated list of supervised tools: (display name, canonical exec arg, PATH
/// aliases to probe). Mirrors `grith_supervisor::profiles::detect_profile`.
fn supported_tools() -> &'static [(&'static str, &'static str, &'static [&'static str])] {
    &[
        ("Claude Code", "claude-code", &["claude-code", "claude"]),
        ("Codex", "codex", &["codex"]),
        ("Aider", "aider", &["aider"]),
        ("Cursor Agent", "cursor-agent", &["cursor-agent"]),
        ("Goose", "goose", &["goose"]),
        ("Copilot CLI", "copilot", &["copilot", "copilot-cli"]),
        ("Cline", "cline", &["cline"]),
        ("OpenClaw", "openclaw", &["openclaw"]),
    ]
}

/// Whether `name` resolves to an executable regular file on any `PATH` entry.
fn binary_on_path(name: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| is_executable_file(&dir.join(name)))
}

/// Whether `path` is (or symlinks to) an executable regular file. Follows
/// symlinks via `metadata()`, so a dangling link or a link to a directory is
/// correctly rejected. On Unix the executable bit is also required.
fn is_executable_file(path: &std::path::Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
}

/// Probe the local Ollama server's `/api/tags` with a short timeout.
///
/// Runs on a dedicated thread so the internal `block_on` is safe regardless of
/// whether the caller is already inside a Tokio runtime (onboarding is sync
/// today, but this keeps the helper context-agnostic).
fn probe_ollama(base_url: &str) -> OllamaStatus {
    let url = base_url.to_string();
    let fallback = OllamaStatus::Unreachable {
        url: base_url.to_string(),
    };
    std::thread::scope(|scope| {
        scope
            .spawn(|| probe_ollama_blocking(&url))
            .join()
            .unwrap_or(fallback)
    })
}

/// The blocking probe body. Must run on a thread with no ambient Tokio runtime.
fn probe_ollama_blocking(base_url: &str) -> OllamaStatus {
    let unreachable = || OllamaStatus::Unreachable {
        url: base_url.to_string(),
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return unreachable();
    };
    rt.block_on(async {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_millis(800))
            .build()
        {
            Ok(c) => c,
            Err(_) => return unreachable(),
        };
        match client.get(format!("{base_url}/api/tags")).send().await {
            Ok(resp) if resp.status().is_success() => {
                let models = resp
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|v| v.get("models").and_then(|m| m.as_array()).map(Vec::len))
                    .unwrap_or(0);
                OllamaStatus::Running { models }
            }
            _ => unreachable(),
        }
    })
}

/// Mark the install as having completed onboarding. Deliberately does NOT touch
/// `exec_notice_seen` — completing setup and having seen the exec notice are
/// independent signals.
fn complete_onboarding(cfg: &mut GrithConfig) {
    cfg.general.onboarded = true;
}

/// Mark the one-line `grith exec` notice as shown. Deliberately does NOT mark
/// the install onboarded — supervising a tool is not completing setup.
fn mark_exec_notice_seen(cfg: &mut GrithConfig) {
    cfg.general.exec_notice_seen = true;
}

/// Print the one-line `grith exec` first-run notice exactly once, then persist
/// `exec_notice_seen = true`. Non-blocking: the supervised tool launches
/// immediately afterwards. Goes to stderr so it never pollutes a tool's stdout.
pub fn show_exec_notice_once(cfg: &mut GrithConfig, tool_name: Option<&str>) {
    let tool_hint = match tool_name {
        Some(name) if !name.is_empty() => format!(" {name}"),
        _ => String::new(),
    };
    let dash = dashboard_base_url(cfg)
        .map(|u| format!("  Dashboard: {u}"))
        .unwrap_or_default();
    eprintln!(
        "👋 First run — grith is now supervising{tool_hint}. Configure providers, trial,\n   and notifications anytime with `grith setup`.{dash}"
    );

    mark_exec_notice_seen(cfg);
    // Best-effort persistence: if we cannot write the user config (e.g. a
    // read-only HOME), we simply show the notice again next time rather than
    // failing the user's exec invocation.
    if let Err(e) = persist_config(cfg) {
        tracing::debug!(error = %e, "could not persist exec_notice_seen");
    }
}

/// Persist the current config to the user config file, creating it if needed.
/// Writes the full effective config (consistent with `grith config set`).
fn persist_config(cfg: &GrithConfig) -> Result<(), crate::error::Error> {
    cfg.save_user_config().map(|_| ())
}

/// `http://<host>:<port>` for the local dashboard, or `None` if the server is
/// disabled. Uses a loopback host literal when the configured host is a
/// wildcard so the printed URL is actually reachable from a browser.
fn dashboard_base_url(cfg: &GrithConfig) -> Option<String> {
    if !cfg.server.enabled {
        return None;
    }
    let host = match cfg.server.host.as_str() {
        "0.0.0.0" | "::" | "" => "127.0.0.1",
        other => other,
    };
    Some(format!("http://{host}:{}", cfg.server.port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_url_disabled_when_server_off() {
        let mut cfg = GrithConfig::default();
        cfg.server.enabled = false;
        assert_eq!(dashboard_base_url(&cfg), None);
    }

    #[test]
    fn dashboard_url_uses_loopback_for_wildcard_host() {
        let mut cfg = GrithConfig::default();
        cfg.server.enabled = true;
        cfg.server.host = "0.0.0.0".into();
        cfg.server.port = 3141;
        assert_eq!(
            dashboard_base_url(&cfg).as_deref(),
            Some("http://127.0.0.1:3141")
        );
    }

    #[test]
    fn dashboard_url_preserves_specific_host() {
        let mut cfg = GrithConfig::default();
        cfg.server.enabled = true;
        cfg.server.host = "127.0.0.1".into();
        cfg.server.port = 8080;
        assert_eq!(
            dashboard_base_url(&cfg).as_deref(),
            Some("http://127.0.0.1:8080")
        );
    }

    #[test]
    fn apply_outcome_sets_provider_and_audit_sync() {
        let mut cfg = GrithConfig::default();
        cfg.general.audit_sync = true;
        let outcome = OnboardingOutcome {
            mode: ProviderMode::Cloud(CloudProvider::Anthropic),
            audit_sync: false,
            trial_started: false,
            completed: true,
            first_command: String::new(),
        };
        apply_outcome(&mut cfg, &outcome);
        assert!(!cfg.general.audit_sync);
        assert_eq!(cfg.llm.default_provider, "anthropic");
    }

    #[test]
    fn apply_outcome_exec_mode_leaves_provider_default() {
        let mut cfg = GrithConfig::default();
        let original = cfg.llm.default_provider.clone();
        let outcome = OnboardingOutcome {
            mode: ProviderMode::Exec,
            audit_sync: true,
            trial_started: false,
            completed: true,
            first_command: String::new(),
        };
        apply_outcome(&mut cfg, &outcome);
        // Exec mode does not touch the built-in provider.
        assert_eq!(cfg.llm.default_provider, original);
    }

    #[test]
    fn supported_tools_cover_known_profiles() {
        let names: Vec<&str> = supported_tools().iter().map(|(_, p, _)| *p).collect();
        for expected in ["claude-code", "codex", "aider", "openclaw"] {
            assert!(names.contains(&expected), "missing {expected}");
        }
        // Every entry's primary exec arg must appear among its aliases.
        for (_, primary, aliases) in supported_tools() {
            assert!(
                aliases.contains(primary),
                "primary {primary} not in aliases"
            );
        }
    }

    #[test]
    fn binary_on_path_finds_present_and_misses_absent() {
        // `sh` is on PATH on any POSIX dev box; a random name is not.
        assert!(binary_on_path("sh"));
        assert!(!binary_on_path("grith-definitely-not-a-real-binary-xyz"));
    }

    #[test]
    #[cfg(unix)]
    fn is_executable_file_handles_symlinks_and_perms() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();

        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(is_executable_file(&exe), "executable regular file");

        let plain = dir.path().join("readme");
        std::fs::write(&plain, b"x").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable_file(&plain), "non-executable file rejected");

        let link = dir.path().join("toollink");
        symlink(&exe, &link).unwrap();
        assert!(is_executable_file(&link), "symlink to exec file accepted");

        let dangling = dir.path().join("dangling");
        symlink(dir.path().join("does-not-exist"), &dangling).unwrap();
        assert!(!is_executable_file(&dangling), "dangling symlink rejected");

        let dirlink = dir.path().join("dirlink");
        symlink(dir.path(), &dirlink).unwrap();
        assert!(
            !is_executable_file(&dirlink),
            "symlink to directory rejected"
        );
    }

    #[test]
    fn onboarding_completion_sets_only_onboarded() {
        // The auto-trigger / `grith setup` flow marks onboarded but must not
        // consume the independent exec-notice signal.
        let mut cfg = GrithConfig::default();
        complete_onboarding(&mut cfg);
        assert!(cfg.general.onboarded);
        assert!(!cfg.general.exec_notice_seen);
    }

    #[test]
    fn exec_notice_sets_only_exec_notice_seen() {
        // Seeing the exec notice must NOT mark the install onboarded — a later
        // interactive `grith` should still offer the wizard.
        let mut cfg = GrithConfig::default();
        mark_exec_notice_seen(&mut cfg);
        assert!(cfg.general.exec_notice_seen);
        assert!(!cfg.general.onboarded);
    }
}
