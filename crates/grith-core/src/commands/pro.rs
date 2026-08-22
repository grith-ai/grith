// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith pro` subcommand — license authentication, status, and plan management.

use crate::daemon::background::{run_license_refresh, RefreshOutcome};
use crate::{daemon, license};

const DEFAULT_BILLING_PORTAL_URL: &str = "https://grith.ai/dashboard/settings/billing";

/// Upper bound on how long we'll wait for browser device-authorization,
/// regardless of the server-reported `expires_in`. Also guards against an
/// `Instant + Duration` overflow panic from an absurd server value.
const MAX_DEVICE_AUTH_WAIT_SECS: u64 = 1800;

/// Compute the device-auth polling deadline, clamping the server-provided
/// `expires_in` to [`MAX_DEVICE_AUTH_WAIT_SECS`] so a malicious/buggy value
/// can neither hang the CLI indefinitely nor overflow `Instant`.
fn device_auth_deadline(expires_in: u64) -> std::time::Instant {
    std::time::Instant::now()
        + std::time::Duration::from_secs(expires_in.min(MAX_DEVICE_AUTH_WAIT_SECS))
}

pub fn cmd_pro_login(api_key: Option<&str>) -> anyhow::Result<()> {
    let base_url = license::api_base_url();
    if let Some(key) = api_key {
        println!("Authenticating with {base_url}...");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let signed = runtime.block_on(async { license::fetch_license(key).await })?;
        return complete_login_from_license(key, signed);
    }

    println!("Starting browser-based device authorization with {base_url}...");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let start = runtime.block_on(async { license::start_device_authorization().await })?;

    println!();
    println!("Open this URL in your browser and sign in:");
    println!("  {}", start.verification_url);
    println!();
    println!("Enter this code on the webpage:");
    println!("  {}", start.user_code);
    println!();
    println!("Waiting for authorization...");

    if let Err(e) = open::that(&start.verification_url) {
        println!("Could not open browser automatically: {e}");
    }

    let expires_at = device_auth_deadline(start.expires_in);
    let poll_interval = std::time::Duration::from_secs(start.interval.max(1));

    loop {
        if std::time::Instant::now() >= expires_at {
            anyhow::bail!(
                "device authorization timed out; run `grith pro login` again for a new code"
            );
        }

        let (status, payload) = runtime
            .block_on(async { license::poll_device_authorization(&start.device_code).await })?;

        match status {
            license::DeviceAuthPollStatus::Pending => {
                std::thread::sleep(poll_interval);
            }
            license::DeviceAuthPollStatus::Expired => {
                anyhow::bail!("device code expired; run `grith pro login` to generate a new code");
            }
            license::DeviceAuthPollStatus::NoActiveLicense => {
                let pricing_url = format!("{}/pricing", crate::license::web_base_url());
                println!();
                println!("You signed in successfully, but your team has no active license.");
                println!("Your free trial may have ended, or your subscription may have lapsed.");
                println!();
                println!("Upgrade or manage billing: {pricing_url}");
                println!("Once your plan is active, run `grith pro login` again.");
                anyhow::bail!("no active license for this team");
            }
            license::DeviceAuthPollStatus::Approved => {
                let Some(payload) = payload else {
                    anyhow::bail!("authorization completed but no device payload was returned");
                };
                println!("Authorization complete.");
                return complete_login_from_license(&payload.api_key, payload.license);
            }
        }
    }
}

pub(crate) fn persist_team_learned_rules_cache(
    rules: &[crate::license::LearnedRuleResponse],
) -> anyhow::Result<std::path::PathBuf> {
    let cache_path = grith_supervisor::learned_rules::team_learned_rules_cache_path();
    let cache_rules: Vec<grith_supervisor::learned_rules::TeamLearnedRule> = rules
        .iter()
        .map(|rule| grith_supervisor::learned_rules::TeamLearnedRule {
            pattern: rule.pattern.clone(),
            profile: rule.profile.clone(),
            scope: rule.scope.clone(),
            reason: rule.reason.clone(),
            created_by: rule.created_by.clone(),
            created_at: rule.created_at.clone(),
        })
        .collect();

    grith_supervisor::learned_rules::write_team_learned_rules_cache(&cache_path, &cache_rules)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(cache_path)
}

/// Best-effort: nudge a running daemon to re-apply the license gate now, so a
/// freshly written license (login / activate / trial / refresh) takes effect
/// immediately — updating the concurrent-session limit and other gated
/// features — instead of waiting for the daemon's 24-hour scheduled refresh or
/// a restart. No-op if no daemon is running or on non-Unix platforms.
#[cfg(unix)]
fn notify_daemon_regate() {
    if let Some((pid, _port)) = crate::daemon::is_dashboard_running() {
        // SAFETY: `pid` comes from our own PID file and was just liveness-checked
        // by `is_dashboard_running` (kill(pid, 0)). SIGHUP is handled by the
        // daemon's re-gate task; a process that exits in the race window yields
        // ESRCH, which we harmlessly ignore.
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGHUP) };
        tracing::debug!(
            pid,
            ret,
            "signalled daemon (SIGHUP) to re-apply license gate"
        );
    } else {
        // No running daemon to signal: the new license will take effect the
        // next time the daemon starts. Logged so an operator diagnosing "my
        // upgrade didn't take effect" can see the nudge was a no-op.
        tracing::debug!("no running daemon to signal; license gate applies on next daemon start");
    }
}

/// No-op on non-Unix platforms (no SIGHUP); the license takes effect on the
/// next scheduled refresh or daemon restart.
#[cfg(not(unix))]
fn notify_daemon_regate() {}

/// Verify the signed license, save it + credentials, and return the verified
/// license plus its on-disk path. Quiet (no printing) so it can be reused by
/// both the login command and the seamless trial flow.
fn persist_login(
    api_key: &str,
    signed: license::SignedLicense,
) -> anyhow::Result<(license::License, std::path::PathBuf)> {
    let license_bytes = serde_json::to_vec(&signed)?;
    let verified = license::verify_license(&license_bytes)
        .map_err(|e| anyhow::anyhow!("license verification failed: {e}"))?;

    let lic_path = license::save_license(&signed)
        .map_err(|e| anyhow::anyhow!("failed to save license: {e}"))?;

    let creds = license::Credentials {
        user_id: verified.user_id.clone(),
        api_key: api_key.to_string(),
        team_id: verified.team_id.clone(),
        license_file: lic_path.display().to_string(),
        activated_at: chrono::Utc::now().to_rfc3339(),
        last_validated: chrono::Utc::now().to_rfc3339(),
        last_synced: None,
    };
    license::save_credentials(&creds)
        .map_err(|e| anyhow::anyhow!("failed to save credentials: {e}"))?;

    // Apply the new license to a running daemon at once (session limit etc.).
    notify_daemon_regate();

    Ok((verified, lic_path))
}

fn complete_login_from_license(
    api_key: &str,
    signed: license::SignedLicense,
) -> anyhow::Result<()> {
    let (verified, lic_path) = persist_login(api_key, signed)?;
    println!("Logged in successfully.");
    println!("  Plan:    {}", verified.plan);
    println!("  Email:   {}", verified.email);
    println!("  Team:    {}", verified.team_id);
    println!("  Expires: {}", verified.valid_until.format("%Y-%m-%d"));
    println!("  License: {}", lic_path.display());
    Ok(())
}

pub fn cmd_pro_status() -> anyhow::Result<()> {
    let creds = license::load_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;

    let Some(creds) = creds else {
        println!("Not logged in.");
        println!("  Run: grith pro login");
        println!("       or: grith pro login --api-key <key>");
        return Ok(());
    };

    let status = license::load_license(&license::license_path());
    let tier = license::plan_tier_from_status(&status);
    let dashboard_url = format!("{}/dashboard/settings", license::web_base_url());
    let billing_url = license::billing_portal_url_from_status(&status)
        .unwrap_or_else(|| DEFAULT_BILLING_PORTAL_URL.to_string());

    let air_gapped = matches!(
        status,
        license::LicenseStatus::Valid(ref l)
        | license::LicenseStatus::GracePeriod { license: ref l, .. }
        | license::LicenseStatus::ExtendedGrace { license: ref l, .. }
            if l.air_gapped
    );

    match &status {
        license::LicenseStatus::Valid(lic) => {
            let days = license::days_until_expiry(lic);
            println!("Plan:       {} ({})", lic.plan, tier);
            println!("Email:      {}", lic.email);
            println!("Team:       {}", lic.team_id);
            println!("Seats:      {}", lic.seats);
            println!(
                "Renewal:    {} ({days} days remaining)",
                lic.valid_until.format("%Y-%m-%d")
            );
            println!("Status:     Active");
            println!("Billing:    {billing_url}");
            if !lic.features.is_empty() {
                println!("Features:   {}", lic.features.join(", "));
            }
        }
        license::LicenseStatus::GracePeriod {
            license: lic,
            expired_days,
        } => {
            println!("Plan:       {} ({})", lic.plan, tier);
            println!("Email:      {}", lic.email);
            println!("Seats:      {}", lic.seats);
            println!("Status:     Grace period ({expired_days} day(s) past expiry)");
            println!("Billing:    {billing_url}");
            println!("            Run: grith pro refresh");
        }
        license::LicenseStatus::ExtendedGrace {
            license: lic,
            expired_days,
        } => {
            println!("Plan:       {} ({})", lic.plan, tier);
            println!("Email:      {}", lic.email);
            println!("Seats:      {}", lic.seats);
            println!("Status:     Extended grace ({expired_days} day(s) past expiry)");
            println!("Billing:    {billing_url}");
            println!("            Renew at {dashboard_url}");
        }
        license::LicenseStatus::Expired => {
            println!("Plan:       community (expired)");
            println!("Status:     License expired beyond grace window. Pro features disabled.");
            println!("            Renew at {dashboard_url}");
        }
        license::LicenseStatus::NotFound => {
            println!("Plan:       community");
            println!("Status:     No license file found.");
            println!("            Run: grith pro activate");
        }
        license::LicenseStatus::Invalid(reason) => {
            println!("Plan:       community");
            println!("Status:     Invalid license: {reason}");
            println!("            Run: grith pro activate");
        }
    }

    let validated = creds.last_validated.clone();
    let validated_dt = chrono::DateTime::parse_from_rfc3339(&validated)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc));
    let hours_since = validated_dt.map(|dt| (chrono::Utc::now() - dt).num_hours());
    if let Some(hours) = hours_since {
        println!("Validated:  {validated} ({hours}h ago)");
    } else {
        println!("Validated:  {validated}");
    }

    if air_gapped {
        println!("Refresh:    disabled (air-gapped contract licence)");
    } else if let Some(daemon_state) = fetch_remote_refresh_state() {
        if let Some(next) = daemon_state.refresh.next_attempt.as_ref() {
            println!("Next refresh: {next}");
        }
        if let (Some(when), Some(kind)) = (
            daemon_state.refresh.last_failure.as_ref(),
            daemon_state.refresh.last_failure_kind.as_ref(),
        ) {
            let reason = daemon_state
                .refresh
                .last_failure_reason
                .as_deref()
                .unwrap_or("");
            println!("Last failure: {when} [{kind}] {reason}");
        }
    } else {
        println!("Refresh:    daemon not running (start with `grith run` to schedule refreshes)");
    }

    if let Some(synced) = &creds.last_synced {
        println!("Last sync:  {synced}");
    }

    Ok(())
}

#[derive(serde::Deserialize)]
struct RemoteRefreshSnapshot {
    refresh: RemoteRefresh,
}

#[derive(serde::Deserialize)]
struct RemoteRefresh {
    next_attempt: Option<String>,
    last_failure: Option<String>,
    last_failure_kind: Option<String>,
    last_failure_reason: Option<String>,
}

fn fetch_remote_refresh_state() -> Option<RemoteRefreshSnapshot> {
    let (_pid, port) = daemon::is_dashboard_running()?;
    let url = format!("http://127.0.0.1:{port}/api/license/status");
    let resp = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .ok()?
        .get(url)
        .send()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<RemoteRefreshSnapshot>().ok()
}

pub fn cmd_pro_upgrade() -> anyhow::Result<()> {
    let status = license::load_license(&license::license_path());
    if matches!(status, license::LicenseStatus::Valid(_)) {
        println!("Already on Pro plan.");
        return Ok(());
    }

    let url = "https://grith.ai/pricing";
    println!("Opening grith.ai/pricing in your browser...");
    if let Err(e) = open::that(url) {
        println!("Could not open browser: {e}");
        println!("Visit: {url}");
    }
    Ok(())
}

/// `grith pro start-trial` — seamless free Pro trial.
///
/// Drives the shared [`run_trial_flow`]: if the CLI isn't linked to an account
/// yet, it runs browser device-auth (sign up or sign in on grith.ai and enter a
/// code) to link this machine, then ensures a trial is active and installs the
/// resulting license. Prints CLI-style progress; the onboarding trial screen
/// runs the same flow and renders its own result.
pub fn cmd_pro_start_trial() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match run_trial_flow(&runtime) {
        TrialFlowOutcome::Activated { plan, valid_until } => {
            let suffix = valid_until
                .map(|u| format!(" until {u}"))
                .unwrap_or_default();
            println!("✓ {plan} trial active{suffix}. Welcome to Pro.");
            print_post_refresh_summary();
        }
        TrialFlowOutcome::AlreadyActive => {
            println!("You already have an active plan — nothing to start.");
        }
        TrialFlowOutcome::NeedsBrowser => {
            println!("Trial activation is still pending. Run `grith pro refresh` in a moment.");
            println!("If a browser sign-in page is open, finish that first.");
        }
        TrialFlowOutcome::Failed(msg) => {
            println!("Couldn't start a trial: {msg}");
        }
    }
    Ok(())
}

/// Outcome of the seamless trial flow, shared by `grith pro start-trial` and
/// the onboarding trial screen.
pub(crate) enum TrialFlowOutcome {
    /// A paid/trial plan is now active.
    Activated {
        plan: String,
        valid_until: Option<String>,
    },
    /// The account already has an active plan.
    AlreadyActive,
    /// Linking started in the browser but did not complete in time; the user
    /// should finish there and run `grith pro refresh`.
    NeedsBrowser,
    /// The flow failed for a concrete reason.
    Failed(String),
}

/// Whether a plan string denotes a real (non-free) plan. `community` is the
/// only free tier; `pro`, `enterprise`, and `pro_trial` are all paid/trial.
/// An empty/blank plan is treated as free (not "already active"), so a missing
/// or malformed plan never falsely short-circuits the trial flow.
fn plan_is_paid(plan: &str) -> bool {
    let plan = plan.trim();
    !plan.is_empty() && !plan.eq_ignore_ascii_case("community")
}

/// The seamless trial flow. Ensures the CLI is linked to an account (browser
/// device-auth signup/sign-in if needed — the signup may itself grant a trial),
/// then ensures a trial is active (requesting one if not) and pulls the license.
pub(crate) fn run_trial_flow(rt: &tokio::runtime::Runtime) -> TrialFlowOutcome {
    // Already on a paid/trial plan?
    if let license::LicenseStatus::Valid(lic) = license::load_license(&license::license_path()) {
        if plan_is_paid(&lic.plan) {
            return TrialFlowOutcome::AlreadyActive;
        }
    }

    // Ensure the CLI is linked to an account. Signing up may already grant a
    // trial, in which case the device-auth payload carries the paid license.
    let creds = match license::load_credentials().ok().flatten() {
        Some(c) => c,
        None => match link_account_via_device_auth(rt) {
            LinkResult::Linked { verified } => {
                if plan_is_paid(&verified.plan) {
                    return TrialFlowOutcome::Activated {
                        plan: verified.plan.clone(),
                        valid_until: Some(verified.valid_until.format("%Y-%m-%d").to_string()),
                    };
                }
                match license::load_credentials().ok().flatten() {
                    Some(c) => c,
                    None => {
                        return TrialFlowOutcome::Failed(
                            "account linked but credentials were not saved".into(),
                        )
                    }
                }
            }
            LinkResult::Pending => return TrialFlowOutcome::NeedsBrowser,
            LinkResult::Failed(msg) => return TrialFlowOutcome::Failed(msg),
        },
    };

    // Linked but still on the free tier — request a trial, then refresh to pull
    // whatever the account now holds.
    let requested = rt
        .block_on(async { attempt_remote_start_trial(&creds.api_key).await })
        .unwrap_or(false);
    if let RefreshOutcome::Replaced = rt.block_on(async { run_license_refresh(&creds).await }) {
        // A trial activated on an already-linked account writes a fresh licence;
        // re-gate a running daemon at once so the higher session cap applies now.
        notify_daemon_regate();
    }

    match license::load_license(&license::license_path()) {
        license::LicenseStatus::Valid(lic) if plan_is_paid(&lic.plan) => {
            TrialFlowOutcome::Activated {
                plan: lic.plan.clone(),
                valid_until: Some(lic.valid_until.format("%Y-%m-%d").to_string()),
            }
        }
        // The endpoint accepted the request but the license hasn't synced yet.
        _ if requested => TrialFlowOutcome::NeedsBrowser,
        _ => TrialFlowOutcome::Failed("a trial isn't available for this account".into()),
    }
}

/// Outcome of linking the CLI to an account via browser device-auth.
enum LinkResult {
    Linked {
        verified: license::License,
    },
    /// Timed out / expired / transient — the user should finish in the browser.
    Pending,
    Failed(String),
}

/// Run browser device-authorization to link this CLI to a (possibly newly
/// signed-up) grith.ai account. Prints the code and opens the server-provided
/// verification URL — that URL, not a hardcoded one, is where the user signs up
/// or signs in and which page grith.ai controls.
fn link_account_via_device_auth(rt: &tokio::runtime::Runtime) -> LinkResult {
    let start = match rt.block_on(async { license::start_device_authorization().await }) {
        Ok(s) => s,
        Err(e) => return LinkResult::Failed(format!("could not start sign-in: {e}")),
    };

    println!();
    println!("To start your free trial, sign up (or sign in) here:");
    println!("  {}", start.verification_url);
    println!("Enter this code on the page:  {}", start.user_code);
    println!("Waiting for you to finish in the browser...");
    let _ = crate::browser::open_url(&start.verification_url);

    let expires_at = device_auth_deadline(start.expires_in);
    let poll_interval = std::time::Duration::from_secs(start.interval.max(1));
    loop {
        if std::time::Instant::now() >= expires_at {
            return LinkResult::Pending;
        }
        match rt.block_on(async { license::poll_device_authorization(&start.device_code).await }) {
            Ok((license::DeviceAuthPollStatus::Approved, Some(payload))) => {
                return match persist_login(&payload.api_key, payload.license) {
                    Ok((verified, _)) => LinkResult::Linked { verified },
                    Err(e) => LinkResult::Failed(format!("{e}")),
                };
            }
            Ok((license::DeviceAuthPollStatus::Approved, None)) => {
                return LinkResult::Failed("sign-in completed but no license was returned".into());
            }
            Ok((license::DeviceAuthPollStatus::Pending, _)) => {
                std::thread::sleep(poll_interval);
            }
            Ok((license::DeviceAuthPollStatus::Expired, _)) => return LinkResult::Pending,
            Ok((license::DeviceAuthPollStatus::NoActiveLicense, _)) => {
                return LinkResult::Failed(format!(
                    "signed in, but this team has no active license - upgrade at {}/pricing and run `grith pro login`",
                    crate::license::web_base_url()
                ));
            }
            // Transient network error — tell the user to finish in the browser.
            Err(_) => return LinkResult::Pending,
        }
    }
}

/// Attempt the server-side trial endpoint for an already-linked account.
/// `Ok(true)` = the server accepted; `Ok(false)` = it declined (e.g. already
/// used); `Err` = network/availability failure.
async fn attempt_remote_start_trial(api_key: &str) -> anyhow::Result<bool> {
    let url = start_trial_endpoint(&license::api_base_url());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    let resp = client
        .post(&url)
        .header("x-grith-api-key", api_key)
        .send()
        .await?;
    Ok(resp.status().is_success())
}

/// The trial endpoint URL for a given API base (trailing slash safe).
fn start_trial_endpoint(api_base: &str) -> String {
    format!("{}/api/license/start-trial", api_base.trim_end_matches('/'))
}

/// Outcome of signing in to an existing account (or team) during onboarding.
pub(crate) enum SignInOutcome {
    SignedIn {
        plan: String,
        team: Option<String>,
        /// Number of team-distributed provider keys pulled.
        keys_pulled: usize,
    },
    /// Browser linking didn't complete in time.
    NeedsBrowser,
    Failed(String),
}

/// Sign in to an existing grith.ai account (or join via a team) by linking this
/// CLI through browser device-auth, then best-effort pull team-distributed
/// provider keys. Used by `grith pro login` adjacents and the onboarding
/// "sign in" option. If already linked, this re-syncs without re-authing.
pub(crate) fn run_sign_in_flow(rt: &tokio::runtime::Runtime) -> SignInOutcome {
    let creds = match license::load_credentials().ok().flatten() {
        Some(c) => c,
        None => match link_account_via_device_auth(rt) {
            LinkResult::Linked { .. } => match license::load_credentials().ok().flatten() {
                Some(c) => c,
                None => {
                    return SignInOutcome::Failed(
                        "account linked but credentials were not saved".into(),
                    )
                }
            },
            LinkResult::Pending => return SignInOutcome::NeedsBrowser,
            LinkResult::Failed(msg) => return SignInOutcome::Failed(msg),
        },
    };

    // Best-effort: pull team-distributed provider keys so a team member is set
    // up immediately. Failures here never fail the sign-in.
    let keys_pulled = pull_team_provider_keys(rt, &creds);

    SignInOutcome::SignedIn {
        plan: current_plan_label(),
        team: current_team_label(),
        keys_pulled,
    }
}

/// Best-effort pull of team-distributed (encrypted) provider keys after sign-in.
/// Returns the number written. Never fails — sync issues just mean the user can
/// run `grith pro sync` later.
fn pull_team_provider_keys(rt: &tokio::runtime::Runtime, creds: &license::Credentials) -> usize {
    let keys = match rt.block_on(async { license::fetch_provider_keys(creds).await }) {
        Ok(k) => k,
        Err(e) => {
            tracing::debug!(error = %e, "fetch provider keys failed during sign-in");
            return 0;
        }
    };
    match license::reconcile_provider_key_files(
        &creds.api_key,
        &license::provider_keys_dir(),
        &keys,
    ) {
        Ok(report) => report.written.len(),
        Err(e) => {
            tracing::debug!(error = %e, "provider key reconcile failed during sign-in");
            0
        }
    }
}

/// The current plan label from the saved license, or `community` if none.
fn current_plan_label() -> String {
    match license::load_license(&license::license_path()) {
        license::LicenseStatus::Valid(lic) => lic.plan.clone(),
        _ => "community".to_string(),
    }
}

/// The current team id from the saved license, if it denotes a real team.
fn current_team_label() -> Option<String> {
    if let license::LicenseStatus::Valid(lic) = license::load_license(&license::license_path()) {
        return team_label(&lic.team_id);
    }
    None
}

/// Normalize a license `team_id` into a display label, suppressing empty or
/// personal-account placeholders so onboarding only surfaces a real team.
fn team_label(team_id: &str) -> Option<String> {
    let team = team_id.trim();
    if team.is_empty() || team.eq_ignore_ascii_case("personal") {
        None
    } else {
        Some(team.to_string())
    }
}

pub fn cmd_pro_billing() -> anyhow::Result<()> {
    let creds = license::load_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;
    let Some(_creds) = creds else {
        anyhow::bail!("Not logged in. Run: grith pro login");
    };

    let status = license::load_license(&license::license_path());
    let tier = license::plan_tier_from_status(&status);
    let url = license::billing_portal_url_from_status(&status)
        .unwrap_or_else(|| DEFAULT_BILLING_PORTAL_URL.to_string());

    match &status {
        license::LicenseStatus::Valid(lic)
        | license::LicenseStatus::GracePeriod { license: lic, .. }
        | license::LicenseStatus::ExtendedGrace { license: lic, .. } => {
            println!("Plan:       {} ({})", lic.plan, tier);
            println!("Seats:      {}", lic.seats);
            println!("Renewal:    {}", lic.valid_until.format("%Y-%m-%d"));
            println!("Team:       {}", lic.team_id);
        }
        _ => {
            println!("Plan:       community");
        }
    }

    println!();
    println!("Opening billing portal in your browser...");
    if let Err(e) = open::that(&url) {
        println!("Could not open browser: {e}");
        println!("Visit: {url}");
    }
    Ok(())
}

pub fn cmd_pro_activate() -> anyhow::Result<()> {
    let creds = license::load_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;
    let Some(mut creds) = creds else {
        anyhow::bail!("Not logged in. Run: grith pro login");
    };

    println!("Fetching license from {}...", license::api_base_url());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let signed = runtime
        .block_on(async { license::fetch_license(&creds.api_key).await })
        .map_err(|e| anyhow::anyhow!("failed to fetch license: {e}"))?;

    let license_bytes = serde_json::to_vec(&signed)?;
    let verified = license::verify_license(&license_bytes)
        .map_err(|e| anyhow::anyhow!("license verification failed: {e}"))?;
    let lic_path = license::save_license(&signed)
        .map_err(|e| anyhow::anyhow!("failed to save license: {e}"))?;

    creds.last_validated = chrono::Utc::now().to_rfc3339();
    creds.license_file = lic_path.display().to_string();
    license::save_credentials(&creds)
        .map_err(|e| anyhow::anyhow!("failed to save credentials: {e}"))?;

    // Apply the refreshed license to a running daemon at once.
    notify_daemon_regate();

    let days = license::days_until_expiry(&verified);
    println!("License activated.");
    println!("  Plan:    {}", verified.plan);
    println!(
        "  Expires: {} ({days} days remaining)",
        verified.valid_until.format("%Y-%m-%d")
    );

    Ok(())
}

pub fn cmd_pro_refresh() -> anyhow::Result<()> {
    let creds = license::load_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;
    let Some(creds) = creds else {
        anyhow::bail!("Not logged in. Run: grith pro login");
    };

    println!("Refreshing license against {}...", license::api_base_url());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match runtime.block_on(async { run_license_refresh(&creds).await }) {
        RefreshOutcome::Replaced => {
            println!("License refreshed.");
            print_post_refresh_summary();
            // Apply the refreshed license to a running daemon at once
            // (session limit etc.), matching login / activate. Without this a
            // `grith pro refresh` that changes tier left the daemon on the old
            // gate until its next scheduled refresh or a restart.
            notify_daemon_regate();
            Ok(())
        }
        RefreshOutcome::Hard(kind, reason) => {
            println!("Refresh rejected ({kind}): {reason}.", kind = kind.as_str());
            println!("Cached license is retained until natural expiry.");
            anyhow::bail!("license refresh hard failure");
        }
        RefreshOutcome::Transient(reason) => {
            println!("Refresh failed (transient): {reason}.");
            println!("Cached license is retained; the daemon will retry automatically.");
            anyhow::bail!("license refresh transient failure");
        }
    }
}

fn print_post_refresh_summary() {
    let status = license::load_license(&license::license_path());
    if let license::LicenseStatus::Valid(lic) = &status {
        let days = license::days_until_expiry(lic);
        println!("  Plan:    {}", lic.plan);
        println!(
            "  Expires: {} ({days} days remaining)",
            lic.valid_until.format("%Y-%m-%d")
        );
        if lic.air_gapped {
            println!("  Mode:    air-gapped (scheduled refresh disabled)");
        }
    }
}

pub fn cmd_pro_logout() -> anyhow::Result<()> {
    license::remove_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;
    // Re-gate a running daemon down to community at once, so the pro session
    // cap and gated features stop applying immediately instead of lingering
    // until the daemon's next scheduled refresh or a restart.
    notify_daemon_regate();
    println!("Logged out. Pro features disabled.");
    Ok(())
}

pub fn cmd_pro_sync(_daemon: &daemon::Daemon) -> anyhow::Result<()> {
    let creds = license::load_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;
    let Some(mut creds) = creds else {
        anyhow::bail!("Not logged in. Run: grith pro login");
    };

    let status = license::load_license(&license::license_path());
    let tier = license::plan_tier_from_status(&status);
    if tier == "community" {
        anyhow::bail!("Sync requires an active Pro license. Run: grith pro activate");
    }

    // The raw audit-record upload was retired with the server's /sync route;
    // usage analytics now sync automatically via the daemon's analytics-v2
    // upload worker. This command still pulls team-shared state on demand.
    println!("Usage analytics sync automatically while the daemon runs.");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    match runtime.block_on(async { license::fetch_policies(&creds).await }) {
        Ok(policy) => {
            let dir = license::policies_dir();
            std::fs::create_dir_all(&dir)?;
            if let Some(safe_name) = license::sanitize_sync_name(&policy.name) {
                let policy_path = dir.join(format!("{safe_name}.json"));
                std::fs::write(&policy_path, serde_json::to_string_pretty(&policy.content)?)?;
                println!(
                    "Policy: {} v{} -> {}",
                    policy.name,
                    policy.version,
                    policy_path.display()
                );
            } else {
                tracing::warn!(name = %policy.name, "skipping policy with unsafe name");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to fetch team policies");
        }
    }

    match runtime.block_on(async { license::fetch_configs(&creds).await }) {
        Ok(configs) => {
            if configs.is_empty() {
                println!("No shared configs to pull.");
            } else {
                let dir = license::configs_dir();
                std::fs::create_dir_all(&dir)?;
                for config in &configs {
                    let Some(safe_name) = license::sanitize_sync_name(&config.name) else {
                        tracing::warn!(name = %config.name, "skipping config with unsafe name");
                        continue;
                    };
                    let config_path = dir.join(format!("{safe_name}.json"));
                    std::fs::write(&config_path, serde_json::to_string_pretty(&config.config)?)?;
                    println!("Config: {} -> {}", config.name, config_path.display());
                }
                println!("Pulled {} shared config(s).", configs.len());
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to fetch shared configs");
        }
    }

    match runtime.block_on(async { license::fetch_provider_keys(&creds).await }) {
        Ok(keys) => {
            let report = license::reconcile_provider_key_files(
                &creds.api_key,
                &license::provider_keys_dir(),
                &keys,
            )
            .map_err(|e| anyhow::anyhow!("sync provider keys: {e}"))?;

            if report.written.is_empty() {
                if report.revoked.is_empty() {
                    println!("No provider keys to pull.");
                } else {
                    println!("Removed {} revoked provider key(s).", report.revoked.len());
                }
            } else {
                for entry in &report.written {
                    println!(
                        "Provider key: {} ({}) -> {} [encrypted]",
                        entry.provider,
                        entry.label,
                        entry.path.display()
                    );
                }
                println!("Pulled {} provider key(s).", report.written.len());
                if !report.revoked.is_empty() {
                    println!("Removed {} revoked provider key(s).", report.revoked.len());
                }
            }
            if report.skipped_unsafe > 0 {
                println!(
                    "Skipped {} provider key(s) with unsafe names.",
                    report.skipped_unsafe
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to fetch provider keys");
        }
    }

    // ---- Push reputation data ----
    {
        let rep_path = grith_proxy::reputation::default_reputation_path();
        let table = grith_proxy::reputation::ReputationTable::load(&rep_path);
        let entries: Vec<serde_json::Value> = table
            .entries
            .iter()
            .filter(|(_, entry)| entry.observation_count() >= 3.0)
            .map(|(key, entry)| {
                // Infer level from the path segment of the key.
                // Key format: profile|action|process|destination|path
                let parts: Vec<&str> = key.split('|').collect();
                let level = if parts.len() >= 5 {
                    let path_seg = parts[4];
                    if path_seg == "*" {
                        3 // process-only wildcard
                    } else if path_seg.ends_with("/*") {
                        1 // parent directory class
                    } else {
                        0 // exact path
                    }
                } else {
                    0
                };
                let profile = parts.first().unwrap_or(&"unknown");
                serde_json::json!({
                    "key": key,
                    "level": level,
                    "profile": profile,
                    "alpha": entry.alpha,
                    "beta": entry.beta,
                    "trust_score": entry.trust_score(),
                    "observation_count": entry.observation_count() as i64,
                    "auto_allowed": entry.trust_score() >= 0.92 && entry.observation_count() >= 8.0,
                    "last_updated": entry.last_updated,
                })
            })
            .collect();

        if entries.is_empty() {
            println!("No reputation data to push.");
        } else {
            // Batch uploads to stay under the 500-entry API limit.
            const REPUTATION_SYNC_BATCH_LIMIT: usize = 400;
            let total = entries.len();
            let mut synced = 0usize;
            for chunk in entries.chunks(REPUTATION_SYNC_BATCH_LIMIT) {
                match runtime
                    .block_on(async { license::sync_reputation(&creds, chunk.to_vec()).await })
                {
                    Ok(n) => synced += n,
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to push reputation batch");
                        break;
                    }
                }
                if synced < total {
                    print!("\r  {synced}/{total} reputation entries synced...");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
            }
            if total > REPUTATION_SYNC_BATCH_LIMIT {
                println!();
            }
            println!("Pushed {synced} reputation entries.");
        }
    }

    // ---- Sync learned rules ----
    match runtime.block_on(async { license::fetch_learned_rules(&creds).await }) {
        Ok(rules) => {
            // Always write the cache — even if empty — so revoked rules are cleared.
            let cache_path = persist_team_learned_rules_cache(&rules)?;
            println!(
                "Learned rules: {} rule(s) -> {}",
                rules.len(),
                cache_path.display()
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to fetch team learned rules");
        }
    }

    creds.last_synced = Some(chrono::Utc::now().to_rfc3339());
    license::save_credentials(&creds)
        .map_err(|e| anyhow::anyhow!("failed to update credentials: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::license::{provider_file_name, sanitize_sync_name};

    #[test]
    fn team_label_suppresses_placeholders() {
        assert_eq!(
            super::team_label("acme-corp"),
            Some("acme-corp".to_string())
        );
        assert_eq!(super::team_label("  acme  "), Some("acme".to_string()));
        assert_eq!(super::team_label(""), None);
        assert_eq!(super::team_label("   "), None);
        assert_eq!(super::team_label("personal"), None);
        assert_eq!(super::team_label("Personal"), None);
    }

    #[test]
    fn plan_is_paid_only_community_is_free() {
        assert!(!super::plan_is_paid("community"));
        assert!(!super::plan_is_paid("  Community  "));
        assert!(!super::plan_is_paid("")); // blank → free, not "already active"
        assert!(!super::plan_is_paid("   "));
        assert!(super::plan_is_paid("pro"));
        assert!(super::plan_is_paid("pro_trial"));
        assert!(super::plan_is_paid("enterprise"));
    }

    #[test]
    fn start_trial_endpoint_is_well_formed() {
        assert_eq!(
            super::start_trial_endpoint("https://grith.ai"),
            "https://grith.ai/api/license/start-trial"
        );
        // Trailing slash on the base must not double up.
        assert_eq!(
            super::start_trial_endpoint("https://grith.ai/"),
            "https://grith.ai/api/license/start-trial"
        );
    }

    #[test]
    fn sanitize_sync_name_rejects_empty() {
        assert_eq!(sanitize_sync_name("   "), None);
    }

    #[test]
    fn sanitize_sync_name_replaces_path_separators() {
        assert_eq!(
            sanitize_sync_name("../../etc/passwd"),
            Some("etc-passwd".to_string())
        );
    }

    #[test]
    fn provider_file_name_uses_legacy_name_for_first_key() {
        assert_eq!(
            provider_file_name("openai", "production", 1),
            Some("openai.json".to_string())
        );
    }

    #[test]
    fn provider_file_name_generates_unique_suffixes() {
        assert_eq!(
            provider_file_name("openai", "production key", 2),
            Some("openai--production-key-2.json".to_string())
        );
    }
}
