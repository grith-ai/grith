// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Pre-built supervisor profiles for known AI coding tools.
//!
//! Each profile defines the expected "routine" behaviour of a specific tool:
//! which paths it normally reads/writes, which commands it spawns, and which
//! network destinations it contacts. These are used to auto-generate proxy
//! allowlist entries so that common operations pass through at low scores,
//! while unusual behaviour gets flagged.
//!
//! Profiles can be loaded from TOML files or auto-detected from the command
//! being supervised.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Bundled profile config embedded at compile time.
/// Used as fallback when no filesystem profiles.toml is found.
const BUNDLED_PROFILES_TOML: &str = include_str!("../../../config/supervisor/profiles.toml");
const DEV_PROFILE_OVERRIDE_ENV: &str = "GRITH_DEV_PROFILE_OVERRIDE";

/// A supervisor profile describing the expected behaviour of a specific tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorProfile {
    /// Machine-readable profile identifier (e.g., "claude-code").
    pub name: String,
    /// Human-readable display name (e.g., "Claude Code").
    pub display_name: String,
    /// Optional explanation of what this profile is for.
    #[serde(default)]
    pub rationale: Option<String>,
    /// Optional parent profile name for layered inheritance.
    ///
    /// When set, the parent profile's entries are merged after the child's
    /// own entries (child takes priority). The parent is resolved recursively,
    /// and `[defaults]` are applied last.
    ///
    /// Stripped from the final resolved profile used at runtime.
    #[serde(default, skip_serializing)]
    pub extends: Option<String>,
    /// Glob patterns for paths the tool routinely accesses.
    /// These generate low-score allowlist entries in the proxy.
    pub routine_paths: Vec<String>,
    /// Commands the tool routinely spawns (e.g., "git", "npm", "node").
    pub routine_commands: Vec<String>,
    /// Network destinations the tool routinely contacts
    /// (e.g., "api.anthropic.com", "registry.npmjs.org").
    pub routine_destinations: Vec<String>,
    /// Listener bind addresses the tool may use without prompting.
    #[serde(default)]
    pub routine_listen_addresses: Vec<String>,
    /// Trusted executable root directories for process-spawn allowlisting.
    ///
    /// Binaries under these roots are auto-allowed for process spawns if they
    /// pass provenance verification (ownership, permissions). This is separate
    /// from `routine_paths` which applies to file I/O — exec roots only affect
    /// `ProcessSpawn` matching via `exec-prefix:` session allowlist entries.
    ///
    /// Example: `["/usr/lib/git-core/", "${HOME}/.local/share/claude/versions/"]`
    #[serde(default)]
    pub routine_exec_roots: Vec<String>,
    /// Directory prefixes whose write/append/delete churn is exempt from the
    /// proxy's rate-limit *burst* counter (and only that — every other filter
    /// still runs). Tools like Claude Code / Codex extract and rewrite large
    /// numbers of files under their XDG cache on startup (`~/.cache/.tmpXXXX/`,
    /// node code-cache, package staging), tripping the burst threshold and
    /// queueing routine work. Declaring those roots here suppresses the false
    /// positive without trusting the paths for anything else.
    ///
    /// Same expansion as `routine_exec_roots`: `~/`, `${HOME}`, `${PROJECT_DIR}`
    /// and globs. Example: `["~/.cache", "${HOME}/.npm/_cacache"]`.
    #[serde(default)]
    pub scratch_roots: Vec<String>,
    /// Paths trusted for read-only access only.
    ///
    /// Unlike `routine_paths` which allow all file I/O (reads and writes),
    /// `readonly_paths` only allow `FileRead` operations. Writes, appends,
    /// deletes, renames, and chmod operations on these paths still go through
    /// the full proxy pipeline.
    ///
    /// Uses **exact match only** (no prefix/glob matching) to prevent
    /// accidental trust widening in sensitive directories.
    ///
    /// Session allowlist entries use the `ro:` namespace (e.g., `ro:/home/user/.ssh/config`).
    ///
    /// Example: `["${HOME}/.ssh/config", "${HOME}/.ssh/known_hosts"]`
    #[serde(default)]
    pub readonly_paths: Vec<String>,
    /// Glob patterns for read-only path matching.
    ///
    /// Unlike `readonly_paths` (exact match only), these support simple glob
    /// patterns with `*` as a single-segment wildcard. Used for SSH public keys
    /// and certificates where the filenames vary per user.
    ///
    /// Session allowlist entries use the `ro-glob:` namespace.
    ///
    /// Example: `["${HOME}/.ssh/*.pub", "${HOME}/.ssh/*-cert"]`
    #[serde(default)]
    pub readonly_path_patterns: Vec<String>,
    /// Launch contract: args that must be present when running under grith.
    ///
    /// If specified, `grith exec` will auto-inject these args if they are
    /// not already present in the user's command line.
    #[serde(default)]
    pub launch_contract: Option<LaunchContract>,
    /// PR 5 Phase B: declared local-only listener policy.
    ///
    /// Lists ports the tool routinely binds for local IPC. A loopback
    /// bind on a declared `(port, family)` allows silently; a wildcard
    /// bind (`0.0.0.0` / `::`) on a declared port can be opportunistically
    /// clamped to loopback at the syscall-argument level when
    /// `allow_clamp = true` AND the binary lives under a routine root
    /// (gated by Phase D). Wildcard binds without a declaration
    /// queue/deny via the standard egress-policy path.
    ///
    /// `routine_listen_addresses` (the legacy field) is reserved for
    /// loopback-only string entries. Schema validation rejects
    /// `0.0.0.0` / `::` from that field — wildcard binds need an
    /// explicit `local_listener_policy` entry, never an unconditional
    /// allowlist.
    #[serde(default)]
    pub local_listener_policy: Vec<LocalListenerEntry>,
    /// PR 6 Phase C: binaries permitted to invoke namespace primitives
    /// (`unshare(2)` / `setns(2)`) silently when spawned from a
    /// profile-declared `routine_exec_root`.
    ///
    /// Tools like `bwrap` / `bubblewrap` / `firejail` / `nsenter`
    /// legitimately need `unshare(CLONE_NEWUSER | CLONE_NEWNS | …)`
    /// to set up their sandboxes. Without this carveout the routine
    /// `bwrap` invocation Codex makes at startup would QUEUE every
    /// time. Each entry is a canonical absolute path (e.g.
    /// `/usr/bin/bwrap`); the supervisor resolves the calling binary's
    /// canonical path via PR 4's `SpawnProvenance` and matches against
    /// this list.
    ///
    /// Entries NOT in a `routine_exec_root` are queued/denied even
    /// when their canonical path matches — the carveout requires
    /// **both** conditions (matched_routine_root AND name in
    /// namespace_users) for fail-safe behaviour. See PR 6 work doc
    /// "Category 3" for the threat model.
    #[serde(default)]
    pub namespace_users: Vec<String>,

    /// Authority-delegating binaries this profile may spawn without the
    /// enforcement QUEUE (only consulted when
    /// `supervisor.enforce_authority_delegating_spawn` is on). Each entry is a
    /// binary basename, e.g. `"systemd-run"`. Empty (the default) permits
    /// none — every authority-delegating spawn is queued for review. Like
    /// `namespace_users`, this is a security capability and is **not**
    /// inherited from parent/`[defaults]`; declare it on the leaf profile.
    #[serde(default)]
    pub permit_authority_delegating: Vec<String>,

    /// Control-injection IPC sockets this profile may connect to without the
    /// enforcement QUEUE (only consulted when
    /// `supervisor.enforce_control_socket_connect` is on). Each entry is a
    /// case-insensitive substring of the socket path, e.g.
    /// `"/run/user/1000/bus"` or a broader `"/tmux-"`. Empty (the default)
    /// permits none. Not inherited — declare it on the leaf profile.
    #[serde(default)]
    pub permit_control_sockets: Vec<String>,
}

/// PR 5 Phase B: a declared local-IPC listener entry on a profile.
/// One row per `(port, family)` the supervised tool binds during
/// normal operation. See [`SupervisorProfile::local_listener_policy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalListenerEntry {
    /// Port the tool binds, matched exactly. `0` matches binds that pass
    /// literal port 0 — the kernel-assigned-ephemeral idiom used by
    /// dynamically-allocated MCP / IPC sockets. It is NOT an any-port
    /// wildcard: a fixed-port bind needs its own entry.
    pub port: u16,
    /// Address family the entry covers.
    #[serde(default)]
    pub family: ListenerFamily,
    /// Human-readable description (audit log + dashboard surfacing).
    /// Empty string is allowed but discouraged.
    #[serde(default)]
    pub desc: String,
    /// PR 5 Phase D: opt-in clamp/rewrite. When `true` AND the binding
    /// binary lives in a routine_exec_root, a wildcard bind on this
    /// `(port, family)` is rewritten to the loopback address at the
    /// syscall-argument level (before the kernel processes the bind).
    /// Audit-logged with original + rewritten addresses. Default
    /// `false` — operators must explicitly opt in.
    #[serde(default)]
    pub allow_clamp: bool,
}

/// PR 5 Phase B: address family scope for a [`LocalListenerEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ListenerFamily {
    /// IPv4 only (`127.0.0.1`).
    V4,
    /// IPv6 only (`::1`).
    V6,
    /// Either v4 or v6 — matches whichever the tool binds.
    #[default]
    Any,
}

/// Launch requirements enforced by `grith exec` before spawning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct LaunchContract {
    /// Args that must be present or will be auto-injected at the start of the
    /// arg list.
    ///
    /// Split into groups: each element beginning with `-` starts a new group,
    /// and a following non-flag element is its value. Each group is checked
    /// and injected independently, so a contract may mix boolean flags with
    /// flag/value pairs without re-injecting one the caller already passed.
    ///
    /// Example: `["--sandbox", "disabled"]` for Cursor CLI.
    #[serde(default)]
    pub required_args: Vec<String>,
}

/// A launcher overlay adds small, context-specific trust when a tool is
/// launched from a known IDE terminal (e.g., VS Code, Cursor).
///
/// Overlays are additive only and restricted to low-risk entries.
#[derive(Debug, Clone, Deserialize)]
pub struct LauncherOverlay {
    /// Overlay identifier (e.g., "vscode-terminal").
    pub name: String,
    /// Parent process basenames that trigger this overlay.
    #[serde(default)]
    pub detect_parent_names: Vec<String>,
    /// Environment variable checks (format: `KEY=value`).
    #[serde(default)]
    pub detect_env: Vec<String>,
    /// Additional commands to trust (e.g., "code").
    #[serde(default)]
    pub routine_commands: Vec<String>,
    /// Additional paths to trust.
    #[serde(default)]
    pub routine_paths: Vec<String>,
}

/// A provider overlay adds LLM provider network destinations.
///
/// Used by the grith REPL when the active provider is known.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderOverlay {
    /// Overlay identifier (e.g., "openai", "anthropic").
    pub name: String,
    /// Network destinations to trust for this provider.
    #[serde(default)]
    pub routine_destinations: Vec<String>,
}

/// Complete parsed profile configuration including overlays.
#[derive(Debug)]
pub struct ProfileConfig {
    pub profiles: Vec<SupervisorProfile>,
    pub launcher_overlays: Vec<LauncherOverlay>,
    pub provider_overlays: Vec<ProviderOverlay>,
}

/// Fully resolved session policy: base profile + optional overlays.
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    /// Name of the base static profile.
    pub base_profile_name: String,
    /// Applied launcher overlay, if any.
    pub launcher_overlay_name: Option<String>,
    /// Applied provider overlay, if any.
    pub provider_overlay_name: Option<String>,
    /// Fully merged profile (base + overlays).
    pub merged_profile: SupervisorProfile,
    /// Stable key for learned-rule scoping (e.g., "codex+launcher:vscode-terminal").
    pub scope_key: String,
}

impl SupervisorProfile {
    /// Load profiles from a TOML file.
    ///
    /// The TOML file should contain an array of profiles under the
    /// `[[profiles]]` key:
    ///
    /// ```toml
    /// [[profiles]]
    /// name = "claude-code"
    /// display_name = "Claude Code"
    /// rationale = "Claude Code routine profile"
    /// routine_paths = ["**/*.rs", "**/*.ts"]
    /// routine_commands = ["git", "npm", "node"]
    /// routine_destinations = ["api.anthropic.com"]
    /// routine_listen_addresses = ["127.0.0.1"]
    /// ```
    pub fn load_from_toml(path: impl AsRef<Path>) -> Result<Vec<SupervisorProfile>> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            Error::ProfileError(format!(
                "failed to read profile file '{}': {e}",
                path.as_ref().display()
            ))
        })?;
        Self::parse_toml(&content)
    }

    /// Parse profiles from a TOML string with layered resolution.
    ///
    /// Resolution order for each profile:
    /// 1. Child profile entries (highest priority)
    /// 2. Parent profile entries (if `extends` is set, resolved recursively)
    /// 3. `[defaults]` entries (lowest priority)
    ///
    /// Duplicates are skipped at each layer. Inheritance cycles, self-references,
    /// unknown parent profiles, and duplicate names are hard errors.
    fn parse_toml(content: &str) -> Result<Vec<SupervisorProfile>> {
        Self::parse_toml_full(content).map(|cfg| cfg.profiles)
    }

    /// Parse the complete profile config including overlays.
    fn parse_toml_full(content: &str) -> Result<ProfileConfig> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct ProfileDefaults {
            routine_paths: Vec<String>,
            routine_commands: Vec<String>,
            routine_destinations: Vec<String>,
            routine_listen_addresses: Vec<String>,
            routine_exec_roots: Vec<String>,
            scratch_roots: Vec<String>,
            readonly_paths: Vec<String>,
            readonly_path_patterns: Vec<String>,
        }

        #[derive(Deserialize)]
        struct ProfileFile {
            #[serde(default)]
            defaults: ProfileDefaults,
            profiles: Vec<SupervisorProfile>,
            #[serde(default)]
            launcher_overlays: Vec<LauncherOverlay>,
            #[serde(default)]
            provider_overlays: Vec<ProviderOverlay>,
        }

        let file: ProfileFile = toml::from_str(content)
            .map_err(|e| Error::ProfileError(format!("failed to parse profiles TOML: {e}")))?;

        // Reject duplicate profile names explicitly.
        let mut raw_map = std::collections::HashMap::new();
        for p in &file.profiles {
            if raw_map.insert(p.name.clone(), p).is_some() {
                return Err(Error::ProfileError(format!(
                    "duplicate profile name: '{}'",
                    p.name
                )));
            }
        }

        // PR 5 Phase B (B4): reject wildcard addresses in
        // `routine_listen_addresses`. Wildcard binds must go through
        // `local_listener_policy`, not the silent-allow shortcut.
        {
            let defaults_offending =
                validate_routine_listen_addresses(&file.defaults.routine_listen_addresses);
            if !defaults_offending.is_empty() {
                return Err(Error::ProfileError(format!(
                    "wildcard address(es) in [defaults].routine_listen_addresses: {}. \
                     Wildcard binds require an explicit local_listener_policy entry.",
                    defaults_offending.join(", ")
                )));
            }
            for p in &file.profiles {
                let offending = validate_routine_listen_addresses(&p.routine_listen_addresses);
                if !offending.is_empty() {
                    return Err(Error::ProfileError(format!(
                        "wildcard address(es) in profile '{}'.routine_listen_addresses: {}. \
                         Wildcard binds require an explicit local_listener_policy entry.",
                        p.name,
                        offending.join(", ")
                    )));
                }
            }
        }

        // Reject duplicate launcher overlay names.
        {
            let mut seen = std::collections::HashSet::new();
            for o in &file.launcher_overlays {
                if !seen.insert(&o.name) {
                    return Err(Error::ProfileError(format!(
                        "duplicate launcher overlay name: '{}'",
                        o.name
                    )));
                }
            }
        }

        // Reject duplicate provider overlay names.
        {
            let mut seen = std::collections::HashSet::new();
            for o in &file.provider_overlays {
                if !seen.insert(&o.name) {
                    return Err(Error::ProfileError(format!(
                        "duplicate provider overlay name: '{}'",
                        o.name
                    )));
                }
            }
        }

        // Cache for resolved profiles (without defaults yet).
        let mut resolved_cache: std::collections::HashMap<String, SupervisorProfile> =
            std::collections::HashMap::new();

        // Resolve a profile by name, merging parent chain.
        fn resolve<'a>(
            name: &str,
            raw_map: &std::collections::HashMap<String, &SupervisorProfile>,
            cache: &'a mut std::collections::HashMap<String, SupervisorProfile>,
            stack: &mut Vec<String>,
        ) -> Result<&'a SupervisorProfile> {
            if cache.contains_key(name) {
                return Ok(&cache[name]);
            }

            let profile = raw_map
                .get(name)
                .ok_or_else(|| Error::ProfileError(format!("unknown profile: '{name}'")))?;

            // Check for cycles.
            if stack.contains(&name.to_string()) {
                stack.push(name.to_string());
                return Err(Error::ProfileError(format!(
                    "inheritance cycle detected: {}",
                    stack.join(" -> ")
                )));
            }

            let mut merged = (*profile).clone();

            if let Some(ref parent_name) = profile.extends {
                // Self-reference check.
                if parent_name == name {
                    return Err(Error::ProfileError(format!(
                        "profile '{name}' cannot extend itself"
                    )));
                }

                stack.push(name.to_string());
                resolve(parent_name, raw_map, cache, stack)?;
                stack.pop();

                let parent = &cache[parent_name];
                merge_vec(&mut merged.routine_paths, &parent.routine_paths);
                merge_vec(&mut merged.routine_commands, &parent.routine_commands);
                merge_vec(
                    &mut merged.routine_destinations,
                    &parent.routine_destinations,
                );
                merge_vec(
                    &mut merged.routine_listen_addresses,
                    &parent.routine_listen_addresses,
                );
                merge_vec(&mut merged.routine_exec_roots, &parent.routine_exec_roots);
                merge_vec(&mut merged.scratch_roots, &parent.scratch_roots);
                merge_vec(&mut merged.readonly_paths, &parent.readonly_paths);
                merge_vec(
                    &mut merged.readonly_path_patterns,
                    &parent.readonly_path_patterns,
                );
                // PR 5 Phase B: inherit declared local listener entries
                // from the parent profile. Entries dedupe by full
                // PartialEq comparison.
                merge_local_listener_policy(
                    &mut merged.local_listener_policy,
                    &parent.local_listener_policy,
                );
            }

            merged.extends = None;
            cache.insert(name.to_string(), merged);
            Ok(&cache[name])
        }

        let names: Vec<String> = file.profiles.iter().map(|p| p.name.clone()).collect();
        for name in &names {
            let mut stack = Vec::new();
            resolve(name, &raw_map, &mut resolved_cache, &mut stack)?;
        }

        // Apply defaults as the final layer.
        let d = &file.defaults;
        let has_defaults = !d.routine_paths.is_empty()
            || !d.routine_commands.is_empty()
            || !d.routine_destinations.is_empty()
            || !d.routine_listen_addresses.is_empty()
            || !d.routine_exec_roots.is_empty()
            || !d.scratch_roots.is_empty()
            || !d.readonly_paths.is_empty()
            || !d.readonly_path_patterns.is_empty();

        let mut profiles: Vec<SupervisorProfile> = Vec::with_capacity(names.len());
        for name in names {
            let mut p = resolved_cache.remove(&name).ok_or_else(|| {
                Error::ProfileError(format!("internal error: resolved profile '{name}' missing"))
            })?;
            if has_defaults {
                merge_vec(&mut p.routine_paths, &d.routine_paths);
                merge_vec(&mut p.routine_commands, &d.routine_commands);
                merge_vec(&mut p.routine_destinations, &d.routine_destinations);
                merge_vec(&mut p.routine_listen_addresses, &d.routine_listen_addresses);
                merge_vec(&mut p.routine_exec_roots, &d.routine_exec_roots);
                merge_vec(&mut p.scratch_roots, &d.scratch_roots);
                merge_vec(&mut p.readonly_paths, &d.readonly_paths);
                merge_vec(&mut p.readonly_path_patterns, &d.readonly_path_patterns);
            }
            profiles.push(p);
        }

        Ok(ProfileConfig {
            profiles,
            launcher_overlays: file.launcher_overlays,
            provider_overlays: file.provider_overlays,
        })
    }

    /// Load profiles from the effective configuration source.
    ///
    /// By default this returns the embedded bundled profiles. A repo-local
    /// filesystem override is only consulted when
    /// `GRITH_DEV_PROFILE_OVERRIDE=1` (or another truthy value) is set.
    pub fn load_from_config() -> Result<Vec<SupervisorProfile>> {
        Self::load_config().map(|cfg| cfg.profiles)
    }

    /// Load the full profile configuration including overlays.
    ///
    /// The embedded bundled copy is authoritative by default. A repo-local
    /// filesystem override is only enabled for explicit developer workflows
    /// via `GRITH_DEV_PROFILE_OVERRIDE`.
    pub fn load_config() -> Result<ProfileConfig> {
        if !developer_override_enabled() {
            return Self::load_bundled_config();
        }

        let relative_path = "config/supervisor/profiles.toml";
        let candidates = [
            std::path::PathBuf::from(relative_path),
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../")
                .join(relative_path),
        ];

        for path in &candidates {
            if !path.exists() {
                continue;
            }
            let content = std::fs::read_to_string(path).map_err(|e| {
                Error::ProfileError(format!(
                    "failed to read profile file '{}': {e}",
                    path.display()
                ))
            })?;
            // If a filesystem file exists but fails to parse, that is a hard
            // error — do NOT silently fall back to embedded content.
            return Self::parse_toml_full(&content);
        }

        // No filesystem override found — use embedded bundled profiles.
        Self::load_bundled_config()
    }

    /// Parse the embedded bundled profile config without filesystem lookup.
    ///
    /// Used by callers that need a known-good baseline (e.g. to validate
    /// that remote overlay profile names exist in the bundled set).
    pub fn load_bundled_config() -> Result<ProfileConfig> {
        Self::parse_toml_full(BUNDLED_PROFILES_TOML)
    }

    /// Auto-detect the appropriate profile name from a command string.
    ///
    /// Inspects the command basename to identify known tools:
    /// - "claude" or "claude-code" -> "claude-code"
    /// - "codex" -> "codex"
    /// - "aider" -> "aider"
    /// - "openclaw" -> "openclaw"
    ///
    /// Returns `None` if the command does not match any known profile.
    pub fn detect_profile(command: &str) -> Option<String> {
        // Extract the basename from the command path
        let basename = Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(command);

        match basename {
            "claude" | "claude-code" => Some("claude-code".into()),
            "codex" => Some("codex".into()),
            "aider" => Some("aider".into()),
            "openclaw" => Some("openclaw".into()),
            "goose" => Some("goose".into()),
            "copilot" | "copilot-cli" => Some("copilot".into()),
            "cursor-agent" => Some("cursor".into()),
            "cline" => Some("cline".into()),
            _ => None,
        }
    }

    /// Whether this profile grants project-derived path trust at all, i.e.
    /// whether any `routine_paths` entry mentions `${PROJECT_DIR}`.
    ///
    /// work/83 F4 gates workspace-wide trust on this: extending trust to a
    /// sibling worktree is *mirroring* the trust the launch tree already has.
    /// A profile that deliberately does not trust its own project directory
    /// must not acquire trust in a sibling one through the back door.
    pub fn declares_project_dir_trust(&self) -> bool {
        self.routine_paths
            .iter()
            .any(|pattern| pattern.contains("${PROJECT_DIR}"))
    }

    /// Build the session allowlist `HashSet` from this profile's configuration.
    ///
    /// The returned set contains entries in the namespaced format expected by
    /// the supervisor event handler:
    /// - bare paths for file I/O prefix matching (globs stripped)
    /// - `exec:<resolved_path>` for routine commands
    /// - `exec-prefix:<root/>` for trusted executable root directories
    /// - `net:<domain>` for routine destinations and listen addresses
    pub fn build_session_allowlist(&self) -> std::collections::HashSet<String> {
        // Canonicalise the two stable roots — and ONLY these — so a profile
        // prefix written against a symlinked `${HOME}` (common) or a
        // container-mounted `${PROJECT_DIR}` still matches the resolved paths
        // B3 produces. The full routine path is deliberately NOT canonicalised:
        // its leaf (e.g. `~/.cache/claude`) is tool-writable, and resolving a
        // tool-planted symlink there would widen the allowlist to the
        // symlink's target — a symlink to `/` would allowlist the whole
        // filesystem for the session. Resolving only the roots keeps the FP
        // fix without that escape; a symlinked leaf simply sends its accesses
        // to the proxy (fail-safe) rather than silently trusting them.
        let (home, project_dir) = resolved_home_and_project_dir();
        self.build_session_allowlist_with_roots(&home, &project_dir)
    }

    /// The env-independent core of [`build_session_allowlist`], split out so
    /// tests can drive `home`/`project_dir` without touching process state.
    pub(crate) fn build_session_allowlist_with_roots(
        &self,
        home: &str,
        project_dir: &str,
    ) -> std::collections::HashSet<String> {
        use std::collections::HashSet;

        let mut allowed = HashSet::<String>::new();

        // work/80: `${PROJECT_DIR}` is the LAUNCH CWD, not a curated path.
        // Expanded at `/`, `$HOME`, or an ancestor of `$HOME`, it would
        // session-trust the entire tree — every credential directory
        // included — so those roots get no project-derived trust at all.
        // Surviving project-derived path prefixes are additionally recorded
        // as inert `projdir:` markers, letting the allow gates refuse to
        // let launch-derived trust cover credential stores or in-project
        // secrets (`syscall_map::is_project_trust_guarded_path`).
        let dangerous_project_root = is_dangerous_project_root(home, project_dir);
        if dangerous_project_root
            && (self
                .routine_paths
                .iter()
                .chain(self.routine_exec_roots.iter())
                .chain(self.readonly_paths.iter())
                .chain(self.readonly_path_patterns.iter())
                .any(|p| p.contains("${PROJECT_DIR}")))
        {
            tracing::warn!(
                project_dir,
                "launch directory is / or the home directory: project-directory trust is \
                 disabled for this session — run the tool from a project subdirectory to \
                 restore routine-path trust"
            );
        }
        let project_entry_usable =
            |pattern: &str| !(dangerous_project_root && pattern.contains("${PROJECT_DIR}"));

        for pattern in &self.routine_paths {
            if !project_entry_usable(pattern) {
                continue;
            }
            let expanded = pattern
                .replace("${HOME}", home)
                .replace("${PROJECT_DIR}", project_dir)
                .trim_end_matches("/**")
                .trim_end_matches("/*")
                .trim_end_matches('*')
                .to_string();
            if !expanded.is_empty() {
                // The prefix is already rooted at the canonicalised
                // `${HOME}`/`${PROJECT_DIR}`, so it matches B3-resolved paths
                // without following any tool-writable leaf symlink. See the
                // `canon_root` note above for why the full path is NOT
                // canonicalised here.
                if pattern.contains("${PROJECT_DIR}") {
                    allowed.insert(format!("projdir:{expanded}"));
                }
                allowed.insert(expanded);
            }
        }

        for cmd in &self.routine_commands {
            if let Some(path) = find_in_path(cmd) {
                // Also insert the canonical path so symlinks are matched.
                if let Ok(canonical) = std::fs::canonicalize(&path) {
                    if let Some(s) = canonical.to_str() {
                        if s != path {
                            allowed.insert(format!("exec:{s}"));
                        }
                    }
                }
                allowed.insert(format!("exec:{path}"));
            } else {
                allowed.insert(format!("exec:{cmd}"));
            }
        }

        // Loopback-only listen addresses seed the `listen:` namespace
        // (portless form = any port on that address). They used to seed
        // `net:{addr}`, which NetListen keys no longer consult — and which
        // also (wrongly) auto-allowed CONNECTS to the same address string.
        for addr in &self.routine_listen_addresses {
            allowed.insert(format!("listen:{addr}"));
        }

        for dest in &self.routine_destinations {
            allowed.insert(format!("net:{dest}"));
        }

        // Read-only trusted paths — auto-allow FileRead only, not writes.
        // Uses `ro:` namespace with exact match (no prefix matching).
        for path in &self.readonly_paths {
            if !project_entry_usable(path) {
                continue;
            }
            let expanded = path
                .replace("${HOME}", home)
                .replace("${PROJECT_DIR}", project_dir);
            if let Some(canonical) = canonicalize_readonly_path(&expanded) {
                allowed.insert(format!("ro:{canonical}"));
            }
        }

        // Read-only glob patterns — auto-allow FileRead for files matching
        // these patterns. Uses `ro-glob:` namespace with simple glob matching.
        for pattern in &self.readonly_path_patterns {
            if !project_entry_usable(pattern) {
                continue;
            }
            let expanded = pattern
                .replace("${HOME}", home)
                .replace("${PROJECT_DIR}", project_dir);
            if !expanded.is_empty() {
                allowed.insert(format!("ro-glob:{expanded}"));
            }
        }

        // Trusted executable root directories — auto-allow process spawns
        // for binaries under these roots (e.g., git helpers, bundled tools).
        // Uses `exec-prefix:` namespace to keep exec trust separate from
        // filesystem path trust.
        //
        // Entries containing glob meta-characters (`*`, `?`, `[`) are walked
        // via `glob` and each matching directory produces its own
        // `exec-prefix:` entry — see `expand_routine_exec_roots` for the
        // resolution model. Literal entries fall back to the legacy
        // substitute-and-trailing-slash path so existing profiles keep
        // working even if a directory is not yet present on disk.
        for root in &self.routine_exec_roots {
            // work/80: an exec root derived from a dangerous launch cwd
            // would grant spawn trust to every binary under `/` or `$HOME`.
            if !project_entry_usable(root) {
                continue;
            }
            let substituted = substitute_path_vars(root, home, project_dir);
            if substituted.is_empty() {
                continue;
            }
            let has_meta = substituted.chars().any(|c| matches!(c, '*' | '?' | '['));
            if has_meta {
                for resolved in expand_glob_or_literal(&substituted) {
                    let normalised = match std::fs::canonicalize(&resolved) {
                        Ok(p) => p.to_string_lossy().into_owned(),
                        Err(_) => continue,
                    };
                    let with_slash = if normalised.ends_with('/') {
                        normalised
                    } else {
                        format!("{normalised}/")
                    };
                    allowed.insert(format!("exec-prefix:{with_slash}"));
                }
            } else {
                let normalised = if substituted.ends_with('/') {
                    substituted
                } else {
                    format!("{substituted}/")
                };
                allowed.insert(format!("exec-prefix:{normalised}"));
            }
        }

        allowed
    }

    /// Convert this profile's routine entries into proxy allowlist entries.
    ///
    /// Returns a list of human-readable allowlist rule strings that can be
    /// fed into the proxy's allowlist filter configuration. Format:
    /// - `path:<glob>` for routine paths
    /// - `cmd:<command>` for routine commands
    /// - `dest:<host>` for routine network destinations
    pub fn to_allowlist_entries(&self) -> Vec<String> {
        let mut entries = Vec::new();
        for path in &self.routine_paths {
            entries.push(format!("path:{path}"));
        }
        for cmd in &self.routine_commands {
            entries.push(format!("cmd:{cmd}"));
        }
        for dest in &self.routine_destinations {
            entries.push(format!("dest:{dest}"));
        }
        for addr in &self.routine_listen_addresses {
            entries.push(format!("listen:{addr}"));
        }
        for root in &self.routine_exec_roots {
            entries.push(format!("exec-root:{root}"));
        }
        for path in &self.readonly_paths {
            entries.push(format!("ro:{path}"));
        }
        entries
    }

    /// PR 4 Phase B: expand `routine_exec_roots` into concrete absolute
    /// path prefixes for provenance/inventory use.
    ///
    /// Each profile entry goes through three stages:
    ///   1. Variable substitution — `${HOME}` and `${PROJECT_DIR}`, and a
    ///      leading `~/` shorthand resolved against `$HOME`.
    ///   2. Glob expansion — entries containing `*`, `?`, or `[` are walked
    ///      via `glob::glob()` so patterns like
    ///      `~/.nvm/versions/node/*/lib/node_modules/@openai/codex` resolve
    ///      to one entry per installed Node version.
    ///   3. Canonicalisation + slash-normalisation — each surviving path is
    ///      canonicalised (drops symlinks, normalises `..`) and given a
    ///      trailing `/` so prefix matches behave correctly. Entries that
    ///      fail to canonicalise are dropped silently (the directory just
    ///      isn't installed on this machine).
    ///
    /// The returned set is de-duplicated. Empty patterns are skipped.
    ///
    /// **Glob semantics:** uses the `glob` crate's default options
    /// (case-sensitive on Linux, doesn't match hidden files unless the
    /// pattern starts with `.`). Bracket expressions `[...]` are
    /// supported; `**` is supported for recursive matching but should
    /// be used sparingly given that this output is later walked by the
    /// session-pinned inventory (Phase C, bounded depth).
    pub fn expand_routine_exec_roots(&self) -> Vec<String> {
        use std::collections::BTreeSet;

        // work/80: same CANONICALISED roots as build_session_allowlist —
        // with a symlinked $HOME (`/home/u` -> `/mnt/data/u`), raw env
        // strings would make `project_dir == home` miss and the
        // dangerous-root drop silently never fire (review catch).
        let (home, project_dir) = resolved_home_and_project_dir();

        // A `${PROJECT_DIR}` exec root expanded at `/`, `$HOME`, or an
        // ancestor of `$HOME` would extend routine-spawn provenance trust
        // to every binary under that tree.
        let dangerous_project_root = is_dangerous_project_root(&home, &project_dir);

        let mut out = BTreeSet::<String>::new();
        for root in &self.routine_exec_roots {
            if dangerous_project_root && root.contains("${PROJECT_DIR}") {
                continue;
            }
            let substituted = substitute_path_vars(root, &home, &project_dir);
            if substituted.is_empty() {
                continue;
            }
            for resolved in expand_glob_or_literal(&substituted) {
                let normalised = match std::fs::canonicalize(&resolved) {
                    Ok(p) => p.to_string_lossy().into_owned(),
                    Err(_) => continue,
                };
                let with_slash = if normalised.ends_with('/') {
                    normalised
                } else {
                    format!("{normalised}/")
                };
                out.insert(with_slash);
            }
        }
        out.into_iter().collect()
    }

    /// Expand `scratch_roots` into concrete absolute path prefixes for the
    /// rate-limit burst exemption (Fix #2). Same variable/glob substitution as
    /// [`expand_routine_exec_roots`], but a non-canonicalisable entry is kept
    /// as its substituted literal rather than dropped: scratch directories are
    /// frequently created and destroyed, so a declared root that doesn't exist
    /// at session start should still match writes that create it. Each entry
    /// is trailing-slashed for prefix matching; the result is de-duplicated.
    pub fn expand_scratch_roots(&self) -> Vec<String> {
        use std::collections::BTreeSet;

        let home = std::env::var("HOME").unwrap_or_default();
        let project_dir = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_default();

        let mut out = BTreeSet::<String>::new();
        for root in &self.scratch_roots {
            let substituted = substitute_path_vars(root, &home, &project_dir);
            if substituted.is_empty() {
                continue;
            }
            for resolved in expand_glob_or_literal(&substituted) {
                let normalised = std::fs::canonicalize(&resolved)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or(resolved);
                let with_slash = if normalised.ends_with('/') {
                    normalised
                } else {
                    format!("{normalised}/")
                };
                out.insert(with_slash);
            }
        }
        out.into_iter().collect()
    }
}

/// The canonicalised `$HOME` and launch-cwd roots shared by
/// `build_session_allowlist` and `expand_routine_exec_roots` (work/80: both
/// must agree, or the dangerous-root drop can silently miss under a
/// symlinked `$HOME`). Only the ROOTS are canonicalised — see the
/// build_session_allowlist comment for why full paths never are.
pub(crate) fn resolved_home_and_project_dir() -> (String, String) {
    let canon_root = |raw: String| -> String {
        std::fs::canonicalize(&raw)
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or(raw)
    };
    let home = canon_root(std::env::var("HOME").unwrap_or_default());
    let project_dir = canon_root(
        std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_default(),
    );
    (home, project_dir)
}

// ---------------------------------------------------------------------------
// work/83 F4 — workspace-wide project trust
// ---------------------------------------------------------------------------

/// Hard cap on the number of workspace roots one session will trust.
///
/// Trust is bounded on purpose: a repository with hundreds of linked
/// worktrees (or an operator config that lists a directory per project)
/// would otherwise turn "project trust" into "trust most of `$HOME`" one
/// entry at a time — the same overreach work/80 closed for a single root.
/// 32 covers every real multi-worktree layout; beyond it we keep the first
/// 32 and warn rather than silently widening.
pub const MAX_WORKSPACE_ROOTS: usize = 32;

/// Wall-clock budget for each git probe at session start.
///
/// The probes run on the supervisor's thread before the event loop starts, so
/// a wedged `git` (network-mounted repo, filesystem stall, a hook that reads
/// stdin) must not hold the supervised tool at its first stop indefinitely.
/// Timing out yields no extra roots, which is the fail-safe direction.
const GIT_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// work/80's dangerous-root predicate, shared by every place that expands
/// `${PROJECT_DIR}` (and by work/83's workspace roots).
///
/// `/`, `$HOME`, and any ancestor of `$HOME` are refused: a session-trust
/// prefix at one of those covers every credential directory on the box, which
/// is the overreach work/80 closed. An empty `home` disables the `$HOME` half
/// (nothing to compare against) but still refuses `/`.
pub(crate) fn is_dangerous_project_root(home: &str, project_dir: &str) -> bool {
    project_dir == "/"
        || (!home.is_empty()
            && (project_dir == home || home.starts_with(&format!("{project_dir}/"))))
}

/// Parse `git worktree list --porcelain` into working-tree root paths.
///
/// The porcelain format is a blank-line-separated record per worktree whose
/// first line is `worktree <absolute path>`. Paths are emitted verbatim, so
/// embedded spaces round-trip correctly (git documents newlines in paths as
/// unrepresentable in this format — such an entry simply fails to
/// canonicalise later and is dropped).
///
/// Bare entries are skipped: a bare repository has no working tree, so there
/// is nothing there for the supervised tool to legitimately edit, and
/// trusting the object store would hand it write access to git history.
///
/// **Prunable entries are skipped too.** `prunable` means git could not
/// follow the entry's `gitdir` file to a real working tree — the shape a
/// hand-written `.git/worktrees/<name>/gitdir` produces. That file lives
/// inside the launch tree, so a supervised tool can create it with an
/// unprompted write; keeping the record would let it name any absolute path
/// as a "worktree" and have this function hand it back as a trust candidate.
/// Skipping prunable records is only the first of the four constraints
/// [`resolve_workspace_roots`] applies to git-derived candidates — on its own
/// it is defeated by also creating `<victim>/.git`, which makes the entry
/// non-prunable.
pub(crate) fn parse_worktree_porcelain(output: &str) -> Vec<String> {
    let mut roots = Vec::new();
    let mut current: Option<String> = None;
    let mut skip = false;
    let flush = |current: &mut Option<String>, skip: &mut bool, roots: &mut Vec<String>| {
        if let Some(path) = current.take() {
            if !*skip {
                roots.push(path);
            }
        }
        *skip = false;
    };
    for line in output.lines() {
        if line.is_empty() {
            flush(&mut current, &mut skip, &mut roots);
        } else if let Some(path) = line.strip_prefix("worktree ") {
            // A `worktree` line always opens a record; flush any record that
            // was not terminated by a blank line (last record, truncated
            // output).
            flush(&mut current, &mut skip, &mut roots);
            if !path.is_empty() {
                current = Some(path.to_string());
            }
        } else if line == "bare"
            // git emits `prunable` bare, or `prunable <reason>` with an
            // explanation ("gitdir file points to non-existent location").
            || line == "prunable"
            || line.starts_with("prunable ")
        {
            skip = true;
        }
    }
    flush(&mut current, &mut skip, &mut roots);
    roots
}

/// Path components that disqualify a workspace root outright.
///
/// A git-derived candidate is attacker-influenced (see
/// [`resolve_workspace_roots`]) and an operator-declared one is a
/// hand-written path that could be a typo; neither is ever legitimately a
/// personal-data or credential directory. `is_credential_store_path` covers
/// the classic credential stores, but the trust prefix this produces
/// auto-allows everything beneath it, so the refusal list is deliberately
/// wider than that: browser profiles, the password store, the keyring
/// directory, and the XDG dot-trees that hold autostart entries and
/// user-installed binaries are all locations where a silent prefix grant is
/// a persistence primitive rather than a project-tree convenience.
///
/// Matched component-wise on the CANONICAL path, so `~/link-to-mozilla`
/// cannot dodge it and `.mozilla-notes` is not caught by accident. Ordinary
/// worktree conventions (`.worktrees/`, `.git/`) are deliberately absent —
/// refusing those would break the layouts F4 exists to serve.
const REFUSED_ROOT_COMPONENTS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".pki",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".gcloud",
    ".config",
    ".local",
    ".var",
    ".mozilla",
    ".thunderbird",
    ".password-store",
    ".gnome",
    ".gnome2",
    ".kde",
    ".putty",
    ".netrc",
];

/// `Some(component)` when `root` is, or lives under, a directory the
/// [`REFUSED_ROOT_COMPONENTS`] list forbids.
pub(crate) fn refused_root_component(root: &str) -> Option<&'static str> {
    let lower = root.replace('\\', "/").to_lowercase();
    let mut hit = lower
        .split('/')
        .filter(|c| !c.is_empty())
        .find_map(|component| {
            REFUSED_ROOT_COMPONENTS
                .iter()
                .find(|refused| **refused == component)
                .copied()
        });
    if hit.is_none() && crate::syscall_map::is_credential_store_path(&format!("{lower}/")) {
        hit = Some("credential store");
    }
    hit
}

/// The directory a git-derived workspace root must live inside.
///
/// `git rev-parse --git-common-dir` names the repository's shared admin
/// directory: `<repo>/.git` for an ordinary repository, `<repo>.git` for a
/// bare one. Its parent is the repository's own home, and THAT parent — the
/// directory the repository sits in — is the widest tree a linked worktree of
/// this repository is ever legitimately found in. Both shapes the false
/// positive was measured on live there: sibling worktrees
/// (`<parent>/worktrees/*`) and nested ones (`<repo>/.worktrees/*`).
///
/// Constraining candidates to this scope is what stops the
/// `.git/worktrees/<name>/gitdir` mint from naming `~/.mozilla`,
/// `~/.password-store` or `~/Documents`: those are not under the scope unless
/// the scope IS `$HOME`, and a `$HOME`-or-above scope is refused by the
/// caller.
///
/// git prints the common dir relative to the cwd when the cwd is inside the
/// main working tree and absolute from a linked worktree, so a relative
/// answer is resolved against `launch_cwd` before canonicalisation.
fn git_common_dir(launch_cwd: &Path) -> Option<std::path::PathBuf> {
    let raw = git_probe(launch_cwd, &["rev-parse", "--git-common-dir"])?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = Path::new(trimmed);
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        launch_cwd.join(candidate)
    };
    std::fs::canonicalize(joined).ok()
}

/// Repository home + enclosing scope derived from a canonical common dir.
fn workspace_scope_for(common_dir: &Path) -> Option<std::path::PathBuf> {
    let home = if common_dir.file_name().is_some_and(|n| n == ".git") {
        common_dir.parent()?
    } else {
        // Bare repository (`<name>.git`): it IS the repository home, and its
        // linked worktrees are parked beside it.
        common_dir
    };
    home.parent().map(Path::to_path_buf)
}

/// True when `candidate` is `scope` itself or a descendant of it. Compared
/// component-wise on canonical paths, so `…/Grith-backup` never borrows
/// `…/Grith`'s scope.
fn path_within(candidate: &Path, scope: &Path) -> bool {
    candidate == scope || candidate.starts_with(scope)
}

/// Verify that `candidate` really is a working tree of the repository whose
/// admin directory is `common_dir`, by reading the back-pointer git keeps in
/// the working tree itself.
///
/// The porcelain listing is derived from `<common_dir>/worktrees/<name>/gitdir`
/// — a file inside the launch tree that a supervised tool writes without a
/// prompt. The back-pointer is the OTHER half of the pair, and it lives in
/// the candidate: a linked worktree has a `.git` FILE reading
/// `gitdir: <common_dir>/worktrees/<name>`, and the main worktree has a `.git`
/// DIRECTORY that IS `<common_dir>`.
///
/// This is not a boundary on its own — a tool can write `<victim>/.git` for a
/// victim that has none — but it is the layer that makes an existing
/// repository unmintable: `std::fs::write` cannot replace that repository's
/// `.git` DIRECTORY with a file, so the sibling checkouts that actually hold
/// `.env` files and deploy keys cannot be named as worktrees of this one.
/// Combined with the scope constraint, what remains reachable is a
/// non-repository directory inside the launch repository's own parent.
///
/// A `.git` that is a symlink is refused: git never creates one, and
/// following it would re-open the escape the canonical-path comparisons
/// close.
fn worktree_backlink_verified(candidate: &Path, common_dir: &Path) -> bool {
    /// A real `.git` link file is one short line; anything larger is not one.
    const MAX_DOT_GIT_FILE_LEN: u64 = 4096;

    let dot_git = candidate.join(".git");
    let Ok(meta) = std::fs::symlink_metadata(&dot_git) else {
        return false;
    };
    if meta.is_dir() {
        // Main worktree: its `.git` directory is the common dir itself.
        return std::fs::canonicalize(&dot_git).is_ok_and(|resolved| resolved == common_dir);
    }
    if !meta.is_file() || meta.len() > MAX_DOT_GIT_FILE_LEN {
        return false;
    }
    let Ok(content) = std::fs::read_to_string(&dot_git) else {
        return false;
    };
    let Some(target) = content
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("gitdir:"))
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        return false;
    };
    let target = Path::new(target);
    let joined = if target.is_absolute() {
        target.to_path_buf()
    } else {
        candidate.join(target)
    };
    let Ok(resolved) = std::fs::canonicalize(joined) else {
        return false;
    };
    // Linked worktree: `<common_dir>/worktrees/<name>`. The equality arm
    // covers a main worktree configured with `--separate-git-dir`, whose
    // `.git` is a file pointing straight at the common dir.
    let admin = common_dir.join("worktrees");
    resolved == common_dir || (resolved.starts_with(&admin) && resolved != admin)
}

/// Canonicalised candidates → the roots this session will actually trust.
///
/// Pure (no filesystem, no git) so the refusal and cap rules are unit
/// testable. Applies, in order: work/80's dangerous-root refusal, removal of
/// the launch cwd (already trusted via `${PROJECT_DIR}`, and re-adding it
/// would only duplicate entries), de-duplication, and the
/// [`MAX_WORKSPACE_ROOTS`] cap.
pub(crate) fn collect_workspace_roots<I>(candidates: I, home: &str, launch_cwd: &str) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut out: Vec<String> = Vec::new();
    for candidate in candidates {
        let root = candidate.trim_end_matches('/').to_string();
        if root.is_empty() {
            continue;
        }
        if is_dangerous_project_root(home, &root) {
            tracing::warn!(
                event = "workspace_root_refused",
                root = %root,
                "refusing to extend project trust to / or the home directory; \
                 declare a project subdirectory instead"
            );
            continue;
        }
        // Applies to EVERY root, however it was derived. A git-derived
        // candidate is attacker-influenced; an operator-declared one can be
        // a typo. Neither is ever legitimately a credential store, a browser
        // profile or an XDG dot-tree, and a trust prefix at one of those is
        // a persistence primitive.
        if let Some(component) = refused_root_component(&root) {
            tracing::warn!(
                event = "workspace_root_refused",
                root = %root,
                component,
                "refusing to extend project trust to a credential/personal-data \
                 directory"
            );
            continue;
        }
        if root == launch_cwd.trim_end_matches('/') {
            continue;
        }
        if out.iter().any(|existing| existing == &root) {
            continue;
        }
        if out.len() >= MAX_WORKSPACE_ROOTS {
            tracing::warn!(
                event = "workspace_roots_truncated",
                cap = MAX_WORKSPACE_ROOTS,
                dropped = %root,
                "workspace trust capped; further roots are ignored"
            );
            break;
        }
        out.push(root);
    }
    out
}

/// Run one `git` probe in `cwd`, capturing stdout, bounded by
/// [`GIT_PROBE_TIMEOUT`].
///
/// Any failure — git missing, not a repository, non-zero exit, timeout — is
/// `None`, i.e. "no extra roots". Never an error: a non-git launch directory
/// is the ordinary case, not a misconfiguration.
///
/// stdout is read only after the child exits, so a probe whose output exceeds
/// the pipe buffer blocks the child and is killed at the deadline. That is
/// acceptable here: `git worktree list` output for the ~32 roots we would
/// keep is orders of magnitude below the buffer, and losing a pathological
/// case costs trust, not safety.
fn git_probe(cwd: &Path, args: &[&str]) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new("git")
        .args(args)
        .current_dir(cwd)
        // stdin closed so a repository hook or credential helper that reads
        // stdin fails instead of hanging the probe.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // The probe runs while the supervised tool owns the terminal, and it
        // reads a repository whose `.git/config` the tool can rewrite without
        // a prompt (it is inside the trusted tree). Neither of these probes
        // authenticates or refreshes the index, but pin the two behaviours
        // that could still reach outside the pipe:
        //  - `GIT_TERMINAL_PROMPT=0`: git opens `/dev/tty` directly for
        //    credential prompts, which `Stdio::null()` on stdin does not
        //    cover; a prompt there would corrupt the tool's PTY.
        //  - `GIT_OPTIONAL_LOCKS=0`: a read-only probe must not contend for
        //    the repository lock with the supervised tool's own git.
        // The piped (non-TTY) stdout already keeps git from spawning a pager.
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .spawn()
        .ok()?;

    let deadline = std::time::Instant::now() + GIT_PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::warn!(
                        event = "workspace_git_probe_timeout",
                        args = ?args,
                        "git probe timed out; no linked-worktree trust this session"
                    );
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => return None,
        }
    }

    let mut stdout = String::new();
    child.stdout.take()?.read_to_string(&mut stdout).ok()?;
    Some(stdout)
}

/// Resolve every project root this session trusts beyond the launch cwd
/// (work/83 F4).
///
/// **Session start only.** The result is snapshotted into the session
/// allowlist and the mass-destruction working set and never recomputed: a
/// supervised tool that could make grith re-read `git worktree list` would
/// widen its own trust with one `git worktree add /home/<user>` — turning a
/// false-positive fix into a privilege escalation. Everything below therefore
/// runs before the event loop, once.
///
/// Sources, both optional:
///  - every worktree of the launch repository (`include_linked_worktrees`) —
///    the MAIN one included, so launching from a subdirectory also trusts the
///    repository root;
///  - operator-declared `additional_project_roots`, for the layout git cannot
///    infer — a worktree of a *different* repository parked alongside this one.
///
/// Every candidate is canonicalised (a symlinked worktree path must compare
/// against the paths the supervisor's B3 resolution produces), then filtered
/// by [`collect_workspace_roots`]. The git-derived half carries four extra
/// constraints because its input is writable by the supervised tool — see
/// [`git_derived_roots`].
pub fn resolve_workspace_roots(
    launch_cwd: &Path,
    home: &str,
    include_linked_worktrees: bool,
    additional_project_roots: &[String],
) -> Vec<String> {
    let launch = launch_cwd.to_string_lossy().into_owned();
    let mut candidates: Vec<String> = Vec::new();

    // Operator-declared roots go in FIRST so the [`MAX_WORKSPACE_ROOTS`] cap
    // can never silently drop an explicit declaration in favour of an
    // enumerated one: `additional_project_roots` exists precisely for the
    // layout git cannot infer, and losing it is the failure the operator
    // would not be able to diagnose.
    for declared in additional_project_roots {
        let substituted = substitute_path_vars(declared, home, &launch);
        if substituted.is_empty() {
            continue;
        }
        candidates.push(substituted);
    }

    // Canonicalise the operator-declared roots before filtering so the
    // dangerous-root refusal cannot be sidestepped by a symlink
    // (`~/link-to-home` resolving to `$HOME`), and so the stored prefixes
    // match the canonical paths the syscall classifier produces. A candidate
    // that does not resolve is dropped: an unresolvable root can never match
    // a real path anyway.
    let mut canonical: Vec<String> = candidates
        .into_iter()
        .filter_map(|candidate| canonicalise_candidate(&candidate))
        .collect();

    if include_linked_worktrees {
        canonical.extend(git_derived_roots(launch_cwd, home));
    }

    collect_workspace_roots(canonical, home, &launch)
}

/// Canonicalise one candidate root, tracing (and dropping) the ones that do
/// not resolve.
fn canonicalise_candidate(candidate: &str) -> Option<String> {
    match std::fs::canonicalize(candidate) {
        Ok(path) => Some(path.to_string_lossy().into_owned()),
        Err(error) => {
            tracing::debug!(
                event = "workspace_root_unresolved",
                root = %candidate,
                error = %error,
                "workspace root does not resolve; not trusted"
            );
            None
        }
    }
}

/// Enumerate the launch repository's worktrees, keeping only the candidates
/// that survive every constraint git-derived input has to earn.
///
/// **`git worktree list` is attacker-influenced input, not testimony.** Its
/// records come from `<common_dir>/worktrees/<name>/gitdir`, files that sit
/// inside the launch tree; project trust already covers that tree, so a
/// supervised tool writes them with no prompt and no proxy evaluation. Left
/// unconstrained, three plain writes let a tool nominate any absolute path on
/// the box — `~/.mozilla`, `~/.password-store`, `~/Documents` — as a
/// project-trusted root, and everything beneath it that is not a credential
/// store would be auto-allowed and would stop escalating under
/// `mass_destruction::is_valuable_out_of_tree`.
///
/// Four constraints, all required, none sufficient alone:
///
/// 1. `prunable` records are dropped by [`parse_worktree_porcelain`] — the
///    shape a bare `gitdir` forgery produces. Defeated on its own by also
///    creating `<victim>/.git`.
/// 2. The candidate must be inside the launch repository's own enclosing
///    directory ([`workspace_scope_for`]), compared component-wise on
///    canonical paths so neither `..` nor a symlink escapes it. This is what
///    puts `$HOME`'s dot-trees out of reach.
/// 3. That scope must not itself be `$HOME`, an ancestor of it, or `/` — a
///    repository checked out directly into the home directory would
///    otherwise have "inside the enclosing directory" mean "anywhere".
///    Such a layout gets no linked-worktree trust at all.
/// 4. The candidate must carry git's own back-pointer to this repository
///    ([`worktree_backlink_verified`]), which makes an existing repository
///    unmintable — its `.git` DIRECTORY cannot be overwritten with a link
///    file.
///
/// Residual, stated plainly: a tool can still mint a root over a
/// NON-repository directory inside the launch repository's parent, or over a
/// directory it creates there. Those roots are project-derived (`projdir:`
/// marked), so work/80's credential-store guard still applies to everything
/// under them. Operators who will not accept that set
/// `supervisor.trust.include_linked_worktrees = false` and declare
/// `additional_project_roots` instead.
fn git_derived_roots(launch_cwd: &Path, home: &str) -> Vec<String> {
    // `--git-common-dir` doubles as the cheap "is this a working tree at
    // all?" probe: it fails outside a repository, so an ordinary non-git
    // launch directory costs one failed exec and no worktree enumeration.
    let Some(common_dir) = git_common_dir(launch_cwd) else {
        return Vec::new();
    };
    let Some(scope) = workspace_scope_for(&common_dir) else {
        return Vec::new();
    };
    let scope_str = scope.to_string_lossy().into_owned();
    if is_dangerous_project_root(home, scope_str.trim_end_matches('/')) || scope_str == "/" {
        tracing::warn!(
            event = "workspace_scope_refused",
            scope = %scope_str,
            "the launch repository sits directly in the home directory; \
             linked-worktree trust is disabled for this session (declare \
             additional_project_roots instead)"
        );
        return Vec::new();
    }

    let Some(listing) = git_probe(launch_cwd, &["worktree", "list", "--porcelain"]) else {
        return Vec::new();
    };

    let mut roots = Vec::new();
    for candidate in parse_worktree_porcelain(&listing) {
        let Ok(resolved) = std::fs::canonicalize(&candidate) else {
            tracing::debug!(
                event = "workspace_root_unresolved",
                root = %candidate,
                "worktree does not resolve; not trusted"
            );
            continue;
        };
        if !path_within(&resolved, &scope) {
            tracing::warn!(
                event = "workspace_root_out_of_scope",
                root = %resolved.display(),
                scope = %scope_str,
                "refusing a reported worktree outside the launch repository's \
                 enclosing directory; git worktree metadata is writable by the \
                 supervised tool"
            );
            continue;
        }
        if !worktree_backlink_verified(&resolved, &common_dir) {
            tracing::warn!(
                event = "workspace_root_unverified",
                root = %resolved.display(),
                "reported worktree does not carry this repository's back-pointer; \
                 not trusted"
            );
            continue;
        }
        roots.push(resolved.to_string_lossy().into_owned());
    }
    roots
}

/// Fold resolved workspace roots into an already-built session allowlist.
///
/// Each root is inserted as a boundary-safe directory prefix (`<root>/`) plus
/// the inert `projdir:` twin work/80 introduced, so every guard that refuses
/// to let launch-derived trust cover a credential store applies to these roots
/// too — `resolve_workspace_roots` supplies the tree, it does not supply an
/// exemption from `is_project_trust_guarded_path`.
///
/// The trailing slash is deliberate and is *stricter* than the legacy
/// `${PROJECT_DIR}/**` expansion (which stores the bare launch path): a
/// sibling directory that merely shares the prefix — `…/worktrees/api` vs
/// `…/worktrees/api-secrets` — must not inherit trust from a string match.
pub fn extend_allowlist_with_workspace_roots(
    allowed: &mut std::collections::HashSet<String>,
    roots: &[String],
) {
    for root in roots {
        let prefix = format!("{}/", root.trim_end_matches('/'));
        allowed.insert(format!("projdir:{prefix}"));
        allowed.insert(prefix);
    }
}

/// PR 4 Phase B: substitute `${HOME}`, `${PROJECT_DIR}`, and a leading
/// `~/` in a profile path entry. Returns the substituted string.
/// Empty inputs round-trip as empty.
fn substitute_path_vars(input: &str, home: &str, project_dir: &str) -> String {
    let with_vars = input
        .replace("${HOME}", home)
        .replace("${PROJECT_DIR}", project_dir);
    if let Some(rest) = with_vars.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else if with_vars == "~" {
        home.to_string()
    } else {
        with_vars
    }
}

/// PR 4 Phase B: expand a (post-substitution) pattern into concrete
/// paths. If the pattern contains a glob meta-character, walks the FS
/// via `glob::glob`. Otherwise returns the literal path as a single
/// entry. Malformed patterns return an empty vec.
///
/// Caps glob expansion at `GLOB_MAX_MATCHES_PER_PATTERN` matches.
/// Beyond that we stop iterating and emit a `tracing::warn`, so an
/// operator who ships `~/.cache/**` doesn't explode the allowlist or
/// Phase C's session-pinned inventory walk.
fn expand_glob_or_literal(pattern: &str) -> Vec<String> {
    const GLOB_MAX_MATCHES_PER_PATTERN: usize = 1024;
    let has_meta = pattern.chars().any(|c| matches!(c, '*' | '?' | '['));
    if !has_meta {
        return vec![pattern.to_string()];
    }
    let mut out = Vec::new();
    if let Ok(entries) = glob::glob(pattern) {
        let mut truncated = false;
        for entry in entries.flatten() {
            if out.len() >= GLOB_MAX_MATCHES_PER_PATTERN {
                truncated = true;
                break;
            }
            match entry.to_str() {
                Some(s) => out.push(s.to_string()),
                None => tracing::debug!(
                    target: "grith_supervisor::profiles",
                    path = ?entry,
                    "dropping non-UTF8 path from routine_exec_roots glob expansion",
                ),
            }
        }
        if truncated {
            tracing::warn!(
                target: "grith_supervisor::profiles",
                pattern,
                cap = GLOB_MAX_MATCHES_PER_PATTERN,
                "routine_exec_roots glob exceeded match cap; truncating",
            );
        }
    }
    out
}

fn developer_override_enabled() -> bool {
    env_flag_enabled(std::env::var_os(DEV_PROFILE_OVERRIDE_ENV).as_deref())
}

fn env_flag_enabled(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| {
        let value = value.to_string_lossy();
        !value.is_empty()
            && value != "0"
            && !value.eq_ignore_ascii_case("false")
            && !value.eq_ignore_ascii_case("no")
    })
}

impl ProfileConfig {
    /// Build the fully resolved effective policy for a session.
    ///
    /// Merges the base profile with optional provider and launcher overlays,
    /// and computes a stable scope key for learned-rule isolation.
    pub fn build_effective_policy(
        &self,
        profile_name: &str,
        launcher_override: Option<&str>,
        provider_override: Option<&str>,
    ) -> Result<EffectivePolicy> {
        let base = self
            .profiles
            .iter()
            .find(|p| p.name == profile_name)
            .ok_or_else(|| {
                Error::ProfileError(format!("no supervisor profile '{profile_name}' found"))
            })?
            .clone();

        // Launcher: explicit override > auto-detection > none.
        let launcher_name = if let Some(name) = launcher_override {
            if !self.launcher_overlays.iter().any(|o| o.name == name) {
                return Err(Error::ProfileError(format!(
                    "unknown launcher overlay: '{name}'"
                )));
            }
            Some(name.to_string())
        } else {
            detect_launcher(&self.launcher_overlays)
        };

        // Provider: explicit only (no auto-detection in v1).
        let provider_name = if let Some(name) = provider_override {
            if !self.provider_overlays.iter().any(|o| o.name == name) {
                return Err(Error::ProfileError(format!(
                    "unknown provider overlay: '{name}'"
                )));
            }
            Some(name.to_string())
        } else {
            None
        };

        let mut merged = base;

        // Apply provider overlay (destinations only).
        if let Some(ref name) = provider_name {
            if let Some(overlay) = self.provider_overlays.iter().find(|o| o.name == *name) {
                merge_vec(
                    &mut merged.routine_destinations,
                    &overlay.routine_destinations,
                );
            }
        }

        // Apply launcher overlay (commands + paths only).
        if let Some(ref name) = launcher_name {
            if let Some(overlay) = self.launcher_overlays.iter().find(|o| o.name == *name) {
                merge_vec(&mut merged.routine_commands, &overlay.routine_commands);
                merge_vec(&mut merged.routine_paths, &overlay.routine_paths);
            }
        }

        // Build scope key: "profile+provider:X+launcher:Y"
        let mut scope_key = profile_name.to_string();
        if let Some(ref name) = provider_name {
            scope_key.push_str(&format!("+provider:{name}"));
        }
        if let Some(ref name) = launcher_name {
            scope_key.push_str(&format!("+launcher:{name}"));
        }

        Ok(EffectivePolicy {
            base_profile_name: profile_name.to_string(),
            launcher_overlay_name: launcher_name,
            provider_overlay_name: provider_name,
            merged_profile: merged,
            scope_key,
        })
    }
}

/// Split a launch contract's required args into independent groups.
///
/// A group starts at each element beginning with `-`; any immediately
/// following non-flag element is that group's value. Leading non-flag
/// elements (a malformed contract) are kept as one group so behaviour stays
/// predictable rather than silently dropping them.
fn split_required_arg_groups(required_args: &[String]) -> Vec<&[String]> {
    let mut groups: Vec<&[String]> = Vec::new();
    let mut start = 0usize;
    for idx in 1..required_args.len() {
        if required_args[idx].starts_with('-') {
            groups.push(&required_args[start..idx]);
            start = idx;
        }
    }
    if start < required_args.len() {
        groups.push(&required_args[start..]);
    }
    groups
}

fn validate_launch_contract_conflicts(args: &[String], required_args: &[String]) -> Result<()> {
    for group in split_required_arg_groups(required_args) {
        validate_launch_contract_group(args, group)?;
    }
    Ok(())
}

fn validate_launch_contract_group(args: &[String], required_args: &[String]) -> Result<()> {
    if required_args.len() != 2 {
        return Ok(());
    }

    let flag = &required_args[0];
    let required_value = &required_args[1];
    if !flag.starts_with('-') || required_value.starts_with('-') {
        return Ok(());
    }

    for (idx, arg) in args.iter().enumerate() {
        if arg == flag {
            match args.get(idx + 1) {
                Some(value) if value == required_value => {}
                Some(value) => {
                    return Err(Error::ProfileError(format!(
                        "launch contract conflict: expected '{flag} {required_value}' but command already contains '{flag} {value}'"
                    )));
                }
                None => {
                    return Err(Error::ProfileError(format!(
                        "launch contract conflict: expected '{flag} {required_value}' but command ends after '{flag}'"
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Enforce a profile's launch contract by injecting required args if missing.
///
/// Returns `true` if args were modified. The `args` slice should be the
/// tool arguments (not including the command name itself).
pub fn enforce_launch_contract(args: &mut Vec<String>, contract: &LaunchContract) -> Result<bool> {
    if contract.required_args.is_empty() {
        return Ok(false);
    }

    let req = &contract.required_args;
    validate_launch_contract_conflicts(args, req)?;

    // Inject each group independently so a contract mixing a boolean flag
    // with a flag/value pair does not re-inject the one already supplied.
    let mut insert_at = 0usize;
    let mut modified = false;
    for group in split_required_arg_groups(req) {
        let found = args.windows(group.len()).any(|window| window == group);
        if found {
            continue;
        }
        for (i, arg) in group.iter().enumerate() {
            args.insert(insert_at + i, arg.clone());
        }
        insert_at += group.len();
        modified = true;
    }
    Ok(modified)
}

/// Auto-detect the launcher environment from parent process and env vars.
///
/// This is best-effort — it is not a security boundary. Unknown launchers
/// fall back to no overlay.
pub fn detect_launcher(overlays: &[LauncherOverlay]) -> Option<String> {
    // 1. Check parent process name.
    if let Some(parent_name) = get_parent_process_name() {
        for overlay in overlays {
            if overlay.detect_parent_names.contains(&parent_name) {
                return Some(overlay.name.clone());
            }
        }
    }

    // 2. Check environment variables as supporting evidence.
    for overlay in overlays {
        for env_spec in &overlay.detect_env {
            if let Some((key, value)) = env_spec.split_once('=') {
                if std::env::var(key).ok().as_deref() == Some(value) {
                    return Some(overlay.name.clone());
                }
            }
        }
    }

    None
}

/// Read the parent process name from /proc on Linux.
#[cfg(target_os = "linux")]
fn get_parent_process_name() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let ppid = status
        .lines()
        .find(|l| l.starts_with("PPid:"))?
        .split_whitespace()
        .nth(1)?
        .parse::<u32>()
        .ok()?;
    std::fs::read_to_string(format!("/proc/{ppid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(not(target_os = "linux"))]
fn get_parent_process_name() -> Option<String> {
    None
}

/// Append default entries to a profile's list, skipping duplicates.
fn merge_vec(profile: &mut Vec<String>, defaults: &[String]) {
    for item in defaults {
        if !profile.contains(item) {
            profile.push(item.clone());
        }
    }
}

/// PR 5 Phase B: union local_listener_policy entries from a parent into a
/// child profile. Dedupes by full PartialEq comparison — two entries are
/// considered duplicate only when port, family, desc, and allow_clamp all
/// match. This means child profiles that override `allow_clamp` for the
/// same `(port, family)` keep their own entry alongside the parent's.
fn merge_local_listener_policy(
    profile: &mut Vec<LocalListenerEntry>,
    defaults: &[LocalListenerEntry],
) {
    for entry in defaults {
        if !profile.contains(entry) {
            profile.push(entry.clone());
        }
    }
}

/// PR 5 Phase B (B4): reject wildcard addresses in `routine_listen_addresses`.
///
/// The legacy field was sometimes mis-used to add `0.0.0.0`/`::` to the
/// silent-allow set, which would expose listeners on every interface
/// without review. PR 5's design splits this responsibility:
/// `routine_listen_addresses` is loopback-only; wildcard binds must go
/// through `local_listener_policy` (which audits and optionally clamps).
///
/// Returns the offending entries when validation fails so the error
/// message can name them. Empty result = OK.
pub(crate) fn validate_routine_listen_addresses(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .filter(|addr| {
            // Localhost is OK; parse anything else and reject wildcard.
            if addr.eq_ignore_ascii_case("localhost") {
                return false;
            }
            match addr.parse::<std::net::IpAddr>() {
                Ok(ip) => {
                    if ip.is_unspecified() {
                        return true;
                    }
                    // IPv4-mapped IPv6 wildcard is also forbidden.
                    if let std::net::IpAddr::V6(v6) = ip {
                        if let Some(v4) = v6.to_ipv4_mapped() {
                            return v4.is_unspecified();
                        }
                    }
                    false
                }
                Err(_) => false, // junk is the caller's problem; we only veto wildcards.
            }
        })
        .cloned()
        .collect()
}

fn canonicalize_readonly_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }

    std::fs::canonicalize(path)
        .ok()
        .and_then(|p| p.to_str().map(String::from))
}

/// Resolve a command name to its absolute path via `$PATH` lookup.
fn find_in_path(cmd: &str) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path_var = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(cmd);
            if let Ok(meta) = std::fs::metadata(&candidate) {
                if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                    return Some(candidate.to_string_lossy().into_owned());
                }
            }
        }
        None
    }
    #[cfg(not(unix))]
    {
        let _ = cmd;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    // ── detect_profile ─────────────────────────────────────────────

    #[test]
    fn detect_claude_code() {
        assert_eq!(
            SupervisorProfile::detect_profile("claude-code"),
            Some("claude-code".into())
        );
    }

    #[test]
    fn detect_claude_bare() {
        assert_eq!(
            SupervisorProfile::detect_profile("claude"),
            Some("claude-code".into())
        );
    }

    #[test]
    fn detect_claude_full_path() {
        assert_eq!(
            SupervisorProfile::detect_profile("/usr/local/bin/claude-code"),
            Some("claude-code".into())
        );
    }

    #[test]
    fn detect_codex() {
        assert_eq!(
            SupervisorProfile::detect_profile("codex"),
            Some("codex".into())
        );
    }

    #[test]
    fn detect_codex_full_path() {
        assert_eq!(
            SupervisorProfile::detect_profile("/home/user/.local/bin/codex"),
            Some("codex".into())
        );
    }

    #[test]
    fn detect_aider() {
        assert_eq!(
            SupervisorProfile::detect_profile("aider"),
            Some("aider".into())
        );
    }

    #[test]
    fn detect_openclaw() {
        assert_eq!(
            SupervisorProfile::detect_profile("openclaw"),
            Some("openclaw".into())
        );
        assert_eq!(
            SupervisorProfile::detect_profile("/usr/local/bin/openclaw"),
            Some("openclaw".into())
        );
    }

    #[test]
    fn detect_goose() {
        assert_eq!(
            SupervisorProfile::detect_profile("goose"),
            Some("goose".into())
        );
    }

    #[test]
    fn detect_goose_full_path() {
        assert_eq!(
            SupervisorProfile::detect_profile("/home/user/.local/bin/goose"),
            Some("goose".into())
        );
    }

    #[test]
    fn detect_copilot() {
        assert_eq!(
            SupervisorProfile::detect_profile("copilot"),
            Some("copilot".into())
        );
    }

    #[test]
    fn detect_copilot_cli() {
        assert_eq!(
            SupervisorProfile::detect_profile("copilot-cli"),
            Some("copilot".into())
        );
    }

    #[test]
    fn detect_copilot_full_path() {
        assert_eq!(
            SupervisorProfile::detect_profile(
                "/home/user/.local/share/mise/installs/copilot/1.0/copilot"
            ),
            Some("copilot".into())
        );
    }

    #[test]
    fn detect_cursor_agent() {
        assert_eq!(
            SupervisorProfile::detect_profile("cursor-agent"),
            Some("cursor".into())
        );
    }

    #[test]
    fn detect_cursor_agent_full_path() {
        assert_eq!(
            SupervisorProfile::detect_profile("/home/user/.local/bin/cursor-agent"),
            Some("cursor".into())
        );
    }

    #[test]
    fn detect_cline() {
        assert_eq!(
            SupervisorProfile::detect_profile("cline"),
            Some("cline".into())
        );
    }

    #[test]
    fn detect_cline_full_path() {
        assert_eq!(
            SupervisorProfile::detect_profile(
                "/home/user/.local/share/mise/installs/cline/2.8/cline"
            ),
            Some("cline".into())
        );
    }

    #[test]
    fn detect_bare_agent_returns_none() {
        // "agent" is too generic — Cursor uses it but other tools may too.
        assert_eq!(SupervisorProfile::detect_profile("agent"), None);
    }

    #[test]
    fn detect_unknown_returns_none() {
        assert_eq!(SupervisorProfile::detect_profile("vim"), None);
        assert_eq!(SupervisorProfile::detect_profile("python3"), None);
        assert_eq!(SupervisorProfile::detect_profile("/usr/bin/bash"), None);
    }

    // ── load_from_config ────────────────────────────────────────────

    #[test]
    fn load_from_config_finds_profiles() {
        let profiles = SupervisorProfile::load_from_config().unwrap();
        assert!(
            profiles.len() >= 10,
            "profiles.toml should have at least 10 profiles, found {}",
            profiles.len()
        );
        let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"generic"));
        assert!(names.contains(&"generic-cli"));
        assert!(names.contains(&"grith-repl"));
        assert!(names.contains(&"claude-code"));
        assert!(names.contains(&"codex"));
        assert!(names.contains(&"aider"));
        assert!(names.contains(&"goose"));
        assert!(names.contains(&"copilot"));
        assert!(names.contains(&"cursor"));
        assert!(names.contains(&"cline"));
        assert!(names.contains(&"openclaw"));
    }

    #[test]
    fn claude_code_profile_has_expected_commands() {
        let profiles = SupervisorProfile::load_from_config().unwrap();
        let claude = profiles.iter().find(|p| p.name == "claude-code").unwrap();
        assert!(claude.routine_commands.contains(&"git".into()));
        assert!(claude.routine_commands.contains(&"cargo".into()));
        assert!(claude.routine_commands.contains(&"node".into()));
    }

    /// work/80: `${PROJECT_DIR}` trust is dropped at dangerous launch
    /// roots and marked with an inert `projdir:` twin elsewhere.
    #[test]
    fn project_dir_trust_dropped_at_dangerous_roots() {
        let profile = SupervisorProfile {
            name: "work80".into(),
            display_name: "work80".into(),
            rationale: None,
            extends: None,
            routine_paths: vec![
                "${PROJECT_DIR}/**".into(),
                "${HOME}/.cache/claude/**".into(),
            ],
            routine_commands: Vec::new(),
            routine_destinations: Vec::new(),
            routine_listen_addresses: Vec::new(),
            routine_exec_roots: vec!["${PROJECT_DIR}/node_modules/.bin".into()],
            scratch_roots: Vec::new(),
            readonly_paths: Vec::new(),
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };
        let home = "/home/user";

        // Launching from `/`, `$HOME`, or an ancestor of `$HOME`: no
        // project-derived entries at all — the explicit HOME literal stays.
        for dangerous in ["/", "/home/user", "/home"] {
            let allowed = profile.build_session_allowlist_with_roots(home, dangerous);
            assert!(
                !allowed.contains(dangerous),
                "launch cwd {dangerous} must not become a trusted prefix"
            );
            assert!(
                !allowed.iter().any(|e| e.starts_with("projdir:")),
                "no projdir markers at dangerous root {dangerous}"
            );
            assert!(
                !allowed
                    .iter()
                    .any(|e| e.starts_with("exec-prefix:") && e.contains("node_modules")),
                "no project exec roots at dangerous root {dangerous}"
            );
            assert!(
                allowed.contains("/home/user/.cache/claude"),
                "curated HOME literal survives at {dangerous}"
            );
        }

        // A genuine project subdirectory keeps trust, plus the marker twin.
        let allowed = profile.build_session_allowlist_with_roots(home, "/home/user/proj");
        assert!(allowed.contains("/home/user/proj"));
        assert!(
            allowed.contains("projdir:/home/user/proj"),
            "project-derived prefix must carry its projdir marker"
        );
        assert!(
            !allowed.contains("projdir:/home/user/.cache/claude"),
            "curated HOME literal must NOT be marked project-derived"
        );

        // Review defect 3: the dangerous-root test is on the CANONICAL
        // roots, so a launch cwd equal to the canonicalised home (even if
        // the raw env strings differed via a symlink) still drops project
        // exec roots. Driving _with_roots with project_dir == home models
        // the post-canonicalisation state both call paths now share.
        let allowed = profile.build_session_allowlist_with_roots("/mnt/data/u", "/mnt/data/u");
        assert!(
            !allowed
                .iter()
                .any(|e| e.starts_with("exec-prefix:") && e.contains("node_modules")),
            "project exec roots must drop when canonical project_dir == canonical home"
        );
    }

    // ---- work/83 F4: workspace-wide project trust -------------------------

    /// The porcelain format is a blank-line-separated record per worktree.
    /// Multiple worktrees, a bare main entry (no working tree — nothing there
    /// for a tool to legitimately edit, and its object store is git history),
    /// and paths containing spaces must all be handled.
    #[test]
    fn worktree_porcelain_parses_records_bare_and_spaced_paths() {
        let listing = "worktree /home/u/proj\n\
                       HEAD 0123456789abcdef0123456789abcdef01234567\n\
                       branch refs/heads/main\n\
                       \n\
                       worktree /home/u/worktrees/feature one\n\
                       HEAD 89abcdef0123456789abcdef0123456789abcdef\n\
                       detached\n\
                       \n\
                       worktree /home/u/mirror.git\n\
                       bare\n\
                       \n\
                       worktree /home/u/worktrees/fix\n\
                       HEAD fedcba9876543210fedcba9876543210fedcba98\n\
                       branch refs/heads/fix\n";
        assert_eq!(
            parse_worktree_porcelain(listing),
            vec![
                "/home/u/proj".to_string(),
                "/home/u/worktrees/feature one".to_string(),
                "/home/u/worktrees/fix".to_string(),
            ],
            "bare entries are skipped; spaced paths survive verbatim"
        );

        // A listing whose final record is not terminated by a blank line
        // (truncated output) still yields that record.
        assert_eq!(
            parse_worktree_porcelain("worktree /a\nHEAD 00\n"),
            vec!["/a".to_string()]
        );
        assert!(parse_worktree_porcelain("").is_empty());
    }

    /// A `prunable` record is what a hand-written
    /// `.git/worktrees/<name>/gitdir` produces, and that file lives inside
    /// the tree project trust already covers — so the supervised tool writes
    /// it with no prompt. Keeping the record would hand back any absolute
    /// path on the box as a trust candidate. Both spellings git uses
    /// (bare `prunable`, and `prunable <reason>`) are dropped.
    #[test]
    fn worktree_porcelain_skips_prunable_records() {
        let listing = "worktree /home/u/proj\n\
                       HEAD 0123456789abcdef0123456789abcdef01234567\n\
                       branch refs/heads/main\n\
                       \n\
                       worktree /home/u/Documents\n\
                       HEAD 0123456789abcdef0123456789abcdef01234567\n\
                       branch refs/heads/main\n\
                       prunable gitdir file points to non-existent location\n\
                       \n\
                       worktree /home/u/.mozilla\n\
                       prunable\n\
                       \n\
                       worktree /home/u/worktrees/fix\n\
                       branch refs/heads/fix\n";
        assert_eq!(
            parse_worktree_porcelain(listing),
            vec![
                "/home/u/proj".to_string(),
                "/home/u/worktrees/fix".to_string(),
            ],
            "prunable records are forged-metadata shaped and must be dropped"
        );
    }

    /// The component refusal is matched on canonical path components, so a
    /// directory whose NAME merely starts with a refused one is unaffected
    /// and the ordinary worktree conventions keep working.
    #[test]
    fn refused_root_components_cover_stores_without_catching_worktrees() {
        for refused in [
            "/home/u/.mozilla/firefox/abc.default",
            "/home/u/.password-store",
            "/home/u/.local/share/keyrings",
            "/home/u/.config/autostart",
            "/home/u/.ssh",
            "/home/u/proj/.aws",
            "/home/u/.gnupg/private-keys-v1.d",
            "/home/u/.config/grith",
        ] {
            assert!(
                refused_root_component(refused).is_some(),
                "{refused} must be refused as a workspace root"
            );
        }
        for allowed in [
            "/home/u/projects/grith/.worktrees/feature",
            "/home/u/projects/grith",
            "/home/u/projects/.mozilla-notes",
            "/home/u/projects/localstack",
            "/home/u/worktrees/fix",
        ] {
            assert_eq!(
                refused_root_component(allowed),
                None,
                "{allowed} is an ordinary project tree and must stay declarable"
            );
        }
    }

    /// The scope a git-derived root has to live inside is the directory the
    /// repository itself sits in — the same answer for an ordinary
    /// repository and for a bare one with worktrees parked beside it.
    #[test]
    fn workspace_scope_is_the_repositorys_enclosing_directory() {
        assert_eq!(
            workspace_scope_for(std::path::Path::new("/home/u/projects/proj/.git")),
            Some(std::path::PathBuf::from("/home/u/projects"))
        );
        assert_eq!(
            workspace_scope_for(std::path::Path::new("/home/u/projects/proj.git")),
            Some(std::path::PathBuf::from("/home/u/projects"))
        );
    }

    /// work/80's dangerous-root refusal applies to every workspace root, and
    /// the total is capped: trust must not grow one worktree at a time into
    /// "most of `$HOME`".
    #[test]
    fn workspace_roots_refuse_dangerous_roots_and_hold_the_cap() {
        let home = "/home/u";
        let launch = "/home/u/proj";

        let refused = collect_workspace_roots(
            [
                "/".to_string(),
                "/home/u".to_string(),
                "/home".to_string(),
                "/home/u/proj".to_string(),  // the launch cwd itself
                "/home/u/proj/".to_string(), // ... with a trailing slash
                "/home/u/wt/a".to_string(),
                "/home/u/wt/a".to_string(), // duplicate
            ],
            home,
            launch,
        );
        assert_eq!(
            refused,
            vec!["/home/u/wt/a".to_string()],
            "/, $HOME, ancestors of $HOME, the launch cwd and duplicates all drop"
        );

        // Cap: the 33rd root is dropped, not trusted.
        let many: Vec<String> = (0..40).map(|i| format!("/home/u/wt/{i}")).collect();
        let capped = collect_workspace_roots(many, home, launch);
        assert_eq!(capped.len(), MAX_WORKSPACE_ROOTS);
        assert_eq!(capped[0], "/home/u/wt/0");
        assert_eq!(capped[MAX_WORKSPACE_ROOTS - 1], "/home/u/wt/31");
    }

    /// Workspace roots enter the allowlist as boundary-safe prefixes carrying
    /// the inert `projdir:` twin, so work/80's credential-store guard covers
    /// them exactly as it covers the launch tree.
    #[test]
    fn workspace_roots_enter_the_allowlist_projdir_marked() {
        let mut allowed = std::collections::HashSet::new();
        extend_allowlist_with_workspace_roots(
            &mut allowed,
            &["/home/u/wt/a".to_string(), "/home/u/wt/b/".to_string()],
        );
        for root in ["/home/u/wt/a/", "/home/u/wt/b/"] {
            assert!(allowed.contains(root), "{root} must be a trusted prefix");
            assert!(
                allowed.contains(&format!("projdir:{root}")),
                "{root} must carry its projdir marker"
            );
        }
        // Boundary safety: the trailing slash is what stops a sibling
        // directory that merely shares the prefix from inheriting trust.
        assert!(!allowed.contains("/home/u/wt/a"));
    }

    /// F4 mirrors trust; it never invents it. A profile with no
    /// `${PROJECT_DIR}` routine path grants no project trust to mirror.
    #[test]
    fn project_dir_trust_declaration_gates_workspace_trust() {
        let mut profile = SupervisorProfile {
            name: "t".into(),
            display_name: "t".into(),
            rationale: None,
            extends: None,
            routine_paths: vec!["${PROJECT_DIR}/**".into()],
            routine_commands: Vec::new(),
            routine_destinations: Vec::new(),
            routine_listen_addresses: Vec::new(),
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            readonly_paths: Vec::new(),
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };
        assert!(profile.declares_project_dir_trust());
        profile.routine_paths = vec!["${HOME}/.cache/tool/**".into()];
        assert!(!profile.declares_project_dir_trust());
    }

    /// `resolve_workspace_roots` is the impure entry point: a non-git launch
    /// directory is not an error, it simply yields nothing, and a declared
    /// root that does not resolve is dropped rather than trusted.
    #[test]
    fn resolve_workspace_roots_tolerates_non_git_and_unresolvable_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let launch = tmp.path().join("launch");
        let sibling = tmp.path().join("sibling");
        std::fs::create_dir_all(&launch).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        let home = tmp.path().to_string_lossy().into_owned();

        let roots = resolve_workspace_roots(
            &launch,
            &home,
            true,
            &[
                sibling.to_string_lossy().into_owned(),
                tmp.path()
                    .join("does-not-exist")
                    .to_string_lossy()
                    .into_owned(),
            ],
        );
        let canonical_sibling = std::fs::canonicalize(&sibling)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(roots, vec![canonical_sibling]);
    }

    #[test]
    fn generic_profile_is_strict_no_destinations() {
        let profiles = SupervisorProfile::load_from_config().unwrap();
        let generic = profiles.iter().find(|p| p.name == "generic").unwrap();
        // generic is the strict fallback — no outbound destinations.
        // Defaults no longer include destinations (moved to generic-cli).
        assert!(
            generic.routine_destinations.is_empty(),
            "generic profile should have no destinations"
        );
    }

    #[test]
    fn generic_cli_inherits_generic_and_defaults() {
        let profiles = SupervisorProfile::load_from_config().unwrap();
        let generic_cli = profiles.iter().find(|p| p.name == "generic-cli").unwrap();
        // generic-cli inherits generic's routine_paths (${PROJECT_DIR}/**)
        assert!(
            generic_cli
                .routine_paths
                .iter()
                .any(|p| p.contains("PROJECT_DIR")),
            "generic-cli should inherit PROJECT_DIR from generic"
        );
        // generic-cli adds GitHub destinations
        assert!(
            generic_cli
                .routine_destinations
                .iter()
                .any(|d| d == "github.com"),
            "generic-cli should have github.com"
        );
        // generic-cli inherits defaults commands (git, ssh, etc.)
        assert!(
            generic_cli.routine_commands.iter().any(|c| c == "git"),
            "generic-cli should inherit git from defaults"
        );
    }

    #[test]
    fn tool_profile_inherits_generic_and_defaults() {
        let profiles = SupervisorProfile::load_from_config().unwrap();
        let goose = profiles.iter().find(|p| p.name == "goose").unwrap();
        // Goose extends generic (not generic-cli).
        // Should have: goose-specific paths + generic PROJECT_DIR + defaults /proc
        assert!(
            goose.routine_paths.iter().any(|p| p.contains("goose")),
            "goose should have goose-specific paths"
        );
        assert!(
            goose
                .routine_paths
                .iter()
                .any(|p| p.contains("PROJECT_DIR")),
            "goose should inherit PROJECT_DIR from generic"
        );
        assert!(
            goose.routine_paths.iter().any(|p| p == "/proc"),
            "goose should inherit /proc from defaults"
        );
        // Should have git from defaults
        assert!(
            goose.routine_commands.iter().any(|c| c == "git"),
            "goose should inherit git from defaults"
        );
    }

    // ── to_allowlist_entries ───────────────────────────────────────

    #[test]
    fn to_allowlist_entries_format() {
        let profile = SupervisorProfile {
            name: "test".into(),
            display_name: "Test".into(),
            rationale: Some("test rationale".into()),
            extends: None,
            routine_paths: vec!["**/*.rs".into()],
            routine_commands: vec!["git".into()],
            routine_destinations: vec!["example.com".into()],
            routine_listen_addresses: vec!["0.0.0.0".into()],
            routine_exec_roots: vec!["/usr/lib/git-core/".into()],
            scratch_roots: Vec::new(),
            readonly_paths: vec!["/home/test/.ssh/config".into()],
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };
        let entries = profile.to_allowlist_entries();
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[0], "path:**/*.rs");
        assert_eq!(entries[1], "cmd:git");
        assert_eq!(entries[2], "dest:example.com");
        assert_eq!(entries[3], "listen:0.0.0.0");
        assert_eq!(entries[4], "exec-root:/usr/lib/git-core/");
        assert_eq!(entries[5], "ro:/home/test/.ssh/config");
    }

    #[test]
    fn to_allowlist_entries_empty_profile() {
        let profile = SupervisorProfile {
            name: "empty".into(),
            display_name: "Empty".into(),
            rationale: None,
            extends: None,
            routine_paths: Vec::new(),
            routine_commands: Vec::new(),
            routine_destinations: Vec::new(),
            routine_listen_addresses: Vec::new(),
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            readonly_paths: Vec::new(),
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };
        assert!(profile.to_allowlist_entries().is_empty());
    }

    #[test]
    fn to_allowlist_entries_counts() {
        let profiles = SupervisorProfile::load_from_config().unwrap();
        let claude = profiles.iter().find(|p| p.name == "claude-code").unwrap();
        let entries = claude.to_allowlist_entries();
        let path_count = entries.iter().filter(|e| e.starts_with("path:")).count();
        let cmd_count = entries.iter().filter(|e| e.starts_with("cmd:")).count();
        let dest_count = entries.iter().filter(|e| e.starts_with("dest:")).count();
        let listen_count = entries.iter().filter(|e| e.starts_with("listen:")).count();
        let exec_root_count = entries
            .iter()
            .filter(|e| e.starts_with("exec-root:"))
            .count();
        assert_eq!(path_count, claude.routine_paths.len());
        assert_eq!(cmd_count, claude.routine_commands.len());
        assert_eq!(dest_count, claude.routine_destinations.len());
        assert_eq!(listen_count, claude.routine_listen_addresses.len());
        assert_eq!(exec_root_count, claude.routine_exec_roots.len());
        let ro_count = entries.iter().filter(|e| e.starts_with("ro:")).count();
        assert_eq!(ro_count, claude.readonly_paths.len());
    }

    // ── TOML parsing ───────────────────────────────────────────────

    #[test]
    fn parse_toml_valid() {
        let toml = r#"
[[profiles]]
name = "test-tool"
display_name = "Test Tool"
rationale = "Used in tests"
routine_paths = ["**/*.py"]
routine_commands = ["python"]
routine_destinations = ["api.example.com"]
routine_listen_addresses = ["127.0.0.1"]

[[profiles]]
name = "other-tool"
display_name = "Other Tool"
rationale = "Also used in tests"
routine_paths = []
routine_commands = ["bash"]
routine_destinations = []
routine_listen_addresses = []
"#;
        let profiles = SupervisorProfile::parse_toml(toml).unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].name, "test-tool");
        assert_eq!(profiles[0].display_name, "Test Tool");
        assert_eq!(profiles[0].routine_paths, vec!["**/*.py"]);
        // PR 5 Phase B: routine_listen_addresses is loopback-only —
        // wildcard binds need an explicit local_listener_policy entry.
        assert_eq!(profiles[0].routine_listen_addresses, vec!["127.0.0.1"]);
        assert_eq!(profiles[1].name, "other-tool");
        assert_eq!(profiles[1].routine_commands, vec!["bash"]);
    }

    #[test]
    fn parse_toml_invalid_returns_error() {
        let bad_toml = "this is not valid toml [[[";
        let result = SupervisorProfile::parse_toml(bad_toml);
        assert!(result.is_err());
    }

    #[test]
    fn load_from_toml_nonexistent_file_returns_error() {
        let result = SupervisorProfile::load_from_toml("/nonexistent/path/profiles.toml");
        assert!(result.is_err());
    }

    // ── Serde roundtrip ────────────────────────────────────────────

    #[test]
    fn serde_json_roundtrip() {
        let profile = SupervisorProfile {
            name: "roundtrip".into(),
            display_name: "Roundtrip Test".into(),
            rationale: Some("roundtrip".into()),
            extends: None,
            routine_paths: vec!["**/*.rs".into()],
            routine_commands: vec!["cargo".into()],
            routine_destinations: vec!["crates.io".into()],
            routine_listen_addresses: vec!["127.0.0.1".into()],
            routine_exec_roots: vec!["/usr/lib/git-core/".into()],
            scratch_roots: Vec::new(),
            readonly_paths: vec!["${HOME}/.ssh/config".into()],
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };
        let json = serde_json::to_string(&profile).unwrap();
        let parsed: SupervisorProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "roundtrip");
        assert_eq!(parsed.routine_paths, vec!["**/*.rs"]);
        assert_eq!(parsed.routine_listen_addresses, vec!["127.0.0.1"]);
        assert_eq!(parsed.routine_exec_roots, vec!["/usr/lib/git-core/"]);
    }

    #[test]
    fn build_session_allowlist_skips_missing_readonly_paths() {
        let profile = SupervisorProfile {
            name: "test".into(),
            display_name: "Test".into(),
            rationale: None,
            extends: None,
            routine_paths: Vec::new(),
            routine_commands: Vec::new(),
            routine_destinations: Vec::new(),
            routine_listen_addresses: Vec::new(),
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            readonly_paths: vec!["/definitely/missing/grith-readonly-path".into()],
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };

        let allowed = profile.build_session_allowlist();
        assert!(
            !allowed.iter().any(|entry| entry.starts_with("ro:")),
            "missing readonly paths must not be trusted by raw string path"
        );
    }

    // ── Layered inheritance error cases ─────────────────────────────

    #[test]
    fn extends_unknown_profile_returns_error() {
        let toml = r#"
[[profiles]]
name = "child"
display_name = "Child"
extends = "nonexistent"
routine_paths = []
routine_commands = []
routine_destinations = []
"#;
        let result = SupervisorProfile::parse_toml(toml);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("nonexistent"),
            "error should mention the unknown profile name: {msg}"
        );
    }

    #[test]
    fn extends_self_returns_error() {
        let toml = r#"
[[profiles]]
name = "self-ref"
display_name = "Self Ref"
extends = "self-ref"
routine_paths = []
routine_commands = []
routine_destinations = []
"#;
        let result = SupervisorProfile::parse_toml(toml);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("cannot extend itself"),
            "error should mention self-reference: {msg}"
        );
    }

    #[test]
    fn extends_cycle_returns_error() {
        let toml = r#"
[[profiles]]
name = "a"
display_name = "A"
extends = "b"
routine_paths = []
routine_commands = []
routine_destinations = []

[[profiles]]
name = "b"
display_name = "B"
extends = "a"
routine_paths = []
routine_commands = []
routine_destinations = []
"#;
        let result = SupervisorProfile::parse_toml(toml);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("cycle"),
            "error should mention inheritance cycle: {msg}"
        );
    }

    #[test]
    fn parse_toml_with_defaults_and_parent_profile() {
        let toml = r#"
[defaults]
routine_commands = ["git", "ssh"]
routine_paths = ["/proc"]

[[profiles]]
name = "base"
display_name = "Base"
routine_paths = ["/base"]
routine_commands = ["cargo"]
routine_destinations = ["base.com"]

[[profiles]]
name = "child"
display_name = "Child"
extends = "base"
routine_paths = ["/child"]
routine_commands = ["node"]
routine_destinations = ["child.com"]
"#;
        let profiles = SupervisorProfile::parse_toml(toml).unwrap();
        let child = profiles.iter().find(|p| p.name == "child").unwrap();

        // Child entries come first, then parent, then defaults.
        assert_eq!(child.routine_paths[0], "/child");
        assert!(child.routine_paths.contains(&"/base".to_string()));
        assert!(child.routine_paths.contains(&"/proc".to_string()));

        assert_eq!(child.routine_commands[0], "node");
        assert!(child.routine_commands.contains(&"cargo".to_string()));
        assert!(child.routine_commands.contains(&"git".to_string()));

        assert!(child
            .routine_destinations
            .contains(&"child.com".to_string()));
        assert!(child.routine_destinations.contains(&"base.com".to_string()));
    }

    #[test]
    fn resolved_profiles_are_fully_merged_in_load_from_config() {
        let profiles = SupervisorProfile::load_from_config().unwrap();
        // Every profile that extends another should have its extends field cleared.
        for p in &profiles {
            assert!(
                p.extends.is_none(),
                "profile '{}' should have extends=None after resolution",
                p.name
            );
        }
        // Copilot extends generic -> defaults.
        // It should have git (from defaults) and github.com (from its own destinations).
        let copilot = profiles.iter().find(|p| p.name == "copilot").unwrap();
        assert!(copilot.routine_commands.contains(&"git".to_string()));
        assert!(
            copilot
                .routine_destinations
                .contains(&"github.com".to_string()),
            "copilot should have github.com in its own destinations"
        );
    }

    #[cfg(unix)]
    #[test]
    fn build_session_allowlist_canonicalizes_readonly_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target.txt");
        let link = tmp.path().join("link.txt");
        std::fs::write(&target, "ok").unwrap();
        symlink(&target, &link).unwrap();

        let profile = SupervisorProfile {
            name: "test".into(),
            display_name: "Test".into(),
            rationale: None,
            extends: None,
            routine_paths: Vec::new(),
            routine_commands: Vec::new(),
            routine_destinations: Vec::new(),
            routine_listen_addresses: Vec::new(),
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            readonly_paths: vec![link.to_string_lossy().into_owned()],
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };

        let allowed = profile.build_session_allowlist();
        let canonical = std::fs::canonicalize(&target).unwrap();
        let canonical = canonical.to_string_lossy().into_owned();

        assert!(allowed.contains(&format!("ro:{canonical}")));
        assert!(!allowed.contains(&format!("ro:{}", link.to_string_lossy())));
    }

    /// CRITICAL regression (go-live review round 2): a `routine_paths` entry
    /// whose leaf is a tool-writable symlink must NOT widen the session
    /// allowlist to the symlink's target. Canonicalising the full routine
    /// path let a symlink planted at e.g. `~/.cache/claude` — pointed at `/`
    /// — allowlist the entire filesystem for the session. Only the stable
    /// `${HOME}`/`${PROJECT_DIR}` roots are resolved now; a symlinked leaf's
    /// accesses go to the proxy (fail-safe), never onto the allowlist.
    #[cfg(unix)]
    #[test]
    fn symlinked_routine_path_leaf_does_not_widen_allowlist() {
        let tmp = tempfile::tempdir().unwrap();
        // A routine path that is itself a symlink pointing at a sensitive
        // location — the shape of the attack.
        let sensitive = tmp.path().join("sensitive-target");
        let routine_link = tmp.path().join("cache-claude");
        std::fs::create_dir(&sensitive).unwrap();
        symlink(&sensitive, &routine_link).unwrap();

        let profile = SupervisorProfile {
            name: "test".into(),
            display_name: "Test".into(),
            rationale: None,
            extends: None,
            routine_paths: vec![
                format!("{}/**", routine_link.to_string_lossy()),
                // A path that does not exist yet must survive untouched.
                "/nonexistent-xyz/cache".into(),
            ],
            routine_commands: Vec::new(),
            routine_destinations: Vec::new(),
            routine_listen_addresses: Vec::new(),
            routine_exec_roots: Vec::new(),
            scratch_roots: Vec::new(),
            readonly_paths: Vec::new(),
            readonly_path_patterns: Vec::new(),
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };

        let allowed = profile.build_session_allowlist();
        let target = std::fs::canonicalize(&sensitive)
            .unwrap()
            .to_string_lossy()
            .into_owned();

        assert!(
            !allowed.contains(&target),
            "the symlink target must NOT be allowlisted — that is the widening bug"
        );
        assert!(
            allowed.contains(&routine_link.to_string_lossy().into_owned()),
            "the literal routine prefix is still kept (its accesses go to the proxy)"
        );
        assert!(
            allowed.contains("/nonexistent-xyz/cache"),
            "a not-yet-created directory must still be allowlisted"
        );
    }

    // ── Duplicate name detection ──────────────────────────────────

    #[test]
    fn duplicate_profile_names_rejected() {
        let toml = r#"
[[profiles]]
name = "dup"
display_name = "Dup 1"
routine_paths = []
routine_commands = []
routine_destinations = []

[[profiles]]
name = "dup"
display_name = "Dup 2"
routine_paths = []
routine_commands = []
routine_destinations = []
"#;
        let result = SupervisorProfile::parse_toml(toml);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("duplicate"), "error: {msg}");
    }

    #[test]
    fn duplicate_launcher_overlay_names_rejected() {
        let toml = r#"
[[profiles]]
name = "base"
display_name = "Base"
routine_paths = []
routine_commands = []
routine_destinations = []

[[launcher_overlays]]
name = "vscode"
detect_parent_names = ["code"]

[[launcher_overlays]]
name = "vscode"
detect_parent_names = ["codium"]
"#;
        let result = SupervisorProfile::parse_toml_full(toml);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("duplicate launcher"), "error: {msg}");
    }

    #[test]
    fn duplicate_provider_overlay_names_rejected() {
        let toml = r#"
[[profiles]]
name = "base"
display_name = "Base"
routine_paths = []
routine_commands = []
routine_destinations = []

[[provider_overlays]]
name = "openai"
routine_destinations = ["openai.com"]

[[provider_overlays]]
name = "openai"
routine_destinations = ["api.openai.com"]
"#;
        let result = SupervisorProfile::parse_toml_full(toml);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("duplicate provider"), "error: {msg}");
    }

    // ── Overlay parsing and effective policy ─────────────────────

    #[test]
    fn parse_overlays_from_toml() {
        let toml = r#"
[[profiles]]
name = "test"
display_name = "Test"
routine_paths = []
routine_commands = ["git"]
routine_destinations = ["example.com"]

[[launcher_overlays]]
name = "vscode-terminal"
detect_parent_names = ["code"]
detect_env = ["TERM_PROGRAM=vscode"]
routine_commands = ["code"]

[[provider_overlays]]
name = "openai"
routine_destinations = ["openai.com", "api.openai.com"]
"#;
        let cfg = SupervisorProfile::parse_toml_full(toml).unwrap();
        assert_eq!(cfg.profiles.len(), 1);
        assert_eq!(cfg.launcher_overlays.len(), 1);
        assert_eq!(cfg.launcher_overlays[0].name, "vscode-terminal");
        assert_eq!(cfg.provider_overlays.len(), 1);
        assert_eq!(cfg.provider_overlays[0].name, "openai");
    }

    #[test]
    fn effective_policy_merges_provider_overlay() {
        let toml = r#"
[[profiles]]
name = "test"
display_name = "Test"
routine_paths = []
routine_commands = ["git"]
routine_destinations = ["example.com"]

[[provider_overlays]]
name = "openai"
routine_destinations = ["openai.com", "api.openai.com"]
"#;
        let cfg = SupervisorProfile::parse_toml_full(toml).unwrap();
        let policy = cfg
            .build_effective_policy("test", None, Some("openai"))
            .unwrap();

        assert_eq!(policy.scope_key, "test+provider:openai");
        assert!(policy
            .merged_profile
            .routine_destinations
            .contains(&"example.com".to_string()));
        assert!(policy
            .merged_profile
            .routine_destinations
            .contains(&"openai.com".to_string()));
    }

    #[test]
    fn effective_policy_merges_launcher_overlay() {
        let toml = r#"
[[profiles]]
name = "test"
display_name = "Test"
routine_paths = []
routine_commands = ["git"]
routine_destinations = []

[[launcher_overlays]]
name = "vscode-terminal"
detect_parent_names = ["code"]
routine_commands = ["code"]
"#;
        let cfg = SupervisorProfile::parse_toml_full(toml).unwrap();
        let policy = cfg
            .build_effective_policy("test", Some("vscode-terminal"), None)
            .unwrap();

        assert_eq!(policy.scope_key, "test+launcher:vscode-terminal");
        assert!(policy
            .merged_profile
            .routine_commands
            .contains(&"code".to_string()));
        assert!(policy
            .merged_profile
            .routine_commands
            .contains(&"git".to_string()));
    }

    #[test]
    fn effective_policy_unknown_launcher_errors() {
        let toml = r#"
[[profiles]]
name = "test"
display_name = "Test"
routine_paths = []
routine_commands = []
routine_destinations = []
"#;
        let cfg = SupervisorProfile::parse_toml_full(toml).unwrap();
        let result = cfg.build_effective_policy("test", Some("nonexistent"), None);
        assert!(result.is_err());
    }

    #[test]
    fn effective_policy_unknown_provider_errors() {
        let toml = r#"
[[profiles]]
name = "test"
display_name = "Test"
routine_paths = []
routine_commands = []
routine_destinations = []
"#;
        let cfg = SupervisorProfile::parse_toml_full(toml).unwrap();
        let result = cfg.build_effective_policy("test", None, Some("nonexistent"));
        assert!(result.is_err());
    }

    #[test]
    fn effective_policy_full_scope_key() {
        let toml = r#"
[[profiles]]
name = "repl"
display_name = "Repl"
routine_paths = []
routine_commands = []
routine_destinations = []

[[launcher_overlays]]
name = "vscode-terminal"
detect_parent_names = ["code"]

[[provider_overlays]]
name = "openai"
routine_destinations = ["openai.com"]
"#;
        let cfg = SupervisorProfile::parse_toml_full(toml).unwrap();
        let policy = cfg
            .build_effective_policy("repl", Some("vscode-terminal"), Some("openai"))
            .unwrap();
        assert_eq!(
            policy.scope_key,
            "repl+provider:openai+launcher:vscode-terminal"
        );
    }

    // ── Launch contract enforcement ─────────────────────────────

    #[test]
    fn enforce_launch_contract_injects_missing_args() {
        let contract = LaunchContract {
            required_args: vec!["--sandbox".into(), "disabled".into()],
        };
        let mut args = vec!["task".into()];
        let modified = enforce_launch_contract(&mut args, &contract).unwrap();
        assert!(modified);
        assert_eq!(args, vec!["--sandbox", "disabled", "task"]);
    }

    #[test]
    fn enforce_launch_contract_noop_when_present() {
        let contract = LaunchContract {
            required_args: vec!["--sandbox".into(), "disabled".into()],
        };
        let mut args = vec!["--sandbox".into(), "disabled".into(), "task".into()];
        let modified = enforce_launch_contract(&mut args, &contract).unwrap();
        assert!(!modified);
        assert_eq!(args, vec!["--sandbox", "disabled", "task"]);
    }

    #[test]
    fn enforce_launch_contract_injects_only_missing_group() {
        // The shipped claude-code contract: a boolean flag plus a flag/value
        // pair. A caller that already passed the boolean must not get it twice.
        let contract = LaunchContract {
            required_args: vec![
                "--dangerously-skip-permissions".into(),
                "--settings".into(),
                "{\"sandbox\":{\"enabled\":false}}".into(),
            ],
        };
        let mut args = vec!["--dangerously-skip-permissions".into()];
        let modified = enforce_launch_contract(&mut args, &contract).unwrap();
        assert!(modified);
        assert_eq!(
            args,
            vec![
                "--settings",
                "{\"sandbox\":{\"enabled\":false}}",
                "--dangerously-skip-permissions"
            ]
        );
        assert_eq!(
            args.iter()
                .filter(|a| *a == "--dangerously-skip-permissions")
                .count(),
            1
        );
    }

    #[test]
    fn enforce_launch_contract_multi_group_all_missing() {
        let contract = LaunchContract {
            required_args: vec![
                "--dangerously-skip-permissions".into(),
                "--settings".into(),
                "{}".into(),
            ],
        };
        let mut args = vec!["task".into()];
        assert!(enforce_launch_contract(&mut args, &contract).unwrap());
        assert_eq!(
            args,
            vec!["--dangerously-skip-permissions", "--settings", "{}", "task"]
        );
    }

    #[test]
    fn enforce_launch_contract_multi_group_all_present_is_noop() {
        let contract = LaunchContract {
            required_args: vec![
                "--dangerously-skip-permissions".into(),
                "--settings".into(),
                "{}".into(),
            ],
        };
        let mut args = vec![
            "--dangerously-skip-permissions".into(),
            "--settings".into(),
            "{}".into(),
        ];
        assert!(!enforce_launch_contract(&mut args, &contract).unwrap());
    }

    #[test]
    fn enforce_launch_contract_detects_conflict_within_group() {
        // Conflict detection must still work when the pair is one group of
        // several, not just when it is the whole contract.
        let contract = LaunchContract {
            required_args: vec![
                "--dangerously-skip-permissions".into(),
                "--settings".into(),
                "{}".into(),
            ],
        };
        let mut args = vec!["--settings".into(), "/my/own.json".into()];
        assert!(enforce_launch_contract(&mut args, &contract).is_err());
    }

    #[test]
    fn enforce_launch_contract_empty_is_noop() {
        let contract = LaunchContract::default();
        let mut args = vec!["task".into()];
        let modified = enforce_launch_contract(&mut args, &contract).unwrap();
        assert!(!modified);
    }

    #[test]
    fn enforce_launch_contract_rejects_conflicting_value() {
        let contract = LaunchContract {
            required_args: vec!["--sandbox".into(), "disabled".into()],
        };
        let mut args = vec!["--sandbox".into(), "enabled".into(), "task".into()];
        let err = enforce_launch_contract(&mut args, &contract).unwrap_err();
        assert!(err.to_string().contains("launch contract conflict"));
    }

    #[test]
    fn load_config_returns_full_profile_config() {
        let cfg = SupervisorProfile::load_config().unwrap();
        assert!(!cfg.profiles.is_empty());
        // Should have overlays if profiles.toml defines them.
    }

    #[test]
    fn named_profiles_extend_generic_not_generic_cli() {
        let profiles = SupervisorProfile::load_from_config().unwrap();
        // After T-01, named tool profiles should extend generic, not generic-cli.
        // They should NOT inherit generic-cli's VS Code destinations unless
        // they explicitly list them.
        let goose = profiles.iter().find(|p| p.name == "goose").unwrap();
        assert!(
            !goose
                .routine_destinations
                .iter()
                .any(|d| d == "visualstudio.com"),
            "goose should not inherit VS Code destinations"
        );
        // But goose should still have git from defaults.
        assert!(goose.routine_commands.iter().any(|c| c == "git"));
    }

    // ── embedded bundled fallback ──────────────────────────────────

    #[test]
    fn bundled_profiles_toml_parses_successfully() {
        let config = SupervisorProfile::parse_toml_full(BUNDLED_PROFILES_TOML)
            .expect("embedded BUNDLED_PROFILES_TOML should parse");
        assert!(
            !config.profiles.is_empty(),
            "bundled config should contain at least one profile"
        );
    }

    /// PR 70: the codex profile auto-injects
    /// `--dangerously-bypass-approvals-and-sandbox` because grith is the
    /// supervising security layer. Without this, codex prompts the user
    /// for every shell command — those prompts bypass grith's audit
    /// trail and confuse "who is asking what."
    #[test]
    fn codex_profile_auto_injects_bypass_flag() {
        let config = SupervisorProfile::parse_toml_full(BUNDLED_PROFILES_TOML).unwrap();
        let codex = config
            .profiles
            .iter()
            .find(|p| p.name == "codex")
            .expect("codex profile must exist in bundled config");
        let contract = codex
            .launch_contract
            .as_ref()
            .expect("codex profile must declare a launch_contract");
        assert!(
            contract
                .required_args
                .iter()
                .any(|a| a == "--dangerously-bypass-approvals-and-sandbox"),
            "codex launch_contract must include --dangerously-bypass-approvals-and-sandbox; \
             without it codex's own approval/sandbox flow runs in parallel with grith and \
             prompts the user, bypassing the audit trail. Required args were: {:?}",
            contract.required_args,
        );
    }

    /// PR 69 Change 3: the codex profile must declare the MCP transport
    /// listener policy with `allow_clamp = true` so PR 5 rewrites
    /// codex's `bind(0.0.0.0, 0)` to loopback instead of denying it.
    /// Regression guard against the entry being deleted or rephrased.
    #[test]
    fn codex_profile_has_mcp_listener_policy() {
        let config = SupervisorProfile::parse_toml_full(BUNDLED_PROFILES_TOML).unwrap();
        let codex = config
            .profiles
            .iter()
            .find(|p| p.name == "codex")
            .expect("codex profile must exist in bundled config");
        let mcp_entry = codex
            .local_listener_policy
            .iter()
            .find(|e| e.port == 0)
            .expect(
                "codex profile must declare a local_listener_policy entry for port 0 \
                 (the kernel-assigned MCP transport port) — without it PR 5 denies \
                 every wildcard bind and the MCP handshake fails",
            );
        assert!(
            mcp_entry.allow_clamp,
            "codex MCP transport entry must set allow_clamp = true so the supervisor \
             rewrites the wildcard bind to loopback"
        );
        assert_eq!(
            mcp_entry.family,
            ListenerFamily::Any,
            "family must cover both `0.0.0.0:0` and `[::]:0` — the v4-only \
             entry left the v6 form of the same ephemeral idiom prompting"
        );
    }

    #[test]
    fn bundled_profiles_have_required_fields() {
        let config = SupervisorProfile::parse_toml_full(BUNDLED_PROFILES_TOML).unwrap();
        for profile in &config.profiles {
            assert!(!profile.name.is_empty(), "profile name must not be empty");
            assert!(
                !profile.display_name.is_empty(),
                "profile {} must have a display_name",
                profile.name
            );
        }
    }

    #[test]
    fn load_bundled_config_returns_valid_config() {
        let config =
            SupervisorProfile::load_bundled_config().expect("load_bundled_config should succeed");
        assert!(!config.profiles.is_empty());
        // Should contain known profiles.
        let names: Vec<&str> = config.profiles.iter().map(|p| p.name.as_str()).collect();
        assert!(
            names.contains(&"claude-code"),
            "missing claude-code profile"
        );
        assert!(names.contains(&"generic"), "missing generic profile");
    }

    #[test]
    fn developer_override_disabled_by_default() {
        assert!(!env_flag_enabled(None));
        assert!(!env_flag_enabled(Some(std::ffi::OsStr::new(""))));
        assert!(!env_flag_enabled(Some(std::ffi::OsStr::new("0"))));
        assert!(!env_flag_enabled(Some(std::ffi::OsStr::new("false"))));
        assert!(!env_flag_enabled(Some(std::ffi::OsStr::new("no"))));
    }

    #[test]
    fn developer_override_truthy_values_enable_override() {
        for value in ["1", "true", "yes"] {
            assert!(env_flag_enabled(Some(std::ffi::OsStr::new(value))));
        }
    }

    // ---- PR 5 Phase B: local_listener_policy schema + validation ----

    #[test]
    fn validate_routine_listen_addresses_rejects_ipv4_wildcard() {
        let offending = validate_routine_listen_addresses(&["127.0.0.1".into(), "0.0.0.0".into()]);
        assert_eq!(offending, vec!["0.0.0.0".to_string()]);
    }

    #[test]
    fn validate_routine_listen_addresses_rejects_ipv6_wildcard() {
        let offending = validate_routine_listen_addresses(&[
            "::1".into(),
            "::".into(),
            "0:0:0:0:0:0:0:0".into(),
        ]);
        assert!(offending.contains(&"::".to_string()));
        assert!(offending.contains(&"0:0:0:0:0:0:0:0".to_string()));
    }

    #[test]
    fn validate_routine_listen_addresses_rejects_ipv4_mapped_wildcard() {
        let offending = validate_routine_listen_addresses(&["::ffff:0.0.0.0".into()]);
        assert_eq!(offending, vec!["::ffff:0.0.0.0".to_string()]);
    }

    #[test]
    fn validate_routine_listen_addresses_accepts_loopback_and_specific_ip() {
        let offending = validate_routine_listen_addresses(&[
            "127.0.0.1".into(),
            "::1".into(),
            "localhost".into(),
            "192.168.1.10".into(),
            "::ffff:127.0.0.1".into(),
        ]);
        assert!(
            offending.is_empty(),
            "expected no rejections: {offending:?}"
        );
    }

    #[test]
    fn parse_toml_rejects_wildcard_in_routine_listen_addresses() {
        let toml = r#"
[[profiles]]
name = "bad"
display_name = "Bad"
rationale = ""
routine_paths = []
routine_commands = []
routine_destinations = []
routine_listen_addresses = ["0.0.0.0"]
"#;
        let err = SupervisorProfile::parse_toml(toml).expect_err("must reject 0.0.0.0");
        let msg = err.to_string();
        assert!(
            msg.contains("0.0.0.0"),
            "expected error to name 0.0.0.0: {msg}"
        );
        assert!(
            msg.contains("local_listener_policy"),
            "should suggest the alternative: {msg}"
        );
    }

    #[test]
    fn parse_toml_accepts_local_listener_policy_entry() {
        let toml = r#"
[[profiles]]
name = "with-local-listener"
display_name = "With Local Listener"
rationale = ""
routine_paths = []
routine_commands = []
routine_destinations = []
routine_listen_addresses = ["127.0.0.1"]

[[profiles.local_listener_policy]]
port = 41234
family = "any"
desc = "MCP local server"
allow_clamp = true

[[profiles.local_listener_policy]]
port = 0
family = "v4"
desc = "ephemeral IPC"
"#;
        let profiles = SupervisorProfile::parse_toml(toml).unwrap();
        assert_eq!(profiles.len(), 1);
        let p = &profiles[0];
        assert_eq!(p.local_listener_policy.len(), 2);
        assert_eq!(p.local_listener_policy[0].port, 41234);
        assert_eq!(p.local_listener_policy[0].family, ListenerFamily::Any);
        assert!(p.local_listener_policy[0].allow_clamp);
        assert_eq!(p.local_listener_policy[1].port, 0);
        assert_eq!(p.local_listener_policy[1].family, ListenerFamily::V4);
        // Default for allow_clamp is false.
        assert!(!p.local_listener_policy[1].allow_clamp);
    }

    #[test]
    fn local_listener_policy_inherits_from_parent_via_extends() {
        let toml = r#"
[[profiles]]
name = "parent"
display_name = "Parent"
rationale = ""
routine_paths = []
routine_commands = []
routine_destinations = []
routine_listen_addresses = []

[[profiles.local_listener_policy]]
port = 5555
family = "any"
desc = "inherited entry"

[[profiles]]
name = "child"
display_name = "Child"
rationale = ""
extends = "parent"
routine_paths = []
routine_commands = []
routine_destinations = []
routine_listen_addresses = []
"#;
        let profiles = SupervisorProfile::parse_toml(toml).unwrap();
        let child = profiles
            .iter()
            .find(|p| p.name == "child")
            .expect("child profile");
        assert_eq!(child.local_listener_policy.len(), 1);
        assert_eq!(child.local_listener_policy[0].port, 5555);
        assert_eq!(child.local_listener_policy[0].desc, "inherited entry");
    }

    // ---- PR 4 Phase B: routine_exec_roots glob expansion ----

    #[test]
    fn substitute_path_vars_handles_home_project_and_tilde() {
        let out = substitute_path_vars("${HOME}/.local/bin", "/h", "/p");
        assert_eq!(out, "/h/.local/bin");
        let out = substitute_path_vars("${PROJECT_DIR}/src", "/h", "/p");
        assert_eq!(out, "/p/src");
        let out = substitute_path_vars("~/.config", "/h", "/p");
        assert_eq!(out, "/h/.config");
        let out = substitute_path_vars("~", "/h", "/p");
        assert_eq!(out, "/h");
        // Leading tilde without slash is NOT expanded (matches glob semantics).
        let out = substitute_path_vars("~tmp", "/h", "/p");
        assert_eq!(out, "~tmp");
    }

    #[test]
    fn expand_glob_or_literal_passes_through_literals() {
        let out = expand_glob_or_literal("/usr/bin/sh");
        assert_eq!(out, vec!["/usr/bin/sh"]);
    }

    #[test]
    fn expand_glob_or_literal_walks_filesystem_for_meta() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::create_dir_all(root.join("c/b")).unwrap();
        // d intentionally has no b subdir — must not appear in output.
        std::fs::create_dir_all(root.join("d")).unwrap();

        let pattern = format!("{}/*/b", root.display());
        let out = expand_glob_or_literal(&pattern);
        assert_eq!(out.len(), 2, "expected two matches, got {out:?}");
        assert!(out.iter().any(|p| p.ends_with("/a/b")));
        assert!(out.iter().any(|p| p.ends_with("/c/b")));
    }

    #[test]
    fn expand_routine_exec_roots_canonicalises_and_adds_trailing_slash() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();

        let profile = SupervisorProfile {
            name: "test".into(),
            extends: None,
            display_name: "Test".into(),
            rationale: None,
            routine_paths: vec![],
            routine_commands: vec![],
            routine_destinations: vec![],
            routine_listen_addresses: vec![],
            routine_exec_roots: vec![real.to_string_lossy().into_owned()],
            scratch_roots: Vec::new(),
            readonly_paths: vec![],
            readonly_path_patterns: vec![],
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };
        let out = profile.expand_routine_exec_roots();
        assert_eq!(out.len(), 1);
        assert!(out[0].ends_with('/'), "expected trailing slash: {}", out[0]);
        assert!(out[0].contains("real"));
    }

    #[test]
    fn expand_scratch_roots_canonicalises_and_keeps_missing_as_literal() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();

        let profile = SupervisorProfile {
            name: "test".into(),
            extends: None,
            display_name: "Test".into(),
            rationale: None,
            routine_paths: vec![],
            routine_commands: vec![],
            routine_destinations: vec![],
            routine_listen_addresses: vec![],
            routine_exec_roots: vec![],
            // One existing dir + one that doesn't exist yet (scratch dirs are
            // created/destroyed, so missing entries are kept as literals — the
            // key difference from expand_routine_exec_roots).
            scratch_roots: vec![
                real.to_string_lossy().into_owned(),
                "/this/scratch/does/not/exist/yet".into(),
            ],
            readonly_paths: vec![],
            readonly_path_patterns: vec![],
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };
        let out = profile.expand_scratch_roots();
        assert_eq!(out.len(), 2, "both roots retained: {out:?}");
        assert!(
            out.iter().all(|p| p.ends_with('/')),
            "all trailing-slashed: {out:?}"
        );
        assert!(out.iter().any(|p| p.contains("real")));
        assert!(out
            .iter()
            .any(|p| p.starts_with("/this/scratch/does/not/exist/yet")));
    }

    #[test]
    fn expand_routine_exec_roots_drops_missing_dirs() {
        let profile = SupervisorProfile {
            name: "test".into(),
            extends: None,
            display_name: "Test".into(),
            rationale: None,
            routine_paths: vec![],
            routine_commands: vec![],
            routine_destinations: vec![],
            routine_listen_addresses: vec![],
            routine_exec_roots: vec!["/this/path/definitely/does/not/exist/pr4".into()],
            scratch_roots: Vec::new(),
            readonly_paths: vec![],
            readonly_path_patterns: vec![],
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };
        assert!(profile.expand_routine_exec_roots().is_empty());
    }

    #[test]
    fn expand_routine_exec_roots_expands_glob() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("v1/lib/node_modules/x")).unwrap();
        std::fs::create_dir_all(root.join("v2/lib/node_modules/x")).unwrap();

        let profile = SupervisorProfile {
            name: "test".into(),
            extends: None,
            display_name: "Test".into(),
            rationale: None,
            routine_paths: vec![],
            routine_commands: vec![],
            routine_destinations: vec![],
            routine_listen_addresses: vec![],
            routine_exec_roots: vec![format!("{}/*/lib/node_modules/x", root.display())],
            scratch_roots: Vec::new(),
            readonly_paths: vec![],
            readonly_path_patterns: vec![],
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };
        let out = profile.expand_routine_exec_roots();
        assert_eq!(out.len(), 2, "expected two glob matches: {out:?}");
        assert!(out.iter().all(|p| p.ends_with('/')));
    }

    #[test]
    fn build_session_allowlist_expands_glob_exec_roots() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("v1/lib/node_modules/x")).unwrap();
        std::fs::create_dir_all(root.join("v2/lib/node_modules/x")).unwrap();

        let profile = SupervisorProfile {
            name: "test".into(),
            extends: None,
            display_name: "Test".into(),
            rationale: None,
            routine_paths: vec![],
            routine_commands: vec![],
            routine_destinations: vec![],
            routine_listen_addresses: vec![],
            routine_exec_roots: vec![format!("{}/*/lib/node_modules/x", root.display())],
            scratch_roots: Vec::new(),
            readonly_paths: vec![],
            readonly_path_patterns: vec![],
            launch_contract: None,
            local_listener_policy: vec![],
            namespace_users: vec![],
            permit_authority_delegating: vec![],
            permit_control_sockets: vec![],
        };
        let allowed = profile.build_session_allowlist();
        let exec_prefix_count = allowed
            .iter()
            .filter(|e| e.starts_with("exec-prefix:"))
            .count();
        assert_eq!(
            exec_prefix_count, 2,
            "expected two exec-prefix entries from glob, got: {allowed:?}"
        );
    }
}
