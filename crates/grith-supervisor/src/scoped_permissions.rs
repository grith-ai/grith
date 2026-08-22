// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Session-only directory-scoped permission defaults and validation.

use std::path::{Component, Path, PathBuf};

use grith_digest::{ScopedAllowRequest, ScopedDenyRequest};

/// Which direction a scope proposal points.
///
/// The two modes share one classifier because a reviewer editing a directory
/// must get the same containment and glob answers either way; they differ
/// only in which refusals apply, and those differences all follow from
/// "granting authority is the risky direction, withholding it is not".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeMode {
    /// Grant the selected operations under the directory for this session.
    Allow,
    /// Block the selected operations under the directory for this session.
    Deny,
}

impl ScopeMode {
    /// Whether this mode grants authority (and so carries the allow-side
    /// breadth and sensitivity floors).
    #[must_use]
    pub fn grants(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// A validated scoped request ready to insert into a session allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedScopedAllow {
    /// Canonical or safely normalized directory, always with a trailing slash.
    pub directory: String,
    /// Namespaced session allowlist entries selected by the reviewer.
    pub rules: Vec<String>,
    /// Warning shown when the directory does not yet exist.
    pub warning: Option<String>,
}

/// A validated scoped refusal ready to insert into the session denylist.
///
/// Deliberately a distinct type from [`ValidatedScopedAllow`]: the two carry
/// rules from different namespaces into different sets, and a single type
/// would let one be passed where the other is expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedScopedDeny {
    /// Canonical or safely normalized directory, always with a trailing slash.
    pub directory: String,
    /// Namespaced session denylist entries selected by the reviewer.
    pub rules: Vec<String>,
    /// Warning shown when the directory does not yet exist.
    pub warning: Option<String>,
}

/// A best-effort path preview for the scope editor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopePathPreview {
    /// Canonical or safely normalized directory, always with a trailing slash.
    pub resolved_directory: String,
    /// Whether the proposed directory currently exists.
    pub exists: bool,
}

/// Live verdict for a scope proposal.
///
/// The editor renders this on every keystroke and `validate_scoped_allow`
/// derives its Enter-time error from the same classification
/// (`classify_scope`), so the two can never disagree. Before this existed the
/// reviewer only learned about breadth, sensitivity and target containment
/// after pressing Enter, and three of the rejections read as "can't find it".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeStatus {
    /// Every check passes and the directory exists.
    Covers,
    /// Every check passes; the directory has not been created yet. Scoping a
    /// directory the tool is about to create is legitimate, so this is a
    /// warning rather than a refusal.
    CoversPending,
    /// The directory existed when the review opened and is gone now. The
    /// reviewed call is frozen but nothing else is, so a concurrent
    /// `git worktree remove` can delete the scope directory mid-review.
    RemovedWhileFrozen,
    /// The directory does not contain the reviewed call's target, so the rule
    /// it would install could not match the call that opened the dialog.
    MissesTarget {
        /// Basename of the reviewed call's target.
        target: String,
    },
    /// Refused by the breadth floor.
    TooBroad {
        /// Reviewer-facing explanation naming the floor.
        reason: String,
    },
    /// Refused because the directory is (or contains) credential material.
    Sensitive {
        /// Reviewer-facing explanation.
        reason: String,
    },
    /// The directory carries glob metacharacters, which the session rule
    /// format does not support.
    Glob,
    /// Deny mode only: the directory is a runtime root the supervised tool
    /// cannot run without. Blocking it does not protect anything — the tool
    /// dies at its next shared-library load — so the editor refuses rather
    /// than letting the reviewer wedge their own session.
    RuntimeRoot {
        /// Reviewer-facing explanation naming the directory.
        reason: String,
    },
    /// Anything else: empty, relative, not a directory, no operation ticked.
    Invalid {
        /// Reviewer-facing explanation.
        reason: String,
    },
}

impl ScopeStatus {
    /// Whether this verdict stops the scope from being applied.
    #[must_use]
    pub fn blocks_apply(&self) -> bool {
        !matches!(
            self,
            Self::Covers | Self::CoversPending | Self::RemovedWhileFrozen
        )
    }

    /// Whether the proposal is accepted but carries a caveat worth colouring.
    #[must_use]
    pub fn is_warning(&self) -> bool {
        matches!(self, Self::CoversPending | Self::RemovedWhileFrozen)
    }

    /// One-line, reviewer-facing explanation. Deliberately free of decoration
    /// so the same string reads correctly in a status line, an inline error
    /// and a supervisor log entry.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Covers => "Covers this operation".to_string(),
            Self::CoversPending => {
                "Directory does not exist yet \u{2014} the scope is session-only".to_string()
            }
            Self::RemovedWhileFrozen => concat!(
                "That directory was removed while this request was frozen ",
                "\u{2014} the scope applies if it is recreated"
            )
            .to_string(),
            Self::MissesTarget { target } => {
                format!("The directory does not contain the target: {target}")
            }
            Self::Glob => concat!(
                "Remove * and ? \u{2014} a directory already covers ",
                "everything beneath it"
            )
            .to_string(),
            Self::TooBroad { reason }
            | Self::Sensitive { reason }
            | Self::RuntimeRoot { reason }
            | Self::Invalid { reason } => reason.clone(),
        }
    }
}

/// Build the safe default scope for a displayed file operation.
///
/// The digest queue stores the `Display` form of `ToolCallType`, so this
/// helper deliberately parses only the small, explicit file-operation set
/// supported by v1.
pub fn default_scoped_allow(tool_call: &str) -> Option<ScopedAllowRequest> {
    let (target, read, write, delete, use_target_directory) =
        if let Some(path) = unary_target(tool_call, "FileRead") {
            (path, true, false, false, false)
        } else if let Some(path) = unary_target(tool_call, "DirList") {
            (path, true, false, false, true)
        } else if let Some(path) = unary_target(tool_call, "FileWrite") {
            (path, false, true, false, false)
        } else if let Some(path) = unary_target(tool_call, "FileAppend") {
            (path, false, true, false, false)
        } else if let Some(path) = unary_target(tool_call, "DirCreate") {
            (path, false, true, false, false)
        } else if let Some(path) = unary_target(tool_call, "FileDelete") {
            (path, false, false, true, false)
        } else {
            let body = unary_target(tool_call, "FileRename")?;
            let old_path = body.split_once(" -> ")?.0;
            (old_path, false, false, true, false)
        };

    let directory = if use_target_directory {
        PathBuf::from(target)
    } else {
        Path::new(target).parent()?.to_path_buf()
    };

    Some(ScopedAllowRequest {
        directory: with_trailing_separator(&directory.to_string_lossy()),
        read,
        write,
        delete,
        persist: false,
    })
}

/// Resolve a directory proposal for display without applying security policy.
pub fn preview_scope_path(directory: &str) -> Result<ScopePathPreview, String> {
    let (path, exists) = resolve_directory(directory)?;
    Ok(ScopePathPreview {
        resolved_directory: with_trailing_separator(&path.to_string_lossy()),
        exists,
    })
}

/// Run every check `validate_scoped_allow` runs, without building the rules.
///
/// `directory_existed_at_open` lets the editor distinguish "you are scoping a
/// directory that does not exist yet" from "the directory you were shown has
/// been deleted underneath you". It changes the wording only; the verdict is
/// identical either way, which is why the supervisor-side re-validation can
/// pass `false` without diverging from what the reviewer was shown.
#[must_use]
pub fn preview_scoped_allow(
    request: &ScopedAllowRequest,
    tool_call: &str,
    directory_existed_at_open: bool,
) -> ScopeStatus {
    preview(
        &Proposal::from(request),
        tool_call,
        directory_existed_at_open,
    )
}

/// [`preview_scoped_allow`] for a proposed refusal.
#[must_use]
pub fn preview_scoped_deny(
    request: &ScopedDenyRequest,
    tool_call: &str,
    directory_existed_at_open: bool,
) -> ScopeStatus {
    preview(
        &Proposal::from(request),
        tool_call,
        directory_existed_at_open,
    )
}

fn preview(
    proposal: &Proposal<'_>,
    tool_call: &str,
    directory_existed_at_open: bool,
) -> ScopeStatus {
    match classify_scope(proposal, tool_call, directory_existed_at_open) {
        Ok((_, status)) => status,
        Err(status) => {
            // Structural guard for the invariant the whole classifier exists
            // to hold: anything `classify_scope` refuses has to read as a
            // refusal in the editor too. A refusal that reported itself as
            // applicable would put the reviewer straight back in the failure
            // this rewrite removes — a green status line followed by an
            // Enter-time error.
            debug_assert!(
                status.blocks_apply(),
                "a refused scope must block apply: {status:?}"
            );
            status
        }
    }
}

/// Validate and canonicalize a session-only scoped permission.
pub fn validate_scoped_allow(
    request: &ScopedAllowRequest,
    current_tool_call: &str,
) -> Result<ValidatedScopedAllow, String> {
    // `false`: this entry point has no dialog history, so it cannot tell a
    // never-created directory from one deleted during the review. Both are
    // accepted with the same warning, so the verdict is unaffected.
    let proposal = Proposal::from(request);
    let (directory, status) =
        classify_scope(&proposal, current_tool_call, false).map_err(|status| status.message())?;

    let directory = with_trailing_separator(&directory.to_string_lossy());
    Ok(ValidatedScopedAllow {
        rules: prefixed_rules(&proposal, &directory, ""),
        directory,
        warning: status.is_warning().then(|| status.message()),
    })
}

/// Validate and canonicalize a session-only scoped refusal.
///
/// Runs the same classifier as [`validate_scoped_allow`] — containment, glob
/// refusal and "the ticked operation must cover the reviewed call" all apply
/// identically, because a refusal that cannot match the call that opened the
/// dialog is just as dead as a grant that cannot. What changes is the refusal
/// set: the breadth floor and the sensitive-directory rules exist to stop
/// authority being granted too widely, and neither has any meaning when the
/// reviewer is withholding authority. Blocking `$HOME` or `~/.ssh` for a
/// session is a legitimate thing to ask for, so deny mode permits both.
pub fn validate_scoped_deny(
    request: &ScopedDenyRequest,
    current_tool_call: &str,
) -> Result<ValidatedScopedDeny, String> {
    let proposal = Proposal::from(request);
    let (directory, status) =
        classify_scope(&proposal, current_tool_call, false).map_err(|status| status.message())?;

    let directory = with_trailing_separator(&directory.to_string_lossy());
    Ok(ValidatedScopedDeny {
        rules: prefixed_rules(&proposal, &directory, DENY_RULE_PREFIX),
        directory,
        warning: status.is_warning().then(|| status.message()),
    })
}

/// Namespace prefix that turns an allow rule into its refusal twin.
///
/// Deny rules live in their own session set, never in the allowlist: a
/// `deny-…` string sitting in `session_allowed` would be one missing
/// namespace exclusion away from being read as a bare allow prefix.
pub const DENY_RULE_PREFIX: &str = "deny-";

fn prefixed_rules(proposal: &Proposal<'_>, directory: &str, prefix: &str) -> Vec<String> {
    let mut rules = Vec::with_capacity(3);
    for namespace in selected_rule_namespaces(proposal) {
        rules.push(format!("{prefix}{namespace}{directory}"));
    }
    rules
}

/// Single source of truth for the live preview and the Enter-time validation.
///
/// Returns the resolved directory plus the non-blocking verdict on success,
/// or the blocking verdict. Every caller must go through this: the reason the
/// editor was unusable is that render-time checked resolution only while
/// Enter checked breadth, sensitivity and containment.
fn classify_scope(
    proposal: &Proposal<'_>,
    tool_call: &str,
    directory_existed_at_open: bool,
) -> Result<(PathBuf, ScopeStatus), ScopeStatus> {
    if proposal.persist {
        return Err(ScopeStatus::Invalid {
            reason: "Persistent directory scopes are not available in v1".to_string(),
        });
    }

    // A scoped rule is matched by `directory_scope_matches` in the supervisor's
    // event handler as a literal string prefix with a `/` boundary — there is
    // no glob support on that path. A reviewer who writes "everything beneath
    // here" the way the profile config does (`.../**`) would otherwise be told
    // the scope applied and then keep getting the same prompts forever, from a
    // rule that can only fire on a directory literally named `**`. Refusing
    // the two wildcard metacharacters is what makes an applied scope
    // guaranteed non-dead.
    //
    // `[` and `]` are deliberately *not* refused, despite the work item naming
    // `[`: literal matching is exactly what makes a directory really called
    // `[token]` scopable, and every Next.js dynamic route segment — including
    // the ones in the tree that produced this work item — is named that way.
    // Refusing brackets would remove the escape hatch on those paths and buy
    // nothing, since a bracketed rule matches the bracketed directory and
    // nothing else. This only ever costs prompts, never grants authority.
    if proposal.directory.contains(['*', '?']) {
        return Err(ScopeStatus::Glob);
    }

    if !proposal.read && !proposal.write && !proposal.delete {
        return Err(ScopeStatus::Invalid {
            reason: "Select at least one operation".to_string(),
        });
    }

    let (directory, exists) =
        resolve_directory(proposal.directory).map_err(|reason| ScopeStatus::Invalid { reason })?;
    if proposal.mode.grants() {
        reject_broad_or_sensitive_scope(&directory, proposal)?;
    } else {
        reject_runtime_root_scope(&directory)?;
    }

    let target = scoped_operation_target(tool_call).ok_or_else(|| ScopeStatus::Invalid {
        reason: "This operation does not support directory scoping".to_string(),
    })?;
    let target = resolve_path(&target)
        .map_err(|reason| ScopeStatus::Invalid { reason })?
        .0;
    if !target.starts_with(&directory) {
        return Err(ScopeStatus::MissesTarget {
            target: target
                .file_name()
                .map_or_else(|| target.to_string_lossy(), |name| name.to_string_lossy())
                .into_owned(),
        });
    }

    // No dead scopes, part two: containment proves the directory covers the
    // target, but the reviewed call also has to fall into one of the ticked
    // namespaces or the applied rules cannot match the very call that opened
    // the dialog — the prompts would continue with nothing on screen to
    // explain why. Mirrors `prefix_namespace` in the supervisor's
    // `is_session_allowlist_match`; the two must stay in step.
    if let Some(namespace) = scoped_rule_namespace(tool_call) {
        if !selected_rule_namespaces(proposal).contains(&namespace) {
            return Err(ScopeStatus::Invalid {
                reason: format!(
                    "Tick {} so this scope covers the current operation",
                    namespace_label(namespace)
                ),
            });
        }
    }

    let status = if exists {
        ScopeStatus::Covers
    } else if directory_existed_at_open {
        ScopeStatus::RemovedWhileFrozen
    } else {
        ScopeStatus::CoversPending
    };
    Ok((directory, status))
}

/// Session-allowlist namespace a scoped rule needs to carry to match
/// `tool_call`. Mirrors `prefix_namespace` in `is_session_allowlist_match`.
fn scoped_rule_namespace(tool_call: &str) -> Option<&'static str> {
    for (kind, namespace) in [
        ("FileRead", "ro-prefix:"),
        ("DirList", "ro-prefix:"),
        ("FileWrite", "write-prefix:"),
        ("FileAppend", "write-prefix:"),
        ("DirCreate", "write-prefix:"),
        ("FileDelete", "delete-prefix:"),
        ("FileRename", "delete-prefix:"),
    ] {
        if unary_target(tool_call, kind).is_some() {
            return Some(namespace);
        }
    }
    None
}

fn selected_rule_namespaces(proposal: &Proposal<'_>) -> Vec<&'static str> {
    let mut namespaces = Vec::with_capacity(3);
    if proposal.read {
        namespaces.push("ro-prefix:");
    }
    if proposal.write {
        namespaces.push("write-prefix:");
    }
    if proposal.delete {
        namespaces.push("delete-prefix:");
    }
    namespaces
}

/// The mode-agnostic view of a scope proposal the classifier operates on.
///
/// Borrowed, not owned: it is rebuilt on every keystroke of the editor's live
/// preview.
// The four bools mirror the wire types this view unifies
// (`ScopedAllowRequest` / `ScopedDenyRequest`), which carry one flag per
// user-facing checkbox. Folding them into an enum here would only move the
// same four states behind a translation layer the classifier has to undo.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy)]
struct Proposal<'a> {
    directory: &'a str,
    read: bool,
    write: bool,
    delete: bool,
    persist: bool,
    mode: ScopeMode,
}

impl<'a> From<&'a ScopedAllowRequest> for Proposal<'a> {
    fn from(request: &'a ScopedAllowRequest) -> Self {
        Self {
            directory: &request.directory,
            read: request.read,
            write: request.write,
            delete: request.delete,
            persist: request.persist,
            mode: ScopeMode::Allow,
        }
    }
}

impl<'a> From<&'a ScopedDenyRequest> for Proposal<'a> {
    fn from(request: &'a ScopedDenyRequest) -> Self {
        Self {
            directory: &request.directory,
            read: request.read,
            write: request.write,
            delete: request.delete,
            // There is no persistence flow for refusals either, and the wire
            // type has no field to carry one.
            persist: false,
            mode: ScopeMode::Deny,
        }
    }
}

fn namespace_label(namespace: &str) -> &'static str {
    match namespace {
        "ro-prefix:" => "read",
        "write-prefix:" => "write/create",
        _ => "delete/rename",
    }
}

/// Return the path whose authority is consumed by the scoped operation.
pub(crate) fn scoped_operation_target(tool_call: &str) -> Option<String> {
    for kind in [
        "FileRead",
        "DirList",
        "FileWrite",
        "FileAppend",
        "DirCreate",
        "FileDelete",
    ] {
        if let Some(path) = unary_target(tool_call, kind) {
            return Some(path.to_string());
        }
    }
    unary_target(tool_call, "FileRename")
        .and_then(|body| body.split_once(" -> ").map(|(old, _)| old.to_string()))
}

/// Return the scoped authority target directly from an evaluated tool call.
pub(crate) fn scoped_call_target(call_type: &grith_proxy::types::ToolCallType) -> Option<&str> {
    use grith_proxy::types::ToolCallType;
    match call_type {
        ToolCallType::FileRead { path }
        | ToolCallType::DirList { path }
        | ToolCallType::FileWrite { path, .. }
        | ToolCallType::FileAppend { path }
        | ToolCallType::DirCreate { path }
        | ToolCallType::FileDelete { path } => Some(path),
        ToolCallType::FileRename { old_path, .. } => Some(old_path),
        _ => None,
    }
}

/// Resolve a filesystem target using the same existing-ancestor strategy as
/// directory validation. This keeps nonexistent create targets comparable to
/// a canonical directory without following a broader symlink silently.
pub(crate) fn resolve_target(path: &str) -> Result<PathBuf, String> {
    resolve_path(path).map(|(path, _)| path)
}

fn unary_target<'a>(tool_call: &'a str, kind: &str) -> Option<&'a str> {
    tool_call
        .strip_prefix(kind)?
        .strip_prefix('(')?
        .strip_suffix(')')
}

fn resolve_directory(directory: &str) -> Result<(PathBuf, bool), String> {
    let raw = Path::new(directory);
    if directory.trim().is_empty() {
        return Err("Directory cannot be empty".to_string());
    }
    if !raw.is_absolute() {
        return Err("Directory must be an absolute path".to_string());
    }

    let (resolved, exists) = resolve_path(directory)?;
    if exists && !resolved.is_dir() {
        return Err("Scope path must be a directory".to_string());
    }
    Ok((resolved, exists))
}

#[cfg(test)]
thread_local! {
    /// Path to delete the next time [`simulate_mid_review_deletion`] runs.
    static VANISH_AT_CANONICALIZE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Test seam for the mid-review deletion race, compiled out of every
/// non-test build.
///
/// The race — a directory that passes the existence probe and is gone by the
/// canonicalisation — is the one window in which the live preview and the
/// Enter-time validation used to disagree, and it cannot be reached from a
/// single-threaded test any other way. Leaving it untested is what let the
/// disagreement ship in the first place.
fn simulate_mid_review_deletion() {
    #[cfg(test)]
    VANISH_AT_CANONICALIZE.with(|slot| {
        if let Some(path) = slot.borrow_mut().take() {
            let _ = std::fs::remove_dir_all(path);
        }
    });
}

/// Resolve a path to its canonical form, reporting whether it exists.
///
/// A `NotFound` from either canonicalisation means the path went away between
/// the existence check and the resolution. The reviewed call is frozen while
/// the review dialog is up, but nothing else is, so a concurrent
/// `git worktree remove` sweeping the tree lands exactly in that window.
/// Falling through to existing-ancestor reconstruction — the same treatment a
/// not-yet-created directory already gets — is what lets the editor say "that
/// directory was removed while this request was frozen" instead of surfacing
/// `os error 2`, and, more importantly, is what stops the live preview and the
/// Enter-time validation disagreeing about whether the scope can be applied.
///
/// Every other io error still refuses. An unreadable ancestor is not a race,
/// and reconstructing a path we could not resolve would mean scoping a
/// directory whose real identity (symlink target included) we never
/// established.
fn resolve_path(path: &str) -> Result<(PathBuf, bool), String> {
    let cleaned = normalize_absolute(Path::new(path))?;
    if cleaned.exists() {
        simulate_mid_review_deletion();
        match std::fs::canonicalize(&cleaned) {
            Ok(resolved) => return Ok((resolved, true)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Could not resolve path: {e}")),
        }
    }

    let mut ancestor = cleaned.as_path();
    let mut suffix = Vec::new();
    let mut resolved = loop {
        if ancestor.exists() {
            match std::fs::canonicalize(ancestor) {
                Ok(resolved) => break resolved,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("Could not resolve parent directory: {e}")),
            }
        }
        let name = ancestor
            .file_name()
            .ok_or_else(|| "Could not resolve an existing parent directory".to_string())?;
        suffix.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| "Could not resolve an existing parent directory".to_string())?;
    };
    for component in suffix.iter().rev() {
        resolved.push(component);
    }
    Ok((resolved, false))
}

fn normalize_absolute(path: &Path) -> Result<PathBuf, String> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push("/"),
            Component::CurDir | Component::Prefix(_) => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err("Directory escapes the filesystem root".to_string());
                }
            }
        }
    }
    Ok(normalized)
}

/// Trees the supervised tool cannot survive losing access to.
///
/// A refusal is not free protection: blocking any of these stops the tool at
/// its next shared-library load, interpreter read or resolver lookup, so the
/// operator gets a dead session instead of a restricted one. Anything in them
/// worth protecting is protected by the proxy's own sensitive-path scoring,
/// which a scoped refusal does not replace.
///
/// Matched by **ancestry**, not equality, and after canonicalisation. Both
/// matter: `/` and `/usr` are refused because they contain these trees, and
/// on a merged-`/usr` distribution `/lib` canonicalises to `/usr/lib`, so an
/// equality test against the literal `/lib` would wave through the very path
/// the loader reads. A directory *inside* one of them — `/usr/lib/node_modules/…`
/// — is still blockable; only the trees themselves and their ancestors are not.
///
/// Note what is absent: `$HOME`, `/home`, `/tmp`, `/var`, `/mnt`, `/media`,
/// `/srv` and every user directory. Blocking those is what deny mode is for.
const CRITICAL_RUNTIME_TREES: &[&str] = &[
    // Kernel interfaces.
    "/proc",
    "/sys",
    "/dev",
    // Resolver, loader config, certificates, account databases.
    "/etc",
    // Shared libraries, in both merged and split layouts.
    "/lib",
    "/lib64",
    "/lib32",
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib32",
    // The interpreters and tools the session spawns.
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    // Session sockets: D-Bus, the keyring, systemd.
    "/run",
];

fn reject_runtime_root_scope(directory: &Path) -> Result<(), ScopeStatus> {
    let normalized = directory.to_string_lossy().replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    let shown = if trimmed.is_empty() { "/" } else { trimmed };
    for tree in CRITICAL_RUNTIME_TREES {
        // A tree that does not exist on this host cannot be depended on by
        // this session either, so skipping it is safe; canonicalising is what
        // makes the merged-`/usr` symlinks resolve to the same path the
        // supervisor will see at syscall time.
        let Ok(canonical) = std::fs::canonicalize(tree) else {
            continue;
        };
        if canonical.starts_with(directory) {
            return Err(ScopeStatus::RuntimeRoot {
                reason: format!(
                    "Blocking {shown} would stop the supervised tool from running \
                     ({}); choose a directory inside it",
                    canonical.display()
                ),
            });
        }
    }
    Ok(())
}

fn reject_broad_or_sensitive_scope(
    directory: &Path,
    request: &Proposal<'_>,
) -> Result<(), ScopeStatus> {
    let normalized = directory.to_string_lossy().replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    let components: Vec<&str> = trimmed.split('/').filter(|part| !part.is_empty()).collect();
    let is_user_home = matches!(
        components.as_slice(),
        ["home", _] | ["Users", _] | ["users", _]
    );
    if trimmed.is_empty()
        || matches!(trimmed, "/home" | "/Users" | "/tmp" | "/var")
        || components.len() < 2
        || is_user_home
    {
        // Naming the floor turns a dead end into an instruction: the editor
        // greys its "wider" hint here and shows this, instead of letting the
        // reviewer walk one component too far and hit it on Enter.
        let floor = if trimmed.is_empty() { "/" } else { trimmed };
        return Err(ScopeStatus::TooBroad {
            reason: format!(
                "That directory scope is too broad \u{2014} pick a directory below {floor}"
            ),
        });
    }

    let home = dirs::home_dir().and_then(|path| std::fs::canonicalize(path).ok());
    if let Some(home) = &home {
        if directory == home {
            return Err(ScopeStatus::TooBroad {
                reason: "The home directory cannot be scoped".to_string(),
            });
        }
    }

    let lower = format!("{}/", trimmed.to_ascii_lowercase());
    let is_sensitive_parent = lower.trim_end_matches('/').ends_with("/.config");

    let mut sensitive_roots = Vec::new();
    if let Some(home) = &home {
        for suffix in [
            ".ssh",
            ".aws",
            ".gnupg",
            ".kube",
            ".config/gcloud",
            ".mozilla",
            ".config/google-chrome",
            ".config/chromium",
            ".config/BraveSoftware",
            ".config/microsoft-edge",
        ] {
            sensitive_roots.push(home.join(suffix));
        }
    }
    for base in [dirs::config_dir(), dirs::data_dir(), dirs::cache_dir()]
        .into_iter()
        .flatten()
    {
        sensitive_roots.push(base.join("grith"));
    }

    // A parent such as ~/.config would sweep several unrelated credential
    // stores into one approval. Keep those broad sensitive parents blocked.
    // An explicitly selected sensitive directory may be scoped for reads in
    // this session, but write/delete authority remains single-request only.
    let contains_sensitive_root = sensitive_roots
        .iter()
        .any(|sensitive| sensitive != directory && sensitive.starts_with(directory));
    if is_sensitive_parent || contains_sensitive_root {
        return Err(ScopeStatus::Sensitive {
            reason: "Sensitive directories require single-request approval".to_string(),
        });
    }

    let targets_sensitive_directory = crate::syscall_map::is_sensitive_path(trimmed)
        || crate::syscall_map::is_sensitive_path(&lower)
        || sensitive_roots
            .iter()
            .any(|sensitive| directory.starts_with(sensitive));
    if targets_sensitive_directory && (request.write || request.delete) {
        return Err(ScopeStatus::Sensitive {
            reason: "Sensitive directories only support read-only scope for this session"
                .to_string(),
        });
    }

    if request.delete {
        if std::env::current_dir()
            .ok()
            .and_then(|path| std::fs::canonicalize(path).ok())
            .is_some_and(|project| project == directory)
        {
            return Err(ScopeStatus::TooBroad {
                reason: "Delete scope for the project root is blocked; choose a subdirectory"
                    .to_string(),
            });
        }
        if let Some(home) = &home {
            if let Ok(relative) = directory.strip_prefix(home) {
                if relative
                    .components()
                    .next()
                    .and_then(|part| part.as_os_str().to_str())
                    .is_some_and(|part| part.starts_with('.'))
                {
                    return Err(ScopeStatus::Sensitive {
                        reason: "Delete scopes are blocked for home configuration directories"
                            .to_string(),
                    });
                }
            }
        }
        if components.windows(3).any(|parts| {
            matches!(parts, ["home", _, hidden] | ["Users", _, hidden] | ["users", _, hidden]
                    if hidden.starts_with('.'))
        }) {
            return Err(ScopeStatus::Sensitive {
                reason: "Delete scopes are blocked for home configuration directories".to_string(),
            });
        }
    }

    Ok(())
}

fn with_trailing_separator(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    if normalized.ends_with('/') {
        normalized
    } else {
        format!("{normalized}/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- work/85: deny mode -------------------------------------------
    fn deny_request(directory: &str) -> ScopedDenyRequest {
        ScopedDenyRequest {
            directory: directory.to_string(),
            read: true,
            write: true,
            delete: true,
        }
    }

    #[test]
    fn deny_accepts_the_breadth_allow_refuses() {
        // The whole point of the mode: the directories most worth blocking
        // are exactly the ones too broad or too sensitive to hand out.
        let home = dirs::home_dir().expect("home directory");
        let home = home.to_string_lossy().into_owned();
        let call = format!("FileRead({home}/notes/secret.md)");

        let allow = ScopedAllowRequest {
            directory: format!("{home}/"),
            read: true,
            write: false,
            delete: false,
            persist: false,
        };
        assert!(
            validate_scoped_allow(&allow, &call).is_err(),
            "granting the home directory must stay refused"
        );

        let blocked = validate_scoped_deny(&deny_request(&format!("{home}/")), &call)
            .expect("blocking the home directory is legitimate");
        assert_eq!(blocked.rules.len(), 3);
        assert!(blocked
            .rules
            .iter()
            .all(|rule| rule.starts_with(DENY_RULE_PREFIX)));
    }

    #[test]
    fn deny_accepts_a_sensitive_directory() {
        let home = dirs::home_dir().expect("home directory");
        let ssh = home.join(".ssh");
        let ssh = ssh.to_string_lossy().into_owned();
        let call = format!("FileRead({ssh}/id_ed25519)");

        let blocked =
            validate_scoped_deny(&deny_request(&format!("{ssh}/")), &call).expect("blockable");
        assert!(blocked.rules.contains(&format!("deny-ro-prefix:{ssh}/")));
    }

    #[test]
    fn deny_refuses_runtime_roots() {
        for root in ["/", "/usr", "/etc", "/lib", "/proc"] {
            let call = format!("FileRead({}/something)", root.trim_end_matches('/'));
            let error = validate_scoped_deny(&deny_request(root), &call)
                .expect_err("runtime roots must be refused");
            assert!(
                error.contains("stop the supervised tool"),
                "unexpected refusal for {root}: {error}"
            );
        }
    }

    #[test]
    fn deny_refuses_a_runtime_root_reached_by_a_trailing_slash_or_dot() {
        // The guard compares canonical, normalised paths, so the spellings
        // that would sidestep a naive string check do not.
        for spelling in ["/usr/", "/usr/.", "/usr/lib/.."] {
            let error = validate_scoped_deny(&deny_request(spelling), "FileRead(/usr/lib/libc.so)")
                .expect_err("runtime root must be refused however it is spelled");
            assert!(
                error.contains("stop the supervised tool"),
                "{spelling}: {error}"
            );
        }
    }

    #[test]
    fn deny_keeps_containment_and_glob_refusals() {
        let missed =
            validate_scoped_deny(&deny_request("/repo/build/"), "FileRead(/repo/src/lib.rs)")
                .expect_err("a rule that cannot match the reviewed call is dead");
        assert!(missed.contains("does not contain the target"));

        let glob = validate_scoped_deny(&deny_request("/repo/**/"), "FileRead(/repo/src/lib.rs)")
            .expect_err("glob metacharacters have no meaning in a session rule");
        assert!(glob.contains("Remove * and ?"));

        let no_ops = validate_scoped_deny(
            &ScopedDenyRequest {
                directory: "/repo/src/".to_string(),
                read: false,
                write: false,
                delete: false,
            },
            "FileRead(/repo/src/lib.rs)",
        )
        .expect_err("a refusal of nothing is not a refusal");
        assert!(no_ops.contains("Select at least one operation"));
    }

    #[test]
    fn deny_rules_carry_only_the_ticked_operations() {
        let request = ScopedDenyRequest {
            directory: "/repo/src/".to_string(),
            read: true,
            write: false,
            delete: true,
        };
        let blocked = validate_scoped_deny(&request, "FileRead(/repo/src/lib.rs)").expect("valid");
        assert_eq!(
            blocked.rules,
            vec![
                "deny-ro-prefix:/repo/src/".to_string(),
                "deny-delete-prefix:/repo/src/".to_string(),
            ]
        );
        assert_eq!(blocked.directory, "/repo/src/");
    }

    #[test]
    fn deny_preview_agrees_with_deny_validation() {
        // The editor's live status line and the Enter-time answer come from
        // one classifier in allow mode; deny mode must not be the exception.
        let cases = [
            ("/repo/src/", "FileRead(/repo/src/lib.rs)"),
            ("/usr/", "FileRead(/usr/lib/libc.so)"),
            ("/repo/build/", "FileRead(/repo/src/lib.rs)"),
        ];
        for (directory, call) in cases {
            let status = preview_scoped_deny(&deny_request(directory), call, false);
            let validated = validate_scoped_deny(&deny_request(directory), call);
            assert_eq!(
                status.blocks_apply(),
                validated.is_err(),
                "{directory} preview and validation disagree"
            );
        }
    }

    fn read_request(directory: &str) -> ScopedAllowRequest {
        ScopedAllowRequest {
            directory: directory.to_string(),
            read: true,
            write: false,
            delete: false,
            persist: false,
        }
    }

    #[test]
    fn defaults_follow_operation_intent() {
        let read = default_scoped_allow("FileRead(/repo/src/lib.rs)").unwrap();
        assert_eq!(read.directory, "/repo/src/");
        assert!(read.read);
        assert!(!read.write);
        assert!(!read.delete);

        let write = default_scoped_allow("FileWrite(/repo/src/lib.rs)").unwrap();
        assert!(write.write);
        assert!(!write.delete);

        let delete = default_scoped_allow("FileDelete(/repo/target/a.o)").unwrap();
        assert_eq!(delete.directory, "/repo/target/");
        assert!(delete.delete);
        assert!(!delete.write);

        let rename = default_scoped_allow("FileRename(/repo/old/a -> /repo/new/a)").unwrap();
        assert_eq!(rename.directory, "/repo/old/");
        assert!(rename.delete);

        let create = default_scoped_allow("DirCreate(/repo/new-dir)").unwrap();
        assert_eq!(create.directory, "/repo/");
        assert!(create.write);
    }

    #[test]
    fn non_file_operations_do_not_offer_scope() {
        assert!(default_scoped_allow("ProcessSpawn(cargo)").is_none());
        assert!(default_scoped_allow("FileChmod(/repo/a, 755)").is_none());
    }

    #[test]
    fn validation_rejects_broad_and_unrelated_scopes() {
        let broad = ScopedAllowRequest {
            directory: "/".to_string(),
            read: true,
            write: false,
            delete: false,
            persist: false,
        };
        assert!(validate_scoped_allow(&broad, "FileRead(/repo/a)").is_err());

        let unrelated = ScopedAllowRequest {
            directory: "/usr/share/".to_string(),
            ..broad
        };
        assert!(validate_scoped_allow(&unrelated, "FileRead(/repo/a)").is_err());

        let other_home = ScopedAllowRequest {
            directory: "/home/another-user/".to_string(),
            ..unrelated
        };
        assert!(
            validate_scoped_allow(&other_home, "FileRead(/home/another-user/document.txt)")
                .is_err()
        );
    }

    #[test]
    fn validation_rejects_sensitive_scope_parents() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let request = ScopedAllowRequest {
            directory: home.join(".config").to_string_lossy().into_owned(),
            read: true,
            write: false,
            delete: false,
            persist: false,
        };
        assert!(validate_scoped_allow(
            &request,
            &format!("FileRead({})", home.join(".config/example").display())
        )
        .is_err());
    }

    #[test]
    fn validation_allows_read_only_sensitive_session_scope() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let directory = home.join(".config/grith");
        let target = directory.join("daemon.token");
        let request = ScopedAllowRequest {
            directory: directory.to_string_lossy().into_owned(),
            read: true,
            write: false,
            delete: false,
            persist: false,
        };

        let validated =
            validate_scoped_allow(&request, &format!("FileRead({})", target.display())).unwrap();
        assert_eq!(validated.rules.len(), 1);
        assert!(validated.rules[0].starts_with("ro-prefix:"));
    }

    #[test]
    fn validation_rejects_sensitive_session_mutation_scope() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let directory = home.join(".config/grith");
        let target = directory.join("config.toml");
        let request = ScopedAllowRequest {
            directory: directory.to_string_lossy().into_owned(),
            read: false,
            write: true,
            delete: false,
            persist: false,
        };

        let error = validate_scoped_allow(&request, &format!("FileWrite({})", target.display()))
            .unwrap_err();
        assert!(error.contains("read-only"));
    }

    #[test]
    fn validation_allows_nonexistent_session_directory_with_warning() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("future");
        let target = directory.join("file.txt");
        let request = ScopedAllowRequest {
            directory: directory.to_string_lossy().into_owned(),
            read: false,
            write: true,
            delete: false,
            persist: false,
        };

        let validated =
            validate_scoped_allow(&request, &format!("FileWrite({})", target.display())).unwrap();
        assert!(validated.warning.is_some());
        assert_eq!(validated.rules.len(), 1);
        assert!(validated.rules[0].starts_with("write-prefix:"));
    }

    /// The whole point of the preview: whatever the status line says before
    /// Enter has to be what Enter does. Any divergence reintroduces the
    /// "it says it can't find it" failure this rewrite removes.
    #[test]
    fn preview_and_validation_never_disagree() {
        let root = tempfile::tempdir().unwrap();
        let existing = root.path().join("pkg");
        std::fs::create_dir(&existing).unwrap();
        let target = existing.join("lib.rs");
        let call = format!("FileWrite({})", target.display());

        let mut write = read_request(&existing.to_string_lossy());
        write.read = false;
        write.write = true;

        let cases = vec![
            write.clone(),
            read_request(&existing.to_string_lossy()),
            ScopedAllowRequest {
                directory: format!("{}/**", existing.display()),
                ..write.clone()
            },
            ScopedAllowRequest {
                directory: "/".to_string(),
                ..write.clone()
            },
            ScopedAllowRequest {
                directory: "relative/path".to_string(),
                ..write.clone()
            },
            ScopedAllowRequest {
                directory: format!("{}-partial", existing.display()),
                ..write.clone()
            },
            ScopedAllowRequest {
                read: false,
                write: false,
                delete: false,
                ..write.clone()
            },
        ];

        for request in cases {
            let status = preview_scoped_allow(&request, &call, false);
            let applied = validate_scoped_allow(&request, &call);
            assert_eq!(
                status.blocks_apply(),
                applied.is_err(),
                "preview and validation disagree on {:?}: {status:?} vs {applied:?}",
                request.directory
            );
            if let Err(error) = applied {
                assert_eq!(error, status.message());
            }
        }
    }

    /// A `*` in the directory used to be accepted and produced a session rule
    /// that `directory_scope_matches` could never fire on.
    #[test]
    fn glob_directory_is_refused_with_a_teaching_message() {
        let request = ScopedAllowRequest {
            directory: "/repo/src/**".to_string(),
            read: true,
            write: false,
            delete: false,
            persist: false,
        };
        let status = preview_scoped_allow(&request, "FileRead(/repo/src/lib.rs)", false);
        assert_eq!(status, ScopeStatus::Glob);
        assert!(status
            .message()
            .contains("already covers everything beneath"));
        assert!(validate_scoped_allow(&request, "FileRead(/repo/src/lib.rs)").is_err());
    }

    /// Containment alone is not enough: the ticked boxes have to include the
    /// reviewed call's own namespace or the applied rules cannot match it.
    #[test]
    fn applied_scope_always_matches_the_reviewed_call() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("build");
        std::fs::create_dir(&directory).unwrap();
        let target = directory.join("out.o");
        let call = format!("FileWrite({})", target.display());

        let read_only = read_request(&directory.to_string_lossy());
        let error = validate_scoped_allow(&read_only, &call).unwrap_err();
        assert!(
            error.contains("write/create"),
            "must name the missing operation: {error}"
        );

        let write = ScopedAllowRequest {
            read: false,
            write: true,
            ..read_only
        };
        let validated = validate_scoped_allow(&write, &call).unwrap();
        let resolved_target = resolve_target(&target.to_string_lossy()).unwrap();
        let resolved_target = resolved_target.to_string_lossy().replace('\\', "/");
        assert!(
            validated.rules.iter().any(|rule| {
                rule.strip_prefix("write-prefix:").is_some_and(|dir| {
                    let dir = dir.trim_end_matches('/');
                    resolved_target
                        .strip_prefix(dir)
                        .is_some_and(|rest| rest.starts_with('/'))
                })
            }),
            "no applied rule matches the reviewed call: {:?}",
            validated.rules
        );
    }

    /// The reviewed call is frozen; nothing else is. A `git worktree remove`
    /// sweeping the tree mid-review used to surface as `os error 2`.
    #[test]
    fn directory_removed_during_review_is_named_not_an_os_error() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("worktree");
        std::fs::create_dir(&directory).unwrap();
        let target = directory.join("todo.md");
        let call = format!("FileWrite({})", target.display());
        std::fs::remove_dir(&directory).unwrap();

        let request = ScopedAllowRequest {
            directory: directory.to_string_lossy().into_owned(),
            read: false,
            write: true,
            delete: false,
            persist: false,
        };
        let status = preview_scoped_allow(&request, &call, true);
        assert_eq!(status, ScopeStatus::RemovedWhileFrozen);
        assert!(!status.blocks_apply(), "the scope still applies");
        assert!(status
            .message()
            .contains("removed while this request was frozen"));

        // And Enter has to agree. A status line that says "applies" followed
        // by an Enter-time `os error 2` is the exact failure this rewrite
        // exists to remove, so the acceptance is asserted, not assumed.
        let validated = validate_scoped_allow(&request, &call)
            .expect("a directory that can be recreated must still be scopable");
        assert_eq!(
            validated.warning,
            Some(ScopeStatus::CoversPending.message()),
            "validation has no dialog history, so it uses the neutral wording"
        );
        assert!(validated
            .rules
            .iter()
            .any(|rule| rule.starts_with("write-prefix:")));

        // Without the dialog's memory the same state is just "not created yet".
        assert_eq!(
            preview_scoped_allow(&request, &call, false),
            ScopeStatus::CoversPending
        );
    }

    /// Overshooting a component while editing produced a not-found-shaped
    /// error on Enter. It is now a specific, live status.
    #[test]
    fn partial_component_reports_the_uncovered_target() {
        let request = read_request("/repo/src-partia");
        let status = preview_scoped_allow(&request, "FileRead(/repo/src/lib.rs)", false);
        assert_eq!(
            status,
            ScopeStatus::MissesTarget {
                target: "lib.rs".to_string()
            }
        );
        assert!(status.blocks_apply());
    }

    /// The editor greys its "wider" hint on this verdict, so the reason has
    /// to name the floor rather than just declaring the scope too broad.
    #[test]
    fn breadth_floor_names_the_directory_it_refuses() {
        let request = read_request("/a/");
        let status = preview_scoped_allow(&request, "FileRead(/a/b/c/d/file.txt)", false);
        let ScopeStatus::TooBroad { reason } = &status else {
            panic!("expected a breadth refusal, got {status:?}");
        };
        assert!(reason.contains("/a"), "must name the floor: {reason}");

        // Two components down is the shallowest scope the floor allows.
        assert!(!preview_scoped_allow(
            &read_request("/a/b/"),
            "FileRead(/a/b/c/d/file.txt)",
            false
        )
        .blocks_apply());
    }

    /// Next.js dynamic-route segments are directories literally named
    /// `[token]`, and the tree that produced this work item is full of them.
    /// Session rules are matched as literal prefixes, so a bracketed scope
    /// matches that directory and nothing else — refusing brackets would only
    /// take the escape hatch away on paths that already generate the most
    /// prompts, while granting no authority either way.
    #[test]
    fn bracketed_route_directory_stays_scopable() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("[token]");
        std::fs::create_dir(&directory).unwrap();
        let target = directory.join("route.ts");
        let call = format!("FileRead({})", target.display());
        let request = read_request(&directory.to_string_lossy());

        assert_eq!(
            preview_scoped_allow(&request, &call, false),
            ScopeStatus::Covers
        );
        let validated = validate_scoped_allow(&request, &call).unwrap();
        assert!(
            validated
                .rules
                .iter()
                .any(|rule| rule.starts_with("ro-prefix:") && rule.contains("[token]")),
            "the bracketed directory must survive into the rule: {:?}",
            validated.rules
        );

        // The wildcards that really cannot fire are still refused.
        let globbed = read_request(&format!("{}/*", directory.display()));
        assert_eq!(
            preview_scoped_allow(&globbed, &call, false),
            ScopeStatus::Glob
        );
    }

    /// Arm the deletion race: `directory` disappears between the next
    /// existence probe and the canonicalisation that follows it.
    fn arm_mid_review_deletion(directory: &Path) {
        VANISH_AT_CANONICALIZE.with(|slot| {
            *slot.borrow_mut() = Some(directory.to_path_buf());
        });
    }

    /// The race the work item names: the reviewed call is frozen, but a
    /// concurrent `git worktree remove` is not. The editor used to promise a
    /// scope ("removed while frozen — applies if it is recreated") and then
    /// refuse it on Enter with `Could not resolve path: … (os error 2)`,
    /// which is the "it can't find it" report this rewrite exists to answer.
    #[test]
    fn a_directory_deleted_between_probe_and_resolve_still_applies() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("worktree");
        let target = directory.join("todo.md");
        let call = format!("FileWrite({})", target.display());
        let request = ScopedAllowRequest {
            directory: directory.to_string_lossy().into_owned(),
            read: false,
            write: true,
            delete: false,
            persist: false,
        };

        std::fs::create_dir(&directory).unwrap();
        arm_mid_review_deletion(&directory);
        let status = preview_scoped_allow(&request, &call, true);
        assert_eq!(status, ScopeStatus::RemovedWhileFrozen);
        assert!(!status.blocks_apply(), "the preview promises the scope");

        std::fs::create_dir(&directory).unwrap();
        arm_mid_review_deletion(&directory);
        let validated = validate_scoped_allow(&request, &call)
            .expect("Enter must honour what the status line promised");
        assert!(validated
            .rules
            .iter()
            .any(|rule| rule.starts_with("write-prefix:")));
    }

    /// The namespace requirement exists to stop a reviewer building a scope
    /// that cannot match the call under review. It must never block the
    /// dialog's own safe default, or the escape hatch is unusable on every
    /// operation it is offered for.
    #[test]
    fn every_default_scope_covers_its_own_call() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("pkg");
        std::fs::create_dir(&directory).unwrap();
        let dir = directory.to_string_lossy().into_owned();
        let file = directory.join("lib.rs").to_string_lossy().into_owned();

        for call in [
            format!("FileRead({file})"),
            format!("DirList({dir})"),
            format!("FileWrite({file})"),
            format!("FileAppend({file})"),
            format!("DirCreate({file})"),
            format!("FileDelete({file})"),
            format!("FileRename({file} -> {dir}/other.rs)"),
        ] {
            let request = default_scoped_allow(&call).unwrap();
            let status = preview_scoped_allow(&request, &call, false);
            assert!(
                !status.blocks_apply(),
                "the default scope was refused for {call}: {status:?}"
            );
            assert!(validate_scoped_allow(&request, &call).is_ok());
        }
    }
}
