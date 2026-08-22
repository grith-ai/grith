// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! work/85 — the workspace-only filesystem boundary.
//!
//! `[supervisor.trust] restrict_to_workspace` (or `grith exec
//! --workspace-only`) turns the session's project trust into a wall: file
//! operations outside the workspace are denied instead of being scored, and a
//! read that today rides through on `ignore_read_only` no longer does.
//!
//! **The boundary is subtractive only.** Every exemption below means "the
//! boundary does not decide this call", never "allow it" — the call still
//! goes through the whole proxy pipeline afterwards. `/etc/shadow` is exempt
//! here (it is under `/etc`, a system read root) and is still denied at 8.0
//! by the secret-scanning filters. A mode that could *grant* would be a new
//! authority path; this one can only take authority away.

/// The set of trees a workspace-only session may touch.
///
/// Built once at session start from the launch cwd plus work/83 F4's
/// `workspace_roots` — which already covers every linked git worktree of the
/// launch repository and any operator-declared `additional_project_roots` —
/// and never recomputed, for the same reason those roots are not: a
/// mid-session re-read would let the supervised tool widen its own boundary
/// with one `git worktree add`.
#[derive(Debug, Clone, Default)]
pub struct WorkspaceBoundary {
    /// Canonical roots, each stored with exactly one trailing separator so
    /// prefix matching cannot cross a directory boundary
    /// (`…/api` must not match `…/api-secrets`).
    roots: Vec<String>,
}

impl WorkspaceBoundary {
    /// Build a boundary from raw root paths. Empty entries are dropped.
    #[must_use]
    pub fn new<I: IntoIterator<Item = String>>(roots: I) -> Self {
        let mut normalised: Vec<String> = Vec::new();
        for root in roots {
            let trimmed = root.trim_end_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            let with_slash = format!("{trimmed}/");
            if !normalised.contains(&with_slash) {
                normalised.push(with_slash);
            }
        }
        Self { roots: normalised }
    }

    /// Whether the boundary has any root at all.
    ///
    /// An empty boundary is inert: it is what a workspace-only session gets
    /// when the launch directory could not be resolved, and denying every
    /// file operation in that case would be a hostile way to report a failed
    /// `getcwd`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The roots, in declaration order, for logging and the session_start line.
    #[must_use]
    pub fn roots(&self) -> &[String] {
        &self.roots
    }

    /// Whether `path` is the workspace or lies inside it.
    #[must_use]
    pub fn contains(&self, path: &str) -> bool {
        let path = path.replace('\\', "/");
        self.roots.iter().any(|root| {
            let bare = root.trim_end_matches('/');
            path == bare || path.starts_with(root.as_str())
        })
    }
}

/// Read-only system roots a supervised tool cannot run without.
///
/// A tool that cannot read `/lib/x86_64-linux-gnu/libc.so.6` does not start,
/// so a boundary that blocked these would not be a security mode, it would be
/// an elaborate way to refuse to run. Exempting them costs nothing the mode
/// is defending against: these trees hold program and runtime data, and the
/// user data an operator switches this mode on to protect — other projects,
/// `$HOME`, mounted media — is not in them.
///
/// Exempt for **reads only**. A write into `/usr` from a supervised AI tool
/// is exactly the kind of out-of-workspace mutation the mode exists to stop.
const SYSTEM_READ_ROOTS: &[&str] = &[
    "/usr/",
    "/lib/",
    "/lib64/",
    "/lib32/",
    "/bin/",
    "/sbin/",
    "/opt/",
    "/etc/",
    "/var/lib/",
    "/var/cache/",
    "/nix/store/",
    "/snap/",
    // Resolver configuration written at runtime. `/etc/resolv.conf` is a
    // SYMLINK into one of these on every systemd-resolved, resolvconf or
    // NetworkManager host — which is to say on most modern Linux — and the
    // resolver opens the link target, not the link. A boundary that stops at
    // `/etc` therefore denies every DNS lookup the session makes, and the
    // supervised tool fails with connection timeouts rather than anything
    // that names the cause. Measured: 75 denied reads of
    // `/run/systemd/resolve/stub-resolv.conf` in one Claude Code session on
    // Ubuntu 24.04, which could not reach its API at all.
    //
    // Deliberately NOT all of `/run`: `/run/user/<uid>` holds the keyring,
    // gnupg and ssh-agent sockets, which are exactly what this mode exists
    // to keep out of reach.
    "/run/systemd/resolve/",
    "/run/resolvconf/",
    "/run/NetworkManager/",
    "/run/nscd/",
];

/// Whether a read of `path` is exempt as system runtime data.
#[must_use]
pub fn is_system_read_root(path: &str) -> bool {
    let path = path.replace('\\', "/");
    SYSTEM_READ_ROOTS
        .iter()
        .any(|root| path.starts_with(root) || path == root.trim_end_matches('/'))
}

/// Whether this call type reads rather than mutates.
///
/// `FileRename` counts as a mutation even though it removes from one
/// directory: the interesting half is the destination, and a rename that
/// leaves the workspace is an exfiltration path, not a read.
#[must_use]
pub fn is_read_like(call_type: &grith_proxy::types::ToolCallType) -> bool {
    use grith_proxy::types::ToolCallType;
    matches!(
        call_type,
        ToolCallType::FileRead { .. } | ToolCallType::DirList { .. }
    )
}

/// Every filesystem path a workspace-only decision has to consider for this
/// call, or `None` when the call is not a file operation the mode governs.
///
/// `FileRename` yields both paths: a rename whose destination is outside the
/// workspace moves data out of it just as surely as a copy, and checking only
/// the source would leave that open.
#[must_use]
pub fn governed_paths(call_type: &grith_proxy::types::ToolCallType) -> Option<Vec<&str>> {
    use grith_proxy::types::ToolCallType;
    match call_type {
        ToolCallType::FileRead { path }
        | ToolCallType::DirList { path }
        | ToolCallType::FileWrite { path, .. }
        | ToolCallType::FileAppend { path }
        | ToolCallType::DirCreate { path }
        | ToolCallType::FileDelete { path } => Some(vec![path.as_str()]),
        ToolCallType::FileRename { old_path, new_path } => {
            Some(vec![old_path.as_str(), new_path.as_str()])
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grith_proxy::types::ToolCallType;

    fn boundary() -> WorkspaceBoundary {
        WorkspaceBoundary::new(vec![
            "/home/dev/proj".to_string(),
            "/home/dev/worktrees/feature/".to_string(),
        ])
    }

    #[test]
    fn roots_are_boundary_safe() {
        let boundary = boundary();
        assert!(boundary.contains("/home/dev/proj"));
        assert!(boundary.contains("/home/dev/proj/src/main.rs"));
        assert!(boundary.contains("/home/dev/worktrees/feature/Cargo.toml"));
        // The sibling that merely shares a prefix is outside.
        assert!(!boundary.contains("/home/dev/proj-secrets/.env"));
        assert!(!boundary.contains("/home/dev/other/src/main.rs"));
        assert!(!boundary.contains("/home/dev/.ssh/id_ed25519"));
    }

    #[test]
    fn empty_boundary_is_inert() {
        assert!(WorkspaceBoundary::new(Vec::new()).is_empty());
        assert!(WorkspaceBoundary::new(vec![String::new(), "/".to_string()]).is_empty());
    }

    #[test]
    fn system_read_roots_cover_the_runtime_but_not_user_data() {
        assert!(is_system_read_root("/usr/lib/node_modules/npm/index.js"));
        assert!(is_system_read_root("/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(is_system_read_root("/etc/passwd"));
        assert!(!is_system_read_root("/home/dev/other/.env"));
        assert!(!is_system_read_root("/tmp/staged-secrets"));
        assert!(!is_system_read_root("/mnt/backup/keys"));
        // A sibling of a root, not the root itself.
        assert!(!is_system_read_root("/usr-local/lib/thing"));
    }

    #[test]
    fn resolver_runtime_config_is_readable_but_the_rest_of_run_is_not() {
        // The regression this pins: `/etc/resolv.conf` symlinks into
        // `/run/systemd/resolve/` on Ubuntu, the resolver opens the target,
        // and denying it takes DNS out for the whole session.
        assert!(is_system_read_root("/run/systemd/resolve/stub-resolv.conf"));
        assert!(is_system_read_root("/run/systemd/resolve/resolv.conf"));
        assert!(is_system_read_root("/run/resolvconf/resolv.conf"));
        assert!(is_system_read_root("/run/NetworkManager/resolv.conf"));

        // The rest of /run stays outside: this is where the keyring, gnupg
        // and ssh-agent sockets live.
        assert!(!is_system_read_root("/run/user/1000/keyring/ssh"));
        assert!(!is_system_read_root("/run/user/1000/bus"));
        assert!(!is_system_read_root("/run/secrets/api-key"));
        assert!(!is_system_read_root("/run/"));
    }

    #[test]
    fn rename_reports_both_ends() {
        let call = ToolCallType::FileRename {
            old_path: "/home/dev/proj/secret".to_string(),
            new_path: "/home/dev/exfil/secret".to_string(),
        };
        assert_eq!(
            governed_paths(&call),
            Some(vec!["/home/dev/proj/secret", "/home/dev/exfil/secret"])
        );
        assert!(!is_read_like(&call));
    }

    #[test]
    fn non_file_calls_are_not_governed() {
        assert!(governed_paths(&ToolCallType::ProcessSpawn {
            command: "curl".to_string(),
            args: Vec::new(),
        })
        .is_none());
    }
}
