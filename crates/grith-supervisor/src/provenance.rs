// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Executable provenance verification for process-spawn trust decisions.
//!
//! This module determines whether a binary at a given path is trusted for
//! auto-allow in the session allowlist. Trust is based on:
//!
//! 1. The canonical (symlink-resolved) path falls under a trusted exec root.
//! 2. The executable and its parent directory chain pass ownership and
//!    permission checks (no world-writable components).
//!
//! # Security model
//!
//! - Trust exact executables or vetted executable roots, not bare basenames.
//! - Canonicalize the executable path before trust decisions.
//! - Refuse trust for binaries in unsafe or user-untrusted writable locations.
//! - Keep process-spawn trust separate from filesystem path trust.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::libc;

/// Result of verifying whether an executable is trusted.
#[derive(Debug, Clone)]
pub struct ExecTrustDecision {
    /// Whether the executable is trusted for auto-allow.
    pub trusted: bool,
    /// The canonical (symlink-resolved) path, if resolution succeeded.
    pub canonical_path: Option<String>,
    /// Human-readable reason for the decision.
    pub reason: String,
}

fn canonicalize_exec_path(raw_path: &str) -> Result<PathBuf, ExecTrustDecision> {
    match std::fs::canonicalize(raw_path) {
        Ok(p) => Ok(p),
        Err(_) => Err(ExecTrustDecision {
            trusted: false,
            canonical_path: None,
            reason: format!("canonicalization failed for '{raw_path}'"),
        }),
    }
}

/// Verify whether an executable path is trusted for auto-allow based on exact
/// executable identity plus provenance (canonical path, ownership, permissions).
pub fn verify_exact_exec_provenance(raw_path: &str, trusted_execs: &[String]) -> ExecTrustDecision {
    let canonical = match canonicalize_exec_path(raw_path) {
        Ok(p) => p,
        Err(decision) => return decision,
    };
    let canonical_str = canonical.to_string_lossy().into_owned();

    if !trusted_execs.iter().any(|exec| exec == &canonical_str) {
        return ExecTrustDecision {
            trusted: false,
            canonical_path: Some(canonical_str),
            reason: "canonical path does not match any trusted exact executable".into(),
        };
    }

    match verify_path_safety(&canonical) {
        Ok(()) => ExecTrustDecision {
            trusted: true,
            canonical_path: Some(canonical_str),
            reason: "trusted exact executable".into(),
        },
        Err(reason) => ExecTrustDecision {
            trusted: false,
            canonical_path: Some(canonical_str),
            reason,
        },
    }
}

/// Verify whether an executable path is trusted for auto-allow based on a
/// trusted root plus provenance (canonical path, ownership, permissions).
pub fn verify_exec_provenance(raw_path: &str, trusted_roots: &[String]) -> ExecTrustDecision {
    let canonical = match canonicalize_exec_path(raw_path) {
        Ok(p) => p,
        Err(decision) => return decision,
    };
    let canonical_str = canonical.to_string_lossy().into_owned();

    let matched_root = trusted_roots
        .iter()
        .find(|root| is_under_root(&canonical_str, root));

    let root = match matched_root {
        Some(r) => r.clone(),
        None => {
            return ExecTrustDecision {
                trusted: false,
                canonical_path: Some(canonical_str),
                reason: "not under any trusted exec root".into(),
            };
        }
    };

    // Step 3: Verify ownership and permissions on the path chain from the
    // trusted root down to the binary.
    match verify_path_safety(&canonical) {
        Ok(()) => ExecTrustDecision {
            trusted: true,
            canonical_path: Some(canonical_str),
            reason: format!("trusted exec root '{root}'"),
        },
        Err(reason) => ExecTrustDecision {
            trusted: false,
            canonical_path: Some(canonical_str),
            reason,
        },
    }
}

/// Check if a canonical path falls under a trusted root directory.
fn is_under_root(path: &str, root: &str) -> bool {
    // Ensure root ends with '/' for proper prefix matching.
    let root_normalized = if root.ends_with('/') {
        root.to_string()
    } else {
        format!("{root}/")
    };
    path.starts_with(&root_normalized)
}

/// Verify that the executable and its parent directories are safely owned.
///
/// For each component from the filesystem root to the binary:
/// - Owner must be root (uid 0) or the current effective user.
/// - Must not be world-writable (mode & 0o002 == 0).
/// - Root-owned components must also not be group-writable (mode & 0o020 == 0),
///   since group members could inject binaries.
/// - User-owned components allow group-writable (common for nvm, Claude, etc.).
///
/// This prevents attacks where another user places a malicious binary in a
/// world-writable directory under a trusted root, while still accepting the
/// common 0o775 permissions that user-space package managers create.
fn verify_path_safety(path: &Path) -> std::result::Result<(), String> {
    let euid = unsafe { libc::geteuid() };

    // Walk each component of the path from root to the binary.
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);

        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(m) => m,
            Err(e) => {
                return Err(format!("cannot stat '{}': {e}", current.display()));
            }
        };

        let owner = metadata.uid();
        let mode = metadata.mode();

        // Owner must be root or the current user.
        if owner != 0 && owner != euid {
            return Err(format!(
                "'{}' owned by uid {owner}, expected root or uid {euid}",
                current.display()
            ));
        }

        // Must not be world-writable (other-write bit).
        if mode & 0o002 != 0 {
            return Err(format!(
                "'{}' is world-writable (mode {mode:#o})",
                current.display()
            ));
        }

        // Root-owned components must also not be group-writable, since any
        // group member could plant a binary. User-owned components are fine
        // with 0o775 — common for nvm, mise, Claude bundled tools, etc.
        if owner == 0 && mode & 0o020 != 0 {
            return Err(format!(
                "'{}' is root-owned and group-writable (mode {mode:#o})",
                current.display()
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_under_root_exact_prefix() {
        assert!(is_under_root(
            "/usr/lib/git-core/git-remote-http",
            "/usr/lib/git-core/"
        ));
    }

    #[test]
    fn is_under_root_without_trailing_slash() {
        assert!(is_under_root(
            "/usr/lib/git-core/git-remote-http",
            "/usr/lib/git-core"
        ));
    }

    #[test]
    fn is_under_root_not_matching() {
        assert!(!is_under_root("/usr/bin/git", "/usr/lib/git-core/"));
    }

    #[test]
    fn is_under_root_partial_name_no_match() {
        // "/usr/lib/git-core-extra/foo" should NOT match "/usr/lib/git-core/"
        assert!(!is_under_root(
            "/usr/lib/git-core-extra/foo",
            "/usr/lib/git-core/"
        ));
    }

    #[test]
    fn verify_system_binary_safety() {
        // /usr/bin/ls should pass safety checks on any reasonable system.
        let path = Path::new("/usr/bin/ls");
        if path.exists() {
            assert!(verify_path_safety(path).is_ok());
        }
    }

    #[test]
    fn verify_provenance_nonexistent() {
        let decision =
            verify_exec_provenance("/nonexistent/binary", &["/usr/lib/git-core/".into()]);
        assert!(!decision.trusted);
        assert!(decision.reason.contains("canonicalization failed"));
    }

    #[test]
    fn verify_provenance_not_under_root() {
        let decision = verify_exec_provenance("/usr/bin/ls", &["/usr/lib/git-core/".into()]);
        assert!(!decision.trusted);
        assert!(decision.reason.contains("not under any trusted exec root"));
    }

    #[test]
    fn verify_provenance_under_trusted_root() {
        // Test with a real binary under /usr/lib/git-core/ if it exists.
        let git_remote = "/usr/lib/git-core/git-remote-http";
        if Path::new(git_remote).exists() {
            let decision = verify_exec_provenance(git_remote, &["/usr/lib/git-core/".into()]);
            assert!(
                decision.trusted,
                "expected trusted, got: {}",
                decision.reason
            );
            assert!(decision.canonical_path.is_some());
        }
    }

    #[test]
    fn basename_alone_does_not_match() {
        // A relative path like "git" should not be trusted.
        let decision = verify_exec_provenance("git", &["/usr/lib/git-core/".into()]);
        // Either canonicalization fails or it doesn't match the root.
        assert!(!decision.trusted);
    }

    #[test]
    fn tmp_world_writable_rejected() {
        // /tmp is world-writable — a binary there should not be trusted.
        let decision = verify_exec_provenance("/tmp/fake-git", &["/tmp/".into()]);
        // Either the file doesn't exist (canonicalization fails) or
        // /tmp is world-writable.
        assert!(!decision.trusted);
    }

    #[test]
    fn verify_exact_exec_requires_canonical_match() {
        let decision =
            verify_exact_exec_provenance("/usr/bin/ls", &["/usr/bin/definitely-not-ls".into()]);
        assert!(!decision.trusted);
        assert!(decision.reason.contains("does not match"));
    }

    #[test]
    fn verify_exact_exec_trusts_safe_system_binary() {
        let path = "/usr/bin/ls";
        if Path::new(path).exists() {
            let decision = verify_exact_exec_provenance(path, &[path.into()]);
            assert!(
                decision.trusted,
                "expected trusted, got: {}",
                decision.reason
            );
        }
    }

    #[test]
    fn user_owned_group_writable_accepted() {
        // User-owned directories with 0o775 (group-writable) are common for
        // nvm, mise, Claude-bundled tools, etc. They should pass verification
        // because the user controls the content. Only root-owned group-writable
        // or world-writable directories are rejected.
        //
        // We place the test dir under $HOME to avoid /tmp (world-writable).
        use std::os::unix::fs::PermissionsExt;

        let home = std::env::var("HOME").unwrap();
        let dir = PathBuf::from(home).join(".cache/grith-provenance-test-775");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();

        // Create a dummy "binary" inside it
        let bin = dir.join("test-bin");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let result = verify_path_safety(&bin);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            result.is_ok(),
            "user-owned 0o775 dir should pass, got: {}",
            result.unwrap_err()
        );
    }

    #[test]
    fn world_writable_component_rejected() {
        // Even a user-owned directory must not be world-writable (0o777).
        use std::os::unix::fs::PermissionsExt;

        let home = std::env::var("HOME").unwrap();
        let dir = PathBuf::from(home).join(".cache/grith-provenance-test-777");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        let bin = dir.join("test-bin");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let result = verify_path_safety(&bin);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(result.is_err(), "world-writable dir should fail");
    }
}
