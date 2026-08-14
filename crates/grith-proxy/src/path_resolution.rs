// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Path resolution for the LLM execution path (go-live review B3).
//!
//! Filters match on path strings. Without resolution, `..` traversal and
//! symlinks launder a sensitive path past every one of them: a tool call
//! naming `/tmp/notes.txt` scores nothing even when that name resolves to
//! `~/.ssh/id_rsa`.
//!
//! The supervisor resolves in `classify.rs` against the *tracee's* cwd, since
//! that is the process whose view matters. On the LLM path the built-in agent
//! performs the operation itself, in this process — so resolving here is not
//! an approximation of the actor's view, it *is* the actor's view. It also
//! removes a TOCTOU window: the path that was scored is the path that is
//! then executed.
//!
//! Two variants, matching the kernel's own symlink semantics:
//! [`resolve_follow`] for operations that act on what a link points at, and
//! [`resolve_nofollow`] for operations that act on the link itself. Reporting
//! `rm /tmp/x` as a delete of `~/.ssh/id_rsa` because `/tmp/x` points there
//! would be both a false positive and a false audit record.

/// Paths whose resolution is pointless or actively misleading.
///
/// `/proc` holds magic symlinks whose targets are not filesystem paths
/// (`/proc/self/fd/3` → `socket:[12345]`); `/sys` and `/dev` are
/// pseudo-filesystems where the walk buys nothing.
fn skip_resolution(path: &str) -> bool {
    path.starts_with("/proc/") || path.starts_with("/sys/") || path.starts_with("/dev/")
}

/// Canonicalize the parent directory and re-append the final component.
fn resolve_parent_only(path: &str) -> String {
    let p = std::path::Path::new(path);
    match (p.parent(), p.file_name()) {
        (Some(parent), Some(name)) => match std::fs::canonicalize(parent) {
            Ok(dir) => dir.join(name).to_string_lossy().into_owned(),
            Err(_) => path.to_string(),
        },
        _ => path.to_string(),
    }
}

/// Resolve `..`, `.` and symlinks **including the final component**.
///
/// For a path that does not exist yet (writing a new file), the parent is
/// resolved instead so traversal and symlinked parent directories are still
/// collapsed. If nothing can be resolved the input is returned unchanged —
/// the pre-resolution behaviour — so this can never score *less* than before.
pub fn resolve_follow(path: &str) -> String {
    if skip_resolution(path) {
        return path.to_string();
    }
    match std::fs::canonicalize(path) {
        Ok(resolved) => resolved.to_string_lossy().into_owned(),
        Err(_) => resolve_parent_only(path),
    }
}

/// Resolve `..`, `.` and symlinks in the **parent directories only**.
///
/// For operations that act on the link itself rather than its target.
pub fn resolve_nofollow(path: &str) -> String {
    if skip_resolution(path) {
        return path.to_string();
    }
    resolve_parent_only(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn follow_resolves_a_symlink_to_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("id_rsa");
        fs::write(&secret, "key").unwrap();
        let link = dir.path().join("notes.txt");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let resolved = resolve_follow(link.to_str().unwrap());
        assert!(
            resolved.ends_with("id_rsa"),
            "expected the symlink to resolve to its target, got {resolved}"
        );
    }

    #[test]
    fn nofollow_keeps_the_link_itself() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("id_rsa");
        fs::write(&secret, "key").unwrap();
        let link = dir.path().join("notes.txt");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let resolved = resolve_nofollow(link.to_str().unwrap());
        assert!(
            resolved.ends_with("notes.txt"),
            "a delete/rename must report the link, not its target, got {resolved}"
        );
    }

    #[test]
    fn follow_collapses_parent_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let secret = dir.path().join("id_rsa");
        fs::write(&secret, "key").unwrap();

        let traversal = format!("{}/../id_rsa", sub.to_str().unwrap());
        let resolved = resolve_follow(&traversal);
        assert!(
            !resolved.contains(".."),
            "`..` must be collapsed: {resolved}"
        );
        assert!(resolved.ends_with("id_rsa"));
    }

    #[test]
    fn nonexistent_file_resolves_via_its_parent() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();

        // Writing a new file through a traversal: the file does not exist, so
        // only the parent can be resolved — but that is enough to collapse
        // the `..`.
        let target = format!("{}/../new.txt", sub.to_str().unwrap());
        let resolved = resolve_follow(&target);
        assert!(
            !resolved.contains(".."),
            "`..` must be collapsed: {resolved}"
        );
        assert!(resolved.ends_with("new.txt"));
    }

    #[test]
    fn unresolvable_path_is_returned_unchanged() {
        // Neither the file nor its parent exists: fall back to the input,
        // which is exactly the pre-B3 behaviour.
        let input = "/nonexistent-root-dir-xyz/deeper/file.txt";
        assert_eq!(resolve_follow(input), input);
    }

    #[test]
    fn proc_paths_are_left_alone() {
        assert_eq!(resolve_follow("/proc/self/environ"), "/proc/self/environ");
        assert_eq!(resolve_nofollow("/sys/kernel/x"), "/sys/kernel/x");
    }
}
