// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! work/83 F4 — workspace-wide project trust, end to end against real git.
//!
//! `${PROJECT_DIR}` expands to the launch cwd only, so in a multi-worktree
//! layout the sibling worktrees of the very repository being worked on get no
//! session trust: 24.9% of calls QUEUEd there against 0.32% under the launch
//! cwd over one measured morning. These tests drive the resolution path with
//! a real repository so the porcelain contract is checked against the git
//! that ships on the box, not against a fixture string.
//!
//! No ptrace, no supervisor loop — resolution is a pure session-start step.

use std::path::{Path, PathBuf};
use std::process::Command;

use grith_supervisor::profiles::{
    extend_allowlist_with_workspace_roots, resolve_workspace_roots, MAX_WORKSPACE_ROOTS,
};

/// Run a git command, returning false if git is unavailable or the command
/// failed. Environments without git skip the git-backed assertions rather
/// than failing — the operator-declared path is covered independently.
fn git(cwd: &Path, args: &[&str]) -> bool {
    Command::new("git")
        // Hermetic: a developer's global/system config (hooks, templates,
        // `worktree` defaults) must not decide whether this test passes.
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "grith test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "grith test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .args(args)
        .current_dir(cwd)
        .output()
        .is_ok_and(|out| out.status.success())
}

fn canonical(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|e| panic!("canonicalize {}: {e}", path.display()))
        .to_string_lossy()
        .into_owned()
}

/// The directory the repository sits in, relative to the fixture root. Git-
/// derived trust is constrained to the launch repository's own enclosing
/// directory, and that scope is refused outright when it is `$HOME` (or an
/// ancestor of it) — so a realistic fixture has to park the repository one
/// level below the stand-in home, exactly as `~/projects/<repo>` does.
const WORKSPACE: &str = "workspace";

/// Build `<tmp>/workspace/repo` with one commit and `<tmp>/workspace/wt` as a
/// linked worktree. Returns `None` when git is unavailable.
fn repo_with_linked_worktree(tmp: &Path) -> Option<(PathBuf, PathBuf)> {
    let workspace = tmp.join(WORKSPACE);
    let repo = workspace.join("repo");
    let worktree = workspace.join("wt");
    std::fs::create_dir_all(&repo).unwrap();
    if !git(&workspace, &["init", "-q", "repo"]) {
        return None;
    }
    if !git(&repo, &["commit", "-q", "--allow-empty", "-m", "init"]) {
        return None;
    }
    if !git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "feature",
            worktree.to_str().unwrap(),
        ],
    ) {
        return None;
    }
    Some((repo, worktree))
}

/// The core F4 claim: a linked worktree of the launch repository is resolved
/// as a trusted project root, and the launch cwd itself is not duplicated.
#[test]
fn linked_worktree_roots_are_trusted_at_session_start() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((repo, worktree)) = repo_with_linked_worktree(tmp.path()) else {
        eprintln!("git unavailable; skipping linked-worktree resolution");
        return;
    };
    let home = canonical(tmp.path());

    let roots = resolve_workspace_roots(&repo, &home, true, &[]);
    assert_eq!(
        roots,
        vec![canonical(&worktree)],
        "the linked worktree is trusted; the launch cwd is not re-added"
    );

    // The knob is honoured: with linked worktrees off, git is never consulted.
    assert!(resolve_workspace_roots(&repo, &home, false, &[]).is_empty());
}

/// A supervised tool must not be able to widen its own trust. Resolution is a
/// session-start snapshot, so a worktree created after the snapshot is not
/// trusted — the caller never re-runs this.
#[test]
fn worktrees_added_after_the_snapshot_are_not_trusted() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((repo, worktree)) = repo_with_linked_worktree(tmp.path()) else {
        eprintln!("git unavailable; skipping snapshot test");
        return;
    };
    let home = canonical(tmp.path());

    let snapshot = resolve_workspace_roots(&repo, &home, true, &[]);
    assert_eq!(snapshot, vec![canonical(&worktree)]);

    let late = tmp.path().join(WORKSPACE).join("late");
    assert!(git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "late",
            late.to_str().unwrap()
        ],
    ));
    assert!(
        !snapshot.contains(&canonical(&late)),
        "the session's trusted set is the start-time snapshot, never re-read"
    );
}

/// work/80's refusal applies to every workspace root, however it was derived:
/// a root at `$HOME` (or an ancestor of it, or `/`) grants trust over every
/// credential directory on the box and is dropped with a warning.
#[test]
fn workspace_roots_at_home_or_root_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let launch = tmp.path().join("launch");
    std::fs::create_dir_all(&launch).unwrap();

    // The tempdir itself standing in for `$HOME`.
    let home = canonical(tmp.path());
    let refused = resolve_workspace_roots(
        &launch,
        &home,
        false,
        &[
            home.clone(),          // == $HOME
            "/".to_string(),       // the filesystem root
            "${HOME}".to_string(), // the same, via expansion
            "~".to_string(),       // and via tilde
        ],
    );
    assert!(
        refused.is_empty(),
        "no dangerous root may be trusted, got {refused:?}"
    );

    // A git-derived root at `$HOME` is refused on the same rule: a repository
    // whose worktree IS the home directory hands over every credential store.
    if repo_with_linked_worktree(tmp.path()).is_some() {
        let repo = tmp.path().join(WORKSPACE).join("repo");
        let home_is_worktree = canonical(&tmp.path().join(WORKSPACE).join("wt"));
        let roots = resolve_workspace_roots(&repo, &home_is_worktree, true, &[]);
        assert!(
            !roots.contains(&home_is_worktree),
            "a worktree that IS the home directory must be refused"
        );
    }
}

/// Trust is bounded: an operator (or a repository with hundreds of linked
/// worktrees) cannot grow project trust into most of `$HOME` one root at a
/// time.
#[test]
fn workspace_root_count_is_capped() {
    let tmp = tempfile::tempdir().unwrap();
    let launch = tmp.path().join("launch");
    std::fs::create_dir_all(&launch).unwrap();
    let home = canonical(tmp.path());

    let mut declared = Vec::new();
    for i in 0..(MAX_WORKSPACE_ROOTS + 8) {
        let root = tmp.path().join(format!("root{i}"));
        std::fs::create_dir_all(&root).unwrap();
        declared.push(root.to_string_lossy().into_owned());
    }

    let roots = resolve_workspace_roots(&launch, &home, false, &declared);
    assert_eq!(roots.len(), MAX_WORKSPACE_ROOTS);
}

/// Every workspace root enters the session allowlist the same way the launch
/// tree does — as a prefix carrying the inert `projdir:` twin — so work/80's
/// credential-store guard applies to it. This test pins the marker; the guard
/// itself is exercised in `event_handler`'s unit tests.
#[test]
fn workspace_roots_carry_the_project_derived_marker() {
    let tmp = tempfile::tempdir().unwrap();
    let launch = tmp.path().join("launch");
    let sibling = tmp.path().join("sibling");
    std::fs::create_dir_all(&launch).unwrap();
    std::fs::create_dir_all(&sibling).unwrap();
    let home = canonical(tmp.path());

    let roots = resolve_workspace_roots(
        &launch,
        &home,
        false,
        &[sibling.to_string_lossy().into_owned()],
    );
    assert_eq!(roots, vec![canonical(&sibling)]);

    let mut allowed = std::collections::HashSet::new();
    extend_allowlist_with_workspace_roots(&mut allowed, &roots);
    let prefix = format!("{}/", canonical(&sibling));
    assert!(allowed.contains(&prefix));
    assert!(
        allowed.contains(&format!("projdir:{prefix}")),
        "a workspace root must be marked project-derived, never literal trust"
    );
}

/// `git worktree list` reports the MAIN worktree, not only the linked ones,
/// so a session launched from a subdirectory trusts the repository root.
/// That is the larger half of the false-positive win (a tool working in
/// `repo/frontend/` prompts today on every read of `../package.json`) and it
/// is a real widening beyond "linked worktrees", so it is pinned here rather
/// than left as an emergent property of the porcelain format.
#[test]
fn launching_from_a_subdirectory_trusts_the_repository_root() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((repo, worktree)) = repo_with_linked_worktree(tmp.path()) else {
        eprintln!("git unavailable; skipping subdirectory launch test");
        return;
    };
    let home = canonical(tmp.path());
    let subdir = repo.join("frontend/src");
    std::fs::create_dir_all(&subdir).unwrap();

    let roots = resolve_workspace_roots(&subdir, &home, true, &[]);
    assert!(
        roots.contains(&canonical(&repo)),
        "the repository root must be trusted when launching from a subdirectory, got {roots:?}"
    );
    assert!(roots.contains(&canonical(&worktree)));
    assert!(
        !roots.contains(&canonical(&subdir)),
        "the launch cwd is already trusted via ${{PROJECT_DIR}} and must not be duplicated"
    );
}

/// Operator-declared roots are resolved before the git enumeration, so the
/// `MAX_WORKSPACE_ROOTS` cap can never silently drop an explicit declaration
/// in favour of an enumerated one. `additional_project_roots` exists for the
/// layout git cannot infer; losing it is the failure an operator could not
/// diagnose.
#[test]
fn declared_roots_are_ordered_ahead_of_git_derived_ones() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((repo, _worktree)) = repo_with_linked_worktree(tmp.path()) else {
        eprintln!("git unavailable; skipping ordering test");
        return;
    };
    let home = canonical(tmp.path());
    let declared = tmp.path().join("other-repo-worktree");
    std::fs::create_dir_all(&declared).unwrap();

    let roots = resolve_workspace_roots(
        &repo,
        &home,
        true,
        &[declared.to_string_lossy().into_owned()],
    );
    assert_eq!(
        roots.first(),
        Some(&canonical(&declared)),
        "an explicitly declared root must be first in line for the cap, got {roots:?}"
    );
    assert!(roots.len() > 1, "git-derived roots still follow: {roots:?}");
}

// ---------------------------------------------------------------------------
// Forged worktree metadata (adversarial review, 2026-08-20)
// ---------------------------------------------------------------------------

/// Forge `<repo>/.git/worktrees/<name>/gitdir` pointing at `<victim>/.git`.
///
/// Three ordinary writes, all INSIDE the launch tree, which project trust
/// already covers — no prompt, no proxy evaluation. This is exactly what a
/// supervised tool does to nominate an arbitrary directory as a "worktree".
fn forge_worktree_record(repo: &Path, name: &str, victim: &Path) {
    let admin = repo.join(format!(".git/worktrees/{name}"));
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::write(admin.join("gitdir"), format!("{}/.git\n", victim.display())).unwrap();
    std::fs::write(admin.join("HEAD"), "ref: refs/heads/master\n").unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
}

/// `git worktree list --porcelain` is derived from files the supervised tool
/// can write without a prompt, so it is attacker-influenced input rather than
/// testimony. Three plain writes used to mint a project-trusted prefix over
/// any absolute path on the box — personal data (`~/Documents`), a browser
/// profile, a password store — and everything beneath it that is not a
/// credential store was then auto-allowed and stopped escalating under
/// `mass_destruction::is_valuable_out_of_tree`.
///
/// Making the forged record non-prunable (by also writing `<victim>/.git`,
/// itself a 0.5-scored write) defeats a prunable-only filter, so the refusal
/// cannot rest on git's own opinion of the record. Both shapes are pinned.
#[test]
fn forged_worktree_metadata_cannot_mint_a_trusted_root() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((repo, legit)) = repo_with_linked_worktree(tmp.path()) else {
        eprintln!("git unavailable; skipping forged-metadata test");
        return;
    };
    let home = canonical(tmp.path());
    let workspace = tmp.path().join(WORKSPACE);

    // Personal data outside the repository's enclosing directory.
    let documents = tmp.path().join("Documents");
    std::fs::create_dir_all(documents.join("private")).unwrap();
    // An existing sibling REPOSITORY inside it — the juicy target, because a
    // checkout is where `.env` files and deploy keys actually live.
    let sibling = workspace.join("other-app");
    std::fs::create_dir_all(&sibling).unwrap();
    assert!(git(&workspace, &["init", "-q", "other-app"]));
    std::fs::write(sibling.join(".env"), "TOKEN=real").unwrap();

    let baseline = resolve_workspace_roots(&repo, &home, true, &[]);
    assert_eq!(
        baseline,
        vec![canonical(&legit)],
        "before the forgery only the genuine worktree is trusted"
    );

    forge_worktree_record(&repo, "docs", &documents);
    forge_worktree_record(&repo, "sib", &sibling);
    // Escalate both records past a prunable-only filter.
    std::fs::write(documents.join(".git"), "gitdir: /nonexistent\n").unwrap();
    // (the sibling's `.git` is a DIRECTORY; a plain write cannot replace it,
    //  which is the point of the back-pointer check)

    let after = resolve_workspace_roots(&repo, &home, true, &[]);
    for minted in [&documents, &sibling] {
        assert!(
            !after.contains(&canonical(minted)),
            "forged worktree metadata must not mint trust over {}, got {after:?}",
            minted.display()
        );
    }
    assert_eq!(
        after, baseline,
        "the genuine worktree stays trusted — the refusal must not cost the \
         false-positive win F4 exists for"
    );

    // And the allowlist that would have been built from it is unchanged.
    let mut allowed = std::collections::HashSet::new();
    extend_allowlist_with_workspace_roots(&mut allowed, &after);
    assert!(!allowed
        .iter()
        .any(|entry| entry.contains("Documents") || entry.contains("other-app")));
}

/// A repository checked out directly into the home directory would make
/// "inside the repository's enclosing directory" mean "anywhere under
/// `$HOME`", which is the whole reachable set the scope constraint exists to
/// remove. Such a layout gets no linked-worktree trust at all — the launch
/// cwd keeps its own `${PROJECT_DIR}` trust, and an operator who needs more
/// declares `additional_project_roots`.
#[test]
fn a_repository_directly_in_home_gets_no_linked_worktree_trust() {
    let tmp = tempfile::tempdir().unwrap();
    let home = canonical(tmp.path());
    let repo = tmp.path().join("flatrepo");
    std::fs::create_dir_all(&repo).unwrap();
    if !git(tmp.path(), &["init", "-q", "flatrepo"])
        || !git(&repo, &["commit", "-q", "--allow-empty", "-m", "init"])
    {
        eprintln!("git unavailable; skipping home-scope test");
        return;
    }
    let worktree = tmp.path().join("flat-wt");
    assert!(git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "feature",
            worktree.to_str().unwrap()
        ],
    ));

    assert!(
        resolve_workspace_roots(&repo, &home, true, &[]).is_empty(),
        "a repository whose enclosing directory is $HOME grants no git-derived trust"
    );
}

/// The refusal list is wider than `is_credential_store_path` because the
/// prefix it guards auto-allows everything beneath it: a browser profile, a
/// password store, the keyring directory and the XDG dot-trees that hold
/// autostart entries and user-installed binaries are all persistence
/// primitives, not project-tree conveniences. It applies to operator-declared
/// roots too — that key is a hand-written path, and a project-local
/// `.grith/config.toml` is itself inside the tree the tool can write.
#[test]
fn credential_and_personal_data_directories_are_refused_however_declared() {
    let tmp = tempfile::tempdir().unwrap();
    let launch = tmp.path().join("workspace/launch");
    std::fs::create_dir_all(&launch).unwrap();
    let home = canonical(tmp.path());

    let mut declared = Vec::new();
    for relative in [
        ".mozilla/firefox/abc.default",
        ".password-store",
        ".local/share/keyrings",
        ".config/autostart",
        ".ssh",
        ".aws",
        ".gnupg",
    ] {
        let path = tmp.path().join(relative);
        std::fs::create_dir_all(&path).unwrap();
        declared.push(path.to_string_lossy().into_owned());
    }

    let roots = resolve_workspace_roots(&launch, &home, false, &declared);
    assert!(
        roots.is_empty(),
        "no credential or personal-data directory may become a project root, got {roots:?}"
    );

    // A neighbouring ordinary project directory is still declarable — the
    // refusal must not swallow the operator escape hatch.
    let other = tmp.path().join("workspace/other-repo-worktree");
    std::fs::create_dir_all(&other).unwrap();
    assert_eq!(
        resolve_workspace_roots(
            &launch,
            &home,
            false,
            &[other.to_string_lossy().into_owned()]
        ),
        vec![canonical(&other)]
    );
}
