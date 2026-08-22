// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Shared path-**name** classifiers used by the name-derived filters.
//!
//! Everything in this module answers a question about what a path is *called*,
//! never about what an operation *does*. That distinction is the whole design:
//! a filename is chosen by whoever created the file — an npm package, a
//! compiler's incremental hash, a documentation author — so it carries no
//! authority on its own. The predicates here exist to stop the weakest,
//! name-derived signals from deciding an outcome, and they are deliberately
//! NOT consulted by the content-derived (`secret_scan`, `dlp_gate`),
//! flow-derived (`taint`), egress (`egress_policy`, `egress_rate`),
//! destruction (`destructive_action`) or volume (`rate_limit`) filters. A
//! malicious dependency is still caught by what it *does*.
//!
//! work/83 (M1/M7/M8): the previous substring-keyword rule produced 831 of one
//! morning's 1,986 supervisor prompts — random rustc incremental hashes ending
//! in `auth`, documentation named `canary-tokens.mdx`, and two accessibility
//! npm packages that ship a `lib/etc/` directory.

/// Path components that mark a **vendored dependency tree** — a directory a
/// package manager, build tool or language runtime populates with third-party
/// or generated content.
///
/// Component-EXACT (never a substring): `/proj/vendors/x` and `/proj/mytarget/y`
/// are ordinary project directories and must keep every rule.
const DEPENDENCY_TREE_COMPONENTS: &[&str] = &[
    "node_modules",     // npm / yarn
    ".pnpm",            // pnpm's content-addressed store
    "bower_components", // legacy bower
    "vendor",           // Go modules / PHP composer / bundler
    ".venv",            // python virtualenv (conventional)
    "venv",             // python virtualenv (bare)
    "site-packages",    // python installed packages
    "Pods",             // CocoaPods
    ".gradle",          // gradle caches
];

// Deliberately NOT in the list above, and why:
//
// * `gems` — an ordinary directory name. `/p/gems/token.txt` is a project
//   directory, not rubygems. Bundler's vendored tree already matches through
//   its `vendor/` component, and a `.rb` under a system gem root is carved by
//   the source-extension rule one layer up. `~/.gem/credentials` holds the
//   RubyGems API key and must keep every rule, which is the other half of why
//   no `gem`-shaped component is safe to blanket-carve.
// * `target` — likewise an ordinary word. Handled by
//   [`target_component_is_build_output`], which requires corroboration that
//   this really is a cargo/maven output directory.

/// Adjacent component PAIRS that mark a dependency tree. Kept separate from
/// [`DEPENDENCY_TREE_COMPONENTS`] because neither half is safe alone —
/// `~/.cargo/config.toml` and `~/.m2/settings.xml` hold registry credentials
/// and must keep their rules; only the package caches beneath them are vendored.
const DEPENDENCY_TREE_COMPONENT_PAIRS: &[(&str, &str)] =
    &[(".cargo", "registry"), (".m2", "repository")];

/// Components that mark GENERATED BUILD OUTPUT.
///
/// Same argument as a vendored dependency tree, from the other end: these paths
/// are *emitted* by a build tool, so their names are copies of source names and
/// carry no authority of their own. The case that forced this list: a
/// documentation site whose pages are ABOUT secrets exports to `out/docs/` and
/// `.next/server/app/docs/`, and every generated `canary-tokens.html`,
/// `07-secret-credential-scanning.txt` and matching `mkdir` prompted — 85 of the
/// 105 prompts that survived the rest of work/83.
///
/// `dist`, `build` and `out` are ordinary English words and could name a
/// hand-written directory. That is acceptable *only* because this predicate now
/// gates weak NAME rules alone: `.env`, `*.pem`, `*.key`, `credential-directory`
/// and `os-secret-store` keep firing inside a generated tree, as does every
/// content, flow, egress and destruction filter.
const GENERATED_OUTPUT_COMPONENTS: &[&str] = &[
    ".next",         // Next.js
    ".nuxt",         // Nuxt
    ".svelte-kit",   // SvelteKit
    ".astro",        // Astro
    ".docusaurus",   // Docusaurus
    ".turbo",        // Turborepo
    ".vercel",       // Vercel build output
    ".output",       // Nitro
    ".parcel-cache", // Parcel
    ".angular",      // Angular CLI cache
    "dist",          // near-universal bundler output
    "build",         // CMake / setuptools / CRA
    "out",           // Next.js static export, tsc outDir
];

/// Filenames whose *tokens* mark them as plausibly credential-bearing.
///
/// Whole-token matches only. The previous `contains` form matched `authority`,
/// `authorize`, `AUTHORS` and every random base36 hash ending in `auth`.
const SENSITIVE_NAME_TOKENS: &[&str] = &[
    "secret",
    "secrets",
    "credential",
    "credentials",
    "token",
    "tokens",
    "passwd",
    "apikey",
    // `auth` alone is the highest-FP token of the set, but it is also the exact
    // basename of Composer's `auth.json` credential store, so it stays — the
    // artifact/source-extension carveouts below are what keep `auth.md`,
    // `auth.ts` and `auth.svg` out.
    "auth",
];

/// True when any `/`-separated component of `path` marks a vendored dependency
/// tree (see [`DEPENDENCY_TREE_COMPONENTS`]).
///
/// Symlink-resolved: a symlink planted at `/proj/node_modules/creds` pointing at
/// `~/.aws/credentials` canonicalises OUT of the tree and therefore keeps every
/// rule. The raw path is consulted FIRST and canonicalisation is only used to
/// *revoke* a carveout, never to grant one — so a symlink pointing INTO a
/// dependency tree (`~/.ssh/x -> /proj/node_modules/x`) is still fully scored,
/// and no `realpath(3)` is issued for the overwhelming majority of paths that
/// have no dependency-tree component at all.
///
/// Canonicalisation failure (the usual case while a package manager is
/// *creating* files) falls back to the raw path — fail-safe, because the only
/// effect of a positive answer is suppressing a name-derived score.
pub fn is_dependency_tree_path(path: &str) -> bool {
    confirmed_tree_match(path, components_indicate_dependency_tree)
}

/// True when any component of `path` marks generated build output (see
/// [`GENERATED_OUTPUT_COMPONENTS`]). Same symlink discipline as
/// [`is_dependency_tree_path`].
pub fn is_generated_output_path(path: &str) -> bool {
    confirmed_tree_match(path, components_indicate_generated_output)
}

/// True when `path` sits in a tree whose *names* carry no authority — a
/// vendored dependency tree or generated build output. This is the predicate
/// the weak name rules gate on; the two halves are kept separate above because
/// they are curated for different reasons and reviewed independently.
pub fn is_name_opaque_tree(path: &str) -> bool {
    confirmed_tree_match(path, |p| {
        components_indicate_dependency_tree(p) || components_indicate_generated_output(p)
    })
}

/// Apply `matches` to the raw path and, only when that says yes, re-apply it to
/// the canonical path. Canonicalisation can only ever REVOKE a carveout, never
/// grant one, and is skipped entirely for the overwhelming majority of paths
/// that have no marker component at all.
fn confirmed_tree_match(path: &str, matches: impl Fn(&str) -> bool) -> bool {
    if !matches(path) {
        return false;
    }
    if let Ok(canonical) = std::fs::canonicalize(path) {
        if let Some(s) = canonical.to_str() {
            return matches(s);
        }
    }
    true
}

fn components_indicate_generated_output(path: &str) -> bool {
    path.split(['/', '\\']).any(|component| {
        GENERATED_OUTPUT_COMPONENTS
            .iter()
            .any(|d| component.eq_ignore_ascii_case(d))
    })
}

fn components_indicate_dependency_tree(path: &str) -> bool {
    let components: Vec<&str> = path.split(['/', '\\']).filter(|c| !c.is_empty()).collect();
    for (i, component) in components.iter().enumerate() {
        if component.eq_ignore_ascii_case("target") {
            if target_component_is_build_output(path, &components, i) {
                return true;
            }
            continue;
        }
        if DEPENDENCY_TREE_COMPONENTS
            .iter()
            .any(|d| component.eq_ignore_ascii_case(d))
        {
            return true;
        }
        if let Some(prev) = i.checked_sub(1).map(|j| components[j]) {
            if DEPENDENCY_TREE_COMPONENT_PAIRS
                .iter()
                .any(|(a, b)| prev.eq_ignore_ascii_case(a) && component.eq_ignore_ascii_case(b))
            {
                return true;
            }
        }
    }
    false
}

/// Is the `target` component at `idx` really a cargo/maven output directory?
///
/// `target` is an ordinary English word and an ordinary directory name, so
/// treating the bare component as a carveout silently stopped scoring
/// `/p/target/x/credentials.json` — and, because the same predicate gated the
/// supervisor's read-visibility check, stopped the read being SEEN at all.
/// Two corroborations, either sufficient:
///
/// 1. **Layout** — the next component, or the one after it (for a
///    cross-compilation target triple: `target/aarch64-unknown-linux-gnu/debug`),
///    is `debug` or `release`. This covers every recorded false positive,
///    including the rustc incremental hardlinks under `target/debug/incremental/`.
/// 2. **`CACHEDIR.TAG`** — cargo writes one at the root of every target
///    directory, so a real one is identifiable on disk for the layouts
///    condition 1 misses (`target/doc/`, `target/package/`, `target/tmp/`).
///
/// The stat in condition 2 is only ever paid by a path that HAS a `target`
/// component and fails the cheap layout test.
fn target_component_is_build_output(path: &str, components: &[&str], idx: usize) -> bool {
    fn is_profile(c: &&str) -> bool {
        c.eq_ignore_ascii_case("debug") || c.eq_ignore_ascii_case("release")
    }
    if components.get(idx + 1).is_some_and(is_profile)
        || components.get(idx + 2).is_some_and(is_profile)
    {
        return true;
    }
    let mut root = String::new();
    if path.starts_with('/') {
        root.push('/');
    }
    root.push_str(&components[..=idx].join("/"));
    std::path::Path::new(&root).join("CACHEDIR.TAG").exists()
}

/// True when a WHOLE token of `file_name` is one of [`SENSITIVE_NAME_TOKENS`],
/// or two adjacent tokens are `api` + `key`.
///
/// `file_name` is a basename. Comparison is case-insensitive, but **case is
/// used as a token boundary** (`AccessToken.bin` → `access` + `token`), so
/// callers that already have a lowercased basename lose only camelCase
/// splitting — pass the original-case basename where one is available.
///
/// Token boundaries: `-`, `_`, `.`, ` `, camelCase transitions, and
/// letter↔digit transitions. The last one is what stops rustc's incremental
/// hashes (`773v9mxq3ohs6twiwt1rzauth.o`) from matching: the hash splits into
/// `…1`/`rzauth`, and `rzauth` is not `auth`.
pub fn name_has_sensitive_token(file_name: &str) -> bool {
    let tokens = tokenise_file_name(file_name);
    if tokens
        .iter()
        .any(|t| SENSITIVE_NAME_TOKENS.contains(&t.as_str()))
    {
        return true;
    }
    // `api_key.json` / `apiKey.txt` — two tokens that only mean anything
    // adjacent. `api` or `key` alone is far too common to score.
    tokens.windows(2).any(|w| w[0] == "api" && w[1] == "key")
}

fn tokenise_file_name(file_name: &str) -> Vec<String> {
    fn flush(current: &mut String, tokens: &mut Vec<String>) {
        if !current.is_empty() {
            tokens.push(std::mem::take(current).to_lowercase());
        }
    }

    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = file_name.chars().collect();

    for (i, &ch) in chars.iter().enumerate() {
        if matches!(ch, '-' | '_' | '.' | ' ') {
            flush(&mut current, &mut tokens);
            continue;
        }
        if i > 0 {
            let prev = chars[i - 1];
            let camel_boundary = ch.is_uppercase()
                && (prev.is_lowercase()
                    || prev.is_ascii_digit()
                    // `HTTPServer` -> `HTTP` + `Server`: an upper run ends one
                    // character before its final capital when a lowercase follows.
                    || (prev.is_uppercase()
                        && chars.get(i + 1).is_some_and(|n| n.is_lowercase())));
            let digit_boundary = ch.is_ascii_digit() != prev.is_ascii_digit();
            if camel_boundary || digit_boundary {
                flush(&mut current, &mut tokens);
            }
        }
        current.push(ch);
    }
    flush(&mut current, &mut tokens);
    tokens
}

/// Collapse `//`, `/./` and `/../` LEXICALLY, or `None` when there is nothing
/// to collapse (the overwhelmingly common case, and the reason the caller pays
/// no allocation for an ordinary path).
///
/// Every anchored rule — `/etc/*`, `~/.ssh/id_*` — compares against the path as
/// the caller spelled it, so `/home/u//.ssh/id_rsa` and `/home/u/./.ssh/id_rsa`
/// silently stopped matching when work/83 replaced substring matching with
/// anchoring. This is purely lexical: it never touches the filesystem and never
/// follows a symlink, so it cannot be used to *gain* a match that
/// canonicalisation would deny — a `..` that crosses a symlinked directory
/// resolves differently on disk, which is why the caller uses this only for
/// pattern anchoring and the symlink-sensitive predicates canonicalise
/// separately.
pub fn normalise_path_lexically(path: &str) -> Option<String> {
    if !(path.contains("//")
        || path.contains("/./")
        || path.contains("/..")
        || path.ends_with("/."))
    {
        return None;
    }
    let absolute = path.starts_with('/');
    let trailing_slash = path.len() > 1 && path.ends_with('/');
    let mut out: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|last| *last != "..") {
                    out.pop();
                } else if !absolute {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    let mut joined = String::new();
    if absolute {
        joined.push('/');
    }
    joined.push_str(&out.join("/"));
    if trailing_slash && !joined.ends_with('/') {
        joined.push('/');
    }
    Some(joined)
}

/// The CLOSED set of backup / rotation suffixes. A backed-up or rotated copy of
/// a credential file is the same credential file, and neither the name rules nor
/// the anchored `path_match` globs see through the extra suffix on their own.
///
/// Closed rather than a glob, which is what keeps ordinary compound names out:
/// `i18n.key.ts` ends in a source extension, not one of these, and
/// `terraform.tfstate.lock.info` ends in `.info`.
const BACKUP_SUFFIXES: &[&str] = &[
    ".bak", ".backup", ".old", ".orig", ".save", ".saved", ".copy", ".tmp", "~",
];

/// Strip ONE trailing backup / rotation suffix from an already-lowercased
/// basename, so `server.pem.bak` is still recognised as key material and
/// `terraform.tfstate.backup` still matches the `*.tfstate` rule.
///
/// Only one suffix is removed — a name has to be deliberately constructed
/// (`x.pem.bak.bak`) to hide behind two, and that construction requires reading
/// the original first, which is itself scored.
pub fn strip_backup_suffix(file_name_lc: &str) -> &str {
    for suffix in BACKUP_SUFFIXES {
        if let Some(stem) = file_name_lc.strip_suffix(suffix) {
            if !stem.is_empty() {
                return stem;
            }
        }
    }
    file_name_lc
}

/// Case-insensitive, allocation-free "is this worth lowercasing?" guard for
/// [`strip_backup_suffix`]. Called on the `path_match` hot path, where the
/// answer is almost always no.
pub fn has_backup_suffix(file_name: &str) -> bool {
    let name = file_name.as_bytes();
    BACKUP_SUFFIXES.iter().any(|suffix| {
        let suffix = suffix.as_bytes();
        name.len() > suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    })
}

/// True when `file_name_lc` (already lowercased) is a **structured credential
/// file** — a basename whose whole shape is a recognised credential-store
/// convention, not merely a name that happens to contain a credential-ish
/// word.
///
/// This is the distinction work/83's de-weighting lost. The weak name signal
/// exists for `apps/web/bin/with-secrets` (an extensionless wrapper script),
/// `my-secrets.txt` and `debug_secretscan-…` — names where the word is
/// incidental. It is NOT the right signal for `secrets.yaml` (a Kubernetes
/// Secret manifest, credential values inline), `credentials.json` or
/// `service-account-credentials.json` (a GCP service-account private key).
/// Those are credential FILES: the extension says what the content is.
///
/// Scored as its own `credential-file-shape` hit in `sensitive_path`, which
/// takes the MAXIMUM of its hits — so this REPLACES `secretish-filename`
/// rather than summing with it. That placement is the point: the defect being
/// fixed was one filename priced by two additive rules, and the fix must not
/// re-create the double count from the other side.
pub fn is_structured_credential_filename(file_name_lc: &str) -> bool {
    if matches!(
        file_name_lc,
        "secrets.yaml" | "secrets.yml" | "secrets.json" | "credentials.json"
    ) {
        return true;
    }
    // `*-credentials.json` / `*_credentials.json` / `*.credentials.json` — the
    // shape every cloud SDK writes a downloaded service-account key as
    // (`service-account-credentials.json`, `gcp_credentials.json`). A separator
    // is required so `nocredentials.json` (no boundary) does not qualify.
    file_name_lc
        .strip_suffix("credentials.json")
        .is_some_and(|stem| stem.ends_with('-') || stem.ends_with('_') || stem.ends_with('.'))
}

/// True when `file_name_lc` (already lowercased) is a documentation, asset or
/// build-artifact file — a class that cannot itself *be* a credential store, so
/// a credential-ish token in its name is a coincidence rather than a signal.
///
/// Deliberately NOT carved, because these genuinely hold credentials:
/// `.json` (Composer `auth.json`, service-account keys), `.yaml`/`.yml`
/// (Kubernetes secrets, CI configs), `.toml`/`.ini`/`.conf` (registry and
/// database credentials), `.txt`, `.sh` (exported secrets), any `.env*`, and
/// extensionless files (`bin/with-secrets`, `~/.netrc`-shaped stores).
///
/// The compensating control for the carved classes is content-derived, not
/// name-derived: `secret_scan`'s 1,620 patterns still read a credential pasted
/// into `notes.md` or an `.svg`, and `dlp_gate` still scores it on the way out.
pub fn is_non_credential_artifact_filename(file_name_lc: &str) -> bool {
    const ARTIFACT_EXTS: &[&str] = &[
        // Documentation / markup
        ".md", ".mdx", ".rst", ".adoc", // Assets
        ".svg", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".avif", ".woff", ".woff2",
        ".ttf", ".mp4", ".pdf", // Build artifacts
        ".o", ".obj", ".d", ".rlib", ".rmeta", ".a", ".so", ".dylib", ".pdb", ".wasm", ".class",
        ".pyc",
    ];
    ARTIFACT_EXTS.iter().any(|ext| file_name_lc.ends_with(ext))
}

/// True for a **schema-migration** SQL file: `.sql` whose basename is numbered
/// (`0016_better_auth_admin_two_factor.sql`) or that lives under a `migrations`
/// component.
///
/// Migrations are committed, reviewed source-of-truth DDL whose names describe
/// the *tables* they create (`…_auth_admin_…`, `…_api_tokens…`), which is why
/// they collide with the keyword rule. A bare `dump.sql` — the shape that could
/// actually contain exported credential rows — is deliberately NOT carved.
pub fn is_migration_sql_filename(file_name_lc: &str, path_lc: &str) -> bool {
    if !file_name_lc.ends_with(".sql") {
        return false;
    }
    let digits = file_name_lc
        .chars()
        .take_while(char::is_ascii_digit)
        .count();
    if digits > 0
        && file_name_lc[digits..]
            .chars()
            .next()
            .is_some_and(|c| c == '-' || c == '_')
    {
        return true;
    }
    path_lc
        .split(['/', '\\'])
        .any(|c| c.eq_ignore_ascii_case("migrations"))
}

#[cfg(test)]
mod generated_tree_tests {
    use super::*;

    /// work/83 replay: 85 of the 105 surviving prompts were the static export
    /// and build cache of a documentation site whose PAGES are about secrets.
    #[test]
    fn generated_output_trees_are_name_opaque() {
        for p in [
            "/p/out/docs/concepts/canary-tokens.html",
            "/p/out/docs/filters/07-secret-credential-scanning",
            "/p/.next/server/app/docs/guides/setting-up-canary-tokens.rsc",
            "/p/dist/bundle-secrets.js",
            "/p/build/authorization.txt",
            "/p/.svelte-kit/output/tokens.json",
        ] {
            assert!(is_generated_output_path(p), "{p} is generated output");
            assert!(is_name_opaque_tree(p), "{p} must be name-opaque");
        }
    }

    /// The two halves stay distinguishable, and ordinary source paths are
    /// neither.
    #[test]
    fn source_paths_are_not_name_opaque() {
        for p in [
            "/p/src/app/api/auth/route.ts",
            "/p/content/docs/pro/authentication.mdx",
            "/home/u/.aws/credentials",
            "/home/u/outbound/secrets.yaml",
            "/home/u/distribution/secrets.yaml",
        ] {
            assert!(!is_name_opaque_tree(p), "{p} must NOT be name-opaque");
        }
        assert!(is_dependency_tree_path("/p/node_modules/x/y.js"));
        assert!(!is_generated_output_path("/p/node_modules/x/y.js"));
        assert!(is_generated_output_path("/p/dist/y.js"));
        assert!(!is_dependency_tree_path("/p/dist/y.js"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_tree_components_match_component_exact() {
        for p in [
            "/p/node_modules/aria-query/lib/etc/roles/literal/alertdialogRole.js",
            "/p/node_modules/cookies",
            "/p/.pnpm/foo@1/node_modules/foo/index.js",
            "/p/bower_components/x/y",
            "/p/vendor/github.com/aws/aws-sdk-go/aws/credentials/creds.go",
            "/p/.venv/lib/python3.11/site-packages/boto3/secrets.py",
            "/p/venv/bin/activate",
            "/ios/Pods/Firebase/auth.h",
            "/p/target/debug/incremental/x-0lrjcx9q6lz73/s-h7bezc6gl.o",
            "/p/target/release/build/x/out/token.rs",
            "/p/target/aarch64-unknown-linux-gnu/debug/deps/libauth.rmeta",
            "/p/.gradle/caches/modules-2/files-2.1/x.jar",
            "/home/u/.cargo/registry/src/index.crates.io-6f17d22bba15001f/foo/token.rs",
            "/home/u/.m2/repository/org/x/1.0/x.jar",
        ] {
            assert!(is_dependency_tree_path(p), "{p} must be a dependency tree");
        }
    }

    #[test]
    fn dependency_tree_is_never_a_substring_match() {
        for p in [
            "/proj/vendors/x",        // "vendors" != "vendor"
            "/proj/mytarget/y",       // "mytarget" != "target"
            "/proj/targets/build.rs", // "targets" != "target"
            // A `target` component with no build-output corroboration is an
            // ordinary directory, and `gems` is an ordinary word.
            "/proj/target/x/credentials.json",
            "/proj/target/tmp/secrets.yaml",
            "/p/gems/token.txt",
            "/home/u/.gem/credentials",
            "/proj/node_modules_old/x",   // not the component
            "/home/u/.cargo/config.toml", // .cargo without registry
            "/home/u/.m2/settings.xml",   // .m2 without repository
            "/home/u/.aws/credentials",
            "/etc/nginx/nginx.conf",
        ] {
            assert!(
                !is_dependency_tree_path(p),
                "{p} must NOT be a dependency tree"
            );
        }
    }

    /// work/83 finding 2: `target` is an ordinary directory name, so the bare
    /// component was silently carving `/p/target/x/credentials.json`. It now
    /// needs corroboration — the cargo/maven layout, or a real `CACHEDIR.TAG`
    /// on disk — while every recorded false positive (all of which live under
    /// `target/debug/`) keeps its carveout.
    #[test]
    fn target_needs_build_output_corroboration() {
        for p in [
            "/p/target/debug/incremental/fp_credential_then_tool-0lrjcx9q/s-abc.o",
            "/p/target/release/build/x/out/token.rs",
            "/p/target/aarch64-unknown-linux-gnu/debug/deps/libauth.rmeta",
        ] {
            assert!(is_dependency_tree_path(p), "{p} is cargo build output");
        }
        for p in [
            "/p/target/x/credentials.json",
            "/p/target/tmp/secrets.yaml",
            "/p/target/audience/tokens.json",
        ] {
            assert!(
                !is_dependency_tree_path(p),
                "{p}: a bare `target` component is not build output"
            );
        }

        // The CACHEDIR.TAG fallback covers the cargo layouts the cheap test
        // misses (`target/doc/`, `target/package/`, `target/tmp/`).
        let root = tempfile::tempdir().expect("tempdir");
        let target = root.path().join("target");
        std::fs::create_dir_all(target.join("doc")).expect("mkdir");
        let doc_file = target.join("doc").join("api-token.txt");
        assert!(
            !is_dependency_tree_path(doc_file.to_str().unwrap()),
            "no CACHEDIR.TAG yet"
        );
        std::fs::write(target.join("CACHEDIR.TAG"), b"Signature: 8a477f597d28d172")
            .expect("write tag");
        assert!(
            is_dependency_tree_path(doc_file.to_str().unwrap()),
            "CACHEDIR.TAG identifies a real cargo target directory"
        );
    }

    #[test]
    fn lexical_normalisation_collapses_only_what_it_should() {
        assert_eq!(normalise_path_lexically("/home/u/.ssh/id_rsa"), None);
        assert_eq!(
            normalise_path_lexically("/home/u//.ssh/id_rsa").as_deref(),
            Some("/home/u/.ssh/id_rsa")
        );
        assert_eq!(
            normalise_path_lexically("/home/u/./.ssh/id_rsa").as_deref(),
            Some("/home/u/.ssh/id_rsa")
        );
        assert_eq!(
            normalise_path_lexically("/home/u/projects/../.aws/credentials").as_deref(),
            Some("/home/u/.aws/credentials")
        );
        assert_eq!(
            normalise_path_lexically("~/./.ssh/id_rsa").as_deref(),
            Some("~/.ssh/id_rsa")
        );
        // A trailing separator is meaningful to the directory-form callers.
        assert_eq!(
            normalise_path_lexically("/etc//nginx/").as_deref(),
            Some("/etc/nginx/")
        );
        // `..` may not climb above an absolute root.
        assert_eq!(
            normalise_path_lexically("/../../etc").as_deref(),
            Some("/etc")
        );
    }

    #[test]
    fn sensitive_tokens_match_whole_tokens_only() {
        for name in [
            "auth.json",
            "credentials.json",
            "secrets.yaml",
            "api-token.txt",
            "my_secret_file",
            "AccessToken.bin",
            "canary-tokens.mdx",
            "api_key.conf",
            "apikey",
            ".git-credentials",
        ] {
            assert!(name_has_sensitive_token(name), "{name} must match");
        }
    }

    #[test]
    fn sensitive_tokens_reject_coincidental_substrings() {
        for name in [
            "hero-zero-ambient-authority-1600x900.svg",
            "authorize.rs",
            "AUTHORS",
            "773v9mxq3ohs6twiwt1rzauth.o",
            "debug_secretscan-32x74bbezc6gl",
            "secretscan",
            "tokenize.js",
            "authenticator.py",
            "author.md",
            "keyapi.txt", // wrong order — only `api` then `key` is the pair
        ] {
            assert!(!name_has_sensitive_token(name), "{name} must NOT match");
        }
    }

    /// camelCase splitting makes `tokenTypes.js` / `AccessToken.php` match the
    /// TOKEN rule — deliberately. Those are suppressed one layer up by
    /// `is_source_code_filename`, not here, so the token rule stays honest
    /// about what the name says and the carveout stays reviewable in one place.
    #[test]
    fn camel_case_source_names_still_tokenise() {
        assert!(name_has_sensitive_token("tokenTypes.js"));
        assert!(name_has_sensitive_token("AccessToken.php"));
    }

    #[test]
    fn artifact_extensions_are_carved_but_config_extensions_are_not() {
        for name in [
            "canary-tokens.mdx",
            "authentication.md",
            "auth.rst",
            "tokens.adoc",
            "hero-zero-ambient-authority-1600x900.svg",
            "secret.png",
            "token.woff2",
            "773v9mxq3ohs6twiwt1rzauth.o",
            "libsecret.so",
            "credentials.rmeta",
            "auth.pyc",
        ] {
            assert!(
                is_non_credential_artifact_filename(name),
                "{name} must be a non-credential artifact"
            );
        }
        for name in [
            "auth.json",
            "secrets.yaml",
            "secrets.yml",
            "credentials.toml",
            "token.ini",
            "auth.conf",
            "api-token.txt",
            "with-secrets", // extensionless wrapper script
            ".env.production",
            "export-secrets.sh",
        ] {
            assert!(
                !is_non_credential_artifact_filename(name),
                "{name} must stay scoreable"
            );
        }
    }

    #[test]
    fn migration_sql_is_carved_but_a_bare_dump_is_not() {
        assert!(is_migration_sql_filename(
            "0016_better_auth_admin_two_factor.sql",
            "/p/packages/db/migrations/0016_better_auth_admin_two_factor.sql"
        ));
        assert!(is_migration_sql_filename(
            "0016-add-tokens.sql",
            "/p/db/0016-add-tokens.sql"
        ));
        assert!(is_migration_sql_filename(
            "add_auth_tables.sql",
            "/p/db/migrations/add_auth_tables.sql"
        ));
        // A bare dump keeps its score: this is the shape that could hold
        // exported credential rows.
        assert!(!is_migration_sql_filename(
            "dump.sql",
            "/p/backups/dump.sql"
        ));
        assert!(!is_migration_sql_filename(
            "secrets_dump.sql",
            "/p/backups/secrets_dump.sql"
        ));
        // Not SQL at all.
        assert!(!is_migration_sql_filename(
            "0016_auth.json",
            "/p/db/migrations/0016_auth.json"
        ));
    }
}
