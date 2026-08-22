// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Path pattern matching filter for filesystem access control.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};
use serde::Deserialize;

/// Configuration for a single path matching rule.
#[derive(Debug, Clone, Deserialize)]
pub struct PathRule {
    pub id: String,
    pub pattern: String,
    pub operations: Vec<String>,
    pub score: f64,
    pub severity: String,
    pub message: String,
    /// FP §5.7: file BASENAMES that exempt a path from this rule even though
    /// `pattern` matched — e.g. the `env-file` rule matches `.env` but excludes
    /// the basename `.env.example` (template scaffolding). Matched basename-
    /// exact (not a path substring), so `.env.example.bak` is NOT exempt.
    /// Default empty.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// work/83 F7: this rule keys on a WEAK filename shape (a word that occurs
    /// constantly in ordinary code) rather than on a credential *class* or an
    /// anchored credential *location*, so it is suppressed inside a vendored
    /// dependency tree — a package chooses its own filenames, and
    /// `node_modules/aws-sdk/lib/credentials/sso_credentials.js` is source
    /// code, not a credential store.
    ///
    /// Only the weak rules carry this. `.env`, `~/.ssh/*`, `~/.aws/*`,
    /// `*.pem`, `*.key`, `/etc/shadow` and friends keep firing everywhere,
    /// including inside a dependency tree: a real credential store planted
    /// under `node_modules/` must still score. Default false.
    #[serde(default)]
    pub weak_name_signal: bool,
}

/// Path matching filter over ANCHORED, compiled glob patterns.
///
/// work/83 M7: patterns used to be stripped of their `*`s and tested with
/// `path.contains()`, which silently threw away everything the pattern said
/// about *where* it applied. `/etc/*` matched
/// `…/node_modules/aria-query/lib/etc/roles/…` — 554 modal prompts in one
/// morning, 277 of them inside 87 seconds of a single `npm install`, because
/// two transitive dependencies of `eslint-plugin-jsx-a11y` ship a `lib/etc/`
/// directory. The same flaw made `/etc/shadow` satisfiable by any
/// attacker-chosen `~/project/etc/shadow`.
///
/// Each rule is compiled once into a [`CompiledPattern`] that preserves its
/// anchor. Every rule is still evaluated (overlapping patterns such as
/// `~/.ssh/*` and `~/.ssh/id_*` must both be considered) and the
/// highest-scoring match wins.
pub struct PathMatchFilter {
    rules: Vec<PathRule>,
    compiled: Vec<CompiledPattern>,
}

impl PathMatchFilter {
    pub fn new(rules: Vec<PathRule>) -> Self {
        let compiled: Vec<CompiledPattern> =
            rules.iter().map(|r| compile_pattern(&r.pattern)).collect();

        Self { rules, compiled }
    }
}

/// A configured pattern with its anchor preserved.
///
/// The grammar is derived from the 14 rules `config/filters/paths.toml` ships;
/// each variant names the rule shape it exists for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompiledPattern {
    /// No `/`, no `*` — `".env"`. Matches the BASENAME exactly. `.envrc` and
    /// `.env.production` are different files; the latter has its own rule
    /// (`env-file-variants`, pattern `.env.*`).
    BasenameExact(String),
    /// No `/`, with `*` — `"*.pem"`, `"*.key"`, `"*.tfstate"`, `".env.*"`,
    /// `"*credentials*"`, `"*secrets*"`. Globs the BASENAME, so
    /// `/p/.pem-notes/a.js` no longer matches `*.pem` and a directory named
    /// `secrets/` no longer drags every file beneath it over the threshold.
    BasenameGlob(String),
    /// Starts with `/` and ends `/*` — `"/etc/*"`. Anchored directory prefix at
    /// the filesystem root, any depth beneath.
    RootPrefix(String),
    /// Starts with `/` — `"/etc/shadow"`. Anchored at the filesystem root and
    /// matched over the WHOLE path.
    RootGlob(String),
    /// Starts with `~/` and ends `/*` — `"~/.ssh/*"`, `"~/.aws/*"`,
    /// `"~/.gnupg/*"`, `"~/.config/gcloud/*"`. Directory prefix relative to a
    /// home root (see [`home_relative`]).
    HomePrefix(String),
    /// Starts with `~/` — `"~/.ssh/id_*"`. Globbed relative to a home root.
    HomeGlob(String),
    /// Contains `/`, neither absolute nor home-anchored, ends `/*`. Directory
    /// prefix matched on a component boundary anywhere in the path. No shipped
    /// rule uses this shape; it exists so operator-authored rules behave.
    SuffixPrefix(String),
    /// Contains `/`, neither absolute nor home-anchored. Path-SUFFIX match on a
    /// component boundary (never mid-component).
    SuffixGlob(String),
}

/// The operation a call performs, for rule matching. Full coverage of every
/// `ToolCallType` — `sensitive_path` applies its own narrower gate on top.
pub(crate) fn operation_for_call_type(call_type: &ToolCallType) -> &'static str {
    {
        match call_type {
            ToolCallType::FileRead { .. } => "read",
            ToolCallType::FileWrite { .. } => "write",
            ToolCallType::FileAppend { .. } => "write",
            ToolCallType::FileDelete { .. } => "delete",
            ToolCallType::DirList { .. } => "list",
            ToolCallType::ShellExec { .. } => "exec",
            ToolCallType::HttpRequest { .. } => "http",
            ToolCallType::FileRename { .. } => "write",
            // Only reached when a caller asks for a single operation; the
            // two-path form in `path_operations` is what actually scores a
            // link, and it uses read-for-target / write-for-link-path.
            ToolCallType::FileLink { .. } => "write",
            ToolCallType::FileChmod { .. } => "write",
            ToolCallType::DirCreate { .. } => "write",
            ToolCallType::NetConnect { .. } => "http",
            ToolCallType::NetListen { .. } => "http",
            ToolCallType::ProcessSpawn { .. } => "exec",
            ToolCallType::DnsQuery { .. } => "dns",
            // PR 6 Phase B: category-2 syscalls.
            ToolCallType::OwnershipChange { .. } => "write",
            ToolCallType::FilesystemMutation { .. } => "write",
            ToolCallType::CrossProcessAccess { .. } => "process",
            ToolCallType::NamespaceOp { .. } => "namespace",
            ToolCallType::DbusMethodCall { .. } => "dbus",
        }
    }
}

/// Compile a configured glob into an anchored [`CompiledPattern`].
pub(crate) fn compile_pattern(pattern: &str) -> CompiledPattern {
    if let Some(rest) = pattern.strip_prefix("~/") {
        return match rest.strip_suffix("/*") {
            Some(dir) => CompiledPattern::HomePrefix(format!("{dir}/")),
            None => CompiledPattern::HomeGlob(rest.to_string()),
        };
    }
    if pattern.starts_with('/') {
        return match pattern.strip_suffix("/*") {
            Some(dir) => CompiledPattern::RootPrefix(format!("{dir}/")),
            None => CompiledPattern::RootGlob(pattern.to_string()),
        };
    }
    if !pattern.contains('/') {
        return if pattern.contains('*') {
            CompiledPattern::BasenameGlob(pattern.to_string())
        } else {
            CompiledPattern::BasenameExact(pattern.to_string())
        };
    }
    match pattern.strip_suffix("/*") {
        Some(dir) => CompiledPattern::SuffixPrefix(format!("{dir}/")),
        None => CompiledPattern::SuffixGlob(pattern.to_string()),
    }
}

impl CompiledPattern {
    /// True when `path` (already `/`-normalised) satisfies this pattern.
    pub(crate) fn matches(&self, path: &str) -> bool {
        let basename = path.rsplit('/').next().unwrap_or(path);
        match self {
            Self::BasenameExact(name) => basename == name,
            // work/83 finding 3: `*.tfstate` is anchored at the END of the
            // basename, so `terraform.tfstate.backup` — which Terraform writes
            // on every apply, holding the same plaintext provider credentials
            // as the state file itself — matched no rule at all. One CLOSED
            // backup suffix is stripped before the glob is retried, which is
            // the same treatment `key-material-file` already gives
            // `server.pem.bak`. It restores parity rather than widening:
            // `server.pem` and `server.key` already score from BOTH filters,
            // and their `.bak` twins only scored from one.
            Self::BasenameGlob(g) => {
                glob_match(g, basename)
                    || (crate::paths::has_backup_suffix(basename) && {
                        let lower = basename.to_ascii_lowercase();
                        let stem = crate::paths::strip_backup_suffix(&lower);
                        stem.len() != lower.len() && glob_match(g, stem)
                    })
            }
            Self::RootPrefix(dir) => path.starts_with(dir.as_str()),
            Self::RootGlob(g) => glob_match(g, path),
            Self::HomePrefix(dir) => {
                home_relative(path).is_some_and(|rest| rest.starts_with(dir.as_str()))
                    || dot_directory_fallback(path, dir, |candidate, dir| {
                        candidate.starts_with(dir)
                    })
            }
            Self::HomeGlob(g) => {
                home_relative(path).is_some_and(|rest| glob_match(g, rest))
                    || dot_directory_fallback(path, g, |candidate, pattern| {
                        glob_match(pattern, candidate)
                    })
            }
            Self::SuffixPrefix(dir) => component_suffix_candidates(path)
                .any(|candidate| candidate.starts_with(dir.as_str())),
            Self::SuffixGlob(g) => {
                component_suffix_candidates(path).any(|candidate| glob_match(g, candidate))
            }
        }
    }
}

/// A `~/`-anchored rule whose first component is a DOT-directory degrades to a
/// component-boundary suffix match.
///
/// `home_relative` recognises `/home/<u>/`, `/Users/<u>/`, `/root/` and the
/// supervisor's own resolved `$HOME` — which is every ordinary layout and no
/// container or service one. A daemon whose home is `/var/lib/svc` or
/// `/opt/app` lost `~/.ssh/*`, `~/.aws/*` and `~/.config/gcloud/*` entirely
/// when work/83 replaced substring matching with anchoring:
/// `/var/lib/svc/.ssh/id_rsa` fell from auto-DENY to a QUEUE.
///
/// The fallback is deliberately self-limiting. It applies only when the rule's
/// own first component is dot-prefixed, and it still requires a full component
/// boundary and a match of the WHOLE remainder — so `~/.config/gcloud/*` needs
/// a real `.config/gcloud/` in the path, and a hypothetical `~/Downloads/*`
/// rule would not float at all. That makes it strictly tighter than the
/// pre-work/83 substring match it restores (which also matched
/// `/p/backup.ssh/id_rsa`), while a non-standard home degrades to the same
/// score as a standard one rather than to no rule.
fn dot_directory_fallback(path: &str, pattern: &str, matches: impl Fn(&str, &str) -> bool) -> bool {
    if !pattern.starts_with('.') {
        return false;
    }
    component_suffix_candidates(path).any(|candidate| matches(candidate, pattern))
}

/// Every suffix of `path` that begins on a component boundary, longest first.
/// `"a/b/c"` yields `"a/b/c"`, `"b/c"`, `"c"` — so a relative pattern matches
/// whole components only and never lands mid-component.
fn component_suffix_candidates(path: &str) -> impl Iterator<Item = &str> {
    std::iter::once(path.trim_start_matches('/')).chain(
        path.match_indices('/')
            .map(move |(i, _)| &path[i + 1..])
            .filter(|s| !s.is_empty()),
    )
}

/// Glob match where `*` matches any run of characters but NEVER crosses `/`.
/// Linear-with-backtracking; patterns are short and fixed at config load.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            // Extending the `*` by one character: refuse to swallow a path
            // separator, so `/etc/*`-style patterns cannot reach into a
            // deeper component than the pattern named.
            if t[st] == '/' {
                return false;
            }
            star = Some((sp, st + 1));
            ti = st + 1;
            pi = sp + 1;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// The part of `path` beneath a home directory, or `None` when it is not under
/// one.
///
/// A `~/`-anchored rule MUST resolve against every plausible home root, not
/// just the current process's `$HOME`. The supervisor evaluates paths on behalf
/// of a traced tool that may run as another user, and `/root/.aws/credentials`
/// is exactly the file these rules exist for — anchoring to `$HOME` alone would
/// have been a protection REGRESSION, not a narrowing.
fn home_relative(path: &str) -> Option<&str> {
    // An UNEXPANDED tilde. The LLM path (`grith run`) scores whatever string
    // the model emitted, and `path_resolution` cannot canonicalise `~/...`
    // (no such literal directory), so the string reaches the filters intact.
    // `~/` at the start of a path has exactly one meaning, so accepting it
    // here restores the coverage the old floating-substring match had.
    if let Some(rest) = path.strip_prefix("~/") {
        return Some(rest);
    }
    for root in ["/home/", "/Users/", "/users/"] {
        if let Some(rest) = path.strip_prefix(root) {
            // Skip the user-name component; `None` when the path IS the home dir.
            return rest.find('/').map(|i| &rest[i + 1..]);
        }
    }
    if let Some(rest) = path.strip_prefix("/root/") {
        return Some(rest);
    }
    // Non-standard layouts (containers, symlinked or relocated homes) via the
    // resolved home directory.
    let home = resolved_home()?;
    let home = home.trim_end_matches('/');
    if home.is_empty() {
        return None;
    }
    path.strip_prefix(home)?.strip_prefix('/')
}

/// The process's resolved home directory, looked up once.
fn resolved_home() -> Option<&'static str> {
    static HOME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    HOME.get_or_init(|| {
        dirs::home_dir().and_then(|p| p.to_str().map(std::string::ToString::to_string))
    })
    .as_deref()
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        _ => Severity::Notice,
    }
}

#[async_trait::async_trait]
impl SecurityFilter for PathMatchFilter {
    fn name(&self) -> &str {
        "path-match"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Static
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        // Judge every (path, operation) the call carries and keep the worst.
        // Link creation has two with different operations — the target is
        // made readable, the link path is written — so a link planted at a
        // rule-protected location is priced like the write it substitutes
        // for (go-live review B2).
        let mut worst: Option<FilterResult> = None;
        for (path, operation) in crate::filters::sensitive_path::path_operations(&ctx.call_type) {
            let result = self.evaluate_path(path, operation);
            let better = match &worst {
                Some(current) => result.score > current.score,
                None => true,
            };
            if result.matched && better {
                worst = Some(result);
            }
        }
        Ok(worst.unwrap_or_else(|| FilterResult::no_match("path-match")))
    }
}

impl PathMatchFilter {
    fn evaluate_path(&self, path: &str, operation: &str) -> FilterResult {
        // work/83 F7: inside a vendored dependency tree the WEAK filename rules
        // (`weak_name_signal`) do not fire — a package chooses its own
        // filenames, so `node_modules/aws-sdk/lib/credentials/` carries no
        // authority. Everything else in this filter keys on a credential class
        // (`*.pem`, `*.key`, `.env`) or an anchored credential location
        // (`~/.ssh/*`, `/etc/shadow`) and keeps firing there, because a real
        // credential store planted under `node_modules/` must still score —
        // pinned by `dependency_tree_gate_never_covers_a_real_credential_store`.
        //
        // Gating the whole filter was the first attempt and was wrong: it took
        // `node_modules/evil/.env` from 6.0 (QUEUE) down to 3.0, which routes
        // as ALLOW.
        //
        // What a dependency *does* is never gated at all: secret_scan
        // (content), taint (flow), egress_policy / egress_rate (destination),
        // destructive_action, rate_limit and operation_risk run unchanged. The
        // predicate is symlink-resolved, so a link out of the tree to a real
        // credential store keeps every rule, and it is evaluated lazily —
        // only a matching weak rule pays for the `realpath(3)`.
        let mut in_dependency_tree: Option<bool> = None;

        // Check all rules for matches and select the highest-scoring one.
        // Overlapping patterns (e.g. "~/.ssh/*" and "~/.ssh/id_*") must all be
        // considered, so every rule is tested rather than stopping at the first.
        let mut best_match: Option<&PathRule> = None;

        // Windows separators are normalised so an anchored pattern behaves the
        // same on every platform, and `//` / `/./` / `/../` are collapsed
        // LEXICALLY — an anchored pattern compares against the path as the
        // caller spelled it, so `/home/u//.ssh/id_rsa` and
        // `/home/u/./.ssh/id_rsa` otherwise stopped matching `~/.ssh/id_*`
        // (work/83 finding 5). Purely lexical: no filesystem access, no
        // symlink following.
        let separator_normalised;
        let path = if path.contains('\\') {
            separator_normalised = path.replace('\\', "/");
            separator_normalised.as_str()
        } else {
            path
        };
        let lexically_normalised;
        let path = match crate::paths::normalise_path_lexically(path) {
            Some(normalised) => {
                lexically_normalised = normalised;
                lexically_normalised.as_str()
            }
            None => path,
        };

        // FP §5.7: the file's basename, for the exclude check below.
        let basename = path.rsplit('/').next().unwrap_or(path);
        for (i, rule) in self.rules.iter().enumerate() {
            if self.compiled[i].matches(path)
                && rule.operations.iter().any(|op| op == operation)
                // FP §5.7: skip when the file's BASENAME exactly equals one of
                // the rule's exclude entries (e.g. `.env` rule excludes the
                // basename `.env.example`). Basename-exact, NOT a path substring:
                // a substring check would over-exclude `.env.example.bak` (a
                // backup that may hold real values) or a real `.env` inside a
                // directory named `.env.example/`.
                && !rule.exclude.iter().any(|ex| basename == ex.as_str())
            {
                if rule.weak_name_signal
                    && *in_dependency_tree
                        .get_or_insert_with(|| crate::paths::is_name_opaque_tree(path))
                {
                    continue;
                }
                match &best_match {
                    Some(current) if current.score >= rule.score => {}
                    _ => best_match = Some(rule),
                }
            }
        }

        match best_match {
            Some(rule) => {
                let severity = parse_severity(&rule.severity);
                FilterResult::matched("path-match", &rule.id, rule.score, severity, &rule.message)
            }
            None => FilterResult::no_match("path-match"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCallType;
    use uuid::Uuid;

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    fn default_rules() -> Vec<PathRule> {
        vec![
            PathRule {
                id: "ssh-private-key".into(),
                pattern: "~/.ssh/id_*".into(),
                operations: vec!["read".into(), "write".into(), "delete".into()],
                score: 5.0,
                severity: "critical".into(),
                message: "Access to SSH private key".into(),
                exclude: vec![],
                weak_name_signal: false,
            },
            PathRule {
                id: "ssh-dir".into(),
                pattern: "~/.ssh/*".into(),
                operations: vec!["write".into(), "delete".into(), "list".into()],
                score: 3.0,
                severity: "warning".into(),
                message: "Access to SSH directory".into(),
                exclude: vec![],
                weak_name_signal: false,
            },
            PathRule {
                id: "env-file".into(),
                pattern: ".env".into(),
                operations: vec!["read".into(), "write".into(), "delete".into()],
                score: 3.0,
                severity: "warning".into(),
                message: "Access to environment file".into(),
                exclude: vec![],
                weak_name_signal: false,
            },
            PathRule {
                id: "pem-files".into(),
                pattern: "*.pem".into(),
                operations: vec!["read".into(), "write".into(), "delete".into()],
                score: 4.0,
                severity: "error".into(),
                message: "Access to PEM file".into(),
                exclude: vec![],
                weak_name_signal: false,
            },
        ]
    }

    #[tokio::test]
    async fn test_ssh_key_read_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.ssh/id_rsa".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "ssh-private-key");
        assert_eq!(result.score, 5.0);
    }

    /// work/83 finding 5: `home_relative` recognises `/home/<u>/`,
    /// `/Users/<u>/`, `/root/` and the process's own `$HOME` — every ordinary
    /// layout and no container or service one — and it did no lexical
    /// normalisation. A daemon home and a `//` or `/./` in the path both lost
    /// `~/`-anchored rules outright.
    #[test]
    fn home_anchored_rules_survive_a_service_home_and_a_messy_path() {
        let id_key = compile_pattern("~/.ssh/id_*");
        let aws = compile_pattern("~/.aws/*");
        let gcloud = compile_pattern("~/.config/gcloud/*");

        // Ordinary layouts, unchanged.
        assert!(id_key.matches("/home/u/.ssh/id_rsa"));
        assert!(id_key.matches("/root/.ssh/id_ed25519"));
        assert!(aws.matches("/home/u/.aws/credentials"));

        // Container / service homes.
        assert!(id_key.matches("/var/lib/svc/.ssh/id_rsa"));
        assert!(aws.matches("/var/lib/svc/.aws/credentials"));
        assert!(gcloud.matches("/opt/app/.config/gcloud/credentials.db"));

        // The fallback is component-boundary only, so it is TIGHTER than the
        // pre-work/83 substring match it restores.
        assert!(!id_key.matches("/p/backup.ssh/id_rsa"));
        assert!(!gcloud.matches("/p/.configuration/gcloud/x"));

        // Lexical normalisation is applied by `evaluate_path`, so the compiled
        // pattern sees a collapsed path. Assert the collapse itself here; the
        // end-to-end score is pinned in the fp83 suite.
        assert_eq!(
            crate::paths::normalise_path_lexically("/home/u//./.ssh/id_rsa").as_deref(),
            Some("/home/u/.ssh/id_rsa")
        );

        // Root-anchored rules are untouched: work/83's central tightening —
        // `/etc/*` must never match `node_modules/**/lib/etc/**` — still holds.
        let etc = compile_pattern("/etc/*");
        assert!(etc.matches("/etc/nginx/nginx.conf"));
        assert!(!etc.matches("/p/node_modules/aria-query/lib/etc/roles/x.js"));
        assert!(!compile_pattern("/etc/shadow").matches("/home/u/project/etc/shadow"));
    }

    /// work/83 finding 3: `*.tfstate` is anchored at the end of the basename,
    /// so `terraform.tfstate.backup` — written by Terraform on every apply and
    /// holding the same plaintext provider credentials — matched no rule at
    /// all. One closed backup suffix is stripped before the glob is retried.
    #[test]
    fn basename_globs_see_through_one_backup_suffix() {
        let tfstate = compile_pattern("*.tfstate");
        assert!(tfstate.matches("/p/terraform.tfstate"));
        assert!(tfstate.matches("/p/terraform.tfstate.backup"));
        assert!(tfstate.matches("/p/terraform.tfstate.bak"));
        assert!(tfstate.matches("/p/terraform.tfstate.old"));
        assert!(tfstate.matches("/p/Terraform.TFState.BACKUP"));

        // Not a backup suffix: Terraform's own lock file, written on every
        // local-backend apply, must not start prompting.
        assert!(!tfstate.matches("/p/terraform.tfstate.lock.info"));
        assert!(!tfstate.matches("/p/terraform.tfstate.d/env"));
        // Only ONE suffix is stripped.
        assert!(!tfstate.matches("/p/terraform.tfstate.bak.bak"));

        // The same treatment `key-material-file` already gave `server.pem.bak`
        // in the other filter, so the two agree.
        assert!(compile_pattern("*.pem").matches("/certs/server.pem.bak"));
        assert!(compile_pattern("*.key").matches("/certs/server.key.old"));
        assert!(!compile_pattern("*.key").matches("/p/i18n.key.ts"));
    }

    // FP §5.7: `exclude` is matched basename-EXACT, so it exempts `.env.example`
    // but NOT `.env.example.bak` (a backup that may hold real values) and NOT a
    // real `.env` whose parent dir happens to be named `.env.example/`.
    #[tokio::test]
    async fn exclude_is_basename_exact_not_substring() {
        // work/83 M7: `.env` is now BASENAME-EXACT, so the shipped config's
        // second rule (`.env.*`, `env-file-variants`) is what covers the
        // overlay files. Both are registered here, exactly as production
        // loads them, so the exclude semantics are tested against the real
        // shape rather than against the old floating-substring one.
        let rules = vec![
            PathRule {
                id: "env-file".into(),
                pattern: ".env".into(),
                operations: vec!["read".into()],
                score: 3.0,
                severity: "warning".into(),
                message: "env".into(),
                exclude: vec![".env.example".into(), ".env.sample".into()],
                weak_name_signal: false,
            },
            PathRule {
                id: "env-file-variants".into(),
                pattern: ".env.*".into(),
                operations: vec!["read".into()],
                score: 3.0,
                severity: "warning".into(),
                message: "env variant".into(),
                exclude: vec![".env.example".into(), ".env.sample".into()],
                weak_name_signal: false,
            },
        ];
        let filter = PathMatchFilter::new(rules);
        let read = |p: &str| make_ctx(ToolCallType::FileRead { path: p.into() });

        // Exempt: exact template basenames.
        for p in ["/home/u/proj/.env.example", "/home/u/proj/.env.sample"] {
            assert!(
                !filter.evaluate(&read(p)).await.unwrap().matched,
                "{p} (template) must be exempt"
            );
        }
        // NOT exempt (over-exclusion guards): backup, overlay, and a real .env
        // inside a directory named after the template.
        for p in [
            "/home/u/proj/.env",
            "/home/u/proj/.env.production",
            "/home/u/proj/.env.example.bak",
            "/home/u/proj/.env.example.local",
            "/home/u/proj/.env.example/.env",
        ] {
            assert!(
                filter.evaluate(&read(p)).await.unwrap().matched,
                "{p} must still fire env-file"
            );
        }
    }

    #[tokio::test]
    async fn test_ssh_dir_list_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::DirList {
            path: "/home/user/.ssh/".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "ssh-dir");
    }

    #[tokio::test]
    async fn test_ssh_config_read_does_not_match_ssh_dir_rule() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.ssh/config".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_env_file_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/project/.env".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "env-file");
    }

    #[tokio::test]
    async fn test_pem_file_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/etc/ssl/cert.pem".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "pem-files");
        assert_eq!(result.score, 4.0);
    }

    #[tokio::test]
    async fn test_pr6_ownership_change_path_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::OwnershipChange {
            target: "/home/user/.ssh/id_ed25519".into(),
            new_uid: 1000,
            new_gid: 1000,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "ssh-private-key");
    }

    #[tokio::test]
    async fn test_pr6_filesystem_mutation_path_matches() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FilesystemMutation {
            op: "mount".into(),
            source: Some("/dev/sda1".into()),
            target: "/project/.env".into(),
            fstype: Some("ext4".into()),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "env-file");
    }

    #[tokio::test]
    async fn test_safe_path_no_match() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/safe.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_wrong_operation_no_match() {
        let filter = PathMatchFilter::new(default_rules());
        // exec is not in the ssh-private-key operations list
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "cat".into(),
            args: vec![],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched); // ShellExec has no path
    }

    #[tokio::test]
    async fn test_no_path_returns_no_match() {
        let filter = PathMatchFilter::new(default_rules());
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://example.com".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_highest_score_wins() {
        let filter = PathMatchFilter::new(default_rules());
        // This path matches both "ssh-private-key" (5.0) and "ssh-dir" (3.0)
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.ssh/id_ed25519".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "ssh-private-key");
        assert_eq!(result.score, 5.0);
    }

    /// A link is judged at **both** ends, worst-of: the target as a read and
    /// the link path as a write (`sensitive_path::path_operations`). So
    /// `ln -s ./mine ~/.ssh/authorized_keys` is priced like the write it
    /// substitutes for rather than like the benign file it names, and
    /// `ln -s ~/.ssh/id_rsa ./artifact` is priced like the read it enables.
    ///
    /// work/83 F9 removed the behavioural novelty signal from `file_link`.
    /// That narrowing rests on this per-end judgement still happening here,
    /// so pin it rather than leave it implicit — if a refactor ever collapses
    /// a link to its primary path, this fails.
    #[tokio::test]
    async fn link_is_judged_at_both_ends() {
        let filter = PathMatchFilter::new(default_rules());

        // Planted AT a protected path; the target is an ordinary project file.
        let ctx = make_ctx(ToolCallType::FileLink {
            target: "/home/user/project/mine.pub".into(),
            link_path: "/home/user/.ssh/authorized_keys".into(),
            symbolic: true,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(
            result.rule_id, "ssh-dir",
            "the link path end must be judged as a write"
        );

        // Exposes a protected path under a benign name; the link path is an
        // ordinary build artifact.
        let ctx = make_ctx(ToolCallType::FileLink {
            target: "/home/user/.ssh/id_rsa".into(),
            link_path: "/home/user/project/build/artifact".into(),
            symbolic: true,
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(
            result.rule_id, "ssh-private-key",
            "the target end must be judged as a read"
        );

        // Neither end named by any rule: no match. Such a link is priced by
        // `operation_risk` alone (0.5) — the residual work/83 F9 accepts
        // deliberately; see the ANOMALY_SCORED_CATEGORIES doc comment.
        let ctx = make_ctx(ToolCallType::FileLink {
            target: "/home/user/project/src/main.rs".into(),
            link_path: "/home/user/project/build/main.rs".into(),
            symbolic: true,
        });
        assert!(!filter.evaluate(&ctx).await.unwrap().matched);
    }

    #[test]
    fn compile_pattern_preserves_each_shipped_rule_shape() {
        use CompiledPattern::{
            BasenameExact, BasenameGlob, HomeGlob, HomePrefix, RootGlob, RootPrefix, SuffixGlob,
            SuffixPrefix,
        };
        assert_eq!(compile_pattern(".env"), BasenameExact(".env".into()));
        assert_eq!(compile_pattern("*.pem"), BasenameGlob("*.pem".into()));
        assert_eq!(compile_pattern(".env.*"), BasenameGlob(".env.*".into()));
        assert_eq!(
            compile_pattern("*credentials*"),
            BasenameGlob("*credentials*".into())
        );
        assert_eq!(compile_pattern("/etc/*"), RootPrefix("/etc/".into()));
        assert_eq!(
            compile_pattern("/etc/shadow"),
            RootGlob("/etc/shadow".into())
        );
        assert_eq!(compile_pattern("~/.aws/*"), HomePrefix(".aws/".into()));
        assert_eq!(compile_pattern("~/.ssh/id_*"), HomeGlob(".ssh/id_*".into()));
        assert_eq!(
            compile_pattern("~/.config/gcloud/*"),
            HomePrefix(".config/gcloud/".into())
        );
        // Operator-authored relative shapes (none shipped).
        assert_eq!(compile_pattern("k8s/*"), SuffixPrefix("k8s/".into()));
        assert_eq!(
            compile_pattern("deploy/secrets.yaml"),
            SuffixGlob("deploy/secrets.yaml".into())
        );
    }

    /// work/83 M7 — the 277-prompts-in-87-seconds case. `/etc/*` is an
    /// ABSOLUTE pattern and must be anchored at the filesystem root.
    #[tokio::test]
    async fn etc_prefix_is_anchored_at_the_filesystem_root() {
        let rules = vec![PathRule {
            id: "etc-system-write".into(),
            pattern: "/etc/*".into(),
            operations: vec!["write".into(), "delete".into()],
            score: 3.0,
            severity: "warning".into(),
            message: "system config".into(),
            exclude: vec![],
            weak_name_signal: false,
        }];
        let filter = PathMatchFilter::new(rules);
        let write = |p: &str| {
            make_ctx(ToolCallType::FileWrite {
                path: p.into(),
                content_hash: String::new(),
            })
        };

        assert!(
            filter
                .evaluate(&write("/etc/nginx/nginx.conf"))
                .await
                .unwrap()
                .matched,
            "a real /etc write must still fire"
        );
        for p in [
            "/p/deps/aria-query/lib/etc/roles/literal/alertdialogRole.js",
            "/home/dan/proj/etc/x.yaml",
            "/home/dan/etc/shadow",
        ] {
            assert!(
                !filter.evaluate(&write(p)).await.unwrap().matched,
                "{p} must NOT match an /etc-anchored rule"
            );
        }
    }

    /// Basename anchoring: `.env` is a file, not a substring, and `*.pem`
    /// globs the basename rather than the whole path.
    #[tokio::test]
    async fn basename_patterns_do_not_match_neighbouring_names() {
        let filter = PathMatchFilter::new(default_rules());
        let read = |p: &str| make_ctx(ToolCallType::FileRead { path: p.into() });

        for p in [
            "/p/.envrc",
            "/p/.environment",
            "/p/.pem-notes/a.js",
            "/p/pemberton.rs",
        ] {
            assert!(
                !filter.evaluate(&read(p)).await.unwrap().matched,
                "{p} must not match a basename rule"
            );
        }
        assert!(filter.evaluate(&read("/p/.env")).await.unwrap().matched);
        assert!(filter.evaluate(&read("/p/a.pem")).await.unwrap().matched);
    }

    /// A `~/`-anchored rule must cover EVERY plausible home root. Anchoring to
    /// the current process's $HOME alone would stop scoring
    /// /root/.aws/credentials — a protection regression, not a narrowing.
    #[tokio::test]
    async fn home_anchored_rules_cover_every_home_root() {
        let rules = vec![PathRule {
            id: "aws-credentials".into(),
            pattern: "~/.aws/*".into(),
            operations: vec!["read".into()],
            score: 4.0,
            severity: "error".into(),
            message: "aws".into(),
            exclude: vec![],
            weak_name_signal: false,
        }];
        let filter = PathMatchFilter::new(rules);
        let read = |p: &str| make_ctx(ToolCallType::FileRead { path: p.into() });

        for p in [
            "/root/.aws/credentials",
            "/home/dan/.aws/credentials",
            "/Users/dan/.aws/credentials",
            "/home/ci-runner/.aws/config",
        ] {
            let r = filter.evaluate(&read(p)).await.unwrap();
            assert!(r.matched, "{p} must fire aws-credentials");
            assert_eq!(r.rule_id, "aws-credentials");
        }
        // An unexpanded tilde from the LLM path still resolves.
        let tilde = filter.evaluate(&read("~/.aws/credentials")).await.unwrap();
        assert!(tilde.matched, "an unexpanded ~/ must still anchor");
        assert_eq!(tilde.rule_id, "aws-credentials");

        // work/83 finding 5: a container / service home is a home too. Anchoring
        // `~/` to the recognised roots alone dropped the rule entirely for
        // `/var/lib/svc` and `/opt/app`, so a dot-directory rule degrades to a
        // component-boundary suffix match.
        for p in ["/opt/build/.aws/credentials", "/var/lib/svc/.aws/config"] {
            let r = filter.evaluate(&read(p)).await.unwrap();
            assert!(r.matched, "{p}: a non-standard home must still match");
            assert_eq!(r.rule_id, "aws-credentials");
        }

        // Not the `.aws` directory, and never a partial component — the
        // fallback is strictly tighter than the substring match it restores.
        for p in [
            "/home/dan/.awsome/notes",
            "/opt/build/aws/credentials",
            "/opt/build/x.aws/credentials",
        ] {
            assert!(
                !filter.evaluate(&read(p)).await.unwrap().matched,
                "{p} must not fire a home-anchored rule"
            );
        }
    }

    /// work/83 F7: only the WEAK filename rules are suppressed inside a
    /// vendored dependency tree. Credential-CLASS rules (`*.pem`, `.env`) keep
    /// firing there — a real credential store planted under `node_modules/`
    /// must still score, and `.pem`/`.key` are not in the taint filter's
    /// sensitive-source list, so suppressing them would leave a private key
    /// both unscored AND untainted. Content/flow/egress filters never consult
    /// this predicate at all.
    #[tokio::test]
    async fn dependency_tree_suppresses_only_the_weak_name_rules() {
        let filter = PathMatchFilter::new(default_rules());
        let write = |p: &str| {
            make_ctx(ToolCallType::FileWrite {
                path: p.into(),
                content_hash: String::new(),
            })
        };

        // Weak filename shapes: a package names its own source files.
        for p in [
            "/p/node_modules/aws-sdk/lib/credentials/sso_credentials.js",
            "/p/node_modules/aws-sdk/clients/secretsmanager.js",
        ] {
            assert!(
                !filter.evaluate(&write(p)).await.unwrap().matched,
                "{p}: weak filename rule must not fire inside a dependency tree"
            );
        }

        // Credential classes are NOT gated, wherever they sit.
        for p in [
            "/p/node_modules/some-pkg/fixtures/test.pem",
            "/p/target/debug/build/x/out/.env",
        ] {
            assert!(
                filter.evaluate(&write(p)).await.unwrap().matched,
                "{p}: a credential-class rule must still fire inside a dependency tree"
            );
        }
        // The same names OUTSIDE a dependency tree still fire.
        assert!(
            filter
                .evaluate(&write("/p/src/.env"))
                .await
                .unwrap()
                .matched
        );
        assert!(
            filter
                .evaluate(&write("/p/certs/test.pem"))
                .await
                .unwrap()
                .matched
        );
    }

    #[test]
    fn glob_star_never_crosses_a_path_separator() {
        assert!(glob_match("*.pem", "cert.pem"));
        assert!(!glob_match("*.pem", "dir/cert.pem"));
        assert!(glob_match(".ssh/id_*", ".ssh/id_rsa"));
        assert!(!glob_match(".ssh/id_*", ".ssh/id_rsa/sub"));
        assert!(glob_match("*credentials*", "service-credentials.json"));
        assert!(glob_match(".env.*", ".env.production"));
        assert!(!glob_match(".env.*", ".env"));
    }
}
