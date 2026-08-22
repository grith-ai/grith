// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! P2 scoring-latency measurement harness (work/77).
//!
//! Measures full-pipeline per-call scoring latency for the DEFAULT filter
//! registry - the exact same construction path the daemon uses
//! (`build_filter_registry_with_config_result` + `build_meta_rule_engine_result`
//! with `ProxyConfig::default()` and the shipped `config/filters/*.toml`) -
//! against a realistic mixed tool-call workload.
//!
//! Unlike `crates/grith-tests/tests/exfil_bench.rs` (per-filter means over
//! batched iterations), this harness times EVERY `SecurityProxy::evaluate`
//! call individually so it can report percentiles (p50/p95/p99), not just
//! means. Not using criterion to avoid adding a dependency - `std::time::
//! Instant` per call, following the exfil_bench pattern.
//!
//! Run in RELEASE mode with output visible:
//!
//! ```text
//! cargo test --release -p grith-core scoring_latency -- --ignored --nocapture
//! ```
//!
//! The test is `#[ignore]`d so debug-mode CI runs don't pay the ~6k
//! evaluations; latency numbers from a debug build are meaningless anyway.

use super::filter_registry::{
    build_filter_registry_with_config_result, build_meta_rule_engine_result,
};
use crate::config::ProxyConfig;
use grith_proxy::engine::SecurityProxy;
use grith_proxy::scoring::ScoringConfig;
use grith_proxy::types::{ProxyAction, ToolCallContext, ToolCallType};
use std::time::Instant;
use uuid::Uuid;

const WARMUP_EVALUATIONS: usize = 500;
const TIMED_EVALUATIONS: usize = 5000;
/// Number of concurrent supervised sessions the workload round-robins
/// across. Stateful phase-3 filters (taint, rate-limit, behavioural,
/// containment) accumulate per-session state, so a handful of sessions
/// each seeing hundreds of calls is closer to real supervisor traffic
/// than either one mega-session or a fresh session per call.
const SESSION_POOL: usize = 8;

/// Build the workload: a realistic mix of supervised-coding-session events.
///
/// Composition (per 100 calls): 40 ordinary project-file reads, 12 project
/// file writes, 5 directory lists, 3 sensitive-path reads (~/.ssh/id_rsa,
/// ~/.aws/credentials, project .env), 15 shell execs, 10 process spawns,
/// 10 HTTP requests, 5 net connects. Percentages follow what a supervised
/// agent coding session actually emits: reads dominate, sensitive touches
/// are rare but present, network is a modest slice.
fn workload_call(i: usize) -> ToolCallType {
    match i % 100 {
        // 40% ordinary project-file reads
        n if n < 40 => {
            let files = [
                "/home/dev/project/src/main.rs",
                "/home/dev/project/src/lib.rs",
                "/home/dev/project/Cargo.toml",
                "/home/dev/project/README.md",
                "/home/dev/project/tests/integration.rs",
                "/home/dev/project/package.json",
                "/home/dev/project/src/components/App.tsx",
                "/home/dev/project/docs/architecture.md",
            ];
            ToolCallType::FileRead {
                path: files[n % files.len()].to_string(),
            }
        }
        // 12% project-file writes
        n if n < 52 => {
            let files = [
                "/home/dev/project/src/main.rs",
                "/home/dev/project/src/new_module.rs",
                "/home/dev/project/Cargo.toml",
                "/home/dev/project/tests/integration.rs",
            ];
            ToolCallType::FileWrite {
                path: files[n % files.len()].to_string(),
                content_hash: format!("{:064x}", n * 7919),
            }
        }
        // 5% directory lists
        n if n < 57 => ToolCallType::DirList {
            path: "/home/dev/project/src".to_string(),
        },
        // 3% sensitive-path reads
        n if n < 60 => {
            let files = [
                "/home/dev/.ssh/id_rsa",
                "/home/dev/.aws/credentials",
                "/home/dev/project/.env",
            ];
            ToolCallType::FileRead {
                path: files[n % files.len()].to_string(),
            }
        }
        // 15% shell execs
        n if n < 75 => {
            let cmds: [(&str, &[&str]); 5] = [
                ("git", &["status", "--porcelain"]),
                ("cargo", &["build", "--release"]),
                ("npm", &["test"]),
                ("grep", &["-rn", "TODO", "src/"]),
                ("ls", &["-la", "/home/dev/project"]),
            ];
            let (command, args) = cmds[n % cmds.len()];
            ToolCallType::ShellExec {
                command: command.to_string(),
                args: args.iter().map(ToString::to_string).collect(),
            }
        }
        // 10% process spawns
        n if n < 85 => {
            let spawns: [(&str, &[&str]); 3] = [
                ("/usr/bin/git", &["diff", "--stat"]),
                ("/usr/bin/node", &["scripts/build.js"]),
                ("/usr/bin/rustc", &["--version"]),
            ];
            let (command, args) = spawns[n % spawns.len()];
            ToolCallType::ProcessSpawn {
                command: command.to_string(),
                args: args.iter().map(ToString::to_string).collect(),
            }
        }
        // 10% HTTP requests
        n if n < 95 => {
            let reqs = [
                ("GET", "https://github.com/grith-ai/grith"),
                ("GET", "https://crates.io/api/v1/crates/tokio"),
                ("POST", "https://api.openai.com/v1/chat/completions"),
            ];
            let (method, url) = reqs[n % reqs.len()];
            ToolCallType::HttpRequest {
                method: method.to_string(),
                url: url.to_string(),
            }
        }
        // 5% net connects
        n => {
            let conns = [("140.82.121.4", 443), ("127.0.0.1", 5432)];
            let (address, port) = conns[n % conns.len()];
            ToolCallType::NetConnect {
                address: address.to_string(),
                port,
            }
        }
    }
}

fn make_ctx(i: usize, sessions: &[Uuid], seq: &mut [u64]) -> ToolCallContext {
    let slot = i % SESSION_POOL;
    seq[slot] += 1;
    let mut ctx =
        ToolCallContext::new("bench", workload_call(i), sessions[slot]).with_profile("claude-code");
    ctx.call_sequence_number = seq[slot];
    ctx
}

fn percentile(sorted_nanos: &[u64], p: f64) -> f64 {
    let idx = ((sorted_nanos.len() as f64) * p).ceil() as usize;
    let idx = idx.clamp(1, sorted_nanos.len()) - 1;
    sorted_nanos[idx] as f64 / 1_000_000.0
}

/// P2 latency measurement: full default 18-filter pipeline, realistic mixed
/// workload, per-call timing, percentile report. See module docs for the
/// invocation command; results are recorded in
/// `work/completed/77-p2-scoring-latency-measurement.md`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "bench: run with `cargo test --release -p grith-core scoring_latency -- --ignored --nocapture`"]
async fn scoring_latency_full_default_pipeline() {
    let proxy_cfg = ProxyConfig::default();
    let (registry, _containment, _canary, _dlp) =
        build_filter_registry_with_config_result(&proxy_cfg)
            .expect("default filter registry must build from shipped config");
    let filter_count = registry.count();
    let meta_rules = build_meta_rule_engine_result().expect("meta rules must load");
    let proxy = SecurityProxy::new(registry, ScoringConfig::default(), meta_rules);

    assert_eq!(
        filter_count, 18,
        "default registry should contain all 18 filters, got {filter_count}"
    );

    let sessions: Vec<Uuid> = (0..SESSION_POOL).map(|_| Uuid::new_v4()).collect();
    let mut seq = vec![0u64; SESSION_POOL];

    // Warmup: exercises lazy initialisation (regex sets, Aho-Corasick
    // automata, session-state allocation) so the timed run measures
    // steady-state latency, which is what a long-lived daemon sees.
    for i in 0..WARMUP_EVALUATIONS {
        let ctx = make_ctx(i, &sessions, &mut seq);
        let _ = proxy.evaluate(&ctx).await;
    }

    // Timed run: every call timed individually so percentiles are exact
    // over the sample, not modelled. Allow-decision latencies are also
    // tracked separately: a deny early-terminates after phase 1 or 2, so
    // allow-only percentiles are the conservative "every filter ran"
    // numbers.
    let mut latencies_ns: Vec<u64> = Vec::with_capacity(TIMED_EVALUATIONS);
    let mut allow_latencies_ns: Vec<u64> = Vec::with_capacity(TIMED_EVALUATIONS);
    let (mut allows, mut queues, mut denies) = (0u32, 0u32, 0u32);
    for i in 0..TIMED_EVALUATIONS {
        let ctx = make_ctx(WARMUP_EVALUATIONS + i, &sessions, &mut seq);
        let start = Instant::now();
        let decision = proxy.evaluate(&ctx).await;
        let elapsed_ns = start.elapsed().as_nanos() as u64;
        latencies_ns.push(elapsed_ns);
        match decision.action {
            ProxyAction::Allow => {
                allows += 1;
                allow_latencies_ns.push(elapsed_ns);
            }
            ProxyAction::Queue { .. } => queues += 1,
            ProxyAction::Deny { .. } => denies += 1,
        }
    }

    latencies_ns.sort_unstable();
    allow_latencies_ns.sort_unstable();
    let mean_ms = latencies_ns.iter().sum::<u64>() as f64 / latencies_ns.len() as f64 / 1_000_000.0;
    let p50 = percentile(&latencies_ns, 0.50);
    let p95 = percentile(&latencies_ns, 0.95);
    let p99 = percentile(&latencies_ns, 0.99);
    let min_ms = latencies_ns[0] as f64 / 1_000_000.0;
    let max_ms = latencies_ns[latencies_ns.len() - 1] as f64 / 1_000_000.0;

    println!("=== P2 scoring latency: full default {filter_count}-filter pipeline ===");
    println!("evaluations: {TIMED_EVALUATIONS} timed (after {WARMUP_EVALUATIONS} warmup), {SESSION_POOL} sessions round-robin");
    println!("decisions:   {allows} allow / {queues} queue / {denies} deny");
    println!("p50:  {p50:.3} ms");
    println!("p95:  {p95:.3} ms");
    println!("p99:  {p99:.3} ms");
    println!("mean: {mean_ms:.3} ms");
    println!("min:  {min_ms:.3} ms   max: {max_ms:.3} ms");
    println!(
        "allow-only (all three phases ran, no early deny termination): p50 {:.3} ms / p95 {:.3} ms / p99 {:.3} ms",
        percentile(&allow_latencies_ns, 0.50),
        percentile(&allow_latencies_ns, 0.95),
        percentile(&allow_latencies_ns, 0.99),
    );

    // Per-filter verification: every registered filter must actually have
    // evaluated calls, otherwise the headline number measures a hollow
    // pipeline. Uses the same FilterMetrics the proxy status API exposes.
    println!("--- per-filter (name, phase, evaluations, mean ms) ---");
    for info in proxy.filter_info() {
        println!(
            "{:<26} {:?}: {} evals, {:.4} ms mean",
            info.name, info.phase, info.evaluation_count, info.avg_latency_ms
        );
        assert!(
            info.evaluation_count > 0,
            "filter {} registered but never evaluated",
            info.name
        );
    }

    // Tie to the documented product target (CLAUDE.md: proxy latency
    // P95 < 15ms per tool call). Generous bound - the point of the
    // harness is the printed numbers, not the assertion.
    assert!(
        p95 < 15.0,
        "p95 {p95:.3} ms exceeds the 15ms product target"
    );
}
