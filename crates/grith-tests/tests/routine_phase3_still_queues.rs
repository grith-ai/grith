// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! PR 4 Phase D critical guardrail: routine spawn + a phase-3 hit
//! still QUEUEs at score `3.5`.
//!
//! This test exists because the work doc rejects "+0.0" as a routine
//! signal: a routine binary that *also* trips a phase-3 filter (taint,
//! behavioural anomaly, etc.) must still escape the auto-allow band.
//! With `+0.5` baseline, the sum is `0.5 + 3.0 = 3.5`, above the
//! `>3.0` QUEUE threshold. If a future refactor lowers
//! `ROUTINE_SPAWN_SCORE` to `0.0`, this test fails loudly.

use grith_proxy::filters::operation_risk::{NON_ROUTINE_SPAWN_SCORE, ROUTINE_SPAWN_SCORE};

#[test]
#[allow(clippy::assertions_on_constants)]
fn routine_score_plus_simulated_phase3_exceeds_queue_threshold() {
    // Simulated phase-3 hit: taint fires at +3.0 for argv referencing
    // tainted paths/env vars (PR 2 condition 1/2). Behavioural anomaly
    // and reputation deviations fire at comparable magnitudes.
    let simulated_phase3 = 3.0_f64;
    let queue_threshold = 3.0_f64;

    let routine_total = ROUTINE_SPAWN_SCORE + simulated_phase3;
    let non_routine_total = NON_ROUTINE_SPAWN_SCORE + simulated_phase3;

    assert!(
        routine_total > queue_threshold,
        "routine ({}) + phase-3 ({}) = {} must exceed QUEUE threshold {} — \
         lowering routine score to 0.0 would silently absorb a phase-3 hit",
        ROUTINE_SPAWN_SCORE,
        simulated_phase3,
        routine_total,
        queue_threshold,
    );
    assert!(non_routine_total > queue_threshold);
    // Confirm the constant itself hasn't drifted to zero.
    assert!(
        (ROUTINE_SPAWN_SCORE - 0.5).abs() < f64::EPSILON,
        "ROUTINE_SPAWN_SCORE must be exactly 0.5, got {ROUTINE_SPAWN_SCORE}",
    );
    // And that the legacy baseline still applies when the signal misses.
    assert!(
        (NON_ROUTINE_SPAWN_SCORE - 1.0).abs() < f64::EPSILON,
        "NON_ROUTINE_SPAWN_SCORE must remain 1.0, got {NON_ROUTINE_SPAWN_SCORE}",
    );
}

/// Defence-in-depth: the routine signal's *only* permitted reduction is
/// 0.5. Any non-zero score still leaves room for additive phase-3 hits.
/// This test enforces the explicit non-zero invariant from the work doc:
/// "Scoring `+0.0` would silently absorb a single phase-3 hit and is
/// explicitly rejected by this PR."
#[test]
#[allow(clippy::assertions_on_constants)]
fn routine_score_is_strictly_positive() {
    assert!(ROUTINE_SPAWN_SCORE > 0.0);
}
