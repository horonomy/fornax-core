//! FORNX-432 PR 1: capacity/memory benchmark harness for
//! [`fornax_verify::independence::SourceFamilyMap::build`] (parent epic
//! FORNX-146, Stage 7A). Measures wall time and output correctness across
//! frozen, deterministic fixture shapes against the v0.0.8-disclosed
//! O(n^2 log n) limitation — see `ancestors_of`'s own doc comment in
//! `fornax-verify` for the real cost source (it rebuilds a full index of
//! the evidence pool on every call, independent of whether the shape has
//! any `derived_from` edges at all).
//!
//! **Every fixture here is synthetic** — frozen by construction
//! (`Uuid::from_u128`, fixed deterministic rules, no RNG, no wall-clock
//! input), never a real workload. This mirrors
//! [`crate::dataset::LabelingProvenance::SyntheticMechanismTest`]'s
//! discipline: every [`FixtureResult`] below carries
//! `contains_synthetic_labels: true` and nothing in this module may be read
//! back as a real-traffic capacity finding.
//!
//! **This module makes no changes to `fornax-verify`'s production
//! behavior.** It is a pure measurement harness over the existing, shipped
//! `SourceFamilyMap::build`/`ancestors_of`. A future PR 2 may optimize
//! those functions; this harness (plus the `bench-reference` feature-gated
//! historical copy in `fornax-verify::independence`) exists so that PR 2's
//! "before" baseline stays reproducible rather than lost the moment the
//! real implementation changes.
//!
//! # Allocation/peak-memory counters
//!
//! This module intentionally does NOT read allocation counters itself —
//! doing so requires a process-wide `#[global_allocator]`, and a *library*
//! crate declaring one would force that allocator onto every downstream
//! consumer of `fornax-bench`'s lib target (including, transitively,
//! anything built in the same workspace graph). The `fornax-bench` *binary*
//! (`main.rs`) owns the counting allocator and supplies the resulting
//! `alloc_count`/`alloc_bytes`/`peak_bytes` into [`FixtureResult`] after
//! calling [`run_fixture`] — this module only measures wall time and
//! correctness.

use std::time::{Duration, Instant};

use fornax_types::sensor::{
    ClockSource, CollectionMethod, EvidenceSource, Freshness, TamperBoundary, TrustClass,
};
use fornax_types::{Evidence, EvidenceKind};
use fornax_verify::independence::SourceFamilyMap;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Fixture sizes used for the three cheap shapes (`flat`,
/// `agent_turn_fanout`, `wide_derived_fanout`): their ancestor-pair output
/// is O(n) or smaller, so even the v0.0.8-disclosed O(n^2 log n) index-
/// rebuild cost (see module docs) stays in the single-digit-seconds range
/// through 10k in a release build.
pub const STANDARD_SIZES: &[usize] = &[100, 1_000, 5_000, 10_000];

/// Fixture sizes used for the two shapes whose stored `DerivationAncestry`
/// pair count is Θ(n^2) (`deep_chain`, `rejoining_dag`) — at n=10_000 that
/// is on the order of 5*10^7 stored pairs, multiple GB of `BTreeSet`
/// overhead. Capped at 2_000 (≈2*10^6 pairs, tens of MB) so this harness
/// measures real quadratic blowup without risking an OOM on a normal dev
/// machine or CI runner.
pub const QUADRATIC_PAIR_SIZES: &[usize] = &[100, 500, 1_000, 2_000];

/// Fixture sizes for `adversarial_dense`: each node's own `derived_from`
/// list has up to n-1 entries, so the *fixture itself* (not just the
/// algorithm's output) is Θ(n^2) in memory. Capped lower than
/// [`QUADRATIC_PAIR_SIZES`] for the same OOM-avoidance reason.
pub const ADVERSARIAL_DENSE_SIZES: &[usize] = &[100, 300, 1_000, 2_000];

/// Wall-time budget (per fixture run) used as a dynamic safety net on top
/// of the static per-shape size caps above: if a run exceeds this, every
/// larger size configured for that shape is skipped and recorded as such,
/// rather than attempted.
pub const TIME_BUDGET: Duration = Duration::from_secs(20);

fn make_evidence(id: u128, event_id: u128, trust: TrustClass, derived_from: Vec<Uuid>) -> Evidence {
    Evidence {
        id: Uuid::from_u128(id),
        session_id: "fornx432-bench".to_string(),
        source_event_id: Uuid::from_u128(event_id),
        kind: EvidenceKind::ExitCode,
        observed_at: "2026-01-01T00:00:00Z".to_string(),
        payload: serde_json::json!({}),
        provenance: "fornx432-bench-fixture".to_string(),
        source: Some(EvidenceSource {
            sensor_name: "fornx432_bench_sensor".to_string(),
            trust_class: trust,
            collected_at: "2026-01-01T00:00:00Z".to_string(),
            provider: None,
            collection_method: CollectionMethod::HookCallback,
            collector_version: None,
            freshness: Freshness {
                clock_source: ClockSource::HostClock,
                caveat: None,
            },
            tamper_boundary: TamperBoundary::default(),
            correlation_group: None,
            derived_from,
        }),
        extension: None,
        evidence_purged: false,
    }
}

/// All `HostObserved`, no edges, no shared `source_event_id` — the
/// baseline shape with zero ancestry/union work, isolating the pure
/// index-rebuild cost every other shape also pays.
pub fn fixture_flat(n: usize) -> Vec<Evidence> {
    (0..n as u128)
        .map(|i| make_evidence(i, i, TrustClass::HostObserved, vec![]))
        .collect()
}

/// k `AgentAdjacent` records per `source_event_id` ("one agent turn fanned
/// out to k sensors"), k cycling 2..=8 — the real `fornax-adapter-claude`
/// shape this whole module exists to measure (see
/// `fornax-verify::independence`'s own module docs).
pub fn fixture_agent_turn_fanout(n: usize) -> Vec<Evidence> {
    let mut out = Vec::with_capacity(n);
    let mut id = 0u128;
    let mut turn = 0u128;
    while out.len() < n {
        let k = 2 + (turn % 7) as usize; // 2..=8
        let take = k.min(n - out.len());
        for _ in 0..take {
            out.push(make_evidence(id, turn, TrustClass::AgentAdjacent, vec![]));
            id += 1;
        }
        turn += 1;
    }
    out
}

/// One root, n-1 children each `derived_from: [root]` — a wide, shallow
/// fanout that unions into a single giant family via Rule 2.
pub fn fixture_wide_derived_fanout(n: usize) -> Vec<Evidence> {
    assert!(n >= 1, "fixture size must be >= 1");
    let root = Uuid::from_u128(0);
    let mut out = vec![make_evidence(0, 0, TrustClass::HostObserved, vec![])];
    for i in 1..n as u128 {
        out.push(make_evidence(i, i, TrustClass::HostObserved, vec![root]));
    }
    out
}

/// A single chain of length n, node i `derived_from: [i-1]`. `ancestors_of`
/// on the tail walks all n-1 ancestors, and the resulting
/// `DerivationAncestry` pair count is Θ(n^2) — the deep-chain half of
/// AC #1's "high-rejoining DAG" requirement.
pub fn fixture_deep_chain(n: usize) -> Vec<Evidence> {
    assert!(n >= 1, "fixture size must be >= 1");
    let mut out = vec![make_evidence(0, 0, TrustClass::HostObserved, vec![])];
    for i in 1..n as u128 {
        out.push(make_evidence(
            i,
            i,
            TrustClass::HostObserved,
            vec![Uuid::from_u128(i - 1)],
        ));
    }
    out
}

/// A layered DAG: layer width `W = max(4, floor(sqrt(n)))`, each node past
/// the first layer `derived_from` K=4 parents in the immediately preceding
/// layer, chosen by a fixed deterministic formula (deduped) — densely
/// rejoining rather than tree-shaped, so `ancestors_of` walks accumulate
/// most of the preceding layers' nodes per query.
pub fn fixture_rejoining_dag(n: usize) -> Vec<Evidence> {
    assert!(n >= 1, "fixture size must be >= 1");
    const PARENTS_PER_NODE: usize = 4;
    let width = ((n as f64).sqrt() as usize).max(4);

    let mut out = Vec::with_capacity(n);
    let first_layer_len = width.min(n);
    for i in 0..first_layer_len {
        out.push(make_evidence(
            i as u128,
            i as u128,
            TrustClass::HostObserved,
            vec![],
        ));
    }

    let mut prev_start = 0usize;
    let mut prev_len = first_layer_len;
    let mut next_id = first_layer_len;
    while next_id < n {
        let layer_len = width.min(n - next_id);
        for j in 0..layer_len {
            let global_i = next_id + j;
            let mut parents: Vec<Uuid> = Vec::with_capacity(PARENTS_PER_NODE);
            for p in 0..PARENTS_PER_NODE {
                let parent_idx = prev_start + ((global_i * 7 + p * 13 + j) % prev_len);
                let parent_uuid = Uuid::from_u128(parent_idx as u128);
                if !parents.contains(&parent_uuid) {
                    parents.push(parent_uuid);
                }
            }
            out.push(make_evidence(
                global_i as u128,
                global_i as u128,
                TrustClass::HostObserved,
                parents,
            ));
        }
        prev_start = next_id;
        prev_len = layer_len;
        next_id += layer_len;
    }
    out
}

/// Worst-case adversarial amplification: node i `derived_from` ALL of
/// 0..i. Every record's ancestry is its own full prefix, so both the
/// fixture's own memory (each `derived_from` list) and the resulting
/// `DerivationAncestry` pair count are Θ(n^2) — hence the much lower size
/// cap ([`ADVERSARIAL_DENSE_SIZES`]) than the other shapes.
pub fn fixture_adversarial_dense(n: usize) -> Vec<Evidence> {
    assert!(n >= 1, "fixture size must be >= 1");
    let mut out = vec![make_evidence(0, 0, TrustClass::HostObserved, vec![])];
    for i in 1..n as u128 {
        let parents: Vec<Uuid> = (0..i).map(Uuid::from_u128).collect();
        out.push(make_evidence(i, i, TrustClass::HostObserved, parents));
    }
    out
}

/// One shape's name, its fixture generator and the sizes to run it at.
pub struct ShapeSpec {
    pub name: &'static str,
    pub sizes: &'static [usize],
    pub generate: fn(usize) -> Vec<Evidence>,
}

/// Every fixture shape this harness runs, in ascending-cost order (cheapest
/// first) — see [`run_all`]'s per-shape early-skip logic, which relies on
/// smaller sizes for a shape running before larger ones.
pub fn shape_specs() -> Vec<ShapeSpec> {
    vec![
        ShapeSpec {
            name: "flat",
            sizes: STANDARD_SIZES,
            generate: fixture_flat,
        },
        ShapeSpec {
            name: "agent_turn_fanout",
            sizes: STANDARD_SIZES,
            generate: fixture_agent_turn_fanout,
        },
        ShapeSpec {
            name: "wide_derived_fanout",
            sizes: STANDARD_SIZES,
            generate: fixture_wide_derived_fanout,
        },
        ShapeSpec {
            name: "rejoining_dag",
            sizes: QUADRATIC_PAIR_SIZES,
            generate: fixture_rejoining_dag,
        },
        ShapeSpec {
            name: "deep_chain",
            sizes: QUADRATIC_PAIR_SIZES,
            generate: fixture_deep_chain,
        },
        ShapeSpec {
            name: "adversarial_dense",
            sizes: ADVERSARIAL_DENSE_SIZES,
            generate: fixture_adversarial_dense,
        },
    ]
}

/// Stable hash of a built [`SourceFamilyMap`]'s observable output
/// (`all_families()`) — correctness recorded next to speed, not measured
/// separately. Two runs (e.g. `build` vs. the `bench-reference` copy)
/// producing the same hash is the harness's own correctness check.
pub fn hash_families(map: &SourceFamilyMap) -> String {
    let encoded =
        serde_json::to_vec(map.all_families()).expect("SourceFamily/FamilyBasis always serialize");
    format!("sha256:{}", hex::encode(Sha256::digest(&encoded)))
}

/// One fixture's measured result. Allocation fields are filled in by the
/// caller (the `fornax-bench` binary, which owns the `#[global_allocator]`)
/// after calling [`run_fixture`] — see module docs.
#[derive(Debug, Clone, Serialize)]
pub struct FixtureResult {
    pub shape: &'static str,
    pub size: usize,
    pub evidence_count: usize,
    pub family_count: usize,
    pub wall_time_ms: f64,
    pub families_hash: String,
    /// `None` until the binary fills it in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alloc_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alloc_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_bytes: Option<u64>,
    /// Also hashed against `fornax_verify::independence::build_reference`
    /// (built only with `--features fornax-verify/bench-reference`) when
    /// that feature is compiled in — `None` otherwise. Mismatch would mean
    /// `build` and `build_reference` have diverged, which must never
    /// happen inside this PR (PR 1 makes no production-code change).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_hash_matches: Option<bool>,
    pub contains_synthetic_labels: bool,
}

/// Why a size was not run for a shape.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedFixture {
    pub shape: &'static str,
    pub size: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapacityReport {
    pub results: Vec<FixtureResult>,
    pub skipped: Vec<SkippedFixture>,
    pub time_budget_seconds: f64,
    pub contains_synthetic_labels: bool,
    pub note: &'static str,
}

/// Builds one fixture and runs `SourceFamilyMap::build` over it, measuring
/// wall time and the output's stable hash. Does not touch allocation
/// counters (see module docs) — the caller fills those in.
pub fn run_fixture(shape: &'static str, size: usize) -> (Duration, FixtureResult) {
    let evidence = (shape_specs()
        .into_iter()
        .find(|s| s.name == shape)
        .expect("unknown shape")
        .generate)(size);

    let start = Instant::now();
    let map = SourceFamilyMap::build(&evidence);
    let elapsed = start.elapsed();

    let families_hash = hash_families(&map);

    #[cfg(feature = "bench-reference")]
    let reference_hash_matches = {
        let reference_map = fornax_verify::independence::build_reference(&evidence);
        Some(hash_families(&reference_map) == families_hash)
    };
    #[cfg(not(feature = "bench-reference"))]
    let reference_hash_matches = None;

    let result = FixtureResult {
        shape,
        size,
        evidence_count: evidence.len(),
        family_count: map.all_families().len(),
        wall_time_ms: elapsed.as_secs_f64() * 1000.0,
        families_hash,
        alloc_count: None,
        alloc_bytes: None,
        peak_bytes: None,
        reference_hash_matches,
        contains_synthetic_labels: true,
    };
    (elapsed, result)
}

/// Runs every shape/size combination from [`shape_specs`], applying the
/// [`TIME_BUDGET`] early-skip rule: once a shape's run at some size exceeds
/// the budget, every larger configured size for that shape is skipped
/// (recorded in `skipped`, never silently dropped) rather than attempted.
/// Allocation fields on each [`FixtureResult`] are left `None` — the
/// caller (the binary, with its `#[global_allocator]`) re-runs
/// [`run_fixture`] itself per combination so it can reset/read its
/// counters around the exact same call; see `main.rs`.
pub fn planned_runs() -> Vec<(&'static str, usize)> {
    let mut plan = Vec::new();
    for spec in shape_specs() {
        for &size in spec.sizes {
            plan.push((spec.name, size));
        }
    }
    plan
}

/// Given the results actually produced so far for a shape (in ascending
/// size order), decides whether the next configured size should still be
/// attempted, per the [`TIME_BUDGET`] rule.
pub fn should_skip_remaining(last_elapsed: Duration) -> bool {
    last_elapsed > TIME_BUDGET
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_fixture_shape_produces_the_requested_count() {
        assert_eq!(fixture_flat(50).len(), 50);
        assert_eq!(fixture_agent_turn_fanout(50).len(), 50);
        assert_eq!(fixture_wide_derived_fanout(50).len(), 50);
        assert_eq!(fixture_deep_chain(50).len(), 50);
        assert_eq!(fixture_rejoining_dag(50).len(), 50);
        assert_eq!(fixture_adversarial_dense(50).len(), 50);
    }

    #[test]
    fn flat_fixture_is_all_singleton_families() {
        let evidence = fixture_flat(20);
        let map = SourceFamilyMap::build(&evidence);
        assert_eq!(map.all_families().len(), 20);
    }

    #[test]
    fn wide_derived_fanout_is_one_family() {
        let evidence = fixture_wide_derived_fanout(20);
        let map = SourceFamilyMap::build(&evidence);
        assert_eq!(map.all_families().len(), 1);
        assert_eq!(map.all_families()[0].evidence_ids.len(), 20);
    }

    #[test]
    fn deep_chain_is_one_family() {
        let evidence = fixture_deep_chain(30);
        let map = SourceFamilyMap::build(&evidence);
        assert_eq!(map.all_families().len(), 1);
        assert_eq!(map.all_families()[0].evidence_ids.len(), 30);
    }

    #[test]
    fn agent_turn_fanout_groups_by_turn() {
        let evidence = fixture_agent_turn_fanout(100);
        let map = SourceFamilyMap::build(&evidence);
        // Every family must have size in [2, 8] (the k range used above),
        // and family sizes must sum back to the evidence count.
        let total: usize = map
            .all_families()
            .iter()
            .map(|f| f.evidence_ids.len())
            .sum();
        assert_eq!(total, 100);
        for family in map.all_families() {
            assert!((2..=8).contains(&family.evidence_ids.len()));
        }
    }

    #[test]
    fn hashing_is_deterministic_for_the_same_fixture() {
        let evidence = fixture_rejoining_dag(80);
        let map_a = SourceFamilyMap::build(&evidence);
        let map_b = SourceFamilyMap::build(&evidence);
        assert_eq!(hash_families(&map_a), hash_families(&map_b));
    }

    #[test]
    fn planned_runs_covers_every_shape() {
        let plan = planned_runs();
        for spec in shape_specs() {
            assert!(plan.iter().any(|(name, _)| *name == spec.name));
        }
    }

    #[test]
    fn run_fixture_reports_a_hash_and_matching_counts() {
        let (_elapsed, result) = run_fixture("flat", 30);
        assert_eq!(result.evidence_count, 30);
        assert_eq!(result.family_count, 30);
        assert!(result.families_hash.starts_with("sha256:"));
        assert!(result.contains_synthetic_labels);
    }
}
