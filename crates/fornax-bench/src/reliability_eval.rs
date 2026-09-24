//! Contextual-reliability decision-value evaluation mechanism (FORNX-104 AC
//! 5: "benchmark demonstrates whether contextual reliability adds marginal
//! decision value").
//!
//! **This module builds the evaluation mechanism only — it does not, and
//! cannot yet, demonstrate a real marginal-value finding.** Exactly like
//! `fornax-bench::dataset`'s own gate (FORNX-95), no real labeled dataset
//! and no real historical [`ReliabilityObservation`] corpus exist in this
//! repository yet: `fornax_verify::reliability` has no live producer of
//! observations (see that module's "out of scope" section). Every test in
//! this module runs against synthetic fixtures, stamped
//! [`crate::dataset::LabelingProvenance::SyntheticMechanismTest`] like every
//! other fixture in this crate, and asserts only that the mechanism runs
//! and produces two *different* [`crate::metrics::MetricsReport`]s — never
//! that one is better than the other. A real finding requires a real
//! dataset; this module is what will consume one once it exists.
//!
//! # What is compared
//!
//! [`run_reliability_eval`] runs [`crate::harness::run_harness`] once over a
//! dataset (the "without contextual reliability" baseline — today's actual
//! `fornax-verify` pipeline), then re-derives a second set of
//! [`crate::harness::PredictionRecord`]s by adjusting each trajectory's
//! `predicted_action` using [`adjust_action_with_reliability`] and a
//! [`fornax_verify::reliability::ReliabilitySignal`] computed for that
//! trajectory's assigned cohort (the "with contextual reliability" arm).
//! [`crate::metrics::compute_metrics`] scores both arms, unmodified.
//!
//! # Why a side table, not a `LabeledTrajectory` field
//!
//! [`crate::dataset::LabeledTrajectory`]/[`crate::dataset::Dataset`] are
//! FORNX-95's frozen wire format — `Dataset::content_hash` is a
//! reproducibility pin over the exact bytes of that format
//! (`crate::dataset::content_hash_of`). Adding a
//! `reliability_context_key` field to `LabeledTrajectory` would change that
//! format and invalidate every existing frozen dataset's hash for a concern
//! (which cohort a trajectory belongs to) that this ticket's AC never asked
//! `fornax-bench`'s core wire format to carry. [`TrajectoryContextAssignment`]
//! is an external side table instead — exactly the same shape choice
//! `fornax_types::RawRepositoryContext` made to keep a raw, ticket-specific
//! concern out of a schema another ticket owns.
//!
//! # The adjustment rule itself is illustrative, not calibrated
//!
//! [`adjust_action_with_reliability`] is a simple, explicit, two-sided rule
//! (a well-supported, reliable cohort can relax `Review` to `Proceed`; a
//! well-supported, unreliable cohort can escalate `Proceed` to `Review`) —
//! not derived from any real calibration study. It never touches `Block`
//! (this ticket does not revisit `DefaultRiskPolicy`'s `Block` safety
//! floors, pinned by `block_is_never_touched_by_either_direction`), and a
//! sparse/new context
//! ([`fornax_verify::reliability::ReliabilitySignal::reliability_estimate`]
//! is `None`) never changes the action at all — see module docs on
//! `fornax_verify::reliability` and FORNX-104 AC 2: sparse contexts must
//! stay uncertain, not borrow unjustified certainty in either direction.
//! Both directions are exercised directly
//! (`relax_direction_fires_on_a_well_supported_reliable_cohort`/
//! `escalate_direction_fires_on_a_well_supported_unreliable_cohort`); the
//! end-to-end `run_reliability_eval` test fixture only naturally exercises
//! the relax direction, since its baseline action is `Review`, never
//! `Proceed`.

use std::collections::HashMap;

use fornax_types::ReliabilityContextKey;
use fornax_verify::decision::RecommendationAction;
use fornax_verify::reliability::{compute_reliability, ReliabilityObservation, ReliabilitySignal};

use crate::dataset::Dataset;
use crate::harness::{run_harness, HarnessConfig, PredictionRecord};
use crate::metrics::{compute_metrics, MetricsReport};

/// The confidence-interval bound at or above which a well-supported cohort
/// is treated as reliable enough to relax a `Review` down to `Proceed`. See
/// module docs, "The adjustment rule itself is illustrative, not
/// calibrated."
///
/// This threshold is deliberately far above what a cohort at exactly
/// [`fornax_types::MINIMUM_COHORT_SAMPLE_SUPPORT`] can ever reach: even an
/// all-`Reliable` cohort of 30 observations has a Wilson lower bound around
/// 0.89, not 0.95 — the interval is still wide at minimum support. Relaxing
/// a `Review` is the direction that *reduces* caution, so this rule
/// requires substantially more than the bare minimum support before it can
/// fire at all (empirically, an all-`Reliable` cohort needs roughly n>=100
/// to clear 0.95) — unreachable at minimum support today, on the same
/// "unreachable on real traffic today, by design" honesty
/// `crate::fusion::UncertaintyBand::Corroborated` documents about itself.
const RELAX_LOWER_BOUND_THRESHOLD: f64 = 0.95;

/// The confidence-interval bound at or below which a well-supported cohort
/// is treated as unreliable enough to escalate a `Proceed` up to `Review`.
const ESCALATE_UPPER_BOUND_THRESHOLD: f64 = 0.5;

/// Which [`ReliabilityContextKey`] a given trajectory (by
/// [`crate::dataset::LabeledTrajectory::id`]) should be evaluated under, for
/// this evaluation run only. See module docs, "Why a side table."
#[derive(Debug, Clone)]
pub struct TrajectoryContextAssignment {
    pub trajectory_id: String,
    pub context_key: ReliabilityContextKey,
}

/// Adjust a base [`RecommendationAction`] using a
/// [`ReliabilitySignal`]. Pure. See module docs for the rule and its
/// deliberate scope limits (never touches `Block`, never acts on a sparse
/// signal).
pub fn adjust_action_with_reliability(
    base: RecommendationAction,
    signal: &ReliabilitySignal,
) -> RecommendationAction {
    let Some(estimate) = &signal.reliability_estimate else {
        // Sparse/new context: never borrow unjustified certainty in either
        // direction (FORNX-104 AC 2).
        return base;
    };

    if base == RecommendationAction::Review
        && estimate.confidence_interval.lower >= RELAX_LOWER_BOUND_THRESHOLD
    {
        RecommendationAction::Proceed
    } else if base == RecommendationAction::Proceed
        && estimate.confidence_interval.upper <= ESCALATE_UPPER_BOUND_THRESHOLD
    {
        RecommendationAction::Review
    } else {
        base
    }
}

/// Output of [`run_reliability_eval`]: the same dataset scored twice, once
/// without and once with the contextual-reliability adjustment applied.
#[derive(Debug, Clone, PartialEq)]
pub struct ReliabilityEvalResult {
    pub without_reliability: MetricsReport,
    pub with_reliability: MetricsReport,
}

/// Runs the real `fornax-verify` pipeline over `dataset` once
/// (`without_reliability`), then re-derives a second prediction set with
/// [`adjust_action_with_reliability`] applied per-trajectory using a
/// [`ReliabilitySignal`] computed from `observations` against whatever
/// [`ReliabilityContextKey`] `assignments` names for that trajectory
/// (`with_reliability`). A trajectory with no entry in `assignments` is left
/// unadjusted in the second arm. Pure and deterministic given `computed_at`
/// — see [`crate::harness::run_harness`]'s own determinism guarantee, which
/// this function inherits unchanged for its baseline arm.
pub fn run_reliability_eval(
    dataset: &Dataset,
    harness_config: &HarnessConfig,
    assignments: &[TrajectoryContextAssignment],
    observations: &[ReliabilityObservation],
    policy_version: u32,
    computed_at: &str,
) -> ReliabilityEvalResult {
    let baseline = run_harness(dataset, harness_config, computed_at);

    let assignment_by_trajectory: HashMap<&str, &ReliabilityContextKey> = assignments
        .iter()
        .map(|a| (a.trajectory_id.as_str(), &a.context_key))
        .collect();

    let adjusted: Vec<PredictionRecord> = baseline
        .iter()
        .map(|p| {
            let mut adjusted_record = p.clone();
            if let Some(context_key) = assignment_by_trajectory.get(p.trajectory_id.as_str()) {
                let signal = compute_reliability(context_key, observations, policy_version);
                adjusted_record.predicted_action =
                    adjust_action_with_reliability(p.predicted_action, &signal);
            }
            adjusted_record
        })
        .collect();

    ReliabilityEvalResult {
        without_reliability: compute_metrics(&baseline),
        with_reliability: compute_metrics(&adjusted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataset::{AdjudicatedExpectedOutcome, LabelingProvenance};
    use fornax_types::{
        aggregate_context, CapabilitySignal, Claim, Evidence, EvidenceGraph, EvidenceKind,
        EvidenceLink, EvidenceRelation, EvidenceSource, ModelFamily, Provider,
        RawReliabilityContext, RawRepositoryContext, RepositoryClass, RuntimeCapabilities,
        SignalAvailability, SignalClass, TaskClass, ToolClass, TrustClass, Verdict,
        CAPABILITY_SCHEMA_VERSION, MINIMUM_COHORT_SAMPLE_SUPPORT,
    };
    use fornax_verify::decision::RiskClass;
    use fornax_verify::reliability::{ObservationOutcome, RELIABILITY_POLICY_VERSION};
    use std::collections::HashMap as StdHashMap;
    use uuid::Uuid;

    fn caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: CAPABILITY_SCHEMA_VERSION,
            provider: Provider::ClaudeCode,
            signals: vec![CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            }],
            notes: StdHashMap::new(),
        }
    }

    fn context_key() -> ReliabilityContextKey {
        aggregate_context(RawReliabilityContext {
            provider: Provider::ClaudeCode,
            model_family: ModelFamily::Claude,
            model_version: "claude-sonnet-5".to_string(),
            adapter_version: "0.0.4".to_string(),
            task_class: TaskClass::TestExecution,
            toolset: vec![ToolClass::Shell],
            repository: RawRepositoryContext {
                identifying_hint: None,
                class: RepositoryClass::PublicOss,
            },
            policy_version: "policy-v3".to_string(),
            verifier_version: "verifier-v2".to_string(),
            fusion_version: "fusion-v1".to_string(),
            capabilities: caps(),
        })
    }

    /// A single-clean-Supports-vote trajectory: fusion always resolves this
    /// to `Verified` with an `IndependenceUnverified` caveat (no correlation
    /// group recorded), which `UncertaintyBand::Qualified` puts at
    /// `RecommendationAction::Review` under `RiskClass::Balanced` — the
    /// exact `Review` starting point `adjust_action_with_reliability` can
    /// relax to `Proceed`. Mirrors `fornax-bench::harness`'s own
    /// `calls_the_real_fusion_and_decision_pipeline_and_produces_a_report`
    /// fixture shape.
    fn trajectory(id: &str) -> crate::dataset::LabeledTrajectory {
        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        };
        let evidence = Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test".into(),
            source: Some(EvidenceSource {
                sensor_name: "test_sensor_v1".into(),
                trust_class: TrustClass::AgentAdjacent,
                collected_at: "2026-01-01T00:00:00Z".into(),
                provider: None,
                collection_method: fornax_types::CollectionMethod::HookCallback,
                collector_version: None,
                freshness: fornax_types::Freshness {
                    clock_source: fornax_types::ClockSource::HostClock,
                    caveat: None,
                },
                tamper_boundary: Default::default(),
                correlation_group: None,
                derived_from: vec![],
            }),
            extension: None,
        };
        let link = EvidenceLink {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            claim_id: claim.id,
            evidence_id: evidence.id,
            relation: EvidenceRelation::Supports,
            linked_at: "2026-01-01T00:00:00Z".into(),
        };
        crate::dataset::LabeledTrajectory {
            id: id.into(),
            claim,
            evidence_graph: EvidenceGraph {
                links: vec![link],
                missing: vec![],
            },
            evidence_pool: vec![evidence],
            adjudicated_expected_outcome: AdjudicatedExpectedOutcome {
                expected_verdict: Verdict::Verified,
                critical_failure: false,
                notes: None,
            },
            labeling_provenance: LabelingProvenance::SyntheticMechanismTest {
                created_by: "test".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                notes: None,
            },
        }
    }

    fn dataset_of(trajectories: Vec<crate::dataset::LabeledTrajectory>) -> Dataset {
        Dataset {
            dataset_version: "0.0.0-mechanism-test".into(),
            description: "reliability eval mechanism test fixture".into(),
            trajectories,
            content_hash: "test-hash".into(),
        }
    }

    fn reliable_observations(key: &ReliabilityContextKey, n: usize) -> Vec<ReliabilityObservation> {
        (0..n)
            .map(|_| ReliabilityObservation {
                context_key: key.clone(),
                outcome: ObservationOutcome::Reliable,
            })
            .collect()
    }

    fn n_reliable_of(
        key: &ReliabilityContextKey,
        reliable: usize,
        total: usize,
    ) -> Vec<ReliabilityObservation> {
        let mut outcomes = vec![ObservationOutcome::Reliable; reliable];
        outcomes.extend(vec![ObservationOutcome::Unreliable; total - reliable]);
        outcomes
            .into_iter()
            .map(|outcome| ReliabilityObservation {
                context_key: key.clone(),
                outcome,
            })
            .collect()
    }

    // --- adjust_action_with_reliability: both directions, in isolation ----

    #[test]
    fn relax_direction_fires_on_a_well_supported_reliable_cohort() {
        let key = context_key();
        let observations = reliable_observations(&key, 150);
        let signal = compute_reliability(&key, &observations, RELIABILITY_POLICY_VERSION);
        assert_eq!(
            adjust_action_with_reliability(RecommendationAction::Review, &signal),
            RecommendationAction::Proceed
        );
    }

    #[test]
    fn escalate_direction_fires_on_a_well_supported_unreliable_cohort() {
        let key = context_key();
        // 5-of-60 Reliable: well above minimum support, Wilson upper bound
        // comfortably under 0.5 -- the escalate branch's actual firing
        // condition, exercised directly since no harness fixture in this
        // module's dataset naturally produces a base `Proceed` action to
        // escalate from.
        let observations = n_reliable_of(&key, 5, 60);
        let signal = compute_reliability(&key, &observations, RELIABILITY_POLICY_VERSION);
        assert!(
            signal
                .reliability_estimate
                .as_ref()
                .unwrap()
                .confidence_interval
                .upper
                <= ESCALATE_UPPER_BOUND_THRESHOLD,
            "fixture must actually clear the escalate threshold, not just be low"
        );
        assert_eq!(
            adjust_action_with_reliability(RecommendationAction::Proceed, &signal),
            RecommendationAction::Review
        );
    }

    #[test]
    fn neither_direction_fires_on_a_mid_reliability_cohort() {
        let key = context_key();
        let observations = n_reliable_of(&key, 30, 60);
        let signal = compute_reliability(&key, &observations, RELIABILITY_POLICY_VERSION);
        assert_eq!(
            adjust_action_with_reliability(RecommendationAction::Review, &signal),
            RecommendationAction::Review
        );
        assert_eq!(
            adjust_action_with_reliability(RecommendationAction::Proceed, &signal),
            RecommendationAction::Proceed
        );
    }

    #[test]
    fn block_is_never_touched_by_either_direction() {
        let key = context_key();
        let strong = compute_reliability(
            &key,
            &reliable_observations(&key, 150),
            RELIABILITY_POLICY_VERSION,
        );
        let weak = compute_reliability(
            &key,
            &n_reliable_of(&key, 5, 60),
            RELIABILITY_POLICY_VERSION,
        );
        assert_eq!(
            adjust_action_with_reliability(RecommendationAction::Block, &strong),
            RecommendationAction::Block
        );
        assert_eq!(
            adjust_action_with_reliability(RecommendationAction::Block, &weak),
            RecommendationAction::Block
        );
    }

    #[test]
    fn baseline_pipeline_alone_reviews_a_clean_single_vote_trajectory() {
        // Sanity check pinning the starting point the adjustment rule acts
        // on -- matches fornax-bench::harness's own equivalent fixture.
        let dataset = dataset_of(vec![trajectory("traj-1")]);
        let config = HarnessConfig::new(RiskClass::Balanced);
        let predictions = run_harness(&dataset, &config, "2026-01-02T00:00:00Z");
        assert_eq!(predictions[0].predicted_verdict, Verdict::Verified);
        assert_eq!(
            predictions[0].predicted_action,
            RecommendationAction::Review
        );
    }

    #[test]
    fn well_supported_reliable_cohort_relaxes_review_to_proceed_in_the_with_reliability_arm() {
        let key = context_key();
        let dataset = dataset_of(vec![trajectory("traj-1")]);
        let config = HarnessConfig::new(RiskClass::Balanced);
        let assignments = vec![TrajectoryContextAssignment {
            trajectory_id: "traj-1".into(),
            context_key: key.clone(),
        }];
        // A clean, uniformly-reliable, well-supported cohort. n=150 all-
        // Reliable clears the Wilson 95%-lower-bound relax threshold
        // (0.95) with margin; n at exactly MINIMUM_COHORT_SAMPLE_SUPPORT
        // would not, since the interval is still wide at minimum support.
        let observations = reliable_observations(&key, 150);

        let result = run_reliability_eval(
            &dataset,
            &config,
            &assignments,
            &observations,
            RELIABILITY_POLICY_VERSION,
            "2026-01-02T00:00:00Z",
        );

        assert_eq!(
            result.without_reliability.review_burden,
            Some(1.0),
            "baseline arm: the one trajectory is Review"
        );
        assert_eq!(
            result.with_reliability.review_burden,
            Some(0.0),
            "reliability-aware arm: relaxed to Proceed"
        );
        // The deliverable is the mechanism, not a claimed finding -- the two
        // reports must genuinely differ, and neither is asserted "better".
        assert_ne!(result.without_reliability, result.with_reliability);
    }

    #[test]
    fn sparse_context_leaves_the_with_reliability_arm_unchanged() {
        let key = context_key();
        let dataset = dataset_of(vec![trajectory("traj-1")]);
        let config = HarnessConfig::new(RiskClass::Balanced);
        let assignments = vec![TrajectoryContextAssignment {
            trajectory_id: "traj-1".into(),
            context_key: key.clone(),
        }];
        // Below MINIMUM_COHORT_SAMPLE_SUPPORT -- must never borrow
        // unjustified certainty (FORNX-104 AC 2), so the action must not
        // change even though every observation happens to be Reliable.
        let observations =
            reliable_observations(&key, (MINIMUM_COHORT_SAMPLE_SUPPORT - 1) as usize);

        let result = run_reliability_eval(
            &dataset,
            &config,
            &assignments,
            &observations,
            RELIABILITY_POLICY_VERSION,
            "2026-01-02T00:00:00Z",
        );

        assert_eq!(result.without_reliability, result.with_reliability);
    }

    #[test]
    fn unassigned_trajectory_is_left_unadjusted() {
        let dataset = dataset_of(vec![trajectory("traj-1")]);
        let config = HarnessConfig::new(RiskClass::Balanced);
        let result = run_reliability_eval(
            &dataset,
            &config,
            &[], // no assignment for traj-1
            &[],
            RELIABILITY_POLICY_VERSION,
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(result.without_reliability, result.with_reliability);
    }

    #[test]
    fn eval_result_is_derived_from_synthetic_labels_only() {
        // Exercises the honesty gate this ticket must not bypass: the
        // dataset's own synthetic-labeling discipline still applies to
        // whatever MetricsReport this mechanism produces.
        let dataset = dataset_of(vec![trajectory("traj-1")]);
        assert!(dataset.contains_synthetic_labels());
        let config = HarnessConfig::new(RiskClass::Balanced);
        let result = run_reliability_eval(
            &dataset,
            &config,
            &[],
            &[],
            RELIABILITY_POLICY_VERSION,
            "2026-01-02T00:00:00Z",
        );
        assert!(result.without_reliability.contains_synthetic_labels);
        assert!(result.with_reliability.contains_synthetic_labels);
    }
}
