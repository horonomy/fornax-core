//! Per-sensor ablation sweep (FORNX-95 AC: "each production sensor has
//! measurable marginal-value evidence or explicit non-value finding").
//!
//! [`run_ablation`] runs [`crate::harness::run_harness`] once as the
//! baseline (nothing disabled), then once more per named sensor with that
//! sensor's evidence stripped (see [`crate::harness::apply_ablation`]'s doc
//! comment for exactly what "stripped" means over frozen input), and
//! reports the metrics delta plus how many trajectories moved from
//! evaluable into the evidence-unavailable bucket as a direct result of
//! removing that one sensor.
//!
//! This module makes no claim about which sensors are "worth keeping" — it
//! only computes deltas. Whether a given delta is large enough to justify a
//! sensor's cost is a judgment call for whoever reads a real (non-synthetic)
//! run's output, which does not exist yet — see the dataset module docs and
//! this ticket's PR body.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::dataset::Dataset;
use crate::harness::{run_harness, HarnessConfig};
use crate::metrics::{compute_metrics, MetricsReport};

/// Signed delta of two `Option<f64>` rates: `Some(ablated - baseline)` only
/// when both sides are `Some`; `None` whenever either side had no data,
/// rather than treating a missing rate as `0.0` and fabricating a delta
/// against it.
fn delta(baseline: Option<f64>, ablated: Option<f64>) -> Option<f64> {
    match (baseline, ablated) {
        (Some(b), Some(a)) => Some(a - b),
        _ => None,
    }
}

/// One sensor's ablation result: its full baseline and ablated
/// [`MetricsReport`]s, plus the deltas a reader most likely wants without
/// re-subtracting the two reports by hand.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AblationResult {
    pub sensor_name: String,
    pub baseline: MetricsReport,
    pub ablated: MetricsReport,
    pub evidence_coverage_delta: Option<f64>,
    pub critical_failure_recall_delta: Option<f64>,
    pub precision_delta: Option<f64>,
    pub false_positive_rate_delta: Option<f64>,
    pub review_burden_delta: Option<f64>,
    /// Count of trajectories where the baseline run had
    /// `evidence_unavailable == false` but the ablated run had it `true` —
    /// i.e. this sensor's evidence was the thing that made the trajectory
    /// evaluable at all. This is a distinct marginal-value signal from the
    /// metric deltas above: a sensor can move trajectories into
    /// evidence-unavailable without changing `correct_count` at all (if
    /// those trajectories were already going to predict the same verdict
    /// via other evidence) — reporting this count separately is what keeps
    /// that case from disappearing into a zero-looking recall/precision
    /// delta.
    pub trajectories_moved_to_unavailable: usize,
    /// True if either the baseline or ablated run drew on any synthetic
    /// record — propagated so a caller cannot read this result as a real
    /// marginal-value finding when it is a mechanism-verification run.
    pub contains_synthetic_labels: bool,
}

/// Runs the baseline (`base_config` as given) once, then once more per
/// sensor name in `sensor_names` with that sensor added to
/// `base_config.disabled_sensors`, and reports each sensor's
/// [`AblationResult`]. `sensor_names` is iterated in its own (typically
/// `BTreeSet`, already sorted) order so results are deterministic and
/// reproducible (AC 1) regardless of caller-side ordering.
///
/// Honest on an empty or synthetic-only dataset: every [`MetricsReport`]
/// this produces already reports `None` rates rather than fabricated
/// numbers (see [`crate::metrics`]'s module docs), and
/// `contains_synthetic_labels` is always set from the actual records that
/// produced each result — this function does not special-case "no data" any
/// further because [`compute_metrics`] already refuses to fabricate it.
pub fn run_ablation(
    dataset: &Dataset,
    base_config: &HarnessConfig,
    sensor_names: &BTreeSet<String>,
    computed_at: &str,
) -> Vec<AblationResult> {
    let baseline_predictions = run_harness(dataset, base_config, computed_at);
    let baseline_metrics = compute_metrics(&baseline_predictions);

    sensor_names
        .iter()
        .map(|sensor_name| {
            let ablated_config = base_config.with_sensor_disabled(sensor_name);
            let ablated_predictions = run_harness(dataset, &ablated_config, computed_at);
            let ablated_metrics = compute_metrics(&ablated_predictions);

            let moved = baseline_predictions
                .iter()
                .zip(ablated_predictions.iter())
                .filter(|(b, a)| {
                    debug_assert_eq!(
                        b.trajectory_id, a.trajectory_id,
                        "baseline/ablated predictions must be in the same trajectory order"
                    );
                    !b.evidence_unavailable && a.evidence_unavailable
                })
                .count();

            AblationResult {
                sensor_name: sensor_name.clone(),
                evidence_coverage_delta: delta(
                    baseline_metrics.evidence_coverage,
                    ablated_metrics.evidence_coverage,
                ),
                critical_failure_recall_delta: delta(
                    baseline_metrics.critical_failure_recall,
                    ablated_metrics.critical_failure_recall,
                ),
                precision_delta: delta(baseline_metrics.precision, ablated_metrics.precision),
                false_positive_rate_delta: delta(
                    baseline_metrics.false_positive_rate,
                    ablated_metrics.false_positive_rate,
                ),
                review_burden_delta: delta(
                    baseline_metrics.review_burden,
                    ablated_metrics.review_burden,
                ),
                trajectories_moved_to_unavailable: moved,
                contains_synthetic_labels: baseline_metrics.contains_synthetic_labels
                    || ablated_metrics.contains_synthetic_labels,
                baseline: baseline_metrics.clone(),
                ablated: ablated_metrics,
            }
        })
        .collect()
}

#[cfg(test)]
mod ablation_tests {
    use super::*;
    use crate::dataset::{AdjudicatedExpectedOutcome, LabeledTrajectory, LabelingProvenance};
    use fornax_types::{
        Claim, ClockSource, CollectionMethod, Evidence, EvidenceGraph, EvidenceKind, EvidenceLink,
        EvidenceRelation, EvidenceSource, Freshness, TrustClass, Verdict,
    };
    use fornax_verify::decision::RiskClass;
    use uuid::Uuid;

    fn evidence_with_sensor(sensor_name: &str) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test".into(),
            source: Some(EvidenceSource {
                sensor_name: sensor_name.into(),
                trust_class: TrustClass::AgentAdjacent,
                collected_at: "2026-01-01T00:00:00Z".into(),
                provider: None,
                collection_method: CollectionMethod::HookCallback,
                collector_version: None,
                freshness: Freshness {
                    clock_source: ClockSource::HostClock,
                    caveat: None,
                },
                tamper_boundary: Default::default(),
                correlation_group: None,
                derived_from: vec![],
            }),
            extension: None,
            evidence_purged: false,
        }
    }

    fn trajectory_supported_by(id: &str, sensor_name: &str) -> LabeledTrajectory {
        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        };
        let ev = evidence_with_sensor(sensor_name);
        let link = EvidenceLink {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            claim_id: claim.id,
            evidence_id: ev.id,
            relation: EvidenceRelation::Supports,
            linked_at: "2026-01-01T00:00:00Z".into(),
        };
        LabeledTrajectory {
            id: id.into(),
            claim,
            evidence_graph: EvidenceGraph {
                links: vec![link],
                missing: vec![],
            },
            evidence_pool: vec![ev],
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

    /// Same shape as [`trajectory_supported_by`], but with two independent
    /// supporting sensors on one claim -- used to prove ablating one of the
    /// two reports an honestly zero coverage delta, since the other
    /// sensor's vote still resolves the claim.
    fn trajectory_supported_by_two_sensors(
        id: &str,
        sensor_a: &str,
        sensor_b: &str,
    ) -> LabeledTrajectory {
        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        };
        let ev_a = evidence_with_sensor(sensor_a);
        let ev_b = evidence_with_sensor(sensor_b);
        let links = vec![
            EvidenceLink {
                id: Uuid::new_v4(),
                session_id: "s1".into(),
                claim_id: claim.id,
                evidence_id: ev_a.id,
                relation: EvidenceRelation::Supports,
                linked_at: "2026-01-01T00:00:00Z".into(),
            },
            EvidenceLink {
                id: Uuid::new_v4(),
                session_id: "s1".into(),
                claim_id: claim.id,
                evidence_id: ev_b.id,
                relation: EvidenceRelation::Supports,
                linked_at: "2026-01-01T00:00:00Z".into(),
            },
        ];
        LabeledTrajectory {
            id: id.into(),
            claim,
            evidence_graph: EvidenceGraph {
                links,
                missing: vec![],
            },
            evidence_pool: vec![ev_a, ev_b],
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

    fn dataset_of(trajectories: Vec<LabeledTrajectory>) -> Dataset {
        Dataset {
            dataset_version: "0.0.0-mechanism-test".into(),
            description: "test".into(),
            trajectories,
            content_hash: "test-hash".into(),
        }
    }

    #[test]
    fn disabling_the_only_supporting_sensor_moves_the_trajectory_to_unavailable() {
        let dataset = dataset_of(vec![trajectory_supported_by("traj-1", "only_sensor_v1")]);
        let base_config = HarnessConfig::new(RiskClass::Balanced);
        let mut sensors = BTreeSet::new();
        sensors.insert("only_sensor_v1".to_string());

        let results = run_ablation(&dataset, &base_config, &sensors, "2026-01-02T00:00:00Z");
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.sensor_name, "only_sensor_v1");
        assert_eq!(r.trajectories_moved_to_unavailable, 1);
        // Coverage must drop (fewer Some(1.0) -> Some(0.0)).
        assert_eq!(r.baseline.evidence_coverage, Some(1.0));
        assert_eq!(r.ablated.evidence_coverage, Some(0.0));
        assert_eq!(r.evidence_coverage_delta, Some(-1.0));
        assert!(r.contains_synthetic_labels);
    }

    #[test]
    fn ablating_a_sensor_this_dataset_never_used_produces_a_zero_delta_not_an_error() {
        let dataset = dataset_of(vec![trajectory_supported_by("traj-1", "only_sensor_v1")]);
        let base_config = HarnessConfig::new(RiskClass::Balanced);
        let mut sensors = BTreeSet::new();
        sensors.insert("irrelevant_sensor_v1".to_string());

        let results = run_ablation(&dataset, &base_config, &sensors, "2026-01-02T00:00:00Z");
        let r = &results[0];
        assert_eq!(r.trajectories_moved_to_unavailable, 0);
        assert_eq!(r.evidence_coverage_delta, Some(0.0));
        assert_eq!(r.baseline, r.ablated);
    }

    /// A redundant sensor -- one whose evidence a second, independent
    /// sensor's vote already makes unnecessary -- must report an honestly
    /// zero coverage/recall/precision delta when ablated, never the
    /// maximum-marginal-value signal a "did ablation remove anything" check
    /// would produce (the bug the advisor caught: see
    /// `crate::harness::evidence_unavailable_for`'s doc comment).
    #[test]
    fn ablating_a_redundant_sensor_reports_zero_coverage_delta_not_maximum() {
        let dataset = dataset_of(vec![trajectory_supported_by_two_sensors(
            "traj-1",
            "sensor_a_v1",
            "sensor_b_v1",
        )]);
        let base_config = HarnessConfig::new(RiskClass::Balanced);
        let mut sensors = BTreeSet::new();
        sensors.insert("sensor_a_v1".to_string());

        let results = run_ablation(&dataset, &base_config, &sensors, "2026-01-02T00:00:00Z");
        let r = &results[0];
        assert_eq!(
            r.trajectories_moved_to_unavailable, 0,
            "sensor_b's independent vote still resolves the claim"
        );
        assert_eq!(r.evidence_coverage_delta, Some(0.0));
        assert_eq!(r.baseline.evaluable_count, 1);
        assert_eq!(r.ablated.evaluable_count, 1);
    }

    /// AC: the ablation mechanism must work correctly and report honestly
    /// even with zero real labeled data — never silently produce
    /// fake-looking numbers from an empty dataset.
    #[test]
    fn empty_dataset_reports_no_data_honestly_for_every_sensor() {
        let dataset = dataset_of(vec![]);
        let base_config = HarnessConfig::new(RiskClass::Balanced);
        let mut sensors = BTreeSet::new();
        sensors.insert("any_sensor_v1".to_string());

        let results = run_ablation(&dataset, &base_config, &sensors, "2026-01-02T00:00:00Z");
        let r = &results[0];
        assert_eq!(r.baseline.total, 0);
        assert_eq!(r.evidence_coverage_delta, None);
        assert_eq!(r.critical_failure_recall_delta, None);
        assert_eq!(r.trajectories_moved_to_unavailable, 0);
    }

    #[test]
    fn sensor_sweep_order_matches_the_input_btreeset_order() {
        let dataset = dataset_of(vec![
            trajectory_supported_by("traj-1", "sensor_a"),
            trajectory_supported_by("traj-2", "sensor_b"),
        ]);
        let base_config = HarnessConfig::new(RiskClass::Balanced);
        let mut sensors = BTreeSet::new();
        sensors.insert("sensor_b".to_string());
        sensors.insert("sensor_a".to_string());

        let results = run_ablation(&dataset, &base_config, &sensors, "2026-01-02T00:00:00Z");
        let names: Vec<&str> = results.iter().map(|r| r.sensor_name.as_str()).collect();
        assert_eq!(names, vec!["sensor_a", "sensor_b"]);
    }
}
