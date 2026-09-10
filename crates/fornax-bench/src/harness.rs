//! Calibration/replay harness (FORNX-95): runs each [`LabeledTrajectory`]
//! through the REAL `fornax-verify` fusion + decision pipeline — never a
//! mock — and records what it predicted alongside what was adjudicated.
//!
//! # Why this harness never calls `fornax-store` or a live sensor
//!
//! A [`LabeledTrajectory`] already carries a frozen `Claim` +
//! `EvidenceGraph` + evidence pool — exactly the shape
//! `fornax_verify::fusion::FusionInput` consumes. Going through
//! `fornax-store` (as `fornax-daemon`'s `compute_fusion` does) would mean
//! persisting a database row per trajectory just to read it straight back
//! out, for no benefit — and it would break AC 1 ("reproducible from frozen
//! inputs/config"), since a real store round-trip is not a pure function of
//! its input file. Nothing here re-derives a graph via
//! `fornax_verify::fusion::project_graph` either: a labeled trajectory's
//! graph is itself the frozen input, not something to project from
//! `Finding`s that don't exist for it.
//!
//! # Why `fornax_verify::judge` is out of scope for this harness directly
//!
//! `fornax_verify::judge::LocalSelfHostedJudgeProvider` makes a live HTTP
//! call — running it from this crate's tests would make
//! `cargo test --workspace` network-dependent and flaky. Per
//! `fornax-verify`'s own fusion module docs, judge-derived evidence enters
//! fusion as an ordinary `EvidenceLink`/`Evidence` pair *upstream* of
//! fusion, produced once (offline, out of band) by
//! `fornax_verify::judge::judge_output_to_evidence` at
//! `TrustClass::ModelInternal`. That means a labeled trajectory's own
//! `evidence_pool` can already contain judge-derived evidence, complete with
//! `EvidenceSource::sensor_name` naming the judge — "judge on/off" is then
//! just another sensor-name ablation over already-collected evidence (see
//! [`crate::ablation`]), with zero network calls from this harness. The
//! judge's `model`/`prompt_version` identity is stamped on
//! [`crate::manifest::RunManifest`] by the caller, read from whatever
//! produced the dataset's judge-derived evidence — this module does not
//! call the judge itself.
//!
//! # Why the disable lever here is not `fornax_types::SensorDisableConfig`
//!
//! [`fornax_types::SensorDisableConfig`]/[`fornax_types::collect_with_disable_check`]
//! gate a *live* [`fornax_types::EvidenceSensor::collect`] call against a
//! real [`fornax_types::AgentEvent`] — neither exists here; a labeled
//! trajectory's evidence was already collected once, frozen into the
//! dataset file. Re-running collection is not an option, so ablation here
//! means something structurally different: given a sensor name, strip every
//! [`fornax_types::Evidence`] whose recorded `source.sensor_name` matches it
//! (and every link that pointed at it) from the frozen pool *before* fusion
//! runs, simulating "this sensor had never produced this evidence" as
//! faithfully as a frozen-input harness can. See [`apply_ablation`].

use std::collections::{BTreeSet, HashSet};

use fornax_types::{Evidence, EvidenceGraph, SignalAvailability, Verdict};
use fornax_verify::decision::{DecisionPolicy, DefaultRiskPolicy, RecommendationAction, RiskClass};
use fornax_verify::fusion::{BaselineFusionPolicy, FusionInput, FusionPolicy};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dataset::{Dataset, LabeledTrajectory};

/// Which sensors (by [`fornax_types::sensor::EvidenceSource::sensor_name`])
/// to strip from every trajectory's evidence pool before fusion, plus which
/// [`RiskClass`] to decide under. `BTreeSet` (not `Vec`) so two configs with
/// the same disabled sensors in different insertion order compare/serialize
/// identically — determinism (AC 1) extends to config equality, not just to
/// a single run's output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessConfig {
    pub risk_class: RiskClass,
    #[serde(default)]
    pub disabled_sensors: BTreeSet<String>,
}

impl HarnessConfig {
    pub fn new(risk_class: RiskClass) -> Self {
        Self {
            risk_class,
            disabled_sensors: BTreeSet::new(),
        }
    }

    /// Returns a copy with one additional sensor disabled — used by
    /// [`crate::ablation::run_ablation`] to build each sweep arm off a
    /// shared base config without mutating it.
    pub fn with_sensor_disabled(&self, sensor_name: &str) -> Self {
        let mut cfg = self.clone();
        cfg.disabled_sensors.insert(sensor_name.to_string());
        cfg
    }
}

/// One trajectory's prediction, paired with what was adjudicated for it.
/// Deliberately keeps `predicted_verdict` (fusion's output) and
/// `predicted_action` (decision's output) as two separate fields, mirroring
/// `fornax_verify::decision`'s own "policy identity is separate from fusion
/// policy identity" split — a caller must be able to tell whether a
/// disagreement came from fusion or from the risk mapping on top of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionRecord {
    pub trajectory_id: String,
    pub claim_id: Uuid,
    pub predicted_verdict: Verdict,
    pub predicted_action: RecommendationAction,
    pub expected_verdict: Verdict,
    pub critical_failure: bool,
    /// True when the evidence this trajectory needed was not actually
    /// resolvable at fusion time — determined from the *input* state
    /// (concerning missing-evidence notes, unresolvable links, or this run's
    /// ablation having stripped the last resolvable evidence), never from
    /// `predicted_verdict == Unavailable`. See [`evidence_unavailable_for`]'s
    /// doc comment for why the naive output-based check is circular and
    /// breaks AC 4 under ablation specifically.
    pub evidence_unavailable: bool,
    /// True only when this specific run's `disabled_sensors` actually
    /// removed at least one resolvable link/evidence entry from this
    /// trajectory — lets [`crate::ablation::AblationResult`] report "N
    /// trajectories moved from evaluable to evidence-unavailable" as its own
    /// coverage-delta signal, distinct from "a correct prediction became
    /// incorrect".
    pub ablation_removed_evidence: bool,
    /// Propagated from [`crate::dataset::LabelingProvenance::is_synthetic`]
    /// — carried per-record so [`crate::metrics::compute_metrics`] can set
    /// `contains_synthetic_labels` without a second dataset lookup.
    pub is_synthetic: bool,
}

/// Same concerning-availability set `fornax_verify::fusion`'s private
/// `is_concerning_availability` uses (R6's `Unavailable` branch) —
/// duplicated here rather than imported because that helper is private to
/// `fornax-verify` and this crate needs the identical judgment for a
/// different purpose (bucketing predictions, not deciding a verdict). Kept
/// in sync by `harness_tests::concerning_availability_matches_fusion_r6_semantics`,
/// which pins every [`SignalAvailability`] variant against
/// [`BaselineFusionPolicy`]'s own observable behavior rather than trusting
/// the two lists to agree by inspection alone.
fn is_concerning_availability(a: &SignalAvailability) -> bool {
    matches!(
        a,
        SignalAvailability::Unsupported
            | SignalAvailability::Unavailable
            | SignalAvailability::CollectionFailed
            | SignalAvailability::Redacted
            | SignalAvailability::Disabled
    )
}

/// Strips every [`Evidence`] whose `source.sensor_name` is in
/// `disabled_sensors` from `evidence_pool`, and every
/// [`fornax_types::EvidenceLink`] that pointed at one of them from `graph`.
/// Evidence with no recorded `source` (most evidence today, pre-FORNX-157)
/// is never touched by any ablation — it cannot be attributed to a named
/// sensor. `graph.missing` is left untouched: a `MissingEvidence` note
/// already records an *absence*, not a sensor's output, so ablating a
/// sensor cannot remove a note that was never that sensor's evidence in the
/// first place — this is a known, deliberate scope limit of a frozen-input
/// harness (a live ablation would also flip availability for the disabled
/// sensor's expected signal class; this harness only ever removes what was
/// actually collected).
///
/// Returns the filtered evidence pool, the filtered graph, and whether
/// anything was actually removed (used by [`evidence_unavailable_for`]).
fn apply_ablation(
    evidence_pool: &[Evidence],
    graph: &EvidenceGraph,
    disabled_sensors: &BTreeSet<String>,
) -> (Vec<Evidence>, EvidenceGraph, bool) {
    if disabled_sensors.is_empty() {
        return (evidence_pool.to_vec(), graph.clone(), false);
    }

    let excluded_ids: HashSet<Uuid> = evidence_pool
        .iter()
        .filter(|e| {
            e.source
                .as_ref()
                .map(|s| disabled_sensors.contains(&s.sensor_name))
                .unwrap_or(false)
        })
        .map(|e| e.id)
        .collect();

    let removed_any = !excluded_ids.is_empty();
    let filtered_pool: Vec<Evidence> = evidence_pool
        .iter()
        .filter(|e| !excluded_ids.contains(&e.id))
        .cloned()
        .collect();
    let filtered_links = graph
        .links
        .iter()
        .filter(|l| !excluded_ids.contains(&l.evidence_id))
        .cloned()
        .collect();
    let filtered_graph = EvidenceGraph {
        links: filtered_links,
        missing: graph.missing.clone(),
    };

    (filtered_pool, filtered_graph, removed_any)
}

/// Determines the `evidence_unavailable` bucket from *input* state, never
/// from `fused.verdict == Unavailable`. The output-based check is circular:
/// `fornax_verify::fusion::BaselineFusionPolicy::fuse`'s own R6 branch only
/// returns `Verdict::Unavailable` when zero votes survived AND
/// `graph.missing` carries a concerning [`SignalAvailability`] — a
/// trajectory with no `MissingEvidence` note at all falls through to
/// `Verdict::Unverified` instead, even when this run's ablation just
/// stripped the last resolvable evidence that would have resolved the
/// claim. Folding that case into "incorrect" is exactly what AC 4 forbids;
/// see `harness_tests::ablation_that_removes_the_only_evidence_is_unavailable_not_incorrect_even_without_a_missing_note`.
///
/// The ablation term is deliberately gated on *nothing resolvable
/// surviving* (`graph.links.is_empty()` after ablation's filtering), not on
/// "ablation removed something". A trajectory with two independent
/// supporting sensors, ablating only one, still has a real surviving vote —
/// treating that as evidence-unavailable would report a fully redundant
/// sensor as having maximum marginal value (the trajectory looks like it
/// "lost its evidence" when it didn't), inverting exactly the signal AC 2
/// exists to measure. See
/// `harness_tests::ablating_one_of_two_independent_supporting_sensors_leaves_the_trajectory_evaluable`.
fn evidence_unavailable_for(
    graph: &EvidenceGraph,
    evidence_pool: &[Evidence],
    ablation_removed_evidence: bool,
) -> bool {
    let concerning_missing = graph
        .missing
        .iter()
        .any(|m| is_concerning_availability(&m.availability));
    let unresolvable_link = graph
        .links
        .iter()
        .any(|l| !evidence_pool.iter().any(|e| e.id == l.evidence_id));
    let ablation_left_nothing_resolvable = ablation_removed_evidence && graph.links.is_empty();
    concerning_missing || unresolvable_link || ablation_left_nothing_resolvable
}

/// Runs every trajectory in `dataset` through the real
/// `fornax_verify::fusion::BaselineFusionPolicy` + `DefaultRiskPolicy`
/// pipeline under `config`, producing one [`PredictionRecord`] per
/// trajectory. Pure and deterministic given `computed_at` — trajectories
/// are sorted by [`LabeledTrajectory::id`] before iterating (same
/// canonical-ordering discipline `BaselineFusionPolicy::fuse` itself uses),
/// so two calls over the same dataset/config/`computed_at` are
/// byte-identical regardless of the dataset file's own row order (AC 1).
pub fn run_harness(
    dataset: &Dataset,
    config: &HarnessConfig,
    computed_at: &str,
) -> Vec<PredictionRecord> {
    let mut trajectories: Vec<&LabeledTrajectory> = dataset.trajectories.iter().collect();
    trajectories.sort_by(|a, b| a.id.cmp(&b.id));

    trajectories
        .into_iter()
        .map(|t| {
            let (evidence_pool, graph, ablation_removed_evidence) = apply_ablation(
                &t.evidence_pool,
                &t.evidence_graph,
                &config.disabled_sensors,
            );

            let input = FusionInput {
                claim: &t.claim,
                graph: &graph,
                evidence: &evidence_pool,
            };
            let fused = BaselineFusionPolicy.fuse(&input, computed_at);
            let recommendation = DefaultRiskPolicy.decide(&fused, config.risk_class);
            let evidence_unavailable =
                evidence_unavailable_for(&graph, &evidence_pool, ablation_removed_evidence);

            PredictionRecord {
                trajectory_id: t.id.clone(),
                claim_id: t.claim.id,
                predicted_verdict: fused.verdict,
                predicted_action: recommendation.action,
                expected_verdict: t.adjudicated_expected_outcome.expected_verdict,
                critical_failure: t.adjudicated_expected_outcome.critical_failure,
                evidence_unavailable,
                ablation_removed_evidence,
                is_synthetic: t.labeling_provenance.is_synthetic(),
            }
        })
        .collect()
}

#[cfg(test)]
mod harness_tests {
    use super::*;
    use crate::dataset::{AdjudicatedExpectedOutcome, LabelingProvenance};
    use fornax_types::{
        Claim, ClockSource, CollectionMethod, EvidenceKind, EvidenceLink, EvidenceRelation,
        EvidenceSource, Freshness, MissingEvidence, SignalClass, TrustClass,
    };

    fn claim(id: Uuid) -> Claim {
        Claim {
            id,
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

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

    fn trajectory(
        id: &str,
        evidence: Vec<Evidence>,
        links_relation: EvidenceRelation,
    ) -> LabeledTrajectory {
        let c = claim(Uuid::new_v4());
        let links: Vec<EvidenceLink> = evidence
            .iter()
            .map(|e| EvidenceLink {
                id: Uuid::new_v4(),
                session_id: "s1".into(),
                claim_id: c.id,
                evidence_id: e.id,
                relation: links_relation,
                linked_at: "2026-01-01T00:00:00Z".into(),
            })
            .collect();
        LabeledTrajectory {
            id: id.into(),
            claim: c,
            evidence_graph: EvidenceGraph {
                links,
                missing: vec![],
            },
            evidence_pool: evidence,
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
    fn calls_the_real_fusion_and_decision_pipeline_and_produces_a_report() {
        let ev = evidence_with_sensor("test_sensor_v1");
        let t = trajectory("traj-1", vec![ev], EvidenceRelation::Supports);
        let dataset = dataset_of(vec![t]);
        let config = HarnessConfig::new(RiskClass::Balanced);

        let predictions = run_harness(&dataset, &config, "2026-01-02T00:00:00Z");
        assert_eq!(predictions.len(), 1);
        let p = &predictions[0];
        // One clean Supports vote, uncorrelated -> Verified/Qualified ->
        // Balanced never Proceeds on a Qualified band (real
        // DefaultRiskPolicy mapping table, not a mock).
        assert_eq!(p.predicted_verdict, Verdict::Verified);
        assert_eq!(p.predicted_action, RecommendationAction::Review);
        assert!(!p.evidence_unavailable);
        assert!(p.is_synthetic);
    }

    #[test]
    fn run_is_deterministic_regardless_of_dataset_row_order() {
        let t1 = trajectory(
            "traj-a",
            vec![evidence_with_sensor("s1")],
            EvidenceRelation::Supports,
        );
        let t2 = trajectory(
            "traj-b",
            vec![evidence_with_sensor("s2")],
            EvidenceRelation::Contradicts,
        );
        let config = HarnessConfig::new(RiskClass::Balanced);

        let forward = dataset_of(vec![t1.clone(), t2.clone()]);
        let backward = dataset_of(vec![t2, t1]);

        let out_forward = run_harness(&forward, &config, "2026-01-02T00:00:00Z");
        let out_backward = run_harness(&backward, &config, "2026-01-02T00:00:00Z");

        let ids_forward: Vec<&str> = out_forward
            .iter()
            .map(|p| p.trajectory_id.as_str())
            .collect();
        let ids_backward: Vec<&str> = out_backward
            .iter()
            .map(|p| p.trajectory_id.as_str())
            .collect();
        assert_eq!(ids_forward, ids_backward);
        assert_eq!(ids_forward, vec!["traj-a", "traj-b"]);
    }

    #[test]
    fn ablation_that_removes_the_only_evidence_is_unavailable_not_incorrect_even_without_a_missing_note(
    ) {
        // Deliberately no MissingEvidence note on this trajectory -- proves
        // the discriminating case the advisor flagged: BaselineFusionPolicy
        // itself would call this Unverified (no concerning-missing note),
        // not Unavailable, once the only evidence is stripped. A naive
        // `predicted_verdict == Unavailable` check would misclassify this as
        // "incorrect" rather than "evidence unavailable".
        let ev = evidence_with_sensor("ablated_sensor_v1");
        let t = trajectory("traj-1", vec![ev], EvidenceRelation::Supports);
        let dataset = dataset_of(vec![t]);
        let config =
            HarnessConfig::new(RiskClass::Balanced).with_sensor_disabled("ablated_sensor_v1");

        let predictions = run_harness(&dataset, &config, "2026-01-02T00:00:00Z");
        let p = &predictions[0];

        // Fusion itself, over the now-empty graph, actually returns
        // Unverified -- confirming this is the discriminating case, not a
        // vacuous one.
        assert_eq!(p.predicted_verdict, Verdict::Unverified);
        assert!(p.ablation_removed_evidence);
        assert!(
            p.evidence_unavailable,
            "must be bucketed as evidence-unavailable, not incorrect, even though \
             predicted_verdict is Unverified rather than Unavailable"
        );
    }

    #[test]
    fn ablating_an_unrelated_sensor_leaves_evidence_unavailable_false() {
        let ev = evidence_with_sensor("real_sensor_v1");
        let t = trajectory("traj-1", vec![ev], EvidenceRelation::Supports);
        let dataset = dataset_of(vec![t]);
        let config =
            HarnessConfig::new(RiskClass::Balanced).with_sensor_disabled("some_other_sensor_v1");

        let predictions = run_harness(&dataset, &config, "2026-01-02T00:00:00Z");
        let p = &predictions[0];
        assert!(!p.ablation_removed_evidence);
        assert!(!p.evidence_unavailable);
        assert_eq!(p.predicted_verdict, Verdict::Verified);
    }

    /// The case the advisor caught: ablating one of two independent
    /// supporting sensors must NOT move the trajectory into the
    /// evidence-unavailable bucket, because a real supporting vote still
    /// survives. Gating `evidence_unavailable_for`'s ablation term on "did
    /// ablation remove anything" instead of "did ablation leave nothing
    /// resolvable" would report a fully redundant sensor as having maximum
    /// marginal value -- exactly inverted from what AC 2 asks this harness
    /// to measure.
    #[test]
    fn ablating_one_of_two_independent_supporting_sensors_leaves_the_trajectory_evaluable() {
        let ev_a = evidence_with_sensor("sensor_a_v1");
        let ev_b = evidence_with_sensor("sensor_b_v1");
        let t = trajectory("traj-1", vec![ev_a, ev_b], EvidenceRelation::Supports);
        let dataset = dataset_of(vec![t]);
        let config = HarnessConfig::new(RiskClass::Balanced).with_sensor_disabled("sensor_a_v1");

        let predictions = run_harness(&dataset, &config, "2026-01-02T00:00:00Z");
        let p = &predictions[0];
        assert!(
            p.ablation_removed_evidence,
            "ablation did remove sensor_a's evidence"
        );
        assert!(
            !p.evidence_unavailable,
            "sensor_b's evidence still resolves the claim -- must stay evaluable"
        );
        assert_eq!(p.predicted_verdict, Verdict::Verified);
    }

    #[test]
    fn explicit_missing_evidence_note_is_bucketed_unavailable_with_no_ablation_involved() {
        let c = claim(Uuid::new_v4());
        let missing = MissingEvidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            claim_id: c.id,
            signal_class: SignalClass::ProcessResult,
            availability: SignalAvailability::Unavailable,
            detail: None,
            noted_at: "2026-01-01T00:00:00Z".into(),
        };
        let t = LabeledTrajectory {
            id: "traj-1".into(),
            claim: c,
            evidence_graph: EvidenceGraph {
                links: vec![],
                missing: vec![missing],
            },
            evidence_pool: vec![],
            adjudicated_expected_outcome: AdjudicatedExpectedOutcome {
                expected_verdict: Verdict::Unavailable,
                critical_failure: false,
                notes: None,
            },
            labeling_provenance: LabelingProvenance::SyntheticMechanismTest {
                created_by: "test".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                notes: None,
            },
        };
        let dataset = dataset_of(vec![t]);
        let config = HarnessConfig::new(RiskClass::Balanced);

        let predictions = run_harness(&dataset, &config, "2026-01-02T00:00:00Z");
        let p = &predictions[0];
        assert_eq!(p.predicted_verdict, Verdict::Unavailable);
        assert!(!p.ablation_removed_evidence);
        assert!(p.evidence_unavailable);
    }

    /// Pins that `is_concerning_availability` (duplicated from
    /// `fornax_verify::fusion`'s private helper of the same judgment,
    /// because that one isn't public) actually agrees with
    /// `BaselineFusionPolicy`'s own real behavior for every
    /// `SignalAvailability` variant, rather than trusting the two lists to
    /// stay in sync by inspection.
    #[test]
    fn concerning_availability_matches_fusion_r6_semantics() {
        let all_variants = [
            SignalAvailability::Unsupported,
            SignalAvailability::Unavailable,
            SignalAvailability::CollectionFailed,
            SignalAvailability::Redacted,
            SignalAvailability::Disabled,
            SignalAvailability::Unknown,
            SignalAvailability::Unrecognized("weird_future_state".to_string()),
            SignalAvailability::Available,
        ];
        for availability in all_variants {
            let c = claim(Uuid::new_v4());
            let missing = MissingEvidence {
                id: Uuid::new_v4(),
                session_id: "s1".into(),
                claim_id: c.id,
                signal_class: SignalClass::ProcessResult,
                availability: availability.clone(),
                detail: None,
                noted_at: "2026-01-01T00:00:00Z".into(),
            };
            let graph = EvidenceGraph {
                links: vec![],
                missing: vec![missing],
            };
            let input = FusionInput {
                claim: &c,
                graph: &graph,
                evidence: &[],
            };
            let fused = BaselineFusionPolicy.fuse(&input, "2026-01-02T00:00:00Z");
            let fusion_says_unavailable = fused.verdict == Verdict::Unavailable;
            let ours_says_concerning = is_concerning_availability(&availability);
            assert_eq!(
                fusion_says_unavailable, ours_says_concerning,
                "availability={availability:?}"
            );
        }
    }
}
