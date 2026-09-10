//! The one, deliberately narrow path from a mined [`CandidateCase`] to a
//! `fornax_bench::dataset::LabeledTrajectory` (FORNX-341 AC: "synthetic
//! fixtures cannot be mislabeled as real human-adjudicated evidence").

use fornax_bench::dataset::{AdjudicatedExpectedOutcome, LabeledTrajectory, LabelingProvenance};

use crate::candidate::CandidateCase;

/// Promote a mined candidate to a labeled trajectory, given a real human
/// adjudication.
///
/// This function takes the adjudication *fields* (`labeled_by`/
/// `labeled_at`), not a `LabelingProvenance` value — a caller cannot pass
/// `LabelingProvenance::SyntheticMechanismTest` here even by mistake,
/// because the variant is constructed internally, always as
/// `HumanAdjudicated`. Combined with [`CandidateCase`] carrying no label
/// field of its own, there is no code path from mining to a labeled
/// trajectory that skips a human adjudication record.
pub fn promote_to_labeled_trajectory(
    candidate: &CandidateCase,
    outcome: AdjudicatedExpectedOutcome,
    labeled_by: String,
    labeled_at: String,
) -> LabeledTrajectory {
    LabeledTrajectory {
        id: candidate.id.to_string(),
        claim: candidate.replay.claim.clone(),
        evidence_graph: candidate.replay.evidence_graph.clone(),
        evidence_pool: candidate.replay.evidence_pool.clone(),
        adjudicated_expected_outcome: outcome,
        labeling_provenance: LabelingProvenance::HumanAdjudicated {
            labeled_by,
            labeled_at,
            notes: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mining::MiningStrategy;
    use fornax_replay::manifest::{ReplayManifest, REPLAY_MANIFEST_SCHEMA_VERSION};
    use fornax_types::{Claim, EvidenceGraph, Provider, Verdict};
    use fornax_verify::decision::{RecommendationAction, RiskClass};
    use fornax_verify::fusion::UncertaintyBand;
    use uuid::Uuid;

    fn candidate() -> CandidateCase {
        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        };
        let replay = ReplayManifest {
            manifest_schema_version: REPLAY_MANIFEST_SCHEMA_VERSION,
            adapter_provider: Provider::ClaudeCode,
            adapter_runtime_version: "1.0.0".into(),
            fusion_policy_name: "baseline".into(),
            fusion_policy_version: 1,
            decision_policy_name: "default".into(),
            decision_policy_version: 1,
            risk_class: RiskClass::Balanced,
            disabled_sensors: Default::default(),
            claim: claim.clone(),
            evidence_pool: vec![],
            evidence_graph: EvidenceGraph::default(),
            recorded_verdict: Verdict::Verified,
            recorded_uncertainty: UncertaintyBand::Qualified,
            recorded_action: RecommendationAction::Proceed,
            recorded_at: "2026-01-01T00:00:00Z".into(),
        };
        CandidateCase {
            schema_version: crate::candidate::CANDIDATE_SCHEMA_VERSION,
            id: CandidateCase::derive_id("s1", &replay),
            session_id: "s1".into(),
            replay,
            context: None,
            local_verdict: Verdict::Verified,
            local_uncertainty: UncertaintyBand::Qualified,
            mined_by: vec![MiningStrategy::BenignControl],
            withheld_evidence: vec![],
            mined_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn a_candidate_case_never_serializes_as_an_adjudicated_label() {
        // Structural guard: CandidateCase must have no field that, once
        // serialized, could be mistaken for an adjudication record.
        let value = serde_json::to_value(candidate()).unwrap();
        assert!(value.get("adjudicated_expected_outcome").is_none());
        assert!(value.get("labeling_provenance").is_none());
    }

    #[test]
    fn promotion_always_stamps_human_adjudicated_never_synthetic() {
        let trajectory = promote_to_labeled_trajectory(
            &candidate(),
            AdjudicatedExpectedOutcome {
                expected_verdict: Verdict::Verified,
                critical_failure: false,
                notes: None,
            },
            "reviewer@example.com".into(),
            "2026-01-02T00:00:00Z".into(),
        );
        assert!(!trajectory.labeling_provenance.is_synthetic());
        assert!(matches!(
            trajectory.labeling_provenance,
            LabelingProvenance::HumanAdjudicated { .. }
        ));
    }
}
