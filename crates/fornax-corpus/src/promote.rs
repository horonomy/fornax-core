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
