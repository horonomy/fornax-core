//! Frozen gold label revisions (FORNX-342 scope: "frozen gold labels are
//! versioned; later relabeling creates a new revision rather than rewriting
//! benchmark history").
//!
//! A [`GoldLabelRevision`] is deliberately **insert-only and metadata-only**
//! -- no free-text field, no session content. This resolves what would
//! otherwise be a real conflict between "never rewrite benchmark history"
//! and FORNX-106 tenant deletion: there is nothing here for a tenant delete
//! to need to touch. Free-text rationale lives only on
//! [`crate::adjudication::review::ReviewRecord`], which the store layer does
//! tenant-tag and delete (`fornax_store::adjudication`).
//!
//! [`GoldLabelRevision`] deserializes through `#[serde(try_from = "..Wire")]`
//! (same precedent as `fornax_types::audit::AuditEvent`) so a hand-forged
//! JSON row with an empty `contributing_review_ids` or a digest that doesn't
//! recompute is rejected before the domain type is ever constructed.

use uuid::Uuid;

use fornax_bench::dataset::{AdjudicatedExpectedOutcome, LabeledTrajectory, LabelingProvenance};
use sha2::{Digest, Sha256};

use crate::adjudication::review::ReviewerKind;
use crate::adjudication::taxonomy::CaseLabel;
use crate::candidate::CandidateCase;
use crate::promote::promote_to_labeled_trajectory;

/// Domain separator for [`GoldLabelRevision::revision_digest`]'s chain --
/// same discipline as `fornax_types::audit_chain`'s `AUDIT_LEDGER_DOMAIN`
/// (never reused across contexts, so a digest from one chain can never be
/// replayed as valid in another).
const GOLD_LABEL_DIGEST_DOMAIN: &[u8] = b"fornax-corpus:gold-label-revision:v1";

/// Why a case was relabeled -- a closed enum, not free-text prose, so "why
/// did this change" is queryable/reportable rather than buried in a comment
/// string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelabelReason {
    InitialFreeze,
    EvidenceCorrection,
    TaxonomyRevision,
    AdjudicationError,
    PolicyChange,
}

/// One frozen gold label revision for one case. See module docs.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "GoldLabelRevisionWire")]
pub struct GoldLabelRevision {
    pub case_id: Uuid,
    pub revision: u32,
    pub round: u32,
    pub label: CaseLabel,
    pub critical_failure: bool,
    pub expected_verdict: Option<fornax_types::Verdict>,
    pub contributing_review_ids: Vec<Uuid>,
    pub frozen_by: String,
    pub frozen_at: String,
    pub supersedes_revision: Option<u32>,
    pub reason: RelabelReason,
    pub revision_digest: String,
}

#[derive(Debug, serde::Deserialize)]
struct GoldLabelRevisionWire {
    case_id: Uuid,
    revision: u32,
    round: u32,
    label: CaseLabel,
    critical_failure: bool,
    expected_verdict: Option<fornax_types::Verdict>,
    contributing_review_ids: Vec<Uuid>,
    frozen_by: String,
    frozen_at: String,
    supersedes_revision: Option<u32>,
    reason: RelabelReason,
    revision_digest: String,
}

/// Rejection vocabulary for constructing a [`GoldLabelRevision`] from
/// untrusted wire bytes.
#[derive(Debug, Clone, thiserror::Error)]
pub enum GoldLabelRejection {
    #[error("revision must be >= 1, found {found}")]
    RevisionMustBePositive { found: u32 },
    #[error("a gold label must have at least one contributing review")]
    NoContributingReviews,
    #[error("revision_digest does not recompute -- possible tampering")]
    DigestMismatch,
    #[error("revision 1 must not have supersedes_revision set")]
    InitialRevisionCannotSupersede,
    #[error("revision > 1 must set supersedes_revision")]
    RelabelMustSupersede,
}

impl TryFrom<GoldLabelRevisionWire> for GoldLabelRevision {
    type Error = GoldLabelRejection;

    fn try_from(w: GoldLabelRevisionWire) -> Result<Self, Self::Error> {
        if w.revision == 0 {
            return Err(GoldLabelRejection::RevisionMustBePositive { found: w.revision });
        }
        if w.contributing_review_ids.is_empty() {
            return Err(GoldLabelRejection::NoContributingReviews);
        }
        if w.revision == 1 && w.supersedes_revision.is_some() {
            return Err(GoldLabelRejection::InitialRevisionCannotSupersede);
        }
        if w.revision > 1 && w.supersedes_revision.is_none() {
            return Err(GoldLabelRejection::RelabelMustSupersede);
        }

        let expected_digest = compute_digest(
            w.case_id,
            w.revision,
            w.label,
            w.critical_failure,
            w.supersedes_revision,
        );
        if expected_digest != w.revision_digest {
            return Err(GoldLabelRejection::DigestMismatch);
        }

        Ok(GoldLabelRevision {
            case_id: w.case_id,
            revision: w.revision,
            round: w.round,
            label: w.label,
            critical_failure: w.critical_failure,
            expected_verdict: w.expected_verdict,
            contributing_review_ids: w.contributing_review_ids,
            frozen_by: w.frozen_by,
            frozen_at: w.frozen_at,
            supersedes_revision: w.supersedes_revision,
            reason: w.reason,
            revision_digest: w.revision_digest,
        })
    }
}

fn compute_digest(
    case_id: Uuid,
    revision: u32,
    label: CaseLabel,
    critical_failure: bool,
    supersedes_revision: Option<u32>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(GOLD_LABEL_DIGEST_DOMAIN);
    hasher.update(case_id.as_bytes());
    hasher.update(revision.to_be_bytes());
    hasher.update(serde_json::to_vec(&label).unwrap_or_default());
    hasher.update([critical_failure as u8]);
    // The chain links to the PREVIOUS revision's number, not its digest --
    // avoiding a bootstrap dependency where computing revision 1's digest
    // would need revision 0's digest to not exist yet. Cross-case tamper
    // detection for the whole gold_labels table is the audit ledger's job
    // (every freeze also appends a GoldLabelFrozen AuditEvent), not this
    // per-case digest's.
    if let Some(prev) = supersedes_revision {
        hasher.update(prev.to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Build the next revision for a case, given its prior revision (`None` for
/// the first freeze).
#[allow(clippy::too_many_arguments)]
pub fn next_revision(
    case_id: Uuid,
    round: u32,
    label: CaseLabel,
    critical_failure: bool,
    contributing_review_ids: Vec<Uuid>,
    frozen_by: String,
    frozen_at: String,
    reason: RelabelReason,
    prior_revision: Option<u32>,
) -> GoldLabelRevision {
    let revision = prior_revision.map(|r| r + 1).unwrap_or(1);
    let revision_digest =
        compute_digest(case_id, revision, label, critical_failure, prior_revision);
    GoldLabelRevision {
        case_id,
        revision,
        round,
        label,
        critical_failure,
        expected_verdict: label.expected_verdict(),
        contributing_review_ids,
        frozen_by,
        frozen_at,
        supersedes_revision: prior_revision,
        reason,
        revision_digest,
    }
}

/// Promote a candidate + its frozen gold label to a
/// `fornax_bench::dataset::LabeledTrajectory`, selecting `LabelingProvenance`
/// from the **actual reviewer kinds that contributed** -- never from a
/// caller-supplied flag. `HumanAdjudicated` only when every contributing
/// reviewer is [`ReviewerKind::Human`]; any other mix (including a mix of
/// human and fixture reviewers) exports as `SyntheticMechanismTest`. This is
/// the FORNX-342 AC "no LLM/Fornax-generated label can be stored as
/// HumanAdjudicated without the required human provenance path" enforced at
/// the one place provenance is actually assigned.
pub fn promote_gold_label(
    candidate: &CandidateCase,
    gold: &GoldLabelRevision,
    contributing_reviewer_kinds: &[ReviewerKind],
    labeled_by: String,
    labeled_at: String,
) -> Option<LabeledTrajectory> {
    let expected_verdict = gold.expected_verdict?;
    let outcome = AdjudicatedExpectedOutcome {
        expected_verdict,
        critical_failure: gold.critical_failure,
        notes: Some(format!(
            "gold_label_revision: {}#{}",
            gold.case_id, gold.revision
        )),
    };

    let all_human = !contributing_reviewer_kinds.is_empty()
        && contributing_reviewer_kinds
            .iter()
            .all(|k| *k == ReviewerKind::Human);

    if all_human {
        Some(promote_to_labeled_trajectory(
            candidate, outcome, labeled_by, labeled_at,
        ))
    } else {
        Some(LabeledTrajectory {
            id: candidate.id.to_string(),
            claim: candidate.replay.claim.clone(),
            evidence_graph: candidate.replay.evidence_graph.clone(),
            evidence_pool: candidate.replay.evidence_pool.clone(),
            adjudicated_expected_outcome: outcome,
            labeling_provenance: LabelingProvenance::SyntheticMechanismTest {
                created_by: labeled_by,
                created_at: labeled_at,
                notes: Some("contains a non-Human contributing reviewer".to_string()),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::CANDIDATE_SCHEMA_VERSION;
    use fornax_replay::manifest::{ReplayManifest, REPLAY_MANIFEST_SCHEMA_VERSION};
    use fornax_types::{Claim, EvidenceGraph, Provider, Verdict};
    use fornax_verify::decision::{RecommendationAction, RiskClass};
    use fornax_verify::fusion::UncertaintyBand;

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
            schema_version: CANDIDATE_SCHEMA_VERSION,
            id: CandidateCase::derive_id("s1", &replay),
            session_id: "s1".into(),
            replay,
            context: None,
            local_verdict: Verdict::Verified,
            local_uncertainty: UncertaintyBand::Qualified,
            mined_by: vec![],
            withheld_evidence: vec![],
            mined_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn all_human_reviewers_promote_to_human_adjudicated() {
        let c = candidate();
        let rev = next_revision(
            c.id,
            1,
            CaseLabel::Reliable,
            false,
            vec![Uuid::new_v4()],
            "adj1".into(),
            "2026-01-01T00:00:00Z".into(),
            RelabelReason::InitialFreeze,
            None,
        );
        let trajectory = promote_gold_label(
            &c,
            &rev,
            &[ReviewerKind::Human, ReviewerKind::Human],
            "adj1".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
        assert!(!trajectory.labeling_provenance.is_synthetic());
    }

    #[test]
    fn any_non_human_contributor_promotes_to_synthetic() {
        let c = candidate();
        let rev = next_revision(
            c.id,
            1,
            CaseLabel::Reliable,
            false,
            vec![Uuid::new_v4()],
            "adj1".into(),
            "2026-01-01T00:00:00Z".into(),
            RelabelReason::InitialFreeze,
            None,
        );
        let trajectory = promote_gold_label(
            &c,
            &rev,
            &[ReviewerKind::Human, ReviewerKind::MechanismTestFixture],
            "adj1".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
        assert!(
            trajectory.labeling_provenance.is_synthetic(),
            "a mechanism-test reviewer anywhere in the chain must never yield HumanAdjudicated"
        );
    }

    #[test]
    fn a_not_evaluable_label_cannot_be_promoted() {
        let c = candidate();
        let rev = next_revision(
            c.id,
            1,
            CaseLabel::NotEvaluable,
            false,
            vec![Uuid::new_v4()],
            "adj1".into(),
            "2026-01-01T00:00:00Z".into(),
            RelabelReason::InitialFreeze,
            None,
        );
        assert!(promote_gold_label(
            &c,
            &rev,
            &[ReviewerKind::Human],
            "adj1".into(),
            "2026-01-01T00:00:00Z".into()
        )
        .is_none());
    }

    fn sample_revision() -> GoldLabelRevision {
        next_revision(
            Uuid::new_v4(),
            1,
            CaseLabel::Reliable,
            false,
            vec![Uuid::new_v4()],
            "adj1".into(),
            "2026-01-01T00:00:00Z".into(),
            RelabelReason::InitialFreeze,
            None,
        )
    }

    #[test]
    fn round_trips_through_serde() {
        let rev = sample_revision();
        let json = serde_json::to_string(&rev).unwrap();
        let back: GoldLabelRevision = serde_json::from_str(&json).unwrap();
        assert_eq!(rev, back);
    }

    #[test]
    fn a_hand_forged_label_with_zero_contributing_reviews_is_rejected() {
        let mut rev = sample_revision();
        rev.contributing_review_ids.clear();
        let json = serde_json::to_string(&rev).unwrap();
        let err = serde_json::from_str::<GoldLabelRevision>(&json).unwrap_err();
        assert!(err.to_string().contains("contributing review"));
    }

    #[test]
    fn a_tampered_digest_is_rejected() {
        let mut rev = sample_revision();
        rev.revision_digest = "0".repeat(64);
        let json = serde_json::to_string(&rev).unwrap();
        let err = serde_json::from_str::<GoldLabelRevision>(&json).unwrap_err();
        assert!(err.to_string().contains("tampering"));
    }

    #[test]
    fn revision_zero_is_rejected() {
        let mut rev = sample_revision();
        rev.revision = 0;
        let json = serde_json::to_string(&rev).unwrap();
        assert!(serde_json::from_str::<GoldLabelRevision>(&json).is_err());
    }

    #[test]
    fn relabeling_appends_revision_2_and_leaves_revision_1_byte_identical() {
        let case_id = Uuid::new_v4();
        let rev1 = next_revision(
            case_id,
            1,
            CaseLabel::Reliable,
            false,
            vec![Uuid::new_v4()],
            "adj1".into(),
            "2026-01-01T00:00:00Z".into(),
            RelabelReason::InitialFreeze,
            None,
        );
        let rev1_clone = rev1.clone();

        let rev2 = next_revision(
            case_id,
            2,
            CaseLabel::Unreliable,
            true,
            vec![Uuid::new_v4()],
            "adj2".into(),
            "2026-01-02T00:00:00Z".into(),
            RelabelReason::EvidenceCorrection,
            Some(rev1.revision),
        );

        assert_eq!(
            rev1, rev1_clone,
            "revision 1 must be untouched by relabeling"
        );
        assert_eq!(rev2.revision, 2);
        assert_eq!(rev2.supersedes_revision, Some(1));
        assert_ne!(rev1.revision_digest, rev2.revision_digest);
    }

    #[test]
    fn not_evaluable_gold_label_has_no_expected_verdict() {
        let rev = next_revision(
            Uuid::new_v4(),
            1,
            CaseLabel::NotEvaluable,
            false,
            vec![Uuid::new_v4()],
            "adj1".into(),
            "2026-01-01T00:00:00Z".into(),
            RelabelReason::InitialFreeze,
            None,
        );
        assert_eq!(rev.expected_verdict, None);
    }
}
