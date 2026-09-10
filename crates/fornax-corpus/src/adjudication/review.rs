//! Reviewer identity/role and review records (FORNX-342 scope: "reviewer
//! identity/role, timestamp, evidence viewed, rationale and confidence
//! provenance").

use uuid::Uuid;

use crate::adjudication::taxonomy::{
    validate_failure_metadata, CaseLabel, Confidence, FailureClass, TaxonomyError,
};

/// Who registered a reviewer. **This is the load-bearing anti-fabrication
/// primitive** (see module docs on `crate::adjudication` and ADR 0014): a
/// gold label whose contributing reviews are all [`ReviewerKind::Human`]
/// exports as `LabelingProvenance::HumanAdjudicated`; any other mix exports
/// as `SyntheticMechanismTest` (`crate::adjudication::gold::promote_gold_label`).
/// There is no reviewer kind that can produce `HumanAdjudicated` without a
/// human explicitly registering as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerKind {
    Human,
    /// A fixture reviewer used only to exercise this mechanism end-to-end in
    /// tests -- every artifact it touches is structurally synthetic. See
    /// `crate::adjudication::gold`'s doc comment.
    MechanismTestFixture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerRole {
    Primary,
    Secondary,
    Adjudicator,
}

/// A registered reviewer. Reviewer ids are local, opaque strings with no
/// external/cross-machine attestation -- a named gap, not a claimed
/// guarantee (see ADR 0014).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReviewerRef {
    pub id: String,
    pub kind: ReviewerKind,
    pub role: ReviewerRole,
    /// Required and non-empty for `ReviewerKind::Human` -- who attested this
    /// is a real reviewer, recorded at registration time. `None` for
    /// `MechanismTestFixture`.
    pub attested_by: Option<String>,
    pub registered_at: String,
}

/// Failure to construct a [`ReviewerRef`].
#[derive(Debug, thiserror::Error)]
pub enum ReviewerError {
    #[error("registering a Human reviewer requires --attested-by (who vouches this is real)")]
    HumanReviewerRequiresAttestation,
}

impl ReviewerRef {
    pub fn new(
        id: String,
        kind: ReviewerKind,
        role: ReviewerRole,
        attested_by: Option<String>,
        registered_at: String,
    ) -> Result<Self, ReviewerError> {
        if kind == ReviewerKind::Human
            && attested_by
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
        {
            return Err(ReviewerError::HumanReviewerRequiresAttestation);
        }
        Ok(Self {
            id,
            kind,
            role,
            attested_by,
            registered_at,
        })
    }
}

/// A reviewer's outcome for one case: either a [`CaseLabel`] with its
/// metadata, or -- valid only for [`ReviewerRole::Adjudicator`] -- an
/// explicit refusal to establish ground truth.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReviewOutcome {
    Label {
        label: CaseLabel,
        critical_failure: bool,
        failure_class: Option<FailureClass>,
    },
    Unresolved {
        reason: String,
    },
}

/// One reviewer's submission for one issued view (FORNX-342 scope item:
/// "reviewer identity/role, timestamp, evidence viewed, rationale and
/// confidence provenance").
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReviewRecord {
    pub id: Uuid,
    pub case_id: Uuid,
    pub view_id: Uuid,
    pub reviewer_id: String,
    pub role: ReviewerRole,
    pub outcome: ReviewOutcome,
    pub confidence: Confidence,
    pub rationale: String,
    pub submitted_at: String,
}

/// Failure to construct a valid [`ReviewRecord`].
#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error("Unresolved outcomes may only be submitted by an Adjudicator, not {role:?}")]
    UnresolvedRequiresAdjudicator { role: ReviewerRole },
    #[error(transparent)]
    Taxonomy(#[from] TaxonomyError),
}

impl ReviewRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        case_id: Uuid,
        view_id: Uuid,
        reviewer_id: String,
        role: ReviewerRole,
        outcome: ReviewOutcome,
        confidence: Confidence,
        rationale: String,
        submitted_at: String,
    ) -> Result<Self, ReviewError> {
        match &outcome {
            ReviewOutcome::Unresolved { .. } if role != ReviewerRole::Adjudicator => {
                return Err(ReviewError::UnresolvedRequiresAdjudicator { role });
            }
            ReviewOutcome::Label {
                label,
                critical_failure,
                failure_class,
            } => {
                validate_failure_metadata(*label, *critical_failure, *failure_class)?;
            }
            ReviewOutcome::Unresolved { .. } => {}
        }
        Ok(Self {
            id,
            case_id,
            view_id,
            reviewer_id,
            role,
            outcome,
            confidence,
            rationale,
            submitted_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_reviewer_requires_attestation() {
        let err = ReviewerRef::new(
            "r1".into(),
            ReviewerKind::Human,
            ReviewerRole::Primary,
            None,
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ReviewerError::HumanReviewerRequiresAttestation
        ));
    }

    #[test]
    fn human_reviewer_with_attestation_succeeds() {
        ReviewerRef::new(
            "r1".into(),
            ReviewerKind::Human,
            ReviewerRole::Primary,
            Some("owner".into()),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
    }

    #[test]
    fn mechanism_test_reviewer_needs_no_attestation() {
        ReviewerRef::new(
            "fixture-1".into(),
            ReviewerKind::MechanismTestFixture,
            ReviewerRole::Primary,
            None,
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
    }

    #[test]
    fn unresolved_outcome_is_refused_for_a_non_adjudicator_role() {
        let err = ReviewRecord::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "r1".into(),
            ReviewerRole::Primary,
            ReviewOutcome::Unresolved {
                reason: "ambiguous claim".into(),
            },
            Confidence::Low,
            "cannot tell".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ReviewError::UnresolvedRequiresAdjudicator { .. }
        ));
    }

    #[test]
    fn unresolved_outcome_is_accepted_for_an_adjudicator() {
        ReviewRecord::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "r1".into(),
            ReviewerRole::Adjudicator,
            ReviewOutcome::Unresolved {
                reason: "reviewers disagree, no way to resolve".into(),
            },
            Confidence::Low,
            "genuinely ambiguous".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
    }

    #[test]
    fn a_label_outcome_still_runs_taxonomy_validation() {
        let err = ReviewRecord::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "r1".into(),
            ReviewerRole::Primary,
            ReviewOutcome::Label {
                label: CaseLabel::Reliable,
                critical_failure: true,
                failure_class: None,
            },
            Confidence::High,
            "looks fine".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap_err();
        assert!(matches!(err, ReviewError::Taxonomy(_)));
    }
}
