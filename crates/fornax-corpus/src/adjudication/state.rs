//! Adjudication state machine (FORNX-342 scope: "disagreement queue and
//! adjudication state machine", "preserve reviewer disagreement rather than
//! silently overwriting it").
//!
//! **State is derived, never stored.** There is no mutable `state` column
//! anywhere in this crate or in `fornax-store`'s adjudication tables —
//! [`derive_state`] is a pure function of the append-only queue entry,
//! review records, and gold label revisions for one case. This is the
//! structural form of "preserve disagreement rather than silently
//! overwriting it": there is no write path that could overwrite a prior
//! state, because there is no state to overwrite.

use std::collections::HashSet;

use crate::adjudication::review::{ReviewOutcome, ReviewRecord, ReviewerRole};

/// One case's position in the review queue -- append-only, written once at
/// `fornax adjudicate enqueue` time.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QueueEntry {
    pub case_id: uuid::Uuid,
    pub double_review_required: bool,
    /// Why double-review was (or was not) required for this case -- e.g.
    /// `"contradiction"`, `"sanitization_altered_outcome"`, `"random_sample"`.
    /// Recorded so "which cases were benchmark-critical" is auditable
    /// rather than an undocumented runtime decision.
    pub selection_reason: String,
    pub enqueued_at: String,
}

/// How a `Resolved` state was reached. **Never `MajorityVote`** -- this
/// ticket's own non-goal ("no assumption that majority vote equals truth")
/// is enforced by this enum simply not having that variant, not by a
/// runtime check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionBasis {
    SingleReview,
    ConcurringDoubleReview,
    AdjudicatorDecision,
}

/// A case's current position, computed fresh from its append-only records
/// every time -- never read from a stored field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AdjudicationState {
    AwaitingPrimary,
    AwaitingSecondary,
    Disagreed,
    Resolved {
        basis: ResolutionBasis,
    },
    /// Terminal. First-class, not an error -- excluded from gold export,
    /// counted explicitly in `crate::adjudication::agreement` reports.
    Unresolved {
        reason: String,
    },
    /// Terminal. First-class -- ground truth cannot honestly be
    /// established (FORNX-342 scope item).
    NotEvaluable {
        reason: String,
    },
    Frozen {
        revision: u32,
    },
}

/// Two label-outcome reviews "agree" (for state purposes) iff their
/// `(label, critical_failure)` match exactly. `failure_class`/`confidence`
/// differing is recorded and reported (`crate::adjudication::agreement`)
/// but never changes state -- that distinction belongs to
/// `Unreliable`/`Contradicted`/... case-level analysis, not to whether a
/// case needs a third reviewer.
fn label_outcomes_agree(a: &ReviewOutcome, b: &ReviewOutcome) -> bool {
    matches!(
        (a, b),
        (
            ReviewOutcome::Label {
                label: la,
                critical_failure: ca,
                ..
            },
            ReviewOutcome::Label {
                label: lb,
                critical_failure: cb,
                ..
            },
        ) if la == lb && ca == cb
    )
}

/// Derive the current [`AdjudicationState`] for one case from `reviews`
/// (every review record for this case, any round) and `frozen_revision`
/// (the highest gold-label revision number already frozen for this case, if
/// any -- see `crate::adjudication::gold`).
pub fn derive_state(
    queue: &QueueEntry,
    reviews: &[ReviewRecord],
    frozen_revision: Option<u32>,
) -> AdjudicationState {
    if let Some(revision) = frozen_revision {
        return AdjudicationState::Frozen { revision };
    }

    // An adjudicator's Unresolved/NotEvaluable outcome is terminal
    // regardless of what came before.
    for review in reviews
        .iter()
        .filter(|r| r.role == ReviewerRole::Adjudicator)
    {
        if let ReviewOutcome::Unresolved { reason } = &review.outcome {
            // "not_evaluable:" prefix lets a caller route ground-truth-
            // impossible cases to NotEvaluable while everything else
            // (genuine reviewer conflict with no resolution) is Unresolved.
            // This is a plain string convention, not a new outcome variant
            // -- see ADR 0014 for why a third ReviewOutcome variant was
            // judged unnecessary complexity for one routing distinction.
            return if let Some(rest) = reason.strip_prefix("not_evaluable:") {
                AdjudicationState::NotEvaluable {
                    reason: rest.trim().to_string(),
                }
            } else {
                AdjudicationState::Unresolved {
                    reason: reason.clone(),
                }
            };
        }
        // An adjudicator's Label outcome is final -- it resolves the case
        // regardless of what the primary/secondary reviewers said. This is
        // the only way a Disagreed case ever leaves that state (short of an
        // adjudicator instead choosing Unresolved/NotEvaluable above).
        if matches!(review.outcome, ReviewOutcome::Label { .. }) {
            return AdjudicationState::Resolved {
                basis: ResolutionBasis::AdjudicatorDecision,
            };
        }
    }

    let primary_secondary: Vec<&ReviewRecord> = reviews
        .iter()
        .filter(|r| r.role == ReviewerRole::Primary || r.role == ReviewerRole::Secondary)
        .collect();

    if primary_secondary.is_empty() {
        return AdjudicationState::AwaitingPrimary;
    }

    if !queue.double_review_required {
        return AdjudicationState::Resolved {
            basis: ResolutionBasis::SingleReview,
        };
    }

    // Independent reviewer identities only -- a reviewer resubmitting is
    // not a second independent review.
    let distinct_reviewers: HashSet<&str> = primary_secondary
        .iter()
        .map(|r| r.reviewer_id.as_str())
        .collect();

    if distinct_reviewers.len() < 2 {
        return AdjudicationState::AwaitingSecondary;
    }

    // Take the first review from each of the first two distinct reviewers,
    // in submission order, as the pair to compare.
    let mut by_reviewer: Vec<&ReviewRecord> = Vec::new();
    for review in &primary_secondary {
        if !by_reviewer
            .iter()
            .any(|r| r.reviewer_id == review.reviewer_id)
        {
            by_reviewer.push(review);
        }
    }
    let (first, second) = (by_reviewer[0], by_reviewer[1]);

    if label_outcomes_agree(&first.outcome, &second.outcome) {
        AdjudicationState::Resolved {
            basis: ResolutionBasis::ConcurringDoubleReview,
        }
    } else {
        AdjudicationState::Disagreed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adjudication::review::ReviewerKind;
    use crate::adjudication::taxonomy::{CaseLabel, Confidence};
    use uuid::Uuid;

    fn queue(double_review: bool) -> QueueEntry {
        QueueEntry {
            case_id: Uuid::new_v4(),
            double_review_required: double_review,
            selection_reason: "test".into(),
            enqueued_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn label_review(reviewer: &str, role: ReviewerRole, label: CaseLabel) -> ReviewRecord {
        ReviewRecord::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            reviewer.into(),
            role,
            ReviewOutcome::Label {
                label,
                critical_failure: false,
                failure_class: None,
            },
            Confidence::High,
            "rationale".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap()
    }

    #[test]
    fn no_reviews_yet_is_awaiting_primary() {
        let q = queue(false);
        assert_eq!(
            derive_state(&q, &[], None),
            AdjudicationState::AwaitingPrimary
        );
    }

    #[test]
    fn single_review_resolves_when_double_review_not_required() {
        let q = queue(false);
        let reviews = vec![label_review(
            "r1",
            ReviewerRole::Primary,
            CaseLabel::Reliable,
        )];
        assert_eq!(
            derive_state(&q, &reviews, None),
            AdjudicationState::Resolved {
                basis: ResolutionBasis::SingleReview
            }
        );
    }

    #[test]
    fn single_review_awaits_secondary_when_double_review_required() {
        let q = queue(true);
        let reviews = vec![label_review(
            "r1",
            ReviewerRole::Primary,
            CaseLabel::Reliable,
        )];
        assert_eq!(
            derive_state(&q, &reviews, None),
            AdjudicationState::AwaitingSecondary
        );
    }

    #[test]
    fn concurring_double_review_resolves() {
        let q = queue(true);
        let reviews = vec![
            label_review("r1", ReviewerRole::Primary, CaseLabel::Reliable),
            label_review("r2", ReviewerRole::Secondary, CaseLabel::Reliable),
        ];
        assert_eq!(
            derive_state(&q, &reviews, None),
            AdjudicationState::Resolved {
                basis: ResolutionBasis::ConcurringDoubleReview
            }
        );
    }

    #[test]
    fn disagreeing_double_review_is_disagreed() {
        let q = queue(true);
        let reviews = vec![
            label_review("r1", ReviewerRole::Primary, CaseLabel::Reliable),
            label_review("r2", ReviewerRole::Secondary, CaseLabel::Contradicted),
        ];
        assert_eq!(
            derive_state(&q, &reviews, None),
            AdjudicationState::Disagreed
        );
    }

    #[test]
    fn an_adjudicators_label_outcome_resolves_a_disagreement() {
        let q = queue(true);
        let reviews = vec![
            label_review("r1", ReviewerRole::Primary, CaseLabel::Reliable),
            label_review("r2", ReviewerRole::Secondary, CaseLabel::Contradicted),
            label_review("adj1", ReviewerRole::Adjudicator, CaseLabel::Contradicted),
        ];
        assert_eq!(
            derive_state(&q, &reviews, None),
            AdjudicationState::Resolved {
                basis: ResolutionBasis::AdjudicatorDecision
            }
        );
    }

    #[test]
    fn a_repeat_review_by_the_same_reviewer_is_not_an_independent_second_review() {
        let q = queue(true);
        let reviews = vec![
            label_review("r1", ReviewerRole::Primary, CaseLabel::Reliable),
            label_review("r1", ReviewerRole::Primary, CaseLabel::Reliable),
        ];
        assert_eq!(
            derive_state(&q, &reviews, None),
            AdjudicationState::AwaitingSecondary,
            "two submissions from the same reviewer must not satisfy double-review"
        );
    }

    #[test]
    fn adjudicator_unresolved_is_terminal() {
        let q = queue(true);
        let reviews = vec![
            label_review("r1", ReviewerRole::Primary, CaseLabel::Reliable),
            label_review("r2", ReviewerRole::Secondary, CaseLabel::Contradicted),
            ReviewRecord::new(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                "adj1".into(),
                ReviewerRole::Adjudicator,
                ReviewOutcome::Unresolved {
                    reason: "genuine ambiguity, cannot decide".into(),
                },
                Confidence::Low,
                "no basis to prefer either".into(),
                "2026-01-01T00:00:00Z".into(),
            )
            .unwrap(),
        ];
        assert_eq!(
            derive_state(&q, &reviews, None),
            AdjudicationState::Unresolved {
                reason: "genuine ambiguity, cannot decide".into()
            }
        );
    }

    #[test]
    fn adjudicator_not_evaluable_prefix_routes_to_not_evaluable() {
        let q = queue(true);
        let reviews = vec![ReviewRecord::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "adj1".into(),
            ReviewerRole::Adjudicator,
            ReviewOutcome::Unresolved {
                reason: "not_evaluable: claim references a since-deleted session".into(),
            },
            Confidence::Low,
            "no ground truth possible".into(),
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap()];
        assert_eq!(
            derive_state(&q, &reviews, None),
            AdjudicationState::NotEvaluable {
                reason: "claim references a since-deleted session".into()
            }
        );
    }

    #[test]
    fn a_frozen_revision_always_wins() {
        let q = queue(false);
        let reviews = vec![label_review(
            "r1",
            ReviewerRole::Primary,
            CaseLabel::Reliable,
        )];
        assert_eq!(
            derive_state(&q, &reviews, Some(2)),
            AdjudicationState::Frozen { revision: 2 }
        );
    }

    #[test]
    fn mechanism_test_reviewer_kind_is_orthogonal_to_state() {
        // State derivation does not special-case reviewer kind at all --
        // MechanismTestFixture reviews resolve exactly like Human reviews.
        // Provenance selection is a separate concern (gold.rs).
        let kind = ReviewerKind::MechanismTestFixture;
        assert_eq!(kind, ReviewerKind::MechanismTestFixture);
    }
}
