//! Research label taxonomy for corpus adjudication (FORNX-342). Deliberately
//! a separate enum from `fornax_types::Verdict` — forcing every research
//! judgment into the runtime five-state vocabulary would collapse
//! distinctions (`Unreliable` vs `Incomplete`) a reviewer needs to make and
//! that the runtime verdict was never designed to carry. [`CaseLabel`]'s
//! mapping to `Verdict` is total and asserted by test, but it is a
//! many-to-one mapping, not an isomorphism.

use fornax_types::Verdict;

/// A reviewer's judgment about one candidate case. See module docs for why
/// this is not `Verdict`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CaseLabel {
    Reliable,
    Unreliable,
    Contradicted,
    Unsupported,
    Incomplete,
    /// Ground truth cannot honestly be established for this case (missing
    /// context, ambiguous claim, etc). A first-class terminal outcome, not
    /// an error — see [`crate::adjudication::state::AdjudicationState::NotEvaluable`].
    NotEvaluable,
}

impl CaseLabel {
    /// This label's `expected_verdict` for `fornax_bench::dataset::AdjudicatedExpectedOutcome`,
    /// or `None` for [`Self::NotEvaluable`] — which is excluded from export
    /// entirely (`crate::adjudication::gold` / the export CLI path), never
    /// forced into a placeholder verdict.
    ///
    /// `Verdict::Unavailable` deliberately has no `CaseLabel` that maps to
    /// it — `Unavailable` is a runtime capability-absence state, not a
    /// research judgment a human reviewer makes about a claim's evidence.
    pub fn expected_verdict(self) -> Option<Verdict> {
        match self {
            CaseLabel::Reliable => Some(Verdict::Verified),
            CaseLabel::Unsupported => Some(Verdict::Unverified),
            CaseLabel::Contradicted => Some(Verdict::Contradicted),
            CaseLabel::Incomplete | CaseLabel::Unreliable => Some(Verdict::Review),
            CaseLabel::NotEvaluable => None,
        }
    }
}

/// Why a case was judged `Unreliable`/`Contradicted`/`Unsupported`/
/// `Incomplete` — orthogonal to [`CaseLabel`] itself, so two reviewers can
/// agree on the label while recording different failure classes (a
/// disagreement worth reporting, not one that changes adjudication state —
/// see `state::derive_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    ClaimContradictedByEvidence,
    ClaimUnsupportedByEvidence,
    EvidenceMissing,
    EvidenceStaleOrMismatched,
    SensorDisagreement,
    Other,
}

/// A reviewer's confidence in their own label — ordinal, never a
/// probability (same discipline as `fornax_verify::fusion::UncertaintyBand`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Failure to construct a valid review submission.
#[derive(Debug, thiserror::Error)]
pub enum TaxonomyError {
    /// A `Reliable` label with `critical_failure: true`, or a `Reliable`
    /// label carrying a `failure_class` — both are self-contradictory: a
    /// reliable case has nothing that failed.
    #[error(
        "label Reliable is incompatible with critical_failure=true and/or a failure_class -- \
         a reliable case has nothing that failed"
    )]
    ReliableLabelWithFailureMetadata,
}

/// Validate that `label`'s failure metadata is internally consistent. Called
/// at review submission (`crate::adjudication::review::ReviewRecord::new`),
/// not just documented as a caller obligation.
pub fn validate_failure_metadata(
    label: CaseLabel,
    critical_failure: bool,
    failure_class: Option<FailureClass>,
) -> Result<(), TaxonomyError> {
    if label == CaseLabel::Reliable && (critical_failure || failure_class.is_some()) {
        return Err(TaxonomyError::ReliableLabelWithFailureMetadata);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_label_has_a_defined_verdict_mapping_or_is_explicitly_excluded() {
        let all = [
            CaseLabel::Reliable,
            CaseLabel::Unreliable,
            CaseLabel::Contradicted,
            CaseLabel::Unsupported,
            CaseLabel::Incomplete,
            CaseLabel::NotEvaluable,
        ];
        for label in all {
            match label {
                CaseLabel::NotEvaluable => assert_eq!(label.expected_verdict(), None),
                _ => assert!(label.expected_verdict().is_some()),
            }
        }
    }

    #[test]
    fn reliable_maps_to_verified() {
        assert_eq!(
            CaseLabel::Reliable.expected_verdict(),
            Some(Verdict::Verified)
        );
    }

    #[test]
    fn contradicted_maps_to_contradicted() {
        assert_eq!(
            CaseLabel::Contradicted.expected_verdict(),
            Some(Verdict::Contradicted)
        );
    }

    #[test]
    fn no_label_maps_to_unavailable() {
        let all = [
            CaseLabel::Reliable,
            CaseLabel::Unreliable,
            CaseLabel::Contradicted,
            CaseLabel::Unsupported,
            CaseLabel::Incomplete,
        ];
        for label in all {
            assert_ne!(label.expected_verdict(), Some(Verdict::Unavailable));
        }
    }

    #[test]
    fn reliable_with_critical_failure_is_refused() {
        let err = validate_failure_metadata(CaseLabel::Reliable, true, None).unwrap_err();
        assert!(matches!(
            err,
            TaxonomyError::ReliableLabelWithFailureMetadata
        ));
    }

    #[test]
    fn reliable_with_a_failure_class_is_refused() {
        let err = validate_failure_metadata(
            CaseLabel::Reliable,
            false,
            Some(FailureClass::EvidenceMissing),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TaxonomyError::ReliableLabelWithFailureMetadata
        ));
    }

    #[test]
    fn contradicted_with_a_failure_class_is_accepted() {
        validate_failure_metadata(
            CaseLabel::Contradicted,
            true,
            Some(FailureClass::ClaimContradictedByEvidence),
        )
        .unwrap();
    }
}
