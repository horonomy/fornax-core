//! Inter-rater agreement and label-distribution reporting (FORNX-342 scope:
//! "inter-rater agreement and label-distribution reports; preserve reviewer
//! disagreement rather than silently overwriting it").
//!
//! **Never a manufactured number.** [`cohens_kappa`] returns
//! [`AgreementStat::Insufficient`] below [`MIN_KAPPA_CASES`] double-reviewed
//! cases and [`AgreementStat::Undefined`] on a degenerate marginal (e.g.
//! every reviewer agreeing on one label, where kappa's expected-agreement
//! denominator is undefined) -- mirroring `fornax_verify::reliability`'s
//! existing `SampleSupport::InsufficientSupport` precedent: this module
//! never rounds an absent result up to a confident-looking float.

use std::collections::BTreeMap;

use crate::adjudication::review::ReviewOutcome;
use crate::adjudication::taxonomy::CaseLabel;

/// Minimum number of double-reviewed cases before [`cohens_kappa`] reports a
/// number at all.
pub const MIN_KAPPA_CASES: usize = 20;

/// A statistic that may be genuinely absent -- never a fabricated number.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgreementStat {
    Value { kappa: f64 },
    Insufficient { have: usize, needed: usize },
    Undefined { reason: String },
}

/// Why two reviewers' outcomes for the same case differed. Recorded and
/// reported -- never fed back into `state::derive_state` (only
/// `(label, critical_failure)` differing changes adjudication state; a
/// `failure_class`/`confidence` difference is real disagreement worth
/// surfacing here but does not, by itself, route a case to `Disagreed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisagreementReason {
    LabelDiffers,
    CriticalFailureDiffers,
    FailureClassDiffers,
}

/// Label distribution across every `Label` outcome given (an `Unresolved`
/// outcome contributes nothing -- it carries no `CaseLabel`).
pub fn label_distribution(outcomes: &[ReviewOutcome]) -> BTreeMap<CaseLabel, usize> {
    let mut dist = BTreeMap::new();
    for outcome in outcomes {
        if let ReviewOutcome::Label { label, .. } = outcome {
            *dist.entry(*label).or_insert(0) += 1;
        }
    }
    dist
}

/// Raw percent agreement on `(label, critical_failure)` across `pairs` of
/// same-case reviews. `None` if `pairs` is empty (nothing to compute over).
pub fn raw_agreement(pairs: &[(ReviewOutcome, ReviewOutcome)]) -> Option<f64> {
    if pairs.is_empty() {
        return None;
    }
    let agreeing = pairs.iter().filter(|(a, b)| outcomes_agree(a, b)).count();
    Some(agreeing as f64 / pairs.len() as f64)
}

/// Every reason `a` and `b` differ, for one pair (empty if they fully
/// agree). Only meaningful for two `Label` outcomes -- an `Unresolved`
/// outcome paired with anything is reported as `LabelDiffers` (there is no
/// label to compare further).
pub fn disagreement_reasons(a: &ReviewOutcome, b: &ReviewOutcome) -> Vec<DisagreementReason> {
    match (a, b) {
        (
            ReviewOutcome::Label {
                label: la,
                critical_failure: ca,
                failure_class: fa,
            },
            ReviewOutcome::Label {
                label: lb,
                critical_failure: cb,
                failure_class: fb,
            },
        ) => {
            let mut reasons = Vec::new();
            if la != lb {
                reasons.push(DisagreementReason::LabelDiffers);
            }
            if ca != cb {
                reasons.push(DisagreementReason::CriticalFailureDiffers);
            }
            if fa != fb {
                reasons.push(DisagreementReason::FailureClassDiffers);
            }
            reasons
        }
        _ if outcomes_agree(a, b) => vec![],
        _ => vec![DisagreementReason::LabelDiffers],
    }
}

fn outcomes_agree(a: &ReviewOutcome, b: &ReviewOutcome) -> bool {
    match (a, b) {
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
        ) => la == lb && ca == cb,
        (ReviewOutcome::Unresolved { .. }, ReviewOutcome::Unresolved { .. }) => true,
        _ => false,
    }
}

/// Cohen's kappa over `pairs` (each a same-case, two-distinct-reviewer
/// `(outcome, outcome)` pair on `(label, critical_failure)` identity).
/// Requires `pairs.len() >= MIN_KAPPA_CASES` and non-degenerate marginals
/// (both reviewers must have used more than one distinct category between
/// them) -- otherwise returns [`AgreementStat::Insufficient`] /
/// [`AgreementStat::Undefined`], never a number.
pub fn cohens_kappa(pairs: &[(ReviewOutcome, ReviewOutcome)]) -> AgreementStat {
    if pairs.len() < MIN_KAPPA_CASES {
        return AgreementStat::Insufficient {
            have: pairs.len(),
            needed: MIN_KAPPA_CASES,
        };
    }

    // Reduce each outcome to a comparable category key; Unresolved is its
    // own category.
    fn category(o: &ReviewOutcome) -> String {
        match o {
            ReviewOutcome::Label {
                label,
                critical_failure,
                ..
            } => format!("{label:?}:{critical_failure}"),
            ReviewOutcome::Unresolved { .. } => "unresolved".to_string(),
        }
    }

    let n = pairs.len() as f64;
    let observed_agreement = pairs
        .iter()
        .filter(|(a, b)| category(a) == category(b))
        .count() as f64
        / n;

    let mut first_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut second_counts: BTreeMap<String, usize> = BTreeMap::new();
    for (a, b) in pairs {
        *first_counts.entry(category(a)).or_insert(0) += 1;
        *second_counts.entry(category(b)).or_insert(0) += 1;
    }

    let all_categories: std::collections::BTreeSet<&String> =
        first_counts.keys().chain(second_counts.keys()).collect();
    if all_categories.len() < 2 {
        return AgreementStat::Undefined {
            reason: "every review used the same category -- kappa's expected-agreement term is \
                     undefined when there is no variation to correct for chance against"
                .to_string(),
        };
    }

    let expected_agreement: f64 = all_categories
        .iter()
        .map(|cat| {
            let p1 = *first_counts.get(*cat).unwrap_or(&0) as f64 / n;
            let p2 = *second_counts.get(*cat).unwrap_or(&0) as f64 / n;
            p1 * p2
        })
        .sum();

    if (1.0 - expected_agreement).abs() < f64::EPSILON {
        return AgreementStat::Undefined {
            reason: "expected agreement is 1.0 -- kappa's denominator is zero".to_string(),
        };
    }

    let kappa = (observed_agreement - expected_agreement) / (1.0 - expected_agreement);
    AgreementStat::Value { kappa }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adjudication::taxonomy::CaseLabel;

    fn label(l: CaseLabel, critical: bool) -> ReviewOutcome {
        ReviewOutcome::Label {
            label: l,
            critical_failure: critical,
            failure_class: None,
        }
    }

    #[test]
    fn label_distribution_ignores_unresolved_outcomes() {
        let outcomes = vec![
            label(CaseLabel::Reliable, false),
            label(CaseLabel::Reliable, false),
            ReviewOutcome::Unresolved { reason: "x".into() },
        ];
        let dist = label_distribution(&outcomes);
        assert_eq!(dist.get(&CaseLabel::Reliable), Some(&2));
        assert_eq!(dist.len(), 1);
    }

    #[test]
    fn raw_agreement_over_all_agreeing_pairs_is_one() {
        let pairs = vec![
            (
                label(CaseLabel::Reliable, false),
                label(CaseLabel::Reliable, false),
            ),
            (
                label(CaseLabel::Reliable, false),
                label(CaseLabel::Reliable, false),
            ),
        ];
        assert_eq!(raw_agreement(&pairs), Some(1.0));
    }

    #[test]
    fn raw_agreement_is_none_on_empty_input() {
        assert_eq!(raw_agreement(&[]), None);
    }

    #[test]
    fn disagreement_reasons_reports_every_differing_field() {
        let a = ReviewOutcome::Label {
            label: CaseLabel::Contradicted,
            critical_failure: true,
            failure_class: Some(crate::adjudication::taxonomy::FailureClass::EvidenceMissing),
        };
        let b = ReviewOutcome::Label {
            label: CaseLabel::Unreliable,
            critical_failure: false,
            failure_class: Some(crate::adjudication::taxonomy::FailureClass::Other),
        };
        let reasons = disagreement_reasons(&a, &b);
        assert!(reasons.contains(&DisagreementReason::LabelDiffers));
        assert!(reasons.contains(&DisagreementReason::CriticalFailureDiffers));
        assert!(reasons.contains(&DisagreementReason::FailureClassDiffers));
    }

    #[test]
    fn kappa_is_insufficient_below_the_minimum_case_count() {
        let pairs: Vec<_> = (0..5)
            .map(|_| {
                (
                    label(CaseLabel::Reliable, false),
                    label(CaseLabel::Unreliable, false),
                )
            })
            .collect();
        assert_eq!(
            cohens_kappa(&pairs),
            AgreementStat::Insufficient {
                have: 5,
                needed: MIN_KAPPA_CASES
            }
        );
    }

    #[test]
    fn kappa_is_undefined_on_degenerate_marginals() {
        let pairs: Vec<_> = (0..MIN_KAPPA_CASES)
            .map(|_| {
                (
                    label(CaseLabel::Reliable, false),
                    label(CaseLabel::Reliable, false),
                )
            })
            .collect();
        assert!(matches!(
            cohens_kappa(&pairs),
            AgreementStat::Undefined { .. }
        ));
    }

    #[test]
    fn kappa_reports_a_value_with_enough_varied_cases() {
        let mut pairs = Vec::new();
        for _ in 0..15 {
            pairs.push((
                label(CaseLabel::Reliable, false),
                label(CaseLabel::Reliable, false),
            ));
        }
        for _ in 0..15 {
            pairs.push((
                label(CaseLabel::Unreliable, false),
                label(CaseLabel::Contradicted, false),
            ));
        }
        assert!(matches!(cohens_kappa(&pairs), AgreementStat::Value { .. }));
    }
}
