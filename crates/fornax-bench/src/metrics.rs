//! Fixed-risk operational metrics over a set of [`PredictionRecord`]s
//! (FORNX-95 AC: "metrics prioritize fixed-risk operational utility, not
//! only aggregate accuracy"; AC: "benchmark distinguishes unavailable
//! evidence from incorrect predictions").
//!
//! # The three-bucket discipline
//!
//! Every prediction lands in exactly one of three buckets, never two:
//!
//! - **evidence-unavailable** — [`PredictionRecord::evidence_unavailable`]
//!   is `true`. Excluded from `correct_count`/`incorrect_count` and from
//!   every recall/precision/false-positive-rate computation. This is the
//!   bucket AC 4 is about: a claim the pipeline honestly couldn't evaluate
//!   must never silently count as a wrong answer, and must never count as a
//!   right one either.
//! - **correct** — evidence was available and `predicted_verdict ==
//!   expected_verdict`.
//! - **incorrect** — evidence was available and the two disagree.
//!
//! `review_burden` is the one metric computed over *all* predictions
//! (including the unavailable bucket) — a claim the pipeline couldn't
//! evaluate still gets routed to some [`RecommendationAction`], and that
//! routing is exactly what review burden measures, independent of whether
//! the routing turned out to be "correct".
//!
//! # What counts as a positive prediction
//!
//! `critical_failure_recall`/`precision`/`false_positive_rate` treat
//! [`RecommendationAction::Block`] — and only `Block` — as "predicted
//! positive". `Review` is deliberately not folded in here: `review_burden`
//! already reports the broader `Review|Block` fraction as its own,
//! separate number, and folding `Review` into "positive" here would let a
//! policy that routes everything uncertain to `Review` look like it has
//! high recall/low false-positive-rate without ever actually blocking
//! anything. See `metrics_tests::review_is_never_counted_as_a_positive_prediction`
//! for the pinned behavior.
//!
//! # Honest "no data"
//!
//! Every rate is `Option<f64>` — `None` when its denominator is zero (no
//! evaluable predictions at all, or no critical-failure cases present in
//! the evaluable subset), never a fabricated `0.0`/`1.0` that could be
//! misread as a real finding from an empty or degenerate input.
//!
//! # Synthetic-label refusal gate
//!
//! `contains_synthetic_labels` is `true` whenever any contributing
//! [`PredictionRecord::is_synthetic`] is `true`. A caller rendering a
//! [`MetricsReport`] as a human-facing result MUST check this field and
//! refuse to present it as a real calibration finding when it is set — see
//! the crate-level docs and this ticket's PR body for the load-bearing
//! reason this exists.

use serde::{Deserialize, Serialize};

use fornax_verify::decision::RecommendationAction;

use crate::harness::PredictionRecord;

/// Fixed-risk operational metrics computed over one set of
/// [`PredictionRecord`]s. See module docs for the three-bucket discipline,
/// the positive-prediction definition, and the synthetic-label gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsReport {
    pub total: usize,
    pub evidence_unavailable_count: usize,
    /// `1 - evidence_unavailable_count / total`. `None` iff `total == 0`.
    pub evidence_coverage: Option<f64>,
    pub evaluable_count: usize,
    pub correct_count: usize,
    pub incorrect_count: usize,
    /// True-positive rate among evaluable, `critical_failure == true`
    /// records: `Block` predicted / all `critical_failure` records. `None`
    /// iff there are zero evaluable `critical_failure` records.
    pub critical_failure_recall: Option<f64>,
    /// `Block` predictions that were actually `critical_failure` / all
    /// `Block` predictions among evaluable records. `None` iff there are
    /// zero evaluable `Block` predictions.
    pub precision: Option<f64>,
    /// `Block` predicted on a non-`critical_failure` evaluable record / all
    /// non-`critical_failure` evaluable records. `None` iff there are zero
    /// evaluable non-`critical_failure` records.
    pub false_positive_rate: Option<f64>,
    /// Fraction of ALL predictions (including evidence-unavailable ones)
    /// whose `predicted_action` is `Review` or `Block` rather than
    /// `Proceed`. `None` iff `total == 0`.
    pub review_burden: Option<f64>,
    /// See module docs' "Synthetic-label refusal gate".
    pub contains_synthetic_labels: bool,
}

fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

/// Computes a [`MetricsReport`] over `predictions`. Pure — no I/O, no clock
/// read, same input always produces the same output (AC 1).
pub fn compute_metrics(predictions: &[PredictionRecord]) -> MetricsReport {
    let total = predictions.len();
    let evidence_unavailable_count = predictions
        .iter()
        .filter(|p| p.evidence_unavailable)
        .count();
    let evaluable: Vec<&PredictionRecord> = predictions
        .iter()
        .filter(|p| !p.evidence_unavailable)
        .collect();
    let evaluable_count = evaluable.len();

    let correct_count = evaluable
        .iter()
        .filter(|p| p.predicted_verdict == p.expected_verdict)
        .count();
    let incorrect_count = evaluable_count - correct_count;

    let true_positives = evaluable
        .iter()
        .filter(|p| p.critical_failure && p.predicted_action == RecommendationAction::Block)
        .count();
    let false_negatives = evaluable
        .iter()
        .filter(|p| p.critical_failure && p.predicted_action != RecommendationAction::Block)
        .count();
    let false_positives = evaluable
        .iter()
        .filter(|p| !p.critical_failure && p.predicted_action == RecommendationAction::Block)
        .count();
    let true_negatives = evaluable
        .iter()
        .filter(|p| !p.critical_failure && p.predicted_action != RecommendationAction::Block)
        .count();

    let review_or_block = predictions
        .iter()
        .filter(|p| p.predicted_action != RecommendationAction::Proceed)
        .count();

    MetricsReport {
        total,
        evidence_unavailable_count,
        evidence_coverage: ratio(total - evidence_unavailable_count, total),
        evaluable_count,
        correct_count,
        incorrect_count,
        critical_failure_recall: ratio(true_positives, true_positives + false_negatives),
        precision: ratio(true_positives, true_positives + false_positives),
        false_positive_rate: ratio(false_positives, false_positives + true_negatives),
        review_burden: ratio(review_or_block, total),
        contains_synthetic_labels: predictions.iter().any(|p| p.is_synthetic),
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::*;
    use fornax_types::Verdict;
    use uuid::Uuid;

    fn record(
        expected_verdict: Verdict,
        predicted_verdict: Verdict,
        predicted_action: RecommendationAction,
        critical_failure: bool,
        evidence_unavailable: bool,
    ) -> PredictionRecord {
        PredictionRecord {
            trajectory_id: "t".into(),
            claim_id: Uuid::new_v4(),
            predicted_verdict,
            predicted_action,
            expected_verdict,
            critical_failure,
            evidence_unavailable,
            ablation_removed_evidence: false,
            is_synthetic: true,
        }
    }

    #[test]
    fn empty_input_yields_honest_no_data_not_fabricated_zeros() {
        let report = compute_metrics(&[]);
        assert_eq!(report.total, 0);
        assert_eq!(report.evidence_coverage, None);
        assert_eq!(report.critical_failure_recall, None);
        assert_eq!(report.precision, None);
        assert_eq!(report.false_positive_rate, None);
        assert_eq!(report.review_burden, None);
    }

    /// The test the advisor named as the one that would catch a subtle bug:
    /// an evidence-unavailable prediction whose predicted verdict does NOT
    /// match its expected verdict must never land in `incorrect_count`.
    #[test]
    fn unavailable_prediction_is_excluded_from_correct_and_incorrect_even_when_verdicts_disagree() {
        let unavailable_and_wrong = record(
            Verdict::Verified,
            Verdict::Unverified,
            RecommendationAction::Review,
            false,
            true,
        );
        let report = compute_metrics(&[unavailable_and_wrong]);
        assert_eq!(report.total, 1);
        assert_eq!(report.evidence_unavailable_count, 1);
        assert_eq!(report.evaluable_count, 0);
        assert_eq!(report.correct_count, 0);
        assert_eq!(
            report.incorrect_count, 0,
            "an unavailable-evidence record must never be folded into 'incorrect'"
        );
    }

    #[test]
    fn evidence_coverage_reflects_the_unavailable_fraction() {
        let available = record(
            Verdict::Verified,
            Verdict::Verified,
            RecommendationAction::Proceed,
            false,
            false,
        );
        let unavailable = record(
            Verdict::Unavailable,
            Verdict::Unavailable,
            RecommendationAction::Block,
            false,
            true,
        );
        let report = compute_metrics(&[available, unavailable]);
        assert_eq!(report.total, 2);
        assert_eq!(report.evidence_unavailable_count, 1);
        assert_eq!(report.evidence_coverage, Some(0.5));
    }

    #[test]
    fn review_is_never_counted_as_a_positive_prediction() {
        // A critical-failure case predicted Review (not Block) must count as
        // a false negative for recall, never a true positive.
        let missed = record(
            Verdict::Contradicted,
            Verdict::Contradicted,
            RecommendationAction::Review,
            true,
            false,
        );
        let report = compute_metrics(&[missed]);
        assert_eq!(report.critical_failure_recall, Some(0.0));
    }

    #[test]
    fn review_burden_counts_review_and_block_across_all_predictions_including_unavailable() {
        let proceed = record(
            Verdict::Verified,
            Verdict::Verified,
            RecommendationAction::Proceed,
            false,
            false,
        );
        let review = record(
            Verdict::Verified,
            Verdict::Verified,
            RecommendationAction::Review,
            false,
            false,
        );
        let block_unavailable = record(
            Verdict::Unavailable,
            Verdict::Unavailable,
            RecommendationAction::Block,
            false,
            true,
        );
        let report = compute_metrics(&[proceed, review, block_unavailable]);
        assert_eq!(report.total, 3);
        // 2 of 3 predictions are Review/Block, including the
        // evidence-unavailable one.
        assert_eq!(report.review_burden, Some(2.0 / 3.0));
    }

    #[test]
    fn perfect_recall_and_precision_on_a_clean_positive_and_negative_pair() {
        let true_positive = record(
            Verdict::Contradicted,
            Verdict::Contradicted,
            RecommendationAction::Block,
            true,
            false,
        );
        let true_negative = record(
            Verdict::Verified,
            Verdict::Verified,
            RecommendationAction::Proceed,
            false,
            false,
        );
        let report = compute_metrics(&[true_positive, true_negative]);
        assert_eq!(report.critical_failure_recall, Some(1.0));
        assert_eq!(report.precision, Some(1.0));
        assert_eq!(report.false_positive_rate, Some(0.0));
    }

    #[test]
    fn contains_synthetic_labels_propagates_from_any_record() {
        let mut r = record(
            Verdict::Verified,
            Verdict::Verified,
            RecommendationAction::Proceed,
            false,
            false,
        );
        r.is_synthetic = false;
        let report_all_real = compute_metrics(&[r.clone()]);
        assert!(!report_all_real.contains_synthetic_labels);

        let mut synthetic = r;
        synthetic.is_synthetic = true;
        let report_mixed = compute_metrics(&[synthetic]);
        assert!(report_mixed.contains_synthetic_labels);
    }
}
