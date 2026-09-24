//! The regression gate (FORNX-344): a fail-closed
//! PASS/BLOCK/INCONCLUSIVE/UNTESTED verdict over a
//! [`crate::regression::RegressionComparison`], using the exact verdict
//! vocabulary `docs/release-assurance-policy.md` defines for release
//! gating -- reused, not reinvented, and never confused with Fornax's own
//! five-state product verdict (`VERIFIED`/`UNVERIFIED`/`CONTRADICTED`/
//! `REVIEW`/`UNAVAILABLE`), which answers a different question about a
//! different thing.
//!
//! # The one real trap this module exists to get right
//!
//! A [`RegressionBudget`] with zero [`BudgetRule`]s must resolve to
//! [`GateVerdict::Untested`], never [`GateVerdict::Pass`]. `Iterator::all`
//! over an empty rule list is vacuously `true` -- a naive
//! `rules.iter().all(|r| rule_passes(r))` implementation would silently
//! report PASS on a budget nobody has calibrated yet, which is exactly the
//! "no fake PASS" failure `docs/release-assurance-policy.md`'s own verdict
//! table forbids ("Silently converting `UNTESTED` into `PASS` is never
//! permitted"). `evaluate_gate` checks emptiness explicitly before ever
//! looking at a rule, and the fixture this crate commits
//! (`fixtures/integrity-lab/budget.json`) ships with `calibrated: false,
//! rules: []` for exactly this reason -- see
//! `gate_tests::an_uncalibrated_empty_budget_is_untested_never_pass`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::regression::{RegressionClass, RegressionComparison};
use crate::slice::{Slice, SliceKey};

/// `docs/release-assurance-policy.md`'s release-candidate verdict
/// vocabulary, reused verbatim for this gate's own verdict -- a different
/// question (may this regression-lab run proceed?) from the same document,
/// never Fornax's product verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    Pass,
    Block,
    Inconclusive,
    Untested,
}

impl GateVerdict {
    /// Worst-of-many ordering per `docs/release-assurance-policy.md`: "A
    /// gate's overall verdict is the worst of its constituent check
    /// verdicts." `Block` is worst, `Pass` is best.
    fn severity(self) -> u8 {
        match self {
            GateVerdict::Pass => 0,
            GateVerdict::Untested => 1,
            GateVerdict::Inconclusive => 2,
            GateVerdict::Block => 3,
        }
    }
}

/// A verdict plus the concrete reason it was reached -- never a bare enum,
/// so a reader never has to re-derive why the gate landed where it did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateReason {
    pub verdict: GateVerdict,
    pub detail: String,
}

/// One budget rule: the maximum number of `Regressed` cases tolerated
/// within one named [`SliceKey`]'s trajectory set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetRule {
    pub slice: SliceKey,
    pub max_regressions: usize,
}

/// The full regression budget. `calibrated: false` (this crate's committed
/// fixture's actual value) states honestly that no real threshold has been
/// derived from a real dataset yet -- see this ticket's ADR for why no
/// numeric threshold is committed today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionBudget {
    pub calibrated: bool,
    pub rules: Vec<BudgetRule>,
}

/// Evaluates `comparison` (with `slices` computed over the same dataset
/// `comparison` was built from) against `budget`. See module docs for the
/// fail-closed empty-budget trap this function's very first check exists
/// to avoid.
pub fn evaluate_gate(
    comparison: &RegressionComparison,
    slices: &[Slice],
    budget: &RegressionBudget,
) -> GateReason {
    if !budget.calibrated || budget.rules.is_empty() {
        return GateReason {
            verdict: GateVerdict::Untested,
            detail: "regression budget is not calibrated (or has zero rules) -- no threshold \
                     exists yet to compare this run against, and an empty check set must never \
                     silently resolve to PASS"
                .to_string(),
        };
    }

    if comparison.baseline_manifest.dataset_content_hash
        != comparison.current_manifest.dataset_content_hash
    {
        return GateReason {
            verdict: GateVerdict::Inconclusive,
            detail: format!(
                "baseline ({}) and current ({}) ran over different dataset content -- a \
                 regression count between two different datasets is not a fair comparison",
                comparison.baseline_manifest.dataset_content_hash,
                comparison.current_manifest.dataset_content_hash
            ),
        };
    }

    let mut worst = GateReason {
        verdict: GateVerdict::Pass,
        detail: format!("all {} budget rule(s) satisfied", budget.rules.len()),
    };
    for rule in &budget.rules {
        let reason = evaluate_rule(rule, comparison, slices);
        if reason.verdict.severity() > worst.verdict.severity() {
            worst = reason;
        }
    }
    worst
}

fn evaluate_rule(
    rule: &BudgetRule,
    comparison: &RegressionComparison,
    slices: &[Slice],
) -> GateReason {
    let slice = slices.iter().find(|s| s.key == rule.slice);
    let slice = match slice {
        Some(s) if !s.trajectory_ids.is_empty() => s,
        _ => {
            return GateReason {
                verdict: GateVerdict::Untested,
                detail: format!(
                    "no trajectory in this run belongs to slice {:?} -- this rule's own \
                     required check did not run at all",
                    rule.slice
                ),
            }
        }
    };

    let ids: BTreeSet<&str> = slice.trajectory_ids.iter().map(String::as_str).collect();
    let regressed_in_slice = comparison
        .cases
        .iter()
        .filter(|c| ids.contains(c.trajectory_id.as_str()) && c.class == RegressionClass::Regressed)
        .count();

    if regressed_in_slice > rule.max_regressions {
        GateReason {
            verdict: GateVerdict::Block,
            detail: format!(
                "{regressed_in_slice} regression(s) in slice {:?}, budget allows {}",
                rule.slice, rule.max_regressions
            ),
        }
    } else {
        GateReason {
            verdict: GateVerdict::Pass,
            detail: format!(
                "{regressed_in_slice} regression(s) in slice {:?}, within budget {}",
                rule.slice, rule.max_regressions
            ),
        }
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use crate::baseline::{BaselineReport, CostSignal};
    use crate::harness::PredictionRecord;
    use crate::manifest::{RunManifest, MANIFEST_SCHEMA_VERSION};
    use crate::metrics::compute_metrics;
    use crate::regression::compare;
    use fornax_types::Verdict;
    use fornax_verify::decision::{RecommendationAction, RiskClass};
    use fornax_verify::fusion::UncertaintyBand;
    use uuid::Uuid;

    fn manifest(dataset_content_hash: &str) -> RunManifest {
        RunManifest {
            manifest_schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            dataset_version: "v1".into(),
            dataset_content_hash: dataset_content_hash.to_string(),
            contains_synthetic_labels: true,
            fusion_policy_name: "baseline".into(),
            fusion_policy_version: 1,
            decision_policy_name: "default".into(),
            decision_policy_version: 1,
            risk_class: RiskClass::Balanced,
            disabled_sensors: Default::default(),
            judge_identity: None,
            run_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn record(
        trajectory_id: &str,
        predicted_verdict: Verdict,
        expected_verdict: Verdict,
    ) -> PredictionRecord {
        PredictionRecord {
            trajectory_id: trajectory_id.to_string(),
            claim_id: Uuid::new_v4(),
            predicted_verdict,
            predicted_action: RecommendationAction::Proceed,
            expected_verdict,
            critical_failure: false,
            uncertainty: UncertaintyBand::Qualified,
            counted_link_ids: Vec::new(),
            discounted_link_ids: Vec::new(),
            missing_evidence_ids: Vec::new(),
            evidence_unavailable: false,
            ablation_removed_evidence: false,
            is_synthetic: true,
        }
    }

    fn report(dataset_content_hash: &str, predictions: Vec<PredictionRecord>) -> BaselineReport {
        BaselineReport {
            baseline_schema_version: "1".into(),
            manifest: manifest(dataset_content_hash),
            metrics: compute_metrics(&predictions),
            predictions,
            cost: CostSignal::Unmeasured {
                reason: "test".into(),
            },
        }
    }

    #[test]
    fn an_uncalibrated_empty_budget_is_untested_never_pass() {
        let baseline = report(
            "h1",
            vec![record("t1", Verdict::Verified, Verdict::Verified)],
        );
        let current = report(
            "h1",
            vec![record("t1", Verdict::Verified, Verdict::Verified)],
        );
        let comparison = compare(&baseline, &current);
        let budget = RegressionBudget {
            calibrated: false,
            rules: vec![],
        };
        let reason = evaluate_gate(&comparison, &[], &budget);
        assert_eq!(
            reason.verdict,
            GateVerdict::Untested,
            "an empty/uncalibrated budget must never vacuously resolve to Pass: {reason:?}"
        );
    }

    #[test]
    fn a_calibrated_budget_with_rules_but_zero_matching_slice_data_is_untested() {
        let baseline = report(
            "h1",
            vec![record("t1", Verdict::Verified, Verdict::Verified)],
        );
        let current = report(
            "h1",
            vec![record("t1", Verdict::Verified, Verdict::Verified)],
        );
        let comparison = compare(&baseline, &current);
        let budget = RegressionBudget {
            calibrated: true,
            rules: vec![BudgetRule {
                slice: SliceKey::Sensor("git_probe".into()),
                max_regressions: 0,
            }],
        };
        // No Slice for "git_probe" is passed in -- this run has no evidence
        // from that sensor at all, so the rule's own check did not run.
        let reason = evaluate_gate(&comparison, &[], &budget);
        assert_eq!(reason.verdict, GateVerdict::Untested);
    }

    #[test]
    fn a_regression_beyond_budget_blocks() {
        let baseline = report(
            "h1",
            vec![record("t1", Verdict::Verified, Verdict::Verified)],
        );
        let current = report(
            "h1",
            vec![record("t1", Verdict::Unverified, Verdict::Verified)],
        );
        let comparison = compare(&baseline, &current);
        let slices = vec![Slice {
            key: SliceKey::Overall,
            trajectory_ids: vec!["t1".to_string()],
        }];
        let budget = RegressionBudget {
            calibrated: true,
            rules: vec![BudgetRule {
                slice: SliceKey::Overall,
                max_regressions: 0,
            }],
        };
        let reason = evaluate_gate(&comparison, &slices, &budget);
        assert_eq!(reason.verdict, GateVerdict::Block);
    }

    #[test]
    fn a_regression_within_budget_passes() {
        let baseline = report(
            "h1",
            vec![record("t1", Verdict::Verified, Verdict::Verified)],
        );
        let current = report(
            "h1",
            vec![record("t1", Verdict::Unverified, Verdict::Verified)],
        );
        let comparison = compare(&baseline, &current);
        let slices = vec![Slice {
            key: SliceKey::Overall,
            trajectory_ids: vec!["t1".to_string()],
        }];
        let budget = RegressionBudget {
            calibrated: true,
            rules: vec![BudgetRule {
                slice: SliceKey::Overall,
                max_regressions: 1,
            }],
        };
        let reason = evaluate_gate(&comparison, &slices, &budget);
        assert_eq!(reason.verdict, GateVerdict::Pass);
    }

    #[test]
    fn comparing_across_different_dataset_content_is_inconclusive() {
        let baseline = report(
            "h1",
            vec![record("t1", Verdict::Verified, Verdict::Verified)],
        );
        let current = report(
            "h2",
            vec![record("t1", Verdict::Verified, Verdict::Verified)],
        );
        let comparison = compare(&baseline, &current);
        let budget = RegressionBudget {
            calibrated: true,
            rules: vec![BudgetRule {
                slice: SliceKey::Overall,
                max_regressions: 0,
            }],
        };
        let reason = evaluate_gate(&comparison, &[], &budget);
        assert_eq!(reason.verdict, GateVerdict::Inconclusive);
    }

    #[test]
    fn block_outranks_inconclusive_and_untested_when_multiple_rules_disagree() {
        // Same dataset content, so no Inconclusive short-circuit -- two
        // rules, one Blocking and one Untested, must resolve to the worst:
        // Block.
        let baseline = report(
            "h1",
            vec![
                record("t1", Verdict::Verified, Verdict::Verified),
                record("t2", Verdict::Verified, Verdict::Verified),
            ],
        );
        let current = report(
            "h1",
            vec![
                record("t1", Verdict::Unverified, Verdict::Verified),
                record("t2", Verdict::Verified, Verdict::Verified),
            ],
        );
        let comparison = compare(&baseline, &current);
        let slices = vec![Slice {
            key: SliceKey::Overall,
            trajectory_ids: vec!["t1".to_string(), "t2".to_string()],
        }];
        let budget = RegressionBudget {
            calibrated: true,
            rules: vec![
                BudgetRule {
                    slice: SliceKey::Overall,
                    max_regressions: 0,
                },
                BudgetRule {
                    slice: SliceKey::Sensor("no_such_sensor".into()),
                    max_regressions: 0,
                },
            ],
        };
        let reason = evaluate_gate(&comparison, &slices, &budget);
        assert_eq!(reason.verdict, GateVerdict::Block);
    }
}
