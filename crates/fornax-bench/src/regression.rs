//! Case-level regression comparison (FORNX-344): diffs a fresh
//! [`crate::baseline::BaselineReport`] against a previously frozen one.
//!
//! Cases are matched by [`crate::harness::PredictionRecord::trajectory_id`]
//! -- **never by position** (never `zip`). A dataset can grow, shrink, or
//! reorder its trajectories between two runs, and matching by index would
//! silently compare unrelated cases whenever that happens; matching by id
//! makes an added/removed trajectory its own honest [`RegressionClass`]
//! instead of a spurious mismatch on some other case.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::baseline::BaselineReport;
use crate::harness::PredictionRecord;
use crate::manifest::RunManifest;
use crate::metrics::is_correct;

pub const REGRESSION_SCHEMA_VERSION: &str = "1";

/// How one case's outcome moved between the baseline and the current run.
/// Every case lands in exactly one class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegressionClass {
    /// The two `PredictionRecord`s are field-for-field identical.
    Unchanged,
    /// Correctness stayed the same, but a non-outcome field moved (e.g. the
    /// uncertainty band, or which links were counted/discounted) --
    /// reported so a reviewer can see evidence-attribution drift even when
    /// the bottom-line verdict/action did not change.
    ChangedNoOutcomeShift,
    /// Was incorrect (or evidence-unavailable) in the baseline, is correct
    /// in the current run.
    Improved,
    /// Was correct in the baseline, is incorrect in the current run. This
    /// is the class `gate::evaluate_gate` treats as a blocker signal.
    Regressed,
    /// Was evaluable in the baseline, is `evidence_unavailable` in the
    /// current run.
    NewlyUnavailable,
    /// Was `evidence_unavailable` in the baseline, is evaluable in the
    /// current run.
    NewlyEvaluable,
    /// This trajectory id exists in the current run but not the baseline.
    Added,
    /// This trajectory id exists in the baseline but not the current run.
    Removed,
}

/// Which [`PredictionRecord::counted_link_ids`]/`discounted_link_ids`/
/// `missing_evidence_ids` sets changed between the two runs, for a case
/// present in both.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EvidenceDelta {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counted_added: Vec<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counted_removed: Vec<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discounted_added: Vec<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discounted_removed: Vec<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_added: Vec<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_removed: Vec<uuid::Uuid>,
}

impl EvidenceDelta {
    fn is_empty(&self) -> bool {
        self == &EvidenceDelta::default()
    }

    fn between(baseline: &PredictionRecord, current: &PredictionRecord) -> Self {
        Self {
            counted_added: added(&baseline.counted_link_ids, &current.counted_link_ids),
            counted_removed: added(&current.counted_link_ids, &baseline.counted_link_ids),
            discounted_added: added(&baseline.discounted_link_ids, &current.discounted_link_ids),
            discounted_removed: added(&current.discounted_link_ids, &baseline.discounted_link_ids),
            missing_added: added(
                &baseline.missing_evidence_ids,
                &current.missing_evidence_ids,
            ),
            missing_removed: added(
                &current.missing_evidence_ids,
                &baseline.missing_evidence_ids,
            ),
        }
    }
}

/// Ids present in `to` but not in `from`, sorted for determinism.
fn added(from: &[uuid::Uuid], to: &[uuid::Uuid]) -> Vec<uuid::Uuid> {
    let from_set: std::collections::BTreeSet<_> = from.iter().collect();
    let mut result: Vec<uuid::Uuid> = to
        .iter()
        .filter(|id| !from_set.contains(id))
        .copied()
        .collect();
    result.sort();
    result
}

/// One trajectory id's full delta.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseDelta {
    pub trajectory_id: String,
    pub class: RegressionClass,
    pub baseline: Option<PredictionRecord>,
    pub current: Option<PredictionRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_delta: Option<EvidenceDelta>,
}

/// Full case-level diff between two [`BaselineReport`]s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegressionComparison {
    pub regression_schema_version: String,
    pub baseline_manifest: RunManifest,
    pub current_manifest: RunManifest,
    pub cases: Vec<CaseDelta>,
    pub regressed_count: usize,
    pub improved_count: usize,
    pub added_count: usize,
    pub removed_count: usize,
}

/// Compares `baseline` against `current`, matching cases by
/// `trajectory_id`. Pure and deterministic; `cases` is sorted by
/// `trajectory_id`.
pub fn compare(baseline: &BaselineReport, current: &BaselineReport) -> RegressionComparison {
    let baseline_by_id: BTreeMap<&str, &PredictionRecord> = baseline
        .predictions
        .iter()
        .map(|p| (p.trajectory_id.as_str(), p))
        .collect();
    let current_by_id: BTreeMap<&str, &PredictionRecord> = current
        .predictions
        .iter()
        .map(|p| (p.trajectory_id.as_str(), p))
        .collect();

    let mut all_ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    all_ids.extend(baseline_by_id.keys().copied());
    all_ids.extend(current_by_id.keys().copied());

    let mut cases = Vec::new();
    let mut regressed_count = 0;
    let mut improved_count = 0;
    let mut added_count = 0;
    let mut removed_count = 0;

    for id in all_ids {
        let b = baseline_by_id.get(id).copied();
        let c = current_by_id.get(id).copied();
        let (class, evidence_delta) = match (b, c) {
            (None, Some(_)) => {
                added_count += 1;
                (RegressionClass::Added, None)
            }
            (Some(_), None) => {
                removed_count += 1;
                (RegressionClass::Removed, None)
            }
            (Some(b), Some(c)) => {
                let class = classify(b, c);
                if class == RegressionClass::Regressed {
                    regressed_count += 1;
                }
                if class == RegressionClass::Improved {
                    improved_count += 1;
                }
                let delta = EvidenceDelta::between(b, c);
                (class, if delta.is_empty() { None } else { Some(delta) })
            }
            (None, None) => unreachable!("id came from one of the two maps"),
        };
        cases.push(CaseDelta {
            trajectory_id: id.to_string(),
            class,
            baseline: b.cloned(),
            current: c.cloned(),
            evidence_delta,
        });
    }

    RegressionComparison {
        regression_schema_version: REGRESSION_SCHEMA_VERSION.to_string(),
        baseline_manifest: baseline.manifest.clone(),
        current_manifest: current.manifest.clone(),
        cases,
        regressed_count,
        improved_count,
        added_count,
        removed_count,
    }
}

fn classify(baseline: &PredictionRecord, current: &PredictionRecord) -> RegressionClass {
    if baseline == current {
        return RegressionClass::Unchanged;
    }
    match (baseline.evidence_unavailable, current.evidence_unavailable) {
        (false, true) => return RegressionClass::NewlyUnavailable,
        (true, false) => return RegressionClass::NewlyEvaluable,
        _ => {}
    }
    let was_correct = is_correct(baseline);
    let is_now_correct = is_correct(current);
    match (was_correct, is_now_correct) {
        (true, false) => RegressionClass::Regressed,
        (false, true) => RegressionClass::Improved,
        _ => RegressionClass::ChangedNoOutcomeShift,
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use crate::baseline::CostSignal;
    use crate::manifest::MANIFEST_SCHEMA_VERSION;
    use crate::metrics::compute_metrics;
    use fornax_types::Verdict;
    use fornax_verify::decision::{RecommendationAction, RiskClass};
    use fornax_verify::fusion::UncertaintyBand;
    use uuid::Uuid;

    fn manifest() -> RunManifest {
        RunManifest {
            manifest_schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            dataset_version: "v1".into(),
            dataset_content_hash: "hash".into(),
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
        evidence_unavailable: bool,
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
            evidence_unavailable,
            ablation_removed_evidence: false,
            is_synthetic: true,
        }
    }

    fn report(predictions: Vec<PredictionRecord>) -> BaselineReport {
        BaselineReport {
            baseline_schema_version: "1".into(),
            manifest: manifest(),
            metrics: compute_metrics(&predictions),
            predictions,
            cost: CostSignal::Unmeasured {
                reason: "test".into(),
            },
        }
    }

    #[test]
    fn a_case_correct_in_baseline_and_wrong_in_current_is_regressed() {
        let baseline = report(vec![record(
            "t1",
            Verdict::Verified,
            Verdict::Verified,
            false,
        )]);
        let current = report(vec![record(
            "t1",
            Verdict::Unverified,
            Verdict::Verified,
            false,
        )]);
        let comparison = compare(&baseline, &current);
        assert_eq!(comparison.regressed_count, 1);
        assert_eq!(comparison.cases[0].class, RegressionClass::Regressed);
    }

    #[test]
    fn a_case_present_only_in_current_is_added_never_a_spurious_regression() {
        let baseline = report(vec![]);
        let current = report(vec![record(
            "t1",
            Verdict::Verified,
            Verdict::Verified,
            false,
        )]);
        let comparison = compare(&baseline, &current);
        assert_eq!(comparison.regressed_count, 0);
        assert_eq!(comparison.added_count, 1);
        assert_eq!(comparison.cases[0].class, RegressionClass::Added);
    }

    #[test]
    fn a_case_present_only_in_baseline_is_removed_never_a_spurious_regression() {
        let baseline = report(vec![record(
            "t1",
            Verdict::Verified,
            Verdict::Verified,
            false,
        )]);
        let current = report(vec![]);
        let comparison = compare(&baseline, &current);
        assert_eq!(comparison.regressed_count, 0);
        assert_eq!(comparison.removed_count, 1);
        assert_eq!(comparison.cases[0].class, RegressionClass::Removed);
    }

    #[test]
    fn reordered_datasets_still_match_by_id_not_position() {
        let baseline = report(vec![
            record("t1", Verdict::Verified, Verdict::Verified, false),
            record("t2", Verdict::Unverified, Verdict::Unverified, false),
        ]);
        // Same two cases, opposite file order -- if `compare` ever zipped by
        // position instead of matching by id, this would misreport both
        // cases as changed.
        let current = report(vec![
            record("t2", Verdict::Unverified, Verdict::Unverified, false),
            record("t1", Verdict::Verified, Verdict::Verified, false),
        ]);
        let comparison = compare(&baseline, &current);
        assert_eq!(comparison.regressed_count, 0);
        assert_eq!(comparison.improved_count, 0);
        assert_eq!(comparison.added_count, 0);
        assert_eq!(comparison.removed_count, 0);
        assert!(
            comparison.cases.iter().all(|c| matches!(
                c.class,
                RegressionClass::Unchanged | RegressionClass::ChangedNoOutcomeShift
            )),
            "every case must match its own id's counterpart, never a case at the same \
             position in the other run's (differently-ordered) file: {:?}",
            comparison.cases
        );
    }

    #[test]
    fn becoming_evidence_unavailable_is_its_own_class_never_regressed() {
        let baseline = report(vec![record(
            "t1",
            Verdict::Verified,
            Verdict::Verified,
            false,
        )]);
        let current = report(vec![record(
            "t1",
            Verdict::Unverified,
            Verdict::Verified,
            true,
        )]);
        let comparison = compare(&baseline, &current);
        assert_eq!(comparison.regressed_count, 0);
        assert_eq!(comparison.cases[0].class, RegressionClass::NewlyUnavailable);
    }
}
