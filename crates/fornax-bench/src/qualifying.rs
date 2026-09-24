//! Qualifying-benchmark gate (FORNX-348, parent epic FORNX-20 / discovery
//! thesis HVDL-15).
//!
//! A calibration revision must never be adopted on the strength of a
//! benchmark run that is not a genuine, frozen, human-adjudicated
//! measurement. This module is the explicit refusal gate: given a
//! [`crate::dataset::Dataset`] and (optionally) the content hash a caller
//! expects it to still match, decide whether a run over it may count as a
//! qualifying benchmark for calibration purposes at all — mirroring
//! `dataset.rs`'s own `contains_synthetic_labels`
//! structural-refusal-not-just-metadata discipline (see that module's docs)
//! and extending it with a second, independent disqualifier: the dataset
//! content silently changing out from under a frozen baseline.
//!
//! Pure — no I/O, no clock read. Never mutates or re-derives the dataset
//! itself.

use serde::{Deserialize, Serialize};

use crate::dataset::Dataset;

/// Every reason a benchmark run over a given dataset is disqualified from
/// counting as a real calibration signal, named explicitly rather than
/// collapsed into a single boolean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisqualificationReason {
    /// At least one trajectory in the dataset carries
    /// [`crate::dataset::LabelingProvenance::SyntheticMechanismTest`] — see
    /// `dataset.rs` module docs for why a synthetic-only label can never be
    /// laundered into a real calibration finding.
    ContainsSyntheticLabels,
    /// The dataset's live content hash disagrees with the hash a caller
    /// expected it to still match — the dataset changed since whatever
    /// baseline recorded `expected`. A calibration revision must never be
    /// (re)qualified against a dataset that silently drifted underneath it.
    DatasetContentHashMismatch { expected: String, actual: String },
}

/// Output of [`qualify`] — whether this dataset qualifies as a calibration
/// benchmark, and every reason it doesn't when it does not. `qualifies` is
/// true iff `disqualification_reasons` is empty; a caller should check
/// `disqualification_reasons`, not just `qualifies`, when it needs to say
/// *why*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualifyingBenchmark {
    pub qualifies: bool,
    pub disqualification_reasons: Vec<DisqualificationReason>,
}

/// Decide whether `dataset` qualifies as a calibration benchmark. Pure.
///
/// `expected_content_hash` is `None` when a caller has no prior frozen hash
/// to compare against (e.g. the very first time this dataset is used) — in
/// that case only the synthetic-labels check applies. When `Some`, a
/// mismatch always disqualifies, independent of the synthetic-labels
/// result — both reasons can fire together.
pub fn qualify(dataset: &Dataset, expected_content_hash: Option<&str>) -> QualifyingBenchmark {
    let mut reasons = Vec::new();

    if dataset.contains_synthetic_labels() {
        reasons.push(DisqualificationReason::ContainsSyntheticLabels);
    }

    if let Some(expected) = expected_content_hash {
        if expected != dataset.content_hash {
            reasons.push(DisqualificationReason::DatasetContentHashMismatch {
                expected: expected.to_string(),
                actual: dataset.content_hash.clone(),
            });
        }
    }

    QualifyingBenchmark {
        qualifies: reasons.is_empty(),
        disqualification_reasons: reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_dataset_json() -> &'static str {
        r#"{
            "dataset_version": "0.0.0-mechanism-test",
            "description": "synthetic fixture for qualifying-gate tests",
            "trajectories": [
                {
                    "id": "traj-1",
                    "claim": {
                        "id": "11111111-1111-1111-1111-111111111111",
                        "session_id": "s1",
                        "source_event_id": "22222222-2222-2222-2222-222222222222",
                        "text": "the command exited successfully",
                        "subject": "command_succeeded",
                        "claimed_at": "2026-01-01T00:00:00Z"
                    },
                    "evidence_graph": { "links": [], "missing": [] },
                    "evidence_pool": [],
                    "adjudicated_expected_outcome": {
                        "expected_verdict": "unverified",
                        "critical_failure": false,
                        "notes": null
                    },
                    "labeling_provenance": {
                        "kind": "synthetic_mechanism_test",
                        "created_by": "test",
                        "created_at": "2026-01-01T00:00:00Z"
                    }
                }
            ]
        }"#
    }

    #[test]
    fn synthetic_labels_disqualify() {
        let dataset = Dataset::parse_str(synthetic_dataset_json()).expect("parse");
        let result = qualify(&dataset, None);
        assert!(!result.qualifies);
        assert_eq!(
            result.disqualification_reasons,
            vec![DisqualificationReason::ContainsSyntheticLabels]
        );
    }

    #[test]
    fn matching_content_hash_does_not_disqualify_on_its_own() {
        let dataset = Dataset::parse_str(synthetic_dataset_json()).expect("parse");
        let hash = dataset.content_hash.clone();
        let result = qualify(&dataset, Some(&hash));
        // Still disqualified for synthetic labels -- this only asserts the
        // hash-matching arm itself contributes nothing extra.
        assert_eq!(
            result.disqualification_reasons,
            vec![DisqualificationReason::ContainsSyntheticLabels]
        );
    }

    #[test]
    fn content_hash_mismatch_disqualifies() {
        let dataset = Dataset::parse_str(synthetic_dataset_json()).expect("parse");
        let result = qualify(&dataset, Some("sha256:not-the-real-hash"));
        assert!(result.disqualification_reasons.contains(
            &DisqualificationReason::DatasetContentHashMismatch {
                expected: "sha256:not-the-real-hash".to_string(),
                actual: dataset.content_hash.clone(),
            }
        ));
    }

    #[test]
    fn no_expected_hash_supplied_skips_that_check_entirely() {
        let dataset = Dataset::parse_str(synthetic_dataset_json()).expect("parse");
        let result = qualify(&dataset, None);
        assert!(result
            .disqualification_reasons
            .iter()
            .all(|r| !matches!(r, DisqualificationReason::DatasetContentHashMismatch { .. })));
    }
}
