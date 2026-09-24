//! Labeled-trajectory dataset ingestion format (FORNX-95).
//!
//! **This module defines the wire format only — it does not populate it with
//! real labeled data.** A real calibration dataset requires human-adjudicated
//! integrity outcomes, which do not exist in this repository yet (see this
//! ticket's PR body for the search that was done and came up empty). Every
//! [`LabeledTrajectory`] this module's tests construct is stamped
//! [`LabelingProvenance::SyntheticMechanismTest`] — a structural refusal
//! gate, not just a metadata note (mirrors `fornax-adapter-conformance`'s
//! `load_fixtures` refusing anything not marked `sanitized: true`). See
//! [`LabelingProvenance::is_synthetic`] and how [`crate::metrics::MetricsReport`]
//! and [`crate::ablation::AblationResult`] propagate `contains_synthetic_labels`
//! so a synthetic-only run can never be read back as a real calibration finding.
//!
//! # Wire shape
//!
//! A dataset file is one JSON document:
//!
//! ```json
//! {
//!   "dataset_version": "0.0.0-mechanism-test",
//!   "description": "...",
//!   "trajectories": [
//!     {
//!       "id": "traj-1",
//!       "claim": { /* fornax_types::Claim */ },
//!       "evidence_graph": { /* fornax_types::EvidenceGraph */ },
//!       "evidence_pool": [ /* fornax_types::Evidence, ... */ ],
//!       "adjudicated_expected_outcome": {
//!         "expected_verdict": "verified",
//!         "critical_failure": false,
//!         "notes": null
//!       },
//!       "labeling_provenance": {
//!         "kind": "synthetic_mechanism_test",
//!         "created_by": "fornax-bench test fixture",
//!         "created_at": "2026-01-01T00:00:00Z",
//!         "notes": null
//!       }
//!     }
//!   ]
//! }
//! ```
//!
//! `expected_verdict` is the repo's own invariant five-state
//! [`fornax_types::Verdict`] vocabulary — never a downstream
//! `RecommendationAction`, which is a function of `(verdict, band,
//! risk_class)` a caller supplies at run time, not something a label could
//! pin without also pinning the risk class it was adjudicated under (see
//! `crate::harness`'s module docs for why decoupling this matters).
//! `critical_failure` is the risk-class-independent judgment "this was a
//! real integrity failure that must not have been allowed to proceed" —
//! what [`crate::metrics`] actually scores recall/precision/false-positive
//! rate against.

use std::collections::BTreeSet;
use std::path::Path;

use fornax_types::{Claim, Evidence, EvidenceGraph, Verdict};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Fixed namespace for [`content_hash_of`]'s `Uuid::new_v5` derivation — an
/// arbitrary constant, not a real dataset id, the same trick
/// `fornax-verify::fusion::project_graph`'s `PROJECTION_NAMESPACE` uses to
/// get a deterministic digest without pulling in a hashing crate the
/// workspace doesn't already depend on.
const DATASET_HASH_NAMESPACE: Uuid = Uuid::from_bytes([
    0x4c, 0x9b, 0x8a, 0x2d, 0x0e, 0x1a, 0x4f, 0x6b, 0x9c, 0x71, 0x3d, 0x0e, 0x8a, 0x5b, 0x22, 0x91,
]);

/// Deterministic content digest of raw dataset bytes (before parsing) — a
/// dataset's `content_hash` changes if and only if its bytes change, making
/// [`RunManifest::dataset_content_hash`] (see `crate::manifest`) a genuine
/// reproducibility pin (AC 1), not merely a copy of the declared
/// `dataset_version` string a caller could forget to bump.
pub fn content_hash_of(bytes: &[u8]) -> String {
    Uuid::new_v5(&DATASET_HASH_NAMESPACE, bytes).to_string()
}

/// Failure modes for reading/parsing a dataset file.
#[derive(Debug, thiserror::Error)]
pub enum DatasetError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse dataset JSON: {source}")]
    Parse {
        #[source]
        source: serde_json::Error,
    },
}

/// Who/what adjudicated a [`LabeledTrajectory`]'s expected outcome, and
/// when. A hard, closed discriminator — not a free-text field a caller could
/// forget to check — so a synthetic-only dataset can never be silently
/// mistaken for real calibration ground truth. See module docs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LabelingProvenance {
    /// A real human reviewed the trajectory and determined the correct
    /// integrity outcome. Not used by anything in this crate's own tests —
    /// no such dataset exists in this repository yet (owner directive: do
    /// not fabricate one).
    HumanAdjudicated {
        labeled_by: String,
        /// RFC3339 timestamp of the adjudication.
        labeled_at: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    /// A fabricated trajectory used only to prove the harness/metrics/
    /// ablation *mechanism* works — never a real calibration finding. Every
    /// fixture this crate's own tests construct uses this variant.
    SyntheticMechanismTest {
        created_by: String,
        /// RFC3339 timestamp the fixture was authored.
        created_at: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
}

impl LabelingProvenance {
    /// True for [`Self::SyntheticMechanismTest`] — the discriminator every
    /// downstream report propagates as `contains_synthetic_labels`.
    pub fn is_synthetic(&self) -> bool {
        matches!(self, Self::SyntheticMechanismTest { .. })
    }
}

/// The adjudicated, risk-class-independent expected outcome for one
/// [`LabeledTrajectory`]. See module docs for why `expected_verdict` is a
/// [`Verdict`], never a `RecommendationAction`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdjudicatedExpectedOutcome {
    pub expected_verdict: Verdict,
    /// "This was a real integrity failure that must not have been allowed
    /// to proceed" — the adjudicator's own judgment, independent of any
    /// [`fornax_verify::decision::RiskClass`] a later run might apply.
    /// [`crate::metrics`] scores critical-failure recall/precision/false-
    /// positive-rate against this field, never against a downstream
    /// `RecommendationAction`.
    pub critical_failure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// One labeled trajectory: a claim, its evidence graph and resolvable
/// evidence pool (constructed/loaded the same shape
/// `fornax_verify::fusion::FusionInput` expects), and the adjudicated
/// expected outcome plus its provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledTrajectory {
    /// Stable id for this record, used for sorting (determinism) and for
    /// matching a trajectory across two runs (e.g. baseline vs. ablated) --
    /// distinct from `claim.id`, which is a `Uuid` regenerated per fixture.
    pub id: String,
    pub claim: Claim,
    pub evidence_graph: EvidenceGraph,
    pub evidence_pool: Vec<Evidence>,
    pub adjudicated_expected_outcome: AdjudicatedExpectedOutcome,
    pub labeling_provenance: LabelingProvenance,
}

/// Wire shape of a dataset file, deserialized directly; [`Dataset`] adds the
/// computed `content_hash` this struct has no field for.
#[derive(Debug, Deserialize)]
struct DatasetFile {
    dataset_version: String,
    description: String,
    trajectories: Vec<LabeledTrajectory>,
}

/// A loaded, versioned, provenance-tagged dataset (AC 5). `content_hash` is
/// always computed from the exact bytes loaded, never trusted from the file
/// itself — a caller cannot forge reproducibility by hand-editing a hash
/// field.
#[derive(Debug, Clone)]
pub struct Dataset {
    pub dataset_version: String,
    pub description: String,
    pub trajectories: Vec<LabeledTrajectory>,
    pub content_hash: String,
}

impl Dataset {
    /// Parses a dataset already read into memory (e.g. from a test, or a
    /// caller that already has the bytes). `content_hash` is computed over
    /// `contents` exactly as given.
    pub fn parse_str(contents: &str) -> Result<Self, DatasetError> {
        let file: DatasetFile =
            serde_json::from_str(contents).map_err(|source| DatasetError::Parse { source })?;
        Ok(Self {
            dataset_version: file.dataset_version,
            description: file.description,
            trajectories: file.trajectories,
            content_hash: content_hash_of(contents.as_bytes()),
        })
    }

    /// Reads and parses a dataset file from disk.
    pub fn load(path: &Path) -> Result<Self, DatasetError> {
        let contents = std::fs::read_to_string(path).map_err(|source| DatasetError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse_str(&contents)
    }

    /// True if any trajectory in this dataset carries
    /// [`LabelingProvenance::SyntheticMechanismTest`] — propagated onto every
    /// [`crate::metrics::MetricsReport`]/[`crate::ablation::AblationResult`]
    /// this dataset produces as `contains_synthetic_labels`, per module
    /// docs.
    pub fn contains_synthetic_labels(&self) -> bool {
        self.trajectories
            .iter()
            .any(|t| t.labeling_provenance.is_synthetic())
    }

    /// Every distinct sensor name recorded on this dataset's evidence
    /// (`Evidence::source.sensor_name`), sorted — a convenience for a caller
    /// building the ablation sweep's sensor list from the dataset itself
    /// rather than hardcoding it. Evidence with no recorded `source` (most
    /// evidence, on any real sensor pre-FORNX-157) contributes nothing.
    pub fn known_sensor_names(&self) -> BTreeSet<String> {
        self.trajectories
            .iter()
            .flat_map(|t| t.evidence_pool.iter())
            .filter_map(|e| e.source.as_ref().map(|s| s.sensor_name.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> String {
        r#"{
            "dataset_version": "0.0.0-mechanism-test",
            "description": "synthetic fixture for round-trip test",
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
        .to_string()
    }

    #[test]
    fn round_trips_a_minimal_dataset() {
        let json = sample_json();
        let dataset = Dataset::parse_str(&json).unwrap();
        assert_eq!(dataset.dataset_version, "0.0.0-mechanism-test");
        assert_eq!(dataset.trajectories.len(), 1);
        assert_eq!(dataset.trajectories[0].id, "traj-1");
        assert!(dataset.contains_synthetic_labels());
    }

    #[test]
    fn content_hash_is_deterministic_and_sensitive_to_bytes() {
        let json = sample_json();
        let a = Dataset::parse_str(&json).unwrap();
        let b = Dataset::parse_str(&json).unwrap();
        assert_eq!(a.content_hash, b.content_hash);

        let mut changed = json.clone();
        changed = changed.replace("traj-1", "traj-2");
        let c = Dataset::parse_str(&changed).unwrap();
        assert_ne!(a.content_hash, c.content_hash);
    }

    #[test]
    fn human_adjudicated_provenance_is_not_synthetic() {
        let json = sample_json().replace(
            r#""labeling_provenance": {
                        "kind": "synthetic_mechanism_test",
                        "created_by": "test",
                        "created_at": "2026-01-01T00:00:00Z"
                    }"#,
            r#""labeling_provenance": {
                        "kind": "human_adjudicated",
                        "labeled_by": "a real reviewer",
                        "labeled_at": "2026-01-01T00:00:00Z"
                    }"#,
        );
        let dataset = Dataset::parse_str(&json).unwrap();
        assert!(!dataset.contains_synthetic_labels());
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        let err = Dataset::parse_str("not json").unwrap_err();
        assert!(matches!(err, DatasetError::Parse { .. }));
    }

    /// The structural refusal gate this module's docs claim: a trajectory
    /// record with no `labeling_provenance` at all must be rejected, not
    /// silently accepted as if provenance were optional. `LabelingProvenance`
    /// carries no `#[serde(default)]`, so serde itself enforces this --
    /// asserted here so the claim is a tested behavior, not an
    /// inspection-only property.
    #[test]
    fn trajectory_missing_labeling_provenance_is_rejected() {
        let json = sample_json().replace(
            r#",
                    "labeling_provenance": {
                        "kind": "synthetic_mechanism_test",
                        "created_by": "test",
                        "created_at": "2026-01-01T00:00:00Z"
                    }"#,
            "",
        );
        let err = Dataset::parse_str(&json).unwrap_err();
        assert!(matches!(err, DatasetError::Parse { .. }));
    }

    #[test]
    fn load_with_missing_file_is_an_io_error() {
        let path =
            std::env::temp_dir().join(format!("fornax-bench-dataset-test-{}.json", Uuid::new_v4()));
        let err = Dataset::load(&path).unwrap_err();
        assert!(matches!(err, DatasetError::Io { .. }));
    }
}
