//! Versioned run manifest (FORNX-95 AC: "results are reproducible from
//! frozen inputs/config"), following this repo's own
//! `release/v0.0.1-candidate-manifest.json` convention (explicit version,
//! explicit provenance) and `fornax-adapter-conformance::fixtures::FixtureMetadata`'s
//! precedent (provider/version/description/sanitized-flag shape) — adapted
//! to this domain rather than copied verbatim, since a benchmark run and a
//! provider fixture are different kinds of artifact.
//!
//! A [`RunManifest`] is stamped onto every run's output so a reader can
//! answer, without re-running anything: exactly which dataset (by content
//! hash, not just a mutable version string), which fusion policy version,
//! which decision policy version, which risk class, and which sensors (if
//! any) were disabled produced this result. Two runs with identical
//! manifests over the identical dataset file must produce byte-identical
//! [`crate::metrics::MetricsReport`]/[`crate::ablation::AblationResult`]
//! output — that equality is what "reproducible" means operationally here.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use fornax_verify::decision::{DecisionPolicy, RiskClass};
use fornax_verify::fusion::FusionPolicy;

use crate::dataset::Dataset;
use crate::harness::HarnessConfig;

/// Schema version of [`RunManifest`] itself, independent of
/// `dataset_version`/policy versions — bump when this struct's own shape
/// changes in a way that could break a consumer parsing an older manifest.
pub const MANIFEST_SCHEMA_VERSION: &str = "1";

/// A fully self-describing record of one benchmark/ablation run's identity
/// (AC 1). Carries no results itself — pair it with the
/// [`crate::metrics::MetricsReport`]/[`crate::ablation::AblationResult`] it
/// stamped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunManifest {
    pub manifest_schema_version: String,
    /// The dataset's own declared version string (author-controlled, may be
    /// reused across edits by mistake).
    pub dataset_version: String,
    /// The dataset's computed content digest — see
    /// [`crate::dataset::content_hash_of`]. Changes if and only if the
    /// dataset file's bytes change, regardless of whether `dataset_version`
    /// was bumped.
    pub dataset_content_hash: String,
    /// True if any trajectory in the dataset this run consumed carries
    /// [`crate::dataset::LabelingProvenance::SyntheticMechanismTest`] — see
    /// `crate::dataset`'s module docs for why this is load-bearing, not
    /// informational.
    pub contains_synthetic_labels: bool,
    pub fusion_policy_name: String,
    pub fusion_policy_version: u32,
    pub decision_policy_name: String,
    pub decision_policy_version: u32,
    pub risk_class: RiskClass,
    /// Sensors disabled for this specific run — empty for a baseline run,
    /// one entry for a single-sensor ablation arm.
    pub disabled_sensors: BTreeSet<String>,
    /// Judge model/prompt-version identity, if the dataset's evidence pool
    /// includes judge-derived evidence this run did not disable — read from
    /// whatever produced that evidence (see `crate::harness`'s module docs
    /// on why the judge is never called live from this crate). `None` when
    /// no judge-derived evidence is in play for this run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge_identity: Option<JudgeIdentity>,
    /// RFC3339 timestamp this manifest was stamped — passed in by the
    /// caller, never read from the clock by anything in this crate's own
    /// library code (mirrors `fornax_verify::fusion::FusionPolicy::fuse`'s
    /// "pure and sync" discipline).
    pub run_at: String,
}

/// Judge model/prompt-version identity, stamped onto a [`RunManifest`] when
/// judge-derived evidence is in play for that run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeIdentity {
    pub model: String,
    pub prompt_version: u32,
}

/// Builds a [`RunManifest`] for a run of `fusion_policy`/`decision_policy`
/// under `harness_config` over `dataset`, stamped `run_at`. Reads each
/// policy's `name()`/`policy_version()` directly from the real policy
/// instances the harness ran against, rather than hardcoding a string —
/// this cannot drift out of sync with the actual policy behavior a run
/// used.
pub fn build_manifest(
    dataset: &Dataset,
    harness_config: &HarnessConfig,
    fusion_policy: &impl FusionPolicy,
    decision_policy: &impl DecisionPolicy,
    judge_identity: Option<JudgeIdentity>,
    run_at: &str,
) -> RunManifest {
    RunManifest {
        manifest_schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        dataset_version: dataset.dataset_version.clone(),
        dataset_content_hash: dataset.content_hash.clone(),
        contains_synthetic_labels: dataset.contains_synthetic_labels(),
        fusion_policy_name: fusion_policy.name().to_string(),
        fusion_policy_version: fusion_policy.policy_version(),
        decision_policy_name: decision_policy.name().to_string(),
        decision_policy_version: decision_policy.policy_version(),
        risk_class: harness_config.risk_class,
        disabled_sensors: harness_config.disabled_sensors.clone(),
        judge_identity,
        run_at: run_at.to_string(),
    }
}

#[cfg(test)]
mod manifest_tests {
    use super::*;
    use fornax_verify::decision::DefaultRiskPolicy;
    use fornax_verify::fusion::BaselineFusionPolicy;

    fn empty_dataset() -> Dataset {
        Dataset {
            dataset_version: "0.0.0-mechanism-test".into(),
            description: "test".into(),
            trajectories: vec![],
            content_hash: "abc123".into(),
        }
    }

    #[test]
    fn manifest_reads_real_policy_identity_not_a_hardcoded_string() {
        let dataset = empty_dataset();
        let config = HarnessConfig::new(RiskClass::Balanced);
        let manifest = build_manifest(
            &dataset,
            &config,
            &BaselineFusionPolicy,
            &DefaultRiskPolicy,
            None,
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(manifest.fusion_policy_name, "deterministic_baseline_v1");
        assert_eq!(manifest.fusion_policy_version, 1);
        assert_eq!(manifest.decision_policy_name, "default_risk_policy_v1");
        assert_eq!(manifest.decision_policy_version, 1);
        assert_eq!(manifest.risk_class, RiskClass::Balanced);
        assert_eq!(manifest.dataset_content_hash, "abc123");
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let dataset = empty_dataset();
        let config = HarnessConfig::new(RiskClass::Strict).with_sensor_disabled("some_sensor_v1");
        let manifest = build_manifest(
            &dataset,
            &config,
            &BaselineFusionPolicy,
            &DefaultRiskPolicy,
            Some(JudgeIdentity {
                model: "test-model".into(),
                prompt_version: 3,
            }),
            "2026-01-02T00:00:00Z",
        );
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: RunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, parsed);
        assert!(parsed.disabled_sensors.contains("some_sensor_v1"));
        assert_eq!(parsed.judge_identity.unwrap().prompt_version, 3);
    }
}
