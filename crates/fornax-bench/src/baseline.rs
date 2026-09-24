//! Frozen baselines (FORNX-344): the artifact `regression::compare` diffs a
//! fresh run against. A [`BaselineReport`] is exactly what
//! [`crate::harness::run_harness`] + [`crate::metrics::compute_metrics`]
//! already produce, wrapped with the [`crate::manifest::RunManifest`] that
//! identifies which dataset/policy/config combination produced it -- no new
//! computation, only freezing an existing one for later comparison.

use serde::{Deserialize, Serialize};

use fornax_verify::decision::DefaultRiskPolicy;
use fornax_verify::fusion::BaselineFusionPolicy;

use crate::dataset::Dataset;
use crate::harness::{run_harness, HarnessConfig, PredictionRecord};
use crate::manifest::{build_manifest, RunManifest};
use crate::metrics::{compute_metrics, MetricsReport};

pub const BASELINE_SCHEMA_VERSION: &str = "1";

/// Whether a per-run cost figure could be attached to this baseline. This
/// crate's pipeline (`BaselineFusionPolicy`/`DefaultRiskPolicy`) is a pure,
/// synchronous, in-process computation with no token/dollar/API-call cost
/// model anywhere in it -- there is nothing today for this field to
/// honestly report beyond that absence. See FORNX-344's own scope note:
/// "cost" as a regression dimension requires an actual costed dependency
/// (a judge call, a paid API) landing on this path, which has not happened
/// yet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CostSignal {
    /// No cost metric exists for this run. `reason` names why, so a reader
    /// never mistakes an absent field for a zero-cost run.
    Unmeasured { reason: String },
}

impl Default for CostSignal {
    fn default() -> Self {
        CostSignal::Unmeasured {
            reason: "no costed dependency (judge call, paid API) is on this crate's fusion/decision path"
                .to_string(),
        }
    }
}

/// A frozen run: its identifying [`RunManifest`], every
/// [`PredictionRecord`] it produced (canonically ordered by
/// [`PredictionRecord::trajectory_id`], matching `run_harness`'s own sort),
/// the [`MetricsReport`] computed from those predictions, and this run's
/// [`CostSignal`]. Two `freeze_baseline` calls over the same dataset/config
/// with the same `run_at` produce a byte-identical `BaselineReport`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineReport {
    pub baseline_schema_version: String,
    pub manifest: RunManifest,
    pub predictions: Vec<PredictionRecord>,
    pub metrics: MetricsReport,
    pub cost: CostSignal,
}

/// Runs the real pipeline over `dataset` under `config`, freezing the
/// result as a [`BaselineReport`] stamped `run_at`. This is the only
/// producer of a [`BaselineReport`] -- `regression::compare` never
/// re-derives one from raw predictions, so a baseline file is always
/// exactly what this function produced, never hand-assembled.
pub fn freeze_baseline(dataset: &Dataset, config: &HarnessConfig, run_at: &str) -> BaselineReport {
    let predictions = run_harness(dataset, config, run_at);
    let metrics = compute_metrics(&predictions);
    let manifest = build_manifest(
        dataset,
        config,
        &BaselineFusionPolicy,
        &DefaultRiskPolicy,
        None,
        run_at,
    );
    BaselineReport {
        baseline_schema_version: BASELINE_SCHEMA_VERSION.to_string(),
        manifest,
        predictions,
        metrics,
        cost: CostSignal::default(),
    }
}

#[cfg(test)]
mod baseline_tests {
    use super::*;
    use crate::dataset::Dataset;

    fn empty_dataset() -> Dataset {
        Dataset {
            dataset_version: "v1".into(),
            description: "empty".into(),
            trajectories: Vec::new(),
            content_hash: "deadbeef".into(),
        }
    }

    #[test]
    fn freezing_the_same_input_twice_is_byte_identical() {
        let dataset = empty_dataset();
        let config = HarnessConfig::new(fornax_verify::decision::RiskClass::Balanced);
        let a = freeze_baseline(&dataset, &config, "2026-01-01T00:00:00Z");
        let b = freeze_baseline(&dataset, &config, "2026-01-01T00:00:00Z");
        assert_eq!(a, b);
    }

    #[test]
    fn cost_is_honestly_unmeasured_never_a_fabricated_zero() {
        let dataset = empty_dataset();
        let config = HarnessConfig::new(fornax_verify::decision::RiskClass::Balanced);
        let report = freeze_baseline(&dataset, &config, "2026-01-01T00:00:00Z");
        match report.cost {
            CostSignal::Unmeasured { reason } => assert!(!reason.is_empty()),
        }
    }
}
