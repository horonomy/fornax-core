//! Regression slicing (FORNX-344): breaks `PredictionRecord` metrics down by
//! the only trajectory dimensions this codebase can actually observe today
//! -- which sensor(s) contributed evidence to a trajectory, and which
//! adapter/provider (if any) that evidence was collected under.
//!
//! Every other context dimension FORNX-344's own scope names --
//! `model`/`model_version`, `task_class`, `repository_class`,
//! `adapter_runtime_version` -- has no local source anywhere in this
//! codebase. No adapter announces a model release in `RuntimeCapabilities`
//! (see ADR 0018 sec 1 for the identical finding on the calibration side,
//! and ADR 0019 for the same finding on `fornax_corpus::CandidateCase`'s
//! `context: Option<CohortIdentity>`), and no task/repository classifier
//! exists. Slicing on any of those would fabricate a coverage breakdown
//! this codebase cannot actually produce -- so `SliceKey` has exactly two
//! real variants plus `Overall`, and no more.

use std::collections::BTreeSet;

use fornax_types::Provider;

use crate::dataset::LabeledTrajectory;

/// One observable slicing dimension. `Overall` always contains every
/// trajectory. Slices are independent breakdowns, not a partition -- a
/// trajectory whose evidence pool spans two sensors appears in both
/// `Sensor` slices, mirroring how an operator would pick one axis at a time
/// on a dashboard rather than a mutually-exclusive bucket.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SliceKey {
    Overall,
    Sensor(String),
    Provider(Provider),
}

impl SliceKey {
    /// Deterministic, human-readable label used both for CLI rendering and
    /// as the sort key `compute_slices` orders its output by -- `Provider`
    /// has no `Ord` impl (it is a small closed-world identity enum, not a
    /// sortable one), so slices are ordered by this label instead of by
    /// deriving `Ord` on the enum itself.
    pub fn label(&self) -> String {
        match self {
            SliceKey::Overall => "overall".to_string(),
            SliceKey::Sensor(name) => format!("sensor:{name}"),
            SliceKey::Provider(p) => format!("provider:{p:?}"),
        }
    }
}

/// One slice's membership: the key plus the trajectory ids belonging to it,
/// in the same canonical (sorted) order `run_harness` already imposes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Slice {
    pub key: SliceKey,
    pub trajectory_ids: Vec<String>,
}

/// Derive every real slice over `trajectories`. Pure; output order is
/// deterministic (sorted by [`SliceKey::label`]) regardless of input order.
pub fn compute_slices(trajectories: &[LabeledTrajectory]) -> Vec<Slice> {
    let mut overall: Vec<String> = trajectories.iter().map(|t| t.id.clone()).collect();
    overall.sort();

    let mut by_sensor: std::collections::BTreeMap<String, BTreeSet<String>> = Default::default();
    let mut by_provider: std::collections::BTreeMap<String, (Provider, BTreeSet<String>)> =
        Default::default();

    for t in trajectories {
        let mut sensors = BTreeSet::new();
        let mut providers = BTreeSet::new();
        for e in &t.evidence_pool {
            if let Some(source) = &e.source {
                sensors.insert(source.sensor_name.clone());
                if let Some(p) = source.provider {
                    providers.insert(format!("{p:?}"));
                    by_provider
                        .entry(format!("{p:?}"))
                        .or_insert_with(|| (p, BTreeSet::new()))
                        .1
                        .insert(t.id.clone());
                }
            }
        }
        for s in sensors {
            by_sensor.entry(s).or_default().insert(t.id.clone());
        }
    }

    let mut slices = vec![Slice {
        key: SliceKey::Overall,
        trajectory_ids: overall,
    }];
    for (sensor, ids) in by_sensor {
        slices.push(Slice {
            key: SliceKey::Sensor(sensor),
            trajectory_ids: ids.into_iter().collect(),
        });
    }
    for (_, (provider, ids)) in by_provider {
        slices.push(Slice {
            key: SliceKey::Provider(provider),
            trajectory_ids: ids.into_iter().collect(),
        });
    }
    slices.sort_by_key(|s| s.key.label());
    slices
}

#[cfg(test)]
mod slice_tests {
    use super::*;
    use crate::dataset::{AdjudicatedExpectedOutcome, LabelingProvenance};
    use fornax_types::sensor::{CollectionMethod, EvidenceSource, TrustClass};
    use fornax_types::{Claim, Evidence, EvidenceGraph, EvidenceKind, Verdict};
    use uuid::Uuid;

    fn trajectory(
        id: &str,
        sensor: Option<&'static str>,
        provider: Option<Provider>,
    ) -> LabeledTrajectory {
        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "t".into(),
            subject: "test_result".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        };
        let evidence_pool = match sensor {
            None => Vec::new(),
            Some(sensor_name) => vec![Evidence {
                id: Uuid::new_v4(),
                session_id: "s1".into(),
                source_event_id: claim.source_event_id,
                kind: EvidenceKind::ExitCode,
                observed_at: "2026-01-01T00:00:00Z".into(),
                payload: serde_json::json!({}),
                provenance: "test".into(),
                source: Some(EvidenceSource::now(
                    sensor_name,
                    TrustClass::HostObserved,
                    provider,
                    CollectionMethod::HookCallback,
                    None,
                )),
                extension: None,
                evidence_purged: false,
            }],
        };
        LabeledTrajectory {
            id: id.to_string(),
            claim,
            evidence_graph: EvidenceGraph::default(),
            evidence_pool,
            adjudicated_expected_outcome: AdjudicatedExpectedOutcome {
                expected_verdict: Verdict::Unverified,
                critical_failure: false,
                notes: None,
            },
            labeling_provenance: LabelingProvenance::SyntheticMechanismTest {
                created_by: "test".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                notes: None,
            },
        }
    }

    #[test]
    fn overall_slice_contains_every_trajectory_sorted() {
        let trajectories = vec![trajectory("b", None, None), trajectory("a", None, None)];
        let slices = compute_slices(&trajectories);
        let overall = slices.iter().find(|s| s.key == SliceKey::Overall).unwrap();
        assert_eq!(overall.trajectory_ids, vec!["a", "b"]);
    }

    #[test]
    fn a_trajectory_with_no_source_appears_in_no_sensor_or_provider_slice() {
        let trajectories = vec![trajectory("a", None, None)];
        let slices = compute_slices(&trajectories);
        assert_eq!(slices.len(), 1, "only Overall: {slices:?}");
    }

    #[test]
    fn sensor_and_provider_slices_are_derived_from_real_evidence_source() {
        let trajectories = vec![trajectory(
            "a",
            Some("git_probe"),
            Some(Provider::ClaudeCode),
        )];
        let slices = compute_slices(&trajectories);
        let sensor_slice = slices
            .iter()
            .find(|s| s.key == SliceKey::Sensor("git_probe".into()))
            .expect("sensor slice must exist");
        assert_eq!(sensor_slice.trajectory_ids, vec!["a"]);
        let provider_slice = slices
            .iter()
            .find(|s| s.key == SliceKey::Provider(Provider::ClaudeCode))
            .expect("provider slice must exist");
        assert_eq!(provider_slice.trajectory_ids, vec!["a"]);
    }

    #[test]
    fn output_order_is_deterministic_regardless_of_input_order() {
        let a = vec![
            trajectory("a", Some("s1"), None),
            trajectory("b", Some("s2"), None),
        ];
        let b = vec![
            trajectory("b", Some("s2"), None),
            trajectory("a", Some("s1"), None),
        ];
        assert_eq!(compute_slices(&a), compute_slices(&b));
    }
}
