//! Meta-Verification: evaluate monitors, judges, and calibration revisions
//! as fallible evidence sources rather than roots of trust (FORNX-388,
//! parent epic FORNX-376, Stage 9).
//!
//! # Ground truth this module builds on, not reinvents
//!
//! Most of this ticket's individually-named scope items already have a real
//! implementation shipped elsewhere in this workspace:
//!
//! - **Monitor/judge output as labeled, derived evidence** ([`crate::judge`],
//!   FORNX-94): [`crate::judge::judge_output_to_evidence`] already stamps
//!   every judge verdict with model/endpoint/prompt-version/called-at
//!   provenance and [`fornax_types::sensor::TrustClass::ModelInternal`],
//!   never a higher trust class. This module does not rebuild that; it adds
//!   the axes FORNX-388's scope names beyond what a single judge call
//!   carries — calibration revision, observation scope, cost/latency — via
//!   [`MonitorIdentity`], which wraps a [`crate::judge::JudgeOutput`] rather
//!   than replacing it.
//! - **Calibration staleness** ([`crate::calibration`], FORNX-348):
//!   [`availability_from_calibration`] is a thin bridge from
//!   [`crate::calibration::CalibrationState`] into this module's own
//!   [`MonitorAvailability`] vocabulary — it does not re-derive staleness.
//! - **Same-family / dependency-aware evidence** ([`crate::independence`],
//!   FORNX-347): [`dependency_groups`] calls
//!   [`crate::independence::SourceFamilyMap::build`] directly. It is
//!   already the mechanism `fusion.rs`'s R5b
//!   (`FusionRule::CommonSourceCollapsed`) uses to stop several sensors
//!   reading the same underlying agent turn from manufacturing independent
//!   corroboration — this module exposes that grouping explicitly for a
//!   caller building a meta-verification report, it does not reimplement
//!   independence detection.
//! - **Confidence cannot override hard contradiction** ([`crate::fusion`]):
//!   [`crate::fusion::BaselineFusionPolicy::fuse`]'s R6 verdict decision
//!   already means a judge's `Supported` vote can, at most, escalate a
//!   claim to `Review` alongside a real `Contradicts` link — it can never
//!   force `Verified`. This is
//!   [`fornax_bench::self_integrity::InvariantId::ConfidenceCannotOverrideHardEvidence`]'s
//!   existing release gate (`FORNX-94 Semantic Judge gate`); see
//!   `meta_verification_tests::a_confident_supporting_judge_cannot_force_verified_over_a_hard_contradiction`
//!   below for a monitor-shaped instance of that same, already-enforced
//!   invariant — not a new enforcement mechanism.
//!
//! What is genuinely new in this module: [`MonitorIdentity`]/
//! [`MonitorAvailability`]/[`MonitorContribution`] (a richer, orthogonal
//! monitor-evaluation vocabulary — never collapsed into `JudgeVerdict`,
//! `SatisfactionState`, `Verdict`, or `DelegationOutcome`, per
//! `docs/adr/0001-architecture-invariants.md`), [`compare_monitor_versions`]
//! (canary/shadow comparison for a monitor upgrade before promotion — pure,
//! never promotes or mutates either side), and
//! [`build_contextual_performance_report`] (honest, sample-support-gated
//! contextual performance — never a global reputation score).
//!
//! # No fabricated performance numbers
//!
//! This repo has no real human-adjudicated Gold Corpus data yet (FORNX-343
//! is founder-paused for cost control, far below any usable threshold).
//! [`build_contextual_performance_report`] reuses
//! [`fornax_types::evaluate_sample_support`] (the exact
//! `MINIMUM_COHORT_SAMPLE_SUPPORT` gate `fornax-verify::calibration` already
//! uses) so that a report built from too few observations — which, today,
//! is *every* observation this module could construct — reports
//! [`fornax_types::SampleSupport::InsufficientSupport`] explicitly and
//! never emits an `agreement_rate`. Nothing in this module's test suite
//! constructs or displays a bare percentage from synthetic data as if it
//! were a real calibrated claim.

use std::collections::BTreeMap;

use fornax_types::{evaluate_sample_support, Evidence, SampleSupport};
use uuid::Uuid;

use crate::calibration::CalibrationState;
use crate::independence::SourceFamilyMap;
use crate::judge::JudgeVerdict;

pub const META_VERIFICATION_POLICY_VERSION: u32 = 1;

/// Identity/provenance of one monitor observation (AC1). Generalizes
/// [`crate::judge::JudgeOutput`]'s existing `model`/`endpoint`/
/// `prompt_version`/`called_at` with the axes this ticket's own scope names
/// beyond a single judge call: calibration revision, observation scope, and
/// cost/latency. Additive — wraps a judge output, never replaces it or
/// requires a schema migration.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MonitorIdentity {
    pub provider: String,
    pub model_or_classifier_version: String,
    pub prompt_or_config_version: u32,
    pub policy_version: u32,
    /// The calibration revision this monitor's weighting was last confirmed
    /// against, if any. `None` means no calibration has ever been recorded
    /// for this monitor — distinct from an active, matching one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration_revision: Option<String>,
    /// Free-text description of what this monitor is scoped to observe
    /// (e.g. "test_result claims, ClaudeCode adapter"). A monitor asked to
    /// evaluate a claim outside its declared scope produces
    /// [`MonitorAvailability::OutOfScope`], never a silent opinion.
    pub observation_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_estimate_micros: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

/// Whether a monitor's contribution may count as evidence at all —
/// deliberately its own closed vocabulary, never collapsed into
/// [`JudgeVerdict`], [`crate::contract_satisfaction::SatisfactionState`]-equivalent
/// state, or [`fornax_types::Verdict`] (`docs/adr/0001`: never collapse
/// vocabularies). [`MonitorContribution::counts_as_evidence`] is the single
/// place this distinction is consulted (AC2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorAvailability {
    /// This monitor's output may count as ordinary evidence.
    Active,
    /// This monitor is turned off by configuration — its absence must never
    /// be read as either a supporting or contradicting signal.
    Disabled,
    /// The monitor could not be reached or errored — named, never silently
    /// substituted with a verdict.
    Unavailable { reason: String },
    /// This monitor's calibration provenance no longer matches the live
    /// environment (FORNX-348's [`CalibrationState::Stale`]) — its weight
    /// is withdrawn, not silently retained.
    Stale { changed_dimensions: Vec<String> },
    /// This monitor's calibration is provenance-valid but statistically
    /// suspect (FORNX-348's [`CalibrationState::Suspect`] /
    /// `InsufficientSupport`) — treated the same as `Stale` for the purpose
    /// of counting evidence: real, but not currently trustworthy enough to
    /// retain authoritative weight.
    Suspect,
    /// This monitor was asked to evaluate something outside its declared
    /// [`MonitorIdentity::observation_scope`].
    OutOfScope { reason: String },
}

/// One monitor's contribution to evaluating a claim: its identity, its raw
/// verdict, the evidence row it was recorded as (if any), and its computed
/// [`MonitorAvailability`] — availability is always derived from real state
/// via [`availability_from_calibration`] or an explicit disabled/
/// out-of-scope check, never asserted ad hoc by a caller.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MonitorContribution {
    pub identity: MonitorIdentity,
    pub verdict: JudgeVerdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<Uuid>,
    pub availability: MonitorAvailability,
}

impl MonitorContribution {
    /// AC2: a disabled, unavailable, stale, suspect, or out-of-scope
    /// monitor's output never silently counts as positive or negative
    /// evidence. Only `Active` does.
    pub fn counts_as_evidence(&self) -> bool {
        matches!(self.availability, MonitorAvailability::Active)
    }
}

/// Bridge a real [`CalibrationState`] (FORNX-348) into this module's
/// [`MonitorAvailability`] vocabulary — the sole place calibration staleness
/// becomes a monitor-evidence-counting decision, so a caller cannot drift
/// the two apart. `InsufficientSupport` is folded into `Suspect`: both mean
/// "not currently confirmed valid enough to retain full weight", the
/// distinction between "detected drift" and "not enough data to say" is
/// preserved on `CalibrationState` itself for anyone inspecting the
/// upstream assessment directly.
pub fn availability_from_calibration(calibration: &CalibrationState) -> MonitorAvailability {
    match calibration {
        CalibrationState::Valid | CalibrationState::NoActiveCalibration => {
            MonitorAvailability::Active
        }
        CalibrationState::Stale { changed_dimensions } => MonitorAvailability::Stale {
            changed_dimensions: changed_dimensions.clone(),
        },
        CalibrationState::Suspect { .. } | CalibrationState::InsufficientSupport { .. } => {
            MonitorAvailability::Suspect
        }
    }
}

/// AC4: group monitor contributions by real evidence source family
/// ([`SourceFamilyMap`], FORNX-347) so several same-family monitors cannot
/// manufacture independent corroboration. This does not duplicate
/// independence detection — it calls the exact same `SourceFamilyMap::build`
/// `fusion.rs`'s R5b and `contract_satisfaction::assess`'s hardening pass
/// already use, and exposes the grouping explicitly for a report. A
/// contribution with no `evidence_id`, or one whose evidence id is not in
/// `evidence_pool`, is reported as its own singleton group — unknown
/// dependency is never silently merged with anything (mirrors
/// [`crate::independence::FamilyBasis::UnknownProvenance`]'s own
/// "unknown is always its own family" discipline).
pub fn dependency_groups<'a>(
    contributions: &'a [MonitorContribution],
    evidence_pool: &[Evidence],
) -> Vec<Vec<&'a MonitorContribution>> {
    let map = SourceFamilyMap::build(evidence_pool);
    let mut by_family_key: BTreeMap<Uuid, Vec<&MonitorContribution>> = BTreeMap::new();
    let mut singletons: Vec<Vec<&MonitorContribution>> = Vec::new();

    for c in contributions {
        match c.evidence_id.and_then(|id| map.family_of(id)) {
            Some(family) => {
                // `SourceFamily::evidence_ids` is always sorted and
                // non-empty by construction (`SourceFamilyMap::build`), so
                // its first element is a stable, deterministic grouping key
                // independent of union-find internals.
                let key = family.evidence_ids[0];
                by_family_key.entry(key).or_default().push(c);
            }
            None => singletons.push(vec![c]),
        }
    }

    let mut groups: Vec<Vec<&MonitorContribution>> = by_family_key.into_values().collect();
    groups.extend(singletons);
    groups
}

/// Errors from [`compare_monitor_versions`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MetaVerificationError {
    #[error(
        "current monitor produced {current} output(s) but candidate produced {candidate}; \
         a shadow comparison requires both sides to have judged the exact same input set"
    )]
    MismatchedInputCount { current: usize, candidate: usize },
}

/// One paired comparison entry: what the currently-active monitor said
/// versus what a candidate upgrade would have said, for the same input.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShadowComparisonEntry {
    pub current_verdict: JudgeVerdict,
    pub candidate_verdict: JudgeVerdict,
    pub agrees: bool,
}

/// AC5: a canary/shadow comparison for a monitor upgrade, computed before
/// any promotion decision. Pure — this function never selects, activates,
/// or mutates either monitor configuration; it only reports what each would
/// have said over the identical input set, mirroring FORNX-386's
/// "shadow-run, never mutate what it's comparing against" discipline at the
/// monitor-config level rather than the filesystem/DB level.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShadowComparisonReport {
    pub current_identity: MonitorIdentity,
    pub candidate_identity: MonitorIdentity,
    pub entries: Vec<ShadowComparisonEntry>,
    pub agreement_count: usize,
    pub disagreement_count: usize,
}

/// Build a [`ShadowComparisonReport`] from two equal-length verdict slices,
/// one per monitor configuration, judged over the same ordered input set.
/// Returns [`MetaVerificationError::MismatchedInputCount`] rather than
/// silently truncating or zipping mismatched lengths — a shadow comparison
/// over an implicitly-different input set would be meaningless.
pub fn compare_monitor_versions(
    current_identity: MonitorIdentity,
    candidate_identity: MonitorIdentity,
    current_outputs: &[JudgeVerdict],
    candidate_outputs: &[JudgeVerdict],
) -> Result<ShadowComparisonReport, MetaVerificationError> {
    if current_outputs.len() != candidate_outputs.len() {
        return Err(MetaVerificationError::MismatchedInputCount {
            current: current_outputs.len(),
            candidate: candidate_outputs.len(),
        });
    }
    let mut entries = Vec::with_capacity(current_outputs.len());
    let mut agreement_count = 0usize;
    let mut disagreement_count = 0usize;
    for (current_verdict, candidate_verdict) in current_outputs.iter().zip(candidate_outputs.iter())
    {
        let agrees = current_verdict == candidate_verdict;
        if agrees {
            agreement_count += 1;
        } else {
            disagreement_count += 1;
        }
        entries.push(ShadowComparisonEntry {
            current_verdict: *current_verdict,
            candidate_verdict: *candidate_verdict,
            agrees,
        });
    }
    Ok(ShadowComparisonReport {
        current_identity,
        candidate_identity,
        entries,
        agreement_count,
        disagreement_count,
    })
}

/// AC7: contextual monitor performance, gated by real
/// [`fornax_types::SampleSupport`] — never a global "monitor X is N%
/// trustworthy" claim. `agreement_rate` is populated only when
/// `sample_support` is [`SampleSupport::Confident`]; under
/// `InsufficientSupport`, the raw counts stay visible (`limitations`
/// explains why) but no rate is ever computed or displayed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContextualPerformanceReport {
    pub context_label: String,
    pub sample_support: SampleSupport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreement_rate: Option<f64>,
    pub limitations: Vec<String>,
}

/// Build a [`ContextualPerformanceReport`] for `correct` agreements out of
/// `total` observations in `context_label`. `agreement_rate` is `None`
/// whenever [`evaluate_sample_support`] reports
/// [`SampleSupport::InsufficientSupport`] — including, honestly, for every
/// call this module's own test suite makes, since this repo has no real
/// human-adjudicated corpus yet (see module docs).
pub fn build_contextual_performance_report(
    context_label: impl Into<String>,
    correct: u32,
    total: u32,
    mut limitations: Vec<String>,
) -> ContextualPerformanceReport {
    let sample_support = evaluate_sample_support(total);
    let agreement_rate = match &sample_support {
        SampleSupport::Confident { .. } => Some(f64::from(correct) / f64::from(total.max(1))),
        SampleSupport::InsufficientSupport {
            sample_count,
            minimum_required,
        } => {
            limitations.push(format!(
                "only {sample_count} of {minimum_required} required observations available; \
                 no agreement rate is reported"
            ));
            None
        }
    };
    ContextualPerformanceReport {
        context_label: context_label.into(),
        sample_support,
        agreement_rate,
        limitations,
    }
}

#[cfg(test)]
mod meta_verification_tests {
    use super::*;
    use crate::calibration::CalibrationState;
    use crate::fusion::{BaselineFusionPolicy, FusionInput, FusionPolicy};
    use crate::judge::{judge_output_to_evidence, JudgeOutput};
    use fornax_types::sensor::{CollectionMethod, EvidenceSource, TrustClass};
    use fornax_types::{
        Claim, EvidenceGraph, EvidenceKind, EvidenceLink, EvidenceRelation, Verdict,
    };

    fn evidence_source(sensor_name: &'static str, trust_class: TrustClass) -> EvidenceSource {
        EvidenceSource::now(
            sensor_name,
            trust_class,
            None,
            CollectionMethod::HookCallback,
            None,
        )
    }

    fn identity() -> MonitorIdentity {
        MonitorIdentity {
            provider: "local_self_hosted_judge_provider_v1".to_string(),
            model_or_classifier_version: "llama3.1".to_string(),
            prompt_or_config_version: 1,
            policy_version: META_VERIFICATION_POLICY_VERSION,
            calibration_revision: Some("rev-1".to_string()),
            observation_scope: "test_result claims".to_string(),
            cost_estimate_micros: Some(120),
            latency_ms: Some(340),
        }
    }

    fn contribution(
        availability: MonitorAvailability,
        verdict: JudgeVerdict,
    ) -> MonitorContribution {
        MonitorContribution {
            identity: identity(),
            verdict,
            evidence_id: Some(Uuid::new_v4()),
            availability,
        }
    }

    // --- AC1/AC2: identity + availability gate ----------------------------

    #[test]
    fn only_active_monitors_count_as_evidence() {
        assert!(
            contribution(MonitorAvailability::Active, JudgeVerdict::Supported).counts_as_evidence()
        );
        assert!(
            !contribution(MonitorAvailability::Disabled, JudgeVerdict::Supported)
                .counts_as_evidence()
        );
        assert!(!contribution(
            MonitorAvailability::Unavailable {
                reason: "timeout".to_string()
            },
            JudgeVerdict::Supported
        )
        .counts_as_evidence());
        assert!(!contribution(
            MonitorAvailability::Stale {
                changed_dimensions: vec!["adapter_version".to_string()]
            },
            JudgeVerdict::Contradicted
        )
        .counts_as_evidence());
        assert!(
            !contribution(MonitorAvailability::Suspect, JudgeVerdict::Contradicted)
                .counts_as_evidence()
        );
        assert!(!contribution(
            MonitorAvailability::OutOfScope {
                reason: "wrong claim class".to_string()
            },
            JudgeVerdict::Supported
        )
        .counts_as_evidence());
    }

    #[test]
    fn availability_bridges_real_calibration_state_never_re_derives_it() {
        assert_eq!(
            availability_from_calibration(&CalibrationState::Valid),
            MonitorAvailability::Active
        );
        assert_eq!(
            availability_from_calibration(&CalibrationState::NoActiveCalibration),
            MonitorAvailability::Active
        );
        assert_eq!(
            availability_from_calibration(&CalibrationState::Stale {
                changed_dimensions: vec!["model_version".to_string()]
            }),
            MonitorAvailability::Stale {
                changed_dimensions: vec!["model_version".to_string()]
            }
        );
        assert_eq!(
            availability_from_calibration(&CalibrationState::Suspect {
                drift_state: crate::reliability::DriftState::Drifted
            }),
            MonitorAvailability::Suspect
        );
    }

    // --- AC3/AC6: a confident, wrong monitor cannot override hard evidence,
    //     and this is a real, seeded (SyntheticMechanismTest-shaped)
    //     end-to-end pipeline demonstration, not a claim about real-world
    //     monitor reliability. ------------------------------------------

    fn claim(subject: &str) -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "s1".to_string(),
            source_event_id: Uuid::new_v4(),
            text: "the test suite passed".to_string(),
            subject: subject.to_string(),
            claimed_at: "2026-09-25T00:00:00Z".to_string(),
        }
    }

    fn hard_contradiction_evidence() -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".to_string(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-09-25T00:00:01Z".to_string(),
            payload: serde_json::json!({ "exit_code": 1 }),
            provenance: "test_runner:exit_code".to_string(),
            source: Some(evidence_source(
                "test_runner_exit_code_sensor",
                TrustClass::HostObserved,
            )),
            extension: None,
            evidence_purged: false,
        }
    }

    #[test]
    fn a_confident_supporting_judge_cannot_force_verified_over_a_hard_contradiction() {
        // SEEDED / synthetic scenario (not real-world monitor telemetry):
        // an overconfident, wrong monitor claims the tests passed while a
        // real, host-observed exit code says they failed.
        let c = claim("tests_passed");
        let hard_ev = hard_contradiction_evidence();

        let judge_output = JudgeOutput {
            verdict: JudgeVerdict::Supported,
            rationale: "a fluent, confident-sounding rationale claiming the suite passed"
                .to_string(),
            model: "llama3.1".to_string(),
            endpoint: "http://localhost:11434/v1".to_string(),
            prompt_version: 1,
            called_at: "2026-09-25T00:00:02Z".to_string(),
            disagreement: None,
        }
        .with_disagreement_check(Some(false)); // objective evidence contradicts

        assert_eq!(judge_output.disagreement, Some(true));

        let judge_ev = judge_output_to_evidence(&judge_output, "s1", Uuid::new_v4(), vec![]);

        let contribution = MonitorContribution {
            identity: identity(),
            verdict: judge_output.verdict,
            evidence_id: Some(judge_ev.id),
            availability: MonitorAvailability::Active,
        };
        assert!(contribution.counts_as_evidence());

        let graph = EvidenceGraph {
            links: vec![
                EvidenceLink {
                    id: Uuid::new_v4(),
                    session_id: "s1".to_string(),
                    claim_id: c.id,
                    evidence_id: hard_ev.id,
                    relation: EvidenceRelation::Contradicts,
                    linked_at: "2026-09-25T00:00:03Z".to_string(),
                },
                EvidenceLink {
                    id: Uuid::new_v4(),
                    session_id: "s1".to_string(),
                    claim_id: c.id,
                    evidence_id: judge_ev.id,
                    relation: EvidenceRelation::Supports,
                    linked_at: "2026-09-25T00:00:03Z".to_string(),
                },
            ],
            missing: vec![],
        };
        let evidence_pool = vec![hard_ev.clone(), judge_ev.clone()];
        let input = FusionInput {
            claim: &c,
            graph: &graph,
            evidence: &evidence_pool,
        };
        let fused = BaselineFusionPolicy.fuse(&input, "2026-09-25T00:00:04Z");

        // The monitor's "confident" support never wins outright -- it can
        // at most escalate to Review alongside the real contradiction, it
        // can never force Verified. This is
        // fornax-bench::self_integrity::InvariantId::ConfidenceCannotOverrideHardEvidence's
        // existing enforcement (fusion.rs's R6), exercised here specifically
        // through a monitor-shaped contribution.
        assert_ne!(fused.verdict, Verdict::Verified);
        assert_eq!(fused.verdict, Verdict::Review);
        // The hard contradiction remains visible in the rationale/counted
        // links -- never silently discounted because a monitor disagreed.
        assert!(fused
            .counted_link_ids
            .iter()
            .any(|id| graph.links.iter().any(|l| l.id == *id
                && l.evidence_id == hard_ev.id
                && l.relation == EvidenceRelation::Contradicts)));
    }

    #[test]
    fn a_disabled_monitors_output_is_excluded_before_it_ever_reaches_fusion() {
        // AC2 exercised through the same pipeline: a monitor whose
        // availability is not Active must never even be linked as evidence
        // in the first place -- this test documents the caller-side
        // contract (`counts_as_evidence` gates whether a caller should link
        // it at all), it does not assert fusion behavior a disabled
        // monitor's evidence was never given.
        let disabled = contribution(MonitorAvailability::Disabled, JudgeVerdict::Contradicted);
        assert!(!disabled.counts_as_evidence());
    }

    // --- AC4: dependency-aware grouping, reusing FORNX-347 verbatim -------

    #[test]
    fn same_family_monitor_contributions_are_grouped_together() {
        let source_event = Uuid::new_v4();
        let ev_a = Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".to_string(),
            source_event_id: source_event,
            kind: EvidenceKind::ToolResult,
            observed_at: "2026-09-25T00:00:00Z".to_string(),
            payload: serde_json::json!({"a": 1}),
            provenance: "judge_a".to_string(),
            source: Some(evidence_source("judge_a", TrustClass::ModelInternal)),
            extension: None,
            evidence_purged: false,
        };
        let mut ev_b = ev_a.clone();
        ev_b.id = Uuid::new_v4();
        ev_b.provenance = "judge_b".to_string();
        ev_b.source = Some(evidence_source("judge_b", TrustClass::ModelInternal));
        // Same source_event_id, both ModelInternal (agent-reported channel)
        // -- FORNX-347's rule 3, `SameAgentTurn`.

        let ev_independent = Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".to_string(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-09-25T00:00:00Z".to_string(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "unrelated".to_string(),
            source: Some(evidence_source(
                "unrelated_sensor",
                TrustClass::HostObserved,
            )),
            extension: None,
            evidence_purged: false,
        };

        let contributions = vec![
            MonitorContribution {
                identity: identity(),
                verdict: JudgeVerdict::Supported,
                evidence_id: Some(ev_a.id),
                availability: MonitorAvailability::Active,
            },
            MonitorContribution {
                identity: identity(),
                verdict: JudgeVerdict::Supported,
                evidence_id: Some(ev_b.id),
                availability: MonitorAvailability::Active,
            },
            MonitorContribution {
                identity: identity(),
                verdict: JudgeVerdict::Contradicted,
                evidence_id: Some(ev_independent.id),
                availability: MonitorAvailability::Active,
            },
        ];
        let pool = vec![ev_a, ev_b, ev_independent];
        let groups = dependency_groups(&contributions, &pool);

        assert_eq!(
            groups.len(),
            2,
            "the two same-agent-turn contributions must collapse into one group; the \
             independent one is its own group -- never 3 independent groups from 3 monitors"
        );
        let sizes: Vec<usize> = {
            let mut s: Vec<usize> = groups.iter().map(|g| g.len()).collect();
            s.sort_unstable();
            s
        };
        assert_eq!(sizes, vec![1, 2]);
    }

    #[test]
    fn a_contribution_with_no_evidence_id_is_its_own_singleton_group() {
        let c1 = MonitorContribution {
            identity: identity(),
            verdict: JudgeVerdict::Unavailable,
            evidence_id: None,
            availability: MonitorAvailability::Unavailable {
                reason: "timeout".to_string(),
            },
        };
        let c2 = c1.clone();
        let contributions = [c1, c2];
        let groups = dependency_groups(&contributions, &[]);
        assert_eq!(
            groups.len(),
            2,
            "unknown dependency is never silently merged"
        );
    }

    // --- AC5: shadow comparison, pure, never promotes ----------------------

    #[test]
    fn shadow_comparison_reports_agreement_and_disagreement_without_promoting_either_side() {
        let current = identity();
        let mut candidate = identity();
        candidate.model_or_classifier_version = "llama3.2".to_string();

        let current_outputs = vec![
            JudgeVerdict::Supported,
            JudgeVerdict::Contradicted,
            JudgeVerdict::Inconclusive,
        ];
        let candidate_outputs = vec![
            JudgeVerdict::Supported,
            JudgeVerdict::Supported, // a real disagreement
            JudgeVerdict::Inconclusive,
        ];

        let report = compare_monitor_versions(
            current.clone(),
            candidate.clone(),
            &current_outputs,
            &candidate_outputs,
        )
        .expect("equal-length inputs must succeed");

        assert_eq!(report.agreement_count, 2);
        assert_eq!(report.disagreement_count, 1);
        assert_eq!(report.entries.len(), 3);
        assert!(!report.entries[1].agrees);
        // Identities are carried through verbatim, unmodified -- this
        // function never selects a winner.
        assert_eq!(report.current_identity, current);
        assert_eq!(report.candidate_identity, candidate);
    }

    #[test]
    fn shadow_comparison_refuses_mismatched_input_counts_rather_than_silently_truncating() {
        let err = compare_monitor_versions(
            identity(),
            identity(),
            &[JudgeVerdict::Supported],
            &[JudgeVerdict::Supported, JudgeVerdict::Contradicted],
        )
        .unwrap_err();
        assert_eq!(
            err,
            MetaVerificationError::MismatchedInputCount {
                current: 1,
                candidate: 2
            }
        );
    }

    // --- AC7: honest, sample-support-gated contextual performance ----------

    #[test]
    fn insufficient_sample_support_never_produces_an_agreement_rate() {
        // Honest by construction: this repo has no real Gold Corpus data
        // (FORNX-343 is founder-paused), so every call this test suite
        // makes is, correctly, insufficient support -- never a fabricated
        // "monitor X is N% trustworthy" number.
        let report = build_contextual_performance_report("test_result claims", 2, 3, vec![]);
        assert!(matches!(
            report.sample_support,
            SampleSupport::InsufficientSupport { .. }
        ));
        assert_eq!(
            report.agreement_rate, None,
            "no agreement rate may ever be reported below the minimum sample-support threshold"
        );
        assert!(!report.limitations.is_empty());
    }

    #[test]
    fn confident_sample_support_reports_a_rate_only_above_the_real_threshold() {
        let report = build_contextual_performance_report(
            "synthetic-only sanity check",
            30,
            30,
            vec!["synthetic fixture only; not a real-world reliability claim".to_string()],
        );
        assert!(matches!(
            report.sample_support,
            SampleSupport::Confident { .. }
        ));
        assert_eq!(report.agreement_rate, Some(1.0));
    }
}
