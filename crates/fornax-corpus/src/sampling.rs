//! Active sampling: rank mined candidate cases for human review by real,
//! named signals (FORNX-349), never a fabricated "information gain" number.
//!
//! # Reuse, not duplication
//!
//! `fornax_verify::voi` already ranks *evidence-acquisition probes within
//! one claim*. This module ranks *cases against each other* for review
//! queue priority -- a different axis, additive to FORNX-345, not a
//! competing scoring system. It reuses [`fornax_verify::voi::derive_gaps`]/
//! [`fornax_verify::voi::EvidenceGap`] to find real uncertainty/conflict
//! signals rather than re-deriving them, and deliberately does **not**
//! reuse `voi::plan`/`VoiPolicy`/`UtilityEstimate`/`AcquisitionCandidate` --
//! `ProbeKind::HumanReview` is scored last in that mechanism by design (it
//! answers "is a human probe worth running for this claim", not "which
//! case most needs a human's attention right now").
//!
//! # What is and is not observable today
//!
//! Four of this ticket's own named sampling criteria have no real source
//! anywhere in this workspace and are deliberately **not** stubbed:
//!
//! - **novel context** -- `CandidateCase::context` is `None` on every live
//!   path (no local source for `model_family`/`task_class`/`repository_class`,
//!   see `docs/adr/0013-integrity-corpus-factory.md`).
//! - **suspected drift** -- no `ReliabilityObservation` writer exists
//!   anywhere; `CalibrationState::Suspect` is unreachable on live traffic
//!   (`docs/adr/0018-calibration-validity-lifecycle.md`).
//! - **model/judge disagreement** -- `/api/judge` output is never
//!   persisted or linked back to a claim (`docs/adr/0017-evidence-source-independence.md`
//!   gap list).
//! - **high-impact false-positive/false-negative** -- requires ground
//!   truth to know a finding was actually wrong; circular while zero gold
//!   labels exist anywhere in this repository.
//!
//! [`SamplingSignal`] therefore only has variants with a real, checkable
//! source today. Adding one of the four above is a real future ticket, not
//! a gap this module papers over.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use fornax_verify::voi::{EvidenceGap, EvidenceGapKind};

use crate::candidate::CandidateCase;
use crate::feedback::ReviewFeedback;
use crate::mining::MiningStrategy;

pub const SAMPLING_POLICY_VERSION: u32 = 1;

/// Every real, named reason a case is worth prioritizing for human review.
/// See module docs for the four criteria deliberately excluded as
/// unobservable today.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SamplingSignal {
    /// `FusedFinding::unresolved_conflict` (`EvidenceGapKind::UnresolvedConflict`).
    UnresolvedConflict,
    /// `MiningStrategy::SensorDisagreement`.
    CrossSensorDisagreement,
    /// `MiningStrategy::HighUncertainty`, or fusion discounted every vote
    /// (`EvidenceGapKind::AllVotesDiscounted`).
    HighUncertainty,
    /// `EvidenceGapKind::IndependenceUnverified` or `SingleSourceCorroboration`
    /// -- a counted vote that may not be independent corroboration at all.
    CorrelatedEvidenceSuspected,
    /// `EvidenceGapKind::NoEvidenceAtAll`.
    NoEvidenceAtAll,
    /// Sanitization (for export) changed the recorded outcome relative to
    /// the real, full-pool verdict (`CandidateCase::sanitization_altered_outcome`)
    /// -- a case where what a reviewer sees may differ from what Fornax
    /// itself concluded.
    SanitizationAlteredOutcome,
    /// `MiningStrategy::VerdictChangedAcrossFindings`.
    VerdictUnstableAcrossFindings,
    /// At least one real [`ReviewFeedback`] on this case has a
    /// disagreement-shaped [`crate::feedback::FeedbackDisposition`]
    /// (`FeedbackDisposition::is_disagreement`).
    HumanFeedbackDisagreement,
}

/// One case's derived signals, ready to rank. Carries `case_id`/`session_id`
/// so a [`SamplingPolicy`] never needs the original `CandidateCase` again.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CaseSignals {
    pub case_id: Uuid,
    pub session_id: String,
    pub signals: BTreeSet<SamplingSignal>,
    pub pattern: PatternKey,
}

/// A deterministic key grouping cases whose mining shape looks alike --
/// used to bound near-duplicate sampling (FORNX-349 AC4), never to judge
/// case content. Two cases share a pattern when they share the same claim
/// subject, the same sorted `mined_by` set, and the same local verdict --
/// deliberately coarse: `Claim::subject` is a single literal
/// (`"test_result"`) on every shipped adapter today (`fornax-adapter-claude`/
/// `-codex`), so the real discrimination comes from `mined_by`/verdict, not
/// `subject` -- `subject` is carried only for forward compatibility with a
/// future adapter that emits more than one subject.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct PatternKey(String);

impl PatternKey {
    pub fn compute(
        subject: &str,
        mined_by: &[MiningStrategy],
        local_verdict: fornax_types::Verdict,
    ) -> Self {
        let mut sorted_strategies = mined_by.to_vec();
        sorted_strategies.sort();
        let mut hasher = Sha256::new();
        hasher.update(subject.as_bytes());
        hasher.update([0u8]);
        for s in &sorted_strategies {
            hasher.update(format!("{s:?}").as_bytes());
            hasher.update([0u8]);
        }
        hasher.update(format!("{local_verdict:?}").as_bytes());
        let digest = hasher.finalize();
        Self(hex::encode(&digest[..8]))
    }

    /// Human-readable label for CLI rendering -- the hash itself, prefixed
    /// so it reads as a grouping key, not a case id.
    pub fn describe(&self) -> String {
        format!("pattern:{}", self.0)
    }
}

/// Derive [`CaseSignals`] for one `candidate`, given the `gaps` its current
/// fused finding produced and any [`ReviewFeedback`] already recorded
/// against it. Pure.
pub fn signals_for_case(
    candidate: &CandidateCase,
    gaps: &[EvidenceGap],
    feedback: &[ReviewFeedback],
) -> CaseSignals {
    let mut signals = BTreeSet::new();

    for gap in gaps {
        match gap.kind {
            EvidenceGapKind::UnresolvedConflict => {
                signals.insert(SamplingSignal::UnresolvedConflict);
            }
            EvidenceGapKind::AllVotesDiscounted => {
                signals.insert(SamplingSignal::HighUncertainty);
            }
            EvidenceGapKind::IndependenceUnverified
            | EvidenceGapKind::SingleSourceCorroboration => {
                signals.insert(SamplingSignal::CorrelatedEvidenceSuspected);
            }
            EvidenceGapKind::NoEvidenceAtAll => {
                signals.insert(SamplingSignal::NoEvidenceAtAll);
            }
            EvidenceGapKind::ExpectedSignalMissing { .. }
            | EvidenceGapKind::SignalClassUnobservable { .. }
            | EvidenceGapKind::StaleSupport => {}
        }
    }

    for strategy in &candidate.mined_by {
        match strategy {
            MiningStrategy::SensorDisagreement => {
                signals.insert(SamplingSignal::CrossSensorDisagreement);
            }
            MiningStrategy::HighUncertainty => {
                signals.insert(SamplingSignal::HighUncertainty);
            }
            MiningStrategy::VerdictChangedAcrossFindings => {
                signals.insert(SamplingSignal::VerdictUnstableAcrossFindings);
            }
            MiningStrategy::EvidenceContradiction | MiningStrategy::BenignControl => {}
        }
    }

    if candidate.sanitization_altered_outcome() {
        signals.insert(SamplingSignal::SanitizationAlteredOutcome);
    }

    if feedback
        .iter()
        .any(|f| f.case_id == candidate.id && f.disposition.is_disagreement())
    {
        signals.insert(SamplingSignal::HumanFeedbackDisagreement);
    }

    let pattern = PatternKey::compute(
        &candidate.replay.claim.subject,
        &candidate.mined_by,
        candidate.local_verdict,
    );

    CaseSignals {
        case_id: candidate.id,
        session_id: candidate.session_id.clone(),
        signals,
        pattern,
    }
}

/// Budget a sampling run must respect (FORNX-349 AC4: "reviewer workload
/// budgets ... duplicate sampling is bounded").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewBudget {
    pub max_cases: usize,
    pub max_per_pattern: usize,
}

pub const DEFAULT_MAX_PER_PATTERN: usize = 2;

impl ReviewBudget {
    pub fn new(max_cases: usize) -> Self {
        Self {
            max_cases,
            max_per_pattern: DEFAULT_MAX_PER_PATTERN,
        }
    }
}

/// Why a case was left out of a [`SamplingPlan`]'s selection -- nothing is
/// silently dropped, mirroring `fornax_verify::voi::EvidencePlan::unavailable`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeferralReason {
    /// This case's pattern already has `already_selected` cases in the
    /// plan, at or above `max_per_pattern`.
    PatternQuotaReached {
        pattern: String,
        already_selected: usize,
    },
    /// `max_cases` was already reached before this case was considered.
    BudgetExhausted,
    /// This case has no sampling signal at all -- ranks below every
    /// signaled case, deferred once the budget runs out rather than
    /// displacing a case with a real reason to prioritize it.
    NoSignal,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SelectedCase {
    pub case_id: Uuid,
    pub rank: u32,
    pub signals: BTreeSet<SamplingSignal>,
    /// Verbatim text for `fornax_store::adjudication::QueueEntry::selection_reason`
    /// -- zero schema change needed to make this auditable.
    pub selection_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeferredCase {
    pub case_id: Uuid,
    pub reason: DeferralReason,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SamplingPlan {
    pub policy_name: String,
    pub policy_version: u32,
    pub selected: Vec<SelectedCase>,
    pub deferred: Vec<DeferredCase>,
    pub distinct_patterns_available: usize,
    pub budget_exhausted: bool,
}

/// Swap/benchmark boundary for sampling policies, mirroring
/// `fornax_verify::fusion::FusionPolicy`/`decision::DecisionPolicy`'s shape.
pub trait SamplingPolicy {
    fn name(&self) -> &'static str;
    fn policy_version(&self) -> u32;
    fn rank(&self, cases: &[CaseSignals], budget: &ReviewBudget) -> SamplingPlan;
}

/// The first [`SamplingPolicy`] (FORNX-349). Deterministic: same input
/// always produces the same plan. Never serializes a numeric score --
/// output is ordinal signals plus a 1-based rank, same discipline as
/// `fornax_verify::voi`'s own "no numeric score is ever serialized"
/// invariant.
pub struct DeterministicSamplingPolicy;

/// Internal-only ranking weight -- never serialized, never part of any
/// public API. More signals ranks higher; ties broken deterministically
/// below.
fn score(signals: &BTreeSet<SamplingSignal>) -> usize {
    signals.len()
}

impl SamplingPolicy for DeterministicSamplingPolicy {
    fn name(&self) -> &'static str {
        "deterministic_active_sampling_v1"
    }

    fn policy_version(&self) -> u32 {
        SAMPLING_POLICY_VERSION
    }

    fn rank(&self, cases: &[CaseSignals], budget: &ReviewBudget) -> SamplingPlan {
        let mut ordered: Vec<&CaseSignals> = cases.iter().collect();
        // Deterministic tiebreak: score desc -> signal-set lexicographic
        // (as a sorted Vec, since BTreeSet already orders itself) -> case_id.
        ordered.sort_by(|a, b| {
            score(&b.signals)
                .cmp(&score(&a.signals))
                .then_with(|| {
                    let a_sorted: Vec<_> = a.signals.iter().collect();
                    let b_sorted: Vec<_> = b.signals.iter().collect();
                    a_sorted.cmp(&b_sorted)
                })
                .then_with(|| a.case_id.cmp(&b.case_id))
        });

        let distinct_patterns_available = cases
            .iter()
            .map(|c| c.pattern.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .len();

        let mut selected = Vec::new();
        let mut deferred = Vec::new();
        let mut per_pattern_count: std::collections::BTreeMap<PatternKey, usize> =
            std::collections::BTreeMap::new();
        let mut budget_exhausted = false;

        for case in ordered {
            if selected.len() >= budget.max_cases {
                budget_exhausted = true;
                deferred.push(DeferredCase {
                    case_id: case.case_id,
                    reason: DeferralReason::BudgetExhausted,
                });
                continue;
            }
            if case.signals.is_empty() {
                deferred.push(DeferredCase {
                    case_id: case.case_id,
                    reason: DeferralReason::NoSignal,
                });
                continue;
            }
            let count = per_pattern_count.entry(case.pattern.clone()).or_insert(0);
            if *count >= budget.max_per_pattern {
                deferred.push(DeferredCase {
                    case_id: case.case_id,
                    reason: DeferralReason::PatternQuotaReached {
                        pattern: case.pattern.describe(),
                        already_selected: *count,
                    },
                });
                continue;
            }
            *count += 1;
            let signal_list: Vec<String> = case.signals.iter().map(|s| format!("{s:?}")).collect();
            selected.push(SelectedCase {
                case_id: case.case_id,
                rank: selected.len() as u32 + 1,
                signals: case.signals.clone(),
                selection_reason: format!(
                    "active_sampling({}@{}) rank={} signals={}",
                    self.name(),
                    self.policy_version(),
                    selected.len() + 1,
                    signal_list.join(",")
                ),
            });
        }

        SamplingPlan {
            policy_name: self.name().to_string(),
            policy_version: self.policy_version(),
            selected,
            deferred,
            distinct_patterns_available,
            budget_exhausted,
        }
    }
}

/// Whether a frozen [`crate::adjudication::taxonomy::CaseLabel`] agrees
/// with a candidate's own `local_verdict` -- derived post-hoc from an
/// already-frozen label, never asked of a blinded reviewer directly (same
/// discipline as `crate::adjudication::state::derive_state`). Three-valued,
/// not boolean: [`crate::adjudication::taxonomy::CaseLabel::NotEvaluable`]
/// has no `expected_verdict` at all, and collapsing that into "disagree"
/// would manufacture a disagreement that was never actually judged. This
/// mapping is verdict-level, not label-level -- `Incomplete`/`Unreliable`
/// both map to `Verdict::Review`, so two labels that `taxonomy.rs`
/// deliberately keeps distinct can both read as `Agrees` here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictAgreement {
    Agrees,
    Disagrees,
    /// The label carries no `expected_verdict` (`NotEvaluable`) -- there is
    /// nothing to compare.
    Undefined,
}

pub fn derived_verdict_agreement(
    label: crate::adjudication::taxonomy::CaseLabel,
    local_verdict: fornax_types::Verdict,
) -> VerdictAgreement {
    match label.expected_verdict() {
        None => VerdictAgreement::Undefined,
        Some(expected) if expected == local_verdict => VerdictAgreement::Agrees,
        Some(_) => VerdictAgreement::Disagrees,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adjudication::taxonomy::CaseLabel;
    use fornax_types::Verdict;

    fn signals(case_id: Uuid, sigs: &[SamplingSignal], pattern: &str) -> CaseSignals {
        CaseSignals {
            case_id,
            session_id: "s1".to_string(),
            signals: sigs.iter().copied().collect(),
            pattern: PatternKey(pattern.to_string()),
        }
    }

    #[test]
    fn cases_with_more_signals_rank_higher() {
        let a = signals(Uuid::new_v4(), &[SamplingSignal::UnresolvedConflict], "p1");
        let b = signals(
            Uuid::new_v4(),
            &[
                SamplingSignal::UnresolvedConflict,
                SamplingSignal::HighUncertainty,
            ],
            "p2",
        );
        let plan =
            DeterministicSamplingPolicy.rank(&[a.clone(), b.clone()], &ReviewBudget::new(10));
        assert_eq!(plan.selected[0].case_id, b.case_id);
        assert_eq!(plan.selected[1].case_id, a.case_id);
    }

    #[test]
    fn cases_with_no_signal_at_all_are_deferred_as_no_signal() {
        let a = signals(Uuid::new_v4(), &[], "p1");
        let plan =
            DeterministicSamplingPolicy.rank(std::slice::from_ref(&a), &ReviewBudget::new(10));
        assert!(plan.selected.is_empty());
        assert_eq!(plan.deferred.len(), 1);
        assert!(matches!(plan.deferred[0].reason, DeferralReason::NoSignal));
    }

    #[test]
    fn pattern_quota_bounds_near_duplicate_sampling() {
        let mut cases = Vec::new();
        for _ in 0..5 {
            cases.push(signals(
                Uuid::new_v4(),
                &[SamplingSignal::HighUncertainty],
                "duplicate-pattern",
            ));
        }
        let distinct = signals(
            Uuid::new_v4(),
            &[SamplingSignal::UnresolvedConflict],
            "unique-pattern",
        );
        cases.push(distinct.clone());

        let budget = ReviewBudget {
            max_cases: 10,
            max_per_pattern: 2,
        };
        let plan = DeterministicSamplingPolicy.rank(&cases, &budget);
        assert_eq!(
            plan.selected.len(),
            3,
            "2 from the duplicate pattern + 1 unique"
        );
        assert!(plan.selected.iter().any(|s| s.case_id == distinct.case_id));
        let quota_deferrals = plan
            .deferred
            .iter()
            .filter(|d| matches!(d.reason, DeferralReason::PatternQuotaReached { .. }))
            .count();
        assert_eq!(quota_deferrals, 3);
    }

    #[test]
    fn budget_exhaustion_defers_the_rest_honestly() {
        let cases: Vec<_> = (0..5)
            .map(|i| {
                signals(
                    Uuid::new_v4(),
                    &[SamplingSignal::HighUncertainty],
                    &format!("p{i}"),
                )
            })
            .collect();
        let plan = DeterministicSamplingPolicy.rank(&cases, &ReviewBudget::new(2));
        assert_eq!(plan.selected.len(), 2);
        assert!(plan.budget_exhausted);
        assert!(plan
            .deferred
            .iter()
            .all(|d| matches!(d.reason, DeferralReason::BudgetExhausted)));
    }

    #[test]
    fn plan_never_serializes_a_numeric_score() {
        let a = signals(Uuid::new_v4(), &[SamplingSignal::UnresolvedConflict], "p1");
        let plan = DeterministicSamplingPolicy.rank(&[a], &ReviewBudget::new(10));
        let json = serde_json::to_value(&plan).unwrap();
        let text = json.to_string();
        // Only ordinal rank (1-based small int) and signal names may
        // appear -- no field named anything score-shaped.
        assert!(!text.contains("\"score\""));
    }

    #[test]
    fn verdict_agreement_is_three_valued_not_boolean() {
        assert_eq!(
            derived_verdict_agreement(CaseLabel::Reliable, Verdict::Verified),
            VerdictAgreement::Agrees
        );
        assert_eq!(
            derived_verdict_agreement(CaseLabel::Contradicted, Verdict::Verified),
            VerdictAgreement::Disagrees
        );
        assert_eq!(
            derived_verdict_agreement(CaseLabel::NotEvaluable, Verdict::Verified),
            VerdictAgreement::Undefined
        );
    }

    #[test]
    fn pattern_key_is_stable_for_identical_shape_and_differs_for_different_verdicts() {
        let k1 = PatternKey::compute(
            "test_result",
            &[MiningStrategy::HighUncertainty],
            Verdict::Unverified,
        );
        let k2 = PatternKey::compute(
            "test_result",
            &[MiningStrategy::HighUncertainty],
            Verdict::Unverified,
        );
        assert_eq!(k1, k2);
        let k3 = PatternKey::compute(
            "test_result",
            &[MiningStrategy::HighUncertainty],
            Verdict::Verified,
        );
        assert_ne!(k1, k3);
    }
}
