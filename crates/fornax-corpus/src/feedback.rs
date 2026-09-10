//! Product feedback on a live finding/recommendation (FORNX-349), kept
//! structurally separate from research adjudication (`crate::adjudication`).
//!
//! # Why feedback can never become a `ReviewRecord`
//!
//! Adjudication (FORNX-342) is blinded by default, requires an attested
//! `Human` reviewer for anything that may ever be frozen into a gold
//! label, and exists specifically to avoid confirmation bias. Product
//! feedback is the opposite shape: the author *saw* the live
//! verdict/recommendation before reacting to it, may be an automated
//! agent, and is submitted single-shot with no blinding at all. If
//! [`ReviewFeedback`] could convert into a [`crate::adjudication::review::ReviewRecord`],
//! an unblinded, unattested, possibly-agent-authored judgment would reach
//! the exact table [`crate::adjudication::gold::promote_gold_label`]
//! reads. So this module defines no such conversion, in either direction:
//! [`ReviewFeedback`] carries no [`crate::adjudication::taxonomy::CaseLabel`]
//! and no [`crate::adjudication::review::ReviewOutcome`] field, and nothing
//! here calls into `crate::adjudication` at all. Feedback is a routing
//! signal that can raise a case's sampling priority
//! (`crate::sampling::SamplingSignal::HumanFeedbackDisagreement`) -- never a
//! path to a frozen label.
//!
//! A `FeedbackAuthor::AutomatedAgent` may submit feedback. This is
//! deliberate and safe specifically *because* of the above: there is no
//! path from any [`FeedbackAuthor`] variant to `HumanAdjudicated`
//! provenance, so an agent's feedback can influence which cases a human
//! reviews next, but can never impersonate the human review itself.

use uuid::Uuid;

use fornax_types::reliability_context::CohortIdentity;

use crate::candidate::CandidateCase;

pub const FEEDBACK_SCHEMA_VERSION: u32 = 1;

/// Who submitted one [`ReviewFeedback`] row. Both variants are recorded
/// explicitly and neither is ever treated as a [`crate::adjudication::review::ReviewerRef`]
/// -- see module docs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeedbackAuthor {
    /// A person using the live product surface (dashboard/CLI), identified
    /// by an opaque local reference -- not necessarily the same identity
    /// space as an adjudication `reviewer_id`.
    LocalOperator { operator_ref: String },
    /// An automated agent (e.g. a coding agent reacting to its own
    /// recommendation). Recorded honestly as such -- never disguised as
    /// `LocalOperator`.
    AutomatedAgent { agent_ref: String },
}

/// What the author is telling Fornax about the finding/recommendation they
/// saw. Deliberately a separate enum from
/// [`crate::adjudication::taxonomy::FailureClass`]: two of these variants
/// (`AgreesWithFinding`, `WrongRecommendation`) have no home in the blinded
/// research taxonomy at all -- `WrongRecommendation` specifically requires
/// seeing `recorded_action`, which `crate::adjudication::blind::blind`
/// deliberately strips from every blinded view. This vocabulary only ever
/// applies to the unblinded, already-decided product surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackDisposition {
    AgreesWithFinding,
    DisagreesWithFinding,
    MissingContext,
    WrongEvidenceMapping,
    WrongRecommendation,
    NotEvaluable,
}

impl FeedbackDisposition {
    /// True for a disposition that names a real problem with the finding
    /// -- used by `crate::sampling` to derive
    /// [`crate::sampling::SamplingSignal::HumanFeedbackDisagreement`].
    /// `AgreesWithFinding` and `NotEvaluable` are not disagreements: the
    /// former is a positive signal, the latter is an honest "cannot judge
    /// this", not a claim that something is wrong.
    pub fn is_disagreement(self) -> bool {
        matches!(
            self,
            FeedbackDisposition::DisagreesWithFinding
                | FeedbackDisposition::MissingContext
                | FeedbackDisposition::WrongEvidenceMapping
                | FeedbackDisposition::WrongRecommendation
        )
    }
}

/// The exact provenance one piece of feedback is bound to (FORNX-349 scope:
/// "bind feedback to exact claim/evidence/fusion/policy/model/runtime/corpus
/// versions"). Read verbatim from a [`CandidateCase`]'s own
/// `fornax_replay::ReplayManifest` -- never re-derived or guessed.
/// `model_version` has no local source anywhere in this workspace (see
/// `docs/adr/0018-calibration-validity-lifecycle.md`) and stays `None`
/// rather than a fabricated placeholder; `context` mirrors
/// [`CandidateCase::context`]'s own honesty ("usually `None` -- no local
/// source for model_family/task_class/repository_class").
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FeedbackBinding {
    pub candidate_schema_version: u32,
    pub fusion_policy_name: String,
    pub fusion_policy_version: u32,
    pub decision_policy_name: String,
    pub decision_policy_version: u32,
    pub adapter_provider: fornax_types::Provider,
    pub adapter_runtime_version: String,
    pub disabled_sensors: std::collections::BTreeSet<String>,
    pub context: Option<CohortIdentity>,
    /// No local source exists for this dimension today -- see module docs.
    /// Never populated except by an explicit future caller who has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
}

impl FeedbackBinding {
    /// Builds a binding from `candidate`'s own frozen manifest -- the only
    /// constructor, so a binding can never disagree with the case it
    /// claims to describe.
    pub fn from_candidate(candidate: &CandidateCase) -> Self {
        let replay = &candidate.replay;
        Self {
            candidate_schema_version: candidate.schema_version,
            fusion_policy_name: replay.fusion_policy_name.clone(),
            fusion_policy_version: replay.fusion_policy_version,
            decision_policy_name: replay.decision_policy_name.clone(),
            decision_policy_version: replay.decision_policy_version,
            adapter_provider: replay.adapter_provider,
            adapter_runtime_version: replay.adapter_runtime_version.clone(),
            disabled_sensors: replay.disabled_sensors.clone(),
            context: candidate.context.clone(),
            model_version: None,
        }
    }
}

/// One piece of product feedback, bound to the exact candidate case it was
/// given on. See module docs for why this can never become research
/// adjudication.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReviewFeedback {
    pub schema_version: u32,
    pub id: Uuid,
    pub case_id: Uuid,
    pub session_id: String,
    pub claim_id: Uuid,
    pub disposition: FeedbackDisposition,
    /// One sentence: what the author actually saw. Required, like
    /// `crate::adjudication::review::ReviewRecord::rationale`.
    pub reason: String,
    pub reviewer_confidence: crate::adjudication::taxonomy::Confidence,
    pub author: FeedbackAuthor,
    pub bound_to: FeedbackBinding,
    pub submitted_at: String,
}

impl ReviewFeedback {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate: &CandidateCase,
        claim_id: Uuid,
        disposition: FeedbackDisposition,
        reason: String,
        reviewer_confidence: crate::adjudication::taxonomy::Confidence,
        author: FeedbackAuthor,
        submitted_at: String,
    ) -> Self {
        Self {
            schema_version: FEEDBACK_SCHEMA_VERSION,
            id: Uuid::new_v4(),
            case_id: candidate.id,
            session_id: candidate.session_id.clone(),
            claim_id,
            disposition,
            reason,
            reviewer_confidence,
            author,
            bound_to: FeedbackBinding::from_candidate(candidate),
            submitted_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adjudication::taxonomy::Confidence;
    use fornax_replay::manifest::ReplayManifest;
    use fornax_types::{graph::EvidenceGraph, Claim, Verdict};
    use fornax_verify::decision::{RecommendationAction, RiskClass};
    use fornax_verify::fusion::UncertaintyBand;
    use std::collections::BTreeSet;

    fn candidate() -> CandidateCase {
        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "s1".to_string(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".to_string(),
            subject: "command_succeeded".to_string(),
            claimed_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let replay = ReplayManifest {
            manifest_schema_version: 1,
            adapter_provider: fornax_types::Provider::ClaudeCode,
            adapter_runtime_version: "0.3.0".to_string(),
            fusion_policy_name: "deterministic_baseline_v1".to_string(),
            fusion_policy_version: 2,
            decision_policy_name: "default_risk_policy_v1".to_string(),
            decision_policy_version: 1,
            risk_class: RiskClass::Balanced,
            disabled_sensors: BTreeSet::new(),
            claim: claim.clone(),
            evidence_pool: vec![],
            evidence_graph: EvidenceGraph {
                links: vec![],
                missing: vec![],
            },
            recorded_verdict: Verdict::Unverified,
            recorded_uncertainty: UncertaintyBand::Undetermined,
            recorded_action: RecommendationAction::Review,
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
        };
        CandidateCase {
            schema_version: crate::candidate::CANDIDATE_SCHEMA_VERSION,
            id: Uuid::new_v4(),
            session_id: "s1".to_string(),
            replay,
            context: None,
            local_verdict: Verdict::Unverified,
            local_uncertainty: UncertaintyBand::Undetermined,
            mined_by: vec![],
            withheld_evidence: vec![],
            mined_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn binding_is_read_verbatim_from_the_candidates_replay_manifest() {
        let c = candidate();
        let binding = FeedbackBinding::from_candidate(&c);
        assert_eq!(binding.fusion_policy_version, 2);
        assert_eq!(binding.adapter_runtime_version, "0.3.0");
        assert_eq!(binding.model_version, None);
    }

    #[test]
    fn feedback_binds_to_the_exact_case_it_was_given_on() {
        let c = candidate();
        let claim_id = c.replay.claim.id;
        let fb = ReviewFeedback::new(
            &c,
            claim_id,
            FeedbackDisposition::DisagreesWithFinding,
            "the evidence shown doesn't support this verdict".to_string(),
            Confidence::High,
            FeedbackAuthor::LocalOperator {
                operator_ref: "op1".to_string(),
            },
            "2026-01-02T00:00:00Z".to_string(),
        );
        assert_eq!(fb.case_id, c.id);
        assert_eq!(fb.claim_id, claim_id);
        assert_eq!(fb.bound_to, FeedbackBinding::from_candidate(&c));
    }

    #[test]
    fn disagreement_dispositions_are_classified_correctly() {
        assert!(!FeedbackDisposition::AgreesWithFinding.is_disagreement());
        assert!(!FeedbackDisposition::NotEvaluable.is_disagreement());
        assert!(FeedbackDisposition::DisagreesWithFinding.is_disagreement());
        assert!(FeedbackDisposition::MissingContext.is_disagreement());
        assert!(FeedbackDisposition::WrongEvidenceMapping.is_disagreement());
        assert!(FeedbackDisposition::WrongRecommendation.is_disagreement());
    }

    #[test]
    fn an_automated_agent_author_is_recorded_honestly_not_disguised() {
        let c = candidate();
        let claim_id = c.replay.claim.id;
        let fb = ReviewFeedback::new(
            &c,
            claim_id,
            FeedbackDisposition::AgreesWithFinding,
            "matches my own observation".to_string(),
            Confidence::Medium,
            FeedbackAuthor::AutomatedAgent {
                agent_ref: "agent-1".to_string(),
            },
            "2026-01-02T00:00:00Z".to_string(),
        );
        let json = serde_json::to_value(&fb.author).unwrap();
        assert_eq!(json["kind"], serde_json::json!("automated_agent"));
    }

    /// FORNX-349 structural guard: this module must never reference
    /// `crate::adjudication`'s label/outcome/gold types, and no function
    /// here may convert a `FeedbackDisposition`/`ReviewFeedback` toward
    /// one. A source scan, not just a doc comment -- if a future edit adds
    /// such a reference, this test fails immediately rather than relying
    /// on a reviewer noticing. Mirrors this workspace's other
    /// source-scanning invariant tests (e.g.
    /// `fornax-daemon/tests/adversarial_daemon_input.rs::
    /// subprocess_surface_is_still_zero_in_production_code`).
    #[test]
    fn feedback_module_never_references_adjudication_label_or_gold_types() {
        let source = include_str!("feedback.rs");
        // Comments (`//`/`///`) may name these types to explain the
        // boundary in prose -- only real, non-comment code must not. Strip
        // every comment line before scanning, and stop before this test
        // function's own body so its forbidden-substring literals (and
        // this very explanation) can't trip themselves.
        let code_end = source
            .find("fn feedback_module_never_references_adjudication_label_or_gold_types")
            .expect("this test's own name must still be findable in its own source");
        let code: String = source[..code_end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "CaseLabel",
            "ReviewOutcome",
            "ReviewerRef",
            "ReviewerKind",
            "promote_gold_label",
            "GoldLabelRevision",
            "adjudication::review::",
            "adjudication::gold::",
            "adjudication::state::",
            "adjudication::blind::",
        ] {
            assert!(
                !code.contains(forbidden),
                "feedback.rs's real code (not a comment) must never reference `{forbidden}` \
                 -- feedback must never become adjudication, see module docs"
            );
        }
    }
}
