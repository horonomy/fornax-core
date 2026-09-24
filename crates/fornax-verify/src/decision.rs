//! Decision UX (FORNX-96, parent epic FORNX-66, local half only — see this
//! ticket's PR body for the SaaS-half follow-up). Translates a computed
//! [`crate::fusion::FusedFinding`] into an actionable recommendation —
//! `PROCEED`/`REVIEW`/`BLOCK` — without ever hiding or replacing the
//! underlying evidence that produced it.
//!
//! # Relationship to fusion
//!
//! This module is strictly downstream of [`crate::fusion`]: a
//! [`DecisionPolicy`] consumes an already-computed `FusedFinding` and never
//! recomputes or reinterprets the evidence graph itself. [`Recommendation`]
//! carries `claim_id` — a pointer back to the `FusedFinding`/claim it was
//! computed from — and never embeds or duplicates the fusion rationale
//! trail. FORNX-96 AC: "Recommendation never replaces the underlying
//! Finding/evidence graph" is enforced operationally at the daemon layer
//! (`fornax-daemon`'s `/api/decision` always returns the `Recommendation`
//! *and* the `FusedFinding` together, never one instead of the other) —
//! this module only guarantees the type-level half of that contract.
//!
//! # Policy identity is separate from fusion policy identity
//!
//! [`Recommendation::policy_name`]/[`Recommendation::policy_version`] name
//! the *decision* policy (e.g. `"default_risk_policy_v1"`), a distinct
//! identity axis from `FusedFinding::policy_name`/`policy_version`, which
//! name the *fusion* policy that produced the referenced `FusedFinding`. A
//! caller must never conflate the two — swapping the decision policy must
//! never require re-fusing evidence, and vice versa.
//!
//! # Risk classes make the same finding yield different actions
//!
//! FORNX-96 AC: "Same finding can yield different actions under explicit
//! policy/risk contexts without changing historical evidence." [`RiskClass`]
//! is the explicit context a caller supplies; [`DefaultRiskPolicy::decide`]
//! is pure — the same `(FusedFinding, RiskClass)` pair always produces the
//! same `Recommendation`, and two different `RiskClass` values run over the
//! identical `FusedFinding` can (and, per the mapping table below,
//! sometimes do) produce different [`RecommendationAction`]s. The
//! `FusedFinding` itself is never mutated or re-derived by this process.
//!
//! # Safety floor: uncertainty is never presented as confidently safe
//!
//! FORNX-96 AC: "High uncertainty/missing critical evidence cannot be
//! presented as confidently safe by default." [`DefaultRiskPolicy`]'s
//! mapping table (see [`DefaultRiskPolicy::action_for`]) enforces this as a
//! hard floor, not a tunable default:
//!
//! - [`fornax_types::Verdict::Verified`] paired with
//!   [`crate::fusion::UncertaintyBand::Qualified`] or `Conflicted` never
//!   maps to `Proceed` under any risk class.
//! - [`fornax_types::Verdict::Unverified`] / `Unavailable` never map to
//!   `Proceed` under the default/[`RiskClass::Balanced`] risk class — nor,
//!   deliberately, under `Strict` or `Lenient` either; see that function's
//!   doc comment for why leniency is not extended here.
//! - [`fornax_types::Verdict::Contradicted`], and any case where
//!   [`crate::fusion::FusedFinding::unresolved_conflict`] is true (which,
//!   under [`crate::fusion::BaselineFusionPolicy`], is the only way
//!   `Verdict::Review` is ever produced), never map to `Proceed` under ANY
//!   risk class.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::fusion::{FusedFinding, UncertaintyBand};
use fornax_types::Verdict;

/// Closed recommendation vocabulary (FORNX-96 scope line: "PROCEED, REVIEW,
/// BLOCK ... recommendation semantics separate from integrity verdict").
/// Deliberately not merged with [`fornax_types::Verdict`] — a
/// `RecommendationAction` is a downstream decision about *what to do*,
/// never a restatement of *what was observed*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationAction {
    Proceed,
    Review,
    Block,
}

/// Closed risk-class vocabulary (FORNX-96 AC: "same finding can yield
/// different actions under explicit policy/risk contexts"). Three classes,
/// ordered from most to least conservative:
///
/// - `Strict`: minimizes false negatives (missed problems) — most likely of
///   the three to `Review`/`Block` rather than `Proceed`.
/// - `Balanced`: the default applied when no risk class is specified by the
///   caller; every hard safety floor documented on this module is written
///   against this class specifically, though `Strict`/`Lenient` honor the
///   same floors (see [`DefaultRiskPolicy::action_for`]).
/// - `Lenient`: still never crosses a hard safety floor established in
///   [`DefaultRiskPolicy`] — it only ever relaxes a `Block` to a `Review`
///   where `DefaultRiskPolicy` judges that safe, never a `Review`/`Block`
///   to `Proceed` in a case this module has decided is unsafe by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Strict,
    Balanced,
    Lenient,
}

/// Output of [`DecisionPolicy::decide`]. Points back at the
/// [`FusedFinding`]/claim it was computed from via `claim_id` rather than
/// embedding or duplicating its rationale — see this module's docs, "FORNX-96
/// AC: recommendation never replaces the underlying Finding/evidence graph".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    pub claim_id: Uuid,
    pub action: RecommendationAction,
    pub risk_class: RiskClass,
    /// Identity of the DECISION policy that produced this recommendation —
    /// a separate identity axis from the FUSION policy that produced the
    /// referenced [`FusedFinding`] (see module docs).
    pub policy_name: String,
    pub policy_version: u32,
    /// Short human-readable summary of *why* this action was chosen. Not a
    /// substitute for the full fusion rationale trail, which stays
    /// reachable via `claim_id` -> the referenced `FusedFinding`.
    pub rationale_summary: String,
}

/// Swap/benchmark boundary for decision recommendations (mirrors
/// [`crate::fusion::FusionPolicy`]'s shape). Maps an already-computed
/// `FusedFinding` plus an explicit `RiskClass` to one `Recommendation` —
/// never touches or recomputes the underlying evidence graph.
pub trait DecisionPolicy {
    /// Stable identity, recorded on every [`Recommendation::policy_name`]
    /// this policy produces.
    fn name(&self) -> &'static str;

    /// This policy's own version — bump whenever its mapping table changes
    /// in a way that could change output for the same input.
    fn policy_version(&self) -> u32;

    fn decide(&self, fused: &FusedFinding, risk: RiskClass) -> Recommendation;
}

/// The first [`DecisionPolicy`] implementation (FORNX-96). Its mapping
/// table is an explicit match over `(Verdict, UncertaintyBand, RiskClass)`,
/// not a numeric/weighted formula — every row is justified in
/// [`Self::action_for`]'s doc comment inline with the row itself.
pub struct DefaultRiskPolicy;

impl DefaultRiskPolicy {
    /// The decision mapping table (FORNX-96's central safety property — see
    /// module docs' "Safety floor" section). Exhaustive over all 5 verdicts
    /// x 4 uncertainty bands x 3 risk classes so that a future change to
    /// [`crate::fusion::BaselineFusionPolicy`] (or a different
    /// `FusionPolicy` implementation entirely) that produces a
    /// verdict/band pairing unreachable today cannot silently fall through
    /// to an unsafe default — every arm is written down, not inferred from
    /// a wildcard that happens to resolve to `Proceed`.
    ///
    /// Reachability today, under [`crate::fusion::BaselineFusionPolicy`]
    /// specifically (documented for reviewers, not relied on by the match
    /// itself — the table below stays exhaustive regardless):
    /// `Verified`/`Contradicted` only ever pair with `Corroborated` or
    /// `Qualified` (never `Undetermined`, since both verdicts require at
    /// least one counted vote; never `Conflicted`, since
    /// `unresolved_conflict` always forces `Verdict::Review` instead).
    /// `Unverified`/`Unavailable` only ever pair with `Undetermined` (both
    /// require zero counted votes). `Review` only ever pairs with
    /// `Conflicted` (the only path `BaselineFusionPolicy` uses to produce
    /// `Verdict::Review` at all).
    fn action_for(
        verdict: Verdict,
        band: UncertaintyBand,
        risk: RiskClass,
    ) -> RecommendationAction {
        use RecommendationAction::{Block, Proceed, Review};
        use RiskClass::{Balanced, Lenient, Strict};
        use UncertaintyBand::{Conflicted, Corroborated, Qualified, Undetermined};
        use Verdict::{Contradicted, Review as ReviewVerdict, Unavailable, Unverified, Verified};

        match (verdict, band, risk) {
            // Verified + Corroborated: the ONLY combination that ever
            // reaches Proceed, under any risk class -- clean support, no
            // caveats, no missing evidence.
            (Verified, Corroborated, Strict) => Proceed,
            (Verified, Corroborated, Balanced) => Proceed,
            (Verified, Corroborated, Lenient) => Proceed,

            // Verified + Qualified: hard AC line -- "high uncertainty ...
            // cannot be presented as confidently safe by default". A
            // caveat fired (stale-but-retained contradiction, unverified
            // independence, a discounted link, etc.) -- never Proceed,
            // at most Review, regardless of risk class.
            (Verified, Qualified, Strict | Balanced | Lenient) => Review,

            // Verified + Undetermined / Conflicted: not reachable from
            // BaselineFusionPolicy today (see doc comment above), kept
            // here so an exhaustive match fails safe -- mapped to the same
            // conservative Review a Qualified band gets, never Proceed.
            (Verified, Undetermined, Strict | Balanced | Lenient) => Review,
            (Verified, Conflicted, Strict | Balanced | Lenient) => Review,

            // Contradicted: hard AC line -- never Proceed under ANY risk
            // class. Corroborated (clean contradiction) blocks outright
            // under Strict/Balanced; Lenient still only relaxes to Review,
            // never Proceed.
            (Contradicted, Corroborated, Strict) => Block,
            (Contradicted, Corroborated, Balanced) => Block,
            (Contradicted, Corroborated, Lenient) => Review,
            // Contradicted + Qualified: a caveated contradiction. Strict
            // still blocks; Balanced/Lenient step down to Review, never
            // Proceed.
            (Contradicted, Qualified, Strict) => Block,
            (Contradicted, Qualified, Balanced) => Review,
            (Contradicted, Qualified, Lenient) => Review,
            // Contradicted + Undetermined / Conflicted: not reachable
            // today (see doc comment above) -- defensive, kept at the most
            // conservative Block across all risk classes.
            (Contradicted, Undetermined, Strict | Balanced | Lenient) => Block,
            (Contradicted, Conflicted, Strict | Balanced | Lenient) => Block,

            // Unverified: hard AC line -- must never map to Proceed under
            // the default/Balanced risk class. Deliberately NOT extended
            // to Lenient either -- "nobody has verified this" is not a
            // case this module is confident enough to relax by default;
            // per the ticket's own instruction, default to NOT allowing
            // leniency when unsure. Strict blocks outright.
            (Unverified, _, Strict) => Block,
            (Unverified, _, Balanced) => Review,
            (Unverified, _, Lenient) => Review,

            // Unavailable: missing critical/expected evidence, explicitly
            // noted so by a sensor -- the AC's "missing critical evidence"
            // case in the clearest form. Same hard floor as Unverified:
            // never Proceed under any class. Strict/Balanced block; Lenient
            // steps down to Review only, still never Proceed.
            (Unavailable, _, Strict) => Block,
            (Unavailable, _, Balanced) => Block,
            (Unavailable, _, Lenient) => Review,

            // Review verdict: under BaselineFusionPolicy this is ONLY ever
            // produced via `unresolved_conflict` (both Supports and
            // Contradicts survived fusion, neither dominates). Hard AC
            // line: unresolved conflict never maps to Proceed under ANY
            // risk class -- held here at the most conservative Block for
            // every band/risk combination, with no exception.
            (ReviewVerdict, _, Strict | Balanced | Lenient) => Block,
        }
    }
}

impl DecisionPolicy for DefaultRiskPolicy {
    fn name(&self) -> &'static str {
        "default_risk_policy_v1"
    }

    fn policy_version(&self) -> u32 {
        1
    }

    fn decide(&self, fused: &FusedFinding, risk: RiskClass) -> Recommendation {
        let action = Self::action_for(fused.verdict, fused.uncertainty, risk);
        let rationale_summary = format!(
            "verdict={:?} uncertainty={:?} risk={:?} -> {:?} under policy {} v{}; see the \
             referenced FusedFinding (claim {}) for the full evidence rationale trail",
            fused.verdict,
            fused.uncertainty,
            risk,
            action,
            self.name(),
            self.policy_version(),
            fused.claim_id
        );
        Recommendation {
            claim_id: fused.claim_id,
            action,
            risk_class: risk,
            policy_name: self.name().to_string(),
            policy_version: self.policy_version(),
            rationale_summary,
        }
    }
}

#[cfg(test)]
mod decision_tests {
    use super::*;
    use crate::fusion::{FusionRule, RationaleEntry, RuleEffect};

    /// Minimal, directly-constructed `FusedFinding` fixture -- this module
    /// tests `DecisionPolicy` in isolation from `FusionPolicy`, so it never
    /// needs a real `EvidenceGraph`/`FusionInput` to exercise the mapping
    /// table.
    fn fused(
        verdict: Verdict,
        uncertainty: UncertaintyBand,
        unresolved_conflict: bool,
    ) -> FusedFinding {
        FusedFinding {
            claim_id: Uuid::new_v4(),
            verdict,
            uncertainty,
            rationale: vec![RationaleEntry {
                rule: FusionRule::VerdictDecided,
                effect: RuleEffect::Decided,
                link_ids: vec![],
                missing_evidence_ids: vec![],
                evidence_ids: vec![],
                detail: "test fixture".into(),
            }],
            counted_link_ids: vec![],
            discounted_link_ids: vec![],
            missing_evidence_ids: vec![],
            unresolved_conflict,
            policy_name: "deterministic_baseline_v1".into(),
            policy_version: 1,
            computed_at: "2026-01-02T00:00:00Z".into(),
        }
    }

    const ALL_RISK_CLASSES: [RiskClass; 3] =
        [RiskClass::Strict, RiskClass::Balanced, RiskClass::Lenient];
    const ALL_BANDS: [UncertaintyBand; 4] = [
        UncertaintyBand::Corroborated,
        UncertaintyBand::Qualified,
        UncertaintyBand::Undetermined,
        UncertaintyBand::Conflicted,
    ];

    // --- Full mapping table, pinned exactly (not just "never Proceed") ----

    /// Pins `DefaultRiskPolicy::action_for`'s entire mapping table -- every
    /// (verdict, band) row, every risk class -- to its exact expected
    /// `RecommendationAction`, not merely "not Proceed". This is what makes
    /// the table this PR documents an actually-reviewable artifact: a
    /// single row flipping (e.g. `Contradicted`/`Corroborated`/`Lenient`
    /// silently changing from `Review` to `Block`) fails here even though
    /// it would satisfy every narrower "never Proceed" safety test below.
    #[test]
    fn mapping_table_is_pinned_exactly_for_every_verdict_band_risk_combination() {
        use RecommendationAction::{Block, Proceed, Review};

        // (verdict, band, strict, balanced, lenient)
        let table: [(
            Verdict,
            UncertaintyBand,
            RecommendationAction,
            RecommendationAction,
            RecommendationAction,
        ); 20] = [
            (
                Verdict::Verified,
                UncertaintyBand::Corroborated,
                Proceed,
                Proceed,
                Proceed,
            ),
            (
                Verdict::Verified,
                UncertaintyBand::Qualified,
                Review,
                Review,
                Review,
            ),
            (
                Verdict::Verified,
                UncertaintyBand::Undetermined,
                Review,
                Review,
                Review,
            ),
            (
                Verdict::Verified,
                UncertaintyBand::Conflicted,
                Review,
                Review,
                Review,
            ),
            (
                Verdict::Contradicted,
                UncertaintyBand::Corroborated,
                Block,
                Block,
                Review,
            ),
            (
                Verdict::Contradicted,
                UncertaintyBand::Qualified,
                Block,
                Review,
                Review,
            ),
            (
                Verdict::Contradicted,
                UncertaintyBand::Undetermined,
                Block,
                Block,
                Block,
            ),
            (
                Verdict::Contradicted,
                UncertaintyBand::Conflicted,
                Block,
                Block,
                Block,
            ),
            (
                Verdict::Unverified,
                UncertaintyBand::Corroborated,
                Block,
                Review,
                Review,
            ),
            (
                Verdict::Unverified,
                UncertaintyBand::Qualified,
                Block,
                Review,
                Review,
            ),
            (
                Verdict::Unverified,
                UncertaintyBand::Undetermined,
                Block,
                Review,
                Review,
            ),
            (
                Verdict::Unverified,
                UncertaintyBand::Conflicted,
                Block,
                Review,
                Review,
            ),
            (
                Verdict::Unavailable,
                UncertaintyBand::Corroborated,
                Block,
                Block,
                Review,
            ),
            (
                Verdict::Unavailable,
                UncertaintyBand::Qualified,
                Block,
                Block,
                Review,
            ),
            (
                Verdict::Unavailable,
                UncertaintyBand::Undetermined,
                Block,
                Block,
                Review,
            ),
            (
                Verdict::Unavailable,
                UncertaintyBand::Conflicted,
                Block,
                Block,
                Review,
            ),
            (
                Verdict::Review,
                UncertaintyBand::Corroborated,
                Block,
                Block,
                Block,
            ),
            (
                Verdict::Review,
                UncertaintyBand::Qualified,
                Block,
                Block,
                Block,
            ),
            (
                Verdict::Review,
                UncertaintyBand::Undetermined,
                Block,
                Block,
                Block,
            ),
            (
                Verdict::Review,
                UncertaintyBand::Conflicted,
                Block,
                Block,
                Block,
            ),
        ];

        for (verdict, band, strict_expected, balanced_expected, lenient_expected) in table {
            let f = fused(verdict, band, verdict == Verdict::Review);
            for (risk, expected) in [
                (RiskClass::Strict, strict_expected),
                (RiskClass::Balanced, balanced_expected),
                (RiskClass::Lenient, lenient_expected),
            ] {
                let rec = DefaultRiskPolicy.decide(&f, risk);
                assert_eq!(
                    rec.action, expected,
                    "verdict={verdict:?} band={band:?} risk={risk:?}"
                );
            }
        }
    }

    #[test]
    fn verified_corroborated_is_the_only_path_to_proceed() {
        for risk in ALL_RISK_CLASSES {
            let f = fused(Verdict::Verified, UncertaintyBand::Corroborated, false);
            let rec = DefaultRiskPolicy.decide(&f, risk);
            assert_eq!(rec.action, RecommendationAction::Proceed, "risk={risk:?}");
        }
    }

    #[test]
    fn verified_qualified_never_proceeds_under_any_risk_class() {
        for risk in ALL_RISK_CLASSES {
            let f = fused(Verdict::Verified, UncertaintyBand::Qualified, false);
            let rec = DefaultRiskPolicy.decide(&f, risk);
            assert_ne!(rec.action, RecommendationAction::Proceed, "risk={risk:?}");
            assert_eq!(rec.action, RecommendationAction::Review, "risk={risk:?}");
        }
    }

    #[test]
    fn verified_conflicted_never_proceeds_defensively() {
        for risk in ALL_RISK_CLASSES {
            let f = fused(Verdict::Verified, UncertaintyBand::Conflicted, false);
            let rec = DefaultRiskPolicy.decide(&f, risk);
            assert_ne!(rec.action, RecommendationAction::Proceed, "risk={risk:?}");
        }
    }

    #[test]
    fn contradicted_never_proceeds_under_any_risk_class_or_band() {
        for risk in ALL_RISK_CLASSES {
            for band in ALL_BANDS {
                let f = fused(Verdict::Contradicted, band, false);
                let rec = DefaultRiskPolicy.decide(&f, risk);
                assert_ne!(
                    rec.action,
                    RecommendationAction::Proceed,
                    "risk={risk:?} band={band:?}"
                );
            }
        }
    }

    #[test]
    fn contradicted_qualified_differs_between_strict_and_balanced() {
        let f = fused(Verdict::Contradicted, UncertaintyBand::Qualified, false);
        let strict = DefaultRiskPolicy.decide(&f, RiskClass::Strict);
        let balanced = DefaultRiskPolicy.decide(&f, RiskClass::Balanced);
        assert_eq!(strict.action, RecommendationAction::Block);
        assert_eq!(balanced.action, RecommendationAction::Review);
        assert_ne!(strict.action, balanced.action);
    }

    #[test]
    fn unverified_never_proceeds_under_the_default_balanced_class() {
        for band in ALL_BANDS {
            let f = fused(Verdict::Unverified, band, false);
            let rec = DefaultRiskPolicy.decide(&f, RiskClass::Balanced);
            assert_ne!(rec.action, RecommendationAction::Proceed, "band={band:?}");
        }
    }

    #[test]
    fn unverified_never_proceeds_under_any_risk_class() {
        for risk in ALL_RISK_CLASSES {
            for band in ALL_BANDS {
                let f = fused(Verdict::Unverified, band, false);
                let rec = DefaultRiskPolicy.decide(&f, risk);
                assert_ne!(
                    rec.action,
                    RecommendationAction::Proceed,
                    "risk={risk:?} band={band:?}"
                );
            }
        }
    }

    #[test]
    fn unverified_strict_and_balanced_differ() {
        let f = fused(Verdict::Unverified, UncertaintyBand::Undetermined, false);
        let strict = DefaultRiskPolicy.decide(&f, RiskClass::Strict);
        let balanced = DefaultRiskPolicy.decide(&f, RiskClass::Balanced);
        assert_eq!(strict.action, RecommendationAction::Block);
        assert_eq!(balanced.action, RecommendationAction::Review);
        assert_ne!(strict.action, balanced.action);
    }

    #[test]
    fn unavailable_never_proceeds_under_any_risk_class() {
        for risk in ALL_RISK_CLASSES {
            for band in ALL_BANDS {
                let f = fused(Verdict::Unavailable, band, false);
                let rec = DefaultRiskPolicy.decide(&f, risk);
                assert_ne!(
                    rec.action,
                    RecommendationAction::Proceed,
                    "risk={risk:?} band={band:?}"
                );
            }
        }
    }

    #[test]
    fn conflicted_unresolved_case_never_proceeds_under_any_tested_risk_class() {
        // Verdict::Review, produced by unresolved_conflict=true --
        // BaselineFusionPolicy's actual conflict path.
        for risk in ALL_RISK_CLASSES {
            let f = fused(Verdict::Review, UncertaintyBand::Conflicted, true);
            let rec = DefaultRiskPolicy.decide(&f, risk);
            assert_ne!(rec.action, RecommendationAction::Proceed, "risk={risk:?}");
            assert_eq!(rec.action, RecommendationAction::Block, "risk={risk:?}");
        }
    }

    // --- Same finding, different risk context, different action -----------

    #[test]
    fn same_fused_finding_yields_different_actions_under_different_risk_classes() {
        let f = fused(Verdict::Contradicted, UncertaintyBand::Corroborated, false);
        let strict = DefaultRiskPolicy.decide(&f, RiskClass::Strict);
        let lenient = DefaultRiskPolicy.decide(&f, RiskClass::Lenient);
        assert_ne!(
            strict.action, lenient.action,
            "same FusedFinding under two risk classes must be able to diverge"
        );
        // The underlying finding itself is never touched by decide().
        assert_eq!(strict.claim_id, f.claim_id);
        assert_eq!(lenient.claim_id, f.claim_id);
    }

    // --- Recommendation always points back at, never replaces, the finding

    #[test]
    fn recommendation_never_embeds_fusion_rationale_only_points_to_the_claim() {
        let f = fused(Verdict::Verified, UncertaintyBand::Corroborated, false);
        let rec = DefaultRiskPolicy.decide(&f, RiskClass::Balanced);
        assert_eq!(rec.claim_id, f.claim_id);
        // Serializing a Recommendation alone never carries a `rationale`
        // array field the way FusedFinding does -- the full rationale is
        // only reachable via claim_id -> the FusedFinding itself.
        let json = serde_json::to_value(&rec).unwrap();
        assert!(json.get("rationale").is_none());
        assert!(json.get("claim_id").is_some());
    }

    #[test]
    fn decision_policy_name_and_version_are_distinct_from_fusion_policy_identity() {
        let f = fused(Verdict::Verified, UncertaintyBand::Corroborated, false);
        assert_eq!(f.policy_name, "deterministic_baseline_v1");
        let rec = DefaultRiskPolicy.decide(&f, RiskClass::Balanced);
        assert_eq!(rec.policy_name, "default_risk_policy_v1");
        assert_ne!(rec.policy_name, f.policy_name);
    }
}
