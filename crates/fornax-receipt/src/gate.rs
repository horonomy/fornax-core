//! The fail-closed receipt gate (FORNX-350 AC5): "at least one real CI/
//! GitHub/deployment-style consumer accepts a valid receipt and rejects/
//! holds an invalid, stale or policy-insufficient receipt."
//!
//! This is its own, third verdict vocabulary -- distinct from
//! [`fornax_types::Verdict`] (what was observed about the claim) and
//! [`fornax_verify::decision::RecommendationAction`] (what Fornax itself
//! recommends doing about it). [`GateOutcome`] answers a narrower question:
//! may *this receipt* authorize *this downstream pipeline step* to
//! proceed? Mirrors `fornax_bench::gate`'s identical three-vocabulary
//! discipline for the regression lab.
//!
//! # The one real trap this module exists to get right
//!
//! A [`ReceiptGatePolicy`] with `calibrated: false` (or with both
//! `allowed_verdicts` and `allowed_actions` empty) must resolve to
//! [`GateOutcome::Untested`], never [`GateOutcome::Accept`]. The naive
//! `checks.iter().all(|c| c.passes())` is vacuously `true` over an empty
//! check set -- `evaluate_receipt_gate` checks this explicitly before
//! evaluating a single rule, lifted verbatim from
//! `fornax_bench::gate::evaluate_gate`'s identical trap.
//!
//! # Default policy (FORNX-350 owner decision)
//!
//! [`ReceiptGatePolicy::require_proceed_no_critical_gaps`] blocks by
//! default only on [`EvidenceGapKind::NoEvidenceAtAll`]/
//! [`EvidenceGapKind::UnresolvedConflict`]/[`EvidenceGapKind::AllVotesDiscounted`]
//! -- the gaps judged unambiguously critical. `IndependenceUnverified`/
//! `SingleSourceCorroboration`/`StaleSupport` are reported in the
//! receipt's own `coverage.gaps` but are **not** default blockers: no
//! shipped sensor stamps `correlation_group` yet (FORNX-92), so making
//! `IndependenceUnverified` a default hard blocker would reject nearly
//! every real finding today, turning an evidence-quality signal into an
//! unusable default policy. `require_signature: false` is the honest
//! default given FORNX-350's verification-only scope -- a
//! high-assurance deployment can require it explicitly once it controls
//! its own trust store.

use serde::{Deserialize, Serialize};

use fornax_types::Verdict;
use fornax_verify::decision::RecommendationAction;
use fornax_verify::voi::EvidenceGapKind;

use crate::freshness::{Freshness, DEFAULT_RECEIPT_TTL_SECONDS};
use crate::verify::{SignatureStatus, VerifiedReceipt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOutcome {
    Accept,
    /// A check actively failed: expired, digest/signature mismatch,
    /// disallowed verdict/action, forbidden gap.
    Reject,
    /// Not a detected defect, but insufficient to authorize: unsigned when
    /// a signature is required, no expiry declared when one is required,
    /// calibration not `Valid` when that's required.
    Hold,
    /// The policy itself is uncalibrated or has no rules. Never `Accept`.
    Untested,
}

impl GateOutcome {
    /// Worst-of-many ordering, mirroring `fornax_bench::gate::GateVerdict::severity`:
    /// `Accept` is best, `Reject` is worst.
    fn severity(self) -> u8 {
        match self {
            GateOutcome::Accept => 0,
            GateOutcome::Untested => 1,
            GateOutcome::Hold => 2,
            GateOutcome::Reject => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateReasonCode {
    PolicyUncalibrated,
    SignatureRequiredButAbsent,
    SignatureUnverifiable,
    SignatureRejected,
    ReceiptExpired,
    NoExpiryDeclared,
    IssuedInFuture,
    MalformedTimestamp,
    VerdictNotAllowed,
    RecommendationNotAllowed,
    CriticalEvidenceGap,
    CalibrationNotValid,
    AllChecksSatisfied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReason {
    pub code: GateReasonCode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateDecision {
    pub outcome: GateOutcome,
    pub reasons: Vec<GateReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptGatePolicy {
    /// `false` (this crate's own default fixture value) resolves the whole
    /// gate to [`GateOutcome::Untested`] before any rule below is
    /// evaluated -- see module docs.
    pub calibrated: bool,
    pub policy_name: String,
    pub policy_version: u32,
    pub require_signature: bool,
    pub allowed_verdicts: Vec<Verdict>,
    pub allowed_actions: Vec<RecommendationAction>,
    pub forbidden_gap_kinds: Vec<EvidenceGapKindWire>,
    pub require_expiry: bool,
    pub max_age_seconds: Option<i64>,
    pub require_calibration_valid: bool,
}

/// [`EvidenceGapKind`] has payload-carrying variants
/// (`ExpectedSignalMissing { signal_class }`); a policy only ever needs to
/// name the *kind*, never a specific signal class, so this wire enum names
/// just the discriminants a policy can list. `matches_kind` is the only
/// place the mapping is defined, so it can never drift from
/// [`EvidenceGapKind`]'s real variants without a compile error forcing an
/// update here too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGapKindWire {
    NoEvidenceAtAll,
    ExpectedSignalMissing,
    SignalClassUnobservable,
    AllVotesDiscounted,
    StaleSupport,
    IndependenceUnverified,
    SingleSourceCorroboration,
    UnresolvedConflict,
}

impl EvidenceGapKindWire {
    fn matches(self, kind: &EvidenceGapKind) -> bool {
        matches!(
            (self, kind),
            (Self::NoEvidenceAtAll, EvidenceGapKind::NoEvidenceAtAll)
                | (
                    Self::ExpectedSignalMissing,
                    EvidenceGapKind::ExpectedSignalMissing { .. }
                )
                | (
                    Self::SignalClassUnobservable,
                    EvidenceGapKind::SignalClassUnobservable { .. }
                )
                | (
                    Self::AllVotesDiscounted,
                    EvidenceGapKind::AllVotesDiscounted
                )
                | (Self::StaleSupport, EvidenceGapKind::StaleSupport)
                | (
                    Self::IndependenceUnverified,
                    EvidenceGapKind::IndependenceUnverified
                )
                | (
                    Self::SingleSourceCorroboration,
                    EvidenceGapKind::SingleSourceCorroboration
                )
                | (
                    Self::UnresolvedConflict,
                    EvidenceGapKind::UnresolvedConflict
                )
        )
    }
}

impl ReceiptGatePolicy {
    /// FORNX-350's own named policy: "require PROCEED + no critical
    /// missing evidence." See module docs for the exact default
    /// blocker/non-blocker gap split (owner decision).
    pub fn require_proceed_no_critical_gaps() -> Self {
        Self {
            calibrated: true,
            policy_name: "require_proceed_no_critical_gaps".to_string(),
            policy_version: 1,
            require_signature: false,
            allowed_verdicts: vec![Verdict::Verified],
            allowed_actions: vec![RecommendationAction::Proceed],
            forbidden_gap_kinds: vec![
                EvidenceGapKindWire::NoEvidenceAtAll,
                EvidenceGapKindWire::UnresolvedConflict,
                EvidenceGapKindWire::AllVotesDiscounted,
            ],
            require_expiry: true,
            max_age_seconds: Some(DEFAULT_RECEIPT_TTL_SECONDS),
            require_calibration_valid: false,
        }
    }
}

/// Evaluates `verified` against `policy`. See module docs for the
/// fail-closed empty/uncalibrated-policy trap this function's very first
/// check exists to avoid. Never short-circuits on the first failing
/// check -- every reason is collected, and the overall outcome is the
/// worst of them, matching `docs/release-assurance-policy.md`'s "a gate's
/// overall verdict is the worst of its constituent check verdicts" rule
/// (already reused verbatim by `fornax_bench::gate`).
pub fn evaluate_receipt_gate(
    verified: &VerifiedReceipt,
    policy: &ReceiptGatePolicy,
) -> GateDecision {
    if !policy.calibrated
        || (policy.allowed_verdicts.is_empty() && policy.allowed_actions.is_empty())
    {
        return GateDecision {
            outcome: GateOutcome::Untested,
            reasons: vec![GateReason {
                code: GateReasonCode::PolicyUncalibrated,
                detail: "receipt gate policy is not calibrated (or names no allowed verdicts/actions) \
                         -- no threshold exists yet to judge this receipt against, and an empty check \
                         set must never silently resolve to Accept"
                    .to_string(),
            }],
        };
    }

    let mut reasons = Vec::new();
    let body = verified.receipt().body();

    match verified.signature() {
        SignatureStatus::Unsigned if policy.require_signature => {
            reasons.push(GateReason {
                code: GateReasonCode::SignatureRequiredButAbsent,
                detail: "policy requires a signature; this receipt is unsigned".to_string(),
            });
        }
        SignatureStatus::Unverifiable { reason } if policy.require_signature => {
            reasons.push(GateReason {
                code: GateReasonCode::SignatureUnverifiable,
                detail: reason.clone(),
            });
        }
        SignatureStatus::Rejected { rejection } => {
            reasons.push(GateReason {
                code: GateReasonCode::SignatureRejected,
                detail: rejection.clone(),
            });
        }
        _ => {}
    }

    match verified.freshness() {
        Freshness::Expired { not_after, now } => reasons.push(GateReason {
            code: GateReasonCode::ReceiptExpired,
            detail: format!("expired at {not_after}, now {now}"),
        }),
        Freshness::NoExpiryDeclared if policy.require_expiry => reasons.push(GateReason {
            code: GateReasonCode::NoExpiryDeclared,
            detail: "policy requires a declared expiry; this receipt has none".to_string(),
        }),
        Freshness::IssuedInFuture { issued_at, now } => reasons.push(GateReason {
            code: GateReasonCode::IssuedInFuture,
            detail: format!("issued_at {issued_at} is after now {now}"),
        }),
        Freshness::MalformedTimestamp { field, value } => reasons.push(GateReason {
            code: GateReasonCode::MalformedTimestamp,
            detail: format!("{field} is malformed: {value:?}"),
        }),
        _ => {}
    }

    if let Some(max_age) = policy.max_age_seconds {
        if let (Ok(issued), Some(not_after_ok)) = (
            body.issued_at.parse::<chrono::DateTime<chrono::Utc>>(),
            body.not_after
                .as_ref()
                .and_then(|s| s.parse::<chrono::DateTime<chrono::Utc>>().ok()),
        ) {
            let declared_age = (not_after_ok - issued).num_seconds();
            if declared_age > max_age {
                reasons.push(GateReason {
                    code: GateReasonCode::ReceiptExpired,
                    detail: format!(
                        "declared TTL {declared_age}s exceeds policy max_age_seconds {max_age}"
                    ),
                });
            }
        }
    }

    if !policy.allowed_verdicts.is_empty()
        && !policy.allowed_verdicts.contains(&body.finding.verdict)
    {
        reasons.push(GateReason {
            code: GateReasonCode::VerdictNotAllowed,
            detail: format!(
                "verdict {:?} is not in the allowed set {:?}",
                body.finding.verdict, policy.allowed_verdicts
            ),
        });
    }

    if !policy.allowed_actions.is_empty()
        && !policy.allowed_actions.contains(&body.recommendation.action)
    {
        reasons.push(GateReason {
            code: GateReasonCode::RecommendationNotAllowed,
            detail: format!(
                "action {:?} is not in the allowed set {:?}",
                body.recommendation.action, policy.allowed_actions
            ),
        });
    }

    for gap in &body.coverage.gaps {
        if policy
            .forbidden_gap_kinds
            .iter()
            .any(|forbidden| forbidden.matches(&gap.kind))
        {
            reasons.push(GateReason {
                code: GateReasonCode::CriticalEvidenceGap,
                detail: format!("{:?}: {}", gap.kind, gap.detail),
            });
        }
    }

    if policy.require_calibration_valid
        && body.calibration.state != fornax_verify::calibration::CalibrationState::Valid
    {
        reasons.push(GateReason {
            code: GateReasonCode::CalibrationNotValid,
            detail: format!(
                "calibration state is {:?}, not Valid",
                body.calibration.state
            ),
        });
    }

    if reasons.is_empty() {
        return GateDecision {
            outcome: GateOutcome::Accept,
            reasons: vec![GateReason {
                code: GateReasonCode::AllChecksSatisfied,
                detail: format!("all checks satisfied under policy {:?}", policy.policy_name),
            }],
        };
    }

    let worst = reasons
        .iter()
        .map(|r| outcome_of(&r.code))
        .max_by_key(|o| o.severity())
        .unwrap_or(GateOutcome::Reject);

    GateDecision {
        outcome: worst,
        reasons,
    }
}

fn outcome_of(code: &GateReasonCode) -> GateOutcome {
    match code {
        GateReasonCode::SignatureRequiredButAbsent
        | GateReasonCode::SignatureUnverifiable
        | GateReasonCode::NoExpiryDeclared => GateOutcome::Hold,
        GateReasonCode::AllChecksSatisfied | GateReasonCode::PolicyUncalibrated => {
            unreachable!("handled by their own early-return branches")
        }
        _ => GateOutcome::Reject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        ClaimRef, CoverageSummary, EmbedPolicy, FindingSummary, IntegrityReceipt, ReceiptBody,
        ReceiptGap, RecommendationSummary,
    };
    use crate::verify::SignatureStatus;
    use fornax_verify::decision::RiskClass;
    use fornax_verify::fusion::UncertaintyBand;
    use uuid::Uuid;

    fn body(
        verdict: Verdict,
        action: RecommendationAction,
        not_after: Option<&str>,
    ) -> ReceiptBody {
        ReceiptBody {
            receipt_schema_version: 1,
            receipt_id: Uuid::nil(),
            issuer: "test".to_string(),
            home_identity: "abcd".to_string(),
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            not_after: not_after.map(str::to_string),
            embed_policy: EmbedPolicy::ReferenceOnly,
            claim: ClaimRef {
                claim_id: Uuid::nil(),
                session_id: "s1".to_string(),
                subject: "command_succeeded".to_string(),
                claim_text_fingerprint: "deadbeef".to_string(),
                claimed_at: "2026-01-01T00:00:00Z".to_string(),
            },
            finding: FindingSummary {
                verdict,
                uncertainty: UncertaintyBand::Qualified,
                unresolved_conflict: false,
                counted_link_count: 1,
                discounted_link_count: 0,
                fired_rules: vec![],
                fusion_policy_name: "baseline".to_string(),
                fusion_policy_version: 2,
                computed_at: "2026-01-01T00:00:00Z".to_string(),
            },
            recommendation: RecommendationSummary {
                action,
                risk_class: RiskClass::Balanced,
                decision_policy_name: "default".to_string(),
                decision_policy_version: 1,
            },
            coverage: CoverageSummary {
                evidence_root: "sha256:abc".to_string(),
                referenced_evidence: vec![],
                missing_evidence: vec![],
                gaps: vec![],
                source_family_bases: vec![],
                withheld: vec![],
            },
            provenance: fornax_types::calibration::CalibrationProvenance {
                schema_version: 1,
                provider: "claude_code".to_string(),
                adapter_version: None,
                capability_schema_version: 1,
                capability_fingerprint: vec![],
                fusion_policy_name: "baseline".to_string(),
                fusion_policy_version: 2,
                decision_policy_name: "default".to_string(),
                decision_policy_version: 1,
                reliability_policy_version: 1,
                disabled_sensors: vec![],
                active_policy_revision_digest: None,
                model_version: None,
                model_family: None,
            },
            calibration: fornax_verify::calibration::CalibrationAssessment {
                state: fornax_verify::calibration::CalibrationState::NoActiveCalibration,
                policy_version: 1,
            },
        }
    }

    fn verified(
        body: ReceiptBody,
        signature: SignatureStatus,
        freshness: Freshness,
    ) -> VerifiedReceipt {
        let digest = crate::schema::digest_of(&body);
        let receipt = IntegrityReceipt::new_trusted(body, digest);
        crate::verify::VerifiedReceipt::for_test(receipt, signature, freshness)
    }

    #[test]
    fn an_uncalibrated_policy_is_untested_never_accept() {
        let v = verified(
            body(
                Verdict::Verified,
                RecommendationAction::Proceed,
                Some("2026-01-02T00:00:00Z"),
            ),
            SignatureStatus::Unsigned,
            Freshness::Fresh {
                not_after: "2026-01-02T00:00:00Z".to_string(),
            },
        );
        let policy = ReceiptGatePolicy {
            calibrated: false,
            ..ReceiptGatePolicy::require_proceed_no_critical_gaps()
        };
        let decision = evaluate_receipt_gate(&v, &policy);
        assert_eq!(decision.outcome, GateOutcome::Untested);
    }

    #[test]
    fn a_valid_proceed_verdict_with_no_gaps_and_fresh_expiry_is_accepted() {
        let v = verified(
            body(
                Verdict::Verified,
                RecommendationAction::Proceed,
                Some("2026-01-02T00:00:00Z"),
            ),
            SignatureStatus::Unsigned,
            Freshness::Fresh {
                not_after: "2026-01-02T00:00:00Z".to_string(),
            },
        );
        let policy = ReceiptGatePolicy::require_proceed_no_critical_gaps();
        let decision = evaluate_receipt_gate(&v, &policy);
        assert_eq!(decision.outcome, GateOutcome::Accept);
    }

    #[test]
    fn an_expired_receipt_is_rejected() {
        let v = verified(
            body(
                Verdict::Verified,
                RecommendationAction::Proceed,
                Some("2026-01-01T00:00:00Z"),
            ),
            SignatureStatus::Unsigned,
            Freshness::Expired {
                not_after: "2026-01-01T00:00:00Z".to_string(),
                now: "2026-01-03T00:00:00Z".to_string(),
            },
        );
        let policy = ReceiptGatePolicy::require_proceed_no_critical_gaps();
        let decision = evaluate_receipt_gate(&v, &policy);
        assert_eq!(decision.outcome, GateOutcome::Reject);
    }

    #[test]
    fn no_declared_expiry_is_a_hold_under_the_default_require_expiry_policy() {
        let v = verified(
            body(Verdict::Verified, RecommendationAction::Proceed, None),
            SignatureStatus::Unsigned,
            Freshness::NoExpiryDeclared,
        );
        let policy = ReceiptGatePolicy::require_proceed_no_critical_gaps();
        let decision = evaluate_receipt_gate(&v, &policy);
        assert_eq!(decision.outcome, GateOutcome::Hold);
    }

    #[test]
    fn a_disallowed_action_is_rejected() {
        let v = verified(
            body(
                Verdict::Verified,
                RecommendationAction::Review,
                Some("2026-01-02T00:00:00Z"),
            ),
            SignatureStatus::Unsigned,
            Freshness::Fresh {
                not_after: "2026-01-02T00:00:00Z".to_string(),
            },
        );
        let policy = ReceiptGatePolicy::require_proceed_no_critical_gaps();
        let decision = evaluate_receipt_gate(&v, &policy);
        assert_eq!(decision.outcome, GateOutcome::Reject);
    }

    #[test]
    fn independence_unverified_is_reported_but_never_a_default_blocker() {
        let mut b = body(
            Verdict::Verified,
            RecommendationAction::Proceed,
            Some("2026-01-02T00:00:00Z"),
        );
        b.coverage.gaps.push(ReceiptGap {
            kind: fornax_verify::voi::EvidenceGapKind::IndependenceUnverified,
            detail: "no correlation_group recorded".to_string(),
        });
        let v = verified(
            b,
            SignatureStatus::Unsigned,
            Freshness::Fresh {
                not_after: "2026-01-02T00:00:00Z".to_string(),
            },
        );
        let policy = ReceiptGatePolicy::require_proceed_no_critical_gaps();
        let decision = evaluate_receipt_gate(&v, &policy);
        assert_eq!(
            decision.outcome,
            GateOutcome::Accept,
            "IndependenceUnverified must not be a default blocker: {decision:?}"
        );
    }

    #[test]
    fn no_evidence_at_all_is_a_default_blocker() {
        let mut b = body(
            Verdict::Verified,
            RecommendationAction::Proceed,
            Some("2026-01-02T00:00:00Z"),
        );
        b.coverage.gaps.push(ReceiptGap {
            kind: fornax_verify::voi::EvidenceGapKind::NoEvidenceAtAll,
            detail: "nobody looked".to_string(),
        });
        let v = verified(
            b,
            SignatureStatus::Unsigned,
            Freshness::Fresh {
                not_after: "2026-01-02T00:00:00Z".to_string(),
            },
        );
        let policy = ReceiptGatePolicy::require_proceed_no_critical_gaps();
        let decision = evaluate_receipt_gate(&v, &policy);
        assert_eq!(decision.outcome, GateOutcome::Reject);
    }
}
