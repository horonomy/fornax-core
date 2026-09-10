//! Fail-closed expiry and clock-skew semantics (FORNX-350 AC4): "a stale/
//! expired receipt cannot silently pass a time-sensitive downstream gate
//! under default policy."
//!
//! **No revocation service.** Real-time revocation requires network
//! infrastructure that does not exist on this codebase's local-first
//! critical path (ADR-0001 D2). `docs/adr/0009-policy-revocation-and-emergency-control.md`'s
//! existing revocation mechanism is a *signed list imported from a file*,
//! not a live service -- this module does not attempt to build a stub
//! seam for one. Freshness here is scoped to what is honestly buildable
//! offline: a declared expiry (`not_after`) plus clock-skew tolerance.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::schema::ReceiptBody;

pub const DEFAULT_RECEIPT_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Same shape/value as `fornax_types::policy::bundle`'s own clock-skew
/// tolerance -- a receipt issued slightly "in the future" by a clock a few
/// minutes ahead of the verifier's own clock should not be rejected
/// outright.
pub const RECEIPT_CLOCK_SKEW_TOLERANCE_SECONDS: i64 = 300;

/// A receipt's freshness state relative to `now`. `NoExpiryDeclared` is its
/// own state, not folded into `Fresh` -- an absent `not_after` is not
/// "fresh forever", it is "nothing was declared to check against", and the
/// default gate policy (see [`crate::gate`]) treats the two differently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    Fresh {
        not_after: String,
    },
    Expired {
        not_after: String,
        now: String,
    },
    /// `not_after` is absent from the receipt body.
    NoExpiryDeclared,
    /// `issued_at` is after `now` by more than the clock-skew tolerance --
    /// a receipt cannot be authenticated from the future.
    IssuedInFuture {
        issued_at: String,
        now: String,
    },
    MalformedTimestamp {
        field: &'static str,
        value: String,
    },
}

/// Assesses `body`'s freshness against `now`. Pure -- `now` is always
/// caller-supplied.
pub fn assess_freshness(body: &ReceiptBody, now: DateTime<Utc>) -> Freshness {
    let issued_at: DateTime<Utc> = match body.issued_at.parse() {
        Ok(t) => t,
        Err(_) => {
            return Freshness::MalformedTimestamp {
                field: "issued_at",
                value: body.issued_at.clone(),
            }
        }
    };

    if issued_at > now + Duration::seconds(RECEIPT_CLOCK_SKEW_TOLERANCE_SECONDS) {
        return Freshness::IssuedInFuture {
            issued_at: body.issued_at.clone(),
            now: now.to_rfc3339(),
        };
    }

    let Some(not_after_str) = body.not_after.as_ref() else {
        return Freshness::NoExpiryDeclared;
    };
    let not_after: DateTime<Utc> = match not_after_str.parse() {
        Ok(t) => t,
        Err(_) => {
            return Freshness::MalformedTimestamp {
                field: "not_after",
                value: not_after_str.clone(),
            }
        }
    };

    if now > not_after + Duration::seconds(RECEIPT_CLOCK_SKEW_TOLERANCE_SECONDS) {
        Freshness::Expired {
            not_after: not_after_str.clone(),
            now: now.to_rfc3339(),
        }
    } else {
        Freshness::Fresh {
            not_after: not_after_str.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        ClaimRef, CoverageSummary, EmbedPolicy, FindingSummary, RecommendationSummary,
    };
    use fornax_verify::decision::{RecommendationAction, RiskClass};
    use fornax_verify::fusion::UncertaintyBand;
    use uuid::Uuid;

    fn body(issued_at: &str, not_after: Option<&str>) -> ReceiptBody {
        ReceiptBody {
            receipt_schema_version: 1,
            receipt_id: Uuid::nil(),
            issuer: "test".to_string(),
            home_identity: "abcd".to_string(),
            issued_at: issued_at.to_string(),
            not_after: not_after.map(str::to_string),
            embed_policy: EmbedPolicy::ReferenceOnly,
            claim: ClaimRef {
                claim_id: Uuid::nil(),
                session_id: "s1".to_string(),
                subject: "command_succeeded".to_string(),
                claim_text_fingerprint: "deadbeef".to_string(),
                claimed_at: issued_at.to_string(),
            },
            finding: FindingSummary {
                verdict: fornax_types::Verdict::Verified,
                uncertainty: UncertaintyBand::Qualified,
                unresolved_conflict: false,
                counted_link_count: 0,
                discounted_link_count: 0,
                fired_rules: vec![],
                fusion_policy_name: "baseline".to_string(),
                fusion_policy_version: 2,
                computed_at: issued_at.to_string(),
            },
            recommendation: RecommendationSummary {
                action: RecommendationAction::Proceed,
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

    fn t(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn a_receipt_within_its_declared_window_is_fresh() {
        let b = body("2026-01-01T00:00:00Z", Some("2026-01-02T00:00:00Z"));
        assert_eq!(
            assess_freshness(&b, t("2026-01-01T12:00:00Z")),
            Freshness::Fresh {
                not_after: "2026-01-02T00:00:00Z".to_string()
            }
        );
    }

    #[test]
    fn a_receipt_past_its_declared_window_is_expired() {
        let b = body("2026-01-01T00:00:00Z", Some("2026-01-02T00:00:00Z"));
        let freshness = assess_freshness(&b, t("2026-01-03T00:00:00Z"));
        assert!(matches!(freshness, Freshness::Expired { .. }));
    }

    #[test]
    fn a_receipt_with_no_declared_expiry_is_its_own_state_not_fresh_forever() {
        let b = body("2026-01-01T00:00:00Z", None);
        assert_eq!(
            assess_freshness(&b, t("2026-01-01T00:00:01Z")),
            Freshness::NoExpiryDeclared
        );
    }

    #[test]
    fn a_receipt_issued_far_in_the_future_is_rejected() {
        let b = body("2026-01-02T00:00:00Z", Some("2026-01-03T00:00:00Z"));
        let freshness = assess_freshness(&b, t("2026-01-01T00:00:00Z"));
        assert!(matches!(freshness, Freshness::IssuedInFuture { .. }));
    }

    #[test]
    fn clock_skew_within_tolerance_issued_in_future_is_not_rejected() {
        let b = body("2026-01-01T00:04:00Z", Some("2026-01-02T00:00:00Z"));
        let freshness = assess_freshness(&b, t("2026-01-01T00:00:00Z"));
        assert!(!matches!(freshness, Freshness::IssuedInFuture { .. }));
    }

    #[test]
    fn expiry_within_skew_tolerance_is_still_fresh() {
        let b = body("2026-01-01T00:00:00Z", Some("2026-01-02T00:00:00Z"));
        // 2 minutes past not_after, well within the 5-minute tolerance.
        let freshness = assess_freshness(&b, t("2026-01-02T00:02:00Z"));
        assert!(matches!(freshness, Freshness::Fresh { .. }));
    }

    #[test]
    fn a_malformed_timestamp_is_reported_never_silently_treated_as_fresh() {
        let mut b = body("2026-01-01T00:00:00Z", Some("placeholder"));
        b.not_after = Some("not-a-timestamp".to_string());
        let freshness = assess_freshness(&b, t("2026-01-01T00:00:00Z"));
        assert!(matches!(
            freshness,
            Freshness::MalformedTimestamp {
                field: "not_after",
                ..
            }
        ));
    }
}
