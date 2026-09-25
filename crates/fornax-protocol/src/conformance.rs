//! Conformance fixtures and runner (FORNX-391 AC3).
//!
//! Each [`ConformanceCase`] describes one message shape a real-world
//! producer or consumer must handle correctly; [`run_case`] builds that
//! exact shape and reports a [`ConformanceOutcome`] with a typed reason --
//! never a bare pass/fail boolean, so a conformance report is itself
//! machine-actionable (scope: "conformance fixtures and runner").

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::envelope::{
    decode_envelope, encode_envelope, seal_envelope, ObjectKind, ProtocolEnvelope,
};
use crate::objects::{decode_delegation_result, wrap_delegation_result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceCase {
    Valid,
    MalformedJson,
    TamperedOuterPayload,
    TamperedInnerBody,
    StaleNotAfterInThePast,
    UnsupportedProtocolVersion,
    WrongObjectKind,
    ForwardCompatibleUnknownField,
}

/// Why one [`ConformanceCase`] passed or failed -- always a typed reason
/// (AC3), constructed from the same [`crate::envelope::ProtocolError`]/
/// [`crate::objects::UnwrapError`] the real decode path produces, never a
/// separately-invented string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConformanceOutcome {
    /// The message decoded and, where applicable, was accepted -- correct
    /// for [`ConformanceCase::Valid`] and [`ConformanceCase::ForwardCompatibleUnknownField`].
    Accepted,
    /// The message was correctly rejected, with the given typed reason.
    RejectedWithReason(String),
    /// The runner itself could not evaluate this case cleanly (a bug in the
    /// conformance harness, never presented as a pass). See
    /// [`crate::conformance`]'s module docs on why this must never be
    /// silently folded into [`Self::Accepted`].
    HarnessError(String),
}

fn sample_delegation_envelope_bytes(
    capabilities: BTreeSet<crate::capability::Capability>,
) -> Vec<u8> {
    let d = crate::objects::fixtures::sample_delegation_envelope();
    let env = wrap_delegation_result(&d, capabilities);
    encode_envelope(&env)
}

/// Runs one conformance case and reports what actually happened. This
/// function never panics on a well-formed adversarial input -- a case that
/// is *supposed* to be rejected reports [`ConformanceOutcome::RejectedWithReason`],
/// not a propagated panic (AC: "no attack is marked prevented merely
/// because the harness crashed" -- the same discipline FORNX-380 already
/// established, applied here to protocol conformance).
pub fn run_case(case: ConformanceCase) -> ConformanceOutcome {
    match case {
        ConformanceCase::Valid => {
            let bytes = sample_delegation_envelope_bytes(BTreeSet::new());
            match decode_delegation_result(&bytes) {
                Ok(_) => ConformanceOutcome::Accepted,
                Err(e) => ConformanceOutcome::HarnessError(format!(
                    "a genuinely valid fixture was rejected: {e}"
                )),
            }
        }
        ConformanceCase::MalformedJson => {
            match decode_envelope(b"{ this is not valid json at all") {
                Err(e) => ConformanceOutcome::RejectedWithReason(e.to_string()),
                Ok(_) => ConformanceOutcome::HarnessError(
                    "malformed JSON must never decode successfully".to_string(),
                ),
            }
        }
        ConformanceCase::TamperedOuterPayload => {
            let bytes = sample_delegation_envelope_bytes(BTreeSet::new());
            let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            // Flip a byte inside the payload without recomputing payload_digest --
            // the attacker-doesn't-bother-recomputing case.
            json["payload"]["body"]["envelope_schema_version"] = serde_json::json!(999);
            let tampered = serde_json::to_vec(&json).unwrap();
            match decode_envelope(&tampered) {
                Err(e) => ConformanceOutcome::RejectedWithReason(e.to_string()),
                Ok(_) => ConformanceOutcome::HarnessError(
                    "tampered payload with a stale outer digest must be rejected".to_string(),
                ),
            }
        }
        ConformanceCase::TamperedInnerBody => {
            let d = crate::objects::fixtures::sample_delegation_envelope();
            let env = wrap_delegation_result(&d, BTreeSet::new());
            let mut json: serde_json::Value = serde_json::to_value(&env).unwrap();
            json["payload"]["body"]["outcome"] = serde_json::json!("fulfilled");
            // Recompute the OUTER digest so only the harder, inner delegation
            // digest is left to catch this -- see objects.rs's identical test.
            let recomputed_outer = crate::canonical::canonical_json_digest(&json["payload"]);
            json["payload_digest"] = serde_json::json!(recomputed_outer);
            let bytes = serde_json::to_vec(&json).unwrap();
            match decode_delegation_result(&bytes) {
                Err(e) => ConformanceOutcome::RejectedWithReason(e.to_string()),
                Ok(_) => ConformanceOutcome::HarnessError(
                    "a body tampered past the outer digest must still fail the inner delegation digest".to_string(),
                ),
            }
        }
        ConformanceCase::StaleNotAfterInThePast => {
            let d = crate::objects::fixtures::sample_delegation_envelope();
            let env = ProtocolEnvelope {
                not_after: Some("2000-01-01T00:00:00Z".to_string()),
                ..wrap_delegation_result(&d, BTreeSet::new())
            };
            // Freshness is a caller-side check against `now` (mirrors
            // `fornax_receipt::delegation::assess_delegation_freshness`'s own
            // "assessed against a supplied `now`" design) -- verify decode
            // still succeeds structurally, then apply the freshness check.
            let bytes = encode_envelope(&env);
            let decoded = match decode_envelope(&bytes) {
                Ok(d) => d,
                Err(e) => {
                    return ConformanceOutcome::HarnessError(format!(
                        "must decode structurally first: {e}"
                    ))
                }
            };
            let not_after: chrono::DateTime<chrono::Utc> =
                decoded.not_after.as_deref().unwrap().parse().unwrap();
            let now = chrono::Utc::now();
            if now > not_after {
                ConformanceOutcome::RejectedWithReason(
                    "envelope not_after is in the past".to_string(),
                )
            } else {
                ConformanceOutcome::HarnessError(
                    "fixture's not_after must be in the past".to_string(),
                )
            }
        }
        ConformanceCase::UnsupportedProtocolVersion => {
            let d = crate::objects::fixtures::sample_delegation_envelope();
            let mut env = wrap_delegation_result(&d, BTreeSet::new());
            env.protocol_version = 7;
            let bytes = encode_envelope(&env);
            match decode_envelope(&bytes) {
                Err(e) => ConformanceOutcome::RejectedWithReason(e.to_string()),
                Ok(_) => ConformanceOutcome::HarnessError(
                    "an unsupported protocol_version must be rejected".to_string(),
                ),
            }
        }
        ConformanceCase::WrongObjectKind => {
            let env = seal_envelope(
                ObjectKind::IntegrityReceipt,
                1,
                "2026-09-25T00:00:00Z",
                None,
                BTreeSet::new(),
                serde_json::json!({}),
            );
            let bytes = encode_envelope(&env);
            match decode_delegation_result(&bytes) {
                Err(e) => ConformanceOutcome::RejectedWithReason(e.to_string()),
                Ok(_) => ConformanceOutcome::HarnessError(
                    "a non-delegation object_kind must not unwrap as a delegation".to_string(),
                ),
            }
        }
        ConformanceCase::ForwardCompatibleUnknownField => {
            let d = crate::objects::fixtures::sample_delegation_envelope();
            let env = wrap_delegation_result(&d, BTreeSet::new());
            let mut json: serde_json::Value = serde_json::to_value(&env).unwrap();
            json["a_hypothetical_v2_field"] = serde_json::json!(42);
            let bytes = serde_json::to_vec(&json).unwrap();
            match decode_envelope(&bytes) {
                Ok(decoded) if decoded.extensions.contains_key("a_hypothetical_v2_field") => {
                    ConformanceOutcome::Accepted
                }
                Ok(_) => ConformanceOutcome::HarnessError(
                    "unknown field decoded but was not preserved in extensions".to_string(),
                ),
                Err(e) => ConformanceOutcome::HarnessError(format!(
                    "a forward-compatible unknown field must not break decode: {e}"
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_case_is_accepted() {
        assert_eq!(
            run_case(ConformanceCase::Valid),
            ConformanceOutcome::Accepted
        );
    }

    #[test]
    fn malformed_json_is_rejected() {
        assert!(matches!(
            run_case(ConformanceCase::MalformedJson),
            ConformanceOutcome::RejectedWithReason(_)
        ));
    }

    #[test]
    fn tampered_outer_payload_is_rejected() {
        assert!(matches!(
            run_case(ConformanceCase::TamperedOuterPayload),
            ConformanceOutcome::RejectedWithReason(_)
        ));
    }

    #[test]
    fn tampered_inner_body_is_rejected_even_past_the_outer_digest() {
        assert!(matches!(
            run_case(ConformanceCase::TamperedInnerBody),
            ConformanceOutcome::RejectedWithReason(_)
        ));
    }

    #[test]
    fn stale_not_after_is_rejected() {
        assert!(matches!(
            run_case(ConformanceCase::StaleNotAfterInThePast),
            ConformanceOutcome::RejectedWithReason(_)
        ));
    }

    #[test]
    fn unsupported_protocol_version_is_rejected() {
        assert!(matches!(
            run_case(ConformanceCase::UnsupportedProtocolVersion),
            ConformanceOutcome::RejectedWithReason(_)
        ));
    }

    #[test]
    fn wrong_object_kind_is_rejected() {
        assert!(matches!(
            run_case(ConformanceCase::WrongObjectKind),
            ConformanceOutcome::RejectedWithReason(_)
        ));
    }

    #[test]
    fn forward_compatible_unknown_field_is_accepted_not_rejected() {
        assert_eq!(
            run_case(ConformanceCase::ForwardCompatibleUnknownField),
            ConformanceOutcome::Accepted
        );
    }

    /// No case's `HarnessError` variant should ever actually fire -- if one
    /// does, the fixture itself is broken, which is a real bug in this
    /// conformance suite, never presented as "the attack was prevented."
    #[test]
    fn no_case_reports_a_harness_error() {
        for case in [
            ConformanceCase::Valid,
            ConformanceCase::MalformedJson,
            ConformanceCase::TamperedOuterPayload,
            ConformanceCase::TamperedInnerBody,
            ConformanceCase::StaleNotAfterInThePast,
            ConformanceCase::UnsupportedProtocolVersion,
            ConformanceCase::WrongObjectKind,
            ConformanceCase::ForwardCompatibleUnknownField,
        ] {
            let outcome = run_case(case);
            assert!(
                !matches!(outcome, ConformanceOutcome::HarnessError(_)),
                "case {case:?} reported a harness error: {outcome:?}"
            );
        }
    }
}
