//! Typed wrap/unwrap between [`crate::envelope::ProtocolEnvelope`] and this
//! repo's existing portable wire types (FORNX-391 AC2/AC5).
//!
//! **Wraps, never replaces (scope: "reuse existing public extension
//! boundaries rather than creating a private protocol fork").** A
//! [`fornax_receipt::delegation::DelegationEnvelope`] is already a
//! self-contained, digest-tamper-evident, reference-only wire object
//! (FORNX-384/350's own AC3 guarantee: raw protected evidence is never
//! embedded, only references/fingerprints -- see [`unwrap_delegation_result`]'s
//! doc comment for how AC5 falls out of that for free). This module adds
//! exactly one thing on top: the [`crate::envelope`] version/capability/
//! canonical-digest wrapper that makes the object *portable across
//! independent implementations* (AC1), not just tamper-evident within this
//! Rust codebase.

use fornax_receipt::delegation::{DelegationEnvelope, DELEGATION_SCHEMA_VERSION};

use crate::envelope::{seal_envelope, ObjectKind, ProtocolEnvelope, ProtocolError};

/// Wraps an already-issued [`DelegationEnvelope`] into a
/// [`ProtocolEnvelope`]. `capabilities` must name every optional semantic
/// (see [`crate::capability`]) this specific envelope's contents actually
/// rely on -- the caller's responsibility, since only the caller knows
/// which contract/requirement types were involved.
pub fn wrap_delegation_result(
    envelope: &DelegationEnvelope,
    capabilities: std::collections::BTreeSet<crate::capability::Capability>,
) -> ProtocolEnvelope {
    let payload = serde_json::to_value(envelope)
        .expect("DelegationEnvelope serialization to Value cannot fail");
    seal_envelope(
        ObjectKind::DelegationResult,
        DELEGATION_SCHEMA_VERSION,
        envelope.body().issued_at.clone(),
        envelope.body().not_after.clone(),
        capabilities,
        payload,
    )
}

/// Rejects a [`ProtocolEnvelope`] whose `object_kind`/digest checked out
/// (via [`crate::envelope::decode_envelope`]) but whose payload does not
/// deserialize as a valid [`DelegationEnvelope`] -- e.g. its *inner*,
/// delegation-specific digest (a distinct check from the outer protocol
/// envelope digest -- see module docs) does not match, meaning the payload
/// was forged to pass the protocol-level canonical-JSON digest (by
/// reconstructing valid canonical JSON) but does not satisfy the stricter,
/// Rust-typed `DelegationEnvelope` shape/tamper contract underneath.
#[derive(Debug, Clone, thiserror::Error)]
pub enum UnwrapError {
    #[error("envelope object_kind is {found:?}, expected DelegationResult")]
    WrongObjectKind { found: crate::envelope::ObjectKind },
    #[error("payload does not deserialize as a valid, unaltered DelegationEnvelope: {detail}")]
    InvalidDelegationPayload { detail: String },
}

/// Unwraps `envelope`'s payload into a verified [`DelegationEnvelope`].
/// Two independent tamper checks must both pass: [`crate::envelope::decode_envelope`]'s
/// outer canonical-JSON digest (already checked by the caller before this
/// function runs) and [`DelegationEnvelope`]'s own inner,
/// `#[serde(try_from = ...)]`-enforced digest (FORNX-384) -- this function
/// re-triggers the second one by deserializing into the typed struct.
///
/// **AC5 falls out of this for free.** [`DelegationEnvelope`] never carries
/// a raw evidence payload to begin with (FORNX-350 AC3/FORNX-384's own
/// redaction discipline) -- there is no code path in this function, or in
/// [`wrap_delegation_result`], that could introduce one. A portable message
/// built from this module is exactly as redaction-safe as the internal
/// object it wraps.
pub fn unwrap_delegation_result(
    envelope: &ProtocolEnvelope,
) -> Result<DelegationEnvelope, UnwrapError> {
    if envelope.object_kind != ObjectKind::DelegationResult {
        return Err(UnwrapError::WrongObjectKind {
            found: envelope.object_kind,
        });
    }
    serde_json::from_value(envelope.payload.clone()).map_err(|e| {
        UnwrapError::InvalidDelegationPayload {
            detail: e.to_string(),
        }
    })
}

/// Convenience: decode raw bytes straight to a verified [`DelegationEnvelope`],
/// running both the outer protocol-envelope check and the inner
/// delegation-envelope check. This is the function
/// `crates/fornax-protocol-refclient`'s independent implementation does
/// **not** call -- the whole point of AC2 is that the refclient reaches an
/// equivalent verification result via its own, separately-written code.
pub fn decode_delegation_result(bytes: &[u8]) -> Result<DelegationEnvelope, DecodeDelegationError> {
    let envelope = crate::envelope::decode_envelope(bytes)?;
    let delegation = unwrap_delegation_result(&envelope)?;
    Ok(delegation)
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DecodeDelegationError {
    #[error(transparent)]
    Envelope(#[from] ProtocolError),
    #[error(transparent)]
    Unwrap(#[from] UnwrapError),
}

/// Public and not test-only: [`crate::conformance`]'s runner needs a real
/// fixture outside `cargo test` too (e.g. a future `fornax protocol
/// conformance` CLI), and a downstream, genuinely independent
/// implementation's own test suite needs a way to obtain a real,
/// producer-issued sample message to test against -- see
/// `crates/fornax-protocol/tests/two_independent_implementations.rs`.
///
/// A real, minimal, end-to-end `DelegationEnvelope` built entirely through
/// this repo's own public APIs (`fornax_verify::contract_satisfaction::assess`,
/// `fornax_receipt::delegation::issue_delegation_envelope`) -- no
/// hand-forged internal struct literals standing in for a real assessment.
/// `receipts: vec![]` is a legitimate, real edge case (no evidence was
/// available), not a shortcut around building a full `IntegrityReceipt`;
/// contract satisfaction against zero evidence is exactly what `assess` is
/// designed to report honestly.
pub mod fixtures {
    use uuid::Uuid;

    use fornax_receipt::delegation::{
        issue_delegation_envelope, DelegationEnvelope, DelegationIdentity, DelegationInputs,
    };
    use fornax_types::epistemic_contract::ClaimClassId;
    use fornax_types::Claim;
    use fornax_verify::contract_satisfaction::{assess, default_registry, SatisfactionReport};

    fn claim(subject: &str, claimed_at: &str) -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "session-1".to_string(),
            source_event_id: Uuid::new_v4(),
            text: format!("claim about {subject}"),
            subject: subject.to_string(),
            claimed_at: claimed_at.to_string(),
        }
    }

    pub fn sample_delegation_envelope() -> DelegationEnvelope {
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let c = claim("tests_passed", "2026-09-25T00:10:00Z");
        let report: SatisfactionReport =
            assess(&registry, &cc, &c, &[], &[]).expect("default registry has tests_passed");

        issue_delegation_envelope(
            DelegationInputs {
                parent: DelegationIdentity {
                    agent_id: "agent-a".to_string(),
                    task_id: Uuid::new_v4(),
                },
                child: DelegationIdentity {
                    agent_id: "agent-b".to_string(),
                    task_id: Uuid::new_v4(),
                },
                claim_class: cc,
                permitted_actions_text: "run the test suite",
                expected_outputs_text: "a pass/fail verdict with evidence",
                assessment: &report,
                receipts: vec![],
                lineage: vec![],
                child_reported_unavailable: false,
            },
            "2026-09-25T00:11:00Z",
            Some(3600),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn a_wrapped_delegation_result_round_trips_through_bytes() {
        let d = fixtures::sample_delegation_envelope();
        let env = wrap_delegation_result(&d, BTreeSet::new());
        let bytes = crate::envelope::encode_envelope(&env);
        let decoded = decode_delegation_result(&bytes).expect("must decode");
        assert_eq!(decoded, d);
    }

    /// AC5: raw protected content is not required in a portable message.
    /// `fixtures::sample_delegation_envelope` is built from raw free text
    /// ("run the test suite", "a pass/fail verdict with evidence") that
    /// `issue_delegation_envelope` (FORNX-384) fingerprints before ever
    /// reaching `DelegationEnvelopeBody` -- this test confirms wrapping
    /// that envelope for the wire does not reintroduce it.
    #[test]
    fn wrapping_for_the_wire_never_reintroduces_raw_scope_text() {
        let d = fixtures::sample_delegation_envelope();
        let env = wrap_delegation_result(&d, BTreeSet::new());
        let json = serde_json::to_string(&env).unwrap();
        assert!(
            !json.contains("run the test suite") && !json.contains("a pass/fail verdict"),
            "wrapped envelope must never carry the raw scope text, only its fingerprint"
        );
    }

    #[test]
    fn wrong_object_kind_is_rejected_explicitly() {
        let env = crate::envelope::seal_envelope(
            ObjectKind::IntegrityReceipt,
            1,
            "2026-09-25T00:00:00Z",
            None,
            BTreeSet::new(),
            serde_json::json!({}),
        );
        let err = unwrap_delegation_result(&env).unwrap_err();
        assert!(matches!(err, UnwrapError::WrongObjectKind { .. }));
    }

    #[test]
    fn a_delegation_payload_tampered_after_protocol_sealing_is_caught_by_the_inner_digest() {
        // Simulates an attacker who recomputes the OUTER canonical-JSON
        // digest after editing the payload (defeating envelope::decode_envelope
        // alone would require this) -- the INNER DelegationEnvelope digest
        // (FORNX-384, independent of and stricter than the outer one) still
        // catches it, because it is not merely a JSON-content digest but a
        // `#[serde(try_from)]`-enforced structural contract.
        let d = fixtures::sample_delegation_envelope();
        let mut payload = serde_json::to_value(&d).unwrap();
        payload["body"]["outcome"] = serde_json::json!("fulfilled"); // was e.g. "insufficient"

        let env = crate::envelope::seal_envelope(
            ObjectKind::DelegationResult,
            1,
            d.body().issued_at.clone(),
            d.body().not_after.clone(),
            BTreeSet::new(),
            payload, // outer digest recomputed fresh over the TAMPERED payload -- passes outer check
        );
        let bytes = crate::envelope::encode_envelope(&env);

        // Outer check alone would pass (digest matches its own tampered payload).
        let outer_decoded = crate::envelope::decode_envelope(&bytes);
        assert!(
            outer_decoded.is_ok(),
            "outer digest is self-consistent with the tampered payload"
        );

        // The inner DelegationEnvelope digest must still reject it.
        let result = decode_delegation_result(&bytes);
        assert!(
            result.is_err(),
            "inner delegation digest must catch tampering the outer canonical digest alone cannot"
        );
    }
}
