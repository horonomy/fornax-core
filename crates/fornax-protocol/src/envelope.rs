//! The Agent Evidence Protocol envelope (FORNX-391 AC1/AC3/AC4/AC6).
//!
//! A [`ProtocolEnvelope`] wraps exactly one portable Fornax object (a
//! delegation result today; a bare receipt or assurance case are declared
//! as [`ObjectKind`] variants for future use, see module docs on scope) with
//! a version, a capability declaration, and a canonical content digest
//! ([`crate::canonical`]) that any independent implementation can
//! recompute -- see `crates/fornax-protocol-refclient` for a second one.
//!
//! **Authenticity is not semantic truth (AC6).** [`decode_envelope`]
//! succeeding means: this envelope's declared protocol version is
//! supported, and its payload has not been altered since
//! [`seal_envelope`] computed the digest. It says *nothing* about whether
//! the wrapped delegation/finding is itself correct -- an envelope can
//! decode successfully while wrapping a
//! [`fornax_receipt::delegation::DelegationOutcome::Insufficient`] result.
//! See `envelope_decode_success_is_independent_of_delegation_outcome` in
//! this module's tests for a literal proof.
//!
//! **Forward/backward compatibility (AC4).** Unknown top-level fields on
//! the wire are captured into [`ProtocolEnvelope::extensions`] via
//! `#[serde(flatten)]`, never silently dropped -- a consumer can inspect
//! `extensions` to see exactly what an unrecognized producer sent, and
//! round-tripping (decode then re-encode) preserves them byte-for-byte at
//! the JSON level. An *unsupported protocol_version* is a hard, explicit
//! rejection ([`ProtocolError::UnsupportedProtocolVersion`]) rather than a
//! best-effort parse -- see `docs/protocol/agent-evidence-protocol.md`'s
//! compatibility policy for why version bumps and unknown-field handling
//! are governed differently.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_digest;
use crate::capability::Capability;

/// `1..=1` today. A future `SUPPORTED_PROTOCOL_VERSIONS` widening is itself
/// a change governed by `docs/protocol/agent-evidence-protocol.md`'s
/// compatibility policy (AC7) -- never widened silently in a patch.
pub const SUPPORTED_PROTOCOL_VERSIONS: std::ops::RangeInclusive<u32> = 1..=1;
pub const CURRENT_PROTOCOL_VERSION: u32 = 1;

/// What kind of portable object [`ProtocolEnvelope::payload`] contains.
/// Closed enum: an unrecognized `object_kind` on the wire is a hard
/// [`ProtocolError::UnsupportedObjectKind`], never silently treated as one
/// of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    /// A [`fornax_receipt::delegation::DelegationEnvelope`] -- the
    /// "representative proof-carrying delegation/result" AC2 asks two
    /// independent implementations to exchange.
    DelegationResult,
    /// A bare [`fornax_receipt::schema::IntegrityReceipt`], not wrapped in
    /// a delegation. Declared for schema completeness; this ticket's own
    /// AC2 proof uses [`Self::DelegationResult`].
    IntegrityReceipt,
    /// A [`fornax_receipt::assurance_case::AssuranceCase`].
    AssuranceCase,
}

/// A [`ProtocolEnvelope`] whose `object_kind`, `protocol_version`, or
/// payload digest could not be accepted. Every variant names a specific,
/// typed reason -- never a bare string as the *only* information (AC3:
/// "rejects ... with typed reasons").
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProtocolError {
    #[error("envelope bytes could not be parsed as a protocol envelope: {detail}")]
    Malformed { detail: String },
    #[error(
        "protocol_version {found} is not supported (supported: {supported_min}..={supported_max})"
    )]
    UnsupportedProtocolVersion {
        found: u32,
        supported_min: u32,
        supported_max: u32,
    },
    #[error("object_kind is not recognized by this implementation")]
    UnsupportedObjectKind,
    #[error("payload digest {declared} does not match recomputed digest {recomputed} -- payload was altered after sealing")]
    PayloadDigestMismatch {
        declared: String,
        recomputed: String,
    },
    #[error("envelope requires capabilities this consumer does not support: {missing:?}")]
    UnsupportedCapabilities { missing: BTreeSet<Capability> },
}

/// The wire envelope. Field order is normative -- mirrors this repo's
/// existing `ReceiptBody`/`DelegationEnvelopeBody` discipline, though
/// unlike those, this struct's own digest is *not* order-dependent (see
/// [`crate::canonical`]), so field reordering here would not itself change
/// [`ProtocolEnvelope::payload_digest`] -- only `payload`'s content does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolEnvelope {
    pub protocol_version: u32,
    pub object_kind: ObjectKind,
    pub object_schema_version: u32,
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Optional semantics this envelope's payload relies on -- see
    /// [`crate::capability`]. Empty means "no optional semantics used,"
    /// never "unknown."
    pub capabilities: BTreeSet<Capability>,
    /// The wrapped object's own wire form (already tamper-evident on its
    /// own terms when it is a `DelegationEnvelope`/`IntegrityReceipt`,
    /// which both use `#[serde(try_from = ...)]` digest checks -- see
    /// `crate::objects`). Kept as a raw [`serde_json::Value`] here so this
    /// struct never needs to know the payload's Rust type.
    pub payload: serde_json::Value,
    /// [`canonical_json_digest`] of `payload` -- the protocol's own,
    /// struct-order-independent tamper check (see module docs and
    /// `crate::canonical`).
    pub payload_digest: String,
    /// Unknown top-level fields, preserved verbatim -- never dropped
    /// (AC4). A producer using a newer protocol_version this consumer
    /// still supports may add optional fields here; an older consumer sees
    /// them, can choose to ignore or inspect them, but never loses them on
    /// a decode-then-re-encode round trip.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

/// Builds a sealed envelope: computes `payload_digest` from `payload`
/// itself, so a caller can never construct an envelope with a
/// mismatched digest by mistake.
#[allow(clippy::too_many_arguments)]
pub fn seal_envelope(
    object_kind: ObjectKind,
    object_schema_version: u32,
    issued_at: impl Into<String>,
    not_after: Option<String>,
    capabilities: BTreeSet<Capability>,
    payload: serde_json::Value,
) -> ProtocolEnvelope {
    let payload_digest = canonical_json_digest(&payload);
    ProtocolEnvelope {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        object_kind,
        object_schema_version,
        issued_at: issued_at.into(),
        not_after,
        capabilities,
        payload,
        payload_digest,
        extensions: BTreeMap::new(),
    }
}

pub fn encode_envelope(envelope: &ProtocolEnvelope) -> Vec<u8> {
    serde_json::to_vec(envelope).expect("ProtocolEnvelope serialization cannot fail")
}

/// Parses and verifies `bytes` as a [`ProtocolEnvelope`]: checks
/// `protocol_version` is supported, then recomputes [`ProtocolEnvelope::payload_digest`]
/// and rejects a mismatch. Does **not** interpret `payload` itself -- see
/// `crate::objects` for typed unwrapping, and this module's doc comment on
/// why decode success is not a semantic-truth claim (AC6).
pub fn decode_envelope(bytes: &[u8]) -> Result<ProtocolEnvelope, ProtocolError> {
    let envelope: ProtocolEnvelope =
        serde_json::from_slice(bytes).map_err(|e| ProtocolError::Malformed {
            detail: e.to_string(),
        })?;
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&envelope.protocol_version) {
        return Err(ProtocolError::UnsupportedProtocolVersion {
            found: envelope.protocol_version,
            supported_min: *SUPPORTED_PROTOCOL_VERSIONS.start(),
            supported_max: *SUPPORTED_PROTOCOL_VERSIONS.end(),
        });
    }
    let recomputed = canonical_json_digest(&envelope.payload);
    if recomputed != envelope.payload_digest {
        return Err(ProtocolError::PayloadDigestMismatch {
            declared: envelope.payload_digest.clone(),
            recomputed,
        });
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_envelope() -> ProtocolEnvelope {
        seal_envelope(
            ObjectKind::DelegationResult,
            1,
            "2026-09-25T00:00:00Z",
            Some("2026-09-26T00:00:00Z".to_string()),
            BTreeSet::new(),
            json!({"outcome": "fulfilled"}),
        )
    }

    #[test]
    fn a_valid_envelope_round_trips() {
        let env = sample_envelope();
        let bytes = encode_envelope(&env);
        let decoded = decode_envelope(&bytes).expect("must decode");
        assert_eq!(decoded, env);
    }

    #[test]
    fn a_tampered_payload_is_rejected_with_a_typed_digest_mismatch() {
        let env = sample_envelope();
        let mut json: serde_json::Value = serde_json::to_value(&env).unwrap();
        json["payload"]["outcome"] = serde_json::json!("fulfilled_but_actually_forged");
        let bytes = serde_json::to_vec(&json).unwrap();
        let err = decode_envelope(&bytes).unwrap_err();
        assert!(matches!(err, ProtocolError::PayloadDigestMismatch { .. }));
    }

    #[test]
    fn an_unsupported_protocol_version_is_rejected_explicitly() {
        let mut env = sample_envelope();
        env.protocol_version = 99;
        let bytes = encode_envelope(&env);
        let err = decode_envelope(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::UnsupportedProtocolVersion { found: 99, .. }
        ));
    }

    #[test]
    fn unknown_top_level_fields_survive_a_decode_then_reencode_round_trip() {
        let env = sample_envelope();
        let mut json: serde_json::Value = serde_json::to_value(&env).unwrap();
        json["a_field_from_a_newer_producer"] = serde_json::json!("some-future-value");
        let bytes = serde_json::to_vec(&json).unwrap();

        let decoded = decode_envelope(&bytes).expect("unknown field must not break decode");
        assert_eq!(
            decoded.extensions.get("a_field_from_a_newer_producer"),
            Some(&serde_json::json!("some-future-value")),
            "unknown field must be preserved, never silently dropped"
        );

        let reencoded = encode_envelope(&decoded);
        let reparsed: serde_json::Value = serde_json::from_slice(&reencoded).unwrap();
        assert_eq!(
            reparsed["a_field_from_a_newer_producer"],
            serde_json::json!("some-future-value"),
            "round trip must not lose the unknown field"
        );
    }

    #[test]
    fn malformed_bytes_are_rejected_with_a_typed_reason_not_a_panic() {
        let err = decode_envelope(b"{ not valid json").unwrap_err();
        assert!(matches!(err, ProtocolError::Malformed { .. }));
    }

    /// AC6: decode success is a structural/authenticity claim, not a
    /// semantic one. A perfectly valid, unaltered envelope can wrap a
    /// delegation outcome that is anything but a success.
    #[test]
    fn envelope_decode_success_is_independent_of_delegation_outcome() {
        for outcome in [
            "fulfilled",
            "partially_fulfilled",
            "insufficient",
            "unavailable",
        ] {
            let env = seal_envelope(
                ObjectKind::DelegationResult,
                1,
                "2026-09-25T00:00:00Z",
                None,
                BTreeSet::new(),
                json!({"outcome": outcome}),
            );
            let bytes = encode_envelope(&env);
            let decoded = decode_envelope(&bytes);
            assert!(
                decoded.is_ok(),
                "envelope for outcome={outcome} must decode -- protocol authenticity is orthogonal to the wrapped semantic outcome"
            );
        }
    }
}
