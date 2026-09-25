//! Reference consumer for the Agent Evidence Protocol (FORNX-391 AC2/AC1).
//!
//! **This crate is the "second independent implementation" the ticket
//! asks for.** It depends on nothing else in this workspace -- not
//! `fornax-types`, not `fornax-verify`, not `fornax-receipt`, not even
//! `fornax-protocol` itself (see its `Cargo.toml`). Every type and every
//! byte of logic here is written fresh against
//! `docs/protocol/agent-evidence-protocol.md`'s published wire
//! specification, the same document an external, unrelated implementation
//! would work from. If this crate can verify a message
//! `fornax-protocol` produced, using only that public specification, AC1
//! ("independently implementable from public material") and AC2 ("two
//! independent implementations successfully exchange and verify") are both
//! demonstrated by construction, not by assertion.
//!
//! It deliberately re-implements the same canonical-JSON digest scheme
//! `fornax_protocol::canonical` documents (recursively sort object keys,
//! no whitespace) -- see [`canonical_json_digest`] -- rather than importing
//! it, and only inspects the wire JSON structurally (via `serde_json::Value`),
//! never by deserializing into the producer's Rust types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Independently re-derived from the spec, not shared code -- see module
/// docs. Must match `fornax_protocol::envelope::SUPPORTED_PROTOCOL_VERSIONS`
/// exactly for interop to work; this is a real coordination point a
/// published spec exists to solve.
pub const SUPPORTED_PROTOCOL_VERSIONS: std::ops::RangeInclusive<u32> = 1..=1;

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize(v)))
                .collect();
            let mut out = serde_json::Map::new();
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// See `fornax_protocol::canonical::canonical_json_digest`'s doc comment
/// for why this exact scheme (recursive key sort, no shared code) is the
/// protocol's own interoperable digest.
pub fn canonical_json_digest(value: &Value) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(&canonicalize(value))
        .expect("canonicalized value serialization cannot fail");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// The minimal wire shape this reference client understands -- deliberately
/// not the producer's `ProtocolEnvelope` type (this crate has no dependency
/// that would let it use that type), a fresh struct written against the
/// spec.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WireEnvelope {
    pub protocol_version: u32,
    pub object_kind: String,
    pub object_schema_version: u32,
    pub issued_at: String,
    #[serde(default)]
    pub not_after: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub payload: Value,
    pub payload_digest: String,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Malformed(String),
    UnsupportedProtocolVersion(u32),
    PayloadDigestMismatch,
    UnrecognizedObjectKind(String),
    MissingExpectedField(&'static str),
}

/// A structural verdict this independent consumer reached, without ever
/// linking against the producer's own Rust types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelegationSummary {
    pub outcome: String,
    pub parent_agent_id: String,
    pub child_agent_id: String,
}

/// Verifies `bytes` as a delegation-result envelope, using only this
/// crate's own independent parsing/digest logic. Returns a minimal
/// structural summary -- enough to prove genuine understanding of the wire
/// shape (parent/child identity, outcome) without depending on any of the
/// producer's internal types.
pub fn verify_delegation_result_bytes(
    bytes: &[u8],
) -> Result<VerifiedDelegationSummary, VerifyError> {
    let envelope: WireEnvelope =
        serde_json::from_slice(bytes).map_err(|e| VerifyError::Malformed(e.to_string()))?;

    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&envelope.protocol_version) {
        return Err(VerifyError::UnsupportedProtocolVersion(
            envelope.protocol_version,
        ));
    }
    if envelope.object_kind != "delegation_result" {
        return Err(VerifyError::UnrecognizedObjectKind(envelope.object_kind));
    }

    let recomputed = canonical_json_digest(&envelope.payload);
    if recomputed != envelope.payload_digest {
        return Err(VerifyError::PayloadDigestMismatch);
    }

    let body = envelope
        .payload
        .get("body")
        .ok_or(VerifyError::MissingExpectedField("payload.body"))?;
    let outcome = body
        .get("outcome")
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingExpectedField("payload.body.outcome"))?
        .to_string();
    let parent_agent_id = body
        .get("parent")
        .and_then(|p| p.get("agent_id"))
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingExpectedField(
            "payload.body.parent.agent_id",
        ))?
        .to_string();
    let child_agent_id = body
        .get("child")
        .and_then(|c| c.get("agent_id"))
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingExpectedField(
            "payload.body.child.agent_id",
        ))?
        .to_string();

    Ok(VerifiedDelegationSummary {
        outcome,
        parent_agent_id,
        child_agent_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_bytes(payload: Value) -> Vec<u8> {
        let digest = canonical_json_digest(&payload);
        let env = json!({
            "protocol_version": 1,
            "object_kind": "delegation_result",
            "object_schema_version": 1,
            "issued_at": "2026-09-25T00:00:00Z",
            "capabilities": [],
            "payload": payload,
            "payload_digest": digest,
        });
        serde_json::to_vec(&env).unwrap()
    }

    fn sample_payload() -> Value {
        json!({
            "body": {
                "outcome": "fulfilled",
                "parent": {"agent_id": "agent-a", "task_id": "00000000-0000-0000-0000-000000000001"},
                "child": {"agent_id": "agent-b", "task_id": "00000000-0000-0000-0000-000000000002"},
            },
            "digest": "sha256:irrelevant-to-this-independent-check",
        })
    }

    #[test]
    fn verifies_a_well_formed_envelope_without_any_shared_code() {
        let bytes = sample_bytes(sample_payload());
        let summary = verify_delegation_result_bytes(&bytes).expect("must verify");
        assert_eq!(summary.outcome, "fulfilled");
        assert_eq!(summary.parent_agent_id, "agent-a");
        assert_eq!(summary.child_agent_id, "agent-b");
    }

    #[test]
    fn rejects_a_tampered_payload() {
        let mut bytes_json: Value =
            serde_json::from_slice(&sample_bytes(sample_payload())).unwrap();
        bytes_json["payload"]["body"]["outcome"] = json!("forged");
        let bytes = serde_json::to_vec(&bytes_json).unwrap();
        assert_eq!(
            verify_delegation_result_bytes(&bytes),
            Err(VerifyError::PayloadDigestMismatch)
        );
    }

    #[test]
    fn rejects_an_unsupported_protocol_version() {
        let mut bytes_json: Value =
            serde_json::from_slice(&sample_bytes(sample_payload())).unwrap();
        bytes_json["protocol_version"] = json!(42);
        let bytes = serde_json::to_vec(&bytes_json).unwrap();
        assert_eq!(
            verify_delegation_result_bytes(&bytes),
            Err(VerifyError::UnsupportedProtocolVersion(42))
        );
    }

    #[test]
    fn rejects_malformed_bytes_without_panicking() {
        let result = verify_delegation_result_bytes(b"not json");
        assert!(matches!(result, Err(VerifyError::Malformed(_))));
    }

    #[test]
    fn canonical_digest_matches_regardless_of_key_order() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(canonical_json_digest(&a), canonical_json_digest(&b));
    }
}
