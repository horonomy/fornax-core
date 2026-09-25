//! Canonical JSON serialization for the Agent Evidence Protocol's own wire
//! digest (FORNX-391 AC1).
//!
//! **Why this exists, distinct from every internal digest in this repo.**
//! [`fornax_receipt::schema::digest_of`] and
//! [`fornax_receipt::delegation::digest_of`] compute a digest over
//! `serde_json::to_vec(&typed_struct)` -- deterministic *within this Rust
//! codebase* because serde's derive macro serializes fields in declaration
//! order. That is fine for an internal tamper check between two copies of
//! the same Rust type, but it is **not** independently reproducible by an
//! external implementation that has never seen `DelegationEnvelopeBody`'s
//! Rust field order -- a second implementation deserializing the payload
//! into a generic JSON value and re-serializing it would, in general, get a
//! *different* byte sequence (map key order is not part of the JSON data
//! model), and would then reject every genuine, unaltered message as
//! "tampered." A real interoperability protocol cannot depend on one
//! language's struct layout.
//!
//! This module defines the protocol's own canonical form instead: object
//! keys sorted lexicographically at every nesting level, no insignificant
//! whitespace, numbers and strings passed through as JSON already
//! represents them. Any implementation that recursively sorts object keys
//! before serializing gets byte-identical output, regardless of what
//! order the keys arrived in. [`crates/fornax-protocol-refclient`] contains
//! a second, independent implementation of exactly this function -- see its
//! module docs -- so [`canonical_json_digest`] is provably reproducible
//! without sharing code.

use serde_json::Value;

/// Recursively rewrites `value` so every object's keys are sorted, using a
/// `BTreeMap` (whose iteration order *is* sorted, unlike `serde_json`'s
/// default map when the `preserve_order` feature is off -- relying on that
/// implicitly would be fragile; this makes the sort explicit and immune to
/// a future feature-flag change in either implementation).
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

/// The canonical wire bytes of `value` -- object keys sorted recursively,
/// no whitespace. Two calls with structurally-equal but differently-ordered
/// input produce byte-identical output.
pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(&canonicalize(value)).expect("canonicalized Value serialization cannot fail")
}

/// `"sha256:<hex>"` over [`canonical_json_bytes`] -- the protocol's own
/// interoperable content digest, independent of struct field order.
pub fn canonical_json_digest(value: &Value) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_json_bytes(value)))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_affect_the_digest() {
        let a = json!({"b": 1, "a": 2, "c": {"z": 1, "y": 2}});
        let b = json!({"a": 2, "c": {"y": 2, "z": 1}, "b": 1});
        assert_eq!(canonical_json_digest(&a), canonical_json_digest(&b));
    }

    #[test]
    fn a_changed_value_changes_the_digest() {
        let a = json!({"a": 1});
        let b = json!({"a": 2});
        assert_ne!(canonical_json_digest(&a), canonical_json_digest(&b));
    }

    #[test]
    fn nested_arrays_of_objects_are_canonicalized_recursively() {
        let a = json!({"list": [{"b": 1, "a": 2}]});
        let b = json!({"list": [{"a": 2, "b": 1}]});
        assert_eq!(canonical_json_digest(&a), canonical_json_digest(&b));
    }
}
