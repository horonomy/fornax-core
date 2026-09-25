//! FORNX-391 AC2: "two independent implementations successfully exchange
//! and verify a representative proof-carrying delegation/result."
//!
//! This test is the literal proof. `fornax-protocol` is the producer (it
//! depends on `fornax-types`/`fornax-verify`/`fornax-receipt`).
//! `fornax-protocol-refclient` is the consumer -- see its `Cargo.toml`: it
//! depends on nothing in this workspace, and its `lib.rs` reimplements the
//! canonical digest scheme from scratch rather than importing
//! `fornax_protocol::canonical`. The only thing connecting them is the
//! published wire bytes and `docs/protocol/agent-evidence-protocol.md`.

use std::collections::BTreeSet;

#[test]
fn producer_and_independent_refclient_agree_on_a_valid_delegation_result() {
    // Producer side: build a real DelegationEnvelope through this repo's
    // own contract-satisfaction pipeline, wrap it in a protocol envelope.
    let delegation = fornax_protocol::objects::fixtures::sample_delegation_envelope();
    let envelope = fornax_protocol::objects::wrap_delegation_result(&delegation, BTreeSet::new());
    let bytes = fornax_protocol::envelope::encode_envelope(&envelope);

    // Consumer side: fornax-protocol-refclient, which has never seen a
    // DelegationEnvelope Rust type or fornax_protocol::canonical's source.
    let summary = fornax_protocol_refclient::verify_delegation_result_bytes(&bytes)
        .expect("the independent reference client must verify a genuinely valid message");

    assert_eq!(summary.parent_agent_id, "agent-a");
    assert_eq!(summary.child_agent_id, "agent-b");
    // The outcome is whatever `assess()` genuinely produced against zero
    // evidence -- both sides must agree on it without either one telling
    // the other what to expect.
    let producer_outcome = format!("{:?}", delegation.body().outcome);
    let producer_outcome_wire = match delegation.body().outcome {
        fornax_receipt::delegation::DelegationOutcome::Fulfilled => "fulfilled",
        fornax_receipt::delegation::DelegationOutcome::PartiallyFulfilled => "partially_fulfilled",
        fornax_receipt::delegation::DelegationOutcome::Insufficient => "insufficient",
        fornax_receipt::delegation::DelegationOutcome::Unavailable => "unavailable",
    };
    assert_eq!(
        summary.outcome, producer_outcome_wire,
        "producer outcome ({producer_outcome}) and independently-parsed wire outcome must agree"
    );
}

#[test]
fn independent_refclient_rejects_a_tampered_message_the_producer_never_sent() {
    let delegation = fornax_protocol::objects::fixtures::sample_delegation_envelope();
    let envelope = fornax_protocol::objects::wrap_delegation_result(&delegation, BTreeSet::new());
    let bytes = fornax_protocol::envelope::encode_envelope(&envelope);

    let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["payload"]["body"]["outcome"] = serde_json::json!("fulfilled");
    let tampered = serde_json::to_vec(&json).unwrap();

    let result = fornax_protocol_refclient::verify_delegation_result_bytes(&tampered);
    assert!(
        result.is_err(),
        "the independent client must reject a payload it did not compute the digest for itself"
    );
}

/// Threat model claim ("unsafe remote reference resolution"): this
/// protocol version's wire shape carries no fetchable remote reference at
/// all. Structural proof over the real wire JSON, not just a doc claim --
/// walks the whole serialized envelope for any key shaped like a URL/href.
#[test]
fn no_protocol_type_carries_a_url_shaped_field() {
    fn assert_no_url_shaped_keys(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let lower = k.to_lowercase();
                    assert!(
                        !lower.contains("url") && !lower.contains("href") && !lower.contains("endpoint"),
                        "found a URL/href/endpoint-shaped key '{k}' at {path} -- the protocol must carry no fetchable remote reference"
                    );
                    assert_no_url_shaped_keys(v, &format!("{path}.{k}"));
                }
            }
            serde_json::Value::Array(items) => {
                for (i, v) in items.iter().enumerate() {
                    assert_no_url_shaped_keys(v, &format!("{path}[{i}]"));
                }
            }
            _ => {}
        }
    }

    let delegation = fornax_protocol::objects::fixtures::sample_delegation_envelope();
    let envelope = fornax_protocol::objects::wrap_delegation_result(&delegation, BTreeSet::new());
    let json = serde_json::to_value(&envelope).unwrap();
    assert_no_url_shaped_keys(&json, "$");
}
