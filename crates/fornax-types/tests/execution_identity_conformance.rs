//! Runs the Host-owned execution identity conformance vectors
//! (`horonomy/.github` `governance/product/execution-identity-conformance-vectors.json`,
//! vendored beside this file; see `fixtures/PROVENANCE.md`) against Fornax's
//! own implementation in `fornax_types::execution_identity` (FORNX-466 AC5).

use fornax_types::execution_identity::{
    native_identity, ExecutionIdentity, Scope, ENVELOPE_VERSION,
};
use serde_json::Value;

fn vectors() -> Value {
    let raw = include_str!("fixtures/execution-identity-conformance-vectors.json");
    serde_json::from_str(raw).expect("vectors are valid JSON")
}

fn list<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} is an array"))
}

#[test]
fn vectors_version_is_the_one_this_implementation_targets() {
    let v = vectors();
    assert_eq!(v["vectors_version"], 1);
    assert_eq!(ENVELOPE_VERSION, 1);
    // Anti-vacuity: a truncated or emptied vectors file must fail loudly
    // rather than let every loop below pass over nothing.
    assert_eq!(list(&v, "valid").len(), 16);
    assert_eq!(list(&v, "invalid").len(), 12);
    assert_eq!(list(&v, "correlations").len(), 8);
    assert_eq!(list(&v, "normalizers").len(), 10);
}

#[test]
fn every_valid_envelope_parses_round_trips_and_keys_exactly() {
    let v = vectors();
    for case in list(&v, "valid") {
        let name = case["name"].as_str().unwrap();
        let identity = ExecutionIdentity::from_wire(&case["wire"])
            .unwrap_or_else(|e| panic!("{name}: must parse: {e}"));
        let expect = &case["expect"];

        assert_eq!(
            identity.to_wire(),
            expect["round_trip"],
            "{name}: round trip"
        );

        for (scope, label) in [
            (Scope::Host, "host"),
            (Scope::Session, "session"),
            (Scope::Agent, "agent"),
            (Scope::TurnTask, "turn_task"),
            (Scope::ProjectWorktree, "project_worktree"),
        ] {
            let got = identity
                .cache_key(scope)
                .map(|k| serde_json::json!(k))
                .unwrap_or(Value::Null);
            assert_eq!(
                got, expect["cache_keys"][label],
                "{name}: cache_key({label})"
            );
        }

        assert_eq!(
            identity.narrowest_attributable_scope().as_str(),
            expect["narrowest_attributable_scope"].as_str().unwrap(),
            "{name}: narrowest scope"
        );

        let ids = expect["display_ids"].as_object().unwrap();
        for (dimension, want) in ids {
            assert_eq!(
                identity.display_id(dimension).unwrap(),
                want.as_str().unwrap(),
                "{name}: display_id({dimension})"
            );
        }
    }
}

#[test]
fn every_invalid_envelope_is_refused() {
    let v = vectors();
    for case in list(&v, "invalid") {
        let name = case["name"].as_str().unwrap();
        assert!(
            ExecutionIdentity::from_wire(&case["wire"]).is_err(),
            "{name}: must be refused"
        );
    }
}

#[test]
fn correlations_match_including_unknown_never_matching_unknown() {
    let v = vectors();
    let valid = list(&v, "valid");
    let find = |name: &str| {
        let case = valid
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("no valid vector named {name}"));
        ExecutionIdentity::from_wire(&case["wire"]).unwrap()
    };
    for case in list(&v, "correlations") {
        let name = case["name"].as_str().unwrap();
        let left = find(case["left"].as_str().unwrap());
        let right = find(case["right"].as_str().unwrap());
        assert_eq!(
            left.correlates_with(&right),
            case["expect"]["correlates"].as_bool().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn normalizers_read_only_authentic_native_fields() {
    let v = vectors();
    for case in list(&v, "normalizers") {
        let name = case["name"].as_str().unwrap();
        let provider = case["provider"].as_str().unwrap();
        let native = native_identity(provider, &case["payload"]);
        let expect = &case["expect"];

        let as_opt = |v: &Value| v.as_str().map(str::to_string);
        assert_eq!(
            native.provider_session_id,
            as_opt(&expect["provider_session_id"]),
            "{name}: session"
        );
        assert_eq!(
            native.agent_id,
            as_opt(&expect["agent_id"]),
            "{name}: agent"
        );
        assert_eq!(native.turn_id, as_opt(&expect["turn_id"]), "{name}: turn");

        let envelope = native
            .into_envelope(
                provider,
                case["host_id"].as_str().unwrap(),
                "2026-10-24T12:00:00.000Z",
            )
            .unwrap_or_else(|e| panic!("{name}: envelope: {e}"));
        assert_eq!(
            envelope.lineage_status.as_str(),
            expect["lineage_status"].as_str().unwrap()
        );
        assert_eq!(
            envelope.narrowest_attributable_scope().as_str(),
            expect["narrowest_attributable_scope"].as_str().unwrap(),
            "{name}: narrowest scope"
        );
    }
}

#[test]
fn an_unmapped_provider_is_unattributed_not_guessed() {
    let payload = serde_json::json!({"session_id": "s-1", "agent_id": "a-1", "turn_id": "t-1"});
    let native = native_identity("open_code", &payload);
    assert_eq!(native, Default::default());
}
