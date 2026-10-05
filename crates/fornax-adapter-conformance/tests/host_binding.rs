use fornax_adapter_claude::{bind_host_event, HostBindingGapReason, HostBindingOutcome};
use fornax_types::{AgentAdapter, EvidenceKind, IngestMessage, SensorDisableConfig};
use serde_json::{json, Value};

const SESSION: &str = "fixture-claude-session-003";

fn canonical(tool_response: Value) -> Value {
    json!({
        "schema_version": 1,
        "event_id": "opaque-observation-42",
        "observed_at": "2026-10-05T01:02:03Z",
        "adapter_id": "other-claude-adapter",
        "adapter_version": "7.2.1",
        "host_version": "claude-code-2.1.238",
        "source": {
            "kind": "hook",
            "native_event_name": "PostToolUse",
            "native_event_id": "native-event-42",
            "replay_key": "replay-42"
        },
        "capability_snapshot_id": "snapshot-42",
        "identity": {
            "envelope_version": 1,
            "observed_at": "2026-10-05T01:02:03Z",
            "host_id": "host-42",
            "tool_provider": "claude_code",
            "lineage_status": "child",
            "provider_session_id": SESSION,
            "tool_instance_id": "tool-instance-1",
            "agent_id": "agent-1",
            "parent_agent_id": "agent-parent-1",
            "turn_id": "turn-1",
            "session_lineage_id": "lineage-1",
            "event_id": "identity-event-42",
            "custom_identity_extension": "kept"
        },
        "scope": "session",
        "kind": "tool_after",
        "facts": {
            "tool_name": "Bash",
            "native_call_id": "call-42",
            "action_kind": "shell_command",
            "operand_completeness": "complete",
            "operands": {"command": "false"},
            "operands_availability": "observed",
            "result_availability": "observed",
            "result": tool_response
        },
        "quality": "literal",
        "field_provenance": {"facts.result": "claude_hook_tool_response"}
    })
}

#[test]
fn canonical_literal_bash_uses_the_existing_sensor_and_preserves_provenance() {
    let response = json!({"stdout": "", "stderr": "boom", "interrupted": false});
    let decoded = fornax_types::host_event::decode_host_event(
        serde_json::to_vec(&canonical(response.clone()))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let outcome = bind_host_event(&decoded, &SensorDisableConfig::empty());
    let HostBindingOutcome::Bound(bound) = outcome else {
        panic!("expected supported Claude Bash observation");
    };
    assert_eq!(bound.event.session_id, SESSION);
    assert_eq!(bound.event.observed_at, "2026-10-05T01:02:03Z");
    assert_eq!(bound.event.raw, Value::Null);
    assert_eq!(
        bound.provenance.canonical_event.event_id(),
        "opaque-observation-42"
    );
    assert_eq!(
        bound.provenance.canonical_event.adapter_id(),
        "other-claude-adapter"
    );
    assert_eq!(
        bound
            .provenance
            .canonical_event
            .identity()
            .provider_session_id
            .as_deref(),
        Some(SESSION)
    );
    assert_eq!(
        bound
            .provenance
            .canonical_event
            .source()
            .native_event_id
            .as_deref(),
        Some("native-event-42")
    );
    let fornax_types::host_event::HostEventFacts::Tool(facts) =
        bound.provenance.canonical_event.facts()
    else {
        panic!("expected tool observation facts");
    };
    assert_eq!(facts.native_call_id.as_deref(), Some("call-42"));
    assert_eq!(bound.evidence.len(), 1);
    let exit = &bound.evidence[0];
    assert_eq!(exit.kind, EvidenceKind::ExitCode);
    assert_eq!(exit.source_event_id, bound.event.id);
    assert_eq!(exit.session_id, SESSION);
    assert_eq!(
        exit.payload,
        json!({"command": "false", "exit_code": 1, "heuristic": true})
    );
    let source = exit.source.as_ref().unwrap();
    assert_eq!(source.trust_class, fornax_types::TrustClass::AgentAdjacent);
    assert_eq!(
        source.collection_method,
        fornax_types::CollectionMethod::HookCallback
    );
    assert_eq!(
        source.collector_version.as_deref(),
        Some(fornax_adapter_claude::ADAPTER_VERSION)
    );
    assert_eq!(bound.provenance.canonical_event.adapter_version(), "7.2.1");
    let identity = bound.provenance.canonical_event.identity();
    assert_eq!(identity.agent_id.as_deref(), Some("agent-1"));
    assert_eq!(identity.parent_agent_id.as_deref(), Some("agent-parent-1"));
    assert_eq!(identity.turn_id.as_deref(), Some("turn-1"));
    assert_eq!(identity.event_id.as_deref(), Some("identity-event-42"));
    assert_eq!(identity.session_lineage_id.as_deref(), Some("lineage-1"));
    let typed_identity = format!("{identity:?}");
    assert!(!typed_identity.contains("custom_identity_extension"));
    assert!(!typed_identity.contains("kept"));
}

#[test]
fn paired_legacy_normalization_keeps_the_heuristic_interpretation() {
    // Paired with the existing sanitized Claude 2.1.238 Bash fixture.
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/claude/post_tool_use_bash_heuristic_failure.json"
    ))
    .unwrap();
    let native = fixture["native_events"][0].clone();
    let canonical_event = canonical(native["tool_response"].clone());
    let mut adapter = fornax_adapter_claude::ClaudeAdapter;
    let legacy = adapter.normalize("unused", &native);
    let expected = match legacy {
        fornax_types::NormalizationOutcome::Messages(messages) => messages
            .into_iter()
            .find_map(|message| match message {
                IngestMessage::Evidence(evidence) if evidence.kind == EvidenceKind::ExitCode => {
                    Some(evidence)
                }
                _ => None,
            })
            .expect("legacy path must emit Bash exit-code evidence"),
        other => panic!("unexpected legacy normalization: {other:?}"),
    };
    let HostBindingOutcome::Bound(bound) = bind_host_event(
        &fornax_types::host_event::decode_host_event(
            &serde_json::to_vec(&canonical_event).unwrap(),
        )
        .unwrap(),
        &SensorDisableConfig::empty(),
    ) else {
        panic!("expected supported Claude Bash observation");
    };
    assert_eq!(bound.evidence[0].payload, expected.payload);
    assert_eq!(bound.evidence[0].provenance, expected.provenance);
}

#[test]
fn unsupported_and_unsafe_bindings_return_gaps_without_evidence() {
    let mut event = canonical(json!({"stdout": "ok", "stderr": "", "interrupted": false}));
    event["identity"]["tool_provider"] = json!("unknown_runtime");
    let decoded =
        fornax_types::host_event::decode_host_event(&serde_json::to_vec(&event).unwrap()).unwrap();
    assert!(matches!(
        bind_host_event(&decoded, &SensorDisableConfig::empty()),
        HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::ProviderBindingUnavailable
    ));

    event = canonical(json!({"stdout": "ok", "stderr": "", "interrupted": false}));
    event["facts"]["operand_completeness"] = json!("partial");
    event["facts"].as_object_mut().unwrap().remove("operands");
    let decoded =
        fornax_types::host_event::decode_host_event(&serde_json::to_vec(&event).unwrap()).unwrap();
    assert!(matches!(
        bind_host_event(&decoded, &SensorDisableConfig::empty()),
        HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::OperandsUnavailable
    ));

    event["facts"]["action_kind"] = json!("shell_command");
    event["facts"]["operand_completeness"] = json!("unknown");
    let decoded =
        fornax_types::host_event::decode_host_event(&serde_json::to_vec(&event).unwrap()).unwrap();
    assert!(matches!(
        bind_host_event(&decoded, &SensorDisableConfig::empty()),
        HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::OperandsUnavailable
    ));
}

#[test]
fn missing_session_and_unknown_result_shape_never_invent_identity_or_exit_code() {
    let mut event = canonical(json!({"stdout": "ok", "stderr": "", "interrupted": false}));
    event["identity"]
        .as_object_mut()
        .unwrap()
        .remove("provider_session_id");
    let decoded =
        fornax_types::host_event::decode_host_event(&serde_json::to_vec(&event).unwrap()).unwrap();
    assert!(matches!(
        bind_host_event(&decoded, &SensorDisableConfig::empty()),
        HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::SessionIdentityUnavailable
    ));

    event = canonical(json!({"stdout": "ok", "stderr": "", "interrupted": false}));
    event["identity"]["provider_session_id"] = json!("");
    let decoded =
        fornax_types::host_event::decode_host_event(&serde_json::to_vec(&event).unwrap()).unwrap();
    assert!(matches!(
        bind_host_event(&decoded, &SensorDisableConfig::empty()),
        HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::SessionIdentityUnavailable
    ));

    let decoded = fornax_types::host_event::decode_host_event(
        &serde_json::to_vec(&canonical(json!({"mystery": 17}))).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        bind_host_event(&decoded, &SensorDisableConfig::empty()),
        HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::ResultShapeUnavailable
    ));

    let decoded = fornax_types::host_event::decode_host_event(
        &serde_json::to_vec(&canonical(json!({"metadata": {"exit_code": 19}}))).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        bind_host_event(&decoded, &SensorDisableConfig::empty()),
        HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::ResultShapeUnavailable
    ));

    for malformed in [
        json!({"stdout": false}),
        json!({"stdout": null}),
        json!({"stderr": 7}),
        json!({"interrupted": "false"}),
        json!({"exit_code": "0"}),
    ] {
        let decoded = fornax_types::host_event::decode_host_event(
            &serde_json::to_vec(&canonical(malformed)).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            bind_host_event(&decoded, &SensorDisableConfig::empty()),
            HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::ResultShapeUnavailable
        ));
    }

    let mut missing_result = canonical(json!({"stdout": "ok"}));
    missing_result["facts"]["result_availability"] = json!("unavailable");
    missing_result["facts"]
        .as_object_mut()
        .unwrap()
        .remove("result");
    let decoded =
        fornax_types::host_event::decode_host_event(&serde_json::to_vec(&missing_result).unwrap())
            .unwrap();
    assert!(matches!(
        bind_host_event(&decoded, &SensorDisableConfig::empty()),
        HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::ResultUnavailable
    ));
}

#[test]
fn disabled_sensor_emits_no_evidence_and_keeps_the_local_observation() {
    let decoded = fornax_types::host_event::decode_host_event(
        &serde_json::to_vec(&canonical(
            json!({"stdout": "ok", "stderr": "", "interrupted": false}),
        ))
        .unwrap(),
    )
    .unwrap();
    let config = SensorDisableConfig::from_toml_str(
        "[sensors]\ndisabled = [\"claude_bash_exit_code_sensor_v1\"]\n",
    )
    .unwrap();
    let HostBindingOutcome::Bound(bound) = bind_host_event(&decoded, &config) else {
        panic!("valid observation remains locally available when collection is disabled");
    };
    assert!(bound.evidence.is_empty());
    assert_eq!(
        bound.sensor_state,
        fornax_types::SignalAvailability::Disabled
    );
}

#[test]
fn canonical_decoder_rejects_duplicate_keys_size_depth_version_and_bad_lineage() {
    use fornax_types::host_event::{
        decode_host_event, HostEventRejection, MAX_HOST_EVENT_BYTES, MAX_HOST_EVENT_NESTING,
    };

    let encoded = serde_json::to_vec(&canonical(json!({"stdout": "ok", "stderr": ""}))).unwrap();
    let encoded = String::from_utf8(encoded).unwrap();
    let duplicate = encoded.replacen(
        "\"event_id\":\"opaque-observation-42\"",
        "\"event_id\":\"duplicate\",\"event_id\":\"opaque-observation-42\"",
        1,
    );
    assert_eq!(
        decode_host_event(duplicate.as_bytes()).unwrap_err(),
        HostEventRejection::DuplicateKey
    );
    assert_eq!(
        decode_host_event(&vec![b' '; MAX_HOST_EVENT_BYTES + 1]).unwrap_err(),
        HostEventRejection::InputTooLarge
    );
    let nested = format!(
        "{}0{}",
        "[".repeat(MAX_HOST_EVENT_NESTING + 1),
        "]".repeat(MAX_HOST_EVENT_NESTING + 1)
    );
    assert_eq!(
        decode_host_event(nested.as_bytes()).unwrap_err(),
        HostEventRejection::ExcessiveNesting
    );

    let mut event = canonical(json!({"stdout": "ok", "stderr": ""}));
    event["schema_version"] = json!(2);
    assert_eq!(
        decode_host_event(&serde_json::to_vec(&event).unwrap()).unwrap_err(),
        HostEventRejection::ContractViolation
    );
    event = canonical(json!({"stdout": "ok", "stderr": ""}));
    event["identity"]["lineage_status"] = json!("root");
    assert_eq!(
        decode_host_event(&serde_json::to_vec(&event).unwrap()).unwrap_err(),
        HostEventRejection::ContractViolation
    );

    event = canonical(json!({"stdout": "ok", "stderr": ""}));
    event["schema_version"] = json!(1.0);
    event["identity"]["envelope_version"] = json!(1.0);
    assert!(decode_host_event(&serde_json::to_vec(&event).unwrap()).is_ok());

    event = canonical(json!({"stdout": "ok", "stderr": ""}));
    event["facts"]["action_kind"] = json!("shell_command");
    event["facts"]["operand_completeness"] = json!("complete");
    event["facts"].as_object_mut().unwrap().remove("operands");
    assert_eq!(
        decode_host_event(&serde_json::to_vec(&event).unwrap()).unwrap_err(),
        HostEventRejection::ContractViolation
    );
}

#[test]
fn synthetic_explicit_exit_code_still_uses_sensor_parsing() {
    let decoded = fornax_types::host_event::decode_host_event(
        &serde_json::to_vec(&canonical(
            json!({"exit_code": 7, "stdout": "", "stderr": ""}),
        ))
        .unwrap(),
    )
    .unwrap();
    let evidence = match bind_host_event(&decoded, &SensorDisableConfig::empty()) {
        HostBindingOutcome::Bound(bound) => bound.evidence,
        HostBindingOutcome::Gap(gap) => panic!("unexpected binding gap: {:?}", gap.reason),
    };
    assert_eq!(evidence[0].payload["exit_code"], 7);
    assert_eq!(evidence[0].payload["heuristic"], false);
}

#[test]
fn reconstructed_events_redacted_operands_and_other_kinds_remain_gaps() {
    let mut event = canonical(json!({"stdout": "ok", "stderr": ""}));
    event["quality"] = json!("reconstructed");
    let decoded =
        fornax_types::host_event::decode_host_event(&serde_json::to_vec(&event).unwrap()).unwrap();
    assert!(matches!(
        bind_host_event(&decoded, &SensorDisableConfig::empty()),
        HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::SourceQualityUnavailable
    ));

    event = canonical(json!({"stdout": "ok", "stderr": ""}));
    event["facts"]["operand_completeness"] = json!("partial");
    event["facts"]["operands_availability"] = json!("redacted");
    let decoded =
        fornax_types::host_event::decode_host_event(&serde_json::to_vec(&event).unwrap()).unwrap();
    assert!(matches!(
        bind_host_event(&decoded, &SensorDisableConfig::empty()),
        HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::OperandsUnavailable
    ));

    event = canonical(json!({"stdout": "ok", "stderr": ""}));
    event["kind"] = json!("tool_before");
    let decoded =
        fornax_types::host_event::decode_host_event(&serde_json::to_vec(&event).unwrap()).unwrap();
    assert!(matches!(
        bind_host_event(&decoded, &SensorDisableConfig::empty()),
        HostBindingOutcome::Gap(gap) if gap.reason == HostBindingGapReason::EventBindingUnavailable
    ));
}
