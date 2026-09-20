//! Parameterized conformance tests (FORNX-156 required test): Claude and
//! Codex adapters both satisfy the same `fornax_types::AgentAdapter`
//! contract. See `src/lib.rs` for why assertions are over properties, not
//! message sequences.

use fornax_adapter_claude::ClaudeAdapter;
use fornax_adapter_codex::CodexAdapter;
use fornax_adapter_conformance::{
    every_message_round_trips_through_the_wire_protocol, normalizing_never_panics,
    probe_provider_matches_declared_provider, provider_is_stamped_consistently,
    unrecognized_always_carries_a_discriminator,
};
use fornax_adapter_opencode::OpenCodeAdapter;
use fornax_types::{AgentAdapter, NormalizationOutcome, Provider};

/// A handful of native fixtures, one per adapter, each including at least
/// one real recognized shape and one shape with no canonical mapping. Kept
/// here (not in `src/lib.rs`) because these are provider-native — the
/// generic harness must never know these field names (that would defeat
/// the point of the contract).
fn claude_fixtures() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "claude-sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "pytest"},
            "tool_response": {"stdout": "ok", "stderr": "", "interrupted": false}
        }),
        serde_json::json!({
            "hook_event_name": "SessionStart",
            "session_id": "claude-sess-1"
        }),
    ]
}

fn codex_fixtures() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "type": "event_msg",
            "payload": {
                "type": "exec_command_end",
                "command": ["pytest"],
                "exit_code": 0
            }
        }),
        serde_json::json!({
            "type": "event_msg",
            "payload": {"type": "task_complete", "last_agent_message": "All tests passed."}
        }),
    ]
}

fn opencode_fixtures() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "hook": "tool.execute.after",
            "payload": {
                "input": {"tool": "bash", "sessionID": "opencode-sess-1", "callID": "c1", "args": {"command": "pytest"}},
                "output": {"title": "pytest", "metadata": {"output": "ok", "exit": 0}, "output": "ok"}
            }
        }),
        serde_json::json!({
            "hook": "event",
            "payload": {"type": "session.created", "properties": {"sessionID": "opencode-sess-1"}}
        }),
    ]
}

#[test]
fn claude_adapter_satisfies_the_conformance_contract() {
    let mut adapter = ClaudeAdapter;
    assert_eq!(adapter.provider(), Provider::ClaudeCode);
    probe_provider_matches_declared_provider(&adapter);
    provider_is_stamped_consistently(&mut adapter, "hint", &claude_fixtures());
    every_message_round_trips_through_the_wire_protocol(&mut adapter, "hint", &claude_fixtures());
}

#[test]
fn codex_adapter_satisfies_the_conformance_contract() {
    let mut adapter = CodexAdapter::new();
    assert_eq!(adapter.provider(), Provider::Codex);
    probe_provider_matches_declared_provider(&adapter);
    provider_is_stamped_consistently(&mut adapter, "hint", &codex_fixtures());
    every_message_round_trips_through_the_wire_protocol(&mut adapter, "hint", &codex_fixtures());
}

#[test]
fn opencode_adapter_satisfies_the_conformance_contract() {
    let mut adapter = OpenCodeAdapter::new();
    assert_eq!(adapter.provider(), Provider::OpenCode);
    probe_provider_matches_declared_provider(&adapter);
    provider_is_stamped_consistently(&mut adapter, "hint", &opencode_fixtures());
    every_message_round_trips_through_the_wire_protocol(&mut adapter, "hint", &opencode_fixtures());
}

/// Unknown-event policy conformance test (FORNX-156 required test): feed
/// each adapter a synthetic, never-seen native event shape and assert it is
/// classified `Unrecognized` with a non-empty discriminator — not a panic,
/// not silently dropped as if it were an ordinary `Ignored` shape.
#[test]
fn claude_adapter_handles_an_unrecognized_native_event_per_policy() {
    let mut adapter = ClaudeAdapter;
    let synthetic = serde_json::json!({
        "hook_event_name": "SomeFutureHookEventNobodyHasSeenYet",
        "session_id": "claude-sess-1",
        "totally_new_field": {"nested": "shape"}
    });
    let outcome = normalizing_never_panics(&mut adapter, "hint", &synthetic);
    match &outcome {
        NormalizationOutcome::Unrecognized { discriminator } => {
            assert_eq!(discriminator, "SomeFutureHookEventNobodyHasSeenYet");
        }
        other => panic!("expected Unrecognized, got {other:?}"),
    }
    unrecognized_always_carries_a_discriminator(&outcome);
}

#[test]
fn codex_adapter_handles_an_unrecognized_native_event_per_policy() {
    let mut adapter = CodexAdapter::new();
    let synthetic = serde_json::json!({
        "type": "event_msg",
        "payload": {"type": "some_future_event_type_nobody_has_seen_yet", "junk": [1, 2, 3]}
    });
    let outcome = normalizing_never_panics(&mut adapter, "hint", &synthetic);
    match &outcome {
        NormalizationOutcome::Unrecognized { discriminator } => {
            assert_eq!(
                discriminator,
                "event_msg:some_future_event_type_nobody_has_seen_yet"
            );
        }
        other => panic!("expected Unrecognized, got {other:?}"),
    }
    unrecognized_always_carries_a_discriminator(&outcome);
}

#[test]
fn opencode_adapter_handles_an_unrecognized_native_event_per_policy() {
    let mut adapter = OpenCodeAdapter::new();
    let synthetic = serde_json::json!({
        "hook": "some.future.hook.nobody.has.seen.yet",
        "payload": {"totally_new_field": {"nested": "shape"}}
    });
    let outcome = normalizing_never_panics(&mut adapter, "hint", &synthetic);
    match &outcome {
        NormalizationOutcome::Unrecognized { discriminator } => {
            assert_eq!(discriminator, "hook:some.future.hook.nobody.has.seen.yet");
        }
        other => panic!("expected Unrecognized, got {other:?}"),
    }
    unrecognized_always_carries_a_discriminator(&outcome);
}

/// A completely malformed/empty native payload must still never panic any
/// adapter (see the trait docs, "Error semantics").
#[test]
fn malformed_native_payload_never_panics_either_adapter() {
    let empty = serde_json::json!({});
    let mut claude = ClaudeAdapter;
    let mut codex = CodexAdapter::new();
    let mut opencode = OpenCodeAdapter::new();
    let _ = normalizing_never_panics(&mut claude, "hint", &empty);
    let _ = normalizing_never_panics(&mut codex, "hint", &empty);
    let _ = normalizing_never_panics(&mut opencode, "hint", &empty);
}
