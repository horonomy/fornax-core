//! Comprehensive contract tests (FORNX-160), extending FORNX-156's original
//! property suite (`tests/conformance.rs`) beyond what fell out incidentally
//! of that ticket's own scope: capability declaration correctness
//! (FORNX-155), provenance correctness (FORNX-157), canonical-payload
//! validation wired to real adapter output (FORNX-158, picking up part of
//! FORNX-289), and unknown-event/failure semantics interacting correctly
//! with the extension envelope (FORNX-158).

use fornax_adapter_claude::ClaudeAdapter;
use fornax_adapter_codex::CodexAdapter;
use fornax_adapter_conformance::{
    capability_declaration_is_well_formed, every_message_round_trips_through_the_wire_protocol,
    evidence_payloads_validate_against_their_canonical_schema, evidence_sources_are_valid,
    load_fixtures, replay_fixture,
};
use fornax_adapter_opencode::OpenCodeAdapter;
use fornax_types::{
    validate_canonical_payload, AgentAdapter, CapabilityProbe, ContentClass, EventKind,
    EvidenceKind, ExtensionEnvelope, IngestMessage, NormalizationOutcome, Provider,
    SignalAvailability, SignalClass,
};

fn claude_native_events() -> Vec<serde_json::Value> {
    load_fixtures("claude")
        .into_iter()
        .filter(|f| !f.name.starts_with("unrecognized_"))
        .flat_map(|f| f.native_events)
        .collect()
}

fn codex_native_events() -> Vec<serde_json::Value> {
    // Excludes the call/output pairing fixture: `session_meta` latches a
    // discovered session id onto the adapter, and the call/output pair only
    // correlates correctly when replayed in order — mixing its two events
    // into this flat, order-agnostic list (used across several independent
    // checks below) would either desync the session id or split the pair.
    // The pairing itself is covered end-to-end, in order, by
    // `golden_fixtures.rs`'s FORNX-55 regression test.
    load_fixtures("codex")
        .into_iter()
        .filter(|f| !f.name.starts_with("unrecognized_") && !f.name.contains("pair"))
        .flat_map(|f| f.native_events)
        .collect()
}

fn opencode_native_events() -> Vec<serde_json::Value> {
    // Unlike Codex's call/output pairing fixture, opencode's
    // tool.execute.before/after pair does not need to be excluded here:
    // each event in `tool_execute_before_after_pair.json` carries its own
    // `sessionID` directly (opencode's plugin payloads are self-contained
    // per hook invocation, not correlated only via adapter state), so it
    // replays correctly even when interleaved with other fixtures' events
    // in this flat, order-preserving list.
    load_fixtures("opencode")
        .into_iter()
        .filter(|f| !f.name.starts_with("unrecognized_"))
        .flat_map(|f| f.native_events)
        .collect()
}

// --- Capability declaration correctness (FORNX-155) -----------------------

#[test]
fn claude_capability_declaration_is_well_formed() {
    capability_declaration_is_well_formed(&ClaudeAdapter);
}

#[test]
fn codex_capability_declaration_is_well_formed() {
    capability_declaration_is_well_formed(&CodexAdapter::new());
}

#[test]
fn opencode_capability_declaration_is_well_formed() {
    capability_declaration_is_well_formed(&OpenCodeAdapter::new());
}

/// Declaration-vs-reality cross-check, not just shape validation: Claude
/// declares `ProcessResult: Unsupported` (`ClaudeAdapter::probe`'s doc — Bash
/// `tool_response` carries no literal exit code). If any real Claude fixture
/// ever produced a *non*-heuristic `ExitCode` Evidence, that would directly
/// contradict this adapter's own capability declaration — a conformance bug
/// the tautological "does probe() equal probe()" checks above cannot catch.
#[test]
fn claude_declares_process_result_unsupported_and_never_emits_a_literal_exit_code() {
    let adapter = ClaudeAdapter;
    assert_eq!(
        adapter.probe().state_of(&SignalClass::ProcessResult),
        SignalAvailability::Unsupported,
        "this test's other assertion depends on this declaration staying Unsupported"
    );

    let mut adapter = ClaudeAdapter;
    for native in claude_native_events() {
        if let NormalizationOutcome::Messages(msgs) = adapter.normalize("fixture-hint", &native) {
            for msg in msgs {
                // FORNX-14: scoped to `ExitCode` evidence specifically — this
                // declaration/assertion is about exit codes, not every
                // evidence kind this adapter emits. A `ProcessObservation`
                // (e.g. `ClaudeGitOutcomeSensor`'s git commit/push evidence)
                // carries no `heuristic` field at all and must not be
                // checked against it.
                if let IngestMessage::Evidence(ev) = msg {
                    if ev.kind != EvidenceKind::ExitCode {
                        continue;
                    }
                    assert_eq!(
                        ev.payload["heuristic"],
                        serde_json::json!(true),
                        "ClaudeAdapter declares ProcessResult Unsupported, so every ExitCode \
                         Evidence it emits must be heuristic, never a literal exit code"
                    );
                }
            }
        }
    }
}

/// Same kind of cross-check for Codex: `ToolInvocation` is declared
/// `Unsupported` (rollout-tail cannot intercept pre-execution) — no golden
/// fixture replay may ever yield a `PreToolUse` event, which would
/// contradict that declaration.
#[test]
fn codex_declares_tool_invocation_unsupported_and_never_emits_pre_tool_use() {
    let adapter = CodexAdapter::new();
    assert_eq!(
        adapter.probe().state_of(&SignalClass::ToolInvocation),
        SignalAvailability::Unsupported,
        "this test's other assertion depends on this declaration staying Unsupported"
    );

    let mut adapter = CodexAdapter::new();
    for native in codex_native_events() {
        if let NormalizationOutcome::Messages(msgs) = adapter.normalize("fixture-hint", &native) {
            for msg in msgs {
                if let IngestMessage::Event(ev) = msg {
                    assert_ne!(
                        ev.kind,
                        EventKind::PreToolUse,
                        "CodexAdapter declares ToolInvocation Unsupported, so it must never \
                         emit a PreToolUse event"
                    );
                }
            }
        }
    }
}

/// FORNX-161's headline declaration-vs-reality cross-check, in the opposite
/// direction from Claude's: opencode declares `ProcessResult: Available`
/// (a literal `output.metadata.exit`), so every `ExitCode` Evidence it
/// produces must be non-heuristic — the inverse of
/// `claude_declares_process_result_unsupported_and_never_emits_a_literal_exit_code`
/// above, and the concrete proof the two providers' declarations aren't
/// just copy-pasted opposite guesses.
#[test]
fn opencode_declares_process_result_available_and_never_emits_a_heuristic_exit_code() {
    let adapter = OpenCodeAdapter::new();
    assert_eq!(
        adapter.probe().state_of(&SignalClass::ProcessResult),
        SignalAvailability::Available,
        "this test's other assertion depends on this declaration staying Available"
    );

    let mut adapter = OpenCodeAdapter::new();
    for native in opencode_native_events() {
        if let NormalizationOutcome::Messages(msgs) = adapter.normalize("fixture-hint", &native) {
            for msg in msgs {
                if let IngestMessage::Evidence(ev) = msg {
                    assert_eq!(
                        ev.payload["heuristic"],
                        serde_json::json!(false),
                        "OpenCodeAdapter declares ProcessResult Available, so every ExitCode \
                         Evidence it emits must be a literal exit code, never a heuristic"
                    );
                }
            }
        }
    }
}

/// Same kind of cross-check for `SubagentLifecycle`: opencode declares it
/// `Unsupported` (no subagent-specific hook in the Hooks interface) — no
/// golden fixture replay may ever yield a `SubagentStart`/`SubagentStop`
/// event, which would contradict that declaration.
#[test]
fn opencode_declares_subagent_lifecycle_unsupported_and_never_emits_subagent_events() {
    let adapter = OpenCodeAdapter::new();
    assert_eq!(
        adapter.probe().state_of(&SignalClass::SubagentLifecycle),
        SignalAvailability::Unsupported,
        "this test's other assertion depends on this declaration staying Unsupported"
    );

    let mut adapter = OpenCodeAdapter::new();
    for native in opencode_native_events() {
        if let NormalizationOutcome::Messages(msgs) = adapter.normalize("fixture-hint", &native) {
            for msg in msgs {
                if let IngestMessage::Event(ev) = msg {
                    assert!(
                        !matches!(ev.kind, EventKind::SubagentStart | EventKind::SubagentStop),
                        "OpenCodeAdapter declares SubagentLifecycle Unsupported, so it must \
                         never emit a subagent lifecycle event"
                    );
                }
            }
        }
    }
}

// --- FORNX-156 wire-protocol property, exercised against golden fixtures --

#[test]
fn claude_golden_fixtures_round_trip_through_the_wire_protocol() {
    let mut adapter = ClaudeAdapter;
    every_message_round_trips_through_the_wire_protocol(
        &mut adapter,
        "fixture-hint",
        &claude_native_events(),
    );
}

#[test]
fn codex_golden_fixtures_round_trip_through_the_wire_protocol() {
    let mut adapter = CodexAdapter::new();
    every_message_round_trips_through_the_wire_protocol(
        &mut adapter,
        "fixture-hint",
        &codex_native_events(),
    );
}

#[test]
fn opencode_golden_fixtures_round_trip_through_the_wire_protocol() {
    let mut adapter = OpenCodeAdapter::new();
    every_message_round_trips_through_the_wire_protocol(
        &mut adapter,
        "fixture-hint",
        &opencode_native_events(),
    );
}

// --- Provenance correctness (FORNX-157) ------------------------------------

#[test]
fn claude_evidence_from_golden_fixtures_carries_valid_provenance() {
    let mut adapter = ClaudeAdapter;
    evidence_sources_are_valid(&mut adapter, "fixture-hint", &claude_native_events());
}

#[test]
fn codex_evidence_from_golden_fixtures_carries_valid_provenance() {
    let mut adapter = CodexAdapter::new();
    evidence_sources_are_valid(&mut adapter, "fixture-hint", &codex_native_events());
}

#[test]
fn opencode_evidence_from_golden_fixtures_carries_valid_provenance() {
    let mut adapter = OpenCodeAdapter::new();
    evidence_sources_are_valid(&mut adapter, "fixture-hint", &opencode_native_events());
}

// --- Canonical-payload validation wired to real output (FORNX-158/289) ----

#[test]
fn claude_evidence_payloads_validate_against_their_canonical_schema() {
    let mut adapter = ClaudeAdapter;
    evidence_payloads_validate_against_their_canonical_schema(
        &mut adapter,
        "fixture-hint",
        &claude_native_events(),
    );
}

#[test]
fn codex_evidence_payloads_validate_against_their_canonical_schema() {
    let mut adapter = CodexAdapter::new();
    evidence_payloads_validate_against_their_canonical_schema(
        &mut adapter,
        "fixture-hint",
        &codex_native_events(),
    );
}

#[test]
fn opencode_evidence_payloads_validate_against_their_canonical_schema() {
    let mut adapter = OpenCodeAdapter::new();
    evidence_payloads_validate_against_their_canonical_schema(
        &mut adapter,
        "fixture-hint",
        &opencode_native_events(),
    );
}

/// FORNX-289: proves the check wired above actually bites at this
/// conformance-layer boundary, not just in `fornax-types`' own unit tests
/// (`crates/fornax-types/src/lib.rs`) — a real `ExitCodePayload` shape
/// (`#[serde(deny_unknown_fields)]`) with `exit_code` as a string instead of
/// an integer must fail `validate_canonical_payload`, the same function
/// `evidence_payloads_validate_against_their_canonical_schema` calls above.
#[test]
fn a_malformed_exit_code_payload_fails_canonical_validation_at_the_conformance_boundary() {
    let bad_payload = serde_json::json!({
        "command": ["ls"],
        "exit_code": "0",
        "heuristic": false
    });
    let err = validate_canonical_payload(EvidenceKind::ExitCode, &bad_payload)
        .expect_err("a string exit_code must not validate as the canonical ExitCodePayload");
    assert!(
        !err.is_empty(),
        "expected a non-empty type-mismatch error, got an empty string"
    );
}

// --- Unknown-event/failure semantics interacting with the extension
//     envelope (FORNX-158) ---------------------------------------------------

/// An `Unrecognized` outcome must never carry any canonical message
/// alongside it — not an event, not evidence, and therefore never an
/// `ExtensionEnvelope` either. `NormalizationOutcome::into_messages()`
/// already guarantees this structurally (see `fornax-types/src/adapter.rs`),
/// but this test re-affirms it at the conformance-suite level against real
/// breaking-change fixtures, not just the type's own unit tests.
#[test]
fn unrecognized_breaking_change_fixtures_never_produce_any_canonical_message() {
    let claude_fixture = load_fixtures("claude")
        .into_iter()
        .find(|f| f.name == "unrecognized_future_hook")
        .expect("expected the unrecognized_future_hook fixture");
    let mut claude = ClaudeAdapter;
    let outcomes = replay_fixture(&mut claude, "fixture-hint", &claude_fixture);
    for outcome in outcomes {
        assert!(outcome.into_messages().is_empty());
    }

    let codex_fixture = load_fixtures("codex")
        .into_iter()
        .find(|f| f.name == "unrecognized_future_event")
        .expect("expected the unrecognized_future_event fixture");
    let mut codex = CodexAdapter::new();
    let outcomes = replay_fixture(&mut codex, "fixture-hint", &codex_fixture);
    for outcome in outcomes {
        assert!(outcome.into_messages().is_empty());
    }

    let opencode_fixture = load_fixtures("opencode")
        .into_iter()
        .find(|f| f.name == "unrecognized_future_hook")
        .expect("expected the unrecognized_future_hook fixture");
    let mut opencode = OpenCodeAdapter::new();
    let outcomes = replay_fixture(&mut opencode, "fixture-hint", &opencode_fixture);
    for outcome in outcomes {
        assert!(outcome.into_messages().is_empty());
    }
}

/// An adapter must never construct an `ExtensionEnvelope` from data it did
/// not itself recognize (see `extension.rs`'s "Not a laundering path for
/// unrecognized native payloads" module doc). Neither Claude nor Codex uses
/// the envelope (see `opencode_tool_execute_evidence_carries_a_real_extension_envelope`
/// below for the first real adapter usage), so this test pins the boundary
/// at the type level: an `ExtensionEnvelope` built with a schema_version
/// outside `SUPPORTED_EXTENSION_SCHEMA_VERSIONS` must fail to deserialize —
/// the "explicit hard failure over silent corruption" half of FORNX-158's
/// forward/backward-compatibility model, re-affirmed here as a conformance
/// concern rather than only an internal `fornax-types` unit test.
#[test]
fn a_version_incompatible_extension_envelope_is_rejected_not_silently_accepted() {
    let envelope = ExtensionEnvelope::new(
        Provider::Codex,
        "conformance-fixture-adapter-0.0.0",
        ContentClass::RawProviderMetadata,
        serde_json::json!({}),
    );
    let mut value = serde_json::to_value(&envelope).unwrap();
    value["schema_version"] = serde_json::json!(9999);
    let result: Result<ExtensionEnvelope, _> = serde_json::from_value(value);
    assert!(
        result.is_err(),
        "an incompatible schema_version must fail explicitly, never silently parse"
    );
}

/// FORNX-158's first real adapter usage of `ExtensionEnvelope`: opencode's
/// real `tool_execute_before_after_pair` fixture carries a `title` and
/// `time` field with no home in `ExitCodePayload`'s canonical shape.
/// `OpenCodeExitCodeSensor` deliberately carries them forward via
/// `ContentClass::ToolTelemetry` rather than dropping them — this test
/// proves that path is actually exercised end-to-end against real captured
/// data, not just reachable in principle.
#[test]
fn opencode_tool_execute_evidence_carries_a_real_extension_envelope() {
    let mut adapter = OpenCodeAdapter::new();
    let fixture = load_fixtures("opencode")
        .into_iter()
        .find(|f| f.name == "tool_execute_before_after_pair")
        .expect("expected the tool_execute_before_after_pair fixture");
    let outcomes = replay_fixture(&mut adapter, "fixture-hint", &fixture);
    let extension = outcomes
        .into_iter()
        .flat_map(|o| o.into_messages())
        .find_map(|m| match m {
            IngestMessage::Evidence(ev) => ev.extension,
            _ => None,
        })
        .expect("expected the tool.execute.after Evidence to carry an ExtensionEnvelope");
    assert_eq!(extension.provider, Provider::OpenCode);
    assert_eq!(extension.content_class, ContentClass::ToolTelemetry);
    assert!(extension.fields.get("title").is_some());
}

// --- Sanity: fixtures actually exercise every documented sensor path ------

/// Guards against a golden-fixture regression where every fixture happens
/// to stop producing Evidence (e.g. a fixture bit-rots as the real provider
/// shape drifts again) without any test noticing — at least one Claude and
/// one Codex fixture must still produce real Evidence today.
#[test]
fn at_least_one_fixture_per_provider_still_produces_evidence() {
    let mut claude = ClaudeAdapter;
    let claude_has_evidence = claude_native_events().iter().any(|native| {
        matches!(
            claude.normalize("fixture-hint", native),
            NormalizationOutcome::Messages(msgs)
                if msgs.iter().any(|m| matches!(m, IngestMessage::Evidence(_)))
        )
    });
    assert!(
        claude_has_evidence,
        "expected at least one Claude fixture to produce Evidence"
    );

    let mut codex = CodexAdapter::new();
    let codex_has_evidence = codex_native_events().iter().any(|native| {
        matches!(
            codex.normalize("fixture-hint", native),
            NormalizationOutcome::Messages(msgs)
                if msgs.iter().any(|m| matches!(m, IngestMessage::Evidence(_)))
        )
    });
    assert!(
        codex_has_evidence,
        "expected at least one Codex fixture to produce Evidence"
    );

    let mut opencode = OpenCodeAdapter::new();
    let opencode_has_evidence = opencode_native_events().iter().any(|native| {
        matches!(
            opencode.normalize("fixture-hint", native),
            NormalizationOutcome::Messages(msgs)
                if msgs.iter().any(|m| matches!(m, IngestMessage::Evidence(_)))
        )
    });
    assert!(
        opencode_has_evidence,
        "expected at least one opencode fixture to produce Evidence"
    );
}
