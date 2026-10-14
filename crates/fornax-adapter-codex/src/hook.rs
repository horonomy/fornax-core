//! Codex lifecycle-hook adapter (HORO-1712 part B), formalized against the
//! `fornax_types::AgentAdapter` contract (FORNX-156). This is the
//! low-latency complement to [`crate::CodexAdapter`]'s rollout-tail path,
//! not a replacement for it — see the module docs on why.
//!
//! ## Why this exists alongside the rollout tailer, not instead of it
//!
//! Codex's lifecycle hooks (`PreToolUse`/`PostToolUse`/`SessionStart`/
//! `Stop`, registered via `~/.codex/hooks.json`) fire synchronously, with no
//! 500ms poll latency — a real low-latency gain over tailing the rollout
//! JSONL. But a real live capture (2026-10-13, codex-cli 0.160.0, HORO-1712
//! comment 27283) found the real `PostToolUse` payload's `tool_response`
//! field is a **bare string** (the command's raw stdout) with no exit-code-
//! shaped field anywhere — a failing `exit 9` and a quiet success both
//! produce `tool_response: ""`. There is nothing in the real hook payload
//! that distinguishes them. This adapter therefore **never produces
//! `Evidence` of any kind** — only `AgentEvent`s, which are observational
//! ("a tool was invoked, here's its raw text response") and carry no
//! verifiable claim a verifier could (dis)confirm. Exit-code-bearing
//! `Evidence::ExitCode` remains exclusively [`crate::CodexAdapter`]'s
//! rollout-tail job (`item_completed`'s `CommandExecution.exit_code`,
//! confirmed real — see that module's docs). This is exactly HORO-1712's
//! own design goal: hooks as a *faster* evidence path where they genuinely
//! add one, rollout as the *truthful* fallback/complement where hooks
//! cannot supply what's needed — not an either/or.
//!
//! ## Dedup against the rollout path
//!
//! A real tool call's hook `tool_use_id` and the rollout's own
//! `item_completed.item.id` were confirmed identical in the same live
//! capture (both `"exec-<uuid>"`). Despite that, this module's dedup ids
//! are computed under **new, hook-specific phase strings**
//! (`"hook:tool_before"`/`"hook:tool_after"`), never the rollout path's own
//! `"tool_after"`/`"tool_after:exit_code"` phases from [`crate::dedup_id`]'s
//! doc comment. Reusing the rollout's phase string for the *same*
//! `native_id` would compute the *same* id for two payloads with genuinely
//! different content (a hook's bare-string `tool_response` vs. the
//! rollout's structured `CommandExecution` item) — `fornax_store`'s
//! idempotent-insert path only collapses a repeated id into `Duplicate`
//! when the content *also* matches; a content mismatch under a shared id is
//! an `IdCollision`, which quarantines the second observation instead of
//! storing it. Giving the hook path its own phase namespace means both
//! paths' `AgentEvent`s for the same real call insert cleanly as two
//! distinct, non-colliding rows — which is correct: they are two genuine,
//! differently-provenanced observations of the same action, not one
//! repeated observation. "Hooks and rollout together do not double count"
//! holds here specifically because the hook path contributes zero
//! `Evidence` — nothing exists for a verifier to double-count, regardless
//! of how many `AgentEvent` rows describe the same call.
//!
//! (The doc comment on [`crate::dedup_id`] reserves the bare `"tool_before"`
//! phase string "for the hook-ingestion path's pre-execution observation" —
//! written before this analysis. That reservation is intentionally not
//! honored here for the reason above; see this crate's CHANGELOG-equivalent
//! commit for HORO-1712 part B.)

use crate::{dedup_id, ADAPTER_VERSION};
use fornax_types::{
    AgentAdapter, AgentEvent, CapabilityProbe, CapabilitySignal, EventKind, IngestMessage,
    NormalizationOutcome, Provider, RuntimeCapabilities, SignalAvailability, SignalClass,
};

/// Stateless: each hook invocation is a fresh, one-shot process (same shape
/// as `fornax-adapter-claude`'s `ClaudeAdapter` — contrast the rollout
/// tailer's `CodexAdapter`, which holds `call_id`-pairing state across a
/// long-lived process).
#[derive(Debug, Default, Clone, Copy)]
pub struct CodexHookAdapter;

impl CapabilityProbe for CodexHookAdapter {
    /// Declared for documentation/conformance-suite honesty only — **this
    /// adapter's `probe()` is never sent to the daemon** (see
    /// [`crate::fornax_hook_codex_event`]'s module docs for why: the
    /// rollout tailer already owns this session's `RuntimeCapabilities`
    /// declaration, and the daemon's capability store is last-writer-wins
    /// per `(session_id, provider)` — a second, hook-sourced declaration
    /// would silently overwrite the tailer's accurate one, including
    /// flipping `ProcessResult` from the tailer's real `Available` to this
    /// adapter's honest-for-itself-but-wrong-for-the-session `Unsupported`).
    fn probe(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Codex,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolInvocation,
                    state: SignalAvailability::Available,
                    detail: Some(
                        "PreToolUse hook, live-confirmed 2026-10-13 against codex-cli 0.160.0"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Available,
                    detail: Some(
                        "PostToolUse hook, live-confirmed 2026-10-13 against codex-cli 0.160.0"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::ToolResultPayload,
                    state: SignalAvailability::Available,
                    detail: Some(
                        "PostToolUse tool_response is a bare raw-stdout string, not a \
                         structured object -- live-confirmed 2026-10-13"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::ProcessResult,
                    state: SignalAvailability::Unsupported,
                    detail: Some(
                        "PostToolUse carries no exit-code-shaped field at all -- a failing \
                         `exit 9` and a quiet success both produce tool_response:\"\", \
                         live-confirmed 2026-10-13 against codex-cli 0.160.0. Exit-code \
                         evidence remains exclusively the rollout tailer's job."
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::SessionLifecycle,
                    state: SignalAvailability::Available,
                    detail: Some("SessionStart hook, live-confirmed 2026-10-13".to_string()),
                },
                CapabilitySignal {
                    class: SignalClass::SubagentLifecycle,
                    state: SignalAvailability::Unsupported,
                    detail: Some(
                        "SubagentStart/Stop hook mapping is out of scope for HORO-1712 part B"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::FinalResponse,
                    state: SignalAvailability::Unsupported,
                    detail: Some(
                        "Stop hook is deliberately Ignored by this adapter -- the rollout \
                         tailer's task_complete already emits SessionEnd and (when matched) a \
                         Claim for this session; a second, hook-sourced Claim from the same \
                         last_assistant_message could not be deduplicated against it \
                         (unrelated random ids on both sides)"
                            .to_string(),
                    ),
                },
            ],
            notes: Default::default(),
        }
    }
}

impl AgentAdapter for CodexHookAdapter {
    fn provider(&self) -> Provider {
        Provider::Codex
    }

    fn adapter_version(&self) -> &'static str {
        ADAPTER_VERSION
    }

    /// `session_hint` is unused: every real Codex hook payload carries its
    /// own `session_id` (live-confirmed 2026-10-13), which is authoritative
    /// for this transport, same policy as `fornax-adapter-claude`'s
    /// `ClaudeAdapter` (FORNX-433 AC3) -- a payload with no real provider
    /// session identity must never fall back to a shared hint, or unrelated
    /// sessions with no real identity would pool into one fake session and
    /// verify each other's claims.
    fn normalize(
        &mut self,
        _session_hint: &str,
        native: &serde_json::Value,
    ) -> NormalizationOutcome {
        translate(native)
    }
}

fn translate(raw: &serde_json::Value) -> NormalizationOutcome {
    let hook_event = raw
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // FORNX-433 AC3 parity (see `normalize`'s doc comment): fail closed on
    // no identity, never fall back to a shared hint.
    let session_id = match raw
        .get("session_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(s) => s.to_string(),
        None => {
            return NormalizationOutcome::Ignored {
                reason: "no provider session identity",
            }
        }
    };

    let kind = match hook_event {
        "PreToolUse" => EventKind::PreToolUse,
        "PostToolUse" => EventKind::PostToolUse,
        "SessionStart" => EventKind::SessionStart,
        // Deliberately Ignored, not Unrecognized -- these are real,
        // recognized Codex hook event names this adapter has no canonical
        // mapping for by design (see this module's and `probe`'s doc
        // comments for why Stop specifically must not become a second,
        // undeduplicatable Claim source).
        "Stop" | "UserPromptSubmit" | "SubagentStart" | "SubagentStop" | "Notification" => {
            return NormalizationOutcome::Ignored {
                reason: "recognized Codex hook event with no canonical mapping in the \
                         hook path (see module docs)",
            }
        }
        "" => {
            return NormalizationOutcome::Unrecognized {
                discriminator: "<missing hook_event_name>".to_string(),
            }
        }
        other => {
            return NormalizationOutcome::Unrecognized {
                discriminator: other.to_string(),
            }
        }
    };

    // `tool_use_id` is required for PreToolUse/PostToolUse (it is this
    // adapter's dedup key and its provenance correlator against the
    // rollout path) but absent on SessionStart, which has no tool call to
    // key on at all.
    let tool_use_id = raw.get("tool_use_id").and_then(|v| v.as_str());
    if matches!(kind, EventKind::PreToolUse | EventKind::PostToolUse) && tool_use_id.is_none() {
        return NormalizationOutcome::Unrecognized {
            discriminator: format!("{hook_event}:<missing tool_use_id>"),
        };
    }

    // Schema-drift guard (HORO-1712 AC: "schema drift fails visibly"): a
    // real PostToolUse's `tool_response`, when present, must be the bare
    // string this adapter's whole design (see module docs) depends on. If
    // Codex ever starts sending a structured object here (e.g. adding a
    // real exit_code field), this adapter must surface that loudly rather
    // than silently keep treating it as absent-and-unusable.
    if kind == EventKind::PostToolUse {
        if let Some(tool_response) = raw.get("tool_response") {
            if !tool_response.is_null() && !tool_response.is_string() {
                return NormalizationOutcome::Unrecognized {
                    discriminator: "PostToolUse:tool_response=<non-string>".to_string(),
                };
            }
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let native_id = tool_use_id.unwrap_or(hook_event);
    let phase = match kind {
        EventKind::PreToolUse => "hook:tool_before",
        EventKind::PostToolUse => "hook:tool_after",
        EventKind::SessionStart => "hook:session_start",
        _ => unreachable!("filtered above"),
    };
    let event_id = dedup_id(&session_id, phase, native_id);

    let tool_name = raw
        .get("tool_name")
        .and_then(|v| v.as_str())
        .map(String::from);
    let tool_input = raw.get("tool_input").cloned();
    let tool_response = raw.get("tool_response").cloned();

    let event = AgentEvent {
        id: event_id,
        session_id,
        provider: Provider::Codex,
        kind,
        observed_at: now,
        tool_name,
        tool_input,
        tool_response,
        raw: raw.clone(),
    };

    // No `IngestMessage::Capabilities` here -- see `probe`'s doc comment.
    // No `IngestMessage::Evidence` here, ever -- see this module's doc
    // comment. Observational `AgentEvent` only.
    NormalizationOutcome::Messages(vec![IngestMessage::Event(event)])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(raw: &serde_json::Value) -> NormalizationOutcome {
        CodexHookAdapter.normalize("unused-hint", raw)
    }

    fn messages(outcome: NormalizationOutcome) -> Vec<IngestMessage> {
        outcome.into_messages()
    }

    /// Real payload, live-confirmed 2026-10-13 (HORO-1712 comment 27283):
    /// successful `echo` command.
    #[test]
    fn real_post_tool_use_success_produces_event_only_no_evidence() {
        let raw = serde_json::json!({
            "session_id": "01a133e8-c9c5-7f70-88f1-9cad93738293",
            "turn_id": "01a133e8-ce25-75f1-9e3f-4a5c4deb605b",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hook-capture-test"},
            "tool_response": "hook-capture-test\n",
            "tool_use_id": "exec-79e04bf2-79af-423d-9cd8-e00d03968add"
        });
        let msgs = messages(normalize(&raw));
        assert_eq!(msgs.len(), 1, "exactly one Event, never Evidence");
        match &msgs[0] {
            IngestMessage::Event(e) => {
                assert_eq!(e.kind, EventKind::PostToolUse);
                assert_eq!(e.provider, Provider::Codex);
                assert_eq!(e.tool_name.as_deref(), Some("Bash"));
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    /// Real payload, live-confirmed 2026-10-13: a genuinely FAILING command
    /// (`exit 9`) produces the exact same empty-string `tool_response` as a
    /// quiet success -- this adapter must not fabricate Evidence from it.
    #[test]
    fn real_post_tool_use_failure_still_produces_no_evidence() {
        let raw = serde_json::json!({
            "session_id": "01a133e9-68cc-7ae0-be24-c7b7eddc1ca4",
            "turn_id": "01a133e9-692f-7562-9bb4-3914d1fcb9ca",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "exit 9"},
            "tool_response": "",
            "tool_use_id": "exec-c44c129d-1a06-48c8-8e5d-ee86100cb994"
        });
        let msgs = messages(normalize(&raw));
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], IngestMessage::Event(_)));
        assert!(
            !msgs.iter().any(|m| matches!(m, IngestMessage::Evidence(_))),
            "must never emit Evidence from a hook payload -- real exit code is unobservable here"
        );
    }

    #[test]
    fn pre_tool_use_produces_event() {
        let raw = serde_json::json!({
            "session_id": "sess-1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hi"},
            "tool_use_id": "exec-abc"
        });
        let msgs = messages(normalize(&raw));
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            IngestMessage::Event(e) => assert_eq!(e.kind, EventKind::PreToolUse),
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn session_start_produces_event() {
        let raw = serde_json::json!({
            "session_id": "sess-1",
            "hook_event_name": "SessionStart",
            "source": "startup"
        });
        let msgs = messages(normalize(&raw));
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            IngestMessage::Event(e) => assert_eq!(e.kind, EventKind::SessionStart),
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn stop_hook_is_ignored_not_a_second_claim_source() {
        let raw = serde_json::json!({
            "session_id": "sess-1",
            "hook_event_name": "Stop",
            "last_assistant_message": "All tests passed."
        });
        assert!(matches!(
            normalize(&raw),
            NormalizationOutcome::Ignored { .. }
        ));
    }

    #[test]
    fn missing_session_id_is_ignored_never_falls_back_to_hint() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_use_id": "exec-abc"
        });
        assert!(matches!(
            normalize(&raw),
            NormalizationOutcome::Ignored { .. }
        ));
    }

    #[test]
    fn missing_hook_event_name_is_unrecognized() {
        let raw = serde_json::json!({"session_id": "sess-1"});
        assert!(matches!(
            normalize(&raw),
            NormalizationOutcome::Unrecognized { .. }
        ));
    }

    #[test]
    fn unknown_hook_event_name_is_unrecognized() {
        let raw = serde_json::json!({
            "session_id": "sess-1",
            "hook_event_name": "SomethingCodexAddsLater"
        });
        assert!(matches!(
            normalize(&raw),
            NormalizationOutcome::Unrecognized { .. }
        ));
    }

    #[test]
    fn post_tool_use_missing_tool_use_id_is_unrecognized() {
        let raw = serde_json::json!({
            "session_id": "sess-1",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": ""
        });
        assert!(matches!(
            normalize(&raw),
            NormalizationOutcome::Unrecognized { .. }
        ));
    }

    /// Schema-drift guard: if Codex ever sends a structured (non-string)
    /// `tool_response`, this must fail visibly, not silently ignore a
    /// possible real exit-code field landing in a shape this adapter never
    /// learned to read.
    #[test]
    fn post_tool_use_non_string_tool_response_is_unrecognized() {
        let raw = serde_json::json!({
            "session_id": "sess-1",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": {"exit_code": 0, "stdout": ""},
            "tool_use_id": "exec-abc"
        });
        assert!(matches!(
            normalize(&raw),
            NormalizationOutcome::Unrecognized { .. }
        ));
    }

    /// Determinism + cross-path non-collision: the same hook payload
    /// translated twice gives the same id (replay-safe), and that id never
    /// equals the rollout path's own dedup id for the same native call,
    /// even though `tool_use_id` and the rollout's `item.id` are confirmed
    /// identical in real captures.
    #[test]
    fn hook_dedup_id_is_deterministic_and_never_collides_with_rollout_phase() {
        let raw = serde_json::json!({
            "session_id": "sess-1",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": "ok",
            "tool_use_id": "exec-same-native-id"
        });
        let first = messages(normalize(&raw));
        let second = messages(normalize(&raw));
        let id1 = match &first[0] {
            IngestMessage::Event(e) => e.id,
            _ => panic!("expected Event"),
        };
        let id2 = match &second[0] {
            IngestMessage::Event(e) => e.id,
            _ => panic!("expected Event"),
        };
        assert_eq!(id1, id2, "same payload must produce the same id");

        let rollout_id = dedup_id("sess-1", "tool_after", "exec-same-native-id");
        assert_ne!(
            id1, rollout_id,
            "hook-sourced id must never equal the rollout path's id for the same native_id"
        );
    }

    #[test]
    fn probe_declares_process_result_unsupported() {
        let caps = CodexHookAdapter.probe();
        let process_result = caps
            .signals
            .iter()
            .find(|s| s.class == SignalClass::ProcessResult)
            .expect("ProcessResult signal present");
        assert_eq!(process_result.state, SignalAvailability::Unsupported);
    }
}
