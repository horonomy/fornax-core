//! Codex CLI adapter (FORNX-29), formalized against the
//! `fornax_types::AgentAdapter` contract (FORNX-156). Codex's hook system is
//! opt-in/unstable and admin-suppressible
//! (docs/research/adapter-capability-matrix.md), so the primary integration
//! point here is tailing the always-on rollout JSONL transcript at
//! `~/.codex/sessions/**/*.jsonl`, not hooks. Thin adapter: translates
//! confirmed `RolloutLine` shapes into canonical `fornax_types::IngestMessage`s.

use fornax_types::{
    AgentAdapter, AgentEvent, CapabilityProbe, Claim, CollectionMethod, EventKind, Evidence,
    EvidenceKind, EvidenceSensor, EvidenceSource, IngestMessage, NormalizationOutcome, Provider,
    RuntimeCapabilities, SensorOutcome, SignalAvailability, SignalClass, TrustClass,
};
use std::collections::HashMap;
use uuid::Uuid;

/// This adapter implementation's own version — independent of the Codex CLI
/// runtime version, which belongs in a `CapabilitySignal::detail` string
/// (see `CodexAdapter::probe`). Attached to every capability declaration via
/// `notes["adapter_version"]`.
pub const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Stateful, unlike `fornax-adapter-claude`'s adapter: the rollout-tail
/// transport is a long-lived process, so `normalize` correlates a
/// `custom_tool_call`'s `call_id` with its later `custom_tool_call_output`
/// (FORNX-55), and remembers the session id discovered from the rollout
/// file's own `session_meta` line so later lines don't need one supplied.
#[derive(Debug, Default)]
pub struct CodexAdapter {
    pending_calls: HashMap<String, String>,
    session_id: Option<String>,
}

impl CodexAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    /// The session id discovered so far from the rollout's own
    /// `session_meta` line, if any has been seen yet.
    pub fn known_session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}

impl CapabilityProbe for CodexAdapter {
    /// Codex's own hooks and PreToolUse input-rewrite are not usable today
    /// (opt-in feature flag, admin-suppressible, no input rewrite — see the
    /// capability matrix doc). Declared conservatively; never inferred as
    /// more capable than confirmed.
    ///
    /// Formalized (FORNX-155) from six fixed bools into an explicit
    /// `SignalClass` -> `SignalAvailability` declaration. `ToolInvocation`
    /// and `SubagentLifecycle` are `Unsupported`, not merely absent: this
    /// adapter's chosen mechanism (rollout-tail, not Codex's opt-in/
    /// admin-suppressible hooks) fundamentally cannot expose pre-execution
    /// interception or subagent lifecycle events. `ProcessResult` is
    /// `Unavailable` — the class exists for Codex in principle via
    /// `exec_command_end.exit_code` (confirmed in the capability matrix
    /// doc); this adapter's primary rollout-tail path just hasn't observed
    /// it (see `translate_line`'s `custom_tool_call_output` handling).
    fn probe(&self) -> RuntimeCapabilities {
        use fornax_types::{CapabilitySignal, SignalAvailability, SignalClass};
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Codex,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolInvocation,
                    state: SignalAvailability::Unsupported,
                    detail: Some(
                        "Codex hooks (the only pre-execution interception mechanism) are \
                         opt-in and admin-suppressible, with no input-rewrite support \
                         (see docs/research/adapter-capability-matrix.md)"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Available,
                    detail: Some(
                        "via rollout custom_tool_call/_output pairing, not hooks".to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::ToolResultPayload,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::SessionLifecycle,
                    state: SignalAvailability::Available,
                    detail: Some("task_complete in rollout".to_string()),
                },
                CapabilitySignal {
                    class: SignalClass::FinalResponse,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::SubagentLifecycle,
                    state: SignalAvailability::Unsupported,
                    detail: Some(
                        "this adapter's rollout-tail mechanism surfaces no subagent lines; \
                         Codex's own SubagentStart/Stop hooks exist but are opt-in/unstable/ \
                         admin-suppressible, same as ToolInvocation above"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::ProcessResult,
                    state: SignalAvailability::Unavailable,
                    detail: Some(
                        "exec_command_end (literal exit_code) not emitted by codex-cli 0.147.0. \
                         custom_tool_call_output does carry a real, parseable exit code \
                         (FORNX-16, live-confirmed) when the session's exec tool is \
                         tools.shell_command (unified_exec disabled) — but the default \
                         tools.exec_command (unified_exec) shape still exposes no exit \
                         status at all, even for a genuinely failing command, so this \
                         stays Unavailable rather than Available at the provider-wide level"
                            .to_string(),
                    ),
                },
            ],
            notes: [(
                "mechanism".to_string(),
                "rollout JSONL tail, not Codex hooks (opt-in/unstable, see adapter-capability-matrix.md)".to_string(),
            )]
            .into(),
        }
    }
}

impl AgentAdapter for CodexAdapter {
    fn provider(&self) -> Provider {
        Provider::Codex
    }

    fn adapter_version(&self) -> &'static str {
        ADAPTER_VERSION
    }

    /// Prefers the session id discovered from the rollout file's own
    /// `session_meta` line (see `Self::session_id`) once known; falls back
    /// to `session_hint` (e.g. the file path, used by `main.rs` before any
    /// `session_meta` line has been seen) otherwise.
    fn normalize(
        &mut self,
        session_hint: &str,
        native: &serde_json::Value,
    ) -> NormalizationOutcome {
        if self.session_id.is_none() {
            if let Some(sid) = native
                .pointer("/payload/session_id")
                .and_then(|v| v.as_str())
            {
                self.session_id = Some(sid.to_string());
            }
        }
        let sid = self
            .session_id
            .clone()
            .unwrap_or_else(|| session_hint.to_string());
        translate_line(native, &sid, &mut self.pending_calls)
    }
}

/// Stamps `notes["session_id"]`/`notes["adapter_version"]` onto a fresh
/// capability declaration for `sid`. Exposed so `main.rs` can build the
/// once-per-connection `Capabilities` message without duplicating the
/// stamping logic.
pub fn stamped_capabilities(adapter: &CodexAdapter, session_id: &str) -> RuntimeCapabilities {
    let mut caps = adapter.probe();
    caps.notes
        .insert("session_id".to_string(), session_id.to_string());
    caps.notes.insert(
        "adapter_version".to_string(),
        adapter.adapter_version().to_string(),
    );
    caps
}

/// FORNX-157: formalizes `exec_command_end`'s literal `exit_code` field
/// extraction — the only Codex shape confirmed to carry a real (non-
/// heuristic) exit code — as an `EvidenceSensor`. Unchanged heuristic from
/// before this migration; see the `tests` module's existing
/// `exec_command_end`-shape tests, whose assertions were left untouched as
/// the before/after regression proof.
struct CodexExecCommandEndSensor;

impl EvidenceSensor for CodexExecCommandEndSensor {
    fn name(&self) -> &'static str {
        "codex_exec_command_end_sensor_v1"
    }

    fn required_capabilities(&self) -> &'static [SignalClass] {
        &[SignalClass::ToolResultPayload]
    }

    fn trust_class(&self) -> TrustClass {
        // Codex's own rollout JSONL is the provider's account of what
        // happened, not something Fornax measured itself.
        TrustClass::AgentAdjacent
    }

    fn collection_method(&self) -> CollectionMethod {
        // Codex's rollout JSONL is tailed/polled as an always-on file, not
        // delivered via an in-process hook callback — distinct from Claude
        // Code's PostToolUse sensor, which shares the same trust class (see
        // `fornax_types::sensor`'s module docs' worked example).
        CollectionMethod::FilePoll
    }

    fn collector_version(&self) -> Option<String> {
        Some(ADAPTER_VERSION.to_string())
    }

    // `caps` is intentionally unused — see `ClaudeBashExitCodeSensor::collect`'s
    // note (fornax-adapter-claude) on why gating on it here would be a
    // behavior change this migration must not introduce.
    fn collect(&self, event: &AgentEvent, _caps: &RuntimeCapabilities) -> SensorOutcome {
        if event.kind != EventKind::PostToolUse {
            return SensorOutcome::not_collected(
                SignalAvailability::Unknown,
                Some("not a PostToolUse event".to_string()),
            );
        }
        let Some(resp) = &event.tool_response else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some("no tool_response present on this event".to_string()),
            );
        };
        let Some(code) = resp.get("exit_code").and_then(|v| v.as_i64()) else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some("no literal exit_code field on this exec_command_end payload".to_string()),
            );
        };

        SensorOutcome::collected(vec![Evidence {
            id: Uuid::new_v4(),
            session_id: event.session_id.clone(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: event.observed_at.clone(),
            payload: serde_json::json!({
                "command": resp.get("command").cloned().unwrap_or_default(),
                "exit_code": code,
            }),
            provenance: format!("codex:{v}:rollout:exec_command_end", v = ADAPTER_VERSION),
            source: Some(EvidenceSource::now(
                self.name(),
                self.trust_class(),
                Some(Provider::Codex),
                self.collection_method(),
                self.collector_version(),
            )),
            extension: None,
        }])
    }
}

/// FORNX-157: formalizes the `custom_tool_call_output` "Script completed"
/// heuristic (no literal exit code exposed in this shape at all — see the
/// doc comment at its original call site) as an `EvidenceSensor`.
///
/// FORNX-16 (live capture 2026-08-31 against codex-cli 0.147.0, the exact
/// version referenced by the FORNX-55 comments below): the "no literal exit
/// code at all" claim was true only for the *default* `exec` custom tool
/// (`tools.exec_command`, the persistent/`unified_exec` shell) — a real
/// failing command (`false`, `exit 1`) through that tool still yields
/// `"Script completed"` with no distinguishing text at all, confirming that
/// gap is real and not fixable from this shape alone.
///
/// But codex-cli 0.147.0 also exposes a second, stateless exec tool,
/// `tools.shell_command` (reached when the `unified_exec` feature is
/// disabled, e.g. `codex exec --disable unified_exec`), whose
/// `custom_tool_call_output` for the *same* `response_item` shape carries a
/// genuine, parseable `"Exit code: <n>"` annotation in the output text for
/// both outcomes — `"Script failed"` / `"Script error:\nExit code: <n>"` on
/// failure, `"Script completed"` / `"Exit code: 0"` on success. `collect`
/// below prefers this literal value whenever it's present (real evidence,
/// `heuristic: false`) and only falls back to the old zero-guess heuristic
/// when no `"Exit code: "` text is present at all — the genuine
/// `unified_exec` gap remains `Unavailable`, not a synthetic verdict.
struct CodexCustomToolCallOutputSensor;

impl EvidenceSensor for CodexCustomToolCallOutputSensor {
    fn name(&self) -> &'static str {
        "codex_custom_tool_call_output_sensor_v1"
    }

    fn required_capabilities(&self) -> &'static [SignalClass] {
        &[SignalClass::ToolResultPayload]
    }

    fn trust_class(&self) -> TrustClass {
        TrustClass::AgentAdjacent
    }

    fn collection_method(&self) -> CollectionMethod {
        // Same rollout-file-poll mechanism as `CodexExecCommandEndSensor`.
        CollectionMethod::FilePoll
    }

    fn collector_version(&self) -> Option<String> {
        Some(ADAPTER_VERSION.to_string())
    }

    // `caps` is intentionally unused — see `ClaudeBashExitCodeSensor::collect`'s
    // note (fornax-adapter-claude) on why gating on it here would be a
    // behavior change this migration must not introduce.
    fn collect(&self, event: &AgentEvent, _caps: &RuntimeCapabilities) -> SensorOutcome {
        if event.kind != EventKind::PostToolUse {
            return SensorOutcome::not_collected(
                SignalAvailability::Unknown,
                Some("not a PostToolUse event".to_string()),
            );
        }
        let Some(resp) = &event.tool_response else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some("no tool_response present on this event".to_string()),
            );
        };
        let blocks: Vec<&str> = resp
            .get("output")
            .and_then(|v| v.as_array())
            .map(|blocks| {
                blocks
                    .iter()
                    .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        // Only used for the "Script completed" fallback marker below, never
        // for exit-code extraction — see `parse_exit_code_from_blocks`'s doc
        // comment for why joined text is unsafe for that.
        let output_text: String = blocks.concat();

        let command = event
            .tool_input
            .as_ref()
            .and_then(|ti| ti.get("command"))
            .cloned()
            .unwrap_or_default();

        // FORNX-16: the `tools.shell_command` wire shape embeds a literal
        // "Exit code: <n>" in the output text for both outcomes — prefer it
        // whenever present, real value, not a guess. See the struct doc
        // comment above for how this was confirmed and how it differs from
        // the still-real `unified_exec` gap below.
        if let Some(code) = parse_exit_code_from_blocks(&blocks) {
            return SensorOutcome::collected(vec![Evidence {
                id: Uuid::new_v4(),
                session_id: event.session_id.clone(),
                source_event_id: event.id,
                kind: EvidenceKind::ExitCode,
                observed_at: event.observed_at.clone(),
                payload: serde_json::json!({
                    "command": command,
                    "exit_code": code,
                    "heuristic": false,
                }),
                provenance: format!(
                    "codex:{v}:rollout:custom_tool_call_output#exit_code_text",
                    v = ADAPTER_VERSION
                ),
                source: Some(EvidenceSource::now(
                    self.name(),
                    self.trust_class(),
                    Some(Provider::Codex),
                    self.collection_method(),
                    self.collector_version(),
                )),
                extension: None,
            }]);
        }

        // "Script completed" is the only confirmed marker on the
        // `unified_exec` (`tools.exec_command`) shape, which carries no
        // parseable exit code at all — even a genuinely failing command
        // still reports "Script completed" there (confirmed live,
        // FORNX-16). So an unrecognized shape, or this heuristic-only
        // shape, never claims more than a zero-guess.
        if !output_text.contains("Script completed") {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some("output text has no recognized completion marker".to_string()),
            );
        }

        SensorOutcome::collected(vec![Evidence {
            id: Uuid::new_v4(),
            session_id: event.session_id.clone(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: event.observed_at.clone(),
            payload: serde_json::json!({
                "command": command,
                "exit_code": 0,
                "heuristic": true,
            }),
            provenance: format!(
                "codex:{v}:rollout:custom_tool_call_output#heuristic:script_completed",
                v = ADAPTER_VERSION
            ),
            source: Some(EvidenceSource::now(
                self.name(),
                self.trust_class(),
                Some(Provider::Codex),
                self.collection_method(),
                self.collector_version(),
            )),
            extension: None,
        }])
    }
}

/// Looks for a literal `"Exit code: <digits>"` annotation the way
/// `tools.shell_command`'s real `custom_tool_call_output` actually places
/// it: as the leading content of one whole output *block*, never merely
/// present somewhere inside a block's text.
///
/// This is deliberately **not** a substring search over the blocks joined
/// together — joining first and searching second would let a command's own
/// *stdout* (the second block in the real shape, which the block carrying
/// the real marker also happens to hold, right after it) forge a fake exit
/// code. A build tool that echoes `"Exit code: 1"` as part of its own
/// output, with no failure at all, must never be able to flip a truthful
/// claim to `heuristic: false` + a fabricated CONTRADICTED verdict — that
/// would be worse than not parsing it at all. Anchoring to "is this block's
/// own leading text" instead of "does the marker appear anywhere" is what
/// keeps `heuristic: false` an honest claim about a provider-emitted field.
///
/// Matches the two real shapes captured live (FORNX-16): a block starting
/// with `"Exit code: <n>"` directly (success), or one starting with
/// `"Script error:"` followed by `"Exit code: <n>"` on the next line
/// (failure). No regex dependency, consistent with this module's existing
/// manual parsing (see `extract_cmd`).
fn parse_exit_code_from_blocks(blocks: &[&str]) -> Option<i64> {
    const MARKER: &str = "Exit code: ";
    for block in blocks {
        let b = block.trim_start();
        let after_marker = if let Some(rest) = b.strip_prefix(MARKER) {
            Some(rest)
        } else {
            b.strip_prefix("Script error:")
                .map(|rest| rest.trim_start_matches(['\n', '\r']))
                .and_then(|rest| rest.strip_prefix(MARKER))
        };
        if let Some(rest) = after_marker {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !digits.is_empty() {
                if let Ok(code) = digits.parse::<i64>() {
                    return Some(code);
                }
            }
        }
    }
    None
}

fn translate_line(
    entry: &serde_json::Value,
    session_id: &str,
    pending_calls: &mut HashMap<String, String>,
) -> NormalizationOutcome {
    let Some(top_type) = entry.get("type").and_then(|v| v.as_str()) else {
        return NormalizationOutcome::Unrecognized {
            discriminator: "<missing type>".to_string(),
        };
    };

    // Confirmed against a real `codex exec` turn (codex-cli 0.147.0,
    // 2026-08-29 live capture, FORNX-55): this installed version never
    // emits `event_msg{type:"exec_command_end"}` at all — shell execution
    // is wrapped as a `response_item` pair, `custom_tool_call` (the
    // invocation) followed later by `custom_tool_call_output` (the
    // result), matched by `call_id`. Handled here alongside the
    // `event_msg` path rather than assuming only one wire shape exists.
    if top_type == "response_item" {
        let Some(payload) = entry.get("payload") else {
            return NormalizationOutcome::Unrecognized {
                discriminator: "response_item:<missing payload>".to_string(),
            };
        };
        let Some(sub_type) = payload.get("type").and_then(|v| v.as_str()) else {
            return NormalizationOutcome::Unrecognized {
                discriminator: "response_item:<missing payload.type>".to_string(),
            };
        };
        return match sub_type {
            "custom_tool_call" if payload.get("name").and_then(|v| v.as_str()) == Some("exec") => {
                if let (Some(call_id), Some(input)) = (
                    payload.get("call_id").and_then(|v| v.as_str()),
                    payload.get("input").and_then(|v| v.as_str()),
                ) {
                    pending_calls.insert(call_id.to_string(), extract_cmd(input));
                }
                // Recognized shape; deliberately produces no canonical
                // message on its own — it is the invocation half of a pair
                // whose result (and any Evidence) is emitted when the
                // matching `custom_tool_call_output` arrives.
                NormalizationOutcome::Ignored {
                    reason: "custom_tool_call: invocation half of a call/output pair, \
                             awaiting matching custom_tool_call_output",
                }
            }
            "custom_tool_call" => NormalizationOutcome::Ignored {
                reason: "custom_tool_call: not an exec invocation, no canonical mapping",
            },
            "custom_tool_call_output" => {
                let Some(call_id) = payload.get("call_id").and_then(|v| v.as_str()) else {
                    return NormalizationOutcome::Unrecognized {
                        discriminator: "response_item:custom_tool_call_output:<missing call_id>"
                            .to_string(),
                    };
                };
                let command = pending_calls.remove(call_id).unwrap_or_default();

                let now = chrono::Utc::now().to_rfc3339();
                let event_id = Uuid::new_v4();
                let event = AgentEvent {
                    id: event_id,
                    session_id: session_id.to_string(),
                    provider: Provider::Codex,
                    kind: EventKind::PostToolUse,
                    observed_at: now.clone(),
                    tool_name: Some("exec_command".to_string()),
                    tool_input: Some(serde_json::json!({"command": command})),
                    tool_response: Some(payload.clone()),
                    raw: entry.clone(),
                };
                let mut out = vec![IngestMessage::Event(event.clone())];

                // FORNX-157: formalized as `CodexCustomToolCallOutputSensor`
                // — see that type for the "Script completed" heuristic and
                // the FORNX-16 real exit-code-text parsing added alongside
                // it.
                let sensor = CodexCustomToolCallOutputSensor;
                let outcome = sensor.collect(&event, &CodexAdapter::new().probe());
                out.extend(outcome.evidence.into_iter().map(IngestMessage::Evidence));
                NormalizationOutcome::Messages(out)
            }
            other => NormalizationOutcome::Unrecognized {
                discriminator: format!("response_item:{other}"),
            },
        };
    }

    if top_type == "session_meta" {
        return NormalizationOutcome::Ignored {
            reason: "session_meta: rollout bookkeeping line, no canonical mapping",
        };
    }

    if top_type != "event_msg" {
        return NormalizationOutcome::Unrecognized {
            discriminator: top_type.to_string(),
        };
    }
    let Some(payload) = entry.get("payload") else {
        return NormalizationOutcome::Unrecognized {
            discriminator: "event_msg:<missing payload>".to_string(),
        };
    };
    let Some(sub_type) = payload.get("type").and_then(|v| v.as_str()) else {
        return NormalizationOutcome::Unrecognized {
            discriminator: "event_msg:<missing payload.type>".to_string(),
        };
    };
    let now = chrono::Utc::now().to_rfc3339();
    let event_id = Uuid::new_v4();

    match sub_type {
        "exec_command_end" => {
            let event = AgentEvent {
                id: event_id,
                session_id: session_id.to_string(),
                provider: Provider::Codex,
                kind: EventKind::PostToolUse,
                observed_at: now.clone(),
                tool_name: Some("exec_command".to_string()),
                tool_input: payload.get("command").cloned(),
                tool_response: Some(payload.clone()),
                raw: entry.clone(),
            };
            let mut out = vec![IngestMessage::Event(event.clone())];
            // FORNX-157: formalized as `CodexExecCommandEndSensor` — see
            // that type for the unchanged literal-exit_code extraction.
            let sensor = CodexExecCommandEndSensor;
            let outcome = sensor.collect(&event, &CodexAdapter::new().probe());
            out.extend(outcome.evidence.into_iter().map(IngestMessage::Evidence));
            NormalizationOutcome::Messages(out)
        }
        "task_complete" => {
            let event = AgentEvent {
                id: event_id,
                session_id: session_id.to_string(),
                provider: Provider::Codex,
                kind: EventKind::SessionEnd,
                observed_at: now.clone(),
                tool_name: None,
                tool_input: None,
                tool_response: None,
                raw: entry.clone(),
            };
            let mut out = vec![IngestMessage::Event(event)];
            if let Some(text) = payload.get("last_agent_message").and_then(|v| v.as_str()) {
                if claims_tests_passed(text) {
                    out.push(IngestMessage::Claim(Claim {
                        id: Uuid::new_v4(),
                        session_id: session_id.to_string(),
                        source_event_id: event_id,
                        text: text.to_string(),
                        subject: "test_result".to_string(),
                        claimed_at: now,
                    }));
                }
            }
            NormalizationOutcome::Messages(out)
        }
        other => NormalizationOutcome::Unrecognized {
            discriminator: format!("event_msg:{other}"),
        },
    }
}

/// Best-effort extraction of the shell command from a `custom_tool_call`'s
/// `input`, which is a JS snippet string like
/// `const r = await tools.exec_command({cmd:"echo hi",workdir:...}); ...`
/// — not structured JSON. No regex dependency; a small manual scan for the
/// `cmd:"..."` argument is enough for provenance purposes. Falls back to
/// the raw input string if the pattern isn't found, rather than dropping
/// the command entirely.
fn extract_cmd(input: &str) -> String {
    if let Some(start) = input.find("cmd:") {
        let rest = &input[start + 4..];
        let rest = rest.trim_start();
        if let Some(quote) = rest.chars().next() {
            if quote == '"' || quote == '\'' {
                let body = &rest[1..];
                let mut result = String::new();
                let mut chars = body.chars();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        if let Some(next) = chars.next() {
                            result.push(next);
                        }
                        continue;
                    }
                    if c == quote {
                        return result;
                    }
                    result.push(c);
                }
            }
        }
    }
    input.to_string()
}

fn claims_tests_passed(text: &str) -> bool {
    let t = text.to_lowercase();
    (t.contains("test") || t.contains("tests"))
        && (t.contains("passed") || t.contains("succeeded") || t.contains("all green"))
        && !t.contains("failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(adapter: &mut CodexAdapter, native: &serde_json::Value) -> NormalizationOutcome {
        adapter.normalize("sess-1", native)
    }

    /// FORNX-155 AC4: the real capabilities this adapter sends, projected
    /// through the legacy wire shape (what `fornax-cli export-spool`
    /// actually emits), must reproduce the exact six bool values this
    /// adapter declared before the formalization — not just a hand-built
    /// fixture that happens to agree.
    #[test]
    fn codex_capabilities_legacy_projection_matches_pre_formalization_bools() {
        let legacy = fornax_types::LegacyCapabilitiesWire::from(&CodexAdapter::new().probe());
        assert!(!legacy.supports_pre_tool_use);
        assert!(legacy.supports_post_tool_use);
        assert!(legacy.supports_tool_response_capture);
        assert!(legacy.supports_session_stop_event);
        assert!(legacy.supports_transcript_tail);
        assert!(!legacy.supports_subagent_lifecycle);
    }

    #[test]
    fn exec_command_end_with_nonzero_exit_produces_event_and_evidence() {
        let entry = serde_json::json!({
            "type": "event_msg",
            "payload": {
                "type": "exec_command_end",
                "command": ["pytest"],
                "exit_code": 1,
                "aggregated_output": "7 failed, 1 passed"
            }
        });
        let msgs = normalize(&mut CodexAdapter::new(), &entry).into_messages();
        assert_eq!(msgs.len(), 2);
        match &msgs[0] {
            IngestMessage::Event(e) => {
                assert_eq!(e.provider, Provider::Codex);
                assert_eq!(e.kind, EventKind::PostToolUse);
            }
            other => panic!("expected Event, got {other:?}"),
        }
        match &msgs[1] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.kind, EvidenceKind::ExitCode);
                assert_eq!(ev.payload["exit_code"], 1);
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    /// FORNX-157: proves the migrated `exec_command_end` path now also
    /// carries structured `EvidenceSource`/trust-class metadata, on top of
    /// the unmodified assertions above (the before/after behavior-
    /// preservation proof for `CodexExecCommandEndSensor`).
    #[test]
    fn exec_command_end_evidence_carries_sensor_source_metadata() {
        let entry = serde_json::json!({
            "type": "event_msg",
            "payload": {
                "type": "exec_command_end",
                "command": ["pytest"],
                "exit_code": 1
            }
        });
        let msgs = normalize(&mut CodexAdapter::new(), &entry).into_messages();
        match &msgs[1] {
            IngestMessage::Evidence(ev) => {
                let source = ev
                    .source
                    .as_ref()
                    .expect("sensor-produced evidence must carry source");
                assert_eq!(source.sensor_name, "codex_exec_command_end_sensor_v1");
                assert_eq!(source.trust_class, TrustClass::AgentAdjacent);
                assert_eq!(source.provider, Some(Provider::Codex));
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    /// FORNX-157: same proof for the `custom_tool_call_output` "Script
    /// completed" heuristic path (`CodexCustomToolCallOutputSensor`).
    #[test]
    fn custom_tool_call_output_evidence_carries_sensor_source_metadata() {
        let mut adapter = CodexAdapter::new();
        let call = serde_json::json!({
            "type": "response_item",
            "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c1", "input": "echo hi"}
        });
        let _ = normalize(&mut adapter, &call);

        let output = serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "c1",
                "output": [{"text": "Script completed"}]
            }
        });
        let msgs = normalize(&mut adapter, &output).into_messages();
        match &msgs[1] {
            IngestMessage::Evidence(ev) => {
                let source = ev
                    .source
                    .as_ref()
                    .expect("sensor-produced evidence must carry source");
                assert_eq!(
                    source.sensor_name,
                    "codex_custom_tool_call_output_sensor_v1"
                );
                assert_eq!(source.trust_class, TrustClass::AgentAdjacent);
                assert_eq!(source.provider, Some(Provider::Codex));
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    #[test]
    fn exec_command_end_without_exit_code_produces_only_event() {
        let entry = serde_json::json!({
            "type": "event_msg",
            "payload": {"type": "exec_command_end", "command": ["pwd"]}
        });
        let msgs = normalize(&mut CodexAdapter::new(), &entry).into_messages();
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn task_complete_with_passing_claim_produces_event_and_claim() {
        let entry = serde_json::json!({
            "type": "event_msg",
            "payload": {"type": "task_complete", "last_agent_message": "All tests passed."}
        });
        let msgs = normalize(&mut CodexAdapter::new(), &entry).into_messages();
        assert_eq!(msgs.len(), 2);
        assert!(matches!(&msgs[1], IngestMessage::Claim(c) if c.subject == "test_result"));
    }

    #[test]
    fn task_complete_without_a_claim_producing_message_is_event_only() {
        let entry = serde_json::json!({
            "type": "event_msg",
            "payload": {"type": "task_complete", "last_agent_message": "Done, see the diff."}
        });
        let msgs = normalize(&mut CodexAdapter::new(), &entry).into_messages();
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn session_meta_line_is_ignored_not_unrecognized() {
        let entry = serde_json::json!({"type": "session_meta", "payload": {"session_id": "s"}});
        match normalize(&mut CodexAdapter::new(), &entry) {
            NormalizationOutcome::Ignored { .. } => {}
            other => panic!("expected Ignored, got {other:?}"),
        }
    }

    #[test]
    fn unknown_event_msg_subtype_is_unrecognized_not_a_crash() {
        let entry = serde_json::json!({"type": "event_msg", "payload": {"type": "token_count"}});
        match normalize(&mut CodexAdapter::new(), &entry) {
            NormalizationOutcome::Unrecognized { discriminator } => {
                assert_eq!(discriminator, "event_msg:token_count")
            }
            other => panic!("expected Unrecognized, got {other:?}"),
        }
    }

    #[test]
    fn missing_type_field_is_unrecognized_not_a_crash() {
        let entry = serde_json::json!({"payload": {}});
        match normalize(&mut CodexAdapter::new(), &entry) {
            NormalizationOutcome::Unrecognized { .. } => {}
            other => panic!("expected Unrecognized, got {other:?}"),
        }
    }

    #[test]
    fn custom_tool_call_then_output_correlate_into_heuristic_evidence() {
        // Confirmed real codex-cli 0.147.0 shapes (2026-08-29 live capture,
        // FORNX-55): shell exec has no exec_command_end event at all; it is
        // this response_item pair matched by call_id.
        let mut adapter = CodexAdapter::new();
        let call = serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": "call_1",
                "name": "exec",
                "input": "const r = await tools.exec_command({cmd:\"echo hi\",workdir:\"/tmp\"}); text(r.output);\n"
            }
        });
        match normalize(&mut adapter, &call) {
            NormalizationOutcome::Ignored { .. } => {}
            other => panic!("expected Ignored, got {other:?}"),
        }
        assert_eq!(
            adapter.pending_calls.get("call_1").map(String::as_str),
            Some("echo hi")
        );

        let output = serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "call_1",
                "output": [
                    {"type": "input_text", "text": "Script completed\nWall time 0.1 seconds\nOutput:\n"},
                    {"type": "input_text", "text": "hi\n"}
                ]
            }
        });
        let msgs = normalize(&mut adapter, &output).into_messages();
        assert_eq!(msgs.len(), 2);
        assert!(
            adapter.pending_calls.is_empty(),
            "call_id should be consumed"
        );
        match &msgs[1] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.payload["exit_code"], 0);
                assert_eq!(ev.payload["command"], "echo hi");
                assert_eq!(ev.payload["heuristic"], true);
                assert!(ev.provenance.contains("script_completed"));
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    /// FORNX-16: real captured failure shape (codex-cli 0.147.0, live
    /// capture 2026-08-31, `codex exec --disable unified_exec`, command
    /// `exit 1` through `tools.shell_command`) — a real nonzero exit code
    /// must be extracted from the `"Exit code: 1"` text, non-heuristic.
    #[test]
    fn custom_tool_call_output_with_real_failure_marker_produces_nonzero_exit_code_evidence() {
        let mut adapter = CodexAdapter::new();
        let call = serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": "call_fail",
                "name": "exec",
                "input": "const r = await tools.shell_command({command:\"exit 1\",workdir:\"/tmp\"}); text(r)\n"
            }
        });
        let _ = normalize(&mut adapter, &call);

        let output = serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "call_fail",
                "output": [
                    {"type": "input_text", "text": "Script failed\nWall time 0.1 seconds\nOutput:\n"},
                    {"type": "input_text", "text": "Script error:\nExit code: 1\nWall time: 0.1 seconds\nOutput:\n"}
                ]
            }
        });
        let msgs = normalize(&mut adapter, &output).into_messages();
        assert_eq!(msgs.len(), 2);
        match &msgs[1] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.kind, EvidenceKind::ExitCode);
                assert_eq!(ev.payload["exit_code"], 1);
                assert_eq!(ev.payload["heuristic"], false);
                assert!(ev.provenance.contains("exit_code_text"));
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    /// Same real shape, success case with an explicit `"Exit code: 0"` —
    /// must also produce a non-heuristic Evidence (not the old zero-guess
    /// heuristic), since a real value is present.
    #[test]
    fn custom_tool_call_output_with_real_success_exit_code_text_is_non_heuristic() {
        let mut adapter = CodexAdapter::new();
        let call = serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": "call_ok",
                "name": "exec",
                "input": "const r = await tools.shell_command({command:\"echo hi\",workdir:\"/tmp\"}); text(r)\n"
            }
        });
        let _ = normalize(&mut adapter, &call);

        let output = serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "call_ok",
                "output": [
                    {"type": "input_text", "text": "Script completed\nWall time 0.1 seconds\nOutput:\n"},
                    {"type": "input_text", "text": "Exit code: 0\nWall time: 0.1 seconds\nOutput:\nhello\n"}
                ]
            }
        });
        let msgs = normalize(&mut adapter, &output).into_messages();
        match &msgs[1] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.payload["exit_code"], 0);
                assert_eq!(ev.payload["heuristic"], false);
                assert!(ev.provenance.contains("exit_code_text"));
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    /// The genuine `unified_exec` gap (no exit-code text at all, even on a
    /// real failing command — confirmed live 2026-08-31) must remain the
    /// unchanged zero-guess heuristic, not silently upgraded.
    #[test]
    fn custom_tool_call_output_without_exit_code_text_keeps_old_heuristic() {
        let mut adapter = CodexAdapter::new();
        let call = serde_json::json!({
            "type": "response_item",
            "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c_uexec", "input": "false"}
        });
        let _ = normalize(&mut adapter, &call);

        let output = serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "c_uexec",
                "output": [{"type": "input_text", "text": "Script completed\nWall time 0.1 seconds\nOutput:\n"}]
            }
        });
        let msgs = normalize(&mut adapter, &output).into_messages();
        match &msgs[1] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.payload["exit_code"], 0);
                assert_eq!(ev.payload["heuristic"], true);
                assert!(ev.provenance.contains("script_completed"));
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    /// Regression: a genuinely successful `unified_exec` command whose own
    /// stdout happens to contain the literal text `"Exit code: 1"` (e.g. a
    /// nested build tool echoing that as part of its normal output) must
    /// never forge a fabricated nonzero, `heuristic: false` exit code. Only
    /// a block whose *own* leading text is the marker counts — see
    /// `parse_exit_code_from_blocks`'s doc comment for why joining blocks
    /// before searching would be unsafe here.
    #[test]
    fn stdout_containing_the_exit_code_words_does_not_forge_a_fake_marker() {
        let mut adapter = CodexAdapter::new();
        let call = serde_json::json!({
            "type": "response_item",
            "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c_stdout_spoof", "input": "make"}
        });
        let _ = normalize(&mut adapter, &call);

        let output = serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "c_stdout_spoof",
                "output": [
                    {"type": "input_text", "text": "Script completed\nWall time 0.1 seconds\nOutput:\n"},
                    {"type": "input_text", "text": "make: Exit code: 1 (from a nested build log)\n"}
                ]
            }
        });
        let msgs = normalize(&mut adapter, &output).into_messages();
        match &msgs[1] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(
                    ev.payload["exit_code"], 0,
                    "must not adopt a number from the command's own stdout"
                );
                assert_eq!(ev.payload["heuristic"], true);
                assert!(ev.provenance.contains("script_completed"));
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    #[test]
    fn custom_tool_call_output_without_recognized_marker_produces_only_event() {
        let mut adapter = CodexAdapter::new();
        let output = serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "call_unknown",
                "output": [{"type": "input_text", "text": "something unexpected\n"}]
            }
        });
        let msgs = normalize(&mut adapter, &output).into_messages();
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn session_id_discovered_from_session_meta_is_used_over_the_hint() {
        let mut adapter = CodexAdapter::new();
        let meta =
            serde_json::json!({"type": "session_meta", "payload": {"session_id": "real-sess"}});
        let _ = adapter.normalize("file-path-hint", &meta);

        let entry = serde_json::json!({
            "type": "event_msg",
            "payload": {"type": "exec_command_end", "command": ["pwd"], "exit_code": 0}
        });
        let msgs = adapter.normalize("file-path-hint", &entry).into_messages();
        match &msgs[0] {
            IngestMessage::Event(e) => assert_eq!(e.session_id, "real-sess"),
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn capabilities_carry_adapter_version_and_session_id_notes() {
        let adapter = CodexAdapter::new();
        let caps = stamped_capabilities(&adapter, "sess-1");
        assert_eq!(
            caps.notes.get("adapter_version").map(String::as_str),
            Some(ADAPTER_VERSION)
        );
        assert_eq!(
            caps.notes.get("session_id").map(String::as_str),
            Some("sess-1")
        );
    }
}
