//! opencode adapter (FORNX-161, architecture-fitness test for FORNX-155–160).
//! Formalized against the `fornax_types::AgentAdapter` contract (FORNX-156),
//! same as `fornax-adapter-claude`/`fornax-adapter-codex`.
//!
//! opencode's integration mechanism is genuinely distinct from both existing
//! providers: it is an in-process JavaScript/TypeScript plugin
//! (`@opencode-ai/plugin`'s `Plugin`/`Hooks` API) that opencode's own runtime
//! invokes synchronously around real events — not an external hook-script
//! process spawned per event (Claude Code) and not a poll/tail of a
//! transcript file opencode writes on its own schedule (Codex). A small
//! companion JS plugin (`plugin/fornax-capture.js`) forwards each hook
//! invocation, verbatim, as one NDJSON line to this crate's binary
//! (`fornax-hook-opencode`) over stdin; this crate never talks to opencode's
//! JS/TS runtime directly.
//!
//! The wire contract between the JS plugin and this adapter is exactly the
//! shape the plugin appends: `{"hook": "<hook name>", "at": "<ISO8601>",
//! "payload": <the hook's real input/output>}` — see
//! `plugin/fornax-capture.js` for the emitting side and
//! `crates/fornax-adapter-conformance/fixtures/opencode/*.json` for real,
//! sanitized captures of every shape this adapter recognizes.
//!
//! Scope (FORNX-161 AC: "one real event path", not broad parity): this
//! adapter translates `tool.execute.before`/`tool.execute.after` (the
//! flagship path — genuinely exercises `AgentEvent`, `EvidenceSensor`,
//! `RuntimeCapabilities`) and the `event` hook's `session.created`/
//! `session.idle` session-lifecycle pair. Every other real hook opencode's
//! plugin API exposes (`chat.message`, `permission.ask`, `plugin.init`, ...)
//! is deliberately `Ignored`, not translated — a recognized shape with no
//! canonical signal class mapped to it yet, not a parse failure.

use fornax_types::{
    collect_with_disable_check, AgentAdapter, AgentEvent, CapabilityProbe, CollectionMethod,
    ContentClass, EventKind, Evidence, EvidenceKind, EvidenceSensor, EvidenceSource,
    ExtensionEnvelope, IngestMessage, NormalizationOutcome, ProcessObservationDetail,
    ProcessObservationPayload, Provider, RuntimeCapabilities, SensorDisableConfig, SensorOutcome,
    SignalAvailability, TrustClass,
};
use uuid::Uuid;

/// This adapter implementation's own version — independent of the opencode
/// CLI version, which belongs in a `CapabilitySignal::detail` string (see
/// `OpenCodeAdapter::probe`).
pub const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The opencode CLI version this adapter's shapes were confirmed against
/// (`opencode --version`, captured 2026-08-30). See
/// `docs/research/adapter-capability-matrix.md`.
pub const CONFIRMED_OPENCODE_VERSION: &str = "1.18.25";

/// Stateful like `fornax-adapter-codex` (not stateless like
/// `fornax-adapter-claude`): opencode's plugin is loaded once per opencode
/// process and its hooks fire for the life of that process's session(s), so
/// this adapter instance persists across many `normalize()` calls and
/// remembers the most recently observed session id as a fallback for a hook
/// payload that doesn't carry one directly (`plugin.init` fires before any
/// session exists at all).
#[derive(Debug, Default)]
pub struct OpenCodeAdapter {
    session_id: Option<String>,
}

impl OpenCodeAdapter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CapabilityProbe for OpenCodeAdapter {
    /// Declared conservatively, matching what this adapter actually
    /// translates (D5, ADR 0001) — confirmed against a real, live opencode
    /// v1.18.25 session on 2026-08-30 (see
    /// `docs/research/0002-third-provider-fitness-report.md`).
    ///
    /// The standout finding, and the reason FORNX-161 exists: `ProcessResult`
    /// is `Available` here, not `Unsupported` (Claude Code) or `Unavailable`
    /// (Codex, heuristic-only). opencode's `tool.execute.after` hook payload
    /// carries a literal `output.metadata.exit` integer — no heuristic
    /// inference needed, the first provider of the three that genuinely
    /// exposes this.
    fn probe(&self) -> RuntimeCapabilities {
        use fornax_types::{CapabilitySignal, SignalClass};
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::OpenCode,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolInvocation,
                    state: SignalAvailability::Available,
                    detail: Some(
                        "opencode's tool.execute.before plugin hook fires synchronously \
                         before the tool runs and can even mutate its args; this adapter \
                         only observes it (never rewrites)"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::ToolResultPayload,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::ProcessResult,
                    state: SignalAvailability::Available,
                    detail: Some(
                        "tool.execute.after's output.metadata.exit is a literal integer \
                         exit code — confirmed real (bash tool, opencode v1.18.25), not a \
                         heuristic"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::SessionLifecycle,
                    state: SignalAvailability::Available,
                    detail: Some("event hook's session.created/session.idle payloads".to_string()),
                },
                CapabilitySignal {
                    class: SignalClass::SubagentLifecycle,
                    state: SignalAvailability::Unsupported,
                    detail: Some(
                        "the @opencode-ai/plugin Hooks interface (v1.18.25) has no \
                         subagent-specific hook — structurally absent, not merely unobserved \
                         this session"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::FinalResponse,
                    state: SignalAvailability::Unavailable,
                    detail: Some(
                        "the event hook's message.updated/message.part.updated text events \
                         genuinely carry the agent's final response, but this adapter \
                         version does not yet translate them — scoped out per FORNX-161's \
                         single-event-path AC, not a structural gap"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::ReasoningSummary,
                    state: SignalAvailability::Unsupported,
                    detail: Some(
                        "no reasoning-summary hook or message-part type observed in the \
                         @opencode-ai/plugin Hooks interface (v1.18.25) for a local \
                         tool-calling model session"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::RawReasoning,
                    state: SignalAvailability::Unsupported,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::TokenLogprobs,
                    state: SignalAvailability::Unsupported,
                    detail: Some(
                        "no logprobs field anywhere in the @opencode-ai/plugin Hooks \
                         interface (v1.18.25)"
                            .to_string(),
                    ),
                },
                CapabilitySignal {
                    class: SignalClass::InternalModelSignals,
                    state: SignalAvailability::Unavailable,
                    detail: Some(
                        "message.updated events carry token/cost telemetry in principle; \
                         not translated by this adapter version"
                            .to_string(),
                    ),
                },
            ],
            notes: [(
                "confirmed_opencode_version".to_string(),
                CONFIRMED_OPENCODE_VERSION.to_string(),
            )]
            .into(),
        }
    }
}

impl AgentAdapter for OpenCodeAdapter {
    fn provider(&self) -> Provider {
        Provider::OpenCode
    }

    fn adapter_version(&self) -> &'static str {
        ADAPTER_VERSION
    }

    fn normalize(
        &mut self,
        session_hint: &str,
        native: &serde_json::Value,
    ) -> NormalizationOutcome {
        translate(self, session_hint, native)
    }
}

fn stamped_capabilities(adapter: &OpenCodeAdapter, session_id: &str) -> RuntimeCapabilities {
    let mut caps = adapter.probe();
    caps.notes
        .insert("session_id".to_string(), session_id.to_string());
    caps.notes.insert(
        "adapter_version".to_string(),
        adapter.adapter_version().to_string(),
    );
    caps
}

/// FORNX-157: opencode's `tool.execute.after` hook is the first real
/// producer of a *literal* exit code across all three adapters — Claude
/// Code's equivalent sensor falls back to a stdout/stderr heuristic, and
/// Codex's to a "Script completed" text match. No heuristic branch exists
/// here on purpose: if `output.metadata.exit` is ever missing on a future
/// opencode version, that is exactly the kind of upstream schema drift
/// `docs/contributing/adding-an-adapter.md`'s "Detecting upstream schema
/// drift" section describes, not something to paper over with a guess.
struct OpenCodeExitCodeSensor {
    adapter_version: &'static str,
}

impl EvidenceSensor for OpenCodeExitCodeSensor {
    fn name(&self) -> &'static str {
        "opencode_tool_exit_code_sensor_v1"
    }

    fn required_capabilities(&self) -> &'static [fornax_types::SignalClass] {
        &[fornax_types::SignalClass::ProcessResult]
    }

    fn trust_class(&self) -> TrustClass {
        // opencode's own tool.execute.after payload is the provider's
        // account of what happened, not something Fornax measured itself.
        TrustClass::AgentAdjacent
    }

    fn collection_method(&self) -> CollectionMethod {
        // `HookCallback`'s doc ("an in-process callback invoked
        // synchronously by the provider around an action") is, taken
        // literally, a *more* exact fit for opencode's real in-process
        // plugin mechanism than for the Claude Code hook-script process it
        // was originally named after (an external process spawned per
        // event, not literally in-process) — see the fitness report for
        // why this counted as evidence the taxonomy already generalizes,
        // not a gap requiring a new variant.
        CollectionMethod::HookCallback
    }

    fn collector_version(&self) -> Option<String> {
        Some(self.adapter_version.to_string())
    }

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
        let Some(exit) = resp.pointer("/metadata/exit").and_then(|v| v.as_i64()) else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some("no output.metadata.exit field on this tool_response".to_string()),
            );
        };

        let extension = build_tool_telemetry_extension(self.adapter_version, resp);

        SensorOutcome::collected(vec![Evidence {
            id: Uuid::new_v4(),
            session_id: event.session_id.clone(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: event.observed_at.clone(),
            payload: serde_json::json!({
                "command": event
                    .tool_input
                    .as_ref()
                    .and_then(|ti| ti.get("command"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                "exit_code": exit,
                "heuristic": false,
            }),
            provenance: format!(
                "opencode:{v}:tool.execute.after#metadata.exit",
                v = self.adapter_version
            ),
            source: Some(EvidenceSource::now(
                self.name(),
                self.trust_class(),
                Some(Provider::OpenCode),
                self.collection_method(),
                self.collector_version(),
            )),
            extension,
        }])
    }
}

/// FORNX-91 "process evidence" sensor: promotes opencode's own
/// `output.time.start`/`output.time.end` timestamps — already reaching this
/// adapter today, previously only carried forward opaquely inside
/// [`build_tool_telemetry_extension`]'s `ExtensionEnvelope` — into canonical
/// `ProcessObservation` evidence with a computed wall-clock duration.
///
/// This is **not** a new OS-level process-monitoring subsystem: it reads
/// fields already present on the same `tool.execute.after` payload
/// [`OpenCodeExitCodeSensor`] reads, and does nothing if they are absent —
/// see the caveat below. `TrustClass::AgentAdjacent`, same class as
/// `OpenCodeExitCodeSensor`: both are opencode's own account of what
/// happened, not something Fornax measured independently.
///
/// **What it can observe**: `duration_ms = time.end - time.start`, and — as
/// a genuine, if narrow, verification contribution — whether those two
/// timestamps are even internally consistent (`end < start` is reported as
/// `SignalAvailability::CollectionFailed`, not a fabricated negative
/// duration).
/// **What it cannot observe**: wall-clock time independent of what opencode
/// itself reported, or anything for a tool call whose payload omits `time`
/// entirely.
///
/// **Caveat**: unlike `output.metadata.exit` (empirically confirmed real
/// against opencode v1.18.25 — see `OpenCodeExitCodeSensor`'s doc comment),
/// `output.time.{start,end}`'s presence has not been independently
/// reconfirmed against a live capture as part of this ticket — it was
/// already referenced by `build_tool_telemetry_extension`'s doc comment
/// before this sensor existed. If a future live capture shows the field is
/// absent or shaped differently, this sensor's honest `Unavailable`
/// response (never a fabricated duration) is exactly the behavior that
/// makes that discovery safe rather than silently wrong — re-verify before
/// trusting this sensor's `Available` case in production, same standing
/// caution as the rest of `docs/research/adapter-capability-matrix.md`.
/// The unit is likewise assumed, not confirmed: `duration_ms` treats
/// `time.start`/`time.end` as epoch milliseconds (the field's name
/// suggests it, nothing captured so far confirms it) — re-verify the unit
/// alongside the field's existence.
struct OpenCodeCommandDurationSensor {
    adapter_version: &'static str,
}

impl EvidenceSensor for OpenCodeCommandDurationSensor {
    fn name(&self) -> &'static str {
        "opencode_command_duration_sensor_v1"
    }

    fn required_capabilities(&self) -> &'static [fornax_types::SignalClass] {
        // Duration is a companion metric to the literal exit code this
        // capability already gates — see `OpenCodeExitCodeSensor`.
        &[fornax_types::SignalClass::ProcessResult]
    }

    fn trust_class(&self) -> TrustClass {
        TrustClass::AgentAdjacent
    }

    fn collection_method(&self) -> CollectionMethod {
        CollectionMethod::HookCallback
    }

    fn collector_version(&self) -> Option<String> {
        Some(self.adapter_version.to_string())
    }

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
        let start = resp.pointer("/time/start").and_then(|v| v.as_i64());
        let end = resp.pointer("/time/end").and_then(|v| v.as_i64());
        let (Some(start), Some(end)) = (start, end) else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some("no time.start/time.end fields on this tool_response".to_string()),
            );
        };

        if end < start {
            return SensorOutcome::not_collected(
                SignalAvailability::CollectionFailed,
                Some(format!(
                    "time.end ({end}) is before time.start ({start}) — inconsistent timing data"
                )),
            );
        }
        let duration_ms = end - start;

        SensorOutcome::collected(vec![Evidence {
            id: Uuid::new_v4(),
            session_id: event.session_id.clone(),
            source_event_id: event.id,
            kind: EvidenceKind::ProcessObservation,
            observed_at: event.observed_at.clone(),
            payload: serde_json::to_value(ProcessObservationPayload {
                description: format!("tool call completed in {duration_ms}ms"),
                observation: Some(ProcessObservationDetail::CommandDuration { duration_ms }),
            })
            .expect("ProcessObservationPayload always serializes"),
            provenance: format!(
                "opencode:{v}:tool.execute.after#time",
                v = self.adapter_version
            ),
            source: Some(EvidenceSource::now(
                self.name(),
                self.trust_class(),
                Some(Provider::OpenCode),
                self.collection_method(),
                self.collector_version(),
            )),
            extension: None,
        }])
    }
}

/// FORNX-158: the first real adapter usage of `ExtensionEnvelope` (neither
/// Claude nor Codex populates it — see the fitness report). opencode's
/// `tool.execute.after` payload carries fields with no home in
/// `ExitCodePayload`'s canonical shape — a human-readable `title`, precise
/// `time.start`/`time.end` timestamps, and a `truncated` flag on the
/// captured output — real provider-specific telemetry, deliberately chosen
/// to carry forward rather than a catch-all for data this adapter doesn't
/// understand (see `extension.rs`'s "not a laundering path" module doc).
/// Returns `None` (no envelope) rather than an empty one when opencode
/// didn't report any of these fields, matching the "`None` is the common
/// case" convention `Evidence::extension`'s own doc describes.
fn build_tool_telemetry_extension(
    adapter_version: &str,
    resp: &serde_json::Value,
) -> Option<ExtensionEnvelope> {
    let title = resp.get("title").cloned();
    let time = resp.get("time").cloned();
    let truncated = resp.pointer("/metadata/truncated").cloned();
    if title.is_none() && time.is_none() && truncated.is_none() {
        return None;
    }
    let mut fields = serde_json::Map::new();
    if let Some(t) = title {
        fields.insert("title".to_string(), t);
    }
    if let Some(t) = time {
        fields.insert("time".to_string(), t);
    }
    if let Some(t) = truncated {
        fields.insert("truncated".to_string(), t);
    }
    Some(ExtensionEnvelope::new(
        Provider::OpenCode,
        adapter_version,
        ContentClass::ToolTelemetry,
        serde_json::Value::Object(fields),
    ))
}

fn session_id_from_event_payload(payload: &serde_json::Value) -> Option<String> {
    payload
        .pointer("/properties/sessionID")
        .and_then(|v| v.as_str())
        .map(String::from)
}

fn translate(
    adapter: &mut OpenCodeAdapter,
    session_hint: &str,
    native: &serde_json::Value,
) -> NormalizationOutcome {
    let Some(hook) = native.get("hook").and_then(|v| v.as_str()) else {
        return NormalizationOutcome::Unrecognized {
            discriminator: "<missing hook field>".to_string(),
        };
    };
    let payload = native
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let now = chrono::Utc::now().to_rfc3339();

    match hook {
        "tool.execute.before" => {
            let session_id = payload
                .pointer("/input/sessionID")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| session_hint.to_string());
            adapter.session_id = Some(session_id.clone());
            let tool_name = payload
                .pointer("/input/tool")
                .and_then(|v| v.as_str())
                .map(String::from);
            let tool_input = payload.pointer("/output/args").cloned();

            let event = AgentEvent {
                id: Uuid::new_v4(),
                session_id: session_id.clone(),
                provider: Provider::OpenCode,
                kind: EventKind::PreToolUse,
                observed_at: now,
                tool_name,
                tool_input,
                tool_response: None,
                raw: native.clone(),
            };
            let caps = stamped_capabilities(adapter, &session_id);
            NormalizationOutcome::Messages(vec![
                IngestMessage::Capabilities(caps),
                IngestMessage::Event(event),
            ])
        }
        "tool.execute.after" => {
            let session_id = payload
                .pointer("/input/sessionID")
                .and_then(|v| v.as_str())
                .map(String::from)
                .or_else(|| adapter.session_id.clone())
                .unwrap_or_else(|| session_hint.to_string());
            adapter.session_id = Some(session_id.clone());
            let tool_name = payload
                .pointer("/input/tool")
                .and_then(|v| v.as_str())
                .map(String::from);
            let tool_input = payload.pointer("/input/args").cloned();
            let tool_response = payload.get("output").cloned();

            let event = AgentEvent {
                id: Uuid::new_v4(),
                session_id: session_id.clone(),
                provider: Provider::OpenCode,
                kind: EventKind::PostToolUse,
                observed_at: now,
                tool_name,
                tool_input,
                tool_response,
                raw: native.clone(),
            };
            let caps = stamped_capabilities(adapter, &session_id);
            // FORNX-302: loaded once per event; every sensor call below
            // routes through `collect_with_disable_check` so a sensor named
            // in `$FORNAX_HOME/config.toml`'s `[sensors].disabled` reports
            // `SignalAvailability::Disabled` instead of running.
            let sensor_config = SensorDisableConfig::load_default();
            let mut out = vec![
                IngestMessage::Capabilities(caps.clone()),
                IngestMessage::Event(event.clone()),
            ];
            let sensor = OpenCodeExitCodeSensor {
                adapter_version: adapter.adapter_version(),
            };
            let outcome = collect_with_disable_check(&sensor, &event, &caps, &sensor_config);
            out.extend(outcome.evidence.into_iter().map(IngestMessage::Evidence));

            // FORNX-91: promote time.start/time.end (already reaching this
            // adapter, previously only carried into the extension envelope)
            // into canonical duration evidence.
            let duration_sensor = OpenCodeCommandDurationSensor {
                adapter_version: adapter.adapter_version(),
            };
            let duration_outcome =
                collect_with_disable_check(&duration_sensor, &event, &caps, &sensor_config);
            out.extend(
                duration_outcome
                    .evidence
                    .into_iter()
                    .map(IngestMessage::Evidence),
            );
            NormalizationOutcome::Messages(out)
        }
        "event" => {
            let event_type = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let kind = match event_type {
                "session.created" => EventKind::SessionStart,
                "session.idle" => EventKind::SessionEnd,
                "" => {
                    return NormalizationOutcome::Unrecognized {
                        discriminator: "event:<missing type>".to_string(),
                    }
                }
                _ => {
                    // A real, recognized opencode event-bus type (there are
                    // many: message.updated, session.updated, ...) this
                    // adapter deliberately doesn't map to a canonical
                    // signal class yet — recognized shape, not a parse
                    // failure, per FORNX-161's single-event-path scope.
                    return NormalizationOutcome::Ignored {
                        reason: "opencode event-bus type not mapped to a canonical signal class",
                    };
                }
            };
            let session_id = session_id_from_event_payload(&payload)
                .or_else(|| adapter.session_id.clone())
                .unwrap_or_else(|| session_hint.to_string());
            adapter.session_id = Some(session_id.clone());

            let event = AgentEvent {
                id: Uuid::new_v4(),
                session_id: session_id.clone(),
                provider: Provider::OpenCode,
                kind,
                observed_at: now,
                tool_name: None,
                tool_input: None,
                tool_response: None,
                raw: native.clone(),
            };
            let caps = stamped_capabilities(adapter, &session_id);
            NormalizationOutcome::Messages(vec![
                IngestMessage::Capabilities(caps),
                IngestMessage::Event(event),
            ])
        }
        "chat.message" | "permission.ask" | "plugin.init" => NormalizationOutcome::Ignored {
            reason: "recognized opencode plugin hook with no canonical signal class mapped yet",
        },
        other => NormalizationOutcome::Unrecognized {
            discriminator: format!("hook:{other}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{EventKind, IngestMessage, Provider, SignalAvailability, SignalClass};

    fn normalize(native: &serde_json::Value) -> NormalizationOutcome {
        OpenCodeAdapter::new().normalize("unused-hint", native)
    }

    #[test]
    fn probe_declares_process_result_available_not_heuristic() {
        let caps = OpenCodeAdapter::new().probe();
        assert_eq!(
            caps.state_of(&SignalClass::ProcessResult),
            SignalAvailability::Available
        );
        assert_eq!(
            caps.state_of(&SignalClass::SubagentLifecycle),
            SignalAvailability::Unsupported
        );
        assert_eq!(
            caps.state_of(&SignalClass::FinalResponse),
            SignalAvailability::Unavailable
        );
    }

    #[test]
    fn tool_execute_after_with_literal_exit_produces_event_and_non_heuristic_evidence() {
        let native = serde_json::json!({
            "hook": "tool.execute.after",
            "payload": {
                "input": {"tool": "bash", "sessionID": "ses-1", "callID": "call_1", "args": {"command": "ls -la ."}},
                "output": {"title": "ls -la .", "metadata": {"output": "total 0\n", "exit": 0, "truncated": false}, "output": "total 0\n"}
            }
        });
        let msgs = normalize(&native).into_messages();
        assert_eq!(msgs.len(), 3);
        assert!(matches!(&msgs[0], IngestMessage::Capabilities(_)));
        match &msgs[1] {
            IngestMessage::Event(e) => {
                assert_eq!(e.provider, Provider::OpenCode);
                assert_eq!(e.kind, EventKind::PostToolUse);
                assert_eq!(e.session_id, "ses-1");
                assert_eq!(e.tool_name.as_deref(), Some("bash"));
            }
            other => panic!("expected Event, got {other:?}"),
        }
        match &msgs[2] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.payload["exit_code"], 0);
                assert_eq!(ev.payload["heuristic"], false);
                assert!(ev.provenance.contains("metadata.exit"));
                let source = ev.source.as_ref().expect("evidence must carry source");
                assert_eq!(source.trust_class, TrustClass::AgentAdjacent);
                assert_eq!(source.collection_method, CollectionMethod::HookCallback);
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    #[test]
    fn tool_execute_after_without_exit_field_produces_only_event() {
        let native = serde_json::json!({
            "hook": "tool.execute.after",
            "payload": {
                "input": {"tool": "bash", "sessionID": "ses-1", "callID": "call_1", "args": {}},
                "output": {"title": "x", "metadata": {"output": ""}, "output": ""}
            }
        });
        let msgs = normalize(&native).into_messages();
        assert_eq!(msgs.len(), 2);
        assert!(matches!(&msgs[0], IngestMessage::Capabilities(_)));
        assert!(matches!(&msgs[1], IngestMessage::Event(_)));
    }

    #[test]
    fn tool_execute_before_produces_pre_tool_use_event() {
        let native = serde_json::json!({
            "hook": "tool.execute.before",
            "payload": {
                "input": {"tool": "bash", "sessionID": "ses-1", "callID": "call_1"},
                "output": {"args": {"command": "ls"}}
            }
        });
        let msgs = normalize(&native).into_messages();
        assert_eq!(msgs.len(), 2);
        match &msgs[1] {
            IngestMessage::Event(e) => assert_eq!(e.kind, EventKind::PreToolUse),
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn session_created_event_produces_session_start() {
        let native = serde_json::json!({
            "hook": "event",
            "payload": {"type": "session.created", "properties": {"sessionID": "ses-1"}}
        });
        let msgs = normalize(&native).into_messages();
        assert_eq!(msgs.len(), 2);
        match &msgs[1] {
            IngestMessage::Event(e) => assert_eq!(e.kind, EventKind::SessionStart),
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn session_idle_event_produces_session_end() {
        let native = serde_json::json!({
            "hook": "event",
            "payload": {"type": "session.idle", "properties": {"sessionID": "ses-1"}}
        });
        let msgs = normalize(&native).into_messages();
        assert_eq!(msgs.len(), 2);
        match &msgs[1] {
            IngestMessage::Event(e) => assert_eq!(e.kind, EventKind::SessionEnd),
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn unmapped_event_bus_type_is_ignored_not_unrecognized() {
        let native = serde_json::json!({
            "hook": "event",
            "payload": {"type": "message.updated", "properties": {"sessionID": "ses-1"}}
        });
        match normalize(&native) {
            NormalizationOutcome::Ignored { .. } => {}
            other => panic!("expected Ignored, got {other:?}"),
        }
    }

    #[test]
    fn chat_message_hook_is_ignored() {
        let native = serde_json::json!({"hook": "chat.message", "payload": {}});
        match normalize(&native) {
            NormalizationOutcome::Ignored { .. } => {}
            other => panic!("expected Ignored, got {other:?}"),
        }
    }

    #[test]
    fn unknown_hook_is_unrecognized_not_a_crash() {
        let native = serde_json::json!({"hook": "some.future.hook", "payload": {}});
        match normalize(&native) {
            NormalizationOutcome::Unrecognized { discriminator } => {
                assert_eq!(discriminator, "hook:some.future.hook")
            }
            other => panic!("expected Unrecognized, got {other:?}"),
        }
    }

    #[test]
    fn missing_hook_field_is_unrecognized_not_a_crash() {
        let native = serde_json::json!({"payload": {}});
        match normalize(&native) {
            NormalizationOutcome::Unrecognized { .. } => {}
            other => panic!("expected Unrecognized, got {other:?}"),
        }
    }

    #[test]
    fn call_pair_correlates_session_id_across_calls_on_the_same_adapter_instance() {
        let mut adapter = OpenCodeAdapter::new();
        let before = serde_json::json!({
            "hook": "tool.execute.before",
            "payload": {"input": {"tool": "bash", "sessionID": "ses-42", "callID": "c1"}, "output": {"args": {}}}
        });
        let after = serde_json::json!({
            "hook": "tool.execute.after",
            "payload": {"input": {"tool": "bash", "callID": "c1", "args": {}}, "output": {"metadata": {"exit": 0}}}
        });
        let _ = adapter.normalize("hint", &before).into_messages();
        let msgs = adapter.normalize("hint", &after).into_messages();
        match &msgs[1] {
            IngestMessage::Event(e) => assert_eq!(e.session_id, "ses-42"),
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn capabilities_carry_adapter_version_and_session_id_notes() {
        let native = serde_json::json!({
            "hook": "event",
            "payload": {"type": "session.created", "properties": {"sessionID": "ses-1"}}
        });
        let msgs = normalize(&native).into_messages();
        match &msgs[0] {
            IngestMessage::Capabilities(caps) => {
                assert_eq!(
                    caps.notes.get("adapter_version").map(String::as_str),
                    Some(ADAPTER_VERSION)
                );
                assert_eq!(
                    caps.notes.get("session_id").map(String::as_str),
                    Some("ses-1")
                );
            }
            other => panic!("expected Capabilities, got {other:?}"),
        }
    }

    // --- FORNX-91: OpenCodeCommandDurationSensor ---------------------------

    fn duration_event(tool_response: serde_json::Value) -> AgentEvent {
        AgentEvent {
            id: Uuid::new_v4(),
            session_id: "ses-1".into(),
            provider: Provider::OpenCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("bash".into()),
            tool_input: Some(serde_json::json!({"command": "ls"})),
            tool_response: Some(tool_response),
            raw: serde_json::json!({}),
        }
    }

    #[test]
    fn duration_sensor_computes_duration_from_time_start_and_end() {
        let event = duration_event(serde_json::json!({
            "metadata": {"exit": 0},
            "time": {"start": 1000, "end": 1250}
        }));
        let sensor = OpenCodeCommandDurationSensor {
            adapter_version: ADAPTER_VERSION,
        };
        let outcome = sensor.collect(&event, &OpenCodeAdapter::new().probe());
        assert!(outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Available);
        let ev = &outcome.evidence[0];
        assert_eq!(ev.kind, EvidenceKind::ProcessObservation);
        assert_eq!(ev.payload["observation"]["duration_ms"], 250);
        let source = ev.source.as_ref().expect("evidence must carry source");
        assert_eq!(source.trust_class, TrustClass::AgentAdjacent);
    }

    #[test]
    fn duration_sensor_reports_unavailable_when_time_fields_are_absent() {
        // The real, empirically-captured `tool_execute_before_after_pair`
        // fixture shape (FORNX-161) — no `time` field at all.
        let event = duration_event(serde_json::json!({
            "metadata": {"exit": 0},
            "output": "total 0\n"
        }));
        let sensor = OpenCodeCommandDurationSensor {
            adapter_version: ADAPTER_VERSION,
        };
        let outcome = sensor.collect(&event, &OpenCodeAdapter::new().probe());
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Unavailable);
    }

    #[test]
    fn duration_sensor_reports_collection_failed_when_end_precedes_start() {
        let event = duration_event(serde_json::json!({
            "time": {"start": 2000, "end": 1000}
        }));
        let sensor = OpenCodeCommandDurationSensor {
            adapter_version: ADAPTER_VERSION,
        };
        let outcome = sensor.collect(&event, &OpenCodeAdapter::new().probe());
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::CollectionFailed);
    }

    #[test]
    fn duration_sensor_reports_unavailable_with_no_tool_response() {
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "ses-1".into(),
            provider: Provider::OpenCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("bash".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        let sensor = OpenCodeCommandDurationSensor {
            adapter_version: ADAPTER_VERSION,
        };
        let outcome = sensor.collect(&event, &OpenCodeAdapter::new().probe());
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Unavailable);
    }

    #[test]
    fn duration_sensor_ignores_non_post_tool_use_events() {
        let mut event = duration_event(serde_json::json!({"time": {"start": 0, "end": 1}}));
        event.kind = EventKind::PreToolUse;
        let sensor = OpenCodeCommandDurationSensor {
            adapter_version: ADAPTER_VERSION,
        };
        let outcome = sensor.collect(&event, &OpenCodeAdapter::new().probe());
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Unknown);
    }
}
