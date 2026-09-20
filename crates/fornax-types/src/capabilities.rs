//! Formalized runtime capability taxonomy and explicit signal-availability
//! semantics (FORNX-155, parent epic FORNX-138).
//!
//! Before this module, `RuntimeCapabilities` was a flat struct of six fixed
//! `bool` fields (`supports_pre_tool_use`, ...). A `false` conflated three
//! materially different situations a verifier needs to tell apart: "this
//! runtime can never expose this signal" (`Unsupported`), "this signal exists
//! in principle but wasn't observed this session" (`Unavailable`), and
//! "nobody has said anything about this signal yet" (ordinary absence). It
//! also had no room for "observed, then withheld by the privacy boundary"
//! (`Redacted`) or "we tried to collect it and it errored" (`CollectionFailed`).
//!
//! This module replaces the bool set with an explicit, extensible taxonomy:
//! a [`SignalClass`] (what kind of signal) paired with a [`SignalAvailability`]
//! (its state), so core verifier/UI code can reason about capability
//! *classes* without branching on [`crate::Provider`] names (D4/D7,
//! `docs/adr/0001-architecture-invariants.md`).
//!
//! Both enums carry a `#[serde(untagged)] Unrecognized(String)` catch-all as
//! their last variant, so a binary older than a persisted/wired snapshot
//! deserializes an unknown tag into a safe fallback that still round-trips
//! the original string, rather than failing to parse. See the module's tests
//! for the exact round-trip guarantee this provides.
//!
//! `RuntimeCapabilities` itself keeps its old wire shape *deserializable*
//! (six legacy `supports_*` bools, `#[serde(default)]`) alongside the new
//! `signals`/`schema_version` fields, so an adapter or on-disk row from
//! before this change still parses. See `state_of`/`is_observable` and the
//! `From<RuntimeCapabilitiesWire>` impl below for the reconstruction rule.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::Provider;

/// Version of the [`RuntimeCapabilities`] snapshot shape. Bumped whenever the
/// taxonomy itself changes in a way a consumer might care about (new
/// `SignalClass`/`SignalAvailability` variant does *not* require a bump —
/// those are forward-compatible by construction; a change to the container
/// shape does). Attached to every snapshot so a persisted/exported snapshot
/// carries its own provenance (FORNX-155 AC: "capability snapshots are
/// versioned and attached to session provenance").
pub const CAPABILITY_SCHEMA_VERSION: u32 = 1;

/// Explicit availability state of one [`SignalClass`] for a given provider
/// session. Never collapsed to a boolean — the whole point of this type is
/// that "not available" has more than one distinct, actionable meaning.
///
/// `Unknown` is the default/ordinary-absence state: nothing has declared an
/// opinion about this signal class yet (e.g. an adapter hasn't announced, or
/// a legacy `false` bool that could have meant either `Unsupported` or
/// `Unavailable` — see `legacy_bool_to_availability`). It is deliberately
/// distinct from `Unrecognized`, which means "this binary doesn't know what
/// this *tag* means" (a parse-time fact), not "the state itself is unknown"
/// (a domain fact). Merging the two would make it impossible to tell a stale
/// binary reading newer data apart from a signal nobody has probed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalAvailability {
    /// Confirmed observable this session. The only state that may gate a
    /// verifier into attempting verification.
    Available,
    /// This runtime fundamentally cannot expose this signal class (e.g.
    /// Codex's rollout-tail integration cannot intercept/rewrite tool input
    /// pre-execution — see `docs/research/adapter-capability-matrix.md`).
    Unsupported,
    /// The signal class exists in principle for this provider, but this
    /// session/version/config did not expose it.
    Unavailable,
    /// The signal was observed, then withheld by the local privacy/redaction
    /// boundary (`fornax_types::redact`) before it could be reported as
    /// available.
    Redacted,
    /// Collection was attempted and failed (parse error, IO error, etc.) —
    /// distinct from never having attempted collection at all.
    CollectionFailed,
    /// Ordinary absence: no adapter has declared an opinion about this
    /// signal class. The default when a class is missing from `signals`.
    Unknown,
    /// Forward-compatibility catch-all: a state tag this binary doesn't
    /// recognize (e.g. persisted by a newer binary). Carries the original
    /// string so a tolerant reader that re-serializes the value does not
    /// silently destroy it. Must stay the last variant — `#[serde(untagged)]`
    /// makes it the fallback the tagged variants above are tried before.
    #[serde(untagged)]
    Unrecognized(String),
}

impl SignalAvailability {
    /// Normalizing constructor: maps a canonical snake_case tag to its real
    /// variant, and anything else to `Unrecognized`. Prefer this over
    /// constructing `Unrecognized` directly — `Unrecognized("available")` is
    /// not equal to `Available` (round-tripping it through serde re-parses
    /// it as `Available`, since `available` matches the tagged variant
    /// first), so callers that need a single canonical value for a known tag
    /// should go through here rather than risk that asymmetry.
    pub fn from_tag(tag: &str) -> Self {
        match tag {
            "available" => Self::Available,
            "unsupported" => Self::Unsupported,
            "unavailable" => Self::Unavailable,
            "redacted" => Self::Redacted,
            "collection_failed" => Self::CollectionFailed,
            "unknown" => Self::Unknown,
            other => Self::Unrecognized(other.to_string()),
        }
    }
}

/// A class of signal a provider integration might be able to observe. One
/// variant per canonical concept named in FORNX-138/FORNX-155's capability
/// taxonomy; a provider that can't expose a class simply reports it
/// `Unsupported`/`Unavailable`, it is not omitted (an omitted class reads as
/// ordinary-absence `Unknown`, which is a materially weaker claim).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalClass {
    /// Pre-execution interception of a tool call (Claude Code's
    /// `PreToolUse`; Codex's opt-in/admin-suppressible hook equivalent).
    ToolInvocation,
    /// Post-execution observation that a tool call happened (Claude Code's
    /// `PostToolUse`; Codex's rollout `custom_tool_call`/`_output` pairing).
    ToolTrace,
    /// The provider's own serialized result body for a tool call (Claude
    /// Code's `tool_response`; Codex's rollout tool-call output blocks).
    ToolResultPayload,
    /// A literal process exit code / termination status, independent of
    /// whatever summarized result payload the provider also exposes.
    ProcessResult,
    /// Session start/end lifecycle events (Claude Code's `Stop`; Codex's
    /// rollout `task_complete`).
    SessionLifecycle,
    /// Subagent start/stop lifecycle events.
    SubagentLifecycle,
    /// The agent's final natural-language response/turn content (Claude
    /// Code's transcript tail; Codex's `last_agent_message`).
    FinalResponse,
    /// A provider-summarized view of the model's reasoning/chain-of-thought.
    ReasoningSummary,
    /// Unsummarized raw reasoning/thinking tokens.
    RawReasoning,
    /// Per-token log-probabilities.
    TokenLogprobs,
    /// Any other provider-internal telemetry not covered by a more specific
    /// class above.
    InternalModelSignals,
    /// Forward-compatibility catch-all for a future signal class this
    /// binary doesn't know about yet. See [`SignalAvailability::Unrecognized`]
    /// for the same pattern and its round-trip guarantee. Must stay last.
    #[serde(untagged)]
    Unrecognized(String),
}

/// One capability declaration: a signal class paired with its availability
/// state and optional free-text rationale (the "why", e.g. "Bash
/// tool_response carries no literal exit code as of v2.1.238" — previously
/// only reachable via `RuntimeCapabilities.notes`, now attached to the
/// specific class it explains).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySignal {
    pub class: SignalClass,
    pub state: SignalAvailability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// What a given provider integration's current connection can actually
/// observe, formalized as an explicit, versioned list of
/// class+state(+detail) declarations rather than fixed bools. Verifiers
/// consult this (via `state_of`/`is_observable`) before deciding
/// `Unavailable` vs. attempting verification — a missing capability must
/// never be silently treated as a pass (D4).
///
/// Deserialization is intentionally asymmetric with serialization: this type
/// always *serializes* its rich shape (`schema_version`, `signals`), but
/// *deserializes* through [`RuntimeCapabilitiesWire`], which also accepts the
/// pre-FORNX-155 flat-bool shape (via `#[serde(default)]` on every field) so
/// an old adapter payload or a pre-migration SQLite row still parses. See
/// `From<RuntimeCapabilitiesWire>` for the exact reconstruction rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RuntimeCapabilitiesWire")]
pub struct RuntimeCapabilities {
    pub schema_version: u32,
    pub provider: Provider,
    pub signals: Vec<CapabilitySignal>,
    /// Free-form notes, e.g. provenance/session-id stamping. NOTE: despite
    /// the name, `notes["session_id"]` is a reserved, machine-consumed
    /// transport field — `fornax-daemon` reads it to key the
    /// `(session_id, provider)` capabilities upsert for a `Capabilities`
    /// message that arrives before any `Event` sets the session hint (see
    /// `fornax-daemon/src/main.rs::handle_message`). It is not promoted to a
    /// real field because the capabilities spool envelope (`fornax-cli`'s
    /// `export_spool`) must never carry a session id — `fornax-cloud` keys
    /// capabilities on `(device_id, provider)`, never an envelope id.
    pub notes: HashMap<String, String>,
}

/// Wire shape accepted on deserialization: the new rich fields plus the six
/// pre-FORNX-155 flat bools, all `#[serde(default)]` so any subset — old
/// payload, new payload, or (in principle) both — parses without error.
#[derive(Deserialize)]
struct RuntimeCapabilitiesWire {
    #[serde(default)]
    schema_version: u32,
    provider: Provider,
    #[serde(default)]
    signals: Vec<CapabilitySignal>,
    #[serde(default)]
    notes: HashMap<String, String>,
    #[serde(default)]
    supports_pre_tool_use: bool,
    #[serde(default)]
    supports_post_tool_use: bool,
    #[serde(default)]
    supports_tool_response_capture: bool,
    #[serde(default)]
    supports_session_stop_event: bool,
    #[serde(default)]
    supports_transcript_tail: bool,
    #[serde(default)]
    supports_subagent_lifecycle: bool,
}

/// A legacy `false` genuinely doesn't distinguish "confirmed unsupported"
/// from "never probed" — `Unknown` is the honest reading of it, and (see
/// `is_observable`) is behaviorally identical to `Unsupported`/`Unavailable`
/// at every verifier gate today, so reconstructing this way changes no
/// externally observable behavior.
fn legacy_bool_to_availability(supported: bool) -> SignalAvailability {
    if supported {
        SignalAvailability::Available
    } else {
        SignalAvailability::Unknown
    }
}

impl From<RuntimeCapabilitiesWire> for RuntimeCapabilities {
    fn from(w: RuntimeCapabilitiesWire) -> Self {
        // Reconstruction rule: `signals` non-empty is authoritative and
        // complete (a caller that sent both a rich `signals` list and the
        // legacy bools is asserting the rich list is the truth). `signals`
        // empty means this is a legacy-shaped payload — rebuild exactly the
        // six classes the old bools covered from them; everything else
        // (ProcessResult, ReasoningSummary, ...) is simply absent, which
        // `state_of` correctly reads as `Unknown`.
        let signals = if !w.signals.is_empty() {
            w.signals
        } else {
            vec![
                CapabilitySignal {
                    class: SignalClass::ToolInvocation,
                    state: legacy_bool_to_availability(w.supports_pre_tool_use),
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: legacy_bool_to_availability(w.supports_post_tool_use),
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::ToolResultPayload,
                    state: legacy_bool_to_availability(w.supports_tool_response_capture),
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::SessionLifecycle,
                    state: legacy_bool_to_availability(w.supports_session_stop_event),
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::FinalResponse,
                    state: legacy_bool_to_availability(w.supports_transcript_tail),
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::SubagentLifecycle,
                    state: legacy_bool_to_availability(w.supports_subagent_lifecycle),
                    detail: None,
                },
            ]
        };
        RuntimeCapabilities {
            schema_version: if w.schema_version == 0 {
                CAPABILITY_SCHEMA_VERSION
            } else {
                w.schema_version
            },
            provider: w.provider,
            signals,
            notes: w.notes,
        }
    }
}

impl RuntimeCapabilities {
    /// The declared state of `class`, or `Unknown` if nothing has declared
    /// an opinion about it (ordinary absence — see `SignalAvailability`
    /// doc). If `class` was declared more than once (a `Vec`, unlike a map,
    /// permits this), the first declaration wins.
    pub fn state_of(&self, class: &SignalClass) -> SignalAvailability {
        self.signals
            .iter()
            .find(|s| &s.class == class)
            .map(|s| s.state.clone())
            .unwrap_or(SignalAvailability::Unknown)
    }

    /// True only when `class` is confirmed `Available` — the single
    /// condition a verifier may use to gate attempting verification. Every
    /// other state (`Unsupported`, `Unavailable`, `Redacted`,
    /// `CollectionFailed`, `Unknown`, `Unrecognized`) reads as "not
    /// observable", matching D4's "missing capability is UNAVAILABLE, never
    /// inferred as a pass".
    pub fn is_observable(&self, class: &SignalClass) -> bool {
        matches!(self.state_of(class), SignalAvailability::Available)
    }
}

/// A capability discovery/handshake contract: an adapter's declaration of
/// what it can currently observe. Deliberately one method, no registry, no
/// dynamic negotiation — a provider adapter's set of observable signal
/// classes is fixed at adapter-implementation time, not discovered at
/// runtime via some richer protocol (that would be exactly the
/// over-engineering FORNX-155 says not to build: no plugin marketplace, no
/// dynamic ABI).
///
/// `probe()` is documented as safe to call once per adapter *process*, not
/// necessarily once per *session*: Claude Code hooks are stateless
/// per-invocation processes with no guaranteed single "session start"
/// moment (see `fornax-adapter-claude`'s `translate()` for why it calls this
/// on every event), so the daemon's `(session_id, provider)` upsert — not a
/// call-once contract here — is what makes repeated announcements
/// idempotent. Implementors of this trait must not assume `probe()` is
/// called at most once for a given session.
pub trait CapabilityProbe {
    fn probe(&self) -> RuntimeCapabilities;
}

/// The flat six-bool shape the pre-FORNX-155 `RuntimeCapabilities` wire type
/// had. Used only at the `fornax-cli` `export-spool` boundary: the spool
/// envelope sent onward to `fornax-cloud` must stay byte-for-byte
/// wire-compatible with that (out-of-scope, separately owned) repo's
/// `fornax-uploader::types::RuntimeCapabilities`, which has not been taught
/// about `signals`/`schema_version`/`detail`. This is a one-way projection
/// (`From<&RuntimeCapabilities>`), never the other direction, and is never
/// itself persisted — the domain type's `signals` list is the single source
/// of truth; this is computed on demand at the moment of export.
#[derive(Debug, Clone, Serialize)]
pub struct LegacyCapabilitiesWire {
    pub provider: Provider,
    pub supports_pre_tool_use: bool,
    pub supports_post_tool_use: bool,
    pub supports_tool_response_capture: bool,
    pub supports_session_stop_event: bool,
    pub supports_transcript_tail: bool,
    pub supports_subagent_lifecycle: bool,
    pub notes: HashMap<String, String>,
}

impl From<&RuntimeCapabilities> for LegacyCapabilitiesWire {
    fn from(c: &RuntimeCapabilities) -> Self {
        Self {
            provider: c.provider,
            supports_pre_tool_use: c.is_observable(&SignalClass::ToolInvocation),
            supports_post_tool_use: c.is_observable(&SignalClass::ToolTrace),
            supports_tool_response_capture: c.is_observable(&SignalClass::ToolResultPayload),
            supports_session_stop_event: c.is_observable(&SignalClass::SessionLifecycle),
            supports_transcript_tail: c.is_observable(&SignalClass::FinalResponse),
            supports_subagent_lifecycle: c.is_observable(&SignalClass::SubagentLifecycle),
            notes: c.notes.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_with(signals: Vec<CapabilitySignal>) -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Codex,
            signals,
            notes: HashMap::new(),
        }
    }

    // --- SignalAvailability / SignalClass forward-compat round-trip -----

    #[test]
    fn unrecognized_state_tag_round_trips_the_original_string() {
        let json = r#""quantum_entangled""#;
        let v: SignalAvailability = serde_json::from_str(json).unwrap();
        assert_eq!(
            v,
            SignalAvailability::Unrecognized("quantum_entangled".to_string())
        );
        let back = serde_json::to_string(&v).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn unrecognized_class_tag_round_trips_the_original_string() {
        let json = r#""neural_trace""#;
        let v: SignalClass = serde_json::from_str(json).unwrap();
        assert_eq!(v, SignalClass::Unrecognized("neural_trace".to_string()));
        let back = serde_json::to_string(&v).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn every_canonical_state_tag_round_trips_to_its_named_variant() {
        let cases = [
            ("\"available\"", SignalAvailability::Available),
            ("\"unsupported\"", SignalAvailability::Unsupported),
            ("\"unavailable\"", SignalAvailability::Unavailable),
            ("\"redacted\"", SignalAvailability::Redacted),
            (
                "\"collection_failed\"",
                SignalAvailability::CollectionFailed,
            ),
            ("\"unknown\"", SignalAvailability::Unknown),
        ];
        for (json, expected) in cases {
            let v: SignalAvailability = serde_json::from_str(json).unwrap();
            assert_eq!(v, expected, "tag {json} did not parse to its named variant");
        }
    }

    #[test]
    fn non_string_availability_input_errors_rather_than_panics() {
        let err = serde_json::from_str::<SignalAvailability>("42");
        assert!(err.is_err());
    }

    #[test]
    fn from_tag_normalizes_canonical_and_unknown_tags() {
        assert_eq!(
            SignalAvailability::from_tag("available"),
            SignalAvailability::Available
        );
        assert_eq!(
            SignalAvailability::from_tag("something_new"),
            SignalAvailability::Unrecognized("something_new".to_string())
        );
    }

    /// Deliberate asymmetry documented on `from_tag`: constructing
    /// `Unrecognized` directly with a string that happens to be a canonical
    /// tag does NOT equal the named variant as a Rust value, but *does*
    /// collapse to it once it round-trips through serde (because on
    /// deserialize, "available" always matches the tagged `Available`
    /// variant before the untagged fallback is tried). This test pins that
    /// behavior down so a future change to variant ordering can't silently
    /// invert it.
    #[test]
    fn unrecognized_wrapping_a_canonical_tag_collapses_on_round_trip() {
        let constructed = SignalAvailability::Unrecognized("available".to_string());
        assert_ne!(constructed, SignalAvailability::Available);
        let json = serde_json::to_string(&constructed).unwrap();
        let back: SignalAvailability = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SignalAvailability::Available);
    }

    // --- RuntimeCapabilities legacy/rich reconstruction ------------------

    #[test]
    fn legacy_flat_bool_payload_reconstructs_the_six_known_classes() {
        let json = r#"{
            "provider":"codex",
            "supports_pre_tool_use":false,
            "supports_post_tool_use":true,
            "supports_tool_response_capture":true,
            "supports_session_stop_event":true,
            "supports_transcript_tail":true,
            "supports_subagent_lifecycle":false,
            "notes":{"a":"b"}
        }"#;
        let c: RuntimeCapabilities = serde_json::from_str(json).unwrap();
        assert_eq!(c.schema_version, CAPABILITY_SCHEMA_VERSION);
        assert_eq!(
            c.state_of(&SignalClass::ToolInvocation),
            SignalAvailability::Unknown
        );
        assert!(c.is_observable(&SignalClass::ToolTrace));
        assert!(c.is_observable(&SignalClass::ToolResultPayload));
        assert!(c.is_observable(&SignalClass::SessionLifecycle));
        assert!(c.is_observable(&SignalClass::FinalResponse));
        assert_eq!(
            c.state_of(&SignalClass::SubagentLifecycle),
            SignalAvailability::Unknown
        );
        // A class the old bools never covered at all is ordinary absence.
        assert_eq!(
            c.state_of(&SignalClass::ProcessResult),
            SignalAvailability::Unknown
        );
        assert_eq!(c.notes.get("a").map(String::as_str), Some("b"));
    }

    #[test]
    fn rich_payload_with_a_future_class_and_future_state_parses_and_round_trips() {
        let json = r#"{
            "schema_version":2,
            "provider":"claude_code",
            "signals":[
                {"class":"tool_trace","state":"available"},
                {"class":"process_result","state":"unsupported","detail":"no literal exit code"},
                {"class":"neural_trace","state":"quantum_pending"}
            ],
            "notes":{}
        }"#;
        let c: RuntimeCapabilities = serde_json::from_str(json).unwrap();
        assert_eq!(c.schema_version, 2);
        assert!(c.is_observable(&SignalClass::ToolTrace));
        assert_eq!(
            c.state_of(&SignalClass::ProcessResult),
            SignalAvailability::Unsupported
        );
        assert!(!c.is_observable(&SignalClass::Unrecognized("neural_trace".to_string())));
        assert_eq!(
            c.state_of(&SignalClass::Unrecognized("neural_trace".to_string())),
            SignalAvailability::Unrecognized("quantum_pending".to_string())
        );

        let reser = serde_json::to_string(&c).unwrap();
        let back: RuntimeCapabilities = serde_json::from_str(&reser).unwrap();
        assert_eq!(
            c, back,
            "rich round-trip through this binary's own Serialize must be lossless"
        );
    }

    #[test]
    fn signals_non_empty_is_authoritative_even_alongside_legacy_bools() {
        // A payload asserting both shapes: the rich `signals` list wins in
        // full, the legacy bools are ignored entirely (not merged).
        let json = r#"{
            "provider":"codex",
            "signals":[{"class":"tool_invocation","state":"available"}],
            "supports_pre_tool_use": false,
            "supports_post_tool_use": true
        }"#;
        let c: RuntimeCapabilities = serde_json::from_str(json).unwrap();
        assert!(c.is_observable(&SignalClass::ToolInvocation));
        assert_eq!(
            c.state_of(&SignalClass::ToolTrace),
            SignalAvailability::Unknown
        );
    }

    #[test]
    fn missing_schema_version_normalizes_to_current() {
        let json = r#"{"provider":"codex","supports_pre_tool_use":true}"#;
        let c: RuntimeCapabilities = serde_json::from_str(json).unwrap();
        assert_eq!(c.schema_version, CAPABILITY_SCHEMA_VERSION);
    }

    #[test]
    fn duplicate_class_declaration_first_wins() {
        let c = caps_with(vec![
            CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            },
            CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Redacted,
                detail: None,
            },
        ]);
        assert_eq!(
            c.state_of(&SignalClass::ToolTrace),
            SignalAvailability::Available
        );
    }

    // --- state_of/is_observable exhaustive table -------------------------

    #[test]
    fn is_observable_is_true_only_for_available_across_every_state() {
        let states = [
            SignalAvailability::Available,
            SignalAvailability::Unsupported,
            SignalAvailability::Unavailable,
            SignalAvailability::Redacted,
            SignalAvailability::CollectionFailed,
            SignalAvailability::Unknown,
            SignalAvailability::Unrecognized("future_state".to_string()),
        ];
        for state in states {
            let is_available = state == SignalAvailability::Available;
            let c = caps_with(vec![CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: state.clone(),
                detail: None,
            }]);
            assert_eq!(
                c.is_observable(&SignalClass::ToolTrace),
                is_available,
                "state {state:?} should be observable only if Available"
            );
        }
    }

    #[test]
    fn absent_class_reads_as_unknown_not_unsupported() {
        let c = caps_with(vec![]);
        assert_eq!(
            c.state_of(&SignalClass::ProcessResult),
            SignalAvailability::Unknown
        );
        assert!(!c.is_observable(&SignalClass::ProcessResult));
    }

    // --- Legacy projection (spool wire-compat) ---------------------------

    #[test]
    fn legacy_projection_reproduces_the_exact_frozen_key_set() {
        let c = caps_with(vec![
            CapabilitySignal {
                class: SignalClass::ToolInvocation,
                state: SignalAvailability::Unsupported,
                detail: None,
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
                class: SignalClass::SessionLifecycle,
                state: SignalAvailability::Available,
                detail: None,
            },
            CapabilitySignal {
                class: SignalClass::FinalResponse,
                state: SignalAvailability::Available,
                detail: None,
            },
            CapabilitySignal {
                class: SignalClass::SubagentLifecycle,
                state: SignalAvailability::Unsupported,
                detail: None,
            },
        ]);
        let dto = LegacyCapabilitiesWire::from(&c);
        let mut v = serde_json::to_value(&dto).unwrap();
        v.as_object_mut().unwrap().insert(
            "type".to_string(),
            serde_json::Value::String("capabilities".to_string()),
        );
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "notes",
                "provider",
                "supports_post_tool_use",
                "supports_pre_tool_use",
                "supports_session_stop_event",
                "supports_subagent_lifecycle",
                "supports_tool_response_capture",
                "supports_transcript_tail",
                "type",
            ]
        );
    }

    #[test]
    fn legacy_inbound_to_domain_to_legacy_projection_is_bit_identical_on_all_six_bools() {
        let json = r#"{
            "provider":"codex",
            "supports_pre_tool_use":false,
            "supports_post_tool_use":true,
            "supports_tool_response_capture":true,
            "supports_session_stop_event":true,
            "supports_transcript_tail":true,
            "supports_subagent_lifecycle":false,
            "notes":{}
        }"#;
        let orig: serde_json::Value = serde_json::from_str(json).unwrap();
        let c: RuntimeCapabilities = serde_json::from_str(json).unwrap();
        let dto = LegacyCapabilitiesWire::from(&c);
        let projected = serde_json::to_value(&dto).unwrap();
        for k in [
            "supports_pre_tool_use",
            "supports_post_tool_use",
            "supports_tool_response_capture",
            "supports_session_stop_event",
            "supports_transcript_tail",
            "supports_subagent_lifecycle",
        ] {
            assert_eq!(
                orig[k], projected[k],
                "bool {k} drifted through legacy->domain->legacy"
            );
        }
    }
}
