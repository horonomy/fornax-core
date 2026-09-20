//! `AgentAdapter` contract (FORNX-156, parent epic FORNX-138).
//!
//! Defines the stable boundary between a provider-native integration
//! (Claude Code hooks, Codex rollout-tail, or any future runtime) and Fornax
//! core. Core code (`fornax-daemon`, `fornax-verify`, `fornax-store`) depends
//! only on this trait and the canonical types in `crate` — never on a
//! provider's native field names or event shapes (D5, ADR 0001: "adapters
//! are thin"; D4/D7: a missing signal is `Unavailable`, never inferred).
//!
//! ## Lifecycle
//!
//! A conforming adapter's observable lifecycle, from core's perspective, is:
//!
//! 1. **Capability declaration** — [`CapabilityProbe::probe`] (a supertrait
//!    requirement, formalized in FORNX-155) returns what this adapter's
//!    runtime can observe, independent of any particular session. An
//!    adapter attaches its own version and the session id it is currently
//!    speaking for via [`RuntimeCapabilities::notes`] (see
//!    `adapter_version`/`session_id` note keys below) — not via a dedicated
//!    field, so this stays wire-compatible with FORNX-155's `notes` map and
//!    needs no `fornax-store`/spool-envelope schema change.
//! 2. **Normalization** — [`AgentAdapter::normalize`] translates one
//!    provider-native payload into zero or more canonical [`crate::IngestMessage`]s
//!    ([`NormalizationOutcome::Messages`]), or reports that the payload was
//!    deliberately skipped ([`NormalizationOutcome::Ignored`]) or not
//!    recognized at all ([`NormalizationOutcome::Unrecognized`]) — see
//!    "Unknown-event policy" below.
//!
//! There is no explicit "session start"/"session end" method on this trait:
//! Claude Code hooks are stateless per-invocation processes with no
//! guaranteed single start moment (an adapter may call `probe()` once per
//! process or once per event — both are conforming, see `probe`'s own
//! doc), while Codex's rollout-tail is a long-lived process reading a
//! session's lifecycle out of the transcript itself. Session boundaries are
//! therefore expressed as ordinary [`crate::EventKind::SessionStart`]/
//! [`crate::EventKind::SessionEnd`] events flowing through `normalize`, not
//! as a separate lifecycle method — this is what lets one trait fit both a
//! hook-invoked binary and a file-tailing daemon (see
//! `docs/research/adapter-capability-matrix.md` for why the two transports
//! cannot be forced into one shape).
//!
//! ## Unknown-event policy
//!
//! An adapter observes provider-native payload shapes it does not recognize
//! for two structurally different reasons, and this contract requires
//! callers to be able to tell them apart:
//!
//! - [`NormalizationOutcome::Ignored`] — the shape *is* recognized, and is
//!   deliberately not translated into a canonical message (e.g. Codex's
//!   `session_meta` line, or a Claude Code hook event this adapter has no
//!   canonical mapping for by design). `reason` is a short, static
//!   explanation, not user data.
//! - [`NormalizationOutcome::Unrecognized`] — the shape was *not* matched by
//!   anything this adapter knows about (a future provider event, a schema
//!   change). `discriminator` carries only the shape's own type tag (e.g.
//!   Claude's `hook_event_name` value, Codex's `payload.type` value) —
//!   never the payload itself.
//!
//! The chosen policy for both cases is **log + skip**: never persist or
//! forward the raw native payload for a shape this contract does not have a
//! canonical mapping for, and never crash or drop the connection over it.
//! Preserving the *raw* payload instead (log+preserve) was considered and
//! rejected: an unrecognized shape is, by definition, un-vetted
//! provider-native JSON, and forwarding it to the daemon would be exactly
//! the uncontrolled "provider-native payload leakage into domain/storage"
//! this ticket's acceptance criteria forbids. A safe, versioned envelope for
//! carrying forward-compatible provider payloads is FORNX-158's job (the
//! "extension envelope"), not this contract's — `Unrecognized`'s
//! `discriminator` field is deliberately the smallest possible signal
//! (a type tag, not a payload) so a future FORNX-158 envelope has something
//! to key off without this contract having pre-built the envelope itself.
//!
//! ## Allowed core dependencies
//!
//! An `AgentAdapter` implementation may depend on `fornax-types` (this
//! crate) and general-purpose libraries (serde, tokio, uuid, chrono). It
//! must **not** depend on `fornax-verify` or `fornax-store` — claim
//! extraction beyond a cheap, duplicated pre-filter (see
//! `fornax-adapter-claude`'s `fornax_verify_claims_tests_passed`, which is
//! intentionally *not* imported from `fornax-verify`) and persistence are
//! core's job, not the adapter's. `fornax-daemon` and other core crates may
//! depend on `fornax-types::AgentAdapter` (the trait) but must never depend
//! on a concrete adapter crate (`fornax-adapter-claude`/`fornax-adapter-codex`)
//! — that dependency direction only exists in test/conformance harnesses
//! (`crates/fornax-adapter-conformance`), never in a shipped binary's
//! dependency graph.
//!
//! ## Error semantics
//!
//! `normalize` never returns a `Result` — a malformed or unrecognized
//! native payload is a normal, expected input (a hook payload from a newer
//! CLI version, a corrupt line in a tailed file), not an exceptional
//! condition, and must never propagate as an error that could tear down an
//! adapter's connection or the session it is observing (D2/D7 spirit:
//! observation must never be what breaks the user's actual coding session).
//! Any genuine I/O failure (a hook's stdin unreadable, a rollout file
//! disappearing) is caught at the adapter's transport layer (`main.rs` in
//! both existing adapters), outside this trait, and handled by best-effort
//! skip/retry — never a panic.

use crate::capabilities::CapabilityProbe;
use crate::{IngestMessage, Provider};

/// Result of normalizing one provider-native payload. See the module docs
/// ("Unknown-event policy") for the distinction between `Ignored` and
/// `Unrecognized`.
#[derive(Debug, Clone)]
pub enum NormalizationOutcome {
    /// Zero or more canonical messages extracted from the native payload.
    /// Zero is valid (e.g. a recognized event this adapter maps to no
    /// canonical message on its own, such as Codex's `custom_tool_call`
    /// invocation half of a call/output pair).
    Messages(Vec<IngestMessage>),
    /// The native payload's shape was recognized but this adapter
    /// deliberately does not translate it into any canonical message.
    Ignored { reason: &'static str },
    /// The native payload's shape was not matched by anything this adapter
    /// knows about. `discriminator` is the shape's own type tag only — never
    /// the payload body (see module docs).
    Unrecognized { discriminator: String },
}

impl NormalizationOutcome {
    /// Convenience: the messages to forward to the daemon, or an empty
    /// `Vec` for `Ignored`/`Unrecognized`. Never panics.
    pub fn into_messages(self) -> Vec<IngestMessage> {
        match self {
            NormalizationOutcome::Messages(msgs) => msgs,
            NormalizationOutcome::Ignored { .. } | NormalizationOutcome::Unrecognized { .. } => {
                vec![]
            }
        }
    }
}

/// The stable provider-adapter boundary (FORNX-156). Implementors translate
/// one provider's native transport (hooks, rollout-tail, or any future
/// mechanism) into canonical [`crate::IngestMessage`]s. See the module docs
/// for the full lifecycle, unknown-event policy, allowed dependencies, and
/// error semantics this trait commits an implementor to.
///
/// A supertrait of [`CapabilityProbe`] (FORNX-155), not a duplicate of it:
/// an adapter's capability declaration and its normalization logic are two
/// separate concerns that happen to be implemented by the same type, and
/// composing via supertrait means core code that only needs capabilities
/// (e.g. a verifier gate) can keep depending on `CapabilityProbe` alone.
pub trait AgentAdapter: CapabilityProbe {
    /// Which provider this adapter instance speaks for. Must match the
    /// `provider` field of every [`crate::AgentEvent`]/[`crate::RuntimeCapabilities`]
    /// this adapter ever produces — the conformance suite asserts this.
    fn provider(&self) -> Provider;

    /// This adapter implementation's own version, independent of the
    /// provider runtime's version (which, where knowable, belongs in a
    /// `CapabilitySignal::detail` string, e.g. "as of v2.1.238"). Attached
    /// to capability declarations via the reserved `notes["adapter_version"]`
    /// key (see the module docs on why this rides on `notes` rather than a
    /// new field) so a persisted/exported capability snapshot always carries
    /// its own adapter provenance.
    fn adapter_version(&self) -> &'static str;

    /// Translate one provider-native payload into canonical messages.
    /// `session_hint` is the session id known to the caller so far (a
    /// long-lived tailing adapter's main loop, for example); an
    /// implementation should prefer a session id it can read out of the
    /// native payload itself when one is present, falling back to
    /// `session_hint` otherwise — neither source is assumed authoritative
    /// over the other, since which one is available is itself a
    /// transport-specific fact (see `docs/research/adapter-capability-matrix.md`).
    ///
    /// Takes `&mut self` because a transport may need to correlate two
    /// native payloads across calls (e.g. Codex's `custom_tool_call` /
    /// `custom_tool_call_output` pairing by `call_id`) — implementations
    /// that need no such state simply never mutate.
    ///
    /// Never panics on malformed or unexpected input (see module docs,
    /// "Error semantics").
    fn normalize(&mut self, session_hint: &str, native: &serde_json::Value)
        -> NormalizationOutcome;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{RuntimeCapabilities, CAPABILITY_SCHEMA_VERSION};
    use std::collections::HashMap;

    /// A minimal in-crate conforming adapter, used only to prove the trait
    /// itself is object-safe-friendly and composable with `CapabilityProbe`
    /// without pulling in either real adapter crate (that cross-crate proof
    /// lives in `crates/fornax-adapter-conformance`).
    struct EchoAdapter {
        calls: u32,
    }

    impl CapabilityProbe for EchoAdapter {
        fn probe(&self) -> RuntimeCapabilities {
            RuntimeCapabilities {
                schema_version: CAPABILITY_SCHEMA_VERSION,
                provider: Provider::Codex,
                signals: vec![],
                notes: HashMap::new(),
            }
        }
    }

    impl AgentAdapter for EchoAdapter {
        fn provider(&self) -> Provider {
            Provider::Codex
        }

        fn adapter_version(&self) -> &'static str {
            "echo-0.0.1"
        }

        fn normalize(
            &mut self,
            _session_hint: &str,
            native: &serde_json::Value,
        ) -> NormalizationOutcome {
            self.calls += 1;
            match native.get("type").and_then(|v| v.as_str()) {
                Some("known_but_skipped") => NormalizationOutcome::Ignored {
                    reason: "test fixture: deliberately uninteresting",
                },
                Some(_) | None => NormalizationOutcome::Unrecognized {
                    discriminator: native
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<missing type>")
                        .to_string(),
                },
            }
        }
    }

    #[test]
    fn trait_object_composes_probe_and_normalize() {
        let mut adapter: Box<dyn AgentAdapter> = Box::new(EchoAdapter { calls: 0 });
        assert_eq!(adapter.provider(), Provider::Codex);
        let caps = adapter.probe();
        assert_eq!(caps.provider, Provider::Codex);

        let out = adapter.normalize("sess-1", &serde_json::json!({"type": "known_but_skipped"}));
        match out {
            NormalizationOutcome::Ignored { reason } => {
                assert_eq!(reason, "test fixture: deliberately uninteresting")
            }
            other => panic!("expected Ignored, got {other:?}"),
        }

        let out = adapter.normalize("sess-1", &serde_json::json!({"type": "something_new"}));
        match out {
            NormalizationOutcome::Unrecognized { discriminator } => {
                assert_eq!(discriminator, "something_new")
            }
            other => panic!("expected Unrecognized, got {other:?}"),
        }
    }

    #[test]
    fn into_messages_is_empty_for_ignored_and_unrecognized() {
        assert!(NormalizationOutcome::Ignored { reason: "x" }
            .into_messages()
            .is_empty());
        assert!(NormalizationOutcome::Unrecognized {
            discriminator: "x".to_string()
        }
        .into_messages()
        .is_empty());
    }
}
