//! Generic `AgentAdapter` conformance harness (FORNX-156). Written against
//! the trait only, with no dependency on either concrete adapter crate — the
//! integration tests under `tests/` instantiate it against
//! `fornax-adapter-claude::ClaudeAdapter` and `fornax-adapter-codex::CodexAdapter`
//! as `[dev-dependencies]`, so this crate never becomes something a shipped
//! binary could accidentally depend on (see the `AgentAdapter` trait docs,
//! "Allowed core dependencies").
//!
//! Assertions are over *properties* every conforming adapter must hold, not
//! over message sequence/count: the two real adapters differ deliberately in
//! how often they announce capabilities (Claude: every event; Codex: once
//! per connection — both conforming, see `AgentAdapter::probe`'s doc on
//! repeated-announcement idempotency), so a sequence-shaped assertion would
//! be true for one and false for the other by construction, not by either
//! one being broken.
//!
//! Extended (FORNX-160, parent epic FORNX-138) from FORNX-156's original
//! property suite into the full golden-fixture kit the epic's conformance
//! AC asks for: versioned, sanitized fixtures of real (and, for a
//! breaking-change probe, deliberately synthetic) provider-native shapes
//! (see the [`fixtures`] module and `fixtures/README.md`), a
//! [`replay_fixture`] harness that drives the same `normalize`-plus-internal-
//! `EvidenceSensor` pipeline a real adapter's `main.rs` does, and contract
//! checks over the FORNX-155 (capability declaration)/FORNX-157 (evidence
//! provenance)/FORNX-158 (canonical-payload validation, extension-envelope
//! boundary) surfaces those tickets added on top of `AgentAdapter` itself.
//! `tests/golden_fixtures.rs` and `tests/contract.rs` are the entry point a
//! future third-party adapter author should copy from — see
//! `docs/contributing/adding-an-adapter.md` step 6.

use fornax_types::{AgentAdapter, IngestMessage, NormalizationOutcome, TrustClass};

pub mod fixtures;
pub use fixtures::{load_fixtures, FixtureMetadata, GoldenFixture};

/// Every `AgentEvent`/`RuntimeCapabilities` a conforming adapter emits must
/// carry that adapter's own declared `provider()` — core code relies on this
/// to route/attribute observations without asking the adapter again.
pub fn provider_is_stamped_consistently<A: AgentAdapter>(
    adapter: &mut A,
    session_hint: &str,
    native_events: &[serde_json::Value],
) {
    let expected = adapter.provider();
    for native in native_events {
        if let NormalizationOutcome::Messages(msgs) = adapter.normalize(session_hint, native) {
            for msg in msgs {
                match msg {
                    IngestMessage::Event(e) => assert_eq!(
                        e.provider, expected,
                        "AgentEvent.provider did not match adapter.provider()"
                    ),
                    IngestMessage::Capabilities(c) => assert_eq!(
                        c.provider, expected,
                        "RuntimeCapabilities.provider did not match adapter.provider()"
                    ),
                    IngestMessage::Claim(_) | IngestMessage::Evidence(_) => {
                        // Neither carries a provider field by design
                        // (see `fornax_types::Claim`/`Evidence`) — nothing
                        // to assert here.
                    }
                    IngestMessage::PolicyBundle { .. } => {
                        // FORNX-119: never emitted by an `AgentAdapter::normalize`
                        // implementation — this variant is CLI/daemon-only
                        // (`fornax policy import`) and carries no provider
                        // field. Nothing to assert here.
                    }
                    IngestMessage::PolicyRevocation { .. } => {
                        // FORNX-123: same reasoning as `PolicyBundle` above.
                    }
                }
            }
        }
    }
}

/// Every message a conforming adapter emits must be a `serde_json`-round-
/// trippable `IngestMessage` — this is the wire contract the daemon's UDS
/// ingest loop (`fornax-daemon::handle_connection`) actually parses against.
pub fn every_message_round_trips_through_the_wire_protocol<A: AgentAdapter>(
    adapter: &mut A,
    session_hint: &str,
    native_events: &[serde_json::Value],
) {
    for native in native_events {
        if let NormalizationOutcome::Messages(msgs) = adapter.normalize(session_hint, native) {
            for msg in msgs {
                let json = serde_json::to_string(&msg).expect("IngestMessage must serialize");
                let _: IngestMessage = serde_json::from_str(&json)
                    .expect("IngestMessage must round-trip through its own wire shape");
            }
        }
    }
}

/// A conforming adapter's `probe()` must report the same `provider` as
/// `provider()` itself — the two are not allowed to disagree.
pub fn probe_provider_matches_declared_provider<A: AgentAdapter>(adapter: &A) {
    assert_eq!(
        adapter.probe().provider,
        adapter.provider(),
        "CapabilityProbe::probe().provider disagreed with AgentAdapter::provider()"
    );
}

/// A conforming adapter must never panic on a shape it doesn't recognize —
/// it must classify the input as `Unrecognized` (or, for a shape it
/// recognizes but chooses not to translate, `Ignored`), never crash the
/// process/session observing it (see the `AgentAdapter` trait docs, "Error
/// semantics"). Returns the outcome so callers can additionally assert on
/// which of the two policy branches a given fixture landed in.
pub fn normalizing_never_panics<A: AgentAdapter>(
    adapter: &mut A,
    session_hint: &str,
    native: &serde_json::Value,
) -> NormalizationOutcome {
    adapter.normalize(session_hint, native)
}

/// `Unrecognized`'s `discriminator` must never be empty — an adapter that
/// can't name what it didn't recognize gives a verifier/operator nothing to
/// act on.
pub fn unrecognized_always_carries_a_discriminator(outcome: &NormalizationOutcome) {
    if let NormalizationOutcome::Unrecognized { discriminator } = outcome {
        assert!(
            !discriminator.is_empty(),
            "Unrecognized outcome must carry a non-empty discriminator"
        );
    }
}

// --- Golden-fixture replay harness (FORNX-160) ---------------------------
//
// Everything below extends the FORNX-156 property-suite above into the
// broader golden-fixture kit: real (or deliberately synthetic)
// provider-native shapes, replayed through a live adapter, with assertions
// over the same properties plus the FORNX-155/157/158 contracts those
// tickets added on top of `AgentAdapter` itself.

/// Replays every native event in `fixture` through `adapter`, in order,
/// against the *same* adapter instance — the full transport ->
/// `AgentAdapter::normalize` -> (internal `EvidenceSensor`) -> canonical
/// `IngestMessage` pipeline a real adapter's `main.rs` exercises. Both
/// shipped adapters call their sensors from inside `normalize` itself, so
/// replaying a fixture through `normalize` already proves the sensor/
/// evidence half of the pipeline, not just event translation — there is no
/// separate "run the sensors" step to add here.
///
/// Returns one [`NormalizationOutcome`] per native event, in fixture order,
/// so a caller can assert on an individual step (e.g. the first half of a
/// call/output pair being `Ignored`) as well as the final one.
pub fn replay_fixture<A: AgentAdapter>(
    adapter: &mut A,
    session_hint: &str,
    fixture: &GoldenFixture,
) -> Vec<NormalizationOutcome> {
    fixture
        .native_events
        .iter()
        .map(|native| adapter.normalize(session_hint, native))
        .collect()
}

/// FORNX-155 contract: every capability declaration a conforming adapter
/// produces must stamp the current [`fornax_types::CAPABILITY_SCHEMA_VERSION`]
/// and its own declared provider — a stale schema version or a
/// provider/declaration mismatch is a conformance bug, not a stylistic nit.
pub fn capability_declaration_is_well_formed<A: AgentAdapter>(adapter: &A) {
    let caps = adapter.probe();
    assert_eq!(
        caps.schema_version,
        fornax_types::CAPABILITY_SCHEMA_VERSION,
        "RuntimeCapabilities.schema_version must match the current CAPABILITY_SCHEMA_VERSION"
    );
    assert_eq!(
        caps.provider,
        adapter.provider(),
        "RuntimeCapabilities.provider must match AgentAdapter::provider()"
    );
}

/// FORNX-157 contract: every `Evidence` a conforming adapter emits for a
/// recognized native event must carry structured `source` provenance whose
/// `trust_class` is a named (not forward-compat `Unrecognized`) variant, and
/// whose `provider` — when present — matches the adapter's own declared
/// provider. `None` sensors that produce no evidence for a given native
/// event are not asserted on here (there is nothing to check).
pub fn evidence_sources_are_valid<A: AgentAdapter>(
    adapter: &mut A,
    session_hint: &str,
    native_events: &[serde_json::Value],
) {
    let expected = adapter.provider();
    for native in native_events {
        if let NormalizationOutcome::Messages(msgs) = adapter.normalize(session_hint, native) {
            for msg in msgs {
                if let IngestMessage::Evidence(ev) = msg {
                    let source = ev
                        .source
                        .as_ref()
                        .expect("conforming adapter's Evidence must carry EvidenceSource");
                    assert!(
                        !matches!(source.trust_class, TrustClass::Unrecognized(_)),
                        "EvidenceSource.trust_class must be a named TrustClass variant, got {:?}",
                        source.trust_class
                    );
                    if let Some(p) = source.provider {
                        assert_eq!(
                            p, expected,
                            "EvidenceSource.provider disagreed with adapter.provider()"
                        );
                    }
                }
            }
        }
    }
}

/// FORNX-158 contract, picking up part of FORNX-289 ("`validate_canonical_payload`
/// has no non-test caller yet"): every canonical `Evidence::payload` a
/// conforming adapter emits must validate against its own `EvidenceKind`'s
/// typed shape. This gives `validate_canonical_payload` a real caller
/// exercising live adapter output, not just the hand-built fixtures in its
/// own unit tests.
///
/// FORNX-289: asserts at least one `Evidence` message was actually produced
/// and validated. Without this, a fixture set that happens to emit zero
/// `Evidence` messages would make the check above vacuously true — the
/// exact "wiring a call that never actually validates anything real"
/// failure mode the ticket called out — and the test suite would report
/// green having exercised nothing.
pub fn evidence_payloads_validate_against_their_canonical_schema<A: AgentAdapter>(
    adapter: &mut A,
    session_hint: &str,
    native_events: &[serde_json::Value],
) {
    let mut validated = 0usize;
    for native in native_events {
        if let NormalizationOutcome::Messages(msgs) = adapter.normalize(session_hint, native) {
            for msg in msgs {
                if let IngestMessage::Evidence(ev) = msg {
                    fornax_types::validate_canonical_payload(ev.kind, &ev.payload).unwrap_or_else(
                        |e| {
                            panic!(
                                "Evidence payload failed canonical validation for {:?}: {e}",
                                ev.kind
                            )
                        },
                    );
                    validated += 1;
                }
            }
        }
    }
    assert!(
        validated > 0,
        "expected at least one Evidence message from {:?}'s fixtures to exercise \
         canonical-payload validation against — got zero, which would make this \
         check vacuously true",
        adapter.provider()
    );
}

/// FORNX-156/158 boundary property, and the AC's "a breaking provider-event
/// change fails with an actionable conformance error, not silent data loss"
/// requirement: an `Unrecognized` outcome must carry a non-empty
/// `discriminator` (the caller learns *something* changed shape) and must
/// never be mistaken for a successful, if empty, translation. Panics with
/// the actual outcome (rather than asserting `false` generically) if a
/// breaking-change fixture instead comes back `Messages` or `Ignored` — the
/// two ways a real schema change could otherwise be silently swallowed
/// instead of surfaced.
pub fn breaking_change_is_reported_not_silently_dropped(outcome: &NormalizationOutcome) {
    match outcome {
        NormalizationOutcome::Unrecognized { discriminator } => {
            assert!(
                !discriminator.is_empty(),
                "Unrecognized must carry a non-empty discriminator"
            );
        }
        other => panic!(
            "expected a breaking-change fixture to come back Unrecognized \
             (actionable), got {other:?} instead (silent data loss/drop)"
        ),
    }
}
