# ADR 0004: `AgentAdapter` — the provider-adapter boundary and normalization contract

Status: Accepted
Date: 2026-08-30
Jira: FORNX-156 (child of FORNX-138)

## Context

FORNX-155 formalized *what a provider integration can observe*
(`RuntimeCapabilities`/`SignalClass`/`SignalAvailability`). It did not define
*how* a provider integration observes it, or what shape core code may assume
every provider integration has. Before this ticket, `fornax-adapter-claude`
and `fornax-adapter-codex` were bin-only crates: `main.rs` mixed transport
plumbing (stdin reads, UDS writes, file tailing) with translation logic
(`translate`/`translate_line`) as private free functions. Nothing outside
either binary could call that logic, so there was no way to prove — short of
reading both files side by side — that the two adapters actually agreed on
what a "conforming adapter" does. This ADR records that contract so it
doesn't have to be re-derived, and so a third provider adapter has a trait to
implement rather than a binary to reverse-engineer.

## Decision

### The `AgentAdapter` trait

```rust
pub trait AgentAdapter: CapabilityProbe {
    fn provider(&self) -> Provider;
    fn adapter_version(&self) -> &'static str;
    fn normalize(&mut self, session_hint: &str, native: &serde_json::Value) -> NormalizationOutcome;
}
```

Defined in `crates/fornax-types/src/adapter.rs`. A **supertrait** of
`CapabilityProbe` (FORNX-155), not a duplicate of it — an adapter's
capability declaration and its normalization logic are separate concerns
implemented by the same type. This lets core code that only needs
capabilities (e.g. a verifier's `is_observable` gate) keep depending on
`CapabilityProbe` alone, unchanged by this ticket.

`normalize` takes `&mut self` because a transport may need cross-call state
(Codex's `custom_tool_call`/`custom_tool_call_output` pairing by `call_id` —
FORNX-55); `session_hint` lets a caller supply what it knows so far (a
long-lived tailing loop's best-known session id) without forcing every
adapter to derive its own — an adapter should prefer a session id it can
read out of the native payload itself when one is present, falling back to
the hint otherwise. Neither source is authoritative in general; which one is
available is itself a transport-specific fact (see
`docs/research/adapter-capability-matrix.md`).

`normalize` never returns a `Result`: a malformed or unrecognized native
payload is expected input, not an exceptional condition (see "Error
semantics" below).

### Lifecycle

There is no explicit session-start/session-end method. Claude Code hooks are
stateless per-invocation processes with no guaranteed single "session start"
moment; Codex's rollout-tail is a long-lived process that reads a session's
lifecycle out of the transcript itself. Session boundaries are expressed as
ordinary `EventKind::SessionStart`/`SessionEnd` events flowing through
`normalize`, which is what lets one trait fit both transports without
forcing either into the other's shape.

`CapabilityProbe::probe()` (FORNX-155) is documented as safe to call once per
adapter *process*, not once per *session* — Claude's adapter announces on
every event (there is no reliable single moment to announce once); Codex's
announces once per connection, gated on a `caps_sent` flag in `main.rs`. Both
are conforming: the daemon's `(session_id, provider)` upsert, not a
call-once contract on `probe()`, is what makes repeated announcements
idempotent.

### Unknown-event policy: `NormalizationOutcome`

```rust
pub enum NormalizationOutcome {
    Messages(Vec<IngestMessage>),
    Ignored { reason: &'static str },
    Unrecognized { discriminator: String },
}
```

Two structurally different reasons an adapter might not translate a native
payload into a canonical message are kept distinct:

- **`Ignored`** — the shape *is* recognized, and this adapter deliberately
  emits no canonical message for it (Codex's `session_meta` bookkeeping
  line; the invocation half of a `custom_tool_call`/`_output` pair, still
  awaiting its match). `reason` is a short, static string, never user data.
- **`Unrecognized`** — the shape was *not* matched by anything this adapter
  knows about (a future provider event, a schema change). `discriminator`
  carries only the shape's own type tag (Claude's `hook_event_name`; Codex's
  `payload.type`) — **never the payload itself**.

**Chosen policy: log + skip.** An unrecognized native payload is never
persisted or forwarded raw, and never crashes the session observing it.
Log+preserve (forwarding the raw payload for later interpretation) was
considered and rejected: an unrecognized shape is by definition un-vetted
provider-native JSON, and forwarding it would be exactly the uncontrolled
"provider-native payload leakage into domain/storage" this ticket's
acceptance criteria forbid. A safe, versioned envelope for carrying
forward-compatible provider payloads is FORNX-158's job (the "extension
envelope"); `Unrecognized::discriminator` is deliberately the smallest
possible signal — a type tag, not a payload — so that future envelope has
something to key off without this contract pre-building it.

### Adapter/runtime version metadata

`adapter_version()` returns this adapter *implementation's* version
(`env!("CARGO_PKG_VERSION")`), independent of the provider *runtime's*
version (which, where knowable, belongs in a `CapabilitySignal::detail`
string, e.g. "as of v2.1.238" — that's a fact about the provider, not the
adapter). It is attached to every capability declaration via the reserved
`notes["adapter_version"]` key, alongside `notes["session_id"]`
(FORNX-155), and to `Evidence.provenance` strings (e.g.
`claude_code:0.0.1:PostToolUse:Bash#tool_response`).

This rides on the existing `RuntimeCapabilities.notes` map and
`Evidence.provenance` string rather than a new field on `AgentEvent`,
deliberately: `fornax-store::insert_event` persists `AgentEvent` into a
fixed SQLite column schema
(`crates/fornax-store/src/lib.rs::insert_event`), and `fornax-cli`'s
`export-spool` must stay byte-for-byte wire-compatible with
`fornax-cloud`'s closed `RuntimeCapabilities` shape for the *capabilities*
envelope (`LegacyCapabilitiesWire`) — see `fornax-types/src/capabilities.rs`.
Adding a column or a spool-envelope field for adapter version is a
schema/wire change with a cost this ticket did not need to pay; `notes` was
already the reserved, machine-consumed transport for exactly this kind of
per-session provenance metadata.

### Allowed core dependencies

An `AgentAdapter` implementation may depend on `fornax-types` and
general-purpose libraries (serde, tokio, uuid, chrono). It must **not**
depend on `fornax-verify` or `fornax-store` — claim extraction beyond a
cheap, intentionally-duplicated pre-filter (see
`fornax-adapter-claude::fornax_verify_claims_tests_passed`, which does not
import `fornax-verify`) and persistence are core's job. Conversely, core
crates (`fornax-daemon`, `fornax-verify`, `fornax-store`) may depend on
`fornax_types::AgentAdapter` (the trait) but must never depend on a concrete
adapter crate. That dependency direction exists only in
`crates/fornax-adapter-conformance`, a test-only harness crate — see
"Conformance harness" below.

### Error semantics

`normalize` never propagates an error. A malformed or unrecognized native
payload (a hook payload from a newer CLI version, a corrupt line in a tailed
file) is normal, expected input, not an exceptional condition, and must
never tear down an adapter's connection or the session it is observing (D2:
observation must never be what breaks the user's actual coding session).
Genuine I/O failures (stdin unreadable, a rollout file disappearing) are
caught at the transport layer (`main.rs`, outside this trait) and handled by
best-effort skip/retry — never a panic. The conformance suite asserts this
directly: `normalizing_never_panics` feeds each adapter a synthetic,
never-seen shape and a completely empty payload, and requires a
`NormalizationOutcome` back, not a panic.

### Core does not branch on provider name

Auditing `fornax-daemon`, `fornax-store`, and `fornax-verify` for
provider-specific parsing (field-name literals like `hook_event_name`,
`transcript_path`, `exec_command_end`, `custom_tool_call`,
`last_agent_message`) found none — those strings appear only in
doc-comments explaining *why* a canonical field exists, or inside the
adapter crates themselves. Core code consumes only `AgentEvent`/`Claim`/
`Evidence`/`RuntimeCapabilities`, entirely through the canonical shapes this
crate already defined (FORNX-24/FORNX-155). This ADR's contribution is
formalizing the boundary those types already implied, not migrating parsing
that had leaked across it. One pre-existing, out-of-scope gap was found and
left as-is (`fornax-daemon::default_unknown_caps` hardcodes `Provider::Codex`
as a placeholder when no adapter has announced yet) — see that function's
doc comment for why the two candidate fixes are each worse than the bug;
tracked as a FORNX-138 follow-up.

### Conformance harness

`crates/fornax-adapter-conformance` is a test-only crate: its `src/lib.rs`
harness functions are written against `AgentAdapter` alone, with zero
dependency on either concrete adapter; `crates/fornax-adapter-claude` and
`crates/fornax-adapter-codex` are `[dev-dependencies]` used only by
`tests/conformance.rs`. This keeps the "core never depends on a concrete
adapter" rule intact even for the crate whose entire purpose is exercising
both concrete adapters side by side.

Assertions are over **properties**, not message sequences: the two real
adapters differ deliberately in *when* they announce capabilities (every
event vs. once per connection — both conforming, see "Lifecycle" above), so
a sequence-shaped assertion (`msgs[0] == Capabilities`, `msgs.len() == N`)
would be true for one adapter and false for the other by construction, not
because either is broken. The properties checked:

- `provider()` and `probe().provider` never disagree.
- Every `AgentEvent`/`RuntimeCapabilities` emitted carries the adapter's own
  declared `provider()`.
- Every emitted `IngestMessage` round-trips through its own `serde_json`
  wire shape (the actual contract `fornax-daemon::handle_connection` parses
  against).
- `normalize` never panics on a synthetic unrecognized shape or a
  completely empty payload; an `Unrecognized` outcome always carries a
  non-empty `discriminator`.

## Consequences

- A third provider adapter implements `AgentAdapter` + `CapabilityProbe` and
  is automatically exercisable by the conformance suite by adding it as a
  `[dev-dependency]` and a fixture set in `tests/conformance.rs` — see
  `docs/contributing/adding-an-adapter.md`.
- `fornax-adapter-claude`/`fornax-adapter-codex` are now `lib` crates
  (`ClaudeAdapter`/`CodexAdapter`) with thin `main.rs` binaries, matching D5
  ("adapters are thin") more literally than before: the binaries now contain
  only stdin/socket/file-tail plumbing, zero translation logic.
- No extension-envelope schema was built (FORNX-158's job); `Unrecognized`'s
  `discriminator` is the only surface this ticket adds that a future
  envelope might consume.
