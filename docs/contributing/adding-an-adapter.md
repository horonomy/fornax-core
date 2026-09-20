# Adding a new provider adapter

See `docs/adr/0004-adapter-contract.md` for the full rationale. This is the
practical checklist and worked example.

Also see, before you start:

- `docs/research/evidence-sensor-contract.md` — the `EvidenceSensor`/
  `EvidenceSource` contract, trust classes, and provenance requirements a new
  sensor implements.
- `docs/research/adapter-capability-matrix.md`'s "Consolidated compatibility
  matrix" — the canonical, code-grounded per-provider `SignalClass` table;
  keep it current when your adapter's `probe()` declares new signals.
- `docs/adr/0005-schema-evolution.md` — if your adapter needs to report
  something genuinely provider-specific that doesn't fit an existing
  canonical `EvidenceKind`, this is the `ExtensionEnvelope` contract (schema
  versioning, unknown-field tolerance, and the promotion-to-canonical
  criteria) rather than inventing an ad hoc untyped field.
- `docs/privacy-redaction-policy.md` — **read this before populating
  `ExtensionEnvelope::fields`**: the redaction boundary in
  `fornax-daemon`'s `handle_message` currently redacts `Evidence::payload`
  only, not `Evidence::source`/`Evidence::extension` (a known, disclosed
  gap, not fixed as of this writing). Do not put raw provider secrets or
  unredacted sensitive text into an extension payload today.

Together, this file plus the three docs above are the full extension
contract FORNX-87 originally scoped as a single integration guide. They stay
as separate, cross-linked documents rather than one merged file — each is
already living/versioned next to the code it describes (`fornax-types`'s
`sensor.rs`/`capabilities.rs`/`extension.rs`) and merging them would create
one large doc no single change actually touches end-to-end. FORNX-87's own
remaining scope — porting this material into the unified Docusaurus site
(`fornax-docs`) — is unaffected by this reconciliation and stays tracked on
that ticket.

## 1. Create the crate

```
crates/fornax-adapter-<provider>/
  Cargo.toml
  src/
    lib.rs   # AgentAdapter + CapabilityProbe impl — all translation logic
    main.rs  # transport plumbing only: read native input, call normalize(), write to the UDS
```

Add both a `[lib]` and a `[[bin]]` target to `Cargo.toml` (see
`crates/fornax-adapter-claude/Cargo.toml` for the exact shape), and add the
crate path to the workspace `members` list in the repo-root `Cargo.toml`.
`fornax-types` is the only Fornax crate this crate may depend on — see the
ADR's "Allowed core dependencies".

## 2. Implement `CapabilityProbe`

Declare, conservatively, what this adapter's runtime can actually observe —
never infer a class as `Available` you have not confirmed. Every
`SignalClass` your adapter cannot expose should be `Unsupported` (runtime
fundamentally can't) or `Unavailable` (exists in principle, not observed
this session), each with a `detail` string citing your evidence (a real
captured payload, the provider's own docs, a version number).

```rust
impl CapabilityProbe for WidgetAdapter {
    fn probe(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Widget, // add a new Provider variant first
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                // ... one CapabilitySignal per SignalClass your transport
                // can say something concrete about.
            ],
            notes: HashMap::new(), // session_id/adapter_version stamped separately, see step 4
        }
    }
}
```

## 3. Implement `AgentAdapter::normalize`

One `match` (or equivalent) over your provider's native discriminator field,
producing a `NormalizationOutcome` per case:

```rust
impl AgentAdapter for WidgetAdapter {
    fn provider(&self) -> Provider { Provider::Widget }
    fn adapter_version(&self) -> &'static str { env!("CARGO_PKG_VERSION") }

    fn normalize(&mut self, session_hint: &str, native: &serde_json::Value) -> NormalizationOutcome {
        let Some(kind) = native.get("event_type").and_then(|v| v.as_str()) else {
            return NormalizationOutcome::Unrecognized {
                discriminator: "<missing event_type>".to_string(),
            };
        };
        match kind {
            "tool_call_finished" => {
                // ... build AgentEvent/Evidence from confirmed fields only ...
                NormalizationOutcome::Messages(vec![/* ... */])
            }
            "heartbeat" => NormalizationOutcome::Ignored {
                reason: "heartbeat: transport keepalive, no canonical mapping",
            },
            other => NormalizationOutcome::Unrecognized {
                discriminator: other.to_string(),
            },
        }
    }
}
```

Rules, from the contract:

- **Never** put a raw, un-vetted provider payload into a canonical message's
  free-form fields as a way of "not losing information" for a shape you
  don't recognize. That is `Unrecognized`'s job, and it carries only a type
  tag — see the ADR's "Unknown-event policy".
- **Never** return an `Err`/panic from `normalize`. Malformed or unexpected
  input is expected input.
- If your transport needs to correlate two native payloads across calls
  (a start/end pair, request/response by id), hold that state as a field on
  your adapter struct — `normalize` takes `&mut self` for exactly this.

## 4. Stamp adapter/version metadata

Attach `adapter_version` and (once known) `session_id` to every capability
declaration via `notes`, the same way both existing adapters do:

```rust
fn stamped_capabilities(adapter: &WidgetAdapter, session_id: &str) -> RuntimeCapabilities {
    let mut caps = adapter.probe();
    caps.notes.insert("session_id".to_string(), session_id.to_string());
    caps.notes.insert("adapter_version".to_string(), adapter.adapter_version().to_string());
    caps
}
```

Include your adapter's identity in any `Evidence::provenance` string you
construct too (e.g. `"widget:<adapter_version>:tool_call_finished"`), so a
finding's rationale can always be traced back to which adapter version
produced the evidence behind it.

## 5. Write the thin `main.rs`

`main.rs` owns reading native input (stdin, a tailed file, a socket — however
your provider actually exposes events) and writing `IngestMessage`s to the
daemon's Unix Domain Socket. It calls `normalize()` and switches on the
`NormalizationOutcome` to decide what to send; it contains no field-name
literals from the provider's native shape. Model it on
`crates/fornax-adapter-claude/src/main.rs` (stateless, one-shot per
invocation via stdin) or `crates/fornax-adapter-codex/src/main.rs`
(long-lived, tailing a transcript file) depending on whether your provider's
integration point is invocation-based or transcript-based.

**Gap found by FORNX-161 (opencode):** neither template above fits a
provider whose real integration point is an in-process plugin/callback API
(the provider's own runtime loads your code and invokes it directly, rather
than spawning your binary per event or leaving a file for you to tail). For
that shape, use a **third pattern**: a small companion script in the
provider's own plugin language that the provider loads in-process, which
spawns your adapter's binary *once* as a long-lived child process and pipes
one line per real hook invocation to its stdin for the life of that process
— see `crates/fornax-adapter-opencode/plugin/fornax-capture.js` and
`crates/fornax-adapter-opencode/src/main.rs` for the worked example. Your
binary's `main.rs` still contains no field-name literals and still only
calls `normalize()` — only the framing (loop over stdin lines instead of one
stdin read) and the process's lifetime differ.

## 6. Wire into the conformance suite

`crates/fornax-adapter-conformance` (FORNX-156, extended into the full
golden-fixture kit by FORNX-160) is the one place every adapter's conformance
is proven, and the entry point a future third-party adapter author should
copy from. Two things to add, both required:

**a. The property suite** (`tests/conformance.rs`). Add your crate as a
`[dev-dependencies]` entry in `crates/fornax-adapter-conformance/Cargo.toml`,
then add a fixture function and two tests mirroring the existing
`claude_*`/`codex_*` tests:

- `<provider>_adapter_satisfies_the_conformance_contract` — runs the generic
  property checks (`probe_provider_matches_declared_provider`,
  `provider_is_stamped_consistently`,
  `every_message_round_trips_through_the_wire_protocol`) against a handful
  of real native fixtures.
- `<provider>_adapter_handles_an_unrecognized_native_event_per_policy` — a
  synthetic, never-seen shape must come back `Unrecognized` with a
  non-empty `discriminator`, never a panic.

**b. Golden fixtures** (`fixtures/<provider>/*.json`, replayed by
`tests/golden_fixtures.rs` and `tests/contract.rs`). Add at least:

- One fixture per real, distinct native shape your adapter recognizes
  (a "happy path" per event kind you translate), sanitized per
  `fixtures/README.md`'s rule (no real usernames/paths/tokens/session data).
- One `unrecognized_future_*.json` synthetic breaking-change probe — a
  shape you fabricate, never observed live, that your adapter has no
  mapping for. This is what proves a real future upstream break would come
  back as an actionable `Unrecognized` error (see `breaking_change_is_reported_not_silently_dropped`
  in `src/lib.rs`), not silent data loss.
- Run your fixtures through the shared contract checks
  (`capability_declaration_is_well_formed`, `evidence_sources_are_valid`,
  `evidence_payloads_validate_against_their_canonical_schema`) the same way
  `tests/contract.rs` does for Claude/Codex — these are generic over any
  `AgentAdapter` and need no new harness code per provider.
- If you ever discover a **real** shape your adapter previously assumed
  wrong and had to fix (a genuine historical schema-drift bug, not a
  hypothetical one), fixture the exact real shape and set
  `historical_schema_drift_ticket` to the ticket that fixed it — see
  `fixtures/codex/custom_tool_call_exec_pair.json` (FORNX-55) for a worked
  example, and the "Detecting upstream schema drift" section below for how
  a real one gets found in the first place. Never fabricate one.

If your adapter needs a new `Provider` variant, add it to
`fornax_types::Provider` (`crates/fornax-types/src/lib.rs`). **Confirmed by
FORNX-161** (the first adapter to actually add a third variant, `OpenCode`):
`cargo check --workspace` and `cargo clippy --workspace --all-targets -- -D
warnings` both pass with zero changes required anywhere outside
`fornax-types/src/lib.rs` itself — there is no exhaustive `match` over
`Provider` anywhere in `fornax-daemon`, `fornax-store`, `fornax-verify`, or
`fornax-cli`; every reference is a literal constructor
(`Provider::ClaudeCode`/`Provider::Codex`), never a switch that would fail
to compile on a third variant. `LegacyCapabilitiesWire` is likewise generic
over `provider: Provider`, not hardcoded to two.

The one real constraint is **not** in this repo: `horonomy/fornax-cloud`'s
ingest boundary enforces a closed, 2-variant `Provider` enum (see
`fornax-daemon::default_unknown_caps`'s doc comment). Nothing in this repo
needs fornax-cloud's enum extended to add a local adapter — the local
daemon, store, and CLI never consult it — but `fornax export-spool` will
produce a `provider` value fornax-cloud's ingest API will reject with a
real 422 if a session from your new provider is ever exported there. Adding
support for your provider on the fornax-cloud side (a separate, out-of-scope
repo) is a prerequisite for cloud sync, not for local monitoring.

## 7. Verify

```
cargo test -p fornax-adapter-<provider>
cargo test -p fornax-adapter-conformance
cargo clippy --workspace --all-targets -- -D warnings
```

## Detecting upstream schema drift

Both Claude Code and Codex are actively-changing surfaces
(`docs/research/adapter-capability-matrix.md`'s own header: "re-verify
before an adapter hard-codes field names"). Neither ships a stable, versioned
public schema, so Fornax cannot subscribe to a change notice — a maintainer
has to notice drift by comparison. This is how:

1. **Version-pin what "confirmed" means.** Every golden fixture in
   `crates/fornax-adapter-conformance/fixtures/` carries the real
   `provider_runtime_version` it was captured against
   (`fixtures/README.md`). That is the baseline: "as of Claude Code
   v2.1.238 / codex-cli 0.147.0, this is the exact shape this adapter
   relies on."
2. **Periodically re-capture against a live session.** When bumping to a
   newer Claude Code or Codex CLI, capture one real session (a hook payload
   dump, a fresh rollout JSONL) and diff its shapes against the checked-in
   fixtures for the *same* event kinds — not just "does the adapter still
   compile," but "does the real payload still have every field this
   adapter's `normalize`/`EvidenceSensor`s read." A field silently renamed
   or removed will not fail compilation; it fails a live diff or (if
   unlucky) reads as `Unavailable`/`Unrecognized` in production first.
3. **The explicit bump ritual.** If a re-capture confirms a real shape
   change:
   - Add a new fixture capturing the new real shape (do not overwrite the
     old one if the old shape can still occur against an older installed
     CLI version — keep both, distinguished by `provider_runtime_version`).
   - Fix the adapter to handle the new shape (see FORNX-55's commit,
     `4437c00`, for the shape of this fix: correlate/parse the new shape,
     keep the old path working if the old shape can still occur, mark any
     new heuristic as `heuristic: true` rather than inventing an
     authoritative field).
   - Add or update the corresponding `historical_schema_drift_ticket`
     fixture and regression test once the fix lands, so a future regression
     to the old (now-wrong) assumption is caught automatically.
   - Update `docs/research/adapter-capability-matrix.md`'s confirmed-shape
     tables to match.
4. **Never guess a shape from secondary sources for a live parser.** The
   capability matrix doc's own Codex table is explicit about this: research
   from issues/PRs motivates *where to look*, but the adapter itself must be
   coded against a real captured payload, and the golden fixture for that
   payload is what proves it — see FORNX-55, where the shape assumed from
   secondary research (`event_msg{type:exec_command_end}`) turned out to
   never occur in the installed CLI at all.
