# Golden fixtures

Real, sanitized provider-native event shapes, one JSON file per fixture,
loaded by `fornax_adapter_conformance::load_fixtures` and replayed through a
live adapter by `fornax_adapter_conformance::replay_fixture` (see
`crates/fornax-adapter-conformance/src/fixtures.rs` and `src/lib.rs`).

## File shape

```json
{
  "provider": "claude_code",
  "provider_runtime_version": "2.1.238",
  "description": "One sentence: what real (or deliberately synthetic) shape this captures and why it matters.",
  "sanitized": true,
  "historical_schema_drift_ticket": null,
  "native_events": [ { "...": "one or more native payloads, replayed in order against one adapter instance" } ]
}
```

- `provider` — `claude_code` or `codex`, matching `fornax_types::Provider`'s wire tag.
- `provider_runtime_version` — the real provider CLI/runtime version this
  shape was confirmed against (see `docs/research/adapter-capability-matrix.md`),
  `"synthetic"` for a deliberately fabricated breaking-change fixture that
  was never observed live (see the `unrecognized_future_*` fixtures), or
  `"unconfirmed"` for a shape that is real (not fabricated) but whose exact
  emitting provider version was not recorded at capture time — say so
  honestly in `description` rather than inventing a version number (see
  `codex/exec_command_end.json`).
- `sanitized` — must be `true`. `load_fixtures` panics on any fixture
  missing this or set to `false` — a fixture that cannot prove it was
  sanitized must never load silently. Sanitizing means: no real usernames,
  no real filesystem paths outside a generic placeholder (`/workspace`,
  `/tmp/...`), no real command output/tokens/secrets, no real session ids
  (`fixture-*` placeholders only).
- `historical_schema_drift_ticket` — optional. Set only when this fixture
  captures a real, previously-shipped provider shape that once broke an
  adapter's assumption (a genuine regression fixture) — e.g. `"FORNX-55"`.
  `null`/omitted for every other fixture. Do not fabricate a ticket
  reference; see `docs/contributing/adding-an-adapter.md`'s "Detecting
  upstream schema drift" section for how a real one gets here.
- `native_events` — one or more native payloads. More than one entry means
  the fixture is a stateful sequence (e.g. Codex's `custom_tool_call` /
  `custom_tool_call_output` call-id pairing) that must be replayed against
  the *same* adapter instance, in order, to reproduce the real behavior.

## Adding a fixture

1. Capture (or, for a breaking-change probe, construct) the native shape.
2. Sanitize it — strip anything real per the `sanitized` rule above.
3. Write the JSON file here, named for what it demonstrates
   (`snake_case.json`).
4. Add a test in `tests/golden_fixtures.rs` (or extend an existing
   parameterized one) asserting the expected `NormalizationOutcome`.
