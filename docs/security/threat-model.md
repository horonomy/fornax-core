# Fornax threat model

Jira: FORNX-233. Durable and repo-level, not regenerated per candidate —
see [`docs/release-security-gate.md`](../release-security-gate.md) for how
this document is used inside the release security gate. This document
enumerates every trust boundary in the shared surface vocabulary
(`docs/release-candidate-evidence.md`, FORNX-231), its current controls,
and known residual risk, as of `threat_model_version` below.

`threat_model_version: 2`

## How this document is maintained

- Any release candidate classified `TRUST_BOUNDARY` or higher
  (`docs/release-assurance-policy.md`, FORNX-229) must append a "Changelog"
  entry (below) recording which boundary changed and how this document's
  description of that boundary was updated — or an explicit statement that
  the boundary's description was reviewed and confirmed unchanged.
- A `MAJOR_OR_GA` candidate requires every boundary below to be re-reviewed
  in the same pass, not only the touched ones, and the changelog entry must
  say so explicitly (`full_review: true`).
- Bumping `threat_model_version` is required whenever a boundary's
  *description* changes (new control, changed data flow, newly identified
  residual risk) — not required for a changelog entry that only confirms
  "reviewed, unchanged."

## Trust boundaries

Ten boundaries, matching the ten `trust boundary: yes` rows of
`docs/release-candidate-evidence.md`'s Shared surface vocabulary table.

### `daemon_socket` — local daemon/socket surface

**Description:** `fornax-daemon` listens on a local Unix domain socket;
adapters/hooks connect to it to report events and read verdicts.
**Current controls:** socket file permissions restricted to the invoking
user (see `docs/release/v0.0.1-qa-security-signoff.md` §"FORNX-57" for the
WAL/SHM sidecar hardening precedent); no network-facing listener exists —
the daemon does not bind a TCP/UDP port. All message processing is
serialized behind a single `AppState.processing` lock (FORNX-281 fix,
`docs/release/v0.0.1-qa-security-signoff.md` §7.6), closing a race where an
out-of-order write/read across independently-spawned per-connection tasks
could compute a wrong verdict.
**Known residual risk:** none currently open above Low. A future
multi-daemon or remote-daemon design would need this section revisited
before shipping.

### `adapter_provider_input` — adapter/provider input handling

**Description:** `fornax-adapter-claude`, `fornax-adapter-codex`,
`fornax-adapter-opencode` parse hook/event payloads from their respective
CLI tools (Claude Code, Codex, opencode) and forward normalized events to
the daemon. As of v0.0.3 (FORNX-161, FORNX-244) this boundary spans three
genuinely distinct integration shapes, not variations on one: Claude
Code's external hook-script process spawned per event, Codex's
poll/tail of a rollout file the CLI writes on its own schedule, and
opencode's in-process JavaScript/TypeScript plugin
(`@opencode-ai/plugin`) that opencode's own runtime invokes synchronously
around real events and that itself spawns a long-lived companion binary
(`fornax-hook-opencode`), piping one NDJSON line per hook invocation to
its stdin for the life of the opencode process
(`crates/fornax-adapter-opencode/plugin/fornax-capture.js`). The last shape
is reviewed separately under `sdk_plugin_trust` below for the
plugin-hosting-process angle; this section covers the payload-parsing
angle common to all three.
**Current controls:** adversarial daemon/adapter input corpus (malformed
JSON, missing/wrong-type/unknown fields, deep nesting, oversized strings,
control characters, path-traversal-looking strings, shell metacharacters,
replayed event IDs) exercised against a real daemon + `fornax-hook-claude`
with zero crashes/panics/subprocess-spawns/filesystem-escapes
(`crates/fornax-daemon/tests/adversarial_daemon_input.rs`, fornax-core#30).
No `std::process::Command`/shell-invocation surface exists anywhere in
production source for untrusted input to reach (verified by exhaustive
grep, `docs/release/v0.0.1-qa-security-signoff.md` §3.2). For opencode
specifically (FORNX-244 review): `OpenCodeAdapter::translate` never derives
`RuntimeCapabilities` values from the native payload — `probe()` returns a
fixed declaration keyed only to the adapter's own build, so a payload
cannot claim a capability the adapter doesn't actually implement; a missing
`hook`/malformed shape returns `Unrecognized`/`Ignored` rather than
panicking (`crates/fornax-adapter-opencode/src/lib.rs` tests
`missing_hook_field_is_unrecognized_not_a_crash`,
`unknown_hook_is_unrecognized_not_a_crash`); `ExtensionEnvelope`
deserialization rejects an incompatible `schema_version` explicitly rather
than silently accepting it
(`crates/fornax-adapter-conformance/tests/contract.rs`
`a_version_incompatible_extension_envelope_is_rejected_not_silently_accepted`).
**Known residual risk:** Informational — `fornax-adapter-claude`'s
`last_assistant_text` reads a `Stop` hook's `transcript_path` via
`std::fs::read_to_string` with no confinement to `$FORNAX_HOME`; a
`../../`-style path could be read if it happens to parse as the expected
transcript JSONL. No privilege boundary is crossed (the hook runs as the
invoking user). Tracked as a future confinement check, not currently
blocking. See `evidence_provenance` below for a High-severity
cross-provider capability-downgrade finding whose root cause is
provider-controlled data flowing through this boundary
(`RuntimeCapabilities.notes["session_id"]`).

### `evidence_provenance` — evidence/provenance integrity

**Description:** the daemon's SQLite store persists observed events and
computed claims/verdicts; this data is the evidentiary record the product's
five-state verdict vocabulary (ADR-0001 D4) is built on.
**Current controls:** WAL/SHM sidecar file permissions hardening
(FORNX-57); serialized message processing (FORNX-281) prevents an
evidence write racing a read of the same session's prior state.
`fornax-daemon`'s `handle_message` never derives `CollectionMethod` or
`Evidence.provenance` from raw provider JSON — each sensor hardcodes its own
value at construction time (e.g. `OpenCodeExitCodeSensor::collection_method`
always returns `CollectionMethod::HookCallback`, `provenance` is built via
`format!("opencode:{v}:tool.execute.after#metadata.exit", ...)` with no
provider-payload interpolation of the trust-relevant part), so
provider-supplied payload data cannot forge a stronger trust class or a
fabricated provenance string (FORNX-244 review, verified by reading
`crates/fornax-adapter-opencode/src/lib.rs`).
**Known residual risk:** High, found and fixed in this review (FORNX-244,
SEC-v0.0.3-0002) — `RuntimeCapabilities.notes["session_id"]` is
provider-controlled data (an adapter reads it straight off the native
payload, e.g. opencode's `/input/sessionID`), and the daemon's in-memory
`state.caps` cache (read by the `Claim` handler to gate every verifier) was
a single slot per `session_id` with no provider check: a same-session
`Capabilities` announcement from a different provider than the one already
cached silently overwrote it — a real cross-provider capability
*downgrade* that could suppress verification and hide evidence, exactly
the shape of this ticket's "capability spoofing/downgrade" focus item. The
persisted store was never affected (`Store::upsert_capabilities` is
correctly scoped to `(session_id, provider)`); only the in-memory read path
`handle_message`'s `Claim` arm consults was. Fixed by refusing to overwrite
an already-cached session's capability snapshot from a different provider
(`crates/fornax-daemon/src/main.rs`'s `Capabilities` arm).

### `egress_redaction` — egress/redaction behavior

**Description:** any path by which locally-observed data (event payloads,
claim text, transcript content) leaves the local trust boundary — export
spool, uploader, cloud ingest.
**Current controls:** `redact_json`/`redact_text` applied at the daemon's
ingestion boundary to every field that reaches storage, including
`tool_input`/`Claim.text` (fixed after FORNX-280, see "Known residual risk"
below for what was found); `fornax-uploader`'s `guard.rs` is an independent
last-line-of-defense check against unredacted secrets reaching the cloud,
covered by its own unit suite (14 passed, `docs/release/v0.0.1-qa-security-signoff.md`
§3.4) plus a live full-stack secret-egress canary re-verification.
**Known residual risk:** Critical, found and fixed — FORNX-280: a
random-hex canary reached the daemon log, SQLite store, and
`fornax export-spool` output unredacted via `AgentEvent.tool_input` and
`Claim.text`, before the ingestion-boundary fix above. Re-verified clean
after the fix. The full downstream `fornax-uploader` → ingest/Pub-Sub →
backend → Postgres → SaaS-UI pipeline was not re-exercised end-to-end after
the fix (a real, disclosed gap, not rounded up to PASS) — tracked in the
FORNX-239 Jira thread's coverage reconciliation. High, found and fixed in
this review (FORNX-244, SEC-v0.0.3-0001) — FORNX-158's `Evidence.extension`
(`ExtensionEnvelope`) is a second path into storage/export alongside
`Evidence.payload`, and `handle_message`'s `Evidence` arm redacted
`payload` but not `extension.fields`/`extension.unknown` before this fix.
opencode's `tool.execute.after` sensor is the first real producer of an
extension envelope and carries the bash tool's own command `title` in it
(`build_tool_telemetry_extension`,
`crates/fornax-adapter-opencode/src/lib.rs`) — exactly as
attacker/agent-controlled as `tool_input` was in FORNX-280, and reachable
by the exact same `fornax export-spool` path
(`evidence_envelope_carries_extension_data_through_export`,
`crates/fornax-cli/src/main.rs`, spools `Evidence` "as-is"). Fixed by
applying `redact_json` to both `extension.fields` and `extension.unknown`
at the same ingestion boundary as `payload`.

### `cloud_identity_tenant` — cloud identity/tenant authorization

**Description:** owned by `fornax-cloud`, not this repo — the SaaS
backend's tenant isolation and authentication/authorization surface.
**Current controls:** out of this repo's scope; see `fornax-cloud`'s own
threat-model/security documentation once it exists.
**Known residual risk:** not assessed in this document. A candidate
spanning `fornax-cloud` with a `TRUST_BOUNDARY`-or-higher change to this
boundary needs a `fornax-cloud`-side threat-model entry, cross-referenced
here rather than duplicated.

### `browser_rendering_injection` — browser rendering/injection surface

**Description:** the `fornax-cloud` React frontend (Evidence dashboard)
renders claim/rationale/evidence text sourced from adapter-observed data.
**Current controls:** static sink enumeration found zero
`dangerouslySetInnerHTML`, zero `innerHTML`/`insertAdjacentHTML`/
`document.write`/`new Function`, no raw-HTML markdown renderer, no
`javascript:`-URI construction; rendered fields use plain JSX text-child
expressions, which React escapes by default
(`docs/release/v0.0.1-qa-security-signoff.md` §3.3). Confirmed live: a
Playwright session injected four XSS payloads
(`<script>`, `<img onerror>`, attribute-breakout `">`, `javascript:` URI)
into claim text end-to-end through the real frontend; zero execution, all
rendered as inert text (`docs/release/0001-fornx-238-dashboard-xss-check.md`).
**Known residual risk:** Informational — the dashboard's `html_escape`
helper does not escape quotes; safe today only because no rendered field is
placed inside an HTML attribute. Revisit if that changes.

### `event_transport` — event transport

**Description:** the path an event takes from adapter/hook to daemon
(local socket) and from daemon/spool to cloud ingest (network).
**Current controls:** see `daemon_socket` and `egress_redaction` above —
this boundary's controls are the union of both; no independent
event-transport-specific control exists beyond them today.
**Known residual risk:** see the two boundaries above.

### `judge_replay_execution` — judge/replay execution

**Description:** any component that replays or re-evaluates prior evidence
to (re)compute a verdict.
**Current controls:** not yet a distinct implemented surface in this repo
as of `threat_model_version: 2` (confirmed unchanged in the FORNX-244 pass) — no dedicated judge/replay execution
component exists in the current crate set (`crates/`). This section is a
placeholder pending that capability's design.
**Known residual risk:** not assessed — nothing to assess yet. Adding a
judge/replay component requires a `TRUST_BOUNDARY`-or-higher classification
and a threat-model changelog entry here before release.

### `enterprise_policy_deployment` — enterprise policy/deployment

**Description:** any enterprise-managed policy or deployment configuration
surface (e.g. managed settings, org-wide policy enforcement).
**Current controls:** not yet a distinct implemented surface in this repo
as of `threat_model_version: 2` (confirmed unchanged in the FORNX-244 pass).
**Known residual risk:** not assessed — nothing to assess yet, same
placeholder status as `judge_replay_execution`.

### `sdk_plugin_trust` — SDK/plugin trust

**Description:** trust granted to third-party SDK integrations or plugins
consuming Fornax data or extending its behavior. No longer a placeholder as
of v0.0.3 (FORNX-161, FORNX-244): `plugin/fornax-capture.js` is a real
`@opencode-ai/plugin` `Plugin` — an in-process JavaScript module that
opencode's own runtime loads and whose `Hooks` it invokes synchronously
around real events, running inside opencode's own process (not a
sandboxed/isolated one). This is the inverse trust direction from the
other two providers: Claude Code and Codex never load any Fornax code into
their own process, whereas opencode does.
**Current controls:** the plugin's job is transport-only — it JSON-encodes
each hook's `input`/`output` verbatim and writes it to a spawned
`fornax-hook-opencode` child's stdin; it never `eval`s, requires, or
executes anything derived from a hook payload, and never returns a value
that could change a tool call's real args (`tool.execute.before` mutation
capability exists in opencode's API but this plugin only observes, never
rewrites — `fornax-adapter-opencode/src/lib.rs`'s own capability doc
confirms this by design). `fornax-hook-opencode` is resolved by bare name
off `PATH`, spawned once at plugin init inside opencode's process — same
trust class as `adapter_provider_input`'s existing `last_assistant_text`
residual risk (no privilege boundary crossed; the child runs as the
invoking user, not a different one). FORNX-291 found and fixed two
failure-mode defects in this integration, both confirmed still fixed in
the code reviewed here: (1) an unhandled `error` event on the spawned
`ChildProcess` was previously a fatal, uncaught exception in the *parent*
process — i.e. in opencode itself, since the plugin runs in-process — when
`fornax-hook-opencode` isn't on `PATH`; a `child.on("error", ...)` (and
`child.stdin.on("error", ...)`) listener now swallows it
(`plugin/fornax-capture.js` lines 31–39); (2) `dispose()` now awaits
`child.stdin.end()`'s callback (bounded by a 200ms timeout so a dead/hung
child can never delay opencode's own shutdown) instead of firing `end()`
and returning immediately, closing the race that could previously drop the
last queued event on a fast opencode shutdown (`plugin/fornax-capture.js`
lines 56–70).
**Known residual risk:** Informational — a dead/missing/wrong-PATH
`fornax-hook-opencode` silently drops all evidence collection for the
opencode session with no user-visible signal beyond opencode's own stderr
being `"ignore"`d (`spawn(..., { stdio: ["pipe", "ignore", "ignore"] })`);
this is a silent availability gap, not a confidentiality/integrity one —
tracked as a future observability improvement, not currently blocking.
No new npm dependency was introduced (`plugin/fornax-capture.js` uses only
`node:child_process`, a Node builtin; no `package.json` exists for this
plugin) and no new Cargo dependency was introduced in
`fornax-adapter-opencode` (all of `serde`/`serde_json`/`tokio`/`anyhow`/
`chrono`/`uuid` are pre-existing workspace-pinned dependencies).

## Changelog

| Version | Date | Candidate | Change |
|---|---|---|---|
| 1 | 2026-09-01 | (retroactive, v0.0.1) | Initial threat model, FORNX-233. Boundary descriptions for `daemon_socket`, `adapter_provider_input`, `evidence_provenance`, `egress_redaction`, `browser_rendering_injection`, `event_transport` populated retroactively from v0.0.1's actual sign-off evidence (`docs/release/v0.0.1-qa-security-signoff.md`, `docs/release/0001-fornx-238-dashboard-xss-check.md`). `cloud_identity_tenant`, `judge_replay_execution`, `enterprise_policy_deployment`, `sdk_plugin_trust` recorded as not-yet-implemented placeholders pending those capabilities' design. |
| 2 | 2026-09-01 | v0.0.3 | FORNX-244 (extensibility/third-provider security review). `adapter_provider_input` description updated: opencode's in-process plugin + long-lived companion binary is a third, genuinely distinct integration shape alongside Claude Code's external hook script and Codex's file-tail. `sdk_plugin_trust` moved off placeholder: real description/controls for `plugin/fornax-capture.js`, including confirmation that FORNX-291's two disclosed failure modes (unhandled child-process `error` crashing opencode itself; `dispose()` not awaiting queued-write flush) are fixed in the reviewed code. `evidence_provenance` and `egress_redaction` each record one High-severity finding found and fixed in this pass: a cross-provider capability-cache downgrade (SEC-v0.0.3-0002) and an unredacted `ExtensionEnvelope` egress path (SEC-v0.0.3-0001). `judge_replay_execution`/`enterprise_policy_deployment` reviewed and confirmed unchanged (not `full_review`; only the candidate's touched boundaries were re-examined, per FORNX-233). See `release/v0.0.3-trust-boundary-delta.json` and `docs/release/v0.0.3-security-signoff.md`. |
