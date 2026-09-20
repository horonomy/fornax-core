# Changelog

All notable changes to Fornax are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow the
canonical Fornax release sequence (`v0.0.1` → … → `v0.1.0` GA) tracked in
Jira epic FORNX-20.

## [Unreleased]

Nothing yet.

## [v0.0.3] — Extensible Evidence Platform

Engineering complete: epic FORNX-138 and all children (FORNX-155–162,
FORNX-289–293) are Done. QA/Security sign-off (FORNX-244) is PASS —
see `docs/release/v0.0.3-qa-signoff.md` and
`docs/release/v0.0.3-security-signoff.md`. **Not yet a frozen/tagged
release** — the release itself (FORNX-245) has not run, so unlike
`[v0.0.1]` below there is no candidate manifest or commit-hash table here
yet; those land once FORNX-245 completes. No `v0.0.2` was ever tagged in
this repo — branch names under `v0.0.2/...` reflect in-flight work whose
scope was absorbed into this release; `v0.0.1` is the only prior tag.

### Added

- **Capability taxonomy** (FORNX-155): `SignalClass`/`SignalAvailability`
  (`fornax_types::capabilities`) replace the six fixed `RuntimeCapabilities`
  booleans with an open, three-state model per signal —
  `Available`/`Unsupported`("runtime fundamentally can't")/`Unavailable`
  ("exists in principle, not observed this session"), plus `Unknown` for an
  undeclared class and `Unrecognized` for forward compatibility. Migration
  `0003_capability_signals.sql` is additive (new nullable columns; the old
  bool columns are kept, not dropped).
- **`EvidenceSensor`/`EvidenceSource` contract** (FORNX-157, extended
  FORNX-159): a uniform trait for evidence collection (`AgentAdjacent`/
  `HostObserved`/`IndependentExternal`/`HumanReviewed`/`ModelInternal` trust
  classes) plus structured collection-method/freshness/tamper-boundary
  metadata on every `Evidence` record. See
  `docs/research/evidence-sensor-contract.md`. Additive migration
  (`0004_evidence_source.sql`); pre-existing rows read back with honest
  `PreProvenance`/`None` defaults, never a fabricated guess.
- **Schema evolution: typed canonical payloads + `ExtensionEnvelope`**
  (FORNX-158): `validate_canonical_payload` checks a canonical
  `(EvidenceKind, payload)` pair against a typed, closed struct; a new,
  versioned, opt-in `ExtensionEnvelope` (`Evidence::extension`, additive
  migration `0005_evidence_extension.sql`) carries genuinely
  provider-specific evidence that isn't ready to be a canonical field yet.
  `SUPPORTED_EXTENSION_SCHEMA_VERSIONS = [1, 2]` both parse; an unrecognized
  version fails loudly and specifically rather than being silently accepted.
  See `docs/adr/0005-schema-evolution.md` for the full contract, including
  the promotion-to-canonical criteria and the deprecation/migration ritual.
- **Third provider: opencode CLI adapter** (`fornax-adapter-opencode`,
  FORNX-161, live-transport hardened by FORNX-291/FORNX-292) — an
  open-source, in-process TypeScript plugin adapter running against a local
  Ollama backend, built as an architecture-fitness proof for the
  capability-driven design above. Headline finding: adding a third
  `Provider` variant and running `cargo check`/`clippy --workspace` found
  **zero unexpected core coupling** — no file in `fornax-daemon`,
  `fornax-store`, or `fornax-verify` needed to change. Its `ProcessResult`
  signal is a literal, non-heuristic exit code (`tool.execute.after`'s
  `output.metadata.exit`) — the first of the three adapters to expose one.
  See `docs/research/0002-third-provider-fitness-report.md` and the
  consolidated compatibility matrix in
  `docs/research/adapter-capability-matrix.md`.
- **opencode plugin→binary→daemon transport, proven live end-to-end**
  (FORNX-291, flaky-test root cause fixed in FORNX-292): a real opencode
  session was driven through the real shipped plugin, the real
  `fornax-hook-opencode` binary, and a real `fornax-daemon`/SQLite store,
  with the daemon's own on-disk state inspected as proof of receipt — not
  just the plugin's own exit status. Found and fixed a real bug in the
  process: an unhandled `child.on('error')` on the spawned binary could
  crash opencode itself (not just the capture pipeline) if the binary was
  missing or dead. `crates/fornax-adapter-opencode/tests/live_transport.rs`
  is now a permanent CI regression for this path. See
  `docs/research/0003-opencode-live-transport-verification.md`.

### Fixed

- **`Evidence::extension.fields`/`.unknown` now go through the same
  redaction boundary as `Evidence::payload`** (SEC-v0.0.3-0001).
  `fornax-daemon`'s `handle_message` redacted `payload` before persistence
  but never called `redact_json` on the extension envelope's own
  content — a structural gap found while documenting this release (the
  boundary was already incomplete; the opencode adapter's `ExtensionEnvelope`
  usage just gives it a real, populated field for the first time), found
  and fixed before release, not shipped as a known limitation. See
  `docs/security/threat-model.md`'s `egress_redaction` section and
  `docs/release/v0.0.3-security-signoff.md`.
- **Cross-provider capability-cache spoofing/downgrade** (SEC-v0.0.3-0002).
  `fornax-daemon`'s in-memory capabilities cache was keyed only on
  provider-controlled `session_id` with no provider discriminator, so a
  same-session `Capabilities` announcement from a different provider could
  silently overwrite another provider's cached snapshot — a real capability
  downgrade that could suppress verification and hide evidence. Fixed by
  refusing a cross-provider overwrite of an already-cached session. See
  `docs/security/threat-model.md`'s `evidence_provenance` section and
  `docs/release/v0.0.3-security-signoff.md`.

### Known limitations
- **opencode's LLM tool-calling turn is stubbed, not fully autonomous, on
  local Ollama.** Every locally available Ollama tool-calling model reliably
  degrades real `tool_calls` into plain-text JSON once wrapped in opencode's
  actual ~20k-token production system prompt — reproduced directly against
  Ollama's own HTTP API, independent of opencode. Both the fixture-capture
  work (FORNX-161) and the live end-to-end proof (FORNX-291) stand a
  deterministic stub in for only that one LLM turn; every tool-execution
  event downstream of it (the real spawned process, its real exit code,
  every hook/plugin/binary/daemon hop) is opencode's own genuine,
  unstubbed code. The **transport leg itself is not a limitation** — it is
  now proven live end-to-end and covered by an automated CI regression
  (FORNX-291/FORNX-292, see "Added" above).
- opencode's `FinalResponse` signal is `Unavailable`: the real event stream
  (`message.updated`/`message.part.updated`) genuinely carries the agent's
  final response, but this adapter version doesn't yet translate it
  (scoped out of FORNX-161's single-event-path AC, not a structural gap).
- opencode's `SubagentLifecycle` is `Unsupported`: the `@opencode-ai/plugin`
  Hooks interface (v1.18.25) has no subagent-specific hook at all.
- **Cross-repo constraint, not fixed here**: `horonomy/fornax-cloud`'s
  ingest boundary still enforces a closed, 2-variant `Provider` enum. Local
  monitoring of an opencode session is fully supported, but
  `fornax export-spool` of an opencode session will be rejected by
  fornax-cloud's ingest API with a real HTTP 422 today. Adding opencode
  support on the fornax-cloud side is a prerequisite for cloud sync of
  opencode sessions, not for local use, and is out of this release's scope.

### Upgrade expectations

- **Nothing here is adapter-breaking.** Every new column
  (`schema_version`/`signals` on `runtime_capabilities`; `source` and
  `extension` on `evidence`) is added via `ALTER TABLE ... ADD COLUMN`, is
  nullable, and reads back as `None`/an honest explicit default for rows
  written before that column existed — no destructive migration, no
  rewritten table, in any of `0003`/`0004`/`0005`. No existing adapter
  (`fornax-adapter-claude`, `fornax-adapter-codex`) changed its wire
  behavior or public trait surface.
- `$FORNAX_HOME`'s on-disk schema stability caveat from `[v0.0.1]` still
  applies unchanged — these migrations were verified additive against a
  schema that already includes `0001`–`0002`, not independently re-verified
  against a genuinely untouched `v0.0.1`-era database file. Back up or
  discard `$FORNAX_HOME` before upgrading if in doubt, same guidance as
  `v0.0.1`.

## [v0.0.1] — Local Evidence MVP

Frozen candidate (see `release/v0.0.1-candidate-manifest.json` and
`docs/release/v0.0.1-qa-security-signoff.md`):

| Repo | Commit |
|---|---|
| `horonomy/fornax-core` | `1c078ed31c23ffac8f515e8a46c97c1888c76457` |
| `horonomy/fornax-cloud` | `84f02a0c8c0a14ca64176c22799ba9f4b50c1b4f` |
| `horonomy/fornax-infra` | `13f17453776dcfa63971e18b2b64bec4aa621abc` |
| `horonomy/fornax-docs` | `d7c42731c16b27caf2149817263ba78969ab5937` |
| `horonomy/fornax-website` | `e351cd579adc9d55362ee15a7b07c735223c9f74` |

### Capabilities

- Local daemon (`fornax-daemon`) owning an on-disk SQLite store, a Unix
  domain socket, and a localhost-only HTTP API + dashboard on `:4317`. No
  cloud dependency on this path.
- Real-time evidence capture from **Claude Code** (`fornax-hook-claude`, via
  `PreToolUse`/`PostToolUse`/`SessionStart`/`UserPromptSubmit`/
  `SubagentStart`/`SubagentStop` hooks) and **Codex CLI**
  (`fornax-hook-codex`, primarily via rollout-file tailing — see
  `docs/research/adapter-capability-matrix.md` for the exact, empirically
  verified capability differences between the two adapters; they are not
  equivalent).
- Claim-vs-evidence verification producing exactly one of five verdicts:
  `VERIFIED` / `UNVERIFIED` / `CONTRADICTED` / `REVIEW` / `UNAVAILABLE` —
  never a numeric trust score, never collapsed to fewer states.
- `fornax status` / `fornax detail` CLI, plus the daemon's `/dashboard` view,
  showing the same verdict/claim/evidence/rationale consistently.
- `fornax export-spool` for opt-in sync of a local session to a running
  `fornax-cloud` stack (`fornax-uploader` → ingest → Pub/Sub emulator →
  backend → Postgres → SaaS UI, all runnable locally per
  `horonomy/fornax-infra`'s README).

### Supported environments

- macOS/Linux, Rust workspace built with `cargo build --workspace`.
- Claude Code (hooks wired via `~/.claude/settings.json`) and Codex CLI
  (rollout-file tailer; hooks are opt-in on the Codex side and not required).

### Known limitations

- Cloud sync is **opt-in and off by default**
  (`FORNAX_CLOUD_SYNC_ENABLED`) — nothing in the local Quick Start requires
  it, and there is no hosted Beta or production SaaS offering at this
  version.
- No enterprise governance features, no causal verification, no
  deception/lie-detection capability. Fornax checks agent claims against
  captured tool-call evidence only.
- Codex integration has real, documented gaps versus Claude Code (see
  `docs/research/adapter-capability-matrix.md`): no universal tool-call
  interception with input rewriting, no stable versioned hook schema, hooks
  are opt-in and can be admin-disabled — the rollout-file tailer is the
  primary/durable integration path for Codex, not hooks.
- All data stays local under `$FORNAX_HOME` (default `~/.fornax`, an
  on-disk SQLite database) unless cloud sync is explicitly enabled.

### Upgrade expectations

This is the first tagged release; there is no prior version to upgrade
from. `$FORNAX_HOME`'s on-disk schema is not yet guaranteed stable across
versions — back up or discard `$FORNAX_HOME` before upgrading past v0.0.1
until a migration policy is published.

See `README.md` for the Quick Start and `docs/release/v0.0.1-release-notes.md`
for the canonical public release notes.
