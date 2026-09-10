# Changelog

All notable changes to Fornax are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow the
canonical Fornax release sequence (`v0.0.1` → … → `v0.1.0` GA) tracked in
Jira epic FORNX-20.

## [Unreleased]

### Added

- `fornax-bench regress freeze/compare` (FORNX-344, Stage 8): an integrity
  regression lab reusing `docs/release-assurance-policy.md`'s own
  PASS/BLOCK/INCONCLUSIVE/UNTESTED verdict vocabulary for a fail-closed
  gate over case-level regressions, matched by trajectory id (never by
  position) between a frozen baseline and a fresh run. Breaks a comparison
  down by the only trajectory dimensions this codebase can actually
  observe (sensor, provider) via a new `slice` module. An empty or
  uncalibrated regression budget resolves to `Untested`, never a vacuous
  `Pass`, from `Iterator::all` over zero rules. Commits synthetic
  mechanism-verification fixtures under
  `crates/fornax-bench/fixtures/integrity-lab/` -- no numeric regression
  threshold is committed, since no real corpus exists yet to calibrate one
  from. See `docs/adr/0020-integrity-regression-lab.md`.
- `fornax_verify::calibration` + `GET /api/calibration` + `fornax
  calibration` (FORNX-348, Stage 8): a non-relaxing calibration floor on
  `/api/decision`'s `Recommendation`. `CalibrationProvenance` snapshots
  every genuinely observable environment dimension (adapter version,
  capability fingerprint, fusion/decision policy identity, disabled
  sensors, active policy revision digest) -- `model_version`/`model_family`
  stay `Option`, populated only when a caller explicitly supplies them,
  since no adapter or sensor in this codebase observes a model release.
  `assess_calibration` compares live provenance against the most recently
  recorded `calibration_revisions` row (new insert-only store table) and
  reports one of five states (`NoActiveCalibration`/`Valid`/`Stale`/
  `Suspect`/`InsufficientSupport`); `apply_calibration_floor` steps a
  `Proceed` recommendation down to `Review` under any non-`Valid`,
  non-`NoActiveCalibration` state, strictly downstream of `fuse()` --
  frozen fusion output and replay-stability are untouched.
  `fornax-bench::qualifying` refuses to let a benchmark run with any
  synthetic label, or a dataset whose content hash no longer matches a
  frozen baseline, count toward a calibration decision. See
  `docs/adr/0018-calibration-validity-lifecycle.md` for why the drift-derived
  half (`Suspect`) is unreachable on live traffic today (no
  `ReliabilityObservation` writer exists anywhere yet), why the floor is
  provably non-regressive today (`Corroborated`/`Proceed` requires a shared
  `correlation_group` no shipped sensor stamps, per ADR 0017), and the
  full honest AC-coverage table.
- `fornax_verify::independence` + `FusionRule::CommonSourceCollapsed` +
  `Independence::PartiallyCorrelated` (FORNX-347, Stage 8): a read-side
  `SourceFamilyMap` catches the real, live common-source amplification that
  FORNX-92's `correlation_group` (never actually written by any shipped
  sensor) could not -- two sensors reading the same `source_event_id` on
  the agent-reported channel (e.g. `ClaudeBashExitCodeSensor` +
  `ClaudeGitOutcomeSensor` on one Bash hook) now collapse to one effective
  vote, while independently-observing host sensors on the same event never
  do. Fusion's derived-evidence exclusion (R3) now walks `derived_from`
  transitively instead of one level. An explicit `correlation_group` can
  never *prevent* this structural collapse -- unions are purely additive.
  `GET /api/evidence-graph` and `fornax evidence-graph` surface which
  records count as one source family, in plain prose, no graph-theory
  vocabulary. `BaselineFusionPolicy`/`DeterministicVoiPolicy` both bump to
  policy version 2. See `docs/adr/0017-evidence-source-independence.md` for
  the full boundary, the fabricated-vs-real ticket-prose correction, and
  what remains unexercised on real traffic.
- `fornax-acquire` crate + `fornax acquire-evidence` / `POST
  /api/acquire-evidence` (FORNX-346, Stage 8): closes the loop from a
  FORNX-345 ranked evidence-plan candidate to real acquisition. Two
  auto-safe probes are implemented -- `VerifyArtifactHash` (real SHA-256
  of a contained file) and `InspectVcsState` (real `fornax-vcs`
  working-tree query) -- both pure in-process reads, no subprocess spawn,
  no network call. Every acquisition is re-gated against *current* policy
  at execution time (never a stale plan), a client selects a candidate by
  rank only (never a raw request, so gating cannot be bypassed), and
  targets are contained to an operator-configured allow-list of real
  directories -- no target resolves anywhere else. On success, the new
  evidence is persisted, the existing verifier registry re-runs, and
  fusion is recomputed; the response always carries both the before and
  after `FusedFinding` together. `RerunTest`/`QueryCiStatus` (needing
  `ProcessSpawn`/`NetworkCall`) are out of scope pending a human decision
  on amending the workspace's zero-subprocess-spawn invariant and
  ADR-0001 D2 -- see `docs/adr/0016-evidence-acquisition-boundary.md` for
  the full boundary and named gaps.
- `fornax evidence-plan` + `GET /api/evidence-plan` (FORNX-345, Stage 8):
  ranks concrete evidence-acquisition candidates (rerun a test, inspect VCS
  state, query CI status, verify an artifact hash, a bounded replay
  experiment, human review) that would close a claim's real evidence gaps —
  derived from fusion's own rationale, the evidence graph's missing-evidence
  notes, and this runtime's unobservable capability signals. Candidates are
  gated against the real `SideEffectAllowList`/`GlobalExperimentPolicy`/
  `SensorDisableConfig` primitives (no fabricated `AUTO_SAFE`/
  `REQUIRE_APPROVAL`/`FORBIDDEN` model); correlated evidence is never scored
  as independent corroboration; a candidate that needs an ungranted side
  effect or is administratively forbidden is always listed, never silently
  dropped. This planner only ranks candidates for acquisition — it decides
  and executes nothing; see `docs/adr/0015-voi-evidence-planner.md` for the
  ranking boundary and the items that cannot be verified without FORNX-346.
- `fornax adjudicate` (FORNX-342, Stage 8): blind-review workflow converting
  sanitized candidate cases into a human-adjudicated gold corpus — reviewer
  registration with a required human-attestation gate, blinded/unblinded
  review, a derived (never stored) adjudication state machine with
  `Unresolved`/`NotEvaluable` as first-class terminal states, versioned
  insert-only gold-label revisions with a per-case digest chain, and
  inter-rater agreement (Cohen's kappa) that reports `Insufficient`/
  `Undefined` rather than a fabricated number below a real sample-size
  floor. `promote_gold_label` selects `HumanAdjudicated` only when every
  contributing reviewer is `Human`; a mechanism-test reviewer anywhere in
  the chain routes export to `SyntheticMechanismTest`. Fixes a
  re-mining-aborts-the-run bug in `fornax corpus mine` found along the way.
- `fornax-corpus` crate + `fornax corpus mine`/`fornax corpus export`
  (FORNX-341, Stage 8): mines real local sessions into sanitized,
  redacted candidate integrity cases (contradiction, high uncertainty,
  sensor disagreement, verdict-changed-across-findings, and benign
  controls), and exports a deterministic corpus manifest. No automatic
  ground-truth labeling, no raw-telemetry centralization — everything is
  gated behind an explicit `FORNAX_CORPUS_MINING_ENABLED` opt-in and
  wired into the existing FORNX-106 retention/deletion mechanism via a
  new `RetentionClass::SanitizedCandidate`.
- FORNX-339: daemon/CLI now perform an explicit `$FORNAX_HOME` identity
  handshake (`x-fornax-home-id` header) so a CLI talking to the wrong
  daemon on a shared port fails closed (`UNAVAILABLE`) instead of
  silently reading another session's data.

### Fixed

- FORNX-346 AC2/AC5 gaps: `InspectVcsState` no longer requires a `FileDiff`
  target -- it falls back to the first configured `AcquisitionRoots` entry
  (a repo-level check, not a per-file one) when a claim carries no such
  evidence, which was true for most real traffic. Added
  `fornax_acquire::budget::AcquisitionBudget` so every probe now respects a
  latency budget (default 5s) and reports `AcquisitionOutcome::TimedOut`
  instead of blocking indefinitely.

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
