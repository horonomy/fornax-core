# Changelog

All notable changes to Fornax are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow the
canonical Fornax release sequence (`v0.0.1` → … → `v0.1.0` GA) tracked in
Jira epic FORNX-20.

## [Unreleased]

### Added

- **Codex first run: `fornax install codex` opts in to daemon capture**
  (FORNX-468). The daemon reads the selected Codex home's `sessions/` rollouts
  (tool commands and output, final assistant message) so a "tests passed"
  claim is checked against the run's own output, with no hand-started tailer
  and no `/hooks` trust needed for findings. The opt-in is recorded in
  `$FORNAX_HOME/codex-watch.json`. Only activity after the daemon is watching
  is read; sessions already on disk are not backfilled. `fornax uninstall
  codex` turns capture off (it is left on, with a message, if it watches a
  different Codex home). **Privacy:** captured data is stored locally and
  passes secret-pattern redaction only; there is no PII redaction (cloud upload
  is a separate opt-in and is off by default). A Codex claim can be `Verified`
  only when Codex reports a literal exit code of 0; heuristic-only evidence
  stays `Review` (ADR-0025). Install, uninstall and plan print one outcome per
  line. Known limit: `install` still writes the capture marker when the
  `notify` edit is refused, because capture is a separate opt-in.

- **`fornax install codex` writes a LaunchAgent plist file** (FORNX-469, macOS
  only, when `fornax-daemon` sits next to `fornax`) and prints the exact
  `launchctl bootstrap` command. Fornax never runs `launchctl` itself, so the
  daemon does not start until you load it. Only an absent path is created: a
  plist Fornax did not write, or cannot read (foreign, binary, non-UTF-8,
  unreadable, a directory or a symlink), is left untouched by install and
  uninstall, and the staging file never follows a planted symlink. Known
  limit: replacing or removing a plist verified as Fornax's can still race a
  same-user writer.

- **`fornax doctor` is a first-run checklist** (FORNX-469, FORNX-471): daemon
  reachable, Codex wiring and capture, and Claude Code hooks, each with the
  next step. It reports only what it can show: a comment or other key
  mentioning the notify script, a capture marker the daemon would ignore, or a
  config file alone are gaps, and capture is judged by the same marker rule the
  daemon uses. A Claude hook entry is reported as configuration only (only
  recorded events show it ran), and Claude Code results are `Review`, never
  `Verified` (ADR-0025). Doctor reads an existing database read-only; it never
  creates or migrates it and leaves the file byte-for-byte unchanged (SQLite
  may create empty `-wal`/`-shm` sidecars to read it).

- `fornax adapter register` accepts shared host-adapter descriptors into the
  existing registry, with explicit digest confirmation and disabled registration.
  List/inspect report declarations and retained-byte integrity without granting
  implementation trust or executing code. The first confirmed host descriptor
  upgrades the index to v2; older mutators must be stopped before that upgrade.

- `fornax adapter info|inspect <id>` now reports the retained registration,
  owned-manifest integrity, and unverified source provenance. `--json` emits
  the shared CLI operation-envelope v1 shape; these facts do not establish
  host installation, trust, or native observation.

- **Evidence-ingress provenance and replay enforcement** (FORNX-431, Stage
  7A/v0.0.9). The daemon's real verdict-persistence choke point now filters
  evidence through a provenance guard (server-stamped origin, session-owner
  derivation from real capability announcements) before any verifier sees
  it, and checks a durable `evidence_consumption` ledger before persisting a
  `Verified` finding. A cross-claim replay of already-consumed evidence
  downgrades to `Review`, never silently re-verifies. Independently
  re-verified against the live daemon under genuine concurrency (FORNX-435).
  See `docs/adr/0024-evidence-ingress-provenance-and-consumption.md`.

- **Evidence-independence capacity bounding** (FORNX-432, Stage 7A/v0.0.9).
  `SourceFamilyMap::build`/`ancestors_of` sped up 10–143x on common shapes
  with byte-identical output (proptest-proven against a frozen reference
  oracle); a new `try_build` aborts construction under a deterministic
  100,000-work-unit budget rather than completing on an adversarial pool,
  with fusion/contract-satisfaction/receipt-issuance/voi all failing safe
  (never a partial result) and the daemon running the bounded cost via
  `spawn_blocking`. Independently re-verified, including a fixture-potency
  negative control (FORNX-436). See
  `docs/research/fornx-432-independence-capacity.md`.

- **Local-daemon ingest quarantine and backpressure** (FORNX-212, local
  scope). A malformed or unprocessable ingest line is now durably recorded
  (`ingest_quarantine` table, with retention-sweep coverage) instead of only
  logged and dropped. A real 512-concurrent-event test proves zero loss and
  bounded drain time against the daemon's 256-connection inflight cap.

### Changed

- **The Codex integration follows `CODEX_HOME`** (FORNX-474). `config.toml`,
  `hooks.json` and the sessions directory the daemon watches are now under a
  non-empty `CODEX_HOME`; unset or empty keeps `~/.codex`. A relative or
  non-UTF-8 `CODEX_HOME` is refused before anything is written. Known limit: a
  differently spelled path for the same directory is treated as a different
  Codex home.

- **The Codex notify script lives under `$FORNAX_HOME/bin`** (FORNX-469). It is
  rendered there with the absolute `fornax` path baked in, so the `notify`
  entry in `config.toml` no longer depends on where the binary was built or
  checked out. `uninstall` removes the entry but leaves the script file.

- `fornax adapter unregister` (and the underlying registry `remove`) adopts
  Strict Retention (HORO-1745): the index entry is still removed, but the
  owned descriptor/config copy and any orphaned staging file are never
  deleted. No `fstat`-then-pathname-`unlink` sequence can prove it still
  targets the exact inode it just verified, so this trades disk cleanliness
  for the guarantee that cleanup can never delete the wrong file. A removal
  now reports `outcome: "partial"` / `cleanup_failed` with the index change
  confirmed committed; re-registering the same id afterward refuses with
  the new `owned_destination_occupied` code (the underlying OS cause is
  `EEXIST`) until the retained file is removed by hand. Applies uniformly
  to configuration and host-adapter registrations alike -- there is no
  special case for either kind.

### Fixed

- **A command that only mentions a test runner can no longer verify a "tests
  passed" claim** (FORNX-477). The verifier matched `pytest`, `cargo test`,
  `jest`, ... as a substring of the command text, so `echo pytest`,
  `pip install pytest`, `true || pytest` or `git commit -m "add vitest"`
  exiting 0 produced `Verified`. It now identifies a runner from the executed
  command's structure: one simple command, or an `&&` list that exits 0,
  optionally inside `sh -c`. Compound (`;`, `||`, pipes), expanded,
  unparseable and non-executing (`--collect-only`, `--no-run`, ...) commands
  are `Unverified`, and a newer unidentified runner command stops an older
  pass from being `Verified`. Genuine runner passes stay `Verified` here (superseded by the REVIEW cap in the next entry), failures
  stay `Contradicted`, and heuristic exit codes stay capped at `Review`. See
  the README section "Which commands count as a test run".

- **A runner name plus exit 0 no longer verifies a "tests passed" claim**
  (FORNX-477, residual). An executable named `pytest` that only does `exit 0`,
  or `cargo test no_such_test` (zero tests selected), still produced
  `Verified`. The Codex, Claude Code and OpenCode adapters now keep the
  runner's final summary counts (never the raw output) on the exit-code
  evidence, and the verifier requires, for `Verified`, exactly one identified
  runner (other `&&` steps may only be `cd`), a summary in that runner's
  format, at least one pass and no failure. Anything else is `Unverified`;
  `Contradicted` and the heuristic `Review` ceiling are unchanged. In this
  release only pytest and `cargo test` output is read, so `cargo nextest run`,
  `npm test`, `jest` and `vitest` passes are `Unverified`. A program that
  prints a forged summary can still pass these conditions; see the next entry.

- **A `test_result` from the agent's own transcript can no longer be `Verified`**
  (FORNX-477, founder decision Option A, 2026-10-29). QA showed an executable
  named `pytest` that prints `3 passed in 0.01s` and exits 0 still reached
  `Verified`; the runner-structure and summary conditions above stay but are
  not sufficient, because the exit code and summary come from the agent's own
  session (trust class `AgentAdjacent`). The most such a finding can now be is
  `Review`. `Verified` needs evidence from a collector `fornax-verify` lists as
  a test-run attestor with trust class `HostObserved` or `IndependentExternal`;
  that list is deliberately empty in production and no shipped sensor attests
  test runs. User-visible consequence: in v0.0.9 every "tests passed" finding
  from Claude Code, Codex (default and `shell_command`) and OpenCode is at most
  `Review`. Unchanged: a genuine non-zero literal exit is `Contradicted`; fake
  runners, zero tests and missing, wrong or malformed summaries are
  `Unverified`; a heuristic `exit_code=0` stays `Review`. In the ablation
  benchmark the benign review burden in config B is 3 of 6 (50%). Host-controlled
  runner receipts or CI evidence are FORNX-443 and nextest/npm/jest/vitest
  summaries are FORNX-479, both outside v0.0.9. See README "Which commands
  count as a test run" and ADR-0025.

- **"The `go test` / `make test` / `yarn test` ... succeeded" can no longer be
  `Verified` from an exit status** (FORNX-477 hardening). A `command_succeeded`
  claim whose command is a test command Fornax cannot read the results of
  (`go`/`mvn`/`gradle`/`dotnet`/`deno`/`bun`/`swift`/`mix`/`bazel`/`make`/`just`/
  `yarn`/`pnpm`/`npm` `test`, `npm run test*`, `tox`/`nox` outside lint
  environments, `rspec`, `phpunit`, `ctest`, `mocha`, `python -m unittest`, and
  launcher forms such as `pdm run pytest` or `bundle exec rspec`) is
  `Unverified` on a clean exit 0, since nothing shows a test ran. A non-zero exit
  is still `Contradicted`; commands that are not test runs (`go build`,
  `make install`, `yarn install`, `tox -e lint`, `pip install pytest`) still
  verify, and `test_result` behaviour is unchanged. *(Superseded in part by the
  FORNX-480 entry below: a clean exit 0 on agent-adjacent evidence is now
  `Review` for those commands too.)*

- **`command_succeeded` is capped at `Review` without an attested source**
  (FORNX-480, founder decision Option B, 2026-10-29). An exit status from the
  agent's own session cannot show that the claimed program ran and exited 0 (a
  same-named executable that only does `exit 0` is indistinguishable), so
  "the `npm install` succeeded" reaches `Verified` only through the same
  attested-collector gate as `test_result` (`HostObserved` or
  `IndependentExternal` class *and* a collector `fornax-verify` lists; a label
  alone is not enough). None ships in v0.0.9. A recorded non-zero exit stays
  `Contradicted`; `command_executed` ("I ran ...") is unchanged, and its
  remaining trust limits (it asserts a command row exists, not that the program
  is the one named) are tracked separately, not resolved. In the ablation
  benchmark the benign review burden in config B is 4 of 6. Production adapters
  never mint `command_succeeded`; it reaches the daemon through the ingest
  socket.

- **"I ran X" / "X succeeded" bind to the command that ran, not to text that
  contains it** (FORNX-477 hardening). The match between a `command_executed` /
  `command_succeeded` claim and a command row was a lowercased substring, so
  `echo npm install` verified "the `npm install` succeeded". A claim now binds
  only to a row that ran the same command step for step; text that merely
  mentions it (`echo`, `timeout`/`sudo` wrappers, pipelines, `;`/`||`/`&&`
  lists, another program path or letter case) is `Unverified`, and a newer
  mention withholds an older success. A claim naming more than one command, or
  a command that cannot be parsed, is `Unverified`. A claim that is a prefix of
  the command that ran (`npm install` vs `npm install --dry-run`), a bare program
  name reached through an absolute path, or one step of a `cd dir && cmd` row is
  `Review`; an env prefix the claim names (`CI=true`) must match in value.
  A real failure is still `Contradicted`. `npm install`, `cargo build` and
  similar exact runs keep verifying from a literal exit code.

- **A test run claimed as `command_succeeded` gets the same bar as
  `test_result`** (FORNX-477, QA 29513 residual). "The `pytest -q` run
  succeeded" reached `Verified` from the same agent-reported exit code. When
  the command the claim names is an identified test run it now needs that
  runner's passing summary and attested evidence: `Review` for a normal pytest
  or `cargo test` run, `Unverified` for a fake runner, zero tests, a runner
  whose output is not read (`jest`, `vitest`, `npm test`, `cargo nextest run`)
  or evidence that merely mentions the runner (`echo pytest`). `Contradicted` for a non-zero exit is unchanged,
  and non-test commands (`npm install`, `cargo build`, `pip install pytest`)
  still verify from a literal exit code.

- **Codex completion replay creates duplicate events and claims** (FORNX-446).
  Rollout `task_complete` records with a nonblank native `turn_id` now retain
  the same session-scoped completion and claim identities across tailer
  replay and restart. Distinct turns remain distinct even with identical
  prose; conflicting content under one identity is still quarantined.
  Linked claims must match the retained completion in the insertion transaction;
  a rejected changed completion cannot introduce a new verified claim. Quarantine
  records retain metadata only for this rejection. Matching partial-ingest retries
  remain eligible after reconnect or restart.
  Existing tool/evidence IDs and the evidence-consumption guard are unchanged.
  Historical random-ID rows are retained: the first replay after upgrading
  can add one stable-ID occurrence beside them; no migration rewrites history.
  Completions without a usable turn ID preserve their prior behavior.

- **rustls security advisories** (FORNX-447). Updated rustls from 0.23.45 to
  0.23.46, which fixes RUSTSEC-2026-0346, RUSTSEC-2026-0347,
  RUSTSEC-2026-0348, and RUSTSEC-2026-0349. This records the upstream fixes;
  it does not assert exploitability or reachability in Fornax.

- **Heuristic `exit_code=0` could reach `Verified` for a `test_result`
  claim** (FORNX-442, found during FORNX-433's native-ingress testing).
  `TestResultVerifier`/`CommandSuccessVerifier` treated any `exit_code=0`
  evidence as `Verified`, including a heuristic inference from "stderr is
  empty" (`fornax-adapter-claude`'s `ClaudeBashExitCodeSensor`; Codex's
  default `tools.exec_command`/`unified_exec` "Script completed"
  fallback). A real `pytest`/`cargo test`/etc. failure writes its summary
  to stdout, not stderr, so this heuristic fired identically on a genuine
  failure — a false "tests passed" claim against a real failure reached
  `Verified`. Fix is safety-monotonic: a heuristic `exit_code=0` now
  downgrades to `Review`, never `Verified`; every authoritative (literal)
  exit-code path is unaffected. Consequence: in their default
  configurations, neither Claude Code nor Codex can currently produce an
  authoritative `Verified` `test_result` finding — tracked as FORNX-443.

### Removed

Intentional breaking cleanup during DogFooding (FORNX-428 S3), before any
external compatibility commitment exists — no deprecated aliases kept:

- The legacy top-level commands `install-claude`, `uninstall-claude`,
  `install-codex`, `uninstall-codex`. Use `fornax install claude-code`,
  `fornax uninstall claude-code`, `fornax install codex`,
  `fornax uninstall codex`.
- `fornax install list|doctor|plan` as nested subcommands of `install`.
  Use `fornax adapter list|doctor|plan` instead.

## [v0.0.8] — Agent Epistemic Trust Kernel

Stage 9 (epic FORNX-376, HVDL-15). Full release notes:
[`docs/release/v0.0.8-release-notes.md`](docs/release/v0.0.8-release-notes.md).
Readiness-gate verdict (FORNX-392): **CONTINUE, with 3 disclosed
carryovers** — not a clean pass. See release notes for the honest
per-carryover detail; nothing here claims more than the gate evidence
supports.

Adds: Epistemic Contracts and claim/evidence satisfaction (FORNX-377/378),
adaptive verification budgets (FORNX-379), an adversarial evidence corpus
and evidence-authenticity hardening (FORNX-380/381), a self-integrity
invariant/property/formal-methods program (FORNX-382/383), proof-carrying
delegation and multi-agent shared-failure detection (FORNX-384/385),
isolated shadow execution (FORNX-386), structured assurance cases
(FORNX-387), a monitor-of-monitor meta-verification layer (FORNX-388),
integrity incident-to-regression tooling (FORNX-389), and a public,
independently-implementable Agent Evidence Protocol (FORNX-391). FORNX-390
(federated calibration) is a research finding, not a shipped feature — its
own decision record concluded narrow/defer.

**Note on this CHANGELOG's own gaps:** entries for `v0.0.2`, `v0.0.4`,
`v0.0.5`, `v0.0.6`, and `v0.0.7` were never added here even though all were
really tagged and released (see each version's own
`docs/release/vX.Y.Z-release-notes.md`, which is the actual source of
truth for those versions). That gap predates this entry and is out of this
release's scope to backfill; flagged here rather than silently continuing
past it.

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
