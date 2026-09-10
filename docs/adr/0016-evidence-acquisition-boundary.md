# ADR 0016 — Evidence Acquisition Boundary: Real Safety Model and Named Gaps

**Status:** Accepted (partial scope — see "Escalated, not built" below)
**Ticket:** FORNX-346 · **Epic:** FORNX-340 (Stage 8 / Active Evidence Intelligence)
**Crate:** `fornax-acquire`

## Context

FORNX-346's own ticket prose assumes reuse of "Stage-5 experiment safety
semantics: `AUTO_SAFE`, `REQUIRE_APPROVAL`, `FORBIDDEN`" and a ticket
"FORNX-178" it names as their source. Neither exists anywhere in this
repository — the same fabricated-prose pattern ADR 0015 already corrected
for FORNX-345. The real safety primitives are
`fornax_types::experiment::{SideEffectClass, SideEffectAllowList}`
(deny-by-default) and `fornax_experiment_runner::{GlobalExperimentPolicy,
is_permitted}` (the host-level second gate). This crate is built on those,
not on the fabricated three-tier vocabulary.

## Decision: two real, auto-safe probes; execution stays in-process

`fornax-acquire` implements exactly two of `fornax_verify::voi::ProbeKind`'s
six variants: `VerifyArtifactHash` (real SHA-256 of a contained file) and
`InspectVcsState` (real `fornax-vcs` working-tree query). Both are pure,
in-process, read-only operations — no subprocess spawn, no network call —
so `fornax-acquire` stays covered by
`fornax-daemon/tests/adversarial_daemon_input.rs::
subprocess_surface_is_still_zero_in_production_code`'s workspace-wide scan
exactly like every other production crate, without needing an exception.

### Named bug found and fixed during ground-truth checking

`fornax_verify::voi`'s `InspectVcsState` requests wrongly declared
`SideEffectClass::ProcessSpawn` as required, in all five places that probe
is produced. `fornax-vcs` is a pure in-process `gix` reimplementation with
zero subprocess spawn (its own module docs say so explicitly) — the
declaration gated an actually auto-safe, read-only probe behind a grant
`GlobalExperimentPolicy::default()` never gives out. Fixed in this branch's
first commit, pinned with a regression test.

## No invented "session repo root"

Nothing in this repository tracks a trusted working-directory/repo-root per
session today. `fornax_types::FileDiffPayload::path` — the only place a
filesystem path appears in canonical evidence at all — is agent-reported
and read straight out of `tool_response`/`tool_input` JSON with no
validation at collection time (see `fornax-adapter-claude`'s
`ClaudeGitOutcomeSensor`). Rather than inventing a "session repo root"
concept that doesn't exist and trusting it, `fornax_acquire::containment`
requires an operator to explicitly configure which real directories
acquisition may ever read from, in `$FORNAX_HOME/config.toml`'s
`[acquisition]` table — empty by default, matching this workspace's
deny-by-default posture everywhere else. This is a genuine, named
constraint on today's deployment shape, not a workaround.

## Never trusts a stale plan

`fornax_verify::voi::EvidencePlan` is a snapshot computed at plan time;
`GlobalExperimentPolicy`/`SensorDisableConfig` are file-backed and can
change before execution happens. `fornax_acquire::gate::classify_for_execution`
re-runs the real `is_permitted` two-layer check against *current* policy
right before acquiring anything — it never reads
`AcquisitionCandidate::availability`, which was computed earlier and may now
be stale. `FilesystemWriteOutsideWorktree` is always refused here too,
mirroring `voi::classify_availability`'s own always-forbidden rule.

`/api/acquire-evidence` reinforces this at the daemon layer: a caller
selects a candidate by its 1-based `rank` in a plan the *server* recomputes
itself, never by submitting a raw `EvidenceRequest`. Accepting an arbitrary
client-supplied request would let a client craft a fake low-side-effect
request and bypass gating entirely.

## Re-verification reuses the existing verifier registry, not new logic

`crates/fornax-daemon/src/main.rs`'s `IngestMessage::Claim` handler already
runs a fixed `Verifier` registry (`TestResultVerifier`,
`CommandExecutedVerifier`, `CommandSuccessVerifier`, `FileModifiedVerifier`,
`GitOperationVerifier`) against a claim's evidence pool and persists the
resulting `Finding`s. `/api/acquire-evidence` reuses this exact dispatch
loop (extracted as `run_verifiers_and_persist_findings`) after newly
acquired evidence lands, then recomputes fusion via the same `compute_fusion`
every other endpoint shares. No new interpretation logic was written for
this ticket — acquisition only makes new evidence available to the same
real verifiers, it does not itself decide what the evidence means.

## New evidence shape: widened `ProcessObservationDetail`, not a new `EvidenceKind`

`VerifyArtifactHash` produces `ProcessObservationDetail::ArtifactHashVerified
{ path, sha256_hex }`, added by widening the existing enum — the
already-established, documented pattern for a new evidence shape in this
schema (see `VcsOperation`/`FileWriteObserved`/`WorkingTreeStatusObserved`'s
own precedent comments). `InspectVcsState` reuses the *existing*
`WorkingTreeStatusObserved` shape `fornax-adapter-claude`'s
`ClaudeGitWorkingTreeSensor` already produces today, rather than inventing a
parallel one.

## Escalated, not built: `RerunTest` and `QueryCiStatus`

These two `ProbeKind` variants require `ProcessSpawn`/`NetworkCall`
respectively. Building them would mean amending the workspace-wide
zero-subprocess-spawn invariant and ADR-0001 D2 ("no cloud dependency on the
local critical path") — a genuine security/architecture decision, posted to
FORNX-346's Jira thread rather than decided unilaterally. Until answered:

- `AC1` ("at least three materially different auto-safe evidence
  acquisition paths execute end-to-end") is met by **two**, not three.
  `BoundedReplayExperiment` without `ProcessSpawn` was considered and
  rejected as a third path: without spawning anything, a caller-supplied
  `InterventionObserver` can only read files inside a staged copy it just
  wrote, producing no new information about external reality — a tautology,
  not a real acquisition.
- `AC7`'s command-injection/SSRF/credential-bearing-probe coverage is
  **not applicable**, not covered — there is no command execution and no
  network client in the delivered surface. What *is* a real, covered
  security surface for the two implemented probes — path traversal, an
  absolute-path escape, and a symlink escape against
  `AcquisitionRoots::resolve_contained` — has negative tests.

## Cannot be verified without further work

1. **AC1 is two-of-three**, pending the escalated decision above.
2. **AC2 ("a representative uncertain finding changes or remains uncertain
   based on newly acquired evidence") is achievable only for claims whose
   evidence carries a resolvable `FileDiff` path.** Most real traffic today
   has no such evidence row — `fornax_acquire::target::resolve_target`
   returns an honest `NoTarget` rather than guessing.
3. **No shipped verifier yet interprets `ArtifactHashVerified`.** The
   before/after fusion delta this ADR's own test exercises is real for
   `InspectVcsState` (an existing verifier already reads
   `WorkingTreeStatusObserved`); a freshly acquired hash currently has no
   consumer that turns it into a `Supports`/`Contradicts` verdict — that is
   real verifier-authoring work, out of scope for this ticket.
4. **AC5 (cost/latency/resource budgets, cancellable)** is not implemented
   in this scope — both delivered probes are sub-second, in-process, and
   have no meaningful budget to enforce or cancel. Deferred alongside the
   escalated paths, where a real budget matters.
5. **AC6 (concurrent sessions cannot cross-attribute acquired evidence)**
   relies entirely on FORNX-339's existing `home_identity` handshake and
   `acquisition_log`/`evidence` being scoped by `session_id` at every read —
   not independently re-verified with a new mechanism in this ticket.
6. **No real binary-spawn CLI end-to-end test exists for `fornax
   acquire-evidence`**, unlike `fornax-cli/tests/corpus_cli_e2e.rs`/
   `adjudicate_cli_e2e.rs`. Coverage here is at the daemon-handler level
   (`api_acquire_evidence` called directly against a real seeded store, no
   mocking) — the same rigor `/api/decision`/`/api/judge` already have,
   which also have no binary-spawn test, since exercising this endpoint
   requires a live HTTP server rather than a store-only CLI workflow.

## Verification

Unit tests cover containment (relative/absolute/traversal/symlink escapes,
missing-config deny-all default), execution-time re-gating (including a
policy-tightened-after-planning regression), and both probes (missing file
is `Unavailable` not `Failed`, a real file's hash matches a known SHA-256,
outside-any-repo is `Unavailable`). Two real end-to-end daemon tests run
against a seeded store, no mocking: one drives a genuine
`VerifyArtifactHash` probe against a real temp file through
`/api/evidence-plan` → `/api/acquire-evidence`, confirming real persistence,
real re-verification, real fusion recomputation, and a real
`acquisition_log` row; the other confirms a `RerunTest` candidate requiring
an ungranted `ProcessSpawn` grant is refused, never silently executed.
