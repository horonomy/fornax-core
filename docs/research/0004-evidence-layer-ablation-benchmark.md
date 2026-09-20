# Evidence-layer ablation benchmark (FORNX-49)

Jira: FORNX-49, parent FORNX-20, discovery thesis HVDL-15. This ticket tests
the core technical thesis behind Fornax's evidence-layer design — that
adding more evidence layers (tool trace → process/files/Git/environment →
deterministic verification) measurably improves verification quality —
against real, deterministic replay of the verifiers that exist today, not
against an aspirational design.

**Bottom line, stated plainly up front: the planned A/B/C/D ablation cannot
be run as specified, because 3 of the 4 layers it would compare do not
exist in `next/v0.0.3` yet.** `EvidenceKind::ExitCode` is the only evidence
kind either shipped adapter (`fornax-adapter-claude`, `fornax-adapter-codex`)
produces. `TestResultVerifier`, `CommandExecutedVerifier`, and
`CommandSuccessVerifier` (all in `crates/fornax-verify`) are the only real
verifiers, and all three consume only `ExitCode` evidence. There is no
"process/files/Git/environment" evidence layer and no separate
"deterministic verification" layer beyond what these three verifiers
already do — layers B, C, and D collapse into one identical configuration.
This is itself the actionable finding this ticket was built to surface, not
a gap papered over with a synthetic C/D.

What *was* built and *is* real: a replay harness that runs a frozen,
non-cherry-picked fixture set through the actual verifiers deterministically,
and measures what the one real evidence layer (claim-only vs.
claim+ExitCode) actually buys today. Those numbers are below, taken directly
from the current test run — updated once, after FORNX-295 (a real bug this
benchmark surfaced) was fixed the same day; see "Follow-ups."

## What this benchmark is, precisely

- **Harness**: `crates/fornax-verify/tests/ablation_bench.rs`, an
  integration test in the crate that already owns every verifier and type
  needed (no new crate, no new workspace member — the smallest correct
  structure for this scope).
- **Fixtures**: 24 frozen `(Claim, Vec<Evidence>, RuntimeCapabilities)`
  cases, built with fixed UUIDs (`Uuid::from_u128`) and a fixed timestamp —
  no `Uuid::new_v4()`, no `Utc::now()` anywhere in fixture construction, so
  the fixture set is byte-for-byte reproducible.
- **Configurations** (see "Why the axis had to change" below):
  - **A** — claim only: evidence forcibly emptied, capabilities fully
    available.
  - **B=C=D** — claim + the one real evidence kind (`ExitCode`),
    capabilities fully available. Stands in for B, C, and D because, as
    measured in this repo today, they are the same configuration.
  - **capability-blind** — same evidence as B, but the two signal classes
    every current verifier gates on (`ToolTrace`, `FinalResponse`) are
    `Unknown`. Not one of the ticket's lettered layers; included because
    it's the actual mechanism that produces `Verdict::Unavailable` in the
    shipped code, and reporting it separately keeps it from being
    conflated with the evidence axis.
- **Determinism**: every fixture, under every configuration, is verified
  to produce an identical `(verdict, rationale, evidence_ids)` triple when
  `verify()` is called twice — the FORNX-27 replay contract, re-asserted
  here rather than assumed.
- **Reproduce**: `cargo test -p fornax-verify --test ablation_bench --
  --nocapture`

## Why the evaluation axis had to change from the ticket's literal framing

The ticket's A/B/C/D letters name *evidence* layers. It would be tempting
to instead ablate *verifier registration* (A = no verifiers ever run, B =
all three verifiers run). That framing was considered and rejected: with no
verifier ever firing, config A becomes a tautology (every claim is
`Unverified`, precision is undefined, recall is always 0) and B/C/D become
one identical column regardless of evidence — it would look like an
ablation without measuring anything. The harness instead ablates the thing
the ticket actually asks about — evidence availability — while holding the
verifier set constant (all three verifiers always registered, matched to a
claim by `subject`). The capability axis is reported as a separate,
labeled third column so it isn't mistaken for a fourth evidence layer.

## Verdict → "flagged" mapping (stated once, used everywhere below)

`Verdict` has five states; precision/recall are two-class. The mapping used
throughout:

- `Contradicted` → **flagged** (a positive detection).
- `Verified`, `Unverified`, `Unavailable` → **not flagged** — these are
  "no signal" outcomes, not decisions to ignore ground truth by inaction, and
  are broken out separately in the raw verdict counts below rather than
  hidden inside a single "not flagged" bucket.
- `Review` is never emitted by any current verifier; included in the tables
  for completeness (always 0).

Ground truth ("problematic") is assigned once per fixture at construction
time: `true` for every false-completion, unsupported-claim,
hallucinated-execution, and omitted-evidence case except one (see the
per-category table); `false` for every benign-healthy case.

## Metrics not computed, and why

- **Recall at a fixed low false-positive rate**: not computable. The
  ticket gates this on sample size permitting it; at n=24 with a
  categorical (non-probabilistic) verdict, there is no score to threshold —
  a verifier either contradicts a claim or it doesn't. Skipped.
- **Calibration metrics**: the ticket already gates these on the output
  being "probabilistic enough to justify them." `Finding.verdict` is a
  closed five-state enum with no associated confidence score. Skipped.
- **Runtime latency/cost**: measured informally — the entire 24-fixture,
  3-configuration, 2x-replay run (144 `verify()` calls total) completes in
  under 1ms of test time (`cargo test` reports `finished in 0.00s`). At
  this scale latency is not a meaningful differentiator between
  configurations; it would only become one if a future verifier performed
  I/O, which none currently do (the crate's own doc comment: "pure, no
  I/O").

## Results (raw, from the actual test run)

```
=== Configuration: A (claim only, no evidence) ===
verdicts: verified=0 unverified=24 contradicted=0 unavailable=0 review=0
precision=undefined (0/0) recall=0% evidence_coverage=0% benign_review_burden=100% (n=24, benign_n=6)

=== Configuration: B=C=D (ExitCode evidence, full verifier pipeline) ===
verdicts: verified=7 unverified=12 contradicted=4 unavailable=1 review=0
precision=100% recall=22% evidence_coverage=79% benign_review_burden=0% (n=24, benign_n=6)

=== Configuration: capability-blind (evidence present, runtime opaque) ===
verdicts: verified=0 unverified=0 contradicted=0 unavailable=24 review=0
precision=undefined (0/0) recall=0% evidence_coverage=79% benign_review_burden=100% (n=24, benign_n=6)
```

Per-category breakdown, config B (the only configuration where anything
interesting happens):

```
false_completion         n=5   verified=1 unverified=0 contradicted=4 unavailable=0 review=0
unsupported_claim        n=5   verified=0 unverified=5 contradicted=0 unavailable=0 review=0
hallucinated_execution   n=5   verified=0 unverified=5 contradicted=0 unavailable=0 review=0
omitted_evidence         n=4   verified=1 unverified=2 contradicted=0 unavailable=1 review=0
benign_healthy           n=5   verified=5 unverified=0 contradicted=0 unavailable=0 review=0
```

Full per-configuration, per-category tables and the raw marginal-value
printout are reproduced verbatim by re-running the command above; they are
not repeated in full here to keep this doc from drifting from the code —
the test's pinned assertions (`assert_eq!` on `contradicted`,
`false_positive`, `evidence_coverage`, `benign_review_burden`) are what
keep the numbers above honest. If a future verifier change shifts any of
them, the test fails and this doc must be regenerated, not left describing
behavior that no longer exists.

### Marginal value, A → B (the only real evidence-layer delta measurable today)

| Metric | A (no evidence) | B=C=D (ExitCode evidence) | Delta |
|---|---|---|---|
| Contradicted (detections) | 0 | 4 | **+4** |
| Recall | 0% (see note) | 22% | **+22pp** |
| Precision | undefined (0/0) | 100% | now defined |
| Evidence coverage | 0% | 79% (19/24) | +79pp |
| Benign review burden | 100% (every case is `Unverified`, so every benign case burdens review) | 0% (0/6) | **−100pp** |

Note on config A's recall: with zero detections and 18 ground-truth-positive
cases (5 false-completion + 5 unsupported + 5 hallucinated + 3 of 4
omitted), recall = 0/18 = 0%, not undefined — recall's denominator
(`TP + FN`) is nonzero even when `TP` is 0. Precision's denominator
(`TP + FP`) is 0/0 and is reported as undefined, per the mapping above.

**Going from claim-only to claim+ExitCode evidence is the entire
measurable effect in this codebase today.** It moves 4 genuine detections
from impossible to real, and it cuts benign review burden by 100 percentage
points (from "every healthy session looks the same as every unhealthy one,
because nothing is ever verified" to "no healthy session requires a human
look"). That is a real, substantial, honestly-measured
effect — attributable entirely to the first evidence layer.

### Two real detectability gaps this benchmark surfaced (not fixture bugs)

The false-completion category was constructed as "obviously should be
caught" (a claim of success contradicted by a nonzero exit code). At the
time this benchmark first ran, only 3 of 5 cases (60%) were actually
caught; one of the two misses (below) has since been fixed as FORNX-295,
bringing this to 4 of 5 (80%). Both were genuine, reproducible findings
about the current verifiers, not artifacts of fixture phrasing:

1. **`CommandExecutedVerifier` never checks exit code, by design.** A
   claim like "I ran `npm install` and it worked" is routed by `subject`
   to `CommandExecutedVerifier`, which only confirms the command executed
   — `verified_regardless_of_exit_code_since_this_only_checks_execution`
   is an existing, intentional unit test in `fornax-verify`. A command
   that ran and failed is `Verified`, not `Contradicted`, if the claim's
   subject routes it here instead of to `CommandSuccessVerifier`. This is
   a verifier-scope gap: claim-subject classification (out of scope for
   this ticket and for FORNX-27) determines whether exit-code checking
   ever happens at all.

2. **`TestResultVerifier`'s `is_test_runner_evidence` heuristic silently
   misses multi-token commands.** It matches by checking whether
   `serde_json::Value::to_string()` of the evidence's `command` field
   contains a literal substring like `"cargo test"`. Codex's real rollout
   shape for `command` is a JSON array of argv tokens (documented in
   `fornax-verify/src/lib.rs`'s own `command_text` doc comment — e.g.
   `["cargo", "test"]`). `to_string()` on that array renders as
   `["cargo","test"]` — a comma-and-quote boundary, not a space — so the
   substring `"cargo test"` never matches. Single-token commands
   (`pytest`, `vitest`, `jest`) work by coincidence, because a one-element
   array serializes to `["pytest"]`, which does contain `"pytest"`.
   Multi-token test commands (`cargo test`, `cargo nextest`, `npm test`)
   silently fall through to "no test-runner invocation observed" —
   `Unverified`, not `Contradicted`, even when a nonzero exit code is
   sitting right there in the evidence. This same bug produces the
   benchmark's one benign-healthy false negative below.

   **Fixed as FORNX-295**, same day: `is_test_runner_evidence` now matches
   against `command_text()` (the function that already joins argv tokens
   with spaces, used by the other two verifiers) instead of
   `Value::to_string()`. Left unfixed in the original benchmark PR — this
   ticket was scoped to measurement, not to patching verifiers discovered
   along the way — but filed and fixed immediately after as a real,
   independent bug; see "Follow-ups" below.

### The other three required categories are structurally undetectable today

- **Unsupported claims** (claim made, no evidence at all): all 5 cases are
  `Unverified`. No verifier here ever promotes an absence of evidence to a
  detection — this is explicit, documented design
  ("missing evidence does not become contradiction", FORNX-14 AC), not a
  gap. It means these claims are invisible to the metrics as "detections"
  by construction; they are visible only as "no-signal" / review-required.
- **Hallucinated execution state** (claim names a command; evidence exists
  only for a *different* command): all 5 cases are `Unverified`, for the
  same documented reason — absence of the *named* command's evidence is
  not contradiction. This category is the clearest illustration of a
  present, real ceiling in the current verifier set: a session that
  fabricates having run `terraform apply` while only `terraform plan`
  actually ran produces the exact same `Unverified` verdict as a claim
  with genuinely no evidence available. The current design cannot
  distinguish "no evidence exists" from "evidence exists but contradicts
  the specific claim by omission." Closing this gap would require either
  a verifier willing to treat "named command absent from an otherwise
  evidence-rich session" as a stronger signal than plain absence, or an
  evidence layer that can assert completeness ("every command this session
  ran is represented here") — which does not exist today.
- **Omitted checks / incomplete evidence**: mixed — 1 `Verified` (a
  `command_executed` claim doesn't need the missing `exit_code` field), 2
  `Unverified` (the missing field, or an untracked test command, prevents a
  `test_result` match), 1 `Unavailable` (a `command_succeeded` claim finds
  its command but can't read the missing `exit_code` field, hitting the
  verifier's own explicit incomplete-evidence branch). This is the one
  category where the system's behavior varies by verifier the way its own
  design intends: `Unavailable` is reserved for "we found the right
  evidence but it's missing the field we need," distinct from
  `Unverified`'s "we found no relevant evidence at all."
- **Benign healthy**: all 5 correctly `Verified`. `benign_cargo_nextest_passed`
  originally surfaced as a false negative on a healthy session, hitting the
  same `is_test_runner_evidence` substring bug described above (`"cargo
  nextest run"` as an argv array never contained the literal substring
  `"cargo nextest"`) — the entire source of the original 17% benign
  review-burden figure in config B. **Fixed same-day as FORNX-295**
  (`is_test_runner_evidence` now reuses the shared `command_text()`
  space-joined normalization instead of a raw `Value::to_string()`); benign
  review burden in config B is now 0%.

## Capability-blind axis

When `ToolTrace` and `FinalResponse` are both reported `Unknown` — the
runtime genuinely cannot observe exit codes — all three verifiers return
`Unavailable` for all 24 cases regardless of what evidence happens to be
present in the fixture. `contradicted=0`, `unavailable=24`. This confirms
the gate at `fornax-verify/src/lib.rs` (checked in all three verifiers)
behaves exactly as documented: it is a genuine, working circuit-breaker
against inventing a verdict the runtime cannot actually support, not a
theoretical claim.

## CONTINUE / NARROW / PIVOT read

**Data supports NARROW, not CONTINUE or PIVOT** — offered as input to the
owner's decision per the ticket's "final business interpretation remains
owner decision," not as a declared conclusion.

- Not **PIVOT**: the one evidence layer that exists produces a real,
  substantial, honestly-measured effect (0 → 4 detections, 100% → 0% drop
  in benign review burden). The underlying thesis — that evidence improves
  verification over claim-only — is not falsified by anything measured
  here. It has one real, positive data point behind it.
- Not **CONTINUE** as currently scoped: the ticket's actual ask — measure
  the *marginal* value of layers B, C, and D against each other — cannot be
  answered, because B, C, and D are the same configuration in the code that
  exists today. Continuing to build ablation infrastructure for layers that
  don't exist would not produce more signal; it would produce the same
  three-verifier, one-evidence-kind result dressed up as four columns.
- **NARROW**: the productive next step is not "run a bigger ablation," it's
  "build the second evidence layer, then this same harness — unchanged —
  will produce a real B vs. C data point." Concretely, from the code
  inspected for this ticket:
  - `EvidenceKind` already declares `ToolResult`, `FileDiff`,
    `ProcessObservation`, and `TranscriptExcerpt` — none are produced by
    either shipped adapter today. Any one of these becoming real, with a
    verifier that consumes it, is what would make a genuine C-layer
    measurement possible.
  - Two concrete, low-risk bugs/design questions were found by this
    benchmark and filed as their own tickets: `is_test_runner_evidence`'s
    substring-vs-array mismatch (FORNX-295, fixed same day) and
    `CommandExecutedVerifier`'s by-design exit-code blindness (FORNX-296,
    a design question deferred to whoever builds claim extraction) — the
    kind of thing worth catching before the next ablation round, since they
    would otherwise suppress real detections independent of any new
    evidence layer.
  - The hallucinated-execution-state category exposes a design ceiling
    (absence of the named command's evidence is indistinguishable from
    absence of any evidence) that a future evidence or verifier design
    should explicitly decide whether to address.

## Follow-ups (not fixed as part of this ticket — scope is measurement)

- ~~Fix `is_test_runner_evidence` to match against `command_text()` instead
  of `Value::to_string()`~~ — **done, FORNX-295**, same day: multi-token
  test-runner invocations (`cargo test`, `cargo nextest run`, `npm test`)
  are now recognized the same way `CommandExecutedVerifier`/
  `CommandSuccessVerifier` already recognize multi-token commands. The
  results above already reflect this fix.
- Decide, as a design question (not silently in a verifier tweak — tracked
  as FORNX-296), whether
  `CommandExecutedVerifier` should ever consult exit code, or whether claim
  extraction should route "ran and it worked"-style claims to
  `CommandSuccessVerifier` instead.
- When a second real `EvidenceKind` ships from either adapter, re-run
  `cargo test -p fornax-verify --test ablation_bench -- --nocapture`
  unchanged — the harness's B/C/D collapse is a fact about today's adapters,
  not a hardcoded limitation of the test.
