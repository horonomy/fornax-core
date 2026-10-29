# ADR 0025 — Authoritative `test_result` Success Signal: Scope and Founder Decision

**Status:** Accepted (scope decision); implementation not yet started
**Ticket:** FORNX-443 · **Related:** FORNX-442 (the fix this ADR's decision
follows from), FORNX-433 (native-ingress tests that surfaced the ceiling),
FORNX-146 (v0.0.9 epic)
**Crates:** `fornax-verify`, `fornax-adapter-claude`, `fornax-adapter-codex`

## Context

FORNX-442 fixed a real false-`Verified` bug: `TestResultVerifier`/
`CommandSuccessVerifier` treated any `exit_code=0` evidence as `Verified`,
including a *heuristic* `exit_code=0` inferred from "stderr is empty" —
which a real `pytest`/`cargo test`/etc. failure also satisfies, since such
failures write their summary to stdout, not stderr. The fix downgrades a
heuristic `exit_code=0` to `Review`, unconditionally, gated on
`payload["heuristic"] == true`.

**Consequence**: in their *default* configuration, neither Claude Code nor
Codex (`unified_exec` enabled, the default) can produce an authoritative
`exit_code` for a Bash/shell tool call at all — so `TestResultVerifier` can
now only ever reach `Review`/`Unverified` for a `test_result` claim from
either provider's default path, never `Verified`, and (for the pure
heuristic-success path) never `Contradicted` either. Only two paths carry a
genuinely authoritative signal today: Codex with `unified_exec` explicitly
disabled (`tools.shell_command`'s literal `"Exit code: <n>"` text), and the
`opencode` adapter (`tool.execute.after`'s literal `output.metadata.exit`).

This is the flagship "an agent claims tests passed; we deterministically
check" scenario the product is built around, so the ceiling has real
product weight — not something to leave undecided.

## Decision (founder, 2026-10-11)

**Accept** the current `Review`/`Unverified` ceiling for heuristic-only
Claude Code and default-Codex `test_result` evidence as a **disclosed
v0.0.9 limitation**. This acceptance is explicitly **not** permission to:

- invent a new `Verified` outcome by relaxing or bypassing FORNX-442's
  safety fix, or
- let this one future capability block every unrelated v0.0.9 engineering
  task.

Equally, it is not permission to market default-provider automatic
test-result verification as already available — product/doc claims must
state the actual ceiling (see
`docs/research/adapter-capability-matrix.md`'s "`test_result` claim verdict
ceiling" section, added alongside this ADR).

FORNX-443 remains the tracked engineering/product-design owner for
eventually adding a genuinely authoritative signal. Preference order,
decided now so a future implementer doesn't re-litigate it:

1. **Independently trustworthy process-exit evidence** — e.g. an upstream
   protocol change giving Claude Code's hook payload a literal exit-code
   field, or Codex defaulting (or being configured) to `tools.shell_command`
   instead of `unified_exec`.
2. **Controlled runner receipts** — a test runner or CI step that emits its
   own signed/structured pass-fail receipt Fornax can trust as
   `IndependentExternal`/`HostObserved`-class evidence, rather than
   reconstructing success from incidental tool output.
3. **Verified CI evidence** — a real CI provider's own pass/fail status
   (already partially modeled elsewhere in this codebase for other evidence
   kinds) as a cross-check.
4. **Parsing arbitrary stdout text per test-runner framework** — explicitly
   the *least* preferred option. Pattern-matching pytest/cargo-test/etc.
   output text is fragile across versions, locales, and custom reporters,
   and any such heuristic must clear the same bar FORNX-442 enforces: proven
   safety-monotonic (never introduces a new false-`Verified` path), with its
   own adversarial regression tests, before it may contribute to `Verified`.

No implementation is authorized by this ADR alone — it records the scope
decision and ordering preference. A future ticket that picks one of the
above still needs its own design review and independent adversarial
verification before merge, per this codebase's standing practice.

## What this ADR does not cover

- `fornax-cloud`'s separately-discovered, separately-tracked instance of
  this same bug class (FORNX-444) — that is a correctness bug in a
  different repo, fixed on its own timeline, not a scope question for this
  ADR.
- Any change to `fornax-verify`'s existing `is_heuristic_evidence`/
  `is_stderr_heuristic_evidence` gating — those stay exactly as FORNX-442
  shipped them.

## Consequences

- Positive: no pressure to ship a rushed, unproven stdout-parsing heuristic
  under release-date pressure; the ceiling is honestly disclosed instead of
  silently worked around.
- Negative: the product's core "verify agent claims" story is weaker than
  desired for the two most common providers' default configurations, for at
  least the v0.0.9 release. Mitigated by: Codex's non-default
  `tools.shell_command` path and the `opencode` adapter already carrying a
  real signal today, and other evidence classes (file-diff, git, CI-webhook)
  not being affected by this ceiling at all.

## Addendum (FORNX-477 residual, 2026-10-29): stdout summary as an extra condition

QA showed a runner name plus exit 0 verified a fake `pytest` that ran no test.
The correction uses stdout in the one way this ADR allows: it is
*safety-monotonic*. The runner's final summary (counts only) can only add a
condition for `Verified` (runner identified, summary in that runner's format,
passed >= 1, failed == 0). It never grants `Verified`, never creates
`Contradicted`, and never raises the heuristic `Review` ceiling.

Residual (unchanged in kind): the summary is written by the executed program,
so a program that prints a forged summary can still pass. Closing that needs
options 1-3 above (host-attested exit, runner receipts, CI evidence), tracked by
FORNX-443. Runners whose output is not read yet (`nextest`, `jest`, `vitest`,
`npm test`) are never `Verified` until their formats are added.
