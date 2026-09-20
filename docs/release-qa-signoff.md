# QA sign-off artifact, worker evidence schema, and finding lifecycle

Jira: FORNX-232. This document owns exactly the row
`docs/release-assurance-policy.md`'s scope table assigns to it: the QA
sign-off artifact format, the worker evidence schema, and the finding
lifecycle. It does not re-derive or restate anything already owned
elsewhere — see "What this document does not own" below.

The canonical risk classes, gate-depth requirements, verdict semantics, and
blocker-class taxonomy this document's schemas feed into are defined in
[`docs/release-assurance-policy.md`](release-assurance-policy.md)
(FORNX-229) and are not repeated here except where quoted for the closed
vocabularies below. The candidate manifest, feature-delta list, golden-
journey catalog, and coverage reconciliation this document's sign-off
process consumes as input are defined in
[`docs/release-candidate-evidence.md`](release-candidate-evidence.md)
(FORNX-231).

**Design basis:** adapted from AAASM-5822 (QA sign-off artifact),
AAASM-5827 (independent finding verification protocol), AAASM-5828
(evidence contracts and worker result schema), and AAASM-5830/AAASM-5845
(runtime recipes and worker/coordinator handoff), each already shipped and
proven in the `agent-assembly` repo's own release-QA campaigns. The schemas
below are grounded in — and cross-checked against —
[`docs/release/v0.0.1-qa-security-signoff.md`](release/v0.0.1-qa-security-signoff.md),
a real QA/security sign-off already produced in this repo before this
ticket existed: every field this document requires is one that document
already needed in practice (frozen candidate SHAs, cited-not-repeated
evidence, explicit NOT RUN vs PASS distinction, a defect found and fixed
mid-pass, a final checklist verdict). This document formalizes that
organically-proven shape into a durable, reusable schema rather than
inventing an untested one.

## What this document does not own

- **Candidate-manifest schema, mechanical gate enforcement, `risk_class`
  field, the `not_blocked`/`candidate_reference` checks themselves** —
  [`docs/release-readiness.md`](release-readiness.md) and
  [`release/candidate-manifest.schema.json`](../release/candidate-manifest.schema.json)
  (FORNX-234). Nothing here changes that script's behavior; §1 below states
  the compatibility constraint those checks impose on this document's
  sign-off format.
- **Feature-delta discovery, golden-journey catalog, coverage
  reconciliation, the shared surface vocabulary** —
  [`docs/release-candidate-evidence.md`](release-candidate-evidence.md)
  (FORNX-231). This document's worker evidence schema reuses that
  document's `surfaces` enum verbatim rather than defining a second one.
- **`/release-qa-gate` orchestration, worker lane sizing, the concurrent-
  worker ceiling** — FORNX-230, which is the consumer of the schemas below
  (it decides how many workers to spawn and which lanes they cover), not
  their producer. This document defines worker/coordinator *roles and the
  data contract between them*, not concurrency limits.
- **Security gate skill, threat model, trust-boundary delta record** —
  FORNX-233. The blocker classes and independent-verification requirement
  for Critical/High findings referenced below are FORNX-229's, applied
  identically by both QA and security; this document does not redefine
  security severity semantics.
- **Risk classification, verdict semantics (`PASS`/`BLOCK`/`INCONCLUSIVE`/
  `UNTESTED`), blocker taxonomy, waiver policy** — FORNX-229. This document
  consumes those definitions; it does not redefine them.

## 1. QA sign-off artifact format

**Jira remains the evidence source of truth** in this repo (per
`docs/release-readiness.md`) — the QA sign-off artifact is not a second
committed file competing with Jira; it is the **required structure** of
the text (issue description and/or comments) on the Jira ticket that
`release-readiness.sh` reads as the `qa` gate's evidence for a candidate,
optionally mirrored into a committed `docs/release/<version>-qa-signoff.md`
file for long-form campaigns exactly as
`docs/release/v0.0.1-qa-security-signoff.md` already does. Either location
is acceptable as long as the Jira ticket's own text satisfies the shape
below, since that is what the mechanical checker actually reads.

### Required fields

| Field | Meaning |
|---|---|
| Candidate | Exact `version` and, per repo, the exact SHA(s) verified — must match `release/<version>-candidate-manifest.json` at sign-off time (FORNX-234's `candidate_reference` check depends on this). |
| Risk class | The candidate's `risk_class` per FORNX-229/231, and which assurance-depth tier was actually executed. |
| Baseline | The previous trusted/released version this candidate's feature-delta was computed against (matches FORNX-231's `baseline_version`). |
| Journeys exercised | Golden-journey IDs (`GJ-####`) actually run, tagged with the priority tier (P0/P1/P2) each belongs to. |
| Coverage reconciliation | Reference to the FORNX-231 coverage-reconciliation result consumed for this candidate; a `NOT_COVERED` item without a disposition here is a sign-off blocker, not a note. |
| Lane results | One result per QA lane actually run (functional/config, golden journeys, design/UI, reliability/failure-path, docs/product-consistency, security-relevant behavior — the same six lanes AAASM-5822 established and this repo's `v0.0.1-qa-security-signoff.md` already exercised across §2/§3/§7). Each lane's result cites worker evidence (§2 below) rather than re-narrating it. |
| Untested/blocked coverage | Every lane or journey not run, with the reason — explicit `NOT RUN`/`UNTESTED`, never silently omitted. Mirrors `v0.0.1-qa-security-signoff.md`'s explicit "NOT RUN, not PASS" convention exactly. |
| Findings | Table of findings reaching this sign-off, each at its current finding-lifecycle state (§3), severity, and Jira reference if `FILED`. |
| Residual risk / waivers | Any accepted risk or owner waiver, per FORNX-229's waiver policy — cites the waiver's recording location, never restates a waiver this document doesn't own. |
| Verdict | The literal line `Verdict: PASS` or `Verdict: BLOCK` — never a third spelling. FORNX-229 defines four gate verdicts (`PASS`/`BLOCK`/`INCONCLUSIVE`/`UNTESTED`), and the sign-off body above (Lane results, Untested/blocked coverage) is where that full four-state record lives, per check. This `Verdict:` line is the sign-off's own **mechanical gate token**, reconciled from those four states down to two: `INCONCLUSIVE` and undispositioned `UNTESTED` are both non-proceed per FORNX-229, so both are reconciled to `Verdict: BLOCK` at this one line — this is a reconciliation of FORNX-229's four states for the mechanical token's sake, not a redefinition or collapse of that vocabulary. |

### Mechanical-checker compatibility (read before writing a real sign-off)

`scripts/release-readiness.sh` (FORNX-234) is not modified by this document
and does not enforce every field above today. As shipped, it checks the
`qa` gate ticket for `done` (Jira `statusCategory`), `not_blocked`
(post-FORNX-279: a case-sensitive, whole-word match — the ticket text must
not contain the literal uppercase token `BLOCK` unless a real BLOCK is
intended), and `candidate_reference` (the exact SHA/version string is
present in the ticket text). **It does not require the positive `Verdict:
PASS` token to exist at all** — a `qa` gate ticket that is Done, contains
no `BLOCK` token, and references the candidate passes today's checker even
with no `Verdict:` line. The requirement that a sign-off *positively* carry
`Verdict: PASS` or `Verdict: BLOCK` is this document's own policy, not
something `release-readiness.sh` enforces yet; wiring that positive check
into the shipped checker is a future FORNX-234 amendment (or a check
FORNX-230's orchestration performs itself before treating a ticket as a
valid gate), not something this docs-only ticket changes. Write real
sign-offs to satisfy the full schema regardless — this note exists so a
reader does not mistake "the checker doesn't reject a missing `Verdict:`
line" for "a missing `Verdict:` line is fine."

The single most load-bearing mechanical constraint on this artifact's
format, restated here because it directly determines whether
`release-readiness.sh` accepts the ticket at all: never write the bare
uppercase word `BLOCK` in sign-off ticket text unless a real BLOCK verdict
is intended — ordinary prose like "release-blocking" or "blocker" is safe
post-FORNX-279 (whole-word match only), but the literal token `BLOCK` is
not decorative.

### Template

```markdown
## <version> QA sign-off

Jira: <gate ticket key>. Date: <date>.

### Candidate
- version: <version>
- <repo>: <sha>
  (repeat per repo in the manifest)

### Risk class and depth
- risk_class: <PATCH_LOW_RISK|FEATURE|TRUST_BOUNDARY|MAJOR_OR_GA>
- depth executed: <matches or exceeds the FORNX-229 table for that class>
- baseline_version: <previous released version>

### Journeys exercised
- GJ-0001 (P0): PASS — <one-line evidence reference>
- GJ-0003 (P1): PASS — <one-line evidence reference>

### Coverage reconciliation
- see <coverage-reconciliation artifact reference>; 0 NOT_COVERED items
  without disposition.

### Lane results
- functional/config: PASS — <worker evidence ref>
- golden journeys: PASS — see Journeys exercised above
- design/UI: NOT RUN — <reason>
- reliability/failure-path: PASS — <worker evidence ref>
- docs/product-consistency: PASS — <worker evidence ref>
- security-relevant behavior: PASS — <worker evidence ref, or reference to the security gate ticket if fully owned there>

### Untested/blocked coverage
- <lane or journey>: NOT RUN — <reason, never silently omitted>

### Findings
| ID | Severity | State | Jira |
|---|---|---|---|
| QF-<version>-0001 | High | FILED | FORNX-XXX |

### Residual risk / waivers
- none, or a reference to the owner disposition per FORNX-229's waiver policy.

Verdict: PASS
```

This template is illustrative, not a rigid form — `v0.0.1-qa-security-signoff.md`'s
real structure (numbered sections, a defect-found-and-fixed section, a
gap-closure follow-up pass) is equally conformant as long as every required
field above is present somewhere in the ticket text and the final line is
exactly `Verdict: PASS` or `Verdict: BLOCK`.

## 2. Worker evidence schema

Every QA worker (one lane, one surface, or one journey subset) returns
**only** the following compact sections to the coordinator — never a
file-by-file summary, chain-of-thought, or a copied raw log:

```
STATUS: COMPLETE | PARTIAL | BLOCKED
BASELINE: <repo>@<sha> (or <version> for a candidate-wide check)
VERIFIED:
  - <concise PASS/FAIL check>: <PASS|FAIL> — <one-line observable evidence>
SUSPECTED_FINDINGS:
  - id: <worker-local temp id, e.g. W3-1>
    severity: <Critical|High|Medium|Low>
    surface: <one of the FORNX-231 shared surface vocabulary values>
    expected: <...>
    actual: <...>
    reproduction: <exact command/steps, not narrative>
    confidence: <HIGH|MEDIUM|LOW>
UNTESTED_OR_BLOCKED:
  - <coverage item>: <reason it was not exercised>
CONFIDENCE: HIGH | MEDIUM | LOW
```

- `UNTESTED` is always preferred over an inferred PASS — the same rule
  `v0.0.1-qa-security-signoff.md` §3.2/§3.3 already applied by explicitly
  marking two dynamic exercises "NOT RUN, not PASS" rather than rounding up.
- A worker may cite implementation source for diagnosis, but an outside-in
  golden-journey check's PASS/FAIL still rests on the journey's own
  `evidence_requirements` (FORNX-231), not on source inspection alone.
- Environment/test-harness failures are recorded distinctly from product
  findings: an `UNTESTED_OR_BLOCKED` entry whose reason is environmental
  (e.g. "backend/Postgres not stood up this pass" — `v0.0.1-qa-security-signoff.md`
  §3.4's exact case) is never listed under `SUSPECTED_FINDINGS`. Only a
  failure attributable to actual product behavior belongs there.

### Evidence contract by surface

The minimum useful evidence a `VERIFIED`/`SUSPECTED_FINDINGS` entry must
cite, by kind of check:

| Kind | Minimum evidence |
|---|---|
| CLI (`cli` surface) | Exact command run, exit status, the meaningful stdout/stderr line(s), expected vs. actual. |
| Daemon/socket/API (`daemon_socket`, `event_transport`) | Request/action sent, the relevant response/log line/effect, expected vs. actual, tested SHA/version. |
| Browser/design (`browser_rendering_injection`, `ui_docs`) | URL/view, action taken, observed result, console/network error status; a screenshot only when it materially supports the finding (matches `docs/release/0001-fornx-238-dashboard-xss-check.md`'s own practice). |
| Docs/product-consistency (`ui_docs`) | The documented claim/command quoted, and the actual behavior observed against it; classified as matching or drifted. |
| Security-relevant (`evidence_provenance`, `egress_redaction`, `cloud_identity_tenant`, `sdk_plugin_trust`) | Precondition, attack/action, observed boundary behavior, exploitability/impact, and whether independent verification is still required (see §3). |
| Reliability/failure-path (`judge_replay_execution`, `adapter_provider_input`) | Induced/reachable failure condition, recovery/degradation behavior actually observed, expected vs. actual — matches `v0.0.1-qa-security-signoff.md` §7.1's adversarial-input corpus practice. |

A worker result citing a check kind not covered above still uses the
generic `VERIFIED`/`SUSPECTED_FINDINGS` shape; this table exists to keep
independently-produced worker evidence comparable across lanes, not to
gate what a worker is allowed to check.

## 3. Finding lifecycle

```
SUSPECTED -> DEDUPED -> INDEPENDENTLY_VERIFIED -> CONFIRMED | REJECTED -> FILED
```

A worker's `SUSPECTED_FINDINGS` entry is **never** automatically a
confirmed product defect and is never filed as a Jira Bug directly from
that state.

| State | Meaning | Who moves it here |
|---|---|---|
| `SUSPECTED` | A worker observed something that looks wrong. | The worker that found it. |
| `DEDUPED` | Checked against existing open Bugs, current epic findings, prior sweep/release findings, and accepted/known limitations. If a match exists, this finding is linked/annotated onto the existing record — it never becomes a second Jira issue. | The coordinator, before any verification step. |
| `INDEPENDENTLY_VERIFIED` | A party other than the original finder reproduced it (see depth rule below), using only the minimum reproduction contract (`reproduction`/`expected`/`actual` from §2) — never the finder's full reasoning, to reduce confirmation bias. | A different worker, the coordinator, or (for Critical/High) a dedicated `qa-finding-verifier` role (§4). |
| `CONFIRMED` | Independent verification reproduced the defect. | Same party as `INDEPENDENTLY_VERIFIED`. |
| `REJECTED` | Independent verification could not reproduce it, or it is determined to be an environment/test-harness artifact rather than a product defect. Recorded compactly in the sign-off (§1's Findings table) — never filed as a Jira Bug. | Same party as `INDEPENDENTLY_VERIFIED`. |
| `FILED` | A `CONFIRMED` finding has a Jira Bug opened for it, carrying affected SHA/version, user/security impact, reproduce steps, expected/actual, evidence, severity/priority, acceptance criteria, and verification method — the same defect-ticket structure this repo already uses (FORNX-279, FORNX-280, FORNX-281 in `v0.0.1-qa-security-signoff.md` §5/§7.3/§7.6). | The coordinator. |

### Independent-verification depth (ties into FORNX-229)

- **Critical/High severity, or any P0-journey-breaking finding**: requires
  independent reproduction by a party other than the original finder before
  `CONFIRMED` — matches FORNX-229's blocker-class rule ("once confirmed
  (independently reproduced ... for High/Critical and P0 findings)") and
  its `TRUST_BOUNDARY`-tier depth requirement. `v0.0.1-qa-security-signoff.md`
  §7.3 (FORNX-280, Critical) is the real precedent: reproduced independently
  before the fix, then re-verified independently after.
- **Medium/other load-bearing defects**: independent verification is
  expected when practical; the coordinator may perform the verification
  itself if worker capacity is constrained, but the verifying party must
  still be distinct from the finder.
- **Low/cosmetic**: lightweight confirmation is sufficient, but it must
  still cite concrete evidence (§2's schema) — never a bare assertion.
- Independent verification must never mutate production or destructive
  infrastructure without explicit human approval, per this repo's
  standing safety rules.

### Rejected candidates stay traceable without Jira noise

A `REJECTED` finding is recorded in the sign-off's Findings table (§1) with
its state and a one-line rejection rationale. It is not filed, not
commented onto an unrelated ticket, and not silently dropped — the sign-off
document itself is the durable, traceable record for candidates that never
became Bugs, exactly as `v0.0.1-qa-security-signoff.md` recorded "NOT RUN"
items and accepted-risk dependency findings inline rather than filing
tickets for them.

## 4. QA verifier roles and coordinator handoff contract

Three roles, no nested spawning (a worker or verifier never spawns a
further sub-agent):

| Role | Responsibility | Input it receives | Output it returns |
|---|---|---|---|
| `qa-coordinator` | Reads the candidate manifest, feature-delta list, and coverage reconciliation (FORNX-231); assigns lanes/journeys to workers per the depth table (FORNX-229); performs deduplication (§3); assembles the final sign-off (§1). | Candidate manifest, feature-delta/coverage artifacts, worker results. | The QA sign-off artifact (§1). |
| `qa-worker` | Executes one lane or journey subset; produces one worker evidence result (§2). | A single lane/journey assignment, the runtime recipe(s) it needs (§5), and the minimum reproduction contract for any known related prior findings (never the coordinator's full state). | One worker evidence result (§2). |
| `qa-finding-verifier` | Independently reproduces a `SUSPECTED`/`DEDUPED` finding for Critical/High/P0 cases (§3). | Only the minimum reproduction contract (`reproduction`/`expected`/`actual`) — never the original worker's full reasoning or transcript, to avoid confirmation bias. | `INDEPENDENTLY_VERIFIED` + `CONFIRMED`/`REJECTED` disposition with its own evidence (§2 shape). |

The coordinator is the only role that reads across multiple workers' full
output; workers and verifiers never see each other's raw transcripts,
only the compact schemas above. Worker-count sizing and lane assignment
strategy belong to FORNX-230's orchestration, not this document.

## 5. Runtime verification recipes

A persistent, secret-free recipe per repo/surface so a fresh worker does
not rediscover launch mechanics from README archaeology every run. Recipes
live under `docs/release/runtime-recipes/<surface>.md`; each recipe states:

| Field | Meaning |
|---|---|
| Working directory | Repo-relative, never an absolute local-user path. |
| Prerequisites | Non-secret only (e.g. "Rust toolchain per `rust-toolchain.toml`"); a required secret is referenced by environment-variable name, never a value. |
| Start command | Exact command(s) to bring the surface up. |
| Readiness probe | How to confirm it's actually ready (log line, port response) before verifying anything against it. |
| Minimum verification probe | The smallest command/action that proves the surface is alive and behaving, distinct from a full golden-journey run. |
| Expected ports/artifacts | Ports/files this surface uses, so a worker can detect collisions before starting a duplicate instance. |
| Cleanup | Exact shutdown/teardown steps — every recipe ends the environment in the state it found it. |
| Variant | `published-artifact` (installs/runs the shipped binary/package) or `source-development` (builds from this checkout) — a public-golden-journey run must use the `published-artifact` variant where one exists; it must never silently substitute a source build for an unavailable public path. |

### Seed recipe: `fornax-core` local daemon path

[`docs/release/runtime-recipes/fornax-daemon-local.md`](release/runtime-recipes/fornax-daemon-local.md)
is the first committed recipe, covering the local `fornax-daemon` +
`fornax-hook-claude` + `fornax` CLI path that `GJ-0001`, `GJ-0002`, and the
daemon side of `GJ-0004` exercise (`GJ-0003` is the Codex hook path, not
covered by this recipe — see the still-open `fornax-hook-codex` recipe
below). It is grounded directly in this repo's own
`README.md` Quick Start — the exact sequence `v0.0.1-qa-security-signoff.md`'s
FORNX-34 evidence and this repo's own adversarial/XSS follow-up passes
(§7.1/§7.2) already executed for real — and follows the eight-field shape
above (working directory, prerequisites, start command, readiness probe,
minimum verification probe, expected ports/artifacts, cleanup, variant).

Populating the remaining recipes (`fornax-hook-codex`, `fornax` CLI subset,
`fornax-cloud`/`fornax-website` surfaces) is ongoing work, the same way
`release/golden-journeys.json`'s four-entry seed catalog is a starting
point, not a claim of exhaustive coverage — each is added when a real QA
pass first needs it, following this same eight-field shape.

## Validation

Docs-only change; no script or crate is modified.

```bash
git diff --stat -- scripts/ crates/         # empty: no code touched
bats tests/release-readiness/release_readiness.bats   # unmodified suite, still green
```

The seed runtime recipe (§5,
`docs/release/runtime-recipes/fornax-daemon-local.md`) was executed for
real on 2026-09-01 — see that file's "Execution record" section — rather
than merely written and left unverified.

## AC-bullet to section map

| FORNX-232 AC bullet | Where it's addressed |
|---|---|
| QA sign-off is durable, exact-candidate-bound and machine-checkable for PASS/BLOCK | §1 (Candidate field, `Verdict:` line; the "Mechanical-checker compatibility" note states exactly which parts `release-readiness.sh` enforces today vs. which are this document's own policy pending a future checker amendment) |
| Worker evidence is compact and sufficient for independent review | §2 |
| High/Critical/P0 suspected failures cannot become release blockers without recorded reproduction/verification unless the evidence source is already independently authoritative and policy explicitly permits it | §3 ("Independent-verification depth"); a security-gate ticket that is itself the independently-authoritative source may be cited directly in §1's security-relevant lane per FORNX-229's independent-additive-gates rule |
| Rejected false positives remain traceable without filing duplicate Bugs | §3 ("Rejected candidates stay traceable without Jira noise") |
| Runtime recipes allow a fresh agent/session to execute common QA surfaces without rediscovering setup from long READMEs | §5 |
| Recipes include cleanup and do not embed credentials/secrets | §5 (Cleanup field; Prerequisites field references env-var names only) |
| Real campaign evidence proves resume/reuse behavior | Grounded throughout against `docs/release/v0.0.1-qa-security-signoff.md`, a real sign-off already produced in this repo (see intro and inline citations in §1–§3); [`docs/release/runtime-recipes/fornax-daemon-local.md`](release/runtime-recipes/fornax-daemon-local.md) reproduces that same document's FORNX-34/§7.1 exercise commands verbatim, proving the recipe format is sufficient to resume that exact campaign without re-deriving it. Full multi-surface resume/reuse proof across a second real candidate lands with the first FORNX-230-orchestrated `/release-qa-gate` run, which is this document's actual consumer. |
