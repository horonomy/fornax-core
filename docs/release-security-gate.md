# Release security gate

Jira: FORNX-233. This document is the canonical owner of the row
`docs/release-assurance-policy.md`'s scope table assigns to it: **the
security gate runbook, the security-specific assurance-depth table, the
versioned threat model, the trust-boundary delta record, and the
security sign-off artifact format.** It does not re-derive or restate
anything already owned elsewhere — see "What this document does not own"
below.

The canonical risk classes, the shared surface vocabulary, the
`PASS`/`BLOCK`/`INCONCLUSIVE`/`UNTESTED` verdict semantics, and the blocker
taxonomy this document's gate produces verdicts against are defined in
[`docs/release-assurance-policy.md`](release-assurance-policy.md)
(FORNX-229) and are not repeated here except where quoted. The
feature-delta items, `risk_class` manifest field, and shared `surfaces`
enum this gate consumes as input are defined in
[`docs/release-candidate-evidence.md`](release-candidate-evidence.md)
(FORNX-231) and are consumed here, not redefined.

## What this document does not own

- **Risk/change class definitions, verdict semantics, blocker taxonomy,
  waiver policy** — `docs/release-assurance-policy.md` (FORNX-229). This
  document consumes those definitions for its own security-depth table; it
  does not redefine them.
- **Candidate manifest schema (`version`/`repos`/`evidence`/`risk_class`),
  feature-delta discovery, the golden-journey catalog, QA coverage
  reconciliation** — `docs/release-candidate-evidence.md` (FORNX-231). This
  document reads a candidate's `risk_class` and feature-delta `surfaces` as
  input; it does not produce them.
- **Mechanical gate enforcement** (that all four gates — `qa`, `security`,
  `docs`, `stage` — are present, Done, not-`BLOCK`, and candidate-referenced)
  — `scripts/release-readiness.sh` (FORNX-234, `docs/release-readiness.md`).
  This document does not change that script's behavior; the security
  sign-off artifact defined below is written to be checkable by exactly the
  checks that script already runs (`evidence.security.*`), plus the
  additional structure defined here for what must be *inside* that sign-off.
- **QA sign-off artifact format, worker evidence schema, finding
  lifecycle** — FORNX-232. This document's findings-table shape (below) is
  security-specific and independent of FORNX-232's QA finding lifecycle;
  the two are not merged, per FORNX-229's "QA and Security are independent
  additive gates" rule.
- **`/release-qa-gate` orchestration, worker lane sizing** — FORNX-230.
  This document defines the security-gate analogue but does not implement
  a QA-side orchestrator.
- **Tag/build/publish/promotion execution** — `scripts/release-execute.sh`
  (FORNX-235).
- **Release-docs/changelog/public-claim consistency** — FORNX-215/216. Any
  security/public-claim consistency check (unsupported absolute-guarantee
  language) is coordinated with those tickets' owned surface, not
  duplicated here.

## Security-specific assurance depth by risk class

`docs/release-assurance-policy.md`'s "Assurance depth by risk class" table
restates this table as the "QA-side analogue"; this document is where the
security column is actually defined and grows. Depth is **additive** — each
tier does everything the tier below it does, plus more:

| Class | Security depth |
|---|---|
| `PATCH_LOW_RISK` | Dependency/advisory/supply-chain scan (`cargo audit`, see "Dependency scanning" below), release-diff review, affected security regressions re-run. |
| `FEATURE` | Above, plus changed-attack-surface review (new/changed inputs, new endpoints, new privilege paths) and a privacy/egress review (does the change introduce a new path for data to leave a trust boundary). |
| `TRUST_BOUNDARY` | Above, plus a trust-boundary delta review (see below) against every surface the candidate's feature-delta items touch, plus adversarial/falsification coverage around the adjacent layers (a control that should reject a bad input is actually exercised with one). |
| `MAJOR_OR_GA` | Above, plus a full threat-model refresh (every boundary in the model re-reviewed, not just touched ones) and a broad penetration checklist / external-assurance inputs where required by product/release planning policy. |

A candidate's security depth is determined by its `risk_class` (the
candidate manifest field FORNX-231 owns), computed as the highest
per-item `risk_class` among its feature-delta items — never rounded down
because most of the diff "feels" lower-risk. A manifest with no
`risk_class` set has not been classified; the security gate fails closed
(`UNTESTED`) rather than assuming `PATCH_LOW_RISK`, per FORNX-229's and
FORNX-231's own fail-closed rule for that field.

### Dependency scanning

`cargo audit` runs in CI (`.github/workflows/ci.yml`'s `security` job,
added by this ticket) against every PR and push to `main`, as the baseline
`PATCH_LOW_RISK`-tier check every higher tier also inherits. A finding is
either fixed, or accepted-risk-and-documented in the sign-off's findings
table (below) with a disposition — never silently ignored. This mirrors
the dependency-scan evidence already produced ad hoc for v0.0.1
(`docs/release/v0.0.1-qa-security-signoff.md` §3.1); this ticket makes that
check run on every change instead of only before a release.

An advisory already reviewed and dispositioned `accepted_risk` in a
security sign-off is ignored by the CI job via `.cargo/audit.toml`'s
`[advisories] ignore` list, each entry commented with the advisory ID, the
reason, and a pointer to the sign-off finding that accepted it — this file
is the mechanical link between "reviewed and accepted" and "CI stays
green," never a place to silently suppress a finding that was never
reviewed. `.cargo/audit.toml` currently ignores exactly the one finding
already accepted-risk in `release/v0.0.1-security-signoff.json`
(`SEC-v0.0.1-0001`, RUSTSEC-2023-0071); adding a new ignore entry without a
corresponding sign-off finding is a process violation, not a CI
convenience.

### Known limitation

The new `security` CI job is not (yet) a required status check on `main`
branch protection — only the `rust` job is (`.github/workflows/ci.yml`'s
own comment explains why that job's name can't change). A PR can merge
with a red `security` job until an owner adds it to the required-checks
list, the same "not wired into a CI pipeline trigger" caveat
`docs/release-readiness.md` already states for its own script.

## Versioned threat model

The durable, versioned threat model lives at
[`docs/security/threat-model.md`](security/threat-model.md). It is durable
and repo-level — not regenerated per candidate, the same durability
convention `docs/release-candidate-evidence.md` uses for the golden-journey
catalog — and enumerates every trust boundary in FORNX-229/231's shared
surface vocabulary, its current controls, and known residual risk. It
carries its own version number and a changelog section: any candidate
classified `TRUST_BOUNDARY` or higher must append a changelog entry
recording what boundary changed and how the model's own description of
that boundary was updated (or explicitly confirmed unchanged). A
`MAJOR_OR_GA` candidate requires every boundary to be re-reviewed, not just
the touched ones, and the changelog entry to say so explicitly.

## Trust-boundary delta record

Per-candidate, produced fresh for each candidate that has at least one
feature-delta item whose `surfaces` include a trust-boundary value (see
FORNX-231's Shared surface vocabulary, "Trust boundary?" column) — i.e.
whenever a candidate's `risk_class` is `TRUST_BOUNDARY` or `MAJOR_OR_GA`.
Schema: [`release/trust-boundary-delta.schema.json`](../release/trust-boundary-delta.schema.json).

```jsonc
{
  "version": "v0.0.1",
  "generated_at": "2026-09-01T00:00:00Z",
  "threat_model_version": 1,          // docs/security/threat-model.md's version this delta was reviewed against
  "boundaries_touched": [
    {
      "surface": "adapter_provider_input",   // must be a trust-boundary=yes value from the shared vocabulary
      "feature_delta_ids": ["FD-v0.0.1-0001"],
      "review": "...",                        // what changed at this boundary and why it does/doesn't introduce new risk
      "adversarial_coverage": "..."           // the falsification/negative test that proves the control still rejects a bad input at this boundary, or NOT_RUN with a reason
    }
  ]
}
```

- A candidate whose `risk_class` is `TRUST_BOUNDARY` or higher and has no
  trust-boundary delta record is `UNTESTED` on the security gate, per
  FORNX-229's verdict semantics — never silently treated as `PASS` because
  the rest of the sign-off looks complete.
- `adversarial_coverage` is the machine-checkable form of this ticket's AC
  "negative/falsification tests: security control weakening should make
  the appropriate gate/test fail" — it must name the actual test/check
  exercised, never "manual review only," mirroring FORNX-231's
  `evidence_requirements` convention for golden journeys (concrete, never a
  bare narrative string).

## Security sign-off artifact

Schema: [`release/security-signoff.schema.json`](../release/security-signoff.schema.json).
This is the artifact the security gate's Jira ticket (the `evidence[]`
entry with `"gate": "security"` in the candidate manifest, FORNX-234's
schema) carries — either embedded in the ticket body/comment as this exact
JSON, or committed to the repo and linked from the ticket, either way
satisfying `release-readiness.sh`'s existing `evidence.security.*` checks
(exists, Done, not-`BLOCK`, candidate-referenced) without any change to
that script.

```jsonc
{
  "version": "v0.0.1",
  "candidate_repos": [
    { "name": "fornax-core", "owner": "horonomy", "sha": "1eed367..." }
    // must match (a subset consistent with) the candidate manifest's repos[]
  ],
  "risk_class": "TRUST_BOUNDARY",
  "trust_boundary_delta_ref": "release/v0.0.1-trust-boundary-delta.json", // required when risk_class is TRUST_BOUNDARY or MAJOR_OR_GA; null otherwise
  "findings": [
    {
      "id": "SEC-v0.0.1-0001",
      "severity": "medium",              // critical | high | medium | low | informational
      "title": "...",
      "evidence": "...",                 // concrete: command run, log line, test name+result — never a bare narrative
      "disposition": "accepted_risk",    // fixed | accepted_risk | waived | open
      "waiver_ref": null                 // Jira comment URL; required (non-null) when disposition is "waived", per FORNX-229's waiver policy
    }
  ],
  "verdict": "PASS"                       // PASS | BLOCK | INCONCLUSIVE | UNTESTED, per FORNX-229's verdict semantics
}
```

- **Exact-candidate-bound**: `candidate_repos` names the exact SHA(s) this
  sign-off attests to. This is the same binding
  `release-readiness.sh`'s `evidence.security.<key>.candidate_reference`
  check already enforces at the ticket-text level (a 7+ char SHA or the
  manifest `version` must appear in the ticket text) — this schema makes
  that binding structured and machine-checkable at the artifact level too,
  rather than relying solely on substring matching over prose.
- **`severity` is effective severity to this candidate, not an upstream
  advisory's own rating.** A scanner (e.g. `npm audit`) may rate a finding
  `high` while it is genuinely unreachable in what actually ships (a
  dev-server-only dependency chain never present in the published
  artifact, for example). `severity` records the reachability-adjusted
  rating, and `evidence` must state the reachability argument explicitly
  whenever `severity` is rated below the scanner's own rating — silently
  downgrading severity with no stated reason is not permitted.
- **Machine-checkable verdict rule**: `verdict` must be the worst of
  `findings[].severity`/`disposition` — any `critical` or `high` finding
  with `disposition` other than `fixed` or a fully policy-compliant
  `waived` (all five conditions in FORNX-229's Residual-risk and waiver
  policy) forces `verdict: "BLOCK"`. This is the machine-checkable form of
  this ticket's AC "High/Critical unresolved findings block release unless
  an explicit policy-compliant owner disposition is recorded."
- A `risk_class` of `TRUST_BOUNDARY` or `MAJOR_OR_GA` with
  `trust_boundary_delta_ref: null` is a schema-invalid sign-off — the
  artifact cannot represent "trust boundary changed, no delta reviewed" as
  a valid `PASS`, mirroring FORNX-231's "NOT_COVERED carries a
  remediation_jira_key" fail-closed convention.
- **Known gap this convention closes, not the shipped checker**:
  `release-readiness.sh`'s `not_blocked` check greps the sign-off ticket's
  text for the literal token `BLOCK` only — a Done ticket carrying a
  security sign-off whose `verdict` is `INCONCLUSIVE` or `UNTESTED` (both
  of which block per FORNX-229's verdict semantics, "no fake PASS") passes
  every check that script runs today, since neither word is `BLOCK`. This
  document's rule closes that gap procedurally rather than mechanically:
  a security sign-off whose `verdict` is not `PASS` must either keep the
  gate ticket out of `Done`, or include the literal token `BLOCK`
  somewhere in the ticket text, so `not_blocked` actually fires. This is a
  process convention this document establishes, not a claim that
  `release-readiness.sh` itself reads `verdict`, `INCONCLUSIVE`, or
  `UNTESTED` — see the AC-bullet map below for where this distinction
  matters.

## Negative/falsification controls

This ticket's AC requires that weakening a security control makes the
relevant gate/test fail, proving the check is non-vacuous rather than a
tautology that always reports green. The concrete, already-dogfooded proof
points (see "Dogfooding" below) are:

- **Redaction-before-egress**: `crates/fornax-daemon`'s `redact_json`/
  `redact_text` boundary (see `docs/privacy-redaction-policy.md`) has a
  regression test that fails if the redaction call is removed at the
  ingestion boundary — this is exactly how the real FORNX-280 defect
  (`docs/release/v0.0.1-qa-security-signoff.md` §7.3) was caught and fixed:
  the test is written against the *symptom* of a weakened control (a raw
  secret marker reaching storage), not against the control's own
  implementation detail, so removing or bypassing the control reliably
  flips the test from pass to fail.
- **`cargo audit` job**: an already-known advisory (RUSTSEC-2023-0071)
  makes the `security` CI job fail whenever it isn't explicitly ignored —
  verified by this ticket's own validation pass (see "Validation" below),
  which observed the job fail with `.cargo/audit.toml` removed and pass
  once restored.
- Any new adversarial/falsification test added under a `TRUST_BOUNDARY`
  candidate's trust-boundary delta record must itself be proven
  non-vacuous the same way: run once against the weakened control (confirm
  fail), then against the real control (confirm pass), recorded in
  `adversarial_coverage`.

## Synthetic/adversarial fixtures never contain real secrets

Every fixture used to exercise a security control (the canary-marker
technique in `docs/release/v0.0.1-qa-security-signoff.md` §3.4/§7.3, any
`cargo audit` test fixture, any future adversarial corpus) must use
generated or clearly-synthetic material (random hex, a placeholder
GitHub-token-shaped string, `sk-fake-...`), never a real credential of any
kind — the same invariant as this repo's global secret-handling policy,
restated here because a security-gate fixture is exactly the place a real
secret could accidentally get pasted "to make the test realistic." A PR
introducing a security fixture is reviewed for this specifically.

## Dogfooding: v0.0.1 through the gate

FORNX-233's AC requires a real Fornax release candidate be run through the
gate. `release/v0.0.1-security-signoff.json` instantiates the schema above
against the already-published, already-signed-off v0.0.1 candidate
(`release/v0.0.1-candidate-manifest.json`), retroactively structuring the
findings already recorded narratively in
`docs/release/v0.0.1-qa-security-signoff.md` §3 and §7 into this
document's machine-checkable shape — it does not re-run that evidence or
change v0.0.1's already-recorded `PASS` verdict, it demonstrates that the
new artifact shape can represent a real candidate's real findings
(including the two accepted-risk dependency findings and the one
previously-fixed Critical, FORNX-280) without loss of information.
`release/v0.0.1-trust-boundary-delta.json` does the same for the
trust-boundary delta record, using the boundaries the v0.0.1 sign-off
document's §7.1/§7.3 sections already exercised
(`adapter_provider_input`, `evidence_provenance`, `egress_redaction`,
`browser_rendering_injection`).

`release/v0.0.1-candidate-manifest.json` itself predates the `risk_class`
field (FORNX-231) and is a frozen historical record — it is intentionally
**not** edited here to backfill `risk_class`, since that manifest is the
exact artifact `release-readiness.sh` already evaluated for the real
v0.0.1 release. `release/v0.0.1-security-signoff.json`'s `risk_class:
"TRUST_BOUNDARY"` is this dogfooding pass's own retroactive classification
(v0.0.1 touched `egress_redaction`, a trust boundary, per FORNX-280),
demonstrating what a candidate manifest *would* have carried had FORNX-231
existed at the time — not a claim that the live manifest was gated on it.

## Validation

Docs/schema/CI-only change. `scripts/release-readiness.sh` and
`scripts/release-execute.sh` are not modified.

```bash
jq . release/security-signoff.schema.json
jq . release/trust-boundary-delta.schema.json
jq . release/v0.0.1-security-signoff.json
jq . release/v0.0.1-trust-boundary-delta.json
ajv validate -s release/security-signoff.schema.json -d release/v0.0.1-security-signoff.json
ajv validate -s release/trust-boundary-delta.schema.json -d release/v0.0.1-trust-boundary-delta.json
```

Both instances validate against their schemas.

**Schema negative controls** (prove the schema actually rejects invalid
sign-offs rather than accepting anything):

- A `findings[]` entry with `disposition: "waived"` and `waiver_ref: null`
  was appended to a copy of `release/v0.0.1-security-signoff.json` and
  re-validated — `ajv` correctly reported it invalid (`waiver_ref must be
  string`), confirming the waiver-binding rule is enforced, not decorative.
- A candidate with `risk_class: "TRUST_BOUNDARY"` and
  `trust_boundary_delta_ref: null` was validated two ways: with
  `threat_model_version` also missing (rejected: `must have required
  property 'threat_model_version'`) and with `threat_model_version`
  present but `trust_boundary_delta_ref` still `null` (rejected:
  `trust_boundary_delta_ref must be string`) — confirming the
  risk-class-conditional binding is enforced in both directions, not only
  documented prose.

**`cargo audit` job negative control** (proves the CI check is non-vacuous,
per this ticket's AC): run locally with `.cargo/audit.toml` temporarily
removed —

```bash
cargo audit   # .cargo/audit.toml absent
```

— failed with exit code 1, reporting exactly RUSTSEC-2023-0071 (the same
finding already recorded as `SEC-v0.0.1-0001`, `accepted_risk`, in
`release/v0.0.1-security-signoff.json`). Restoring `.cargo/audit.toml` and
re-running:

```bash
cargo audit   # .cargo/audit.toml present
```

— exited 0. This confirms the job fails on a real, currently-present
advisory and passes only because that specific advisory is explicitly,
traceably ignored — not because the check is a no-op.

## AC-bullet to section map

| FORNX-233 AC bullet | Where it's addressed |
|---|---|
| Skill/runbook exists with explicit risk tiers and BLOCK semantics | This document as a whole; "Security-specific assurance depth by risk class" |
| Versioned threat model and trust-boundary delta are durable and linked to release evidence | "Versioned threat model"; "Trust-boundary delta record" |
| Security sign-off is exact-candidate-bound and machine-checkable | "Security sign-off artifact" |
| Missing or non-PASS security sign-off prevents release readiness | A missing sign-off, a non-Done sign-off, or a sign-off explicitly carrying the literal token `BLOCK` is already mechanically caught by `scripts/release-readiness.sh`'s existing `evidence.security.*` checks (FORNX-234). A sign-off whose `verdict` is `INCONCLUSIVE` or `UNTESTED` is **not** mechanically caught by that script today (it only greps for `BLOCK`) — "Security sign-off artifact" above establishes the procedural convention (non-`PASS` keeps the ticket out of `Done`, or the ticket text must literally say `BLOCK`) that closes this gap without changing the shipped checker |
| High/Critical unresolved findings block release unless an explicit policy-compliant owner disposition is recorded | "Security sign-off artifact" (machine-checkable verdict rule), deferring to FORNX-229's waiver policy for what "policy-compliant" means |
| Synthetic/adversarial security fixtures never contain real secrets | "Synthetic/adversarial fixtures never contain real secrets" |
| Negative controls prove at least key egress/auth/redaction/security checks are non-vacuous | "Negative/falsification controls" |
| A real Fornax release candidate is dogfooded through the gate | "Dogfooding: v0.0.1 through the gate" |
