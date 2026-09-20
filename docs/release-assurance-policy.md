# Release assurance policy

Jira: FORNX-229. This is the canonical policy: the shared vocabulary and
rules that the release-assurance *tools* implement and that the release-
assurance *tickets still to be built* must conform to rather than each
inventing their own. It does not replace or re-implement anything already
shipped — see "What already exists" below.

## Scope boundary (read this before extending this doc)

FORNX-229 is one of nine tickets under the Release Assurance epic
(FORNX-228). Several are Done and already ship real tooling; several are
still `To Do` and own specific pieces of this space. This document defines
only what no other ticket, done or planned, already owns:

| Concern | Owner | Status |
|---|---|---|
| Candidate-manifest schema, mechanical gate enforcement (qa/security/docs/stage all required, Done+not-BLOCK+candidate-referenced) | FORNX-234 | Done |
| Tag/build/publish/promotion execution, tag immutability, yank/deprecate mechanics | FORNX-235 | Done |
| `/release-qa-gate` orchestration, worker lane sizing | FORNX-230 | Done — `.claude/skills/release-qa-gate/SKILL.md` |
| Candidate manifest content, feature-delta discovery, golden-journey **catalog** (stable IDs, P0/P1/P2 assignment per journey, evidence contract), coverage reconciliation | FORNX-231 | Done — `docs/release-candidate-evidence.md` |
| QA sign-off artifact format, worker evidence schema, finding lifecycle | FORNX-232 | Done — `docs/release-qa-signoff.md` |
| Security gate skill, versioned threat model, trust-boundary delta record | FORNX-233 | Done — `docs/release-security-gate.md` |
| Post-release smoke/canary/rollback automation | FORNX-236 | Done |
| Release-docs/changelog/website-impact workflow | FORNX-216 | Done |
| **Risk classification, assurance-depth policy, verdict semantics, blocker taxonomy, waiver policy, the canonical relay, degraded-CI evidence policy** | **FORNX-229 (this doc)** | This ticket |

Notably, FORNX-233 already names the four risk/change classes used below
(`PATCH_LOW_RISK`, `FEATURE`, `TRUST_BOUNDARY`, `MAJOR_OR_GA`) and defines
its own *security-specific* additive depth per class. This document defines
the classes themselves — what makes a change fall into each one — as a
single shared taxonomy so FORNX-230/232/233/236 classify a given release
candidate identically instead of drifting. It does not redefine FORNX-233's
security-depth table, and it does not build FORNX-231's golden-journey
catalog — it states the policy principle (which risk tiers require which
journey tiers) that catalog must satisfy.

## What already exists (do not re-derive)

- **`scripts/release-readiness.sh`** (FORNX-234, `docs/release-readiness.md`)
  mechanically enforces that a candidate manifest's four gates — `qa`,
  `security`, `docs`, `stage` — each carry a Done, non-BLOCK, candidate-
  referenced Jira sign-off. It does not vary which gates are required by
  risk; risk instead governs *what must be true inside* a gate's sign-off
  before it may be recorded as Done (see "Assurance depth by risk class"
  below) — this keeps the shipped checker's "all four gates always
  required" behavior correct as-is. An optional `risk_class` manifest field
  is now defined in
  [`docs/release-candidate-evidence.md`](release-candidate-evidence.md)
  (FORNX-231, which owns the manifest schema); `release-readiness.sh` itself
  still does not read or enforce it.
- **`scripts/release-execute.sh`** (FORNX-235, `docs/release-execute.md`)
  performs the canonical relay's `Release` and post-`Release` mechanics:
  tag creation (immutable, never moved), canonical GitHub Release,
  partial-failure evidence, and `--yank` for post-publication deprecation.
- **`scripts/release-post-verify.sh`** (FORNX-236,
  `docs/release-post-verify.md`) performs the canonical relay's
  `Post-Release Verification` step: clones the actually published tag into
  an isolated context, verifies artifact/version identity and checksum
  coverage against the release-execution evidence, runs a small P0 smoke
  matrix, and derives the `PUBLISHED_PENDING_VERIFICATION -> HEALTHY`
  transition — never by re-running readiness, per the "no fake PASS" rule
  in Verdict semantics below.
- **CI_UNAVAILABLE_EXTERNAL classification** (this session's own working
  practice, and Jira comments on FORNX-229/234) already establishes that
  hosted-CI unavailability is not itself a correctness failure, and that a
  local-equivalent verification manifest can substitute. This document
  promotes that practice from Jira-comment/session-convention status to
  committed policy (see "Degraded-CI evidence" below) so it survives
  outside any one session's context.
- **The five-state finding vocabulary** (`VERIFIED` / `UNVERIFIED` /
  `CONTRADICTED` / `REVIEW` / `UNAVAILABLE`, ADR-0001 D4) is Fornax's
  **product** verdict for what the daemon concludes about an agent's claim.
  It is a different vocabulary for a different question. The release-
  assurance verdicts defined below (`PASS` / `BLOCK` / `INCONCLUSIVE` /
  `UNTESTED`) describe whether a *release candidate* may proceed, never an
  agent-integrity finding. Do not conflate the two, and do not collapse
  either one into the other.

## The canonical release relay

```
Scope Freeze -> Stage READY -> Feature Delta -> QA Coverage Reconciliation
  -> QA PASS -> Security PASS -> Release Docs PASS -> Exact-Candidate Readiness
  -> Release -> Post-Release Verification -> HEALTHY
```

| State | Meaning | Owning ticket/tool |
|---|---|---|
| Scope Freeze | The set of changes targeting this version is fixed; no new scope is added without restarting downstream assurance for the added scope. | Release planning (Jira fix-version), not a tool today |
| Stage READY | The pre-release milestone gate (Gate 2 class checks, e.g. FORNX-34) is satisfied. | Existing per-milestone Stage tickets |
| Feature Delta | What actually changed vs. the last released baseline is enumerated (capability/schema/config/UI surfaces, not path-only heuristics). | FORNX-231 |
| QA Coverage Reconciliation | Every feature-delta item is classified `COVERED` / `PARTIALLY_COVERED` / `STALE_COVERAGE` / `NOT_COVERED` / `DUPLICATE_EXISTING_COVERAGE` / `OUT_OF_CURRENT_RELEASE_QA_SCOPE`; material `NOT_COVERED` blocks. | FORNX-231 |
| QA PASS | QA gate sign-off recorded per the assurance depth this candidate's risk class requires (below). | FORNX-230/232, enforced by FORNX-234 |
| Security PASS | Security gate sign-off recorded per its own risk-scaled depth (FORNX-233), independently of QA PASS. | FORNX-233, enforced by FORNX-234 |
| Release Docs PASS | Version-specific release-docs/changelog/website-impact ticket is Done and candidate-referenced — never a multi-version epic (see FORNX-234's PR #26 gate-scoping fix). | FORNX-216, enforced by FORNX-234 |
| Exact-Candidate Readiness | All four gates verified mechanically against the exact candidate manifest. | `scripts/release-readiness.sh` (FORNX-234) |
| Release | Tag/publish/promote against the frozen candidate. | `scripts/release-execute.sh` (FORNX-235) |
| Post-Release Verification | The actually published/deployed artifact is smoke-tested from a clean environment. | FORNX-236 |
| HEALTHY | Only reachable after Post-Release Verification PASS — a release is `PUBLISHED_PENDING_VERIFICATION` until then, never HEALTHY on publication alone. | FORNX-236 |

**Blocking semantics:** each state gates the next. A state may not be
skipped, and a later state passing does not retroactively excuse an earlier
one — e.g. a clean Post-Release smoke does not make a missing QA PASS
acceptable after the fact. QA PASS and Security PASS are **independent
additive gates**: neither may substitute for or waive the other, and both
are required regardless of which one a given change's risk class weighs
more heavily.

## Risk / change classes

Every release candidate — and, where changes are large enough to differ
internally, every individual feature-delta item — is classified into
exactly one of four classes. Classification is based on the nature of the
change, not on SemVer alone: a pre-1.0 patch release can still touch a
trust boundary, and must be classified `TRUST_BOUNDARY` even though the
version number says "patch."

| Class | Definition |
|---|---|
| `PATCH_LOW_RISK` | Bug fixes, dependency/toolchain bumps, refactors, docs/config changes, and other changes with no behavioral change to a trust boundary, public API/schema, or default posture. |
| `FEATURE` | New user/operator-visible capability, or an additive change to an existing capability, that does not itself alter a trust boundary (see boundary list below) or an already-shipped compatibility guarantee. |
| `TRUST_BOUNDARY` | Any change that touches: local daemon/socket surface, adapter/provider input handling, evidence/provenance integrity, egress/redaction behavior, cloud identity/tenant authorization, browser rendering/injection surface, event transport, judge/replay execution, enterprise policy/deployment, or SDK/plugin trust — the same boundary list FORNX-233 uses for its trust-boundary delta record. |
| `MAJOR_OR_GA` | A milestone explicitly designated GA/major by product/release planning (e.g. the eventual `v0.1.0`), or any release that changes a previously-guaranteed compatibility/support commitment. |

Classes are **additive**, each one implying every requirement of the
classes before it plus its own:
`PATCH_LOW_RISK` ⊂ `FEATURE` ⊂ `TRUST_BOUNDARY` ⊂ `MAJOR_OR_GA`.

A release candidate's overall class is the **highest** class among its
feature-delta items — one `TRUST_BOUNDARY` change inside an otherwise
`FEATURE`-class release makes the whole candidate `TRUST_BOUNDARY` for
gate-depth purposes, even though most of the diff is unrelated.

Classification is a FORNX-231 candidate-manifest field once built
(tracked there, not here); this document is the definition that field's
values must satisfy.

## Assurance depth by risk class

Depth is **additive**, not a replacement — each tier does everything the
tier below it does, plus more:

| Class | QA depth | Security depth (canonically owned by [`docs/release-security-gate.md`](release-security-gate.md), FORNX-233; restated here as the QA-side analogue) |
|---|---|---|
| `PATCH_LOW_RISK` | P0 golden journeys touched by the change only; reuse already-green exact-candidate CI evidence rather than re-running unaffected suites. | Dependency/advisory/supply-chain scan, release-diff review, affected security regressions. |
| `FEATURE` | Above, plus all P0 journeys plus P1 journeys for the touched surface. | Above, plus changed-attack-surface and privacy/egress review. |
| `TRUST_BOUNDARY` | Above, plus P2 journeys for the touched surface, plus independent reproduction (not solely coordinator-asserted) of any High/Critical suspected finding. | Above, plus trust-boundary delta review and adversarial/falsification coverage around the adjacent layers. |
| `MAJOR_OR_GA` | Above, plus full P0/P1/P2 sweep across all surfaces (not just touched ones), regardless of how small the actual diff looks. | Above, plus full threat-model refresh and broad penetration checklist / external-assurance inputs where required by policy. |

"P0/P1/P2 journeys" refers to the golden-journey catalog FORNX-231 owns
building; this table states when each tier must be pulled in, not what the
journeys are. A deep sweep (full catalog, all surfaces) is required exactly
at `MAJOR_OR_GA` — never below it merely because a release "feels
significant"; conversely, a release must not stay at `PATCH_LOW_RISK` depth
merely because it is numbered as a patch when its content is
`TRUST_BOUNDARY` or higher by the classification rule above.

## Verdict semantics: PASS / BLOCK / INCONCLUSIVE / UNTESTED

Every gate (QA, Security, Docs, Stage) and every individual verification
lane within a gate must resolve to exactly one of these four states. No
other spelling, and no silent default to PASS:

| Verdict | Meaning | May the candidate proceed? |
|---|---|---|
| `PASS` | The required depth for this candidate's risk class was executed, and every check within it observed the expected result. | Yes, for this gate. |
| `BLOCK` | A required check ran and observed a result that violates a blocker class (below), or an owner/reviewer explicitly recorded a BLOCK. | No, until the blocker is resolved or an explicit policy-compliant waiver is recorded (see Residual-risk waivers). |
| `INCONCLUSIVE` | A required check ran but could not produce a confident PASS or BLOCK (flaky signal, ambiguous evidence, environment fault masking the real result). | No — `INCONCLUSIVE` is not a weaker PASS; it blocks exactly like `BLOCK` until resolved into a real PASS or BLOCK. |
| `UNTESTED` | A required check for this risk class's depth did not run at all — including because hosted CI could not execute it (see Degraded-CI evidence) or because a surface was explicitly out of scope. | No, unless the specific missing signal is individually risk-dispositioned under the waiver policy below. Silently converting `UNTESTED` into `PASS` is never permitted. |

A gate's overall verdict is the worst of its constituent check verdicts:
one `BLOCK` or `UNTESTED`-and-undispositioned check makes the whole gate
non-`PASS`, regardless of how many other checks passed. This is the "no
fake PASS" rule this ticket's AC requires.

## Blocker classes

Any of the following, once confirmed (independently reproduced per the
depth table above for High/Critical and P0 findings), is a release blocker
by default and forces `BLOCK` on the owning gate:

- Critical or High severity security finding.
- Sensitive-data egress (data leaving a trust boundary without the
  redaction/consent the product claims).
- Tenant or authentication/authorization bypass.
- Data corruption or data loss.
- A security or safety control found to fail open instead of closed.
- A broken P0 user/operator/security journey.
- Wrong release artifact, wrong version identity, or an artifact that does
  not match its recorded checksum/digest/signature.
- Migration failure (schema/data migration does not complete or is not
  reversible when the release requires reversibility).
- Release-doc or public-claim mismatch (the release notes/website assert
  something the shipped candidate does not actually do).

This list is the shared vocabulary FORNX-232 (finding lifecycle) and
FORNX-233 (security severity/BLOCK semantics) classify findings against;
it does not replace either ticket's own schema.

## Residual-risk and waiver policy

A `BLOCK` or undispositioned `UNTESTED` verdict may be waived only when
**all** of the following hold, mirroring the owner-only exception pattern
already established for merge/history decisions in this repo (see
`CONTRIBUTING.md` for standing review/merge conventions, and this repo's
FORNX-52 owner-authorized `main` history normalization — recorded in this
repo's own CLAUDE.md history note — as precedent for a documented one-time
exception):

1. The specific missing/failing signal, and the reason it cannot be
   produced, is stated explicitly — never a blanket "trust me."
2. A verified repo/org **owner** (never a maintainer/collaborator/bot, and
   never inferred from admin-capable API access alone) records the
   disposition in the same ticket/evidence trail the gate reads.
3. The disposition is scoped to this exact candidate/version — it does not
   carry forward to the next release without being re-recorded.
4. Waiving does not touch a Critical/High security finding, tenant/auth
   bypass, or data corruption/loss blocker class — those are never
   waivable regardless of owner sign-off; the fix must land instead.
5. The waiver is visible in the same evidence trail `release-readiness.sh`
   reads (a Jira comment on the gate's sign-off ticket), not a side
   channel invisible to the mechanical check.

Absent an owner disposition meeting all five conditions, `BLOCK` and
undispositioned `UNTESTED` remain blocking. This is deliberately narrower
than a general "reviewer discretion" clause — it is an exception mechanism,
not a routine approval path.

## Degraded-CI evidence (`CI_DEGRADED_EXTERNAL`)

Promotes the CI_UNAVAILABLE_EXTERNAL / CI_DEGRADED_EXTERNAL practice from
this session's working convention and the FORNX-229/234 Jira comments to
committed policy:

- Hosted CI being unable to execute for an external reason (billing/quota
  exhaustion, account-wide suspension, runner infrastructure outage,
  provider outage) is **never itself a correctness failure** and never by
  itself produces `BLOCK`.
- The candidate may still reach `PASS` when a **local CI-equivalent
  verification manifest** proves every otherwise-required check ran
  against the exact candidate SHA, recording: exact SHA(s), the commands
  run, environment/toolchain versions, dependency/lockfile identity, and a
  PASS/FAIL/UNTESTED outcome per gate, with evidence preserved for audit.
- Depth is never downgraded merely because verification happened locally
  instead of on hosted CI — the same risk-class depth table above still
  applies in full.
- Any check that genuinely cannot be reproduced locally stays explicit
  `UNTESTED`; this policy's waiver rules (above) decide whether that
  specific missing signal is materially blocking, per gate.
- Local-vs-hosted equivalence should be encoded in shared scripts/`just`
  targets where practical, so both invocation paths run the same
  underlying commands rather than two commands that merely sound similar.
- Restore hosted CI when the external condition clears; do not serialize
  ordinary development on that wait, and record the exception window so a
  temporary degraded mode does not silently become permanent process
  drift.

This is the same classification this session applied ad hoc
(`CI_FAILED` vs `CI_UNAVAILABLE_EXTERNAL`) and the same shape FORNX-234's
readiness amendment already describes for the readiness checker
specifically — this document is where it lives canonically for the whole
release-assurance policy, not only the readiness gate.

## Patch/hotfix and post-publication behavior

- A patch/hotfix release still goes through the full relay above; its risk
  class is determined by its actual content (see "Risk/change classes"),
  not shortened just because it is called a patch.
- A change genuinely classified `PATCH_LOW_RISK` gets `PATCH_LOW_RISK`
  depth — this is the intended cost saving, not a loophole: the depth
  table already scopes it to touched-surface P0 coverage plus reused CI
  evidence.
- Rollback/roll-forward/yank/deprecate mechanics after publication are
  already implemented (`scripts/release-execute.sh --yank`, FORNX-235):
  published tags are never rewritten or moved; a failed release is
  corrected via a new hotfix release or an explicit yanked/deprecated
  state, never by silently editing history. This document adds no new
  mechanism here — it only confirms that a yanked/deprecated release must
  re-enter the relay above (at minimum a new Scope Freeze through Release)
  rather than being "fixed" by mutating the original release record.

## AC-bullet to section map

| FORNX-229 AC bullet | Where it's addressed |
|---|---|
| One canonical release assurance runbook/policy is committed | This document |
| Risk depth is determined by change risk as well as SemVer | Risk/change classes |
| QA and Security are independent additive gates | Canonical release relay (Blocking semantics) |
| Release docs/public-claim gate is included but not duplicated | Canonical release relay table (Release Docs PASS row, owned by FORNX-216) |
| Stage READY vs frozen release-candidate assurance responsibilities are clearly separated | Canonical release relay table |
| Every outcome can be recorded as evidence-backed PASS/BLOCK/INCONCLUSIVE with explicit untested/blocked surfaces | Verdict semantics |
| Future patch releases can reuse the policy without redesign | Assurance depth by risk class; Patch/hotfix section |
