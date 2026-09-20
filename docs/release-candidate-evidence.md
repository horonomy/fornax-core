# Candidate manifest schema, feature-delta discovery, golden journeys, and QA coverage reconciliation

Jira: FORNX-231. This document owns exactly the row `docs/release-assurance-policy.md`'s
scope table assigns to it: candidate-manifest *content* additions, feature-delta
discovery, the golden-journey **catalog**, and QA coverage reconciliation. It does
not re-derive or restate anything already owned elsewhere — see "What this document
does not own" below.

The canonical risk classes, gate-depth requirements, and PASS/BLOCK/INCONCLUSIVE/
UNTESTED verdict semantics this document's outputs feed into are defined in
[`docs/release-assurance-policy.md`](release-assurance-policy.md) (FORNX-229) and
are not repeated here except where quoted for the closed vocabularies below.

## What this document does not own

- **The manifest's existing fields** (`version`, `repos[]`, `evidence[]`,
  `release_notes_ticket`, `release_notes_path`) and the mechanical checks
  `scripts/release-readiness.sh` runs against them — see
  [`docs/release-readiness.md`](release-readiness.md) and
  [`release/candidate-manifest.schema.json`](../release/candidate-manifest.schema.json)
  (FORNX-234). This document adds one new optional manifest field
  (`risk_class`, below) and does not touch, re-specify, or re-implement the rest.
- **Gate enforcement mechanics** (qa/security/docs/stage presence, Done/not-BLOCK/
  candidate-referenced) — `scripts/release-readiness.sh` (FORNX-234). Nothing here
  changes that script's behavior.
- **`/release-qa-gate` orchestration and worker lane sizing** — FORNX-230, which
  is the consumer of this document's outputs (feature-delta list, coverage
  reconciliation result, `risk_class`), not their producer.
- **QA sign-off artifact format, worker evidence schema, finding lifecycle** —
  FORNX-232.
- **Security gate skill, threat model, trust-boundary delta record** — FORNX-233.
- **Risk classification definitions themselves, verdict semantics, blocker
  taxonomy, waiver policy** — FORNX-229. This document consumes those
  definitions; it does not redefine them.

## Shared surface vocabulary

Golden-journey `surfaces` and feature-delta `surfaces` (below) are the same
closed enum, so a P0 journey tagged with a surface is guaranteed comparable to a
feature-delta item tagged with that same surface — this is the join the coverage
reconciliation step depends on. Ten of the fourteen values are FORNX-229's own
trust-boundary list (`docs/release-assurance-policy.md`, "Risk / change classes"),
renamed to identifiers; the remaining four cover feature-delta breadth this
document's scope requires (public API/schema/migrations, infra/config, CLI,
UI/docs) that are not themselves trust boundaries.

| Surface | Trust boundary? | Meaning |
|---|---|---|
| `daemon_socket` | yes | Local daemon/socket surface. |
| `adapter_provider_input` | yes | Adapter/provider input handling (e.g. `fornax-hook-claude`, `fornax-hook-codex`). |
| `evidence_provenance` | yes | Evidence/provenance integrity. |
| `egress_redaction` | yes | Egress/redaction behavior. |
| `cloud_identity_tenant` | yes | Cloud identity/tenant authorization. |
| `browser_rendering_injection` | yes | Browser rendering/injection surface. |
| `event_transport` | yes | Event transport. |
| `judge_replay_execution` | yes | Judge/replay execution. |
| `enterprise_policy_deployment` | yes | Enterprise policy/deployment. |
| `sdk_plugin_trust` | yes | SDK/plugin trust. |
| `public_api_schema_migration` | no | Public API/schema/migration changes. |
| `infra_config` | no | Infra/config changes not covered by a boundary row above. |
| `cli` | no | The `fornax` CLI's own behavior, not otherwise covered above. |
| `ui_docs` | no | UI and docs surfaces, including website-visible behavior claims. |

Both catalogs below are validated against this closed set. A surface value
outside this enum is a schema error, not silently ignored — extending the enum
is a change to this document, reviewed the same as any other policy change,
never inferred ad hoc by a discovery tool.

## Candidate manifest: `risk_class` (the one field this document adds)

`docs/release-assurance-policy.md` (lines 47–49, pre-this-change) explicitly
deferred a `risk_class` manifest field to this ticket. It is now added to
[`release/candidate-manifest.schema.json`](../release/candidate-manifest.schema.json)
as an **optional** top-level string field:

```jsonc
{
  "version": "v0.0.1",
  "risk_class": "FEATURE",  // optional; one of PATCH_LOW_RISK|FEATURE|TRUST_BOUNDARY|MAJOR_OR_GA
  "repos": [ /* unchanged */ ],
  "evidence": [ /* unchanged */ ]
}
```

- Optional, not required: making it required would invalidate every
  already-committed manifest (`release/example-candidate-manifest.json`,
  `release/v0.0.1-candidate-manifest.json`) and would assert an enforcement
  the shipped checker deliberately does not perform (FORNX-229 kept
  `release-readiness.sh`'s "all four gates always required" behavior correct
  as-is; risk instead governs depth *inside* a gate, not gate presence).
- `scripts/release-readiness.sh` does not read this field and its behavior is
  unchanged by this addition — verified by running its existing test suite
  unmodified (see Validation below).
- The **consumer** of this field is FORNX-230's orchestration (it decides
  which assurance depth and which golden-journey tiers a candidate's QA lane
  must cover) and this document's own coverage-reconciliation step (below).
  A manifest without `risk_class` set is a signal that classification has not
  happened yet, not an implicit `PATCH_LOW_RISK` default — an orchestrator
  that needs the field must fail closed (`UNTESTED`) rather than assume the
  lowest tier.

`docs/release-assurance-policy.md` is updated in this same PR to point its
"No `risk_class` manifest field exists today" sentence at this document instead
of describing it as absent (see that file's own diff).

## Feature-delta discovery

A **feature-delta item** is one unit of enumerated change between a release
candidate and its previous trusted/released baseline. Feature-delta discovery
is a per-candidate output, produced fresh for each candidate — never a durable
catalog like golden journeys.

```jsonc
{
  "version": "v0.0.1",
  "baseline_version": "v0.0.0",              // the previous trusted/released baseline this delta is against
  "generated_at": "2026-09-01T00:00:00Z",
  "items": [
    {
      "id": "FD-v0.0.1-0001",                // stable within this candidate's delta set; not reused across candidates
      "surfaces": ["adapter_provider_input"], // 1+ values from the Shared surface vocabulary above
      "risk_class": "TRUST_BOUNDARY",         // this item's own class per FORNX-229's per-item classification rule
      "summary": "fornax-hook-codex now forwards tool-result payloads to the daemon",
      "sources": {
        "jira_keys": ["FORNX-190"],
        "pull_requests": ["horonomy/fornax-core#77"],
        "diff_paths": ["crates/fornax-hook-codex/src/forward.rs"]
      },
      "discovery_method": "diff_review"       // one of: jira_scope | pr_history | api_schema_diff | adapter_capability_diff | infra_config_diff | ui_docs_diff | diff_review
    }
  ],
  "discrepancies": []
}
```

- `sources` cross-checks Jira scope, merged PR/Git history, and the diff
  itself — path rules (`diff_paths`) are one input signal among several, never
  the sole basis for classifying an item, per FORNX-231's AC that path-only
  mapping must not be the only detection route for capability/schema/config/UI
  changes.
- `discrepancies[]` is the machine-checkable form of "a mismatch between Jira,
  PR lineage and candidate is detected instead of silently accepted" (FORNX-231
  AC). Each entry names the exact mismatch kind and the conflicting sources —
  e.g. a PR merged into the candidate's SHA range with no corresponding Jira
  fix-version entry, or a Jira issue in the fix version with no merged PR
  found. **A non-empty `discrepancies[]` blocks** — it is not informational; a
  discrepancy must be resolved (either the source data corrected, or the
  discrepancy explicitly dispositioned per FORNX-229's waiver policy) before
  Feature Delta can be considered complete in the canonical relay.
- An item whose surface cannot be determined is not silently dropped: it gets
  `surfaces: ["infra_config"]` at minimum (the least-specific catch-all) plus a
  `sources.diff_paths` entry, and is treated as unclassified for coverage
  reconciliation purposes (see "unknown ⇒ never `COVERED`" below) — this is
  the "unknown paths/capabilities are handled conservatively rather than
  ignored" AC.
- A candidate's overall `risk_class` (the manifest field above) must equal the
  highest `risk_class` among its feature-delta items, per FORNX-229's
  additive-classes rule. A manifest `risk_class` lower than the max item class
  is itself a discrepancy.

## Golden-journey catalog

The catalog is durable and repo-level — not regenerated per candidate — stored
at [`release/golden-journeys.json`](../release/golden-journeys.json). Coverage
reconciliation (below) checks each candidate's feature-delta items against
this fixed catalog rather than inventing journeys per release.

```jsonc
{
  "schema_version": 1,
  "journeys": [
    {
      "id": "GJ-0001",                  // stable, sequential, zero-padded, never reused
      "status": "active",               // "active" | "retired" — retired journeys are kept, never deleted
      "priority": "P0",                 // P0 | P1 | P2, per FORNX-229's assurance-depth table
      "title": "...",
      "persona": "operator",            // who exercises this journey: operator | security_reviewer | end_user | ...
      "surfaces": ["daemon_socket"],    // 1+ values from the Shared surface vocabulary above
      "setup": "...",                   // preconditions to exercise the journey
      "expected_result": "...",         // the externally observable result that proves the journey works
      "evidence_requirements": ["..."]  // what artifact(s) prove this journey was actually exercised
    }
  ]
}
```

- **ID stability**: `GJ-<4-digit sequence>`, assigned once and never reused —
  even for a retired journey, so a stale coverage-reconciliation record or an
  old release's evidence trail always resolves to the same journey identity.
  Retiring a journey sets `status: "retired"`; it is never deleted from the
  file, so historical coverage reconciliation results for past releases remain
  interpretable.
- **P0/P1/P2** is the same tier vocabulary FORNX-229's assurance-depth table
  uses to decide which journeys a given risk class must cover (`PATCH_LOW_RISK`
  → touched P0 only, up through `MAJOR_OR_GA` → full P0/P1/P2 sweep across all
  surfaces). This document assigns the tier per journey; FORNX-229 states when
  each tier is pulled in.
- **Evidence contract**: `evidence_requirements` is intentionally concrete
  (log lines, exit codes, screenshots — never "manual verification" as a bare
  string) so a QA worker's sign-off (FORNX-232's schema) can be checked against
  it mechanically rather than trusted on narrative alone.
- The seed catalog in `release/golden-journeys.json` currently has four
  entries (`GJ-0001`–`GJ-0004`), grounded in the four binaries
  `docs/release-execute.md` already builds and checksums
  (`fornax`, `fornax-daemon`, `fornax-hook-claude`, `fornax-hook-codex`) plus
  one adversarial/fail-closed journey. This is a starting catalog, not a
  claim of exhaustive coverage — growing it is ordinary ongoing work, not a
  reason to reopen this ticket.

## QA coverage reconciliation

Per-candidate output, produced after feature-delta discovery, classifying
every feature-delta item's coverage:

```jsonc
{
  "version": "v0.0.1",
  "generated_at": "2026-09-01T00:00:00Z",
  "results": [
    {
      "feature_delta_id": "FD-v0.0.1-0001",
      "classification": "NOT_COVERED",
      // one of: COVERED | PARTIALLY_COVERED | STALE_COVERAGE | NOT_COVERED |
      //         DUPLICATE_EXISTING_COVERAGE | OUT_OF_CURRENT_RELEASE_QA_SCOPE
      "matched_journeys": ["GJ-0003"],   // golden-journey IDs whose surfaces overlap this item; [] if none matched
      "rationale": "GJ-0003 exercises the codex adapter happy path only; this item changes error-path forwarding, which GJ-0003 does not cover.",
      "remediation_jira_key": null       // required (non-null) when classification is NOT_COVERED — see below
    }
  ],
  "overall": "BLOCK"                     // PASS only if no result is NOT_COVERED without a disposition
}
```

- **Classification is mechanical, not a narrative summary**: `matched_journeys`
  is derived from the shared `surfaces` join (a feature-delta item's surfaces
  intersecting a golden journey's surfaces is necessary but not sufficient —
  `rationale` records the human/tool judgment on whether the match is actually
  adequate, which is why `PARTIALLY_COVERED` and `STALE_COVERAGE` exist as
  distinct outcomes from a bare "matched: yes/no").
- **Unknown ⇒ never `COVERED`**: an item with `surfaces: ["infra_config"]`
  from the unclassified fallback above, or an item matching zero journeys,
  must classify as `NOT_COVERED` at best — it is never permitted to default to
  `COVERED` or `OUT_OF_CURRENT_RELEASE_QA_SCOPE` merely because no journey was
  found. `OUT_OF_CURRENT_RELEASE_QA_SCOPE` requires an explicit, recorded
  scoping decision (a Jira reference), not the absence of a match.
- **`NOT_COVERED` carries a `remediation_jira_key`**: this is the machine-
  checkable form of "material uncovered behavior creates durable test/QA work
  before the release gate can pass" (FORNX-231 AC/scope). A `NOT_COVERED`
  result with `remediation_jira_key: null` is itself a schema violation for
  this artifact, not merely a policy nit — the artifact cannot represent
  "materially uncovered, no follow-up" as a valid state.
- **`overall`** is `PASS`/`BLOCK`/`INCONCLUSIVE`/`UNTESTED` per FORNX-229's
  verdict semantics — the worst constituent result. Any `NOT_COVERED` result
  without a `remediation_jira_key` (schema-invalid, but a reconciler must fail
  closed rather than crash) or any result the reconciler could not compute
  forces `overall` away from `PASS`, mirroring FORNX-229's "one BLOCK or
  UNTESTED-and-undispositioned check makes the whole gate non-PASS" rule.
- This artifact, plus the manifest's `risk_class` and the feature-delta list,
  is what FORNX-230's orchestration, FORNX-232's QA sign-off, and Security/
  Release Notes workflows all read — the explicit mechanism behind FORNX-231's
  "reusable ... without copy-paste drift" AC: one artifact set, several
  consumers, none of them re-deriving it.

## Validation

Docs- and schema-only change. `scripts/release-readiness.sh` is not modified.

```bash
jq . release/candidate-manifest.schema.json
jq . release/golden-journeys.json
jq . release/example-candidate-manifest.json
jq . release/v0.0.1-candidate-manifest.json
bats tests/release-readiness/release_readiness.bats   # unmodified suite, proves the risk_class addition is inert
git diff --stat -- scripts/                            # empty: no script touched
```

## AC-bullet to section map

| FORNX-231 AC bullet | Where it's addressed |
|---|---|
| Manifest is generated from real Git/Jira/artifact/runtime facts and records exact candidate lineage | Existing manifest fields (unchanged, `docs/release-readiness.md`) plus `risk_class` (Candidate manifest section) |
| A mismatch between Jira, PR lineage and candidate is detected instead of silently accepted | Feature-delta discovery, `discrepancies[]` |
| Feature-delta discovery catches capability/schema/config/UI changes that path-only mapping could miss | Feature-delta discovery, `sources`/`discovery_method`, Shared surface vocabulary |
| Golden journeys have stable IDs and explicit observable evidence contracts | Golden-journey catalog |
| Coverage reconciliation is machine-readable and blocks material `NOT_COVERED` release scope | QA coverage reconciliation |
| Unknown paths/capabilities are handled conservatively rather than ignored | Feature-delta discovery (unclassified fallback), QA coverage reconciliation ("Unknown ⇒ never `COVERED`") |
| Manifest/coverage outputs are reusable by QA, Security, Release and Release Notes workflows without copy-paste drift | QA coverage reconciliation (closing paragraph); Shared surface vocabulary (single join key) |
