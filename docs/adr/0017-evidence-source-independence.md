# ADR 0017 — Evidence Source-Dependency Families: Real vs. Unexercised

**Status:** Accepted
**Ticket:** FORNX-347 · **Epic:** FORNX-340 (Stage 8 / Active Evidence Intelligence)
**Crate:** `fornax-verify` (`independence.rs`)

## Context

FORNX-347's own "Background" section states "FORNX-92 already provides
`correlation_group`, derivation lineage, freshness and trust classes" and
asks for a "source/dependency DAG across model-authored outputs,
tool-derived summaries, deterministic probes, external systems and derived
findings." That framing is structurally true but operationally misleading —
the same "ticket prose vs. reality" gap this session's other Stage-8 tickets
found.

## The real gap is not what the ticket implies

`EvidenceSource::correlation_group` has **zero real writers** anywhere in
this workspace — every shipped sensor calls `EvidenceSource::now(..)`, which
hardcodes `correlation_group: None`. `FusionRule::CorrelationCollapsed` and
`voi::Independence::SameSourceAsCounted` were consequently unreachable on
real traffic before this ticket (ADR 0015 already conceded this). The
*actual*, live, on-real-traffic common-source amplification runs through a
column nobody was reading for this purpose: `Evidence::source_event_id`, a
`NOT NULL` persisted column every sensor stamps. `fornax-adapter-claude`'s
`translate()` fans one `AgentEvent` out to multiple sensors — a Bash
`PostToolUse` on a `git commit` produces both `ClaudeBashExitCodeSensor` and
`ClaudeGitOutcomeSensor` evidence, both `TrustClass::AgentAdjacent`, both
reading the same `tool_response`, both stamped with the same
`source_event_id`. Fusion counted those as two independent supporting
votes. This is the real defect this ticket fixes.

The "5-category source DAG" the ticket describes maps almost entirely onto
`TrustClass`'s existing five variants — a flat tag, not a graph. The graph
structure genuinely missing was evidence→evidence, and its real edges are
`derived_from` (already present, one real writer: `judge.rs`) and
`source_event_id` (always present, never read for this purpose before now).

## Decision: read-side union-find, no new writer, no migration

`fornax_verify::independence::SourceFamilyMap` builds a union-find over one
evidence pool from three real relations: explicit `correlation_group`
(FORNX-92, honored when present), transitive `derived_from` ancestry (not
just one level — see `ancestors_of`), and same `source_event_id` on the
agent-reported channel only (`AgentAdjacent`/`ModelInternal`). Never
`HostObserved`/`IndependentExternal`/`HumanReviewed` — two independently
observing host sensors on the same event are genuinely distinct
observations (e.g. `ClaudeFileWriteConfirmedSensor`'s `std::fs::metadata`
check vs. `ClaudeGitWorkingTreeSensor`'s in-process git query on the same
Edit event), and collapsing them would under-count Fornax's most valuable
evidence — the unsafe direction. Evidence with no recorded `source` is
always its own singleton.

Read-side only, never persisted, no new column, no adapter change, no
migration — mirrors `EvidenceGraph`'s own "read-side aggregate" discipline.

## Additive unions: explicit metadata can never *prevent* a structural collapse

The North Star invariant ("correlated evidence must never be counted as
independent") cuts one way: unions only ever grow. An explicit
`correlation_group` can record that two records share a source, but
recording two *different* explicit groups on records that structurally
share the same real `source_event_id` does not un-share that event. Fusion
(`FusionRule::CommonSourceCollapsed`, R5b) implements this as a two-phase
process: phase 1 keeps R5's existing exact-`correlation_group` collapse
byte-identical; phase 2 applies the family map to *every* phase-1 survivor,
not just originally-ungrouped links, so a cross-explicit-group same-event
pair still collapses. This edge case was caught by a failing test during
development — the first implementation only checked originally-ungrouped
links and missed it.

## Collapse can only ever suppress corroboration-count inflation

`CommonSourceCollapsed` (like `CorrelationCollapsed` before it) always
keeps exactly one representative per `(relation, family)` bucket — `s` and
`c_count` (the supports/contradicts counts fusion decides on) never drop to
zero where they weren't already zero. This means collapse can demote
`Corroborated` to `Qualified`, but it can never flip `Verified` to anything
else, and it can never manufacture a contradiction. Pinned by a dedicated
test (`common_source_collapse_stays_qualified_never_corroborated`) and by
the `fornax-bench` regression fixture below.

## `Independence::PartiallyCorrelated` is now reachable

`voi::independence_of` previously had exactly two live outcomes
(`IndependentOfCounted`/`Unverified`) plus one fixture-only outcome
(`SameSourceAsCounted`, requiring an explicit group). `PartiallyCorrelated`
existed in the enum but no code path could ever return it. It is now
returned when a probe's trust class matches counted evidence spanning two
or more distinct source families — some of what fusion counted really is a
different source, but not all of it. `EvidenceGapKind::SingleSourceCorroboration`
is re-keyed the same way; since R5b already collapses same-family/
same-relation votes to one, it can now only fire in the narrow case where a
single family spans *both* relations (a source that both supports and
contradicts the claim) — real and interesting, but narrower than before
this ticket.

## "Evidence Explorer" maps to two real surfaces, not a UI

No web UI exists in this repository for evidence — `docs/`/the daemon
source contain no such thing. FORNX-90's "Evidence Explorer" is the name
for `GET /api/evidence-graph` plus `fornax evidence-graph`'s text renderer;
`/dashboard` is a small hardcoded HTML table of recent findings, unrelated.
AC6 ("Evidence Explorer exposes source-family/dependency rationale without
requiring graph-theory expertise") is scoped down honestly to exactly these
two surfaces: `api_evidence_graph` gains a `source_families` array
(claim-scoped, never leaking unrelated session families) and a
`source_family` index per link; `render_evidence_graph` gains a plain-prose
section ("family N — K records, counted as ONE source: same agent turn
(event ...)") with zero graph/union-find vocabulary, shown only when at
least one family genuinely groups more than one record. Inventing a real
graphical UI would be new, unscoped work — not attempted here.

## Version bumps

`BaselineFusionPolicy::policy_version()` 1→2 (covers both the transitive-R3
widening and R5b together — one bump, not two). `DeterministicVoiPolicy::policy_version()`
1→2 (covers both the family-based `independence_of` rewrite and the
re-keyed `SingleSourceCorroboration`). Two real call sites that assert
against the live version number were updated
(`fornax-replay`'s drift test, `fornax-bench`'s manifest identity test);
several other `fusion_policy_version: 1`/`fusion_policy_version: 2`
literals elsewhere in the workspace are hand-built test fixtures unrelated
to the real policy and were correctly left untouched.

## Cannot be verified without further work

1. **The `derived_from` transitive-closure widening is correct but
   currently unexercised on real traffic.** Only `judge.rs` writes
   `derived_from`, and that evidence (`/api/judge`'s response) is never
   persisted or linked to a claim today — same caveat class as ADR 0015's
   gap #1. The `(source_event_id, agent-channel)` union, by contrast, *is*
   live today, confirmed against three real adapter sensors on one event.
2. **Grouping `ModelInternal` into the agent channel is forward-looking,
   not yet exercised.** Judge evidence is stamped with `claim.source_event_id`
   (the claim-producing event, e.g. `SessionEnd`) — not the `PostToolUse`
   event behind the tool-adjacent evidence it might otherwise correlate
   with — so rule 3 never actually unions judge output with tool evidence
   today. Justified as forward-looking for a future reasoning-summary
   sensor, not claimed as a currently-live path.
3. **Anything resting on `correlation_group` alone stays dead**, including
   `UncertaintyBand::Corroborated` itself — this module *reads* the
   explicit field when present but must never depend on it being present.
4. **`SingleSourceCorroboration`'s new narrow trigger has no real-traffic
   confirmation.** It requires one family spanning both relations, which no
   fixture beyond this ADR's own test currently exercises against captured
   data.
5. **Not attempted, and explicitly out of scope by the ticket's own AC3
   wording:** a *configurable* unknown-dependency policy. This repo's
   equivalent knob is a versioned `FusionPolicy`/`VoiPolicy` implementation,
   not a config field — "conservative" is met (unknown provenance is always
   a singleton, never independence), "configurable" is a deliberate scope
   decision, not a gap.
6. **Statistically calibrated independence is not attempted**, per the
   ticket's own explicit prohibition — no numeric score is serialized
   anywhere in this module; `UtilityEstimate`'s ordinal-not-probability
   discipline (ADR 0015) is preserved unchanged.

**Out of scope, tracked as real follow-up work, not silently dropped:**
stamping `correlation_group` at the adapters on the persisted ingest path
(FORNX-92's own unfinished half — five-plus call sites across three adapter
crates); persisting/linking judge evidence into the graph (would make gap
#1 above live); a real Evidence Explorer UI (FORNX-90's unfinished half).

## Escalation

None. This is read-side derivation over columns already persisted: no
migration, no new writer, no new dependency, no side effect, no
irreversible action. The one change that *would* warrant an owner decision
— altering the adapters to stamp `correlation_group` on the persisted
ingest path — is deliberately excluded from this ticket's scope, and that
exclusion is precisely what keeps this a routine engineering change.

## Verification

10 unit tests in `independence.rs` cover the load-bearing safety property
(two `HostObserved` records on the same event never collapse), transitive
ancestry through an unlinked intermediate, cycle safety, the
unknown-provenance singleton, and the additive-union invariant. 5 new
`fusion.rs` tests cover the live real-traffic collapse shape, the
`HostObserved`-sibling safety property at the fusion level, the
verdict-never-flips invariant, and the cross-explicit-group same-event edge
case found during development. 2 new `voi.rs` tests cover
`PartiallyCorrelated` reachability and the narrowed
`SingleSourceCorroboration` trigger. A real end-to-end daemon test against a
seeded store confirms `GET /api/evidence-graph` surfaces a genuine
common-source family from two real sensor-shaped evidence rows. A
`fornax-bench` fixture, run through the real `run_harness` pipeline (not
mocked), proves the naive per-group-counting reading (3 distinct groups →
`Corroborated` → `Proceed`) never happens once `source_event_id`-based
collapse is applied — the actual, concrete false-uplift prevention this
ticket's AC5 asks for.
