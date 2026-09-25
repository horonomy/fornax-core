# Adversarial evidence threat model (FORNX-380)

Jira: [FORNX-380](https://lightning-dust-mite.atlassian.net/browse/FORNX-380)
("Adversarial Evidence Forge"), parent epic
[FORNX-376](https://lightning-dust-mite.atlassian.net/browse/FORNX-376)
(Stage 9, "Agent Epistemic Trust Kernel"). This document is narrower and
newer than [`docs/security/threat-model.md`](threat-model.md) (FORNX-233,
`threat_model_version: 2`) — that document is the durable, release-gated
catalog of this repo's ten trust boundaries and is out of scope for this
document to edit. This document instead treats the *evidence/claim data*
that flows through the FORNX-377 (Epistemic Contract schema)/FORNX-378
(Contract Satisfaction Engine)/FORNX-379 (Verification Budget) pipeline as
potentially adversarial and enumerates who can control what, and where
that content is (or is not) checked. The corresponding attack corpus is
[`crates/fornax-bench/src/adversarial.rs`](../../crates/fornax-bench/src/adversarial.rs)'s
`corpus()`.

## Attacker model

The attacker is the monitored coding agent itself (Claude Code, Codex,
opencode, or any future provider), or anything sitting between it and
Fornax's evidence store: a compromised or buggy adapter, a spoofed sensor
implementation, a replayed transport message, or — for the small surface
where claim/evidence text is read by anything text-aware — a judge prompt
the agent's own output can partially influence via prompt injection.

The attacker does **not** control: `fornax-verify`'s own code, the
`ContractRegistry`'s registered contracts (trusted, in-process Rust, never
deserialized from an untrusted source per FORNX-377/378's own Non-goals),
or wall-clock time (`staleness_of` is pure and clock-free, comparing two
already-stored timestamps — see `docs/security/threat-model.md`'s
`daemon_socket`/`adapter_provider_input` sections for the separate question
of whether the *daemon* itself can be attacked over its local transport,
which this document does not re-litigate).

## Attacker capability matrix

| Surface | What the attacker controls | What it cannot control |
|---|---|---|
| `Claim::text`, `Claim::subject` | Full content — this is literally the agent's own reported claim. | Whether `assess()`/`assess_claim` read it as anything other than an opaque label used only for logging/matching `subject` against a `ClaimClassId` — see "prompt injection" below. |
| Evidence payload content | Full content for any `EvidenceKind` the agent's own tool calls can produce (e.g. what a `ToolResult`/`TranscriptExcerpt` payload actually says). | The evidence's `kind` tag matching what a requirement declares, and (see below) its `TrustClass` label's declared value, though not necessarily that label's authenticity — see "forged provenance" below. |
| Evidence existence, for `TrustClass::AgentAdjacent` evidence | Whether such evidence exists at all — the agent's own provider integration reports it. | Nothing else; this is the attacker's strongest lever, and exactly why every representative contract's `Required` requirement pins `HostObserved`/`IndependentExternal`/`HumanReviewed`, never `AgentAdjacent`, as the acceptable trust class. |
| Timing of the agent's own actions | When it emits a claim or triggers evidence collection. | The daemon's own clock, or (per FORNX-377/378) whether a backwards-dated evidence row is treated as fresh — `staleness_of` rejects `observed_at` after `claimed_at` as `Indeterminate`, never `Fresh`, regardless of the requested timing. |
| Capability declaration | Whether its own adapter's `RuntimeCapabilities.probe()` correctly reports what it can observe. | Since FORNX-380's own AC4 fix (`assess_with_capabilities`), a requirement's `capability_prerequisites` are now cross-checked against the caller-supplied `available_capabilities`, not merely trusted from the evidence's mere existence. |
| Evidence *label* authenticity (`TrustClass::HostObserved`/`IndependentExternal`) | Nothing at the `fornax-verify` layer examined by this document — see "forged provenance," a disclosed, unresolved gap. | — |

## Failure classes and current disposition

Each class below names its corpus fixture(s)
(`crates/fornax-bench/src/adversarial.rs::corpus()`) and current
[`AttackOutcome`](../../crates/fornax-bench/src/adversarial.rs). `Escaped`
means the pipeline has no mechanism for this specific attack today — a
disclosed, real gap, not a defect this ticket claims to fix.

| Class | Fixture(s) | Outcome | Notes |
|---|---|---|---|
| Fake test success | `fornx380-03` | Prevented/Detected | Agent-only `ToolResult` with no `HostObserved` `ExitCode` cannot satisfy a `Required` requirement. |
| Test tampering (trust downgrade) | `fornx380-04` | Detected | A real `ExitCode` row labeled `AgentAdjacent` instead of `HostObserved` fails the trust-class bar. |
| Omitted failure | `fornx380-05` | Detected | No evidence submitted reads as `Unavailable`, never an implicit pass. |
| Stale/replayed evidence | `fornx380-cat-03` (pre-existing FORNX-378 test, cataloged) | Prevented | `FreshnessWindow::Perishable` magnitude check. |
| Same-source amplification | `fornx380-cat-02` (pre-existing FORNX-378 test, cataloged) | Prevented | `SourceFamilyMap`-based `MustBeIndependentOf` hardening. |
| Forged provenance (trust-class label authenticity) | `fornx380-11` | **Escaped** | Nothing at this layer cryptographically verifies a `TrustClass::HostObserved` label was actually assigned by the real sensor. Belongs to a sensor/transport-layer defense, out of `fornax-verify`'s scope — see `docs/security/threat-model.md`'s `adapter_provider_input`/`evidence_provenance` sections for the closest existing coverage of that boundary. |
| Capability/version spoofing | `fornx380-01`/`fornx380-02` | Escaped (plain `assess`) / Prevented (`assess_with_capabilities`) | This ticket's own AC4 finding and fix. |
| TOCTOU (evidence after claim) | `fornx380-06` | Prevented | `staleness_of` explicitly returns `Indeterminate` for a negative age — a real, deliberate ordering check, not incidental to the magnitude check (this document's own investigation initially assumed otherwise and was corrected against the actual code before merging). |
| Fake health endpoint | `fornx380-07` | Detected | `deployment_healthy` requires `IndependentExternal`; an `AgentAdjacent` self-report fails it. |
| Prompt injection in claim text | `fornx380-08` | Prevented | Requirement matching is structural (kind/trust/freshness/coverage) and never reads `Claim::text` as instructions. |
| Graph/resource abuse | `fornx380-12` (pre-existing FORNX-378 PR #181 finding, cataloged) | **Escaped** | `SourceFamilyMap::build`'s O(n² log n) transitive-ancestry pass, found during FORNX-378's own security review, not fixed there or here — recommend a follow-up ticket against `fornax-verify::independence` before this module sees production-scale evidence pools. |
| Receipt replay (cross-claim) | `fornx380-10` | **Escaped** | `assess()` is a pure per-call function with no cross-call ledger of which evidence has already been "spent" on a prior claim — a real gap that belongs to a store/daemon-level consumption ledger, out of `fornax-verify`'s scope. |
| Receipt replay (within one call) | `fornx380-cat-01` (pre-existing FORNX-378 test, cataloged) | Prevented | Duplicate `Evidence::id` deduplicated before evaluation. |
| VoI/cost manipulation | `fornx380-cat-04`, `fornx380-14` | Prevented | `promote_if_better`'s predeclared-threshold gate rejects a cheaper candidate that hides a critical miss. |
| Multi-agent coordinated poisoning | `fornx380-09` | Prevented | Shared `derived_from` ancestry across two sessions/trust classes is still recognized as one `SourceFamilyMap` family. |
| Benign hard negatives | `fornx380-16`–`fornx380-19`, `fornx380-21` | Detected (i.e., correctly NOT flagged) | Legitimate dual-source evidence, security-flavored-but-benign claim text, a genuinely capable adapter across all six representative contracts, and genuinely independent sources are all confirmed to pass cleanly — proving the hardening above does not over-flag. |

## What this document does not cover

- Prompt injection or judge-prompt manipulation at the semantic-judge layer
  (no such component exists yet in this repository as of Stage 9 — tracked
  separately if/when one ships).
- Fake health endpoints or receipt replay at the transport/socket level
  (see `docs/security/threat-model.md`'s `event_transport` and
  `judge_replay_execution` sections for that angle).
- Multi-agent coordination at the daemon/session level (this document only
  covers coordination visible through shared evidence ancestry within a
  single `assess()` call's evidence pool).

## Integration with the FORNX-344 regression lab

Per this ticket's scope, this corpus is wired into the existing
case-level regression comparison (`crates/fornax-bench/src/regression.rs`,
FORNX-344) using only static, local, synthetic fixtures — no live
corpus-watch capture (paused by founder directive since 2026-09-17,
resume-authorization required, out of scope for this ticket to touch). See
`crates/fornax-bench/src/adversarial.rs`'s
`a_regressed_attack_fixture_is_caught_by_the_existing_regression_lab` test
for the minimal, real wiring: an attack fixture's `PredictionRecord` is
compared baseline-vs-current through `regression::compare` exactly like any
other trajectory, so a future change that reintroduces a previously-fixed
attack (e.g. a regression in `assess_with_capabilities`) is caught by the
same mechanism that catches any other correctness regression — no parallel
"incident knowledge loop" infrastructure was built, this ticket reuses what
FORNX-344 already provides.

## Non-goals (inherited from the ticket)

No production offensive capability, malware development, or unrestricted
network attack framework — every fixture in the corpus is a pure,
in-process, read-only Rust test over synthetic in-memory data. No claim
that any `AttackOutcome` count here estimates a real-world attack base
rate.
