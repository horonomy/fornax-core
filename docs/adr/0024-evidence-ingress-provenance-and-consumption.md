# 0024 — Evidence ingress provenance and consumption enforcement (FORNX-431)

Status: Accepted. Stage 7A (FORNX-146), parent epic FORNX-376.

## Context

FORNX-381 (v0.0.8) built `provenance_guard`'s pure types — `CollectorAuthority`,
`bind_evidence_to_session`, `authorize_evidence_source`, an in-memory
`EvidenceConsumptionLedger` — and `assess_with_provenance_guard`, a guarded
wrapper around `contract_satisfaction::assess`. None of it had a production
caller. Worse than the ticket's own framing: the five live `Verifier`s
(`TestResultVerifier`, `CommandExecutedVerifier`, `CommandSuccessVerifier`,
`FileModifiedVerifier`, `GitOperationVerifier`) never read `source` or
`trust_class` at all. Collector identity on the real daemon request path was
100% payload-controlled — `sensor_name`, `trust_class`, `session_id`, and
`provider` were all set by whoever sent the UDS message, with nothing
checking any of it before a verdict got computed and persisted.

## What this closes

Four slices, landed as four separate PRs:

1. **Types** (`fornax-types::provenance_guard`): `EvidenceOrigin`
   (`UdsIngest`/`DaemonAcquisition`/`PrivilegedExecutor`/`Unknown`) —
   server-stamped only, never a field the wire `Evidence` type exposes.
   `SessionOwner` (`Unknown`/`Single`/`Ambiguous`), `admission_decision`.
   `ClaimAnchor` (`session_id` + `claim.source_event_id`) and
   `classify_consumption_by_anchor` for related-claim reuse.
2. **Persistence** (`fornax-store::evidence_consumption`): migration 0019 —
   `evidence.ingress_origin` (nullable), `evidence_consumption` table
   (`UNIQUE(evidence_id, claim_id)`). `evidence_origin`, `session_owner`,
   `record_consumption`.
3. **Daemon wiring**: `insert_evidence_with_origin` stamps real origin at
   the three write paths (UDS ingest → `UdsIngest`, `/api/acquire-evidence`
   → `DaemonAcquisition`, `fornax-acquire-exec` → `PrivilegedExecutor`).
   `insert_claim_idempotent` makes a resubmitted claim a no-op, not a
   spurious `ingest_quarantine` entry.
4. **Enforcement** (this slice): `run_verifiers_and_persist_findings` — the
   one real choke point every live verdict passes through (Claim ingest,
   `/api/acquire-evidence`, `/api/reverify`) — now filters evidence through
   `admission_decision` before any verifier sees it, and checks
   `record_consumption` against the claim's anchor before persisting a
   `Verified` finding. A cross-anchor replay downgrades the verdict to
   `Review`; a same-anchor (legitimately related) reuse does not.

## What's actually enforced now

- A forged `HostObserved` label on a sensor only ever authorized for
  `AgentAdjacent` is quarantined, not verified.
- An unregistered sensor name is quarantined.
- Evidence shaped like an acquisition result (no `source`) injected over
  UDS is quarantined — `UdsIngest` requires a vouched-for source;
  `DaemonAcquisition`/`PrivilegedExecutor` origins are the only paths a
  missing `source` is expected.
- Evidence claiming a provider that contradicts the session's actually
  announced owner is quarantined.
- A claim from a genuinely different turn (`source_event_id`) citing
  evidence already consumed by an earlier claim is downgraded to `Review`,
  never `Verified`.
- Every quarantine/replay rejection is durably recorded in
  `evidence_consumption` (queryable), never only logged.

Proven with real daemon-process integration tests
(`crates/fornax-daemon/tests/provenance_enforcement.rs`) over the real UDS
path, plus a fixture-potency check (each negative fixture verified
successfully when run directly through the raw `Verifier`, bypassing
admission — proving the guard is doing something) and a source-scan test
asserting exactly one production call site to `insert_finding` exists in
`fornax-daemon`.

## Real-world cost: the anchor rule

`fornax-adapter-claude` emits one `test_result`-class claim per `Stop`
event (`collect_claude_bash_exit_code`'s caller in `lib.rs`), bound to that
turn's own `source_event_id`. Before this change, re-asserting "tests
still pass" in a later turn — without actually re-running the test command
— could still verify against the earlier turn's exit-code evidence
(whatever was last observed). After this change, that pattern downgrades
to `Review`: the later claim's anchor differs from the evidence's original
consumer, so it's treated as the cross-claim replay case FORNX-380 fixture
10 names, not a legitimate restatement. **This is deliberate, not a
regression** — an agent claiming a fact is true without re-checking it is
exactly the gap AC1 exists to close — but it is a real, user-visible
behavior change worth stating plainly rather than discovering by surprise.
An agent that wants a later claim verified needs to re-run the command and
produce fresh evidence for that turn.

## Residual risks, stated plainly (not hidden)

- **Same-user UDS impersonation of a registered sensor remains possible.**
  Any process running as the same OS user as the daemon can open a
  connection to the UDS socket and send a message claiming to be
  `claude_bash_exit_code_sensor_v1`. This guard authenticates *what a
  message claims about itself* against a known-sensor allowlist and the
  session's announced provider — it does not authenticate *which process*
  sent the message. Closing that gap needs real runtime attribution
  (HORO-1599/HORO-1601), explicitly out of this ticket's scope per its own
  dependency note.
- **Direct SQLite file writes bypass this entirely.** `ingress_origin` is
  stamped by `fornax-store`'s insert functions, not by a database-level
  constraint. A process with direct filesystem access to `fornax.db` can
  write a row with any `ingress_origin` value it likes. This guard defends
  the ingest *protocol*, not the filesystem.
- **`source_event_id` is payload-controlled.** The anchor rule guards
  against an honest adapter re-asserting a claim without fresh evidence —
  it does not stop a genuine forger from minting entirely fresh evidence
  under a fabricated event id. Content-replay detection (a new evidence id
  with suspiciously duplicated content) was deliberately left out of
  scope: a forger can simply mint fresh evidence, so this wouldn't close
  the actual threat it might appear to address.
- **Two or more providers announcing on one session forces every
  provider-claiming evidence row to quarantine** (`SessionOwner::Ambiguous`
  always fails the provider-match check). This fails closed, correctly,
  but means any same-user process can force a victim session toward
  `Unverified`/`Review` by sending a second, conflicting capability
  announcement. It cannot promote anything to `Verified`, which is the
  invariant that actually matters.

## FORNX-441 follow-up: one canonical read, not one choke point

Slice 4 above enforced admission at `run_verifiers_and_persist_findings` —
genuinely the one real *verdict-persisting* choke point, but not the only
place a session's evidence pool reached a security-relevant consumer. An
independent review (2026-10) found that `/api/fusion`, `/api/decision`,
`/api/judge`, `/api/evidence-plan`, `/api/acquire-evidence`'s own input,
`/api/reverify`'s fused_before/after, `/api/contract`, `/api/evidence-graph`,
`fornax receipt issue`, `fornax corpus mine`, and `fornax`'s cloud
export-spool all called `Store::evidence_for_session`/`evidence_graph_for_claim`
directly — raw, unfiltered reads with zero admission check. A forged
`HostObserved` label, an unregistered sensor, or cross-session evidence
reached contract satisfaction, fusion-derived endpoints, a signed receipt,
or a cloud-bound export with no provenance check ever having run on it.

A first attempted fix (`fornax_verify::contract_satisfaction::assess_with_provenance_guard`,
landed for `/api/contract` alone) was itself wrong: it had no concept of
`EvidenceOrigin`, so it would incorrectly reject legitimate
`DaemonAcquisition`/`PrivilegedExecutor` evidence (no `source` by design),
and its own regression test inserted evidence via plain `insert_evidence`
(reads back `Unknown` origin), so it never actually exercised the
sensor-authorization check it claimed to prove. It was deleted entirely,
along with `ProvenanceGuardViolation`.

**The fix**: one pure function, `fornax_types::provenance_guard::admit_evidence_rows`,
composing — in order — session binding (AC2), `admission_decision` (origin +
sensor trust), and an optional cross-claim replay exclusion. One I/O module,
`fornax_store::admitted_evidence`, wraps it in two read-only methods:

- `Store::admitted_evidence_for_session` — session-scoped, no replay
  exclusion (no single claim to scope it to). Used by
  `run_verifiers_and_persist_findings` (replay stays handled exactly as
  slice 4 left it — a separate, later `record_consumption` write, not
  folded into this read), `/api/evidence-graph`'s family/independence
  build, `fornax corpus mine`, cloud export-spool, and `fornax timeline`.
- `Store::admitted_evidence_for_claim` — claim-scoped, replay-exclusion
  applied. Used by `compute_fusion` (the shared logic behind fusion,
  decision, judge, evidence-plan, acquire-evidence's input, and reverify's
  before/after) and `fornax receipt issue`.

Neither method writes anything — no `record_consumption`, no
`record_admission_quarantine` — so a read can never steal evidence
ownership from whichever claim should legitimately consume it; the live
verdict path (`run_verifiers_and_persist_findings`) remains the only
writer of both.

**Not every consumer treats a rejection the same way**, deliberately:

- Verdict-bearing consumers (fusion family, contract, receipt, corpus,
  ingest) exclude the rejected row from what they compute over, and
  surface it as `provenance_rejected`/`provenance_violations` rather than
  silently shrinking a count.
- `fornax timeline` is a forensic display, not a verdict computation — a
  rejected row stays visible, annotated `[QUARANTINED: reason]`, because
  silently filtering it would render identically to "NOT FOUND" and
  mislead an operator into thinking the row never existed.
- `/api/evidence-graph`'s `links` keeps every persisted link but annotates
  each one `provenance_rejected: true/false`, for the same reason.

Proven by a dedicated adversarial matrix (`fornx441_matrix_*` in
`fornax-daemon/src/main.rs`): one legitimate control row plus one forged
row, both linked to the same claim, run through every rewired consumer.
Each matrix test was confirmed load-bearing by hand-reverting its specific
call site to the old raw read and observing the test fail, then restoring.

### Additional residual risks from this follow-up

- **Session-scoped reads intentionally skip cross-claim replay exclusion.**
  `admitted_evidence_for_session` (evidence-graph's family map, corpus
  mining, export-spool, timeline) has no single claim to scope replay
  exclusion to, so evidence already consumed by one claim can still appear
  in another claim's family/export/timeline view via this path. This is
  the correct tradeoff for those consumers (a family map spanning the
  whole session needs the whole session's admitted pool) but means replay
  protection is real only at the points that actually persist a verdict
  (`run_verifiers_and_persist_findings`) or scope to one claim
  (`compute_fusion`, receipt issuance) — not a blanket property of every
  read in this module.
- **Export-spool checks admission per-session, not per-claim.** A row
  rejected for one claim's replay scope is not excluded from the spool if
  it was legitimately admitted at the session level — the cloud sync
  boundary cares about origin/sensor trust, not per-claim replay.
- **Already-mined corpus candidate documents predating this fix are not
  retroactively cleaned.** `fornax corpus mine` now reads the admitted
  pool, but any `corpus_candidate` row written before this fix was baked
  from the old raw read and is not re-mined automatically.

## Explicitly out of scope (AC5)

No second collector registry was introduced — `CollectorAuthority` remains
the only allowlist. Session ownership comes from the existing
`runtime_capabilities` table, no new session-identity table. No provider
was ever guessed from a sensor-name prefix or any other heuristic. No
executable adapter installation changed. `fornax-acquire-exec`'s origin
stamp is a one-line addition (`PrivilegedExecutor`), not a new trust
authority.
