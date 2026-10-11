# FORNX-380 adversarial corpus: live-ingress status (FORNX-433 AC2)

**Status:** living doc, honest-by-construction. FORNX-433 AC2 requires "all
historical escape cases run against live ingress, known remaining escapes
disclosed." This doc is that disclosure — it maps every fixture in
`fornax_bench::adversarial::corpus()` to its status against the **real live
daemon** (UDS ingest, real `fornax-verify` verifiers, real persisted
`Finding`), not just its original `fornax-verify::assess()` pure-function
result.

## Why these are two different layers

`corpus()`'s fixtures were authored and are still asserted against
`fornax-verify`'s `contract_satisfaction::assess()` — a pure function over
directly-constructed `Evidence`/`Claim` structs, with no daemon, no UDS
socket, no admission guard in front of it. That is deliberate (it is the
fastest, most precise way to pin the contract-satisfaction logic itself),
but it means a fixture's `known_outcome` describes what `assess()` alone
does, not what happens when the same attack shape is submitted through the
real ingestion path a live session actually uses — which, since FORNX-431/
FORNX-441, includes a provenance/admission guard this layer never sees at
all.

## Status, by fixture

| Fixture | Corpus `known_outcome` | Live-ingress status |
|---|---|---|
| `fornx380-cat-01..04` (pre-existing FORNX-377/378/379) | Prevented | **Not applicable to live replay** — these exercise `fornax-verify`'s internal contract-satisfaction/independence/budget machinery directly (duplicate evidence rows, source-family amplification, staleness, promotion-gate cost gaming); none of them has a hook-payload shape to submit over UDS, they are about computation over an already-assembled evidence pool, not about what ingestion accepts. |
| `fornx380-01-capability-spoofing-plain-assess` | **Escaped** (by design — the "before" half of a before/after pair) | Not a live-ingress question at all: this fixture exists specifically to demonstrate what *plain* `assess()` (no capability awareness) misses; fixture 02 is its closure. Neither has a live-ingestion shape (capability-prerequisite checking is a pure contract-satisfaction concern). |
| `fornx380-02-capability-spoofing-hardened` | Prevented | Not applicable (same reason as 01). |
| `fornx380-03..09`, `12..22` | Prevented / Detected / Inconclusive | Not applicable — each exercises a pure-function concern (trust-class checking, staleness ordering, graph independence, budget bounding, harness-crash handling, VoI cost gaming, determinism, hard negatives, taxonomy/provenance meta-proofs) with no corresponding "submit this over the real UDS ingest path" shape. Submitting the equivalent *evidence content* through the live daemon is exactly what `provenance_enforcement.rs`'s own fixtures already do (see below) — these corpus entries are the right place to pin the contract-satisfaction logic, not to also re-prove ingestion. |
| `fornx380-10-receipt-replay-cross-claim` | **Escaped** (documented at the time as "a real, disclosed gap... would belong to a store/daemon-level consumption ledger, not fornax-verify") | **Closed at the live-daemon layer**, exactly as that fixture's own description anticipated. FORNX-431/441 added a durable `evidence_consumption` ledger (`Store::record_consumption`) and `admit_evidence_rows`'s replay-exclusion check (`fornax_types::provenance_guard::ClaimReplayScope`). Proven live, end-to-end, against the real daemon: `fornax-daemon/tests/provenance_enforcement.rs::cross_anchor_replay_is_downgraded_not_verified` (cross-anchor reuse of already-consumed evidence downgrades to `Review`, never re-`Verified`) and `::same_anchor_related_claims_both_reach_verified_without_downgrade` (the companion positive control proving legitimately related same-anchor claims are *not* wrongly penalized). `fornax-verify::assess()` itself still has no ledger — that remains correctly out of its scope, per the fixture's own original note — the fix lives at the daemon/store layer that actually has cross-call state. |
| `fornx380-11-forged-trust-class-label` | **Escaped** (documented at the time as "the actual defense is at the sensor/socket layer, out of this crate's scope") | **Closed at the live-daemon layer**, exactly as anticipated. FORNX-441's `CollectorAuthority`/`authorize_evidence_source` (`fornax_types::provenance_guard`) is precisely that sensor/socket-layer defense. Proven: a unit test directly in `provenance_guard`'s own test module (`fornx380_11_forged_host_observed_label_from_an_agent_only_sensor_is_quarantined`), **and**, against the real live daemon over its real UDS socket, `provenance_enforcement.rs::forged_host_observed_label_never_reaches_verified`, **and** (FORNX-433 AC2, this doc's own occasion) `provenance_enforcement.rs::admit_evidence_rows_rejects_every_fixture_that_would_have_verified_without_it`, which additionally proves the guard is load-bearing specifically at `admit_evidence_rows` — the exact call site the live daemon's `run_verifiers_and_persist_findings` uses — by showing the same forged evidence would reach `Verified` if admission were bypassed entirely. |

## Genuine remaining escapes, disclosed

**None**, as of this doc's writing (FORNX-433 AC2). Both corpus entries
originally marked `Escaped` (`fornx380-10`, `fornx380-11`) are now closed at
the layer each fixture's own description said the real fix belonged —
confirmed by direct test, not by assumption. `fornx380-01` was never a
"remaining" escape; it is the deliberate "before" half of an already-closed
before/after pair.

This does **not** mean the system has zero gaps — it means this specific,
frozen, versioned corpus (FORNX-380, `current_versions()` pinned to a named
commit/environment) has no currently-known escape left unaddressed. A new
attack shape not in this corpus could still exist; this doc only speaks to
what the corpus already covers. If a future fixture is added with
`AttackOutcome::Escaped`, it must be added here too, in the same table, with
the same honesty, not silently left only in `fornax-bench`.
