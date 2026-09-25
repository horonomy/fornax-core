# Bounded model-checking scope (FORNX-383)

Jira: [FORNX-383](https://lightning-dust-mite.atlassian.net/browse/FORNX-383)
("Trust-Kernel Formal Methods"). Parent epic FORNX-376 (Stage 9). Depends on
FORNX-382's invariant registry (`fornax_bench::self_integrity::registry()`).

## What this is not

**Fornax is not formally verified.** This ticket applies bounded model
checking to exactly two narrow, hand-picked functions in the trust kernel —
not the daemon, not the store, not the network/adapter boundary, not the
distributed protocol between `fornax-core` and `fornax-cloud`. Any release
note, README, or marketing copy that generalizes "two functions are
Kani-checked" into "Fornax is formally verified" is wrong and must be
corrected. See Non-goals below.

## Tool selection — investigated against real code, not adopted ceremonially

Jira's AC1 requires justifying tool choice "against actual code" and
explicitly warns against "a ceremonial formal-method layer." Before writing
any proof, this ticket read the actual implementation of every candidate
target area named in FORNX-383's scope: `crates/fornax-store/src/acquisition.rs`,
`crates/fornax-acquire/src/gate.rs`, `crates/fornax-types/src/receipt.rs`
and `crates/fornax-types/src/policy/bundle.rs` (receipt/delegation
freshness), `crates/fornax-store/src/audit_checkpoint.rs`, and
`crates/fornax-verify/src/voi.rs`.

**TLA+/PlusCal was not adopted.** It is the right tool for genuinely
distributed, multi-process protocol reasoning. Fornax's actual architecture
(ADR-0001) is a single local daemon process with coarse-grained
`Arc<Mutex<_>>`/`Arc<RwLock<_>>` state — FORNX-382 already investigated and
rejected Loom for exactly this reason ("the mutex already serializes every
access, so there is no finer-grained legal interleaving for Loom to usefully
explore"). Writing a separate TLA+ spec of a single-process function would
duplicate logic in a second language that inevitably drifts from the real
implementation — the definition of ceremonial adoption AC1 warns against.

**Kani was adopted** for exactly the reason TLA+ was rejected: it
model-checks the *actual Rust function* under bounded symbolic inputs, with
no separate spec to keep in sync. `cargo-kani` was installed and `cargo kani
setup` completed successfully in this environment (~6 minutes, one-time
toolchain download) — a real, empirically-confirmed feasibility check, not
an assumption.

## What was modeled and checked

### Target 1: acquisition-authorization state machine (`fornax-acquire::gate`)

`classify_for_execution` (`crates/fornax-acquire/src/gate.rs`) is the
`AUTO_SAFE` / approval-required / forbidden state machine named explicitly
in FORNX-383's candidate list. Its entire decision surface is 4 closed
`SideEffectClass` variants × independent grant/deny in both the spec's own
allow-list and the host policy — 256 concrete cases.

Two Kani proof harnesses were written in `#[cfg(kani)] mod kani_proofs`
inside that file:

- `proof_filesystem_write_is_never_available` — the always-forbidden safety
  rule holds across every combination, not just the one case the existing
  example test covers.
- `proof_available_implies_policy_grants_every_required_class` — soundness:
  `Available` is never returned unless the *current* policy genuinely grants
  every required class (the staleness bug this module exists to prevent).
- `proof_naive_gate_is_exploitable_seeded_counterexample` — AC3 vacuity
  check: a deliberately weakened stand-in that skips the policy re-check
  provably lets a denied side effect through, proving the real function's
  check is load-bearing.

**Status: written, compiles under `cargo kani`, not empirically verified to
pass.** Running `cargo kani --harness proof_filesystem_write_is_never_available`
against the real code hit **CBMC out-of-memory** after ~10 minutes at >9 GB
RSS (confirmed via `ps`, not merely slow). Root cause, isolated by
investigation: `SideEffectAllowList::new`/`GlobalExperimentPolicy::new` both
canonicalize their contents via `Vec::sort()` + `dedup()` — correct,
sensible production code (ADR-invariant: "two allow-lists built from the
same set, in any order, compare equal"), but Rust's generic
pattern-defeating sort implementation has enough internal branching that
CBMC's symbolic execution of it, combined across two independently-symbolic
4-element inputs, exhausts memory before reaching a verdict. This is a real,
disproportionate tool/library friction, not a proof design error — the
underlying state space is 256 cases, objectively tiny; the cost is entirely
an artifact of modeling a generic sort algorithm symbolically.

This is exactly the class of finding AC1 anticipates ("if setup friction is
disproportionate to the value... report honestly" — this ticket's own
authoring brief). The harnesses are preserved as correct, reviewable
documentation of the intended property and are compileable proof of intent;
a follow-up (not in this ticket's scope) could resolve this by adding a
`cfg(kani)`-only sort-free construction path for these two types, or by
reducing the harness to test one side symbolically against a small
enumerated set of concrete literals for the other — both were considered
but not pursued further given this ticket's own scope boundaries and the
"retained scope depends on value" framing Jira gives this ticket.

### Target 2: receipt/delegation freshness (`fornax-types::policy::bundle`)

`key_temporal_status` (extracted from `verify_signed_envelope` in this
ticket — see the commit `♻️ types: Extract pure key-temporal-window check
for Kani proof`, behavior-preserving, all 3 pre-existing key-window tests
pass unmodified) is the trusted-key `not_before`/`not_after` validity-window
decision — the receipt/delegation-freshness target from FORNX-383's
candidate list.

Its comparison core, `key_temporal_status_from_parsed`, takes already-parsed
`DateTime<Utc>` values rather than `&str` — deliberately, to route the proof
around `chrono`'s RFC 3339 parser, which hit the *same class* of CBMC
friction as `Vec::sort` on the first attempt (a generic character-scanning
loop CBMC could not bound automatically; confirmed via the same
unwinding-loop diagnostic pattern before this extraction). Parsing itself is
not an invariant this ticket targets; the comparison logic is.

Four Kani proof harnesses, all **verified and passing**
(`cargo kani --harness <name>`, each completing in well under a minute):

- `proof_not_yet_valid_implies_now_before_not_before`
- `proof_retired_implies_now_after_not_after`
- `proof_valid_iff_within_window` — the full correctness characterization:
  `Valid` holds if and only if `now` is within `[not_before, not_after]`.
- `proof_naive_status_is_exploitable_seeded_counterexample` — AC3 vacuity
  check: a deliberately weakened reimplementation that skips the
  `not_after` check provably reports `Valid` for a retired key, proving the
  property-checking technique itself is capable of catching a real removed
  safety control.

No new production bug was found in `key_temporal_status` itself — all
proofs pass against the real, unmodified comparison logic. AC4 ("any real
counterexample is fixed and pinned") is accordingly not exercised in this
target: there was nothing to fix.

## Model assumptions and excluded behaviors (AC5)

- Both targets are pure, single-threaded, allocation-free (beyond the
  `String`s `key_temporal_status`'s outer wrapper still parses — the proved
  core takes already-parsed values) functions. Neither target's proof says
  anything about concurrent access, I/O, or the daemon's process boundary —
  FORNX-382's concurrency stress test (a different technique, real `tokio`
  tasks against the actual `Arc<Mutex<_>>` primitive) is the tool used for
  that concern, not Kani.
- `bounded_datetime()` (both files) restricts the symbolic timestamp
  neighborhood to ±1000 seconds around a fixed epoch — chosen to keep CBMC's
  state space small and dense around the interesting boundary cases, not
  because the real system only ever sees timestamps in that range. This is
  a genuine boundedness limitation of bounded model checking generally, not
  specific to this proof.
- `parse_rfc3339_plain` itself (the actual string-parsing logic) is **not**
  covered by either proof — see "Target 2" above. Its existing example-based
  test coverage (`policy::tests::t39`/`t40`/`t53` and others) is unchanged
  and remains the coverage for that boundary.
- The acquisition-gate proof's two safety/soundness properties are **not**
  currently machine-verified — see Target 1's honest status above. Treat
  them as documented intent, not as evidence.

## Recommended CI wiring (AC6 — documented, not applied)

Per this repository's CI-change review boundary (pipeline definition edits
require human review, independent of ordinary engineering autonomy — see
`docs/security/self-integrity-ci-wiring.md` for the identical boundary
FORNX-382 already documented), `.github/workflows/*` is **not** modified by
this ticket. Recommended wiring for whoever applies it:

```yaml
# New job, NOT part of the required `rust` check:
kani-verify:
  if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
  steps:
    - run: cargo install --locked kani-verifier
    - run: cargo kani setup
    - run: cd crates/fornax-types && cargo kani --harness proof_valid_iff_within_window
    - run: cd crates/fornax-types && cargo kani --harness proof_not_yet_valid_implies_now_before_not_before
    - run: cd crates/fornax-types && cargo kani --harness proof_retired_implies_now_after_not_after
    - run: cd crates/fornax-types && cargo kani --harness proof_naive_status_is_exploitable_seeded_counterexample
    # gate.rs harnesses omitted from CI until the Vec::sort OOM finding
    # above is resolved by a follow-up ticket.
```

Scheduled/manual trigger only — never part of the fast atomic-commit path
(`rust` required check), matching FORNX-382's own AC6 precedent and this
ticket's finding that even the passing harnesses take real wall-clock time
(tens of seconds each) unsuitable for per-PR blocking.

## Acceptance criteria — honest status

1. ✅ Tool/target selection justified against actual code (Loom rejected by
   FORNX-382 precedent + re-confirmed here; TLA+ rejected as mismatched to a
   single-process coarse-lock architecture; Kani adopted and empirically
   feasibility-checked before any proof was written).
2. ⚠️ **Partial.** At least two critical invariants are checked with
   versioned models: `key_temporal_status`'s three properties (not-yet-valid
   correctness, retired correctness, full valid-iff-window characterization)
   are genuinely modeled, versioned by this commit, and machine-verified.
   The acquisition-gate's two properties are modeled and written but **not**
   machine-verified (CBMC OOM) — a real, disclosed gap, not fabricated.
3. ✅ At least one deliberately weakened path yields a counterexample,
   proving the check is not vacuous — `proof_naive_status_is_exploitable_seeded_counterexample`
   (verified, passing) and `proof_naive_gate_is_exploitable_seeded_counterexample`
   (written, same CBMC-resource caveat as its sibling proofs in that file).
4. N/A (no real counterexample was found against production code in this
   pass — nothing to fix). Not fabricated as satisfied.
5. ✅ Model assumptions, boundedness, and excluded behaviors published above,
   including the honest limitation of the acquisition-gate target.
6. ✅ This document exists specifically to prevent that broadening — see
   "What this is not" at the top.
