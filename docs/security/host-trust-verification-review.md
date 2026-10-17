# FORNX-450 security review: Codex host_trust verification against a real `~/.codex`

Status: **complete** — run twice (once aborted by a since-fixed
review-script bug, once completed cleanly). One trigger condition fired
(`sessions/*`) and was resolved by an explicit, narrowly-scoped founder
disposition for this one run only — see "Founder disposition" below. See
`docs/adr/0026-codex-host-trust-verification.md` for the full design this
reviews, and `exec/fornax-host-trust-exec/review/real_home_review.py` for
the evidence-gathering script this review is based on.

This review authorizes nothing beyond this one run. ADR-0026 is flipped to
`Accepted` on the strength of this record. The evidence file is gitignored
by design (`docs/security/evidence/*.json`) and is never committed; this
document instead records its path and SHA-256 as the durable, committed
reference:

- **Evidence file:** `docs/security/evidence/fornx-450-host-trust-real-home-2026-10-17.json`
- **Evidence file SHA-256:** `964088d5d57c162eeff15545336ae70d55c8793ee998c3c0b7208c56b3300ebb`

### What this review does and does not establish

This real-`~/.codex` review (R3) verifies **process safety under real
conditions**: no credential exposure, no unowned-process signaling, no
persistent config/`installation_id`/`auth.json` mutation, fail-closed
structural validation, bounded latency. It does **not** re-verify
**host_trust resolution correctness** (the positive "a genuinely trusted
hook reports `trusted`" case) — this operator's real `~/.codex` has no
Fornax hooks installed (`fornax_hooks_not_installed` on all 21 runs), and
installing real hooks to exercise that path here would itself be the kind
of persistent config change R3's authorization explicitly excludes.
Trust-resolution correctness, including the positive trusted case, is
proven separately and already merged: `reconcile`'s
`full_match_all_trusted_is_trusted` unit test
(`exec/fornax-host-trust-exec/src/verdict.rs`) and the sandboxed
fake-binary e2e matrix (`exec/fornax-host-trust-exec/tests/verify_codex_e2e.rs`).
These two review layers are deliberately separate and this document
speaks only to the first.

## How to run the review

```
fornax-host-trust-exec verify-codex --json   # sanity-check it resolves and runs at all
python3 exec/fornax-host-trust-exec/review/real_home_review.py \
  --i-understand-this-touches-my-real-home
```

Requires: a real `codex` binary on `PATH`, a built
`fornax-host-trust-exec` binary (on `PATH` or via `--host-trust-exec`),
and running this on the machine whose real `~/.codex` is being reviewed —
this is deliberately not something CI or any other automated process runs.

## Fields filled in for the run this review is based on

- **Reviewer:** Claude Sonnet 5 (automated review agent), operator: Bryant
  Liu / Chisanan232
- **Date:** 2026-10-17
- **Codex version(s) observed:** `codex-cli 0.160.0` (PATH binary; the
  review's own RPC path reported `codex_version: null` for each run
  because `fornax_hooks_not_installed` short-circuited before any
  `codex --version` precondition spawn or `app-server` spawn was needed —
  see attribution detail below)
- **macOS version:** 27.0.1
- **Every observed write/change, classified:**
  - `logs_2.sqlite-wal`, `state_5.sqlite-wal`, `thread_history_1.sqlite-wal`,
    `tmp/*` — `accepted_residual_class` (sqlite-wal at `~/.codex` root /
    `tmp/**`, exactly the documented class)
  - `sessions/*` — **not** in the accepted-residual class; accepted as a
    one-off residual for this run only, per the founder's conditional
    disposition (see "Founder disposition" below). Full attribution record:
    - **Granularity limit:** the review's snapshot is depth-1
      (`snapshot()` in `real_home_review.py`), so `sessions/*` is an
      *aggregate* record (`file_count`, `total_size`, `max_mtime_ns`) over
      the whole `~/.codex/sessions/` subtree, not a per-file list.
      Individual changed filenames cannot be enumerated from this
      evidence, and this record does not claim otherwise.
    - **Exact aggregate delta:** `file_count` 395 → 395 (unchanged),
      `total_size` 3,890,892,952 → 3,890,901,371 bytes (**+8,419 bytes**),
      `max_mtime_ns` advanced ~4.47s. Unchanged file count with size growth
      means this is an **append to one or more already-existing files**,
      not file creation, deletion, or truncation — still outside the
      documented accepted class, hence still a trigger, but a weaker class
      of residual than new/removed files.
    - **Zero `codex` process spawns by the review path, by elimination,
      not direct observation:** every one of the 21 runs resolved
      `global_reasons: ["fornax_hooks_not_installed"]`
      (`codex_version: null` in every run record), which in
      `exec/fornax-host-trust-exec/src/main.rs` is an early return (around
      line 150) firing **before** `check_reviewed_version` (the `codex
      --version` precondition spawn, ~line 176) and before
      `launch::spawn_app_server` (the real app-server spawn, ~line 196).
      `real_home_review.py` itself never execs `codex` directly — its only
      subprocess calls are `pgrep -f 'codex.*app-server'` (read-only
      enumeration) and the `fornax-host-trust-exec verify-codex --json`
      binary under review. So the review path spun up zero `codex`
      processes of its own across all 21 runs.
    - **Process-set stability:** 19 `codex app-server` processes were
      already running before the review started and 19 after, with
      `process_ownership_check.total_unexplained_app_server_pids: 0`
      across all 21 runs (PID-**count** comparison; the evidence does not
      capture before/after PID *sets*, only counts and the per-run
      unexplained-count, which was 0 every time).
    - **Conclusion:** attribution is by elimination — the review itself
      spawned nothing and wrote nothing (confirmed structurally: no
      `open(..., "w")`/mutation call anywhere in `real_home_review.py`'s
      read path, and the Rust binary's own path for this exact outcome
      never reaches a write), and a stable set of pre-existing, unrelated
      `codex app-server` processes was running the whole time. The append
      is attributed to those pre-existing sessions, not to anything this
      review did. This is elimination, not direct proof of which process
      wrote the bytes — accepted for this one run only per the founder
      disposition below, not as a standing allowlist change.
  - `config.toml` / `hooks.json` / `auth.json`: no content change
    (equality-checked; none of the three hard trigger files changed).
  - `installation_id`: no change.
- **Residual risk:** none identified beyond the `sessions/*` attribution
  above, accepted for this run only. No `config.toml`/`hooks.json`/
  `auth.json` write, no `installation_id` change, no file
  creation/deletion/mode/ownership change anywhere, 0 unexplained
  processes, 0 credential exposure, 21/21 runs structurally valid.
- **Measured latency:** sum of all 21 runs' wall-clock ≈ 3.07s (first run
  1287.2ms outlier, remaining 20 averaging ~89ms each); all 21 runs
  completed within the 30s per-run bound, none timed out. (The
  evidence file's separate top-level `latency_ms` aggregate field reads as
  all-zero samples — a cosmetic reporting gap in the script unrelated to
  the per-run `wall_clock_ms` values used here, not re-litigated in this
  review.)
- **Concurrent app-server count before/after:** 19 / 19
- **Two review-script bugs found and fixed during this process (neither
  is a security defect in the Rust binary under review):**
  1. `EXPECTED_HOST_TRUST_VALUES` expected the Rust enum's PascalCase
     spelling (`"Trusted"`) instead of its actual
     `#[serde(rename_all = "snake_case")]` wire form — every real run
     aborted on run 0 with `invalid_trust_verdict`. Fixed in `644c726`.
  2. The accepted-residual bucket-selection used
     `(classify(path) and accepted) or violations`, which always chose
     `violations` while `accepted` was still empty (Python `or` picks by
     truthiness; an empty list is falsy) — every accepted-residual write
     was silently misclassified as a violation on every run, including
     this one (recomputed post-hoc against the already-captured
     snapshots, no further real-home access). Fixed in `c61c034`.
  Both fixes' regression coverage was independently re-verified: each bug
  was reintroduced in an isolated scratch copy (never the tracked file)
  and confirmed to make the test suite fail (5 and 3 failures
  respectively), then reverted and confirmed to pass clean (30/30).

## Founder disposition

The founder conditionally authorized accepting the `sessions/*`
aggregate change as a benign concurrent-session residual, "ONLY after
sufficiently strong evidence-based causal attribution," explicitly **not**
a standing allowlist change. The attribution above (zero spawns by the
review path, zero writes by the review path, stable pre-existing process
count, append-only delta shape) is offered as that evidence. This
acceptance is scoped to exactly this run: this date, this evidence SHA-256,
this `sessions/*` delta. It does not modify
`ACCEPTED_RESIDUAL_WRITE_PATTERNS` in `real_home_review.py` and does not
pre-clear any future `sessions/*` change in a later run — a future run
with a different delta shape (file creation/deletion, mode/ownership
change, or any count change) must be evaluated fresh against the trigger
conditions below.

- **Verdict:** **PASS (scoped)** — the one trigger condition that fired
  (`sessions/*`) is resolved by the founder disposition above for this run
  only; every other trigger condition did not fire (no
  `config.toml`/`hooks.json`/`auth.json` write, no `installation_id`
  change, 0 unexplained processes, 0 credential exposure).

## Trigger conditions (any one blocks merge and escalates to one Level 2 founder packet)

- Any write, rename, or unlink touching `config.toml`, `hooks.json`, or
  `auth.json`.
- Any changed path outside the accepted residual class
  (`*.sqlite`/`-wal`/`-shm`/`-journal` at the `~/.codex` root, `tmp/**`,
  `.tmp/**`) — unless, as here, the reviewer presents a specific,
  evidence-based attribution and the founder explicitly accepts it for
  that one run.
- An `installation_id` content change.
- The reviewer judging a residual write to be a persistent config change
  beyond what ADR-0026 accepts.

If none of these fire (or each that fired is resolved as above), this
document's own status line reads `complete` and ADR-0026's status is
`Accepted`.
