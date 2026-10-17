# FORNX-450 security review: Codex host_trust verification against a real `~/.codex`

Status: **blocked_pending_founder_disposition** — run twice (once aborted
by a since-fixed review-script bug, once completed cleanly); one trigger
condition fired and is escalated below. See
`docs/adr/0026-codex-host-trust-verification.md` for the full design this
reviews, and `exec/fornax-host-trust-exec/review/real_home_review.py` for
the evidence-gathering script this review is based on.

This review authorizes nothing by itself. ADR-0026 stays `Proposed` until
this document records a pass with no trigger from that ADR's
"Founder-decision callout" list, backed by a committed evidence file at
`docs/security/evidence/fornx-450-host-trust-real-home-<date>.json`.

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

## Fields to fill in once run

- **Reviewer:** Claude Sonnet 5 (automated review agent), operator: Bryant
  Liu / Chisanan232
- **Date:** 2026-10-17
- **Codex version(s) observed:** `codex-cli 0.160.0` (PATH binary; the
  review's own RPC path reported `codex_version: null` for each run
  because `fornax_hooks_not_installed` short-circuited before any
  `app-server` spawn was needed — see verdict detail below)
- **macOS version:** 27.0.1
- **Evidence file:** `docs/security/evidence/fornx-450-host-trust-real-home-2026-10-17.json`
  (gitignored, not committed, per design)
- **Every observed write/change, classified:**
  - `logs_2.sqlite-wal`, `state_5.sqlite-wal`, `thread_history_1.sqlite-wal`,
    `tmp/*` — `accepted_residual_class` (sqlite-wal at `~/.codex` root /
    `tmp/**`, exactly the documented class)
  - `sessions/*` — **not** in the accepted-residual class. Attribution:
    19 `codex app-server` processes were already running on this machine
    before the review started and 19 after (`process_ownership_check`:
    0 unexplained PIDs both runs), i.e. this change is from the
    operator's own pre-existing, unrelated Codex sessions writing their
    own session logs during the ~1.3s the 21 review invocations took —
    not from anything the review script wrote (it performs zero writes,
    confirmed structurally: no `open(..., "w")`/mutation call anywhere
    in `real_home_review.py` or in `fornax-host-trust-exec verify-codex`
    on this path). This is my analysis, not a unilateral clearance — see
    the escalation below; this document stays un-flipped pending that.
  - `config.toml` / `hooks.json` / `auth.json`: no content change
    (equality-checked; none of the three hard trigger files changed).
  - `installation_id`: no change.
- **Residual risk:** none identified beyond the `sessions/*` attribution
  question above. No `config.toml`/`hooks.json`/`auth.json` write, no
  `installation_id` change, 0 unexplained processes, 0 credential
  exposure, 21/21 runs structurally valid.
- **Measured latency (min/median/p95/max):** 86.7 / 89.0 / 92.7 / 1287.2 ms
  (the 1287.2ms outlier is the first run; all 21 runs completed within
  the 30s per-run bound, none timed out)
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
- **Verdict:** **BLOCK (escalated)** — one trigger condition
  (`sessions/*` outside the accepted-residual class) fired per this
  document's own rules. Escalated as a Level 2 founder decision; this
  document and ADR-0026 stay as-is until that resolves one way or the
  other.

## Trigger conditions (any one blocks merge and escalates to one Level 2 founder packet)

- Any write, rename, or unlink touching `config.toml`, `hooks.json`, or
  `auth.json`.
- Any changed path outside the accepted residual class
  (`*.sqlite`/`-wal`/`-shm`/`-journal` at the `~/.codex` root, `tmp/**`,
  `.tmp/**`).
- An `installation_id` content change.
- The reviewer judging a residual write to be a persistent config change
  beyond what ADR-0026 accepts.

If none of these fire, record PASS here, flip ADR-0026's status to
`Accepted`, and this document's own status line to `complete`.
