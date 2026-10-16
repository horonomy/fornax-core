# FORNX-450 security review: Codex host_trust verification against a real `~/.codex`

Status: **pending** — not yet run. See
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

- **Reviewer:**
- **Date:**
- **Codex version(s) observed:** (PATH binary; note any Codex.app-bundled
  version seen running concurrently, per ADR-0026's "per-binary verdict"
  note)
- **macOS version:**
- **Evidence file:** `docs/security/evidence/fornx-450-host-trust-real-home-<date>.json`
- **Every observed write/change, classified:** (copy from the evidence
  file's `snapshot_diff`; every entry must be either
  `accepted_residual_class` or explicitly justified here — a fresh
  justification is not permitted for the three named trigger files)
- **Residual risk:**
- **Measured latency (min/median/p95/max):**
- **Concurrent app-server count before/after:**
- **Verdict:** PASS / BLOCK

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
