# Fixture provenance

`fornax-hooks-list-before.json` and `fornax-hooks-list-after.json` are
vendored verbatim from `horonomy/internal-docs`
`tools/codex-host-probe/fixtures/native/horo1716-operator-surface/`, commit
`fa343ec7fe6d1b9aeb52cae18978a2f8dfe749f9` (2026-10-16), via
`gh api repos/horonomy/internal-docs/contents/...`.

These are real `hooks/list` RPC responses captured against a real Codex
`app-server`, inside an isolated synthetic home (`<isolated-home>`
placeholder, substituted at test time) — not synthetic/hand-written
fixtures. `-before.json` shows all three Fornax hooks `untrusted`;
`-after.json` shows the same three `trusted`, after a matching
`[hooks.state.*]` pin was written. Used by FORNX-450
(`exec/fornax-host-trust-exec`) to prove the real-shape parser against
ground truth, per internal-docs ADR-0015 R7 (preserve existing
identity/provenance guarantees — never recompute what Codex already
computed).

Do not hand-edit these files. Re-vendor from the same source path if a
newer capture is needed, and update the commit SHA above.
