# Contributing to Fornax

Canonical development conventions for `fornax-core`. This is the single
source of truth for these rules — other files point here rather than
repeating the body.

## Ticket-scoped PR delivery

Every PR corresponds to exactly one implementation ticket (Task or Story
acting as its own implementation unit). One ticket has at most one PR. A
ticket needing changes in multiple repos gets split into repo-scoped
implementation tickets first — never one Jira ticket claimed by multiple PRs.

## Branch / worktree

`main` is the stable/release line — it only receives the v0.0.1 governance
history plus unrelated cross-cutting PRs (branding, company governance). All
release-epic feature work happens on a single rolling **integration branch**,
`next/v0.0.4` as of this writing (previously `next/v0.0.3`, superseded in
place — never merged back to `main`, never deleted). One ticket = one branch
cut from the integration branch's current tip, merged straight back into it —
there is no per-stage or per-epic aggregation branch layer. Branch name
version prefix (`v0.0.4`, `v0.6.0`, `v0.7.0`, ...) tracks the target release
epic, not a separate branch to merge into.

```
git fetch origin --prune
git worktree add ../fornax-core-<TICKET>-<slug> \
  -b <target-release>/<TICKET>/<short_summary> origin/next/v0.0.4
```

Base off `origin/main` instead only for work explicitly scoped to the
stable/release line itself (e.g. governance/branding fixes, a release-freeze
commit). When the integration branch is promoted to `main` at release time,
that is a deliberate release action, not a routine PR base.

One ticket = one branch = one worktree. Never implement in the main
worktree. `<short_summary>` is 2–4 words, snake_case.

## Commits

Gitmoji + scope, imperative mood, one semantic change per commit:

```
✨ (scope): Add X
🐛 (scope): Fix Y
♻️ (scope): Extract Z
🧪 (scope): Test the empty case
📝 (scope): Document W
```

One test case = one commit. A test needing a new fixture/mock/utility gets
that as its own preceding commit. Ask before each commit: "if reverted
alone, does this undo exactly one clearly explainable change?" If no, split.

## Pull requests

Title: `[TICKET] <GitEmoji> (<scope>): <summary>`.

Body includes: Jira link, Why, Scope, Non-goals, Changes, Design decisions,
Security/privacy, Tests, E2E/manual verification (screenshots for
frontend/UI work), AC checklist, Known limitations, Rollback notes when
relevant. See `.github/PULL_REQUEST_TEMPLATE.md`.

## Self-review

Before merge, review as an independent senior reviewer would: does it match
the PR description and Jira goal, is every AC actually met, any scope creep,
correctness (races/retries/restart/state/edge cases), maintainability,
security (secrets/injection/logging leakage/network exposure), and is
fmt/lint/type/test all green. Fix anything wrong, re-test, re-review. Record
LGTM/self-review evidence in the PR before merging.

## Changelog and release docs

A PR with user- or operator-visible impact adds an entry to `CHANGELOG.md`'s
`[Unreleased]` section in the same PR. See
`docs/release/release-docs-governance.md` for the full policy: which of
changelog / release notes / docs / website an update needs, required
metadata for breaking/security changes, and sequencing across
`fornax-core`/`fornax-docs`/`fornax-website`.

## Merge

Merge method: **create a merge commit**. Never squash, never rebase-merge.
Admin permission may be used to *perform* the merge, never to bypass a
failing required check, an unresolved security finding, or a required
review gate.

## Frontend/UI verification

Any UI-affecting ticket must actually run the app, exercise the real flow,
and capture real screenshots (Playwright where appropriate) as verification
evidence — compiling/unit tests alone are not sufficient.

## Force-push

Force-push to `main` is forbidden under all normal circumstances (see
`docs/adr/` and the global CLAUDE.md Push Gate Policy). The one documented
exception is recorded in `docs/migration/0001-pr-governance-migration.md`
and does not set precedent.
