# Release docs governance: changelog, release notes, docs and website impact

Jira: FORNX-216 (general policy). Supersedes nothing — FORNX-217 executed
this exact set of updates for `v0.0.1` (see its Jira comment for the real
evidence trail); this document generalizes that instance into a repeatable,
version-agnostic policy so a future release doesn't have to rediscover the
same decisions. It also fills a gap `docs/release-readiness.md` already
called out: the release-readiness checker's `docs` gate needed a defined
workflow before FORNX-216 existed.

This is a workflow for an autonomous-agent-driven project: every step below
is written to be followed by an agent without a human editor in the loop.

## The four artifacts, and what triggers each

A single change can require zero, one, or all four of these. They have
different audiences and different source-of-truth locations — never
conflate them.

| Artifact | Audience | Lives in | Triggered by |
|---|---|---|---|
| **Changelog entry** | Maintainers, contributors, downstream integrators reading git history | `<repo>/CHANGELOG.md`, `[Unreleased]` section | Any merged PR with user- or operator-visible impact in that repo (see categories below). Internal-only refactors, test-only changes, and CI/tooling-only changes are exempt — see "No release note" below. |
| **Release notes** | End users and operators deciding whether/how to upgrade | `fornax-core/docs/release/<version>-release-notes.md` (canonical; this is the pattern FORNX-217 established for `v0.0.1`) | Every tagged release, always — assembled from that release's accumulated `[Unreleased]` changelog entries across every repo the candidate spans, not written from scratch. |
| **Docs update** | People installing, configuring, or operating Fornax | `fornax-docs` (Docusaurus site) | A change to install/config/CLI/API surface, provider/runtime support, architecture concepts an operator needs, troubleshooting, or migration steps. Not every release needs a docs change; a release with no user-facing surface change doesn't. |
| **Website update** | Prospective users and evaluators | `fornax-website` | A change to what Fornax is claimed to do, support, or cost: capability/support matrix, pricing, deployment modes, maturity status (e.g. "local-first only" → "hosted Beta available"), security/privacy/data-egress claims, product positioning. Impact-driven, not mandatory per release — see "N/A requires rationale" below. |

### No release note

A change gets **no** changelog entry when it is purely internal: refactors
with no behavior change, test-only changes, CI/tooling/docs-of-docs changes,
dependency bumps with no observable behavior change. State this explicitly
in the PR (`Known limitations: n/a` / a one-line "No release note: internal
only" note) rather than leaving it ambiguous — a reviewer or later agent
should never have to guess whether an omission was a decision or a miss.

## Categories

Every changelog/release-note entry is tagged with exactly one of:

`Added` · `Changed` · `Fixed` · `Security` · `Deprecated` · `Removed` · `Internal`

`Internal` entries may stay in a repo's own `CHANGELOG.md` for maintainer
visibility but are omitted from the public, user-facing release notes
document — they exist for provenance, not for the end-user audience.

## Change source: the `[Unreleased]` section is the fragment

FORNX-216 asked whether to use per-PR change fragments, generated metadata,
or a hybrid. Decision: **the existing `[Unreleased]` section in each repo's
`CHANGELOG.md` is the fragment log.** No new fragment-file tooling (e.g.
towncrier-style `changelog.d/`) is introduced by this ticket — `fornax-core`
already has exactly this structure (see its `CHANGELOG.md`), and a second,
separate fragment mechanism would just be two sources of truth for the same
thing. If a future release finds hand-editing one shared `[Unreleased]`
section causes real merge-conflict pain across concurrently-landing PRs,
that's a case for adopting fragment-file tooling — record that decision in
a new ADR when it actually happens, don't pre-build it speculatively here.

Practically, for every PR that needs a changelog entry:

1. Add one bullet to `[Unreleased]` in the changed repo's `CHANGELOG.md`, in
   the same commit as the change it describes (or a dedicated
   `📝 (changelog): ...` commit immediately after), tagged with its category
   and referencing the Jira ticket.
2. At release time, `[Unreleased]` becomes the new version section (rename
   the heading, don't retype the content), and a fresh empty `[Unreleased]`
   is opened above it. This is exactly what `fornax-core`'s `CHANGELOG.md`
   already does at the `v0.0.1` boundary.

## Breaking changes, migration, security, and compatibility

A changelog entry for a breaking change, deprecation, security fix, or
on-disk/wire compatibility change must include, inline in the same bullet
or an indented sub-block:

- **Breaking/Removed**: what stops working and the replacement, if any.
- **Migration**: the concrete steps an operator runs, or an explicit
  statement that no migration path exists yet (as `fornax-core`'s
  `v0.0.1` entry already does for `$FORNAX_HOME`'s on-disk schema).
- **Security**: severity and affected versions only — never exploit detail.
  See "Security disclosure" below for sequencing.
- **Compatibility**: which provider/runtime/adapter versions the change was
  verified against, if it touches adapter behavior (per
  `docs/research/adapter-capability-matrix.md`'s precedent of stating
  exact, verified capability differences rather than assumed parity).

This reuses fields the PR template already has (`CONTRIBUTING.md`: Design
decisions, Security/privacy, Known limitations, Rollback notes) — the rule
is that content produced there is not allowed to stay PR-only; it must be
promoted into the changelog entry, since PRs are not the durable public
record.

## Security disclosure handling

Public changelog/release-note entries for a security fix are written and
merged **only after** the fix ships, following `SECURITY.md`'s private
GitHub Security Advisory process. A changelog entry for an unreleased
security fix must not name the exploitable mechanism — "a redaction gap
that could expose local paths in evidence records" is acceptable; the exact
input that triggers it is not, until the advisory is public. This mirrors
the existing `docs/release/v0.0.1-qa-security-signoff.md` pattern of
disclosing findings honestly without turning the release notes into an
exploit index.

## Sequencing across repos

The three public repos have a real dependency order, not an arbitrary one —
`fornax-docs` syncs and builds against `fornax-core` content (its build
literally fails when `fornax-core`'s prose doesn't parse as MDX, as FORNX-217
found), and `fornax-website`'s claims must never outrun what `fornax-core`
actually ships. So for a release touching more than one repo:

1. **`fornax-core`** (and any other artifact-publishing repo, e.g.
   `fornax-cloud`) merges first. Its `CHANGELOG.md` `[Unreleased]` section
   is the authoritative record of what actually shipped.
2. **`fornax-docs`** updates/rebuilds second, using the just-merged
   `fornax-core`/`fornax-cloud` state as ground truth for capability claims.
   Its build (`npm run build`, which fails closed via
   `onBrokenLinks: 'throw'`) is the docs/link-consistency check — see "CI
   checks" below.
3. **`fornax-website`** reviews last, checking its claims against what
   steps 1–2 just established as true. A website change that ships before
   `fornax-core`/`fornax-docs` risks advertising a capability that isn't
   actually merged yet.

Private repos (`fornax-cloud`, `fornax-infra`) follow the same internal
changelog discipline (step 1's pattern) but have no public website
obligation; they still feed `fornax-core`'s aggregated release notes when
their changes are user-visible (e.g. cloud sync behavior).

### N/A requires rationale

A release that doesn't need a docs or website update still records that
decision, not silence — `fornax-website`'s `v0.0.1` review ("independent
review, no defects found, no PR needed") is the precedent. Record it as a
one-line comment on that release's docs-gate ticket (see below), naming
what was checked and why nothing changed.

## Who/what is responsible

This is procedural, not role-based — whichever agent or contributor merges
a user/operator-visible PR is responsible for that PR's changelog entry, in
the same PR. Cross-repo docs/website review for a release is performed by
whichever agent executes that release's docs-gate ticket (see below); it is
not a distinct human role.

## CI checks

- **`fornax-docs` build** (`npm run build`) is the existing, automatable
  docs consistency check: `onBrokenLinks: 'throw'` fails the build on any
  broken internal link, and `mdx: {format: md}` on synced content (per
  FORNX-217's fix) keeps `fornax-core`-authored prose from breaking the
  Docusaurus MDX parser. Run it in `fornax-docs` CI on every PR and on every
  scheduled/triggered re-sync from `fornax-core`.
- **Missing-changelog-entry check**: not implemented as of this ticket.
  A future CI check could flag a PR that touches non-internal source paths
  without a corresponding `CHANGELOG.md` diff, but building that check is
  out of scope here — this document defines the rule it would enforce, not
  the tooling itself.
- **Version-consistency / release-readiness**: already implemented and
  wired — `scripts/release-readiness.sh` (FORNX-234) validates a release
  candidate manifest against required `qa`/`security`/`docs`/`stage` gates
  before `scripts/release-execute.sh` (FORNX-235) will proceed. This
  document's job is to define what satisfies the `docs` gate (see next
  section); it does not change that script.

## The docs gate, concretely

`docs/release-readiness.md` already requires every candidate manifest to
carry a `docs` gate pointing at "the exact-version release-docs ticket for
this candidate... never a cross-cutting, multi-version Epic." This policy
document (FORNX-216) is that cross-cutting epic-level definition and is
**never** itself cited as `docs` gate evidence. Concretely, per release:

1. Open one version-scoped Jira ticket (the `FORNX-217` pattern) whose
   scope is exactly: verify Quick Start, reconcile docs/website claims
   against what this version's manifest actually ships, land the
   `CHANGELOG.md` version section and the canonical release notes file.
2. Its closing comment records, per repo touched: what changed, what didn't
   need to change (with rationale), and the evidence (PR numbers, build/test
   results) — the same shape `FORNX-217`'s closing comment already used.
3. Reference that ticket's key as the `docs` gate's `jira_key` in the
   release candidate manifest.

## Patch/hotfix and backport

A patch/hotfix release follows the same rules at smaller scope:

- Its changelog entry lands in the same `CHANGELOG.md` under its own new
  version heading (e.g. a `v0.0.1` patch gets its own section, not a
  rewrite of the `v0.0.1` section it patches).
- A backported fix's changelog line is duplicated into every branch it's
  cherry-picked onto — the cherry-pick is not complete until the changelog
  entry travels with the code change, so a reader of any given branch's
  `CHANGELOG.md` sees a complete, self-contained history for that branch.
- Patch releases do not require a new canonical release-notes file when the
  fix has no user-facing behavior change beyond "a bug is fixed" — a short
  changelog entry under `Fixed` is sufficient; use judgment per the
  categories above for whether a dedicated release-notes update is also
  warranted (e.g. a patch fixing a security issue always gets one, per
  "Security disclosure handling").

## What this document does not cover

- It does not implement CI enforcement for the missing-changelog-entry
  check described above — that is future work if the manual discipline
  proves insufficient in practice.
- It does not introduce fragment-file tooling — see "Change source" above
  for why, and the condition under which that decision should be revisited.
- It does not change `release-readiness.md`/`release-execute.sh` — it
  defines what the `docs` gate means, which those scripts already had a
  slot for but no written definition of, per FORNX-234's own "Known
  limitations" note pointing at FORNX-216.
