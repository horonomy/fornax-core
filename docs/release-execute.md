# Release execution

Jira: FORNX-235. Builds ON `scripts/release-readiness.sh` (FORNX-234,
`docs/release-readiness.md`) — that script is called as a hard precondition
gate and is never reimplemented here.

The canonical release relay this tool's `Release` step fits into, plus the
rollback/yank/deprecate policy `--yank` implements, are defined in
[`docs/release-assurance-policy.md`](release-assurance-policy.md)
(FORNX-229).

> **DO NOT run `scripts/release-execute.sh --execute` without explicit owner
> authorization for a real release.** `--execute` creates and pushes real
> immutable Git tags and a real public GitHub Release on `horonomy/fornax-core`.
> These are the two irreversible actions this tool performs. `--dry-run`
> (the default) only ever prints what would happen and never touches a
> remote tag or a GitHub Release. `--yank` edits an existing GitHub Release's
> notes and also requires the same authorization discipline before real use.

## What this is

`scripts/release-execute.sh <manifest.json> [--dry-run|--execute] \`
`  --evidence-dir <dir> [--repo-fixture-dir <dir>] [--evidence-out <path>]`

`scripts/release-execute.sh --yank <version> --reason "<text>" [--repo <owner>/<name>]`

Same `--evidence-dir` / `--repo-fixture-dir` input contract as
`release-readiness.sh` (this script has no Jira/MCP/network access of its
own — the caller pre-fetches evidence tickets into normalized fixtures; see
`docs/release-readiness.md`). `--evidence-dir` is also reused, for free, as
the source of release-notes text when the manifest's `release_notes_ticket`
points at one of the same pre-fetched tickets.

## Modes

### `--dry-run` (default)

1. Runs `release-readiness.sh` against the same manifest/evidence.
2. If **not ready**: refuses, prints exactly which readiness checks failed,
   and exits **3**. This happens in dry-run too — dry-run shows the plan for
   a candidate that has already passed the precondition, it does not bypass
   the precondition.
3. If **ready**: prints one JSON plan describing:
   - Every repo/tag/SHA that would get an annotated tag created and pushed
     (`plan.irreversible_steps`, `irreversible: true`).
   - The canonical GitHub Release that would be created on
     `horonomy/fornax-core` (also irreversible).
   - The reversible local steps: `cargo build --release` (this checkout
     only) and sha256 checksum computation (`plan.reversible_steps`,
     `irreversible: false`).
   - Where release notes would come from (`release_notes.source`) and
     whether a source is configured at all (`release_notes.status`) —
     a manifest with neither `release_notes_ticket` nor
     `release_notes_path` set gets `status: "fail"` here even though the
     dry-run itself still exits 0; a real `--execute` refuses without one.
   Exits **0** regardless — dry-run's job is to show the plan for an
   already-ready candidate, not to re-gate on execute-time hazards (those
   are exactly what `--execute`'s own checks are for).

### `--execute`

Same readiness gate (refuses with exit 3 if not ready). Then, in order,
stopping at the first failure (fail-fast — "stop fan-out"):

1. **Tag immutability check**, per repo with `publishes_artifact: true`:
   queries the tag via the GitHub API (`gh api repos/<o>/<r>/git/ref/tags/<v>`,
   peeling an annotated tag object to its commit SHA). Tag absent → safe to
   create. Tag present at the **same** commit as the manifest → idempotent
   success, nothing pushed. Tag present at a **different** commit → hard
   fail; the tag is never moved.
2. **Tag create + push**: creates an annotated tag object and a
   `refs/tags/<version>` ref via the GitHub API (no local clone needed —
   this generalizes to every repo in the manifest, not just this checkout).
3. **Build**: `CARGO_TARGET_DIR=./target cargo build --release --workspace`
   — **this checkout only** (`fornax-core`). Cross-repo builds are out of
   scope: other manifest repos get tag/release actions but never a local
   build from here.
4. **Checksums**: sha256 of `target/release/{fornax,fornax-daemon,fornax-hook-claude,fornax-hook-codex}`.
5. **Release notes**: resolved from `release_notes_ticket`'s
   `--evidence-dir` fixture (`.text` field) or `release_notes_path` (a
   committed file). Neither present → hard fail; a release cannot be
   created without notes.
6. **Canonical GitHub Release**: created on `horonomy/fornax-core` via
   `gh release create`, attaching the checksum file. Already exists for
   this version → idempotent success, no second create.

Every step is recorded to `--evidence-out` **immediately after it runs**,
not only at the end — a script killed mid-sequence by `set -e` still leaves
a truthful record of which steps passed before the one that failed. The
evidence file's `overall` field is `"FAIL"` the moment any step fails, and
steps after a failure simply do not appear — this is the mechanism behind
the "partial-publish handling" AC: a step-3-of-6 failure is recorded as
exactly that, never reported as a full success.

```json
{
  "mode": "execute",
  "overall": "FAIL",
  "timestamp": "2026-08-30T00:00:00Z",
  "steps": [
    {"name": "readiness.gate", "status": "pass", "detail": "..."},
    {"name": "tag.horonomy/fornax-core.immutability", "status": "pass", "detail": "..."},
    {"name": "tag.horonomy/fornax-core.create_push", "status": "pass", "detail": "..."},
    {"name": "build.fornax-core", "status": "fail", "detail": "cargo build --release --workspace failed"}
  ]
}
```

### `--yank <version> --reason "<text>"`

**Not readiness-gated** — yanking a bad release must work even when the
readiness checker would refuse issuing a *new* one. Edits the existing
GitHub Release's notes, prepending a `DEPRECATED / YANKED` banner with the
reason and timestamp. **Never deletes or moves the underlying Git tag** —
published tags are immutable by policy (see FORNX-235 AC). Use this, plus a
new corrective release (a new version tag through the normal `--execute`
path), as the recovery procedure for a bad release. There is no
"unpublish" or "rewrite history" path by design.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Dry-run plan printed for a ready candidate, `--execute` fully succeeded, or `--yank` succeeded |
| 1 | `--execute`/`--yank` failed partway — see the evidence file (or stdout, if `--evidence-out` wasn't given) for exactly which step |
| 2 | Usage error (bad args, missing manifest, missing `jq`/`gh`) |
| 3 | Readiness refusal — `release-readiness.sh` returned `ready:false`; the failing checks are printed on stderr and as JSON on stdout |

## Testing

`tests/release-execute/release_execute.bats` (bats-core, run manually like
FORNX-234's suite — not currently wired into CI, matching the existing
pattern). Every `git`/`gh`/`cargo` call in the script lives behind a
function; the tests put fake `gh` and `cargo` binaries
(`tests/release-execute/fakebin/`) ahead of the real ones on `PATH` and
exercise the real production code path — no live network, GitHub, or Jira
call happens, and no real `cargo build` runs (`RELEASE_EXECUTE_REPO_ROOT`
redirects the build into a scratch directory).

```bash
bats tests/release-execute/release_execute.bats
```

Covers: dry-run refusal on a not-ready candidate, dry-run plan on a ready
one, a manifest missing a release-notes source, the tag-immutability
same-SHA idempotent path, the different-SHA hard fail (and that no tag
create/push is attempted after it), a mid-sequence build failure's
truthful partial-evidence recording, execute refusing on a not-ready
candidate without making any `gh` call, the yank happy path and its
not-readiness-gated property, yank on a nonexistent release, and basic
usage errors.

## Known limitations (out of scope for this pass)

- No cryptographic tag/release signing, SBOM, or provenance attestation.
- No migration execution step (FORNX-235's scope note: "no real production
  release is performed by this cross-cutting ticket itself"; migrations as
  an audited release step are follow-on work).
- Not wired into a CI/CD trigger — invoked manually or by a future
  `/release-preparation`-style skill, per the Release Operations Policy
  (Claude Code's role there is observational/preparatory, not operational).
- Cross-repo builds are out of scope: `--execute` can tag/release every repo
  in the manifest, but can only build and checksum this checkout's own
  binaries.
- FORNX-229/230/231/232/233/216 (version/schema/migration compatibility,
  changelog consistency, release-blocker lists) remain out of scope, same
  as documented in `docs/release-readiness.md`.
