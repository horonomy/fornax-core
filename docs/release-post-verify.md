# Post-release verification

Jira: FORNX-236. Verifies the version users actually **receive** after
publication — a fresh, independent clone of the published tag, built in an
isolated context — never the build workspace `scripts/release-execute.sh`
(FORNX-235) used to publish it. Base/candidate readiness
(`scripts/release-readiness.sh`, FORNX-234) and published truth (this
script) are two different directions per the canonical relay in
[`docs/release-assurance-policy.md`](release-assurance-policy.md)
(FORNX-229): `... -> Release -> Post-Release Verification -> HEALTHY`.

## Why this script never calls `release-readiness.sh`

This is deliberate, not an oversight. The release-assurance policy's
verdict semantics require that no verdict may be silently converted into a
`PASS`, and this ticket's AC states failure must never be reported healthy
merely because pre-release QA passed. If this tool re-ran the readiness
gate, a candidate that passed QA/security/docs/stage weeks ago but whose
*published artifact* is actually broken could still show green upstream —
exactly the false-confidence path the policy forbids. This tool checks the
one thing readiness cannot: what actually shipped.

## What this is

```
scripts/release-post-verify.sh <manifest.json> --release-evidence <path> \
    --evidence-out <path> [--workdir <dir>] [--canary-url <url>] \
    [--repo <owner>/<name>]
```

- `<manifest.json>` — the same candidate manifest
  (`release/candidate-manifest.schema.json`) used by readiness/execute.
- `--release-evidence` — the FORNX-235 `release-execute.sh --evidence-out`
  file. This is the release *execution* record: it names which binaries
  were checksummed and records `mode`/`overall`. This tool treats it as
  input evidence, never as something it re-derives.
- `--evidence-out` (**required**) — where the durable post-verify result is
  written. Required, unlike `release-execute.sh`'s optional flag of the
  same name, because a result that only went to stdout is not linkable
  from Jira/Release Notes, and this ticket's AC requires that it is.
- `--workdir` — the clean context. Defaults to a fresh `mktemp -d`. Never
  the repo checkout this script itself lives in.
- `--canary-url` — a single HTTP health probe for a hosted environment.
  Omitted today because fornax-core ships local CLI/daemon binaries only —
  see "P0 smoke matrix" below.
- `--repo` — test-only override of the canonical release repo, defaults to
  `horonomy/fornax-core`.

There is no `--dry-run` mode: unlike `release-execute.sh`, nothing this
tool does is irreversible (it only reads, clones, and builds), so there is
nothing to rehearse. There is no `--replay` flag either — manual invocation
**is** the replay path.

## The clean context

1. `git clone --depth 1 --branch <version> https://github.com/<owner>/<repo> <workdir>/src`
   — a fresh clone of the **published tag**, not this checkout.
2. `CARGO_TARGET_DIR=<workdir>/target cargo build --release --workspace` is
   run **inside that clone**, with `CARGO_TARGET_DIR` explicitly forced
   under `--workdir`. This matters on this machine specifically:
   `~/.cargo/config.toml` globally redirects builds to a shared
   `~/.cargo/shared-target`; inheriting that here would silently reuse a
   shared build workspace and falsify the isolation this AC requires. The
   resolved workdir and target dir are recorded in the evidence
   `artifact` object so isolation is auditable, not merely asserted.
3. Artifact identity is read from the clean clone itself
   (`git -C <clone> rev-parse HEAD`), never re-asked of `gh` — `gh` is used
   only to confirm the release exists at all.

**What isolation does not mean**: `~/.cargo/registry` is still shared with
the host. This is build-artifact isolation, not full hermeticity.

Every external `git`/`gh`/`cargo`/`curl` call lives behind one named
function, matching `release-execute.sh`'s pattern, so tests substitute fake
binaries ahead of the real ones on `PATH` and exercise the real production
code path.

## P0 smoke matrix

Real checks today, given fornax-core ships five local binaries and no
hosted deployment (the same boundary precedent FORNX-235 used for scoping
cross-repo builds out):

| Check | What it proves |
|---|---|
| `precondition.release_published` | A GitHub Release for this version actually exists |
| `precondition.release_execute_pass` | The release-execution evidence is a successful `execute` run |
| `artifact.clean_fetch` | The published tag can be cloned independently |
| `artifact.tag_identity` | The clone's `HEAD` matches the candidate manifest's SHA |
| `artifact.source_version_identity` | The clean tree's `[workspace.package]` version matches the release version |
| `smoke.build` | The published source actually builds in a clean context |
| `checksum.coverage` | Every binary `release-execute.sh` checksummed is present in the clean build |
| `smoke.version_identity` | The built `fornax --version` reports the intended version — the primary negative-fixture target |
| `smoke.startup` | `fornax status` starts and degrades gracefully with no daemon running |
| `canary.hosted` | A single HTTP health probe, when `--canary-url` is given |

Deliberately **not** re-run — each recorded as a dispositioned `UNTESTED`
row, never silently skipped, per this ticket's AC that smoke stays fast and
P0-focused rather than duplicating full release QA:

| Check | Why it's dispositioned, not run |
|---|---|
| `smoke.provider_capture` | Real-provider capture is pre-release QA depth (FORNX-238-class evidence) |
| `smoke.core_verdict_path` | VERIFIED/CONTRADICTED core path is covered by pre-release QA |
| `smoke.persistence_restart` | Persistence/restart is pre-release QA depth |
| `smoke.privacy_egress` | Owned by the security gate and `docs/privacy-redaction-policy.md` |
| `smoke.api_db_journey` | No hosted API/DB/SaaS surface in this release |
| `smoke.migrations` | No schema/data migration in this release's scope |
| `smoke.docs_links` | No hosted docs/website surface in this release's scope |
| `artifact.signature` | No signing/SBOM/provenance exists yet (a known FORNX-235 limitation) |
| `canary.hosted` (when `--canary-url` omitted) | No hosted environment exists to canary today |

Recomputed checksums are deliberately **not** compared byte-for-byte
against the publisher's recorded hashes — Rust release builds are not
bit-reproducible across environments, so a mismatch there would be noise,
not signal. The identity proofs that do gate are the clone's tag SHA and
the running binary's own `--version` output.

## Verdict vocabulary and release health

Every check resolves to exactly one of the four release-assurance verdicts
(`PASS` / `BLOCK` / `INCONCLUSIVE` / `UNTESTED` — see
`docs/release-assurance-policy.md`), never a plain `pass`/`fail`, because
this tool owns the ticket's central invariant: an `UNTESTED` row is never
silently a `PASS`, and a dispositioned `UNTESTED` (one of the matrix rows
above) never blocks by itself. `overall` is the worst of all check
verdicts: `BLOCK` beats `INCONCLUSIVE` beats undispositioned `UNTESTED`
beats `PASS`.

`release_health` is written into the durable evidence file and derived
purely from `overall` at the moment of the last flush:

| `overall` | `release_health` |
|---|---|
| `PASS` | `HEALTHY` |
| `BLOCK` | `UNHEALTHY` |
| `INCONCLUSIVE` or undispositioned `UNTESTED` | `PUBLISHED_PENDING_VERIFICATION` |

`HEALTHY` is reachable only by every check resolving `PASS` or dispositioned
`UNTESTED` — this is the mechanism behind "failure never gets reported as
healthy merely because pre-release QA passed."

## Output shape

```json
{
  "mode": "post-verify",
  "version": "v0.0.1",
  "overall": "BLOCK",
  "release_health": "UNHEALTHY",
  "promotion_allowed": false,
  "artifact": {
    "repo": "horonomy/fornax-core", "tag": "v0.0.1",
    "source": "published_tag_clone",
    "expected_sha": "...", "resolved_sha": "...",
    "workdir": "/tmp/...", "cargo_target_dir": "/tmp/.../target"
  },
  "recovery": {
    "failing_checks": ["smoke.version_identity"],
    "next_step": "Stop promotion/announcement. File/link a Bug against this release. ..."
  },
  "timestamp": "2026-09-01T00:00:00Z",
  "checks": [ { "name": "...", "status": "PASS", "dispositioned": false, "detail": "...", "timestamp": "...", "extra": null } ]
}
```

`recovery` is present only when `overall != "PASS"`. It never auto-yanks a
release — that is an irreversible published-surface action and an owner
decision; it names the next command
(`scripts/release-execute.sh --yank <version> --reason "<...>"`) rather
than invoking it.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `overall == PASS` → `release_health` is `HEALTHY`, promotion allowed |
| 1 | Not verified healthy — `BLOCK`, `INCONCLUSIVE`, or undispositioned `UNTESTED` |
| 2 | Usage/input error: bad args, missing `jq`/`git`/`gh`(/`curl` with `--canary-url`), manifest or `--release-evidence` absent/unparseable, missing `--evidence-out` |
| 3 | Precondition refusal: no published GitHub Release for this version, or the release-execute evidence itself is not `overall: PASS` — nothing was actually released to verify |

## Testing

`tests/release-post-verify/release_post_verify.bats` (bats-core, run
manually — not wired into CI, matching the existing pattern). Fake
`git`/`gh`/`cargo`/`curl` binaries (`tests/release-post-verify/fakebin/`)
sit ahead of the real ones on `PATH`; the fake `cargo` writes small
*executable* stub binaries so the script's real `--version`/`status`
invocations run for real against those stand-ins, not a parallel
test-only branch.

```bash
bats tests/release-post-verify/release_post_verify.bats
```

Covers: the happy path (`HEALTHY`, promotion allowed, dispositioned rows
present but non-blocking); the negative fixture proving a wrong built
version is detected (`smoke.version_identity` BLOCK, exit 1, `UNHEALTHY`,
promotion false); a wrong clone SHA failing `artifact.tag_identity`; both
precondition refusals (no release published, release-execute evidence not
`PASS`) exiting 3 with no clone attempted; checksum-coverage BLOCK on a
missing recorded binary and non-blocking observation of an extra one;
canary PASS/BLOCK (2xx vs 503, the latter stopping promotion); a
mid-sequence clean-build failure leaving a truthful partial record that is
never `HEALTHY`; `CARGO_TARGET_DIR` isolation under `--workdir`; and usage
errors.

## Known limitations (out of scope for this pass)

- Not triggered automatically by a publication event; manual invocation
  only, matching `release-execute.sh`'s own CI-trigger limitation.
- No cryptographic signature/SBOM/provenance verification — nothing is
  signed yet.
- `--canary-url` is implemented and tested, but no Fornax environment
  consumes it today — fornax-core ships local binaries only.
- Recomputed-checksum byte comparison against the publisher's values is
  intentionally not a gate (see "P0 smoke matrix" above).
- Never performs the recovery action itself (no auto-yank, no auto-Bug
  filing) — it names the next step; a human or a future ticket wires that
  up.
- Does not re-run full release QA — the dispositioned `UNTESTED` rows name
  exactly what it declines to cover and why, per this ticket's AC that
  smoke stays fast and P0-focused.
