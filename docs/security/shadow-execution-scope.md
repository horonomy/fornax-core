# Shadow Execution / Digital Twin Verification — scope and fidelity (FORNX-386)

Jira: [FORNX-386](https://lightning-dust-mite.atlassian.net/browse/FORNX-386),
Stage 9 (epic FORNX-376), target `v0.3.0`. Depends on FORNX-379
(`crates/fornax-verify/src/verification_budget.rs`). Reuses FORNX-346
(`exec/fornax-acquire-exec`, the Active Evidence Executor) as the precedent
for treating subprocess/network capability as a single, audited exception
surface rather than something this ticket reopens, and Stage-5's experiment
safety mechanism (`crates/fornax-experiment-runner`, FORNX-99/100) as the
isolation primitive this ticket extends rather than duplicates.

## What this module is

`crates/fornax-experiment-runner/src/shadow/` adds a bounded pre-flight
verification capability: run a proposed high-impact action against an
isolated digital twin and compare the observed effect to what was expected,
before ever recommending real execution. It reuses, unmodified:

- [`staging::StagedWorktree`](../../crates/fornax-experiment-runner/src/staging.rs)
  — ephemeral, path-escape-refusing, symlink-skipping filesystem isolation,
  with unconditional `Drop`-based cleanup.
- [`policy::GlobalExperimentPolicy`](../../crates/fornax-experiment-runner/src/policy.rs)
  / `is_permitted` — the two-layer, deny-by-default `SideEffectClass` gate.
- [`orphan::sweep_orphaned_staging_dirs`](../../crates/fornax-experiment-runner/src/orphan.rs)
  — the startup sweep for anything left behind by a crashed process.
- [`executor::Cancellation`](../../crates/fornax-experiment-runner/src/executor.rs)
  — the cooperative cancellation flag checked at phase boundaries.

No second experiment runtime was built. The only genuinely new code is the
two domain runners below and the `ShadowResult`/`EnvironmentFidelity`
comparison types that wrap them.

## Why exactly two domains, and why these two

FORNX-386 AC1 requires at least two *materially different* domains. Jira's
own scope text suggests "code/test changes plus database migration,
infrastructure plan or deployment configuration" as examples — not a
requirement to build all of them. This PR deliberately chose the two domains
that can be verified against **fully local, disposable resources with zero
external systems touched**, and declined the others for a specific,
documented reason:

| Domain considered | Chosen? | Why |
|---|---|---|
| File mutation (config/code changes) | ✅ | `StagedWorktree` already provides complete, audited isolation for this; verification is pure file-content/JSON-syntax comparison, no subprocess needed. |
| Database migration | ✅ | A throwaway, file-backed SQLite database created fresh per run, inside the same staging root the orphan sweep already scans. No real database, no network, no credential. |
| Infrastructure plan (Terraform/Cloudflare/AWS) | ❌ (this PR) | Any real fidelity for this domain requires either a real provider API (a live credential, real network egress — exactly what this ticket's own AC5/AC7 forbid by default) or a fully mocked provider backend sophisticated enough to be worth trusting, which is its own multi-week effort. Building it against a real provider "in plan-only mode" was explicitly rejected: a plan-only call still requires real credentials and real network reachability to the provider's API, which this module must never touch by default. |
| Deployment configuration | ❌ (this PS) | Same reasoning as infrastructure plan — verifying a deployment config's *effect* without actually deploying it requires either a real target environment or a simulator with no existing implementation in this codebase to reuse; out of scope for a safety-bounded first pass. |

This is a legitimate, honest scope narrowing under Jira's own AC1 wording
("at least two ... such as"), not a shortcut on the two domains actually
shipped — see `crates/fornax-experiment-runner/src/shadow/mod.rs`'s own
module docs for the equivalent statement in code.

## Fidelity disclosure (AC2, AC4)

Every [`ShadowResult`](../../crates/fornax-experiment-runner/src/shadow/mod.rs)
carries an `EnvironmentFidelity` naming exactly what the run does and does
not prove. `ShadowResult::satisfies_production_obligation` is the only
sanctioned way to ask whether a specific production obligation was
discharged, and it requires the obligation kind to appear in
`EnvironmentFidelity::covers` — anything not explicitly listed there returns
`false`, never a default `true`.

**File mutation domain** covers `file_content` and `json_syntax`. It does
**not** cover: executing any build or test command against the mutated
tree, or observing runtime behavior of any kind.

**SQLite migration domain** covers `schema_mechanics` against
representative seeded data. It does **not** cover: production database
engine behavior (fornax-cloud runs Postgres, not SQLite), or production-scale
data volume / concurrent-writer load.

## Safety invariants (AC5, AC7)

1. **Production mutation is impossible by default.** Every runner operates
   exclusively on a fresh copy (`StagedWorktree`) or a fresh, empty file
   (`shadow.sqlite3` inside a run-scoped staging subdirectory) — the real
   source tree and any real database are never opened for writing.
2. **No network, ever, by construction.** `shadow::is_local_only_target`
   refuses any connection-target string naming a non-local scheme
   (`postgres://`, `mysql://`, `http://`, ...) before any connection is
   attempted — proven by
   `db_migration::tests::a_network_shaped_target_is_refused_before_any_connection_attempt`.
   Neither runner has a code path capable of opening a real network socket
   at all; this check exists as an explicit, tested guarantee anyway rather
   than relying on "the code just doesn't do that" as the only evidence.
3. **No credential ever enters the isolated environment.**
   `shadow::contains_forbidden_parameter_key` refuses any proposal whose own
   parameters carry a credential-shaped key
   (`token`/`password`/`secret`/`api_key`/`credential`, case-insensitive
   substring match — the same named-not-heuristic discipline
   `fornax-acquire-exec`'s `STRIPPED_CREDENTIAL_ENV_VARS` uses) before the
   shadow environment is even provisioned.
4. **Path-traversal and symlink escapes are refused, not clamped.** The
   file-mutation domain reuses `StagedWorktree::resolve_contained` (already
   tested at the staging layer) and adds its own end-to-end negative
   controls:
   `file_mutation::tests::a_path_traversal_attempt_is_refused_not_clamped`
   and (Unix only)
   `file_mutation::tests::a_symlink_escape_is_never_followed_into_the_shadow_copy`.
5. **Cancellation and cleanup are honest.** Both runners check
   `Cancellation::is_cancelled()` before provisioning any resource and
   report `ShadowOutcome::Aborted` rather than silently treating an
   incomplete run as success. `StagedWorktree`'s `Drop` guarantee covers
   in-process cleanup; `sweep_orphaned_staging_dirs` — reused directly,
   because both domains place their resources under the same staging root
   — covers a process-kill scenario for either domain, proven by
   `db_migration::tests::an_abandoned_shadow_database_directory_is_reclaimed_by_the_existing_orphan_sweep`.

## Approval model (Scope)

Any shadow run that would need `SideEffectClass::NetworkCall`,
`SideEffectClass::ProcessSpawn`, or
`SideEffectClass::FilesystemWriteOutsideWorktree` goes through
`shadow::shadow_run_permitted`, which reuses `policy::is_permitted`'s
existing two-layer, deny-by-default gate rather than a parallel permission
system. Neither shipped domain runner in this PR actually requires any of
those three classes — both operate entirely within
`SideEffectClass::EphemeralWorktreeMutation`'s scope — so this gate is
exercised by this PR's own tests (`shadow::tests::shadow_run_permitted_denies_when_either_layer_denies`)
but is not yet wired to a live caller that would ever request a
higher-privilege class. A future domain that genuinely needs one goes
through this same gate, not a new one.

## Real fragility findings (AC3)

- **File mutation:** a config-file mutation that is textually plausible but
  syntactically broken (a trailing comma in JSON) is caught only by actually
  parsing the mutated content inside the isolated copy — a plain text diff
  cannot reliably tell you this in advance.
  (`file_mutation::tests::a_syntactically_broken_json_mutation_is_a_real_detected_failure`)
- **Database migration:** a `CREATE UNIQUE INDEX` migration that is
  perfectly valid SQL in isolation fails the instant it is run against
  representative seeded data containing a pre-existing duplicate — reading
  the migration's own SQL text gives no hint of this; only executing it
  against real rows does.
  (`db_migration::tests::a_unique_constraint_migration_fails_against_seeded_duplicate_data`)
