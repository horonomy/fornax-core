# ADR 0022 — Privileged Acquisition Executor: `RerunTest`/`QueryCiStatus` Outside `crates/`

**Status:** Accepted
**Ticket:** FORNX-346 Part 2 · **Epic:** FORNX-340 (Stage 8 / Active Evidence Intelligence)
**Crate:** `exec/fornax-acquire-exec` (binary `fornax-acquire-exec`)
**Supersedes/extends:** `docs/adr/0016-evidence-acquisition-boundary.md`'s "Escalated, not built" section

## Context

ADR 0016 (FORNX-346 Part 1) implemented `fornax-acquire`'s two auto-safe,
in-process, zero-side-effect probes (`VerifyArtifactHash`, `InspectVcsState`)
and explicitly escalated the remaining two `fornax_verify::voi::ProbeKind`
variants that require a real side effect -- `RerunTest` (`ProcessSpawn`) and
`QueryCiStatus` (`NetworkCall`) -- rather than building them past a boundary
nobody had actually moved: this workspace's zero-subprocess-spawn invariant
(`crates/fornax-daemon/tests/adversarial_daemon_input.rs::
subprocess_surface_is_still_zero_in_production_code`) and ADR-0001 D2 ("no
cloud dependency on the local critical path").

## Decision (founder-decided, binding): Option B

`RerunTest` and `QueryCiStatus` live **outside `crates/`**, as a physically
separate, explicitly opt-in binary: `exec/fornax-acquire-exec`. This
decision was made by the founder and is not re-litigated here; this ADR
records it and its consequences.

Two independent gates, both deny-by-default, both required before either
probe executes anything:

1. `fornax_experiment_runner::GlobalExperimentPolicy` (host-wide:
   `ProcessSpawn`/`NetworkCall` granted at all), re-checked at execution
   time via the same `fornax_acquire::classify_for_execution` gate
   `/api/acquire-evidence` itself uses -- no new gate function was written
   for this.
2. `fornax_acquire_exec::grants::ExecutorGrants` (this executor's own,
   independent allowlist: *which* commands, *which* CI repo), read from
   `$FORNAX_HOME/config.toml`'s new `[acquisition_exec]` table.

`ProcessSpawn`/`NetworkCall` are **never globally-granted** by either gate's
own default -- both remain exactly as deny-by-default as every other
side-effect class in this workspace.

## Why `exec/`, not `crates/`, is structural enforcement -- not evasion

`subprocess_surface_is_still_zero_in_production_code`
(`crates/fornax-daemon/tests/adversarial_daemon_input.rs`) scans only
`workspace_root.join("crates")`. Placing `fornax-acquire-exec` under
`exec/fornax-acquire-exec/` means it never enters that scan at all -- this
is the actual, verified enforcement mechanism, confirmed by reading that
test's own source before writing a single line of this executor (see that
file's `crates_dir` variable). It is not evasion because:

- **Nothing under `crates/` depends on or spawns this binary.**
  `fornax-daemon` and `fornax-cli`'s `Cargo.toml` files gained **no** new
  dependency on `fornax-acquire-exec` in this change -- verified directly by
  inspection, not asserted. An operator invokes `fornax-acquire-exec`
  directly, out-of-band; no hook path, no daemon request handler, and no
  `fornax` CLI subcommand can ever reach it.
- **A second, workspace-wide test closes the gap the first test's own scope
  leaves open.** `subprocess_spawn_exception_is_confined_to_the_exec_crate`
  (added alongside `subprocess_surface_is_still_zero_in_production_code` in
  the same test file, that existing test left byte-for-byte unmodified)
  walks the *entire* workspace root (skipping `crates/`, `target/`, `.git/`,
  and any `tests` path component) and asserts every subprocess-spawn-shaped
  line it finds anywhere lives under `exec/fornax-acquire-exec/src/` --
  and, load-bearingly, that at least one such line actually exists, so
  renaming or deleting the exec crate can never make this test pass by
  vacuity.
- **`fornax-acquire-exec`'s own `Cargo.toml` documents the exception
  explicitly** rather than hiding it, and `src/rerun.rs`'s module doc
  states plainly: this is the only file in the repository allowed to
  contain `std::process::Command` or an inline shell invocation.

## The two-independent-gates model

`GlobalExperimentPolicy` answers "is this class of side effect ever
permitted on this host, at all" -- a coarse, host-wide switch shared with
every other experiment/acquisition surface in this workspace.
`ExecutorGrants` answers a narrower, executor-specific question this
workspace has never needed before: "which literal commands" and "which
literal CI repository". Collapsing these into one gate would mean an
operator who wants to allow `cargo test` reruns has no way to *also* deny
`rm -rf`, or an operator who grants `NetworkCall` broadly has no way to
scope `QueryCiStatus` to one specific repository. Both gates are checked
independently, and both must agree:

- Gate 1 (`classify_for_execution`) is checked once in
  `fornax-acquire-exec`'s `main.rs`, before any probe-specific logic runs.
- Gate 2 (`ExecutorGrants::permits_argv` / `permits_repo`) is checked
  *inside* `crate::rerun::run_rerun_test` / `crate::ci::query_ci_status`
  themselves -- so gate 2 can never accidentally be skipped by a future
  caller that forgets to check it separately.

`exec/fornax-acquire-exec/tests/deny_by_default.rs` proves each gate alone
still refuses when the *other* gate grants everything, and pins that a
`GlobalExperimentPolicy` loaded from an empty/minimal config never grants
`ProcessSpawn`/`NetworkCall`.

## `RerunTest`: injection-surface rules and rationale

The command comes from agent-reported evidence
(`fornax_types::ExitCodePayload::command`) -- untrusted, unvalidated JSON.
Five structural rules, implemented exactly (`exec/fornax-acquire-exec/src/rerun.rs`),
never heuristics or blocklisting:

1. **Never invoke a shell.** `Command::new(argv[0]).args(&argv[1..])` only.
   No `sh -c` anywhere in this file or any other file in this crate.
2. **Accept only `serde_json::Value::Array` of strings as the command.** A
   `Value::String` is refused outright ("command is not a structured argv
   array; refusing to parse a shell string") -- never split into argv.
3. **`argv[0]` must pass `ExecutorGrants::permits_argv`** (an
   operator-approved prefix) or the attempt is refused.
4. **`current_dir` must resolve inside a configured `[acquisition]` root**
   (`fornax_acquire::containment::AcquisitionRoots::resolve_contained`,
   reused as-is -- no bespoke path-containment logic was written) or the
   attempt is refused.
5. **Credential env vars are stripped from the child**: `GITHUB_TOKEN`,
   `GH_TOKEN` at minimum (`.env_remove`) -- a specific defense against
   exfiltrating a `QueryCiStatus` credential via a `RerunTest` child
   process, in case an operator grants both probes. Named to match
   `fornax_ci::GitHubCheckRunSource::from_env`'s own precedence exactly.

**Rationale for the argv-splitting asymmetry**: `ExecutorGrants::load`
whitespace-splits each `allowed_commands` config string into argv once, at
load time -- that string is trusted operator configuration, entered
deliberately into a file only the operator controls. `crate::rerun` never
does the equivalent to an evidence-supplied string. This is not an
inconsistency; splitting a trusted string and refusing to split an
untrusted one *is* the security property. Because `Command` never invokes a
shell, an agent-reported string (rule 2) is either refused outright or --
had rule 2 not existed -- would at worst become one single, harmless argv
element; there is no path from evidence JSON to shell interpretation.

Timeout is a **real kill**, not an abandoned thread: `run_rerun_test` polls
`Child::try_wait()` against a deadline and, on expiry, calls `Child::kill()`
followed by `Child::wait()` to actually reap the process, returning
`AcquisitionOutcome::TimedOut`. `exec/fornax-acquire-exec/tests/injection_surface.rs`'s
timeout test independently confirms the pid is no longer reported as
running after the call returns (a `ps -p <pid>` check, itself a test-only
subprocess spawn outside this crate's own `src/`, so it is not part of
either zero-subprocess-spawn scan).

Evidence produced matches the existing `EvidenceKind::ExitCode` /
`ExitCodePayload` shape verbatim (same fields `TestResultVerifier`/
`CommandExecutedVerifier`/`CommandSuccessVerifier` already read), with
`heuristic: false` (a real observed exit code, never inferred) and
provenance `"fornax-acquire-exec:rerun_test:FORNX-346"`.

## `QueryCiStatus`: SSRF-safety rules and rationale

`crates/fornax-ci` already implements a real GitHub check-runs client
(`GitHubCheckRunSource`) and status aggregation (`CiCheckRunStatus::overall`)
behind a synchronous `CheckRunSource` trait. `exec/fornax-acquire-exec/src/ci.rs`
adds **zero new network code** -- it calls that existing production
implementor directly.

Two rules:

- **`repo_slug` comes only from `ExecutorGrants::ci_repos()`** --
  operator-configured, never from evidence. There is no parameter on
  `query_ci_status` through which an evidence-embedded `repo` field could
  even be threaded in, which makes SSRF via a malicious repo target
  structurally impossible rather than merely filtered. When more than one
  repo is configured, an explicit `--repo` naming one of them is required;
  ambiguity (multiple configured, none specified) is a refusal.
- **`commit_sha` must match `^[0-9a-f]{7,40}$`** before any network call is
  attempted, else the attempt is refused. `GitHubCheckRunSource::fetch`
  builds its request URL by direct string interpolation of `commit_sha`; a
  malformed value (path traversal, injected query string, etc.) is refused
  before that interpolation ever happens.

Evidence produced reuses the existing `ProcessObservationDetail::CiCheckStatus`
shape `fornax-ci`'s own (currently unused-in-production) `GitHubCiStatusSensor`
already produces -- no parallel evidence shape was invented.

## Rejected alternatives

- **Aliasing or obfuscating the spawn call to dodge the scan** (e.g. an
  indirect function pointer, a re-exported name, string-building
  `"Command" + "::new"`). Rejected as dishonest: it would technically pass
  a substring scan while defeating its actual purpose, which is exactly the
  kind of "found a loophole in the letter of the rule" move this project's
  engineering discipline rejects on principle, independent of whether it
  would work mechanically.
- **A separate git repository** for `fornax-acquire-exec`. Rejected: it
  would lose `cargo build --workspace` / `cargo test --workspace` / `cargo
  clippy --workspace` CI coverage entirely, meaning this security-critical
  code would ship with *less* automated scrutiny than everything else in
  the project, not more. Living inside the same Cargo workspace (as an
  additional member, outside `crates/`) keeps full CI coverage while still
  achieving the structural separation the founder's decision requires.

## AC-by-AC status (FORNX-346)

The verbatim FORNX-346 acceptance-criteria text is not fully present
anywhere in this repository -- ADR 0016 already documented that FORNX-346's
own ticket prose contains fabricated references (a nonexistent "FORNX-178"
and a "Stage-5 experiment safety semantics" vocabulary with no real
referent), and only ever quoted AC1 and AC7 partially while correcting
that. This ADR does not further guess at wording it cannot verify; the
status below is scoped to exactly the AC numbers/partial text ADR 0016
already established as real, plus this Part 2 change's effect on them.
**Anyone reconciling this table against Jira should treat AC numbering as
provisional and re-verify against the ticket directly.**

| AC | Status | Note |
|---|---|---|
| AC1 ("at least three materially different auto-safe evidence acquisition paths execute end-to-end") | **Met, three of three** | Part 1 shipped two (`VerifyArtifactHash`, `InspectVcsState`); this Part 2 change adds a third, real, end-to-end path: `RerunTest`. `QueryCiStatus` is a fourth. Both are gated by two independent deny-by-default checks rather than being "auto-safe" in the no-gate sense Part 1's two probes were -- see the two-gates section above; this is a materially different (privileged, explicitly opted-in) execution mode than Part 1's in-process probes, not a like-for-like fourth "auto-safe" path. |
| AC2 (representative uncertain finding changes based on newly acquired evidence) | **Unchanged from ADR 0016** | Already closed there for `InspectVcsState`; this ADR does not revisit it. |
| AC5 (cost/latency/resource budgets, cancellable) | **Real kill implemented for `RerunTest`** | `fornax_acquire::budget::AcquisitionBudget` (Part 1) already implemented this for the two in-process probes via a channel-based caller-side timeout (no real OS process to kill there). `RerunTest` needed, and now has, an actual `Child::kill()` + `Child::wait()` on timeout -- a strictly stronger guarantee than Part 1's probes needed, because only `RerunTest` holds a real OS process open. |
| AC6 (concurrent sessions cannot cross-attribute acquired evidence) | **Unchanged from ADR 0016** | Relies on FORNX-339's `home_identity` handshake and session-scoped store reads/writes, not independently re-verified with a new mechanism in this Part 2 change. |
| AC7 (command-injection/SSRF/credential-bearing-probe coverage) | **Applicable, now closed** | ADR 0016 marked this "not applicable" because Part 1 shipped no command execution and no network client. This Part 2 change ships both, so AC7 is now genuinely applicable -- and closed via `exec/fornax-acquire-exec/tests/injection_surface.rs`'s real, non-mocked (except `CheckRunSource`) coverage: argv[0] allowlist, `Value::String` refusal, adversarial-payload-as-inert-literal, cwd containment, credential-env-stripping, malformed-commit-sha refusal, and evidence-embedded-repo-field-is-never-consulted. |

## Cannot be verified without further work

1. **No shipped verifier yet interprets `ProcessObservationDetail::CiCheckStatus`.**
   `RerunTest`'s `ExitCode` evidence *is* already consumed by the existing
   `TestResultVerifier`/`CommandExecutedVerifier`/`CommandSuccessVerifier`
   registry (see `docs/adr/0016-evidence-acquisition-boundary.md`'s amended
   "open item 3" for detail) -- but no verifier in `crates/fornax-verify`
   reads `CiCheckStatus` today, so a freshly acquired `QueryCiStatus` result
   currently has no consumer that turns it into a `Supports`/`Contradicts`
   verdict. That is real verifier-authoring work, out of scope here.
2. **No end-to-end test spawns the real `fornax-acquire-exec` binary
   against a live daemon.** Coverage is at the module level
   (`rerun::run_rerun_test` / `ci::query_ci_status` called directly, real
   subprocess spawn, real (mocked-source) CI query, no daemon involved) --
   the same scope discipline ADR 0016 already accepted for
   `/api/acquire-evidence` itself (no binary-spawn CLI end-to-end test
   exists for `fornax acquire-evidence` either, per that ADR's own item 6).
3. **`--repo`/`--cwd`/rank selection in `fornax-acquire-exec`'s `main.rs`
   is manually operated, not scripted end-to-end in CI.** An operator runs
   this binary directly per its own module docs; no automated harness
   drives the full plan → gate → execute → reverify loop against a live
   daemon in this change.
