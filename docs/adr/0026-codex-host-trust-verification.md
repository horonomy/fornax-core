# ADR 0026: Codex `hooks/list`-backed host_trust verification

Status: Accepted
Date: 2026-10-16
Jira: FORNX-450

## Naming note (read this first)

This ADR implements **`horonomy/internal-docs` ADR-0015**
(`docs/engineering/adr-0015-cross-product-host-trust-resolution.md`,
accepted 2026-10-16, Option A), *not* any locally-numbered Fornax ADR.
Fornax's own `docs/adr/0015-*.md`, `0009-*.md` and `0014-*.md` are unrelated
documents (a VoI planner, a policy revocation decision, and a corpus
adjudication decision respectively). Every reference to "ADR-0015" /
"ADR-0009" / "ADR-0014" below — including in the requirement numbering —
means the internal-docs document, never the Fornax-local one with the same
number. This note exists because the collision is real and easy to follow
into the wrong file.

## Context

Codex computes a content hash per installed hook and persists trust
against that hash in `~/.codex/config.toml`
(`[hooks.state."<key>"].trusted_hash`), and exposes the live
`currentHash`/`trustStatus` through its own `hooks/list` JSON-RPC method
over `codex app-server` (stdio). Fornax's existing Codex integration
(`crates/fornax-cli/src/codex_hooks.rs`) only ever *writes*
`~/.codex/hooks.json`; nothing in this codebase has ever read Codex's own
live trust verdict. internal-docs ADR-0015 accepted Option A: build this
authoritatively, via Codex's own RPC, gated behind an explicit
operator-invoked command, subject to seven binding requirements (R1–R7
below). This document is Fornax's own implementation of that mechanism and
the security review R3 requires before merge.

## Decision

Add a new, standalone executable, `exec/fornax-host-trust-exec`
(`fornax-host-trust-exec verify-codex`), that spawns `codex app-server`
inside a macOS Seatbelt sandbox, speaks newline-delimited JSON-RPC to call
`hooks/list`, and reconciles the response against Fornax's own installed
`~/.codex/hooks.json` entries. The verdict is fail-closed: `trusted` only
when every signal agrees; anything else is `untrusted` or `unknown`.

### Why `exec/`, not `crates/`

`crates/fornax-daemon/tests/adversarial_daemon_input.rs`
(`subprocess_surface_is_still_zero_in_production_code`, FORNX-238) scans
every `.rs` file under `crates/` for subprocess-spawn calls and fails CI if
one is found. Placing the spawn site in `fornax-cli` or any new `crates/`
crate would require widening that standing invariant — itself a boundary
change this ticket is not authorized to make. `exec/fornax-acquire-exec`
(ADR-0022) already establishes the convention: a privileged side effect
lives in its own binary outside `crates/`, with nothing under `crates/`
depending on it. `fornax-host-trust-exec` follows the same convention and
depends on no `fornax-*` crate at all, which also gives it zero shared code
with HORO-1718 Gate B's native notify/hook-observation work by construction
(enforced by `nothing_under_crates_depends_on_host_trust_exec` and a crate
dependency allowlist test).

### Why `exec/fornax-host-adapter-exec`'s fail-closed decision (D11) does not apply here

D11 refuses to execute a *third-party adapter binary* on the strength of a
Fornax-pinned digest, because a same-user writer can swap the bytes between
the check and the `exec()` — Fornax would be vouching for code it cannot
bind. This feature is structurally different: Fornax never vouches for
Codex's bytes. It runs the operator's own already-installed Codex binary —
the same one their interactive sessions already run — with a fixed argv and
a read-only RPC call, inside a sandbox that denies it from doing anything
but answer. A same-user attacker who can replace the `codex` binary already
owns every Codex session on that machine; "a compromised Codex lies about
its own trust state" is out of scope for this ADR and is recorded as such in
the Security considerations table below. Codex is the trust root here, not
an adapter Fornax is certifying.

## Wire protocol

Hand-rolled, not a new dependency: newline-delimited JSON (confirmed live
against `codex-cli` 0.160.0 and against the internal-docs harness's own
client, `tools/codex-host-probe/codex_host_probe/offline_cli.py` — not LSP's
`Content-Length` framing). Handshake: `initialize` (id 0) →
`initialized` notification → `hooks/list` (id 1). The client's outgoing
method set is closed by construction — an enum, not a generic
`method: &str` — so it can never be made to send anything else, which is
part of how R4/R5 are enforced structurally rather than by convention. A
reader thread owns the child's stdout, skips any message carrying `method`
(Codex sends unprompted notifications, e.g.
`remoteControl/status/changed`), and the main thread waits against one
overall deadline. Response structs have no `deny_unknown_fields` (Codex may
add fields); `trustStatus` is matched against an explicit allow-list
(`managed | untrusted | trusted | modified`) and any other value maps to
`unknown` with a precise reason code rather than a parse failure.

## Verdict and reason codes

Verification proceeds in a fixed order; any refusal before the RPC call
means **no process was spawned**:

1. Platform must be macOS with `sandbox-exec` present (`sandbox_unavailable`
   otherwise — every other platform fails closed here, by design, not as a
   gap to fill later).
2. Resolve and canonicalize the Codex binary (`--codex-bin` or a no-shell
   `PATH` walk); must be a regular executable file
   (`codex_binary_not_found`).
3. Read `~/.codex/hooks.json` read-only, select Fornax's own handlers by the
   existing `codex_hooks.rs` identity predicate (duplicated, not
   refactored into a shared crate — see "Identity predicate" below); none
   found is `fornax_hooks_not_installed` (no spawn), unparseable is
   `hooks_json_unreadable` (no spawn).
4. Snapshot A: sha256 of `hooks.json`/`config.toml` (in-process, never
   emitted); metadata only (exists/len/mtime/inode) for `auth.json` — its
   contents are never read, consistent with the global "never inspect
   secret plaintext" rule, since `auth.json` is a credential file.
5. Run `codex --version` under the same sandbox; must match
   `REVIEWED_CODEX_VERSIONS` or the whole run refuses
   (`codex_version_unreviewed`) — **app-server never starts on an
   unreviewed version.**
6. Spawn `app-server` under a Seatbelt profile that denies all network,
   denies all process-exec except the one canonicalized Codex binary, and
   denies writes to `config.toml`/`hooks.json`/`auth.json` by literal path
   (paths passed via `-D` params, never interpolated into profile text).
   `--disable plugins` avoids app-server's default `git ls-remote` to
   `github.com/openai/plugins.git` (confirmed live) — a network call that
   would otherwise directly violate R5 regardless of the sandbox (the
   sandbox is defense in depth here, not the only control).
7. Cross-check `initialize`'s `codexHome` (must canonicalize-equal the
   target `~/.codex`) and `userAgent` version (must match step 5's
   version) — catches a Codex installation whose live session reads a
   different home or a version-reporting mismatch.
8. Call `hooks/list`; reconcile each expected Fornax hook's key
   (`<sourcePath>:<event>:<group_idx>:<handler_idx>`) against the response.
   Missing is `hook_absent_from_host_listing` (the orphaned-entry case,
   `unknown`); an unexpected Fornax-shaped entry, a duplicate key, or a
   command/event mismatch at a matching key are each their own reason code
   (`unexpected_fornax_hook_in_host_listing`, `duplicate_host_key`,
   `host_listing_identity_mismatch`) rather than being silently merged.
9. Snapshot B; any difference from Snapshot A is
   `host_state_changed_during_verification` and fails the aggregate,
   regardless of what the RPC itself reported.
10. **Aggregate**: `trusted` only if the expected hook set is non-empty and
    complete, there are no global reason codes, every hook individually
    resolved `trusted`, and the tripwire is clean. Otherwise: any `unknown`
    reason wins over any `untrusted` reason. This is never computed as
    `.all()` over a possibly-empty collection — an empty expected set must
    not vacuously report `trusted` (the same anti-vacuity discipline this
    campaign already enforced twice elsewhere, HORO-1902/HORO-1903).

Exit code 0 only when the aggregate is `trusted`; 3 otherwise.

### Identity predicate

`fornax-host-trust-exec` duplicates (does not import) `codex_hooks.rs`'s
small identity predicate (`HOOK_BIN = "fornax-hook-codex-event"`, the three
event names, basename-of-first-token matching). A golden-fixture
consistency test (`crates/fornax-cli`'s own e2e suite, cross-referencing a
vendored copy of real `fornax install codex` output) proves the duplicate
has not drifted looser than the original, without creating a shared crate
or a `crates/` → `exec/` dependency in either direction.

## Requirement → mechanism → test (internal-docs ADR-0015, R1–R7)

| Req | Mechanism | Test |
|---|---|---|
| R1 no implicit launch | `fornax` CLI structurally cannot spawn anything (existing FORNX-238 scan, unchanged). The new binary's only spawn site is the `verify-codex` handler; `--help`/`--version`/parse errors exit inside clap before reaching it. | `help_and_usage_paths_never_invoke_codex` (argv-logging shim must see zero invocations) |
| R2 explicit action | Separate binary, one subcommand, zero other trigger paths (no daemon/hook/CLI/config/env route). | Same test, plus a dependency allowlist |
| R3 security review | Complete — see "Security review record" below; the review doc and evidence SHA-256 are the binding record. | N/A — process gate |
| R4 no trust/activation side effect | The RPC client's outgoing method set is closed (`initialize`/`initialized`/`hooks/list` only — no `thread/*`/`turn/*` exists in the type, so nothing can fire a hook). Seatbelt denies exec of anything but Codex and denies writes to the two trust-bearing files. Snapshot tripwire on both. | `protocol_can_only_emit_allowlisted_methods`; macOS tamper-shim e2e |
| R5 no unapproved mutation | Network fully denied (blocks the plugin-sync fetch and any credential refresh). `auth.json` write-denied + metadata tripwire; `config.toml` write-denied + digest tripwire. `--disable plugins` avoids the sync attempt outright. Child env is `env_clear()`'d then allow-listed (`HOME`, `CODEX_HOME`, `PATH`, `LANG`/`LC_ALL` only) so no API key or token reaches the child. No `thread`/`turn` RPC exists, so no model spend is possible. | Same tamper-shim e2e; `env_whitelist_is_exact` |
| R6 fail closed | Verdict aggregation rule above; version allow-list; `codexHome`/version cross-checks; tripwire. | Full negative matrix (unreachable/timeout/malformed/truncated/orphaned/duplicate/mismatch/unreviewed-version/tamper) |
| R7 preserve identity/provenance | `currentHash` taken verbatim from Codex, never recomputed (Option B was not approved — recomputing it here would silently reintroduce the exact risk ADR-0015 rejected). Identity predicate duplicated and pinned against a golden fixture. `codex_hooks.rs`'s install path is untouched. | Golden consistency test; vendored real-RPC-shape parse test |

## Security considerations

| Concern | Mechanism |
|---|---|
| Implicit launch from passive output | R1/R2 above — structurally impossible, not policy |
| Real `~/.codex` boundary (vs. the harness's isolated synthetic home) | This is the boundary this ADR exists to review; see real-home evidence below |
| Trust/activation side effects | Closed outgoing-method enum; Seatbelt exec/write denial; tripwire |
| Network egress | Seatbelt `deny network*`; `--disable plugins` removes the one known default network call |
| Credential mutation | `auth.json` write-denied; metadata-only tripwire; contents never read |
| Config mutation | `config.toml`/`hooks.json` write-denied; digest tripwire |
| Residual Codex runtime writes (sqlite/-wal/-shm, `installation_id`, `tmp/`, `.tmp/`) | Accepted as an unavoidable class (confirmed: denying them kills Codex startup entirely); classified and bounded in the real-home evidence, not silently ignored |
| Model spend | No RPC method exists that could trigger one |
| Untrusted executable dispatch | Seatbelt `deny process-exec` except the one canonicalized Codex binary |
| Environment leakage to child | `env_clear()` + explicit allow-list |
| Binary resolution / PATH hijack | Canonicalized path, no shell, no `PATH`-trusting exec |
| Same-user TOCTOU | Out of scope by design — see "Why D11 does not apply" above; Codex is the trust root, not an adapter being certified |
| Compromised Codex lying about trust | Out of scope — recorded here, not silently assumed away |
| Soft RPC schema drift | Version allow-list gates app-server start entirely; unknown `trustStatus` values map to `unknown`, never silently to `trusted` |
| Concurrency with live Codex / Codex.app sessions | Verdict is reported per-binary-path-and-version; multiple app-servers against the same real home is an observed, tolerated condition, not an error |
| Output secrecy | No file contents or hashes of secret-bearing files ever appear in output; `auth.json` stays metadata-only |
| Bounds / timeouts | Line-length and total-bytes caps on the RPC stream; one overall deadline; hard process teardown (`SIGTERM` then `SIGKILL`) |
| Orphaned child processes | Process-group spawn + group-kill teardown |
| Platform scope | macOS only; every other platform fails closed at step 1, not attempted |
| Symlinked `$HOME` prefix | `$HOME` is canonicalized before any Seatbelt literal-path param is derived from it. Empirically required, not defensive paranoia: macOS resolves a Seatbelt `(literal ...)` match against the kernel-level canonical path, and `$HOME` commonly sits under a symlinked prefix (`/tmp`→`/private/tmp`, `/var`→`/private/var`); without this, a real tamper attempt against `hooks.json` succeeded instead of being denied — caught by this feature's own e2e test (`tests/verify_codex_e2e.rs::tamper_attempts_are_blocked_and_files_stay_byte_identical`), not assumed |
| Version-preflight deadline (FORNX-451) | `check_reviewed_version`'s read of `--version` stdout and its wait for the child to exit are each individually bounded (`read_to_string_and_wait_bounded`/`wait_bounded`) rather than relying on the caller's overall deadline, which did not start until after this step returned. Empirically required: a silently-hanging child (open stdout, never writes) or one that closes stdout but never exits could previously block this function indefinitely despite the `timeout` parameter — caught by source review before any real-home run, covered by 3 new unit tests (`launch.rs`'s `tests` module) that reproduce both hang shapes directly, with no sandbox/macOS dependency |
| Process-ownership scope (FORNX-451 follow-on) | The bounded-timeout path kills and reaps only the exact `Child` handle `check_reviewed_version` itself spawned — never a PID discovered by name-matching other processes. A 4th unit test spawns an unrelated sibling process in the same test and confirms it survives untouched |

## Founder-decision callout

No founder decision was required beyond internal-docs ADR-0015's own
acceptance, which explicitly delegates each product's implementation and
security review to that product (R3), with one exception: the real-home
run's `sessions/*` residual (see "Security review record" below) escalated
to one Level 2 founder packet and was resolved by an explicit, narrowly
scoped founder disposition accepting it as a one-off environmental
residual for that run only — not a standing allowlist change. A Level 2
founder packet is escalated for any future run that records one of:

- any write/rename/unlink touching `config.toml`, `hooks.json`, or
  `auth.json`;
- any changed path outside the accepted residual-write class above;
- an `installation_id` content change;
- the reviewer judging a residual write to be a persistent config change
  beyond what's accepted here.

## Measured latency

Recorded in `docs/security/evidence/fornx-450-host-trust-real-home-2026-10-17.json`
(SHA-256 `964088d5d57c162eeff15545336ae70d55c8793ee998c3c0b7208c56b3300ebb`):
min 86.7ms / median 89.0ms / p95 93.8ms / max 1287.2ms over the 21 real
runs (the 1287.2ms value is the first run only, a one-time cold-start
cost; all 21 completed within the 30s per-run bound). 19 `codex
app-server` processes running concurrently throughout, before and after,
0 unexplained.

## Security review record

Complete: `docs/security/host-trust-verification-review.md` records
reviewer, date, versions, every observed write classified, and verdict
**PASS (scoped)**. `exec/fornax-host-trust-exec/review/real_home_review.py`
wrote sanitized evidence to `docs/security/evidence/` (gitignored by
design; SHA-256 recorded in the review doc and above). One Level 2 trigger
fired (`sessions/*`, an append-only aggregate delta outside the documented
accepted-residual class) and was resolved by explicit founder disposition
for this run only — see the review doc's own "Founder disposition"
section for the full attribution record and its stated limits. This review
verifies real-`~/.codex` process safety; it does not exercise the positive
host_trust-resolution path (no Fornax hooks are installed on this
operator's real `~/.codex`), which is proven separately by
`verdict.rs::full_match_all_trusted_is_trusted` and the sandboxed
fake-binary e2e matrix in `tests/verify_codex_e2e.rs`, both already merged
on this branch.

## Test infrastructure note

The real-shim e2e layer (`tests/verify_codex_e2e.rs`) uses a compiled
helper binary (`tests/fixtures/fake_codex.rs`, built as
`fornax-host-trust-exec-fake-codex`), not a shell script. Empirically
confirmed: macOS's Seatbelt `(allow process-exec (literal ...))` rule does
not match a `#!/bin/sh` shebang-interpreted script through
`sandbox-exec`, even when the literal path matches exactly — only a real
compiled (even relocated/copied) binary. `tests/fixtures/fake-codex.sh`
still exists and is used by `tests/session_streams.rs`, which exercises
`protocol::Session` directly over raw pipes and never goes through the
sandbox at all.

## Consequences

- Every Codex version bump turns the feature into `unknown
  (codex_version_unreviewed)` until re-reviewed. Deliberate: the evidence
  must bind to what actually runs, not to an assumption that a newer Codex
  behaves the same way.
- macOS only for the live-sandboxed path; Linux/Windows get a structural
  `sandbox_unavailable` refusal, not a degraded best-effort mode.
- `--disable plugins` means plugin-sourced hooks are excluded from the
  listing. Fornax's own hooks are user-source and unaffected (confirmed
  live: trust status identical with and without the flag).
- The verdict is per-Codex-binary-and-version; an operator with multiple
  Codex installations (observed: Codex.app's bundled CLI and a separate
  Homebrew install) gets independent answers for each, which is correct
  but means "is it trusted" is not a single global fact on such a machine.

## What this ADR does not decide

- A non-macOS isolation mechanism (future ticket).
- Any `fornax adapter info codex` or `doctor` hint surfacing this verdict
  inline (future ticket) — this ADR only authorizes the standalone
  `verify-codex` command.
- Writing a trust pin on the operator's behalf — read-only by design (R4),
  not a feature gap.
- A centralized Option-B hash-reference implementation — moot; internal-docs
  ADR-0015 accepted Option A only.

## Links

- `horonomy/internal-docs` `docs/engineering/adr-0015-cross-product-host-trust-resolution.md`
  — the binding decision this ADR implements.
- `docs/adr/0022-privileged-acquisition-executor.md` — `exec/` placement
  convention.
- `docs/adr/0023-external-adapter-registry.md` §D11 — the fail-closed
  execution-review precedent this ADR explicitly distinguishes itself from.
- `docs/security/threat-model.md` — extended alongside this ADR with a
  short cross-reference section.
- `crates/fornax-cli/src/codex_hooks.rs` — the install path this feature
  reads from but never mutates.
