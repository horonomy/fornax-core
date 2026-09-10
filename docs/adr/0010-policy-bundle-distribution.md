# ADR 0010: Policy bundle distribution (background poll transport)

Status: Accepted
Date: 2026-09-03
Jira: FORNX-311 (child of FORNX-69, Stage-7/v0.6.0, blocker of release-gate
FORNX-124)

## Context

ADR-0008 (FORNX-119) built local activation, rollback defense, and
staleness floors, but named a footgun in its own "FORNX-121
refresh-transport prerequisite" section:

> The staleness floors defined here ship **inert** in v0.6.0. [...] with
> file-import (`fornax policy import`) as the *only* ingress this ticket
> provides, `confirmed_at` never advances after a bundle's initial import
> — nothing re-submits the same bundle to trigger a `Confirm`. That means
> every device's cached policy marches inexorably toward `Critical = Block`
> on a fixed clock [...] The correct sequencing is: build a refresh
> transport first, then wire enforcement to consume these floors.

ADR-0009 (FORNX-123) built revocation and named, in its own "Out of scope"
list, two prerequisites this ticket closes:

> - **Cloud→device policy distribution channel** — the biggest named gap
>   (honest limit #1).
> - **A `SignedPolicyBundle` producer in `fornax-cloud`** — a separate
>   ticket.

FORNX-311 is the fornax-core (device-side) half of a cross-repo ticket.
`fornax-cloud` implements the producer/fetch-endpoint half separately and
in parallel, in a different repo — that PR is out of this repo's scope;
this document is authoritative on the wire contract between them from the
device side.

## Decision

### Pull, never push

A background task inside `fornaxd` periodically `GET`s a fornax-cloud
endpoint with a bearer credential. There is no webhook, no inbound push
path — that would require an always-on inbound network surface, breaking
ADR-0001 D2's "no cloud dependency on the local critical path" posture (the
daemon already binds only to `127.0.0.1` for its HTTP surface, and the UDS
ingest path is local-only by construction). Pull keeps the daemon's network
posture unchanged: it makes outbound requests on its own schedule, exactly
like `fornax-verify`'s existing `reqwest` usage for other outbound calls,
and nothing external can reach in.

### Precompute-serve-verbatim, no conditional fetch, ever

The full response is processed every cycle, even when nothing has changed.
Re-submitting byte-identical bundle bytes through the **already-existing**
`submit_policy_bundle` produces `ActivationDecision::Confirm` — the *only*
mechanism that advances `confirmed_at` and resets the staleness clock (see
`evaluate_activation` in `crates/fornax-types/src/policy/cache.rs`). This is
deliberately the cheapest possible design: no `ETag`/`If-None-Match`, no
"skip if the digest looks the same" optimization, nothing that could ever
diverge from `submit_policy_bundle`'s own idempotent-resubmission contract.

**No future conditional-fetch/304 optimization may be introduced without
re-opening ADR-0008's footgun.** A 304-style short-circuit would mean a
poll cycle that changes nothing on the wire also does nothing to
`confirmed_at` — exactly the gap this ADR closes. If bandwidth or server
load ever justifies conditional fetching, the response's absence must still
somehow trigger an equivalent `Confirm` (e.g. the daemon re-submitting its
own last-known bytes locally), not merely skip the request.

### Reuse the existing device credential, add no new trust logic

The credential is a bearer token string read from a local file
(`FORNAX_DEVICE_CREDENTIAL_FILE`, default `$FORNAX_HOME/device-credential`)
— this ticket's job is reading and using it, not designing a new device
identity protocol. No prior device-credential-file concept existed
elsewhere in `fornax-core` to reuse at the time of this ticket; this file
format is the first one, and a future device-identity ticket should extend
it rather than add a second, competing credential source.

**This ticket adds ZERO new trust logic.** The poll task's entire job is:
fetch bytes, hand them to the already-existing, already-tested
`handle_policy_bundle_ingest`/`handle_policy_revocation_ingest` functions
(FORNX-119/123), exactly as the UDS ingest path (`fornax policy
import`/`fornax policy revoke`) already does. `verify_bundle`,
`evaluate_activation`, `submit_policy_bundle`, `submit_policy_revocation`,
and `load_policy_cache` are all untouched by this ticket.

## Normative poll-cycle order

(Verbatim from `crates/fornax-daemon/src/policy_poll.rs`'s module doc
comment — that file is the source of truth; this is a durable snapshot.)

1. If polling is disabled (no `FORNAX_POLICY_POLL_URL`, or no valid,
   correctly-permissioned credential file) -> `Disabled`, no network
   contact, no error. This is the expected state for most installs and
   logs at `info`, never as an error.
2. Wait for the tick: at startup, jitter `0..=30s` (avoids a fleet-restart
   thundering herd); thereafter `interval * backoff_multiplier`.
3. `GET <url>` with the bearer header, `Accept: application/json`, connect
   timeout 5s, total timeout 20s. Transport failure -> `Unreachable`, go to
   step 11.
4. HTTP 401/403 -> `AuthFailed`. Any other non-2xx -> `HttpError{status}`.
   Both -> step 11. Never retried within one cycle.
5. Read the body bounded by `MAX_RESPONSE_BYTES` (2 MiB), enforced WHILE
   STREAMING (`Response::chunk`, never trusting `Content-Length`, which is
   attacker-influenced). Exceeding it -> `TooLarge`, step 11.
6. Parse as the poll-response envelope. Parse failure -> `Malformed`, step
   11. Nothing inside is trusted yet.
7. If `revocation` is present: bound-check its serialized length against
   `MAX_PAYLOAD_BYTES` before re-serializing/handing it on, then call
   `handle_policy_revocation_ingest`. This happens BEFORE any bundle in the
   same cycle.
8. For each entry in `bundles`, in order, bounded by
   `MAX_BUNDLES_PER_RESPONSE` (32; truncate + warn beyond that), same
   length check, then call `handle_policy_bundle_ingest`. Each submission
   is independent — one rejection never aborts the loop; a rejection is an
   ordinary per-bundle outcome, not a poll-cycle failure.
9. The response is submitted in FULL every cycle regardless of whether
   anything looks unchanged — see "Precompute-serve-verbatim" above.
10. Success (steps 3-9 completed without a transport/parse-level failure,
    regardless of individual per-bundle accept/reject outcomes): record
    `Ok`, reset `consecutive_failures` to 0 and `backoff_multiplier` to 1.
11. Failure: increment `consecutive_failures`; set `backoff_multiplier =
    min(2^consecutive_failures, ceiling)` where `interval * ceiling <=
    3600` (cap total backoff interval at 1 hour). NEVER touch
    `state.policy`'s `state`/`usable`/`loaded_slot` fields on a
    transport-level failure — the existing cache stands exactly as
    FORNX-119 left it; only the `last_poll` status field changes (plus,
    additively, a `PolicyRefreshUnavailable` diagnostic once
    `consecutive_failures >= 3`).
12. Loop to step 2. Never exits except on task abort at daemon shutdown.

### Revocation-before-bundle ordering

`evaluate_activation` already checks revocation first (FORNX-123); step 7
running before step 8 in the *same* poll cycle means a bundle whose
revision digest was just revoked is rejected immediately, rather than
surviving until the revocation happens to be picked up on a later cycle.

### Panic containment

The outer supervisor loop spawns each individual poll-cycle attempt as its
own task and awaits its `JoinHandle`, treating a `JoinError` (the spawned
task panicked) as an ordinary failure outcome (`"panicked"`) for that
cycle — logged, recorded in `last_poll`, and the loop continues to the next
tick. A raw panic inside one cycle's HTTP/parsing/ingest logic can never
silently end all future polling.

### Concurrency: no `AppState::processing` lock

The poll task does not acquire the mutex that serializes evidence/claim
processing. Bundle/revocation ingest touches entirely separate tables from
evidence/claim processing, and `submit_policy_bundle`'s own `BEGIN
IMMEDIATE` transaction is the real serializer for policy-cache writes.
Holding the broader `processing` lock here would put a background network
task ahead of a live hook request, against ADR-0001 D2's spirit that the
local critical path must never wait on anything network-shaped.

## Trust boundary restatement

This ticket adds **zero new trust logic**. Every byte this module produces
is handed, unmodified beyond re-serialization of an already-parsed
`serde_json::Value`, to the exact same `handle_policy_bundle_ingest`/
`handle_policy_revocation_ingest` functions the UDS ingest path has used
since FORNX-119/123. `verify_bundle`, `evaluate_activation`,
`submit_policy_bundle`, `submit_policy_revocation`, and
`load_policy_cache` are untouched — none of their evaluation order,
rejection vocabulary, or cache semantics changed to accommodate this
transport. The poll task's only design surface is: how bytes get fetched
(HTTP, bearer auth, bounded, timed-out) and how failures are classified and
backed off — never what makes a bundle trustworthy.

## Honest limits

- **The poll interval is now the concrete, named emergency-response
  bound.** Under sustained failure, up to `interval * backoff-ceiling` —
  at the shipped defaults (900s interval, 1-hour backoff ceiling), up to
  ~1 hour worst case before a device notices a fresh bundle or an
  emergency revocation. A device that is fully offline for longer than
  that sees nothing until connectivity returns; this is inherent to a
  local-first pull architecture (ADR-0001 D2), not an oversight of this
  ticket.
- **`min_revocation_sequence` anti-withholding (ADR-0009 honest limit #3)
  remains unbuilt.** This ticket makes it buildable — a real transport now
  exists for fornax-cloud to eventually convey such a floor over — but does
  not build it. A malicious or compromised relay could still selectively
  withhold a specific poll response's revocation content without this
  device detecting the omission.
- **Team/project-scoped bindings confer no device eligibility yet**, per
  fornax-cloud's own limitation on its producer side. This affects what a
  device actually receives through this transport even once it is polling
  successfully — worth naming here since it is easy to mistake "the poll
  transport works" for "the device is receiving everything it should."

## Consequences

- ADR-0008's named footgun is closed: `confirmed_at` now has a real,
  automatic refresh mechanism, so the staleness floors it wired are no
  longer an inert ticking-outage timer for a device that never re-imports
  by hand.
- ADR-0009's "Out of scope" items #1 and #2 (cloud→device distribution
  channel; a `SignedPolicyBundle` producer in fornax-cloud) are closed —
  item #2 by fornax-cloud's own, separate PR in that repo, referenced but
  not reviewed here.
- The daemon gains its first outbound network dependency (`reqwest`, with
  `rustls-tls`), scoped to `crates/fornax-daemon` only — `fornax-store`
  remains free of any HTTP client dependency, still provably enforced by
  its own `t72_offline_startup_makes_no_network_calls` regression test,
  which passes unmodified by this ticket.
- A new, narrow credential-handling surface exists (a bearer token read
  from a local file) with its own permission check (refuses a
  group/world-readable file) and a hard requirement that the value never
  reach a log line, an HTTP response, or a diagnostic string.

## Test coverage index

All in `crates/fornax-daemon/src/policy_poll.rs`'s own `#[cfg(test)] mod
tests` (T01-T20; this crate has no library target, so these live alongside
the module rather than in `tests/`, using a hand-rolled TCP HTTP/1.1 mock
server — no new dependency — and a from-scratch signed-bundle/
signed-revocation builder against only public `fornax_types` API):

- T01-T03: pure helper math (`compute_backoff_multiplier`'s ceiling
  behavior, `upsert_refresh_unavailable_diagnostic`'s additive/idempotent
  behavior).
- **T04 (the headline test)**: identical resubmission confirms and
  advances `confirmed_at` while `sequence`/generation stay unchanged — the
  direct proof this ADR closes ADR-0008's footgun.
- T05-T09: config resolution (disabled with no URL/no credential file, a
  group-readable credential file is refused, interval clamped to the
  60s floor, `http://` refused for a non-local host).
- T10-T14: each transport/parse-level failure outcome
  (`unreachable`/`auth_failed`/`http_error`/`too_large`/`malformed`) in
  isolation.
- T15: revocation-before-bundle same-cycle ordering.
- T16: a stale (sequence-not-advanced) bundle is rejected via the existing
  `submit_policy_bundle` path, the active generation stands untouched, and
  `last_rejection` is populated.
- T17: an injected panic inside one cycle is contained and the next tick
  recovers.
- T18: repeated failures grow backoff, the `PolicyRefreshUnavailable`
  diagnostic appears at the 3rd consecutive failure, and a subsequent
  success resets both `consecutive_failures` and the backoff multiplier.
- T19: aborting the supervisor task does not hang.
- T20: the credential value never appears in any `last_poll.detail` string
  across every outcome above.

`crates/fornax-daemon/src/main.rs`'s existing `t78_api_policy_never_leaks_display_name_or_sensor_names`
regression test was updated (additively, `last_poll` added to its expected
top-level key set) and passes; `fornax-store`'s
`t72_offline_startup_makes_no_network_calls` passes unmodified, proving no
HTTP dependency leaked into that crate.
