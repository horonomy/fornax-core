# Worker evidence contract

Jira: FORNX-230. FORNX-232 now owns and ships the durable worker evidence
schema this file previously stubbed as provisional — see
[`docs/release-qa-signoff.md`](../../../docs/release-qa-signoff.md) §2
("Worker evidence schema") for the actual `STATUS`/`BASELINE`/`VERIFIED`/
`SUSPECTED_FINDINGS`/`UNTESTED_OR_BLOCKED`/`CONFIDENCE` shape every QA
worker returns, and §4 ("QA verifier roles and coordinator handoff
contract") for the `qa-coordinator`/`qa-worker`/`qa-finding-verifier` role
split. This file does not restate or fork that schema — a second,
diverging worker-evidence shape living here would be exactly the
copy-paste drift FORNX-231/232 both explicitly guard against.

## What this file adds on top of FORNX-232's schema

FORNX-232 §4 states plainly: "Worker-count sizing and lane assignment
strategy belong to FORNX-230's orchestration, not this document." The one
thing this skill's dispatch needs that FORNX-232's schema does not itself
carry is **which lane** ([`lane-surface-mapping.md`](lane-surface-mapping.md))
a given worker result belongs to, so the coordinator (Step 6) can compute
the worst-of verdict per lane before rolling it up to the gate overall.

When dispatching a worker, the coordinator tags the assignment with its
lane id from `lane-surface-mapping.md` (e.g. `adapters_providers`). The
worker's returned evidence stays exactly FORNX-232 §2's shape — this skill
adds no new field to it. The coordinator associates the lane id with the
result on its own side (it already knows which lane it dispatched to; the
worker does not need to echo it back).

## Aggregation into the gate verdict (SKILL.md Step 6)

- A lane's verdict is `BLOCK` if any of its workers' results carry a
  `SUSPECTED_FINDINGS` entry that reaches `CONFIRMED` (FORNX-232 §3's
  finding lifecycle), `PASS` if `STATUS: COMPLETE` with no confirmed
  finding and nothing in `UNTESTED_OR_BLOCKED`, `INCONCLUSIVE` if
  `STATUS: PARTIAL` with no confirmed finding but genuine ambiguity
  remains, and `UNTESTED` if `STATUS: BLOCKED` or the lane was never
  dispatched (e.g. Step 1's fail-closed discovery outcome).
- The gate's overall verdict is the worst of all lane verdicts, per
  FORNX-229's verdict semantics — restated in `SKILL.md` Step 6, not here.
