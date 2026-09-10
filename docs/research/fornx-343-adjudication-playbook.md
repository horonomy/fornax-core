# FORNX-343 Gold Corpus Bootstrap — Founder Adjudication Playbook

**Status:** Ready to execute. Everything below this line is automated
tooling and prose; the only step that requires you is Phase 3 (adjudicate)
and the go/no-go on Phase 0 (which real sessions are in scope).

**Why this exists:** FORNX-343's own AC requires "at least one frozen
`HumanAdjudicated` corpus revision" and states human adjudication is
*intentionally* part of the evidence chain — no engineering path
substitutes for a real person exercising real judgment on real sessions.
FORNX-341 (mining) and FORNX-342 (adjudication mechanism) are both merged
and fully tested with synthetic fixtures; this playbook is the bridge from
"mechanism works" to "a real gold label exists."

## What you are being asked to decide and do

1. **Decide which real local sessions are in scope** (Phase 0 below) —
   this is a privacy/consent judgment only you can make, since it touches
   real session content from real repos on your machine.
2. **Review a small number of real candidate cases** (Phase 3) using the
   rubric below, via `fornax adjudicate`.

Everything else — mining, blinding, queueing, freezing, exporting,
agreement reporting — is a single command each, already implemented and
tested.

## Phase -1 — check whether you have enough real data yet

I checked `$HOME/.fornax/fornax.db` on this machine directly (read-only —
`SELECT COUNT(*)` against `agent_events`/`claims`/`evidence`, nothing
mined or exported) and found essentially no real session history there:
2 `agent_events`, 0 `claims`, 1 `evidence` row. Mining needs real `claims`
to work from — with zero, there is nothing to mine yet on this machine
today.

Before Phase 0, confirm you actually have (or are willing to accumulate)
enough real usage:

```bash
sqlite3 "$FORNAX_HOME/fornax.db" \
  "SELECT (SELECT COUNT(*) FROM agent_events) AS events, (SELECT COUNT(*) FROM claims) AS claims, (SELECT COUNT(*) FROM evidence) AS evidence;"
```

If `claims` is 0 (or very small) everywhere you check, the honest next
step is to use Claude Code/Codex with the Fornax hooks installed for a
handful of real sessions first (see `fornax install-claude`/
`fornax install-codex` if not already installed), then return to Phase 0
once real claims exist. There is no shortcut here that doesn't fabricate
data — an empty or synthetic-only corpus is exactly what this ticket's own
non-goals forbid presenting as real.

## Exact scope: how many cases, how long

- **Recommended pilot size: 8–15 candidate cases**, drawn from real
  sessions, covering as many of FORNX-343's own named dataset-strategy
  classes as actually occur in your real usage:
  healthy/correctly-completed, false/premature completion,
  unsupported/overly-broad claims, omitted verification, contradictory
  tool/system evidence, stale/correlated evidence traps, semantic-judge
  disagreement, and (if any exist) a causal/replay-ambiguous case. This is
  a *pilot*, not a target volume manufactured to close the ticket —
  FORNX-343's own scope explicitly forbids inflating sample size for its
  own sake, and explicitly permits reporting "insufficient data" honestly
  for any class your real sessions don't happen to produce.
- **A real numeric inter-rater agreement (Cohen's kappa) requires at least
  20 double-reviewed cases** (`fornax_corpus::adjudication::agreement::MIN_KAPPA_CASES`).
  With a pilot below that, `fornax adjudicate report` will honestly report
  `Insufficient` for kappa — this is the correct, non-fabricated outcome
  per ADR 0014, not a bug to work around. If you want a real kappa figure
  later, the natural way to get one solo is a **test–retest double-review**:
  register a second reviewer identity for yourself and re-review the same
  ≥20 cases at a later sitting (a few days apart, so the first pass isn't
  memorized) — the commands in Phase 3 already support this via
  `--double-review`.
- **Estimated time**: roughly 3–7 minutes per case (read the blinded case,
  decide a label, write one sentence of rationale) — a 10-case pilot is
  roughly **30–70 minutes** total, in one sitting or split across several.

## Phase 0 — decide what's in scope (you, before anything runs)

`fornax corpus mine --session <SESSION>` reads directly from
`$FORNAX_HOME/fornax.db` and only ever touches sessions you name
explicitly — nothing is mined automatically or in bulk. Before running
anything:

- Pick a small number of real sessions (recommend 5–10, to have enough
  claims for mining strategies to find 8–15 candidates across different
  failure classes) from repos/work you're comfortable including in a
  research corpus under this project's existing privacy/redaction
  boundary (`fornax_corpus::sanitize` — evidence-kind allowlist, redaction
  before anything is written to `corpus_candidates`).
- List session ids with:

  ```
  sqlite3 "$FORNAX_HOME/fornax.db" \
    "SELECT session_id, COUNT(*), MIN(claimed_at), MAX(claimed_at) FROM claims GROUP BY session_id ORDER BY MAX(claimed_at) DESC LIMIT 30;"
  ```

  (Read-only query — does not mine or export anything.)
- **What you must decide, and what I will not infer for you:** which
  session ids are appropriate to include. I do not know which of your real
  sessions touch client work, unpublished material, or anything else you
  would not want in even a sanitized, redacted, local research corpus. If
  in doubt, leave a session out — a smaller honest corpus beats a larger
  one you're unsure about.

## Phase 1 — mine (automated, one command per session)

```bash
export FORNAX_HOME="${FORNAX_HOME:-$HOME/.fornax}"
export FORNAX_CORPUS_MINING_ENABLED=1

for session in <session-id-1> <session-id-2> ...; do
  fornax corpus mine --session "$session"
done
```

Each invocation reports which mining strategies fired (contradiction, high
uncertainty, sensor disagreement, verdict-changed, benign control) and how
many candidates were produced. Benign controls are mandatory —
`fornax corpus export` refuses a controls-absent corpus, so mine enough
sessions that at least one produces a clean, uncontroversial control case.

## Phase 2 — enqueue for review (automated, one command per candidate)

List what was mined, then enqueue each case id:

```bash
sqlite3 "$FORNAX_HOME/fornax.db" \
  "SELECT id, session_id, json_extract(document, '$.mined_by') FROM corpus_candidates ORDER BY mined_at;"

for case in <case-id-1> <case-id-2> ...; do
  fornax adjudicate enqueue --case "$case"
done
```

Add `--double-review` on the subset (≥20, if you later go for a real kappa)
you intend to review twice.

## Phase 3 — register yourself and review (the human step)

Register yourself as a real human reviewer — this is the one command that
is *itself audited* (per `fornax adjudicate`'s own help text), so use a
real, stable identifier:

```bash
fornax adjudicate reviewer-add --id you --role primary --kind human --attested-by "<your name or email>"
```

For each enqueued case:

```bash
fornax adjudicate next --reviewer you --case <case-id>
```

This prints a **blinded** view (`BlindedCase`) — deliberately with no
verdict field, so you judge the evidence, not Fornax's own conclusion. Read
it, then submit:

```bash
fornax adjudicate submit \
  --view <view-id-from-next> \
  --label <one of: reliable | unreliable | contradicted | unsupported | incomplete | not-evaluable> \
  [--critical-failure] \
  [--failure-class <one of: claim-contradicted-by-evidence | claim-unsupported-by-evidence | evidence-missing | evidence-stale-or-mismatched | sensor-disagreement | other>] \
  --confidence <low | medium | high> \
  --rationale "<one sentence: what evidence made you choose this label>"
```

### The exact rubric — what each label means

| Label | Choose this when... |
|---|---|
| `reliable` | The evidence you can see genuinely supports the claim as stated — no material gap or contradiction. |
| `unreliable` | The claim is not well-supported, but you would not call it flatly contradicted — evidence is thin, indirect, or only partially on-point. |
| `contradicted` | At least one piece of evidence directly conflicts with the claim (e.g. a test claimed passing, but exit-code evidence shows failure). |
| `unsupported` | The claim asserts something no evidence in the view addresses at all — not contradicted, just never checked. |
| `incomplete` | Evidence is present but a piece you'd need to judge confidently is visibly missing (an explicit "evidence unavailable" marker in the view). |
| `not-evaluable` | You genuinely cannot form a judgment from what's shown — not the same as `unsupported`; use this when the view itself is broken/insufficient to reason about at all, not when the claim merely lacks support. |

- `--critical-failure`: set this when a wrong "reliable" verdict here would
  represent a genuinely dangerous false-positive (e.g. claiming tests pass
  when they silently didn't) — this flags the case for extra weight in
  later benchmark reporting, not a judgment about the case's difficulty.
- `--confidence`: your own honest confidence in the label you just gave,
  not a measure of the evidence's completeness (that's what `incomplete`
  is for).
- `--rationale`: one sentence, concrete, pointing at what you actually saw
  in the view — this is what a future re-reviewer or auditor reads to
  understand *why*, not a formality.

### What you must NOT do

- **Do not infer a label from what you think Fornax "should" have
  concluded.** You are the ground truth here, not a check on the
  mechanism. If your honest read of the evidence disagrees with what you'd
  guess Fornax computed, label it your way — that disagreement is exactly
  what this pipeline exists to surface.
- **Do not guess at evidence that isn't shown.** The blinded view is
  deliberately incomplete in places (that's real evidence-gap information,
  not a UI bug) — judge only what's in front of you.
- **Do not skip `not-evaluable`/`incomplete` to force a clean-looking
  corpus.** An honestly ambiguous case is more valuable here than a
  forced clean label — `AdjudicationState` and the eventual benchmark
  report both treat these as first-class outcomes, not noise to eliminate.

### If two reviews of the same case disagree

`fornax adjudicate disagreements` lists cases where two reviews produced
different labels. Resolve by adding one more review under the
`adjudicator` role:

```bash
fornax adjudicate reviewer-add --id you-adjudicator --role adjudicator --kind human --attested-by "<your name or email>"
fornax adjudicate next --reviewer you-adjudicator --case <case-id> --unblinded
fornax adjudicate submit --view <view-id> --label <...> --confidence <...> --rationale "<why this resolves the disagreement>"
```

The adjudicator role may see the *unblinded* view (including the two
disagreeing reviews) specifically to resolve the conflict — this is the
one role/step where blinding is intentionally lifted.

## Phase 4 — freeze and export (automated, one command each)

Once a case is `Resolved` (single review with no disagreement, or an
adjudicator resolution):

```bash
fornax adjudicate freeze --case <case-id> --by you --reason initial-freeze
```

Check the honest agreement/label-distribution report at any point:

```bash
fornax adjudicate report
```

Once every case you intend to include is frozen:

```bash
fornax adjudicate export --out gold-v1.jsonl --dataset-version v1
fornax corpus export --out corpus-manifest-v1.json --corpus-version v1
```

`gold-v1.jsonl` is a real `fornax-bench` dataset file, stamped
`LabelingProvenance::HumanAdjudicated` because every contributing reviewer
was `human` — the only way that provenance tag is ever produced.

## Phase 5 — hand back to the pipeline (automated, I do this once you hand me the files)

Once `gold-v1.jsonl` exists, tell me and I will:

- Run `fornax-bench`'s ablation/evaluation mechanisms against it for
  FORNX-95, feeding results back honestly (including an explicit
  insufficient-data report if the pilot is too small for a given
  breakdown).
- Hand the same corpus to FORNX-97/FORNX-107's evaluation paths.
- Never soften a negative result, per this ticket's own explicit
  constraint.

## How ambiguity gets recorded, end to end

Every non-clean judgment has an honest home in this pipeline, never
silently collapsed:

- Ambiguous evidence → `incomplete` or `not-evaluable` label (your call,
  per the rubric above).
- Disagreement between two reviewers → `Disagreed` state, visible in
  `fornax adjudicate disagreements`, resolved only by an explicit
  adjudicator review, never by majority vote (no such resolution path
  exists in this codebase — see ADR 0014).
- An adjudicator who still can't establish ground truth →
  `--unresolved "<reason>"` (or `--unresolved "not_evaluable:<reason>"`)
  instead of a forced label — stays `Unresolved`/`NotEvaluable` forever,
  never frozen into a gold label.
- Too few double-reviewed cases for a real kappa → `report` says
  `Insufficient`, not a fabricated number.
