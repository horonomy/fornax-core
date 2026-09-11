# FORNX-343 Adjudication Quick Reference

One page, not a walkthrough. See `docs/research/fornx-343-adjudication-playbook.md`
for the full phased procedure (mining, reviewer setup, disagreement escalation,
freeze, export) — this page is only the part a reviewer needs while actually
labeling a worksheet produced by `fornax adjudicate worksheet-export`.

The rubric text below is also embedded verbatim inside every worksheet file's
`instructions` field, so you never need this file open to label — it exists so
the rubric has one canonical source instead of being retyped in two places.

## The six labels

| Label | Means | Do NOT use when |
|---|---|---|
| `reliable` | The evidence pool actually supports the claim, nothing in it contradicts it | The pool is thin/generic and you're inferring "probably fine" |
| `unreliable` | The pool doesn't reliably support the claim (weak/generic/single-source), but nothing directly contradicts it | There's a direct contradiction — that's `contradicted` |
| `contradicted` | Something in the pool directly contradicts the claim | The claim is merely unsupported, not actively contradicted |
| `unsupported` | Nothing in the pool speaks to the claim at all | Some weak evidence exists — that's `unreliable`, not `unsupported` |
| `incomplete` | You can name specific evidence that's missing and would change your answer | You just feel uncertain without being able to name what's missing |
| `not_evaluable` | The case itself is malformed/unusable (bad claim text, empty pool that isn't a real "unsupported" case) | The evidence is fine but weak — that's `unreliable`/`unsupported` |

## Illustrative examples (hypothetical — not real trajectories)

These are invented to show the boundary between labels, not drawn from any
real session. Do not treat them as a template to force real cases into.

- **Clear `reliable`**: claim "the test suite passed"; evidence pool has an
  `ExitCode` item with `code: 0` from the actual test-runner invocation, and a
  `ProcessObservation` item confirming that invocation ran. Nothing contradicts.
- **Clear `contradicted`**: claim "the command exited successfully"; evidence
  pool has an `ExitCode` item with `code: 1` linked `Contradicts` to the claim.
- **Genuinely ambiguous — `incomplete`, not a forced guess**: claim "the fix
  resolved the reported bug"; evidence pool has only an `ExitCode: 0` from a
  *different* command than the one that reproduces the bug. You can name the
  missing evidence (a reproduction of the original failure, re-run and passing)
  — that's what makes this `incomplete` rather than a guess at `reliable` or
  `unreliable`.
- **`unsupported` vs `incomplete`, the distinction that matters**: an empty
  evidence pool for a claim that has no natural evidence source at all is
  `unsupported`. An empty pool where you can point at exactly what a sensor
  *should* have captured but the pool doesn't show it is `incomplete`.

## Confidence and abstain

`confidence` is your honest confidence in *this specific label for this
specific case* — not a general opinion of the system under review. Low
confidence is a legitimate, expected outcome; it is not a reason to abstain.

Only an `adjudicator`-role reviewer resolving a primary/secondary
disagreement may abstain (`unresolved`, optionally prefixed
`not_evaluable:` to route to that terminal state instead of a bare
`Unresolved`). A primary or secondary reviewer should commit to a label at
low confidence rather than abstain — this is deliberate: abstaining is for
genuine adjudication deadlock, not reviewer uncertainty.

## Disagreement

If two independent (`primary`/`secondary`) reviewers' labels conflict on the
same case, re-run `worksheet-export` for that case with an `adjudicator`-role
reviewer and `--unblinded` (the adjudicator alone may see `local_verdict`
before deciding) — see the full playbook's Phase 3 for the exact commands.

## What must NOT be inferred

- Do not infer code correctness, intent, or "probably fine" beyond what
  `evidence_pool_count`/the claim text actually show.
- A nonzero `withheld_evidence_count` means real evidence exists but wasn't
  exportable — that's grounds for `incomplete`, never something to assume
  away in either direction.
- Do not let a claim's phrasing (confident-sounding prose) raise your label
  above what the evidence pool itself supports.
