#!/usr/bin/env bash
# FORNX-343 batch-readiness watcher.
#
# Real capture is live (Claude Code hooks installed via `fornax install-claude`
# against the real $FORNAX_HOME, 2026-09-11). This script automates every step
# up to, but never including, the human labeling judgment itself:
#
#   1. discover real sessions that have produced at least one claim
#   2. mine each into candidate cases (idempotent -- derive_id is a
#      content-hash, re-mining the same session is a safe no-op)
#   3. rank/sample the smallest valid batch (dry-run first, to see how many
#      distinct patterns actually exist before enqueueing anything)
#   4. once >= MIN_BATCH cases across >= MIN_PATTERNS distinct patterns are
#      available, enqueue them for real and export one worksheet
#
# Never fabricates a session, a claim, or a label. If real data isn't there
# yet, this exits quietly having done nothing but mine/rank what's real.
#
# Usage: FORNAX_HOME=~/.fornax fornax-corpus-watch.sh [worksheet_out_path]

set -euo pipefail

FORNAX_HOME="${FORNAX_HOME:-$HOME/.fornax}"
export FORNAX_HOME
export FORNAX_CORPUS_MINING_ENABLED=1

MIN_BATCH=10
MIN_PATTERNS=3
REVIEWER_ID="${FORNAX_REVIEWER_ID:-founder}"
OUT="${1:-$FORNAX_HOME/worksheet-v1.json}"
DB="$FORNAX_HOME/fornax.db"

if [ ! -f "$DB" ]; then
  echo "fornax-corpus-watch: no $DB yet -- daemon has never run here"
  exit 0
fi

# 1. Discover every distinct real session that has produced a claim.
sessions=$(sqlite3 "$DB" "select distinct session_id from claims;" || true)
if [ -z "$sessions" ]; then
  claim_count=$(sqlite3 "$DB" "select count(*) from claims;")
  event_count=$(sqlite3 "$DB" "select count(*) from agent_events;")
  echo "fornax-corpus-watch: no claims yet ($event_count real event(s) captured, 0 claims). Waiting for real sessions to reach a claim-producing point (e.g. a Stop event with an assertion)."
  exit 0
fi

session_count=$(echo "$sessions" | wc -l | tr -d ' ')
echo "fornax-corpus-watch: $session_count real session(s) with claims -- mining each"

# 2. Mine every session (idempotent, deterministic ids).
while IFS= read -r sid; do
  [ -z "$sid" ] && continue
  fornax corpus mine --session "$sid" 2>&1 | sed "s/^/  [mine $sid] /" || true
done <<< "$sessions"

# 3. Dry-run sample to see what's actually minable before touching the queue.
#
# FORNX-361: `adjudicate sample --dry-run` has been observed to hang
# indefinitely once the corpus grows large enough (32k+ agent_events) --
# a real perf bug, tracked separately. A cron-fired caller of this script
# must never let that hang accumulate an unbounded pile of orphaned
# 100%-CPU processes across ticks, so this step is time-boxed. A timeout
# here means "couldn't tell this tick" -- exactly like "not enough real
# data yet" from this watcher's own honesty contract -- never a fabricated
# readiness signal.
DRY_RUN_TIMEOUT_SECONDS="${FORNAX_CORPUS_WATCH_DRY_RUN_TIMEOUT:-60}"
# `|| status=$?` (not `if ! ...; then status=$?`) so `$status` holds the
# command's REAL exit code -- `!` on the `if` line negates `$?` itself, not
# just branch selection, which would make a 124 (timeout) indistinguishable
# from any other failure.
status=0
dry_run_out=$(timeout "$DRY_RUN_TIMEOUT_SECONDS" fornax adjudicate sample --budget "$MIN_BATCH" --dry-run 2>&1) || status=$?
if [ "$status" -eq 124 ]; then
  echo "fornax-corpus-watch: adjudicate sample --dry-run did not finish within ${DRY_RUN_TIMEOUT_SECONDS}s (FORNX-361) -- treating this tick as inconclusive, not as threshold-not-met. Not enqueueing or exporting."
  exit 0
elif [ "$status" -ne 0 ]; then
  echo "$dry_run_out"
  echo "fornax-corpus-watch: adjudicate sample --dry-run failed (exit $status)."
  exit "$status"
fi
echo "$dry_run_out"

selected=$(echo "$dry_run_out" | grep -oE '[0-9]+ selected' | grep -oE '[0-9]+' || echo 0)
patterns=$(echo "$dry_run_out" | grep -oE '[0-9]+ distinct patterns' | grep -oE '[0-9]+' || echo 0)

if [ "${selected:-0}" -lt "$MIN_BATCH" ] || [ "${patterns:-0}" -lt "$MIN_PATTERNS" ]; then
  echo "fornax-corpus-watch: not enough real data yet for a methodologically valid batch (selected=$selected/$MIN_BATCH, distinct_patterns=$patterns/$MIN_PATTERNS). Not enqueueing or exporting. Waiting for more real sessions."
  exit 0
fi

echo "fornax-corpus-watch: threshold reached (selected=$selected, distinct_patterns=$patterns) -- enqueueing for real"
sample_out=$(fornax adjudicate sample --budget "$MIN_BATCH")
echo "$sample_out"

case_ids=$(sqlite3 "$DB" "select case_id from adjudication_queue;" | paste -sd, -)
if [ -z "$case_ids" ]; then
  echo "fornax-corpus-watch: sample enqueued nothing (unexpected) -- not exporting a worksheet"
  exit 0
fi

fornax adjudicate reviewer-add --id "$REVIEWER_ID" --role primary --kind human --attested-by "$REVIEWER_ID" 2>&1 | grep -v "already" || true
fornax adjudicate worksheet-export --reviewer "$REVIEWER_ID" --case "$case_ids" --out "$OUT"

n=$(python3 -c "import json; print(len(json.load(open('$OUT'))['entries']))")
echo "READY: worksheet with $n case(s) written to $OUT"
echo "READY_PATH=$OUT"
echo "READY_COUNT=$n"
