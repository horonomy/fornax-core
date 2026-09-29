#!/usr/bin/env bash
# Fornax status-line wrapper (FORNX-30 project-scoped dogfooding).
#
# SUPERSEDED by `fornax statusline provider` and the shared statusline host
# (HORO-1567). Frozen deliberately: existing `.claude/settings.local.json`
# files point at this path, so its behaviour and its stdout stay
# byte-identical rather than changing underneath a working setup. It takes no
# fixes -- its three known limitations (a hardcoded `~/.claude/statusline.py`
# upstream, a hardcoded `target/debug/fornax`, and a bare shield codepoint
# with no variation selector) are why it is superseded. See
# docs/dogfooding-status-line.md for the migration path.
#
# A project-level `statusLine` command fully REPLACES the user's global one
# for sessions rooted in this project (Claude Code does not merge non-list
# settings across scopes). This script preserves that behavior instead of
# silently dropping it: it invokes the user's existing global
# ~/.claude/statusline.py with the exact same stdin JSON Claude Code gave
# this script, then appends the Fornax segment as an additional line.
#
# Fails safe: a missing global statusline.py, or an unreachable Fornax
# daemon, degrades gracefully rather than breaking the status line.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GLOBAL_STATUSLINE="${HOME}/.claude/statusline.py"

INPUT="$(cat)"

ORIGINAL=""
if [ -f "$GLOBAL_STATUSLINE" ]; then
  ORIGINAL="$(printf '%s' "$INPUT" | python3 "$GLOBAL_STATUSLINE" 2>/dev/null || true)"
fi

FORNAX_BIN="$REPO_ROOT/target/debug/fornax"
if [ -x "$FORNAX_BIN" ]; then
  FORNAX_SEG="$("$FORNAX_BIN" status 2>/dev/null || echo '🛡 fornax: error')"
else
  FORNAX_SEG="🛡 fornax: not built (run cargo build --workspace)"
fi

if [ -n "$ORIGINAL" ]; then
  printf '%s\n%s\n' "$ORIGINAL" "$FORNAX_SEG"
else
  printf '%s\n' "$FORNAX_SEG"
fi
