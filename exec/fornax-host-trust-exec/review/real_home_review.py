#!/usr/bin/env python3
"""FORNX-450 real-`~/.codex` security review.

Internal-docs ADR-0015 R3 requires a security review, separate from that
ADR's own acceptance, before `fornax-host-trust-exec` may run against the
operator's REAL `~/.codex` rather than an isolated synthetic home. This
script is that review's evidence-gathering half (see
`docs/adr/0026-codex-host-trust-verification.md` "Security review record"
and `docs/security/host-trust-verification-review.md`, the human-authored
half).

What this script does and does not do:

- Reads filesystem METADATA only, and minimizes even that: full per-file
  records (relative path, type, size, mtime, mode) are collected only for
  `~/.codex`'s TOP-LEVEL entries (depth 1) plus the four named files this
  review cares about. Anything nested deeper (session logs, rollouts,
  caches -- which can encode project/session-identifying names in their
  filenames) is collapsed to a per-top-level-directory aggregate (file
  count, total size, latest mtime) instead of being listed file-by-file.
  This still catches any new/removed top-level entry or bulk size/count
  change under a directory, without exporting individual nested filenames.
- Never reads file contents, with three narrow, declared exceptions below.
- `config.toml`/`hooks.json`/`installation_id`: compares content for
  byte-equality between two snapshots and records only a boolean
  ("unchanged"/"changed"), never the bytes themselves.
- `auth.json`: metadata only, ever. Its contents are never read, matching
  the global "never inspect secret plaintext" rule -- this is a
  credential file.
- Runs `fornax-host-trust-exec verify-codex --json` 21 times against the
  real home and real `codex` binary on PATH. The RPC-derived parts of that
  JSON are REDACTED before being added to evidence (see
  `redact_verify_result`): per-hook `command`/`sourcePath`/`key` strings
  (which belong to whatever hooks the operator has configured for ANY
  tool, not just Fornax's, and can contain arbitrary paths/arguments) are
  dropped. Only `event`, `trust`, `host_trust_status`, a `hash_present`
  boolean, and `reasons` survive per hook -- enough to confirm the
  verdict, nothing that could leak another tool's hook configuration.
- Evidence written to disk is checked against an explicit top-level key
  allowlist (`ALLOWED_EVIDENCE_KEYS`) AND a nested per-run/per-hook
  allowlist (`ALLOWED_RUN_RESULT_KEYS`/`ALLOWED_HOOK_KEYS`, via
  `assert_run_result_allowed`) right before the write -- an unexpected key
  at either level fails the run instead of silently writing it.
- Never kills a process based on a `pgrep` text match. `codex_app_server_pids()`
  is DIAGNOSTIC ONLY -- it populates a count in evidence for a human to
  look at. The only process this script ever signals is the ONE it
  itself forked for a given `verify-codex` call (`proc.pid` from a
  `Popen` handle held continuously since fork) -- that is genuine,
  race-free ownership, unlike a name-matched PID which could belong to a
  concurrent peer session. An earlier revision of this script conflated
  the two and could have killed an unrelated process on timeout; fixed
  before any real-home run, see `run_verify_once`.
- On a timeout, or if a run fails `validate_run_structure`'s fail-closed
  schema/exit-code/verdict check, aborts all remaining runs rather than
  piling more invocations onto a host that just misbehaved. This check
  applies to every run including the LAST one requested -- a prior
  revision's exit condition could reach exit 0 if exactly the final run
  was the one that failed; fixed, see `validate_run_structure` and the
  `all_runs_structurally_ok` check in `main`.
- Never writes raw, unstructured text into evidence for a failed run.
  Non-JSON stdout becomes a length + SHA-256 digest (`_parse_error`); a
  structurally invalid response becomes a fixed-vocabulary reason code
  (`_structural_failure`). Neither ever contains the original bytes.
- Per-hook `reasons`/`global_reasons` go through a strict, closed
  allowlist (`redact_reason_code`) rather than sanitize-and-cap free
  text: only a known tag name survives; any payload a variant might
  carry (host/RPC-sourced, e.g. `host_rpc_error`'s detail) is dropped
  entirely, and an unrecognized tag becomes a generic marker.
- `docs/security/evidence/*.json` is gitignored -- this script's output
  is never auto-committed by a broad `git add`; attaching a specific
  evidence file to the PR record is a deliberate, separate human action.
- Never writes a trust pin into the real `config.toml`. The positive/
  negative verdict matrix is covered by the synthetic CI suite
  (`tests/verify_codex_e2e.rs`) already; this script only observes
  whatever the real home's current state already is.
- Writes its output to `docs/security/evidence/fornx-450-host-trust-real-home-<date>.json`,
  with the real `$HOME` path replaced by the literal `<home>` everywhere
  it would otherwise appear.
- Makes no network call, no model/LLM call, and no credential-store
  mutation anywhere in this file -- there is no code path to one.

This script requires explicit operator confirmation to run (see `main`'s
`--i-understand-this-touches-my-real-home` flag) -- it is never invoked
by CI, by any Fornax command, or automatically by any part of this
ticket's implementation.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ACCEPTED_RESIDUAL_WRITE_PATTERNS = (
    # (relative-path predicate) -> accepted class name
    lambda p: p.suffix in (".sqlite", ".sqlite-wal", ".sqlite-shm", ".sqlite-journal") and "/" not in p.as_posix(),
    lambda p: p.parts[:1] == ("tmp",),
    lambda p: p.parts[:1] == (".tmp",),
)

NEVER_READ_CONTENTS = {"auth.json"}
CONTENT_EQUALITY_ONLY = {"config.toml", "hooks.json", "installation_id"}

# Explicit evidence-output allowlist (minimization requirement #2). Any key
# that shows up in `evidence` outside this set fails the write rather than
# being silently persisted.
ALLOWED_EVIDENCE_KEYS = {
    "schema_version",
    "generated_at_utc",
    "macos_version",
    "preconditions",
    "app_server_process_count_after",
    "runs",
    "first_run",
    "latency_ms",
    "snapshot_diff",
    "snapshot_before",
    "snapshot_after",
    "violations_found",
    "process_ownership_check",
}

# Strict allowlist of known `ReasonCode` wire tags (requirement 6): any
# reason string/object that doesn't match one of these EXACTLY is
# replaced with a generic "unknown_reason_code" marker. A payload some
# variants carry (`unrecognized_trust_status`, `codex_version_unreviewed`,
# `host_rpc_error` -- host/RPC-sourced free text) is always dropped,
# never exported in any form, structured or not. Treat every reason as
# untrusted data: if the wire format or variant set ever changes, this
# allowlist fails closed to "unknown" rather than passing new text through.
KNOWN_REASON_CODE_NAMES = {
    "fornax_hooks_not_installed",
    "fornax_hooks_incomplete",
    "hook_absent_from_host_listing",
    "unexpected_fornax_hook_in_host_listing",
    "duplicate_host_key",
    "host_listing_identity_mismatch",
    "host_response_malformed",
    "unrecognized_trust_status",
    "hook_disabled_by_host",
    "host_reported_hook_errors",
    "host_state_changed_during_verification",
    "sandbox_unavailable",
    "hooks_json_unreadable",
    "codex_binary_not_found",
    "codex_version_unreadable",
    "codex_version_unreviewed",
    "codex_home_mismatch",
    "codex_version_conflict",
    "host_unreachable",
    "timeout",
    "host_rpc_error",
}
UNKNOWN_REASON_CODE_MARKER = "unknown_reason_code"

# Nested keys this review's redaction is allowed to leave inside a run's
# `result` block -- checked in addition to the top-level allowlist, so a
# future field added to `redact_verify_result`'s output can't silently
# widen what gets exported without a reviewer noticing here too.
ALLOWED_RUN_RESULT_KEYS = {
    "schema_version",
    "operation",
    "adapter_id",
    "outcome",
    "codex_version",
    "host_trust",
    "global_reasons",
    "hooks",
    "timing_ms",
}
ALLOWED_HOOK_KEYS = {"event", "trust", "host_trust_status", "hash_present", "reasons"}
# Bounded diagnostic shapes for a run that didn't produce a well-formed
# redacted result -- never raw text, per requirement 6 ("record bounded
# error codes, lengths and safe diagnostic categories instead").
ALLOWED_PARSE_ERROR_KEYS = {"_parse_error", "stdout_length", "stdout_sha256"}
ALLOWED_STRUCTURAL_FAILURE_KEYS = {"_structural_failure", "reason"}
ALLOWED_TIMEOUT_KEYS = {"_timeout"}


def redact_reason_code(raw) -> str:
    """Extracts and allowlist-checks only the TAG of one reason entry,
    whatever shape the wire format uses for it, and always discards any
    payload. Handles every representation a Rust enum-with-data could
    plausibly serialize as, because we do not control that format and
    must not assume it stays a bare string forever:

    - a bare string tag (e.g. "sandbox_unavailable")
    - a dict with a tag under "code"/"type"/"tag" (payload elsewhere in
      the dict, e.g. {"code": "host_rpc_error", "detail": "..."})
    - a [tag, payload] pair

    Anything else, or a tag that isn't in `KNOWN_REASON_CODE_NAMES`,
    becomes the generic marker -- never the original text."""
    tag = None
    if isinstance(raw, str):
        tag = raw
    elif isinstance(raw, dict):
        for key in ("code", "type", "tag"):
            if isinstance(raw.get(key), str):
                tag = raw[key]
                break
    elif isinstance(raw, (list, tuple)) and raw and isinstance(raw[0], str):
        tag = raw[0]
    if tag in KNOWN_REASON_CODE_NAMES:
        return tag
    return UNKNOWN_REASON_CODE_MARKER


def redact_reasons(reasons):
    if reasons is None:
        return None
    return [redact_reason_code(r) for r in reasons]


def sanitize(text: str, home: Path) -> str:
    """Strips the real $HOME out of text. Used only for our own
    precondition check (`codex --version` output) -- every other
    free-text surface (raw stdout, reason strings) is now bounded by a
    dedicated, stricter mechanism (hashing / allowlisting) rather than
    sanitize-and-cap, per the R3 pre-flight review."""
    return text.replace(str(home), "<home>")


EXPECTED_HOST_TRUST_VALUES = {"Trusted", "Untrusted", "Unknown"}
ALLOWED_EXIT_CODES = {0, 3}  # per main.rs: 0 iff Trusted, 3 otherwise


def validate_run_structure(raw_parsed: dict, exit_code: int) -> str | None:
    """Fail-closed structural/semantic check on one run (requirement 3).
    Returns None if the run is well-formed, else a short, fixed-vocabulary
    reason string -- never a description built from the data itself,
    which would reopen the same "raw text in evidence" problem this
    review is closing elsewhere. Every one of these conditions must hold
    for ANY run, including the very last one requested -- there is no
    run-count-based shortcut that can skip this check."""
    if not isinstance(raw_parsed, dict):
        return "not_an_object"
    if exit_code not in ALLOWED_EXIT_CODES:
        return "unexpected_exit_code"
    for key in ("schema_version", "operation", "outcome", "result"):
        if key not in raw_parsed:
            return f"missing_field_{key}"
    result = raw_parsed.get("result")
    if not isinstance(result, dict):
        return "result_not_an_object"
    host_trust = result.get("host_trust")
    if host_trust not in EXPECTED_HOST_TRUST_VALUES:
        return "invalid_trust_verdict"
    if not isinstance(result.get("hooks"), list):
        return "missing_hooks_list"
    if exit_code == 0 and host_trust != "Trusted":
        return "exit_verdict_mismatch"
    if exit_code == 3 and host_trust == "Trusted":
        return "exit_verdict_mismatch"
    return None


def assert_allowed_keys(obj: dict, allowed: set, _path: str = "evidence") -> None:
    extra = set(obj.keys()) - allowed
    assert not extra, f"evidence-output allowlist violated at {_path}: unexpected key(s) {sorted(extra)}"


def assert_run_result_allowed(parsed: dict, _path: str) -> None:
    """Nested counterpart to `assert_allowed_keys` -- the top-level
    allowlist alone would pass a `runs: [...]` list containing anything,
    since `runs` itself is an allowed key. This walks into each run's
    redacted result (and each hook inside it) so a field added to
    `redact_verify_result` without a matching allowlist update fails the
    write instead of silently exporting it."""
    if "_timeout" in parsed:
        assert_allowed_keys(parsed, ALLOWED_TIMEOUT_KEYS, _path)
        return
    if "_parse_error" in parsed:
        assert_allowed_keys(parsed, ALLOWED_PARSE_ERROR_KEYS, _path)
        return
    if "_structural_failure" in parsed:
        assert_allowed_keys(parsed, ALLOWED_STRUCTURAL_FAILURE_KEYS, _path)
        return
    assert_allowed_keys(parsed, ALLOWED_RUN_RESULT_KEYS, _path)
    for i, h in enumerate(parsed.get("hooks") or []):
        assert_allowed_keys(h, ALLOWED_HOOK_KEYS, f"{_path}.hooks[{i}]")


def redact_verify_result(parsed: dict) -> dict:
    """Keeps only what's needed to confirm the trust verdict from one
    `verify-codex --json` run. Drops per-hook `command`/`sourcePath`/`key`
    -- those describe the operator's OWN configured hooks for any tool,
    not just Fornax's, and must not be exported verbatim. Every surviving
    `reasons`/`global_reasons` entry goes through `redact_reason_code`'s
    strict allowlist rather than being sanitized-and-capped free text --
    some wire variants carry a host/RPC-sourced payload, and the payload
    is now dropped entirely rather than bounded."""
    result = parsed.get("result") or {}
    redacted_hooks = []
    for h in result.get("hooks") or []:
        redacted_hooks.append(
            {
                "event": h.get("event"),
                "trust": h.get("trust"),
                "host_trust_status": h.get("host_trust_status"),
                "hash_present": bool(h.get("current_hash")),
                "reasons": redact_reasons(h.get("reasons")),
            }
        )
    return {
        "schema_version": parsed.get("schema_version"),
        "operation": parsed.get("operation"),
        "adapter_id": parsed.get("adapter_id"),
        "outcome": parsed.get("outcome"),
        "codex_version": (parsed.get("codex") or {}).get("version"),
        "host_trust": result.get("host_trust"),
        "global_reasons": redact_reasons(result.get("global_reasons")),
        "hooks": redacted_hooks,
        "timing_ms": parsed.get("timing_ms"),
    }


class ChildProcessTimeout(Exception):
    """Raised when the outer `fornax-host-trust-exec verify-codex` call
    itself times out. Distinct from a normal non-zero exit: a timeout
    means we cannot trust that `launch::teardown()` ran, so the sandboxed
    `codex` descendant it owned may now be orphaned -- see
    `run_verify_once`'s docstring for exactly what we do and do not do
    about that."""


def run(cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def codex_app_server_pids() -> set[int]:
    """DIAGNOSTIC ONLY -- never used to decide what to terminate. A
    system-wide `pgrep -f` match is not proof of ownership: an earlier
    revision of this script treated a before/after difference in this
    set as "our run's leaked descendant" and sent it SIGKILL on timeout.
    That is wrong -- a concurrent peer session's own `codex app-server`
    (or any other unrelated process matching the same pattern) can start
    inside the same window and would be killed by mistake. This function
    now exists only to populate `unexplained_app_server_pid_count` in
    evidence for a HUMAN to look at; nothing in this script signals a PID
    obtained from it. See `run_verify_once` for the one PID this script
    is actually allowed to terminate."""
    try:
        out = run(["pgrep", "-f", "codex.*app-server"], timeout=5)
    except Exception:
        return set()
    pids = set()
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.isdigit():
            pids.add(int(line))
    return pids


def run_verify_once(
    binary: str, timeout: int = 30
) -> tuple[subprocess.CompletedProcess, set[int]]:
    """Runs one `verify-codex --json` invocation.

    Ownership fix (requirement 2): on timeout, this terminates ONLY the
    exact process this call itself forked -- `proc.pid` from a `Popen`
    handle held continuously since fork. That is genuine, unambiguous
    ownership: it cannot match a concurrent peer session's process (a
    `pgrep` text match could), and it cannot be fooled by PID reuse
    (we hold the live handle, not a PID looked up after the fact). SIGTERM
    first, a short grace period, then SIGKILL only if it is still our own
    child and still alive.

    This does NOT attempt to clean up a sandboxed `codex` grandchild that
    `launch::teardown()` would have reaped on a normal exit -- a SIGKILL
    to this process can't let its own cleanup code run, and signalling a
    `pgrep`-matched PID instead would reintroduce the exact unsafe-kill
    defect this fix removes. `codex_app_server_pids()` is still sampled
    before/after purely as a diagnostic for the evidence file; a nonzero
    count there means a human should look, not that this script acted.
    """
    pids_before = codex_app_server_pids()
    proc = subprocess.Popen(
        [binary, "verify-codex", "--json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
        pids_after = codex_app_server_pids()
        unexplained = pids_after - pids_before
        raise ChildProcessTimeout(
            f"verify-codex (owned pid {proc.pid}) timed out after {timeout}s; terminated only "
            f"that exact owned child. {len(unexplained)} unrelated/unexplained app-server PID(s) "
            "observed via diagnostic scan afterward -- NOT killed; requires manual inspection."
        )
    pids_after = codex_app_server_pids()
    unexplained = pids_after - pids_before
    completed = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
    return completed, unexplained


def file_record(path: Path, root: Path, allow_content_equality: bool = False) -> dict:
    """`allow_content_equality` must be true ONLY for the canonical
    top-level file (depth 1) -- never for a same-named file found deeper
    in the tree. Matching by filename alone, at any depth, would read the
    bytes of -- and record the full nested path of -- an unrelated file
    that happens to share a name with `config.toml`/`hooks.json`/
    `installation_id` (e.g. a session log under `sessions/<project>/`),
    defeating the directory-aggregation minimization above it. This was a
    real bug in an earlier revision of this script, caught by an
    automated security review before any real-home run."""
    rel = path.relative_to(root)
    try:
        st = path.lstat()
    except OSError as e:
        return {"path": rel.as_posix(), "error": str(e)}
    kind = "symlink" if path.is_symlink() else ("dir" if path.is_dir() else "file")
    record = {
        "path": rel.as_posix(),
        "type": kind,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "mode": oct(st.st_mode & 0o777),
    }
    name = path.name
    if allow_content_equality and name in CONTENT_EQUALITY_ONLY and kind == "file":
        assert name not in NEVER_READ_CONTENTS, f"refusing to read {name}'s contents -- it is a credential file"
        try:
            record["_contents_for_internal_diff_only"] = path.read_bytes()
        except OSError:
            record["_contents_for_internal_diff_only"] = None
    return record


def snapshot(codex_home: Path) -> list[dict]:
    """Full records for depth-1 entries only; everything nested deeper
    collapses into one aggregate record per top-level directory -- see
    module docstring, minimization requirement #1. Depth-1-only is
    deliberate: matching the four named files by filename regardless of
    depth was the privacy-minimization bypass fixed alongside this
    docstring (see `file_record`'s `allow_content_equality` note)."""
    if not codex_home.is_dir():
        return []
    records: list[dict] = []
    aggregates: dict[str, dict] = {}
    for p in sorted(codex_home.rglob("*")):
        rel = p.relative_to(codex_home)
        depth = len(rel.parts)
        name = p.name
        if depth == 1:
            records.append(file_record(p, codex_home, allow_content_equality=name in CONTENT_EQUALITY_ONLY))
            continue
        top = rel.parts[0]
        try:
            st = p.lstat()
        except OSError:
            continue
        bucket = aggregates.setdefault(
            top, {"path": f"{top}/*", "type": "aggregate", "file_count": 0, "total_size": 0, "max_mtime_ns": 0}
        )
        if not p.is_dir():
            bucket["file_count"] += 1
            bucket["total_size"] += st.st_size
        bucket["max_mtime_ns"] = max(bucket["max_mtime_ns"], st.st_mtime_ns)
    records.extend(aggregates.values())
    return records


def assert_no_raw_bytes(obj, _path: str = "evidence") -> None:
    """Fails loudly, before any write, if a raw `bytes` value survived into
    the evidence tree -- the one shape `_contents_for_internal_diff_only`
    can take and the one thing that must never reach disk. Recurses
    through dicts/lists only, which is everything `evidence` is built
    from."""
    if isinstance(obj, bytes):
        raise AssertionError(f"raw bytes found at {_path} -- refusing to write evidence containing file contents")
    if isinstance(obj, dict):
        for k, v in obj.items():
            assert_no_raw_bytes(v, f"{_path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            assert_no_raw_bytes(v, f"{_path}[{i}]")


def strip_internal_contents(records: list[dict]) -> list[dict]:
    """Removes the content-equality-only internal field before anything
    gets written to disk -- that field exists only so `diff_snapshots`
    can compute a boolean, never to be serialized."""
    out = []
    for r in records:
        r = dict(r)
        r.pop("_contents_for_internal_diff_only", None)
        out.append(r)
    return out


def diff_snapshots(before: list[dict], after: list[dict]) -> dict:
    before_by_path = {r["path"]: r for r in before if "error" not in r}
    after_by_path = {r["path"]: r for r in after if "error" not in r}
    added = sorted(set(after_by_path) - set(before_by_path))
    removed = sorted(set(before_by_path) - set(after_by_path))
    changed = []
    for path in sorted(set(before_by_path) & set(after_by_path)):
        b, a = before_by_path[path], after_by_path[path]
        name = Path(path).name
        if b.get("type") == "aggregate" or a.get("type") == "aggregate":
            if (
                b.get("file_count") != a.get("file_count")
                or b.get("total_size") != a.get("total_size")
            ):
                changed.append({"path": path, "kind": "aggregate_changed"})
            continue
        if name in CONTENT_EQUALITY_ONLY:
            if b.get("_contents_for_internal_diff_only") != a.get("_contents_for_internal_diff_only"):
                changed.append({"path": path, "kind": "content_changed"})
            continue
        if b["size"] != a["size"] or b["mtime_ns"] != a["mtime_ns"] or b["mode"] != a["mode"]:
            changed.append({"path": path, "kind": "metadata_changed"})

    def classify(rel_path: str) -> str | None:
        p = Path(rel_path)
        for pattern in ACCEPTED_RESIDUAL_WRITE_PATTERNS:
            if pattern(p):
                return "accepted_residual_class"
        return None

    violations = []
    accepted = []
    for path in added:
        bucket = (classify(path) and accepted) or violations
        bucket.append({"path": path, "change": "added"})
    for path in removed:
        bucket = (classify(path) and accepted) or violations
        bucket.append({"path": path, "change": "removed"})
    for entry in changed:
        name = Path(entry["path"]).name
        if name in CONTENT_EQUALITY_ONLY:
            violations.append({"path": entry["path"], "change": "content_changed"})
            continue
        bucket = (classify(entry["path"]) and accepted) or violations
        bucket.append({"path": entry["path"], "change": "metadata_changed"})

    return {
        "added": added,
        "removed": removed,
        "changed": [c["path"] for c in changed],
        "accepted_residual": accepted,
        "violations": violations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--i-understand-this-touches-my-real-home",
        action="store_true",
        help="Required. Confirms you intend to run 21 real verify-codex "
        "invocations against your actual ~/.codex and real codex binary.",
    )
    parser.add_argument("--runs", type=int, default=21)
    parser.add_argument(
        "--host-trust-exec",
        default=None,
        help="Path to the fornax-host-trust-exec binary. Defaults to "
        "looking for it on PATH, then a freshly-built workspace target.",
    )
    args = parser.parse_args()

    if not args.i_understand_this_touches_my_real_home:
        print(
            "Refusing to run without --i-understand-this-touches-my-real-home. "
            "This script runs real verify-codex invocations against your actual "
            "~/.codex and spawns your real codex app-server repeatedly.",
            file=sys.stderr,
        )
        return 2

    home = Path.home()
    codex_home = home / ".codex"
    binary = args.host_trust_exec or shutil.which("fornax-host-trust-exec")
    if not binary:
        print("fornax-host-trust-exec not found on PATH; pass --host-trust-exec <path>", file=sys.stderr)
        return 2

    evidence: dict = {
        "schema_version": 1,
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "macos_version": platform.mac_ver()[0],
    }

    codex_on_path = shutil.which("codex")
    pids_before_anything = codex_app_server_pids()
    evidence["preconditions"] = {
        "codex_on_path": bool(codex_on_path),
        "codex_version": sanitize(run([codex_on_path, "--version"]).stdout.strip(), home)
        if codex_on_path
        else None,
        "app_server_process_count_before": len(pids_before_anything),
    }

    before = snapshot(codex_home)

    runs = []
    run_ok_flags = []
    unexplained_pid_counts = []
    timed_out = False
    for i in range(args.runs):
        start = datetime.datetime.now()
        try:
            proc, unexplained_pids = run_verify_once(binary, timeout=30)
        except ChildProcessTimeout as e:
            timed_out = True
            run_ok_flags.append(False)
            runs.append({"index": i, "exit_code": None, "wall_clock_ms": None, "result": {"_timeout": True}})
            print(f"ABORTING remaining runs: {e}", file=sys.stderr)
            break
        elapsed_ms = (datetime.datetime.now() - start).total_seconds() * 1000
        unexplained_pid_counts.append(len(unexplained_pids))
        try:
            raw_parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            # Anomalous: verify-codex is specified to always emit JSON on
            # --json. Bounded diagnostic only (requirement 6) -- a length
            # and a digest, never the raw text itself, however short a
            # cap might be.
            parsed = {
                "_parse_error": True,
                "stdout_length": len(proc.stdout),
                "stdout_sha256": hashlib.sha256(proc.stdout.encode("utf-8", "replace")).hexdigest(),
            }
            run_ok_flags.append(False)
            assert_run_result_allowed(parsed, f"evidence.runs[{i}].result")
            runs.append(
                {
                    "index": i,
                    "exit_code": proc.returncode,
                    "wall_clock_ms": round(elapsed_ms, 1),
                    "result": parsed,
                    "unexplained_app_server_pid_count": len(unexplained_pids),
                }
            )
            print("ABORTING remaining runs: verify-codex returned non-JSON stdout", file=sys.stderr)
            break

        failure_reason = validate_run_structure(raw_parsed, proc.returncode)
        if failure_reason is not None:
            # Fail-closed (requirement 3): a structurally/semantically
            # invalid run is a finding on ITS OWN, including -- and this
            # is the exact gap that was found -- when it's the very last
            # of the `--runs` requested, where a length-based check alone
            # would not have noticed.
            parsed = {"_structural_failure": True, "reason": failure_reason}
            run_ok_flags.append(False)
            assert_run_result_allowed(parsed, f"evidence.runs[{i}].result")
            runs.append(
                {
                    "index": i,
                    "exit_code": proc.returncode,
                    "wall_clock_ms": round(elapsed_ms, 1),
                    "result": parsed,
                    "unexplained_app_server_pid_count": len(unexplained_pids),
                }
            )
            print(f"ABORTING remaining runs: run {i} failed structural validation ({failure_reason})", file=sys.stderr)
            break

        parsed = redact_verify_result(raw_parsed)
        run_ok_flags.append(True)
        assert_run_result_allowed(parsed, f"evidence.runs[{i}].result")
        runs.append(
            {
                "index": i,
                "exit_code": proc.returncode,
                "wall_clock_ms": round(elapsed_ms, 1),
                "result": parsed,
                "unexplained_app_server_pid_count": len(unexplained_pids),
            }
        )

    after = snapshot(codex_home)
    pids_after_all = codex_app_server_pids()
    evidence["app_server_process_count_after"] = len(pids_after_all)
    total_unexplained = sum(unexplained_pid_counts)
    # Diagnostic only -- never grounds for having killed anything (see
    # `run_verify_once`/`codex_app_server_pids`). A nonzero count here
    # means a human should look at what else was running, not that a
    # kill happened or should have.
    evidence["process_ownership_check"] = {
        "runs_completed": len(unexplained_pid_counts),
        "unexplained_app_server_pid_count_per_run": unexplained_pid_counts,
        "total_unexplained_app_server_pids": total_unexplained,
        "timed_out": timed_out,
    }
    all_runs_structurally_ok = bool(run_ok_flags) and all(run_ok_flags) and len(runs) == args.runs
    evidence["runs"] = runs
    evidence["first_run"] = runs[0] if runs else None
    timings = [r["result"].get("timing_ms", {}).get("total_ms") for r in runs if "result" in r]
    timings = [t for t in timings if isinstance(t, (int, float))]
    if timings:
        sorted_t = sorted(timings)
        evidence["latency_ms"] = {
            "samples": sorted_t,
            "min": sorted_t[0],
            "median": sorted_t[len(sorted_t) // 2],
            "p95": sorted_t[int(len(sorted_t) * 0.95)] if len(sorted_t) > 1 else sorted_t[0],
            "max": sorted_t[-1],
        }

    diff = diff_snapshots(before, after)
    evidence["snapshot_diff"] = diff
    evidence["snapshot_before"] = strip_internal_contents(before)
    evidence["snapshot_after"] = strip_internal_contents(after)
    evidence["violations_found"] = (
        len(diff["violations"]) > 0 or total_unexplained > 0 or timed_out or not all_runs_structurally_ok
    )

    assert_no_raw_bytes(evidence)
    assert_allowed_keys(evidence, ALLOWED_EVIDENCE_KEYS)

    out_dir = Path(__file__).resolve().parents[3] / "docs" / "security" / "evidence"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"fornx-450-host-trust-real-home-{datetime.date.today().isoformat()}.json"
    # No `default=str` fallback: this evidence file may have had
    # config.toml/hooks.json/installation_id bytes pass through earlier
    # processing (see `_contents_for_internal_diff_only`). `default=str`
    # would silently stringify any stray `bytes` object that escaped
    # `strip_internal_contents` instead of failing loudly -- exactly the
    # "fails open" shape this campaign has already found and fixed twice
    # elsewhere (HORO-1902/HORO-1903). A strict dump turns that class of
    # bug into an immediate `TypeError` here, caught by
    # `assert_no_raw_bytes` just above with a clearer message first.
    out_path.write_text(json.dumps(evidence, indent=2))

    print(f"Evidence written to {out_path}")
    if total_unexplained > 0 or timed_out:
        print(
            f"UNEXPLAINED APP-SERVER PID(S): {total_unexplained} observed across "
            f"{len(unexplained_pid_counts)} completed run(s); timed_out={timed_out}. "
            "Diagnostic only -- nothing was killed based on this; inspect manually.",
            file=sys.stderr,
        )
    if not all_runs_structurally_ok:
        print(
            f"STRUCTURAL/FAIL-CLOSED CHECK FAILED: {len(runs)}/{args.runs} runs completed, "
            f"ok={run_ok_flags} -- see each run's result for the specific reason",
            file=sys.stderr,
        )
    if diff["violations"]:
        print(f"VIOLATIONS FOUND ({len(diff['violations'])}): {diff['violations']}", file=sys.stderr)
    if evidence["violations_found"]:
        return 1
    print("No violations found. accepted_residual writes:", diff["accepted_residual"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
