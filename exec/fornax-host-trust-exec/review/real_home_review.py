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
  allowlist (`ALLOWED_EVIDENCE_KEYS`) right before the write -- an
  unexpected key fails the run instead of silently writing it.
- Checks owned-child process cleanup after EVERY run (not just once at
  the end): records the live `codex.*app-server` process count after each
  of the 21 runs and fails loudly if it ever grows, i.e. if
  `launch::teardown()` ever leaked a process.
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
import json
import os
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
    "process_leak_check",
}

def sanitize(text: str, home: Path) -> str:
    return text.replace(str(home), "<home>")


def assert_allowed_keys(obj: dict, allowed: set, _path: str = "evidence") -> None:
    extra = set(obj.keys()) - allowed
    assert not extra, f"evidence-output allowlist violated at {_path}: unexpected key(s) {sorted(extra)}"


def redact_verify_result(parsed: dict) -> dict:
    """Keeps only what's needed to confirm the trust verdict from one
    `verify-codex --json` run. Drops per-hook `command`/`sourcePath`/`key`
    -- those describe the operator's OWN configured hooks for any tool,
    not just Fornax's, and must not be exported verbatim."""
    if "_unparseable_stdout" in parsed:
        return parsed
    result = parsed.get("result") or {}
    redacted_hooks = []
    for h in result.get("hooks") or []:
        redacted_hooks.append(
            {
                "event": h.get("event"),
                "trust": h.get("trust"),
                "host_trust_status": h.get("host_trust_status"),
                "hash_present": bool(h.get("current_hash")),
                "reasons": h.get("reasons"),
            }
        )
    return {
        "schema_version": parsed.get("schema_version"),
        "operation": parsed.get("operation"),
        "adapter_id": parsed.get("adapter_id"),
        "outcome": parsed.get("outcome"),
        "codex_version": (parsed.get("codex") or {}).get("version"),
        "host_trust": result.get("host_trust"),
        "global_reasons": result.get("global_reasons"),
        "hooks": redacted_hooks,
        "timing_ms": parsed.get("timing_ms"),
    }


def run(cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def codex_app_server_count() -> int:
    try:
        out = run(["pgrep", "-f", "codex.*app-server"], timeout=5)
    except Exception:
        return -1
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    return len(lines)


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
    evidence["preconditions"] = {
        "codex_on_path": bool(codex_on_path),
        "codex_version": sanitize(run([codex_on_path, "--version"]).stdout.strip(), home)
        if codex_on_path
        else None,
        "app_server_process_count_before": codex_app_server_count(),
    }

    before = snapshot(codex_home)

    runs = []
    process_counts = [evidence["preconditions"]["app_server_process_count_before"]]
    leaked = False
    for i in range(args.runs):
        start = datetime.datetime.now()
        proc = run([binary, "verify-codex", "--json"], timeout=30)
        elapsed_ms = (datetime.datetime.now() - start).total_seconds() * 1000
        try:
            parsed = redact_verify_result(json.loads(proc.stdout))
        except json.JSONDecodeError:
            parsed = {"_unparseable_stdout": sanitize(proc.stdout, home)}
        count_after_run = codex_app_server_count()
        if count_after_run > max(process_counts):
            leaked = True
        process_counts.append(count_after_run)
        runs.append(
            {
                "index": i,
                "exit_code": proc.returncode,
                "wall_clock_ms": round(elapsed_ms, 1),
                "result": parsed,
                "app_server_process_count_after_this_run": count_after_run,
            }
        )

    after = snapshot(codex_home)
    evidence["app_server_process_count_after"] = codex_app_server_count()
    evidence["process_leak_check"] = {
        "samples": process_counts,
        "leak_detected": leaked,
    }
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
    evidence["violations_found"] = len(diff["violations"]) > 0 or leaked

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
    if leaked:
        print(
            f"PROCESS LEAK DETECTED: app-server count samples {process_counts} grew mid-run",
            file=sys.stderr,
        )
    if diff["violations"]:
        print(f"VIOLATIONS FOUND ({len(diff['violations'])}): {diff['violations']}", file=sys.stderr)
    if diff["violations"] or leaked:
        return 1
    print("No violations found. accepted_residual writes:", diff["accepted_residual"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
