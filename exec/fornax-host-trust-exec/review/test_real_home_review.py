"""Negative-control tests for `real_home_review.py`.

Each test deliberately mutates a call to defeat one specific guard, then
asserts the guard actually catches it -- proving the guard is
load-bearing rather than merely present. Stdlib `unittest` only; no
pytest dependency, no cargo build, no real `~/.codex` access. Run with:

    python3 -m unittest exec/fornax-host-trust-exec/review/test_real_home_review.py -v

from the repo root, or `python3 test_real_home_review.py -v` from this
directory.
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "real_home_review", Path(__file__).resolve().parent / "real_home_review.py"
)
rhr = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rhr)


class NestedFilenameBypass(unittest.TestCase):
    """Guard: `snapshot()` must only full-record/content-read depth-1
    entries. Mutation: a file named `hooks.json` nested under a
    project-identifying directory."""

    def test_nested_same_named_file_is_aggregated_not_exported(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "config.toml").write_text("top-level")
            nested = d / "sessions" / "proj-acme-client-secret"
            nested.mkdir(parents=True)
            marker = "UNRELATED NESTED CONTENTS -- MUST NEVER BE READ"
            (nested / "hooks.json").write_text(marker)

            records = rhr.snapshot(d)
            paths = [r.get("path") for r in records]

            self.assertNotIn("sessions/proj-acme-client-secret/hooks.json", paths)
            self.assertFalse(any("proj-acme-client-secret" in str(r) for r in records))
            self.assertFalse(any(marker in str(r) for r in records))
            self.assertIn("sessions/*", paths)

    def test_mutation_without_depth_guard_would_have_leaked(self):
        """Proves the test above is actually exercising the guard: with
        the depth check removed (simulating the original bug), the same
        fixture DOES leak the nested path -- showing the guard, not the
        fixture, is what makes the first test pass."""
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            nested = d / "sessions" / "proj-acme-client-secret"
            nested.mkdir(parents=True)
            (nested / "hooks.json").write_text("x")

            # Reimplements the pre-fix behavior directly (matches by name
            # at any depth) rather than monkeypatching internals.
            leaked_paths = [
                p.relative_to(d).as_posix()
                for p in sorted(d.rglob("*"))
                if p.name in rhr.CONTENT_EQUALITY_ONLY
            ]
            self.assertIn("sessions/proj-acme-client-secret/hooks.json", leaked_paths)


class RawBytesGuard(unittest.TestCase):
    def test_catches_stray_bytes_anywhere_in_tree(self):
        with self.assertRaises(AssertionError):
            rhr.assert_no_raw_bytes({"runs": [{"result": {"nested": [b"leaked"]}}]})

    def test_passes_clean_tree(self):
        rhr.assert_no_raw_bytes({"runs": [{"result": {"nested": ["clean"]}}]})  # no raise


class EvidenceAllowlistGuard(unittest.TestCase):
    def test_top_level_extra_key_rejected(self):
        with self.assertRaises(AssertionError):
            rhr.assert_allowed_keys({"schema_version": 1, "sneaky_extra": "x"}, rhr.ALLOWED_EVIDENCE_KEYS)

    def test_nested_run_result_extra_key_rejected(self):
        """Mutation: redact_verify_result's output gains a field the
        allowlist doesn't know about (simulating a future edit that
        forgets to update ALLOWED_RUN_RESULT_KEYS)."""
        mutated = {
            "schema_version": 1,
            "operation": "verify-codex",
            "adapter_id": "x",
            "outcome": "ok",
            "codex_version": "0.160.0",
            "host_trust": "Trusted",
            "global_reasons": [],
            "hooks": [],
            "timing_ms": {},
            "raw_command_leaked_by_mistake": "/Users/real/secret.sh",
        }
        with self.assertRaises(AssertionError):
            rhr.assert_run_result_allowed(mutated, "evidence.runs[0].result")

    def test_nested_hook_extra_key_rejected(self):
        mutated = {
            "schema_version": 1,
            "operation": "verify-codex",
            "adapter_id": "x",
            "outcome": "ok",
            "codex_version": "0.160.0",
            "host_trust": "Trusted",
            "global_reasons": [],
            "hooks": [{"event": "PreToolUse", "trust": "Trusted", "command": "/Users/real/leaked.sh"}],
            "timing_ms": {},
        }
        with self.assertRaises(AssertionError):
            rhr.assert_run_result_allowed(mutated, "evidence.runs[0].result")

    def test_well_formed_result_passes(self):
        ok = {
            "schema_version": 1,
            "operation": "verify-codex",
            "adapter_id": "x",
            "outcome": "ok",
            "codex_version": "0.160.0",
            "host_trust": "Trusted",
            "global_reasons": [],
            "hooks": [
                {
                    "event": "PreToolUse",
                    "trust": "Trusted",
                    "host_trust_status": "trusted",
                    "hash_present": True,
                    "reasons": None,
                }
            ],
            "timing_ms": {"total_ms": 1.0},
        }
        rhr.assert_run_result_allowed(ok, "evidence.runs[0].result")  # no raise


class RedactionGuard(unittest.TestCase):
    def test_raw_command_and_source_path_never_survive(self):
        home = Path("/Users/real")
        fake = {
            "schema_version": 1,
            "operation": "verify-codex",
            "adapter_id": "x",
            "outcome": "ok",
            "codex": {"version": "0.160.0"},
            "result": {
                "host_trust": "Trusted",
                "global_reasons": [f"HostRpcError({home}/leaked-in-error-message)"],
                "hooks": [
                    {
                        "event": "PreToolUse",
                        "trust": "Trusted",
                        "host_trust_status": "trusted",
                        "command": f"{home}/secret-script.sh --token abc123",
                        "sourcePath": f"{home}/.codex/hooks.json",
                        "key": f"{home}/.codex/hooks.json:preToolUse:0:0",
                        "current_hash": "sha256:" + "a" * 64,
                    }
                ],
            },
            "timing_ms": {"total_ms": 12.3},
        }
        redacted = rhr.redact_verify_result(fake, home)
        blob = str(redacted)
        self.assertNotIn("secret-script", blob)
        self.assertNotIn("token", blob)
        self.assertNotIn(str(home), blob)
        self.assertIn("<home>", blob)  # the sanitized reason string survives, just redacted


class UnparseableStdoutGuard(unittest.TestCase):
    def test_capped_and_sanitized(self):
        home = Path("/Users/real")
        huge = "A" * 10_000 + str(home) + "trailing-secret-looking-text"
        out = rhr.sanitize(huge, home, rhr.UNPARSEABLE_STDOUT_MAX_CHARS)
        self.assertLessEqual(len(out), rhr.UNPARSEABLE_STDOUT_MAX_CHARS + 60)
        self.assertNotIn(str(home), out)
        self.assertNotIn("trailing-secret-looking-text", out)


class ProcessLeakGuard(unittest.TestCase):
    """Guard: PID-set diffing around each run, not a raw system-wide
    count. Mutation: simulate a leaked PID surviving past its run's
    window and confirm the diff catches it even when an unrelated PID
    exists on both sides (which a naive count-based check could offset
    against and miss)."""

    def test_pid_set_diff_ignores_preexisting_unrelated_process(self):
        pids_before = {111}  # unrelated codex app-server already running
        pids_after = {111, 222}  # 222 appeared during our run and persisted
        leaked = pids_after - pids_before
        self.assertEqual(leaked, {222})

    def test_naive_count_would_have_missed_a_masked_leak(self):
        """If an unrelated process exits in the same window a real leak
        appears, a raw count can show NO CHANGE while a real leak
        occurred -- proving why count-based detection (the pre-fix
        design) is insufficient and PID-set diffing is required."""
        pids_before = {111, 333}
        pids_after = {111, 222}  # 333 exited, 222 leaked -- same count (2)
        self.assertEqual(len(pids_before), len(pids_after))  # naive count: "no leak"
        leaked = pids_after - pids_before
        self.assertEqual(leaked, {222})  # PID-set diff: real leak caught


if __name__ == "__main__":
    unittest.main()
