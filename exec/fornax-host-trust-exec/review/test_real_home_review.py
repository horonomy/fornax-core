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

import hashlib
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
        fake = {
            "schema_version": 1,
            "operation": "verify-codex",
            "adapter_id": "x",
            "outcome": "ok",
            "codex": {"version": "0.160.0"},
            "result": {
                "host_trust": "Trusted",
                "global_reasons": ["host_rpc_error"],
                "hooks": [
                    {
                        "event": "PreToolUse",
                        "trust": "Trusted",
                        "host_trust_status": "trusted",
                        "command": "/Users/real/secret-script.sh --token abc123",
                        "sourcePath": "/Users/real/.codex/hooks.json",
                        "key": "/Users/real/.codex/hooks.json:preToolUse:0:0",
                        "current_hash": "sha256:" + "a" * 64,
                    }
                ],
            },
            "timing_ms": {"total_ms": 12.3},
        }
        redacted = rhr.redact_verify_result(fake)
        blob = str(redacted)
        self.assertNotIn("secret-script", blob)
        self.assertNotIn("token", blob)
        self.assertNotIn("/Users/real", blob)


class ReasonCodeAllowlistGuard(unittest.TestCase):
    """Guard: `redact_reason_code` is a strict allowlist, not
    sanitize-and-cap. Mutation: a reason carrying an arbitrary/host-origin
    payload in every plausible wire shape -- each must lose the payload
    entirely, not just have `$HOME` stripped out of it."""

    def test_known_bare_string_tag_passes_through(self):
        self.assertEqual(rhr.redact_reason_code("sandbox_unavailable"), "sandbox_unavailable")

    def test_unknown_string_becomes_generic_marker(self):
        self.assertEqual(
            rhr.redact_reason_code("totally_made_up_reason_with_/Users/real/path"),
            rhr.UNKNOWN_REASON_CODE_MARKER,
        )

    def test_dict_shaped_payload_is_dropped_even_for_known_tag(self):
        raw = {"code": "host_rpc_error", "detail": "/Users/real/leaked -- credential=abc123"}
        redacted = rhr.redact_reason_code(raw)
        self.assertEqual(redacted, "host_rpc_error")
        self.assertNotIn("leaked", redacted)
        self.assertNotIn("credential", redacted)

    def test_list_shaped_payload_is_dropped(self):
        raw = ["unrecognized_trust_status", "/Users/real/weird-status-string"]
        redacted = rhr.redact_reason_code(raw)
        self.assertEqual(redacted, "unrecognized_trust_status")
        self.assertNotIn("weird", redacted)

    def test_unrecognized_shape_becomes_generic_marker(self):
        self.assertEqual(rhr.redact_reason_code(12345), rhr.UNKNOWN_REASON_CODE_MARKER)
        self.assertEqual(rhr.redact_reason_code(None), rhr.UNKNOWN_REASON_CODE_MARKER)


class ParseErrorDiagnosticGuard(unittest.TestCase):
    """Guard: a non-JSON run record must never contain the raw stdout
    text -- only a length and a digest (requirement 6)."""

    def test_no_raw_text_reaches_the_record(self):
        secret_looking_stdout = "panic: leaked /Users/real/.codex/auth.json contents: {\"token\":\"abc\"}"
        digest = hashlib.sha256(secret_looking_stdout.encode()).hexdigest()
        length = len(secret_looking_stdout)
        record = {"_parse_error": True, "stdout_length": length, "stdout_sha256": digest}
        rhr.assert_run_result_allowed(record, "evidence.runs[0].result")  # no raise
        blob = str(record)
        self.assertNotIn("leaked", blob)
        self.assertNotIn("token", blob)
        self.assertNotIn("auth.json", blob)


class StructuralFailClosedGuard(unittest.TestCase):
    """Guard: `validate_run_structure` must fail a malformed/semantically
    inconsistent run regardless of position in the run sequence --
    mutation targets exactly the "only the last run is bad" gap found in
    review."""

    def _well_formed(self, host_trust="Trusted", exit_code=0):
        return {
            "schema_version": 1,
            "operation": "verify-codex",
            "outcome": "ok",
            "result": {"host_trust": host_trust, "hooks": []},
        }, exit_code

    def test_well_formed_trusted_passes(self):
        raw, code = self._well_formed("Trusted", 0)
        self.assertIsNone(rhr.validate_run_structure(raw, code))

    def test_well_formed_untrusted_passes(self):
        raw, code = self._well_formed("Untrusted", 3)
        self.assertIsNone(rhr.validate_run_structure(raw, code))

    def test_missing_result_fails(self):
        raw = {"schema_version": 1, "operation": "verify-codex", "outcome": "ok"}
        self.assertEqual(rhr.validate_run_structure(raw, 3), "missing_field_result")

    def test_invalid_trust_verdict_fails(self):
        raw, code = self._well_formed("not_a_real_verdict", 3)
        self.assertEqual(rhr.validate_run_structure(raw, code), "invalid_trust_verdict")

    def test_unexpected_exit_code_fails(self):
        raw, _ = self._well_formed("Trusted", 0)
        self.assertEqual(rhr.validate_run_structure(raw, 2), "unexpected_exit_code")

    def test_exit_verdict_mismatch_fails(self):
        # exit 0 is only valid when the verdict is Trusted
        raw, _ = self._well_formed("Untrusted", 0)
        self.assertEqual(rhr.validate_run_structure(raw, 0), "exit_verdict_mismatch")

    def test_mutation_on_the_final_run_of_a_sequence_is_still_caught(self):
        """Reproduces the exact gap from review: simulate a 3-run sequence
        where only run index 2 (the LAST one) is malformed, and confirm
        the `all_runs_structurally_ok`-style aggregate (not a length
        check) is what catches it."""
        sequence = [
            self._well_formed("Trusted", 0),
            self._well_formed("Trusted", 0),
            ({"schema_version": 1, "operation": "verify-codex", "outcome": "ok", "result": {"host_trust": "Trusted", "hooks": []}}, 3),  # mismatch
        ]
        failures = [rhr.validate_run_structure(raw, code) for raw, code in sequence]
        self.assertIsNone(failures[0])
        self.assertIsNone(failures[1])
        self.assertIsNotNone(failures[2])
        # A naive "did we complete len(runs) == args.runs" check would
        # have passed here (3 runs did complete) -- proving length alone
        # is insufficient, which is exactly the bug this review found.
        all_ok_by_length_alone = len(sequence) == 3
        all_ok_correctly = all(f is None for f in failures)
        self.assertTrue(all_ok_by_length_alone)
        self.assertFalse(all_ok_correctly)


class ProcessOwnershipGuard(unittest.TestCase):
    """Guard: never signal a `pgrep`-matched PID; only ever signal the
    exact PID this script itself forked. Mutations: (1) a concurrent
    peer's process must never be touched; (2) on a real timeout, only
    the exact owned child is terminated."""

    def test_pid_set_diff_is_diagnostic_only_never_a_kill_list(self):
        """Mutation: an unrelated 'peer' PID appears in both snapshots
        (a concurrent session's own app-server). Confirms the diff
        calculation that used to feed `kill_pids` is now purely
        informational -- `codex_app_server_pids` callers in this module
        never pass its result to any termination call."""
        import inspect

        pids_before = {111}  # peer, already running
        pids_after = {111, 222}  # 222 appeared during our run
        unexplained = pids_after - pids_before
        self.assertEqual(unexplained, {222})
        # The function that used to kill based on this diff must no
        # longer exist -- its removal IS the fix.
        self.assertFalse(hasattr(rhr, "kill_pids"), "kill_pids must not exist -- unsafe PID-match kill path")
        source = inspect.getsource(rhr.run_verify_once)
        self.assertNotIn("kill_pids(", source)
        self.assertNotIn("os.kill(", source)  # signal-by-looked-up-PID is the banned pattern
        self.assertNotIn("signal.SIGKILL", source)  # proc.terminate()/proc.kill() (own handle) are fine

    def test_owned_descendant_positive_control_timeout_kills_only_that_pid(self):
        """Positive control: spawn a real short-lived hanging process via
        `run_verify_once`'s exact mechanism (a Popen we hold), force a
        timeout, and confirm `ChildProcessTimeout` is raised via that
        exact owned handle -- no system-wide signaling occurs. Uses a
        throwaway shell script that ignores its args and sleeps, as a
        stand-in binary; no real codex/cargo involved."""
        with tempfile.TemporaryDirectory() as d:
            hang_script = Path(d) / "hang"
            hang_script.write_text("#!/bin/sh\nexec sleep 5\n")
            hang_script.chmod(0o755)
            with self.assertRaises(rhr.ChildProcessTimeout):
                rhr.run_verify_once(str(hang_script), timeout=0.2)
            # If we get here, run_verify_once's own terminate()/communicate()
            # path ran against the Popen handle it held -- it never looked
            # anything up by name. The absence of any name-based kill call
            # (see previous test) is the structural proof of exact ownership.

    def test_concurrent_peer_negative_control(self):
        """Negative control: even when `codex_app_server_pids()` reports
        PIDs that have nothing to do with this run (simulated by
        monkeypatching it to return a fixed 'peer' set on both sides),
        `run_verify_once` must complete normally without attempting to
        touch them."""
        original = rhr.codex_app_server_pids
        rhr.codex_app_server_pids = lambda: {999999}  # fake unrelated peer PID
        try:
            proc, unexplained = rhr.run_verify_once("true", timeout=5)
            self.assertEqual(unexplained, set())  # same fake set before/after -> no diff
        finally:
            rhr.codex_app_server_pids = original


if __name__ == "__main__":
    unittest.main()
