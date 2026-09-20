#!/usr/bin/env bats
# Tests for scripts/release-post-verify.sh (FORNX-236).
#
# Every git/gh/cargo/curl call in the script lives behind a function; these
# tests put fake binaries (tests/release-post-verify/fakebin/) ahead of the
# real ones on PATH and exercise the actual production code path — no live
# network, GitHub, or real cargo build happens here. The fake `cargo` writes
# small executable stub binaries so the script's own --version/status smoke
# checks run for real against those stand-ins.

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../../scripts/release-post-verify.sh"
  F="${BATS_TEST_DIRNAME}/fixtures/happy"
  FAKEBIN="${BATS_TEST_DIRNAME}/fakebin"
  export PATH="${FAKEBIN}:${PATH}"
  export FAKE_GH_LOG="$(mktemp)"
  export FAKE_GIT_LOG="$(mktemp)"
  export FAKE_CARGO_LOG="$(mktemp)"
  export FAKE_CURL_LOG="$(mktemp)"
  WORKDIR="$(mktemp -d)"
  EVIDENCE_OUT="$(mktemp)"
  unset FAKE_RELEASE_EXISTS FAKE_CLONE_FAIL FAKE_CLONE_SHA FAKE_SOURCE_VERSION \
    FAKE_CARGO_FAIL FAKE_BUILT_VERSION FAKE_STARTUP_FAIL FAKE_SKIP_DAEMON_BINARY \
    FAKE_EXTRA_BINARY FAKE_CANARY_HTTP_CODE || true
  export FAKE_RELEASE_EXISTS=true
  export FAKE_CLONE_SHA="abcdef1234567890abcdef1234567890abcdef12"
  export FAKE_SOURCE_VERSION="0.0.1"
  export FAKE_BUILT_VERSION="0.0.1"
}

teardown() {
  rm -rf "$WORKDIR"
  rm -f "$EVIDENCE_OUT" "$FAKE_GH_LOG" "$FAKE_GIT_LOG" "$FAKE_CARGO_LOG" "$FAKE_CURL_LOG"
}

run_ok() {
  run bash "$SCRIPT" "${F}/manifest.json" \
    --release-evidence "${F}/release-evidence.json" \
    --evidence-out "$EVIDENCE_OUT" --workdir "$WORKDIR" "$@"
}

# --- happy path -----------------------------------------------------------

@test "happy path: exit 0, HEALTHY, promotion allowed" {
  run_ok
  [ "$status" -eq 0 ]
  jq -e '.overall == "PASS"' "$EVIDENCE_OUT"
  jq -e '.release_health == "HEALTHY"' "$EVIDENCE_OUT"
  jq -e '.promotion_allowed == true' "$EVIDENCE_OUT"
  jq -e '.artifact.resolved_sha == "abcdef1234567890abcdef1234567890abcdef12"' "$EVIDENCE_OUT"
}

@test "happy path: dispositioned UNTESTED rows do not block overall PASS" {
  run_ok
  [ "$status" -eq 0 ]
  jq -e '.checks[] | select(.name=="smoke.api_db_journey" and .status=="UNTESTED" and .dispositioned==true)' "$EVIDENCE_OUT"
  jq -e '.checks[] | select(.name=="canary.hosted" and .status=="UNTESTED" and .dispositioned==true)' "$EVIDENCE_OUT"
}

# --- AC: negative fixture proves detection of a wrong artifact ------------

@test "wrong built version is detected: exit 1, BLOCK, UNHEALTHY, promotion false" {
  export FAKE_BUILT_VERSION="0.0.2"
  run_ok
  [ "$status" -eq 1 ]
  jq -e '.overall == "BLOCK"' "$EVIDENCE_OUT"
  jq -e '.release_health == "UNHEALTHY"' "$EVIDENCE_OUT"
  jq -e '.promotion_allowed == false' "$EVIDENCE_OUT"
  jq -e '.checks[] | select(.name=="smoke.version_identity" and .status=="BLOCK")' "$EVIDENCE_OUT"
  jq -e '.recovery.failing_checks | index("smoke.version_identity")' "$EVIDENCE_OUT"
}

@test "wrong clone sha is a hard fail on tag identity" {
  export FAKE_CLONE_SHA="1111111111111111111111111111111111111111"
  run_ok
  [ "$status" -eq 1 ]
  jq -e '.checks[] | select(.name=="artifact.tag_identity" and .status=="BLOCK")' "$EVIDENCE_OUT"
  jq -e '.release_health == "UNHEALTHY"' "$EVIDENCE_OUT"
}

# --- preconditions ----------------------------------------------------------

@test "no published GitHub Release: exit 3, no clone attempted" {
  export FAKE_RELEASE_EXISTS=false
  run_ok
  [ "$status" -eq 3 ]
  [ ! -s "$FAKE_GIT_LOG" ]
  jq -e '.checks[] | select(.name=="precondition.release_published" and .status=="BLOCK")' "$EVIDENCE_OUT"
}

@test "release-execute evidence not overall PASS: exit 3, no clone attempted" {
  run bash "$SCRIPT" "${F}/manifest.json" \
    --release-evidence "${F}/release-evidence-failed.json" \
    --evidence-out "$EVIDENCE_OUT" --workdir "$WORKDIR"
  [ "$status" -eq 3 ]
  [ ! -s "$FAKE_GIT_LOG" ]
}

# --- checksum coverage -------------------------------------------------------

@test "a release-execute-recorded binary missing from the clean build is a BLOCK" {
  export FAKE_SKIP_DAEMON_BINARY=true
  run_ok
  [ "$status" -eq 1 ]
  jq -e '.checks[] | select(.name=="checksum.coverage" and .status=="BLOCK" and (.detail | contains("fornax-daemon")))' "$EVIDENCE_OUT"
}

@test "an extra built binary not in the release record is recorded but does not block" {
  export FAKE_EXTRA_BINARY=true
  run_ok
  [ "$status" -eq 0 ]
  jq -e '.checks[] | select(.name=="checksum.coverage" and .status=="PASS")' "$EVIDENCE_OUT"
  jq -e '.checks[] | select(.name=="checksum.coverage") | .extra.extra_binaries | index("fornax-extra-tool")' "$EVIDENCE_OUT"
}

# --- canary ------------------------------------------------------------------

@test "canary probe 2xx: PASS, promotion allowed" {
  export FAKE_CANARY_HTTP_CODE=200
  run_ok --canary-url "https://example.invalid/health"
  [ "$status" -eq 0 ]
  jq -e '.checks[] | select(.name=="canary.hosted" and .status=="PASS")' "$EVIDENCE_OUT"
}

@test "canary probe 503 stops further promotion" {
  export FAKE_CANARY_HTTP_CODE=503
  run_ok --canary-url "https://example.invalid/health"
  [ "$status" -eq 1 ]
  jq -e '.checks[] | select(.name=="canary.hosted" and .status=="BLOCK")' "$EVIDENCE_OUT"
  jq -e '.promotion_allowed == false' "$EVIDENCE_OUT"
}

# --- mid-sequence build failure: truthful partial evidence -------------------

@test "clean build failure is a truthful partial record, never HEALTHY" {
  export FAKE_CARGO_FAIL=true
  run_ok
  [ "$status" -eq 1 ]
  jq -e '.overall == "BLOCK"' "$EVIDENCE_OUT"
  jq -e '.release_health != "HEALTHY"' "$EVIDENCE_OUT"
  jq -e '.checks[] | select(.name=="smoke.build" and .status=="BLOCK")' "$EVIDENCE_OUT"
  # checks that depend on a successful build must never appear
  run jq -e '.checks[] | select(.name=="smoke.version_identity")' "$EVIDENCE_OUT"
  [ "$status" -ne 0 ]
}

@test "clean context uses an isolated CARGO_TARGET_DIR under --workdir" {
  run_ok
  [ "$status" -eq 0 ]
  jq -e --arg w "$WORKDIR" '.artifact.cargo_target_dir | startswith($w)' "$EVIDENCE_OUT"
  grep -q "CARGO_TARGET_DIR=${WORKDIR}" "$FAKE_CARGO_LOG"
}

# --- usage -------------------------------------------------------------------

@test "missing --evidence-out is a usage error, exit 2" {
  run bash "$SCRIPT" "${F}/manifest.json" --release-evidence "${F}/release-evidence.json"
  [ "$status" -eq 2 ]
}

@test "missing manifest file is a usage error, exit 2" {
  run bash "$SCRIPT" "/nonexistent/manifest.json" \
    --release-evidence "${F}/release-evidence.json" --evidence-out "$EVIDENCE_OUT"
  [ "$status" -eq 2 ]
}

@test "missing --release-evidence file is a usage error, exit 2" {
  run bash "$SCRIPT" "${F}/manifest.json" \
    --release-evidence "/nonexistent/evidence.json" --evidence-out "$EVIDENCE_OUT"
  [ "$status" -eq 2 ]
}
