#!/usr/bin/env bash
# release-post-verify.sh — FORNX-236
#
# Verifies the version users actually RECEIVE after publication — a fresh
# clone of the published tag built in an isolated context — never the build
# workspace release-execute.sh (FORNX-235) used to publish it. Base/candidate
# truth (release-readiness.sh, FORNX-234) and published truth (this script)
# are two different directions; this script checks the second one.
#
# This script deliberately DOES NOT call release-readiness.sh. A green
# pre-release QA/security gate must never, by itself, produce a HEALTHY
# post-release verdict — that is the "no fake PASS" property this ticket's
# AC requires (see docs/release-post-verify.md).
#
# Usage:
#   release-post-verify.sh <manifest.json> --release-evidence <path> \
#       --evidence-out <path> [--workdir <dir>] [--canary-url <url>] \
#       [--repo <owner>/<name>]
#
# <manifest.json>        The candidate manifest (release/candidate-manifest.schema.json).
# --release-evidence      The FORNX-235 release-execute.sh --evidence-out file —
#                         the release execution record this script verifies
#                         the published artifact's identity/checksums against.
# --evidence-out          REQUIRED. Where the durable post-verify evidence is
#                         written — this is what makes the result linkable
#                         from Jira/Release Notes (AC: durable + linkable).
# --workdir               Clean working directory for the independent clone
#                         and build. Defaults to a fresh mktemp -d. Never the
#                         repo checkout this script itself lives in.
# --canary-url            Optional. A single HTTP health probe used as the
#                         hosted-canary gate. Omitted -> UNTESTED (dispositioned)
#                         since fornax-core ships local binaries only today.
# --repo                  Optional. owner/name of the canonical release repo.
#                         Defaults to horonomy/fornax-core (test-only override).
#
# Exit codes:
#   0   overall == PASS  -> release_health HEALTHY, promotion_allowed:true
#   1   overall == BLOCK | INCONCLUSIVE | undispositioned UNTESTED
#   2   usage/input error (bad args, missing jq/git/gh, unreadable manifest
#       or --release-evidence, missing --evidence-out)
#   3   precondition refusal: nothing was actually released to verify — no
#       published GitHub Release for this version, or the release-execute
#       evidence itself isn't overall PASS
#
# THIS SCRIPT NEVER CALLS JIRA and never calls release-readiness.sh.

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

EXIT_FAILED=1
EXIT_USAGE=2
EXIT_NOT_RELEASED=3

usage() {
  cat >&2 <<EOF
Usage:
  ${SCRIPT_NAME} <manifest.json> --release-evidence <path> --evidence-out <path> \\
      [--workdir <dir>] [--canary-url <url>] [--repo <owner>/<name>]
EOF
  exit "$EXIT_USAGE"
}

MANIFEST=""
RELEASE_EVIDENCE=""
EVIDENCE_OUT=""
WORKDIR=""
CANARY_URL=""
REPO_ARG=""

while [ $# -gt 0 ]; do
  case "$1" in
    --release-evidence) RELEASE_EVIDENCE="${2:-}"; shift 2 ;;
    --evidence-out) EVIDENCE_OUT="${2:-}"; shift 2 ;;
    --workdir) WORKDIR="${2:-}"; shift 2 ;;
    --canary-url) CANARY_URL="${2:-}"; shift 2 ;;
    --repo) REPO_ARG="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *)
      if [ -z "$MANIFEST" ]; then
        MANIFEST="$1"; shift
      else
        usage
      fi
      ;;
  esac
done

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit "$EXIT_USAGE"; }
command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit "$EXIT_USAGE"; }
command -v gh >/dev/null 2>&1 || { echo "gh is required" >&2; exit "$EXIT_USAGE"; }
if [ -n "$CANARY_URL" ]; then
  command -v curl >/dev/null 2>&1 || { echo "curl is required for --canary-url" >&2; exit "$EXIT_USAGE"; }
fi

[ -n "$MANIFEST" ] || usage
[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit "$EXIT_USAGE"; }
jq empty "$MANIFEST" 2>/dev/null || { echo "manifest is not valid JSON" >&2; exit "$EXIT_USAGE"; }
[ -n "$RELEASE_EVIDENCE" ] || usage
[ -f "$RELEASE_EVIDENCE" ] || { echo "release-evidence file not found: $RELEASE_EVIDENCE" >&2; exit "$EXIT_USAGE"; }
jq empty "$RELEASE_EVIDENCE" 2>/dev/null || { echo "release-evidence is not valid JSON" >&2; exit "$EXIT_USAGE"; }
[ -n "$EVIDENCE_OUT" ] || { echo "--evidence-out is required" >&2; exit "$EXIT_USAGE"; }

VERSION="$(jq -r '.version // empty' "$MANIFEST")"
[ -n "$VERSION" ] || { echo "manifest has no \"version\" field" >&2; exit "$EXIT_USAGE"; }
VERSION_NO_V="${VERSION#v}"

if [ -n "$REPO_ARG" ]; then
  REPO_OWNER="${REPO_ARG%%/*}"
  REPO_NAME="${REPO_ARG##*/}"
else
  REPO_OWNER="horonomy"
  REPO_NAME="fornax-core"
fi

EXPECTED_SHA="$(jq -r --arg n "$REPO_NAME" '.repos[]? | select(.name==$n) | .sha' "$MANIFEST")"
[ -n "$EXPECTED_SHA" ] || { echo "manifest has no repo entry named ${REPO_NAME}" >&2; exit "$EXIT_USAGE"; }

WORKDIR="${WORKDIR:-$(mktemp -d)}"
CARGO_TARGET_DIR="${WORKDIR}/target"
CLONE_DIR="${WORKDIR}/src"

# ---------------------------------------------------------------------------
# Evidence recording — flushed after every check so a mid-sequence stop still
# leaves a truthful record. release_health is derived purely from `overall`
# at the moment of the LAST flush: PASS -> HEALTHY is unreachable except by
# every check resolving PASS or dispositioned-UNTESTED — this is the
# mechanism behind "failure never gets reported as healthy" (AC).
# ---------------------------------------------------------------------------

STEPS_FILE="$(mktemp)"
EVIDENCE_TMP="$(mktemp)"
cleanup() { rm -f "$STEPS_FILE" "$EVIDENCE_TMP"; }
trap cleanup EXIT
: > "$STEPS_FILE"

ARTIFACT_JSON="$(jq -n \
  --arg repo "${REPO_OWNER}/${REPO_NAME}" --arg tag "$VERSION" \
  --arg expected_sha "$EXPECTED_SHA" --arg workdir "$WORKDIR" \
  --arg cargo_target_dir "$CARGO_TARGET_DIR" \
  '{repo:$repo, tag:$tag, source:"published_tag_clone", expected_sha:$expected_sha, resolved_sha:null, workdir:$workdir, cargo_target_dir:$cargo_target_dir}')"

set_artifact_field() {
  ARTIFACT_JSON="$(jq --arg k "$1" --arg v "$2" '.[$k]=$v' <<<"$ARTIFACT_JSON")"
}

compute_overall() {
  jq -s -r '
    if length==0 then "UNTESTED"
    elif any(.[]; .status=="BLOCK") then "BLOCK"
    elif any(.[]; .status=="INCONCLUSIVE") then "INCONCLUSIVE"
    elif any(.[]; .status=="UNTESTED" and (.dispositioned|not)) then "UNTESTED"
    else "PASS" end
  ' "$STEPS_FILE" 2>/dev/null || echo "UNTESTED"
}

release_health_for() {
  case "$1" in
    PASS) echo "HEALTHY" ;;
    BLOCK) echo "UNHEALTHY" ;;
    *) echo "PUBLISHED_PENDING_VERIFICATION" ;;
  esac
}

flush_evidence() {
  local overall release_health promotion_allowed recovery_json
  overall="$(compute_overall)"
  release_health="$(release_health_for "$overall")"
  if [ "$overall" = "PASS" ]; then promotion_allowed="true"; else promotion_allowed="false"; fi

  recovery_json="null"
  if [ "$overall" != "PASS" ]; then
    recovery_json="$(jq -n --arg version "$VERSION" \
      --slurpfile steps "$STEPS_FILE" \
      '{
        failing_checks: [$steps[] | select(.status=="BLOCK" or .status=="INCONCLUSIVE" or (.status=="UNTESTED" and (.dispositioned|not))) | .name],
        next_step: ("Stop promotion/announcement. File/link a Bug against this release. If the published artifact is confirmed bad, run: scripts/release-execute.sh --yank " + $version + " --reason \"<failing check>\" (never move/delete the tag). Re-run release-post-verify.sh after a corrective release.")
      }')"
  fi

  jq -n \
    --arg mode "post-verify" \
    --arg version "$VERSION" \
    --arg overall "$overall" \
    --arg release_health "$release_health" \
    --argjson promotion_allowed "$promotion_allowed" \
    --argjson artifact "$ARTIFACT_JSON" \
    --argjson recovery "$recovery_json" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --slurpfile steps "$STEPS_FILE" \
    '{mode:$mode, version:$version, overall:$overall, release_health:$release_health,
      promotion_allowed:$promotion_allowed, artifact:$artifact, recovery:$recovery,
      timestamp:$timestamp, checks:$steps}' > "$EVIDENCE_TMP"
  cp "$EVIDENCE_TMP" "$EVIDENCE_OUT"
}

add_check() {
  # add_check <name> <PASS|BLOCK|INCONCLUSIVE|UNTESTED> <true|false dispositioned> <detail> [extra_json]
  local name="$1" status="$2" dispositioned="$3" detail="$4" extra="${5:-null}"
  jq -nc --arg name "$name" --arg status "$status" --argjson dispositioned "$dispositioned" \
    --arg detail "$detail" --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson extra "$extra" \
    '{name:$name,status:$status,dispositioned:$dispositioned,detail:$detail,timestamp:$timestamp,extra:$extra}' >> "$STEPS_FILE"
  flush_evidence
}

step_failed() {
  echo "FAILED: $1" >&2
  flush_evidence
  cat "$EVIDENCE_TMP"
  exit "$2"
}

# ---------------------------------------------------------------------------
# External-system operations — every git/gh/curl call lives in one of these
# functions so tests can substitute fake binaries earlier on PATH.
# ---------------------------------------------------------------------------

gh_release_exists() { gh release view "$1" --repo "$2" >/dev/null 2>&1; }

clone_published_tag() {
  # clone_published_tag <owner> <repo> <tag> <dest>
  git clone --depth 1 --branch "$3" "https://github.com/$1/$2" "$4" >/dev/null 2>&1
}

resolve_clone_sha() { git -C "$1" rev-parse HEAD 2>/dev/null; }

build_clean_workspace() {
  # build_clean_workspace <clone_dir> <cargo_target_dir>
  ( cd "$1" && CARGO_TARGET_DIR="$2" cargo build --release --workspace )
}

extract_cargo_workspace_version() {
  # extract_cargo_workspace_version <Cargo.toml path>
  awk '
    /^\[workspace\.package\]/ { f=1; next }
    /^\[/ { f=0 }
    f && /^version[ \t]*=/ {
      sub(/^version[ \t]*=[ \t]*/, "");
      gsub(/["'"'"']/, "");
      gsub(/[ \t]+$/, "");
      print; exit
    }
  ' "$1" 2>/dev/null
}

curl_probe_status() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null || echo "000"
}

# ---------------------------------------------------------------------------
# Preconditions — fail-fast with exit 3: nothing was actually released to
# verify, so there is nothing yet to call HEALTHY or UNHEALTHY.
# ---------------------------------------------------------------------------

if gh_release_exists "$VERSION" "${REPO_OWNER}/${REPO_NAME}"; then
  add_check "precondition.release_published" "PASS" false "GitHub Release ${VERSION} found on ${REPO_OWNER}/${REPO_NAME}"
else
  add_check "precondition.release_published" "BLOCK" false "no GitHub Release ${VERSION} found on ${REPO_OWNER}/${REPO_NAME} — nothing to post-verify"
  step_failed "no published release to verify" "$EXIT_NOT_RELEASED"
fi

RE_MODE="$(jq -r '.mode // empty' "$RELEASE_EVIDENCE")"
RE_OVERALL="$(jq -r '.overall // empty' "$RELEASE_EVIDENCE")"
if [ "$RE_MODE" = "execute" ] && [ "$RE_OVERALL" = "PASS" ]; then
  add_check "precondition.release_execute_pass" "PASS" false "release-execute.sh evidence is mode=execute overall=PASS"
else
  add_check "precondition.release_execute_pass" "BLOCK" false "release-execute.sh evidence is not a successful execute run (mode=${RE_MODE:-<missing>}, overall=${RE_OVERALL:-<missing>})"
  step_failed "release-execute evidence does not show a successful release" "$EXIT_NOT_RELEASED"
fi

# ---------------------------------------------------------------------------
# Clean fetch + identity — a fresh clone of the published tag, never this
# checkout or the build workspace release-execute.sh used.
# ---------------------------------------------------------------------------

if clone_published_tag "$REPO_OWNER" "$REPO_NAME" "$VERSION" "$CLONE_DIR"; then
  add_check "artifact.clean_fetch" "PASS" false "cloned published tag ${VERSION} from ${REPO_OWNER}/${REPO_NAME} into ${CLONE_DIR} (depth 1, independent of the build workspace)"
else
  add_check "artifact.clean_fetch" "BLOCK" false "failed to clone published tag ${VERSION} from ${REPO_OWNER}/${REPO_NAME}"
  step_failed "clean clone failed" "$EXIT_FAILED"
fi

RESOLVED_SHA="$(resolve_clone_sha "$CLONE_DIR")"
set_artifact_field "resolved_sha" "$RESOLVED_SHA"
if [ -n "$RESOLVED_SHA" ] && [ "$RESOLVED_SHA" = "$EXPECTED_SHA" ]; then
  add_check "artifact.tag_identity" "PASS" false "published tag ${VERSION} resolves to ${RESOLVED_SHA}, matching the candidate manifest"
else
  add_check "artifact.tag_identity" "BLOCK" false "published tag ${VERSION} resolves to ${RESOLVED_SHA:-<unknown>}, expected ${EXPECTED_SHA} per the candidate manifest — wrong artifact"
  step_failed "tag identity mismatch" "$EXIT_FAILED"
fi

SOURCE_VERSION="$(extract_cargo_workspace_version "${CLONE_DIR}/Cargo.toml")"
if [ "$SOURCE_VERSION" = "$VERSION_NO_V" ]; then
  add_check "artifact.source_version_identity" "PASS" false "clean-cloned Cargo.toml [workspace.package] version is ${SOURCE_VERSION}, matching ${VERSION}"
else
  add_check "artifact.source_version_identity" "BLOCK" false "clean-cloned Cargo.toml [workspace.package] version is ${SOURCE_VERSION:-<unreadable>}, expected ${VERSION_NO_V}"
  step_failed "source version identity mismatch" "$EXIT_FAILED"
fi

# ---------------------------------------------------------------------------
# Build in the clean context — CARGO_TARGET_DIR is forced under $WORKDIR so
# this never reuses the shared build workspace and never falsifies isolation.
# ---------------------------------------------------------------------------

if build_clean_workspace "$CLONE_DIR" "$CARGO_TARGET_DIR"; then
  add_check "smoke.build" "PASS" false "cargo build --release --workspace succeeded in the clean clone (CARGO_TARGET_DIR=${CARGO_TARGET_DIR})"
else
  add_check "smoke.build" "BLOCK" false "cargo build --release --workspace failed in the clean clone"
  step_failed "clean build failed" "$EXIT_FAILED"
fi

RELEASE_BIN_DIR="${CARGO_TARGET_DIR}/release"

# ---------------------------------------------------------------------------
# Checksum coverage — every binary release-execute.sh recorded a checksum for
# must actually exist in the clean build. Extra built binaries not in that
# list are recorded as an observation only; they don't affect the verdict.
# ---------------------------------------------------------------------------

CHECKSUM_STEP="$(jq -c '.steps[]? | select(.name=="checksum.compute")' "$RELEASE_EVIDENCE" 2>/dev/null || true)"
if [ -z "$CHECKSUM_STEP" ]; then
  add_check "checksum.coverage" "INCONCLUSIVE" false "release-execute evidence has no checksum.compute step to verify the clean build against"
else
  CHECKSUM_TEXT="$(jq -r '.extra.checksums // empty' <<<"$CHECKSUM_STEP")"
  MISSING=""
  EXPECTED_BASENAMES=()
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    path="$(awk '{print $2}' <<<"$line")"
    base="$(basename "$path")"
    [ -n "$base" ] || continue
    EXPECTED_BASENAMES+=("$base")
    if [ ! -f "${RELEASE_BIN_DIR}/${base}" ]; then
      MISSING="${MISSING}${MISSING:+, }${base}"
    fi
  done <<< "$CHECKSUM_TEXT"

  EXTRA=()
  if [ -d "$RELEASE_BIN_DIR" ]; then
    for f in "${RELEASE_BIN_DIR}"/*; do
      [ -f "$f" ] || continue
      b="$(basename "$f")"
      found="false"
      for e in "${EXPECTED_BASENAMES[@]:-}"; do
        [ "$e" = "$b" ] && { found="true"; break; }
      done
      [ "$found" = "true" ] || EXTRA+=("$b")
    done
  fi

  if [ -n "$MISSING" ]; then
    add_check "checksum.coverage" "BLOCK" false "release-execute recorded binaries missing from the clean build: ${MISSING}"
  else
    EXTRA_JSON="$(printf '%s\n' "${EXTRA[@]:-}" | jq -R . | jq -s '. - [""]')"
    add_check "checksum.coverage" "PASS" false "every release-execute-recorded binary is present in the clean build" \
      "$(jq -n --argjson extra_binaries "$EXTRA_JSON" '{extra_binaries:$extra_binaries}')"
  fi
fi

# ---------------------------------------------------------------------------
# P0 smoke — version identity of the actual binary, and startup/graceful
# degradation with no daemon running.
# ---------------------------------------------------------------------------

FORNAX_BIN="${RELEASE_BIN_DIR}/fornax"
if [ -x "$FORNAX_BIN" ]; then
  BIN_VERSION_OUTPUT="$("$FORNAX_BIN" --version 2>/dev/null || true)"
  if [[ "$BIN_VERSION_OUTPUT" == *"$VERSION_NO_V"* ]]; then
    add_check "smoke.version_identity" "PASS" false "fornax --version reports '${BIN_VERSION_OUTPUT}', matching ${VERSION}"
  else
    add_check "smoke.version_identity" "BLOCK" false "fornax --version reports '${BIN_VERSION_OUTPUT}', expected it to contain ${VERSION_NO_V} — published artifact does not match the intended version"
  fi

  export FORNAX_HOME="${WORKDIR}/fornax-home"
  mkdir -p "$FORNAX_HOME"
  if STARTUP_OUTPUT="$("$FORNAX_BIN" status 2>&1)"; then
    if [ -n "$STARTUP_OUTPUT" ]; then
      add_check "smoke.startup" "PASS" false "fornax status started and exited 0 with no daemon running (graceful degradation)"
    else
      add_check "smoke.startup" "INCONCLUSIVE" false "fornax status exited 0 but produced no output"
    fi
  else
    add_check "smoke.startup" "BLOCK" false "fornax status failed to start against a clean FORNAX_HOME with no daemon running"
  fi
else
  add_check "smoke.version_identity" "BLOCK" false "fornax binary not found at ${FORNAX_BIN} after a successful build — cannot verify version identity"
  add_check "smoke.startup" "BLOCK" false "fornax binary not found at ${FORNAX_BIN} after a successful build — cannot verify startup"
fi

# ---------------------------------------------------------------------------
# Hosted canary — a single health probe. Stops further promotion on failure.
# Absent for this release (no hosted service in fornax-core today) -> a
# dispositioned UNTESTED, never a silent PASS.
# ---------------------------------------------------------------------------

if [ -n "$CANARY_URL" ]; then
  CODE="$(curl_probe_status "$CANARY_URL")"
  if [[ "$CODE" =~ ^2[0-9][0-9]$ ]]; then
    add_check "canary.hosted" "PASS" false "canary probe to ${CANARY_URL} returned HTTP ${CODE}"
  else
    add_check "canary.hosted" "BLOCK" false "canary probe to ${CANARY_URL} returned HTTP ${CODE} — stopping further promotion"
  fi
else
  add_check "canary.hosted" "UNTESTED" true "no --canary-url given; fornax-core has no hosted environment to canary in this release"
fi

# ---------------------------------------------------------------------------
# P0 matrix items explicitly out of scope for THIS pass — each one named and
# reasoned, never silently skipped (a silently-skipped item is exactly what
# the "no fake PASS" AC forbids).
# ---------------------------------------------------------------------------

DISPOSITIONED_UNTESTED=(
  "smoke.provider_capture|Real-provider capture is exercised by pre-release QA depth (the FORNX-238-class evidence gate). Re-running it here would duplicate release QA rather than smoke-test the published artifact."
  "smoke.core_verdict_path|The VERIFIED/CONTRADICTED core path is covered by pre-release QA; not re-exercised post-publish so smoke stays fast and P0-focused."
  "smoke.persistence_restart|Persistence/restart is pre-release QA depth; not duplicated here for the same reason."
  "smoke.privacy_egress|The critical local privacy/egress check is owned by the security gate and docs/privacy-redaction-policy.md, not re-run here."
  "smoke.api_db_journey|fornax-core ships local CLI/daemon binaries only; no hosted API/DB/SaaS surface exists in this release's candidate manifest to smoke."
  "smoke.migrations|No schema/data migration exists in this release's scope."
  "smoke.docs_links|No hosted docs/website surface is part of this release's candidate manifest."
  "artifact.signature|No cryptographic signing/SBOM/provenance exists yet (a known FORNX-235 limitation this ticket does not add)."
)
for entry in "${DISPOSITIONED_UNTESTED[@]}"; do
  name="${entry%%|*}"
  reason="${entry#*|}"
  add_check "$name" "UNTESTED" true "$reason"
done

flush_evidence
cat "$EVIDENCE_TMP"

FINAL_OVERALL="$(compute_overall)"
if [ "$FINAL_OVERALL" = "PASS" ]; then
  exit 0
else
  exit "$EXIT_FAILED"
fi
