#!/usr/bin/env bash
# release-readiness.sh — FORNX-234
#
# Verifies a release candidate manifest (release/candidate-manifest.schema.json)
# is actually ready: every repo's recorded SHA is real and on `main`, and every
# required evidence gate (qa, security, docs, stage) points at a Jira ticket
# that is Done, not BLOCKed, and references *this* candidate (not a stale one).
#
# Fails closed: any missing/unreachable/ambiguous input is a FAIL, never a PASS.
#
# Usage:
#   release-readiness.sh <manifest.json> --evidence-dir <dir> [--repo-fixture-dir <dir>]
#
# --evidence-dir <dir>       Directory of normalized per-ticket evidence fixtures,
#                            one file per Jira key: <dir>/<KEY>.json, shape:
#                              {"key":"FORNX-1","exists":true,
#                               "status_category":"done|indeterminate|new",
#                               "status_name":"Done","text":"<description + comments>"}
#                            This is the production input contract: the caller
#                            (an agent with Jira MCP access, or a `jira-fetch`
#                            wrapper hitting the REST API) pre-fetches each
#                            evidence ticket into this shape. A shell script has
#                            no MCP access, so it never calls Jira directly.
#
# --repo-fixture-dir <dir>   Test-only override. Instead of calling `gh api`,
#                            read <dir>/<owner>__<repo>.json, shape:
#                              {"commit_exists":true,"compare_status":"identical"}
#                            compare_status is main...sha via GitHub's compare
#                            API: "identical"|"behind" => sha is an ancestor of
#                            main (PASS); "ahead"|"diverged"|"error" => FAIL.
#
# --cargo-toml <path>        Path to the workspace Cargo.toml checked against
#                             the candidate version (FORNX anti-drift gate,
#                             HORO-1609). Default "Cargo.toml" (repo root of
#                             the checkout this script runs from). Only
#                             consulted for the manifest repo entry whose
#                             owner/name matches this checkout's own
#                             `origin` remote — release-execute.sh already
#                             treats "build from this checkout" the same way.
#
# Output: one compact JSON object on stdout:
#   {"ready":bool,"version":"...","checks":[{"name":...,"status":"pass"|"fail","detail":...}],"candidate":{...}}
# Exit code: 0 if ready, 1 otherwise (including usage/input errors).

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

usage() {
  echo "Usage: ${SCRIPT_NAME} <manifest.json> --evidence-dir <dir> [--repo-fixture-dir <dir>]" >&2
  exit 2
}

MANIFEST=""
EVIDENCE_DIR=""
REPO_FIXTURE_DIR=""
CARGO_TOML="Cargo.toml"
THIS_REPO_OWNER=""
THIS_REPO_NAME=""

while [ $# -gt 0 ]; do
  case "$1" in
    --evidence-dir)
      EVIDENCE_DIR="${2:-}"
      shift 2
      ;;
    --repo-fixture-dir)
      REPO_FIXTURE_DIR="${2:-}"
      shift 2
      ;;
    --cargo-toml)
      CARGO_TOML="${2:-}"
      shift 2
      ;;
    --this-repo-owner)
      THIS_REPO_OWNER="${2:-}"
      shift 2
      ;;
    --this-repo-name)
      THIS_REPO_NAME="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      if [ -z "$MANIFEST" ]; then
        MANIFEST="$1"
        shift
      else
        usage
      fi
      ;;
  esac
done

[ -n "$MANIFEST" ] || usage
[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }
[ -n "$EVIDENCE_DIR" ] || usage

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }

# Resolve which manifest repo entry is "this checkout" for the workspace-
# version anti-drift check, unless the caller already pinned it explicitly
# (tests do this to stay independent of the ambient git remote).
if [ -z "$THIS_REPO_OWNER" ] || [ -z "$THIS_REPO_NAME" ]; then
  if origin_url="$(git config --get remote.origin.url 2>/dev/null)" && [ -n "$origin_url" ]; then
    [ -n "$THIS_REPO_OWNER" ] || THIS_REPO_OWNER="$(echo "$origin_url" | sed -E 's#.*[:/]([^/]+)/([^/.]+)(\.git)?$#\1#')"
    [ -n "$THIS_REPO_NAME" ] || THIS_REPO_NAME="$(echo "$origin_url" | sed -E 's#.*[:/]([^/]+)/([^/.]+)(\.git)?$#\2#')"
  fi
fi

CHECKS_FILE="$(mktemp)"
trap 'rm -f "$CHECKS_FILE"' EXIT
: > "$CHECKS_FILE"

add_check() {
  # add_check <name> <pass|fail> <detail>
  jq -n --arg name "$1" --arg status "$2" --arg detail "$3" \
    '{name:$name,status:$status,detail:$detail}' >> "$CHECKS_FILE"
}

# ---------------------------------------------------------------------------
# Repo/SHA verification — thin interface: fixture dir (tests) or `gh api` (prod)
# ---------------------------------------------------------------------------

repo_commit_exists() {
  # repo_commit_exists <owner> <repo> <sha>  ->  prints "true"/"false"
  local owner="$1" repo="$2" sha="$3"
  if [ -n "$REPO_FIXTURE_DIR" ]; then
    local f="${REPO_FIXTURE_DIR}/${owner}__${repo}.json"
    if [ -f "$f" ]; then
      jq -r '.commit_exists' "$f"
    else
      echo "false"
    fi
    return
  fi
  if gh api "repos/${owner}/${repo}/commits/${sha}" >/dev/null 2>&1; then
    echo "true"
  else
    echo "false"
  fi
}

repo_compare_status() {
  # repo_compare_status <owner> <repo> <sha>  ->  prints identical|behind|ahead|diverged|error
  local owner="$1" repo="$2" sha="$3"
  if [ -n "$REPO_FIXTURE_DIR" ]; then
    local f="${REPO_FIXTURE_DIR}/${owner}__${repo}.json"
    if [ -f "$f" ]; then
      jq -r '.compare_status' "$f"
    else
      echo "error"
    fi
    return
  fi
  local out
  if out="$(gh api "repos/${owner}/${repo}/compare/main...${sha}" --jq '.status' 2>/dev/null)"; then
    echo "$out"
  else
    echo "error"
  fi
}

# ---------------------------------------------------------------------------
# Evidence verification — thin interface: evidence-dir fixtures (always)
# ---------------------------------------------------------------------------

evidence_file() {
  echo "${EVIDENCE_DIR}/$1.json"
}

evidence_exists() {
  local key="$1" f
  f="$(evidence_file "$key")"
  if [ -f "$f" ] && [ "$(jq -r '.exists // false' "$f" 2>/dev/null)" = "true" ]; then
    echo "true"
  else
    echo "false"
  fi
}

evidence_field() {
  # evidence_field <key> <jq filter>
  local key="$1" filter="$2" f
  f="$(evidence_file "$key")"
  jq -r "$filter" "$f" 2>/dev/null || true
}

# case-insensitive substring: haystack, needle
contains_ci() {
  local haystack="$1" needle="$2"
  local h n
  h="$(printf '%s' "$haystack" | tr '[:upper:]' '[:lower:]')"
  n="$(printf '%s' "$needle" | tr '[:upper:]' '[:lower:]')"
  case "$h" in
    *"$n"*) return 0 ;;
    *) return 1 ;;
  esac
}

# explicit BLOCK verdict token: case-sensitive, whole word only.
# A naive case-insensitive substring match on "block" false-positives on
# ordinary English ("blocking", "blocker", "should block done") that shows
# up in routine ticket prose and would make this check permanently
# unsatisfiable for any well-written ticket. Sign-off verdicts are written
# as an uppercase token (see tests/release-readiness/fixtures/block_verdict),
# so match only that.
has_block_verdict() {
  local haystack="$1"
  printf '%s' "$haystack" | grep -qE '(^|[^A-Za-z])BLOCK([^A-Za-z]|$)'
}

# ---------------------------------------------------------------------------
# Load manifest
# ---------------------------------------------------------------------------

if ! jq empty "$MANIFEST" 2>/dev/null; then
  add_check "manifest.parse" "fail" "manifest is not valid JSON"
  jq -s '{ready:false, version:null, checks:., candidate:null}' "$CHECKS_FILE"
  exit 1
fi

VERSION="$(jq -r '.version // empty' "$MANIFEST")"
if [ -z "$VERSION" ]; then
  add_check "manifest.version" "fail" "manifest has no \"version\" field"
else
  add_check "manifest.version" "pass" "$VERSION"
fi

REPO_COUNT="$(jq '.repos | length' "$MANIFEST" 2>/dev/null || echo 0)"
if [ "$REPO_COUNT" -lt 1 ]; then
  add_check "manifest.repos" "fail" "manifest has no repo entries"
fi

# Required gates presence
MISSING_GATES=""
for gate in qa security docs stage; do
  gate_count="$(jq --arg g "$gate" '[.evidence[]? | select(.gate == $g)] | length' "$MANIFEST")"
  if [ "$gate_count" -lt 1 ]; then
    MISSING_GATES="${MISSING_GATES}${MISSING_GATES:+, }${gate}"
  fi
done
if [ -n "$MISSING_GATES" ]; then
  add_check "manifest.gates.presence" "fail" "missing required gate(s): ${MISSING_GATES}"
else
  add_check "manifest.gates.presence" "pass" "qa, security, docs, stage all present"
fi

# ---------------------------------------------------------------------------
# Per-repo checks: SHA exists, SHA is on main
# ---------------------------------------------------------------------------

REPO_SHA_MAP="$(mktemp)"
trap 'rm -f "$CHECKS_FILE" "$REPO_SHA_MAP"' EXIT
jq -c '.repos[]? // empty' "$MANIFEST" > "$REPO_SHA_MAP"

while IFS= read -r repo_json; do
  [ -n "$repo_json" ] || continue
  name="$(jq -r '.name' <<<"$repo_json")"
  owner="$(jq -r '.owner' <<<"$repo_json")"
  sha="$(jq -r '.sha' <<<"$repo_json")"

  exists="$(repo_commit_exists "$owner" "$name" "$sha")"
  if [ "$exists" = "true" ]; then
    add_check "repo.${owner}/${name}.sha_exists" "pass" "commit ${sha} found"
  else
    add_check "repo.${owner}/${name}.sha_exists" "fail" "commit ${sha} not found in ${owner}/${name}"
    continue
  fi

  cmp_status="$(repo_compare_status "$owner" "$name" "$sha")"
  case "$cmp_status" in
    identical|behind)
      add_check "repo.${owner}/${name}.sha_on_main" "pass" "sha is on main (compare status: ${cmp_status})"
      ;;
    ahead|diverged)
      add_check "repo.${owner}/${name}.sha_on_main" "fail" "sha ${sha} is not an ancestor of main (compare status: ${cmp_status})"
      ;;
    *)
      add_check "repo.${owner}/${name}.sha_on_main" "fail" "could not confirm sha ${sha} is on main (compare status: ${cmp_status})"
      ;;
  esac

  # Anti-drift (HORO-1609): the checked-out workspace version must equal the
  # candidate version for the repo this checkout actually builds from.
  # publishes_artifact repos we don't build from here (a multi-repo manifest
  # entry for a sibling repo) are out of scope — their tag/SHA is already
  # verified above; their own version file lives in their own checkout.
  publishes_artifact="$(jq -r '.publishes_artifact' <<<"$repo_json")"
  if [ "$publishes_artifact" = "true" ] && [ "$owner" = "$THIS_REPO_OWNER" ] && [ "$name" = "$THIS_REPO_NAME" ]; then
    if [ ! -f "$CARGO_TOML" ]; then
      add_check "repo.${owner}/${name}.workspace_version_matches_candidate" "fail" "Cargo.toml not found at ${CARGO_TOML}"
    else
      workspace_version="$(awk '/^\[workspace\.package\]/{f=1;next} /^\[/{f=0} f && /^version[[:space:]]*=/{print; exit}' "$CARGO_TOML" | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/')"
      candidate_version="${VERSION#v}"
      if [ -z "$workspace_version" ]; then
        add_check "repo.${owner}/${name}.workspace_version_matches_candidate" "fail" "no [workspace.package] version found in ${CARGO_TOML}"
      elif [ "$workspace_version" = "$candidate_version" ]; then
        add_check "repo.${owner}/${name}.workspace_version_matches_candidate" "pass" "workspace version ${workspace_version} matches candidate ${VERSION}"
      else
        add_check "repo.${owner}/${name}.workspace_version_matches_candidate" "fail" "workspace version ${workspace_version} in ${CARGO_TOML} does not match candidate ${VERSION} — bump [workspace.package].version before tagging"
      fi
    fi
  fi
done < "$REPO_SHA_MAP"

# ---------------------------------------------------------------------------
# Per-evidence checks: ticket exists, Done, not BLOCKed, references this candidate
# ---------------------------------------------------------------------------

EVIDENCE_LIST="$(mktemp)"
trap 'rm -f "$CHECKS_FILE" "$REPO_SHA_MAP" "$EVIDENCE_LIST"' EXIT
jq -c '.evidence[]? // empty' "$MANIFEST" > "$EVIDENCE_LIST"

while IFS= read -r ev_json; do
  [ -n "$ev_json" ] || continue
  gate="$(jq -r '.gate' <<<"$ev_json")"
  key="$(jq -r '.jira_key' <<<"$ev_json")"
  applies_to="$(jq -c '.applies_to_repos // []' <<<"$ev_json")"
  prefix="evidence.${gate}.${key}"

  exists="$(evidence_exists "$key")"
  if [ "$exists" != "true" ]; then
    add_check "${prefix}.exists" "fail" "Jira ticket ${key} not found or evidence fixture missing"
    continue
  fi
  add_check "${prefix}.exists" "pass" "ticket found"

  status_category="$(evidence_field "$key" '.status_category // "unknown"')"
  status_name="$(evidence_field "$key" '.status_name // "unknown"')"
  if [ "$status_category" = "done" ]; then
    add_check "${prefix}.done" "pass" "status: ${status_name}"
  else
    add_check "${prefix}.done" "fail" "ticket ${key} is not Done (status: ${status_name})"
  fi

  text="$(evidence_field "$key" '.text // ""')"
  if has_block_verdict "$text"; then
    add_check "${prefix}.not_blocked" "fail" "ticket ${key} records a BLOCK verdict"
  else
    add_check "${prefix}.not_blocked" "pass" "no BLOCK verdict found"
  fi

  repos_in_scope="$(jq -r 'length' <<<"$applies_to")"
  if [ "$repos_in_scope" -gt 0 ]; then
    missing_refs=""
    while IFS= read -r repo_name; do
      [ -n "$repo_name" ] || continue
      repo_sha="$(jq -r --arg n "$repo_name" '.repos[]? | select(.name == $n) | .sha' "$MANIFEST")"
      if [ -z "$repo_sha" ]; then
        missing_refs="${missing_refs}${missing_refs:+, }${repo_name} (unknown repo in manifest)"
        continue
      fi
      short_sha="${repo_sha:0:7}"
      if contains_ci "$text" "$short_sha"; then
        :
      else
        missing_refs="${missing_refs}${missing_refs:+, }${repo_name} (expected sha prefix ${short_sha})"
      fi
    done < <(jq -r '.[]' <<<"$applies_to")
    if [ -z "$missing_refs" ]; then
      add_check "${prefix}.candidate_reference" "pass" "ticket references current candidate SHA for: $(jq -r 'join(", ")' <<<"$applies_to")"
    else
      add_check "${prefix}.candidate_reference" "fail" "ticket ${key} does not reference the current candidate SHA for: ${missing_refs} — evidence may be stale or for a different candidate"
    fi
  else
    if contains_ci "$text" "$VERSION"; then
      add_check "${prefix}.candidate_reference" "pass" "ticket references candidate version ${VERSION}"
    else
      add_check "${prefix}.candidate_reference" "fail" "ticket ${key} does not reference candidate version ${VERSION} — evidence may be stale or for a different candidate"
    fi
  fi
done < "$EVIDENCE_LIST"

# ---------------------------------------------------------------------------
# Assemble output
# ---------------------------------------------------------------------------

ANY_FAIL="$(jq -s '[.[] | select(.status == "fail")] | length' "$CHECKS_FILE")"
if [ "$ANY_FAIL" -gt 0 ]; then
  READY="false"
else
  READY="true"
fi

CANDIDATE="$(jq '{repos, evidence}' "$MANIFEST")"

jq -n \
  --argjson ready "$READY" \
  --arg version "$VERSION" \
  --slurpfile checks "$CHECKS_FILE" \
  --argjson candidate "$CANDIDATE" \
  '{ready: $ready, version: (if ($version|length) > 0 then $version else null end), checks: $checks, candidate: $candidate}'

if [ "$READY" = "true" ]; then
  exit 0
else
  exit 1
fi
