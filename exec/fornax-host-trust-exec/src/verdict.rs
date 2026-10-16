//! Reconciliation of `identity::ExpectedHook`s against a `hooks/list`
//! response, and the fail-closed aggregation rule (internal-docs ADR-0015
//! R6). Pure data in, pure data out — no I/O, no spawning, so this module
//! is fully unit-testable without a shim or a sandbox.

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;

use crate::identity::ExpectedHook;
use crate::protocol::{
    canonical_event_name, command_basename, looks_like_sha256_digest, HooksListHook,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    Trusted,
    Untrusted,
    Unknown,
}

/// Every reason this crate can attach to a hook or to the overall run.
/// Each variant names exactly one cause — never a bucket — so a reader of
/// `--json` output can tell precisely what happened without guessing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    FornaxHooksNotInstalled,
    FornaxHooksIncomplete,
    HookAbsentFromHostListing,
    UnexpectedFornaxHookInHostListing,
    DuplicateHostKey,
    HostListingIdentityMismatch,
    HostResponseMalformed,
    UnrecognizedTrustStatus(String),
    HookDisabledByHost,
    HostReportedHookErrors,
    HostStateChangedDuringVerification,
}

#[derive(Debug, Clone, Serialize)]
pub struct HookVerdict {
    pub event: &'static str,
    pub key: String,
    pub trust: Trust,
    pub host_trust_status: Option<String>,
    pub current_hash: Option<String>,
    pub reasons: Vec<ReasonCode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AggregateVerdict {
    pub host_trust: Trust,
    pub hooks: Vec<HookVerdict>,
    pub global_reasons: Vec<ReasonCode>,
}

/// Reconciles `expected` (from `hooks.json`, via `identity::read_expected_hooks`)
/// against `reported` (every hook `hooks/list` returned, already flattened
/// across every `data[].hooks` entry) for the single `hooks_json_path` these
/// expectations were derived from.
///
/// This is where internal-docs ADR-0015 R6's fail-closed rule actually
/// lives: an empty `expected` is never `trusted` (`FornaxHooksNotInstalled`
/// instead), a partially-installed set is never `trusted`
/// (`FornaxHooksIncomplete`), and any `unknown` reason anywhere always beats
/// any `untrusted` reason for the aggregate — this is intentionally not
/// `.all(...)` over a possibly-empty collection.
pub fn reconcile(
    hooks_json_path: &Path,
    expected: &[ExpectedHook],
    reported: &[HooksListHook],
) -> AggregateVerdict {
    let mut global_reasons = Vec::new();

    if expected.is_empty() {
        return AggregateVerdict {
            host_trust: Trust::Unknown,
            hooks: Vec::new(),
            global_reasons: vec![ReasonCode::FornaxHooksNotInstalled],
        };
    }
    if !has_every_event(expected) {
        global_reasons.push(ReasonCode::FornaxHooksIncomplete);
    }

    // Index reported hooks whose command basename is HOOK_BIN by key, so a
    // duplicate key is caught instead of silently keeping the last one.
    let mut by_key: HashMap<&str, Vec<&HooksListHook>> = HashMap::new();
    for hook in reported {
        if command_basename(&hook.command) == crate::identity::HOOK_BIN {
            by_key.entry(hook.key.as_str()).or_default().push(hook);
        }
    }

    let expected_keys: std::collections::HashSet<String> = expected
        .iter()
        .map(|e| e.expected_key(hooks_json_path))
        .collect();

    let mut hook_verdicts = Vec::new();
    for exp in expected {
        let key = exp.expected_key(hooks_json_path);
        let matches = by_key.get(key.as_str()).cloned().unwrap_or_default();
        hook_verdicts.push(verdict_for_one(
            exp.event_pascal,
            exp.event_snake,
            &key,
            matches,
        ));
    }

    // Anything Fornax-shaped in the response that wasn't expected.
    for (key, matches) in &by_key {
        if !expected_keys.contains(*key) {
            for hook in matches {
                hook_verdicts.push(HookVerdict {
                    event: canonical_event_name(&hook.event_name).unwrap_or("unknown_event"),
                    key: (*key).to_string(),
                    trust: Trust::Unknown,
                    host_trust_status: Some(hook.trust_status.clone()),
                    current_hash: Some(hook.current_hash.clone()),
                    reasons: vec![ReasonCode::UnexpectedFornaxHookInHostListing],
                });
            }
        }
    }

    let host_trust = aggregate(&global_reasons, &hook_verdicts);
    AggregateVerdict {
        host_trust,
        hooks: hook_verdicts,
        global_reasons,
    }
}

fn has_every_event(expected: &[ExpectedHook]) -> bool {
    crate::identity::EVENTS
        .iter()
        .all(|event| expected.iter().any(|e| &e.event_pascal == event))
}

fn verdict_for_one(
    event: &'static str,
    event_snake: &'static str,
    key: &str,
    matches: Vec<&HooksListHook>,
) -> HookVerdict {
    if matches.is_empty() {
        return HookVerdict {
            event,
            key: key.to_string(),
            trust: Trust::Unknown,
            host_trust_status: None,
            current_hash: None,
            reasons: vec![ReasonCode::HookAbsentFromHostListing],
        };
    }
    if matches.len() > 1 {
        return HookVerdict {
            event,
            key: key.to_string(),
            trust: Trust::Unknown,
            host_trust_status: Some(matches[0].trust_status.clone()),
            current_hash: Some(matches[0].current_hash.clone()),
            reasons: vec![ReasonCode::DuplicateHostKey],
        };
    }

    let hook = matches[0];
    let mut reasons = Vec::new();

    let identity_ok = canonical_event_name(&hook.event_name) == Some(event_snake)
        && command_basename(&hook.command) == crate::identity::HOOK_BIN;
    if !identity_ok {
        reasons.push(ReasonCode::HostListingIdentityMismatch);
    }
    if !looks_like_sha256_digest(&hook.current_hash) {
        reasons.push(ReasonCode::HostResponseMalformed);
    }

    let blocking = !reasons.is_empty();
    let trust = if blocking {
        Trust::Unknown
    } else {
        match hook.trust_status.as_str() {
            "trusted" => Trust::Trusted,
            "untrusted" | "modified" => Trust::Untrusted,
            other => {
                reasons.push(ReasonCode::UnrecognizedTrustStatus(other.to_string()));
                Trust::Unknown
            }
        }
    };
    // Informational, not blocking: a disabled hook can still genuinely be
    // `trusted`/`untrusted` per Codex's trust state -- `enabled` is a
    // different axis (whether it currently runs), not trust itself.
    if !hook.enabled {
        reasons.push(ReasonCode::HookDisabledByHost);
    }

    HookVerdict {
        event,
        key: key.to_string(),
        trust,
        host_trust_status: Some(hook.trust_status.clone()),
        current_hash: Some(hook.current_hash.clone()),
        reasons,
    }
}

/// Never `.all(...)` over a possibly-empty collection — callers that reach
/// here already know `hooks` is non-empty (the `expected.is_empty()` case
/// returns earlier), but the rule is still: any `Unknown` anywhere beats
/// any `Untrusted`, and only a clean all-`Trusted` set with no global
/// reasons is `Trusted`.
fn aggregate(global_reasons: &[ReasonCode], hooks: &[HookVerdict]) -> Trust {
    if !global_reasons.is_empty() {
        return Trust::Unknown;
    }
    if hooks.is_empty() {
        return Trust::Unknown;
    }
    if hooks.iter().any(|h| h.trust == Trust::Unknown) {
        return Trust::Unknown;
    }
    if hooks.iter().any(|h| h.trust == Trust::Untrusted) {
        return Trust::Untrusted;
    }
    Trust::Trusted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ExpectedHook;
    use std::path::PathBuf;

    fn hooks_json_path() -> PathBuf {
        PathBuf::from("/home/op/.codex/hooks.json")
    }

    fn full_expected() -> Vec<ExpectedHook> {
        vec![
            ExpectedHook {
                event_pascal: "PreToolUse",
                event_snake: "pre_tool_use",
                group_idx: 0,
                handler_idx: 0,
            },
            ExpectedHook {
                event_pascal: "PostToolUse",
                event_snake: "post_tool_use",
                group_idx: 0,
                handler_idx: 0,
            },
            ExpectedHook {
                event_pascal: "SessionStart",
                event_snake: "session_start",
                group_idx: 0,
                handler_idx: 0,
            },
        ]
    }

    fn reported_trusted_for(expected: &[ExpectedHook], path: &Path) -> Vec<HooksListHook> {
        expected
            .iter()
            .map(|e| HooksListHook {
                key: e.expected_key(path),
                event_name: match e.event_pascal {
                    "PreToolUse" => "preToolUse".into(),
                    "PostToolUse" => "postToolUse".into(),
                    "SessionStart" => "sessionStart".into(),
                    _ => unreachable!(),
                },
                command: "fornax-hook-codex-event".into(),
                source_path: path.to_path_buf(),
                enabled: true,
                current_hash: format!("sha256:{}", "a".repeat(64)),
                trust_status: "trusted".into(),
            })
            .collect()
    }

    #[test]
    fn empty_expected_is_unknown_not_vacuously_trusted() {
        let v = reconcile(&hooks_json_path(), &[], &[]);
        assert_eq!(v.host_trust, Trust::Unknown);
        assert_eq!(v.global_reasons, vec![ReasonCode::FornaxHooksNotInstalled]);
    }

    #[test]
    fn partial_install_is_unknown_not_trusted() {
        let expected = vec![full_expected()[0].clone()]; // only PreToolUse
        let reported = reported_trusted_for(&expected, &hooks_json_path());
        let v = reconcile(&hooks_json_path(), &expected, &reported);
        assert_eq!(v.host_trust, Trust::Unknown);
        assert!(v
            .global_reasons
            .contains(&ReasonCode::FornaxHooksIncomplete));
    }

    #[test]
    fn full_match_all_trusted_is_trusted() {
        let expected = full_expected();
        let reported = reported_trusted_for(&expected, &hooks_json_path());
        let v = reconcile(&hooks_json_path(), &expected, &reported);
        assert_eq!(v.host_trust, Trust::Trusted);
        assert!(v.global_reasons.is_empty());
        assert_eq!(v.hooks.len(), 3);
    }

    #[test]
    fn one_untrusted_hook_makes_aggregate_untrusted() {
        let expected = full_expected();
        let mut reported = reported_trusted_for(&expected, &hooks_json_path());
        reported[1].trust_status = "untrusted".into();
        let v = reconcile(&hooks_json_path(), &expected, &reported);
        assert_eq!(v.host_trust, Trust::Untrusted);
    }

    #[test]
    fn orphaned_entry_missing_from_listing_is_unknown() {
        let expected = full_expected();
        let mut reported = reported_trusted_for(&expected, &hooks_json_path());
        reported.remove(2); // SessionStart never shows up in the RPC response
        let v = reconcile(&hooks_json_path(), &expected, &reported);
        assert_eq!(v.host_trust, Trust::Unknown);
        let session_start = v.hooks.iter().find(|h| h.event == "SessionStart").unwrap();
        assert_eq!(
            session_start.reasons,
            vec![ReasonCode::HookAbsentFromHostListing]
        );
    }

    #[test]
    fn unknown_beats_untrusted_in_aggregate() {
        let expected = full_expected();
        let mut reported = reported_trusted_for(&expected, &hooks_json_path());
        reported[0].trust_status = "untrusted".into();
        reported.remove(2); // also orphan one -> Unknown must win over Untrusted
        let v = reconcile(&hooks_json_path(), &expected, &reported);
        assert_eq!(v.host_trust, Trust::Unknown);
    }

    #[test]
    fn duplicate_key_in_response_is_unknown() {
        let expected = full_expected();
        let mut reported = reported_trusted_for(&expected, &hooks_json_path());
        let dup = reported[0].clone();
        reported.push(dup);
        let v = reconcile(&hooks_json_path(), &expected, &reported);
        let pre = v.hooks.iter().find(|h| h.event == "PreToolUse").unwrap();
        assert_eq!(pre.reasons, vec![ReasonCode::DuplicateHostKey]);
        assert_eq!(v.host_trust, Trust::Unknown);
    }

    #[test]
    fn identity_mismatch_at_matching_key_is_unknown() {
        let expected = full_expected();
        let mut reported = reported_trusted_for(&expected, &hooks_json_path());
        reported[0].event_name = "postToolUse".into(); // key matches PreToolUse but eventName lies
        let v = reconcile(&hooks_json_path(), &expected, &reported);
        let pre = v.hooks.iter().find(|h| h.event == "PreToolUse").unwrap();
        assert!(pre
            .reasons
            .contains(&ReasonCode::HostListingIdentityMismatch));
        assert_eq!(v.host_trust, Trust::Unknown);
    }

    #[test]
    fn malformed_hash_is_unknown() {
        let expected = full_expected();
        let mut reported = reported_trusted_for(&expected, &hooks_json_path());
        reported[0].current_hash = "not-a-digest".into();
        let v = reconcile(&hooks_json_path(), &expected, &reported);
        let pre = v.hooks.iter().find(|h| h.event == "PreToolUse").unwrap();
        assert!(pre.reasons.contains(&ReasonCode::HostResponseMalformed));
        assert_eq!(v.host_trust, Trust::Unknown);
    }

    #[test]
    fn unrecognized_trust_status_is_unknown_never_trusted() {
        let expected = full_expected();
        let mut reported = reported_trusted_for(&expected, &hooks_json_path());
        reported[0].trust_status = "approved".into();
        let v = reconcile(&hooks_json_path(), &expected, &reported);
        let pre = v.hooks.iter().find(|h| h.event == "PreToolUse").unwrap();
        assert_eq!(pre.trust, Trust::Unknown);
        assert_eq!(v.host_trust, Trust::Unknown);
    }

    #[test]
    fn unexpected_fornax_shaped_entry_is_reported_unknown() {
        let expected = full_expected();
        let mut reported = reported_trusted_for(&expected, &hooks_json_path());
        reported.push(HooksListHook {
            key: format!("{}:pre_tool_use:5:0", hooks_json_path().display()),
            event_name: "preToolUse".into(),
            command: "fornax-hook-codex-event".into(),
            source_path: hooks_json_path(),
            enabled: true,
            current_hash: format!("sha256:{}", "b".repeat(64)),
            trust_status: "trusted".into(),
        });
        let v = reconcile(&hooks_json_path(), &expected, &reported);
        assert!(v.hooks.iter().any(|h| h
            .reasons
            .contains(&ReasonCode::UnexpectedFornaxHookInHostListing)));
    }

    #[test]
    fn disabled_host_hook_is_informational_but_still_trusted_if_status_says_so() {
        let expected = full_expected();
        let mut reported = reported_trusted_for(&expected, &hooks_json_path());
        reported[0].enabled = false;
        let v = reconcile(&hooks_json_path(), &expected, &reported);
        let pre = v.hooks.iter().find(|h| h.event == "PreToolUse").unwrap();
        assert_eq!(pre.trust, Trust::Trusted);
        assert_eq!(pre.reasons, vec![ReasonCode::HookDisabledByHost]);
        assert_eq!(v.host_trust, Trust::Trusted);
    }
}
