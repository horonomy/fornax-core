//! Claude Code hook adapter (FORNX-28), formalized against the
//! `fornax_types::AgentAdapter` contract (FORNX-156). Thin by design (D5,
//! ADR 0001): no verification logic here, only translation of hook stdin
//! JSON into canonical `fornax_types::IngestMessage`s.

use fornax_types::{
    AgentAdapter, AgentEvent, CapabilityProbe, Claim, CollectionMethod, EventKind, Evidence,
    EvidenceKind, EvidenceSensor, EvidenceSource, IngestMessage, NormalizationOutcome,
    ProcessObservationDetail, Provider, RuntimeCapabilities, SensorOutcome, SignalAvailability,
    SignalClass, TrustClass, VcsOperation, VcsOutcome,
};
use uuid::Uuid;

/// This adapter implementation's own version — independent of the Claude
/// Code runtime version, which belongs in a `CapabilitySignal::detail`
/// string (see `ClaudeAdapter::probe`). Attached to every capability
/// declaration via `notes["adapter_version"]`.
pub const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Stateless: Claude Code hooks are one-shot per-invocation processes, so
/// there is no cross-call state to hold (contrast `fornax-adapter-codex`'s
/// `call_id` pairing).
#[derive(Debug, Default, Clone, Copy)]
pub struct ClaudeAdapter;

impl CapabilityProbe for ClaudeAdapter {
    /// Declared conservatively, matching what this adapter actually reads —
    /// never inferred as more capable than confirmed (D5, ADR 0001).
    /// Confirmed against a live Claude Code v2.1.238 session (2026-08-29):
    /// PostToolUse and Stop both fire with the shapes this adapter parses.
    ///
    /// Formalized (FORNX-155) from six fixed bools into an explicit
    /// `SignalClass` -> `SignalAvailability` declaration. Every class this
    /// adapter previously declared `true` for stays `Available`;
    /// `ProcessResult` is `Unsupported`: Claude Code's Bash `tool_response`
    /// never carries a literal exit code, only a heuristic derived from
    /// stdout/stderr/interrupted (see `normalize`'s `PostToolUse` handling).
    fn probe(&self) -> RuntimeCapabilities {
        use fornax_types::{CapabilitySignal, SignalAvailability, SignalClass};
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::ClaudeCode,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolInvocation,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::ToolResultPayload,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::SessionLifecycle,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::FinalResponse,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::SubagentLifecycle,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::ProcessResult,
                    state: SignalAvailability::Unsupported,
                    detail: Some(
                        "Bash tool_response carries no literal exit code as of v2.1.238; \
                         ExitCode evidence is heuristic from stdout/stderr/interrupted"
                            .to_string(),
                    ),
                },
            ],
            notes: [(
                "exit_code".to_string(),
                "heuristic from stdout/stderr/interrupted — Claude Code's Bash tool_response \
                 carries no literal exit code as of v2.1.238"
                    .to_string(),
            )]
            .into(),
        }
    }
}

impl AgentAdapter for ClaudeAdapter {
    fn provider(&self) -> Provider {
        Provider::ClaudeCode
    }

    fn adapter_version(&self) -> &'static str {
        ADAPTER_VERSION
    }

    /// `session_hint` is unused here on purpose: every Claude Code hook
    /// payload carries its own `session_id`, which is authoritative for
    /// this transport (see the trait docs on why neither source is assumed
    /// authoritative in general).
    fn normalize(
        &mut self,
        session_hint: &str,
        native: &serde_json::Value,
    ) -> NormalizationOutcome {
        translate(self, session_hint, native)
    }
}

fn stamped_capabilities(adapter: &ClaudeAdapter, session_id: &str) -> RuntimeCapabilities {
    let mut caps = adapter.probe();
    // Reserved, machine-consumed transport fields — see the doc comment on
    // `RuntimeCapabilities::notes` in `fornax-types/src/capabilities.rs`.
    caps.notes
        .insert("session_id".to_string(), session_id.to_string());
    caps.notes.insert(
        "adapter_version".to_string(),
        adapter.adapter_version().to_string(),
    );
    caps
}

/// FORNX-157: formalizes what this adapter has always done inline —
/// extracting a heuristic exit code from a Claude Code Bash `tool_response`
/// — as an `EvidenceSensor`. The heuristic itself is byte-for-byte the same
/// as before this migration (see the `tests` module's existing exit-code
/// tests, whose assertions were left untouched as the before/after
/// regression proof).
///
/// Carries `adapter_version` as a field (rather than a trait parameter,
/// which `EvidenceSensor::collect`'s fixed signature has no room for) so
/// its provenance strings keep embedding it, exactly as `translate` did
/// before this migration.
struct ClaudeBashExitCodeSensor {
    adapter_version: &'static str,
}

impl EvidenceSensor for ClaudeBashExitCodeSensor {
    fn name(&self) -> &'static str {
        "claude_bash_exit_code_sensor_v1"
    }

    fn required_capabilities(&self) -> &'static [SignalClass] {
        &[SignalClass::ToolResultPayload]
    }

    fn trust_class(&self) -> TrustClass {
        // Claude Code's own tool_response is the provider's account of what
        // happened, not something Fornax measured itself.
        TrustClass::AgentAdjacent
    }

    fn collection_method(&self) -> CollectionMethod {
        // PostToolUse fires as an in-process hook callback invoked by
        // Claude Code around the Bash call — distinct from Codex's
        // rollout-file-poll sensors, which share the same trust class (see
        // `fornax_types::sensor`'s module docs' worked example).
        CollectionMethod::HookCallback
    }

    fn collector_version(&self) -> Option<String> {
        Some(self.adapter_version.to_string())
    }

    // `caps` is intentionally unused: gating this sensor on
    // `ToolResultPayload` being confirmed `Available` would change which
    // sessions produce evidence today (a behavior change this migration
    // must not introduce). The real adapter only ever calls `collect` on a
    // live Claude Code PostToolUse event, where this capability is always
    // available in practice.
    fn collect(&self, event: &AgentEvent, _caps: &RuntimeCapabilities) -> SensorOutcome {
        if event.kind != EventKind::PostToolUse || event.tool_name.as_deref() != Some("Bash") {
            return SensorOutcome::not_collected(
                SignalAvailability::Unknown,
                Some("not a Bash PostToolUse event".to_string()),
            );
        }
        let Some(resp) = &event.tool_response else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some("no tool_response present on this event".to_string()),
            );
        };

        // Field name is not stable across CC versions (see
        // docs/research/adapter-capability-matrix.md); check a small set of
        // plausible keys rather than assume one.
        let explicit_code = ["exit_code", "exitCode", "returncode", "status"]
            .iter()
            .find_map(|k| resp.get(k).and_then(|v| v.as_i64()));

        // Confirmed against a real Claude Code v2.1.238 transcript
        // (2026-08-29): the Bash tool_response never carries any of the
        // keys above — it is {stdout, stderr, interrupted, isImage,
        // noOutputExpected}. Fall back to a heuristic derived from that
        // shape so Evidence is still produced, and mark its provenance as
        // heuristic (not authoritative) rather than silently fabricating a
        // real exit code.
        let (code, provenance) = match explicit_code {
            Some(code) => (
                Some(code),
                format!(
                    "claude_code:{v}:PostToolUse:Bash#tool_response",
                    v = self.adapter_version
                ),
            ),
            None => {
                let interrupted = resp
                    .get("interrupted")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let stderr_nonempty = resp
                    .get("stderr")
                    .and_then(|v| v.as_str())
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                if interrupted {
                    (
                        Some(130),
                        format!(
                            "claude_code:{v}:PostToolUse:Bash#heuristic:interrupted",
                            v = self.adapter_version
                        ),
                    )
                } else if stderr_nonempty {
                    (
                        Some(1),
                        format!(
                            "claude_code:{v}:PostToolUse:Bash#heuristic:stderr_nonempty",
                            v = self.adapter_version
                        ),
                    )
                } else if resp.get("stdout").is_some() {
                    (
                        Some(0),
                        format!(
                            "claude_code:{v}:PostToolUse:Bash#heuristic:stderr_empty",
                            v = self.adapter_version
                        ),
                    )
                } else {
                    (None, String::new())
                }
            }
        };

        let Some(code) = code else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some("no recognizable exit-code shape in tool_response".to_string()),
            );
        };

        SensorOutcome::collected(vec![Evidence {
            id: Uuid::new_v4(),
            session_id: event.session_id.clone(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: event.observed_at.clone(),
            payload: serde_json::json!({
                "command": event
                    .tool_input
                    .as_ref()
                    .and_then(|ti| ti.get("command"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                "exit_code": code,
                "heuristic": explicit_code.is_none(),
            }),
            provenance,
            source: Some(EvidenceSource::now(
                self.name(),
                self.trust_class(),
                Some(Provider::ClaudeCode),
                self.collection_method(),
                self.collector_version(),
            )),
            extension: None,
        }])
    }
}

/// FORNX-14 "file changed" claim class: reconstructs a diff-shaped string
/// for Edit/Write/MultiEdit `PostToolUse` events purely from `tool_input`.
///
/// A prior design pass identified a second, "authoritative" collection path:
/// Claude Code's hook payload may also carry a `structuredPatch` field
/// (observed in transcript JSONL entries). That field's exact shape in a
/// real *hook* payload — as opposed to a transcript entry — is UNCONFIRMED
/// in this repo: no captured `PostToolUse` hook payload has shown it, only
/// transcript JSONL has. Per this repo's own established policy
/// (`docs/research/adapter-capability-matrix.md`: re-verify field shapes
/// against the installed CLI version before trusting them), this sensor
/// deliberately never reads or guesses at `structuredPatch`'s shape — doing
/// so risks silently misrepresenting evidence as authoritative when it is
/// not. Only the confirmed-real `tool_input` (`old_string`/`new_string` for
/// Edit, `edits[]` for MultiEdit, `content` for Write) is used, and all
/// evidence this sensor produces is marked `#heuristic:tool_input` — never
/// authoritative.
///
/// TODO(FORNX-14 follow-up): once a live Claude Code `PostToolUse` hook
/// payload confirms `structuredPatch`'s real field names/shape (a live hook
/// capture against a specific installed CLI version, not a guess), add an
/// authoritative collection path here, and a corresponding
/// `Verdict::Contradicted` branch to `fornax-verify`'s `FileModifiedVerifier`
/// (which today has no way to detect a claimed file change that did *not*
/// happen, since the heuristic path only ever observes edits that did
/// occur). Both are deliberately out of scope for this ticket's narrowed
/// implementation — see the PR description for FORNX-14's heuristic-only
/// scope.
struct ClaudeEditWriteDiffSensor {
    adapter_version: &'static str,
}

impl ClaudeEditWriteDiffSensor {
    /// Reconstructs a unified-diff-*shaped* string from an Edit's
    /// `old_string`/`new_string` pair: every line of `old_string` prefixed
    /// `-`, then every line of `new_string` prefixed `+`. Deliberately omits
    /// an `@@` hunk header — `tool_input` carries no line-number/position
    /// information, and fabricating one would misrepresent this evidence as
    /// more precise than it is.
    fn render_edit_diff(old_string: &str, new_string: &str) -> String {
        let mut diff = String::new();
        for line in old_string.lines() {
            diff.push('-');
            diff.push_str(line);
            diff.push('\n');
        }
        for line in new_string.lines() {
            diff.push('+');
            diff.push_str(line);
            diff.push('\n');
        }
        diff
    }

    /// Reconstructs a diff-shaped string for a Write: every line of
    /// `content` prefixed `+`. There is no "old" side to render — a Write
    /// is a full file write, not a diff against prior content.
    fn render_write_diff(content: &str) -> String {
        let mut diff = String::new();
        for line in content.lines() {
            diff.push('+');
            diff.push_str(line);
            diff.push('\n');
        }
        diff
    }
}

impl EvidenceSensor for ClaudeEditWriteDiffSensor {
    fn name(&self) -> &'static str {
        "claude_edit_write_diff_sensor_v1"
    }

    fn required_capabilities(&self) -> &'static [SignalClass] {
        &[SignalClass::ToolResultPayload]
    }

    fn trust_class(&self) -> TrustClass {
        // Same reasoning as `ClaudeBashExitCodeSensor`: this is Claude
        // Code's own account of what it wrote, reconstructed from its
        // tool_input, not something Fornax measured independently.
        TrustClass::AgentAdjacent
    }

    fn collection_method(&self) -> CollectionMethod {
        CollectionMethod::HookCallback
    }

    fn collector_version(&self) -> Option<String> {
        Some(self.adapter_version.to_string())
    }

    fn collect(&self, event: &AgentEvent, _caps: &RuntimeCapabilities) -> SensorOutcome {
        let is_target_tool = matches!(
            event.tool_name.as_deref(),
            Some("Edit") | Some("Write") | Some("MultiEdit")
        );
        if event.kind != EventKind::PostToolUse || !is_target_tool {
            return SensorOutcome::not_collected(
                SignalAvailability::Unknown,
                Some("not an Edit/Write/MultiEdit PostToolUse event".to_string()),
            );
        }

        // Same precedent as `ClaudeBashExitCodeSensor`: presence of
        // `tool_response` is the "did this actually execute" gate, checked
        // before anything else.
        let Some(resp) = &event.tool_response else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some("no tool_response present on this event".to_string()),
            );
        };

        let input = event.tool_input.as_ref();

        let diff = match event.tool_name.as_deref() {
            Some("Edit") => input.and_then(|ti| {
                let old_s = ti.get("old_string").and_then(|v| v.as_str())?;
                let new_s = ti.get("new_string").and_then(|v| v.as_str())?;
                Some(Self::render_edit_diff(old_s, new_s))
            }),
            Some("MultiEdit") => input
                .and_then(|ti| ti.get("edits"))
                .and_then(|v| v.as_array())
                .filter(|edits| !edits.is_empty())
                .map(|edits| {
                    edits
                        .iter()
                        .map(|e| {
                            let old_s = e.get("old_string").and_then(|v| v.as_str()).unwrap_or("");
                            let new_s = e.get("new_string").and_then(|v| v.as_str()).unwrap_or("");
                            Self::render_edit_diff(old_s, new_s)
                        })
                        .collect::<Vec<_>>()
                        .join("")
                }),
            Some("Write") => input
                .and_then(|ti| ti.get("content"))
                .and_then(|v| v.as_str())
                .map(Self::render_write_diff),
            _ => None,
        };

        let Some(diff) = diff else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some(
                    "tool_input did not carry a recognizable old_string/new_string/content shape"
                        .to_string(),
                ),
            );
        };

        // Case variance precedent, same as `ClaudeBashExitCodeSensor`'s
        // `explicit_code` multi-key probe.
        let path = resp
            .get("filePath")
            .and_then(|v| v.as_str())
            .or_else(|| resp.get("file_path").and_then(|v| v.as_str()))
            .or_else(|| {
                input
                    .and_then(|ti| ti.get("file_path"))
                    .and_then(|v| v.as_str())
            });

        let Some(path) = path else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some("no file path found in tool_response or tool_input".to_string()),
            );
        };

        SensorOutcome::collected(vec![Evidence {
            id: Uuid::new_v4(),
            session_id: event.session_id.clone(),
            source_event_id: event.id,
            kind: EvidenceKind::FileDiff,
            observed_at: event.observed_at.clone(),
            payload: serde_json::json!({
                "path": path,
                "diff": diff,
            }),
            provenance: format!(
                "claude_code:{v}:PostToolUse:{tool}#heuristic:tool_input",
                v = self.adapter_version,
                tool = event.tool_name.as_deref().unwrap_or("")
            ),
            source: Some(EvidenceSource::now(
                self.name(),
                self.trust_class(),
                Some(Provider::ClaudeCode),
                self.collection_method(),
                self.collector_version(),
            )),
            extension: None,
        }])
    }
}

/// FORNX-14 "git commit/push claim" class: parses `git commit`/`git push`
/// output from a Bash `tool_response` into structured `VcsOperation`
/// evidence.
///
/// Unlike [`ClaudeEditWriteDiffSensor`] (which reconstructs a diff-shaped
/// string heuristically from `tool_input`, never authoritatively), this
/// sensor parses git's own real printed stdout/stderr — evidentially
/// authoritative, not a `tool_input` reconstruction — hence its provenance
/// ends `#tool_response:...`, not `#heuristic:...`.
///
/// **Security note**: a `git push` remote URL can embed a credential
/// (`https://x-access-token:ghp_xxx@github.com/o/r.git`). `redact_text` does
/// not catch this shape (`:`/`@` fall outside its detector's allowed
/// character set — a verified real gap). This sensor therefore sanitizes
/// `remote` itself, before it ever reaches `Evidence::payload` — see
/// [`Self::sanitize_remote`] — rather than relying on the shared redactor.
struct ClaudeGitOutcomeSensor {
    adapter_version: &'static str,
}

impl ClaudeGitOutcomeSensor {
    /// True when `command` (the Bash `tool_input.command` string) looks like
    /// a `git commit` or `git push` invocation. Deliberately a plain
    /// lowercased substring check — no existing command-text normalization
    /// idiom exists in this crate to reuse (unlike `fornax-verify`'s
    /// `command_text`, which normalizes a *stored evidence payload's*
    /// `command` field, not a raw `tool_input` string being gated here).
    fn command_kind(command: &str) -> Option<VcsOperation> {
        let lower = command.to_lowercase();
        // A compound command naming both (`git commit -m x && git push`) is
        // treated as a commit only — see the module docs for why splitting
        // this into two evidence rows from one event is out of scope here.
        if lower.contains("git commit") {
            Some(VcsOperation::Commit)
        } else if lower.contains("git push") {
            Some(VcsOperation::Push)
        } else {
            None
        }
    }

    /// True when `s` looks like a git commit SHA: 7-40 hex characters (git's
    /// abbreviated SHA is 7+ chars by default; a full SHA-1 is 40).
    fn looks_sha_shaped(s: &str) -> bool {
        (7..=40).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Parses `git commit`'s real stdout for its bracketed summary line
    /// (`[main 0e2fbd4] message`, `[main (root-commit) 0e2fbd4] message`,
    /// `[detached HEAD abc1234] message`) or its "nothing to commit" text.
    /// Returns `(outcome, commit_sha, branch)`. `None` means unparseable —
    /// callers must fall back to `SensorOutcome::not_collected`, never
    /// fabricate an outcome.
    fn parse_commit(text: &str) -> Option<(VcsOutcome, Option<String>, Option<String>)> {
        let lower = text.to_lowercase();
        if lower.contains("nothing to commit") || lower.contains("no changes added to commit") {
            return Some((VcsOutcome::NothingToCommit, None, None));
        }
        for line in text.lines() {
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix('[') else {
                continue;
            };
            let Some(close_idx) = rest.find(']') else {
                continue;
            };
            let inner = &rest[..close_idx];
            let tokens: Vec<&str> = inner.split_whitespace().collect();
            let Some(&last) = tokens.last() else {
                continue;
            };
            if !Self::looks_sha_shaped(last) {
                continue;
            }
            let branch = tokens[..tokens.len() - 1].join(" ");
            let branch = if branch.is_empty() {
                None
            } else {
                Some(branch)
            };
            return Some((VcsOutcome::Created, Some(last.to_string()), branch));
        }
        None
    }

    /// Parses `git push`'s real stdout/stderr. Returns
    /// `(outcome, branch, remote)`. `None` means unparseable — callers must
    /// fall back to `SensorOutcome::not_collected`.
    fn parse_push(text: &str) -> Option<(VcsOutcome, Option<String>, Option<String>)> {
        let remote = Self::extract_remote_line(text);

        // Rejection markers are checked before the ref-update scan below: a
        // rejected push's "! [rejected]  main -> main (fetch first)" line
        // also contains " -> " and would otherwise be misread as a
        // successful ref update.
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("! [")
                || trimmed.contains("[rejected]")
                || trimmed.contains("error:")
            {
                return Some((VcsOutcome::Rejected, None, remote));
            }
        }

        if text.contains("Everything up-to-date") {
            return Some((VcsOutcome::UpToDate, None, remote));
        }

        for line in text.lines() {
            let trimmed = line.trim();
            let Some(arrow_idx) = trimmed.find(" -> ") else {
                continue;
            };
            let before = &trimmed[..arrow_idx];
            let mut parts = before.split_whitespace();
            let Some(range) = parts.next() else { continue };
            let Some(local_ref) = parts.next() else {
                continue;
            };
            if range.contains("..") {
                return Some((VcsOutcome::RefUpdated, Some(local_ref.to_string()), remote));
            }
        }
        None
    }

    fn extract_remote_line(text: &str) -> Option<String> {
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("To ") {
                return Self::sanitize_remote(rest.trim());
            }
        }
        None
    }

    /// Strips userinfo (`user:pass@`/`user@`) and any query string from a
    /// git remote URL, keeping only `scheme://host/path`. Returns `None`
    /// (never a raw fallback) when `remote` doesn't parse as
    /// `scheme://...` — see this sensor's security note.
    fn sanitize_remote(remote: &str) -> Option<String> {
        let (scheme, rest) = remote.split_once("://")?;
        let after_userinfo = match rest.rfind('@') {
            Some(idx) => &rest[idx + 1..],
            None => rest,
        };
        let path_part = after_userinfo.split('?').next().unwrap_or(after_userinfo);
        if path_part.is_empty() {
            return None;
        }
        Some(format!("{scheme}://{path_part}"))
    }
}

impl EvidenceSensor for ClaudeGitOutcomeSensor {
    fn name(&self) -> &'static str {
        "claude_git_outcome_sensor_v1"
    }

    fn required_capabilities(&self) -> &'static [SignalClass] {
        &[SignalClass::ToolResultPayload]
    }

    fn trust_class(&self) -> TrustClass {
        TrustClass::AgentAdjacent
    }

    fn collection_method(&self) -> CollectionMethod {
        CollectionMethod::HookCallback
    }

    fn collector_version(&self) -> Option<String> {
        Some(self.adapter_version.to_string())
    }

    fn collect(&self, event: &AgentEvent, _caps: &RuntimeCapabilities) -> SensorOutcome {
        if event.kind != EventKind::PostToolUse || event.tool_name.as_deref() != Some("Bash") {
            return SensorOutcome::not_collected(
                SignalAvailability::Unknown,
                Some("not a Bash PostToolUse event".to_string()),
            );
        }

        let Some(command) = event
            .tool_input
            .as_ref()
            .and_then(|ti| ti.get("command"))
            .and_then(|v| v.as_str())
        else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unknown,
                Some("no command string in tool_input".to_string()),
            );
        };

        let Some(operation) = Self::command_kind(command) else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unknown,
                Some("not a git commit/push command".to_string()),
            );
        };

        let Some(resp) = &event.tool_response else {
            return SensorOutcome::not_collected(
                SignalAvailability::Unavailable,
                Some("no tool_response present on this event".to_string()),
            );
        };

        let stdout = resp.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
        let stderr = resp.get("stderr").and_then(|v| v.as_str()).unwrap_or("");
        // git commonly prints progress/summary to stderr (especially for
        // `push`), so both streams are scanned together.
        let combined = format!("{stdout}\n{stderr}");

        // `parse_commit` returns `(outcome, commit_sha, branch)`; `parse_push`
        // returns `(outcome, branch, remote)` — different tuple shapes per
        // operation, so each arm below binds its own fields explicitly
        // rather than sharing one destructuring pattern (that mismatch was a
        // real bug caught in review before this landed).
        let (outcome, commit_sha, branch, remote) = match operation {
            VcsOperation::Commit => {
                let Some((outcome, commit_sha, branch)) = Self::parse_commit(&combined) else {
                    return SensorOutcome::not_collected(
                        SignalAvailability::Unavailable,
                        Some(
                            "git output did not match a recognizable commit outcome shape"
                                .to_string(),
                        ),
                    );
                };
                (outcome, commit_sha, branch, None)
            }
            VcsOperation::Push => {
                let Some((outcome, branch, remote)) = Self::parse_push(&combined) else {
                    return SensorOutcome::not_collected(
                        SignalAvailability::Unavailable,
                        Some(
                            "git output did not match a recognizable push outcome shape"
                                .to_string(),
                        ),
                    );
                };
                (outcome, None, branch, remote)
            }
        };

        let (op_label, outcome_label, provenance_tag) = match operation {
            VcsOperation::Commit => ("commit", format!("{outcome:?}"), "git_commit"),
            VcsOperation::Push => ("push", format!("{outcome:?}"), "git_push"),
        };

        SensorOutcome::collected(vec![Evidence {
            id: Uuid::new_v4(),
            session_id: event.session_id.clone(),
            source_event_id: event.id,
            kind: EvidenceKind::ProcessObservation,
            observed_at: event.observed_at.clone(),
            payload: serde_json::to_value(fornax_types::ProcessObservationPayload {
                description: format!("git {op_label} {outcome_label}"),
                observation: Some(ProcessObservationDetail::VcsOperation {
                    operation,
                    outcome,
                    commit_sha,
                    branch,
                    remote,
                }),
            })
            .expect("ProcessObservationPayload always serializes"),
            provenance: format!(
                "claude_code:{v}:PostToolUse:Bash#tool_response:{provenance_tag}",
                v = self.adapter_version
            ),
            source: Some(EvidenceSource::now(
                self.name(),
                self.trust_class(),
                Some(Provider::ClaudeCode),
                self.collection_method(),
                self.collector_version(),
            )),
            extension: None,
        }])
    }
}

fn translate(
    adapter: &ClaudeAdapter,
    session_hint: &str,
    raw: &serde_json::Value,
) -> NormalizationOutcome {
    let hook_event = raw
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let session_id = raw
        .get("session_id")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| session_hint.to_string());
    let now = chrono::Utc::now().to_rfc3339();

    let kind = match hook_event {
        "PreToolUse" => EventKind::PreToolUse,
        "PostToolUse" => EventKind::PostToolUse,
        "SessionStart" => EventKind::SessionStart,
        "Stop" => EventKind::SessionEnd,
        "UserPromptSubmit" => EventKind::UserPromptSubmit,
        "SubagentStart" => EventKind::SubagentStart,
        "SubagentStop" => EventKind::SubagentStop,
        "Notification" => EventKind::Notification,
        "" => {
            return NormalizationOutcome::Unrecognized {
                discriminator: "<missing hook_event_name>".to_string(),
            }
        }
        other => {
            // A hook event name this adapter has no canonical mapping for.
            // Never seen live yet, so treated as genuinely unrecognized
            // (not a deliberate `Ignored`) — see the trait docs.
            return NormalizationOutcome::Unrecognized {
                discriminator: other.to_string(),
            };
        }
    };

    let event_id = Uuid::new_v4();
    let tool_name = raw
        .get("tool_name")
        .and_then(|v| v.as_str())
        .map(String::from);
    let tool_input = raw.get("tool_input").cloned();
    let tool_response = raw.get("tool_response").cloned();

    let event = AgentEvent {
        id: event_id,
        session_id: session_id.clone(),
        provider: Provider::ClaudeCode,
        kind,
        observed_at: now.clone(),
        tool_name: tool_name.clone(),
        tool_input,
        tool_response: tool_response.clone(),
        raw: raw.clone(),
    };

    // Declare capabilities on every event, not just session start: Claude
    // Code hooks are stateless invocations of this binary, so there is no
    // single "session start" moment where a capability declaration is
    // guaranteed to be sent exactly once. The daemon's Capabilities handler
    // overwrites its per-session map entry, so repeated identical
    // declarations are idempotent. This was a real gap found 2026-08-29
    // while proving FORNX-34 against live Claude Code data: without it,
    // the daemon never learns this session can expose exit-code evidence,
    // and every claim resolves Unavailable regardless of Evidence present.
    let caps = stamped_capabilities(adapter, &session_id);
    let mut out = vec![
        IngestMessage::Capabilities(caps.clone()),
        IngestMessage::Event(event.clone()),
    ];

    // PostToolUse for a Bash call: if Claude Code's tool_response carries an
    // exit-code-shaped field, extract it as Evidence. Formalized (FORNX-157)
    // as a `ClaudeBashExitCodeSensor` implementing `EvidenceSensor` — see
    // that type for the unchanged heuristic (proven by the `tests` module's
    // existing exit-code tests, whose assertions were not touched by this
    // change).
    if kind == EventKind::PostToolUse && tool_name.as_deref() == Some("Bash") {
        let sensor = ClaudeBashExitCodeSensor {
            adapter_version: adapter.adapter_version(),
        };
        let outcome = sensor.collect(&event, &caps);
        out.extend(outcome.evidence.into_iter().map(IngestMessage::Evidence));
    }

    // PostToolUse for an Edit/Write/MultiEdit call (FORNX-14): reconstruct a
    // heuristic file-diff from `tool_input` — see `ClaudeEditWriteDiffSensor`
    // for why only this path is implemented.
    if kind == EventKind::PostToolUse
        && matches!(
            tool_name.as_deref(),
            Some("Edit") | Some("Write") | Some("MultiEdit")
        )
    {
        let sensor = ClaudeEditWriteDiffSensor {
            adapter_version: adapter.adapter_version(),
        };
        let outcome = sensor.collect(&event, &caps);
        out.extend(outcome.evidence.into_iter().map(IngestMessage::Evidence));
    }

    // PostToolUse for a Bash call whose command looks like `git commit`/
    // `git push` (FORNX-14): parse git's own real stdout/stderr into
    // structured `VcsOperation` evidence. Gated the same way as
    // `ClaudeBashExitCodeSensor` (Bash PostToolUse); the sensor itself does
    // the finer-grained command-text gate.
    if kind == EventKind::PostToolUse && tool_name.as_deref() == Some("Bash") {
        let sensor = ClaudeGitOutcomeSensor {
            adapter_version: adapter.adapter_version(),
        };
        let outcome = sensor.collect(&event, &caps);
        out.extend(outcome.evidence.into_iter().map(IngestMessage::Evidence));
    }

    // Stop: best-effort claim extraction from the transcript's last
    // assistant message, if Claude Code gave us a transcript_path.
    if kind == EventKind::SessionEnd {
        if let Some(text) = last_assistant_text(raw) {
            if fornax_verify_claims_tests_passed(&text) {
                out.push(IngestMessage::Claim(Claim {
                    id: Uuid::new_v4(),
                    session_id,
                    source_event_id: event_id,
                    text,
                    subject: "test_result".to_string(),
                    claimed_at: now,
                }));
            }
        }
    }

    NormalizationOutcome::Messages(out)
}

/// Duplicated (not imported) on purpose: adapters must not depend on
/// fornax-verify (that would blur the "adapters are thin, verifiers own
/// domain logic" boundary — see the `AgentAdapter` trait docs' "Allowed core
/// dependencies" section) — this is only a cheap pre-filter so the daemon
/// isn't sent every Stop-event message as a candidate claim. The daemon's
/// verifier is the actual authority.
fn fornax_verify_claims_tests_passed(text: &str) -> bool {
    let t = text.to_lowercase();
    (t.contains("test") || t.contains("tests"))
        && (t.contains("passed") || t.contains("succeeded") || t.contains("all green"))
        && !t.contains("failed")
}

fn last_assistant_text(raw: &serde_json::Value) -> Option<String> {
    let path = raw.get("transcript_path").and_then(|v| v.as_str())?;
    let content = std::fs::read_to_string(path).ok()?;
    let mut last_text: Option<String> = None;
    for line in content.lines() {
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if entry.get("type").and_then(|v| v.as_str()) != Some("assistant") {
            continue;
        }
        // A real assistant turn's content array frequently has a tool_use
        // (or thinking) block at index 0 with no "text" field at all —
        // confirmed against a live Claude Code v2.1.238 transcript
        // 2026-08-29, where content[0] was a tool_use block. Scan every
        // block in the turn for a "text"-typed one instead of assuming
        // index 0.
        if let Some(blocks) = entry.pointer("/message/content").and_then(|v| v.as_array()) {
            for block in blocks {
                if block.get("type").and_then(|v| v.as_str()) == Some("text") {
                    if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                        last_text = Some(text.to_string());
                    }
                }
            }
        }
    }
    last_text
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{EventKind, EvidenceKind, IngestMessage, Provider};

    fn normalize(raw: &serde_json::Value) -> NormalizationOutcome {
        ClaudeAdapter.normalize("unused-hint", raw)
    }

    /// FORNX-155 AC4: the real capabilities this adapter sends, projected
    /// through the legacy wire shape (what `fornax-cli export-spool`
    /// actually emits), must reproduce the exact six bool values this
    /// adapter declared before the formalization — not just a hand-built
    /// fixture that happens to agree.
    #[test]
    fn claude_capabilities_legacy_projection_matches_pre_formalization_bools() {
        let legacy = fornax_types::LegacyCapabilitiesWire::from(&ClaudeAdapter.probe());
        assert!(legacy.supports_pre_tool_use);
        assert!(legacy.supports_post_tool_use);
        assert!(legacy.supports_tool_response_capture);
        assert!(legacy.supports_session_stop_event);
        assert!(legacy.supports_transcript_tail);
        assert!(legacy.supports_subagent_lifecycle);
    }

    #[test]
    fn post_tool_use_bash_with_exit_code_produces_event_and_evidence() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "pytest"},
            "tool_response": {"exit_code": 1}
        });
        let msgs = normalize(&raw).into_messages();
        assert_eq!(msgs.len(), 3);
        assert!(matches!(&msgs[0], IngestMessage::Capabilities(_)));
        match &msgs[1] {
            IngestMessage::Event(e) => {
                assert_eq!(e.provider, Provider::ClaudeCode);
                assert_eq!(e.kind, EventKind::PostToolUse);
                assert_eq!(e.session_id, "sess-1");
            }
            other => panic!("expected Event, got {other:?}"),
        }
        match &msgs[2] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.payload["exit_code"], 1);
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    /// FORNX-157: proves the exit-code evidence path now also carries
    /// structured `EvidenceSource`/trust-class metadata, on top of the
    /// unmodified provenance/payload assertions above (which are the
    /// before/after behavior-preservation proof for the migration onto
    /// `ClaudeBashExitCodeSensor`).
    #[test]
    fn post_tool_use_bash_evidence_carries_sensor_source_metadata() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "pytest"},
            "tool_response": {"exit_code": 1}
        });
        let msgs = normalize(&raw).into_messages();
        match &msgs[2] {
            IngestMessage::Evidence(ev) => {
                let source = ev
                    .source
                    .as_ref()
                    .expect("sensor-produced evidence must carry source");
                assert_eq!(source.sensor_name, "claude_bash_exit_code_sensor_v1");
                assert_eq!(source.trust_class, fornax_types::TrustClass::AgentAdjacent);
                assert_eq!(source.provider, Some(Provider::ClaudeCode));
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    /// FORNX-157: the sensor is directly unit-testable in isolation from
    /// `normalize()`'s hook-JSON plumbing, given only a canonical
    /// `AgentEvent` — proving the "adapters consume canonical types, not
    /// raw transport" boundary holds on the collection side too.
    #[test]
    fn claude_bash_exit_code_sensor_reports_unavailable_with_no_tool_response() {
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "sess-1".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("Bash".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        };
        let sensor = ClaudeBashExitCodeSensor {
            adapter_version: ADAPTER_VERSION,
        };
        let outcome = sensor.collect(&event, &ClaudeAdapter.probe());
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Unavailable);
    }

    #[test]
    fn post_tool_use_real_claude_code_shape_infers_heuristic_success() {
        // Confirmed real Claude Code v2.1.238 Bash tool_response shape
        // (2026-08-29 live capture): no exit_code/exitCode/returncode/status
        // key exists at all. Empty stderr + not interrupted should still
        // yield heuristic exit-code-0 Evidence, marked as a heuristic.
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hi"},
            "tool_response": {"stdout": "hi\n", "stderr": "", "interrupted": false, "isImage": false, "noOutputExpected": false}
        });
        let msgs = normalize(&raw).into_messages();
        assert_eq!(msgs.len(), 3);
        match &msgs[2] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.payload["exit_code"], 0);
                assert_eq!(ev.payload["heuristic"], true);
                assert!(ev.provenance.contains("heuristic:stderr_empty"));
            }
            _ => panic!("expected Evidence"),
        }
    }

    #[test]
    fn post_tool_use_real_shape_stderr_nonempty_infers_heuristic_failure() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "false"},
            "tool_response": {"stdout": "", "stderr": "boom", "interrupted": false}
        });
        let msgs = normalize(&raw).into_messages();
        assert_eq!(msgs.len(), 3);
        match &msgs[2] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.payload["exit_code"], 1);
                assert!(ev.provenance.contains("heuristic:stderr_nonempty"));
            }
            _ => panic!("expected Evidence"),
        }
    }

    #[test]
    fn post_tool_use_without_any_recognizable_shape_produces_only_event() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hi"},
            "tool_response": {}
        });
        let msgs = normalize(&raw).into_messages();
        assert_eq!(msgs.len(), 2);
        assert!(matches!(&msgs[0], IngestMessage::Capabilities(_)));
        assert!(matches!(&msgs[1], IngestMessage::Event(_)));
    }

    #[test]
    fn stop_event_finds_text_block_when_content_0_is_tool_use() {
        // Confirmed real Claude Code v2.1.238 transcript shape (2026-08-29
        // live capture): an assistant turn's content[0] is routinely a
        // tool_use block with no "text" field — the final text-bearing
        // block can be anywhere in the array, not just index 0.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fornax-test-transcript-{}.jsonl", Uuid::new_v4()));
        let transcript = serde_json::json!({
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {}},
                    {"type": "text", "text": "all tests passed"}
                ]
            }
        })
        .to_string();
        std::fs::write(&path, transcript).unwrap();

        let raw = serde_json::json!({
            "hook_event_name": "Stop",
            "session_id": "sess-1",
            "transcript_path": path.to_str().unwrap()
        });
        let msgs = normalize(&raw).into_messages();
        std::fs::remove_file(&path).ok();

        assert_eq!(msgs.len(), 3);
        match &msgs[2] {
            IngestMessage::Claim(c) => assert_eq!(c.text, "all tests passed"),
            _ => panic!("expected Claim"),
        }
    }

    #[test]
    fn stop_event_without_transcript_path_produces_only_event() {
        let raw = serde_json::json!({
            "hook_event_name": "Stop",
            "session_id": "sess-1"
        });
        let msgs = normalize(&raw).into_messages();
        assert_eq!(msgs.len(), 2);
        assert!(matches!(&msgs[0], IngestMessage::Capabilities(_)));
        assert!(matches!(&msgs[1], IngestMessage::Event(_)));
    }

    #[test]
    fn unknown_hook_event_is_unrecognized_not_a_crash() {
        let raw = serde_json::json!({
            "hook_event_name": "SomethingClaudeCodeAddsLater",
            "session_id": "sess-1"
        });
        match normalize(&raw) {
            NormalizationOutcome::Unrecognized { discriminator } => {
                assert_eq!(discriminator, "SomethingClaudeCodeAddsLater")
            }
            other => panic!("expected Unrecognized, got {other:?}"),
        }
    }

    #[test]
    fn missing_hook_event_name_is_unrecognized_not_a_crash() {
        let raw = serde_json::json!({"session_id": "sess-1"});
        match normalize(&raw) {
            NormalizationOutcome::Unrecognized { .. } => {}
            other => panic!("expected Unrecognized, got {other:?}"),
        }
    }

    #[test]
    fn user_prompt_submit_produces_one_event() {
        let raw = serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "session_id": "sess-1",
            "prompt": "run the tests"
        });
        let msgs = normalize(&raw).into_messages();
        assert_eq!(msgs.len(), 2);
        assert!(matches!(&msgs[0], IngestMessage::Capabilities(_)));
        assert!(
            matches!(&msgs[1], IngestMessage::Event(e) if e.kind == EventKind::UserPromptSubmit)
        );
    }

    #[test]
    fn capabilities_carry_adapter_version_and_session_id_notes() {
        let raw = serde_json::json!({
            "hook_event_name": "SessionStart",
            "session_id": "sess-1"
        });
        let msgs = normalize(&raw).into_messages();
        match &msgs[0] {
            IngestMessage::Capabilities(caps) => {
                assert_eq!(
                    caps.notes.get("adapter_version").map(String::as_str),
                    Some(ADAPTER_VERSION)
                );
                assert_eq!(
                    caps.notes.get("session_id").map(String::as_str),
                    Some("sess-1")
                );
            }
            other => panic!("expected Capabilities, got {other:?}"),
        }
    }

    // --- FORNX-14: ClaudeEditWriteDiffSensor -------------------------------

    #[test]
    fn post_tool_use_edit_produces_file_diff_evidence() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/repo/src/lib.rs",
                "old_string": "fn old() {}",
                "new_string": "fn new() {}"
            },
            "tool_response": {"filePath": "/repo/src/lib.rs"}
        });
        let msgs = normalize(&raw).into_messages();
        assert_eq!(msgs.len(), 3);
        match &msgs[2] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.kind, EvidenceKind::FileDiff);
                assert_eq!(ev.payload["path"], "/repo/src/lib.rs");
                let diff = ev.payload["diff"].as_str().unwrap();
                assert!(diff.contains("-fn old() {}"));
                assert!(diff.contains("+fn new() {}"));
                assert!(ev.provenance.ends_with("#heuristic:tool_input"));
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    #[test]
    fn post_tool_use_write_produces_only_plus_prefixed_diff() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/repo/src/new_file.rs",
                "content": "line one\nline two"
            },
            "tool_response": {"filePath": "/repo/src/new_file.rs"}
        });
        let msgs = normalize(&raw).into_messages();
        assert_eq!(msgs.len(), 3);
        match &msgs[2] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.kind, EvidenceKind::FileDiff);
                let diff = ev.payload["diff"].as_str().unwrap();
                assert!(diff.contains("+line one"));
                assert!(diff.contains("+line two"));
                assert!(!diff.contains('-'));
                assert!(ev.provenance.ends_with("#heuristic:tool_input"));
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    #[test]
    fn post_tool_use_multiedit_concatenates_both_edits() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "MultiEdit",
            "tool_input": {
                "file_path": "/repo/src/lib.rs",
                "edits": [
                    {"old_string": "a1", "new_string": "a2", "replace_all": false},
                    {"old_string": "b1", "new_string": "b2", "replace_all": false}
                ]
            },
            "tool_response": {"filePath": "/repo/src/lib.rs"}
        });
        let msgs = normalize(&raw).into_messages();
        assert_eq!(msgs.len(), 3);
        match &msgs[2] {
            IngestMessage::Evidence(ev) => {
                assert_eq!(ev.kind, EvidenceKind::FileDiff);
                let diff = ev.payload["diff"].as_str().unwrap();
                assert!(diff.contains("-a1"));
                assert!(diff.contains("+a2"));
                assert!(diff.contains("-b1"));
                assert!(diff.contains("+b2"));
            }
            other => panic!("expected Evidence, got {other:?}"),
        }
        // Single evidence entry, not one per edit.
        assert_eq!(msgs.len(), 3);
    }

    #[test]
    fn post_tool_use_edit_without_tool_response_produces_only_event() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/repo/src/lib.rs",
                "old_string": "a",
                "new_string": "b"
            }
        });
        let msgs = normalize(&raw).into_messages();
        assert_eq!(msgs.len(), 2);
        assert!(matches!(&msgs[0], IngestMessage::Capabilities(_)));
        assert!(matches!(&msgs[1], IngestMessage::Event(_)));
    }

    #[test]
    fn claude_edit_write_diff_sensor_reports_unavailable_with_no_tool_response() {
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "sess-1".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("Edit".into()),
            tool_input: Some(serde_json::json!({"old_string": "a", "new_string": "b"})),
            tool_response: None,
            raw: serde_json::json!({}),
        };
        let sensor = ClaudeEditWriteDiffSensor {
            adapter_version: ADAPTER_VERSION,
        };
        let outcome = sensor.collect(&event, &ClaudeAdapter.probe());
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Unavailable);
    }

    /// Bash PostToolUse events must not be picked up by the new
    /// Edit/Write/MultiEdit branch — the existing Bash exit-code tests above
    /// already prove the Bash sensor's own behavior is unchanged; this
    /// proves the new sensor doesn't also fire (and thus doesn't double up
    /// evidence) on a Bash event.
    #[test]
    fn bash_event_does_not_trigger_file_diff_sensor() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "pytest"},
            "tool_response": {"exit_code": 0}
        });
        let msgs = normalize(&raw).into_messages();
        // Exactly one Evidence message (the Bash exit-code one), not two.
        let evidence_count = msgs
            .iter()
            .filter(|m| matches!(m, IngestMessage::Evidence(_)))
            .count();
        assert_eq!(evidence_count, 1);
        match &msgs[2] {
            IngestMessage::Evidence(ev) => assert_eq!(ev.kind, EvidenceKind::ExitCode),
            other => panic!("expected Evidence, got {other:?}"),
        }
    }

    // --- FORNX-14: ClaudeGitOutcomeSensor ----------------------------------

    fn git_evidence(msgs: &[IngestMessage]) -> &Evidence {
        msgs.iter()
            .find_map(|m| match m {
                IngestMessage::Evidence(ev) if ev.kind == EvidenceKind::ProcessObservation => {
                    Some(ev)
                }
                _ => None,
            })
            .expect("expected a ProcessObservation Evidence message")
    }

    #[test]
    fn successful_commit_produces_created_outcome_with_sha_and_branch() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git commit -m 'fix bug'"},
            "tool_response": {
                "stdout": "[main 0e2fbd4] fix bug\n 1 file changed, 2 insertions(+)\n",
                "stderr": "",
                "interrupted": false
            }
        });
        let msgs = normalize(&raw).into_messages();
        let ev = git_evidence(&msgs);
        assert_eq!(
            ev.payload["observation"]["observation_kind"],
            "vcs_operation"
        );
        assert_eq!(ev.payload["observation"]["operation"], "commit");
        assert_eq!(ev.payload["observation"]["outcome"], "created");
        assert_eq!(ev.payload["observation"]["commit_sha"], "0e2fbd4");
        assert_eq!(ev.payload["observation"]["branch"], "main");
        assert!(ev.provenance.ends_with("#tool_response:git_commit"));
        let source = ev.source.as_ref().expect("evidence must carry source");
        assert_eq!(source.sensor_name, "claude_git_outcome_sensor_v1");
        assert_eq!(source.trust_class, fornax_types::TrustClass::AgentAdjacent);
    }

    #[test]
    fn root_commit_and_detached_head_shapes_still_extract_sha() {
        let raw_root = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git commit -m 'init'"},
            "tool_response": {"stdout": "[main (root-commit) 0e2fbd4] init\n", "stderr": ""}
        });
        let msgs = normalize(&raw_root).into_messages();
        let ev = git_evidence(&msgs);
        assert_eq!(ev.payload["observation"]["commit_sha"], "0e2fbd4");

        let raw_detached = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git commit -m 'wip'"},
            "tool_response": {"stdout": "[detached HEAD abc1234] wip\n", "stderr": ""}
        });
        let msgs2 = normalize(&raw_detached).into_messages();
        let ev2 = git_evidence(&msgs2);
        assert_eq!(ev2.payload["observation"]["commit_sha"], "abc1234");
        assert_eq!(ev2.payload["observation"]["branch"], "detached HEAD");
    }

    #[test]
    fn nothing_to_commit_produces_nothing_to_commit_outcome_with_no_sha() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git commit -m 'noop'"},
            "tool_response": {
                "stdout": "On branch main\nnothing to commit, working tree clean\n",
                "stderr": ""
            }
        });
        let msgs = normalize(&raw).into_messages();
        let ev = git_evidence(&msgs);
        assert_eq!(ev.payload["observation"]["outcome"], "nothing_to_commit");
        assert!(ev.payload["observation"]["commit_sha"].is_null());
    }

    #[test]
    fn successful_push_produces_ref_updated_with_branch_and_sanitized_remote() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git push"},
            "tool_response": {
                "stdout": "",
                "stderr": "To https://github.com/o/r.git\n   a1b2c3d..e4f5a6b  main -> main\n"
            }
        });
        let msgs = normalize(&raw).into_messages();
        let ev = git_evidence(&msgs);
        assert_eq!(ev.payload["observation"]["operation"], "push");
        assert_eq!(ev.payload["observation"]["outcome"], "ref_updated");
        assert_eq!(ev.payload["observation"]["branch"], "main");
        assert_eq!(
            ev.payload["observation"]["remote"],
            "https://github.com/o/r.git"
        );
        assert!(ev.provenance.ends_with("#tool_response:git_push"));
    }

    #[test]
    fn everything_up_to_date_produces_up_to_date_outcome() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git push"},
            "tool_response": {"stdout": "", "stderr": "Everything up-to-date\n"}
        });
        let msgs = normalize(&raw).into_messages();
        let ev = git_evidence(&msgs);
        assert_eq!(ev.payload["observation"]["outcome"], "up_to_date");
    }

    #[test]
    fn rejected_push_produces_rejected_outcome() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git push"},
            "tool_response": {
                "stdout": "",
                "stderr": "To https://github.com/o/r.git\n ! [rejected]        main -> main (fetch first)\nerror: failed to push some refs to 'https://github.com/o/r.git'\n"
            }
        });
        let msgs = normalize(&raw).into_messages();
        let ev = git_evidence(&msgs);
        assert_eq!(ev.payload["observation"]["outcome"], "rejected");
    }

    /// Falsification: unparseable git output must never fabricate a
    /// `VcsOperation` outcome — no `ProcessObservation` evidence from this
    /// sensor. The pre-existing `ClaudeBashExitCodeSensor` still legitimately
    /// fires on the same event (it's Bash-generic, not git-specific) and
    /// produces its own `ExitCode` evidence — that's unrelated and expected,
    /// which is why this asserts on evidence *kind*, not evidence *count*.
    #[test]
    fn unparseable_git_output_produces_no_process_observation_evidence() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git commit -m 'x'"},
            "tool_response": {"stdout": "some totally unexpected output\n", "stderr": ""}
        });
        let msgs = normalize(&raw).into_messages();
        let process_observation_count = msgs
            .iter()
            .filter(|m| {
                matches!(
                    m,
                    IngestMessage::Evidence(ev) if ev.kind == EvidenceKind::ProcessObservation
                )
            })
            .count();
        assert_eq!(process_observation_count, 0);
    }

    /// Falsification: a non-git Bash command must not trigger this sensor at
    /// all — the existing Bash exit-code sensor's evidence must be the only
    /// evidence produced, unaffected by this sensor's addition.
    #[test]
    fn non_git_bash_command_does_not_trigger_git_outcome_sensor() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "pytest"},
            "tool_response": {"stdout": "5 passed\n", "stderr": "", "interrupted": false}
        });
        let msgs = normalize(&raw).into_messages();
        let evidence: Vec<_> = msgs
            .iter()
            .filter_map(|m| match m {
                IngestMessage::Evidence(ev) => Some(ev),
                _ => None,
            })
            .collect();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, EvidenceKind::ExitCode);
    }

    /// Required secret regression test: a push whose stderr embeds a
    /// credential in the remote URL must never let that credential reach
    /// storage in ANY field of the evidence, checked via full payload
    /// serialization (not just the `remote` field).
    #[test]
    fn credential_embedded_in_push_remote_url_is_never_stored() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git push"},
            "tool_response": {
                "stdout": "",
                "stderr": "To https://x-access-token:ghp_FAKELOOKINGTOKEN1234567890@github.com/o/r.git\n   a1b2c3d..e4f5a6b  main -> main\n"
            }
        });
        let msgs = normalize(&raw).into_messages();
        let ev = git_evidence(&msgs);
        assert_eq!(
            ev.payload["observation"]["remote"],
            "https://github.com/o/r.git"
        );
        let full = serde_json::to_string(ev).unwrap();
        assert!(!full.contains("ghp_FAKELOOKINGTOKEN1234567890"));
        assert!(!full.contains("x-access-token"));
    }

    /// FORNX-244 coverage-gap closure: a commit *message* embedding a
    /// canary/secret-shaped token must never reach the stored evidence.
    /// Unlike the push-remote case above, `parse_commit` never even reads
    /// the commit message text (only the bracketed `[branch sha]` summary
    /// line) and `description` is synthesized from the operation/outcome
    /// labels alone (`format!("git {op_label} {outcome_label}")`), so the
    /// message text has no path into the payload at all — this test proves
    /// that structurally, via full-payload serialization, rather than
    /// assuming it from reading the code.
    #[test]
    fn commit_message_with_embedded_secret_never_reaches_stored_evidence() {
        let marker = "FORNX-CANARY-ghp_SECRETLOOKINGTOKEN1234567890-DO-NOT-LEAK";
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": format!("git commit -m 'wip {marker}'")},
            "tool_response": {
                "stdout": format!("[main 0e2fbd4] wip {marker}\n 1 file changed, 1 insertion(+)\n"),
                "stderr": ""
            }
        });
        let msgs = normalize(&raw).into_messages();
        let ev = git_evidence(&msgs);
        assert_eq!(ev.payload["observation"]["commit_sha"], "0e2fbd4");
        let full = serde_json::to_string(ev).unwrap();
        assert!(
            !full.contains(marker),
            "commit message canary leaked into stored evidence: {full}"
        );
    }

    /// FORNX-244 coverage-gap closure: `sanitize_remote` strips a query
    /// string entirely (per its own doc comment), not just userinfo — a
    /// credential passed as `?token=...` rather than `user:pass@` must also
    /// never reach storage.
    #[test]
    fn credential_in_push_remote_query_string_is_never_stored() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git push"},
            "tool_response": {
                "stdout": "",
                "stderr": "To https://github.com/o/r.git?token=ghp_QUERYSTRINGTOKEN1234567890\n   a1b2c3d..e4f5a6b  main -> main\n"
            }
        });
        let msgs = normalize(&raw).into_messages();
        let ev = git_evidence(&msgs);
        assert_eq!(
            ev.payload["observation"]["remote"],
            "https://github.com/o/r.git"
        );
        let full = serde_json::to_string(ev).unwrap();
        assert!(!full.contains("ghp_QUERYSTRINGTOKEN1234567890"));
        assert!(!full.contains("token="));
    }

    /// FORNX-244 coverage-gap closure: an scp-style SSH remote
    /// (`git@github.com:o/r.git`, no `scheme://`) does not match
    /// `sanitize_remote`'s `scheme://` precondition, so it must come back as
    /// `None` (omitted) rather than passed through raw — falsification-style,
    /// mirroring `unparseable_git_output_produces_no_process_observation_evidence`.
    /// This matters because an scp-style remote can itself carry a
    /// non-default SSH user (`deploy@host:path`) that should not be stored
    /// verbatim just because it doesn't look like a `://` URL.
    #[test]
    fn scp_style_ssh_remote_is_omitted_not_passed_through_raw() {
        let raw = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git push"},
            "tool_response": {
                "stdout": "",
                "stderr": "To git@github.com:o/r.git\n   a1b2c3d..e4f5a6b  main -> main\n"
            }
        });
        let msgs = normalize(&raw).into_messages();
        let ev = git_evidence(&msgs);
        assert_eq!(ev.payload["observation"]["outcome"], "ref_updated");
        assert!(
            ev.payload["observation"]["remote"].is_null(),
            "scp-style remote must be omitted, not passed through raw: {:?}",
            ev.payload["observation"]["remote"]
        );
        let full = serde_json::to_string(ev).unwrap();
        assert!(!full.contains("git@github.com"));
    }

    #[test]
    fn claude_git_outcome_sensor_reports_unavailable_with_no_tool_response() {
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "sess-1".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("Bash".into()),
            tool_input: Some(serde_json::json!({"command": "git commit -m 'x'"})),
            tool_response: None,
            raw: serde_json::json!({}),
        };
        let sensor = ClaudeGitOutcomeSensor {
            adapter_version: ADAPTER_VERSION,
        };
        let outcome = sensor.collect(&event, &ClaudeAdapter.probe());
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Unavailable);
    }
}
