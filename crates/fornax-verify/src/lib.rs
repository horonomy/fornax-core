//! Deterministic claim verification (FORNX-27).
//!
//! `Claim + Evidence[] + RuntimeCapabilities -> Finding`, pure — no I/O.
//! Verifiers must never invent evidence: absent the signal they need, they
//! return `Unavailable`, not `Verified`.

use fornax_types::{
    Claim, Evidence, EvidenceKind, Finding, RuntimeCapabilities, SignalClass, Verdict,
};
use uuid::Uuid;

pub trait Verifier {
    /// Verifier's stable name, recorded on every `Finding` it produces.
    fn name(&self) -> &'static str;

    /// Whether this verifier applies to the given claim's `subject`.
    fn applies_to(&self, claim: &Claim) -> bool;

    /// Compute a finding for `claim` given all evidence observed so far in
    /// the same session and what the runtime is capable of observing.
    fn verify(&self, claim: &Claim, evidence: &[Evidence], caps: &RuntimeCapabilities) -> Finding;
}

/// First high-signal verifier (epic's canonical aha scenario): an agent
/// claims tests passed; deterministically check the most recent test-runner
/// exit code observed in evidence.
pub struct TestResultVerifier;

impl TestResultVerifier {
    /// Very small, deliberately literal claim-text heuristic for v0.0.1 —
    /// claim extraction itself is out of scope for FORNX-27; this verifier
    /// only decides the subject match and the verdict, given an already
    /// extracted `Claim`.
    pub fn claims_tests_passed(text: &str) -> bool {
        let t = text.to_lowercase();
        (t.contains("test") || t.contains("tests"))
            && (t.contains("passed")
                || t.contains("pass")
                || t.contains("succeeded")
                || t.contains("all green"))
            && !t.contains("failed")
    }
}

impl Verifier for TestResultVerifier {
    fn name(&self) -> &'static str {
        "test_result_verifier_v1"
    }

    fn applies_to(&self, claim: &Claim) -> bool {
        claim.subject == "test_result"
    }

    fn verify(&self, claim: &Claim, evidence: &[Evidence], caps: &RuntimeCapabilities) -> Finding {
        let now = chrono::Utc::now().to_rfc3339();

        // Formalized (FORNX-155) from the old `!caps.supports_post_tool_use
        // && !caps.supports_transcript_tail` bool check — same two classes,
        // same gate semantics. Deliberately not widened to also require
        // `SignalClass::ProcessResult`: this verifier is about exit codes so
        // that class feels natural to add here, but doing so would silently
        // change which sessions resolve `Unavailable` today.
        if !caps.is_observable(&SignalClass::ToolTrace)
            && !caps.is_observable(&SignalClass::FinalResponse)
        {
            return unavailable(
                claim.id,
                self.name(),
                "runtime does not expose tool-result/transcript evidence needed to check exit codes",
                now,
            );
        }

        // Find the most recent exit-code-bearing evidence for a test-runner
        // invocation in this session, most recent first (evidence is stored
        // oldest-first; scan from the end).
        let test_evidence = evidence.iter().rev().find(|e| is_test_runner_evidence(e));

        let Some(ev) = test_evidence else {
            return Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale: "no test-runner invocation observed in this session's evidence"
                    .to_string(),
                computed_at: now,
            };
        };

        let exit_code = ev.payload.get("exit_code").and_then(|v| v.as_i64());

        match exit_code {
            Some(0) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Verified,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!("observed test-runner exit_code=0 ({})", ev.provenance),
                computed_at: now,
            },
            Some(code) if is_stderr_heuristic_evidence(ev) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Review,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "claim states tests passed; stderr was non-empty but Claude Code's \
                     tool_response carries no real exit code, so this cannot be confirmed \
                     as a failure -- flagged for review, not treated as contradicted \
                     (heuristic exit_code={code}, {})",
                    ev.provenance
                ),
                computed_at: now,
            },
            Some(code) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Contradicted,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "claim states tests passed, but observed test-runner exit_code={code} ({})",
                    ev.provenance
                ),
                computed_at: now,
            },
            None => unavailable(
                claim.id,
                self.name(),
                "test-runner evidence found but no exit_code field present",
                now,
            ),
        }
    }
}

/// Second claim class (FORNX-14): an agent claims a specific command was
/// executed (e.g. "I ran `npm install`."). Deterministically check for
/// `EvidenceKind::ExitCode` evidence — the only evidence kind either shipped
/// adapter (`fornax-adapter-claude`/`fornax-adapter-codex`) actually
/// produces today — whose `command` field names the same command.
///
/// Absence of matching evidence is `Unverified`, not `Contradicted`: a
/// command not observed running is not proof it didn't run (FORNX-14 AC
/// "missing evidence does not become contradiction").
pub struct CommandExecutedVerifier;

impl CommandExecutedVerifier {
    /// Very small, deliberately literal claim-text heuristic, mirroring
    /// [`TestResultVerifier::claims_tests_passed`] — claim extraction itself
    /// is out of scope here; this only decides subject match given an
    /// already-extracted `Claim`.
    pub fn claims_command_executed(text: &str) -> bool {
        let t = text.to_lowercase();
        t.contains("ran ") || t.contains("i ran") || t.contains("executed") || t.contains("running")
    }

    /// Extract the literal command the claim names, from backtick- or
    /// double-quote-delimited text (e.g. "I ran `npm install`."). Returns
    /// `None` when the claim names no literal command to check against
    /// evidence — such a claim is `Unverified`, not fabricated a match for.
    fn extract_command_literal(text: &str) -> Option<String> {
        extract_delimited(text, '`').or_else(|| extract_delimited(text, '"'))
    }
}

impl Verifier for CommandExecutedVerifier {
    fn name(&self) -> &'static str {
        "command_executed_verifier_v1"
    }

    fn applies_to(&self, claim: &Claim) -> bool {
        claim.subject == "command_executed"
    }

    fn verify(&self, claim: &Claim, evidence: &[Evidence], caps: &RuntimeCapabilities) -> Finding {
        let now = chrono::Utc::now().to_rfc3339();

        // Same gate as `TestResultVerifier` and for the same reason: both
        // shipped adapters declare `SignalClass::ProcessResult` itself
        // unavailable/unsupported even though they still emit heuristic
        // `ExitCode` evidence over `ToolTrace`/`FinalResponse` — gating on
        // `ProcessResult` here would make this verifier `Unavailable` for
        // every real session today.
        if !caps.is_observable(&SignalClass::ToolTrace)
            && !caps.is_observable(&SignalClass::FinalResponse)
        {
            return unavailable(
                claim.id,
                self.name(),
                "runtime does not expose tool-trace/transcript evidence needed to check command execution",
                now,
            );
        }

        let Some(claimed) = Self::extract_command_literal(&claim.text) else {
            return Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale: "claim text does not name a literal command to check against evidence"
                    .to_string(),
                computed_at: now,
            };
        };
        let claimed_lower = claimed.to_lowercase();

        let matching = evidence.iter().rev().find(|e| {
            e.kind == EvidenceKind::ExitCode && command_text(&e.payload).contains(&claimed_lower)
        });

        match matching {
            Some(ev) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Verified,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "observed command matching \"{claimed}\" executed ({})",
                    ev.provenance
                ),
                computed_at: now,
            },
            None => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "no evidence of a command matching \"{claimed}\" observed in this session"
                ),
                computed_at: now,
            },
        }
    }
}

/// Third claim class (FORNX-14): an agent claims a command succeeded (or
/// failed), as distinct from merely claiming it ran at all. Deterministically
/// checks the same `EvidenceKind::ExitCode` evidence's `exit_code` field for
/// the literal command the claim names.
///
/// Unlike [`TestResultVerifier`] (which may fall back to "the most recent
/// test-runner invocation" because all test-runner commands are the same
/// claim subject), a claim naming no specific command is `Unverified`, not
/// bound to whatever command happened to run most recently — that command
/// may be unrelated, and reporting its exit code as this claim's evidence
/// would risk a false `Contradicted` against unrelated evidence.
pub struct CommandSuccessVerifier;

impl CommandSuccessVerifier {
    /// Deliberately literal claim-text heuristic, mirroring
    /// [`TestResultVerifier::claims_tests_passed`].
    pub fn claims_command_succeeded(text: &str) -> bool {
        let t = text.to_lowercase();
        (t.contains("succeeded")
            || t.contains("completed successfully")
            || t.contains("ran successfully")
            || t.contains("worked"))
            && !t.contains("failed")
    }
}

impl Verifier for CommandSuccessVerifier {
    fn name(&self) -> &'static str {
        "command_success_verifier_v1"
    }

    fn applies_to(&self, claim: &Claim) -> bool {
        claim.subject == "command_succeeded"
    }

    fn verify(&self, claim: &Claim, evidence: &[Evidence], caps: &RuntimeCapabilities) -> Finding {
        let now = chrono::Utc::now().to_rfc3339();

        if !caps.is_observable(&SignalClass::ToolTrace)
            && !caps.is_observable(&SignalClass::FinalResponse)
        {
            return unavailable(
                claim.id,
                self.name(),
                "runtime does not expose tool-trace/transcript evidence needed to check command exit status",
                now,
            );
        }

        // A generic claim with no named command ("the command succeeded")
        // must not bind to whatever command happened to run most recently —
        // that command may be entirely unrelated, and reporting its exit
        // code as this claim's evidence would risk a false `Contradicted`
        // against unrelated evidence (AC: "missing evidence does not become
        // contradiction"; also "do not label ordinary mismatch as
        // intentional lying"). Only a claim naming a specific command can be
        // checked at all.
        let Some(claimed) =
            CommandExecutedVerifier::extract_command_literal(&claim.text).map(|s| s.to_lowercase())
        else {
            return Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale:
                    "claim names no specific command; cannot bind to unrelated command evidence"
                        .to_string(),
                computed_at: now,
            };
        };

        let command_evidence = evidence.iter().rev().find(|e| {
            e.kind == EvidenceKind::ExitCode && command_text(&e.payload).contains(&claimed)
        });

        let Some(ev) = command_evidence else {
            return Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "no evidence of a command matching \"{claimed}\" observed in this session"
                ),
                computed_at: now,
            };
        };

        let exit_code = ev.payload.get("exit_code").and_then(|v| v.as_i64());

        match exit_code {
            Some(0) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Verified,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!("observed command exit_code=0 ({})", ev.provenance),
                computed_at: now,
            },
            Some(code) if is_stderr_heuristic_evidence(ev) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Review,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "claim states the command succeeded; stderr was non-empty but Claude \
                     Code's tool_response carries no real exit code, so this cannot be \
                     confirmed as a failure -- flagged for review, not treated as \
                     contradicted (heuristic exit_code={code}, {})",
                    ev.provenance
                ),
                computed_at: now,
            },
            Some(code) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Contradicted,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "claim states the command succeeded, but observed exit_code={code} ({})",
                    ev.provenance
                ),
                computed_at: now,
            },
            None => unavailable(
                claim.id,
                self.name(),
                "command evidence found but no exit_code field present",
                now,
            ),
        }
    }
}

/// Fourth claim class (FORNX-14): an agent claims a specific file was
/// modified (e.g. "I updated `src/lib.rs`."). Deterministically checks for
/// `EvidenceKind::FileDiff` evidence naming a matching path.
///
/// Narrowed scope (see the FORNX-14 PR description and
/// `fornax-adapter-claude`'s `ClaudeEditWriteDiffSensor` doc comment): the
/// only evidence this verifier can ever see today is heuristic, reconstructed
/// from `tool_input` rather than an authoritative diff. There is therefore no
/// way for this verifier to positively detect that a claimed file change did
/// *not* happen — absence of matching evidence only means "not observed",
/// never "did not happen" — so there is deliberately no `Verdict::Contradicted`
/// branch. Matching evidence found produces `Verdict::Review`, never
/// `Verdict::Verified`, for the same reason `TestResultVerifier`/
/// `CommandSuccessVerifier` downgrade their own heuristic branch to `Review`
/// via `is_stderr_heuristic_evidence`: this evidence's provenance always ends
/// `#heuristic:tool_input`, so it is Claude Code's own unverified account of
/// what it wrote, not something Fornax confirmed independently.
///
/// TODO(FORNX-14 follow-up): once an authoritative `structuredPatch`-derived
/// evidence path exists (see the adapter-side TODO), this verifier can gain a
/// `Verdict::Contradicted` branch and upgrade authoritative matches to
/// `Verdict::Verified` — deliberately out of scope here.
pub struct FileModifiedVerifier;

impl FileModifiedVerifier {
    /// Extract a path literal from claim text and require it to look
    /// path-shaped (contains `/` or a `.`-extension) — a bare backtick-quoted
    /// word like `` `npm install` `` or `` `build` `` must not spuriously
    /// bind to file evidence just because it's delimited the same way a
    /// command literal is.
    fn extract_path_literal(text: &str) -> Option<String> {
        let candidate = extract_delimited(text, '`').or_else(|| extract_delimited(text, '"'))?;
        let looks_path_shaped = candidate.contains('/')
            || (candidate.contains('.')
                && candidate.rsplit('.').next().is_some_and(|ext| {
                    !ext.is_empty()
                        && ext.len() <= 8
                        && ext.chars().all(|c| c.is_ascii_alphanumeric())
                }));
        if looks_path_shaped {
            Some(candidate)
        } else {
            None
        }
    }

    /// True when `evidence_path` names the same file as `claimed_path`: the
    /// claimed path must match `evidence_path` on a path-segment boundary,
    /// not merely as a substring (so a claim naming `src/lib.rs` matches
    /// evidence for `/Users/x/project/src/lib.rs` but not
    /// `src/otherlib.rs`).
    fn path_matches(evidence_path: &str, claimed_path: &str) -> bool {
        if evidence_path == claimed_path {
            return true;
        }
        evidence_path
            .strip_suffix(claimed_path)
            .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with('/'))
    }
}

impl Verifier for FileModifiedVerifier {
    fn name(&self) -> &'static str {
        "file_modified_verifier_v1"
    }

    fn applies_to(&self, claim: &Claim) -> bool {
        claim.subject == "file_written"
    }

    fn verify(&self, claim: &Claim, evidence: &[Evidence], caps: &RuntimeCapabilities) -> Finding {
        let now = chrono::Utc::now().to_rfc3339();

        // Deliberately gated on `ToolTrace`/`ToolResultPayload`, NOT
        // `FinalResponse` — unlike `TestResultVerifier`/`CommandExecutedVerifier`/
        // `CommandSuccessVerifier`, this verifier never derives anything from
        // transcript text; its only evidence source is `EvidenceKind::FileDiff`,
        // produced solely from `PostToolUse` tool_input/tool_response. Gating
        // on `FinalResponse` here would open this verifier for sessions that
        // can never actually produce the evidence it looks for.
        if !caps.is_observable(&SignalClass::ToolTrace)
            && !caps.is_observable(&SignalClass::ToolResultPayload)
        {
            return unavailable(
                claim.id,
                self.name(),
                "runtime does not expose tool-trace/tool-result evidence needed to check file modifications",
                now,
            );
        }

        let Some(claimed_path) = Self::extract_path_literal(&claim.text) else {
            return Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale:
                    "claim text does not name a literal, path-shaped file to check against evidence"
                        .to_string(),
                computed_at: now,
            };
        };

        let matching = evidence.iter().rev().find(|e| {
            e.kind == EvidenceKind::FileDiff
                && e.payload
                    .get("path")
                    .and_then(|v| v.as_str())
                    .is_some_and(|p| Self::path_matches(p, &claimed_path))
        });

        let Some(ev) = matching else {
            return Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "no file-diff evidence observed for a file matching \"{claimed_path}\" in this session"
                ),
                computed_at: now,
            };
        };

        let diff_nonempty = ev
            .payload
            .get("diff")
            .and_then(|v| v.as_str())
            .is_some_and(|d| !d.is_empty());

        if !diff_nonempty {
            return Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "file-diff evidence for \"{claimed_path}\" was found but its diff is empty"
                ),
                computed_at: now,
            };
        }

        Finding {
            id: Uuid::new_v4(),
            claim_id: claim.id,
            verdict: Verdict::Review,
            evidence_ids: vec![ev.id],
            verifier_name: self.name().to_string(),
            rationale: format!(
                "observed a file-diff matching \"{claimed_path}\", but this evidence is always \
                 heuristic (reconstructed from tool_input, never authoritative) in this \
                 implementation -- flagged for review, not confirmed verified ({})",
                ev.provenance
            ),
            computed_at: now,
        }
    }
}

/// Fifth claim class (FORNX-14): an agent claims a git commit or push
/// happened (e.g. "I committed with SHA `0e2fbd4`.", "I pushed to `main`.").
/// One verifier handles both `git_commit`/`git_push` subjects — unlike
/// `CommandExecutedVerifier`/`CommandSuccessVerifier`'s split, both subjects
/// here need identical evidence lookup (the same `ProcessObservation`
/// `vcs_operation` evidence), just a different verdict mapping per subject.
///
/// Unlike [`FileModifiedVerifier`] (capped at `Review` because its only
/// evidence is a `tool_input` reconstruction, never authoritative),
/// `Verdict::Verified` is reachable here: the commit SHA / branch / remote
/// come from git's own real printed stdout/stderr, captured verbatim in
/// Claude Code's `tool_response` — an authoritative-evidence path, not a
/// heuristic one (see `fornax-adapter-claude`'s `ClaudeGitOutcomeSensor`,
/// whose provenance ends `#tool_response:...`, never `#heuristic:...`).
/// **Invariant**: if a future change ever derives this evidence from
/// `tool_input` instead of `tool_response` (e.g. before the command has
/// actually run), it must be marked heuristic and capped at `Review`,
/// mirroring the `FileModifiedVerifier` precedent — never silently promoted
/// to `Verified`.
pub struct GitOperationVerifier;

impl GitOperationVerifier {
    /// True when `s` looks like a git commit SHA (7-40 hex chars) — mirrors
    /// `fornax-adapter-claude::ClaudeGitOutcomeSensor::looks_sha_shaped`.
    /// Duplicated rather than imported: `fornax-verify` must not depend on
    /// an adapter crate (adapters are downstream of core, never the reverse).
    fn looks_sha_shaped(s: &str) -> bool {
        (7..=40).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Extracts a SHA-shaped literal from claim text, reusing the same
    /// delimited-literal extraction as `CommandExecutedVerifier`/
    /// `FileModifiedVerifier`. `None` means the claim names no SHA literal
    /// to check evidence against.
    fn extract_sha_literal(text: &str) -> Option<String> {
        let candidate = extract_delimited(text, '`').or_else(|| extract_delimited(text, '"'))?;
        if Self::looks_sha_shaped(&candidate) {
            Some(candidate)
        } else {
            None
        }
    }

    fn sha_matches(claimed: &str, actual: &str) -> bool {
        let c = claimed.to_lowercase();
        let a = actual.to_lowercase();
        a.starts_with(&c) || c.starts_with(&a)
    }

    /// True when `e` is `ProcessObservation` evidence for a `vcs_operation`
    /// observation whose `operation` field matches `operation` (`"commit"`
    /// or `"push"`).
    fn matches_operation(e: &Evidence, operation: &str) -> bool {
        e.kind == EvidenceKind::ProcessObservation
            && e.payload
                .pointer("/observation/observation_kind")
                .and_then(|v| v.as_str())
                == Some("vcs_operation")
            && e.payload
                .pointer("/observation/operation")
                .and_then(|v| v.as_str())
                == Some(operation)
    }

    fn verify_commit(&self, claim: &Claim, evidence: &[Evidence], now: String) -> Finding {
        let Some(ev) = evidence
            .iter()
            .rev()
            .find(|e| Self::matches_operation(e, "commit"))
        else {
            return Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale: "no git commit evidence observed in this session".to_string(),
                computed_at: now,
            };
        };

        let outcome = ev
            .payload
            .pointer("/observation/outcome")
            .and_then(|v| v.as_str());
        match outcome {
            Some("created") => {
                let actual_sha = ev
                    .payload
                    .pointer("/observation/commit_sha")
                    .and_then(|v| v.as_str());
                let claimed_sha = Self::extract_sha_literal(&claim.text);
                match (&claimed_sha, actual_sha) {
                    (Some(claimed), Some(actual)) if !Self::sha_matches(claimed, actual) => {
                        Finding {
                            id: Uuid::new_v4(),
                            claim_id: claim.id,
                            verdict: Verdict::Contradicted,
                            evidence_ids: vec![ev.id],
                            verifier_name: self.name().to_string(),
                            rationale: format!(
                                "claim names commit sha \"{claimed}\", but observed commit sha \
                             \"{actual}\" ({})",
                                ev.provenance
                            ),
                            computed_at: now,
                        }
                    }
                    _ => Finding {
                        id: Uuid::new_v4(),
                        claim_id: claim.id,
                        verdict: Verdict::Verified,
                        evidence_ids: vec![ev.id],
                        verifier_name: self.name().to_string(),
                        rationale: format!("observed git commit created ({})", ev.provenance),
                        computed_at: now,
                    },
                }
            }
            Some("nothing_to_commit") => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Contradicted,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "claim states a commit was made, but git reported nothing to commit ({})",
                    ev.provenance
                ),
                computed_at: now,
            },
            _ => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale: "git commit evidence found but its outcome was not recognized"
                    .to_string(),
                computed_at: now,
            },
        }
    }

    fn verify_push(&self, claim: &Claim, evidence: &[Evidence], now: String) -> Finding {
        let Some(ev) = evidence
            .iter()
            .rev()
            .find(|e| Self::matches_operation(e, "push"))
        else {
            return Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale: "no git push evidence observed in this session".to_string(),
                computed_at: now,
            };
        };

        let outcome = ev
            .payload
            .pointer("/observation/outcome")
            .and_then(|v| v.as_str());
        match outcome {
            Some("ref_updated") => {
                let actual_branch = ev
                    .payload
                    .pointer("/observation/branch")
                    .and_then(|v| v.as_str());
                let claimed_branch = extract_delimited(&claim.text, '`')
                    .or_else(|| extract_delimited(&claim.text, '"'));
                match (&claimed_branch, actual_branch) {
                    (Some(claimed), Some(actual)) if !claimed.eq_ignore_ascii_case(actual) => {
                        Finding {
                            id: Uuid::new_v4(),
                            claim_id: claim.id,
                            verdict: Verdict::Unverified,
                            evidence_ids: vec![],
                            verifier_name: self.name().to_string(),
                            rationale: format!(
                            "claim names branch \"{claimed}\", but observed push updated branch \
                             \"{actual}\" -- ambiguous (multi-branch session), not confirmed wrong \
                             ({})",
                            ev.provenance
                        ),
                            computed_at: now,
                        }
                    }
                    _ => Finding {
                        id: Uuid::new_v4(),
                        claim_id: claim.id,
                        verdict: Verdict::Verified,
                        evidence_ids: vec![ev.id],
                        verifier_name: self.name().to_string(),
                        rationale: format!("observed git push ref updated ({})", ev.provenance),
                        computed_at: now,
                    },
                }
            }
            Some("rejected") => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Contradicted,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "claim states the push succeeded, but git rejected the push ({})",
                    ev.provenance
                ),
                computed_at: now,
            },
            Some("up_to_date") => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Review,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "git reported nothing to push (\"Everything up-to-date\") for this \
                     invocation; the branch may have been pushed earlier in the session -- \
                     flagged for review, not confirmed ({})",
                    ev.provenance
                ),
                computed_at: now,
            },
            _ => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![],
                verifier_name: self.name().to_string(),
                rationale: "git push evidence found but its outcome was not recognized".to_string(),
                computed_at: now,
            },
        }
    }
}

impl Verifier for GitOperationVerifier {
    fn name(&self) -> &'static str {
        "git_operation_verifier_v1"
    }

    fn applies_to(&self, claim: &Claim) -> bool {
        claim.subject == "git_commit" || claim.subject == "git_push"
    }

    /// Deliberately gated on `ToolTrace`/`ToolResultPayload`, NOT
    /// `FinalResponse` — same divergence as `FileModifiedVerifier` and for
    /// the same reason: this verifier's only evidence source is
    /// `EvidenceKind::ProcessObservation`'s `vcs_operation` shape, produced
    /// solely from a `PostToolUse` `tool_response`, never from transcript
    /// text. Gating on `FinalResponse` would open this verifier for sessions
    /// that can never actually produce the evidence it looks for.
    fn verify(&self, claim: &Claim, evidence: &[Evidence], caps: &RuntimeCapabilities) -> Finding {
        let now = chrono::Utc::now().to_rfc3339();

        if !caps.is_observable(&SignalClass::ToolTrace)
            && !caps.is_observable(&SignalClass::ToolResultPayload)
        {
            return unavailable(
                claim.id,
                self.name(),
                "runtime does not expose tool-trace/tool-result evidence needed to check git commit/push outcomes",
                now,
            );
        }

        match claim.subject.as_str() {
            "git_commit" => self.verify_commit(claim, evidence, now),
            "git_push" => self.verify_push(claim, evidence, now),
            _ => unavailable(
                claim.id,
                self.name(),
                "applies_to guarantees subject is git_commit or git_push",
                now,
            ),
        }
    }
}

/// Extract the substring between the first pair of `delim` characters in
/// `text`, trimmed. Returns `None` when `delim` doesn't appear twice or the
/// enclosed text is empty.
fn extract_delimited(text: &str, delim: char) -> Option<String> {
    let start = text.find(delim)?;
    let rest = &text[start + delim.len_utf8()..];
    let end = rest.find(delim)?;
    let inner = rest[..end].trim();
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

/// Normalize an `ExitCode` payload's `command` field to a lowercase string
/// for substring matching, regardless of which real adapter shape produced
/// it — Claude Code's Bash `tool_input.command` is a plain string (e.g.
/// `"npm install"`), Codex's rollout `exec_command_end.command` is a JSON
/// array of argv tokens (e.g. `["npm", "install"]`).
fn command_text(payload: &serde_json::Value) -> String {
    match payload.get("command") {
        Some(serde_json::Value::Array(tokens)) => tokens
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase(),
        Some(serde_json::Value::String(s)) => s.to_lowercase(),
        Some(other) => other.to_string().to_lowercase(),
        None => String::new(),
    }
}

fn is_test_runner_evidence(e: &Evidence) -> bool {
    // FORNX-295: must use the space-joined `command_text` normalization, not
    // a raw `Value::to_string()` — Codex's real rollout shape is a JSON argv
    // array (e.g. `["cargo","test"]`), whose `to_string()` renders as
    // `["cargo","test"]` (quotes and brackets intact) and never contains the
    // literal substring "cargo test". Using the shared helper here matches
    // how `command_text` is already used elsewhere in this file.
    let cmd = command_text(&e.payload);
    e.payload.get("exit_code").is_some()
        && (cmd.contains("pytest")
            || cmd.contains("cargo test")
            || cmd.contains("cargo nextest")
            || cmd.contains("npm test")
            || cmd.contains("vitest")
            || cmd.contains("jest"))
}

/// True when `e`'s nonzero `exit_code` was synthesized by
/// `fornax-adapter-claude`'s `ClaudeBashExitCodeSensor` from the
/// `stderr_nonempty` heuristic (`"heuristic": true` and provenance ending in
/// `#heuristic:stderr_nonempty`) rather than observed from a real exit code.
///
/// Claude Code's real PostToolUse `tool_response` never carries an actual
/// exit code field; the adapter falls back to inferring failure from
/// non-empty stderr, which is wrong whenever a command writes to stderr
/// (a warning, a progress message, ...) but still exits 0. Deliberately
/// narrow: `heuristic:interrupted` (an explicit signal that the user killed
/// the command) and `heuristic:stderr_empty` (which only ever produces
/// exit_code 0) are excluded — only this specific heuristic reason is
/// unreliable in the failure direction.
fn is_stderr_heuristic_evidence(e: &Evidence) -> bool {
    e.payload.get("heuristic").and_then(|v| v.as_bool()) == Some(true)
        && e.provenance.ends_with("heuristic:stderr_nonempty")
}

fn unavailable(claim_id: Uuid, verifier: &str, reason: &str, now: String) -> Finding {
    Finding {
        id: Uuid::new_v4(),
        claim_id,
        verdict: Verdict::Unavailable,
        evidence_ids: vec![],
        verifier_name: verifier.to_string(),
        rationale: reason.to_string(),
        computed_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{CapabilitySignal, EvidenceKind, Provider, SignalAvailability};

    fn caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Codex,
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
                    state: SignalAvailability::Unsupported,
                    detail: None,
                },
            ],
            notes: Default::default(),
        }
    }

    fn with_state(
        mut c: RuntimeCapabilities,
        class: SignalClass,
        state: SignalAvailability,
    ) -> RuntimeCapabilities {
        if let Some(s) = c.signals.iter_mut().find(|s| s.class == class) {
            s.state = state;
        } else {
            c.signals.push(CapabilitySignal {
                class,
                state,
                detail: None,
            });
        }
        c
    }

    fn evidence_with_exit_code(code: i64) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::json!({"command": ["pytest"], "exit_code": code}),
            provenance: "codex:rollout:exec_command_end".into(),
            source: None,
            extension: None,
        }
    }

    fn claim(text: &str) -> Claim {
        claim_for("test_result", text)
    }

    pub(crate) fn claim_for(subject: &str, text: &str) -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: text.into(),
            subject: subject.into(),
            claimed_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// `command` as Codex's real rollout shape: a JSON array of argv tokens.
    pub(crate) fn evidence_for_command(command: &[&str], exit_code: i64) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::json!({"command": command, "exit_code": exit_code}),
            provenance: "codex:rollout:exec_command_end".into(),
            source: None,
            extension: None,
        }
    }

    #[test]
    fn contradicts_when_agent_claims_pass_but_exit_code_nonzero() {
        let v = TestResultVerifier;
        let c = claim("All tests passed.");
        let ev = vec![evidence_with_exit_code(1)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Contradicted);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    #[test]
    fn verified_when_exit_code_zero() {
        let v = TestResultVerifier;
        let c = claim("All tests passed.");
        let ev = vec![evidence_with_exit_code(0)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Verified);
    }

    #[test]
    fn unverified_when_no_test_evidence_present() {
        let v = TestResultVerifier;
        let c = claim("All tests passed.");
        let f = v.verify(&c, &[], &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
    }

    /// FORNX-295 regression: Codex's real rollout evidence carries `command`
    /// as a JSON argv array (`["cargo","test"]`), not a single string. A
    /// naive `Value::to_string()` renders that as `["cargo","test"]` — which
    /// never contains the literal substring "cargo test" — so this multi-
    /// token command was silently invisible to `is_test_runner_evidence`.
    #[test]
    fn recognizes_multi_token_argv_test_runner_commands() {
        let v = TestResultVerifier;
        let c = claim("All tests passed.");
        let ev = vec![evidence_for_command(&["cargo", "test"], 1)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Contradicted);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);

        let ev2 = vec![evidence_for_command(&["cargo", "nextest", "run"], 0)];
        let f2 = v.verify(&c, &ev2, &caps());
        assert_eq!(f2.verdict, Verdict::Verified);
    }

    #[test]
    fn unavailable_when_runtime_cannot_observe_tool_results() {
        let v = TestResultVerifier;
        let c = claim("All tests passed.");
        let mut no_caps = caps();
        no_caps = with_state(no_caps, SignalClass::ToolTrace, SignalAvailability::Unknown);
        no_caps = with_state(
            no_caps,
            SignalClass::FinalResponse,
            SignalAvailability::Unknown,
        );
        let f = v.verify(&c, &[], &no_caps);
        assert_eq!(f.verdict, Verdict::Unavailable);
    }

    /// FORNX-155 AC4 regression: deserializing the exact pre-formalization
    /// flat-bool JSON shape for every combination of the two classes this
    /// verifier's gate consults must still produce the pre-change verdict.
    /// This is the proof that the formalization changed no externally
    /// observable behavior, not just that the two hand-built fixtures above
    /// happen to agree.
    #[test]
    fn legacy_bool_shapes_reproduce_pre_formalization_verdicts_for_every_combination() {
        let v = TestResultVerifier;
        let ev = vec![evidence_with_exit_code(0)];

        for (post_tool_use, transcript_tail) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            let json = format!(
                r#"{{"provider":"codex","supports_pre_tool_use":true,
                "supports_post_tool_use":{post_tool_use},
                "supports_tool_response_capture":true,
                "supports_session_stop_event":true,
                "supports_transcript_tail":{transcript_tail},
                "supports_subagent_lifecycle":false,"notes":{{}}}}"#
            );
            let caps: RuntimeCapabilities = serde_json::from_str(&json).unwrap();
            let c = claim("All tests passed.");
            let f = v.verify(&c, &ev, &caps);

            let expect_available = post_tool_use || transcript_tail;
            if expect_available {
                assert_eq!(
                    f.verdict,
                    Verdict::Verified,
                    "post_tool_use={post_tool_use} transcript_tail={transcript_tail}"
                );
            } else {
                assert_eq!(
                    f.verdict,
                    Verdict::Unavailable,
                    "post_tool_use={post_tool_use} transcript_tail={transcript_tail}"
                );
            }
        }
    }

    #[test]
    fn claim_text_heuristic_matches_expected_phrasings() {
        assert!(TestResultVerifier::claims_tests_passed("All tests passed."));
        assert!(TestResultVerifier::claims_tests_passed("tests succeeded"));
        assert!(!TestResultVerifier::claims_tests_passed("3 tests failed"));
    }

    /// FORNX-27 AC: "A replay command/test can recompute findings from
    /// persisted evidence." Re-running verify() against the exact same
    /// claim+evidence+capabilities (as if freshly loaded from storage,
    /// FORNX-26) must yield the identical verdict and rationale — no hidden
    /// state, no non-determinism, safe to recompute after a verifier change.
    #[test]
    fn recomputing_from_the_same_persisted_inputs_is_deterministic() {
        let v = TestResultVerifier;
        let c = claim("All tests passed.");
        let ev = vec![evidence_with_exit_code(1)];
        let capabilities = caps();

        let first = v.verify(&c, &ev, &capabilities);
        let replayed = v.verify(&c, &ev, &capabilities);

        assert_eq!(first.verdict, replayed.verdict);
        assert_eq!(first.rationale, replayed.rationale);
        assert_eq!(first.evidence_ids, replayed.evidence_ids);
    }

    /// FORNX-15 regression: `fornax-adapter-claude`'s `ClaudeBashExitCodeSensor`
    /// synthesizes `exit_code: 1` whenever a Bash tool call's stderr is
    /// non-empty, because Claude Code's real PostToolUse `tool_response`
    /// carries no actual exit code field (documented capability gap, not a
    /// real signal). A command that writes to stderr but genuinely exits 0
    /// must not be reported as `Contradicted` against a "tests passed"
    /// claim -- it must be flagged `Review`, since the heuristic cannot
    /// actually confirm failure. Mirrors the exact payload shape produced by
    /// `post_tool_use_real_shape_stderr_nonempty_infers_heuristic_failure`
    /// in `fornax-adapter-claude`.
    #[test]
    fn heuristic_stderr_nonempty_failure_is_review_not_contradicted() {
        let v = TestResultVerifier;
        let c = claim("All tests passed.");
        let ev = vec![Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::json!({
                "command": "pytest",
                "exit_code": 1,
                "heuristic": true,
            }),
            provenance: "claude_code:1.2.3:PostToolUse:Bash#heuristic:stderr_nonempty".into(),
            source: None,
            extension: None,
        }];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Review);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    /// Companion to the above: `heuristic:interrupted` is an explicit real
    /// signal from Claude Code (the user genuinely killed/interrupted the
    /// command), not an unreliable inference, so a nonzero exit_code from
    /// that reason must still produce `Contradicted` -- proving the
    /// downgrade above didn't get accidentally widened to the wrong case.
    #[test]
    fn heuristic_interrupted_failure_still_contradicts() {
        let v = TestResultVerifier;
        let c = claim("All tests passed.");
        let ev = vec![Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::json!({
                "command": "pytest",
                "exit_code": 130,
                "heuristic": true,
            }),
            provenance: "claude_code:1.2.3:PostToolUse:Bash#heuristic:interrupted".into(),
            source: None,
            extension: None,
        }];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Contradicted);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    /// FORNX-159 AC: "Provenance fields remain stable under replay." Extends
    /// `recomputing_from_the_same_persisted_inputs_is_deterministic` above
    /// (FORNX-27's replay contract) with evidence that actually carries the
    /// full FORNX-157/159 `EvidenceSource` — a verifier consumes `Evidence`
    /// by shared reference and must not mutate, drop, or otherwise disturb
    /// its provenance metadata while computing a finding, whether run once
    /// or replayed.
    #[test]
    fn evidence_source_provenance_is_unchanged_by_verification_and_stable_under_replay() {
        let v = TestResultVerifier;
        let c = claim("All tests passed.");
        let source = fornax_types::EvidenceSource::now(
            "codex_exec_command_end_sensor_v1",
            fornax_types::TrustClass::AgentAdjacent,
            Some(fornax_types::Provider::Codex),
            fornax_types::CollectionMethod::FilePoll,
            Some("codex-adapter-0.1.0".to_string()),
        );
        let mut ev = evidence_with_exit_code(0);
        ev.source = Some(source.clone());
        let ev = vec![ev];
        let capabilities = caps();

        let first = v.verify(&c, &ev, &capabilities);
        let replayed = v.verify(&c, &ev, &capabilities);

        // The finding itself is deterministic (FORNX-27's existing
        // guarantee, re-asserted here against provenance-bearing evidence).
        assert_eq!(first.verdict, replayed.verdict);
        assert_eq!(first.rationale, replayed.rationale);

        // The provenance metadata on the input evidence is untouched by
        // either verify() call — not mutated, not stripped to None.
        assert_eq!(ev[0].source.as_ref(), Some(&source));
    }
}

#[cfg(test)]
mod command_executed_verifier_tests {
    use super::*;
    use fornax_types::{CapabilitySignal, Provider, SignalAvailability};

    fn caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Codex,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::FinalResponse,
                    state: SignalAvailability::Available,
                    detail: None,
                },
            ],
            notes: Default::default(),
        }
    }

    fn no_caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Codex,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Unknown,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::FinalResponse,
                    state: SignalAvailability::Unknown,
                    detail: None,
                },
            ],
            notes: Default::default(),
        }
    }

    #[test]
    fn verified_when_named_command_matches_evidence() {
        let v = CommandExecutedVerifier;
        let c = crate::tests::claim_for("command_executed", "I ran `npm install`.");
        let ev = vec![crate::tests::evidence_for_command(&["npm", "install"], 0)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Verified);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    #[test]
    fn verified_regardless_of_exit_code_since_this_only_checks_execution() {
        let v = CommandExecutedVerifier;
        let c = crate::tests::claim_for("command_executed", "I ran `pytest`.");
        let ev = vec![crate::tests::evidence_for_command(&["pytest"], 1)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Verified);
    }

    #[test]
    fn unverified_when_no_matching_command_evidence() {
        let v = CommandExecutedVerifier;
        let c = crate::tests::claim_for("command_executed", "I ran `npm install`.");
        let ev = vec![crate::tests::evidence_for_command(&["pytest"], 0)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
        assert!(f.evidence_ids.is_empty());
    }

    #[test]
    fn unverified_when_claim_names_no_literal_command() {
        let v = CommandExecutedVerifier;
        let c = crate::tests::claim_for("command_executed", "I ran a command.");
        let ev = vec![crate::tests::evidence_for_command(&["pytest"], 0)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
    }

    #[test]
    fn unavailable_when_runtime_cannot_observe_tool_traces() {
        let v = CommandExecutedVerifier;
        let c = crate::tests::claim_for("command_executed", "I ran `npm install`.");
        let f = v.verify(&c, &[], &no_caps());
        assert_eq!(f.verdict, Verdict::Unavailable);
    }

    #[test]
    fn claim_text_heuristic_matches_expected_phrasings() {
        assert!(CommandExecutedVerifier::claims_command_executed(
            "I ran `npm install`."
        ));
        assert!(CommandExecutedVerifier::claims_command_executed(
            "Executed the build script."
        ));
        assert!(!CommandExecutedVerifier::claims_command_executed(
            "The build passed."
        ));
    }

    #[test]
    fn recomputing_from_the_same_persisted_inputs_is_deterministic() {
        let v = CommandExecutedVerifier;
        let c = crate::tests::claim_for("command_executed", "I ran `npm install`.");
        let ev = vec![crate::tests::evidence_for_command(&["npm", "install"], 0)];
        let capabilities = caps();

        let first = v.verify(&c, &ev, &capabilities);
        let replayed = v.verify(&c, &ev, &capabilities);

        assert_eq!(first.verdict, replayed.verdict);
        assert_eq!(first.rationale, replayed.rationale);
        assert_eq!(first.evidence_ids, replayed.evidence_ids);
    }
}

#[cfg(test)]
mod command_success_verifier_tests {
    use super::*;
    use fornax_types::{CapabilitySignal, Provider, SignalAvailability};

    fn caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Codex,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Available,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::FinalResponse,
                    state: SignalAvailability::Available,
                    detail: None,
                },
            ],
            notes: Default::default(),
        }
    }

    fn no_caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::Codex,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Unknown,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::FinalResponse,
                    state: SignalAvailability::Unknown,
                    detail: None,
                },
            ],
            notes: Default::default(),
        }
    }

    #[test]
    fn verified_when_named_command_exit_code_zero() {
        let v = CommandSuccessVerifier;
        let c = crate::tests::claim_for("command_succeeded", "The `npm install` succeeded.");
        let ev = vec![crate::tests::evidence_for_command(&["npm", "install"], 0)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Verified);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    #[test]
    fn contradicted_when_named_command_exit_code_nonzero() {
        let v = CommandSuccessVerifier;
        let c = crate::tests::claim_for("command_succeeded", "The `npm install` succeeded.");
        let ev = vec![crate::tests::evidence_for_command(&["npm", "install"], 1)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Contradicted);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    #[test]
    fn generic_claim_without_named_command_is_unverified_even_with_evidence_present() {
        let v = CommandSuccessVerifier;
        let c = crate::tests::claim_for("command_succeeded", "The command succeeded.");
        let ev = vec![crate::tests::evidence_for_command(&["npm", "install"], 0)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
        assert!(f.evidence_ids.is_empty());
    }

    /// Regression: a generic claim must never bind to unrelated evidence
    /// just because it is the most recent in the session — that would
    /// produce a false `Contradicted` against a command the claim never
    /// named (e.g. an unrelated failing `pytest` run "contradicting" a claim
    /// about "the deploy").
    #[test]
    fn generic_claim_does_not_bind_to_unrelated_failing_evidence() {
        let v = CommandSuccessVerifier;
        let c = crate::tests::claim_for("command_succeeded", "The command succeeded.");
        let ev = vec![crate::tests::evidence_for_command(&["pytest"], 1)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
        assert!(f.evidence_ids.is_empty());
    }

    #[test]
    fn unverified_when_no_command_evidence_present() {
        let v = CommandSuccessVerifier;
        let c = crate::tests::claim_for("command_succeeded", "The command succeeded.");
        let f = v.verify(&c, &[], &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
    }

    #[test]
    fn unavailable_when_runtime_cannot_observe_tool_traces() {
        let v = CommandSuccessVerifier;
        let c = crate::tests::claim_for("command_succeeded", "The command succeeded.");
        let f = v.verify(&c, &[], &no_caps());
        assert_eq!(f.verdict, Verdict::Unavailable);
    }

    #[test]
    fn claim_text_heuristic_matches_expected_phrasings() {
        assert!(CommandSuccessVerifier::claims_command_succeeded(
            "The build succeeded."
        ));
        assert!(CommandSuccessVerifier::claims_command_succeeded(
            "It completed successfully."
        ));
        assert!(!CommandSuccessVerifier::claims_command_succeeded(
            "The build failed."
        ));
    }

    #[test]
    fn recomputing_from_the_same_persisted_inputs_is_deterministic() {
        let v = CommandSuccessVerifier;
        let c = crate::tests::claim_for("command_succeeded", "The `pytest` succeeded.");
        let ev = vec![crate::tests::evidence_for_command(&["pytest"], 1)];
        let capabilities = caps();

        let first = v.verify(&c, &ev, &capabilities);
        let replayed = v.verify(&c, &ev, &capabilities);

        assert_eq!(first.verdict, replayed.verdict);
        assert_eq!(first.rationale, replayed.rationale);
        assert_eq!(first.evidence_ids, replayed.evidence_ids);
    }

    /// FORNX-15 regression: same false-`Contradicted` bug as
    /// `TestResultVerifier`, exercised through `CommandSuccessVerifier`'s
    /// own named-command matching path.
    #[test]
    fn heuristic_stderr_nonempty_failure_is_review_not_contradicted() {
        let v = CommandSuccessVerifier;
        let c = crate::tests::claim_for("command_succeeded", "The `npm install` succeeded.");
        let ev = vec![Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::json!({
                "command": "npm install",
                "exit_code": 1,
                "heuristic": true,
            }),
            provenance: "claude_code:1.2.3:PostToolUse:Bash#heuristic:stderr_nonempty".into(),
            source: None,
            extension: None,
        }];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Review);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    /// Companion: `heuristic:interrupted` remains a real signal and still
    /// contradicts, proving the downgrade wasn't widened past its intended
    /// scope.
    #[test]
    fn heuristic_interrupted_failure_still_contradicts() {
        let v = CommandSuccessVerifier;
        let c = crate::tests::claim_for("command_succeeded", "The `npm install` succeeded.");
        let ev = vec![Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::json!({
                "command": "npm install",
                "exit_code": 130,
                "heuristic": true,
            }),
            provenance: "claude_code:1.2.3:PostToolUse:Bash#heuristic:interrupted".into(),
            source: None,
            extension: None,
        }];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Contradicted);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }
}

#[cfg(test)]
mod file_modified_verifier_tests {
    use super::*;
    use fornax_types::{CapabilitySignal, Provider, SignalAvailability};

    fn caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::ClaudeCode,
            signals: vec![
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
            ],
            notes: Default::default(),
        }
    }

    fn no_caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::ClaudeCode,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Unknown,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::ToolResultPayload,
                    state: SignalAvailability::Unknown,
                    detail: None,
                },
            ],
            notes: Default::default(),
        }
    }

    fn file_diff_evidence(path: &str, diff: &str) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::FileDiff,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::json!({"path": path, "diff": diff}),
            provenance: "claude_code:1.2.3:PostToolUse:Edit#heuristic:tool_input".into(),
            source: None,
            extension: None,
        }
    }

    #[test]
    fn review_when_named_file_matches_evidence() {
        let v = FileModifiedVerifier;
        let c = crate::tests::claim_for("file_written", "I updated `src/lib.rs`.");
        let ev = vec![file_diff_evidence(
            "/Users/x/project/src/lib.rs",
            "-old\n+new\n",
        )];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Review);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    #[test]
    fn unverified_when_no_matching_file_evidence() {
        let v = FileModifiedVerifier;
        let c = crate::tests::claim_for("file_written", "I updated `src/lib.rs`.");
        let ev = vec![file_diff_evidence(
            "/Users/x/project/src/otherlib.rs",
            "+new\n",
        )];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
        assert!(f.evidence_ids.is_empty());
    }

    /// Path-segment-boundary regression: a naive substring match would wrongly
    /// bind `src/lib.rs` to `src/otherlib.rs` since the latter ends with the
    /// former's characters preceded by no `/`.
    #[test]
    fn does_not_substring_match_across_path_segment_boundary() {
        let v = FileModifiedVerifier;
        let c = crate::tests::claim_for("file_written", "I updated `lib.rs`.");
        let ev = vec![file_diff_evidence(
            "/Users/x/project/src/otherlib.rs",
            "+new\n",
        )];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
    }

    #[test]
    fn unverified_when_claim_names_no_path_literal() {
        let v = FileModifiedVerifier;
        let c = crate::tests::claim_for("file_written", "I updated the file.");
        let ev = vec![file_diff_evidence("/Users/x/project/src/lib.rs", "+new\n")];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
        assert!(f.evidence_ids.is_empty());
    }

    /// A generic/unrelated claim naming a command, not a path, must not
    /// spuriously bind to file evidence just because it is backtick-quoted
    /// the same way a path literal is.
    #[test]
    fn unrelated_command_claim_does_not_bind_to_file_evidence() {
        let v = FileModifiedVerifier;
        let c = crate::tests::claim_for("file_written", "I ran `npm install`.");
        let ev = vec![file_diff_evidence("/Users/x/project/src/lib.rs", "+new\n")];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
        assert!(f.evidence_ids.is_empty());
    }

    #[test]
    fn unavailable_when_runtime_cannot_observe_tool_traces_or_results() {
        let v = FileModifiedVerifier;
        let c = crate::tests::claim_for("file_written", "I updated `src/lib.rs`.");
        let f = v.verify(&c, &[], &no_caps());
        assert_eq!(f.verdict, Verdict::Unavailable);
    }

    #[test]
    fn recomputing_from_the_same_persisted_inputs_is_deterministic() {
        let v = FileModifiedVerifier;
        let c = crate::tests::claim_for("file_written", "I updated `src/lib.rs`.");
        let ev = vec![file_diff_evidence(
            "/Users/x/project/src/lib.rs",
            "-old\n+new\n",
        )];
        let capabilities = caps();

        let first = v.verify(&c, &ev, &capabilities);
        let replayed = v.verify(&c, &ev, &capabilities);

        assert_eq!(first.verdict, replayed.verdict);
        assert_eq!(first.rationale, replayed.rationale);
        assert_eq!(first.evidence_ids, replayed.evidence_ids);
    }
}

#[cfg(test)]
mod git_operation_verifier_tests {
    use super::*;
    use fornax_types::{CapabilitySignal, Provider, SignalAvailability};

    fn caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::ClaudeCode,
            signals: vec![
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
            ],
            notes: Default::default(),
        }
    }

    fn no_caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::ClaudeCode,
            signals: vec![
                CapabilitySignal {
                    class: SignalClass::ToolTrace,
                    state: SignalAvailability::Unknown,
                    detail: None,
                },
                CapabilitySignal {
                    class: SignalClass::ToolResultPayload,
                    state: SignalAvailability::Unknown,
                    detail: None,
                },
            ],
            notes: Default::default(),
        }
    }

    fn vcs_evidence(observation: serde_json::Value) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ProcessObservation,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::json!({
                "description": "git observation",
                "observation": observation,
            }),
            provenance: "claude_code:1.2.3:PostToolUse:Bash#tool_response:git_commit".into(),
            source: None,
            extension: None,
        }
    }

    fn commit_evidence(outcome: &str, commit_sha: Option<&str>, branch: Option<&str>) -> Evidence {
        vcs_evidence(serde_json::json!({
            "observation_kind": "vcs_operation",
            "operation": "commit",
            "outcome": outcome,
            "commit_sha": commit_sha,
            "branch": branch,
        }))
    }

    fn push_evidence(outcome: &str, branch: Option<&str>) -> Evidence {
        vcs_evidence(serde_json::json!({
            "observation_kind": "vcs_operation",
            "operation": "push",
            "outcome": outcome,
            "branch": branch,
        }))
    }

    // --- git_commit ---------------------------------------------------

    #[test]
    fn created_with_no_sha_literal_in_claim_is_verified() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_commit", "I committed the change.");
        let ev = vec![commit_evidence("created", Some("0e2fbd4"), Some("main"))];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Verified);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    #[test]
    fn created_with_matching_sha_literal_is_verified() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_commit", "I committed with sha `0e2fbd4`.");
        let ev = vec![commit_evidence("created", Some("0e2fbd4"), Some("main"))];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Verified);
    }

    /// Falsification (required): a mismatched SHA literal must actually
    /// contradict, not silently pass.
    #[test]
    fn created_with_mismatched_sha_literal_is_contradicted() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_commit", "I committed with sha `deadbee`.");
        let ev = vec![commit_evidence("created", Some("abc1234"), Some("main"))];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Contradicted);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    #[test]
    fn nothing_to_commit_is_contradicted() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_commit", "I committed the change.");
        let ev = vec![commit_evidence("nothing_to_commit", None, None)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Contradicted);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    #[test]
    fn no_matching_evidence_is_unverified_for_git_commit() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_commit", "I committed the change.");
        let f = v.verify(&c, &[], &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
        assert!(f.evidence_ids.is_empty());
    }

    // --- git_push -------------------------------------------------------

    #[test]
    fn ref_updated_is_verified() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_push", "I pushed the branch.");
        let ev = vec![push_evidence("ref_updated", Some("main"))];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Verified);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    #[test]
    fn ref_updated_with_matching_branch_literal_is_verified() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_push", "I pushed to `main`.");
        let ev = vec![push_evidence("ref_updated", Some("main"))];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Verified);
    }

    #[test]
    fn ref_updated_with_mismatched_branch_literal_is_unverified() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_push", "I pushed to `develop`.");
        let ev = vec![push_evidence("ref_updated", Some("main"))];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
    }

    #[test]
    fn rejected_push_is_contradicted() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_push", "I pushed the branch.");
        let ev = vec![push_evidence("rejected", None)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Contradicted);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    #[test]
    fn up_to_date_push_is_review() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_push", "I pushed the branch.");
        let ev = vec![push_evidence("up_to_date", None)];
        let f = v.verify(&c, &ev, &caps());
        assert_eq!(f.verdict, Verdict::Review);
        assert_eq!(f.evidence_ids, vec![ev[0].id]);
    }

    #[test]
    fn no_matching_evidence_is_unverified_for_git_push() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_push", "I pushed the branch.");
        let f = v.verify(&c, &[], &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
        assert!(f.evidence_ids.is_empty());
    }

    // --- capability gate --------------------------------------------------

    #[test]
    fn capability_gate_closed_is_unavailable_for_git_commit() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_commit", "I committed the change.");
        let f = v.verify(&c, &[], &no_caps());
        assert_eq!(f.verdict, Verdict::Unavailable);
    }

    #[test]
    fn capability_gate_closed_is_unavailable_for_git_push() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_push", "I pushed the branch.");
        let f = v.verify(&c, &[], &no_caps());
        assert_eq!(f.verdict, Verdict::Unavailable);
    }

    // --- applies_to ---------------------------------------------------

    #[test]
    fn applies_to_both_git_subjects_only() {
        let v = GitOperationVerifier;
        assert!(v.applies_to(&crate::tests::claim_for("git_commit", "x")));
        assert!(v.applies_to(&crate::tests::claim_for("git_push", "x")));
        assert!(!v.applies_to(&crate::tests::claim_for("test_result", "x")));
    }

    // --- determinism ----------------------------------------------------

    #[test]
    fn recomputing_from_the_same_persisted_inputs_is_deterministic() {
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_commit", "I committed with sha `0e2fbd4`.");
        let ev = vec![commit_evidence("created", Some("0e2fbd4"), Some("main"))];
        let capabilities = caps();

        let first = v.verify(&c, &ev, &capabilities);
        let replayed = v.verify(&c, &ev, &capabilities);

        assert_eq!(first.verdict, replayed.verdict);
        assert_eq!(first.rationale, replayed.rationale);
        assert_eq!(first.evidence_ids, replayed.evidence_ids);
    }
}
