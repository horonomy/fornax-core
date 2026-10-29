//! Deterministic claim verification (FORNX-27).
//!
//! `Claim + Evidence[] + RuntimeCapabilities -> Finding`, pure — no I/O.
//! Verifiers must never invent evidence: absent the signal they need, they
//! return `Unavailable`, not `Verified`.

use fornax_types::{
    Claim, Evidence, EvidenceKind, Finding, RuntimeCapabilities, SignalClass, TrustClass, Verdict,
};
use uuid::Uuid;

pub mod calibration;
pub mod contract_satisfaction;
pub mod decision;
pub mod fusion;
pub mod independence;
pub mod judge;
pub mod meta_verification;
pub mod reliability;
mod runner_command;
pub mod verification_budget;
pub mod voi;

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
        let test_evidence = evidence.iter().rposition(is_test_runner_evidence);

        let Some(ev_idx) = test_evidence else {
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

        let ev = &evidence[ev_idx];
        let exit_code = ev.payload.get("exit_code").and_then(|v| v.as_i64());

        // FORNX-477: only *identified* runner rows are evidence, but a newer
        // exit-code row that merely mentions a runner (`cd repo && pytest`
        // exiting 1, `pytest | tail`, ...) may be the real run -- failing,
        // passing or masked. An older result must not decide over it.
        let newer_unidentified_runner_mention = evidence[ev_idx + 1..]
            .iter()
            .any(mentions_unidentified_runner);

        match exit_code {
            // FORNX-433 follow-up: a heuristic `exit_code=0` (no real exit
            // code observed — see `is_heuristic_evidence`'s doc comment for
            // why "no stderr" never proves success) must not reach Verified.
            // A real test-runner exit code (`heuristic` absent/false) still
            // does.
            Some(0) if is_heuristic_evidence(ev) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Review,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "claim states tests passed; the only signal observed is a heuristic \
                     exit_code=0 (no stderr/failure marker seen), which does not prove the \
                     test runner actually succeeded -- flagged for review, not verified \
                     ({})",
                    ev.provenance
                ),
                computed_at: now,
            },
            Some(0) if newer_unidentified_runner_mention => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: "an earlier test-runner run exited 0, but a more recent command that \
                            mentions a test runner could not be identified as a test run"
                    .to_string(),
                computed_at: now,
            },
            // FORNX-477: a runner name and exit status 0 do not show any test
            // ran (a script called `pytest` that only does `exit 0`, or
            // `cargo test no_such_test`, also exit 0). `Verified` needs the
            // runner's own passing summary, attributable to this command.
            Some(0) if !execution_proven(ev) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale:
                    "the test runner exited 0, but no passing-test summary from that runner \
                            was observed for this command, so it is not shown that any test ran"
                        .to_string(),
                computed_at: now,
            },
            // FORNX-477 trust boundary: the runner's exit status and summary
            // are written by whatever program the agent ran. A QA-owned
            // script named `pytest` can print `3 passed` and exit 0 without
            // running a test, and nothing in the transcript can tell it apart
            // from the real runner. Evidence that only the agent's own
            // provider account carries (`AgentAdjacent`, or no recorded
            // source at all) therefore tops out at `Review`; `Verified` needs
            // evidence Fornax or an outside system observed (ADR-0025
            // options 1-3, FORNX-443).
            Some(0) if !is_independently_attested(ev) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Review,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "claim states tests passed and the agent's transcript shows a test runner \
                     exiting 0 with a passing summary, but that output is written by the \
                     program the agent ran and is not independently attested, so it does not \
                     show the tests ran -- flagged for review, not verified ({})",
                    ev.provenance
                ),
                computed_at: now,
            },
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
        // Both spellings of the claim's literal: as written (an env assignment such
        // as `CI=1 pytest` is case-sensitive) and lowercased (the evidence match
        // above lowercases, so `PYTEST` matches `echo pytest` and must be seen as
        // naming a runner too). Every runner counts, including those whose output
        // is not read (`jest`, `npm test`); OR-ing only adds downgrades.
        let names_runner = |literal: String| {
            runner_command::names_test_runner(Some(&serde_json::Value::String(literal)))
        };
        let claim_names_test_runner = names_runner(claimed.clone())
            || CommandExecutedVerifier::extract_command_literal(&claim.text)
                .is_some_and(names_runner);

        match exit_code {
            // Same reasoning as `TestResultVerifier`'s mirror branch above:
            // a heuristic `exit_code=0` does not prove the command actually
            // succeeded.
            Some(0) if is_heuristic_evidence(ev) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Review,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "claim states the command succeeded; the only signal observed is a \
                     heuristic exit_code=0 (no stderr/failure marker seen), which does not \
                     prove the command actually succeeded -- flagged for review, not \
                     verified ({})",
                    ev.provenance
                ),
                computed_at: now,
            },
            // FORNX-477: "the `pytest` run succeeded" asserts that tests ran
            // and passed just as "all tests passed" does, so re-labelling the
            // claim `command_succeeded` must not buy a different bar. When the
            // matched command is an identified test run, the same conditions
            // apply as for `test_result` (a passing summary from that runner,
            // and evidence the agent did not write: `is_independently_attested`).
            Some(0) if is_test_runner_evidence(ev) && !execution_proven(ev) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: "the claimed command is a test run that exited 0, but no passing-test \
                            summary from that runner was observed, so it is not shown that any \
                            test ran"
                    .to_string(),
                computed_at: now,
            },
            Some(0) if is_test_runner_evidence(ev) && !is_independently_attested(ev) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Review,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: format!(
                    "the claimed command is a test run that exited 0 with a passing summary, \
                     but that output is written by the program the agent ran and is not \
                     independently attested, so it does not show the tests ran -- flagged for \
                     review, not verified ({})",
                    ev.provenance
                ),
                computed_at: now,
            },
            // The claim names a test runner but the evidence it matched is not
            // an identified run of one (`echo pytest`, a compound command, ...).
            Some(0) if claim_names_test_runner && !is_test_runner_evidence(ev) => Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Unverified,
                evidence_ids: vec![ev.id],
                verifier_name: self.name().to_string(),
                rationale: "the claimed command is a test runner, but the matching evidence is \
                            not an identified run of one"
                    .to_string(),
                computed_at: now,
            },
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

/// Collectors that may attest a test run, by `EvidenceSource::sensor_name`.
///
/// Deliberately empty: no shipped sensor measures a test run outside the
/// agent's own account of it. `claude_git_working_tree_sensor_v1` and
/// `claude_file_write_confirmed_sensor_v1` are `HostObserved`, but they observe
/// the working tree, not a runner; letting their identity vouch for an exit
/// code would let anything that can submit evidence under a registered name
/// promote itself. The real host-controlled runner receipt / CI evidence is
/// FORNX-443 and adds its collector here, with its own tests.
///
/// Under `cfg(test)` a fixture collector exists so the `Verified` arm can be
/// exercised. That proves only the gate's logic, not that production
/// attestation exists.
fn test_run_attestors() -> &'static [&'static str] {
    #[cfg(test)]
    {
        &["test_fixture_run_attestor"]
    }
    #[cfg(not(test))]
    {
        &[]
    }
}

/// True when the evidence was produced by a collector authorised to attest a
/// test run *and* carries a trust class other than the agent's own account
/// (`HostObserved`, or `IndependentExternal` such as CI). The class label alone
/// never suffices: it is a field of the submitted record, so the collector
/// identity must also be one this verifier knows (`test_run_attestors`).
/// Evidence with no recorded source predates the sensor contract and is not
/// treated as attested.
fn is_independently_attested(e: &Evidence) -> bool {
    e.source.as_ref().is_some_and(|s| {
        matches!(
            s.trust_class,
            TrustClass::HostObserved | TrustClass::IndependentExternal
        ) && test_run_attestors().contains(&s.sensor_name.as_str())
    })
}

/// True when the exit-code evidence for a runner command also carries that
/// runner's own summary showing at least one test passed and none failed.
/// The summary only ever adds a condition for `Verified`; it never grants one
/// (ADR-0025's safety-monotonic bar for stdout-derived signals).
fn execution_proven(e: &Evidence) -> bool {
    let Some(kind) = runner_command::proven_runner(e.payload.get("command")) else {
        return false;
    };
    let Some(summary) = e.payload.get("test_summary") else {
        return false;
    };
    let format = summary.get("format").and_then(|v| v.as_str());
    let passed = summary.get("passed").and_then(|v| v.as_u64());
    let failed = summary.get("failed").and_then(|v| v.as_u64());
    let format_matches = match kind {
        runner_command::RunnerKind::Pytest => format == Some("pytest"),
        runner_command::RunnerKind::Cargo => format == Some("cargo"),
        runner_command::RunnerKind::Other => false,
    };
    format_matches && passed.is_some_and(|n| n >= 1) && failed == Some(0)
}

fn is_test_runner_evidence(e: &Evidence) -> bool {
    // FORNX-477: identify the runner from the executed command's structure
    // (see `runner_command`), never from a substring of the command text --
    // `echo pytest` or `pip install pytest` exiting 0 is not a test run. The
    // exit code itself must still be present on the same evidence row.
    runner_command::is_test_run(
        e.payload.get("command"),
        e.payload.get("exit_code").and_then(|v| v.as_i64()),
    ) && e.payload.get("exit_code").is_some()
}

/// An exit-code row whose command text names a test runner but which
/// `is_test_runner_evidence` could not identify as one. Used only to *withhold*
/// `Verified` (see `TestResultVerifier::verify`); a substring match never
/// grants a verdict.
fn mentions_unidentified_runner(e: &Evidence) -> bool {
    if e.payload.get("exit_code").is_none() || is_test_runner_evidence(e) {
        return false;
    }
    let cmd = command_text(&e.payload);
    let tokens: Vec<&str> = cmd
        .split(|c: char| !(c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '/' | '+')))
        .filter(|t| !t.is_empty())
        .collect();
    // Substring, not equality: `pytest-3`, `python3-pytest`, `./node_modules/.bin/jest`
    // all count. A false mention only withholds Verified.
    let names_runner = |t: &&str| {
        ["pytest", "py.test", "vitest", "jest"]
            .iter()
            .any(|r| t.contains(r))
    };
    // `cargo` or `npm` followed, anywhere later, by `test` / `nextest`.
    let subcommand_after = |program: &str, subs: &[&str]| {
        tokens
            .iter()
            .position(|t| t.rsplit('/').next() == Some(program))
            .is_some_and(|i| tokens[i + 1..].iter().any(|t| subs.contains(t)))
    };
    tokens.iter().any(names_runner)
        || subcommand_after("cargo", &["test", "nextest"])
        || subcommand_after("npm", &["test"])
}

/// True when `e.payload["heuristic"]` is `true` — the evidence's `exit_code`
/// was inferred, not observed from a real exit code (set by
/// `fornax-adapter-claude`'s `ClaudeBashExitCodeSensor` and
/// `fornax-adapter-codex`'s `CodexCustomToolCallOutputSensor`'s
/// `script_completed` fallback branch; absent, or `false`, for every sensor
/// that parses a genuine literal exit code).
///
/// FORNX-433 follow-up (found while adversarially testing FORNX-433's native
/// ingress tests against a realistic Claude `pytest -q` failure shape):
/// `heuristic:stderr_empty`'s original assumption — "empty stderr implies
/// exit_code 0 is reliable" — is backwards. It is unreliable in exactly the
/// direction that matters: a real `pytest`/`cargo test`/etc. failure writes
/// its failure summary to **stdout**, not stderr, so "stderr is empty"
/// proves nothing about success. Both match arms above that gate on this
/// function exist so a bare heuristic `exit_code=0` downgrades to `Review`
/// rather than reaching `Verified` — the false-VERIFIED path this ticket's
/// own doc comment used to claim didn't exist.
fn is_heuristic_evidence(e: &Evidence) -> bool {
    e.payload.get("heuristic").and_then(|v| v.as_bool()) == Some(true)
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
/// narrow to the *nonzero* heuristic reason: the zero/success heuristic
/// branch (`heuristic:stderr_empty` / Codex's `heuristic:script_completed`)
/// is handled separately by [`is_heuristic_evidence`] above, which downgrades
/// it to `Review` unconditionally rather than treating it as reliable.
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

    /// The summary a genuine run of `command` would print, as the adapters
    /// store it (`None` when the command is not a runner whose output the
    /// first cut can read: pytest and cargo test).
    fn passing_summary_for(command: &serde_json::Value) -> Option<serde_json::Value> {
        match runner_command::proven_runner(Some(command))? {
            runner_command::RunnerKind::Pytest => {
                Some(serde_json::json!({"format": "pytest", "passed": 3, "failed": 0}))
            }
            runner_command::RunnerKind::Cargo => {
                Some(serde_json::json!({"format": "cargo", "passed": 3, "failed": 0}))
            }
            runner_command::RunnerKind::Other => None,
        }
    }

    /// A genuine passing run: the exit code plus the runner's own summary.
    fn with_passing_summary(mut e: Evidence) -> Evidence {
        if let Some(summary) = e.payload.get("command").and_then(passing_summary_for) {
            e.payload["test_summary"] = summary;
        }
        e
    }

    /// `pytest` exiting `code`; a 0 exit carries a genuine passing summary.
    /// Use `bare_runner_evidence` for the no-output (fake runner) case.
    fn evidence_with_exit_code(code: i64) -> Evidence {
        let e = bare_runner_evidence(code);
        if code == 0 {
            with_passing_summary(e)
        } else {
            e
        }
    }

    /// The evidence source a fixture claims. Most tests here exercise the
    /// runner/summary rules and use an attested channel (`HostObserved`) so
    /// those rules, not the attestation gate, decide the verdict; the gate has
    /// its own tests (`transcript_only_test_evidence_never_reaches_verified`).
    pub(crate) fn source_with(trust: fornax_types::TrustClass) -> fornax_types::EvidenceSource {
        fornax_types::EvidenceSource::now(
            "test_fixture_run_attestor",
            trust,
            Some(fornax_types::Provider::Codex),
            fornax_types::CollectionMethod::FilePoll,
            None,
        )
    }

    /// `pytest` exiting `code` with no test summary at all: what a QA-owned
    /// executable named `pytest` that only does `exit 0` produces.
    fn bare_runner_evidence(code: i64) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::json!({"command": ["pytest"], "exit_code": code}),
            provenance: "codex:rollout:exec_command_end".into(),
            source: Some(source_with(fornax_types::TrustClass::HostObserved)),
            extension: None,
            evidence_purged: false,
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
            source: Some(source_with(fornax_types::TrustClass::HostObserved)),
            extension: None,
            evidence_purged: false,
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

    /// FORNX-433 follow-up regression: a *heuristic* `exit_code=0` (e.g.
    /// `fornax-adapter-claude`'s `ClaudeBashExitCodeSensor` inferring success
    /// purely from "stderr is empty", which a real `pytest -q` failure that
    /// writes its summary to stdout also satisfies) must never reach
    /// `Verified` -- that was the exact false-VERIFIED path FORNX-433's own
    /// native-ingress tests surfaced. `verified_when_exit_code_zero` above is
    /// the authoritative-evidence control proving this fix discriminates by
    /// the `heuristic` flag, not by the exit code value.
    #[test]
    fn heuristic_exit_code_zero_is_review_not_verified() {
        let v = TestResultVerifier;
        let c = claim("All tests passed.");
        let mut ev = evidence_with_exit_code(0);
        ev.payload["heuristic"] = serde_json::json!(true);
        ev.provenance = "claude_code:PostToolUse:Bash#heuristic:stderr_empty".into();
        let f = v.verify(&c, &[ev.clone()], &caps());
        assert_eq!(f.verdict, Verdict::Review);
        assert_eq!(f.evidence_ids, vec![ev.id]);
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

        let ev2 = vec![with_passing_summary(evidence_for_command(
            &["cargo", "test"],
            0,
        ))];
        let f2 = v.verify(&c, &ev2, &caps());
        assert_eq!(f2.verdict, Verdict::Verified);

        // nextest is recognised as a runner (a failure contradicts) but its
        // output format is not read in this cut, so a pass is never Verified.
        let ev3 = vec![evidence_for_command(&["cargo", "nextest", "run"], 0)];
        assert_eq!(v.verify(&c, &ev3, &caps()).verdict, Verdict::Unverified);
    }

    /// FORNX-477: evidence_for_command with a raw `command` JSON value, so a
    /// string (Claude Bash) and an argv array (Codex) are both expressible.
    fn verdict_for_command(command: serde_json::Value, exit_code: i64) -> Verdict {
        let mut ev = bare_runner_evidence(exit_code);
        ev.payload["command"] = command;
        if exit_code == 0 {
            ev = with_passing_summary(ev);
        }
        TestResultVerifier
            .verify(&claim("All tests passed."), &[ev], &caps())
            .verdict
    }

    /// Same as `verdict_for_command` but the run printed no recognised summary.
    fn verdict_for_command_without_summary(command: serde_json::Value, exit_code: i64) -> Verdict {
        let mut ev = bare_runner_evidence(exit_code);
        ev.payload["command"] = command;
        TestResultVerifier
            .verify(&claim("All tests passed."), &[ev], &caps())
            .verdict
    }

    /// FORNX-477: a command that merely *mentions* a runner (or only
    /// installs/reads/commits about it) is not a test run, so a claim of
    /// "tests passed" must stay Unverified -- never Verified, and never
    /// Contradicted by an unrelated command's exit code either.
    #[test]
    fn commands_that_only_mention_a_runner_never_verify_or_contradict() {
        use serde_json::json;
        let not_runs = [
            json!("echo pytest"),
            json!("true # jest"),
            json!("rm -rf /nonexistent/vitest"),
            json!("pip install pytest"),
            json!("cat jest.config.js"),
            json!("git commit -m \"add vitest dep\""),
            json!("npm install jest"),
            json!("cargo build --tests && echo cargo test"),
            json!("echo ok; pytest"),
            json!("true || pytest"),
            json!("pytest || true"),
            json!("pytest -q || echo failed"),
            json!("printf 'cargo test'"),
            json!("echo pytest && true"),
            json!("pip install pytest && echo ok"),
            json!("cd repo && echo jest"),
            json!("pytest &&"),
            json!("&& pytest"),
            json!("pytest && && true"),
            json!("pytest &&& true"),
            json!("exit 0 && pytest -q"),
            json!("exec true && pytest"),
            json!(["bash", "-c", "exit 0 && pytest"]),
            json!(["bash", "-nc", "pytest"]),
            json!(["sh", "-ncx", "pytest"]),
            json!("pytest 2>&1 | tail"),
            json!("pytest 2>&1x"),
            json!("pytest 3>&1"),
            json!("pytest 2>&1>out"),
            json!("pytest 2>&2"),
            json!("pytest a2>&1"),
            json!("echo 2>&1 pytest"),
            json!("source env.sh && pytest -q"),
            json!("true && . ./env.sh && cargo test"),
            json!("uv run --with pytest python script.py"),
            json!("pytest\u{a0}-q"),
            json!("pytest\u{b}-q"),
            json!(["bash", "-c", "pytest\u{c}-q"]),
            json!("readonly A=1 && pytest -q"),
            json!("PATH=/tmp/evil && pytest -q"),
            json!("CI=1 && pytest -q"),
            json!("local x && pytest -q"),
            json!("logout && pytest"),
            json!("pushd x && cargo test"),
            json!("uv run --with jest echo hi"),
            json!("npx -p jest node x.js"),
            json!("pytest -q | tee out.txt"),
            json!("pytest -q &"),
            json!("(pytest -q)"),
            json!("pytest -q\ntrue"),
            json!("echo $(pytest)"),
            json!("echo `pytest`"),
            json!("$RUNNER -q"),
            json!("pytest $ARGS"),
            json!("PYTHONPATH=src pytest -q"),
            json!("PATH=/tmp/evil pytest -q"),
            json!("PYTEST_ADDOPTS=--collect-only pytest"),
            json!("NODE_OPTIONS=--require=x.js jest"),
            json!("FOO='a b' pytest"),
            json!("vitest list"),
            json!("pytest -q # jest"),
            json!("pytest -q; true"),
            json!("pytest;true"),
            json!("pytest -q > out.txt"),
            json!("pytest 2>err.txt"),
            json!("pytest < in.txt"),
            json!("pytest (a)"),
            json!("pytest {a,b}"),
            json!("pytest `true`"),
            json!("pytest \"$X\""),
            json!("pytest \"`true`\""),
            json!("'CI=1' pytest"),
            json!("python3 -m pip install pytest"),
            json!("python3 -m unittest -v"),
            json!("pnpm run vitest"),
            json!(["bash", "-x", "pytest"]),
            json!(["echo", "pytest"]),
            json!(["cat", "jest.config.js"]),
            json!(["git", "commit", "-m", "cargo test"]),
            json!(["/bin/zsh", "-lc", "echo pytest"]),
            json!(["/bin/bash", "-c", "true # jest"]),
            json!(["/bin/sh", "-lc", "pip install pytest"]),
            json!(["/bin/sh", "-c", "echo hi; cargo test"]),
            json!(["/bin/sh", "-c", "pytest", "extra-arg"]),
            json!(["/bin/sh", "-c"]),
            json!("pytest 'unterminated"),
            json!(""),
            json!(null),
            json!(42),
        ];
        for cmd in not_runs {
            for code in [0, 1] {
                assert_eq!(
                    verdict_for_command(cmd.clone(), code),
                    Verdict::Unverified,
                    "command {cmd} exit {code} must not be treated as a test run"
                );
            }
        }
    }

    /// FORNX-477: omitting a spoofable-substring match must not cost real
    /// runs. Each executed runner (any shell wrapper Codex/Claude use) with a
    /// real exit code keeps its verdict: 0 -> Verified, nonzero -> Contradicted.
    #[test]
    fn genuine_runner_invocations_keep_their_verdicts() {
        use serde_json::json;
        let runs = [
            json!("pytest"),
            json!("pytest -q tests/"),
            json!("python3 -m pytest -q ."),
            json!("CI=1 pytest -q"),
            json!("pytest -v tests/"),
            json!("pytest --cov=src --maxfail=1 -q"),
            json!("jest --coverage --ci --color"),
            json!("cargo test 2>&1"),
            json!(["zsh", "-lc", "pytest -q 2>&1"]),
            json!("pytest -xvs -k smoke"),
            json!("CI=1 RUST_BACKTRACE=1 cargo test"),
            json!("./.venv/bin/pytest -q"),
            json!("uv run pytest -q"),
            json!("cargo test"),
            json!("cargo test --workspace"),
            json!("cargo +nightly test -p fornax-verify --lib -- some::test"),
            json!("cargo nextest run -p fornax-verify"),
            json!("npm test"),
            json!("npx vitest run"),
            json!("bunx vitest run"),
            json!("npx --yes jest --ci"),
            json!("vitest run"),
            json!("jest"),
            json!("pnpm exec vitest run"),
            json!("'pytest' -q \"tests/a b\""),
            json!(["pytest"]),
            json!(["cargo", "test"]),
            json!(["cargo", "nextest", "run"]),
            json!(["/bin/sh", "-lc", "python3 -m pytest -q ."]),
            json!(["/bin/zsh", "-lc", "cargo test --workspace"]),
            json!(["/bin/bash", "-c", "npm test"]),
            json!(["bash", "-ic", "pytest -q"]),
        ];
        for cmd in runs {
            // Runners whose summary the first cut reads (pytest, cargo test)
            // are Verified with a genuine passing summary; the others are
            // still recognised (a failure contradicts) but a pass cannot be
            // shown from their output yet, so it stays Unverified.
            let expected_pass = if passing_summary_for(&cmd).is_some() {
                Verdict::Verified
            } else {
                Verdict::Unverified
            };
            assert_eq!(
                verdict_for_command(cmd.clone(), 0),
                expected_pass,
                "command {cmd} exit 0"
            );
            assert_eq!(
                verdict_for_command(cmd.clone(), 1),
                Verdict::Contradicted,
                "command {cmd} exit 1"
            );
            // No summary (a fake runner, or output not captured): never Verified.
            assert_eq!(
                verdict_for_command_without_summary(cmd.clone(), 0),
                Verdict::Unverified,
                "command {cmd} exit 0 without a summary"
            );
        }
    }

    /// FORNX-477: an older genuine pass must not verify the claim when a
    /// *newer* command that mentions a runner could not be identified as a test
    /// run (it may be the real, failing -- or masked -- run, e.g.
    /// `cd repo && pytest` exiting 1, or `pytest | tail` exiting 0). A genuine
    /// failure stays Contradicted; an older ambiguous row never hurts a newer
    /// genuine pass.
    #[test]
    fn an_older_pass_is_not_verified_over_a_newer_unidentified_runner_command() {
        let pass = with_passing_summary(evidence_for_command(&["pytest", "-q"], 0));
        for (newer, code) in [
            ("cd repo && pytest -q", 1),
            ("pytest -q | tail", 0),
            ("pytest -q | tail", 1),
            ("git commit -m pytest", 0),
            ("git commit -m 'run py.test'", 0),
            ("cargo +nightly test | tail", 1),
            ("cargo nextest run | tee out", 0),
            ("npx jest | tail", 0),
            ("pytest-3 -q | tail", 0),
            ("./node_modules/.bin/jest | tail", 0),
        ] {
            let newer_ev = evidence_for_command(&["/bin/zsh", "-lc", newer], code);
            let f = TestResultVerifier.verify(
                &claim("All tests passed."),
                &[pass.clone(), newer_ev],
                &caps(),
            );
            assert_eq!(f.verdict, Verdict::Unverified, "{newer} exit {code}");
        }

        let fail = evidence_for_command(&["pytest", "-q"], 1);
        let ambiguous = evidence_for_command(&["/bin/zsh", "-lc", "git commit -m pytest"], 0);
        let f = TestResultVerifier.verify(
            &claim("All tests passed."),
            &[fail.clone(), ambiguous.clone()],
            &caps(),
        );
        // A genuine failure stays Contradicted: following it with a command
        // that merely mentions a runner must not let an agent dodge it.
        assert_eq!(f.verdict, Verdict::Contradicted);
        assert_eq!(f.evidence_ids, vec![fail.id]);

        let f = TestResultVerifier.verify(
            &claim("All tests passed."),
            &[ambiguous, pass.clone()],
            &caps(),
        );
        assert_eq!(f.verdict, Verdict::Verified);
        assert_eq!(f.evidence_ids, vec![pass.id]);
    }

    /// FORNX-477: an `&&` list exits 0 only if every command in it ran and
    /// exited 0, so a runner inside it is proven by an overall 0; a non-zero
    /// overall status does not say which command failed and must never be
    /// pinned on the runner (no Contradicted, no Verified).
    #[test]
    fn and_lists_prove_the_runner_only_through_an_overall_zero() {
        use serde_json::json;
        for cmd in [
            json!("cd repo && cargo test"),
            json!(["/bin/zsh", "-lc", "cd crates/x && cargo test"]),
        ] {
            assert_eq!(
                verdict_for_command(cmd.clone(), 0),
                Verdict::Verified,
                "{cmd}"
            );
            assert_eq!(
                verdict_for_command(cmd.clone(), 1),
                Verdict::Unverified,
                "{cmd}"
            );
        }
        // Another command in the list could have printed the summary
        // (`echo '3 passed in 0.1s' && cargo test no_such`), so only `cd`
        // may accompany the runner for its summary to be attributed to it.
        for cmd in [
            json!("make build && pytest -q"),
            json!("CI=1 pytest && echo done"),
            json!("cargo test -p x 2>&1 && echo done"),
            json!(["/bin/zsh", "-lc", "cd crates/x && cargo nextest run"]),
            json!(["bash", "-c", "uv run pytest -q && ruff check"]),
            json!("echo '3 passed in 0.1s' && cargo test no_such"),
        ] {
            assert_eq!(
                verdict_for_command(cmd.clone(), 0),
                Verdict::Unverified,
                "{cmd}"
            );
        }
        for cmd in [
            json!("make build && pytest --collect-only"),
            json!("echo pytest && true"),
            json!("cd repo && git commit -m 'cargo test'"),
        ] {
            assert_eq!(
                verdict_for_command(cmd.clone(), 0),
                Verdict::Unverified,
                "{cmd}"
            );
        }
    }

    /// FORNX-477: invocations that exit 0 without executing tests (listing,
    /// help, compile-only, "no tests found is fine") are not a test run.
    #[test]
    fn runner_invocations_that_do_not_execute_tests_are_unverified() {
        use serde_json::json;
        for cmd in [
            json!("pytest --collect-only"),
            json!("pytest --co -q"),
            json!("pytest --collect-only=yes"),
            json!("pytest --collect"),
            json!("pytest --setup-plan"),
            json!("pytest --setup-only"),
            json!("pytest --fixtures-per-test"),
            json!("jest --showConfig"),
            json!("pytest --collectonly"),
            json!("pytest -o addopts=--collect-only"),
            json!("pytest --override-ini=addopts=--co"),
            json!("pytest -qh"),
            json!("pytest -ofoo=bar"),
            json!("pytest -xo addopts=--co"),
            json!("pytest -hx"),
            json!("pytest --setupplan"),
            json!("pytest --setuponly"),
            json!("pytest --funcargs"),
            json!("pytest -oaddopts=--co"),
            json!("jest --list-tests"),
            json!("jest --pass-with-no-tests -t nomatch"),
            json!("jest --changedFilesWithAncestor"),
            json!("vitest bench"),
            json!("pytest -Vq"),
            json!("jest -v"),
            json!("vitest -v"),
            json!("jest --clearCache"),
            json!("jest --init"),
            json!("jest --onlyChanged"),
            json!("jest --changedSince=HEAD"),
            json!("vitest init"),
            json!("npm test --if-present"),
            json!("cargo nextest run --no-tests=pass"),
            json!("pytest --help"),
            json!("pytest -h"),
            json!("cargo test --no-run"),
            json!("cargo test -- --list"),
            json!("cargo nextest list"),
            json!("jest --listTests"),
            json!("jest --passWithNoTests"),
            json!("vitest --version"),
            json!(["pytest", "--collect-only"]),
        ] {
            assert_eq!(
                verdict_for_command(cmd.clone(), 0),
                Verdict::Unverified,
                "{cmd}"
            );
        }
    }

    fn verdict_with_summary(
        command: serde_json::Value,
        exit_code: i64,
        summary: Option<serde_json::Value>,
    ) -> Verdict {
        let mut ev = bare_runner_evidence(exit_code);
        ev.payload["command"] = command;
        if let Some(summary) = summary {
            ev.payload["test_summary"] = summary;
        }
        TestResultVerifier
            .verify(&claim("All tests passed."), &[ev], &caps())
            .verdict
    }

    /// FORNX-477 (QA 29513 residual): "the `pytest` run succeeded" asserts that
    /// tests passed as much as "all tests passed" does. Re-labelling the claim
    /// `command_succeeded` must neither skip the runner/summary conditions nor
    /// the trust bar, while commands that are not test runs keep verifying.
    #[test]
    fn a_test_run_relabelled_as_command_succeeded_gets_the_test_result_bar() {
        use fornax_types::TrustClass;
        let verdict = |text: &str, ev: Evidence, trust: Option<TrustClass>| {
            let mut ev = ev;
            if let Some(trust) = trust {
                ev.source = Some(source_with(trust));
            }
            CommandSuccessVerifier
                .verify(&claim_for("command_succeeded", text), &[ev], &caps())
                .verdict
        };
        let passing = |cmd: &[&str]| with_passing_summary(evidence_for_command(cmd, 0));
        let agent = || Some(TrustClass::AgentAdjacent);

        // RED before the fix: these were Verified from the agent's own account.
        assert_eq!(
            verdict(
                "The `pytest -q` run succeeded.",
                passing(&["pytest", "-q"]),
                agent()
            ),
            Verdict::Review
        );
        assert_eq!(
            verdict(
                "The `cargo test` run completed successfully.",
                passing(&["cargo", "test"]),
                agent()
            ),
            Verdict::Review
        );
        // No recorded source is not attested either.
        let mut unsourced = passing(&["pytest", "-q"]);
        unsourced.source = None;
        assert_eq!(
            verdict("The `pytest -q` run succeeded.", unsourced, None),
            Verdict::Review
        );
        // Fake runner (exit 0, no summary) and a zero-test run stay Unverified.
        assert_eq!(
            verdict(
                "The `pytest` run succeeded.",
                evidence_for_command(&["pytest"], 0),
                agent()
            ),
            Verdict::Unverified
        );
        let mut zero = evidence_for_command(&["cargo", "test", "no_such_test"], 0);
        zero.payload["test_summary"] =
            serde_json::json!({"format": "cargo", "passed": 0, "failed": 0});
        assert_eq!(
            verdict(
                "The `cargo test no_such_test` run succeeded.",
                zero,
                agent()
            ),
            Verdict::Unverified
        );
        // The claim names a runner but the matched evidence merely mentions it.
        assert_eq!(
            verdict(
                "The `pytest` run succeeded.",
                evidence_for_command(&["echo", "pytest"], 0),
                agent()
            ),
            Verdict::Unverified
        );
        // Runners whose output is not read (jest, vitest, npm test, nextest) and
        // env-prefixed spellings are still test assertions: evidence that merely
        // mentions them must not verify, and a real run has no summary format.
        for (text, mention) in [
            ("The `jest` run succeeded.", vec!["cat", "jest.config.js"]),
            ("The `npx jest` run succeeded.", vec!["echo", "npx jest"]),
            ("The `npm test` run succeeded.", vec!["echo", "npm test"]),
            ("The `vitest` run succeeded.", vec!["echo", "vitest"]),
            (
                "The `cargo nextest run` run succeeded.",
                vec!["echo", "cargo nextest run"],
            ),
            (
                "The `CI=1 pytest` run succeeded.",
                vec!["echo", "CI=1 pytest"],
            ),
            // Spelling that differs only in case still matches the (lowercased)
            // evidence text, so it must be recognised as naming a runner.
            ("The `PYTEST` run succeeded.", vec!["echo", "pytest"]),
            ("The `Jest` run succeeded.", vec!["echo", "jest"]),
            ("The `Npm Test` run succeeded.", vec!["echo", "npm test"]),
        ] {
            assert_eq!(
                verdict(text, evidence_for_command(&mention, 0), agent()),
                Verdict::Unverified,
                "{text}"
            );
        }
        assert_eq!(
            verdict(
                "The `jest` run succeeded.",
                evidence_for_command(&["jest"], 0),
                Some(TrustClass::HostObserved)
            ),
            Verdict::Unverified,
            "a real jest run has no readable summary, so it cannot verify"
        );
        // A real failing run is still contradicted.
        assert_eq!(
            verdict(
                "The `pytest -q` run succeeded.",
                evidence_for_command(&["pytest", "-q"], 1),
                agent()
            ),
            Verdict::Contradicted
        );
        // Positive control: an attested channel still verifies a real run
        // (fixture attestor; production ships none).
        assert_eq!(
            verdict(
                "The `pytest -q` run succeeded.",
                passing(&["pytest", "-q"]),
                Some(TrustClass::HostObserved)
            ),
            Verdict::Verified
        );
        // Legitimate non-test commands are unaffected, including ones that merely
        // mention a runner's name.
        for (text, cmd) in [
            ("The `npm install` succeeded.", vec!["npm", "install"]),
            ("The `cargo build` succeeded.", vec!["cargo", "build"]),
            (
                "The `pip install pytest` succeeded.",
                vec!["pip", "install", "pytest"],
            ),
        ] {
            assert_eq!(
                verdict(text, evidence_for_command(&cmd, 0), agent()),
                Verdict::Verified,
                "{text}"
            );
            assert_eq!(
                verdict(text, evidence_for_command(&cmd, 1), agent()),
                Verdict::Contradicted,
                "{text}"
            );
        }
    }

    /// FORNX-477 trust boundary (QA 29501): a forged passing summary printed
    /// by an executable named `pytest` is indistinguishable, in the agent's
    /// transcript, from the real runner's. Evidence that only the agent's own
    /// provider account carries must never be `Verified`; only evidence Fornax
    /// or an outside system observed may be.
    #[test]
    fn transcript_only_test_evidence_never_reaches_verified() {
        use fornax_types::TrustClass;
        let verdict_for = |source: Option<fornax_types::EvidenceSource>| {
            let mut ev = evidence_with_exit_code(0);
            ev.source = source;
            TestResultVerifier
                .verify(&claim("All tests passed."), &[ev], &caps())
                .verdict
        };
        // RED before the gate: the forged-but-well-formed summary verified.
        assert_eq!(
            verdict_for(Some(source_with(TrustClass::AgentAdjacent))),
            Verdict::Review
        );
        // No recorded source (pre-sensor-contract evidence) is not attested.
        assert_eq!(verdict_for(None), Verdict::Review);
        assert_eq!(
            verdict_for(Some(source_with(TrustClass::ModelInternal))),
            Verdict::Review
        );
        assert_eq!(
            verdict_for(Some(source_with(TrustClass::Unrecognized("x".into())))),
            Verdict::Review
        );
        // Positive controls: an attested channel still verifies a real run.
        assert_eq!(
            verdict_for(Some(source_with(TrustClass::HostObserved))),
            Verdict::Verified
        );
        assert_eq!(
            verdict_for(Some(source_with(TrustClass::IndependentExternal))),
            Verdict::Verified
        );
    }

    /// FORNX-477 founder decision: a trust-class label alone is not enough.
    /// Anything that can submit evidence could write `HostObserved` or
    /// `IndependentExternal` into the record, or borrow the name of a shipped
    /// `HostObserved` sensor (git working tree, file-write confirmation) that
    /// does not observe test runs. Only a collector this verifier lists as a
    /// test-run attestor may promote, and none ships in production.
    #[test]
    fn a_trusted_class_label_without_an_attesting_collector_never_verifies() {
        use fornax_types::{CollectionMethod, EvidenceSource, TrustClass};
        let source = |name: &'static str, trust: TrustClass| {
            EvidenceSource::now(name, trust, None, CollectionMethod::FilePoll, None)
        };
        for (name, trust) in [
            // A shipped HostObserved sensor's identity, on exit-code evidence.
            (
                "claude_git_working_tree_sensor_v1",
                TrustClass::HostObserved,
            ),
            (
                "claude_file_write_confirmed_sensor_v1",
                TrustClass::HostObserved,
            ),
            // The agent's own sensor claiming a trusted class (forged label).
            ("codex_exec_command_end_sensor_v1", TrustClass::HostObserved),
            (
                "codex_exec_command_end_sensor_v1",
                TrustClass::IndependentExternal,
            ),
            // An unregistered name claiming either trusted class.
            ("made_up_ci_sensor", TrustClass::IndependentExternal),
            ("made_up_host_sensor", TrustClass::HostObserved),
            // A look-alike of the fixture attestor name.
            ("test_fixture_run_attestor ", TrustClass::HostObserved),
        ] {
            let mut ev = evidence_with_exit_code(0);
            ev.source = Some(source(name, trust.clone()));
            assert_eq!(
                TestResultVerifier
                    .verify(&claim("All tests passed."), &[ev], &caps())
                    .verdict,
                Verdict::Review,
                "{name} / {trust:?}"
            );
        }
    }

    /// The gate only lowers a verdict: it never touches `Contradicted` for a
    /// failing run, and an unattested run without a passing summary is still
    /// `Unverified` (the stronger refusal), not `Review`.
    #[test]
    fn attestation_gate_only_lowers_and_keeps_other_protections() {
        use fornax_types::TrustClass;
        for trust in [TrustClass::AgentAdjacent, TrustClass::HostObserved] {
            let mut failing = evidence_with_exit_code(1);
            failing.source = Some(source_with(trust.clone()));
            assert_eq!(
                TestResultVerifier
                    .verify(&claim("All tests passed."), &[failing], &caps())
                    .verdict,
                Verdict::Contradicted
            );
            let mut fake = bare_runner_evidence(0);
            fake.source = Some(source_with(trust));
            assert_eq!(
                TestResultVerifier
                    .verify(&claim("All tests passed."), &[fake], &caps())
                    .verdict,
                Verdict::Unverified
            );
        }
    }

    /// FORNX-477 residual: a runner name plus exit 0 is not proof that tests
    /// ran. A QA-owned executable named `pytest` that only does `exit 0`
    /// (and `cargo test no_such_test`) exits 0 with no passing-test summary.
    #[test]
    fn a_runner_name_with_exit_zero_and_no_passing_summary_is_unverified() {
        use serde_json::json;
        // RED: the fake `pytest` (empty output) and zero-selected cargo run.
        assert_eq!(
            verdict_with_summary(json!(["pytest"]), 0, None),
            Verdict::Unverified
        );
        assert_eq!(
            verdict_with_summary(
                json!("/tmp/qa/bin/pytest"),
                0,
                Some(json!({"format": "pytest", "passed": 0, "failed": 0}))
            ),
            Verdict::Unverified
        );
        assert_eq!(
            verdict_with_summary(
                json!(["cargo", "test", "no_such_test"]),
                0,
                Some(json!({"format": "cargo", "passed": 0, "failed": 0}))
            ),
            Verdict::Unverified
        );
        // A summary that reports failures cannot verify, even with exit 0.
        assert_eq!(
            verdict_with_summary(
                json!(["pytest"]),
                0,
                Some(json!({"format": "pytest", "passed": 2, "failed": 1}))
            ),
            Verdict::Unverified
        );
        // The summary must come from the runner kind that was identified.
        assert_eq!(
            verdict_with_summary(
                json!(["pytest"]),
                0,
                Some(json!({"format": "cargo", "passed": 3, "failed": 0}))
            ),
            Verdict::Unverified
        );
        // Malformed summary shapes fail closed.
        for bad in [
            json!({"format": "pytest"}),
            json!({"format": "pytest", "passed": "3", "failed": 0}),
            json!({"format": "pytest", "passed": 3}),
            json!("3 passed"),
        ] {
            assert_eq!(
                verdict_with_summary(json!(["pytest"]), 0, Some(bad.clone())),
                Verdict::Unverified,
                "{bad}"
            );
        }
        // GREEN: a genuine run with a matching passing summary is Verified.
        assert_eq!(
            verdict_with_summary(
                json!(["pytest"]),
                0,
                Some(json!({"format": "pytest", "passed": 1, "failed": 0}))
            ),
            Verdict::Verified
        );
        assert_eq!(
            verdict_with_summary(
                json!(["/bin/zsh", "-lc", "cd crates/x && cargo test"]),
                0,
                Some(json!({"format": "cargo", "passed": 12, "failed": 0}))
            ),
            Verdict::Verified
        );
    }

    /// The summary only ever withholds `Verified`: a genuine failing runner
    /// stays Contradicted whatever (or nothing) the output claimed, and a
    /// summary on non-runner evidence neither verifies nor contradicts.
    #[test]
    fn the_summary_never_grants_verified_or_contradicted() {
        use serde_json::json;
        let good = || Some(json!({"format": "pytest", "passed": 5, "failed": 0}));
        assert_eq!(
            verdict_with_summary(json!(["pytest"]), 1, good()),
            Verdict::Contradicted
        );
        assert_eq!(
            verdict_with_summary(json!(["pytest"]), 1, None),
            Verdict::Contradicted
        );
        assert_eq!(
            verdict_with_summary(json!(["echo", "pytest"]), 0, good()),
            Verdict::Unverified
        );
        assert_eq!(
            verdict_with_summary(json!("echo '5 passed in 0.1s' && pytest"), 0, good()),
            Verdict::Unverified
        );
        assert_eq!(
            verdict_with_summary(json!("pytest --collect-only"), 0, good()),
            Verdict::Unverified
        );
        // Recognised runners whose output format is not read in this cut
        // can never be Verified, even with a (forged) pytest-shaped summary.
        for cmd in [
            json!("npm test"),
            json!("npx jest"),
            json!("cargo nextest run"),
        ] {
            assert_eq!(
                verdict_with_summary(cmd.clone(), 0, good()),
                Verdict::Unverified,
                "{cmd}"
            );
        }
    }

    /// The summary must belong to the row that is judged: a later runner row
    /// without one withholds Verified, a later failure still contradicts, and
    /// a cargo command cannot be vouched for by a pytest-format summary (nor
    /// the reverse).
    #[test]
    fn the_judged_row_must_carry_its_own_matching_summary() {
        use serde_json::json;
        let pass = with_passing_summary(evidence_for_command(&["pytest", "-q"], 0));
        let later_bare = evidence_for_command(&["pytest", "-k", "x"], 0);
        let later_fail = evidence_for_command(&["pytest", "-k", "x"], 1);
        let judge = |rows: &[Evidence]| {
            TestResultVerifier
                .verify(&claim("All tests passed."), rows, &caps())
                .verdict
        };
        assert_eq!(judge(&[pass.clone(), later_bare]), Verdict::Unverified);
        assert_eq!(judge(&[pass, later_fail]), Verdict::Contradicted);
        assert_eq!(
            verdict_with_summary(
                json!(["cargo", "test"]),
                0,
                Some(json!({"format": "pytest", "passed": 3, "failed": 0}))
            ),
            Verdict::Unverified
        );
        assert_eq!(
            verdict_with_summary(
                json!("python -m pytest"),
                0,
                Some(json!({"format": "cargo", "passed": 3, "failed": 0}))
            ),
            Verdict::Unverified
        );
    }

    /// A heuristic exit 0 (inferred from empty stderr) stays Review even
    /// when a summary is present; the summary does not raise the ceiling.
    #[test]
    fn a_summary_does_not_raise_the_heuristic_ceiling() {
        let mut ev = with_passing_summary(evidence_for_command(&["pytest", "-q"], 0));
        ev.payload["heuristic"] = serde_json::json!(true);
        let f = TestResultVerifier.verify(&claim("All tests passed."), &[ev], &caps());
        assert_eq!(f.verdict, Verdict::Review);
    }

    /// FORNX-477: the heuristic ceiling (FORNX-433) must survive the
    /// stricter matcher -- a heuristic exit 0 from a genuine runner stays
    /// Review, and a spoof-shaped command with a heuristic exit stays
    /// Unverified (it never reaches the exit-code branch at all).
    #[test]
    fn heuristic_ceiling_is_unchanged_by_command_identification() {
        let mut real = with_passing_summary(evidence_for_command(&["pytest", "-q"], 0));
        real.payload["heuristic"] = serde_json::json!(true);
        let f = TestResultVerifier.verify(&claim("All tests passed."), &[real], &caps());
        assert_eq!(f.verdict, Verdict::Review);

        let mut spoof = evidence_for_command(&["echo", "pytest"], 0);
        spoof.payload["heuristic"] = serde_json::json!(true);
        let f = TestResultVerifier.verify(&claim("All tests passed."), &[spoof], &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
    }

    /// FORNX-477: a spoof-shaped command appearing *after* a genuine failing
    /// run must not mask it, and one appearing before must not satisfy it:
    /// only genuine runner evidence is selected.
    #[test]
    fn spoof_commands_neither_mask_nor_replace_genuine_runner_evidence() {
        let genuine_fail = evidence_for_command(&["pytest", "-q"], 1);
        let spoof_after = evidence_for_command(&["echo", "pytest"], 0);
        let f = TestResultVerifier.verify(
            &claim("All tests passed."),
            &[genuine_fail.clone(), spoof_after],
            &caps(),
        );
        assert_eq!(f.verdict, Verdict::Contradicted);
        assert_eq!(f.evidence_ids, vec![genuine_fail.id]);

        let spoof_only = evidence_for_command(&["echo", "pytest"], 0);
        let f = TestResultVerifier.verify(&claim("All tests passed."), &[spoof_only], &caps());
        assert_eq!(f.verdict, Verdict::Unverified);
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
            evidence_purged: false,
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
            evidence_purged: false,
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

    /// FORNX-433 follow-up regression — see `TestResultVerifier`'s
    /// `heuristic_exit_code_zero_is_review_not_verified` for the full
    /// rationale: a heuristic `exit_code=0` must not reach `Verified` here
    /// either.
    #[test]
    fn heuristic_named_command_exit_code_zero_is_review_not_verified() {
        let v = CommandSuccessVerifier;
        let c = crate::tests::claim_for("command_succeeded", "The `npm install` succeeded.");
        let mut ev = crate::tests::evidence_for_command(&["npm", "install"], 0);
        ev.payload["heuristic"] = serde_json::json!(true);
        ev.provenance = "claude_code:PostToolUse:Bash#heuristic:stderr_empty".into();
        let f = v.verify(&c, &[ev.clone()], &caps());
        assert_eq!(f.verdict, Verdict::Review);
        assert_eq!(f.evidence_ids, vec![ev.id]);
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
            evidence_purged: false,
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
            evidence_purged: false,
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
            evidence_purged: false,
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
            evidence_purged: false,
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
