//! FORNX-477: the test-run summary a runner prints at the end of its output.
//!
//! A test-runner command name plus exit status 0 does not show that any test
//! ran: a script called `pytest` that only does `exit 0`, or `cargo test
//! no_such_test` (`running 0 tests`), exits 0 too. Adapters that receive the
//! command's output therefore extract the runner's own final summary and store
//! only its counts on the exit-code evidence (never the raw output). The
//! verifier uses it strictly as an *extra condition* before `Verified` (see
//! `fornax-verify`'s `TestResultVerifier`); it can withhold `Verified` but it
//! can never grant it or produce `Contradicted` (ADR-0025's safety-monotonic
//! bar for any stdout parsing).
//!
//! Recognised formats are deliberately few and strictly anchored:
//! * pytest: the last non-empty line, e.g. `=== 2 passed, 1 skipped in 0.03s ===`
//!   or `2 passed in 0.02s`;
//! * cargo test: every `test result: ok. N passed; M failed; ...` line, summed.
//!
//! Anything else (including both formats at once, or a failing cargo result
//! line) yields `None`. This is a transcript the executed code itself writes,
//! so a hostile executable can still print a convincing summary; closing that
//! needs host-attested evidence (ADR-0025 options 1-3, FORNX-443).

use serde_json::{json, Value};

/// Which runner's summary format matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryFormat {
    Pytest,
    Cargo,
}

impl SummaryFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            SummaryFormat::Pytest => "pytest",
            SummaryFormat::Cargo => "cargo",
        }
    }
}

/// Counts from a recognised runner summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestSummary {
    pub format: SummaryFormat,
    pub passed: u64,
    pub failed: u64,
}

impl TestSummary {
    /// The evidence-payload form: `{"format":"pytest","passed":2,"failed":0}`.
    pub fn to_json(self) -> Value {
        json!({"format": self.format.as_str(), "passed": self.passed, "failed": self.failed})
    }
}

/// Extract the final test summary from a command's combined output.
pub fn summarize(output: &str) -> Option<TestSummary> {
    let text = strip_ansi(output);
    let lines: Vec<&str> = text
        .split(['\n', '\r'])
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let pytest = lines.last().and_then(|l| pytest_summary(l));
    let cargo = cargo_summary(&lines);
    match (pytest, cargo) {
        (Some(p), None) => Some(p),
        (None, Some(c)) => Some(c),
        // Nothing recognised, or two formats at once (ambiguous).
        _ => None,
    }
}

/// `summarize` as an evidence-payload value.
pub fn summary_json(output: &str) -> Option<Value> {
    summarize(output).map(TestSummary::to_json)
}

/// Add `test_summary` (counts only) to an exit-code evidence payload when
/// `output` ends in a recognised runner summary.
pub fn attach_summary(payload: &mut Value, output: Option<&str>) {
    if let (Some(summary), Some(object)) = (output.and_then(summary_json), payload.as_object_mut())
    {
        object.insert("test_summary".to_string(), summary);
    }
}

fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI: ESC [ params final-byte(@..~)
            if chars.peek() == Some(&'[') {
                chars.next();
                for n in chars.by_ref() {
                    if ('@'..='~').contains(&n) {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// `N word` tokens separated by `, `, ending ` in <secs>s` (optionally
/// followed by `(h:mm:ss)`), with optional `=` decoration.
fn pytest_summary(line: &str) -> Option<TestSummary> {
    let body = line.trim_matches(|c: char| c == '=' || c.is_whitespace());
    let (counts, timing) = body.rsplit_once(" in ")?;
    let timing = timing.split(" (").next()?;
    let secs = timing.strip_suffix('s')?;
    if secs.is_empty() || !secs.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    let (mut passed, mut failed) = (0u64, 0u64);
    let mut any = false;
    for part in counts.split(", ") {
        let (n, word) = part.split_once(' ')?;
        let n: u64 = n.parse().ok()?;
        match word {
            "passed" => passed += n,
            "failed" | "error" | "errors" => failed += n,
            "skipped" | "deselected" | "xfailed" | "xpassed" | "warning" | "warnings" | "rerun" => {
            }
            _ => return None,
        }
        any = true;
    }
    any.then_some(TestSummary {
        format: SummaryFormat::Pytest,
        passed,
        failed,
    })
}

/// Sum of all `test result:` lines; every one must be `ok.`.
fn cargo_summary(lines: &[&str]) -> Option<TestSummary> {
    let (mut passed, mut failed) = (0u64, 0u64);
    let mut seen = false;
    for line in lines {
        let Some(rest) = line.strip_prefix("test result: ") else {
            continue;
        };
        let rest = rest.strip_prefix("ok. ")?;
        seen = true;
        for part in rest.split("; ") {
            let part = part.split(';').next()?.trim();
            let Some((n, word)) = part.split_once(' ') else {
                continue;
            };
            let Ok(n) = n.parse::<u64>() else { continue };
            match word {
                "passed" => passed += n,
                "failed" => failed += n,
                _ => {}
            }
        }
    }
    seen.then_some(TestSummary {
        format: SummaryFormat::Cargo,
        passed,
        failed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pytest(passed: u64, failed: u64) -> Option<TestSummary> {
        Some(TestSummary {
            format: SummaryFormat::Pytest,
            passed,
            failed,
        })
    }

    #[test]
    fn pytest_final_line_in_both_decorations() {
        assert_eq!(summarize("....\n2 passed in 0.02s\n"), pytest(2, 0));
        assert_eq!(
            summarize("x\n============ 3 passed, 1 skipped, 2 warnings in 1.50s ============\n"),
            pytest(3, 0)
        );
        assert_eq!(
            summarize("== 1 failed, 4 passed, 1 error in 0.30s (0:00:00) ==\n"),
            pytest(4, 2)
        );
        assert_eq!(
            summarize("\u{1b}[32m2 passed\u{1b}[0m in 0.02s"),
            pytest(2, 0)
        );
        assert_eq!(summarize("a\r\n5 passed in 9s\r\n"), pytest(5, 0));
    }

    #[test]
    fn pytest_summary_must_be_the_last_non_empty_line() {
        assert_eq!(summarize("5 passed in 0.1s\nsomething else\n"), None);
        assert_eq!(summarize("5 passed in 0.1s\n\n\n"), pytest(5, 0));
    }

    #[test]
    fn pytest_non_summaries_are_rejected() {
        for out in [
            "",
            "no tests ran in 0.01s",
            "collected 0 items\n",
            "5 passed",
            "5 passed in fast",
            "five passed in 0.1s",
            "5 flying in 0.1s",
            "echo 5 passed in 0.1s extra words",
            "-5 passed in 0.1s",
        ] {
            assert_eq!(summarize(out), None, "{out:?}");
        }
        // Zero passed is a summary (the verifier then refuses Verified).
        assert_eq!(summarize("1 skipped in 0.01s"), pytest(0, 0));
    }

    #[test]
    fn cargo_results_are_summed_and_all_must_be_ok() {
        let out = "running 2 tests\n..\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        assert_eq!(
            summarize(out),
            Some(TestSummary {
                format: SummaryFormat::Cargo,
                passed: 2,
                failed: 0
            })
        );
        let zero = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\n";
        assert_eq!(summarize(zero).map(|s| s.passed), Some(0));
        let failed = "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        assert_eq!(summarize(failed), None);
        let one_bad = "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        assert_eq!(summarize(one_bad), None);
    }

    #[test]
    fn two_formats_at_once_are_ambiguous() {
        let out = "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n2 passed in 0.02s\n";
        assert_eq!(summarize(out), None);
    }

    #[test]
    fn json_form_carries_counts_only() {
        assert_eq!(
            summary_json("2 passed in 0.02s").unwrap(),
            json!({"format": "pytest", "passed": 2, "failed": 0})
        );
        assert_eq!(summary_json("nothing here"), None);
    }
}
