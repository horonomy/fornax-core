//! FORNX-477: decide from an executed command's *structure* whether it is a
//! genuine test-runner invocation.
//!
//! `TestResultVerifier` turns "exit_code=0 for a test-runner command" into
//! `Verified`. Matching a runner name as a substring of the command text let
//! `echo pytest`, `pip install pytest`, `cat jest.config.js` or
//! `git commit -m "add vitest"` satisfy a "tests passed" claim without any
//! test having run. This module instead requires that the command, once its
//! shell wrapper is removed, is exactly one simple command whose program (and
//! subcommand) is a known runner.
//!
//! The rule is deliberately conservative: anything it cannot prove is a single
//! test-runner execution -- compound commands (`;`, `&&`, `||`, `|`, `&`),
//! redirections, subshells, expansions (`$`, backticks), comments, newlines,
//! unterminated quotes, unknown programs, list/help/compile-only flags -- is
//! "not a test run", which the verifier reports as `Unverified`. A false
//! `Unverified` costs a missed credit; a false `Verified` breaks the trust
//! contract.
//!
//! Residual (not closable from the command string alone): an executable
//! *named* like a runner is trusted to be that runner. Exit codes stay
//! agent-adjacent transcript evidence, so this does not change the trust
//! class of the evidence, only which commands may carry it.

use serde_json::Value;

/// Flags after which a runner exits 0 without executing any test. Long flags
/// also match as an abbreviation of at least four characters (argparse and
/// clap accept unambiguous prefixes), erring toward `Unverified`.
const NON_EXECUTING_LONG_FLAGS: &[&str] = &[
    "--collect-only",
    "--help",
    "--version",
    "--no-run",
    "--list",
    "--listTests",
    "--passWithNoTests",
    "--dry-run",
    "--fixtures",
    "--fixtures-per-test",
    "--markers",
    "--setup-plan",
    "--setup-only",
    "--showConfig",
    "--collectonly",
    "--setupplan",
    "--setuponly",
    "--funcargs",
    "--changedFilesWithAncestor",
    "--cache-show",
    "--override-ini",
    "--clearCache",
    "--init",
    "--onlyChanged",
    "--changedSince",
    "--lastCommit",
    "--findRelatedTests",
    "--changed",
    "--if-present",
    "--no-tests",
];
/// `-o` is pytest's `--override-ini` (it can set `addopts=--collect-only`) and
/// jest's `--onlyChanged` (exits 0 when nothing changed).
const NON_EXECUTING_SHORT_FLAGS: &[&str] = &["-h", "-V", "-o"];

/// Shell builtins that end the shell, change what later commands resolve to,
/// or run other code. Inside an `&&` list any of them means an overall status
/// of 0 no longer proves the runner ran, so the list is not identified.
const SHELL_STATE_BUILTINS: &[&str] = &[
    "exit",
    "logout",
    "exec",
    "return",
    "break",
    "continue",
    "source",
    ".",
    "eval",
    "export",
    "hash",
    "rehash",
    "alias",
    "unalias",
    "set",
    "setopt",
    "unsetopt",
    "emulate",
    "enable",
    "declare",
    "typeset",
    "integer",
    "readonly",
    "local",
    "unset",
    "function",
    "autoload",
    "trap",
    "shopt",
    "builtin",
    "command",
    "kill",
    "wait",
    "disown",
    "pushd",
    "popd",
    "path",
    "printf",
    "read",
    "mapfile",
    "readarray",
    "let",
    "getopts",
    "ulimit",
    "umask",
];

/// Valueless launcher flags that may precede the launched runner. Any other
/// flag may take a value (`uv run --with pytest python x.py`), which would
/// make the value look like the program.
const LAUNCHER_VALUELESS_FLAGS: &[&str] = &[
    "--yes",
    "-y",
    "--no-install",
    "--frozen",
    "--locked",
    "--isolated",
    "--no-sync",
    "--",
];

/// Environment assignments tolerated in front of a runner. Allowlist, not
/// denylist: anything else (`PATH`, `PYTHONPATH`, `PYTEST_ADDOPTS`, `NODE_OPTIONS`,
/// ...) can change which code the runner name resolves to or whether it runs
/// any test, so a command carrying one is not identified as a test run.
const BENIGN_ASSIGNMENTS: &[&str] = &[
    "CI",
    "FORCE_COLOR",
    "NO_COLOR",
    "RUST_BACKTRACE",
    "RUST_LOG",
    "CARGO_TERM_COLOR",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONUNBUFFERED",
    "NODE_ENV",
];

/// True when `command` (a Claude Bash command string, or a Codex argv array,
/// optionally run through a `sh|bash|zsh` command-string wrapper) shows a test runner executing tests
/// and `exit_code` is the exit status of that command.
///
/// * One simple command: the runner's own exit status, any value.
/// * `a && b && ...`: `&&` runs the next command only after the previous one
///   exited 0 and the list's status is the last one executed, so an overall
///   status of 0 proves every command ran and exited 0. A non-zero status does
///   not say which command failed (the runner may never have run), so it is
///   never attributed to the runner.
pub(crate) fn is_test_run(command: Option<&Value>, exit_code: Option<i64>) -> bool {
    let Some(segments) = command_segments(command) else {
        return false;
    };
    match segments.as_slice() {
        [only] => simple_command_runs_tests(only),
        _ => {
            exit_code == Some(0)
                && !segments.iter().any(|s| changes_shell_state(s))
                && segments.iter().any(|s| simple_command_runs_tests(s))
        }
    }
}

#[derive(Debug)]
struct Word {
    text: String,
    /// Any part of the word was quoted or escaped in the source.
    quoted: bool,
}

fn command_segments(command: Option<&Value>) -> Option<Vec<Vec<Word>>> {
    match command? {
        Value::String(script) => shell_segments(script),
        Value::Array(tokens) => {
            let argv: Vec<&str> = tokens.iter().map(Value::as_str).collect::<Option<_>>()?;
            if argv.is_empty() {
                return None;
            }
            if is_shell(argv[0]) {
                // shell command-string wrapper: anything but exactly that shape (extra
                // positional arguments, a missing script) is ambiguous.
                let flag = argv.get(1)?;
                if is_shell_command_flag(flag) {
                    return if argv.len() == 3 {
                        shell_segments(argv[2])
                    } else {
                        None
                    };
                }
            }
            // Directly exec'd argv: no shell, so no metacharacter is special.
            Some(vec![argv
                .iter()
                .map(|t| Word {
                    text: (*t).to_string(),
                    quoted: true,
                })
                .collect()])
        }
        _ => None,
    }
}

fn basename(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// `-c`, `-lc`, `-ic`, `-ec`, ...: a single-dash cluster that contains `c` and
/// nothing that stops the shell from running the script (`-n` only parses it).
fn is_shell_command_flag(flag: &str) -> bool {
    flag.starts_with('-')
        && !flag.starts_with("--")
        && flag.contains('c')
        && flag[1..].chars().all(|c| "cleuxvi".contains(c))
}

fn is_shell(program: &str) -> bool {
    matches!(basename(program), "sh" | "bash" | "zsh" | "dash")
}

/// Split a shell script into simple commands joined only by `&&`, or `None`
/// when it is anything else (`;`, `||`, `|`, `&`, redirections, subshells,
/// expansions, comments, newlines, unterminated quotes, empty commands).
fn shell_segments(script: &str) -> Option<Vec<Vec<Word>>> {
    // A shell splits words only on space and tab. Any other whitespace or
    // control character (NBSP, VT, FF, ...) is part of a word in the shell but
    // would be a separator here, so such a script is not parsed at all.
    if script
        .chars()
        .any(|c| (c.is_whitespace() || c.is_control()) && !matches!(c, ' ' | '\t' | '\n' | '\r'))
    {
        return None;
    }
    let mut segments: Vec<Vec<Word>> = Vec::new();
    let mut words: Vec<Word> = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quoted = false;
    let mut chars = script.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                if in_word {
                    words.push(Word {
                        text: std::mem::take(&mut cur),
                        quoted,
                    });
                    in_word = false;
                    quoted = false;
                }
            }
            // `2>&1` merges stderr into stdout and leaves the exit status alone.
            '>' if in_word && !quoted && cur == "2" && stderr_to_stdout_follows(&chars) => {
                chars.next();
                chars.next();
                cur.clear();
                in_word = false;
            }
            '&' if chars.peek() == Some(&'&') => {
                chars.next();
                if in_word {
                    words.push(Word {
                        text: std::mem::take(&mut cur),
                        quoted,
                    });
                    in_word = false;
                    quoted = false;
                }
                if words.is_empty() {
                    return None;
                }
                segments.push(std::mem::take(&mut words));
            }
            '\n' | '\r' | ';' | '&' | '|' | '<' | '>' | '(' | ')' | '{' | '}' | '$' | '`' => {
                return None;
            }
            '#' if !in_word => return None,
            '\\' => {
                // A trailing backslash or a line continuation is not a plain
                // word.
                let next = chars.next()?;
                if next == '\n' || next == '\r' {
                    return None;
                }
                cur.push(next);
                in_word = true;
                quoted = true;
            }
            '\'' => {
                in_word = true;
                quoted = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        ch => cur.push(ch),
                    }
                }
            }
            '"' => {
                in_word = true;
                quoted = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '$' | '`' => return None,
                        '\\' => match chars.next()? {
                            ch @ ('"' | '\\' | '$' | '`') => cur.push(ch),
                            ch => {
                                cur.push('\\');
                                cur.push(ch);
                            }
                        },
                        ch => cur.push(ch),
                    }
                }
            }
            ch => {
                in_word = true;
                cur.push(ch);
            }
        }
    }
    if in_word {
        words.push(Word { text: cur, quoted });
    }
    if words.is_empty() {
        // Empty script, or a trailing `&&`.
        return None;
    }
    segments.push(words);
    Some(segments)
}

/// After the `>` of a lone `2`: the rest is exactly `&1` and a word boundary.
fn stderr_to_stdout_follows(chars: &std::iter::Peekable<std::str::Chars<'_>>) -> bool {
    let mut ahead = chars.clone();
    ahead.next() == Some('&')
        && ahead.next() == Some('1')
        && matches!(ahead.next(), None | Some(' ') | Some('\t'))
}

fn assignment_name(word: &Word) -> Option<&str> {
    if word.quoted {
        return None;
    }
    let (name, _) = word.text.split_once('=')?;
    let mut chars = name.chars();
    let valid_start = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    (valid_start && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')).then_some(name)
}

/// An assignment-only segment, or one led by a shell-state builtin.
fn changes_shell_state(words: &[Word]) -> bool {
    let command = words.iter().position(|w| assignment_name(w).is_none());
    match command {
        None => true,
        Some(i) => SHELL_STATE_BUILTINS.contains(&words[i].text.as_str()),
    }
}

fn simple_command_runs_tests(words: &[Word]) -> bool {
    classify_segment(words).is_some()
}

/// Which runner a simple command executes, if it is an identified test run.
fn classify_segment(words: &[Word]) -> Option<RunnerKind> {
    let mut rest = words;
    while let Some(first) = rest.first() {
        match assignment_name(first) {
            Some(name) if BENIGN_ASSIGNMENTS.contains(&name) => rest = &rest[1..],
            Some(_) => return None,
            None => break,
        }
    }
    let args: Vec<&str> = rest.iter().map(|w| w.text.as_str()).collect();
    runner_invocation(&args, true)
}

/// The runner families whose final summary line the output parser
/// understands (`fornax_types::test_output`); every other identified runner is
/// `Other` and can therefore never be `Verified` (no execution proof).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunnerKind {
    Pytest,
    Cargo,
    Other,
}

/// The runner whose own output `command` produced, when that output can be
/// attributed to it: exactly one runner step, and every other step is a
/// silent `cd <dir>`. A list such as `echo '3 passed in 1s' && pytest` or
/// `make && cargo test` mixes in output of another program, so it yields
/// `None` and the output proves nothing.
pub(crate) fn proven_runner(command: Option<&Value>) -> Option<RunnerKind> {
    let segments = command_segments(command)?;
    let mut runner = None;
    for segment in &segments {
        if let Some(kind) = classify_segment(segment) {
            if runner.replace(kind).is_some() {
                return None;
            }
        } else if !is_plain_cd(segment) {
            return None;
        }
    }
    runner.filter(|kind| *kind != RunnerKind::Other)
}

/// How an evidence row's command relates to the command a claim names
/// (FORNX-477 exact binding). Never inferred from a substring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandBinding {
    /// The same command, step for step: the same program string and the same
    /// arguments.
    Exact,
    /// Close to the claimed command but not provably it: the claimed command
    /// followed by more arguments (`npm install` claimed, `npm install
    /// --dry-run` run), or the same program name reached through an absolute
    /// path (`/tmp/x/npm`). Extra arguments can change what the command did and
    /// an absolute path can be another program, so this is weaker than `Exact`.
    Prefix,
    /// The claimed command's text appears in the row but the row is not a run
    /// of it (`echo npm install`, `timeout 60 npm install`, a pipeline, a
    /// compound list). It can withhold a verdict, never support one.
    Mentioned,
    NotBound,
}

/// True when the claim's command literal parses to at least one simple
/// command, i.e. it can be compared structurally at all.
pub(crate) fn claim_command_parses(literal: &str) -> bool {
    command_segments(Some(&Value::String(literal.to_string()))).is_some_and(|segments| {
        !segments.is_empty() && segments.iter().all(|s| !core(s).is_empty())
    })
}

/// Bind a claim's command literal to one evidence row's `command`.
/// `evidence_text_lower` is the row's flattened, lowercased command text, used
/// only to tell `Mentioned` from `NotBound`. `exit_zero_reliable` is true only
/// for a genuine (non-heuristic) exit status 0: a plain `cd dir && cmd` row
/// binds `cmd` only then, because a guessed 0 does not show `cd` succeeded.
pub(crate) fn bind_command(
    claimed: &str,
    evidence: Option<&Value>,
    evidence_text_lower: &str,
    exit_zero_reliable: bool,
) -> CommandBinding {
    let Some(claim_segments) = command_segments(Some(&Value::String(claimed.to_string()))) else {
        return CommandBinding::NotBound;
    };
    if let Some(evidence_segments) = command_segments(evidence) {
        // Whole-command equality, step for step.
        if claim_segments.len() == evidence_segments.len() {
            let mut all_exact = true;
            let mut all_close = true;
            for (c, e) in claim_segments.iter().zip(&evidence_segments) {
                match compare(c, e) {
                    Fit::Exact => {}
                    Fit::Close => all_exact = false,
                    Fit::No => {
                        all_exact = false;
                        all_close = false;
                    }
                }
            }
            if all_exact {
                return CommandBinding::Exact;
            }
            if all_close {
                return CommandBinding::Prefix;
            }
        }
        // A single claimed command against a single, longer command, or
        // against `cd <dir> && <command>` with a genuine exit 0 (the only
        // other step is a silent `cd`, so the command ran and exited 0).
        if let [claim] = claim_segments.as_slice() {
            let runs: Vec<&Vec<Word>> = match evidence_segments.as_slice() {
                [only] => vec![only],
                list if exit_zero_reliable && list.len() > 1 => {
                    let others_are_cd = list.iter().filter(|s| !is_plain_cd(s)).count() == 1;
                    if others_are_cd {
                        list.iter().filter(|s| !is_plain_cd(s)).collect()
                    } else {
                        Vec::new()
                    }
                }
                _ => Vec::new(),
            };
            if let [observed] = runs.as_slice() {
                return match compare_prefix(claim, observed.as_slice()) {
                    Fit::Exact if evidence_segments.len() == 1 => CommandBinding::Exact,
                    Fit::Exact | Fit::Close => CommandBinding::Prefix,
                    Fit::No => mention_or_not(claimed, evidence_text_lower),
                };
            }
        }
    }
    mention_or_not(claimed, evidence_text_lower)
}

/// `Mentioned` only when the claimed command's text appears at word
/// boundaries, so a short claim such as `make` is not "mentioned" by
/// `cat Makefile`.
fn mention_or_not(claimed: &str, evidence_text_lower: &str) -> CommandBinding {
    let needle = claimed.trim().to_lowercase();
    if needle.is_empty() {
        return CommandBinding::NotBound;
    }
    let is_word = |c: char| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/');
    let mut from = 0;
    while let Some(i) = evidence_text_lower[from..].find(&needle) {
        let start = from + i;
        let end = start + needle.len();
        let before_ok = evidence_text_lower[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word(c));
        let after_ok = evidence_text_lower[end..]
            .chars()
            .next()
            .is_none_or(|c| !is_word(c));
        if before_ok && after_ok {
            return CommandBinding::Mentioned;
        }
        from = start + needle.chars().next().map_or(1, char::len_utf8);
    }
    CommandBinding::NotBound
}

/// A segment without its leading benign environment assignments (`CI=1`),
/// which do not change which command ran.
fn core(words: &[Word]) -> &[Word] {
    let mut rest = words;
    while let Some(first) = rest.first() {
        match assignment_name(first) {
            Some(name) if BENIGN_ASSIGNMENTS.contains(&name) => rest = &rest[1..],
            _ => break,
        }
    }
    rest
}

/// The leading benign assignments of a segment, verbatim (`CI=1`).
fn leading_assignments(words: &[Word]) -> Vec<&str> {
    let n = words.len() - core(words).len();
    words[..n].iter().map(|w| w.text.as_str()).collect()
}

enum Fit {
    Exact,
    Close,
    No,
}

/// Every environment assignment the claim names must appear, with the same
/// value, on the observed command (`CI=true` does not bind `CI=false`); an
/// observed assignment the claim does not mention is ignored.
fn assignments_fit(claim_seg: &[Word], observed_seg: &[Word]) -> bool {
    let observed = leading_assignments(observed_seg);
    leading_assignments(claim_seg)
        .iter()
        .all(|a| observed.contains(a))
}

/// An unquoted word the shell would expand (`*.rs`, `~`) is not the same
/// argument as its quoted spelling.
fn word_matches(claimed: &Word, observed: &Word) -> bool {
    if claimed.text != observed.text {
        return false;
    }
    if claimed.quoted == observed.quoted {
        return true;
    }
    let unquoted = if claimed.quoted { observed } else { claimed };
    !unquoted.text.contains(['*', '?', '[', ']', '~', '{', '}'])
}

/// Exact: same program string and equal arguments. Close: the same, but the
/// program was reached through an absolute path with the claimed basename.
fn compare(claimed_seg: &[Word], observed_seg: &[Word]) -> Fit {
    let (claimed, observed) = (core(claimed_seg), core(observed_seg));
    if !assignments_fit(claimed_seg, observed_seg)
        || claimed.is_empty()
        || claimed.len() != observed.len()
        || !claimed[1..]
            .iter()
            .zip(&observed[1..])
            .all(|(c, e)| word_matches(c, e))
    {
        return Fit::No;
    }
    program_fit(&claimed[0].text, &observed[0].text)
}

/// Like `compare` but the claim may be a strict prefix of the observed
/// arguments (`Close` then, never `Exact`).
fn compare_prefix(claimed_seg: &[Word], observed_seg: &[Word]) -> Fit {
    let (claimed, observed) = (core(claimed_seg), core(observed_seg));
    if !assignments_fit(claimed_seg, observed_seg)
        || claimed.is_empty()
        || claimed.len() > observed.len()
    {
        return Fit::No;
    }
    if !claimed[1..]
        .iter()
        .zip(&observed[1..claimed.len()])
        .all(|(c, e)| word_matches(c, e))
    {
        return Fit::No;
    }
    match program_fit(&claimed[0].text, &observed[0].text) {
        Fit::No => Fit::No,
        _ if claimed.len() < observed.len() => Fit::Close,
        fit => fit,
    }
}

/// A claimed program with a path must match exactly (`./deploy.sh` never binds
/// `./other/deploy.sh`); a bare claimed name against an absolute path with that
/// basename is only `Close`, since a path can be a different program.
fn program_fit(claimed: &str, observed: &str) -> Fit {
    if claimed == observed {
        Fit::Exact
    } else if !claimed.contains('/') && observed.starts_with('/') && basename(observed) == claimed {
        Fit::Close
    } else {
        Fit::No
    }
}

/// `cd <dir>`: one plain, non-option argument.
fn is_plain_cd(words: &[Word]) -> bool {
    matches!(words, [cd, dir] if cd.text == "cd" && !cd.quoted
        && !dir.text.is_empty() && !dir.text.starts_with('-'))
}

/// `args[0]` is the program. `allow_launcher` is true only at the top level so
/// `uv run npx pnpm ...` chains are not followed.
fn runner_invocation(args: &[&str], allow_launcher: bool) -> Option<RunnerKind> {
    let program = args.first().copied()?;
    let name = basename(program);
    let tail = &args[1..];

    let kind = match name {
        "pytest" | "py.test" => Some(RunnerKind::Pytest),
        // `vitest list` / `jest list`-style subcommands only enumerate tests.
        // `-v` is `--version` for both; `init`/`list` do not run tests.
        "vitest" | "jest" => (!matches!(tail, ["list" | "init" | "bench", ..])
            && !tail.contains(&"-v"))
        .then_some(RunnerKind::Other),
        n if is_python(n) => matches!(tail, ["-m", "pytest", ..]).then_some(RunnerKind::Pytest),
        "cargo" => {
            let tail = match tail.first() {
                Some(t) if t.starts_with('+') => &tail[1..],
                _ => tail,
            };
            match tail {
                ["test", ..] => Some(RunnerKind::Cargo),
                ["nextest", "run", ..] => Some(RunnerKind::Other),
                _ => None,
            }
        }
        "npm" => matches!(tail, ["test", ..]).then_some(RunnerKind::Other),
        "npx" | "pnpx" | "bunx" if allow_launcher => return launched_runner(tail),
        "uv" | "poetry" if allow_launcher => {
            return match tail {
                ["run", rest @ ..] => launched_runner(rest),
                _ => None,
            };
        }
        "pnpm" if allow_launcher => {
            return match tail {
                ["exec", rest @ ..] => launched_runner(rest),
                _ => None,
            };
        }
        _ => None,
    };
    kind.filter(|_| !tail.iter().any(|a| is_non_executing_flag(a)))
}

/// After a launcher (`npx`, `uv run`, ...): skip its value-less flags, then
/// the remainder must itself be a runner invocation.
fn launched_runner(args: &[&str]) -> Option<RunnerKind> {
    let mut skip = 0;
    while let Some(arg) = args.get(skip).filter(|a| a.starts_with('-')) {
        if !LAUNCHER_VALUELESS_FLAGS.contains(arg) {
            return None;
        }
        skip += 1;
    }
    runner_invocation(&args[skip..], false)
}

fn is_python(name: &str) -> bool {
    name.strip_prefix("python")
        .is_some_and(|v| v.is_empty() || v.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

fn is_non_executing_flag(arg: &str) -> bool {
    if NON_EXECUTING_SHORT_FLAGS.contains(&arg) {
        return true;
    }
    if arg.starts_with('-') && !arg.starts_with("--") {
        let short = &arg[1..];
        // `-ofoo`, `-hx`, `-Vx`: the flag with an attached value or cluster.
        if short.starts_with(['o', 'h', 'V']) {
            return true;
        }
        // A cluster of short flags (`-qh`, `-Vq`, `-xo`) containing one.
        if short.len() > 1
            && short.chars().all(|c| c.is_ascii_alphabetic())
            && short.contains(['o', 'h', 'V'])
        {
            return true;
        }
    }
    // `--flag=value` is the same flag; flags compare case-, dash- and
    // underscore-insensitively (`--list-tests` == `--listTests`) and as an
    // unambiguous-prefix abbreviation, erring toward `Unverified`.
    let base = arg.split_once('=').map_or(arg, |(flag, _)| flag);
    if !base.starts_with("--") {
        return false;
    }
    let base = normalize_flag(base);
    base.len() >= 2
        && NON_EXECUTING_LONG_FLAGS
            .iter()
            .any(|flag| normalize_flag(flag).starts_with(&base))
}

fn normalize_flag(flag: &str) -> String {
    flag.chars()
        .filter(|c| !matches!(c, '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect()
}
