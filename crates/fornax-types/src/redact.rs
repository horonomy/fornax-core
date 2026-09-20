//! Local privacy/redaction boundary (FORNX-33).
//!
//! Raw tool output (Bash `tool_response`, Codex `aggregated_output`) can
//! carry secrets — confirmed empirically, not hypothetically (see
//! docs/research/adapter-capability-matrix.md and the FORNX-33 Jira finding).
//! This redacts recognizable secret shapes from a JSON evidence payload
//! *before* it is ever persisted or considered for cloud egress. It is a
//! conservative pattern-based classifier, not a guarantee — never treat
//! "redacted" as "safe to sync" without also checking a policy allowlist.

use serde_json::Value;

/// A single detector: name (for provenance) + how to spot the value.
struct Detector {
    name: &'static str,
    matches: fn(&str) -> bool,
}

fn looks_like_github_token(s: &str) -> bool {
    s.starts_with("ghp_") || s.starts_with("gho_") || s.starts_with("ghu_") || s.starts_with("ghs_")
}

fn looks_like_generic_high_entropy_secret(s: &str) -> bool {
    // Long, unbroken alphanumeric-ish run with no spaces — the shape of an
    // API key/token, not natural-language text. Deliberately conservative:
    // false positives (redacting something benign) are far cheaper than
    // false negatives here.
    if s.len() < 20 || s.len() > 200 || s.contains(char::is_whitespace) {
        return false;
    }
    let alnum_ish = s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '_'
            || c == '-'
            || c == '.'
            || c == '/'
            || c == '+'
            || c == '='
    });
    if !alnum_ish {
        return false;
    }
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let has_alpha = s.chars().any(|c| c.is_ascii_alphabetic());
    has_digit && has_alpha
}

fn looks_like_env_secret_assignment(s: &str) -> bool {
    let upper = s.to_uppercase();
    [
        "TOKEN=",
        "API_KEY=",
        "APIKEY=",
        "SECRET=",
        "PASSWORD=",
        "PRIVATE_KEY=",
    ]
    .iter()
    .any(|marker| upper.contains(marker))
}

fn detectors() -> Vec<Detector> {
    vec![
        Detector {
            name: "github_token",
            matches: looks_like_github_token,
        },
        Detector {
            name: "env_secret_assignment",
            matches: looks_like_env_secret_assignment,
        },
        Detector {
            name: "high_entropy_token",
            matches: looks_like_generic_high_entropy_secret,
        },
    ]
}

/// Redact recognizable secrets from free-text (e.g. a shell command's
/// aggregated stdout+stderr). Line-oriented and token-oriented: whole lines
/// matching an env-assignment shape are fully redacted (the value is on the
/// same line as its name); otherwise individual whitespace-delimited tokens
/// that look like a high-entropy secret are replaced in place.
pub fn redact_text(input: &str) -> String {
    let dets = detectors();
    input
        .lines()
        .map(|line| {
            if dets
                .iter()
                .any(|d| d.name == "env_secret_assignment" && (d.matches)(line))
            {
                return "[REDACTED: possible secret assignment]".to_string();
            }
            line.split_whitespace()
                .map(|tok| {
                    if dets
                        .iter()
                        .any(|d| d.name != "env_secret_assignment" && (d.matches)(tok))
                    {
                        "[REDACTED]".to_string()
                    } else {
                        tok.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Recursively redact every string value in a JSON payload. Keys are left
/// alone (field names aren't secrets); only values are scanned. Applied to
/// every `Evidence.payload` and `AgentEvent.tool_response`/`raw` before
/// storage — redaction happens at the boundary, once, not re-derived per
/// downstream consumer.
pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(redact_text(s)),
        Value::Array(items) => Value::Array(items.iter().map(redact_json).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_json(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_github_personal_access_token() {
        let out = redact_text("GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz");
        assert_eq!(out, "[REDACTED: possible secret assignment]");
    }

    #[test]
    fn redacts_bare_high_entropy_token_without_a_name() {
        let out = redact_text("here is a token: ghp_abcdefghijklmnopqrstuvwxyz0123456789");
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("ghp_"));
    }

    #[test]
    fn leaves_ordinary_command_output_untouched() {
        let out = redact_text("7 failed, 1 passed in 3.21s");
        assert_eq!(out, "7 failed, 1 passed in 3.21s");
    }

    /// FORNX-19: confirms a documented gap rather than adding speculative
    /// detection — a path containing a real username is short, lowercase,
    /// and path-separator-heavy enough that it does not trip the
    /// high-entropy shape (no digit, or too short once split on `/`).
    #[test]
    fn does_not_redact_a_path_containing_a_username() {
        let out = redact_text("reading /Users/alice/.ssh/id_rsa for the demo");
        assert!(out.contains("/Users/alice/.ssh/id_rsa"));
    }

    /// FORNX-19: confirms a documented gap — a short, human-chosen password
    /// passed as a literal CLI argument is under the 20-character floor for
    /// the high-entropy detector and isn't an env-assignment line, so it is
    /// not redacted today.
    #[test]
    fn does_not_redact_a_short_password_shaped_cli_argument() {
        let out = redact_text("mysql -u root --password hunter2 -e 'select 1'");
        assert!(out.contains("hunter2"));
    }

    /// FORNX-19: a long, high-entropy value passed as a literal shell
    /// argument (not a `NAME=value` assignment) IS caught, because
    /// `high_entropy_token` tests the token itself, independent of the flag
    /// name preceding it — no new detector needed for this shape.
    #[test]
    fn redacts_a_high_entropy_secret_passed_as_a_shell_argument() {
        let out = redact_text(
            "curl --api-key zqT9v2Lk8pXwR4nHc7bEaMdJ1sYuF6oQ3iZgN0tKrV5 https://example.com",
        );
        assert!(!out.contains("zqT9v2Lk8pXwR4nHc7bEaMdJ1sYuF6oQ3iZgN0tKrV5"));
        assert!(out.contains("[REDACTED]"));
        assert!(out.contains("--api-key"));
    }

    /// FORNX-19: `redact_text` is not a pure "replace the matched substring
    /// in place" transform — it rebuilds each line via
    /// `split_whitespace().join(" ")`, which normalizes (and can lossily
    /// collapse) whitespace even on lines with nothing to redact. Documented
    /// as a fidelity caveat, not a detection gap.
    #[test]
    fn normalizes_whitespace_even_when_nothing_is_redacted() {
        let out = redact_text("  indented\ttext  with   gaps");
        assert_eq!(out, "indented text with gaps");
    }

    #[test]
    fn redacts_nested_json_values_not_keys() {
        let v = serde_json::json!({
            "exit_code": 1,
            "aggregated_output": "JIRA_API_TOKEN=ATATT3xFfGF0LAvBpMqDMfvc_secretvaluehere123"
        });
        let redacted = redact_json(&v);
        assert_eq!(redacted["exit_code"], 1);
        assert_eq!(
            redacted["aggregated_output"],
            "[REDACTED: possible secret assignment]"
        );
    }
}
