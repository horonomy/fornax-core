//! Terminal-safe display of manifest-derived strings.
//!
//! Several fields in the pinned `host-adapter-manifest` v1 schema have no
//! character restriction beyond non-empty -- `adapter_version` is
//! `{"type":"string","minLength":1}` with no `pattern` at all, and
//! `runtime_files[].path`'s pattern excludes only `\0`/`\r`/`\n`, not ESC.
//! A manifest's own schema validity does not make its strings
//! terminal-safe: an ESC-prefixed control sequence printed raw can rewrite
//! the operator's terminal output (move the cursor, hide subsequent text,
//! clear the screen) rather than just displaying as a string. Matches this
//! repo's existing convention (ADR-0023: "all displayed strings are
//! length-capped and control-char-rejected") rather than inventing a new
//! one.

const MAX_DISPLAY_CHARS: usize = 256;

/// Replaces every control character (including ESC) with U+FFFD and caps
/// length, so the result is always safe to pass to `println!`.
pub fn sanitize_for_display(value: &str) -> String {
    let mut out: String = value
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .take(MAX_DISPLAY_CHARS)
        .collect();
    if value.chars().count() > MAX_DISPLAY_CHARS {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_including_esc_are_replaced() {
        let malicious = "1.0.0\u{1b}[2J\u{1b}[H-pwned";
        let sanitized = sanitize_for_display(malicious);
        assert!(
            !sanitized.contains('\u{1b}'),
            "ESC must never survive sanitization: {sanitized:?}"
        );
        assert!(sanitized.contains("1.0.0"));
        assert!(sanitized.contains("pwned"));
    }

    #[test]
    fn ordinary_strings_pass_through_unchanged() {
        assert_eq!(sanitize_for_display("claude-code"), "claude-code");
    }

    #[test]
    fn overlong_strings_are_capped_and_marked() {
        let long = "a".repeat(1000);
        let sanitized = sanitize_for_display(&long);
        assert!(sanitized.len() < long.len());
        assert!(sanitized.ends_with("..."));
    }
}
