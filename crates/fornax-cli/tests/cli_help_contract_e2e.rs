//! End-to-end CLI-contract tests against the real compiled `fornax` binary
//! (HORO-1610, HORO-1621, ADR-0013). The unit tests in `main.rs` cover
//! parsing and in-process computation; these cover what a real invocation
//! actually prints and exits with — the width/non-TTY/NO_COLOR/version
//! properties a unit test over `Cli::command()` can't observe, because
//! clap's `wrap_help` wrapping depends on the real terminal-width
//! resolution path (`COLUMNS` env var / isatty), not anything a derive-level
//! unit test touches.

use std::process::Command;

fn fornax_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax")
}

fn run(args: &[&str], columns: Option<&str>, no_color: bool) -> (String, String, i32) {
    let mut cmd = Command::new(fornax_bin());
    cmd.args(args);
    if let Some(c) = columns {
        cmd.env("COLUMNS", c);
    } else {
        cmd.env_remove("COLUMNS");
    }
    if no_color {
        cmd.env("NO_COLOR", "1");
    } else {
        cmd.env_remove("NO_COLOR");
    }
    let out = cmd.output().expect("spawn fornax");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

fn max_line_len(s: &str) -> usize {
    s.lines().map(|l| l.chars().count()).max().unwrap_or(0)
}

#[test]
fn root_help_has_no_unbounded_line_at_narrow_width() {
    let (stdout, _stderr, code) = run(&["--help"], Some("70"), false);
    assert_eq!(code, 0);
    // Generous slack over the stated 70 columns for box-drawing/ANSI-free
    // prose that doesn't break on every exact boundary — the ADR-0013 §5
    // anti-vacuity bar is "no unbounded line", not pixel-perfect wrapping.
    let longest = max_line_len(&stdout);
    assert!(
        longest <= 100,
        "root --help at COLUMNS=70 had a {longest}-char line — expected wrap_help to bound it"
    );
}

#[test]
fn root_help_renders_at_three_widths_without_crashing() {
    for width in ["70", "110", "160"] {
        let (stdout, _stderr, code) = run(&["--help"], Some(width), false);
        assert_eq!(code, 0, "COLUMNS={width}");
        assert!(!stdout.is_empty());
    }
}

#[test]
fn root_help_is_usable_non_tty_piped_output() {
    // Command::output() already captures via pipes (non-TTY) by construction
    // — this just asserts that path produces real content, not an
    // interactive-only blank/prompt.
    let (stdout, _stderr, code) = run(&["--help"], None, false);
    assert_eq!(code, 0);
    assert!(stdout.contains("Usage"));
    assert!(stdout.contains("fornax"));
}

#[test]
fn no_color_emits_no_ansi_escapes() {
    let (stdout, _stderr, _code) = run(&["--help"], None, true);
    assert!(
        !stdout.contains('\u{1b}'),
        "NO_COLOR=1 must emit no ANSI escape codes"
    );
}

#[test]
fn version_flag_matches_authoritative_cargo_metadata() {
    let (stdout, _stderr, code) = run(&["--version"], None, false);
    assert_eq!(code, 0);
    assert_eq!(
        stdout.trim(),
        format!("fornax {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn version_is_side_effect_free_and_offline() {
    // No daemon, no network reachable in this sandboxed test run; if
    // `--version` tried either, it would hang or error instead of
    // returning instantly.
    let start = std::time::Instant::now();
    let (_stdout, _stderr, code) = run(&["--version"], None, false);
    assert_eq!(code, 0);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "--version must not block on daemon/network"
    );
}

#[test]
fn unknown_command_is_a_clean_non_zero_exit_naming_the_input() {
    let (_stdout, stderr, code) = run(&["bogus-xyz-command"], None, false);
    assert_ne!(code, 0);
    assert!(
        !stderr.contains("panicked"),
        "must not be a raw panic/stack trace"
    );
    assert!(stderr.contains("bogus-xyz-command") || stderr.to_lowercase().contains("unrecognized"));
}

#[test]
fn adapter_help_lists_the_management_subcommands() {
    let (stdout, _stderr, code) = run(&["adapter", "--help"], None, false);
    assert_eq!(code, 0);
    assert!(stdout.contains("list"));
    assert!(stdout.contains("doctor"));
    assert!(stdout.contains("plan"));
}

#[test]
fn adapter_list_prints_known_adapters_and_touches_no_filesystem_state() {
    let home = std::env::temp_dir().join(format!("fornax-e2e-home-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&home).unwrap();
    let mut cmd = Command::new(fornax_bin());
    cmd.args(["adapter", "list"]).env("HOME", &home);
    let out = cmd.output().expect("spawn");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("claude-code"));
    assert!(stdout.contains("codex"));
    assert!(
        !home.join(".claude").exists(),
        "adapter list must be read-only — must not create ~/.claude"
    );
    assert!(
        !home.join(".codex").exists(),
        "adapter list must be read-only — must not create ~/.codex"
    );
    std::fs::remove_dir_all(&home).ok();
}

#[test]
fn adapter_plan_json_round_trips_adapter_field() {
    let home = std::env::temp_dir().join(format!("fornax-e2e-home-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&home).unwrap();
    let mut cmd = Command::new(fornax_bin());
    cmd.args(["adapter", "plan", "claude-code", "--json"])
        .env("HOME", &home);
    let out = cmd.output().expect("spawn");
    assert!(out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("plan --json must be valid JSON");
    assert_eq!(v["adapter"], "claude-code");
    assert_eq!(v["changed"], true);
    assert!(
        !home.join(".claude").exists(),
        "plan must never write — it only previews"
    );
    std::fs::remove_dir_all(&home).ok();
}

#[test]
fn install_unknown_adapter_is_a_clean_error_not_a_stack_trace() {
    let (_stdout, stderr, code) = run(&["install", "nope-not-a-real-adapter"], None, false);
    assert_ne!(code, 0);
    assert!(!stderr.contains("panicked"));
}

#[test]
fn legacy_adapter_commands_are_gone_and_write_nothing() {
    for legacy in [
        "install-claude",
        "uninstall-claude",
        "install-codex",
        "uninstall-codex",
    ] {
        let home = std::env::temp_dir().join(format!("fornax-e2e-home-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        let mut cmd = Command::new(fornax_bin());
        cmd.args([legacy]).env("HOME", &home);
        let out = cmd.output().expect("spawn");
        let code = out.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            code, 2,
            "`{legacy}` must be clap's usage-error exit for an unrecognized \
             subcommand, got {code} (stderr: {stderr})"
        );
        assert!(
            !stderr.contains("panicked"),
            "`{legacy}` must not panic: {stderr}"
        );
        assert!(
            stderr.contains(legacy) || stderr.to_lowercase().contains("unrecognized"),
            "`{legacy}` error must name the unrecognized input: {stderr}"
        );
        assert!(
            !home.join(".claude").exists() && !home.join(".codex").exists(),
            "`{legacy}` must not silently still install anything"
        );
        std::fs::remove_dir_all(&home).ok();
    }
}
