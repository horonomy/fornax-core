//! HORO-1618: `<command> --help` must terminate in clap's parser/help path
//! before any real handler runs — never start/connect to the daemon, never
//! read or write `$FORNAX_HOME`, regardless of whether that command is a
//! read-only live-state query (`status`), a mutation (`install`), or a
//! direct-store reader (`audit`/`timeline`).
//!
//! Each case runs the real compiled binary against a scratch `$FORNAX_HOME`
//! that starts empty and is asserted to stay empty, with `FORNAX_HTTP_PORT`
//! pointed at a closed port so a `status`/`detail` handler that actually ran
//! would hang or error against it rather than silently succeed — if any of
//! these commands ever started entering its handler for `--help`, this
//! would catch it structurally, not just by scanning output text.

use std::fs;
use std::process::Command;
use std::time::{Duration, Instant};

fn fornax_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax")
}

fn run_help_in_scratch_home(args: &[&str]) -> (String, String, i32, std::path::PathBuf) {
    let home = std::env::temp_dir().join(format!("fornax-help-purity-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&home).expect("create scratch home");
    let start = Instant::now();
    let out = Command::new(fornax_bin())
        .args(args)
        .env("HOME", &home)
        .env("FORNAX_HOME", home.join(".fornax"))
        // A closed, almost-certainly-unbound port: a handler that actually
        // tried to reach the daemon would fail to connect, not time out
        // silently — either way it would not look like a clean help exit.
        .env("FORNAX_HTTP_PORT", "1")
        .output()
        .expect("spawn fornax");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "`fornax {args:?} --help`-shaped invocation took {elapsed:?} -- too slow for a pure \
         parser/help path, suggests a handler ran and attempted real work"
    );
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
        home,
    )
}

fn assert_help_is_pure(args: &[&str]) {
    let (stdout, stderr, code, home) = run_help_in_scratch_home(args);
    assert_eq!(
        code, 0,
        "`fornax {args:?}` must exit 0 (clap's help success semantics), got {code} \
         (stderr: {stderr})"
    );
    assert!(
        stdout.to_lowercase().contains("usage"),
        "`fornax {args:?}` must print clap-formatted help, got: {stdout}"
    );
    assert!(
        !fs::read_dir(&home)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false),
        "`fornax {args:?}` must not create anything under a fresh $HOME/$FORNAX_HOME, \
         found entries in {home:?}"
    );
    fs::remove_dir_all(&home).ok();
}

#[test]
fn root_help_is_pure() {
    assert_help_is_pure(&["--help"]);
}

#[test]
fn status_help_is_pure_a_live_daemon_state_command() {
    // `status` would otherwise connect to the daemon's HTTP API
    // (`base_url()`/`/api/status`) -- see main.rs's dispatch.
    assert_help_is_pure(&["status", "--help"]);
}

#[test]
fn detail_help_is_pure_a_live_daemon_state_command() {
    assert_help_is_pure(&["detail", "--help"]);
}

#[test]
fn install_help_is_pure_a_mutation_command() {
    assert_help_is_pure(&["install", "--help"]);
}

#[test]
fn install_adapter_help_is_pure_a_mutation_command() {
    assert_help_is_pure(&["install", "claude-code", "--help"]);
}

#[test]
fn adapter_help_is_pure_a_registry_inspection_command() {
    assert_help_is_pure(&["adapter", "--help"]);
}

#[test]
fn audit_help_is_pure_a_direct_store_reader() {
    assert_help_is_pure(&["audit", "--help"]);
}

#[test]
fn timeline_help_is_pure_a_direct_store_reader() {
    assert_help_is_pure(&["timeline", "--help"]);
}

/// Anti-vacuity: `--help` in a nonsensical position (before the subcommand
/// even has its required args) must still short-circuit cleanly rather than
/// surface a usage error from deeper validation logic -- proving these
/// tests exercise clap's dedicated help path, not merely "any early exit".
#[test]
fn help_wins_even_before_a_required_positional_is_supplied() {
    assert_help_is_pure(&["uninstall", "--help"]);
}
