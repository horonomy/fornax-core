//! Structural proofs, not assertions-by-convention, for the boundaries
//! this crate's whole design depends on:
//!
//! - internal-docs ADR-0015 R1/R2 (no implicit launch, explicit action
//!   only) rest in part on there being exactly one place in this crate
//!   that can spawn a process.
//! - Separation from HORO-1718 Gate B rests on this crate depending on no
//!   `fornax-*` crate, and nothing under `crates/` depending back on it.
//!
//! These are source-text scans, same style as
//! `crates/fornax-daemon/tests/adversarial_daemon_input.rs`'s own
//! `subprocess_surface_is_still_zero_in_production_code` and
//! `exec/fornax-host-adapter-exec/tests/review_only.rs`'s
//! `source_tree_contains_no_subprocess_spawn_call` -- cheap, and they fail
//! CI the moment the boundary is crossed, rather than relying on a reviewer
//! noticing.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn this_crate_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Tokens that mean "this file can start a new process." Same list
/// `exec/fornax-host-adapter-exec/tests/review_only.rs` scans for, plus
/// the shell-escape forms it also bans.
const SPAWN_TOKENS: &[&str] = &[
    "std::process::Command",
    "process::Command",
    "Command::new",
    "sh -c",
    "/bin/sh",
];

/// Strips a trailing `#[cfg(test)]\nmod tests { ... }` block so the scans
/// below only see production code -- test helpers inside `launch.rs`
/// itself (e.g. `env_whitelist_is_exact`'s own `Command::new("/usr/bin/true")`
/// smoke check) are not part of the real spawn surface this crate ships.
fn strip_test_module(contents: &str) -> &str {
    contents.split("#[cfg(test)]").next().unwrap_or(contents)
}

fn rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rs_files(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    out
}

#[test]
fn spawn_surface_is_confined_to_launch_module() {
    let mut offenders = Vec::new();
    for file in rs_files(&this_crate_src()) {
        let is_launch = file.file_name().and_then(|n| n.to_str()) == Some("launch.rs");
        let raw = fs::read_to_string(&file).unwrap();
        let contents = strip_test_module(&raw);
        for token in SPAWN_TOKENS {
            if contents.contains(token) && !is_launch {
                offenders.push(format!("{}: contains {:?}", file.display(), token));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "spawn-capable token found outside src/launch.rs -- internal-docs ADR-0015 R1/R2 depend on \
         exactly one spawn site existing:\n{}",
        offenders.join("\n")
    );
}

/// `launch.rs` itself must contain exactly one `Command::new(` call --
/// proving the single-spawn-site claim above isn't just "no token outside
/// launch.rs" but also "not an unbounded number of sites inside it either."
#[test]
fn launch_module_has_exactly_one_spawn_call_site() {
    let raw = fs::read_to_string(this_crate_src().join("launch.rs")).unwrap();
    let contents = strip_test_module(&raw);
    let count = contents.matches("Command::new(").count();
    assert_eq!(
        count, 1,
        "expected exactly one Command::new( call in launch.rs, found {count}"
    );
}

/// internal-docs ADR-0015 R4/R5: the client's outgoing vocabulary must
/// stay exactly {initialize, initialized, hooks/list} -- pins the enum's
/// method set so a future edit can't silently widen what this crate can
/// ask Codex to do.
#[test]
fn protocol_can_only_emit_allowlisted_methods() {
    use fornax_host_trust_exec::protocol::ClientMessage;
    use std::path::PathBuf;

    let variants = [
        ClientMessage::Initialize,
        ClientMessage::Initialized,
        ClientMessage::HooksList {
            cwd: PathBuf::from("/x"),
        },
    ];
    let methods: Vec<&str> = variants.iter().map(|m| m.method()).collect();
    assert_eq!(methods, vec!["initialize", "initialized", "hooks/list"]);
}

/// Gate B separation: this crate's own manifest must name no `fornax-*`
/// dependency. A relative-path dependency on a sibling crate would show up
/// here as a `path = "../../crates/..."` style table even without the
/// name looking like `fornax-*`, so this also rejects any `path = ` table
/// under `[dependencies]` as a belt-and-suspenders check.
#[test]
fn crate_dependency_allowlist() {
    let manifest =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let deps_section = manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|rest| rest.split("[dev-dependencies]").next())
        .expect("Cargo.toml must have a [dependencies] section");
    assert!(
        !deps_section.contains("fornax-"),
        "fornax-host-trust-exec must depend on no fornax-* crate (keeps it \
         structurally separate from HORO-1718 Gate B); found a reference in \
         [dependencies]:\n{deps_section}"
    );
    assert!(
        !deps_section.contains("path ="),
        "fornax-host-trust-exec must not path-depend on any sibling crate"
    );
}

/// The other half of Gate B separation: nothing under `crates/` may
/// depend back on this crate.
#[test]
fn nothing_under_crates_depends_on_host_trust_exec() {
    let crates_dir = repo_root().join("crates");
    let mut offenders = Vec::new();
    let Ok(entries) = fs::read_dir(&crates_dir) else {
        panic!("expected {} to exist", crates_dir.display());
    };
    for entry in entries.flatten() {
        let manifest_path = entry.path().join("Cargo.toml");
        if let Ok(contents) = fs::read_to_string(&manifest_path) {
            if contents.contains("fornax-host-trust-exec") {
                offenders.push(manifest_path.display().to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a crate under crates/ depends on fornax-host-trust-exec, which must stay \
         reachable only from its own CLI (internal-docs ADR-0015 R1/R2):\n{}",
        offenders.join("\n")
    );
}
