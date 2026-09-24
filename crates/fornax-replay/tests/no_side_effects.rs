//! FORNX-98 AC 2: replay never performs external side effects by default.
//!
//! Two structural checks, mirroring
//! `fornax-daemon/tests/adversarial_daemon_input.rs::subprocess_surface_is_still_zero_in_production_code`'s
//! source-inspection idiom:
//!
//! 1. This crate's production source (`src/`, excluding this `tests/`
//!    directory) contains no subprocess-spawn or network-client call.
//! 2. This crate's own `Cargo.toml` declares no networking/process
//!    dependency in the first place -- so the invariant holds even before
//!    inspecting any call site.
//!
//! A runtime-level check is unnecessary here (unlike the daemon, which
//! actually needs to prove behavior under adversarial *input*): `replay`'s
//! only parameter is an in-memory `ReplayManifest` value, so there is no
//! I/O surface at its call boundary to exercise at runtime in the first
//! place -- the guarantee is structural by construction, and these tests
//! pin that construction.

use std::path::Path;

const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    "process::Command",
    "Command::new",
    "sh -c",
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "std::net::",
    "tokio::net",
    "reqwest::",
    "hyper::",
];

#[test]
fn production_source_has_no_subprocess_or_network_surface() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    visit_rs_files(&src_dir, &mut |path| {
        let contents = std::fs::read_to_string(path).unwrap_or_default();
        for (i, line) in contents.lines().enumerate() {
            for needle in FORBIDDEN_SUBSTRINGS {
                if line.contains(needle) {
                    offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "found subprocess/network surface in fornax-replay production code:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cargo_toml_declares_no_networking_or_process_dependency() {
    let cargo_toml_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let contents = std::fs::read_to_string(&cargo_toml_path).expect("read Cargo.toml");
    // Only the [dependencies] section matters -- [dev-dependencies] may
    // legitimately need adapter crates for fixture-derived tests, and those
    // never run inside `replay` itself.
    let deps_section = contents
        .split("[dev-dependencies]")
        .next()
        .unwrap_or(&contents);
    for forbidden in ["reqwest", "hyper", "tokio", "\"net\""] {
        assert!(
            !deps_section.contains(forbidden),
            "fornax-replay's [dependencies] must not declare '{forbidden}'"
        );
    }
}

fn visit_rs_files(dir: &Path, f: &mut impl FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit_rs_files(&path, f);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            f(&path);
        }
    }
}
