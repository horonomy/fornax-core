//! HORO-1715: proves the founder-recorded fail-closed decision end to end,
//! against a real registered descriptor and real on-disk files -- not just
//! unit-level assertions on `review`'s pure functions.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use fornax_host_adapter_exec::review::{self, VersionCompatibility};
use fornax_store::adapter_registry::{register_host_descriptor, set_registration_enabled};

fn temp_home() -> PathBuf {
    std::env::temp_dir().join(format!(
        "fornax-host-adapter-exec-test-{}",
        uuid::Uuid::new_v4()
    ))
}

/// Writes a small file at `path` with `contents`, creating parent dirs, and
/// returns its `sha256:<hex>` digest (computed the same way `review` does,
/// independently reimplemented here so a bug in `review`'s own hashing
/// can't hide behind a test that trusts the same code it's testing).
fn write_file_and_digest(path: &Path, contents: &[u8]) -> String {
    fs::create_dir_all(path.parent().expect("parent dir")).expect("mkdir");
    let mut file = fs::File::create(path).expect("create file");
    file.write_all(contents).expect("write file");
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(contents);
    let encoded: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{encoded}")
}

fn manifest_json(
    adapter_id: &str,
    executable: &Path,
    runtime_files: &[(&Path, &str, &str)],
    needs_environment: &[&str],
) -> String {
    let runtime_files_json: Vec<serde_json::Value> = runtime_files
        .iter()
        .map(|(path, kind, digest)| {
            serde_json::json!({"path": path.to_string_lossy(), "kind": kind, "digest": digest})
        })
        .collect();
    serde_json::json!({
        "manifest_kind": "host-adapter",
        "manifest_version": 1,
        "adapter_id": adapter_id,
        "adapter_version": "1.0.0",
        "protocol_versions": [1],
        "contract_version_range": {"minimum": 1, "maximum": 1},
        "roles": ["LifecycleSource"],
        "capabilities": ["lifecycle.session"],
        "host_version_constraints": [{"provider": "synthetic_host", "minimum": null, "maximum": null}],
        "configuration_schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "properties": {}, "additionalProperties": false},
        "launch": {"executable": executable.to_string_lossy(), "argv": ["--stdio-json"]},
        "runtime_files": runtime_files_json,
        "input_limits": {"max_bytes": 1048576},
        "needs": {"environment": needs_environment, "read_paths": [], "write_paths": []},
    })
    .to_string()
}

#[test]
fn doctor_on_an_unregistered_id_refuses_without_panicking() {
    let home = temp_home();
    let descriptor = fornax_store::adapter_registry::lookup_host_descriptor(&home, "nope");
    assert!(
        descriptor.is_err(),
        "lookup of an unregistered id must fail, not panic"
    );
}

#[test]
fn review_reports_matching_digest_but_never_claims_execution_is_safe() {
    let home = temp_home();
    fs::create_dir_all(&home).expect("mkdir home");

    let adapter_id = "synthetic_adapter";
    let executable = home.join("adapter-bin");
    let dependency = home.join("adapter-lib.so");
    let exe_digest = write_file_and_digest(&executable, b"#!/bin/sh\necho hi\n");
    let dep_digest = write_file_and_digest(&dependency, b"fake shared object bytes");

    let raw = manifest_json(
        adapter_id,
        &executable,
        &[
            (&executable, "entrypoint", exe_digest.as_str()),
            (&dependency, "dependency", dep_digest.as_str()),
        ],
        &[],
    );
    register_host_descriptor(&home, "test-source", "2026-10-09T00:00:00Z", raw.as_bytes())
        .expect("register descriptor");

    let descriptor =
        fornax_store::adapter_registry::lookup_host_descriptor(&home, adapter_id).expect("lookup");
    let review = review::build_review(&descriptor).expect("build review");

    assert_eq!(review.fields.adapter_id, adapter_id);
    assert!(
        matches!(review.version, VersionCompatibility::Compatible { .. }),
        "protocol/contract version 1 must negotiate as compatible"
    );
    assert!(!review.environment_grant_declared);
    assert!(!review.measurement_capacity_exceeded);
    assert_eq!(review.runtime_files.len(), 2);
    assert!(
        review.runtime_files.iter().all(|f| f.matches_declared),
        "both declared files' real bytes match their declared digests"
    );
    assert!(
        review.implementation_digest.is_some(),
        "a fully measurable manifest must produce an implementation digest"
    );
    // Not enabled by default -- registration always starts disabled.
    assert!(!review.entry_enabled);
}

#[test]
fn review_detects_a_tampered_runtime_file_as_a_mismatch_not_a_match() {
    let home = temp_home();
    fs::create_dir_all(&home).expect("mkdir home");

    let adapter_id = "synthetic_adapter";
    let executable = home.join("adapter-bin");
    let original_digest = write_file_and_digest(&executable, b"original bytes");

    let raw = manifest_json(
        adapter_id,
        &executable,
        &[(&executable, "entrypoint", original_digest.as_str())],
        &[],
    );
    register_host_descriptor(&home, "test-source", "2026-10-09T00:00:00Z", raw.as_bytes())
        .expect("register descriptor");

    // Tamper with the on-disk bytes AFTER registration -- the declared
    // digest in the registered manifest still says `original_digest`.
    write_file_and_digest(&executable, b"a non-root writer changed this file");

    let descriptor =
        fornax_store::adapter_registry::lookup_host_descriptor(&home, adapter_id).expect("lookup");
    let review = review::build_review(&descriptor).expect("build review");

    let file = review
        .runtime_files
        .first()
        .expect("one declared runtime file");
    assert!(
        !file.matches_declared,
        "tampered bytes must be reported as a mismatch, never silently treated as a match"
    );
    assert_ne!(
        file.measured_digest.as_deref(),
        Some(original_digest.as_str())
    );
}

#[test]
fn review_flags_a_declared_environment_grant_as_unavailable() {
    let home = temp_home();
    fs::create_dir_all(&home).expect("mkdir home");

    let adapter_id = "synthetic_adapter";
    let executable = home.join("adapter-bin");
    let digest = write_file_and_digest(&executable, b"bytes");

    let raw = manifest_json(
        adapter_id,
        &executable,
        &[(&executable, "entrypoint", digest.as_str())],
        &["SOME_SECRET"],
    );
    register_host_descriptor(&home, "test-source", "2026-10-09T00:00:00Z", raw.as_bytes())
        .expect("register descriptor");

    let descriptor =
        fornax_store::adapter_registry::lookup_host_descriptor(&home, adapter_id).expect("lookup");
    let review = review::build_review(&descriptor).expect("build review");

    assert!(review.environment_grant_declared);
}

#[test]
fn a_host_adapter_registration_cannot_currently_be_enabled_at_all() {
    // `fornax-store` itself already refuses to enable a `host-adapter-v1`
    // registration until the separately owned runner/trust handoff exists
    // (`RegistryErrorCode::ExecutionBoundaryUnavailable`) -- this crate's
    // own fail-closed decision is a second, independent layer on top of
    // that, not the only thing currently preventing execution. Asserts the
    // current, real behavior rather than assuming enablement is reachable.
    let home = temp_home();
    fs::create_dir_all(&home).expect("mkdir home");

    let adapter_id = "synthetic_adapter";
    let executable = home.join("adapter-bin");
    let digest = write_file_and_digest(&executable, b"bytes");

    let raw = manifest_json(
        adapter_id,
        &executable,
        &[(&executable, "entrypoint", digest.as_str())],
        &[],
    );
    register_host_descriptor(&home, "test-source", "2026-10-09T00:00:00Z", raw.as_bytes())
        .expect("register descriptor");

    let enable_result = set_registration_enabled(&home, adapter_id, true);
    assert!(
        enable_result.is_err(),
        "a host-adapter-v1 registration must not be enablable yet -- expected \
         ExecutionBoundaryUnavailable, got {enable_result:?}"
    );

    let descriptor =
        fornax_store::adapter_registry::lookup_host_descriptor(&home, adapter_id).expect("lookup");
    let review = review::build_review(&descriptor).expect("build review");

    // Still disabled, and this crate's own review/refusal logic does not
    // depend on the enabled flag either way -- there is no code path in
    // this binary that would spawn an adapter regardless of its state.
    assert!(!review.entry_enabled);
}

/// The defining regression test for the founder decision itself: this
/// crate's entire source tree must contain zero subprocess-spawn call
/// sites. If a future change ever adds one back, this test -- not just a
/// doc comment -- fails.
#[test]
fn source_tree_contains_no_subprocess_spawn_call() {
    let banned = [
        "std::process::Command",
        "Command::new",
        "tokio::process",
        "posix_spawn",
        "execve",
        "execv(",
        "execvp(",
        "fexecve",
    ];
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offending = Vec::new();
    for entry in fs::read_dir(&src_dir).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let contents = fs::read_to_string(&path).expect("read source file");
        // Skip comment lines -- this crate's own module docs describe the
        // absence of these calls by name (e.g. "there is no
        // std::process::Command ... anywhere in it"), which would
        // otherwise false-positive against the exact prose explaining the
        // founder decision this test enforces.
        let code_only: String = contents
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for needle in banned {
            if code_only.contains(needle) {
                offending.push(format!("{}: contains '{needle}'", path.display()));
            }
        }
    }
    assert!(
        offending.is_empty(),
        "this crate must never spawn a subprocess (founder decision, 2026-10-09): {offending:?}"
    );
}
