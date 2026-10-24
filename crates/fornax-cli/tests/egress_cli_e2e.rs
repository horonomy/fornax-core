//! Real end-to-end CLI flow for `fornax egress` (FORNX-464): the actual
//! compiled `fornax` binary against an isolated `$FORNAX_HOME`. No daemon,
//! no network, no real corporate or personal data.

use std::process::{Command, Output};
use uuid::Uuid;

fn fornax_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax")
}

fn temp_home() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("fornax-egress-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn run(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(fornax_bin())
        .args(args)
        .env("FORNAX_HOME", home)
        .output()
        .expect("run fornax")
}

fn ok(home: &std::path::Path, args: &[&str]) -> String {
    let out = run(home, args);
    assert!(
        out.status.success(),
        "fornax {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fails(home: &std::path::Path, args: &[&str]) -> String {
    let out = run(home, args);
    assert!(!out.status.success(), "fornax {args:?} should have failed");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn projection(home: &std::path::Path) -> serde_json::Value {
    let raw = std::fs::read_to_string(home.join("egress-projection.json")).unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn a_fresh_install_says_nothing_leaves_and_the_monthly_upload_is_described_as_scheduled() {
    let home = temp_home();
    let status = ok(&home, &["egress", "status"]);
    assert!(status.contains("profile: unconfigured"), "{status}");
    assert!(status.contains("NOTHING leaves this machine"), "{status}");
    assert!(
        status.contains("scheduled/monthly upload: the daemon sends each closed month"),
        "{status}"
    );
    assert!(
        !status.contains("not available in this release"),
        "{status}"
    );
    std::fs::remove_dir_all(&home).ok();
}

#[test]
fn the_personal_flow_records_consent_and_the_projection_never_authorizes_the_uploader() {
    let home = temp_home();
    ok(&home, &["egress", "profile-set", "personal"]);
    ok(
        &home,
        &[
            "egress",
            "allow-add",
            "--purpose",
            "evidence_batch_upload",
            "https://ingest.example.test/v1",
        ],
    );
    let out = ok(
        &home,
        &[
            "egress",
            "consent-grant",
            "--purpose",
            "evidence_batch_upload",
            "--destination",
            "https://ingest.example.test/v1",
            "--classes",
            "evidence_metadata,finding_verdicts",
            "--days",
            "30",
        ],
    );
    assert!(out.contains("recorded consent"), "{out}");
    let status = ok(&home, &["egress", "status"]);
    assert!(status.contains("-- live"), "{status}");
    assert!(
        status.contains("https://ingest.example.test:443/v1"),
        "{status}"
    );

    // The uploader projection exists, is personal, and authorizes nothing.
    let p = projection(&home);
    assert_eq!(p["schema_version"], 1);
    assert_eq!(p["profile"], "personal");
    assert_eq!(p["authorized"], serde_json::json!([]));
    std::fs::remove_dir_all(&home).ok();
}

#[test]
fn claim_text_and_the_reserved_uploader_purpose_cannot_be_granted() {
    let home = temp_home();
    ok(&home, &["egress", "profile-set", "personal"]);
    let err = fails(
        &home,
        &[
            "egress",
            "consent-grant",
            "--purpose",
            "evidence_batch_upload",
            "--destination",
            "https://ingest.example.test/v1",
            "--classes",
            "claim_text",
        ],
    );
    assert!(err.contains("only metadata classes"), "{err}");
    let err = fails(
        &home,
        &[
            "egress",
            "consent-grant",
            "--purpose",
            "uploader_spool_stream",
            "--destination",
            "https://ingest.example.test/v1",
            "--classes",
            "evidence_metadata",
        ],
    );
    assert!(err.contains("not available"), "{err}");
    std::fs::remove_dir_all(&home).ok();
}

#[test]
fn corporate_revokes_consents_refuses_new_ones_and_needs_confirmation_to_leave() {
    let home = temp_home();
    ok(&home, &["egress", "profile-set", "personal"]);
    ok(
        &home,
        &[
            "egress",
            "allow-add",
            "--purpose",
            "audit_checkpoint",
            "https://cp.example.test/c",
        ],
    );
    ok(
        &home,
        &[
            "egress",
            "consent-grant",
            "--purpose",
            "audit_checkpoint",
            "--destination",
            "https://cp.example.test/c",
            "--classes",
            "evidence_metadata",
        ],
    );
    ok(&home, &["egress", "profile-set", "corporate"]);
    let status = ok(&home, &["egress", "status"]);
    assert!(status.contains("corporate is local-only"), "{status}");
    assert!(status.contains("monthly upload never"), "{status}");
    assert!(status.contains("-- revoked"), "{status}");
    assert_eq!(projection(&home)["profile"], "corporate");

    let err = fails(
        &home,
        &[
            "egress",
            "consent-grant",
            "--purpose",
            "audit_checkpoint",
            "--destination",
            "https://cp.example.test/c",
            "--classes",
            "evidence_metadata",
        ],
    );
    assert!(err.contains("local-only"), "{err}");
    let err = fails(&home, &["egress", "profile-set", "personal"]);
    assert!(err.contains("--confirm-leave-corporate"), "{err}");
    ok(
        &home,
        &[
            "egress",
            "profile-set",
            "personal",
            "--confirm-leave-corporate",
        ],
    );
    std::fs::remove_dir_all(&home).ok();
}

#[test]
fn corporate_status_names_the_authorized_judge_exception_and_is_not_org_enforced() {
    let home = temp_home();
    ok(&home, &["egress", "profile-set", "corporate"]);
    ok(
        &home,
        &[
            "egress",
            "allow-add",
            "--purpose",
            "semantic_judge",
            "https://judge.invalid/v1",
        ],
    );
    ok(
        &home,
        &[
            "egress",
            "consent-grant",
            "--purpose",
            "semantic_judge",
            "--destination",
            "https://judge.invalid/v1",
            "--classes",
            "claim_text,redacted_evidence_payload",
            "--authorization-ref",
            "TEST-DISPOSABLE-NO-NETWORK",
        ],
    );
    let status = ok(&home, &["egress", "status"]);
    assert!(status.contains("allowlisted policy fetch"), "{status}");
    assert!(status.contains("semantic-judge gateway"), "{status}");
    assert!(status.contains("recorded corporate processing"), "{status}");
    assert!(
        status.contains("not organization-enforced policy"),
        "{status}"
    );
    assert!(
        !status.contains("no evidence, checkpoint or work data"),
        "{status}"
    );
    std::fs::remove_dir_all(&home).ok();
}
