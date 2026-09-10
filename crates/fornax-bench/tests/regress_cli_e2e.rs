//! Real end-to-end CLI test for `fornax-bench regress freeze/compare`
//! (FORNX-344): spawns the actual compiled `fornax-bench` binary against the
//! committed `fixtures/integrity-lab/` mechanism-verification fixtures.
//! Proves the mechanism (freeze -> compare -> gate) works over a real
//! runtime, not just the library's own unit tests. Every fixture used here
//! carries `LabelingProvenance::SyntheticMechanismTest` -- see
//! `fixtures/integrity-lab/mechanism-corpus.json` and this crate's own
//! module docs for why that is load-bearing, not informational.

use std::path::Path;
use std::process::Command;

fn bench_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax-bench")
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/integrity-lab")
        .join(name)
        .to_str()
        .unwrap()
        .to_string()
}

#[test]
fn comparing_the_committed_baseline_against_itself_is_unchanged_and_untested() {
    let corpus = fixture("mechanism-corpus.json");
    let baseline = fixture("mechanism-baseline.json");

    let output = Command::new(bench_bin())
        .args([
            "regress",
            "compare",
            "--dataset",
            &corpus,
            "--baseline",
            &baseline,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["gate"]["verdict"], "untested");
    assert_eq!(parsed["comparison"]["regressed_count"], 0);
    assert_eq!(parsed["comparison"]["improved_count"], 0);
    let cases = parsed["comparison"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2, "the committed corpus has exactly 2 cases");
    assert!(
        cases.iter().all(|c| c["class"] == "Unchanged"),
        "committed corpus vs. its own committed baseline must be Unchanged: {cases:?}"
    );
}

#[test]
fn comparing_with_the_committed_uncalibrated_budget_is_also_untested_never_a_fake_pass() {
    let corpus = fixture("mechanism-corpus.json");
    let baseline = fixture("mechanism-baseline.json");
    let budget = fixture("budget.json");

    let output = Command::new(bench_bin())
        .args([
            "regress",
            "compare",
            "--dataset",
            &corpus,
            "--baseline",
            &baseline,
            "--budget",
            &budget,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        parsed["gate"]["verdict"], "untested",
        "the committed budget.json ships calibrated:false, rules:[] -- must never silently \
         resolve to pass: {parsed}"
    );
}

#[test]
fn freezing_the_committed_corpus_twice_is_byte_identical_modulo_run_at() {
    let corpus = fixture("mechanism-corpus.json");
    let dir =
        std::env::temp_dir().join(format!("fornax-bench-freeze-e2e-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let out_a = dir.join("a.json");
    let out_b = dir.join("b.json");

    for out in [&out_a, &out_b] {
        let output = Command::new(bench_bin())
            .args([
                "regress",
                "freeze",
                "--dataset",
                &corpus,
                "--out",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    let mut a: serde_json::Value = serde_json::from_slice(&std::fs::read(&out_a).unwrap()).unwrap();
    let mut b: serde_json::Value = serde_json::from_slice(&std::fs::read(&out_b).unwrap()).unwrap();
    // run_at is a real clock read (the one place this binary reads it) --
    // strip it before comparing everything else for equality.
    a["manifest"]["run_at"] = serde_json::Value::Null;
    b["manifest"]["run_at"] = serde_json::Value::Null;
    assert_eq!(a, b);

    std::fs::remove_dir_all(&dir).ok();
}
