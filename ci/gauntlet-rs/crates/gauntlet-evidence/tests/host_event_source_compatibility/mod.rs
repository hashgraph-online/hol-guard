use serde_json::Value;
use std::path::Path;
use std::process::Command;

/// Preserve historical vectors while requiring an exact reviewed source pair,
/// unchanged reducer ASTs, and current Python replay of every frozen case.
pub fn verify(kind: &str, historical_sha: &Value, cases: usize) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap();
    let output = Command::new("python3")
        .args(["-I", "-B"])
        .arg(root.join("ci/gauntlet-rs/proofs/verify_host_event_fixture_compatibility.py"))
        .arg(kind)
        .output()
        .expect("Python 3 is required to verify reviewed fixture compatibility");
    assert!(
        output.status.success(),
        "current Python compatibility proof failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let proof: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        proof["schema"],
        "gauntlet-host-event-source-compatibility.v1"
    );
    assert_eq!(proof["kind"], kind);
    assert_eq!(proof["historical_source_sha256"], *historical_sha);
    assert_eq!(proof["replayed_cases"], cases);
    assert_eq!(proof["unchanged_function_asts"], 2);
    proof["current_source_sha256"].clone()
}
