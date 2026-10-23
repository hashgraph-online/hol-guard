use gauntlet_evidence::{
    native_review_completed, recompute_native_review_summary, verify_native_review_summary,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/native_review_summary_v1.json")).unwrap()
}

#[test]
fn python_review_status_and_summary_match() {
    let fixture = fixture();
    assert_eq!(
        fixture["schema"],
        "gauntlet-python-native-review-summary.v1"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap();
    for (field, source) in [
        (
            "source_sha256",
            "ci/gauntlet/benchmark/builtin_hook_supervisor.py",
        ),
        (
            "status_sha256",
            "ci/gauntlet/benchmark/native_review_status.py",
        ),
    ] {
        assert_eq!(
            fixture[field],
            format!(
                "{:x}",
                Sha256::digest(std::fs::read(root.join(source)).unwrap())
            )
        );
    }
    let status = fixture["review_cases"].as_array().unwrap();
    assert_eq!(fixture["reason_count"], 28);
    assert_eq!(status.len(), 39);
    for row in status {
        assert_eq!(
            native_review_completed(&row["response"]),
            row["completed"].as_bool().unwrap(),
            "{}",
            row["name"]
        );
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    for row in cases {
        let observed = recompute_native_review_summary(&row["events"], &row["contained"]);
        if row["error"].is_null() {
            assert_eq!(observed.unwrap(), row["result"], "{}", row["name"]);
        } else {
            assert_eq!(
                observed.unwrap_err().to_string(),
                row["error"].as_str().unwrap(),
                "{}",
                row["name"]
            );
        }
    }
}

#[test]
fn stored_summary_cannot_override_recomputed_missing_post() {
    let fixture = fixture();
    let rows = fixture["cases"].as_array().unwrap();
    let missing = rows
        .iter()
        .find(|row| row["name"] == "missing-post")
        .unwrap();
    let builtin = json!({
        "transport_observations": missing["events"],
        "contained_transport_observations": missing["contained"],
        "review_summary": missing["result"],
    });
    assert_eq!(
        verify_native_review_summary(&builtin).unwrap(),
        json!({"review_complete": false, "execution_eligible": false})
    );
    let mut forged = builtin;
    forged["review_summary"]["missing_required_post_call_ids"] = json!([]);
    assert_eq!(
        verify_native_review_summary(&forged)
            .unwrap_err()
            .to_string(),
        "native output review incomplete or unavailable"
    );
}
