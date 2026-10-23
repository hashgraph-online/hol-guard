use gauntlet_worker_state::{fixed_builder_run_plan, BuilderRunError};
use serde_json::{json, Value};

fn request(case: &Value) -> Value {
    json!({
        "image_id":case["image_id"],
        "job_id":case["job_id"],
        "source_sha":case["source_sha"],
        "source_archive_sha256":case["source_archive_sha256"],
        "tag":case["tag"],
        "memory_gib":case["memory_gib"],
        "local_version":case["local_version"],
        "retest_build_job_id":case["retest_build_job_id"]
    })
}

#[test]
fn fixed_podman_run_vector_matches_pinned_python_for_release_and_local_builds() {
    let fixture: Value = serde_json::from_str(include_str!("python_builder_run_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/control_plane/vm_build.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(fixture["schema"], "gauntlet-builder-run-fixtures.v1");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases.iter().take(4) {
        let plan = fixed_builder_run_plan(&request(case)).unwrap();
        assert_eq!(plan.to_json()["argv"], case["argv"], "{case}");
        assert_eq!(plan.source_archive_sha256, "c".repeat(64));
        assert!(!plan.execution_eligible);
    }
    let base = request(&cases[0]);
    for case in cases.iter().skip(4) {
        let mut invalid = base.clone();
        invalid["memory_gib"] = case["memory"].clone();
        assert_eq!(case["refusal"], "bounded positive build memory required");
        assert_eq!(
            fixed_builder_run_plan(&invalid),
            Err(BuilderRunError::InvalidMemory),
            "{case}"
        );
    }
}

#[test]
fn fixed_plan_refuses_arbitrary_image_tag_path_or_retest_identity() {
    let fixture: Value = serde_json::from_str(include_str!("python_builder_run_v1.json")).unwrap();
    let mut base = request(&fixture["cases"][0]);
    base["command"] = json!("sh");
    assert_eq!(
        fixed_builder_run_plan(&base),
        Err(BuilderRunError::InvalidRequest)
    );
    base.as_object_mut().unwrap().remove("command");

    for (field, replacement) in [
        ("image_id", json!("localhost/untagged:latest")),
        ("job_id", json!("../escape")),
        ("source_sha", json!("A".repeat(40))),
        ("source_archive_sha256", json!("0".repeat(63))),
        ("tag", json!("v3.50.0")),
        ("local_version", json!("3.50.0a1")),
        ("retest_build_job_id", json!("fedcba9876543210")),
    ] {
        let mut invalid = base.clone();
        invalid[field] = replacement;
        assert_eq!(
            fixed_builder_run_plan(&invalid),
            Err(BuilderRunError::InvalidIdentity),
            "{field}"
        );
    }

    let mut local = request(&fixture["cases"][2]);
    local["local_version"] = json!("3.50.0a0");
    assert_eq!(
        fixed_builder_run_plan(&local),
        Err(BuilderRunError::InvalidIdentity)
    );
}
