use gauntlet_host_state::{project_public_jobs, PublicJobsError};
use serde_json::{json, Value};

#[test]
fn public_allowlist_archive_filter_and_order_match_pinned_python() {
    let fixture: Value = serde_json::from_str(include_str!("python_public_jobs_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/control_plane/agent.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(fixture["schema"], "gauntlet-public-jobs-fixtures.v1");
    let jobs = fixture["mixed_input"].as_array().unwrap();
    let projection = project_public_jobs(jobs).unwrap();
    assert_eq!(
        projection.to_json()["jobs"],
        fixture["mixed_output"]["jobs"]
    );
    assert_eq!(projection.archived_jobs, 1);
    assert_eq!(
        projection.to_json()["archived_jobs"],
        fixture["mixed_output"]["archived_jobs"]
    );
    assert!(!projection.publication_eligible);
}

#[test]
fn public_projection_keeps_only_newest_two_hundred() {
    let fixture: Value = serde_json::from_str(include_str!("python_public_jobs_v1.json")).unwrap();
    let limit = &fixture["limit"];
    let input: Vec<_> = (0..limit["input_count"].as_u64().unwrap())
        .map(|number| json!({"id":format!("{number:016x}"),"state":"queued","created_at":number}))
        .collect();
    let projection = project_public_jobs(&input).unwrap();
    assert_eq!(
        projection.jobs.len(),
        limit["visible_count"].as_u64().unwrap() as usize
    );
    assert_eq!(projection.jobs[0]["id"], limit["first_id"]);
    assert_eq!(projection.jobs.last().unwrap()["id"], limit["last_id"]);
    assert_eq!(projection.archived_jobs, 0);
}

#[test]
fn malformed_history_refuses_without_partial_publication() {
    let valid = json!({"id":"0000000000000001","state":"queued","created_at":1});
    for invalid in [
        json!({"id":"0000000000000002","state":"queued"}),
        json!({"id":"0000000000000002","state":"queued","created_at":"yesterday"}),
        json!({"id":"0000000000000002","state":"queued","created_at":2,"local_build":null}),
    ] {
        assert_eq!(
            project_public_jobs(&[valid.clone(), invalid]),
            Err(PublicJobsError::InvalidJob)
        );
    }
}
