use gauntlet_host_state::{admitted, archive_unwatched, next_queued_job, QueueConfig, QueueError};
use serde_json::{json, Value};

fn fixture() -> Value {
    let fixture: Value =
        serde_json::from_str(include_str!("python_release_queue_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    assert_eq!(fixture["schema"], "gauntlet-release-queue-fixtures.v1");
    for (path, field) in [
        ("ci/gauntlet/control_plane/releases.py", "releases_sha256"),
        ("ci/gauntlet/control_plane/agent.py", "agent_sha256"),
    ] {
        let source = manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == path)
            .unwrap();
        assert_eq!(fixture[field], source["sha256"]);
    }
    fixture
}

fn config(fixture: &Value, mode: &str) -> QueueConfig {
    QueueConfig::from_operations(&fixture["configs"][mode]).unwrap()
}

#[test]
fn admission_matches_pinned_python_for_both_modes() {
    let fixture = fixture();
    let cases = fixture["admitted"].as_array().unwrap();
    assert_eq!(cases.len(), 30);
    for case in cases {
        let mode = case["mode"].as_str().unwrap();
        let result = admitted(&config(&fixture, mode), &case["job"]).unwrap();
        assert_eq!(result, case["admitted"].as_bool().unwrap(), "{case}");
    }
}

#[test]
fn archival_matches_pinned_python_and_preserves_uncertain_jobs() {
    let fixture = fixture();
    let cases = fixture["archived"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let mode = case["mode"].as_str().unwrap();
        let mut jobs = case["before"].as_array().unwrap().clone();
        let saved = archive_unwatched(
            &config(&fixture, mode),
            &mut jobs,
            case["now"].as_f64().unwrap(),
        )
        .unwrap();
        assert_eq!(jobs, *case["after"].as_array().unwrap(), "{mode}");
        assert_eq!(
            saved,
            serde_json::from_value::<Vec<String>>(case["saved"].clone()).unwrap()
        );
        for state in ["preparing", "running", "unknown"] {
            assert!(jobs
                .iter()
                .any(|job| job["state"] == state && job.get("archived_at").is_none()));
        }
    }
}

#[test]
fn selection_matches_pinned_python_predicate_and_order() {
    let fixture = fixture();
    let cases = fixture["selected"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for case in cases {
        let mode = case["mode"].as_str().unwrap();
        let jobs = case["jobs"].as_array().unwrap();
        let actual = next_queued_job(
            &config(&fixture, mode),
            jobs,
            case["held"].as_bool().unwrap(),
            case["active"].as_bool().unwrap(),
            case["admission_reasons"].as_bool().unwrap(),
        )
        .unwrap();
        assert_eq!(actual, case["selected"].as_str(), "{case}");
    }
}

#[test]
fn invalid_configuration_and_job_batch_refuse_without_partial_archive() {
    for bad in [
        json!({"discovery_mode":"other", "release_tags":["v3.48.0"]}),
        json!({"discovery_mode":"release-tags", "release_tags":[]}),
        json!({"discovery_mode":"release-tags", "release_tags":["v3.48.0", "v3.48.0"]}),
        json!({"discovery_mode":"release-tags", "release_tags":["v3.48.0-rc1"]}),
    ] {
        assert_eq!(
            QueueConfig::from_operations(&bad),
            Err(QueueError::InvalidConfig)
        );
    }
    let config = config(&fixture(), "release-tags");
    let mut jobs = vec![
        json!({"id":"0000000000000001", "state":"queued", "kind":"pull-request"}),
        json!({"id":"0000000000000002", "kind":"pull-request"}),
    ];
    let original = jobs.clone();
    assert_eq!(
        archive_unwatched(&config, &mut jobs, 100.0),
        Err(QueueError::InvalidJob)
    );
    assert_eq!(jobs, original);
    assert_eq!(
        archive_unwatched(&config, &mut jobs, f64::NAN),
        Err(QueueError::InvalidTime)
    );
}
