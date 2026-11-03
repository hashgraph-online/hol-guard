use super::*;

#[test]
fn rollback_uses_only_quiescent_last_good_metadata_and_exact_measured_identity() {
    let f = Fixture::new(false);
    let (mut owner, settings) = f.begin();
    assert!(owner.rollback_target().is_err());
    let normal = jobs::SwitchRequest {
        job_id: "next".into(),
        target_runtime_id: "old".into(),
        expected_generation: 5,
        rollback: false,
    };
    assert!(owner.prepare_for(&normal).is_err());
    owner.advance(SelectionPhase::StopIntent).unwrap();
    owner.commit(&settings).unwrap();
    owner.mark_healthy("switch-test").unwrap();
    assert!(owner.rollback_target().is_err());
    owner.complete_publication("switch-test").unwrap();
    assert_eq!(owner.rollback_target().unwrap(), pointer("old").runtime);
    let request = jobs::SwitchRequest {
        rollback: true,
        ..normal
    };
    owner.prepare_for(&request).unwrap();
    owner
        .check_rollback_target(&request, &pointer("old").runtime)
        .unwrap();
    let mut changed = pointer("old").runtime;
    changed.installation_sha256 = "9".repeat(64);
    assert!(owner.check_rollback_target(&request, &changed).is_err());
    let wrong = jobs::SwitchRequest {
        target_runtime_id: "another".into(),
        ..request
    };
    assert!(owner.prepare_for(&wrong).is_err());
}
#[test]
fn legacy_request_bytes_and_fingerprints_stay_unchanged_and_rollback_is_a_distinct_intent() {
    let raw = r#"{"job_id":"legacy","target_runtime_id":"next","expected_generation":5}"#;
    let request: jobs::SwitchRequest = serde_json::from_str(raw).unwrap();
    assert!(!request.rollback);
    assert_eq!(serde_json::to_string(&request).unwrap(), raw);
    let expected = format!(
        "{:x}",
        Sha256::digest(format!(
            "[\"guard-cigar-switch-job-request.v1\",{raw},\"old\"]"
        ))
    );
    let old = jobs::SwitchJob::new(request.clone(), "old".into()).unwrap();
    assert_eq!(old.request_sha256, expected);
    let reverse = jobs::SwitchRequest {
        rollback: true,
        ..request
    };
    assert_ne!(
        jobs::SwitchJob::new(reverse.clone(), "old".into())
            .unwrap()
            .request_sha256,
        old.request_sha256
    );
    assert_eq!(reverse.operation(), "rollback");
}
