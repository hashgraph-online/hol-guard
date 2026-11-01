use super::*;
use std::os::unix::fs::PermissionsExt;

fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    home
}
fn job(id: &str) -> SwitchJob {
    SwitchJob::new(
        SwitchRequest {
            job_id: id.into(),
            target_runtime_id: "target".into(),
            expected_generation: 5,
            rollback: false,
        },
        "source".into(),
    )
    .unwrap()
}
#[test]
fn durable_metadata_is_idempotent_bounded_and_never_creates_an_installation() {
    let dir = home();
    let home = dir.path();
    let _owner = Owner::acquire(home).unwrap();
    for index in 0..MAX_JOBS {
        let mut record = job(&format!("switch-{index}"));
        save(home, &mut record, JobPhase::Queued, "queued").unwrap();
    }
    assert_eq!(preparation::total_job_count(home).unwrap(), MAX_JOBS);
    assert!(!home.join("context-assistance/installations").exists());
    let mut existing = get(home, "switch-0").unwrap().unwrap();
    save(home, &mut existing, JobPhase::Ready, "ready").unwrap();
    let mut excess = job("one-more");
    assert!(save(home, &mut excess, JobPhase::Queued, "queued")
        .unwrap_err()
        .ends_with("switch_job_limit"));
    assert!(get(home, "one-more").unwrap().is_none());
    assert_eq!(list(home).unwrap().len(), MAX_JOBS);
}
#[test]
fn a_cancel_marker_is_bound_to_the_exact_request_and_does_not_change_preferences() {
    let dir = home();
    let home = dir.path();
    let _owner = Owner::acquire(home).unwrap();
    let mut record = job("cancel-test");
    save(home, &mut record, JobPhase::Ready, "ready").unwrap();
    assert!(!cancelled(home, &record).unwrap());
    mark_cancel(home, &record).unwrap();
    assert!(cancelled(home, &record).unwrap());
    assert!(!home.join("config.toml").exists());
    let mut changed = record.clone();
    changed.request.expected_generation += 1;
    changed.request_sha256 = request_hash(&changed.request, &changed.source_runtime_id).unwrap();
    assert!(cancelled(home, &changed).is_err());
    assert_eq!(
        get(home, "cancel-test")
            .unwrap()
            .unwrap()
            .request
            .expected_generation,
        5
    );
}
#[test]
fn stored_progress_cannot_change_request_identity_or_reverse_a_terminal_job() {
    let dir = home();
    let home = dir.path();
    let _owner = Owner::acquire(home).unwrap();
    let mut record = job("final-test");
    save(home, &mut record, JobPhase::Cancelled, "cancelled").unwrap();
    let path = directory(home, false)
        .unwrap()
        .join(record_name("final-test"));
    let before = fs::read(&path).unwrap();
    let mut changed = record.clone();
    changed.request.expected_generation = 6;
    changed.request_sha256 = request_hash(&changed.request, &changed.source_runtime_id).unwrap();
    assert!(save(home, &mut changed, JobPhase::Cancelled, "cancelled").is_err());
    assert!(save(home, &mut record, JobPhase::Ready, "ready").is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(get(home, "../escape").is_err());
}

#[test]
fn restoration_has_a_separate_bounded_budget_without_extending_the_preparation_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let mut record = job("restore-budget");
    let original = record.deadline_at_ms;
    save(home, &mut record, JobPhase::Committing, "committing").unwrap();
    let old = serde_json::to_value(&record).unwrap();
    assert!(old.get("restoration_deadline_at_ms").is_none());
    let decoded: SwitchJob = serde_json::from_value(old).unwrap();
    decoded.validate().unwrap();
    record.restoration_deadline_at_ms = Some(original + 30_001);
    assert!(save(
        home,
        &mut record,
        JobPhase::Restoring,
        "restoring_previous_runtime"
    )
    .is_err());
    record.restoration_deadline_at_ms = Some(original + 30_000);
    save(
        home,
        &mut record,
        JobPhase::Restoring,
        "restoring_previous_runtime",
    )
    .unwrap();
    assert_eq!(record.deadline_at_ms, original);
    record.restoration_deadline_at_ms = Some(original + 29_999);
    assert!(save(
        home,
        &mut record,
        JobPhase::Restoring,
        "restoring_previous_runtime"
    )
    .is_err());
}

#[test]
fn disabled_job_mode_is_bound_without_changing_legacy_records_or_cancellation_identity() {
    let dir = home();
    let home = dir.path();
    let _owner = Owner::acquire(home).unwrap();
    let live = job("cold-mode");
    let raw = serde_json::to_value(&live).unwrap();
    assert!(raw.get("source_disabled").is_none());
    let decoded: SwitchJob = serde_json::from_value(raw).unwrap();
    decoded.validate().unwrap();
    assert!(!decoded.source_disabled);
    let mut cold =
        SwitchJob::new_disabled(live.request.clone(), live.source_runtime_id.clone()).unwrap();
    assert_ne!(live.request_sha256, cold.request_sha256);
    save(home, &mut cold, JobPhase::Ready, "ready_disabled").unwrap();
    mark_cancel(home, &cold).unwrap();
    assert!(cancelled(home, &cold).unwrap());
    assert!(cancelled(home, &live).is_err());
    let mut changed = cold.clone();
    changed.source_disabled = false;
    assert!(changed.validate().is_err());
    changed.request_sha256 = changed.bound_hash().unwrap();
    assert!(save(home, &mut changed, JobPhase::Ready, "ready").is_err());
    assert!(get(home, "cold-mode").unwrap().unwrap().source_disabled);
    assert!(!home.join("config.toml").exists());
}

#[test]
fn initial_job_has_no_source_id_and_cannot_claim_rollback_or_an_existing_data_generation() {
    let live = job("initial-mode");
    let first = SwitchJob::new_initial(live.request.clone()).unwrap();
    assert!(first.is_initial());
    assert!(first.source_runtime_id.is_empty());
    assert!(first.source_disabled);
    assert_eq!(first.operation(), "select");
    assert_ne!(first.request_sha256, live.request_sha256);
    let encoded = serde_json::to_value(&first).unwrap();
    assert_eq!(encoded["source_runtime_id"], "");
    serde_json::from_value::<SwitchJob>(encoded)
        .unwrap()
        .validate()
        .unwrap();
    assert!(SwitchJob::new(live.request.clone(), String::new()).is_err());
    assert!(SwitchJob::new_disabled(live.request.clone(), String::new()).is_err());
    let mut invalid = first.clone();
    invalid.source_disabled = false;
    assert!(invalid.validate().is_err());
    let mut invalid = first;
    invalid.prepared_data_generation = Some("8".repeat(64));
    assert!(invalid.validate().is_err());
    let reverse = SwitchRequest {
        rollback: true,
        ..live.request
    };
    assert!(SwitchJob::new_initial(reverse).is_err());
}
