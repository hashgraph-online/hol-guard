//! Recovery progress is not a sealed selection or runtime authority.
use super::*;
use std::os::unix::fs::PermissionsExt;
fn fixture() -> (tempfile::TempDir, Owner, SwitchJob) {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let owner = Owner::acquire(dir.path()).unwrap();
    let mut job = SwitchJob::new_initial(SwitchRequest {
        job_id: "initial".into(),
        target_runtime_id: "target".into(),
        expected_generation: 5,
        rollback: false,
    })
    .unwrap();
    save(
        dir.path(),
        &mut job,
        JobPhase::RecoveryRequired,
        "recovery_required",
    )
    .unwrap();
    (dir, owner, job)
}
#[test]
fn explicit_recovery_renews_only_its_budget_and_cancellation_identity() {
    let (dir, _owner, original) = fixture();
    mark_cancel(dir.path(), &original).unwrap();
    assert!(cancelled(dir.path(), &original).unwrap());
    let mut first = begin(dir.path(), &original, 7).unwrap();
    assert_eq!(first.operation(), "recover");
    assert_eq!(first.request, original.request);
    assert_eq!(first.request_sha256, original.request_sha256);
    assert_eq!(first.deadline_at_ms, original.deadline_at_ms);
    let attempt = first.recovery.as_ref().unwrap().clone();
    assert_eq!(attempt.deadline_at_ms - attempt.started_at_ms, 120_000);
    assert_eq!(attempt.expected_generation, 7);
    assert!(!cancelled(dir.path(), &first).unwrap());
    mark_cancel(dir.path(), &first).unwrap();
    assert!(cancelled(dir.path(), &first).unwrap());
    save(
        dir.path(),
        &mut first,
        JobPhase::RecoveryRequired,
        "cancelled_verification",
    )
    .unwrap();
    let second = begin(dir.path(), &first, 8).unwrap();
    assert_ne!(second.recovery.as_ref().unwrap().id, attempt.id);
    assert_eq!(second.recovery.as_ref().unwrap().expected_generation, 8);
    assert!(!cancelled(dir.path(), &second).unwrap());
    mark_cancel(dir.path(), &first).unwrap();
    assert!(
        !cancelled(dir.path(), &second).unwrap(),
        "a stale cancel cannot cancel another attempt"
    );
    mark_cancel(dir.path(), &second).unwrap();
    assert!(cancelled(dir.path(), &second).unwrap());
    assert!(!dir.path().join("config.toml").exists());
    assert!(!dir.path().join("cigar-lifecycle.json").exists());
    assert!(!dir.path().join("context-assistance/installations").exists());
}
#[test]
fn stale_or_forged_progress_cannot_rearm_or_extend_a_live_attempt() {
    let (dir, _owner, original) = fixture();
    let active = begin(dir.path(), &original, 7).unwrap();
    assert!(begin(dir.path(), &original, 8).is_err());
    let mut changed = active.clone();
    changed.recovery.as_mut().unwrap().id = "a".repeat(32);
    assert!(save(
        dir.path(),
        &mut changed,
        JobPhase::PreparingRecovery,
        "changed"
    )
    .is_err());
    changed = active.clone();
    changed.recovery.as_mut().unwrap().deadline_at_ms += 1;
    assert!(changed.validate().is_err());
    let mut regular = SwitchJob::new(original.request.clone(), "source".into()).unwrap();
    regular.created_at_ms = active.created_at_ms;
    regular.deadline_at_ms = active.deadline_at_ms;
    regular.updated_at_ms = active.updated_at_ms;
    regular.recovery = active.recovery.clone();
    // A bounded progress nonce is valid for a stopped former live switch,
    // but cannot replace a different persisted request or authorize recovery.
    regular.validate().unwrap();
    assert!(save(
        dir.path(),
        &mut regular,
        JobPhase::PreparingRecovery,
        "forged"
    )
    .is_err());
    assert_eq!(get(dir.path(), "initial").unwrap().unwrap(), active);
}

#[test]
fn public_recovery_metadata_preserves_generations_beyond_javascript_integer_precision() {
    let generation = 9_007_199_254_740_993;
    let attempt = RecoveryAttempt {
        id: "a".repeat(32),
        expected_generation: generation,
        started_at_ms: 1,
        deadline_at_ms: 120_001,
    };
    assert_eq!(
        attempt.describe()["expected_generation"],
        generation.to_string()
    );
    assert_eq!(
        serde_json::to_value(&attempt).unwrap()["expected_generation"].as_u64(),
        Some(generation)
    );
}
