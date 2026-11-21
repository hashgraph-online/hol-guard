//! Filesystem/MAC/erasure tests only; no actual SDK qualification is inferred.
use super::*;
use guard_cigar_release::{SelectionData, SelectionInstallation, SelectionOrigin};
use std::os::unix::fs::PermissionsExt;

pub(super) fn home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
pub(super) fn intent() -> InitialSelection {
    InitialSelection {
        schema: "guard-cigar-initial-selection.v1".into(),
        revision: 1,
        request_id: "first".into(),
        expected_service_generation: 1,
        before_settings_sha256: "4".repeat(64),
        after_settings_sha256: "5".repeat(64),
        empty_data_sha256: "6".repeat(64),
        phase: InitialPhase::Prepared,
        target: SelectionPointer {
            runtime: SelectionInstallation {
                installation_id: "first-sdk".into(),
                installation_sha256: "1".repeat(64),
                approval_sha256: "2".repeat(64),
                producer_sha256: "3".repeat(64),
                origin: SelectionOrigin::Enrolled {
                    sdk_version: "0.14.1".into(),
                    core_version: "0.14.0".into(),
                    profile_id: "cigar-014".into(),
                    adapter_id: "guard-cigar-python-sdk-v1".into(),
                    adapter_revision: 1,
                },
            },
            data: SelectionData::LegacySaved,
        },
    }
}
fn bytes(home: &Path, record: &InitialSelection, key: &[u8; 32]) -> Vec<u8> {
    let payload = serde_json::to_string(record).unwrap();
    let mac = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        &message(home, &payload).unwrap(),
    );
    serde_json::to_vec(&Envelope {
        schema: "guard-cigar-sealed-initial-selection.v1".into(),
        payload,
        mac: hex::encode(mac.as_ref()),
    })
    .unwrap()
}
fn publish(home: &Path, record: &InitialSelection) {
    let home = home.canonicalize().unwrap();
    let lock = WriteLock::acquire(&home).unwrap();
    lock.publish_lifecycle(LifecycleFile::Key, None, &[57u8; 32])
        .unwrap();
    lock.publish_lifecycle(
        LifecycleFile::InitialSelection,
        None,
        &bytes(&home, record, &[57u8; 32]),
    )
    .unwrap();
}
#[test]
fn pending_initial_intent_blocks_startup_and_regular_initialization_without_creating_a_previous_sdk(
) {
    let dir = home();
    publish(dir.path(), &intent());
    let mut owner = Owner::acquire(dir.path()).unwrap();
    assert!(owner.record().is_none());
    assert!(owner
        .check_initial_clear()
        .unwrap_err()
        .ends_with("initial_selection_recovery_required"));
    assert!(owner.initialize(intent().target).is_err());
    assert!(owner
        .prepare_for(&jobs::SwitchRequest {
            job_id: "another".into(),
            target_runtime_id: "different".into(),
            expected_generation: 1,
            rollback: false
        })
        .is_err());
    assert!(owner.record().is_none());
    assert!(!dir.path().join("cigar-lifecycle.json").exists());
    assert!(!dir.path().join("config.toml").exists());
}
#[test]
fn cancelled_intent_is_inert_but_completed_intent_cannot_hide_a_missing_selected_record() {
    let a = home();
    let cancelled = intent().advance(InitialPhase::Cancelled).unwrap();
    publish(a.path(), &cancelled);
    let owner = Owner::acquire(a.path()).unwrap();
    owner.check_initial_clear().unwrap();
    assert!(owner.record().is_none());
    drop(owner);
    let b = home();
    let mut completed = intent();
    for p in [
        InitialPhase::CommitIntent,
        InitialPhase::Committed,
        InitialPhase::Healthy,
        InitialPhase::Completed,
    ] {
        completed = completed.advance(p).unwrap();
    }
    publish(b.path(), &completed);
    let owner = Owner::acquire(b.path()).unwrap();
    assert!(owner.check_initial_clear().is_err());
}
#[test]
fn initial_intent_mac_binds_profile_key_schema_and_every_target_field() {
    let a = home();
    let b = home();
    let record = intent();
    let raw = bytes(a.path(), &record, &[57u8; 32]);
    assert_eq!(decode(a.path(), &raw, Some(&[57u8; 32])).unwrap(), record);
    assert!(decode(b.path(), &raw, Some(&[57u8; 32])).is_err());
    assert!(decode(a.path(), &raw, Some(&[58u8; 32])).is_err());
    assert!(decode(a.path(), &raw, None).is_err());
    let mut value: Value = serde_json::from_slice(&raw).unwrap();
    let mut payload: Value = serde_json::from_str(value["payload"].as_str().unwrap()).unwrap();
    payload["target"]["runtime"]["installation_id"] = json!("substituted");
    value["payload"] = json!(payload.to_string());
    assert!(decode(
        a.path(),
        &serde_json::to_vec(&value).unwrap(),
        Some(&[57u8; 32])
    )
    .is_err());
    value["schema"] = json!("guard-cigar-sealed-selection.v2");
    assert!(decode(
        a.path(),
        &serde_json::to_vec(&value).unwrap(),
        Some(&[57u8; 32])
    )
    .is_err());
}
#[test]
fn stale_initial_metadata_is_detected_before_an_existing_selection_write() {
    let dir = home();
    publish(
        dir.path(),
        &intent().advance(InitialPhase::Cancelled).unwrap(),
    );
    let mut owner = Owner::acquire(dir.path()).unwrap();
    let lock = WriteLock::acquire(dir.path()).unwrap();
    let old = lock
        .lifecycle_bytes(LifecycleFile::InitialSelection)
        .unwrap()
        .unwrap();
    let mut changed = owner.initial_record().unwrap().clone();
    changed.revision += 1;
    lock.publish_lifecycle(
        LifecycleFile::InitialSelection,
        Some(&old),
        &bytes(&owner.home, &changed, &[57u8; 32]),
    )
    .unwrap();
    drop(lock);
    assert!(owner.initialize(intent().target).is_err());
    assert!(!dir.path().join("cigar-lifecycle.json").exists());
    owner.reload().unwrap();
    assert_eq!(owner.initial_record().unwrap().revision, changed.revision);
}
#[test]
fn full_saved_erasure_clears_initial_intent_before_its_key_and_never_restores_a_scope() {
    let dir = home();
    publish(dir.path(), &intent());
    DataRemoval::acquire(dir.path()).unwrap().remove().unwrap();
    for p in [
        "cigar-initial-selection.json",
        "cigar-lifecycle.key",
        "cigar-lifecycle.json",
        "cigar-scopes.json",
        "cigar-erasure.json",
    ] {
        assert!(!dir.path().join(p).exists(), "{p}");
    }
    let owner = Owner::acquire(dir.path()).unwrap();
    owner.check_initial_clear().unwrap();
    assert!(owner.initial_record().is_none());
    assert!(owner.record().is_none());
}
