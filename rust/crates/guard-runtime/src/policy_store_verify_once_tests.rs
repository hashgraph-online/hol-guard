//! The current snapshot is verified once per snapshot and generation floor;
//! later requests re-check only its expiry.

use super::*;
use std::sync::Arc;

fn short_lived_snapshot(generation: u64, key: &[u8], guard_home: &Path) -> PolicySnapshotV3 {
    let mut snapshot = signed_snapshot(generation, key, guard_home);
    snapshot.expires_at_ms = now_ms().unwrap() + 2_000;
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, key).unwrap();
    snapshot
}

#[test]
fn a_verified_snapshot_still_expires_and_a_raised_floor_reverifies_it() {
    let root = test_root("verify-once");
    let key = install_test_key(&root, 11);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    store
        .push(&serde_json::json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": short_lived_snapshot(5, &key, &root),
        }))
        .unwrap();
    let first = store.current_admitted_snapshot().unwrap();
    let second = store.current_admitted_snapshot().unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert!(store.state.lock().unwrap().verified.is_some());

    store.state.lock().unwrap().generation_floor = 6;
    assert_eq!(
        store.current_admitted_snapshot().unwrap_err(),
        "snapshot_generation_downgrade"
    );
    store.state.lock().unwrap().generation_floor = 5;
    assert!(store.current_admitted_snapshot().is_ok());

    std::thread::sleep(std::time::Duration::from_millis(2_100));
    assert_eq!(
        store.current_admitted_snapshot().unwrap_err(),
        "snapshot_expired"
    );
    fs::remove_dir_all(root).unwrap();
}
