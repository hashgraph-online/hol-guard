use super::*;
use crate::policy_store::tests::{install_test_key, signed_snapshot, test_root};
use guard_contracts::{GuardHookSourceMetadataV2, GUARD_HOOK_ENVELOPE_V2_SCHEMA};
use guard_policy_snapshot::POLICY_SNAPSHOT_PUSH_SCHEMA;
use serde_json::json;
use std::sync::{mpsc, Barrier};
use std::time::Duration;

#[test]
fn launch_fence_holds_policy_push_until_dispatch_or_abort() {
    let root = test_root("launch-policy-fence");
    let key = install_test_key(&root, 37);
    let store = Arc::new(PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap());
    let first = signed_snapshot(1, &key, &root);
    store
        .push(&json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":first}))
        .unwrap();
    let envelope = GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.into(),
        request_id: Some("fence-test".into()),
        harness: "omp".into(),
        event: "PreToolUse".into(),
        raw_payload: json!({}),
        deadline_budget_ms: Some(1000),
        policy_generation: 1,
        policy_snapshot: serde_json::to_value(&first).unwrap(),
        source: GuardHookSourceMetadataV2 {
            cwd: Some(root.to_string_lossy().into_owned()),
            home_dir: root.to_string_lossy().into_owned(),
            guard_home: root.to_string_lossy().into_owned(),
            source_ref_external_allowed: false,
            execution_environment: None,
        },
        recording_only: false,
    };
    let fence = store.fence_for_launch(&envelope).unwrap();
    assert_eq!(fence.snapshot().generation, 1);
    let second = signed_snapshot(2, &key, &root);
    let barrier = Arc::new(Barrier::new(2));
    let (sender, receiver) = mpsc::channel();
    let worker_store = store.clone();
    let worker_barrier = barrier.clone();
    let worker = std::thread::spawn(move || {
        worker_barrier.wait();
        sender
            .send(
                worker_store.push(&json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":second})),
            )
            .unwrap();
    });
    barrier.wait();
    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(fence);
    receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
    assert_eq!(store.current_generation(), Some(2));
    assert!(
        matches!(store.fence_for_launch(&envelope), Err(reason) if reason == "native_policy_snapshot_not_current")
    );
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
