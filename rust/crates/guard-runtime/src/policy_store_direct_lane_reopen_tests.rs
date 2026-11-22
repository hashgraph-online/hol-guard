use super::super::super::tests::{install_test_key, signed_snapshot};
use super::super::tests::{binding, fixture, push, write_ack, Fixture};
use super::super::{
    now_ms, DIRECT_LANE_ACK_DIRECTORY, DIRECT_LANE_ACK_FILE_NAME, DIRECT_LANE_ACK_MAX_LEASE_MS,
};
use super::StructuredLaneView;
use guard_policy_snapshot::POLICY_SNAPSHOT_PUSH_SCHEMA;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn ack_path(fixture: &Fixture) -> PathBuf {
    fixture
        .root
        .join(DIRECT_LANE_ACK_DIRECTORY)
        .join(DIRECT_LANE_ACK_FILE_NAME)
}

fn ack(fixture: &Fixture, generation: u64, digest: &str) {
    write_ack(
        &fixture.root,
        generation,
        digest,
        now_ms().unwrap() + DIRECT_LANE_ACK_MAX_LEASE_MS,
        0o600,
    );
}

fn bound_fixture(label: &str, view: &Value) -> Fixture {
    let fixture = fixture(label);
    let mut lane = binding(&fixture, "/work/repo");
    lane["structured_output_config"] = view.clone();
    push(&fixture, Some(lane)).unwrap();
    fixture
}

fn await_view(
    fixture: &Fixture,
    generation: u64,
    digest: &str,
    wait: Duration,
) -> (Option<StructuredLaneView>, Duration) {
    let started = Instant::now();
    let view = fixture
        .store
        .structured_output_binding_awaiting(generation, digest, started + wait);
    (view, started.elapsed())
}

#[test]
fn a_lane_that_never_opened_is_not_awaited() {
    let view = json!({"managed_policy_status": "absent"});
    let fixture = bound_fixture("reopen-never-opened", &view);
    let generation = fixture.snapshot.generation;
    let digest = fixture.snapshot.policy_digest.clone();

    // Bound but never acknowledged, so no hook was admitted: nothing marks
    // this as a lane that will come back.
    let (awaited, elapsed) = await_view(&fixture, generation, &digest, Duration::from_secs(4));
    assert_eq!(awaited, None);
    assert!(elapsed < Duration::from_secs(1));
}

#[test]
fn a_routed_post_tool_use_waits_for_a_same_generation_reopen() {
    let view = json!({"managed_policy_status": "absent"});
    let fixture = bound_fixture("reopen-same-generation", &view);
    let generation = fixture.snapshot.generation;
    let digest = fixture.snapshot.policy_digest.clone();
    ack(&fixture, generation, &digest);
    let deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(
        fixture
            .store
            .structured_output_binding(generation, &digest, Some(deadline)),
        Some(Some(view.clone()))
    );

    // The daemon closes the lane; a plain read is unavailable.
    fs::remove_file(ack_path(&fixture)).unwrap();
    assert_eq!(
        fixture
            .store
            .structured_output_binding(generation, &digest, Some(deadline)),
        None
    );

    let reopen = {
        let root = fixture.root.clone();
        let digest = digest.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            write_ack(
                &root,
                generation,
                &digest,
                now_ms().unwrap() + DIRECT_LANE_ACK_MAX_LEASE_MS,
                0o600,
            );
        })
    };
    let (awaited, _) = await_view(&fixture, generation, &digest, Duration::from_secs(4));
    reopen.join().unwrap();
    assert_eq!(
        awaited,
        Some(StructuredLaneView {
            generation,
            policy_digest: digest.clone(),
            view: Some(view),
        })
    );

    // A lane that stays closed is still unavailable once the wait ends.
    fs::remove_file(ack_path(&fixture)).unwrap();
    let (closed, elapsed) = await_view(&fixture, generation, &digest, Duration::from_millis(60));
    assert_eq!(closed, None);
    assert!(elapsed >= Duration::from_millis(60));
}

#[test]
fn a_routed_post_tool_use_takes_the_view_a_republish_acknowledged() {
    let view = json!({"managed_policy_status": "absent"});
    let fixture = bound_fixture("reopen-newer-generation", &view);
    let generation = fixture.snapshot.generation;
    let digest = fixture.snapshot.policy_digest.clone();
    ack(&fixture, generation, &digest);
    let deadline = Instant::now() + Duration::from_secs(5);
    assert!(fixture
        .store
        .structured_output_binding(generation, &digest, Some(deadline))
        .is_some());
    fs::remove_file(ack_path(&fixture)).unwrap();

    // The republish lands at the next generation, as the daemon's rebind
    // does, and is acknowledged while the routed hook waits.
    let key = install_test_key(&fixture.root, 9);
    let next = signed_snapshot(generation + 1, &key, &fixture.root);
    let next_digest = next.policy_digest.clone();
    let mut lane = binding(&fixture, "/work/repo");
    let next_view = json!({"managed_policy_status": "absent", "republished": true});
    lane["structured_output_config"] = next_view.clone();
    let request = json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": next,
        "direct_lane": lane,
    });
    let republish = {
        let root = fixture.root.clone();
        let next_digest = next_digest.clone();
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                fixture.store.push(&request).unwrap();
                write_ack(
                    &root,
                    generation + 1,
                    &next_digest,
                    now_ms().unwrap() + DIRECT_LANE_ACK_MAX_LEASE_MS,
                    0o600,
                );
            });
            let awaited = await_view(&fixture, generation, &digest, Duration::from_secs(4)).0;
            handle.join().unwrap();
            awaited
        })
    };
    assert_eq!(
        republish,
        Some(StructuredLaneView {
            generation: generation + 1,
            policy_digest: next_digest,
            view: Some(next_view),
        })
    );
}

#[test]
fn a_rebind_that_is_never_acknowledged_is_not_awaited() {
    let view = json!({"managed_policy_status": "absent"});
    let fixture = bound_fixture("reopen-never-acknowledged", &view);
    let generation = fixture.snapshot.generation;
    let digest = fixture.snapshot.policy_digest.clone();
    ack(&fixture, generation, &digest);
    let deadline = Instant::now() + Duration::from_secs(5);
    assert!(fixture
        .store
        .structured_output_binding(generation, &digest, Some(deadline))
        .is_some());
    fs::remove_file(ack_path(&fixture)).unwrap();

    // The daemon binds the next generation and never acknowledges it. The
    // lane admitted a hook at the old generation only, so a hook routed at
    // the new one has nothing to wait for.
    let key = install_test_key(&fixture.root, 9);
    let next = signed_snapshot(generation + 1, &key, &fixture.root);
    let next_digest = next.policy_digest.clone();
    let mut lane = binding(&fixture, "/work/repo");
    lane["structured_output_config"] = view;
    fixture
        .store
        .push(&json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": next,
            "direct_lane": lane,
        }))
        .unwrap();
    let (awaited, elapsed) = await_view(
        &fixture,
        generation + 1,
        &next_digest,
        Duration::from_secs(4),
    );
    assert_eq!(awaited, None);
    assert!(elapsed < Duration::from_secs(1));
}

#[test]
fn a_republish_refused_for_a_changed_input_keeps_the_hook_waiting() {
    let view = json!({"managed_policy_status": "absent"});
    let fixture = bound_fixture("reopen-changed-input", &view);
    let generation = fixture.snapshot.generation;
    let digest = fixture.snapshot.policy_digest.clone();
    ack(&fixture, generation, &digest);
    let deadline = Instant::now() + Duration::from_secs(5);
    assert!(fixture
        .store
        .structured_output_binding(generation, &digest, Some(deadline))
        .is_some());
    fs::remove_file(ack_path(&fixture)).unwrap();

    // The next generation is bound and acknowledged, but an input it names
    // has moved since, so it admits nothing. The lane that last admitted a
    // hook is still the old one, and the routed hook keeps waiting for a
    // valid republish rather than giving up at once.
    let key = install_test_key(&fixture.root, 9);
    let next = signed_snapshot(generation + 1, &key, &fixture.root);
    let next_digest = next.policy_digest.clone();
    let mut lane = binding(&fixture, "/work/repo");
    lane["structured_output_config"] = view;
    fixture
        .store
        .push(&json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": next,
            "direct_lane": lane,
        }))
        .unwrap();
    ack(&fixture, generation + 1, &next_digest);
    fs::write(&fixture.input, b"moved since the binding").unwrap();

    let (awaited, elapsed) = await_view(&fixture, generation, &digest, Duration::from_millis(200));
    assert_eq!(awaited, None);
    assert!(elapsed >= Duration::from_millis(200));
    assert!(fixture
        .store
        .direct_lane_was_admitted_at(generation, &digest));
}

#[test]
fn an_older_binding_never_replaces_a_newer_admission() {
    let view = json!({"managed_policy_status": "absent"});
    let fixture = bound_fixture("reopen-stale-admission", &view);
    let generation = fixture.snapshot.generation;
    let digest = fixture.snapshot.policy_digest.clone();
    let older = fixture.store.direct_lane.lock().unwrap().clone().unwrap();

    let key = install_test_key(&fixture.root, 9);
    let next = signed_snapshot(generation + 1, &key, &fixture.root);
    let next_digest = next.policy_digest.clone();
    let mut lane = binding(&fixture, "/work/repo");
    lane["structured_output_config"] = view;
    fixture
        .store
        .push(&json!({
            "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
            "snapshot": next,
            "direct_lane": lane,
        }))
        .unwrap();
    ack(&fixture, generation + 1, &next_digest);
    let deadline = Instant::now() + Duration::from_secs(5);
    assert!(fixture
        .store
        .structured_output_binding(generation + 1, &next_digest, Some(deadline))
        .is_some());

    // A hook that passed its checks against the older binding records late,
    // after the republish: the newer admission stands.
    fixture.store.note_direct_lane_admitted(&older);
    assert!(fixture
        .store
        .direct_lane_was_admitted_at(generation + 1, &next_digest));
    assert!(!fixture
        .store
        .direct_lane_was_admitted_at(generation, &digest));
}
