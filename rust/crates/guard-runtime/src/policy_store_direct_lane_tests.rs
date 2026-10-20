use super::super::tests::{
    install_test_key, policy_with_default, signed_snapshot, signed_snapshot_with_policy, test_root,
};
use super::{now_ms, PolicySnapshotStore};
use super::{
    observe_input, DirectLaneDefer, DIRECT_LANE_ACK_DIRECTORY, DIRECT_LANE_ACK_FILE_NAME,
    DIRECT_LANE_ACK_MAX_LEASE_MS, DIRECT_LANE_ACK_SCHEMA,
};
use guard_policy_snapshot::{PolicySnapshotV3, POLICY_SNAPSHOT_PUSH_SCHEMA};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::Ordering;

pub(crate) struct Fixture {
    pub(crate) root: std::path::PathBuf,
    pub(crate) store: PolicySnapshotStore,
    pub(crate) snapshot: PolicySnapshotV3,
    pub(crate) input: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub(crate) fn fixture(label: &str) -> Fixture {
    open_fixture(label, false)
}

/// Same fixture with an allow default, so a native allow is not raised to warn.
pub(crate) fn allowing_fixture(label: &str) -> Fixture {
    open_fixture(label, true)
}

fn open_fixture(label: &str, allow_default: bool) -> Fixture {
    let root = test_root(&format!("direct-lane-{label}"));
    let key = install_test_key(&root, 9);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = if allow_default {
        signed_snapshot_with_policy(1, &key, &root, policy_with_default("allow"))
    } else {
        signed_snapshot(1, &key, &root)
    };
    let input = root.join("config.toml");
    fs::write(&input, b"mode = \"enforce\"\n").unwrap();
    Fixture {
        root,
        store,
        snapshot,
        input,
    }
}

pub(crate) fn binding(fixture: &Fixture, workspace: &str) -> Value {
    let absent = fixture.root.join("absent.toml");
    json!({
        "workspaces": [workspace],
        "inputs": [
            {"path": fixture.input.to_str().unwrap(), "stat": observe_input(fixture.input.to_str().unwrap())},
            {"path": absent.to_str().unwrap(), "stat": null},
        ],
    })
}

pub(crate) fn push(fixture: &Fixture, direct_lane: Option<Value>) -> Result<Vec<u8>, String> {
    let mut request = json!({
        "schema": POLICY_SNAPSHOT_PUSH_SCHEMA,
        "snapshot": fixture.snapshot,
    });
    if let Some(direct_lane) = direct_lane {
        request["direct_lane"] = direct_lane;
    }
    fixture.store.push(&request)
}

fn write_ack(
    root: &Path,
    generation: u64,
    policy_digest: &str,
    lease_expires_at_ms: u64,
    mode: u32,
) {
    let directory = root.join(DIRECT_LANE_ACK_DIRECTORY);
    fs::create_dir_all(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.join(DIRECT_LANE_ACK_FILE_NAME);
    let _ = fs::remove_file(&path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&path)
        .unwrap();
    let body = json!({
        "schema": DIRECT_LANE_ACK_SCHEMA,
        "generation": generation,
        "policy_digest": policy_digest,
        "lease_expires_at_ms": lease_expires_at_ms,
    });
    file.write_all(&serde_json::to_vec(&body).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

pub(crate) fn write_current_ack(fixture: &Fixture) {
    write_ack(
        &fixture.root,
        fixture.snapshot.generation,
        &fixture.snapshot.policy_digest,
        // The longest lease the store admits, so a stalled CI runner cannot
        // expire it mid-test; expiry has its own tests with explicit leases.
        now_ms().unwrap() + DIRECT_LANE_ACK_MAX_LEASE_MS,
        0o600,
    );
}

#[test]
fn bound_snapshot_is_admitted_while_ack_and_inputs_hold() {
    let fixture = fixture("admit");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::AckMissing)
    );
    write_current_ack(&fixture);
    let admitted = fixture.store.admit_direct_lane("/work/repo").unwrap();
    assert_eq!(admitted.generation, fixture.snapshot.generation);
    assert_eq!(
        fixture.store.admit_direct_lane("/work/other").err(),
        Some(DirectLaneDefer::WorkspaceUnknown)
    );
}

#[test]
fn withdrawn_or_stale_ack_defers() {
    let fixture = fixture("ack");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    let digest = fixture.snapshot.policy_digest.clone();
    let wrong_digest = "0".repeat(64);
    let now = now_ms().unwrap();
    for (generation, digest, lease, mode, expected) in [
        (
            1,
            digest.as_str(),
            now.saturating_sub(1),
            0o600,
            DirectLaneDefer::AckExpired,
        ),
        (
            2,
            digest.as_str(),
            now + 30_000,
            0o600,
            DirectLaneDefer::AckMismatch,
        ),
        (
            1,
            wrong_digest.as_str(),
            now + 30_000,
            0o600,
            DirectLaneDefer::AckMismatch,
        ),
        (
            1,
            digest.as_str(),
            now + 600_000,
            0o600,
            DirectLaneDefer::AckMismatch,
        ),
        (
            1,
            digest.as_str(),
            now + 30_000,
            0o644,
            DirectLaneDefer::AckMismatch,
        ),
    ] {
        write_ack(&fixture.root, generation, digest, lease, mode);
        assert_eq!(
            fixture.store.admit_direct_lane("/work/repo").err(),
            Some(expected)
        );
    }
    let directory = fixture.root.join(DIRECT_LANE_ACK_DIRECTORY);
    write_current_ack(&fixture);
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::AckMismatch)
    );
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(directory.join(DIRECT_LANE_ACK_FILE_NAME)).unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::AckMissing)
    );
    fs::remove_dir(&directory).unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::AckMissing)
    );
}

/// Write the current ACK beside the live one, then move it into place, as
/// the publisher does.
fn replace_with_current_ack(root: &Path, policy_digest: &str) {
    replace_with_current_ack_until(root, policy_digest, now_ms().unwrap() + 30_000);
}

fn replace_with_current_ack_until(root: &Path, policy_digest: &str, lease_expires_at_ms: u64) {
    let staging = root.join("staging");
    write_ack(&staging, 1, policy_digest, lease_expires_at_ms, 0o600);
    fs::rename(
        staging
            .join(DIRECT_LANE_ACK_DIRECTORY)
            .join(DIRECT_LANE_ACK_FILE_NAME),
        root.join(DIRECT_LANE_ACK_DIRECTORY)
            .join(DIRECT_LANE_ACK_FILE_NAME),
    )
    .unwrap();
}

/// Let this store's hook wait far longer than the shipped budget for the ACK a
/// scoped thread is about to write. The shipped 100 ms covers one publisher
/// write on a healthy host; a loaded CI runner can take longer to schedule the
/// writing thread, and the hook would then read the stale ACK it started with.
fn widen_settle_budget(fixture: &Fixture) {
    fixture
        .store
        .direct_lane_ack_wait
        .settle_override_ms
        .store(10_000, Ordering::Release);
}

/// Returns once a hook has claimed the settle wait for `generation`, so the
/// ACK lands while that hook is polling rather than racing its start. Gives up
/// after ten seconds so a regression fails the test instead of hanging it.
fn await_settle_wait(claimed: &std::sync::atomic::AtomicU64, generation: u64) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while claimed.load(Ordering::Acquire) < generation && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
}

#[test]
fn an_ack_behind_the_bound_snapshot_is_awaited_briefly() {
    let fixture = fixture("ack-settle");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    let digest = fixture.snapshot.policy_digest.clone();
    let lease = now_ms().unwrap() + 30_000;
    write_ack(&fixture.root, 0, &digest, lease, 0o600);
    widen_settle_budget(&fixture);
    let claimed = &fixture.store.direct_lane_ack_wait.claimed;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            await_settle_wait(claimed, 1);
            replace_with_current_ack(&fixture.root, &digest);
        });
        assert!(fixture.store.admit_direct_lane("/work/repo").is_ok());
    });
    assert_eq!(
        fixture
            .store
            .direct_lane_ack_wait
            .claimed
            .load(Ordering::Acquire),
        1
    );
}

#[test]
fn a_bounded_hook_admission_never_settles_past_its_deadline() {
    let fixture = fixture("ack-settle-bounded");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    let digest = fixture.snapshot.policy_digest.clone();
    write_ack(&fixture.root, 0, &digest, now_ms().unwrap() + 30_000, 0o600);
    // The store would wait ten seconds for the ACK to catch up, and the ACK
    // never does. A caller whose own budget is spent gets the stale read back
    // at once, and leaves the generation's wait for a hook that can afford it.
    widen_settle_budget(&fixture);
    let started = std::time::Instant::now();
    let defer = fixture
        .store
        .admit_direct_hook_or_subdirectory_by("/work/repo", started)
        .err();
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(defer, Some(DirectLaneDefer::AckMismatch));
    assert_eq!(
        fixture
            .store
            .direct_lane_ack_wait
            .claimed
            .load(Ordering::Acquire),
        0
    );
    // A caller that still has a little budget waits on the generation, and
    // waits no longer than the budget it arrived with.
    let started = std::time::Instant::now();
    let deadline = started + std::time::Duration::from_millis(50);
    let defer = fixture
        .store
        .admit_direct_hook_or_subdirectory_by("/work/repo", deadline)
        .err();
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(defer, Some(DirectLaneDefer::AckMismatch));
    assert_eq!(
        fixture
            .store
            .direct_lane_ack_wait
            .claimed
            .load(Ordering::Acquire),
        1
    );
}

#[test]
fn an_ack_that_expires_during_the_wait_is_expired() {
    let fixture = fixture("ack-settle-expired");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    let digest = fixture.snapshot.policy_digest.clone();
    write_ack(&fixture.root, 0, &digest, now_ms().unwrap() + 30_000, 0o600);
    widen_settle_budget(&fixture);
    let claimed = &fixture.store.direct_lane_ack_wait.claimed;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            await_settle_wait(claimed, 1);
            // Already past when the waiting hook reads it.
            let lease = now_ms().unwrap().saturating_sub(1);
            replace_with_current_ack_until(&fixture.root, &digest, lease);
        });
        assert_eq!(
            fixture.store.admit_direct_lane("/work/repo").err(),
            Some(DirectLaneDefer::AckExpired)
        );
    });
}

#[test]
fn an_older_ack_the_publisher_stopped_renewing_is_not_awaited() {
    let fixture = fixture("ack-dead");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    let digest = fixture.snapshot.policy_digest.clone();
    write_ack(&fixture.root, 0, &digest, now_ms().unwrap() - 1, 0o600);
    let started = std::time::Instant::now();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::AckMismatch)
    );
    assert!(started.elapsed() < std::time::Duration::from_millis(100));
    assert_eq!(
        fixture
            .store
            .direct_lane_ack_wait
            .claimed
            .load(Ordering::Acquire),
        0
    );
}

#[test]
fn an_ack_that_never_catches_up_delays_only_one_hook() {
    let fixture = fixture("ack-stuck");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    let digest = fixture.snapshot.policy_digest.clone();
    write_ack(&fixture.root, 0, &digest, now_ms().unwrap() + 30_000, 0o600);
    let started = std::time::Instant::now();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::AckMismatch)
    );
    assert!(started.elapsed() >= std::time::Duration::from_millis(100));
    assert_eq!(
        fixture
            .store
            .direct_lane_ack_wait
            .claimed
            .load(Ordering::Acquire),
        1
    );
    // The wait is claimed for this generation, so later hooks defer at once.
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::AckMismatch)
    );
    replace_with_current_ack(&fixture.root, &digest);
    assert!(fixture.store.admit_direct_lane("/work/repo").is_ok());
}

#[test]
fn changed_or_created_input_defers() {
    let fixture = fixture("inputs");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    write_current_ack(&fixture);
    assert!(fixture.store.admit_direct_lane("/work/repo").is_ok());
    fs::write(fixture.root.join("absent.toml"), b"x = 1\n").unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::InputChanged)
    );
    fs::remove_file(fixture.root.join("absent.toml")).unwrap();
    assert!(fixture.store.admit_direct_lane("/work/repo").is_ok());
    fs::write(&fixture.input, b"mode = \"observe\"\n").unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::InputChanged)
    );
}

#[test]
fn idempotent_push_rebinds_and_unbound_push_closes_the_lane() {
    let fixture = fixture("rebind");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    write_current_ack(&fixture);
    fs::write(&fixture.input, b"mode = \"enforce\" # touched\n").unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::InputChanged)
    );
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    assert!(fixture.store.admit_direct_lane("/work/repo").is_ok());
    push(&fixture, None).unwrap();
    assert_eq!(
        fixture.store.admit_direct_lane("/work/repo").err(),
        Some(DirectLaneDefer::Unbound)
    );
}

#[test]
fn malformed_binding_rejects_the_push_without_installing_it() {
    let fixture = fixture("malformed");
    for direct_lane in [
        json!({"workspaces": ["relative/repo"], "inputs": []}),
        json!({"workspaces": ["/a", "/a"], "inputs": []}),
        json!({"workspaces": [], "inputs": [{"path": "/a", "stat": null}, {"path": "/a", "stat": null}]}),
        json!({"workspaces": [], "inputs": [], "extra": true}),
        json!({"workspaces": [], "inputs": [{"path": "/a", "stat": {"mtime_ns": 1, "size": 1, "ino": 1}}]}),
        json!({"workspaces": [], "inputs": [], "integrity_key_b64": "Bwc"}),
        json!({"workspaces": [], "inputs": [], "integrity_key_id": "synthetic:1"}),
        json!({"workspaces": [], "inputs": [], "integrity_key_b64": "Bw+c", "integrity_key_id": "synthetic:1"}),
        json!({"workspaces": [], "inputs": [], "integrity_key_b64": "", "integrity_key_id": "synthetic:1"}),
        json!({"workspaces": [], "inputs": [], "integrity_key_b64": "Bwc", "integrity_key_id": ""}),
        json!({"workspaces": [], "inputs": [], "integrity_key_b64": "Bwc", "integrity_key_id": "a\nb"}),
        json!({"workspaces": [], "inputs": [], "integrity_key_b64": "A".repeat(2049), "integrity_key_id": "synthetic:1"}),
        json!({"workspaces": [], "inputs": [], "integrity_key_b64": "Bwc", "integrity_key_id": "k".repeat(257)}),
    ] {
        assert!(push(&fixture, Some(direct_lane)).is_err());
        assert_eq!(fixture.store.current_generation(), None);
    }
    assert_eq!(
        fixture.store.admit_direct_lane("/a").err(),
        Some(DirectLaneDefer::Unbound)
    );
}

#[test]
fn defer_reasons_name_the_daemon_path() {
    assert_eq!(DirectLaneDefer::Unbound.code(), "direct_lane_unbound");
    assert_eq!(
        DirectLaneDefer::SnapshotUnavailable.code(),
        "direct_lane_snapshot_unavailable"
    );
    assert_eq!(
        DirectLaneDefer::AckMissing.code(),
        "direct_lane_ack_missing"
    );
    assert_eq!(
        DirectLaneDefer::AckMismatch.code(),
        "direct_lane_ack_mismatch"
    );
    assert_eq!(
        DirectLaneDefer::AckExpired.code(),
        "direct_lane_ack_expired"
    );
    assert_eq!(
        DirectLaneDefer::WorkspaceUnknown.code(),
        "direct_lane_workspace_unknown"
    );
    assert_eq!(
        DirectLaneDefer::InputChanged.code(),
        "direct_lane_input_changed"
    );
}

#[test]
fn the_bound_integrity_key_is_admitted_only_with_a_current_ack() {
    let fixture = fixture("integrity-key");
    let mut bound = binding(&fixture, "/work/repo");
    bound["integrity_key_b64"] = json!("BwcHBw");
    bound["integrity_key_id"] = json!("synthetic:07070707");
    push(&fixture, Some(bound)).unwrap();
    assert_eq!(
        fixture.store.admit_direct_binding().err(),
        Some(DirectLaneDefer::AckMissing)
    );
    write_current_ack(&fixture);
    let admitted = fixture.store.admit_direct_binding().unwrap();
    let key = admitted.integrity_key.as_ref().unwrap();
    assert_eq!(key.key.as_slice(), &[7, 7, 7, 7]);
    assert_eq!(key.key_id, "synthetic:07070707");

    // A binding without the key still admits; the hooks that need it defer.
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    write_current_ack(&fixture);
    assert!(fixture
        .store
        .admit_direct_binding()
        .unwrap()
        .integrity_key
        .is_none());
}

#[test]
fn review_facts_bind_when_present_and_read_as_absent_otherwise() {
    let fixture = fixture("review-facts");
    push(&fixture, Some(binding(&fixture, "/work/repo"))).unwrap();
    write_current_ack(&fixture);
    let review = fixture.store.admit_direct_binding().unwrap().review.clone();
    assert_eq!(review, super::DirectLaneReviewFacts::default());

    let mut bound = binding(&fixture, "/work/repo");
    bound["blocked_request_mode"] = json!("ask");
    bound["approval_center_origin"] = json!("http://[::1]:4781");
    bound["review_oauth_source"] = json!("default");
    bound["review_host_cwd"] = json!("/work/repo");
    push(&fixture, Some(bound.clone())).unwrap();
    let review = fixture.store.admit_direct_binding().unwrap().review.clone();
    assert_eq!(review.blocked_request_mode.as_deref(), Some("ask"));
    assert_eq!(
        review.approval_center_origin.as_deref(),
        Some("http://[::1]:4781")
    );
    assert_eq!(review.review_oauth_source.as_deref(), Some("default"));
    assert_eq!(review.review_host_cwd.as_deref(), Some("/work/repo"));

    // A fact the resident cannot accept costs only that fact, never the lane.
    bound["approval_center_origin"] = json!("http://192.168.1.10:4781");
    bound["blocked_request_mode"] = json!("prompt");
    push(&fixture, Some(bound)).unwrap();
    assert!(fixture.store.admit_direct_lane("/work/repo").is_ok());
    let review = fixture.store.admit_direct_binding().unwrap().review.clone();
    assert_eq!(review.approval_center_origin, None);
    assert_eq!(review.blocked_request_mode, None);
    assert_eq!(review.review_oauth_source.as_deref(), Some("default"));
}
