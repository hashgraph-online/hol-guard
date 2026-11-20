use super::super::tests::{fixture_directory, fixture_file, test_root};
use super::*;
use serde_json::json;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const KEY: [u8; 32] = [7; 32];

fn home(label: &str) -> PathBuf {
    let root = test_root(&format!("materialize-{label}"));
    let runtime = root.join(RUNTIME_DIRECTORY);
    fixture_directory(&runtime);
    #[cfg(unix)]
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn request(root: &Path) -> Value {
    let now = now_ms().unwrap();
    json!({
        "schema": SCHEMA, "version": 1, "verifier_key": KEY.to_vec(),
        "guard_home": root, "lock_wait_ms": 1000,
        "runtime_identity": "a".repeat(64), "rule_digest": "b".repeat(64),
        "mode": "enforce", "issued_at_ms": now, "expires_at_ms": now + 60_000,
        "scope_contract": {"schema":"guard-native-scope.v1","kind":"guard-home",
            "scope_digest":"c".repeat(64),"workspace_binding":"request-source"},
        "effective_policy": {
            "protection_posture":"protected","security_level":"balanced","default_action":"warn",
            "unknown_publisher_action":"review","changed_hash_action":"require-reapproval",
            "new_network_domain_action":"warn","subprocess_action":"warn","risk_actions":{},
            "harness_risk_actions":{},"harness_actions":{},"publisher_actions":{},"artifact_actions":{},
            "sandbox_analysis":"off","receipt_redaction_level":"full"
        }
    })
}

fn business(mut value: Value) -> Value {
    value["business_policy"] = json!({"schema":"guard.native-business-policy.v1","version":1,
        "defaultAction":"allow","rules":[{"id":"mail.external","action":"block",
        "match":{"schema":"guard.business-policy-match.v1","version":1,
            "services":["google_gmail"],"operations":["mail_send"]}}]});
    value
}

fn materialize(value: &Value) -> Result<Vec<u8>, String> {
    materialize_from_reader(serde_json::to_vec(value).unwrap().as_slice())
}

fn generation_of(bytes: &[u8]) -> u64 {
    serde_json::from_slice::<PolicySnapshotV3>(bytes)
        .unwrap()
        .generation
}

fn state(root: &Path) -> (u64, String) {
    let home = Home {
        runtime: root.join(RUNTIME_DIRECTORY),
        root: root.to_owned(),
    };
    read_generation(&home).unwrap().unwrap()
}

fn plant(path: &Path, bytes: &[u8]) {
    let _ = fs::remove_file(path);
    fixture_file(path, bytes);
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn an_unchanged_policy_reuses_its_retained_generation() {
    let root = home("reuse");
    let value = request(&root);
    let first = materialize(&value).unwrap();
    assert_eq!(generation_of(&first), 1);
    assert_eq!(state(&root).0, 1);
    assert_eq!(materialize(&value).unwrap(), first);
    // Times are not policy identity; a later request still reuses the bytes.
    assert_eq!(materialize(&request(&root)).unwrap(), first);
    assert!(!root.join(RUNTIME_DIRECTORY).join(PENDING_NAME).exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn changed_content_takes_the_next_generation() {
    let root = home("changed");
    let mut value = request(&root);
    materialize(&value).unwrap();
    value["mode"] = json!("observe");
    let second = materialize(&value).unwrap();
    assert_eq!(generation_of(&second), 2);
    let snapshot: PolicySnapshotV3 = serde_json::from_slice(&second).unwrap();
    assert_eq!(state(&root), (2, snapshot.policy_digest));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn renewal_is_strictly_newer_and_a_retry_reuses_the_candidate() {
    let root = home("renew");
    let mut value = request(&root);
    materialize(&value).unwrap();
    value["renew_after_generation"] = json!(1);
    let renewed = materialize(&value).unwrap();
    assert_eq!(generation_of(&renewed), 2);
    assert_eq!(materialize(&value).unwrap(), renewed);
    value["renew_after_generation"] = json!(0);
    assert_eq!(
        materialize(&value).unwrap_err(),
        "native_policy_snapshot_generation_invalid"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_expired_snapshot_is_renewed() {
    let root = home("expired");
    let mut value = request(&root);
    let now = now_ms().unwrap();
    value["issued_at_ms"] = json!(now - 10_000);
    value["expires_at_ms"] = json!(now - 5_000);
    materialize(&value).unwrap();
    let renewed = materialize(&request(&root)).unwrap();
    assert_eq!(generation_of(&renewed), 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_crashed_transaction_is_completed_at_every_boundary() {
    for (label, cache_written, state_written) in [
        ("crash-a", false, false),
        ("crash-b", true, false),
        ("crash-c", true, true),
    ] {
        let root = home(label);
        let runtime = root.join(RUNTIME_DIRECTORY);
        let mut value = request(&root);
        let first = materialize(&value).unwrap();
        let first_state = fs::read(root.join(STATE_NAME)).unwrap();
        value["mode"] = json!("observe");
        let second = materialize(&value).unwrap();
        let second_state = fs::read(root.join(STATE_NAME)).unwrap();
        // The crash left the candidate, and possibly the cache and the
        // generation, before the candidate was dropped.
        plant(&runtime.join(PENDING_NAME), &second);
        plant(
            &runtime.join(CACHE_NAME),
            if cache_written { &second } else { &first },
        );
        plant(
            &root.join(STATE_NAME),
            if state_written {
                &second_state
            } else {
                &first_state
            },
        );
        assert_eq!(materialize(&value).unwrap(), second);
        assert_eq!(state(&root).0, 2);
        assert!(!runtime.join(PENDING_NAME).exists());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn a_candidate_conflicting_with_its_committed_generation_is_refused() {
    let root = home("conflict");
    let runtime = root.join(RUNTIME_DIRECTORY);
    let mut value = request(&root);
    materialize(&value).unwrap();
    let committed = fs::read(root.join(STATE_NAME)).unwrap();
    let cache = fs::read(runtime.join(CACHE_NAME)).unwrap();
    // Another home's generation one, with different content.
    let other = home("conflict-other");
    value["guard_home"] = json!(other);
    value["mode"] = json!("observe");
    let candidate = materialize(&value).unwrap();
    plant(&runtime.join(PENDING_NAME), &candidate);
    plant(&runtime.join(CACHE_NAME), &cache);
    plant(&root.join(STATE_NAME), &committed);
    value["guard_home"] = json!(root);
    assert_eq!(
        materialize(&value).unwrap_err(),
        "native_policy_snapshot_transaction_conflict"
    );
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(other).unwrap();
}

#[test]
fn omitting_a_retained_business_binding_is_not_removal_authority() {
    let root = home("business");
    let value = request(&root);
    materialize(&business(value.clone())).unwrap();
    assert_eq!(
        materialize(&value).unwrap_err(),
        "native_business_policy_removal_requires_authority"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resident_state_without_a_generation_record_is_refused() {
    let root = home("state-missing");
    plant(
        &root.join(RUNTIME_DIRECTORY).join(RESIDENT_STATE_NAMES[1]),
        b"{}",
    );
    assert_eq!(
        materialize(&request(&root)).unwrap_err(),
        "native_policy_snapshot_generation_state_missing"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn retained_state_must_agree_with_the_cache() {
    let root = home("state-agree");
    let value = request(&root);
    materialize(&value).unwrap();
    fs::remove_file(root.join(STATE_NAME)).unwrap();
    assert_eq!(
        materialize(&value).unwrap_err(),
        "native_policy_snapshot_generation_state_invalid"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_committed_generation_is_never_resigned_without_its_cache() {
    let root = home("cache-missing");
    let value = request(&root);
    materialize(&value).unwrap();
    fs::remove_file(root.join(RUNTIME_DIRECTORY).join(CACHE_NAME)).unwrap();
    assert_eq!(
        materialize(&value).unwrap_err(),
        "native_policy_snapshot_cache_missing"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_tampered_cache_is_refused() {
    let root = home("tamper");
    let value = request(&root);
    let bytes = materialize(&value).unwrap();
    let mut snapshot: PolicySnapshotV3 = serde_json::from_slice(&bytes).unwrap();
    let flipped = if snapshot.integrity.mac.starts_with('0') {
        "1"
    } else {
        "0"
    };
    snapshot.integrity.mac.replace_range(0..1, flipped);
    plant(
        &root.join(RUNTIME_DIRECTORY).join(CACHE_NAME),
        &snapshot_bytes(&snapshot).unwrap(),
    );
    assert_eq!(
        materialize(&value).unwrap_err(),
        "native_policy_snapshot_cache_integrity_invalid"
    );
    plant(
        &root.join(RUNTIME_DIRECTORY).join(CACHE_NAME),
        b"{\"schema\":1}",
    );
    assert_eq!(
        materialize(&value).unwrap_err(),
        "native_policy_snapshot_cache_invalid"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_held_lock_times_out() {
    let root = home("lock");
    let mut value = request(&root);
    materialize(&value).unwrap();
    let path = root.join(LOCK_NAME);
    #[cfg(windows)]
    let (holder, _binding) = crate::resident_state::private_lock_file(&path, &root).unwrap();
    #[cfg(not(windows))]
    let holder = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    fs2::FileExt::try_lock_exclusive(&holder).unwrap();
    value["lock_wait_ms"] = json!(30);
    assert_eq!(
        materialize(&value).unwrap_err(),
        "native_policy_snapshot_generation_lock_timeout"
    );
    fs2::FileExt::unlock(&holder).unwrap();
    drop(holder);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_request_sealed_under_another_verifier_key_commits_nothing() {
    let root = home("key-mismatch");
    let key = root
        .join(RUNTIME_DIRECTORY)
        .join(crate::policy_store::VERIFIER_KEY_FILE_NAME);
    plant(&key, &[9; 32]);
    assert_eq!(
        materialize(&business(request(&root))).unwrap_err(),
        "native_policy_verifier_key_mismatch"
    );
    assert!(!root.join(RUNTIME_DIRECTORY).join(CACHE_NAME).exists());
    assert!(!root.join(RUNTIME_DIRECTORY).join(PENDING_NAME).exists());
    assert!(!root.join(STATE_NAME).exists());
    // The home's own key is accepted.
    plant(&key, &KEY);
    materialize(&business(request(&root))).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_unbounded_lock_wait_is_refused() {
    let root = home("lock-wait");
    let mut value = request(&root);
    value["lock_wait_ms"] = json!(u64::MAX);
    assert_eq!(materialize(&value).unwrap_err(), ERROR);
    fs::remove_dir_all(root).unwrap();
}
