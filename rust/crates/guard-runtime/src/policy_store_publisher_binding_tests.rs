use super::super::tests::{fixture_file, install_test_key, signed_snapshot, test_root};
use super::super::PolicySnapshotStore;
use super::{published_runtime_identity, PUBLISHER_SNAPSHOT_FILE_NAME};
use guard_policy_snapshot::{snapshot_bytes, PolicySnapshotV3};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn publish(root: &Path, bytes: &[u8]) {
    let path = root.join(PUBLISHER_SNAPSHOT_FILE_NAME);
    // Windows fixtures create the file exclusively.
    let _ = fs::remove_file(&path);
    fixture_file(&path, bytes);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn publish_snapshot(root: &Path, snapshot: &PolicySnapshotV3) {
    publish(root, &snapshot_bytes(snapshot).unwrap());
}

#[test]
fn only_an_authenticated_publisher_snapshot_names_its_runtime() {
    let root = test_root("publisher-binding");
    let key = install_test_key(&root, 9);
    // Nothing published yet.
    assert_eq!(published_runtime_identity(&root, &key), None);
    publish(&root, b"not json");
    assert_eq!(published_runtime_identity(&root, &key), None);

    let snapshot = signed_snapshot(1, &key, &root);
    publish_snapshot(&root, &snapshot);
    assert_eq!(
        published_runtime_identity(&root, &key),
        Some("a".repeat(64))
    );

    // A binding changed after signing is not the publisher's.
    let mut tampered = snapshot.clone();
    tampered.runtime_identity = "b".repeat(64);
    publish_snapshot(&root, &tampered);
    assert_eq!(published_runtime_identity(&root, &key), None);

    // Nor is a snapshot signed under another home's key.
    publish_snapshot(&root, &signed_snapshot(1, &[3u8; 32], &root));
    assert_eq!(published_runtime_identity(&root, &key), None);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_store_reads_the_publisher_binding_with_its_own_key() {
    let root = test_root("publisher-store");
    let key = install_test_key(&root, 10);
    let store = PolicySnapshotStore::new(&root, &"b".repeat(64)).unwrap();
    assert_eq!(store.runtime_identity(), "b".repeat(64));
    assert_eq!(store.published_runtime_identity(), None);
    // `signed_snapshot` binds runtime "a", another runtime than the store's.
    publish_snapshot(&root, &signed_snapshot(1, &key, &root));
    assert_eq!(store.published_runtime_identity(), Some("a".repeat(64)));
    // A publisher snapshot that is not private is not read.
    #[cfg(unix)]
    {
        let path = root.join(PUBLISHER_SNAPSHOT_FILE_NAME);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(store.published_runtime_identity(), None);
    }
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
