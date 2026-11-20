//! Real process exits exercise filesystem state without running an SDK.
use super::*;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
fn home() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
fn pair_lock(d: &tempfile::TempDir) -> WriteLock {
    WriteLock::acquire(d.path()).unwrap()
}
fn tmp_count(d: &tempfile::TempDir) -> usize {
    fs::read_dir(d.path())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".cigar-catalog-state.")
        })
        .count()
}
#[test]
fn publication_is_private_compare_and_swap_and_never_replaces_the_key() {
    let d = home();
    let lock = pair_lock(&d);
    assert!(lock.catalog_pair().unwrap().is_none());
    lock.publish_catalog(None, b"first", &[11; 32]).unwrap();
    let first = lock.catalog_pair().unwrap().unwrap();
    assert_eq!(first.cache(), b"first");
    assert_eq!(first.key(), &[11; 32]);
    for (name, mode) in [
        (NAME, 0o700),
        ("cigar-catalog-state/key", 0o600),
        ("cigar-catalog-state/catalog.json", 0o600),
    ] {
        assert_eq!(
            fs::metadata(d.path().join(name)).unwrap().mode() & 0o777,
            mode
        );
    }
    assert!(!d.path().join("cigar-catalog.key").exists());
    assert!(!d.path().join("cigar-catalog.json").exists());
    lock.publish_catalog(Some(&first), b"second", first.key())
        .unwrap();
    assert!(lock
        .publish_catalog(Some(&first), b"stale", first.key())
        .is_err());
    let second = lock.catalog_pair().unwrap().unwrap();
    assert_eq!(second.cache(), b"second");
    assert!(lock
        .publish_catalog(Some(&second), b"wrong-key", &[12; 32])
        .is_err());
    fs::set_permissions(
        d.path().join(NAME).join(CACHE),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    assert!(lock
        .publish_catalog(Some(&second), b"readonly", second.key())
        .is_err());
    assert_eq!(lock.catalog_pair().unwrap().unwrap().cache(), b"second");
}
#[test]
fn complete_legacy_pairs_keep_their_key_and_partial_or_mixed_layouts_refuse() {
    let d = home();
    let lock = pair_lock(&d);
    lock.publish_lifecycle(lifecycle::LifecycleFile::CatalogKey, None, &[14; 32])
        .unwrap();
    assert!(lock.catalog_pair().is_err());
    assert!(lock.publish_catalog(None, b"reset", &[15; 32]).is_err());
    lock.publish_lifecycle(lifecycle::LifecycleFile::CatalogCache, None, b"legacy")
        .unwrap();
    let legacy = lock.catalog_pair().unwrap().unwrap();
    lock.publish_catalog(Some(&legacy), b"refreshed", legacy.key())
        .unwrap();
    assert!(!d.path().join(NAME).exists());
    assert_eq!(
        fs::read(d.path().join("cigar-catalog.key")).unwrap(),
        [14; 32]
    );
    fs::create_dir(d.path().join(NAME)).unwrap();
    fs::set_permissions(d.path().join(NAME), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(lock.catalog_pair(),Err(Failure::Error(c)) if c=="cigar_catalog_layout_conflict")
    );
    assert_eq!(
        fs::read(d.path().join("cigar-catalog.json")).unwrap(),
        b"refreshed"
    );
}
#[test]
fn incomplete_committed_or_linked_state_is_never_reset_or_followed() {
    let d = home();
    let lock = pair_lock(&d);
    lock.publish_catalog(None, b"known", &[18; 32]).unwrap();
    let key = d.path().join(NAME).join(KEY);
    fs::rename(&key, d.path().join("saved-key")).unwrap();
    assert!(
        matches!(lock.catalog_pair(),Err(Failure::Error(c)) if c=="cigar_catalog_state_incomplete")
    );
    assert!(lock.publish_catalog(None, b"reset", &[19; 32]).is_err());
    assert!(!key.exists());
    symlink(d.path().join("saved-key"), &key).unwrap();
    assert!(lock.catalog_pair().is_err());
    fs::remove_file(&key).unwrap();
    fs::hard_link(d.path().join("saved-key"), &key).unwrap();
    assert!(lock.catalog_pair().is_err());
    assert_eq!(fs::read(d.path().join(NAME).join(CACHE)).unwrap(), b"known");
}
#[test]
fn unknown_or_linked_orphan_children_prevent_cleanup_without_touching_other_files() {
    let d = home();
    let lock = pair_lock(&d);
    let name = format!(".cigar-catalog-state.123.{}.tmp", "a".repeat(32));
    let path = d.path().join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(d.path().join("unrelated"), b"preserved").unwrap();
    symlink(d.path().join("unrelated"), path.join(KEY)).unwrap();
    assert!(lock.publish_catalog(None, b"new", &[21; 32]).is_err());
    assert!(path.join(KEY).is_symlink());
    assert_eq!(fs::read(d.path().join("unrelated")).unwrap(), b"preserved");
    fs::remove_file(path.join(KEY)).unwrap();
    fs::write(path.join("unknown-child"), b"preserved").unwrap();
    assert!(lock.publish_catalog(None, b"new", &[21; 32]).is_err());
    assert!(path.join("unknown-child").exists());
    fs::remove_file(path.join("unknown-child")).unwrap();
    lock.publish_catalog(None, b"new", &[21; 32]).unwrap();
    assert_eq!(tmp_count(&d), 0);
}
fn crash(d: &tempfile::TempDir, point: &str) {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "guard_config_update::io::writer::catalog::tests::crash_child",
            "--ignored",
            "--nocapture",
        ])
        .env("GUARD_CIGAR_CATALOG_IO_TEST_HOME", d.path())
        .env("GUARD_CIGAR_CATALOG_IO_TEST_POINT", point)
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(86),
        "{point}: {} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
fn real_process_loss_during_initialization_exposes_no_pair_or_the_complete_pair() {
    for point in [
        "init_directory",
        "init_key",
        "init_cache",
        "init_synced",
        "init_renamed",
        "init_parent_synced",
    ] {
        let d = home();
        fs::write(d.path().join("unrelated"), b"kept").unwrap();
        crash(&d, point);
        let lock = pair_lock(&d);
        let current = lock.catalog_pair().unwrap();
        let published = matches!(point, "init_renamed" | "init_parent_synced");
        assert_eq!(current.is_some(), published, "{point}");
        if let Some(p) = &current {
            assert_eq!(p.cache(), b"first");
            assert_eq!(p.key(), &[11; 32]);
            assert_eq!(tmp_count(&d), 0);
        } else {
            assert!(!d.path().join(NAME).exists());
            assert_eq!(tmp_count(&d), 1);
        }
        lock.publish_catalog(
            current.as_ref(),
            b"retry",
            current.as_ref().map(|p| p.key()).unwrap_or(&[23; 32]),
        )
        .unwrap();
        assert_eq!(tmp_count(&d), 0);
        assert_eq!(lock.catalog_pair().unwrap().unwrap().cache(), b"retry");
        assert_eq!(fs::read(d.path().join("unrelated")).unwrap(), b"kept");
    }
}
#[test]
fn real_process_loss_during_updates_preserves_the_key_and_old_or_new_cache() {
    for point in ["update_written", "update_renamed", "update_synced"] {
        let d = home();
        crash(&d, point);
        let lock = pair_lock(&d);
        let current = lock.catalog_pair().unwrap().unwrap();
        assert_eq!(current.key(), &[11; 32]);
        assert_eq!(
            current.cache(),
            if point == "update_written" {
                b"first".as_slice()
            } else {
                b"updated".as_slice()
            }
        );
        lock.publish_catalog(Some(&current), current.cache(), current.key())
            .unwrap();
        assert_eq!(
            lock.catalog_pair().unwrap().unwrap().cache(),
            current.cache()
        );
        assert_eq!(fs::read_dir(d.path().join(NAME)).unwrap().count(), 2);
    }
}
#[test]
fn post_rename_errors_remain_unknown_until_identical_current_bytes_are_confirmed() {
    let d = home();
    let lock = pair_lock(&d);
    fault_next(Fault::Error("init_renamed"));
    assert!(
        matches!(lock.publish_catalog(None,b"first",&[11;32]),Err(Failure::Error(c)) if c=="cigar_catalog_commit_outcome_unknown")
    );
    let current = lock.catalog_pair().unwrap().unwrap();
    lock.publish_catalog(Some(&current), current.cache(), current.key())
        .unwrap();
    fault_next(Fault::Error("update_renamed"));
    assert!(
        matches!(lock.publish_catalog(Some(&current),b"updated",current.key()),Err(Failure::Error(c)) if c=="cigar_catalog_commit_outcome_unknown")
    );
    let updated = lock.catalog_pair().unwrap().unwrap();
    assert_eq!(updated.cache(), b"updated");
    assert_eq!(updated.key(), current.key());
    lock.publish_catalog(Some(&updated), updated.cache(), updated.key())
        .unwrap();
}
#[test]
#[ignore = "internal child of the explicit catalog process-loss tests; requires task-private test inputs"]
fn crash_child() {
    let home = PathBuf::from(std::env::var_os("GUARD_CIGAR_CATALOG_IO_TEST_HOME").unwrap());
    let point = std::env::var("GUARD_CIGAR_CATALOG_IO_TEST_POINT").unwrap();
    let lock = WriteLock::acquire(&home).unwrap();
    if point.starts_with("update_") {
        lock.publish_catalog(None, b"first", &[11; 32]).unwrap();
        let current = lock.catalog_pair().unwrap().unwrap();
        let at = match point.as_str() {
            "update_written" => "update_written",
            "update_renamed" => "update_renamed",
            "update_synced" => "update_synced",
            _ => panic!("unknown point"),
        };
        fault_next(Fault::Crash(at));
        lock.publish_catalog(Some(&current), b"updated", current.key())
            .unwrap();
    } else {
        let at = match point.as_str() {
            "init_directory" => "init_directory",
            "init_key" => "init_key",
            "init_cache" => "init_cache",
            "init_synced" => "init_synced",
            "init_renamed" => "init_renamed",
            "init_parent_synced" => "init_parent_synced",
            _ => panic!("unknown point"),
        };
        fault_next(Fault::Crash(at));
        lock.publish_catalog(None, b"first", &[11; 32]).unwrap();
    }
    panic!("crash checkpoint not reached");
}
