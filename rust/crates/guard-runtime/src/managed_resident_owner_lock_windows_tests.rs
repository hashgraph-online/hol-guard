#[cfg(windows)]
#[test]
fn managed_owner_lock_allows_overlapping_private_directory_binds() {
    use crate::managed_resident::acquire_managed_owner_lock;
    use std::fs;

    let home = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-bind-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir(&home).unwrap();
    let root = home.join("native-runtime");
    fs::create_dir(&root).unwrap();
    let lock = acquire_managed_owner_lock(&root).unwrap();
    crate::resident_state::bind_windows_existing_directory(&root, &home).unwrap();
    crate::resident_state::ensure_private_directory_under(&root.join("child"), &home, true)
        .unwrap();
    drop(lock);
    fs::remove_dir_all(home).unwrap();
}

/// fs2 reports a held Windows lock as ERROR_LOCK_VIOLATION, which std does not
/// map to `WouldBlock`. Clients must still see the owner as busy, not broken.
#[cfg(windows)]
#[test]
fn managed_owner_lock_reports_windows_contention_as_busy() {
    use crate::managed_resident::acquire_managed_owner_lock;
    use std::fs;

    let home = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-busy-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir(&home).unwrap();
    let root = home.join("native-runtime");
    fs::create_dir(&root).unwrap();
    let lock = acquire_managed_owner_lock(&root).unwrap();
    assert!(matches!(
        acquire_managed_owner_lock(&root),
        Err(error) if error == "native_resident_owner_busy"
    ));
    drop(lock);
    drop(acquire_managed_owner_lock(&root).unwrap());
    fs::remove_dir_all(home).unwrap();
}
