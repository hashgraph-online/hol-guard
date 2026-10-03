#[cfg(windows)]
#[test]
fn managed_owner_lock_allows_overlapping_private_directory_binds() {
    use crate::managed_resident::acquire_managed_owner_lock;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    let home = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-bind-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
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
