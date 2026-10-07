#[cfg(unix)]
use super::*;

#[cfg(unix)]
#[test]
fn managed_owner_lock_is_exclusive_for_resident_lifetime() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-lock-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

    let first = acquire_managed_owner_lock(&root).unwrap();
    assert!(matches!(
        acquire_managed_owner_lock(&root),
        Err(error) if error == "native_resident_owner_busy"
    ));
    let marker = root.join(MANAGED_OWNER_LOCK_FILE_NAME);
    let displaced = root.join("managed-resident-owner.v1.lock.displaced");
    fs::rename(&marker, &displaced).unwrap();
    fs::write(&marker, []).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        acquire_managed_owner_lock(&root),
        Err(error) if error == "native_resident_owner_busy"
    ));
    drop(first);
    let second = acquire_managed_owner_lock(&root).unwrap();
    drop(second);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn managed_owner_barrier_allows_authority_load_in_same_process() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-authority-load-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let key_path = root.join("policy-verifier.key");
    fs::write(&key_path, [7u8; 32]).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

    let owner = acquire_managed_owner_lock(&root).unwrap();
    let loaded = crate::policy_store::PolicySnapshotStore::new(&root, &"a".repeat(64));
    assert!(loaded.is_ok(), "authority load failed: {:?}", loaded.err());
    drop(owner);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn managed_owner_lock_rejects_second_process() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    if let Some(root) = std::env::var_os("HOL_GUARD_OWNER_LOCK_CHILD") {
        let root = PathBuf::from(root);
        let _lock = acquire_managed_owner_lock(&root).unwrap();
        fs::write(root.join("child-ready"), []).unwrap();
        std::thread::sleep(Duration::from_secs(5));
        return;
    }

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-lock-process-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = root.join("child-ready");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("managed_owner_lock_rejects_second_process")
        .arg("--nocapture")
        .env(
            "HOL_GUARD_OWNER_LOCK_CHILD",
            root.to_string_lossy().as_ref(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut child_ready = false;
    for _ in 0..200 {
        if marker.exists() {
            child_ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let result = if child_ready {
        acquire_managed_owner_lock(&root)
    } else {
        Err("child_not_ready".to_owned())
    };
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&root);

    assert!(child_ready, "child process did not acquire the owner lock");
    assert!(matches!(
        result,
        Err(error) if error == "native_resident_owner_busy"
    ));
}

#[path = "managed_resident_owner_lock_windows_tests.rs"]
mod owner_lock_windows_tests;
