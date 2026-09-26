use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

fn test_root() -> std::path::PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hol-guard-approval-enrollment-{}-{suffix}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    crate::resident_state::protect_windows_private_path(&root, true, &root).unwrap();
    root
}

#[test]
fn transition_lock_rejects_concurrent_owner_and_recovers_on_release() {
    let root = test_root();
    let path = transition_lock_path(&root).unwrap();
    #[cfg(unix)]
    let directory = crate::state_directory_lock::acquire(&root).unwrap();
    #[cfg(unix)]
    let opened = open_transition_lock(&path, &directory).unwrap();
    #[cfg(not(unix))]
    let opened = open_transition_lock(&path).unwrap();
    validate_transition_lock(&path, &opened.file).unwrap();
    fs2::FileExt::try_lock_exclusive(&opened.file).unwrap();

    assert_eq!(
        with_transition_lock(&root, || Ok::<(), String>(())).unwrap_err(),
        "native_approval_authority_busy"
    );
    drop(opened);
    with_transition_lock(&root, || Ok::<(), String>(())).unwrap();
}

#[cfg(unix)]
#[test]
fn transition_directory_lock_survives_lock_path_replacement() {
    use std::fs::OpenOptions;

    let root = test_root();
    let path = transition_lock_path(&root).unwrap();
    with_transition_lock(&root, || {
        fs::remove_file(&path).unwrap();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.open(&path).unwrap();
        assert_eq!(
            with_transition_lock(&root, || Ok::<(), String>(())),
            Err("native_approval_authority_busy".to_owned())
        );
        Ok::<(), String>(())
    })
    .unwrap();
    with_transition_lock(&root, || Ok::<(), String>(())).unwrap();
}

#[test]
fn test_enrollment_binding_fixture_round_trips() {
    let root = test_root();
    let device = guard_policy_snapshot::digest_bytes(b"fixture-device");
    let installation = guard_policy_snapshot::digest_bytes(b"fixture-installation");
    write_test_enrollment_bindings(&root, &device, &installation).unwrap();
    let loaded = load_unlocked(&root).unwrap().unwrap();
    assert_eq!(loaded.device_binding, device);
    assert_eq!(loaded.installation_binding, installation);
    fs::remove_dir_all(root).unwrap();
}
