//! The operation owns the transition lock even if a descriptor is duplicated.

use super::*;

#[test]
fn operation_release_is_not_extended_by_a_duplicate_descriptor() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "guard-transition-descriptor-{}-{suffix}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = transition_lock_path(&root).unwrap();
    let opened = open_transition_lock(&path).unwrap();
    validate_transition_lock(&path, &opened.file).unwrap();
    fs2::FileExt::try_lock_exclusive(&opened.file).unwrap();
    // A concurrent fork can retain the same open file description until exec.
    // Duplication models that lifetime without timing, processes, or a wait.
    let duplicate = opened.file.try_clone().unwrap();
    let owner = TransitionLock { _file: opened.file };

    assert_eq!(
        with_transition_lock(&root, || Ok::<(), String>(())).unwrap_err(),
        "native_approval_authority_busy"
    );
    drop(owner);
    with_transition_lock(&root, || Ok::<(), String>(())).unwrap();

    // Keep the duplicate alive until after the next operation was admitted.
    drop(duplicate);
    std::fs::remove_dir_all(root).unwrap();
}
