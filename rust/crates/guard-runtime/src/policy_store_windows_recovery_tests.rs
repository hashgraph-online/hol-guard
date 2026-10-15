use super::*;
use std::io::Write;

fn test_root(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-policy-recovery-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    crate::resident_state::ensure_private_directory(&root, true).unwrap();
    root
}

fn private_bytes(path: &Path, bytes: &[u8]) {
    let private_root = path.parent().unwrap_or(path);
    let mut file = crate::resident_state::private_file(path, true, private_root).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn authority_recovery_replaces_only_valid_private_backup() {
    let root = test_root("backup");
    let target = root.join("policy-snapshot-v3.json");
    let backup = root.join(".policy-snapshot-v3.json.previous");
    private_bytes(&backup, b"previous");

    recover_authority_replacement(&target).unwrap();

    assert!(crate::resident_state::open_private_read(
        &target,
        AUTHORITY_RECORD_MAX_BYTES,
        "authority",
        &root,
    )
    .unwrap()
    .is_some());
    assert!(crate::resident_state::open_private_read(
        &backup,
        AUTHORITY_RECORD_MAX_BYTES,
        "authority",
        &root,
    )
    .unwrap()
    .is_none());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn authority_replace_succeeds_while_a_reader_holds_the_target() {
    let root = test_root("replace-reader");
    let target = root.join("policy-snapshot-v3.json");
    let temporary = root.join(".policy-snapshot-v3.json.tmp");
    private_bytes(&target, b"before");
    private_bytes(&temporary, b"after-replace");
    let reader = std::fs::File::open(&target).unwrap();
    crate::resident_state::replace_windows_private_file(&temporary, &target, &root).unwrap();
    drop(reader);
    assert_eq!(std::fs::read(&target).unwrap(), b"after-replace");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn authority_recovery_rejects_non_file_backup() {
    let root = test_root("reparse-or-directory");
    let target = root.join("policy-snapshot-v3.json");
    let backup = root.join(".policy-snapshot-v3.json.previous");
    crate::resident_state::ensure_private_directory(&backup, true).unwrap();

    assert_eq!(
        recover_authority_replacement(&target).unwrap_err(),
        "native_policy_snapshot_authority_recovery_failed"
    );
    std::fs::remove_dir_all(root).unwrap();
}
