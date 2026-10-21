use super::*;
use std::io::Write;

#[test]
fn context_loading_obeys_the_authority_transition_fence() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "guard-context-fence-{}-{suffix}",
        std::process::id()
    ));
    let root = crate::resident_state::ensure_private_directory(&root, true).unwrap();
    let mut key =
        crate::resident_state::private_file(&root.join("policy-verifier.key"), false, &root)
            .unwrap();
    key.write_all(&[23u8; 32]).unwrap();
    drop(key);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let result = super::super::approval_enrollment::with_transition_lock(&root, || {
        Ok(build_context(&store, "request-1"))
    })
    .unwrap();
    assert_eq!(result.unwrap_err(), "native_approval_authority_busy");
    assert_ne!(
        build_context(&store, "request-1").unwrap_err(),
        "native_approval_authority_busy"
    );
    std::fs::remove_dir_all(root).unwrap();
}
