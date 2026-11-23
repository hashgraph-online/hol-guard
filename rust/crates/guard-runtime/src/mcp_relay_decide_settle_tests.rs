//! When a queued approval row may be written.

use std::io::Write;

use serde_json::json;

use super::*;
use crate::hook_direct_evidence::MAX_RECORD_BYTES;

#[test]
fn missing_approval_center_uses_the_loopback_default() {
    assert_eq!(
        approval_center_origin("/missing-guard-home", None),
        "http://127.0.0.1:4781"
    );
    assert_eq!(
        approval_center_origin("/missing-guard-home", Some("http://127.0.0.1:9876")),
        "http://127.0.0.1:9876"
    );
}

/// A full evidence queue refuses before the approval row is written, so no
/// pending request is left that neither a receipt nor an answer names.
#[test]
fn no_row_is_queued_without_room_for_its_receipt() {
    let suffix = crate::unique_nanos::unique_nanos();
    let root = std::env::temp_dir().join(format!(
        "guard-relay-settle-{}-{suffix}",
        std::process::id()
    ));
    let root = crate::resident_state::ensure_private_directory(&root, true).unwrap();
    let mut key =
        crate::resident_state::private_file(&root.join("policy-verifier.key"), false, &root)
            .unwrap();
    key.write_all(&[29u8; 32]).unwrap();
    drop(key);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(room_for_row(&store), Ok(()));
    let large = "x".repeat(MAX_RECORD_BYTES - 64);
    while store.direct_evidence().has_headroom() {
        assert!(store
            .direct_evidence()
            .offer(json!({ "payload": large.clone() })));
    }
    assert_eq!(room_for_row(&store), Err(EVIDENCE_FULL));
    std::fs::remove_dir_all(root).unwrap();
}
