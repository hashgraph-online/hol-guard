use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn root() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "guard-claim-index-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    crate::resident_state::ensure_private_directory(&path, true).unwrap()
}

fn claim(index: usize) -> WorkspaceReviewClaimV1 {
    WorkspaceReviewClaimV1 {
        claim_id: format!("{index:064x}"),
        envelope_digest: format!("{:064x}", index + 1),
        semantic_decision_digest: Some(format!("{:064x}", index + 2)),
        legacy_semantic_recovered: false,
        expires_at_ms: Some(1),
    }
}

#[test]
fn permanent_index_preserves_both_key_purposes_beyond_the_legacy_limit() {
    let base = root();
    let mut digest = None;
    for index in 0..1100 {
        digest = Some(insert_claim(&base, digest.as_deref(), &claim(index)).unwrap());
    }
    sync_directories_before_commit(&base).unwrap();
    let anchor = ClaimIndexAnchor {
        root: digest.unwrap(),
        claim_count: 1100,
    };
    for index in [0, 512, 1023, 1099] {
        let expected = claim(index);
        assert_eq!(
            find_claim(&base, &anchor, &expected.claim_id).unwrap(),
            Some(expected.clone())
        );
        assert_eq!(
            find_semantic(
                &base,
                &anchor,
                expected.semantic_decision_digest.as_ref().unwrap()
            )
            .unwrap(),
            Some(expected)
        );
    }
    assert_eq!(
        find_claim(&base, &anchor, &claim(1101).claim_id).unwrap(),
        None
    );
    assert!(insert_claim(&base, Some(&anchor.root), &claim(0)).is_err());
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn uncommitted_nodes_do_not_change_an_existing_anchor() {
    let base = root();
    let first = insert_claim(&base, None, &claim(1)).unwrap();
    let old = ClaimIndexAnchor {
        root: first,
        claim_count: 1,
    };
    let next = insert_claim(&base, Some(&old.root), &claim(2)).unwrap();
    assert_eq!(find_claim(&base, &old, &claim(2).claim_id).unwrap(), None);
    assert_eq!(
        find_claim(&base, &old, &claim(1).claim_id).unwrap(),
        Some(claim(1))
    );
    let committed = ClaimIndexAnchor {
        root: next,
        claim_count: 2,
    };
    assert_eq!(
        find_claim(&base, &committed, &claim(2).claim_id).unwrap(),
        Some(claim(2))
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn malformed_parent_edge_is_not_an_absent_claim() {
    let base = root();
    let expected = claim(1);
    let wanted = key("claim", &expected.claim_id);
    let wrong_edge = if wanted.starts_with('0') { "1" } else { "0" };
    let malformed_leaf = write_node(
        &base,
        &Node::Leaf {
            key: key("claim", &claim(2).claim_id),
            claim: claim(2),
        },
    )
    .unwrap();
    let root_digest = write_node(
        &base,
        &Node::Branch {
            prefix: wanted[..1].to_owned(),
            children: BTreeMap::from([
                (wanted[1..2].to_owned(), malformed_leaf.clone()),
                (wrong_edge.to_owned(), malformed_leaf),
            ]),
        },
    )
    .unwrap();
    let anchor = ClaimIndexAnchor {
        root: root_digest,
        claim_count: 1,
    };
    assert_eq!(
        find_claim(&base, &anchor, &expected.claim_id).unwrap_err(),
        INVALID
    );
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn altered_missing_and_rolled_back_nodes_never_become_absent_claims() {
    let base = root();
    let old_root = insert_claim(&base, None, &claim(1)).unwrap();
    let new_root = insert_claim(&base, Some(&old_root), &claim(2)).unwrap();
    let anchor = ClaimIndexAnchor {
        root: new_root.clone(),
        claim_count: 2,
    };
    let (old_path, _) = node_path(&base, &old_root, false).unwrap();
    let (path, _) = node_path(&base, &new_root, false).unwrap();
    let original = fs::read(&path).unwrap();
    for replacement in [b"{}".to_vec(), fs::read(old_path).unwrap()] {
        fs::write(&path, replacement).unwrap();
        assert!(find_claim(&base, &anchor, &claim(2).claim_id).is_err());
    }
    fs::write(&path, original).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(find_claim(&base, &anchor, &claim(2).claim_id).is_err());
    fs::remove_dir_all(base).unwrap();
}

#[cfg(unix)]
#[test]
fn index_rejects_symlinked_storage() {
    let base = root();
    let other = root();
    std::os::unix::fs::symlink(&other, base.join("workspace-review-claims")).unwrap();
    assert!(insert_claim(&base, None, &claim(1)).is_err());
    fs::remove_dir_all(base).unwrap();
    fs::remove_dir_all(other).unwrap();
}
