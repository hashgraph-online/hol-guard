use super::*;

#[test]
fn signed_expression_association_is_durable_and_cannot_be_removed_or_changed_under_old_mac() {
    let root = test_root("v4-expression-durable");
    let key = install_test_key(&root, 37);
    let mut candidate = snapshot_v4(4, &key, &root);
    let mut authority = serde_json::to_value(&candidate.scoped_authority).unwrap();
    authority["command_expressions"] = serde_json::json!([{
        "decision_id":1,"expression":{"combinator":"all","conditions":[{
            "field":"command","operator":"startsWith","value":"printf","caseSensitive":true
        }]}
    }]);
    candidate.scoped_authority = serde_json::from_value(authority.clone()).unwrap();
    sign(&mut candidate, &key);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let ack: PolicySnapshotAckV2 =
        serde_json::from_slice(&store.push(&push_value(&candidate)).unwrap()).unwrap();
    assert_eq!(ack.policy_digest, candidate.policy_digest);
    assert_eq!(ack.source_input_digest, candidate.source_input_digest);
    for removed in [false, true] {
        let mut changed = authority.clone();
        if removed {
            changed
                .as_object_mut()
                .unwrap()
                .remove("command_expressions");
        } else {
            changed["command_expressions"][0]["expression"]["conditions"][0]["value"] =
                "echo".into();
        }
        let mut tampered = candidate.clone();
        tampered.scoped_authority = serde_json::from_value(changed).unwrap();
        assert!(store.push(&push_value(&tampered)).is_err());
        assert_eq!(store.current_generation(), Some(4));
    }
    drop(store);
    let reopened = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let loaded = reopened
        .validate_versioned_request_snapshot(&reference(&candidate), root.to_str().unwrap(), 4)
        .unwrap();
    assert_eq!(
        serde_json::to_value(loaded.as_ref()).unwrap(),
        serde_json::to_value(&candidate).unwrap()
    );
    assert!(reopened.current_snapshot().is_err());
    fs::remove_dir_all(root).unwrap();
}
