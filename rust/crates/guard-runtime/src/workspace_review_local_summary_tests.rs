use super::*;

fn summary(fixture: &Fixture) -> Result<Value, String> {
    let request = json!({"operation":"workspace_review_local_summary",
        "request":{"request_id":"business-test"}});
    let response = crate::resident_ops::evaluate_resident_bytes(
        &canonical_json_bytes(&request).unwrap(),
        Some(&fixture.store),
    )?;
    serde_json::from_slice(&response).map_err(|_| "test_invalid_summary_response".into())
}

#[test]
fn resident_summary_omits_private_values_and_asserts_no_current_account_or_effect() {
    let fixture = Fixture::new("business-local-summary");
    let value = input(b"LOCAL_BODY_CANARY", &[b"LOCAL_ATTACHMENT_CANARY".to_vec()]);
    fixture.stage(&value);
    let response = summary(&fixture).unwrap();
    assert_eq!(response["service"], "google_gmail");
    assert_eq!(response["operation"], "mail_send");
    assert_eq!(response["recipient_count"], 1);
    assert_eq!(response["attachment_count"], 1);
    assert_eq!(response["account_currentness"], "not_asserted");
    assert_eq!(response["execution_state"], "not_checked");
    let encoded = response.to_string();
    for private in [
        "LOCAL_BODY_CANARY",
        "LOCAL_ATTACHMENT_CANARY",
        "example.test",
    ] {
        assert!(!encoded.contains(private));
    }
    for name in [
        "primary_base64",
        "attachments_base64",
        "account_binding",
        "tenant_binding",
        "recipients",
        "resource_binding",
        "revision_binding",
    ] {
        assert!(response.get(name).is_none());
    }
    assert!(fixture.load().is_ok());
    assert!(!fixture
        .root
        .join("workspace-review-business-attempts")
        .exists());
}

#[test]
fn changed_private_snapshot_refuses_summary_instead_of_exporting_unverified_facts() {
    let fixture = Fixture::new("business-local-summary-tamper");
    let value = input(b"ORIGINAL_LOCAL_BODY", &[]);
    fixture.stage(&value);
    assert!(summary(&fixture).is_ok());
    let mut changed = value.clone();
    changed["facts"]["volume"]["recipient_count"] = json!(200);
    write(&fixture.root, &fixture.input_path(&value), &changed);
    assert!(summary(&fixture).is_err());
}

#[test]
fn summary_does_not_acquire_transition_write_lock_and_rejects_caller_supplied_facts() {
    let fixture = Fixture::new("business-local-summary-fence");
    fixture.stage(&input(b"LOCAL_BODY", &[]));
    let result =
        super::super::super::approval_enrollment::with_transition_lock(&fixture.root, || {
            Ok(summary(&fixture))
        })
        .unwrap();
    assert!(result.is_ok());
    let forged = json!({"operation":"workspace_review_local_summary",
        "request":{"request_id":"business-test","recipient_count":0}});
    assert!(crate::resident_ops::evaluate_resident_bytes(
        &canonical_json_bytes(&forged).unwrap(),
        Some(&fixture.store)
    )
    .is_err());
}

#[test]
fn generic_pending_request_has_a_finite_unavailable_summary_error() {
    let root = super::super::super::tests::test_root("business-summary-generic");
    let key = super::super::super::tests::install_test_key(&root, 71);
    let store = super::super::super::PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = super::super::super::tests::signed_snapshot(1, &key, &root);
    store
        .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot}))
        .unwrap();
    let directory = root.join("workspace-review-requests");
    crate::resident_state::ensure_private_directory(&directory, true).unwrap();
    write(
        &root,
        &directory.join("generic-request.json"),
        &json!({
            "schema":"guard-native-workspace-review-request.v1","version":1,
            "request_id":"generic-request","status":"pending",
            "action":{},"intent":{},"revision":{},"policy":{}
        }),
    );
    let operation = json!({"operation":"workspace_review_local_summary",
        "request":{"request_id":"generic-request"}});
    let error = crate::resident_ops::evaluate_resident_bytes(
        &canonical_json_bytes(&operation).unwrap(),
        Some(&store),
    )
    .unwrap_err();
    assert_eq!(error, "native_local_business_summary_unavailable");
    let response: Value = serde_json::from_slice(&crate::resident_protocol::safe_error_response(
        &error, false,
    ))
    .unwrap();
    assert_eq!(
        response["error"],
        "native_local_business_summary_unavailable"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn policy_change_during_summary_loading_refuses_the_stale_projection() {
    let fixture = Fixture::new("business-local-summary-policy-change");
    fixture.stage(&input(b"LOCAL_POLICY_BOUND_BODY", &[]));
    let mut updated = fixture.snapshot.clone();
    updated.generation += 1;
    updated.policy_digest = policy_digest(&updated).unwrap();
    updated.integrity.mac = integrity_mac(&updated, &fixture.key).unwrap();
    let result =
        super::super::super::workspace_review_local_summary::build_with_policy_change_test_hook(
            &fixture.store,
            "business-test",
            || {
                fixture
                    .store
                    .push(&json!({"schema":"guard-policy-snapshot-push.v1", "snapshot":updated}))
                    .unwrap();
            },
        );
    assert_eq!(
        result.unwrap_err(),
        "native_local_business_summary_unavailable"
    );
}
