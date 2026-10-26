use super::{evaluate_resident_bytes, safe_error_response};
use guard_contracts::NATIVE_APPROVAL_MAX_BYTES;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn policy_store() -> (crate::policy_store::PolicySnapshotStore, PathBuf) {
    let suffix = crate::unique_nanos::unique_nanos();
    let root = std::env::temp_dir().join(format!(
        "hol-guard-resident-enrollment-test-{}-{suffix}",
        std::process::id()
    ));
    #[cfg(windows)]
    let root = crate::resident_state::ensure_private_directory(&root, true).unwrap();
    #[cfg(not(windows))]
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key_path = root.join("policy-verifier.key");
    #[cfg(windows)]
    {
        use std::io::Write;
        let mut file = crate::resident_state::private_file(&key_path, false, &root).unwrap();
        file.write_all(&[23u8; 32]).unwrap();
    }
    #[cfg(not(windows))]
    fs::write(&key_path, [23u8; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = crate::policy_store::PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    (store, root)
}

#[test]
fn approval_error_transport_is_finite() {
    let known: Value =
        serde_json::from_slice(&safe_error_response("native_approval_replay", false))
            .expect("known approval error is JSON");
    assert_eq!(known["error"], "native_approval_replay");

    let unknown: Value = serde_json::from_slice(&safe_error_response(
        "native_approval_future_unregistered_code",
        false,
    ))
    .expect("redacted approval error is JSON");
    assert_eq!(unknown["error"], "native_request_invalid_json");

    let lifecycle: Value = serde_json::from_slice(&safe_error_response(
        "native_resident_start_in_progress",
        true,
    ))
    .expect("known lifecycle error is JSON");
    assert_eq!(lifecycle["error"], "native_resident_start_in_progress");

    let unsupported: Value = serde_json::from_slice(&safe_error_response(
        "native_request_schema_unsupported",
        false,
    ))
    .expect("schema-unsupported error is JSON");
    assert_eq!(unsupported["error"], "native_request_schema_unsupported");

    let lifecycle_event: Value =
        serde_json::from_slice(&safe_error_response("native_hook_event_unsupported", false))
            .expect("unsupported hook event error is JSON");
    assert_eq!(lifecycle_event["error"], "native_hook_event_unsupported");

    for code in [
        "native_resident_future_unregistered_code",
        "native_policy_snapshot_future_unregistered_code",
    ] {
        let redacted: Value = serde_json::from_slice(&safe_error_response(code, false))
            .expect("redacted error is JSON");
        assert_eq!(redacted["error"], "native_request_invalid_json");
    }
    for code in [
        "native_business_policy_floor_invalid",
        "native_business_policy_removal_requires_authority",
        "native_business_source_authority_missing",
        "native_business_source_authority_invalid",
        "native_business_source_authority_not_current",
        "native_business_source_mutation_in_progress",
        "native_business_source_enforce_required",
    ] {
        let response: Value = serde_json::from_slice(&safe_error_response(code, false)).unwrap();
        assert_eq!(response["error"], code);
        assert_eq!(response["retryable"], false);
    }
    let unknown_business: Value = serde_json::from_slice(&safe_error_response(
        "native_business_policy_future_unregistered_code",
        false,
    ))
    .unwrap();
    assert_eq!(unknown_business["error"], "native_request_invalid_json");
}

#[test]
fn approval_requests_have_a_smaller_raw_payload_bound() {
    let padding = "x".repeat(NATIVE_APPROVAL_MAX_BYTES);
    let request =
        format!(r#"{{"operation":"approval_challenge","request":{{"padding":"{padding}"}}}}"#);
    assert_eq!(
        evaluate_resident_bytes(request.as_bytes(), None).unwrap_err(),
        "native_approval_request_bounds_exceeded"
    );
}

#[test]
fn resident_workspace_enrollment_requires_canonical_absolute_candidate() {
    let (store, root) = policy_store();
    let relative = br#"{"operation":"workspace_review_authority_enroll","request":{"record_path":"relative.json"}}"#;
    assert_eq!(
        evaluate_resident_bytes(relative, Some(&store)).unwrap_err(),
        "native_workspace_review_authority_invalid"
    );
    let noncanonical = br#"{"request":{"record_path":"relative.json"},"operation":"workspace_review_authority_enroll"}"#;
    assert_eq!(
        evaluate_resident_bytes(noncanonical, Some(&store)).unwrap_err(),
        "native_workspace_review_decision_noncanonical"
    );
    let absent = serde_json::json!({
        "operation": "workspace_review_authority_enroll",
        "request": {"record_path": root.join("absent.json").to_string_lossy()},
    });
    let canonical = guard_policy_snapshot::canonical_json_bytes(&absent).unwrap();
    assert_eq!(
        evaluate_resident_bytes(&canonical, Some(&store)).unwrap_err(),
        "native_workspace_review_authority_missing"
    );
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn prompt_capability_is_portable_and_containment_matches_dispatch() {
    let features = super::capabilities().features;
    assert!(features
        .iter()
        .any(|feature| feature == guard_contracts::PROMPT_ANALYZE_FEATURE));
    assert!(features
        .iter()
        .any(|feature| feature == guard_contracts::DATA_FLOW_ANALYZE_FEATURE));
    assert_eq!(
        features
            .iter()
            .any(|feature| feature == guard_contracts::CONTAINED_EXECUTION_FEATURE),
        cfg!(unix)
    );
    assert_eq!(
        features
            .iter()
            .any(|feature| feature == "codex-binding-capture-v1"),
        cfg!(unix)
    );
    assert!(features
        .iter()
        .any(|feature| feature == "claude-hook-bridge-v1"));
    assert!(features
        .iter()
        .any(|feature| feature == "claude-session-start-v1"));
    assert!(features
        .iter()
        .any(|feature| feature == "codex-hook-bridge-v1"));
    assert!(features
        .iter()
        .any(|feature| feature == "bounded-hook-bridge-v1"));
    assert!(features
        .iter()
        .any(|feature| feature == "cursor-hook-bridge-v1"));
}

#[test]
fn command_admission_failures_reach_the_publisher_unchanged() {
    // A publisher that cannot tell which admission check rejected its binding
    // has nothing to recover from: every push looks like a malformed request,
    // so the resident keeps no policy and every prompt fails closed. Each
    // admission failure must therefore survive the safe-error transport as
    // itself.
    // Read the declared vocabulary rather than a hand-picked subset. A list
    // written out here only ever covers the codes someone remembered to add,
    // so a newly declared code could be dropped from the transport and no test
    // would notice.
    assert!(!guard_contracts::NATIVE_COMMAND_CONTROL_ERROR_CODES.is_empty());
    for &code in guard_contracts::NATIVE_COMMAND_CONTROL_ERROR_CODES {
        let response: Value = serde_json::from_slice(&safe_error_response(code, false))
            .expect("admission error is JSON");
        assert_eq!(
            response["error"], code,
            "{code} was rewritten by the transport"
        );
        assert_eq!(response["retryable"], false);
    }
}
