use super::*;
use crate::managed_resident::currentness::request;
use crate::policy_store::{approval_authority, approval_v4_authority, ClientAuthorityObservation};
use crate::resident_client::ResidentClientError;
use crate::resident_protocol::evaluate_resident_bytes;
use std::time::{Duration, Instant};

const MISMATCH: &str = "native_policy_snapshot_context_mismatch";

#[path = "policy_client_currentness_fixture.rs"]
mod completed_mutation_fixture;

fn envelope(root: &Path, snapshot: &Value, event: &str) -> Vec<u8> {
    canonical_json_bytes(&serde_json::json!({
        "schema": GUARD_HOOK_ENVELOPE_V2_SCHEMA, "request_id": "client-currentness",
        "harness": "codex", "event": event,
        "raw_payload": {"tool_name":"Read", "tool_input":{"file_path":"synthetic.txt"},
            "tool_response":"synthetic"}, "deadline_budget_ms":750,
        "policy_generation": snapshot["generation"], "policy_snapshot": snapshot,
        "source":{"cwd":root, "home_dir":root, "guard_home":root}
    }))
    .unwrap()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_millis(750)
}

fn installed(root: &Path, version: u8) -> (PolicySnapshotStore, [u8; 32], Value) {
    let key = install_test_key(root, 83);
    let store =
        PolicySnapshotStore::new_with_resident_generation(root, &"a".repeat(64), 47).unwrap();
    let mut value = serde_json::to_value(signed_snapshot(1, &key, root)).unwrap();
    let schema = if version == 4 {
        value["schema"] = guard_policy_snapshot::POLICY_SNAPSHOT_V4_SCHEMA.into();
        value["version"] = 4.into();
        value["source_input_digest"] = "b".repeat(64).into();
        value["scoped_authority"] = serde_json::json!({
            "schema":"guard-native-policy-authority.v1", "generic_precedence":"specificity-recency.v1",
            "rows":[], "managed":null,
        });
        let mut snapshot: guard_policy_snapshot::PolicySnapshotV4 =
            serde_json::from_value(value).unwrap();
        snapshot.policy_digest = guard_policy_snapshot::policy_digest_v4(&snapshot).unwrap();
        snapshot.integrity.mac = guard_policy_snapshot::integrity_mac_v4(&snapshot, &key).unwrap();
        value = serde_json::to_value(snapshot).unwrap();
        guard_policy_snapshot::POLICY_SNAPSHOT_V4_PUSH_SCHEMA
    } else {
        POLICY_SNAPSHOT_PUSH_SCHEMA
    };
    store
        .push(&serde_json::json!({"schema":schema,"snapshot":value}))
        .unwrap();
    (store, key, value)
}

fn private_bytes(path: &Path, bytes: &[u8]) {
    #[cfg(windows)]
    {
        // These cases deliberately replace an existing authenticated record.
        // Match fs::write while retaining the private-file owner/ACL checks.
        let mut file =
            crate::resident_state::private_file(path, false, path.parent().unwrap()).unwrap();
        file.write_all(bytes).unwrap();
    }
    #[cfg(not(windows))]
    fixture_file(path, bytes);
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn unchanged_real_pre_and_post_results_retain_exact_bytes_for_v3_and_v4() {
    for version in [3, 4] {
        let root = test_root(&format!("client-unchanged-{version}"));
        let (store, _, snapshot) = installed(&root, version);
        for event in ["PreToolUse", "PostToolUse"] {
            let payload = envelope(&root, &snapshot, event);
            let expected = evaluate_resident_bytes(&payload, Some(&store)).unwrap();
            let mut calls = 0;
            let actual = request(&root, &payload, deadline(), |remaining| {
                calls += 1;
                assert!(remaining <= Duration::from_millis(750));
                evaluate_resident_bytes(&payload, Some(&store)).map_err(Into::into)
            })
            .unwrap()
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(actual, expected);
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn real_evaluation_then_completed_publication_or_withdrawal_refuses_old_response() {
    completed_mutation_fixture::assert_completed_mutation_refuses_response(false);
}

#[test]
fn prepared_mutation_requires_exact_context_mismatch_after_real_evaluation() {
    completed_mutation_fixture::assert_completed_mutation_refuses_response(true);
}

#[test]
fn policy_and_optional_approval_errors_are_not_treated_as_absence() {
    for name in [
        SNAPSHOT_FILE_NAME,
        "approval-authority.v1.json",
        "approval-authority-v4.json",
    ] {
        for bytes in [b"{}".as_slice(), b"null", b"{\"x\":1,\"x\":2}", b"not-json"] {
            let root = test_root(&format!("client-invalid-{name}-{}", bytes.len()));
            let (_, _, snapshot) = installed(&root, 3);
            private_bytes(&root.join(name), bytes);
            let mut sent = false;
            let result = request(
                &root,
                &envelope(&root, &snapshot, "PreToolUse"),
                deadline(),
                |_| {
                    sent = true;
                    Ok(vec![])
                },
            );
            assert_eq!(result.unwrap_err(), MISMATCH);
            assert!(!sent);
            fs::remove_dir_all(root).unwrap();
        }
    }
}

#[test]
fn absent_policy_and_retired_floor_refuse_before_transport() {
    for retired in [false, true] {
        let root = test_root(&format!("client-missing-{retired}"));
        let (store, key, snapshot) = installed(&root, 3);
        if retired {
            store
                .withdraw(&super::withdrawal_tests::request(&store, 5, &key))
                .unwrap();
        } else {
            fs::remove_file(root.join(SNAPSHOT_FILE_NAME)).unwrap();
        }
        assert_eq!(
            request(
                &root,
                &envelope(&root, &snapshot, "PostToolUse"),
                deadline(),
                |_| { panic!("no transport for unavailable authority") }
            )
            .unwrap_err(),
            MISMATCH
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn optional_public_record_changes_and_invalid_records_after_send_refuse() {
    for name in ["approval-authority.v1.json", "approval-authority-v4.json"] {
        let root = test_root(&format!("client-optional-{name}"));
        let (_, _, snapshot) = installed(&root, 3);
        let result = request(
            &root,
            &envelope(&root, &snapshot, "PreToolUse"),
            deadline(),
            |_| {
                private_bytes(&root.join(name), b"{}");
                Ok(b"response".to_vec())
            },
        );
        assert_eq!(result.unwrap_err(), MISMATCH);
        fs::remove_dir_all(root).unwrap();
    }
    let root = test_root("client-approval-present");
    let (_, _, snapshot) = installed(&root, 3);
    approval_authority::write_test_record(&root, &[9; 32], 1);
    assert!(ClientAuthorityObservation::capture(&root).is_ok());
    let payload = envelope(&root, &snapshot, "PreToolUse");
    assert_eq!(
        request(&root, &payload, deadline(), |_| Ok(b"same".to_vec()))
            .unwrap()
            .unwrap(),
        b"same"
    );
    let replaced = request(&root, &payload, deadline(), |_| {
        approval_authority::write_test_record(&root, &[10; 32], 1);
        Ok(b"response".to_vec())
    });
    assert_eq!(replaced.unwrap_err(), MISMATCH);
    assert!(ClientAuthorityObservation::capture(&root).is_ok());
    let result = request(&root, &payload, deadline(), |_| {
        fs::remove_file(root.join("approval-authority.v1.json")).unwrap();
        Ok(b"response".to_vec())
    });
    assert_eq!(result.unwrap_err(), MISMATCH);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn structurally_valid_v4_public_record_is_observed_without_secure_store_transition() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let root = test_root("client-approval-v4-present");
    let (_, _, snapshot) = installed(&root, 4);
    let pair = Ed25519KeyPair::from_seed_unchecked(&[11; 32]).unwrap();
    let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
    cose.extend_from_slice(pair.public_key().as_ref());
    let record = guard_contracts::ApprovalAuthorityV4 {
        schema: guard_contracts::NATIVE_APPROVAL_AUTHORITY_V4_SCHEMA.into(),
        version: 4,
        key_id: guard_policy_snapshot::digest_bytes(&cose),
        rp_id: "example.com".into(),
        origin: "https://example.com".into(),
        credential_id: hex::encode([12; 32]),
        cose_public_key: hex::encode(cose),
        algorithm: -8,
        device_binding: "c".repeat(64),
        installation_binding: "d".repeat(64),
        enrollment_generation: 1,
        previous_key_id: None,
        status: "active".into(),
        enrollment_signature: String::new(),
    };
    let bytes = approval_v4_authority::tests::test_record_bytes(&record).unwrap();
    let path = root.join("approval-authority-v4.json");
    private_bytes(&path, &bytes);
    let mut before: Vec<_> = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    before.sort();
    let payload = envelope(&root, &snapshot, "PreToolUse");
    assert_eq!(
        request(&root, &payload, deadline(), |_| Ok(b"same".to_vec()))
            .unwrap()
            .unwrap(),
        b"same"
    );
    let mut after: Vec<_> = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    after.sort();
    assert_eq!(before, after);
    let mut replacement = record.clone();
    replacement.credential_id = hex::encode([13; 32]);
    let replacement_bytes = approval_v4_authority::tests::test_record_bytes(&replacement).unwrap();
    let replaced = request(&root, &payload, deadline(), |_| {
        private_bytes(&path, &replacement_bytes);
        Ok(b"response".to_vec())
    });
    assert_eq!(replaced.unwrap_err(), MISMATCH);
    assert!(ClientAuthorityObservation::capture(&root).is_ok());
    let result = request(&root, &payload, deadline(), |_| {
        fs::remove_file(&path).unwrap();
        Ok(b"response".to_vec())
    });
    assert_eq!(result.unwrap_err(), MISMATCH);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn symlink_directory_and_nonprivate_authority_never_pass_as_absent() {
    for name in [
        SNAPSHOT_FILE_NAME,
        "approval-authority.v1.json",
        "approval-authority-v4.json",
    ] {
        for kind in ["symlink", "directory", "nonprivate"] {
            let root = test_root(&format!("client-private-{name}-{kind}"));
            let (_, _, snapshot) = installed(&root, 3);
            let path = root.join(name);
            if path.exists() {
                fs::remove_file(&path).unwrap();
            }
            match kind {
                "symlink" => std::os::unix::fs::symlink(root.join("missing"), &path).unwrap(),
                "directory" => fs::create_dir(&path).unwrap(),
                _ => {
                    private_bytes(&path, b"{}");
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
            }
            assert_eq!(
                request(
                    &root,
                    &envelope(&root, &snapshot, "PreToolUse"),
                    deadline(),
                    |_| { panic!("invalid authority must not send") }
                )
                .unwrap_err(),
                MISMATCH
            );
            fs::remove_dir_all(root).unwrap();
        }
    }
}

#[test]
fn deadline_and_transport_error_boundaries_preserve_classification() {
    let root = test_root("client-deadline");
    let (_, _, snapshot) = installed(&root, 3);
    let payload = envelope(&root, &snapshot, "PreToolUse");
    assert_eq!(
        request(&root, &payload, Instant::now(), |_| panic!("expired")).unwrap_err(),
        "native_client_deadline_exceeded"
    );
    let expected = ResidentClientError {
        code: "synthetic_transport_failure".into(),
        retryable_teardown: true,
    };
    assert_eq!(
        request(&root, &payload, deadline(), |_| Err(ResidentClientError {
            code: expected.code.clone(),
            retryable_teardown: expected.retryable_teardown
        }))
        .unwrap()
        .unwrap_err(),
        expected
    );
    let expired = Instant::now() + Duration::from_millis(20);
    assert_eq!(
        request(&root, &payload, expired, |_| {
            std::thread::sleep(
                expired.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
            Ok(b"late".to_vec())
        })
        .unwrap_err(),
        "native_client_deadline_exceeded"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn nonhook_operations_use_original_transport_without_policy_observation() {
    let root = test_root("client-nonhook");
    for operation in [
        "health",
        "shutdown",
        "policy_snapshot_push",
        "policy_snapshot_observe",
        "policy_snapshot_withdraw",
    ] {
        let payload =
            canonical_json_bytes(&serde_json::json!({"operation":operation,"request":{}})).unwrap();
        let mut called = false;
        assert_eq!(
            request(&root, &payload, deadline(), |_| {
                called = true;
                Ok(b"original".to_vec())
            })
            .unwrap()
            .unwrap(),
            b"original"
        );
        assert!(called);
    }
    for payload in [
        b"{}".as_slice(),
        b"{\"operation\":\"unknown\",\"request\":{}}",
        b"{\"operation\":\"health\",\"operation\":\"shutdown\",\"request\":{}}",
    ] {
        assert!(request(&root, payload, deadline(), |_| panic!(
            "invalid requests do not send"
        ))
        .is_err());
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn existing_authenticated_key_lifetime_is_not_redefined_by_client_observation() {
    let root = test_root("client-key-lifetime");
    let (store, _, snapshot) = installed(&root, 3);
    let payload = envelope(&root, &snapshot, "PreToolUse");
    let result = request(&root, &payload, deadline(), |_| {
        let response = evaluate_resident_bytes(&payload, Some(&store)).unwrap();
        fs::remove_file(root.join(VERIFIER_KEY_FILE_NAME)).unwrap();
        Ok(response)
    });
    assert!(result.unwrap().is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn actual_mutating_control_routes_are_not_wrapped_as_hook_reads() {
    let root = test_root("client-real-controls");
    let key = install_test_key(&root, 84);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 48).unwrap();
    let push = canonical_json_bytes(&serde_json::json!({"operation":"policy_snapshot_push",
        "request":{"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":signed_snapshot(1,&key,&root)}}))
    .unwrap();
    assert!(!root.join(SNAPSHOT_FILE_NAME).exists());
    let ack = request(&root, &push, deadline(), |_| {
        evaluate_resident_bytes(&push, Some(&store)).map_err(Into::into)
    })
    .unwrap()
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&ack).unwrap()["status"],
        "accepted"
    );
    let withdraw =
        canonical_json_bytes(&serde_json::json!({"operation":"policy_snapshot_withdraw",
        "request":super::withdrawal_tests::request(&store, 10, &key)}))
        .unwrap();
    let ack = request(&root, &withdraw, deadline(), |_| {
        evaluate_resident_bytes(&withdraw, Some(&store)).map_err(Into::into)
    })
    .unwrap()
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&ack).unwrap()["response"]["status"],
        "withdrawn"
    );
    assert!(store.current_snapshot().is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn continuity_never_substitutes_for_resident_authentication() {
    let root = test_root("client-authentication");
    let (store, _, snapshot) = installed(&root, 3);
    let path = root.join(SNAPSHOT_FILE_NAME);
    let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    record["floor_mac"] = "0".repeat(64).into();
    private_bytes(&path, &canonical_json_bytes(&record).unwrap());
    assert!(ClientAuthorityObservation::capture(&root).is_ok());
    let payload = envelope(&root, &snapshot, "PreToolUse");
    let result = request(&root, &payload, deadline(), |_| {
        evaluate_resident_bytes(&payload, Some(&store)).map_err(Into::into)
    });
    assert!(result.unwrap().is_err());
    assert!(PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 48).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unchanged_authority_expiring_during_response_return_is_refused() {
    for version in [3, 4] {
        let clock = super::super::policy_store_authority::TestClock::at(now_ms().unwrap());
        let root = test_root(&format!("client-expiring-{version}"));
        let (store, key, mut snapshot) = installed(&root, version);
        snapshot["generation"] = 2.into();
        snapshot["expires_at_ms"] = (now_ms().unwrap() + 200).into();
        let schema = if version == 4 {
            let mut value: guard_policy_snapshot::PolicySnapshotV4 =
                serde_json::from_value(snapshot).unwrap();
            value.policy_digest = guard_policy_snapshot::policy_digest_v4(&value).unwrap();
            value.integrity.mac = guard_policy_snapshot::integrity_mac_v4(&value, &key).unwrap();
            snapshot = serde_json::to_value(value).unwrap();
            guard_policy_snapshot::POLICY_SNAPSHOT_V4_PUSH_SCHEMA
        } else {
            let mut value: PolicySnapshotV3 = serde_json::from_value(snapshot).unwrap();
            value.policy_digest = policy_digest(&value).unwrap();
            value.integrity.mac = integrity_mac(&value, &key).unwrap();
            snapshot = serde_json::to_value(value).unwrap();
            POLICY_SNAPSHOT_PUSH_SCHEMA
        };
        store
            .push(&serde_json::json!({"schema":schema,"snapshot":snapshot}))
            .unwrap();
        let payload = envelope(&root, &snapshot, "PreToolUse");
        let fingerprint = authority_fingerprint(&root.join(SNAPSHOT_FILE_NAME)).unwrap();
        let expiry = snapshot["expires_at_ms"].as_u64().unwrap();
        let mut evaluated = false;
        let result = request(&root, &payload, deadline(), |_| {
            let response = evaluate_resident_bytes(&payload, Some(&store)).unwrap();
            evaluated = true;
            // Advance only after actual evaluation, with identical authority
            // bytes and the original monotonic request deadline unchanged.
            clock.set(expiry);
            assert_eq!(now_ms().unwrap(), expiry);
            assert_eq!(
                authority_fingerprint(&root.join(SNAPSHOT_FILE_NAME)).unwrap(),
                fingerprint
            );
            Ok(response)
        });
        assert!(evaluated);
        assert!(
            result.is_err(),
            "an evaluated response outlived its unchanged snapshot"
        );
        assert_eq!(result.unwrap_err(), MISMATCH);
        fs::remove_dir_all(root).unwrap();
    }
}
