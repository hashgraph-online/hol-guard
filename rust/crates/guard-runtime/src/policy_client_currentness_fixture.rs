//! Share real mutation setup while preserving distinct client refusal contracts.

use super::*;
use crate::policy_store::AuthenticatedPolicySnapshot;

fn prepare_authority_record(root: &Path, key: &[u8; 32], withdraw: bool) -> PathBuf {
    let path = root.join("prepared-client-authority.json");
    let snapshot = if withdraw {
        None
    } else {
        Some(AuthenticatedPolicySnapshot::V3(signed_snapshot(
            10, key, root,
        )))
    };
    let digest = snapshot
        .as_ref()
        .map(|value| value.policy_digest().clone())
        .unwrap_or_else(|| "d".repeat(64));
    // Complete encoding, signing and durable file creation before measuring the
    // response boundary. The actual private replacement still happens in send.
    crate::policy_store::persist_authority(&path, 10, &digest, snapshot.as_ref(), key).unwrap();
    let loaded = crate::policy_store::load_current_authority(
        &path,
        &"a".repeat(64),
        &guard_rule_contract::rule_digest(),
        &crate::policy_store::scope_digest_for_test(root),
        key,
    )
    .unwrap();
    assert_eq!(loaded.generation_floor, 10);
    assert_eq!(loaded.snapshot.is_none(), withdraw);
    assert!(!loaded.invalid_on_startup);
    path
}

pub(super) fn assert_completed_mutation_refuses_response(strict_currentness: bool) {
    for version in [3, 4] {
        for event in ["PreToolUse", "PostToolUse"] {
            for withdraw in [false, true] {
                let prefix = if strict_currentness {
                    "client-changed-strict"
                } else {
                    "client-changed"
                };
                let root = test_root(&format!("{prefix}-{version}-{event}-{withdraw}"));
                let (store, key, snapshot) = installed(&root, version);
                let payload = envelope(&root, &snapshot, event);
                let prepare = || {
                    let independent = PolicySnapshotStore::new_with_resident_generation(
                        &root,
                        &"a".repeat(64),
                        47,
                    )
                    .unwrap();
                    let mutation = if withdraw {
                        super::super::withdrawal_tests::request(&independent, 10, &key)
                    } else {
                        serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,
                            "snapshot":signed_snapshot(10, &key, &root)})
                    };
                    (independent, mutation)
                };
                let authority_path = root.join(SNAPSHOT_FILE_NAME);
                let original_fingerprint = authority_fingerprint(&authority_path).unwrap();
                // The ordinary case still measures the entire real writer. The
                // strict case isolates the actual authenticated record replacement.
                let prepared = if strict_currentness {
                    Some(prepare_authority_record(&root, &key, withdraw))
                } else {
                    None
                };
                assert_eq!(
                    authority_fingerprint(&authority_path).unwrap(),
                    original_fingerprint
                );
                let private_root =
                    crate::resident_state::private_root_for_state_base(&root).unwrap();
                let mut evaluated = false;
                let result = request(&root, &payload, deadline(), |_| {
                    let response = evaluate_resident_bytes(&payload, Some(&store)).unwrap();
                    evaluated = true;
                    if let Some(path) = prepared {
                        crate::policy_store::policy_store_persistence::replace_temporary(
                            &path,
                            &authority_path,
                            "authority",
                            &private_root,
                        )
                        .unwrap();
                    } else {
                        let (independent, mutation) = prepare();
                        if withdraw {
                            independent.withdraw(&mutation).unwrap();
                        } else {
                            independent.push(&mutation).unwrap();
                        }
                        drop(independent);
                    }
                    // The unmodified transport boundary would return these actual result bytes.
                    assert_eq!(
                        serde_json::from_slice::<Value>(&response).unwrap()["receipt"]
                            ["policy_generation"],
                        1
                    );
                    Ok(response)
                });
                assert!(evaluated);
                assert_ne!(
                    authority_fingerprint(&authority_path).unwrap(),
                    original_fingerprint
                );
                if strict_currentness {
                    assert_eq!(result.unwrap_err(), MISMATCH);
                } else {
                    // Real durable mutation may consume the unchanged 750 ms budget.
                    // Either refusal is safe; an old authoritative result never is.
                    assert!(matches!(
                        result.unwrap_err().as_str(),
                        MISMATCH | "native_client_deadline_exceeded"
                    ));
                }
                fs::remove_dir_all(root).unwrap();
            }
        }
    }
}
