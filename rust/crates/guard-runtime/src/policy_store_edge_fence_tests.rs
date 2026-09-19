use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn request(root: &Path, snapshot: &PolicySnapshotV3, post: bool) -> GuardHookEnvelopeV2 {
    GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.into(),
        request_id: Some("synthetic-authority-fence".into()),
        harness: "claude-code".into(),
        event: if post { "PostToolUse" } else { "PreToolUse" }.into(),
        raw_payload: if post {
            serde_json::json!({"tool_name":"Bash","tool_input":{"command":"pwd"},"tool_response":"synthetic output"})
        } else {
            serde_json::json!({"tool_name":"Bash","tool_input":{"command":"pwd"}})
        },
        deadline_budget_ms: Some(100),
        policy_generation: snapshot.generation,
        policy_snapshot: serde_json::to_value(snapshot).unwrap(),
        source: GuardHookSourceMetadataV2 {
            cwd: Some(root.to_string_lossy().into_owned()),
            home_dir: root.to_string_lossy().into_owned(),
            guard_home: root.to_string_lossy().into_owned(),
            source_ref_external_allowed: false,
        },
    }
}

struct ObserverGuard;
impl Drop for ObserverGuard {
    fn drop(&mut self) {
        crate::edge::AFTER_EVALUATION.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

fn evaluate_after_mutation(
    store: &PolicySnapshotStore,
    envelope: GuardHookEnvelopeV2,
    mutation: impl FnOnce() + 'static,
) -> Result<Vec<u8>, String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    crate::edge::AFTER_EVALUATION.with(|slot| {
        assert!(slot
            .borrow_mut()
            .replace(Box::new(move || {
                observed.fetch_add(1, Ordering::SeqCst);
                mutation();
            }))
            .is_none());
    });
    let _observer = ObserverGuard;
    let result = crate::edge::evaluate_envelope_with_store(envelope, store);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    result
}

#[test]
fn unchanged_v3_authority_preserves_exact_pre_and_post_results() {
    for post in [false, true] {
        let root = test_root(if post {
            "edge-fence-post-control"
        } else {
            "edge-fence-pre-control"
        });
        let key = install_test_key(&root, 61);
        let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
        let snapshot = signed_snapshot(1, &key, &root);
        store
            .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":snapshot}))
            .unwrap();
        let envelope = request(&root, &snapshot, post);
        let expected = crate::edge::evaluate_envelope_with_store(envelope.clone(), &store).unwrap();
        assert_eq!(
            evaluate_after_mutation(&store, envelope, || {}).unwrap(),
            expected
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn changed_v3_authority_refuses_completed_pre_and_post_results() {
    for post in [false, true] {
        for mutation in [
            "same-store",
            "independent-store",
            "removed-authority",
            "changed-approval",
        ] {
            let root = test_root(&format!("edge-fence-{post}-{mutation}"));
            let key = install_test_key(&root, 62);
            let store = Arc::new(PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap());
            let snapshot = signed_snapshot(1, &key, &root);
            store
                .push(
                    &serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":snapshot}),
                )
                .unwrap();
            let envelope = request(&root, &snapshot, post);
            let changed_root = root.clone();
            let changed_store = Arc::clone(&store);
            let result = evaluate_after_mutation(&store, envelope, move || match mutation {
                "same-store" | "independent-store" => {
                    let push = serde_json::json!({
                        "schema":POLICY_SNAPSHOT_PUSH_SCHEMA,
                        "snapshot":signed_snapshot(2, &key, &changed_root),
                    });
                    if mutation == "same-store" {
                        changed_store.push(&push).unwrap();
                    } else {
                        PolicySnapshotStore::new(&changed_root, &"a".repeat(64))
                            .unwrap()
                            .push(&push)
                            .unwrap();
                    }
                }
                "removed-authority" => {
                    fs::remove_file(changed_root.join(SNAPSHOT_FILE_NAME)).unwrap()
                }
                "changed-approval" => fixture_file(
                    &changed_root.join(
                        crate::policy_store::approval_authority::APPROVAL_AUTHORITY_FILE_NAME,
                    ),
                    b"{}",
                ),
                _ => unreachable!(),
            });
            let expected = if mutation == "same-store" {
                "native_policy_snapshot_not_current"
            } else {
                "native_policy_snapshot_context_mismatch"
            };
            assert_eq!(
                result.err().as_deref(),
                Some(expected),
                "post={post} mutation={mutation}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }
}
