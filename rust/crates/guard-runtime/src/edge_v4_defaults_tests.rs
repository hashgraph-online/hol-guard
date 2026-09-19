use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};

fn defaults_snapshot(
    generation: u64,
    key: &[u8],
    root: &Path,
    action: &str,
    mode: &str,
) -> PolicySnapshotV4 {
    let mut candidate = snapshot_v4(generation, key, root);
    candidate.scoped_authority = serde_json::from_value(json!({
        "schema":"guard-native-policy-authority.v1", "generic_precedence":"specificity-recency.v1",
        "rows":[], "managed":null,
    }))
    .unwrap();
    candidate.mode = mode.into();
    candidate.effective_policy.default_action = action.into();
    candidate.effective_policy.subprocess_action = "allow".into();
    sign(&mut candidate, key);
    candidate
}

fn request(
    candidate: &PolicySnapshotV4,
    root: &Path,
    event: &str,
    payload: Value,
) -> GuardHookEnvelopeV2 {
    serde_json::from_value(json!({
        "schema":"guard-hook-envelope.v2", "request_id":"defaults-edge", "harness":"codex", "event":event,
        "raw_payload":payload, "deadline_budget_ms":1000,
        "policy_generation":candidate.generation, "policy_snapshot":reference(candidate),
        "source":{"cwd":root,"home_dir":root,"guard_home":root}
    })).unwrap()
}

fn edge(store: &PolicySnapshotStore, request: GuardHookEnvelopeV2) -> Value {
    serde_json::from_slice(&crate::edge::evaluate_envelope_with_store(request, store).unwrap())
        .unwrap()
}

fn emit_vector(name: &str, edge: &Value, candidate: &PolicySnapshotV4, resident_generation: u64) {
    println!(
        "DEFAULT_EDGE_VECTOR={}",
        json!({
            "name":name, "edge":edge,
            "expectedBinding":{"generation":candidate.generation,"policy_digest":candidate.policy_digest,
                "source_input_digest":candidate.source_input_digest,"runtime_identity":candidate.runtime_identity,
                "resident_generation":resident_generation,"mode":candidate.mode}
        })
    );
}

#[test]
fn authenticated_defaults_preserve_existing_pre_and_post_decisions_for_every_action_and_mode() {
    let root = test_root("v4-defaults-parity");
    let key = install_test_key(&root, 79);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 41).unwrap();
    let payloads = [
        (
            "environment",
            json!({"tool_name":"Shell","tool_input":{"command":"env SYNTHETIC=1 printf synthetic"},"tool_response":"synthetic"}),
        ),
        (
            "compound",
            json!({"tool_name":"Shell","tool_input":{"command":"printf first && printf second"},"tool_response":"synthetic"}),
        ),
        (
            "read",
            json!({"tool_name":"Read","tool_input":{"file_path":"synthetic.txt"},"tool_response":"synthetic"}),
        ),
        (
            "write",
            json!({"tool_name":"Write","tool_input":{"file_path":"synthetic.txt","content":"synthetic"},"tool_response":"synthetic"}),
        ),
        (
            "package",
            json!({"tool_name":"Shell","tool_input":{"command":"npm install synthetic-package"},"tool_response":"synthetic"}),
        ),
        (
            "unknown",
            json!({"tool_name":"UnknownSyntheticTool","tool_response":"synthetic"}),
        ),
    ];
    let mut generation = 1;
    for mode in ["enforce", "observe"] {
        for action in [
            "allow",
            "warn",
            "review",
            "require-reapproval",
            "sandbox-required",
            "block",
        ] {
            let candidate = defaults_snapshot(generation, &key, &root, action, mode);
            generation += 1;
            store.push(&push_value(&candidate)).unwrap();
            let mut legacy = signed_snapshot_with_policy(
                candidate.generation,
                &key,
                &root,
                candidate.effective_policy.clone(),
            );
            legacy.mode = mode.into();
            for (name, payload) in &payloads {
                for event in ["PreToolUse", "PostToolUse"] {
                    let source = request(&candidate, &root, event, payload.clone());
                    if event == "PreToolUse" {
                        assert!(crate::policy_scoped_request::derive_scoped_policy_request(
                            &source, "codex"
                        )
                        .is_err());
                    }
                    let actual = edge(&store, source.clone());
                    let expected: Value = serde_json::from_slice(
                        &crate::edge::evaluate_envelope_with_snapshot(
                            source,
                            &crate::policy_enforcement::AdmittedPolicySnapshot::new(legacy.clone())
                                .unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    let mut result = actual["result"].clone();
                    if event == "PostToolUse" {
                        result.as_object_mut().unwrap().remove("observe_mode");
                        result
                            .as_object_mut()
                            .unwrap()
                            .remove("observed_policy_action");
                    }
                    assert_eq!(result, expected["result"], "{name}/{event}/{mode}/{action}");
                    assert_eq!(
                        actual["policy_binding"]["source_input_digest"],
                        candidate.source_input_digest
                    );
                    assert_eq!(actual["policy_binding"]["resident_generation"], 41);
                    assert_eq!(
                        actual["policy_binding"]["selected_decision_id"],
                        Value::Null
                    );
                    assert_eq!(actual["receipt"]["observe_mode"], mode == "observe");
                    assert_eq!(actual["receipt"]["policy_digest"], candidate.policy_digest);
                    assert_eq!(
                        actual["receipt"]["policy_action"],
                        actual["result"]["policy_action"]
                    );
                    emit_vector(
                        &format!("{name}/{event}/{mode}/{action}"),
                        &actual,
                        &candidate,
                        41,
                    );
                }
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn existing_scoped_generic_composition_is_not_replaced_by_the_defaults_extension() {
    let root = test_root("v4-defaults-generic-compat");
    let key = install_test_key(&root, 84);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 46).unwrap();
    for (generation, mode) in [(1, "enforce"), (2, "observe")] {
        let candidate = defaults_snapshot(generation, &key, &root, "warn", mode);
        store.push(&push_value(&candidate)).unwrap();
        let mut legacy = signed_snapshot_with_policy(
            generation,
            &key,
            &root,
            candidate.effective_policy.clone(),
        );
        legacy.mode = mode.into();
        let source = request(
            &candidate,
            &root,
            "PreToolUse",
            json!({
                "tool_name":"Shell","tool_input":{"command":"ssh synthetic@example.invalid"},
                "source_scope":"project","publisher":"synthetic-publisher","approval_requests":[]
            }),
        );
        assert!(
            crate::policy_scoped_request::derive_scoped_policy_request(&source, "codex").is_ok()
        );
        let actual = edge(&store, source.clone());
        let prior: Value = serde_json::from_slice(
            &crate::edge::evaluate_envelope_with_snapshot(
                source,
                &crate::policy_enforcement::AdmittedPolicySnapshot::new(legacy.clone()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        // These are distinct preexisting producer semantics, not authority
        // inferred from the signed source. Preserve the reviewed V4 behavior.
        assert_eq!(prior["result"]["policy_action"], "review");
        assert_eq!(prior["result"]["decision"], "deny");
        assert_eq!(actual["result"]["policy_action"], "warn");
        assert_eq!(actual["result"]["decision"], "allow");
        assert_eq!(actual["observed_policy_action"], Value::Null);
        emit_vector(
            &format!("existing-generic-ssh/{mode}"),
            &actual,
            &candidate,
            46,
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn authenticated_defaults_preserve_verified_source_output_and_reviewed_excerpt() {
    let root = test_root("v4-defaults-source-output");
    // The secure reader rejects aliases in the supplied path. Match the
    // existing source-read fixtures when the platform's temp root is an alias.
    #[cfg(unix)]
    let root = fs::canonicalize(root).unwrap();
    let key = install_test_key(&root, 83);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 45).unwrap();
    let content = "synthetic output";
    let output = root.join("synthetic.rs");
    fixture_file(&output, content.as_bytes());
    let digest = hex::encode(Sha256::digest(content.as_bytes()));
    for (generation, mode) in [(1, "enforce"), (2, "observe")] {
        let candidate = defaults_snapshot(generation, &key, &root, "allow", mode);
        store.push(&push_value(&candidate)).unwrap();
        let mut payload = json!({"tool_name":"Read","tool_input":{"file_path":output},"guard_source_ref":{
            "version":1,"path":output,"output_sha256":digest,"output_chars":content.len()
        }});
        let allowed = edge(
            &store,
            request(&candidate, &root, "PostToolUse", payload.clone()),
        );
        #[cfg(unix)]
        {
            assert_eq!(allowed["result"]["decision"], "allow", "{allowed}");
            assert_eq!(allowed["result"]["reason_code"], "source_full_scan_allow");
            assert_eq!(allowed["result"]["reviewed_output_sha256"], digest);
            emit_vector(&format!("source-file/{mode}"), &allowed, &candidate, 45);
        }
        #[cfg(not(unix))]
        {
            // The existing reader requires a descriptor-bound path walk and
            // refuses on these platforms. Authenticated defaults cannot
            // manufacture a reviewed-output proof for an unsupported read.
            assert_eq!(allowed["result"]["decision"], "deny", "{allowed}");
            assert_eq!(allowed["result"]["reason_code"], "no_output_to_review");
            assert_eq!(allowed["result"]["model_output_action"], "block");
            assert_eq!(allowed["result"]["reviewed_output_sha256"], Value::Null);
            emit_vector(
                &format!("source-file-refusal/{mode}"),
                &allowed,
                &candidate,
                45,
            );
        }
        payload["guard_source_ref"]["output_sha256"] = json!("f".repeat(64));
        let denied = edge(&store, request(&candidate, &root, "PostToolUse", payload));
        assert_eq!(denied["result"]["decision"], "deny");
        assert_eq!(denied["result"]["model_output_action"], "block");
        emit_vector(&format!("source-mismatch/{mode}"), &denied, &candidate, 45);
        let excerpt = edge(
            &store,
            request(
                &candidate,
                &root,
                "PostToolUse",
                json!({
                    "tool_name":"Read", "tool_response":vec![content;25]
                }),
            ),
        );
        assert_eq!(excerpt["result"]["decision"], "allow");
        assert_eq!(
            excerpt["result"]["model_output_action"],
            "replace_with_reviewed_excerpt"
        );
        assert_eq!(excerpt["result"]["reviewed_excerpt"], content.repeat(24));
        emit_vector(
            &format!("reviewed-excerpt/{mode}"),
            &excerpt,
            &candidate,
            45,
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn authenticated_defaults_keep_intrinsic_blocks_and_source_content_review() {
    let root = test_root("v4-defaults-intrinsic");
    let key = install_test_key(&root, 80);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 42).unwrap();
    for (generation, mode) in [(1, "enforce"), (2, "observe")] {
        let candidate = defaults_snapshot(generation, &key, &root, "allow", mode);
        store.push(&push_value(&candidate)).unwrap();
        let denied = edge(
            &store,
            request(
                &candidate,
                &root,
                "PreToolUse",
                json!({
                    "tool_name":"Shell", "tool_input":{"command":"rm -rf /"}
                }),
            ),
        );
        assert_eq!(denied["result"]["decision"], "deny");
        assert_eq!(denied["result"]["policy_action"], "block");
        // Invalid source metadata must remain an intrinsic native denial,
        // including when the authenticated policy is Observe/Allow.
        let denied = edge(
            &store,
            request(
                &candidate,
                &root,
                "PostToolUse",
                json!({
                    "tool_name":"Read", "guard_source_ref":{
                        "version":1, "path":"/missing-synthetic-source", "output_sha256":"a".repeat(64),
                        "output_chars":9
                    }
                }),
            ),
        );
        assert_eq!(denied["result"]["decision"], "deny");
        assert_eq!(denied["result"]["model_output_action"], "block");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn defaults_route_never_drops_scoped_rows_managed_controls_or_configuration_origins() {
    let root = test_root("v4-defaults-origin-refusal");
    let key = install_test_key(&root, 81);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 43).unwrap();
    let row_authority = serde_json::to_value(snapshot_v4(1, &key, &root).scoped_authority).unwrap();
    let managed_vector: Value = serde_json::from_str(include_str!(
        "../../../../contracts/native-policy-snapshot/v4/managed-configuration-vector.json"
    ))
    .unwrap();
    let base = serde_json::to_value(
        defaults_snapshot(1, &key, &root, "allow", "enforce").scoped_authority,
    )
    .unwrap();
    let mut managed = base.clone();
    managed["managed"] = json!({"revision":1,"managed_revision":1,"catalog_digest":crate::policy_scoped_managed::catalog_digest(),"global_lockdown":true,"controls":[]});
    let mut configuration = base;
    configuration["managed_config"] =
        managed_vector["snapshot"]["scoped_authority"]["managed_config"].clone();
    for (index, authority) in [row_authority, managed, configuration]
        .into_iter()
        .enumerate()
    {
        let mut candidate = defaults_snapshot(index as u64 + 1, &key, &root, "allow", "enforce");
        candidate.scoped_authority = serde_json::from_value(authority).unwrap();
        assert!(!candidate.scoped_authority.is_defaults_only());
        sign(&mut candidate, &key);
        store.push(&push_value(&candidate)).unwrap();
        let source = request(
            &candidate,
            &root,
            "PostToolUse",
            json!({"tool_name":"Read","tool_response":"synthetic"}),
        );
        assert_eq!(
            crate::edge::evaluate_envelope_with_store(source, &store).unwrap_err(),
            "native_scoped_hook_route_unsupported"
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn defaults_edge_requires_current_full_native_source_and_refuses_unsupported_transports() {
    let root = test_root("v4-defaults-source-fence");
    let key = install_test_key(&root, 82);
    let store =
        PolicySnapshotStore::new_with_resident_generation(&root, &"a".repeat(64), 44).unwrap();
    let candidate = defaults_snapshot(1, &key, &root, "block", "enforce");
    store.push(&push_value(&candidate)).unwrap();
    for event in ["PreToolUse", "PostToolUse"] {
        let source = request(
            &candidate,
            &root,
            event,
            json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic"},"tool_response":"synthetic"}),
        );
        assert_eq!(edge(&store, source.clone())["result"]["decision"], "deny");
        for field in ["policy_digest", "source_input_digest", "runtime_identity"] {
            let mut wrong = source.clone();
            wrong.policy_snapshot[field] = json!("f".repeat(64));
            assert!(crate::edge::evaluate_envelope_with_store(wrong, &store).is_err());
        }
        let encrypted = request(&candidate, &root, event, json!({"guard_payload_ref":{}}));
        assert_eq!(
            crate::edge::evaluate_envelope_with_store(encrypted, &store).unwrap_err(),
            "native_scoped_hook_route_unsupported"
        );
    }
    let next = defaults_snapshot(2, &key, &root, "allow", "enforce");
    store.push(&push_value(&next)).unwrap();
    let stale = request(
        &candidate,
        &root,
        "PostToolUse",
        json!({"tool_response":"synthetic"}),
    );
    assert!(crate::edge::evaluate_envelope_with_store(stale, &store).is_err());
    fs::remove_file(root.join(SNAPSHOT_FILE_NAME)).unwrap();
    let withdrawn = request(
        &next,
        &root,
        "PostToolUse",
        json!({"tool_response":"synthetic"}),
    );
    assert!(crate::edge::evaluate_envelope_with_store(withdrawn, &store).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[path = "policy_store_versioned_command_tests.rs"]
mod command_tests;
