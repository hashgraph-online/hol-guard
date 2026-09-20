use super::super::command_authority_tests::publish_marker;
use super::super::command_floor_tests::control_snapshot;
use super::super::*;
use guard_contracts::NativeReviewScopeV1;
use serde_json::json;

fn request(root: &Path, snapshot: &PolicySnapshotV3, payload: Value) -> GuardHookEnvelopeV2 {
    GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.into(),
        request_id: None,
        harness: "cursor".into(),
        event: "PreToolUse".into(),
        raw_payload: payload,
        deadline_budget_ms: Some(750),
        policy_generation: snapshot.generation,
        policy_snapshot: json!({
            "generation": snapshot.generation,
            "policy_digest": snapshot.policy_digest,
            "runtime_identity": snapshot.runtime_identity,
        }),
        source: GuardHookSourceMetadataV2 {
            cwd: Some(root.join("workspace").to_string_lossy().into()),
            home_dir: root.to_string_lossy().into(),
            guard_home: root.to_string_lossy().into(),
            source_ref_external_allowed: false,
        },
    }
}

#[test]
fn current_signed_noncommand_reviews_have_distinct_receipt_scope() {
    let root = test_root("noncommand-review");
    let key = install_test_key(&root, 84);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = control_snapshot(1, 1, 1, "enabled", &key, &root);
    publish_marker(&store, &snapshot, "committed");
    let ack: PolicySnapshotAckV1 = serde_json::from_slice(
        &store
            .push(&json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": snapshot}))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ack.generation, snapshot.generation);
    assert_eq!(ack.policy_digest, snapshot.policy_digest);
    let cases = [
        (
            "network",
            json!({"tool_name": "WebFetch", "tool_input": {"url": "https://example.com/docs", "prompt": "read"}}),
            true,
        ),
        (
            "network_url",
            json!({"tool_name": "WebFetch", "tool_input": {"url": "https://example.com/docs"}}),
            true,
        ),
        (
            "ollama",
            json!({"tool_name": "Bash", "tool_input": {"command": "ollama push guard-fixture-model"}}),
            false,
        ),
        (
            "read",
            json!({"tool_name": "Read", "tool_input": {"file_path": ".env"}}),
            true,
        ),
        (
            "mcp",
            json!({"tool_name": "mcp__filesystem__read", "tool_input": {"path": "README.md"}}),
            true,
        ),
        (
            "mcp_command",
            json!({"tool_name": "mcp__filesystem__read", "tool_input": {"command": "cat .env"}}),
            false,
        ),
    ];
    let mut fixtures = Vec::new();
    for (name, payload, noncommand) in cases {
        let envelope = request(&root, &snapshot, payload);
        let encoded = crate::edge::evaluate_envelope_with_store(envelope.clone(), &store).unwrap();
        let edge: GuardHookEdgeResultV2 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(edge.result["policy_action"], "review");
        assert_eq!(edge.receipt.policy_generation, snapshot.generation);
        assert_eq!(
            edge.receipt.policy_digest.as_ref(),
            Some(&snapshot.policy_digest)
        );
        assert_eq!(
            edge.receipt.review_scope,
            noncommand.then_some(NativeReviewScopeV1::Noncommand)
        );
        assert_eq!(edge.receipt.command_extensions.is_none(), noncommand);
        let receipt_value = serde_json::to_value(&edge.receipt).unwrap();
        assert_eq!(receipt_value.get("review_scope").is_some(), noncommand);
        if name == "mcp_command" {
            assert_eq!(edge.result["action"]["action_type"], "mcp_tool");
        }
        if let Some(label) = match name {
            "network_url" => Some("WebFetch"),
            "read" => Some("Read"),
            "mcp" => Some("MCP"),
            _ => None,
        } {
            let active_snapshot = store.current_snapshot().unwrap();
            assert_eq!(active_snapshot, snapshot);
            let evidence = json!({
                "schema": "pr2974.native-non-command-review-evidence.v1",
                "label": label,
                "envelope": envelope,
                "active_snapshot": active_snapshot,
                "edge_json": std::str::from_utf8(&encoded).unwrap(),
            });
            let original = serde_json::to_string(&evidence).unwrap();
            assert!(original.len() <= 64 * 1024);
            println!("HOL_GUARD_NATIVE_NONCOMMAND_EVIDENCE_V1 {original}");
        }
        fixtures.push(json!({
            "case": name, "edge": edge,
            "payload": envelope.raw_payload, "source": envelope.source,
            "snapshot": {
                "generation": snapshot.generation, "policy_digest": snapshot.policy_digest,
                "runtime_identity": snapshot.runtime_identity, "rule_digest": snapshot.rule_digest,
                "mode": snapshot.mode,
            },
        }));
    }
    let stale = request(
        &root,
        &snapshot,
        json!({"tool_name":"Read", "tool_input":{"file_path":".env"}}),
    );
    let next = control_snapshot(2, 1, 1, "enabled", &key, &root);
    publish_marker(&store, &next, "committed");
    store
        .push(&json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": next}))
        .unwrap();
    assert!(crate::edge::evaluate_envelope_with_store(stale, &store).is_err());
    // Optional test-only stdout fixture enables Python to consume these exact
    // Rust-produced bytes. It never adds a runtime command or changes transport.
    if std::env::var("HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE").as_deref() == Ok("1") {
        println!(
            "HOL_GUARD_NONCOMMAND_RECEIPTS={}",
            serde_json::to_string(&fixtures).unwrap()
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_and_present_commands_without_controls_do_not_claim_noncommand_scope() {
    let root = test_root("noncommand-unbound-command");
    let key = install_test_key(&root, 85);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = signed_snapshot(1, &key, &root);
    assert!(snapshot.command_extensions.is_none());
    store
        .push(&json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": snapshot}))
        .unwrap();
    for payload in [
        json!({"tool_name": "Bash", "tool_input": {"command": "cat .env"}}),
        json!({"tool_name": "mcp__filesystem__read", "tool_input": {"command": "cat .env"}}),
    ] {
        let edge: GuardHookEdgeResultV2 = serde_json::from_slice(
            &crate::edge::evaluate_envelope_with_store(request(&root, &snapshot, payload), &store)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(edge.result["policy_action"], "review");
        assert!(edge.receipt.command_extensions.is_none());
        assert!(edge.receipt.review_scope.is_none());
    }
    for payload in [
        json!({"tool_name": "Bash", "tool_input": {"command": 7}}),
        json!({"tool_name": "Bash", "tool_input": {"command": " "}}),
        json!({"tool_name": "mcp__filesystem__read", "tool_input": {
            "command": "cat .env", "cmd": "echo changed",
        }}),
    ] {
        let edge: GuardHookEdgeResultV2 = serde_json::from_slice(
            &crate::edge::evaluate_envelope_with_store(request(&root, &snapshot, payload), &store)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(edge.result["policy_action"], "block");
        assert!(edge.receipt.review_scope.is_none());
        assert!(edge.receipt.command_extensions.is_none());
    }
    // A signed current noncommand request uses its separate policy domain;
    // missing command controls alone neither fabricate nor forbid this proof.
    let edge: GuardHookEdgeResultV2 = serde_json::from_slice(
        &crate::edge::evaluate_envelope_with_store(
            request(
                &root,
                &snapshot,
                json!({"tool_name": "Read", "tool_input": {"file_path": ".env"}}),
            ),
            &store,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(edge.result["policy_action"], "review");
    assert_eq!(
        edge.receipt.review_scope,
        Some(NativeReviewScopeV1::Noncommand)
    );
    assert!(edge.receipt.command_extensions.is_none());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn noncommand_scope_preserves_nontrivial_command_floors_and_intrinsic_blocks() {
    let root = test_root("noncommand-protected-floors");
    let key = install_test_key(&root, 86);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let mut snapshot = control_snapshot(1, 7, 11, "disabled", &key, &root);
    let controls = snapshot.command_extensions.as_mut().unwrap();
    controls.layers[0].global_lockdown = true;
    controls.effective_digest = controls.compute_effective_digest().unwrap();
    super::super::command_floor_tests::resign(&mut snapshot, &key);
    publish_marker(&store, &snapshot, "committed");
    store
        .push(&json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": snapshot}))
        .unwrap();
    for payload in [
        json!({"tool_name": "WebFetch", "tool_input": {"url": "https://example.com/docs"}}),
        json!({"tool_name": "Read", "tool_input": {"file_path": ".env"}}),
        json!({"tool_name": "mcp__filesystem__read", "tool_input": {"path": "README.md"}}),
    ] {
        let edge: GuardHookEdgeResultV2 = serde_json::from_slice(
            &crate::edge::evaluate_envelope_with_store(request(&root, &snapshot, payload), &store)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(edge.result["policy_action"], "review");
        assert_eq!(
            edge.receipt.review_scope,
            Some(NativeReviewScopeV1::Noncommand)
        );
        assert!(edge.receipt.command_extensions.is_none());
    }
    for (payload, command_bound) in [
        (
            json!({"tool_name": "Bash", "tool_input": {"command": "ollama push guard-fixture-model"}}),
            true,
        ),
        (json!({"tool_name": "kill"}), false),
    ] {
        let edge: GuardHookEdgeResultV2 = serde_json::from_slice(
            &crate::edge::evaluate_envelope_with_store(request(&root, &snapshot, payload), &store)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(edge.result["policy_action"], "block");
        assert!(edge.receipt.review_scope.is_none());
        assert_eq!(edge.receipt.command_extensions.is_some(), command_bound);
    }
    fs::remove_dir_all(root).unwrap();
}
