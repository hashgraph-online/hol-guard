use super::*;

fn native(index: usize) -> (NativeHookDecisionReceiptV1, PreToolActionV1) {
    let receipt = serde_json::from_value(json!({
        "schema":"guard-native-hook-decision-receipt.v1", "version":1, "authority":"rust",
        "decision_id":format!("{index:064x}"), "request_id":"private-request", "request_digest":"b".repeat(64),
        "harness":"codex", "event_name":"PreToolUse", "payload_kind":"inline", "policy_generation":7,
        "policy_digest":"c".repeat(64), "rule_digest":"d".repeat(64), "runtime_identity":"e".repeat(64),
        "decision":"review", "model_output_action":"allow", "policy_action":"review", "observed_policy_action":null,
        "reason_code":"private-reason", "workspace_bound":true, "source_ref_external_allowed":false,
        "reviewed_output_sha256":null, "observe_mode":false, "deadline_budget_ms":100,
        "origin_authentication":"f".repeat(64), "execution_intent_digest":"1".repeat(64)
    })).unwrap();
    let action = serde_json::from_value(json!({"schema":"guard-pre-tool-action.v1","version":1,
        "harness":"codex","event":"PreToolUse","action_type":"command","operation":"execute",
        "bounded":true,"sensitive_target":false}))
    .unwrap();
    (receipt, action)
}

#[test]
fn native_action_facts_bind_exact_workspace_app_policy_and_hide_private_bindings() {
    let actions = Actions::default();
    let (receipt, action) = native(1);
    actions.capture("/workspace/one", &receipt, action);
    let fact = actions.get(&receipt.decision_id).unwrap();
    for app in ["dashboard", "codex"] {
        assert!(fact
            .require_scope(Path::new("/workspace/one"), app, &fact.policy)
            .is_ok());
    }
    assert!(fact
        .require_scope(Path::new("/workspace/two"), "codex", &fact.policy)
        .is_err());
    assert!(fact
        .require_scope(Path::new("/workspace/one"), "claude-code", &fact.policy)
        .is_err());
    let mut policy = fact.policy.clone();
    policy.generation += 1;
    assert!(fact
        .require_scope(Path::new("/workspace/one"), "codex", &policy)
        .is_err());
    policy = fact.policy.clone();
    policy.digest = "a".repeat(64);
    assert!(fact
        .require_scope(Path::new("/workspace/one"), "codex", &policy)
        .is_err());
    policy = fact.policy.clone();
    policy.runtime = "a".repeat(64);
    assert!(fact
        .require_scope(Path::new("/workspace/one"), "codex", &policy)
        .is_err());
    let projection = format!(
        "{}{}{}",
        fact.document().text,
        fact.query(),
        fact.association()
    );
    for private in [
        "private-request",
        "private-reason",
        "/workspace/one",
        &"f".repeat(64),
        &"1".repeat(64),
    ] {
        assert!(!projection.contains(private));
    }
    assert_eq!(
        fact.association()["binding"],
        "authenticated_native_decision"
    );
    assert_eq!(fact.association()["execution_binding"], "unqualified");
    assert_eq!(fact.association()["approval_grant"], false);
}

#[test]
fn malformed_or_unauthenticated_or_other_event_facts_never_enter_the_registry() {
    let actions = Actions::default();
    for mutate in 0..5 {
        let (mut receipt, mut action) = native(2);
        match mutate {
            0 => receipt.origin_authentication = None,
            1 => receipt.execution_intent_digest = None,
            2 => receipt.policy_digest = None,
            3 => receipt.event_name = "PostToolUse".into(),
            _ => action.harness = "other".into(),
        }
        actions.capture("/workspace/one", &receipt, action);
        assert!(actions.get(&receipt.decision_id).is_err());
    }
    let (receipt, action) = native(2);
    actions.capture("/workspace/../private", &receipt, action);
    assert!(actions.get(&receipt.decision_id).is_err());
    assert!(matches!(
        actions.get("caller text"),
        Err(RuntimeError::RequestInvalid)
    ));
}

#[test]
fn bounded_expiring_nonblocking_registry_rejects_replaced_and_closed_origins() {
    let actions = Actions::default();
    for index in 1..=CAPACITY + 1 {
        let (receipt, action) = native(index);
        actions.capture("/workspace/one", &receipt, action);
    }
    assert_eq!(actions.entries.lock().unwrap().len(), CAPACITY);
    assert!(actions.get(&format!("{:064x}", 1)).is_err());
    let (mut receipt, action) = native(CAPACITY + 1);
    let before = actions.get(&receipt.decision_id).unwrap();
    receipt.execution_intent_digest = Some("2".repeat(64));
    actions.capture("/workspace/one", &receipt, action.clone());
    assert!(before != actions.get(&receipt.decision_id).unwrap());
    let mut lock = actions.entries.lock().unwrap();
    let started = Instant::now();
    actions.capture("/workspace/one", &receipt, action.clone());
    assert!(started.elapsed() < Duration::from_millis(100));
    assert!(matches!(
        actions.get(&receipt.decision_id),
        Err(RuntimeError::Busy)
    ));
    lock.back_mut().unwrap().0 = Instant::now() - TTL;
    drop(lock);
    assert!(actions.get(&receipt.decision_id).is_err());
    actions.capture("/workspace/one", &receipt, action);
    actions.clear().unwrap();
    assert!(actions.get(&receipt.decision_id).is_err());
    actions.close();
    assert!(matches!(
        actions.get(&receipt.decision_id),
        Err(RuntimeError::Cancelled)
    ));
    assert!(actions.entries.lock().unwrap().is_empty());
}
