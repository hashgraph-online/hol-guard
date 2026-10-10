use super::*;
struct NoopEval;

impl PackageEvalApi for NoopEval {
    fn evaluate_package_request_artifact(
        &self,
        _artifact: &GuardArtifact,
        _store: &dyn crate::local_supply_chain::SupplyChainStore,
        _workspace_dir: &std::path::Path,
        _now: &str,
        _external_archive_network_authorized: bool,
        _retain_external_archive_blob: bool,
    ) -> Result<crate::local_supply_chain::PackageRequestEvaluation, String> {
        unreachable!("test seam only supplies user_copy/decision mapping")
    }

    fn supply_chain_user_copy(
        &self,
        title: &str,
        summary: &str,
        next_step: Option<&str>,
        dashboard_url: Option<&str>,
        harness_message: Option<&str>,
    ) -> Map<String, Value> {
        let mut copy = Map::new();
        copy.insert("title".into(), Value::String(title.to_string()));
        copy.insert("summary".into(), Value::String(summary.to_string()));
        copy.insert(
            "next_step".into(),
            next_step.map_or(Value::Null, |v| Value::String(v.to_string())),
        );
        copy.insert(
            "dashboard_url".into(),
            dashboard_url.map_or(Value::Null, |v| Value::String(v.to_string())),
        );
        copy.insert(
            "harness_message".into(),
            harness_message.map_or(Value::Null, |v| Value::String(v.to_string())),
        );
        copy
    }
    fn package_decision_for_action(&self, action: &str) -> String {
        // Mirror the Python `_package_decision_for_action` mapping directly —
        // the trait seam supplies this for real evaluators; the test double
        // only needs the same pure mapping to satisfy the impl.
        match action {
            "block" => "block",
            "review" | "require-reapproval" | "sandbox-required" => "ask",
            "warn" => "warn",
            _ => "allow",
        }
        .to_string()
    }
}

fn base_eval() -> Map<String, Value> {
    serde_json::from_str::<Map<String, Value>>(
        r#"{"bundle_version":"b1","cache_status":"miss","decision":"ask","enforcement":"enforce","entitlement_state":"entitled","evidence_ids":[],"exception_id":null,"external_archive_source_hashes":[],"matched_rule_id":null,"package_intent_hash":"abc123","packages":[{"decision":"ask","name":"left-pad","requestedVersion":"1.0.0"},{"name":"raw"}],"policy_action":"review","policy_version":"p1","reasons":[{"code":"existing_reason","message":"keep me","severity":"low","source":"guard-local"}],"record_monitor_evidence":false,"refresh_required":false,"risk_summary":"original summary","user_copy":{"dashboard_url":"https://dash","harness_message":"HM","next_step":"ns","summary":"S","title":"T"},"workspace_fingerprint":"wf1"}"#,
    )
    .unwrap()
}

fn reuse(
    action: GuardAction,
    status: &str,
    reason_code: &str,
    current: GuardAction,
    saved: Option<GuardAction>,
    should_claim: bool,
) -> ApprovalReuseDecision {
    ApprovalReuseDecision {
        action,
        status: Box::leak(status.to_string().into_boxed_str()),
        reason_code: reason_code.to_string(),
        current_action: current,
        saved_action: saved,
        should_claim,
        current_normalization_reason_code: None,
        saved_normalization_reason_code: None,
        original_current_action: Some(current.as_str().to_string()),
        original_saved_action: saved.map(|s| s.as_str().to_string()),
        original_current_type: "str".to_string(),
        original_saved_type: saved.map(|_| "str".to_string()),
        saved_artifact_hash_is_context_token: None,
    }
}

fn canon(v: &Map<String, Value>) -> String {
    let mut buf = Vec::new();
    guard_contracts::write_canonical_json(&Value::Object(v.clone()), &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

#[test]
fn decision_for_action_mapping() {
    assert_eq!(package_decision_for_action(GuardAction::Block), "block");
    assert_eq!(
        package_decision_for_action(GuardAction::SandboxRequired),
        "ask"
    );
    assert_eq!(
        package_decision_for_action(GuardAction::RequireReapproval),
        "ask"
    );
    assert_eq!(package_decision_for_action(GuardAction::Review), "ask");
    assert_eq!(package_decision_for_action(GuardAction::Warn), "warn");
    assert_eq!(package_decision_for_action(GuardAction::Allow), "allow");
}

#[test]
fn requires_review_truth_table() {
    for (pa, dec, want) in [
        (Some("block"), Some("allow"), true),
        (Some("allow"), Some("ask"), true),
        (Some("warn"), Some("warn"), false),
        (Some("require-reapproval"), Some("allow"), true),
        (Some("review"), Some("review"), false),
        (Some("allow"), Some("allow"), false),
        (None, None, false),
    ] {
        let mut e = Map::new();
        if let Some(p) = pa {
            e.insert("policy_action".into(), json!(p));
        }
        if let Some(d) = dec {
            e.insert("decision".into(), json!(d));
        }
        assert_eq!(
            stored_package_policy_evaluation_requires_review(&Value::Object(e)),
            want,
            "pa={pa:?} dec={dec:?}"
        );
    }
}

#[test]
fn uses_saved_package_approval() {
    let e = json!({"reasons":[{"code":"saved_package_approval"},{"code":"other"}]});
    assert!(evaluation_uses_saved_package_approval(&e));
    let e2 = json!({"reasons":[{"code":"other"}]});
    assert!(!evaluation_uses_saved_package_approval(&e2));
    let e3 = json!({"reasons":[]});
    assert!(!evaluation_uses_saved_package_approval(&e3));
    let e4 = json!({});
    assert!(!evaluation_uses_saved_package_approval(&e4));
}

#[test]
fn approval_reuse_reason_message_verbatim() {
    let cases = [
        ("approval_reuse_current_block", "Saved approval was rejected because current package policy blocks this request."),
        ("approval_reuse_sandbox_required", "Saved approval was rejected because current package policy requires sandbox enforcement."),
        ("approval_reuse_reapproval_required", "Saved approval was rejected because current package policy requires fresh approval."),
        ("approval_reuse_integrity_failure", "Saved approval was rejected because its integrity could not be verified."),
        ("approval_reuse_identity_changed", "Saved approval was rejected because the current package identity or scope changed."),
        ("approval_reuse_content_changed", "Saved approval was rejected because the current package content or execution context changed."),
        ("approval_reuse_claim_failed", "Saved approval was rejected because it changed, expired, or was already consumed."),
        ("approval_reuse_context_changed_after_claim", "Saved approval was rejected because retained authority changed after it was claimed."),
        ("approval_reuse_saved_action_unknown", "Saved approval was rejected because its action is unknown or malformed."),
    ];
    for (code, want) in cases {
        let r = reuse(
            GuardAction::Review,
            "rejected",
            code,
            GuardAction::Review,
            None,
            false,
        );
        assert_eq!(approval_reuse_reason_message(&r), want, "{code}");
    }
    let r = reuse(
        GuardAction::Review,
        "rejected",
        "approval_reuse_no_saved_decision",
        GuardAction::Review,
        None,
        false,
    );
    assert_eq!(
        approval_reuse_reason_message(&r),
        "Saved package policy was not reused (approval_reuse_no_saved_decision)."
    );
    let r2 = reuse(
        GuardAction::Review,
        "rejected",
        "something_else",
        GuardAction::Review,
        None,
        false,
    );
    assert_eq!(
        approval_reuse_reason_message(&r2),
        "Saved package policy was not reused (something_else)."
    );
}

#[test]
fn clear_command_matches_oracle() {
    let artifact = GuardArtifact {
        artifact_id: "npm:left-pad".into(),
        name: "left-pad".into(),
        harness: "claude-code".into(),
        artifact_type: "package-request".into(),
        source_scope: "local".into(),
        config_path: "/cfg".into(),
        command: None,
        args: vec![],
        url: None,
        transport: None,
        publisher: None,
        metadata: Value::Object(Map::new()),
        runtime_private_metadata: Value::Object(Map::new()),
    };
    let full: Map<String, Value> = serde_json::from_str(
        r#"{"scope":"artifact","decision_id":7,"harness":"codex","artifact_id":"npm:x","artifact_hash":"h h","workspace":"/w s","publisher":"pub's"}"#,
    ).unwrap();
    assert_eq!(
        saved_package_policy_clear_command(&artifact, "hash", &full, "/work dir"),
        "hol-guard policies clear --decision-id 7 --harness codex --scope artifact --artifact-id npm:x --artifact-hash 'h h' --policy-workspace '/w s' --publisher 'pub'\"'\"'s'"
    );
    let min = Map::new();
    assert_eq!(
        saved_package_policy_clear_command(&artifact, "hash", &min, "/work dir"),
        "hol-guard policies clear --harness claude-code --scope artifact --artifact-id npm:left-pad --policy-workspace '/work dir'"
    );
    let global: Map<String, Value> =
        serde_json::from_str(r#"{"scope":"global","workspace":"/weird dir"}"#).unwrap();
    assert_eq!(
        saved_package_policy_clear_command(&artifact, "hash", &global, "/work dir"),
        "hol-guard policies clear --harness claude-code --scope global --artifact-id npm:left-pad --policy-workspace '/weird dir'"
    );
    let blank: Map<String, Value> =
        serde_json::from_str(r#"{"scope":"harness","artifact_id":""}"#).unwrap();
    assert_eq!(
        saved_package_policy_clear_command(&artifact, "hash", &blank, "/work dir"),
        "hol-guard policies clear --harness claude-code --scope harness --artifact-id npm:left-pad"
    );
}

#[test]
fn approval_reuse_evidence_oracle() {
    let eval = json!({"reasons":[
        {"code":"a","approval_reuse":{"reason_code":"rc","status":"rejected"}},
        {"code":"b","approval_reuse":"notdict"},
        {"code":"c"},
        {"code":"d","approval_reuse":{"source":"overridden","x":1}}
    ]});
    let items = package_approval_reuse_evidence(&eval);
    assert_eq!(items.len(), 2);
    let mut b0 = Vec::new();
    guard_contracts::write_canonical_json(&Value::Object(items[0].clone()), &mut b0).unwrap();
    assert_eq!(
        String::from_utf8(b0).unwrap(),
        r#"{"reason_code":"rc","source":"approval_reuse","status":"rejected"}"#
    );
    let mut b1 = Vec::new();
    guard_contracts::write_canonical_json(&Value::Object(items[1].clone()), &mut b1).unwrap();
    assert_eq!(
        String::from_utf8(b1).unwrap(),
        r#"{"source":"overridden","x":1}"#
    );
}

#[test]
fn current_policy_action_block_oracle() {
    let eval = NoopEval;
    let m = base_eval();
    let out = package_evaluation_with_current_policy_action(&eval, &m, GuardAction::Block);
    let got = canon(&out);
    let want = r#"{"bundle_version":"b1","cache_status":"miss","decision":"block","enforcement":"enforce","entitlement_state":"entitled","evidence_ids":[],"exception_id":null,"external_archive_source_hashes":[],"matched_rule_id":null,"package_intent_hash":"abc123","packages":[{"decision":"block","name":"left-pad","requestedVersion":"1.0.0"},{"decision":"block","name":"raw"}],"policy_action":"block","policy_version":"p1","reasons":[{"code":"current_package_policy","message":"HOL Guard's current package policy blocks `left-pad@1.0.0`.","policy_action":"block","severity":"high","source":"guard-local"},{"code":"existing_reason","message":"keep me","severity":"low","source":"guard-local"}],"record_monitor_evidence":false,"refresh_required":false,"risk_summary":"HOL Guard's current package policy blocks `left-pad@1.0.0`.","user_copy":{"dashboard_url":null,"harness_message":"HOL Guard's current package policy blocks `left-pad@1.0.0`.","next_step":"Review the current package request in HOL Guard, then retry.","summary":"HOL Guard's current package policy blocks `left-pad@1.0.0`.","title":"Current package policy"},"workspace_fingerprint":"wf1"}"#;
    assert_eq!(got, want);
}

#[test]
fn current_policy_action_noop_when_same() {
    let eval = NoopEval;
    let mut m = base_eval();
    m.insert("policy_action".into(), json!("block"));
    let out = package_evaluation_with_current_policy_action(&eval, &m, GuardAction::Block);
    assert_eq!(canon(&out), canon(&m));
}

#[test]
fn rejected_reuse_oracle() {
    let eval = NoopEval;
    let m = base_eval();
    let r = reuse(
        GuardAction::Block,
        "rejected",
        "approval_reuse_current_block",
        GuardAction::Block,
        Some(GuardAction::Allow),
        false,
    );
    let out = package_evaluation_with_rejected_reuse(&eval, &m, &r);
    let got = canon(&out);
    let want = r#"{"bundle_version":"b1","cache_status":"miss","decision":"block","enforcement":"enforce","entitlement_state":"entitled","evidence_ids":[],"exception_id":null,"external_archive_source_hashes":[],"matched_rule_id":null,"package_intent_hash":"abc123","packages":[{"decision":"block","name":"left-pad","requestedVersion":"1.0.0"},{"decision":"block","name":"raw"}],"policy_action":"block","policy_version":"p1","reasons":[{"approval_reuse":{"action":"block","current_action":"block","original_current_action":"block","original_current_type":"str","original_saved_action":"allow","original_saved_type":"str","reason_code":"approval_reuse_current_block","saved_action":"allow","should_claim":false,"status":"rejected"},"code":"approval_reuse_current_block","message":"Saved approval was rejected because current package policy blocks this request.","severity":"high","source":"guard-local"},{"code":"existing_reason","message":"keep me","severity":"low","source":"guard-local"}],"record_monitor_evidence":false,"refresh_required":false,"risk_summary":"Saved approval was rejected because current package policy blocks this request.","user_copy":{"dashboard_url":null,"harness_message":"Saved approval was rejected because current package policy blocks this request.","next_step":"Review the current package request in HOL Guard, then retry.","summary":"Saved approval was rejected because current package policy blocks this request.","title":"Saved approval not reusable"},"workspace_fingerprint":"wf1"}"#;
    assert_eq!(got, want);
}

#[test]
fn rejected_reuse_same_action_reasons_only() {
    let eval = NoopEval;
    let mut m = base_eval();
    m.insert("policy_action".into(), json!("require-reapproval"));
    let r = ApprovalReuseDecision {
        action: GuardAction::RequireReapproval,
        status: "rejected",
        reason_code: "approval_reuse_saved_action_unknown".to_string(),
        current_action: GuardAction::Review,
        saved_action: Some(GuardAction::RequireReapproval),
        should_claim: false,
        current_normalization_reason_code: None,
        saved_normalization_reason_code: Some("guard_action_unknown".to_string()),
        original_current_action: Some("review".to_string()),
        original_saved_action: Some("bogus".to_string()),
        original_current_type: "str".to_string(),
        original_saved_type: Some("str".to_string()),
        saved_artifact_hash_is_context_token: None,
    };
    let out = package_evaluation_with_rejected_reuse(&eval, &m, &r);
    let got = canon(&out);
    let want = r#"{"bundle_version":"b1","cache_status":"miss","decision":"ask","enforcement":"enforce","entitlement_state":"entitled","evidence_ids":[],"exception_id":null,"external_archive_source_hashes":[],"matched_rule_id":null,"package_intent_hash":"abc123","packages":[{"decision":"ask","name":"left-pad","requestedVersion":"1.0.0"},{"name":"raw"}],"policy_action":"require-reapproval","policy_version":"p1","reasons":[{"approval_reuse":{"action":"require-reapproval","current_action":"review","original_current_action":"review","original_current_type":"str","original_saved_action":"bogus","original_saved_type":"str","reason_code":"approval_reuse_saved_action_unknown","saved_action":"require-reapproval","saved_normalization_reason_code":"guard_action_unknown","should_claim":false,"status":"rejected"},"code":"approval_reuse_saved_action_unknown","message":"Saved approval was rejected because its action is unknown or malformed.","severity":"high","source":"guard-local"},{"code":"existing_reason","message":"keep me","severity":"low","source":"guard-local"}],"record_monitor_evidence":false,"refresh_required":false,"risk_summary":"original summary","user_copy":{"dashboard_url":"https://dash","harness_message":"HM","next_step":"ns","summary":"S","title":"T"},"workspace_fingerprint":"wf1"}"#;
    assert_eq!(got, want);
}

#[test]
fn policy_override_oracle() {
    let eval = NoopEval;
    let m = base_eval();
    let r = reuse(
        GuardAction::Block,
        "rejected",
        "approval_reuse_current_block",
        GuardAction::Block,
        Some(GuardAction::Allow),
        false,
    );
    let out = package_policy_override_evaluation(
        &eval,
        &m,
        "allow",
        "allow",
        "Saved package policy",
        "sum",
        "hm",
        None,
        "saved_package_approval",
        "rm",
        Some(&r),
        Some("consumed"),
    );
    let got = canon(&out);
    let want = r#"{"bundle_version":"b1","cache_status":"miss","decision":"allow","enforcement":"enforce","entitlement_state":"entitled","evidence_ids":[],"exception_id":null,"external_archive_source_hashes":[],"matched_rule_id":null,"package_intent_hash":"abc123","packages":[{"decision":"allow","name":"left-pad","requestedVersion":"1.0.0"},{"decision":"allow","name":"raw"}],"policy_action":"allow","policy_version":"p1","reasons":[{"approval_claim_disposition":"consumed","approval_reuse":{"action":"block","current_action":"block","original_current_action":"block","original_current_type":"str","original_saved_action":"allow","original_saved_type":"str","reason_code":"approval_reuse_current_block","saved_action":"allow","should_claim":false,"status":"rejected"},"code":"saved_package_approval","message":"rm","severity":"low","source":"guard-local"},{"code":"existing_reason","message":"keep me","severity":"low","source":"guard-local"}],"record_monitor_evidence":false,"refresh_required":false,"risk_summary":"hm","user_copy":{"dashboard_url":null,"harness_message":"hm","next_step":null,"summary":"sum","title":"Saved package policy"},"workspace_fingerprint":"wf1"}"#;
    assert_eq!(got, want);
}

#[test]
fn policy_override_min_oracle() {
    let eval = NoopEval;
    let m = base_eval();
    let out = package_policy_override_evaluation(
        &eval,
        &m,
        "ask",
        "review",
        "T2",
        "S2",
        "HM2",
        Some("step"),
        "rc2",
        "rm2",
        None,
        None,
    );
    let got = canon(&out);
    let want = r#"{"bundle_version":"b1","cache_status":"miss","decision":"ask","enforcement":"enforce","entitlement_state":"entitled","evidence_ids":[],"exception_id":null,"external_archive_source_hashes":[],"matched_rule_id":null,"package_intent_hash":"abc123","packages":[{"decision":"ask","name":"left-pad","requestedVersion":"1.0.0"},{"decision":"ask","name":"raw"}],"policy_action":"review","policy_version":"p1","reasons":[{"code":"rc2","message":"rm2","severity":"low","source":"guard-local"},{"code":"existing_reason","message":"keep me","severity":"low","source":"guard-local"}],"record_monitor_evidence":false,"refresh_required":false,"risk_summary":"HM2","user_copy":{"dashboard_url":null,"harness_message":"HM2","next_step":"step","summary":"S2","title":"T2"},"workspace_fingerprint":"wf1"}"#;
    assert_eq!(got, want);
}
