use super::*;
use serde_json::json;

/// Vectors recorded from the pre-port Python bodies of
/// `_package_evaluation_with_current_policy_action`,
/// `_package_evaluation_with_rejected_reuse`, and
/// `_package_policy_override_evaluation`.
const VECTORS: &str = include_str!("../testdata/package_evaluation_compose_vectors.json");

fn request(kind: &str, evaluation: Value) -> PackageEvaluationComposeRequestV1 {
    PackageEvaluationComposeRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "compose-1".to_owned(),
        guard_home: "/tmp/guard-home".to_owned(),
        kind: kind.to_owned(),
        evaluation,
        current_action: None,
        approval_reuse: None,
        variant: None,
        claim_disposition: None,
        clear_command: None,
    }
}

fn from_vector(vector: &Value) -> PackageEvaluationComposeRequestV1 {
    let spec = vector["request"].as_object().unwrap();
    let text = |key: &str| spec.get(key).and_then(Value::as_str).map(str::to_owned);
    let mut out = request(spec["kind"].as_str().unwrap(), vector["evaluation"].clone());
    out.current_action = text("current_action");
    out.approval_reuse = spec.get("approval_reuse").cloned();
    out.variant = text("variant");
    out.claim_disposition = text("claim_disposition");
    out.clear_command = text("clear_command");
    out
}

fn run(request: &PackageEvaluationComposeRequestV1) -> Result<Value, String> {
    evaluate_package_evaluation_compose(request)
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

#[test]
fn matches_python_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 70);
    for vector in &vectors {
        let request = from_vector(vector);
        let result = run(&request).unwrap();
        assert_eq!(result["status"], "ok", "{}", vector["name"]);
        assert_eq!(result["request_id"], "compose-1");
        assert_eq!(
            result["request_sha256"],
            request_digest(&request).unwrap(),
            "{}",
            vector["name"]
        );
        assert_eq!(
            result["payload"]["patch"], vector["patch"],
            "{}",
            vector["name"]
        );
    }
}

fn base() -> Value {
    json!({"policy_action": "review", "reasons": [], "packages": [{"name": "a"}]})
}

#[test]
fn rejects_unknown_kind_and_schema() {
    assert_eq!(run(&request("bogus", base())).unwrap_err(), invalid());
    let mut wrong = request("current_policy_action", base());
    wrong.current_action = Some("block".to_owned());
    wrong.schema = "other".to_owned();
    assert_eq!(
        run(&wrong).unwrap_err(),
        "native_package_evaluation_compose_schema_mismatch"
    );
}

#[test]
fn rejects_malformed_inputs_instead_of_guessing() {
    let mut req = request("current_policy_action", base());
    assert_eq!(run(&req).unwrap_err(), invalid(), "missing current_action");
    req.current_action = Some("maybe".to_owned());
    assert_eq!(run(&req).unwrap_err(), invalid(), "unknown action");
    req.current_action = Some("block".to_owned());
    req.variant = Some("reused".to_owned());
    assert_eq!(run(&req).unwrap_err(), invalid(), "stray field for kind");
    for evaluation in [
        json!({"policy_action": "bogus", "reasons": [], "packages": []}),
        json!({"policy_action": "review", "reasons": [1], "packages": []}),
        json!({"policy_action": "review", "reasons": [], "packages": ["x"]}),
        json!({"policy_action": "review", "reasons": []}),
        json!({"policy_action": "review", "reasons": [], "packages": [], "extra": 1}),
        json!("nope"),
    ] {
        let mut bad = request("current_policy_action", evaluation);
        bad.current_action = Some("block".to_owned());
        assert_eq!(run(&bad).unwrap_err(), invalid());
    }
}

#[test]
fn rejects_malformed_reuse_evidence() {
    let good = json!({"action": "block", "status": "rejected", "reason_code": "approval_reuse_claim_failed",
        "current_action": "review", "saved_action": "allow", "should_claim": false});
    let mut req = request("rejected_reuse", base());
    req.approval_reuse = Some(good.clone());
    assert!(run(&req).is_ok());
    for (key, value) in [
        ("action", json!("nope")),
        ("status", json!("maybe")),
        ("reason_code", json!(" ")),
        ("current_action", json!(null)),
        ("saved_action", json!("nope")),
        ("should_claim", json!("yes")),
    ] {
        let mut evidence = good.clone();
        evidence[key] = value;
        req.approval_reuse = Some(evidence);
        assert_eq!(run(&req).unwrap_err(), invalid(), "{key}");
    }
    req.approval_reuse = None;
    assert_eq!(run(&req).unwrap_err(), invalid());
}

#[test]
fn saved_allow_and_block_validate_variant_facts() {
    let reuse = json!({"action": "allow", "status": "accepted", "reason_code": "approval_reuse_accepted",
        "current_action": "allow", "saved_action": "allow", "should_claim": true});
    let mut allow = request("saved_allow", base());
    allow.approval_reuse = Some(reuse.clone());
    assert_eq!(run(&allow).unwrap_err(), invalid(), "variant required");
    allow.variant = Some("claimed_revalidated".to_owned());
    allow.claim_disposition = Some("consumed".to_owned());
    assert_eq!(
        run(&allow).unwrap_err(),
        invalid(),
        "disposition only on reused"
    );
    allow.variant = Some("reused".to_owned());
    allow.claim_disposition = Some("bogus".to_owned());
    assert_eq!(run(&allow).unwrap_err(), invalid());
    let mut block = request("saved_block", base());
    block.approval_reuse = Some(reuse);
    assert_eq!(
        run(&block).unwrap_err(),
        invalid(),
        "clear command required"
    );
    let mut archive = request("external_archive_override", base());
    assert_eq!(run(&archive).unwrap_err(), invalid());
    archive.variant = Some("elsewhere".to_owned());
    assert_eq!(run(&archive).unwrap_err(), invalid());
}

#[test]
fn archive_override_verdict_is_runtime_chosen() {
    let mut req = request("external_archive_override", base());
    req.variant = Some("shim_delegated".to_owned());
    let patch = &run(&req).unwrap()["payload"]["patch"];
    assert_eq!(patch["policy_action"], "allow");
    assert_eq!(patch["decision"], "allow");
}

#[test]
fn archive_block_always_blocks() {
    for variant in ["launch_unbound", "mcp_unbound", "binding_unavailable"] {
        let mut req = request("external_archive_override", base());
        req.variant = Some(variant.to_owned());
        let patch = &run(&req).unwrap()["payload"]["patch"];
        assert_eq!(patch["policy_action"], "block");
        assert_eq!(patch["decision"], "block");
        assert_eq!(patch["packages"][0]["decision"], "block");
    }
}

#[test]
fn repeated_saved_overrides_do_not_stack_reasons() {
    // Evidence exactly as Python's `to_evidence()` emits it: explicit nulls,
    // the context-token flag, and non-default original types.
    let evidence = json!({"action": "allow", "status": "accepted",
        "reason_code": "approval_reuse_accepted", "current_action": "allow",
        "saved_action": "allow", "should_claim": true,
        "current_normalization_reason_code": null, "saved_normalization_reason_code": null,
        "original_current_action": null, "original_saved_action": null,
        "original_current_type": "GuardAction", "original_saved_type": "str",
        "saved_artifact_hash_is_context_token": true});
    let other = json!({"code": "other", "message": "m"});
    for (kind, variant, clear) in [
        ("saved_allow", Some("reused"), None),
        ("saved_block", None, Some("hol-guard policies clear")),
    ] {
        let mut req = request(kind, base());
        req.approval_reuse = Some(evidence.clone());
        req.variant = variant.map(str::to_owned);
        req.clear_command = clear.map(str::to_owned);
        let first = run(&req).unwrap()["payload"]["patch"]["reasons"][0].clone();
        assert_eq!(first["approval_reuse"], evidence);
        let mut again = req.clone();
        again.evaluation = json!({"policy_action": "review", "packages": [{"name": "a"}],
            "reasons": [first.clone(), other.clone(), first.clone()]});
        let patch = &run(&again).unwrap()["payload"]["patch"];
        assert_eq!(patch["reasons"], json!([first, other]), "{kind}");
    }
}
