use super::*;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::PathBuf;

/// The real `guard.db` schema the shared decision lookup and the claim read:
/// the override resolves saved decisions through the lookup op, which selects
/// the full policy row and stamps the authority revision a claim compares, so
/// a reduced schema no longer exercises the override's own path.
fn seed_store(home: &std::path::Path) {
    crate::policy_decision_lookup_op::tests::seed_store(&home.join("guard.db"));
}

fn temp_home(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let home = std::env::temp_dir().join(format!(
        "hol-guard-apply-stored-{tag}-{}-{nonce}",
        std::process::id(),
    ));
    std::fs::create_dir_all(&home).unwrap();
    home
}

/// The approval-context token a package request's artifact hash is. A plain
/// digest is not one, and `validate_context_tokens` reads a row carrying one as
/// changed content, so the claim would never be attempted for it.
fn approval_context_token() -> String {
    crate::context_digest::build_context_token(&guard_contracts::ContextDigestComponentsV1 {
        identity: json!({"artifact_id": "command:install", "harness": "claude"}),
        content: json!({"packages": [{"ecosystem": "npm", "package_name": "left-pad"}]}),
        capabilities: json!({}),
        policy: json!({}),
        sandbox: json!({}),
        extension_control_digest: String::new(),
    })
    .expect("the token is built from canonical JSON")
}

fn base_evaluation() -> Value {
    json!({
        "decision": "allow",
        "policy_action": "allow",
        "enforcement": "audit",
        "entitlement_state": "granted",
        "cache_status": "miss",
        "workspace_fingerprint": "wf",
        "reasons": [],
        "packages": [{"ecosystem": "npm", "package_name": "left-pad"}],
        "matched_rule_id": null,
        "exception_id": null,
        "risk_summary": {},
        "record_monitor_evidence": false,
        "external_archive_source_hashes": [],
        "user_copy": {"title": "t", "summary": "s"},
        "package_intent_hash": "ih",
        "policy_version": "pv",
        "bundle_version": null,
        "refresh_required": false,
        "evidence_ids": [],
    })
}

fn request_for(home: &std::path::Path) -> ApplyStoredPackagePolicyRequestV1 {
    ApplyStoredPackagePolicyRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "apply-stored-1".into(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        evaluation: base_evaluation(),
        artifact: json!({
            "artifact_id": "command:install",
            "name": "install",
            "harness": "claude",
            "artifact_type": "package_request",
            "source_scope": "workspace",
            "config_path": "",
            "args": [],
            "metadata": {},
        }),
        artifact_hash: approval_context_token(),
        workspace_dir: home.to_string_lossy().into_owned(),
        now: "2026-10-06T00:00:00Z".into(),
        runtime_private_metadata: None,
        current_action: None,
        claim_saved_approval: false,
    }
}

#[test]
fn empty_store_returns_evaluation_unchanged() {
    let home = temp_home("empty");
    seed_store(&home);
    let bytes = evaluate_apply_stored_package_policy(&request_for(&home)).unwrap();
    let result: ApplyStoredPackagePolicyResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.schema, PACKAGE_AUTHORITY_RESULT_SCHEMA);
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    assert_eq!(result.request_id, "apply-stored-1");
    // No saved approval -> the override returns the evaluation untouched.
    assert_eq!(result.payload.unwrap(), base_evaluation());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn resident_dispatch_round_trip() {
    let home = temp_home("dispatch");
    seed_store(&home);
    let envelope = serde_json::to_vec(&json!({
        "operation": "apply_stored_package_policy",
        "request": serde_json::to_value(request_for(&home)).unwrap(),
    }))
    .unwrap();
    let bytes = crate::resident_ops::evaluate_resident_bytes(&envelope, None).unwrap();
    let result: ApplyStoredPackagePolicyResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.status, "ok");
    assert_eq!(result.payload.unwrap(), base_evaluation());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn schema_mismatch_returns_error_result() {
    let home = temp_home("schema");
    seed_store(&home);
    let mut request = request_for(&home);
    request.schema = "wrong-schema".into();
    let bytes = evaluate_apply_stored_package_policy(&request).unwrap();
    let result: ApplyStoredPackagePolicyResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "schema_mismatch");
    let _ = std::fs::remove_dir_all(&home);
}

/// A saved allow the lookup answers with and a claim can take: an artifact-scope
/// row from a remote policy source, whose integrity the claim treats as
/// protected without local key material, so the claim turns on the authority
/// revision and the row identity alone.
fn seed_saved_allow(home: &std::path::Path) {
    let conn = Connection::open(home.join("guard.db")).unwrap();
    conn.execute(
        "insert into policy_decisions
           (decision_id, harness, scope, artifact_id, action, artifact_hash,
            source, created_at, updated_at)
         values (11, 'claude', 'artifact', 'command:install', 'allow', ?1,
                 'cloud-signed-memory', '2026-10-01T00:00:00+00:00',
                 '2026-10-01T00:00:00+00:00')",
        [approval_context_token()],
    )
    .unwrap();
}

#[test]
fn the_resident_lookup_reports_the_saved_decision_identifier() {
    let home = temp_home("decision-id");
    seed_store(&home);
    seed_saved_allow(&home);
    let store = ResidentSupplyChainStore::new(&home.join("guard.db"), &home);
    let lookup = store.resolve_policy_decision_lookup(
        "claude",
        "command:install",
        Some(approval_context_token().as_str()),
        "package-request-workspace:v2:unused",
        None,
        "2026-10-06T00:00:00Z",
        false,
    );
    let decision = lookup.decision.expect("the saved row is read");
    // Without this column the override cannot name the decision it claims and
    // returns every saved approval unapplied.
    assert_eq!(decision["decision_id"], json!(11));
    assert_eq!(decision["action"], json!("allow"));
    assert_eq!(decision["artifact_hash"], json!(approval_context_token()));
    // The revision the claim compares against the store's current one. A
    // decision resolved without it can never be claimed, so a saved allow
    // would never be applied.
    assert_eq!(decision["_approval_authority_revision"], json!(5));
    let _ = std::fs::remove_dir_all(&home);
}

/// The failure event is written into the same database the lookup could not
/// query. A store with no schema drops that insert, so the operation result
/// has to carry the lookup code while the review evaluation stays put.
#[test]
fn a_store_without_a_schema_reports_the_lookup_error_on_the_result() {
    let home = temp_home("lookup-error-op");
    let mut request = request_for(&home);
    let mut evaluation = base_evaluation();
    evaluation["decision"] = json!("review");
    evaluation["policy_action"] = json!("review");
    request.evaluation = evaluation.clone();
    let bytes = evaluate_apply_stored_package_policy(&request).unwrap();
    let result: ApplyStoredPackagePolicyResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "native_policy_decision_lookup_query_failed");
    assert_eq!(result.payload.as_ref(), Some(&evaluation));
    let conn = Connection::open(home.join("guard.db")).unwrap();
    let recorded = conn.query_row(
        "SELECT COUNT(*) FROM guard_events WHERE event_name = ?1",
        ["package_policy_lookup_failed"],
        |row| row.get::<_, i64>(0),
    );
    assert!(
        recorded.is_err(),
        "the failure event must not land in a store with no schema"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_store_the_lookup_cannot_query_reports_the_error_code() {
    let home = temp_home("lookup-error");
    let store = ResidentSupplyChainStore::new(&home.join("guard.db"), &home);
    let lookup = store.resolve_policy_decision_lookup(
        "claude",
        "command:install",
        Some("guard-approval-context:v1:missing"),
        "package-request-workspace:v2:unused",
        None,
        "2026-10-06T00:00:00Z",
        false,
    );
    assert!(lookup.decision.is_none());
    assert_eq!(
        lookup.error.as_deref(),
        Some("native_policy_decision_lookup_query_failed")
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_saved_allow_is_claimed_and_applied_to_the_evaluation() {
    let home = temp_home("claimed");
    seed_store(&home);
    seed_saved_allow(&home);
    let mut request = request_for(&home);
    request.claim_saved_approval = true;
    // The package lane settled on review; a claimed approval is only visible
    // when the evaluation did not already carry an allow.
    let mut evaluation = base_evaluation();
    evaluation["decision"] = json!("review");
    evaluation["policy_action"] = json!("review");
    request.evaluation = evaluation;
    let bytes = evaluate_apply_stored_package_policy(&request).unwrap();
    let result: ApplyStoredPackagePolicyResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.status, "ok");
    let payload = result.payload.unwrap();
    assert_eq!(payload["decision"], json!("allow"));
    assert_eq!(payload["policy_action"], json!("allow"));
    assert_eq!(payload["saved_approval_applied"], json!(true));
    assert_eq!(payload["saved_approval_decision_id"], json!(11));
    let _ = std::fs::remove_dir_all(&home);
}
