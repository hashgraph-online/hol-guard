use super::*;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::PathBuf;

/// Minimal `guard.db` carrying only the tables the override reads.
fn seed_store(home: &std::path::Path) {
    let conn = Connection::open(home.join("guard.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE policy_decisions (
           decision_id INTEGER PRIMARY KEY, scope TEXT, artifact_id TEXT,
           harness TEXT, artifact_hash TEXT, publisher TEXT, workspace TEXT,
           decision TEXT, updated_at TEXT, occurred_at TEXT,
           approval_context_token TEXT, expires_at TEXT, claim_nonce TEXT,
           decision_hash TEXT
        );",
    )
    .unwrap();
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
        artifact_hash: "deadbeef".into(),
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
