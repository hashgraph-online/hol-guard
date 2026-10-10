use super::*;
use serde_json::json;

fn temp_home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "approval_gate_op_test_{}_{}_{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn base_request(method: ApprovalGateMethodV1, home: &Path) -> ApprovalGateRequestV1 {
    ApprovalGateRequestV1 {
        schema: APPROVAL_GATE_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        guard_home: home.to_string_lossy().to_string(),
        method,
        params: None,
        approval_gate_input: None,
        approval_gate_grant: None,
        strict: false,
        purpose: None,
        now: None,
        duration_seconds: None,
        device_label: None,
        session_signals: vec!["sid=test".to_owned()],
    }
}

/// `public_config` returns the 11-key disabled snapshot for a fresh home.
#[test]
fn public_config_round_trip() {
    let home = temp_home("cfg");
    let bytes =
        evaluate_approval_gate_request(&base_request(ApprovalGateMethodV1::PublicConfig, &home))
            .unwrap();
    let r: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(r["status"].as_str().unwrap(), "ok");
    assert_eq!(r["schema"].as_str().unwrap(), APPROVAL_GATE_RESULT_SCHEMA);
    assert_eq!(r["request_id"].as_str().unwrap(), "req-1");
    assert!(!r["payload"]["enabled"].as_bool().unwrap());
    assert!(!r["payload"]["totp_enabled"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(&home);
}

/// `create_verifier` emits the pbkdf2_sha256 dict for a long password.
#[test]
fn create_verifier_round_trip() {
    let home = temp_home("ver");
    let mut req = base_request(ApprovalGateMethodV1::CreateVerifier, &home);
    req.approval_gate_input = Some(ApprovalGateInputWireV1 {
        password: Some("correct-horse-battery".to_owned()),
        ..Default::default()
    });
    let r: Value = serde_json::from_slice(&evaluate_approval_gate_request(&req).unwrap()).unwrap();
    assert_eq!(r["status"].as_str().unwrap(), "ok");
    assert_eq!(r["payload"]["algorithm"].as_str().unwrap(), "pbkdf2_sha256");
    assert_eq!(r["payload"]["iterations"].as_i64().unwrap(), 310_000);
    assert_eq!(r["payload"]["salt"].as_str().unwrap().len(), 24);
    let _ = std::fs::remove_dir_all(&home);
}

/// `create_verifier` with a short password → `approval_gate_weak_password`.
#[test]
fn create_verifier_weak_password_errors() {
    let home = temp_home("weak");
    let mut req = base_request(ApprovalGateMethodV1::CreateVerifier, &home);
    req.approval_gate_input = Some(ApprovalGateInputWireV1 {
        password: Some("short".to_owned()),
        ..Default::default()
    });
    let r: Value = serde_json::from_slice(&evaluate_approval_gate_request(&req).unwrap()).unwrap();
    assert_eq!(r["status"].as_str().unwrap(), "error");
    assert_eq!(r["code"].as_str().unwrap(), "approval_gate_weak_password");
    assert_eq!(r["error_status"].as_i64().unwrap(), 400);
    let _ = std::fs::remove_dir_all(&home);
}

/// `validate_grant` on an unknown grant id → `approval_gate_required` (the
/// grant isn't in the table — fail-closed, not a panic).
#[test]
fn validate_unknown_grant_errors() {
    let home = temp_home("vg");
    let mut req = base_request(ApprovalGateMethodV1::ValidateGrant, &home);
    req.strict = true;
    req.purpose = Some("settings_write".to_owned());
    req.approval_gate_grant = Some(ApprovalGateGrantWireV1 {
        grant_id: "missing".to_owned(),
        purpose: "settings_write".to_owned(),
        issued_at: "2026-10-02T00:00:00+00:00".to_owned(),
        expires_at: "2099-10-02T00:00:00+00:00".to_owned(),
        action: "".to_owned(),
        scope: "local".to_owned(),
        subject: "".to_owned(),
        session_nonce: "".to_owned(),
        factor_set: vec!["password".to_owned()],
        strict: true,
        used_cooldown: false,
        cooldown_expires_at: None,
        password_verified: true,
        totp_verified: false,
    });
    let r: Value = serde_json::from_slice(&evaluate_approval_gate_request(&req).unwrap()).unwrap();
    assert_eq!(r["status"].as_str().unwrap(), "error");
    assert_eq!(r["code"].as_str().unwrap(), "approval_gate_required");
    let _ = std::fs::remove_dir_all(&home);
}

/// `audit_payload` echoes purpose + grant presence in the nested envelope.
#[test]
fn audit_payload_wraps_gate_block() {
    let home = temp_home("audit");
    let mut req = base_request(ApprovalGateMethodV1::AuditPayload, &home);
    req.purpose = Some("policy_write".to_owned());
    let r: Value = serde_json::from_slice(&evaluate_approval_gate_request(&req).unwrap()).unwrap();
    assert_eq!(r["status"].as_str().unwrap(), "ok");
    let gate = &r["payload"]["approval_gate"];
    assert_eq!(gate["purpose"].as_str().unwrap(), "policy_write");
    assert!(!gate["satisfied"].as_bool().unwrap());
    assert!(!gate["used_cooldown"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(&home);
}

/// Schema mismatch → `native_approval_gate_schema_mismatch` error envelope.
#[test]
fn schema_mismatch_rejects() {
    let home = temp_home("schema");
    let mut req = base_request(ApprovalGateMethodV1::PublicConfig, &home);
    req.schema = "wrong".to_owned();
    let r: Value = serde_json::from_slice(&evaluate_approval_gate_request(&req).unwrap()).unwrap();
    assert_eq!(r["status"].as_str().unwrap(), "error");
    assert_eq!(
        r["code"].as_str().unwrap(),
        "native_approval_gate_schema_mismatch"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// Missing a required `params` field (RequirePolicyWrite needs action+scope)
/// → `native_approval_gate_invalid`, not a panic.
#[test]
fn missing_param_errors() {
    let home = temp_home("mp");
    let mut req = base_request(ApprovalGateMethodV1::RequirePolicyWrite, &home);
    req.params = Some(json!({"scope": "local"})); // no action
    let r: Value = serde_json::from_slice(&evaluate_approval_gate_request(&req).unwrap()).unwrap();
    assert_eq!(r["status"].as_str().unwrap(), "error");
    assert_eq!(r["code"].as_str().unwrap(), "native_approval_gate_invalid");
    let _ = std::fs::remove_dir_all(&home);
}
