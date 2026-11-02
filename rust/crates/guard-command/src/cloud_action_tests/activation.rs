//! Signed activation of catalog extensions and lockdown.

use super::*;

// ---- activation ----

pub(super) struct Signer {
    pair: Ed25519KeyPair,
    pub(super) public: [u8; 32],
}

pub(super) fn signer() -> Signer {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = pair.public_key().as_ref().try_into().unwrap();
    Signer { pair, public }
}

fn catalog_digest() -> String {
    packaged_command_program().unwrap().catalog_digest.clone()
}

pub(super) fn payload(workspace_id: &str) -> Value {
    json!({
        "schema": ACTIVATION_SCHEMA,
        "workspace_id": workspace_id,
        "catalog_digest": catalog_digest(),
        "global_lockdown": false,
        "controls": [{"extension_id": "command.mcp-synthetic", "state": "enabled"}],
        "issued_at": "2026-11-01T00:00:00Z",
        "expires_at": "2026-11-02T00:00:00Z",
    })
}

pub(super) fn sign(signer: &Signer, payload: &Value) -> Value {
    let message = canonical_bytes(payload).unwrap();
    json!({
        "payload": payload,
        "signature": STANDARD.encode(signer.pair.sign(&message).as_ref()),
    })
}

pub(super) fn evaluator_trusting(signer: &Signer) -> CloudActionEvaluator {
    CloudActionEvaluator::new(
        load_binding_set(BINDINGS.as_bytes()).unwrap(),
        Some(signer.public),
    )
}

pub(super) fn run_with_activation(evaluator: &CloudActionEvaluator, activation: Value) -> Value {
    let mut request = request_for(evaluator);
    request["activation"] = activation;
    run(evaluator, &request)
}

#[test]
fn a_validly_signed_activation_is_accepted_and_recorded_in_provenance() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let without = run(&evaluator, &request_for(&evaluator));
    assert_success(&without);
    let signed = sign(&signer, &payload("ws-synthetic-1"));
    let with = run_with_activation(&evaluator, signed);
    assert_success(&with);
    assert_eq!(with["action"], without["action"]);
    assert_ne!(
        with["evaluation_provenance_digest"],
        without["evaluation_provenance_digest"]
    );
    let mut other = payload("ws-synthetic-1");
    other["global_lockdown"] = true.into();
    let other_result = run_with_activation(&evaluator, sign(&signer, &other));
    assert_success(&other_result);
    assert_ne!(
        other_result["evaluation_provenance_digest"],
        with["evaluation_provenance_digest"]
    );
}

#[test]
fn an_activation_signed_by_another_key_is_rejected() {
    let trusted = signer();
    let attacker = signer();
    let evaluator = evaluator_trusting(&trusted);
    let result = run_with_activation(&evaluator, sign(&attacker, &payload("ws-synthetic-1")));
    assert_error(&result, "activation_invalid");
}

#[test]
fn a_tampered_activation_payload_is_rejected() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let mut signed = sign(&signer, &payload("ws-synthetic-1"));
    signed["payload"]["controls"] = json!([{"extension_id": "command.mcp-synthetic", "state": "enabled"},
        {"extension_id": "command.mcp-other", "state": "enabled"}]);
    assert_error(
        &run_with_activation(&evaluator, signed),
        "activation_invalid",
    );

    let mut signed = sign(&signer, &payload("ws-synthetic-1"));
    signed["payload"]["expires_at"] = "2099-01-01T00:00:00Z".into();
    assert_error(
        &run_with_activation(&evaluator, signed),
        "activation_invalid",
    );

    let mut signed = sign(&signer, &payload("ws-synthetic-1"));
    signed["signature"] = "not base64 !!".into();
    assert_error(
        &run_with_activation(&evaluator, signed),
        "activation_invalid",
    );

    let mut signed = sign(&signer, &payload("ws-synthetic-1"));
    signed["signature"] = STANDARD.encode([0u8; 64]).into();
    assert_error(
        &run_with_activation(&evaluator, signed),
        "activation_invalid",
    );
}

#[test]
fn an_expired_or_not_yet_valid_activation_is_rejected() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let mut expired = payload("ws-synthetic-1");
    expired["expires_at"] = "2026-11-01T11:59:59Z".into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &expired)),
        "activation_expired",
    );
    // The expiry instant itself is already expired.
    let mut at_expiry = payload("ws-synthetic-1");
    at_expiry["expires_at"] = "2026-11-01T12:00:00Z".into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &at_expiry)),
        "activation_expired",
    );
    let mut early = payload("ws-synthetic-1");
    early["issued_at"] = "2026-11-01T12:00:01Z".into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &early)),
        "activation_expired",
    );
    let mut at_issue = payload("ws-synthetic-1");
    at_issue["issued_at"] = "2026-11-01T12:00:00Z".into();
    assert_success(&run_with_activation(&evaluator, sign(&signer, &at_issue)));
}

#[test]
fn an_activation_for_another_workspace_or_catalog_is_rejected() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let other_workspace = sign(&signer, &payload("ws-synthetic-2"));
    assert_error(
        &run_with_activation(&evaluator, other_workspace),
        "activation_mismatch",
    );
    let mut other_catalog = payload("ws-synthetic-1");
    other_catalog["catalog_digest"] = "0".repeat(64).into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &other_catalog)),
        "activation_mismatch",
    );
}

#[test]
fn an_activation_with_no_configured_key_is_rejected_not_ignored() {
    let signer = signer();
    let keyless = evaluator();
    let signed = sign(&signer, &payload("ws-synthetic-1"));
    assert_error(
        &run_with_activation(&keyless, signed),
        "activation_key_unavailable",
    );
    // No activation and no key is the ordinary case.
    assert_success(&run(&keyless, &request_for(&keyless)));
}

#[test]
fn a_malformed_signed_activation_is_rejected() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let mut wrong_schema = payload("ws-synthetic-1");
    wrong_schema["schema"] = "guard.cloud-workspace-activation.v2".into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &wrong_schema)),
        "activation_unsupported_version",
    );
    let mut extra = payload("ws-synthetic-1");
    extra["unexpected"] = true.into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &extra)),
        "activation_invalid",
    );
    let mut bad_time = payload("ws-synthetic-1");
    bad_time["expires_at"] = "tomorrow".into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &bad_time)),
        "activation_invalid",
    );
    // A float cannot be canonicalized, so it can never carry a valid signature.
    let mut float = payload("ws-synthetic-1");
    float["controls"][0]["weight"] = serde_json::from_str("1.5").unwrap();
    let unsigned = json!({"payload": float, "signature": "AAAA"});
    assert_error(
        &run_with_activation(&evaluator, unsigned),
        "activation_invalid",
    );
    let mut document = sign(&signer, &payload("ws-synthetic-1"));
    document["extra"] = true.into();
    assert_error(
        &run_with_activation(&evaluator, document),
        "invalid_request",
    );
}

pub(super) fn activation_with_controls(controls: Value) -> (Signer, SignedActivation) {
    let signer = signer();
    let mut body = payload("ws-synthetic-1");
    body["controls"] = controls;
    let signed: SignedActivation = serde_json::from_value(sign(&signer, &body)).unwrap();
    (signer, signed)
}

pub(super) fn verify(
    signed: &SignedActivation,
    key: &[u8; 32],
) -> Result<crate::cloud_action_activation::VerifiedActivation, &'static str> {
    let digest = catalog_digest();
    verify_activation(
        Some(signed),
        Some(key),
        &ActivationContext {
            workspace_id: "ws-synthetic-1",
            catalog_digest: &digest,
            now: "2026-11-01T12:00:00Z",
        },
    )
}

#[test]
fn a_disable_beats_an_enable_in_either_order() {
    let enable = json!({"extension_id": "command.mcp-synthetic", "state": "enabled"});
    let disable = json!({"extension_id": "command.mcp-synthetic", "state": "disabled"});
    let other = json!({"extension_id": "command.mcp-other", "state": "enabled"});
    for controls in [
        json!([enable, disable, other]),
        json!([disable, enable, other]),
        json!([enable, enable, disable, other]),
    ] {
        let (signer, signed) = activation_with_controls(controls);
        let verified = verify(&signed, &signer.public).unwrap();
        assert!(!verified.external_enabled("command.mcp-synthetic"));
        assert!(verified.external_enabled("command.mcp-other"));
        assert!(!verified.external_enabled("command.mcp-unlisted"));
    }
    let (signer, signed) = activation_with_controls(json!([enable]));
    assert!(verify(&signed, &signer.public)
        .unwrap()
        .external_enabled("command.mcp-synthetic"));
}

#[test]
fn an_absent_activation_enables_nothing_and_a_signed_lockdown_is_carried() {
    let digest = catalog_digest();
    let none = verify_activation(
        None,
        None,
        &ActivationContext {
            workspace_id: "ws-synthetic-1",
            catalog_digest: &digest,
            now: "2026-11-01T12:00:00Z",
        },
    )
    .unwrap();
    assert!(!none.global_lockdown);
    assert!(!none.external_enabled("command.mcp-synthetic"));
    assert!(none.digest.is_none());

    let signer = signer();
    let mut body = payload("ws-synthetic-1");
    body["global_lockdown"] = true.into();
    let signed: SignedActivation = serde_json::from_value(sign(&signer, &body)).unwrap();
    let verified = verify(&signed, &signer.public).unwrap();
    assert!(verified.global_lockdown);
    assert!(verified.digest.is_some());
}

#[test]
fn an_activation_key_must_be_exactly_32_hex_bytes() {
    let signer = signer();
    let hex_key = hex::encode(signer.public);
    assert_eq!(parse_public_key(&hex_key).unwrap(), signer.public);
    assert_eq!(
        parse_public_key(&format!("{hex_key}\n")).unwrap(),
        signer.public
    );
    for bad in ["", "zz", &hex_key[..62], &format!("{hex_key}00"), "0x1234"] {
        assert_eq!(
            parse_public_key(bad).unwrap_err(),
            "activation_key_invalid",
            "{bad:?}"
        );
    }
}
