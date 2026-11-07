use super::*;

/// `base64url(b"k" * 32)` without padding.
const KEY: &str = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s";
const NOW: &str = "2026-01-10T00:00:00+00:00";

fn ask(request: Value) -> Value {
    answer(request).expect("answer")
}

fn signed(payload: Value) -> Value {
    ask(json!({"op": "sign", "key": KEY, "key_id": "key-1", "payload": payload}))["envelope"]
        .clone()
}

fn binding() -> Value {
    json!({
        "deviceId": "device-1",
        "dpopThumbprint": "thumb-1",
        "grantId": "grant-1",
        "installationId": "install-1",
        "machineId": "machine-1",
        "runtimeId": null,
        "workspaceId": "workspace-1",
    })
}

fn capability_fields() -> Value {
    let mut fields = binding();
    let extra = json!({
        "expiresAt": "2026-02-01T00:00:00+00:00",
        "issuedAt": "2026-01-01T00:00:00+00:00",
        "issuer": "local-cli",
        "nonce": "nonce-1",
        "operation": OPERATION,
    });
    for (field, value) in extra.as_object().expect("fields") {
        fields[field] = value.clone();
    }
    fields
}

fn check(capability: Value, revocation: Value) -> Value {
    ask(json!({
        "op": "capability",
        "key": KEY,
        "key_id": "key-1",
        "capability": capability,
        "revocation": revocation,
        "binding": binding(),
        "now": NOW,
    }))
}

fn capability_with(field: &str, value: Value) -> Value {
    let mut fields = capability_fields();
    fields[field] = value;
    signed(fields)
}

#[test]
fn signatures_cover_the_python_stable_json_bytes() {
    let envelope = signed(json!({"issuer": "local-cli", "note": "café ☕", "n": 1.5}));
    // hmac(b"k" * 32, stable_json_serialize(unsigned).encode(), sha256)
    assert_eq!(
        envelope["signature"],
        "6c34421567fb65ed68c5bb2c79eb1724b961a2d317ca0bb8b9a687df37a12324"
    );
    assert_eq!(envelope["keyId"], "key-1");
    let verified =
        ask(json!({"op": "verify", "key": KEY, "key_id": "key-1", "envelope": envelope}));
    assert_eq!(
        verified,
        json!({"unsigned": {"issuer": "local-cli", "note": "café ☕", "n": 1.5, "keyId": "key-1"}})
    );
}

#[test]
fn digests_match_python_sha256_of_stable_json() {
    assert_eq!(
        ask(json!({"op": "digest", "payload": {"b": [1, 2.0, "é"], "a": null}})),
        json!({"digest": "878131cedddfbee4292f213fde5ba4bcba524ebb0d2702e17efbf25be41afbe4"})
    );
}

#[test]
fn verification_refuses_in_python_order() {
    let verify = |key: Value, envelope: Value| {
        ask(json!({"op": "verify", "key": key, "key_id": "key-1", "envelope": envelope}))
    };
    let envelope = signed(json!({"issuer": "local-cli"}));
    let mut padded = envelope.clone();
    padded["signature"] = json!(format!(
        "  {} ",
        envelope["signature"].as_str().expect("sig")
    ));
    assert!(verify(json!(KEY), padded).get("unsigned").is_some());
    let mut tampered = envelope.clone();
    tampered["issuer"] = json!("other");
    let mut blank = envelope.clone();
    blank["signature"] = json!("  ");
    let mut renamed = envelope.clone();
    renamed["keyId"] = json!("key-2");
    for (key, envelope, code) in [
        (json!(KEY), json!(null), "cloud_review_capability_missing"),
        (json!(KEY), json!([]), "cloud_review_capability_missing"),
        (
            json!(KEY),
            blank,
            "cloud_review_capability_signature_missing",
        ),
        (
            json!(null),
            envelope.clone(),
            "cloud_review_signing_key_unavailable",
        ),
        (
            json!("%%"),
            envelope.clone(),
            "cloud_review_signing_key_unavailable",
        ),
        (json!(KEY), renamed, "cloud_review_capability_key_mismatch"),
        (
            json!(KEY),
            tampered,
            "cloud_review_capability_signature_invalid",
        ),
    ] {
        assert_eq!(verify(key, envelope), json!({"error": code}));
    }
}

#[test]
fn a_genuine_current_capability_is_returned_with_its_digest() {
    let capability = signed(capability_fields());
    let answer = check(capability.clone(), Value::Null);
    let mut unsigned = capability.as_object().expect("capability").clone();
    unsigned.remove("signature");
    let expected_digest = digest(&Value::Object(unsigned.clone())).expect("digest");
    assert_eq!(
        answer,
        json!({"capability": unsigned, "digest": expected_digest})
    );
}

#[test]
fn capability_checks_refuse_in_python_order() {
    for (field, value, code) in [
        (
            "operation",
            json!("guard.other"),
            "cloud_review_capability_operation_invalid",
        ),
        ("issuer", json!(" "), "cloud_review_capability_invalid"),
        ("nonce", json!(null), "cloud_review_capability_invalid"),
        (
            "issuedAt",
            json!("not a time"),
            "cloud_review_capability_time_invalid",
        ),
        (
            "expiresAt",
            json!("2025-12-31T00:00:00+00:00"),
            "cloud_review_capability_time_invalid",
        ),
        (
            "issuedAt",
            json!("2026-01-10T00:06:00+00:00"),
            "cloud_review_capability_issued_in_future",
        ),
        (
            "expiresAt",
            json!("2027-01-02T00:00:00+00:00"),
            "cloud_review_capability_ttl_invalid",
        ),
        (
            "expiresAt",
            json!("2026-01-10T00:00:00Z"),
            "cloud_review_capability_expired",
        ),
    ] {
        assert_eq!(
            check(capability_with(field, value), Value::Null),
            json!({"error": code}),
            "{field}"
        );
    }
    let skewed = capability_with("issuedAt", json!("2026-01-10T00:05:00+00:00"));
    assert!(check(skewed, Value::Null).get("capability").is_some());
    let mut request = json!({
        "op": "capability", "key": KEY, "key_id": "key-1",
        "capability": signed(capability_fields()), "revocation": null,
        "binding": binding(), "now": "yesterday",
    });
    assert_eq!(
        ask(request.clone()),
        json!({"error": "cloud_review_current_time_invalid"})
    );
    request["now"] = json!(NOW);
    request["binding"] = Value::Null;
    assert_eq!(ask(request), json!({"error": BINDING_UNREADABLE}));
}

#[test]
fn another_binding_answers_the_digest_to_revoke() {
    let capability = capability_with("grantId", json!("grant-2"));
    let mut unsigned = capability.as_object().expect("capability").clone();
    unsigned.remove("signature");
    assert_eq!(
        check(capability, Value::Null),
        json!({
            "error": "cloud_review_capability_binding_mismatch",
            "drift_digest": digest(&Value::Object(unsigned)).expect("digest"),
        })
    );
    // A binding field the capability lacks reads as null, as `dict.get` does.
    let mut fields = capability_fields();
    fields.as_object_mut().expect("fields").remove("runtimeId");
    assert!(check(signed(fields), Value::Null)
        .get("capability")
        .is_some());
}

#[test]
fn a_revocation_covers_its_capability_or_every_capability() {
    let capability = signed(capability_fields());
    let current = check(capability.clone(), Value::Null)["digest"].clone();
    let revocation = |digest: Value| {
        signed(json!({
            "capabilityDigest": digest,
            "issuer": "local-cli",
            "revokedAt": "2026-01-05T00:00:00+00:00",
        }))
    };
    for digest in [current, Value::Null] {
        assert_eq!(
            check(capability.clone(), revocation(digest)),
            json!({"error": "cloud_review_capability_revoked"})
        );
    }
    let unrelated = check(capability.clone(), revocation(json!("0".repeat(64))));
    assert!(unrelated.get("capability").is_some());
    let undated = signed(json!({"capabilityDigest": null, "issuer": "local-cli"}));
    let numbered = signed(json!({"capabilityDigest": 7, "revokedAt": "2026-01-05T00:00:00Z"}));
    for revocation in [json!("revoked"), json!([]), undated, numbered] {
        assert_eq!(
            check(capability.clone(), revocation),
            json!({"error": "cloud_review_capability_revocation_invalid"})
        );
    }
    let mut forged = revocation(Value::Null);
    forged["issuer"] = json!("someone-else");
    assert_eq!(
        check(capability, forged),
        json!({"error": "cloud_review_capability_signature_invalid"})
    );
}

fn job() -> Value {
    json!({
        "operation": OPERATION,
        "protocolVersion": 2,
        "id": " job-1 ",
        "deviceId": "device-1",
        "workspaceId": "workspace-1",
        "nonce": "nonce-1",
        "expiresAt": "2026-01-10T01:00:00+00:00",
        "idempotencyKey": "idem-1",
        "payload": {"b": [1, 2.0, "é"], "a": null},
    })
}

fn identify(job: Value) -> Value {
    ask(json!({"op": "job", "job": job, "now": NOW}))
}

#[test]
fn a_job_identity_carries_its_stripped_fields_and_payload_digest() {
    assert_eq!(
        identify(job()),
        json!({"identity": {
            "operation": OPERATION,
            "id": "job-1",
            "deviceId": "device-1",
            "workspaceId": "workspace-1",
            "nonce": "nonce-1",
            "expiresAt": "2026-01-10T01:00:00+00:00",
            "idempotencyKey": "idem-1",
            "payloadDigest": "878131cedddfbee4292f213fde5ba4bcba524ebb0d2702e17efbf25be41afbe4",
        }})
    );
    let mut float_version = job();
    float_version["protocolVersion"] = json!(2.0);
    assert!(identify(float_version).get("identity").is_some());
}

#[test]
fn job_checks_refuse_in_python_order() {
    let with = |field: &str, value: Value| {
        let mut job = job();
        job[field] = value;
        job
    };
    let without = |field: &str| {
        let mut job = job();
        job.as_object_mut().expect("job").remove(field);
        job
    };
    for (job, code) in [
        (json!([]), "remote_exact_job_invalid"),
        (
            with("operation", json!("guard.other")),
            "remote_exact_job_operation_invalid",
        ),
        (
            with("protocolVersion", json!(1)),
            "cloud_review_protocol_upgrade_required",
        ),
        (
            with("protocolVersion", json!("2")),
            "cloud_review_protocol_upgrade_required",
        ),
        (
            with("protocolVersion", json!(true)),
            "cloud_review_protocol_upgrade_required",
        ),
        (with("schemaVersion", json!(1)), "remote_exact_job_invalid"),
        (without("id"), "remote_exact_job_id_missing"),
        (
            with("deviceId", json!(" ")),
            "remote_exact_job_device_missing",
        ),
        (
            with("workspaceId", json!(3)),
            "remote_exact_job_workspace_missing",
        ),
        (without("nonce"), "remote_exact_job_nonce_missing"),
        (without("expiresAt"), "remote_exact_job_expiry_missing"),
        (
            without("idempotencyKey"),
            "remote_exact_job_idempotency_key_missing",
        ),
        (with("payload", json!([])), "remote_exact_job_invalid"),
        (with("expiresAt", json!("soon")), "remote_exact_job_expired"),
        (with("expiresAt", json!(NOW)), "remote_exact_job_expired"),
        (
            with("expiresAt", json!("2026-01-11T00:00:01+00:00")),
            "remote_exact_job_expiry_too_distant",
        ),
    ] {
        assert_eq!(identify(job), json!({"error": code}));
    }
    let late = ask(json!({"op": "job", "job": job(), "now": "never"}));
    assert_eq!(late, json!({"error": "cloud_review_current_time_invalid"}));
}

#[test]
fn unknown_requests_are_refused_and_the_command_is_named() {
    assert_eq!(answer(json!({"op": "forget"})), Err(invalid()));
    assert_eq!(
        answer(json!({"op": "digest", "payload": {}, "extra": 1})),
        Err(invalid())
    );
    assert!(is_command("exact-cloud-review"));
    assert!(!is_command("exact-cloud-reviews"));
}

#[test]
fn the_resident_answers_exactly_like_the_helper() {
    let inner = json!({"op": "digest", "payload": {"b": 2, "a": 1}});
    let operation: crate::resident_protocol::ResidentOperationV1 = serde_json::from_value(json!({
        "operation": "exact_cloud_review",
        "request": {"schema": RESIDENT_REQUEST_SCHEMA, "request": inner.clone()},
    }))
    .expect("resident envelope");
    let crate::resident_protocol::ResidentOperationV1::ExactCloudReview(request) = operation else {
        panic!("routed to another operation");
    };
    let decoded: Value =
        serde_json::from_slice(&evaluate_resident_request(request).expect("answer")).unwrap();
    assert_eq!(decoded["schema"], RESIDENT_RESULT_SCHEMA);
    assert_eq!(decoded["status"], "ok");
    assert_eq!(decoded["answer"], ask(inner));
}

#[test]
fn the_resident_request_never_prints_its_signing_key() {
    let request: ExactCloudReviewResidentRequest = serde_json::from_value(json!({
        "schema": RESIDENT_REQUEST_SCHEMA,
        "request": {"op": "sign", "key": KEY, "key_id": "key-1", "payload": {}},
    }))
    .unwrap();
    assert!(!format!("{request:?}").contains(KEY));
}

#[test]
fn the_resident_refuses_another_schema() {
    let request: ExactCloudReviewResidentRequest = serde_json::from_value(json!({
        "schema": "guard-exact-cloud-review-resident-request.v0",
        "request": {"op": "digest", "payload": {}},
    }))
    .unwrap();
    assert_eq!(evaluate_resident_request(request).unwrap_err(), invalid());
}
