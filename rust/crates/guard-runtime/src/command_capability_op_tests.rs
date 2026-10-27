use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::json;
use std::collections::BTreeMap;

const KEY: &[u8] = b"command-capability-test-key";
const KEY_ID: &str = "key-1";
const DEVICE: &str = "device-1";
const WORKSPACE: &str = "workspace-1";
const NOW: &str = "2026-03-01T00:00:00+00:00";

fn sign(mut capability: Value) -> Value {
    let object = capability.as_object_mut().expect("object");
    object.remove("signature");
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).expect("key");
    mac.update(&canonical_bytes(&capability).expect("canonical"));
    let signature = hex::encode(mac.finalize().into_bytes());
    capability
        .as_object_mut()
        .expect("object")
        .insert("signature".to_owned(), Value::from(signature));
    capability
}

fn capability() -> Value {
    sign(json!({
        "version": 1,
        "keyId": KEY_ID,
        "issuer": "guard-cloud",
        "issuedAt": "2026-02-01T00:00:00+00:00",
        "expiresAt": "2026-04-01T00:00:00+00:00",
        "nonce": "nonce-1",
        "deviceId": DEVICE,
        "workspaceId": WORKSPACE,
        "operations": ["guard.app.status", "guard.packageShims.repair"],
    }))
}

fn request() -> CommandCapabilityRequestV1 {
    CommandCapabilityRequestV1 {
        schema: COMMAND_CAPABILITY_REQUEST_SCHEMA.to_owned(),
        request_id: "request-1".to_owned(),
        capability: capability(),
        integrity_key_b64: Some(Base64UrlUnpadded::encode_string(KEY)),
        integrity_key_id: Some(KEY_ID.to_owned()),
        device_id: Some(DEVICE.to_owned()),
        workspace_id: Some(WORKSPACE.to_owned()),
        oauth_error: None,
        now: NOW.to_owned(),
        job: Value::Null,
        schema_versions: BTreeMap::new(),
        replay_items: Vec::new(),
        replay_identity: Value::Null,
    }
}

fn job() -> Value {
    json!({
        "operation": "guard.packageShims.repair",
        "id": "job-1",
        "deviceId": DEVICE,
        "workspaceId": WORKSPACE,
        "nonce": "job-nonce",
        "expiresAt": "2026-03-01T00:30:00+00:00",
        "idempotencyKey": "idem-1",
        "schemaVersion": 3,
        "payload": {"shim": "npm"},
    })
}

fn with_job(mut request: CommandCapabilityRequestV1) -> CommandCapabilityRequestV1 {
    request.job = job();
    request
        .schema_versions
        .insert("guard.packageShims.repair".to_owned(), Value::from(3));
    request
}

fn reason(request: &CommandCapabilityRequestV1) -> String {
    evaluate(request)["reason"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

fn authorization_reason(request: &CommandCapabilityRequestV1) -> String {
    evaluate(request)["authorization"]["reason"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

fn mutate(request: &mut CommandCapabilityRequestV1, key: &str, value: Value) {
    let mut capability = request.capability.clone();
    capability
        .as_object_mut()
        .expect("object")
        .insert(key.to_owned(), value);
    request.capability = sign(capability);
}

#[test]
fn verifies_a_signed_capability() {
    let result = evaluate(&request());
    assert_eq!(result["capability_valid"], Value::Bool(true));
    assert_eq!(result["reason"], Value::Null);
    assert_eq!(result["issuer"], Value::from("guard-cloud"));
    assert_eq!(result["device_id"], Value::from(DEVICE));
    assert_eq!(result["authorization"], Value::Null);
}

#[test]
fn projects_grants_onto_the_known_operation_set() {
    let mut request = request();
    mutate(
        &mut request,
        "operations",
        json!(["guard.app.retired", "guard.app.status"]),
    );
    assert_eq!(
        evaluate(&request)["operations"],
        json!(["guard.app.status"])
    );
}

#[test]
fn rejects_a_forged_signature() {
    let mut request = request();
    request
        .capability
        .as_object_mut()
        .expect("object")
        .insert("signature".to_owned(), Value::from("00".repeat(32)));
    assert_eq!(reason(&request), "signed_payload_invalid_signature");
}

#[test]
fn rejects_an_envelope_without_a_signature() {
    let mut request = request();
    request
        .capability
        .as_object_mut()
        .expect("object")
        .remove("signature");
    assert_eq!(reason(&request), "signed_payload_missing_signature");
}

#[test]
fn rejects_a_capability_signed_under_another_key() {
    let mut request = request();
    request.integrity_key_id = Some("key-2".to_owned());
    assert_eq!(reason(&request), "signed_payload_key_mismatch");
}

#[test]
fn rejects_a_capability_when_no_signing_key_is_available() {
    let mut request = request();
    request.integrity_key_b64 = None;
    assert_eq!(reason(&request), "local_signing_key_unavailable");
}

#[test]
fn reads_a_float_version_as_the_supported_version() {
    let mut request = request();
    mutate(&mut request, "version", json!(1.0));
    assert_eq!(evaluate(&request)["capability_valid"], Value::Bool(true));
}

#[test]
fn rejects_an_unsupported_version() {
    let mut request = request();
    mutate(&mut request, "version", json!(2));
    assert_eq!(reason(&request), "capability_version_unsupported");
}

#[test]
fn rejects_an_expired_capability() {
    let mut request = request();
    request.now = "2026-05-01T00:00:00+00:00".to_owned();
    assert_eq!(reason(&request), "capability_expired");
}

#[test]
fn rejects_a_capability_issued_beyond_the_clock_skew() {
    let mut request = request();
    request.now = "2026-01-31T23:00:00+00:00".to_owned();
    assert_eq!(reason(&request), "capability_issued_in_future");
}

#[test]
fn admits_a_capability_issued_inside_the_clock_skew() {
    let mut request = request();
    request.now = "2026-01-31T23:58:00+00:00".to_owned();
    assert_eq!(evaluate(&request)["capability_valid"], Value::Bool(true));
}

#[test]
fn rejects_a_capability_whose_lifetime_exceeds_the_maximum() {
    let mut request = request();
    mutate(
        &mut request,
        "expiresAt",
        json!("2028-02-01T00:00:00+00:00"),
    );
    assert_eq!(reason(&request), "capability_ttl_exceeded");
}

#[test]
fn rejects_a_capability_that_expires_before_it_was_issued() {
    let mut request = request();
    mutate(
        &mut request,
        "expiresAt",
        json!("2026-01-01T00:00:00+00:00"),
    );
    assert_eq!(reason(&request), "capability_expiry_invalid");
}

#[test]
fn rejects_a_capability_bound_to_another_device() {
    let mut request = request();
    mutate(&mut request, "deviceId", json!("device-2"));
    assert_eq!(reason(&request), "capability_device_mismatch");
}

#[test]
fn rejects_a_capability_bound_to_another_workspace() {
    let mut request = request();
    mutate(&mut request, "workspaceId", json!("workspace-2"));
    assert_eq!(reason(&request), "capability_workspace_mismatch");
}

#[test]
fn reports_the_callers_oauth_failure_before_reading_the_binding() {
    let mut request = request();
    mutate(&mut request, "deviceId", json!("device-2"));
    request.oauth_error = Some("cloud_connection_required".to_owned());
    assert_eq!(reason(&request), "cloud_connection_required");
}

#[test]
fn narrows_an_unknown_oauth_failure_to_the_connection_code() {
    let mut request = request();
    request.oauth_error = Some("something_else".to_owned());
    assert_eq!(reason(&request), "cloud_connection_required");
}

#[test]
fn reports_a_device_binding_mismatch_the_caller_resolved() {
    let mut request = request();
    request.oauth_error = Some("cloud_device_binding_mismatch".to_owned());
    assert_eq!(reason(&request), "cloud_device_binding_mismatch");
}

#[test]
fn rejects_duplicate_operations() {
    let mut request = request();
    mutate(
        &mut request,
        "operations",
        json!(["guard.app.status", "guard.app.status"]),
    );
    assert_eq!(reason(&request), "capability_operations_invalid");
}

#[test]
fn rejects_an_empty_operation_list() {
    let mut request = request();
    mutate(&mut request, "operations", json!([]));
    assert_eq!(reason(&request), "capability_operations_invalid");
}

#[test]
fn rejects_an_invalid_current_time() {
    let mut request = request();
    request.now = "not-a-time".to_owned();
    assert_eq!(reason(&request), "invalid_current_time");
}

#[test]
fn authorizes_a_leased_job() {
    let result = evaluate(&with_job(request()));
    let authorization = &result["authorization"];
    assert_eq!(authorization["authorized"], Value::Bool(true));
    assert_eq!(
        authorization["operation"],
        Value::from("guard.packageShims.repair")
    );
    assert_eq!(authorization["requires_local_approval"], Value::Bool(true));
    assert_eq!(authorization["identity"]["id"], Value::from("job-1"));
    assert!(authorization["identity"]["payloadDigest"]
        .as_str()
        .is_some_and(|digest| digest.len() == 64));
}

#[test]
fn a_read_only_operation_needs_no_local_approval() {
    let mut request = request();
    request.job = json!({
        "operation": "guard.app.status",
        "id": "job-2",
        "deviceId": DEVICE,
        "workspaceId": WORKSPACE,
        "nonce": "job-nonce",
        "expiresAt": "2026-03-01T00:30:00+00:00",
        "idempotencyKey": "idem-2",
        "schemaVersion": 1,
        "payload": {},
    });
    request
        .schema_versions
        .insert("guard.app.status".to_owned(), Value::from(1));
    assert_eq!(
        evaluate(&request)["authorization"]["requires_local_approval"],
        Value::Bool(false)
    );
}

#[test]
fn refuses_a_job_for_an_operation_the_capability_does_not_grant() {
    let mut request = with_job(request());
    mutate(&mut request, "operations", json!(["guard.app.status"]));
    assert_eq!(
        authorization_reason(&request),
        "command_operation_not_granted"
    );
}

#[test]
fn refuses_a_job_for_an_unsupported_operation() {
    let mut request = with_job(request());
    request.schema_versions.clear();
    assert_eq!(
        authorization_reason(&request),
        "command_operation_unsupported"
    );
}

#[test]
fn refuses_a_job_whose_schema_version_does_not_match() {
    let mut request = with_job(request());
    request
        .schema_versions
        .insert("guard.packageShims.repair".to_owned(), Value::from(4));
    assert_eq!(
        authorization_reason(&request),
        "command_schema_version_mismatch"
    );
}

#[test]
fn refuses_a_job_missing_its_idempotency_key() {
    let mut request = with_job(request());
    request
        .job
        .as_object_mut()
        .expect("object")
        .insert("idempotencyKey".to_owned(), Value::from("   "));
    assert_eq!(
        authorization_reason(&request),
        "command_idempotency_key_missing"
    );
}

#[test]
fn refuses_a_job_id_outside_the_portable_argument_set() {
    let mut request = with_job(request());
    request
        .job
        .as_object_mut()
        .expect("object")
        .insert("id".to_owned(), Value::from("job;rm -rf /"));
    assert_eq!(authorization_reason(&request), "command_id_invalid");
}

#[test]
fn refuses_a_job_without_an_object_payload() {
    let mut request = with_job(request());
    request
        .job
        .as_object_mut()
        .expect("object")
        .insert("payload".to_owned(), Value::from("payload"));
    assert_eq!(authorization_reason(&request), "command_payload_invalid");
}

#[test]
fn refuses_a_job_that_is_not_an_object() {
    let mut request = with_job(request());
    request.job = Value::from("job-1");
    assert_eq!(authorization_reason(&request), "command_job_invalid");
}

#[test]
fn refuses_an_expired_job() {
    let mut request = with_job(request());
    request.now = "2026-03-01T01:00:00+00:00".to_owned();
    assert_eq!(authorization_reason(&request), "command_expired");
}

#[test]
fn refuses_a_job_whose_lease_outlives_the_maximum() {
    let mut request = with_job(request());
    request.job.as_object_mut().expect("object").insert(
        "expiresAt".to_owned(),
        Value::from("2026-03-03T00:00:00+00:00"),
    );
    assert_eq!(authorization_reason(&request), "command_expiry_too_distant");
}

#[test]
fn refuses_a_job_already_recorded_under_its_idempotency_key() {
    let mut request = with_job(request());
    request.replay_items = vec![json!({
        "idempotencyKey": "idem-1",
        "expiresAt": "2026-03-01T06:00:00+00:00",
    })];
    assert_eq!(authorization_reason(&request), "command_replayed");
}

#[test]
fn refuses_a_job_already_recorded_under_its_id() {
    let mut request = with_job(request());
    request.replay_items = vec![json!({
        "jobId": "job-1",
        "expiresAt": "2026-03-01T06:00:00+00:00",
    })];
    assert_eq!(authorization_reason(&request), "command_replayed");
}

#[test]
fn an_expired_replay_row_no_longer_blocks_a_job() {
    let mut request = with_job(request());
    request.replay_items = vec![json!({
        "jobId": "job-1",
        "expiresAt": "2026-02-01T00:00:00+00:00",
    })];
    assert_eq!(
        evaluate(&request)["authorization"]["authorized"],
        Value::Bool(true)
    );
}

#[test]
fn an_invalid_capability_refuses_the_job_it_carried() {
    let mut request = with_job(request());
    request.now = "2026-05-01T00:00:00+00:00".to_owned();
    let result = evaluate(&request);
    assert_eq!(result["capability_valid"], Value::Bool(false));
    assert_eq!(
        result["authorization"]["reason"],
        Value::from("capability_expired")
    );
    assert_eq!(result["authorization"]["authorized"], Value::Bool(false));
}

#[test]
fn canonical_bytes_escape_non_ascii_like_python() {
    assert_eq!(
        canonical_bytes(&json!({"b": "caf\u{e9}", "a": "\u{1f600}"})).expect("canonical"),
        br#"{"a":"\ud83d\ude00","b":"caf\u00e9"}"#.to_vec()
    );
}

#[test]
fn canonical_bytes_use_the_short_control_escapes() {
    assert_eq!(
        canonical_bytes(&json!("a\nb\tc\u{1}")).expect("canonical"),
        br#""a\nb\tc\u0001""#.to_vec()
    );
}

#[test]
fn refuses_a_request_naming_another_contract() {
    let mut request = request();
    request.schema = "guard-command-capability-request.v2".to_owned();
    assert_eq!(
        refusal(&request),
        Some("native_command_capability_schema_mismatch")
    );
}

#[test]
fn refuses_more_replay_history_than_the_contract_admits() {
    let mut request = request();
    request.replay_items = vec![json!({}); COMMAND_CAPABILITY_MAX_REPLAY_ITEMS + 1];
    assert_eq!(
        refusal(&request),
        Some("native_command_capability_too_many_items")
    );
}

#[test]
fn the_binding_digest_never_covers_the_signing_key() {
    let mut other = request();
    other.integrity_key_b64 = Some(Base64UrlUnpadded::encode_string(b"another-key"));
    assert_eq!(
        request_digest(&request()).expect("digest"),
        request_digest(&other).expect("digest")
    );
}

#[test]
fn the_response_carries_the_request_identity() {
    let encoded = evaluate_command_capability_request(&request()).expect("response");
    let response: Value = serde_json::from_slice(&encoded).expect("json");
    assert_eq!(
        response["schema"],
        Value::from(COMMAND_CAPABILITY_RESULT_SCHEMA)
    );
    assert_eq!(response["request_id"], Value::from("request-1"));
    assert_eq!(response["status"], Value::from("ok"));
    assert_eq!(response["code"], Value::from("ok"));
    assert!(response["request_sha256"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:")));
}

#[test]
fn a_refused_request_carries_no_payload() {
    let mut request = request();
    request.schema = "other".to_owned();
    let encoded = evaluate_command_capability_request(&request).expect("response");
    let response: Value = serde_json::from_slice(&encoded).expect("json");
    assert_eq!(response["status"], Value::from("error"));
    assert_eq!(
        response["code"],
        Value::from("native_command_capability_schema_mismatch")
    );
    assert_eq!(response.get("payload"), None);
}

fn replay_identity() -> Value {
    json!({
        "operation": "guard.review.syncPolicyMemory",
        "id": "exact-job-1",
        "deviceId": DEVICE,
        "workspaceId": WORKSPACE,
        "nonce": "exact-nonce",
        "expiresAt": "2026-03-01T00:30:00+00:00",
        "idempotencyKey": "exact-idem-1",
        "payloadDigest": "digest",
    })
}

#[test]
fn a_request_carrying_no_replay_identity_is_asked_nothing_about_replay() {
    assert_eq!(evaluate(&request())["replayed"], Value::Null);
}

#[test]
fn an_unrecorded_replay_identity_is_new() {
    let mut request = request();
    request.replay_identity = replay_identity();
    assert_eq!(evaluate(&request)["replayed"], Value::Bool(false));
}

#[test]
fn a_replay_identity_matching_an_unexpired_row_is_seen() {
    let mut request = request();
    request.replay_identity = replay_identity();
    request.replay_items = vec![json!({
        "jobId": "exact-job-1",
        "expiresAt": "2026-03-01T01:00:00+00:00",
    })];
    assert_eq!(evaluate(&request)["replayed"], Value::Bool(true));
}

#[test]
fn a_replay_identity_matching_an_expired_row_is_new() {
    let mut request = request();
    request.replay_identity = replay_identity();
    request.replay_items = vec![json!({
        "idempotencyKey": "exact-idem-1",
        "expiresAt": "2026-02-28T00:00:00+00:00",
    })];
    assert_eq!(evaluate(&request)["replayed"], Value::Bool(false));
}

#[test]
fn a_replay_identity_matching_a_recorded_digest_is_seen() {
    let mut request = request();
    request.replay_identity = replay_identity();
    let digest = content_digest(&canonical_bytes(&replay_identity()).expect("canonical"));
    request.replay_items = vec![json!({
        "identityDigest": digest,
        "expiresAt": "2026-03-01T01:00:00+00:00",
    })];
    assert_eq!(evaluate(&request)["replayed"], Value::Bool(true));
}

#[test]
fn a_replay_identity_read_at_an_unreadable_time_is_seen() {
    let mut request = request();
    request.replay_identity = replay_identity();
    request.now = "not-a-time".to_owned();
    assert_eq!(evaluate(&request)["replayed"], Value::Bool(true));
}

#[test]
fn a_refused_capability_still_answers_the_replay_question() {
    let mut request = request();
    request.replay_identity = replay_identity();
    request.capability = Value::Null;
    let result = evaluate(&request);
    assert_eq!(result["capability_valid"], Value::Bool(false));
    assert_eq!(result["replayed"], Value::Bool(false));
}
