//! `CommandCapability` - resident op that verifies the signed Guard Cloud
//! command capability and authorizes one leased job against it.
//!
//! Faithful port of `runtime/command_capability.py`'s `_verify_signed_payload`,
//! `_verified_capability`, `command_job_identity`, `authorize_command_job` and
//! `_command_job_seen`. Those functions decided whether a remote command could
//! run on this machine, which made the Python edge a second evaluator on a
//! security boundary. The runtime now performs every comparison; the caller
//! supplies the stored envelope, the signing key, the device binding it
//! resolved and the replay rows it holds, and persists what the verdict says.
//!
//! Error codes are the Python ones verbatim, because callers surface them in
//! `hol-guard commands status` and in the cloud command audit trail.

use guard_contracts::{
    command_operation_is_classified, command_operation_requires_local_approval,
    utc_timestamp_micros, CommandCapabilityRequestV1, CommandCapabilityResultV1,
    COMMAND_CAPABILITY_ISSUE_SKEW_SECONDS, COMMAND_CAPABILITY_MAX_BYTES,
    COMMAND_CAPABILITY_MAX_REPLAY_ITEMS, COMMAND_CAPABILITY_MAX_TTL_SECONDS,
    COMMAND_CAPABILITY_REQUEST_SCHEMA, COMMAND_CAPABILITY_RESULT_SCHEMA,
    COMMAND_CAPABILITY_VERSION, COMMAND_JOB_MAX_LIFETIME_SECONDS,
};
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::guard_store_json::dumps_sorted;
use crate::package_authority_op::request_digest_with_limit;

const MICROS_PER_SECOND: i64 = 1_000_000;

pub(crate) fn evaluate_command_capability_request(
    request: &CommandCapabilityRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 =
        request_digest(request).map_err(|_| "native_command_capability_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(evaluate(request))),
    };
    crate::encode_response(&CommandCapabilityResultV1 {
        schema: COMMAND_CAPABILITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The reply's binding digest never covers the signing key, so a caller that
/// sees the digest learns nothing about the secret it sent.
fn request_digest(request: &CommandCapabilityRequestV1) -> Result<String, String> {
    let mut material = serde_json::to_value(request)
        .map_err(|_| "native_command_capability_invalid".to_owned())?;
    if let Some(object) = material.as_object_mut() {
        object.insert("integrity_key_b64".to_owned(), Value::Null);
    }
    request_digest_with_limit(&material, COMMAND_CAPABILITY_MAX_BYTES)
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &CommandCapabilityRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != COMMAND_CAPABILITY_REQUEST_SCHEMA {
        return Some("native_command_capability_schema_mismatch");
    }
    // More replay history than the contract admits is refused rather than
    // answered from a truncated scan, which would read as "not replayed".
    if request.replay_items.len() > COMMAND_CAPABILITY_MAX_REPLAY_ITEMS {
        return Some("native_command_capability_too_many_items");
    }
    None
}

fn evaluate(request: &CommandCapabilityRequestV1) -> Value {
    let wants_job = !request.job.is_null();
    let replayed = replay_answer(request);
    match verified_capability(request) {
        Err(code) => {
            let authorization = wants_job.then(|| refused_authorization(code));
            json!({
                "capability_valid": false,
                "reason": code,
                "issuer": Value::Null,
                "issued_at": Value::Null,
                "expires_at": Value::Null,
                "device_id": Value::Null,
                "workspace_id": Value::Null,
                "operations": Vec::<String>::new(),
                "authorization": authorization,
                "replayed": replayed,
            })
        }
        Ok(capability) => {
            let operations = capability
                .get("operations")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let authorization = wants_job.then(|| match authorize(request, &capability) {
                Err(code) => refused_authorization(code),
                Ok(authorized) => authorized,
            });
            json!({
                "capability_valid": true,
                "reason": Value::Null,
                "issuer": capability.get("issuer").cloned().unwrap_or(Value::Null),
                "issued_at": capability.get("issuedAt").cloned().unwrap_or(Value::Null),
                "expires_at": capability.get("expiresAt").cloned().unwrap_or(Value::Null),
                "device_id": capability.get("deviceId").cloned().unwrap_or(Value::Null),
                "workspace_id": capability.get("workspaceId").cloned().unwrap_or(Value::Null),
                "operations": operations,
                "authorization": authorization,
                "replayed": replayed,
            })
        }
    }
}

fn refused_authorization(code: &str) -> Value {
    json!({
        "authorized": false,
        "reason": code,
        "identity": Value::Null,
        "operation": Value::Null,
        "requires_local_approval": false,
    })
}

/// `_verify_signed_payload` followed by `_verified_capability`: the envelope's
/// signature, then every binding the grant claims, then the projection onto
/// the operations this runtime still recognizes.
fn verified_capability(
    request: &CommandCapabilityRequestV1,
) -> Result<Map<String, Value>, &'static str> {
    let capability = verify_signed_payload(request)?;
    if !numeric_equal(
        capability.get("version"),
        &Value::from(COMMAND_CAPABILITY_VERSION),
    ) {
        return Err("capability_version_unsupported");
    }
    if !non_blank_string(capability.get("issuer")) {
        return Err("capability_issuer_invalid");
    }
    let issued_at = timestamp(capability.get("issuedAt")).ok_or("capability_issued_at_invalid")?;
    let expires_at = timestamp(capability.get("expiresAt")).ok_or("capability_expiry_invalid")?;
    let current = utc_timestamp_micros(request.now.trim()).ok_or("invalid_current_time")?;
    if issued_at > current + COMMAND_CAPABILITY_ISSUE_SKEW_SECONDS * MICROS_PER_SECOND {
        return Err("capability_issued_in_future");
    }
    if expires_at <= issued_at {
        return Err("capability_expiry_invalid");
    }
    if expires_at - issued_at > COMMAND_CAPABILITY_MAX_TTL_SECONDS * MICROS_PER_SECOND {
        return Err("capability_ttl_exceeded");
    }
    if expires_at <= current {
        return Err("capability_expired");
    }
    if !non_blank_string(capability.get("nonce")) {
        return Err("capability_nonce_invalid");
    }
    // The caller resolves the OAuth device binding; a failure there is raised
    // where Python raised it, before the grant's own fields are read.
    if let Some(code) = request.oauth_error.as_deref() {
        return Err(oauth_error_code(code));
    }
    if capability.get("deviceId").and_then(Value::as_str) != request.device_id.as_deref() {
        return Err("capability_device_mismatch");
    }
    if capability.get("workspaceId").and_then(Value::as_str) != request.workspace_id.as_deref() {
        return Err("capability_workspace_mismatch");
    }
    let granted = granted_operations(capability.get("operations"))?;
    // Project signed grants onto the current runtime operation set, so a
    // capability cannot outlive the operations it was issued for.
    let mut active: Vec<&str> = granted
        .iter()
        .map(String::as_str)
        .filter(|operation| command_operation_is_classified(operation))
        .collect();
    active.sort_unstable();
    let mut projected = capability;
    projected.insert(
        "operations".to_owned(),
        Value::from(
            active
                .iter()
                .map(|value| Value::from(*value))
                .collect::<Vec<_>>(),
        ),
    );
    Ok(projected)
}

/// The two codes `_oauth_target` raises. Anything else the caller reports is
/// narrowed to the connection code rather than echoed into the audit trail.
fn oauth_error_code(code: &str) -> &'static str {
    match code {
        "cloud_device_binding_mismatch" => "cloud_device_binding_mismatch",
        _ => "cloud_connection_required",
    }
}

fn granted_operations(operations: Option<&Value>) -> Result<Vec<String>, &'static str> {
    let items = operations
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or("capability_operations_invalid")?;
    let mut granted = Vec::with_capacity(items.len());
    for item in items {
        let operation = item
            .as_str()
            .filter(|operation| !operation.is_empty())
            .ok_or("capability_operations_invalid")?;
        if granted.iter().any(|seen: &String| seen == operation) {
            return Err("capability_operations_invalid");
        }
        granted.push(operation.to_owned());
    }
    Ok(granted)
}

/// `_verify_signed_payload` for this op's own capability envelope.
fn verify_signed_payload(
    request: &CommandCapabilityRequestV1,
) -> Result<Map<String, Value>, &'static str> {
    verify_signed_envelope(
        &request.capability,
        request.integrity_key_b64.as_deref(),
        request.integrity_key_id.as_deref(),
    )
}

/// `_verify_signed_payload`: the envelope's HMAC over its own canonical bytes,
/// keyed by the local policy integrity secret. Shared with the envelope op,
/// which asks the same question about the local approval grants.
pub(crate) fn verify_signed_envelope(
    payload: &Value,
    integrity_key_b64: Option<&str>,
    integrity_key_id: Option<&str>,
) -> Result<Map<String, Value>, &'static str> {
    let envelope = payload.as_object().ok_or("signed_payload_missing")?;
    let signature = envelope
        .get("signature")
        .and_then(Value::as_str)
        .filter(|signature| !signature.is_empty())
        .ok_or("signed_payload_missing_signature")?;
    let key = decode_key(integrity_key_b64).ok_or("local_signing_key_unavailable")?;
    let key_id = integrity_key_id.ok_or("local_signing_key_unavailable")?;
    let mut unsigned = envelope.clone();
    unsigned.remove("signature");
    if unsigned.get("keyId").and_then(Value::as_str) != Some(key_id) {
        return Err("signed_payload_key_mismatch");
    }
    let expected = hmac_hex(&key, &canonical_bytes(&Value::Object(unsigned.clone()))?)?;
    if !constant_time_equal(signature.as_bytes(), expected.as_bytes()) {
        return Err("signed_payload_invalid_signature");
    }
    Ok(unsigned)
}

/// `_signed_payload`: the caller's fields, the key id they were signed under,
/// and the HMAC over exactly those bytes.
pub(crate) fn sign_envelope(
    payload: &Value,
    integrity_key_b64: Option<&str>,
    integrity_key_id: Option<&str>,
) -> Result<Map<String, Value>, &'static str> {
    let fields = payload.as_object().ok_or("signed_payload_missing")?;
    let key = decode_key(integrity_key_b64).ok_or("local_signing_key_unavailable")?;
    let key_id = integrity_key_id.ok_or("local_signing_key_unavailable")?;
    let mut unsigned = fields.clone();
    unsigned.insert("keyId".to_owned(), Value::from(key_id));
    let signature = hmac_hex(&key, &canonical_bytes(&Value::Object(unsigned.clone()))?)?;
    let mut signed = unsigned;
    signed.insert("signature".to_owned(), Value::from(signature));
    Ok(signed)
}

/// `_identity_digest`: the digest the replay rows and the approval grants
/// both name an identity by.
pub(crate) fn envelope_digest(payload: &Value) -> Result<String, &'static str> {
    Ok(content_digest(&canonical_bytes(payload)?))
}

fn hmac_hex(key: &[u8], message: &[u8]) -> Result<String, &'static str> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| "local_signing_key_unavailable")?;
    mac.update(message);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn decode_key(encoded: Option<&str>) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(encoded?).ok()
}

/// `command_job_identity`: the leased job's own fields, in the order Python
/// read them, reduced to the identity the replay scan and audit trail use.
fn job_identity(request: &CommandCapabilityRequestV1) -> Result<Map<String, Value>, &'static str> {
    let job = request.job.as_object().ok_or("command_job_invalid")?;
    let operation = job
        .get("operation")
        .and_then(Value::as_str)
        .filter(|operation| request.schema_versions.contains_key(*operation))
        .ok_or("command_operation_unsupported")?;
    let mut identity = Map::new();
    identity.insert("operation".to_owned(), Value::from(operation));
    const REQUIRED: &[(&str, &str)] = &[
        ("id", "command_id_missing"),
        ("deviceId", "command_device_missing"),
        ("workspaceId", "command_workspace_missing"),
        ("nonce", "command_nonce_missing"),
        ("expiresAt", "command_expiry_missing"),
        ("idempotencyKey", "command_idempotency_key_missing"),
    ];
    for (field, missing) in REQUIRED {
        let value = job
            .get(*field)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(*missing)?;
        if *field == "id" && !portable_command_argument(value) {
            return Err("command_id_invalid");
        }
        identity.insert((*field).to_owned(), Value::from(value));
    }
    let expected_version = request
        .schema_versions
        .get(operation)
        .ok_or("command_operation_unsupported")?;
    if !numeric_equal(job.get("schemaVersion"), expected_version) {
        return Err("command_schema_version_mismatch");
    }
    identity.insert(
        "schemaVersion".to_owned(),
        job.get("schemaVersion").cloned().unwrap_or(Value::Null),
    );
    let payload = job
        .get("payload")
        .filter(|payload| payload.is_object())
        .ok_or("command_payload_invalid")?;
    identity.insert(
        "payloadDigest".to_owned(),
        Value::from(content_digest(&canonical_bytes(payload)?)),
    );
    Ok(identity)
}

/// `authorize_command_job` minus the capability check its caller already made.
fn authorize(
    request: &CommandCapabilityRequestV1,
    capability: &Map<String, Value>,
) -> Result<Value, &'static str> {
    let identity = job_identity(request)?;
    let operation = identity
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("command_operation_unsupported")?
        .to_owned();
    let granted = capability
        .get("operations")
        .and_then(Value::as_array)
        .is_some_and(|operations| {
            operations
                .iter()
                .any(|value| value.as_str() == Some(operation.as_str()))
        });
    if !granted {
        return Err("command_operation_not_granted");
    }
    if identity.get("deviceId") != capability.get("deviceId") {
        return Err("command_device_mismatch");
    }
    if identity.get("workspaceId") != capability.get("workspaceId") {
        return Err("command_workspace_mismatch");
    }
    let expires_at = timestamp(identity.get("expiresAt")).ok_or("command_expiry_invalid")?;
    let current = utc_timestamp_micros(request.now.trim()).ok_or("invalid_current_time")?;
    if expires_at <= current {
        return Err("command_expired");
    }
    if expires_at > current + COMMAND_JOB_MAX_LIFETIME_SECONDS * MICROS_PER_SECOND {
        return Err("command_expiry_too_distant");
    }
    let identity_digest = content_digest(&canonical_bytes(&Value::Object(identity.clone()))?);
    if job_seen(request, &identity, &identity_digest, current) {
        return Err("command_replayed");
    }
    Ok(json!({
        "authorized": true,
        "reason": Value::Null,
        "identity": Value::Object(identity),
        "operation": operation,
        "requires_local_approval": command_operation_requires_local_approval(&operation),
    }))
}

/// `_command_job_seen` for a caller that decided its own authorization and
/// only needs the replay answer. A time the runtime cannot read leaves the
/// rows unreadable, so the identity reads as already seen rather than new.
fn replay_answer(request: &CommandCapabilityRequestV1) -> Option<bool> {
    let identity = request.replay_identity.as_object()?;
    let Some(current) = utc_timestamp_micros(request.now.trim()) else {
        return Some(true);
    };
    let Ok(canonical) = canonical_bytes(&Value::Object(identity.clone())) else {
        return Some(true);
    };
    Some(job_seen(
        request,
        identity,
        &content_digest(&canonical),
        current,
    ))
}

/// An unexpired row naming this identity, job id or idempotency key means
/// the lease already ran.
fn job_seen(
    request: &CommandCapabilityRequestV1,
    identity: &Map<String, Value>,
    identity_digest: &str,
    current: i64,
) -> bool {
    let job_id = identity.get("id");
    let idempotency_key = identity.get("idempotencyKey");
    request.replay_items.iter().any(|item| {
        let Some(item) = item.as_object() else {
            return false;
        };
        let matches = item.get("identityDigest").and_then(Value::as_str) == Some(identity_digest)
            || (job_id.is_some() && item.get("jobId") == job_id)
            || (idempotency_key.is_some() && item.get("idempotencyKey") == idempotency_key);
        matches && timestamp(item.get("expiresAt")).is_some_and(|expires| expires > current)
    })
}

fn timestamp(value: Option<&Value>) -> Option<i64> {
    utc_timestamp_micros(value?.as_str()?.trim())
}

fn non_blank_string(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

/// Python compares the stored number with `==`, which does not distinguish an
/// integer from the same value written as a float.
fn numeric_equal(left: Option<&Value>, right: &Value) -> bool {
    match (left, right) {
        (Some(Value::Number(left)), Value::Number(right)) => {
            match (left.as_f64(), right.as_f64()) {
                (Some(left), Some(right)) => left == right,
                _ => left == right,
            }
        }
        (Some(left), right) => left == right,
        (None, _) => false,
    }
}

/// `portable_command.portable_command_argument`: the bounded identifier set a
/// job id must stay inside to be safe to echo into a copy-paste command.
fn portable_command_argument(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:@/+=,-".contains(character))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

/// `_canonical_bytes`: `json.dumps(sort_keys=True, separators=(",", ":"),
/// ensure_ascii=True)`. The signature covers these exact bytes, so the shared
/// CPython-exact encoder owns the escaping and the float spelling. It declines
/// only values JSON could not carry here in the first place.
fn canonical_bytes(value: &Value) -> Result<Vec<u8>, &'static str> {
    Ok(dumps_sorted(value)
        .ok_or("command_capability_unencodable")?
        .into_bytes())
}

fn content_digest(payload: &[u8]) -> String {
    guard_policy_snapshot::digest_bytes(payload)
}

#[cfg(test)]
#[path = "command_capability_op_tests.rs"]
mod tests;
