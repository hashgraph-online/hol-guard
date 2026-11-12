//! `exact-cloud-review --stdin`: the signed local consent behind exact Guard
//! Cloud reviews. Ported from `runtime/exact_cloud_review.py` (`_sign`,
//! `_verify`, `_capability_digest`, `_verified_capability` and
//! `_exact_job_identity`).
//!
//! The capability a user issues with `hol-guard cloud-review enable` and the
//! revocation `disable` writes are HMAC envelopes over the local policy
//! integrity secret. Whether a stored capability is genuine, current, bound to
//! this device and not revoked decides whether Guard Cloud may resolve one
//! review on this machine, so the runtime answers it. Python reads the stored
//! envelopes, the signing key and the OAuth binding, and writes what comes
//! back:
//!
//! - `{"op": "sign", "key", "key_id", "payload"}` answers `{"envelope"}`;
//! - `{"op": "verify", "key", "key_id", "envelope"}` answers `{"unsigned"}`;
//! - `{"op": "digest", "payload"}` answers `{"digest"}`;
//! - `{"op": "capability", "key", "key_id", "capability", "revocation",
//!   "binding", "now"}` answers `{"capability", "digest"}`;
//! - `{"op": "job", "job", "now"}` answers `{"identity"}`.
//!
//! A refusal answers `{"error": code}` with the Python code verbatim, plus
//! `drift_digest` when the capability names another OAuth binding, so the
//! caller can revoke exactly that capability. A `null` binding means the
//! caller could not read one; the answer is `binding_unreadable` at the point
//! the binding is compared, and the caller raises its own reason.
//!
//! The envelopes are encoded as `stable_json_serialize` writes them (sorted
//! keys, compact, UTF-8), which is what every stored signature covers.

use std::io::Read;

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{utc_timestamp_micros, write_canonical_json_utf8};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::daemon_lifecycle_text::py_strip;

const OPERATION: &str = "guard.review.resolveExact";
const PROTOCOL_VERSION: f64 = 2.0;
const MICROS_PER_SECOND: i64 = 1_000_000;
/// `EXACT_CLOUD_REVIEW_MAX_TTL_SECONDS`: a capability lives at most a year.
const MAX_TTL_MICROS: i64 = 365 * 24 * 60 * 60 * MICROS_PER_SECOND;
/// Clock skew a capability's `issuedAt` may run ahead of this machine.
const ISSUE_SKEW_MICROS: i64 = 5 * 60 * MICROS_PER_SECOND;
/// A leased exact review expires within a day.
const JOB_MAX_LIFETIME_MICROS: i64 = 24 * 60 * 60 * MICROS_PER_SECOND;
/// The job fields an identity carries, each with the code naming it missing.
const JOB_STRINGS: [(&str, &str); 6] = [
    ("id", "remote_exact_job_id_missing"),
    ("deviceId", "remote_exact_job_device_missing"),
    ("workspaceId", "remote_exact_job_workspace_missing"),
    ("nonce", "remote_exact_job_nonce_missing"),
    ("expiresAt", "remote_exact_job_expiry_missing"),
    ("idempotencyKey", "remote_exact_job_idempotency_key_missing"),
];
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
/// The caller could not read the OAuth binding; it names its own reason.
const BINDING_UNREADABLE: &str = "binding_unreadable";

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Sign {
        key: Option<String>,
        key_id: Option<String>,
        payload: Map<String, Value>,
    },
    Verify {
        key: Option<String>,
        key_id: Option<String>,
        envelope: Value,
    },
    Digest {
        payload: Value,
    },
    Capability {
        key: Option<String>,
        key_id: Option<String>,
        capability: Value,
        revocation: Value,
        binding: Option<Map<String, Value>>,
        now: String,
    },
    Job {
        job: Value,
        now: String,
    },
}

/// The local signing key as the request carries it.
struct SigningKey<'a> {
    key: Option<&'a str>,
    key_id: Option<&'a str>,
}

impl SigningKey<'_> {
    fn material(&self) -> Result<(Vec<u8>, &str), Refusal> {
        let key = self
            .key
            .and_then(|key| Base64UrlUnpadded::decode_vec(key).ok());
        match (key, self.key_id) {
            (Some(key), Some(key_id)) => Ok((key, key_id)),
            _ => Err(Refusal::code("cloud_review_signing_key_unavailable")),
        }
    }
}

/// A refusal code, or a request the runtime cannot read at all.
#[derive(Debug, PartialEq)]
enum Refusal {
    Code(&'static str, Option<String>),
    Fault(&'static str),
}

impl Refusal {
    fn code(code: &'static str) -> Self {
        Self::Code(code, None)
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "exact-cloud-review"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "exact_cloud_review_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("exact_cloud_review_request_too_large".to_owned());
    }
    let request: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    serde_json::to_vec(&answer(request)?)
        .map_err(|_| "exact_cloud_review_response_encode_failed".to_owned())
}

const RESIDENT_REQUEST_SCHEMA: &str = "guard-exact-cloud-review-resident-request.v1";
const RESIDENT_RESULT_SCHEMA: &str = "guard-exact-cloud-review-resident-result.v1";

/// One exact Cloud Review request for the resident, so a Review job does not
/// start a helper process for every signature, check and digest it needs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExactCloudReviewResidentRequest {
    schema: String,
    request: Value,
}

impl std::fmt::Debug for ExactCloudReviewResidentRequest {
    // The request can carry the local signing key, so it is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExactCloudReviewResidentRequest")
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

/// The resident's answer: the same JSON the `exact-cloud-review` helper
/// prints, under `answer`. A refusal is an answer; only a fault is an error.
pub(crate) fn evaluate_resident_request(
    request: ExactCloudReviewResidentRequest,
) -> Result<Vec<u8>, String> {
    if request.schema != RESIDENT_REQUEST_SCHEMA {
        return Err(invalid());
    }
    let answer = answer(request.request)?;
    crate::encode_response(&json!({
        "schema": RESIDENT_RESULT_SCHEMA,
        "status": "ok",
        "answer": answer,
    }))
}

fn invalid() -> String {
    "exact_cloud_review_request_invalid".to_owned()
}

fn answer(request: Value) -> Result<Value, String> {
    let request: Request = serde_json::from_value(request).map_err(|_| invalid())?;
    let answered = match request {
        Request::Sign {
            key,
            key_id,
            payload,
        } => {
            sign(&signing_key(&key, &key_id), payload).map(|envelope| json!({"envelope": envelope}))
        }
        Request::Verify {
            key,
            key_id,
            envelope,
        } => verify(&signing_key(&key, &key_id), &envelope)
            .map(|unsigned| json!({"unsigned": unsigned})),
        Request::Digest { payload } => digest(&payload).map(|digest| json!({"digest": digest})),
        Request::Capability {
            key,
            key_id,
            capability,
            revocation,
            binding,
            now,
        } => verified_capability(
            &signing_key(&key, &key_id),
            &capability,
            &revocation,
            binding.as_ref(),
            &now,
        ),
        Request::Job { job, now } => {
            job_identity(&job, &now).map(|identity| json!({"identity": identity}))
        }
    };
    match answered {
        Ok(answer) => Ok(answer),
        Err(Refusal::Code(code, None)) => Ok(json!({"error": code})),
        Err(Refusal::Code(code, Some(drift))) => Ok(json!({"error": code, "drift_digest": drift})),
        Err(Refusal::Fault(code)) => Err(code.to_owned()),
    }
}

fn signing_key<'a>(key: &'a Option<String>, key_id: &'a Option<String>) -> SigningKey<'a> {
    SigningKey {
        key: key.as_deref(),
        key_id: key_id.as_deref(),
    }
}

/// `_canonical`: `stable_json_serialize(payload).encode("utf-8")`.
fn canonical(value: &Value) -> Result<Vec<u8>, Refusal> {
    let mut out = Vec::new();
    write_canonical_json_utf8(value, &mut out)
        .map_err(|_| Refusal::Fault("exact_cloud_review_unencodable"))?;
    Ok(out)
}

/// `_capability_digest` and the job's `payloadDigest`.
fn digest(value: &Value) -> Result<String, Refusal> {
    Ok(guard_policy_snapshot::digest_bytes(&canonical(value)?))
}

fn hmac_hex(key: &[u8], message: &[u8]) -> Result<String, Refusal> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Refusal::code("cloud_review_signing_key_unavailable"))?;
    mac.update(message);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// `_sign`: the fields, the key id they are signed under, and the HMAC over
/// exactly those bytes.
fn sign(key: &SigningKey<'_>, payload: Map<String, Value>) -> Result<Map<String, Value>, Refusal> {
    let (key, key_id) = key.material()?;
    let mut signed = payload;
    signed.insert("keyId".to_owned(), Value::from(key_id));
    let signature = hmac_hex(&key, &canonical(&Value::Object(signed.clone()))?)?;
    signed.insert("signature".to_owned(), Value::from(signature));
    Ok(signed)
}

/// `_verify`: the envelope's unsigned fields when its HMAC is genuine.
fn verify(key: &SigningKey<'_>, envelope: &Value) -> Result<Map<String, Value>, Refusal> {
    let envelope = envelope
        .as_object()
        .ok_or(Refusal::code("cloud_review_capability_missing"))?;
    let signature = text(envelope.get("signature"))
        .ok_or(Refusal::code("cloud_review_capability_signature_missing"))?;
    let mut unsigned = envelope.clone();
    unsigned.remove("signature");
    let (key, key_id) = key.material()?;
    if unsigned.get("keyId").and_then(Value::as_str) != Some(key_id) {
        return Err(Refusal::code("cloud_review_capability_key_mismatch"));
    }
    let expected = hmac_hex(&key, &canonical(&Value::Object(unsigned.clone()))?)?;
    if !constant_time_equal(signature.as_bytes(), expected.as_bytes()) {
        return Err(Refusal::code("cloud_review_capability_signature_invalid"));
    }
    Ok(unsigned)
}

/// `_verified_capability`: the stored capability, when it is genuine, current,
/// names this device's OAuth binding and no revocation covers it. `binding`
/// is the caller's binding, or `None` when it could not read one.
fn verified_capability(
    key: &SigningKey<'_>,
    capability: &Value,
    revocation: &Value,
    binding: Option<&Map<String, Value>>,
    now: &str,
) -> Result<Value, Refusal> {
    let capability = verify(key, capability)?;
    if capability.get("operation").and_then(Value::as_str) != Some(OPERATION) {
        return Err(Refusal::code("cloud_review_capability_operation_invalid"));
    }
    if text(capability.get("issuer")).is_none() || text(capability.get("nonce")).is_none() {
        return Err(Refusal::code("cloud_review_capability_invalid"));
    }
    let issued_at = timestamp(capability.get("issuedAt"));
    let expires_at = timestamp(capability.get("expiresAt"));
    let current = current_time(now)?;
    let (Some(issued_at), Some(expires_at)) = (issued_at, expires_at) else {
        return Err(Refusal::code("cloud_review_capability_time_invalid"));
    };
    if expires_at <= issued_at {
        return Err(Refusal::code("cloud_review_capability_time_invalid"));
    }
    if issued_at > current + ISSUE_SKEW_MICROS {
        return Err(Refusal::code("cloud_review_capability_issued_in_future"));
    }
    if expires_at - issued_at > MAX_TTL_MICROS {
        return Err(Refusal::code("cloud_review_capability_ttl_invalid"));
    }
    if expires_at <= current {
        return Err(Refusal::code("cloud_review_capability_expired"));
    }
    let binding = binding.ok_or(Refusal::code(BINDING_UNREADABLE))?;
    let capability = Value::Object(capability);
    let capability_digest = digest(&capability)?;
    if binding
        .iter()
        .any(|(field, value)| capability.get(field).unwrap_or(&Value::Null) != value)
    {
        return Err(Refusal::Code(
            "cloud_review_capability_binding_mismatch",
            Some(capability_digest),
        ));
    }
    if !revocation.is_null() {
        let revocation_invalid = Refusal::code("cloud_review_capability_revocation_invalid");
        if !revocation.is_object() {
            return Err(revocation_invalid);
        }
        let revocation = verify(key, revocation)?;
        if timestamp(revocation.get("revokedAt")).is_none() {
            return Err(revocation_invalid);
        }
        match revocation.get("capabilityDigest") {
            None | Some(Value::Null) => {
                return Err(Refusal::code("cloud_review_capability_revoked"))
            }
            Some(Value::String(revoked)) if *revoked == capability_digest => {
                return Err(Refusal::code("cloud_review_capability_revoked"))
            }
            Some(Value::String(_)) => {}
            Some(_) => return Err(revocation_invalid),
        }
    }
    Ok(json!({"capability": capability, "digest": capability_digest}))
}

/// `_exact_job_identity` plus the lease checks `authorize_exact_cloud_review_job`
/// makes before it looks at the payload.
fn job_identity(job: &Value, now: &str) -> Result<Map<String, Value>, Refusal> {
    let job = job
        .as_object()
        .ok_or(Refusal::code("remote_exact_job_invalid"))?;
    if job.get("operation").and_then(Value::as_str) != Some(OPERATION) {
        return Err(Refusal::code("remote_exact_job_operation_invalid"));
    }
    // Python compares with `!=`, which reads 2.0 as the same version.
    let version = job.get("protocolVersion").and_then(|value| match value {
        Value::Number(number) => number.as_f64(),
        _ => None,
    });
    if version != Some(PROTOCOL_VERSION) {
        return Err(Refusal::code("cloud_review_protocol_upgrade_required"));
    }
    if job.contains_key("schemaVersion") {
        return Err(Refusal::code("remote_exact_job_invalid"));
    }
    let mut identity = Map::new();
    identity.insert("operation".to_owned(), Value::from(OPERATION));
    for (field, missing) in JOB_STRINGS {
        let value = text(job.get(field)).ok_or(Refusal::code(missing))?;
        identity.insert(field.to_owned(), Value::from(value));
    }
    let payload = job
        .get("payload")
        .filter(|payload| payload.is_object())
        .ok_or(Refusal::code("remote_exact_job_invalid"))?;
    identity.insert("payloadDigest".to_owned(), Value::from(digest(payload)?));
    let Some(expires_at) = timestamp(identity.get("expiresAt")) else {
        return Err(Refusal::code("remote_exact_job_expired"));
    };
    let current = current_time(now)?;
    if expires_at <= current {
        return Err(Refusal::code("remote_exact_job_expired"));
    }
    if expires_at > current + JOB_MAX_LIFETIME_MICROS {
        return Err(Refusal::code("remote_exact_job_expiry_too_distant"));
    }
    Ok(identity)
}

/// `_text`: a stripped string with something in it.
fn text(value: Option<&Value>) -> Option<&str> {
    let value = py_strip(value?.as_str()?);
    (!value.is_empty()).then_some(value)
}

/// `parse_utc_timestamp`, in microseconds since the epoch.
fn timestamp(value: Option<&Value>) -> Option<i64> {
    utc_timestamp_micros(text(value)?)
}

fn current_time(now: &str) -> Result<i64, Refusal> {
    utc_timestamp_micros(py_strip(now)).ok_or(Refusal::code("cloud_review_current_time_invalid"))
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

#[cfg(test)]
#[path = "exact_cloud_review_tests.rs"]
mod tests;
