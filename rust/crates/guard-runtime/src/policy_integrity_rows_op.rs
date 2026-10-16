//! `PolicyIntegrityRows` - resident op that verifies and signs local policy
//! rows with the policy-integrity HMAC key.
//!
//! Every canonical payload, SHA-256 hash and HMAC-SHA256 tag is computed
//! here through `guard_policy_snapshot::policy_integrity`, the same code the
//! saved-decision lookup verifies with. Digest and tag comparisons are
//! constant-time. The key is decoded into zeroizing memory, used only for
//! this request, and never echoed in a result or an error code.
//!
//! Requests fail as a whole (no payload) when the schema, item count, key
//! encoding or a row shape is invalid, or when a sign item has no key. A
//! verify item without a usable key answers `unknown_key`, matching the
//! store's own verification.
//!
//! A `generation` section reads the store's local rows read-only and decides
//! startup's trusted control state; it needs the key and fails the request
//! when the store or the given state is unusable.
//!
//! The reply's `request_sha256` binds every request field except
//! `integrity_key_b64`: the digest never covers key bytes, so a reply, log or
//! diagnostic that carries the digest reveals nothing about the key.

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{
    PolicyIntegrityGenerationRequestV1, PolicyIntegrityRowsPayloadV1, PolicyIntegrityRowsRequestV1,
    PolicyIntegrityRowsResultV1, PolicyIntegritySignItemV1, PolicyIntegritySignatureV1,
    PolicyIntegrityVerifyItemV1, PolicyIntegrityVerifyOutcomeV1, POLICY_INTEGRITY_ROWS_MAX_BYTES,
    POLICY_INTEGRITY_ROWS_MAX_ITEMS, POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
    POLICY_INTEGRITY_ROWS_RESULT_SCHEMA,
};
use guard_policy_snapshot::policy_integrity::{sign_local_policy_row, verify_local_policy_row};
use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::package_authority_op::request_digest_with_limit;

/// Upper bound on the decoded key; the store mints 32-byte keys.
const MAX_KEY_BYTES: usize = 1024;

pub(crate) fn evaluate_policy_integrity_rows_request(
    request: &PolicyIntegrityRowsRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(
        &KeyRedactedRequest::from(request),
        POLICY_INTEGRITY_ROWS_MAX_BYTES,
    )
    .map_err(|_| "native_policy_integrity_rows_too_large".to_owned())?;
    let payload = evaluate(request).map_err(str::to_owned)?;
    crate::encode_response(&PolicyIntegrityRowsResultV1 {
        schema: POLICY_INTEGRITY_ROWS_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(payload),
    })
}

/// The request as it is digested: every field but the key. Field names and
/// omission rules mirror `PolicyIntegrityRowsRequestV1`.
#[derive(Serialize)]
pub(crate) struct KeyRedactedRequest<'a> {
    schema: &'a str,
    request_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_key_id: Option<&'a str>,
    verify: &'a [PolicyIntegrityVerifyItemV1],
    sign: &'a [PolicyIntegritySignItemV1],
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<&'a PolicyIntegrityGenerationRequestV1>,
}

impl<'a> From<&'a PolicyIntegrityRowsRequestV1> for KeyRedactedRequest<'a> {
    fn from(request: &'a PolicyIntegrityRowsRequestV1) -> Self {
        Self {
            schema: &request.schema,
            request_id: &request.request_id,
            integrity_key_id: request.integrity_key_id.as_deref(),
            verify: &request.verify,
            sign: &request.sign,
            generation: request.generation.as_ref(),
        }
    }
}

pub(crate) fn evaluate(
    request: &PolicyIntegrityRowsRequestV1,
) -> Result<PolicyIntegrityRowsPayloadV1, &'static str> {
    if request.schema != POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA {
        return Err("native_policy_integrity_rows_schema_invalid");
    }
    if request.verify.len() + request.sign.len() > POLICY_INTEGRITY_ROWS_MAX_ITEMS {
        return Err("native_policy_integrity_rows_too_many_items");
    }
    let key = decode_key(request.integrity_key_b64.as_deref())?;
    let key_id = request
        .integrity_key_id
        .as_deref()
        .filter(|value| !value.is_empty());
    let key_bytes: Option<&[u8]> = key.as_ref().map(|key| &key[..]);
    let verify = request
        .verify
        .iter()
        .map(|item| verify_item(item, key_bytes, key_id))
        .collect::<Result<Vec<_>, _>>()?;
    let sign = if request.sign.is_empty() {
        Vec::new()
    } else {
        let (Some(key), Some(key_id)) = (key_bytes, key_id) else {
            return Err("native_policy_integrity_key_unavailable");
        };
        request
            .sign
            .iter()
            .map(|item| sign_item(item, key, key_id))
            .collect::<Result<Vec<_>, _>>()?
    };
    let generation = match &request.generation {
        None => None,
        Some(generation) => {
            let (Some(key), Some(key_id)) = (key_bytes, key_id) else {
                return Err("native_policy_integrity_key_unavailable");
            };
            Some(crate::policy_integrity_generation::decide(
                generation, key, key_id,
            )?)
        }
    };
    Ok(PolicyIntegrityRowsPayloadV1 {
        verify,
        sign,
        generation,
    })
}

/// The decoded key, `None` when the caller shipped none. A key that is not
/// unpadded base64url, is empty, or is oversized fails the request.
fn decode_key(encoded: Option<&str>) -> Result<Option<Zeroizing<Vec<u8>>>, &'static str> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let key = Zeroizing::new(
        Base64UrlUnpadded::decode_vec(encoded)
            .map_err(|_| "native_policy_integrity_key_invalid")?,
    );
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err("native_policy_integrity_key_invalid");
    }
    Ok(Some(key))
}

fn verify_item(
    item: &PolicyIntegrityVerifyItemV1,
    key: Option<&[u8]>,
    key_id: Option<&str>,
) -> Result<PolicyIntegrityVerifyOutcomeV1, &'static str> {
    if !item.row.is_object() {
        return Err("native_policy_integrity_row_invalid");
    }
    let outcome = verify_local_policy_row(
        &item.row,
        key,
        key_id,
        item.degraded_mode,
        item.trusted_generation,
    );
    Ok(PolicyIntegrityVerifyOutcomeV1 {
        status: outcome.status.to_owned(),
        payload_hash: outcome.payload_hash,
        key_id: outcome.key_id,
        message: outcome.message.map(str::to_owned),
    })
}

fn sign_item(
    item: &PolicyIntegritySignItemV1,
    key: &[u8],
    key_id: &str,
) -> Result<PolicyIntegritySignatureV1, &'static str> {
    if !item.row.is_object() || !decision_id_signable(&item.row) {
        return Err("native_policy_integrity_row_invalid");
    }
    let signature = sign_local_policy_row(&item.row, key, key_id, &item.signed_at, item.generation)
        .map_err(|_| "native_policy_integrity_row_invalid")?;
    Ok(PolicyIntegritySignatureV1 {
        integrity_version: signature["integrity_version"]
            .as_i64()
            .ok_or("native_policy_integrity_row_invalid")?,
        integrity_generation: item.generation,
        payload_hash: text(&signature["payload_hash"])?,
        payload_mac: text(&signature["payload_mac"])?,
        integrity_key_id: key_id.to_owned(),
        signed_at: item.signed_at.clone(),
    })
}

/// A numeric `decision_id` outside the signed 64-bit range would sign as
/// null here while the store holds the full integer; refuse it instead.
fn decision_id_signable(row: &Value) -> bool {
    match row.get("decision_id") {
        Some(Value::Number(number)) => number.as_i64().is_some(),
        _ => true,
    }
}

fn text(value: &Value) -> Result<String, &'static str> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or("native_policy_integrity_row_invalid")
}

#[cfg(test)]
#[path = "policy_integrity_rows_op_tests.rs"]
mod tests;
