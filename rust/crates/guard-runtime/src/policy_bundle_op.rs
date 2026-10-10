//! `PolicyBundleAuthority` resident op.
//!
//! Rust owns every verdict about signed Guard Cloud policy bundles. The Python
//! transport sends one `kind` plus a JSON `input`; large documents travel as
//! JSON text chunks. A malformed request is a typed error result and never
//! falls back to Python.

use guard_contracts::{
    PolicyBundleAuthorityRequestV1, PolicyBundleAuthorityResultV1,
    POLICY_BUNDLE_AUTHORITY_MAX_BYTES, POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA,
    POLICY_BUNDLE_AUTHORITY_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::{json, Value};

use super::context_digest_json::write_canonical_json_with_limit;
use crate::policy_bundle_json::parse_chunks;
use crate::policy_bundle_keys::{keys_from_wire, Key};
use crate::policy_bundle_py::Obj;

const INVALID: &str = "native_policy_bundle_authority_invalid";
const UNKNOWN_KIND: &str = "native_policy_bundle_authority_unknown_kind";

/// Why a handler produced no verdict document.
pub(crate) enum Fail {
    /// The request itself is malformed: an error result.
    Invalid,
    /// A policy-level rejection code reported inside an `ok` result.
    Code(String),
}

pub(crate) type Handled = Result<Value, Fail>;

impl From<&str> for Fail {
    fn from(code: &str) -> Self {
        Fail::Code(code.to_owned())
    }
}

impl From<String> for Fail {
    fn from(code: String) -> Self {
        Fail::Code(code)
    }
}

/// The `{"error": code}` verdict document.
pub(crate) fn rejected(code: &str) -> Value {
    json!({ "error": code })
}

pub(crate) fn field<'a>(input: &'a Obj, name: &str) -> Result<&'a Value, Fail> {
    input.get(name).ok_or(Fail::Invalid)
}

pub(crate) fn text_field<'a>(input: &'a Obj, name: &str) -> Result<&'a str, Fail> {
    field(input, name)?.as_str().ok_or(Fail::Invalid)
}

pub(crate) fn optional_text<'a>(input: &'a Obj, name: &str) -> Result<Option<&'a str>, Fail> {
    match input.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(Fail::Invalid),
    }
}

pub(crate) fn number_field(input: &Obj, name: &str) -> Result<f64, Fail> {
    field(input, name)?.as_f64().ok_or(Fail::Invalid)
}

pub(crate) fn flag(input: &Obj, name: &str) -> Result<bool, Fail> {
    field(input, name)?.as_bool().ok_or(Fail::Invalid)
}

pub(crate) fn keys_field(input: &Obj, name: &str) -> Result<Vec<Key>, Fail> {
    match input.get(name) {
        Some(Value::Array(_)) => Ok(keys_from_wire(input.get(name))),
        _ => Err(Fail::Invalid),
    }
}

/// Decode a chunked JSON document; a parse failure is a policy-level code.
pub(crate) fn document(input: &Obj, name: &str) -> Result<Value, Fail> {
    match field(input, name)? {
        Value::Array(chunks) => parse_chunks(chunks).map_err(Fail::from),
        _ => Err(Fail::Invalid),
    }
}

pub(crate) fn object_document(input: &Obj, name: &str) -> Result<Obj, Fail> {
    match document(input, name)? {
        Value::Object(map) => Ok(map),
        _ => Err(Fail::Invalid),
    }
}

fn request_digest(request: &PolicyBundleAuthorityRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| INVALID)?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, POLICY_BUNDLE_AUTHORITY_MAX_BYTES)
        .map_err(|_| INVALID)?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

fn dispatch(kind: &str, input: &Obj) -> Option<Handled> {
    crate::policy_bundle_op_validate::handle(kind, input)
        .or_else(|| crate::policy_bundle_op_keys::handle(kind, input))
        .or_else(|| crate::policy_bundle_op_delivery::handle(kind, input))
}

fn respond(
    request: &PolicyBundleAuthorityRequestV1,
    digest: String,
    status: &str,
    code: &str,
    result: Value,
) -> Result<Vec<u8>, String> {
    crate::encode_response(&PolicyBundleAuthorityResultV1 {
        schema: POLICY_BUNDLE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256: digest,
        status: status.to_owned(),
        code: code.to_owned(),
        result,
    })
}

pub(crate) fn evaluate_policy_bundle_authority_request(
    request: &PolicyBundleAuthorityRequestV1,
) -> Result<Vec<u8>, String> {
    let digest = request_digest(request).unwrap_or_default();
    if request.schema != POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 128
        || digest.is_empty()
    {
        return respond(request, digest, "error", INVALID, Value::Null);
    }
    let Value::Object(input) = &request.input else {
        return respond(request, digest, "error", INVALID, Value::Null);
    };
    match dispatch(&request.kind, input) {
        None => respond(request, digest, "error", UNKNOWN_KIND, Value::Null),
        Some(Err(Fail::Invalid)) => respond(request, digest, "error", INVALID, Value::Null),
        Some(Err(Fail::Code(code))) => respond(request, digest, "ok", "ok", rejected(&code)),
        Some(Ok(value)) => respond(request, digest, "ok", "ok", value),
    }
}
