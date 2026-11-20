//! `TransitionPlan.payload` and `TransitionPlan.subject`: the bounds and
//! shape every runtime transition plan must meet before it is authorized,
//! and the digest the lifecycle approval binds.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::shape::Refusal;
use super::shape::{artifact_identity, native_runtime_bindings, record_files, record_installs};
use super::{no, Request};
use crate::codex_hook_authority_record::python_json::python_canonical_json;

const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_INSTALL_BYTES: usize = 4 * 1024 * 1024;
const MAX_FILES: usize = 128;
const MAX_INSTALLS: usize = 64;

/// Bytes a standard base64 snapshot decodes to.
fn decoded_len(value: &Value) -> usize {
    value.as_str().map_or(0, |text| {
        let digits = text.trim_end_matches('=').len();
        digits * 3 / 4
    })
}

fn list<'a>(payload: &'a Map<String, Value>, key: &str) -> &'a [Value] {
    payload
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// Every check `TransitionPlan.payload` makes, in its order.
fn check(payload: &Map<String, Value>) -> Result<(), Refusal> {
    let files = list(payload, "files");
    let size: usize = files
        .iter()
        .filter_map(Value::as_object)
        .map(|change| {
            decoded_len(change.get("before").unwrap_or(&Value::Null))
                + decoded_len(change.get("after").unwrap_or(&Value::Null))
        })
        .sum();
    if size > MAX_FILE_BYTES {
        return Err(no("plan_too_large"));
    }
    let installs = list(payload, "managed_installs");
    if installs.len() > MAX_INSTALLS {
        return Err(no("managed_install_plan_invalid"));
    }
    record_installs(payload, python_canonical_json)?;
    let mut wrapped = Map::new();
    wrapped.insert("installs".to_owned(), Value::Array(installs.to_vec()));
    let encoded = python_canonical_json(&Value::Object(wrapped)).ok_or_else(|| no("invalid"))?;
    if encoded.len() > MAX_INSTALL_BYTES {
        return Err(no("managed_install_plan_too_large"));
    }
    let operation = payload.get("operation_id").and_then(Value::as_str);
    if operation.is_none_or(str::is_empty) || files.is_empty() || files.len() > MAX_FILES {
        return Err(no("plan_invalid"));
    }
    record_files(payload)?;
    for name in ["predecessor", "candidate"] {
        artifact_identity(payload.get(name))?;
    }
    native_runtime_bindings(payload)
}

/// `plan_check`: the plan is valid; answers the subject the approval binds.
pub(super) fn subject(request: &Request) -> Result<Value, Refusal> {
    let payload = request.payload.as_ref().ok_or_else(|| no("invalid"))?;
    check(payload)?;
    let canonical =
        python_canonical_json(&Value::Object(payload.clone())).ok_or_else(|| no("invalid"))?;
    Ok(json!({"subject": hex::encode(Sha256::digest(canonical.as_bytes()))}))
}

/// `files_check`: each planned change, as `TransitionFile.payload` and a
/// stored record's files must be shaped.
pub(super) fn files(request: &Request) -> Result<Value, Refusal> {
    let payload = request.payload.as_ref().ok_or_else(|| no("invalid"))?;
    record_files(payload)?;
    Ok(json!({"ok": true}))
}

/// One planned change, alone, as `TransitionFile.payload` checks it.
pub(super) fn one(change: &Map<String, Value>) -> Result<(), Refusal> {
    let mut wrapped = Map::new();
    wrapped.insert(
        "files".to_owned(),
        Value::Array(vec![Value::Object(change.clone())]),
    );
    record_files(&wrapped).map(|_| ())
}

/// `files_check_each`: every planned change on its own, so two plans may
/// name the same target.
pub(super) fn each(request: &Request) -> Result<Value, Refusal> {
    let payload = request.payload.as_ref().ok_or_else(|| no("invalid"))?;
    for change in list(payload, "files") {
        one(change.as_object().ok_or_else(|| no("files_invalid"))?)?;
    }
    Ok(json!({"ok": true}))
}

/// `check_transition_files`: the planned changes form one record.
pub(crate) fn check_files(files: &[Value]) -> Result<(), Refusal> {
    let mut wrapped = Map::new();
    wrapped.insert("files".to_owned(), Value::Array(files.to_vec()));
    record_files(&wrapped).map(|_| ())
}
