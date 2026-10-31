//! `harness-coverage --stdin`: verify, register or unregister managed user
//! harnesses in the machine registry for the Python MDM surfaces.
//!
//! `harness_coverage` does the work; this command frames the request and
//! writes the answer back as JSON. A refused registry change is an answer,
//! carrying the class of error the caller raises; only a malformed request
//! fails the command.

use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::harness_coverage::{register, unregister, verify, CoverageError, Verification};

const SCHEMA: &str = "harness-coverage.v1";
// A user's coverage request is bounded well below this by the caller.
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    state_root: PathBuf,
    registry_owner_uid: u32,
    #[serde(default)]
    required_harnesses: Option<Vec<String>>,
    #[serde(default)]
    home: Option<String>,
    #[serde(default)]
    installs: Option<Vec<Value>>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "harness-coverage"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "harness_coverage_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("harness_coverage_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "harness_coverage_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("harness_coverage_request_invalid".to_owned());
    }
    let response = respond(request).ok_or_else(|| "harness_coverage_request_invalid".to_owned())?;
    serde_json::to_vec(&response).map_err(|_| "harness_coverage_response_encode_failed".to_owned())
}

fn respond(request: Request) -> Option<Value> {
    let state_root = request.state_root.as_path();
    let owner_uid = request.registry_owner_uid;
    match (
        request.op.as_str(),
        request.required_harnesses,
        request.home,
        request.installs,
    ) {
        ("verify", Some(required), None, None) => {
            Some(verification_json(&verify(state_root, owner_uid, &required)))
        }
        ("register", None, Some(home), Some(installs)) => Some(change_json(register(
            state_root,
            owner_uid,
            &PathBuf::from(home),
            &installs,
        ))),
        ("unregister", None, Some(home), None) => {
            Some(change_json(unregister(state_root, owner_uid, &home)))
        }
        _ => None,
    }
}

fn verification_json(verification: &Verification) -> Value {
    let coverage = verification.coverage.map_or(Value::Null, |coverage| {
        json!({
            "required": coverage.required,
            "protected": coverage.protected,
            "degraded": coverage.degraded,
            "missing": coverage.missing,
        })
    });
    json!({
        "ok": true,
        "state": verification.state,
        "reason_code": verification.reason_code,
        "coverage": coverage,
    })
}

fn change_json(result: Result<(), CoverageError>) -> Value {
    match result {
        Ok(()) => json!({"ok": true}),
        Err(error) => json!({
            "ok": false,
            "error_class": error.class.as_str(),
            "reason_code": error.reason_code,
        }),
    }
}

#[cfg(test)]
#[path = "harness_coverage_command_tests.rs"]
mod tests;
