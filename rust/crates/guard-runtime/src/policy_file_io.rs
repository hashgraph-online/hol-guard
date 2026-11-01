//! `policy-file-io --stdin`: read one trusted local policy file, or replace
//! it atomically with an owner-only file (`policy_document_io.py` before it
//! moved here).
//!
//! The file and its folder must belong to the effective user, must not be
//! writable by group or others, and are reached without following a link;
//! the file must have exactly one link. A refusal is `{"failure": code}` with
//! the reason code Python raises as `PolicyFileTrustError`; only a malformed
//! request fails the command.

use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{json, Value};

#[cfg(unix)]
#[path = "policy_file_io_unix.rs"]
mod platform;
#[cfg(not(unix))]
#[path = "policy_file_io_other.rs"]
mod platform;

#[cfg(test)]
#[path = "policy_file_io_tests.rs"]
mod tests;

const SCHEMA: &str = "policy-file-io.v1";
/// The largest policy file Guard reads or writes (`MAX_POLICY_BYTES`).
const MAX_POLICY_BYTES: usize = 1_048_576;
/// One policy file, JSON-escaped, with room for the envelope.
const MAX_REQUEST_BYTES: u64 = 8 * 1024 * 1024;

/// A refusal code Python raises as `PolicyFileTrustError`.
type Failure = &'static str;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    path: PathBuf,
    #[serde(default)]
    content: Option<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "policy-file-io"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "policy_file_io_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("policy_file_io_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if request.schema != SCHEMA || !request.path.is_absolute() {
        return Err(invalid());
    }
    let answer = match (request.op.as_str(), request.content.as_deref()) {
        ("read", None) => answer_read(&request.path),
        ("write", Some(content)) => answer_write(&request.path, content),
        _ => return Err(invalid()),
    };
    serde_json::to_vec(&answer).map_err(|_| "policy_file_io_response_unencodable".to_owned())
}

fn invalid() -> String {
    "policy_file_io_request_invalid".to_owned()
}

fn answer_read(path: &std::path::Path) -> Value {
    match read_policy_text(path) {
        Ok(text) => json!({ "text": text }),
        Err(code) => json!({ "failure": code }),
    }
}

fn answer_write(path: &std::path::Path, content: &str) -> Value {
    match write_policy_text(path, content) {
        Ok(()) => json!({ "written": true }),
        Err(code) => json!({ "failure": code }),
    }
}

fn read_policy_text(path: &std::path::Path) -> Result<String, Failure> {
    let payload = platform::read_trusted(path, MAX_POLICY_BYTES)?;
    String::from_utf8(payload).map_err(|_| "policy_file_not_utf8")
}

fn write_policy_text(path: &std::path::Path, content: &str) -> Result<(), Failure> {
    if content.len() > MAX_POLICY_BYTES {
        return Err("policy_output_too_large");
    }
    platform::write_private(path, content.as_bytes())
}
