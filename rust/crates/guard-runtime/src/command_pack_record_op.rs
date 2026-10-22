//! `CommandPackRecord` - resident op that verifies or opens an authenticated
//! command-pack record.
//!
//! The policy publisher authenticates the active pack record on every poll.
//! Each record it checked used to cost a one-shot `pack-lifecycle` process
//! that re-verified the runtime before answering. The resident runs the same
//! record evaluator in process, so the answers are the one-shot's own.
//!
//! Only reading operations are served. For a pack record, `verify` returns
//! the authenticated header and `open` adds the publication and inventories
//! it binds in the Guard home's pack cache; sealing stays on the one-shot path
//! with the writes it belongs to. For the active-security record, the
//! operations that answer from the request alone are served, the ones the
//! publisher repeats on every poll; preparing a newer record reads fetched
//! proofs and stays on the one-shot path.

use std::path::Path;

use guard_contracts::{
    CommandPackRecordRequestV1, CommandPackRecordResultV1, COMMAND_PACK_RECORD_REQUEST_SCHEMA,
    COMMAND_PACK_RECORD_RESULT_SCHEMA,
};
use serde_json::Value;

use crate::package_authority_op::request_digest_with_limit;

/// Where a Guard home keeps the pack cache an `open` reads.
const PACK_CACHE: [&str; 2] = ["native-runtime", "command-packs"];

/// Active-security operations that answer from the request alone: no files,
/// clock or randomness. See the note on `active_pack_security::evaluate`.
const ACTIVE_SECURITY_OPERATIONS: [&str; 7] = [
    "scope", "check", "read", "change", "marker", "binding", "resume",
];

pub(crate) fn evaluate_command_pack_record_request(
    request: &CommandPackRecordRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, crate::MAX_NATIVE_REQUEST_BYTES)
        .map_err(|_| "native_command_pack_record_too_large".to_owned())?;
    let (status, code, payload) = match answer(request) {
        Ok(value) => ("ok", "ok".to_owned(), Some(value)),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&CommandPackRecordResultV1 {
        schema: COMMAND_PACK_RECORD_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code,
        payload,
    })
}

fn answer(request: &CommandPackRecordRequestV1) -> Result<Value, String> {
    if request.schema != COMMAND_PACK_RECORD_REQUEST_SCHEMA {
        return Err("native_command_pack_record_schema_mismatch".to_owned());
    }
    let record = &request.record;
    let operation = record["operation"].as_str();
    let invalid = || Err("native_command_pack_record_operation_invalid".to_owned());
    match (record["kind"].as_str(), operation) {
        (Some("record"), Some("verify")) => {}
        (Some("record"), Some("open")) => {
            require_pack_cache(&request.guard_home, &record["directory"])?
        }
        (Some("record"), _) => return invalid(),
        (Some("active-security"), Some(operation))
            if ACTIVE_SECURITY_OPERATIONS.contains(&operation) => {}
        (Some("active-security"), _) => return invalid(),
        _ => return Err("native_command_pack_record_kind_invalid".to_owned()),
    }
    crate::pack_lifecycle::evaluate(record)
}

/// An `open` reads only the pack cache of the Guard home the resident serves.
///
/// The one-shot trusted its caller with the directory. The resident is bound
/// to one Guard home, so a directory naming any other cache is refused rather
/// than read. Both sides are resolved, because the caller spells the cache
/// through the home's resolved prefix.
fn require_pack_cache(guard_home: &str, directory: &Value) -> Result<(), String> {
    let invalid = || "native_command_pack_record_directory_invalid".to_owned();
    let directory = directory
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid)?;
    let home = std::fs::canonicalize(guard_home).map_err(|_| invalid())?;
    let expected = PACK_CACHE.iter().fold(home, |path, part| path.join(part));
    let actual = std::fs::canonicalize(Path::new(directory)).map_err(|_| invalid())?;
    if actual == expected {
        Ok(())
    } else {
        Err(invalid())
    }
}

#[cfg(test)]
#[path = "command_pack_record_op_tests.rs"]
mod tests;
