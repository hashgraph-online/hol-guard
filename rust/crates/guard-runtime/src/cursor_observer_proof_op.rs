//! `CursorObserverProof` - resident op that verifies the attestation proof a
//! managed Cursor after-observer hook presents.
//!
//! The proof is an HMAC-SHA256 over the conversation id, the normalized
//! command, the approval binding and the observer event, keyed by the
//! owner-private attestation key in the Guard home. The key is read here and
//! never leaves the resident. Every failure to verify is `valid: false`.

use std::fs;
use std::io::Read;
use std::path::Path;

use guard_command::cursor_shell_command::{
    normalize_cursor_shell_command, CursorShellNormalization,
};
use guard_contracts::{
    CursorObserverProofRequestV1, CursorObserverProofResultV1, CURSOR_OBSERVER_PROOF_MAX_BYTES,
    CURSOR_OBSERVER_PROOF_RESULT_SCHEMA,
};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::guard_store_json::py_strip;
use crate::package_authority_op::request_digest_with_limit;
use crate::resident_transport::constant_time_eq;

const ATTESTATION_RELATIVE: [&str; 2] = ["secrets", "cursor-hook-attestation.key"];
const MAX_KEY_BYTES: u64 = 4096;

pub(crate) fn evaluate_cursor_observer_proof_request(
    request: &CursorObserverProofRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, CURSOR_OBSERVER_PROOF_MAX_BYTES)
        .map_err(|_| "native_cursor_observer_proof_too_large".to_owned())?;
    crate::encode_response(&CursorObserverProofResultV1 {
        schema: CURSOR_OBSERVER_PROOF_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(evaluate(request)),
    })
}

pub(crate) fn evaluate(request: &CursorObserverProofRequestV1) -> Value {
    json!({ "valid": verify(request) })
}

fn verify(request: &CursorObserverProofRequestV1) -> bool {
    let proof = py_strip(&request.proof);
    if proof.is_empty() {
        return false;
    }
    if request.require_pending_match {
        let pending = request.pending_proof.as_deref().map(py_strip).unwrap_or("");
        if pending.is_empty() || !constant_time_eq(pending.as_bytes(), proof.as_bytes()) {
            return false;
        }
    }
    // The retired callers normalized the command and the proof computation
    // normalized it again; both passes are part of the keyed message.
    let Some(command) = normalized_once_more(&request.command) else {
        return false;
    };
    let Some(secret) = read_attestation_key(Path::new(&request.guard_home)) else {
        return false;
    };
    let expected = proof_hex(
        &secret,
        &[
            py_strip(&request.conversation_id),
            py_strip(&command),
            py_strip(&request.approval_binding),
            py_strip(&request.observer_event),
        ],
    );
    constant_time_eq(expected.as_bytes(), proof.as_bytes())
}

fn normalized_once_more(command: &str) -> Option<String> {
    let CursorShellNormalization::Command(first) = normalize_cursor_shell_command(command) else {
        return None;
    };
    match normalize_cursor_shell_command(&first) {
        CursorShellNormalization::Command(second) => Some(second),
        CursorShellNormalization::Unnormalizable => None,
    }
}

fn proof_hex(secret: &[u8], fields: &[&str]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(fields.join("\0").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// The attestation key, only when it is a regular, non-empty, owner-private
/// file reached without following a link. Anything else is no key.
///
/// The file is opened first and every check runs on the opened handle, so a
/// path swapped after the check cannot supply bytes the checks never saw.
fn read_attestation_key(guard_home: &Path) -> Option<Vec<u8>> {
    let path = ATTESTATION_RELATIVE
        .iter()
        .fold(guard_home.to_path_buf(), |base, part| base.join(part));
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(&path).ok()?;
    let metadata = file.metadata().ok()?;
    let size = metadata.len();
    if !metadata.is_file() || size == 0 || size > MAX_KEY_BYTES {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = nix::unistd::geteuid().as_raw();
        if metadata.mode() & 0o077 != 0 || metadata.uid() != owner {
            return None;
        }
    }
    let mut bytes = Vec::new();
    file.take(size).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 == size).then_some(bytes)
}

#[cfg(test)]
#[path = "cursor_observer_proof_vectors_tests.rs"]
mod vectors;
