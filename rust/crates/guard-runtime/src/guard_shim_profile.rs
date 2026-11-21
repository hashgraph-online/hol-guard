//! `guard-shim-profile --stdin`: the shell profile that puts the harness
//! launcher directory first on PATH (`prepare_guard_shim_shell_profile` in
//! `guard/shims.py` rendered it before the block moved here).
//!
//! The caller picks, reads and writes the profile; this only renders the
//! content with exactly one Guard-managed block.

use std::io::Read;

use guard_command::shims::guard_shim_profile_content;
use serde::Deserialize;
use serde_json::json;

const COMMAND: &str = "guard-shim-profile";
const SCHEMA: &str = "guard-shim-profile.v1";
const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    /// The profile's current text, empty when it does not exist yet.
    existing: String,
    shim_dir: String,
    /// Whether the profile is fish's `config.fish` rather than a POSIX one.
    fish: bool,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "guard_shim_profile_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("guard_shim_profile_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "guard_shim_profile_request_invalid".to_owned())?;
    if request.schema != SCHEMA || request.shim_dir.is_empty() {
        return Err("guard_shim_profile_request_invalid".to_owned());
    }
    let content = guard_shim_profile_content(&request.existing, &request.shim_dir, request.fish);
    serde_json::to_vec(&json!({ "content": content }))
        .map_err(|_| "guard_shim_profile_response_unencodable".to_owned())
}

#[cfg(test)]
#[path = "guard_shim_profile_tests.rs"]
mod tests;
