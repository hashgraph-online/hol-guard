//! One matcher stage of a contained command's output chain, for the Python
//! sink.
//!
//! Native authority chose the chain before the core ran; the Python sink cuts
//! `head` and `tail` stages itself and hands each `grep`, `egrep`, `fgrep` or
//! `rg` stage here. The matcher runs exactly as Guard's own sink runs it: the
//! installed binary located by ownership, an environment built here, and the
//! captured text alone on its standard input. A host with no matcher, and
//! every host without the Unix sink, answers as a shell's missing program.
//!
//! The arguments are checked against the same stdin-only grammar native
//! authority applied to the chain, so a request can never make the matcher
//! read a file, a pattern file or recurse.

use std::io::Read;

use base64ct::{Base64, Encoding};
use serde::Deserialize;
use serde_json::{json, Value};

const SCHEMA: &str = "contained-output-match.v1";
const MAX_REQUEST_BYTES: u64 = 192 * 1024 * 1024;
const MATCHERS: [&str; 4] = ["grep", "egrep", "fgrep", "rg"];
const FILTER_FAILED: &str = "contained_output_filter_failed";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    program: String,
    arguments: Vec<String>,
    input: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "contained-output-match"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "contained_output_match_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("contained_output_match_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if request.schema != SCHEMA
        || !MATCHERS.contains(&request.program.as_str())
        || !guard_command::pretool::contained_matcher_stage(&request.program, &request.arguments)
    {
        return Err(invalid());
    }
    let input = Base64::decode_vec(&request.input).map_err(|_| invalid())?;
    serde_json::to_vec(&answer(&input, &request.program, &request.arguments))
        .map_err(|_| "contained_output_match_response_unencodable".to_owned())
}

fn answer(input: &[u8], program: &str, arguments: &[String]) -> Value {
    match matched(input, program, arguments) {
        Some((stdout, stderr, status)) => json!({
            "stdout": Base64::encode_string(&stdout),
            "stderr": String::from_utf8_lossy(&stderr),
            "status": status,
        }),
        None => json!({ "error": FILTER_FAILED }),
    }
}

#[cfg(unix)]
fn matched(input: &[u8], program: &str, arguments: &[String]) -> Option<(Vec<u8>, Vec<u8>, i32)> {
    crate::contained_workspace_sink::matched(input, program, arguments).ok()
}

#[cfg(not(unix))]
fn matched(_input: &[u8], program: &str, _arguments: &[String]) -> Option<(Vec<u8>, Vec<u8>, i32)> {
    let missing = format!("hol-guard: {program}: not found\n");
    Some((Vec::new(), missing.into_bytes(), 127))
}

fn invalid() -> String {
    "contained_output_match_request_invalid".to_owned()
}

#[cfg(test)]
#[path = "contained_output_match_tests.rs"]
mod tests;
