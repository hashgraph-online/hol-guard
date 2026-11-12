//! `ExtensionControlTerminal` - resident op that decides whether the session
//! asking to enroll extension-control authority is really at the local
//! keyboard.
//!
//! Pure: the caller ships the probe output it collected and acts only on the
//! verdict returned here. A request that names neither platform, or both, is
//! refused rather than guessed at.

use guard_command::extension_control_terminal::extension_control_terminal_verdict;
use guard_contracts::{
    ExtensionControlTerminalRequestV1, ExtensionControlTerminalResultV1,
    EXTENSION_CONTROL_TERMINAL_MAX_BYTES, EXTENSION_CONTROL_TERMINAL_REQUEST_SCHEMA,
    EXTENSION_CONTROL_TERMINAL_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;

const INVALID: &str = "native_extension_control_terminal_invalid";
const TOO_LARGE: &str = "native_extension_control_terminal_too_large";

pub(crate) fn evaluate_extension_control_terminal_request(
    request: &ExtensionControlTerminalRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, EXTENSION_CONTROL_TERMINAL_MAX_BYTES)
        .map_err(|_| TOO_LARGE.to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&ExtensionControlTerminalResultV1 {
        schema: EXTENSION_CONTROL_TERMINAL_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

fn evaluate(request: &ExtensionControlTerminalRequestV1) -> Result<Value, String> {
    if request.schema != EXTENSION_CONTROL_TERMINAL_REQUEST_SCHEMA || request.request_id.is_empty()
    {
        return Err(INVALID.to_owned());
    }
    let verdict = extension_control_terminal_verdict(
        &request.remote_environment,
        request.posix.as_ref(),
        request.windows.as_ref(),
    )
    .map_err(|_| INVALID.to_owned())?;
    Ok(json!({ "verdict": verdict.as_str() }))
}

#[cfg(test)]
#[path = "extension_control_terminal_op_tests.rs"]
mod tests;
