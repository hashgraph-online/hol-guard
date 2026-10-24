//! `PackageIntentExtract` — reads a whole tool call for package intent.
//!
//! Python used to walk the tool arguments for command texts itself and send
//! each one back as its own `package_intent_parse` request, so a shell call
//! with several candidate commands cost a resident round trip per command.
//! The resident now runs `extract_package_intent_request`, the same walk and
//! parse the MCP relay decision already uses, in one request.

use std::path::Path;

use guard_command::package_intent_parser::extract_package_intent_request;
use guard_contracts::{
    PackageIntentExtractRequestV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA,
    PACKAGE_INTENT_EXTRACT_MAX_BYTES,
};

use crate::package_authority_op::{
    err_result, package_intent_parse_result, request_digest_with_limit, string_environment,
};

/// The first package intent the call's commands name, answered in the
/// `package_intent_parse` result shape.
pub(crate) fn evaluate_package_intent_extract(
    request: &PackageIntentExtractRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, PACKAGE_INTENT_EXTRACT_MAX_BYTES)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return serde_json::to_vec(&err_result(
            &request.request_id,
            &request_sha256,
            "schema_mismatch",
        ))
        .map_err(|e| e.to_string());
    }
    let environment = string_environment(request.environment.as_ref());
    let intent = extract_package_intent_request(
        request.tool_name.as_str().unwrap_or_default(),
        &request.arguments,
        request
            .action_envelope_command
            .as_deref()
            .filter(|command| !command.is_empty()),
        request.workspace.as_deref().map(Path::new),
        request.home_dir.as_deref().map(Path::new),
        environment.as_ref(),
    );
    package_intent_parse_result(&request.request_id, request_sha256, intent)
}

#[cfg(test)]
#[path = "package_intent_extract_op_tests.rs"]
mod tests;
