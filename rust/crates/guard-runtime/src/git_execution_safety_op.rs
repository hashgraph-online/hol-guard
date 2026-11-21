//! `GitExecutionSafety` resident op (RTM-032).
//!
//! Rust owns the verdict for whether a Git invocation can execute configured
//! helpers, hooks or transports; the Python transport only reports observed
//! facts and relays `allowed`. Any malformed request is an error result with
//! `allowed = false`.

use guard_contracts::{
    GitExecutionSafetyRequestV1, GitExecutionSafetyResultV1, GIT_EXECUTION_SAFETY_MAX_BYTES,
    GIT_EXECUTION_SAFETY_REQUEST_SCHEMA, GIT_EXECUTION_SAFETY_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;

use super::context_digest_json::write_canonical_json_with_limit;

fn request_digest(request: &GitExecutionSafetyRequestV1) -> Result<String, &'static str> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_git_execution_safety_invalid")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, GIT_EXECUTION_SAFETY_MAX_BYTES)
        .map_err(|_| "native_git_execution_safety_invalid")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

fn request_is_bounded(request: &GitExecutionSafetyRequestV1) -> bool {
    request.request_id.len() <= 128
        && request.environment.len() <= 128
        && request.arguments.len() <= 64
        && std::iter::once(&request.cwd)
            .chain(std::iter::once(&request.home))
            .chain(request.account_home.iter())
            .chain(request.git_binary.iter())
            .chain(request.git_path.iter())
            .chain(request.branch.iter())
            .chain(request.reference.iter())
            .chain(request.arguments.iter())
            .chain(request.environment.keys())
            .chain(request.environment.values())
            .all(|value| value.len() <= 8192 && !value.contains('\0'))
}

pub(crate) fn evaluate_git_execution_safety_request(
    request: &GitExecutionSafetyRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, allowed, resolved_path) =
        if request.schema != GIT_EXECUTION_SAFETY_REQUEST_SCHEMA {
            (
                "error",
                "native_git_execution_safety_schema_mismatch",
                false,
                None,
            )
        } else if !request_is_bounded(request) {
            ("error", "native_git_execution_safety_invalid", false, None)
        } else {
            let verdict = crate::git_execution_safety_checks::decide(request);
            ("ok", "ok", verdict.allowed, verdict.resolved_path)
        };
    crate::encode_response(&GitExecutionSafetyResultV1 {
        schema: GIT_EXECUTION_SAFETY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        allowed,
        resolved_path,
    })
}
