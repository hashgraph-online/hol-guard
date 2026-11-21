//! `VerifiedReadExecute` resident op: one Guard-owned bounded workspace read.
//!
//! Plans the read from the argv, performs it in the caller's working
//! directory, and answers with the text it may show, the proof's binding
//! digest and the silent-verified decision. The reply is bound to the request
//! with `request_id` plus the canonical request digest. Every failure comes
//! back as an `error` status, because the executor treats each the same way:
//! the verified read ends and the command goes back to ordinary review.

#[cfg(unix)]
use std::panic::{catch_unwind, AssertUnwindSafe};

use guard_contracts::{
    VerifiedReadExecutePayloadV1, VerifiedReadExecuteQueryV1, VerifiedReadExecuteRequestV1,
    VerifiedReadExecuteResultV1, VERIFIED_READ_EXECUTE_MAX_BYTES,
    VERIFIED_READ_EXECUTE_REQUEST_SCHEMA, VERIFIED_READ_EXECUTE_RESULT_SCHEMA,
};

fn execute(
    request: &VerifiedReadExecuteRequestV1,
) -> Result<VerifiedReadExecutePayloadV1, &'static str> {
    if request.schema != VERIFIED_READ_EXECUTE_REQUEST_SCHEMA {
        return Err("native_verified_read_execute_schema_mismatch");
    }
    let VerifiedReadExecuteQueryV1::Local {
        argv,
        cwd,
        home_dir,
    } = &request.query;
    perform(argv, cwd, home_dir.as_deref())
}

#[cfg(unix)]
fn perform(
    argv: &[String],
    cwd: &str,
    home_dir: Option<&str>,
) -> Result<VerifiedReadExecutePayloadV1, &'static str> {
    use crate::verified_read_execute::Failure;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        crate::verified_read_execute::execute(argv, cwd, home_dir)
    }))
    .map_err(|_| "native_verified_read_execute_failed")?
    .map_err(|failure| match failure {
        Failure::Refused => "native_verified_read_execute_refused",
        Failure::Unavailable => "native_verified_read_execute_unavailable",
    })?;
    Ok(VerifiedReadExecutePayloadV1::Local {
        operation_id: outcome.operation_id,
        stdout: outcome.stdout,
        binding_digest: outcome.binding_digest,
        decision: outcome.decision,
    })
}

/// The executor opens each component beneath the repository by descriptor;
/// this platform has no such open, so the read fails closed.
#[cfg(not(unix))]
fn perform(
    _argv: &[String],
    _cwd: &str,
    _home_dir: Option<&str>,
) -> Result<VerifiedReadExecutePayloadV1, &'static str> {
    Err("native_verified_read_execute_unsupported")
}

fn result(
    request: &VerifiedReadExecuteRequestV1,
    request_sha256: &str,
    outcome: Result<VerifiedReadExecutePayloadV1, &'static str>,
) -> VerifiedReadExecuteResultV1 {
    let (status, code, payload) = match outcome {
        Ok(payload) => ("ok", "ok", Some(payload)),
        Err(code) => ("error", code, None),
    };
    VerifiedReadExecuteResultV1 {
        schema: VERIFIED_READ_EXECUTE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256: request_sha256.to_owned(),
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    }
}

pub(crate) fn evaluate_verified_read_execute(
    request: &VerifiedReadExecuteRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = crate::package_authority_op::request_digest_with_limit(
        request,
        VERIFIED_READ_EXECUTE_MAX_BYTES,
    )
    .map_err(|_| "native_verified_read_execute_request_too_large".to_owned())?;
    let reply = result(request, &request_sha256, execute(request));
    match crate::encode_response(&reply) {
        // Escaped control characters can carry a bounded read past the
        // response frame; that read is refused rather than truncated.
        Err(code) if code == "native_response_too_large" => crate::encode_response(&result(
            request,
            &request_sha256,
            Err("native_verified_read_execute_output_too_large"),
        )),
        encoded => encoded,
    }
}

#[cfg(test)]
#[path = "verified_read_execute_op_tests.rs"]
mod tests;
