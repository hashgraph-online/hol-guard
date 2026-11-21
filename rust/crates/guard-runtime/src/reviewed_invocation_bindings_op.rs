//! `ReviewedInvocationBindingsValidate` - bind every reviewed literal vector
//! an extension carries to the operation that owns it, with the grammar that
//! will enforce the extension once it is installed.
//!
//! Python built matchers of its own for this, so an author could pass review
//! with a vector the runtime later assigns elsewhere. The matching lives in
//! `guard-command` now and this op is the only binder.
//!
//! Pure: the caller ships the discovery it parsed, and the op never opens the
//! store, the keyring or an extension file.

use std::time::{Duration, Instant};

use guard_command::reviewed_invocation_bindings::{
    validate_reviewed_invocations, ReviewedInvocation, ReviewedOperation,
};
use guard_contracts::{
    ReviewedInvocationBindingsRequestV1, ReviewedInvocationBindingsResultV1,
    REVIEWED_INVOCATION_BINDINGS_DEADLINE_MILLIS, REVIEWED_INVOCATION_BINDINGS_MAX_BYTES,
    REVIEWED_INVOCATION_BINDINGS_MAX_OPERATIONS, REVIEWED_INVOCATION_BINDINGS_MAX_ROWS,
    REVIEWED_INVOCATION_BINDINGS_REQUEST_SCHEMA, REVIEWED_INVOCATION_BINDINGS_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;

#[cfg(test)]
#[path = "reviewed_invocation_bindings_op_tests.rs"]
mod tests;

pub(crate) fn evaluate_reviewed_invocation_bindings_request(
    request: &ReviewedInvocationBindingsRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, REVIEWED_INVOCATION_BINDINGS_MAX_BYTES)
        .map_err(|_| "native_reviewed_invocation_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&ReviewedInvocationBindingsResultV1 {
        schema: REVIEWED_INVOCATION_BINDINGS_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

/// `evaluate` - the first reviewed row the grammar refuses, or nothing.
///
/// A refusal names the row and the builder's own code for it, and rides an
/// `ok` reply so the caller can report which safe variant the author has to
/// change. Only a request built against another contract, one past a limit, or
/// a discovery the grammar cannot read is an error.
pub(crate) fn evaluate(request: &ReviewedInvocationBindingsRequestV1) -> Result<Value, String> {
    if request.schema != REVIEWED_INVOCATION_BINDINGS_REQUEST_SCHEMA {
        return Err("native_reviewed_invocation_schema_mismatch".to_owned());
    }
    if request.operations.len() > REVIEWED_INVOCATION_BINDINGS_MAX_OPERATIONS
        || request.rows.len() > REVIEWED_INVOCATION_BINDINGS_MAX_ROWS
    {
        return Err("native_reviewed_invocation_too_large".to_owned());
    }
    let operations: Vec<ReviewedOperation> = request
        .operations
        .iter()
        .map(|operation| ReviewedOperation {
            operation_id: operation.operation_id.clone(),
            path: operation.path.clone(),
            flags: operation.flags.iter().cloned().collect(),
            options_with_values: operation.options_with_values.iter().cloned().collect(),
        })
        .collect();
    let rows: Vec<ReviewedInvocation> = request
        .rows
        .iter()
        .map(|row| ReviewedInvocation {
            operation_id: row.operation_id.clone(),
            argv: row.argv.clone(),
        })
        .collect();
    let blocked = request.blocked_operation_ids.iter().cloned().collect();
    let deadline =
        Instant::now() + Duration::from_millis(REVIEWED_INVOCATION_BINDINGS_DEADLINE_MILLIS);
    match validate_reviewed_invocations(
        &request.executable,
        &operations,
        &rows,
        &blocked,
        Some(deadline),
    ) {
        Ok(None) => Ok(json!({"refused": Value::Null})),
        Ok(Some(refusal)) => Ok(json!({
            "refused": {"index": refusal.index, "code": refusal.code}
        })),
        Err(code) => Err(code.to_owned()),
    }
}
