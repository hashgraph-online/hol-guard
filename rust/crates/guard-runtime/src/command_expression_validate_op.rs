//! `CommandExpressionValidate` - compile every command expression a policy
//! document carries, once, with the engine that will later match them.
//!
//! Python validated these patterns with its own regex module while the runtime
//! matched them with another, so a document could be accepted when it was
//! written and refused when a command ran against it. The dialect lives in
//! `guard-command` now and this op is the only validator.
//!
//! Pure: the caller ships the expressions it parsed, and the op never opens the
//! store, the keyring or a policy file.

use guard_command::command_expression_match::validate_expression;
use guard_contracts::{
    CommandExpressionValidationRequestV1, CommandExpressionValidationResultV1,
    COMMAND_EXPRESSION_VALIDATION_MAX_EXPRESSIONS, COMMAND_EXPRESSION_VALIDATION_REQUEST_SCHEMA,
    COMMAND_EXPRESSION_VALIDATION_RESULT_SCHEMA, COMMAND_POLICY_DECISION_MAX_BYTES,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;

#[cfg(test)]
#[path = "command_expression_validate_op_tests.rs"]
mod tests;

pub(crate) fn evaluate_command_expression_validation_request(
    request: &CommandExpressionValidationRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, COMMAND_POLICY_DECISION_MAX_BYTES)
        .map_err(|_| "native_command_expression_validation_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&CommandExpressionValidationResultV1 {
        schema: COMMAND_EXPRESSION_VALIDATION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

/// `evaluate` - the first expression the dialect refuses, or nothing.
///
/// A pattern an author can fix is the answer, not a failure: it rides an `ok`
/// reply so the caller can name the rule that carried it. Only a request built
/// against another contract, or one past the rule limit, is an error.
pub(crate) fn evaluate(request: &CommandExpressionValidationRequestV1) -> Result<Value, String> {
    if request.schema != COMMAND_EXPRESSION_VALIDATION_REQUEST_SCHEMA {
        return Err("native_command_expression_validation_schema_mismatch".to_owned());
    }
    if request.expressions.len() > COMMAND_EXPRESSION_VALIDATION_MAX_EXPRESSIONS {
        return Err("native_command_expression_validation_too_large".to_owned());
    }
    for (index, expression) in request.expressions.iter().enumerate() {
        if let Err(code) = validate_expression(expression) {
            return Ok(json!({"invalid": {"index": index, "code": code}}));
        }
    }
    Ok(json!({"invalid": Value::Null}))
}
