//! Pure document semantics use the same owner and deadline admission as hooks.

use guard_contracts::RequestContextPolicyDocumentV1;
use serde_json::{json, Value};

use crate::request_context_op::Budget;

#[cfg(test)]
#[path = "policy_document_op_tests.rs"]
mod tests;
#[path = "policy_document_wire.rs"]
mod wire;

pub(crate) fn evaluate(
    body: &RequestContextPolicyDocumentV1,
    budget: &Budget,
    guard_home: &str,
) -> Result<Value, &'static str> {
    budget.check()?;
    if body.query.starts_with("wire_") {
        let result = wire::operation(&body.query, &body.input, guard_home, budget)?;
        return Ok(json!({"kind":"policy_document","query":body.query,"result":result}));
    }
    if body.query.len() > 32
        || serde_json::to_vec(&body.input)
            .map_err(|_| "native_request_context_policy_document_invalid")?
            .len()
            > 5 * 1024 * 1024
    {
        return Err("native_request_context_policy_document_invalid");
    }
    let result =
        guard_command::policy_document::evaluate(&body.query, &body.input, budget.deadline())
            .map_err(|_| "native_request_context_policy_document_unavailable")?;
    budget.check()?;
    let result = wire::result_wire(result, guard_home, budget)?;
    Ok(json!({"kind":"policy_document","query":body.query,"result":result}))
}
