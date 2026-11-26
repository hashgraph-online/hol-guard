//! Pure document semantics use the same owner and deadline admission as hooks.

use guard_contracts::RequestContextPolicyDocumentV1;
use std::time::Instant;

use serde_json::{json, Value};

use crate::request_context_op::Budget;

#[path = "policy_bundle_candidate.rs"]
mod candidate;
#[cfg(test)]
#[path = "policy_document_op_tests.rs"]
mod tests;
#[path = "policy_document_wire.rs"]
mod wire;

/// One policy-document query. `bundle_candidate` reads the store's policy
/// bundle authority as well as the document compiler, so the runtime answers
/// it; every other query belongs to the compiler.
fn query(name: &str, input: &Value, deadline: Instant) -> Result<Value, &'static str> {
    if name == candidate::QUERY {
        let answer = candidate::query(input, deadline);
        return if Instant::now() >= deadline {
            Err("policy_document_deadline")
        } else {
            Ok(answer)
        };
    }
    guard_command::policy_document::evaluate(name, input, deadline)
}

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
    let result = query(&body.query, &body.input, budget.deadline())
        .map_err(|_| "native_request_context_policy_document_unavailable")?;
    budget.check()?;
    let result = wire::result_wire(result, guard_home, budget)?;
    Ok(json!({"kind":"policy_document","query":body.query,"result":result}))
}
