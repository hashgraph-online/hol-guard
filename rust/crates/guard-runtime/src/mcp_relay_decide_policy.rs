//! The tool policy pass of one relay decision, with its saved lookups read
//! from the store as the proxy reads them.

use super::store;
use super::POLICY_NEED;
use crate::mcp_tool_policy_decision::Decision;
use crate::mcp_tool_policy_flow::{evaluate_pass, Ctx, Pass, PassMemo, Phase, Stop};
use guard_contracts::McpToolPolicyObservationV1;
use serde_json::{json, Value};

/// Saved lookups one decision may name before it is left to the proxy.
const MAX_POLICY_ROUNDS: usize = 8;
const POLICY_FAILED: &str = "mcp_relay_policy_failed";

/// Run the tool policy, answering each saved lookup it names from the store:
/// the saved rows when there are any, the empty store's answer otherwise.
/// Each round replays the pass over the same subject, so the parts no
/// observation steers are evaluated once for the call.
pub(super) fn run_policy(
    subject: &guard_contracts::McpToolPolicySubjectV1,
    saved: Option<&store::Saved<'_>>,
) -> Result<Decision, &'static str> {
    let mut observations: Vec<McpToolPolicyObservationV1> = Vec::new();
    let memo = PassMemo::new(subject);
    for _ in 0..MAX_POLICY_ROUNDS {
        let ctx = Ctx {
            observations: &observations,
            lookup: None,
            memo: Some(&memo),
        };
        match evaluate_pass(&ctx, subject, Phase::Initial, false) {
            Ok(Pass::Final(decision)) => return Ok(*decision),
            Ok(Pass::Claimed { .. }) | Err(Stop::Fail(_)) => return Err(POLICY_FAILED),
            Err(Stop::Need(need)) => {
                let result = match saved {
                    Some(saved) => saved.answer(&need)?,
                    None => empty_store_answer(&need)?,
                };
                observations.push(McpToolPolicyObservationV1 { need, result });
            }
        }
    }
    Err(POLICY_NEED)
}

/// What the proxy observes for a saved lookup against a store with no saved
/// policy rows and no one-shot approvals. Any other effect defers.
pub(super) fn empty_store_answer(need: &Value) -> Result<Value, &'static str> {
    match need.get("kind").and_then(Value::as_str) {
        Some("grant_lookup") => Ok(json!({"decision": null})),
        Some("policy_lookup") => Ok(json!({
            "decision": null,
            "ignored_local_integrity": false,
            "reuse_diagnostic": {"reason": null},
        })),
        _ => Err(POLICY_NEED),
    }
}
