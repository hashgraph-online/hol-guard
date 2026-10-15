//! The relay's answer to a call under `mode = "observe"`.
//!
//! Observe is the non-blocking posture: the proxy forwards what it would
//! have stopped for approval and records what it would have done. It routes
//! an observed call as the resident's `route_tool_call` answers it:
//!
//! - a pending saved approval is not claimed. `_apply_decision_override`
//!   presents the current policy instead (source `observe-current-policy`,
//!   no pending approval), and the route and every receipt follow that
//!   downgraded decision;
//! - a stored block and a terminal action (`block`, `sandbox-required`) still
//!   block, and an allow or warn forwards, exactly as outside observe mode;
//! - any other action takes `observe_forward`. `_observe_tool_forward`
//!   re-resolves the call, asks the resident's `observe_tool_forward` for the
//!   executed action, and forwards under the `policy-observe` decision source
//!   with that action. When the observed action would not have executed, the
//!   executed action is `allow` and the `observe_mode` item (observed and
//!   authoritative action) follows the decision's own evidence in the allow
//!   receipt. It queues no inbox row. Under `blocked_request_mode = "ask"`
//!   the proxy first consults the native prompt and inline elicitation,
//!   which the resident cannot answer, so the call defers there and the
//!   session runs under the proxy (`mcp_relay_decide_session.rs`).
//!
//! The resident answers each of these. The observe-forward evidence is a
//! forward's (`mcp_relay_decide.rs`), held until the relay completes the
//! forward, and the drain writes the allow receipt `_allow_and_forward`
//! writes. The proxy's per-call event (`observe_mode`,
//! `observed_policy_action`) is never persisted by `serve`, so the relay
//! leaves none either.
//!
//! The proxy re-resolves the call after draining the child stream; the
//! resident decides once, on the state the decision's read snapshot held, as
//! for every other forward. A catalog boundary change before the write leaves
//! the relay's "no native decision" answer, as for every forward.

use super::{Routed, ROUTE_UNSUPPORTED};
use crate::mcp_tool_policy_decision::Decision;
use guard_contracts::McpObserveToolForwardQueryV1;
use serde_json::{json, Value};

/// The decision source `_observe_tool_forward` records.
const OBSERVE_SOURCE: &str = "policy-observe";
/// The source of the resident's observe-mode downgrade.
const DOWNGRADE_SOURCE: &str = "observe-current-policy";
const OBSERVE_MODE: &str = "observe";
/// `blocked_request_mode`, under which the proxy observes without a prompt.
const SAFE_ALTERNATIVE_MODE: &str = "safe-alternative";

/// The proxy payload with its observe-mode downgrade taken out, and the
/// downgraded decision when there is one (`_apply_decision_override`). An
/// override other than the exact observe downgrade of `decision` defers.
pub(super) fn downgrade(
    mut proxy: Value,
    mode: &str,
    decision: &Decision,
) -> Result<(Value, Option<Decision>), &'static str> {
    let taken = proxy
        .get_mut("route")
        .and_then(|route| route.get_mut("decision_override"))
        .map(Value::take)
        .unwrap_or(Value::Null);
    if taken.is_null() {
        return Ok((proxy, None));
    }
    let current = decision.current_action.ok_or(ROUTE_UNSUPPORTED)?;
    let expected = json!({"action": current.as_str(), "source": DOWNGRADE_SOURCE});
    if mode != OBSERVE_MODE || decision.pending.is_none() || taken != expected {
        return Err(ROUTE_UNSUPPORTED);
    }
    let mut downgraded = decision.clone();
    downgraded.action = current;
    downgraded.source = DOWNGRADE_SOURCE.to_owned();
    downgraded.pending = None;
    downgraded.claim_disposition = None;
    Ok((proxy, Some(downgraded)))
}

/// `_observe_tool_forward` of the call's decision: the forward it records
/// and the evidence the resident appends to the decision's own. Only under
/// `safe-alternative`: under `ask` the proxy first prompts for the call.
pub(super) fn forward(
    blocked_request_mode: Option<&str>,
    decision: &Decision,
) -> Result<(Routed, Option<Vec<Value>>), &'static str> {
    if blocked_request_mode != Some(SAFE_ALTERNATIVE_MODE) {
        return Err(ROUTE_UNSUPPORTED);
    }
    let observed = crate::mcp_proxy_route::observe_tool_forward(&McpObserveToolForwardQueryV1 {
        fresh: crate::mcp_tool_policy_proxy::facts(decision),
    });
    let policy_action = observed
        .get("executed_action")
        .and_then(Value::as_str)
        .ok_or(ROUTE_UNSUPPORTED)?
        .to_owned();
    let append = match observed.get("evidence_append") {
        Some(Value::Array(items)) => items.clone(),
        _ => return Err(ROUTE_UNSUPPORTED),
    };
    let routed = Routed::Forward {
        source: OBSERVE_SOURCE.to_owned(),
        policy_action,
    };
    Ok((routed, (!append.is_empty()).then_some(append)))
}

#[cfg(test)]
#[path = "mcp_relay_decide_observe_tests.rs"]
mod tests;
