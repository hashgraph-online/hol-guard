//! Decide one native MCP relay `tools/call` in a single resident round trip.
//!
//! The Python proxy builds the tool-call identity, evaluates the tool policy,
//! applies the saved-allow gate, routes the call and records the outcome. This
//! operation repeats that path for the calls whose answer needs nothing the
//! resident cannot read itself: a workspace the current snapshot settled while
//! the publisher's ACK holds, a harness the binding's MCP view covers, and a
//! store without saved policy rows or one-shot approvals, so every saved
//! lookup the policy names has no decision. Such a call is either forwarded
//! (an allow or warn) or blocked (a terminal or stored block). A block's
//! evidence is queued for the daemon's drain before the answer is returned.
//! The proxy records a forward only after the child answered it, so a
//! forward's evidence is held under a ticket the relay commits once the child
//! responded; a forward the relay never completes (a catalog boundary change,
//! a lost answer) leaves no allow receipt.
//!
//! Every other call defers, and the relay answers it with the proxy's
//! fail-closed "no native decision" response: a saved policy row, a pending
//! approval, a call that needs a prompt, a queue or an observe override, and
//! any binding, lane or evidence failure.

use crate::mcp_tool_policy_decision::Decision;
use crate::mcp_tool_policy_flow::{evaluate_pass, Ctx, Pass, Phase, Stop};
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::{
    McpToolArgumentsV1, McpToolCallBuildV1, McpToolCallHashInputV1, McpToolCallIdentityPayloadV1,
    McpToolPolicyObservationV1, McpToolPolicyProxyInputV1,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::Path;
use std::time::Instant;

pub(crate) const MCP_RELAY_DECIDE_FEATURE: &str = "mcp-relay-decide-v1";
const RESULT_SCHEMA: &str = "guard-mcp-relay-decide-result.v1";
/// The harnesses whose MCP proxy the relay replaces.
const RELAY_HARNESSES: [&str; 4] = ["codex", "copilot", "cursor", "opencode"];
/// Saved lookups one decision may name before it is left to the proxy.
const MAX_POLICY_ROUNDS: usize = 8;

const HARNESS_UNSUPPORTED: &str = "mcp_relay_harness_unsupported";
const RUNTIME_SUPERSEDED: &str = "mcp_relay_runtime_superseded";
const WORKSPACE_INVALID: &str = "mcp_relay_workspace_invalid";
const EVIDENCE_UNDRAINED: &str = "mcp_relay_evidence_undrained";
const BINDING_INCOMPLETE: &str = "mcp_relay_binding_incomplete";
const IDENTITY_FAILED: &str = "mcp_relay_identity_failed";
const POLICY_NEED: &str = "mcp_relay_policy_need";
const POLICY_FAILED: &str = "mcp_relay_policy_failed";
const ROUTE_UNSUPPORTED: &str = "mcp_relay_route_unsupported";
const EVIDENCE_FULL: &str = "mcp_relay_evidence_full";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpRelayDecideRequestV1 {
    pub(crate) guard_home: String,
    /// The proxy's `--workspace`, normalized, which its config carries.
    #[serde(default)]
    pub(crate) workspace: Option<String>,
    /// `Path(workspace or cwd).resolve()`, which the approval hash binds.
    pub(crate) hash_workspace: String,
    pub(crate) build: McpToolCallBuildV1,
    /// The call arguments in the order the host sent them.
    pub(crate) arguments: McpToolArgumentsV1,
    #[serde(default)]
    pub(crate) launcher_path: Option<String>,
    pub(crate) launcher_home: String,
    pub(crate) catalog_state: String,
    /// The `tools/call` params, which the daemon projects into evidence.
    pub(crate) params: Value,
}

/// What the relay does with the call.
#[derive(Debug, Clone, PartialEq)]
enum Answer {
    Forward { ticket: String },
    Block { message: String, data: Value },
}

/// The route the proxy takes for a decided call.
#[derive(Debug, Clone, PartialEq)]
enum Routed {
    Forward {
        source: String,
        policy_action: String,
    },
    Terminal {
        policy_action: String,
    },
    StoredBlock,
}

pub(crate) fn evaluate(
    request: McpRelayDecideRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let body = match decide(&request, policy_store) {
        Ok(Answer::Forward { ticket }) => {
            json!({"schema": RESULT_SCHEMA, "outcome": "forward", "ticket": ticket})
        }
        Ok(Answer::Block { message, data }) => json!({
            "schema": RESULT_SCHEMA,
            "outcome": "block",
            "message": message,
            "data": data,
        }),
        Err(reason) => json!({"schema": RESULT_SCHEMA, "outcome": "defer", "reason": reason}),
    };
    serde_json::to_vec(&body).map_err(|_| "mcp_relay_decide_result_encoding_failed".to_owned())
}

fn decide(
    request: &McpRelayDecideRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Answer, &'static str> {
    let harness = request.build.harness.as_str();
    if !RELAY_HARNESSES.contains(&harness) {
        return Err(HARNESS_UNSUPPORTED);
    }
    if !crate::hook_direct::runtime_current() {
        return Err(RUNTIME_SUPERSEDED);
    }
    let candidate = request
        .workspace
        .as_deref()
        .unwrap_or(&request.hash_workspace);
    let workspace = settled_directory(candidate)?;
    let (_snapshot, binding) = policy_store
        .admit_direct_hook(&workspace)
        .map_err(|defer| defer.code())?;
    if binding.evidence_drain != Some(true) {
        return Err(EVIDENCE_UNDRAINED);
    }
    let control_digest = binding
        .exact_action_control_digest
        .clone()
        .ok_or(BINDING_INCOMPLETE)?;
    let view = view::harness_view(binding.mcp_relay.as_ref(), harness)?;
    store::require_no_saved_policy(Path::new(&request.guard_home))?;

    let identity = identity(request, &view, control_digest)?;
    let subject = subject::subject(request, &identity, &view)?;
    let decision = run_policy(&subject)?;
    let proxy = crate::mcp_tool_policy_proxy::proxy_payload(
        &McpToolPolicyProxyInputV1 {
            catalog_state: request.catalog_state.clone(),
            mode: view.mode.clone(),
            package_present: false,
            // Both only steer a call that is neither allowed nor blocked,
            // which defers below whatever they are.
            asks_for_approval: false,
            inline_available: false,
            tool_name: request.build.tool_name.clone(),
        },
        &decision,
    );
    let routed = route(&proxy, &decision)?;
    let tool = &request.build.tool_name;
    let server = &request.build.server_name;
    let (blocked, outcome, source, policy_action) = match routed {
        Routed::Forward {
            source,
            policy_action,
        } => (None, "forward", source, policy_action),
        Routed::Terminal { policy_action } => {
            let message = if policy_action == "block" {
                format!("HOL Guard blocked tool call {tool} from {server}.")
            } else {
                format!(
                    "HOL Guard requires an enforceable sandbox for tool call {tool} from \
                     {server}; this runtime cannot provide one."
                )
            };
            let data = json!({"approvalRequests": [], "guardPolicyAction": policy_action});
            (
                Some(Answer::Block { message, data }),
                "block",
                "policy-block".to_owned(),
                policy_action,
            )
        }
        Routed::StoredBlock => (
            Some(Answer::Block {
                message: format!(
                    "HOL Guard blocked tool call {tool} from {server}. This exact request is \
                     already blocked by authenticated saved policy."
                ),
                data: json!({"approvalRequests": [], "guardPolicyAction": "block"}),
            }),
            "block",
            "policy-block".to_owned(),
            "block".to_owned(),
        ),
    };
    let evidence = json!({
        "kind": "mcp_tool_call",
        "harness": harness,
        "outcome": outcome,
        "decision_source": source,
        "policy_action": policy_action,
        "tool_name": tool,
        "params": request.params,
        // The arguments in host key order, which the decoded params lost.
        "arguments": serde_json::to_value(&request.arguments).map_err(|_| IDENTITY_FAILED)?,
        "identity": serde_json::to_value(&identity).map_err(|_| IDENTITY_FAILED)?,
        "decision": decision.to_value(),
    });
    match blocked {
        // The relay commits the ticket once the child answered the forward.
        None => policy_store
            .mcp_relay_pending()
            .hold(evidence, Instant::now())
            .map(|ticket| Answer::Forward { ticket })
            .ok_or(EVIDENCE_FULL),
        Some(block) if policy_store.direct_evidence().offer(evidence) => Ok(block),
        Some(_) => Err(EVIDENCE_FULL),
    }
}

/// `Path.resolve(strict=True)` of a directory, as the lane settles it.
fn settled_directory(candidate: &str) -> Result<String, &'static str> {
    let resolved = std::fs::canonicalize(Path::new(candidate)).map_err(|_| WORKSPACE_INVALID)?;
    if !resolved.is_dir() {
        return Err(WORKSPACE_INVALID);
    }
    resolved
        .into_os_string()
        .into_string()
        .map_err(|_| WORKSPACE_INVALID)
}

/// The artifact and approval-context token `build_tool_call_identity` makes.
fn identity(
    request: &McpRelayDecideRequestV1,
    view: &view::HarnessView,
    control_digest: String,
) -> Result<McpToolCallIdentityPayloadV1, &'static str> {
    let (artifact, private) = crate::mcp_tool_call_identity_build::build_artifact(&request.build)
        .map_err(|_| IDENTITY_FAILED)?;
    let input = McpToolCallHashInputV1 {
        arguments: guard_command::mcp_tool_signals::risk_arguments(&request.arguments),
        config: Some(view.hash_config.clone()),
        workspace: Some(request.hash_workspace.clone()),
        extension_control_digest: Some(control_digest),
    };
    let hashed = crate::context_digest::build_mcp_tool_approval(
        &crate::mcp_tool_call_identity_op::hash_request(&artifact, &input),
    )
    .map_err(|_| IDENTITY_FAILED)?;
    Ok(McpToolCallIdentityPayloadV1 {
        artifact,
        runtime_private_metadata: private,
        artifact_hash: Some(hashed.token_or_digest),
        risk_categories: hashed.risk_categories,
    })
}

/// Run the tool policy, answering each saved lookup it names as the empty
/// store answers it.
fn run_policy(subject: &guard_contracts::McpToolPolicySubjectV1) -> Result<Decision, &'static str> {
    let mut observations: Vec<McpToolPolicyObservationV1> = Vec::new();
    for _ in 0..MAX_POLICY_ROUNDS {
        let ctx = Ctx {
            observations: &observations,
            lookup: None,
        };
        match evaluate_pass(&ctx, subject, Phase::Initial, false) {
            Ok(Pass::Final(decision)) => return Ok(*decision),
            Ok(Pass::Claimed { .. }) | Err(Stop::Fail(_)) => return Err(POLICY_FAILED),
            Err(Stop::Need(need)) => {
                let result = empty_store_answer(&need)?;
                observations.push(McpToolPolicyObservationV1 { need, result });
            }
        }
    }
    Err(POLICY_NEED)
}

/// What the proxy observes for a saved lookup against a store with no saved
/// policy rows and no one-shot approvals. Any other effect defers.
fn empty_store_answer(need: &Value) -> Result<Value, &'static str> {
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

/// The proxy route for a decided call, when it is a forward or a block.
fn route(proxy: &Value, decision: &Decision) -> Result<Routed, &'static str> {
    if decision.pending.is_some() || proxy["gate"].get("disable") == Some(&Value::Bool(true)) {
        return Err(ROUTE_UNSUPPORTED);
    }
    let routed = &proxy["route"];
    if !routed["need"].is_null() || !routed["decision_override"].is_null() {
        return Err(ROUTE_UNSUPPORTED);
    }
    let route = &routed["route"];
    let text = |key: &str| route.get(key).and_then(Value::as_str).map(str::to_owned);
    match route.get("kind").and_then(Value::as_str) {
        Some("stored_block") => Ok(Routed::StoredBlock),
        Some("terminal") => Ok(Routed::Terminal {
            policy_action: text("policy_action").ok_or(ROUTE_UNSUPPORTED)?,
        }),
        Some("allow_and_forward") if route.get("remember") == Some(&Value::Bool(false)) => {
            Ok(Routed::Forward {
                source: text("decision_source").ok_or(ROUTE_UNSUPPORTED)?,
                policy_action: text("policy_action").ok_or(ROUTE_UNSUPPORTED)?,
            })
        }
        _ => Err(ROUTE_UNSUPPORTED),
    }
}

/// Map a decision's view of the call arguments, for the subject.
fn object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}

#[path = "mcp_relay_decide_store.rs"]
mod store;
#[path = "mcp_relay_decide_subject.rs"]
mod subject;
#[path = "mcp_relay_decide_view.rs"]
mod view;

#[cfg(test)]
#[path = "mcp_relay_decide_tests.rs"]
mod tests;
