//! Decide one native MCP relay `tools/call` in a single resident round trip.
//!
//! The Python proxy builds the tool-call identity, evaluates the tool policy,
//! applies the saved-allow gate, routes the call and records the outcome. This
//! operation repeats that path for the calls whose answer needs nothing the
//! resident cannot read itself: a workspace the current snapshot settled while
//! the publisher's ACK holds, a harness the binding's MCP view covers, and a
//! store whose saved lookups the resident reads as the proxy would: none at
//! all, or only local rows the daemon's published integrity key verifies (see
//! `mcp_relay_decide_store.rs` and `mcp_relay_decide_saved.rs`), for a call
//! the package parser finds no intent in (`mcp_relay_decide_package.rs`).
//! Such a call is forwarded (an allow or warn) or blocked (a terminal or
//! stored block). A block's evidence is queued for the daemon's drain first.
//! The proxy records a forward only after the child answered it, so a
//! forward's evidence is held under a ticket the relay commits once the child
//! responded; a forward the relay never completes (a catalog boundary change,
//! a lost answer) leaves no allow receipt.
//!
//! A call the proxy forwards only after claiming its saved allow or one-shot
//! approval is held for the relay to claim (see `mcp_relay_decide_claim.rs`).
//!
//! A call queued under `safe-alternative` blocks (`mcp_relay_decide_queue.rs`).
//! Under `mode = "observe"` a call that needs approval forwards and records
//! what Guard would have done (`mcp_relay_decide_observe.rs`).
//! Every other call defers, and the relay answers it with the proxy's
//! fail-closed "no native decision" response: remote, bundle or unverifiable
//! saved policy, a call that needs a prompt (the `ask` mode), and any
//! binding, lane or evidence failure.

use crate::approval_proof_op::Disposition;
use crate::mcp_tool_policy_decision::Decision;
use crate::policy_enforcement::AdmittedPolicySnapshot;
use crate::policy_store::policy_store_direct_lane::DirectLaneBinding;
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::{
    McpToolArgumentsV1, McpToolCallBuildV1, McpToolCallHashInputV1, McpToolCallIdentityPayloadV1,
    McpToolPolicyProxyInputV1,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

pub(crate) use session::session_decidable;

pub(crate) const MCP_RELAY_DECIDE_FEATURE: &str = "mcp-relay-decide-v1";
const RESULT_SCHEMA: &str = "guard-mcp-relay-decide-result.v1";
/// The harnesses whose MCP proxy the relay replaces.
const RELAY_HARNESSES: [&str; 4] = ["codex", "copilot", "cursor", "opencode"];

const HARNESS_UNSUPPORTED: &str = "mcp_relay_harness_unsupported";
const RUNTIME_SUPERSEDED: &str = "mcp_relay_runtime_superseded";
const WORKSPACE_INVALID: &str = "mcp_relay_workspace_invalid";
const EVIDENCE_UNDRAINED: &str = "mcp_relay_evidence_undrained";
const BINDING_INCOMPLETE: &str = "mcp_relay_binding_incomplete";
const IDENTITY_FAILED: &str = "mcp_relay_identity_failed";
const POLICY_NEED: &str = "mcp_relay_policy_need";
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
    /// The proxy's `PATH` as set, which the package parser resolves in.
    #[serde(default)]
    pub(crate) path: Option<String>,
    pub(crate) launcher_home: String,
    pub(crate) catalog_state: String,
    /// The `tools/call` params, which the daemon projects into evidence.
    pub(crate) params: Value,
}

/// What the relay does with the call; `Claim` spends the held saved approval
/// once the relay found the catalog still current.
#[derive(Debug, Clone, PartialEq)]
enum Answer {
    Forward { ticket: String },
    Block { message: String, data: Value },
    Claim { ticket: String },
}

/// The lane admission one decision was made under.
struct Admitted {
    workspace: String,
    snapshot: Arc<AdmittedPolicySnapshot>,
    binding: Arc<DirectLaneBinding>,
}

/// A decision that forwards only once its saved approval is claimed.
pub(crate) struct ClaimContext {
    request: McpRelayDecideRequestV1,
    admitted: Admitted,
    claimed: Claimed,
}

/// The approval a decision claims and the forward it then routes.
struct Claimed {
    artifact_id: String,
    artifact_hash: String,
    pending: Map<String, Value>,
    disposition: Option<Disposition>,
    source: String,
    policy_action: String,
}

/// The identity and policy decision of one call.
struct Resolved {
    identity: McpToolCallIdentityPayloadV1,
    decision: Decision,
    mode: String,
    /// The bound `receipt_redaction_level`, which the inbox row is written with.
    redaction_level: Option<String>,
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
    /// Forward once the pending saved approval is claimed.
    Claim {
        source: String,
        policy_action: String,
    },
    /// Queue an approval request, as the blocked-request mode answers it.
    Queue {
        policy_action: String,
    },
    /// The queue route's safe-alternative block (`mcp_relay_decide_queue.rs`).
    SafeAlternative {
        policy_action: String,
        redaction_level: String,
    },
    /// Forward and record what Guard would have stopped (`mode = "observe"`).
    ObserveForward,
}

pub(crate) fn evaluate(
    request: McpRelayDecideRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let answer = decide(&request, policy_store);
    if matches!(
        answer,
        Err(package::PACKAGE_INTENT | package::PACKAGE_AMBIGUOUS)
    ) {
        mark_package_server(&request, policy_store);
    }
    encode(answer)
}

/// Hand later sessions of a server whose call went to the package policy to
/// the proxy, which decides such calls (`mcp_relay_servers.rs`).
fn mark_package_server(request: &McpRelayDecideRequestV1, policy_store: &PolicySnapshotStore) {
    let build = &request.build;
    let Some(identity) = build.server_identity.as_ref() else {
        return;
    };
    let server = crate::mcp_relay_servers::RelayServerV1 {
        harness: build.harness.clone(),
        server_name: build.server_name.clone(),
        source_scope: build.source_scope.clone(),
        config_path: build.config_path.clone(),
        server_id: build.server_id.clone(),
        identity_hash: identity.identity_hash.clone(),
    };
    policy_store.mcp_relay_servers().record(&server, true);
}

fn encode(answer: Result<Answer, &'static str>) -> Result<Vec<u8>, String> {
    let body = match answer {
        Ok(Answer::Forward { ticket }) => {
            json!({"schema": RESULT_SCHEMA, "outcome": "forward", "ticket": ticket})
        }
        Ok(Answer::Claim { ticket }) => {
            json!({"schema": RESULT_SCHEMA, "outcome": "claim", "ticket": ticket})
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
    let admitted = admit(request, policy_store)?;
    let connection = store::open(Path::new(&request.guard_home))?;
    // One read snapshot for the store checks and every lookup they gate, so a
    // row or state the daemon commits between them cannot slip past.
    let snapshot = connection
        .as_deref()
        .map(Connection::unchecked_transaction)
        .transpose()
        .map_err(|_| store::STORE_UNREADABLE)?;
    let mut resolved = resolve(request, &admitted, connection.as_deref())?;
    drop(snapshot);
    let proxy = crate::mcp_tool_policy_proxy::proxy_payload(
        &McpToolPolicyProxyInputV1 {
            catalog_state: request.catalog_state.clone(),
            mode: resolved.mode.clone(),
            package_present: false,
            // Both only steer a call that is neither allowed nor blocked,
            // which is answered only under `safe-alternative`, where the
            // proxy consults neither; any other mode defers its queue or
            // observe-forward route.
            asks_for_approval: false,
            inline_available: false,
            tool_name: request.build.tool_name.clone(),
        },
        &resolved.decision,
    );
    let (proxy, downgraded) = observe::downgrade(proxy, &resolved.mode, &resolved.decision)?;
    let routed = route(&proxy, downgraded.as_ref().unwrap_or(&resolved.decision))?;
    if routed == Routed::ObserveForward {
        // `_observe_tool_forward` records the decision without the downgrade.
        let mode = admitted.binding.review.blocked_request_mode.as_deref();
        let (routed, append) = observe::forward(mode, &resolved.decision)?;
        return settle(request, &resolved, routed, append, policy_store);
    }
    if let Some(decision) = downgraded {
        resolved.decision = decision;
    }
    match routed {
        Routed::Claim {
            source,
            policy_action,
        } => {
            let claimed = Claimed {
                artifact_id: resolved.identity.artifact.artifact_id.clone(),
                artifact_hash: resolved
                    .identity
                    .artifact_hash
                    .clone()
                    .ok_or(IDENTITY_FAILED)?,
                pending: resolved.decision.pending.clone().ok_or(ROUTE_UNSUPPORTED)?,
                disposition: resolved.decision.claim_disposition,
                source,
                policy_action,
            };
            let context = ClaimContext {
                request: request.clone(),
                admitted,
                claimed,
            };
            policy_store
                .mcp_relay_claims()
                .hold(context, Instant::now())
                .map(|ticket| Answer::Claim { ticket })
                .ok_or(EVIDENCE_FULL)
        }
        Routed::Queue { policy_action } => {
            let mode = admitted.binding.review.blocked_request_mode.as_deref();
            let level = resolved.redaction_level.as_deref();
            let routed = queue::safe_alternative(mode, level, policy_action)?;
            settle(request, &resolved, routed, None, policy_store)
        }
        routed => settle(request, &resolved, routed, None, policy_store),
    }
}

/// Admit the call's settled workspace to the direct lane.
fn admit(
    request: &McpRelayDecideRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Admitted, &'static str> {
    if !RELAY_HARNESSES.contains(&request.build.harness.as_str()) {
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
    let (snapshot, binding) = policy_store
        .admit_direct_hook_or_subdirectory(&workspace)
        .map_err(|defer| defer.code())?;
    if binding.evidence_drain != Some(true) {
        return Err(EVIDENCE_UNDRAINED);
    }
    Ok(Admitted {
        workspace,
        snapshot,
        binding,
    })
}

/// Pass the package check, build the identity and run the tool policy,
/// reading saved lookups on `connection`, held in one transaction.
fn resolve(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    connection: Option<&Connection>,
) -> Result<Resolved, &'static str> {
    package::package_gate(request)?;
    let binding = &admitted.binding;
    let control_digest = binding
        .exact_action_control_digest
        .clone()
        .ok_or(BINDING_INCOMPLETE)?;
    let view = view::bound_harness_view(binding, &request.build.harness)?;
    let saved = match connection {
        Some(connection) => store::saved(connection, binding, &request.guard_home)?,
        None => None,
    };
    let identity = identity(request, &view, control_digest)?;
    let subject = subject::subject(request, &identity, &view)?;
    let decision = run_policy(&subject, saved.as_ref())?;
    Ok(Resolved {
        identity,
        decision,
        mode: view.mode,
        redaction_level: view.receipt_redaction_level,
    })
}

/// Answer a forward or block route and queue or hold its evidence; a claimed
/// call's evidence also carries what the post-claim check appended.
fn settle(
    request: &McpRelayDecideRequestV1,
    resolved: &Resolved,
    routed: Routed,
    evidence_append: Option<Vec<Value>>,
    policy_store: &PolicySnapshotStore,
) -> Result<Answer, &'static str> {
    let (identity, decision) = (&resolved.identity, &resolved.decision);
    let harness = request.build.harness.as_str();
    let tool = &request.build.tool_name;
    let server = &request.build.server_name;
    let mut review = None;
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
        Routed::SafeAlternative {
            policy_action,
            redaction_level,
        } => {
            review = Some(json!({"redaction_level": redaction_level}));
            let (message, data) = queue::safe_alternative_block(tool, server, &decision.signals);
            (
                Some(Answer::Block { message, data }),
                "block",
                queue::SAFE_ALTERNATIVE_SOURCE.to_owned(),
                policy_action,
            )
        }
        Routed::Claim { .. } | Routed::Queue { .. } | Routed::ObserveForward => {
            return Err(ROUTE_UNSUPPORTED)
        }
    };
    let mut evidence = json!({
        "kind": "mcp_tool_call",
        "harness": harness,
        "outcome": outcome,
        "decision_source": source,
        "policy_action": policy_action,
        "tool_name": tool,
        "params": request.params,
        // The arguments in host key order, which the decoded params lost.
        "arguments": serde_json::to_value(&request.arguments).map_err(|_| IDENTITY_FAILED)?,
        "identity": serde_json::to_value(identity).map_err(|_| IDENTITY_FAILED)?,
        "decision": decision.to_value(),
    });
    if let Some(append) = evidence_append {
        evidence["evidence_append"] = Value::Array(append);
    }
    // The silent inbox row the drain writes after the block receipt.
    if let Some(review) = review {
        evidence["review"] = review;
    }
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

#[path = "mcp_relay_decide_claim.rs"]
mod claim;
pub(crate) use claim::claim;
#[path = "mcp_relay_decide_observe.rs"]
mod observe;
#[path = "mcp_relay_decide_package.rs"]
mod package;
#[path = "mcp_relay_decide_policy.rs"]
mod policy;
use policy::run_policy;
#[path = "mcp_relay_decide_queue.rs"]
mod queue;
use queue::route;
#[path = "mcp_relay_decide_saved.rs"]
mod saved;
#[path = "mcp_relay_decide_session.rs"]
mod session;
#[path = "mcp_relay_decide_store.rs"]
mod store;
#[path = "mcp_relay_decide_subject.rs"]
mod subject;
#[path = "mcp_relay_decide_view.rs"]
mod view;

#[cfg(test)]
#[path = "mcp_relay_decide_tests.rs"]
mod tests;
