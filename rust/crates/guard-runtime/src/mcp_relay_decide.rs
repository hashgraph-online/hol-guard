//! Decide one native MCP relay `tools/call` in a single resident round trip.
//!
//! The Python proxy builds the tool-call identity, evaluates the tool policy,
//! applies the saved-allow gate, routes the call and records the outcome. This
//! operation repeats that path for the calls whose answer needs nothing the
//! resident cannot read itself: a workspace the current snapshot settled while
//! the publisher's ACK holds, a harness the binding's MCP view covers, and a
//! store whose saved lookups the resident reads as the proxy would: none at
//! all, or only local rows the daemon's published integrity key verifies (see
//! `mcp_relay_decide_store.rs` and `mcp_relay_decide_saved.rs`).
//! Such a call is forwarded (an allow or warn) or blocked (a terminal or
//! stored block). A block's evidence is queued for the daemon's drain first.
//! The proxy records a forward only after the child answered it, so a
//! forward's evidence is held under a ticket the relay commits once the child
//! responded; a forward the relay never completes (a catalog boundary change,
//! a lost answer) leaves no allow receipt.
//!
//! A call that installs or runs a package goes through the package lane
//! instead (`mcp_relay_decide_package.rs`), which decides it from an
//! evaluation the relay cannot perform inside one round trip: the first decide
//! of such a call answers `evaluate`, and the relay sends the same call again
//! with the evaluation attached (`mcp_relay_decide_package_leg.rs`). Its
//! receipt is the package request's own (`mcp_relay_decide_package_receipt.rs`).
//!
//! A call the proxy forwards only after claiming its saved allow or one-shot
//! approval is held for the relay to claim (see `mcp_relay_decide_claim.rs`).
//!
//! A call queued under `safe-alternative` blocks (`mcp_relay_decide_queue.rs`).
//! A call queued under `ask` writes its approval request and blocks on it
//! (`mcp_relay_decide_ask.rs`), for the harnesses whose native prompt is a
//! pure function of the decision.
//! Under `mode = "observe"` a call that needs approval forwards and records
//! what Guard would have done (`mcp_relay_decide_observe.rs`).
//! Every other call defers, and the relay answers it with the proxy's
//! fail-closed "no native decision" response: remote, bundle or unverifiable
//! saved policy, a call that needs an inline elicitation the resident cannot
//! raise, and any binding, lane or evidence failure.

use self::package_route::ToolLeg;
use crate::approval_proof_op::Disposition;
use crate::mcp_tool_policy_decision::Decision;
use crate::policy_enforcement::AdmittedPolicySnapshot;
use crate::policy_store::policy_store_direct_lane::DirectLaneBinding;
use crate::policy_store::PolicySnapshotStore;
use guard_command::package_intent_common::PackageIntent;
use guard_contracts::{
    McpToolArgumentsV1, McpToolCallBuildV1, McpToolCallHashInputV1, McpToolCallIdentityPayloadV1,
    McpToolPolicyProxyInputV1,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

pub(crate) use session::session_decidable;

pub(crate) const MCP_RELAY_DECIDE_FEATURE: &str = "mcp-relay-decide-v1";
const RESULT_SCHEMA: &str = "guard-mcp-relay-decide-result.v1";
/// The harnesses whose MCP proxy the relay replaces.
const RELAY_HARNESSES: [&str; 4] = ["codex", "copilot", "cursor", "opencode"];
/// `blocked_request_mode`, under which the queue route asks for approval.
const ASK_MODE: &str = "ask";

const HARNESS_UNSUPPORTED: &str = "mcp_relay_harness_unsupported";
const RUNTIME_SUPERSEDED: &str = "mcp_relay_runtime_superseded";
const WORKSPACE_INVALID: &str = "mcp_relay_workspace_invalid";
const EVIDENCE_UNDRAINED: &str = "mcp_relay_evidence_undrained";
const BINDING_INCOMPLETE: &str = "mcp_relay_binding_incomplete";
const IDENTITY_FAILED: &str = "mcp_relay_identity_failed";
const POLICY_NEED: &str = "mcp_relay_policy_need";
const ROUTE_UNSUPPORTED: &str = "mcp_relay_route_unsupported";
const EVIDENCE_FULL: &str = "mcp_relay_evidence_full";
/// Every defer the package lane answers with, which is what hands a server to
/// the proxy. The gate's workspace check is not one of them: it fires before
/// an intent is known, for a call that may carry no package request at all.
const PACKAGE_DEFER_PREFIX: &str = "mcp_relay_package";

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
    /// The proxy's working directory, which a queued approval row records and
    /// a package call's execution context is bound to.
    #[serde(default)]
    pub(crate) cwd: Option<String>,
    /// The proxy's `os.environ`, which only a package call's execution context
    /// is built from (`_resident_environment`).
    #[serde(default)]
    pub(crate) environment: BTreeMap<String, String>,
    /// The supply-chain evaluation of this call's package request, which the
    /// relay performs and sends with the second decide of the same call.
    #[serde(default)]
    pub(crate) package_evaluation: Option<Map<String, Value>>,
    /// Set by the relay when it has no evaluation to send: the rounds did not
    /// settle on one, or the decide carrying one asked for another. The lane
    /// decides nothing without it, so this decide is the refusal rather than a
    /// second request for an evaluation that is not coming.
    #[serde(default)]
    pub(crate) package_evaluation_unsettled: bool,
    pub(crate) catalog_state: String,
    /// The `tools/call` params, which the daemon projects into evidence.
    pub(crate) params: Value,
    /// The client's inline approval prompt, which the relay owns.
    #[serde(default)]
    pub(crate) inline: Inline,
}

/// What the relay knows about the client's inline elicitation prompt.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Inline {
    /// Whether the client's `initialize` declared the `elicitation`
    /// capability, which `_record_client_capabilities` reads.
    #[serde(default)]
    pub(crate) available: bool,
    /// The answer to the prompt the relay already raised for this call.
    #[serde(default)]
    pub(crate) answer: Option<inline::Reply>,
}

/// What the relay does with the call; `Claim` spends the held saved approval
/// once the relay found the catalog still current.
#[derive(Debug, Clone, PartialEq)]
enum Answer {
    Forward {
        ticket: String,
    },
    Block {
        message: String,
        data: Value,
    },
    Claim {
        ticket: String,
    },
    /// Raise the client's inline prompt and decide the call again with it.
    Elicit {
        params: Value,
    },
    /// Evaluate this call's package request and ask again with the evaluation
    /// attached. A decide answers with no ticket and is decided again; a claim
    /// answers with the ticket its rows are held against again, which the
    /// second claim of the same call spends.
    Evaluate {
        ticket: Option<String>,
    },
}

/// The lane admission one decision was made under.
#[derive(Clone)]
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

/// One held claim: a tool call's, or a package call's.
///
/// The two spend differently — a package claim re-resolves twice and carries
/// an evaluation of its own — so the lane holds which it raised, and the claim
/// request is answered by the spend that matches.
pub(crate) enum HeldClaim {
    Tool(ClaimContext),
    Package(PackageClaimContext),
}

/// A package call that forwards only once the approvals its two policies
/// left are claimed. Unlike a tool call's, the claim carries an evaluation of
/// its own: the relay re-reads the package request after the claim, with the
/// external archive network authorized, and the policy is re-resolved from
/// that (`mcp_relay_decide_package_spend.rs`).
pub(crate) struct PackageClaimContext {
    request: McpRelayDecideRequestV1,
    admitted: Admitted,
    claimed: package_claim::PackageClaimed,
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

/// What one resolve does with the package request the gate found.
enum PackageLeg<'a> {
    /// Decide it, from the request's own evaluation: the stored policy, and
    /// the route the lane takes over it and the tool authority together.
    Decide(&'a PackageIntent),
    /// Re-resolve a claimed one, from the evaluation the relay re-read the
    /// request with after the claim: the stored policy alone, because the
    /// route a claimed call takes is the post-claim revalidation's.
    Claimed(&'a PackageIntent, &'a Map<String, Value>),
}

/// The package leg one resolve produced, for the caller that asked for it.
enum Legged {
    Decided(Box<package_leg::Packaged>),
    Reresolved(Box<package_leg::Reresolved>),
}

impl Legged {
    /// The decided leg, for the decide path that asked for a route.
    fn decided(&self) -> Option<&package_leg::Packaged> {
        match self {
            Self::Decided(packaged) => Some(packaged.as_ref()),
            Self::Reresolved(_) => None,
        }
    }

    /// The re-resolution, for the claim that asked for a policy.
    fn reresolved(self) -> Option<package_leg::Reresolved> {
        match self {
            Self::Reresolved(reresolved) => Some(*reresolved),
            Self::Decided(_) => None,
        }
    }
}

/// The route the proxy takes for a decided call.
#[derive(Debug, Clone, PartialEq)]
enum Routed {
    Forward {
        source: String,
        policy_action: String,
        /// Whether the forward first saves the artifact allow the inline
        /// prompt approved (`allow_tool_call(remember=True)`).
        remember: bool,
    },
    Terminal {
        policy_action: String,
    },
    /// `_stored_tool_block_response`, whose message names the call a package
    /// tool call when the request it carries went to the package lane.
    StoredBlock {
        package_request: bool,
    },
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
    /// The queue route's approval-center block under `ask`, whose request row
    /// is already written (`mcp_relay_decide_ask.rs`).
    Asked {
        policy_action: String,
        message: String,
        data: Value,
        /// The written request and the desktop notice the store op returned,
        /// for the drain to raise the approval surface from.
        approval: Value,
    },
    /// Forward and record what Guard would have stopped (`mode = "observe"`).
    ObserveForward,
    /// Raise the client's inline prompt; the route needs its answer
    /// (`mcp_relay_decide_inline.rs`).
    Elicit,
    /// The inline prompt denied the call, or answered it invalidly.
    InlineDenied {
        /// `inline-denied` or `inline-invalid`.
        source: &'static str,
    },
}

pub(crate) fn evaluate(
    request: McpRelayDecideRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let answer = decide(&request, policy_store);
    // Every package-lane defer, from the gate's own to the lane's, so a server
    // whose package call the relay could not answer goes to the proxy whole.
    if matches!(&answer, Err(reason) if reason.starts_with(PACKAGE_DEFER_PREFIX)) {
        mark_package_server(&request, policy_store);
    }
    encode(answer)
}

/// The package request one decide request carries, as this gate reads it.
///
/// The relay parses the intent of the call it is evaluating in process, from
/// the request it sent. `PackageIntent` is not wire-serializable, so the two
/// halves each parse the same inputs rather than shipping one to the other
/// (`mcp_relay_decide_package.rs`). A request this gate refuses carries no
/// intent for the relay either, so the call is evaluated by neither.
pub(crate) fn relayed_package_intent(request: Value) -> Option<PackageIntent> {
    let request: McpRelayDecideRequestV1 = serde_json::from_value(request).ok()?;
    package::package_gate(&request).ok().flatten()
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
        Ok(Answer::Elicit { params }) => {
            json!({"schema": RESULT_SCHEMA, "outcome": "elicit", "params": params})
        }
        Ok(Answer::Evaluate { ticket }) => match ticket {
            Some(ticket) => {
                json!({"schema": RESULT_SCHEMA, "outcome": "evaluate", "ticket": ticket})
            }
            None => json!({"schema": RESULT_SCHEMA, "outcome": "evaluate"}),
        },
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

/// The evaluation leg of a package call, when this decide is one.
///
/// The package lane decides from an evaluation whose archive and registry
/// rounds the relay performs, which no single round trip can hold. So the
/// first decide of a package call asks for it, and the relay decides the same
/// call again with the evaluation attached. A relay whose rounds did not
/// settle says so instead, and that decide is the refusal: asking again for an
/// evaluation that is not coming would refuse the call in every later session
/// too, where the refusal hands the server to the proxy.
fn evaluation_leg(
    request: &McpRelayDecideRequestV1,
    is_package: bool,
) -> Option<Result<Answer, &'static str>> {
    if !is_package || request.package_evaluation.is_some() {
        return None;
    }
    if request.package_evaluation_unsettled {
        return Some(Err(package_leg::EVALUATION_ABSENT));
    }
    Some(Ok(Answer::Evaluate { ticket: None }))
}

fn decide(
    request: &McpRelayDecideRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Answer, &'static str> {
    policy_store
        .require_guard_home(&request.guard_home)
        .map_err(|_| BINDING_INCOMPLETE)?;
    let admitted = admit(request, policy_store)?;
    // Keep authority fixed through routing and evidence finalization, not
    // only while the tool policy is evaluated.
    let _command_lease = policy_store
        .command_authority_lease(&admitted.snapshot)
        .map_err(|_| BINDING_INCOMPLETE)?;
    let intent = package::package_gate(request)?;
    if let Some(answer) = evaluation_leg(request, intent.is_some()) {
        return answer;
    }
    let connection = store::open(Path::new(&request.guard_home))?;
    // One read snapshot for the store checks and every lookup they gate, so a
    // row or state the daemon commits between them cannot slip past.
    let snapshot = connection
        .as_deref()
        .map(Connection::unchecked_transaction)
        .transpose()
        .map_err(|_| store::STORE_UNREADABLE)?;
    let (mut resolved, legged) = resolve(
        request,
        &admitted,
        connection.as_deref(),
        intent.as_ref().map(PackageLeg::Decide),
        policy_store,
    )?;
    drop(snapshot);
    // A package call is answered by its own lane, under the package policy and
    // the tool authority together, so none of the tool-only route below runs
    // for it.
    if let Some(packaged) = legged.as_ref().and_then(Legged::decided) {
        return settle_package(request, &admitted, &resolved, packaged, policy_store);
    }
    let asks = admitted.binding.review.blocked_request_mode.as_deref() == Some(ASK_MODE);
    let proxy = crate::mcp_tool_policy_proxy::proxy_payload(
        &McpToolPolicyProxyInputV1 {
            catalog_state: request.catalog_state.clone(),
            mode: resolved.mode.clone(),
            package_present: false,
            asks_for_approval: asks,
            // `_inline_prompt_available`: the client declared the capability
            // and the proxy class raises the prompt. `OpenCodeMcpGuardProxy`
            // takes the base class's no-op, so it never prompts inline.
            inline_available: request.inline.available && request.build.harness != ask::OPENCODE,
            tool_name: request.build.tool_name.clone(),
            // The answer to the prompt the relay already raised; without one
            // the route names the `inline_approval` fact and the relay asks.
            inline_approval: request.inline.answer.map(inline::Reply::contract),
        },
        &resolved.decision,
        // What `_allow_after_native_prompt` answers for this harness, so the
        // route takes the prompt's own answer instead of naming the
        // `native_prompt` fact the resident cannot gather. The proxy asks it
        // about the decision the route names, gate and override included.
        |tool| asks.then(|| ask::native_prompt_allows(&request.build.harness, tool)),
    );
    let (proxy, downgraded) = observe::downgrade(proxy, &resolved.mode, &resolved.decision)?;
    let routed = route(
        &proxy,
        downgraded.as_ref().unwrap_or(&resolved.decision),
        request.inline.answer,
    )?;
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
                .hold(HeldClaim::Tool(context), Instant::now())
                .map(|ticket| Answer::Claim { ticket })
                .ok_or(EVIDENCE_FULL)
        }
        // Phase one of the inline prompt: the relay raises it and decides the
        // call again with the answer. No evidence is written for this pass,
        // so the second decide is an ordinary full decide of the same call.
        Routed::Elicit => Ok(Answer::Elicit {
            params: inline::prompt(
                &request.build.server_name,
                &request.build.tool_name,
                &resolved.decision.summary,
            ),
        }),
        Routed::Forward {
            source,
            policy_action,
            remember: true,
        } => {
            // The remembered allow is an artifact-scoped policy write, and the
            // approval gate holds every allow to a decision while it is
            // enabled. `upsert_policy` raising `ApprovalGateError` is what
            // sends the proxy to the re-approval queue, so the resident asks
            // the gate before it forwards and the drain performs the write.
            let routed =
                if ask::remembered_write_refused(&request.guard_home, &resolved.identity.artifact)?
                {
                    ask::queue(
                        request,
                        &admitted,
                        &resolved,
                        "require-reapproval".to_owned(),
                    )?
                } else {
                    Routed::Forward {
                        source,
                        policy_action,
                        remember: true,
                    }
                };
            settle(request, &resolved, routed, None, policy_store)
        }
        Routed::Queue { policy_action } => {
            let mode = admitted.binding.review.blocked_request_mode.as_deref();
            let routed = match mode {
                // The row is written before the block is answered, as the
                // proxy queues it before it replies to the client.
                Some(ASK_MODE) => ask::queue(request, &admitted, &resolved, policy_action)?,
                _ => queue::safe_alternative(
                    mode,
                    resolved.redaction_level.as_deref(),
                    policy_action,
                )?,
            };
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

/// Build the identity and run the tool policy, reading saved lookups on
/// `connection`, held in one transaction. A call the gate found a package
/// intent in also resolves its package leg, on that same snapshot: the lane's
/// second resolution reads the store again, so it belongs inside it. What
/// that leg is depends on who asked — a route for the decide path, the policy
/// alone for a claim that routes it by the post-claim revalidation instead.
fn resolve(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    connection: Option<&Connection>,
    leg: Option<PackageLeg<'_>>,
    policy_store: &PolicySnapshotStore,
) -> Result<(Resolved, Option<Legged>), &'static str> {
    policy_store
        .require_guard_home(&request.guard_home)
        .map_err(|_| BINDING_INCOMPLETE)?;
    let _command_lease = policy_store
        .command_authority_lease(&admitted.snapshot)
        .map_err(|_| BINDING_INCOMPLETE)?;
    let binding = &admitted.binding;
    let control_digest = binding
        .exact_action_control_digest
        .clone()
        .ok_or(BINDING_INCOMPLETE)?;
    let view = view::bound_harness_view(binding, &request.build.harness)?;
    let saved = match connection {
        Some(connection) => store::saved(
            connection,
            binding,
            &request.guard_home,
            &request.build.harness,
        )?,
        None => None,
    };
    let identity = identity(request, &view, control_digest.clone())?;
    let subject = subject::subject(request, &identity, &view)?;
    let catalog = crate::contributed_mcp_decision_op::Catalog {
        guard_home: &request.guard_home,
        controls: admitted.snapshot.command_extensions.as_ref(),
    };
    let decision = run_policy(&subject, saved.as_ref(), connection, &catalog)?;
    let packaged = match leg {
        Some(PackageLeg::Decide(intent)) => {
            let inputs = package_leg::package_inputs(
                request,
                &view,
                saved.as_ref(),
                &control_digest,
                &identity,
                intent,
                request.package_evaluation.as_ref(),
            )?;
            Some(Legged::Decided(Box::new(package_leg::decide_package_leg(
                request,
                inputs,
                &subject,
                &catalog,
                // The queue route of the package lane is answered by the same
                // bound mode and redaction level the tool lane's queue route is.
                package_lane::QueueBinding {
                    blocked_request_mode: binding.review.blocked_request_mode.as_deref(),
                    redaction_level: view.receipt_redaction_level.as_deref(),
                },
            )?)))
        }
        Some(PackageLeg::Claimed(intent, evaluation)) => Some(Legged::Reresolved(Box::new(
            package_leg::reresolve_package_leg(
                request,
                &view,
                saved.as_ref(),
                &control_digest,
                &identity,
                intent,
                evaluation,
            )?,
        ))),
        None => None,
    };
    Ok((
        Resolved {
            identity,
            decision,
            mode: view.mode,
            redaction_level: view.receipt_redaction_level,
        },
        packaged,
    ))
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
    let mut approval = None;
    let mut remembered = false;
    let (blocked, outcome, source, policy_action) = match routed {
        Routed::Forward {
            source,
            policy_action,
            remember,
        } => {
            // The artifact allow the inline prompt approved, which the drain
            // saves before it records the forward.
            if remember {
                remembered = true;
            }
            (None, "forward", source, policy_action)
        }
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
        Routed::StoredBlock { package_request } => (
            Some(Answer::Block {
                message: {
                    let kind = if package_request {
                        "package tool call"
                    } else {
                        "tool call"
                    };
                    format!(
                        "HOL Guard blocked {kind} {tool} from {server}. This exact request is \
                         already blocked by authenticated saved policy."
                    )
                },
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
        Routed::Asked {
            policy_action,
            message,
            data,
            approval: raised,
        } => {
            approval = Some(raised);
            (
                Some(Answer::Block { message, data }),
                "block",
                ask::APPROVAL_PENDING_SOURCE.to_owned(),
                policy_action,
            )
        }
        Routed::InlineDenied { source } => (
            Some(Answer::Block {
                message: inline::block_message(source, tool, server),
                data: json!({"approvalRequests": [], "guardPolicyAction": "block"}),
            }),
            "block",
            source.to_owned(),
            "block".to_owned(),
        ),
        Routed::Claim { .. } | Routed::Queue { .. } | Routed::ObserveForward | Routed::Elicit => {
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
    // `allow_tool_call(remember=True, emit_runtime_evidence=False)`, which the
    // drain performs before the forward's own record.
    if remembered {
        evidence["remember"] = json!(true);
    }
    if let Some(append) = evidence_append {
        evidence["evidence_append"] = Value::Array(append);
    }
    // The silent inbox row the drain writes after the block receipt.
    if let Some(review) = review {
        evidence["review"] = review;
    }
    // The approval-center surface the proxy raises once the row is written.
    if let Some(approval) = approval {
        evidence["approval"] = approval;
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

/// Answer one decided package call.
///
/// A leg the package policy decided is answered here and queues the receipt
/// the drain writes it from: the package request's own, not the tool call's.
/// A leg the tool policy decided is the plain tool-policy response the proxy
/// renders for any other call, so it goes through `settle` and leaves the
/// ordinary `mcp_tool_call` receipt against the tool artifact. The decision it
/// is answered under is `resolved.decision`, which is the re-resolution the
/// lane composed from: both are `run_policy` over the same subject on the
/// snapshot this decide still holds.
fn settle_package(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    resolved: &Resolved,
    packaged: &package_leg::Packaged,
    policy_store: &PolicySnapshotStore,
) -> Result<Answer, &'static str> {
    let queued;
    let answer = match &packaged.outcome {
        package_lane::PackageOutcome::Answered(answer) => answer,
        // The row the bound `ask` mode writes reads the store this holds, so
        // the answer is only completed here.
        package_lane::PackageOutcome::AskPackage(asked) => {
            queued = package_ask::queue(request, admitted, resolved, &packaged.artifact, asked)?;
            &queued
        }
        // So do the observed rows the forward is queued with, which the
        // answer carries the notices of once they are written.
        package_lane::PackageOutcome::ObservePackage { answer, observed } => {
            queued = package_observe::queue(
                request,
                admitted,
                resolved,
                &packaged.artifact,
                answer,
                observed,
            )?;
            &queued
        }
        // Nothing is answered and nothing is written: the rows are held
        // against a ticket, and the call is decided again once the claim that
        // spends them commits.
        package_lane::PackageOutcome::ClaimPackage(leg) => {
            let claimed = package_claim::claimed(leg, resolved, &packaged.artifact)?;
            let context = PackageClaimContext {
                request: request.clone(),
                admitted: admitted.clone(),
                claimed,
            };
            return policy_store
                .mcp_relay_claims()
                .hold(HeldClaim::Package(context), Instant::now())
                .map(|ticket| Answer::Claim { ticket })
                .ok_or(EVIDENCE_FULL);
        }
        package_lane::PackageOutcome::ToolLeg(leg) => {
            let routed = match leg {
                ToolLeg::StoredBlock => Routed::StoredBlock {
                    package_request: true,
                },
                ToolLeg::Terminal { policy_action } => Routed::Terminal {
                    policy_action: policy_action.clone(),
                },
                ToolLeg::Queue { policy_action } => {
                    let mode = admitted.binding.review.blocked_request_mode.as_deref();
                    match mode {
                        Some(ASK_MODE) => {
                            ask::queue(request, admitted, resolved, policy_action.clone())?
                        }
                        _ => queue::safe_alternative(
                            mode,
                            resolved.redaction_level.as_deref(),
                            policy_action.clone(),
                        )?,
                    }
                }
            };
            return settle(request, resolved, routed, None, policy_store);
        }
    };
    let identity = serde_json::to_value(&resolved.identity).map_err(|_| IDENTITY_FAILED)?;
    let evidence = package_receipt::record(
        request,
        &identity,
        &resolved.decision,
        &packaged.artifact,
        &packaged.workspace,
        answer,
    )?;
    match answer.block.clone() {
        // As for a tool call, the relay commits the ticket once the child
        // answered the forward.
        None => policy_store
            .mcp_relay_pending()
            .hold(evidence, Instant::now())
            .map(|ticket| Answer::Forward { ticket })
            .ok_or(EVIDENCE_FULL),
        Some((message, data)) if policy_store.direct_evidence().offer(evidence) => {
            Ok(Answer::Block { message, data })
        }
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

#[path = "mcp_relay_decide_ask.rs"]
mod ask;
#[path = "mcp_relay_decide_ask_row.rs"]
mod ask_row;
#[path = "mcp_relay_decide_claim.rs"]
mod claim;
pub(crate) use claim::claim;
#[path = "mcp_relay_decide_inline.rs"]
pub(crate) mod inline;
#[path = "mcp_relay_decide_observe.rs"]
mod observe;
#[path = "mcp_relay_decide_package.rs"]
mod package;
#[path = "mcp_relay_decide_package_answer.rs"]
mod package_answer;
#[path = "mcp_relay_decide_package_archive.rs"]
mod package_archive;
#[path = "mcp_relay_decide_package_ask.rs"]
mod package_ask;
// What the claimed package lane composes, short of the store write.
#[path = "mcp_relay_decide_package_claim.rs"]
mod package_claim;
#[path = "mcp_relay_decide_package_config.rs"]
mod package_config;
#[path = "mcp_relay_decide_package_lane.rs"]
mod package_lane;
#[path = "mcp_relay_decide_package_leg.rs"]
mod package_leg;
#[path = "mcp_relay_decide_package_observe.rs"]
mod package_observe;
#[path = "mcp_relay_decide_package_policy.rs"]
mod package_policy;
// The revalidation a claimed package call is decided again by.
#[path = "mcp_relay_decide_package_postclaim.rs"]
mod package_postclaim;
#[path = "mcp_relay_decide_package_receipt.rs"]
mod package_receipt;
#[path = "mcp_relay_decide_package_route.rs"]
mod package_route;
#[path = "mcp_relay_decide_package_snapshot.rs"]
mod package_snapshot;
// What a claimed package call spends, and the answer it commits with.
#[path = "mcp_relay_decide_package_spend.rs"]
mod package_spend;
#[path = "mcp_relay_decide_policy.rs"]
mod policy;
use policy::run_policy;
// The provider lookups a reviewed provider action is steered by.
#[path = "mcp_relay_decide_provider.rs"]
mod provider;
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
