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

use crate::approval_proof_op::Disposition;
use crate::mcp_tool_policy_decision::Decision;
use crate::policy_enforcement::AdmittedPolicySnapshot;
use crate::policy_store::policy_store_direct_lane::DirectLaneBinding;
use crate::policy_store::PolicySnapshotStore;
use guard_command::package_intent_common::PackageIntent;
use guard_contracts::{McpToolArgumentsV1, McpToolCallBuildV1, McpToolCallIdentityPayloadV1};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

pub(crate) use session::session_decidable;

pub(crate) const MCP_RELAY_DECIDE_FEATURE: &str = "mcp-relay-decide-v2";
const RESULT_SCHEMA: &str = "guard-mcp-relay-decide-result.v1";
/// The harnesses whose MCP proxy the relay replaces.
const RELAY_HARNESSES: [&str; 6] = ["cline", "codex", "copilot", "cursor", "hermes", "opencode"];
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
    /// Set by a relay that leaves a Composio wrapper's provider catalog hash
    /// to the resident, which reads it from the store as the proxy did. A
    /// resident that predates it rejects the field, so the relay defers and
    /// the call fails closed instead of hashing without the catalog.
    #[serde(default)]
    pub(crate) resident_provider_catalog: bool,
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
    session: session_config::SessionSettings,
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
        /// The approval center origin the daemon listens on, which the
        /// block's silent inbox row links to.
        center: Option<String>,
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
    package_server::after_decide(&answer, &request, policy_store);
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
    let session = session_config::session_settings(
        &binding,
        &request.build.harness,
        &request.guard_home,
        request.workspace.as_deref(),
    );
    Ok(Admitted {
        workspace,
        snapshot,
        binding,
        session,
    })
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

#[path = "mcp_relay_decide_ask.rs"]
mod ask;
#[path = "mcp_relay_decide_ask_row.rs"]
pub(crate) mod ask_row;
#[path = "mcp_relay_decide_claim.rs"]
mod claim;
#[path = "mcp_relay_decide_encode.rs"]
mod encode;
use encode::encode;
#[path = "mcp_relay_decide_flow.rs"]
mod flow;
pub(crate) use claim::claim;
use flow::{decide, evaluation_leg};
#[path = "mcp_relay_decide_inline.rs"]
pub(crate) mod inline;
#[path = "mcp_relay_decide_observe.rs"]
mod observe;
#[path = "mcp_relay_decide_package.rs"]
mod package;
pub(crate) use package::parse_intent as parse_package_intent;
#[path = "mcp_relay_decide_package_answer.rs"]
mod package_answer;
#[path = "mcp_relay_decide_package_archive.rs"]
mod package_archive;
#[path = "mcp_relay_decide_package_ask.rs"]
mod package_ask;
#[path = "mcp_relay_decide_review_link.rs"]
mod review_link;
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
// Which package-lane defers send the call's server to the proxy.
#[path = "mcp_relay_decide_package_server.rs"]
mod package_server;
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
#[path = "mcp_relay_decide_resolve.rs"]
mod resolve;
use resolve::resolve;
#[path = "mcp_relay_decide_saved.rs"]
mod saved;
#[path = "mcp_relay_decide_session.rs"]
mod session;
#[path = "mcp_relay_decide_session_config.rs"]
mod session_config;
#[path = "mcp_relay_decide_settle.rs"]
mod settlement;
use settlement::{settle, settle_package};
#[path = "mcp_relay_decide_store.rs"]
pub(crate) mod store;
#[path = "mcp_relay_decide_subject.rs"]
mod subject;
#[path = "mcp_relay_decide_view.rs"]
mod view;

#[cfg(test)]
#[path = "mcp_relay_decide_tests.rs"]
mod tests;
