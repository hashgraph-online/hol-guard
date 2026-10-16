//! The approval-center block the queue route takes under
//! `blocked_request_mode = "ask"`.
//!
//! `_queue_approval_center_response` answers the queue route by the bound
//! blocked-request mode. Under `ask` the proxy writes the call's approval
//! request, raises the desktop notice and the approval center, and blocks the
//! call on that request; the agent is told which request to approve and that
//! retrying the same action is what resumes it. This ports that branch for
//! every relay harness, so the resident answers such a call without the
//! Python proxy in the byte path.
//!
//! `_allow_after_native_prompt` is the one fact the route still needs under
//! `ask`, and every relay harness answers it from the decision alone: the
//! opencode proxy with `decision.source != "policy"`, and every other one
//! with its base class's `False`, which routes the call to the client's
//! inline elicitation (`mcp_relay_decide_inline.rs`) and reaches this queue
//! only once that prompt falls through or the client offers none.
//!
//! The row is written before the block is answered, through the daemon's own
//! `queue_blocked_approvals` store operation under the shared storage gate,
//! and read back through `get_approval_request` with the cwd a queued row is
//! derived against. The call's `temporary_mcp_approval` hint, which Python
//! attaches to every queue read, is attached here for the same reason: a
//! browser MCP call whose approval carried no bounded-grant hint would lose
//! the 15m/1h/5h choices in the approval center. The read's other hint,
//! `local_tool_approval`, reads a trusted-local-tool scanner evidence entry,
//! which a tool call's evidence never holds.
//!
//! What the resident cannot reproduce defers, and a defer blocks the call, so
//! each one costs the user a stopped tool call:
//!
//! - a binding with no approval-center origin, no review OAuth source or no
//!   bound receipt redaction level, which the daemon publishes together;
//! - a decision whose signals, projected risk summary or launch target are
//!   empty, since the queued row would then fall back to the artifact's own
//!   risk facts, which the Python proxy derives and the relay does not carry.
//!
//! The link the block names is the row's own, read through
//! `first_approval_url`: once the row is written the call is answered with it,
//! never deferred over it.
//!
//! The row itself — the evaluation item, the queue arguments and the
//! bounded-grant hint — is shaped by `mcp_relay_decide_ask_row`.
//!
//! One gap is accepted rather than deferred: the row is written before the
//! block's evidence is offered, so an evidence buffer that is full after the
//! write leaves a queued request the agent never hears about. The user still
//! sees it in the approval center, and the call is blocked either way.

use std::path::Path;

use guard_contracts::{
    GuardStoreRequestV1, McpToolCallArtifactV1, McpToolFactsV1, GUARD_STORE_REQUEST_SCHEMA,
};
use serde_json::{json, Map, Value};

use super::ask_row::{args, nonempty, project, review_item, temporary_mcp_approval};
use super::{Admitted, McpRelayDecideRequestV1, Resolved, Routed};
use crate::hook_direct::saved_decision::consume::{repair_store_permissions, storage_gate};
use crate::local_mcp_grant_identity::composio_requires_action_review;
use crate::local_store_read::STORE_FILE_NAME;

/// The decision source `_queue_approval_center_response` records for a call
/// it blocks on a queued approval request.
pub(super) const APPROVAL_PENDING_SOURCE: &str = "approval-center-pending";
/// The one relay harness whose `_allow_after_native_prompt` reads the
/// decision; every other one answers `False` from its base class.
pub(super) const OPENCODE: &str = "opencode";
/// The busy timeout the daemon's own store calls take.
const BUSY_TIMEOUT_MS: u64 = 250;
/// The actions `_needs_review` queues; any other item is dropped unwritten.
const REVIEWABLE: [&str; 2] = ["review", "require-reapproval"];

/// The hosts `canonical_local_approval_url` treats as this machine.
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "::1", "localhost"];

const ASK_UNSUPPORTED: &str = "mcp_relay_ask_unsupported";
const ASK_QUEUE_FAILED: &str = "mcp_relay_ask_queue_failed";
const REMEMBER_UNSUPPORTED: &str = "mcp_relay_remember_unsupported";

/// `_allow_after_native_prompt` for a relay harness, read off the decision the
/// route names: the gated one, with the route's own observe-mode override on
/// top, exactly as the proxy's need loop answers it.
///
/// `OpenCodeMcpGuardProxy` reads the decision's source; the base class every
/// other relay harness uses answers `False`, which routes the call on to the
/// client's inline elicitation.
pub(super) fn native_prompt_allows(harness: &str, tool: &McpToolFactsV1) -> bool {
    harness == OPENCODE && tool.source != "policy"
}

/// Whether the allow a remembered inline approval saves would be refused, in
/// which case the proxy queues a re-approval request instead of forwarding.
///
/// `upsert_policy` writes an artifact-scoped `allow`, which the approval gate
/// holds to a decision whenever it is enabled, and the relay carries no
/// grant. The resident asks the gate before it forwards, because the drain
/// performs the write after the child already answered the call.
pub(super) fn remembered_write_refused(
    guard_home: &str,
    artifact: &McpToolCallArtifactV1,
) -> Result<bool, &'static str> {
    // `allow_tool_call` refuses to remember a provider action whose every call
    // is reviewed and raises where the proxy has no answer for it. The route
    // reads the tool name for this, and the write reads the server's command,
    // so a command the route did not see leaves the call to the proxy.
    if composio_requires_action_review(artifact.command.as_deref().unwrap_or_default()) {
        return Err(REMEMBER_UNSUPPORTED);
    }
    Ok(crate::approval_gate_consumers::require_policy_write(
        Path::new(guard_home),
        crate::approval_gate_op::grants(),
        "allow",
        "artifact",
        None,
        None,
    )
    .is_err())
}

/// Write this call's approval request and block on it, as the `ask` branch of
/// `_queue_approval_center_response` does.
pub(super) fn queue(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    resolved: &Resolved,
    policy_action: String,
) -> Result<Routed, &'static str> {
    prepare(request, admitted, resolved, policy_action, &[])?.write(request)
}

/// An approval request every check has passed, ready to be written.
pub(super) struct Prepared {
    policy_action: String,
    center: String,
    oauth_source: String,
    workspace: String,
    args: Map<String, Value>,
}

/// Everything `queue` checks and derives before it writes, so a caller that
/// must defer before it commits anything can do so. `evidence_append` follows
/// the decision's own scanner evidence in the queued row, as the proxy's
/// post-claim evidence does.
pub(super) fn prepare(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    resolved: &Resolved,
    policy_action: String,
    evidence_append: &[Value],
) -> Result<Prepared, &'static str> {
    if !REVIEWABLE.contains(&policy_action.as_str()) {
        return Err(ASK_UNSUPPORTED);
    }
    let review = &admitted.binding.review;
    let (Some(center), Some(oauth_source), Some(redaction_level)) = (
        review.approval_center_origin.as_deref(),
        review.review_oauth_source.as_deref(),
        resolved.redaction_level.as_deref(),
    ) else {
        return Err(ASK_UNSUPPORTED);
    };
    let artifact = &resolved.identity.artifact;
    let artifact_hash = resolved
        .identity
        .artifact_hash
        .as_deref()
        .ok_or(ASK_UNSUPPORTED)?;
    let signals = &resolved.decision.signals;
    if !signals.iter().any(|signal| !signal.is_empty()) {
        return Err(ASK_UNSUPPORTED);
    }
    let projection = project(request, artifact)?;
    let mut item = review_item(
        artifact,
        artifact_hash,
        signals,
        &projection,
        &policy_action,
        &resolved.decision,
    );
    append_scanner_evidence(&mut item, evidence_append);
    let now = now_isoformat().ok_or(ASK_QUEUE_FAILED)?;
    Ok(Prepared {
        args: args(request, item, artifact, center, &now, redaction_level),
        policy_action,
        center: center.to_owned(),
        oauth_source: oauth_source.to_owned(),
        workspace: admitted.workspace.clone(),
    })
}

/// `(*_tool_decision_scanner_evidence(decision), *evidence_append)`: the
/// row's evidence, still left out when both are empty.
fn append_scanner_evidence(item: &mut Map<String, Value>, evidence_append: &[Value]) {
    if evidence_append.is_empty() {
        return;
    }
    let evidence = item
        .entry("scanner_evidence")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(evidence) = evidence {
        evidence.extend_from_slice(evidence_append);
    }
}

impl Prepared {
    /// Write the request, read it back and block the call on it.
    pub(super) fn write(self, request: &McpRelayDecideRequestV1) -> Result<Routed, &'static str> {
        let Self {
            policy_action,
            center,
            oauth_source,
            workspace,
            args,
        } = self;
        let (request_id, notice) = write(request, &oauth_source, args)?;
        let row = read_back(request, &request_id)?;
        let review_url = review_url(&row, &center, &request_id);
        let message = format!(
            "HOL Guard stopped tool call {} from {}. Approve request {request_id} at \
             {review_url}, then retry the same action.",
            request.build.tool_name, request.build.server_name
        );
        let data = json!({
            "approvalCenterUrl": center,
            "approvalRequests": [Value::Object(row)],
            "guardPolicyAction": policy_action,
            "reviewUrl": review_url,
        });
        Ok(Routed::Asked {
            policy_action,
            message,
            data,
            // What `_notify_pending_approval` and `_maybe_open_approval_center`
            // raise once the row is written, which the drain owns.
            approval: json!({
                "approval_center_url": center,
                "review_url": review_url,
                "request_id": request_id,
                "workspace": workspace,
                "notices": [notice],
            }),
        })
    }
}

/// `first_approval_url(...) or approval_center_url`: the written row's own
/// link, rewritten when it names a stale loopback center, and this center's
/// deep link for the row's request when the row carries no link at all.
fn review_url(row: &Map<String, Value>, center: &str, request_id: &str) -> String {
    if let Some(approval_url) = nonempty(row.get("approval_url")) {
        return canonical_local_approval_url(&approval_url, center);
    }
    let request_id = nonempty(row.get("request_id")).unwrap_or_else(|| request_id.to_owned());
    let center = center.trim();
    if center.is_empty() || request_id.is_empty() {
        return center.to_owned();
    }
    format!("{}/requests/{request_id}", center.trim_end_matches('/'))
}

/// `canonical_local_approval_url`: a link this machine serves is rewritten to
/// the active center's scheme and host, and every other link is left alone.
fn canonical_local_approval_url(approval_url: &str, center: &str) -> String {
    let approval_url = approval_url.trim();
    let (Some((scheme, netloc, rest)), Some((center_scheme, center_netloc, _))) =
        (split_url(approval_url), split_url(center.trim()))
    else {
        return approval_url.to_owned();
    };
    if !loopback(scheme, netloc) || !loopback(center_scheme, center_netloc) {
        return approval_url.to_owned();
    }
    format!(
        "{}://{center_netloc}{rest}",
        center_scheme.to_ascii_lowercase()
    )
}

/// `urlparse` as far as the rewrite reads it: scheme, netloc and the rest of
/// the link, which `urlunparse` puts back unchanged.
fn split_url(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, authority) = url.split_once("://")?;
    let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    Some((scheme, &authority[..end], &authority[end..]))
}

/// An `http`/`https` link this machine serves.
fn loopback(scheme: &str, netloc: &str) -> bool {
    (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
        && LOOPBACK_HOSTS.contains(&url_host(netloc))
}

/// `_parsed_url_host`: the netloc without its userinfo or port.
fn url_host(netloc: &str) -> &str {
    let host_port = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    if let Some(bracketed) = host_port.strip_prefix('[') {
        return bracketed
            .split_once(']')
            .map_or(bracketed, |(host, _)| host);
    }
    if host_port.matches(':').count() == 1 {
        return host_port
            .rsplit_once(':')
            .map_or(host_port, |(host, _)| host);
    }
    host_port
}

/// Write the request through the daemon's own store operation, under the
/// storage gate every writer of this store holds.
fn write(
    request: &McpRelayDecideRequestV1,
    oauth_source: &str,
    args: Map<String, Value>,
) -> Result<(String, Value), &'static str> {
    let guard_home = Path::new(&request.guard_home);
    let _gate = storage_gate(guard_home).map_err(|_| ASK_QUEUE_FAILED)?;
    let written = store(
        request,
        "mcp-relay-ask-queue",
        "queue_blocked_approvals",
        oauth_source,
        args,
    );
    repair_store_permissions(guard_home);
    let written = written?;
    // Python raises what the queue loop stopped on after naming what it had
    // already written; a relayed call has no later step to raise into, so an
    // error defers whether or not a row was written.
    if !written["error"].is_null() {
        return Err(ASK_QUEUE_FAILED);
    }
    let entry = written["queued"]
        .as_array()
        .and_then(|queued| queued.first())
        .ok_or(ASK_QUEUE_FAILED)?;
    let request_id = entry["request_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or(ASK_QUEUE_FAILED)?
        .to_owned();
    Ok((request_id, entry["notice"].clone()))
}

/// `store.get_approval_request(request_id)`, with the queue hints Python
/// attaches to every approval read.
fn read_back(
    request: &McpRelayDecideRequestV1,
    request_id: &str,
) -> Result<Map<String, Value>, &'static str> {
    let mut args = Map::new();
    args.insert("request_id".to_owned(), json!(request_id));
    args.insert("derive_scope".to_owned(), json!(true));
    args.insert("cwd".to_owned(), json!(request.cwd));
    // `RuntimeError("Persisted approval request not found")`: the row was
    // written, so a read that cannot find it leaves a store the resident
    // cannot reason about.
    let Value::Object(mut row) = store(
        request,
        "mcp-relay-ask-read",
        "get_approval_request",
        "mcp-relay",
        args,
    )?
    else {
        return Err(ASK_QUEUE_FAILED);
    };
    if let Some(hint) = temporary_mcp_approval(&row) {
        row.insert("temporary_mcp_approval".to_owned(), hint);
    }
    Ok(row)
}

/// One store call against this home's `guard.db`.
fn store(
    request: &McpRelayDecideRequestV1,
    request_id: &str,
    method: &str,
    source: &str,
    args: Map<String, Value>,
) -> Result<Value, &'static str> {
    crate::guard_store_op::evaluate(&GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: request_id.to_owned(),
        store_path: Path::new(&request.guard_home)
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: request.guard_home.clone(),
        method: method.to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: BUSY_TIMEOUT_MS,
        args,
    })
    .map(|(payload, _)| payload)
    .map_err(|_| ASK_QUEUE_FAILED)
}

/// `_now()`: `datetime.now(timezone.utc).isoformat()`, which leaves the
/// fraction out at exactly zero microseconds.
fn now_isoformat() -> Option<String> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    crate::policy_bundle_time::micros_to_utc_isoformat(i64::try_from(micros).ok()?, "+00:00")
}

#[cfg(test)]
#[path = "mcp_relay_decide_ask_tests.rs"]
mod tests;
