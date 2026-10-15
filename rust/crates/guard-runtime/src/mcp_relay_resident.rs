//! The native MCP relay's `tools/call` authority: one resident round trip.
//!
//! Each call is sent to the live resident that runs this executable as one
//! `mcp_relay_decide` request, which builds the identity, evaluates the tool
//! policy, routes the call and queues the evidence the proxy would record.
//! A forward's evidence is held under a ticket, and the relay commits it with
//! `mcp_relay_commit` once the child answered, as the proxy records a forward
//! only after the child's response. A forward the relay drops at the catalog
//! boundary, and one whose decision answer never arrived, is never committed.
//! Each forward carries its own ticket, so a nested call never commits or
//! drops the outer call's record. Commits run after the host has the
//! response; a ticket a full drain kept is retried after a later forward.
//! The facts the proxy fixes for a session (the launch fingerprint, the
//! server identity, the workspace the approval hash binds and the launcher
//! paths) are computed once, so no call hashes the executable again.
//!
//! A call the proxy forwards only after claiming its saved approval comes
//! back as a held claim. Once the relay's own drain found the catalog the
//! decision saw still current, it sends that ticket with `mcp_relay_claim`
//! to the same resident, never a rediscovered one, which claims the approval,
//! re-decides the call and answers it as the proxy answers after its claim.
//!
//! The relay answers only what the resident decided. A call it cannot send
//! as the proxy would see it (a shell or package request, a Composio action,
//! arguments whose key order or numbers the decoded map lost), a resident
//! that cannot be reached, and every deferred decision get the proxy's
//! fail-closed "no native decision" response.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::claude_hook_bridge_http::remaining;
use crate::mcp_relay_args::RelayArgs;
use crate::mcp_relay_authority::{
    blocked_response, no_decision_response, tool_name, ClaimTicket, ForwardTicket, RelayAuthority,
    ToolCallVerdict,
};
use crate::mcp_relay_catalog::{CatalogSnapshot, RelayCatalog};
use crate::mcp_relay_launch::Launch;
use crate::mcp_relay_pending::COMMIT_RESULT_SCHEMA;
use crate::resident_state::ResidentState;

const STATE_DIRECTORY: &str = "native-runtime";
const RESULT_SCHEMA: &str = "guard-mcp-relay-decide-result.v1";
const DECIDE_TIMEOUT: Duration = Duration::from_millis(1_000);
const COMMIT_TIMEOUT: Duration = Duration::from_millis(250);
/// The resident rolls a claim back unless it can commit well before this.
const CLAIM_TIMEOUT: Duration = Duration::from_millis(3_000);
const MINIMUM_TIMEOUT: Duration = Duration::from_millis(50);
/// Tickets a full drain kept, retried later; the oldest is dropped beyond it.
const MAX_RETAINED: usize = 16;
/// The session facts every decision request carries.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RelayFacts {
    guard_home: String,
    workspace: Option<String>,
    hash_workspace: String,
    harness: String,
    server_name: String,
    source_scope: String,
    config_path: String,
    transport: String,
    server_id: Option<String>,
    fingerprint: Map<String, Value>,
    server_identity: Value,
    launcher_path: Option<String>,
    /// The proxy's own `PATH`, as set.
    path: Option<String>,
    launcher_home: String,
}

/// The process facts the proxy reads from its own environment.
pub(crate) struct ProcessFacts {
    pub(crate) path: Option<OsString>,
    pub(crate) home: Option<OsString>,
    pub(crate) cwd: Option<PathBuf>,
}

impl ProcessFacts {
    pub(crate) fn current() -> Self {
        Self {
            path: std::env::var_os("PATH"),
            home: std::env::var_os("HOME"),
            cwd: std::env::current_dir().ok(),
        }
    }
}

/// A resident this relay reached, kept for the next call.
struct Resident {
    state: ResidentState,
    token: Vec<u8>,
}

/// The decision authority the relay ships with.
pub(crate) struct ResidentRelayAuthority {
    facts: Option<RelayFacts>,
    resident: Option<Resident>,
    commits: Commits,
    /// Asks the daemon to prepare the lane when a call is deferred.
    kick: Option<Box<dyn crate::mcp_relay_lane::LaneKick>>,
    /// The lane was not ready at startup and the first call has not waited
    /// for it yet.
    warming: bool,
    /// The relayed catalog's report, until the resident records it.
    report: Option<report::CatalogReport>,
}

/// What a commit request did with one ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    Committed,
    /// The record may still be held: a full drain or an unanswered request.
    Retained,
    /// The resident holds no record for the ticket.
    Gone,
}

/// Tickets of answered forwards the relay still has to commit.
#[derive(Debug, Default)]
struct Commits {
    /// Forwards the child answered, committed once the host has the response.
    due: Vec<String>,
    /// Tickets whose record may still be held, oldest first.
    retained: VecDeque<String>,
}

impl Commits {
    fn retain(&mut self, ticket: String) {
        if self.retained.len() >= MAX_RETAINED {
            self.retained.pop_front();
        }
        self.retained.push_back(ticket);
    }

    /// After a forward, commit the retained tickets and then the due ones,
    /// stopping at the first the resident did not take; each ticket is
    /// single-use, so a retry never records a call twice.
    fn settle(&mut self, mut send: impl FnMut(&str) -> Sent) {
        if self.due.is_empty() {
            return;
        }
        let mut work: Vec<String> = self.retained.drain(..).collect();
        work.append(&mut self.due);
        let mut open = true;
        for ticket in work {
            let sent = if open { send(&ticket) } else { Sent::Retained };
            if sent == Sent::Retained {
                open = false;
                self.retain(ticket);
            }
        }
    }
}

impl ResidentRelayAuthority {
    /// Without session facts every call is answered "no native decision".
    pub(crate) fn new(args: &RelayArgs, launch: &Launch, process: &ProcessFacts) -> Self {
        Self {
            facts: relay_facts(args, launch, process),
            resident: None,
            commits: Commits::default(),
            kick: None,
            warming: false,
            report: None,
        }
    }

    /// Queue a completed forward's evidence for the daemon's drain.
    fn commit(&self, ticket: &str) -> Sent {
        let (Some(facts), Some(resident)) = (self.facts.as_ref(), self.resident.as_ref()) else {
            return Sent::Retained;
        };
        let payload = json!({
            "operation": "mcp_relay_commit",
            "request": {"guard_home": facts.guard_home, "ticket": ticket},
        });
        let Ok(payload) = serde_json::to_vec(&payload) else {
            return Sent::Retained;
        };
        // Only the resident that issued the ticket holds its record.
        match send(resident, &payload, Instant::now() + COMMIT_TIMEOUT) {
            Ok(output) => committed(&output),
            Err(_) => Sent::Retained,
        }
    }

    fn exchange(&mut self, guard_home: &Path, payload: &[u8]) -> Option<Vec<u8>> {
        self.exchange_until(guard_home, payload, Instant::now() + DECIDE_TIMEOUT)
    }

    fn exchange_until(
        &mut self,
        guard_home: &Path,
        payload: &[u8],
        deadline: Instant,
    ) -> Option<Vec<u8>> {
        let state_base = guard_home.join(STATE_DIRECTORY);
        let previous = match self.resident.take() {
            Some(resident) => match send(&resident, payload, deadline) {
                Ok(output) => {
                    self.resident = Some(resident);
                    return Some(output);
                }
                Err(retryable) => Some((resident.state, retryable)),
            },
            None => None,
        };
        let fresh = discover(&state_base)?;
        // A resident that may have seen the request is never asked again: a
        // retry goes only to a restarted resident or follows a teardown
        // before authentication.
        if let Some((state, retryable)) = previous {
            let same = state.process_id == fresh.state.process_id
                && state.process_start_marker == fresh.state.process_start_marker;
            if same && !retryable {
                self.resident = Some(fresh);
                return None;
            }
        }
        let output = send(&fresh, payload, deadline).ok()?;
        self.resident = Some(fresh);
        Some(output)
    }
}

impl RelayAuthority for ResidentRelayAuthority {
    fn decide(
        &mut self,
        message: &Value,
        params: &Map<String, Value>,
        order: Option<&[String]>,
        catalog: &RelayCatalog,
    ) -> ToolCallVerdict {
        let id = message.get("id");
        let no_decision = || ToolCallVerdict::Respond(no_decision_response(id, params));
        let Some(facts) = self.facts.as_ref() else {
            defer::note(defer::FACTS_UNAVAILABLE);
            return no_decision();
        };
        let Some((message, payload, expected)) = prepare(facts, message, order, catalog) else {
            defer::note(defer::REQUEST_UNSENDABLE);
            return no_decision();
        };
        let guard_home = PathBuf::from(&facts.guard_home);
        self.warm_up();
        let mut output = self.exchange(&guard_home, &payload);
        if reply_of(output.as_deref()).is_none() && self.rekick(output.as_deref()) {
            output = self.exchange(&guard_home, &payload);
        }
        match output.as_deref().and_then(reply) {
            Some(Reply::Forward { ticket }) => ToolCallVerdict::Forward(ForwardTicket {
                message,
                expected,
                evidence: Some(ticket),
            }),
            Some(Reply::Claim { ticket }) => ToolCallVerdict::Claim(ClaimTicket {
                message,
                expected,
                claim: ticket,
            }),
            Some(Reply::Block { message, data }) => ToolCallVerdict::Respond(blocked_response(
                id,
                &tool_name(params),
                Some(&message),
                Some(data),
            )),
            None => {
                defer::note(&defer::reply_cause(output.as_deref()));
                no_decision()
            }
        }
    }

    fn claim(&mut self, ticket: ClaimTicket) -> ToolCallVerdict {
        let no_decision = ToolCallVerdict::Respond(ticket.no_decision());
        let (Some(facts), Some(resident)) = (self.facts.as_ref(), self.resident.as_ref()) else {
            return no_decision;
        };
        let payload = json!({
            "operation": "mcp_relay_claim",
            "request": {"guard_home": facts.guard_home, "ticket": ticket.claim},
        });
        let Ok(payload) = serde_json::to_vec(&payload) else {
            return no_decision;
        };
        // Only the resident that decided the call holds its claim, and a
        // claim request is never repeated: a lost answer spends nothing twice.
        let answered = send(resident, &payload, Instant::now() + CLAIM_TIMEOUT).ok();
        match answered.as_deref().and_then(reply) {
            Some(Reply::Forward { ticket: evidence }) => ToolCallVerdict::Forward(ForwardTicket {
                message: ticket.message,
                expected: ticket.expected,
                evidence: Some(evidence),
            }),
            Some(Reply::Block { message, data }) => {
                let params = ticket
                    .message
                    .get("params")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                ToolCallVerdict::Respond(blocked_response(
                    ticket.message.get("id"),
                    &tool_name(&params),
                    Some(&message),
                    Some(data),
                ))
            }
            Some(Reply::Claim { .. }) | None => no_decision,
        }
    }

    fn boundary_changed(&mut self, ticket: ForwardTicket) -> Value {
        // The call was never written, so its evidence is never committed.
        let params = ticket
            .message
            .get("params")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        no_decision_response(ticket.message.get("id"), &params)
    }

    fn complete(&mut self, ticket: ForwardTicket, response: Value) -> Value {
        self.commits.due.extend(ticket.evidence);
        response
    }

    fn settle(&mut self) {
        let mut commits = std::mem::take(&mut self.commits);
        commits.settle(|ticket| self.commit(ticket));
        self.commits = commits;
        self.poll_report();
    }

    fn catalog_complete(&mut self, tools: &[Value]) {
        self.report_server(tools);
    }
}

/// The frame the child would read and the decide request built from it, or
/// `None` when the call is not sent. The proxy writes the child
/// `json.dumps(json.loads(frame))`, so the request, its evidence and the
/// forwarded frame all come from that one rewrite. An id the rewrite would
/// change is not sent: the host correlates the answer by the id it sent.
fn prepare(
    facts: &RelayFacts,
    message: &Value,
    order: Option<&[String]>,
    catalog: &RelayCatalog,
) -> Option<(Value, Vec<u8>, CatalogSnapshot)> {
    let frame = python_canonical(message).filter(|frame| frame.get("id") == message.get("id"))?;
    let call = frame.get("params")?.as_object()?;
    let (payload, expected) = decide_request(facts, call, order, catalog)?;
    Some((frame, payload, expected))
}

/// How the resident answered one commit.
fn committed(output: &[u8]) -> Sent {
    let Ok(result) = serde_json::from_slice::<Value>(output) else {
        return Sent::Retained;
    };
    if result.get("schema").and_then(Value::as_str) != Some(COMMIT_RESULT_SCHEMA) {
        return Sent::Retained;
    }
    let flag = |name: &str| result.get(name).and_then(Value::as_bool);
    match (flag("committed"), flag("retained")) {
        (Some(true), _) => Sent::Committed,
        (Some(false), Some(false)) => Sent::Gone,
        _ => Sent::Retained,
    }
}

/// What the resident decided.
#[derive(Debug, Clone, PartialEq)]
enum Reply {
    Forward { ticket: String },
    Claim { ticket: String },
    Block { message: String, data: Value },
}

fn reply_of(output: Option<&[u8]>) -> Option<Reply> {
    output.and_then(reply)
}

fn reply(output: &[u8]) -> Option<Reply> {
    let result: Value = serde_json::from_slice(output).ok()?;
    if result.get("schema")?.as_str()? != RESULT_SCHEMA {
        return None;
    }
    let ticket = || {
        result
            .get("ticket")?
            .as_str()
            .filter(|ticket| !ticket.is_empty())
            .map(str::to_owned)
    };
    match result.get("outcome")?.as_str()? {
        "forward" => Some(Reply::Forward { ticket: ticket()? }),
        "claim" => Some(Reply::Claim { ticket: ticket()? }),
        "block" => Some(Reply::Block {
            message: result.get("message")?.as_str()?.to_owned(),
            data: result.get("data").filter(|data| data.is_object())?.clone(),
        }),
        _ => None,
    }
}

/// The first live resident of this executable, with its token.
fn discover(state_base: &Path) -> Option<Resident> {
    // Discovery checks the directory's privacy; it must already exist.
    if !std::fs::symlink_metadata(state_base).is_ok_and(|metadata| metadata.is_dir()) {
        return None;
    }
    let states = crate::resident_state::discover_same_executable_states(state_base).ok()?;
    states.into_iter().find_map(|(_scope, _digest, state)| {
        crate::resident_state::validate_same_executable_process_identity(
            state.process_id,
            &state.process_start_marker,
        )
        .ok()?;
        let token = crate::resident_state::token_from_state(&state).ok()?;
        Some(Resident { state, token })
    })
}

/// Send once; `Err(true)` when the connection was torn down before the
/// resident could read the request.
fn send(resident: &Resident, payload: &[u8], deadline: Instant) -> Result<Vec<u8>, bool> {
    let timeout = remaining(deadline);
    if timeout < MINIMUM_TIMEOUT {
        return Err(false);
    }
    let identity = crate::resident_client::ExpectedProcessIdentity {
        process_id: resident.state.process_id,
        start_marker: &resident.state.process_start_marker,
        digest: None,
    };
    crate::resident_client::send_request_for_digest_detailed(
        &resident.state.transport,
        &resident.state.endpoint,
        &resident.token,
        payload,
        timeout,
        &identity,
    )
    .map_err(|error| error.retryable_teardown)
}

#[path = "mcp_relay_resident_defer.rs"]
mod defer;
#[path = "mcp_relay_resident_lane.rs"]
mod lane;
#[path = "mcp_relay_python_wire.rs"]
mod python_wire;
#[path = "mcp_relay_resident_report.rs"]
mod report;
#[path = "mcp_relay_resident_request.rs"]
mod request;
use python_wire::python_canonical;
use request::{decide_request, relay_facts};

#[cfg(test)]
#[path = "mcp_relay_resident_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "mcp_relay_resident_wire_tests.rs"]
mod wire_tests;
