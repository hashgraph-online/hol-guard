//! The native MCP relay state machine.
//!
//! Port of the transport in `RuntimeMcpGuardProxy.serve`: host requests are
//! forwarded to the child and correlated by id; child notifications go to the
//! host; child (reverse) requests are proxied to the host while their answers,
//! notifications and further host requests are serviced; out-of-order
//! responses are buffered per id on both sides. `tools/list` traffic feeds the
//! catalog mirror, and every `tools/call` goes to the `RelayAuthority` after
//! the child stream is drained. A forwarded call is written only after a
//! pre-write quiet edge with the catalog it was decided against unchanged.
//! A listing that makes the catalog whole is reported to the authority once
//! the host has its response, as the proxy's `_report_relay_server` does.

use std::time::Duration;

use guard_command::mcp_stdio_session::{is_request, response_key, ResponseBuffers};
use serde_json::{json, Map, Value};

use crate::mcp_relay_authority::{
    no_decision_response, sync_failed_response, ClaimTicket, RelayAuthority, ToolCallVerdict,
};
use crate::mcp_relay_catalog::{cursor_fact, CatalogSnapshot, RelayCatalog};
use crate::mcp_relay_host::{HostLink, HostRead};

/// `_TOOLS_CALL_PREWRITE_QUIET_SECONDS`.
pub(crate) const PREWRITE_QUIET: Duration = Duration::from_millis(5);
/// Ceiling on child-response and nested client-response waits.
const MAX_RESPONSE_TIMEOUT_SECONDS: u64 = 30;
/// Reverse requests nested deeper than this are refused instead of proxied.
const MAX_NESTING: usize = 32;
const TIMEOUT_CODE: i64 = -32800;
const NESTING_CODE: i64 = -32603;
const RESERVED_ID_CODE: i64 = -32600;
const CHILD_TIMEOUT: &str = "Guard runtime MCP proxy timed out waiting for the MCP server.";
const CLIENT_TIMEOUT: &str = "Guard runtime MCP proxy timed out waiting for the client response.";
const NESTING_REFUSED: &str =
    "Guard runtime MCP proxy refused a reverse request nested too deeply.";
const RESERVED_ID_REFUSED: &str =
    "Guard runtime MCP proxy refused a reverse request naming one of its own prompts.";
const CHILD_EOF: &str = "Guard stdio proxy did not receive a response from the MCP server.";
const HOST_LOST: &str =
    "Guard runtime MCP proxy lost the client while waiting for a server response.";
const LIST_CHANGED: [&str; 2] = ["notifications/tools/list_changed", "tools/list_changed"];

/// The child's output stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChildEof;

/// Outcome of a pre-write quiet edge.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Quiet {
    Silent,
    Frame(Value),
    Busy,
}

/// The relay's view of the MCP server child.
pub(crate) trait ChildLink {
    fn send(&mut self, message: &Value) -> Result<(), String>;
    /// Next child frame within `timeout`; `Ok(None)` on timeout.
    fn next(&mut self, timeout: Duration) -> Result<Option<Value>, ChildEof>;
    fn next_quiet(&mut self, quiet: Duration) -> Result<Quiet, ChildEof>;
    /// Stop a child that missed its response deadline.
    fn quarantine(&mut self);
}

/// Why `serve` returned normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayExit {
    /// The host closed its stream.
    HostClosed,
    /// A response timed out and the child was quarantined.
    TimedOut,
}

/// `_child_response_timeout_seconds` from `approval_wait_timeout_seconds`.
pub(crate) fn child_response_timeout(configured_seconds: i64) -> Duration {
    let seconds = u64::try_from(configured_seconds)
        .ok()
        .filter(|seconds| *seconds > 0)
        .map_or(MAX_RESPONSE_TIMEOUT_SECONDS, |seconds| {
            seconds.min(MAX_RESPONSE_TIMEOUT_SECONDS)
        });
    Duration::from_secs(seconds)
}

/// `_timeout_response`.
pub(crate) fn timeout_response(
    id: Option<&Value>,
    source: &str,
    timeout: Duration,
    message: &str,
) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": {
            "code": TIMEOUT_CODE,
            "message": message,
            "data": {
                "guard_timeout": true,
                "source": source,
                "timeout_seconds": timeout.as_secs_f64(),
            },
        },
    })
}

/// `_is_timeout_response`.
pub(crate) fn is_timeout_response(response: &Value) -> bool {
    let Some(error) = response.get("error") else {
        return false;
    };
    error.get("code").and_then(Value::as_i64) == Some(TIMEOUT_CODE)
        && error
            .get("data")
            .and_then(|data| data.get("guard_timeout"))
            .and_then(Value::as_bool)
            == Some(true)
}

/// A present, non-null id (`message.get("id")` is not `None`).
fn live_id(id: Option<&Value>) -> Option<&Value> {
    id.filter(|id| !id.is_null())
}

/// `payload.get("id") == request_id`, comparing canonical JSON.
fn same_id(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (live_id(left), live_id(right)) {
        (None, None) => true,
        (Some(left), Some(right)) => response_key(Some(left)) == response_key(Some(right)),
        _ => false,
    }
}

fn method(message: &Value) -> Option<&str> {
    message.get("method").and_then(Value::as_str)
}

fn is_list_changed(message: &Value) -> bool {
    method(message).is_some_and(|name| LIST_CHANGED.contains(&name))
}

enum Guarded {
    Response(Value),
    BoundaryChanged,
}

/// The relay: one host, one child, one decision authority.
pub(crate) struct Relay<C, H, A> {
    child: C,
    host: H,
    authority: A,
    catalog: RelayCatalog,
    child_responses: ResponseBuffers,
    client_responses: ResponseBuffers,
    timeout: Duration,
    /// How long one inline approval prompt waits for the client's answer.
    inline_timeout: Duration,
    /// `_inline_prompt_counter`, which names the prompts of this session.
    prompts: u64,
    depth: usize,
    /// A listing was captured since the catalog was last reported.
    report_due: bool,
    /// The fingerprint of the catalog last handed to the authority, which
    /// owns its delivery and retries it until the resident records it.
    reported: Option<String>,
}

impl<C: ChildLink, H: HostLink, A: RelayAuthority> Relay<C, H, A> {
    pub(crate) fn new(
        child: C,
        host: H,
        authority: A,
        timeout: Duration,
        inline_timeout: Duration,
    ) -> Self {
        Self {
            child,
            host,
            authority,
            catalog: RelayCatalog::default(),
            child_responses: ResponseBuffers::default(),
            client_responses: ResponseBuffers::default(),
            timeout,
            inline_timeout,
            prompts: 0,
            depth: 0,
            report_due: false,
            reported: None,
        }
    }

    pub(crate) fn into_child(self) -> C {
        self.child
    }

    /// `serve`: relay until the host closes or a response times out. An
    /// `Err` is a fatal transport failure; the caller stops the child.
    pub(crate) fn serve(&mut self) -> Result<RelayExit, String> {
        loop {
            let (message, order) = match self.host.next(None) {
                HostRead::Message(message, order) => (message, order),
                HostRead::Eof => return Ok(RelayExit::HostClosed),
                HostRead::Timeout => continue,
                HostRead::Invalid(reason) => return Err(reason.to_owned()),
            };
            if let Some(response) = self.handle(message, order.as_deref())? {
                let sent = self.host.send(&response);
                self.authority.settle();
                sent?;
                self.report_catalog();
                if is_timeout_response(&response) {
                    return Ok(RelayExit::TimedOut);
                }
            }
        }
    }

    /// `_handle_message_serialized`.
    fn handle(
        &mut self,
        message: Value,
        order: Option<&[String]>,
    ) -> Result<Option<Value>, String> {
        if is_list_changed(&message) {
            self.catalog.invalidate();
        }
        if !is_request(&message) {
            // Notifications and client responses go to the child verbatim.
            self.child.send(&message)?;
            return Ok(None);
        }
        let empty = Value::Object(Map::new());
        let params = message.get("params").unwrap_or(&empty);
        let call_params = match (method(&message), params) {
            (Some("tools/call"), Value::Object(params)) => Some(params.clone()),
            _ => None,
        };
        let Some(params) = call_params else {
            if method(&message) == Some("initialize") {
                // `_record_client_capabilities`, which reads the client's
                // `elicitation` capability before the session carries traffic.
                self.authority.client_capabilities(message.get("params"));
            }
            return self.forward_request(&message).map(Some);
        };
        let mut asked = false;
        loop {
            // A resumed call drained before it took the prompt's answer, so
            // draining again here would hand the answer to a nested call.
            if !asked && self.drain(Duration::ZERO).is_err() {
                self.catalog.poison();
                return Ok(Some(sync_failed_response(message.get("id"), &params)));
            }
            let verdict = match self
                .authority
                .decide(&message, &params, order, &self.catalog)
            {
                ToolCallVerdict::Claim(ticket) => self.claim(ticket),
                verdict => verdict,
            };
            return match verdict {
                ToolCallVerdict::Respond(response) => Ok(Some(response)),
                ToolCallVerdict::Forward(ticket) => match self
                    .forward_guarded(&ticket.message, &ticket.expected)?
                {
                    Guarded::Response(response) => {
                        Ok(Some(self.authority.complete(ticket, response)))
                    }
                    Guarded::BoundaryChanged => Ok(Some(self.authority.boundary_changed(ticket))),
                },
                // A claim answers with a respond or a forward, never a claim.
                ToolCallVerdict::Claim(ticket) => Ok(Some(ticket.no_decision())),
                // One prompt per call: the answer is a fact of this call, and
                // an authority that asks for a second one decided nothing.
                ToolCallVerdict::Elicit(_) if asked => {
                    Ok(Some(no_decision_response(message.get("id"), &params)))
                }
                ToolCallVerdict::Elicit(ask) => {
                    asked = true;
                    let answer = self.elicit(ask)?;
                    // The drain the next decide opens runs before the answer
                    // is handed over, so no call it services takes this one.
                    if self.drain(Duration::ZERO).is_err() {
                        self.catalog.poison();
                        return Ok(Some(sync_failed_response(message.get("id"), &params)));
                    }
                    self.authority.elicited(answer.as_ref());
                    continue;
                }
            };
        }
    }

    /// `_allow_and_forward` before its claim: drain the child stream and
    /// claim only while the catalog the decision saw is still current. A
    /// claim the relay never asks for expires unspent in the authority.
    fn claim(&mut self, ticket: ClaimTicket) -> ToolCallVerdict {
        if self.drain(Duration::ZERO).is_err() {
            self.catalog.poison();
            return ToolCallVerdict::Respond(ticket.no_decision());
        }
        if !self.catalog.matches(&ticket.expected) {
            return ToolCallVerdict::Respond(ticket.no_decision());
        }
        self.authority.claim(ticket)
    }

    /// `_report_relay_server`: hand a newly whole catalog to the authority.
    /// Each catalog is handed over once; the authority sends it off the
    /// relay loop and sends it again from `settle` until it is recorded.
    fn report_catalog(&mut self) {
        if !std::mem::take(&mut self.report_due) {
            return;
        }
        let Some(tools) = self.catalog.complete_tools() else {
            return;
        };
        let fingerprint = self.catalog.snapshot().fingerprint;
        if fingerprint.is_none() || fingerprint == self.reported {
            return;
        }
        self.reported = fingerprint;
        self.authority.catalog_complete(&tools);
    }

    /// A non-`tools/call` request; `tools/list` also drives the catalog.
    fn forward_request(&mut self, message: &Value) -> Result<Value, String> {
        let listing = (method(message) == Some("tools/list")).then(|| {
            let cursor = cursor_fact(message.get("params"));
            let generation = self.catalog.begin(cursor.clone());
            (cursor, generation)
        });
        let response = self
            .child
            .send(message)
            .and_then(|()| self.await_response(message.get("id")));
        match (response, listing) {
            (Ok(response), Some((cursor, generation))) => {
                self.catalog.capture(cursor, generation, &response);
                self.report_due = true;
                Ok(response)
            }
            (Err(error), Some((_, generation))) => {
                self.catalog.fail(generation);
                Err(error)
            }
            (response, None) => response,
        }
    }

    /// Write a decided call only after a quiet edge with the catalog intact.
    fn forward_guarded(
        &mut self,
        message: &Value,
        expected: &CatalogSnapshot,
    ) -> Result<Guarded, String> {
        loop {
            if !self.catalog.matches(expected) {
                return Ok(Guarded::BoundaryChanged);
            }
            match self.child.next_quiet(PREWRITE_QUIET) {
                Ok(Quiet::Silent) => break,
                Ok(Quiet::Frame(frame)) => self.multiplex(frame)?,
                Ok(Quiet::Busy) => return Ok(Guarded::BoundaryChanged),
                Err(ChildEof) => return Err(CHILD_EOF.to_owned()),
            }
        }
        self.child.send(message)?;
        self.await_response(message.get("id"))
            .map(Guarded::Response)
    }

    /// Multiplex every queued child frame until `quiet` passes in silence.
    fn drain(&mut self, quiet: Duration) -> Result<(), String> {
        while let Some(frame) = self.child.next(quiet).map_err(|_| CHILD_EOF.to_owned())? {
            self.multiplex(frame)?;
        }
        Ok(())
    }

    /// The `_forward_message` response loop.
    fn await_response(&mut self, id: Option<&Value>) -> Result<Value, String> {
        loop {
            if let Some(response) = live_id(id).and_then(|id| self.child_responses.pop(id)) {
                return Ok(response);
            }
            match self.child.next(self.timeout) {
                Ok(Some(frame)) if same_id(frame.get("id"), id) && !is_request(&frame) => {
                    return Ok(frame);
                }
                Ok(Some(frame)) => self.multiplex(frame)?,
                Ok(None) => {
                    self.child.quarantine();
                    return Ok(timeout_response(
                        id,
                        "child_response",
                        self.timeout,
                        CHILD_TIMEOUT,
                    ));
                }
                Err(ChildEof) => return Err(CHILD_EOF.to_owned()),
            }
        }
    }

    /// `_multiplex_child_payload`.
    fn multiplex(&mut self, frame: Value) -> Result<(), String> {
        if is_list_changed(&frame) {
            self.catalog.invalidate();
        }
        if is_request(&frame) {
            return self.proxy_child_request(frame);
        }
        if frame.get("id").is_some() {
            if live_id(frame.get("id")).is_some() {
                self.child_responses.buffer(frame);
            }
            return Ok(());
        }
        self.host.send(&frame)
    }
}

#[path = "mcp_relay_core_prompt.rs"]
mod prompt;

#[path = "mcp_relay_core_reverse.rs"]
mod reverse;

pub(crate) use prompt::inline_approval_timeout;

#[cfg(test)]
#[path = "mcp_relay_core_tests.rs"]
mod tests;
