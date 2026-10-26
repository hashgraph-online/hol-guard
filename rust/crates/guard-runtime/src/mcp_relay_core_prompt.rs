//! The inline approval prompt the relay raises on the host.
//!
//! Port of `_inline_approval_request` and `_request_inline_approval`
//! (`runtime_mcp.py`): the prompt goes out under an id this session counts,
//! and the wait services the client's notifications, responses and requests
//! until the answer lands, exactly as the proxy's own prompt loop does.

use std::time::Duration;

use guard_command::mcp_stdio_session::{is_notification, is_request};
use serde_json::{json, Value};

use super::{live_id, same_id, ChildLink, Relay, RelayAuthority, MAX_NESTING};
use crate::mcp_relay_host::{HostLink, HostRead};

/// `_inline_approval_timeout_seconds` without a configured wait, which the
/// proxy leaves uncapped: a person is reading the prompt.
const DEFAULT_INLINE_TIMEOUT_SECONDS: u64 = 120;

/// The ids the relay keeps for its own prompts (`_inline_prompt_counter`).
const ID_PREFIX: &str = "guard-elicitation-";

/// `_inline_approval_timeout_seconds` from `approval_wait_timeout_seconds`.
/// The proxy caps no inline prompt, so neither does the relay.
pub(crate) fn inline_approval_timeout(configured_seconds: i64) -> Duration {
    let seconds = u64::try_from(configured_seconds)
        .ok()
        .filter(|seconds| *seconds > 0)
        .unwrap_or(DEFAULT_INLINE_TIMEOUT_SECONDS);
    Duration::from_secs(seconds)
}

/// Whether `id` names one of the relay's own prompts. A reverse request from
/// the child under such an id is refused instead of proxied: the client would
/// otherwise hold two live requests under one id, and each wait would take
/// whichever answer arrived first, handing the prompt's answer to the child.
pub(super) fn reserved_id(id: Option<&Value>) -> bool {
    id.and_then(Value::as_str)
        .is_some_and(|id| id.starts_with(ID_PREFIX))
}

impl<C: ChildLink, H: HostLink, A: RelayAuthority> Relay<C, H, A> {
    /// `_inline_approval_request` and `_request_inline_approval`: raise the
    /// prompt on the host under an id this session counts, and wait for the
    /// client's answer. `Ok(None)` is a prompt the client never answered.
    pub(super) fn elicit(&mut self, params: Value) -> Result<Option<Value>, String> {
        if self.depth >= MAX_NESTING {
            // The wait below services the client's requests, each of which may
            // raise a prompt of its own. At the nesting ceiling the relay
            // raises none: an unanswered prompt is the fail-closed answer, and
            // the stack stays bounded however many calls the client stacks up.
            return Ok(None);
        }
        self.prompts += 1;
        let id = Value::String(format!("{ID_PREFIX}{}", self.prompts));
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "elicitation/create",
            "params": params,
        });
        self.host.send(&request)?;
        self.depth += 1;
        let answer = self.await_prompt_response(&id);
        self.depth -= 1;
        answer
    }

    /// The inline prompt's response loop, which services the client's other
    /// traffic as `_request_inline_approval` does. A timeout and a client
    /// that closed its stream are both answers the proxy makes up itself.
    fn await_prompt_response(&mut self, id: &Value) -> Result<Option<Value>, String> {
        let id = Some(id);
        loop {
            if let Some(response) = live_id(id).and_then(|id| self.client_responses.pop(id)) {
                return Ok(Some(response));
            }
            // The wait is per read, not a deadline over the whole prompt: the
            // proxy recomputes `_inline_approval_timeout_seconds` on every
            // pass of this loop, and each pass only runs because the client is
            // still talking. The timeout measures a silent client.
            let (message, order) = match self.host.next(Some(self.inline_timeout)) {
                HostRead::Message(message, order) => (message, order),
                HostRead::Timeout | HostRead::Eof => return Ok(None),
                HostRead::Invalid(reason) => return Err(reason.to_owned()),
            };
            if same_id(message.get("id"), id) && !is_request(&message) {
                return Ok(Some(message));
            }
            if is_notification(&message) {
                self.child.send(&message)?;
                continue;
            }
            if !is_request(&message) {
                if live_id(message.get("id")).is_some() {
                    self.client_responses.buffer(message);
                }
                continue;
            }
            if let Some(response) = self.handle(message, order.as_deref())? {
                let sent = self.host.send(&response);
                self.authority.settle();
                sent?;
            }
        }
    }
}
