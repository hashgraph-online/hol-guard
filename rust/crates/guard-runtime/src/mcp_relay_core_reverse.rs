//! The reverse requests an MCP server child raises on its client.
//!
//! Port of `_proxy_child_request` and its response loop (`runtime_mcp.py`):
//! the request is proxied to the host, and the wait services the client's
//! notifications, responses and requests until the answer comes back, with
//! the nesting the proxy bounds bounded here too.

use serde_json::{json, Value};

use guard_command::mcp_stdio_session::{is_notification, is_request};

use super::{
    live_id, prompt, same_id, timeout_response, ChildLink, Relay, RelayAuthority, CLIENT_TIMEOUT,
    HOST_LOST, MAX_NESTING, NESTING_CODE, NESTING_REFUSED, RESERVED_ID_CODE, RESERVED_ID_REFUSED,
};
use crate::mcp_relay_host::{HostLink, HostRead};

impl<C: ChildLink, H: HostLink, A: RelayAuthority> Relay<C, H, A> {
    /// `_proxy_child_request`: a reverse request from the child.
    pub(super) fn proxy_child_request(&mut self, request: Value) -> Result<(), String> {
        let id = request.get("id").cloned();
        let refused = if self.depth >= MAX_NESTING {
            Some((NESTING_CODE, NESTING_REFUSED))
        } else if prompt::reserved_id(id.as_ref()) {
            Some((RESERVED_ID_CODE, RESERVED_ID_REFUSED))
        } else {
            None
        };
        if let Some((code, message)) = refused {
            let refusal = json!({
                "jsonrpc": "2.0",
                "id": id.unwrap_or(Value::Null),
                "error": {"code": code, "message": message},
            });
            return self.child.send(&refusal);
        }
        self.host.send(&request)?;
        self.depth += 1;
        let outcome = self.await_client_response(id.as_ref());
        self.depth -= 1;
        outcome
    }

    fn await_client_response(&mut self, id: Option<&Value>) -> Result<(), String> {
        loop {
            if let Some(response) = live_id(id).and_then(|id| self.client_responses.pop(id)) {
                return self.child.send(&response);
            }
            let (message, order) = match self.host.next(Some(self.timeout)) {
                HostRead::Message(message, order) => (message, order),
                HostRead::Timeout => {
                    let timeout = timeout_response(
                        id,
                        "nested_client_response",
                        self.timeout,
                        CLIENT_TIMEOUT,
                    );
                    return self.child.send(&timeout);
                }
                HostRead::Eof => return Err(HOST_LOST.to_owned()),
                HostRead::Invalid(reason) => return Err(reason.to_owned()),
            };
            if same_id(message.get("id"), id) && !is_request(&message) {
                return self.child.send(&message);
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
