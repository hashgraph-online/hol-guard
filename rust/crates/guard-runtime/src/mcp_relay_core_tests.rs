use std::collections::VecDeque;

use serde_json::json;

use super::*;
use crate::mcp_relay_authority::PendingNativeAuthority;

const TIMEOUT: Duration = Duration::from_secs(30);
const INLINE_TIMEOUT: Duration = Duration::from_secs(120);

enum Step {
    Frame(Value),
    Timeout,
    Eof,
}

/// A scripted MCP server: `queue` is what it emits, in order; with
/// `auto_reply` each request written to it queues a matching result.
#[derive(Default)]
struct FakeChild {
    queue: VecDeque<Step>,
    quiet: VecDeque<Result<Quiet, ChildEof>>,
    auto_reply: bool,
    sent: Vec<Value>,
    quarantined: bool,
}

impl FakeChild {
    fn replying() -> Self {
        Self {
            auto_reply: true,
            ..Self::default()
        }
    }

    fn emit(mut self, frame: Value) -> Self {
        self.queue.push_back(Step::Frame(frame));
        self
    }
}

impl ChildLink for FakeChild {
    fn send(&mut self, message: &Value) -> Result<(), String> {
        if self.auto_reply && is_request(message) {
            let reply = json!({
                "jsonrpc": "2.0",
                "id": message["id"].clone(),
                "result": {"echo": message["method"].clone()},
            });
            self.queue.push_back(Step::Frame(reply));
        }
        self.sent.push(message.clone());
        Ok(())
    }

    fn next(&mut self, _timeout: Duration) -> Result<Option<Value>, ChildEof> {
        match self.queue.pop_front() {
            Some(Step::Frame(frame)) => Ok(Some(frame)),
            Some(Step::Timeout) | None => Ok(None),
            Some(Step::Eof) => Err(ChildEof),
        }
    }

    fn next_quiet(&mut self, _quiet: Duration) -> Result<Quiet, ChildEof> {
        self.quiet.pop_front().unwrap_or(Ok(Quiet::Silent))
    }

    fn quarantine(&mut self) {
        self.quarantined = true;
    }
}

/// A scripted MCP client; an exhausted script is end of stream.
#[derive(Default)]
struct FakeHost {
    inbox: VecDeque<HostRead>,
    sent: Vec<Value>,
}

impl FakeHost {
    fn with(messages: Vec<Value>) -> Self {
        Self {
            inbox: messages
                .into_iter()
                .map(|message| HostRead::Message(message, None))
                .collect(),
            sent: Vec::new(),
        }
    }
}

impl HostLink for FakeHost {
    fn next(&mut self, _timeout: Option<Duration>) -> HostRead {
        self.inbox.pop_front().unwrap_or(HostRead::Eof)
    }

    fn send(&mut self, message: &Value) -> Result<(), String> {
        self.sent.push(message.clone());
        Ok(())
    }
}

fn request(id: Value, method: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": {}})
}

fn echo(id: Value, method: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {"echo": method}})
}

fn progress() -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}})
}

fn relay<A: RelayAuthority>(
    child: FakeChild,
    host: FakeHost,
    authority: A,
) -> Relay<FakeChild, FakeHost, A> {
    Relay::new(child, host, authority, TIMEOUT, INLINE_TIMEOUT)
}

#[test]
fn child_response_timeout_caps_and_defaults() {
    assert_eq!(child_response_timeout(0), Duration::from_secs(30));
    assert_eq!(child_response_timeout(-5), Duration::from_secs(30));
    assert_eq!(child_response_timeout(10), Duration::from_secs(10));
    assert_eq!(child_response_timeout(120), Duration::from_secs(30));
}

#[test]
fn timeout_responses_have_the_proxy_shape() {
    let response = timeout_response(
        Some(&json!(4)),
        "child_response",
        Duration::from_secs(30),
        CHILD_TIMEOUT,
    );
    assert_eq!(
        response,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "error": {
                "code": -32800,
                "message": "Guard runtime MCP proxy timed out waiting for the MCP server.",
                "data": {"guard_timeout": true, "source": "child_response", "timeout_seconds": 30.0},
            },
        })
    );
    assert!(is_timeout_response(&response));
    assert_eq!(
        timeout_response(None, "x", TIMEOUT, CHILD_TIMEOUT)["id"],
        Value::Null
    );
    assert!(!is_timeout_response(&json!({"error": {"code": -32800}})));
    assert!(!is_timeout_response(
        &json!({"error": {"code": -32001, "data": {"guard_timeout": true}}})
    ));
    assert!(!is_timeout_response(&json!({"result": {}})));
}

#[test]
fn same_id_compares_canonical_ids() {
    assert!(same_id(None, None));
    assert!(same_id(None, Some(&Value::Null)));
    assert!(same_id(Some(&json!(1)), Some(&json!(1))));
    assert!(!same_id(Some(&json!(1)), Some(&json!("1"))));
    assert!(!same_id(Some(&json!(1)), None));
    assert!(same_id(
        Some(&json!({"a": 1, "b": 2})),
        Some(&json!({"b": 2, "a": 1}))
    ));
}

#[test]
fn forwards_requests_and_returns_their_responses() {
    let host = FakeHost::with(vec![request(json!(1), "initialize")]);
    let mut relay = relay(FakeChild::replying(), host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(relay.host.sent, vec![echo(json!(1), "initialize")]);
    assert_eq!(relay.child.sent, vec![request(json!(1), "initialize")]);
}

#[test]
fn host_notifications_and_responses_go_to_the_child_verbatim() {
    let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    let answer = json!({"jsonrpc": "2.0", "id": 5, "result": {}});
    let host = FakeHost::with(vec![initialized.clone(), answer.clone()]);
    let mut relay = relay(FakeChild::replying(), host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(relay.child.sent, vec![initialized, answer]);
    assert!(relay.host.sent.is_empty());
}

#[test]
fn out_of_order_responses_are_buffered_by_id() {
    let child = FakeChild::default()
        .emit(echo(json!(2), "b"))
        .emit(echo(json!(1), "a"));
    let host = FakeHost::with(vec![request(json!(1), "a"), request(json!(2), "b")]);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(
        relay.host.sent,
        vec![echo(json!(1), "a"), echo(json!(2), "b")]
    );
}

#[test]
fn child_notifications_reach_the_host_while_a_response_is_pending() {
    let child = FakeChild::replying().emit(progress());
    let host = FakeHost::with(vec![request(json!("r"), "resources/read")]);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(
        relay.host.sent,
        vec![progress(), echo(json!("r"), "resources/read")]
    );
}

#[test]
fn null_id_child_frames_are_dropped_not_buffered() {
    let stray =
        json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse"}});
    let child = FakeChild::replying().emit(stray);
    let host = FakeHost::with(vec![request(json!(1), "ping")]);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(relay.host.sent, vec![echo(json!(1), "ping")]);
}

#[test]
fn a_null_id_request_correlates_with_a_null_id_response() {
    let host = FakeHost::with(vec![request(Value::Null, "ping")]);
    let mut relay = relay(FakeChild::replying(), host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(relay.host.sent, vec![echo(Value::Null, "ping")]);
}

#[test]
fn reverse_requests_round_trip_through_the_host() {
    let reverse = request(json!("s1"), "sampling/createMessage");
    let answer = json!({"jsonrpc": "2.0", "id": "s1", "result": {"ok": true}});
    let child = FakeChild::replying().emit(reverse.clone());
    let host = FakeHost::with(vec![request(json!(1), "prompts/get"), answer.clone()]);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(
        relay.host.sent,
        vec![reverse, echo(json!(1), "prompts/get")]
    );
    assert_eq!(
        relay.child.sent,
        vec![request(json!(1), "prompts/get"), answer]
    );
    assert_eq!(relay.depth, 0);
}

#[test]
fn host_traffic_is_serviced_while_a_reverse_request_waits() {
    let reverse = request(json!("s1"), "roots/list");
    let answer = json!({"jsonrpc": "2.0", "id": "s1", "result": {"roots": []}});
    let early = json!({"jsonrpc": "2.0", "id": "other", "result": {}});
    let cancelled =
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 9}});
    let child = FakeChild::replying().emit(reverse.clone());
    let host = FakeHost::with(vec![
        request(json!(1), "prompts/get"),
        cancelled.clone(),
        early,
        request(json!(2), "ping"),
        answer.clone(),
    ]);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(
        relay.host.sent,
        vec![
            reverse,
            echo(json!(2), "ping"),
            echo(json!(1), "prompts/get"),
        ]
    );
    assert_eq!(
        relay.child.sent,
        vec![
            request(json!(1), "prompts/get"),
            cancelled,
            request(json!(2), "ping"),
            answer,
        ]
    );
}

#[test]
fn a_silent_host_times_out_the_reverse_request() {
    let reverse = request(json!("s1"), "elicitation/create");
    let child = FakeChild::replying().emit(reverse.clone());
    let mut host = FakeHost::with(vec![request(json!(1), "prompts/get")]);
    host.inbox.push_back(HostRead::Timeout);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(
        relay.child.sent[1],
        timeout_response(
            Some(&json!("s1")),
            "nested_client_response",
            TIMEOUT,
            CLIENT_TIMEOUT
        )
    );
    assert_eq!(
        relay.host.sent,
        vec![reverse, echo(json!(1), "prompts/get")]
    );
}

#[test]
fn losing_the_host_during_a_reverse_request_is_fatal() {
    let child = FakeChild::replying().emit(request(json!("s1"), "roots/list"));
    let host = FakeHost::with(vec![request(json!(1), "prompts/get")]);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Err(HOST_LOST.to_owned()));
}

#[test]
fn reverse_requests_nested_too_deeply_are_refused() {
    let host = FakeHost::default();
    let mut relay = relay(FakeChild::default(), host, PendingNativeAuthority);
    relay.depth = MAX_NESTING;
    relay
        .multiplex(request(json!("deep"), "roots/list"))
        .unwrap();
    assert!(relay.host.sent.is_empty());
    assert_eq!(
        relay.child.sent,
        vec![json!({
            "jsonrpc": "2.0",
            "id": "deep",
            "error": {"code": -32603, "message": NESTING_REFUSED},
        })]
    );
}

#[test]
fn a_reverse_request_naming_a_guard_prompt_is_refused() {
    let host = FakeHost::default();
    let mut relay = relay(FakeChild::default(), host, PendingNativeAuthority);
    // The relay raises its own prompts under this id. Proxying the request
    // would leave the client holding two live requests under one id, and each
    // wait would take whichever answer came back first.
    relay
        .multiplex(request(json!("guard-elicitation-1"), "elicitation/create"))
        .unwrap();
    assert!(relay.host.sent.is_empty());
    assert_eq!(
        relay.child.sent,
        vec![json!({
            "jsonrpc": "2.0",
            "id": "guard-elicitation-1",
            "error": {"code": -32600, "message": RESERVED_ID_REFUSED},
        })]
    );
}

#[test]
fn a_child_response_timeout_quarantines_the_child_and_stops() {
    let host = FakeHost::with(vec![request(json!(1), "ping"), request(json!(2), "ping")]);
    let mut relay = relay(FakeChild::default(), host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::TimedOut));
    assert!(relay.child.quarantined);
    assert_eq!(
        relay.host.sent,
        vec![timeout_response(
            Some(&json!(1)),
            "child_response",
            TIMEOUT,
            CHILD_TIMEOUT
        )]
    );
    assert_eq!(relay.child.sent.len(), 1);
}

#[test]
fn child_eof_while_waiting_is_fatal() {
    let mut child = FakeChild::default();
    child.queue.push_back(Step::Eof);
    let host = FakeHost::with(vec![request(json!(1), "ping")]);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Err(CHILD_EOF.to_owned()));
}

#[test]
fn an_invalid_host_stream_is_fatal() {
    let mut host = FakeHost::default();
    host.inbox
        .push_back(HostRead::Invalid("mcp_relay_host_message_invalid"));
    let mut relay = relay(FakeChild::default(), host, PendingNativeAuthority);
    assert_eq!(
        relay.serve(),
        Err("mcp_relay_host_message_invalid".to_owned())
    );
}

#[path = "mcp_relay_core_call_tests.rs"]
mod tools_call;

#[path = "mcp_relay_core_prompt_tests.rs"]
mod inline_prompt;
