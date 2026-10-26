//! `tools/call` handling: the drain, the decision seam, the pre-write quiet
//! edge, and the catalog boundary.

use serde_json::json;

use super::*;
use crate::mcp_relay_authority::{ClaimTicket, ForwardTicket, PendingNativeAuthority};

/// Forwards every call against the catalog it sees and records the outcome.
#[derive(Default)]
struct ForwardingAuthority {
    decided: usize,
    completed: Vec<Value>,
    boundaries: usize,
    settled: usize,
    reported: Vec<Vec<Value>>,
}

impl RelayAuthority for ForwardingAuthority {
    fn decide(
        &mut self,
        message: &Value,
        _params: &Map<String, Value>,
        _order: Option<&[String]>,
        catalog: &RelayCatalog,
    ) -> ToolCallVerdict {
        self.decided += 1;
        ToolCallVerdict::Forward(ForwardTicket {
            message: message.clone(),
            expected: catalog.snapshot(),
            evidence: None,
        })
    }

    fn boundary_changed(&mut self, ticket: ForwardTicket) -> Value {
        self.boundaries += 1;
        json!({"jsonrpc": "2.0", "id": ticket.message["id"].clone(), "boundary": true})
    }

    fn complete(&mut self, _ticket: ForwardTicket, response: Value) -> Value {
        self.completed.push(response.clone());
        response
    }

    fn settle(&mut self) {
        self.settled += 1;
    }

    fn catalog_complete(&mut self, tools: &[Value]) {
        self.reported.push(tools.to_vec());
    }
}

fn call(id: i64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "read", "arguments": {}}})
}

fn list_changed() -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
}

#[test]
fn tools_call_without_a_native_decision_is_blocked() {
    let host = FakeHost::with(vec![call(7)]);
    let mut relay = relay(FakeChild::replying(), host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert!(relay.child.sent.is_empty());
    assert_eq!(
        relay.host.sent,
        vec![json!({
            "jsonrpc": "2.0",
            "id": 7,
            "error": {
                "code": -32001,
                "message": "HOL Guard could not obtain a native decision for this tool call.",
                "data": {"approvalRequests": [], "guardPolicyAction": "block"},
            },
        })]
    );
}

#[test]
fn tools_call_drains_queued_child_frames_first() {
    let child = FakeChild::default().emit(progress());
    let host = FakeHost::with(vec![call(7)]);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(relay.host.sent.len(), 2);
    assert_eq!(relay.host.sent[0], progress());
    assert_eq!(relay.host.sent[1]["error"]["code"], -32001);
}

#[test]
fn tools_call_fails_closed_when_the_child_stream_cannot_be_drained() {
    let mut child = FakeChild::default();
    child.queue.push_back(Step::Eof);
    let host = FakeHost::with(vec![call(3)]);
    let mut relay = relay(child, host, ForwardingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(relay.authority.decided, 0);
    assert_eq!(relay.catalog.snapshot().state, "error");
    assert_eq!(
        relay.host.sent,
        vec![json!({
            "jsonrpc": "2.0",
            "id": 3,
            "error": {
                "code": -32001,
                "message": "HOL Guard could not synchronize the MCP server notification stream before this tool call.",
                "data": {"approvalRequests": [], "guardPolicyAction": "require-reapproval"},
            },
        })]
    );
}

#[test]
fn a_forwarded_call_is_written_after_a_quiet_edge_and_completed() {
    let host = FakeHost::with(vec![call(1)]);
    let mut relay = relay(FakeChild::replying(), host, ForwardingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(relay.child.sent, vec![call(1)]);
    assert_eq!(relay.host.sent, vec![echo(json!(1), "tools/call")]);
    assert_eq!(
        relay.authority.completed,
        vec![echo(json!(1), "tools/call")]
    );
    assert_eq!(relay.authority.boundaries, 0);
    assert_eq!(relay.authority.settled, 1);
}

#[test]
fn frames_seen_at_the_quiet_edge_are_relayed_before_the_write() {
    let mut child = FakeChild::replying();
    child.quiet.push_back(Ok(Quiet::Frame(progress())));
    let host = FakeHost::with(vec![call(1)]);
    let mut relay = relay(child, host, ForwardingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(
        relay.host.sent,
        vec![progress(), echo(json!(1), "tools/call")]
    );
    assert_eq!(relay.child.sent, vec![call(1)]);
}

#[test]
fn a_catalog_change_at_the_quiet_edge_is_a_boundary_failure() {
    let mut child = FakeChild::replying();
    child.quiet.push_back(Ok(Quiet::Frame(list_changed())));
    let host = FakeHost::with(vec![call(1)]);
    let mut relay = relay(child, host, ForwardingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert!(relay.child.sent.is_empty());
    assert_eq!(relay.authority.boundaries, 1);
    assert!(relay.authority.completed.is_empty());
    assert_eq!(
        relay.host.sent,
        vec![
            list_changed(),
            json!({"jsonrpc": "2.0", "id": 1, "boundary": true}),
        ]
    );
    assert_eq!(relay.catalog.snapshot().state, "invalidated");
}

#[test]
fn a_busy_quiet_edge_is_a_boundary_failure() {
    let mut child = FakeChild::replying();
    child.quiet.push_back(Ok(Quiet::Busy));
    let host = FakeHost::with(vec![call(1)]);
    let mut relay = relay(child, host, ForwardingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert!(relay.child.sent.is_empty());
    assert_eq!(
        relay.host.sent,
        vec![json!({"jsonrpc": "2.0", "id": 1, "boundary": true})]
    );
}

#[test]
fn child_eof_at_the_quiet_edge_is_fatal() {
    let mut child = FakeChild::replying();
    child.quiet.push_back(Err(ChildEof));
    let host = FakeHost::with(vec![call(1)]);
    let mut relay = relay(child, host, ForwardingAuthority::default());
    assert_eq!(relay.serve(), Err(CHILD_EOF.to_owned()));
    assert!(relay.child.sent.is_empty());
}

#[test]
fn a_host_list_changed_notification_invalidates_the_catalog() {
    let host = FakeHost::with(vec![list_changed()]);
    let mut relay = relay(FakeChild::replying(), host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(relay.catalog.snapshot().state, "invalidated");
    assert_eq!(relay.child.sent, vec![list_changed()]);
}

#[test]
fn tools_list_responses_feed_the_catalog() {
    let listing = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "read", "inputSchema": {"type": "object"}}
    ]}});
    let child = FakeChild::default().emit(listing.clone());
    let host = FakeHost::with(vec![request(json!(1), "tools/list")]);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(relay.host.sent, vec![listing]);
    let snapshot = relay.catalog.snapshot();
    assert_eq!(snapshot.state, "complete");
    assert_eq!(snapshot.generation, 1);
}

#[test]
fn a_whole_catalog_is_reported_once_until_it_changes() {
    let page = |id: i64, tools: &[&str], next: Option<&str>| {
        let tools: Vec<Value> = tools
            .iter()
            .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
            .collect();
        let mut result = json!({"tools": tools});
        if let Some(next) = next {
            result["nextCursor"] = json!(next);
        }
        json!({"jsonrpc": "2.0", "id": id, "result": result})
    };
    let child = FakeChild::default()
        .emit(page(1, &["read"], Some("more")))
        .emit(page(2, &["list"], None))
        .emit(page(3, &["list", "read"], None))
        .emit(page(4, &["write"], None));
    let host = FakeHost::with(vec![
        request(json!(1), "tools/list"),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"cursor": "more"}}),
        request(json!(3), "tools/list"),
        request(json!(4), "tools/list"),
    ]);
    let mut relay = relay(child, host, ForwardingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    let names: Vec<Vec<&str>> = relay
        .authority
        .reported
        .iter()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool["name"].as_str())
                .collect()
        })
        .collect();
    assert_eq!(names, vec![vec!["list", "read"], vec!["write"]]);
}

#[test]
fn a_failed_tools_list_poisons_the_catalog() {
    let mut child = FakeChild::default();
    child.queue.push_back(Step::Eof);
    let host = FakeHost::with(vec![request(json!(1), "tools/list")]);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Err(CHILD_EOF.to_owned()));
    assert_eq!(relay.catalog.snapshot().state, "error");
}

#[test]
fn a_timed_out_tools_list_leaves_the_catalog_unauthorized() {
    let mut child = FakeChild::default();
    child.queue.push_back(Step::Timeout);
    let host = FakeHost::with(vec![request(json!(1), "tools/list")]);
    let mut relay = relay(child, host, PendingNativeAuthority);
    assert_eq!(relay.serve(), Ok(RelayExit::TimedOut));
    assert_ne!(relay.catalog.snapshot().state, "complete");
}

/// Holds a claim for every call and forwards each claim it is asked to spend.
#[derive(Default)]
struct ClaimingAuthority {
    claimed: Vec<String>,
    completed: usize,
}

impl RelayAuthority for ClaimingAuthority {
    fn decide(
        &mut self,
        message: &Value,
        _params: &Map<String, Value>,
        _order: Option<&[String]>,
        catalog: &RelayCatalog,
    ) -> ToolCallVerdict {
        ToolCallVerdict::Claim(ClaimTicket {
            message: message.clone(),
            expected: catalog.snapshot(),
            claim: "claim-1".to_owned(),
            request: json!(null),
        })
    }

    fn claim(&mut self, ticket: ClaimTicket) -> ToolCallVerdict {
        self.claimed.push(ticket.claim);
        ToolCallVerdict::Forward(ForwardTicket {
            message: ticket.message,
            expected: ticket.expected,
            evidence: None,
        })
    }

    fn boundary_changed(&mut self, ticket: ForwardTicket) -> Value {
        json!({"jsonrpc": "2.0", "id": ticket.message["id"].clone(), "boundary": true})
    }

    fn complete(&mut self, _ticket: ForwardTicket, response: Value) -> Value {
        self.completed += 1;
        response
    }
}

#[test]
fn a_held_claim_is_spent_after_the_drain_and_forwarded() {
    let host = FakeHost::with(vec![call(4)]);
    let mut relay = relay(FakeChild::replying(), host, ClaimingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(relay.authority.claimed, vec!["claim-1".to_owned()]);
    assert_eq!(relay.authority.completed, 1);
    assert_eq!(relay.child.sent, vec![call(4)]);
    assert_eq!(relay.host.sent, vec![echo(json!(4), "tools/call")]);
}

#[test]
fn a_catalog_change_before_the_claim_spends_nothing() {
    // The drain before the decision stops at the gap; the one before the
    // claim sees the list change.
    let mut child = FakeChild::replying();
    child.queue.push_back(Step::Timeout);
    child.queue.push_back(Step::Frame(list_changed()));
    let host = FakeHost::with(vec![call(5)]);
    let mut relay = relay(child, host, ClaimingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert!(relay.authority.claimed.is_empty());
    assert!(relay.child.sent.is_empty());
    assert_eq!(relay.host.sent.len(), 2);
    assert_eq!(relay.host.sent[0], list_changed());
    assert_eq!(
        relay.host.sent[1]["error"]["message"],
        "HOL Guard could not obtain a native decision for this tool call."
    );
}

#[test]
fn a_failed_drain_before_the_claim_poisons_the_catalog_and_spends_nothing() {
    let mut child = FakeChild::replying();
    child.queue.push_back(Step::Timeout);
    child.queue.push_back(Step::Eof);
    let host = FakeHost::with(vec![call(6)]);
    let mut relay = relay(child, host, ClaimingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert!(relay.authority.claimed.is_empty());
    assert!(relay.child.sent.is_empty());
    assert_eq!(relay.catalog.snapshot().state, "error");
    assert_eq!(relay.host.sent[0]["error"]["code"], -32001);
}

#[test]
fn an_authority_without_claims_answers_a_claim_with_no_decision() {
    let message = call(8);
    let ticket = ClaimTicket {
        message: message.clone(),
        expected: RelayCatalog::default().snapshot(),
        claim: "claim-1".to_owned(),
        request: json!(null),
    };
    let ToolCallVerdict::Respond(response) = PendingNativeAuthority.claim(ticket) else {
        panic!("a claim without a holder must respond");
    };
    assert_eq!(response["id"], 8);
    assert_eq!(response["error"]["data"]["guardPolicyAction"], "block");
}
