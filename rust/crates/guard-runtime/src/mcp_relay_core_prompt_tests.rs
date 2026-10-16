//! The inline approval prompt's transport: the client's capabilities, the
//! request the relay raises, the answer it hands back, and the one prompt a
//! call gets.

use serde_json::json;

use super::*;
use crate::mcp_relay_authority::ForwardTicket;

/// Asks for the prompt once per call, then answers with what came back.
#[derive(Default)]
struct PromptingAuthority {
    /// The `initialize` params the relay handed over, once per session.
    capabilities: Vec<Option<Value>>,
    /// The answers the relay handed back, in order.
    answers: Vec<Option<Value>>,
    /// Ask for a second prompt for the same call instead of deciding it.
    insistent: bool,
    /// The call this authority has already asked about, so a second call of
    /// the same session raises a prompt of its own.
    prompted: Option<Value>,
    /// How many prompts it asked for, over every call.
    prompts: usize,
}

impl RelayAuthority for PromptingAuthority {
    fn decide(
        &mut self,
        message: &Value,
        _params: &Map<String, Value>,
        _order: Option<&[String]>,
        _catalog: &RelayCatalog,
    ) -> ToolCallVerdict {
        let id = message["id"].clone();
        if self.insistent || self.prompted.as_ref() != Some(&id) {
            self.prompted = Some(id);
            self.prompts += 1;
            return ToolCallVerdict::Elicit(json!({"mode": "form", "message": "approve?"}));
        }
        ToolCallVerdict::Respond(json!({
            "jsonrpc": "2.0",
            "id": message["id"].clone(),
            "result": {"answers": self.answers.len()},
        }))
    }

    fn client_capabilities(&mut self, params: Option<&Value>) {
        self.capabilities.push(params.cloned());
    }

    fn elicited(&mut self, answer: Option<&Value>) {
        self.answers.push(answer.cloned());
    }

    fn boundary_changed(&mut self, ticket: ForwardTicket) -> Value {
        json!({"jsonrpc": "2.0", "id": ticket.message["id"].clone(), "boundary": true})
    }

    fn complete(&mut self, _ticket: ForwardTicket, response: Value) -> Value {
        response
    }
}

fn call(id: i64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": "read", "arguments": {}}})
}

fn answer(id: &str, decision: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {"action": "accept",
        "content": {"decision": decision}}})
}

fn prompt(counter: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": format!("guard-elicitation-{counter}"),
        "method": "elicitation/create",
        "params": {"mode": "form", "message": "approve?"},
    })
}

#[test]
fn the_prompt_is_raised_on_the_client_and_its_answer_decides_the_call() {
    let host = FakeHost::with(vec![call(3), answer("guard-elicitation-1", "approve")]);
    let mut relay = relay(FakeChild::replying(), host, PromptingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(
        relay.authority.answers,
        vec![Some(answer("guard-elicitation-1", "approve"))]
    );
    assert_eq!(
        relay.host.sent,
        vec![
            prompt(1),
            json!({"jsonrpc": "2.0", "id": 3, "result": {"answers": 1}}),
        ]
    );
    // The prompt is the relay's own request: the child never sees it.
    assert!(relay.child.sent.is_empty());
}

#[test]
fn every_prompt_of_a_session_has_its_own_id() {
    let host = FakeHost::with(vec![
        call(1),
        answer("guard-elicitation-1", "approve"),
        call(2),
        answer("guard-elicitation-2", "deny"),
    ]);
    let mut relay = relay(FakeChild::replying(), host, PromptingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    let raised: Vec<Value> = relay
        .host
        .sent
        .iter()
        .filter(|message| message["method"] == json!("elicitation/create"))
        .cloned()
        .collect();
    assert_eq!(raised, vec![prompt(1), prompt(2)]);
}

#[test]
fn an_unanswered_prompt_leaves_the_call_to_the_authority() {
    // A client that closes its stream, and one that never answers, are both
    // prompts the proxy answers itself with a cancel.
    for unanswered in [HostRead::Eof, HostRead::Timeout] {
        let mut host = FakeHost::with(vec![call(5)]);
        host.inbox.push_back(unanswered);
        let mut relay = relay(FakeChild::replying(), host, PromptingAuthority::default());
        assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
        assert_eq!(relay.authority.answers, vec![None]);
        assert_eq!(
            relay.host.sent.last().unwrap()["result"],
            json!({"answers": 1})
        );
    }
}

#[test]
fn a_second_prompt_for_one_call_is_no_decision() {
    let host = FakeHost::with(vec![call(9), answer("guard-elicitation-1", "approve")]);
    let authority = PromptingAuthority {
        insistent: true,
        ..PromptingAuthority::default()
    };
    let mut relay = relay(FakeChild::replying(), host, authority);
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(relay.authority.prompts, 2);
    assert!(relay.child.sent.is_empty());
    let blocked = relay.host.sent.last().unwrap();
    assert_eq!(blocked["id"], json!(9));
    assert_eq!(blocked["error"]["data"]["guardPolicyAction"], "block");
}

#[test]
fn a_prompt_still_carries_the_clients_other_traffic() {
    let host = FakeHost::with(vec![
        call(6),
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}}),
        json!({"jsonrpc": "2.0", "id": 99, "result": {"late": true}}),
        answer("guard-elicitation-1", "deny"),
    ]);
    let mut relay = relay(FakeChild::replying(), host, PromptingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(
        relay.authority.answers,
        vec![Some(answer("guard-elicitation-1", "deny"))]
    );
    // The notification reached the child; the stray response was buffered.
    assert_eq!(
        relay.child.sent,
        vec![json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}})]
    );
}

#[test]
fn only_the_initialize_hands_over_the_clients_capabilities() {
    let initialize = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"capabilities": {"elicitation": {}}}});
    let host = FakeHost::with(vec![
        initialize.clone(),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    ]);
    let mut relay = relay(FakeChild::replying(), host, PromptingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    assert_eq!(
        relay.authority.capabilities,
        vec![Some(initialize["params"].clone())]
    );
    // The initialize itself still reaches the child untouched.
    assert_eq!(relay.child.sent.first(), Some(&initialize));
}

/// Asks once for every call it sees, so a call serviced while a prompt waits
/// raises a prompt of its own.
#[derive(Default)]
struct NestingAuthority {
    asked: Vec<Value>,
    answers: Vec<Option<Value>>,
}

impl RelayAuthority for NestingAuthority {
    fn decide(
        &mut self,
        message: &Value,
        _params: &Map<String, Value>,
        _order: Option<&[String]>,
        _catalog: &RelayCatalog,
    ) -> ToolCallVerdict {
        let id = message["id"].clone();
        if !self.asked.contains(&id) {
            self.asked.push(id);
            return ToolCallVerdict::Elicit(json!({"mode": "form", "message": "approve?"}));
        }
        ToolCallVerdict::Respond(json!({"jsonrpc": "2.0", "id": id, "result": {}}))
    }

    fn elicited(&mut self, answer: Option<&Value>) {
        self.answers.push(answer.cloned());
    }

    fn boundary_changed(&mut self, ticket: ForwardTicket) -> Value {
        json!({"jsonrpc": "2.0", "id": ticket.message["id"].clone(), "boundary": true})
    }

    fn complete(&mut self, _ticket: ForwardTicket, response: Value) -> Value {
        response
    }
}

#[test]
fn prompts_stop_at_the_nesting_ceiling() {
    // A call serviced while a prompt waits can raise another prompt, and the
    // wait of that prompt services the next call. The relay raises
    // `MAX_NESTING` of them and decides the rest without one, so a client
    // cannot stack waits on the relay without bound.
    let calls: Vec<Value> = (1..=(MAX_NESTING as i64 + 8)).map(call).collect();
    let answered = calls.len();
    let host = FakeHost::with(calls);
    let mut relay = relay(FakeChild::replying(), host, NestingAuthority::default());
    assert_eq!(relay.serve(), Ok(RelayExit::HostClosed));
    let raised = relay
        .host
        .sent
        .iter()
        .filter(|message| message["method"] == json!("elicitation/create"))
        .count();
    assert_eq!(raised, MAX_NESTING);
    // Every call is still decided; the ones past the ceiling are decided with
    // the unanswered prompt the relay never raised.
    assert_eq!(relay.authority.answers.len(), answered);
    assert_eq!(relay.depth, 0);
}
