//! The resident relay authority's trait answers and the decide wire: how a
//! `tools/call` becomes a decide request and how the resident's reply is read.

use super::*;
/// A package evaluation borrows the same lane a decision travels on: the
/// resident is already discovered, its direct-lane identity already checked,
/// and an evaluation's rounds are requests like any other.
impl crate::supply_chain_eval_transport::ResidentLane for ResidentRelayAuthority {
    fn exchange_until(&mut self, payload: &[u8], deadline: Instant) -> Option<Vec<u8>> {
        let guard_home = PathBuf::from(&self.facts.as_ref()?.guard_home);
        ResidentRelayAuthority::exchange_until(self, &guard_home, payload, deadline)
    }

    fn runtime_sha256(&self) -> Option<String> {
        self.resident
            .as_ref()
            .map(|resident| resident.state.runtime_sha256.clone())
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
        // The answer belongs to this call: the relay raised its prompt with
        // nothing else running, so the next request it sends spends it.
        let inline = json!({
            "available": self.inline_available,
            "answer": self.inline_answer.take(),
        });
        let Some((message, request, expected)) = prepare(facts, message, order, catalog, &inline)
        else {
            defer::note(defer::REQUEST_UNSENDABLE);
            return no_decision();
        };
        let Some(payload) = request::decide_payload(&request) else {
            defer::note(defer::REQUEST_UNSENDABLE);
            return no_decision();
        };
        let guard_home = PathBuf::from(&facts.guard_home);
        self.warm_up();
        let mut output = self.exchange(&guard_home, &payload);
        // Retries share one budget: each is bounded by it, and none starts
        // without the time a resident needs to answer.
        let retry_until = Instant::now() + RETRY_BUDGET;
        while reply_of(output.as_deref()).is_none()
            && self.rekick(output.as_deref(), retry_until)
            && remaining(retry_until) >= MINIMUM_TIMEOUT
        {
            output = self.exchange_until(&guard_home, &payload, retry_until);
        }
        // A package call is decided from an evaluation whose archive and
        // registry rounds this relay performs, which the decide round trip
        // cannot hold. The resident asks for it once and the same call is sent
        // again with it attached.
        if matches!(reply_of(output.as_deref()), Some(Reply::Evaluate { .. })) {
            let Some(payload) = self.evaluated(&request) else {
                let cause = self.mark_unsettled(&guard_home, &request);
                defer::note(defer::PACKAGE_UNEVALUATED);
                return ToolCallVerdict::Respond(undecided_response(id, params, &cause));
            };
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
                request,
            }),
            Some(Reply::Elicit { params }) => ToolCallVerdict::Elicit(params),
            Some(Reply::Block { message, data }) => ToolCallVerdict::Respond(blocked_response(
                id,
                &tool_name(params),
                Some(&message),
                Some(data),
            )),
            // The evaluation travels with the second send, so a second request
            // for one is an answer this exchange cannot take.
            Some(Reply::Evaluate { .. }) => {
                let cause = self.mark_unsettled(&guard_home, &request);
                defer::note(defer::PACKAGE_UNDECIDED);
                ToolCallVerdict::Respond(undecided_response(id, params, &cause))
            }
            None => {
                let cause = defer::reply_cause(output.as_deref());
                defer::note(&cause);
                ToolCallVerdict::Respond(undecided_response(id, params, &cause))
            }
        }
    }

    fn claim(&mut self, ticket: ClaimTicket) -> ToolCallVerdict {
        let no_decision = ToolCallVerdict::Respond(ticket.no_decision());
        let Some(payload) = self.claim_payload(&ticket.claim, None) else {
            return no_decision;
        };
        let mut answered = self.send_claim(&payload);
        let asked = answered.as_deref().and_then(reply);
        // A package call's claim is spent against an evaluation the authority
        // runs after the claim, whose archive and registry rounds this relay
        // performs. The claim request cannot carry them either, so the
        // authority holds the same rows against a fresh ticket and asks for
        // the evaluation. The round that asked spent nothing.
        if let Some(Reply::Evaluate { ticket: Some(held) }) = asked {
            let Some(evaluation) = self.evaluation(&ticket.request, true) else {
                return no_decision;
            };
            let Some(payload) = self.claim_payload(&held, Some(evaluation)) else {
                return no_decision;
            };
            answered = self.send_claim(&payload);
        }
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
            // The decision the claim settles was already made, so a second
            // claim and a prompt are answers this exchange cannot take. The
            // evaluation travels with the second claim, so a second request
            // for one cannot be taken either.
            Some(Reply::Claim { .. })
            | Some(Reply::Elicit { .. })
            | Some(Reply::Evaluate { .. }) => no_decision,
            // A refused claim names its cause as a refused decision does, so
            // a version skew asks for a restart or repair the same way.
            None => ToolCallVerdict::Respond(refused_claim(&ticket.message, answered.as_deref())),
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

    fn client_capabilities(&mut self, params: Option<&Value>) {
        // `_record_client_capabilities`: only a declared `elicitation` object
        // offers the prompt, so anything else leaves the queue route alone.
        self.inline_available = params
            .and_then(|params| params.get("capabilities"))
            .and_then(Value::as_object)
            .is_some_and(|capabilities| {
                capabilities
                    .get("elicitation")
                    .is_some_and(Value::is_object)
            });
    }

    fn elicited(&mut self, answer: Option<&Value>) {
        // `_request_inline_approval` answers an unanswered prompt with a
        // cancel, which falls through to the approval queue.
        self.inline_answer = Some(answer.map_or(InlineReply::Fallthrough, InlineReply::classify));
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
pub(super) fn prepare(
    facts: &RelayFacts,
    message: &Value,
    order: Option<&[String]>,
    catalog: &RelayCatalog,
    inline: &Value,
) -> Option<(Value, Value, CatalogSnapshot)> {
    let frame = python_canonical(message).filter(|frame| frame.get("id") == message.get("id"))?;
    let call = frame.get("params")?.as_object()?;
    let (request, expected) = decide_request(facts, call, order, catalog, inline)?;
    Some((frame, request, expected))
}

/// How the resident answered one commit.
pub(super) fn committed(output: &[u8]) -> Sent {
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
pub(super) enum Reply {
    Forward {
        ticket: String,
    },
    Claim {
        ticket: String,
    },
    Block {
        message: String,
        data: Value,
    },
    /// Raise the client's inline prompt, then decide this call again.
    Elicit {
        params: Value,
    },
    /// Evaluate the package request this call carries, then ask again with
    /// the evaluation attached: a decide with no ticket is decided again, and
    /// a claim carries the ticket its rows are held against again.
    Evaluate {
        ticket: Option<String>,
    },
}

/// The answer to a claim the authority refused, named by its cause.
pub(super) fn refused_claim(message: &Value, answered: Option<&[u8]>) -> Value {
    let cause = defer::reply_cause(answered);
    defer::note(&cause);
    let params = message
        .get("params")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    undecided_response(message.get("id"), &params, &cause)
}

fn reply_of(output: Option<&[u8]>) -> Option<Reply> {
    output.and_then(reply)
}

pub(super) fn reply(output: &[u8]) -> Option<Reply> {
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
        "evaluate" => Some(Reply::Evaluate { ticket: ticket() }),
        "elicit" => Some(Reply::Elicit {
            params: result
                .get("params")
                .filter(|params| params.is_object())?
                .clone(),
        }),
        "block" => Some(Reply::Block {
            message: result.get("message")?.as_str()?.to_owned(),
            data: result.get("data").filter(|data| data.is_object())?.clone(),
        }),
        _ => None,
    }
}

#[cfg(test)]
#[path = "mcp_relay_resident_claim_tests.rs"]
mod claim_tests;
