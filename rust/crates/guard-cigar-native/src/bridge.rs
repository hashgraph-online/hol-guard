//! `__guard-cigar-bridge`: the supervisor's graph and broker bridge.
//!
//! Replaces the Python `bridge.py`. It owns graph and broker workers, each a
//! child process of this executable in worker mode, and dispatches the same
//! `guard-cigar-bridge.v1` operations to them. No files are read here; Guard
//! hands every document over the pipe.

use crate::broker_host::Broker;
use crate::frames::{member, null_to_empty, or_empty, serve, text, REQUEST_FAILED};
use crate::graph::{self, Graph};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{stdin, stdout};

#[derive(Default)]
struct Bridge {
    graphs: HashMap<String, Graph>,
    views: HashMap<(String, String), Value>,
    brokers: HashMap<String, Broker>,
}

/// Serve the bridge on stdin and stdout until the supervisor closes it.
pub(crate) fn run() -> i32 {
    let mut bridge = Bridge::default();
    serve(&mut stdin().lock(), &mut stdout().lock(), |request| {
        let stop = request.get("op").and_then(Value::as_str) == Some("shutdown");
        (bridge.dispatch(request), stop)
    });
    bridge.close_all();
    0
}

impl Bridge {
    fn dispatch(&mut self, request: &Value) -> Result<Value, &'static str> {
        let op = text(request, "op")?;
        if op.starts_with("broker_") {
            return self.broker(op, request);
        }
        match op {
            "health" => return Ok(json!({"running": true})),
            "doctor" => return graph::doctor(),
            "shutdown" => return Ok(json!({"closed": true})),
            _ => {}
        }
        let key = text(request, "graph")?;
        if op == "open_graph" {
            if self.graphs.contains_key(key) {
                return Err(REQUEST_FAILED);
            }
            let graph = Graph::open(key, or_empty(request, "limits"))?;
            let capabilities = graph.capabilities();
            self.graphs.insert(key.to_owned(), graph);
            return capabilities;
        }
        if op == "close_graph" {
            let mut graph = self.graphs.remove(key).ok_or(REQUEST_FAILED)?;
            graph.close();
            self.views.retain(|(owner, _), _| owner != key);
            return Ok(json!({"closed": true}));
        }
        let graph = self.graphs.get_mut(key).ok_or(REQUEST_FAILED)?;
        match op {
            "replace_source" => graph.call(json!({
                "op": "replace_source",
                "source": member(request, "source")?,
                "documents": member(request, "documents")?,
            })),
            "create_view" => {
                let spec = member(request, "spec")?;
                let id = text(&spec, "id")?.to_owned();
                let handle = graph.view_call(json!({"op": "define_view", "spec": spec}))?;
                self.views.insert((key.to_owned(), id), handle);
                Ok(json!({"created": true}))
            }
            "revoke_view" => {
                let view = text(request, "view")?.to_owned();
                let result = graph.view_call(json!({"op": "revoke_view", "view_id": view}))?;
                self.views.remove(&(key.to_owned(), view));
                Ok(result)
            }
            "compile_view" | "explain_view" => {
                let view = text(request, "view")?;
                let handle = self
                    .views
                    .get(&(key.to_owned(), view.to_owned()))
                    .ok_or(REQUEST_FAILED)?
                    .clone();
                let (field, value) = if op == "compile_view" {
                    ("request", member(request, "request")?)
                } else {
                    ("context", member(request, "context")?)
                };
                graph.view_call(json!({"op": op, "view": handle, field: value}))
            }
            "stats" => graph.call(json!({"op": "stats"})),
            "clear_cache" => {
                graph.call(json!({"op": "clear_cache"}))?;
                Ok(json!({"cleared": true}))
            }
            _ => Err(REQUEST_FAILED),
        }
    }

    fn broker(&mut self, op: &str, request: &Value) -> Result<Value, &'static str> {
        let key = text(request, "domain")?;
        if op == "broker_open" {
            let limits = [
                null_to_empty(member(request, "graph_limits")?),
                null_to_empty(member(request, "retention")?),
                null_to_empty(member(request, "queues")?),
                null_to_empty(member(request, "transport")?),
            ];
            let storage = request
                .get("storage")
                .filter(|value| !value.is_null())
                .cloned();
            if let Some(mut previous) = self.brokers.remove(key) {
                previous.close();
            }
            let broker = Broker::open(key, limits, storage)?;
            let capabilities = broker.capabilities();
            self.brokers.insert(key.to_owned(), broker);
            return capabilities;
        }
        if op == "broker_close" {
            let mut broker = self.brokers.remove(key).ok_or(REQUEST_FAILED)?;
            broker.close();
            return Ok(json!({"closed": true}));
        }
        let broker = self.brokers.get_mut(key).ok_or(REQUEST_FAILED)?;
        let field = |name: &str| member(request, name);
        match op {
            "broker_revision" => {
                broker.call(json!({"op": "source_revision", "source": field("source")?}))
            }
            "broker_provenance" => {
                broker.call(json!({"op": "provenance", "source": field("source")?}))
            }
            "broker_replace" => broker.call(json!({
                "op": "replace_source",
                "source": field("source")?,
                "expected": field("expected")?,
                "documents": field("documents")?,
                "provenance": field("provenance")?,
            })),
            "broker_grant" => broker.grant(
                field("view")?,
                null_to_empty(field("limits")?),
                null_to_empty(field("queue")?),
                field("lease_ms")?,
            ),
            "broker_revoke" => {
                let revoked = broker.call(json!({"op": "revoke", "agent": field("client")?}))?;
                Ok(json!({"revoked": revoked}))
            }
            "broker_proposal" => {
                broker.call(json!({"op": "proposal", "proposal_id": field("proposal")?}))
            }
            "broker_admit" => broker.call(json!({
                "op": "admit_proposal",
                "proposal_id": field("proposal")?,
                "provenance": field("provenance")?,
            })),
            "broker_reject" => {
                broker.call(json!({"op": "reject_proposal", "proposal_id": field("proposal")?}))?;
                Ok(json!({"rejected": true}))
            }
            "broker_submission" => {
                broker.call(json!({"op": "submission", "ticket": field("ticket")?}))
            }
            "broker_check_answer" => broker.call(json!({
                "op": "check_answer",
                "ticket": field("ticket")?,
                "submission_id": field("submission_id")?,
                "reviews": field("reviews")?,
                "policy": null_to_empty(field("policy")?),
            })),
            "broker_bind_execution" => broker.handoff_call(json!({
                "op": "bind_execution",
                "ticket": field("ticket")?,
                "submission_id": field("submission_id")?,
                "effect_id": field("effect_id")?,
                "intent_digest": field("intent_digest")?,
                "review": field("review")?,
            })),
            "broker_take_execution" => broker.handoff_call(json!({
                "op": "take_execution_handoff",
                "binding": field("binding")?,
                "review": field("review")?,
            })),
            _ => Err(REQUEST_FAILED),
        }
    }

    fn close_all(&mut self) {
        for graph in self.graphs.values_mut() {
            graph.close();
        }
        for broker in self.brokers.values_mut() {
            broker.close();
        }
    }
}
