//! Host side of the `cigar.context-worker.v1` graph worker.
//!
//! Ports the checks of the Python `LocalContextGraph` the bridge used before:
//! the init hello must name this protocol, engine release and frame limits,
//! and only the worker's documented error codes pass through. Anything else
//! closes the worker.

use crate::channel::{Channel, MAX_HOST_FRAME, MAX_HOST_RESPONSE};
use serde_json::{json, Value};

const WORKER_ERRORS: [&str; 7] = [
    "InvalidInput",
    "LimitExceeded",
    "RequiredUnavailable",
    "BudgetUnsatisfiable",
    "Tokenizer",
    "Integrity",
    "BaseMismatch",
];
const VIEWS: &str = "context_views.v1";
const EXPLANATIONS: &str = "selection_explanation.v1";

/// Decode one graph worker reply for request `id`.
pub(crate) fn decode(reply: &Value, id: u32) -> Result<Value, Option<&'static str>> {
    let ok = reply.get("ok").and_then(Value::as_bool).ok_or(None)?;
    if reply.get("id").and_then(Value::as_u64) != Some(u64::from(id)) {
        return Err(None);
    }
    if ok {
        return reply.get("result").cloned().ok_or(None);
    }
    let code = reply.get("error").and_then(Value::as_str).ok_or(None)?;
    Err(Some(known(&WORKER_ERRORS, code).ok_or(None)?))
}

/// The static copy of `code` when it is one of `codes`.
pub(crate) fn known(codes: &[&'static str], code: &str) -> Option<&'static str> {
    codes.iter().copied().find(|known| *known == code)
}

pub(crate) struct Graph {
    channel: Channel,
    features: Vec<String>,
}

impl Graph {
    /// Start a worker and open one graph in `domain`.
    pub(crate) fn open(domain: &str, limits: Value) -> Result<Self, &'static str> {
        let mut channel = Channel::spawn(&[], decode)?;
        let hello = channel.call(json!({"op": "init", "domain": domain, "limits": limits}));
        let features = match hello.map(|hello| hello_features(&hello)) {
            Ok(Some(features)) => features,
            Ok(None) => {
                channel.close();
                return Err("IncompatibleWorker");
            }
            Err(code) => {
                channel.close();
                return Err(code);
            }
        };
        Ok(Self { channel, features })
    }

    /// The negotiated features. This is not a release qualification claim.
    pub(crate) fn capabilities(&self) -> Result<Value, &'static str> {
        if self.channel.is_closed() {
            return Err("Closed");
        }
        Ok(json!({
            "schema": "cigar.local-worker-capabilities.v1",
            "protocol": crate::WORKER_PROTOCOL,
            "core_version": crate::CORE_VERSION,
            "features": self.features,
            "max_frame_bytes": MAX_HOST_FRAME,
            "max_response_bytes": MAX_HOST_RESPONSE,
            "execution": "isolated-process-serialized",
            "authority": "trusted-host",
            "requires_hol_services": false,
        }))
    }

    pub(crate) fn call(&mut self, command: Value) -> Result<Value, &'static str> {
        self.channel.call(command)
    }

    /// A view command; needs the views feature, and explain needs explanations.
    pub(crate) fn view_call(&mut self, command: Value) -> Result<Value, &'static str> {
        let explain = command.get("op").and_then(Value::as_str) == Some("explain_view");
        if !self.has(VIEWS) {
            return Err("IncompatibleWorker");
        }
        if explain {
            self.capabilities()?;
            if !self.has(EXPLANATIONS) {
                return Err("IncompatibleWorker");
            }
        }
        self.channel.call(command)
    }

    pub(crate) fn close(&mut self) {
        self.channel.close();
    }

    fn has(&self, feature: &str) -> bool {
        self.features.iter().any(|item| item == feature)
    }
}

/// The sorted, deduplicated feature list of a compatible hello, else `None`.
pub(crate) fn hello_features(hello: &Value) -> Option<Vec<String>> {
    let compatible = hello.get("protocol").and_then(Value::as_str) == Some(crate::WORKER_PROTOCOL)
        && hello.get("core_version").and_then(Value::as_str) == Some(crate::CORE_VERSION)
        && hello.get("max_frame_bytes").and_then(Value::as_u64) == Some(MAX_HOST_FRAME as u64)
        && hello.get("max_response_bytes").and_then(Value::as_u64)
            == Some(MAX_HOST_RESPONSE as u64);
    if !compatible {
        return None;
    }
    let mut features = match hello.get("capabilities") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()?,
        Some(_) => return None,
    };
    features.sort();
    features.dedup();
    Some(features)
}

/// The startup self-test: index one document, compile it and verify the
/// snapshot, all in a fresh worker that is closed afterwards.
pub(crate) fn doctor() -> Result<Value, &'static str> {
    let mut graph = Graph::open("guard-runtime-doctor", json!({}))?;
    let result = (|| {
        let capabilities = graph.capabilities()?;
        graph.call(json!({"op": "upsert", "document": {
            "id": "doctor", "source": "guard:doctor", "text": "Guard local context works.",
        }}))?;
        let compiled = graph.call(json!({"op": "compile", "request": {
            "required": ["doctor"], "allowed": ["doctor"], "max_tokens": 256,
        }}))?;
        let snapshot = compiled
            .get("snapshot")
            .ok_or(crate::frames::REQUEST_FAILED)?;
        let rendered = snapshot
            .pointer("/stats/rendered_tokens")
            .cloned()
            .ok_or(crate::frames::REQUEST_FAILED)?;
        let verified = graph.call(json!({"op": "verify", "snapshot": snapshot}))? == compiled;
        Ok(json!({
            "capabilities": capabilities,
            "compile_verified": verified,
            "rendered_tokens": rendered,
        }))
    })();
    graph.close();
    result
}
