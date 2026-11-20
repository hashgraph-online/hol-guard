//! Host side of the `cigar.context-broker.v1` worker (`--broker` mode).
//!
//! Ports the checks of the Python `LocalContextBroker`: the init hello must
//! match this engine release, loopback host and frame limits, and offer
//! mutual grant proofs; replies must have exactly the documented members.
//! A grant result that does not match the broker's epoch closes the broker.

use crate::channel::{Channel, MAX_HOST_FRAME, MAX_HOST_RESPONSE};
use crate::graph::known;
use cigar_context::broker::protocol::{MAX_AGENT_FRAME, MAX_AGENT_RESPONSE};
use serde_json::{json, Map, Value};

pub(crate) const BROKER_ERRORS: [&str; 15] = [
    "AccessDenied",
    "Stale",
    "Conflict",
    "Quota",
    "InvalidInput",
    "Unavailable",
    "LimitExceeded",
    "RequiredUnavailable",
    "BudgetUnsatisfiable",
    "Tokenizer",
    "Integrity",
    "BaseMismatch",
    "Expired",
    "Cancelled",
    "Closed",
];
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const HANDOFF: &str = "execution_handoff.v1";

/// What a broker reply carries: a result, or a server error code. The reply's
/// `dispatched` flag must be a boolean but is not needed by the client.
pub(crate) enum Outcome {
    Done(Value),
    Failed(&'static str),
}

/// Check a broker reply envelope for request `id`. `None` means malformed.
pub(crate) fn outcome(reply: &Value, id: u64) -> Option<Outcome> {
    let reply = exact(reply, &["id", "outcome", "protocol", "timing"])?;
    if reply["protocol"].as_str() != Some(crate::BROKER_PROTOCOL)
        || reply["id"].as_u64() != Some(id)
    {
        return None;
    }
    let timing = exact(&reply["timing"], &["queue_us", "service_us"])?;
    if timing
        .values()
        .any(|value| value.as_u64().is_none_or(|value| value > MAX_SAFE_INTEGER))
    {
        return None;
    }
    let outcome = reply["outcome"].as_object()?;
    match outcome.get("status").and_then(Value::as_str) {
        Some("ok") if outcome.len() == 2 => outcome.get("result").cloned().map(Outcome::Done),
        Some("error") => {
            let outcome = exact(&reply["outcome"], &["dispatched", "error", "status"])?;
            let code = known(&BROKER_ERRORS, outcome["error"].as_str()?)?;
            outcome["dispatched"].as_bool()?;
            Some(Outcome::Failed(code))
        }
        _ => None,
    }
}

/// The object when its keys are exactly `keys` (sorted), else `None`.
fn exact<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Map<String, Value>> {
    let object = value.as_object()?;
    (object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)))
        .then_some(object)
}

fn decode(reply: &Value, id: u32) -> Result<Value, Option<&'static str>> {
    match outcome(reply, u64::from(id)) {
        Some(Outcome::Done(result)) => Ok(result),
        Some(Outcome::Failed(code)) => Err(Some(code)),
        None => Err(None),
    }
}

/// Lowercase 64-character hex, the form of epochs, secrets and nonces.
pub(crate) fn is_hex64(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(crate) struct Broker {
    channel: Channel,
    hello: Value,
}

impl Broker {
    /// Start a broker worker for `domain`. `storage` is omitted when `None`.
    pub(crate) fn open(
        domain: &str,
        limits: [Value; 4],
        storage: Option<Value>,
    ) -> Result<Self, &'static str> {
        let [graph, retention, queues, transport] = limits;
        let mut channel = Channel::spawn(&["--broker"], decode)?;
        let mut init = json!({
            "op": "init", "domain": domain, "graph": graph, "retention": retention,
            "queues": queues, "transport": transport,
        });
        let persisted = storage.is_some();
        if let (Some(storage), Some(init)) = (storage, init.as_object_mut()) {
            init.insert("storage".into(), storage);
        }
        match channel.call(init) {
            Ok(hello) if compatible(&hello, persisted) => Ok(Self { channel, hello }),
            Ok(_) => {
                channel.close();
                Err("IncompatibleWorker")
            }
            Err(code) => {
                channel.close();
                Err(code)
            }
        }
    }

    pub(crate) fn capabilities(&self) -> Result<Value, &'static str> {
        if self.channel.is_closed() {
            return Err("Closed");
        }
        Ok(self.hello.clone())
    }

    pub(crate) fn call(&mut self, command: Value) -> Result<Value, &'static str> {
        self.channel.call(command)
    }

    /// Execution handoff commands need the worker to offer them.
    pub(crate) fn handoff_call(&mut self, command: Value) -> Result<Value, &'static str> {
        let offered = self.capabilities()?["capabilities"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(HANDOFF)));
        if !offered {
            return Err("IncompatibleWorker");
        }
        self.channel.call(command)
    }

    /// Grant one agent a view; returns the connection config the agent uses.
    pub(crate) fn grant(
        &mut self,
        view: Value,
        limits: Value,
        queue: Value,
        lease_ms: Value,
    ) -> Result<Value, &'static str> {
        let result = self.channel.call(json!({
            "op": "grant",
            "spec": {"view": view, "limits": limits, "lease_ms": lease_ms},
            "queue": queue,
        }))?;
        let epoch = &self.hello["epoch"];
        match exact(&result, &["epoch", "secret"]) {
            Some(grant)
                if grant["epoch"] == *epoch && is_hex64(epoch) && is_hex64(&grant["secret"]) =>
            {
                Ok(json!({
                    "schema": "cigar.broker-client.v1",
                    "host": "127.0.0.1",
                    "port": self.hello["port"],
                    "epoch": grant["epoch"],
                    "secret": grant["secret"],
                }))
            }
            _ => {
                self.channel.close();
                Err("Transport")
            }
        }
    }

    pub(crate) fn close(&mut self) {
        self.channel.close();
    }
}

fn compatible(hello: &Value, persisted: bool) -> bool {
    let number = |key: &str| hello.get(key).and_then(Value::as_u64);
    let text = |key: &str| hello.get(key).and_then(Value::as_str);
    let base = text("protocol") == Some(crate::BROKER_PROTOCOL)
        && text("core_version") == Some(crate::CORE_VERSION)
        && text("host") == Some("127.0.0.1")
        && number("port").is_some_and(|port| (1..=65_535).contains(&port))
        && hello.get("epoch").is_some_and(is_hex64)
        && number("max_frame_bytes") == Some(MAX_AGENT_FRAME as u64)
        && number("max_response_bytes") == Some(MAX_AGENT_RESPONSE as u64)
        && number("host_max_frame_bytes") == Some(MAX_HOST_FRAME as u64)
        && number("host_max_response_bytes") == Some(MAX_HOST_RESPONSE as u64)
        && hello.get("requires_hol_services") == Some(&Value::Bool(false))
        && text("execution") == Some("single-owner-fair-dispatch");
    let features = hello
        .get("capabilities")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().all(Value::is_string)
                && items
                    .iter()
                    .any(|item| item.as_str() == Some("mutual_grant_proof.v1"))
        });
    let stored = !persisted
        || hello
            .get("storage")
            .and_then(|stored| exact(stored, &["mode", "restored"]))
            .is_some_and(|stored| {
                stored["mode"].as_str() == Some("sqlite-checkpoint.v1")
                    && stored["restored"].is_boolean()
            });
    base && features && stored
}
