//! Resident-only secret execution. The request names a sink and approval
//! binding. The secret itself is read and consumed entirely in Rust.

use serde::Deserialize;
use serde_json::json;

use crate::secret_broker::{self, Request as BrokerRequest};
use crate::secret_delivery::{self, Sink};

pub(crate) const COMMAND: &str = "secret-exec";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    broker: BrokerRequest,
    program: String,
    #[serde(default)]
    args: Vec<String>,
    approval_binding: String,
}

pub(crate) fn run_command(bytes: &[u8]) -> serde_json::Value {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return refusal("secret_request_invalid");
    };
    let mut broker = request.broker;
    broker.approval_binding = Some(request.approval_binding.clone());
    let secret = match secret_broker::resolve_native(&broker) {
        Ok(secret) => secret,
        Err(error) => return refusal(&error),
    };
    let sink = match broker.sink.as_str() {
        "environment" => Sink::Environment(broker.destination.clone()),
        "stdin" => Sink::Stdin,
        "file_descriptor" => Sink::FileDescriptor,
        _ => return refusal("secret_sink_unsupported"),
    };
    match secret_delivery::deliver(&secret.value, &request.program, &request.args, sink) {
        Ok(result) => json!({
            "ok": true,
            "status": result.status,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "redacted": result.redacted,
            "binding_digest": secret.binding.digest(),
        }),
        Err(error) => refusal(&error),
    }
}

fn refusal(error: &str) -> serde_json::Value {
    json!({"ok": false, "error": error})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_request_is_value_free() {
        let result = run_command(br#"{"broker":{},"program":"fixture","approval_binding":"x"}"#);
        assert_eq!(result["ok"], false);
        assert!(!result.to_string().contains("fixture-value-7"));
    }
}
