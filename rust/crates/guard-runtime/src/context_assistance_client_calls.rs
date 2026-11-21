//! The two other resident requests Guard's CIGAR clients send: a `context_agent`
//! request for the MCP context tools and a `runner_authority` request for the
//! usage meter and the Codex config switches.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use guard_contracts::{
    RUNNER_AUTHORITY_MAX_BYTES, RUNNER_AUTHORITY_REQUEST_SCHEMA, RUNNER_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use super::{CODE_PREFIX, UNAVAILABLE};

const AGENT_REQUEST_SCHEMA: &str = "guard-context-agent-request.v1";
const AGENT_RESULT_SCHEMA: &str = "guard-context-agent-result.v1";
const AGENT_DATA_SCHEMA: &str = "guard-cigar-agent-data.v1";
const MAX_AGENT_REQUEST_BYTES: usize = 64 * 1024;
/// An agent request may compile context from the workspace.
const AGENT_TIMEOUT: Duration = Duration::from_secs(8);
const RUNNER_UNAVAILABLE: &str = "native_runner_authority_unavailable";

static CALL_IDS: AtomicU64 = AtomicU64::new(1);

/// One `context_agent` request: the `result` of the agent data, or the code.
pub(crate) fn agent(guard_home: &str, input: Value) -> Result<Value, String> {
    let request = json!({
        "schema": AGENT_REQUEST_SCHEMA,
        "request_id": call_id("context-agent"),
        "query": {"kind": "agent", "guard_home": guard_home, "input": input},
    });
    let digest =
        crate::package_authority_op::request_digest_with_limit(&request, MAX_AGENT_REQUEST_BYTES)
            .map_err(|_| format!("{CODE_PREFIX}request_invalid"))?;
    let payload = send(
        guard_home,
        "context_agent",
        &request,
        AGENT_RESULT_SCHEMA,
        &digest,
        AGENT_TIMEOUT,
        MAX_AGENT_REQUEST_BYTES,
    )
    .map_err(|code| engine_code(code, UNAVAILABLE))?;
    let Value::Object(mut payload) = payload else {
        return Err(UNAVAILABLE.to_owned());
    };
    if payload.get("kind").and_then(Value::as_str) != Some("agent") {
        return Err(UNAVAILABLE.to_owned());
    }
    let invalid = || format!("{CODE_PREFIX}payload_invalid");
    let Some(Value::Object(mut data)) = payload.remove("data") else {
        return Err(invalid());
    };
    if data.get("schema").and_then(Value::as_str) != Some(AGENT_DATA_SCHEMA)
        || data.get("data_role") != Some(&Value::Bool(true))
    {
        return Err(invalid());
    }
    match data.remove("result") {
        Some(result @ Value::Object(_)) => Ok(result),
        _ => Err(invalid()),
    }
}

/// One `runner_authority` request of `kind`: its payload, or the code.
pub(crate) fn runner_authority(
    guard_home: &str,
    kind: &str,
    args: Value,
    timeout: Duration,
) -> Result<Value, String> {
    let request = json!({
        "schema": RUNNER_AUTHORITY_REQUEST_SCHEMA,
        "request_id": call_id("context-cli"),
        "guard_home": guard_home,
        "kind": kind,
        "args": args,
    });
    let mut canonical = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(
        &request,
        &mut canonical,
        RUNNER_AUTHORITY_MAX_BYTES,
    )
    .map_err(|_| RUNNER_UNAVAILABLE.to_owned())?;
    let digest = guard_policy_snapshot::digest_bytes(&canonical);
    send(
        guard_home,
        "runner_authority",
        &request,
        RUNNER_AUTHORITY_RESULT_SCHEMA,
        &digest,
        timeout,
        RUNNER_AUTHORITY_MAX_BYTES,
    )
    .map_err(|code| code.unwrap_or_else(|| RUNNER_UNAVAILABLE.to_owned()))
}

/// Send `request` as `operation` and return the payload of the reply bound
/// to it. `Err(Some(code))` is the resident's refusal; `Err(None)` is no
/// usable reply.
fn send(
    guard_home: &str,
    operation: &str,
    request: &Value,
    result_schema: &str,
    digest: &str,
    timeout: Duration,
    max_bytes: usize,
) -> Result<Value, Option<String>> {
    let deadline = Instant::now() + timeout;
    let encoded = serde_json::to_vec(&json!({
        "operation": operation,
        "deadline_budget_ms": u64::try_from(timeout.as_millis()).unwrap_or(1).max(1),
        "request": request,
    }))
    .map_err(|_| None)?;
    if encoded.len() > max_bytes {
        return Err(None);
    }
    let state_dir = std::fs::canonicalize(Path::new(guard_home))
        .map_err(|_| None)?
        .join("native-runtime");
    let remaining = deadline.saturating_duration_since(Instant::now());
    let output = crate::managed_resident::client_request(&state_dir, &encoded, remaining)
        .map_err(|_| None)?;
    let Value::Object(mut envelope) = serde_json::from_slice(&output).map_err(|_| None)? else {
        return Err(None);
    };
    if envelope.get("schema").and_then(Value::as_str) != Some(result_schema)
        || envelope.get("request_id") != request.get("request_id")
        || envelope.get("request_sha256").and_then(Value::as_str) != Some(digest)
    {
        return Err(None);
    }
    let code = envelope
        .get("code")
        .and_then(Value::as_str)
        .map(str::to_owned);
    match envelope.get("status").and_then(Value::as_str) {
        Some("ok") if code.as_deref() == Some("ok") => envelope.remove("payload").ok_or(None),
        Some("error") => Err(code),
        _ => Err(None),
    }
}

/// A refusal code inside the engine's namespace, or `fallback`.
fn engine_code(code: Option<String>, fallback: &str) -> String {
    code.filter(|code| {
        code.strip_prefix(CODE_PREFIX).is_some_and(|rest| {
            (1..=64).contains(&rest.len())
                && rest
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
    })
    .unwrap_or_else(|| fallback.to_owned())
}

fn call_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!(
        "{prefix}-{}-{nanos:x}-{}",
        std::process::id(),
        CALL_IDS.fetch_add(1, Ordering::Relaxed)
    )
}
