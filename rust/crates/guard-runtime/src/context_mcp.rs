//! The Guard MCP server's CIGAR context tools.
//!
//! The Python MCP server keeps one opaque session per MCP process and sends
//! each step here as one JSON line on stdin:
//!
//! - `{"op":"catalog"}`: every context tool's definition.
//! - `{"op":"tools","session":…}`: the tools this connection may use now.
//! - `{"op":"call","session":…,"name":…,"arguments":{…}}`: one tool call's
//!   text result.
//! - `{"op":"close","session":…}`: end the connection's pairing.
//!
//! Each answer carries the session back. The session holds the private
//! credential the resident issued this MCP process; it is never a tool
//! argument or result. A begin whose outcome is unknown is not retried: a lost
//! pairing needs a fresh MCP process and a person to pair it again.

use std::io::{Read, Write};

use serde_json::{json, Map, Value};

#[path = "context_mcp_catalog.rs"]
mod catalog;
#[cfg(test)]
#[path = "context_mcp_tests.rs"]
mod tests;

pub(crate) const COMMAND: &str = "context-mcp";

const MAX_INPUT_BYTES: u64 = 256 * 1024;
const UNAVAILABLE: &str = "native_context_assistance_unavailable";
const INVALID: &str = "native_context_assistance_payload_invalid";
const ERROR_MESSAGE: &str = "Context is unavailable or this connection needs current \
human-approved workspace access. Guard approvals remain independent.";

/// The resident's `context_agent` request, replaceable in tests.
pub(crate) type Ask<'a> = dyn FnMut(Value) -> Result<Value, String> + 'a;

/// `context-mcp --guard-home HOME`, one request on stdin; the exit code.
pub(crate) fn run(argv: &[String]) -> i32 {
    let home = match argv {
        [flag, home] if flag == "--guard-home" => home.clone(),
        _ => {
            eprintln!("usage: hol-guard-runtime context-mcp --guard-home GUARD_HOME");
            return 2;
        }
    };
    let mut input = Vec::new();
    if std::io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut input)
        .is_err()
        || input.len() as u64 > MAX_INPUT_BYTES
    {
        return 2;
    }
    let Ok(request) = serde_json::from_slice::<Value>(&input) else {
        return 2;
    };
    let mut ask = |message: Value| crate::context_assistance_client::agent(&home, message);
    let answer = answer(&request, &mut ask);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = writeln!(out, "{answer}");
    let _ = out.flush();
    0
}

/// The private pairing state of one MCP process.
#[derive(Default)]
struct Session {
    credential: Option<String>,
    started: bool,
}

impl Session {
    fn read(value: Option<&Value>) -> Self {
        let credential = value
            .and_then(|session| session.get("credential"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let started = value
            .and_then(|session| session.get("started"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Self {
            credential,
            started,
        }
    }

    fn value(&self) -> Value {
        json!({"credential": self.credential, "started": self.started})
    }

    /// Pair once when context is available: discover, then begin at most once.
    fn ensure(&mut self, ask: &mut Ask<'_>) -> Result<(), String> {
        let discovery = ask(json!({"action": "discover"}))?;
        if discovery.get("available") != Some(&Value::Bool(true)) {
            self.credential = None;
            return Ok(());
        }
        if self.credential.is_none() && !self.started {
            self.started = true;
            let private = ask(json!({"action": "begin"}))?;
            match private.get("credential").and_then(Value::as_str) {
                Some(credential) if credential.len() == 64 => {
                    self.credential = Some(credential.to_owned());
                }
                _ => return Err(INVALID.to_owned()),
            }
        }
        Ok(())
    }

    /// The tool names this connection may use now; none when unpaired.
    fn allowed(&mut self, ask: &mut Ask<'_>) -> Result<Vec<String>, String> {
        self.ensure(ask)?;
        let Some(credential) = self.credential.clone() else {
            return Ok(Vec::new());
        };
        let state = ask(json!({"action": "status", "credential": credential, "arguments": {}}))?;
        let names = state
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| INVALID.to_owned())?;
        names
            .iter()
            .map(|name| match name.as_str() {
                Some(name) if catalog::action(name).is_some() => Ok(name.to_owned()),
                _ => Err(INVALID.to_owned()),
            })
            .collect()
    }
}

/// The answer to one request.
pub(crate) fn answer(request: &Value, ask: &mut Ask<'_>) -> Value {
    let mut session = Session::read(request.get("session"));
    match request.get("op").and_then(Value::as_str) {
        Some("catalog") => json!({"tools": catalog::definitions()}),
        Some("tools") => {
            let allowed = session.allowed(ask).unwrap_or_default();
            let tools: Vec<Value> = catalog::definitions()
                .into_iter()
                .filter(|tool| {
                    tool.get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| allowed.iter().any(|allowed| allowed == name))
                })
                .collect();
            json!({"session": session.value(), "tools": tools})
        }
        Some("call") => {
            let name = request.get("name").and_then(Value::as_str).unwrap_or("");
            let Some(action) = catalog::action(name) else {
                return json!({"session": session.value(), "known": false});
            };
            let arguments = request
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new()));
            let result = session.ensure(ask).and_then(|()| {
                ask(json!({
                    "action": action,
                    "credential": session.credential.clone().unwrap_or_default(),
                    "arguments": arguments,
                }))
            });
            json!({"session": session.value(), "known": true, "text": envelope(result)})
        }
        Some("close") => {
            if let Some(credential) = session.credential.take() {
                // Finite native leases still expire after process loss.
                let _ = ask(json!({"action": "close", "credential": credential}));
            }
            json!({"session": session.value()})
        }
        _ => json!({"session": session.value(), "error": "unknown_op"}),
    }
}

/// A tool call's text result: the data, or the refusal code and a fixed
/// message that grants nothing.
fn envelope(result: Result<Value, String>) -> String {
    match result {
        Ok(data) => json!({"ok": true, "data_role": true, "data": data}).to_string(),
        Err(code) => {
            let code = if code.is_empty() {
                UNAVAILABLE.to_owned()
            } else {
                code
            };
            json!({
                "ok": false,
                "data_role": true,
                "error": {"code": code, "message": ERROR_MESSAGE},
            })
            .to_string()
        }
    }
}
