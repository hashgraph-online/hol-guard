//! The Guard MCP server's CIGAR context tools.
//!
//! The Python MCP server starts one `context-mcp` process per MCP connection
//! and keeps it for the connection's life. Each step is one JSON line on
//! stdin, answered by one JSON line on stdout:
//!
//! - `{"op":"catalog"}`: every context tool's definition.
//! - `{"op":"tools"}`: the tools this connection may use now.
//! - `{"op":"call","name":…,"arguments":{…}}`: one tool call's text result.
//! - `{"op":"close"}`: end the connection's pairing and exit.
//!
//! The pairing session lives only in this process: the private credential the
//! resident issues is never sent to Python, a tool argument or a result. The
//! process holds a resident lease while it runs, so the resident and its
//! memory-only pairing stay up between calls. A begin whose outcome is
//! unknown is not retried: a lost pairing needs a fresh MCP process and a
//! person to pair it again. End of input closes the pairing like `close`.

use std::io::{BufRead, Read, Write};

use serde_json::{json, Map, Value};

use crate::managed_resident::HeldLease;

#[path = "context_mcp_catalog.rs"]
mod catalog;
#[cfg(test)]
#[path = "context_mcp_tests.rs"]
mod tests;

pub(crate) const COMMAND: &str = "context-mcp";

const MAX_LINE_BYTES: u64 = 256 * 1024;
const UNAVAILABLE: &str = "native_context_assistance_unavailable";
const INVALID: &str = "native_context_assistance_payload_invalid";
const ERROR_MESSAGE: &str = "Context is unavailable or this connection needs current \
human-approved workspace access. Guard approvals remain independent.";

/// The resident's `context_agent` request, replaceable in tests.
pub(crate) type Ask<'a> = dyn FnMut(Value) -> Result<Value, String> + 'a;

/// `context-mcp --guard-home HOME`: answer requests until `close` or the end
/// of input; the exit code.
pub(crate) fn run(argv: &[String]) -> i32 {
    let home = match argv {
        [flag, home] if flag == "--guard-home" => home.clone(),
        _ => {
            eprintln!("usage: hol-guard-runtime context-mcp --guard-home GUARD_HOME");
            return 2;
        }
    };
    let mut held: Option<HeldLease> = None;
    let mut ask = |message: Value| {
        if held.is_none() {
            held = crate::context_assistance_client::state_dir(&home)
                .and_then(|dir| HeldLease::acquire(&dir).ok());
        }
        crate::context_assistance_client::agent(&home, message, held.as_ref())
    };
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    // `held` outlives `serve`, so the lease is released only after the
    // pairing is closed.
    serve(&mut input, &mut out, &mut ask)
}

/// Answer each line of `input` on `out` with one session.
pub(crate) fn serve(input: &mut dyn BufRead, out: &mut dyn Write, ask: &mut Ask<'_>) -> i32 {
    let mut session = Session::default();
    loop {
        let mut line = Vec::new();
        let read = Read::take(&mut *input, MAX_LINE_BYTES + 1).read_until(b'\n', &mut line);
        let request = match read {
            Ok(0) | Err(_) => break,
            Ok(_) if line.len() as u64 > MAX_LINE_BYTES => break,
            Ok(_) if line.iter().all(u8::is_ascii_whitespace) => continue,
            Ok(_) => serde_json::from_slice::<Value>(&line).unwrap_or(Value::Null),
        };
        let reply = answer(&request, &mut session, ask);
        if writeln!(out, "{reply}").and_then(|()| out.flush()).is_err() {
            break;
        }
        if request.get("op").and_then(Value::as_str) == Some("close") {
            return 0;
        }
    }
    session.close(ask);
    0
}

/// The private pairing state of one MCP process.
#[derive(Default)]
struct Session {
    credential: Option<String>,
    started: bool,
}

impl Session {
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

    /// End the pairing, if any. Finite native leases still expire after
    /// process loss.
    fn close(&mut self, ask: &mut Ask<'_>) {
        if let Some(credential) = self.credential.take() {
            let _ = ask(json!({"action": "close", "credential": credential}));
        }
    }
}

/// The answer to one request.
fn answer(request: &Value, session: &mut Session, ask: &mut Ask<'_>) -> Value {
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
            json!({"tools": tools})
        }
        Some("call") => {
            let name = request.get("name").and_then(Value::as_str).unwrap_or("");
            let Some(action) = catalog::action(name) else {
                return json!({"known": false});
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
            json!({"known": true, "text": envelope(result)})
        }
        Some("close") => {
            session.close(ask);
            json!({"closed": true})
        }
        _ => json!({"error": "unknown_op"}),
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
