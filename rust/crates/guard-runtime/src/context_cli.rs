//! `hol-guard context …`: inspect and control CIGAR context assistance from a
//! terminal.
//!
//! The Python CLI resolves the Guard home and hands every argument to this
//! command; reading the arguments, asking the resident and writing the answer
//! all happen here. Control and version requests go to the resident's
//! `context_assistance` operation; `usage` and `lean` go to its runner
//! authority, the same way the dashboard reaches them.

use std::io::Write;

use serde_json::{json, Map, Value};

#[path = "context_cli_args.rs"]
mod args;
#[path = "context_cli_codex.rs"]
mod codex;
#[path = "context_cli_render.rs"]
mod render;
#[cfg(test)]
#[path = "context_cli_tests.rs"]
mod tests;

use args::{Command, Parsed};

pub(crate) const COMMAND: &str = "context";

const CLI_SCHEMA: &str = "guard-context-assistance-cli.v1";
const STATUS_SCHEMA: &str = "guard-context-assistance-status.v2";
const VERSIONS_SCHEMA: &str = "guard-cigar-versions-result.v1";
const HOME_UNAVAILABLE: &str = "native_context_assistance_home_unavailable";
const INVALID: &str = "native_context_assistance_payload_invalid";

/// Run `context` with the arguments after it; the process exit code.
pub(crate) fn run(argv: &[String]) -> i32 {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let code = match args::parse(argv) {
        Ok(Parsed::Help(text)) => {
            let _ = out.write_all(text.as_bytes());
            0
        }
        Ok(Parsed::Run(command)) => execute(&command, &mut out, &mut err),
        Err(message) => {
            let _ = writeln!(err, "{}", args::usage_line());
            let _ = writeln!(err, "hol-guard context: error: {message}");
            2
        }
    };
    let _ = out.flush();
    code
}

fn execute(command: &Command, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(home) = command.guard_home.as_deref() else {
        return unavailable(out, command.json, HOME_UNAVAILABLE);
    };
    match &command.action {
        args::Action::Usage => codex::usage(home, command.json, out, err),
        args::Action::Lean { action, limit } => {
            codex::lean(home, action, *limit, command.json, out)
        }
        args::Action::Control(kind) => match control(home, kind) {
            Ok(state) if command.json => print_json(out, &state),
            Ok(state) => {
                let _ = out.write_all(render::status(&state).as_bytes());
                0
            }
            Err(code) => unavailable(out, command.json, &code),
        },
        args::Action::Versions(input) => match versions(home, input) {
            Ok(answer) if command.json => print_json(out, &answer),
            Ok(answer) => {
                let _ = out.write_all(render::versions(&answer).as_bytes());
                0
            }
            Err(code) => unavailable(out, command.json, &code),
        },
    }
}

/// The engine state after a control request of `kind`.
fn control(home: &str, kind: &str) -> Result<Value, String> {
    let payload =
        crate::context_assistance_client::ask(home, &json!({"kind": kind, "input": {}}), false)?;
    state(&payload)
}

/// A version request's `result` with the engine state beside it.
fn versions(home: &str, input: &Map<String, Value>) -> Result<Value, String> {
    let payload = crate::context_assistance_client::ask(
        home,
        &json!({"kind": "versions", "input": input}),
        true,
    )?;
    let state = state(&payload)?;
    let data = payload.get("data").and_then(Value::as_object);
    match data {
        Some(data)
            if data.get("schema").and_then(Value::as_str) == Some(VERSIONS_SCHEMA)
                && data.get("result").is_some_and(Value::is_object) =>
        {
            let mut answer = data.clone();
            answer.insert("state".into(), state);
            Ok(Value::Object(answer))
        }
        _ => Err(INVALID.to_owned()),
    }
}

/// The payload's engine state, when it has the fields the CLI shows.
fn state(payload: &Map<String, Value>) -> Result<Value, String> {
    let state = payload.get("state").and_then(Value::as_object);
    let valid = state.is_some_and(|state| {
        let text = |field: &str| state.get(field).is_some_and(Value::is_string);
        let flag = |field: &str| state.get(field).is_some_and(Value::is_boolean);
        let or_null = |field: &str, kind: fn(&Value) -> bool| {
            state
                .get(field)
                .is_some_and(|value| value.is_null() || kind(value))
        };
        state.get("schema").and_then(Value::as_str) == Some(STATUS_SCHEMA)
            && text("availability")
            && text("generation")
            && flag("requested_enabled")
            && flag("effective_enabled")
            && or_null("diagnostic", Value::is_string)
            && or_null("job", Value::is_object)
            && or_null("installation_options", Value::is_array)
    });
    match state {
        Some(state) if valid => Ok(Value::Object(state.clone())),
        _ => Err(INVALID.to_owned()),
    }
}

fn print_json(out: &mut dyn Write, value: &Value) -> i32 {
    let _ = writeln!(out, "{value}");
    0
}

fn unavailable(out: &mut dyn Write, as_json: bool, code: &str) -> i32 {
    let _ = if as_json {
        writeln!(
            out,
            "{}",
            json!({"schema": CLI_SCHEMA, "status": "unavailable", "code": code})
        )
    } else if code == HOME_UNAVAILABLE {
        writeln!(
            out,
            "The local Guard context service could not be reached. Check this installation's Guard home."
        )
    } else {
        writeln!(
            out,
            "Context assistance unavailable ({code}). Guard protection remains available."
        )
    };
    1
}
