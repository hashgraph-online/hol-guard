//! The request/answer side of `runner_authority` kind `grok_user_config`: it
//! validates the request, runs the merge steps of `grok_user_config` through
//! the byte-exact editor and, for a layout that editor does not handle, the
//! semantic one, and shapes the answer Python reads.

use serde_json::{json, Value};
use toml::{Table, Value as Toml};

use super::grok_toml_engine::Eng;
use super::grok_toml_semantic::Semantic;
use super::grok_user_config::{candidates, prepare, remove_owned, Editor, Fail, Res};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const INVALID_TOML: &str = "Grok config is not valid TOML.";
const NOT_SURVIVED: &str = "Grok settings did not survive TOML serialization.";

const READ_KEYS: &[&str] = &["existing_text", "mode", "previous_state"];
const MERGE_KEYS: &[&str] = &[
    "existing_text",
    "hook_command",
    "mode",
    "previous_state",
    "retired_commands",
];

enum Mode {
    Candidates,
    Merge,
    Remove,
}

struct Request<'a> {
    mode: Mode,
    text: &'a str,
    state: &'a Value,
    command: &'a str,
    retired: Vec<String>,
}

fn parse(args: &Value) -> Result<Request<'_>, &'static str> {
    let map = args_object(args)?;
    let string = |key: &str| map.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let (mode, keys) = match string("mode")? {
        "candidates" => (Mode::Candidates, READ_KEYS),
        "remove" => (Mode::Remove, READ_KEYS),
        "merge" => (Mode::Merge, MERGE_KEYS),
        _ => return Err(ERR_INVALID),
    };
    if map.len() != keys.len() || !keys.iter().all(|key| map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let state = map
        .get("previous_state")
        .filter(|value| value.is_object())
        .ok_or(ERR_INVALID)?;
    let (command, retired) = match mode {
        Mode::Merge => {
            let listed = map
                .get("retired_commands")
                .and_then(Value::as_array)
                .ok_or(ERR_INVALID)?;
            let retired = listed
                .iter()
                .map(|item| item.as_str().map(str::to_string).ok_or(ERR_INVALID))
                .collect::<Result<Vec<_>, _>>()?;
            (string("hook_command")?, retired)
        }
        _ => ("", Vec::new()),
    };
    Ok(Request {
        mode,
        text: string("existing_text")?,
        state,
        command,
        retired,
    })
}

/// The document without empty tables or arrays, which a rendering may drop.
fn pruned(table: Table) -> Table {
    let mut kept = Table::new();
    for (key, value) in table {
        match value {
            Toml::Table(inner) => {
                let inner = pruned(inner);
                if !inner.is_empty() {
                    kept.insert(key, Toml::Table(inner));
                }
            }
            Toml::Array(list) if list.is_empty() => {}
            other => {
                kept.insert(key, other);
            }
        }
    }
    kept
}

fn run<E: Editor>(ed: &mut E, request: &Request<'_>) -> Res<Value> {
    let before = ed.sem().clone();
    let outcome = match request.mode {
        Mode::Candidates => {
            remove_owned(ed, request.state)?;
            return Ok(json!({ "commands": candidates(ed.sem()) }));
        }
        Mode::Remove => {
            remove_owned(ed, request.state)?;
            None
        }
        Mode::Merge => Some(prepare(
            ed,
            request.command,
            request.state,
            &request.retired,
        )?),
    };
    let text = ed.text();
    let Ok(parsed) = text.parse::<Table>() else {
        return Err(Fail::Mismatch);
    };
    // Removal is not checked by the Python merge and may leave an emptied
    // array of tables that no longer renders; only a merge must match exactly.
    let same = match request.mode {
        Mode::Merge => parsed == *ed.sem(),
        _ => pruned(parsed) == pruned(ed.sem().clone()),
    };
    if !same {
        return Err(Fail::Mismatch);
    }
    Ok(match outcome {
        Some(state) => {
            let merged = if before == *ed.sem() {
                request.text.to_string()
            } else {
                text
            };
            json!({ "merged": merged, "state": state })
        }
        None => json!({ "text": text }),
    })
}

fn answer(request: &Request<'_>) -> Result<Value, String> {
    if request.text.starts_with('\u{feff}') {
        return Err(INVALID_TOML.to_string());
    }
    let sem: Table = request.text.parse().map_err(|_| INVALID_TOML.to_string())?;
    let first = run(&mut Eng::new(request.text, sem.clone()), request);
    let outcome = match first {
        Err(Fail::Unsupported | Fail::Mismatch) => {
            Semantic::new(request.text, sem).and_then(|mut ed| run(&mut ed, request))
        }
        settled => settled,
    };
    outcome.map_err(|fail| match fail {
        Fail::Error(message) => message,
        Fail::Unsupported | Fail::Mismatch => NOT_SURVIVED.to_string(),
    })
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let request = parse(args)?;
    Ok(answer(&request).unwrap_or_else(|message| json!({ "error": message })))
}
