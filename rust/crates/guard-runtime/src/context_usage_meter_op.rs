//! `context_usage`: the meter for `hol-guard context usage`.
//!
//! The command passes the user's home and the two folder settings it was run
//! with; the Guard home is the one the resident verified for the request. The
//! answer is the meter's state, this week's CIGAR savings estimate and, when
//! asked, the text to print. The first count of a long history runs in the
//! background, so the command asks again while the state is `counting`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

/// The settings that move where Codex and Claude Code keep their records.
const SETTINGS: [(&str, &str); 2] = [
    ("codex_home", "CODEX_HOME"),
    ("claude_config_dir", "CLAUDE_CONFIG_DIR"),
];

fn optional_text<'a>(
    args: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, &'static str> {
    match args.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.as_str())),
        Some(_) => Err(ERR_INVALID),
    }
}

/// `{op: "read", home_dir, codex_home?, claude_config_dir?, text?}`.
pub(crate) fn dispatch(args: &Value, guard_home: &str) -> KindResult {
    let args = args_object(args)?;
    if args.get("op").and_then(Value::as_str) != Some("read") {
        return Err(ERR_INVALID);
    }
    let home = optional_text(args, "home_dir")?
        .filter(|home| Path::new(home).is_absolute())
        .map(PathBuf::from)
        .ok_or(ERR_INVALID)?;
    let mut env = HashMap::new();
    for (field, name) in SETTINGS {
        if let Some(value) = optional_text(args, field)?.filter(|value| !value.is_empty()) {
            env.insert(name.to_owned(), value.to_owned());
        }
    }
    let wants_text = match args.get("text") {
        None => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return Err(ERR_INVALID),
    };
    let guard_home = Path::new(guard_home);
    let state = super::read(&home, guard_home, env.clone());
    let report = if state.get("state").and_then(Value::as_str) == Some("ready") {
        let report = crate::context_assistance_savings::report::report(guard_home, &home, |name| {
            env.get(name).cloned()
        });
        serde_json::to_value(report).unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    let text =
        (wants_text && state["state"] == "ready").then(|| super::text::render(&state, &report));
    Ok(json!({"usage": state, "savings": report, "text": text}))
}
