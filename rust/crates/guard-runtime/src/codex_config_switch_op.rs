//! `codex_config`: the Codex config switches for `hol-guard context lean`.
//!
//! The command passes the user's home and `CODEX_HOME` as it was run, already
//! made absolute against its own working folder; the Guard home is the one the
//! resident verified for the request. The answer is the switch's state or the
//! code of what stopped it and, when asked, the text to print.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{change, render_lean, render_lean_failure, status, Homes, Switch};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

/// `{switch: "lean" | "short_replies", action, home_dir, codex_home?, limit?,
/// text?}`.
pub(crate) fn dispatch(args: &Value, guard_home: &str) -> KindResult {
    let args = args_object(args)?;
    let switch = match args.get("switch").and_then(Value::as_str) {
        Some("lean") => Switch::Lean,
        Some("short_replies") => Switch::ShortReplies,
        _ => return Err(ERR_INVALID),
    };
    let action = args
        .get("action")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let allowed = match switch {
        Switch::Lean => ["status", "enable", "disable"].contains(&action),
        Switch::ShortReplies => ["status", "enable", "disable", "ensure"].contains(&action),
    };
    if !allowed {
        return Err(ERR_INVALID);
    }
    let home_dir = args
        .get("home_dir")
        .and_then(Value::as_str)
        .filter(|home| Path::new(home).is_absolute())
        .map(PathBuf::from)
        .ok_or(ERR_INVALID)?;
    let codex_home = match args.get("codex_home") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(_) => return Err(ERR_INVALID),
    };
    let wants_text = match args.get("text") {
        None => false,
        Some(Value::Bool(flag)) => *flag && switch == Switch::Lean,
        Some(_) => return Err(ERR_INVALID),
    };
    let homes = Homes {
        guard_home: PathBuf::from(guard_home),
        home_dir,
        codex_home,
    };
    let answer = if action == "status" {
        status(switch, &homes)
    } else {
        change(switch, &homes, action, args.get("limit"))
    };
    Ok(match answer {
        Ok(state) => {
            let text = wants_text.then(|| render_lean(&state));
            json!({"ok": true, "state": state, "text": text})
        }
        Err(code) => {
            let text = wants_text.then(|| render_lean_failure(&code));
            json!({"ok": false, "code": code, "text": text})
        }
    })
}
