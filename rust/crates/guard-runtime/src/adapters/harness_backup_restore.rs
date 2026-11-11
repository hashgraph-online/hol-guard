//! `runner_authority` kind `harness_backup_restore`: what uninstall does with
//! the config Guard backed up before it installed (`parse_backup_payload` in
//! `guard/adapters/state_files.py` and the restore branches of the Cursor
//! hooks and Copilot uninstalls before they moved here).
//!
//! Python reads the backup file and checks whether the target exists, then
//! writes or removes the target as told. The request is
//! `{"backup": text | null, "target_exists": bool}`, with `null` when the
//! backup could not be read. The answer is
//! `{"action": "write" | "unlink" | "keep", "content": text | null,
//! "restored": bool}`: write the saved config back, remove the config Guard
//! created, or leave the target alone. `restored` says whether the backup was
//! fully applied, so the caller may delete the backup and its state.
//!
//! Python's decoder also accepted `NaN` and `Infinity`; a backup holding one
//! reads as unreadable here, and Guard never writes one.

use serde_json::{json, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 2] = ["backup", "target_exists"];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    if fields.len() != KEYS.len() || !KEYS.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let backup = match &fields["backup"] {
        Value::Null => None,
        Value::String(text) => Some(text.as_str()),
        _ => return Err(ERR_INVALID),
    };
    let target_exists = fields["target_exists"].as_bool().ok_or(ERR_INVALID)?;
    Ok(plan(backup, target_exists))
}

fn plan(backup: Option<&str>, target_exists: bool) -> Value {
    let keep = |restored: bool| json!({"action": "keep", "content": null, "restored": restored});
    let Some(Value::Object(envelope)) = backup.and_then(|text| serde_json::from_str(text).ok())
    else {
        return keep(false);
    };
    let existed = envelope.get("existed") == Some(&Value::Bool(true));
    match envelope.get("content") {
        Some(Value::String(content)) if existed => {
            json!({"action": "write", "content": content, "restored": true})
        }
        _ if existed => keep(false),
        _ if target_exists => json!({"action": "unlink", "content": null, "restored": true}),
        _ => keep(true),
    }
}
