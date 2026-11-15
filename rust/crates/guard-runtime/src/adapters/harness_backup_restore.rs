//! `runner_authority` kind `harness_backup_restore`: what uninstall does with
//! the config Guard backed up before it installed (`parse_backup_payload` in
//! `guard/adapters/state_files.py` and the restore branches of the Cursor
//! hooks and Copilot uninstalls before they moved here).
//!
//! Python reads and decodes the backup file and checks whether the target
//! exists, then writes or removes the target as told. Only facts cross the
//! boundary, so a config of any size restores: the request is
//! `{"envelope": {"existed": bool, "has_content": bool} | null,
//! "target_exists": bool}`, with `null` when the backup could not be read or
//! is not a JSON object. `existed` is true only when the envelope's `existed`
//! is `true`, and `has_content` only when its `content` is a string. The
//! answer is `{"action": "write" | "unlink" | "keep", "restored": bool}`:
//! write the saved content back, remove the config Guard created, or leave the
//! target alone. `restored` says whether the backup was fully applied, so the
//! caller may delete the backup and its state.

use serde_json::{json, Map, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    exact_keys(fields, &["envelope", "target_exists"])?;
    let envelope = match &fields["envelope"] {
        Value::Null => None,
        Value::Object(envelope) => {
            exact_keys(envelope, &["existed", "has_content"])?;
            let flag = |key: &str| envelope[key].as_bool().ok_or(ERR_INVALID);
            Some((flag("existed")?, flag("has_content")?))
        }
        _ => return Err(ERR_INVALID),
    };
    let target_exists = fields["target_exists"].as_bool().ok_or(ERR_INVALID)?;
    Ok(plan(envelope, target_exists))
}

fn exact_keys(fields: &Map<String, Value>, keys: &[&str]) -> Result<(), &'static str> {
    if fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key)) {
        Ok(())
    } else {
        Err(ERR_INVALID)
    }
}

fn plan(envelope: Option<(bool, bool)>, target_exists: bool) -> Value {
    let answer = |action: &str, restored: bool| json!({"action": action, "restored": restored});
    match envelope {
        None => answer("keep", false),
        Some((true, true)) => answer("write", true),
        Some((true, false)) => answer("keep", false),
        Some((false, _)) if target_exists => answer("unlink", true),
        Some((false, _)) => answer("keep", true),
    }
}
