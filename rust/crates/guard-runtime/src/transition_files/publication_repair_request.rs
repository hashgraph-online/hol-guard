//! `publication_repair_request_plan`: the checks a captured repair request
//! must pass before its plan is rebuilt, ported from
//! `codex_hook_repair_request._plan_from_payload`, `_checked_files` and the
//! binding shape of `_inverse_from_payload`.
//!
//! A request artifact preserves a plan between preparation and approval.
//! Loading it never grants repair or selects another runtime: the plan must
//! be exactly the one the runtime derives from the same files, so a
//! normalization that would change a reviewed plan is refused.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::publication::Call;
use super::publication_repair_plan::{payload, ACTION, SCHEMA};
use super::{Fault, Step};

const MAX_FILES: usize = 128;
const PLAN_INVALID: Fault = Fault::Transition("authority_repair_request_plan_invalid");
const CONTEXT_INVALID: Fault = Fault::Transition("authority_repair_request_context_invalid");
const FILES_INVALID: Fault = Fault::Transition("files_invalid");
const KEYS: [&str; 8] = [
    "schema",
    "action",
    "guard_home",
    "config_path",
    "operation_id",
    "files",
    "native_runtime",
    "verification_workspace",
];

/// The runtime a plan names: exactly its path, size, mtime and digest.
fn native_shape(value: Option<&Value>) -> bool {
    let Some(Value::Object(native)) = value else {
        return false;
    };
    let integer = |key: &str| {
        native
            .get(key)
            .is_some_and(|number| number.is_i64() || number.is_u64())
    };
    let text = |key: &str| native.get(key).is_some_and(Value::is_string);
    native.len() == 4 && text("path") && text("sha256") && integer("size") && integer("mtime_ns")
}

/// `_checked_files`: one to 128 changes that form one transition record.
fn checked_files(value: Option<&Value>) -> Step<&Vec<Value>> {
    let files = value
        .and_then(Value::as_array)
        .filter(|files| !files.is_empty() && files.len() <= MAX_FILES)
        .filter(|files| files.iter().all(Value::is_object))
        .ok_or(FILES_INVALID)?;
    crate::runtime_transition_record::check_files(files)
        .map_err(|(reason, detail)| Fault::Refused(reason, detail))?;
    Ok(files)
}

/// The answer to one request: `kind` is `repair` for a missing-manifest
/// repair plan and `inverse` for a publication inverse plan, whose binding
/// the caller rebuilds from its own journal.
pub(super) fn plan(call: &mut Call<'_>) -> Step<Value> {
    let value = call.args.get("payload").ok_or(PLAN_INVALID)?;
    match call.text("kind")? {
        "repair" => repair(call, value),
        "inverse" => inverse(value),
        _ => Err(FILES_INVALID),
    }
}

/// The binding every inverse request carries, before it is rebuilt.
fn inverse(value: &Value) -> Step<Value> {
    let Value::Object(object) = value else {
        return Err(PLAN_INVALID);
    };
    let text = |key: &str| object.get(key).is_some_and(Value::is_string);
    if !native_shape(object.get("native_runtime"))
        || !text("operation_id")
        || !text("verification_workspace")
    {
        return Err(PLAN_INVALID);
    }
    Ok(Value::Null)
}

/// `_plan_from_payload`: answers which of the files is the manifest change.
fn repair(call: &Call<'_>, value: &Value) -> Step<Value> {
    let Value::Object(object) = value else {
        return Err(PLAN_INVALID);
    };
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(PLAN_INVALID);
    }
    let home = call.text("guard_home")?.to_owned();
    let config = call.text("config_path")?.to_owned();
    let text = |key: &str| object.get(key).and_then(Value::as_str);
    if text("schema") != Some(SCHEMA)
        || text("action") != Some(ACTION)
        || text("guard_home") != Some(home.as_str())
        || text("config_path") != Some(config.as_str())
        || text("operation_id").is_none()
        || text("verification_workspace").is_none()
    {
        return Err(CONTEXT_INVALID);
    }
    if !native_shape(object.get("native_runtime")) {
        return Err(PLAN_INVALID);
    }
    let files = checked_files(object.get("files"))?;
    let canonical = call.canonical(Path::new(&config))?;
    let (manifest, _) = Call::targets(Path::new(&home), &canonical);
    let changes: Vec<usize> = files
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            item.get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| Path::new(path) == manifest.as_path())
        })
        .map(|(index, _)| index)
        .collect();
    let [index] = changes.as_slice() else {
        return Err(PLAN_INVALID);
    };
    let index = *index;
    let mut args = Map::new();
    args.insert("operation_id".to_owned(), field(object, "operation_id"));
    args.insert("home".to_owned(), json!(home));
    args.insert("config".to_owned(), json!(config));
    args.insert("files".to_owned(), Value::Array(files.clone()));
    args.insert("change".to_owned(), files[index].clone());
    args.insert("native_runtime".to_owned(), field(object, "native_runtime"));
    args.insert(
        "verification_workspace".to_owned(),
        field(object, "verification_workspace"),
    );
    // Refuse normalization that silently changes a reviewed payload.
    if Value::Object(payload(&args)?) != *value {
        return Err(PLAN_INVALID);
    }
    Ok(json!({ "change": index }))
}

fn field(object: &Map<String, Value>, key: &str) -> Value {
    object.get(key).cloned().unwrap_or(Value::Null)
}
