//! Codex: a whole uninstall in one op, ported from
//! `CodexHarnessAdapter._uninstall_owned`.
//!
//! The caller holds installation ownership and has recovered any pending
//! publication. This op plans the uninstall (`uninstall_plan`), checks that
//! every compared file still holds what the plan captured, publishes the plan
//! with its removals, journals the receipt and manifest removals as they are
//! written, and removes the hook key once no manifest uses it.
//!
//! Request fields: `uninstall_plan`'s (`owned`, `authority_files` and the
//! owner fields) plus `package_roots` and `budget`.
//! Answer: `events` (the journal records, in order) and either `manifest`
//! (the launcher manifest) or what stopped it: `reply`, `fault` (a
//! transition fault) or `key_error` (the hook key's refusal reason).

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::codex_alternate_plan::decoded;
use super::codex_install::{remove_unused_key, stopped, text, transition};
use super::codex_install_plan::wire_file;
use super::codex_uninstall_plan::uninstall_plan;
use super::{Ctx, Failure, Step};

/// The journal record `record_codex_mutation` writes for a removed file.
fn removal(operation: &str, change: &Value) -> Step<Value> {
    let before = decoded(change.get("before"))?;
    Ok(json!({ "mutation": {
        "operation": operation,
        "path": change.get("path").cloned().ok_or(Failure::Invalid)?,
        "before_present": before.is_some(),
        "after_present": false,
        "before_digest": before.map(|data| hex::encode(Sha256::digest(data))),
        "after_digest": null,
    }}))
}

/// `PreparedHarnessInstall.publish(removals=True, on_write=audit)`: the
/// mutation records in order, each authority file's removal journaled just
/// after it is written.
fn publish(
    fields: &Map<String, Value>,
    files: &[Value],
    authority: &[(Value, &str)],
    events: &mut Vec<Value>,
) -> Step<Result<(), Value>> {
    let mut request = Map::new();
    for key in ["package_roots", "budget"] {
        if let Some(value) = fields.get(key) {
            request.insert(key.into(), value.clone());
        }
    }
    request.insert("op".into(), json!("publish"));
    request.insert("files".into(), Value::Array(files.to_vec()));
    request.insert("removals".into(), json!(true));
    request.insert("rollback".into(), json!(true));
    let invalid = || json!({ "transition": "native_transition_invalid" });
    let Ok(answer) = crate::transition_files::dispatch(&Value::Object(request)) else {
        return Ok(Err(invalid()));
    };
    for event in answer
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if event.get("mutation").is_some() {
            events.push(event.clone());
            continue;
        }
        let Some(change) = event
            .get("written")
            .and_then(Value::as_u64)
            .and_then(|index| files.get(usize::try_from(index).ok()?))
        else {
            continue;
        };
        if let Some((_, operation)) = authority
            .iter()
            .find(|(path, _)| Some(path) == change.get("path"))
        {
            events.push(removal(operation, change)?);
        }
    }
    if let Some(error) = answer.get("restore_error").or_else(|| answer.get("error")) {
        return Ok(Err(error.clone()));
    }
    if answer.get("ok").and_then(Value::as_bool) != Some(true) {
        return Ok(Err(invalid()));
    }
    Ok(Ok(()))
}

/// `uninstall`.
pub(super) fn uninstall(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut events = Vec::new();
    let plan = uninstall_plan(ctx, fields)?;
    let files = plan
        .get("files")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(wire_file)
        .collect::<Step<Vec<Value>>>()?;
    let compared = plan
        .get("compared")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|index| {
            let index = usize::try_from(index.as_u64().ok_or(Failure::Invalid)?)
                .map_err(|_| Failure::Invalid)?;
            files.get(index).cloned().ok_or(Failure::Invalid)
        })
        .collect::<Step<Vec<Value>>>()?;
    let mut request = Map::new();
    request.insert("op".into(), json!("compare"));
    request.insert("files".into(), Value::Array(compared));
    request.insert("generation".into(), json!("before"));
    request.insert("inverse".into(), json!(false));
    if let Err(fault) = transition(fields, request, &mut events) {
        return stopped(json!({ "fault": fault }), events);
    }

    let Some(Value::Array(paths)) = fields.get("authority_files") else {
        return Err(Failure::Invalid);
    };
    let authority: Vec<(Value, &str)> = paths
        .iter()
        .cloned()
        .zip(["remove_authority_receipt", "remove_manifest"])
        .collect();
    if let Err(fault) = publish(fields, &files, &authority, &mut events)? {
        return stopped(json!({ "fault": fault }), events);
    }
    if let Err(reason) = remove_unused_key(text(fields, "home")?, &mut events) {
        return stopped(json!({ "key_error": reason }), events);
    }
    let manifest = plan.get("manifest").cloned().ok_or(Failure::Invalid)?;
    stopped(json!({ "manifest": manifest }), events)
}
