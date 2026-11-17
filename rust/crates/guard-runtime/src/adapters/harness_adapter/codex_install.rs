//! Codex: a whole install in one op, ported from
//! `CodexHarnessAdapter._install_owned`.
//!
//! The caller holds installation ownership and has recovered any pending
//! publication. This op reads the publication target, plans the install
//! (`install_plan`), publishes the authenticated generation with its backups
//! written ahead of it (`publish_hooks`), and then the retirements and
//! launchers planned beside them. When those fail they restore themselves
//! and the committed generation is withdrawn too, so legacy hooks never run
//! beside their migration.
//!
//! Request fields: `install_plan`'s and `publish_hooks`' (`home`, `config`,
//! `operation_id`, `spec`, `budget_spent` and the short-path fields).
//! Answer: `events` (the journal records, in order) and either `plan` (the
//! `install_plan` answer's `shim_manifest`, `backup_path` and `migrated`)
//! with `state` (the verified hook state as JSON
//! text), or what stopped it: `conflict`, `fault`, `reply`, `error` with an
//! optional `rollback_error` (`publish_hooks`), or `retire_error` with
//! `withdrawn` saying whether the generation's inverse was published.

use serde_json::{json, Map, Value};

use super::codex_install_plan::install_plan;
use super::codex_publish::publish_hooks;
use super::{Ctx, Failure, Step};
use crate::codex_hook_key;

/// `record_codex_mutation` journals the key's removal as empty bytes.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The journal records of an answer; file-write markers index the files of
/// the op that wrote them, which the caller does not see, so only the
/// mutation records travel on.
pub(super) fn mutations(answer: &Value, events: &mut Vec<Value>) {
    if let Some(list) = answer.get("events").and_then(Value::as_array) {
        events.extend(
            list.iter()
                .filter(|event| event.get("mutation").is_some())
                .cloned(),
        );
    }
}

/// One transition op on the caller's home: its value, or the fault it sent.
pub(super) fn transition(
    fields: &Map<String, Value>,
    mut request: Map<String, Value>,
    events: &mut Vec<Value>,
) -> Result<Value, Value> {
    for key in ["package_roots", "budget"] {
        if let Some(value) = fields.get(key) {
            request.insert(key.into(), value.clone());
        }
    }
    let invalid = || json!({ "transition": "native_transition_invalid" });
    let answer =
        crate::transition_files::dispatch(&Value::Object(request)).map_err(|_| invalid())?;
    mutations(&answer, events);
    if let Some(error) = answer.get("restore_error").or_else(|| answer.get("error")) {
        return Err(error.clone());
    }
    if answer.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(invalid());
    }
    Ok(answer.get("value").cloned().unwrap_or(Value::Null))
}

pub(super) fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Step<&'a str> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)
}

/// `PreparedHarnessInstall.publish(removals=True)` over `files`.
fn publish(
    fields: &Map<String, Value>,
    files: Vec<Value>,
    events: &mut Vec<Value>,
) -> Result<(), Value> {
    let mut request = Map::new();
    request.insert("op".into(), json!("publish"));
    request.insert("files".into(), Value::Array(files));
    request.insert("removals".into(), json!(true));
    request.insert("rollback".into(), json!(true));
    transition(fields, request, events).map(drop)
}

/// `_withdraw_publication`: the committed generation's inverse, then the
/// hook key when no manifest uses it any longer.
fn withdraw(fields: &Map<String, Value>, publication: &[Value], events: &mut Vec<Value>) -> bool {
    let inverse = publication
        .iter()
        .map(|change| {
            let mut file = change.clone();
            for (forward, backward) in [("before", "after"), ("before_mode", "after_mode")] {
                file[forward] = change[backward].clone();
                file[backward] = change[forward].clone();
            }
            file
        })
        .collect();
    if publish(fields, inverse, events).is_err() {
        return false;
    }
    let Ok(home) = text(fields, "home") else {
        return false;
    };
    remove_unused_key(home, events).is_ok()
}

/// `remove_hook_secret_if_unused`: the hook key goes once no manifest uses
/// it, journaled as `record_codex_mutation` does; the refusal reason when the
/// key cannot be read.
pub(super) fn remove_unused_key(home: &str, events: &mut Vec<Value>) -> Result<(), Value> {
    let answer = codex_hook_key::answer("key_remove_if_unused", home)
        .ok_or_else(|| json!("codex_hook_manifest_secret_invalid"))?;
    if let Some(reason) = answer.get("error") {
        return Err(reason.clone());
    }
    if answer.get("removed") == Some(&json!(true)) {
        let path = codex_hook_key::key_path(std::path::Path::new(home));
        events.push(json!({ "mutation": {
            "operation": "remove_unused_key",
            "path": path.to_string_lossy(),
            "before_present": true,
            "after_present": false,
            "before_digest": EMPTY_SHA256,
            "after_digest": null,
        }}));
    }
    Ok(())
}

pub(super) fn stopped(mut answer: Value, events: Vec<Value>) -> Step<Value> {
    answer["events"] = Value::Array(events);
    Ok(answer)
}

/// `install`.
pub(super) fn install(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut events = Vec::new();
    let mut request = Map::new();
    request.insert("op".into(), json!("publication_target"));
    request.insert("home".into(), json!(text(fields, "home")?));
    request.insert("config".into(), json!(text(fields, "config")?));
    // The runtime refuses a pending publication and snapshots the config.
    let target = match transition(fields, request, &mut events) {
        Ok(Value::Object(target)) => target,
        Ok(_) => {
            return stopped(
                json!({ "fault": { "transition": "native_transition_invalid" } }),
                events,
            )
        }
        Err(fault) => return stopped(json!({ "fault": fault }), events),
    };

    let mut plan = install_plan(ctx, fields)?;
    mutations(&plan, &mut events);
    if let Some(plan) = plan.as_object_mut() {
        plan.remove("events");
    }
    if plan.get("conflict").is_some() || plan.get("fault").is_some() {
        return stopped(plan, events);
    }
    let files = plan
        .get("files")
        .and_then(Value::as_array)
        .filter(|files| files.len() >= 4)
        .ok_or(Failure::Invalid)?
        .clone();
    let backups = plan
        .get("backups")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .clone();
    let backed_up = |change: &Value| {
        change
            .get("path")
            .is_some_and(|path| backups.contains(path))
    };
    // The plan leads with authority, manifest, receipt and config.
    let publication = files[..4].to_vec();
    let ahead: Vec<Value> = files[4..]
        .iter()
        .filter(|change| backed_up(change))
        .cloned()
        .collect();
    let remaining: Vec<Value> = files[4..]
        .iter()
        .filter(|change| !backed_up(change))
        .cloned()
        .collect();

    let mut publish_request = fields.clone();
    let offset = ahead.len();
    let mut written = ahead;
    written.extend(publication.iter().cloned());
    publish_request.insert("files".into(), Value::Array(written));
    publish_request.insert("config_index".into(), json!(offset + 3));
    publish_request.insert("manifest_index".into(), json!(offset + 1));
    publish_request.insert("receipt_index".into(), json!(offset + 2));
    publish_request.insert(
        "original".into(),
        target.get("before").cloned().unwrap_or(Value::Null),
    );
    publish_request.insert(
        "original_identity".into(),
        target.get("identity").cloned().unwrap_or(Value::Null),
    );
    publish_request.insert(
        "key_present".into(),
        json!(target.get("key_present") == Some(&json!(true))),
    );
    publish_request.insert("after_manifest".into(), publication[1]["after"].clone());
    let mut published = publish_hooks(ctx, &publish_request)?;
    mutations(&published, &mut events);
    let Some(state) = published.get("state").cloned() else {
        if let Some(answer) = published.as_object_mut() {
            answer.remove("events");
        }
        return stopped(published, events);
    };

    if let Err(fault) = publish(fields, remaining, &mut events) {
        let withdrawn = withdraw(fields, &publication, &mut events);
        return stopped(
            json!({ "retire_error": fault, "withdrawn": withdrawn }),
            events,
        );
    }
    // The caller reports the install from these; the files stay here, so a
    // plan with many retained launch generations stays under the response
    // bound.
    let mut report = Map::new();
    for key in [
        "shim_manifest",
        "backup_path",
        "migrated",
        "managed_servers",
        "skipped_servers",
    ] {
        report.insert(key.into(), plan.get(key).cloned().ok_or(Failure::Invalid)?);
    }
    stopped(json!({ "plan": report, "state": state }), events)
}
