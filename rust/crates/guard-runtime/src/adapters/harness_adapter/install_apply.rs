//! `apply_install`: a harness install, published where its plan is made.
//!
//! What `NativeHarnessAdapter.install` chained from Python: prepare both
//! launcher shims, prepare the adapter's own plan with the shim manifest,
//! then publish every planned file as `PreparedHarnessInstall.publish` did,
//! restoring what it wrote when a later file fails. The caller still holds
//! installation ownership and journals the mutation records the publish hands
//! back, so the answer is `{"manifest": text, "publish": answer}` where
//! `publish` is the `transition_files` publish answer, with the progress
//! events no caller here watches left out. Fields: those of `prepare_install`
//! less `shim`, the shim's `launcher_name`, `display_name` and
//! `interpreter`, and `transition` (`package_roots` and `budget`).

use serde_json::{json, Map, Value};

use super::{guard_shim, route, shims_apply, Ctx, Failure, Spec, Step};
use crate::transition_files::resolve_lenient;

/// `normalized_after_mode`: a published mode never keeps group/world write.
fn normalized_after_mode(mode: u64) -> u64 {
    if cfg!(windows) || mode & !0o777 != 0 {
        return mode;
    }
    mode & !0o022
}

/// `TransitionFile(...).payload()` for one planned change of an answer;
/// `None` for a target `payload()` refuses as `file_target_invalid`.
fn payload(entry: &Value) -> Step<Option<Value>> {
    let entry = entry.as_object().ok_or(Failure::Invalid)?;
    let path = entry
        .get("path")
        .and_then(Value::as_str)
        .map(std::path::Path::new)
        .ok_or(Failure::Invalid)?;
    if !path.is_absolute() || path.symlink_metadata().is_ok_and(|meta| meta.is_symlink()) {
        return Ok(None);
    }
    let before = entry.get("before").cloned().unwrap_or(Value::Null);
    let after = entry.get("after").cloned().unwrap_or(Value::Null);
    let mode = |key: &str| entry.get(key).and_then(Value::as_u64).unwrap_or(0o600);
    let before_mode = mode("before_mode");
    let mut after_mode = mode("after_mode");
    // `publishes_user_file`: an existing file this change rewrites.
    if !before.is_null() && (before != after || before_mode != after_mode) {
        after_mode = normalized_after_mode(after_mode);
    }
    Ok(Some(json!({
        "path": resolve_lenient(path).to_string_lossy(),
        "before": before,
        "after": after,
        "before_mode": before_mode,
        "after_mode": after_mode,
        "kind": "binding",
        "no_follow": entry.get("no_follow").and_then(Value::as_bool).unwrap_or(false),
    })))
}

pub(super) fn payloads(answer: &Value) -> Step<Option<Vec<Value>>> {
    answer
        .get("files")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(payload)
        .collect::<Step<Option<Vec<_>>>>()
}

/// A `transition_files` publish answer for a plan refused before any file
/// was written.
pub(super) fn refused_publish(reason: &str) -> Value {
    json!({ "error": { "transition": reason }, "events": [] })
}

fn refused(reason: &str) -> Value {
    json!({ "manifest": null, "publish": refused_publish(reason) })
}

/// `PreparedHarnessInstall.publish` over `files`, with the caller's
/// `transition` context; the progress events no caller watches are dropped.
pub(super) fn publish(
    files: Vec<Value>,
    removals: bool,
    fields: &Map<String, Value>,
) -> Step<Value> {
    let mut request = match fields.get("transition") {
        Some(Value::Object(transition)) => transition.clone(),
        _ => return Err(Failure::Invalid),
    };
    request.insert("op".into(), json!("publish"));
    request.insert("files".into(), Value::Array(files));
    request.insert("removals".into(), json!(removals));
    request.insert("rollback".into(), json!(true));
    let mut published =
        crate::transition_files::dispatch(&Value::Object(request)).map_err(|_| Failure::Invalid)?;
    if let Some(Value::Array(events)) = published.get_mut("events") {
        events.retain(|event| event.get("written").is_none());
    }
    Ok(published)
}

pub(super) fn apply(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    if spec.harness == "copilot" {
        return copilot(spec, ctx, fields);
    }
    if spec.harness == "cursor" {
        return super::cursor_apply::install(spec, ctx, fields);
    }
    let mut shim_fields = Map::new();
    shim_fields.insert("harness".into(), json!(spec.harness));
    for key in ["launcher_name", "display_name", "interpreter"] {
        shim_fields.insert(key.into(), fields.get(key).cloned().unwrap_or(Value::Null));
    }
    let shim = guard_shim::prepare(ctx, &shim_fields)?;
    let shim_manifest = shim
        .get("manifest")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let Some(mut files) = payloads(&shim)? else {
        return Ok(refused("file_target_invalid"));
    };
    let mut plan_fields = fields.clone();
    for key in [
        "launcher_name",
        "display_name",
        "interpreter",
        "transition",
        "shell_profile",
    ] {
        plan_fields.remove(key);
    }
    plan_fields.insert("shim".into(), json!(shim_manifest));
    let plan = route(spec, "prepare_install", ctx, &plan_fields)?;
    let Some(planned) = payloads(&plan)? else {
        return Ok(refused("file_target_invalid"));
    };
    files.extend(planned);
    let manifest = plan
        .get("manifest")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?
        .to_owned();
    let published = publish(files, false, fields)?;
    Ok(json!({ "manifest": manifest, "publish": published }))
}

/// The only reason an answer of just `transition_error` names.
fn transition_refusal(answer: &Value) -> Option<&str> {
    let answer = answer.as_object()?;
    if answer.len() != 1 {
        return None;
    }
    answer.get("transition_error")?.as_str()
}

/// Copilot's `_prepared_install(create_key=True).publish(...)`: the detection
/// digest, both launcher shims with their default names, the plan made from
/// that digest, and the enrolled state key pinned beside them. A path two
/// sources plan differently refuses the install before any write.
fn copilot(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut asked = Map::new();
    asked.insert("create_key".into(), json!(true));
    let found = route(spec, "install_detection", ctx, &asked)?;
    if let Some(reason) = transition_refusal(&found) {
        return Ok(refused(reason));
    }
    let mut shim_fields = Map::new();
    shim_fields.insert("harness".into(), json!(spec.harness));
    shim_fields.insert("launcher_name".into(), Value::Null);
    shim_fields.insert("display_name".into(), Value::Null);
    shim_fields.insert(
        "interpreter".into(),
        fields.get("interpreter").cloned().unwrap_or(Value::Null),
    );
    let shim = guard_shim::prepare(ctx, &shim_fields)?;
    let shim_manifest = shim
        .get("manifest")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    asked.insert(
        "digest".into(),
        found.get("digest").cloned().ok_or(Failure::Invalid)?,
    );
    asked.insert("shim".into(), json!(shim_manifest));
    let plan = route(spec, "prepare_install", ctx, &asked)?;
    if let Some(reason) = transition_refusal(&plan) {
        return Ok(refused(reason));
    }
    let key = ctx.guard_home.join("managed").join("adapter-state.key");
    let key = match shims_apply::identity_dependency(ctx, &super::path_text(&key))? {
        Ok(key) => key,
        Err(reason) => return Ok(refused(reason)),
    };
    let (Some(planned), Some(shims)) = (payloads(&plan)?, payloads(&shim)?) else {
        return Ok(refused("file_target_invalid"));
    };
    let mut files: Vec<Value> = Vec::new();
    for change in std::iter::once(key).chain(planned).chain(shims) {
        let path = change.get("path").cloned();
        match files
            .iter()
            .find(|known| known.get("path").cloned() == path)
        {
            Some(known) if *known != change => {
                return Ok(refused("adapter_preparation_generation_conflict"));
            }
            Some(_) => {}
            None => files.push(change),
        }
    }
    let manifest = plan
        .get("manifest")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?
        .to_owned();
    let published = publish(files, false, fields)?;
    Ok(json!({ "manifest": manifest, "publish": published }))
}
