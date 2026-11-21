//! `apply_uninstall`: a harness uninstall, done where its plan is made.
//!
//! The plan is prepared first, so a refusal leaves the launcher in place.
//! Then the launcher shims are removed, each write, copy and delete of the
//! plan runs in order, and `finish_uninstall` renders the manifest. A
//! managed write hands back the mutation record the caller's install
//! transaction appends; those records come back under `events` with the
//! answer or the failure, so a plan stopped partway still journals what it
//! changed. A shim-only adapter removes its launchers and answers with no
//! events.

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::describe::Install;
use super::files::{adapter_result, manifest_answer, render};
use super::{answer, route, shim_remove, Ctx, Failure, Spec, Step};
use crate::pyjson::PyVal;
use crate::runner_authority_op::KindResult;
use crate::transition_files::{managed_write, write_no_follow, Fault};

fn os(error: std::io::Error) -> Failure {
    Failure::Os(error.to_string())
}

pub(super) fn fault(fault: Fault) -> Failure {
    match fault {
        Fault::Os(error) => os(error),
        Fault::Integrity(code, _) if code == "codex_hook_transaction_target_not_regular" => {
            Failure::Integrity("codex_hook_transaction_target_not_regular")
        }
        Fault::Integrity(_, message) | Fault::Runtime(message) => Failure::Runtime(message),
        Fault::Transition(_) | Fault::Refused(..) => Failure::Invalid,
    }
}

fn text<'a>(entry: &'a Map<String, Value>, key: &str) -> Step<&'a str> {
    entry
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)
}

fn entries<'a>(plan: &'a Value, key: &str) -> Step<&'a [Value]> {
    match plan.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(Failure::Invalid),
    }
}

fn write(ctx: &Ctx, entry: &Value, events: &mut Vec<Value>) -> Step<()> {
    let entry = entry.as_object().ok_or(Failure::Invalid)?;
    let target = ctx.absolute(Path::new(text(entry, "path")?));
    let payload = text(entry, "text")?.as_bytes();
    let flag = |key: &str| entry.get(key).and_then(Value::as_bool) == Some(true);
    if flag("parents") {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(os)?;
        }
    }
    if flag("raw") {
        return fs::write(&target, payload).map_err(os);
    }
    if flag("no_follow") {
        return write_no_follow(&target, payload, 0o600).map_err(os);
    }
    match entry.get("mode") {
        None | Some(Value::Null) => fs::write(&target, payload).map_err(os),
        Some(mode) => {
            let mode = mode
                .as_u64()
                .and_then(|mode| u32::try_from(mode).ok())
                .ok_or(Failure::Invalid)?;
            let mutation = managed_write(&target, payload, mode).map_err(fault)?;
            events.push(mutation);
            Ok(())
        }
    }
}

fn execute(ctx: &Ctx, plan: &Value, events: &mut Vec<Value>) -> Step<Vec<String>> {
    for entry in entries(plan, "writes")? {
        write(ctx, entry, events)?;
    }
    for entry in entries(plan, "copies")? {
        let entry = entry.as_object().ok_or(Failure::Invalid)?;
        let from = ctx.absolute(Path::new(text(entry, "from")?));
        let to = ctx.absolute(Path::new(text(entry, "to")?));
        fs::copy(&from, &to).map_err(os)?;
        remove(&from)?;
    }
    let mut removed = Vec::new();
    for entry in entries(plan, "deletes")? {
        let value = entry.as_str().ok_or(Failure::Invalid)?;
        remove(&ctx.absolute(Path::new(value)))?;
        removed.push(value.to_owned());
    }
    Ok(removed)
}

/// `Path.unlink(missing_ok=True)`.
fn remove(path: &Path) -> Step<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(os(error)),
        _ => Ok(()),
    }
}

/// A shim-only adapter's uninstall: its launchers, and the manifest naming them.
fn shim_only(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let (shim, shim_path) = shim_remove::remove(spec, ctx)?;
    manifest_answer(adapter_result(
        spec.harness,
        false,
        &shim_path,
        &shim,
        Vec::new(),
    ))
}

pub(super) fn apply(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> KindResult {
    let mut events = Vec::new();
    let _config = match super::install_apply::opencode_lock(spec, ctx) {
        Ok(lock) => lock,
        Err(failure) => return answer(Err(failure)),
    };
    let step = if spec.install == Install::Shim {
        shim_only(spec, ctx)
    } else if spec.harness == "cursor" {
        super::cursor_apply::uninstall(spec, ctx, fields)
    } else if spec.harness == "cline" {
        super::cline_apply::uninstall(ctx, fields)
    } else {
        // The plan comes first, so a refusal leaves the launcher in place.
        route(spec, "prepare_uninstall", ctx, fields).and_then(|plan| {
            let (shim, _) = shim_remove::remove(spec, ctx)?;
            let removed = execute(ctx, &plan, &mut events)?;
            let mut finish = fields.clone();
            finish.insert("shim".into(), json!(render(&PyVal::Dict(shim))?));
            finish.insert(
                "finish".into(),
                plan.get("finish").cloned().unwrap_or(Value::Null),
            );
            finish.insert("removed".into(), json!(removed));
            route(spec, "finish_uninstall", ctx, &finish)
        })
    };
    // Every answer but a question carries `events`, empty when nothing was
    // written, so the caller journals one shape. A question stays the
    // answer's only key: the adapter answers it and asks again from the start.
    let asks = matches!(step, Err(Failure::Reply(_)));
    let mut out = answer(step)?;
    if !asks {
        out.as_object_mut()
            .ok_or(crate::runner_authority_op::ERR_INVALID)?
            .insert("events".into(), Value::Array(events));
    }
    Ok(out)
}
