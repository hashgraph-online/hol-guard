//! `apply_guard_shims` and `apply_plan`: launcher shims, the shell profile's
//! PATH block, and an adapter's own prepared plan, each published in one
//! native call instead of being prepared here and written from Python.
//!
//! Both answer `publish`, the `transition_files` publish answer the caller
//! journals and checks, beside the manifests the prepared steps rendered.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::install_apply::{payloads, publish, refused_publish};
use super::{files, guard_shim, route, shim_profile, Ctx, Failure, Spec, Step};
use crate::transition_files::resolve_lenient;

const SHIM_KEYS: [&str; 3] = ["harness", "launcher_name", "display_name"];

/// `apply_guard_shims`: each `shims` entry (`harness`, `launcher_name`,
/// `display_name`) rendered with `interpreter`, and the shell profile when
/// `profile` names its `shell` and `shim_dir_transient`. Answers `shims`
/// (each manifest text, in order), `profile` (its manifest or `null`) and
/// `publish`. Nothing to write publishes nothing.
pub(super) fn apply_guard_shims(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shims = fields
        .get("shims")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    let mut planned = Vec::new();
    let mut manifests = Vec::new();
    for shim in shims {
        let shim = shim.as_object().ok_or(Failure::Invalid)?;
        let mut shim_fields = Map::new();
        for key in SHIM_KEYS {
            shim_fields.insert(key.into(), shim.get(key).cloned().unwrap_or(Value::Null));
        }
        shim_fields.insert(
            "interpreter".into(),
            fields.get("interpreter").cloned().unwrap_or(Value::Null),
        );
        let prepared = guard_shim::prepare(ctx, &shim_fields)?;
        manifests.push(prepared.get("manifest").cloned().ok_or(Failure::Invalid)?);
        planned.push(prepared);
    }
    let profile = match fields.get("profile") {
        None | Some(Value::Null) => None,
        Some(Value::Object(profile)) => Some(shim_profile::prepare(ctx, profile)?),
        Some(_) => return Err(Failure::Invalid),
    };
    let profile_manifest = profile
        .as_ref()
        .map(|answer| answer.get("manifest").cloned().ok_or(Failure::Invalid))
        .transpose()?
        .unwrap_or(Value::Null);
    planned.extend(profile);
    let mut changes = Vec::new();
    for answer in &planned {
        let Some(files) = payloads(answer)? else {
            return Ok(answered(
                manifests,
                profile_manifest,
                refused_publish("file_target_invalid"),
            ));
        };
        changes.extend(files);
    }
    let published = if changes.is_empty() {
        json!({ "ok": true, "events": [] })
    } else {
        publish(changes, false, fields)?
    };
    Ok(answered(manifests, profile_manifest, published))
}

fn answered(shims: Vec<Value>, profile: Value, publish: Value) -> Value {
    json!({ "shims": shims, "profile": profile, "publish": publish })
}

/// `TransitionFile.identity_dependency(path).payload()`: existing authority
/// pinned by digest, never rewritten. `Err` carries the transition reason
/// that refuses the plan before any write.
pub(super) fn identity_dependency(ctx: &Ctx, path: &str) -> Step<Result<Value, &'static str>> {
    let path = ctx.absolute(std::path::Path::new(path));
    let data = match files::snapshot(ctx, &path) {
        Ok(Some(data)) => data,
        Ok(None) => return Ok(Err("authority_dependency_missing")),
        Err(Failure::Integrity(reason)) => return Ok(Err(reason)),
        Err(failure) => return Err(failure),
    };
    let Some(mode) = files::mode(ctx, &path) else {
        return Ok(Err("authority_dependency_missing"));
    };
    Ok(Ok(json!({
        "path": resolve_lenient(&path).to_string_lossy(),
        "before": null,
        "after": null,
        "before_mode": mode,
        "after_mode": mode,
        "kind": "binding",
        "no_follow": true,
        "expected_digest": hex::encode(Sha256::digest(&data)),
    })))
}

/// `apply_plan`: the adapter's `plan_op` answer, published with
/// `removals`, as `_prepared(answer).publish(...)` did. A plan that answers
/// only `transition_error` is refused before any write. Answers `manifest`
/// (the plan's text) and `publish`, or the plan's own `reply` while it
/// still waits on one.
pub(super) fn apply_plan(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let plan_op = fields
        .get("plan_op")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let removals = fields.get("removals").and_then(Value::as_bool) == Some(true);
    let mut plan_fields = fields.clone();
    for key in ["plan_op", "removals", "transition"] {
        plan_fields.remove(key);
    }
    let plan = route(spec, plan_op, ctx, &plan_fields)?;
    // A plan still waiting on a reply goes back to the caller, which answers
    // it and asks again; nothing has been written yet.
    if plan
        .as_object()
        .is_some_and(|plan| plan.len() == 1 && plan.contains_key("reply"))
    {
        return Ok(plan);
    }
    if let Some(reason) = plan.get("transition_error").and_then(Value::as_str) {
        if plan.as_object().is_some_and(|plan| plan.len() == 1) {
            return Ok(json!({ "manifest": null, "publish": refused_publish(reason) }));
        }
    }
    let mut changes = Vec::new();
    let identities = match plan.get("identity") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(paths)) => paths.as_slice(),
        Some(_) => return Err(Failure::Invalid),
    };
    for path in identities {
        let path = path.as_str().ok_or(Failure::Invalid)?;
        match identity_dependency(ctx, path)? {
            Ok(change) => changes.push(change),
            Err(reason) => {
                return Ok(json!({ "manifest": null, "publish": refused_publish(reason) }));
            }
        }
    }
    let Some(planned) = payloads(&plan)? else {
        let publish = refused_publish("file_target_invalid");
        return Ok(json!({ "manifest": null, "publish": publish }));
    };
    changes.extend(planned);
    let manifest = plan.get("manifest").cloned().ok_or(Failure::Invalid)?;
    Ok(json!({ "manifest": manifest, "publish": publish(changes, removals, fields)? }))
}
