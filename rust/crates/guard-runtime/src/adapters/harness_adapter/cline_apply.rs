//! Cline's `install` and `uninstall` in one native call each, as
//! `ClineHarnessAdapter.install` and `.uninstall` ran them from Python: the
//! transport plan, the chosen transport installed and confirmed (falling back
//! to native hooks when the plan allows it), the `cline` launcher with the
//! shell profile's PATH block, the MCP proxy entries and the manifest.
//!
//! An install answers `manifest` (its JSON text), `publish` (the launcher's
//! publish answer) and `published`/`failure` in the shape the generic client
//! settles for every harness.

use serde_json::{json, Map, Value};

use super::{answer, cline_install, cline_mcp, probe_run, shim_remove, shims_apply};
use super::{Ctx, Failure, Spec, Step};
use crate::pyjson::PyVal;

const LAUNCHER: &str = "cline";
const LABEL: &str = "Cline CLI";

/// `_reconcile`: install one transport, hand its probe back and let the
/// kind confirm it.
fn reconcile(ctx: &Ctx, transport: &str, frozen: bool) -> Step<Map<String, Value>> {
    let mut asked = Map::new();
    asked.insert("transport".into(), json!(transport));
    asked.insert("frozen".into(), json!(frozen));
    let installed = cline_install::dispatch("install_transport", ctx, &asked)?;
    let probe = installed.get("probe").ok_or(Failure::Invalid)?;
    match probe.get("canary") {
        Some(canary) => asked.insert("canary".into(), canary.clone()),
        None => asked.insert(
            "verdict".into(),
            probe.get("result").cloned().ok_or(Failure::Invalid)?,
        ),
    };
    let manifest = installed.get("manifest").ok_or(Failure::Invalid)?;
    let text = serde_json::to_string(manifest).map_err(|_| Failure::Invalid)?;
    asked.insert("manifest".into(), json!(text));
    match cline_install::dispatch("confirm_transport", ctx, &asked)? {
        Value::Object(confirmed) => Ok(confirmed),
        _ => Err(Failure::Invalid),
    }
}

fn frozen(fields: &Map<String, Value>) -> bool {
    fields.get("frozen") == Some(&Value::Bool(true))
}

/// The `cline` launcher and the PATH block, published together. Answers the
/// launcher's manifest with `shell_profile` added, and the publish answer.
fn shim(ctx: &Ctx, fields: &Map<String, Value>) -> Step<(Value, Value)> {
    let mut asked = Map::new();
    asked.insert(
        "shims".into(),
        json!([{"harness": "cline", "launcher_name": LAUNCHER, "display_name": LABEL}]),
    );
    for key in ["interpreter", "transition"] {
        asked.insert(key.into(), fields.get(key).cloned().unwrap_or(Value::Null));
    }
    asked.insert(
        "profile".into(),
        fields.get("shell_profile").cloned().unwrap_or(Value::Null),
    );
    let applied = shims_apply::apply_guard_shims(ctx, &asked)?;
    let publish = applied.get("publish").cloned().ok_or(Failure::Invalid)?;
    let manifest = applied
        .get("shims")
        .and_then(Value::as_array)
        .and_then(|shims| shims.first())
        .ok_or(Failure::Invalid)?;
    let mut manifest = match manifest {
        Value::String(text) => serde_json::from_str::<Value>(text).map_err(|_| Failure::Invalid)?,
        other => other.clone(),
    };
    let profile = match applied.get("profile") {
        Some(Value::String(text)) => serde_json::from_str(text).unwrap_or(json!(text)),
        Some(profile) => profile.clone(),
        None => Value::Null,
    };
    manifest
        .as_object_mut()
        .ok_or(Failure::Invalid)?
        .insert("shell_profile".into(), profile);
    Ok((manifest, publish))
}

fn stopped(publish: Value, failed: Value) -> Value {
    json!({ "manifest": null, "publish": publish, "published": [], "failure": failed })
}

/// `install(context, surface=...)`.
pub(super) fn install(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let fields = probe_run::with_cline_cli(spec, ctx, fields)?;
    let frozen = frozen(&fields);
    let mut plan_fields = Map::new();
    for key in ["surface", "cli"] {
        if let Some(value) = fields.get(key) {
            plan_fields.insert(key.into(), value.clone());
        }
    }
    plan_fields.insert("frozen".into(), json!(frozen));
    let plan = cline_install::dispatch("install_plan", ctx, &plan_fields)?;
    let mut transport = plan
        .get("transport")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?
        .to_owned();
    let transport_manifest = match reconcile(ctx, &transport, frozen) {
        Ok(manifest) => manifest,
        Err(Failure::Runtime(_)) if plan.get("fallback") == Some(&Value::Bool(true)) => {
            "hooks".clone_into(&mut transport);
            let mut manifest = reconcile(ctx, &transport, frozen)?;
            manifest.insert("fallback_from_plugin".into(), json!(true));
            manifest
        }
        Err(failure) => return Err(failure),
    };
    let mut publish = json!({ "ok": true, "events": [] });
    let mut shim_manifest = Value::Null;
    if plan.get("shim") == Some(&Value::Bool(true)) {
        let (manifest, published) = shim(ctx, &fields)?;
        if published.get("ok") != Some(&Value::Bool(true)) {
            return Ok(stopped(published, Value::Null));
        }
        shim_manifest = manifest;
        publish = published;
    }
    let mcp_install = if plan.get("mcp") == Some(&Value::Bool(true)) {
        match cline_mcp::install(ctx) {
            Ok(installed) => installed,
            Err(failure) => {
                return Ok(stopped(
                    publish,
                    answer(Err(failure)).map_err(|_| Failure::Invalid)?,
                ))
            }
        }
    } else {
        Value::Null
    };
    let embed = |value: &Value| -> Step<Value> {
        if value.is_null() {
            return Ok(Value::Null);
        }
        Ok(json!(
            serde_json::to_string(value).map_err(|_| Failure::Invalid)?
        ))
    };
    let mut finish = Map::new();
    finish.insert(
        "surface".into(),
        plan.get("surface").cloned().unwrap_or(Value::Null),
    );
    finish.insert("transport".into(), json!(transport));
    finish.insert(
        "transport_manifest".into(),
        embed(&Value::Object(transport_manifest))?,
    );
    finish.insert("shim".into(), embed(&shim_manifest)?);
    finish.insert("mcp_install".into(), embed(&mcp_install)?);
    finish.insert(
        "cli".into(),
        fields.get("cli").cloned().unwrap_or(Value::Null),
    );
    let manifest = match cline_install::dispatch("finish_install", ctx, &finish) {
        Ok(manifest) => manifest,
        Err(failure) => {
            return Ok(stopped(
                publish,
                answer(Err(failure)).map_err(|_| Failure::Invalid)?,
            ))
        }
    };
    let text = serde_json::to_string(&manifest).map_err(|_| Failure::Invalid)?;
    Ok(json!({ "manifest": text, "publish": publish, "published": [], "failure": null }))
}

/// `uninstall(context, surface=...)`: the transports and MCP entries the
/// surface names, then the `cline` launcher when the runtime says so.
pub(super) fn uninstall(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut asked = Map::new();
    if let Some(surface) = fields.get("surface") {
        asked.insert("surface".into(), surface.clone());
    }
    let answer = cline_install::dispatch("uninstall", ctx, &asked)?;
    let mut manifest = answer.get("manifest").cloned().ok_or(Failure::Invalid)?;
    if answer.get("remove_shim") == Some(&Value::Bool(true)) {
        let (shim, _) = shim_remove::remove_named(ctx, LAUNCHER, LABEL, &[])?;
        let shim = super::files::render(&PyVal::Dict(shim))?;
        let shim: Value = serde_json::from_str(&shim).map_err(|_| Failure::Invalid)?;
        manifest
            .as_object_mut()
            .ok_or(Failure::Invalid)?
            .insert("shim".into(), shim);
    }
    let text = serde_json::to_string(&manifest).map_err(|_| Failure::Invalid)?;
    Ok(json!({ "manifest": text }))
}
