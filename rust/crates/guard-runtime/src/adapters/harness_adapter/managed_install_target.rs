//! One harness's install or uninstall inside a native installation
//! transaction, as `NativeHarnessAdapter.install` and `uninstall` ran it from
//! Python.
//!
//! The launcher shim and the adapter's own plan are prepared and published
//! here; the owner that holds the Guard home appends the install's journal
//! lines itself, so no mutation record travels back to Python. A failure is
//! answered in the exception Python raises for it: a publication fault in its
//! own shape, and an adapter's refusal, OS error, missing file, runtime error
//! or integrity error under `{"adapter": {<one key>: message}}`.
//!
//! The request fields every target shares come from the caller's process:
//! `interpreter`, `shell_profile`, `transition`, `frozen`, `runtime`, and the
//! per-harness `facts` map the adapter would otherwise have asked for with
//! a reply.

use serde_json::{json, Map, Value};

#[path = "paseo_delegated.rs"]
mod paseo_delegated;

use super::describe::{Hook, Install};
use super::files::{render, text, Doc};
use super::{
    answer, codex, hook_config, install_apply, route, shims_apply, uninstall_apply, Ctx, Failure,
    Spec, Step,
};
use crate::pyjson::{self, PyVal};
use crate::transition_files::{OwnedFailure, Owner};

pub(super) type Owned<T> = Result<T, OwnedFailure>;

pub(super) const INVALID: OwnedFailure = OwnedFailure::Transition("native_transition_invalid");

/// The one-key answers an adapter step raises as an exception.
const ADAPTER_KEYS: [&str; 5] = [
    "refusal",
    "os_error",
    "not_found",
    "runtime_error",
    "integrity",
];

/// An adapter step's failure, as the owned transaction answers it.
pub(super) fn stopped(failure: Failure) -> OwnedFailure {
    match failure {
        Failure::Reply(_) => {
            OwnedFailure::Runtime("Guard needed a fact its caller did not supply".to_owned())
        }
        Failure::Invalid => INVALID,
        // A transition that began after the owner's own check still refuses as one.
        Failure::Refusal(reason) if reason == "pending_transition" => {
            OwnedFailure::Transition("pending_transition")
        }
        other => match answer(Err(other)) {
            Ok(one_key) => OwnedFailure::Fault(json!({ "adapter": one_key })),
            Err(_) => INVALID,
        },
    }
}

/// The adapter failure an answer carries under one of its exception keys.
fn adapter_fault(answer: &Value) -> Option<OwnedFailure> {
    ADAPTER_KEYS.iter().find_map(|key| {
        let value = answer.get(*key)?;
        let mut one_key = Map::new();
        one_key.insert((*key).to_owned(), value.clone());
        Some(OwnedFailure::Fault(json!({ "adapter": one_key })))
    })
}

/// `native_transition_files.settle`: journal what a publish wrote under the
/// owner, then raise the fault it ended with.
pub(super) fn published(owner: &mut Owner, publish: Option<&Value>) -> Owned<()> {
    let Some(publish) = publish.filter(|publish| publish.is_object()) else {
        return Err(INVALID);
    };
    owner.record_events(publish);
    for key in ["restore_error", "error"] {
        if let Some(fault) = publish.get(key).filter(|fault| !fault.is_null()) {
            return Err(OwnedFailure::Fault(fault.clone()));
        }
    }
    if publish.get("ok") == Some(&Value::Bool(true)) {
        Ok(())
    } else {
        Err(INVALID)
    }
}

/// The facts the caller's process supplied for this harness.
fn attach_facts(spec: &Spec, request: &Map<String, Value>, fields: &mut Map<String, Value>) {
    let per_harness = |group: &str| {
        request
            .get(group)
            .and_then(Value::as_object)
            .and_then(|facts| facts.get(spec.harness))
            .cloned()
    };
    if let Some(facts) = per_harness("facts") {
        fields.insert("facts".into(), facts);
    }
    if spec.extension() {
        fields.insert(
            "runtime".into(),
            request.get("runtime").cloned().unwrap_or(Value::Null),
        );
    }
}

/// The fields `apply_install` takes: the launcher's names, the caller's
/// process facts, the bounded hook argv and the surface.
fn plan_fields(
    spec: &Spec,
    ctx: &Ctx,
    request: &Map<String, Value>,
    surface: Option<&str>,
) -> Step<Map<String, Value>> {
    let mut fields = Map::new();
    fields.insert(
        "launcher_name".into(),
        if spec.launcher_name.is_empty() {
            Value::Null
        } else {
            json!(spec.launcher_name)
        },
    );
    fields.insert(
        "display_name".into(),
        spec.display_name.map_or(Value::Null, |name| json!(name)),
    );
    for key in ["interpreter", "shell_profile", "transition"] {
        fields.insert(key.into(), request.get(key).cloned().unwrap_or(Value::Null));
    }
    attach_facts(spec, request, &mut fields);
    if spec.hook != Hook::None {
        let mut asked = Map::new();
        if let Some(facts) = fields.get("facts") {
            asked.insert("facts".into(), facts.clone());
        }
        let hook = route(spec, "hook_spec", ctx, &asked)
            .and_then(|spec_answer| hook_config::with_config(spec, ctx, spec_answer))?;
        fields.insert(
            "hook_argv".into(),
            hook.get("hook_argv").cloned().ok_or(Failure::Invalid)?,
        );
    }
    if spec.frozen_fact() {
        fields.insert(
            "frozen".into(),
            request.get("frozen").cloned().unwrap_or(Value::Null),
        );
    }
    if let Some(surface) = surface {
        fields.insert("surface".into(), json!(surface));
    }
    Ok(fields)
}

/// The launchers a harness's install publishes, and the manifest text that
/// names them.
fn publish_shim(
    spec: &Spec,
    ctx: &Ctx,
    request: &Map<String, Value>,
    owner: &mut Owner,
) -> Owned<String> {
    let mut entry = Map::new();
    entry.insert("harness".into(), json!(spec.harness));
    entry.insert("launcher_name".into(), Value::Null);
    entry.insert("display_name".into(), Value::Null);
    let mut fields = Map::new();
    fields.insert("shims".into(), json!([entry]));
    for key in ["interpreter", "transition"] {
        fields.insert(key.into(), request.get(key).cloned().unwrap_or(Value::Null));
    }
    let applied = shims_apply::apply_guard_shims(ctx, &fields).map_err(stopped)?;
    published(owner, applied.get("publish"))?;
    applied
        .get("shims")
        .and_then(Value::as_array)
        .and_then(|manifests| manifests.first())
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(INVALID)
}

/// A shim-only harness's install: its launchers, and the manifest naming
/// them under `harness`, `active` and `config_path`.
fn shim_install(
    spec: &Spec,
    ctx: &Ctx,
    request: &Map<String, Value>,
    owner: &mut Owner,
) -> Owned<String> {
    let rendered = publish_shim(spec, ctx, request, owner)?;
    let Ok(PyVal::Dict(shim)) = pyjson::parse(&rendered) else {
        return Err(INVALID);
    };
    let config = shim
        .iter()
        .find(|(key, _)| key == "shim_path")
        .map(|(_, path)| path.clone())
        .ok_or(INVALID)?;
    let mut doc = Doc::default();
    doc.set("harness", text(spec.harness))
        .set("active", PyVal::Bool(true))
        .set("config_path", config)
        .spread(&shim);
    render(&doc.value()).map_err(stopped)
}

/// `NativeHarnessAdapter.install`: the manifest text of the installed
/// harness, every publish journaled under `owner`.
pub(super) fn install(
    spec: &Spec,
    ctx: &Ctx,
    request: &Map<String, Value>,
    owner: &mut Owner,
    surface: Option<&str>,
) -> Owned<String> {
    if spec.harness == "codex" {
        return codex::codex_managed::install(spec, ctx, request, owner);
    }
    match spec.install {
        Install::Delegated => paseo_delegated::install_paseo(spec, ctx, request, owner),
        Install::Shim => shim_install(spec, ctx, request, owner),
        Install::Plan => {
            let fields = plan_fields(spec, ctx, request, surface).map_err(stopped)?;
            let applied = install_apply::apply(spec, ctx, &fields).map_err(stopped)?;
            // Each earlier publish is journaled before the last one, then any
            // failure the runtime met after a publish that succeeded.
            for earlier in applied
                .get("published")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                published(owner, Some(earlier))?;
            }
            published(owner, applied.get("publish"))?;
            if let Some(failure) = applied.get("failure").filter(|failure| failure.is_object()) {
                return Err(adapter_fault(failure).unwrap_or(INVALID));
            }
            applied
                .get("manifest")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(INVALID)
        }
    }
}

/// `NativeHarnessAdapter.uninstall`: the plan prepared, the launchers removed
/// and the plan applied, with each managed write journaled under `owner`
/// even when a later step fails.
pub(super) fn uninstall(
    spec: &Spec,
    ctx: &Ctx,
    request: &Map<String, Value>,
    owner: &mut Owner,
    surface: Option<&str>,
) -> Owned<String> {
    if spec.harness == "codex" {
        return codex::codex_managed::uninstall(spec, ctx, request, owner);
    }
    let mut fields = Map::new();
    attach_facts(spec, request, &mut fields);
    if let Some(surface) = surface {
        fields.insert("surface".into(), json!(surface));
    }
    let applied = uninstall_apply::apply(spec, ctx, &fields).map_err(|_| INVALID)?;
    owner.record_events(&applied);
    if let Some(fault) = adapter_fault(&applied) {
        return Err(fault);
    }
    applied
        .get("manifest")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(INVALID)
}
