//! Paseo's delegated install, run in the runtime under the owner of the Guard
//! home, as `install_delegated` ran it from Python.
//!
//! Each native provider Paseo could hand a session to is preflighted, installed
//! with its own adapter, bound to its proof and recorded in the managed-install
//! store. The receipt of every proof is then written, Paseo's launcher is
//! published and the manifest rendered. Every write is journaled under the
//! owner, so a later failure keeps what an earlier provider changed for the
//! transaction's recovery.
//!
//! The request carries `delegates` (which provider runtimes this host has),
//! `now` and `source` for the rows, and the per-provider `facts`
//! every other install takes. Paseo installs for the daemon
//! user, so each provider installs without the caller's workspace.

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::harness_adapter::describe;
use crate::harness_adapter::managed_install_target::{install, stopped, Owned, INVALID};
use crate::harness_adapter::managed_record::store_call;
use crate::harness_adapter::paseo::{preflight_native, prepare_install};
use crate::harness_adapter::paseo_install::{delegate_bind, delegate_receipt, finish_install};
use crate::harness_adapter::uninstall_apply::fault;
use crate::harness_adapter::{Ctx, Spec};
use crate::transition_files::{managed_write, Owner};

/// The private mode `atomic_write_text` publishes a receipt with.
const RECEIPT_MODE: u32 = 0o600;

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Owned<&'a str> {
    fields.get(key).and_then(Value::as_str).ok_or(INVALID)
}

fn string(fields: &Map<String, Value>, key: &str) -> Owned<String> {
    Ok(text(fields, key)?.to_owned())
}

/// `NativeHarnessAdapter._install_delegated`: the manifest text of Paseo.
pub(super) fn install_paseo(
    spec: &Spec,
    ctx: &Ctx,
    request: &Map<String, Value>,
    owner: &mut Owner,
) -> Owned<String> {
    // The earlier read-only check does not authorize a mutation.
    let prepared = prepare_install(ctx, request).map_err(stopped)?;
    let providers = prepared.get("providers").cloned().ok_or(INVALID)?;
    let targets = prepared
        .get("targets")
        .and_then(Value::as_array)
        .ok_or(INVALID)?;
    let daemon = Ctx {
        workspace: None,
        ..ctx.clone()
    };
    let now = string(request, "now")?;
    let source = request
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let mut proofs = Map::new();
    for target in targets {
        let target = target.as_str().ok_or(INVALID)?;
        let mut asked = request.clone();
        asked.insert("target".into(), json!(target));
        preflight_native(ctx, delegate(&asked)?).map_err(stopped)?;
        let provider = describe::spec(target).ok_or(INVALID)?;
        let manifest = install(provider, &daemon, request, owner, None)?;
        asked.insert("manifest".into(), json!(manifest));
        let bound = delegate_bind(ctx, &asked).map_err(stopped)?;
        store_call(
            ctx,
            source,
            "set_managed_install",
            json!({
                "harness": target,
                "active": true,
                "workspace": null,
                "manifest_json": text(bound.as_object().ok_or(INVALID)?, "bound")?,
                "now": now,
            }),
        )
        .map_err(stopped)?;
        proofs.insert(
            target.to_owned(),
            json!(text(bound.as_object().ok_or(INVALID)?, "proof")?),
        );
    }
    let mut asked = request.clone();
    asked.insert("providers".into(), providers.clone());
    asked.insert("proofs".into(), Value::Object(proofs));
    let receipt = delegate_receipt(ctx, &asked).map_err(stopped)?;
    let receipt = receipt.as_object().ok_or(INVALID)?;
    let shim = super::publish_shim(spec, &daemon, request, owner)?;
    let written = managed_write(
        Path::new(text(receipt, "path")?),
        text(receipt, "text")?.as_bytes(),
        RECEIPT_MODE,
    )
    .map_err(|failure| stopped(fault(failure)))?;
    owner.record_events(&json!({ "events": [written] }));
    let mut finish = request.clone();
    finish.insert("shim".into(), json!(shim));
    finish.insert("providers".into(), providers);
    finish.insert("receipt".into(), json!(text(receipt, "text")?));
    let answer = finish_install(spec, ctx, &finish).map_err(stopped)?;
    string(answer.as_object().ok_or(INVALID)?, "manifest")
}

fn delegate(fields: &Map<String, Value>) -> Owned<&'static str> {
    crate::harness_adapter::paseo_install::target(fields).map_err(stopped)
}
