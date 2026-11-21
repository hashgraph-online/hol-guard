//! Paseo's delegated install: each native provider's proof, bound after
//! that provider's own install, and the receipt Python writes from them.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::describe::PASEO_DELEGATES;
use super::files::{self, path_value, render, text, Doc};
use super::paseo::{
    launcher_paths, native_configs, providers, require_guard_local, rows, Provider,
};
use super::paseo_paths::{config_identity, receipt_path};
use super::{path_text, proof, Ctx, Failure, Spec, Step};
use crate::pyjson::PyVal;

pub(super) const RECEIPT_SCHEMA: &str = "guard.paseo-native-install.v1";
const INSTALL_NOTES: [&str; 4] = [
    super::paseo::COVERAGE_LIMIT,
    "Start new provider sessions after installation. Existing sessions may retain old hooks.",
    "Paseo configuration, provider commands, credentials, models, and permissions were not changed.",
    "Native hooks are shared with other clients and remain installed when Paseo support is removed.",
];
const BOUND_PATH_KEYS: [&str; 4] = [
    "managed_hook_manifest_path",
    "managed_hook_config_path",
    "managed_plugin_path",
    "global_plugin_path",
];

pub(super) fn target(fields: &Map<String, Value>) -> Step<&'static str> {
    let name = fields
        .get("target")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    PASEO_DELEGATES
        .iter()
        .copied()
        .find(|delegate| *delegate == name)
        .ok_or(Failure::Invalid)
}

fn proof_paths(proof: &Value) -> Vec<String> {
    proof
        .get("protection_artifact_proof")
        .and_then(|envelope| envelope.get("artifacts"))
        .and_then(Value::as_array)
        .map(|artifacts| {
            artifacts
                .iter()
                .filter_map(|item| item.get("path").and_then(Value::as_str).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// `install_native` after the provider's own install: bind its proof.
pub(super) fn delegate_bind(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let harness = target(fields)?;
    let raw = fields
        .get("manifest")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let Ok(PyVal::Dict(entries)) = crate::pyjson::parse(raw) else {
        return Err(Failure::Invalid);
    };
    let manifest = PyVal::Dict(entries.clone())
        .to_json()
        .ok_or(Failure::Invalid)?;
    let primary = manifest.get("config_path").and_then(Value::as_str);
    let Some(primary) = primary.filter(|primary| {
        manifest.get("active") == Some(&Value::Bool(true))
            && ctx.absolute(Path::new(primary)).is_file()
    }) else {
        return Err(Failure::Refusal(format!(
            "The {harness} adapter did not install native protection; Paseo setup was not completed."
        )));
    };
    let mut additional: Vec<String> = native_configs(harness)
        .iter()
        .map(|relative| ctx.home.join(relative))
        .filter(|path| harness != "opencode" && ctx.absolute(path).is_file())
        .map(|path| path_text(&path))
        .collect();
    additional.extend(BOUND_PATH_KEYS.iter().filter_map(|key| {
        manifest
            .get(*key)
            .and_then(Value::as_str)
            .map(str::to_owned)
    }));
    let mut bound = files::Doc(entries);
    bound.set(
        "protection_artifact_paths",
        PyVal::List(additional.iter().cloned().map(text).collect()),
    );
    let mut with_paths = manifest.as_object().cloned().ok_or(Failure::Invalid)?;
    with_paths.insert("protection_artifact_paths".into(), json!(additional));
    let envelope = proof::bind(ctx, &with_paths)?;
    bound.set("protection_artifact_proof", envelope.clone());
    let mut proof_doc = Doc::default();
    proof_doc.set("protection_artifact_proof", envelope);
    let proof = proof_doc.value();
    let primary = path_text(&ctx.resolved(Path::new(primary)));
    if !proof_paths(&proof.to_json().ok_or(Failure::Invalid)?).contains(&primary) {
        return Err(Failure::Refusal(format!(
            "Cannot verify {harness}'s native installation inside the managed home."
        )));
    }
    Ok(json!({"bound": render(&bound.value())?, "proof": render(&proof)?}))
}

/// The proofs Python collected, in target order, as JSON objects.
fn collected_proofs(fields: &Map<String, Value>) -> Step<Vec<(String, PyVal)>> {
    let proofs = fields
        .get("proofs")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    proofs
        .iter()
        .map(
            |(harness, raw)| match raw.as_str().map(crate::pyjson::parse) {
                Some(Ok(proof @ PyVal::Dict(_))) => Ok((harness.clone(), proof)),
                _ => Err(Failure::Invalid),
            },
        )
        .collect()
}

/// `write_receipt`, up to the write Python performs: providers unchanged,
/// launchers local and every proof still verifying.
pub(super) fn delegate_receipt(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let path = receipt_path(ctx)?;
    if Some(&providers(ctx)?.1) != fields.get("providers") {
        return Err(Failure::Refusal(
            "Paseo providers changed during installation; rerun hol-guard install paseo.".into(),
        ));
    }
    for shim in launcher_paths(ctx, "paseo") {
        require_guard_local(ctx, &shim)?;
    }
    let proofs = collected_proofs(fields)?;
    let intact = proofs.iter().all(|(_, proof)| {
        proof
            .to_json()
            .is_some_and(|proof| proof::verify(ctx, &proof) == Some(true))
    });
    if proofs.is_empty() || !intact {
        return Err(Failure::Refusal(
            "Native protection changed during Paseo installation; rerun setup before relying on it.".into(),
        ));
    }
    let mut receipt = Doc::default();
    receipt
        .set("schema_version", text(RECEIPT_SCHEMA))
        .set("paseo_config_path", text(config_identity(ctx)?))
        .set("native_proofs", PyVal::Dict(proofs));
    Ok(json!({"path": path_text(&path), "text": format!("{}\n", render(&receipt.value())?)}))
}

fn protection_paths(receipt: &Value) -> Vec<String> {
    let mut paths: Vec<String> = receipt
        .get("native_proofs")
        .and_then(Value::as_object)
        .map(|proofs| proofs.values().flat_map(proof_paths).collect())
        .unwrap_or_default();
    paths.sort();
    paths.dedup();
    paths
}

pub(super) fn finish_install(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let receipt: Value = fields
        .get("receipt")
        .and_then(Value::as_str)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .ok_or(Failure::Invalid)?;
    let (providers, _) = providers_from(fields)?;
    let rows = rows(ctx, fields, &providers, &receipt)?;
    let mut doc = Doc::default();
    doc.spread(&shim)
        .set("harness", text(spec.harness))
        .set("active", PyVal::Bool(true))
        .set("config_path", path_value(&receipt_path(ctx)?))
        .set("mode", text("native-provider-hooks"))
        .set("coverage_status", text("limited"))
        .set("cloud_inventory_status", text("native-providers-only"))
        .set("runtime_verification", text("not-performed"))
        .set(
            "providers",
            PyVal::List(rows.into_iter().map(|(row, _)| row).collect()),
        )
        .set(
            "protection_artifact_paths",
            PyVal::List(protection_paths(&receipt).into_iter().map(text).collect()),
        )
        .set("notes", PyVal::List(INSTALL_NOTES.map(text).to_vec()));
    files::manifest_answer(doc)
}

/// The providers `prepare_install` read, as Python handed them back.
fn providers_from(fields: &Map<String, Value>) -> Step<(Vec<Provider>, Value)> {
    let raw = fields.get("providers").cloned().ok_or(Failure::Invalid)?;
    let parsed = raw
        .as_array()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|row| {
            let optional = |key: &str| row.get(key).and_then(Value::as_str).map(str::to_owned);
            Ok(Provider {
                id: row
                    .get("provider")
                    .and_then(Value::as_str)
                    .ok_or(Failure::Invalid)?
                    .to_owned(),
                native: optional("native_harness"),
                enabled: row
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or(Failure::Invalid)?,
                unsupported: optional("unsupported_reason"),
            })
        })
        .collect::<Step<Vec<_>>>()?;
    Ok((parsed, raw))
}
