//! Paseo: Guard protects Paseo's agent tools through the native hooks of the
//! providers its daemon runs, and keeps a receipt of their install proofs.
//!
//! Python installs each native provider with that provider's adapter and
//! registers the bound manifest; every decision around those installs is
//! made here: which providers to install, the write targets each must pass
//! first, the proof each install carries, the receipt and the result.
//! Requests carry `delegates`, whether each native provider's runtime is
//! available, as its adapter answers it.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::files::{self, render, text, Doc};
use super::paseo_install as install;
use super::paseo_paths::{
    config_identity, config_path, read_config_object, receipt_path, require_local, walk,
};
use super::{common, path_answer, path_text, proof, which, Ctx, Failure, Spec, Step};
use crate::pyjson::PyVal;

pub(super) const COVERAGE_LIMIT: &str = "Paseo delegates tool execution to native providers. Guard protects supported \
providers through their native hooks, not Paseo's permission notifications. Paseo terminals, daemon \
git/browser actions, plugin code, custom commands, ACP providers, and other hosts are not covered by this \
adapter.";
const UNINSTALL_NOTES: [&str; 2] = [
    "Removed Paseo's installation receipt and launcher. Shared native Guard hooks were left intact.",
    "Use hol-guard uninstall <native-harness> separately to remove native protection for all clients.",
];
/// Each native provider's config files under the daemon user's home.
pub(super) fn native_configs(harness: &str) -> &'static [&'static str] {
    match harness {
        "claude-code" => &[".claude/settings.json"],
        "codex" => &[".codex/config.toml", ".codex/hooks.json"],
        "copilot" => &[".copilot/config.json", ".copilot/mcp-config.json"],
        "opencode" => &[
            ".config/opencode/opencode.json",
            ".config/opencode/opencode.jsonc",
            ".config/opencode/plugins/hol-guard-pretool.ts",
        ],
        "pi" => &[
            ".pi/agent/settings.json",
            ".pi/agent/extensions/hol-guard.ts",
        ],
        "omp" => &[
            ".omp/agent/settings.json",
            ".omp/agent/extensions/hol-guard.ts",
        ],
        _ => &[],
    }
}

/// `guard_launcher_paths`: every launcher name, plain and `.cmd`.
pub(super) fn launcher_paths(ctx: &Ctx, harness: &str) -> Vec<PathBuf> {
    let names = match harness {
        "claude-code" => vec!["claude", "claude-code"],
        other => vec![other],
    };
    let directory = ctx.guard_home.join("bin");
    names
        .iter()
        .flat_map(|name| ["", ".cmd"].map(|suffix| directory.join(format!("guard-{name}{suffix}"))))
        .collect()
}

pub(super) fn require_guard_local(ctx: &Ctx, path: &Path) -> Step<()> {
    require_local(ctx, &ctx.guard_home, path, Some(&ctx.home))
}

pub(super) struct Provider {
    pub(super) id: String,
    pub(super) native: Option<String>,
    pub(super) enabled: bool,
    pub(super) unsupported: Option<String>,
}

impl Provider {
    fn wire(&self) -> Doc {
        let optional = |value: &Option<String>| value.clone().map_or(PyVal::Null, text);
        let mut doc = Doc::default();
        doc.set("provider", text(self.id.clone()))
            .set("native_harness", optional(&self.native))
            .set("enabled", PyVal::Bool(self.enabled))
            .set("unsupported_reason", optional(&self.unsupported));
        doc
    }
}

/// `paseo_providers(context)` and the raw rows, which later steps compare.
pub(super) fn providers(ctx: &Ctx) -> Step<(Vec<Provider>, Value)> {
    let environ: Map<String, Value> = ctx
        .env
        .iter()
        .filter(|(key, value)| {
            let key = key.to_uppercase();
            !value.is_empty()
                && super::describe::ENV_PREFIXES
                    .iter()
                    .any(|prefix| key.starts_with(prefix))
        })
        .map(|(key, value)| (key.clone(), json!(value)))
        .collect();
    let answer = crate::paseo_providers::dispatch(&json!({
        "config_path": path_text(&config_path(ctx)?),
        "xdg_default": path_text(&ctx.home.join(".config")),
        "environ": environ,
    }))
    .map_err(|_| Failure::Invalid)?;
    if let Some(Value::String(error)) = answer.get("error") {
        return Err(Failure::Refusal(error.clone()));
    }
    let rows = answer.get("providers").cloned().ok_or(Failure::Invalid)?;
    let parsed = rows
        .as_array()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|row| {
            let optional = |key: &str| match row.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(value)) => Ok(Some(value.clone())),
                Some(_) => Err(Failure::Invalid),
            };
            Ok(Provider {
                id: row
                    .get("provider")
                    .and_then(Value::as_str)
                    .ok_or(Failure::Invalid)?
                    .to_owned(),
                native: optional("native_harness")?,
                enabled: row
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or(Failure::Invalid)?,
                unsupported: optional("unsupported_reason")?,
            })
        })
        .collect::<Step<Vec<_>>>()?;
    Ok((parsed, rows))
}

fn available(fields: &Map<String, Value>, harness: &str) -> Step<bool> {
    fields
        .get("delegates")
        .and_then(|delegates| delegates.get(harness))
        .and_then(Value::as_bool)
        .ok_or(Failure::Invalid)
}

/// `provider_status(provider, context, receipt)`.
fn status(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    provider: &Provider,
    receipt: &Value,
) -> Step<&'static str> {
    if !provider.enabled {
        return Ok("disabled");
    }
    let Some(native) = provider
        .native
        .as_deref()
        .filter(|_| provider.unsupported.is_none())
    else {
        return Ok("unsupported");
    };
    if !available(fields, native)? {
        return Ok("runtime-unavailable");
    }
    Ok(
        match receipt
            .get("native_proofs")
            .and_then(|proofs| proofs.get(native))
        {
            None | Some(Value::Null) => "not-installed",
            Some(proof) if proof::verify(ctx, proof) == Some(true) => "native-hooks-installed",
            Some(_) => "changed",
        },
    )
}

pub(super) fn rows(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    providers: &[Provider],
    receipt: &Value,
) -> Step<Vec<(PyVal, &'static str)>> {
    providers
        .iter()
        .map(|provider| {
            let status = status(ctx, fields, provider, receipt)?;
            let mut row = provider.wire();
            row.set("status", text(status));
            Ok((row.value(), status))
        })
        .collect()
}

/// `preflight_native(harness, context)`: every write target the native
/// install may touch, before any shared setting changes.
fn preflight_native(ctx: &Ctx, harness: &str) -> Step<()> {
    for relative in native_configs(harness) {
        let path = ctx.home.join(relative);
        require_local(ctx, &ctx.home, &path, Some(&ctx.home))?;
        if path.extension().is_some_and(|ext| ext == "json") {
            read_config_object(ctx, &path)?;
        }
    }
    let managed = ctx.guard_home.join("managed").join(harness);
    require_guard_local(ctx, &managed)?;
    let absolute = ctx.absolute(&managed);
    if absolute.is_dir() {
        for path in walk(&absolute) {
            require_guard_local(ctx, &path)?;
        }
    }
    if harness == "opencode" {
        require_guard_local(
            ctx,
            &ctx.guard_home.join("opencode/plugins/hol-guard-pretool.ts"),
        )?;
    }
    launcher_paths(ctx, harness)
        .iter()
        .try_for_each(|path| require_guard_local(ctx, path))
}

/// `_prepare_install_targets`: the providers to install, each preflighted.
fn prepare_install(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let (providers, raw) = providers(ctx)?;
    let mut targets: Vec<String> = rows(ctx, fields, &providers, &json!({}))?
        .iter()
        .zip(&providers)
        .filter(|((_, status), _)| *status == "not-installed")
        .filter_map(|(_, provider)| provider.native.clone())
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return Err(Failure::Refusal(
            "No supported, enabled Paseo provider runtime was found. Install a native provider on the daemon \
             host and remove custom command/config-home overrides, then run hol-guard install paseo again."
                .into(),
        ));
    }
    for target in &targets {
        preflight_native(ctx, target)?;
    }
    for shim in launcher_paths(ctx, "paseo") {
        require_guard_local(ctx, &shim)?;
    }
    Ok(json!({"targets": targets, "providers": raw}))
}

/// `read_receipt(context)`.
fn read_receipt(ctx: &Ctx) -> Step<Value> {
    let entries = read_config_object(ctx, &receipt_path(ctx)?)?;
    if entries.is_empty() {
        return Ok(json!({}));
    }
    let payload = PyVal::Dict(entries).to_json().ok_or(Failure::Invalid)?;
    let identity = config_identity(ctx)?;
    if payload.get("schema_version").and_then(Value::as_str) != Some(install::RECEIPT_SCHEMA)
        || payload.get("paseo_config_path").and_then(Value::as_str) != Some(identity.as_str())
    {
        return Err(Failure::Refusal(
            "Paseo's installation receipt is invalid; run hol-guard apps repair paseo.".into(),
        ));
    }
    if !payload.get("native_proofs").is_some_and(Value::is_object) {
        return Err(Failure::Refusal(
            "Paseo's native installation proofs are missing; run hol-guard apps repair paseo."
                .into(),
        ));
    }
    Ok(payload)
}

/// The fields Paseo's diagnostics add to the default report.
fn diagnostics(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let found = fields
        .get("found")
        .and_then(Value::as_bool)
        .ok_or(Failure::Invalid)?;
    let report = || -> Step<Doc> {
        let receipt = read_receipt(ctx)?;
        let rows = rows(ctx, fields, &providers(ctx)?.0, &receipt)?;
        let any = |states: &[&str]| rows.iter().any(|(_, status)| states.contains(status));
        let status = if any(&["changed"]) {
            "broken"
        } else if any(&["native-hooks-installed"])
            && !any(&["not-installed", "runtime-unavailable"])
        {
            "active"
        } else if found {
            "partial"
        } else {
            "not_found"
        };
        let mut doc = Doc::default();
        doc.set("setup_status", text(status))
            .set(
                "providers",
                PyVal::List(rows.into_iter().map(|(row, _)| row).collect()),
            )
            .set("coverage_status", text("limited"))
            .set("cloud_inventory_status", text("native-providers-only"))
            .set("runtime_verification", text("not-performed"));
        Ok(doc)
    };
    let doc = match report() {
        Ok(doc) => doc,
        Err(Failure::Refusal(message) | Failure::Os(message)) => {
            let mut doc = Doc::default();
            doc.set("setup_status", text("broken"))
                .set("providers", PyVal::List(Vec::new()))
                .set(
                    "warnings",
                    PyVal::List(vec![text(message), text(COVERAGE_LIMIT)]),
                );
            doc
        }
        Err(other) => return Err(other),
    };
    Ok(json!({"update": render(&doc.value())?}))
}

fn detect(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let available = which::resolve_command(ctx, spec.executable, &[]).is_some();
    let mut paths = Vec::new();
    let mut artifacts = Vec::new();
    let mut warnings = Vec::new();
    let mut scan = || -> Step<()> {
        let path = config_path(ctx)?;
        if ctx.absolute(&path).is_file() {
            paths.push(path_text(&path));
        }
        if !paths.is_empty() || available {
            for provider in providers(ctx)?.0.iter().filter(|provider| provider.enabled) {
                let metadata = provider.wire().value().to_json().ok_or(Failure::Invalid)?;
                artifacts.push(json!({
                    "artifact_id": format!("paseo:provider:{}", provider.id),
                    "name": provider.id,
                    "harness": spec.harness,
                    "artifact_type": "agent",
                    "source_scope": "global",
                    "config_path": path_text(&path),
                    "command": null,
                    "args": [],
                    "url": null,
                    "transport": null,
                    "publisher": null,
                    "metadata": metadata,
                }));
            }
            warnings = vec![COVERAGE_LIMIT.to_owned()];
        }
        Ok(())
    };
    match scan() {
        Ok(()) => {}
        Err(Failure::Refusal(message)) => warnings = vec![message],
        Err(other) => return Err(other),
    }
    Ok(json!({
        "artifacts": artifacts,
        "config_paths": paths,
        "warnings": warnings,
        "installed": !paths.is_empty() || available,
        "command_available": available,
        "workspace_aibom": spec.workspace_aibom,
    }))
}

fn prepare_uninstall(ctx: &Ctx) -> Step<Value> {
    let path = receipt_path(ctx)?;
    let present = ctx.absolute(&path).exists();
    let deletes: Vec<String> = present.then(|| path_text(&path)).into_iter().collect();
    Ok(json!({"writes": [], "deletes": deletes, "finish": {}}))
}

fn finish_uninstall(spec: &Spec, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let mut doc = Doc::default();
    doc.spread(&shim)
        .set("harness", text(spec.harness))
        .set("active", PyVal::Bool(false))
        .set("notes", PyVal::List(UNINSTALL_NOTES.map(text).to_vec()));
    files::manifest_answer(doc)
}

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "policy_path" => path_answer(&config_path(ctx)?),
        "detect" => detect(spec, ctx),
        "prepare_install" => prepare_install(ctx, fields),
        "delegate_preflight" => preflight_native(ctx, install::target(fields)?).map(|()| json!({})),
        "delegate_bind" => install::delegate_bind(ctx, fields),
        "delegate_receipt" => install::delegate_receipt(ctx, fields),
        "finish_install" => install::finish_install(spec, ctx, fields),
        "prepare_uninstall" => prepare_uninstall(ctx),
        "finish_uninstall" => finish_uninstall(spec, fields),
        "diagnostics" => diagnostics(ctx, fields),
        _ => common(spec, op, ctx),
    }
}
