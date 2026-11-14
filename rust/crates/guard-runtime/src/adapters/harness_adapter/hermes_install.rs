//! `prepare_install` for Hermes: the overlay and pre-tool payload, the Guard
//! entries in `config.yaml` and its allowlist, the records uninstall restores
//! from, and the authenticated manifest, as one plan.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::files::{self, path_value, shim_notes, text, Change, Doc};
use super::hermes::{self, HARNESS};
use super::openclaw::{hook_argv, install_state};
use super::{cloud_identity, hermes_config, hermes_hooks, path_text, Ctx, Failure, Spec, Step};
use crate::adapter_state_integrity_op::sign_state;
use crate::hermes_inspect::{inspect_config, Syntax};
use crate::pyjson::{self, PyVal};

const MANAGED_LABEL: &str = "Hermes managed";
const INSTALLED_NOTE: &str =
    "Guard generated a Hermes MCP overlay, fail-closed hooks.pre_tool_call entry, and MCP proxy bundle.";

/// What the `config.yaml` rewrite produced, when the file could be read.
struct Rewrite {
    text: String,
    allowlist: Change,
    managed: Vec<String>,
    previous_guard: Option<PyVal>,
}

/// The current `config.yaml` mapping, `{}` when absent, `None` when it
/// cannot be read completely.
fn existing_config(ctx: &Ctx, path: &Path) -> Option<Doc> {
    if !ctx.absolute(path).exists() {
        return Some(Doc::default());
    }
    let inspection = inspect_config(&ctx.absolute(path), Syntax::Yaml).ok()?;
    if !inspection.file.complete {
        return None;
    }
    inspection.payload.map(Doc)
}

fn plan(request: Value) -> Step<Value> {
    crate::hermes_install_plan::dispatch(&request).map_err(|_| Failure::Invalid)
}

/// `kept_servers`: the user's servers Guard does not manage, then the overlay
/// under the names the plan gives it.
fn kept_servers(
    current: &[(String, PyVal)],
    managed: &[String],
    overlay: &[(String, PyVal)],
) -> Step<(PyVal, Vec<String>)> {
    let names: Vec<&str> = current.iter().map(|(name, _)| name.as_str()).collect();
    let keys: Vec<&str> = overlay.iter().map(|(name, _)| name.as_str()).collect();
    let answer =
        plan(json!({"op": "servers", "names": names, "managed": managed, "overlay": keys}))?;
    let keep = answer
        .get("keep")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    let raw = answer
        .get("add")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    let add = hermes::strings(answer.get("add"));
    if add.len() != raw.len() || add.len() != overlay.len() {
        return Err(Failure::Invalid);
    }
    let mut kept = Doc::default();
    for index in keep {
        let index = index
            .as_u64()
            .and_then(|index| usize::try_from(index).ok())
            .ok_or(Failure::Invalid)?;
        let (name, config) = current.get(index).ok_or(Failure::Invalid)?;
        kept.set(name, config.clone());
    }
    for (key, (_, config)) in add.iter().zip(overlay) {
        kept.set(key, config.clone());
    }
    Ok((kept.value(), add))
}

/// The `guard` section Hermes's runtime policy reads.
fn guard_section(ctx: &Ctx) -> Step<PyVal> {
    let answer = plan(json!({
        "op": "guard_section",
        "base_url": hermes_config::consumer_base_url(ctx),
        "timeout_seconds": hermes::HOOK_HOST_TIMEOUT_SECONDS,
    }))?;
    let section = answer
        .get("section")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    let mut doc = Doc::default();
    for pair in section {
        let key = pair
            .get(0)
            .and_then(Value::as_str)
            .ok_or(Failure::Invalid)?;
        let value = pair.get(1).ok_or(Failure::Invalid)?;
        doc.set(
            key,
            pyjson::parse(&value.to_string()).map_err(|_| Failure::Invalid)?,
        );
    }
    Ok(doc.value())
}

/// `_write_guard_to_hermes_config_yaml`, as text, without writing it.
fn rewrite(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    config: &Path,
    overlay: &[(String, PyVal)],
    argv: &[PyVal],
) -> Step<Option<Rewrite>> {
    let Some(mut existing) = existing_config(ctx, config) else {
        return Ok(None);
    };
    let field = |doc: &Doc, key: &str| {
        doc.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };
    let previous_guard = field(&existing, "guard").filter(|guard| guard.as_dict().is_some());
    let current = match field(&existing, "mcp_servers") {
        Some(PyVal::Dict(servers)) => servers,
        _ => Vec::new(),
    };
    let (servers, managed) = kept_servers(&current, &hermes::managed_server_names(ctx), overlay)?;
    existing.set("mcp_servers", servers);
    existing.set("guard", guard_section(ctx)?);
    let home = config.parent().unwrap_or(config);
    let allowlist = hermes_hooks::sync(ctx, &mut existing, argv, home)?;
    let text = hermes::yaml(fields, &existing.value())?;
    Ok(Some(Rewrite {
        text,
        allowlist,
        managed,
        previous_guard,
    }))
}

/// A JSON file the bundle owns, rendered with `indent=2` and a newline.
fn json_change(ctx: &Ctx, path: &Path, payload: &PyVal) -> Step<Change> {
    text_change(ctx, path, format!("{}\n", files::render(payload)?))
}

fn text_change(ctx: &Ctx, path: &Path, after: String) -> Step<Change> {
    let target = files::output_path(ctx, path)?;
    let before = files::snapshot(ctx, &target)?;
    let before_mode = match before {
        Some(_) => files::mode(ctx, &target).ok_or(Failure::Invalid)?,
        None => 0o600,
    };
    Ok(Change {
        path: ctx.resolved(&target),
        before,
        after: Some(after.into_bytes()),
        before_mode,
        after_mode: 0o600,
        no_follow: true,
    })
}

/// The existing manifest, its key order kept, and whether it authenticates.
fn existing_manifest(ctx: &Ctx, path: &Path) -> (bool, bool, Option<PyVal>) {
    let (payload, ordered) = hermes::manifest_snapshot(ctx, path);
    let verified = hermes::verified(ctx, &payload);
    (payload.is_empty(), verified, ordered)
}

/// `hermes_previous_guard_for_install`: an authentic manifest's record wins
/// over the section seen in `config.yaml` now.
fn previous_guard(verified: bool, ordered: Option<&PyVal>, observed: Option<PyVal>) -> PyVal {
    let recorded = || {
        ordered
            .and_then(|manifest| manifest.get("previous_guard_section"))
            .filter(|section| section.as_dict().is_some())
            .cloned()
    };
    let chosen = if verified { recorded() } else { observed };
    chosen.unwrap_or(PyVal::Null)
}

/// Each source, with the host mirror's servers a bare sandbox inherits.
fn sources(ctx: &Ctx) -> Step<Vec<hermes_config::Source>> {
    let home = hermes::hermes_home(ctx);
    let mut sources = hermes_config::load_sources(ctx, &home)?;
    let Some(host) = hermes::host_home(ctx) else {
        return Ok(sources);
    };
    let bare = !crate::hermes_detect::home_has_artifacts(&ctx.absolute(&home)).unwrap_or(true);
    if ctx.resolved(&host) != ctx.resolved(&home) && bare {
        for (key, config) in hermes_config::load_sources(ctx, &host)? {
            if !sources.iter().any(|(existing, _)| *existing == key) {
                sources.push((key, config));
            }
        }
    }
    Ok(sources)
}

fn strings(values: &[String]) -> PyVal {
    PyVal::List(values.iter().map(|value| text(value.clone())).collect())
}

fn sign(ctx: &Ctx, manifest: Doc) -> Step<Doc> {
    let unavailable = || Failure::Runtime("native_adapter_state_integrity_unavailable".to_owned());
    let payload = match PyVal::Dict(manifest.0.clone()).to_json() {
        Some(Value::Object(payload)) => payload,
        _ => return Err(Failure::Invalid),
    };
    let signed =
        sign_state(&hermes::key_home(ctx), HARNESS, payload, true).map_err(|_| unavailable())?;
    let stamp = signed.get("state_authentication").ok_or_else(unavailable)?;
    let mut manifest = manifest;
    manifest.set(
        "state_authentication",
        pyjson::parse(&stamp.to_string()).map_err(|_| Failure::Invalid)?,
    );
    Ok(manifest)
}

pub(super) fn prepare(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let sources = sources(ctx)?;
    let shim = files::shim_manifest(fields)?;
    let argv = hook_argv(fields)?;
    let root = hermes::managed_root(ctx);
    let (manifest_path, overlay_path, pretool_path) = hermes::bundle(ctx);
    files::within_root(ctx, &ctx.guard_home, &root, MANAGED_LABEL)?;
    for path in [&manifest_path, &overlay_path, &pretool_path] {
        files::within_root(ctx, &root, path, MANAGED_LABEL)?;
    }
    let (manifest_empty, verified, ordered) = existing_manifest(ctx, &manifest_path);
    let state = install_state(ctx, manifest_empty, &overlay_path, &pretool_path)?;
    let overlay = hermes_config::overlay(ctx, fields, &sources)?;
    let identity = cloud_identity::hints(ctx, spec.harness);
    let mut pretool = Doc::default();
    pretool
        .set("command", PyVal::List(argv.clone()))
        .set("harness", text(HARNESS))
        .set(
            "timeout_seconds",
            PyVal::Int(hermes::HOOK_HOST_TIMEOUT_SECONDS.to_string()),
        )
        .set("fail_open", PyVal::Bool(false));

    let home = hermes::hermes_home(ctx);
    let config = home.join("config.yaml");
    files::within_root(ctx, &home, &config, "Hermes config")?;
    let rewrite = rewrite(ctx, fields, &config, &overlay, &argv)?;

    let mut changes = vec![
        json_change(ctx, &overlay_path, &PyVal::Dict(overlay))?,
        json_change(ctx, &pretool_path, &pretool.value())?,
    ];
    let (managed, observed) = match rewrite {
        None => (Vec::new(), None),
        Some(rewrite) => {
            changes.push(rewrite.allowlist);
            changes.push(text_change(
                ctx,
                &hermes::authorized(ctx, &config),
                rewrite.text,
            )?);
            let mut record = Doc::default();
            record.set("servers", strings(&rewrite.managed));
            changes.push(json_change(
                ctx,
                &root.join("managed-servers.json"),
                &record.value(),
            )?);
            let previous = root.join("previous-guard-section.json");
            if !ctx.absolute(&previous).exists() {
                let mut record = Doc::default();
                record.set(
                    "guard",
                    rewrite.previous_guard.clone().unwrap_or(PyVal::Null),
                );
                changes.push(json_change(ctx, &previous, &record.value())?);
            }
            (rewrite.managed, rewrite.previous_guard)
        }
    };

    let mut notes = vec![text(INSTALLED_NOTE)];
    notes.extend(shim_notes(&shim));
    let capabilities = ["same_channel", "pretool", "mcp_proxy"]
        .iter()
        .map(|name| ((*name).to_owned(), PyVal::Bool(true)))
        .collect();
    let mut manifest = hermes::result_head(true, &overlay_path, &[]);
    manifest
        .set("hermes_config_yaml_path", path_value(&config))
        .set(
            "hermes_config_yaml_resolved_path",
            text(path_text(&ctx.resolved(&config))),
        )
        .spread(&shim)
        .set("install_state", state)
        .set("managed_root", path_value(&root))
        .set("managed_manifest_path", path_value(&manifest_path))
        .set("mcp_overlay_path", path_value(&overlay_path))
        .set("pretool_hook_path", path_value(&pretool_path))
        .set("managed_server_names", strings(&managed))
        .set(
            "previous_guard_section",
            previous_guard(verified, ordered.as_ref(), observed),
        )
        .set("capabilities", PyVal::Dict(capabilities))
        .set("servers", hermes_config::manifest_servers(&sources))
        .set("notes", PyVal::List(notes));
    if let Some(identity) = &identity {
        manifest.set(
            "cloud_agent_identity",
            cloud_identity::hints_value(identity),
        );
    }
    let manifest = sign(ctx, manifest)?.value();
    changes.push(json_change(ctx, &manifest_path, &manifest)?);
    Ok(json!({
        "files": changes.iter().map(Change::wire).collect::<Vec<_>>(),
        "manifest": files::render(&manifest)?,
    }))
}
