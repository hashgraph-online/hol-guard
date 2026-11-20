//! Codex: the rest of an install, install plan or uninstall request, from
//! the `launch` its caller sent.
//!
//! Python sends only what the runtime cannot see: the launch facts, the
//! captured bytes, the authenticated bindings and the journal. The config and
//! hooks pairs, the managed hook groups and the legacy bridge identity every
//! one of these ops compares against are derived here from the context and
//! the hook argv. A field the request names is kept, as is a request without
//! `launch`.

use std::borrow::Cow;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::codex::{argv, compact, config_path, groups, paths, strings, text, NATIVE_HOOK_COMMAND};
use super::codex_spec::spelled;
use super::paseo_paths::abspath;
use super::{caller, path_text, Ctx, Failure, Step};
use crate::pyjson::{self, PyVal};

/// `_LEGACY_MANAGED_HOOK_STATUS_MESSAGES`, sorted: the status messages an
/// earlier install gave its handlers.
const LEGACY_STATUSES: [&str; 5] = [
    "HOL Guard checking Bash command",
    "HOL Guard checking Codex approval request",
    "HOL Guard checking prompt",
    "HOL Guard checking tool action",
    "HOL Guard checking tool result",
];

/// `python_bridge_argv(argv)[1:]`: a registration that wraps a Python bridge
/// argv in the native subcommand is that argv.
fn legacy_tail(argv: &[String]) -> &[String] {
    let bridge = match argv {
        [runtime, command, rest @ ..]
            if argv.len() > 3 && !runtime.is_empty() && command == NATIVE_HOOK_COMMAND =>
        {
            rest
        }
        _ => argv,
    };
    bridge.get(1..).unwrap_or(&[])
}

/// The hook argv, the groups Guard registers and their bindings, as a
/// `launch` renders them.
struct Registration {
    argv: Vec<String>,
    groups: String,
    bindings: String,
}

fn registration(ctx: &Ctx, launch: &Map<String, Value>) -> Step<Registration> {
    let answer = argv(ctx, launch)?;
    let hook_argv = strings(answer.get("argv"))?;
    let mut rendering = Map::new();
    rendering.insert("argv".into(), json!(hook_argv));
    rendering.insert(
        "long_timeout".into(),
        launch
            .get("long_timeout")
            .cloned()
            .ok_or(Failure::Invalid)?,
    );
    let rendered = groups(ctx, &rendering)?;
    let field =
        |key: &str| text(rendered.as_object().ok_or(Failure::Invalid)?, key).map(str::to_owned);
    Ok(Registration {
        argv: hook_argv,
        groups: field("groups")?,
        bindings: field("bindings")?,
    })
}

/// `legacy_binding_fields`: what an exact current bridge entry is matched
/// against for legacy re-adoption.
fn legacy_fields(ctx: &Ctx, registration: &Registration) -> Step<[(&'static str, Value); 4]> {
    // `json.dumps(json.loads(bindings), separators=(",", ":"))`.
    let expected = match pyjson::parse(&registration.bindings) {
        Ok(bindings @ PyVal::List(_)) => compact(&bindings, true),
        _ => return Err(Failure::Invalid),
    };
    let mut legacy = vec![caller::executable(ctx)?.to_owned()];
    legacy.extend_from_slice(legacy_tail(&registration.argv));
    Ok([
        ("expected", json!(expected)),
        ("argv", json!(registration.argv)),
        ("legacy_argv", json!(legacy)),
        ("statuses", json!(LEGACY_STATUSES)),
    ])
}

/// The command syntax a native owner check splits with: this host's. A field
/// the request names is kept.
pub(super) fn host_syntax<'a>(
    ctx: &Ctx,
    fields: &'a Map<String, Value>,
) -> Cow<'a, Map<String, Value>> {
    if fields.contains_key("windows") && fields.contains_key("long_paths") {
        return Cow::Borrowed(fields);
    }
    let mut request = fields.clone();
    fill(&mut request, "windows", json!(ctx.windows));
    fill(&mut request, "long_paths", json!({}));
    Cow::Owned(request)
}

/// `detect_legacy`: the legacy-adoption block `codex_detect` matches hook
/// handlers against, built from the `launch` a caller sent.
pub(super) fn detect_legacy(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let launch = launch_of(fields)?.ok_or(Failure::Invalid)?;
    let mut legacy = Map::new();
    for (key, value) in legacy_fields(ctx, &registration(ctx, launch)?)? {
        legacy.insert(key.to_owned(), value);
    }
    legacy.insert("windows".into(), json!(ctx.windows));
    legacy.insert("long_paths".into(), json!({}));
    Ok(json!({ "legacy": legacy }))
}

fn launch_of(fields: &Map<String, Value>) -> Step<Option<&Map<String, Value>>> {
    match fields.get("launch") {
        None => Ok(None),
        Some(Value::Object(launch)) => Ok(Some(launch)),
        Some(_) => Err(Failure::Invalid),
    }
}

/// `install_fields`: the working directory and the Guard home the launch
/// runs under; the caller names only its package root.
fn fill_install(ctx: &Ctx, launch: &Map<String, Value>, request: &mut Map<String, Value>) {
    fill(request, "cwd", json!(ctx.cwd.as_deref().map(path_text)));
    if let Some(home) = launch.get("runtime_guard_home") {
        fill(request, "guard_home", home.clone());
    }
}

fn fill(request: &mut Map<String, Value>, key: &str, value: Value) {
    request.entry(key).or_insert(value);
}

/// An install or install plan request. `whole` is the `install` op, which
/// also names the anchored Guard home and config it publishes under and
/// starts with its budget unspent.
pub(super) fn complete<'a>(
    ctx: &Ctx,
    fields: &'a Map<String, Value>,
    whole: bool,
) -> Step<Cow<'a, Map<String, Value>>> {
    let Some(launch) = launch_of(fields)? else {
        return Ok(Cow::Borrowed(fields));
    };
    let registration = registration(ctx, launch)?;
    let mut request = fields.clone();
    let paths = paths(ctx);
    let pairs: Vec<(String, String)> = paths["pairs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pair| {
            Some((
                pair["config"].as_str()?.to_owned(),
                pair["hooks"].as_str()?.to_owned(),
            ))
        })
        .collect();
    fill(
        &mut request,
        "pairs",
        json!(pairs
            .iter()
            .map(|(config, hooks)| [config, hooks])
            .collect::<Vec<_>>()),
    );
    fill(
        &mut request,
        "workspace_config",
        json!(pairs.get(1).map(|(config, _)| config)),
    );
    fill(&mut request, "managed", json!(registration.groups));
    fill_install(ctx, launch, &mut request);
    for (key, value) in legacy_fields(ctx, &registration)? {
        fill(&mut request, key, value);
    }
    if whole {
        let home = abspath(ctx, &ctx.guard_home);
        let config = abspath(ctx, Path::new(&spelled(ctx, &config_path(ctx))));
        fill(&mut request, "home", json!(path_text(&home)));
        fill(&mut request, "config", json!(path_text(&config)));
        fill(&mut request, "budget_spent", json!(false));
    }
    Ok(Cow::Owned(request))
}

/// An uninstall request: the legacy bridge identity its owner checks read.
/// The launch is consumed.
pub(super) fn complete_uninstall<'a>(
    ctx: &Ctx,
    fields: &'a Map<String, Value>,
) -> Step<Cow<'a, Map<String, Value>>> {
    let Some(launch) = launch_of(fields)? else {
        return Ok(Cow::Borrowed(fields));
    };
    let legacy = legacy_fields(ctx, &registration(ctx, launch)?)?;
    let mut request = fields.clone();
    request.remove("launch");
    fill_install(ctx, launch, &mut request);
    for (key, value) in legacy {
        fill(&mut request, key, value);
    }
    Ok(Cow::Owned(request))
}

#[cfg(test)]
#[path = "codex_install_request_tests.rs"]
mod tests;
