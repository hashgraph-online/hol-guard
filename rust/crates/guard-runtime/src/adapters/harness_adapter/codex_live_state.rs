//! Codex: `codex_native_hook_state` from the files themselves. The runtime
//! reads `config.toml` and `hooks.json`, authenticates this install's hook
//! manifest, verifies it against the installation the caller describes and
//! decides the state launch, doctor and install readback report.
//!
//! The caller sends only what its own process knows: the installation it
//! expects (`spec`) and its package roots. An 8.3 short name a handler command
//! carries is expanded by this host.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use guard_contracts::{
    CodexHookManifestExpectedV1, CodexHookManifestFailureV1, CodexHookManifestVerifyRequestV1,
    CODEX_HOOK_MANIFEST_VERIFY_REQUEST_SCHEMA,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::codex::{config_path, flag, hooks_path, EVENTS};
use super::codex_hook_state::decide;
use super::codex_live_read::{live_hooks, LiveHooks};
use super::{path_text, Ctx, Failure, Step};
use crate::codex_hook_manifest_auth as manifest_auth;
use crate::codex_hook_manifest_refusal::refusal;
use crate::codex_hook_manifest_verify_op::evaluate_request;
use crate::pyjson::{self, PyVal};

type Entries = Vec<(String, PyVal)>;

/// How deep a live hook group and the manifest may nest and still cross to
/// the verifier, as `native_codex_hook_manifest_verify` bounds them.
const MAX_GROUP_DEPTH: usize = 29;
const MAX_MANIFEST_DEPTH: usize = 31;

pub(super) use crate::codex_hook_manifest_refusal::UNAVAILABLE;

/// `codex_native_hook_state`. Request fields: `spec` (the installation the
/// caller expects), `package_roots`, `windows`, `long_paths` and an optional
/// `budget_spent`.
pub(super) fn live_hook_state(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let spec = fields
        .get("spec")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    let config = config_path(ctx);
    let hooks_file = hooks_path(ctx);
    if spec_text(spec, "config_path")? != path_text(&config) {
        return Err(Failure::Invalid);
    }
    let LiveHooks {
        features,
        toml_hooks,
        json_hooks,
        tokens,
    } = LiveHooks::read(ctx);
    let live = live_hooks(&toml_hooks, &json_hooks);
    let state = verified_live_state(ctx, spec, fields, &config, live, &tokens)?;
    let integrity = match pyjson::parse(&Value::Object(state).to_string()) {
        Ok(PyVal::Dict(entries)) => entries,
        _ => return Err(Failure::Invalid),
    };
    let read: Entries = vec![
        ("features".into(), features),
        ("toml_hooks".into(), toml_hooks),
        ("json_hooks".into(), json_hooks),
    ];
    let mut base = fields.clone();
    base.insert("config_path".into(), json!(path_text(&config)));
    base.insert("hooks_path".into(), json!(path_text(&hooks_file)));
    decide(ctx, &base, read, integrity, Some(&tokens))
}

/// The resident verifier's integrity state for the live `hooks` (with the
/// TOML `tokens` they carry), and the manifest path it checked. Request
/// fields are `live_hook_state`'s.
pub(super) fn verified_live_state(
    ctx: &Ctx,
    spec: &Map<String, Value>,
    fields: &Map<String, Value>,
    config: &Path,
    live: &PyVal,
    tokens: &Map<String, Value>,
) -> Step<Map<String, Value>> {
    // A caller whose hook budget is already spent gets the unverified state
    // the resident verifier gave it before, without touching the manifest.
    let loaded = if fields.get("budget_spent").and_then(Value::as_bool) == Some(true) {
        (None, Some(owned(UNAVAILABLE)))
    } else {
        authenticated(ctx, spec, config)?
    };
    verified_state(ctx, spec, config, loaded, hooks_wire(live, tokens), fields)
}

/// The integrity state the verifier decides for one authenticated manifest
/// (or the failure that left none), with the path its config target owns.
pub(super) fn verified_state(
    ctx: &Ctx,
    spec: &Map<String, Value>,
    config: &Path,
    (manifest, failure): Authenticated,
    hooks: Option<Value>,
    fields: &Map<String, Value>,
) -> Step<Map<String, Value>> {
    let request = CodexHookManifestVerifyRequestV1 {
        schema: CODEX_HOOK_MANIFEST_VERIFY_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        posix: cfg!(unix),
        current_uid: current_uid(),
        failure: failure.map(|(reason, message)| CodexHookManifestFailureV1 { reason, message }),
        expected: match &manifest {
            Some(_) => Some(expected(ctx, spec, config)?),
            None => None,
        },
        canonical_paths: manifest
            .as_ref()
            .map(|manifest| canonical_paths(ctx, manifest))
            .unwrap_or_default(),
        installed_python_package_files: manifest
            .as_ref()
            .map(|manifest| installed(ctx, manifest, fields))
            .transpose()?
            .unwrap_or_default(),
        manifest,
        hooks,
        windows: flag(fields, "windows")?,
        long_paths: super::codex_owners::long_paths(fields)?,
        private_groups: Vec::new(),
    };
    let verified = evaluate_request(&request);
    let mut state = verified
        .get("state")
        .and_then(Value::as_object)
        .cloned()
        .ok_or(Failure::Invalid)?;
    let manifest_path = manifest_path(ctx, Path::new(spec_text(spec, "guard_home")?), config);
    state.insert("manifest_path".into(), json!(path_text(&manifest_path)));
    Ok(state)
}

pub(super) fn spec_text<'a>(spec: &'a Map<String, Value>, key: &str) -> Step<&'a str> {
    spec.get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)
}

fn spec_strings(spec: &Map<String, Value>, key: &str) -> Step<Vec<String>> {
    spec.get(key)
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect()
}

/// `load_authenticated_hook_manifest`, or the failure the verifier reports.
pub(super) type Authenticated = (Option<Value>, Option<(String, String)>);

pub(super) fn authenticated(
    ctx: &Ctx,
    spec: &Map<String, Value>,
    config: &Path,
) -> Step<Authenticated> {
    let guard_home = ctx.absolute(Path::new(spec_text(spec, "guard_home")?));
    let path = ctx.absolute(&manifest_path(ctx, &guard_home, config));
    let home = guard_home.to_str().ok_or(Failure::Invalid)?;
    Ok(settled(manifest_auth::load_path(home, &path)))
}

/// The authenticated manifest, or the failure the verifier reports for it.
pub(super) fn settled(loaded: Result<Map<String, Value>, &'static str>) -> Authenticated {
    match loaded {
        Ok(manifest) if depth(&Value::Object(manifest.clone())) <= MAX_MANIFEST_DEPTH => {
            (Some(Value::Object(manifest)), None)
        }
        Ok(_) => (
            None,
            Some(owned((
                "codex_hook_manifest_invalid",
                "The Codex hook manifest holds values Guard cannot verify.",
            ))),
        ),
        Err(reason) => (None, Some(refusal(reason))),
    }
}

pub(super) fn owned((reason, message): (&str, &str)) -> (String, String) {
    (reason.to_owned(), message.to_owned())
}

fn depth(value: &Value) -> usize {
    1 + match value {
        Value::Array(items) => items.iter().map(depth).max().unwrap_or(0),
        Value::Object(entries) => entries.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// `hook_manifest_path`: the manifest a config target owns in a Guard home.
fn manifest_path(ctx: &Ctx, guard_home: &Path, config: &Path) -> PathBuf {
    let target = path_text(&ctx.resolved(config));
    let digest = hex::encode(Sha256::digest(target.as_bytes()));
    guard_home
        .join("managed")
        .join("codex")
        .join(format!("hooks-{}.manifest.json", &digest[..24]))
}

fn canonical(ctx: &Ctx, path: &str) -> String {
    path_text(&ctx.resolved(Path::new(path)))
}

/// The installation `_verify_hook_manifest` expects, canonically spelled.
fn expected(
    ctx: &Ctx,
    spec: &Map<String, Value>,
    config: &Path,
) -> Step<CodexHookManifestExpectedV1> {
    let workspace = match spec.get("workspace_dir") {
        Some(Value::String(path)) => json!(canonical(ctx, path)),
        _ => Value::Null,
    };
    let mut packaged_paths = BTreeMap::new();
    for pair in spec
        .get("packaged_file_paths")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
    {
        let (Some(role), Some(path)) = (
            pair.get(0).and_then(Value::as_str),
            pair.get(1).and_then(Value::as_str),
        ) else {
            return Err(Failure::Invalid);
        };
        packaged_paths.insert(role.to_owned(), canonical(ctx, path));
    }
    Ok(CodexHookManifestExpectedV1 {
        config_path: path_text(config),
        config_target: path_text(&ctx.resolved(config)),
        context: json!({
            "guard_home": canonical(ctx, spec_text(spec, "guard_home")?),
            "home_dir": canonical(ctx, spec_text(spec, "home_dir")?),
            "runtime_guard_home": canonical(ctx, spec_text(spec, "runtime_guard_home")?),
            "workspace_dir": workspace,
        }),
        package_version: spec_text(spec, "package_version")?.to_owned(),
        interpreter_path: spec_text(spec, "interpreter_path")?.to_owned(),
        packaged_paths,
        fallback_argv: spec_strings(spec, "fallback_argv")?,
        daemon_start_argv: spec_strings(spec, "daemon_start_argv")?,
        event_bindings: spec
            .get("event_bindings")
            .and_then(Value::as_array)
            .ok_or(Failure::Invalid)?
            .clone(),
    })
}

/// Every path the manifest names for a packaged file or the interpreter.
fn manifest_paths(manifest: &Value) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    if let Some(files) = manifest.get("packaged_files").and_then(Value::as_array) {
        paths.extend(
            files
                .iter()
                .filter_map(|item| item.get("path").and_then(Value::as_str))
                .map(str::to_owned),
        );
    }
    if let Some(interpreter) = manifest.get("interpreter").filter(|item| item.is_object()) {
        let target = interpreter.get("target").filter(|item| item.is_object());
        for value in [
            interpreter.get("invocation_path"),
            target.and_then(|target| target.get("path")),
        ] {
            if let Some(path) = value.and_then(Value::as_str) {
                paths.push(path.to_owned());
            }
        }
    }
    let mut seen = BTreeSet::new();
    paths.retain(|path| Path::new(path).is_absolute() && seen.insert(path.clone()));
    paths
}

fn canonical_paths(ctx: &Ctx, manifest: &Value) -> BTreeMap<String, String> {
    manifest_paths(manifest)
        .into_iter()
        .map(|path| {
            let spelled = canonical(ctx, &path);
            (path, spelled)
        })
        .collect()
}

/// `_is_installed_python_package_file` for each manifest path.
fn installed(ctx: &Ctx, manifest: &Value, fields: &Map<String, Value>) -> Step<Vec<String>> {
    let roots: Vec<PathBuf> = fields
        .get("package_roots")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|root| root.as_str().map(PathBuf::from).ok_or(Failure::Invalid))
        .collect::<Step<_>>()?;
    Ok(manifest_paths(manifest)
        .into_iter()
        .filter(|path| {
            let resolved = ctx.resolved(Path::new(path));
            roots
                .iter()
                .any(|root| resolved.starts_with(root) && resolved != *root)
        })
        .collect())
}

/// The live hooks as the verifier reads them: each managed event's group
/// list, with a group JSON cannot carry sent as `null`.
pub(super) fn hooks_wire(hooks: &PyVal, tokens: &Map<String, Value>) -> Option<Value> {
    if !matches!(hooks, PyVal::Dict(_)) {
        return None;
    }
    let mut wire = Map::new();
    for (event, ..) in EVENTS {
        if let Some(PyVal::List(groups)) = hooks.get(event) {
            let groups = groups
                .iter()
                .map(|group| plain(group, 1, tokens).unwrap_or(Value::Null))
                .collect();
            wire.insert(event.to_owned(), Value::Array(groups));
        }
    }
    Some(Value::Object(wire))
}

/// `_plain`: the value as JSON, or `None` for one JSON cannot carry.
pub(super) fn plain(value: &PyVal, depth: usize, tokens: &Map<String, Value>) -> Option<Value> {
    if depth > MAX_GROUP_DEPTH {
        return None;
    }
    Some(match value {
        PyVal::Null => Value::Null,
        PyVal::Bool(flag) => Value::Bool(*flag),
        PyVal::Int(digits) => match (digits.parse::<i64>(), digits.parse::<u64>()) {
            (Ok(number), _) => json!(number),
            (_, Ok(number)) => json!(number),
            _ => return None,
        },
        PyVal::Float(number) if number.is_finite() => json!(number),
        PyVal::Float(_) => return None,
        // A token stands for a TOML date or a non-finite float.
        PyVal::Str(text) if tokens.contains_key(text) => return None,
        PyVal::Str(text) => Value::String(text.clone()),
        PyVal::List(items) => Value::Array(
            items
                .iter()
                .map(|item| plain(item, depth + 1, tokens))
                .collect::<Option<_>>()?,
        ),
        PyVal::Dict(entries) => {
            let mut object = Map::new();
            for (key, item) in entries {
                object.insert(key.clone(), plain(item, depth + 1, tokens)?);
            }
            Value::Object(object)
        }
    })
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    Some(nix::unistd::getuid().as_raw())
}

#[cfg(windows)]
fn current_uid() -> Option<u32> {
    None
}

#[cfg(test)]
#[path = "codex_live_state_tests.rs"]
mod tests;
