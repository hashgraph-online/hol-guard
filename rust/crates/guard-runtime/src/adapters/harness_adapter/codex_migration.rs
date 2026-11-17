//! Codex: `prepare_codex_hook_migration`, the step an install plans per
//! config and `hooks.json` pair before it writes its own groups.
//!
//! Both files are read without following links and parsed here. Every active
//! handler is inventoried (`preactivation`), and with `require_owners` each
//! one must have a verified owner. The legacy `hooks.json` groups, less the
//! handlers Guard owns, fold into the config, which is rendered onto the text
//! it was read from. `hooks.json` is retired, and a changed config keeps its
//! original in the migration backup.
//!
//! Request fields: `config` and `hooks` paths, `owned` (JSON text of the
//! manifest bindings), `require_owners`, and the owner fields `strip` reads
//! (`cwd`, `guard_home`, `package_root`, `expected`, `argv`, `legacy_argv`,
//! `statuses`, `windows`, `long_paths`). Answer: `{"files": [...], "config":
//! <payload JSON text>, "tokens": {token: meaning}}`. A Windows short name is
//! expanded by this host, as `codex_hook_owners` does.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::codex::{compact, flag, scope_for, text};
use super::codex_merge::get;
use super::files::{self, Change};
use super::{codex_files, codex_merge, codex_owners, path_text, Ctx, Failure, Step};
use crate::codex_toml_read::{self, ReadError};
use crate::guard_store_json::py_repr_str;
use crate::pyjson::{self, JsonFailure, PyVal};

const DUPLICATE: &str = "codex_hook_inventory_source_duplicate_key";
const MALFORMED: &str = "codex_hook_inventory_source_malformed";
const PRIVATE_MODE: u32 = 0o600;
/// The fields every owner op takes besides its own.
const OWNER_FIELDS: [&str; 9] = [
    "cwd",
    "guard_home",
    "package_root",
    "expected",
    "argv",
    "legacy_argv",
    "statuses",
    "windows",
    "long_paths",
];

pub(super) fn migration(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let config_path = canonical(ctx, Path::new(text(fields, "config")?));
    let hooks_path = canonical(ctx, Path::new(text(fields, "hooks")?));
    let owned = match pyjson::parse(text(fields, "owned")?) {
        Ok(PyVal::List(owned)) => owned,
        _ => return Err(Failure::Invalid),
    };
    let require_owners = flag(fields, "require_owners")?;
    let owner_fields = owner_fields(fields)?;
    let scope = scope_for(ctx, &config_path);

    let (before_config, config_mode) = existing(ctx, &config_path)?;
    let (before_hooks, hooks_mode) = existing(ctx, &hooks_path)?;
    let config_entries = read_toml(before_config.as_deref(), &config_path, "Codex config file")?;
    let hooks = read_json(before_hooks.as_deref(), &hooks_path, "Codex hooks file")?;
    let mut avoid = Vec::new();
    strings(&PyVal::Dict(hooks.clone()), &mut avoid);
    owned
        .iter()
        .for_each(|binding| strings(binding, &mut avoid));
    let avoid: Vec<&str> = avoid.iter().map(String::as_str).collect();
    let (config, tokens) = codex_toml_read::wire_avoiding(&config_entries, &avoid);
    let PyVal::Dict(config) = config else {
        return Err(Failure::Invalid);
    };
    let enabled = hooks_enabled(&config);
    let no_bindings: Vec<PyVal> = Vec::new();
    for (payload, path, format, bindings) in [
        (&config, &config_path, "toml", &owned),
        (&hooks, &hooks_path, "json", &no_bindings),
    ] {
        let owners = preactivation(
            &owner_fields,
            get(payload, "hooks").unwrap_or(&PyVal::Null),
            bindings,
            &tokens,
            (path, scope, format, enabled),
        )?;
        if require_owners {
            for owner in owners {
                require_owner(&owner_fields, &owner, path)?;
            }
        }
    }

    let (config, changed) = match get(&hooks, "hooks") {
        Some(json_hooks @ PyVal::Dict(_)) => {
            let cleaned = strip(&owner_fields, json_hooks, &owned)?;
            migrate(&config, &cleaned, &tokens, scope)?
        }
        _ => (compact(&PyVal::Dict(config), false), false),
    };
    let config_text = if changed {
        Some(render(&config, &tokens, before_config.as_deref())?)
    } else {
        None
    };
    let mut files = vec![
        Change {
            path: config_path.clone(),
            after: config_text
                .map(String::into_bytes)
                .or_else(|| before_config.clone()),
            before: before_config.clone(),
            before_mode: config_mode,
            after_mode: if changed { PRIVATE_MODE } else { config_mode },
            no_follow: true,
        }
        .wire(),
        Change {
            path: hooks_path,
            before: before_hooks,
            after: None,
            before_mode: hooks_mode,
            after_mode: hooks_mode,
            no_follow: true,
        }
        .wire(),
    ];
    if changed {
        let mut request = Map::new();
        request.insert("config".into(), json!(path_text(&config_path)));
        request.insert("before".into(), json!(encoded(before_config.as_deref())));
        let backup = codex_files::migration_backup(ctx, &request)?;
        files.push(backup.get("file").cloned().ok_or(Failure::Invalid)?);
    }
    Ok(json!({ "files": files, "config": config, "tokens": tokens }))
}

/// `path.parent.resolve(strict=False) / path.name`.
fn canonical(ctx: &Ctx, path: &Path) -> PathBuf {
    let path = ctx.absolute(path);
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => ctx.resolved(parent).join(name),
        _ => path,
    }
}

/// The snapshot and its mode, `0o600` for an absent file.
fn existing(ctx: &Ctx, path: &Path) -> Step<(Option<Vec<u8>>, u32)> {
    let before = files::snapshot(ctx, path)?;
    let mode = match before {
        Some(_) => files::mode(ctx, path).unwrap_or(PRIVATE_MODE),
        None => PRIVATE_MODE,
    };
    Ok((before, mode))
}

fn encoded(bytes: Option<&[u8]>) -> Option<String> {
    use base64::Engine as _;
    bytes.map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// `parse_toml_object` over the captured bytes.
pub(super) fn read_toml(
    data: Option<&[u8]>,
    path: &Path,
    label: &str,
) -> Step<Vec<(String, codex_toml_read::TomlVal)>> {
    let Some(data) = data else {
        return Ok(Vec::new());
    };
    let refused = |reason: &str| {
        Failure::Runtime(format!(
            "{reason}: Guard could not parse {label} at {}. Repair the TOML before retrying \
             install.",
            path_text(path)
        ))
    };
    let text = std::str::from_utf8(data).map_err(|_| refused(MALFORMED))?;
    codex_toml_read::read(text).map_err(|error| match error {
        ReadError::DuplicateKey => refused(DUPLICATE),
        ReadError::Malformed => refused(MALFORMED),
    })
}

/// `parse_json_object` over the captured bytes.
pub(super) fn read_json(
    data: Option<&[u8]>,
    path: &Path,
    label: &str,
) -> Step<Vec<(String, PyVal)>> {
    let Some(data) = data else {
        return Ok(Vec::new());
    };
    let path = path_text(path);
    let malformed = || {
        Failure::Runtime(format!(
            "{MALFORMED}: Guard refused to overwrite unreadable {label} at {path} because its \
             JSON is malformed. Repair the JSON before retrying install."
        ))
    };
    let text = std::str::from_utf8(data).map_err(|_| malformed())?;
    match pyjson::parse_unique_naming(text) {
        Ok(PyVal::Dict(entries)) => Ok(entries),
        Ok(_) => Err(Failure::Runtime(format!(
            "{MALFORMED}: Guard refused to overwrite non-object {label} at {path}. Replace it \
             with a JSON object before retrying install."
        ))),
        Err((JsonFailure::Duplicate, Some(key))) => Err(Failure::Runtime(format!(
            "{DUPLICATE}: Guard found duplicate key {} in {label} at {path}. Remove the \
             duplicate before retrying install.",
            py_repr_str(&key)
        ))),
        Err(_) => Err(malformed()),
    }
}

pub(super) fn strings(value: &PyVal, out: &mut Vec<String>) {
    match value {
        PyVal::Str(text) => out.push(text.clone()),
        PyVal::List(items) => items.iter().for_each(|item| strings(item, out)),
        PyVal::Dict(entries) => {
            for (key, item) in entries {
                out.push(key.clone());
                strings(item, out);
            }
        }
        _ => {}
    }
}

/// `_payload_has_hooks_feature_enabled`.
fn hooks_enabled(entries: &[(String, PyVal)]) -> bool {
    match get(entries, "features").and_then(PyVal::as_dict) {
        Some(features) => !matches!(get(features, "hooks"), Some(PyVal::Bool(false))),
        None => true,
    }
}

pub(super) fn owner_fields(fields: &Map<String, Value>) -> Step<Map<String, Value>> {
    OWNER_FIELDS
        .iter()
        .map(|key| {
            let value = fields.get(*key).cloned().ok_or(Failure::Invalid)?;
            Ok(((*key).to_owned(), value))
        })
        .collect()
}

/// One `codex_hook_owners` op over the shared owner fields.
pub(super) fn owners_op(
    base: &Map<String, Value>,
    op: &str,
    extra: Map<String, Value>,
) -> Step<Value> {
    let mut request = base.clone();
    request.insert("op".into(), json!(op));
    request.extend(extra);
    codex_owners::dispatch(&request)
}

pub(super) fn without_legacy(base: &Map<String, Value>) -> Map<String, Value> {
    let mut request = base.clone();
    for key in [
        "cwd",
        "guard_home",
        "package_root",
        "expected",
        "argv",
        "legacy_argv",
        "statuses",
    ] {
        request.remove(key);
    }
    request
}

/// `_preactivation_owners`: each active handler's command and ownership.
fn preactivation(
    base: &Map<String, Value>,
    hooks: &PyVal,
    owned: &[PyVal],
    tokens: &Map<String, Value>,
    (path, scope, format, enabled): (&Path, &str, &str, bool),
) -> Step<Vec<Map<String, Value>>> {
    let mut extra = Map::new();
    extra.insert("hooks".into(), json!(compact(hooks, false)));
    extra.insert(
        "owned".into(),
        json!(compact(&PyVal::List(owned.to_vec()), false)),
    );
    extra.insert("tokens".into(), Value::Object(tokens.clone()));
    extra.insert("source_path".into(), json!(path_text(path)));
    extra.insert("scope".into(), json!(scope));
    extra.insert("format".into(), json!(format));
    extra.insert("hooks_enabled".into(), json!(enabled));
    let answer = owners_op(base, "preactivation", extra)?;
    let owners = answer
        .get("owners")
        .and_then(Value::as_array)
        .ok_or_else(|| Failure::Runtime("codex_hook_owners answered without owners".into()))?;
    owners
        .iter()
        .map(|owner| owner.as_object().cloned().ok_or(Failure::Invalid))
        .collect()
}

/// `_require_preactivation_owners` for one handler.
fn require_owner(base: &Map<String, Value>, owner: &Map<String, Value>, path: &Path) -> Step<()> {
    let mut extra = Map::new();
    for key in ["command", "ownership", "coordinate"] {
        let value = owner
            .get(key)
            .and_then(Value::as_str)
            .ok_or(Failure::Invalid)?;
        extra.insert(key.into(), json!(value));
    }
    extra.insert("source_path".into(), json!(path_text(path)));
    let answer = owners_op(&without_legacy(base), "owner", extra)?;
    match answer.get("conflict").and_then(Value::as_str) {
        Some(conflict) => Err(Failure::Runtime(conflict.to_owned())),
        None => Ok(()),
    }
}

/// `_strip_owned_hooks(..., unlaunchable=True, hold_recorded=False)`.
fn strip(base: &Map<String, Value>, hooks: &PyVal, owned: &[PyVal]) -> Step<String> {
    strip_owned(base, hooks, owned, true, false)
}

/// `_strip_owned_hooks`: the hooks, as JSON text, once Guard's own are gone.
pub(super) fn strip_owned(
    base: &Map<String, Value>,
    hooks: &PyVal,
    owned: &[PyVal],
    unlaunchable: bool,
    hold_recorded: bool,
) -> Step<String> {
    let mut extra = Map::new();
    extra.insert("hooks".into(), json!(compact(hooks, false)));
    extra.insert(
        "owned".into(),
        json!(compact(&PyVal::List(owned.to_vec()), false)),
    );
    extra.insert("unlaunchable".into(), json!(unlaunchable));
    extra.insert("hold_recorded".into(), json!(hold_recorded));
    let answer = owners_op(base, "strip", extra)?;
    answer
        .get("hooks")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Failure::Invalid)
}

/// `_migrate_hooks_json_into_config`: the config and whether it changed.
fn migrate(
    config: &[(String, PyVal)],
    hooks: &str,
    tokens: &Map<String, Value>,
    scope: &str,
) -> Step<(String, bool)> {
    let mut request = Map::new();
    request.insert(
        "config".into(),
        json!(compact(&PyVal::Dict(config.to_vec()), false)),
    );
    request.insert("hooks".into(), json!(hooks));
    request.insert("tokens".into(), Value::Object(tokens.clone()));
    request.insert("scope".into(), json!(scope));
    let answer = codex_merge::dispatch("migrate", &request)?;
    let config = answer
        .get("config")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    Ok((
        config.to_owned(),
        answer.get("changed") == Some(&json!(true)),
    ))
}

/// `dump_toml(config, original=before)`.
pub(super) fn render(
    config: &str,
    tokens: &Map<String, Value>,
    original: Option<&[u8]>,
) -> Step<String> {
    let original = original.map(|bytes| String::from_utf8_lossy(bytes).into_owned());
    let answer = crate::codex_toml_render::dispatch(&json!({
        "payload": config,
        "tokens": tokens,
        "original": original,
    }))
    .map_err(|_| Failure::Invalid)?;
    answer
        .get("text")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Failure::Invalid)
}
