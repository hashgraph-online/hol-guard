//! Codex: the install plan for one config besides the main one.
//!
//! The config's `hooks.json` folds into it (`hook_migration`), then Guard's
//! own entries come out of the result (`alternate_cleanup`), which is
//! rendered onto the migrated text so the plan and an ordinary install agree
//! on its spacing. Every user hook the migration carried over must still be
//! there. The files are the config change, the retired `hooks.json` and the
//! migration backup when the config changed.
//!
//! Request fields: `config` and `hooks` paths, `before_config` and
//! `before_hooks` (base64 bytes the caller captured, or null),
//! `managed_server_names`, `require_owners` and the owner fields. Answer:
//! `{"files": [...]}`, or `{"conflict": true}` when either file changed
//! after the caller read it.

use base64::Engine as _;
use serde_json::{json, Map, Value};

use super::codex::{compact, scope_for, text};
use super::codex_files::existing;
use super::codex_merge::{self, get};
use super::codex_migration::{migration, owner_fields, read_toml, render, strip_owned};
use super::codex_servers::alternate_cleanup;
use super::files::Change;
use super::{Ctx, Failure, Step};
use crate::codex_toml_read;
use crate::pyjson::{self, PyVal};

const PRIVATE_MODE: u32 = 0o600;

pub(super) fn alternate_plan(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let base = owner_fields(fields)?;
    let mut request = fields.clone();
    request.insert("owned".into(), json!("[]"));
    let migrated = migration(ctx, &request)?;
    let files = migrated
        .get("files")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    let [config_file, hooks_file, rest @ ..] = files.as_slice() else {
        return Err(Failure::Invalid);
    };
    if config_file.get("before") != fields.get("before_config")
        || hooks_file.get("before") != fields.get("before_hooks")
    {
        return Ok(json!({ "conflict": true }));
    }
    let config = migrated
        .get("config")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let tokens = migrated.get("tokens").cloned().ok_or(Failure::Invalid)?;
    let token_map = tokens.as_object().ok_or(Failure::Invalid)?;

    let mut cleanup = base.clone();
    cleanup.insert("payload".into(), json!(config));
    cleanup.insert("tokens".into(), tokens.clone());
    cleanup.insert("remove_hooks".into(), json!(true));
    cleanup.insert(
        "managed_server_names".into(),
        fields
            .get("managed_server_names")
            .cloned()
            .ok_or(Failure::Invalid)?,
    );
    let cleaned = alternate_cleanup(&cleanup)?;
    let rendered = cleaned
        .get("rendered")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let flag = |key: &str| cleaned.get(key) == Some(&Value::Bool(true));

    let before = decoded(config_file.get("before"))?;
    let after = decoded(config_file.get("after"))?;
    let was_migrated = before != after;
    let before_mode = config_file
        .get("before_mode")
        .and_then(Value::as_u64)
        .and_then(|mode| u32::try_from(mode).ok())
        .ok_or(Failure::Invalid)?;
    let config_path = std::path::Path::new(
        config_file
            .get("path")
            .and_then(Value::as_str)
            .ok_or(Failure::Invalid)?,
    );
    let planned = if was_migrated || flag("changed") {
        let original = if was_migrated { &after } else { &before };
        Some(render(rendered, token_map, original.as_deref())?.into_bytes())
    } else {
        before.clone()
    };

    let scope = scope_for(ctx, std::path::Path::new(text(fields, "config")?));
    let expected = expected_hooks(&base, &[], decoded(hooks_file.get("before"))?.as_deref())?;
    let mut subset = Map::new();
    subset.insert("expected".into(), json!(expected));
    subset.insert("actual".into(), json!(rendered));
    subset.insert("tokens".into(), tokens);
    subset.insert("scope".into(), json!(scope));
    codex_merge::dispatch("subset", &subset)?;

    let mut planned_files = vec![Change {
        path: config_path.to_path_buf(),
        before,
        after: planned,
        before_mode,
        after_mode: if was_migrated || flag("hooks_changed") {
            PRIVATE_MODE
        } else {
            before_mode
        },
        no_follow: true,
    }
    .wire()];
    planned_files.push(hooks_file.clone());
    planned_files.extend(rest.iter().cloned());
    Ok(json!({ "files": planned_files }))
}

pub(super) fn decoded(value: Option<&Value>) -> Step<Option<Vec<u8>>> {
    match value {
        Some(Value::String(encoded)) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map(Some)
            .map_err(|_| Failure::Invalid),
        Some(Value::Null) | None => Ok(None),
        _ => Err(Failure::Invalid),
    }
}

/// `_unmanaged_migration_payload`: the `hooks.json` hooks the migration
/// keeps, pruned by the same rule, as payload JSON text.
pub(super) fn expected_hooks(
    base: &Map<String, Value>,
    owned: &[PyVal],
    data: Option<&[u8]>,
) -> Step<String> {
    let entries = match data.map(std::str::from_utf8) {
        Some(Ok(text)) => match pyjson::parse_unique_naming(text) {
            Ok(PyVal::Dict(entries)) => entries,
            _ => return Err(Failure::Invalid),
        },
        Some(Err(_)) => return Err(Failure::Invalid),
        None => Vec::new(),
    };
    let hooks = match get(&entries, "hooks") {
        Some(hooks @ PyVal::Dict(_)) => hooks,
        _ => return Ok("{}".into()),
    };
    let cleaned = strip_owned(base, hooks, owned, true, false)?;
    Ok(match pyjson::parse(&cleaned) {
        Ok(PyVal::Dict(entries)) if entries.is_empty() => "{}".into(),
        Ok(PyVal::Dict(_)) => format!("{{\"hooks\":{cleaned}}}"),
        _ => return Err(Failure::Invalid),
    })
}

/// `prepare_codex_alternate_cleanup`: one config without this install's
/// legacy hooks (`remove_hooks`) and the named proxied servers, as a file
/// change. Request fields: `config`, `remove_hooks`, `managed_server_names`
/// and the owner fields. Answer: `{"file": <change>}`.
pub(super) fn alternate_change(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let given = std::path::Path::new(text(fields, "config")?);
    let path = match (given.parent(), given.file_name()) {
        (Some(parent), Some(name)) => ctx.resolved(parent).join(name),
        _ => ctx.absolute(given),
    };
    let (before, mode) = existing(ctx, &path)?;
    let entries = read_toml(before.as_deref(), &path, "Codex config file")?;
    let (payload, tokens) = codex_toml_read::wire(&entries);
    let mut cleanup = owner_fields(fields)?;
    cleanup.insert("payload".into(), json!(compact(&payload, false)));
    cleanup.insert("tokens".into(), json!(tokens));
    cleanup.insert(
        "remove_hooks".into(),
        json!(fields.get("remove_hooks").and_then(Value::as_bool) == Some(true)),
    );
    cleanup.insert(
        "managed_server_names".into(),
        fields
            .get("managed_server_names")
            .cloned()
            .ok_or(Failure::Invalid)?,
    );
    let cleaned = alternate_cleanup(&cleanup)?;
    let flag = |key: &str| cleaned.get(key) == Some(&Value::Bool(true));
    let after = if flag("changed") {
        let rendered = cleaned
            .get("rendered")
            .and_then(Value::as_str)
            .ok_or(Failure::Invalid)?;
        Some(render(rendered, &tokens, before.as_deref())?.into_bytes())
    } else {
        before.clone()
    };
    let change = Change {
        path,
        before,
        after,
        before_mode: mode,
        after_mode: if flag("hooks_changed") {
            PRIVATE_MODE
        } else {
            mode
        },
        no_follow: true,
    };
    Ok(json!({ "file": change.wire() }))
}
