//! Codex: the main config's part of an install plan.
//!
//! The `hooks.json` beside the main config folds into it (`hook_migration`),
//! the install backup is kept or captured (`main_backup`), and Guard's hook
//! groups go in (`config_hooks`). Every user hook the migration carried over
//! must still be there afterwards.
//!
//! Request fields: `config` and `hooks` paths, `before_config` and
//! `before_hooks` (base64 bytes the caller captured, or null), `owned` (JSON
//! text of the manifest bindings), `managed` (JSON text of Guard's groups),
//! `require_owners` and the owner fields. Answer: `{"config": <payload JSON
//! text>, "tokens": {...}, "backup": <file>, "files": [...]}` with the
//! migration's files after the config change, or `{"conflict": true}` when
//! either file changed after the caller read it.

use serde_json::{json, Map, Value};

use super::codex::{compact, scope_for, text};
use super::codex_alternate_plan::{decoded, expected_hooks};
use super::codex_config_hooks::install;
use super::codex_files::main_backup;
use super::codex_merge;
use super::codex_migration::{migration, owner_fields, render};
use super::{Ctx, Failure, Step};
use crate::pyjson::{self, PyVal};

pub(super) fn main_plan(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let base = owner_fields(fields)?;
    let parse = |key: &str| pyjson::parse(text(fields, key)?).map_err(|_| Failure::Invalid);
    let PyVal::List(owned) = parse("owned")? else {
        return Err(Failure::Invalid);
    };
    let managed = parse("managed")?;
    if !matches!(managed, PyVal::Dict(_)) {
        return Err(Failure::Invalid);
    }
    let migrated = migration(ctx, fields)?;
    let files = migrated
        .get("files")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    let [config_file, hooks_file, ..] = files.as_slice() else {
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
    let tokens = migrated
        .get("tokens")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    let before = decoded(config_file.get("before"))?;
    let was_migrated = before != decoded(config_file.get("after"))?;

    let mut backup_request = Map::new();
    if was_migrated {
        backup_request.insert(
            "migrated".into(),
            json!(render(config, tokens, before.as_deref())?),
        );
    } else {
        backup_request.insert(
            "original".into(),
            config_file.get("before").cloned().unwrap_or(Value::Null),
        );
    }
    let backup = main_backup(ctx, &backup_request)?;

    let PyVal::Dict(payload) = pyjson::parse(config).map_err(|_| Failure::Invalid)? else {
        return Err(Failure::Invalid);
    };
    let config_path = std::path::Path::new(text(fields, "config")?);
    let payload = install(ctx, &base, payload, (&owned, &managed), tokens, config_path)?;
    let payload = compact(&PyVal::Dict(payload), false);

    let expected = expected_hooks(&base, &owned, decoded(hooks_file.get("before"))?.as_deref())?;
    let mut subset = Map::new();
    subset.insert("expected".into(), json!(expected));
    subset.insert("actual".into(), json!(payload));
    subset.insert("tokens".into(), json!(tokens));
    subset.insert("scope".into(), json!(scope_for(ctx, config_path)));
    codex_merge::dispatch("subset", &subset)?;

    Ok(json!({
        "config": payload,
        "tokens": tokens,
        "backup": backup.get("file").cloned().ok_or(Failure::Invalid)?,
        "files": files[1..].to_vec(),
    }))
}
