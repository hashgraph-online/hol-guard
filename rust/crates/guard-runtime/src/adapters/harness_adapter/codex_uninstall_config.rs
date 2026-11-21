//! Codex: the main `config.toml` an uninstall writes.
//!
//! With the install backup (`original`), the config keeps every later edit
//! and loses only what the install added: Guard's hooks are stripped, each
//! remaining hook's `[hooks.state]` entry follows it, and `uninstall_restore`
//! puts back the hook feature and the proxied servers. A result equal to the
//! backup is the backup's exact text. The `hooks.json` beside the config
//! stays as it is; its user hooks keep the feature on, and a change to it
//! while this runs refuses.
//!
//! Without a backup only the handlers the manifest binds go, and their state
//! entries follow as above.
//!
//! Request fields: `config` and `hooks_json` paths, `current` and `original`
//! (base64 bytes, `original` null without a backup), `owned` (JSON text of
//! the manifest bindings) and the owner fields. Answer: `{"delete": bool,
//! "text": <TOML text> | null}`; a null text keeps the current bytes.

use std::path::Path;

use base64::Engine as _;
use serde_json::{json, Map, Value};

use super::codex::{compact, text};
use super::codex_config_hooks::remap;
use super::codex_merge::{get, pop, py_eq, set};
use super::codex_migration::{owner_fields, owners_op, read_toml, render, strings, strip_owned};
use super::codex_uninstall::uninstall_restore;
use super::{path_text, Ctx, Failure, Step};
use crate::codex_toml_read::{self, TomlVal};
use crate::pyjson::{self, PyVal};

type Entries = Vec<(String, PyVal)>;

pub(super) fn uninstall_config(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let config_path = Path::new(text(fields, "config")?);
    let hooks_json = ctx.absolute(Path::new(text(fields, "hooks_json")?));
    let PyVal::List(owned) = pyjson::parse(text(fields, "owned")?).map_err(|_| Failure::Invalid)?
    else {
        return Err(Failure::Invalid);
    };
    let base = owner_fields(fields)?;
    let current_bytes = bytes(fields.get("current"))?.ok_or(Failure::Invalid)?;
    let original = bytes(fields.get("original"))?;
    let current = read_toml(Some(&current_bytes), config_path, "Codex config file")?;
    // An empty backup records a config the install created.
    let backup = original
        .as_deref()
        .filter(|data| !data.is_empty())
        .map(|data| read_toml(Some(data), config_path, "Codex config backup"))
        .transpose()?;

    let json_before = json_bytes(&hooks_json)?;
    let json_hooks = json_bytes_hooks(json_before.as_deref());
    let mut avoid = Vec::new();
    owned
        .iter()
        .for_each(|binding| strings(binding, &mut avoid));
    if let Some(hooks) = &json_hooks {
        strings(hooks, &mut avoid);
    }
    let (current, backup, tokens) = wire(current, backup, &avoid)?;
    let original_text = |data: &[u8]| String::from_utf8_lossy(data).into_owned();
    let current_text = original_text(&current_bytes);

    if original.is_none() {
        let text = manifest_strip(ctx, &base, current, &owned, &tokens, config_path)?
            .map(|payload| {
                render(
                    &compact(&PyVal::Dict(payload), false),
                    &tokens,
                    Some(&current_bytes),
                )
            })
            .transpose()?;
        return Ok(json!({ "delete": false, "text": text }));
    }

    let cleaned = match get(&current, "hooks") {
        Some(PyVal::Dict(hooks)) => {
            let mut cleaned = stripped(&base, &PyVal::Dict(hooks.clone()), &owned)?;
            remap(ctx, &base, hooks, &mut cleaned, &tokens, config_path)?;
            drop_empty_state(&mut cleaned);
            Some(cleaned)
        }
        _ => None,
    };
    let json_cleaned = match &json_hooks {
        Some(hooks @ PyVal::Dict(_)) => Some(stripped(&base, hooks, &owned)?),
        _ => None,
    };
    let mut request = Map::new();
    request.insert(
        "payload".into(),
        json!(compact(&PyVal::Dict(current.clone()), false)),
    );
    request.insert(
        "backup".into(),
        backup.as_ref().map_or(Value::Null, |backup| {
            json!(compact(&PyVal::Dict(backup.clone()), false))
        }),
    );
    request.insert("hooks".into(), dict_text(cleaned));
    request.insert("json_hooks".into(), dict_text(json_cleaned));
    let answer = uninstall_restore(&request)?;
    if json_bytes(&hooks_json)? != json_before {
        return Err(Failure::Runtime(format!(
            "codex_uninstall_config_changed: the Codex config at {} or its hooks file changed \
             while Guard was uninstalling, so Guard left them and the install backup in place. \
             Run `hol-guard uninstall codex` again.",
            path_text(config_path)
        )));
    }
    if answer.get("delete") == Some(&Value::Bool(true)) {
        return Ok(json!({ "delete": true, "text": null }));
    }
    if answer.get("changed") != Some(&Value::Bool(true)) {
        return Ok(json!({ "delete": false, "text": null }));
    }
    let rendered = answer
        .get("rendered")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let parsed = pyjson::parse(rendered).map_err(|_| Failure::Invalid)?;
    // Nothing changed since install: put back the user's exact bytes.
    let unchanged = backup.is_some_and(|backup| py_eq(&parsed, &PyVal::Dict(backup)));
    let text = if unchanged {
        original_text(original.as_deref().unwrap_or_default())
    } else {
        render(rendered, &tokens, Some(current_text.as_bytes()))?
    };
    Ok(json!({ "delete": false, "text": text }))
}

/// A base64 field that may be null.
fn bytes(value: Option<&Value>) -> Step<Option<Vec<u8>>> {
    match value {
        Some(Value::String(encoded)) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map(Some)
            .map_err(|_| Failure::Invalid),
        Some(Value::Null) => Ok(None),
        _ => Err(Failure::Invalid),
    }
}

/// Both payloads in one token space, so equal values share a token.
fn wire(
    current: Vec<(String, TomlVal)>,
    backup: Option<Vec<(String, TomlVal)>>,
    avoid: &[String],
) -> Step<(Entries, Option<Entries>, Map<String, Value>)> {
    let has_backup = backup.is_some();
    let entries = vec![
        ("current".to_owned(), TomlVal::Table(current)),
        (
            "backup".to_owned(),
            TomlVal::Table(backup.unwrap_or_default()),
        ),
    ];
    let avoid: Vec<&str> = avoid.iter().map(String::as_str).collect();
    let (payload, tokens) = codex_toml_read::wire_avoiding(&entries, &avoid);
    let PyVal::Dict(mut parts) = payload else {
        return Err(Failure::Invalid);
    };
    let mut take = |key: &str| match pop(&mut parts, key) {
        Some(PyVal::Dict(entries)) => Ok(entries),
        _ => Err(Failure::Invalid),
    };
    let current = take("current")?;
    let backup = take("backup")?;
    Ok((current, has_backup.then_some(backup), tokens))
}

/// The hooks file's bytes, None when it is absent.
fn json_bytes(path: &Path) -> Step<Option<Vec<u8>>> {
    if !path.exists() {
        return Ok(None);
    }
    std::fs::read(path).map(Some).map_err(|_| {
        Failure::Runtime(format!(
            "codex_uninstall_config_unreadable: Guard could not read the Codex hooks file at {}, \
             so it left the config and the install backup in place. Repair the file's \
             permissions and run `hol-guard uninstall codex` again.",
            path_text(path)
        ))
    })
}

/// The `hooks` table of a readable `hooks.json`. Codex cannot run hooks from
/// a file it cannot parse, so such a file holds none.
fn json_bytes_hooks(data: Option<&[u8]>) -> Option<PyVal> {
    let text = std::str::from_utf8(data?).ok()?;
    match pyjson::parse_unique_naming(text) {
        Ok(PyVal::Dict(entries)) => get(&entries, "hooks")
            .filter(|hooks| matches!(hooks, PyVal::Dict(_)))
            .cloned(),
        _ => None,
    }
}

fn stripped(base: &Map<String, Value>, hooks: &PyVal, owned: &[PyVal]) -> Step<Entries> {
    match pyjson::parse(&strip_owned(base, hooks, owned, true, false)?) {
        Ok(PyVal::Dict(cleaned)) => Ok(cleaned),
        _ => Err(Failure::Invalid),
    }
}

fn drop_empty_state(hooks: &mut Entries) {
    if matches!(get(hooks, "state"), Some(PyVal::Dict(state)) if state.is_empty()) {
        pop(hooks, "state");
    }
}

fn dict_text(hooks: Option<Entries>) -> Value {
    hooks.map_or(Value::Null, |hooks| {
        json!(compact(&PyVal::Dict(hooks), false))
    })
}

/// No backup: the payload without the handlers the manifest binds, or None
/// when none is there.
fn manifest_strip(
    ctx: &Ctx,
    base: &Map<String, Value>,
    mut payload: Entries,
    owned: &[PyVal],
    tokens: &Map<String, Value>,
    config_path: &Path,
) -> Step<Option<Entries>> {
    let Some(PyVal::Dict(hooks)) = get(&payload, "hooks").cloned() else {
        return Ok(None);
    };
    if owned.is_empty() {
        return Ok(None);
    }
    let mut request = Map::new();
    for key in ["windows", "long_paths"] {
        request.insert(key.into(), base.get(key).cloned().ok_or(Failure::Invalid)?);
    }
    let mut extra = Map::new();
    extra.insert(
        "hooks".into(),
        json!(compact(&PyVal::Dict(hooks.clone()), false)),
    );
    extra.insert(
        "bindings".into(),
        json!(compact(&PyVal::List(owned.to_vec()), false)),
    );
    let answer = owners_op(&request, "remove", extra)?;
    if answer.get("changed") != Some(&Value::Bool(true)) {
        return Ok(None);
    }
    let PyVal::Dict(mut cleaned) = answer
        .get("hooks")
        .and_then(Value::as_str)
        .and_then(|hooks| pyjson::parse(hooks).ok())
        .ok_or(Failure::Invalid)?
    else {
        return Err(Failure::Invalid);
    };
    remap(ctx, base, &hooks, &mut cleaned, tokens, config_path)?;
    drop_empty_state(&mut cleaned);
    if cleaned.is_empty() {
        pop(&mut payload, "hooks");
    } else {
        set(&mut payload, "hooks", PyVal::Dict(cleaned));
    }
    Ok(Some(payload))
}
