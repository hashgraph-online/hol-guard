//! `publication_repair_plan`: the checked payload and approval subject of a
//! prepared Codex authority repair, ported from
//! `PreparedCodexHookRepair.payload` and `.subject`.
//!
//! A repair may only restore the missing manifest from retained authority.
//! Every other file is an exact-digest dependency, and the key, the
//! authority receipt and the config must be among them. When the repair
//! names the native runtime that verifies it, that binary must be one of the
//! dependencies and still carry the generation the plan captured.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::inspect::{resolve_lenient, sha256_hex};
use super::publication::Call;
use super::{Fault, Step};
use crate::codex_hook_authority_record::python_json::python_canonical_json;
use crate::runtime_transition_record::check_change;

pub(super) const SCHEMA: &str = "hol-guard.codex-authority-repair-plan.v1";
pub(super) const ACTION: &str = "apps.repair.codex-authority";
const MAX_FILES: usize = 128;
const INVALID: Fault = Fault::Transition("authority_repair_plan_invalid");
const BINDING: Fault = Fault::Transition("authority_repair_native_binding_invalid");
const CHANGED: Fault = Fault::Transition("native_runtime_generation_changed");

pub(super) fn plan(call: &mut Call<'_>) -> Step<Value> {
    let payload = payload(call.args)?;
    let canonical = python_canonical_json(&Value::Object(payload.clone())).ok_or(INVALID)?;
    let operation = payload
        .get("operation_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let subject = format!(
        "codex-authority-repair:{operation}:{}",
        sha256_hex(canonical.as_bytes())
    );
    Ok(json!({ "payload": payload, "subject": subject }))
}

fn text<'a>(args: &'a Map<String, Value>, key: &str) -> Step<&'a str> {
    args.get(key).and_then(Value::as_str).ok_or(INVALID)
}

pub(super) fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn spelled(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub(super) fn payload(args: &Map<String, Value>) -> Step<Map<String, Value>> {
    let operation = text(args, "operation_id")?;
    if !canonical_uuid(operation) {
        return Err(INVALID);
    }
    let home = resolve_lenient(Path::new(text(args, "home")?));
    let config = PathBuf::from(text(args, "config")?);
    let config = match (config.parent(), config.file_name()) {
        (Some(parent), Some(name)) => resolve_lenient(parent).join(name),
        _ => return Err(INVALID),
    };
    let files: Vec<&Map<String, Value>> = args
        .get("files")
        .and_then(Value::as_array)
        .ok_or(INVALID)?
        .iter()
        .map(|item| item.as_object().ok_or(INVALID))
        .collect::<Step<_>>()?;
    let change = args
        .get("change")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    check_files(&home, &config, &files, change)?;
    for item in &files {
        check_change(item).map_err(|(reason, detail)| Fault::Refused(reason, detail))?;
    }
    let mut payload = Map::new();
    payload.insert("schema".to_owned(), json!(SCHEMA));
    payload.insert("action".to_owned(), json!(ACTION));
    payload.insert("guard_home".to_owned(), json!(spelled(&home)));
    payload.insert("config_path".to_owned(), json!(spelled(&config)));
    payload.insert("operation_id".to_owned(), json!(operation));
    payload.insert(
        "files".to_owned(),
        Value::Array(
            files
                .iter()
                .map(|item| Value::Object((*item).clone()))
                .collect(),
        ),
    );
    let native = args.get("native_runtime").filter(|value| !value.is_null());
    let workspace = args
        .get("verification_workspace")
        .filter(|value| !value.is_null());
    if native.is_some() || workspace.is_some() {
        let (native, workspace) = binding(native, workspace, &files)?;
        payload.insert("native_runtime".to_owned(), native);
        payload.insert("verification_workspace".to_owned(), json!(workspace));
    }
    Ok(payload)
}

fn field<'a>(item: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    item.get(key).filter(|value| !value.is_null())
}

fn check_files(
    home: &Path,
    config: &Path,
    files: &[&Map<String, Value>],
    change: &Map<String, Value>,
) -> Step<()> {
    let path =
        |item: &Map<String, Value>| item.get("path").and_then(Value::as_str).map(str::to_owned);
    let mut seen = std::collections::BTreeSet::new();
    for item in files {
        seen.insert(path(item).ok_or(INVALID)?);
    }
    let (manifest, receipt) = Call::targets(home, &spelled(&resolve_lenient(config)));
    let changed = change.get("after").and_then(Value::as_str).is_some();
    if files.len() > MAX_FILES
        || seen.len() != files.len()
        || path(change).as_deref() != Some(spelled(&manifest).as_str())
        || field(change, "before").is_some()
        || !changed
        || field(change, "expected_digest").is_some()
        || change.get("no_follow") != Some(&Value::Bool(true))
        || change.get("kind").and_then(Value::as_str) != Some("binding")
        || change.get("after_mode").and_then(Value::as_u64) != Some(0o600)
        || files.iter().filter(|item| **item == change).count() != 1
        || files.iter().any(|item| {
            *item != change
                && (field(item, "expected_digest").is_none()
                    || field(item, "before").is_some()
                    || field(item, "after").is_some())
        })
    {
        return Err(INVALID);
    }
    let secret = home.join("managed").join("codex").join("hook-manifest.key");
    let digested: std::collections::BTreeSet<String> = files
        .iter()
        .filter(|item| field(item, "expected_digest").is_some())
        .filter_map(|item| path(item))
        .collect();
    for required in [&secret, &receipt, &config.to_path_buf()] {
        if !digested.contains(&spelled(required)) {
            return Err(INVALID);
        }
    }
    Ok(())
}

fn integer(value: Option<&Value>) -> Option<i128> {
    match value {
        Some(Value::Number(number)) => number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from)),
        _ => None,
    }
}

fn exact(path: &Path) -> bool {
    path.is_absolute() && resolve_lenient(path) == path
}

fn binding(
    native: Option<&Value>,
    workspace: Option<&Value>,
    files: &[&Map<String, Value>],
) -> Step<(Value, String)> {
    let native = native.and_then(Value::as_object).ok_or(BINDING)?;
    let workspace = PathBuf::from(workspace.and_then(Value::as_str).ok_or(BINDING)?);
    let binary = PathBuf::from(native.get("path").and_then(Value::as_str).ok_or(BINDING)?);
    let size = integer(native.get("size"))
        .filter(|size| *size > 0)
        .ok_or(BINDING)?;
    let mtime = integer(native.get("mtime_ns")).ok_or(BINDING)?;
    let digest = native
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or(BINDING)?;
    let hex = digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let bound = files.iter().any(|item| {
        item.get("path").and_then(Value::as_str) == Some(spelled(&binary).as_str())
            && item.get("expected_digest").and_then(Value::as_str) == Some(digest)
            && field(item, "artifact_identity")
                .and_then(Value::as_object)
                .is_some_and(|identity| integer(identity.get("size")) == Some(size))
    });
    if !exact(&workspace) || !workspace.is_dir() || !exact(&binary) || !hex || !bound {
        return Err(BINDING);
    }
    if modified_ns(&binary).ok_or(CHANGED)? != mtime {
        return Err(CHANGED);
    }
    let native = json!({
        "path": spelled(&binary),
        "size": native.get("size"),
        "mtime_ns": native.get("mtime_ns"),
        "sha256": digest,
    });
    Ok((native, spelled(&workspace)))
}

/// `os.stat(path).st_mtime_ns`.
fn modified_ns(path: &Path) -> Option<i128> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    match modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(after) => i128::try_from(after.as_nanos()).ok(),
        Err(before) => i128::try_from(before.duration().as_nanos())
            .ok()
            .map(|n| -n),
    }
}
