//! What a runtime transition record may hold: the planned files and their
//! dependencies, the managed install rows, the native runtime bindings and
//! the artifact identities. Every refusal is the reason code the Python
//! transition layer raised for the same record.

use std::collections::HashSet;
use std::path::Path;

use serde_json::{Map, Value};

/// A refusal reason, with the file it names when there is one.
pub(crate) type Refusal = (String, Option<String>);

fn refuse<T>(reason: &str) -> Result<T, Refusal> {
    Err((reason.to_owned(), None))
}

const FILE_FIELDS: [&str; 6] = [
    "path",
    "before",
    "after",
    "before_mode",
    "after_mode",
    "kind",
];
const FILE_OPTIONAL: [&str; 4] = [
    "no_follow",
    "expected_digest",
    "artifact_identity",
    "invocation_identity",
];
const ARTIFACT_FIELDS: [&str; 7] = [
    "version",
    "source_commit",
    "target",
    "format",
    "sha256",
    "path",
    "generation",
];

fn object<'a>(value: &'a Value, reason: &str) -> Result<&'a Map<String, Value>, Refusal> {
    value.as_object().map_or_else(|| refuse(reason), Ok)
}

fn keys_are(map: &Map<String, Value>, keys: &[&str]) -> bool {
    map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))
}

/// `_record_objects`: a list of at most `maximum` objects; absent is empty.
pub(crate) fn record_objects<'a>(
    payload: &'a Map<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<Vec<&'a Map<String, Value>>, Refusal> {
    let reason = format!("{key}_invalid");
    let Some(value) = payload.get(key) else {
        return Ok(Vec::new());
    };
    let items = value.as_array().filter(|items| items.len() <= maximum);
    let Some(items) = items else {
        return refuse(&reason);
    };
    items.iter().map(|item| object(item, &reason)).collect()
}

/// `_record_number`: a finite number; booleans and absence are refused.
pub(crate) fn record_number(payload: &Map<String, Value>, key: &str) -> Result<f64, Refusal> {
    payload
        .get(key)
        .and_then(Value::as_f64)
        .filter(|number| number.is_finite())
        .map_or_else(|| refuse("deadline_invalid"), Ok)
}

pub(crate) fn lower_hex_64(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn integer(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

/// An owner the record may pin: root or this user. Windows records none.
fn trusted_owner(value: &Value) -> bool {
    match value {
        Value::Null => !cfg!(unix),
        _ => integer(value).is_some_and(|owner| owner >= 0 && owner_matches(owner)),
    }
}

#[cfg(unix)]
fn owner_matches(owner: i128) -> bool {
    owner == 0 || owner == i128::from(nix::unistd::geteuid().as_raw())
}

#[cfg(not(unix))]
fn owner_matches(_owner: i128) -> bool {
    true
}

fn bounded_text(value: &Value, maximum: usize) -> Option<&str> {
    value.as_str().filter(|text| {
        let length = text.chars().count();
        0 < length && length <= maximum && !text.contains('\0')
    })
}

fn mode(value: Option<&Value>) -> Option<u32> {
    value
        .and_then(Value::as_u64)
        .filter(|mode| *mode <= 0o777)
        .and_then(|mode| u32::try_from(mode).ok())
}

/// `_validate_digest_dependency`.
fn digest_dependency(change: &Map<String, Value>) -> Result<(), Refusal> {
    if !change.contains_key("expected_digest") {
        if change.contains_key("artifact_identity") || change.contains_key("invocation_identity") {
            return refuse("artifact_dependency_invalid");
        }
        return Ok(());
    }
    if !lower_hex_64(change.get("expected_digest"))
        || !change.get("before").is_some_and(Value::is_null)
        || !change.get("after").is_some_and(Value::is_null)
        || change.get("before_mode") != change.get("after_mode")
        || change.get("kind").and_then(Value::as_str) != Some("binding")
        || change.get("no_follow") != Some(&Value::Bool(true))
    {
        return refuse("authority_dependency_invalid");
    }
    if let Some(identity) = change.get("artifact_identity") {
        let identity = object(identity, "artifact_dependency_invalid")?;
        let shaped = keys_are(identity, &["size", "owner_uid"])
            || keys_are(identity, &["size", "owner_uid", "role"]);
        let role_ok = identity
            .get("role")
            .is_none_or(|role| bounded_text_any(role, 128));
        let size_ok = identity
            .get("size")
            .and_then(integer)
            .is_some_and(|size| (0..(1_i128 << 63)).contains(&size));
        let owner_ok = identity.get("owner_uid").is_some_and(trusted_owner);
        if !shaped || !role_ok || !size_ok || !owner_ok {
            return refuse("artifact_dependency_invalid");
        }
    }
    if let Some(invocation) = change.get("invocation_identity") {
        let reason = "invocation_dependency_invalid";
        let invocation = object(invocation, reason)?;
        if !change.contains_key("artifact_identity")
            || !keys_are(invocation, &["path", "mode", "owner_uid", "link_target"])
        {
            return refuse(reason);
        }
        let path_ok = bounded_text(&invocation["path"], 4096).is_some_and(absolute);
        let link_ok = match &invocation["link_target"] {
            Value::Null => true,
            link => bounded_text(link, 4096).is_some(),
        };
        if !path_ok
            || mode(invocation.get("mode")).is_none()
            || !trusted_owner(&invocation["owner_uid"])
            || !link_ok
        {
            return refuse(reason);
        }
    }
    Ok(())
}

/// A role is any non-empty text of at most `maximum` characters.
fn bounded_text_any(value: &Value, maximum: usize) -> bool {
    value.as_str().is_some_and(|text| {
        let length = text.chars().count();
        0 < length && length <= maximum
    })
}

fn absolute(path: &str) -> bool {
    Path::new(path).is_absolute()
}

/// `recorded_noop`: an unchanged, unpinned file is never published.
fn recorded_noop(change: &Map<String, Value>) -> bool {
    change.get("expected_digest").is_none_or(Value::is_null)
        && change.get("artifact_identity").is_none_or(Value::is_null)
        && change.get("before") == change.get("after")
        && change.get("before_mode") == change.get("after_mode")
}

/// `_unsafe_file_mode`: world write, or group write outside a packaged role.
fn unsafe_mode(mode: u32, artifact_identity: Option<&Value>) -> bool {
    let artifact_role = artifact_identity
        .and_then(Value::as_object)
        .is_some_and(|identity| identity.get("role").is_some_and(Value::is_string));
    cfg!(unix) && (mode & 0o002 != 0 || (mode & 0o020 != 0 && !artifact_role))
}

/// `_record_files`: at most 128 changes, each to its own absolute path.
pub(crate) fn record_files(
    payload: &Map<String, Value>,
) -> Result<Vec<&Map<String, Value>>, Refusal> {
    let changes = record_objects(payload, "files", 128)?;
    let mut paths = HashSet::new();
    for change in &changes {
        let known = change.keys().all(|key| {
            FILE_FIELDS.contains(&key.as_str()) || FILE_OPTIONAL.contains(&key.as_str())
        });
        let path = change.get("path").and_then(Value::as_str);
        let kind = change.get("kind").and_then(Value::as_str);
        if !FILE_FIELDS.iter().all(|key| change.contains_key(*key))
            || !known
            || !path.is_some_and(absolute)
            || !matches!(kind, Some("binding" | "selection"))
            || !change.get("no_follow").is_none_or(Value::is_boolean)
        {
            return refuse("files_invalid");
        }
        digest_dependency(change)?;
        for generation in ["before", "after"] {
            let Some(recorded) = mode(change.get(&format!("{generation}_mode"))) else {
                return Err(("file_mode_invalid".to_owned(), path.map(str::to_owned)));
            };
            if generation == "after"
                && unsafe_mode(recorded, change.get("artifact_identity"))
                && !recorded_noop(change)
            {
                return Err(("file_mode_invalid".to_owned(), path.map(str::to_owned)));
            }
            if !matches!(change.get(generation), Some(Value::Null | Value::String(_))) {
                return refuse("files_invalid");
            }
        }
        if !paths.insert(path.unwrap_or_default()) {
            return refuse("plan_invalid");
        }
    }
    Ok(changes)
}

/// `_artifact_identity`: the seven text fields of a runtime artifact.
pub(crate) fn artifact_identity(value: Option<&Value>) -> Result<&Map<String, Value>, Refusal> {
    let artifact = object(value.unwrap_or(&Value::Null), "artifact_identity_invalid")?;
    if !keys_are(artifact, &ARTIFACT_FIELDS)
        || !artifact.values().all(|item| bounded_text_any(item, 4096))
    {
        return refuse("artifact_identity_invalid");
    }
    if !artifact["path"].as_str().is_some_and(absolute) {
        return refuse("artifact_path_invalid");
    }
    Ok(artifact)
}

/// `_native_runtime_bindings`: both sides or neither, each pinned by a
/// dependency on the same file, digest and size.
pub(crate) fn native_runtime_bindings(payload: &Map<String, Value>) -> Result<(), Refusal> {
    let reason = "native_runtime_bindings_invalid";
    let empty = Value::Object(Map::new());
    let bindings = object(payload.get("native_runtimes").unwrap_or(&empty), reason)?;
    if !bindings.is_empty() && !keys_are(bindings, &["candidate", "predecessor"]) {
        return refuse(reason);
    }
    for value in bindings.values() {
        let identity = object(value, reason)?;
        let positive = |key: &str| identity.get(key).and_then(integer).filter(|n| *n > 0);
        if !keys_are(identity, &["path", "size", "mtime_ns", "sha256"])
            || !identity["path"].as_str().is_some_and(absolute)
            || positive("size").is_none()
            || positive("mtime_ns").is_none()
            || !lower_hex_64(identity.get("sha256"))
        {
            return refuse(reason);
        }
        let pinned = record_files(payload)?.iter().any(|change| {
            change.get("path") == identity.get("path")
                && change.get("expected_digest") == identity.get("sha256")
                && change
                    .get("artifact_identity")
                    .and_then(Value::as_object)
                    .is_some_and(|artifact| {
                        artifact.get("size").and_then(integer) == positive("size")
                    })
        });
        if !pinned {
            return refuse("native_runtime_dependency_missing");
        }
    }
    Ok(())
}

/// `_record_installs`: at most 64 managed install rows, one per harness.
pub(crate) fn record_installs(
    payload: &Map<String, Value>,
    encode: impl Fn(&Value) -> Option<String>,
) -> Result<(), Refusal> {
    let reason = "managed_install_snapshot_invalid";
    let mut harnesses = HashSet::new();
    for row in record_objects(payload, "managed_installs", 64)? {
        let Some(harness) = row.get("harness").and_then(Value::as_str) else {
            return refuse(reason);
        };
        if !keys_are(row, &["harness", "before", "after"]) {
            return refuse(reason);
        }
        for key in ["before", "after"] {
            if !row[key].is_null() {
                object(&row[key], reason)?;
            }
        }
        if harness.is_empty() || harness.chars().count() > 80 {
            return refuse("managed_install_target_invalid");
        }
        for snapshot in [&row["before"], &row["after"]] {
            let Some(snapshot) = snapshot.as_object() else {
                continue;
            };
            let shaped = keys_are(
                snapshot,
                &["harness", "active", "workspace", "manifest", "updated_at"],
            ) && snapshot["harness"].as_str() == Some(harness)
                && snapshot["active"].is_boolean()
                && snapshot["manifest"].is_object()
                && snapshot["updated_at"].is_string()
                && matches!(snapshot["workspace"], Value::Null | Value::String(_));
            if !shaped {
                return refuse(reason);
            }
        }
        let encoded =
            encode(&Value::Object(row.clone())).ok_or_else(|| (reason.to_owned(), None))?;
        if encoded.len() > 1024 * 1024 {
            return refuse("managed_install_snapshot_too_large");
        }
        if !harnesses.insert(harness) {
            return refuse("managed_install_plan_invalid");
        }
    }
    Ok(())
}

/// Everything `_read_record` checks after the record authenticates.
pub(crate) fn validate_record(
    payload: &Map<String, Value>,
    encode: impl Fn(&Value) -> Option<String>,
) -> Result<(), Refusal> {
    if record_files(payload)?.is_empty() {
        return refuse("plan_invalid");
    }
    record_installs(payload, encode)?;
    native_runtime_bindings(payload)?;
    record_objects(payload, "recovery_causes", 8)?;
    for name in ["candidate", "predecessor"] {
        artifact_identity(payload.get(name))?;
    }
    for name in [
        "deadline_epoch",
        "deadline_monotonic",
        "forward_expires_epoch",
        "forward_expires_monotonic",
    ] {
        record_number(payload, name)?;
    }
    Ok(())
}
