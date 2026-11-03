//! `runner_authority` kind `isolation_provider`: the trusted checks behind
//! the Guard-owned isolation provider registry (`isolation_provider.py`
//! `validate_provider_plan_inputs`, `_path_has_symlink_below_root`, `_sha256_regular_file` and
//! `_read_managed_provider_config` before they moved here).
//!
//! Python keeps the provider objects and path spelling: it resolves each path
//! with the host's own `Path` rules and sends the parts, so the decisions here
//! never re-implement Windows path semantics.

use std::io::Read;
use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::local_skill_index::open_no_follow;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const REGISTRY_SCHEMA: &str = "guard.provider-registry.v1";
/// Path-name tokens that must never appear as a mounted input or declared output.
const FORBIDDEN_PATH_NAMES: [&str; 7] = [".env", ".ssh", ".git", ".gnupg", ".hg", ".svn", ".bzr"];
/// Exact host socket paths that must never be mounted.
const FORBIDDEN_SOCKET_PATHS: [&str; 6] = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/crio/crio.sock",
];
/// Guard state directory names that must never be mounted.
const GUARD_STATE_NAMES: [&str; 2] = [".hol-guard", "guard-state"];
const ANCHOR_FIELDS: [&str; 5] = [
    "providerKind",
    "implementationVersion",
    "binaryOrImageDigest",
    "signingIdentity",
    "trustDomain",
];
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    match map.get("op").and_then(Value::as_str) {
        Some("plan_inputs") if map.len() == 2 => plan_inputs(map),
        Some("locate") if map.len() == 5 => locate(map),
        Some("digest") if map.len() == 2 => Ok(digest(Path::new(text(map, "path")?))),
        Some("registry") if map.len() == 2 => Ok(registry(Path::new(text(map, "config")?))),
        _ => Err(ERR_INVALID),
    }
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    map.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn strings<'a>(map: &'a Map<String, Value>, key: &str) -> Result<Vec<&'a str>, &'static str> {
    map.get(key)
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|part| part.as_str().ok_or(ERR_INVALID))
        .collect()
}

/// `validate_provider_plan_inputs`: the first input or declared output that
/// touches `.env`, `.ssh`, VCS metadata, a host control socket or Guard
/// state, by its index and the rule it broke.
fn plan_inputs(map: &Map<String, Value>) -> KindResult {
    let paths = map
        .get("paths")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    for (index, path) in paths.iter().enumerate() {
        let path = path
            .as_object()
            .filter(|path| path.len() == 4)
            .ok_or(ERR_INVALID)?;
        let raw = text(path, "raw")?;
        let resolved = text(path, "resolved")?;
        let name = text(path, "name")?.to_lowercase();
        let parts: Vec<String> = strings(path, "parts")?
            .into_iter()
            .map(str::to_lowercase)
            .collect();
        let named = |names: &[&str]| parts.iter().any(|part| names.contains(&part.as_str()));
        let refusal =
            if FORBIDDEN_PATH_NAMES.contains(&name.as_str()) || named(&FORBIDDEN_PATH_NAMES) {
                Some("forbidden_path")
            } else if FORBIDDEN_SOCKET_PATHS.contains(&raw)
                || FORBIDDEN_SOCKET_PATHS.contains(&resolved)
            {
                Some("control_socket")
            } else if named(&GUARD_STATE_NAMES) {
                Some("guard_state")
            } else {
                None
            };
        if let Some(refusal) = refusal {
            return Ok(json!({ "refusal": refusal, "index": index }));
        }
    }
    Ok(json!({ "refusal": null }))
}

/// A configured provider path must resolve inside the provider root, and no
/// component between the root and the artifact may be a symlink. Python sends
/// both part lists case-normalised for the host.
fn locate(map: &Map<String, Value>) -> KindResult {
    let root_parts = strings(map, "root_parts")?;
    let path_parts = strings(map, "path_parts")?;
    let root = Path::new(text(map, "root")?);
    let lexical = Path::new(text(map, "lexical")?);
    if !path_parts.starts_with(&root_parts) {
        return Ok(json!({ "refusal": "outside" }));
    }
    if has_symlink_below_root(lexical, root) {
        return Ok(json!({ "refusal": "symlink" }));
    }
    Ok(json!({ "refusal": null }))
}

/// `_path_has_symlink_below_root`: every lexical ancestor up to the root is a
/// real directory; an unreadable one counts as a link.
fn has_symlink_below_root(lexical: &Path, root: &Path) -> bool {
    let mut current = lexical;
    while current != root {
        match std::fs::symlink_metadata(current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return true,
            Ok(_) => {}
            // `Path.is_symlink` reads a missing component as no link.
            Err(error) if is_absent(&error) => {}
            Err(_) => return true,
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }
    false
}

/// `_sha256_regular_file`: the artifact's digest, read without following a
/// final symlink.
fn digest(path: &Path) -> Value {
    let Ok(mut artifact) = open_no_follow(path) else {
        return json!({ "refusal": "unreadable" });
    };
    match artifact.metadata() {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return json!({ "refusal": "not_regular" }),
        Err(_) => return json!({ "refusal": "unreadable" }),
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        match artifact.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => digest.update(&buffer[..read]),
            Err(_) => return json!({ "refusal": "unreadable" }),
        }
    }
    json!({ "digest": hex::encode(digest.finalize()) })
}

/// `load_managed_provider_registry` and `_read_managed_provider_config`: the
/// declarations in the admin-owned registry, each an OCI isolation provider
/// with a complete trust anchor. A missing registry declares none.
fn registry(config: &Path) -> Value {
    if std::fs::metadata(config).is_err_and(|error| is_absent(&error)) {
        return json!({ "declarations": [] });
    }
    let refuse = |message: &str| json!({ "refusal": message });
    let Ok(file) = open_no_follow(config) else {
        return refuse("managed provider registry is unreadable");
    };
    let Ok(metadata) = file.metadata() else {
        return refuse("managed provider registry is invalid");
    };
    if !metadata.is_file() || writable_by_others(&metadata) {
        return refuse("managed provider registry is not admin-owned");
    }
    let mut bytes = Vec::new();
    if file
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_CONFIG_BYTES
    {
        return refuse("managed provider registry is invalid");
    }
    let Ok(Value::Object(payload)) = serde_json::from_slice::<Value>(&bytes) else {
        return refuse("managed provider registry is invalid");
    };
    if payload.get("schema").and_then(Value::as_str) != Some(REGISTRY_SCHEMA) {
        return refuse("managed provider registry schema is invalid");
    }
    let Some(providers) = payload.get("providers").and_then(Value::as_array) else {
        return refuse("managed provider registry providers are invalid");
    };
    let mut declarations = Vec::new();
    for declaration in providers {
        match declared(declaration) {
            Ok(declaration) => declarations.push(declaration),
            Err(message) => return refuse(message),
        }
    }
    json!({ "declarations": declarations })
}

fn declared(declaration: &Value) -> Result<Value, &'static str> {
    const INVALID: &str = "managed provider declaration is invalid";
    let declaration = declaration.as_object().ok_or(INVALID)?;
    let path = declaration.get("path").and_then(Value::as_str);
    let anchor = declaration.get("trustAnchor").and_then(Value::as_object);
    let (Some("oci-isolation"), Some(path), Some(anchor)) = (
        declaration.get("kind").and_then(Value::as_str),
        path,
        anchor,
    ) else {
        return Err(INVALID);
    };
    let mut fields = Map::new();
    for field in ANCHOR_FIELDS {
        match anchor.get(field).and_then(Value::as_str) {
            Some(value) if !value.is_empty() => {
                fields.insert(field.to_owned(), Value::from(value));
            }
            _ => return Err("managed provider trust anchor is invalid"),
        }
    }
    Ok(json!({ "path": path, "trustAnchor": fields }))
}

fn is_absent(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// A group- or world-writable registry is not admin-owned.
#[cfg(unix)]
fn writable_by_others(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o022 != 0
}

#[cfg(not(unix))]
fn writable_by_others(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
#[path = "isolation_provider_registry_tests.rs"]
mod tests;
