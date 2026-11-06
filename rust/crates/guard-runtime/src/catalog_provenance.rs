//! `catalog_provenance` runner-authority kind: how a catalog migration event
//! names the install that wrote it without naming the user.
//!
//! Two shapes:
//!
//! - `{"resource_path": str, "frozen": bool}` answers
//!   `{"install_kind": str, "resource_root_digest": hex}`. The kind comes from
//!   the path's shape, never its contents, and the directory holding the
//!   resource is reduced to a domain-separated digest, which tells two installs
//!   apart without naming either. `frozen` is the caller's own bundle state.
//! - `{"writer_version": str, "previous_version": str}` answers
//!   `{"downgrade": bool}`: whether the writer is an older release than the
//!   install that produced the catalog it replaces.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_PATH_BYTES: usize = 4_096;
const ROOT_DIGEST_DOMAIN: &[u8] = b"hol-guard.catalog-resource-root.v1\0";

/// Path markers in the order they are tried; the first match names the install.
const INSTALL_MARKERS: &[(&str, &str)] = &[
    ("/pipx/", "pipx"),
    ("/uv/tools/", "uv-tool"),
    ("/site-packages/", "site-packages"),
    ("/src/codex_plugin_scanner/", "source-checkout"),
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    if args.len() != 2 {
        return Err(ERR_INVALID);
    }
    match (
        args.get("resource_path"),
        args.get("frozen"),
        args.get("writer_version"),
        args.get("previous_version"),
    ) {
        (Some(Value::String(path)), Some(Value::Bool(frozen)), None, None) => Ok(json!({
            "install_kind": install_kind(path, *frozen),
            "resource_root_digest": resource_root_digest(path),
        })),
        (None, None, Some(Value::String(writer)), Some(Value::String(previous))) => Ok(json!({
            "downgrade": version_ordinal(writer) < version_ordinal(previous),
        })),
        _ => Err(ERR_INVALID),
    }
}

/// Classify the install from the shape of the path, never its contents.
fn install_kind(resource_path: &str, frozen: bool) -> &'static str {
    let normalized = resource_path.replace('\\', "/");
    if frozen {
        // A frozen bundle is what the Desktop app ships; the marker only
        // refines which bundle produced it.
        return if normalized.contains("org.hol.guard.desktop") {
            "desktop-bundle"
        } else {
            "frozen-bundle"
        };
    }
    INSTALL_MARKERS
        .iter()
        .find(|(marker, _)| normalized.contains(*marker))
        .map_or("unknown", |(_, kind)| *kind)
}

/// A stable, non-identifying id for the directory an install loaded from.
fn resource_root_digest(resource_path: &str) -> String {
    let root = parent_directory(resource_path);
    let bytes = root.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(ROOT_DIGEST_DOMAIN);
    hasher.update(&bytes[..bytes.len().min(MAX_PATH_BYTES)]);
    hex::encode(hasher.finalize())
}

/// The directory holding `path`, spelled as Python's `PurePath(path).parent`:
/// rejoined from components, so a doubled separator or `.` part reads the same.
fn parent_directory(path: &str) -> String {
    let normalized: PathBuf = Path::new(path).components().collect();
    match normalized.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_string_lossy().into_owned(),
        Some(_) => ".".to_owned(),
        None if normalized.as_os_str().is_empty() => ".".to_owned(),
        None => normalized.to_string_lossy().into_owned(),
    }
}

/// The leading numeric components of a version, for ordering only.
///
/// `3.47.0a2` orders as `[3, 47, 0]`. Pre-release suffixes are dropped rather
/// than parsed: this only answers "is the writer older", and an alpha of the
/// same release is not a downgrade worth recording.
fn version_ordinal(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map_while(|component| {
            let digits: String = component.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .collect()
}

#[cfg(test)]
#[path = "catalog_provenance_tests.rs"]
mod tests;
