//! Fetches from the installed release bundle.
//!
//! The bundle ships its delivery data under one fixed directory, one
//! subdirectory per release tag. A location names the asset to read; this
//! resolves it against the bundle's source and reads a member out of its
//! container in one step, so a bulk traversal asks once per object.
use super::{container, location, request, Outcome};
use serde_json::{json, Value};
use std::{fs, path::Path};

const OBJECT_BYTES: u64 = 65536;
const PACK_BYTES: u64 = 32 * 1024 * 1024;

/// Validate a location of the installed bundle and, for a container member,
/// return its verified bytes. A whole asset is only resolved: the caller holds
/// the file handle and whoever consumes the bytes checks their digest.
///
/// `root` is the bundle's asset directory, chosen by the installation and
/// already checked by the caller up to that directory. This refuses a tag
/// directory that is a symlink; the container itself is read without
/// following one.
pub(super) fn fetch(input: &Value) -> Outcome {
    let plan = location::asset(&json!({
        "profile": "installed",
        "target": input["target"],
        "source": input["source"],
    }))?;
    let limit = if plan["kind"] == "object" {
        OBJECT_BYTES
    } else {
        PACK_BYTES
    };
    let length = input["length"]
        .as_u64()
        .filter(|length| (1..=limit).contains(length))
        .ok_or("installed bundle fetch bounds invalid")?;
    if plan["bound"].is_null() {
        return Ok(plan);
    }
    let root = input["root"].as_str().ok_or_else(request)?;
    let text = |key: &str| plan[key].as_str().unwrap_or_default();
    let directory = Path::new(root).join(text("tag"));
    if fs::symlink_metadata(&directory).is_ok_and(|found| found.file_type().is_symlink()) {
        return Err("delivery container unreadable".into());
    }
    let path = directory.join(text("asset"));
    container::member(&json!({
        "path": path.to_string_lossy(),
        "asset": text("asset"),
        "name": text("name"),
        "length": length,
    }))
}

#[cfg(test)]
#[path = "installed_tests.rs"]
mod tests;
