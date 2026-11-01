//! Fetches from the installed release bundle.
//!
//! The bundle ships its delivery data under one fixed directory, one
//! subdirectory per release tag, named for the tag's batch. A location names the asset to read; this
//! resolves it against the bundle's source and reads a member out of its
//! container in one step. A bulk traversal can share a process while retaining
//! those same checks for each object.
use super::{container, location, request, Outcome};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const OBJECT_BYTES: u64 = 65536;
const PACK_BYTES: u64 = 32 * 1024 * 1024;
const BATCH_ITEMS: usize = 64;
const BATCH_BYTES: u64 = BATCH_ITEMS as u64 * OBJECT_BYTES;

/// Read a bounded batch of small installed objects with the same checks as a
/// single fetch. Validate the whole request before opening any container.
pub(super) fn batch(input: &Value) -> Outcome {
    let items = input["items"]
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= BATCH_ITEMS)
        .ok_or("installed bundle batch bounds invalid")?;
    let mut total = 0u64;
    let mut plans = Vec::with_capacity(items.len());
    for item in items {
        let plan = location::asset(&json!({
            "profile": "installed", "target": item["target"], "source": input["source"],
        }))?;
        let length = item["length"]
            .as_u64()
            .filter(|length| (1..=OBJECT_BYTES).contains(length))
            .ok_or("installed bundle batch bounds invalid")?;
        if plan["kind"] != "object" {
            return Err("installed bundle batch requires objects".into());
        }
        total = total
            .checked_add(length)
            .filter(|total| *total <= BATCH_BYTES)
            .ok_or("installed bundle batch bounds invalid")?;
        plans.push((plan, length));
    }
    let mut groups = BTreeMap::<(PathBuf, String), Vec<(usize, String, u64)>>::new();
    let mut replies = vec![Value::Null; items.len()];
    let mut directories = vec![Value::Null; items.len()];
    for (index, (plan, length)) in plans.into_iter().enumerate() {
        if plan["bound"].is_null() {
            replies[index] = plan;
            continue;
        }
        directories[index] = plan["directory"].clone();
        let path = path(&input["root"], &plan)?;
        groups
            .entry((path, plan["asset"].as_str().unwrap_or_default().to_owned()))
            .or_default()
            .push((
                index,
                plan["name"].as_str().unwrap_or_default().to_owned(),
                length,
            ));
    }
    for ((path, asset), members) in groups {
        check_tag(&path)?;
        let verified = container::members(
            &path,
            &asset,
            members
                .iter()
                .map(|(_, name, length)| (name.as_str(), *length)),
        )?;
        for ((index, _, _), mut reply) in members.into_iter().zip(verified) {
            // Each item answers as a single fetch of it would.
            reply["directory"] = directories[index].take();
            replies[index] = reply;
        }
    }
    let mut reply = json!({});
    reply["items"] = Value::Array(replies);
    Ok(reply)
}

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
    let path = path(&input["root"], &plan)?;
    check_tag(&path)?;
    let mut reply = container::member(&json!({
        "path": path.to_string_lossy(),
        "asset": plan["asset"],
        "name": plan["name"],
        "length": length,
    }))?;
    // The caller keys its answer cache on the file this read, so it learns
    // the directory from here rather than mapping the tag a second time.
    reply["directory"] = plan["directory"].clone();
    Ok(reply)
}

fn path(root: &Value, plan: &Value) -> Result<PathBuf, String> {
    let root = root.as_str().ok_or_else(request)?;
    let text = |key: &str| plan[key].as_str().unwrap_or_default();
    let directory = Path::new(root).join(text("directory"));
    Ok(directory.join(text("asset")))
}

fn check_tag(path: &Path) -> Result<(), String> {
    let directory = path.parent().ok_or_else(request)?;
    if fs::symlink_metadata(directory).is_ok_and(|found| found.file_type().is_symlink()) {
        return Err("delivery container unreadable".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "installed_tests.rs"]
mod tests;
