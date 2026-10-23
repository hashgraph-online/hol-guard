//! Data-only Python parity for private-cell task idmaps and mount inventory.
//! The caller still needs trustworthy kernel collection of these observations.

use crate::crypto::is_sha256;
use crate::{EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const TASK_COUNT: &str = "exact frozen task/provider mount inventory required";
const TASK: &str = "task/provider source, inode or unchanged mode differs from frozen custody";
const OBSERVATION: &str = "exactly one private-cell idmapped-task-mounts observation required";
const DECLARATION: &str = "task declaration/outside observation binding differs";
const DUPLICATE: &str = "duplicate outside task mapping";
const IDMAP: &str = "outside kernel idmapping lacks unchanged physical task custody";
const MOUNT_BUDGET: &str = "bounded kernel mount inventory required";
const MOUNT_SYNTAX: &str = "malformed kernel mount inventory";
const MOUNT_UNEXPECTED: &str = "unexpected kernel/control filesystem mount";
const MOUNT_IMMUTABLE: &str = "immutable private-cell mount became writable/unsafe";
const MOUNT_DEVICE: &str = "device directory is not readonly";
const MOUNT_MUTABLE: &str = "mutable private-cell mount lost its declared floor";

fn exact_keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == names.len() && names.iter().all(|name| object.contains_key(*name))
    })
}

fn number(row: &Value, field: &str, reason: &'static str) -> Result<u64> {
    row.get(field)
        .and_then(Value::as_u64)
        .ok_or(EvidenceError::Invalid(reason))
}

fn string<'a>(row: &'a Value, field: &str, reason: &'static str) -> Result<&'a str> {
    row.get(field)
        .and_then(Value::as_str)
        .ok_or(EvidenceError::Invalid(reason))
}

fn task_idmaps(
    plane: &Value,
    rows: &Value,
    workspace_source: &str,
    provider_mounts: &[String],
    pid: u64,
) -> Result<(usize, Vec<String>)> {
    let workspace_path = string(plane, "workspace_path", TASK_COUNT)?;
    let mut expected = BTreeMap::from([(workspace_path.to_owned(), workspace_source.to_owned())]);
    for path in provider_mounts {
        expected.insert(path.clone(), path.clone());
    }
    let tasks = plane
        .get("task_mounts")
        .and_then(Value::as_array)
        .filter(|tasks| tasks.len() == expected.len() && expected.len() <= 9)
        .ok_or(EvidenceError::Invalid(TASK_COUNT))?;
    let mut seen = BTreeSet::new();
    let mut destinations = Vec::new();
    for row in tasks {
        let destination = string(row, "destination", TASK)?;
        let source = string(row, "source", TASK)?;
        number(row, "device", TASK)?;
        let inode = number(row, "inode", TASK)?;
        let mode = number(row, "mode", TASK)?;
        if !exact_keys(row, &["source", "destination", "device", "inode", "mode"])
            || !seen.insert(destination.to_owned())
            || expected.get(destination).map(String::as_str) != Some(source)
            || inode == 0
            || mode & 0o700 != 0o700
            || mode & !0o755 != 0
        {
            return Err(EvidenceError::Invalid(TASK));
        }
        destinations.push(destination.to_owned());
    }
    let observations = rows.as_array().ok_or(EvidenceError::Invalid(OBSERVATION))?;
    let matching: Vec<&Value> = observations
        .iter()
        .filter(|row| row.get("kind") == Some(&json!("idmapped-task-mounts")))
        .collect();
    if matching.len() != 1 {
        return Err(EvidenceError::Invalid(OBSERVATION));
    }
    let observation = matching[0];
    let mounts = observation
        .get("mounts")
        .and_then(Value::as_array)
        .ok_or(EvidenceError::Invalid(DECLARATION))?;
    if !plane["task_digest"].as_str().is_some_and(is_sha256)
        || observation["declaration_digest"] != plane["task_digest"]
        || mounts.len() != tasks.len()
    {
        return Err(EvidenceError::Invalid(DECLARATION));
    }
    let mut measured = BTreeMap::new();
    for row in mounts {
        let destination = string(row, "destination", DUPLICATE)?;
        measured.insert(destination.to_owned(), row);
    }
    if measured.len() != tasks.len() {
        return Err(EvidenceError::Invalid(DUPLICATE));
    }
    for row in tasks {
        let destination = string(row, "destination", IDMAP)?;
        let actual = measured
            .get(destination)
            .ok_or(EvidenceError::Invalid(IDMAP))?;
        let physical = json!({
            "device": row["device"], "inode": row["inode"],
            "mode": row["mode"], "uid": 10001, "gid": 10001,
        });
        let product = json!({
            "device": row["device"], "inode": row["inode"],
            "mode": row["mode"], "uid": 10004, "gid": 10004,
        });
        if !exact_keys(
            actual,
            &[
                "source",
                "destination",
                "physical",
                "product_view",
                "observer_pid",
            ],
        ) || actual["source"] != row["source"]
            || actual["observer_pid"] != json!(pid)
            || actual["physical"] != physical
            || actual["product_view"] != product
        {
            return Err(EvidenceError::Invalid(IDMAP));
        }
    }
    Ok((tasks.len(), destinations))
}

fn mount_inventory(raw: &str, prefix: &str, task_destinations: &[String]) -> Result<usize> {
    if raw.len() > 4 * 1024 * 1024 || raw.chars().count() >= 1024 * 1024 {
        return Err(EvidenceError::Invalid(MOUNT_BUDGET));
    }
    let normalized = raw.replace("\r\n", "\n");
    if normalized.chars().any(|value| {
        matches!(
            value,
            '\r' | '\u{000b}'
                | '\u{000c}'
                | '\u{001c}'
                | '\u{001d}'
                | '\u{001e}'
                | '\u{0085}'
                | '\u{2028}'
                | '\u{2029}'
        )
    }) {
        return Err(EvidenceError::Invalid(MOUNT_SYNTAX));
    }
    let mut mounts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in normalized.lines() {
        let (left, right) = line
            .split_once(" - ")
            .ok_or(EvidenceError::Invalid(MOUNT_SYNTAX))?;
        let left: Vec<&str> = left.split_whitespace().collect();
        let right: Vec<&str> = right.split_whitespace().collect();
        if left.len() < 6 || right.len() < 3 {
            return Err(EvidenceError::Invalid(MOUNT_SYNTAX));
        }
        let path = left[4]
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        if mounts.contains_key(&path)
            || path.starts_with("/oldroot")
            || path.starts_with("/sys")
            || matches!(right[0], "sysfs" | "cgroup" | "cgroup2")
        {
            return Err(EvidenceError::Invalid(MOUNT_UNEXPECTED));
        }
        mounts.insert(path, left[5].split(',').map(str::to_owned).collect());
    }
    for path in [
        "/",
        "/usr",
        "/opt/node",
        "/public",
        "/etc/alternatives",
        prefix,
    ] {
        if !["ro", "nosuid", "nodev"].iter().all(|option| {
            mounts
                .get(path)
                .is_some_and(|flags| flags.contains(*option))
        }) {
            return Err(EvidenceError::Invalid(MOUNT_IMMUTABLE));
        }
    }
    if !["ro", "nosuid"].iter().all(|option| {
        mounts
            .get("/dev")
            .is_some_and(|flags| flags.contains(*option))
    }) {
        return Err(EvidenceError::Invalid(MOUNT_DEVICE));
    }
    for path in ["/product", "/tmp"]
        .into_iter()
        .chain(task_destinations.iter().map(String::as_str))
    {
        if !["rw", "nosuid", "nodev"].iter().all(|option| {
            mounts
                .get(path)
                .is_some_and(|flags| flags.contains(*option))
        }) {
            return Err(EvidenceError::Invalid(MOUNT_MUTABLE));
        }
    }
    Ok(mounts.len())
}

/// Match Python `_tasks` followed by `_mountinfo` over supplied observations.
/// An actual Linux collector and source-bound signed plane are still required.
pub fn verify_private_cell_mount_relation(
    plane: &Value,
    rows: &Value,
    workspace_source: &str,
    provider_mounts: &[String],
    pid: u64,
    prefix: &str,
    mountinfo: &str,
) -> Result<Value> {
    let (task_count, destinations) =
        task_idmaps(plane, rows, workspace_source, provider_mounts, pid)?;
    let mount_count = mount_inventory(mountinfo, prefix, &destinations)?;
    Ok(json!({
        "task_mount_count": task_count,
        "kernel_mount_count": mount_count,
        "execution_eligible": false,
    }))
}
