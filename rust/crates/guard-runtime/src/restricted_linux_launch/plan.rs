//! Fixed, private namespace plan validation before any repository execution.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(super) type Result<T> = std::result::Result<T, &'static str>;
pub(super) const DIRECTORY: &str = "/guard-linux-plan";
pub(super) const FILENAME: &str = "linux-plan.json";
pub(super) const MAX_BYTES: u64 = 64 * 1024 * 1024;
const FIELDS: &[&str] = &[
    "schema",
    "command",
    "read_roots",
    "read_files",
    "list_roots",
    "write_roots",
    "executables",
    "read_identities",
    "write_identities",
    "device_files",
    "mapping_records",
];

pub(super) struct Plan {
    pub command: Vec<String>,
    pub read_roots: Vec<PathBuf>,
    pub read_files: Vec<PathBuf>,
    pub list_roots: Vec<PathBuf>,
    pub write_roots: Vec<PathBuf>,
    pub executables: Vec<PathBuf>,
    pub device_files: Vec<PathBuf>,
    pub read_identities: BTreeMap<PathBuf, (u64, u64)>,
    pub write_identities: BTreeMap<PathBuf, (u64, u64)>,
    pub mapping_records: Value,
}

fn paths(value: &Value) -> Result<Vec<PathBuf>> {
    let values = value.as_array().ok_or("Invalid Linux path vector.")?;
    values
        .iter()
        .map(|v| {
            let text = v.as_str().ok_or("Invalid Linux path vector.")?;
            if text.contains('\0') || !Path::new(text).is_absolute() {
                return Err("Invalid Linux path vector.");
            }
            Ok(PathBuf::from(text))
        })
        .collect()
}

fn identities(value: &Value, paths: &[PathBuf]) -> Result<BTreeMap<PathBuf, (u64, u64)>> {
    let records = value
        .as_array()
        .filter(|v| v.len() == paths.len())
        .ok_or("Incomplete Linux inode evidence.")?;
    let mut result = BTreeMap::new();
    for record in records {
        let values = record
            .as_array()
            .filter(|v| v.len() == 3)
            .ok_or("Invalid Linux inode evidence.")?;
        let path = PathBuf::from(values[0].as_str().ok_or("Invalid Linux inode evidence.")?);
        let first = values[1].as_u64().ok_or("Invalid Linux inode evidence.")?;
        let second = values[2].as_u64().ok_or("Invalid Linux inode evidence.")?;
        if result.insert(path, (first, second)).is_some() {
            return Err("Ambiguous Linux inode evidence.");
        }
    }
    if result.keys().collect::<BTreeSet<_>>() != paths.iter().collect::<BTreeSet<_>>() {
        return Err("Mismatched Linux inode evidence.");
    }
    Ok(result)
}

pub(super) fn locator(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err("Invalid private Linux plan locator.");
    }
    Ok(())
}

pub(super) fn parse(value: Value) -> Result<Plan> {
    let object = value
        .as_object()
        .ok_or("Unsupported Linux execution plan.")?;
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != FIELDS.iter().copied().collect()
        || value["schema"].as_str() != Some("guard-linux-readonly-plan.v2")
    {
        return Err("Unsupported Linux execution plan.");
    }
    let command: Vec<String> = serde_json::from_value(value["command"].clone())
        .map_err(|_| "Invalid Linux command vector.")?;
    if command.is_empty()
        || command.len() > 4096
        || command.iter().any(|v| v.contains('\0'))
        || command.iter().map(String::len).sum::<usize>() > 1_048_576
    {
        return Err("Invalid Linux command vector.");
    }
    let read_roots = paths(&value["read_roots"])?;
    let read_files = paths(&value["read_files"])?;
    let list_roots = paths(&value["list_roots"])?;
    let write_roots = paths(&value["write_roots"])?;
    let executables = paths(&value["executables"])?;
    let device_files = paths(&value["device_files"])?;
    if read_roots.len()
        + read_files.len()
        + list_roots.len()
        + write_roots.len()
        + executables.len()
        + device_files.len()
        > 250_000
        || !Path::new(&command[0]).is_absolute()
    {
        return Err("Linux plan exceeds its boundary.");
    }
    let read_identities = identities(&value["read_identities"], &read_files)?;
    let write_identities = identities(&value["write_identities"], &write_roots)?;
    let image = Path::new(&command[0])
        .canonicalize()
        .map_err(|_| "The command does not resolve to an approved image.")?;
    if !executables.contains(&image) {
        return Err("The command does not resolve to an approved image.");
    }
    Ok(Plan {
        command,
        read_roots,
        read_files,
        list_roots,
        write_roots,
        executables,
        device_files,
        read_identities,
        write_identities,
        mapping_records: value["mapping_records"].clone(),
    })
}
