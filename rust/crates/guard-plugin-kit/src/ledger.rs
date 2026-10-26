//! The record of what `hol-guard plugin install --apply` installed.
//!
//! `uninstall` plans from this record instead of asking HOL again, so it only
//! removes what Guard added and still works after a listing leaves HOL. Each
//! entry keeps the install targets Guard ran, and they are checked again with
//! the same rules as a fresh spec before anything is planned from them.
//!
//! Writers hold an exclusive lock on `installs.lock` and replace the record
//! with a rename, so two installs at once never lose an entry. A record that
//! does not parse, or is not a regular file, is an error and is never
//! overwritten.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::install;

pub const SCHEMA: &str = "hol.plugin-kit.installs.v1";
const DIR: &str = "plugin-kit";
const FILE: &str = "installs.json";
const LOCK: &str = "installs.lock";

pub const INVALID: &str = "plugin_kit_ledger_invalid";
pub const NOT_RECORDED: &str = "plugin_kit_install_not_recorded";
const UNWRITABLE: &str = "plugin_kit_ledger_unwritable";

fn directory(guard_home: &str) -> Result<PathBuf, String> {
    let home = Path::new(guard_home);
    if !home.is_absolute() {
        return Err("plugin_kit_guard_home_invalid".to_owned());
    }
    Ok(home.join(DIR))
}

fn read(directory: &Path) -> Result<Map<String, Value>, String> {
    let path = directory.join(FILE);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Map::new()),
        Ok(meta) if meta.is_file() => {}
        _ => return Err(INVALID.to_owned()),
    }
    let bytes = fs::read(&path).map_err(|_| INVALID.to_owned())?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| INVALID.to_owned())?;
    if value.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
        return Err(INVALID.to_owned());
    }
    match value.get("installs") {
        Some(Value::Object(installs)) => Ok(installs.clone()),
        _ => Err(INVALID.to_owned()),
    }
}

fn write(directory: &Path, installs: Map<String, Value>) -> Result<(), String> {
    let mut body = serde_json::to_vec_pretty(&json!({"schema": SCHEMA, "installs": installs}))
        .map_err(|_| "plugin_kit_encode_failed".to_owned())?;
    body.push(b'\n');
    let temporary = directory.join(format!(".{FILE}.{}.tmp", std::process::id()));
    // Only a crashed earlier run with this pid can leave it; we hold the lock.
    let _ = fs::remove_file(&temporary);
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(&body)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&temporary, directory.join(FILE)));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written.map_err(|_| UNWRITABLE.to_owned())
}

fn locked<T>(directory: &Path, work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    fs::create_dir_all(directory).map_err(|_| UNWRITABLE.to_owned())?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(directory.join(LOCK))
        .map_err(|_| UNWRITABLE.to_owned())?;
    fs2::FileExt::lock_exclusive(&lock).map_err(|_| UNWRITABLE.to_owned())?;
    let result = work();
    let _ = fs2::FileExt::unlock(&lock);
    result
}

fn runtimes(entry: &Value) -> Vec<String> {
    let mut runtimes: Vec<String> = entry["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|target| target["runtime"].as_str().map(str::to_owned))
        .collect();
    runtimes.sort();
    runtimes
}

/// Add (`installed`) or drop one runtime of a listing. Adding needs the spec
/// the install ran from; dropping needs only the slug.
pub fn record(
    guard_home: &str,
    slug: &str,
    runtime: &str,
    installed: bool,
    spec: Option<Value>,
) -> Result<Value, String> {
    let added = match (installed, spec) {
        (true, Some(spec)) => {
            install::validate(&spec)?;
            if spec["slug"].as_str() != Some(slug) {
                return Err("plugin_kit_install_spec_mismatch".to_owned());
            }
            let target = spec["targets"]
                .as_array()
                .and_then(|targets| targets.iter().find(|t| t["runtime"] == runtime))
                .cloned()
                .ok_or_else(|| "plugin_kit_install_runtime_not_offered".to_owned())?;
            Some((spec, target))
        }
        (true, None) => return Err("plugin_kit_request_invalid".to_owned()),
        (false, _) => None,
    };
    let directory = directory(guard_home)?;
    locked(&directory, || {
        let mut installs = read(&directory)?;
        let mut targets: Vec<Value> = installs
            .get(slug)
            .and_then(|entry| entry["targets"].as_array())
            .cloned()
            .unwrap_or_default();
        targets.retain(|target| target["runtime"] != runtime);
        let entry = match added {
            Some((spec, target)) => {
                targets.push(target);
                Some(json!({
                    "name": spec["name"],
                    "version": spec["version"],
                    "listingUrl": spec["listingUrl"],
                    "targets": targets,
                }))
            }
            None if targets.is_empty() => None,
            None => installs.get(slug).cloned().map(|mut entry| {
                entry["targets"] = Value::Array(targets);
                entry
            }),
        };
        let recorded = entry.as_ref().map(runtimes).unwrap_or_default();
        match entry {
            Some(entry) => installs.insert(slug.to_owned(), entry),
            None => installs.remove(slug),
        };
        write(&directory, installs)?;
        Ok(json!({"slug": slug, "runtimes": recorded}))
    })
}

/// Every listing Guard installed, as `{slug: [runtime, ...]}`.
pub fn installs(guard_home: &str) -> Result<Value, String> {
    let installs = read(&directory(guard_home)?)?;
    Ok(Value::Object(
        installs
            .iter()
            .map(|(slug, entry)| (slug.clone(), json!(runtimes(entry))))
            .collect(),
    ))
}

/// The install spec Guard recorded for a listing, rebuilt for `uninstall`.
pub fn spec(guard_home: &str, slug: &str) -> Result<Value, String> {
    let installs = read(&directory(guard_home)?)?;
    let entry = installs.get(slug).ok_or_else(|| NOT_RECORDED.to_owned())?;
    Ok(json!({
        "schema": install::SPEC_SCHEMA,
        "slug": slug,
        "name": entry["name"],
        "version": entry["version"],
        "listingUrl": entry["listingUrl"],
        "targets": entry["targets"],
    }))
}
