//! The record of what `hol-guard plugin install --apply` installed.
//!
//! `uninstall` plans from this record instead of asking HOL again, so it only
//! removes what Guard added and still works after a listing leaves HOL. Each
//! entry keeps the install targets Guard ran, and they are checked again with
//! the same rules as a fresh spec before anything is planned from them.
//!
//! Writers hold an exclusive lock on `installs.lock` and replace the record
//! with a rename, so two installs at once never lose an entry. The record is
//! written owner-only (0600 on Unix). A record that does not parse, or is not
//! a regular file, is an error and is never overwritten; `installs` with
//! `recover` moves an unparseable regular file aside so Guard can start a new
//! one.

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

/// Why the record cannot be used. Only a record that is readable but not a
/// record Guard can parse counts as corrupt; an I/O error, something other
/// than a regular file, or a newer Guard's schema is left alone.
enum Unusable {
    Unreadable,
    Corrupt,
}

fn load(directory: &Path) -> Result<Map<String, Value>, Unusable> {
    let path = directory.join(FILE);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Map::new()),
        Ok(meta) if meta.is_file() => {}
        _ => return Err(Unusable::Unreadable),
    }
    let bytes = fs::read(&path).map_err(|_| Unusable::Unreadable)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| Unusable::Corrupt)?;
    match value.get("schema").and_then(Value::as_str) {
        Some(SCHEMA) => {}
        Some(other) if other.starts_with("hol.plugin-kit.installs.") => {
            return Err(Unusable::Unreadable)
        }
        _ => return Err(Unusable::Corrupt),
    }
    match value.get("installs") {
        Some(Value::Object(installs)) => Ok(installs.clone()),
        _ => Err(Unusable::Corrupt),
    }
}

fn read(directory: &Path) -> Result<Map<String, Value>, String> {
    load(directory).map_err(|_| INVALID.to_owned())
}

fn write(directory: &Path, installs: Map<String, Value>) -> Result<(), String> {
    let mut body = serde_json::to_vec_pretty(&json!({"schema": SCHEMA, "installs": installs}))
        .map_err(|_| "plugin_kit_encode_failed".to_owned())?;
    body.push(b'\n');
    let temporary = directory.join(format!(".{FILE}.{}.tmp", std::process::id()));
    // Only a crashed earlier run with this pid can leave it; we hold the lock.
    let _ = fs::remove_file(&temporary);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options
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

/// The fields of a target that `uninstall` needs. A v2 spec may carry fields
/// this Guard does not know; they are not kept.
fn stored_target(target: &Value) -> Value {
    let mut stored = Map::new();
    for key in ["runtime", "plugin", "repository"] {
        if let Some(value) = target.get(key).filter(|value| !value.is_null()) {
            stored.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(marketplace) = target.get("marketplace").filter(|m| m.is_object()) {
        let mut kept = Map::new();
        for key in ["repository", "name", "ref"] {
            if let Some(value) = marketplace.get(key).filter(|value| !value.is_null()) {
                kept.insert(key.to_owned(), value.clone());
            }
        }
        stored.insert("marketplace".to_owned(), Value::Object(kept));
    }
    Value::Object(stored)
}

/// Whether two recorded marketplaces have the same name and repository.
fn same_marketplace(a: &Value, b: &Value) -> bool {
    let key = |m: &Value, k: &str| {
        m.get(k)
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
    };
    a.is_object()
        && key(a, "name") == key(b, "name")
        && key(a, "repository") == key(b, "repository")
}

/// Runtimes of an entry whose marketplace Guard added, so `uninstall` may
/// remove it again.
fn added_marketplaces(entry: Option<&Value>) -> Vec<String> {
    entry
        .and_then(|entry| entry["addedMarketplaces"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|runtime| runtime.as_str().map(str::to_owned))
        .collect()
}

/// Add (`installed`) or drop one runtime of a listing. Adding needs the spec
/// the install ran from; dropping needs only the slug. `marketplace_added`
/// says Guard registered the marketplace for this install (it was not there
/// before); a reinstall that found it keeps whatever was recorded earlier.
pub fn record(
    guard_home: &str,
    slug: &str,
    runtime: &str,
    installed: bool,
    spec: Option<Value>,
    origin: &str,
    marketplace_added: bool,
) -> Result<Value, String> {
    let added = match (installed, spec) {
        (true, Some(spec)) => {
            install::validate(&spec, origin)?;
            if spec["slug"].as_str() != Some(slug) {
                return Err("plugin_kit_install_spec_mismatch".to_owned());
            }
            let target = spec["targets"]
                .as_array()
                .and_then(|targets| targets.iter().find(|t| t["runtime"] == runtime))
                .map(stored_target)
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
        let previous = targets
            .iter()
            .find(|target| target["runtime"] == runtime)
            .map(|target| target["marketplace"].clone());
        targets.retain(|target| target["runtime"] != runtime);
        let mut owned = added_marketplaces(installs.get(slug));
        // Ownership carries over a reinstall only when it targets the same
        // marketplace; Guard never added one a newer spec moved to.
        let same_marketplace = match (&added, &previous) {
            (Some((_, target)), Some(before)) => same_marketplace(&target["marketplace"], before),
            _ => false,
        };
        let owned_before = same_marketplace && owned.iter().any(|r| r == runtime);
        owned.retain(|r| r != runtime);
        if added.is_some() && (marketplace_added || owned_before) {
            owned.push(runtime.to_owned());
            owned.sort();
        }
        let entry = match added {
            Some((spec, target)) => {
                targets.push(target);
                Some(json!({
                    "name": spec["name"],
                    "version": spec["version"],
                    "listingUrl": spec["listingUrl"],
                    "targets": targets,
                    "addedMarketplaces": owned,
                }))
            }
            None if targets.is_empty() => None,
            None => installs.get(slug).cloned().map(|mut entry| {
                entry["targets"] = Value::Array(targets);
                entry["addedMarketplaces"] = json!(owned);
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

fn summary(installs: &Map<String, Value>) -> Value {
    Value::Object(
        installs
            .iter()
            .map(|(slug, entry)| (slug.clone(), json!(runtimes(entry))))
            .collect(),
    )
}

/// Every listing Guard installed, as `{slug: [runtime, ...]}`. With
/// `recover`, the answer is `{"installs": {...}, "recovered": name|null}`:
/// a record that is a regular file but no longer parses is renamed to
/// `installs.json.corrupt-<unix seconds>[-n]`, never over an earlier one,
/// and Guard starts empty.
pub fn installs(guard_home: &str, recover: bool) -> Result<Value, String> {
    let directory = directory(guard_home)?;
    if !recover {
        return read(&directory).map(|installs| summary(&installs));
    }
    locked(&directory, || match load(&directory) {
        Ok(installs) => Ok(json!({"installs": summary(&installs), "recovered": null})),
        Err(Unusable::Unreadable) => Err(INVALID.to_owned()),
        Err(Unusable::Corrupt) => {
            let seconds = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            // Writers hold the lock, so a name that is free now stays free.
            let name = (0..100)
                .map(|n| match n {
                    0 => format!("{FILE}.corrupt-{seconds}"),
                    n => format!("{FILE}.corrupt-{seconds}-{n}"),
                })
                .find(|name| fs::symlink_metadata(directory.join(name)).is_err())
                .ok_or_else(|| UNWRITABLE.to_owned())?;
            fs::rename(directory.join(FILE), directory.join(&name))
                .map_err(|_| UNWRITABLE.to_owned())?;
            Ok(json!({"installs": {}, "recovered": name}))
        }
    })
}

/// Runtimes whose marketplace Guard added for this listing.
pub fn marketplaces_added(guard_home: &str, slug: &str) -> Result<Vec<String>, String> {
    let installs = read(&directory(guard_home)?)?;
    Ok(added_marketplaces(installs.get(slug)))
}

/// The install spec Guard recorded for a listing, rebuilt for `uninstall`.
pub fn spec(guard_home: &str, slug: &str) -> Result<Value, String> {
    let installs = read(&directory(guard_home)?)?;
    let entry = installs.get(slug).ok_or_else(|| NOT_RECORDED.to_owned())?;
    Ok(json!({
        "schema": install::SPEC_SCHEMA_V2,
        "slug": slug,
        "name": entry["name"],
        "version": entry["version"],
        "listingUrl": entry["listingUrl"],
        "targets": entry["targets"],
    }))
}
