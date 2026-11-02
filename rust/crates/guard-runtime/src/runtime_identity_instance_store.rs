//! Running runtime instances carried from one probe to the next, for probe
//! requests that name an `instance_home`.
//!
//! Once the file at a runtime's path is replaced, nothing on disk says what an
//! older process started from. The probe binds each process to its build
//! while the file still provably matches; `runtime-instances.json` in the
//! Guard home keeps the running ones so the next probe can carry them as known
//! instances. Losing or damaging the file only makes those processes unknown,
//! which never clears an advisory, and a stored instance the probe would
//! refuse is dropped on its own, so it costs only the process it named.
//!
//! Scans of different scopes share the file. Each write re-reads it and
//! replaces only the locations its own probe covered, so a scan never restores
//! what another one removed. Two scans racing on the same location keep the
//! later one's view; a process the earlier scan bound is then unknown again,
//! never fixed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde_json::{json, Value};

use crate::encrypted_secret_store::atomic_write_bytes;
use crate::runtime_identity_instances::{validate_known, KnownInstance};

pub(crate) const FEATURE: &str = "runtime-identity-instance-store-v1";
pub(super) const STORE_NAME: &str = "runtime-instances.json";
const STORE_SCHEMA: &str = "guard.runtime-instances.v1";
pub(super) const MAX_STORED: usize = 1_024;
/// A full store is well under this; anything larger is not one Guard wrote.
const MAX_STORE_BYTES: u64 = 4 * 1024 * 1024;

/// The instances an earlier probe saw running, or none when the record is
/// missing or unreadable.
pub(super) fn load(home: &Path) -> Vec<KnownInstance> {
    stored(home)
        .into_iter()
        .filter_map(|item| serde_json::from_value(item).ok())
        .collect()
}

/// Keep what `reply` saw running, and the stored instances at locations it
/// did not cover. A failed write leaves those processes unknown, never fixed.
pub(super) fn remember(home: &Path, reply: &Value) {
    let Some(rows) = reply["instances"].as_array() else {
        return;
    };
    let probed: BTreeSet<&str> = reply["locations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|location| location["location_id"].as_str())
        .collect();
    let artifacts: BTreeMap<&str, &Value> = reply["artifacts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|artifact| Some((artifact["artifact_id"].as_str()?, artifact)))
        .collect();
    let mut kept: Vec<Value> = rows
        .iter()
        .filter(|row| row["state"] == "running" && !row["location_id"].is_null())
        .filter_map(|row| {
            let artifact = artifacts.get(row["artifact_id"].as_str()?)?;
            Some(json!({
                "boot_identity": row["boot_identity"],
                "pid": row["pid"],
                "start_identity": row["start_identity"],
                "location_id": row["location_id"],
                "artifact": artifact,
            }))
        })
        .collect();
    let mut seen: BTreeSet<String> = kept.iter().map(process_key).collect();
    for item in stored(home) {
        let elsewhere = item["location_id"]
            .as_str()
            .is_none_or(|location| !probed.contains(location));
        if elsewhere && seen.insert(process_key(&item)) {
            kept.push(item);
        }
    }
    kept.truncate(MAX_STORED);
    let payload = json!({"schema": STORE_SCHEMA, "instances": kept});
    if let Ok(text) = serde_json::to_vec(&payload) {
        let _ = atomic_write_bytes(&home.join(STORE_NAME), &text, 0o600);
    }
}

fn process_key(item: &Value) -> String {
    json!([item["boot_identity"], item["pid"], item["start_identity"]]).to_string()
}

/// The stored records the probe would accept, each checked on its own.
fn stored(home: &Path) -> Vec<Value> {
    let Some(data) = read_store(&home.join(STORE_NAME)) else {
        return Vec::new();
    };
    if data["schema"] != STORE_SCHEMA {
        return Vec::new();
    }
    let Value::Array(items) = data["instances"].clone() else {
        return Vec::new();
    };
    items.into_iter().filter(carried).take(MAX_STORED).collect()
}

fn read_store(path: &Path) -> Option<Value> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_STORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Every field present, and the record one the probe accepts as known.
fn carried(item: &Value) -> bool {
    let Some(fields) = item.as_object() else {
        return false;
    };
    const KEYS: [&str; 5] = [
        "artifact",
        "boot_identity",
        "location_id",
        "pid",
        "start_identity",
    ];
    fields.len() == KEYS.len()
        && KEYS.iter().all(|key| fields.contains_key(*key))
        && serde_json::from_value::<KnownInstance>(item.clone())
            .is_ok_and(|known| validate_known(std::slice::from_ref(&known)).is_ok())
}

#[cfg(test)]
#[path = "runtime_identity_instance_store_tests.rs"]
mod tests;
