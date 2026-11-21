//! The tombstone that records one managed removal: who authorized it, for
//! which installation, and each step it has taken since.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Map, Value};

use super::files::{open_without_following, private_directory, replace_private};
use super::{
    fields, has_exact_keys, is_hex64, isoformat, os_error, python_json_line, value_error, Answer,
    Refusal,
};
use crate::policy_bundle_time::from_isoformat;

// Three events with bounded fields fit in a few kilobytes.
const MAX_TOMBSTONE_BYTES: u64 = 64 * 1024;
const MAX_TOMBSTONES: usize = 4096;
const TOMBSTONE_STATUSES: [&str; 4] = ["issued", "started", "completed", "failed"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TombstoneRequest {
    root: PathBuf,
    status: String,
    evidence: Evidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    fingerprint: String,
    actor: String,
    reason: String,
    machine_installation_id: String,
    installation_generation: String,
    issued_at: String,
    expires_at: String,
}

/// Append `status` to the tombstone for one authorization, refusing a
/// tombstone that does not match it or a step its history does not allow.
pub(super) fn record_tombstone(request: &TombstoneRequest, now: i64) -> Answer {
    if !TOMBSTONE_STATUSES.contains(&request.status.as_str()) {
        return Err(value_error("mdm_removal_tombstone_status_invalid"));
    }
    let evidence = &request.evidence;
    if !is_hex64(&evidence.fingerprint) {
        return Err(value_error("mdm_removal_tombstone_invalid"));
    }
    let write_failed = os_error("mdm_removal_tombstone_write_failed");
    private_directory(&request.root).map_err(|_| write_failed)?;
    let target = request.root.join(format!("{}.json", evidence.fingerprint));
    let identity = tombstone_identity(evidence);
    let mut events = Vec::new();
    match fs::symlink_metadata(&target) {
        Ok(metadata) => events = existing_events(&target, &metadata, &identity)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if regular_file_count(&request.root).map_err(|_| write_failed)? >= MAX_TOMBSTONES {
                return Err(os_error("mdm_removal_tombstone_capacity_exceeded"));
            }
        }
        Err(_) => return Err(write_failed),
    }
    let previous = events
        .last()
        .and_then(|event| event.get("status"))
        .and_then(Value::as_str);
    if !transition_is_allowed(previous, &request.status) {
        return Err(value_error("mdm_removal_tombstone_transition_invalid"));
    }
    let updated_at = isoformat(now)?;
    events.push(json!({"at": updated_at, "status": request.status}));
    let mut payload = identity;
    payload.insert("events".to_owned(), Value::Array(events));
    payload.insert("status".to_owned(), Value::String(request.status.clone()));
    payload.insert("updatedAt".to_owned(), Value::String(updated_at));
    let bytes = python_json_line(&Value::Object(payload))?;
    let target_text = target.to_str().ok_or(write_failed)?.to_owned();
    replace_private(&request.root, &target, &evidence.fingerprint, &bytes)
        .map_err(|_| write_failed)?;
    Ok(fields([("path", Value::String(target_text))]))
}

fn tombstone_identity(evidence: &Evidence) -> Map<String, Value> {
    fields([
        ("actor", Value::String(evidence.actor.clone())),
        (
            "authorizationExpiresAt",
            Value::String(evidence.expires_at.clone()),
        ),
        (
            "authorizationFingerprint",
            Value::String(evidence.fingerprint.clone()),
        ),
        (
            "authorizationIssuedAt",
            Value::String(evidence.issued_at.clone()),
        ),
        (
            "installationGeneration",
            Value::String(evidence.installation_generation.clone()),
        ),
        (
            "machineInstallationId",
            Value::String(evidence.machine_installation_id.clone()),
        ),
        ("operation", Value::String("deactivate".to_owned())),
        ("reason", Value::String(evidence.reason.clone())),
        (
            "schemaVersion",
            Value::String("hol-guard-removal-tombstone.v1".to_owned()),
        ),
    ])
}

/// The events of the tombstone already at `target`, each a step its
/// predecessor allows, in time order, and ending at the recorded status.
fn existing_events(
    target: &Path,
    metadata: &fs::Metadata,
    identity: &Map<String, Value>,
) -> Result<Vec<Value>, Refusal> {
    let invalid = value_error("mdm_removal_tombstone_invalid");
    if !metadata.is_file() || metadata.len() > MAX_TOMBSTONE_BYTES {
        return Err(invalid);
    }
    let mut bytes = Vec::new();
    open_without_following(target)
        .and_then(|file| file.take(MAX_TOMBSTONE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| invalid)?;
    let Ok(Value::Object(existing)) = serde_json::from_slice::<Value>(&bytes) else {
        return Err(invalid);
    };
    let keys = identity
        .keys()
        .map(String::as_str)
        .chain(["events", "status", "updatedAt"]);
    if !has_exact_keys(&existing, keys) {
        return Err(invalid);
    }
    if identity
        .iter()
        .any(|(key, value)| existing.get(key) != Some(value))
    {
        return Err(value_error("mdm_removal_tombstone_identity_mismatch"));
    }
    let Some(Value::Array(recorded)) = existing.get("events") else {
        return Err(invalid);
    };
    if !(1..=3).contains(&recorded.len()) {
        return Err(invalid);
    }
    let mut events = Vec::new();
    let mut previous: Option<(&str, i64)> = None;
    for event in recorded {
        let (Some(at), Some(status)) = (event_text(event, "at"), event_text(event, "status"))
        else {
            return Err(invalid);
        };
        let Some(time) = from_isoformat(at)
            .filter(|parsed| parsed.is_aware())
            .and_then(|parsed| parsed.utc_micros())
        else {
            return Err(invalid);
        };
        if previous.is_some_and(|(_, earlier)| time < earlier)
            || !transition_is_allowed(previous.map(|(status, _)| status), status)
        {
            return Err(invalid);
        }
        events.push(json!({"at": at, "status": status}));
        previous = Some((status, time));
    }
    let last = recorded.last().ok_or(invalid)?;
    if existing.get("status") != last.get("status") || existing.get("updatedAt") != last.get("at") {
        return Err(invalid);
    }
    Ok(events)
}

/// A string field of an event object holding exactly `at` and `status`.
fn event_text<'a>(event: &'a Value, key: &str) -> Option<&'a str> {
    let event = event.as_object()?;
    if event.len() != 2 {
        return None;
    }
    event.get(key)?.as_str()
}

fn transition_is_allowed(previous: Option<&str>, next: &str) -> bool {
    match previous {
        None => matches!(next, "issued" | "started"),
        Some("issued") => next == "started",
        Some("started") => matches!(next, "completed" | "failed"),
        Some(_) => false,
    }
}

fn regular_file_count(root: &Path) -> io::Result<usize> {
    let mut count = 0;
    for entry in fs::read_dir(root)? {
        if entry?.file_type()?.is_file() {
            count += 1;
        }
    }
    Ok(count)
}
