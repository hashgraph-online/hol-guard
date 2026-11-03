//! The `policy` and `runtimes` sections of `fleet-posture/v1`.
//!
//! `fleet_policy_section` mirrors the policy acknowledgement Guard sends in
//! the same request, or, without one, the last policy bundle error the store
//! recorded: `{"acknowledgement": object|null, "last_error": any}` answers the
//! section.
//!
//! `fleet_runtime_posture` reduces a `hol-guard runtime posture` payload to
//! the `runtimes` section: `{"posture": object, "hash_key": str}` answers the
//! section. The native request parser refuses any array wider than 4096
//! entries, so the posture's `runtimes` and `unresolved_launches` lists arrive
//! as lists of chunks that join back in order. The section names no path,
//! server or command line: the executable is named
//! by its content digest and its location by a digest keyed with the
//! per-install secret. A posture whose status is not one the contract names
//! is refused, as is a value Python could not look up in a set.
//!
//! Codes and digests must match their whole value. The Python patterns also
//! accepted one trailing newline and carried it into the section, which the
//! contract never allowed.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::cloud_request_text::py_truthy;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

use super::selection::{keyed_digest, normalized_timestamp, HARNESS_IDS};

const MAX_RUNTIMES: usize = 64;
const MAX_ADVISORY_IDS: usize = 16;
const MAX_ADVISORY_ID_CHARS: usize = 128;
const MAX_UNRESOLVED_LAUNCHES: usize = 10_000;
const MAX_TEXT_CHARS: usize = 80;
const MAX_VERSION_CHARS: usize = 64;
const MAX_CODE_CHARS: usize = 64;
const STATUSES: [&str; 3] = ["ok", "partial", "unavailable"];
const ASSURANCES: [&str; 4] = [
    "vendor_verified",
    "locally_trusted",
    "self_reported",
    "unknown",
];
const LOCATION_STATES: [&str; 3] = ["present", "missing", "unknown"];

pub(super) fn policy(args: &Map<String, Value>) -> KindResult {
    if args.len() != 2 || !args.contains_key("last_error") {
        return Err(ERR_INVALID);
    }
    let acknowledgement = match args.get("acknowledgement") {
        Some(Value::Object(acknowledgement)) => Some(acknowledgement),
        Some(Value::Null) => None,
        _ => return Err(ERR_INVALID),
    };
    let mut section = json!({
        "appliedBundleVersion": null,
        "appliedBundleHash": null,
        "appliedPolicyVersionNumber": null,
        "status": "none",
        "errorCode": null,
        "appliedAt": null,
    });
    if let Some(acknowledgement) = acknowledgement.filter(|ack| !ack.is_empty()) {
        let status = match acknowledgement.get("status").and_then(Value::as_str) {
            Some("applied" | "synced") => "applied",
            Some("validated") => "validated",
            Some("failed") => "rejected",
            _ => "none",
        };
        let error_code = truthy_or(acknowledgement, "errorCode", "reason");
        section["appliedBundleVersion"] = positive_int(acknowledgement.get("bundleVersion"));
        section["appliedBundleHash"] = clipped(acknowledgement.get("bundleHash"), MAX_TEXT_CHARS);
        section["appliedPolicyVersionNumber"] = positive_int(acknowledgement.get("policyRevision"));
        section["status"] = Value::from(status);
        if status == "rejected" {
            section["errorCode"] = clipped(error_code, MAX_TEXT_CHARS);
        }
        section["appliedAt"] =
            normalized_timestamp(truthy_or(acknowledgement, "appliedAt", "observedAt"))
                .map_or(Value::Null, Value::from);
        return Ok(section);
    }
    if let Some(reason) = args
        .get("last_error")
        .and_then(|last| last.get("reason"))
        .filter(|reason| reason.is_string())
    {
        section["status"] = Value::from("rejected");
        section["errorCode"] = clipped(Some(reason), MAX_TEXT_CHARS);
    }
    Ok(section)
}

pub(super) fn runtimes(args: &Map<String, Value>) -> KindResult {
    if args.len() != 2 {
        return Err(ERR_INVALID);
    }
    let key = super::hash_key(args)?;
    let posture = args
        .get("posture")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let mut status = match posture.get("status") {
        Some(Value::String(status)) if STATUSES.contains(&status.as_str()) => status.as_str(),
        _ => return Err(ERR_INVALID),
    };
    let rows: Vec<&Map<String, Value>> = joined(posture.get("runtimes"))
        .into_iter()
        .filter_map(Value::as_object)
        .collect();
    let truncated = rows.len() > MAX_RUNTIMES;
    let mut reason = optional_code(posture.get("error"));
    if truncated && status == "ok" {
        status = "partial";
        reason = Value::from("runtime_candidate_limit_reached");
    }
    let advisories_available = posture
        .get("coverage")
        .and_then(Value::as_object)
        .and_then(|coverage| coverage.get("advisories_available"))
        == Some(&Value::Bool(true));
    let unresolved = joined(posture.get("unresolved_launches"))
        .len()
        .min(MAX_UNRESOLVED_LAUNCHES);
    let items = rows
        .iter()
        .take(MAX_RUNTIMES)
        .map(|row| item(row, key))
        .collect::<Result<Vec<Value>, &'static str>>()?;
    Ok(json!({
        "status": status,
        "reason": reason,
        "coverage": "observed_only",
        "scopeComplete": false,
        "advisoriesAvailable": advisories_available,
        "candidateLimitReached": posture.get("candidate_limit_reached").is_some_and(py_truthy)
            || truncated,
        "unresolvedLaunches": unresolved,
        "items": items,
    }))
}

/// The entries of a chunked list, in order; anything but a list of chunks
/// holds none.
fn joined(value: Option<&Value>) -> Vec<&Value> {
    let Some(Value::Array(chunks)) = value else {
        return Vec::new();
    };
    chunks
        .iter()
        .filter_map(Value::as_array)
        .flatten()
        .collect()
}

fn item(row: &Map<String, Value>, key: &[u8]) -> KindResult {
    let mut harnesses: BTreeSet<&str> = BTreeSet::new();
    for entry in row
        .get("launched_by")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(harness) = entry.get("harness").and_then(Value::as_str) {
            if HARNESS_IDS.contains(&harness) {
                harnesses.insert(harness);
            }
        }
    }
    let version = row
        .get("version")
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty())
        .map_or(Value::Null, |version| {
            Value::from(clip(version, MAX_VERSION_CHARS))
        });
    let executable = row
        .get("executable_sha256")
        .and_then(Value::as_str)
        .filter(|digest| is_sha256_hex(digest))
        .map_or(Value::Null, |digest| {
            Value::from(format!("sha256:{digest}"))
        });
    let location = match row.get("path").and_then(Value::as_str) {
        Some(path) if !path.is_empty() => Value::from(keyed_digest(key, path)?),
        _ => Value::Null,
    };
    Ok(json!({
        "family": code(row.get("family")),
        "version": version,
        "identityAssurance": member(row.get("identity_assurance"), &ASSURANCES)?,
        "executableHash": executable,
        "os": code(row.get("os")),
        "arch": code(row.get("arch")),
        "locationState": member(row.get("location_state"), &LOCATION_STATES)?,
        "reason": optional_code(row.get("reason")),
        "locationHash": location,
        "harnesses": harnesses.into_iter().collect::<Vec<&str>>(),
        "advisoryIds": advisory_ids(row.get("advisory_matches")),
    }))
}

/// `_advisory_ids`: the distinct ids of the matches, in order, at most 16.
fn advisory_ids(matches: Option<&Value>) -> Vec<&str> {
    let mut ids: Vec<&str> = Vec::new();
    for entry in matches.and_then(Value::as_array).into_iter().flatten() {
        let advisory_id = match entry {
            Value::Object(entry) => entry.get("advisory_id"),
            other => Some(other),
        };
        if let Some(advisory_id) = advisory_id.and_then(Value::as_str) {
            let chars = advisory_id.chars().count();
            if (1..=MAX_ADVISORY_ID_CHARS).contains(&chars) && !ids.contains(&advisory_id) {
                ids.push(advisory_id);
            }
        }
    }
    ids.truncate(MAX_ADVISORY_IDS);
    ids
}

/// `value if value in allowed else "unknown"`; Python could not look an array
/// or object up in a set, so those refuse the section.
fn member(value: Option<&Value>, allowed: &[&str]) -> KindResult {
    match value {
        Some(Value::Array(_) | Value::Object(_)) => Err(ERR_INVALID),
        Some(Value::String(text)) if allowed.contains(&text.as_str()) => {
            Ok(Value::from(text.as_str()))
        }
        _ => Ok(Value::from("unknown")),
    }
}

/// `_code`: a short lowercase code, else `unknown`.
fn code(value: Option<&Value>) -> &str {
    match value.and_then(Value::as_str) {
        Some(text)
            if (1..=MAX_CODE_CHARS).contains(&text.len())
                && text.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                }) =>
        {
            text
        }
        _ => "unknown",
    }
}

/// `_code(value) if value is not None else None`.
fn optional_code(value: Option<&Value>) -> Value {
    match value {
        None | Some(Value::Null) => Value::Null,
        value => Value::from(code(value)),
    }
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `clip`: the first `limit` characters.
fn clip(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

fn clipped(value: Option<&Value>, limit: usize) -> Value {
    value
        .and_then(Value::as_str)
        .map_or(Value::Null, |text| Value::from(clip(text, limit)))
}

/// `record.get(first) or record.get(second)`.
fn truthy_or<'a>(record: &'a Map<String, Value>, first: &str, second: &str) -> Option<&'a Value> {
    record
        .get(first)
        .filter(|value| py_truthy(value))
        .or_else(|| record.get(second))
}

/// `_int_or_none`: an integer of at least one; booleans and floats are not.
fn positive_int(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Number(number)) => {
            let text = number.to_string();
            if text.bytes().all(|byte| byte.is_ascii_digit()) && text != "0" {
                Value::Number(number.clone())
            } else {
                Value::Null
            }
        }
        _ => Value::Null,
    }
}

#[cfg(test)]
#[path = "fleet_posture_sections_tests.rs"]
mod tests;
