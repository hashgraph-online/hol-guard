//! Whether an observed harness version is covered by the bundled evidence
//! (`op: "decide"`), and the local store of untested-version warnings the
//! user acknowledged (`op: "acknowledge"`, `op: "clear"`).
//!
//! The decision is a pure function of the observation, the manifest, the
//! running Guard build, and the acknowledgement store. Its result is display
//! data only: it never feeds policy, approval, or tool admission. Every
//! uncertain input lands on an uncertain state; nothing falls through to
//! `tested`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[path = "harness_version_manifest.rs"]
mod manifest;

const SCHEMA: &str = "harness-version-compatibility.v1";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const PAYLOAD_SCHEMA: &str = "hol-guard-harness-version-compatibility.v1";
const OBSERVATION_MAX_AGE_SECONDS: f64 = 15.0 * 60.0;
const ACKNOWLEDGEMENTS_FILENAME: &str = "harness-version-acknowledgements.json";
const STORE_VERSION: u64 = 1;
const MAX_ACKNOWLEDGEMENTS: usize = 32;
const MAX_STORE_BYTES: u64 = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    guard_home: String,
    harness: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    manifest_path: Option<String>,
    #[serde(default)]
    guard_version: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    now: Option<f64>,
    #[serde(default)]
    observation: Option<Observation>,
    /// Each canonical harness's declared capability rows, keyed by harness.
    #[serde(default)]
    contracts: BTreeMap<String, Vec<CapabilityRow>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    state: String,
    version: Option<String>,
    source: String,
    installation_id: Option<String>,
    reason: Option<String>,
    observed_at: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityRow {
    event: String,
    transport: String,
    declared_actions: Vec<String>,
}

#[derive(Clone)]
struct Acknowledgement {
    harness: String,
    key: String,
    acknowledged_at: String,
}

impl Acknowledgement {
    fn to_value(&self) -> Value {
        json!({
            "harness": self.harness,
            "key": self.key,
            "acknowledged_at": self.acknowledged_at,
        })
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "harness-version-compatibility"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "harness_version_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("harness_version_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    answer(&request).map(|value| value.to_string().into_bytes())
}

fn invalid() -> String {
    "harness_version_request_invalid".to_owned()
}

fn answer(request: &Request) -> Result<Value, String> {
    let guard_home = PathBuf::from(&request.guard_home);
    if request.schema != SCHEMA || !guard_home.is_absolute() {
        return Err(invalid());
    }
    match request.op.as_str() {
        "decide" => decide(request, &guard_home),
        "acknowledge" => acknowledge(request, &guard_home),
        "clear" => clear(request, &guard_home),
        _ => Err(invalid()),
    }
}

/// Events the adapter declares an active protection transport for.
fn declared_events(rows: Option<&Vec<CapabilityRow>>) -> BTreeSet<String> {
    rows.into_iter()
        .flatten()
        .filter(|row| {
            !matches!(row.transport.as_str(), "none" | "adapter_declared")
                && !row
                    .declared_actions
                    .iter()
                    .any(|action| action == "unavailable")
        })
        .map(|row| row.event.clone())
        .collect()
}

/// Bind an acknowledgement to installation, exact version, and coverage.
fn acknowledgement_key(
    harness: &str,
    installation_id: &str,
    version: &str,
    revision: &str,
    guard_version: &str,
) -> String {
    let material = [
        "hvc-ack.v1",
        harness,
        installation_id,
        version,
        revision,
        guard_version,
    ]
    .join("\0");
    hex::encode(Sha256::digest(material.as_bytes()))
}

fn decide(request: &Request, guard_home: &Path) -> Result<Value, String> {
    let harness = request.harness.as_str();
    let observation = request.observation.as_ref().ok_or_else(invalid)?;
    let guard_version = request.guard_version.as_deref().ok_or_else(invalid)?;
    let platform = request.platform.as_deref().ok_or_else(invalid)?;
    let now = request.now.ok_or_else(invalid)?;
    let manifest_path = PathBuf::from(request.manifest_path.as_deref().ok_or_else(invalid)?);
    if harness.is_empty() || harness.len() > 64 || !manifest_path.is_absolute() {
        return Err(invalid());
    }
    let version = observation
        .version
        .as_deref()
        .and_then(manifest::parse_version);
    let age = now - observation.observed_at;
    let fresh =
        observation.state == "observed" && (0.0..=OBSERVATION_MAX_AGE_SECONDS).contains(&age);
    let declared = declared_events(request.contracts.get(harness));
    let mut payload = json!({
        "schema": PAYLOAD_SCHEMA,
        "harness": harness,
        "state": "version_unknown",
        "reason": observation.reason,
        "detected_version": version.as_ref().map(|found| found.canonical.clone()),
        "version_is_prerelease": version.as_ref().is_some_and(|found| found.prerelease),
        "version_source": observation.source,
        "observed_at": iso_utc_z(observation.observed_at),
        "observation_fresh": fresh,
        "guard_version": guard_version,
        "platform": platform,
        "coverage_revision": null,
        "tested_versions": [],
        "tested_scope": null,
        "tested_events": [],
        "declared_events": declared,
        "evidence": [],
        "limitations": [],
        "remediation": [],
        "acknowledgement": { "eligible": false, "acknowledged": false, "key": null },
        // Compatibility is informational. Enforcement never reads this payload.
        "enforcement_effect": "none",
    });
    let loaded = manifest::load(&manifest_path, &request.contracts);
    let coverage = loaded
        .as_ref()
        .ok()
        .and_then(|manifest| manifest.harnesses.get(harness));
    if let Ok(manifest) = &loaded {
        payload["coverage_revision"] = json!(manifest.revision);
    }
    let mut applicable = Vec::new();
    if let Some(coverage) = coverage {
        payload["limitations"] = json!(coverage.limitations);
        payload["remediation"] = json!(coverage.remediation);
        applicable = coverage
            .records
            .iter()
            .filter(|record| {
                record.guard_version == guard_version
                    && record.platforms.iter().any(|item| item == platform)
            })
            .collect();
    }
    let tested_versions: BTreeSet<&str> = applicable
        .iter()
        .map(|record| record.harness_version.as_str())
        .collect();
    payload["tested_versions"] = json!(tested_versions);

    let (Some(version), "observed") = (&version, observation.state.as_str()) else {
        payload["reason"] = json!(observation
            .reason
            .as_deref()
            .filter(|reason| !reason.is_empty())
            .unwrap_or("version_unobserved"));
        return Ok(payload);
    };
    if !fresh {
        payload["reason"] = json!("observation_stale");
        return Ok(payload);
    }
    let manifest = match &loaded {
        Ok(manifest) => manifest,
        Err(reason) => return Ok(unavailable(payload, reason)),
    };
    if coverage.is_none_or(|coverage| coverage.records.is_empty()) {
        return Ok(unavailable(payload, "harness_not_covered"));
    }
    if applicable.is_empty() {
        return Ok(unavailable(payload, "no_evidence_for_this_build"));
    }

    let detected = version.canonical.as_str();
    let matching: Vec<_> = applicable
        .iter()
        .filter(|record| record.harness_version == detected)
        .collect();
    if matching.is_empty() {
        payload["state"] = json!("untested");
        payload["reason"] = json!("version_not_in_evidence");
        let key = acknowledgement_key(
            harness,
            observation.installation_id.as_deref().unwrap_or_default(),
            detected,
            &manifest.revision,
            guard_version,
        );
        let eligible = observation.installation_id.is_some();
        let acknowledged = eligible
            && load_acknowledgements(guard_home)
                .iter()
                .any(|entry| entry.harness == harness && entry.key == key);
        payload["acknowledgement"] = json!({
            "eligible": eligible,
            "acknowledged": acknowledged,
            "key": eligible.then_some(key),
        });
        return Ok(payload);
    }

    let tested_events: BTreeSet<&str> = matching
        .iter()
        .flat_map(|record| record.events.iter().map(String::as_str))
        .collect();
    let all_declared = !declared.is_empty()
        && declared
            .iter()
            .all(|event| tested_events.contains(event.as_str()));
    payload["state"] = json!("tested");
    payload["reason"] = Value::Null;
    payload["tested_events"] = json!(tested_events);
    payload["tested_scope"] = json!(if all_declared {
        "all_declared_events"
    } else {
        "partial"
    });
    payload["evidence"] = matching.iter().map(|record| record.to_value()).collect();
    Ok(payload)
}

fn unavailable(mut payload: Value, reason: &str) -> Value {
    payload["state"] = json!("coverage_unavailable");
    payload["reason"] = json!(reason);
    payload
}

fn valid_harness(harness: &str) -> bool {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN
        .get_or_init(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,63}$").expect("harness pattern"))
        .is_match(harness)
}

fn valid_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn store_path(guard_home: &Path) -> PathBuf {
    guard_home.join(ACKNOWLEDGEMENTS_FILENAME)
}

/// Read the bounded store; a corrupt store acknowledges nothing.
fn load_acknowledgements(guard_home: &Path) -> Vec<Acknowledgement> {
    let mut bytes = Vec::new();
    let read = fs::File::open(store_path(guard_home))
        .and_then(|file| file.take(MAX_STORE_BYTES + 1).read_to_end(&mut bytes));
    if read.is_err() || bytes.len() as u64 > MAX_STORE_BYTES {
        return Vec::new();
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };
    if payload.get("version").and_then(Value::as_u64) != Some(STORE_VERSION) {
        return Vec::new();
    }
    let Some(items) = payload.get("items").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .take(MAX_ACKNOWLEDGEMENTS)
        .filter_map(valid_entry)
        .collect()
}

fn valid_entry(value: &Value) -> Option<Acknowledgement> {
    let object = value.as_object()?;
    if object.len() != 3 {
        return None;
    }
    let harness = object.get("harness")?.as_str()?;
    let key = object.get("key")?.as_str()?;
    let acknowledged_at = object.get("acknowledged_at")?.as_str()?;
    (valid_harness(harness) && valid_key(key) && acknowledged_at.chars().count() <= 40).then(|| {
        Acknowledgement {
            harness: harness.to_owned(),
            key: key.to_owned(),
            acknowledged_at: acknowledged_at.to_owned(),
        }
    })
}

/// Store one acknowledgement, replacing earlier ones for the harness.
fn acknowledge(request: &Request, guard_home: &Path) -> Result<Value, String> {
    let key = request.key.as_deref().ok_or_else(invalid)?;
    if !valid_harness(&request.harness) || !valid_key(key) {
        return Err(invalid());
    }
    let entry = Acknowledgement {
        harness: request.harness.clone(),
        key: key.to_owned(),
        acknowledged_at: iso_utc_z(now_seconds()),
    };
    let mut entries: Vec<Acknowledgement> = load_acknowledgements(guard_home)
        .into_iter()
        .filter(|item| item.harness != request.harness)
        .collect();
    entries.push(entry.clone());
    write_store(guard_home, &entries).map_err(store_error)?;
    Ok(json!({ "entry": entry.to_value() }))
}

fn clear(request: &Request, guard_home: &Path) -> Result<Value, String> {
    if !valid_harness(&request.harness) || request.key.is_some() {
        return Err(invalid());
    }
    let entries = load_acknowledgements(guard_home);
    let kept: Vec<Acknowledgement> = entries
        .iter()
        .filter(|item| item.harness != request.harness)
        .cloned()
        .collect();
    if kept.len() != entries.len() {
        write_store(guard_home, &kept).map_err(store_error)?;
    }
    Ok(json!({ "cleared": entries.len() - kept.len() }))
}

fn store_error(_: io::Error) -> String {
    "harness_version_acknowledgement_store_unavailable".to_owned()
}

/// Replace the store atomically with an owner-only file.
fn write_store(guard_home: &Path, entries: &[Acknowledgement]) -> io::Result<()> {
    fs::create_dir_all(guard_home)?;
    let start = entries.len().saturating_sub(MAX_ACKNOWLEDGEMENTS);
    let items: Vec<Value> = entries[start..]
        .iter()
        .map(Acknowledgement::to_value)
        .collect();
    let body = json!({ "items": items, "version": STORE_VERSION }).to_string();
    let mut temporary = tempfile::Builder::new()
        .prefix(".hvc-ack-")
        .tempfile_in(guard_home)?;
    temporary.write_all(body.as_bytes())?;
    temporary.as_file().sync_all()?;
    #[cfg(unix)]
    fs::set_permissions(
        temporary.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;
    temporary
        .persist(store_path(guard_home))
        .map_err(|error| error.error)?;
    sync_directory(guard_home);
    Ok(())
}

/// Flush the rename. A platform that cannot open a directory handle fails
/// the open, and the update itself already succeeded.
fn sync_directory(directory: &Path) {
    if let Ok(handle) = fs::File::open(directory) {
        let _ = handle.sync_all();
    }
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

/// `datetime.fromtimestamp(epoch, timezone.utc).isoformat()` with a `Z`.
fn iso_utc_z(epoch: f64) -> String {
    let micros = if epoch.is_finite() {
        (epoch * 1_000_000.0).round() as i64
    } else {
        0
    };
    let seconds = micros.div_euclid(1_000_000);
    let fraction = micros.rem_euclid(1_000_000);
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let micro = if fraction == 0 {
        String::new()
    } else {
        format!(".{fraction:06}")
    };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{micro}Z",
        second_of_day / 3_600,
        second_of_day % 3_600 / 60,
        second_of_day % 60
    )
}

#[cfg(test)]
#[path = "harness_version_compat_tests.rs"]
mod tests;
