//! The owner-private files behind `hol-guard daemon recovery`: the latest
//! snapshot, the per-operation receipts and the diagnostics archive.
//!
//! The Python CLI reaches these through `daemon-recovery --stdin` mode
//! `store`; every read, write, retention rule and lock is decided here.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::daemon_recovery_contract::{self as contract, DIAGNOSTICS_SCHEMA};

const STATE_DIRECTORY: &str = "native-runtime";
const STATE_NAME: &str = "daemon-user-recovery.json";
const MAX_STATE_BYTES: u64 = 16 * 1024;
const RECEIPT_NAME: &str = "daemon-user-recovery-receipts.json";
const MAX_RECEIPT_BYTES: usize = 64 * 1024;
const MAX_RECEIPTS: usize = 64;
const RECEIPT_SCHEMA: &str = "hol-guard-recovery.receipts.v1";
const RECEIPT_PHASES: [&str; 5] = [
    "stopping",
    "starting",
    "verifying",
    "timed_out_waiting",
    "complete",
];
const DIAGNOSTICS_NAME: &str = "daemon-recovery-diagnostics.json";
const MAX_DIAGNOSTICS_BYTES: usize = 64 * 1024;
const ARCHIVE_SCHEMA: &str = "hol-guard-recovery-diagnostics-archive.v1";
const MAX_RETAINED_INCIDENTS: usize = 20;
const RETENTION_MICROS: i128 = 7 * 86_400 * 1_000_000;
const DIAGNOSTICS_LOCK_NAME: &str = "daemon-recovery-diagnostics.lock";

/// A refusal the CLI maps onto its exception classes by `kind`.
#[derive(Debug)]
pub(crate) struct Fail {
    pub(crate) kind: &'static str,
    pub(crate) code: String,
}

type Stored<T> = Result<T, Fail>;

fn contract_fail(code: String) -> Fail {
    let kind = if code.starts_with("recovery_diagnostics_") {
        "diagnostics"
    } else {
        "contract"
    };
    Fail { kind, code }
}

fn fail(kind: &'static str, code: &str) -> Fail {
    Fail {
        kind,
        code: code.to_owned(),
    }
}

fn storage() -> Fail {
    fail("storage", "recovery_storage_unavailable")
}

/// One `store` request: `{"op": ..., ...}` against `guard_home`.
pub(crate) fn answer(guard_home: &str, request: &Value) -> Stored<Value> {
    let home = Path::new(guard_home);
    let text = |key: &str| request.get(key).and_then(Value::as_str);
    let operation = || {
        text("operation_id")
            .and_then(contract::lenient_uuid)
            .ok_or_else(|| fail("contract", "operation_id_invalid"))
    };
    let now = || text("now").map_or_else(now_iso, str::to_owned);
    let snapshot = request.get("snapshot").unwrap_or(&Value::Null);
    match text("op").unwrap_or("") {
        "validate" => contract::validate(
            snapshot,
            request
                .get("allow_inspection")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        )
        .map_err(contract_fail),
        "sequence" => contract::validate_sequence(
            request.get("previous").filter(|value| !value.is_null()),
            snapshot,
        )
        .map_err(contract_fail),
        "build_diagnostics" => {
            let generated = text("generated_at").map_or_else(now_iso, str::to_owned);
            contract::build_report(request.get("snapshots").unwrap_or(&Value::Null), &generated)
                .map_err(contract_fail)
        }
        "validate_diagnostics" => {
            contract::validate_report(request.get("report").unwrap_or(&Value::Null))
                .map_err(contract_fail)
        }
        "persist" => persist_snapshot(home, snapshot, &now()).map(|()| Value::Null),
        "latest" => Ok(load_latest(home)?.unwrap_or(Value::Null)),
        "receipt" => Ok(load_receipt(home, &operation()?)?.unwrap_or(Value::Null)),
        "status" => load_snapshot(home, &operation()?),
        "diagnostics" => load_diagnostics(home, &operation()?, &now()),
        "persist_diagnostics" => {
            let generated = text("generated_at").map_or_else(now_iso, str::to_owned);
            persist_diagnostics(
                home,
                request.get("snapshots").unwrap_or(&Value::Null),
                &generated,
                &now(),
            )
        }
        "load_diagnostics" => {
            let reports = with_diagnostics_lock(home, || prune(home, load_archive(home)?, &now()))?;
            Ok(reports.last().cloned().unwrap_or(Value::Null))
        }
        "diagnostics_for" => {
            let expected = text("operation_id")
                .and_then(contract::canonical_uuid)
                .ok_or_else(|| fail("diagnostics", "recovery_diagnostics_operation_id_invalid"))?;
            report_for(home, &expected, &now())
        }
        _ => Err(fail("contract", "recovery_store_op_invalid")),
    }
}

/// `datetime.now(timezone.utc).isoformat()`.
fn now_iso() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64());
    crate::approval_gate_state::iso_from_epoch(seconds)
}

fn state_directory(home: &Path) -> PathBuf {
    home.join(STATE_DIRECTORY)
}

fn read_state(home: &Path, name: &str, maximum: u64) -> Stored<Option<Vec<u8>>> {
    let directory = state_directory(home);
    let private_root =
        crate::resident_state::private_root_for_state_base(&directory).map_err(|_| storage())?;
    crate::policy_store::read_private_file(
        &directory.join(name),
        maximum,
        "private_state",
        &private_root,
    )
    .map_err(|_| storage())
}

fn write_state(home: &Path, name: &str, content: &[u8], maximum: u64) -> Stored<()> {
    let directory = state_directory(home);
    crate::resident_state::ensure_private_directory_under(&directory, home, false)
        .map_err(|_| storage())?;
    let private_root =
        crate::resident_state::private_root_for_state_base(&directory).map_err(|_| storage())?;
    crate::policy_store::persist_private_bytes(
        &directory.join(name),
        content,
        maximum,
        "private_state",
        &private_root,
    )
    .map_err(|_| storage())
}

/// `sha256(str(Path(guard_home).expanduser().resolve()))`.
fn home_key(home: &Path) -> String {
    let resolved = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let text = resolved.to_string_lossy();
    // `canonicalize` adds the verbatim prefix that Python's `resolve` omits.
    let text = text
        .strip_prefix(r"\\?\")
        .filter(|rest| !rest.starts_with("UNC\\"))
        .unwrap_or(&text);
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn receipt_invalid() -> Fail {
    fail("state", "recovery_receipt_invalid")
}

fn load_receipt_records(home: &Path) -> Stored<Vec<(String, Value)>> {
    let Some(payload) = read_state(home, RECEIPT_NAME, MAX_RECEIPT_BYTES as u64)? else {
        return Ok(Vec::new());
    };
    let decoded: Value = serde_json::from_slice(&payload).map_err(|_| receipt_invalid())?;
    if decoded.get("schema").and_then(Value::as_str) != Some(RECEIPT_SCHEMA)
        || decoded.get("homeKey").and_then(Value::as_str) != Some(home_key(home).as_str())
    {
        return Err(receipt_invalid());
    }
    let records = decoded
        .get("records")
        .and_then(Value::as_array)
        .filter(|records| records.len() <= MAX_RECEIPTS)
        .ok_or_else(receipt_invalid)?;
    let mut loaded = Vec::new();
    for record in records {
        let record = record.as_object().ok_or_else(receipt_invalid)?;
        let operation_id = record
            .get("operationId")
            .map(|value| {
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_owned)
            })
            .and_then(|text| contract::lenient_uuid(&text))
            .ok_or_else(receipt_invalid)?;
        let snapshot = contract::validate(record.get("snapshot").unwrap_or(&Value::Null), false)
            .map_err(|_| receipt_invalid())?;
        if snapshot["operationId"].as_str() != Some(operation_id.as_str()) {
            return Err(receipt_invalid());
        }
        loaded.push((operation_id, snapshot));
    }
    Ok(loaded)
}

fn load_receipt(home: &Path, operation_id: &str) -> Stored<Option<Value>> {
    Ok(load_receipt_records(home)?
        .into_iter()
        .find(|(id, _)| id == operation_id)
        .map(|(_, snapshot)| snapshot))
}

fn persist_receipt(home: &Path, snapshot: &Value) -> Stored<()> {
    let operation_id = snapshot["operationId"].as_str().unwrap_or("").to_owned();
    let mut records: Vec<(String, Value)> = load_receipt_records(home)?
        .into_iter()
        .filter(|(id, _)| *id != operation_id)
        .collect();
    records.push((operation_id, snapshot.clone()));
    let excess = records.len().saturating_sub(MAX_RECEIPTS);
    records.drain(..excess);
    let key = home_key(home);
    loop {
        let body: Vec<Value> = records
            .iter()
            .map(|(id, snapshot)| json!({"operationId": id, "snapshot": snapshot}))
            .collect();
        let encoded = contract::encode(&json!({
            "schema": RECEIPT_SCHEMA,
            "homeKey": key,
            "records": body,
        }));
        if encoded.len() <= MAX_RECEIPT_BYTES || records.len() <= 1 {
            return write_state(home, RECEIPT_NAME, &encoded, MAX_RECEIPT_BYTES as u64);
        }
        records.remove(0);
    }
}

fn persist_snapshot(home: &Path, snapshot: &Value, now: &str) -> Stored<()> {
    let validated = contract::validate(snapshot, false).map_err(contract_fail)?;
    let phase = validated["phase"].as_str().unwrap_or("");
    if RECEIPT_PHASES.contains(&phase) {
        persist_receipt(home, &validated)?;
    }
    let mut payload = contract::encode(&validated);
    payload.push(b'\n');
    write_state(home, STATE_NAME, &payload, MAX_STATE_BYTES)?;
    // Diagnostics are best effort and never change the recovery outcome.
    let _ = (|| -> Stored<Value> {
        let previous = with_diagnostics_lock(home, || prune(home, load_archive(home)?, now))?.pop();
        let mut events = match previous {
            Some(report) if report["operationId"] == validated["operationId"] => {
                report["events"].as_array().cloned().unwrap_or_default()
            }
            _ => Vec::new(),
        };
        events.push(validated.clone());
        persist_diagnostics(home, &Value::Array(events), now, now)
    })();
    Ok(())
}

fn load_latest(home: &Path) -> Stored<Option<Value>> {
    let Some(payload) = read_state(home, STATE_NAME, MAX_STATE_BYTES)? else {
        return Ok(None);
    };
    serde_json::from_slice::<Value>(&payload)
        .ok()
        .and_then(|decoded| contract::validate(&decoded, false).ok())
        .map(Some)
        .ok_or_else(|| fail("state", "recovery_state_invalid"))
}

fn load_snapshot(home: &Path, operation_id: &str) -> Stored<Value> {
    if let Some(snapshot) = load_latest(home)? {
        if snapshot["operationId"].as_str() == Some(operation_id) {
            return Ok(snapshot);
        }
    }
    load_receipt(home, operation_id)?.ok_or_else(|| fail("missing", operation_id))
}

/// The archive is an optional projection of the operation record: when it is
/// missing, malformed or unreadable, rebuild a report from that record.
fn load_diagnostics(home: &Path, operation_id: &str, now: &str) -> Stored<Value> {
    if let Ok(report) = report_for(home, operation_id, now) {
        return Ok(report);
    }
    let snapshot = load_snapshot(home, operation_id)?;
    let events = Value::Array(vec![snapshot]);
    let report = contract::build_report(&events, now).map_err(contract_fail)?;
    let _ = persist_diagnostics(home, &events, now, now);
    Ok(report)
}

fn with_diagnostics_lock<T>(home: &Path, body: impl FnOnce() -> Stored<T>) -> Stored<T> {
    let path = home.join(DIAGNOSTICS_LOCK_NAME);
    #[cfg(not(windows))]
    let lock = crate::resident_state::private_lock_file(&path, home).map_err(|_| storage())?;
    #[cfg(windows)]
    let (lock, _binding) =
        crate::resident_state::private_lock_file(&path, home).map_err(|_| storage())?;
    crate::resident_state::try_lock_exclusive_briefly(&lock).map_err(|_| storage())?;
    let result = body();
    let _ = fs2::FileExt::unlock(&lock);
    result
}

fn state_invalid() -> Fail {
    fail("diagnostics", "recovery_diagnostics_state_invalid")
}

fn load_archive(home: &Path) -> Stored<Vec<Value>> {
    let Some(payload) = read_state(home, DIAGNOSTICS_NAME, MAX_DIAGNOSTICS_BYTES as u64)? else {
        return Ok(Vec::new());
    };
    let decoded: Value = serde_json::from_slice(&payload).map_err(|_| state_invalid())?;
    // Accept the pre-archive single-report file as a one-entry archive.
    if decoded.get("schema").and_then(Value::as_str) == Some(DIAGNOSTICS_SCHEMA) {
        return Ok(vec![
            contract::validate_report(&decoded).map_err(contract_fail)?
        ]);
    }
    let map = decoded
        .as_object()
        .filter(|map| map.len() == 2 && map.contains_key("schema") && map.contains_key("reports"))
        .ok_or_else(state_invalid)?;
    let reports = map
        .get("reports")
        .and_then(Value::as_array)
        .filter(|_| map.get("schema").and_then(Value::as_str) == Some(ARCHIVE_SCHEMA))
        .ok_or_else(state_invalid)?;
    reports
        .iter()
        .map(|report| contract::validate_report(report).map_err(|_| state_invalid()))
        .collect()
}

fn encode_archive(reports: &[Value]) -> Stored<Vec<u8>> {
    let payload = contract::encode(&json!({"schema": ARCHIVE_SCHEMA, "reports": reports}));
    if payload.len() > MAX_DIAGNOSTICS_BYTES {
        return Err(fail(
            "diagnostics",
            "recovery_diagnostics_archive_too_large",
        ));
    }
    Ok(payload)
}

fn sort_key(report: &Value) -> (i128, String) {
    let at = report["generatedAt"]
        .as_str()
        .and_then(crate::guard_store_json::aware_epoch_micros)
        .unwrap_or(i128::MIN);
    (at, report["operationId"].as_str().unwrap_or("").to_owned())
}

fn prune(home: &Path, reports: Vec<Value>, now: &str) -> Stored<Vec<Value>> {
    let now = crate::guard_store_json::aware_epoch_micros(now)
        .ok_or_else(|| fail("diagnostics", "recovery_diagnostics_timestamp_invalid"))?;
    let cutoff = now - RETENTION_MICROS;
    let total = reports.len();
    let mut retained: Vec<Value> = reports
        .into_iter()
        .filter(|report| sort_key(report).0 >= cutoff)
        .collect();
    retained.sort_by_key(sort_key);
    if retained.len() != total {
        // Compaction is optional during reads; the in-memory view stays usable.
        if let Ok(payload) = encode_archive(&retained) {
            let _ = write_state(
                home,
                DIAGNOSTICS_NAME,
                &payload,
                MAX_DIAGNOSTICS_BYTES as u64,
            );
        }
    }
    Ok(retained)
}

fn persist_diagnostics(
    home: &Path,
    snapshots: &Value,
    generated: &str,
    now: &str,
) -> Stored<Value> {
    let report = contract::build_report(snapshots, generated).map_err(contract_fail)?;
    with_diagnostics_lock(home, || {
        let mut reports: Vec<Value> = prune(home, load_archive(home)?, now)?
            .into_iter()
            .filter(|candidate| candidate["operationId"] != report["operationId"])
            .collect();
        reports.push(report.clone());
        reports.sort_by_key(sort_key);
        let excess = reports.len().saturating_sub(MAX_RETAINED_INCIDENTS);
        reports.drain(..excess);
        let payload = loop {
            match encode_archive(&reports) {
                Ok(payload) => break payload,
                Err(error) if reports.len() > 1 => {
                    let _ = error;
                    reports.remove(0);
                }
                Err(error) => return Err(error),
            }
        };
        write_state(
            home,
            DIAGNOSTICS_NAME,
            &payload,
            MAX_DIAGNOSTICS_BYTES as u64,
        )
    })?;
    Ok(report)
}

fn report_for(home: &Path, operation_id: &str, now: &str) -> Stored<Value> {
    let reports = with_diagnostics_lock(home, || prune(home, load_archive(home)?, now))?;
    reports
        .into_iter()
        .rev()
        .find(|report| report["operationId"].as_str() == Some(operation_id))
        .ok_or_else(|| fail("missing", operation_id))
}

#[cfg(test)]
#[path = "daemon_recovery_store_tests.rs"]
mod tests;
