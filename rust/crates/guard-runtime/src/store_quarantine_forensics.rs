//! `store-quarantine-forensics --stdin`: the owner-only record Guard keeps
//! for each SQLite store it quarantines (`sqlite_quarantine_forensics.py`).
//!
//! - `record` writes the record before the store files move: the facts the
//!   store gathered (error, probe, file identities, versions), the error
//!   message with the Guard home redacted, whether the linked SQLite predates
//!   the WAL-reset fix, and a diagnosis of the store's first page;
//! - `outcome` adds the recovery outcome afterwards, keeping what the record
//!   already holds.
//!
//! Records carry no absolute paths, so they are safe to retain indefinitely.
//! Each write lands through an owner-only temporary file and a rename.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Map, Value};

const SCHEMA: &str = "store-quarantine-forensics.v1";
const RECORD_SCHEMA: &str = "guard.store-quarantine-forensics.v1";
const RECORD_SUFFIX: &str = ".forensics.json";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const MESSAGE_LIMIT: usize = 500;
const MAX_ID_BYTES: usize = 64;
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// SQLite 3.7.0 through 3.51.2 can corrupt a WAL database when several
/// connections write and checkpoint concurrently (the "WAL-reset" bug).
const WAL_RESET_BUG_FIXED_IN: [u64; 3] = [3, 51, 3];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    guard_home: String,
    quarantine_id: String,
    #[serde(default)]
    record: Option<Facts>,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    salvage: Option<Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Facts {
    store_path: Option<String>,
    quarantined_at: String,
    error_class: String,
    error_message: String,
    sqlite_errorcode: Option<i64>,
    sqlite_errorname: Option<String>,
    probe: Option<Map<String, Value>>,
    files: Map<String, Value>,
    pid: i64,
    guard_version: String,
    sqlite_version: String,
    process: Option<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "store-quarantine-forensics"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "store_quarantine_forensics_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("store_quarantine_forensics_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if request.schema != SCHEMA
        || request.guard_home.is_empty()
        || !quarantine_id_is_valid(&request.quarantine_id)
    {
        return Err(invalid());
    }
    let path = record_path(Path::new(&request.guard_home), &request.quarantine_id);
    let payload = match (request.op.as_str(), request.record, request.outcome) {
        ("record", Some(facts), None) if request.salvage.is_none() => {
            record(&request.guard_home, &request.quarantine_id, facts)
        }
        ("outcome", None, Some(outcome)) => {
            with_outcome(&path, &request.quarantine_id, outcome, request.salvage)
        }
        _ => return Err(invalid()),
    };
    write_owner_only(&path, &Value::Object(payload))
        .map_err(|_| "store_quarantine_forensics_write_failed".to_owned())?;
    Ok(json!({ "written": true }).to_string().into_bytes())
}

fn invalid() -> String {
    "store_quarantine_forensics_request_invalid".to_owned()
}

/// Quarantine ids name a file beside the store, so they are one plain name.
fn quarantine_id_is_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn record_path(guard_home: &Path, quarantine_id: &str) -> PathBuf {
    guard_home.join(format!("guard.db.corrupt-{quarantine_id}{RECORD_SUFFIX}"))
}

fn record(guard_home: &str, quarantine_id: &str, facts: Facts) -> Map<String, Value> {
    let message: String = facts
        .error_message
        .replace(guard_home, "<guard_home>")
        .chars()
        .take(MESSAGE_LIMIT)
        .collect();
    let mut payload = Map::new();
    payload.insert("schema".into(), json!(RECORD_SCHEMA));
    payload.insert("quarantine_id".into(), json!(quarantine_id));
    payload.insert("quarantined_at".into(), json!(facts.quarantined_at));
    payload.insert("error_class".into(), json!(facts.error_class));
    payload.insert("error_message".into(), json!(message));
    payload.insert("probe".into(), json!(facts.probe));
    payload.insert("files".into(), Value::Object(facts.files));
    payload.insert("pid".into(), json!(facts.pid));
    payload.insert("guard_version".into(), json!(facts.guard_version));
    payload.insert(
        "sqlite_wal_reset_bug_possible".into(),
        json!(wal_reset_bug_possible(&facts.sqlite_version)),
    );
    payload.insert("sqlite_version".into(), json!(facts.sqlite_version));
    if let Some(store_path) = facts.store_path.filter(|path| !path.is_empty()) {
        let header = header_diagnosis(Path::new(&store_path));
        if !header.is_empty() {
            payload.insert("header".into(), Value::Object(header));
        }
    }
    if let Some(code) = facts.sqlite_errorcode {
        payload.insert("sqlite_errorcode".into(), json!(code));
    }
    if let Some(name) = facts.sqlite_errorname {
        payload.insert("sqlite_errorname".into(), json!(name));
    }
    if let Some(process) = facts.process {
        payload.insert("process".into(), json!(process));
    }
    payload
}

/// True when `version` predates the WAL-reset fix. A version that does not
/// read as dotted numbers cannot be shown to carry the fix.
pub(crate) fn wal_reset_bug_possible(version: &str) -> bool {
    let parts: Option<Vec<u64>> = version.split('.').map(|part| part.parse().ok()).collect();
    parts.is_none_or(|parts| parts.as_slice() < WAL_RESET_BUG_FIXED_IN.as_slice())
}

/// Classify the store's first page without recording any of its content.
///
/// Tells a store whose page 1 was overwritten by another page (a stray write
/// or a stale WAL checkpoint) from a truncated, zeroed or foreign file. Only
/// the magic match, a page-kind label and sizes are returned; a store that is
/// missing, a symlink or unreadable yields nothing.
pub(crate) fn header_diagnosis(path: &Path) -> Map<String, Value> {
    let mut diagnosis = Map::new();
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return diagnosis;
    };
    if !metadata.is_file() {
        return diagnosis;
    }
    let mut head = Vec::with_capacity(100);
    let Ok(file) = File::open(path) else {
        return diagnosis;
    };
    if file.take(100).read_to_end(&mut head).is_err() {
        return diagnosis;
    }
    let size = metadata.len();
    let magic_ok = head.starts_with(SQLITE_MAGIC);
    diagnosis.insert("file_size".into(), json!(size));
    diagnosis.insert("header_magic_ok".into(), json!(magic_ok));
    if !head.is_empty() && head.iter().all(|byte| *byte == 0) {
        diagnosis.insert("header_zeroed".into(), json!(true));
    }
    if head.len() >= 100 && magic_ok {
        let raw = u64::from(u16::from_be_bytes([head[16], head[17]]));
        let page_size = if raw == 1 { 65536 } else { raw };
        diagnosis.insert("page_size_field".into(), json!(page_size));
        if (512..=65536).contains(&page_size) && page_size.is_power_of_two() {
            diagnosis.insert("size_multiple_of_page".into(), json!(size % page_size == 0));
        }
        diagnosis.insert(
            "wal_mode_header".into(),
            json!(head[18] == 2 && head[19] == 2),
        );
    }
    if !magic_ok {
        let kind = match head.first() {
            Some(0x02) => Some("interior-index"),
            Some(0x05) => Some("interior-table"),
            Some(0x0A) => Some("leaf-index"),
            Some(0x0D) => Some("leaf-table"),
            _ => None,
        };
        if let Some(kind) = kind {
            diagnosis.insert("page1_looks_like_btree_page".into(), json!(kind));
        }
    }
    diagnosis
}

/// The existing record with `outcome` (and `salvage`, when any) added. A
/// record that is missing, unreadable or not an object starts over.
fn with_outcome(
    path: &Path,
    quarantine_id: &str,
    outcome: String,
    salvage: Option<Map<String, Value>>,
) -> Map<String, Value> {
    let mut payload = read_record(path).unwrap_or_default();
    payload
        .entry("schema")
        .or_insert_with(|| json!(RECORD_SCHEMA));
    payload
        .entry("quarantine_id")
        .or_insert_with(|| json!(quarantine_id));
    payload.insert("outcome".into(), json!(outcome));
    if let Some(salvage) = salvage.filter(|salvage| !salvage.is_empty()) {
        payload.insert("salvage".into(), Value::Object(salvage));
    }
    payload
}

fn read_record(path: &Path) -> Option<Map<String, Value>> {
    if !fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return None;
    }
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// Write `payload` as one canonical JSON line through a new owner-only
/// temporary file beside `path`, then rename it into place.
fn write_owner_only(path: &Path, payload: &Value) -> std::io::Result<()> {
    let mut text = Vec::new();
    guard_contracts::write_canonical_json_with_limit(
        payload,
        &mut text,
        MAX_RECORD_BYTES as usize,
        "store_quarantine_forensics_record_too_large",
    )
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    text.push(b'\n');
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| std::io::Error::other("random"))?;
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", hex::encode(nonce)));
    let written = write_new_private(&temporary, &text).and_then(|()| fs::rename(&temporary, path));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
#[path = "store_quarantine_forensics_tests.rs"]
mod tests;
