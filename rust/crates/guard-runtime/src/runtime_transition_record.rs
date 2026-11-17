//! `runtime-transition-record --stdin`: the signed runtime transition
//! journal and its not-started refusal receipts.
//!
//! The runtime signs, encodes, writes, reads and authenticates every record
//! under `<guard home>/managed`, and checks each opened record's shape. The
//! caller still holds the install lock and the policy integrity key, which
//! lives in the platform secret store, and passes the key for each call.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_policy_snapshot::local_authority_integrity::{
    sign_local_authority_payload, verify_local_authority_payload,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

#[path = "runtime_transition_record_shape.rs"]
mod shape;

#[path = "runtime_transition_phase.rs"]
mod phase;

#[path = "runtime_transition_begin.rs"]
mod begin;

#[path = "runtime_transition_plan.rs"]
mod plan;

use crate::codex_hook_authority_record::python_json::{parse_python_json, python_canonical_json};
use shape::{validate_record, Refusal};

/// `TransitionFile.payload`: one planned change a transition may record.
pub(crate) fn check_change(change: &Map<String, Value>) -> Result<(), (String, Option<String>)> {
    plan::one(change)
}

pub(crate) use plan::check_files;

const SCHEMA: &str = "runtime-transition-record.v1";
const RECORD_SCHEMA: &str = "hol-guard.runtime-transition.v1";
const PURPOSE: &str = "guard-runtime-transition-inverse";
const REFUSAL_SCHEMA: &str = "hol-guard.runtime-transition-not-started.v1";
const REFUSAL_PURPOSE: &str = "guard-runtime-transition-not-started";
const MAX_RECORD: usize = 32 * 1024 * 1024;
const MAX_REFUSAL: usize = 4096;
const MAX_REFUSALS: usize = 128;
const MAX_KEY_BYTES: usize = 1024;
const MAX_REQUEST_BYTES: u64 = 40 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    guard_home: String,
    integrity_key_b64: Option<String>,
    integrity_key_id: Option<String>,
    operation_id: Option<String>,
    payload: Option<Map<String, Value>>,
    previous: Option<bool>,
    artifact_generation: Option<String>,
    reason_code: Option<String>,
    deadline_seconds: Option<f64>,
    step: Option<String>,
    expected_phase: Option<String>,
    owner: Option<Value>,
    now: Option<f64>,
    observation: Option<Value>,
    first_cause: Option<String>,
    cause: Option<Value>,
    side: Option<String>,
    action: Option<String>,
    subject: Option<String>,
    now_epoch: Option<f64>,
    deadline_monotonic: Option<f64>,
    grant_expires_epoch: Option<f64>,
    approval_required: Option<bool>,
    installer_operation_id: Option<String>,
}

struct Key {
    bytes: Zeroizing<Vec<u8>>,
    id: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "runtime-transition-record"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "runtime_transition_record_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("runtime_transition_record_request_too_large".to_owned());
    }
    let answer = match serde_json::from_slice::<Request>(&bytes) {
        Ok(request) if request.schema == SCHEMA => answer(&request),
        _ => refused(("invalid".to_owned(), None)),
    };
    serde_json::to_vec(&answer).map_err(|_| "runtime_transition_record_answer_failed".to_owned())
}

fn answer(request: &Request) -> Value {
    let outcome = match request.op.as_str() {
        "write" => request
            .payload
            .as_ref()
            .ok_or_else(|| no("invalid"))
            .and_then(|payload| write_record(request, payload))
            .map(|()| json!({"ok": true})),
        "step_check" => phase::check(request),
        "step_commit" => phase::commit(request),
        "begin_check" => begin::check(request),
        "begin_commit" => begin::commit(request),
        "plan_check" => plan::subject(request),
        "files_check" => plan::files(request),
        "files_check_each" => plan::each(request),
        "read" => read_record(request).map(|payload| json!({"payload": payload})),
        "retire" => retire(request).map(|()| json!({"ok": true})),
        "refusal_write" => write_refusal(request).map(|()| json!({"ok": true})),
        "refusal_read" => read_refusal(request),
        _ => Err(("invalid".to_owned(), None)),
    };
    outcome.unwrap_or_else(refused)
}

fn refused((reason, detail): Refusal) -> Value {
    match detail {
        Some(detail) => json!({"error": reason, "detail": detail}),
        None => json!({"error": reason}),
    }
}

fn no(reason: &str) -> Refusal {
    (reason.to_owned(), None)
}

fn managed(request: &Request) -> Result<PathBuf, Refusal> {
    let home = Path::new(&request.guard_home);
    if !home.is_absolute() {
        return Err(no("invalid"));
    }
    Ok(home.join("managed"))
}

fn journal(request: &Request) -> Result<PathBuf, Refusal> {
    Ok(managed(request)?.join("runtime-transition.json"))
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn key(request: &Request) -> Result<Key, Refusal> {
    let (Some(encoded), Some(id)) = (&request.integrity_key_b64, &request.integrity_key_id) else {
        return Err(no("signing_authority_unavailable"));
    };
    let bytes = Base64UrlUnpadded::decode_vec(encoded)
        .map(Zeroizing::new)
        .map_err(|_| no("signing_authority_unavailable"))?;
    if bytes.is_empty() || bytes.len() > MAX_KEY_BYTES || id.is_empty() {
        return Err(no("signing_authority_unavailable"));
    }
    Ok(Key {
        bytes,
        id: id.clone(),
    })
}

fn deadline(request: &Request) -> Result<Option<Instant>, Refusal> {
    match request.deadline_seconds {
        None => Ok(None),
        Some(seconds) if seconds.is_finite() && seconds > 0.0 => Ok(Some(
            Instant::now() + Duration::from_secs_f64(seconds.min(86_400.0)),
        )),
        Some(_) => Err(no("deadline_exceeded")),
    }
}

fn before(deadline: Option<Instant>) -> Result<(), Refusal> {
    match deadline {
        Some(deadline) if Instant::now() >= deadline => Err(no("deadline_exceeded")),
        _ => Ok(()),
    }
}

/// Sign `payload` and return its canonical text with a trailing newline.
fn sealed(
    payload: &Map<String, Value>,
    key: &Key,
    purpose: &str,
    signed_at: &str,
    unavailable: &str,
) -> Result<String, Refusal> {
    let fields = sign_local_authority_payload(
        &Value::Object(payload.clone()),
        &key.bytes,
        &key.id,
        purpose,
        signed_at,
    )
    .map_err(|_| no(unavailable))?;
    let mut signed = payload.clone();
    signed.insert(
        "authentication".to_owned(),
        json!({
            "integrity_version": fields.integrity_version,
            "payload_hash": fields.payload_hash,
            "payload_mac": fields.payload_mac,
            "integrity_key_id": fields.integrity_key_id,
            "signed_at": fields.signed_at,
        }),
    );
    let mut text = python_canonical_json(&Value::Object(signed)).ok_or_else(|| no("invalid"))?;
    text.push('\n');
    Ok(text)
}

/// Parse and authenticate a signed record; return it without its signature.
fn opened(
    raw: &str,
    key: &Key,
    purpose: &str,
    (invalid, unauthenticated): (&str, &str),
) -> Result<Map<String, Value>, Refusal> {
    let (value, nonfinite) = parse_python_json(raw).map_err(|_| no(invalid))?;
    let Value::Object(mut payload) = value else {
        return Err(no(invalid));
    };
    let integrity = payload.remove("authentication");
    let valid = !nonfinite
        && integrity.as_ref().is_some_and(Value::is_object)
        && verify_local_authority_payload(
            &Value::Object(payload.clone()),
            integrity.as_ref().unwrap_or(&Value::Null),
            Some(&key.bytes),
            Some(&key.id),
            purpose,
        )
        .status
            == "valid";
    if !valid {
        return Err(no(unauthenticated));
    }
    Ok(payload)
}

fn read_text(path: &Path, maximum: usize) -> Option<String> {
    crate::daemon_policy_authority::read_private_regular_text(path, maximum as u64, false)
}

/// `RuntimeTransition._write`: sign the journal and replace it atomically.
fn write_record(request: &Request, payload: &Map<String, Value>) -> Result<(), Refusal> {
    let deadline = deadline(request)?;
    let key = key(request)?;
    let operation = payload
        .get("operation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| no("invalid"))?;
    let text = sealed(
        payload,
        &key,
        PURPOSE,
        operation,
        "local_authority_integrity_runtime_unavailable",
    )?;
    before(deadline)?;
    if text.len() > MAX_RECORD {
        return Err(no("record_too_large"));
    }
    let path = journal(request)?;
    let parent = path.parent().ok_or_else(|| no("invalid"))?;
    crate::daemon_edge::standalone::ensure_private_directory(parent)
        .map_err(|_| no("record_write_failed"))?;
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.is_file() {
            return Err(no("codex_hook_transaction_target_not_regular"));
        }
    }
    crate::daemon_edge::standalone::write_private_atomic(&path, text.as_bytes())
        .map_err(|_| no("record_write_failed"))
}

/// `RuntimeTransition._read_record`: authenticate the journal, or its retired
/// copy, for this home and operation, and check every field it carries.
fn read_record(request: &Request) -> Result<Map<String, Value>, Refusal> {
    let operation = request
        .operation_id
        .as_deref()
        .ok_or_else(|| no("invalid"))?;
    let current = journal(request)?;
    let path = if request.previous == Some(true) {
        current.with_file_name("runtime-transition.previous.json")
    } else {
        current
    };
    let raw = read_text(&path, MAX_RECORD).ok_or_else(|| no("record_unavailable"))?;
    let key = key(request)?;
    let payload = opened(
        &raw,
        &key,
        PURPOSE,
        ("record_invalid", "record_unauthenticated"),
    )?;
    let text = |name: &str| payload.get(name).and_then(Value::as_str);
    if text("schema") != Some(RECORD_SCHEMA) || text("guard_home") != Some(&request.guard_home) {
        return Err(no("record_context_mismatch"));
    }
    if text("operation_id") != Some(operation) {
        return Err(no("operation_superseded"));
    }
    validate_record(&payload, python_canonical_json)?;
    Ok(payload)
}

/// `RuntimeTransition.retire`: keep one private terminal receipt.
fn retire(request: &Request) -> Result<(), Refusal> {
    let current = journal(request)?;
    let previous = current.with_file_name("runtime-transition.previous.json");
    if exists(&previous) && read_text(&previous, MAX_RECORD).is_none() {
        return Err(no("previous_record_unsafe"));
    }
    fs::rename(&current, &previous).map_err(|_| no("record_retire_failed"))?;
    sync_directory(previous.parent());
    Ok(())
}

/// `str(uuid.UUID(value)) == value`: the canonical lowercase spelling.
fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn refusal_path(request: &Request) -> Result<PathBuf, Refusal> {
    let operation = request.operation_id.as_deref().unwrap_or_default();
    if !canonical_uuid(operation) {
        return Err(no("operation_id_invalid"));
    }
    Ok(managed(request)?
        .join("runtime-refusals")
        .join(format!("{operation}.json")))
}

/// `record_approval_refusal`: one create-only receipt that a transition
/// was refused before it began. It never grants anything.
fn write_refusal(request: &Request) -> Result<(), Refusal> {
    let deadline = deadline(request)?.ok_or_else(|| no("invalid"))?;
    let reason = request.reason_code.as_deref().unwrap_or_default();
    if !reason_code(reason) {
        return Err(no("refusal_context_invalid"));
    }
    if exists(&journal(request)?) {
        return Err(no("pending_transition"));
    }
    let path = refusal_path(request)?;
    let key = key(request)?;
    let operation = request.operation_id.clone().unwrap_or_default();
    let generation = request
        .artifact_generation
        .clone()
        .ok_or_else(|| no("invalid"))?;
    let mut payload = Map::new();
    payload.insert("schema".to_owned(), json!(REFUSAL_SCHEMA));
    payload.insert("guard_home".to_owned(), json!(request.guard_home));
    payload.insert("operation_id".to_owned(), json!(operation));
    payload.insert("artifact_generation".to_owned(), json!(generation));
    payload.insert("reason_code".to_owned(), json!(reason));
    let text = sealed(
        &payload,
        &key,
        REFUSAL_PURPOSE,
        &operation,
        "refusal_write_failed",
    )?;
    if text.len() > MAX_REFUSAL {
        return Err(no("refusal_capacity"));
    }
    let parent = path.parent().ok_or_else(|| no("invalid"))?;
    private_refusal_directory(parent)?;
    let count = fs::read_dir(parent)
        .map_err(|_| no("refusal_directory_unsafe"))?
        .take(MAX_REFUSALS + 1)
        .count();
    if count >= MAX_REFUSALS {
        return Err(no("refusal_capacity"));
    }
    before(Some(deadline))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&path).map_err(|error| match error.kind() {
        std::io::ErrorKind::AlreadyExists => no("refusal_exists"),
        _ => no("refusal_write_failed"),
    })?;
    for chunk in text.as_bytes().chunks(64 * 1024) {
        before(Some(deadline))?;
        file.write_all(chunk)
            .map_err(|_| no("refusal_write_failed"))?;
    }
    file.sync_all().map_err(|_| no("refusal_write_failed"))?;
    drop(file);
    sync_directory(Some(parent));
    Ok(())
}

/// The refusal directory: created private, a real directory at its own
/// canonical path, owned by this user and closed to everyone else.
fn private_refusal_directory(directory: &Path) -> Result<(), Refusal> {
    let unsafe_directory = || no("refusal_directory_unsafe");
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory).map_err(|_| unsafe_directory())?;
    let metadata = fs::symlink_metadata(directory).map_err(|_| unsafe_directory())?;
    let canonical = fs::canonicalize(directory).map_err(|_| unsafe_directory())?;
    if canonical != directory || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unsafe_directory());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != nix::unistd::getuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(unsafe_directory());
        }
    }
    Ok(())
}

/// `refusal_status`: the authenticated receipt's generation and reason.
fn read_refusal(request: &Request) -> Result<Value, Refusal> {
    if exists(&journal(request)?) {
        return Err(no("pending_transition"));
    }
    let path = refusal_path(request)?;
    let raw = read_text(&path, MAX_REFUSAL).ok_or_else(|| no("record_unavailable"))?;
    let key = key(request)?;
    let payload = opened(
        &raw,
        &key,
        REFUSAL_PURPOSE,
        ("refusal_invalid", "refusal_unauthenticated"),
    )?;
    let text = |name: &str| payload.get(name).and_then(Value::as_str);
    let shaped = payload.len() == 5
        && text("schema") == Some(REFUSAL_SCHEMA)
        && text("guard_home") == Some(&request.guard_home)
        && text("operation_id") == request.operation_id.as_deref()
        && shape::lower_hex_64(payload.get("artifact_generation"))
        && text("reason_code").is_some_and(reason_code);
    if !shaped {
        return Err(no("refusal_context_invalid"));
    }
    Ok(json!({
        "artifact_generation": payload["artifact_generation"],
        "reason_code": payload["reason_code"],
    }))
}

/// `fsync_directory`: make a rename or create durable; best effort.
fn sync_directory(directory: Option<&Path>) {
    #[cfg(unix)]
    if let Some(directory) = directory {
        if let Ok(handle) = fs::File::open(directory) {
            let _ = handle.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = directory;
}

#[cfg(all(test, unix))]
#[path = "runtime_transition_record_tests.rs"]
mod tests;
