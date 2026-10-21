//! The evidence writer's correlation seam: the per-install HMAC key and the
//! proven request handle derived from it.
//!
//! Ports `runtime/command_activity_correlation.py` and the two privacy types
//! it derives through (`InstallationCorrelationKey`, `StrongHarnessIdentifier`
//! in `runtime/command_activity_privacy.py`). The key never leaves this
//! process in readable form: it is written once with private permissions, and
//! only the keyed digest reaches a record.
//!
//! Like the Composio seam, this lives in `guard-runtime` rather than beside
//! the writer in `guard-command`, because it needs the harness registry.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use guard_command::hook_evidence_writer::{CorrelationHandle, InstallationCorrelationKey};
use guard_contracts::write_canonical_json;
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::encrypted_secret_store::random_bytes;
use crate::guard_config_harness::canonical_harness_id;

type HmacSha256 = Hmac<Sha256>;

/// `COMMAND_ACTIVITY_CORRELATION_KEY_FILE` (:28).
pub(crate) const CORRELATION_KEY_FILE: &str = "command-activity-correlation-key.json";
/// `COMMAND_ACTIVITY_CORRELATION_KEY_SCHEMA_VERSION` (:27).
const KEY_SCHEMA_VERSION: &str = "guard.command-activity-correlation-key.v1";
/// `COMMAND_ACTIVITY_CORRELATION_VERSION` (privacy :30).
const CORRELATION_VERSION: &str = "guard.command-activity-correlation.v1";
/// `COMMAND_ACTIVITY_SCHEMA_VERSION` (contract :18).
const ACTIVITY_SCHEMA_VERSION: &str = "1.0.0";
const KEY_BYTES: usize = 32;
#[cfg_attr(not(unix), allow(dead_code))]
const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg_attr(not(unix), allow(dead_code))]
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const MAX_KEY_FILE_BYTES: u64 = 4096;

/// `_PROVEN_REQUEST_ID_FIELDS` (:35-55). Only a native, top-level request id
/// documented by a harness adapter can pair pre- and post-execution evidence.
const PROVEN_REQUEST_ID_FIELDS: [(&str, &str, &str); 19] = [
    ("grok", "PreToolUse", "toolUseId"),
    ("grok", "PostToolUse", "toolUseId"),
    ("grok", "PostToolUseFailure", "toolUseId"),
    ("zcode", "PreToolUse", "tool_use_id"),
    ("zcode", "PostToolUse", "tool_use_id"),
    ("zcode", "PostToolUseFailure", "tool_use_id"),
    ("codex", "PreToolUse", "tool_call_id"),
    ("codex", "PostToolUse", "tool_call_id"),
    ("codex", "PostToolUseFailure", "tool_call_id"),
    ("claude-code", "PreToolUse", "tool_use_id"),
    ("claude-code", "PostToolUse", "tool_use_id"),
    ("claude-code", "PostToolUseFailure", "tool_use_id"),
    ("cursor", "PreToolUse", "generation_id"),
    ("cursor", "afterShellExecution", "generation_id"),
    ("cursor", "afterMCPExecution", "generation_id"),
    ("pi", "PreToolUse", "tool_call_id"),
    ("pi", "PostToolUse", "tool_call_id"),
    ("omp", "PreToolUse", "tool_call_id"),
    ("omp", "PostToolUse", "tool_call_id"),
];

/// `load_or_create_installation_correlation_key` (:58-79).
///
/// One key per install. A reader that finds the file keeps it; a writer that
/// loses the race to create it reads the winner's key, so two processes
/// starting together still derive the same handles.
pub(crate) fn load_or_create_correlation_key(
    guard_home: &Path,
) -> io::Result<InstallationCorrelationKey> {
    let key_path = prepare_key_path(guard_home)?;
    match read_key(&key_path) {
        Ok(key) => return Ok(key),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let (key_id, material) = new_key();
    let temporary = write_private_temporary(&key_path, &serialize_key(&key_id, &material))?;
    let created = match fs::hard_link(&temporary, &key_path) {
        Ok(()) => {
            set_private_mode(&key_path);
            fsync_directory(key_path.parent());
            InstallationCorrelationKey::new(&key_id, &material)
        }
        // Another process created the key between the read and the link.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_key(&key_path),
        Err(error) => Err(error),
    };
    let _ = fs::remove_file(&temporary);
    created
}

/// `derive_proven_request_correlation` (:98-130).
///
/// `Ok(None)` is the answer for every call the adapters do not document a
/// request id for; `Err` is the Python `ValueError`, which makes the writer
/// reload the key once before it gives up on the record.
pub(crate) fn derive_proven_request_correlation(
    harness: &str,
    event: &str,
    payload: &Map<String, Value>,
    key: &InstallationCorrelationKey,
) -> io::Result<Option<CorrelationHandle>> {
    let Some((_, _, field)) = PROVEN_REQUEST_ID_FIELDS
        .iter()
        .find(|(known_harness, known_event, _)| *known_harness == harness && *known_event == event)
    else {
        return Ok(None);
    };
    // Cursor's pre-tool payload is synthesized from two source hooks, and only
    // those two carry the generation id this handle claims to prove.
    if harness == "cursor"
        && event == "PreToolUse"
        && !matches!(
            payload
                .get("cursor_source_hook_event")
                .and_then(Value::as_str),
            Some("beforeShellExecution") | Some("beforeMCPExecution")
        )
    {
        return Ok(None);
    }
    let value = match payload.get(*field) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(value)) => value,
        Some(_) => {
            return Err(invalid(&format!(
                "{harness} {event} {field} must be an exact string"
            )))
        }
    };
    let framed = frame_identifier(harness, "request", value, &key.key_id)?;
    Ok(Some(CorrelationHandle {
        kind: "request".to_owned(),
        harness: harness.to_owned(),
        key_id: key.key_id.clone(),
        digest: hmac_hex(key.material(), &framed),
    }))
}

/// `StrongHarnessIdentifier.__init__` + `.derive` (privacy :153-186).
fn frame_identifier(harness: &str, kind: &str, value: &str, key_id: &str) -> io::Result<Vec<u8>> {
    if canonical_harness_id(harness) != Some(harness) {
        return Err(invalid("harness must identify a supported Guard harness"));
    }
    if !opaque_strong_identifier(value) {
        return Err(invalid(
            "strong harness identifier must be a bounded opaque native identifier",
        ));
    }
    // A counter or a timestamp is guessable, so a handle derived from one
    // would let anyone holding the record re-derive the raw identifier.
    if weak_identifier(value) || iso_timestamp(value) || alphabet_size(value) < 6 {
        return Err(invalid(
            "predictable counters and timestamps are not strong harness identifiers",
        ));
    }
    let mut framed = Vec::new();
    for part in [
        CORRELATION_VERSION.as_bytes(),
        ACTIVITY_SCHEMA_VERSION.as_bytes(),
        key_id.as_bytes(),
        harness.as_bytes(),
        kind.as_bytes(),
        value.as_bytes(),
    ] {
        framed.extend_from_slice(&(part.len() as u32).to_be_bytes());
        framed.extend_from_slice(part);
    }
    Ok(framed)
}

/// `_OPAQUE_STRONG_IDENTIFIER` (:38) — `[A-Za-z0-9][A-Za-z0-9._:-]{15,511}`.
fn opaque_strong_identifier(value: &str) -> bool {
    let length = value.chars().count();
    if !(16..=512).contains(&length) {
        return false;
    }
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
        })
}

/// `_WEAK_IDENTIFIER` (:34-37), case-insensitive whole-string match.
fn weak_identifier(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    let digits = |rest: &str| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit());
    if digits(&lowered) {
        return true;
    }
    for prefix in ["request", "req", "session", "sess", "run", "event"] {
        let Some(rest) = lowered.strip_prefix(prefix) else {
            continue;
        };
        let rest = match rest.as_bytes().first() {
            Some(b'.') | Some(b'_') | Some(b':') | Some(b'-') => &rest[1..],
            _ => rest,
        };
        if digits(rest) {
            return true;
        }
    }
    false
}

/// `_ISO_TIMESTAMP` (:39-41), whole-string.
fn iso_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    let digits_at = |start: usize, count: usize| {
        bytes.len() >= start + count && bytes[start..start + count].iter().all(u8::is_ascii_digit)
    };
    if !(digits_at(0, 4)
        && bytes.get(4) == Some(&b'-')
        && digits_at(5, 2)
        && bytes.get(7) == Some(&b'-')
        && digits_at(8, 2)
        && matches!(bytes.get(10), Some(b'T') | Some(b't'))
        && digits_at(11, 2)
        && bytes.get(13) == Some(&b':')
        && digits_at(14, 2)
        && bytes.get(16) == Some(&b':')
        && digits_at(17, 2))
    {
        return false;
    }
    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        let start = index + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end == start {
            return false;
        }
        index = end;
    }
    match bytes.get(index) {
        Some(b'Z') | Some(b'z') => index + 1 == bytes.len(),
        Some(b'+') | Some(b'-') => {
            digits_at(index + 1, 2)
                && bytes.get(index + 3) == Some(&b':')
                && digits_at(index + 4, 2)
                && index + 6 == bytes.len()
        }
        _ => false,
    }
}

/// `identifier_alphabet` (:159) — distinct lowercased alphanumerics.
fn alphabet_size(value: &str) -> usize {
    let mut seen: Vec<char> = Vec::new();
    for character in value.chars().filter(|c| c.is_ascii_alphanumeric()) {
        let lowered = character.to_ascii_lowercase();
        if !seen.contains(&lowered) {
            seen.push(lowered);
        }
    }
    seen.len()
}

/// `_STABLE_ID` (privacy :33) — `[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*`, ≤128.
fn stable_id(value: &str) -> bool {
    if value.is_empty() || value.chars().count() > 128 {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let mut index = 1;
    while index < bytes.len() && alphanumeric(bytes[index]) {
        index += 1;
    }
    while index < bytes.len() {
        if !matches!(bytes[index], b'.' | b'_' | b'-') {
            return false;
        }
        index += 1;
        let start = index;
        while index < bytes.len() && alphanumeric(bytes[index]) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    true
}

/// `_prepare_key_path` (:133-137).
fn prepare_key_path(guard_home: &Path) -> io::Result<PathBuf> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(PRIVATE_DIRECTORY_MODE);
    }
    builder.create(guard_home)?;
    if !guard_home.is_dir() {
        return Err(invalid("guard_home must be a directory"));
    }
    Ok(guard_home.join(CORRELATION_KEY_FILE))
}

/// `_new_key` (:140-143).
fn new_key() -> (String, Vec<u8>) {
    let material = random_bytes(KEY_BYTES);
    (
        format!("correlation.v1.{}", fingerprint(&material)),
        material,
    )
}

fn fingerprint(material: &[u8]) -> String {
    hex::encode(Sha256::digest(material))[..16].to_owned()
}

/// `_serialize_key` (:146-153) — sorted compact JSON plus a trailing newline.
fn serialize_key(key_id: &str, material: &[u8]) -> Vec<u8> {
    let mut payload = Map::new();
    let _ = payload.insert(
        "schema_version".to_owned(),
        Value::String(KEY_SCHEMA_VERSION.to_owned()),
    );
    let _ = payload.insert("key_id".to_owned(), Value::String(key_id.to_owned()));
    let _ = payload.insert(
        "material".to_owned(),
        Value::String(base64_encode(material)),
    );
    let mut encoded = Vec::new();
    write_canonical_json(&Value::Object(payload), &mut encoded)
        .expect("correlation key payload is canonical JSON");
    encoded.push(b'\n');
    encoded
}

/// `_read_key` (:172-181). The file is opened without following a link, so the
/// mode repair and the read both land on the file the check accepted.
fn read_key(path: &Path) -> io::Result<InstallationCorrelationKey> {
    let mut options = OpenOptions::new();
    let _ = options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut handle = options.open(path)?;
    let metadata = handle.metadata()?;
    if !metadata.is_file() {
        return Err(invalid(
            "command activity correlation key must be a regular file",
        ));
    }
    // A real key file is under 200 bytes; anything larger fails the parse
    // below anyway, and this keeps a planted file out of memory first.
    if metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(invalid("invalid command activity correlation key file"));
    }
    set_private_handle_mode(&handle);
    let mut raw = String::new();
    if handle.read_to_string(&mut raw).is_err() || !raw.is_ascii() {
        return Err(invalid("invalid command activity correlation key file"));
    }
    parse_key(&raw)
}

/// `_parse_key` (:184-208).
fn parse_key(raw: &str) -> io::Result<InstallationCorrelationKey> {
    let Ok(Value::Object(payload)) = serde_json::from_str::<Value>(raw) else {
        return Err(invalid(
            "invalid command activity correlation key file shape",
        ));
    };
    if payload.len() != 3
        || !payload.contains_key("schema_version")
        || !payload.contains_key("key_id")
        || !payload.contains_key("material")
    {
        return Err(invalid(
            "invalid command activity correlation key file shape",
        ));
    }
    if payload.get("schema_version").and_then(Value::as_str) != Some(KEY_SCHEMA_VERSION) {
        return Err(invalid(
            "unsupported command activity correlation key schema",
        ));
    }
    let (Some(key_id), Some(encoded)) = (
        payload.get("key_id").and_then(Value::as_str),
        payload.get("material").and_then(Value::as_str),
    ) else {
        return Err(invalid("invalid command activity correlation key fields"));
    };
    let Some(material) = base64_decode(encoded) else {
        return Err(invalid("invalid command activity correlation key material"));
    };
    if !stable_id(key_id) {
        return Err(invalid("key_id must be a stable lowercase identifier"));
    }
    let key = InstallationCorrelationKey::new(key_id, &material)?;
    // The id names the material it was derived from, so a file whose two
    // halves disagree was edited and cannot be trusted to join anything.
    if key.key_id != format!("correlation.v1.{}", fingerprint(&material)) {
        return Err(invalid(
            "command activity correlation key identity does not match its material",
        ));
    }
    Ok(key)
}

/// `_write_private_temporary` (:211-228).
fn write_private_temporary(path: &Path, payload: &[u8]) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("correlation-key");
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut last = io::Error::new(io::ErrorKind::AlreadyExists, "temporary name taken");
    for _ in 0..8 {
        let temporary = parent.join(format!(".{name}.{}", hex::encode(random_bytes(8))));
        let mut options = OpenOptions::new();
        let _ = options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = options.mode(PRIVATE_FILE_MODE);
        }
        let mut handle = match options.open(&temporary) {
            Ok(handle) => handle,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last = error;
                continue;
            }
            Err(error) => return Err(error),
        };
        let written = handle
            .write_all(payload)
            .and_then(|()| handle.flush())
            .and_then(|()| handle.sync_all());
        if let Err(error) = written {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        return Ok(temporary);
    }
    Err(last)
}

fn fsync_directory(parent: Option<&Path>) {
    if let Some(parent) = parent {
        if let Ok(handle) = File::open(parent) {
            let _ = handle.sync_all();
        }
    }
}

fn set_private_mode(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_FILE_MODE));
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn set_private_handle_mode(handle: &File) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = handle.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE));
    }
    #[cfg(not(unix))]
    let _ = handle;
}

fn base64_encode(material: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(material)
}

fn base64_decode(encoded: &str) -> Option<Vec<u8>> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(encoded).ok()
}

fn hmac_hex(material: &[u8], framed: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(material).expect("hmac accepts any key");
    mac.update(framed);
    hex::encode(mac.finalize().into_bytes())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_owned())
}

#[cfg(test)]
#[path = "hook_evidence_correlation_tests.rs"]
mod tests;
