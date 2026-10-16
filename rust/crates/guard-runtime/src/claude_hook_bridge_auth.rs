//! Daemon state authentication and identity-challenge verification for the
//! native Claude hook bridge: a port of `_private_file_text`,
//! `_authenticated_state` and `_verify_challenge_response` in
//! `codex_daemon_hook_auth.py`. Every error string is the `ValueError`
//! message CPython raises, because the bridge writes it into the hook reason.

#[cfg(unix)]
use std::fs::Metadata;
use std::fs::{self, File};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::claude_hook_bridge_render::py_strip;
use crate::claude_hook_bridge_url::resolve_absolute;
use crate::daemon_policy_authority::{canonical_discovery_payload, hmac_sha256_raw};
use crate::resident_transport::constant_time_eq;

pub(crate) const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "::1"];
const DISCOVERY_PROTOCOL_VERSION: i64 = 1;
const CHALLENGE_TTL_MS: i128 = 5_000;
/// Discovery files are a few hundred bytes; anything this large is not one.
const PRIVATE_FILE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const GENERATION_FIELDS: [&str; 6] = [
    "state_id",
    "auth_token_id",
    "host",
    "port",
    "pid",
    "started_at",
];

const MALFORMED_KEY: &str = "daemon discovery key is malformed";
const STATE_AUTHENTICATION_FAILED: &str = "daemon state authentication failed";
const CHALLENGE_MISMATCH: &str = "daemon identity challenge did not match authenticated state";
const CHALLENGE_EXPIRED: &str = "daemon identity challenge expired";
const CHALLENGE_AUTHENTICATION_FAILED: &str = "daemon identity challenge authentication failed";

/// An authenticated `daemon-state.json` payload and the discovery key that
/// signed it.
#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedState {
    pub(crate) payload: Map<String, Value>,
    pub(crate) key: String,
}

impl AuthenticatedState {
    pub(crate) fn text(&self, field: &str) -> &str {
        self.payload
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    /// The validated listener port.
    pub(crate) fn port(&self) -> u16 {
        json_int(self.payload.get("port"))
            .and_then(|port| u16::try_from(port).ok())
            .unwrap_or(0)
    }

    /// `_daemon_generation_identity(a) == _daemon_generation_identity(b)`
    /// and the discovery keys match.
    pub(crate) fn same_generation(&self, other: &AuthenticatedState) -> bool {
        GENERATION_FIELDS
            .iter()
            .all(|field| py_eq(self.payload.get(*field), other.payload.get(*field)))
            && constant_time_eq(self.key.as_bytes(), other.key.as_bytes())
    }
}

/// `Path(path).parent`, which is `.` for a bare file name.
fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// `_private_file_text`: an owner-only regular file in an owner-only
/// directory, read as stripped UTF-8.
pub(crate) fn private_file_text(path: &Path, label: &str) -> Result<String, String> {
    private_file_raw(path, label).map(|text| py_strip(&text).to_owned())
}

/// The directory and file metadata of a private file, refused unless the
/// directory is a directory and the file is a regular file (not a link).
#[cfg(unix)]
fn private_file_metadata(path: &Path, label: &str) -> Result<(Metadata, Metadata), String> {
    let unavailable = || format!("{label} is unavailable");
    let parent = fs::symlink_metadata(parent_of(path)).map_err(|_| unavailable())?;
    let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !parent.is_dir() {
        return Err("Guard home is not a directory".to_owned());
    }
    if !metadata.file_type().is_file() {
        return Err(format!("{label} must be a regular file"));
    }
    Ok((parent, metadata))
}

/// [`private_file_text`] without the strip: the file's UTF-8 text as is.
#[cfg(windows)]
pub(crate) fn private_file_raw(path: &Path, label: &str) -> Result<String, String> {
    let file = crate::claude_hook_bridge_auth_windows::open_private_file(path, label)?;
    read_private_text(file, label)
}

/// [`private_file_text`] without the strip: the file's UTF-8 text as is.
#[cfg(unix)]
pub(crate) fn private_file_raw(path: &Path, label: &str) -> Result<String, String> {
    let (parent, metadata) = private_file_metadata(path, label)?;
    let uid = nix::unistd::getuid().as_raw();
    if parent.uid() != uid || metadata.uid() != uid {
        return Err(format!("{label} ownership does not match the current user"));
    }
    if parent.mode() & 0o077 != 0 || metadata.mode() & 0o077 != 0 {
        return Err(format!("{label} permissions are not owner-only"));
    }
    let unreadable = || format!("{label} is unreadable");
    // Open without following a link and confirm it is the file just
    // checked, so a swap between the check and the read is refused.
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| unreadable())?;
    let opened = file.metadata().map_err(|_| unreadable())?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(unreadable());
    }
    read_private_text(file, label)
}

/// Read a checked private file, capped, as UTF-8.
fn read_private_text(file: File, label: &str) -> Result<String, String> {
    let unreadable = || format!("{label} is unreadable");
    let mut bytes = Vec::new();
    file.take(PRIVATE_FILE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    if bytes.len() as u64 > PRIVATE_FILE_MAX_BYTES {
        return Err(unreadable());
    }
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(text.to_owned()),
        Err(error) => Err(utf8_error_message(&bytes, error)),
    }
}

/// The `UnicodeDecodeError` text `read_text(encoding="utf-8")` raises.
fn utf8_error_message(bytes: &[u8], error: std::str::Utf8Error) -> String {
    let start = error.valid_up_to();
    let (end, reason) = match error.error_len() {
        None => (bytes.len(), "unexpected end of data"),
        Some(length) => {
            let invalid_start = matches!(bytes[start], 0x80..=0xC1 | 0xF5..=0xFF);
            let reason = if invalid_start {
                "invalid start byte"
            } else {
                "invalid continuation byte"
            };
            (start + length, reason)
        }
    };
    let position = if end - start == 1 {
        format!("byte 0x{:02x} in position {start}", bytes[start])
    } else {
        format!("bytes in position {start}-{}", end - 1)
    };
    format!("'utf-8' codec can't decode {position}: {reason}")
}

/// `bytes.fromhex`: hex digit pairs, with ASCII whitespace allowed only
/// between pairs.
pub(crate) fn py_fromhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            index += 1;
            continue;
        }
        let high = (bytes[index] as char).to_digit(16)?;
        let low = (*bytes.get(index + 1)? as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
        index += 2;
    }
    Some(out)
}

/// `_sign_discovery_payload`: HMAC-SHA256 of the canonical payload under the
/// 32-byte discovery key, as lowercase hex.
fn sign_discovery_payload(key: &str, payload: &Map<String, Value>) -> Result<String, String> {
    let key = py_fromhex(key)
        .filter(|key| key.len() == 32)
        .ok_or_else(|| MALFORMED_KEY.to_owned())?;
    Ok(hex::encode(hmac_sha256_raw(
        &key,
        &canonical_discovery_payload(payload),
    )))
}

/// The value of a JSON integer literal (never a boolean), when it fits.
pub(crate) fn json_int(value: Option<&Value>) -> Option<i128> {
    match value? {
        Value::Number(number) => {
            let text = number.to_string();
            if text.contains(['.', 'e', 'E']) {
                None
            } else {
                text.parse().ok()
            }
        }
        _ => None,
    }
}

fn is_json_int(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Number(number)) if !number.to_string().contains(['.', 'e', 'E']))
}

enum Numeric {
    Int(String),
    Float(f64),
}

fn numeric(value: &Value) -> Option<Numeric> {
    match value {
        Value::Bool(flag) => Some(Numeric::Int(if *flag { "1" } else { "0" }.to_owned())),
        Value::Number(number) => {
            let text = number.to_string();
            if text.contains(['.', 'e', 'E']) {
                text.parse().ok().map(Numeric::Float)
            } else if text == "-0" {
                Some(Numeric::Int("0".to_owned()))
            } else {
                Some(Numeric::Int(text))
            }
        }
        _ => None,
    }
}

fn value_eq(left: &Value, right: &Value) -> bool {
    if let (Some(left), Some(right)) = (numeric(left), numeric(right)) {
        return match (left, right) {
            (Numeric::Int(left), Numeric::Int(right)) => left == right,
            (Numeric::Float(left), Numeric::Float(right)) => left == right,
            (Numeric::Int(int), Numeric::Float(float))
            | (Numeric::Float(float), Numeric::Int(int)) => {
                int.parse::<f64>().is_ok_and(|int| int == float)
            }
        };
    }
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(l, r)| value_eq(l, r))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .all(|(key, l)| right.get(key).is_some_and(|r| value_eq(l, r)))
        }
        _ => false,
    }
}

/// Python `==` between two `dict.get` results: a missing key reads as
/// `None`, booleans equal `0`/`1`, and integers equal integral floats.
pub(crate) fn py_eq(left: Option<&Value>, right: Option<&Value>) -> bool {
    value_eq(left.unwrap_or(&Value::Null), right.unwrap_or(&Value::Null))
}

/// `Path(text).resolve()` as a string, relative paths joining the cwd.
fn resolved(text: &str) -> Result<String, String> {
    if text.contains('\0') {
        return Err("embedded null byte".to_owned());
    }
    if Path::new(text).is_absolute() {
        return Ok(resolve_absolute(text));
    }
    let cwd = std::env::current_dir().map_err(|_| "daemon state Guard home is invalid")?;
    let joined = cwd.join(text);
    let joined = joined
        .to_str()
        .ok_or("daemon state Guard home is invalid")?;
    Ok(resolve_absolute(joined))
}

/// `_authenticated_state(state_path)`.
pub(crate) fn authenticated_state(state_path: &Path) -> Result<AuthenticatedState, String> {
    let home = parent_of(state_path);
    let key = match private_file_text(&home.join("daemon-discovery-key"), "daemon discovery key") {
        Ok(key) => key,
        // A home whose daemon never started has neither file yet; that is
        // a daemon that is not up, not state that failed authentication.
        Err(_) if fs::symlink_metadata(state_path).is_err() => {
            return Err("daemon state is unavailable".to_owned());
        }
        Err(error) => return Err(error),
    };
    let text = private_file_text(state_path, "daemon state")?;
    let payload: Value =
        serde_json::from_str(&text).map_err(|_| "daemon state is malformed".to_owned())?;
    let Value::Object(payload) = payload else {
        return Err("daemon state must be a JSON object".to_owned());
    };
    if payload.is_empty() {
        // A stopped or restarting daemon leaves this exact tombstone behind.
        return Err("daemon state records a stopped daemon".to_owned());
    }
    let mut unsigned = payload.clone();
    unsigned.remove("state_signature");
    let key_bytes = py_fromhex(&key).ok_or_else(|| MALFORMED_KEY.to_owned())?;
    let expected_key_id = Value::String(hex::encode(Sha256::digest(&key_bytes)));
    let authenticated = match payload.get("state_signature") {
        Some(Value::String(signature)) => {
            py_eq(
                unsigned.get("discovery_protocol_version"),
                Some(&Value::from(DISCOVERY_PROTOCOL_VERSION)),
            ) && py_eq(unsigned.get("discovery_key_id"), Some(&expected_key_id))
                && constant_time_eq(
                    signature.as_bytes(),
                    sign_discovery_payload(&key, &unsigned)?.as_bytes(),
                )
        }
        _ => false,
    };
    if !authenticated {
        return Err(STATE_AUTHENTICATION_FAILED.to_owned());
    }
    let text_field = |field: &str| unsigned.get(field).and_then(Value::as_str);
    let host_ok = text_field("host")
        .is_some_and(|host| LOOPBACK_HOSTS.contains(&host.to_lowercase().as_str()));
    let port_ok = json_int(unsigned.get("port")).is_some_and(|port| 0 < port && port <= 65_535);
    let pid_ok = is_json_int(unsigned.get("pid"))
        && unsigned.get("pid").is_some_and(|pid| {
            let pid = pid.to_string();
            !pid.starts_with('-') && pid != "0"
        });
    let complete = host_ok
        && port_ok
        && pid_ok
        && text_field("state_id").is_some_and(|id| !id.is_empty())
        && text_field("started_at").is_some_and(|started| !started.is_empty())
        && text_field("auth_token_id").is_some();
    let Some(guard_home) = text_field("guard_home").filter(|_| complete) else {
        return Err("daemon state identity is incomplete".to_owned());
    };
    let home_text = home.to_str().ok_or("daemon state Guard home is invalid")?;
    if resolved(guard_home)? != resolved(home_text)? {
        return Err("daemon state belongs to a different Guard home".to_owned());
    }
    Ok(AuthenticatedState { payload, key })
}

fn now_ms() -> i128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_millis() as i128,
        Err(error) => -(error.duration().as_millis() as i128),
    }
}

/// `_verify_challenge_response`: returns the proof to present with the hook.
pub(crate) fn verify_challenge_response(
    response: &Map<String, Value>,
    state: &AuthenticatedState,
    nonce: &str,
    hook_event: &str,
) -> Result<String, String> {
    let mut unsigned = response.clone();
    unsigned.remove("proof");
    let expected = [
        (
            "protocol_version",
            Some(Value::from(DISCOVERY_PROTOCOL_VERSION)),
        ),
        ("nonce", Some(Value::String(nonce.to_owned()))),
        ("state_id", state.payload.get("state_id").cloned()),
        ("host", state.payload.get("host").cloned()),
        ("port", state.payload.get("port").cloned()),
        ("pid", state.payload.get("pid").cloned()),
        ("started_at", state.payload.get("started_at").cloned()),
        ("guard_home", state.payload.get("guard_home").cloned()),
        ("hook_event", Some(Value::String(hook_event.to_owned()))),
    ];
    if expected
        .iter()
        .any(|(field, value)| !py_eq(unsigned.get(*field), value.as_ref()))
    {
        return Err(CHALLENGE_MISMATCH.to_owned());
    }
    let now = now_ms();
    let issued = json_int(unsigned.get("issued_at_ms"));
    let expires = json_int(unsigned.get("expires_at_ms"));
    let fresh = matches!(
        (issued, expires),
        (Some(issued), Some(expires))
            if issued <= now + 1_000 && expires >= now && expires - issued <= CHALLENGE_TTL_MS
    );
    if !fresh {
        return Err(CHALLENGE_EXPIRED.to_owned());
    }
    let expected_proof = sign_discovery_payload(&state.key, &unsigned)?;
    match response.get("proof") {
        Some(Value::String(proof))
            if constant_time_eq(proof.as_bytes(), expected_proof.as_bytes()) =>
        {
            Ok(proof.clone())
        }
        _ => Err(CHALLENGE_AUTHENTICATION_FAILED.to_owned()),
    }
}

#[cfg(all(test, unix))]
#[path = "claude_hook_bridge_auth_tests.rs"]
mod tests;
