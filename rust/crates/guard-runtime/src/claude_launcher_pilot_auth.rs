//! Existing Python daemon-discovery authentication, for the private launcher pilot.
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::{Failure, Result};

fn ascii_string(value: &str, output: &mut String) {
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{8}' => output.push_str("\\b"),
            '\u{c}' => output.push_str("\\f"),
            ch if (' '..='~').contains(&ch) => output.push(ch),
            ch => {
                for unit in ch.encode_utf16(&mut [0; 2]) {
                    use std::fmt::Write;
                    write!(output, "\\u{unit:04x}").expect("write to String");
                }
            }
        }
    }
    output.push('"');
}

/// Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True).
/// State/registration schemas contain integers, never floats or surrogate scalars.
pub(super) fn canonical(value: &Value) -> Result<String> {
    let mut output = String::new();
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) if value.is_i64() || value.is_u64() => {
            output.push_str(&value.to_string())
        }
        Value::String(value) => ascii_string(value, &mut output),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(&canonical(value)?);
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<&String> = values.keys().collect();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                ascii_string(key, &mut output);
                output.push(':');
                output.push_str(&canonical(&values[key])?);
            }
            output.push('}');
        }
        _ => {
            return Err(Failure::identity(
                "daemon authentication JSON has unsupported numbers",
            ))
        }
    }
    Ok(output)
}

pub(super) fn sign(key: &[u8], value: &Value) -> Result<String> {
    Ok(hex::encode(crate::hmac_sha256(
        key,
        b"",
        canonical(value)?.as_bytes(),
    )))
}

pub(super) fn unsigned_verified(
    value: &Value,
    field: &str,
    key: &[u8],
) -> Result<Map<String, Value>> {
    let mut unsigned = value
        .as_object()
        .cloned()
        .ok_or_else(|| Failure::identity("daemon state must be a JSON object"))?;
    let signature = unsigned
        .remove(field)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| Failure::identity("daemon state authentication failed"))?;
    let expected = sign(key, &Value::Object(unsigned.clone()))?;
    if !crate::constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
        return Err(Failure::identity("daemon state authentication failed"));
    }
    Ok(unsigned)
}

#[derive(Clone)]
pub(super) struct State {
    pub(super) value: Map<String, Value>,
    pub(super) key: Vec<u8>,
}

fn private_auth_text(path: &Path, label: &str, maximum: u64) -> Result<String> {
    let unavailable = || Failure::identity(&format!("{label} is unavailable"));
    let parent = path.parent().ok_or_else(unavailable)?;
    let directory = parent.symlink_metadata().map_err(|_| unavailable())?;
    let metadata = path.symlink_metadata().map_err(|_| unavailable())?;
    if !directory.is_dir() {
        return Err(Failure::identity("Guard home is not a directory"));
    }
    if !metadata.is_file() {
        return Err(Failure::identity(&format!(
            "{label} must be a regular file"
        )));
    }
    let owner = nix::unistd::getuid().as_raw();
    if directory.uid() != owner || metadata.uid() != owner {
        return Err(Failure::identity(&format!(
            "{label} ownership does not match the current user"
        )));
    }
    if directory.mode() & 0o077 != 0 || metadata.mode() & 0o077 != 0 {
        return Err(Failure::identity(&format!(
            "{label} permissions are not owner-only"
        )));
    }
    super::files::private_text(path, maximum)
        .map_err(|_| Failure::identity(&format!("{label} is unreadable")))
}

pub(super) fn load_state(path: &Path) -> Result<State> {
    let parent = path
        .parent()
        .ok_or_else(|| Failure::identity("daemon state Guard home is invalid"))?;
    let key_text = private_auth_text(
        &parent.join("daemon-discovery-key"),
        "daemon discovery key",
        128,
    )?;
    let key = hex::decode(key_text.trim())
        .map_err(|_| Failure::identity("daemon discovery key is malformed"))?;
    if key.len() != 32 {
        return Err(Failure::identity("daemon discovery key is malformed"));
    }
    let value: Value = serde_json::from_str(&private_auth_text(path, "daemon state", 1_000_000)?)
        .map_err(|_| Failure::identity("daemon state is malformed"))?;
    let unsigned = unsigned_verified(&value, "state_signature", &key)?;
    let key_id = hex::encode(Sha256::digest(&key));
    if unsigned
        .get("discovery_protocol_version")
        .and_then(Value::as_u64)
        != Some(1)
        || unsigned.get("discovery_key_id").and_then(Value::as_str) != Some(key_id.as_str())
    {
        return Err(Failure::identity("daemon state authentication failed"));
    }
    let host = string(&unsigned, "host")?;
    let port = unsigned.get("port").and_then(Value::as_u64).unwrap_or(0);
    if !["localhost", "127.0.0.1", "::1"].contains(&host.to_lowercase().as_str())
        || !(1..=65535).contains(&port)
        || unsigned.get("pid").and_then(Value::as_u64).unwrap_or(0) == 0
    {
        return Err(Failure::identity("daemon state identity is incomplete"));
    }
    for name in ["state_id", "started_at", "auth_token_id", "guard_home"] {
        if string(&unsigned, name)?.is_empty() {
            return Err(Failure::identity("daemon state identity is incomplete"));
        }
    }
    if Path::new(string(&unsigned, "guard_home")?)
        .canonicalize()
        .ok()
        != parent.canonicalize().ok()
    {
        return Err(Failure::identity(
            "daemon state belongs to a different Guard home",
        ));
    }
    Ok(State {
        value: unsigned,
        key,
    })
}

pub(super) fn string<'a>(value: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::identity("daemon state identity is incomplete"))
}

pub(super) fn challenge_proof(
    response: &Value,
    state: &State,
    nonce: &str,
    event: &str,
    now_ms: u64,
) -> Result<String> {
    let response = response
        .as_object()
        .ok_or_else(|| Failure::identity("daemon identity challenge returned malformed JSON"))?;
    for name in [
        "state_id",
        "host",
        "port",
        "pid",
        "started_at",
        "guard_home",
    ] {
        if response.get(name) != state.value.get(name) {
            return Err(Failure::identity(
                "daemon identity challenge did not match authenticated state",
            ));
        }
    }
    if response.get("protocol_version").and_then(Value::as_u64) != Some(1)
        || response.get("nonce").and_then(Value::as_str) != Some(nonce)
        || response.get("hook_event").and_then(Value::as_str) != Some(event)
    {
        return Err(Failure::identity(
            "daemon identity challenge did not match authenticated state",
        ));
    }
    let issued = response.get("issued_at_ms").and_then(Value::as_u64);
    let expires = response.get("expires_at_ms").and_then(Value::as_u64);
    if !matches!((issued, expires), (Some(start), Some(end)) if start <= now_ms.saturating_add(1000) && end >= now_ms && i128::from(end) - i128::from(start) <= 5000)
    {
        return Err(Failure::identity("daemon identity challenge expired"));
    }
    let mut unsigned = response.clone();
    let proof = unsigned
        .remove("proof")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| Failure::identity("daemon identity challenge authentication failed"))?;
    let expected = sign(&state.key, &Value::Object(unsigned))?;
    if !crate::constant_time_eq(proof.as_bytes(), expected.as_bytes()) {
        return Err(Failure::identity(
            "daemon identity challenge authentication failed",
        ));
    }
    Ok(proof)
}

pub(super) fn same_generation(first: &State, second: &State) -> bool {
    [
        "state_id",
        "auth_token_id",
        "host",
        "port",
        "pid",
        "started_at",
    ]
    .iter()
    .all(|name| first.value.get(*name) == second.value.get(*name))
        && crate::constant_time_eq(&first.key, &second.key)
}
