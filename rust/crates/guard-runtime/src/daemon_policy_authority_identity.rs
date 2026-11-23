use super::process::daemon_pid_is_running;
use super::*;

/// `_live_guard_daemon_identity`.
pub(crate) fn load_running_guard_daemon_identity(guard_home: &Path) -> Option<DaemonIdentity> {
    let (payload, auth_token) = load_authenticated_daemon_identity(guard_home)?;
    if !daemon_state_matches_compatible_runtime(&payload) {
        return None;
    }
    let compatibility_version = payload.get("compatibility_version")?.as_i64()?;
    if compatibility_version != GUARD_DAEMON_COMPATIBILITY_VERSION {
        return None;
    }
    let port = payload.get("port")?.as_i64()?;
    let pid = payload.get("pid")?.as_i64()?;
    if !(1..=65535).contains(&port) || pid <= 0 {
        return None;
    }
    if !daemon_pid_is_running(pid) {
        return None;
    }
    let base_url = format!("http://127.0.0.1:{port}");
    let healthz = http_get_json(&format!("{base_url}/healthz"), &[])?;
    if !healthz_payload_is_current(&healthz) {
        return None;
    }
    if daemon_pid_matches_command(pid, guard_home) {
        return Some(DaemonIdentity {
            port: u16::try_from(port).ok()?,
            auth_token,
        });
    }
    // Wrapped daemons may require authenticated detailed health for
    // binding.
    if daemon_healthz_details_match(&base_url, &auth_token, guard_home, &payload) {
        return Some(DaemonIdentity {
            port: u16::try_from(port).ok()?,
            auth_token,
        });
    }
    None
}
/// `_load_authenticated_daemon_identity`: the
/// HMAC-verified state payload plus the `auth_token_id`-pinned token.
pub(crate) fn load_authenticated_daemon_identity(
    guard_home: &Path,
) -> Option<(Map<String, Value>, String)> {
    let payload = load_authenticated_daemon_state(guard_home)?;
    let auth_token = load_guard_daemon_auth_token(guard_home)?;
    let expected_token_id = payload.get("auth_token_id")?.as_str()?;
    let state_id = payload.get("state_id")?.as_str()?;
    if state_id.is_empty() || auth_token.is_empty() {
        return None;
    }
    // `secrets.compare_digest(sha256(token), auth_token_id)` parity.
    let token_id = hex::encode(Sha256::digest(auth_token.as_bytes()));
    if !constant_time_eq(token_id.as_bytes(), expected_token_id.as_bytes()) {
        return None;
    }
    Some((payload, auth_token))
}

/// `load_authenticated_daemon_state` (discovery.py:110-:123): the
/// discovery key authenticates the state payload via an HMAC.
pub(crate) fn load_authenticated_daemon_state(guard_home: &Path) -> Option<Map<String, Value>> {
    let discovery_key = load_daemon_discovery_key(guard_home)?;
    let raw = read_private_regular_text(
        &guard_home.join("daemon-state.json"),
        DAEMON_STATE_JSON_MAX_BYTES,
        false,
    )?;
    let payload: Value = serde_json::from_str(&raw).ok()?;
    let payload = payload.as_object()?;
    if !verify_daemon_state(payload, &discovery_key) {
        return None;
    }
    Some(payload.clone())
}

/// `load_daemon_discovery_key` (discovery.py:24-:34), stripped as
/// `read_private_regular_text` strips it there.
pub(crate) fn load_daemon_discovery_key(guard_home: &Path) -> Option<String> {
    let encoded = read_private_regular_text(&guard_home.join("daemon-discovery-key"), 256, false)?;
    let encoded = encoded.trim();
    if encoded.len() != DAEMON_DISCOVERY_KEY_BYTES * 2 {
        return None;
    }
    hex::decode(encoded).ok()?;
    Some(encoded.to_lowercase())
}

/// `load_guard_daemon_auth_token` —
/// `daemon-auth-token`, private parent required.
pub(crate) fn load_guard_daemon_auth_token(guard_home: &Path) -> Option<String> {
    let token = read_private_regular_text(
        &guard_home.join("daemon-auth-token"),
        DAEMON_AUTH_TOKEN_MAX_BYTES,
        true,
    )?;
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_owned())
}

/// `verify_daemon_state` (discovery.py:97-:107): the `state_signature`
/// must equal `HMAC(key, canonical(unsigned))` and the embedded
/// `discovery_key_id`/`discovery_protocol_version` must match.
pub(crate) fn verify_daemon_state(payload: &Map<String, Value>, discovery_key: &str) -> bool {
    let signature = payload
        .get(DAEMON_STATE_SIGNATURE_FIELD)
        .and_then(Value::as_str);
    let Some(signature) = signature else {
        return false;
    };
    let mut unsigned = payload.clone();
    unsigned.remove(DAEMON_STATE_SIGNATURE_FIELD);
    if unsigned
        .get("discovery_protocol_version")
        .and_then(Value::as_i64)
        != Some(DAEMON_DISCOVERY_PROTOCOL_VERSION)
    {
        return false;
    }
    let Some(discovery_key_bytes) = hex::decode(discovery_key).ok() else {
        return false;
    };
    let key_id = hex::encode(Sha256::digest(discovery_key_bytes.as_slice()));
    if unsigned.get("discovery_key_id").and_then(Value::as_str) != Some(key_id.as_str()) {
        return false;
    }
    let Some(expected) = sign_discovery_payload(discovery_key, &unsigned) else {
        return false;
    };
    constant_time_eq(expected.as_bytes(), signature.as_bytes())
}

/// `canonical_discovery_payload` (discovery.py:72-:73): compact sorted
/// JSON.
pub(crate) fn canonical_discovery_payload(payload: &Map<String, Value>) -> Vec<u8> {
    // serde_json's Value::Object is a BTreeMap, so iteration is
    // already key-sorted; compact separators match Python's
    // (",", ":"). ensure_ascii is the default for json.dumps, so
    // non-ASCII must be escaped to match byte-for-byte.
    let mut out = Vec::new();
    write_json_ensure_ascii(&Value::Object(payload.clone()), &mut out);
    out
}

/// `sign_discovery_payload` (discovery.py:76-:78).
fn sign_discovery_payload(discovery_key: &str, payload: &Map<String, Value>) -> Option<String> {
    let key = hex::decode(discovery_key).ok()?;
    let message = canonical_discovery_payload(payload);
    let tag = hmac_sha256_raw(&key, &message);
    Some(hex::encode(tag))
}

/// Minimal JSON serializer matching `json.dumps(..., sort_keys=True,
/// separators=(",", ":"), ensure_ascii=True)` — keys sorted (BTreeMap),
/// compact, non-ASCII escaped.
fn write_json_ensure_ascii(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_ensure_ascii(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_string(key, out);
                out.push(b':');
                write_json_ensure_ascii(item, out);
            }
            out.push(b'}');
        }
    }
}

fn write_json_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\x08' => out.extend_from_slice(b"\\b"),
            '\x0c' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c if (c as u32) < 0x7f => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            c => {
                // ensure_ascii: escape every non-ASCII scalar as \uXXXX
                // (surrogate pairs for astral plane).
                let code = c as u32;
                if code > 0xffff {
                    let v = code - 0x1_0000;
                    let hi = 0xd800 + (v >> 10);
                    let lo = 0xdc00 + (v & 0x3ff);
                    out.extend_from_slice(format!("\\u{hi:04x}\\u{lo:04x}").as_bytes());
                } else {
                    out.extend_from_slice(format!("\\u{code:04x}").as_bytes());
                }
            }
        }
    }
    out.push(b'"');
}

/// Raw HMAC-SHA256 over an arbitrary message (single-shot; the crate's
/// `hmac_sha256` is label+nonce shaped for the resident protocol).
pub(crate) fn hmac_sha256_raw(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}
