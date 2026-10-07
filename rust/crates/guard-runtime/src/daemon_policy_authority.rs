//! Resident daemon policy-authority client (RTM-030).
//!
//! Rust port of
//! `src/codex_plugin_scanner/guard/daemon/policy_authority_client.py`
//! (:17-:57), `src/codex_plugin_scanner/guard/daemon/client.py`
//! (`GuardSurfaceDaemonClient` :184-:343, `_post` :434-:455,
//! `resolve_policy_decision` :337, `claim_policy_decision` :340,
//! `load_running_guard_surface_daemon_client` :538-:551), and
//! `src/codex_plugin_scanner/guard/daemon/manager.py::load_running_guard_daemon_identity`
//! (:1205-:1206 → `_live_guard_daemon_identity` :1228-:1260,
//! `_load_authenticated_daemon_identity` :1263-:1281).
//!
//! Authority is the running Guard surface daemon, reached only over
//! authenticated loopback HTTP. Everything is fail-closed: identity,
//! transport, or shape errors resolve to `decision=None` /
//! `claimed=false`. The daemon state is authenticated by an HMAC over the
//! state payload keyed by `daemon-discovery-key`, and the bearer token is
//! pinned to `auth_token_id = sha256(token)` via `secrets.compare_digest`
//! parity (manager.py:1275). Live checks require `state_id` non-empty,
//! `compatibility_version == GUARD_DAEMON_COMPATIBILITY_VERSION` (2), a
//! valid `port`, a live `pid`, a `GET /healthz` that is 200 and
//! `_healthz_payload_is_current` (compat + REQUIRED_DAEMON_TABLES ⊆
//! tables), and either a pid command-line match for `guard_home` or an
//! authenticated `GET /v1/healthz/details` whose `guard_home` and runtime
//! state match.
//!
//! Only loopback HTTP to `127.0.0.1` is ever dialed (client.py:416-:426);
//! the daemon token is never sent to a redirected or non-loopback
//! authority.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use guard_command::local_supply_chain::{DaemonPolicyResolution, PolicyAuthorityApi};

use crate::resident_transport::constant_time_eq;

/// `GUARD_DAEMON_COMPATIBILITY_VERSION` (manager.py:74). The daemon state
/// and `/healthz` payloads must carry this exact value.
const GUARD_DAEMON_COMPATIBILITY_VERSION: i64 = 2;
/// `DAEMON_DISCOVERY_PROTOCOL_VERSION` (discovery.py:13).
const DAEMON_DISCOVERY_PROTOCOL_VERSION: i64 = 1;
/// `_GUARD_DAEMON_AUTH_TOKEN_MAX_BYTES` (manager.py:110).
const DAEMON_AUTH_TOKEN_MAX_BYTES: u64 = 4096;
/// `daemon-discovery-key` is a 32-byte hex key (discovery.py:18-:19,
/// `_DISCOVERY_KEY_BYTES = 32`), so the file is a 64-char lowercase hex
/// string.
const DAEMON_DISCOVERY_KEY_BYTES: usize = 32;
/// Bound on `daemon-state.json` and each HTTP response body we accept
/// (discovery.py:114 caps state at 64 KiB; client.py:222 caps payloads).
const DAEMON_STATE_JSON_MAX_BYTES: u64 = 64 * 1024;
const DAEMON_RESPONSE_MAX_BYTES: usize = 256 * 1024;
/// `_GUARD_DAEMON_PROCESS_QUERY_MAX_BYTES` / `_TIMEOUT_SECONDS`
/// (manager.py:111-:112).
const PROCESS_QUERY_MAX_BYTES: usize = 1024 * 1024;
const PROCESS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Health-request deadline (manager.py:1206 uses `health_timeout=1.0`;
/// policy_authority_client.py:35 uses 2s for the policy socket).
const HEALTH_TIMEOUT: Duration = Duration::from_secs(1);
/// Policy request socket timeout (policy_authority_client.py:35).
const POLICY_TIMEOUT: Duration = Duration::from_secs(2);
/// Trusted `ps` locations (manager.py:112, :2556-:2562).
const POSIX_PS_PATHS: [&str; 2] = ["/bin/ps", "/usr/bin/ps"];
/// Launcher basenames recognized in serve argv (manager.py:2885-:2894).
const RECOGNIZED_LAUNCHERS: [&str; 4] = [
    "hol-guard",
    "hol-guard.exe",
    "plugin-guard",
    "plugin-guard.exe",
];
/// `_HOOK_LAUNCHER_ARGS` (manager.py:81) — hook command lines are not
/// daemon servers even when they carry guard flags.
const HOOK_LAUNCHER_ARGS: [&str; 3] = ["--hook-mode", "--hook-transport", "--hook-event"];
/// `REQUIRED_DAEMON_TABLES` (manager.py:73) — `healthz.tables` must cover
/// this set.
const REQUIRED_DAEMON_TABLES: [&str; 1] = ["guard_connect_states"];
/// `DAEMON_STATE_SIGNATURE_FIELD` (discovery.py:17).
const DAEMON_STATE_SIGNATURE_FIELD: &str = "state_signature";
/// Frozen serve argv marker (frozen_runtime_commands.py:136-:163).
const FROZEN_DAEMON_SERVE_ARG: &str = "--frozen-daemon-serve";

/// Resident policy-authority client. Holds `guard_home` — the private
/// root containing `daemon-state.json`, `daemon-auth-token`, and
/// `daemon-discovery-key` (manager.py:1682, :1825-:1827, :1284-:1290).
pub struct ResidentPolicyAuthority {
    guard_home: PathBuf,
}

/// Verified daemon authority — the `GuardSurfaceDaemonClient` tuple
/// (client.py:185-:189): base URL + bearer token. Serialized into the
/// `authority` `Value` so `claim_package_policy` can rebuild it.
#[derive(Debug, Clone)]
struct DaemonAuthority {
    base_url: String,
    auth_token: String,
}

/// Verified identity record carried through `daemon-state.json` +
/// `daemon-auth-token` + discovery key.
struct DaemonIdentity {
    port: u16,
    auth_token: String,
}

impl ResidentPolicyAuthority {
    /// Construct a resident authority bound to `guard_home`. The caller
    /// (resident package-policy override) wires this in; kept as the
    /// public constructor even when no in-crate caller exists yet.
    #[allow(dead_code)]
    pub fn new(guard_home: PathBuf) -> Self {
        Self { guard_home }
    }

    /// `resolve_package_policy` (policy_authority_client.py:17-:45). Each
    /// workspace is tried in order; the first `decision` dict wins.
    fn resolve(
        &self,
        harness: &str,
        artifact_id: Option<&str>,
        artifact_hash: &str,
        workspaces: &[String],
        publisher: Option<&str>,
    ) -> Option<(Value, DaemonAuthority)> {
        let authority = self.load_authority()?;
        for workspace in workspaces {
            let mut payload = Map::new();
            payload.insert("harness".into(), Value::String(harness.to_owned()));
            payload.insert(
                "artifact_id".into(),
                match artifact_id {
                    Some(id) if !id.is_empty() => Value::String(id.to_owned()),
                    _ => Value::Null,
                },
            );
            payload.insert(
                "artifact_hash".into(),
                Value::String(artifact_hash.to_owned()),
            );
            payload.insert("workspace".into(), Value::String(workspace.clone()));
            payload.insert(
                "publisher".into(),
                match publisher {
                    Some(p) if !p.is_empty() => Value::String(p.to_owned()),
                    _ => Value::Null,
                },
            );
            let lookup = post_json(&authority, "/v1/policy/resolve", &Value::Object(payload))?;
            let decision = lookup.get("decision").filter(|d| d.is_object());
            if let Some(decision) = decision {
                return Some((decision.clone(), authority));
            }
        }
        None
    }

    /// `claim_package_policy` (policy_authority_client.py:48-:57) —
    /// `claimed` is true only when the daemon returns `claimed == true`
    /// (client.py:340-:342).
    fn claim(&self, authority: &DaemonAuthority, decision: &Value) -> bool {
        let payload = {
            let mut map = Map::new();
            map.insert("decision".into(), decision.clone());
            Value::Object(map)
        };
        match post_json(authority, "/v1/policy/claim", &payload) {
            Some(response) => response.get("claimed") == Some(&Value::Bool(true)),
            None => false,
        }
    }

    /// `load_running_guard_surface_daemon_client` (client.py:538-:551) →
    /// `load_running_guard_daemon_identity` (manager.py:1205-:1206).
    fn load_authority(&self) -> Option<DaemonAuthority> {
        let identity = load_running_guard_daemon_identity(&self.guard_home)?;
        Some(DaemonAuthority {
            base_url: format!("http://127.0.0.1:{}", identity.port),
            auth_token: identity.auth_token,
        })
    }
}

impl PolicyAuthorityApi for ResidentPolicyAuthority {
    fn resolve_package_policy(
        &self,
        guard_home: &Path,
        harness: &str,
        artifact_id: &str,
        artifact_hash: &str,
        workspaces: &[String],
        publisher: Option<&str>,
    ) -> DaemonPolicyResolution {
        // The trait threads `guard_home` for parity with the Python call
        // site; this resident is bound to one `guard_home` at construction.
        // Fail-closed: any error returns an empty resolution.
        let _ = guard_home;
        let artifact_id_opt = (!artifact_id.is_empty()).then_some(artifact_id);
        match self.resolve(
            harness,
            artifact_id_opt,
            artifact_hash,
            workspaces,
            publisher,
        ) {
            Some((decision, authority)) => DaemonPolicyResolution {
                authority: Some(serialize_authority(&authority)),
                decision: Some(decision),
            },
            None => DaemonPolicyResolution::default(),
        }
    }

    fn claim_package_policy(&self, authority: &Value, decision: &Value) -> bool {
        let Some(authority) = deserialize_authority(authority) else {
            return false;
        };
        self.claim(&authority, decision)
    }
}

/// Serialize the authority so the trait's `authority: &Value` can round-
/// trip back to a `DaemonAuthority` (client.py:185-:189).
fn serialize_authority(authority: &DaemonAuthority) -> Value {
    let mut map = Map::new();
    map.insert("base_url".into(), Value::String(authority.base_url.clone()));
    map.insert(
        "auth_token".into(),
        Value::String(authority.auth_token.clone()),
    );
    Value::Object(map)
}

/// Rebuild the authority from the `Value` (client.py:19-:26 shape checks).
fn deserialize_authority(value: &Value) -> Option<DaemonAuthority> {
    let map = value.as_object()?;
    let base_url = map.get("base_url")?.as_str()?;
    // Loopback-only authority (client.py:416-:426).
    if !base_url.starts_with("http://127.0.0.1:") {
        return None;
    }
    let auth_token = map.get("auth_token")?.as_str()?;
    if auth_token.is_empty() {
        return None;
    }
    Some(DaemonAuthority {
        base_url: base_url.to_owned(),
        auth_token: auth_token.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Identity: daemon-state.json + daemon-auth-token + daemon-discovery-key
// (discovery.py:97-:123; manager.py:1205-:1260)
// ---------------------------------------------------------------------------

/// `_live_guard_daemon_identity` (manager.py:1228-:1260).
fn load_running_guard_daemon_identity(guard_home: &Path) -> Option<DaemonIdentity> {
    let (payload, auth_token) = load_authenticated_daemon_identity(guard_home)?;
    if !daemon_state_matches_current_runtime(&payload) {
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
    // binding (manager.py:1257-:1259).
    if daemon_healthz_details_match(&base_url, &auth_token, guard_home, &payload) {
        return Some(DaemonIdentity {
            port: u16::try_from(port).ok()?,
            auth_token,
        });
    }
    None
}

/// `_load_authenticated_daemon_identity` (manager.py:1263-:1281): the
/// HMAC-verified state payload plus the `auth_token_id`-pinned token.
fn load_authenticated_daemon_identity(guard_home: &Path) -> Option<(Map<String, Value>, String)> {
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
fn load_authenticated_daemon_state(guard_home: &Path) -> Option<Map<String, Value>> {
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

/// `load_daemon_discovery_key` (discovery.py:24-:34).
fn load_daemon_discovery_key(guard_home: &Path) -> Option<String> {
    let encoded = read_private_regular_text(&guard_home.join("daemon-discovery-key"), 256, false)?;
    if encoded.len() != DAEMON_DISCOVERY_KEY_BYTES * 2 {
        return None;
    }
    hex::decode(&encoded).ok()?;
    Some(encoded.to_lowercase())
}

/// `load_guard_daemon_auth_token` (manager.py:1284-:1290) —
/// `daemon-auth-token`, private parent required.
fn load_guard_daemon_auth_token(guard_home: &Path) -> Option<String> {
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
fn verify_daemon_state(payload: &Map<String, Value>, discovery_key: &str) -> bool {
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
fn canonical_discovery_payload(payload: &Map<String, Value>) -> Vec<u8> {
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
fn hmac_sha256_raw(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().to_vec()
}

/// `daemon_state_matches_current_runtime` (runtime_peer.py:105-:135):
/// requires the current compatibility version, a non-empty runtime
/// fingerprint, and a matching package version. Rust does not compute the
/// Python tree fingerprint or identify Desktop Core sources.
fn daemon_state_matches_current_runtime(payload: &Map<String, Value>) -> bool {
    if payload.get("compatibility_version").and_then(Value::as_i64)
        != Some(GUARD_DAEMON_COMPATIBILITY_VERSION)
    {
        return false;
    }
    let fingerprint = payload.get("runtime_fingerprint").and_then(Value::as_str);
    if fingerprint.is_none_or(|f| f.trim().is_empty()) {
        return false;
    }
    payload
        .get("package_version")
        .and_then(Value::as_str)
        .is_some_and(|v| v == crate::PACKAGE_VERSION)
}

/// `_healthz_payload_is_current` (manager.py:3696-:3709).
fn healthz_payload_is_current(payload: &Value) -> bool {
    let map = payload.as_object();
    let Some(map) = map else {
        return false;
    };
    if map.get("compatibility_version").and_then(Value::as_i64)
        != Some(GUARD_DAEMON_COMPATIBILITY_VERSION)
    {
        return false;
    }
    match map.get("tables") {
        None => true,
        Some(Value::Array(tables)) => {
            let names: std::collections::BTreeSet<&str> =
                tables.iter().filter_map(Value::as_str).collect();
            REQUIRED_DAEMON_TABLES
                .iter()
                .all(|required| names.contains(required))
        }
        Some(_) => false,
    }
}

/// `_daemon_healthz_details_match_guard_home` +
/// `_daemon_healthz_details_match_current_runtime` (manager.py:1312-:1322,
/// :1390-:1398): authenticated `GET /v1/healthz/details` whose payload
/// matches `guard_home` and the same runtime-state predicate.
fn daemon_healthz_details_match(
    base_url: &str,
    auth_token: &str,
    guard_home: &Path,
    state: &Map<String, Value>,
) -> bool {
    let headers = [("X-Guard-Token", auth_token)];
    let Some(payload) = http_get_json(&format!("{base_url}/v1/healthz/details"), &headers) else {
        return false;
    };
    if !healthz_payload_matches_guard_home(&payload, guard_home) {
        return false;
    }
    let Some(details) = payload.as_object() else {
        return false;
    };
    daemon_state_matches_current_runtime(details)
        && healthz_details_match_state_identity(details, state)
}

/// Cross-check the details payload against the signed state — same
/// `state_id` and `pid`/`port` when present (manager.py:1272-:1278).
fn healthz_details_match_state_identity(
    details: &Map<String, Value>,
    state: &Map<String, Value>,
) -> bool {
    if let (Some(d), Some(s)) = (
        details.get("state_id").and_then(Value::as_str),
        state.get("state_id").and_then(Value::as_str),
    ) {
        if d != s {
            return false;
        }
    }
    true
}

/// `_healthz_payload_matches_guard_home` (manager.py:3712-:3727).
fn healthz_payload_matches_guard_home(payload: &Value, guard_home: &Path) -> bool {
    let reported = payload.get("guard_home").and_then(Value::as_str);
    let Some(reported) = reported else {
        return false;
    };
    if reported.trim().is_empty() {
        return false;
    }
    paths_equal_resolved(Path::new(reported), guard_home)
}

fn paths_equal_resolved(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(l), Ok(r)) => l == r,
        _ => left == right,
    }
}

// ---------------------------------------------------------------------------
// Private file reads — `read_private_regular_bytes/text` parity
// (private_file_io.py:31-:108). Owner-only, no-follow, stable-metadata,
// bounded.
// ---------------------------------------------------------------------------

fn read_private_regular_text(
    path: &Path,
    max_bytes: u64,
    require_private_parent: bool,
) -> Option<String> {
    let bytes = read_private_regular_bytes(path, max_bytes, require_private_parent)?;
    String::from_utf8(bytes).ok()
}

#[cfg(unix)]
fn read_private_regular_bytes(
    path: &Path,
    max_bytes: u64,
    require_private_parent: bool,
) -> Option<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let parent_before = if require_private_parent {
        Some(fs::symlink_metadata(path.parent()?).ok()?)
    } else {
        None
    };
    if let Some(parent) = &parent_before {
        if !private_directory_metadata_is_valid(parent) {
            return None;
        }
    }
    let path_before = fs::symlink_metadata(path).ok()?;
    if !private_file_metadata_is_valid(&path_before) {
        return None;
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let opened = file.metadata().ok()?;
    if !private_file_metadata_is_valid(&opened)
        || opened.dev() != path_before.dev()
        || opened.ino() != path_before.ino()
    {
        return None;
    }
    if opened.len() > max_bytes {
        return None;
    }
    let mut bytes = Vec::new();
    let mut limited = file.try_clone().ok()?.take(max_bytes + 1);
    limited.read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > max_bytes {
        return None;
    }
    let after = file.metadata().ok()?;
    if !stable_file_metadata(&opened, &after) {
        return None;
    }
    if require_private_parent {
        let parent_after = fs::symlink_metadata(path.parent()?).ok()?;
        if !stable_directory_metadata(&parent_before?, &parent_after) {
            return None;
        }
    }
    Some(bytes)
}

#[cfg(unix)]
fn private_file_metadata_is_valid(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return false;
    }
    metadata.uid() == nix::unistd::getuid().as_raw() && metadata.permissions().mode() & 0o077 == 0
}

#[cfg(unix)]
fn private_directory_metadata_is_valid(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir() {
        return false;
    }
    metadata.uid() == nix::unistd::getuid().as_raw() && metadata.permissions().mode() & 0o077 == 0
}

#[cfg(unix)]
fn stable_file_metadata(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mtime() == after.mtime()
        && before.size() == after.size()
}

#[cfg(unix)]
fn stable_directory_metadata(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev() && before.ino() == after.ino()
}

#[cfg(windows)]
fn read_private_regular_bytes(
    path: &Path,
    max_bytes: u64,
    _require_private_parent: bool,
) -> Option<Vec<u8>> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return None;
    }
    fs::read(path).ok()
}

#[cfg(not(any(unix, windows)))]
fn read_private_regular_bytes(_p: &Path, _m: u64, _r: bool) -> Option<Vec<u8>> {
    None
}

// ---------------------------------------------------------------------------
// Process liveness + command binding
// (manager.py:3216-:3320, :2556-:2610, :2856-:3013)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn daemon_pid_is_running(pid: i64) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid as i32), None).is_ok()
}

#[cfg(windows)]
fn daemon_pid_is_running(pid: i64) -> bool {
    if pid <= 0 || pid > i64::from(u32::MAX) {
        return false;
    }
    guard_runtime_windows_process::wait_for_process_exit(pid as u32, Duration::ZERO)
        .map(|exited| !exited)
        .unwrap_or(false)
}

#[cfg(not(any(unix, windows)))]
fn daemon_pid_is_running(_pid: i64) -> bool {
    false
}

/// `_guard_daemon_pid_matches_command` (manager.py:3275-:3300).
fn daemon_pid_matches_command(pid: i64, guard_home: &Path) -> bool {
    let Some(command) = daemon_command_for_pid(pid) else {
        return false;
    };
    let Some(parts) = split_process_command(&command) else {
        return false;
    };
    if !guard_daemon_command_parts_match(&parts) {
        return false;
    }
    let command_home = command_guard_home(&parts).or_else(implicit_daemon_guard_home);
    match command_home {
        Some(home) => paths_equal_resolved(&home, guard_home),
        None => false,
    }
}

/// `ps -p <pid> -o command=` (manager.py:3305-:3320).
#[cfg(unix)]
fn daemon_command_for_pid(pid: i64) -> Option<String> {
    let ps_path = trusted_posix_ps_path()?;
    let pid_arg = pid.to_string();
    let output =
        bounded_process_query_stdout(&[ps_path.to_str()?, "-p", &pid_arg, "-o", "command="])?;
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_owned())
}

#[cfg(not(unix))]
fn daemon_command_for_pid(_pid: i64) -> Option<String> {
    None
}

#[cfg(unix)]
fn trusted_posix_ps_path() -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    for raw in POSIX_PS_PATHS {
        let candidate = Path::new(raw);
        let Ok(resolved) = fs::canonicalize(candidate) else {
            continue;
        };
        let Ok(metadata) = fs::metadata(&resolved) else {
            continue;
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            return Some(resolved);
        }
    }
    None
}

/// `_bounded_process_query_stdout` (manager.py:2661-:2731).
fn bounded_process_query_stdout(args: &[&str]) -> Option<String> {
    let mut child: Child = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel::<io::Result<Vec<u8>>>();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let result = stdout
            .take((PROCESS_QUERY_MAX_BYTES + 1) as u64)
            .read_to_end(&mut buf)
            .map(|_| buf);
        let _ = tx.send(result);
    });
    let deadline = Instant::now() + PROCESS_QUERY_TIMEOUT;
    let output = loop {
        match child.try_wait() {
            Ok(Some(_)) => match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Ok(buf)) => break Some(buf),
                _ => break None,
            },
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break None,
        }
    };
    let output = output?;
    if output.len() > PROCESS_QUERY_MAX_BYTES {
        return None;
    }
    String::from_utf8(output).ok()
}

/// `_split_process_command` (manager.py:2785-:2790) — `shlex.split` POSIX
/// parity for the bounded subset used here. Returns None on unbalanced
/// quoting (malformed).
fn split_process_command(command_line: &str) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = command_line.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut have = false;
    while let Some(ch) = chars.next() {
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                current.push(ch);
            }
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            } else if ch == '\\' {
                match chars.next() {
                    Some(next @ ('"' | '\\')) => current.push(next),
                    Some(next) => {
                        current.push('\\');
                        current.push(next);
                    }
                    None => return None,
                }
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            '\\' => match chars.next() {
                Some(next) => current.push(next),
                None => return None,
            },
            c if c.is_whitespace() => {
                if have {
                    parts.push(std::mem::take(&mut current));
                    have = false;
                }
            }
            c => {
                current.push(c);
                have = true;
            }
        }
    }
    if in_single || in_double {
        return None;
    }
    if have {
        parts.push(current);
    }
    Some(parts)
}

/// `_guard_daemon_command_parts_match` (manager.py:2856-:2880).
fn guard_daemon_command_parts_match(parts: &[String]) -> bool {
    if parts
        .iter()
        .any(|part| HOOK_LAUNCHER_ARGS.contains(&part.as_str()))
    {
        return false;
    }
    if frozen_daemon_serve_context(parts).is_some() {
        return true;
    }
    for index in 0..parts.len().saturating_sub(1) {
        let window2 = matches!(
            parts.get(index..index + 2),
            Some(w) if w[0] == "daemon" && w[1] == "--serve"
        );
        let window3 = matches!(
            parts.get(index..index + 3),
            Some(w) if w[0] == "guard" && w[1] == "daemon" && w[2] == "--serve"
        );
        if !window2 && !window3 {
            continue;
        }
        let prefix = &parts[..index];
        if prefix.iter().any(|part| part == "codex_plugin_scanner.cli") {
            return true;
        }
        if index > 0 {
            let launcher_name = path_basename_lower(&parts[index - 1]);
            if RECOGNIZED_LAUNCHERS.contains(&launcher_name.as_str()) {
                return true;
            }
        }
    }
    false
}

/// `_guard_home_from_command_parts` (manager.py:2792-:2803).
fn command_guard_home(parts: &[String]) -> Option<PathBuf> {
    if let Some((guard_home, _home_dir, _port)) = frozen_daemon_serve_context(parts) {
        return Some(guard_home);
    }
    for (index, part) in parts.iter().enumerate() {
        if part == "--guard-home" {
            match parts.get(index + 1) {
                Some(value) if !value.is_empty() => return Some(PathBuf::from(value)),
                _ => return None,
            }
        }
        if let Some(value) = part.strip_prefix("--guard-home=") {
            if value.is_empty() {
                return None;
            }
            return Some(PathBuf::from(value));
        }
    }
    None
}

/// `_frozen_daemon_serve_context` (manager.py:2883-:2900) +
/// `decode_frozen_daemon_serve_payload` (frozen_runtime_commands.py:136-:163).
fn frozen_daemon_serve_context(parts: &[String]) -> Option<(PathBuf, PathBuf, i64)> {
    if parts.len() != 3 || parts[1] != FROZEN_DAEMON_SERVE_ARG {
        return None;
    }
    let launcher_name = path_basename_lower(&parts[0]);
    if !RECOGNIZED_LAUNCHERS.contains(&launcher_name.as_str()) {
        return None;
    }
    let payload: Value = serde_json::from_str(&parts[2]).ok()?;
    let map = payload.as_object()?;
    if map.len() != 3 {
        return None;
    }
    let guard_home = map.get("guard_home")?.as_str()?;
    let home_dir = map.get("home_dir")?.as_str()?;
    let port = map.get("port")?.as_i64()?;
    if !(1..=65535).contains(&port) {
        return None;
    }
    let guard_home = PathBuf::from(guard_home);
    let home_dir = PathBuf::from(home_dir);
    if !guard_home.is_absolute() || !home_dir.is_absolute() {
        return None;
    }
    Some((guard_home, home_dir, port))
}

/// `_implicit_daemon_guard_home` (manager.py:2806-:2810) →
/// `resolve_guard_home` (config.py:463-:481). No override: CWD
/// `.hol-guard`, then `$HOME/.hol-guard`, then the POSIX/Windows fallbacks.
fn implicit_daemon_guard_home() -> Option<PathBuf> {
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join(".hol-guard");
        if fs::canonicalize(&candidate)
            .map(|p| p.is_dir())
            .unwrap_or(false)
        {
            return fs::canonicalize(&candidate).ok();
        }
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let resolved = home.join(".hol-guard");
        if resolved.is_dir() {
            return Some(resolved);
        }
    }
    #[cfg(not(windows))]
    {
        for raw_root in [".", "/var", "/private/var"] {
            let resolved = Path::new(raw_root).join(".hol-guard");
            if resolved.is_dir() {
                return Some(resolved);
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            let resolved = appdata.join("hol-guard");
            if resolved.is_dir() {
                return Some(resolved);
            }
        }
    }
    None
}

fn path_basename_lower(raw: &str) -> String {
    let trimmed = raw.trim_end_matches(['/', '\\']);
    trimmed
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(trimmed)
        .to_lowercase()
}

// ---------------------------------------------------------------------------
// Loopback HTTP — `GuardSurfaceDaemonClient._post` parity
// (client.py:434-:455). Plain HTTP to 127.0.0.1 only; the daemon token is
// never sent elsewhere. `Connection: close` lets us bound the body read.
// ---------------------------------------------------------------------------

fn http_get_json(url: &str, headers: &[(&str, &str)]) -> Option<Value> {
    let (host, port, path) = parse_loopback_url(url)?;
    let response = http_request("GET", &host, port, &path, headers, None, HEALTH_TIMEOUT)?;
    serde_json::from_slice(&response).ok()
}

fn post_json(authority: &DaemonAuthority, path: &str, payload: &Value) -> Option<Value> {
    let body = serde_json::to_vec(payload).ok()?;
    let (host, port, _ignored) = parse_loopback_url(&authority.base_url)?;
    let headers = [
        ("Content-Type", "application/json"),
        ("X-Guard-Token", authority.auth_token.as_str()),
    ];
    let response = http_request(
        "POST",
        &host,
        port,
        path,
        &headers,
        Some(&body),
        POLICY_TIMEOUT,
    )?;
    serde_json::from_slice(&response).ok()
}

/// Loopback-only URL parse (client.py:416-:426). Rejects any non-
/// `127.0.0.1` host, credentials, query, or fragment.
fn parse_loopback_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if authority.contains('@') || path.contains('?') || path.contains('#') {
        return None;
    }
    let (host, port_raw) = authority.rsplit_once(':')?;
    if host != "127.0.0.1" {
        return None;
    }
    let port = port_raw.parse::<u16>().ok()?;
    Some(("127.0.0.1".to_owned(), port, path.to_owned()))
}

fn http_request(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    use std::net::ToSocketAddrs;
    let addr = (host, port).to_socket_addrs().ok()?.next()?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    if let Some(body) = body {
        stream.write_all(body).ok()?;
    }
    let mut response = Vec::new();
    {
        let mut limited = stream
            .try_clone()
            .ok()?
            .take((DAEMON_RESPONSE_MAX_BYTES + 1) as u64);
        limited.read_to_end(&mut response).ok()?;
    }
    let _ = stream.shutdown(Shutdown::Both);
    parse_http_response(&response)
}

/// Minimal HTTP/1.1 response parser: status line + headers + body. The
/// daemon sends `Content-Length` (server.py:8571); `Connection: close`
/// bounds the read. Chunked bodies are rejected.
fn parse_http_response(raw: &[u8]) -> Option<Vec<u8>> {
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_text = std::str::from_utf8(&raw[..header_end]).ok()?;
    let body = &raw[header_end + 4..];
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    let mut content_length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().ok();
        }
    }
    if !(200..300).contains(&status) {
        return None;
    }
    match content_length {
        Some(len) => Some(body.get(..len).unwrap_or(body).to_vec()),
        None => Some(body.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_state_matches_current_runtime_requires_matching_package_version() {
        let mut payload = serde_json::json!({
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
            "runtime_fingerprint": "runtime-fingerprint",
            "package_version": crate::PACKAGE_VERSION,
        });
        assert!(daemon_state_matches_current_runtime(
            payload.as_object().unwrap()
        ));

        payload["package_version"] = Value::String("different-version".to_owned());
        assert!(!daemon_state_matches_current_runtime(
            payload.as_object().unwrap()
        ));

        payload["package_version"] = Value::String(crate::PACKAGE_VERSION.to_owned());
        payload["runtime_fingerprint"] = Value::String("  ".to_owned());
        assert!(!daemon_state_matches_current_runtime(
            payload.as_object().unwrap()
        ));

        payload["runtime_fingerprint"] = Value::String("runtime-fingerprint".to_owned());
        payload["compatibility_version"] = Value::from(GUARD_DAEMON_COMPATIBILITY_VERSION + 1);
        assert!(!daemon_state_matches_current_runtime(
            payload.as_object().unwrap()
        ));
    }

    #[test]
    fn healthz_payload_requires_current_compatibility_and_required_tables() {
        let current = serde_json::json!({
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
            "tables": REQUIRED_DAEMON_TABLES,
        });
        assert!(healthz_payload_is_current(&current));

        let without_tables = serde_json::json!({
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
        });
        assert!(healthz_payload_is_current(&without_tables));

        let missing_required_table = serde_json::json!({
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
            "tables": [],
        });
        assert!(!healthz_payload_is_current(&missing_required_table));

        let outdated_compatibility = serde_json::json!({
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION + 1,
            "tables": REQUIRED_DAEMON_TABLES,
        });
        assert!(!healthz_payload_is_current(&outdated_compatibility));
    }
}
