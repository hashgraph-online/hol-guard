//! `dashboard_reconnect`: the proofs a dashboard update uses to find the
//! restarted daemon again.
//!
//! Before an update restart the dashboard asks for an authorization. Its
//! verifier is an HMAC of the record under the daemon discovery key, handed
//! only to that browser; the record itself is kept in a store under the Guard
//! home, signed with the same key. After the restart the browser asks a
//! candidate daemon for a challenge, checks the daemon's proof and answers
//! with its own. Both proofs are HMACs of the challenge under the verifier.
//!
//! The discovery key never leaves this process. The home is the one the
//! resident verified for the request, never a path from the arguments.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::daemon_policy_authority::{
    canonical_discovery_payload, hmac_sha256_raw, load_daemon_discovery_key,
    read_private_regular_text,
};
use crate::encrypted_secret_store::{atomic_write_bytes, random_bytes};
use crate::resident_transport::constant_time_eq;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const PROTOCOL_VERSION: i64 = 1;
const AUTHORIZATION_TTL_MS: i64 = 5 * 60 * 1000;
const CHALLENGE_TTL_MS: i64 = 10 * 1000;
const SURFACE: &str = "dashboard";
const STORE_FILE: &str = "dashboard-reconnect-authorizations.json";
const STORE_SCHEMA: &str = "guard.dashboard-reconnect-authorizations.v1";
const SIGNATURE_FIELD: &str = "signature";
const VERIFIER_PURPOSE: &str = "guard-dashboard-reconnect-verifier-v1";
const MAX_AUTHORIZATIONS: usize = 32;
const MAX_STORE_BYTES: u64 = 64 * 1024;
const HEX_ID_LENGTH: usize = 64;

/// The challenge fields that must be non-empty strings.
const CHALLENGE_STRING_FIELDS: [&str; 8] = [
    "reconnect_id",
    "client_nonce",
    "server_nonce",
    "state_id",
    "candidate_origin",
    "installation_id",
    "guard_home_id",
    "surface",
];
/// The challenge fields that are 32-byte hex identifiers, compared lowercased.
const CHALLENGE_HEX_FIELDS: [&str; 5] = [
    "reconnect_id",
    "client_nonce",
    "server_nonce",
    "installation_id",
    "guard_home_id",
];

/// Serializes the read, prune and write of the store in `prepare`, so two
/// overlapping requests cannot drop each other's authorization.
static STORE: Mutex<()> = Mutex::new(());

/// One stored authorization, for the `dashboard` surface only.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Authorization {
    reconnect_id: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
    installation_id: String,
    guard_home_id: String,
}

impl Authorization {
    fn to_map(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("reconnect_id".into(), json!(self.reconnect_id));
        map.insert("surface".into(), json!(SURFACE));
        map.insert("issued_at_ms".into(), json!(self.issued_at_ms));
        map.insert("expires_at_ms".into(), json!(self.expires_at_ms));
        map.insert("installation_id".into(), json!(self.installation_id));
        map.insert("guard_home_id".into(), json!(self.guard_home_id));
        map
    }

    fn is_current(&self, key: &DiscoveryKey, home_id: &str, now_ms: i64) -> bool {
        self.issued_at_ms <= now_ms
            && now_ms <= self.expires_at_ms
            && self.installation_id == key.id()
            && self.guard_home_id == home_id
    }
}

/// The daemon discovery key, decoded.
struct DiscoveryKey(Vec<u8>);

impl DiscoveryKey {
    fn load(home: &Path) -> Option<Self> {
        let encoded = load_daemon_discovery_key(home)?;
        hex::decode(encoded).ok().map(Self)
    }

    /// `discovery_key_id`: the SHA-256 of the key bytes.
    fn id(&self) -> String {
        hex::encode(Sha256::digest(&self.0))
    }

    fn sign(&self, payload: &Map<String, Value>) -> String {
        hex::encode(hmac_sha256_raw(
            &self.0,
            &canonical_discovery_payload(payload),
        ))
    }

    /// The browser-held verifier for one authorization.
    fn verifier(&self, authorization: &Authorization) -> String {
        let mut payload = authorization.to_map();
        payload.insert("purpose".into(), json!(VERIFIER_PURPOSE));
        self.sign(&payload)
    }
}

pub(crate) fn dispatch(args: &Value, guard_home: &str) -> KindResult {
    let args = args_object(args)?;
    let home = Some(guard_home)
        .filter(|text| !text.contains('\0'))
        .map(Path::new)
        .filter(|home| home.is_absolute())
        .ok_or(ERR_INVALID)?;
    let now_ms = match args.get("now_ms") {
        None | Some(Value::Null) => current_time_ms(),
        Some(value) => value.as_i64().ok_or(ERR_INVALID)?,
    };
    match args.get("op").and_then(Value::as_str) {
        Some("prepare") => Ok(prepare(home, now_ms)),
        Some("challenge") => Ok(challenge(home, args, now_ms)),
        Some("consume") => Ok(consume(home, args, now_ms)),
        Some("challenge_identity") => Ok(json!({
            "identity": args.get("challenge").and_then(normalized_challenge).map(|challenge| {
                hex::encode(Sha256::digest(canonical_discovery_payload(&challenge)))
            }),
        })),
        _ => Err(ERR_INVALID),
    }
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Store one new authorization and answer it with its verifier.
fn prepare(home: &Path, now_ms: i64) -> Value {
    let Some(key) = DiscoveryKey::load(home) else {
        return json!({ "error": "identity_unavailable" });
    };
    let authorization = Authorization {
        reconnect_id: hex::encode(random_bytes(32)),
        issued_at_ms: now_ms,
        expires_at_ms: now_ms.saturating_add(AUTHORIZATION_TTL_MS),
        installation_id: key.id(),
        guard_home_id: guard_home_id(home),
    };
    let _store = STORE.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(records) = load_authorizations(home, &key) else {
        return json!({ "error": "state_invalid" });
    };
    let mut live: Vec<Authorization> = records
        .into_iter()
        .filter(|record| record.expires_at_ms >= now_ms)
        .collect();
    live.push(authorization.clone());
    // A stable sort, so equal issue times keep their stored order.
    live.sort_by_key(|record| record.issued_at_ms);
    let kept = &live[live.len().saturating_sub(MAX_AUTHORIZATIONS)..];
    if write_authorizations(home, &key, kept).is_err() {
        return json!({ "error": "state_unwritable" });
    }
    let mut answer = authorization.to_map();
    answer.insert("protocol_version".into(), json!(PROTOCOL_VERSION));
    answer.insert("verifier".into(), json!(key.verifier(&authorization)));
    json!({ "authorization": answer })
}

fn refused(reason: &str) -> Value {
    json!({ "challenge": null, "reason": format!("dashboard_reconnect_{reason}") })
}

/// Issue a short-lived server proof for a prepared verifier.
fn challenge(home: &Path, args: &Map<String, Value>, now_ms: i64) -> Value {
    let reconnect_id = hex_id(args.get("reconnect_id"));
    let client_nonce = hex_id(args.get("client_nonce"));
    let candidate_origin = non_empty_text(args.get("candidate_origin"));
    let state_id = non_empty_text(args.get("state_id"));
    let (Some(reconnect_id), Some(client_nonce), Some(candidate_origin), Some(state_id)) =
        (reconnect_id, client_nonce, candidate_origin, state_id)
    else {
        return refused("malformed_challenge");
    };
    let Some(key) = DiscoveryKey::load(home) else {
        return refused("identity_unavailable");
    };
    let Some(authorization) = load_authorizations(home, &key).and_then(|records| {
        records
            .into_iter()
            .find(|record| record.reconnect_id == reconnect_id)
    }) else {
        return refused("authorization_unavailable");
    };
    if !authorization.is_current(&key, &guard_home_id(home), now_ms) {
        return refused("authorization_expired");
    }
    let mut challenge = Map::new();
    challenge.insert("protocol_version".into(), json!(PROTOCOL_VERSION));
    challenge.insert("reconnect_id".into(), json!(reconnect_id));
    challenge.insert("client_nonce".into(), json!(client_nonce));
    challenge.insert("server_nonce".into(), json!(hex::encode(random_bytes(32))));
    challenge.insert("state_id".into(), json!(state_id));
    challenge.insert("candidate_origin".into(), json!(candidate_origin));
    challenge.insert(
        "installation_id".into(),
        json!(authorization.installation_id),
    );
    challenge.insert("guard_home_id".into(), json!(authorization.guard_home_id));
    challenge.insert("surface".into(), json!(SURFACE));
    challenge.insert("issued_at_ms".into(), json!(now_ms));
    challenge.insert(
        "expires_at_ms".into(),
        json!(authorization
            .expires_at_ms
            .min(now_ms.saturating_add(CHALLENGE_TTL_MS))),
    );
    let proof = reconnect_proof(&key.verifier(&authorization), "server", &challenge);
    challenge.insert("proof".into(), json!(proof));
    json!({ "challenge": challenge, "reason": "dashboard_reconnect_challenge_issued" })
}

fn verdict(verified: bool, reason: &str) -> Value {
    json!({ "verified": verified, "reason": format!("dashboard_reconnect_{reason}") })
}

/// Verify one browser proof against a prepared authorization.
fn consume(home: &Path, args: &Map<String, Value>, now_ms: i64) -> Value {
    let normalized = args.get("challenge").and_then(normalized_challenge);
    let proof = hex_id(args.get("proof"));
    let (Some(challenge), Some(proof)) = (normalized, proof) else {
        return verdict(false, "malformed_proof");
    };
    let field = |name: &str| challenge.get(name).and_then(Value::as_str);
    let time = |name: &str| challenge.get(name).and_then(Value::as_i64).unwrap_or(0);
    if time("expires_at_ms") < now_ms || time("issued_at_ms") > now_ms {
        return verdict(false, "proof_expired");
    }
    if field("candidate_origin")
        != args
            .get("expected_candidate_origin")
            .and_then(Value::as_str)
        || field("state_id") != args.get("expected_state_id").and_then(Value::as_str)
        || field("surface") != Some(SURFACE)
    {
        return verdict(false, "proof_context_mismatch");
    }
    let Some(key) = DiscoveryKey::load(home) else {
        return verdict(false, "identity_unavailable");
    };
    let authorization = load_authorizations(home, &key).and_then(|records| {
        records
            .into_iter()
            .find(|record| Some(record.reconnect_id.as_str()) == field("reconnect_id"))
    });
    let Some(authorization) =
        authorization.filter(|record| record.is_current(&key, &guard_home_id(home), now_ms))
    else {
        return verdict(false, "authorization_unavailable");
    };
    if field("installation_id") != Some(authorization.installation_id.as_str())
        || field("guard_home_id") != Some(authorization.guard_home_id.as_str())
    {
        return verdict(false, "proof_context_mismatch");
    }
    let expected = reconnect_proof(&key.verifier(&authorization), "client", &challenge);
    if !constant_time_eq(proof.as_bytes(), expected.as_bytes()) {
        return verdict(false, "proof_invalid");
    }
    verdict(true, "proof_accepted")
}

/// The canonical HMAC both proof steps use, keyed by the verifier.
fn reconnect_proof(verifier: &str, context: &str, challenge: &Map<String, Value>) -> String {
    let mut payload = challenge.clone();
    payload.insert("proof_context".into(), json!(context));
    let key = hex::decode(verifier).unwrap_or_default();
    hex::encode(hmac_sha256_raw(
        &key,
        &canonical_discovery_payload(&payload),
    ))
}

/// A non-reversible identity for one canonical Guard home: the SHA-256 of its
/// resolved path, as Python's `Path.resolve` spells it.
fn guard_home_id(home: &Path) -> String {
    let resolved = std::fs::canonicalize(home)
        .map(without_verbatim_prefix)
        .unwrap_or_else(|_| home.to_path_buf());
    hex::encode(Sha256::digest(resolved.to_string_lossy().as_bytes()))
}

/// Drop the `\\?\` prefix Windows canonical paths carry and Python's do not.
/// No other platform spells a path this way.
fn without_verbatim_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy().into_owned();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => path,
    }
}

/// A 32-byte identifier as 64 hex digits, lowercased.
fn hex_id(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| text.len() == HEX_ID_LENGTH && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
}

fn non_empty_text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// The authenticated fields of a challenge, with its identifiers lowercased.
fn normalized_challenge(value: &Value) -> Option<Map<String, Value>> {
    let value = value.as_object()?;
    // JSON `1.0` equals the protocol version too, as it does in Python.
    if value.get("protocol_version").and_then(Value::as_f64) != Some(PROTOCOL_VERSION as f64) {
        return None;
    }
    let mut normalized = Map::new();
    normalized.insert("protocol_version".into(), json!(PROTOCOL_VERSION));
    for field in CHALLENGE_STRING_FIELDS {
        let text = non_empty_text(value.get(field))?;
        let text = if CHALLENGE_HEX_FIELDS.contains(&field) {
            hex_id(value.get(field))?
        } else {
            text.to_owned()
        };
        normalized.insert(field.into(), json!(text));
    }
    for field in ["issued_at_ms", "expires_at_ms"] {
        normalized.insert(field.into(), json!(value.get(field)?.as_i64()?));
    }
    Some(normalized)
}

fn normalized_authorization(value: &Value) -> Option<Authorization> {
    let value = value.as_object()?;
    if value.get("surface").and_then(Value::as_str) != Some(SURFACE) {
        return None;
    }
    let issued_at_ms = value.get("issued_at_ms")?.as_i64()?;
    let expires_at_ms = value
        .get("expires_at_ms")?
        .as_i64()
        .filter(|expires| *expires >= issued_at_ms)?;
    Some(Authorization {
        reconnect_id: hex_id(value.get("reconnect_id"))?,
        issued_at_ms,
        expires_at_ms,
        installation_id: hex_id(value.get("installation_id"))?,
        guard_home_id: hex_id(value.get("guard_home_id"))?,
    })
}

/// The stored authorizations: none when the store is absent, and `None` when
/// it is unreadable, not private, unsigned or signed by another key.
fn load_authorizations(home: &Path, key: &DiscoveryKey) -> Option<Vec<Authorization>> {
    let path = home.join(STORE_FILE);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(_) => return None,
        Ok(_) => {}
    }
    let text = read_private_regular_text(&path, MAX_STORE_BYTES, false)?;
    let Ok(Value::Object(mut payload)) = serde_json::from_str(&text) else {
        return None;
    };
    if payload.get("schema").and_then(Value::as_str) != Some(STORE_SCHEMA) {
        return None;
    }
    let Some(Value::String(signature)) = payload.remove(SIGNATURE_FIELD) else {
        return None;
    };
    if !constant_time_eq(signature.as_bytes(), key.sign(&payload).as_bytes()) {
        return None;
    }
    let records = payload.get("records")?.as_array()?;
    if records.len() > MAX_AUTHORIZATIONS {
        return None;
    }
    records.iter().map(normalized_authorization).collect()
}

fn write_authorizations(
    home: &Path,
    key: &DiscoveryKey,
    records: &[Authorization],
) -> std::io::Result<()> {
    let mut payload = Map::new();
    payload.insert("schema".into(), json!(STORE_SCHEMA));
    payload.insert(
        "records".into(),
        Value::Array(
            records
                .iter()
                .map(|record| Value::Object(record.to_map()))
                .collect(),
        ),
    );
    let signature = key.sign(&payload);
    payload.insert(SIGNATURE_FIELD.into(), json!(signature));
    atomic_write_bytes(
        &home.join(STORE_FILE),
        &canonical_discovery_payload(&payload),
        0o600,
    )
}

#[cfg(all(test, unix))]
#[path = "dashboard_reconnect_tests.rs"]
mod tests;
