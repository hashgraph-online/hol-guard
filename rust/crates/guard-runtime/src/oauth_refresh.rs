//! Resident OAuth token-refresh orchestration — `runner.py` `_oauth_refresh_*`
//! cluster (:4140–:4385) ported to the resident crate so an expired access
//! token refreshes in-process instead of handing the call back to Python.
//!
//! Ownership split matches the Python contract:
//! - the *refresh call itself* lives in
//!   `guard_command::guard_sync_transport::refresh_guard_oauth_access_token`
//!   (transport + classification, returns `OAuthRefreshOutcome`),
//! - this module owns the *policy*: the circuit breaker that parks a known-dead
//!   or rate-limited grant, the bounded `invalid_grant` retry, and the
//!   credential-rotation persist under `oauth-refresh.lock`.
//!
//! Fail-closed throughout: any transport, classification, or persist failure
//! surfaces a reauthorizable `EvalError::Validation`; a confirmed dead grant
//! flips `needs_reauthorization` so the next caller demands re-sign-in rather
//! than hammering the token endpoint.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use guard_command::guard_sync_transport::{self as gst, OAuthRefreshOutcome, OAuthRefreshRequest};
use guard_command::local_supply_chain::{SupplyChainStore, Timestamp};
use guard_command::supply_chain_package_eval::EvalError;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::oauth_secret_authority;

/// `runner.py:_OAUTH_INVALID_GRANT_MAX_ATTEMPTS` (:4112) — one edge-4xx retry.
const INVALID_GRANT_MAX_ATTEMPTS: u32 = 2;
/// `runner.py:_OAUTH_INVALID_GRANT_RETRY_DELAY_SECONDS` (:4113).
const INVALID_GRANT_RETRY_DELAY_SECONDS: f64 = 0.75;
/// `runner.py:_OAUTH_REFRESH_CIRCUIT_STATE_KEY` (:4125).
const CIRCUIT_STATE_KEY: &str = "guard_oauth_refresh_circuit";
/// `runner.py:_OAUTH_REFRESH_CIRCUIT_FINGERPRINT_SALT_KEY` (:4133).
const CIRCUIT_SALT_KEY: &str = "guard_oauth_refresh_circuit_fingerprint_salt";
/// `runner.py:_OAUTH_REFRESH_CIRCUIT_FINGERPRINT_ITERATIONS` (:4137).
const CIRCUIT_FINGERPRINT_ITERATIONS: u32 = 600_000;
/// `runner.py:_OAUTH_REFRESH_CIRCUIT_BASE_BACKOFF_ENV` (:4126).
const BASE_BACKOFF_ENV: &str = "GUARD_OAUTH_REFRESH_CIRCUIT_BASE_BACKOFF_SECONDS";
/// `runner.py:_OAUTH_REFRESH_CIRCUIT_MAX_BACKOFF_ENV` (:4127).
const MAX_BACKOFF_ENV: &str = "GUARD_OAUTH_REFRESH_CIRCUIT_MAX_BACKOFF_SECONDS";
/// `runner.py:_OAUTH_REFRESH_CIRCUIT_DEFAULT_BASE_BACKOFF_SECONDS` (:4128).
const BASE_BACKOFF_DEFAULT: f64 = 30.0;
/// `runner.py:_OAUTH_REFRESH_CIRCUIT_DEFAULT_MAX_BACKOFF_SECONDS` (:4129).
const MAX_BACKOFF_DEFAULT: f64 = 300.0;
/// `runner.py` `_oauth_local_credentials_state_key` — the
/// `oauth_local_credentials` sync payload.
const CREDENTIALS_STATE_KEY: &str = "oauth_local_credentials";
/// Lock file for the rotation persist — serializes the secret rewrite +
/// re-fingerprint across concurrent resident / Python writers.
const REFRESH_LOCK_NAME: &str = "oauth-refresh.lock";
const CREDENTIAL_LOCK_NAME: &str = "oauth-credentials.lock";
const OAUTH_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

fn acquire_lock(path: &Path, timeout: Duration) -> Result<File, EvalError> {
    let f = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .map_err(|e| EvalError::Validation(format!("Guard OAuth lock open failed: {e}")))?;
    let deadline = Instant::now() + timeout;
    loop {
        match fs2::FileExt::try_lock_exclusive(&f) {
            Ok(()) => return Ok(f),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => {
                return Err(EvalError::Validation(
                    "Guard OAuth credential rotation is held by another process; retry.".into(),
                ));
            }
        }
    }
}
/// Reauth message mirrors `_guard_oauth_reconnect_after_revoked_message` so a
/// propagated dead-grant matches the Python surface byte-for-byte (the retry
/// loop keys off the exact string).
const RECONNECT_AFTER_REVOKED: &str =
    "Guard Cloud sign-in is no longer valid. Reconnect Guard Cloud to continue.";

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn now_timestamp() -> Timestamp {
    Timestamp::from_unix_micros(now_unix() * 1_000_000)
}

fn circuit_backoff_seconds(env_key: &str, default: f64) -> f64 {
    std::env::var(env_key)
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(default)
}

/// `runner.py:_oauth_refresh_circuit_salt` (:4140) — read or mint a persisted
/// per-installation salt so two racing writers converge on the same fingerprint.
fn circuit_salt(store: &dyn SupplyChainStore) -> Vec<u8> {
    let encoded = store
        .get_sync_payload(CIRCUIT_SALT_KEY)
        .and_then(|p| p.get("salt").and_then(Value::as_str).map(str::to_owned));
    if let Some(encoded) = encoded.as_deref() {
        if let Ok(salt) = Base64::decode_vec(encoded) {
            return salt;
        }
    }
    let mut salt = [0u8; 32];
    if getrandom::fill(&mut salt).is_err() {
        // Deterministic fallback only when the OS RNG is unavailable; the
        // fingerprint is a lookup key, not a credential, so a time+token mixed
        // value keeps it usable without being reversible.
        let mut seed = Sha256::new();
        seed.update(now_unix().to_be_bytes());
        seed.update(store.guard_home().to_string_lossy().as_bytes());
        return seed.finalize().to_vec();
    }
    let mut payload = Map::new();
    payload.insert(
        "salt".to_owned(),
        Value::String(Base64::encode_string(&salt)),
    );
    store.set_sync_payload(CIRCUIT_SALT_KEY, &Value::Object(payload));
    // Two racing processes can both land here; converge on the winning write.
    store
        .get_sync_payload(CIRCUIT_SALT_KEY)
        .and_then(|p| p.get("salt").and_then(Value::as_str).map(str::to_owned))
        .and_then(|e| Base64::decode_vec(&e).ok())
        .unwrap_or_else(|| salt.to_vec())
}

/// `runner.py:_oauth_refresh_circuit_fingerprint` (:4164) — PBKDF2-HMAC-SHA256,
/// truncated to 32 hex chars; a non-reversible lookup key, not a credential.
fn circuit_fingerprint(refresh_token: &str, salt: &[u8]) -> String {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        refresh_token.as_bytes(),
        salt,
        CIRCUIT_FINGERPRINT_ITERATIONS,
        &mut out,
    );
    hex::encode(out)[..32].to_owned()
}

fn load_circuit(store: &dyn SupplyChainStore) -> Value {
    store
        .get_sync_payload(CIRCUIT_STATE_KEY)
        .unwrap_or(Value::Object(Map::new()))
}

fn save_circuit(store: &dyn SupplyChainStore, state: Value) {
    store.set_sync_payload(CIRCUIT_STATE_KEY, &state);
}

fn clear_circuit(store: &dyn SupplyChainStore) {
    save_circuit(store, Value::Object(Map::new()));
}

/// `runner.py:_oauth_refresh_circuit_check` (:4199) — fast-fail while a
/// known-dead or rate-limited grant is parked. Clears when the stored refresh
/// token no longer matches the fingerprint that failed (a peer re-paired).
/// Returns `Err(Validation)` on dead-grant, `Ok(Some(wait_s))` on rate-limit
/// backoff so the caller can surface a bounded wait.
fn circuit_check(
    store: &dyn SupplyChainStore,
    refresh_token: &str,
) -> Result<Option<f64>, EvalError> {
    let state = load_circuit(store);
    let fingerprint = state
        .get("refresh_token_fingerprint")
        .and_then(Value::as_str);
    let Some(fingerprint) = fingerprint else {
        return Ok(None);
    };
    if fingerprint != circuit_fingerprint(refresh_token, &circuit_salt(store)) {
        clear_circuit(store);
        return Ok(None);
    }
    let next_allowed = state
        .get("next_refresh_allowed_at")
        .and_then(Value::as_str)
        .and_then(guard_command::local_supply_chain::parse_timestamp);
    let now = now_timestamp();
    let next_allowed_unix = next_allowed.map(|t| t.unix_seconds());
    let now_unix_s = now.unix_seconds();
    if next_allowed_unix.is_none() || next_allowed_unix.unwrap() <= now_unix_s {
        return Ok(None);
    }
    if state
        .get("needs_reauthorization")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(EvalError::Validation(RECONNECT_AFTER_REVOKED.to_owned()));
    }
    let remaining = (next_allowed_unix.unwrap() - now_unix_s).max(1) as f64;
    Ok(Some(remaining))
}

/// `runner.py:_oauth_refresh_circuit_record_dead_grant` (:4228) — flip the
/// binding to needs-reauthorization and park refresh behind the bounded backoff.
fn circuit_record_dead_grant(store: &dyn SupplyChainStore, refresh_token: &str) {
    let fingerprint = circuit_fingerprint(refresh_token, &circuit_salt(store));
    let mut state = load_circuit(store);
    if state
        .get("refresh_token_fingerprint")
        .and_then(Value::as_str)
        != Some(fingerprint.as_str())
    {
        state = Value::Object(Map::new());
    }
    let failures = state
        .get("consecutive_failures")
        .and_then(Value::as_i64)
        .unwrap_or(0)
        + 1;
    let previous_backoff = state.get("backoff_seconds").and_then(Value::as_f64);
    let backoff = if failures >= 2 {
        previous_backoff
            .map(|b| {
                (b * 2.0).min(circuit_backoff_seconds(
                    MAX_BACKOFF_ENV,
                    MAX_BACKOFF_DEFAULT,
                ))
            })
            .unwrap_or_else(|| circuit_backoff_seconds(BASE_BACKOFF_ENV, BASE_BACKOFF_DEFAULT))
    } else {
        circuit_backoff_seconds(BASE_BACKOFF_ENV, BASE_BACKOFF_DEFAULT)
    };
    let next_allowed = now_timestamp().add_seconds_f64(backoff).isoformat();
    save_circuit(
        store,
        serde_json::json!({
            "refresh_token_fingerprint": fingerprint,
            "consecutive_failures": failures,
            "needs_reauthorization": true,
            "notice_sent": state.get("notice_sent").and_then(Value::as_bool).unwrap_or(false),
            "backoff_seconds": backoff,
            "next_refresh_allowed_at": next_allowed,
        }),
    );
}

/// `runner.py:_oauth_refresh_circuit_record_rate_limit` (:4278) — park refresh
/// until the server-provided Retry-After elapses (bounded by the max backoff).
fn circuit_record_rate_limit(store: &dyn SupplyChainStore, refresh_token: &str, retry_after: f64) {
    let fingerprint = circuit_fingerprint(refresh_token, &circuit_salt(store));
    let mut state = load_circuit(store);
    if state
        .get("refresh_token_fingerprint")
        .and_then(Value::as_str)
        != Some(fingerprint.as_str())
    {
        state = Value::Object(Map::new());
    }
    let bounded = retry_after.max(1.0).min(circuit_backoff_seconds(
        MAX_BACKOFF_ENV,
        MAX_BACKOFF_DEFAULT,
    ));
    let next_allowed = now_timestamp().add_seconds_f64(bounded).isoformat();
    save_circuit(
        store,
        serde_json::json!({
            "refresh_token_fingerprint": fingerprint,
            "consecutive_failures": state.get("consecutive_failures").and_then(Value::as_i64).unwrap_or(0),
            "needs_reauthorization": state.get("needs_reauthorization").and_then(Value::as_bool).unwrap_or(false),
            "notice_sent": state.get("notice_sent").and_then(Value::as_bool).unwrap_or(false),
            "backoff_seconds": bounded,
            "next_refresh_allowed_at": next_allowed,
        }),
    );
}

/// `runner.py:_oauth_refresh_circuit_record_success` — a successful refresh
/// clears the parked backoff so the next expiry retries immediately.
fn circuit_record_success(store: &dyn SupplyChainStore, refresh_token: &str) {
    let fingerprint = circuit_fingerprint(refresh_token, &circuit_salt(store));
    let state = load_circuit(store);
    if state
        .get("refresh_token_fingerprint")
        .and_then(Value::as_str)
        == Some(fingerprint.as_str())
    {
        clear_circuit(store);
    }
}

/// `oauth_token_claims.py:oauth_binding_metadata` (:38) — recover the
/// grant/machine/workspace/device binding from the fresh access token's claims.
/// Returns `None` when the token's issuer disagrees with the stored issuer or
/// any required claim is absent.
fn binding_from_access_token(access_token: &str, issuer: &str) -> Option<Map<String, Value>> {
    let claims = decode_jwt_claims(access_token)?;
    let token_issuer = claims.get("iss").and_then(Value::as_str);
    if let Some(t) = token_issuer {
        if t.trim_end_matches('/') != issuer.trim_end_matches('/') {
            return None;
        }
    }
    let claim_str = |keys: &[&str]| -> Option<String> {
        keys.iter()
            .find_map(|k| claims.get(*k).and_then(Value::as_str))
            .map(str::to_owned)
    };
    let grant_id = claim_str(&["grant", "grantId"]);
    let machine_id = claim_str(&["machine", "machineId"]);
    let workspace_id = claim_str(&["workspace", "workspaceId"]);
    let device_id = claims
        .get("device")
        .and_then(|d| d.get("id").or_else(|| claims.get("deviceId")))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| claim_str(&["deviceId"]));
    if grant_id.is_none() || machine_id.is_none() || workspace_id.is_none() {
        return None;
    }
    let mut binding = Map::new();
    binding.insert("grant_id".into(), Value::String(grant_id.unwrap()));
    binding.insert("machine_id".into(), Value::String(machine_id.unwrap()));
    binding.insert("workspace_id".into(), Value::String(workspace_id.unwrap()));
    if let Some(d) = device_id {
        binding.insert("device_id".into(), Value::String(d));
    }
    Some(binding)
}

/// `runner.py:_oauth_refresh_binding` — prefer refreshed claims; otherwise
/// retain stored credential fields and fill gaps from recovery.
fn refresh_binding(
    credentials: &Value,
    recovered: &Map<String, Value>,
    refreshed: bool,
) -> Map<String, Value> {
    let mut binding = Map::new();
    for key in ["device_id", "grant_id", "machine_id", "workspace_id"] {
        let value = if refreshed {
            recovered.get(key).cloned()
        } else {
            credentials
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .map(Value::String)
                .or_else(|| recovered.get(key).cloned())
        };
        if let Some(v) = value {
            binding.insert(key.to_owned(), v);
        }
    }
    binding
}

/// Decode the JWT payload segment into a claims map (no signature check — the
/// token was just returned over the authenticated TLS channel).
fn decode_jwt_claims(token: &str) -> Option<Map<String, Value>> {
    let seg = token.split('.').nth(1)?.trim_end_matches('=');
    let bytes = Base64UrlUnpadded::decode_vec(seg).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.as_object().cloned()
}

/// `runner.py:_persist_rotated_oauth_refresh_token` (:4454) —
/// `set_oauth_local_credentials` written under the `oauth-refresh.lock`
/// file lock so concurrent resident / Python writers serialize the secret
/// rewrite + record re-fingerprint. `refresh_token` is the rotated grant (or
/// the unchanged one when the endpoint did not rotate); `access_token` /
/// `access_token_expires_at` refresh the cached token fields.
///
/// Parity note: the Rust persist writes only `EncryptedFileSecretStore` (the
/// production fallback store) — the system-keyring leg is intentionally not
/// ported (stage B), matching the same deferred-backend decision as the
/// credential *read* authority in `package_authority_op.rs`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_rotated_oauth_refresh_token(
    store: &dyn SupplyChainStore,
    credentials: &Value,
    package_firewall_entitlement: Option<&Value>,
    cloud_user_profile: Option<&Value>,
    refresh_token: &str,
    access_token: Option<&str>,
    access_token_expires_at: Option<&str>,
) -> Result<(), EvalError> {
    let issuer = credentials.get("issuer").and_then(Value::as_str);
    let client_id = credentials.get("client_id").and_then(Value::as_str);
    let dpop_private_key_pem = credentials
        .get("dpop_private_key_pem")
        .and_then(Value::as_str);
    let dpop_public_jwk = credentials
        .get("dpop_public_jwk")
        .and_then(Value::as_object);
    let dpop_public_jwk_thumbprint = credentials
        .get("dpop_public_jwk_thumbprint")
        .and_then(Value::as_str);
    let (issuer, client_id, dpop_private_key_pem, dpop_public_jwk, dpop_public_jwk_thumbprint) =
        match (
            issuer,
            client_id,
            dpop_private_key_pem,
            dpop_public_jwk,
            dpop_public_jwk_thumbprint,
        ) {
            (Some(i), Some(c), Some(pk), Some(jwk), Some(tp)) => (i, c, pk, jwk, tp),
            _ => return Err(EvalError::Validation(RECONNECT_AFTER_REVOKED.to_owned())),
        };

    // `oauth_refresh_binding` — prefer refreshed claims, fall back to stored.
    let recovered = access_token
        .and_then(|t| binding_from_access_token(t, issuer))
        .unwrap_or_else(|| {
            credentials
                .get("access_token")
                .and_then(Value::as_str)
                .and_then(|t| binding_from_access_token(t, issuer))
                .unwrap_or_default()
        });
    let binding = refresh_binding(credentials, &recovered, access_token.is_some());

    let guard_home = store.guard_home().to_path_buf();
    let _credential_lock =
        acquire_lock(&guard_home.join(CREDENTIAL_LOCK_NAME), OAUTH_LOCK_TIMEOUT)?;

    // Build the secret payload the same way `set_oauth_local_credentials` does:
    // canonical sorted-compact JSON of the secret material.
    let mut secret_payload = Map::new();
    secret_payload.insert(
        "refresh_token".into(),
        Value::String(refresh_token.to_owned()),
    );
    secret_payload.insert(
        "dpop_private_key_pem".into(),
        Value::String(dpop_private_key_pem.to_owned()),
    );
    secret_payload.insert(
        "dpop_public_jwk".into(),
        Value::Object(dpop_public_jwk.clone()),
    );
    secret_payload.insert(
        "dpop_public_jwk_thumbprint".into(),
        Value::String(dpop_public_jwk_thumbprint.to_owned()),
    );
    if let Some(at) = access_token {
        secret_payload.insert("access_token".into(), Value::String(at.to_owned()));
    }
    if let Some(eat) = access_token_expires_at {
        secret_payload.insert(
            "access_token_expires_at".into(),
            Value::String(eat.to_owned()),
        );
    }
    // Canonical sorted-compact JSON (`json.dumps(sort_keys=True, separators)`).
    let secret_json = canonical_json(&secret_payload);
    let secret_hash = oauth_secret_authority::secret_fingerprint(&secret_json)
        .map_err(|e| EvalError::Validation(format!("{RECONNECT_AFTER_REVOKED} {e}")))?;

    // The record: carry the stored binding metadata forward, refresh the
    // secret ref/fingerprint, and overlay the entitlement/profile fields the
    // caller already had.
    let mut payload = Map::new();
    payload.insert("issuer".into(), Value::String(issuer.to_owned()));
    payload.insert("client_id".into(), Value::String(client_id.to_owned()));
    let secret_ref = credentials
        .get("credentials_ref")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            crate::policy_integrity_resolver::build_scoped_secret_ref(
                "guard-oauth-local-credentials",
                &guard_home,
            )
        });
    payload.insert("credentials_ref".into(), Value::String(secret_ref.clone()));
    payload.insert("credentials_sha256".into(), Value::String(secret_hash));
    for key in [
        "grant_id",
        "machine_id",
        "device_id",
        "workspace_id",
        "supply_chain_plan_id",
        "runtime_id",
        "runtime_label",
    ] {
        if let Some(v) = binding
            .get(key)
            .cloned()
            .or_else(|| credentials.get(key).cloned())
        {
            payload.insert(key.into(), v);
        }
    }
    if let Some(ent) = package_firewall_entitlement {
        for key in [
            "supply_chain_entitlement_expires_at",
            "supply_chain_firewall",
        ] {
            if let Some(v) = ent.get(key).cloned() {
                payload.insert(key.into(), v);
            }
        }
    }
    if let Some(profile) = cloud_user_profile {
        payload.insert("cloud_user_profile".into(), profile.clone());
    }

    let mut secret_store =
        crate::encrypted_secret_store::EncryptedFileSecretStore::new(&guard_home);
    secret_store.ensure_ready().map_err(|e| {
        EvalError::Validation(format!(
            "{RECONNECT_AFTER_REVOKED} secret store unavailable: {e}"
        ))
    })?;
    secret_store
        .set_secret(&secret_ref, &secret_json)
        .map_err(|e| {
            EvalError::Validation(format!(
                "{RECONNECT_AFTER_REVOKED} secret write failed: {e}"
            ))
        })?;
    store.set_sync_payload(CREDENTIALS_STATE_KEY, &Value::Object(payload));
    Ok(())
}

/// Canonical sorted-compact JSON — `json.dumps(payload, sort_keys=True,
/// separators=(",", ":"))`. serde_json object iteration is already sorted
/// (BTreeMap-backed `Map`), so a plain `to_string` matches.
fn canonical_json(payload: &Map<String, Value>) -> String {
    Value::Object(payload.clone()).to_string()
}

/// The refresh orchestration result handed back to
/// `ResidentGuardSyncRunner::resolve_guard_sync_auth_context`.
pub(crate) struct RefreshedAuth {
    pub access_token: String,
}

/// `runner.py:_refresh_guard_oauth_access_token` (:4350) — the circuit-checked,
/// invalid-grant-retried, rotation-persisted refresh. Returns the fresh access
/// token on success; `Err(Validation)` on dead grant or reauthorizable failure.
pub(crate) fn refresh_oauth_access_token(
    store: &dyn SupplyChainStore,
    credentials: &Value,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
    dpop_key_material: &Map<String, Value>,
    credential_reloader: &dyn Fn() -> Option<(String, Map<String, Value>)>,
) -> Result<RefreshedAuth, EvalError> {
    use EvalError;

    // Circuit fast-fail before touching the endpoint.
    if let Some(wait) = circuit_check(store, refresh_token)? {
        return Err(EvalError::Validation(format!(
            "Guard Cloud rate-limited the token refresh; retry in {wait:.0}s."
        )));
    }

    // `runner.py:_SYNC_HTTP_TIMEOUT_SECONDS` (:799).
    let timeout = 20.0f64;
    let private_key_pem = dpop_key_material
        .get("private_key_pem")
        .and_then(Value::as_str)
        .ok_or_else(|| EvalError::Validation(RECONNECT_AFTER_REVOKED.to_owned()))?;
    let public_jwk = dpop_key_material
        .get("public_jwk")
        .and_then(Value::as_object)
        .ok_or_else(|| EvalError::Validation(RECONNECT_AFTER_REVOKED.to_owned()))?;
    let algorithm = dpop_key_material
        .get("algorithm")
        .and_then(Value::as_str)
        .unwrap_or("ES256");

    let _refresh_lock = acquire_lock(
        &store.guard_home().join(REFRESH_LOCK_NAME),
        OAUTH_LOCK_TIMEOUT,
    )?;

    let mut attempt_refresh_token = refresh_token.to_owned();
    let mut attempt_private_key_pem = private_key_pem.to_owned();
    let mut attempt_public_jwk = public_jwk.clone();
    if let Some((rt, mat)) = credential_reloader() {
        let pk = mat
            .get("private_key_pem")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let pj = mat.get("public_jwk").and_then(Value::as_object).cloned();
        if let (Some(pk), Some(pj)) = (pk, pj) {
            attempt_refresh_token = rt;
            attempt_private_key_pem = pk;
            attempt_public_jwk = pj;
        } else {
            attempt_refresh_token = rt;
        }
    }
    let mut nonce: Option<String> = None;
    let mut nonce_retry_count: u32 = 0;

    let mut attempt: u32 = 0;
    loop {
        let req = OAuthRefreshRequest {
            token_endpoint,
            client_id,
            refresh_token: &attempt_refresh_token,
            dpop_private_key_pem: &attempt_private_key_pem,
            dpop_public_jwk: &attempt_public_jwk,
            algorithm,
            nonce: nonce.as_deref(),
            timeout_seconds: timeout,
            now_unix: now_unix(),
        };
        match gst::refresh_guard_oauth_access_token(&req) {
            OAuthRefreshOutcome::Refreshed {
                access_token,
                rotation_refresh_token,
                access_token_expires_at,
            } => {
                let effective_refresh =
                    rotation_refresh_token.unwrap_or_else(|| attempt_refresh_token.clone());
                persist_rotated_oauth_refresh_token(
                    store,
                    credentials,
                    None,
                    None,
                    &effective_refresh,
                    Some(&access_token),
                    access_token_expires_at.as_deref(),
                )?;
                circuit_record_success(store, &effective_refresh);
                return Ok(RefreshedAuth { access_token });
            }
            OAuthRefreshOutcome::NonceChallenge(challenge) => {
                if Some(challenge.as_str()) == nonce.as_deref() || nonce_retry_count >= 3 {
                    return Err(EvalError::Validation(RECONNECT_AFTER_REVOKED.to_owned()));
                }
                nonce = Some(challenge);
                nonce_retry_count += 1;
                continue; // same attempt — re-sign with the challenge nonce
            }
            OAuthRefreshOutcome::RateLimited(retry_after) => {
                circuit_record_rate_limit(store, &attempt_refresh_token, retry_after);
                return Err(EvalError::Validation(format!(
                    "Guard Cloud rate-limited the token refresh; retry in {retry_after:.0}s."
                )));
            }
            OAuthRefreshOutcome::DeadGrant => {
                // `_refresh_guard_oauth_access_token` — an edge-4xx invalid_grant
                // can be a rotation race; retry once with a reloaded credential
                // before declaring the grant genuinely dead.
                attempt += 1;
                if attempt >= INVALID_GRANT_MAX_ATTEMPTS {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs_f64(
                    INVALID_GRANT_RETRY_DELAY_SECONDS,
                ));
                if let Some((rt, mat)) = credential_reloader() {
                    let pk = mat
                        .get("private_key_pem")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let pj = mat.get("public_jwk").and_then(Value::as_object).cloned();
                    if let (Some(pk), Some(pj)) = (pk, pj) {
                        attempt_refresh_token = rt;
                        attempt_private_key_pem = pk;
                        attempt_public_jwk = pj;
                    } else {
                        attempt_refresh_token = rt;
                    }
                }
                continue;
            }
            OAuthRefreshOutcome::Failed(reason) => {
                return Err(EvalError::Validation(format!(
                    "{RECONNECT_AFTER_REVOKED} {reason}"
                )));
            }
        }
    }
    // Second invalid_grant post-rotation = genuinely revoked: record the
    // breaker and demand reauthorization.
    circuit_record_dead_grant(store, &attempt_refresh_token);
    Err(EvalError::Validation(RECONNECT_AFTER_REVOKED.to_owned()))
}
