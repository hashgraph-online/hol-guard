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

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_command::guard_sync_transport::{self as gst, OAuthRefreshOutcome, OAuthRefreshRequest};
use guard_command::local_supply_chain::{SupplyChainStore, Timestamp};
use guard_command::supply_chain_package_eval::EvalError;
use serde_json::{Map, Value};

use crate::oauth_refresh_circuit as circuit;
use crate::oauth_secret_authority;
use crate::oauth_token_claims as token_claims;

/// `runner.py:_OAUTH_INVALID_GRANT_MAX_ATTEMPTS` (:4112) — one edge-4xx retry.
const INVALID_GRANT_MAX_ATTEMPTS: u32 = 2;
/// `runner.py:_OAUTH_INVALID_GRANT_RETRY_DELAY_SECONDS` (:4113).
const INVALID_GRANT_RETRY_DELAY_SECONDS: f64 = 0.75;
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

/// Mirrors `_guard_oauth_reauthorization_message`; Python parks refresh with
/// `failure_kind = "rejected"` when the token endpoint rejected the request
/// with an error other than invalid_grant.
const REAUTHORIZATION_REQUIRED: &str =
    "Guard authorization expired. Run `hol-guard connect` to sign in again.";

/// The error a parked needs-reauthorization circuit reports. State written
/// before `failure_kind` existed keeps the revoked-grant error.
fn parked_reauthorization_message(rejected: bool) -> &'static str {
    if rejected {
        REAUTHORIZATION_REQUIRED
    } else {
        RECONNECT_AFTER_REVOKED
    }
}

/// A refresh that Cloudflare blocked or challenged is a network failure, not a
/// revoked sign-in, so it keeps its own reason instead of the reconnect copy.
fn failed_refresh_error(reason: String) -> EvalError {
    if guard_command::guard_sync_transport::is_cloud_edge_block_reason(&reason) {
        return EvalError::Validation(reason);
    }
    EvalError::Validation(format!("{RECONNECT_AFTER_REVOKED} {reason}"))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn now_timestamp() -> Timestamp {
    Timestamp::from_unix_micros(now_unix() * 1_000_000)
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

    // Refreshed claims win; otherwise the saved fields stay and the saved
    // token's claims only fill gaps when they agree with them.
    let saved = credentials.as_object().cloned().unwrap_or_default();
    let recovered = match access_token {
        Some(token) => decode_jwt_claims(token)
            .map(|claims| token_claims::binding(&claims, Some(issuer)))
            .unwrap_or_default(),
        None => saved
            .get("access_token")
            .and_then(Value::as_str)
            .and_then(decode_jwt_claims)
            .map(|claims| token_claims::binding_from_credentials(&claims, Some(issuer), &saved))
            .unwrap_or_default(),
    };
    let binding = token_claims::refresh_binding(&saved, &recovered, access_token.is_some());

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
    carry_binding_fields(&mut payload, &binding, credentials);
    carry_account_fields(
        &mut payload,
        credentials,
        package_firewall_entitlement,
        cloud_user_profile,
    );

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

/// Put the binding and the saved runtime metadata on the rotated credential
/// row. The binding already keeps the saved fields when no new access token
/// arrived, so a new token's binding never falls back to the previous one.
fn carry_binding_fields(
    payload: &mut Map<String, Value>,
    binding: &Map<String, Value>,
    credentials: &Value,
) {
    for key in ["grant_id", "machine_id", "device_id", "workspace_id"] {
        if let Some(v) = binding.get(key) {
            payload.insert(key.into(), v.clone());
        }
    }
    for key in ["supply_chain_plan_id", "runtime_id", "runtime_label"] {
        if let Some(v) = credentials.get(key) {
            payload.insert(key.into(), v.clone());
        }
    }
}

/// Put the account grant and profile on the rotated credential row. A refresh
/// that brings none keeps the saved ones, so a paid account does not lose its
/// entitlement expiry on rotation.
fn carry_account_fields(
    payload: &mut Map<String, Value>,
    credentials: &Value,
    package_firewall_entitlement: Option<&Value>,
    cloud_user_profile: Option<&Value>,
) {
    for key in [
        "supply_chain_entitlement_expires_at",
        "supply_chain_firewall",
    ] {
        if let Some(v) = package_firewall_entitlement
            .and_then(|ent| ent.get(key))
            .or_else(|| credentials.get(key))
            .filter(|v| !v.is_null())
        {
            payload.insert(key.into(), v.clone());
        }
    }
    if let Some(profile) = cloud_user_profile
        .or_else(|| credentials.get("cloud_user_profile"))
        .filter(|v| !v.is_null())
    {
        payload.insert("cloud_user_profile".into(), profile.clone());
    }
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

/// The wait the circuit parks a rate limit for: the server's `Retry-After`
/// when it is whole seconds (the circuit caps it at an hour), else the wait
/// the exchange already settled on.
fn rate_limit_seconds(header: Option<&str>, wait_seconds: f64) -> i64 {
    header
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(wait_seconds.ceil() as i64)
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

    // Circuit fast-fail before touching the endpoint. A circuit that cannot be
    // read fails closed rather than letting every caller probe the endpoint.
    let breaker = circuit::Circuit::new(store.guard_home(), circuit::Backoff::from_env());
    match breaker
        .check(refresh_token, now_timestamp())
        .map_err(EvalError::Internal)?
    {
        circuit::Check::Open => {}
        circuit::Check::Parked { rejected } => {
            return Err(EvalError::Validation(
                parked_reauthorization_message(rejected).to_owned(),
            ))
        }
        circuit::Check::RateLimited { wait_seconds } => {
            return Err(EvalError::Validation(format!(
                "Guard Cloud rate-limited the token refresh; retry in {wait_seconds}s."
            )))
        }
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
                ..
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
                // Recording is best effort: the refresh already succeeded.
                let _ = breaker.clear(now_timestamp());
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
            OAuthRefreshOutcome::RateLimited {
                wait_seconds: retry_after,
                retry_after: header,
            } => {
                let _ = breaker.record_rate_limit(
                    &attempt_refresh_token,
                    rate_limit_seconds(header.as_deref(), retry_after),
                    now_timestamp(),
                );
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
                // The caller waits before it performs the retry exchange.
                guard_command::egress_broker::pause(INVALID_GRANT_RETRY_DELAY_SECONDS);
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
            OAuthRefreshOutcome::Unreachable(reason) => {
                return Err(EvalError::Internal(format!(
                    "{} {reason}",
                    gst::OAUTH_REFRESH_UNREACHABLE
                )))
            }
            OAuthRefreshOutcome::Rejected(reason)
            | OAuthRefreshOutcome::Unusable(reason)
            | OAuthRefreshOutcome::Failed(reason) => return Err(failed_refresh_error(reason)),
        }
    }
    // Second invalid_grant post-rotation = genuinely revoked: record the
    // breaker and demand reauthorization.
    let _ = breaker.record_dead_grant(&attempt_refresh_token, circuit::REVOKED, now_timestamp());
    Err(EvalError::Validation(RECONNECT_AFTER_REVOKED.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rotated_row_keeps_only_the_computed_binding() {
        let saved = serde_json::json!({
            "grant_id": "grant-old",
            "machine_id": "machine-old",
            "device_id": "device-old",
            "workspace_id": "workspace-old",
            "runtime_id": "runtime-1",
        });
        let mut binding = Map::new();
        binding.insert("grant_id".into(), Value::String("grant-new".into()));
        let mut payload = Map::new();
        carry_binding_fields(&mut payload, &binding, &saved);
        assert_eq!(
            payload.get("grant_id"),
            Some(&Value::String("grant-new".into()))
        );
        for key in ["machine_id", "device_id", "workspace_id"] {
            assert!(payload.get(key).is_none(), "{key}");
        }
        assert_eq!(
            payload.get("runtime_id"),
            Some(&Value::String("runtime-1".into()))
        );
    }

    #[test]
    fn a_rotation_keeps_the_saved_account_grant_and_profile() {
        let saved = serde_json::json!({
            "supply_chain_firewall": true,
            "supply_chain_entitlement_expires_at": "2026-12-01T00:00:00Z",
            "cloud_user_profile": {"name": "synthetic"},
        });
        let mut payload = Map::new();
        carry_account_fields(&mut payload, &saved, None, None);
        assert_eq!(
            payload.get("supply_chain_firewall"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            payload.get("supply_chain_entitlement_expires_at"),
            saved.get("supply_chain_entitlement_expires_at")
        );
        assert_eq!(
            payload.get("cloud_user_profile"),
            saved.get("cloud_user_profile")
        );

        let granted = serde_json::json!({"supply_chain_firewall": false});
        let mut payload = Map::new();
        carry_account_fields(&mut payload, &saved, Some(&granted), None);
        assert_eq!(
            payload.get("supply_chain_firewall"),
            Some(&Value::Bool(false))
        );
    }

    #[test]
    fn a_refresh_blocked_by_cloudflare_is_not_reported_as_a_revoked_sign_in() {
        let edge = "Guard Cloud is unreachable from this network: Cloudflare in front of Guard Cloud challenged the request (HTTP 403).";
        match failed_refresh_error(edge.to_owned()) {
            EvalError::Validation(reason) => assert_eq!(reason, edge),
            other => panic!("unexpected error: {other:?}"),
        }
        match failed_refresh_error("HTTP Error 400".to_owned()) {
            EvalError::Validation(reason) => {
                assert_eq!(reason, format!("{RECONNECT_AFTER_REVOKED} HTTP Error 400"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn a_rate_limit_parks_for_the_server_retry_after() {
        assert_eq!(rate_limit_seconds(Some("1800"), 120.0), 1800);
        assert_eq!(rate_limit_seconds(Some(" 45 "), 120.0), 45);
        assert_eq!(
            rate_limit_seconds(Some("Wed, 21 Oct 2015 07:28:00 GMT"), 120.0),
            120
        );
        assert_eq!(rate_limit_seconds(None, 12.5), 13);
    }

    #[test]
    fn parked_circuit_reports_the_message_for_its_failure_kind() {
        assert_eq!(
            parked_reauthorization_message(true),
            REAUTHORIZATION_REQUIRED
        );
        assert_eq!(
            parked_reauthorization_message(false),
            RECONNECT_AFTER_REVOKED
        );
    }
}
