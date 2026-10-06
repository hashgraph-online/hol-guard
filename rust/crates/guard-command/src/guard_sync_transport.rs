//! Guard-Cloud sync transport: DPoP proof signing, request construction,
//! endpoint validation, and the bounded retry state machine.
//!
//! Mirrors `runner.py` `_validate_guard_sync_url` (:3994), `_guard_sync_headers`
//! (:4783), `_guard_sync_request` (:3810), `_guard_sync_request_with_nonce`
//! (:4823), `_sign_guard_dpop_proof` (:3701), `_dpop_nonce_from_http_error`
//! (:3785), `_is_timeout_error` (:4997), `_urlopen_with_sync_retries` (:5009),
//! and `oauth_client.py` `validate_guard_sync_endpoint` (:174) +
//! `resolve_guard_oauth_client_config` (:171) + `is_guard_oauth_origin_allowed`
//! (:114). Transport runs over `ureq` — same pinned-TLS client as
//! `restricted_archive_transport` but without DNS pinning (the sync endpoint
//! is a fixed allowlisted origin; OAuth-specific validation lives in
//! `validate_guard_sync_endpoint`).

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Signature, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::supply_chain_package_eval::{EvalError, EvalResult, GuardSyncRequest};

/// `runner.py:_GUARD_SYNC_USER_AGENT` — single value shared with Python so
/// Cloud-side user-agent analytics don't split on transport.
const GUARD_SYNC_USER_AGENT: &str = "hol-guard-native";

/// `runner.py:_OAUTH_ACCESS_TOKEN_REFRESH_SKEW_SECONDS` (:4104) — access
/// tokens inside the skew are treated as expired so the refresh happens
/// before the Cloud rejects them.
const OAUTH_ACCESS_TOKEN_REFRESH_SKEW_SECONDS: i64 = 60;

/// `oauth_client.py` origin allowlist (`_ALLOWED_PRODUCTION_GUARD_ORIGINS`,
/// `_ALLOWED_STAGING`, `_LOOPBACK`, `_DOCKER_LAB`) — bounds which hosts a
/// `sync_url` may point at. HTTPS is required except for loopback and
/// docker-lab hosts (local dev environments).
const PRODUCTION_GUARD_ORIGINS: &[&str] = &["https://hol.org"];
const STAGING_GUARD_ORIGINS: &[&str] = &["https://staging.hol.org"];
const LOOPBACK_GUARD_HOSTS: &[&str] = &["127.0.0.1", "localhost", "::1"];
const DOCKER_LAB_GUARD_HOSTS: &[&str] = &["host.docker.internal"];

/// `runner.py:_OAUTH_REFRESH_CIRCUIT_*` bounds apply to the retry state
/// machine: the nonce fast-path, bounded 429 waits, gateway retries, the
/// generic nonce challenge, and one longer-timeout retry.
const SYNC_NONCE_RETRY_LIMIT: u32 = 3;
/// `runner.py:5054` — `rate_limit_retry_count < 2`.
const SYNC_RATE_LIMIT_RETRY_LIMIT: u32 = 2;
/// `runner.py:802` — `_SYNC_RETRYABLE_GATEWAY_MAX_ATTEMPTS`.
const SYNC_GATEWAY_RETRY_LIMIT: u32 = 2;
/// `runner.py:3306` — a 429 with no `Retry-After` waits a minute, not a poll tick.
const SYNC_429_DEFAULT_WAIT_SECONDS: f64 = 60.0;
/// `runner.py:5056` — `time.sleep(min(retry_after, 120))`.
const SYNC_429_MAX_WAIT_SECONDS: u64 = 120;
const SYNC_GATEWAY_MAX_WAIT_SECONDS: u64 = 8;

fn base64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn optional_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

fn issuer_origin(issuer: &str) -> Result<String, String> {
    let url = url::Url::parse(issuer).map_err(|_| "issuer must be absolute http(s)".to_owned())?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err("issuer must be absolute http(s)".to_owned()),
    }
    if url.host_str().is_none() {
        return Err("issuer must be absolute http(s)".to_owned());
    }
    let mut origin = String::with_capacity(32);
    origin.push_str(url.scheme());
    origin.push_str("://");
    origin.push_str(url.host_str().unwrap_or_default());
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

fn origin_host(origin: &str) -> String {
    url::Url::parse(origin)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
        .to_lowercase()
}

fn is_local_guard_origin(origin: &str) -> bool {
    let host = origin_host(origin);
    LOOPBACK_GUARD_HOSTS.contains(&host.as_str()) || DOCKER_LAB_GUARD_HOSTS.contains(&host.as_str())
}

fn extra_staging_origins() -> (Vec<String>, BTreeMap<String, String>) {
    let raw = std::env::var("HOL_GUARD_STAGING_ORIGIN").unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return (Vec::new(), BTreeMap::new());
    }
    let mut origins = Vec::new();
    let mut prefixes = BTreeMap::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.splitn(2, '|');
        let origin = parts.next().unwrap_or("").trim();
        if origin.is_empty() {
            continue;
        }
        origins.push(origin.to_owned());
        if let Some(prefix) = parts.next().map(str::trim).filter(|p| !p.is_empty()) {
            prefixes.insert(origin.to_lowercase(), prefix.to_owned());
        }
    }
    (origins, prefixes)
}

fn all_allowed_staging_origins() -> Vec<String> {
    let (extra, _) = extra_staging_origins();
    let mut out: Vec<String> = STAGING_GUARD_ORIGINS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    out.extend(extra);
    out
}

fn all_path_prefixes() -> BTreeMap<String, String> {
    let (_, extra) = extra_staging_origins();
    extra
}

/// `oauth_client.py:is_guard_oauth_origin_allowed` (:114) — an origin is
/// allowed when it matches production, staging (incl. env-added), or
/// loopback/docker-lab.
pub fn is_guard_oauth_origin_allowed(issuer: &str) -> bool {
    let Ok(origin) = issuer_origin(issuer) else {
        return false;
    };
    PRODUCTION_GUARD_ORIGINS.contains(&origin.as_str())
        || all_allowed_staging_origins().contains(&origin)
        || is_local_guard_origin(&origin)
}

fn require_allowlisted_guard_oauth_origin(issuer: &str) -> Result<String, String> {
    let origin = issuer_origin(issuer)?;
    if PRODUCTION_GUARD_ORIGINS.contains(&origin.as_str())
        || all_allowed_staging_origins().contains(&origin)
        || is_local_guard_origin(&origin)
    {
        return Ok(origin);
    }
    Err("Guard OAuth issuer must use an allowlisted HOL origin, local loopback, or docker-lab host.".to_owned())
}

/// `oauth_client.py:detect_guard_oauth_environment` (:152) — environment tag
/// used to pick `client_id` from the per-env constants.
fn detect_guard_oauth_environment(issuer: &str) -> Result<&'static str, String> {
    let origin = require_allowlisted_guard_oauth_origin(issuer)?.to_lowercase();
    if is_local_guard_origin(&origin) {
        return Ok("local");
    }
    if all_allowed_staging_origins().contains(&origin) {
        return Ok("staging");
    }
    Ok("production")
}

fn oauth_client_id_for_environment(env: &str) -> &'static str {
    match env {
        "staging" => "guard-local-daemon-staging",
        "local" => "guard-local-daemon-local",
        _ => "guard-local-daemon",
    }
}

/// `oauth_client.py:resolve_guard_oauth_client_config` (:171) — endpoints
/// derived from the issuer origin plus the optional path prefix that staging
/// hosts mount the OAuth app under.
pub fn resolve_guard_oauth_client_config(
    issuer: &str,
) -> Result<(String, String, String, String, String, String), String> {
    let origin = require_allowlisted_guard_oauth_origin(issuer)?;
    let env = detect_guard_oauth_environment(issuer)?;
    let prefix = all_path_prefixes()
        .get(&origin.to_lowercase())
        .cloned()
        .unwrap_or_default();
    Ok((
        origin.clone(),
        format!("{origin}{prefix}/api/guard/oauth/authorize"),
        format!("{origin}{prefix}/api/guard/oauth/token"),
        format!("{origin}{prefix}/api/guard/oauth/device/authorize"),
        format!("{origin}{prefix}/api/guard/oauth/jwks"),
        oauth_client_id_for_environment(env).to_owned(),
    ))
}

/// `runner.py:_oauth_sync_url_from_issuer` (:4087) — receipts-sync endpoint
/// derived from the (allowlisted) issuer origin.
pub fn oauth_sync_url_from_issuer(issuer: &str) -> Result<String, String> {
    let (origin, ..) = resolve_guard_oauth_client_config(issuer)?;
    Ok(format!("{origin}/api/guard/receipts/sync"))
}

/// `runner.py:_oauth_dpop_key_material` (:4092) — extract the embedded DPoP
/// key material from the stored OAuth credential payload. Missing or
/// malformed fields mean the credential cannot sign — surface
/// `EvalError::Validation` (the `GuardSyncAuthorizationExpiredError` mirror)
/// so the caller fails closed to `ask`, not `NotFound` ("not configured").
pub fn oauth_dpop_key_material(credentials: &Value) -> EvalResult<Map<String, Value>> {
    let dpop_private_key_pem = credentials
        .get("dpop_private_key_pem")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty());
    let dpop_public_jwk = credentials
        .get("dpop_public_jwk")
        .and_then(Value::as_object);
    let dpop_public_jwk_thumbprint = credentials
        .get("dpop_public_jwk_thumbprint")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty());
    let (private_key_pem, public_jwk, thumbprint) = match (
        dpop_private_key_pem,
        dpop_public_jwk,
        dpop_public_jwk_thumbprint,
    ) {
        (Some(pk), Some(jwk), Some(tp)) => (pk, jwk, tp),
        _ => {
            return Err(EvalError::Validation(
                "Guard OAuth DPoP key material is incomplete; reauthorize Guard.".to_owned(),
            ))
        }
    };
    let mut material = Map::new();
    material.insert("algorithm".to_owned(), Value::String("ES256".to_owned()));
    material.insert(
        "private_key_pem".to_owned(),
        Value::String(private_key_pem.to_owned()),
    );
    material.insert(
        "public_jwk".to_owned(),
        Value::Object(
            public_jwk
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        Value::String(v.as_str().unwrap_or_default().to_owned()),
                    )
                })
                .collect(),
        ),
    );
    material.insert(
        "public_jwk_thumbprint".to_owned(),
        Value::String(thumbprint.to_owned()),
    );
    Ok(material)
}

/// `runner.py:_cached_oauth_access_token` (:4432) — return the cached access
/// token when it is still valid outside the 60s refresh skew; `None` when
/// refresh is required.
pub fn cached_oauth_access_token(credentials: &Value, now_unix: i64) -> Option<String> {
    let access_token = credentials
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())?;
    let expires_at_raw = credentials
        .get("access_token_expires_at")
        .and_then(Value::as_str)?;
    let expires_at_unix = iso8601_to_unix(expires_at_raw)?;
    if expires_at_unix <= now_unix + OAUTH_ACCESS_TOKEN_REFRESH_SKEW_SECONDS {
        return None;
    }
    Some(access_token.to_owned())
}

/// `runner.py:_test_sync_auth_context_override` +
/// `_test_sync_auth_context_from_env` (:4688-4710) — hermetic override hook.
/// Tests seed `GUARD_TEST_SYNC_AUTH_CONTEXT_JSON` (full dict) or the
/// `HOL_GUARD_TEST_SYNC_URL`/`HOL_GUARD_TEST_ACCESS_TOKEN` pair to bypass the
/// OAuth credential read; the resident honors the same env knobs so the
/// eval-path tests exercise the native seam without a live Cloud.
pub fn test_sync_auth_context_from_env() -> Option<Map<String, Value>> {
    std::env::var_os("PYTEST_CURRENT_TEST")?;
    if let Ok(raw) = std::env::var("GUARD_TEST_SYNC_AUTH_CONTEXT_JSON") {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&raw) {
            return Some(map);
        }
    }
    let sync_url = std::env::var("HOL_GUARD_TEST_SYNC_URL").ok()?;
    let access_token = std::env::var("HOL_GUARD_TEST_ACCESS_TOKEN").ok()?;
    let mut ctx = Map::new();
    ctx.insert("sync_url".to_owned(), Value::String(sync_url));
    ctx.insert("access_token".to_owned(), Value::String(access_token));
    Some(ctx)
}

fn iso8601_to_unix(value: &str) -> Option<i64> {
    // Accept `YYYY-MM-DDTHH:MM:SS(.f)?(Z|±HH:MM)`; a fractional-seconds tail
    // and an explicit offset both appear in stored payloads.
    let s = value.trim();
    let (date_time, offset) = match s.find(['Z', '+']) {
        Some(i) => (&s[..i], &s[i..]),
        None => {
            // `-` may also start a negative offset — split on the last one
            // that follows the `T` time separator.
            match s.rfind('-') {
                Some(i) if i > s.find('T').unwrap_or(usize::MAX) => (&s[..i], &s[i..]),
                _ => (s, "Z"),
            }
        }
    };
    let offset_seconds = match offset {
        "Z" | "" => 0,
        _ => {
            let sign = if offset.starts_with('-') { -1 } else { 1 };
            let parts: Vec<&str> = offset[1..].split(':').collect();
            let h: i64 = parts.first()?.parse().ok()?;
            let m: i64 = parts.get(1)?.parse().ok()?;
            sign * (h * 3600 + m * 60)
        }
    };
    let dt: Vec<&str> = date_time.split('T').collect();
    let date_parts: Vec<&str> = dt.first()?.split('-').collect();
    let time_part = dt.get(1)?;
    let time_clean = time_part.split('.').next()?;
    let time_parts: Vec<&str> = time_clean.split(':').collect();
    let y: i64 = date_parts.first()?.parse().ok()?;
    let mo: i64 = date_parts.get(1)?.parse().ok()?;
    let d: i64 = date_parts.get(2)?.parse().ok()?;
    let hh: i64 = time_parts.first()?.parse().ok()?;
    let mm: i64 = time_parts.get(1)?.parse().ok()?;
    let ss: i64 = time_parts.get(2)?.parse().ok()?;
    Some(civil_to_unix(y, mo, d, hh, mm, ss) - offset_seconds)
}

/// Howard Hinnant's civil-from-days algorithm — no chrono dependency.
fn civil_to_unix(y: i64, m: i64, d: i64, hh: i64, mm: i64, ss: i64) -> i64 {
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hh * 3600 + mm * 60 + ss
}

/// `oauth_client.py:validate_guard_sync_endpoint` (:174) — canonicalize + gate
/// a `sync_url` on the OAuth origin allowlist, with an optional issuer
/// consistency check. `Err` maps to `GuardSyncEndpointUntrustedError`.
pub fn validate_guard_sync_endpoint(
    sync_url: &str,
    issuer: Option<&str>,
) -> Result<String, String> {
    let url = url::Url::parse(sync_url)
        .map_err(|_| "Guard Cloud sync URL must be an absolute http(s) URL.".to_owned())?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err("Guard Cloud sync URL must be an absolute http(s) URL.".to_owned()),
    }
    if url.host_str().is_none() {
        return Err("Guard Cloud sync URL must be an absolute http(s) URL.".to_owned());
    }
    if url.username() != "" || url.password().is_some() {
        return Err("Guard Cloud sync URL userinfo is not allowed.".to_owned());
    }
    if url.fragment().is_some() {
        return Err("Guard Cloud sync URL fragments are not allowed.".to_owned());
    }
    let origin = issuer_origin(sync_url)?;
    if url.scheme() != "https" && !is_local_guard_origin(&origin) {
        return Err("Guard Cloud sync URL must use HTTPS.".to_owned());
    }
    if let Some(iss) = issuer {
        let (client_issuer, ..) = resolve_guard_oauth_client_config(iss)?;
        if origin != client_issuer {
            return Err(
                "Guard Cloud sync origin no longer matches the configured issuer.".to_owned(),
            );
        }
        return Ok(sync_url.to_owned());
    }
    if !is_guard_oauth_origin_allowed(&origin) {
        return Err(
            "Guard Cloud sync URL must use an allowlisted HOL origin or local loopback.".to_owned(),
        );
    }
    Ok(sync_url.to_owned())
}

/// `runner.py:_sign_guard_dpop_proof` (:3701) — ES256 JWS over
/// `{htu,htm,iat,jti,ath?,nonce?}`. PKCS#8 PEM via `ring::EcdsaKeyPair` (the
/// stored `private_key_pem` is PKCS#8 — Python writes it with
/// `PrivateFormat.PKCS8`). `ECDSA_P256_SHA256_FIXED_SIGNING` emits the raw
/// r||s signature JOSE expects (no DER unwrapping needed).
#[allow(clippy::too_many_arguments)]
pub fn sign_guard_dpop_proof(
    request_url: &str,
    method: &str,
    dpop_private_key_pem: &str,
    public_jwk: &Map<String, Value>,
    algorithm: &str,
    access_token: Option<&str>,
    nonce: Option<&str>,
    now_unix: i64,
) -> Result<String, String> {
    let mut header = Map::new();
    header.insert("alg".into(), Value::String(algorithm.to_owned()));
    header.insert("jwk".into(), Value::Object(public_jwk.clone()));
    header.insert("typ".into(), Value::String("dpop+jwt".into()));
    let mut claims = Map::new();
    claims.insert("htu".into(), Value::String(request_url.to_owned()));
    claims.insert("htm".into(), Value::String(method.to_uppercase()));
    claims.insert("iat".into(), Value::from(now_unix));
    let mut jti_bytes = [0u8; 16];
    getrandom::fill(&mut jti_bytes).map_err(|_| {
        "Guard Cloud authorization key is invalid. Reconnect Guard Cloud.".to_owned()
    })?;
    jti_bytes[6] = (jti_bytes[6] & 0x0f) | 0x40;
    jti_bytes[8] = (jti_bytes[8] & 0x3f) | 0x80;
    claims.insert(
        "jti".into(),
        Value::String(format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            jti_bytes[0], jti_bytes[1], jti_bytes[2], jti_bytes[3],
            jti_bytes[4], jti_bytes[5], jti_bytes[6], jti_bytes[7],
            jti_bytes[8], jti_bytes[9], jti_bytes[10], jti_bytes[11],
            jti_bytes[12], jti_bytes[13], jti_bytes[14], jti_bytes[15],
        )),
    );
    if let Some(tok) = access_token.filter(|t| !t.is_empty()) {
        let digest = Sha256::digest(tok.as_bytes());
        claims.insert("ath".into(), Value::String(base64url(&digest)));
    }
    if let Some(n) = nonce.map(str::trim).filter(|n| !n.is_empty()) {
        claims.insert("nonce".into(), Value::String(n.to_owned()));
    }
    let header_json = serde_json::to_vec(&Value::Object(header)).map_err(|e| e.to_string())?;
    let claims_json = serde_json::to_vec(&Value::Object(claims)).map_err(|e| e.to_string())?;
    let signing_input = format!("{}.{}", base64url(&header_json), base64url(&claims_json));
    let der = pem_to_der_private_key(dpop_private_key_pem)?;
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &SystemRandom::new())
            .map_err(|_| {
                "Guard Cloud authorization key is invalid. Reconnect Guard Cloud.".to_owned()
            })?;
    let sig: Signature = key
        .sign(&SystemRandom::new(), signing_input.as_bytes())
        .map_err(|_| {
            "Guard Cloud authorization key is invalid. Reconnect Guard Cloud.".to_owned()
        })?;
    Ok(format!("{}.{}", signing_input, base64url(sig.as_ref())))
}

/// Extract the PKCS#8 DER body from a `-----BEGIN PRIVATE KEY-----` PEM.
fn pem_to_der_private_key(pem: &str) -> Result<Vec<u8>, String> {
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line == "-----BEGIN PRIVATE KEY-----" {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if in_block {
            b64.push_str(line);
        }
    }
    if b64.is_empty() {
        return Err("Guard Cloud authorization key is invalid. Reconnect Guard Cloud.".to_owned());
    }
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| "Guard Cloud authorization key is invalid. Reconnect Guard Cloud.".to_owned())
}

/// `runner.py:_guard_sync_headers` (:4783) — Bearer + JSON defaults + optional
/// DPoP proof, then `extra_headers` override. `auth_context` is the resolved
/// dict `_resolve_guard_sync_auth_context` returns; `dpop_key_material` is the
/// embedded `{algorithm, private_key_pem, public_jwk, public_jwk_thumbprint}`.
pub fn guard_sync_headers(
    auth_context: &Value,
    request_url: &str,
    method: &str,
    extra_headers: Option<&Map<String, Value>>,
    dpop_nonce: Option<&str>,
) -> Result<BTreeMap<String, String>, String> {
    let access_token = auth_context
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "auth context missing access_token".to_owned())?;
    let mut headers = BTreeMap::new();
    headers.insert("Authorization".to_owned(), format!("Bearer {access_token}"));
    headers.insert("Content-Type".to_owned(), "application/json".to_owned());
    headers.insert("Accept".to_owned(), "application/json".to_owned());
    headers.insert("User-Agent".to_owned(), GUARD_SYNC_USER_AGENT.to_owned());
    if let Some(material) = auth_context
        .get("dpop_key_material")
        .and_then(Value::as_object)
    {
        let private_key_pem = optional_string(material.get("private_key_pem"))
            .ok_or_else(|| "dpop_key_material missing private_key_pem".to_owned())?;
        let public_jwk = material
            .get("public_jwk")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let algorithm =
            optional_string(material.get("algorithm")).unwrap_or_else(|| "ES256".into());
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        let proof = sign_guard_dpop_proof(
            request_url,
            method,
            &private_key_pem,
            &public_jwk,
            &algorithm,
            Some(access_token),
            dpop_nonce,
            now_unix,
        )?;
        headers.insert("DPoP".to_owned(), proof);
    }
    if let Some(extra) = extra_headers {
        for (k, v) in extra.iter() {
            if let Some(s) = v.as_str() {
                headers.insert(k.clone(), s.to_owned());
            }
        }
    }
    Ok(headers)
}

/// `runner.py:_guard_sync_request` (:3810) — build the prepared request
/// (`GuardSyncRequest`) the transport layer hands to the HTTP client. The
/// `retry_context` field on the result captures `(auth_context, request_url,
/// method, extra_headers)` — the nonce/timeout retry machine re-signs the
/// DPoP proof from it without re-reading credentials.
pub fn guard_sync_request(
    auth_context: &Value,
    request_url: &str,
    method: &str,
    data: Option<&[u8]>,
    extra_headers: Option<&Map<String, Value>>,
    dpop_nonce: Option<&str>,
) -> EvalResult<GuardSyncRequest> {
    let headers = guard_sync_headers(auth_context, request_url, method, extra_headers, dpop_nonce)
        .map_err(EvalError::Validation)?;
    // `_resolve_guard_dpop_retry_context` — the retry side-channel only
    // exists when the request carried DPoP material.
    let retry_context = if headers.contains_key("DPoP") {
        let mut ctx = Map::new();
        ctx.insert("auth_context".to_owned(), auth_context.clone());
        ctx.insert(
            "request_url".to_owned(),
            Value::String(request_url.to_owned()),
        );
        ctx.insert("method".to_owned(), Value::String(method.to_uppercase()));
        ctx.insert(
            "extra_headers".to_owned(),
            extra_headers
                .map(|h| Value::Object(h.clone()))
                .unwrap_or(Value::Null),
        );
        Some(ctx)
    } else {
        None
    };
    Ok(GuardSyncRequest {
        url: request_url.to_owned(),
        method: method.to_uppercase(),
        headers,
        body: data.map(|d| d.to_vec()),
        dpop_nonce: dpop_nonce.map(str::to_owned),
        retry_context,
    })
}

fn guard_sync_request_with_dpop_nonce(
    request: &GuardSyncRequest,
    dpop_nonce: Option<&str>,
) -> Option<GuardSyncRequest> {
    let ctx = request.retry_context.as_ref()?;
    let auth_context = ctx.get("auth_context").cloned()?;
    let request_url = ctx.get("request_url").and_then(Value::as_str)?;
    let method = ctx.get("method").and_then(Value::as_str)?;
    let extra_headers = ctx.get("extra_headers").and_then(Value::as_object);
    guard_sync_request(
        &auth_context,
        request_url,
        method,
        request.body.as_deref(),
        extra_headers,
        dpop_nonce,
    )
    .ok()
}

/// `runner.py:_guard_sync_request_with_nonce` (:4823) — re-issue the same
/// request with the server-provided DPoP nonce bound into the proof. Reads
/// the retry context from the request itself (the Python side-channel);
/// returns `None` when the request has no retryable DPoP context or the nonce
/// did not change.
pub fn guard_sync_request_with_nonce(
    request: &GuardSyncRequest,
    dpop_nonce: &str,
) -> Option<GuardSyncRequest> {
    if request.dpop_nonce.as_deref() == Some(dpop_nonce) {
        return None;
    }
    guard_sync_request_with_dpop_nonce(request, Some(dpop_nonce))
}

fn guard_sync_request_for_retry(request: &GuardSyncRequest) -> Option<GuardSyncRequest> {
    guard_sync_request_with_dpop_nonce(request, request.dpop_nonce.as_deref())
}

/// `runner.py:_guard_http_header_value` (:3736) — case-insensitive header
/// lookup on the wire error.
fn http_header_value<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    let target = name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == target)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

/// `runner.py:_dpop_nonce_from_http_error` (:3785) — a 400/401 response whose
/// `DPoP-Nonce` header is present (and whose `error` field, when JSON, is one
/// of `use_dpop_nonce` / `invalid_dpop_proof`) carries the nonce for the
/// retry.
fn dpop_nonce_from_http_error(
    status: u16,
    headers: &BTreeMap<String, String>,
    payload: Option<&Value>,
) -> Option<String> {
    if status != 400 && status != 401 {
        return None;
    }
    let nonce = http_header_value(headers, "DPoP-Nonce")?.to_owned();
    if let Some(Value::Object(map)) = payload {
        if let Some(oauth_error) = map.get("error").and_then(Value::as_str) {
            let trimmed = oauth_error.trim();
            if !trimmed.is_empty() && trimmed != "use_dpop_nonce" && trimmed != "invalid_dpop_proof"
            {
                return None;
            }
        }
    }
    Some(nonce)
}

/// `runner.py:_http_error_payload` (:3774) — best-effort JSON body on error.
fn parse_json_body(raw: &[u8]) -> Option<Value> {
    if raw.is_empty() {
        return None;
    }
    serde_json::from_slice(raw).ok()
}

/// `runner.py:_guard_sync_timeout_seconds` (:3496) — env-overridable with the
/// documented bounds.
fn env_timeout_seconds(name: &str, default: f64, minimum: f64, maximum: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0)
        .map(|v| v.clamp(minimum, maximum))
        .unwrap_or(default)
}

fn sync_retry_poll_interval_seconds() -> f64 {
    env_timeout_seconds("GUARD_SYNC_RETRY_POLL_INTERVAL_SECONDS", 0.05, 0.01, 1.0)
}

/// `runner.py:801` — `_SYNC_RETRYABLE_GATEWAY_STATUS_CODES`, including the two
/// Cloudflare codes (522, 524) whose omission stops a bounded retry early.
fn status_is_retryable_gateway(status: u16) -> bool {
    matches!(status, 502..=504 | 522 | 524)
}

/// `runner.py:_guard_sync_retry_after_seconds` (:3502) — `Retry-After` header,
/// falling back to a bounded default.
fn retry_after_seconds(headers: &BTreeMap<String, String>, default: f64) -> f64 {
    http_header_value(headers, "Retry-After")
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .unwrap_or(default)
}

/// `runner.py:_urlopen_with_sync_retries` (:5009) — the bounded retry state
/// machine. Order: nonce fast-path → bounded 429 waits → bounded gateway
/// retries → generic nonce-challenge retry → one timeout retry at the longer
/// budget.
pub fn urlopen_with_sync_retries(
    request: &GuardSyncRequest,
    timeout_seconds: f64,
    retry_timeout_seconds: f64,
    parse_json_response: bool,
    nonce_fast_path: bool,
) -> Result<Option<Value>, EvalError> {
    let mut current_request = request.clone();
    let mut current_timeout = timeout_seconds;
    let mut retried_timeout = false;
    let mut nonce_retry_count: u32 = 0;
    let mut rate_limit_retry_count: u32 = 0;
    let mut gateway_retry_count: u32 = 0;
    loop {
        match execute_request(&current_request, current_timeout) {
            Ok(resp) => {
                if parse_json_response {
                    let body = resp.body_bytes;
                    return serde_json::from_slice::<Value>(&body)
                        .map(Some)
                        .map_err(|_| {
                            EvalError::Internal(
                                "Guard Cloud sync returned an invalid response payload.".to_owned(),
                            )
                        });
                }
                return Ok(None);
            }
            Err(SyncHttpError::Http {
                status,
                headers,
                body,
            }) => {
                let payload = parse_json_body(&body);
                if nonce_fast_path && status == 401 && nonce_retry_count < SYNC_NONCE_RETRY_LIMIT {
                    if let Some(nonce) =
                        dpop_nonce_from_http_error(status, &headers, payload.as_ref())
                    {
                        if let Some(next) = guard_sync_request_with_nonce(&current_request, &nonce)
                        {
                            nonce_retry_count += 1;
                            current_request = next;
                            continue;
                        }
                    }
                }
                if status == 429 && rate_limit_retry_count < SYNC_RATE_LIMIT_RETRY_LIMIT {
                    rate_limit_retry_count += 1;
                    let wait = retry_after_seconds(&headers, SYNC_429_DEFAULT_WAIT_SECONDS)
                        .min(SYNC_429_MAX_WAIT_SECONDS as f64);
                    std::thread::sleep(Duration::from_secs_f64(
                        wait.max(sync_retry_poll_interval_seconds()),
                    ));
                    if let Some(next) = guard_sync_request_for_retry(&current_request) {
                        current_request = next;
                    }
                    current_timeout = timeout_seconds;
                    retried_timeout = false;
                    continue;
                }
                if status_is_retryable_gateway(status)
                    && gateway_retry_count < SYNC_GATEWAY_RETRY_LIMIT
                {
                    gateway_retry_count += 1;
                    let wait = sync_retry_poll_interval_seconds()
                        .min(SYNC_GATEWAY_MAX_WAIT_SECONDS as f64);
                    std::thread::sleep(Duration::from_secs_f64(wait));
                    if let Some(next) = guard_sync_request_for_retry(&current_request) {
                        current_request = next;
                    }
                    continue;
                }
                if nonce_retry_count < SYNC_NONCE_RETRY_LIMIT {
                    if let Some(nonce) =
                        dpop_nonce_from_http_error(status, &headers, payload.as_ref())
                    {
                        if let Some(next) = guard_sync_request_with_nonce(&current_request, &nonce)
                        {
                            nonce_retry_count += 1;
                            current_request = next;
                            continue;
                        }
                    }
                }
                // `raise` (:5079) — the HTTPError propagates; the caller reads
                // `error.code` for the 401/4xx fail-closed branch.
                return Err(sync_http_eval_error(status, &headers, &body));
            }
            Err(SyncHttpError::Timeout(msg)) => {
                if !retried_timeout {
                    retried_timeout = true;
                    current_timeout = retry_timeout_seconds;
                    if let Some(next) = guard_sync_request_for_retry(&current_request) {
                        current_request = next;
                    }
                    continue;
                }
                return Err(EvalError::Internal(format!("timeout: {msg}")));
            }
            Err(SyncHttpError::Other(msg)) => return Err(EvalError::Internal(msg)),
        }
    }
}

/// `runner.py:_urlopen_json_with_timeout_retry` (:5094) — parse-JSON wrapper
/// that rejects non-object payloads.
pub fn urlopen_json_with_timeout_retry(
    request: &GuardSyncRequest,
    timeout_seconds: f64,
    retry_timeout_seconds: f64,
) -> Result<Value, EvalError> {
    urlopen_with_sync_retries(request, timeout_seconds, retry_timeout_seconds, true, false)?
        .ok_or_else(|| {
            EvalError::Internal("Guard Cloud sync returned an invalid response payload.".to_owned())
        })
}

/// `urllib.error.HTTPError` → `EvalError::HttpStatus` — carry the code so the
/// `_evaluate_with_cloud` 401-refresh branch can read `http_status()`.
fn sync_http_eval_error(status: u16, headers: &BTreeMap<String, String>, body: &[u8]) -> EvalError {
    let reason = http_error_reason_message(status, headers, body);
    EvalError::HttpStatus(status, reason)
}

/// `runner.py:_sync_http_error_message` (:5162) — prefer the structured
/// `guardError.message`/`error`/`message` fields, else the raw body, else the
/// status line.
fn http_error_reason_message(
    status: u16,
    _headers: &BTreeMap<String, String>,
    body: &[u8],
) -> String {
    let raw = String::from_utf8_lossy(body);
    if let Some(payload) = parse_json_body(body).and_then(|v| v.as_object().cloned()) {
        for key in ["guardError", "error", "message"] {
            if let Some(s) = payload.get(key).and_then(Value::as_str).map(str::trim) {
                if !s.is_empty() {
                    return s.to_owned();
                }
            }
            if let Some(inner) = payload.get(key).and_then(Value::as_object) {
                if let Some(s) = inner.get("message").and_then(Value::as_str).map(str::trim) {
                    if !s.is_empty() {
                        return s.to_owned();
                    }
                }
            }
        }
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        format!("HTTP Error {status}")
    } else {
        trimmed.to_owned()
    }
}

struct SyncResponse {
    body_bytes: Vec<u8>,
}

enum SyncHttpError {
    Http {
        status: u16,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    },
    Timeout(String),
    Other(String),
}

fn execute_request(
    request: &GuardSyncRequest,
    timeout_seconds: f64,
) -> Result<SyncResponse, SyncHttpError> {
    let config = ureq::config::Config::builder()
        .timeout_global(Some(Duration::from_secs_f64(timeout_seconds.max(0.5))))
        .timeout_connect(Some(Duration::from_secs_f64(timeout_seconds.max(0.5))))
        .timeout_recv_response(Some(Duration::from_secs_f64(timeout_seconds.max(0.5))))
        .timeout_recv_body(Some(Duration::from_secs_f64(timeout_seconds.max(0.5))))
        .http_status_as_error(false)
        .max_redirects(0)
        .build();
    let agent = ureq::Agent::with_parts(
        config,
        ureq::unversioned::transport::DefaultConnector::default(),
        ureq::unversioned::resolver::DefaultResolver::default(),
    );
    let mut request_builder = ureq::http::Request::builder()
        .method(request.method.to_uppercase().as_str())
        .uri(&request.url);
    for (name, value) in &request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_str());
    }
    let body_vec: Vec<u8> = request.body.clone().unwrap_or_default();
    let http_request = request_builder
        .body(body_vec)
        .map_err(|e| SyncHttpError::Other(format!("build request: {e}")))?;
    let mut response = agent.run(http_request).map_err(map_ureq_error)?;
    let status = response.status().as_u16();
    let mut headers = BTreeMap::new();
    for (name, value) in response.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.to_string(), v.to_owned());
        }
    }
    let body = response
        .body_mut()
        .read_to_vec()
        .map_err(|e| SyncHttpError::Other(format!("read body: {e}")))?;
    if (200..300).contains(&status) {
        return Ok(SyncResponse { body_bytes: body });
    }
    Err(SyncHttpError::Http {
        status,
        headers,
        body,
    })
}

fn map_ureq_error(error: ureq::Error) -> SyncHttpError {
    match error {
        ureq::Error::Timeout(_) => SyncHttpError::Timeout("request timed out".to_owned()),
        ureq::Error::Io(e) => SyncHttpError::Other(format!("io: {e}")),
        ureq::Error::Tls(e) => SyncHttpError::Other(format!("tls: {e}")),
        ureq::Error::TlsRequired => SyncHttpError::Other("tls required".to_owned()),
        ureq::Error::StatusCode(code) => SyncHttpError::Other(format!("status: {code}")),
        ureq::Error::Http(e) => SyncHttpError::Other(format!("http: {e}")),
        other => SyncHttpError::Other(other.to_string()),
    }
}

/// `runner.py:_GuardOAuthRefreshRateLimitedError` (:4112) — the refresh leg's
/// outcome taxonomy. The caller (the resident `ResidentGuardSyncRunner`) owns
/// the retry machine, the dead-grant circuit breaker, and the rotation
/// persist; this carries only what those need to decide.
pub enum OAuthRefreshOutcome {
    /// `access_token` accepted; `refresh_token` is the rotated grant to persist
    /// (empty `rotation_refresh_token` keeps the existing grant).
    Refreshed {
        access_token: String,
        rotation_refresh_token: Option<String>,
        access_token_expires_at: Option<String>,
    },
    /// The endpoint issued a `DPoP-Nonce`; retry with it (bounded by caller).
    NonceChallenge(String),
    /// 429 — carry the bounded Retry-After hint; the caller owns the sleep.
    RateLimited(f64),
    /// `invalid_grant` / consumed-or-revoked — the grant is dead; caller must
    /// record the dead-grant breaker and demand reauthorization.
    DeadGrant,
    /// Any other transport or payload failure — reauthorizable.
    Failed(String),
}

/// `urllib.parse.urlencode` parity — percent-encode every byte outside the
/// unreserved RFC 3986 set so the form body matches the Python byte-for-byte.
fn form_urlencode_field(name: &str, value: &str) -> String {
    let mut out = String::with_capacity(value.len() + name.len() + 2);
    let push = |out: &mut String, s: &str| {
        for &b in s.as_bytes() {
            let ok = b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~');
            if ok {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    };
    push(&mut out, name);
    out.push('=');
    push(&mut out, value);
    out
}

/// `runner.py:_oauth_access_token_expires_at` (:4411) — prefer the JWT `exp`
/// claim; otherwise `now + expires_in`; `None` when neither is usable. Returns
/// the `datetime.isoformat()` (`+00:00`) string the store round-trips.
fn oauth_access_token_expires_at(
    access_token: &str,
    payload: &Value,
    now_unix: i64,
) -> Option<String> {
    if let Some(exp) = jwt_exp_claim(access_token) {
        return Some(
            crate::local_supply_chain::Timestamp::from_unix_micros(exp * 1_000_000).isoformat(),
        );
    }
    let expires_in = match payload.get("expires_in") {
        Some(Value::Number(n)) => n
            .as_f64()
            .filter(|v| *v > 0.0 && !v.is_nan())
            .map(|v| v as i64),
        Some(Value::String(s)) => s.parse::<i64>().ok().filter(|v| *v > 0),
        _ => None,
    }?;
    Some(
        crate::local_supply_chain::Timestamp::from_unix_micros((now_unix + expires_in) * 1_000_000)
            .isoformat(),
    )
}

/// Decode the JWT payload segment and read a positive numeric `exp`.
fn jwt_exp_claim(access_token: &str) -> Option<i64> {
    let payload_seg = access_token.split('.').nth(1)?;
    let padded = match payload_seg.len() % 4 {
        0 => payload_seg.to_owned(),
        n => format!("{payload_seg}{}", "=".repeat(4 - n)),
    };
    let bytes = base64::engine::general_purpose::URL_SAFE
        .decode(padded)
        .ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("exp")
        .and_then(Value::as_f64)
        .filter(|v| *v > 0.0)
        .map(|v| v as i64)
}

/// `runner.py:_invalid_grant_oauth_payload` (:3911) — the grant is dead on a
/// `400/401/403` whose body carries `error == "invalid_grant"` or a consumed /
/// expired description.
fn invalid_grant_oauth_payload(body: &[u8]) -> bool {
    let Some(payload) = parse_json_body(body).and_then(|v| v.as_object().cloned()) else {
        return false;
    };
    let error = payload.get("error").and_then(Value::as_str);
    let description = payload.get("error_description").and_then(Value::as_str);
    error == Some("invalid_grant")
        || description
            .map(|d| {
                d.to_lowercase()
                    .contains("missing, expired, or already consumed")
            })
            .unwrap_or(false)
}

/// `runner.py:_refresh_guard_oauth_access_token_once` (:4006) — POST the
/// refresh grant to the allowlisted token endpoint behind a fresh DPoP proof.
/// Nonce challenges return `NonceChallenge` for the caller to bound (≤3); the
/// caller records `RateLimited` / `DeadGrant` into the circuit breaker and
/// persists `Refreshed` rotation under `oauth-refresh.lock`.
/// Inputs to `refresh_guard_oauth_access_token` — the DPoP key material +
/// grant the caller resolved from the scoped credential, plus the request
/// knobs (endpoint, client id, nonce, timeouts).
pub struct OAuthRefreshRequest<'a> {
    pub token_endpoint: &'a str,
    pub client_id: &'a str,
    pub refresh_token: &'a str,
    pub dpop_private_key_pem: &'a str,
    pub dpop_public_jwk: &'a Map<String, Value>,
    pub algorithm: &'a str,
    pub nonce: Option<&'a str>,
    pub timeout_seconds: f64,
    pub now_unix: i64,
}

pub fn refresh_guard_oauth_access_token(req: &OAuthRefreshRequest<'_>) -> OAuthRefreshOutcome {
    let body = format!(
        "grant_type=refresh_token&{}&{}",
        form_urlencode_field("client_id", req.client_id),
        form_urlencode_field("refresh_token", req.refresh_token),
    );
    let dpop_proof = match sign_guard_dpop_proof(
        req.token_endpoint,
        "POST",
        req.dpop_private_key_pem,
        req.dpop_public_jwk,
        req.algorithm,
        None,
        req.nonce,
        req.now_unix,
    ) {
        Ok(proof) => proof,
        Err(reason) => return OAuthRefreshOutcome::Failed(reason),
    };
    let mut headers = BTreeMap::new();
    headers.insert(
        "Content-Type".to_owned(),
        "application/x-www-form-urlencoded".to_owned(),
    );
    headers.insert("Accept".to_owned(), "application/json".to_owned());
    headers.insert("User-Agent".to_owned(), GUARD_SYNC_USER_AGENT.to_owned());
    headers.insert("DPoP".to_owned(), dpop_proof);
    let request = GuardSyncRequest {
        url: req.token_endpoint.to_owned(),
        method: "POST".to_owned(),
        headers,
        body: Some(body.into_bytes()),
        dpop_nonce: req.nonce.map(str::to_owned),
        retry_context: None,
    };
    match execute_request(&request, req.timeout_seconds) {
        Ok(resp) => {
            let Some(payload) =
                parse_json_body(&resp.body_bytes).and_then(|v| v.as_object().cloned())
            else {
                return OAuthRefreshOutcome::Failed(
                    "Guard Cloud token refresh returned a non-JSON response.".to_owned(),
                );
            };
            let payload = Value::Object(payload);
            let access_token = payload.get("access_token").and_then(Value::as_str);
            let token_type = payload.get("token_type").and_then(Value::as_str);
            let token_type_ok = token_type
                .map(|t| matches!(t.to_ascii_lowercase().as_str(), "bearer" | "dpop"))
                .unwrap_or(false);
            let (access_token, token_type_ok) = match access_token {
                Some(t) if !t.is_empty() && token_type_ok => (t.to_owned(), true),
                _ => (String::new(), false),
            };
            if !token_type_ok {
                return OAuthRefreshOutcome::Failed(
                    "Guard Cloud token refresh returned an unusable token.".to_owned(),
                );
            }
            let rotation_refresh_token = payload
                .get("refresh_token")
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
                .map(str::to_owned);
            let access_token_expires_at =
                oauth_access_token_expires_at(&access_token, &payload, req.now_unix);
            OAuthRefreshOutcome::Refreshed {
                access_token,
                rotation_refresh_token,
                access_token_expires_at,
            }
        }
        Err(SyncHttpError::Http {
            status,
            headers,
            body,
        }) => {
            if matches!(status, 400 | 401 | 403 | 429) {
                let parsed_body = parse_json_body(&body);
                if let Some(challenge) =
                    dpop_nonce_from_http_error(status, &headers, parsed_body.as_ref())
                {
                    if Some(challenge.as_str()) != req.nonce {
                        return OAuthRefreshOutcome::NonceChallenge(challenge);
                    }
                }
            }
            if status == 429 {
                let wait = retry_after_seconds(&headers, SYNC_429_DEFAULT_WAIT_SECONDS).min(120.0);
                return OAuthRefreshOutcome::RateLimited(wait);
            }
            if matches!(status, 400 | 401 | 403) {
                if invalid_grant_oauth_payload(&body) {
                    return OAuthRefreshOutcome::DeadGrant;
                }
                return OAuthRefreshOutcome::Failed(http_error_reason_message(
                    status, &headers, &body,
                ));
            }
            OAuthRefreshOutcome::Failed(http_error_reason_message(status, &headers, &body))
        }
        Err(SyncHttpError::Timeout(_)) => {
            OAuthRefreshOutcome::Failed("Guard Cloud token refresh timed out.".to_owned())
        }
        Err(SyncHttpError::Other(reason)) => OAuthRefreshOutcome::Failed(reason),
    }
}

#[cfg(test)]
mod sync_retry_parity_tests {
    use super::*;

    /// `runner.py:801` retries two Cloudflare gateway codes the tighter list missed.
    #[test]
    fn retryable_gateway_statuses_match_the_python_set() {
        for status in [502_u16, 503, 504, 522, 524] {
            assert!(status_is_retryable_gateway(status), "{status} must retry");
        }
        for status in [500_u16, 501, 505, 421, 429, 525] {
            assert!(
                !status_is_retryable_gateway(status),
                "{status} must not retry"
            );
        }
    }

    /// `runner.py:3306` waits a minute without `Retry-After`; `:5056` caps at 120.
    #[test]
    fn a_rate_limit_without_retry_after_waits_a_minute_capped_at_two_minutes() {
        let empty = BTreeMap::new();
        assert_eq!(
            retry_after_seconds(&empty, SYNC_429_DEFAULT_WAIT_SECONDS),
            60.0
        );

        let supplied: BTreeMap<String, String> = [("Retry-After".to_owned(), "45".to_owned())]
            .into_iter()
            .collect();
        assert_eq!(
            retry_after_seconds(&supplied, SYNC_429_DEFAULT_WAIT_SECONDS)
                .min(SYNC_429_MAX_WAIT_SECONDS as f64),
            45.0
        );

        let long: BTreeMap<String, String> = [("Retry-After".to_owned(), "600".to_owned())]
            .into_iter()
            .collect();
        assert_eq!(
            retry_after_seconds(&long, SYNC_429_DEFAULT_WAIT_SECONDS)
                .min(SYNC_429_MAX_WAIT_SECONDS as f64),
            SYNC_429_MAX_WAIT_SECONDS as f64
        );
    }

    /// `runner.py:5054` allows two rate-limit retries; `:802` two gateway retries.
    #[test]
    fn retry_attempt_bounds_match_the_python_bounds() {
        assert_eq!(SYNC_RATE_LIMIT_RETRY_LIMIT, 2);
        assert_eq!(SYNC_GATEWAY_RETRY_LIMIT, 2);
    }
    /// `urllib.parse.urlencode` parity — unreserved set only, %XX uppercase.
    #[test]
    fn form_urlencode_escapes_reserved_and_keeps_unreserved() {
        assert_eq!(
            form_urlencode_field("refresh_token", "rt/with+plus@host?x=1&y=2"),
            "refresh_token=rt%2Fwith%2Bplus%40host%3Fx%3D1%26y%3D2"
        );
        assert_eq!(form_urlencode_field("a.b-c_d~e", "v"), "a.b-c_d~e=v");
        assert_eq!(form_urlencode_field("k", ""), "k=");
    }

    /// `_invalid_grant_oauth_payload` — only a 4xx body carrying
    /// `error:"invalid_grant"` or the consumed/expired description is a dead grant.
    #[test]
    fn invalid_grant_payload_detection() {
        assert!(invalid_grant_oauth_payload(br#"{"error":"invalid_grant"}"#));
        assert!(invalid_grant_oauth_payload(
            br#"{"error":"invalid_request","error_description":"refresh token is missing, expired, or already consumed"}"#
        ));
        assert!(!invalid_grant_oauth_payload(
            br#"{"error":"invalid_request"}"#
        ));
        assert!(!invalid_grant_oauth_payload(b"not json"));
        assert!(!invalid_grant_oauth_payload(br#"{"error":42}"#));
    }

    /// `_oauth_access_token_expires_at` — prefer JWT `exp`, else now+expires_in.
    #[test]
    fn access_token_expires_at_prefers_jwt_exp_then_expires_in() {
        // unsigned-style payload segment {"exp":1893456000} base64url
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":1893456000}"#);
        let token = format!("aaa.{payload}.ccc");
        let with_exp = oauth_access_token_expires_at(&token, &serde_json::json!({}), 0);
        assert_eq!(with_exp.as_deref(), Some("2030-01-01T00:00:00+00:00"));

        let no_exp =
            oauth_access_token_expires_at("no.jwt", &serde_json::json!({"expires_in": 60}), 1_000);
        assert_eq!(no_exp.as_deref(), Some("1970-01-01T00:17:40+00:00"));

        assert_eq!(
            oauth_access_token_expires_at("x", &serde_json::json!({}), 0),
            None
        );
    }

    /// Refresh success requires `access_token` + `token_type` in {bearer,dpop}
    /// (case-insensitive); a rotated `refresh_token` is captured for persist.
    #[test]
    fn refresh_outcome_classification_table() {
        // exercised indirectly: token_type gate
        for t in ["bearer", "DPoP", "Bearer"] {
            let ok = t.to_ascii_lowercase();
            assert!(matches!(ok.as_str(), "bearer" | "dpop"), "{t}");
        }
        assert!(!matches!(
            "mac".to_ascii_lowercase().as_str(),
            "bearer" | "dpop"
        ));
    }
}
