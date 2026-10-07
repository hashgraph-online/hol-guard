#![forbid(unsafe_code)]
//! Google server-flow identity evidence for a credential-owning worker.
//! This is not an execution grant, credential-isolation proof or hook producer.

use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ISSUER: &str = "https://accounts.google.com";
const KEYS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const MAX_TOKEN: usize = 24 * 1024;
const MAX_KEYS: u64 = 64 * 1024;
const LIFETIME: u64 = 300;
const CLOCK_SKEW: u64 = 30;

pub mod directory;
pub mod dispatch;
pub mod oauth;
pub mod outbound;
mod sender;
pub mod worker_input;

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityError {
    Invalid,
    Expired,
    KeyFetchUnavailable,
    ExchangeUnavailable,
}

// No Clone, Debug or serialization: challenge/key material belongs to the
// worker, not a browser/model-selected verification policy or public RPC.
pub struct GoogleLoginChallenge {
    client_id: String,
    hosted_domains: BTreeSet<String>,
    nonce: String,
    namespace_key: [u8; 32],
    created_at: u64,
    expected_account_binding: Option<String>,
}

pub struct GoogleIdentityEvidence {
    account_binding: String,
    tenant_binding: String,
    expires_at: u64,
    sender: Option<sender::VerifiedSender>,
}
impl GoogleIdentityEvidence {
    pub fn account_binding(&self) -> &str {
        &self.account_binding
    }
    pub fn tenant_binding(&self) -> &str {
        &self.tenant_binding
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl GoogleLoginChallenge {
    /// Configuration and namespace key must come from authenticated worker
    /// configuration. Creating evidence does not enroll or authorize an account.
    pub fn new(
        client_id: String,
        hosted_domains: Vec<String>,
        namespace_key: [u8; 32],
    ) -> Result<Self, IdentityError> {
        if !bounded_ascii(&client_id, 512)
            || hosted_domains.is_empty()
            || hosted_domains.len() > 256
            || namespace_key == [0; 32]
        {
            return Err(IdentityError::Invalid);
        }
        let domains: BTreeSet<_> = hosted_domains.iter().cloned().collect();
        if domains.len() != hosted_domains.len()
            || domains
                .iter()
                .any(|d| !d.contains('.') || !guard_contracts::is_canonical_business_domain(d))
        {
            return Err(IdentityError::Invalid);
        }
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| IdentityError::Invalid)?;
        Ok(Self {
            client_id,
            hosted_domains: domains,
            nonce: Base64UrlUnpadded::encode_string(&random),
            namespace_key,
            created_at: now()?,
            expected_account_binding: None,
        })
    }
    /// Pin an existing account from authenticated worker configuration. An
    /// initial successful login is evidence only, not account enrollment.
    pub fn with_expected_account(mut self, binding: &str) -> Result<Self, IdentityError> {
        if binding.len() != 64
            || binding != binding.to_ascii_lowercase()
            || hex::decode(binding).is_err()
        {
            return Err(IdentityError::Invalid);
        }
        self.expected_account_binding = Some(binding.to_owned());
        Ok(self)
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Consumes the challenge on success or failure. Tokens stay local and are
    /// never sent to tokeninfo, logs, telemetry or the public key endpoint.
    pub fn verify(
        self,
        id_token: &str,
        access_token: &str,
    ) -> Result<GoogleIdentityEvidence, IdentityError> {
        let observed = now()?;
        self.check_time(observed)?;
        let token = Token::parse(id_token, access_token)?;
        let keys = cached_keys(&token.header.kid)?;
        // Network/key rotation work must not freeze the admission clock.
        self.verify_with_keys(token, access_token, &keys, now()?)
    }

    fn check_time(&self, observed: u64) -> Result<(), IdentityError> {
        if observed < self.created_at || observed >= self.created_at.saturating_add(LIFETIME) {
            return Err(IdentityError::Expired);
        }
        Ok(())
    }

    fn verify_with_keys(
        self,
        token: Token<'_>,
        access_token: &str,
        keys: &KeySet,
        observed: u64,
    ) -> Result<GoogleIdentityEvidence, IdentityError> {
        self.check_time(observed)?;
        keys.validate()?;
        let key = keys
            .keys
            .iter()
            .find(|k| k.kid == token.header.kid)
            .ok_or(IdentityError::Invalid)?;
        key.validate()?;
        let n = decode(key.n.as_deref().ok_or(IdentityError::Invalid)?, 1024)?;
        let e = decode(key.e.as_deref().ok_or(IdentityError::Invalid)?, 8)?;
        RsaPublicKeyComponents { n: &n, e: &e }
            .verify(
                &RSA_PKCS1_2048_8192_SHA256,
                token.signed.as_bytes(),
                &token.signature,
            )
            .map_err(|_| IdentityError::Invalid)?;
        let c = token.claims;
        if !matches!(c.iss.as_str(), ISSUER | "accounts.google.com")
            || c.aud != self.client_id
            || c.azp.as_ref().is_some_and(|v| v != &self.client_id)
            || c.nonce != self.nonce
            || !bounded_ascii(&c.sub, 255)
            || !self.hosted_domains.contains(&c.hd)
            || c.iat > observed.saturating_add(CLOCK_SKEW)
            || c.iat.saturating_add(CLOCK_SKEW) < self.created_at
            || c.iat >= c.exp
            || observed >= c.exp
            || observed >= c.iat.saturating_add(LIFETIME)
        {
            return Err(IdentityError::Invalid);
        }
        let access_digest = Sha256::digest(access_token.as_bytes());
        if decode(&c.at_hash, 16)? != access_digest[..16] {
            return Err(IdentityError::Invalid);
        }
        let expires_at = c
            .exp
            .min(self.created_at.saturating_add(LIFETIME))
            .min(c.iat.saturating_add(LIFETIME));
        let account_binding = binding(
            &self.namespace_key,
            b"hol-guard.google-account.v1\0",
            &[ISSUER, &self.client_id, &c.hd, &c.sub],
        );
        if self
            .expected_account_binding
            .as_ref()
            .is_some_and(|expected| expected != &account_binding)
        {
            return Err(IdentityError::Invalid);
        }
        Ok(GoogleIdentityEvidence {
            sender: sender::VerifiedSender::from_claims(c.email, c.email_verified),
            account_binding,
            tenant_binding: binding(
                &self.namespace_key,
                b"hol-guard.google-tenant.v1\0",
                &[ISSUER, &c.hd],
            ),
            expires_at,
        })
    }
}

fn now() -> Result<u64, IdentityError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| IdentityError::Invalid)
}
fn bounded_ascii(s: &str, maximum: usize) -> bool {
    !s.is_empty() && s.len() <= maximum && s.bytes().all(|b| b.is_ascii_graphic())
}
fn decode(s: &str, maximum: usize) -> Result<Vec<u8>, IdentityError> {
    if s.len() > maximum.div_ceil(3) * 4 {
        return Err(IdentityError::Invalid);
    }
    let bytes = Base64UrlUnpadded::decode_vec(s).map_err(|_| IdentityError::Invalid)?;
    if bytes.len() > maximum || Base64UrlUnpadded::encode_string(&bytes) != s {
        return Err(IdentityError::Invalid);
    }
    Ok(bytes)
}
fn binding(key: &[u8; 32], kind: &[u8], fields: &[&str]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("fixed HMAC key length");
    mac.update(kind);
    for field in fields {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field.as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    #[serde(default, deserialize_with = "present_string")]
    typ: Option<String>,
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    hd: String,
    nonce: String,
    at_hash: String,
    #[serde(default, deserialize_with = "present_string")]
    azp: Option<String>,
    iat: u64,
    exp: u64,
    #[serde(default, deserialize_with = "present_string")]
    email: Option<String>,
    #[serde(default, deserialize_with = "present_bool")]
    email_verified: Option<bool>,
}

fn present_bool<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    bool::deserialize(d).map(Some)
}

fn present_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
struct Token<'a> {
    header: Header,
    claims: Claims,
    signed: &'a str,
    signature: Vec<u8>,
}
impl<'a> Token<'a> {
    fn parse(raw: &'a str, access_token: &str) -> Result<Self, IdentityError> {
        if raw.len() > MAX_TOKEN || !bounded_ascii(access_token, 8192) {
            return Err(IdentityError::Invalid);
        }
        let parts: Vec<_> = raw.split('.').collect();
        if parts.len() != 3 {
            return Err(IdentityError::Invalid);
        }
        let header: Header =
            serde_json::from_slice(&decode(parts[0], 1024)?).map_err(|_| IdentityError::Invalid)?;
        if header.alg != "RS256"
            || !bounded_ascii(&header.kid, 256)
            || header.typ.as_deref().is_some_and(|s| s != "JWT")
        {
            return Err(IdentityError::Invalid);
        }
        let claims = serde_json::from_slice(&decode(parts[1], 16 * 1024)?)
            .map_err(|_| IdentityError::Invalid)?;
        let signed = raw.rsplit_once('.').ok_or(IdentityError::Invalid)?.0;
        Ok(Self {
            header,
            claims,
            signed,
            signature: decode(parts[2], 1024)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeySet {
    keys: Vec<Jwk>,
}
#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    n: Option<String>,
    e: Option<String>,
}
impl KeySet {
    fn validate(&self) -> Result<(), IdentityError> {
        let mut ids = BTreeSet::new();
        if self.keys.is_empty() || self.keys.len() > 32 {
            return Err(IdentityError::Invalid);
        }
        for key in &self.keys {
            if !bounded_ascii(&key.kid, 256) || !ids.insert(&key.kid) {
                return Err(IdentityError::Invalid);
            }
        }
        Ok(())
    }
}

impl Jwk {
    fn validate(&self) -> Result<(), IdentityError> {
        if self.kty != "RSA"
            || self.alg.as_deref() != Some("RS256")
            || self.usage.as_deref() != Some("sig")
        {
            return Err(IdentityError::Invalid);
        }
        let n = decode(self.n.as_deref().ok_or(IdentityError::Invalid)?, 1024)?;
        if n.len() < 256
            || n[0] == 0
            || decode(self.e.as_deref().ok_or(IdentityError::Invalid)?, 8)? != [1, 0, 1]
        {
            return Err(IdentityError::Invalid);
        }
        Ok(())
    }
}

#[derive(Default)]
struct KeyCache {
    entry: Option<(Arc<KeySet>, Instant)>,
    last_refresh: Option<Instant>,
}
impl KeyCache {
    fn get(
        &mut self,
        observed: Instant,
        kid: &str,
        fetch: impl FnOnce() -> Result<(KeySet, Duration), IdentityError>,
    ) -> Result<Arc<KeySet>, IdentityError> {
        if let Some((keys, expires)) = &self.entry {
            if observed < *expires {
                if keys.keys.iter().any(|key| key.kid == kid) {
                    return Ok(Arc::clone(keys));
                }
                // A rotated kid gets one bounded early refresh; attacker-chosen
                // unknown kids cannot turn every verification into network I/O.
                if self.last_refresh.is_some_and(|time| {
                    observed.saturating_duration_since(time) < Duration::from_secs(30)
                }) {
                    return Err(IdentityError::Invalid);
                }
            }
        }
        self.last_refresh = Some(observed);
        let (keys, lifetime) = fetch()?;
        keys.validate()?;
        let keys = Arc::new(keys);
        self.entry = Some((Arc::clone(&keys), observed + lifetime));
        Ok(keys)
    }
}

fn cached_keys(kid: &str) -> Result<Arc<KeySet>, IdentityError> {
    static CACHE: OnceLock<Mutex<KeyCache>> = OnceLock::new();
    // Public keys only. The fixed endpoint's bounded refresh is serialized,
    // and every admission rechecks the wall clock after acquiring keys.
    CACHE
        .get_or_init(|| Mutex::new(KeyCache::default()))
        .lock()
        .map_err(|_| IdentityError::KeyFetchUnavailable)?
        .get(Instant::now(), kid, fetch_keys)
}

fn cache_lifetime(control: &str, age: Option<&str>) -> Duration {
    let mut maximum = None;
    for directive in control.split(',').map(str::trim) {
        if directive.eq_ignore_ascii_case("no-store")
            || directive.eq_ignore_ascii_case("no-cache")
            || directive.to_ascii_lowercase().starts_with("no-cache=")
        {
            return Duration::ZERO;
        }
        if let Some((name, value)) = directive.split_once('=') {
            if name.eq_ignore_ascii_case("max-age") {
                if maximum.is_some() {
                    return Duration::ZERO;
                }
                maximum = value.parse::<u64>().ok();
                if maximum.is_none() {
                    return Duration::ZERO;
                }
            }
        }
    }
    let Some(age) = age.map_or(Some(0), |value| value.parse::<u64>().ok()) else {
        return Duration::ZERO;
    };
    Duration::from_secs(maximum.unwrap_or(0).saturating_sub(age).min(3600))
}

fn fetch_keys() -> Result<(KeySet, Duration), IdentityError> {
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .max_response_header_size(16 * 1024)
        .timeout_global(Some(Duration::from_secs(5)))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent
        .get(KEYS_URL)
        .call()
        .map_err(|_| IdentityError::KeyFetchUnavailable)?;
    if response.status().as_u16() != 200 {
        return Err(IdentityError::KeyFetchUnavailable);
    }
    let controls = response
        .headers()
        .get_all("cache-control")
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<Vec<_>, _>>();
    let ages = response
        .headers()
        .get_all("age")
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<Vec<_>, _>>();
    let lifetime = match (controls, ages) {
        (Ok(controls), Ok(ages)) if ages.len() <= 1 => {
            cache_lifetime(&controls.join(","), ages.first().copied())
        }
        _ => Duration::ZERO,
    };
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_KEYS)
        .read_to_vec()
        .map_err(|_| IdentityError::KeyFetchUnavailable)?;
    let keys = serde_json::from_slice(&bytes).map_err(|_| IdentityError::KeyFetchUnavailable)?;
    Ok((keys, lifetime))
}

#[cfg(test)]
mod tests;
