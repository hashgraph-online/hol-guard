//! A fake Yanez deployment for tests: real Ed25519 and BLS12-381 keys, real
//! signatures, and an in-memory `PulseTransport` with single-use consumption.
//! Compiled only with the `testkit` feature or under `cfg(test)`.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use base64ct::{Base64UrlUnpadded, Encoding};
use blst::min_pk::SecretKey;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Map, Value};

use crate::client::{CreatedAuthorization, PollOutcome, PulseTransport, UserKeys};
use crate::jws::{JwkSet, SigningKey};
use crate::receipt::RegisteredUserKey;
use crate::user_sig::BLS_DST;
use crate::{AssuranceTier, PulseError};

pub const ISSUER: &str = crate::receipt::YANEZ_ISSUER;
pub const YID: &str = "yid_test_owner";
pub const AGENT_KEY_ID: &str = "yak_0123456789ab";
pub const AGENT_KEY: &str = "yak_0123456789ab_secret_material";

/// A Yanez Ed25519 signing key.
pub struct YanezKey {
    pub kid: String,
    pair: Ed25519KeyPair,
}

impl YanezKey {
    pub fn new(kid: &str, seed: u8) -> Self {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("seed");
        Self {
            kid: kid.to_owned(),
            pair,
        }
    }

    pub fn signing_key(&self) -> SigningKey {
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(self.pair.public_key().as_ref());
        SigningKey {
            kid: self.kid.clone(),
            public_key,
        }
    }

    pub fn jwk(&self) -> Value {
        json!({
            "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": self.kid,
            "x": Base64UrlUnpadded::encode_string(self.pair.public_key().as_ref()),
        })
    }
}

/// An approver's BLS key on a YID device.
pub struct UserKey {
    secret: SecretKey,
}

impl UserKey {
    pub fn new(seed: u8) -> Self {
        Self {
            secret: SecretKey::key_gen(&[seed; 32], &[]).expect("ikm"),
        }
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.secret.sk_to_pk().compress())
    }

    pub fn registered(&self, tier: Option<AssuranceTier>) -> RegisteredUserKey {
        RegisteredUserKey {
            public_key_hex: self.public_hex(),
            tier,
        }
    }
}

/// Everything that goes into one receipt. Tests change one field at a time.
pub struct ReceiptSpec {
    pub issuer: String,
    pub yid: String,
    pub request_id: String,
    pub agent_key_id: String,
    pub terms: Value,
    pub tier: AssuranceTier,
    pub decided_at: i64,
    pub consent_not_after: i64,
    /// Terms the approver signed, when they differ from the receipt's.
    pub signed_terms: Option<Value>,
    /// YID inside the signed envelope, when it differs from `yid`.
    pub signed_yid: Option<String>,
    /// When the device signed, when it differs from `decided_at`.
    pub signed_at: Option<i64>,
}

impl ReceiptSpec {
    pub fn new(request_id: &str, terms: Value, now: i64) -> Self {
        Self {
            issuer: ISSUER.to_owned(),
            yid: YID.to_owned(),
            request_id: request_id.to_owned(),
            agent_key_id: AGENT_KEY_ID.to_owned(),
            terms,
            tier: AssuranceTier::High,
            decided_at: now,
            consent_not_after: now + 300,
            signed_terms: None,
            signed_yid: None,
            signed_at: None,
        }
    }
}

/// Sign a receipt with `yanez` and `user`.
pub fn mint_receipt(spec: &ReceiptSpec, yanez: &YanezKey, user: &UserKey) -> String {
    mint_receipt_edited(spec, yanez, user, |_| {}, |_, _| {})
}

/// Sign a receipt after rewriting its JSON text, for receipts no
/// well-behaved signer would produce: duplicate keys, extra header fields.
/// `edit_envelope` runs before the approver signs; `edit_token` gets the
/// header and claims text before Yanez signs.
pub fn mint_receipt_edited(
    spec: &ReceiptSpec,
    yanez: &YanezKey,
    user: &UserKey,
    edit_envelope: impl Fn(&mut String),
    edit_token: impl Fn(&mut String, &mut String),
) -> String {
    let envelope = json!({
        "version": 1,
        "issuer": spec.issuer,
        "action": "agent_authorizations.decision",
        "assurance_tier": spec.tier.as_str(),
        "authorization_request_id": spec.request_id,
        "decision": "approve",
        "consent_not_after": spec.consent_not_after,
        "signed_at": spec.signed_at.unwrap_or(spec.decided_at),
        "terms": spec.signed_terms.clone().unwrap_or_else(|| spec.terms.clone()),
        "yid": spec.signed_yid.clone().unwrap_or_else(|| spec.yid.clone()),
    });
    let mut envelope_text = envelope.to_string();
    edit_envelope(&mut envelope_text);
    let message = envelope_text.into_bytes();
    let signature = user.secret.sign(&message, BLS_DST, &[]);
    let mut claims = Map::new();
    for (k, v) in [
        ("iss", json!(spec.issuer)),
        ("sub", json!(spec.yid)),
        ("jti", json!(spec.request_id)),
        ("iat", json!(spec.decided_at)),
        ("yanez_agent_key_id", json!(spec.agent_key_id)),
        ("yanez_decision", json!("approved")),
        ("yanez_decided_at", json!(spec.decided_at)),
        ("yanez_match_overlap", json!(42)),
        ("yanez_terms", spec.terms.clone()),
        ("yanez_consent_not_after", json!(spec.consent_not_after)),
        ("yanez_assurance_tier", json!(spec.tier.as_str())),
        (
            "yanez_user_public_key",
            json!(format!("0x{}", user.public_hex())),
        ),
        (
            "yanez_user_signature",
            json!(format!("0x{}", hex::encode(signature.compress()))),
        ),
        (
            "yanez_signed_message",
            json!(Base64UrlUnpadded::encode_string(&message)),
        ),
        ("yanez_user_sig_alg", json!("BLS12-381-G2-basic")),
    ] {
        claims.insert(k.to_owned(), v);
    }
    let mut header = json!({"alg": "EdDSA", "kid": yanez.kid, "typ": "JWT"}).to_string();
    let mut claims = Value::Object(claims).to_string();
    edit_token(&mut header, &mut claims);
    let h = Base64UrlUnpadded::encode_string(header.as_bytes());
    let c = Base64UrlUnpadded::encode_string(claims.as_bytes());
    let input = format!("{h}.{c}");
    let sig = yanez.pair.sign(input.as_bytes());
    format!("{input}.{}", Base64UrlUnpadded::encode_string(sig.as_ref()))
}

/// What the fake service does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Reject,
    Expire,
    Pending,
}

/// In-memory Pulse. Approvals are signed with real keys at poll time.
pub struct FakePulse {
    pub yanez_keys: RefCell<Vec<YanezKey>>,
    pub user: UserKey,
    pub user_tier: RefCell<Option<AssuranceTier>>,
    pub user_registered: RefCell<bool>,
    pub yid: RefCell<String>,
    pub decision: RefCell<Decision>,
    pub approve_tier: RefCell<AssuranceTier>,
    pub now: RefCell<i64>,
    pub offline: RefCell<bool>,
    pub agent_key_revoked: RefCell<bool>,
    pub created: RefCell<BTreeMap<String, Value>>,
    /// Request id each idempotency key created, so a retry gets the same one.
    pub idempotency: RefCell<BTreeMap<String, String>>,
    /// Consent deadline Guard asked for on each request, in epoch seconds.
    pub deadlines: RefCell<BTreeMap<String, i64>>,
    pub consumed: RefCell<BTreeSet<String>>,
    pub public_key_fetches: RefCell<u32>,
    next_id: RefCell<u32>,
}

impl FakePulse {
    pub fn new(now: i64) -> Self {
        Self {
            yanez_keys: RefCell::new(vec![YanezKey::new("yanez-2026-01", 1)]),
            user: UserKey::new(9),
            user_tier: RefCell::new(Some(AssuranceTier::High)),
            user_registered: RefCell::new(true),
            yid: RefCell::new(YID.to_owned()),
            decision: RefCell::new(Decision::Approve),
            approve_tier: RefCell::new(AssuranceTier::High),
            now: RefCell::new(now),
            offline: RefCell::new(false),
            agent_key_revoked: RefCell::new(false),
            created: RefCell::new(BTreeMap::new()),
            idempotency: RefCell::new(BTreeMap::new()),
            deadlines: RefCell::new(BTreeMap::new()),
            consumed: RefCell::new(BTreeSet::new()),
            public_key_fetches: RefCell::new(0),
            next_id: RefCell::new(0),
        }
    }

    fn online(&self) -> Result<(), PulseError> {
        if *self.offline.borrow() {
            return Err(PulseError::Unavailable);
        }
        if *self.agent_key_revoked.borrow() {
            return Err(PulseError::AgentKeyRejected);
        }
        Ok(())
    }

    /// Sign a receipt for an already-created request.
    pub fn receipt_for(&self, request_id: &str) -> String {
        let terms = self.created.borrow()[request_id].clone();
        let now = *self.now.borrow();
        let mut spec = ReceiptSpec::new(request_id, terms, now);
        // Pulse carries the requested deadline into the receipt unchanged.
        if let Some(deadline) = self.deadlines.borrow().get(request_id) {
            spec.consent_not_after = *deadline;
        }
        spec.yid = self.yid.borrow().clone();
        spec.tier = *self.approve_tier.borrow();
        let keys = self.yanez_keys.borrow();
        mint_receipt(&spec, keys.last().expect("key"), &self.user)
    }
}

/// Epoch seconds for a UTC `YYYY-MM-DDTHH:MM:SS[.fff](Z|+00:00)` timestamp,
/// the forms Guard sends. A fraction is dropped.
fn epoch_from_utc(text: &str) -> Option<i64> {
    let rest = text
        .strip_suffix('Z')
        .or_else(|| text.strip_suffix("+00:00"))?;
    let whole = rest.split_once('.').map_or(rest, |(whole, fraction)| {
        if fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            ""
        } else {
            whole
        }
    });
    let b = whole.as_bytes();
    if b.len() != 19
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let part = &whole[from..to];
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (y, m, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hh, mm, ss) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    // Days from 1970-01-01 to the civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3_600 + mm * 60 + ss)
}

impl PulseTransport for FakePulse {
    fn create_authorization(
        &self,
        terms: &Value,
        consent_not_after_rfc3339: &str,
        idempotency_key: &str,
    ) -> Result<CreatedAuthorization, PulseError> {
        self.online()?;
        if let Some(request_id) = self.idempotency.borrow().get(idempotency_key) {
            return Ok(CreatedAuthorization {
                request_id: request_id.clone(),
            });
        }
        let deadline = epoch_from_utc(consent_not_after_rfc3339)
            .ok_or(PulseError::InvalidRequest("intent_expires_at"))?;
        let mut next = self.next_id.borrow_mut();
        *next += 1;
        let request_id = format!("azr_{next:04}");
        self.created
            .borrow_mut()
            .insert(request_id.clone(), terms.clone());
        self.deadlines
            .borrow_mut()
            .insert(request_id.clone(), deadline);
        self.idempotency
            .borrow_mut()
            .insert(idempotency_key.to_owned(), request_id.clone());
        Ok(CreatedAuthorization { request_id })
    }

    fn poll(&self, request_id: &str) -> Result<PollOutcome, PulseError> {
        self.online()?;
        if !self.created.borrow().contains_key(request_id) {
            return Err(PulseError::WrongRequest);
        }
        Ok(match *self.decision.borrow() {
            Decision::Approve => PollOutcome::Approved {
                artifact: self.receipt_for(request_id),
            },
            Decision::Reject => PollOutcome::Rejected,
            Decision::Expire => PollOutcome::Expired,
            Decision::Pending => PollOutcome::Pending,
        })
    }

    fn user_keys(&self) -> Result<UserKeys, PulseError> {
        self.online()?;
        let keys = if *self.user_registered.borrow() {
            vec![self.user.registered(*self.user_tier.borrow())]
        } else {
            Vec::new()
        };
        Ok(UserKeys {
            yid: self.yid.borrow().clone(),
            keys,
        })
    }

    fn public_keys(&self) -> Result<JwkSet, PulseError> {
        if *self.offline.borrow() {
            return Err(PulseError::Unavailable);
        }
        *self.public_key_fetches.borrow_mut() += 1;
        Ok(JwkSet {
            keys: self
                .yanez_keys
                .borrow()
                .iter()
                .map(YanezKey::signing_key)
                .collect(),
        })
    }

    fn consume(&self, artifact: &str, _consumer_token: &str) -> Result<(), PulseError> {
        if *self.offline.borrow() {
            return Err(PulseError::Unavailable);
        }
        let claims = crate::jws::verify(artifact, &self.public_keys()?)?.claims;
        // Like the real service, an expired consent is never consumed.
        let not_after = claims
            .get("yanez_consent_not_after")
            .and_then(Value::as_i64);
        if not_after.is_none_or(|deadline| *self.now.borrow() > deadline) {
            return Err(PulseError::ConsentExpired);
        }
        let jti = claims
            .get("jti")
            .and_then(Value::as_str)
            .ok_or(PulseError::ReceiptInvalid("claims"))?;
        if !self.consumed.borrow_mut().insert(jti.to_owned()) {
            return Err(PulseError::Replayed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_retry_with_the_same_idempotency_key_gets_the_same_request() {
        let pulse = FakePulse::new(1_790_467_200);
        let terms = json!({"schema_version": 1});
        let deadline = "2026-09-27T00:16:00Z";
        let first = pulse
            .create_authorization(&terms, deadline, "key-a")
            .unwrap();
        let retry = pulse
            .create_authorization(&terms, deadline, "key-a")
            .unwrap();
        let other = pulse
            .create_authorization(&terms, deadline, "key-b")
            .unwrap();
        assert_eq!(first.request_id, retry.request_id);
        assert_ne!(first.request_id, other.request_id);
        assert_eq!(pulse.created.borrow().len(), 2);
    }

    #[test]
    fn utc_timestamps_parse_to_epoch_seconds() {
        assert_eq!(epoch_from_utc("2026-09-27T00:00:00Z"), Some(1_790_467_200));
        assert_eq!(
            epoch_from_utc("2026-09-27T00:00:00+00:00"),
            Some(1_790_467_200)
        );
        assert_eq!(
            epoch_from_utc("2026-09-27T00:00:00.250000+00:00"),
            Some(1_790_467_200)
        );
        assert_eq!(epoch_from_utc("2000-02-29T23:59:59Z"), Some(951_868_799));
        assert_eq!(epoch_from_utc("1969-12-31T00:00:00Z"), Some(-86_400));
        for bad in [
            "2026-09-27T00:00:00",
            "2026-09-27T00:00:00+02:00",
            "2026-09-27 00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-09-27T00:00:00.Z",
            "",
        ] {
            assert_eq!(epoch_from_utc(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_receipt_carries_the_deadline_guard_asked_for() {
        let now = 1_790_467_200;
        let pulse = FakePulse::new(now);
        let terms = json!({"schema_version": 1});
        let created = pulse
            .create_authorization(&terms, "2026-09-27T00:01:00Z", "key-a")
            .unwrap();
        let artifact = pulse.receipt_for(&created.request_id);
        let keys = pulse.public_keys().unwrap();
        let claims = crate::jws::verify(&artifact, &keys).unwrap().claims;
        assert_eq!(claims["yanez_consent_not_after"], json!(now + 60));
        // The receipt stops verifying the second after that deadline.
        let (registry, pinned) = (pulse.user_keys().unwrap(), vec![pulse.user.public_hex()]);
        let policy = |at: i64| crate::receipt::ReceiptPolicy {
            expected_issuer: ISSUER,
            expected_yid: YID,
            expected_agent_key_id: Some(AGENT_KEY_ID),
            expected_request_id: &created.request_id,
            expected_terms: &terms,
            expected_consent_not_after: now + 60,
            min_tier: AssuranceTier::Medium,
            max_age_seconds: crate::receipt::DEFAULT_MAX_AGE_SECONDS,
            registry: &registry,
            pinned_user_keys: Some(&pinned),
            now_epoch: at,
        };
        let verify = |at| crate::receipt::verify_receipt(&artifact, &keys, &policy(at));
        verify(now + 60).expect("valid until the requested deadline");
        assert_eq!(verify(now + 61).unwrap_err(), PulseError::ConsentExpired);
        // Nor can it be consumed after the deadline.
        let consume_at = |at| {
            *pulse.now.borrow_mut() = at;
            pulse.consume(&artifact, "t")
        };
        assert_eq!(consume_at(now + 61), Err(PulseError::ConsentExpired));
        assert_eq!(consume_at(now + 60), Ok(()));
        assert_eq!(
            pulse
                .create_authorization(&terms, "not a time", "key-b")
                .unwrap_err(),
            PulseError::InvalidRequest("intent_expires_at")
        );
    }
}
