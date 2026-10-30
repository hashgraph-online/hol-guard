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

pub const ISSUER: &str = "https://yid.yanez.ai";
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
        }
    }
}

/// Sign a receipt with `yanez` and `user`.
pub fn mint_receipt(spec: &ReceiptSpec, yanez: &YanezKey, user: &UserKey) -> String {
    let envelope = json!({
        "version": 1,
        "issuer": spec.issuer,
        "action": "agent_authorizations.decision",
        "assurance_tier": spec.tier.as_str(),
        "authorization_request_id": spec.request_id,
        "decision": "approve",
        "consent_not_after": spec.consent_not_after,
        "signed_at": spec.decided_at,
        "terms": spec.signed_terms.clone().unwrap_or_else(|| spec.terms.clone()),
        "yid": spec.signed_yid.clone().unwrap_or_else(|| spec.yid.clone()),
    });
    let message = serde_json::to_vec(&envelope).expect("envelope");
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
    let header = json!({"alg": "EdDSA", "kid": yanez.kid, "typ": "JWT"});
    let h = Base64UrlUnpadded::encode_string(header.to_string().as_bytes());
    let c = Base64UrlUnpadded::encode_string(Value::Object(claims).to_string().as_bytes());
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
        spec.yid = self.yid.borrow().clone();
        spec.tier = *self.approve_tier.borrow();
        let keys = self.yanez_keys.borrow();
        mint_receipt(&spec, keys.last().expect("key"), &self.user)
    }
}

impl PulseTransport for FakePulse {
    fn create_authorization(
        &self,
        terms: &Value,
        _consent_not_after_rfc3339: &str,
        _idempotency_key: &str,
    ) -> Result<CreatedAuthorization, PulseError> {
        self.online()?;
        let mut next = self.next_id.borrow_mut();
        *next += 1;
        let request_id = format!("azr_{next:04}");
        self.created
            .borrow_mut()
            .insert(request_id.clone(), terms.clone());
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
        let jti = crate::jws::verify(artifact, &self.public_keys()?)?
            .claims
            .get("jti")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if !self.consumed.borrow_mut().insert(jti) {
            return Err(PulseError::Replayed);
        }
        Ok(())
    }
}
