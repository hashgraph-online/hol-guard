//! Acceptance vectors for receipt verification, signed with real keys.

use serde_json::{json, Value};

use crate::jws::JwkSet;
use crate::receipt::{verify_receipt, ReceiptPolicy, RegisteredUserKey, DEFAULT_MAX_AGE_SECONDS};
use crate::terms::{build_terms, ActionBinding};
use crate::testkit::{mint_receipt, ReceiptSpec, UserKey, YanezKey, AGENT_KEY_ID, ISSUER, YID};
use crate::{AssuranceTier, PulseError};

const NOW: i64 = 1_790_467_200;
const REQUEST: &str = "azr_0001";

fn terms() -> Value {
    build_terms(
        &[3; 32],
        &ActionBinding {
            purpose: "approval_decision",
            action: "allow-once",
            scope: "workspace",
            subject: "cmd",
            session_nonce: "sn",
            session_binding: "sb",
            request_nonce: "nonce-0123456789abcdef",
            factor_generation: 1,
        },
    )
    .unwrap()
}

struct World {
    yanez: YanezKey,
    user: UserKey,
    jwks: JwkSet,
    registered: Vec<RegisteredUserKey>,
    terms: Value,
}

fn world() -> World {
    let yanez = YanezKey::new("k1", 1);
    let user = UserKey::new(2);
    let jwks = JwkSet::parse(&json!({"keys": [yanez.jwk()]})).unwrap();
    let registered = vec![user.registered(Some(AssuranceTier::High))];
    World {
        yanez,
        user,
        jwks,
        registered,
        terms: terms(),
    }
}

fn policy<'a>(w: &'a World, now: i64) -> ReceiptPolicy<'a> {
    ReceiptPolicy {
        expected_issuer: Some(ISSUER),
        expected_yid: YID,
        expected_agent_key_id: Some(AGENT_KEY_ID),
        expected_request_id: REQUEST,
        expected_terms: &w.terms,
        min_tier: AssuranceTier::Medium,
        max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
        registered_keys: &w.registered,
        now_epoch: now,
    }
}

fn spec(w: &World) -> ReceiptSpec {
    ReceiptSpec::new(REQUEST, w.terms.clone(), NOW)
}

fn check(w: &World, s: &ReceiptSpec) -> Result<crate::receipt::VerifiedReceipt, PulseError> {
    verify_receipt(
        &mint_receipt(s, &w.yanez, &w.user),
        &w.jwks,
        &policy(w, NOW + 5),
    )
}

#[test]
fn accept_a_genuine_fresh_receipt() {
    let w = world();
    let r = check(&w, &spec(&w)).expect("valid");
    assert_eq!(r.yid, YID);
    assert_eq!(r.jti, REQUEST);
    assert_eq!(r.tier, AssuranceTier::High);
}

#[test]
fn wrong_yid_is_refused() {
    let w = world();
    let mut s = spec(&w);
    s.yid = "yid_attacker".into();
    s.signed_yid = Some("yid_attacker".into());
    assert_eq!(check(&w, &s).unwrap_err(), PulseError::WrongYid);
}

#[test]
fn envelope_yid_must_match_receipt_subject() {
    let w = world();
    let mut s = spec(&w);
    s.signed_yid = Some("yid_other".into());
    assert!(matches!(
        check(&w, &s).unwrap_err(),
        PulseError::UserSignatureInvalid("envelope_yid")
    ));
}

#[test]
fn wrong_issuer_is_refused() {
    let w = world();
    let mut s = spec(&w);
    s.issuer = "https://evil.example".into();
    assert_eq!(check(&w, &s).unwrap_err(), PulseError::WrongIssuer);
}

#[test]
fn low_assurance_is_refused() {
    let w = world();
    let mut s = spec(&w);
    s.tier = AssuranceTier::Low;
    assert_eq!(check(&w, &s).unwrap_err(), PulseError::AssuranceTooLow);
    let mut high_floor = policy(&w, NOW + 5);
    high_floor.min_tier = AssuranceTier::High;
    let mut s = spec(&w);
    s.tier = AssuranceTier::Medium;
    let artifact = mint_receipt(&s, &w.yanez, &w.user);
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &high_floor).unwrap_err(),
        PulseError::AssuranceTooLow
    );
}

#[test]
fn a_low_floor_is_never_accepted_as_policy() {
    let w = world();
    let mut p = policy(&w, NOW);
    p.min_tier = AssuranceTier::Low;
    let artifact = mint_receipt(&spec(&w), &w.yanez, &w.user);
    assert!(matches!(
        verify_receipt(&artifact, &w.jwks, &p).unwrap_err(),
        PulseError::InvalidRequest(_)
    ));
}

#[test]
fn terms_for_another_action_are_refused() {
    let w = world();
    let mut s = spec(&w);
    let mut other = w.terms.clone();
    other["hol_guard"]["binding"] = json!("00".repeat(32));
    s.terms = other.clone();
    s.signed_terms = Some(other);
    assert_eq!(check(&w, &s).unwrap_err(), PulseError::TermsMismatch);
}

#[test]
fn receipt_terms_must_match_what_the_user_signed() {
    let w = world();
    let mut s = spec(&w);
    let mut signed = w.terms.clone();
    signed["summary"] = json!("something else");
    s.signed_terms = Some(signed);
    assert!(matches!(
        check(&w, &s).unwrap_err(),
        PulseError::UserSignatureInvalid("envelope_terms")
    ));
}

#[test]
fn stale_and_consent_expired_receipts_are_refused() {
    let w = world();
    let artifact = mint_receipt(&spec(&w), &w.yanez, &w.user);
    let late = NOW + DEFAULT_MAX_AGE_SECONDS + 1;
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, late)).unwrap_err(),
        PulseError::Stale
    );
    let mut s = spec(&w);
    s.consent_not_after = NOW + 2;
    let artifact = mint_receipt(&s, &w.yanez, &w.user);
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, NOW + 3)).unwrap_err(),
        PulseError::ConsentExpired
    );
}

#[test]
fn a_decision_dated_in_the_future_is_refused() {
    let w = world();
    let mut s = spec(&w);
    s.decided_at = NOW + 600;
    assert!(matches!(
        check(&w, &s).unwrap_err(),
        PulseError::ReceiptInvalid("future")
    ));
}

#[test]
fn receipt_for_another_request_is_refused() {
    let w = world();
    let mut s = spec(&w);
    s.request_id = "azr_9999".into();
    assert_eq!(check(&w, &s).unwrap_err(), PulseError::WrongRequest);
}

#[test]
fn receipt_from_another_agent_key_is_refused() {
    let w = world();
    let mut s = spec(&w);
    s.agent_key_id = "yak_ffffffffffff".into();
    assert_eq!(check(&w, &s).unwrap_err(), PulseError::WrongAgentKey);
}

#[test]
fn forged_yanez_signature_and_unknown_kid_are_refused() {
    let w = world();
    let forger = YanezKey::new("k1", 99);
    let artifact = mint_receipt(&spec(&w), &forger, &w.user);
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::ReceiptInvalid("signature")
    );
    let rotated = YanezKey::new("k2", 5);
    let artifact = mint_receipt(&spec(&w), &rotated, &w.user);
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::UnknownSigningKey
    );
}

#[test]
fn yanez_key_rotation_verifies_with_retired_and_current_keys() {
    let w = world();
    let current = YanezKey::new("k2", 5);
    let both = JwkSet::parse(&json!({"keys": [w.yanez.jwk(), current.jwk()]})).unwrap();
    for key in [&w.yanez, &current] {
        let artifact = mint_receipt(&spec(&w), key, &w.user);
        verify_receipt(&artifact, &both, &policy(&w, NOW)).expect("rotated key verifies");
    }
}

#[test]
fn forged_user_signature_is_refused() {
    let w = world();
    let impostor = UserKey::new(77);
    let artifact = mint_receipt(&spec(&w), &w.yanez, &impostor);
    // The impostor key is not registered to the pinned YID.
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::UserKeyNotRegistered
    );
}

#[test]
fn revoked_or_downgraded_user_keys_are_refused() {
    let mut w = world();
    w.registered.clear();
    let artifact = mint_receipt(&spec(&w), &w.yanez, &w.user);
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::UserKeyNotRegistered
    );
    w.registered = vec![w.user.registered(None)];
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::UserKeyNotRegistered
    );
    // A key registered at medium cannot vouch for a high-tier signature.
    w.registered = vec![w.user.registered(Some(AssuranceTier::Medium))];
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::UserKeyNotRegistered
    );
}

#[test]
fn user_key_rotation_accepts_the_new_registered_key() {
    let mut w = world();
    let new_device = UserKey::new(3);
    w.registered = vec![new_device.registered(Some(AssuranceTier::High))];
    let artifact = mint_receipt(&spec(&w), &w.yanez, &new_device);
    verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).expect("new device verifies");
    let old = mint_receipt(&spec(&w), &w.yanez, &w.user);
    assert_eq!(
        verify_receipt(&old, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::UserKeyNotRegistered
    );
}

#[test]
fn tampered_payload_and_wrong_alg_are_refused() {
    let w = world();
    let artifact = mint_receipt(&spec(&w), &w.yanez, &w.user);
    let mut parts: Vec<String> = artifact.split('.').map(str::to_owned).collect();
    let flipped = if &parts[1][0..2] == "ey" { "ex" } else { "ey" };
    parts[1].replace_range(0..2, flipped);
    assert!(verify_receipt(&parts.join("."), &w.jwks, &policy(&w, NOW)).is_err());
    use base64ct::{Base64UrlUnpadded, Encoding};
    let none = Base64UrlUnpadded::encode_string(br#"{"alg":"none","kid":"k1"}"#);
    let parts: Vec<&str> = artifact.split('.').collect();
    let forged = format!("{none}.{}.{}", parts[1], parts[2]);
    assert_eq!(
        verify_receipt(&forged, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::ReceiptInvalid("alg")
    );
}
