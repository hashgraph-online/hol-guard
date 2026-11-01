//! Acceptance vectors for receipt verification, signed with real keys.

use serde_json::{json, Value};

use crate::client::UserKeys;
use crate::jws::JwkSet;
use crate::receipt::{
    verify_receipt, ReceiptPolicy, DEFAULT_MAX_AGE_SECONDS, SIGNED_AT_ALLOWANCE_SECONDS,
};
use crate::terms::{build_terms, ActionBinding};
use crate::testkit::{
    mint_receipt, mint_receipt_edited, ReceiptSpec, UserKey, YanezKey, AGENT_KEY_ID, ISSUER, YID,
};
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
    registry: UserKeys,
    pinned: Vec<String>,
    terms: Value,
}

fn world() -> World {
    let yanez = YanezKey::new("k1", 1);
    let user = UserKey::new(2);
    let jwks = JwkSet::parse(&json!({"keys": [yanez.jwk()]})).unwrap();
    let registry = UserKeys {
        yid: YID.to_owned(),
        keys: vec![user.registered(Some(AssuranceTier::High))],
    };
    World {
        pinned: vec![user.public_hex()],
        yanez,
        user,
        jwks,
        registry,
        terms: terms(),
    }
}

fn policy<'a>(w: &'a World, now: i64) -> ReceiptPolicy<'a> {
    ReceiptPolicy {
        expected_issuer: ISSUER,
        expected_yid: YID,
        expected_agent_key_id: Some(AGENT_KEY_ID),
        expected_request_id: REQUEST,
        expected_terms: &w.terms,
        expected_consent_not_after: NOW + 300,
        min_tier: AssuranceTier::Medium,
        max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
        registry: &w.registry,
        pinned_user_keys: Some(&w.pinned),
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
fn an_old_signature_inside_a_fresh_receipt_is_refused() {
    let w = world();
    // The outer edge: the oldest decision, signed by a phone running slow.
    let (mut s, late) = (spec(&w), NOW + DEFAULT_MAX_AGE_SECONDS);
    s.signed_at = Some(NOW - SIGNED_AT_ALLOWANCE_SECONDS);
    s.consent_not_after = late;
    let artifact = mint_receipt(&s, &w.yanez, &w.user);
    let oldest = ReceiptPolicy {
        expected_consent_not_after: late,
        ..policy(&w, late)
    };
    verify_receipt(&artifact, &w.jwks, &oldest).expect("within both bounds");
    for (signed_at, ok) in [
        (NOW - SIGNED_AT_ALLOWANCE_SECONDS, true),
        (NOW + SIGNED_AT_ALLOWANCE_SECONDS, true),
        (NOW - SIGNED_AT_ALLOWANCE_SECONDS - 1, false),
        (NOW - DEFAULT_MAX_AGE_SECONDS * 4, false),
        (NOW + SIGNED_AT_ALLOWANCE_SECONDS + 1, false),
    ] {
        let mut s = spec(&w);
        s.signed_at = Some(signed_at);
        let result = check(&w, &s);
        if ok {
            assert!(
                result.is_ok(),
                "signed_at {signed_at} is within the allowance"
            );
        } else {
            assert!(
                matches!(
                    result,
                    Err(PulseError::UserSignatureInvalid("envelope_signed_at"))
                ),
                "signed_at {signed_at} is refused"
            );
        }
    }
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
    w.registry.keys.clear();
    let artifact = mint_receipt(&spec(&w), &w.yanez, &w.user);
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::UserKeyNotRegistered
    );
    w.registry.keys = vec![w.user.registered(None)];
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::UserKeyNotRegistered
    );
    // A key registered at medium cannot vouch for a high-tier signature.
    w.registry.keys = vec![w.user.registered(Some(AssuranceTier::Medium))];
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::UserKeyNotRegistered
    );
}

#[test]
fn a_new_device_counts_only_once_guard_pins_it() {
    let mut w = world();
    let new_device = UserKey::new(3);
    w.registry.keys = vec![new_device.registered(Some(AssuranceTier::High))];
    let artifact = mint_receipt(&spec(&w), &w.yanez, &new_device);
    // Registered at Yanez is not enough: Yanez alone cannot add a key.
    assert_eq!(
        verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).unwrap_err(),
        PulseError::UserKeyNotPinned
    );
    let enrollment = ReceiptPolicy {
        pinned_user_keys: None,
        ..policy(&w, NOW)
    };
    verify_receipt(&artifact, &w.jwks, &enrollment).expect("enrollment pins the key");
    w.pinned.push(new_device.public_hex());
    verify_receipt(&artifact, &w.jwks, &policy(&w, NOW)).expect("confirmed device verifies");
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

/// Verify a receipt whose JSON text was rewritten before signing.
fn check_edited(
    w: &World,
    edit_envelope: impl Fn(&mut String),
    edit_token: impl Fn(&mut String, &mut String),
) -> Result<crate::receipt::VerifiedReceipt, PulseError> {
    let artifact = mint_receipt_edited(&spec(w), &w.yanez, &w.user, edit_envelope, edit_token);
    verify_receipt(&artifact, &w.jwks, &policy(w, NOW + 5))
}

fn replace_once(text: &mut String, from: &str, to: &str) {
    assert!(text.contains(from), "{from} not in {text}");
    *text = text.replacen(from, to, 1);
}

#[test]
fn duplicate_keys_are_refused_in_the_claims_and_the_envelope() {
    let w = world();
    let claims = check_edited(
        &w,
        |_| {},
        |_, c| {
            replace_once(
                c,
                r#""yanez_decision":"approved""#,
                r#""yanez_decision":"rejected","yanez_decision":"approved""#,
            );
        },
    );
    assert_eq!(
        claims.unwrap_err(),
        PulseError::ReceiptInvalid("claims_json")
    );
    let envelope = check_edited(
        &w,
        |e| {
            replace_once(
                e,
                r#""decision":"approve""#,
                r#""decision":"reject","decision":"approve""#,
            )
        },
        |_, _| {},
    );
    assert_eq!(
        envelope.unwrap_err(),
        PulseError::UserSignatureInvalid("envelope_json")
    );
}

#[test]
fn a_header_with_crit_is_refused() {
    let w = world();
    let result = check_edited(
        &w,
        |_| {},
        |h, _| replace_once(h, r#""kid":"#, r#""crit":["exp"],"kid":"#),
    );
    assert_eq!(result.unwrap_err(), PulseError::ReceiptInvalid("crit"));
}

#[test]
fn the_envelope_must_be_an_approval_decision() {
    let w = world();
    let rejected = check_edited(
        &w,
        |e| replace_once(e, r#""decision":"approve""#, r#""decision":"reject""#),
        |_, _| {},
    );
    assert_eq!(
        rejected.unwrap_err(),
        PulseError::UserSignatureInvalid("envelope_decision")
    );
    let other_action = check_edited(
        &w,
        |e| {
            replace_once(
                e,
                r#""action":"agent_authorizations.decision""#,
                r#""action":"agent_keys.enroll""#,
            )
        },
        |_, _| {},
    );
    assert_eq!(
        other_action.unwrap_err(),
        PulseError::UserSignatureInvalid("envelope_action")
    );
}

#[test]
fn iat_must_equal_the_decision_time() {
    let w = world();
    let result = check_edited(
        &w,
        |_| {},
        |_, c| {
            replace_once(
                c,
                &format!(r#""iat":{NOW}"#),
                &format!(r#""iat":{}"#, NOW - 1),
            );
        },
    );
    assert_eq!(result.unwrap_err(), PulseError::ReceiptInvalid("iat"));
}

#[test]
fn a_registry_answer_for_another_yid_cannot_vouch() {
    let mut w = world();
    w.registry.yid = "yid_other".into();
    assert_eq!(check(&w, &spec(&w)).unwrap_err(), PulseError::WrongYid);
}

#[test]
fn the_consent_bound_cannot_be_later_than_guard_asked() {
    let w = world();
    let mut later = spec(&w);
    later.consent_not_after = NOW + 301;
    assert_eq!(
        check(&w, &later).unwrap_err(),
        PulseError::ReceiptInvalid("consent")
    );
    let mut earlier = spec(&w);
    earlier.consent_not_after = NOW + 60;
    assert!(
        check(&w, &earlier).is_ok(),
        "an earlier bound is the user's choice"
    );
}
