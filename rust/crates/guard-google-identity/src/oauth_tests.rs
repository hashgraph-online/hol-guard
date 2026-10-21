use super::*;
use crate::{Base64UrlUnpadded, Digest, Encoding, Sha256, Token};
use serde_json::{json, Value};
use std::cell::Cell;
use std::collections::BTreeMap;

const ACCESS: &str = "synthetic-worker-access-token";
const SECRET: &str = "synthetic-registered-client-secret";
pub(super) fn binding() -> String {
    "a".repeat(64)
}
pub(super) fn session() -> GoogleSendAuthorization {
    GoogleSendAuthorization::begin(
        GoogleLoginChallenge::new(
            "approved-client".into(),
            vec!["work.example".into()],
            [7; 32],
        )
        .unwrap(),
        SECRET.into(),
        "https://worker.example/guard/business/google/callback".into(),
        binding(),
    )
    .unwrap()
}
fn pairs(value: &str) -> BTreeMap<String, String> {
    AuthUrl::new(value.into())
        .unwrap()
        .url()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}
pub(super) fn claims(session: &GoogleSendAuthorization) -> Value {
    let time = now().unwrap();
    json!({"iss":super::super::ISSUER,"aud":"approved-client","sub":"synthetic-subject",
        "hd":"work.example","email":"sender@work.example","email_verified":true,
        "nonce":session.challenge.nonce(),"iat":time,"exp":time+3600,
        "at_hash":Base64UrlUnpadded::encode_string(&Sha256::digest(ACCESS.as_bytes())[..16])})
}
pub(super) fn response(claims: &Value) -> Value {
    json!({"access_token":ACCESS,"refresh_token":"synthetic-refresh-token","token_type":"Bearer",
        "expires_in":3600,"scope":format!("openid email {SEND_SCOPE}"),
        "id_token":crate::tests::signed(&json!({"alg":"RS256","kid":"synthetic-key"}),claims)})
}
pub(super) fn http_response(value: &Value) -> HttpResponse {
    oauth2::http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(value).unwrap())
        .unwrap()
}
pub(super) fn verify(
    challenge: GoogleLoginChallenge,
    id: &str,
    access: &str,
) -> Result<GoogleIdentityEvidence, IdentityError> {
    challenge.verify_with_keys(
        Token::parse(id, access)?,
        access,
        &crate::tests::keys(),
        now()?,
    )
}

#[test]
fn registered_authorization_url_has_nonce_state_pkce_and_only_send_scopes() {
    let session = session();
    let params = pairs(session.authorization_url());
    assert!(session.authorization_url().starts_with(AUTHORIZE_URL));
    assert_eq!(params["client_id"], "approved-client");
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["scope"], format!("openid email {SEND_SCOPE}"));
    assert_eq!(params["nonce"], session.challenge.nonce());
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(params["include_granted_scopes"], "false");
    assert_eq!(params["access_type"], "offline");
    assert!(!session.authorization_url().contains(SECRET));
    assert!(!session
        .authorization_url()
        .contains(session.verifier.as_str()));
    let second = self::session();
    assert_ne!(params["state"], pairs(second.authorization_url())["state"]);
    assert_ne!(
        params["code_challenge"],
        pairs(second.authorization_url())["code_challenge"]
    );
}

#[test]
fn wrong_state_session_code_or_expired_challenge_has_zero_exchange_calls() {
    for failure in ["state", "session", "code", "expired"] {
        let mut session = session();
        let mut state = session.state.to_string();
        let mut owner = binding();
        let mut code = "synthetic-code".to_owned();
        match failure {
            "state" => state = "wrong-state".into(),
            "session" => owner = "b".repeat(64),
            "code" => code = "bad\ncode".into(),
            _ => session.challenge.created_at -= 301,
        }
        let calls = Cell::new(0);
        let result = session.complete_with(
            &state,
            code,
            &owner,
            |_| {
                calls.set(calls.get() + 1);
                Err(ExchangeTransportError)
            },
            verify,
        );
        assert!(result.is_err(), "{failure}");
        assert_eq!(calls.get(), 0, "{failure}");
    }
}

#[test]
fn exchange_outages_are_distinct_from_refused_or_malformed_grants() {
    for status in [400, 401, 429, 500, 503] {
        let session = session();
        let state = session.state.to_string();
        let result = session.complete_with(
            &state,
            "synthetic-code".into(),
            &binding(),
            |_| {
                let mut response = HttpResponse::new(b"private provider diagnostic".to_vec());
                *response.status_mut() = oauth2::http::StatusCode::from_u16(status).unwrap();
                Ok::<_, ExchangeTransportError>(response)
            },
            |_, _, _| panic!("failed exchange must not admit identity"),
        );
        let expected = if status == 429 || status >= 500 {
            IdentityError::ExchangeUnavailable
        } else {
            IdentityError::Invalid
        };
        assert_eq!(result.err(), Some(expected));
    }
    let session = session();
    let state = session.state.to_string();
    assert_eq!(
        session
            .complete_with(
                &state,
                "synthetic-code".into(),
                &binding(),
                |_| Err(ExchangeTransportError),
                verify
            )
            .err(),
        Some(IdentityError::ExchangeUnavailable)
    );
    let session = self::session();
    let state = session.state.to_string();
    assert_eq!(
        session
            .complete_with(
                &state,
                "synthetic-code".into(),
                &binding(),
                |_| Ok::<_, ExchangeTransportError>(http_response(&json!({}))),
                verify
            )
            .err(),
        Some(IdentityError::Invalid)
    );
}

#[test]
fn code_exchange_uses_owned_verifier_registered_redirect_and_secret() {
    let session = session();
    let expected_verifier = session.verifier.to_string();
    let state = session.state.to_string();
    let body = response(&claims(&session));
    let calls = Cell::new(0);
    let credential = session
        .complete_with(
            &state,
            "synthetic-code".into(),
            &binding(),
            |request| {
                calls.set(calls.get() + 1);
                assert_eq!(request.uri().to_string(), TOKEN_URL);
                assert_eq!(request.method(), "POST");
                let params = pairs(&format!(
                    "https://worker.example/?{}",
                    std::str::from_utf8(request.body()).unwrap()
                ));
                assert_eq!(params["code_verifier"], expected_verifier);
                assert_eq!(params["client_secret"], SECRET);
                assert_eq!(params["code"], "synthetic-code");
                assert_eq!(params["grant_type"], "authorization_code");
                assert_eq!(
                    params["redirect_uri"],
                    "https://worker.example/guard/business/google/callback"
                );
                Ok::<_, ExchangeTransportError>(http_response(&body))
            },
            verify,
        )
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert!(credential.is_current());
    assert!(credential.authenticates_sender("sender@work.example"));
    for sender in [
        "other@work.example",
        "sender+alias@work.example",
        "Sender@work.example",
    ] {
        assert!(!credential.authenticates_sender(sender));
    }
    assert!(credential.has_refresh_credential());
    assert_eq!(credential.identity().account_binding().len(), 64);
    assert!(credential.expires_at() <= now().unwrap() + 300);
    assert_eq!(credential.access_token.as_str(), ACCESS);
}

#[test]
fn signed_sender_claims_are_required_for_send_credentials() {
    for (field, value) in [
        ("email", Value::Null),
        ("email", json!("display <sender@work.example>")),
        ("email", json!("sender@@work.example")),
        ("email", json!("sender@WORK.EXAMPLE")),
        ("email", json!("sender\r\n@work.example")),
        ("email_verified", json!(false)),
        ("email_verified", Value::Null),
        ("email_verified", json!("true")),
    ] {
        let session = session();
        let state = session.state.to_string();
        let mut c = claims(&session);
        c[field] = value;
        let body = response(&c);
        assert!(session
            .complete_with(
                &state,
                "synthetic-code".into(),
                &binding(),
                |_| Ok::<_, ExchangeTransportError>(http_response(&body)),
                verify
            )
            .is_err());
    }
    for field in ["email", "email_verified"] {
        let session = session();
        let state = session.state.to_string();
        let mut c = claims(&session);
        c.as_object_mut().unwrap().remove(field);
        let body = response(&c);
        assert!(session
            .complete_with(
                &state,
                "synthetic-code".into(),
                &binding(),
                |_| Ok::<_, ExchangeTransportError>(http_response(&body)),
                verify
            )
            .is_err());
    }
}

#[test]
fn sender_match_expires_with_credential_and_accepts_canonical_email_scope() {
    let session = session();
    let state = session.state.to_string();
    let mut body = response(&claims(&session));
    body["scope"] = json!(format!(
        "openid https://www.googleapis.com/auth/userinfo.email {SEND_SCOPE}"
    ));
    let mut credential = session
        .complete_with(
            &state,
            "synthetic-code".into(),
            &binding(),
            |_| Ok::<_, ExchangeTransportError>(http_response(&body)),
            verify,
        )
        .unwrap();
    assert!(credential.authenticates_sender("sender@work.example"));
    credential.expires_monotonic = Instant::now();
    assert!(!credential.authenticates_sender("sender@work.example"));
}

#[test]
fn grant_scope_type_expiry_and_missing_identity_fail_before_identity_admission() {
    for (field, value) in [
        ("scope", json!("openid")),
        (
            "scope",
            json!(format!("openid {SEND_SCOPE} https://mail.google.com/")),
        ),
        ("scope", json!(format!("openid {SEND_SCOPE} {SEND_SCOPE}"))),
        ("scope", Value::Null),
        ("scope", json!(format!("openid\n{SEND_SCOPE}"))),
        ("access_token", json!("bad\ntoken")),
        ("token_type", json!("MAC")),
        ("expires_in", json!(0)),
        ("expires_in", json!(3601)),
        ("expires_in", Value::Null),
        ("refresh_token", json!("bad\ntoken")),
        ("id_token", Value::Null),
    ] {
        let session = session();
        let state = session.state.to_string();
        let mut body = response(&claims(&session));
        body[field] = value;
        let admitted = Cell::new(0);
        let result = session.complete_with(
            &state,
            "synthetic-code".into(),
            &binding(),
            |_| Ok::<_, ExchangeTransportError>(http_response(&body)),
            |challenge, id, access| {
                admitted.set(admitted.get() + 1);
                verify(challenge, id, access)
            },
        );
        assert!(result.is_err(), "{field}");
        assert_eq!(admitted.get(), 0, "{field}");
    }
}

#[test]
fn exchanged_token_still_requires_google_signature_nonce_tenant_and_access_binding() {
    for (field, value) in [
        ("nonce", json!("wrong-nonce")),
        ("aud", json!("wrong-client")),
        ("hd", json!("personal.example")),
        ("at_hash", json!("wrong-access-hash")),
    ] {
        let session = session();
        let state = session.state.to_string();
        let mut c = claims(&session);
        c[field] = value;
        let body = response(&c);
        assert!(
            session
                .complete_with(
                    &state,
                    "synthetic-code".into(),
                    &binding(),
                    |_| Ok::<_, ExchangeTransportError>(http_response(&body)),
                    verify
                )
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn token_response_known_duplicates_and_generic_serialization_are_refused() {
    let session = session();
    let body = response(&claims(&session));
    let decoded: GoogleTokenResponse = serde_json::from_value(body.clone()).unwrap();
    assert!(serde_json::to_string(&decoded).is_err());
    assert_eq!(format!("{decoded:?}"), "GoogleTokenResponse(REDACTED)");
    for field in ["access_token", "id_token", "scope", "token_type"] {
        let original = serde_json::to_string(&body).unwrap();
        let duplicate = original.replacen('{', &format!("{{\"{field}\":{},", body[field]), 1);
        assert!(
            serde_json::from_str::<GoogleTokenResponse>(&duplicate).is_err(),
            "{field}"
        );
    }
}

#[test]
fn reconnecting_a_pinned_account_refuses_another_valid_subject() {
    let first = session();
    let state = first.state.to_string();
    let body = response(&claims(&first));
    let enrolled = first
        .complete_with(
            &state,
            "synthetic-code".into(),
            &binding(),
            |_| Ok::<_, ExchangeTransportError>(http_response(&body)),
            verify,
        )
        .unwrap();
    let challenge = GoogleLoginChallenge::new(
        "approved-client".into(),
        vec!["work.example".into()],
        [7; 32],
    )
    .unwrap()
    .with_expected_account(enrolled.identity().account_binding())
    .unwrap();
    let reconnect = GoogleSendAuthorization::begin(
        challenge,
        SECRET.into(),
        "https://worker.example/guard/business/google/callback".into(),
        binding(),
    )
    .unwrap();
    let state = reconnect.state.to_string();
    let mut c = claims(&reconnect);
    c["sub"] = json!("another-valid-subject");
    let body = response(&c);
    assert!(reconnect
        .complete_with(
            &state,
            "synthetic-code".into(),
            &binding(),
            |_| Ok::<_, ExchangeTransportError>(http_response(&body)),
            verify
        )
        .is_err());
}

#[test]
fn configuration_rejects_unregistered_shape_and_unsafe_redirects() {
    for redirect in [
        "http://worker.example/callback",
        "https://user:password@worker.example/callback",
        "https://worker.example/callback#fragment",
        "https://worker.example/callback?override=1",
        "",
    ] {
        assert!(GoogleSendAuthorization::begin(
            GoogleLoginChallenge::new(
                "approved-client".into(),
                vec!["work.example".into()],
                [7; 32]
            )
            .unwrap(),
            SECRET.into(),
            redirect.into(),
            binding()
        )
        .is_err());
    }
    let request = oauth2::http::Request::builder()
        .method("POST")
        .uri("https://attacker.example/token")
        .body(b"synthetic-code".to_vec())
        .unwrap();
    assert!(exchange_http(request).is_err());
}

#[test]
fn token_deadline_starts_before_exchange_and_cannot_extend_after_clock_rollback() {
    let mono = Instant::now();
    let start = ExchangeStart {
        wall: 100,
        monotonic: mono,
    };
    let (wall, deadline) =
        credential_deadline(&start, 103, 103, 400, 5, mono + Duration::from_secs(3)).unwrap();
    assert_eq!(wall, 105);
    assert_eq!(deadline, mono + Duration::from_secs(5));
    assert!(credential_deadline(&start, 106, 106, 400, 5, mono + Duration::from_secs(6)).is_err());
    assert!(credential_deadline(&start, 103, 103, 400, 5, mono + Duration::from_secs(5)).is_err());
    assert!(credential_deadline(&start, 99, 100, 400, 5, mono).is_err());
    assert!(credential_deadline(&start, 103, 102, 400, 5, mono).is_err());
    let (wall, deadline) =
        credential_deadline(&start, 101, 102, 104, 3600, mono + Duration::from_secs(2)).unwrap();
    assert_eq!(wall, 104);
    assert_eq!(deadline, mono + Duration::from_secs(4));
}

#[test]
fn token_endpoint_requires_one_json_content_type() {
    for (value, expected) in [
        ("application/json", true),
        ("application/json; charset=utf-8", true),
        ("APPLICATION/JSON", true),
        ("text/html", false),
        ("text/json", false),
    ] {
        let response = oauth2::http::Response::builder()
            .header("content-type", value)
            .body(())
            .unwrap();
        assert_eq!(json_media_type(response.headers()), expected);
    }
    let response = oauth2::http::Response::builder().body(()).unwrap();
    assert!(!json_media_type(response.headers()));
    let response = oauth2::http::Response::builder()
        .header("content-type", "application/json")
        .header("content-type", "text/html")
        .body(())
        .unwrap();
    assert!(!json_media_type(response.headers()));
}
