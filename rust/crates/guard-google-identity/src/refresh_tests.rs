use super::*;
use crate::oauth::worker_input_tests::{command, credential};
use serde_json::json;
use std::cell::Cell;

fn token() -> serde_json::Value {
    json!({"access_token":"synthetic-renewed-access", "expires_in":3600,
        "token_type":"Bearer", "scope":format!("openid email {SEND_SCOPE}")})
}
fn info() -> serde_json::Value {
    json!({"sub":"subject-one", "hd":"work.example", "email":"sender@work.example", "email_verified":true})
}
fn reply(value: &serde_json::Value) -> HttpResponse {
    super::super::tests::http_response(value)
}

#[test]
fn rollback_during_exchange_or_identity_lookup_never_returns_authorization() {
    for during in [true, false] {
        let original = credential("subject-one");
        let time = now().unwrap();
        let mut times = if during {
            vec![time, time - 1]
        } else {
            vec![time, time + 1, time]
        }
        .into_iter();
        let lookups = Cell::new(0);
        let result = original.refresh_with_clock(
            |_| Ok::<_, ExchangeTransportError>(reply(&token())),
            |_| {
                lookups.set(lookups.get() + 1);
                Ok::<_, ExchangeTransportError>(reply(&info()))
            },
            || Ok(times.next().unwrap()),
        );
        assert_eq!(result.err(), Some(IdentityError::Expired));
        assert_eq!(lookups.get(), usize::from(!during));
    }
}

#[test]
fn entropy_or_missing_refresh_failure_revokes_pending_inputs_before_any_exchange() {
    for entropy in [true, false] {
        let mut original = credential("subject-one");
        if !entropy {
            original.refresh_token = None;
        }
        let mut account = GoogleSendAccount::new(original).unwrap();
        let pending = account
            .prepare_command(command("sender@work.example", "pending"))
            .unwrap();
        let exchanges = Cell::new(0);
        assert_eq!(
            account.refresh_with_epoch(
                |_| {
                    exchanges.set(exchanges.get() + 1);
                    Err(IdentityError::ExchangeUnavailable)
                },
                || Err(GoogleSendAccountError::Unavailable)
            ),
            Err(IdentityError::Invalid)
        );
        assert_eq!(exchanges.get(), 0);
        assert!(!pending.is_current() && !account.is_current() && !account.can_refresh());
    }
}

#[test]
fn malformed_duplicate_and_provider_error_responses_never_create_credentials() {
    for userinfo_failure in [false, true] {
        for status in [200, 401, 503] {
            let calls = Cell::new(0);
            let malformed = || {
                oauth2::http::Response::builder().status(status)
                .header("content-type", "application/json")
                .body(if userinfo_failure {
                    br#"{"sub":"subject-one","sub":"subject-other","hd":"work.example","email":"sender@work.example","email_verified":true}"#.to_vec()
                } else {
                    br#"{"access_token":"synthetic-a","access_token":"synthetic-b","token_type":"Bearer","expires_in":3600}"#.to_vec()
                }).unwrap()
            };
            let result = credential("subject-one").refresh_with(
                |_| {
                    Ok::<_, ExchangeTransportError>(if userinfo_failure {
                        reply(&token())
                    } else {
                        malformed()
                    })
                },
                |_| {
                    calls.set(calls.get() + 1);
                    Ok::<_, ExchangeTransportError>(malformed())
                },
            );
            assert_eq!(
                result.err(),
                Some(if status == 503 {
                    IdentityError::ExchangeUnavailable
                } else {
                    IdentityError::Invalid
                })
            );
            assert_eq!(calls.get(), usize::from(userinfo_failure));
        }
    }
}

#[test]
fn missing_managed_domain_or_oversized_identity_response_never_renews() {
    let mut missing = info();
    missing.as_object_mut().unwrap().remove("hd");
    let oversized = json!({"padding":"x".repeat(16 * 1024)});
    for value in [missing, oversized] {
        assert_eq!(
            credential("subject-one")
                .refresh_with(
                    |_| Ok::<_, ExchangeTransportError>(reply(&token())),
                    |_| Ok::<_, ExchangeTransportError>(reply(&value))
                )
                .err(),
            Some(IdentityError::Invalid)
        );
    }
}

#[test]
fn registered_refresh_uses_fixed_exchange_and_same_principal_with_no_token_export() {
    let original = credential("subject-one");
    let calls = Cell::new(0);
    let renewed = original
        .refresh_with(
            |request| {
                calls.set(calls.get() + 1);
                assert_eq!(request.method(), "POST");
                assert_eq!(*request.uri(), TOKEN_URL);
                let pairs = oauth2::url::form_urlencoded::parse(request.body())
                    .collect::<std::collections::BTreeMap<_, _>>();
                assert_eq!(pairs["grant_type"], "refresh_token");
                assert_eq!(pairs["refresh_token"], "synthetic-refresh-token");
                assert_eq!(pairs["client_id"], "approved-client");
                assert!(!pairs.contains_key("scope") && !pairs.contains_key("redirect_uri"));
                Ok::<_, ExchangeTransportError>(reply(&token()))
            },
            |access| {
                calls.set(calls.get() + 1);
                assert_eq!(access, "synthetic-renewed-access");
                Ok::<_, ExchangeTransportError>(reply(&info()))
            },
        )
        .unwrap();
    assert_eq!(calls.get(), 2);
    assert_eq!(
        renewed.identity().account_binding(),
        original.identity().account_binding()
    );
    assert!(renewed.is_current() && renewed.can_refresh());
    assert_eq!(
        renewed.refresh_token.as_ref().unwrap().as_str(),
        "synthetic-refresh-token"
    );
    assert!(renewed.expires_at() <= now().unwrap() + crate::LIFETIME);
}

#[test]
fn refresh_preserves_known_scopes_when_omitted_and_retains_rotated_refresh_material() {
    let mut response = token();
    response.as_object_mut().unwrap().remove("scope");
    response["refresh_token"] = json!("synthetic-rotated-refresh");
    let renewed = credential("subject-one")
        .refresh_with(
            |_| Ok::<_, ExchangeTransportError>(reply(&response)),
            |_| Ok::<_, ExchangeTransportError>(reply(&info())),
        )
        .unwrap();
    assert_eq!(
        renewed.refresh_token.as_ref().unwrap().as_str(),
        "synthetic-rotated-refresh"
    );
}

#[test]
fn changed_subject_tenant_mailbox_or_unverified_email_never_renews() {
    for key in ["sub", "hd", "email", "email_verified"] {
        let mut changed = info();
        changed[key] = match key {
            "sub" => json!("subject-other"),
            "hd" => json!("other.example"),
            "email" => json!("other@work.example"),
            _ => json!(false),
        };
        assert_eq!(
            credential("subject-one")
                .refresh_with(
                    |_| Ok::<_, ExchangeTransportError>(reply(&token())),
                    |_| Ok::<_, ExchangeTransportError>(reply(&changed))
                )
                .err(),
            Some(IdentityError::Invalid)
        );
    }
}

#[test]
fn excessive_scopes_bad_token_and_missing_registration_refuse_before_userinfo() {
    for key in ["scope", "access_token", "expires_in", "token_type"] {
        let mut changed = token();
        changed[key] = match key {
            "scope" => json!(format!(
                "openid email {SEND_SCOPE} https://www.googleapis.com/auth/drive"
            )),
            "access_token" => json!(""),
            "expires_in" => json!(0),
            _ => json!("MAC"),
        };
        let calls = Cell::new(0);
        assert_eq!(
            credential("subject-one")
                .refresh_with(
                    |_| Ok::<_, ExchangeTransportError>(reply(&changed)),
                    |_| {
                        calls.set(calls.get() + 1);
                        Ok::<_, ExchangeTransportError>(reply(&info()))
                    }
                )
                .err(),
            Some(IdentityError::Invalid)
        );
        assert_eq!(calls.get(), 0);
    }
    let mut missing = credential("subject-one");
    missing.refresh_token = None;
    assert_eq!(
        missing
            .refresh_with(
                |_| panic!("no registered refresh"),
                |_| Ok::<_, ExchangeTransportError>(reply(&info()))
            )
            .err(),
        Some(IdentityError::Invalid)
    );
}

#[test]
fn successful_account_refresh_invalidates_pending_bindings_and_failure_stays_revoked() {
    let mut account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let pending = account
        .prepare_command(command("sender@work.example", "same bytes"))
        .unwrap();
    let binding = pending.input_binding().to_owned();
    account
        .refresh_with(|original| {
            original.refresh_with(
                |_| Ok::<_, ExchangeTransportError>(reply(&token())),
                |_| Ok::<_, ExchangeTransportError>(reply(&info())),
            )
        })
        .unwrap();
    assert!(!pending.is_current());
    assert_ne!(
        account
            .prepare_command(command("sender@work.example", "same bytes"))
            .unwrap()
            .input_binding(),
        binding
    );
    let pending = account
        .prepare_command(command("sender@work.example", "pending"))
        .unwrap();
    assert_eq!(
        account.refresh_with(|_| Err(IdentityError::ExchangeUnavailable)),
        Err(IdentityError::ExchangeUnavailable)
    );
    assert!(!pending.is_current() && !account.is_current() && !account.can_refresh());
    let calls = Cell::new(0);
    assert_eq!(
        account.refresh_with(|_| {
            calls.set(calls.get() + 1);
            Err(IdentityError::Invalid)
        }),
        Err(IdentityError::Invalid)
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn expired_access_material_can_refresh_but_clock_rollback_cannot() {
    let mut original = credential("subject-one");
    original.expires_at = 0;
    original.expires_monotonic = Instant::now();
    assert!(!original.is_current());
    assert!(original
        .refresh_with(
            |_| Ok::<_, ExchangeTransportError>(reply(&token())),
            |_| Ok::<_, ExchangeTransportError>(reply(&info()))
        )
        .unwrap()
        .is_current());
    original.refresh_registration.as_mut().unwrap().observed_at = now().unwrap() + 60;
    assert_eq!(
        original
            .refresh_with(
                |_| panic!("rollback must refuse before exchange"),
                |_| Ok::<_, ExchangeTransportError>(reply(&info()))
            )
            .err(),
        Some(IdentityError::Expired)
    );
}
