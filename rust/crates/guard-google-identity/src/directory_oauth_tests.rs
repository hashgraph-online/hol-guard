use super::*;
use crate::oauth::worker_input_tests::{command, credential};
use serde_json::json;

#[test]
fn directory_grant_has_no_send_scope_or_sender_execution_authority() {
    let session = GoogleSendAuthorization::begin_directory(
        GoogleLoginChallenge::new(
            "approved-client".into(),
            vec!["work.example".into()],
            [7; 32],
        )
        .unwrap(),
        "synthetic-secret".into(),
        "https://worker.example/callback".into(),
        tests::binding(),
    )
    .unwrap();
    let url = AuthUrl::new(session.authorization_url().into()).unwrap();
    let scope = url
        .url()
        .query_pairs()
        .find(|(k, _)| k == "scope")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(scope, format!("openid email {DIRECTORY_SCOPE}"));
    assert!(!scope.contains(SEND_SCOPE));
    let read = directory_test_credential();
    assert!(read.is_current());
    assert!(!read.authenticates_sender("sender@work.example"));
    assert!(read
        .prepare_command(command("sender@work.example", "body"))
        .is_err());
    let send = credential("subject-one");
    assert_eq!(
        send.directory_user("recipient@work.example").err(),
        Some(crate::directory::DirectoryError::Invalid)
    );
}

#[test]
fn directory_admission_refuses_send_or_mixed_scope_grants() {
    for scope in [
        format!("openid email {SEND_SCOPE}"),
        format!("openid email {DIRECTORY_SCOPE} {SEND_SCOPE}"),
    ] {
        let session = GoogleSendAuthorization::begin_directory(
            GoogleLoginChallenge::new(
                "approved-client".into(),
                vec!["work.example".into()],
                [7; 32],
            )
            .unwrap(),
            "synthetic-secret".into(),
            "https://worker.example/callback".into(),
            tests::binding(),
        )
        .unwrap();
        let state = session.state.to_string();
        let mut response = tests::response(&tests::claims(&session));
        response["scope"] = json!(scope);
        assert!(session
            .complete_with(
                &state,
                "synthetic-code".into(),
                &tests::binding(),
                |_| Ok::<_, ExchangeTransportError>(tests::http_response(&response)),
                tests::verify
            )
            .is_err());
    }
}
