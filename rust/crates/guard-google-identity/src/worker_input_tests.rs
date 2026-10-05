use super::tests::{binding, claims, http_response, response, session, verify};
use super::*;
use crate::worker_input::GoogleWorkerInputError;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::json;

fn credential(subject: &str) -> GoogleSendCredential {
    let session = session();
    let state = session.state.to_string();
    let mut claims = claims(&session);
    claims["sub"] = json!(subject);
    let response = response(&claims);
    session
        .complete_with(
            &state,
            "synthetic-code".into(),
            &binding(),
            |_| Ok::<_, ExchangeTransportError>(http_response(&response)),
            verify,
        )
        .unwrap()
}

fn command(sender: &str, body: &str) -> String {
    let mime = format!("From: {sender}\r\nTo: recipient@work.example\r\nSubject: Synthetic\r\nContent-Type: text/plain\r\n\r\n{body}");
    let raw = Base64UrlUnpadded::encode_string(mime.as_bytes());
    format!("gws gmail users messages send --params '{{\"userId\":\"me\"}}' --json '{{\"raw\":\"{raw}\"}}'")
}

#[test]
fn frozen_command_is_paired_with_verified_sender_and_account() {
    let source = command("sender@work.example", "synthetic body");
    let input = credential("subject-one")
        .prepare_command(source.clone())
        .unwrap();
    assert!(input.is_current());
    assert_eq!(input.input().body_bytes(), b"synthetic body");
    assert_eq!(
        input.input().recipients()[0].address(),
        "recipient@work.example"
    );
    assert_eq!(input.input().sender(), "sender@work.example");
    assert_eq!(input.input_binding().len(), 64);
    let again = credential("subject-one")
        .prepare_command(source.clone())
        .unwrap();
    assert_eq!(input.input_binding(), again.input_binding());
    let other = credential("subject-two").prepare_command(source).unwrap();
    assert_ne!(input.input_binding(), other.input_binding());
    let changed = credential("subject-one")
        .prepare_command(command("sender@work.example", "changed"))
        .unwrap();
    assert_ne!(input.input_binding(), changed.input_binding());
}

#[test]
fn worker_refuses_foreign_sender_expired_credentials_and_shell_composition() {
    assert_eq!(
        credential("subject-one")
            .prepare_command(command("other@work.example", "body"))
            .err(),
        Some(GoogleWorkerInputError::Sender)
    );
    let mut expired = credential("subject-one");
    expired.expires_monotonic = Instant::now();
    assert_eq!(
        expired
            .prepare_command(command("sender@work.example", "body"))
            .err(),
        Some(GoogleWorkerInputError::Expired)
    );
    assert_eq!(
        credential("subject-one")
            .prepare_command(format!(
                "{}; echo extra",
                command("sender@work.example", "body")
            ))
            .err(),
        Some(GoogleWorkerInputError::Command)
    );
}

#[test]
fn worker_refuses_both_wall_clock_deadlines_with_live_monotonic_lease() {
    for expire_identity in [false, true] {
        let mut credential = credential("subject-one");
        assert!(credential.expires_monotonic > Instant::now());
        if expire_identity {
            credential.identity.expires_at = 0;
        } else {
            credential.expires_at = 0;
        }
        assert_eq!(
            credential
                .prepare_command(command("sender@work.example", "body"))
                .err(),
            Some(GoogleWorkerInputError::Expired)
        );
    }
}
