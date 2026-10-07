use super::*;
use crate::oauth::worker_input_tests::credential;
use std::cell::Cell;

fn reply(status: u16, body: &[u8]) -> Reply {
    Reply {
        status,
        json: true,
        bytes: Zeroizing::new(body.to_vec()),
    }
}

#[test]
fn one_fixed_attempt_preserves_exact_body_and_returns_private_acknowledgement() {
    let calls = Cell::new(0);
    let body = br#"{"raw":"synthetic"}"#;
    let attempt = credential("subject-one")
        .send_with(body, |url, authorization, bytes| {
            calls.set(calls.get() + 1);
            assert_eq!(url, GMAIL_SEND_URL);
            assert!(authorization.starts_with("Bearer "));
            assert_eq!(bytes, body);
            Some(reply(
                200,
                br#"{"id":"synthetic-id","threadId":"synthetic-thread"}"#,
            ))
        })
        .unwrap();
    assert_eq!(calls.get(), 1);
    let RawSendAttempt::Accepted(ack) = attempt else {
        panic!("expected provider acknowledgement");
    };
    assert_eq!(ack.id.as_str(), "synthetic-id");
    assert_eq!(ack.thread_id.as_str(), "synthetic-thread");
}

#[test]
fn wrong_purpose_expiry_and_invalid_size_never_enter_transport() {
    let never = |_: &str, _: &str, _: &[u8]| -> Option<Reply> {
        panic!("must refuse before effect");
    };
    assert_eq!(
        crate::oauth::directory_test_credential()
            .send_with(b"{}", never)
            .err(),
        Some(GoogleDispatchError::WrongPurpose)
    );
    let mut expired = credential("subject-one");
    expired.expires_monotonic = std::time::Instant::now();
    assert_eq!(
        expired.send_with(b"{}", never).err(),
        Some(GoogleDispatchError::Expired)
    );
    assert_eq!(
        credential("subject-one")
            .send_with(&vec![0; 256 * 1024 + 1], never)
            .err(),
        Some(GoogleDispatchError::InputChanged)
    );
}

#[test]
fn network_and_provider_errors_remain_uncertain_and_are_not_retried() {
    for status in [303, 400, 401, 403, 429, 500, 503] {
        let calls = Cell::new(0);
        let attempt = credential("subject-one")
            .send_with(b"{}", |_, _, _| {
                calls.set(calls.get() + 1);
                Some(reply(
                    status,
                    br#"{"id":"synthetic-id","threadId":"synthetic-thread"}"#,
                ))
            })
            .unwrap();
        assert!(matches!(attempt, RawSendAttempt::Unconfirmed));
        assert_eq!(calls.get(), 1);
    }
    assert!(matches!(
        credential("subject-one")
            .send_with(b"{}", |_, _, _| None)
            .unwrap(),
        RawSendAttempt::Unconfirmed
    ));
}

#[test]
fn malformed_duplicate_extra_and_oversized_acknowledgements_never_confirm() {
    for body in [
        b"{}".as_slice(),
        br#"{"id":"one","id":"two","threadId":"thread"}"#,
        br#"{"id":"one","threadId":"thread","raw":"private"}"#,
        br#"{"id":"","threadId":"thread"}"#,
    ] {
        assert!(acknowledgement(reply(200, body)).is_none());
    }
    assert!(acknowledgement(reply(200, &vec![b' '; MAX_REPLY + 1])).is_none());
    let mut wrong_type = reply(200, br#"{"id":"one","threadId":"thread"}"#);
    wrong_type.json = false;
    assert!(acknowledgement(wrong_type).is_none());
}

#[test]
fn opaque_provider_ids_do_not_lose_a_valid_acknowledgement() {
    let ack = acknowledgement(reply(
        200,
        "{\"id\":\"opaque.id:+/α\",\"threadId\":\"thread.with:punctuation/+\"}".as_bytes(),
    ))
    .unwrap();
    assert_eq!(ack.id.as_str(), "opaque.id:+/α");
    assert_eq!(ack.thread_id.as_str(), "thread.with:punctuation/+");
    let oversized =
        serde_json::to_vec(&serde_json::json!({"id":"x".repeat(257),"threadId":"thread"})).unwrap();
    assert!(acknowledgement(reply(200, &oversized)).is_none());
}
