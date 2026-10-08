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
fn poisoned_account_lease_refuses_with_zero_transport_calls() {
    let mut credential = credential("subject-one");
    let active = std::sync::Arc::new(std::sync::RwLock::new(true));
    credential.account_lease = Some(std::sync::Arc::clone(&active));
    assert!(std::thread::spawn(move || {
        let _writer = active.write().unwrap();
        panic!("synthetic lease poisoning");
    })
    .join()
    .is_err());
    let calls = Cell::new(0);
    assert!(!credential.is_current());
    assert_eq!(
        credential
            .send_with(b"{}", |_, _, _| {
                calls.set(calls.get() + 1);
                None
            })
            .err(),
        Some(GoogleDispatchError::Expired)
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn concurrent_account_revocation_waits_for_admitted_transport_and_refuses_pending_input() {
    use crate::oauth::{worker_input_tests::command, GoogleSendAccount};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    };
    use std::time::Duration;
    let account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let admitted = account
        .prepare_command(command("sender@work.example", "first"))
        .unwrap()
        .test_credential();
    let pending = account
        .prepare_command(command("sender@work.example", "second"))
        .unwrap()
        .test_credential();
    let calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let calls = Arc::clone(&calls);
        let sending = scope.spawn(move || {
            admitted.send_with(b"{}", |_, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                None
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let revoking = scope.spawn(|| {
            started_tx.send(()).unwrap();
            account.revoke();
            done_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(
            done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        release_tx.send(()).unwrap();
        assert!(matches!(
            sending.join().unwrap().unwrap(),
            RawSendAttempt::Unconfirmed
        ));
        done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        revoking.join().unwrap();
    });
    assert!(!account.is_current());
    assert_eq!(
        pending
            .send_with(b"{}", |_, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                None
            })
            .err(),
        Some(GoogleDispatchError::Expired)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn revoked_account_lease_refuses_before_transport() {
    let mut credential = credential("subject-one");
    credential.account_lease = Some(std::sync::Arc::new(std::sync::RwLock::new(false)));
    let calls = Cell::new(0);
    assert_eq!(
        credential
            .send_with(b"{}", |_, _, _| {
                calls.set(calls.get() + 1);
                None
            })
            .err(),
        Some(GoogleDispatchError::Expired)
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn bounded_transport_holds_lease_against_concurrent_revocation() {
    let mut credential = credential("subject-one");
    let active = std::sync::Arc::new(std::sync::RwLock::new(true));
    credential.account_lease = Some(std::sync::Arc::clone(&active));
    let calls = Cell::new(0);
    let result = credential
        .send_with(b"{}", |_, _, _| {
            calls.set(calls.get() + 1);
            assert!(active.try_write().is_err());
            None
        })
        .unwrap();
    assert!(matches!(result, RawSendAttempt::Unconfirmed));
    assert_eq!(calls.get(), 1);
    *active.try_write().unwrap() = false;
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
