//! An evaluation that panics must not be the end of the conversation. The
//! worker catches the unwind and settles it like any other failure, so the
//! client that asked gets a fixed answer it will not retry against, the panic
//! is counted where health can see it, and the worker stays up for the next
//! request. These cases drive `settle_evaluation`, which is the whole of that
//! contract and the only thing either panic site does with a caught unwind.

use super::*;

fn answer(outcome: thread::Result<Result<Vec<u8>, String>>) -> serde_json::Value {
    serde_json::from_slice(&settle_evaluation(outcome)).unwrap()
}

fn caught<F: FnOnce() -> Result<Vec<u8>, String>>(
    body: F,
) -> thread::Result<Result<Vec<u8>, String>> {
    catch_unwind(AssertUnwindSafe(body))
}

#[test]
fn a_panicking_evaluation_is_answered_without_inviting_a_retry() {
    let before = counters::snapshot().panics;

    let response = answer(caught(|| panic!("evaluation panicked")));

    assert_eq!(response["error"], "native_runtime_panicked");
    assert_eq!(response["retryable"], false);
    assert!(
        counters::snapshot().panics > before,
        "the panic was answered but never counted"
    );
}

#[test]
fn a_panic_that_carries_no_message_is_answered_the_same_way() {
    let response = answer(caught(|| std::panic::panic_any(7u32)));

    assert_eq!(response["error"], "native_runtime_panicked");
    assert_eq!(response["retryable"], false);
}

#[test]
fn settling_leaves_an_ordinary_answer_alone_and_redacts_an_unknown_reason() {
    let served = settle_evaluation(Ok(Ok(b"{\"ok\":true}".to_vec())));
    assert_eq!(served, b"{\"ok\":true}".to_vec());

    let failed: serde_json::Value = serde_json::from_slice(&settle_evaluation(Ok(Err(
        "native_reason_the_client_was_never_promised".to_owned(),
    ))))
    .unwrap();
    assert_eq!(failed["error"], "native_request_invalid_json");
    assert_eq!(failed["retryable"], false);
}

#[test]
fn a_worker_settles_the_request_after_a_panicking_one() {
    assert_eq!(
        answer(caught(|| panic!("first request panicked")))["error"],
        "native_runtime_panicked"
    );

    let next = settle_evaluation(caught(|| Ok(b"{\"ok\":true}".to_vec())));
    assert_eq!(next, b"{\"ok\":true}".to_vec());
}
