//! An evaluation that panics must not be the end of the conversation. The
//! worker catches the unwind and settles it like any other failure, so the
//! client that asked gets a fixed answer it will not retry against, and the
//! panic is counted where health can see it. That the worker itself survives
//! is a property of where the `catch_unwind` sits — inside the loop body, so
//! the unwind never reaches the thread — rather than of anything these cases
//! can observe. What they do drive is `settle_evaluation`, the one function
//! both panic sites hand a caught unwind to, and the whole of what either does
//! with it.

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

/// Settling a panic must not leave anything behind that colours the next
/// answer. This says nothing about worker dispatch — it never reaches one —
/// only that the function the worker calls carries no state between requests.
#[test]
fn settling_a_panic_leaves_the_next_answer_untouched() {
    assert_eq!(
        answer(caught(|| panic!("first request panicked")))["error"],
        "native_runtime_panicked"
    );

    let next = settle_evaluation(caught(|| Ok(b"{\"ok\":true}".to_vec())));
    assert_eq!(next, b"{\"ok\":true}".to_vec());
}
