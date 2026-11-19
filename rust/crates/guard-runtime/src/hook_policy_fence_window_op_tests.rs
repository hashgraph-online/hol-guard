use super::*;
use serde_json::Value;

fn request(home: &str, action: &str) -> HookPolicyFenceWindowRequestV1 {
    HookPolicyFenceWindowRequestV1 {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id: format!("fence-{action}"),
        guard_home: home.to_owned(),
        action: action.to_owned(),
        admitted: None,
        waited_ms: None,
        attempt_until_micros: None,
    }
}

#[test]
fn a_window_closes_once_the_last_waiter_leaves() {
    let home = "/synthetic/fence-window";
    let enter = request(home, "enter");
    let _: Value = serde_json::from_slice(&evaluate(&enter).expect("enter")).expect("response");
    let mut second = request(home, "enter");
    second.request_id = "fence-second".to_owned();
    let _: Value = serde_json::from_slice(&evaluate(&second).expect("enter")).expect("response");
    let mut leave = request(home, "leave");
    leave.request_id = "fence-enter".to_owned();
    leave.admitted = Some(true);
    let first: Value = serde_json::from_slice(&evaluate(&leave).expect("leave")).expect("response");
    assert!(first["result"]["window_event"].is_null());
    leave.request_id = "fence-second".to_owned();
    leave.admitted = Some(false);
    let last: Value = serde_json::from_slice(&evaluate(&leave).expect("leave")).expect("response");
    assert_eq!(last["result"]["window_event"]["event_name"], EVENT_NAME);
    assert_eq!(
        last["result"]["window_event"]["payload"]["absorbed_calls"],
        1
    );
    assert_eq!(
        last["result"]["window_event"]["payload"]["exhausted_calls"],
        1
    );
}

#[test]
fn a_direct_wait_without_daemon_window_is_one_event() {
    let mut request = request("/synthetic/direct-fence", "absorb_direct");
    request.waited_ms = Some(450);
    let output: Value =
        serde_json::from_slice(&evaluate(&request).expect("absorb")).expect("response");
    assert_eq!(
        output["result"]["window_event"]["payload"]["absorbed_calls"],
        1
    );
    assert_eq!(
        output["result"]["window_event"]["payload"]["exhausted_calls"],
        0
    );
}

#[test]
fn an_expired_window_preserves_counts_for_late_leaves() {
    let home = "/synthetic/stale-fence-window";
    let mut first_enter = request(home, "enter");
    first_enter.request_id = "fence-stale-first".to_owned();
    let _: Value =
        serde_json::from_slice(&evaluate(&first_enter).expect("enter")).expect("response");
    let mut second_enter = request(home, "enter");
    second_enter.request_id = "fence-stale-second".to_owned();
    let _: Value =
        serde_json::from_slice(&evaluate(&second_enter).expect("enter")).expect("response");
    let windows = WINDOWS.get().expect("window state");
    let mut windows = windows.lock().expect("window lock");
    let stale = windows
        .get_mut(home)
        .expect("synthetic window")
        .waiters
        .get_mut("fence-stale-first")
        .expect("stale waiter");
    stale.started_micros -= MAX_WINDOW_AGE_MICROS + 1;
    drop(windows);

    let mut leave = request(home, "leave");
    leave.request_id = "fence-stale-second".to_owned();
    leave.admitted = Some(true);
    let first: Value =
        serde_json::from_slice(&evaluate(&leave).expect("late leave")).expect("response");
    assert_eq!(first["result"]["window_event"]["event_name"], EVENT_NAME);
    assert_eq!(
        first["result"]["window_event"]["payload"]["absorbed_calls"],
        1
    );
    assert_eq!(
        first["result"]["window_event"]["payload"]["exhausted_calls"],
        1
    );
}

#[test]
fn a_sweep_and_direct_wait_queue_both_events() {
    let home = "/synthetic/queued-fence-events";
    let mut enter = request(home, "enter");
    enter.request_id = "fence-queued-stale".to_owned();
    let _: Value = serde_json::from_slice(&evaluate(&enter).expect("enter")).expect("response");
    let windows = WINDOWS.get().expect("window state");
    let mut windows = windows.lock().expect("window lock");
    let stale = windows
        .get_mut(home)
        .expect("synthetic window")
        .waiters
        .get_mut("fence-queued-stale")
        .expect("stale waiter");
    stale.started_micros -= MAX_WINDOW_AGE_MICROS + 1;
    drop(windows);

    let mut direct = request(home, "absorb_direct");
    direct.waited_ms = Some(25);
    let first: Value =
        serde_json::from_slice(&evaluate(&direct).expect("direct wait")).expect("response");
    assert_eq!(first["result"]["window_event"]["event_name"], EVENT_NAME);
    assert_eq!(
        first["result"]["window_event"]["payload"]["exhausted_calls"],
        1
    );
    assert_eq!(
        first["result"]["window_event"]["payload"]["absorbed_calls"],
        0
    );
    assert_eq!(
        first["result"]["window_events"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        first["result"]["window_events"][1]["payload"]["absorbed_calls"],
        1
    );

    let mut next = request(home, "enter");
    next.request_id = "fence-queued-next".to_owned();
    let queued: Value =
        serde_json::from_slice(&evaluate(&next).expect("queued event")).expect("response");
    assert!(queued["result"]["window_event"].is_null());
}

#[test]
fn an_admitted_leave_wins_over_expiry_for_its_waiter() {
    let home = "/synthetic/admitted-late-fence";
    let mut enter = request(home, "enter");
    enter.request_id = "fence-admitted-late".to_owned();
    let _: Value = serde_json::from_slice(&evaluate(&enter).expect("enter")).expect("response");
    let windows = WINDOWS.get().expect("window state");
    let mut windows = windows.lock().expect("window lock");
    let stale = windows
        .get_mut(home)
        .expect("synthetic window")
        .waiters
        .get_mut("fence-admitted-late")
        .expect("stale waiter");
    stale.started_micros -= MAX_WINDOW_AGE_MICROS + 1;
    drop(windows);

    let mut leave = request(home, "leave");
    leave.request_id = "fence-admitted-late".to_owned();
    leave.admitted = Some(true);
    let result: Value =
        serde_json::from_slice(&evaluate(&leave).expect("late leave")).expect("response");
    assert_eq!(result["result"]["window_event"]["event_name"], EVENT_NAME);
    assert_eq!(
        result["result"]["window_event"]["payload"]["absorbed_calls"],
        1
    );
    assert_eq!(
        result["result"]["window_event"]["payload"]["exhausted_calls"],
        0
    );
}

#[test]
fn an_active_attempt_survives_a_sweep_before_its_late_leave() {
    let home = "/synthetic/active-attempt-fence";
    let mut first = request(home, "enter");
    first.request_id = "fence-active-first".to_owned();
    let _: Value = serde_json::from_slice(&evaluate(&first).expect("enter")).expect("response");

    let windows = WINDOWS.get().expect("window state");
    let mut windows = windows.lock().expect("window lock");
    let waiter = windows
        .get_mut(home)
        .expect("synthetic window")
        .waiters
        .get_mut("fence-active-first")
        .expect("active waiter");
    waiter.started_micros -= MAX_WINDOW_AGE_MICROS + 1;
    drop(windows);

    let mut attempt = request(home, "attempt");
    attempt.request_id = "fence-active-first".to_owned();
    attempt.attempt_until_micros = Some(now_micros().expect("clock").saturating_add(10_000_000));
    let _: Value = serde_json::from_slice(&evaluate(&attempt).expect("attempt")).expect("response");

    let mut second = request(home, "enter");
    second.request_id = "fence-active-second".to_owned();
    let swept: Value =
        serde_json::from_slice(&evaluate(&second).expect("sweep")).expect("response");
    assert!(swept["result"]["window_event"].is_null());

    let mut leave = request(home, "leave");
    leave.request_id = "fence-active-second".to_owned();
    leave.admitted = Some(true);
    let _: Value =
        serde_json::from_slice(&evaluate(&leave).expect("second leave")).expect("response");
    leave.request_id = "fence-active-first".to_owned();
    let final_event: Value =
        serde_json::from_slice(&evaluate(&leave).expect("first leave")).expect("response");
    assert_eq!(
        final_event["result"]["window_event"]["payload"]["absorbed_calls"],
        2
    );
    assert_eq!(
        final_event["result"]["window_event"]["payload"]["exhausted_calls"],
        0
    );
}
