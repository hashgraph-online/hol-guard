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
        elapsed_ms: None,
        remaining_ms: None,
        persist_events: false,
        bound: false,
        event_name: None,
        recording_only: false,
    }
}

#[test]
fn wait_plan_preserves_the_rebuild_cap_and_both_deadline_margins() {
    let mut call = request("/synthetic/fence-plan", "wait");
    call.elapsed_ms = Some(7_900);
    call.remaining_ms = Some(600);
    let response: Value = serde_json::from_slice(&evaluate(&call).unwrap()).unwrap();
    assert_eq!(
        response["result"]["poll"],
        json!({"sleep_ms": 100, "retry_by_ms": 100, "attempt_budget_ms": 350})
    );
    assert!(plan_wait(7_901, 20_000).is_none());
    assert!(plan_wait(0, 599).is_none());
    assert!(plan_wait(u64::MAX, 20_000).is_none());
    assert!(plan_wait(0, 0).is_none());
}

#[test]
fn review_fence_requires_a_bound_enforcing_hook() {
    let mut call = request("/synthetic/review-fence", "review_enter");
    call.bound = true;
    call.event_name = Some("PostToolUse".to_owned());
    let response: Value = serde_json::from_slice(&evaluate(&call).unwrap()).unwrap();
    assert_eq!(response["result"]["fenced"], false);

    call.event_name = Some("PreToolUse".to_owned());
    call.recording_only = true;
    let response: Value = serde_json::from_slice(&evaluate(&call).unwrap()).unwrap();
    assert_eq!(response["result"]["fenced"], false);
}

#[test]
fn native_wait_plan_registers_one_attempt_lease_for_the_window() {
    let home = "/synthetic/fence-plan-lease";
    let enter = request(home, "enter");
    evaluate(&enter).unwrap();
    let mut poll = request(home, "wait");
    poll.request_id.clone_from(&enter.request_id);
    poll.elapsed_ms = Some(0);
    poll.remaining_ms = Some(2000);
    let before = now_micros().unwrap();
    evaluate(&poll).unwrap();
    let expiry = || {
        WINDOWS.get().unwrap().lock().unwrap()[home].waiters[&poll.request_id]
            .attempt_until_micros
            .unwrap()
    };
    let first = expiry();
    assert!((before + 1_750_000..=now_micros().unwrap() + 1_750_000).contains(&first));
    // A later plan can shorten the caller's attempt but cannot prolong the registration.
    let mut repeated_poll = request(home, "wait");
    repeated_poll.request_id.clone_from(&poll.request_id);
    repeated_poll.elapsed_ms = Some(500);
    repeated_poll.remaining_ms = Some(2000);
    evaluate(&repeated_poll).unwrap();
    assert_eq!(expiry(), first);
}

#[test]
fn resident_persists_completed_windows_once_after_write_contention() {
    check_contended_batch(MAX_BATCH_EVENTS, 0);
}

#[test]
fn resident_records_a_dropped_window_when_the_pending_queue_is_full() {
    check_contended_batch(MAX_PENDING_EVENTS, 1);
}

fn check_contended_batch(queued: usize, dropped: i64) {
    let dir = tempfile::tempdir().unwrap();
    let guard_home = dir.path().to_str().unwrap();
    let connection =
        rusqlite::Connection::open(dir.path().join(crate::local_store_read::STORE_FILE_NAME))
            .unwrap();
    connection
        .execute_batch(
            "create table guard_events (event_name text, payload_json text, occurred_at text);",
        )
        .unwrap();
    let gate = std::fs::File::create_new(
        dir.path()
            .join(crate::hook_evidence_store_gate::STORAGE_GATE_FILE_NAME),
    )
    .unwrap();
    fs2::FileExt::try_lock_exclusive(&gate).unwrap();
    let mut enter = request(guard_home, "enter");
    enter.persist_events = true;
    evaluate(&enter).unwrap();
    {
        let mut windows = WINDOWS.get().unwrap().lock().unwrap();
        let pending = &mut windows.get_mut(guard_home).unwrap().pending_events;
        let now = now_micros().unwrap();
        pending.extend((0..queued).map(|_| event(now, now, 1, 0).unwrap()));
    }
    let mut leave = request(guard_home, "leave");
    leave.persist_events = true;
    leave.request_id.clone_from(&enter.request_id);
    leave.admitted = Some(false);
    assert_eq!(
        evaluate(&leave).unwrap_err(),
        "hook_policy_fence_window_write_failed"
    );
    fs2::FileExt::unlock(&gate).unwrap();
    connection.execute_batch("begin immediate;").unwrap();
    assert_eq!(
        evaluate(&leave).unwrap_err(),
        "hook_policy_fence_window_write_failed"
    );
    connection.execute_batch("rollback;").unwrap();

    let result: Value = serde_json::from_slice(&evaluate(&leave).unwrap()).unwrap();
    assert!(result["result"]["window_event"].is_null());
    assert_eq!(result["result"]["window_events"], json!([]));
    evaluate(&leave).unwrap();
    evaluate(&leave).unwrap();

    let count: i64 = connection
        .query_row(
            "select count(*) from guard_events where event_name = ?",
            [EVENT_NAME],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, queued as i64 + 1 - dropped);
    let reported: i64 = connection
        .query_row(
            "select coalesce(sum(json_extract(payload_json, '$.dropped_windows')), 0) \
             from guard_events where event_name = ?",
            [OVERFLOW_EVENT_NAME],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reported, dropped);
    if dropped == 0 {
        let (payload, occurred_at): (String, String) = connection
            .query_row(
                "select payload_json, occurred_at from guard_events \
                 where json_extract(payload_json, '$.exhausted_calls') = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let payload: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(payload["ended_at"], occurred_at);
        assert_eq!(payload["absorbed_calls"], 0);
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
