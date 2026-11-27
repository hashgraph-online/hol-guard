use guard_contracts::{ProviderCapabilityV1 as Cap, ProviderConnectionStateV1 as State};
use rusqlite::Connection;

use super::*;
use crate::provider_integration_store::{
    ensure_provider_integration_schema, provider_connection, put_connection, ProviderConnection,
};

const SHIELD: &str = "provider.exampleshield";
const OTHER: &str = "provider.otherwatch";
const PER_MINUTE: u64 = 60;
const SUBJECT: &str = "subject-a";

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    ensure_provider_integration_schema(&connection).unwrap();
    put_connection(
        &connection,
        &ProviderConnection {
            provider_id: SHIELD.to_owned(),
            manifest_digest: format!("{:064x}", 7),
            state: State::Connected,
            opt_in_facts: Vec::new(),
            connected_at_ms: 1_000,
            updated_at_ms: 1_000,
            last_verified_at_ms: Some(1_000),
        },
    )
    .unwrap();
    connection
}

fn admit(worker: &mut ProviderWorker, now_ms: u64, subject: &str) -> Admission {
    worker.admit(
        now_ms,
        SHIELD,
        State::Connected,
        PER_MINUTE,
        Cap::OriginReputation,
        subject,
    )
}

fn fail(
    worker: &mut ProviderWorker,
    connection: &Connection,
    now_ms: u64,
    subject: &str,
) -> Recorded {
    worker
        .record(
            connection,
            now_ms,
            SHIELD,
            Cap::OriginReputation,
            subject,
            ExchangeOutcome::Failed,
        )
        .unwrap()
}

#[test]
fn the_bucket_holds_a_tenth_of_a_minute_and_refills_at_the_declared_rate() {
    let mut worker = ProviderWorker::new();
    let burst = (PER_MINUTE / 10) as usize;
    let sent = (0..burst + 3)
        .filter(|index| admit(&mut worker, 0, &format!("s{index}")) == Admission::Send)
        .count();
    assert_eq!(sent, burst);
    assert_eq!(admit(&mut worker, 999, "late"), Admission::RateLimited);
    assert_eq!(admit(&mut worker, 1_000, "late"), Admission::Send);
    assert_eq!(admit(&mut worker, 1_000, "later"), Admission::RateLimited);
    let mut over_a_minute = 0;
    for second in 1..=60u64 {
        for index in 0..5 {
            if admit(
                &mut worker,
                1_000 + second * 1_000,
                &format!("m{second}-{index}"),
            ) == Admission::Send
            {
                over_a_minute += 1;
            }
        }
    }
    assert!(over_a_minute <= PER_MINUTE as usize, "{over_a_minute}");
}

#[test]
fn one_provider_spending_its_budget_does_not_spend_another() {
    let mut worker = ProviderWorker::new();
    while admit(&mut worker, 0, SUBJECT) == Admission::Send {}
    assert_eq!(
        worker.admit(
            0,
            OTHER,
            State::Connected,
            PER_MINUTE,
            Cap::OriginReputation,
            SUBJECT
        ),
        Admission::Send
    );
}

#[test]
fn a_failed_subject_waits_out_the_negative_cache_and_others_do_not() {
    let connection = store();
    let mut worker = ProviderWorker::new();
    assert_eq!(admit(&mut worker, 0, SUBJECT), Admission::Send);
    fail(&mut worker, &connection, 0, SUBJECT);
    assert_eq!(
        admit(&mut worker, NEGATIVE_CACHE_MS - 1, SUBJECT),
        Admission::RecentlyFailed {
            until_ms: NEGATIVE_CACHE_MS
        }
    );
    assert_eq!(admit(&mut worker, 1_000, "subject-b"), Admission::Send);
    assert_eq!(
        admit(&mut worker, NEGATIVE_CACHE_MS, SUBJECT),
        Admission::Send
    );
}

#[test]
fn five_failures_open_the_circuit_for_five_minutes_and_one_more_reopens_it() {
    let connection = store();
    let mut worker = ProviderWorker::new();
    for index in 0..CIRCUIT_FAILURES - 1 {
        let subject = format!("s{index}");
        assert_eq!(admit(&mut worker, 0, &subject), Admission::Send);
        assert!(!fail(&mut worker, &connection, 0, &subject).circuit_opened);
    }
    assert_eq!(admit(&mut worker, 0, "last"), Admission::Send);
    assert!(fail(&mut worker, &connection, 0, "last").circuit_opened);
    assert_eq!(
        admit(&mut worker, CIRCUIT_OPEN_MS - 1, "fresh"),
        Admission::CircuitOpen {
            until_ms: CIRCUIT_OPEN_MS
        }
    );
    assert_eq!(
        admit(&mut worker, CIRCUIT_OPEN_MS, "probe"),
        Admission::Send
    );
    assert!(fail(&mut worker, &connection, CIRCUIT_OPEN_MS, "probe").circuit_opened);
    assert!(matches!(
        admit(&mut worker, CIRCUIT_OPEN_MS + 1, "fresh"),
        Admission::CircuitOpen { .. }
    ));
}

#[test]
fn an_answer_closes_the_count_and_clears_the_subject() {
    let connection = store();
    let mut worker = ProviderWorker::new();
    for index in 0..CIRCUIT_FAILURES - 1 {
        let subject = format!("s{index}");
        admit(&mut worker, 0, &subject);
        fail(&mut worker, &connection, 0, &subject);
    }
    admit(&mut worker, 0, "ok");
    worker
        .record(
            &connection,
            0,
            SHIELD,
            Cap::OriginReputation,
            "ok",
            ExchangeOutcome::Answered,
        )
        .unwrap();
    admit(&mut worker, 0, "s-next");
    assert!(!fail(&mut worker, &connection, 0, "s-next").circuit_opened);
}

#[test]
fn a_rate_limit_answer_empties_the_bucket_and_counts_as_a_failure() {
    let connection = store();
    let mut worker = ProviderWorker::new();
    assert_eq!(admit(&mut worker, 0, SUBJECT), Admission::Send);
    worker
        .record(
            &connection,
            0,
            SHIELD,
            Cap::OriginReputation,
            SUBJECT,
            ExchangeOutcome::RateLimited,
        )
        .unwrap();
    assert_eq!(admit(&mut worker, 0, "subject-b"), Admission::RateLimited);
    assert!(matches!(
        admit(&mut worker, 2_000, SUBJECT),
        Admission::RecentlyFailed { .. }
    ));
}

#[test]
fn unauthorized_marks_the_key_invalid_once_and_stops_calls() {
    let connection = store();
    let mut worker = ProviderWorker::new();
    assert_eq!(admit(&mut worker, 0, SUBJECT), Admission::Send);
    let first = worker
        .record(
            &connection,
            5_000,
            SHIELD,
            Cap::OriginReputation,
            SUBJECT,
            ExchangeOutcome::Unauthorized,
        )
        .unwrap();
    assert!(first.key_invalidated);
    let stored = provider_connection(&connection, SHIELD).unwrap().unwrap();
    assert_eq!(stored.state, State::KeyInvalid);
    assert_eq!(
        worker.admit(
            5_000,
            SHIELD,
            stored.state,
            PER_MINUTE,
            Cap::OriginReputation,
            "other"
        ),
        Admission::NotConnected(State::KeyInvalid)
    );
}

#[test]
fn the_negative_cache_is_bounded() {
    let connection = store();
    let mut worker = ProviderWorker::new();
    admit(&mut worker, 0, SUBJECT);
    for index in 0..NEGATIVE_CACHE_SUBJECTS + 10 {
        fail(&mut worker, &connection, index as u64, &format!("s{index}"));
    }
    let failed = &worker.providers[SHIELD].failed;
    assert_eq!(failed.len(), NEGATIVE_CACHE_SUBJECTS);
    assert!(!failed.contains_key(&(Cap::OriginReputation, "s0".to_owned())));
    assert!(failed.contains_key(&(
        Cap::OriginReputation,
        format!("s{}", NEGATIVE_CACHE_SUBJECTS + 9)
    )));
}

#[test]
fn refresh_lands_late_in_the_lifetime_and_before_expiry() {
    let observed = 10_000;
    let expires = 10_000 + 600_000;
    assert_eq!(refresh_at(observed, expires, 0), observed + 450_000);
    assert_eq!(refresh_at(observed, expires, u32::MAX), observed + 540_000);
    let middle = refresh_at(observed, expires, u32::MAX / 2);
    assert!(middle > observed + 450_000 && middle < observed + 540_000);
    assert_eq!(refresh_at(observed, observed, 7), observed);
    assert_eq!(refresh_at(observed, observed - 1, 7), observed);
    assert!(refresh_at(0, u64::MAX, u32::MAX) < u64::MAX);
}

fn open_circuit(worker: &mut ProviderWorker, connection: &Connection) {
    for index in 0..CIRCUIT_FAILURES {
        let subject = format!("open{index}");
        assert_eq!(admit(worker, 0, &subject), Admission::Send);
        fail(worker, connection, 0, &subject);
    }
}

#[test]
fn a_half_open_circuit_lets_one_probe_out_at_a_time() {
    let connection = store();
    let mut worker = ProviderWorker::new();
    open_circuit(&mut worker, &connection);
    assert_eq!(
        admit(&mut worker, CIRCUIT_OPEN_MS, "probe"),
        Admission::Send
    );
    for index in 0..5 {
        assert_eq!(
            admit(&mut worker, CIRCUIT_OPEN_MS + 1, &format!("other{index}")),
            Admission::CircuitOpen {
                until_ms: CIRCUIT_OPEN_MS
            }
        );
    }
    worker
        .record(
            &connection,
            CIRCUIT_OPEN_MS + 2,
            SHIELD,
            Cap::OriginReputation,
            "probe",
            ExchangeOutcome::Answered,
        )
        .unwrap();
    assert_eq!(
        admit(&mut worker, CIRCUIT_OPEN_MS + 3, "after-a"),
        Admission::Send
    );
    assert_eq!(
        admit(&mut worker, CIRCUIT_OPEN_MS + 3, "after-b"),
        Admission::Send
    );
}

#[test]
fn a_probe_that_never_reports_does_not_hold_the_circuit_shut() {
    let connection = store();
    let mut worker = ProviderWorker::new();
    open_circuit(&mut worker, &connection);
    assert_eq!(admit(&mut worker, CIRCUIT_OPEN_MS, "lost"), Admission::Send);
    assert!(matches!(
        admit(&mut worker, CIRCUIT_OPEN_MS + PROBE_TIMEOUT_MS - 1, "next"),
        Admission::CircuitOpen { .. }
    ));
    assert_eq!(
        admit(&mut worker, CIRCUIT_OPEN_MS + PROBE_TIMEOUT_MS, "next"),
        Admission::Send
    );
    assert!(matches!(
        admit(&mut worker, CIRCUIT_OPEN_MS + PROBE_TIMEOUT_MS, "third"),
        Admission::CircuitOpen { .. }
    ));
}

#[test]
fn several_unauthorized_results_report_one_invalidation_until_a_reconnect() {
    let connection = store();
    let mut worker = ProviderWorker::new();
    let unauthorized = |worker: &mut ProviderWorker, now_ms: u64, subject: &str| {
        worker
            .record(
                &connection,
                now_ms,
                SHIELD,
                Cap::OriginReputation,
                subject,
                ExchangeOutcome::Unauthorized,
            )
            .unwrap()
            .key_invalidated
    };
    admit(&mut worker, 0, "a");
    admit(&mut worker, 0, "b");
    assert!(unauthorized(&mut worker, 5_000, "a"));
    assert!(!unauthorized(&mut worker, 6_000, "b"));
    crate::provider_integration_store::set_connection_state(
        &connection,
        SHIELD,
        State::Connected,
        7_000,
    )
    .unwrap();
    assert!(unauthorized(&mut worker, 8_000, "c"));
}

#[test]
fn an_uneven_rate_still_refills_at_the_declared_rate() {
    let per_minute = 59;
    let mut worker = ProviderWorker::new();
    let admit_at = |worker: &mut ProviderWorker, now_ms: u64, subject: String| {
        worker.admit(
            now_ms,
            SHIELD,
            State::Connected,
            per_minute,
            Cap::OriginReputation,
            &subject,
        ) == Admission::Send
    };
    while admit_at(&mut worker, 0, "drain".to_owned()) {}
    let sent = (1..=MINUTE_MS_FOR_TESTS)
        .filter(|now_ms| admit_at(&mut worker, *now_ms, format!("t{now_ms}")))
        .count();
    assert!((58..=59).contains(&sent), "{sent}");
}

const MINUTE_MS_FOR_TESTS: u64 = 60 * 1000;
