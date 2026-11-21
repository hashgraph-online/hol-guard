use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::*;

/// A clock the test moves by hand, in milliseconds.
fn manual() -> (Arc<AtomicU64>, Box<dyn Fn() -> f64 + Send + Sync>) {
    let millis = Arc::new(AtomicU64::new(1_000_000));
    let read = Arc::clone(&millis);
    (
        millis,
        Box::new(move || read.load(Ordering::SeqCst) as f64 / 1000.0),
    )
}

fn limits(active: usize) -> Limits {
    Limits {
        active,
        ..Limits::default()
    }
}

#[test]
fn admits_within_capacity_and_frees_on_release() {
    let (_, clock) = manual();
    let scheduler = Scheduler::new(limits(2), clock);
    let reservation = scheduler
        .reserve_bytes(10, 1e9)
        .unwrap_or_else(|_| unreachable!());
    let mut permit = scheduler
        .acquire("codex", "c1", 0, reservation, 1e9)
        .unwrap_or_else(|_| unreachable!());
    let stats = scheduler.stats();
    assert_eq!(stats["active"], 1);
    assert_eq!(stats["retained_bytes"], 10);
    assert_eq!(stats["per_harness_active"]["codex"], 1);
    permit.release();
    let stats = scheduler.stats();
    assert_eq!(stats["active"], 0);
    assert_eq!(stats["completed"], 1);
    assert_eq!(stats["retained_bytes"], 0);
}

#[test]
fn an_expired_deadline_is_refused_and_counted() {
    let (_, clock) = manual();
    let scheduler = Scheduler::new(limits(1), clock);
    assert_eq!(
        scheduler.reserve_bytes(1, 0.0).err(),
        Some(DEADLINE_EXHAUSTED)
    );
    assert_eq!(
        scheduler.reserve_bytes(64 * 1024 * 1024, 1e9).err(),
        Some(QUEUE_BYTES)
    );
    let stats = scheduler.stats();
    assert_eq!(stats["rejected"][DEADLINE_EXHAUSTED], 1);
    assert_eq!(stats["rejected"][QUEUE_BYTES], 1);
}

#[test]
fn a_dropped_reservation_returns_its_bytes() {
    let (_, clock) = manual();
    let scheduler = Scheduler::new(limits(1), clock);
    drop(scheduler.reserve_bytes(100, 1e9));
    assert_eq!(scheduler.stats()["retained_bytes"], 0);
}

#[test]
fn a_waiter_whose_deadline_passes_is_refused() {
    let scheduler = Scheduler::new(limits(1), monotonic());
    let now = (scheduler.clock)();
    let first = scheduler
        .reserve_bytes(1, now + 5.0)
        .unwrap_or_else(|_| unreachable!());
    let _held = scheduler
        .acquire("codex", "a", 0, first, now + 5.0)
        .unwrap_or_else(|_| unreachable!());
    let second = scheduler
        .reserve_bytes(1, now + 5.0)
        .unwrap_or_else(|_| unreachable!());
    let refused = scheduler.acquire("codex", "b", 0, second, now + 0.05);
    assert_eq!(refused.err(), Some(DEADLINE_EXHAUSTED));
    let stats = scheduler.stats();
    assert_eq!(stats["queued"], 0);
    assert_eq!(stats["retained_bytes"], 1);
}

#[test]
fn a_full_queue_refuses_for_capacity() {
    let (_, clock) = manual();
    let scheduler = Scheduler::new(
        Limits {
            active: 0,
            per_client_queued: 1,
            ..Limits::default()
        },
        clock,
    );
    let mut state = scheduler.lock();
    state.queued_by_client.insert("c".to_owned(), 1);
    drop(state);
    let reservation = scheduler
        .reserve_bytes(1, 1e9)
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        scheduler.acquire("codex", "c", 0, reservation, 1e9).err(),
        Some(QUEUE_CAPACITY)
    );
    assert_eq!(scheduler.stats()["retained_bytes"], 0);
}

#[test]
fn lanes_rotate_by_weight() {
    let (_, clock) = manual();
    let scheduler = Scheduler::new(limits(0), clock);
    let mut state = scheduler.lock();
    for (lane, client) in [(0, "d"), (0, "d"), (1, "s"), (2, "e")] {
        state.sequence += 1;
        let id = state.sequence;
        state.items.insert(
            id,
            Item {
                sequence: id,
                harness: "codex".to_owned(),
                client: client.to_owned(),
                lane,
                bytes: 0,
                expires_at: 1e9,
                queued_at: 1000.0,
                admitted_at: None,
                rejection: None,
            },
        );
        enqueue(&mut state, id);
    }
    let ids: Vec<u64> = (0..4)
        .filter_map(|_| scheduler.next_item(&mut state))
        .collect();
    let order: Vec<usize> = ids.iter().map(|id| state.items[id].lane).collect();
    assert_eq!(order, [0, 0, 1, 2]);
}

#[test]
fn an_item_that_cannot_finish_is_refused_before_it_starts() {
    let (_, clock) = manual();
    let scheduler = Scheduler::new(limits(0), clock);
    let mut state = scheduler.lock();
    state.sequence = 1;
    state.items.insert(
        1,
        Item {
            sequence: 1,
            harness: "codex".to_owned(),
            client: "c".to_owned(),
            lane: 0,
            bytes: 0,
            expires_at: 1000.3,
            queued_at: 1000.0,
            admitted_at: None,
            rejection: None,
        },
    );
    enqueue(&mut state, 1);
    assert_eq!(scheduler.next_item(&mut state), None);
    assert_eq!(state.items[&1].rejection, Some(DEADLINE_EXHAUSTED));
    assert_eq!(state.queued, 0);
}

#[test]
fn unknown_harnesses_are_reported_as_other() {
    let mut counts = HashMap::new();
    counts.insert("codex".to_owned(), 1);
    counts.insert("x".to_owned(), 2);
    counts.insert("y".to_owned(), 3);
    assert_eq!(
        bounded_harness_counts(&counts),
        json!({"codex": 1, "other": 5})
    );
    assert_eq!(lane_index("evidence"), 2);
    assert_eq!(lane_index("unknown"), 1);
}
